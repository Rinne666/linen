"""The multiwave event state machine and its read-only projection (CF-S2-A).

The ledger in :mod:`linen.server.skill_coverage` stores one immutable row per
event.  This module adds the two event types that describe a unit's *history*
rather than its registration:

``wave_started``
    a wave took the unit over: who owns it, which blocks the owner was given,
    and - from the second wave on - why the previous owner was replaced.

``attempt_recorded``
    a wave reached a terminal state with its evidence.

Two properties make this more than a second table with two more column
values:

* The **order** of the events is decided by the server, inside the same
  transaction as the insert.  A client cannot say "this is wave 3" and have
  the ledger believe it: the wave number is derived from the stored stream.
* The **projection** is a pure function of that stream.  Replaying the same
  events always yields the same result, and the projection never invents a
  wave, an attempt or a finding that did not happen.

The shape of an attempt follows the pinned upstream validator
(``validate-coverage-ledger.cjs`` @ c1c8a8c).  Upstream keeps the archived
waves in ``unit.attempts[]`` and the *current* wave in the unit's live
fields, and it requires every archived attempt to carry a non-empty
``reassignment_reason``.  That is why the reason travels on the *next*
``wave_started`` event: the reason a hunter was replaced is often only known
once the replacement is dispatched, and the projection attaches it to the
archived attempt it belongs to.

The upstream validator knows nothing about events - it validates a static
document.  The event ordering rules here are therefore linen's own contract,
and the compatibility with upstream is proven by running the vendored
validator over a projected ledger, not by assuming it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol, Sequence

from linen.contracts.common import (
    cf_canonical_json,
    cf_is_legacy_coverage_id,
    cf_payload_digest,
)
from linen.contracts.skill_audit import (
    AttemptRecordedPayload,
    CoverageBlockSelection,
    CoverageCanonicalRefs,
    WaveStartedPayload,
)
from linen.server.services import utcnow
from linen.server.skill_coverage import (
    CoverageEventConflict,
    CoverageEventRejected,
    CoverageRunNotFound,
)


class CoverageWaveUntrusted(PermissionError):
    """The caller is not an accepted multiwave event writer."""


class CoverageMultiwaveDisabled(RuntimeError):
    """Production multiwave event recording is switched off."""


class CoverageWaveSourceUnavailable(RuntimeError):
    """No trusted source could resolve the wave's inputs."""


class CoverageAttemptSourceUnavailable(RuntimeError):
    """No trusted source could resolve the attempt's evidence."""


class CoverageWaveOrderRejected(CoverageEventRejected):
    """The event does not fit the stored history of the unit."""


class CoverageWavePlanner(Protocol):
    """Resolves the trusted inputs of one wave of a coverage unit.

    The implementation has to answer with the *assignment* of the wave: who
    owns it, which blocks the owner was handed, the paths the owner starts
    from, and - from the second wave on - the source-backed reason the
    previous owner was replaced.  The server never takes any of these from a
    request body (D-026).
    """

    def __call__(
        self,
        *,
        project_id: str,
        run_id: str,
        coverage_id: str,
        wave: int,
    ) -> "CoverageWavePlan": ...


class CoverageAttemptSource(Protocol):
    """Resolves the admitted evidence of one terminal attempt.

    The evidence is the output of a hunter, but it reaches the ledger only
    after the trusted admission layer accepted it.  The provider returns the
    admitted record; the server binds it to the wave's owner.
    """

    def __call__(
        self,
        *,
        project_id: str,
        run_id: str,
        coverage_id: str,
        wave: int,
    ) -> "CoverageAttemptPlan": ...


@dataclass(frozen=True)
class CoverageWavePlan:
    """The trusted assignment of one wave."""

    agent_id: str
    block_selection: CoverageBlockSelection
    starting_paths: list[str] = field(default_factory=list)
    reassignment_reason: str | None = None


@dataclass(frozen=True)
class CoverageAttemptPlan:
    """The admitted evidence of one terminal attempt."""

    status: str
    reviewed_paths: list[str] = field(default_factory=list)
    local_checks: list[Mapping[str, Any]] = field(default_factory=list)
    result_fingerprints: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CoverageMultiwavePolicy:
    """What the server needs before it records a multiwave event.

    The defaults are the safe ones: no writer, no planner, no attempt source,
    so a stock deployment refuses every multiwave write.  The policy is
    application configuration, never a request field.
    """

    enabled: bool = False
    trusted_caller: bool = False
    wave_planner: CoverageWavePlanner | None = None
    attempt_source: CoverageAttemptSource | None = None


#: The policy a stock server runs with.
DEFAULT_MULTIWAVE_POLICY = CoverageMultiwavePolicy()


@dataclass(frozen=True)
class RecordedCoverageEvent:
    """One stored multiwave event."""

    event_id: int
    project_id: str
    run_id: str
    coverage_id: str
    event_type: str
    event_key: str
    payload_sha256: str
    created_at: str
    payload: WaveStartedPayload | AttemptRecordedPayload
    replayed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "coverage_id": self.coverage_id,
            "event_type": self.event_type,
            "event_key": self.event_key,
            "payload_sha256": self.payload_sha256,
            "created_at": self.created_at,
            "payload": self.payload.model_dump(mode="json"),
            "replayed": self.replayed,
        }


def wave_started_event_key(coverage_id: str, wave: int) -> str:
    """The idempotency key of a wave start inside one run."""

    return f"wave_started:{coverage_id}:{wave}"


def attempt_recorded_event_key(coverage_id: str, wave: int) -> str:
    """The idempotency key of an attempt inside one run."""

    return f"attempt_recorded:{coverage_id}:{wave}"


# --- reading the stored history --------------------------------------------


def list_coverage_events(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str | None = None,
) -> list[dict[str, Any]]:
    """Read the event stream of one run (or one unit) in write order."""

    sql = (
        "SELECT event_id, project_id, run_id, coverage_id, event_type, event_key, "
        "payload_json, payload_sha256, created_at FROM skill_coverage_events "
        "WHERE project_id = ? AND run_id = ?"
    )
    params: list[Any] = [project_id, run_id]
    if coverage_id is not None:
        sql += " AND coverage_id = ?"
        params.append(coverage_id)
    sql += " ORDER BY event_id"
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def _unit_events(events: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The events of a single unit, in write order."""

    return list(events)


def _wave_starts(
    events: Sequence[Mapping[str, Any]]
) -> dict[int, Mapping[str, Any]]:
    """The wave starts of a unit, keyed by wave number."""

    starts: dict[int, Mapping[str, Any]] = {}
    for event in events:
        if event.get("event_type") != "wave_started":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            payload = json.loads(str(event.get("payload_json") or "{}"))
        wave = payload.get("wave")
        if not isinstance(wave, int):
            raise CoverageEventRejected("wave_started event has no wave number")
        if wave in starts:
            raise CoverageEventConflict(
                f"wave {wave} was started more than once for this coverage unit"
            )
        starts[wave] = event
    return starts


def _attempts(
    events: Sequence[Mapping[str, Any]]
) -> dict[int, Mapping[str, Any]]:
    """The recorded attempts of a unit, keyed by wave number."""

    attempts: dict[int, Mapping[str, Any]] = {}
    for event in events:
        if event.get("event_type") != "attempt_recorded":
            continue
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            payload = json.loads(str(event.get("payload_json") or "{}"))
        wave = payload.get("wave")
        if not isinstance(wave, int):
            raise CoverageEventRejected("attempt_recorded event has no wave number")
        if wave in attempts:
            raise CoverageEventConflict(
                f"wave {wave} recorded more than one attempt for this coverage unit"
            )
        attempts[wave] = event
    return attempts


def _payload_of(event: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = event.get("payload")
    if isinstance(payload, Mapping):
        return payload
    return json.loads(str(event.get("payload_json") or "{}"))


def _registration(events: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    for event in events:
        if event.get("event_type") == "unit_registered":
            return _payload_of(event)
    raise CoverageEventRejected(
        "the coverage unit is not registered, so it has no wave history"
    )


# --- the state machine ------------------------------------------------------


def _check_canonical_id(coverage_id: str, payload: Any) -> None:
    if cf_is_legacy_coverage_id(coverage_id):
        raise CoverageEventRejected(
            "coverage_id must be a canonical id; the retired cov-<n> scheme is "
            "read-only through an explicit alias map (D-017)"
        )
    expected = payload.derived_coverage_id()
    if coverage_id != expected:
        raise CoverageEventRejected(
            "coverage_id must equal the canonical id derived from the four "
            f"dimensions: {expected!r}"
        )


def _assert_unit_registered(
    events: Sequence[Mapping[str, Any]], coverage_id: str
) -> None:
    registration = _registration(events)
    refs = registration.get("canonical_refs")
    if not isinstance(refs, Mapping):
        raise CoverageEventRejected("the registration carries no canonical refs")


def _used_artifacts(events: Sequence[Mapping[str, Any]]) -> set[str]:
    """Every local artifact an earlier attempt of the unit already used."""

    used: set[str] = set()
    for event in events:
        if event.get("event_type") != "attempt_recorded":
            continue
        payload = _payload_of(event)
        checks = payload.get("local_checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, Mapping):
                continue
            artifact = check.get("artifact")
            if isinstance(artifact, str):
                used.add(artifact)
    return used


def _record_event(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    event_type: str,
    event_key: str,
    payload: Any,
    agent_id: str,
    wave: int,
) -> RecordedCoverageEvent:
    """Insert one multiwave event, enforcing the state machine."""

    content = payload.digest_content()
    normalized = cf_canonical_json(content)
    digest = cf_payload_digest(content)

    owns_transaction = not conn.in_transaction
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    try:
        run = conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ? AND project_id = ?",
            (run_id, project_id),
        ).fetchone()
        if run is None:
            raise CoverageRunNotFound(
                f"run {run_id} does not belong to project {project_id}"
            )

        existing = conn.execute(
            "SELECT event_id, payload_sha256, created_at FROM skill_coverage_events "
            "WHERE project_id = ? AND run_id = ? AND event_key = ?",
            (project_id, run_id, event_key),
        ).fetchone()
        if existing is not None:
            if existing["payload_sha256"] != digest:
                raise CoverageEventConflict(
                    f"event {event_key} is already stored in run {run_id} with a "
                    "different payload"
                )
            return RecordedCoverageEvent(
                event_id=existing["event_id"],
                project_id=project_id,
                run_id=run_id,
                coverage_id=coverage_id,
                event_type=event_type,
                event_key=event_key,
                payload_sha256=existing["payload_sha256"],
                created_at=existing["created_at"],
                payload=payload,
                replayed=True,
            )

        events = list_coverage_events(
            conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
        )
        if event_type == "wave_started":
            _validate_wave_start(
                events, coverage_id=coverage_id, wave=wave, agent_id=agent_id
            )
        else:
            _validate_attempt(
                events,
                coverage_id=coverage_id,
                wave=wave,
                agent_id=agent_id,
                payload=payload,
            )

        now = utcnow()
        try:
            cursor = conn.execute(
                "INSERT INTO skill_coverage_events ("
                "project_id, run_id, coverage_id, event_type, payload_version, "
                "agent_id, wave, event_key, payload_json, payload_sha256, created_at"
                ") VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    project_id,
                    run_id,
                    coverage_id,
                    event_type,
                    agent_id,
                    wave,
                    event_key,
                    normalized,
                    digest,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if "FOREIGN KEY" in message:
                raise CoverageRunNotFound(
                    f"run {run_id} does not belong to project {project_id}"
                ) from exc
            raise CoverageEventConflict(
                f"event {event_key} is already stored in run {run_id}"
            ) from exc

        return RecordedCoverageEvent(
            event_id=int(cursor.lastrowid),
            project_id=project_id,
            run_id=run_id,
            coverage_id=coverage_id,
            event_type=event_type,
            event_key=event_key,
            payload_sha256=digest,
            created_at=now,
            payload=payload,
            replayed=False,
        )
    except Exception:
        if owns_transaction:
            conn.rollback()
        raise
    else:
        if owns_transaction:
            conn.commit()


def _validate_wave_start(
    events: Sequence[Mapping[str, Any]],
    *,
    coverage_id: str,
    wave: int,
    agent_id: str,
) -> None:
    """A wave may only start on top of a settled history."""

    _assert_unit_registered(events, coverage_id)
    starts = _wave_starts(events)
    attempts = _attempts(events)

    if wave in starts:
        raise CoverageWaveOrderRejected(
            f"wave {wave} was already started for this coverage unit"
        )
    if starts and wave <= max(starts):
        raise CoverageWaveOrderRejected(
            f"wave {wave} does not follow the stored waves of this coverage unit"
        )
    if not starts and wave != 1:
        raise CoverageWaveOrderRejected(
            "the first wave of a coverage unit must be wave 1"
        )
    if starts:
        previous = max(starts)
        if previous not in attempts:
            raise CoverageWaveOrderRejected(
                f"wave {previous} has no recorded attempt, so the unit cannot be "
                f"reassigned to wave {wave}"
            )
    # Every wave of a unit has its own owner: upstream refuses a current
    # assignment whose owner already owned an archived attempt, so a
    # reassignment that keeps the old owner would never be a legal ledger.
    owners = {
        _payload_of(event).get("agent_id")
        for other_wave, event in starts.items()
        if other_wave < wave
    }
    if agent_id in owners:
        raise CoverageWaveOrderRejected(
            f"agent {agent_id!r} already owned an earlier wave of this coverage unit"
        )


def _validate_attempt(
    events: Sequence[Mapping[str, Any]],
    *,
    coverage_id: str,
    wave: int,
    agent_id: str,
    payload: AttemptRecordedPayload,
) -> None:
    """An attempt may only record the wave that is currently open."""

    _assert_unit_registered(events, coverage_id)
    starts = _wave_starts(events)
    attempts = _attempts(events)

    if wave not in starts:
        raise CoverageWaveOrderRejected(
            f"wave {wave} was never started for this coverage unit"
        )
    if wave in attempts:
        raise CoverageWaveOrderRejected(
            f"wave {wave} already recorded an attempt for this coverage unit"
        )
    if starts and wave != max(starts):
        raise CoverageWaveOrderRejected(
            f"wave {wave} is not the current wave of this coverage unit"
        )
    start_payload = _payload_of(starts[wave])
    owner = start_payload.get("agent_id")
    if owner != agent_id:
        raise CoverageWaveOrderRejected(
            f"wave {wave} belongs to another owner, so its attempt cannot be "
            "recorded under a different agent"
        )

    owners = {
        _payload_of(event).get("agent_id")
        for other_wave, event in starts.items()
        if other_wave < wave
    }
    if agent_id in owners:
        raise CoverageWaveOrderRejected(
            f"agent {agent_id!r} already owned an earlier wave of this coverage unit"
        )

    used = _used_artifacts(events)
    for index, check in enumerate(payload.local_checks):
        artifact = check.artifact
        if isinstance(artifact, str) and artifact in used:
            raise CoverageWaveOrderRejected(
                f"local_checks[{index}].artifact: artifact from an earlier attempt "
                "cannot be reused"
            )
        if isinstance(artifact, str):
            used.add(artifact)


def record_wave_started(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    payload: WaveStartedPayload,
) -> RecordedCoverageEvent:
    """Record one trusted ``wave_started`` event."""

    _check_canonical_id(coverage_id, payload)
    return _record_event(
        conn,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        event_type="wave_started",
        event_key=wave_started_event_key(coverage_id, payload.wave),
        payload=payload,
        agent_id=payload.agent_id,
        wave=payload.wave,
    )


def record_attempt(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    payload: AttemptRecordedPayload,
) -> RecordedCoverageEvent:
    """Record one trusted ``attempt_recorded`` event."""

    _check_canonical_id(coverage_id, payload)
    return _record_event(
        conn,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        event_type="attempt_recorded",
        event_key=attempt_recorded_event_key(coverage_id, payload.wave),
        payload=payload,
        agent_id=payload.agent_id,
        wave=payload.wave,
    )


# --- the trusted entry point -------------------------------------------------


def _registration_refs(events: Sequence[Mapping[str, Any]]) -> CoverageCanonicalRefs:
    registration = _registration(events)
    refs = registration.get("canonical_refs")
    if not isinstance(refs, Mapping):
        raise CoverageEventRejected("the registration carries no canonical refs")
    return CoverageCanonicalRefs(**{str(key): str(value) for key, value in refs.items()})


def next_wave_number(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
) -> int:
    """The wave number the server would assign next.

    The number is derived from the stored history, never taken from a
    request: a caller cannot declare "this is wave 3".
    """

    events = list_coverage_events(
        conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
    )
    starts = _wave_starts(events)
    return (max(starts) + 1) if starts else 1


def resolve_wave_payload(
    policy: CoverageMultiwavePolicy,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    wave: int,
    canonical_refs: CoverageCanonicalRefs,
) -> WaveStartedPayload:
    """Build the wave payload the server is willing to persist.

    Every value comes from the server's own trusted sources: the wave number
    is derived from the stored history, the owner and the block map come from
    the installed planner, and the canonical refs come from the registration.
    """

    if not policy.enabled:
        raise CoverageMultiwaveDisabled(
            "production multiwave recording is disabled; no trusted writer is installed"
        )
    if not policy.trusted_caller:
        raise CoverageWaveUntrusted(
            "the caller is not an accepted multiwave event writer"
        )
    if policy.wave_planner is None:
        raise CoverageWaveSourceUnavailable(
            "no trusted wave planner is installed, so no wave can be assigned"
        )
    plan = policy.wave_planner(
        project_id=project_id, run_id=run_id, coverage_id=coverage_id, wave=wave
    )
    return WaveStartedPayload(
        schema_version=1,
        canonical_refs=canonical_refs,
        wave=wave,
        agent_id=plan.agent_id,
        block_selection=plan.block_selection,
        starting_paths=list(plan.starting_paths),
        reassignment_reason=plan.reassignment_reason,
    )


def resolve_attempt_payload(
    policy: CoverageMultiwavePolicy,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    wave: int,
    canonical_refs: CoverageCanonicalRefs,
    agent_id: str,
) -> AttemptRecordedPayload:
    """Build the attempt payload the server is willing to persist.

    The evidence comes from the installed attempt source, which only ever
    hands over evidence that the trusted admission layer accepted.  The
    owner is the one that holds the wave, so an attempt can never be filed
    under somebody else.
    """

    if not policy.enabled:
        raise CoverageMultiwaveDisabled(
            "production multiwave recording is disabled; no trusted writer is installed"
        )
    if not policy.trusted_caller:
        raise CoverageWaveUntrusted(
            "the caller is not an accepted multiwave event writer"
        )
    if policy.attempt_source is None:
        raise CoverageAttemptSourceUnavailable(
            "no trusted attempt source is installed, so no attempt can be recorded"
        )
    plan = policy.attempt_source(
        project_id=project_id, run_id=run_id, coverage_id=coverage_id, wave=wave
    )
    return AttemptRecordedPayload(
        schema_version=1,
        canonical_refs=canonical_refs,
        wave=wave,
        agent_id=agent_id,
        status=plan.status,
        reviewed_paths=list(plan.reviewed_paths),
        local_checks=list(plan.local_checks),
        result_fingerprints=list(plan.result_fingerprints),
        unresolved=list(plan.unresolved),
    )


def _assert_multiwave_allowed(policy: CoverageMultiwavePolicy) -> None:
    """The gate every multiwave write passes first.

    The gate comes before the state is read, so a server that records no
    multiwave events does not even reveal whether a wave exists.
    """

    if not policy.enabled:
        raise CoverageMultiwaveDisabled(
            "production multiwave recording is disabled; no trusted writer is installed"
        )
    if not policy.trusted_caller:
        raise CoverageWaveUntrusted(
            "the caller is not an accepted multiwave event writer"
        )


def record_trusted_wave_started(
    conn: sqlite3.Connection,
    *,
    policy: CoverageMultiwavePolicy,
    project_id: str,
    run_id: str,
    coverage_id: str,
) -> RecordedCoverageEvent:
    """The production entry point for a wave start.

    The payload is derived here, from the installed trusted sources; a
    caller cannot supply it.  The write stays closed until a policy with a
    planner and a trusted caller is installed (A16).
    """

    _assert_multiwave_allowed(policy)
    events = list_coverage_events(
        conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
    )
    canonical_refs = _registration_refs(events)
    wave = next_wave_number(
        conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
    )
    payload = resolve_wave_payload(
        policy,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        wave=wave,
        canonical_refs=canonical_refs,
    )
    return record_wave_started(
        conn,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        payload=payload,
    )


def record_trusted_attempt(
    conn: sqlite3.Connection,
    *,
    policy: CoverageMultiwavePolicy,
    project_id: str,
    run_id: str,
    coverage_id: str,
) -> RecordedCoverageEvent:
    """The production entry point for a terminal attempt.

    The attempt belongs to the wave that is currently open, and its owner is
    that wave's owner.
    """

    _assert_multiwave_allowed(policy)
    events = list_coverage_events(
        conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
    )
    canonical_refs = _registration_refs(events)
    starts = _wave_starts(events)
    if not starts:
        raise CoverageWaveOrderRejected(
            "no wave was started for this coverage unit"
        )
    wave = max(starts)
    attempts = _attempts(events)
    if wave in attempts:
        raise CoverageWaveOrderRejected(
            f"wave {wave} already recorded an attempt for this coverage unit"
        )
    owner = _payload_of(starts[wave]).get("agent_id")
    if not isinstance(owner, str):
        raise CoverageEventRejected(f"wave {wave} has no owner")
    payload = resolve_attempt_payload(
        policy,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        wave=wave,
        canonical_refs=canonical_refs,
        agent_id=owner,
    )
    return record_attempt(
        conn,
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        payload=payload,
    )


# --- the read-only projection ----------------------------------------------


@dataclass(frozen=True)
class CoverageUnitProjection:
    """The multiwave view of one coverage unit, rebuilt from its events.

    The projection is a pure function of the event stream.  It reports the
    unit's current wave and status, the archived attempts, the block map in
    effect and the unresolved blockers.  It never invents a wave, never
    archives an attempt that has no terminal record, and never turns a
    finding into a confirmed one.
    """

    coverage_id: str
    canonical_refs: dict[str, str]
    prior_status: str
    wave: int
    status: str
    agent_id: str | None
    reviewed_paths: list[str]
    local_checks: list[dict[str, Any]]
    result_fingerprints: list[str]
    unresolved: list[str]
    attempts: list[dict[str, Any]]
    block_selection: dict[str, Any] | None
    starting_paths: list[str]
    registration_event_id: int
    #: Whether this unit may be published as a complete upstream ledger
    #: (D-034).  A unit that is only registered has no real starting paths,
    #: and a ledger that invents them would claim a coverage nobody ran.
    exportable: bool = True
    export_blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage_id": self.coverage_id,
            "canonical_refs": dict(self.canonical_refs),
            "prior_status": self.prior_status,
            "wave": self.wave,
            "status": self.status,
            "agent_id": self.agent_id,
            "reviewed_paths": list(self.reviewed_paths),
            "local_checks": [dict(check) for check in self.local_checks],
            "result_fingerprints": list(self.result_fingerprints),
            "unresolved": list(self.unresolved),
            "attempts": [dict(attempt) for attempt in self.attempts],
            "block_selection": (
                dict(self.block_selection) if self.block_selection is not None else None
            ),
            "starting_paths": list(self.starting_paths),
            "registration_event_id": self.registration_event_id,
            "exportable": self.exportable,
            "export_blockers": list(self.export_blockers),
        }

    def to_upstream_unit(self) -> dict[str, Any]:
        """The unit in the shape the upstream coverage ledger expects."""

        refs = self.canonical_refs
        blocks = self.block_selection or {}
        excluded = blocks.get("excluded_blocks")
        return {
            "coverage_id": self.coverage_id,
            "canonical_refs": dict(refs),
            "surface": refs.get("surface", ""),
            "boundary": refs.get("boundary", ""),
            "subsystem": refs.get("subsystem", ""),
            "attack_class": refs.get("attack_class", ""),
            "starting_paths": list(self.starting_paths),
            "ordinary_attack_class_block": blocks.get("ordinary_attack_class_block"),
            "selected_companion_blocks": list(
                blocks.get("selected_companion_blocks") or []
            ),
            "excluded_blocks": [
                {"block": entry["block"], "reason": entry["reason"]}
                for entry in (excluded or [])
            ],
            "prior_status": self.prior_status,
            "attempts": [dict(attempt) for attempt in self.attempts],
            "wave": self.wave,
            "status": self.status,
            "agent_id": self.agent_id,
            "reviewed_paths": list(self.reviewed_paths),
            "local_checks": [dict(check) for check in self.local_checks],
            "result_fingerprints": list(self.result_fingerprints),
            "unresolved": list(self.unresolved),
        }


def project_multiwave(
    events: Iterable[Mapping[str, Any]],
) -> list[CoverageUnitProjection]:
    """Rebuild the multiwave view of every unit in an event stream.

    The projection is deterministic: the same stream always produces the same
    result, and a stream that contains no wave produces a unit that is still
    ``planned`` - never an invented wave.
    """

    by_unit: dict[str, list[Mapping[str, Any]]] = {}
    order: list[str] = []
    for event in events:
        coverage_id = event.get("coverage_id")
        if not isinstance(coverage_id, str) or not coverage_id:
            raise CoverageEventRejected("event has no coverage_id")
        if coverage_id not in by_unit:
            by_unit[coverage_id] = []
            order.append(coverage_id)
        by_unit[coverage_id].append(event)

    projections: list[CoverageUnitProjection] = []
    for coverage_id in order:
        projections.append(_project_unit(coverage_id, by_unit[coverage_id]))
    return projections


def _project_unit(
    coverage_id: str, events: Sequence[Mapping[str, Any]]
) -> CoverageUnitProjection:
    registration_event = None
    for event in events:
        if event.get("event_type") == "unit_registered":
            registration_event = event
            break
    if registration_event is None:
        raise CoverageEventRejected(
            f"coverage unit {coverage_id} has no registration event"
        )

    registration = _payload_of(registration_event)
    refs = registration.get("canonical_refs")
    if not isinstance(refs, Mapping):
        raise CoverageEventRejected("the registration carries no canonical refs")
    canonical_refs = {str(key): str(value) for key, value in refs.items()}
    prior_status = str(registration.get("prior_status") or "none")
    registration_event_id = int(
        registration_event.get("event_id") or registration_event.get("registration_event_id") or 0
    )

    starts = _wave_starts(events)
    attempts = _attempts(events)

    archived: list[dict[str, Any]] = []
    for wave in sorted(starts):
        if wave == max(starts, default=0):
            continue
        attempt = attempts.get(wave)
        if attempt is None:
            # A wave that never reached a terminal state is not archived.
            continue
        attempt_payload = _payload_of(attempt)
        next_start = starts.get(wave + 1)
        reason = None
        if next_start is not None:
            reason = _payload_of(next_start).get("reassignment_reason")
        archived.append(
            {
                "wave": wave,
                "status": attempt_payload.get("status"),
                "agent_id": attempt_payload.get("agent_id"),
                "reviewed_paths": list(attempt_payload.get("reviewed_paths") or []),
                "local_checks": [dict(c) for c in (attempt_payload.get("local_checks") or [])],
                "result_fingerprints": list(
                    attempt_payload.get("result_fingerprints") or []
                ),
                "unresolved": list(attempt_payload.get("unresolved") or []),
                "reassignment_reason": reason,
            }
        )

    current_wave = max(starts, default=0)
    live_attempt = attempts.get(current_wave) if current_wave else None
    if live_attempt is not None:
        live = _payload_of(live_attempt)
        status = str(live.get("status"))
        agent_id = live.get("agent_id")
        reviewed_paths = list(live.get("reviewed_paths") or [])
        local_checks = [dict(c) for c in (live.get("local_checks") or [])]
        result_fingerprints = list(live.get("result_fingerprints") or [])
        unresolved = list(live.get("unresolved") or [])
    elif current_wave:
        start_payload = _payload_of(starts[current_wave])
        status = "in_progress"
        agent_id = start_payload.get("agent_id")
        reviewed_paths = []
        local_checks = []
        result_fingerprints = []
        unresolved = []
    else:
        status = "planned"
        agent_id = None
        reviewed_paths = []
        local_checks = []
        result_fingerprints = []
        unresolved = []

    block_selection = None
    starting_paths: list[str] = []
    if current_wave:
        start_payload = _payload_of(starts[current_wave])
        selection = start_payload.get("block_selection")
        if isinstance(selection, Mapping):
            block_selection = dict(selection)
            # A record written before the capability state existed does not
            # say whether the companion catalog was there (D-032).  The
            # projection reports that as ``unknown`` instead of backfilling
            # ``unavailable``: an absent field is not evidence that the
            # catalog was missing.
            block_selection.setdefault("companion_catalog_state", "unknown")
        paths = start_payload.get("starting_paths")
        if isinstance(paths, list):
            starting_paths = [str(path) for path in paths]

    # Export eligibility (D-034): a unit that never started a wave has no
    # real starting paths, and a ledger that invents them would claim a
    # coverage nobody ran.
    export_blockers: list[str] = []
    if not current_wave:
        export_blockers.append(
            "the unit is registered but no wave has started, so its starting paths "
            "are unknown"
        )
    elif not starting_paths:
        export_blockers.append(
            f"wave {current_wave} recorded no starting paths, so the unit cannot be "
            "published as a complete upstream ledger"
        )

    return CoverageUnitProjection(
        coverage_id=coverage_id,
        canonical_refs=canonical_refs,
        prior_status=prior_status,
        wave=current_wave or 1,
        status=status,
        agent_id=agent_id if isinstance(agent_id, str) else None,
        reviewed_paths=reviewed_paths,
        local_checks=local_checks,
        result_fingerprints=result_fingerprints,
        unresolved=unresolved,
        attempts=archived,
        block_selection=block_selection,
        starting_paths=starting_paths,
        registration_event_id=registration_event_id,
        exportable=not export_blockers,
        export_blockers=export_blockers,
    )


def upstream_coverage_ledger(
    projections: Iterable[CoverageUnitProjection],
) -> list[dict[str, Any]]:
    """The projected units as an upstream coverage ledger document.

    Only units that are allowed to be published appear here (D-034): a unit
    that never started a wave is kept in the native projection, where its
    ``planned`` state is visible, but it is not dressed up as a complete
    upstream ledger.

    The upstream ledger is a top-level array whose units are sorted by
    coverage id, so the projection is sorted the same way.
    """

    units = [
        projection.to_upstream_unit()
        for projection in projections
        if projection.exportable
    ]
    units.sort(key=lambda unit: str(unit.get("coverage_id") or ""))
    return units


def upstream_ledger_export_report(
    projections: Iterable[CoverageUnitProjection],
) -> dict[str, Any]:
    """The exportable ledger and the units that were left out of it.

    Leaving a unit out silently would be the same kind of gap as inventing
    its starting paths, so the report names every unit that was not
    published and why.
    """

    materialised = list(projections)
    return {
        "units": upstream_coverage_ledger(materialised),
        "skipped": [
            {
                "coverage_id": projection.coverage_id,
                "blockers": list(projection.export_blockers),
            }
            for projection in materialised
            if not projection.exportable
        ],
    }
