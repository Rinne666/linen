"""Trusted write interface for the skill coverage event ledger (CF-S1-C).

The ledger is append-only: a registered coverage unit is written once and
never rewritten.  Everything that makes that true lives here rather than in
the routers, so the HTTP surface and the tests exercise the same rules:

* the coverage id must be the canonical id derived from the four descriptive
  dimensions, and the retired ``cov-<n>`` scheme is rejected as an active id
  (D-017);
* the uniqueness check and the insert share one transaction, so a legitimate
  retry can never slip a second row in between them;
* content comparison uses the canonical JSON digest of the payload, and the
  storage timestamp takes no part in it, so a retry compares equal to the
  original write instead of looking like a conflict;
* a registration that contradicts an already stored event is rejected, never
  silently overwritten.

The ledger records protocol history, so a caller that merely reaches the
socket is not a trusted writer.  Registration is therefore gated by a
:class:`CoverageRegistrationPolicy` that ships **disabled**: production
registration stays blocked until a trusted baseline resolver and a trusted
run plan are installed.  Nothing in the request body can switch that on
(D-026).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, Sequence

from linen.contracts.common import (
    cf_canonical_json,
    cf_is_legacy_coverage_id,
    cf_payload_digest,
)
from linen.contracts.skill_audit import UnitRegisteredPayload
from linen.server.services import utcnow


class CoverageRegistrationDisabled(RuntimeError):
    """Production coverage registration is switched off."""


class CoverageCallerUntrusted(PermissionError):
    """The caller is not an accepted coverage event writer."""


class CoverageBaselineUnavailable(RuntimeError):
    """No trustworthy historical baseline could be established."""


class CoverageUnitNotPlanned(ValueError):
    """The coverage unit is not part of the run's trusted plan."""


class CoverageRunNotFound(LookupError):
    """The run does not exist or does not belong to the project."""


class CoverageEventRejected(ValueError):
    """The request is not a legal registration event."""


class CoverageEventConflict(ValueError):
    """The registration contradicts an event that is already stored."""


class CoverageBaselineResolver(Protocol):
    """Derives the prior status of a coverage unit from real history.

    The implementation must be able to tell three situations apart: a
    verified absence of compatible history, a compatible history that was
    found, and a history that could not be established.  Only the first two
    may produce a stored prior status.
    """

    def __call__(
        self, *, project_id: str, run_id: str, coverage_id: str
    ) -> "CoverageBaselineResolution": ...


class CoveragePlanResolver(Protocol):
    """Whether a coverage unit belongs to the trusted plan of a run."""

    def __call__(self, *, project_id: str, run_id: str, coverage_id: str) -> bool: ...


@dataclass(frozen=True)
class CoverageBaselineResolution:
    """The outcome of looking for the historical baseline of a unit.

    ``state`` is ``"resolved"`` only when a prior status was actually
    derived.  ``"unknown"`` means the history could not be established and
    ``"failed"`` means the lookup itself failed; neither may be stored, and
    an unknown history is never the same thing as an absent one.
    """

    state: str
    prior_status: str | None = None
    kind: str | None = None
    lookup_ref: str | None = None
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.state == "resolved"

    @classmethod
    def resolved_status(
        cls, *, prior_status: str, kind: str, lookup_ref: str
    ) -> "CoverageBaselineResolution":
        return cls(
            state="resolved",
            prior_status=prior_status,
            kind=kind,
            lookup_ref=lookup_ref,
        )

    @classmethod
    def unknown(cls, reason: str = "the historical baseline is unknown") -> "CoverageBaselineResolution":
        return cls(state="unknown", reason=reason)

    @classmethod
    def failed(cls, reason: str = "the historical baseline lookup failed") -> "CoverageBaselineResolution":
        return cls(state="failed", reason=reason)


@dataclass(frozen=True)
class CoverageRegistrationPolicy:
    """What the server needs before it will accept a registration.

    The defaults are the safe ones: registration is off and no trusted
    resolver is installed, so a stock deployment refuses every write.
    """

    enabled: bool = False
    trusted_caller: bool = False
    baseline_resolver: CoverageBaselineResolver | None = None
    plan_resolver: CoveragePlanResolver | None = None


#: The policy a stock server runs with.
DEFAULT_REGISTRATION_POLICY = CoverageRegistrationPolicy()


@dataclass(frozen=True)
class RegisteredUnit:
    """One stored ``unit_registered`` event."""

    event_id: int
    project_id: str
    run_id: str
    coverage_id: str
    event_key: str
    payload_sha256: str
    created_at: str
    payload: UnitRegisteredPayload
    replayed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "coverage_id": self.coverage_id,
            "event_key": self.event_key,
            "payload_sha256": self.payload_sha256,
            "created_at": self.created_at,
            "payload": self.payload.model_dump(mode="json"),
            "replayed": self.replayed,
        }


@dataclass(frozen=True)
class RegisteredUnitProjection:
    """The minimal registration view rebuilt from the event stream.

    It deliberately stops at registration: no wave is invented, no attempt is
    created, and a model fact's disposition never turns into coverage.
    """

    project_id: str
    run_id: str
    coverage_id: str
    canonical_refs: dict[str, str]
    prior_status: str
    registration_event_id: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "run_id": self.run_id,
            "coverage_id": self.coverage_id,
            "canonical_refs": dict(self.canonical_refs),
            "prior_status": self.prior_status,
            "registration_event_id": self.registration_event_id,
        }


def unit_registration_event_key(coverage_id: str) -> str:
    """The idempotency key of a registration inside one run."""

    return f"unit_registered:{coverage_id}"


def resolve_registration_payload(
    policy: CoverageRegistrationPolicy,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    canonical_refs: Mapping[str, str],
) -> UnitRegisteredPayload:
    """Build the payload the server is willing to persist.

    Every value here comes from the server's own trusted sources.  A prior
    status that the request body states is never believed: the historical
    baseline has to be resolved by the installed provider, and an unknown
    history blocks the registration instead of becoming ``none``.
    """

    if not policy.enabled:
        raise CoverageRegistrationDisabled(
            "production coverage registration is disabled; no trusted writer is installed"
        )
    if not policy.trusted_caller:
        raise CoverageCallerUntrusted(
            "the caller is not an accepted coverage event writer"
        )
    if policy.plan_resolver is None:
        raise CoverageUnitNotPlanned(
            "no trusted run plan is installed, so no coverage unit can be planned"
        )
    if not policy.plan_resolver(
        project_id=project_id, run_id=run_id, coverage_id=coverage_id
    ):
        raise CoverageUnitNotPlanned(
            f"coverage unit {coverage_id} is not part of the trusted plan of run {run_id}"
        )
    if policy.baseline_resolver is None:
        raise CoverageBaselineUnavailable(
            "no trusted historical baseline resolver is installed"
        )
    resolution = policy.baseline_resolver(
        project_id=project_id, run_id=run_id, coverage_id=coverage_id
    )
    if not resolution.resolved:
        raise CoverageBaselineUnavailable(
            resolution.reason or "the historical baseline is unknown"
        )
    if not resolution.prior_status or not resolution.kind or not resolution.lookup_ref:
        raise CoverageBaselineUnavailable(
            "the historical baseline resolution is incomplete"
        )
    return UnitRegisteredPayload(
        schema_version=1,
        canonical_refs=dict(canonical_refs),
        prior_status=resolution.prior_status,
        baseline={"kind": resolution.kind, "lookup_ref": resolution.lookup_ref},
    )


def register_unit(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    payload: UnitRegisteredPayload,
) -> RegisteredUnit:
    """Record one trusted ``unit_registered`` event.

    The uniqueness check and the insert run inside a single transaction, so a
    concurrent writer can only win or lose the race cleanly: the loser sees
    the stored event and either replays it (identical payload) or is rejected
    with a conflict (different payload).
    """

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

    content = payload.digest_content()
    normalized = cf_canonical_json(content)
    digest = cf_payload_digest(content)
    event_key = unit_registration_event_key(coverage_id)

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
                    f"coverage unit {coverage_id} is already registered in run "
                    f"{run_id} with a different payload"
                )
            return RegisteredUnit(
                event_id=existing["event_id"],
                project_id=project_id,
                run_id=run_id,
                coverage_id=coverage_id,
                event_key=event_key,
                payload_sha256=existing["payload_sha256"],
                created_at=existing["created_at"],
                payload=payload,
                replayed=True,
            )

        now = utcnow()
        try:
            cursor = conn.execute(
                "INSERT INTO skill_coverage_events ("
                "project_id, run_id, coverage_id, event_type, payload_version, "
                "agent_id, wave, event_key, payload_json, payload_sha256, created_at"
                ") VALUES (?, ?, ?, 'unit_registered', 1, NULL, NULL, ?, ?, ?, ?)",
                (
                    project_id,
                    run_id,
                    coverage_id,
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
                f"coverage unit {coverage_id} is already registered in run {run_id}"
            ) from exc

        return RegisteredUnit(
            event_id=int(cursor.lastrowid),
            project_id=project_id,
            run_id=run_id,
            coverage_id=coverage_id,
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


def list_registered_units(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
) -> list[RegisteredUnit]:
    """Read the registration events of one run back in write order."""

    rows = conn.execute(
        "SELECT event_id, project_id, run_id, coverage_id, event_key, payload_json, "
        "payload_sha256, created_at FROM skill_coverage_events "
        "WHERE project_id = ? AND run_id = ? AND event_type = 'unit_registered' "
        "ORDER BY event_id",
        (project_id, run_id),
    ).fetchall()
    return [
        RegisteredUnit(
            event_id=row["event_id"],
            project_id=row["project_id"],
            run_id=row["run_id"],
            coverage_id=row["coverage_id"],
            event_key=row["event_key"],
            payload_sha256=row["payload_sha256"],
            created_at=row["created_at"],
            payload=UnitRegisteredPayload.model_validate(json.loads(row["payload_json"])),
        )
        for row in rows
    ]


def project_registered_units(
    events: Iterable[Mapping[str, object]],
) -> list[RegisteredUnitProjection]:
    """Rebuild the registration view from an append-only event stream.

    The projection is a pure function of the events, so replaying the same
    stream always yields the same unit list.  The ledger makes a duplicate
    registration inside one run impossible, so a duplicate here means the
    stream was replayed or hand-assembled; it is reported as a conflict
    instead of being resolved by a last-writer-wins rule.
    """

    projected: list[RegisteredUnitProjection] = []
    seen: set[str] = set()
    for event in events:
        coverage_id = event.get("coverage_id")
        if not isinstance(coverage_id, str) or not coverage_id:
            raise CoverageEventRejected("event has no coverage_id")
        if coverage_id in seen:
            raise CoverageEventConflict(
                f"coverage unit {coverage_id} is registered more than once"
            )
        raw = event.get("payload")
        payload = raw if isinstance(raw, UnitRegisteredPayload) else UnitRegisteredPayload.model_validate(raw)
        if payload.derived_coverage_id() != coverage_id:
            raise CoverageEventRejected(
                f"event coverage_id {coverage_id!r} does not match its canonical refs"
            )
        event_id = event.get("registration_event_id", event.get("event_id"))
        if not isinstance(event_id, int):
            raise CoverageEventRejected("event has no registration event id")
        seen.add(coverage_id)
        projected.append(
            RegisteredUnitProjection(
                project_id=str(event.get("project_id") or ""),
                run_id=str(event.get("run_id") or ""),
                coverage_id=coverage_id,
                canonical_refs=dict(payload.canonical_refs.model_dump()),
                prior_status=payload.prior_status,
                registration_event_id=event_id,
            )
        )
    return projected


def registered_unit_ids(units: Sequence[RegisteredUnit]) -> list[str]:
    """The canonical unit ids of a registration projection, in write order."""

    return [unit.coverage_id for unit in units]
