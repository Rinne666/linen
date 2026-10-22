"""Regression tests for the CF-S2-A multiwave event ledger.

The acceptance identifiers follow the product manager's S2-A matrix
(A01-A16).  The multiwave events are the second and third kind of entry in
the append-only coverage ledger: they record a unit's *history* rather than
its registration.

Two things are load bearing here and are tested accordingly:

* the server decides the order of the events, inside the transaction that
  writes them - a caller cannot declare "this is wave 3";
* the projection is a pure function of the event stream, and it never invents
  a wave, an attempt or a finding.

The last test group runs the *vendored upstream validator* over a projected
ledger, so "our attempt shape matches upstream" is a measured result rather
than a claim.  It is skipped when node is unavailable.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess

import pytest
from pydantic import ValidationError

from linen.contracts.skill_audit import (
    AttemptRecordedPayload,
    CoverageBlockSelection,
    CoverageExcludedBlock,
    CoverageLocalCheck,
    WaveStartedPayload,
)
from linen.dispatcher.analysis.cf_skill_assets import (
    VALIDATE_COVERAGE_LEDGER,
    cf_skill_dir,
    validator_command,
)
from linen.server import db
from linen.server.skill_coverage import (
    CoverageEventConflict,
    CoverageEventRejected,
    register_unit,
)
from linen.server.skill_coverage_waves import (
    DEFAULT_MULTIWAVE_POLICY,
    CoverageAttemptSourceUnavailable,
    CoverageAttemptPlan,
    CoverageMultiwaveDisabled,
    CoverageMultiwavePolicy,
    CoverageWaveOrderRejected,
    CoverageWavePlan,
    CoverageWaveSourceUnavailable,
    CoverageWaveUntrusted,
    attempt_recorded_event_key,
    list_coverage_events,
    next_wave_number,
    project_multiwave,
    record_attempt,
    record_trusted_attempt,
    record_trusted_wave_started,
    record_wave_started,
    upstream_coverage_ledger,
    wave_started_event_key,
)
from linen.contracts.skill_audit import CoverageCanonicalRefs, UnitRegisteredPayload

PROJECT = "p1"
RUN = "run-1"

AGENT_1 = "ag-w1-hunt-abcdef123456"
AGENT_2 = "ag-w2-hunt-abcdef123456"
AGENT_3 = "ag-w3-hunt-abcdef123456"

REFS = {
    "surface": "http-public-api",
    "boundary": "anonymous-to-authenticated",
    "subsystem": "authorization",
    "attack_class": "access-control",
}
COVERAGE_ID = "http-public-api::anonymous-to-authenticated::authorization::access-control"


# --- fixtures ---------------------------------------------------------------


class WavePlannerDouble:
    """A test-only trusted planner: it hands out the assignment of a wave."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, int]] = []

    def __call__(
        self, *, project_id: str, run_id: str, coverage_id: str, wave: int
    ) -> CoverageWavePlan:
        self.calls.append((project_id, run_id, coverage_id, wave))
        return CoverageWavePlan(
            agent_id=AGENT_1 if wave == 1 else AGENT_2,
            block_selection=_blocks(),
            starting_paths=["src/authz.py"],
            reassignment_reason=None if wave == 1 else "the owner was replaced",
        )


class AttemptSourceDouble:
    """A test-only trusted attempt source: the admitted evidence of a wave."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, int]] = []

    def __call__(
        self, *, project_id: str, run_id: str, coverage_id: str, wave: int
    ) -> CoverageAttemptPlan:
        self.calls.append((project_id, run_id, coverage_id, wave))
        return CoverageAttemptPlan(
            status="covered",
            reviewed_paths=["src/authz.py"],
            local_checks=[
                {
                    "agent_id": AGENT_1 if wave == 1 else AGENT_2,
                    "reviewed_paths": ["src/authz.py"],
                    "invariant": "an anonymous caller cannot read another user's record",
                    "method": "source",
                    "result": "the handler reads the record without an ownership check",
                    "artifact": None,
                }
            ],
            result_fingerprints=[],
            unresolved=[],
        )


@pytest.fixture
def board(tmp_path, monkeypatch):
    """A configured database with one project and one run."""

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')", (PROJECT,)
        )
        conn.execute(
            "INSERT INTO runs (run_id, project_id, task_type, idempotency_key, "
            "timeout_seconds, created_at, updated_at) "
            "VALUES (?, ?, 'hunt', ?, 600, 'now', 'now')",
            (RUN, PROJECT, f"idem-{PROJECT}-{RUN}"),
        )
    return tmp_path


def _register(conn: sqlite3.Connection, coverage_id: str = COVERAGE_ID) -> None:
    payload = UnitRegisteredPayload(
        schema_version=1,
        canonical_refs=CoverageCanonicalRefs(**REFS),
        prior_status="none",
        baseline={"kind": "no_compatible_ledger", "lookup_ref": "verified-absence-1"},
    )
    register_unit(
        conn,
        project_id=PROJECT,
        run_id=RUN,
        coverage_id=coverage_id,
        payload=payload,
    )


def _blocks(
    *,
    ordinary: str | None = "ATTACK-CLASSES.md#Access control",
    selected: list[str] | None = None,
    excluded: list[dict[str, str]] | None = None,
    source: str = "skill_audit.py:317",
) -> CoverageBlockSelection:
    return CoverageBlockSelection(
        ordinary_attack_class_block=ordinary,
        selected_companion_blocks=list(selected or []),
        excluded_blocks=[
            CoverageExcludedBlock(block=entry["block"], reason=entry["reason"])
            for entry in (excluded or [])
        ],
        source=source,
    )


def _check(
    *,
    agent_id: str = AGENT_1,
    paths: list[str] | None = None,
    artifact: str | None = None,
    method: str = "source",
) -> CoverageLocalCheck:
    return CoverageLocalCheck(
        agent_id=agent_id,
        reviewed_paths=list(paths or ["src/authz.py"]),
        invariant="an anonymous caller cannot read another user's record",
        method=method,
        result="the handler reads the record without an ownership check",
        artifact=artifact,
    )


def _wave(
    wave: int,
    *,
    agent_id: str = AGENT_1,
    reason: str | None = None,
    blocks: CoverageBlockSelection | None = None,
    starting_paths: list[str] | None = None,
) -> WaveStartedPayload:
    return WaveStartedPayload(
        schema_version=1,
        canonical_refs=CoverageCanonicalRefs(**REFS),
        wave=wave,
        agent_id=agent_id,
        block_selection=blocks if blocks is not None else _blocks(),
        starting_paths=list(starting_paths or ["src/authz.py"]),
        reassignment_reason=reason,
    )


def _attempt(
    wave: int,
    *,
    agent_id: str = AGENT_1,
    status: str = "covered",
    checks: list[CoverageLocalCheck] | None = None,
    fingerprints: list[str] | None = None,
    unresolved: list[str] | None = None,
) -> AttemptRecordedPayload:
    checks = list(checks if checks is not None else [_check(agent_id=agent_id)])
    return AttemptRecordedPayload(
        schema_version=1,
        canonical_refs=CoverageCanonicalRefs(**REFS),
        wave=wave,
        agent_id=agent_id,
        status=status,
        reviewed_paths=["src/authz.py"],
        local_checks=checks,
        result_fingerprints=list(fingerprints or []),
        unresolved=list(unresolved or []),
    )


def _events(conn: sqlite3.Connection) -> list[dict]:
    return list_coverage_events(conn, project_id=PROJECT, run_id=RUN)


def _projection(conn: sqlite3.Connection):
    return project_multiwave(_events(conn))


# --- A01: versioned, closed contracts ---------------------------------------


def test_wave_started_contract_is_closed_and_versioned():
    """A01: the wave payload is a closed, versioned model."""

    with pytest.raises(ValidationError):
        WaveStartedPayload(
            schema_version=2,
            canonical_refs=CoverageCanonicalRefs(**REFS),
            wave=1,
            agent_id=AGENT_1,
            block_selection=_blocks(),
        )
    with pytest.raises(ValidationError):
        WaveStartedPayload(
            schema_version=1,
            canonical_refs=CoverageCanonicalRefs(**REFS),
            wave=1,
            agent_id=AGENT_1,
            block_selection=_blocks(),
            prior_status="none",
        )


def test_attempt_recorded_contract_is_closed_and_versioned():
    """A01: the attempt payload is a closed, versioned model."""

    with pytest.raises(ValidationError):
        AttemptRecordedPayload(
            schema_version=2,
            canonical_refs=CoverageCanonicalRefs(**REFS),
            wave=1,
            agent_id=AGENT_1,
            status="covered",
        )
    with pytest.raises(ValidationError):
        AttemptRecordedPayload(
            schema_version=1,
            canonical_refs=CoverageCanonicalRefs(**REFS),
            wave=1,
            agent_id=AGENT_1,
            status="covered",
            confirmed=True,
        )


def test_attempt_status_is_terminal_only():
    """A06: only covered, candidate and blocked are terminal."""

    for status in ("planned", "in_progress", "deferred", "out_of_scope", "not_applicable"):
        with pytest.raises(ValidationError):
            AttemptRecordedPayload(
                schema_version=1,
                canonical_refs=CoverageCanonicalRefs(**REFS),
                wave=1,
                agent_id=AGENT_1,
                status=status,
            )


# --- A02: the unit has to be registered first --------------------------------


def test_wave_started_requires_registered_unit(board):
    """A02: a wave cannot start for a unit that was never registered."""

    with db.get_conn() as conn:
        with pytest.raises(CoverageEventRejected):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(1),
            )


def test_attempt_recorded_requires_registered_unit(board):
    """A02: an attempt cannot be recorded for an unregistered unit."""

    with db.get_conn() as conn:
        with pytest.raises(CoverageEventRejected):
            record_attempt(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_attempt(1),
            )


# --- A03/A04/A05: the order of the events ------------------------------------


def test_first_wave_must_be_wave_one(board):
    """A03: the first wave of a unit is wave 1."""

    with db.get_conn() as conn:
        _register(conn)
        with pytest.raises(CoverageWaveOrderRejected):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(2, agent_id=AGENT_2, reason="there was no earlier wave"),
            )


def test_wave_numbers_strictly_increase(board):
    """A03: a wave that already happened is never rewritten.

    A wave number is part of the event key, so a second wave with the same
    number is either the same event (replayed) or a contradiction (a
    conflict).  Neither may produce a second row.
    """

    with db.get_conn() as conn:
        _register(conn)
        first = record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        replay = record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        assert replay.replayed is True
        assert replay.event_id == first.event_id

        with pytest.raises(CoverageEventConflict):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(1, agent_id=AGENT_2, blocks=_blocks(source="another plan")),
            )

    with db.get_conn() as conn:
        assert len(_events(conn)) == 3


def test_wave_cannot_start_before_the_previous_attempt(board):
    """A03: a unit is only reassigned once its wave reached a terminal state."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        with pytest.raises(CoverageWaveOrderRejected):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
            )


def test_attempt_recorded_requires_started_wave(board):
    """A04: an attempt needs a wave that was started."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        with pytest.raises(CoverageWaveOrderRejected):
            record_attempt(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_attempt(2, agent_id=AGENT_2),
            )


def test_attempt_recorded_conflicting_payload_rejected(board):
    """A05: one wave may not carry two different terminal attempts."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        with pytest.raises(CoverageEventConflict):
            record_attempt(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_attempt(1, status="blocked", unresolved=["the harness is missing"]),
            )


def test_attempt_recorded_idempotent_replay(board):
    """A05: the same attempt may be replayed without a second row."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        first = record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        second = record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        assert first.replayed is False
        assert second.replayed is True
        assert second.event_id == first.event_id
        assert len(_events(conn)) == 3


def test_wave_event_transaction_rollback(board, monkeypatch):
    """A03: a rejected wave leaves nothing behind."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        before = len(_events(conn))

    from linen.server import skill_coverage_waves as waves

    original = waves.utcnow

    def _boom() -> str:
        raise RuntimeError("the clock failed")

    monkeypatch.setattr(waves, "utcnow", _boom)
    with db.get_conn() as conn:
        with pytest.raises(RuntimeError):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
            )

    with db.get_conn() as conn:
        assert len(_events(conn)) == before


# --- A08/A09/A10: owner freshness and evidence hygiene ----------------------


def test_reassignment_requires_a_reason(board):
    """A08: a reassignment states why the previous owner was replaced."""

    with pytest.raises(ValidationError):
        _wave(2, agent_id=AGENT_2, reason=None)
    with pytest.raises(ValidationError):
        _wave(1, agent_id=AGENT_1, reason="there was no previous owner")
    assert _wave(2, agent_id=AGENT_2, reason="the owner was replaced").reassignment_reason


def test_new_wave_must_not_reuse_the_previous_owner(board):
    """A09: every wave of a unit has its own owner."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        with pytest.raises(CoverageWaveOrderRejected):
            record_wave_started(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_wave(2, agent_id=AGENT_1, reason="the owner was replaced"),
            )


def test_attempt_owner_must_own_the_wave(board):
    """A09: an attempt is recorded under the owner of its wave."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        with pytest.raises(CoverageWaveOrderRejected):
            record_attempt(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_attempt(1, agent_id=AGENT_3),
            )


def test_local_artifact_must_be_owned_by_its_own_agent():
    """A10: an artifact belongs to the agent that produced it."""

    with pytest.raises(ValidationError):
        _check(
            agent_id=AGENT_2,
            artifact=f"agents/{AGENT_1}/artifacts/report.md",
            method="local",
        )


def test_artifact_is_not_reused_within_an_attempt(board):
    """A10: the same artifact may not be cited twice by one attempt."""

    artifact = f"agents/{AGENT_1}/artifacts/report.md"
    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        with pytest.raises(CoverageWaveOrderRejected):
            record_attempt(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
                payload=_attempt(
                    1,
                    checks=[
                        _check(agent_id=AGENT_1, artifact=artifact, method="local"),
                        _check(agent_id=AGENT_1, artifact=artifact, method="local"),
                    ],
                ),
            )


def test_archived_artifact_is_not_reused_by_a_later_attempt(board):
    """A10: an artifact of an earlier attempt cannot be reused.

    A later owner may not cite the earlier owner's artifact at all: the
    contract already refuses it, because an artifact has to live under the
    agent that produced it.
    """

    artifact = f"agents/{AGENT_1}/artifacts/report.md"
    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_attempt(
                1,
                checks=[
                    _check(agent_id=AGENT_1, artifact=artifact, method="local")
                ],
            ),
        )
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
        )
        with pytest.raises(ValidationError):
            _attempt(
                2,
                agent_id=AGENT_2,
                checks=[
                    _check(agent_id=AGENT_2, artifact=artifact, method="local")
                ],
            )


# --- A11/A12: the block map has a traceable source --------------------------


def test_block_selection_requires_a_source():
    """A11/A12: a block map that cannot be traced is not a trusted record."""

    with pytest.raises(ValidationError):
        CoverageBlockSelection(
            ordinary_attack_class_block="ATTACK-CLASSES.md#Access control",
            source="",
        )


def test_excluded_blocks_need_a_reason_and_may_not_be_selected():
    """A12: an exclusion states its reason and never overlaps a selection."""

    with pytest.raises(ValidationError):
        CoverageBlockSelection(
            selected_companion_blocks=["WEB-PROTOCOL-AND-AUTH.md#Cache behavior"],
            excluded_blocks=[
                {
                    "block": "WEB-PROTOCOL-AND-AUTH.md#Cache behavior",
                    "reason": "the route is not cached",
                }
            ],
            source="plan",
        )
    with pytest.raises(ValidationError):
        CoverageBlockSelection(
            excluded_blocks=[{"block": "X.md#y", "reason": ""}],
            source="plan",
        )


def test_block_selection_is_recorded_with_the_wave(board):
    """A11/A12: the block map of a wave is stored with the wave."""

    blocks = _blocks(
        selected=["WEB-PROTOCOL-AND-AUTH.md#Cache behavior"],
        excluded=[
            {
                "block": "CLIENT-SIDE.md#Storage",
                "reason": "the surface is server side only",
            }
        ],
        source="dispatcher/tasks/skill_audit.py:317",
    )
    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(1, blocks=blocks),
        )
        projection = _projection(conn)[0]
        assert projection.block_selection is not None
        assert projection.block_selection["ordinary_attack_class_block"] == (
            "ATTACK-CLASSES.md#Access control"
        )
        assert projection.block_selection["selected_companion_blocks"] == [
            "WEB-PROTOCOL-AND-AUTH.md#Cache behavior"
        ]
        assert projection.block_selection["source"] == "dispatcher/tasks/skill_audit.py:317"


# --- A13/A14: the projection neither invents nor forgets ---------------------


def test_projection_does_not_invent_missing_wave(board):
    """A13: a registered unit without a wave stays planned."""

    with db.get_conn() as conn:
        _register(conn)
        projection = _projection(conn)[0]
        assert projection.status == "planned"
        assert projection.agent_id is None
        assert projection.attempts == []
        assert projection.block_selection is None
        assert projection.wave == 1


def test_projection_does_not_invent_missing_attempt(board):
    """A13: a wave without a terminal record is in progress, not archived."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        projection = _projection(conn)[0]
        assert projection.status == "in_progress"
        assert projection.agent_id == AGENT_1
        assert projection.attempts == []
        assert projection.reviewed_paths == []


def test_projection_does_not_confirm_finding(board):
    """A13: a candidate attempt stays a candidate."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_attempt(1, status="candidate", fingerprints=["FP-1"]),
        )
        projection = _projection(conn)[0]
        assert projection.status == "candidate"
        assert projection.result_fingerprints == ["FP-1"]
        assert projection.unresolved == []


def test_multiwave_projection_is_deterministic(board):
    """A14: replaying the same stream yields the same projection."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
        )
        record_attempt(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_attempt(2, agent_id=AGENT_2, status="blocked", unresolved=["no harness"]),
        )
        first = [row.to_dict() for row in _projection(conn)]
        second = [row.to_dict() for row in _projection(conn)]
        assert first == second
        assert first[0]["attempts"][0]["reassignment_reason"] == "the owner was replaced"


def test_projection_archives_only_settled_waves(board):
    """A07: the archived attempts are the settled earlier waves."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
        )
        projection = _projection(conn)[0]
        assert projection.wave == 2
        assert [attempt["wave"] for attempt in projection.attempts] == [1]
        assert projection.attempts[0]["wave"] < projection.wave
        assert projection.attempts[0]["reassignment_reason"] == "the owner was replaced"
        # The last wave has no terminal record yet, so it is the live one.
        assert projection.status == "in_progress"
        assert projection.agent_id == AGENT_2


def test_last_wave_is_not_archived_without_a_next_wave(board):
    """A07: the last wave stays live; it is not archived and gets no reason."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        projection = _projection(conn)[0]
        assert projection.wave == 1
        assert projection.attempts == []
        assert projection.status == "covered"


# --- A16: production stays closed --------------------------------------------


def test_multiwave_production_policy_remains_disabled():
    """A16: a stock server records no multiwave event."""

    assert DEFAULT_MULTIWAVE_POLICY.enabled is False
    assert DEFAULT_MULTIWAVE_POLICY.trusted_caller is False
    assert DEFAULT_MULTIWAVE_POLICY.wave_planner is None
    assert DEFAULT_MULTIWAVE_POLICY.attempt_source is None


def test_trusted_entry_point_is_closed_by_default(board):
    """A16: the production entry point refuses without an installed policy."""

    with db.get_conn() as conn:
        _register(conn)
        with pytest.raises(CoverageMultiwaveDisabled):
            record_trusted_wave_started(
                conn,
                policy=DEFAULT_MULTIWAVE_POLICY,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
            )
        with pytest.raises(CoverageMultiwaveDisabled):
            record_trusted_attempt(
                conn,
                policy=DEFAULT_MULTIWAVE_POLICY,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
            )


def test_trusted_entry_point_needs_a_trusted_caller(board):
    """A16: an untrusted caller is refused before anything is written."""

    policy = CoverageMultiwavePolicy(
        enabled=True, trusted_caller=False, wave_planner=WavePlannerDouble()
    )
    with db.get_conn() as conn:
        _register(conn)
        with pytest.raises(CoverageWaveUntrusted):
            record_trusted_wave_started(
                conn,
                policy=policy,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE_ID,
            )


def test_trusted_entry_point_derives_the_wave_and_the_owner(board):
    """A16: the wave number and the owner come from the server's sources."""

    planner = WavePlannerDouble()
    policy = CoverageMultiwavePolicy(
        enabled=True, trusted_caller=True, wave_planner=planner
    )
    with db.get_conn() as conn:
        _register(conn)
        recorded = record_trusted_wave_started(
            conn,
            policy=policy,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
        )
        assert recorded.event_type == "wave_started"
        assert planner.calls == [(PROJECT, RUN, COVERAGE_ID, 1)]
        payload = recorded.payload
        assert payload.wave == 1
        assert payload.agent_id == AGENT_1
        assert payload.reassignment_reason is None


def test_trusted_entry_point_derives_the_attempt_owner(board):
    """A16: an attempt is filed under the owner that holds the wave."""

    planner = WavePlannerDouble()
    source = AttemptSourceDouble()
    policy = CoverageMultiwavePolicy(
        enabled=True,
        trusted_caller=True,
        wave_planner=planner,
        attempt_source=source,
    )
    with db.get_conn() as conn:
        _register(conn)
        record_trusted_wave_started(
            conn,
            policy=policy,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
        )
        recorded = record_trusted_attempt(
            conn,
            policy=policy,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
        )
        assert recorded.event_type == "attempt_recorded"
        assert recorded.payload.agent_id == AGENT_1
        assert source.calls == [(PROJECT, RUN, COVERAGE_ID, 1)]
        assert recorded.payload.status == "covered"


def test_multiwave_is_not_reachable_over_http(board):
    """A16: the public endpoint still only accepts unit_registered."""

    from fastapi.testclient import TestClient

    from linen.server.app import app

    body = {
        "run_id": RUN,
        "event_type": "wave_started",
        "payload_version": 1,
        "coverage_id": COVERAGE_ID,
        "canonical_refs": REFS,
    }
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 422


# --- the trusted provider interface -----------------------------------------


def test_wave_plan_is_the_source_of_the_wave_payload(board):
    """The wave plan is a trusted source, not a request field."""

    plan = CoverageWavePlan(
        agent_id=AGENT_1,
        block_selection=_blocks(source="plan"),
        starting_paths=["src/authz.py"],
        reassignment_reason=None,
    )
    assert plan.agent_id == AGENT_1
    assert plan.block_selection.source == "plan"
    assert CoverageMultiwavePolicy(
        enabled=True, trusted_caller=True
    ).wave_planner is None


# --- upstream compatibility --------------------------------------------------


def _upstream_validator_available() -> bool:
    return shutil.which("node") is not None


@pytest.mark.skipif(not _upstream_validator_available(), reason="node is not installed")
def test_cf_attempt_projection_matches_upstream(board, tmp_path):
    """The projected ledger passes the pinned upstream validator."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_attempt(
                1,
                checks=[
                    _check(
                        agent_id=AGENT_1,
                        artifact=f"agents/{AGENT_1}/artifacts/report.md",
                        method="local",
                    )
                ],
            ),
        )
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(2, agent_id=AGENT_2, reason="the owner was replaced"),
        )
        record_attempt(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_attempt(
                2,
                agent_id=AGENT_2,
                status="blocked",
                checks=[
                    _check(
                        agent_id=AGENT_2,
                        artifact=f"agents/{AGENT_2}/artifacts/report.md",
                        method="local",
                    )
                ],
                unresolved=["the harness cannot replay the request"],
            ),
        )
        ledger = upstream_coverage_ledger(_projection(conn))

    target = tmp_path / "coverage-ledger.json"
    target.write_text(json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8")
    result = subprocess.run(
        validator_command(cf_skill_dir() / VALIDATE_COVERAGE_LEDGER, target),
        capture_output=True,
        text=True,
        cwd=str(cf_skill_dir()),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


@pytest.mark.skipif(not _upstream_validator_available(), reason="node is not installed")
def test_cf_attempt_reassignment_reason_mapping(board, tmp_path):
    """The reason of the next wave is the reason of the archived attempt."""

    with db.get_conn() as conn:
        _register(conn)
        record_wave_started(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_wave(1)
        )
        record_attempt(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=COVERAGE_ID, payload=_attempt(1)
        )
        record_wave_started(
            conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE_ID,
            payload=_wave(2, agent_id=AGENT_2, reason="the critic found the owner unavailable"),
        )
        ledger = upstream_coverage_ledger(_projection(conn))

    assert ledger[0]["attempts"][0]["reassignment_reason"] == (
        "the critic found the owner unavailable"
    )
    target = tmp_path / "coverage-ledger.json"
    target.write_text(json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8")
    result = subprocess.run(
        validator_command(cf_skill_dir() / VALIDATE_COVERAGE_LEDGER, target),
        capture_output=True,
        text=True,
        cwd=str(cf_skill_dir()),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_event_keys_are_deterministic():
    """The idempotency keys follow the frozen shape."""

    assert wave_started_event_key(COVERAGE_ID, 1) == f"wave_started:{COVERAGE_ID}:1"
    assert attempt_recorded_event_key(COVERAGE_ID, 2) == f"attempt_recorded:{COVERAGE_ID}:2"
    assert os.sep not in wave_started_event_key(COVERAGE_ID, 1)
