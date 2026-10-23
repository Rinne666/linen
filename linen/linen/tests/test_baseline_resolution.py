"""Regression tests for the trusted prior status resolution (CF-S2-B2-C).

The resolver answers one question - *what does the history say about this
coverage unit?* - with exactly one of the eleven upstream ``prior_status``
values, or with nothing at all.

The boundaries that matter:

* **``unknown`` is not a twelfth prior status.**  A resolution that does not
  know carries an empty ``prior_status``; the contract refuses to hold one
  (B2-C-T01);
* ``none`` and ``new`` are different claims: ``none`` says there is no
  compatible historical ledger at all, ``new`` says a compatible ledger exists
  and this unit is new in it (B2-C-T02, B2-C-T03);
* both of them need a **trusted, complete** scope - an unverified or partial
  scope proves nothing about an absence (B2-C-T04, B2-C-T05);
* a historical unit's coverage state and a historical verdict are different
  things, and the verdict wins when it is trusted (B2-C-T06 - B2-C-T09);
* a source comparison that could not be made is never turned into "same" or
  "changed" (B2-C-T10);
* the resolution is a pure function of its trusted inputs (B2-C-T11).

The acceptance ids follow the PM's B2-C matrix (PM v3.0, section 3.3/3.4).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from linen.contracts.baseline import (
    CF_PRIOR_STATUSES,
    PriorStatusResolution,
    PriorStatusResolutionState,
    SourceComparisonResult,
)
from linen.server import db
from linen.server.baseline_resolution import (
    VERDICT_CONFIRMED,
    VERDICT_NEEDS_VALIDATION,
    VERDICT_REJECTED,
    CurrentClaim,
    HistoricalUnitState,
    TrustedHistoricalVerdict,
    TrustedHistoryScope,
    resolve_prior_status,
    unit_state_from_ledgers,
)

PROJECT = "p-resolve"
RUN = "run-current"
COVERAGE = "surface::boundary::subsystem::attack-class"
OTHER = "surface::boundary::subsystem::other-class"


def _scope(
    *,
    trusted_negative: bool = True,
    complete: bool = True,
    members: tuple[str, ...] = ("acme/app/run-1",),
    conflict: bool = False,
) -> TrustedHistoryScope:
    return TrustedHistoryScope(
        trusted_negative=trusted_negative,
        complete=complete,
        scope_kind="declared_predecessor_lineage",
        member_source_refs=members,
        seal_ref="cf-ref-v1:seal",
        conflict=conflict,
    )


def _unit(status: str = "covered", *, coverage_id: str = COVERAGE) -> HistoricalUnitState:
    return HistoricalUnitState(
        coverage_id=coverage_id,
        present=True,
        status=status,
        fingerprints=("F-1",) if status == "candidate" else (),
        source_ref="acme/app/run-1",
    )


def _comparison(outcome: str) -> SourceComparisonResult:
    if outcome == "same":
        return SourceComparisonResult(
            project_id=PROJECT,
            historical_source_ref="acme/app/run-1",
            outcome="same",
            relevant_paths=["app.py"],
            compared_paths=["app.py"],
        )
    if outcome == "changed":
        return SourceComparisonResult(
            project_id=PROJECT,
            historical_source_ref="acme/app/run-1",
            outcome="changed",
            relevant_paths=["app.py"],
            changed_paths=["app.py"],
        )
    return SourceComparisonResult(
        project_id=PROJECT,
        historical_source_ref="acme/app/run-1",
        outcome="unknown",
        relevant_paths=["app.py"],
        unknown_paths=["app.py"],
    )


def _verdict(
    verdict: str, *, fingerprint: str = "F-1", evidence_sha256: str = "a" * 64
) -> TrustedHistoricalVerdict:
    return TrustedHistoricalVerdict(
        coverage_id=COVERAGE,
        fingerprint=fingerprint,
        verdict=verdict,
        evidence_ref="cf-ref-v1:verdict",
        evidence_sha256=evidence_sha256,
    )


def _resolve(**kwargs):
    payload = {
        "project_id": PROJECT,
        "run_id": RUN,
        "coverage_id": COVERAGE,
        "scope": _scope(),
        "unit": _unit(),
        "comparison": _comparison("same"),
        "read_source_refs": ("acme/app/run-1",),
    }
    payload.update(kwargs)
    return resolve_prior_status(**payload)


# --- the eleven values ------------------------------------------------------


def test_b2_c_t02_no_compatible_history_is_none():
    """B2-C-T02: a trusted, complete and empty scope is ``none``."""

    result = _resolve(scope=_scope(members=()), unit=None, comparison=None)
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == "none"
    assert result.reason_code == "no_compatible_history"


def test_b2_c_t03_a_new_unit_in_an_existing_history_is_new():
    """B2-C-T03: compatible history exists, this unit is new in it."""

    result = _resolve(unit=None, comparison=None)
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == "new"
    assert result.reason_code == "unit_absent_from_complete_history"


@pytest.mark.parametrize(
    ("status", "outcome", "expected"),
    [
        ("covered", "same", "prior_covered_same_source"),
        ("covered", "changed", "prior_covered_changed_source"),
        ("deferred", "same", "prior_deferred"),
        ("blocked", "same", "prior_blocked"),
        ("out_of_scope", "same", "prior_out_of_scope"),
    ],
)
def test_b2_c_t06_the_coverage_state_of_the_historical_unit(status, outcome, expected):
    """B2-C-T06: the historical coverage state maps to its own value."""

    result = _resolve(unit=_unit(status), comparison=_comparison(outcome))
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == expected


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("same", "prior_confirmed_same_source"),
        ("changed", "prior_confirmed_changed_source"),
    ],
)
def test_b2_c_t07_a_confirmed_verdict_uses_the_source_comparison(outcome, expected):
    """B2-C-T07: a confirmed historical finding follows the source."""

    result = _resolve(
        unit=_unit("candidate"),
        comparison=_comparison(outcome),
        verdict=_verdict(VERDICT_CONFIRMED),
    )
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == expected


def test_b2_c_t08_a_finding_that_still_needs_validation():
    """B2-C-T08: a finding that still needs validation keeps its blocking reason."""

    result = _resolve(
        unit=_unit("candidate"),
        comparison=_comparison("changed"),
        verdict=_verdict(VERDICT_NEEDS_VALIDATION),
    )
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == "prior_needs_validation"


def test_b2_c_t09_a_rejected_claim_with_new_evidence_may_enter_again():
    """B2-C-T09: a rejected claim re-enters only with evidence it never saw."""

    result = _resolve(
        unit=_unit("candidate"),
        comparison=_comparison("changed"),
        verdict=_verdict(VERDICT_REJECTED, evidence_sha256="a" * 64),
        current_claim=CurrentClaim(
            fingerprint="F-1", evidence_ref="cf-ref-v1:claim", evidence_sha256="b" * 64
        ),
    )
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == "prior_rejected_claim_changed"


def test_every_upstream_value_is_reachable():
    """B2-C: the mapping reaches all eleven upstream values."""

    reached = {
        _resolve(scope=_scope(members=()), unit=None, comparison=None).prior_status,
        _resolve(unit=None, comparison=None).prior_status,
        _resolve(
            unit=_unit("candidate"),
            comparison=_comparison("same"),
            verdict=_verdict(VERDICT_CONFIRMED),
        ).prior_status,
        _resolve(
            unit=_unit("candidate"),
            comparison=_comparison("changed"),
            verdict=_verdict(VERDICT_CONFIRMED),
        ).prior_status,
        _resolve(
            unit=_unit("candidate"),
            comparison=_comparison("same"),
            verdict=_verdict(VERDICT_NEEDS_VALIDATION),
        ).prior_status,
        _resolve(unit=_unit("deferred")).prior_status,
        _resolve(unit=_unit("blocked")).prior_status,
        _resolve(unit=_unit("out_of_scope")).prior_status,
        _resolve(unit=_unit("covered"), comparison=_comparison("same")).prior_status,
        _resolve(unit=_unit("covered"), comparison=_comparison("changed")).prior_status,
        _resolve(
            unit=_unit("candidate"),
            comparison=_comparison("changed"),
            verdict=_verdict(VERDICT_REJECTED, evidence_sha256="a" * 64),
            current_claim=CurrentClaim(
                fingerprint="F-1", evidence_ref="cf-ref-v1:claim", evidence_sha256="b" * 64
            ),
        ).prior_status,
    }
    assert reached == set(CF_PRIOR_STATUSES)


# --- the negative paths -----------------------------------------------------


def test_b2_c_t01_an_unknown_resolution_carries_no_prior_status():
    """B2-C-T01: ``unknown`` is not a twelfth prior status."""

    result = _resolve(scope=_scope(trusted_negative=False))
    assert result.state == PriorStatusResolutionState.unknown
    assert result.prior_status == ""
    assert result.reason_code == "history_scope_not_trusted"

    with pytest.raises(ValidationError):
        PriorStatusResolution(
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE,
            state=PriorStatusResolutionState.unknown,
            prior_status="none",
            reason_code="history_scope_not_trusted",
            resolution_digest="0" * 64,
        )


def test_b2_c_t04_an_untrusted_scope_proves_no_absence():
    """B2-C-T04: without a verified seal, an absence is not a conclusion."""

    result = _resolve(scope=_scope(trusted_negative=False), unit=None, comparison=None)
    assert result.state == PriorStatusResolutionState.unknown
    assert result.prior_status == ""
    assert result.reason_code == "history_scope_not_trusted"


def test_b2_c_t05_an_incomplete_scope_proves_no_absence():
    """B2-C-T05: a partial scope may prove existence, never absence."""

    result = _resolve(scope=_scope(complete=False), unit=None, comparison=None)
    assert result.state == PriorStatusResolutionState.unknown
    assert result.reason_code == "history_scope_not_trusted"


def test_an_unread_history_member_blocks_an_absence_claim():
    """``new`` is a claim about every member: one unread member blocks it."""

    result = _resolve(
        scope=_scope(members=("acme/app/run-1", "acme/app/run-2")),
        unit=None,
        comparison=None,
        read_source_refs=("acme/app/run-1",),
    )
    assert result.state == PriorStatusResolutionState.unknown
    assert result.prior_status == ""
    assert result.reason_code == "history_scope_not_read"


def test_a_conflicting_scope_fails():
    """A scope that contradicts itself was not searched."""

    result = _resolve(scope=_scope(conflict=True))
    assert result.state == PriorStatusResolutionState.failed
    assert result.prior_status == ""
    assert result.reason_code == "history_scope_conflict"


def test_b2_c_t10_an_unknown_comparison_is_never_same_or_changed():
    """B2-C-T10: an undecided source stays undecided."""

    result = _resolve(unit=_unit("covered"), comparison=_comparison("unknown"))
    assert result.state == PriorStatusResolutionState.unknown
    assert result.prior_status == ""
    assert result.reason_code == "source_comparison_unknown"

    confirmed = _resolve(
        unit=_unit("candidate"),
        comparison=_comparison("unknown"),
        verdict=_verdict(VERDICT_CONFIRMED),
    )
    assert confirmed.state == PriorStatusResolutionState.unknown
    assert confirmed.reason_code == "source_comparison_unknown"


def test_a_candidate_without_a_trusted_verdict_is_unknown():
    """A finding whose verdict nobody verified is not a prior status."""

    result = _resolve(unit=_unit("candidate"), verdict=None)
    assert result.state == PriorStatusResolutionState.unknown
    assert result.reason_code == "no_trusted_historical_verdict"


def test_a_unit_without_evidence_is_unknown():
    """A unit that was only registered carries no evidence."""

    result = _resolve(unit=_unit("planned"), comparison=None)
    assert result.state == PriorStatusResolutionState.unknown
    assert result.reason_code == "historical_unit_has_no_evidence"


def test_a_rejection_without_a_current_claim_does_not_reopen():
    """A rejection without new evidence only blocks the same claim."""

    result = _resolve(
        unit=_unit("candidate"),
        comparison=_comparison("changed"),
        verdict=_verdict(VERDICT_REJECTED),
        current_claim=None,
    )
    assert result.state == PriorStatusResolutionState.unknown
    assert result.prior_status == ""
    assert result.reason_code == "no_trusted_historical_verdict"


def test_conflicting_historical_units_fail():
    """Two members that disagree about the unit are a conflict, not a choice."""

    result = _resolve(unit_conflict=True)
    assert result.state == PriorStatusResolutionState.failed
    assert result.reason_code == "history_scope_conflict"


# --- the resolution itself --------------------------------------------------


def test_b2_c_t11_the_same_inputs_give_the_same_resolution():
    """B2-C-T11: the resolution is a pure function of its trusted inputs."""

    first = _resolve(unit=_unit("candidate"), verdict=_verdict(VERDICT_CONFIRMED))
    second = _resolve(unit=_unit("candidate"), verdict=_verdict(VERDICT_CONFIRMED))
    assert first.resolution_digest == second.resolution_digest
    assert first.prior_status == second.prior_status


def test_the_resolution_names_the_evidence_it_used():
    """A reviewer has to be able to find the history a resolution read."""

    result = _resolve(
        unit=_unit("covered"),
        comparison=_comparison("same"),
        source_attestation_refs=["cf-ref-v1:attestation"],
    )
    assert result.lineage_seal_ref == "cf-ref-v1:seal"
    assert "cf-ref-v1:attestation" in result.source_attestation_refs
    assert result.source_comparison_digest
    assert "cf-ref-v1:seal" in result.evidence_refs


def test_the_unit_state_is_read_from_the_registered_ledgers():
    """The historical unit state comes from the ledger bytes themselves."""

    ledger = (
        '[{"coverage_id": "%s", "status": "covered", "reviewed_paths": ["a.py"], '
        '"local_checks": [], "result_fingerprints": [], "unresolved": []}]' % COVERAGE
    ).encode("utf-8")
    other = (
        '[{"coverage_id": "%s", "status": "blocked", "reviewed_paths": ["b.py"], '
        '"local_checks": [], "result_fingerprints": [], "unresolved": []}]' % OTHER
    ).encode("utf-8")
    state, conflict = unit_state_from_ledgers(
        {"acme/app/run-1": ledger, "acme/app/run-2": other}, coverage_id=COVERAGE
    )
    assert state is not None
    assert state.present is True
    assert state.status == "covered"
    assert conflict is False

    missing, conflict = unit_state_from_ledgers(
        {"acme/app/run-1": other}, coverage_id=COVERAGE
    )
    assert missing is None
    assert conflict is False


def test_two_members_that_disagree_about_the_unit_conflict():
    """The first member does not win; the conflict is reported."""

    one = (
        '[{"coverage_id": "%s", "status": "covered", "reviewed_paths": ["a.py"], '
        '"local_checks": [], "result_fingerprints": [], "unresolved": []}]' % COVERAGE
    ).encode("utf-8")
    two = (
        '[{"coverage_id": "%s", "status": "blocked", "reviewed_paths": ["a.py"], '
        '"local_checks": [], "result_fingerprints": [], "unresolved": []}]' % COVERAGE
    ).encode("utf-8")
    state, conflict = unit_state_from_ledgers(
        {"acme/app/run-1": one, "acme/app/run-2": two}, coverage_id=COVERAGE
    )
    assert state is not None
    assert conflict is True


# --- the controlled entry point ----------------------------------------------


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')",
            (PROJECT,),
        )
    return tmp_path


def test_the_controlled_entry_point_gathers_the_trusted_scope(
    board, tmp_path, validation_auth_key
):
    """B2-C: the entry point reads the scope itself and refuses to guess."""

    from linen.dispatcher.analysis.cf_baseline_validation import (
        resolve_prior_status as resolve_entry,
        seal_historical_scope,
    )
    from linen.server.skill_baseline_sources import seal_lineage_manifest

    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, project_id, task_type, idempotency_key, "
            "timeout_seconds, created_at, updated_at) "
            "VALUES (?, ?, 'audit', ?, 60, 'now', 'now')",
            (RUN, PROJECT, f"idem-{RUN}-{PROJECT}"),
        )
        manifest = seal_lineage_manifest(
            conn, project_id=PROJECT, members=[], scope_kind="lineage_root"
        )
        seal_historical_scope(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="2026-01-01T00:00:00Z",
        )

    with db.get_conn() as conn:
        result = resolve_entry(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN,
            coverage_id=COVERAGE,
            historical_ledgers={},
        )
    assert result.state == PriorStatusResolutionState.resolved
    assert result.prior_status == "none"
    assert result.reason_code == "no_compatible_history"
    assert result.lineage_seal_ref


def test_the_controlled_entry_point_refuses_unregistered_ledgers(
    board, validation_auth_key
):
    """B2-C: a ledger that is not the registered one may not be read."""

    from linen.dispatcher.analysis.cf_baseline_validation import (
        resolve_prior_status as resolve_entry,
    )
    from linen.server.baseline_resolution import BaselineResolutionRejected

    with db.get_conn() as conn:
        with pytest.raises(BaselineResolutionRejected):
            resolve_entry(
                conn=conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=COVERAGE,
                historical_ledgers={"acme/app/run-1": b"[]"},
            )
