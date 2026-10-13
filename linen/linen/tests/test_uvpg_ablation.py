"""Small UVPG review ablation matrix.

This is intentionally a regression matrix, not a benchmark framework.  It
compares the legacy per-Fact compatibility path with the candidate-local proof
review and records the two safety properties that matter: a real proof still
confirms, while missing or contradictory independent review does not.
"""
from __future__ import annotations

from linen.server import db
from linen.server.models import ConcludeRequest, CreateReviewRequest, ProofPayload
from linen.server.routers.intents import conclude
from linen.server.routers.projects import plan_proof_gap
from linen.server.routers.reviews import create_review
from linen.server import uvpg
from linen.server.dynamic_verification import evaluate_dynamic_verification
from linen.server.uvpg import (
    REQUIRED_ROLES,
    collect_candidate_proof_subgraph,
    evaluate_proof_gate,
    evaluate_shadow_gate,
)

from test_uvpg import _strict_board


def _completion_with_package(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET audit_mode = 'scope' WHERE id = 'p'")
        conn.execute("DELETE FROM reviews")
        conn.execute("UPDATE facts SET status = 'draft', evidence = 'api.py:1' WHERE project_id = 'p'")
        identifiers = [row[0] for row in conn.execute("SELECT id FROM facts WHERE project_id = 'p'")]
        for fid in identifiers:
            iid = 'produce-' + fid
            conn.execute("INSERT INTO intents (id,project_id,to_fact_id,description,creator,created_at,concluded_at) VALUES (?,'p',?,'fixture claim','fixture','now','now')", (iid, fid))
            conn.execute("INSERT INTO intent_sources (intent_id,project_id,fact_id) VALUES (?,'p','origin')", (iid,))
        conn.execute("INSERT INTO facts (id,project_id,description,type,evidence,status) VALUES ('summary','p','bounded','audit_summary','fixture summary','triaged')")
        conn.execute("INSERT INTO intents (id,project_id,to_fact_id,description,creator,created_at,concluded_at) VALUES ('summarize','p','summary','@analysis:audit-summary','fixture','now','now')")
        for fid in identifiers:
            conn.execute("INSERT INTO intent_sources (intent_id,project_id,fact_id) VALUES ('summarize','p',?)", (fid,))
    from copy import deepcopy
    from test_uvpg import REPORTABLE_ASSESSMENT

    # An acknowledged design weakness reaches a terminal assessment without
    # Technical Confirmation, while its package review still binds the atoms.
    assessment = deepcopy(REPORTABLE_ASSESSMENT)
    assessment.update(classification='design_weakness', threat_model_status='acknowledged_design_weakness')
    from linen.server.routers.projects import get_proof_package

    packet = get_proof_package('p', 'candidate')
    verification = dict(_unified_review().cold_verification)
    verification['proof_input_sha256'] = packet['proof_input_sha256']
    verification.update(input_source_generation=packet['source_generation'], input_plan_revision=packet['plan_revision'])
    request = _unified_review().model_copy(update={'finding_assessment': assessment, 'cold_verification': verification})
    create_review('p', 'candidate', request)


def test_completion_accepts_only_the_current_reviewed_package_without_mutating_atoms(tmp_path, monkeypatch):
    from linen.server.services import audit_completion_blockers_from_db

    _completion_with_package(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        assert audit_completion_blockers_from_db(conn, 'p', ['summary']) == []
        assert conn.execute("SELECT status FROM facts WHERE id = 'capability_before'").fetchone()[0] == 'draft'
        assert conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0] == 1


def test_changed_proof_atom_reopens_completion_even_with_earlier_valid_package(tmp_path, monkeypatch):
    from linen.server.services import audit_completion_blockers_from_db

    _completion_with_package(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET description = 'changed capability' WHERE id = 'capability_before'")
        blockers = audit_completion_blockers_from_db(conn, 'p', ['summary'])
    assert any('capability_before' in item for item in blockers)


def test_later_unresolved_atom_review_cannot_be_hidden_by_package_review(tmp_path, monkeypatch):
    from linen.server.services import audit_completion_blockers_from_db

    _completion_with_package(tmp_path, monkeypatch)
    create_review('p', 'capability_before', CreateReviewRequest(verdict='NEEDS_REVIEW', confidence='firm', summary='guard remains uncertain', created_by='reviewer'))
    with db.get_conn() as conn:
        blockers = audit_completion_blockers_from_db(conn, 'p', ['summary'])
    assert any('capability_before' in item for item in blockers)


def test_stale_package_review_cannot_attest_to_new_claims(tmp_path, monkeypatch):
    from linen.server.routers.projects import get_proof_package
    from fastapi import HTTPException
    import pytest

    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
    packet = get_proof_package('p', 'candidate')
    assert 'reviews' not in packet and 'hints' not in packet
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET description = 'different impact' WHERE id = 'impact_observation'")
    verification = dict(_unified_review().cold_verification)
    verification['proof_input_sha256'] = packet['proof_input_sha256']
    verification.update(input_source_generation=packet['source_generation'], input_plan_revision=packet['plan_revision'])
    with pytest.raises(HTTPException) as caught:
        create_review('p', 'candidate', _unified_review().model_copy(update={'cold_verification': verification}))
    assert caught.value.status_code == 409
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0] == 0


def test_legacy_package_marker_alone_does_not_close_draft_atom_ancestry(tmp_path, monkeypatch):
    from linen.server.services import audit_completion_blockers_from_db
    import json

    _completion_with_package(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        row = conn.execute("SELECT id,diagnostics FROM reviews").fetchone()
        diagnostics = json.loads(row['diagnostics'])
        diagnostics['cold_verification'].pop('proof_input_sha256')
        conn.execute("UPDATE reviews SET diagnostics = ? WHERE id = ?", (json.dumps(diagnostics), row['id']))
        blockers = audit_completion_blockers_from_db(conn, 'p', ['summary'])
    assert any('capability_before' in item for item in blockers)


def test_replan_invalidates_the_reviewed_package_basis(tmp_path, monkeypatch):
    from linen.server.services import audit_completion_blockers_from_db

    _completion_with_package(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET plan_revision = plan_revision + 1 WHERE id = 'p'")
        blockers = audit_completion_blockers_from_db(conn, 'p', ['summary'])
    assert any('capability_before' in item for item in blockers)


def _unified_review() -> CreateReviewRequest:
    return CreateReviewRequest(
        verdict="VALID",
        confidence="firm",
        summary="independently reviewed complete proof package",
        created_by="ablation-reviewer",
        cold_verification={
            "review_kind": "vulnerability_proof",
            "candidate_id": "candidate",
        },
    )


def test_ablation_a0_legacy_and_a1_unified_both_confirm_real_proof(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        legacy = evaluate_proof_gate(conn, "p", "candidate")
    assert legacy.status == "PASS"

    isolated = tmp_path / "unified"
    isolated.mkdir()
    _strict_board(isolated, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
    create_review("p", "candidate", _unified_review())
    with db.get_conn() as conn:
        unified = evaluate_proof_gate(conn, "p", "candidate")
        review_count = conn.execute(
            "SELECT COUNT(*) AS n FROM reviews WHERE project_id = 'p'"
        ).fetchone()["n"]
    assert unified.status == "PASS"
    assert review_count == 1


def test_ablation_a2_no_independent_review_cannot_confirm(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
        result = evaluate_proof_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "UNREVIEWED_EVIDENCE" in result.reason_codes


def test_ablation_candidate_local_and_guard_counterexamples(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    create_review("p", "candidate", CreateReviewRequest(
        verdict="INVALID", confidence="firm", summary="authorization guard blocks path",
        created_by="ablation-reviewer",
        cold_verification={"review_kind": "vulnerability_proof", "candidate_id": "candidate"},
    ))
    with db.get_conn() as conn:
        guarded = evaluate_proof_gate(conn, "p", "candidate")
    assert guarded.status == "FAIL"
    assert "CONTRADICTED_EVIDENCE" in guarded.reason_codes

    isolated = tmp_path / "cross-candidate"
    isolated.mkdir()
    _strict_board(isolated, monkeypatch, second_candidate=True)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
    create_review("p", "candidate", _unified_review())
    with db.get_conn() as conn:
        cross_candidate = evaluate_proof_gate(conn, "p", "candidate")
    assert cross_candidate.status == "FAIL"
    assert "CROSS_CANDIDATE_EVIDENCE" in cross_candidate.reason_codes


def _replay_static_candidate(tmp_path, monkeypatch, *, force_early_package_review=False):
    roles = set(REQUIRED_ROLES)
    _strict_board(tmp_path, monkeypatch, omit=roles)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
    if force_early_package_review:
        monkeypatch.setattr(uvpg, "candidate_proof_package_review_ready", lambda _reasons: True)

    review_count = 0
    for _ in range(40):
        with db.get_conn() as conn:
            result = evaluate_shadow_gate(conn, "p", "candidate")
        if result.status == "PASS":
            break
        planned = plan_proof_gap("p", "candidate")
        assert planned["created_intent"], planned
        gap = planned["gap"]
        if gap["suggested_intent_type"] == "review:cold-verifier":
            assert gap["target_fact_id"] == "candidate"
            create_review("p", "candidate", CreateReviewRequest(
                verdict="VALID",
                confidence="firm",
                summary="independently reviewed complete proof package",
                created_by="ablation-reviewer",
                intent_id=planned["intent_id"],
                cold_verification={
                    "review_kind": "vulnerability_proof",
                    "candidate_id": "candidate",
                },
            ))
            review_count += 1
            continue

        role = gap["expected_fact_type"]
        assert role in REQUIRED_ROLES, gap
        response = conclude("p", planned["intent_id"], ConcludeRequest(
            worker="proof-worker",
            type=role,
            description=f"Reviewed fixture evidence for {role}",
            evidence=f"fixture evidence: {role}",
            status="triaged",
            proof=ProofPayload(claim_kind=role, subject_ids=["candidate"]),
        ))
        assert response.fact.type == role
    else:
        raise AssertionError("static proof planner did not converge")

    with db.get_conn() as conn:
        final = evaluate_shadow_gate(conn, "p", "candidate")
        dynamic = evaluate_dynamic_verification(conn, "p", "candidate")
        view = collect_candidate_proof_subgraph(conn, "p", "candidate")
        fact_count = conn.execute(
            "SELECT COUNT(*) AS n FROM facts WHERE project_id = 'p'"
        ).fetchone()["n"]
        intent_count = conn.execute(
            "SELECT COUNT(*) AS n FROM intents WHERE project_id = 'p'"
        ).fetchone()["n"]
        persisted_review_count = conn.execute(
            "SELECT COUNT(*) AS n FROM reviews WHERE project_id = 'p'"
        ).fetchone()["n"]
    assert final.status == "PASS", final.reason_codes
    assert set(view.facts_by_role) >= roles
    assert persisted_review_count == review_count
    assert dynamic.status == "incomplete"
    return {
        "reviews": review_count,
        "intents": intent_count,
        "facts": fact_count,
        "roles": set(view.facts_by_role),
        "dynamic_status": dynamic.status,
    }


def test_ablation_defers_unified_review_without_changing_static_gate(tmp_path, monkeypatch):
    current_dir = tmp_path / "current"
    current_dir.mkdir()
    current = _replay_static_candidate(current_dir, monkeypatch)

    prior_dir = tmp_path / "prior"
    prior_dir.mkdir()
    monkeypatch.setattr(uvpg, "candidate_proof_package_review_ready", lambda _reasons: True)
    prior = _replay_static_candidate(
        prior_dir, monkeypatch, force_early_package_review=True,
    )

    assert current["roles"] == prior["roles"]
    assert current["reviews"] == 1
    assert prior["reviews"] == 10
    assert current["intents"] == 10
    assert prior["intents"] == 19
    assert current["facts"] == prior["facts"] == 10
    assert current["dynamic_status"] == prior["dynamic_status"] == "incomplete"
