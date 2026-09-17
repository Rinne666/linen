"""Small UVPG review ablation matrix.

This is intentionally a regression matrix, not a benchmark framework.  It
compares the legacy per-Fact compatibility path with the candidate-local proof
review and records the two safety properties that matter: a real proof still
confirms, while missing or contradictory independent review does not.
"""
from __future__ import annotations

from linen.server import db
from linen.server.models import CreateReviewRequest
from linen.server.routers.reviews import create_review
from linen.server.uvpg import evaluate_proof_gate

from test_uvpg import _strict_board


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
