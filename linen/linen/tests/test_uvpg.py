from __future__ import annotations

import json

from linen.server import db
from linen.server.models import Fact, ProofPayload
from linen.server.uvpg import evaluate_shadow_gate, load_invariant_library, validate_proof_payload


def _proof(*roles: str) -> dict:
    return {
        "schema_version": 1,
        "claim_kind": roles[0],
        "subject_ids": ["f1"],
        "attributes": {"proof_roles": list(roles)},
    }


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "uvpg.db")
    with db.get_conn() as conn:
        conn.execute("INSERT INTO projects (id, title, created_at) VALUES ('p', 'p', 'now')")
        conn.execute("INSERT INTO facts (id, project_id, description, type, proof) VALUES ('f1', 'p', 'candidate', 'vulnerability', ?)", (json.dumps(_proof(
            "attacker_control", "reachability", "security_invariant", "security_boundary",
            "capability_before", "capability_after", "capability_delta", "negative_control", "impact_observation",
        )),))
        conn.execute("INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) VALUES ('r1', 'p', 'f1', 'VALID', 'firm', 'ok', 'now')")


def test_proof_payload_validates_and_legacy_fact_still_parses(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM facts WHERE id='f1'").fetchone()
        assert Fact(**dict(row)).proof is not None
        assert validate_proof_payload(conn, "p", ProofPayload(**_proof("attacker_control")), subject_fact_id="f1") == []
        result = evaluate_shadow_gate(conn, "p", "f1")
        assert result.status == "FAIL"
        assert "MISSING_PROOF_EDGE" not in result.reason_codes
        assert "MISSING_INVARIANT" in result.reason_codes
        assert result.as_dict()["gate_version"] == "uvpg-shadow-v2"


def test_shadow_gate_reports_missing_negative_control_without_blocking_completion(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET proof = ? WHERE id='f1'", (json.dumps(_proof(
            "attacker_control", "reachability", "security_invariant", "security_boundary",
            "capability_before", "capability_after", "capability_delta", "impact_observation",
        )),))
        result = evaluate_shadow_gate(conn, "p", "f1")
        assert result.status == "FAIL"
        assert "MISSING_NEGATIVE_CONTROL" in result.reason_codes
        assert result.as_dict()["mode"] == "shadow"


def test_invariant_library_covers_required_classes():
    invariants = load_invariant_library()["invariants"]
    assert {"injection", "authorization", "authentication_session", "business_logic", "race_toc_tou", "configuration", "sandbox_isolation"} <= set(invariants)


def _strict_board(tmp_path, monkeypatch, *, omit=(), invalid_review=None, second_candidate=False):
    _setup(tmp_path, monkeypatch)
    roles = [
        "attacker_control", "reachability", "security_invariant", "security_boundary",
        "capability_before", "capability_after", "capability_delta", "negative_control",
        "impact_observation",
    ]
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
        conn.execute("DELETE FROM facts")
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate', 'p', 'candidate', 'vulnerability', 'candidate_finding')")
        for role in roles:
            if role in omit:
                continue
            conn.execute("INSERT INTO facts (id, project_id, description, type, proof) VALUES (?, 'p', ?, ?, ?)", (role, role, role, json.dumps({"claim_kind": role, "subject_ids": [role]})))
        edges = {
            "attacker_control": ("candidate", "attacker_control", "depends_on"),
            "reachability": ("candidate", "reachability", "depends_on"),
            "security_invariant": ("security_invariant", "candidate", "violates"),
            "security_boundary": ("security_boundary", "candidate", "crosses"),
            "capability_delta_before": ("capability_delta", "capability_before", "depends_on"),
            "capability_delta_after": ("capability_delta", "capability_after", "depends_on"),
            "negative_control": ("negative_control", "capability_before", "baseline_for"),
            "impact_observation": ("impact_observation", "candidate", "observed_by"),
            "delta": ("candidate", "capability_delta", "depends_on"),
            "negative_candidate": ("candidate", "negative_control", "depends_on"),
        }
        for edge_id, (source, target, relation) in edges.items():
            if source in omit or target in omit:
                continue
            conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES (?, 'p', 'fact', ?, 'fact', ?, ?, 'now', 'test')", (edge_id, source, target, relation))
        required_reviewed = {"candidate", "security_invariant", "security_boundary", "capability_delta", "negative_control", "impact_observation"}
        for index, role in enumerate(["candidate", *roles], 1):
            if role in omit:
                continue
            verdict = "INVALID" if role == invalid_review else "VALID"
            confidence = "firm"
            conn.execute("INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) VALUES (?, 'p', ?, ?, ?, 'test', ?)", (f"review-{index}", role, verdict, confidence, f"{index:02d}"))
        if second_candidate:
            conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate-b', 'p', 'other', 'vulnerability', 'candidate_finding')")
            conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('cross', 'p', 'fact', 'candidate', 'fact', 'candidate-b', 'depends_on', 'now', 'test')")
    return "candidate"


def test_strict_graph_closure_passes_and_reports_summary(tmp_path, monkeypatch):
    fact_id = _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        result = evaluate_shadow_gate(conn, "p", fact_id)
    assert result.status == "PASS", result.reason_codes
    assert result.reason_codes == ()
    assert set(result.proof_summary["graph_closure_result"]) == {
        "attacker_control", "reachability", "security_invariant", "security_boundary",
        "capability_before", "capability_after", "capability_delta", "negative_control", "impact_observation",
    }


def test_missing_invariant_is_not_satisfied_by_unconnected_fact(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, omit={"security_invariant"})
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES ('orphan', 'p', 'orphan invariant', 'security_invariant')")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "MISSING_INVARIANT" in result.reason_codes


def test_cross_candidate_evidence_is_rejected(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, second_candidate=True)
    with db.get_conn() as conn:
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "CROSS_CANDIDATE_EVIDENCE" in result.reason_codes


def test_invalid_review_on_proof_fact_is_contradiction(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, invalid_review="capability_delta")
    with db.get_conn() as conn:
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "CONTRADICTED_EVIDENCE" in result.reason_codes


def test_missing_review_on_key_proof_fact_is_unreviewed(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, omit={"negative_control"})
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews WHERE fact_id = 'impact_observation'")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "UNREVIEWED_EVIDENCE" in result.reason_codes


def test_proof_cycle_is_bounded_and_deterministic(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('cycle', 'p', 'fact', 'capability_before', 'fact', 'candidate', 'supports', 'now', 'test')")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "PROOF_CYCLE" in result.reason_codes
