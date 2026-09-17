from __future__ import annotations

import json
import hashlib

import pytest

from linen.server import db
from linen.server.models import ConcludeRequest, CreateReviewRequest
from linen.server.routers.projects import confirm_technical_finding
from linen.server.routers.projects import plan_proof_gap
from linen.server.routers.intents import conclude
from linen.server.models import Fact, ProofPayload
from linen.server.uvpg import (
    collect_candidate_proof_subgraph,
    derive_proof_gaps,
    evaluate_shadow_gate,
    load_invariant_library,
    MAX_EDGES,
    proof_graph_fingerprint,
    validate_proof_payload,
)
from linen.server.routers.reviews import create_review
from linen.server.dynamic_verification import evaluate_dynamic_verification, effective_verification_level
from linen.server.routers.projects import finalize_dynamic_verification, get_dynamic_verification


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
        assert result.as_dict()["gate_version"] == "uvpg-proof-v1"


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


def test_technical_confirmation_promotes_once_and_is_idempotent(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET evidence = 'frozen evidence' WHERE id = 'candidate'")
    first = confirm_technical_finding("p", "candidate")
    second = confirm_technical_finding("p", "candidate")
    assert first["status"] == "confirmed"
    assert first["gate_version"] == "uvpg-proof-v1"
    assert first["confirmed_fact_id"] == second["confirmed_fact_id"]
    with db.get_conn() as conn:
        assert evaluate_shadow_gate(conn, "p", "candidate").status == "PASS"
        assert "confirmed_finding" not in evaluate_shadow_gate(conn, "p", "candidate").proof_summary["fact_ids"]
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM graph_edges WHERE relation_type = 'promotes_to'").fetchone()["n"] == 1


def test_failed_technical_confirmation_writes_nothing(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, omit={"negative_control"})
    response = confirm_technical_finding("p", "candidate")
    assert response.status_code == 409
    assert response.body
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["n"] == 0
        assert conn.execute("SELECT COUNT(*) AS n FROM graph_edges WHERE relation_type = 'promotes_to'").fetchone()["n"] == 0


def test_proof_gap_planner_is_prioritized_deduplicated_and_server_binds_edge(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, omit={"security_invariant"})
    first = plan_proof_gap("p", "candidate")
    second = plan_proof_gap("p", "candidate")
    assert first["created"] is True
    assert first["gap"]["code"] == "MISSING_INVARIANT"
    assert second["created"] is False
    assert second["reason"] == "duplicate_open_obligation"
    intent_id = first["intent_id"]
    request = ConcludeRequest(
        worker="proof-worker", type="security_invariant", description="Object ownership must be enforced",
        evidence="policy: ownership check", status="triaged",
        proof={"claim_kind": "security_invariant", "subject_ids": ["candidate"]},
    )
    response = conclude("p", intent_id, request)
    assert response.fact.type == "security_invariant"
    with db.get_conn() as conn:
        edge = conn.execute("SELECT source_id, target_id, relation_type FROM graph_edges WHERE target_id = 'candidate' AND relation_type = 'violates'").fetchone()
        assert tuple(edge) == (response.fact.id, "candidate", "violates")


def test_proof_gap_conclusion_rejects_wrong_fact_role(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch, omit={"security_invariant"})
    planned = plan_proof_gap("p", "candidate")
    request = ConcludeRequest(
        worker="proof-worker", type="impact_observation", description="wrong role",
        evidence="evidence", status="triaged",
    )
    with pytest.raises(Exception, match="PROOF_OBLIGATION_FACT_TYPE_MISMATCH"):
        conclude("p", planned["intent_id"], request)


def test_blackboard_workflow_edges_are_not_proof_projection(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('hypothesis', 'p', 'workflow hypothesis', 'hypothesis', 'hypothesis')")
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('workflow', 'p', 'fact', 'hypothesis', 'fact', 'candidate', 'supports', 'now', 'test')")
        view = collect_candidate_proof_subgraph(conn, "p", "candidate")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "PASS"
    assert "hypothesis" not in view.proof_fact_ids


def test_review_gap_targets_one_proof_fact_and_closes_after_review(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews WHERE fact_id = 'negative_control'")
        gaps = derive_proof_gaps(conn, "p", "candidate")
    review_gap = next(gap for gap in gaps if gap.code == "UNREVIEWED_EVIDENCE")
    assert review_gap.target_fact_id == "negative_control"
    planned = plan_proof_gap("p", "candidate")
    assert planned["gap"]["target_fact_id"] == "negative_control"
    with db.get_conn() as conn:
        assert tuple(
            row["fact_id"] for row in conn.execute(
                "SELECT fact_id FROM intent_sources WHERE intent_id = ?", (planned["intent_id"],)
            )
        ) == ("negative_control",)
    create_review("p", "negative_control", CreateReviewRequest(
        verdict="VALID", confidence="firm", summary="reviewed", created_by="reviewer", intent_id=planned["intent_id"],
    ))
    with db.get_conn() as conn:
        assert "UNREVIEWED_EVIDENCE" not in evaluate_shadow_gate(conn, "p", "candidate").reason_codes


def test_repair_gap_is_blocked_without_auto_intent(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET proof = ? WHERE id = 'security_invariant'", (json.dumps({
            "claim_kind": "security_invariant", "subject_ids": ["security_invariant"],
            "evidence_refs": [{"line_start": 1, "line_end": 1, "file": "proof.txt"}],
        }),))
        gaps = derive_proof_gaps(conn, "p", "candidate")
    assert any(gap.code == "INVALID_SOURCE_EXCERPT" and gap.status == "blocked" for gap in gaps)
    planned = plan_proof_gap("p", "candidate")
    assert planned["created"] is False
    assert planned["reason"] == "no_investigative_gap"


def test_unrelated_candidate_canonical_edges_do_not_contaminate_projection(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate-b', 'p', 'candidate b', 'vulnerability', 'candidate_finding')")
        for role in ("capability_before", "capability_after", "capability_delta", "negative_control"):
            conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES (?, 'p', ?, ?)", (f"b-{role}", role, role))
        for edge_id, source, target, relation in (
            ("b-before", "candidate-b", "b-capability_before", "depends_on"),
            ("b-after", "candidate-b", "b-capability_after", "depends_on"),
            ("b-delta", "candidate-b", "b-capability_delta", "depends_on"),
            ("b-negative", "candidate-b", "b-negative_control", "depends_on"),
        ):
            conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, metadata, created_at, created_by) VALUES (?, 'p', 'fact', ?, 'fact', ?, ?, ?, 'now', 'test')", (edge_id, source, target, relation, json.dumps({"candidate_id": "candidate-b"})))
        view = collect_candidate_proof_subgraph(conn, "p", "candidate")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "PASS"
    assert not set(view.proof_fact_ids) & {"candidate-b", "b-capability_before", "b-capability_after", "b-capability_delta", "b-negative_control"}


def test_unrelated_blackboard_edges_do_not_consume_local_edge_budget(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        for index in range(MAX_EDGES + 20):
            fact_id = f"noise-{index:03d}"
            conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES (?, 'p', ?, 'noise')", (fact_id, fact_id))
            conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES (?, 'p', 'fact', ?, 'fact', 'candidate', 'produces', 'now', 'test')", (f"noise-edge-{index:03d}", fact_id))
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "PASS"
    assert "PROOF_GRAPH_TOO_LARGE" not in result.reason_codes


def test_reachable_local_proof_edges_consume_edge_budget(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        for index in range(MAX_EDGES + 1):
            fact_id = f"extra-attacker-{index:03d}"
            conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES (?, 'p', ?, 'attacker_control')", (fact_id, fact_id))
            conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES (?, 'p', 'fact', 'candidate', 'fact', ?, 'depends_on', 'now', 'test')", (f"extra-edge-{index:03d}", fact_id))
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "PROOF_GRAPH_TOO_LARGE" in result.reason_codes


def test_remote_legacy_candidate_and_malformed_edge_are_ignored(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate-b', 'p', 'candidate b', 'vulnerability', 'candidate_finding')")
        conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES ('b-invariant', 'p', 'b invariant', 'security_invariant')")
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('b-malformed', 'p', 'fact', 'b-invariant', 'fact', 'candidate-b', 'baseline_for', 'now', 'test')")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "PASS"
    assert "CROSS_CANDIDATE_EVIDENCE" not in result.reason_codes
    assert "INVALID_EDGE_RELATION" not in result.reason_codes


def test_legacy_cross_candidate_fact_is_rejected_when_reachable(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate-b', 'p', 'candidate b', 'vulnerability', 'candidate_finding')")
        conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES ('b-before', 'p', 'b before', 'capability_before')")
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('a-to-b-proof', 'p', 'fact', 'candidate', 'fact', 'b-before', 'depends_on', 'now', 'test')")
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('b-anchor', 'p', 'fact', 'candidate-b', 'fact', 'b-before', 'depends_on', 'now', 'test')")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "CROSS_CANDIDATE_EVIDENCE" in result.reason_codes


def test_local_malformed_edge_is_not_silently_ignored(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('local-malformed', 'p', 'fact', 'candidate', 'fact', 'security_invariant', 'baseline_for', 'now', 'test')")
        result = evaluate_shadow_gate(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "INVALID_EDGE_RELATION" in result.reason_codes


def test_fingerprint_ignores_remote_and_review_mutation(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        first = proof_graph_fingerprint(conn, "p", "candidate")
        conn.execute("INSERT INTO facts (id, project_id, description, type, semantic_type) VALUES ('candidate-b', 'p', 'candidate b', 'vulnerability', 'candidate_finding')")
        conn.execute("INSERT INTO facts (id, project_id, description, type) VALUES ('b-before', 'p', 'b before', 'capability_before')")
        conn.execute("INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, relation_type, created_at, created_by) VALUES ('remote-edge', 'p', 'fact', 'candidate-b', 'fact', 'b-before', 'depends_on', 'now', 'test')")
        second = proof_graph_fingerprint(conn, "p", "candidate")
        conn.execute("INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) VALUES ('local-review', 'p', 'attacker_control', 'VALID', 'firm', 'local', 'later')")
        third = proof_graph_fingerprint(conn, "p", "candidate")
    assert first == second
    # Reviews attest to this digest; they are not part of the evidence being
    # attested, otherwise recording a review would invalidate itself.
    assert third == second


def test_unified_candidate_review_is_one_gate_and_stales_on_proof_change(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("DELETE FROM reviews")
    create_review("p", "candidate", CreateReviewRequest(
        verdict="VALID", confidence="firm", summary="whole proof reviewed", created_by="reviewer",
        cold_verification={"review_kind": "vulnerability_proof", "candidate_id": "candidate"},
    ))
    with db.get_conn() as conn:
        assert evaluate_shadow_gate(conn, "p", "candidate").status == "PASS"
        conn.execute("UPDATE facts SET description = 'changed proof claim' WHERE id = 'security_invariant'")
        stale = evaluate_shadow_gate(conn, "p", "candidate")
    assert stale.status == "FAIL"
    assert "PROOF_GRAPH_CHANGED" in stale.reason_codes


def _dynamic_board(tmp_path, monkeypatch, *, include_negative=True, same_capability=False, unsafe=False):
    candidate_id = _strict_board(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    repo.mkdir()
    positive_path = repo / "positive.log"
    negative_path = repo / "negative.log"
    positive_path.write_text("positive", encoding="utf-8")
    negative_path.write_text("negative", encoding="utf-8")
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET repo_root = ? WHERE id = 'p'", (str(repo),))
        generation = conn.execute("SELECT source_generation FROM projects WHERE id = 'p'").fetchone()[0]
        for run_id, artifact_id, path in (("run-positive", "artifact-positive", positive_path), ("run-negative", "artifact-negative", negative_path)):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            conn.execute(
                "INSERT INTO artifacts (artifact_id, project_id, kind, workspace_path, sha256, media_type, byte_size, producer_run_id, created_at) VALUES (?, 'p', 'dynamic-log', ?, ?, 'text/plain', ?, ?, 'now')",
                (artifact_id, path.name, digest, path.stat().st_size, run_id),
            )
            task_type = "explore" if unsafe else "poc:isolated"
            conn.execute(
                "INSERT INTO runs (run_id, project_id, task_type, attempt, idempotency_key, graph_revision, source_generation, plan_revision, timeout_seconds, status, artifact_ids, created_at, updated_at) VALUES (?, 'p', ?, 1, ?, 1, ?, 1, 30, 'succeeded', ?, 'now', 'now')",
                (run_id, task_type, run_id, generation, json.dumps([artifact_id])),
            )
        positive_capability = "protected:B" if not same_capability else "same"
        negative_capability = "owned:A" if not same_capability else "same"
        def proof(claim_kind, run_id, artifact_id, capability, outcome):
            return json.dumps({
                "claim_kind": claim_kind,
                "subject_ids": [candidate_id],
                "attributes": {
                    "mode": "dynamic", "candidate_id": candidate_id, "run_id": run_id,
                    "artifact_ids": [artifact_id], "oracle_kind": "resource_identity",
                    "capability_observed": capability, "observed_outcome": outcome,
                    "environment_fingerprint": "env-1", "harness_id": "idor-harness", "target_id": "target-1",
                },
            })
        conn.execute("INSERT INTO facts (id, project_id, description, type, proof) VALUES ('dynamic-positive', 'p', 'positive reproduction', 'reproduction', ?)", (proof("reproduction", "run-positive", "artifact-positive", positive_capability, {"resource_identity": positive_capability}),))
        if include_negative:
            conn.execute("INSERT INTO facts (id, project_id, description, type, proof) VALUES ('dynamic-negative', 'p', 'negative baseline', 'negative_control', ?)", (proof("negative_control", "run-negative", "artifact-negative", negative_capability, {"resource_identity": negative_capability}),))
        conn.execute("INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) VALUES ('dynamic-review-positive', 'p', 'dynamic-positive', 'VALID', 'firm', 'reviewed', 'now')")
        if include_negative:
            conn.execute("INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) VALUES ('dynamic-review-negative', 'p', 'dynamic-negative', 'VALID', 'firm', 'reviewed', 'now')")
    confirm_technical_finding("p", candidate_id)
    return candidate_id


def test_valid_review_never_promotes_candidate(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    create_review("p", "candidate", CreateReviewRequest(
        verdict="VALID", confidence="firm", summary="credible", created_by="reviewer",
    ))
    with db.get_conn() as conn:
        row = conn.execute("SELECT semantic_type FROM facts WHERE id = 'candidate'").fetchone()
        assert row["semantic_type"] == "candidate_finding"
        assert conn.execute("SELECT COUNT(*) AS n FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["n"] == 0
        assert conn.execute("SELECT COUNT(*) AS n FROM graph_edges WHERE relation_type = 'promotes_to'").fetchone()["n"] == 0


def test_static_confirmation_succeeds_without_dynamic_evidence(tmp_path, monkeypatch):
    _strict_board(tmp_path, monkeypatch)
    result = confirm_technical_finding("p", "candidate")
    assert result["status"] == "confirmed"
    assert result["verification_level"] == "static_confirmed"


def test_dynamic_positive_without_negative_is_incomplete(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch, include_negative=False)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "incomplete"
    assert "MISSING_DYNAMIC_NEGATIVE_CONTROL" in result.reason_codes


def test_dynamic_verification_requires_capability_delta_and_passes_idor_fixture(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "PASS", result.reason_codes
    receipt = finalize_dynamic_verification("p", "candidate")
    assert receipt["status"] == "PASS"
    assert receipt["effective_verification_level"] == "dynamic_confirmed"
    second = finalize_dynamic_verification("p", "candidate")
    assert second["receipt_sequence"] == receipt["receipt_sequence"]
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM audit_events WHERE event_type = 'dynamic_verification_pass'").fetchone()["n"] == 1
        confirmed = conn.execute("SELECT id FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["id"]
        assert effective_verification_level(conn, "p", confirmed) == "dynamic_confirmed"


def test_dynamic_equal_positive_negative_outcomes_fail_delta(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch, same_capability=True)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "NO_DYNAMIC_CAPABILITY_DELTA" in result.reason_codes


def test_dynamic_unisolated_run_cannot_upgrade_static_confirmation(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch, unsafe=True)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "UNSAFE_DYNAMIC_EXECUTION" in result.reason_codes


def test_dynamic_artifact_tampering_invalidates_effective_level(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    finalize_dynamic_verification("p", "candidate")
    positive_path = tmp_path / "repo" / "positive.log"
    positive_path.write_text("tampered", encoding="utf-8")
    with db.get_conn() as conn:
        confirmed = conn.execute("SELECT id FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["id"]
        result = evaluate_dynamic_verification(conn, "p", "candidate")
        level = effective_verification_level(conn, "p", confirmed)
    assert "DYNAMIC_ARTIFACT_HASH_MISMATCH" in result.reason_codes
    assert level == "static_confirmed"


def test_dynamic_receipt_does_not_carry_forward_to_new_generation(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    finalize_dynamic_verification("p", "candidate")
    with db.get_conn() as conn:
        confirmed = conn.execute("SELECT id FROM facts WHERE semantic_type = 'confirmed_finding'").fetchone()["id"]
        conn.execute("UPDATE projects SET source_generation = 2 WHERE id = 'p'")
        assert effective_verification_level(conn, "p", confirmed) == "static_confirmed"


def test_dynamic_evidence_is_candidate_bound(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        row = conn.execute("SELECT proof FROM facts WHERE id = 'dynamic-negative'").fetchone()
        proof = json.loads(row["proof"])
        proof["attributes"]["candidate_id"] = "candidate-b"
        conn.execute("UPDATE facts SET proof = ? WHERE id = 'dynamic-negative'", (json.dumps(proof),))
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "incomplete"
    assert "MISSING_DYNAMIC_NEGATIVE_CONTROL" in result.reason_codes
