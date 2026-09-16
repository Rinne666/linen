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
        assert evaluate_shadow_gate(conn, "p", "f1").status == "PASS"


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
