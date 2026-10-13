from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.contracts.oracle import OracleDefinition, OraclePredicate, judge_http_observation
from linen.dispatcher.analysis.artifacts import snapshot_source, digest
from linen.dispatcher.config import ReconConfig
from linen.dispatcher.runtime.oracle_runner import RegisteredOracleProcess
from linen.server import db, oracle_registry
from linen.server.dynamic_verification import evaluate_dynamic_verification
from test_uvpg import _dynamic_board


def test_judge_uses_transport_values_and_rejects_broken_baselines():
    predicate = OraclePredicate(kind="json_equals", json_pointer="/resource", expected="protected:B")
    assert judge_http_observation(predicate, {"status_code": 200, "body": '{"resource":"protected:B"}', "truncated": False})
    assert not judge_http_observation(predicate, {"status_code": 403, "body": "denied", "truncated": False})
    with pytest.raises(ValueError):
        judge_http_observation(predicate, {"status_code": 500, "body": "target crashed", "truncated": False})
    with pytest.raises(ValueError):
        judge_http_observation(predicate, {"status_code": 200, "body": '{"capability_observed":true}', "truncated": False, "capability_observed": True})
    with pytest.raises(ValueError):
        judge_http_observation(predicate, {"status_code": 200, "body": '{"resource":"protected:B"}', "truncated": True})


def test_model_fact_claims_cannot_override_independent_observation(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        for fid in ("dynamic-positive", "dynamic-negative"):
            proof = json.loads(conn.execute("SELECT proof FROM facts WHERE id = ?", (fid,)).fetchone()["proof"])
            proof["attributes"]["capability_observed"] = "model claims identical capabilities"
            proof["attributes"]["observed_outcome"] = {"untrusted": "identical self report"}
            conn.execute("UPDATE facts SET proof = ? WHERE id = ?", (json.dumps(proof), fid))
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "PASS", result.reason_codes
    assert result.receipt["observed_delta"]["positive"]["body"] != result.receipt["observed_delta"]["negative"]["body"]


@pytest.mark.parametrize("actual,expected,matched", [
    ({"resource": ["protected:B", 1]}, {"resource": ["protected:B", 1]}, True),
    ({"resource": ["protected:B", True]}, {"resource": ["protected:B", 1]}, False),
    ([{"balance": False}], [{"balance": 0}], False),
])
def test_nested_json_predicates_do_not_coerce_boolean_capability_witnesses(actual, expected, matched):
    predicate = OraclePredicate(kind="json_equals", expected=expected)
    assert judge_http_observation(predicate, {"status_code": 200, "body": json.dumps(actual), "truncated": False}) is matched


def test_ordinary_worker_run_cannot_masquerade_as_an_oracle(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE runs SET worker_type = 'codex' WHERE run_id = 'run-positive'")
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "UNTRUSTED_DYNAMIC_OBSERVATION" in result.reason_codes


@pytest.mark.parametrize("field,value", [("candidate_id", "other"), ("source_generation", 2), ("role", "negative"),
                                         ("capability_observed", False)])
def test_oracle_receipt_is_bound_and_recomputed(tmp_path, monkeypatch, field, value):
    _dynamic_board(tmp_path, monkeypatch)
    path = tmp_path / "p/positive.log"
    receipt = json.loads(path.read_text())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    with db.get_conn() as conn:
        conn.execute("UPDATE artifacts SET sha256 = ? WHERE artifact_id = 'artifact-positive'", (digest(path.read_bytes()),))
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "FAIL"


def test_unregistered_oracle_never_uses_fact_self_report(tmp_path, monkeypatch):
    _dynamic_board(tmp_path, monkeypatch)
    monkeypatch.setattr(oracle_registry, "_catalog_path", None)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "FAIL"
    assert "INDEPENDENT_ORACLE_UNAVAILABLE" in result.reason_codes


def test_missing_registered_oracle_is_not_delegated_to_a_model(tmp_path, monkeypatch):
    from test_uvpg import _strict_board
    from linen.server.routers.projects import plan_proof_gap

    _strict_board(tmp_path, monkeypatch)
    monkeypatch.setattr(oracle_registry, "_catalog_path", None)
    planned = plan_proof_gap("p", "candidate")
    assert planned["created_intent"] is False
    assert planned["reason"] == "independent_oracle_unavailable"
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM intents WHERE creator = 'dispatcher.proof-gap'").fetchone()[0] == 0


@pytest.mark.parametrize("description,expected", [
    ("@oracle:resource-read:positive", ("resource-read", "positive")),
    ("@uvpg:proof:c:MISSING_DYNAMIC_REPRODUCTION:g1:poc:isolated:reproduction trusted @oracle:resource-read:positive", ("resource-read", "positive")),
    ("@uvpg:proof:c:MISSING_DYNAMIC_REPRODUCTION:g1:poc:isolated:reproduction trusted @oracle:resource-read:negative", None),
    ("@uvpg:proof:c:MISSING_IMPACT:g1:characterize:impact trusted @oracle:resource-read:positive", None),
])
def test_only_matching_dynamic_obligation_routes_to_registered_oracle(description, expected):
    from linen.dispatcher.tasks.oracle import parse_oracle_intent
    from linen.server.models import Intent

    assert parse_oracle_intent(Intent(id="i", description=description, from_=["c"], creator="test", created_at="now")) == expected


@pytest.mark.parametrize("fact_type", ["capability_before", "capability_after", "capability_delta", "impact_observation", "negative_control", "attacker_control"])
def test_proof_claims_are_independently_reviewed_before_summary(fact_type):
    from linen.dispatcher.analysis.audit_graph import _review_proposals
    from conftest import make_project
    from linen.server.models import Fact

    project = make_project()
    project.facts.append(Fact(id="proof-draft", description="bounded source claim", type=fact_type, evidence="app.py:1", status="draft"))
    assert any(proposal["from"] == ["proof-draft"] for proposal in _review_proposals(project))
