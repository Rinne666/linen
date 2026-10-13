"""Exercise scheduler promotion through the enforcing HTTP API, without an LLM."""
from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from test_audit_pipeline import config
import test_uvpg
from linen.dispatcher.analysis import audit_graph
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.server import db
from linen.server.app import app


@pytest.mark.parametrize("condition", ["ready", "missing_control", "changed_receipt"])
def test_scheduler_uses_enforcing_confirmation_and_persisted_promotion(
    tmp_path, monkeypatch, condition,
):
    # The shared fixture normally promotes immediately; leave that operation to
    # the scheduler so the real enforcing endpoint is exercised below.
    with monkeypatch.context() as setup_patch:
        setup_patch.setattr(test_uvpg, "confirm_technical_finding", lambda *_: None)
        test_uvpg._dynamic_board(
            tmp_path, monkeypatch, include_negative=condition != "missing_control",
        )
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET audit_mode = 'hypothesis' WHERE id = 'p'")
    cfg = config(tmp_path)
    with TestClient(app) as http:
        client = LinenClient("http://testserver")
        monkeypatch.setattr(client, "_session", lambda: http)
        loop = DispatcherLoop.__new__(DispatcherLoop)
        loop.config = cfg
        loop.client = client
        loop.container_manager = LocalBackend(cfg.local, client)
        # Unrelated baseline/review proposals do not affect this assertion.
        monkeypatch.setattr(audit_graph, "required_intents", lambda *_, **__: [])
        original_plan = client.plan_proof_gap
        original_confirm = client.confirm_technical_finding
        confirmations = []

        def plan(project_id, fact_id):
            result = original_plan(project_id, fact_id)
            if condition == "changed_receipt":
                assert result.data["confirmation_status"] == "eligible"
                (tmp_path / "p" / "positive.log").write_text("tampered receipt")
            return result

        def confirm(project_id, fact_id):
            result = original_confirm(project_id, fact_id)
            confirmations.append(result)
            return result

        monkeypatch.setattr(client, "plan_proof_gap", plan)
        monkeypatch.setattr(client, "confirm_technical_finding", confirm)
        loop._materialize_audit_intents(client.get_project("p"))
        fresh = client.get_project("p")
        promoted = [f for f in fresh.facts if f.semantic_type == "confirmed_finding"]
        if condition == "ready":
            assert len(promoted) == 1
            assert confirmations[0].data["verification_level"] == "dynamic_confirmed"
            assert audit_graph._technical_confirmation(fresh, promoted[0])
            assert not loop._materialize_audit_intents(fresh)
            assert len(confirmations) == 1  # Restart/poll reads the persisted edge.
        else:
            assert promoted == []
            if condition == "missing_control":
                assert confirmations == []
            else:
                assert len(confirmations) == 1
                assert confirmations[0].status_code == 409
        with db.get_conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE project_id = 'p' "
                "AND event_type = 'technical_confirmation'"
            ).fetchone()[0]
            assert count == (1 if condition == "ready" else 0)


def test_promoted_finding_inherits_only_current_candidate_assessment(tmp_path, monkeypatch):
    from linen.server.audit_state import completion_gate_from_db, latest_finding_assessment

    test_uvpg._dynamic_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET audit_mode = 'hypothesis' WHERE id = 'p'")
        confirmed_id = conn.execute(
            "SELECT id FROM facts WHERE semantic_type = 'confirmed_finding'"
        ).fetchone()[0]
        assert latest_finding_assessment(conn, "p", confirmed_id) == latest_finding_assessment(conn, "p", "candidate")
        gate = completion_gate_from_db(conn, "p")
        assert next(check for check in gate.checks if check.id == "finding_reviews").status == "pass"
        # A newer contrary candidate review remains authoritative.
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, created_at) "
            "VALUES ('new-review', 'p', 'candidate', 'NEEDS_REVIEW', 'tentative', 'new uncertainty', 'zz')"
        )
        gate = completion_gate_from_db(conn, "p")
        assert next(check for check in gate.checks if check.id == "finding_reviews").status == "fail"
        conn.execute("DELETE FROM graph_edges WHERE relation_type = 'promotes_to'")
        assert latest_finding_assessment(conn, "p", confirmed_id) is None


def test_summary_refresh_uses_retry_budget_for_current_inputs():
    from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta

    board = ProjectDetail(
        project=ProjectMeta(id="p", title="Audit", status="active", audit_mode="scope", created_at="now"),
        facts=[Fact(id=f"f{n}", description="valid summary", type="audit_summary", status="triaged") for n in range(3)],
        intents=[Intent(id=f"i{n}", from_=[f"source{n}"], to=f"f{n}",
                        description=audit_graph.AUDIT_SUMMARY_INTENT, type="synthesize",
                        creator="dispatcher.audit", created_at="now", concluded_at="now") for n in range(3)],
        hints=[], reviews=[],
    )
    proposal = audit_graph._stage_intent_proposal(board, ["confirmed"], "synthesize", audit_graph.AUDIT_SUMMARY_INTENT)
    assert proposal is not None  # Three successful older summaries are not failures.
    assert proposal["from"] == ["confirmed"]
    for n in range(audit_graph.MAX_STAGE_INTENT_ATTEMPTS):
        board.intents.append(Intent(id=f"failed{n}", from_=["confirmed"], description=audit_graph.AUDIT_SUMMARY_INTENT,
                                    type="synthesize", creator="dispatcher.audit", created_at="now", concluded_at="now"))
    assert audit_graph._stage_intent_proposal(board, ["confirmed"], "synthesize", audit_graph.AUDIT_SUMMARY_INTENT) is None
