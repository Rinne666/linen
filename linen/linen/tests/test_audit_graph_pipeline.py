from __future__ import annotations

import json
from pathlib import Path

import pytest

from click.testing import CliRunner

from test_audit_pipeline import FakeDriver, api, config, project
from linen.cli import main
from linen.dispatcher.analysis import audit_graph, coverage, scope_gate
from linen.dispatcher.analysis.benchmark import compare_strategies, evaluate
from linen.dispatcher.config import (
    PocSandboxConfig,
    ScopeAdjudicationConfig,
)
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks import explore
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, ProofPayload, Review


def _approve(client, project_id: str, fact_id: str) -> None:
    response = client.create_review(
        project_id, fact_id, "VALID", "independently checked", confidence="firm",
        diagnostics={"attestation_check": {
            "artifact_integrity": "valid",
            "source_consistency": "consistent",
            "scope_complete": "yes",
            "contradictions": [],
        }},
    )
    assert response.ok, response.text


def _conclude(client, project_id: str, parents: list[str], description: str,
              fact_type: str, evidence: str) -> str:
    intent = client.create_intent(
        project_id, parents, description, "dispatcher.audit", intent_type="search",
    ).data
    assert client.heartbeat(project_id, intent["id"], "tester").ok
    response = client.conclude(
        project_id, intent["id"], "tester", description,
        fact_type=fact_type, evidence=evidence,
    )
    assert response.ok, response.text
    return response.data["fact"]["id"]


def test_scope_initial_intents_are_derived_from_graph(tmp_path):
    cfg = config(tmp_path, mode="scope")
    from linen.server.models import ProjectDetail, ProjectMeta

    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[Fact(id="origin", description="repo"), Fact(id="goal", description="audit")],
        intents=[], hints=[], reviews=[],
    )
    proposals = audit_graph.required_intents(board, tmp_path, cfg.audit)
    assert [(item["type"], item["description"]) for item in proposals] == [
        ("search", "@analysis:coverage-plan"),
    ]
    assert all(item["from"] == ["origin"] for item in proposals)


def test_terminal_coverage_plan_is_not_reproposed_forever(tmp_path):
    cfg = config(tmp_path, mode="scope")
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[Fact(id="origin", description="repo"), Fact(id="goal", description="audit")],
        intents=[Intent(
            id="i001", from_=["origin"], description=coverage.PLAN_INTENT,
            type="search", creator=audit_graph.CREATOR,
            created_at="2026-01-01T00:00:01Z", concluded_at="2026-01-01T00:00:02Z",
        )],
        hints=[], reviews=[],
    )

    assert audit_graph.required_intents(board, tmp_path, cfg.audit) == []


def test_proof_obligation_binds_identity_without_relabeling() -> None:
    intent = Intent(
        id="i024", from_=["f006"],
        description="@uvpg:proof:f006:MISSING_ATTACKER_CONTROL:g1:verify:attacker_control Verify attacker control",
        type="verify", creator=audit_graph.CREATOR,
        created_at="2026-01-01T00:00:01Z",
    )
    fact = explore._bind_proof_obligation(intent, {
        "description": "request id is attacker controlled",
        "type": "attacker_control",
        "evidence": "file:Api.java\nline:42",
    })

    assert fact["proof"]["claim_kind"] == "attacker_control"
    assert fact["proof"]["subject_ids"] == ["f006"]
    with pytest.raises(explore.ProofContractError, match="requires fact type attacker_control"):
        explore._bind_proof_obligation(intent, {
            "description": "request id is attacker controlled",
            "type": "validation",
            "evidence": "file:Api.java\nline:42",
        })


def test_unresolved_review_gets_one_deterministic_contradiction_followup(tmp_path):
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="hypothesis", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"),
            Fact(id="goal", description="audit"),
            Fact(id="f001", description="candidate authorization bypass",
                 type="vulnerability", status="draft", evidence="Api.java:12"),
        ],
        intents=[Intent(
            id="i001", from_=["f001"], description="@analysis:review:f001",
            type="review:cold-verifier", creator="dispatcher.audit",
            created_at="2026-01-01T00:00:01Z", concluded_at="2026-01-01T00:00:02Z",
        )],
        hints=[],
        reviews=[Review(
            id="r001", fact_id="f001", verdict="NEEDS_REVIEW",
            confidence="tentative", summary="guard behavior remains ambiguous",
            created_at="2026-01-01T00:00:02Z",
        )],
    )

    assert audit_graph._review_proposals(board) == [{
        "from": ["f001"],
        "type": "review:contradiction-reasoner",
        "description": "@analysis:review:f001:contradiction-reasoner",
    }]

    board.intents.append(Intent(
        id="i002", from_=["f001"],
        description="@analysis:review:f001:contradiction-reasoner",
        type="review:contradiction-reasoner", creator="dispatcher.audit",
        created_at="2026-01-01T00:00:03Z", concluded_at="2026-01-01T00:00:04Z",
    ))
    board.reviews.append(Review(
        id="r002", fact_id="f001", verdict="VALID", confidence="firm",
        summary="source proves the guard is bypassable",
        created_at="2026-01-01T00:00:04Z",
    ))
    board.facts[-1].status = "triaged"
    assert audit_graph._review_proposals(board) == []


def test_uvpg_proof_atom_does_not_get_generic_review_proposal() -> None:
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="hypothesis", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"),
            Fact(id="goal", description="audit"),
            Fact(
                id="f001", description="reachable path", type="reachability", status="draft",
                proof=ProofPayload(claim_kind="reachability"),
            ),
        ],
        intents=[], hints=[], reviews=[],
    )

    assert audit_graph._review_proposals(board) == []


def test_validated_intermediate_facts_do_not_schedule_generic_review():
    intermediate_types = [
        "coverage_plan", "architecture_map", "authz_matrix",
        "state_model", "cross_service_map", "contract_map", "hypothesis_batch",
        "variant_batch", "module_summary", "semantic_summary", "audit_summary",
    ]
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_reviewless", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"), Fact(id="goal", description="audit"),
            *(Fact(id=f"f-{kind}", description=kind, type=kind, status="triaged")
              for kind in intermediate_types),
        ],
        intents=[], hints=[], reviews=[],
    )

    assert audit_graph._review_proposals(board) == []


def test_coverage_result_keeps_review_because_it_carries_negative_assurance():
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_coverage_review", title="audit", status="active",
            bootstrap_enabled=False, audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"), Fact(id="goal", description="audit"),
            Fact(id="f-coverage", description="checked cell", type="coverage_result", status="draft"),
        ],
        intents=[], hints=[], reviews=[],
    )

    proposals = audit_graph._review_proposals(board)

    assert len(proposals) == 1
    assert proposals[0]["from"] == ["f-coverage"]


def test_legacy_plan_review_does_not_trigger_a_second_llm_attestation(tmp_path):
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"),
            Fact(id="goal", description="audit"),
            Fact(
                id="f001", description="Coverage plan", type="coverage_plan",
                status="false_positive", evidence="artifact: plan.json",
            ),
        ],
        intents=[Intent(
            id="i001", from_=["f001"], description="@analysis:review:f001",
            type="review:devils-advocate", creator="dispatcher.audit",
            created_at="2026-01-01T00:00:01Z", concluded_at="2026-01-01T00:00:02Z",
        )],
        hints=[],
        reviews=[Review(
            id="r001", fact_id="f001", verdict="INVALID", confidence="certain",
            summary="A scope plan is not a vulnerability",
            created_at="2026-01-01T00:00:02Z",
        )],
    )

    assert coverage.effective_reviews(board, "f001") == []
    assert audit_graph._review_proposals(board) == []

    board.reviews.append(Review(
        id="r002", fact_id="f001", verdict="VALID", confidence="firm",
        summary="Plan hash and scope match",
        attestation_check={
            "artifact_integrity": "valid",
            "source_consistency": "consistent",
            "scope_complete": "yes",
            "contradictions": [],
        },
        created_at="2026-01-01T00:00:03Z",
    ))
    board.facts[-1].status = "triaged"
    assert coverage.reviewed(board, "f001")
    assert audit_graph._review_proposals(board) == []


def test_scheduler_materializes_graph_intents_idempotently(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    board = project(api, audit_mode="scope")
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = cfg
    loop.client = client
    loop.container_manager = LocalBackend(cfg.local, client)
    assert loop._materialize_audit_intents(board)
    fresh = client.get_project(board.project.id)
    assert {intent.description for intent in fresh.intents} == {
        "@analysis:coverage-plan",
    }
    assert all(intent.creator == audit_graph.CREATOR for intent in fresh.intents)
    assert not loop._materialize_audit_intents(fresh)


def test_scope_gate_bypasses_a_full_legacy_ready_window(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.scope_adjudication = ScopeAdjudicationConfig(
        enabled=True,
        local_paths=["SECURITY.md"],
    )
    board = project(api, audit_mode="scope")
    for index in range(2):
        assert client.create_intent(
            board.project.id,
            ["origin"],
            f"legacy managed work {index}",
            audit_graph.CREATOR,
            intent_type="verify",
        ).ok
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = cfg
    loop.client = client
    loop.container_manager = LocalBackend(cfg.local, client)

    assert loop._materialize_audit_intents(client.get_project(board.project.id))
    assert any(
        intent.description == "@analysis:scope-evidence"
        for intent in client.get_project(board.project.id).intents
    )


def test_scope_evidence_missing_repository_becomes_visible_blocker(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.scope_adjudication = ScopeAdjudicationConfig(
        enabled=True,
        local_paths=["SECURITY.md"],
    )
    board = project(api, audit_mode="scope")
    pid = board.project.id
    intent_id = client.create_intent(
        pid,
        ["origin"],
        scope_gate.EVIDENCE_INTENT,
        audit_graph.CREATOR,
        intent_type="search",
    ).data["id"]
    worker = cfg.workers[0]
    assert client.heartbeat(pid, intent_id, worker.name).ok
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == intent_id)

    outcome = explore.run_explore_task(
        cfg,
        client,
        LocalBackend(cfg.local, client),
        current,
        client.export_project(pid),
        intent,
        worker,
        TaskCancellation(),
    )

    assert outcome == "blocked"
    fresh = client.get_project(pid)
    assert fresh.intents[0].worker is None
    assert len(fresh.errors) == 1
    assert fresh.errors[0].classification == "blocked"
    assert fresh.errors[0].code == "source_repository_missing"


def test_isolated_poc_uses_sandbox_backend_without_host_fallback(api, tmp_path, monkeypatch):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.poc_sandbox = PocSandboxConfig(enabled=True, image="trusted-local-image")
    current = project(api, audit_mode="scope")
    pid = current.project.id
    host = LocalBackend(cfg.local, client)
    workdir = Path(host.ensure_running(pid))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler(value):\n    return value\n")
    plan = coverage.create_plan(repo, workdir, cfg.audit.coverage)
    source_id = _conclude(
        client, pid, ["origin"], coverage.PLAN_INTENT, plan["type"], plan["evidence"],
    )
    intent_id = client.create_intent(
        pid, [source_id], "reproduce candidate safely", "reasoner", intent_type="poc:isolated",
    ).data["id"]
    client.heartbeat(pid, intent_id, "tester")
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == intent_id)
    driver = FakeDriver()
    monkeypatch.setattr(explore, "get_driver", lambda _: driver)

    class FakeSandbox:
        def __init__(self, *args):
            self.args = args

    monkeypatch.setattr(explore, "ReviewSandboxBackend", FakeSandbox)
    seen = []

    def execute(backend, *args, **kwargs):
        seen.append(backend)
        return ProcessResult(0, json.dumps({"accepted": True, "data": {
            "description": "bounded PoC did not reproduce", "type": "observation", "evidence": "exit=0",
        }}), "")

    monkeypatch.setattr(explore, "run_worker_process", execute)
    assert explore.run_explore_task(
        cfg, client, host, current, client.export_project(pid), intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    assert len(seen) == 1 and isinstance(seen[0], FakeSandbox)
    assert seen[0] is not host
    assert "Withheld for isolated proof-of-concept" in driver.prompts[0]


def test_benchmark_requires_three_runs_and_reports_stability(tmp_path):
    report = evaluate({"a", "b"}, [{"a", "b"}, {"a"}, {"a", "b", "noise"}])
    assert report["stability"]["minimum_recall"] == 0.5
    assert report["stability"]["all_run_intersection"] == ["a"]
    assert report["runs"][2]["unexpected"] == ["noise"]

    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps({"expected": ["a", "b"]}))
    runs = []
    for index, values in enumerate((["a", "b"], ["a"], ["a", "b"])):
        path = tmp_path / f"run-{index}.json"
        path.write_text(json.dumps({"confirmed": values}))
        runs.append(path)
    args = ["audit-benchmark", "--expected", str(expected)]
    for path in runs:
        args.extend(["--run", str(path)])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert '"minimum_recall": 0.5' in result.output


def test_coverage_strategy_benchmark_reports_cost_recall_and_completion():
    run = {
        "confirmed": ["known-1"],
        "rejected": ["candidate-fp"],
        "metrics": {
            "review_calls": 2,
            "pi_calls": 6,
            "tokens": 12000,
            "wall_time_ms": 45000,
            "repeated_reads": 1,
            "cross_endpoint_chains": 1,
            "completion_correct": True,
        },
    }
    report = compare_strategies(
        {"known-1", "known-2"}, [run, run, run], [run, run, run],
    )
    file_topic = report["strategies"]["file_topic"]
    assert file_topic["stability"]["minimum_recall"] == 0.5
    assert file_topic["mean_metrics"]["review_calls"] == 2
    assert file_topic["mean_metrics"]["tokens"] == 12000
    assert file_topic["mean_metrics"]["wall_time_ms"] == 45000
    assert file_topic["mean_metrics"]["completion_correct_runs"] == 3
    assert file_topic["mean_metrics"]["confirmed_findings"] == 1
    assert file_topic["mean_metrics"]["rejected_findings"] == 1
    assert file_topic["completion_stability"] is True
