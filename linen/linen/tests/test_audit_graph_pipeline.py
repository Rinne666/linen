from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from click.testing import CliRunner

from test_audit_pipeline import FakeDriver, api, config, project
from linen.cli import main
from linen.dispatcher.analysis import audit_graph, coverage, recon, scope_gate, skill_findings
from linen.dispatcher.analysis.benchmark import compare_strategies, evaluate
from linen.dispatcher.config import (
    AuditConfig,
    PocSandboxConfig,
    ScopeAdjudicationConfig,
    SemanticAuditConfig,
)
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks import explore
from linen.server.routers.intents import _candidate_attempt_count
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, ProofPayload, Review


def test_confirmed_promotions_do_not_consume_candidate_attempt_budget():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE facts (project_id TEXT, type TEXT, semantic_type TEXT, source_generation INTEGER)"
    )
    conn.executemany(
        "INSERT INTO facts VALUES ('proj_001', 'vulnerability', ?, 1)",
        [("candidate_finding",)] * 4 + [("confirmed_finding",)] * 4,
    )
    assert _candidate_attempt_count(conn, "proj_001", 1) == 4

    facts = [
        Fact(
            id=f"f{index:03d}", description="attempt", type="vulnerability",
            semantic_type=("candidate_finding" if index <= 4 else "confirmed_finding"),
            source_generation=1,
        )
        for index in range(1, 9)
    ]
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="hypothesis", created_at="2026-01-01T00:00:00Z",
            source_generation=1,
        ),
        facts=facts, intents=[], hints=[], reviews=[],
    )
    assert audit_graph.candidate_budget_overflow_ids(board, 4) == set()

    conn.execute(
        "INSERT INTO facts VALUES ('proj_001', 'vulnerability', 'rejected_finding', 1)"
    )
    assert _candidate_attempt_count(conn, "proj_001", 1) == 5
    conn.close()


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
    cfg.audit.recon.enabled = True
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
        ("search", recon.SNAPSHOT_INTENT),
    ]
    assert all(item["from"] == ["origin"] for item in proposals)


def test_terminal_recon_snapshot_without_result_has_bounded_retry(tmp_path):
    cfg = config(tmp_path, mode="scope")
    cfg.audit.recon.enabled = True
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[Fact(id="origin", description="repo"), Fact(id="goal", description="audit")],
        intents=[Intent(
            id="i001", from_=["origin"], description=recon.SNAPSHOT_INTENT,
            type="search", creator=audit_graph.CREATOR,
            created_at="2026-01-01T00:00:01Z", concluded_at="2026-01-01T00:00:02Z",
        )],
        hints=[], reviews=[],
    )

    proposals = audit_graph.required_intents(board, tmp_path, cfg.audit)
    assert len(proposals) == 1
    assert proposals[0]["target"].endswith("attempt:2")
    for index in range(2, audit_graph.MAX_STAGE_INTENT_ATTEMPTS + 1):
        board.intents.append(board.intents[0].model_copy(update={"id": f"i{index:03d}"}))
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
    fact_with_server_bound_role = explore._bind_proof_obligation(intent, {
        "description": "request reaches the handler without an identity gate",
        "type": "attacker_control",
        "evidence": "file:Api.java\nline:42",
        "proof": {"attributes": {"path_signature": "HTTP request -> handler"}},
    })
    assert fact_with_server_bound_role["proof"]["claim_kind"] == "attacker_control"
    assert fact_with_server_bound_role["proof"]["attributes"] == {
        "path_signature": "HTTP request -> handler",
    }

    with pytest.raises(explore.ProofContractError, match="proof claim_kind must be attacker_control"):
        explore._bind_proof_obligation(intent, {
            "description": "request reaches the handler",
            "type": "attacker_control",
            "evidence": "file:Api.java\nline:42",
            "proof": {"claim_kind": "reachability"},
        })
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


def test_sanitizer_negative_control_gets_independent_review():
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_negative_control", title="audit", status="active",
            bootstrap_enabled=False, audit_mode="scope", created_at="2026-01-01T00:00:00Z",
        ),
        facts=[
            Fact(id="origin", description="repo"), Fact(id="goal", description="audit"),
            Fact(
                id="f-negative", description="parameter binding blocks SQL injection",
                type="sanitizer", semantic_type="observation", status="draft",
                evidence="testcode/BenchmarkTest00011.py:47-50",
            ),
        ],
        intents=[], hints=[], reviews=[],
    )

    assert audit_graph._review_proposals(board) == [{
        "from": ["f-negative"],
        "type": "review:devils-advocate",
        "description": "@analysis:review:f-negative",
    }]


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
    cfg.audit.recon.enabled = True
    board = project(api, audit_mode="scope")
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = cfg
    loop.client = client
    loop.container_manager = LocalBackend(cfg.local, client)
    assert loop._materialize_audit_intents(board)
    fresh = client.get_project(board.project.id)
    assert {intent.description for intent in fresh.intents} == {
        recon.SNAPSHOT_INTENT,
    }
    assert all(intent.creator == audit_graph.CREATOR for intent in fresh.intents)
    assert not loop._materialize_audit_intents(fresh)


def test_scope_gate_bypasses_a_full_legacy_ready_window(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.recon.enabled = True
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
    cfg.audit.recon.enabled = True
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


def test_exhausted_recon_repair_budget_concludes_claim_free_gap(api, tmp_path, monkeypatch):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.recon.enabled = True
    cfg.audit.max_result_attempts = 3
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = request.args['value']\nhandle(value)\n")
    board = project(api, repo=repo, audit_mode="scope")
    backend = LocalBackend(cfg.local, client)
    workdir = Path(backend.ensure_running(board.project.id))
    snapshot = recon.create_snapshot(repo, workdir, 1, cfg.audit.recon)
    snapshot_intent = client.create_intent(
        board.project.id, ["origin"], recon.SNAPSHOT_INTENT,
        audit_graph.CREATOR, intent_type="search",
    ).data
    assert client.heartbeat(board.project.id, snapshot_intent["id"], "tester").ok
    snapshot_write = client.conclude(
        board.project.id, snapshot_intent["id"], "tester",
        snapshot["description"], fact_type=snapshot["type"], evidence=snapshot["evidence"],
    )
    assert snapshot_write.ok, snapshot_write.text
    snapshot_fact_id = snapshot_write.data["fact"]["id"]
    category_intent = client.create_intent(
        board.project.id, [snapshot_fact_id], recon.category_description("input-validation"),
        audit_graph.CREATOR, intent_type="search",
    ).data
    worker = cfg.workers[0]
    assert client.heartbeat(board.project.id, category_intent["id"], worker.name).ok
    current = client.get_project(board.project.id)
    intent = next(item for item in current.intents if item.id == category_intent["id"])
    monkeypatch.setattr(
        explore, "_run_process",
        lambda *_args, **_kwargs: pytest.fail("exhausted correction budget must not call a model"),
    )

    outcome = explore.run_explore_task(
        cfg,
        client,
        backend,
        current,
        client.export_project(board.project.id),
        intent,
        worker,
        TaskCancellation(),
        attempt=4,
    )

    assert outcome == "success"
    concluded = client.get_project(board.project.id)
    result = next(f for f in concluded.facts if f.type == "recon")
    record = recon.result_record(result, workdir)
    assert result.status == "triaged"
    assert record["status"] == "partial"
    assert record["leads"] == []
    assert record["citations"] == []
    assert "No model result passed validation" in record["gaps"][0]


def test_isolated_poc_uses_sandbox_backend_without_host_fallback(api, tmp_path, monkeypatch):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.recon.enabled = True
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
    prompt = driver.prompts[0]
    assert "Withheld for isolated proof-of-concept" in prompt
    # The reproduction target (candidate statement and cited evidence) must
    # cross into the container; prior graph reasoning stays withheld.
    assert prompt.startswith("# ISOLATED POC EXECUTION TASK")
    assert "Candidate statement to reproduce" in prompt
    assert "Cited evidence" in prompt
    assert coverage.PLAN_INTENT in prompt


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


def _audit_config(tmp_path) -> AuditConfig:
    return AuditConfig(
        enabled=True,
        mode="scope",
        scope_adjudication=ScopeAdjudicationConfig(enabled=False),
        semantic=SemanticAuditConfig(enabled=False),
    )


def _chain_board(
    *,
    with_reachability: bool = True,
    promoted: bool = False,
) -> ProjectDetail:
    now = "2026-01-01T00:00:00Z"
    facts = [
        Fact(id="origin", description="repo"),
        Fact(id="f-df1", description="cookie reaches file open", type="dataflow"),
        Fact(id="f-df2", description="path traversal precondition", type="dataflow"),
    ]
    intents = [
        Intent(id="i-df1", from_=["origin"], to="f-df1", description="trace cookie",
               type="search", creator=audit_graph.CREATOR, created_at=now, concluded_at=now),
        Intent(id="i-df2", from_=["f-df1"], to="f-df2", description="verify traversal",
               type="verify", creator=audit_graph.CREATOR, created_at=now, concluded_at=now),
    ]
    reviews = [
        Review(id="r-df1", fact_id="f-df1", verdict="VALID", confidence="firm",
               summary="checked", created_at=now),
        Review(id="r-df2", fact_id="f-df2", verdict="VALID", confidence="firm",
               summary="checked", created_at=now),
    ]
    if with_reachability:
        facts.append(Fact(id="f-reach", description="anonymous route reachable", type="reachability"))
        intents.append(Intent(
            id="i-reach", from_=["f-df2"], to="f-reach", description="verify reachability",
            type="reach", creator=audit_graph.CREATOR, created_at=now, concluded_at=now,
        ))
        reviews.append(Review(id="r-reach", fact_id="f-reach", verdict="VALID",
                              confidence="firm", summary="checked", created_at=now))
    if promoted:
        facts.append(Fact(id="f-vuln", description="terminal finding", type="vulnerability",
                          semantic_type="candidate_finding"))
        intents.append(Intent(
            id="i-char", from_=["f-df1", "f-df2"], to="f-vuln",
            description="characterize the chain", type="characterize",
            creator=audit_graph.CREATOR, created_at=now, concluded_at=now,
        ))
    return ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="audit", status="active", bootstrap_enabled=False,
            audit_mode="scope", created_at=now,
        ),
        facts=facts, intents=intents, hints=[], reviews=reviews,
    )


def test_required_intents_promotes_reviewed_chain_to_characterize(tmp_path):
    board = _chain_board()
    proposals = audit_graph.required_intents(board, tmp_path, _audit_config(tmp_path))
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal["type"] == "characterize"
    assert sorted(proposal["from"]) == ["f-df1", "f-df2", "f-reach"]
    assert "f-df1" in proposal["description"] and "f-reach" in proposal["description"]


def test_required_intents_requests_reachability_before_characterize(tmp_path):
    board = _chain_board(with_reachability=False)
    proposals = audit_graph.required_intents(board, tmp_path, _audit_config(tmp_path))
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal["type"] == "reach"
    assert sorted(proposal["from"]) == ["f-df1", "f-df2"]


def test_promotion_skips_already_promoted_component(tmp_path):
    board = _chain_board(promoted=True)
    assert audit_graph.required_intents(board, tmp_path, _audit_config(tmp_path)) == []


def test_unreviewed_chain_does_not_promote(tmp_path):
    board = _chain_board()
    board.reviews = []
    assert audit_graph.required_intents(board, tmp_path, _audit_config(tmp_path)) == []


def _dynamic_fact(fact_id: str, fact_type: str, candidate: str) -> Fact:
    return Fact(
        id=fact_id, description="isolated run", type=fact_type,
        proof=ProofPayload(
            claim_kind=fact_type, subject_ids=[candidate],
            attributes={"mode": "dynamic", "candidate_id": candidate},
        ),
    )


def test_dynamic_evidence_gate_requires_both_roles_and_reviews():
    board = _chain_board(promoted=True)
    assert not audit_graph._dynamic_evidence_complete(board, "f-vuln")
    board.facts.append(_dynamic_fact("f-pos", "reproduction", "f-vuln"))
    assert not audit_graph._dynamic_evidence_complete(board, "f-vuln")
    board.facts.append(_dynamic_fact("f-neg", "negative_control", "f-vuln"))
    assert not audit_graph._dynamic_evidence_complete(board, "f-vuln")
    now = "2026-01-01T00:00:00Z"
    board.reviews.extend([
        Review(id="r-pos", fact_id="f-pos", verdict="VALID", confidence="firm",
               summary="checked", created_at=now),
        Review(id="r-neg", fact_id="f-neg", verdict="VALID", confidence="firm",
               summary="checked", created_at=now),
    ])
    assert audit_graph._dynamic_evidence_complete(board, "f-vuln")
    # Static-mode evidence does not satisfy the dynamic gate.
    board.facts = [
        Fact(
            id="f-pos", description="static", type="reproduction",
            proof=ProofPayload(claim_kind="reproduction", subject_ids=["f-vuln"],
                               attributes={"mode": "static", "candidate_id": "f-vuln"}),
        ) if fact.id == "f-pos" else fact
        for fact in board.facts
    ]
    assert not audit_graph._dynamic_evidence_complete(board, "f-vuln")


def test_audit_summary_blocks_unconfirmed_candidate_without_dynamic_evidence(tmp_path):
    """The summary gate wiring: the fake-convergence guard returns None for a
    candidate whose dynamic evidence pair is missing, regardless of the
    sandbox flag (Recon being inactive also blocks here, which keeps this a
    deterministic unit-level check of the guard's inputs)."""
    cfg = _audit_config(tmp_path)
    cfg.poc_sandbox = PocSandboxConfig(enabled=True, image="poc-test:latest")
    board = _chain_board(promoted=True)
    assert not audit_graph._dynamic_evidence_complete(board, "f-vuln")
    assert audit_graph.audit_summary_inputs(board, tmp_path, cfg) is None


# --- E41: the authority boundary for coverage observations ------------------
# A structurally valid model coverage unit may claim it covered a boundary.
# That claim is a non-authoritative audit observation: it must not become a
# confirmed finding and must not satisfy the coverage-complete attestation.


def _covered_coverage_unit_fact() -> Fact:
    """A model coverage unit that claims the boundary is covered."""

    return Fact(
        id="f-cov-covered",
        description="hunter claims POST /x is covered",
        type="coverage_unit",
        semantic_type="coverage_unit",
        proof=ProofPayload(
            claim_kind="coverage_unit",
            subject_ids=["f-df1"],
            attributes={"coverage_unit": {
                "coverage_id": "POST%20%2Fx::anon%3Edb::api::injection",
                "state": "covered",
                "surface": "POST /x",
                "boundary": "anon->db",
                "subsystem": "api",
                "attack_class": "injection",
            }},
        ),
    )


def test_coverage_observation_does_not_confirm_finding(tmp_path):
    """E41: the confirmation authority is unchanged by a coverage observation."""

    cfg = _audit_config(tmp_path)
    plain = _chain_board(promoted=True)
    with_coverage = _chain_board(promoted=True)
    with_coverage.facts.append(_covered_coverage_unit_fact())

    # The attestation gate reacts to the coverage observation in no way.
    assert audit_graph.audit_summary_inputs(with_coverage, tmp_path, cfg) == \
           audit_graph.audit_summary_inputs(plain, tmp_path, cfg)

    # The unit never becomes a finding record and never confirms anything.
    assert skill_findings.collect_finding_records(with_coverage) == []
    assert not [fact for fact in with_coverage.facts
                if fact.semantic_type == "confirmed_finding"]

    # The covered unit only removes itself from the hunt queue; the critic
    # wave remains, because coverage is still a non-authoritative observation.
    config = SimpleNamespace(
        skill_driven=SimpleNamespace(
            enabled=True,
            coverage_seeds=[SimpleNamespace(
                coverage_id="POST%20%2Fx::anon%3Edb::api::injection",
                surface="POST /x", boundary="anon->db", subsystem="api",
                attack_class="injection", starting_paths=["app.py"])],
            max_bounces=2, max_candidates_per_wave=8))
    proposals = audit_graph._skill_driven_proposals(with_coverage, config, limit=8)
    assert all(proposal["type"] != "hunt" for proposal in proposals)
    assert any(proposal["type"] == "coverage-critic" for proposal in proposals)
