from __future__ import annotations

import json
from pathlib import Path

import pytest

from click.testing import CliRunner

from test_audit_pipeline import FakeDriver, api, config, project
from linen.cli import main
from linen.dispatcher.analysis import audit_graph, coverage, scope_gate, triage
from linen.dispatcher.analysis.benchmark import evaluate
from linen.dispatcher.analysis.semgrep import digest, write_json
from linen.dispatcher.analysis.spring_scan import SPRING_SCAN_INTENT, extract_routes, run_spring_scan
from linen.dispatcher.config import (
    CandidateTriageConfig,
    PocSandboxConfig,
    ScopeAdjudicationConfig,
    SpringScanConfig,
)
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks import explore
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, Review


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


def _scanner_fact(client, project_id: str, workdir: Path) -> tuple[str, list[dict]]:
    run = workdir / ".linen-analysis" / "fixture"
    source = run / "source"
    source.mkdir(parents=True)
    content = b"danger();\nsafe();\n"
    (source / "App.java").write_bytes(content)
    candidates = [
        {"fingerprint": "keep-me", "rule_id": "danger", "locations": [], "status": "unverified"},
        {"fingerprint": "drop-me", "rule_id": "noise", "locations": [], "status": "unverified"},
    ]
    write_json(run / "candidates.json", candidates)
    manifest = {
        "schema_version": 1,
        "status": "completed",
        "scanner": {"name": "fixture"},
        "snapshot": {"id": digest(content), "files": {"App.java": digest(content)}, "skipped": []},
        "artifact_hashes": {"candidates.json": digest((run / "candidates.json").read_bytes())},
    }
    write_json(run / "manifest.json", manifest)
    evidence = (
        f"artifact: {run / 'manifest.json'}\n"
        f"manifest_sha256: {digest((run / 'manifest.json').read_bytes())}\n"
        "status: completed"
    )
    return _conclude(client, project_id, ["origin"], "fixture scan", "route_scan", evidence), candidates


def test_scope_initial_intents_are_derived_from_graph(tmp_path):
    cfg = config(tmp_path, scan=True, mode="scope")
    cfg.audit.spring = SpringScanConfig(enabled=True)
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


def test_legacy_plan_review_is_preserved_but_requires_fresh_attestation(tmp_path):
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
    assert audit_graph._review_proposals(board) == [{
        "from": ["f001"],
        "type": "review:devils-advocate",
        "description": "@analysis:review:f001:attestation",
    }]

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
    cfg = config(tmp_path, scan=True, mode="scope")
    cfg.audit.spring = SpringScanConfig(enabled=True)
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


def test_reviewed_plan_fans_out_scanners_from_one_canonical_snapshot(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, scan=True, mode="scope")
    cfg.audit.spring = SpringScanConfig(enabled=True)
    current = project(api, audit_mode="scope")
    pid = current.project.id
    backend = LocalBackend(cfg.local, client)
    workdir = Path(backend.ensure_running(pid))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Api.java").write_text(
        '@RestController class Api { @GetMapping("/health") String health() { return "ok"; } }'
    )
    plan = coverage.create_plan(repo, workdir, cfg.audit.coverage)
    plan_id = _conclude(
        client, pid, ["origin"], coverage.PLAN_INTENT,
        plan["type"], plan["evidence"],
    )
    _approve(client, pid, plan_id)

    current = client.get_project(pid)
    proposals = audit_graph.required_intents(current, workdir, cfg.audit)
    assert {(item["type"], item["description"]) for item in proposals} == {
        ("search", SPRING_SCAN_INTENT),
    }
    assert all(item["from"] == [plan_id] for item in proposals)
    choices = audit_graph.selectable_skill_choices(current, workdir, cfg.audit)
    assert [(choice["skill_id"], choice["from"]) for choice in choices] == [
        ("security.semgrep", [plan_id]),
    ]

    _, plan_path, plan_record = coverage.get_plan(current, workdir)
    route_fact = run_spring_scan(
        plan_path.parent / "source",
        workdir / ".linen-analysis",
        cfg.audit.spring,
        canonical_snapshot=plan_record["snapshot"],
    )
    route_manifest = Path(route_fact["evidence"].splitlines()[0].removeprefix("artifact: "))
    assert json.loads(route_manifest.read_text())["snapshot"]["id"] == plan_record["snapshot"]["id"]


def test_spring_route_extractor_marks_only_uncovered_literal_route(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = """
@RestController
@RequestMapping("/api")
class ApiController {
  @GetMapping("/admin") public String admin() { return "ok"; }
  @GetMapping("/public") public String publicRoute() { return "ok"; }
}
class Config implements WebMvcConfigurer {
  void configure(InterceptorRegistry registry) {
    registry.addInterceptor(auth).addPathPatterns("/api/**").excludePathPatterns("/api/public");
  }
}
"""
    (repo / "ApiController.java").write_text(source)
    routes = extract_routes("ApiController.java", source)
    assert {(route["http_method"], route["path"]) for route in routes} == {
        ("GET", "/api/admin"), ("GET", "/api/public"),
    }
    fact = run_spring_scan(repo, tmp_path / "analysis", SpringScanConfig(enabled=True))
    manifest_path = Path(fact["evidence"].splitlines()[0].removeprefix("artifact: "))
    candidates = json.loads((manifest_path.parent / "candidates.json").read_text())
    assert [(item["properties"]["http_method"], item["properties"]["route"])
            for item in candidates] == [("GET", "/api/public")]
    assert candidates[0]["status"] == "unverified"


def test_triage_kept_candidate_becomes_independent_verification_branch(api, tmp_path):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.triage = CandidateTriageConfig(candidates_per_batch=20)
    current = project(api, audit_mode="scope")
    pid = current.project.id
    backend = LocalBackend(cfg.local, client)
    workdir = Path(backend.ensure_running(pid))
    source_id, _ = _scanner_fact(client, pid, workdir)
    _approve(client, pid, source_id)
    current = client.get_project(pid)
    source = next(fact for fact in current.facts if fact.id == source_id)
    batch = triage.batches(source, workdir, cfg.audit.triage)[0]
    intent_id = client.create_intent(
        pid, [source_id], batch["description"], "dispatcher.audit", intent_type="triage",
    ).data["id"]
    client.heartbeat(pid, intent_id, "tester")
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == intent_id)
    fact = triage.triage_outcome_fact({"data": {
        "description": "classified candidates", "type": "candidate_triage", "evidence": "source read",
        "triage": [
            {"fingerprint": "keep-me", "outcome": "keep", "category": "command-injection", "rationale": "reachable sink"},
            {"fingerprint": "drop-me", "outcome": "drop", "category": "noise", "rationale": "constant only"},
        ],
    }}, current, intent, workdir, cfg.audit.triage)
    response = client.conclude(
        pid, intent_id, "tester", fact["description"], fact_type=fact["type"], evidence=fact["evidence"],
    )
    triage_id = response.data["fact"]["id"]
    _approve(client, pid, triage_id)

    proposals = audit_graph._candidate_verify_proposals(  # graph contract, not a private queue
        client.get_project(pid), workdir, cfg.audit,
    )
    assert len(proposals) == 1
    assert proposals[0]["from"] == [triage_id]
    assert proposals[0]["description"] == triage.verify_description(source_id, "keep-me", 1)
    assert "drop-me" not in proposals[0]["description"]


def test_isolated_poc_uses_sandbox_backend_without_host_fallback(api, tmp_path, monkeypatch):
    _, client = api
    cfg = config(tmp_path, mode="scope")
    cfg.audit.poc_sandbox = PocSandboxConfig(enabled=True, image="trusted-local-image")
    current = project(api, audit_mode="scope")
    pid = current.project.id
    host = LocalBackend(cfg.local, client)
    workdir = Path(host.ensure_running(pid))
    source_id, _ = _scanner_fact(client, pid, workdir)
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
