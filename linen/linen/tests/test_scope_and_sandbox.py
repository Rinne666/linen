from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from test_audit_pipeline import api, config, project, FakeDriver
from linen.dispatcher.analysis import audit_graph, coverage
from linen.dispatcher.analysis.artifacts import load_artifact, select_snapshot
from linen.dispatcher.analysis.artifacts import digest
from linen.dispatcher.config import CoverageConfig, ReviewSandboxConfig
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.runtime.review_sandbox import DockerReviewProcess
from linen.dispatcher.tasks import explore, reason, review
from linen.dispatcher.workers.base import DriverResult


def scope_setup(api, tmp_path, *, topics=None):
    _, client = api
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "a.py").write_text("value = 1\n")
    (repo / "b.py").write_text("other = 2\n")
    cfg = config(tmp_path)
    cfg.audit.mode = "scope"
    cfg.audit.coverage = CoverageConfig(topics=topics or ["authorization"], files_per_cell=1)
    current = project(api, repo, audit_mode="scope")
    pid = current.project.id
    backend = LocalBackend(cfg.local, client)
    iid = client.create_intent(pid, ["origin"], coverage.PLAN_INTENT, "reasoner", intent_type="search").data["id"]
    client.heartbeat(pid, iid, "tester")
    current = client.get_project(pid)
    intent = next(i for i in current.intents if i.id == iid)
    assert explore.run_explore_task(cfg, client, backend, current, client.export_project(pid), intent,
                                    cfg.workers[0], TaskCancellation()) == "success"
    current = client.get_project(pid)
    fact, path, plan = coverage.get_plan(current, Path(backend.container_name(pid)))
    return cfg, backend, pid, fact, path, plan


def approve(client, pid, fid):
    assert client.create_review(
        pid,
        fid,
        "VALID",
        "verified",
        confidence="firm",
        diagnostics={"attestation_check": {
            "artifact_integrity": "valid",
            "source_consistency": "consistent",
            "scope_complete": "yes",
            "contradictions": [],
        }},
    ).ok


def run_cell(api, cfg, backend, pid, plan_fact, plan, cell, monkeypatch, *, outcome="checked", parents=None):
    _, client = api
    parents = parents or [plan_fact.id]
    data = {"from": parents, "type": "verify", "description": coverage.cell_description(plan, cell)}
    coverage.validate_intent(client.get_project(pid), Path(backend.container_name(pid)), cfg.audit.coverage, data)
    iid = client.create_intent(pid, parents, data["description"], "reasoner", intent_type="verify").data["id"]
    client.heartbeat(pid, iid, "tester")
    current = client.get_project(pid)
    intent = next(i for i in current.intents if i.id == iid)
    filename = cell["files"][0]
    text = (Path(plan["source"]) / filename).read_text().splitlines()[0]
    leads = []
    if outcome == "needs_followup":
        leads = [{
            "file": filename,
            "line": 1,
            "summary": "Observed a bounded authorization-relevant value",
            "next_step": "Trace this value to its concrete authorization decision",
        }]
    driver = FakeDriver()
    monkeypatch.setattr(explore, "get_driver", lambda _: driver)
    monkeypatch.setattr(explore, "run_worker_process", lambda *a, **k: ProcessResult(0, json.dumps({
        "accepted": True, "data": {"description": "checked", "coverage": {
            "outcome": outcome, "inspected_files": cell["files"],
            "citations": [{"file": filename, "line": 1, "code": text}],
            "leads": leads, "rationale": "examined input boundary",
        }},
    }), ""))
    assert explore.run_explore_task(cfg, client, backend, current, client.export_project(pid), intent,
                                    cfg.workers[0], TaskCancellation()) == "success"
    assert "Managed coverage task" in driver.prompts[0]
    current = client.get_project(pid)
    return next(i.to for i in current.intents if i.id == iid)


def test_coverage_conclude_repairs_contract_without_generic_prompt(
    api, tmp_path, monkeypatch,
):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    cell = plan["cells"][0]
    description = coverage.cell_description(plan, cell)
    iid = client.create_intent(
        pid, [fact.id], description, "reasoner", intent_type="verify",
    ).data["id"]
    client.heartbeat(pid, iid, "tester")
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == iid)
    filename = cell["files"][0]
    exact = (Path(plan["source"]) / filename).read_text().splitlines()[0]

    class ConcludingDriver(FakeDriver):
        def __init__(self):
            super().__init__()
            self.conclude_prompts = []

        def supports_conclude(self):
            return True

        def build_conclude(self, worker, prompt, session):
            self.conclude_prompts.append(prompt)
            return ["fake-worker", "--conclude"]

    driver = ConcludingDriver()
    responses = iter([
        ProcessResult(0, json.dumps({
            "accepted": True, "data": {"description": "bad citation", "coverage": {
                "outcome": "checked", "inspected_files": cell["files"],
                "citations": [{"file": filename, "line": 1, "code": "invented"}],
                "rationale": "checked",
            }},
        }), ""),
        # The documented unwrapped form is accepted only for a managed
        # coverage task and is normalized before generic payload validation.
        ProcessResult(0, json.dumps({
            "description": "repaired", "coverage": {
                "outcome": "checked", "inspected_files": cell["files"],
                "citations": [{"file": filename, "line": 1, "code": exact}],
                "rationale": "verified exact frozen-source citations",
            },
        }), ""),
    ])
    monkeypatch.setattr(explore, "get_driver", lambda _: driver)
    monkeypatch.setattr(explore, "run_worker_process", lambda *a, **k: next(responses))

    assert explore.run_explore_task(
        cfg, client, backend, current, client.export_project(pid), intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    assert driver.prompts[0].startswith("# Managed coverage task")
    assert "senior application security auditor" not in driver.prompts[0]
    assert "Citation does not match the frozen source" in driver.conclude_prompts[0]
    result_id = next(item.to for item in client.get_project(pid).intents if item.id == iid)
    assert next(item for item in client.get_project(pid).facts if item.id == result_id).type == "coverage_result"


def test_plan_covers_every_file_topic_pair(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src/a.py").write_text("a=1")
    (repo / "README").write_text("doc")
    work = tmp_path / "work"
    payload = coverage.create_plan(repo, work, CoverageConfig(topics=["authorization", "input"], files_per_cell=1))
    from linen.server.models import Fact
    _, plan = load_artifact(Fact(id="f", **payload), work)
    pairs = [(name, cell["topic"]) for cell in plan["cells"] for name in cell["files"]]
    assert len(pairs) == len(set(pairs)) == 4
    assert set(pairs) == {(name, topic) for name in ("README", "src/a.py") for topic in ("authorization", "input")}
    with pytest.raises(ValueError, match="nothing was silently truncated"):
        coverage.create_plan(repo, work, CoverageConfig(max_cells=1, files_per_cell=1))


def test_scope_requires_all_reviewed_cells_and_allows_zero_findings(api, tmp_path, monkeypatch):
    _, client = api
    cfg, backend, pid, fact, path, plan = scope_setup(api, tmp_path)
    work = Path(backend.container_name(pid))
    assert len(plan["cells"]) == 2
    approve(client, pid, fact.id)
    first = run_cell(api, cfg, backend, pid, fact, plan, plan["cells"][0], monkeypatch)
    assert any("awaiting_review" in b for b in coverage.scope_blockers(client.get_project(pid), work, cfg.audit.coverage, [fact.id]))
    approve(client, pid, first)
    assert coverage.scope_blockers(client.get_project(pid), work, cfg.audit.coverage, [fact.id])
    second = run_cell(api, cfg, backend, pid, fact, plan, plan["cells"][1], monkeypatch)
    approve(client, pid, second)
    assert coverage.scope_blockers(client.get_project(pid), work, cfg.audit.coverage, [fact.id]) == []

    current = client.get_project(pid)
    group = coverage.module_summary_groups(current, work, cfg.audit.coverage)[0]
    module_intent_id = client.create_intent(
        pid, [group["plan_fact_id"], *group["result_ids"]], group["description"],
        "dispatcher.audit", intent_type="synthesize",
    ).data["id"]
    client.heartbeat(pid, module_intent_id, "tester")
    current = client.get_project(pid)
    module_intent = next(i for i in current.intents if i.id == module_intent_id)
    assert explore.run_explore_task(
        cfg, client, backend, current, client.export_project(pid), module_intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    module_fact = next(i.to for i in client.get_project(pid).intents if i.id == module_intent_id)
    approve(client, pid, module_fact)

    trace_intent = client.create_intent(
        pid, [fact.id], "ordinary reviewed trace", "reasoner", intent_type="trace",
    ).data["id"]
    client.heartbeat(pid, trace_intent, "tester")
    trace_response = client.conclude(
        pid, trace_intent, "tester", "No exploitable path in this trace",
        fact_type="observation", evidence="a.py:1",
    )
    trace_fact = trace_response.data["fact"]["id"]
    approve(client, pid, trace_fact)

    current = client.get_project(pid)
    inputs = audit_graph.audit_summary_inputs(current, work, cfg.audit)
    assert set(inputs) == {module_fact, trace_fact}
    summary_intent_id = client.create_intent(
        pid, inputs, audit_graph.AUDIT_SUMMARY_INTENT,
        "dispatcher.audit", intent_type="synthesize",
    ).data["id"]
    client.heartbeat(pid, summary_intent_id, "tester")
    current = client.get_project(pid)
    summary_intent = next(i for i in current.intents if i.id == summary_intent_id)
    assert explore.run_explore_task(
        cfg, client, backend, current, client.export_project(pid), summary_intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    summary_fact = next(i.to for i in client.get_project(pid).intents if i.id == summary_intent_id)
    approve(client, pid, summary_fact)
    assert audit_graph.scope_blockers(client.get_project(pid), work, cfg.audit, [summary_fact]) == []

    monkeypatch.setattr(reason, "get_driver", lambda _: FakeDriver())
    monkeypatch.setattr(reason, "run_worker_process", lambda *a, **k: ProcessResult(0, json.dumps({
        "accepted": True, "data": {"complete": {"from": [summary_fact], "description": "All planned checks complete; zero findings"}},
    }), ""))
    current = client.get_project(pid)
    assert reason.run_reason_task(cfg, client, backend, current, client.export_project(pid),
                                  cfg.workers[0], TaskCancellation()) == "success"
    assert client.get_project(pid).project.status == "completed"


def test_needs_followup_stays_uncovered_and_retry_links_history(api, tmp_path, monkeypatch):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    work = Path(backend.container_name(pid))
    cell = plan["cells"][0]
    approve(client, pid, fact.id)
    result = run_cell(api, cfg, backend, pid, fact, plan, cell, monkeypatch, outcome="needs_followup")
    approve(client, pid, result)
    state = coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)
    assert state["cells"][0]["status"] == "needs_followup"
    retry = next(
        proposal for proposal in audit_graph.required_intents(
            client.get_project(pid), work, cfg.audit,
        )
        if proposal["description"] == coverage.cell_description(plan, cell)
    )
    assert retry["from"] == [fact.id, result]
    with pytest.raises(ValueError, match="prior outcome"):
        coverage.validate_intent(client.get_project(pid), work, cfg.audit.coverage, {
            "from": [fact.id], "type": "verify", "description": coverage.cell_description(plan, cell),
        })
    second = run_cell(api, cfg, backend, pid, fact, plan, cell, monkeypatch, parents=[result])
    approve(client, pid, second)
    assert coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)["cells"][0]["status"] == "checked"


def test_invalid_coverage_review_becomes_retryable(api, tmp_path, monkeypatch):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    work = Path(backend.container_name(pid))
    cell = plan["cells"][0]
    approve(client, pid, fact.id)
    result = run_cell(api, cfg, backend, pid, fact, plan, cell, monkeypatch)
    assert client.create_review(
        pid, result, "INVALID", "rationale contradicts source at a.py:1", confidence="certain",
    ).ok

    state = coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)
    assert state["cells"][0]["status"] == "invalid"
    retry = next(
        proposal for proposal in audit_graph.required_intents(
            client.get_project(pid), work, cfg.audit,
        )
        if proposal["description"] == coverage.cell_description(plan, cell)
    )
    assert retry["from"] == [fact.id, result]

    replacement = run_cell(
        api, cfg, backend, pid, fact, plan, cell, monkeypatch, parents=[result],
    )
    approve(client, pid, replacement)
    assert coverage.coverage_state(
        client.get_project(pid), work, cfg.audit.coverage,
    )["cells"][0]["status"] == "checked"


def test_coverage_review_uses_attestation_specific_prompt(api, tmp_path, monkeypatch):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    result = run_cell(api, cfg, backend, pid, fact, plan, plan["cells"][0], monkeypatch)
    iid = client.create_intent(
        pid, [result], f"@analysis:review:{result}", "dispatcher.audit",
        intent_type="review:devils-advocate",
    ).data["id"]
    client.heartbeat(pid, iid, "tester")
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == iid)
    driver = FakeDriver()
    monkeypatch.setattr(review, "get_driver", lambda _: driver)
    monkeypatch.setattr(review, "run_worker_process", lambda *a, **k: ProcessResult(0, json.dumps({
        "verdict": "VALID",
        "confidence": "firm",
        "summary": "independently checked each assigned source file",
        "reasoning": "citations and rationale match the frozen source",
    }), ""))

    assert review.run_review_task(
        cfg, client, backend, current, client.export_project(pid), intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    assert driver.prompts[0].startswith("# Managed coverage review")
    assert "devil's advocate" not in driver.prompts[0]
    assert "Verify every claimed citation and every objective statement" in driver.prompts[0]
    assert next(item for item in client.get_project(pid).facts if item.id == result).status == "triaged"


def test_budget_and_duplicate_intents_do_not_silently_complete(api, tmp_path):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    work = Path(backend.container_name(pid))
    description = coverage.cell_description(plan, plan["cells"][0])
    client.create_intent(pid, [fact.id], description, "reasoner", intent_type="verify")
    state = coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)
    assert state["cells"][0]["status"] == "queued"
    with pytest.raises(ValueError, match="running"):
        coverage.validate_intent(client.get_project(pid), work, cfg.audit.coverage,
                                 {"from": [fact.id], "type": "verify", "description": description})
    assert coverage.scope_blockers(client.get_project(pid), work, cfg.audit.coverage, [fact.id])


def test_compacted_coverage_intents_return_to_pending_without_spending_budget(
    api, tmp_path,
):
    http, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path, topics=[
        "authorization", "input-validation", "dangerous-operations",
    ])
    work = Path(backend.container_name(pid))
    for cell in plan["cells"]:
        assert client.create_intent(
            pid, [fact.id], coverage.cell_description(plan, cell),
            "dispatcher.audit", intent_type="verify",
        ).ok
    assert http.put(f"/projects/{pid}/status", json={"status": "stopped"}).status_code == 200
    response = client.compact_coverage_intents(pid, keep=2, dry_run=False)
    assert response.ok

    state = coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)
    assert state["summary"]["by_status"] == {"pending": 4, "queued": 2}
    assert all(row["attempts"] in {0, 1} for row in state["cells"])


def test_false_citations_and_changed_snapshots_rejected(api, tmp_path):
    _, client = api
    cfg, backend, pid, fact, path, plan = scope_setup(api, tmp_path)
    cell = plan["cells"][0]
    iid = client.create_intent(pid, [fact.id], coverage.cell_description(plan, cell), "reasoner", intent_type="verify").data["id"]
    current = client.get_project(pid)
    intent = next(i for i in current.intents if i.id == iid)
    with pytest.raises(ValueError, match="frozen source"):
        coverage.outcome_fact({"coverage": {
            "outcome": "checked", "rationale": "done", "inspected_files": cell["files"],
            "citations": [{"file": cell["files"][0], "line": 1, "code": "invented"}],
        }}, current, intent, Path(backend.container_name(pid)))

    with pytest.raises(ValueError, match="structured lead"):
        coverage.outcome_fact({"coverage": {
            "outcome": "needs_followup", "rationale": "candidate remains",
            "inspected_files": cell["files"],
            "citations": [{"file": cell["files"][0], "line": 1, "code": "value = 1"}],
            "leads": [],
        }}, current, intent, Path(backend.container_name(pid)))

    relocated = coverage.outcome_fact({"coverage": {
        "outcome": "checked", "rationale": "done", "inspected_files": cell["files"],
        "citations": [{"file": cell["files"][0], "line": 99, "code": "value = 1"}],
    }}, current, intent, Path(backend.container_name(pid)))
    normalized = json.loads(relocated["evidence"])["citations"][0]
    assert normalized == {"file": cell["files"][0], "line": 1, "code": "value = 1"}
    indentation_drift = coverage.outcome_fact({"coverage": {
        "outcome": "checked", "rationale": "done", "inspected_files": cell["files"],
        "citations": [{"file": cell["files"][0], "line": 1, "code": "\t\tvalue = 1"}],
    }}, current, intent, Path(backend.container_name(pid)))
    canonical = json.loads(indentation_drift["evidence"])["citations"][0]
    assert canonical == {"file": cell["files"][0], "line": 1, "code": "value = 1"}
    (path.parent / "source" / cell["files"][0]).write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        coverage.cell_context(current, intent, Path(backend.container_name(pid)))


def test_sandbox_snapshot_selection_uses_ancestor_plan(api, tmp_path):
    _, client = api
    cfg, backend, pid, fact, path, plan = scope_setup(api, tmp_path)
    source, snapshot = select_snapshot(client.get_project(pid), fact.id, Path(backend.container_name(pid)))
    assert source == path.parent / "source"
    assert snapshot["id"] == plan["snapshot"]["id"]
    with pytest.raises(ValueError, match="ancestor"):
        select_snapshot(client.get_project(pid), "origin", Path(backend.container_name(pid)))


def test_sandbox_rejects_privileged_or_host_environment():
    with pytest.raises(ValueError, match="non-root"):
        ReviewSandboxConfig(user="0:0")
    with pytest.raises(ValueError, match="environment"):
        ReviewSandboxConfig(env_allowlist=["HOME"])


def test_missing_docker_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.runtime.review_sandbox.shutil.which", lambda _: None)
    proc = DockerReviewProcess(ReviewSandboxConfig(enabled=True, image="no-image"), tmp_path,
                               {"id": "test", "files": {}}, tmp_path / "run", ["sh"], {}, 2)
    with pytest.raises(RuntimeError, match="refusing host fallback"):
        proc.start()


@pytest.mark.skipif(not os.environ.get("LINEN_DOCKER_TEST_IMAGE"), reason="Set LINEN_DOCKER_TEST_IMAGE for real isolation tests")
def test_real_docker_isolation_and_timeout(tmp_path):
    image = os.environ["LINEN_DOCKER_TEST_IMAGE"]
    source = tmp_path / "source"
    source.mkdir()
    (source / "code.txt").write_text("visible-source")
    outside = tmp_path / "history.txt"
    outside.write_text("private-history")
    snapshot = {"id": "test", "files": {"code.txt": digest(b"visible-source")}}
    cfg = ReviewSandboxConfig(enabled=True, image=image)
    script = (
        'test "$(cat /repo/code.txt)" = visible-source && '
        f'test ! -e "{outside}" && '
        'test ! -e /var/run/docker.sock && '
        'test ! -e /root/.codex && '
        'test -z "$UNAPPROVED_SECRET" && '
        'test "$(id -u)" != 0 && '
        '! touch /repo/forbidden && '
        '! touch /etc/forbidden && '
        'echo writable > /work/probe && '
        'test "$(cat /work/probe)" = writable && echo isolated'
    )
    proc = DockerReviewProcess(cfg, source, snapshot, tmp_path / "run", ["/bin/sh", "-c", script],
                               {"UNAPPROVED_SECRET": "do-not-pass"}, 15)
    proc.start()
    result = proc.communicate(20)
    assert result.returncode == 0 and "isolated" in result.stdout, result
    assert not (source / "forbidden").exists()
    assert not subprocess.run(["docker", "inspect", proc.name], capture_output=True).returncode == 0
    slow = DockerReviewProcess(cfg, source, snapshot, tmp_path / "slow", ["/bin/sh", "-c", "sleep 60"], {}, 1)
    slow.start()
    result = slow.communicate(5)
    assert result.timed_out
    assert subprocess.run(["docker", "inspect", slow.name], capture_output=True).returncode != 0
    cancelled = DockerReviewProcess(cfg, source, snapshot, tmp_path / "cancelled", ["/bin/sh", "-c", "sleep 60"], {}, 30)
    cancelled.start()
    cancelled.cancel("user stopped")
    result = cancelled.communicate(5)
    assert result.cancelled
    assert subprocess.run(["docker", "inspect", cancelled.name], capture_output=True).returncode != 0


@pytest.mark.skipif(not os.environ.get("LINEN_DOCKER_TEST_IMAGE"), reason="Set LINEN_DOCKER_TEST_IMAGE for real isolation tests")
def test_review_task_uses_real_container_and_saves_execution(api, tmp_path, monkeypatch):
    import shlex

    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    cfg.audit.review_sandbox = ReviewSandboxConfig(enabled=True, image=os.environ["LINEN_DOCKER_TEST_IMAGE"])
    iid = client.create_intent(pid, [fact.id], "Prior graph reasoning should be withheld", "reasoner",
                               intent_type="review:cold-verifier").data["id"]
    client.heartbeat(pid, iid, "tester")
    current = client.get_project(pid)
    intent = next(i for i in current.intents if i.id == iid)
    response = json.dumps({"accepted": True, "data": {"verdict": "VALID", "confidence": "firm", "summary": "scope checked"}})

    class ContainerDriver(FakeDriver):
        def build_execute(self, worker, prompt, session):
            self.prompts.append(prompt)
            return DriverResult(["/bin/sh", "-c", "test -r /repo/a.py && test -r /input/record.json && printf '%s\\n' " + shlex.quote(response)])

    driver = ContainerDriver()
    monkeypatch.setattr(review, "get_driver", lambda _: driver)
    assert review.run_review_task(cfg, client, backend, current, client.export_project(pid), intent,
                                   cfg.workers[0], TaskCancellation()) == "success"
    current = client.get_project(pid)
    execution = current.reviews[0].cold_verification["execution"]
    assert execution["backend"] == "docker"
    assert execution["snapshot"] == plan["snapshot"]["id"]
    assert execution["image_id"].startswith("sha256:")
    assert Path(execution["artifact"]).is_file()
    assert "Prior graph reasoning should be withheld" not in driver.prompts[0]


def test_retry_budget_and_changed_scope_are_explicit(api, tmp_path, monkeypatch):
    _, client = api
    cfg, backend, pid, fact, _, plan = scope_setup(api, tmp_path)
    cfg.audit.coverage.max_attempts_per_cell = 1
    cell = plan["cells"][0]
    result = run_cell(api, cfg, backend, pid, fact, plan, cell, monkeypatch, outcome="blocked")
    approve(client, pid, result)
    work = Path(backend.container_name(pid))
    state = coverage.coverage_state(client.get_project(pid), work, cfg.audit.coverage)
    assert state["cells"][0]["retry_exhausted"]
    with pytest.raises(ValueError, match="budget"):
        coverage.validate_intent(client.get_project(pid), work, cfg.audit.coverage, {
            "from": [result], "type": "verify", "description": coverage.cell_description(plan, cell),
        })
    cfg.audit.coverage.topics = ["other-topic"]
    assert any("configuration changed" in b for b in coverage.scope_blockers(client.get_project(pid), work, cfg.audit.coverage, [fact.id]))
