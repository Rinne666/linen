from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient

from linen.dispatcher.analysis.policy import completion_blockers, SCAN_INTENT_DESCRIPTION
from linen.dispatcher.analysis.semgrep import digest, normalize_sarif, run_scan
from linen.dispatcher.config import DispatchConfig, SemgrepConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks import bootstrap, explore, reason, review
from linen.dispatcher.tasks.common import run_worker_process
from linen.dispatcher.workers.base import DriverResult
from linen.server import db
from linen.server.routers import executions
from linen.server.models import ProjectDetail


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    from linen.server.app import app
    with TestClient(app) as http:
        client = LinenClient("http://testserver")
        monkeypatch.setattr(client, "_session", lambda: http)
        yield http, client


def config(tmp_path, *, audit=True, scan=False, mode="hypothesis"):
    return DispatchConfig.model_validate({
        "server": "http://testserver",
        "runtime": {"interval": 60, "max_workers": 2, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "vuln_audit"},
        "tasks": {"bootstrap": {"timeout": 5, "conclude_timeout": 5},
                  "reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path / "work")},
        "workers": [{"name": "tester", "type": "mock", "task_types": ["reason", "explore", "review"],
                     "max_running": 1, "priority": 0}],
        "audit": {"enabled": audit, "mode": mode,
                  "semgrep": {"enabled": scan, "rules": str(tmp_path / "rules.yaml")}},
    })


def project(api, repo=None, *, audit_mode="none"):
    http, client = api
    body = {"title": "audit", "origin": "source", "goal": "verify hypothesis",
            "bootstrap_enabled": False, "audit_mode": audit_mode}
    if repo:
        body["repo_root"] = str(repo)
    response = http.post("/projects", json=body)
    assert response.status_code == 201, response.text
    return client.get_project(response.json()["project"]["id"])


def add_fact(client, pid, *, parent="origin", fact_type="vulnerability"):
    response = client.create_intent(pid, [parent], "verify", "reasoner", intent_type="characterize")
    iid = response.data["id"]
    assert client.heartbeat(pid, iid, "tester").ok
    response = client.conclude(pid, iid, "tester", "candidate", fact_type=fact_type, evidence="file: app.py:1")
    assert response.ok, response.text
    return response.data["fact"]["id"]


def sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [{"id": "eval", "properties": {"cwe": ["CWE-95"]}}]}},
        "results": [{"ruleId": "eval", "message": {"text": "check input"}, "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}
        }], "codeFlows": [{"threadFlows": [{"locations": []}]}]}],
    }]}


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("eval(input())\n")
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr("linen.dispatcher.analysis.semgrep.shutil.which", lambda _: "/fake/semgrep")
    monkeypatch.setattr("linen.dispatcher.analysis.semgrep.subprocess.run", lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout="1.test", stderr=""))
    calls = []

    def execute(source, argv, *, errors=None, timed_out=False, returncode=0):
        calls.append(argv)
        assert source != repo
        assert (source / "app.py").read_text() == (repo / "app.py").read_text()
        Path(argv[argv.index("--json-output") + 1]).write_text(json.dumps({
            "paths": {"scanned": ["app.py"], "skipped": []}, "errors": errors or [],
        }))
        return ProcessResult(returncode, json.dumps(sarif()), "scanner log", timed_out=timed_out)

    return repo, SemgrepConfig(enabled=True, rules=rules), execute, calls


def manifest(fact):
    path = Path(fact["evidence"].splitlines()[0].removeprefix("artifact: "))
    return path, json.loads(path.read_text())


def test_scope_scan_uses_exact_canonical_files_not_scanner_exclusions(scanner, tmp_path):
    repo, scanner_config, execute, _ = scanner
    content = (repo / "app.py").read_bytes()
    canonical_files = {"app.py": digest(content)}
    canonical = {
        "id": digest(json.dumps({"files": canonical_files, "skipped": []}, sort_keys=True).encode()),
        "files": canonical_files,
        "skipped": [],
    }
    restrictive = scanner_config.model_copy(update={
        "max_target_bytes": 1,
        "exclude": ["app.py"],
        "cache": False,
    })

    fact = run_scan(
        repo,
        tmp_path / "analysis",
        restrictive,
        execute,
        canonical_snapshot=canonical,
    )
    _, record = manifest(fact)

    assert record["status"] == "completed"
    assert record["snapshot"] == canonical


def test_review_diagnostics_round_trip_and_export(api):
    http, client = api
    pid = project(api).project.id
    fid = add_fact(client, pid)
    diagnostics = {"cold_verification": {"subclaims": ["input", "path"], "isolation_observed": "yes"}}
    response = client.create_review(pid, fid, "VALID", "verified", confidence="firm", diagnostics=diagnostics)
    assert response.ok, response.text
    assert response.data["cold_verification"] == diagnostics["cold_verification"]
    current = client.get_project(pid)
    assert current.reviews[0].cold_verification == diagnostics["cold_verification"]
    exported = yaml.safe_load(client.export_project(pid))
    assert exported["reviews"][0]["cold_verification"] == diagnostics["cold_verification"]
    assert next(f for f in exported["facts"] if f["id"] == fid)["status"] == "triaged"
    bad = http.post(f"/projects/{pid}/facts/{fid}/reviews", json={
        "verdict": "VALID", "summary": "bad", "cold_verification": ["not an object"],
    })
    assert bad.status_code == 422


def test_legacy_review_migration_preserves_data(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    old_schema = db.SCHEMA.replace("    diagnostics TEXT NOT NULL DEFAULT '{}',\n", "")
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute("INSERT INTO projects (id,title,created_at) VALUES ('p','old','now')")
        conn.execute("INSERT INTO reviews (id,project_id,fact_id,verdict,summary,created_at) "
                     "VALUES ('r','p','f','VALID','original','now')")
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        assert dict(conn.execute("SELECT summary,diagnostics FROM reviews").fetchone()) == {
            "summary": "original", "diagnostics": "{}",
        }
        db._ensure_review_columns(conn)  # migration is idempotent


def test_gate_checks_reviews_ancestors_and_open_intents(api):
    _, client = api
    pid = project(api).project.id
    source = add_fact(client, pid, fact_type="source")
    terminal = add_fact(client, pid, parent=source)
    assert completion_blockers(client.get_project(pid), [terminal])
    client.create_review(pid, terminal, "VALID", "yes", confidence="firm")
    assert any(source in blocker for blocker in completion_blockers(client.get_project(pid), [terminal]))
    client.create_review(pid, source, "VALID", "yes", confidence="certain")
    assert completion_blockers(client.get_project(pid), [terminal]) == []
    client.create_intent(pid, [source], "more work", "reasoner", intent_type="trace")
    assert any("Open intents" in b for b in completion_blockers(client.get_project(pid), [terminal]))
    client.create_review(pid, source, "NEEDS_REVIEW", "missing config", confidence="tentative")
    assert any(source in b for b in completion_blockers(client.get_project(pid), [terminal]))


def test_server_rejects_audit_completion_until_terminal_fact_is_reviewed(api):
    """The API boundary must reject the draft-terminal bypass, not only reason.py."""
    _, client = api
    pid = project(api, audit_mode="hypothesis").project.id
    terminal = add_fact(client, pid)

    blocked = client.complete(pid, [terminal], "unreviewed terminal", "reasoner")
    assert blocked.status_code == 409
    assert "unresolved status draft" in blocked.text

    assert client.create_review(pid, terminal, "VALID", "independent trace", confidence="certain").ok
    completed = client.complete(pid, [terminal], "reviewed terminal", "reasoner")
    assert completed.ok, completed.text


def test_server_rejects_scope_summary_that_omits_reviewed_fact(api):
    _, client = api
    pid = project(api, audit_mode="scope").project.id
    summary = add_fact(client, pid, fact_type="audit_summary")
    assert client.create_review(pid, summary, "VALID", "summary checked", confidence="firm").ok
    orphan = add_fact(client, pid, fact_type="observation")
    assert client.create_review(pid, orphan, "VALID", "trace checked", confidence="firm").ok

    blocked = client.complete(pid, [summary], "incomplete summary", "reasoner")

    assert blocked.status_code == 409
    assert f"Scope audit fact {orphan} is not included" in blocked.text


def test_scope_is_the_default_audit_mode_and_recon_is_explicit(tmp_path):
    raw = config(tmp_path).model_dump()
    raw["audit"].pop("mode")
    assert DispatchConfig.model_validate(raw).audit.mode == "scope"

    raw["workers"][0]["task_types"] = ["bootstrap", "reason", "explore", "review"]
    with pytest.raises(ValueError, match="recon.enabled"):
        DispatchConfig.model_validate(raw)
    raw["audit"]["recon"] = {"enabled": True}
    assert DispatchConfig.model_validate(raw).audit.recon.enabled


def test_audit_recon_records_non_authoritative_fact_without_completing(api, tmp_path, monkeypatch):
    """Optional bootstrap is a recon record, never an audit completion path."""
    _, client = api
    cfg_raw = config(tmp_path, mode="scope").model_dump()
    cfg_raw["audit"]["recon"] = {"enabled": True}
    cfg_raw["workers"][0]["task_types"] = ["bootstrap", "reason", "explore", "review"]
    cfg = DispatchConfig.model_validate(cfg_raw)
    current = project(api, audit_mode="scope")
    pid = current.project.id
    intent_id = client.create_intent(pid, ["origin"], "bootstrap", "dispatcher.bootstrap").data["id"]
    client.heartbeat(pid, intent_id, cfg.workers[0].name)
    current = client.get_project(pid)
    intent = next(intent for intent in current.intents if intent.id == intent_id)
    driver = FakeDriver()
    monkeypatch.setattr(bootstrap, "get_driver", lambda _: driver)
    monkeypatch.setattr(bootstrap, "run_worker_process", lambda *a, **kw: ProcessResult(0, json.dumps({
        "accepted": True,
        "data": {"fact": {"description": "candidate map", "type": "source", "evidence": "repo/a.py:1"},
                 "complete": {"description": "must be ignored"}},
    }), ""))
    assert bootstrap.run_bootstrap_task(
        cfg, client, LocalBackend(cfg.local, client), current, intent, cfg.workers[0], TaskCancellation()
    ) == "success"
    final = client.get_project(pid)
    recon = next(fact for fact in final.facts if fact.id not in {"origin", "goal"})
    assert final.project.status == "active"
    assert recon.type == "recon"
    assert recon.status == "draft"
    assert "candidate map" in recon.description


def test_audit_dispatcher_keeps_non_audit_bootstrap_behavior(api, tmp_path, monkeypatch):
    _, client = api
    cfg_raw = config(tmp_path, mode="scope").model_dump()
    cfg_raw["audit"]["recon"] = {"enabled": True}
    cfg_raw["workers"][0]["task_types"] = ["bootstrap", "reason", "explore", "review"]
    cfg = DispatchConfig.model_validate(cfg_raw)
    current = project(api, audit_mode="none")
    pid = current.project.id
    intent_id = client.create_intent(pid, ["origin"], "bootstrap", "dispatcher.bootstrap").data["id"]
    client.heartbeat(pid, intent_id, cfg.workers[0].name)
    current = client.get_project(pid)
    intent = next(item for item in current.intents if item.id == intent_id)
    monkeypatch.setattr(bootstrap, "get_driver", lambda _: FakeDriver())
    monkeypatch.setattr(bootstrap, "run_worker_process", lambda *a, **kw: ProcessResult(0, json.dumps({
        "accepted": True,
        "data": {
            "fact": {"description": "ordinary bootstrap result"},
            "complete": {"description": "ordinary project complete"},
        },
    }), ""))

    assert bootstrap.run_bootstrap_task(
        cfg, client, LocalBackend(cfg.local, client), current, intent,
        cfg.workers[0], TaskCancellation(),
    ) == "success"
    final = client.get_project(pid)
    produced = next(fact for fact in final.facts if fact.id not in {"origin", "goal"})
    assert final.project.status == "completed"
    assert produced.type != "recon"


def test_worker_execution_records_preserve_replay_metadata_and_output(tmp_path):
    cfg = config(tmp_path)
    backend = LocalBackend(cfg.local)
    handle = backend.ensure_running("proj_repro")
    result = run_worker_process(
        backend,
        handle,
        cfg.workers[0],
        ["/bin/sh", "-c", "printf stdout; printf stderr >&2"],
        phase="evidence_test",
        timeout_seconds=5,
    )
    assert result.returncode == 0
    records = list((Path(handle) / ".linen-executions").glob("*.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text())
    assert record["phase"] == "evidence_test"
    assert record["returncode"] == 0
    assert record["argv_sha256"]
    assert Path(record["stdout"]).read_text() == "stdout"
    assert Path(record["stderr"]).read_text() == "stderr"


def test_pi_execution_record_preserves_prompt_without_persisting_argv(tmp_path):
    cfg = config(tmp_path)
    worker = cfg.workers[0].model_copy(update={"name": "local-pi", "type": "pi"})
    backend = LocalBackend(cfg.local)
    handle = backend.ensure_running("proj_pi_prompt")
    prompt = "audit prompt with project context"
    result = run_worker_process(
        backend,
        handle,
        worker,
        ["/bin/sh", "-c", "printf pi-output", "--", "-p", prompt],
        phase="semantic_recipe",
        timeout_seconds=5,
        recipe_id="architecture_map",
        recipe_label="Architecture map",
        recipe_version=1,
    )
    assert result.returncode == 0
    record_path = next((Path(handle) / ".linen-executions").glob("*.json"))
    record = json.loads(record_path.read_text())
    assert record["schema_version"] == 3
    assert record["worker_type"] == "pi"
    assert record["command"] == "pi -p"
    assert record["recipe_id"] == "architecture_map"
    assert record["recipe_label"] == "Architecture map"
    assert record["recipe_version"] == 1
    assert Path(record["prompt"]).read_text() == prompt
    assert prompt not in record_path.read_text()


def test_pi_execution_api_lists_legacy_records_and_expands_response(api, tmp_path, monkeypatch):
    board = project(api)
    http, _ = api
    workspace_root = tmp_path / "workspaces"
    archive = workspace_root / board.project.id / ".linen-executions"
    archive.mkdir(parents=True)
    record_id = "20260907T130135.190661Z-explore_execute-2494e40e"
    record_path = archive / f"{record_id}.json"
    record_path.write_text(json.dumps({
        "schema_version": 1,
        "phase": "explore_execute",
        "worker": "local-pi",
        "started_at": "2026-09-07T13:01:35.190661Z",
        "duration_ms": 4200,
        "timeout_seconds": 600,
        "returncode": 0,
        "timed_out": False,
        "cancelled": False,
    }))
    stdout = "\n".join([
        json.dumps({"type": "session", "id": "session-001"}),
        json.dumps({"type": "message_end", "message": {
            "role": "user", "content": [{"type": "text", "text": "trace this source"}],
        }}),
        json.dumps({"type": "turn_end", "message": {
            "role": "assistant", "content": [{"type": "text", "text": "confirmed response"}],
        }}),
    ])
    record_path.with_suffix(".stdout").write_text(stdout)
    record_path.with_suffix(".stderr").write_text("diagnostic")
    monkeypatch.setattr(executions, "_workspace_root_override", workspace_root.resolve())

    listing = http.get(f"/projects/{board.project.id}/executions")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["command"] == "pi -p"
    assert listing.json()["items"][0]["session_id"] == "session-001"

    detail = http.get(f"/projects/{board.project.id}/executions/{record_id}")
    assert detail.status_code == 200
    assert detail.json()["prompt"] == "trace this source"
    assert detail.json()["response"] == "confirmed response"
    assert detail.json()["stderr"] == "diagnostic"

    raw = http.get(f"/projects/{board.project.id}/executions/{record_id}/streams/stdout")
    assert raw.status_code == 200
    assert raw.text == stdout


def test_pi_execution_api_exposes_recipe_metadata(api, tmp_path, monkeypatch):
    board = project(api)
    http, _ = api
    workspace_root = tmp_path / "workspaces"
    archive = workspace_root / board.project.id / ".linen-executions"
    archive.mkdir(parents=True)
    record_id = "20260909T010203.000000Z-semantic_recipe-12345678"
    record_path = archive / f"{record_id}.json"
    record_path.write_text(json.dumps({
        "schema_version": 3,
        "command": "pi -p",
        "phase": "semantic_recipe",
        "recipe_id": "authz_matrix",
        "recipe_label": "Authorization matrix",
        "recipe_version": 1,
        "worker": "local-pi",
        "started_at": "2026-09-09T01:02:03Z",
        "duration_ms": 1200,
        "returncode": 0,
        "prompt": str(record_path.with_suffix(".prompt")),
        "stdout": str(record_path.with_suffix(".stdout")),
        "stderr": str(record_path.with_suffix(".stderr")),
    }))
    record_path.with_suffix(".prompt").write_text("selected recipe prompt")
    record_path.with_suffix(".stdout").write_text("{}")
    record_path.with_suffix(".stderr").write_text("")
    monkeypatch.setattr(executions, "_workspace_root_override", workspace_root.resolve())

    listing = http.get(
        f"/projects/{board.project.id}/executions?phase=semantic_recipe"
    )
    assert listing.status_code == 200
    assert listing.json()["items"][0]["recipe_id"] == "authz_matrix"
    assert listing.json()["items"][0]["recipe_label"] == "Authorization matrix"
    assert listing.json()["items"][0]["recipe_version"] == 1

    detail = http.get(f"/projects/{board.project.id}/executions/{record_id}")
    assert detail.status_code == 200
    assert detail.json()["recipe_id"] == "authz_matrix"
    assert detail.json()["prompt"] == "selected recipe prompt"


class FakeDriver:
    def __init__(self):
        self.prompts = []

    def prepare_session(self):
        return None

    def build_execute(self, worker, prompt, session):
        self.prompts.append(prompt)
        return DriverResult(["fake-worker"], session="fresh")

    def extract_response_text(self, stdout, stderr):
        return stdout

    def extract_session(self, session, stdout, stderr):
        return session


@pytest.mark.parametrize("enabled", [True, False])
def test_reason_gate_blocks_only_opted_in_dispatcher(api, tmp_path, monkeypatch, enabled):
    _, client = api
    cfg = config(tmp_path, audit=enabled)
    original = project(api)
    pid = original.project.id
    fid = add_fact(client, pid)
    driver = FakeDriver()
    monkeypatch.setattr(reason, "get_driver", lambda _: driver)
    monkeypatch.setattr(reason, "run_worker_process", lambda *a, **k: ProcessResult(0, json.dumps({
        "accepted": True, "data": {"complete": {"from": [fid], "description": "done"}},
    }), ""))
    backend = LocalBackend(cfg.local, client)
    assert reason.run_reason_task(cfg, client, backend, original, client.export_project(pid),
                                  cfg.workers[0], TaskCancellation()) == "success"
    current = client.get_project(pid)
    assert current.project.status == ("active" if enabled else "completed")
    if enabled:
        assert any("Audit completion blocked" in hint.content for hint in current.hints)


def test_scan_cache_invalidates_source_rules_and_corrupt_artifacts(scanner, tmp_path):
    repo, cfg, execute, calls = scanner
    first = run_scan(repo, tmp_path / "artifacts", cfg, execute)
    path, data = manifest(first)
    assert data["status"] == "completed"
    assert data["candidate_count"] == 1
    assert first["type"] == "scan_batch"
    second = run_scan(repo, tmp_path / "artifacts", cfg, execute)
    assert "Cache hit: True" in second["description"]
    assert len(calls) == 1
    (path.parent / "candidates.json").write_text("[]")
    run_scan(repo, tmp_path / "artifacts", cfg, execute)
    assert len(calls) == 2
    cfg.rules.write_text("rules: [changed]\n")
    run_scan(repo, tmp_path / "artifacts", cfg, execute)
    assert len(calls) == 3
    (repo / "app.py").write_text("eval('changed')\n")
    changed = run_scan(repo, tmp_path / "artifacts", cfg, execute)
    assert len(calls) == 4
    assert manifest(changed)[1]["snapshot"]["id"] != data["snapshot"]["id"]
    assert (path.parent / "source/app.py").read_text() == "eval(input())\n"


@pytest.mark.parametrize("failure", ["parse", "timeout", "exit", "invalid_json"])
def test_incomplete_scans_are_visible_and_not_cached(scanner, tmp_path, failure):
    repo, cfg, execute, calls = scanner

    def failing(source, argv):
        result = execute(source, argv, errors=[{"type": "ParseError"}] if failure == "parse" else [],
                         timed_out=failure == "timeout", returncode=2 if failure == "exit" else 0)
        if failure == "invalid_json":
            result.stdout = "not SARIF"
        return result

    for _ in range(2):
        fact = run_scan(repo, tmp_path / "artifacts", cfg, failing)
        _, data = manifest(fact)
        assert data["status"] in {"partial", "failed"}
        assert data["errors"]
    assert len(calls) == 2


def test_sarif_keeps_flows_and_deduplicates_identical_alerts():
    doc = sarif()
    doc["runs"][0]["results"] *= 2
    candidates = normalize_sarif(doc)
    assert len(candidates) == 1
    assert candidates[0]["occurrences"] == 2
    assert candidates[0]["code_flows"]
    with pytest.raises(ValueError):
        normalize_sarif({"version": "2.1.0", "runs": []})


def test_snapshot_records_exclusions_and_missing_scanner(scanner, tmp_path, monkeypatch):
    repo, cfg, execute, _ = scanner
    (repo / "linked.py").symlink_to(repo / "app.py")
    (repo / ".venv").mkdir()
    (repo / ".venv/ignored.py").write_text("secret")
    monkeypatch.setattr("linen.dispatcher.analysis.semgrep.shutil.which", lambda _: None)
    _, data = manifest(run_scan(repo, tmp_path / "artifacts", cfg, execute))
    assert data["status"] == "failed"
    assert {s["reason"] for s in data["snapshot"]["skipped"]} == {"symlink", "excluded"}


def test_scan_explore_review_and_reason_complete_through_board(api, scanner, tmp_path, monkeypatch):
    _, client = api
    repo, _, execute, _ = scanner
    cfg = config(tmp_path, scan=True)
    current = project(api, repo)
    pid = current.project.id
    backend = LocalBackend(cfg.local, client)
    worker = cfg.workers[0]
    response = client.create_intent(pid, ["origin"], SCAN_INTENT_DESCRIPTION, "reasoner", intent_type="search")
    iid = response.data["id"]
    assert client.heartbeat(pid, iid, worker.name).ok
    current = client.get_project(pid)
    intent = next(i for i in current.intents if i.id == iid)
    monkeypatch.setattr(explore, "run_worker_process", lambda backend, source, worker, argv, **kw:
                        execute(Path(source), argv))
    assert explore.run_explore_task(cfg, client, backend, current, client.export_project(pid),
                                    intent, worker, TaskCancellation()) == "success"
    current = client.get_project(pid)
    batch = next(f for f in current.facts if f.type == "scan_batch")
    assert batch.status == "draft"
    candidate = add_fact(client, pid, parent=batch.id)

    driver = FakeDriver()
    monkeypatch.setattr(review, "get_driver", lambda _: driver)
    # Real review task saves its model output using the existing Review API.
    monkeypatch.setattr(review, "run_worker_process", lambda *a, **kw: ProcessResult(0, json.dumps({
        "accepted": True, "data": {"verdict": "VALID", "summary": "verified", "confidence": "firm",
                                    "attestation_check": {
                                        "artifact_integrity": "valid: manifest digest matches",
                                        "source_consistency": "consistent: app.py:1",
                                        "scope_complete": "yes: declared batch completed",
                                        "contradictions": [],
                                    },
                                    "cold_verification": {
                                        "sub_claims": {"source": "input", "path": "app.py:1", "effect": "sink"},
                                        "sub_claim_failure": "none",
                                        "static_status": "confirmed",
                                        "poc_status": "not required",
                                        "prosecution": "source reaches sink",
                                        "defense": "no effective guard",
                                        "severity_challenged": "impact remains material",
                                        "isolation_observed": "read-only source",
                                    }},
    }), ""))
    for fid in (batch.id, candidate):
        response = client.create_intent(pid, [fid], "SECRET PRIOR REASONING", "reasoner",
                                        intent_type="review:cold-verifier")
        review_id = response.data["id"]
        client.heartbeat(pid, review_id, worker.name)
        current = client.get_project(pid)
        review_intent = next(i for i in current.intents if i.id == review_id)
        assert review.run_review_task(cfg, client, backend, current, client.export_project(pid),
                                      review_intent, worker, TaskCancellation()) == "success"
    assert all("SECRET PRIOR REASONING" not in prompt for prompt in driver.prompts)
    assert "audit-process attestation" in driver.prompts[0]
    assert "Withheld" in driver.prompts[1]
    current = client.get_project(pid)
    assert completion_blockers(current, [candidate]) == []
    assert len(current.reviews) == 2
    assert all(r.cold_verification for r in current.reviews)
    monkeypatch.setattr(reason, "get_driver", lambda _: driver)
    monkeypatch.setattr(reason, "run_worker_process", lambda *a, **kw: ProcessResult(0, json.dumps({
        "accepted": True, "data": {"complete": {"from": [candidate], "description": "hypothesis verified"}},
    }), ""))
    assert reason.run_reason_task(cfg, client, backend, current, client.export_project(pid),
                                  worker, TaskCancellation()) == "success"
    assert client.get_project(pid).project.status == "completed"


def test_audit_configuration_requires_review_and_local_rules(tmp_path):
    raw = config(tmp_path).model_dump()
    raw["workers"][0]["task_types"] = ["reason", "explore"]
    with pytest.raises(ValueError, match="review worker"):
        DispatchConfig.model_validate(raw)
    raw["workers"][0]["task_types"] = ["bootstrap", "review"]
    with pytest.raises(ValueError, match="recon.enabled"):
        DispatchConfig.model_validate(raw)
    with pytest.raises(ValueError, match="local rule file"):
        SemgrepConfig(enabled=True)


def test_cancelled_scan_does_not_conclude_intent(api, scanner, tmp_path, monkeypatch):
    _, client = api
    repo, _, execute, _ = scanner
    cfg = config(tmp_path, scan=True)
    current = project(api, repo)
    pid = current.project.id
    worker = cfg.workers[0]
    iid = client.create_intent(pid, ["origin"], SCAN_INTENT_DESCRIPTION, "reasoner", intent_type="search").data["id"]
    client.heartbeat(pid, iid, worker.name)
    current = client.get_project(pid)
    cancellation = TaskCancellation()

    def cancelled_run(backend, source, worker, argv, **kw):
        result = execute(Path(source), argv)
        cancellation.cancel("project stopped")
        return result

    monkeypatch.setattr(explore, "run_worker_process", cancelled_run)
    assert explore.run_explore_task(cfg, client, LocalBackend(cfg.local, client), current,
                                    client.export_project(pid), current.intents[0], worker, cancellation) == "cancelled"
    current = client.get_project(pid)
    assert not any(f.type == "scan_batch" for f in current.facts)
    assert current.intents[0].concluded_at is None
