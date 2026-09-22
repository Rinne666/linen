from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from linen.dispatcher.analysis.policy import completion_blockers
from linen.dispatcher.config import DispatchConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks import reason, review
from linen.dispatcher.tasks.common import run_worker_process
from linen.dispatcher.workers.base import DriverResult
from linen.server import db
from linen.server.routers import executions
from linen.server.models import ProjectDetail
from linen.server.audit_state import fact_semantic_type


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    from linen.server.app import app
    with TestClient(app) as http:
        client = LinenClient("http://testserver")
        monkeypatch.setattr(client, "_session", lambda: http)
        yield http, client


def config(tmp_path, *, audit=True, mode="hypothesis"):
    return DispatchConfig.model_validate({
        "server": "http://testserver",
        "runtime": {"interval": 60, "max_workers": 2, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "vuln_audit"},
        "tasks": {"reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path / "work")},
        "workers": [{"name": "tester", "type": "mock", "task_types": ["reason", "explore", "review"],
                     "max_running": 1, "priority": 0}],
        "audit": {"enabled": audit, "mode": mode},
    })


def project(api, repo=None, *, audit_mode="none"):
    http, client = api
    body = {"title": "audit", "origin": "source", "goal": "verify hypothesis",
            "audit_mode": audit_mode}
    if repo:
        body["repo_root"] = str(repo)
    response = http.post("/projects", json=body)
    assert response.status_code == 201, response.text
    return client.get_project(response.json()["project"]["id"])


def test_candidate_disposition_is_project_observation_not_finding() -> None:
    assert fact_semantic_type("fact-1", "candidate_disposition", "triaged") == "observation"


def add_fact(client, pid, *, parent="origin", fact_type="vulnerability"):
    description = f"verify {fact_type} from {parent}"
    response = client.create_intent(pid, [parent], description, "reasoner", intent_type="characterize")
    iid = response.data["id"]
    assert client.heartbeat(pid, iid, "tester").ok
    response = client.conclude(pid, iid, "tester", "candidate", fact_type=fact_type, evidence="file: app.py:1")
    assert response.ok, response.text
    return response.data["fact"]["id"]


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
    http, client = api
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


def test_hypothesis_completion_accepts_reviewed_negative_assurance(api):
    _, client = api
    pid = project(api, audit_mode="hypothesis").project.id
    source = add_fact(client, pid, fact_type="source")
    assurance = add_fact(
        client,
        pid,
        parent=source,
        fact_type="negative_assurance",
    )
    client.create_review(pid, source, "VALID", "verified", confidence="certain")
    client.create_review(pid, assurance, "INVALID", "initial concern", confidence="firm")
    client.create_review(pid, assurance, "VALID", "verified", confidence="firm")

    assert completion_blockers(client.get_project(pid), [assurance]) == []


def test_server_rejects_audit_completion_until_terminal_fact_is_confirmed(api):
    """A Review is not a substitute for Technical Confirmation."""
    _, client = api
    pid = project(api, audit_mode="hypothesis").project.id
    terminal = add_fact(client, pid)

    blocked = client.complete(pid, [terminal], "unreviewed terminal", "reasoner")
    assert blocked.status_code == 409
    assert "unresolved status draft" in blocked.text

    assert client.create_review(pid, terminal, "VALID", "independent trace", confidence="certain").ok
    still_blocked = client.complete(pid, [terminal], "reviewed terminal", "reasoner")
    assert still_blocked.status_code == 409
    assert "confirmed finding" in still_blocked.text


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

    raw["audit"]["recon"] = {"enabled": True}
    assert DispatchConfig.model_validate(raw).audit.recon.enabled
    raw["audit"]["mode"] = "hypothesis"
    with pytest.raises(ValueError, match="recon requires scope mode"):
        DispatchConfig.model_validate(raw)



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
    assert current.project.status == "completed"
    if enabled:
        assert not any("Audit completion blocked" in hint.content for hint in current.hints)


def test_audit_configuration_requires_review_and_local_rules(tmp_path):
    raw = config(tmp_path).model_dump()
    raw["workers"][0]["task_types"] = ["reason", "explore"]
    with pytest.raises(ValueError, match="review worker"):
        DispatchConfig.model_validate(raw)
    raw["audit"]["mode"] = "hypothesis"
    raw["audit"]["recon"] = {"enabled": True}
    with pytest.raises(ValueError, match="recon requires scope mode"):
        DispatchConfig.model_validate(raw)
