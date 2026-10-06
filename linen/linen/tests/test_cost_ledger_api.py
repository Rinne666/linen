from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from linen.dispatcher.config import LocalConfig
from linen.dispatcher.runtime.backend import LocalBackend
from linen.server import db
from linen.server.app import app
from linen.server.routers.executions import configure_workspace_root, workspace_root


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "ledger.db")
    configure_workspace_root(tmp_path / "workspace")
    with TestClient(app) as test_client:
        yield test_client
    configure_workspace_root(None)


def test_cost_ledger_excludes_setup_failures_and_keeps_unknown_usage_null(
    client: TestClient, tmp_path: Path,
) -> None:
    created = client.post("/projects", json={
        "title": "ledger fixture", "origin": "source", "goal": "goal", "hints": [],
    })
    assert created.status_code == 201
    project_id = created.json()["project"]["id"]
    hint = client.post(f"/projects/{project_id}/hints", json={
        "content": "Inspect the authorization boundary", "creator": "human",
    })
    assert hint.status_code == 201
    with db.get_conn() as conn:
        hint_event = conn.execute(
            "SELECT event_type, actor, entity_id FROM audit_events "
            "WHERE project_id = ? AND entity_kind = 'hint' ORDER BY sequence DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    assert hint_event is not None
    assert (hint_event["event_type"], hint_event["actor"], hint_event["entity_id"]) == (
        "human_hint_created", "human", hint.json()["id"],
    )
    archive = tmp_path / "workspace" / project_id / ".linen-executions"
    archive.mkdir(parents=True)
    (archive / "new-setup.json").write_text(json.dumps({
        "worker": "claude", "worker_type": "claudecode", "phase": "reason_execute",
        "duration_ms": 15, "process_started": False, "attempt_status": "setup_failed",
        "failure_code": "process_setup_failed", "usage": None,
    }))
    # Older archive records lack process and usage fields; keep their previous
    # invocation count while explicitly exposing that usage is unobserved.
    (archive / "old-run.json").write_text(json.dumps({
        "worker": "pi", "worker_type": "pi", "phase": "explore_execute",
        "duration_ms": 40, "returncode": 0,
    }))
    (archive / "partial-usage.json").write_text(json.dumps({
        "worker": "claude", "worker_type": "claudecode", "phase": "review_execute",
        "duration_ms": 25, "returncode": 0, "process_started": True,
        "attempt_status": "completed", "usage_source": "cli_structured",
        "usage": {
            "input_tokens": 5, "output_tokens": 7, "cached_input_tokens": None,
            "cache_creation_input_tokens": None, "total_tokens": None,
        },
    }))
    run_id = "unarchived-setup-failure"
    registered = client.post(f"/projects/{project_id}/runs", json={
        "run_id": run_id,
        "project_id": project_id,
        "task_type": "reason",
        "attempt": 1,
        "idempotency_key": "unarchived-setup-failure-key",
        "graph_revision": 1,
        "source_generation": 1,
        "plan_revision": 1,
        "timeout_seconds": 60,
        "status": "running",
        "stage": "reason_execute",
        "started_at": "2026-10-05T00:00:00Z",
        "worker_name": "codex",
        "worker_type": "codex",
    })
    assert registered.status_code == 201, registered.text
    failed_run = {**registered.json(), "status": "failed", "finished_at": "2026-10-05T00:00:00Z"}
    assert client.put(f"/projects/{project_id}/runs/{run_id}", json=failed_run).status_code == 200
    setup_event = {
        "event_id": f"execution-attempt-{run_id}-reason_execute",
        "project_id": project_id,
        "run_id": run_id,
        "idempotency_key": f"execution-attempt:{run_id}:reason_execute:finished",
        "event_type": "execution_attempt_finished",
        "actor": "dispatcher.execution",
        "entity_kind": "run",
        "entity_id": run_id,
        "graph_revision": 1,
        "source_generation": 1,
        "plan_revision": 1,
        "payload": {
            "phase": "reason_execute", "attempt_status": "setup_failed",
            "process_started": False, "failure_code": "process_setup_failed",
        },
        "created_at": registered.json()["started_at"],
    }
    assert client.post(f"/projects/{project_id}/events", json=setup_event).status_code == 201

    run_id = "unarchived-still-running"
    running = client.post(f"/projects/{project_id}/runs", json={
        "run_id": run_id, "project_id": project_id, "task_type": "reason",
        "attempt": 1, "idempotency_key": "unarchived-running-key", "graph_revision": 1,
        "source_generation": 1, "plan_revision": 1, "timeout_seconds": 60,
        "status": "running", "stage": "reason_execute", "worker_name": "codex",
        "worker_type": "codex",
    })
    assert running.status_code == 201, running.text

    response = client.get(f"/projects/{project_id}/cost")
    assert response.status_code == 200, response.text
    ledger = response.json()
    assert ledger["total"]["calls"] == 2
    assert ledger["total"]["setup_failures"] == 2
    assert ledger["total"]["unarchived_attempts"] == 2
    assert ledger["total"]["usage_recorded_calls"] == 1
    assert ledger["total"]["usage_unknown_calls"] == 2
    assert ledger["total"]["input_tokens"] == 5
    assert ledger["total"]["output_tokens"] == 7
    assert ledger["by_category"]["reason"]["attempt_status_counts"] == {
        "setup_failed": 2, "unarchived_running_or_interrupted": 1,
    }
    assert ledger["by_category"]["reason"]["failure_code_counts"] == {
        "process_setup_failed": 2, "archive_missing": 1,
    }
    assert ledger["total"]["usage_coverage_calls"] == {
        "input_tokens": 1, "output_tokens": 1,
    }


def test_cost_ledger_defaults_to_dispatcher_workspace_root(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LINEN_WORKSPACE_ROOT", raising=False)
    configure_workspace_root(None)

    created = client.post("/projects", json={
        "title": "default workspace fixture", "origin": "source", "goal": "goal", "hints": [],
    })
    assert created.status_code == 201, created.text
    project_id = created.json()["project"]["id"]
    assert workspace_root() == tmp_path.resolve()
    assert Path(LocalBackend(LocalConfig()).container_name(project_id)) == tmp_path / project_id

    archive = tmp_path / project_id / ".linen-executions"
    archive.mkdir(parents=True)
    (archive / "default-root-call.json").write_text(json.dumps({
        "worker": "codex", "worker_type": "codex", "phase": "reason_execute",
        "duration_ms": 125, "process_started": True, "attempt_status": "completed",
    }))

    response = client.get(f"/projects/{project_id}/cost")
    assert response.status_code == 200, response.text
    assert response.json()["total"]["calls"] == 1
    assert response.json()["total"]["duration_ms"] == 125


def test_cost_ledger_counts_unarchived_run_when_process_started(
    client: TestClient,
) -> None:
    created = client.post("/projects", json={
        "title": "unarchived call fixture", "origin": "source", "goal": "goal", "hints": [],
    })
    assert created.status_code == 201, created.text
    project_id = created.json()["project"]["id"]
    run_id = "unarchived-started-call"
    registered = client.post(f"/projects/{project_id}/runs", json={
        "run_id": run_id, "project_id": project_id, "task_type": "reason",
        "attempt": 1, "idempotency_key": "unarchived-started-call-key",
        "graph_revision": 1, "source_generation": 1, "plan_revision": 1,
        "timeout_seconds": 60, "status": "running", "stage": "reason_execute",
        "worker_name": "codex", "worker_type": "codex",
        "started_at": "2026-10-05T00:00:00Z",
    })
    assert registered.status_code == 201, registered.text
    failed_run = {**registered.json(), "status": "failed", "finished_at": "2026-10-05T00:00:00Z"}
    assert client.put(f"/projects/{project_id}/runs/{run_id}", json=failed_run).status_code == 200

    attempt_event = {
        "event_id": f"execution-attempt-{run_id}-reason_execute",
        "project_id": project_id,
        "run_id": run_id,
        "idempotency_key": f"execution-attempt:{run_id}:reason_execute:finished",
        "event_type": "execution_attempt_finished",
        "actor": "dispatcher.execution",
        "entity_kind": "run",
        "entity_id": run_id,
        "graph_revision": 1,
        "source_generation": 1,
        "plan_revision": 1,
        "payload": {
            "phase": "reason_execute", "attempt_status": "failed",
            "process_started": True, "failure_code": "worker_exit_nonzero",
        },
        "created_at": registered.json()["started_at"],
    }
    event_response = client.post(f"/projects/{project_id}/events", json=attempt_event)
    assert event_response.status_code == 201, event_response.text

    response = client.get(f"/projects/{project_id}/cost")
    assert response.status_code == 200, response.text
    ledger = response.json()
    assert ledger["total"]["calls"] == 1
    assert ledger["total"]["unarchived_attempts"] == 1
    assert ledger["total"]["duration_ms"] == 0
    assert ledger["total"]["usage_unknown_calls"] == 1
    assert ledger["by_category"]["reason"]["calls"] == 1
    assert ledger["total"]["failure_code_counts"] == {"worker_exit_nonzero": 1}
