from __future__ import annotations

import sqlite3
import hashlib
import json

from fastapi.testclient import TestClient
import pytest

from linen.server import db
from linen.server.app import app
from linen.server.routers import executions


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as value:
        yield value


def _project(client: TestClient) -> str:
    response = client.post("/projects", json={"title": "vnext", "origin": "origin", "goal": "goal"})
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _run(project_id: str, *, status: str = "queued", key: str = "run-key", run_id: str = "run-1", started_at: str | None = None) -> dict:
    return {
        "run_id": run_id, "project_id": project_id, "task_type": "scan", "attempt": 1,
        "idempotency_key": key, "graph_revision": 1, "source_generation": 1,
        "plan_revision": 1, "timeout_seconds": 30, "status": status, "artifact_ids": [], "started_at": started_at,
    }


def test_legacy_audit_events_are_extended_and_backfilled(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE projects (id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
                               created_at TEXT NOT NULL);
        INSERT INTO projects VALUES ('p', 'p', 'active', '2026-01-01T00:00:00Z');
        CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL,
            event_type TEXT NOT NULL, actor TEXT NOT NULL, entity_kind TEXT, entity_id TEXT,
            source_generation INTEGER NOT NULL, plan_revision INTEGER NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
        INSERT INTO audit_events(project_id,event_type,actor,source_generation,plan_revision,payload,created_at)
            VALUES ('p','old','worker',1,1,'{}','2026-01-01T00:00:00Z');
        """)
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        row = conn.execute("SELECT event_id, schema_version, graph_revision FROM audit_events").fetchone()
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert dict(row) == {"event_id": "evt-1", "schema_version": 1, "graph_revision": 0}
    assert {"artifacts", "runs", "context_projections", "snapshots"} <= tables


def test_snapshot_is_stable_and_run_transition_is_idempotent(client: TestClient) -> None:
    project_id = _project(client)
    first = client.get(f"/projects/{project_id}/snapshot").json()
    second = client.get(f"/projects/{project_id}/snapshot").json()
    assert first["snapshot_id"] == second["snapshot_id"]
    assert first["nodes"] == second["nodes"]

    created = client.post(f"/projects/{project_id}/runs", json=_run(project_id))
    assert created.status_code == 201
    assert client.post(f"/projects/{project_id}/runs", json=_run(project_id)).json() == created.json()
    conflicting_identity = _run(project_id)
    conflicting_identity["task_type"] = "different-task"
    assert client.post(f"/projects/{project_id}/runs", json=conflicting_identity).status_code == 409
    running = _run(project_id, status="running")
    assert client.put(f"/projects/{project_id}/runs/run-1", json=running).status_code == 200
    assert client.put(f"/projects/{project_id}/runs/run-1", json=running).status_code == 200
    illegal = client.put(f"/projects/{project_id}/runs/run-1", json=_run(project_id, status="queued"))
    assert illegal.status_code == 409


def test_run_rejects_unknown_artifact_and_terminal_mutation(client: TestClient) -> None:
    project_id = _project(client)
    assert client.post(f"/projects/{project_id}/runs", json=_run(project_id)).status_code == 201
    assert client.put(
        f"/projects/{project_id}/runs/run-1",
        json={**_run(project_id, status="running"), "artifact_ids": ["missing"]},
    ).status_code == 422
    assert client.put(f"/projects/{project_id}/runs/run-1", json=_run(project_id, status="running")).status_code == 200
    completed = client.put(f"/projects/{project_id}/runs/run-1", json=_run(project_id, status="completed"))
    assert completed.status_code == 200
    replay = client.put(f"/projects/{project_id}/runs/run-1", json=_run(project_id, status="completed"))
    assert replay.status_code == 200
    mutated = {**_run(project_id, status="completed"), "worker_name": "changed"}
    assert client.put(f"/projects/{project_id}/runs/run-1", json=mutated).status_code == 409


def test_recover_only_expired_running_runs_and_is_idempotent(client: TestClient) -> None:
    project_id = _project(client)
    old = _run(project_id, status="running", started_at="2000-01-01T00:00:00Z")
    fresh = _run(project_id, status="running", key="fresh-key", run_id="run-2", started_at="2999-01-01T00:00:00Z")
    queued = _run(project_id, key="queued-key", run_id="run-3")
    assert client.post(f"/projects/{project_id}/runs", json=old).status_code == 201
    assert client.post(f"/projects/{project_id}/runs", json=fresh).status_code == 201
    assert client.post(f"/projects/{project_id}/runs", json=queued).status_code == 201
    before = client.get(f"/projects/{project_id}/snapshot").json()

    recovered = client.post(f"/projects/{project_id}/runs/recover")
    assert recovered.status_code == 200
    assert [run["run_id"] for run in recovered.json()] == ["run-1"]
    assert recovered.json()[0]["status"] == "interrupted"
    assert client.get(f"/projects/{project_id}/runs/run-2").json()["status"] == "running"
    assert client.get(f"/projects/{project_id}/runs/run-3").json()["status"] == "queued"
    assert client.post(f"/projects/{project_id}/runs/recover").json() == []
    events = client.get(f"/projects/{project_id}/events").json()
    assert sum(event["event_type"] == "run_orphan_recovered" for event in events) == 1
    after = client.get(f"/projects/{project_id}/snapshot").json()
    assert after["graph_revision"] == before["graph_revision"]


def test_event_artifact_and_context_roundtrip(client: TestClient) -> None:
    project_id = _project(client)
    snapshot = client.get(f"/projects/{project_id}/snapshot").json()
    event = {
        "event_id": "event-1", "project_id": project_id, "event_type": "artifact_registered", "actor": "dispatcher",
        "graph_revision": 1, "source_generation": 1, "plan_revision": 1, "idempotency_key": "event-key",
        "payload": {"ok": True}, "created_at": "2026-01-01T00:00:01Z",
    }
    assert client.post(f"/projects/{project_id}/events", json=event).json()["sequence"] == client.post(f"/projects/{project_id}/events", json=event).json()["sequence"]
    artifact = {"artifact_id": "a-1", "project_id": project_id, "kind": "report", "workspace_path": "out/report.md", "sha256": "a" * 64, "media_type": "text/markdown", "related_node_ids": []}
    first_artifact = client.post(f"/projects/{project_id}/artifacts", json=artifact)
    assert first_artifact.status_code == 201
    assert client.post(f"/projects/{project_id}/artifacts", json=artifact).json() == first_artifact.json()
    projection = {"projection_id": "ctx-1", "project_id": project_id, "snapshot_id": snapshot["snapshot_id"], "graph_revision": 1, "source_generation": 1, "plan_revision": 1, "node_ids": [], "edge_ids": [], "artifact_ids": ["a-1"], "context": {"x": 1}, "selection_policy": "explicit", "created_at": "2026-01-01T00:00:02Z"}
    response = client.post(f"/projects/{project_id}/context-projections", json=projection)
    assert response.status_code == 201
    assert client.get(f"/projects/{project_id}/context-projections/ctx-1").json()["projection_digest"] == response.json()["projection_digest"]

    # ``created_at`` is observational metadata, not part of a projection's
    # canonical identity, so a delayed replay remains idempotent.
    replay = client.post(
        f"/projects/{project_id}/context-projections",
        json={**projection, "created_at": "2026-01-02T00:00:02Z"},
    )
    assert replay.status_code == 201
    assert replay.json() == response.json()


def test_projection_and_run_references_are_validated(client: TestClient) -> None:
    project_id = _project(client)
    snapshot = client.get(f"/projects/{project_id}/snapshot").json()
    base = {
        "projection_id": "ctx-validated", "project_id": project_id,
        "snapshot_id": snapshot["snapshot_id"],
        "graph_revision": snapshot["graph_revision"],
        "source_generation": snapshot["source_generation"],
        "plan_revision": snapshot["plan_revision"],
        "node_ids": [], "edge_ids": [], "artifact_ids": [],
        "context": {}, "selection_policy": "explicit",
        "created_at": "2026-01-01T00:00:02Z",
    }
    assert client.post(
        f"/projects/{project_id}/context-projections",
        json={**base, "graph_revision": snapshot["graph_revision"] + 1},
    ).status_code == 422
    assert client.post(
        f"/projects/{project_id}/context-projections",
        json={**base, "node_ids": ["not-a-node"]},
    ).status_code == 422
    assert client.post(
        f"/projects/{project_id}/context-projections",
        json={**base, "edge_ids": ["not-an-edge"]},
    ).status_code == 422

    assert client.post(f"/projects/{project_id}/context-projections", json=base).status_code == 201
    assert client.post(
        f"/projects/{project_id}/runs",
        json={**_run(project_id), "context_projection_id": "missing"},
    ).status_code == 422
    assert client.post(
        f"/projects/{project_id}/runs",
        json={**_run(project_id), "context_projection_id": "ctx-validated"},
    ).status_code == 201

    other_project = _project(client)
    assert client.post(
        f"/projects/{other_project}/runs",
        json={**_run(other_project), "context_projection_id": "ctx-validated"},
    ).status_code == 422


def test_event_idempotency_key_rejects_different_content(client: TestClient) -> None:
    project_id = _project(client)
    event = {
        "event_id": "event-identity", "project_id": project_id,
        "event_type": "artifact_registered", "actor": "dispatcher",
        "graph_revision": 1, "source_generation": 1, "plan_revision": 1,
        "idempotency_key": "event-identity-key", "payload": {"ok": True},
        "created_at": "2026-01-01T00:00:01Z",
    }
    assert client.post(f"/projects/{project_id}/events", json=event).status_code == 201
    conflict = client.post(
        f"/projects/{project_id}/events",
        json={**event, "event_id": "event-other", "payload": {"ok": False}},
    )
    assert conflict.status_code == 409


def test_artifact_content_is_confined_and_integrity_checked(client: TestClient, tmp_path, monkeypatch) -> None:
    project_id = _project(client)
    workspace = tmp_path / "workspace"
    project_dir = workspace / project_id
    project_dir.mkdir(parents=True)
    monkeypatch.setattr(executions, "_workspace_root_override", workspace.resolve())
    content = b"verified artifact\n"
    path = project_dir / "report.txt"
    path.write_bytes(content)
    metadata = {
        "artifact_id": "content-1", "project_id": project_id, "kind": "report",
        "workspace_path": "report.txt", "sha256": hashlib.sha256(content).hexdigest(),
        "media_type": "text/plain", "byte_size": len(content),
    }
    assert client.post(f"/projects/{project_id}/artifacts", json=metadata).status_code == 201
    response = client.get(f"/projects/{project_id}/artifacts/content-1/content")
    assert response.status_code == 200
    assert response.content == content
    assert response.headers["content-type"].startswith("text/plain")
    assert "filename=\"report.txt\"" in response.headers["content-disposition"]

    path.write_bytes(b"tampered")
    assert client.get(f"/projects/{project_id}/artifacts/content-1/content").status_code == 409


def test_artifact_content_rejects_missing_escape_and_symlink(client: TestClient, tmp_path, monkeypatch) -> None:
    project_id = _project(client)
    workspace = tmp_path / "workspace"
    project_dir = workspace / project_id
    project_dir.mkdir(parents=True)
    monkeypatch.setattr(executions, "_workspace_root_override", workspace.resolve())
    digest = "b" * 64
    missing = {
        "artifact_id": "missing-content", "project_id": project_id, "kind": "text",
        "workspace_path": "missing.txt", "sha256": digest, "media_type": "text/plain",
    }
    assert client.post(f"/projects/{project_id}/artifacts", json=missing).status_code == 201
    assert client.get(f"/projects/{project_id}/artifacts/missing-content/content").status_code == 404
    escape = {**missing, "artifact_id": "escape", "workspace_path": "../outside.txt"}
    assert client.post(f"/projects/{project_id}/artifacts", json=escape).status_code == 422

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (project_dir / "link.txt").symlink_to(outside)
    symlink = {**missing, "artifact_id": "symlink", "workspace_path": "link.txt"}
    assert client.post(f"/projects/{project_id}/artifacts", json=symlink).status_code == 201
    assert client.get(f"/projects/{project_id}/artifacts/symlink/content").status_code == 409


def test_schema4_execution_metadata_is_exposed_for_run_join(client: TestClient, tmp_path, monkeypatch) -> None:
    project_id = _project(client)
    workspace = tmp_path / "workspace"
    archive = workspace / project_id / ".linen-executions"
    archive.mkdir(parents=True)
    record_id = "20260913T010203.000000Z-explore_execute-contract01"
    record_path = archive / f"{record_id}.json"
    record_path.write_text(json.dumps({
        "schema_version": 4, "command": "pi -p", "phase": "explore_execute", "worker": "worker-1",
        "started_at": "2026-09-13T01:02:03Z", "duration_ms": 100,
        "timeout_seconds": 30, "returncode": 0,
        "run_id": "run-join", "attempt": 2, "idempotency_key": "idem-join",
        "context_projection_id": "ctx-join", "manifest_digest": "sha256:" + "a" * 64,
        "recipe_digest": "sha256:" + "b" * 64,
    }), encoding="utf-8")
    record_path.with_suffix(".stdout").write_text("{}", encoding="utf-8")
    record_path.with_suffix(".stderr").write_text("", encoding="utf-8")
    monkeypatch.setattr(executions, "_workspace_root_override", workspace.resolve())
    response = client.get(f"/projects/{project_id}/executions")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["schema_version"] == 4
    assert item["run_id"] == "run-join"
    assert item["attempt"] == 2
    assert item["context_projection_id"] == "ctx-join"
    assert item["manifest_digest"].startswith("sha256:")
    assert item["recipe_digest"].startswith("sha256:")


def test_non_pi_schema4_execution_is_not_in_pi_archive(client: TestClient, tmp_path, monkeypatch) -> None:
    project_id = _project(client)
    workspace = tmp_path / "workspace"
    archive = workspace / project_id / ".linen-executions"
    archive.mkdir(parents=True)
    record_id = "run-codex-explore_execute"
    record_path = archive / f"{record_id}.json"
    record_path.write_text(json.dumps({
        "schema_version": 4, "command": "codex", "phase": "explore_execute",
        "worker": "worker-1", "worker_type": "codex", "started_at": "2026-09-13T01:02:03Z",
        "duration_ms": 100, "timeout_seconds": 30, "returncode": 0,
        "run_id": "run-codex", "attempt": 1, "idempotency_key": "idem-codex",
        "recipe_digest": "sha256:" + "b" * 64,
    }), encoding="utf-8")
    record_path.with_suffix(".stdout").write_text("codex output", encoding="utf-8")
    record_path.with_suffix(".stderr").write_text("", encoding="utf-8")
    monkeypatch.setattr(executions, "_workspace_root_override", workspace.resolve())
    response = client.get(f"/projects/{project_id}/executions")
    assert response.status_code == 200
    assert response.json()["items"] == []
