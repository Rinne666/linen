from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from linen.server import db
from linen.server.app import app
from linen.server.routers import projects


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as test_client:
        yield test_client


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "test",
            "origin": "starting point",
            "goal": "finish",
            "hints": [{"content": "initial clue", "creator": "human"}],
        },
    )
    assert response.status_code == 201
    assert response.json()["project"]["bootstrap_enabled"] is True
    assert response.json()["project"]["audit_mode"] == "none"
    return response.json()["project"]["id"]


def test_project_workflow_create_conclude_complete_and_reopen(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "investigate", "creator": "reasoner", "worker": None},
    )
    assert response.status_code == 201
    assert response.json()["id"] == "i001"

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "explorer"

    response = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={
            "worker": "explorer",
            "description": "new fact",
            "type": "vulnerability",
            "evidence": "file: app.py:7\ncode: dangerous(user_input)",
        },
    )
    assert response.status_code == 200
    assert response.json()["fact"]["id"] == "f001"
    assert response.json()["fact"]["description"] == "new fact"

    response = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["f001"], "description": "solved", "worker": "reasoner"},
    )
    assert response.status_code == 200
    assert response.json()["to"] == "goal"

    report = client.get(f"/projects/{project_id}/export?format=report")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/markdown")
    assert "# test — Final Result Report" in report.text
    assert "**Completed.** solved" in report.text
    assert "### Finding 1: `f001`" in report.text
    assert "file: app.py:7" in report.text
    assert "No open intents remain." in report.text

    response = client.post(
        f"/projects/{project_id}/reopen",
        json={"description": "human correction", "creator": "human"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["project"]["status"] == "active"
    assert payload["fact"]["id"] == "f002"
    assert payload["fact"]["description"] == "human correction"
    assert payload["intent"]["from"] == ["f001"]
    assert payload["intent"]["to"] == "f002"


def test_intent_semantics_are_inferred_when_optional_fields_are_omitted(client: TestClient) -> None:
    project_id = _create_project(client)
    response = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "@analysis:semantic-verify:authz:v1",
            "creator": "reasoner",
        },
    )
    assert response.status_code == 201
    assert response.json()["phase"] == "verification"
    assert response.json()["relation_type"] == "supports"


def test_negative_assurance_is_a_valid_hypothesis_completion_terminal(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={"title": "audit", "origin": "source", "goal": "safe", "audit_mode": "hypothesis"},
    )
    project_id = response.json()["project"]["id"]
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "check", "creator": "worker"},
    ).status_code == 201
    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat", json={"worker": "worker"}
    ).status_code == 200
    concluded = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={
            "worker": "worker",
            "description": "No exploitable path was found.",
            "type": "negative_assurance",
            "evidence": "snapshot:sha256:test",
        },
    )
    assert concluded.status_code == 200
    assert concluded.json()["fact"]["semantic_type"] == "negative_assurance"
    assert client.post(
        f"/projects/{project_id}/facts/f001/reviews",
        json={"verdict": "VALID", "confidence": "firm", "summary": "checked", "created_by": "reviewer"},
    ).status_code == 201
    complete = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["f001"], "description": "safe", "worker": "reasoner"},
    )
    assert complete.status_code == 200, complete.text


def test_stage_put_is_idempotent_and_decision_targets_are_validated(client: TestClient) -> None:
    project_id = _create_project(client)
    body = {"label": "coverage", "phase_order": 1, "status": "pending"}
    first = client.put(f"/projects/{project_id}/stages/coverage", json=body)
    assert first.status_code == 200
    revision = client.get("/projects").json()[0]["graph_revision"]
    events = len(client.get(f"/projects/{project_id}/events").json())
    second = client.put(f"/projects/{project_id}/stages/coverage", json=body)
    assert second.status_code == 200
    assert client.get("/projects").json()[0]["graph_revision"] == revision
    assert len(client.get(f"/projects/{project_id}/events").json()) == events
    assert client.post(
        f"/projects/{project_id}/decisions",
        json={"target_kind": "fact", "target_id": "missing", "decision": "exclude", "rationale": "typo", "actor": "human"},
    ).status_code == 404


def test_skill_receipt_is_bound_to_stage_and_verified_artifact(
    client: TestClient, tmp_path: Path,
) -> None:
    project_id = _create_project(client)
    stage = client.put(
        f"/projects/{project_id}/stages/semgrep",
        json={
            "label": "Semgrep",
            "phase_order": 30,
            "status": "pending",
            "skill_id": "security.semgrep",
            "capability": "static-analysis.sarif",
        },
    )
    assert stage.status_code == 200
    running_body = {
        "stage_id": "semgrep",
        "intent_id": None,
        "skill_id": "security.semgrep",
        "skill_version": "1",
        "capability": "static-analysis.sarif",
        "status": "running",
    }
    started = client.post(f"/projects/{project_id}/skill-runs", json=running_body)
    assert started.status_code == 201, started.text
    run_id = started.json()["id"]

    artifact_dir = tmp_path / ".linen-analysis" / "semgrep-run"
    artifact_dir.mkdir(parents=True)
    artifact = artifact_dir / "manifest.json"
    artifact.write_text('{"status":"completed"}', encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    completed_body = {
        **running_body,
        "status": "completed",
        "artifact_ref": str(artifact),
        "artifact_sha256": digest,
    }
    bad = client.put(
        f"/projects/{project_id}/skill-runs/{run_id}",
        json={**completed_body, "artifact_sha256": "0" * 64},
    )
    assert bad.status_code == 422
    finished = client.put(
        f"/projects/{project_id}/skill-runs/{run_id}", json=completed_body,
    )
    assert finished.status_code == 200, finished.text
    gate = client.get(f"/projects/{project_id}/completion-gate").json()
    receipt_check = next(check for check in gate["checks"] if check["id"] == "skill_receipts")
    assert receipt_check["status"] == "pass"
    assert receipt_check["evidence_ids"] == [run_id]
    assert client.put(
        f"/projects/{project_id}/skill-runs/{run_id}", json=completed_body,
    ).status_code == 409


def test_completed_report_uses_immutable_snapshot(client: TestClient) -> None:
    project_id = _create_project(client)
    # Generic projects preserve the legacy completion contract.
    client.post(f"/projects/{project_id}/intents", json={"from": ["origin"], "description": "work", "creator": "w"})
    client.post(f"/projects/{project_id}/intents/i001/heartbeat", json={"worker": "w"})
    client.post(f"/projects/{project_id}/intents/i001/conclude", json={"worker": "w", "description": "fact"})
    assert client.post(f"/projects/{project_id}/complete", json={"from": ["f001"], "description": "done", "worker": "w"}).status_code == 200
    before = client.get(f"/projects/{project_id}/export?format=report")
    assert before.headers.get("etag")
    assert client.post(f"/projects/{project_id}/hints", json={"content": "after", "creator": "human"}).status_code == 201
    after = client.get(f"/projects/{project_id}/export?format=report")
    assert after.text == before.text


def test_stopping_project_releases_claims_and_reason_but_keeps_hints_writable(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "lease_id": "lease-stop", "trigger": "facts:2->3"},
    )

    response = client.put(f"/projects/{project_id}/status", json={"status": "stopped"})
    assert response.status_code == 200
    assert response.json()["reason"] is None

    detail = client.get(f"/projects/{project_id}").json()
    assert detail["intents"][0]["worker"] is None
    assert client.post(
        f"/projects/{project_id}/hints",
        json={"content": "manual note", "creator": "human"},
    ).status_code == 201
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "blocked", "creator": "reasoner", "worker": None},
    ).status_code == 403


def test_stopped_project_compacts_surplus_coverage_intents_without_deleting_history(
    client: TestClient,
) -> None:
    project_id = _create_project(client)
    endpoint = f"/projects/{project_id}/intents/compact-coverage"
    assert client.post(endpoint, json={"keep": 2, "dry_run": False}).status_code == 409
    for index in range(6):
        response = client.post(
            f"/projects/{project_id}/intents",
            json={
                "from": ["origin"],
                "description": f"@coverage:plan:cell-{index}",
                "type": "verify",
                "creator": "dispatcher.audit",
            },
        )
        assert response.status_code == 201
    # Non-managed and non-coverage work must never be compacted.
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "ordinary trace", "creator": "reasoner"},
    ).status_code == 201
    assert client.put(
        f"/projects/{project_id}/status", json={"status": "stopped"},
    ).status_code == 200

    preview = client.post(endpoint, json={"keep": 2, "dry_run": True})
    assert preview.status_code == 200
    assert preview.json()["eligible_count"] == 6
    assert len(preview.json()["retired_ids"]) == 4
    assert all(intent["concluded_at"] is None for intent in client.get(
        f"/projects/{project_id}",
    ).json()["intents"])

    applied = client.post(endpoint, json={"keep": 2, "dry_run": False})
    assert applied.status_code == 200
    assert applied.json()["retired_ids"] == preview.json()["retired_ids"]
    detail = client.get(f"/projects/{project_id}").json()
    coverage_intents = [
        intent for intent in detail["intents"]
        if intent["description"].startswith("@coverage:")
    ]
    assert sum(intent["concluded_at"] is None for intent in coverage_intents) == 2
    assert sum(
        intent["type"] == "cancelled:coverage-compaction"
        for intent in coverage_intents
    ) == 4
    assert any(hint["creator"] == "dispatcher.compaction" for hint in detail["hints"])
    ordinary = next(
        intent for intent in detail["intents"] if intent["description"] == "ordinary trace"
    )
    assert ordinary["concluded_at"] is None

    exported = client.get(f"/projects/{project_id}/export?format=yaml").text
    assert "cancelled_intents:" in exported
    assert "count: 4" in exported
    assert "type: cancelled:coverage-compaction" not in exported


def test_intent_creation_rejects_goal_source_and_mismatched_initial_worker(client: TestClient) -> None:
    project_id = _create_project(client)

    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["goal"], "description": "invalid", "creator": "reasoner", "worker": None},
    ).status_code == 400
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "invalid", "creator": "reasoner", "worker": "explorer"},
    ).status_code == 400


def test_settings_and_export_are_backed_by_the_same_database(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.put("/settings", json={"intent_timeout": 30, "reason_timeout": 45})
    assert response.status_code == 200
    assert client.get("/settings").json() == {"intent_timeout": 30, "reason_timeout": 45}

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    assert exported.status_code == 200
    assert "origin: starting point" in exported.text
    assert "goal: finish" in exported.text
    assert client.get(f"/projects/{project_id}/export?format=invalid").status_code == 400


def test_json_and_sarif_exports_include_semantics_gate_and_findings(client: TestClient) -> None:
    project_id = _create_project(client)
    created = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": "trace untrusted input to command execution",
            "display_title": "Trace command input",
            "creator": "reasoner",
        },
    )
    assert created.status_code == 201
    concluded = client.post(
        f"/projects/{project_id}/intents/{created.json()['id']}/conclude",
        json={
            "worker": "reasoner",
            "description": "Untrusted command argument reaches a process launcher",
            "display_title": "Command argument injection",
            "type": "vulnerability",
            "evidence": "file: app.py:7",
        },
    )
    assert concluded.status_code == 200

    structured = client.get(f"/projects/{project_id}/export?format=json")
    assert structured.status_code == 200
    assert structured.headers["content-type"].startswith("application/json")
    payload = structured.json()
    assert payload["project"]["source_generation"] == 1
    assert payload["completion_gate"]["project_id"] == project_id
    assert payload["facts"][-1]["display_title"] == "Command argument injection"
    assert "graph_edges" in payload
    assert "audit_stages" in payload
    assert "skill_runs" in payload
    assert "human_decisions" in payload

    sarif = client.get(f"/projects/{project_id}/export?format=sarif")
    assert sarif.status_code == 200
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    sarif_payload = sarif.json()
    assert sarif_payload["version"] == "2.1.0"
    assert sarif_payload["runs"][0]["results"][0]["message"]["text"].startswith(
        "Untrusted command argument"
    )


def test_expired_intent_and_reason_leases_can_be_reclaimed(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "lease_id": "lease-old", "trigger": "bootstrap"},
    )
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE project_id = ?",
            (project_id,),
        )
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            (project_id,),
        )

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "worker-b"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "worker-b"

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "lease_id": "lease-new", "trigger": "facts:2->3"},
    )
    assert response.status_code == 200
    assert response.json()["reason"]["worker"] == "worker-b"
    assert response.json()["reason"]["lease_id"] == "lease-new"


def test_live_reason_lease_rejects_competing_worker(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "lease_id": "lease-a", "trigger": "bootstrap"},
    ).status_code == 200

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "lease_id": "lease-b", "trigger": "facts:2->3"},
    )

    assert response.status_code == 409
    assert "worker-a" in response.json()["detail"]


def test_reason_lease_token_rejects_stale_same_worker_operations(client: TestClient) -> None:
    project_id = _create_project(client)
    claim_path = f"/projects/{project_id}/reason/claim"
    heartbeat_path = f"/projects/{project_id}/reason/heartbeat"
    release_path = f"/projects/{project_id}/reason/release"

    assert client.post(
        claim_path,
        json={"worker": "worker-a", "lease_id": "lease-current", "trigger": "initial"},
    ).status_code == 200
    assert client.post(
        claim_path,
        json={"worker": "worker-a", "lease_id": "lease-stale", "trigger": "initial"},
    ).status_code == 409
    assert client.post(
        heartbeat_path,
        json={"worker": "worker-a", "lease_id": "lease-stale"},
    ).status_code == 409
    assert client.post(
        release_path,
        json={"worker": "worker-a", "lease_id": "lease-stale"},
    ).status_code == 409

    assert client.post(
        heartbeat_path,
        json={"worker": "worker-a", "lease_id": "lease-current"},
    ).status_code == 200
    assert client.post(
        release_path,
        json={"worker": "worker-a", "lease_id": "lease-current"},
    ).status_code == 200


def test_graph_revision_and_activity_status_follow_semantic_board_changes(client: TestClient) -> None:
    project_id = _create_project(client)

    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["graph_revision"] == 1
    assert summary["activity_status"] == "idle"

    created = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "inspect", "creator": "reasoner"},
    )
    assert created.status_code == 201
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["graph_revision"] == 2
    assert summary["activity_status"] == "queued"

    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    ).status_code == 200
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["graph_revision"] == 2
    assert summary["activity_status"] == "working"

    assert client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={
            "worker": "explorer",
            "description": "candidate",
            "type": "vulnerability",
            "evidence": "source.py:1",
            "status": "draft",
        },
    ).status_code == 200
    assert client.post(
        f"/projects/{project_id}/facts/f001/reviews",
        json={
            "verdict": "VALID",
            "confidence": "firm",
            "summary": "confirmed",
            "created_by": "reviewer",
        },
    ).status_code == 201
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["graph_revision"] == 4
    assert summary["review_count"] == 1
    assert summary["activity_status"] == "idle"

    assert client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "reasoner", "lease_id": "lease-reason", "trigger": "review"},
    ).status_code == 200
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["graph_revision"] == 4
    assert summary["activity_status"] == "reasoning"


def test_intent_error_blocks_dispatch_is_visible_and_can_be_retried(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "inspect", "creator": "reasoner"},
    ).status_code == 201
    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    ).status_code == 200

    failed = client.post(
        f"/projects/{project_id}/intents/i001/fail",
        json={
            "worker": "explorer",
            "task_type": "explore",
            "code": "source_repository_missing",
            "classification": "blocked",
            "message": "No source repository is attached.",
            "remediation": "Attach source, then retry.",
        },
    )
    assert failed.status_code == 200
    assert failed.json()["classification"] == "blocked"
    assert failed.json()["attempt_count"] == 1

    detail = client.get(f"/projects/{project_id}").json()
    assert detail["intents"][0]["worker"] is None
    assert detail["errors"][0]["code"] == "source_repository_missing"
    assert detail["errors"][0]["resolved_at"] is None
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["activity_status"] == "blocked"
    assert summary["blocked_intent_count"] == 1
    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    ).status_code == 409

    retried = client.post(
        f"/projects/{project_id}/intents/i001/retry",
        json={"actor": "Human"},
    )
    assert retried.status_code == 200
    detail = client.get(f"/projects/{project_id}").json()
    assert detail["errors"][0]["resolved_at"] is not None
    assert detail["errors"][0]["resolution"] == "manual retry requested by Human"
    summary = next(p for p in client.get("/projects").json() if p["id"] == project_id)
    assert summary["activity_status"] == "queued"
    assert summary["blocked_intent_count"] == 0
    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    ).status_code == 200

    timeline = client.get(f"/projects/{project_id}/export?format=timeline")
    assert "INTENT BLOCKED i001 [source_repository_missing]" in timeline.text
    assert "INTENT ERROR RESOLVED i001" in timeline.text


def test_transient_intent_error_uses_backoff_and_promotes_after_retry_budget(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "inspect", "creator": "reasoner"},
    )
    body = {
        "worker": "explorer",
        "task_type": "explore",
        "code": "task_failed",
        "classification": "transient",
        "message": "Worker output was invalid.",
        "base_retry_seconds": 30,
        "max_retry_seconds": 60,
        "max_attempts": 2,
    }
    first = client.post(f"/projects/{project_id}/intents/i001/fail", json=body)
    assert first.status_code == 200
    assert first.json()["classification"] == "transient"
    assert first.json()["retry_at"] is not None
    assert first.json()["attempt_count"] == 1

    second = client.post(f"/projects/{project_id}/intents/i001/fail", json=body)
    assert second.status_code == 200
    assert second.json()["classification"] == "blocked"
    assert second.json()["retry_at"] is None
    assert second.json()["attempt_count"] == 2


def test_project_creation_persists_audit_profile_and_exports_it(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "no bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": False,
            "audit_mode": "scope",
        },
    )

    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    project = client.get(f"/projects/{project_id}").json()["project"]
    assert project["bootstrap_enabled"] is False
    assert project["audit_mode"] == "scope"
    exported = client.get(f"/projects/{project_id}/export?format=yaml").text
    assert "bootstrap_enabled: false" in exported
    assert "audit_mode: scope" in exported


def test_project_creation_rejects_invalid_bootstrap_enabled(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "invalid bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": "sometimes",
        },
    )

    assert response.status_code == 422


def test_git_project_skips_retained_clone_targets_and_advances_counter(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clones = tmp_path / "clones"
    (clones / "proj_001").mkdir(parents=True)
    (clones / "proj_002").mkdir()
    monkeypatch.setenv("LINEN_CLONES_ROOT", str(clones))
    clone_targets: list[Path] = []

    def fake_clone(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        target = Path(argv[-1])
        clone_targets.append(target)
        target.mkdir()
        (target / ".git").mkdir()
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(projects.subprocess, "run", fake_clone)

    response = client.post(
        "/projects",
        json={
            "title": "audit",
            "origin": "https://example.test/repo.git",
            "goal": "find bugs",
            "clone_url": "https://example.test/repo.git",
        },
    )

    assert response.status_code == 201, response.text
    project = response.json()["project"]
    assert project["id"] == "proj_003"
    assert Path(project["repo_root"]) == (clones / "proj_003").resolve()
    assert clone_targets == [clones / "proj_003"]
    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT value FROM counters WHERE name = 'project'"
        ).fetchone()["value"] == 3

    # The skipped ids are real gaps; the next ordinary project continues
    # after the id assigned to the successful clone.
    ordinary = client.post(
        "/projects",
        json={"title": "next", "origin": "description", "goal": "finish"},
    )
    assert ordinary.status_code == 201
    assert ordinary.json()["project"]["id"] == "proj_004"


def test_failed_clone_does_not_consume_skipped_project_id(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clones = tmp_path / "clones"
    (clones / "proj_001").mkdir(parents=True)
    monkeypatch.setenv("LINEN_CLONES_ROOT", str(clones))

    def failed_clone(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        Path(argv[-1]).mkdir()
        return subprocess.CompletedProcess(argv, 128, stdout="", stderr="network failed")

    monkeypatch.setattr(projects.subprocess, "run", failed_clone)
    body = {
        "title": "audit",
        "origin": "https://example.test/repo.git",
        "goal": "find bugs",
        "clone_url": "https://example.test/repo.git",
    }

    response = client.post("/projects", json=body)

    assert response.status_code == 422
    assert not (clones / "proj_002").exists()
    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT value FROM counters WHERE name = 'project'"
        ).fetchone()["value"] == 0

    def successful_clone(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        Path(argv[-1]).mkdir()
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(projects.subprocess, "run", successful_clone)
    retry = client.post("/projects", json=body)
    assert retry.status_code == 201, retry.text
    assert retry.json()["project"]["id"] == "proj_002"


def test_project_creation_ui_reports_clone_progress_and_blocks_duplicate_submit(
    client: TestClient,
) -> None:
    html = client.get("/").text

    assert "if (this.isCreatingProject) return" in html
    assert ':disabled="isCreatingProject || !newProject.title' in html
    assert "Cloning source on the server" in html
    assert "Cloning…" in html
    assert "p.activity_status || 'idle'" in html
    assert "projectActivityStatus(project)" in html


def test_ui_exposes_report_export_download_and_copyable_sidebar(client: TestClient) -> None:
    html = client.get("/").text

    assert "Final result & project export" in html
    assert "switchExportTab('report')" in html
    assert "downloadExportPreview()" in html
    assert "copySidePanelText()" in html
    assert "side-panel-copyable" in html
    assert "Retry intent" in html
    assert "selectedIntentError()" in html
    assert "intent_blocked" in html


def test_ui_uses_semantic_node_titles_typed_edges_and_progressive_detail(
    client: TestClient,
) -> None:
    html = client.get("/").text

    assert "factDisplayTitle(fact)" in html
    assert "semanticFamily(record" in html
    assert "edgeRelationForIntent(intent" in html
    assert "label: intent.description" not in html
    assert "const lbl = intent.description" not in html
    assert "Blackboard semantics" in html
    for family in ("Scope", "Work", "Evidence", "Reasoning", "Outcome"):
        assert f"<b>{family}</b>" in html
    assert "Completion Gate" in html
    assert "Human adjudication" in html
    assert "toggleTimelineRaw(entry.id)" in html
    assert "switchExportTab('json')" in html
    assert "switchExportTab('sarif')" in html


def test_project_workbench_groups_secondary_surfaces_without_duplicate_drawer(
    client: TestClient,
) -> None:
    html = client.get("/").text

    for label in ("Inspect", "Audit", "Activity"):
        assert f">{label}</button>" in html
    assert ">New intent</button>" in html
    assert ">Analyst note</button>" in html
    assert "Execution details" in html
    assert "activityDrawerOpen" not in html
    assert 'class="graph-header-stats' not in html
