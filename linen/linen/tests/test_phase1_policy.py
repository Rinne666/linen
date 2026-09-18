from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from linen.server import db
from linen.server.app import app
from linen.server.kernel import create_intent as create_intent_kernel
from linen.server.models import CreateIntentRequest, ProjectDetail, ProjectMeta
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks.common import best_effort_release_reason


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as test_client:
        yield test_client


def test_intent_creation_is_idempotent_by_stable_semantics(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "idempotency", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    payload = {
        "from": ["origin"],
        "description": "Trace request input to the handler",
        "creator": "reasoner",
        "action": "trace",
        "target": "request input -> handler",
        "scope": "api",
    }
    first = client.post(f"/projects/{project}/intents", json=payload)
    second = client.post(f"/projects/{project}/intents", json=payload)

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert len(client.get(f"/projects/{project}").json()["intents"]) == 1


def test_intent_identity_ignores_evidence_sources(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "semantic identity", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    first = client.post(
        f"/projects/{project}/intents",
        json={
            "from": ["origin"],
            "description": "Trace the request boundary",
            "creator": "reasoner",
            "action": "trace",
            "target": "request boundary",
        },
    )
    second = client.post(
        f"/projects/{project}/intents",
        json={
            "from": ["origin"],
            "description": "Same semantic task with another explanation",
            "creator": "reasoner",
            "action": "trace",
            "target": "request boundary",
        },
    )

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


def test_concurrent_intent_creation_has_one_id(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "concurrent idempotency", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    body = CreateIntentRequest(
        **{
            "from": ["origin"],
            "description": "Inspect the request boundary",
            "creator": "reasoner",
            "action": "inspect",
            "target": "request boundary",
            "scope": "api",
        }
    )

    def create() -> str:
        with db.get_conn() as conn:
            return create_intent_kernel(conn, project, body).id

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(lambda _: create(), range(2)))

    assert ids[0] == ids[1]
    assert len(client.get(f"/projects/{project}").json()["intents"]) == 1


def test_goal_based_completion_does_not_require_empty_queue(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "goal", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    intent = client.post(
        f"/projects/{project}/intents",
        json={"from": ["origin"], "description": "optional follow-up", "creator": "reasoner"},
    ).json()
    assert intent["id"] == "i001"
    gate = client.get(f"/projects/{project}/completion-gate").json()
    open_work = next(check for check in gate["checks"] if check["id"] == "open_work")
    assert open_work["status"] == "pass"
    assert open_work["blocking"] is False


def test_blocked_intent_can_be_resolved_by_retry_or_abandon(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "blocked resolution", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]

    def blocked_intent(target: str) -> str:
        intent = client.post(
            f"/projects/{project}/intents",
            json={
                "from": ["origin"], "description": target, "creator": "reasoner",
                "action": "inspect", "target": target,
            },
        ).json()
        intent_id = intent["id"]
        assert client.post(
            f"/projects/{project}/intents/{intent_id}/heartbeat",
            json={"worker": "worker-a"},
        ).status_code == 200
        assert client.post(
            f"/projects/{project}/intents/{intent_id}/fail",
            json={
                "worker": "worker-a", "task_type": "explore", "code": "no_route",
                "classification": "transient", "message": "cannot reach target",
                "max_attempts": 1,
            },
        ).status_code == 200
        return intent_id

    retry_id = blocked_intent("retry this")
    retry = client.post(
        f"/projects/{project}/intents/{retry_id}/resolve",
        json={"actor": "reason-worker", "action": "retry"},
    )
    assert retry.status_code == 200
    assert retry.json()["concluded_at"] is None
    assert client.post(
        f"/projects/{project}/intents/{retry_id}/heartbeat",
        json={"worker": "worker-b"},
    ).status_code == 200
    assert client.post(
        f"/projects/{project}/intents/{retry_id}/resolve",
        json={"actor": "reason-worker", "action": "retry"},
    ).status_code == 409

    abandon_id = blocked_intent("abandon this")
    abandon = client.post(
        f"/projects/{project}/intents/{abandon_id}/resolve",
        json={"actor": "reason-worker", "action": "abandon"},
    )
    assert abandon.status_code == 200
    assert abandon.json()["concluded_at"] is not None


def test_resolve_rejects_intents_without_an_open_blocked_error(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "invalid resolution", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    intent = client.post(
        f"/projects/{project}/intents",
        json={"from": ["origin"], "description": "not blocked", "creator": "reasoner", "action": "inspect", "target": "not-blocked"},
    ).json()
    resolve_url = f"/projects/{project}/intents/{intent['id']}/resolve"
    assert client.post(resolve_url, json={"actor": "reason-worker", "action": "retry"}).status_code == 409

    assert client.post(
        f"/projects/{project}/intents/{intent['id']}/heartbeat",
        json={"worker": "worker-a"},
    ).status_code == 200
    assert client.post(
        f"/projects/{project}/intents/{intent['id']}/fail",
        json={
            "worker": "worker-a", "task_type": "explore", "code": "blocked",
            "classification": "blocked", "message": "permanent failure",
        },
    ).status_code == 200
    assert client.post(resolve_url, json={"actor": "reason-worker", "action": "abandon"}).status_code == 200
    assert client.post(resolve_url, json={"actor": "reason-worker", "action": "retry"}).status_code == 409


def test_blocked_resolution_survives_server_restart(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "restart recovery", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    intent = client.post(
        f"/projects/{project}/intents",
        json={"from": ["origin"], "description": "recover", "creator": "reasoner", "action": "inspect", "target": "recover"},
    ).json()
    intent_id = intent["id"]
    assert client.post(
        f"/projects/{project}/intents/{intent_id}/heartbeat",
        json={"worker": "worker-a"},
    ).status_code == 200
    assert client.post(
        f"/projects/{project}/intents/{intent_id}/fail",
        json={
            "worker": "worker-a", "task_type": "explore", "code": "blocked",
            "classification": "blocked", "message": "restart me",
        },
    ).status_code == 200

    with TestClient(app) as restarted:
        resolved = restarted.post(
            f"/projects/{project}/intents/{intent_id}/resolve",
            json={"actor": "reason-worker", "action": "retry"},
        )
    assert resolved.status_code == 200
    assert client.post(
        f"/projects/{project}/intents/{intent_id}/heartbeat",
        json={"worker": "worker-b"},
    ).status_code == 200


def test_reason_release_only_advances_cursor_on_success() -> None:
    class FakeClient:
        def __init__(self):
            self.payloads = []

        def release_reason(self, project_id, worker, lease_id, seen_event_seq=None):
            self.payloads.append(seen_event_seq)
            return ApiResult(200, {})

    fake = FakeClient()
    best_effort_release_reason(fake, "p", "w", "l", 12)
    best_effort_release_reason(fake, "p", "w", "l", 12, ack=True)

    assert fake.payloads == [None, 12]


def test_reason_failure_retries_same_event_sequence() -> None:
    project = ProjectDetail(
        project=ProjectMeta(
            id="p",
            title="retry",
            status="active",
            created_at="2026-01-01T00:00:00+00:00",
            reason_last_seen_event_seq=3,
            event_seq=4,
        ),
        facts=[],
        intents=[],
        hints=[],
    )
    scheduler = DispatcherLoop.__new__(DispatcherLoop)

    first = scheduler._reason_trigger(project)
    second = scheduler._reason_trigger(project)

    assert first == second == "events:3->4"


def test_events_created_during_reason_round_remain_pending_for_next_round(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "event wakeup", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    before = client.get(f"/projects/{project}").json()["project"]
    assert client.post(
        f"/projects/{project}/reason/claim",
        json={"worker": "reasoner", "lease_id": "round-1", "trigger": "events"},
    ).status_code == 200

    def create(index: int) -> int:
        response = client.post(
            f"/projects/{project}/intents",
            json={
                "from": ["origin"], "description": f"event {index}",
                "creator": "reasoner", "action": "inspect", "target": f"event-{index}",
            },
        )
        assert response.status_code == 201
        return response.json()["id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(create, range(4)))

    during = client.get(f"/projects/{project}").json()["project"]
    assert during["event_seq"] > before["event_seq"]
    released = client.post(
        f"/projects/{project}/reason/release",
        json={"worker": "reasoner", "lease_id": "round-1", "seen_event_seq": before["event_seq"]},
    )
    assert released.status_code == 200
    after = client.get(f"/projects/{project}").json()["project"]
    assert after["reason_last_seen_event_seq"] == before["event_seq"]
    assert after["event_seq"] == during["event_seq"]
    assert after["event_seq"] > after["reason_last_seen_event_seq"]


def test_concurrent_blocked_resolve_allows_only_one_transition(client) -> None:
    project = client.post(
        "/projects",
        json={"title": "resolve race", "origin": "repo", "goal": "done"},
    ).json()["project"]["id"]
    intent = client.post(
        f"/projects/{project}/intents",
        json={"from": ["origin"], "description": "race", "creator": "reasoner", "action": "inspect", "target": "race"},
    ).json()
    intent_id = intent["id"]
    assert client.post(
        f"/projects/{project}/intents/{intent_id}/heartbeat",
        json={"worker": "worker-a"},
    ).status_code == 200
    assert client.post(
        f"/projects/{project}/intents/{intent_id}/fail",
        json={
            "worker": "worker-a", "task_type": "explore", "code": "blocked",
            "classification": "blocked", "message": "permanent failure",
        },
    ).status_code == 200

    def resolve(action: str) -> int:
        return client.post(
            f"/projects/{project}/intents/{intent_id}/resolve",
            json={"actor": action, "action": action},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(resolve, ["retry", "abandon"]))
    assert sorted(statuses) == [200, 409]
