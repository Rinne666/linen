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
