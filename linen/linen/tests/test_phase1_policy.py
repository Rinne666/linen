from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from linen.server import db
from linen.server.app import app


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
