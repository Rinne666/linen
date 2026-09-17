from __future__ import annotations

import json

from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks import review

from conftest import (
    FakeClient,
    FakeContainerManager,
    FakeDriver,
    FakeLease,
    make_config,
    make_intent,
    make_project,
)


def _lease_factory(lease: FakeLease):
    return lambda *_args, **_kwargs: lease


def _context_required() -> str:
    return json.dumps({
        "accepted": True,
        "data": {
            "status": "context_required",
            "context_request": {
                "node_ids": ["f001"],
                "relation_types": ["supports"],
                "artifact_ids": [],
                "reason": "Need one bounded supporting node",
            },
        },
    })


def test_review_context_request_is_rejected_and_sandbox_is_cleaned(monkeypatch) -> None:
    config = make_config()
    project = make_project(intents=[make_intent()])
    client = FakeClient(project)
    client.reviews = []
    client.create_review = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("context request must not write a review")
    )
    backend = FakeContainerManager()
    driver = FakeDriver()
    lease = FakeLease()

    class FakeProcess:
        def __init__(self) -> None:
            self.killed = False

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()

    class FakeSandbox:
        def __init__(self, *args) -> None:
            self.last_process = process

    config.audit.review_sandbox.enabled = True
    config.audit.review_sandbox.image = "test-image"
    monkeypatch.setattr(review, "get_driver", lambda *_args: driver)
    monkeypatch.setattr(review.HeartbeatLease, "for_intent", _lease_factory(lease))
    monkeypatch.setattr(
        review,
        "run_worker_process",
        lambda *_args, **_kwargs: ProcessResult(0, _context_required(), ""),
    )
    monkeypatch.setattr(review, "ReviewSandboxBackend", FakeSandbox)
    monkeypatch.setattr(
        review,
        "select_snapshot",
        lambda *_args: (backend, {"id": "snap-1", "files": {}}),
    )
    monkeypatch.setattr(review, "review_inputs", lambda *_args: {})

    outcome = review.run_review_task(
        config,
        client,
        backend,
        project,
        "graph",
        project.intents[0],
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "failed"
    assert process.killed
    assert client.released == [("proj_001", "i001", "test-worker")]
    assert lease.started and lease.stopped
