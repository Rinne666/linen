from __future__ import annotations

from concurrent.futures import Future
import json

import pytest

from linen.dispatcher.models import RunningTask
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks.common import (
    _attempt_status,
    _result_failure_code,
    classify_provider_failure,
)
from linen.server.models import AuditEvent

from conftest import make_config, make_project


class FailureClient:
    def __init__(self) -> None:
        self.project = make_project()
        self.project.project.audit_mode = "scope"
        self.issues: list[dict] = []
        self.events: list[AuditEvent] = []

    def get_project(self, _project_id):
        return self.project

    def report_project_worker_issue(self, project_id, worker, task_type, code, message, remediation, intent_id):
        self.issues.append({"worker": worker, "code": code})
        self.project.project.status = "stopped"
        self.project.project.event_seq += 1
        return ApiResult(200, {"event_seq": self.project.project.event_seq})

    def get_audit_events(self, _project_id, *, after, limit):
        return [event for event in self.events if event.sequence > after][:limit]

    def resume(self) -> None:
        self.project.project.status = "active"
        self.project.project.event_seq += 1
        self.events.append(AuditEvent(
            sequence=self.project.project.event_seq,
            event_type="project_worker_issue_resumed", actor="Human",
            entity_kind="project", entity_id=self.project.project.id,
            payload={"worker_issues": [self.issues[-1]]},
            created_at="1970-01-01T00:00:00Z",
        ))


def failure_loop(tmp_path, client=None):
    loop = DispatcherLoop.__new__(DispatcherLoop)
    config = make_config()
    loop.config = config.model_copy(update={
        "local": config.local.model_copy(update={"workspace_root": str(tmp_path)}),
    })
    loop.client = client or FailureClient()
    loop.futures = {}
    loop.runtime_project_ids = set()
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_provider_until = {}
    loop.worker_provider_reason = {}
    loop.worker_provider_opened_at = {}
    loop.worker_provider_origin = {}
    loop._log_state = {}
    loop._restore_provider_circuits()
    return loop


def finish(loop, outcome, *, task_type="reason", provider_required=True):
    future: Future[str] = Future()
    future.set_result(outcome)
    loop.futures[future] = RunningTask(
        loop.client.project.project.id, task_type, "test-worker", TaskCancellation(),
        provider_required=provider_required,
    )
    loop._reap_futures()


def transport_output():
    return "\n".join(json.dumps(event) for event in (
        {"type": "error", "message": "Reconnecting... workspace routing discovery failed"},
        {"type": "turn.failed", "error": {"message": "workspace routing discovery failed"}},
    ))


def test_terminal_transport_errors_are_classified_and_archived():
    result = ProcessResult(1, transport_output(), "")
    assert classify_provider_failure(result) == "provider_transport_unavailable"
    assert _attempt_status(result, True) == "failed"
    assert _result_failure_code(result, True) == "provider_transport_unavailable"
    # Explicit terminal errors can also accompany a zero CLI exit code.
    result.returncode = 0
    assert _attempt_status(result, True) == "failed"
    assert _result_failure_code(result, True) == "provider_transport_unavailable"


def test_recovered_stream_and_assistant_text_do_not_open_transport_circuit():
    recovered = "\n".join(json.dumps(event) for event in (
        {"type": "error", "message": "stream disconnected; reconnecting"},
        {"type": "item.completed", "item": {
            "type": "agent_message", "text": "The fixture says workspace routing discovery failed",
        }},
        {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}},
    ))
    result = ProcessResult(0, recovered, "")
    assert classify_provider_failure(result) is None
    assert _attempt_status(result, True) == "completed"
    assert _result_failure_code(result, True) is None
    assert classify_provider_failure(ProcessResult(
        1, json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "workspace routing discovery failed",
        }}), "unrelated worker failure",
    )) is None


def test_explicit_routing_timeout_keeps_transport_cause_after_worker_timeout():
    result = ProcessResult(124, json.dumps({
        "type": "error", "message": "Reconnecting... workspace routing discovery timed out",
    }), "", timed_out=True)
    assert classify_provider_failure(result) == "provider_transport_unavailable"
    assert _attempt_status(result, True) == "timed_out"
    assert _result_failure_code(result, True) == "provider_transport_unavailable"
    assert _result_failure_code(ProcessResult(124, "", "", timed_out=True), True) == "worker_timeout"


def test_transport_strikes_survive_restart_and_end_in_manual_resume(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: now[0])
    loop = failure_loop(tmp_path)
    client = loop.client
    for attempt, retry_at in ((1, 160.0), (2, 281.0), (3, 522.0)):
        finish(loop, "provider_transport_unavailable")
        assert loop.worker_transport_failures == {"test-worker": attempt}
        assert loop.worker_provider_until["test-worker"] == retry_at
        assert loop._select_worker("proj_001", "reason").worker is None
        assert loop._select_worker("proj_001", "explore", provider_required=False).worker is not None
        now[0] = retry_at + 1
        loop = failure_loop(tmp_path, client)
        assert loop.worker_transport_failures == {"test-worker": attempt}
        if attempt < 3:
            assert loop._select_worker("proj_001", "reason").worker is not None
    assert client.project.project.status == "stopped"
    assert client.issues == [{"worker": "test-worker", "code": "provider_transport_unavailable"}]
    now[0] += 100_000
    loop = failure_loop(tmp_path, client)
    assert loop._select_worker("proj_001", "reason").worker is None
    client.resume()
    loop._honor_project_worker_issue_resumes(client.project)
    assert loop.worker_transport_failures == {}
    assert loop._select_worker("proj_001", "reason").worker is not None
    assert failure_loop(tmp_path, client).worker_transport_failures == {}


@pytest.mark.parametrize("outcome", ["failed", "rejected", "invalid_result:bad JSON", "task_crashed"])
def test_reason_without_intent_has_persistent_bounded_retry(tmp_path, monkeypatch, outcome):
    now = [100.0]
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: now[0])
    loop = failure_loop(tmp_path)
    client = loop.client
    for attempt in range(1, 4):
        finish(loop, outcome)
        state = loop.reason_failures["proj_001"]
        assert state.attempts == attempt
        assert not loop._reason_failure_allows_dispatch(client.project)
        # Ordinary Reason failures leave healthy Explore execution available.
        assert loop._select_worker("proj_001", "explore").worker is not None
        now[0] = state.retry_at + 1
        loop = failure_loop(tmp_path, client)
        assert loop._reason_failure_allows_dispatch(client.project) is (attempt < 3)
    assert client.project.project.status == "stopped"
    assert client.issues == [{"worker": "test-worker", "code": "reason_execution_failed"}]
    client.resume()
    loop._honor_project_worker_issue_resumes(client.project)
    assert loop._reason_failure_allows_dispatch(client.project)
    assert failure_loop(tmp_path, client).reason_failures == {}


@pytest.mark.parametrize("outcome", ["success", "noop", "waiting", "stale"])
def test_successful_worker_response_clears_failure_strikes(tmp_path, monkeypatch, outcome):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    finish(loop, "failed")
    finish(loop, "provider_transport_unavailable")
    finish(loop, outcome)
    assert loop.reason_failures == {}
    assert loop.worker_transport_failures == {}
    assert loop.worker_provider_until == {}
    restored = failure_loop(tmp_path, loop.client)
    assert restored.reason_failures == {}
    assert restored.worker_transport_failures == {}


def test_concurrent_graph_updates_do_not_exhaust_reason_failure_budget(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    for _ in range(3):
        finish(loop, "stale")
    assert loop.reason_failures == {}
    assert loop.client.issues == []
    assert loop.client.project.project.status == "active"


def test_valid_waits_do_not_emit_noop_stalls_or_preserve_old_cooldowns(tmp_path):
    loop = failure_loop(tmp_path)
    loop._reason_noop_streak = {"proj_001": 2}
    loop._reason_cooldown_until = {"proj_001": 9999999999}
    loop._append_runtime_health_event = lambda *_a, **_k: pytest.fail("valid waits are not stalls")
    for _ in range(4):
        finish(loop, "waiting")
    assert loop._reason_noop_streak == {}
    assert loop._reason_cooldown_until == {}


def test_fresh_plan_resets_reason_failures_but_priority_wakes_do_not(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    finish(loop, "failed")
    project = loop.client.project
    project.project.graph_revision += 5
    project.project.event_seq += 5
    assert not loop._reason_failure_allows_dispatch(project)
    project.project.plan_revision += 1
    assert loop._reason_failure_allows_dispatch(project)
    assert failure_loop(tmp_path, loop.client).reason_failures == {}


def test_non_provider_work_does_not_clear_transport_circuit(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    finish(loop, "provider_transport_unavailable")
    finish(loop, "success", task_type="explore", provider_required=False)
    assert loop.worker_transport_failures == {"test-worker": 1}


def test_old_resume_cannot_clear_a_later_reason_block(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    for _ in range(3):
        finish(loop, "failed")
    client = loop.client
    state = loop.reason_failures["proj_001"]
    client.events.append(AuditEvent(
        sequence=state.blocked_event_seq,
        event_type="project_worker_issue_resumed", actor="Human",
        entity_kind="project", entity_id="proj_001",
        payload={"worker_issues": [client.issues[-1]]},
        created_at="2099-01-01T00:00:00Z",
    ))
    loop._honor_project_worker_issue_resumes(client.project)
    assert not loop._reason_failure_allows_dispatch(client.project)
    client.resume()
    loop._honor_project_worker_issue_resumes(client.project)
    assert loop.reason_failures == {}


def test_reason_future_crashes_also_exhaust_the_failure_budget(tmp_path, monkeypatch):
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = failure_loop(tmp_path)
    for _ in range(3):
        future: Future[str] = Future()
        future.set_exception(RuntimeError("runner crashed before producing a result"))
        loop.futures[future] = RunningTask(
            "proj_001", "reason", "test-worker", TaskCancellation(),
        )
        loop._reap_futures()
    assert loop.reason_failures["proj_001"].attempts == 3
    assert loop.client.project.project.status == "stopped"
