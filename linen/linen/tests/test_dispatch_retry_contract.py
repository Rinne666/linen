from __future__ import annotations

from concurrent.futures import Future
from types import SimpleNamespace

from linen.dispatcher.models import RunningTask
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.scheduler.loop import DispatcherLoop, WorkerSelection
from linen.dispatcher.scheduler import loop as scheduler_module
from linen.server.models import IntentError, ProjectSummary
from linen.dispatcher.protocol.client import ApiResult

from conftest import make_config, make_intent, make_project


class _Executor:
    def __init__(self) -> None:
        self.calls: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

    def submit(self, runner, *args, **kwargs):
        self.calls.append((runner, args, kwargs))
        return Future()


class _ClaimClient:
    def __init__(self) -> None:
        self.claims: list[tuple[object, ...]] = []

    def claim_reason(self, *args):
        self.claims.append(args)
        return ApiResult(200, {})


def _base_loop() -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = make_config()
    loop.client = _ClaimClient()
    loop.client.release_reason = lambda *_args: ApiResult(200, {})
    loop.container_manager = object()
    loop.executor = _Executor()
    loop.futures = {}
    loop.runtime_project_ids = set()
    loop.worker_rejected_until = {}
    loop.worker_unhealthy_until = {}
    loop.worker_provider_until = {}
    loop.worker_provider_reason = {}
    loop._log_state = {}
    loop._clear_log_state = lambda *_args: None
    loop._clear_project_log_state = lambda *_args: None
    loop._select_worker = lambda *_args, **_kwargs: WorkerSelection(
        worker=loop.config.workers[0],
        blocked_busy=[],
        blocked_unhealthy=[],
        blocked_rejected=[],
        blocked_task_type=[],
    )
    return loop


def test_reason_dispatch_passes_stable_trigger_and_attempt(monkeypatch) -> None:
    loop = _base_loop()
    project = make_project()
    runner = lambda *args, **kwargs: "success"
    monkeypatch.setattr(scheduler_module, "run_reason_task", runner)

    assert loop._dispatch_reason(project, "graph", "initial")

    _runner, _args, kwargs = loop.executor.calls[0]
    assert kwargs["trigger"] == "initial"
    assert kwargs["attempt"] == 1
    task = next(iter(loop.futures.values()))
    assert task.attempt == 1
    assert task.trigger == "initial"


def test_legacy_fake_runner_does_not_receive_contract_keywords() -> None:
    loop = _base_loop()

    def old_runner(*args):
        return "success"

    loop._submit_task_runner(old_runner, "arg", trigger="stable", attempt=2)
    assert loop.executor.calls[0][2] == {}


def test_intent_attempt_uses_current_persistent_error_history_only() -> None:
    project = make_project(intents=[make_intent()])
    project.errors = [
        IntentError(
            id="e1",
            intent_id="i001",
            task_type="explore",
            code="task_failed",
            classification="transient",
            message="first",
            first_failed_at="2026-01-01T00:00:00Z",
            last_failed_at="2026-01-01T00:00:00Z",
            attempt_count=1,
            resolved_at="2026-01-01T00:00:02Z",
        ),
        IntentError(
            id="e2",
            intent_id="i001",
            task_type="explore",
            code="task_failed",
            classification="transient",
            message="second",
            first_failed_at="2026-01-01T00:00:01Z",
            last_failed_at="2026-01-01T00:00:01Z",
            attempt_count=2,
        ),
    ]

    assert (
        DispatcherLoop._intent_attempt(
            project, project.intents[0], task_type="explore"
        )
        == 3
    )


def test_resolved_or_other_task_errors_do_not_advance_new_attempt() -> None:
    project = make_project(intents=[make_intent()])
    project.errors = [
        IntentError(
            id="old",
            intent_id="i001",
            task_type="explore",
            code="task_failed",
            classification="transient",
            message="resolved old plan",
            first_failed_at="2026-01-01T00:00:00Z",
            last_failed_at="2026-01-01T00:00:00Z",
            attempt_count=9,
            resolved_at="2026-01-01T00:00:01Z",
        ),
        IntentError(
            id="other",
            intent_id="i001",
            task_type="review",
            code="task_failed",
            classification="transient",
            message="different task",
            first_failed_at="2026-01-01T00:00:00Z",
            last_failed_at="2026-01-01T00:00:00Z",
            attempt_count=4,
        ),
    ]

    assert (
        DispatcherLoop._intent_attempt(
            project, project.intents[0], task_type="explore"
        )
        == 1
    )


def test_ordinary_failure_error_budget_is_two_and_provider_budget_is_preserved() -> None:
    loop = _base_loop()
    recorded: list[dict[str, object]] = []

    class Client(_ClaimClient):
        def report_intent_error(self, *args, **kwargs):
            recorded.append(kwargs)
            return ApiResult(200, {})

    loop.client = Client()
    task = RunningTask(
        "proj_001", "explore", "worker", TaskCancellation(), intent_id="i001"
    )
    loop._record_intent_error(task, "failed")
    loop._record_intent_error(task, "rate_limited")

    assert recorded[0]["max_attempts"] == 2
    assert recorded[1]["max_attempts"] == 15


def _active_summary(project_id: str = "proj_001") -> ProjectSummary:
    return ProjectSummary(
        id=project_id,
        title="test",
        status="active",
        bootstrap_enabled=True,
        created_at="2026-01-01T00:00:00Z",
        fact_count=0,
        intent_count=0,
        working_intent_count=0,
        unclaimed_intent_count=0,
        hint_count=0,
    )


def test_orphan_intent_recovery_reports_once_with_ordinary_retry_budget() -> None:
    loop = _base_loop()
    calls: list[dict[str, object]] = []

    class Client(_ClaimClient):
        def recover_runs(self, project_id: str):
            calls.append({"recover": project_id})
            return [
                SimpleNamespace(
                    run_id="run-orphan",
                    project_id=project_id,
                    intent_id="i001",
                    task_type="explore_execute",
                    attempt=1,
                    status="interrupted",
                    graph_revision=0,
                    worker_name="worker",
                )
            ]

        def report_intent_error(self, *args, **kwargs):
            calls.append(kwargs)
            return ApiResult(200, {})

    loop.client = Client()
    summary = _active_summary()
    loop._recover_orphan_runs([summary])
    loop._recover_orphan_runs([summary])

    reports = [call for call in calls if "code" in call]
    assert len([call for call in calls if "recover" in call]) == 1
    assert len(reports) == 1
    assert reports[0]["code"] == "orphan_run_interrupted"
    assert reports[0]["task_type"] == "explore"
    assert reports[0]["max_attempts"] == 2


def test_orphan_recovery_retries_after_network_error_then_reports_once() -> None:
    loop = _base_loop()
    recovery_calls = 0
    reports: list[dict[str, object]] = []

    class Client(_ClaimClient):
        def recover_runs(self, project_id: str):
            nonlocal recovery_calls
            recovery_calls += 1
            if recovery_calls == 1:
                raise OSError("temporary network failure")
            return [
                SimpleNamespace(
                    run_id="run-retry-once",
                    project_id=project_id,
                    intent_id="i001",
                    task_type="explore_execute",
                    attempt=1,
                    status="interrupted",
                    graph_revision=0,
                    worker_name="worker",
                )
            ]

        def report_intent_error(self, *args, **kwargs):
            reports.append(kwargs)
            return ApiResult(200, {})

    loop.client = Client()
    summary = _active_summary()
    loop._recover_orphan_runs([summary])
    assert summary.id not in loop._orphan_recovery_done
    loop._recover_orphan_runs([summary])
    loop._recover_orphan_runs([summary])

    assert recovery_calls == 2
    assert len(reports) == 1
    assert loop._orphan_recovery_done == {summary.id}


def test_orphan_recovery_is_noop_for_legacy_client_and_empty_response() -> None:
    loop = _base_loop()
    summary = _active_summary()
    loop._recover_orphan_runs([summary])
    assert loop._orphan_recovery_done == {summary.id}

    class EmptyClient(_ClaimClient):
        def recover_runs(self, _project_id: str):
            return []

    loop = _base_loop()
    loop.client = EmptyClient()
    loop._recover_orphan_runs([summary])
