from __future__ import annotations

from concurrent.futures import Future
import json

from linen.dispatcher.analysis import coverage
from linen.dispatcher.models import RunningTask
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.scheduler.worker_select import choose_worker
from linen.dispatcher.tasks.common import classify_provider_failure
from linen.server.models import AuditEvent, CompletionGate, Fact, IntentError, ProjectSummary, Review

from conftest import make_config, make_intent, make_project


def _loop() -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.runtime_project_ids = set()
    loop.cleanup_futures = {}
    loop._cleanup_pending = set()
    loop._inactive_cleanup_done = {}
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_provider_until = {}
    loop.worker_provider_reason = {}
    loop._manual_provider_retries_seen = set()
    loop._log_state = {}
    loop.project_cursor = 0
    return loop


def _summary(project_id: str, status: str) -> ProjectSummary:
    return ProjectSummary(
        id=project_id,
        title=project_id,
        status=status,
        bootstrap_enabled=True,
        created_at="2026-01-01T00:00:00Z",
        fact_count=2,
        intent_count=0,
        working_intent_count=0,
        unclaimed_intent_count=0,
        hint_count=0,
    )


def test_dispatch_reason_refuses_duplicate_local_reason_task() -> None:
    loop = _loop()
    loop.futures = {
        Future(): RunningTask(
            "proj_001", "reason", "test-worker", TaskCancellation(),
        )
    }

    assert not loop._dispatch_reason(make_project(), "graph", "initial")


def test_refresh_runtime_projects_discards_active_and_changed_cleanup_markers() -> None:
    loop = _loop()
    loop.runtime_project_ids = {"active", "stopped", "deleted"}
    loop._inactive_cleanup_done = {
        "active": "stopped",
        "stopped": "stopped",
        "changed": "completed",
        "deleted": "completed",
    }

    loop._refresh_runtime_projects(
        [
            _summary("active", "active"),
            _summary("stopped", "stopped"),
            _summary("changed", "stopped"),
        ]
    )

    assert loop.runtime_project_ids == {"active"}
    assert loop._inactive_cleanup_done == {"stopped": "stopped"}


def test_reap_cleanup_future_records_only_successful_inactive_cleanup() -> None:
    loop = _loop()
    succeeded: Future[bool] = Future()
    failed: Future[bool] = Future()
    succeeded.set_result(True)
    failed.set_result(False)
    loop.cleanup_futures = {
        succeeded: ("container-success", "proj-success", "completed"),
        failed: ("container-failed", "proj-failed", "stopped"),
    }
    loop._cleanup_pending = {"container-success", "container-failed"}
    loop._inactive_cleanup_done = {"proj-failed": "stopped"}

    loop._reap_cleanup_futures()

    assert loop.cleanup_futures == {}
    assert loop._cleanup_pending == set()
    assert loop._inactive_cleanup_done == {"proj-success": "completed"}


def test_choose_worker_prefers_lower_running_count_without_priority() -> None:
    workers = make_config().workers
    first = workers[0].model_copy(update={"name": "first", "priority": 1})
    busy = workers[0].model_copy(update={"name": "busy", "priority": 0})
    equally_loaded = workers[0].model_copy(update={"name": "equal", "priority": 9})

    ordered = choose_worker(
        [busy, equally_loaded, first],
        {"busy": 2, "first": 0, "equal": 0},
    )

    assert {worker.name for worker in ordered[:2]} == {"first", "equal"}
    assert ordered[-1].name == "busy"


def test_completion_sources_ignore_stale_generations_and_nonterminal_facts() -> None:
    project = make_project()
    project.project.audit_mode = "hypothesis"
    project.project.source_generation = 2
    project.facts.extend([
        Fact(
            id="f002", description="old", type="negative_assurance",
            semantic_type="negative_assurance", source_generation=1,
        ),
        Fact(
            id="f003", description="draft", type="negative_assurance",
            semantic_type="negative_assurance", source_generation=2, status="draft",
        ),
        Fact(
            id="f004", description="current", type="negative_assurance",
            semantic_type="negative_assurance", source_generation=2, status="triaged",
        ),
    ])

    assert DispatcherLoop._completion_sources(project) == ["f004"]


def test_cancel_inactive_tasks_marks_stopped_and_deleted_projects() -> None:
    loop = _loop()
    stopped = TaskCancellation()
    deleted = TaskCancellation()
    loop.futures = {
        Future(): RunningTask("stopped", "explore", "worker", stopped),
        Future(): RunningTask("deleted", "reason", "worker", deleted),
    }

    loop._cancel_inactive_tasks([_summary("stopped", "stopped")])

    assert stopped.reason == "stopped"
    assert deleted.reason == "deleted"


def test_select_worker_reports_busy_unhealthy_rejected_and_unsupported_workers(monkeypatch) -> None:
    loop = _loop()
    base = make_config()
    busy = base.workers[0].model_copy(update={"name": "busy", "task_types": ["reason"]})
    unhealthy = base.workers[0].model_copy(update={"name": "unhealthy", "task_types": ["reason"]})
    rejected = base.workers[0].model_copy(update={"name": "rejected", "task_types": ["reason"]})
    unsupported = base.workers[0].model_copy(update={"name": "unsupported", "task_types": ["explore"]})
    loop.config = base.model_copy(update={"workers": [busy, unhealthy, rejected, unsupported]})
    loop.futures = {Future(): RunningTask("proj", "reason", "busy", TaskCancellation())}
    loop.worker_unhealthy_until = {"unhealthy": 110.0}
    loop.worker_rejected_until = {("proj", "reason", "rejected"): 120.0}
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)

    selection = loop._select_worker("proj", "reason")

    assert selection.worker is None
    assert selection.blocked_busy == ["busy(1/1)"]
    assert selection.blocked_unhealthy == ["unhealthy(10.0s)"]
    assert selection.blocked_rejected == ["rejected(20.0s)"]
    assert selection.blocked_task_type == ["unsupported"]


def test_provider_circuit_blocks_models_but_not_deterministic_work(monkeypatch) -> None:
    loop = _loop()
    loop.config = make_config()
    loop.futures = {}
    loop.worker_provider_until = {"test-worker": 3700.0}
    loop.worker_provider_reason = {"test-worker": "quota_exhausted"}
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)

    model_selection = loop._select_worker("proj", "explore")
    scanner_selection = loop._select_worker("proj", "explore", provider_required=False)

    assert model_selection.worker is None
    assert model_selection.blocked_unhealthy == [
        "test-worker(provider:quota_exhausted)"
    ]
    assert scanner_selection.worker is not None
    assert scanner_selection.worker.name == "test-worker"


def test_reap_quota_failure_opens_provider_circuit(monkeypatch) -> None:
    loop = _loop()
    loop.config = make_config()
    done: Future[str] = Future()
    done.set_result("quota_exhausted")
    loop.futures = {
        done: RunningTask("proj", "explore", "test-worker", TaskCancellation())
    }
    loop.runtime_project_ids = {"proj"}
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)

    loop._reap_futures()

    assert loop.worker_provider_until == {"test-worker": 3700.0}
    assert loop.worker_provider_reason == {"test-worker": "quota_exhausted"}


def test_provider_circuit_persists_across_dispatcher_restart(tmp_path, monkeypatch) -> None:
    config = make_config()
    config = config.model_copy(
        update={
            "local": config.local.model_copy(
                update={"workspace_root": str(tmp_path)}
            )
        }
    )
    monkeypatch.setattr("linen.dispatcher.scheduler.loop.time.time", lambda: 100.0)
    loop = _loop()
    loop.config = config
    loop.worker_provider_until = {"test-worker": 3700.0}
    loop.worker_provider_reason = {"test-worker": "quota_exhausted"}

    loop._persist_provider_circuits()

    restored = DispatcherLoop.__new__(DispatcherLoop)
    restored.config = config
    restored.worker_provider_until = {}
    restored.worker_provider_reason = {}
    restored._restore_provider_circuits()
    assert restored.worker_provider_until == {"test-worker": 3700.0}
    assert restored.worker_provider_reason == {"test-worker": "quota_exhausted"}


def test_manual_retry_clears_one_persisted_provider_cooldown() -> None:
    loop = _loop()
    loop.config = make_config()
    loop.worker_provider_until = {"test-worker": 3700.0}
    loop.worker_provider_reason = {"test-worker": "quota_exhausted"}
    loop._persist_provider_circuits = lambda: None
    project = make_project()
    project.errors.append(IntentError(
        id="e001",
        intent_id="i001",
        task_type="explore",
        worker="test-worker",
        code="provider_quota_exhausted",
        classification="transient",
        message="quota exhausted",
        first_failed_at="1970-01-01T00:01:40Z",
        last_failed_at="1970-01-01T00:01:40Z",
        resolved_at="1970-01-01T00:03:20Z",
        resolution="manual retry requested by Human",
    ))

    loop._honor_manual_provider_retries(project)
    loop._honor_manual_provider_retries(project)

    assert loop.worker_provider_until == {}
    assert loop.worker_provider_reason == {}
    assert loop._manual_provider_retries_seen == {"e001"}


def test_reason_waits_for_runnable_or_claimed_work_but_can_resolve_blocked_work() -> None:
    loop = _loop()
    intent = make_intent()
    intent.worker = None
    project = make_project(intents=[intent])

    assert not loop._reason_may_run(project)
    intent.worker = "test-worker"
    assert not loop._reason_may_run(project)
    intent.worker = None
    project.errors.append(IntentError(
        id="e001",
        intent_id=intent.id,
        task_type="explore",
        worker="test-worker",
        code="proof_contract_mismatch",
        classification="blocked",
        message="wrong proof type",
        first_failed_at="2026-01-01T00:00:00Z",
        last_failed_at="2026-01-01T00:00:00Z",
    ))
    assert loop._reason_may_run(project)


def test_new_fact_event_wakes_reason_while_other_intents_remain_open_once() -> None:
    loop = _loop()
    project = make_project(intents=[make_intent("i001")])
    project.project.event_seq = 9
    project.project.reason_last_seen_event_seq = 8
    fact_event = AuditEvent(
        sequence=9,
        event_type="audit_task_concluded",
        actor="local-pi",
        entity_kind="intent",
        entity_id="i002",
        payload={"fact_id": "f003"},
        created_at="2026-01-01T00:00:00Z",
    )

    assert loop._reason_trigger(project) == "events:8->9"
    assert loop._reason_may_run(project, [fact_event])

    project.project.reason_last_seen_event_seq = 9
    assert loop._reason_trigger(project) is None
    assert not loop._reason_may_run(project, [])


def test_reason_does_not_wake_for_its_own_new_open_intent_event() -> None:
    loop = _loop()
    project = make_project(intents=[make_intent("i001")])
    event = AuditEvent(
        sequence=4,
        event_type="audit_task_created",
        actor="local-pi",
        entity_kind="intent",
        entity_id="i002",
        payload={"from": ["f001"]},
        created_at="2026-01-01T00:00:00Z",
    )
    assert not loop._reason_may_run(project, [event])


def test_coverage_plan_is_model_free_explore_work() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={"enabled": True})}
    )
    project = make_project()
    project.project.audit_mode = "scope"
    intent = make_intent()
    intent.type = "search"
    intent.description = coverage.PLAN_INTENT

    assert not loop._explore_requires_provider(project, intent)


def test_scope_evidence_is_model_free_explore_work() -> None:
    from linen.dispatcher.analysis import scope_gate
    from linen.dispatcher.config import ScopeAdjudicationConfig

    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={
            "enabled": True,
            "scope_adjudication": ScopeAdjudicationConfig(enabled=True),
        })}
    )
    project = make_project()
    project.project.audit_mode = "scope"
    intent = make_intent()
    intent.creator = "dispatcher.audit"
    intent.type = "search"
    intent.description = scope_gate.EVIDENCE_INTENT

    assert not loop._explore_requires_provider(project, intent)


def test_intent_error_gate_blocks_permanent_and_future_retry() -> None:
    loop = _loop()
    project = make_project(intents=[make_intent()])
    intent = project.intents[0]
    intent.worker = None
    project.errors = [
        IntentError(
            id="e001",
            intent_id=intent.id,
            task_type="explore",
            worker="test-worker",
            code="source_repository_missing",
            classification="blocked",
            message="missing source",
            first_failed_at="2026-01-01T00:00:00Z",
            last_failed_at="2026-01-01T00:00:00Z",
        )
    ]
    assert not loop._intent_error_allows_dispatch(project, intent)

    project.errors[0].classification = "transient"
    project.errors[0].retry_at = "2099-01-01T00:00:00Z"
    assert not loop._intent_error_allows_dispatch(project, intent)

    project.errors[0].retry_at = "2020-01-01T00:00:00Z"
    assert loop._intent_error_allows_dispatch(project, intent)


def test_pending_scope_gate_withholds_existing_technical_work() -> None:
    from linen.dispatcher.analysis import scope_gate
    from linen.dispatcher.config import ScopeAdjudicationConfig

    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={
            "enabled": True,
            "scope_adjudication": ScopeAdjudicationConfig(enabled=True),
        })}
    )
    project = make_project()
    project.project.audit_mode = "scope"
    technical = make_intent("i-technical")
    technical.worker = None
    gate = make_intent("i-gate")
    gate.worker = None
    gate.creator = "dispatcher.audit"
    gate.type = "search"
    gate.description = scope_gate.EVIDENCE_INTENT

    assert loop._scope_gate_pending(project)
    assert not loop._scope_gate_intent_allowed(project, technical)
    assert loop._scope_gate_intent_allowed(project, gate)


def test_provider_blocked_review_falls_through_to_model_free_explore() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={"enabled": True})}
    )
    loop.futures = {}
    project = make_project()
    project.project.audit_mode = "scope"
    review_intent = make_intent("i-review")
    review_intent.worker = None
    review_intent.type = "review:devils-advocate"
    review_intent.creator = "dispatcher.audit"
    scan_intent = make_intent("i-scan")
    scan_intent.worker = None
    scan_intent.type = "search"
    scan_intent.description = coverage.PLAN_INTENT
    scan_intent.creator = "dispatcher.audit"
    project.intents = [review_intent, scan_intent]
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()
    loop.client = type(
        "Client",
        (),
        {
            "get_project": lambda _self, _project_id: project,
            "export_project": lambda _self, _project_id: "graph",
        },
    )()
    loop._materialize_audit_intents = lambda _project: False
    loop._dispatch_review = lambda *_args: False
    dispatched: list[str] = []
    loop._dispatch_explore = lambda _project, _graph, intent: dispatched.append(intent.id) or True

    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert dispatched == ["i-scan"]


def test_ordinary_investigation_competes_with_managed_coverage_cell() -> None:
    loop = _loop()
    loop.config = make_config()
    loop.futures = {}
    project = make_project()
    managed = make_intent("i-managed")
    managed.worker = None
    managed.type = "verify"
    managed.creator = "dispatcher.audit"
    managed.description = f"{coverage.CELL_PREFIX}cell-1"
    managed.created_at = "2026-01-01T00:00:03Z"
    ordinary = make_intent("i-investigation")
    ordinary.worker = None
    ordinary.type = "search"
    ordinary.description = "search sibling endpoint"
    ordinary.created_at = "2026-01-01T00:00:02Z"
    project.intents = [managed, ordinary]
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()
    loop.client = type(
        "Client",
        (),
        {
            "get_project": lambda _self, _project_id: project,
            "export_project": lambda _self, _project_id: "graph",
        },
    )()
    loop._materialize_audit_intents = lambda _project: False
    dispatched: list[str] = []
    loop._dispatch_explore = lambda _project, _graph, intent: dispatched.append(intent.id) or True

    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert dispatched == ["i-investigation"]


def test_goal_based_completion_precedes_unrelated_explore_when_gate_ready() -> None:
    loop = _loop()
    loop.config = make_config()
    loop.futures = {}
    project = make_project(intents=[make_intent("i-optional")])
    project.project.audit_mode = "hypothesis"
    project.project.reason_last_seen_event_seq = 5
    project.project.event_seq = 5
    terminal = Fact(
        id="f-terminal", description="reviewed negative assurance",
        type="negative_assurance", semantic_type="negative_assurance",
        status="triaged", source_generation=1,
    )
    project.facts.append(terminal)
    project.intents[0].worker = None
    gate = CompletionGate(
        project_id=project.project.id, lifecycle_status="active", execution_status="idle",
        audit_mode="hypothesis", source_generation=1, plan_revision=1,
        ready=True, checks=[], blockers=[],
    )
    completed: list[list[str]] = []
    explored: list[str] = []
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()

    class Client:
        def get_project(self, _project_id):
            return project

        def get_completion_gate(self, _project_id):
            return gate

        def export_project(self, _project_id):
            return "graph"

        def complete(self, _project_id, sources, _description, _worker):
            completed.append(sources)
            return ApiResult(200, {})

    loop.client = Client()
    loop._materialize_audit_intents = lambda _project: False
    loop._reconcile_audit_stages = lambda _project: False
    loop._dispatch_explore = lambda _project, _graph, intent: explored.append(intent.id) or True
    loop._dispatch_review = lambda *_args: False

    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert completed == [["f-terminal"]]
    assert explored == []


def test_fresh_reason_event_precedes_ready_goal_based_completion() -> None:
    loop = _loop()
    loop.config = make_config()
    loop.futures = {}
    project = make_project(intents=[make_intent("i-optional")])
    project.project.audit_mode = "hypothesis"
    project.project.reason_last_seen_event_seq = 8
    project.project.event_seq = 9
    project.intents[0].worker = None
    project.facts.append(Fact(
        id="f-terminal", description="reviewed negative assurance",
        type="negative_assurance", semantic_type="negative_assurance",
        status="triaged", source_generation=1,
    ))
    event = AuditEvent(
        sequence=9, event_type="audit_task_concluded", actor="worker",
        entity_kind="intent", entity_id="i-source", payload={"fact_id": "f004"},
        created_at="2026-01-01T00:00:00Z",
    )
    gate = CompletionGate(
        project_id=project.project.id, lifecycle_status="active", execution_status="idle",
        audit_mode="hypothesis", source_generation=1, plan_revision=1,
        ready=True, checks=[], blockers=[],
    )
    completed: list[list[str]] = []
    reason_triggers: list[str] = []
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()

    class Client:
        def get_project(self, _project_id):
            return project

        def get_audit_events(self, _project_id, *, after, limit):
            return [item for item in [event] if item.sequence > after][:limit]

        def get_completion_gate(self, _project_id):
            return gate

        def export_project(self, _project_id):
            return "graph"

        def complete(self, _project_id, sources, _description, _worker):
            completed.append(sources)
            return ApiResult(200, {})

    loop.client = Client()
    loop._materialize_audit_intents = lambda _project: False
    loop._reconcile_audit_stages = lambda _project: False
    loop._dispatch_reason = lambda _project, _graph, trigger, _events: reason_triggers.append(trigger) or True
    loop._dispatch_explore = lambda *_args: False
    loop._dispatch_review = lambda *_args: False

    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert reason_triggers == ["events:8->9"]
    assert completed == []

    project.project.reason_last_seen_event_seq = 9
    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert completed == [["f-terminal"]]


def test_provider_failure_classifier_reads_only_explicit_error_fields() -> None:
    quota_event = {
        "type": "message_end",
        "message": {
            "stopReason": "error",
            "errorMessage": (
                '429 {"error":{"type":"rate_limit_error",'
                '"message":"已达到 Token Plan 用量上限"}}'
            ),
        },
    }
    assert classify_provider_failure(
        ProcessResult(0, json.dumps(quota_event, ensure_ascii=False), "")
    ) == "quota_exhausted"
    assert classify_provider_failure(
        ProcessResult(1, "", "HTTP 429 Too Many Requests")
    ) == "rate_limited"
    assert classify_provider_failure(
        ProcessResult(
            1,
            "API Error: Request rejected (429) · 已达到 Token Plan 用量上限：请购买积分补充用量。",
            '[claude-code:unrecognized_model] {"model":"example"}',
        )
    ) == "quota_exhausted"

    prompt_echo = {"type": "message", "content": "Investigate a 429 rate limit bug"}
    assert classify_provider_failure(
        ProcessResult(0, json.dumps(prompt_echo), "")
    ) is None
    assert classify_provider_failure(
        ProcessResult(1, "The target prints: API Error: 429", "unrelated failure")
    ) is None


def test_disabled_worker_healthcheck_skips_automatic_startup_but_force_runs_diagnostic() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"runtime": config.runtime.model_copy(update={"worker_healthcheck": "disabled"})}
    )
    calls: list[bool] = []
    loop._run_startup_healthchecks = lambda *, show_commands: calls.append(show_commands)
    loop._startup_healthchecks_checked = False

    loop.run_startup_healthchecks()

    assert calls == []
    assert loop._startup_healthchecks_checked

    loop._startup_healthchecks_checked = False
    loop.run_startup_healthchecks(show_commands=True, force=True)

    assert calls == [True]


def test_startup_only_worker_healthcheck_runs_automatic_startup_check() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"runtime": config.runtime.model_copy(update={"worker_healthcheck": "startup_only"})}
    )
    calls: list[bool] = []
    loop._run_startup_healthchecks = lambda *, show_commands: calls.append(show_commands)
    loop._startup_healthchecks_checked = False

    loop.run_startup_healthchecks()

    assert calls == [False]


def test_reap_futures_removes_project_from_runtime_when_no_tasks_remain() -> None:
    """Regression: when a project's last running task is reaped, the project
    must be removed from `runtime_project_ids`. Otherwise the project holds
    a slot under `max_running_projects` forever (until status changes), and
    idle-project dispatch is blocked from picking up other projects.
    """
    loop = _loop()
    success: Future[str] = Future()
    success.set_result("success")
    loop.futures = {success: RunningTask("proj_X", "reason", "worker", TaskCancellation())}
    loop.runtime_project_ids = {"proj_X"}

    loop._reap_futures()

    assert loop.futures == {}
    assert "proj_X" not in loop.runtime_project_ids


def test_reap_failed_intent_persists_transient_error() -> None:
    loop = _loop()
    loop.config = make_config()
    recorded: list[dict] = []

    class Client:
        def report_intent_error(self, project_id, intent_id, worker, **payload):
            recorded.append({
                "project_id": project_id,
                "intent_id": intent_id,
                "worker": worker,
                **payload,
            })
            from linen.dispatcher.protocol.client import ApiResult
            return ApiResult(200, {})

    loop.client = Client()
    done: Future[str] = Future()
    done.set_result("failed")
    loop.futures = {
        done: RunningTask(
            "proj_X", "explore", "worker", TaskCancellation(), intent_id="i007",
        )
    }
    loop.runtime_project_ids = {"proj_X"}

    loop._reap_futures()

    assert len(recorded) == 1
    assert recorded[0]["intent_id"] == "i007"
    assert recorded[0]["classification"] == "transient"
    assert recorded[0]["code"] == "task_failed"


def test_reap_futures_keeps_project_in_runtime_when_other_tasks_still_running() -> None:
    """Counter-test: do NOT remove a project that still has another running
    task. Otherwise `max_project_workers` accounting breaks.
    """
    loop = _loop()
    running: Future[str] = Future()  # never finishes
    done: Future[str] = Future()
    done.set_result("success")
    loop.futures = {
        running: RunningTask("proj_X", "reason", "worker", TaskCancellation()),
        done: RunningTask("proj_X", "explore", "worker", TaskCancellation()),
    }
    loop.runtime_project_ids = {"proj_X"}

    loop._reap_futures()

    assert len(loop.futures) == 1
    assert "proj_X" in loop.runtime_project_ids


def test_idle_dispatch_unblocks_after_running_project_finishes() -> None:
    """Integration regression: the invariant that gates idle dispatch is
    `_running_project_count(active) < max_running_projects`. With
    `max_running_projects=1` and a still-active project whose only task has
    been reaped, the count must drop to 0 — otherwise the slot is held
    forever. This test verifies the post-reap state, which is exactly
    what `_dispatch_available` checks at its `idle-limit` gate.
    """
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"runtime": config.runtime.model_copy(update={"max_running_projects": 1})}
    )
    # proj_X had a task that just finished.
    done: Future[str] = Future()
    done.set_result("success")
    loop.futures = {done: RunningTask("proj_X", "reason", "worker", TaskCancellation())}
    loop.runtime_project_ids = {"proj_X"}

    summaries = [_summary("proj_X", "active"), _summary("proj_Y", "active")]

    # Before reap: slot is held → idle dispatch would be blocked.
    assert loop._running_project_count(summaries) == 1

    loop._reap_futures()

    # After reap: slot is free → idle dispatch can pick up proj_Y.
    assert loop._running_project_count(summaries) == 0
    assert loop.futures == {}
