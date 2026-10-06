from __future__ import annotations

from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
import json
import pytest
from types import SimpleNamespace
import time

from linen.dispatcher.analysis import coverage, recon
from linen.dispatcher.models import RunningTask
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.cancellation import CANCELLATION_CLEANUP_GRACE_SECONDS
from linen.dispatcher.runtime.process import LocalProcess, ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.scheduler.worker_select import choose_worker
from linen.dispatcher.tasks.common import classify_provider_failure
from linen.server.models import (
    AuditEvent,
    CompletionGate,
    Fact,
    Intent,
    IntentError,
    ProjectSummary,
    Review,
)

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
    loop.worker_provider_opened_at = {}
    loop.worker_provider_origin = {}
    loop._manual_provider_retries_seen = set()
    loop._log_state = {}
    loop.project_cursor = 0
    # Scheduling tests isolate preflight; its real behavior is checked below.
    loop._source_audit_preflight = lambda _project: True
    loop._audit_project_budget_state = lambda _project: None
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


def test_choose_worker_orders_by_priority_then_live_load() -> None:
    workers = make_config().workers
    preferred = workers[0].model_copy(update={"name": "preferred", "priority": 9})
    busy_preferred = workers[0].model_copy(update={"name": "busy-preferred", "priority": 9})
    default = workers[0].model_copy(update={"name": "default", "priority": 0})

    ordered = choose_worker(
        [default, busy_preferred, preferred],
        {"preferred": 0, "busy-preferred": 3, "default": 0},
    )

    # The preferred worker wins even though an equal-load default exists.
    assert ordered[0].name == "preferred"
    # A busy preferred worker still outranks an idle lower-priority one.
    assert ordered[1].name == "busy-preferred"
    assert ordered[-1].name == "default"


def test_choose_worker_breaks_priority_ties_on_live_load() -> None:
    workers = make_config().workers
    idle = workers[0].model_copy(update={"name": "idle", "priority": 1})
    busy = workers[0].model_copy(update={"name": "busy", "priority": 1})

    ordered = choose_worker([busy, idle], {"idle": 0, "busy": 4})

    assert ordered[0].name == "idle"


def test_choose_worker_treats_unset_priority_as_zero() -> None:
    workers = make_config().workers
    unset = workers[0].model_copy(update={"name": "unset", "priority": None})
    explicit = workers[0].model_copy(update={"name": "explicit", "priority": 1})

    ordered = choose_worker([unset, explicit], {"unset": 0, "explicit": 0})

    assert ordered[0].name == "explicit"


def _codex_worker(**overrides):
    worker = make_config().workers[0]
    return worker.model_copy(update={"name": "cx", "type": "codex", **overrides})


def test_codex_audit_worker_defaults_to_read_only() -> None:
    project = make_project()
    project.project.audit_mode = "scope"

    worker = DispatcherLoop._codex_audit_sandbox(_codex_worker(sandbox_mode=None), project)

    assert worker is not None
    assert worker.sandbox_mode == "read-only"


def test_codex_audit_worker_honors_explicit_sandbox_mode() -> None:
    project = make_project()
    project.project.audit_mode = "scope"

    worker = DispatcherLoop._codex_audit_sandbox(
        _codex_worker(sandbox_mode="danger-full-access"), project
    )

    # An explicit operator choice must survive: the OS sandbox may be
    # unavailable, and a silent downgrade would strand the worker.
    assert worker is not None
    assert worker.sandbox_mode == "danger-full-access"


def test_codex_audit_worker_leaves_non_codex_and_non_audit_projects_alone() -> None:
    claude = make_config().workers[0].model_copy(
        update={"name": "cl", "type": "claudecode", "sandbox_mode": None}
    )
    audit_project = make_project()
    audit_project.project.audit_mode = "scope"
    assert DispatcherLoop._codex_audit_sandbox(claude, audit_project).sandbox_mode is None

    non_audit = make_project()
    non_audit.project.audit_mode = "none"
    worker = DispatcherLoop._codex_audit_sandbox(_codex_worker(sandbox_mode=None), non_audit)
    assert worker.sandbox_mode is None


def test_codex_audit_worker_exempts_poc_isolated_intents() -> None:
    project = make_project()
    project.project.audit_mode = "scope"
    intent = make_intent().model_copy(update={"type": "poc:isolated"})

    worker = DispatcherLoop._codex_audit_sandbox(_codex_worker(sandbox_mode=None), project, intent)

    assert worker is not None
    assert worker.sandbox_mode is None


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
    loop.worker_provider_opened_at = {"test-worker": 100.0}
    loop.worker_provider_origin = {"test-worker": ("proj_001", 12)}

    loop._persist_provider_circuits()

    restored = DispatcherLoop.__new__(DispatcherLoop)
    restored.config = config
    restored.worker_provider_until = {}
    restored.worker_provider_reason = {}
    restored._restore_provider_circuits()
    assert restored.worker_provider_until == {"test-worker": 3700.0}
    assert restored.worker_provider_reason == {"test-worker": "quota_exhausted"}
    assert restored.worker_provider_origin == {"test-worker": ("proj_001", 12)}


def test_manual_retry_clears_one_persisted_provider_cooldown() -> None:
    loop = _loop()
    loop.config = make_config()
    loop.worker_provider_until = {"test-worker": 3700.0}
    loop.worker_provider_reason = {"test-worker": "quota_exhausted"}
    loop.worker_provider_origin = {"test-worker": ("proj_001", 7)}
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
    assert loop.worker_provider_origin == {}
    assert loop._manual_provider_retries_seen == {"e001"}


def test_project_worker_issue_resume_clears_only_newer_worker_circuits() -> None:
    loop = _loop()
    now = time.time()
    project = make_project()
    project.project.event_seq = 2
    loop.worker_provider_until = {
        "quota-cli": now + 3600,
        "still-blocked-cli": now + 3600,
    }
    loop.worker_provider_reason = {
        "quota-cli": "quota_exhausted",
        "still-blocked-cli": "quota_exhausted",
    }
    loop.worker_provider_opened_at = {
        "quota-cli": now - 30,
        "still-blocked-cli": now - 5,
    }
    resume_after_open = datetime.fromtimestamp(now - 10, UTC).isoformat().replace("+00:00", "Z")
    resume_before_open = datetime.fromtimestamp(now - 10, UTC).isoformat().replace("+00:00", "Z")
    loop.client = SimpleNamespace(get_audit_events=lambda *_args, **_kwargs: [
        AuditEvent(
            sequence=1,
            event_type="project_worker_issue_resumed",
            actor="Human",
            entity_kind="project",
            entity_id=project.project.id,
            payload={"worker_issues": [{"worker": "quota-cli", "code": "provider_quota_exhausted"}]},
            created_at=resume_after_open,
        ),
        AuditEvent(
            sequence=2,
            event_type="project_worker_issue_resumed",
            actor="Human",
            entity_kind="project",
            entity_id=project.project.id,
            payload={"worker_issues": [{"worker": "still-blocked-cli", "code": "provider_quota_exhausted"}]},
            created_at=resume_before_open,
        ),
    ])
    persisted = []
    loop._persist_provider_circuits = lambda: persisted.append(True)

    loop._honor_project_worker_issue_resumes(project)

    assert loop.worker_provider_until == {"still-blocked-cli": now + 3600}
    assert loop.worker_provider_reason == {"still-blocked-cli": "quota_exhausted"}
    assert loop.worker_provider_opened_at == {"still-blocked-cli": now - 5}
    assert loop.worker_provider_origin == {}
    assert persisted == [True]


def test_resume_after_block_clears_same_second_provider_circuit() -> None:
    loop = _loop()
    project = make_project()
    project.project.event_seq = 21
    loop.worker_provider_until = {"quota-cli": 5000.0}
    loop.worker_provider_reason = {"quota-cli": "quota_exhausted"}
    loop.worker_provider_opened_at = {"quota-cli": 100.75}
    loop.worker_provider_origin = {"quota-cli": (project.project.id, 20)}
    loop._persist_provider_circuits = lambda: None
    loop.client = SimpleNamespace(get_audit_events=lambda *_args, **_kwargs: [
        AuditEvent(
            sequence=21,
            event_type="project_worker_issue_resumed",
            actor="Human",
            entity_kind="project",
            entity_id=project.project.id,
            payload={"worker_issues": [{"worker": "quota-cli", "code": "provider_quota_exhausted"}]},
            # Server utcnow() stores second precision; this timestamp is less
            # than opened_at even though the resume event follows the block.
            created_at="1970-01-01T00:01:40Z",
        ),
    ])

    loop._honor_project_worker_issue_resumes(project)

    assert loop.worker_provider_until == {}
    assert loop.worker_provider_reason == {}
    assert loop.worker_provider_opened_at == {}
    assert loop.worker_provider_origin == {}


def test_resume_before_block_event_does_not_clear_provider_circuit() -> None:
    loop = _loop()
    project = make_project()
    project.project.event_seq = 19
    loop.worker_provider_until = {"quota-cli": 5000.0}
    loop.worker_provider_reason = {"quota-cli": "quota_exhausted"}
    loop.worker_provider_opened_at = {"quota-cli": 100.0}
    loop.worker_provider_origin = {"quota-cli": (project.project.id, 20)}
    loop.client = SimpleNamespace(get_audit_events=lambda *_args, **_kwargs: [
        AuditEvent(
            sequence=19,
            event_type="project_worker_issue_resumed",
            actor="Human",
            entity_kind="project",
            entity_id=project.project.id,
            payload={"worker_issues": [{"worker": "quota-cli", "code": "provider_quota_exhausted"}]},
            created_at="1970-01-01T00:01:41Z",
        ),
    ])

    loop._honor_project_worker_issue_resumes(project)

    assert loop.worker_provider_until == {"quota-cli": 5000.0}
    assert loop.worker_provider_origin == {"quota-cli": (project.project.id, 20)}


def test_quota_issue_response_persists_provider_circuit_origin() -> None:
    loop = _loop()
    loop.worker_provider_until = {"quota-cli": 5000.0}
    loop.worker_provider_reason = {"quota-cli": "quota_exhausted"}
    loop.client = SimpleNamespace(
        report_project_worker_issue=lambda *_args: ApiResult(
            status_code=200, data={"event_seq": 27},
        ),
    )
    loop._persist_provider_circuits = lambda: None
    task = RunningTask(
        "proj_001", "explore", "quota-cli", TaskCancellation(),
        intent_id="i001",
    )

    loop._pause_project_for_cli_issue(task, "quota_exhausted")

    assert loop.worker_provider_origin == {"quota-cli": ("proj_001", 27)}


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
    project.facts.append(Fact(id="f003", description="new trace", type="dataflow"))
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


def test_recon_snapshot_is_model_free_explore_work() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={"enabled": True, "recon": config.audit.recon.model_copy(update={"enabled": True})})}
    )
    project = make_project()
    project.project.audit_mode = "scope"
    intent = make_intent()
    intent.type = "search"
    intent.description = recon.SNAPSHOT_INTENT

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


def test_pending_scope_gate_preserves_model_free_evidence_collection() -> None:
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
    assert loop._explore_requires_provider(project, technical)
    assert not loop._explore_requires_provider(project, gate)


def test_provider_blocked_review_falls_through_to_model_free_explore() -> None:
    loop = _loop()
    config = make_config()
    loop.config = config.model_copy(
        update={"audit": config.audit.model_copy(update={"enabled": True, "recon": config.audit.recon.model_copy(update={"enabled": True})})}
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
    scan_intent.description = recon.SNAPSHOT_INTENT
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
        entity_kind="intent", entity_id="i-source", payload={"fact_id": "f-terminal"},
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


@pytest.mark.parametrize(
    ("policy", "ready", "open_intent", "claimed_reason", "expected"),
    [
        ("goal_based", True, False, False, True),
        ("goal_based", True, True, False, True),
        ("exhaustive", True, False, False, True),
        ("exhaustive", True, True, False, False),
        ("goal_based", False, False, False, False),
        ("goal_based", True, False, True, False),
    ],
)
def test_exhausted_budget_allows_only_gate_ready_completion(
    policy: str,
    ready: bool,
    open_intent: bool,
    claimed_reason: bool,
    expected: bool,
) -> None:
    loop = _loop()
    loop.config = SimpleNamespace(
        runtime=SimpleNamespace(max_project_workers=2),
        audit=SimpleNamespace(max_runs_per_project=250, wall_clock_budget_seconds=43200),
    )
    loop.futures = {}
    project = make_project(
        intents=[make_intent("i-optional")] if open_intent else [],
    )
    project.project.audit_mode = "hypothesis"
    project.project.completion_policy = policy
    if claimed_reason:
        project.project.reason = object()
    project.facts.append(Fact(
        id="f-terminal", description="reviewed negative assurance",
        type="negative_assurance", semantic_type="negative_assurance",
        status="triaged", source_generation=1,
    ))
    gate = CompletionGate(
        project_id=project.project.id, lifecycle_status="active", execution_status="idle",
        audit_mode="hypothesis", source_generation=1, plan_revision=1,
        ready=ready, checks=[], blockers=[] if ready else ["evidence missing"],
    )
    completed: list[list[str]] = []
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()

    class Client:
        def get_project(self, _project_id):
            return project

        def get_completion_gate(self, _project_id):
            return gate

        def complete(self, _project_id, sources, _description, _worker):
            completed.append(sources)
            return ApiResult(200, {})

    loop.client = Client()
    loop._audit_project_budget_state = lambda _project: (
        "audit_run_budget_exhausted", "run budget exhausted", "2026-01-01T00:00:00Z",
    )
    loop._append_runtime_health_event = lambda *_args, **_kwargs: None

    assert loop._try_dispatch_project(_summary("proj_001", "active")) is expected
    assert bool(completed) is expected


def test_unavailable_budget_state_stays_blocked_without_completion_check() -> None:
    loop = _loop()
    loop.config = SimpleNamespace(
        runtime=SimpleNamespace(max_project_workers=2),
        audit=SimpleNamespace(max_runs_per_project=250, wall_clock_budget_seconds=43200),
    )
    loop.futures = {}
    project = make_project()
    project.project.audit_mode = "hypothesis"
    loop.container_manager = type(
        "Containers", (), {"container_name": lambda _self, project_id: project_id}
    )()

    class Client:
        def get_project(self, _project_id):
            return project

        def get_completion_gate(self, _project_id):
            raise AssertionError("gate must not run when persisted budget state is unavailable")

    loop.client = Client()
    loop._audit_project_budget_state = lambda _project: "unavailable"
    assert not loop._try_dispatch_project(_summary("proj_001", "active"))


def test_wall_clock_budget_cancels_project_tasks_and_reaps_them(tmp_path) -> None:
    project = make_project()
    project.project.audit_mode = "scope"
    started_at = (datetime.now(UTC) - timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
    runs = [SimpleNamespace(run_id="run-1", started_at=started_at)]
    recorded: list[tuple[str, str, str]] = []

    class Client:
        def get_project(self, _project_id):
            return project

        def list_runs(self, _project_id):
            return runs

    loop = _loop()
    loop.config = SimpleNamespace(
        audit=SimpleNamespace(max_runs_per_project=100, wall_clock_budget_seconds=1),
    )
    loop._audit_project_budget_state = DispatcherLoop._audit_project_budget_state.__get__(loop)
    loop.client = Client()
    loop.futures = {}
    loop._audit_deadlines = {}
    loop._append_runtime_health_event = lambda _p, event, code, _payload: recorded.append((event, code, _p.project.id))
    loop._log_changed = lambda *_args, **_kwargs: None
    loop._clear_project_log_state = lambda *_args: None
    loop.worker_provider_until = {}
    loop.worker_provider_reason = {}
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.runtime_project_ids = {project.project.id}

    process = LocalProcess(
        ["python3", "-c", "import time; time.sleep(30)"],
        cwd=str(tmp_path),
        env={},
        timeout_seconds=30,
        term_grace_seconds=1,
    )
    process.start()
    cancellation = TaskCancellation()
    cancellation.attach_process(process)
    task = RunningTask(project.project.id, "explore", "worker", cancellation, intent_id="i001")
    loop.futures = {Future(): task}

    loop._enforce_running_audit_budgets([_summary(project.project.id, "active")])
    started = time.monotonic()
    result = process.communicate(timeout=CANCELLATION_CLEANUP_GRACE_SECONDS)
    assert result.cancelled
    assert result.cancel_reason == "audit_wall_clock_budget_exhausted"
    assert time.monotonic() - started < CANCELLATION_CLEANUP_GRACE_SECONDS
    assert recorded == [(
        "audit_budget_blocked", "audit_wall_clock_budget_exhausted", project.project.id,
    )]

    future = Future()
    future.set_result("cancelled")
    loop.futures = {future: task}
    loop._reap_futures()
    assert loop.futures == {}
    cancellation.close()


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

    # Claude Code can wrap the same provider rejection in its JSON result
    # envelope instead of printing an API Error line. Only inspect the result
    # text when the CLI marks that envelope as an error.
    structured_cli_error = {
        "type": "result",
        "is_error": True,
        "api_error_status": 429,
        "terminal_reason": "api_error",
        "result": (
            "API Error: Request rejected (429) · 已达到 Token Plan 用量上限："
            "请升级 Token Plan 套餐或购买积分补充用量。 (2056)"
        ),
    }
    assert classify_provider_failure(
        ProcessResult(1, json.dumps(structured_cli_error, ensure_ascii=False), "")
    ) == "quota_exhausted"
    structured_success = {
        "type": "result",
        "is_error": False,
        "result": "The source mentions a Token Plan usage limit as audit data.",
    }
    assert classify_provider_failure(
        ProcessResult(0, json.dumps(structured_success), "")
    ) is None

    prompt_echo = {"type": "message", "content": "Investigate a 429 rate limit bug"}
    assert classify_provider_failure(
        ProcessResult(0, json.dumps(prompt_echo), "")
    ) is None
    assert classify_provider_failure(
        ProcessResult(1, "The target prints: API Error: 429", "unrelated failure")
    ) is None


def test_killed_run_cannot_claim_a_cli_configuration_failure() -> None:
    # Claude Code prints its model-catalog notice as a bracketed SDK
    # diagnostic. The same banner accompanies successful runs, so on its own
    # it is not evidence of a terminal provider rejection.
    banner = '[claude-code:unrecognized_model] {"model":"MiniMax-M3","query_source":"sdk"}'
    assert classify_provider_failure(
        ProcessResult(1, "", f"auto mode notice\n{banner}")
    ) is None

    # A timed-out or signal-killed process leaves only partial diagnostics and
    # must never pause the project for a configuration-class outcome, even when
    # those fragments contain a configuration marker.
    assert classify_provider_failure(
        ProcessResult(143, "", f"unsupported model\n{banner}", timed_out=True)
    ) is None
    assert classify_provider_failure(
        ProcessResult(137, "", "unrecognized_model: model not in catalog")
    ) is None

    # A genuine terminal rejection from a process that exited on its own still
    # classifies.
    assert classify_provider_failure(
        ProcessResult(1, "", "unrecognized_model: MiniMax-M3 is not known to this build")
    ) == "cli_model_unrecognized"

    # Transient provider pressure still surfaces even for a killed process.
    assert classify_provider_failure(
        ProcessResult(143, "", "HTTP 429 Too Many Requests", timed_out=True)
    ) == "rate_limited"


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


@pytest.mark.parametrize('source_state', ['valid', 'missing_link', 'empty', 'wrong_link'])
def test_source_preflight_checks_worker_visible_repository_before_models(tmp_path, source_state) -> None:
    loop = _loop()
    loop.config = make_config()
    loop.config.audit.enabled = True
    project = make_project()
    project.project.audit_mode = 'scope'
    repo = tmp_path / 'target'
    repo.mkdir()
    (repo / 'app.py').write_text('' if source_state == 'empty' else 'value = 1\n')
    project.project.repo_root = str(repo)
    work = tmp_path / 'work'
    work.mkdir()
    if source_state != 'missing_link':
        linked = repo
        if source_state == 'wrong_link':
            linked = tmp_path / 'unrelated'
            linked.mkdir()
        (work / 'repo').symlink_to(linked, target_is_directory=True)
    loop.container_manager = SimpleNamespace(ensure_running=lambda _pid: str(work))
    issues = []
    loop.client = SimpleNamespace(report_project_worker_issue=lambda *a, **kw: issues.append(kw) or ApiResult(200, {}))
    accepted = DispatcherLoop._source_audit_preflight(loop, project)
    assert accepted is (source_state == 'valid')
    assert bool(issues) is (source_state != 'valid')
    if issues:
        assert issues[0]['code'] == 'source_repository_preflight_failed'


def _open_intent(intent_id: str) -> Intent:
    """An unclaimed, unconcluded audit intent (no worker, no to_fact)."""
    return Intent(
        id=intent_id,
        from_=["f001"],
        description="investigate",
        creator="dispatcher.audit",
        created_at="2026-01-01T00:00:02Z",
    )


def _blocked_error(intent_id: str) -> IntentError:
    return IntentError(
        id=f"e-{intent_id}",
        intent_id=intent_id,
        task_type="explore",
        code="provider_quota_exhausted",
        classification="blocked",
        message="blocked",
        first_failed_at="2026-01-01T00:00:03Z",
        last_failed_at="2026-01-01T00:00:03Z",
    )


def test_blocked_open_intents_are_not_counted_as_dispatchable() -> None:
    """An open intent withheld by a `blocked` error can never be picked up, so
    it must not masquerade as pending work."""
    loop = _loop()
    project = make_project(intents=[_open_intent("i-blocked"), _open_intent("i-fresh")])
    project.errors.append(_blocked_error("i-blocked"))

    assert loop._project_open_intent_count(project) == 2
    assert loop._dispatchable_open_intent_count(project) == 1


def test_reason_noop_cooldown_engages_even_when_explore_work_is_pending() -> None:
    """Pending Explore work is scheduled separately and cannot justify no-op Reason calls."""
    import time as _time

    loop = _loop()
    loop.config = make_config()
    project = make_project(intents=[_open_intent("i-blocked")])
    project.project.audit_mode = "scope"
    loop.client = SimpleNamespace(get_project=lambda _pid: project)
    loop._append_runtime_health_event = lambda *args, **kwargs: None

    limit = loop.config.audit.reason_noop_limit
    for _ in range(limit):
        loop._observe_reason_noop(SimpleNamespace(project_id="proj_001", run_id=None))

    assert loop._reason_cooldown_until.get("proj_001", 0.0) > _time.time()


def test_priority_reason_wakes_include_human_hints_and_blocking_errors() -> None:
    loop = _loop()
    hint = AuditEvent(
        sequence=11, event_type="human_hint_created", actor="user",
        entity_kind="hint", entity_id="h1", payload={"hint_id": "h1"},
        created_at="2026-01-01T00:00:00Z",
    )
    blocked = AuditEvent(
        sequence=12, event_type="audit_task_failed", actor="worker",
        entity_kind="intent", entity_id="i1",
        payload={"classification": "blocked", "retry_at": None},
        created_at="2026-01-01T00:00:00Z",
    )
    assert loop._reason_has_priority_wake(make_project(), [hint])
    assert loop._reason_has_priority_wake(make_project(), [blocked])


def test_reason_does_not_wake_for_routine_summary_facts() -> None:
    loop = _loop()
    project = make_project(intents=[make_intent("i001")])
    project.facts.extend([
        Fact(id="f-summary", description="module summary", type="module_summary"),
        Fact(id="f-architecture", description="architecture map", type="architecture_map"),
    ])
    events = [
        AuditEvent(sequence=i, event_type="audit_task_concluded", actor="worker",
                   entity_kind="intent", entity_id=f"i{i}", payload={"fact_id": fid},
                   created_at="2026-01-01T00:00:00Z")
        for i, fid in ((1, "f-summary"), (2, "f-architecture"))
    ]
    assert not loop._reason_may_run(project, events)


def test_fresh_recon_and_machine_path_facts_wake_reason_with_open_work() -> None:
    loop = _loop()
    project = make_project(intents=[make_intent("i-pending").model_copy(update={
        "description": recon.category_description("authorization"),
        "to": None,
        "concluded_at": None,
    })])
    project.facts.append(Fact(id="f-machine", description="machine candidates", type="recon"))
    event = AuditEvent(
        sequence=31, event_type="audit_task_concluded", actor="codeql",
        entity_kind="intent", entity_id="i-codeql", payload={"fact_id": "f-machine"},
        created_at="2026-01-01T00:00:00Z",
    )
    assert loop._reason_may_run(project, [event])
    assert loop._reason_has_priority_wake(project, [event])


def _scope_recon_warmup(categories: list[str] | None = None):
    loop = _loop()
    config = make_config()
    recon_config = config.audit.recon.model_copy(update={
        "enabled": True,
        "categories": categories or ["authorization", "input-validation"],
    })
    loop.config = config.model_copy(update={
        "audit": config.audit.model_copy(update={"enabled": True, "recon": recon_config}),
    })
    project = make_project(intents=[make_intent("i-pending").model_copy(update={
        "description": recon.category_description("authorization"),
    })])
    project.project = project.project.model_copy(update={"audit_mode": "scope"})
    return loop, project


def _conclusion(sequence: int, fact_id: str, *, event_type: str = "audit_task_concluded") -> AuditEvent:
    return AuditEvent(
        sequence=sequence, event_type=event_type, actor="worker",
        entity_kind="intent", entity_id=f"i-{sequence}", payload={"fact_id": fact_id},
        created_at="2026-01-01T00:00:00Z",
    )


def test_scope_reason_batches_only_warmup_until_initial_categories_return() -> None:
    loop, project = _scope_recon_warmup()
    policy = Fact(id="f-policy", description="policy preflight", type="policy_evidence")
    project.facts.append(policy)
    event = _conclusion(40, policy.id)

    assert loop._reason_may_run(project, [event])
    assert loop._reason_waits_for_initial_recon(project, [event])

    # Current-generation and current-plan results satisfy the barrier. An open
    # managed intent remains, so the completed lenses still get one synthesis wake.
    for index, category in enumerate(("authorization", "input-validation"), start=1):
        result = Fact(id=f"f-recon-{index}", description=category, type="recon")
        producer = make_intent(f"i-recon-{index}").model_copy(update={
            "description": recon.category_description(category),
            "to": result.id,
        })
        project.facts.append(result)
        project.intents.append(producer)
    # A discovered managed category can still be in progress after all
    # configured initial categories have returned.
    project.intents.append(make_intent("i-followup").model_copy(update={
        "description": recon.category_description("followup"),
        "to": None,
        "concluded_at": None,
    }))
    final_event = _conclusion(41, "f-recon-2")
    assert loop._reason_waits_for_initial_recon(project, [final_event]) is False
    assert loop._reason_may_run(project, [final_event])


def test_scope_reason_warmup_never_delays_human_blocked_or_candidate_evidence() -> None:
    loop, project = _scope_recon_warmup()
    candidate = Fact(
        id="f-candidate", description="new candidate", type="candidate_finding",
        semantic_type="candidate_finding",
    )
    project.facts.append(candidate)
    assert not loop._reason_waits_for_initial_recon(
        project, [_conclusion(50, candidate.id)],
    )

    hint = AuditEvent(
        sequence=51, event_type="human_hint_created", actor="user",
        entity_kind="hint", entity_id="h-new", payload={"hint_id": "h-new"},
        created_at="2026-01-01T00:00:00Z",
    )
    blocked = AuditEvent(
        sequence=52, event_type="audit_task_failed", actor="worker",
        entity_kind="intent", entity_id="i-bad",
        payload={"classification": "blocked", "retry_at": None},
        created_at="2026-01-01T00:00:00Z",
    )
    assert not loop._reason_waits_for_initial_recon(project, [hint])
    assert not loop._reason_waits_for_initial_recon(project, [blocked])

    recon_lead = Fact(
        id="f-recon-lead", description="candidate path from repository Recon",
        type="recon", evidence="status: partial\nleads: 1\ngaps: 2",
    )
    project.facts.append(recon_lead)
    project.intents.append(make_intent("i-recon-lead").model_copy(update={
        "description": recon.category_description("input-validation"),
        "to": recon_lead.id,
    }))
    event = _conclusion(53, recon_lead.id)
    assert loop._reason_has_priority_wake(project, [event])
    assert not loop._reason_waits_for_initial_recon(project, [event])


def test_scope_warmup_delay_is_scoped_to_managed_recon_and_current_plan() -> None:
    loop, project = _scope_recon_warmup()
    project.project = project.project.model_copy(update={"audit_mode": "hypothesis"})
    policy = Fact(id="f-policy", description="policy preflight", type="policy_evidence")
    project.facts.append(policy)
    assert not loop._reason_waits_for_initial_recon(project, [_conclusion(60, policy.id)])

    project.project = project.project.model_copy(update={"audit_mode": "scope"})
    stale = make_intent("i-stale").model_copy(update={
        "description": recon.category_description("authorization"),
        "source_generation": 0,
        "to": "f-stale",
    })
    project.intents.append(stale)
    assert loop._reason_waits_for_initial_recon(project, [_conclusion(61, policy.id)])
