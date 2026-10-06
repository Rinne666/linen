from __future__ import annotations

from collections.abc import Mapping
import hashlib
import inspect
import json
import logging
import re
import shutil
import subprocess
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests

from linen.contracts import AuditEventEnvelope
from linen.dispatcher.analysis import audit_graph, audit_recipes, codeql, coverage, recon, scope_gate, stages
from linen.dispatcher.analysis.source_preflight import preflight_source_repository
from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.models import RunningTask
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.startup_healthcheck import format_failure_summary, run_startup_healthchecks
from linen.dispatcher.scheduler.worker_select import choose_worker
from linen.dispatcher.workers.registry import get_driver
from linen.dispatcher.tasks.explore import run_explore_task
from linen.dispatcher.tasks.reason import run_reason_task
from linen.dispatcher.tasks.review import run_review_task
from linen.server.models import AuditEvent, CompletionGate, Intent, ProjectDetail, ProjectSummary

LOG = logging.getLogger(__name__)
UNHEALTHY_RETRY_AFTER_SECONDS = 5
REJECTED_RETRY_AFTER_SECONDS = 5
RATE_LIMIT_RETRY_AFTER_SECONDS = 300
QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS = 3600
PROJECT_PAUSING_CLI_ISSUES = {
    "quota_exhausted",
    "cli_model_unsupported",
    "cli_model_unrecognized",
    "cli_auth_failed",
    "cli_executable_missing",
}


@dataclass(slots=True)
class WorkerSelection:
    worker: WorkerConfig | None
    blocked_busy: list[str]
    blocked_unhealthy: list[str]
    blocked_rejected: list[str]
    blocked_task_type: list[str]


class DispatcherLoop:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = DispatchConfig.load(config_path)
        self.client = LinenClient(self.config.server)
        self.container_manager = LocalBackend(self.config.local, client=self.client)
        self.executor = ThreadPoolExecutor(max_workers=self.config.runtime.max_workers)
        self.cleanup_executor = ThreadPoolExecutor(max_workers=max(1, min(8, self.config.runtime.max_workers)))
        self.futures: dict[Future[str], RunningTask] = {}
        self.cleanup_futures: dict[Future[bool], tuple[str, str | None, str | None]] = {}
        self.runtime_project_ids: set[str] = set()
        self.worker_unhealthy_until: dict[str, float] = {}
        self.worker_rejected_until: dict[tuple[str, str, str], float] = {}
        self.worker_provider_until: dict[str, float] = {}
        self.worker_provider_reason: dict[str, str] = {}
        self.worker_provider_opened_at: dict[str, float] = {}
        self.worker_provider_origin: dict[str, tuple[str, int]] = {}
        self._manual_provider_retries_seen: set[str] = set()
        self._provider_resume_event_cursors: dict[str, int] = {}
        self._execution_attempt_state_cache: dict[tuple[str, int], dict[str, bool]] = {}
        self._restore_provider_circuits()
        self._log_state: dict[str, tuple[int, str, tuple[object, ...]]] = {}
        self._cleanup_pending: set[str] = set()
        self._inactive_cleanup_done: dict[str, str] = {}
        self.project_cursor = 0
        self._settings_checked = False
        self._startup_healthchecks_checked = False
        self._orphan_recovery_done: set[str] = set()
        self._orphan_recovery_reported: set[str] = set()
        self._reason_noop_streak: dict[str, int] = {}
        self._reason_cooldown_until: dict[str, float] = {}
        self._reason_cooldown_restored: set[str] = set()
        self._audit_idle_state: dict[str, dict[str, float | int | None]] = {}
        self._audit_deadlines: dict[str, float] = {}

    def close(self) -> None:
        if self.futures:
            LOG.info(
                "dispatcher shutting down waiting_for_tasks=%s running_projects=%s",
                len(self.futures),
                sorted({task.project_id for task in self.futures.values()}),
            )
        self.executor.shutdown(wait=True)
        self.cleanup_executor.shutdown(wait=True)
        self.container_manager.close()
        self.client.close()

    def run(self, once: bool = False) -> None:
        try:
            self.run_startup_healthchecks()
            while True:
                try:
                    if not self._settings_checked:
                        self._validate_server_settings()
                        self._settings_checked = True
                    self._reap_futures()
                    self._reap_cleanup_futures()
                    summaries = self.client.list_projects()
                    self._recover_orphan_runs(summaries)
                    self._refresh_runtime_projects(summaries)
                    self._cancel_inactive_tasks(summaries)
                    self._enforce_running_audit_budgets(summaries)
                    self._queue_container_cleanups(summaries)
                    self._dispatch_available(summaries)
                except requests.RequestException as exc:
                    if once:
                        raise
                    LOG.warning(
                        "dispatcher server request failed error=%s retry_in=%ss",
                        exc,
                        self.config.runtime.interval,
                    )
                    time.sleep(self.config.runtime.interval)
                    continue
                if once:
                    break
                time.sleep(self.config.runtime.interval)
        finally:
            self.close()

    def run_startup_healthchecks_only(self) -> None:
        try:
            self.run_startup_healthchecks(show_commands=True, force=True)
        finally:
            self.close()

    def run_startup_healthchecks(self, *, show_commands: bool = False, force: bool = False) -> None:
        if self._startup_healthchecks_checked:
            return
        # Local mode reuses the host's logged-in CLIs, so we only verify the
        # binaries are on PATH and runnable. HTTP pings to the upstream API
        # aren't useful here (the worker uses the host CLI's own credentials,
        # not the env keys in dispatch.yaml).
        self._run_local_binary_check()
        self._startup_healthchecks_checked = True
        if not force and self.config.runtime.worker_healthcheck == "disabled":
            return
        self._run_startup_healthchecks(show_commands=show_commands)

    def _run_local_binary_check(self) -> None:
        binaries: dict[str, list[str]] = {}
        for worker in self.config.workers:
            binary = get_driver(worker.type).local_binary()
            if binary is None:
                continue
            binaries.setdefault(binary, []).append(worker.name)
        if not binaries:
            return

        LOG.info("[*] Local execution: checking %d worker CLI(s) on this host", len(binaries))
        available: list[str] = []
        missing: list[str] = []
        for binary in sorted(binaries):
            workers = ", ".join(sorted(binaries[binary]))
            path, runnable = self._probe_local_cli(binary)
            if path is None:
                missing.append(binary)
                LOG.error("[-] %-8s not found on PATH (workers: %s)", binary, workers)
            elif runnable:
                available.append(binary)
                LOG.info("[+] %-8s %s (workers: %s)", binary, path, workers)
            else:
                available.append(binary)
                LOG.warning("[!] %-8s %s found but `%s --help` failed (workers: %s)", binary, path, binary, workers)

        if not available:
            raise RuntimeError(
                "local execution: none of the configured worker CLIs are installed on PATH ("
                + ", ".join(sorted(binaries))
                + "). Install them and make sure each runs directly from your shell, then retry."
            )
        if missing:
            LOG.warning(
                "[!] Missing CLIs, their workers cannot run: %s. Install them or drop those workers.",
                ", ".join(sorted(missing)),
            )
        LOG.warning(
            "[!] Local mode uses each CLI's own host config: make sure %s already logged in / "
            "configured and usable directly (e.g. `claude -p ...` works). For an actual model "
            "probe, set runtime.healthcheck_probe=response.",
            ", ".join(sorted(available)),
        )

    @staticmethod
    def _probe_local_cli(binary: str) -> tuple[str | None, bool]:
        path = shutil.which(binary)
        if path is None:
            return None, False
        try:
            result = subprocess.run(
                [binary, "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return path, False
        return path, result.returncode == 0

    def _recover_orphan_runs(self, summaries: list[ProjectSummary]) -> None:
        """Recover expired server runs once per active project lifetime.

        The server decides which running rows are expired and returns only
        those rows as ``interrupted``. Recovery restores scheduler retry and
        checkpoint state only; it never mutates facts, intents, or edges.
        """
        done = getattr(self, "_orphan_recovery_done", None)
        if done is None:
            done = set()
            self._orphan_recovery_done = done
        reported = getattr(self, "_orphan_recovery_reported", None)
        if reported is None:
            reported = set()
            self._orphan_recovery_reported = reported
        recover = getattr(getattr(self, "client", None), "recover_runs", None)
        for summary in summaries:
            if summary.status != "active" or summary.id in done:
                continue
            if recover is None:
                # Legacy clients cannot perform recovery; avoid retrying the
                # unsupported operation on every scheduler tick.
                done.add(summary.id)
                continue
            try:
                recovered = recover(summary.id)
            except Exception:
                LOG.exception("orphan run recovery failed project=%s", summary.id)
                continue
            # A failed request remains eligible for the next scheduler tick;
            # only a successful response (including []) consumes the one-shot
            # lifecycle recovery slot.
            done.add(summary.id)
            if getattr(recovered, "data", None) is not None:
                recovered = recovered.data
            if not isinstance(recovered, (list, tuple)) or not recovered:
                continue
            for run in recovered:
                value = lambda key, default=None: (
                    run.get(key, default) if isinstance(run, Mapping)
                    else getattr(run, key, default)
                )
                run_id = str(value("run_id", "")).strip()
                if not run_id or run_id in reported:
                    continue
                status = value("status")
                if status not in {None, "interrupted"}:
                    continue
                reported.add(run_id)
                project_id = str(value("project_id") or summary.id)
                intent_id = value("intent_id")
                task_type = str(value("task_type", ""))
                attempt = int(value("attempt") or 1)
                graph_revision = int(value("graph_revision") or 0)
                worker = str(value("worker_name") or "dispatcher.recovery")
                if intent_id:
                    self._report_orphan_intent_error(
                        project_id, str(intent_id), worker or "dispatcher.recovery", task_type,
                    )
                elif task_type in {"reason", "reason_execute"}:
                    LOG.info(
                        "reason run recovered project=%s event_seq=%s attempt=%s; cursor remains unacknowledged",
                        project_id, graph_revision, attempt,
                    )

    def _report_orphan_intent_error(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        task_type: str,
    ) -> None:
        reporter = getattr(getattr(self, "client", None), "report_intent_error", None)
        if reporter is None:
            return
        normalized_type = {
            "explore": "explore",
            "explore_execute": "explore",
            "review": "review",
            "review_execute": "review",
        }.get(task_type, task_type or "explore")
        try:
            response = reporter(
                project_id, intent_id, worker,
                task_type=normalized_type,
                code="orphan_run_interrupted",
                classification="transient",
                message="The dispatcher recovered an expired running attempt; retry it.",
                remediation="Inspect the prior run output if the retry fails again.",
                base_retry_seconds=15,
                max_retry_seconds=300,
                max_attempts=2,
            )
            if not response.ok:
                LOG.warning(
                    "orphan intent error write failed project=%s intent=%s status=%s body=%s",
                    project_id, intent_id, response.status_code, response.text,
                )
        except Exception:
            LOG.exception(
                "orphan intent error persistence crashed project=%s intent=%s",
                project_id, intent_id,
            )

    def _dispatch_available(self, summaries: list[ProjectSummary]) -> None:
        if len(self.futures) >= self.config.runtime.max_workers:
            self._log_changed(
                "dispatch/global",
                logging.INFO,
                "skip dispatch because max_workers reached running_tasks=%s",
                len(self.futures),
            )
            return
        active = [summary for summary in summaries if summary.status == "active"]
        if not active:
            self._log_changed("dispatch/global", logging.INFO, "skip dispatch because no active projects")
            return

        running_projects = self._ordered_projects(
            [summary for summary in active if summary.id in self.runtime_project_ids]
        )
        idle_projects = self._ordered_projects(
            [summary for summary in active if summary.id not in self.runtime_project_ids]
        )

        dispatched = True
        while dispatched and len(self.futures) < self.config.runtime.max_workers:
            dispatched = False
            for summary in running_projects:
                if self._try_dispatch_project(summary):
                    dispatched = True
                    if len(self.futures) >= self.config.runtime.max_workers:
                        return
            if dispatched:
                continue
            if self._running_project_count(active) >= self.config.runtime.max_running_projects:
                self._log_changed(
                    "dispatch/idle-limit",
                    logging.INFO,
                    "skip idle project dispatch because max_running_projects reached running_projects=%s",
                    self._running_project_count(active),
                )
                return
            for summary in idle_projects:
                if self._running_project_count(active) >= self.config.runtime.max_running_projects:
                    self._log_changed(
                        "dispatch/idle-limit",
                        logging.INFO,
                        "stop idle project dispatch because max_running_projects reached running_projects=%s",
                        self._running_project_count(active),
                    )
                    return
                if self._try_dispatch_project(summary):
                    dispatched = True
                    break

    def _ordered_projects(self, summaries: list[ProjectSummary]) -> list[ProjectSummary]:
        if not summaries:
            return []
        ids = [summary.id for summary in summaries]
        ids.sort()
        offset = self.project_cursor % len(ids)
        ordered_ids = ids[offset:] + ids[:offset]
        by_id = {summary.id: summary for summary in summaries}
        self.project_cursor += 1
        return [by_id[project_id] for project_id in ordered_ids]

    def _source_audit_preflight(self, project: ProjectDetail) -> bool:
        """Block managed audits before any model call when source is unavailable."""
        if (
            not self.config.audit.enabled
            or project.project.audit_mode not in {"scope", "hypothesis"}
        ):
            return True

        project_id = project.project.id
        try:
            # Ensure the preflight inspects the exact workdir and `repo` path
            # that a worker receives. This also attempts to materialize the
            # configured per-project or dispatcher-level source link.
            workdir = Path(self.container_manager.ensure_running(project_id))
            configured_root = project.project.repo_root or self.config.local.repo_root
            failure = preflight_source_repository(
                workdir,
                configured_root,
                self.config.audit.recon.exclude,
            )
        except Exception as exc:
            failure = f"Could not prepare the worker-visible source workspace: {exc}."

        if failure is None:
            return True

        remediation = (
            "Set project repo_root or dispatcher local.repo_root to an existing readable source "
            "directory. Ensure the dispatcher worker can traverse it and that <workspace>/repo "
            "resolves to that same directory, then resume the project."
        )
        response = self.client.report_project_worker_issue(
            project_id,
            worker="dispatcher.source-preflight",
            task_type="reason",
            code="source_repository_preflight_failed",
            message=f"Source audit preflight failed: {failure}",
            remediation=remediation,
        )
        if not response.ok:
            LOG.warning(
                "source audit preflight issue could not be persisted project=%s status=%s body=%s",
                project_id,
                response.status_code,
                response.text,
            )
        else:
            LOG.warning(
                "blocked source audit before model work project=%s reason=%s",
                project_id,
                failure,
            )
        return False

    def _try_dispatch_project(self, summary: ProjectSummary) -> bool:
        if not hasattr(self, "_reason_cooldown_until"):
            self._reason_cooldown_until = {}
        if not hasattr(self, "_reason_cooldown_restored"):
            self._reason_cooldown_restored = set()
        if not hasattr(self, "_audit_idle_state"):
            self._audit_idle_state = {}
        skip_scope = f"project:{summary.id}:skip"
        container_name = self.container_manager.container_name(summary.id)
        if container_name in self._cleanup_pending:
            self._log_changed(
                f"{skip_scope}:cleanup_pending",
                logging.DEBUG,
                "skip project=%s because container cleanup is still pending container=%s",
                summary.id,
                container_name,
            )
            return False
        at_capacity = (
            self._project_running_task_count(summary.id)
            >= self.config.runtime.max_project_workers
        )

        project = self.client.get_project(summary.id)
        if project.project.status != "active":
            self._log_changed(
                f"{skip_scope}:status",
                logging.INFO,
                "skip project=%s because status=%s",
                summary.id,
                project.project.status,
            )
            return False
        budget_state = self._audit_project_budget_state(project)
        if budget_state == "unavailable":
            self._log_changed(
                f"project:{summary.id}:audit_budget_unavailable",
                logging.WARNING,
                "defer audit dispatch because persisted runs are unavailable project=%s",
                summary.id,
            )
            return False
        if budget_state is not None:
            self._record_audit_budget_blocker(project, budget_state)
            if self._complete_if_gate_ready(project):
                return True
            return False
        if not self._source_audit_preflight(project):
            return True
        self._honor_manual_provider_retries(project)
        self._honor_project_worker_issue_resumes(project)
        # Managed audit mechanics are derived exclusively from the exported
        # graph and immutable project artifacts. Scope mode derives the Recon DAG;
        # hypothesis mode derives only configured baseline scan
        # and review edges. Materializing a missing edge here preserves the
        # blackboard as the only task ledger and makes restarts deterministic.
        if project.project.reason is None and self._materialize_audit_intents(project):
            project = self.client.get_project(summary.id)

        # The stage ledger is a deterministic projection, not a queue.  Keep
        # it converged with the graph after intent materialization and before
        # choosing a worker.  Only changed rows are written; this matters
        # because the server advances graph_revision for a stage mutation.
        if self._reconcile_audit_stages(project):
            project = self.client.get_project(summary.id)

        if project.project.reason is None:
            reason_trigger = self._reason_trigger(project)
            trigger_events = (
                self._reason_trigger_events(project, reason_trigger)
                if reason_trigger is not None else []
            )
            if reason_trigger is not None and self._reason_may_run(project, trigger_events):
                if self._reason_waits_for_initial_recon(project, trigger_events):
                    self._log_changed(
                        f"project:{summary.id}:reason_wait_initial_recon",
                        logging.INFO,
                        "defer warmup reason project=%s until initial Recon categories return",
                        summary.id,
                    )
                    # Do not advance reason_last_seen_event_seq. The first
                    # post-bootstrap Reason pass will receive the whole event batch.
                    return False
                self._restore_reason_cooldown(project)
                cooldown_until = self._reason_cooldown_until.get(summary.id, 0.0)
                priority_wake = self._reason_has_priority_wake(project, trigger_events)
                if time.time() < cooldown_until and not priority_wake:
                    self._log_changed(
                        f"project:{summary.id}:reason_noop_cooldown",
                        logging.INFO,
                        "cool down stalled reason project=%s remaining=%.0fs",
                        summary.id,
                        cooldown_until - time.time(),
                    )
                    return False
                if at_capacity:
                    self._log_changed(
                        f"{skip_scope}:max_project_workers",
                        logging.INFO,
                        "skip project=%s because max_project_workers reached running_tasks=%s",
                        summary.id,
                        self._project_running_task_summary(summary.id),
                    )
                    return False
                export_yaml = self.client.export_project(summary.id)
                return self._dispatch_reason(project, export_yaml, reason_trigger, trigger_events)

        self._observe_audit_idle_health(project)

        completion_gate = None
        if (
            project.project.reason is None
            and project.project.audit_mode != "none"
            and hasattr(self.client, "get_completion_gate")
        ):
            try:
                completion_gate = self.client.get_completion_gate(project.project.id)
            except Exception as exc:
                LOG.warning(
                    "completion gate read failed project=%s error=%s",
                    project.project.id,
                    exc,
                )
            else:
                if (
                    completion_gate.ready
                    and project.project.completion_policy == "goal_based"
                ):
                    if self._commit_completion_gate(project, completion_gate):
                        return True
                elif not completion_gate.ready:
                    self._log_changed(
                        f"{skip_scope}:completion_gate",
                        logging.INFO,
                        "audit waiting for completion evidence project=%s execution=%s blockers=%s",
                        project.project.id,
                        completion_gate.execution_status,
                        completion_gate.blockers,
                    )

        if at_capacity:
            self._log_changed(
                f"{skip_scope}:max_project_workers",
                logging.INFO,
                "skip project=%s because max_project_workers reached running_tasks=%s",
                summary.id,
                self._project_running_task_summary(summary.id),
            )
            return False
        running_intent_ids = self._project_running_explore_intents(summary.id)
        unclaimed_intents = [
            intent
            for intent in project.intents
            if intent.to is None
            and intent.concluded_at is None  # review tasks conclude via
                                              # concluded_at (not to_fact_id);
                                              # without this, the scheduler
                                              # re-dispatches a "done" review
                                              # intent every tick.
            and intent.worker is None
            and intent.id not in running_intent_ids
        ]
        deferred_by_error = [
            intent for intent in unclaimed_intents
            if not self._intent_error_allows_dispatch(project, intent)
        ]
        if deferred_by_error:
            unclaimed_intents = [
                intent for intent in unclaimed_intents
                if intent not in deferred_by_error
            ]
            self._log_changed(
                f"{skip_scope}:intent_errors",
                logging.INFO,
                "intent errors withholding work project=%s intents=%s",
                summary.id,
                [intent.id for intent in deferred_by_error],
            )
        if unclaimed_intents:
            scope_evidence_pending = self._scope_evidence_review_pending(project)
            scope_pending = self._scope_gate_pending(project)
            deferred_by_scope = []
            if scope_evidence_pending or scope_pending:
                runnable_intents = []
                for intent in unclaimed_intents:
                    description = intent.description.strip()
                    is_recon_work = (
                        description == recon.SNAPSHOT_INTENT
                        or description == recon.COVERAGE_REVIEW_INTENT
                        or recon.category_from_description(description) is not None
                        or codeql.is_intent(intent)
                    )
                    if scope_evidence_pending and scope_gate.is_adjudication_intent(intent):
                        deferred_by_scope.append(intent)
                    elif scope_pending and (
                        is_recon_work
                        or description == audit_graph.AUDIT_SUMMARY_INTENT
                    ):
                        deferred_by_scope.append(intent)
                    else:
                        runnable_intents.append(intent)
                unclaimed_intents = runnable_intents
            if deferred_by_scope:
                self._log_changed(
                    f"{skip_scope}:scope_gate",
                    logging.INFO,
                    "scope gate withholding adjudication or Recon work until required independent reviews pass project=%s intents=%s",
                    summary.id,
                    [intent.id for intent in deferred_by_scope],
                )
        if running_intent_ids and not unclaimed_intents:
            self._log_changed(
                f"{skip_scope}:explore_running",
                logging.DEBUG,
                "skip explore project=%s because all unclaimed intents are already running locally intents=%s",
                summary.id,
                sorted(running_intent_ids),
            )
        if unclaimed_intents:
            # Review intents are routed to the review dispatcher (mirrors
            # the explore dispatcher but for adversarial validation). The
            # fact under review is in intent.from[0]. Created by reason
            # tasks or by the UI's "Run review" button.
            review_intents = [
                i for i in unclaimed_intents
                if (i.type or "").strip() == "review"
                or (i.type or "").strip().startswith("review:")
            ]
            if review_intents:
                next_intent = min(
                    review_intents,
                    key=lambda i: (i.last_heartbeat_at or i.created_at, i.created_at, i.id),
                )
                export_yaml = self.client.export_project(summary.id)
                if self._dispatch_review(project, export_yaml, next_intent):
                    return True
            explore_intents = [intent for intent in unclaimed_intents if intent not in review_intents]
            if not explore_intents:
                return False
            # Pick the least-recently attempted intent. A released intent keeps
            # its heartbeat timestamp, so failures rotate to the back of the
            # persisted blackboard queue instead of starving older work.
            next_intent = min(
                explore_intents,
                key=lambda i: (
                    int(self._explore_requires_provider(project, i)),
                    i.last_heartbeat_at or i.created_at,
                    i.created_at,
                    i.id,
                ),
            )
            export_yaml = self.client.export_project(summary.id)
            return self._dispatch_explore(project, export_yaml, next_intent)
        if project.project.reason is not None:
            self._log_changed(
                f"{skip_scope}:reason_claimed",
                logging.DEBUG,
                "skip reason project=%s because reason is already claimed by %s",
                summary.id,
                project.project.reason.worker,
            )
            return False
        if (
            completion_gate is not None
            and project.project.completion_policy == "exhaustive"
            and completion_gate.ready
        ):
            if self._commit_completion_gate(project, completion_gate):
                return True
        self._log_changed(
            f"{skip_scope}:graph_unchanged",
            logging.DEBUG,
            "skip reason project=%s because reason state unchanged facts=%s hints=%s open_intents=%s intents=%s",
            summary.id,
            len(project.facts),
            len(project.hints),
            self._project_open_intent_count(project),
            len(project.intents),
        )
        return False

    def _audit_project_budget_state(
        self, project: ProjectDetail,
    ) -> tuple[str, str, str] | str | None:
        """Return a deterministic audit budget blocker before materialization or dispatch."""
        if project.project.audit_mode == "none":
            return None
        list_runs = getattr(getattr(self, "client", None), "list_runs", None)
        if list_runs is None:
            return "unavailable"
        try:
            runs = list_runs(project.project.id)
        except Exception:
            LOG.exception("audit run budget lookup failed project=%s", project.project.id)
            return "unavailable"

        run_ids = {
            self._run_value(run, "run_id")
            for run in runs
            if isinstance(self._run_value(run, "run_id"), str)
        }
        matched_run_ids: set[str] = set()
        unregistered_local_runs = 0
        for task in self.futures.values():
            if task.project_id != project.project.id:
                continue
            if isinstance(task.run_id, str) and task.run_id in run_ids:
                matched_run_ids.add(task.run_id)
                continue

            matched_run = None
            for run in runs:
                run_id = self._run_value(run, "run_id")
                if not isinstance(run_id, str) or run_id in matched_run_ids:
                    continue
                if self._run_value(run, "worker_name") != task.worker_name:
                    continue
                if self._run_value(run, "status") not in {"queued", "running"}:
                    continue
                run_intent_id = self._run_value(run, "intent_id")
                if task.intent_id is not None:
                    if run_intent_id != task.intent_id:
                        continue
                elif run_intent_id is not None or not str(
                    self._run_value(run, "task_type") or ""
                ).startswith("reason"):
                    continue
                matched_run = run_id
                break
            if matched_run is None:
                # Dispatch is asynchronous: reserve a local slot until this
                # task's first persisted run appears, then count that run only.
                unregistered_local_runs += 1
            else:
                matched_run_ids.add(matched_run)
        run_count = len(runs) + unregistered_local_runs
        max_runs = getattr(self.config.audit, "max_runs_per_project", 250)
        wall_clock_budget = getattr(self.config.audit, "wall_clock_budget_seconds", 43200)
        deadline_epoch = self._wall_clock_deadline(project.project.id, runs)
        if deadline_epoch is not None and time.time() >= deadline_epoch:
            deadline = datetime.fromtimestamp(deadline_epoch, timezone.utc).isoformat().replace("+00:00", "Z")
            return (
                "audit_wall_clock_budget_exhausted",
                f"Wall-clock budget exhausted ({wall_clock_budget} seconds).",
                deadline,
            )
        if run_count >= max_runs:
            run_starts = sorted(
                (
                    (self._timestamp_seconds(self._run_value(run, "started_at")),
                     self._run_value(run, "started_at"))
                    for run in runs
                ),
                key=lambda item: item[0] if item[0] is not None else float("inf"),
            )
            occurrence = (
                run_starts[min(max_runs - 1, len(run_starts) - 1)][1]
                if run_starts else project.project.created_at
            )
            if not isinstance(occurrence, str) or not occurrence.strip():
                occurrence = project.project.created_at
            return (
                "audit_run_budget_exhausted",
                f"Run budget exhausted at the configured limit of {max_runs} runs.",
                occurrence,
            )

        return None

    def _wall_clock_deadline(self, project_id: str, runs: list[object] | None = None) -> float | None:
        """Return the persisted project cutoff, with run history as a migration fallback."""
        deadlines = getattr(self, "_audit_deadlines", None)
        if deadlines is None:
            deadlines = {}
            self._audit_deadlines = deadlines
        if project_id in deadlines:
            return deadlines[project_id]
        budget = getattr(self.config.audit, "wall_clock_budget_seconds", 43200)
        get_events = getattr(getattr(self, "client", None), "get_audit_events", None)
        if callable(get_events):
            try:
                for event in get_events(project_id, after=0, limit=2000):
                    payload = getattr(event, "payload", {})
                    if (
                        getattr(event, "event_type", None) == "audit_budget_started"
                        and getattr(event, "actor", None) == "dispatcher.health"
                        and payload.get("code") == "audit_wall_clock_budget_started"
                        and payload.get("budget_limit") == budget
                    ):
                        deadline = self._timestamp_seconds(payload.get("deadline_at"))
                        if deadline is not None:
                            deadlines[project_id] = deadline
                            return deadline
            except Exception:
                LOG.debug("persisted audit deadline lookup failed project=%s", project_id, exc_info=True)
        if runs is None:
            try:
                runs = self.client.list_runs(project_id)
            except Exception:
                return None
        starts = [
            self._timestamp_seconds(self._run_value(run, "started_at"))
            for run in runs
        ]
        starts = [started for started in starts if started is not None]
        if starts:
            deadline = min(starts) + budget
            deadlines[project_id] = deadline
            return deadline
        # Before the first run row/event is visible, all local tasks share one
        # in-memory deadline; _task_cancellation persists its origin event.
        if any(task.project_id == project_id for task in self.futures.values()):
            deadline = time.time() + budget
            deadlines[project_id] = deadline
            return deadline
        return None

    def _task_cancellation(self, project: ProjectDetail) -> TaskCancellation:
        project_id = project.project.id
        if project.project.audit_mode == "none":
            return TaskCancellation()
        try:
            runs = self.client.list_runs(project_id)
        except Exception:
            LOG.exception("could not restore audit deadline before dispatch project=%s", project_id)
            runs = []
        deadline = self._wall_clock_deadline(project_id, runs)
        wall_clock_budget = getattr(self.config.audit, "wall_clock_budget_seconds", 43200)
        if deadline is None:
            started = time.time()
            deadline = started + wall_clock_budget
            self._audit_deadlines[project_id] = deadline
            started_at = datetime.fromtimestamp(started, timezone.utc).isoformat().replace("+00:00", "Z")
            deadline_at = datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z")
            self._append_runtime_health_event(
                project,
                "audit_budget_started",
                "audit_wall_clock_budget_started",
                {
                    "budget_limit": wall_clock_budget,
                    "started_at": started_at,
                    "deadline_at": deadline_at,
                    "occurred_at": started_at,
                },
            )
        return TaskCancellation(deadline_epoch=deadline)

    def _record_audit_budget_blocker(
        self,
        project: ProjectDetail,
        state: tuple[str, str, str] | str,
    ) -> None:
        if state == "unavailable":
            return
        code, message, occurred_at = state
        budget_limit = (
            getattr(self.config.audit, "max_runs_per_project", 250)
            if code == "audit_run_budget_exhausted"
            else getattr(self.config.audit, "wall_clock_budget_seconds", 43200)
        )
        self._append_runtime_health_event(
            project,
            "audit_budget_blocked",
            code,
            {"message": message, "budget_limit": budget_limit, "occurred_at": occurred_at},
        )
        self._log_changed(
            f"project:{project.project.id}:audit_budget:{code}",
            logging.WARNING,
            "audit project budget exhausted project=%s code=%s detail=%s",
            project.project.id,
            code,
            message,
        )

    def _enforce_running_audit_budgets(self, summaries: list[ProjectSummary]) -> None:
        """Cancel in-flight model work as soon as an audit wall-clock cutoff passes."""
        active = {task.project_id for task in self.futures.values()}
        for summary in summaries:
            if summary.id not in active:
                continue
            try:
                project = self.client.get_project(summary.id)
                state = self._audit_project_budget_state(project)
            except Exception:
                LOG.exception("could not enforce audit deadline project=%s", summary.id)
                continue
            if state == "unavailable" or state is None:
                continue
            self._record_audit_budget_blocker(project, state)
            if state[0] == "audit_wall_clock_budget_exhausted":
                for task in list(self.futures.values()):
                    if task.project_id == summary.id:
                        task.cancellation.cancel("audit_wall_clock_budget_exhausted")

    @staticmethod
    def _run_value(run: object, key: str) -> object:
        return run.get(key) if isinstance(run, Mapping) else getattr(run, key, None)

    @staticmethod
    def _timestamp_seconds(value: object) -> float | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            return None

    def _append_runtime_health_event(
        self,
        project: ProjectDetail,
        event_type: str,
        code: str,
        payload: dict[str, object],
    ) -> int | None:
        append = getattr(getattr(self, "client", None), "append_event", None)
        if append is None:
            return None
        sequence = project.project.event_seq
        idempotency_key = (
            f"dispatcher-health:{code}:g{project.project.source_generation}"
            f":p{project.project.plan_revision}"
        )
        if event_type in {"audit_budget_blocked", "audit_budget_started"}:
            idempotency_key += f":limit={payload.get('budget_limit', 'unknown')}"
        else:
            idempotency_key += f":e{sequence}"
        cache_key = (project.project.id, idempotency_key)
        if event_type in {"audit_budget_blocked", "audit_budget_started"}:
            cache = getattr(self, "_budget_health_events", None)
            if cache is None:
                cache = self._budget_health_events = {}
            if cache_key in cache:
                return cache[cache_key]
        occurrence = payload.get("occurred_at")
        created_at = (
            occurrence.strip()
            if isinstance(occurrence, str) and occurrence.strip()
            else project.project.created_at
        )
        event = AuditEventEnvelope(
            event_id=f"health-{hashlib.sha256(idempotency_key.encode()).hexdigest()[:24]}",
            project_id=project.project.id,
            idempotency_key=idempotency_key,
            event_type=event_type,
            actor="dispatcher.health",
            entity_kind="project",
            entity_id=project.project.id,
            graph_revision=project.project.graph_revision,
            source_generation=project.project.source_generation,
            plan_revision=project.project.plan_revision,
            payload={"code": code, **payload},
            created_at=created_at,
        )
        try:
            response = append(event)
        except Exception:
            LOG.exception("runtime health event write failed project=%s code=%s", project.project.id, code)
            return None
        if hasattr(response, "ok") and not response.ok:
            if event_type in {"audit_budget_blocked", "audit_budget_started"} and response.status_code == 409:
                # A restarted dispatcher may encounter a budget event written
                # at an earlier graph revision. Recover that immutable event;
                # never replace its content or relax server idempotency checks.
                getter = getattr(self.client, "get_audit_events", None)
                after = 0
                try:
                    while callable(getter) and after < sequence:
                        page = getter(project.project.id, after=after, limit=2000)
                        if not page:
                            break
                        for prior in page:
                            if (
                                prior.sequence <= sequence
                                and prior.event_type == event_type
                                and prior.actor == "dispatcher.health"
                                and prior.source_generation == project.project.source_generation
                                and prior.plan_revision == project.project.plan_revision
                                and prior.payload.get("code") == code
                                and prior.payload.get("budget_limit") == payload.get("budget_limit")
                            ):
                                cache[cache_key] = prior.sequence
                                return prior.sequence
                        last = max(prior.sequence for prior in page)
                        if last <= after:
                            break
                        after = last
                except Exception:
                    LOG.debug("budget health event recovery failed project=%s", project.project.id, exc_info=True)
            LOG.warning(
                "runtime health event write rejected project=%s code=%s status=%s",
                project.project.id,
                code,
                getattr(response, "status_code", "unknown"),
            )
            return None
        if isinstance(response, Mapping):
            result_sequence = response.get("sequence")
        else:
            result_sequence = getattr(response, "sequence", None)
            result_data = getattr(response, "data", None)
            if result_sequence is None and result_data is not None:
                result_sequence = (
                    result_data.get("sequence")
                    if isinstance(result_data, Mapping)
                    else getattr(result_data, "sequence", None)
                )
        try:
            result_sequence = int(result_sequence) if result_sequence is not None else sequence + 1
        except (TypeError, ValueError):
            result_sequence = sequence + 1
        if event_type == "audit_budget_blocked":
            cache[cache_key] = result_sequence
        return result_sequence

    def _observe_reason_noop(self, task: RunningTask) -> None:
        project_id = task.project_id
        if not hasattr(self, "_reason_noop_streak"):
            self._reason_noop_streak = {}
        if not hasattr(self, "_reason_cooldown_until"):
            self._reason_cooldown_until = {}
        streak = self._reason_noop_streak.get(project_id, 0) + 1
        self._reason_noop_streak[project_id] = streak
        limit = getattr(self.config.audit, "reason_noop_limit", 3)
        if streak < limit:
            return
        try:
            project = self.client.get_project(project_id)
        except Exception:
            LOG.exception("reason no-op health lookup failed project=%s", project_id)
            return
        if project.project.audit_mode == "none":
            self._reason_noop_streak.pop(project_id, None)
            return
        # Reason's no-op says its strategy pass made no graph progress. Open
        # Explore/Review work is scheduled independently and must not keep
        # waking Reason on routine graph churn forever.
        cooldown = getattr(self.config.audit, "reason_noop_cooldown_seconds", 900)
        until = time.time() + cooldown
        self._reason_cooldown_until[project_id] = until
        no_op_at = None
        if task.run_id:
            try:
                runs = self.client.list_runs(project_id)
                run = next(
                    (item for item in runs if self._run_value(item, "run_id") == task.run_id),
                    None,
                )
                no_op_at = self._run_value(run, "finished_at") if run is not None else None
            except Exception:
                LOG.debug("reason no-op run lookup failed project=%s run=%s", project_id, task.run_id, exc_info=True)
        self._append_runtime_health_event(
            project,
            "audit_stall_detected",
            "reason_noop_streak",
            {
                "consecutive_noop_runs": streak,
                "cooldown_seconds": cooldown,
                "occurred_at": (
                    no_op_at
                    if isinstance(no_op_at, str)
                    else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                ),
            },
        )
        self._reason_noop_streak[project_id] = 0
        LOG.warning(
            "audit reason stalled project=%s no_op_runs=%s cooldown_seconds=%s",
            project_id,
            streak,
            cooldown,
        )

    def _restore_reason_cooldown(self, project: ProjectDetail) -> None:
        """Recover an active no-op cooldown from its persisted health event."""
        project_id = project.project.id
        if project_id in self._reason_cooldown_restored:
            return
        getter = getattr(getattr(self, "client", None), "get_audit_events", None)
        if getter is None:
            return
        after = project.project.reason_last_seen_event_seq
        through = project.project.event_seq
        events: list[AuditEvent] = []
        try:
            while after < through:
                page = getter(project_id, after=after, limit=2000)
                if not page:
                    break
                events.extend(event for event in page if event.sequence <= through)
                last = max(event.sequence for event in page)
                if last <= after:
                    break
                after = last
        except Exception:
            LOG.debug("reason cooldown recovery failed project=%s", project_id, exc_info=True)
            return
        self._reason_cooldown_restored.add(project_id)
        for event in reversed(events):
            payload = event.payload if isinstance(event.payload, dict) else {}
            if (
                event.event_type != "audit_stall_detected"
                or payload.get("code") != "reason_noop_streak"
                or event.source_generation != project.project.source_generation
                or event.plan_revision != project.project.plan_revision
            ):
                continue
            occurred_at = self._timestamp_seconds(payload.get("occurred_at") or event.created_at)
            cooldown = payload.get("cooldown_seconds")
            if occurred_at is None:
                return
            try:
                until = occurred_at + max(0, int(cooldown))
            except (TypeError, ValueError):
                return
            if until > time.time():
                self._reason_cooldown_until[project_id] = until
            return

    def _observe_audit_idle_health(self, project: ProjectDetail) -> None:
        if project.project.audit_mode == "none":
            return
        if not hasattr(self, "_audit_idle_state"):
            self._audit_idle_state = {}
        if (
            project.project.status != "active"
            or self._project_open_intent_count(project) != 0
            or any(task.project_id == project.project.id for task in self.futures.values())
        ):
            self._audit_idle_state.pop(project.project.id, None)
            return

        project_id = project.project.id
        now = time.time()
        state = self._audit_idle_state.get(project_id)
        current_seq = project.project.event_seq
        if state is None:
            last_event_at = None
            latest_event = None
            if current_seq > 0:
                getter = getattr(getattr(self, "client", None), "get_audit_events", None)
                if getter is not None:
                    try:
                        events = getter(project_id, after=current_seq - 1, limit=1)
                        if events:
                            latest_event = events[-1]
                            last_event_at = self._timestamp_seconds(events[-1].created_at)
                    except Exception:
                        LOG.debug("latest audit event lookup failed project=%s", project_id, exc_info=True)
            if last_event_at is None:
                last_event_at = self._timestamp_seconds(project.project.created_at)
            state = {
                "event_seq": current_seq,
                "event_at": last_event_at if last_event_at is not None else now,
                "health_seq": (
                    latest_event.sequence
                    if latest_event is not None
                    and latest_event.event_type == "audit_stall_detected"
                    and isinstance(latest_event.payload, dict)
                    and latest_event.payload.get("code") == "no_event_progress"
                    and latest_event.source_generation == project.project.source_generation
                    and latest_event.plan_revision == project.project.plan_revision
                    else None
                ),
            }
            self._audit_idle_state[project_id] = state
        else:
            health_seq = state.get("health_seq")
            if current_seq > int(health_seq or state.get("event_seq") or 0):
                last_event_at = None
                getter = getattr(getattr(self, "client", None), "get_audit_events", None)
                if getter is not None:
                    try:
                        events = getter(project_id, after=current_seq - 1, limit=1)
                        if events:
                            last_event_at = self._timestamp_seconds(events[-1].created_at)
                    except Exception:
                        LOG.debug("latest audit event lookup failed project=%s", project_id, exc_info=True)
                state = {
                    "event_seq": current_seq,
                    "event_at": last_event_at if last_event_at is not None else now,
                    "health_seq": None,
                }
                self._audit_idle_state[project_id] = state

        idle_since = state.get("event_at")
        idle_limit = getattr(self.config.audit, "idle_stall_seconds", 1800)
        if idle_since is None or now - float(idle_since) < idle_limit:
            return
        if state.get("health_seq") is not None:
            return
        health_seq = self._append_runtime_health_event(
            project,
            "audit_stall_detected",
            "no_event_progress",
            {
                "event_seq": current_seq,
                "idle_seconds": idle_limit,
                "threshold_seconds": idle_limit,
                "occurred_at": datetime.fromtimestamp(
                    float(idle_since) + idle_limit, timezone.utc,
                ).isoformat().replace("+00:00", "Z"),
            },
        )
        state["health_seq"] = health_seq

    @staticmethod
    def _completion_sources(project: ProjectDetail) -> list[str]:
        """Select the gate-backed terminal facts for an atomic completion."""
        generation = project.project.source_generation
        current = [
            fact for fact in project.facts
            if fact.id not in {"origin", "goal"}
            and fact.source_generation == generation
        ]
        if project.project.audit_mode == "scope":
            summaries = [fact.id for fact in current if fact.type == "audit_summary"]
            return summaries[-1:]
        if project.project.audit_mode == "hypothesis":
            return [
                fact.id for fact in current
                if fact.status == "triaged"
                and (
                fact.type == "negative_assurance"
                or fact.semantic_type in {"confirmed_finding", "negative_assurance"}
                or (fact.type == "vulnerability" and fact.legacy)
                )
            ]
        return []

    def _commit_completion_gate(
        self, project: ProjectDetail, gate: CompletionGate,
    ) -> bool:
        if not gate.ready:
            return False
        sources = self._completion_sources(project)
        if not sources:
            return False
        response = self.client.complete(
            project.project.id,
            sources,
            (
                "Audit pipeline converged: required stages, managed Skill "
                "receipts, independent reviews, and terminal evidence passed "
                "the Completion Gate."
            ),
            "dispatcher.completion-gate",
        )
        if response.ok:
            LOG.info(
                "completion gate committed project=%s sources=%s",
                project.project.id,
                sources,
            )
            return True
        if response.status_code not in {403, 409}:
            LOG.warning(
                "completion gate commit failed project=%s status=%s body=%s",
                project.project.id,
                response.status_code,
                response.text,
            )
        return False

    def _complete_if_gate_ready(self, project: ProjectDetail) -> bool:
        """Permit only gate-backed completion when an audit budget is exhausted."""
        if (
            project.project.reason is not None
            or project.project.audit_mode == "none"
            or (
                project.project.completion_policy == "exhaustive"
                and self._project_open_intent_count(project) > 0
            )
            or not hasattr(self.client, "get_completion_gate")
        ):
            return False
        try:
            gate = self.client.get_completion_gate(project.project.id)
        except Exception as exc:
            LOG.warning(
                "completion gate read failed project=%s error=%s",
                project.project.id,
                exc,
            )
            return False
        return self._commit_completion_gate(project, gate)

    def _materialize_audit_intents(self, project: ProjectDetail) -> bool:
        if not self.config.audit.enabled or project.project.audit_mode == "none":
            return False
        workdir = Path(self.container_manager.ensure_running(project.project.id))
        # Keep only a small ready window on the blackboard. The complete audit
        # DAG remains derivable from facts, intents, and reviews.
        limit = min(8, max(1, self.config.runtime.max_project_workers * 2))
        open_managed = sum(
            audit_graph.managed_description(intent.description)
            and intent.to is None
            and intent.concluded_at is None
            for intent in project.intents
        )
        proposal_limit = limit - open_managed
        priority_scope_gate = (
            self.config.audit.scope_adjudication.enabled
            and project.project.audit_mode == "scope"
            and (
                (scope_evidence := scope_gate.result_for_intent(
                    project, scope_gate.EVIDENCE_INTENT,
                )) is None
                or not coverage.reviewed(project, scope_evidence.id)
                or (scope_adjudication := scope_gate.result_for_intent(
                    project, scope_gate.ADJUDICATION_INTENT,
                )) is None
                or not coverage.reviewed(project, scope_adjudication.id)
            )
        )
        if proposal_limit <= 0 and not priority_scope_gate:
            proposal_limit = 0

        # Proof mode is candidate-centric and bounded: the server derives one
        # highest-value obligation and suppresses duplicate open Intents. It
        # never creates a Fact or calls Technical Confirmation here.
        if hasattr(self.client, "plan_proof_gap") and proposal_limit > 0 and not priority_scope_gate:
            over_budget_candidates = audit_graph.candidate_budget_overflow_ids(
                project, self.config.audit.max_candidate_findings,
            )
            for fact in sorted(project.facts, key=lambda item: item.id):
                if (
                    fact.source_generation != project.project.source_generation
                    or fact.semantic_type != "candidate_finding"
                    or fact.id in over_budget_candidates
                ):
                    continue
                response = self.client.plan_proof_gap(project.project.id, fact.id)
                if response.ok and isinstance(response.data, dict):
                    if response.data.get("candidate_refuted"):
                        LOG.info(
                            "recorded unreachable negative control project=%s candidate=%s fact=%s reused=%s",
                            project.project.id, fact.id,
                            response.data.get("negative_control_fact_id"),
                            response.data.get("reused"),
                        )
                        return True
                    if response.data.get("created_intent"):
                        LOG.info("materialized proof-gap intent project=%s candidate=%s intent=%s", project.project.id, fact.id, response.data.get("intent_id"))
                        return True
                if response.status_code not in {200, 403, 409}:
                    LOG.warning("proof-gap planning failed project=%s candidate=%s status=%s body=%s", project.project.id, fact.id, response.status_code, response.text)
            if proposal_limit == 0:
                return False
        proposals = audit_graph.required_intents(
            project, workdir, self.config.audit,
            limit=1 if priority_scope_gate else proposal_limit,
        )
        created = 0
        known_intent_ids = {intent.id for intent in project.intents}
        for proposal in proposals:
            target = proposal.get("target")
            if target is None:
                prior = [
                    intent for intent in project.intents
                    if intent.description.strip() == proposal["description"].strip()
                    and intent.source_generation == project.project.source_generation
                    and intent.plan_revision == project.project.plan_revision
                ]
                any_historical = any(
                    intent.description.strip() == proposal["description"].strip()
                    for intent in project.intents
                )
                if prior or any_historical:
                    target = (
                        f"{proposal['description']}:generation:{project.project.source_generation}"
                        f":plan:{project.project.plan_revision}:attempt:{len(prior) + 1}"
                    )
                else:
                    target = proposal["description"]
            response = self.client.create_intent(
                project.project.id,
                proposal["from"],
                proposal["description"],
                audit_graph.CREATOR,
                action=proposal.get("action") or proposal.get("type"),
                target=target,
                intent_type=proposal.get("type"),
            )
            if response.status_code in {403, 409}:
                continue
            if not response.ok:
                LOG.warning(
                    "audit intent write failed project=%s status=%s body=%s description=%s",
                    project.project.id, response.status_code, response.text, proposal["description"],
                )
                continue
            response_intent_id = response.data.get("id") if isinstance(response.data, dict) else None
            if not isinstance(response_intent_id, str) or response_intent_id in known_intent_ids:
                continue
            known_intent_ids.add(response_intent_id)
            created += 1
        if created:
            LOG.info(
                "materialized graph-derived audit intents project=%s created=%s proposed=%s",
                project.project.id, created, len(proposals),
            )
        return created > 0

    def _reconcile_audit_stages(self, project: ProjectDetail) -> bool:
        """Converge the server-owned stage projection from graph/artifacts."""
        if not self.config.audit.enabled or project.project.audit_mode == "none":
            return False
        if not hasattr(self.client, "reconcile_audit_stages"):
            return False
        workdir = Path(self.container_manager.ensure_running(project.project.id))
        rows = stages.reconcile(self.config.audit, project, workdir)
        changed = stages.changed_rows(project, rows)
        if not changed:
            return False
        response = self.client.reconcile_audit_stages(
            project.project.id,
            rows,
            source_generation=project.project.source_generation,
            plan_revision=project.project.plan_revision,
        )
        if response.ok:
            LOG.debug(
                "reconciled audit stages project=%s changed=%s",
                project.project.id, len(changed),
            )
            return True
        if response.status_code not in {403, 409}:
            LOG.warning(
                "audit stage reconciliation failed project=%s status=%s body=%s",
                project.project.id, response.status_code, response.text,
            )
        return False

    @staticmethod
    def _intent_attempt(
        project: ProjectDetail,
        intent: Intent,
        *,
        task_type: str,
    ) -> int:
        """Derive an intent attempt from the append-only error history.

        A lease is an authorization token and is intentionally not part of
        execution identity.  Only the current unresolved error for this
        intent/task contributes; resolved history belongs to an older logical
        plan and must not advance a fresh attempt after restart.
        """
        current = [
            error
            for error in project.errors
            if (
                error.intent_id == intent.id
                and error.task_type == task_type
                and error.resolved_at is None
            )
        ]
        if not current:
            return 1
        return max(int(error.attempt_count) for error in current) + 1

    def _next_intent_attempt(
        self,
        project: ProjectDetail,
        intent: Intent,
        *,
        task_type: str,
    ) -> int:
        """Continue the correction ordinal across phases and re-dispatches.

        A failed attempt itself advances ``graph_revision`` when its error is
        recorded, so graph revision cannot scope this budget. Keep the ordinal
        within the same source generation and plan, which define the actual
        audit work item.
        """
        attempt = self._intent_attempt(project, intent, task_type=task_type)
        if task_type != "explore" or not (
            self.config.audit.enabled and project.project.audit_mode != "none"
        ):
            return attempt
        try:
            runs = self.client.list_runs(project.project.id)
        except Exception:
            LOG.exception(
                "could not restore result-correction attempt project=%s intent=%s",
                project.project.id, intent.id,
            )
            return attempt
        process_started_by_run = self._execution_attempt_process_states(project)
        prior_attempts = [
            int(value)
            for run in runs
            if self._run_value(run, "intent_id") == intent.id
            and not str(self._run_value(run, "task_type") or "").startswith("review")
            and self._run_value(run, "source_generation") == project.project.source_generation
            and self._run_value(run, "plan_revision") == project.project.plan_revision
            and process_started_by_run.get(self._run_value(run, "run_id")) is not False
            and (value := self._run_value(run, "attempt")) is not None
        ]
        return max(attempt, max(prior_attempts, default=0) + 1)

    def _execution_attempt_process_states(
        self, project: ProjectDetail,
    ) -> dict[str, bool]:
        """Read process-start metadata for runs in the current event snapshot.

        A cancelled or policy-blocked run that never started a worker process
        must not consume a result-correction attempt. Older runs without this
        event remain conservatively counted.
        """
        project_id = project.project.id
        through = int(getattr(project.project, "event_seq", 0) or 0)
        cache = getattr(self, "_execution_attempt_state_cache", None)
        if cache is None:
            cache = self._execution_attempt_state_cache = {}
        cache_key = (project_id, through)
        if cache_key in cache:
            return cache[cache_key]
        getter = getattr(getattr(self, "client", None), "get_audit_events", None)
        if getter is None or through <= 0:
            return {}

        states: dict[str, bool] = {}
        after = 0
        try:
            while after < through:
                page = getter(project_id, after=after, limit=2000)
                if not page:
                    break
                for event in page:
                    if (
                        event.sequence > through
                        or event.event_type != "execution_attempt_finished"
                        or not event.entity_id
                    ):
                        continue
                    started = event.payload.get("process_started")
                    if isinstance(started, bool):
                        states[event.entity_id] = started
                last = max(event.sequence for event in page)
                if last <= after:
                    break
                after = last
        except Exception:
            LOG.warning(
                "execution attempt metadata unavailable project=%s",
                project_id,
                exc_info=True,
            )
            return {}

        # Keep only the latest event snapshot per project to bound dispatcher
        # memory while avoiding repeated reads during one scheduler revision.
        for key in [key for key in cache if key[0] == project_id and key != cache_key]:
            cache.pop(key, None)
        cache[cache_key] = states
        return states

    def _reason_attempt(
        self,
        project: ProjectDetail,
        trigger: str,
    ) -> int:
        """Return the attempt encoded by a deterministic reason trigger."""
        match = re.search(r"(?:^|:)attempt:(\d+)(?:$|,)", trigger)
        if match is not None:
            return max(1, int(match.group(1)))
        return 1

    def _submit_task_runner(self, runner, *args, **kwargs):
        """Submit vNext kwargs without breaking legacy fake runners.

        Older embedders commonly replace task runners with positional-only
        fakes.  Filter only the additive contract keywords when the callable
        does not declare them; runners with ``**kwargs`` receive the full
        contract payload.
        """
        try:
            parameters = inspect.signature(runner).parameters.values()
        except (TypeError, ValueError):
            parameters = ()
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        if not accepts_kwargs:
            names = {
                parameter.name
                for parameter in parameters
                if parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            }
            kwargs = {name: value for name, value in kwargs.items() if name in names}
        return self.executor.submit(runner, *args, **kwargs)

    def _dispatch_reason(
        self,
        project: ProjectDetail,
        export_yaml: str,
        trigger: str,
        trigger_events: list[AuditEvent] | None = None,
    ) -> bool:
        if self._project_has_running_reason(project.project.id):
            self._log_changed(
                f"project:{project.project.id}:skip:reason_running",
                logging.DEBUG,
                "skip reason project=%s because a reason task is already running locally",
                project.project.id,
            )
            return False
        selection = self._select_worker(
            project.project.id,
            "reason",
            worker_preference=project.project.worker_preference,
        )
        worker = self._codex_audit_sandbox(selection.worker, project)
        if worker is None:
            self._log_changed(
                f"project:{project.project.id}:worker:reason",
                logging.INFO,
                "no worker available for reason project=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s",
                project.project.id,
                selection.blocked_busy,
                selection.blocked_unhealthy,
                selection.blocked_rejected,
            )
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:reason")
        lease_id = uuid.uuid4().hex
        attempt = self._reason_attempt(project, trigger)
        claim = self.client.claim_reason(project.project.id, worker.name, lease_id, trigger)
        if claim.status_code in (403, 409):
            level = logging.INFO if claim.status_code == 403 else logging.WARNING
            LOG.log(
                level,
                "reason claim failed project=%s worker=%s status=%s",
                project.project.id,
                worker.name,
                claim.status_code,
            )
            return False
        if not claim.ok:
            LOG.warning(
                "reason claim failed project=%s worker=%s status=%s",
                project.project.id,
                worker.name,
                claim.status_code,
            )
            return False
        cancellation = self._task_cancellation(project)
        try:
            future = self._submit_task_runner(
                run_reason_task,
                self.config,
                self.client,
                self.container_manager,
                project,
                export_yaml,
                worker,
                cancellation,
                lease_id=lease_id,
                trigger=trigger,
                trigger_events=trigger_events or [],
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit reason task project=%s worker=%s", project.project.id, worker.name)
            cancellation.close()
            self._best_effort_release_reason(project.project.id, worker.name, lease_id)
            return False
        self.futures[future] = RunningTask(
            project.project.id,
            "reason",
            worker.name,
            cancellation,
            intent_id=None,
            intent_count=len(project.intents),
            graph_revision=project.project.graph_revision,
            attempt=attempt,
            trigger=trigger,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info(
            "dispatched reason project=%s worker=%s trigger=%s",
            project.project.id, worker.name, trigger,
        )
        return True

    def _dispatch_explore(self, project: ProjectDetail, export_yaml: str, intent: Intent) -> bool:
        provider_required = self._explore_requires_provider(project, intent)
        codeql_scan = (
            self.config.audit.enabled
            and codeql.active_for_project(project, self.config.audit.codeql)
            and project.project.audit_mode == "scope"
            and codeql.is_intent(intent)
        )
        dynamic_recipe = (
            self.config.audit.enabled
            and self.config.audit.semantic.enabled
            and project.project.audit_mode == "scope"
            and audit_recipes.is_dynamic_recipe_intent(intent)
        )
        selection = self._select_worker(
            project.project.id,
            "explore",
            # Deterministic snapshot collection does not call an LLM. All
            # provider-backed work honors the project's explicit CLI choice,
            # including repository-wide reconnaissance.
            worker_preference=project.project.worker_preference,
            provider_required=provider_required,
            worker_health_required=not (codeql_scan or dynamic_recipe),
        )
        worker = self._codex_audit_sandbox(selection.worker, project, intent)
        if worker is None:
            self._log_changed(
                f"project:{project.project.id}:worker:explore",
                logging.INFO,
                "no worker available for explore project=%s intent=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s",
                project.project.id,
                intent.id,
                selection.blocked_busy,
                selection.blocked_unhealthy,
                selection.blocked_rejected,
            )
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:explore")
        trigger = f"explore:intent:{intent.id}"
        attempt = self._next_intent_attempt(project, intent, task_type="explore")
        claim = self.client.heartbeat(project.project.id, intent.id, worker.name)
        if claim.status_code in (403, 409):
            level = logging.INFO if claim.status_code == 403 else logging.WARNING
            LOG.log(
                level,
                "explore claim failed project=%s intent=%s worker=%s status=%s",
                project.project.id,
                intent.id,
                worker.name,
                claim.status_code,
            )
            return False
        if not claim.ok:
            LOG.warning(
                "explore claim failed project=%s intent=%s worker=%s status=%s",
                project.project.id,
                intent.id,
                worker.name,
                claim.status_code,
            )
            return False
        cancellation = self._task_cancellation(project)
        try:
            future = self._submit_task_runner(
                run_explore_task,
                self.config,
                self.client,
                self.container_manager,
                project,
                export_yaml,
                intent,
                worker,
                cancellation,
                trigger=trigger,
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit explore task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
            cancellation.close()
            self._best_effort_release(project.project.id, intent.id, worker.name)
            return False
        self.futures[future] = RunningTask(
            project.project.id,
            "explore",
            worker.name,
            cancellation,
            intent_id=intent.id,
            provider_required=provider_required,
            attempt=attempt,
            trigger=trigger,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info("dispatched explore project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        return True

    def _dispatch_review(self, project: ProjectDetail, export_yaml: str, intent: Intent) -> bool:
        """Spawn a review task for a candidate fact.

        Mirrors `_dispatch_explore` but for `task_type=review`. The worker
        reads the candidate fact (intent.from[0]), runs the `vuln_audit/review.md`
        prompt as a devil's advocate, and POSTs a Review. The fact's status
        is re-aggregated server-side on every review write.
        """
        selection = self._select_worker(
            project.project.id,
            "review",
            worker_preference=project.project.worker_preference,
        )
        worker = self._codex_audit_sandbox(selection.worker, project, intent)
        if worker is None:
            self._log_changed(
                f"project:{project.project.id}:worker:review",
                logging.INFO,
                "no worker available for review project=%s intent=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s",
                project.project.id,
                intent.id,
                selection.blocked_busy,
                selection.blocked_unhealthy,
                selection.blocked_rejected,
            )
            return False
        self._clear_log_state(f"project:{project.project.id}:worker:review")
        trigger = f"review:intent:{intent.id}"
        attempt = self._intent_attempt(project, intent, task_type="review")
        claim = self.client.heartbeat(project.project.id, intent.id, worker.name)
        if claim.status_code in (403, 409):
            level = logging.INFO if claim.status_code == 403 else logging.WARNING
            LOG.log(
                level,
                "review claim failed project=%s intent=%s worker=%s status=%s",
                project.project.id, intent.id, worker.name, claim.status_code,
            )
            return False
        if not claim.ok:
            LOG.warning(
                "review claim failed project=%s intent=%s worker=%s status=%s",
                project.project.id, intent.id, worker.name, claim.status_code,
            )
            return False
        cancellation = self._task_cancellation(project)
        try:
            future = self._submit_task_runner(
                run_review_task,
                self.config,
                self.client,
                self.container_manager,
                project,
                export_yaml,
                intent,
                worker,
                cancellation,
                trigger=trigger,
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit review task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
            cancellation.close()
            self._best_effort_release(project.project.id, intent.id, worker.name)
            return False
        self.futures[future] = RunningTask(
            project.project.id,
            "review",
            worker.name,
            cancellation,
            intent_id=intent.id,
            attempt=attempt,
            trigger=trigger,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info("dispatched review project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        return True

    @staticmethod
    def _codex_audit_sandbox(
        worker: WorkerConfig | None,
        project: ProjectDetail,
        intent: Intent | None = None,
    ) -> WorkerConfig | None:
        """Default Codex audit work to read-only unless the operator opted out.

        The OS sandbox (``--sandbox read-only``) is the only read-only
        mechanism Codex exposes, so it stays the safe default for audit
        tasks. An explicit ``sandbox_mode`` in dispatch.yaml always wins: on
        hosts that cannot apply a restrictive Seatbelt profile the operator
        must disclose a different isolation strategy rather than silently
        lose the worker, and the choice is visible in config review.
        ``poc:isolated`` runs execute inside the disposable Docker sandbox,
        where read-only would block the reproduction.
        """
        if worker is None or project.project.audit_mode == "none":
            return worker
        if worker.type != "codex" or worker.sandbox_mode is not None:
            return worker
        if intent is not None and (intent.type or "").startswith("poc:isolated"):
            return worker
        return worker.model_copy(update={"sandbox_mode": "read-only"})

    def _select_worker(
        self,
        project_id: str,
        task_type: str,
        *,
        worker_preference: str = "auto",
        provider_required: bool = True,
        worker_health_required: bool = True,
    ) -> WorkerSelection:
        now = time.time()
        candidates: list[WorkerConfig] = []
        blocked_busy: list[str] = []
        blocked_unhealthy: list[str] = []
        blocked_rejected: list[str] = []
        blocked_task_type: list[str] = []
        running_counts = self._worker_counts()
        if worker_preference != "auto" and not any(
            worker.type == worker_preference and task_type in worker.task_types
            for worker in self.config.workers
        ):
            return WorkerSelection(
                worker=None,
                blocked_busy=[],
                blocked_unhealthy=[],
                blocked_rejected=[],
                blocked_task_type=[
                    f"preferred CLI {worker_preference} is not configured for {task_type}"
                ],
            )
        for worker in self.config.workers:
            if worker_preference != "auto" and worker.type != worker_preference:
                continue
            if task_type not in worker.task_types:
                blocked_task_type.append(worker.name)
                continue
            running = running_counts.get(worker.name, 0)
            if running >= worker.max_running:
                blocked_busy.append(f"{worker.name}({running}/{worker.max_running})")
                continue
            unhealthy_until = self.worker_unhealthy_until.get(worker.name, 0)
            if worker_health_required and unhealthy_until > now:
                blocked_unhealthy.append(f"{worker.name}({unhealthy_until - now:.1f}s)")
                continue
            provider_until = getattr(self, "worker_provider_until", {}).get(worker.name, 0)
            if provider_required and provider_until > now:
                reason = getattr(self, "worker_provider_reason", {}).get(worker.name, "unavailable")
                # Keep the selection summary stable across polling cycles.
                # The exact retry window is logged once when the circuit opens;
                # including a live countdown here would defeat `_log_changed`.
                blocked_unhealthy.append(f"{worker.name}(provider:{reason})")
                continue
            if provider_until and provider_until <= now:
                self.worker_provider_until.pop(worker.name, None)
                self.worker_provider_reason.pop(worker.name, None)
                getattr(self, "worker_provider_opened_at", {}).pop(worker.name, None)
                self._persist_provider_circuits()
            rejected_until = self.worker_rejected_until.get((project_id, task_type, worker.name), 0)
            if worker_health_required and rejected_until > now:
                blocked_rejected.append(f"{worker.name}({rejected_until - now:.1f}s)")
                continue
            candidates.append(worker)
        if not candidates:
            LOG.debug(
                "worker selection project=%s task=%s no candidates blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s blocked_task_type=%s",
                project_id,
                task_type,
                blocked_busy,
                blocked_unhealthy,
                blocked_rejected,
                blocked_task_type,
            )
            return WorkerSelection(
                worker=None,
                blocked_busy=blocked_busy,
                blocked_unhealthy=blocked_unhealthy,
                blocked_rejected=blocked_rejected,
                blocked_task_type=blocked_task_type,
            )
        ordered = choose_worker(candidates, running_counts)
        LOG.debug(
            "worker selection project=%s task=%s candidates=%s blocked_busy=%s blocked_unhealthy=%s blocked_rejected=%s blocked_task_type=%s chosen=%s",
            project_id,
            task_type,
            [f"{worker.name}({running_counts.get(worker.name, 0)}/{worker.max_running})" for worker in candidates],
            blocked_busy,
            blocked_unhealthy,
            blocked_rejected,
            blocked_task_type,
            ordered[0].name if ordered else None,
        )
        return WorkerSelection(
            worker=ordered[0] if ordered else None,
            blocked_busy=blocked_busy,
            blocked_unhealthy=blocked_unhealthy,
            blocked_rejected=blocked_rejected,
            blocked_task_type=blocked_task_type,
        )

    def _explore_requires_provider(self, project: ProjectDetail, intent: Intent) -> bool:
        """Keep deterministic audit work runnable during an LLM outage."""
        description = intent.description.strip()
        scope_audit = self.config.audit.enabled and project.project.audit_mode == "scope"
        if not scope_audit:
            return True
        if (
            self.config.audit.scope_adjudication.enabled
            and scope_gate.is_evidence_intent(intent)
        ):
            return False
        if self.config.audit.recon_active and description == "@analysis:recon-snapshot":
            return False
        if codeql.active_for_project(project, self.config.audit.codeql) and codeql.is_intent(intent):
            return False
        if (
            self.config.audit.semantic.enabled
            and audit_recipes.is_dynamic_recipe_intent(intent)
        ):
            return False
        return description != audit_graph.AUDIT_SUMMARY_INTENT

    def _scope_evidence_review_pending(self, project: ProjectDetail) -> bool:
        if not (
            self.config.audit.scope_adjudication.enabled
            and project.project.audit_mode == "scope"
        ):
            return False
        evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
        return (
            evidence is None
            or evidence.type != scope_gate.POLICY_EVIDENCE_TYPE
            or not coverage.reviewed(project, evidence.id)
        )

    def _scope_gate_pending(self, project: ProjectDetail) -> bool:
        if not (
            self.config.audit.scope_adjudication.enabled
            and project.project.audit_mode == "scope"
        ):
            return False
        if self._scope_evidence_review_pending(project):
            return True
        adjudication = scope_gate.result_for_intent(
            project, scope_gate.ADJUDICATION_INTENT,
        )
        return (
            adjudication is None
            or adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE
            or not coverage.reviewed(project, adjudication.id)
        )

    @staticmethod
    def _intent_error_allows_dispatch(
        project: ProjectDetail, intent: Intent,
    ) -> bool:
        error = next(
            (
                item for item in reversed(project.errors)
                if item.intent_id == intent.id and item.resolved_at is None
            ),
            None,
        )
        if error is None:
            return True
        if error.classification == "blocked":
            return False
        if not error.retry_at:
            return True
        try:
            retry_at = datetime.fromisoformat(error.retry_at.replace("Z", "+00:00"))
        except ValueError:
            LOG.warning(
                "invalid intent error retry timestamp project=%s intent=%s error=%s retry_at=%s",
                project.project.id,
                intent.id,
                error.id,
                error.retry_at,
            )
            return False
        return retry_at <= datetime.now(timezone.utc)

    def _provider_circuit_path(self) -> Path | None:
        root = self.config.local.workspace_root
        if root is None:
            return None
        return Path(root).expanduser() / ".linen-provider-circuits.json"

    def _honor_manual_provider_retries(self, project: ProjectDetail) -> None:
        """Let an explicit Retry now bypass one persisted provider cooldown."""
        seen = getattr(self, "_manual_provider_retries_seen", None)
        if seen is None:
            seen = self._manual_provider_retries_seen = set()
        changed = False
        for error in project.errors:
            if (
                error.id in seen
                or error.resolved_at is None
                or not (error.resolution or "").startswith("manual retry requested by ")
            ):
                continue
            seen.add(error.id)
            try:
                resolved_at = datetime.fromisoformat(
                    error.resolved_at.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                continue
            worker_names = [error.worker] if error.worker else list(self.worker_provider_until)
            for worker_name in worker_names:
                if not worker_name:
                    continue
                until = self.worker_provider_until.get(worker_name, 0)
                reason = self.worker_provider_reason.get(worker_name)
                retry_window = (
                    QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS
                    if reason == "quota_exhausted"
                    else RATE_LIMIT_RETRY_AFTER_SECONDS
                )
                if until <= 0 or resolved_at < until - retry_window:
                    continue
                self.worker_provider_until.pop(worker_name, None)
                self.worker_provider_reason.pop(worker_name, None)
                getattr(self, "worker_provider_opened_at", {}).pop(worker_name, None)
                getattr(self, "worker_provider_origin", {}).pop(worker_name, None)
                changed = True
                LOG.info(
                    "manual retry cleared provider circuit project=%s intent=%s worker=%s",
                    project.project.id,
                    error.intent_id,
                    worker_name,
                )
        if changed:
            self._persist_provider_circuits()

    def _honor_project_worker_issue_resumes(self, project: ProjectDetail) -> None:
        """Clear provider cooldowns for workers explicitly resumed by an operator."""
        getter = getattr(getattr(self, "client", None), "get_audit_events", None)
        if getter is None:
            return
        project_id = project.project.id
        through = int(getattr(project.project, "event_seq", 0) or 0)
        cursors = getattr(self, "_provider_resume_event_cursors", None)
        if cursors is None:
            cursors = self._provider_resume_event_cursors = {}
        after = cursors.get(project_id, 0)
        if after >= through:
            return

        events: list[AuditEvent] = []
        try:
            while after < through:
                page = getter(project_id, after=after, limit=2000)
                if not page:
                    break
                events.extend(event for event in page if event.sequence <= through)
                last = max(event.sequence for event in page)
                if last <= after:
                    break
                after = last
        except Exception:
            LOG.warning(
                "provider resume events unavailable project=%s",
                project_id,
                exc_info=True,
            )
            return
        cursors[project_id] = min(after, through)

        opened_at = getattr(self, "worker_provider_opened_at", {})
        origins = getattr(self, "worker_provider_origin", None)
        if origins is None:
            origins = self.worker_provider_origin = {}
        changed = False
        for event in events:
            if event.event_type != "project_worker_issue_resumed":
                continue
            issues = event.payload.get("worker_issues")
            if not isinstance(issues, list):
                continue
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                worker_name = issue.get("worker")
                if not isinstance(worker_name, str) or not worker_name:
                    continue
                until = self.worker_provider_until.get(worker_name, 0)
                if until <= 0:
                    continue
                origin = origins.get(worker_name)
                if origin is not None:
                    origin_project_id, blocked_event_seq = origin
                    if (
                        origin_project_id != project_id
                        or event.sequence <= blocked_event_seq
                    ):
                        continue
                else:
                    # Older circuit files have no event provenance. Retain the
                    # timestamp guard for those files only.
                    try:
                        resumed_at = datetime.fromisoformat(
                            event.created_at.replace("Z", "+00:00")
                        ).timestamp()
                    except (AttributeError, ValueError):
                        continue
                    circuit_opened_at = opened_at.get(worker_name)
                    if circuit_opened_at is not None and resumed_at < circuit_opened_at:
                        continue
                self.worker_provider_until.pop(worker_name, None)
                self.worker_provider_reason.pop(worker_name, None)
                opened_at.pop(worker_name, None)
                origins.pop(worker_name, None)
                changed = True
                LOG.info(
                    "project worker issue resume cleared provider circuit project=%s worker=%s",
                    project_id,
                    worker_name,
                )
        if changed:
            self._persist_provider_circuits()

    def _restore_provider_circuits(self) -> None:
        if getattr(self, "worker_provider_opened_at", None) is None:
            self.worker_provider_opened_at = {}
        if getattr(self, "worker_provider_origin", None) is None:
            self.worker_provider_origin = {}
        path = self._provider_circuit_path()
        if path is None or not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            workers = payload.get("workers", {}) if isinstance(payload, dict) else {}
            configured = {worker.name for worker in self.config.workers}
            now = time.time()
            for worker_name, state in workers.items():
                if worker_name not in configured or not isinstance(state, dict):
                    continue
                until = float(state.get("until", 0))
                reason = state.get("reason")
                if until <= now or reason not in {"rate_limited", "quota_exhausted"}:
                    continue
                self.worker_provider_until[worker_name] = until
                self.worker_provider_reason[worker_name] = reason
                opened_at = state.get("opened_at")
                if isinstance(opened_at, (int, float)):
                    self.worker_provider_opened_at[worker_name] = float(opened_at)
                else:
                    retry_window = (
                        QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS
                        if reason == "quota_exhausted"
                        else RATE_LIMIT_RETRY_AFTER_SECONDS
                    )
                    self.worker_provider_opened_at[worker_name] = max(
                        0.0, until - retry_window,
                    )
                origin_project_id = state.get("origin_project_id")
                origin_blocked_event_seq = state.get("origin_blocked_event_seq")
                if (
                    isinstance(origin_project_id, str)
                    and origin_project_id
                    and isinstance(origin_blocked_event_seq, int)
                    and not isinstance(origin_blocked_event_seq, bool)
                    and origin_blocked_event_seq >= 0
                ):
                    self.worker_provider_origin[worker_name] = (
                        origin_project_id, origin_blocked_event_seq,
                    )
                LOG.warning(
                    "restored worker provider circuit worker=%s outcome=%s retry_in=%.0fs",
                    worker_name,
                    reason,
                    until - now,
                )
        except (OSError, TypeError, ValueError) as exc:
            LOG.warning("provider circuit restore failed path=%s error=%s", path, exc)

    def _persist_provider_circuits(self) -> None:
        path = self._provider_circuit_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            origins = getattr(self, "worker_provider_origin", {})
            payload = {
                "schema_version": 2,
                "workers": {
                    worker_name: {
                        "until": until,
                        "reason": self.worker_provider_reason.get(worker_name, "unavailable"),
                        "opened_at": getattr(self, "worker_provider_opened_at", {}).get(worker_name),
                        "origin_project_id": (
                            origins[worker_name][0] if worker_name in origins else None
                        ),
                        "origin_blocked_event_seq": (
                            origins[worker_name][1] if worker_name in origins else None
                        ),
                    }
                    for worker_name, until in self.worker_provider_until.items()
                    if until > time.time()
                },
            }
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            temporary.replace(path)
        except (OSError, TypeError, ValueError) as exc:
            LOG.warning("provider circuit persist failed path=%s error=%s", path, exc)

    def _worker_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for task in self.futures.values():
            counts[task.worker_name] = counts.get(task.worker_name, 0) + 1
        return counts

    def _project_running_task_count(self, project_id: str) -> int:
        return sum(1 for task in self.futures.values() if task.project_id == project_id)

    def _project_running_task_summary(self, project_id: str) -> list[str]:
        summary: list[str] = []
        for task in self.futures.values():
            if task.project_id != project_id:
                continue
            if task.intent_id is None:
                summary.append(f"{task.task_type}:{task.worker_name}")
            else:
                summary.append(f"{task.task_type}:{task.worker_name}:{task.intent_id}")
        summary.sort()
        return summary

    def _project_has_running_reason(self, project_id: str) -> bool:
        return any(task.project_id == project_id and task.task_type == "reason" for task in self.futures.values())

    def _project_running_explore_intents(self, project_id: str) -> set[str]:
        return {
            task.intent_id
            for task in self.futures.values()
            if task.project_id == project_id and task.task_type == "explore" and task.intent_id is not None
        }

    def _running_project_count(self, summaries: list[ProjectSummary]) -> int:
        active_ids = {summary.id for summary in summaries if summary.status == "active"}
        return len(self.runtime_project_ids & active_ids)

    def _project_open_intent_count(self, project: ProjectDetail) -> int:
        return sum(1 for intent in project.intents if intent.to is None and intent.concluded_at is None)

    def _dispatchable_open_intent_count(self, project: ProjectDetail) -> int:
        """Open intents the scheduler could actually pick up.

        Mirrors the dispatch gate (`_intent_error_allows_dispatch`) so an audit
        whose only open intents are withheld by an unresolved error is treated
        as stalled rather than as having pending work.
        """
        return sum(
            1 for intent in project.intents
            if intent.to is None
            and intent.concluded_at is None
            and self._intent_error_allows_dispatch(project, intent)
        )

    def _reason_trigger_events(self, project: ProjectDetail, trigger: str) -> list[AuditEvent]:
        match = re.fullmatch(r"events:(\d+)->(\d+)", trigger)
        getter = getattr(getattr(self, "client", None), "get_audit_events", None)
        if match is None or getter is None:
            return []
        after, through = (int(value) for value in match.groups())
        events: list[AuditEvent] = []
        try:
            while after < through:
                page = getter(project.project.id, after=after, limit=2000)
                if not page:
                    break
                events.extend(event for event in page if event.sequence <= through)
                last = max(event.sequence for event in page)
                if last <= after:
                    break
                after = last
        except Exception:
            LOG.exception("reason trigger event lookup failed project=%s trigger=%s", project.project.id, trigger)
        return events

    def _reason_may_run(
        self, project: ProjectDetail, trigger_events: list[AuditEvent] | None = None,
    ) -> bool:
        """Wake strategy for security-significant evidence, not routine coverage churn."""
        open_intents = [
            intent for intent in project.intents
            if intent.to is None and intent.concluded_at is None
        ]
        no_open_intents = not open_intents
        facts_by_id = {fact.id: fact for fact in project.facts}
        strategy_fact_types = {
            "candidate_finding", "confirmed_finding", "negative_assurance",
            "candidate_disposition", "source", "sink", "dataflow",
            "sanitizer", "validation", "reachability", "recon",
            "scope", "hypothesis",
        }
        for event in trigger_events or []:
            if event.event_type in {
                "audit_task_abandoned", "technical_confirmation",
                "dynamic_verification_pass", "proof_strategy_replan_required",
                "human_hint_created",
            }:
                return True
            if event.event_type == "audit_task_failed":
                classification = event.payload.get("classification")
                if classification in {"blocked", "permanent"} or event.payload.get("retry_at") is None:
                    return True
            if event.event_type not in {"audit_task_concluded", "review_created"}:
                continue
            fact_id = event.payload.get("fact_id")
            fact = facts_by_id.get(fact_id) if isinstance(fact_id, str) else None
            if fact is None:
                continue
            # Generic explore facts carry their typed evidence in `type`
            # (for example `reachability` or `dataflow`) while their
            # `semantic_type` is commonly the broader value `observation`.
            # Check both fields so newly concluded evidence wakes Reason and
            # can advance the audit instead of leaving the project idle.
            if (
                fact.semantic_type in strategy_fact_types
                or fact.type in strategy_fact_types
                or fact.type in {
                    "candidate_disposition", "vulnerability", "negative_assurance",
                    "policy_evidence", "scope_adjudication", "hypothesis_batch",
                    "variant_batch",
                }
            ):
                return True
            if event.event_type == "audit_task_concluded" and fact.type == "coverage_result":
                try:
                    evidence = json.loads(fact.evidence or "{}")
                except (TypeError, ValueError):
                    continue
                if evidence.get("outcome") in {"needs_followup", "blocked"} or evidence.get("leads"):
                    return True
        if no_open_intents:
            # The first Reason pass seeds a new project. Later, run lifecycle
            # events from a failed Reason attempt alone must not create a loop.
            return project.project.reason_last_seen_event_seq == 0
        for intent in open_intents:
            blocked = any(
                error.intent_id == intent.id
                and error.resolved_at is None
                and error.classification == "blocked"
                for error in project.errors
            )
            if intent.worker is not None or not blocked:
                return False
        return True

    def _reason_trigger(self, project: ProjectDetail) -> str | None:
        if project.project.event_seq > project.project.reason_last_seen_event_seq:
            return (
                f"events:{project.project.reason_last_seen_event_seq}"
                f"->{project.project.event_seq}"
            )
        return None

    @staticmethod
    def _reason_has_priority_wake(
        project: ProjectDetail, trigger_events: list[AuditEvent],
    ) -> bool:
        """Events with fresh safety evidence may pass a no-op cooldown."""
        if not trigger_events:
            return False
        significant = {
            "audit_task_abandoned", "technical_confirmation",
            "dynamic_verification_pass", "proof_strategy_replan_required",
            "human_hint_created",
        }
        if any(event.event_type in significant for event in trigger_events):
            return True
        if any(
            event.event_type == "audit_task_failed"
            and (
                event.payload.get("classification") in {"blocked", "permanent"}
                or event.payload.get("retry_at") is None
            )
            for event in trigger_events
        ):
            return True
        facts_by_id = {fact.id: fact for fact in project.facts}
        priority_fact_types = {
            "candidate_finding", "confirmed_finding", "vulnerability",
            "negative_assurance", "candidate_disposition", "dataflow",
            "reachability", "recon", "hypothesis_batch", "variant_batch",
            "policy_evidence", "scope_adjudication",
        }
        for event in trigger_events:
            if event.event_type not in {"audit_task_concluded", "review_created"}:
                continue
            fact_id = event.payload.get("fact_id")
            fact = facts_by_id.get(fact_id) if isinstance(fact_id, str) else None
            if fact is not None and (
                fact.semantic_type in {"candidate_finding", "confirmed_finding", "negative_assurance", "scope", "hypothesis"}
                or fact.type in priority_fact_types
            ):
                return True
        return False

    def _reason_waits_for_initial_recon(
        self, project: ProjectDetail, trigger_events: list[AuditEvent],
    ) -> bool:
        """Batch scope-mode Recon warmup events until configured lenses return.

        This deliberately inspects only current-generation/plan graph rows; it
        does not open Recon artifacts or write additional protocol facts.
        """
        audit = getattr(getattr(self, "config", None), "audit", None)
        recon_config = getattr(audit, "recon", None)
        if (
            project.project.audit_mode != "scope"
            or recon_config is None
            or not recon.active_for_project(project, recon_config)
            or not trigger_events
        ):
            return False

        # Human direction, terminal failures, candidate facts, and explicit
        # security evidence must never wait for the Recon bootstrap barrier.
        if self._reason_has_non_warmup_priority(project, trigger_events):
            return False

        current_intents = [
            intent for intent in project.intents
            if intent.source_generation == project.project.source_generation
            and intent.plan_revision == project.project.plan_revision
        ]
        managed_descriptions = {
            recon.SNAPSHOT_INTENT,
            codeql.INTENT,
            scope_gate.EVIDENCE_INTENT,
            scope_gate.ADJUDICATION_INTENT,
        }
        has_managed_work = any(
            intent.to is None
            and intent.concluded_at is None
            and (
                intent.description.strip() in managed_descriptions
                or intent.description.strip().startswith(codeql.QUERY_PREFIX)
                or recon.category_from_description(intent.description) is not None
            )
            for intent in current_intents
        )
        if not has_managed_work:
            return False

        initial_incomplete = False
        for category in recon_config.categories:
            fact = recon.latest_category_fact(project, category)
            if fact is None or fact.source_generation != project.project.source_generation:
                initial_incomplete = True
                continue
            producer = next((intent for intent in current_intents if intent.to == fact.id), None)
            if producer is None:
                initial_incomplete = True
        if not initial_incomplete:
            return False

        # Delay only event batches wholly explained by bootstrap/preflight,
        # policy evidence, or a managed Recon/CodeQL result. A mixed batch may
        # contain a fresh reason to act, so let normal evidence gating decide.
        for event in trigger_events:
            if event.event_type not in {"audit_task_concluded", "review_created"}:
                return False
            fact_id = event.payload.get("fact_id")
            if not isinstance(fact_id, str):
                return False
            fact = next((item for item in project.facts if item.id == fact_id), None)
            if fact is None:
                return False
            if fact.type in {"policy_evidence", "bootstrap", "preflight", "source_preflight"}:
                continue
            producer = next((intent for intent in current_intents if intent.to == fact.id), None)
            if producer is None:
                return False
            if fact.type == "recon" and (
                recon.category_from_description(producer.description) is not None
                or producer.description.strip() == "@analysis:codeql-path-candidates"
                or producer.description.strip().startswith("@analysis:codeql-query:")
            ):
                continue
            return False
        return True

    @staticmethod
    def _reason_has_non_warmup_priority(
        project: ProjectDetail, trigger_events: list[AuditEvent],
    ) -> bool:
        if any(
            event.event_type in {
                "human_hint_created", "audit_task_abandoned", "technical_confirmation",
                "dynamic_verification_pass", "proof_strategy_replan_required",
            }
            or event.event_type == "audit_task_failed" and (
                event.payload.get("classification") in {"blocked", "permanent"}
                or event.payload.get("retry_at") is None
            )
            for event in trigger_events
        ):
            return True
        facts_by_id = {fact.id: fact for fact in project.facts}
        urgent_types = {
            "candidate_finding", "confirmed_finding", "vulnerability",
            "negative_assurance", "candidate_disposition", "source", "sink",
            "dataflow", "sanitizer", "validation", "reachability",
            "scope_adjudication", "hypothesis_batch", "variant_batch",
        }
        return any(
            event.event_type in {"audit_task_concluded", "review_created"}
            and isinstance((fact_id := event.payload.get("fact_id")), str)
            and (fact := facts_by_id.get(fact_id)) is not None
            and (
                fact.type in urgent_types
                or fact.semantic_type in urgent_types
                or fact.type == "recon" and DispatcherLoop._recon_fact_has_leads(fact)
            )
            for event in trigger_events
        )

    @staticmethod
    def _recon_fact_has_leads(fact) -> bool:
        """Read the exported summary only; do not open provider artifacts."""
        evidence = fact.evidence if isinstance(fact.evidence, str) else ""
        for label in ("leads", "candidates"):
            match = re.search(rf"(?m)^{label}:\s*(\d+)\b", evidence)
            if match and int(match.group(1)) > 0:
                return True
        return False

    def _reap_futures(self) -> None:
        # Some embedders and older tests construct the loop without calling
        # ``__init__``; lazily establish the new circuit state for backwards
        # compatibility with that supported pattern.
        if not hasattr(self, "worker_provider_until"):
            self.worker_provider_until = {}
        if not hasattr(self, "worker_provider_reason"):
            self.worker_provider_reason = {}
        if not hasattr(self, "_reason_noop_streak"):
            self._reason_noop_streak = {}
        if not hasattr(self, "_reason_cooldown_until"):
            self._reason_cooldown_until = {}
        done = [future for future in self.futures if future.done()]
        for future in done:
            task = self.futures.pop(future)
            try:
                outcome = future.result()
                if outcome == "cancelled":
                    LOG.info(
                        "task cancelled project=%s task=%s worker=%s",
                        task.project_id,
                        task.task_type,
                        task.worker_name,
                    )
                elif outcome not in {"success", "noop"}:
                    LOG.warning(
                        "task finished project=%s task=%s worker=%s outcome=%s",
                        task.project_id,
                        task.task_type,
                        task.worker_name,
                        outcome,
                    )
                self._clear_project_log_state(task.project_id)
                if outcome == "unhealthy":
                    retry_after_seconds = UNHEALTHY_RETRY_AFTER_SECONDS
                    self.worker_unhealthy_until[task.worker_name] = time.time() + retry_after_seconds
                    LOG.info(
                        "worker marked unhealthy worker=%s retry_after=%.0fs",
                        task.worker_name,
                        retry_after_seconds,
                    )
                else:
                    self.worker_unhealthy_until.pop(task.worker_name, None)
                if outcome in {"rate_limited", "quota_exhausted"}:
                    retry_after_seconds = (
                        QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS
                        if outcome == "quota_exhausted"
                        else RATE_LIMIT_RETRY_AFTER_SECONDS
                    )
                    now = time.time()
                    provider_until = now + retry_after_seconds
                    opened_at = getattr(self, "worker_provider_opened_at", None)
                    if opened_at is None:
                        opened_at = self.worker_provider_opened_at = {}
                    current_until = self.worker_provider_until.get(task.worker_name, 0)
                    current_reason = self.worker_provider_reason.get(task.worker_name)
                    new_episode = current_until <= now or current_reason != outcome
                    if new_episode:
                        opened_at[task.worker_name] = now
                    origins = getattr(self, "worker_provider_origin", None)
                    if origins is not None and (new_episode or outcome == "quota_exhausted"):
                        origins.pop(task.worker_name, None)
                    self.worker_provider_until[task.worker_name] = max(
                        self.worker_provider_until.get(task.worker_name, 0),
                        provider_until,
                    )
                    self.worker_provider_reason[task.worker_name] = outcome
                    self._persist_provider_circuits()
                    LOG.warning(
                        "worker provider circuit opened worker=%s outcome=%s retry_after=%.0fs",
                        task.worker_name,
                        outcome,
                        retry_after_seconds,
                    )
                elif outcome in {"success", "noop"} and task.provider_required:
                    removed = self.worker_provider_until.pop(task.worker_name, None)
                    self.worker_provider_reason.pop(task.worker_name, None)
                    getattr(self, "worker_provider_opened_at", {}).pop(task.worker_name, None)
                    getattr(self, "worker_provider_origin", {}).pop(task.worker_name, None)
                    if removed is not None:
                        self._persist_provider_circuits()
                rejection_key = (task.project_id, task.task_type, task.worker_name)
                if outcome == "rejected":
                    retry_after_seconds = REJECTED_RETRY_AFTER_SECONDS
                    self.worker_rejected_until[rejection_key] = time.time() + retry_after_seconds
                    LOG.info(
                        "worker marked rejected project=%s task=%s worker=%s retry_after=%.0fs",
                        task.project_id,
                        task.task_type,
                        task.worker_name,
                        retry_after_seconds,
                    )
                else:
                    self.worker_rejected_until.pop(rejection_key, None)
                if task.task_type == "reason":
                    if outcome == "noop":
                        self._observe_reason_noop(task)
                    elif outcome == "success":
                        self._reason_noop_streak.pop(task.project_id, None)
                        self._reason_cooldown_until.pop(task.project_id, None)
                if outcome in PROJECT_PAUSING_CLI_ISSUES:
                    self._pause_project_for_cli_issue(task, outcome)
                elif outcome not in {"success", "noop", "cancelled", "blocked"}:
                    self._record_intent_error(task, outcome)
            except Exception as exc:
                LOG.exception("task crashed project=%s task=%s worker=%s", task.project_id, task.task_type, task.worker_name)
                self._record_intent_error(task, "task_crashed", detail=str(exc))
            finally:
                task.cancellation.close()

        # Refresh `runtime_project_ids` to mirror the projects that actually
        # still have a running task. Without this, a project stays "in
        # runtime" forever after its first dispatch, blocking idle-project
        # dispatch under `max_running_projects` constraints (only
        # `_refresh_runtime_projects` would clean up — and only when the
        # project status changes, which never happens for a still-active
        # project that simply finished a task).
        if done:
            active_ids = {task.project_id for task in self.futures.values()}
            self.runtime_project_ids.intersection_update(active_ids)

    def _record_intent_error(
        self,
        task: RunningTask,
        outcome: str,
        *,
        detail: str | None = None,
    ) -> None:
        """Best-effort persistence for task failures that lack richer handling."""
        if task.intent_id is None:
            return
        reporter = getattr(getattr(self, "client", None), "report_intent_error", None)
        if reporter is None:
            return
        profiles = {
            "invalid_result": (
                "invalid_blackboard_result",
                "Worker output could not be validated into the required result fact.",
                10,
                120,
                2,
            ),
            "failed": (
                "task_failed",
                "The task failed before it could produce a valid blackboard result.",
                15,
                300,
                2,
            ),
            "task_crashed": (
                "task_crashed",
                "The task runner raised an unexpected exception.",
                15,
                300,
                2,
            ),
            "unhealthy": (
                "worker_unhealthy",
                "The selected worker failed its health check.",
                5,
                60,
                2,
            ),
            "rate_limited": (
                "provider_rate_limited",
                "The model provider rate-limited this task.",
                RATE_LIMIT_RETRY_AFTER_SECONDS,
                900,
                15,
            ),
            "quota_exhausted": (
                "provider_quota_exhausted",
                "The model provider quota is exhausted.",
                QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS,
                QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS,
                15,
            ),
            "rejected": (
                "worker_rejected",
                "The worker rejected the task under its current policy.",
                5,
                60,
                2,
            ),
        }
        code, message, base_retry, max_retry, max_attempts = profiles.get(
            outcome,
            (
                "task_failed",
                f"The task ended with outcome {outcome}.",
                15,
                300,
                2,
            ),
        )
        if outcome.startswith("invalid_result:"):
            detail = outcome.partition(":")[2]
            code, message, base_retry, max_retry, max_attempts = profiles["invalid_result"]
        if detail:
            message = f"{message} {detail}"[:4000]
        try:
            response = reporter(
                task.project_id,
                task.intent_id,
                task.worker_name,
                task_type=task.task_type,
                code=code,
                classification="transient",
                message=message,
                remediation=(
                    "Inspect the task execution output. If the cause is permanent, "
                    "correct it before requesting a manual retry."
                ),
                base_retry_seconds=base_retry,
                max_retry_seconds=max_retry,
                max_attempts=max_attempts,
            )
            if not response.ok:
                LOG.warning(
                    "intent error write failed project=%s intent=%s outcome=%s status=%s body=%s",
                    task.project_id,
                    task.intent_id,
                    outcome,
                    response.status_code,
                    response.text,
                )
        except Exception:
            LOG.exception(
                "intent error persistence crashed project=%s intent=%s outcome=%s",
                task.project_id,
                task.intent_id,
                outcome,
            )

    def _pause_project_for_cli_issue(self, task: RunningTask, outcome: str) -> None:
        profiles = {
            "quota_exhausted": (
                "provider_quota_exhausted",
                f"{task.worker_name} reported that its model provider quota is exhausted.",
                "Restore provider quota or choose another available CLI, then resume the project.",
            ),
            "cli_model_unsupported": (
                "cli_model_unsupported",
                f"{task.worker_name} rejected its configured model for the signed-in account.",
                "Configure a model supported by this CLI account or choose another CLI, then resume the project.",
            ),
            "cli_model_unrecognized": (
                "cli_model_unrecognized",
                f"{task.worker_name}'s provider does not recognize its configured model.",
                "Correct the model/provider settings for this CLI or choose another CLI, then resume the project.",
            ),
            "cli_auth_failed": (
                "cli_auth_failed",
                f"{task.worker_name} could not authenticate with its configured provider.",
                "Sign in again or repair the CLI credentials, then resume the project.",
            ),
            "cli_executable_missing": (
                "cli_executable_missing",
                f"The configured executable for {task.worker_name} could not be started.",
                "Install the CLI or correct its executable path, then resume the project.",
            ),
        }
        code, message, remediation = profiles[outcome]
        reporter = getattr(
            getattr(self, "client", None), "report_project_worker_issue", None,
        )
        if reporter is None:
            self._record_intent_error(task, outcome, detail=message)
            return
        try:
            response = reporter(
                task.project_id,
                task.worker_name,
                task.task_type,
                code,
                message,
                remediation,
                task.intent_id,
            )
            if not response.ok:
                LOG.warning(
                    "project CLI issue write failed project=%s task=%s worker=%s status=%s body=%s",
                    task.project_id,
                    task.task_type,
                    task.worker_name,
                    response.status_code,
                    response.text,
                )
                self._record_intent_error(task, outcome, detail=message)
                return
            if outcome == "quota_exhausted":
                data = getattr(response, "data", None)
                blocked_event_seq = (
                    data.get("event_seq") if isinstance(data, Mapping) else None
                )
                origins = getattr(self, "worker_provider_origin", None)
                if origins is None:
                    origins = self.worker_provider_origin = {}
                # Replace stale provenance even when a compatible API response
                # omits event_seq; those circuits use the legacy time fallback.
                origins.pop(task.worker_name, None)
                if (
                    isinstance(blocked_event_seq, int)
                    and not isinstance(blocked_event_seq, bool)
                    and blocked_event_seq > 0
                ):
                    origins[task.worker_name] = (
                        task.project_id, blocked_event_seq,
                    )
                self._persist_provider_circuits()
            LOG.error(
                "paused project after CLI issue project=%s task=%s worker=%s code=%s intent=%s",
                task.project_id,
                task.task_type,
                task.worker_name,
                code,
                task.intent_id,
            )
        except Exception:
            LOG.exception(
                "project CLI issue persistence crashed project=%s task=%s worker=%s",
                task.project_id,
                task.task_type,
                task.worker_name,
            )
            self._record_intent_error(task, outcome, detail=message)

    def _cleanup_completed_containers(self, summaries: list[ProjectSummary]) -> None:
        for summary in summaries:
            if summary.status != "completed":
                continue
            if self._inactive_cleanup_done.get(summary.id) == summary.status:
                continue
            container_name = self.container_manager.container_name(summary.id)
            if container_name in self._cleanup_pending:
                continue
            if not self.container_manager.needs_completed_cleanup(summary.id):
                self._inactive_cleanup_done[summary.id] = summary.status
                continue
            future = self.cleanup_executor.submit(self.container_manager.cleanup_completed, summary.id)
            self.cleanup_futures[future] = (container_name, summary.id, summary.status)
            self._cleanup_pending.add(container_name)

    def _cleanup_stopped_containers(self, summaries: list[ProjectSummary]) -> None:
        for summary in summaries:
            if summary.status != "stopped":
                continue
            if self._inactive_cleanup_done.get(summary.id) == summary.status:
                continue
            container_name = self.container_manager.container_name(summary.id)
            if container_name in self._cleanup_pending:
                continue
            if not self.container_manager.needs_stopped_cleanup(summary.id):
                self._inactive_cleanup_done[summary.id] = summary.status
                continue
            future = self.cleanup_executor.submit(self.container_manager.cleanup_stopped, summary.id)
            self.cleanup_futures[future] = (container_name, summary.id, summary.status)
            self._cleanup_pending.add(container_name)

    def _queue_container_cleanups(self, summaries: list[ProjectSummary]) -> None:
        self._cleanup_completed_containers(summaries)
        self._cleanup_stopped_containers(summaries)

    def _reap_cleanup_futures(self) -> None:
        done = [future for future in self.cleanup_futures if future.done()]
        for future in done:
            name, project_id, target_status = self.cleanup_futures.pop(future)
            self._cleanup_pending.discard(name)
            try:
                success = future.result()
                if success and project_id is not None and target_status in ("completed", "stopped"):
                    self._inactive_cleanup_done[project_id] = target_status
                elif project_id is not None:
                    self._inactive_cleanup_done.pop(project_id, None)
            except Exception:
                if project_id is not None:
                    self._inactive_cleanup_done.pop(project_id, None)
                LOG.exception("container cleanup failed container=%s", name)

    def _refresh_runtime_projects(self, summaries: list[ProjectSummary]) -> None:
        active_ids = {summary.id for summary in summaries if summary.status == "active"}
        self.runtime_project_ids.intersection_update(active_ids)
        inactive_status_by_id = {summary.id: summary.status for summary in summaries if summary.status != "active"}
        for project_id, status in list(self._inactive_cleanup_done.items()):
            current_status = inactive_status_by_id.get(project_id)
            if current_status != status:
                self._inactive_cleanup_done.pop(project_id, None)

    def _cancel_inactive_tasks(self, summaries: list[ProjectSummary]) -> None:
        status_by_project = {summary.id: summary.status for summary in summaries}
        for task in self.futures.values():
            status = status_by_project.get(task.project_id, "deleted")
            if status != "active" and task.cancellation.cancel(status):
                LOG.info(
                    "cancelling running task for inactive project project=%s task=%s worker=%s status=%s",
                    task.project_id,
                    task.task_type,
                    task.worker_name,
                    status,
                )

    def _best_effort_release(self, project_id: str, intent_id: str, worker_name: str) -> None:
        response = self.client.release(project_id, intent_id, worker_name)
        if not response.ok and response.status_code not in (403, 409):
            LOG.warning("release failed project=%s intent=%s worker=%s status=%s", project_id, intent_id, worker_name, response.status_code)

    def _best_effort_release_reason(self, project_id: str, worker_name: str, lease_id: str) -> None:
        response = self.client.release_reason(project_id, worker_name, lease_id)
        if not response.ok and response.status_code not in (403, 409):
            LOG.warning("reason release failed project=%s worker=%s status=%s", project_id, worker_name, response.status_code)

    def _log_changed(self, scope: str, level: int, message: str, *args: object) -> None:
        state = (level, message, args)
        if self._log_state.get(scope) == state:
            return
        self._log_state[scope] = state
        LOG.log(level, message, *args)

    def _clear_log_state(self, scope: str) -> None:
        self._log_state.pop(scope, None)

    def _clear_project_log_state(self, project_id: str) -> None:
        prefix = f"project:{project_id}:"
        for scope in list(self._log_state):
            if scope.startswith(prefix):
                self._log_state.pop(scope, None)

    def _validate_server_settings(self) -> None:
        settings = self.client.get_settings()
        interval = self.config.runtime.interval
        for name, value in (("intent_timeout", settings.intent_timeout), ("reason_timeout", settings.reason_timeout)):
            if value <= interval:
                raise RuntimeError(
                    f"server {name}={value}s must be greater than dispatcher interval={interval}s"
                )
            if value < interval * 2:
                LOG.warning(
                    "server %s is tight %s=%ss interval=%ss; heartbeat slack is only %ss",
                    name,
                    name,
                    value,
                    interval,
                    value - interval,
                )
                continue
            LOG.info(
                "server setting validated %s=%ss interval=%ss",
                name,
                value,
                interval,
            )

    def _run_startup_healthchecks(self, *, show_commands: bool) -> None:
        results = run_startup_healthchecks(self.config, show_commands=show_commands)
        if any(result.ok for result in results):
            return
        raise RuntimeError(format_failure_summary(results))
