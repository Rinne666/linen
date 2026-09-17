from __future__ import annotations

from collections.abc import Mapping
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

from linen.dispatcher.analysis import audit_graph, audit_recipes, coverage, scope_gate, stages, triage
from linen.dispatcher.analysis.external_scanners import scanner_for_intent, scanner_specs
from linen.dispatcher.analysis.spring_scan import SPRING_SCAN_INTENT
from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.models import AuditGraphCheckpoint, RunningTask
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.startup_healthcheck import format_failure_summary, run_startup_healthchecks
from linen.dispatcher.scheduler.worker_select import choose_worker
from linen.dispatcher.workers.registry import get_driver
from linen.dispatcher.tasks.explore import run_explore_task
from linen.dispatcher.tasks.reason import run_audit_graph_reason_task, run_reason_task
from linen.dispatcher.tasks.review import run_review_task
from linen.server.models import Intent, ProjectDetail, ProjectSummary

LOG = logging.getLogger(__name__)
UNHEALTHY_RETRY_AFTER_SECONDS = 5
REJECTED_RETRY_AFTER_SECONDS = 5
RATE_LIMIT_RETRY_AFTER_SECONDS = 300
QUOTA_EXHAUSTED_RETRY_AFTER_SECONDS = 3600


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
        self.audit_graph_checkpoints: dict[str, AuditGraphCheckpoint] = {}
        self.runtime_project_ids: set[str] = set()
        self.worker_unhealthy_until: dict[str, float] = {}
        self.worker_rejected_until: dict[tuple[str, str, str], float] = {}
        self.worker_provider_until: dict[str, float] = {}
        self.worker_provider_reason: dict[str, str] = {}
        self._restore_provider_circuits()
        self._log_state: dict[str, tuple[int, str, tuple[object, ...]]] = {}
        self._cleanup_pending: set[str] = set()
        self._inactive_cleanup_done: dict[str, str] = {}
        self.project_cursor = 0
        self._settings_checked = False
        self._startup_healthchecks_checked = False
        self._orphan_recovery_done: set[str] = set()
        self._orphan_recovery_reported: set[str] = set()

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
        self._run_managed_scanner_check()
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
            "configured and usable directly (e.g. `claude -p ...` works) — linen injects no API keys.",
            ", ".join(sorted(available)),
        )

    def _run_managed_scanner_check(self) -> None:
        missing: list[str] = []
        for spec in scanner_specs(self.config.audit):
            executable = str(spec.config.executable)
            path = shutil.which(executable)
            if path is None:
                missing.append(f"{spec.label} executable `{executable}`")
                continue
            if spec.name == "spotbugs-findsecbugs":
                plugin = spec.config.plugin.expanduser().resolve() if spec.config.plugin else None
                if plugin is None or not plugin.is_file():
                    missing.append(f"FindSecBugs plugin `{plugin or 'unset'}`")
                    continue
            LOG.info("[+] managed scanner %-24s %s", spec.label, path)
        if missing:
            raise RuntimeError(
                "enabled managed scanners are unavailable: " + ", ".join(missing)
                + ". Install them or disable their audit config blocks."
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
                elif task_type in {"audit_graph_reason", "audit_graph"}:
                    checkpoints = getattr(self, "audit_graph_checkpoints", None)
                    if checkpoints is None:
                        checkpoints = {}
                        self.audit_graph_checkpoints = checkpoints
                    prior = checkpoints.get(project_id)
                    prior_attempts = (
                        prior.attempts
                        if prior is not None and prior.graph_revision == graph_revision
                        else 0
                    )
                    checkpoints[project_id] = AuditGraphCheckpoint(
                        graph_revision=graph_revision,
                        attempts=max(prior_attempts, attempt),
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

    def _try_dispatch_project(self, summary: ProjectSummary) -> bool:
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
        if self._project_running_task_count(summary.id) >= self.config.runtime.max_project_workers:
            self._log_changed(
                f"{skip_scope}:max_project_workers",
                logging.INFO,
                "skip project=%s because max_project_workers reached running_tasks=%s",
                summary.id,
                self._project_running_task_summary(summary.id),
            )
            return False

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
        # Managed audit mechanics are derived exclusively from the exported
        # graph and immutable project artifacts. Scope mode derives the full
        # coverage DAG; hypothesis mode derives only configured baseline scan
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

        if self._is_initial_project(project):
            export_yaml = self.client.export_project(summary.id)
            return self._dispatch_reason(project, export_yaml, "initial")
        has_managed_audit_work = any(
            audit_graph.managed_description(intent.description)
            and intent.to is None
            and intent.concluded_at is None
            for intent in project.intents
        )
        if project.project.reason is None and not has_managed_audit_work:
            audit_graph_trigger = self._audit_graph_reason_trigger(project)
            if audit_graph_trigger is not None:
                export_yaml = self.client.export_project(summary.id)
                return self._dispatch_reason(
                    project,
                    export_yaml,
                    audit_graph_trigger,
                    profile="audit_graph",
                )
            reason_trigger = self._reason_trigger(project)
            if reason_trigger is not None:
                export_yaml = self.client.export_project(summary.id)
                return self._dispatch_reason(project, export_yaml, reason_trigger)
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
        if self._scope_gate_pending(project):
            withheld = len(unclaimed_intents)
            unclaimed_intents = [
                intent for intent in unclaimed_intents
                if self._scope_gate_intent_allowed(project, intent)
            ]
            self._log_changed(
                f"{skip_scope}:scope_gate",
                logging.INFO,
                "scope adjudication gate withholding technical work project=%s visible_gate_intents=%s withheld=%s",
                summary.id,
                [intent.id for intent in unclaimed_intents],
                withheld - len(unclaimed_intents),
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
            managed_intents = [
                intent for intent in explore_intents
                if audit_graph.managed_description(intent.description)
            ]
            # Pick the least-recently attempted intent. A released intent keeps
            # its heartbeat timestamp, so failures rotate to the back of the
            # persisted blackboard queue instead of starving older work. For
            # never-attempted intents this is ordinary FIFO ordering. Non-cell
            # graph work (scanner, review, triage, synthesis) stays ahead of
            # bulk coverage, including on boards created before ready-window
            # bounding was introduced.
            next_intent = min(
                managed_intents or explore_intents,
                key=lambda i: (
                    int(self._explore_requires_provider(project, i)),
                    int(i.description.strip().startswith(coverage.CELL_PREFIX)),
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
            project.project.audit_mode != "none"
            and hasattr(self.client, "get_completion_gate")
        ):
            try:
                gate = self.client.get_completion_gate(project.project.id)
            except Exception as exc:
                LOG.warning(
                    "completion gate read failed project=%s error=%s",
                    project.project.id,
                    exc,
                )
            else:
                if gate.ready:
                    sources = self._completion_sources(project)
                    if sources:
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
                else:
                    self._log_changed(
                        f"{skip_scope}:completion_gate",
                        logging.INFO,
                        "audit waiting for completion evidence project=%s execution=%s blockers=%s",
                        project.project.id,
                        gate.execution_status,
                        gate.blockers,
                    )
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

    def _materialize_audit_intents(self, project: ProjectDetail) -> bool:
        if not self.config.audit.enabled or project.project.audit_mode == "none":
            return False
        workdir = Path(self.container_manager.ensure_running(project.project.id))
        # Keep only a small ready window on the blackboard. The complete audit
        # DAG remains derivable from facts, intents, and reviews, but thousands
        # of future coverage cells no longer hide scanner/triage work or make
        # the UI look as if every cell is already running.
        limit = min(8, max(1, self.config.runtime.max_project_workers * 2))
        open_managed = sum(
            audit_graph.managed_description(intent.description)
            and intent.to is None
            and intent.concluded_at is None
            for intent in project.intents
        )
        proposal_limit = limit - open_managed
        legacy_overflow = open_managed > limit
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
        if proposal_limit <= 0 and not legacy_overflow and not priority_scope_gate:
            proposal_limit = 0

        # Proof mode is candidate-centric and bounded: the server derives one
        # highest-value obligation and suppresses duplicate open Intents. It
        # never creates a Fact or calls Technical Confirmation here.
        if hasattr(self.client, "plan_proof_gap") and proposal_limit > 0 and not priority_scope_gate:
            for fact in sorted(project.facts, key=lambda item: item.id):
                if fact.source_generation != project.project.source_generation or fact.semantic_type != "candidate_finding":
                    continue
                response = self.client.plan_proof_gap(project.project.id, fact.id)
                if response.ok and isinstance(response.data, dict) and response.data.get("created"):
                    LOG.info("materialized proof-gap intent project=%s candidate=%s intent=%s", project.project.id, fact.id, response.data.get("intent_id"))
                    return True
                if response.status_code not in {200, 403, 409}:
                    LOG.warning("proof-gap planning failed project=%s candidate=%s status=%s body=%s", project.project.id, fact.id, response.status_code, response.text)
            if proposal_limit == 0:
                return False
        proposals = audit_graph.required_intents(
            project, workdir, self.config.audit,
            limit=1 if legacy_overflow or priority_scope_gate else proposal_limit,
        )
        if legacy_overflow:
            # Existing projects may already contain hundreds of eagerly
            # materialized coverage cells. Permit only a higher-priority graph
            # edge through that legacy backlog; never add another coverage cell.
            proposals = [
                proposal for proposal in proposals
                if not proposal["description"].strip().startswith(coverage.CELL_PREFIX)
            ][:1]
        created = 0
        for proposal in proposals:
            response = self.client.create_intent(
                project.project.id,
                proposal["from"],
                proposal["description"],
                audit_graph.CREATOR,
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
        if not hasattr(self.client, "upsert_audit_stage"):
            return False
        workdir = Path(self.container_manager.ensure_running(project.project.id))
        rows = stages.reconcile(self.config.audit, project, workdir)
        changed = stages.changed_rows(project, rows)
        written = False
        for row in changed:
            response = self.client.upsert_audit_stage(
                project.project.id,
                row["stage_id"],
                label=row["label"],
                phase_order=row["phase_order"],
                required=row["required"],
                status=row["status"],
                capability=row.get("capability"),
                skill_id=row.get("skill_id"),
                run_id=row.get("run_id"),
                detail=row.get("detail"),
                source_generation=project.project.source_generation,
                plan_revision=project.project.plan_revision,
            )
            if response.ok:
                written = True
            elif response.status_code not in {403, 409}:
                LOG.warning(
                    "audit stage reconciliation failed project=%s stage=%s status=%s body=%s",
                    project.project.id, row["stage_id"], response.status_code, response.text,
                )
        if written:
            LOG.debug(
                "reconciled audit stages project=%s changed=%s",
                project.project.id, len(changed),
            )
        return written

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

    def _reason_attempt(
        self,
        project: ProjectDetail,
        trigger: str,
        *,
        profile: str,
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
        *,
        profile: str = "default",
    ) -> bool:
        if self._project_has_running_reason(project.project.id):
            self._log_changed(
                f"project:{project.project.id}:skip:reason_running",
                logging.DEBUG,
                "skip reason project=%s because a reason task is already running locally",
                project.project.id,
            )
            return False
        selection = self._select_worker(project.project.id, "reason")
        worker = selection.worker
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
        attempt = self._reason_attempt(project, trigger, profile=profile)
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
        try:
            task_runner = (
                run_audit_graph_reason_task
                if profile == "audit_graph"
                else run_reason_task
            )
            future = self._submit_task_runner(
                task_runner,
                self.config,
                self.client,
                self.container_manager,
                project,
                export_yaml,
                worker,
                cancellation := TaskCancellation(),
                lease_id=lease_id,
                trigger=trigger,
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit reason task project=%s worker=%s", project.project.id, worker.name)
            self._best_effort_release_reason(project.project.id, worker.name, lease_id)
            return False
        self.futures[future] = RunningTask(
            project.project.id,
            "reason",
            worker.name,
            cancellation,
            intent_id=None,
            intent_count=len(project.intents),
            reason_profile=profile,
            graph_revision=project.project.graph_revision,
            attempt=attempt,
            trigger=trigger,
        )
        self.runtime_project_ids.add(project.project.id)
        self._clear_project_log_state(project.project.id)
        LOG.info(
            "dispatched reason project=%s worker=%s profile=%s trigger=%s",
            project.project.id, worker.name, profile, trigger,
        )
        return True

    def _dispatch_explore(self, project: ProjectDetail, export_yaml: str, intent: Intent) -> bool:
        provider_required = self._explore_requires_provider(project, intent)
        selection = self._select_worker(
            project.project.id,
            "explore",
            provider_required=provider_required,
        )
        worker = selection.worker
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
        attempt = self._intent_attempt(project, intent, task_type="explore")
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
                cancellation := TaskCancellation(),
                trigger=trigger,
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit explore task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
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
        selection = self._select_worker(project.project.id, "review")
        worker = selection.worker
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
                cancellation := TaskCancellation(),
                trigger=trigger,
                attempt=attempt,
            )
        except Exception:
            LOG.exception("failed to submit review task project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
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

    def _select_worker(
        self,
        project_id: str,
        task_type: str,
        *,
        provider_required: bool = True,
    ) -> WorkerSelection:
        now = time.time()
        candidates: list[WorkerConfig] = []
        blocked_busy: list[str] = []
        blocked_unhealthy: list[str] = []
        blocked_rejected: list[str] = []
        blocked_task_type: list[str] = []
        running_counts = self._worker_counts()
        for worker in self.config.workers:
            if task_type not in worker.task_types:
                blocked_task_type.append(worker.name)
                continue
            running = running_counts.get(worker.name, 0)
            if running >= worker.max_running:
                blocked_busy.append(f"{worker.name}({running}/{worker.max_running})")
                continue
            unhealthy_until = self.worker_unhealthy_until.get(worker.name, 0)
            if unhealthy_until > now:
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
                self._persist_provider_circuits()
            rejected_until = self.worker_rejected_until.get((project_id, task_type, worker.name), 0)
            if rejected_until > now:
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
            [f"{worker.name}({running_counts.get(worker.name, 0)}/{worker.max_running},p{worker.priority})" for worker in candidates],
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
        """Keep deterministic audit scanners runnable during an LLM outage."""
        description = intent.description.strip()
        if scanner_for_intent(self.config.audit, description) is not None:
            return False
        scope_audit = self.config.audit.enabled and project.project.audit_mode == "scope"
        if not scope_audit:
            return True
        if (
            self.config.audit.scope_adjudication.enabled
            and scope_gate.is_evidence_intent(intent)
        ):
            return False
        if intent.type == "search" and description == coverage.PLAN_INTENT:
            return False
        if (
            self.config.audit.spring.enabled
            and intent.type == "search"
            and description == SPRING_SCAN_INTENT
        ):
            return False
        return not (
            description.startswith(coverage.MODULE_SUMMARY_PREFIX)
            or description.startswith(triage.SCAN_SUMMARY_PREFIX)
            or description == audit_recipes.SUMMARY_INTENT
            or description == audit_graph.AUDIT_SUMMARY_INTENT
        )

    def _scope_gate_pending(self, project: ProjectDetail) -> bool:
        if not (
            self.config.audit.scope_adjudication.enabled
            and project.project.audit_mode == "scope"
        ):
            return False
        evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
        if (
            evidence is None
            or evidence.type != scope_gate.POLICY_EVIDENCE_TYPE
            or not coverage.reviewed(project, evidence.id)
        ):
            return True
        adjudication = scope_gate.result_for_intent(
            project, scope_gate.ADJUDICATION_INTENT,
        )
        return (
            adjudication is None
            or adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE
            or not coverage.reviewed(project, adjudication.id)
        )

    def _scope_gate_intent_allowed(
        self, project: ProjectDetail, intent: Intent,
    ) -> bool:
        if not self._scope_gate_pending(project):
            return True
        if scope_gate.is_evidence_intent(intent) or scope_gate.is_adjudication_intent(intent):
            return True
        if not (intent.type or "").startswith("review") or len(intent.from_) != 1:
            return False
        source = next(
            (fact for fact in project.facts if fact.id == intent.from_[0]),
            None,
        )
        return source is not None and source.type in {
            scope_gate.POLICY_EVIDENCE_TYPE,
            scope_gate.SCOPE_ADJUDICATION_TYPE,
        }

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

    def _restore_provider_circuits(self) -> None:
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
            payload = {
                "schema_version": 1,
                "workers": {
                    worker_name: {
                        "until": until,
                        "reason": self.worker_provider_reason.get(worker_name, "unavailable"),
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

    def _is_initial_project(self, project: ProjectDetail) -> bool:
        fact_ids = {fact.id for fact in project.facts}
        if fact_ids != {"origin", "goal"} or len(project.facts) != 2:
            return False

    def _reason_trigger(self, project: ProjectDetail) -> str | None:
        if project.project.event_seq > project.project.reason_last_seen_event_seq:
            return (
                f"events:{project.project.reason_last_seen_event_seq}"
                f"->{project.project.event_seq}"
            )
        return None

    def _audit_graph_reason_trigger(self, project: ProjectDetail) -> str | None:
        graph_config = self.config.audit.graph_reason
        if (
            not self.config.audit.enabled
            or not graph_config.enabled
            or project.project.audit_mode == "none"
        ):
            return None
        checkpoints = getattr(self, "audit_graph_checkpoints", {})
        checkpoint = checkpoints.get(project.project.id)
        revision = project.project.graph_revision
        if checkpoint is None or checkpoint.graph_revision != revision:
            return f"audit_graph:revision:{revision}:attempt:1"
        if checkpoint.attempts < graph_config.max_attempts_per_revision:
            return (
                f"audit_graph:revision:{revision}:"
                f"attempt:{checkpoint.attempts + 1}"
            )
        return None

    def _reap_futures(self) -> None:
        # Some embedders and older tests construct the loop without calling
        # ``__init__``; lazily establish the new circuit state for backwards
        # compatibility with that supported pattern.
        if not hasattr(self, "worker_provider_until"):
            self.worker_provider_until = {}
        if not hasattr(self, "worker_provider_reason"):
            self.worker_provider_reason = {}
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
                elif outcome != "success":
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
                    provider_until = time.time() + retry_after_seconds
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
                elif outcome == "success" and task.provider_required:
                    removed = self.worker_provider_until.pop(task.worker_name, None)
                    self.worker_provider_reason.pop(task.worker_name, None)
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
                if outcome not in {"success", "cancelled", "blocked"}:
                    self._record_intent_error(task, outcome)
                if task.task_type == "reason" and task.reason_profile == "audit_graph":
                    checkpoints = getattr(self, "audit_graph_checkpoints", None)
                    if checkpoints is None:
                        checkpoints = {}
                        self.audit_graph_checkpoints = checkpoints
                    start_revision = task.graph_revision or 0
                    prior = checkpoints.get(task.project_id)
                    if outcome == "success":
                        fresh = self.client.get_project(task.project_id)
                        checkpoints[task.project_id] = AuditGraphCheckpoint(
                            graph_revision=fresh.project.graph_revision,
                            attempts=self.config.audit.graph_reason.max_attempts_per_revision,
                        )
                    elif outcome != "cancelled":
                        attempts = (
                            prior.attempts + 1
                            if prior is not None and prior.graph_revision == start_revision
                            else 1
                        )
                        checkpoints[task.project_id] = AuditGraphCheckpoint(
                            graph_revision=start_revision,
                            attempts=attempts,
                        )
                        LOG.info(
                            "audit graph checkpoint updated project=%s revision=%s attempts=%s/%s outcome=%s",
                            task.project_id,
                            start_revision,
                            attempts,
                            self.config.audit.graph_reason.max_attempts_per_revision,
                            outcome,
                        )
            except Exception as exc:
                LOG.exception("task crashed project=%s task=%s worker=%s", task.project_id, task.task_type, task.worker_name)
                self._record_intent_error(task, "task_crashed", detail=str(exc))

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
