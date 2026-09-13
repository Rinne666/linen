from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import logging
from pathlib import Path
import time
import uuid
from dataclasses import dataclass

from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import ExecutionBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.runtime.process import ProcessResult

PROCESS_COMMUNICATE_GRACE_SECONDS = 15
LOG_PREVIEW_LIMIT = 1200
GRAPH_SNAPSHOT_ROOT = "/tmp/linen-prompts"
LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class ConcludeWriteResult:
    status: str
    fact_id: str | None = None


def preview(text: str, limit: int = LOG_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def did_timeout(result: ProcessResult) -> bool:
    return not result.cancelled and (result.timed_out or result.returncode in (124, 137))


def classify_provider_failure(result: ProcessResult) -> str | None:
    """Classify explicit provider errors without scanning echoed prompt text.

    Pi emits JSONL event records and may exit with status 0 even when every
    provider attempt failed.  Its stdout also contains user/model text, so a
    broad substring check would let an audit target or prompt forge a cooldown.
    Only structured error fields are inspected; stderr is considered only for
    non-zero exits used by other worker CLIs.
    """
    messages: list[str] = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(event, dict):
            _collect_provider_errors(event, messages)
    if result.returncode != 0 and result.stderr:
        messages.append(result.stderr[-4000:])

    normalized = "\n".join(messages).casefold()
    if not normalized:
        return None
    quota_markers = (
        "quota_exceeded",
        "insufficient_quota",
        "usage limit",
        "usage_limit",
        "token plan",
        "用量上限",
        "购买积分",
        "额度已用尽",
    )
    if any(marker in normalized for marker in quota_markers):
        return "quota_exhausted"
    rate_limit_markers = (
        "rate_limit",
        "rate limit",
        "too many requests",
        "http 429",
        "429 {",
    )
    if any(marker in normalized for marker in rate_limit_markers):
        return "rate_limited"
    return None


def _collect_provider_errors(value: object, messages: list[str]) -> None:
    if not isinstance(value, dict):
        return
    for key in ("errorMessage", "finalError"):
        message = value.get(key)
        if isinstance(message, str):
            messages.append(message)
    error = value.get("error")
    if isinstance(error, str):
        messages.append(error)
    elif isinstance(error, dict):
        for key in ("type", "message", "code"):
            message = error.get(key)
            if isinstance(message, str):
                messages.append(message)
    message = value.get("message")
    if isinstance(message, dict):
        _collect_provider_errors(message, messages)
    nested_messages = value.get("messages")
    if isinstance(nested_messages, list):
        for nested in nested_messages:
            if isinstance(nested, dict):
                _collect_provider_errors(nested, messages)


def cancel_reason(result: ProcessResult, cancellation: TaskCancellation | None = None) -> str | None:
    if result.cancelled:
        return result.cancel_reason or "cancelled"
    if cancellation is not None:
        return cancellation.reason
    return None


def communicate_timeout(timeout_seconds: int, grace_seconds: int = PROCESS_COMMUNICATE_GRACE_SECONDS) -> int:
    return timeout_seconds + grace_seconds


def task_healthcheck_enabled(config: DispatchConfig) -> bool:
    return config.runtime.worker_healthcheck == "startup_and_task"


def write_graph_snapshot_reference(
    backend: ExecutionBackend,
    project_handle: str,
    graph_yaml: str,
    *,
    phase: str,
) -> str:
    path = f"{GRAPH_SNAPSHOT_ROOT}/{phase}-{uuid.uuid4().hex[:12]}/graph.yaml"
    backend.write_text_file(project_handle, path, graph_yaml)
    return (
        "The graph YAML snapshot is stored in this file on the dispatcher host:\n\n"
        f"{path}\n\n"
        "Before using the graph, read the entire file and treat its contents as the YAML snapshot "
        "for this Graph section."
    )


def run_worker_process(
    backend: ExecutionBackend,
    project_handle: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
    recipe_id: str | None = None,
    recipe_label: str | None = None,
    recipe_version: int | None = None,
) -> ProcessResult:
    LOG.info(
        "starting worker project=%s worker=%s phase=%s timeout=%ss",
        project_handle,
        worker.name,
        phase,
        timeout_seconds,
    )
    process = backend.build_exec_process(
        project_handle,
        dict(worker.env),
        argv,
        timeout_seconds=timeout_seconds,
    )
    process.start()
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    try:
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        result = process.communicate(timeout=communicate_timeout(timeout_seconds))
        _write_execution_record(
            backend,
            project_handle,
            worker,
            argv,
            phase,
            started_at,
            int((time.perf_counter() - started) * 1000),
            timeout_seconds,
            result,
            recipe_id=recipe_id,
            recipe_label=recipe_label,
            recipe_version=recipe_version,
        )
        return result
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)


def _write_execution_record(
    backend: ExecutionBackend,
    project_handle: str,
    worker: WorkerConfig,
    argv: list[str],
    phase: str,
    started_at: datetime,
    duration_ms: int,
    timeout_seconds: int,
    result: ProcessResult,
    *,
    recipe_id: str | None = None,
    recipe_label: str | None = None,
    recipe_version: int | None = None,
) -> None:
    """Persist the raw process result with stable metadata for later audit.

    Local execution uses the project workdir as its handle.  We intentionally
    store an argv digest rather than the argv itself because the latter embeds
    the full model prompt and may contain user-provided secrets.  The model's
    complete stdout/stderr, exit state, and timing are preserved alongside the
    board evidence so a finding can be reconstructed after the CLI session
    cache has been pruned.
    """
    try:
        root = Path(project_handle).resolve() / ".linen-executions"
        stamp = started_at.strftime("%Y%m%dT%H%M%S.%fZ")
        record_id = f"{stamp}-{phase}-{uuid.uuid4().hex[:8]}"
        record_path = root / f"{record_id}.json"
        prompt_path = root / f"{record_id}.prompt"
        stdout_path = root / f"{record_id}.stdout"
        stderr_path = root / f"{record_id}.stderr"
        prompt = _pi_prompt_from_argv(argv) if worker.type == "pi" else None
        if prompt is not None:
            backend.write_text_file(project_handle, str(prompt_path), prompt)
        backend.write_text_file(project_handle, str(stdout_path), result.stdout)
        backend.write_text_file(project_handle, str(stderr_path), result.stderr)
        command_digest = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        record = {
            "schema_version": 3,
            "phase": phase,
            "recipe_id": recipe_id,
            "recipe_label": recipe_label,
            "recipe_version": recipe_version,
            "worker": worker.name,
            "worker_type": worker.type,
            "command": "pi -p" if prompt is not None else None,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "timeout_seconds": timeout_seconds,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "cancel_reason": result.cancel_reason,
            "argv_sha256": command_digest,
            "prompt": str(prompt_path) if prompt is not None else None,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
        backend.write_text_file(project_handle, str(record_path), json.dumps(record, indent=2) + "\n")
    except Exception as exc:  # Execution evidence must never hide task output.
        LOG.warning("execution record write failed project=%s phase=%s error=%s", project_handle, phase, exc)


def _pi_prompt_from_argv(argv: list[str]) -> str | None:
    """Return the payload passed to Pi's final ``-p`` flag without persisting argv.

    Pi may be wrapped by ``/bin/sh`` and model-provider setup arguments. Looking
    backwards finds the actual Pi prompt while keeping API keys and injected
    provider configuration out of the execution record.
    """
    for index in range(len(argv) - 2, -1, -1):
        if argv[index] == "-p":
            return argv[index + 1]
    return None


def project_allows_conclude_fallback(client: LinenClient, project_id: str, *, worker_name: str, intent_id: str) -> bool:
    project = client.get_project(project_id)
    if project.project.status == "active":
        return True
    LOG.info(
        "skip conclude fallback because project is no longer active project=%s intent=%s worker=%s status=%s",
        project_id,
        intent_id,
        worker_name,
        project.project.status,
    )
    return False


def best_effort_release_reason(
    client: LinenClient, project_id: str, worker_name: str, lease_id: str,
) -> None:
    response = client.release_reason(project_id, worker_name, lease_id)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "reason release failed project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released reason project=%s worker=%s", project_id, worker_name)
    else:
        LOG.info(
            "reason release skipped project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )


def write_conclude_result(
    client: LinenClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_type: str | None = None,
    evidence: str | None = None,
    fact_status: str = "draft",
) -> str:
    return write_conclude_result_with_fact_id(
        client,
        project_id,
        intent_id,
        worker_name,
        description,
        source=source,
        phase_ms=phase_ms,
        total_ms=total_ms,
        fact_type=fact_type,
        evidence=evidence,
        fact_status=fact_status,
    ).status


def write_conclude_result_with_fact_id(
    client: LinenClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_type: str | None = None,
    evidence: str | None = None,
    fact_status: str = "draft",
) -> ConcludeWriteResult:
    response = client.conclude(
        project_id,
        intent_id,
        worker_name,
        description,
        fact_type=fact_type,
        evidence=evidence,
        status=fact_status,
    )
    if response.ok:
        fact_id: str | None = None
        if isinstance(response.data, dict):
            fact = response.data.get("fact")
            if isinstance(fact, dict):
                candidate = fact.get("id")
                if isinstance(candidate, str) and candidate:
                    fact_id = candidate
        if total_ms is None:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
            )
        else:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s total_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
                total_ms,
            )
        return ConcludeWriteResult(status="success", fact_id=fact_id)
    if response.status_code == 403:
        LOG.info(
            "project became inactive during conclude project=%s intent=%s worker=%s",
            project_id,
            intent_id,
            worker_name,
        )
    else:
        LOG.warning(
            "conclude write failed project=%s intent=%s worker=%s status=%s body=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
            response.text,
        )
    best_effort_release(client, project_id, intent_id, worker_name)
    return ConcludeWriteResult(status="failed", fact_id=None)


def best_effort_release(client: LinenClient, project_id: str, intent_id: str, worker_name: str) -> None:
    response = client.release(project_id, intent_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "release failed project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released intent project=%s intent=%s worker=%s", project_id, intent_id, worker_name)
    else:
        LOG.info(
            "release skipped project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
