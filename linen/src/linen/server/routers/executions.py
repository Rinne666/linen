from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from linen.server.db import get_conn
from linen.server.models import (
    PiExecutionDetail,
    PiExecutionPage,
    PiExecutionSummary,
    ProjectCostLedger,
    WorkerCallCost,
)
from linen.server.services import get_project_or_404


router = APIRouter(tags=["executions"])

_workspace_root_override: Path | None = None
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


def configure_workspace_root(path: Path | None) -> None:
    global _workspace_root_override
    _workspace_root_override = path.expanduser().resolve() if path is not None else None


def workspace_root() -> Path:
    if _workspace_root_override is not None:
        return _workspace_root_override
    configured = os.environ.get("LINEN_WORKSPACE_ROOT")
    # LocalBackend uses the dispatcher's current directory when the config does
    # not set local.workspace_root. Use that same default so API archive and
    # artifact reads find the files the dispatcher writes in a standard local
    # setup.
    return Path(configured).expanduser().resolve() if configured else Path.cwd().resolve()


def _execution_dir(project_id: str) -> Path:
    root = workspace_root()
    directory = (root / project_id / ".linen-executions").resolve()
    try:
        directory.relative_to(root)
    except ValueError as exc:
        raise HTTPException(404, "Execution archive not found") from exc
    return directory


def _record_path(project_id: str, execution_id: str) -> Path:
    if not _EXECUTION_ID.fullmatch(execution_id) or ".." in execution_id:
        raise HTTPException(404, "Execution record not found")
    path = (_execution_dir(project_id) / f"{execution_id}.json").resolve()
    if path.parent != _execution_dir(project_id) or not path.is_file():
        raise HTTPException(404, "Execution record not found")
    return path


def _load_record(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(404, "Execution record is unavailable") from exc
    if not isinstance(value, dict):
        raise HTTPException(404, "Execution record is unavailable")
    return value


def _text_path(record_path: Path, suffix: str) -> Path:
    path = record_path.with_suffix(f".{suffix}").resolve()
    if path.parent != record_path.parent.resolve():
        raise HTTPException(404, "Execution stream not found")
    return path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _message_text(message: object) -> str:
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict) or item.get("type") != "text":
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts).strip()


def _parse_pi_stream(stdout: str) -> tuple[str | None, str, str]:
    session_id: str | None = None
    prompt = ""
    response = ""
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "session" and isinstance(event.get("id"), str):
            session_id = event["id"]

        messages: list[dict] = []
        message = event.get("message")
        if isinstance(message, dict):
            messages.append(message)
        if event.get("type") == "agent_end" and isinstance(event.get("messages"), list):
            messages.extend(item for item in event["messages"] if isinstance(item, dict))

        for item in messages:
            role = item.get("role")
            text = _message_text(item)
            if not text:
                continue
            if role == "user" and not prompt:
                prompt = text
            elif role == "assistant":
                response = text
    return session_id, prompt, response


def _pi_probe(record_path: Path) -> tuple[bool, str | None]:
    stdout_path = _text_path(record_path, "stdout")
    try:
        with stdout_path.open("r", encoding="utf-8", errors="replace") as stream:
            first_line = stream.readline(131_072)
    except OSError:
        return False, None
    try:
        event = json.loads(first_line)
    except json.JSONDecodeError:
        return False, None
    if not isinstance(event, dict) or event.get("type") != "session":
        return False, None
    session_id = event.get("id")
    return True, session_id if isinstance(session_id, str) else None


def _is_pi_record(record: dict, record_path: Path) -> tuple[bool, str | None]:
    if "command" in record:
        return record.get("command") == "pi -p", None
    return _pi_probe(record_path)


def _summary(record_path: Path, record: dict, session_id: str | None = None) -> PiExecutionSummary:
    prompt_path = _text_path(record_path, "prompt")
    stdout_path = _text_path(record_path, "stdout")
    stderr_path = _text_path(record_path, "stderr")
    return PiExecutionSummary(
        id=record_path.stem,
        schema_version=(record.get("schema_version") if isinstance(record.get("schema_version"), int) else 3),
        command="pi -p",
        phase=str(record.get("phase") or "unknown"),
        recipe_id=str(record["recipe_id"]) if record.get("recipe_id") else None,
        recipe_label=str(record["recipe_label"]) if record.get("recipe_label") else None,
        recipe_version=(
            record["recipe_version"]
            if isinstance(record.get("recipe_version"), int) else None
        ),
        worker=str(record.get("worker") or "pi"),
        started_at=str(record.get("started_at") or ""),
        duration_ms=_nonnegative_int(record.get("duration_ms")),
        timeout_seconds=_nonnegative_int(record.get("timeout_seconds")),
        returncode=record.get("returncode") if isinstance(record.get("returncode"), int) else None,
        timed_out=bool(record.get("timed_out")),
        cancelled=bool(record.get("cancelled")),
        cancel_reason=str(record["cancel_reason"]) if record.get("cancel_reason") else None,
        session_id=session_id,
        prompt_available=prompt_path.is_file() or _file_size(stdout_path) > 0,
        response_available=_file_size(stdout_path) > 0,
        stdout_bytes=_file_size(stdout_path),
        stderr_bytes=_file_size(stderr_path),
        run_id=str(record["run_id"]) if record.get("run_id") else None,
        attempt=record["attempt"] if isinstance(record.get("attempt"), int) else None,
        idempotency_key=str(record["idempotency_key"]) if record.get("idempotency_key") else None,
        context_projection_id=(
            str(record["context_projection_id"])
            if record.get("context_projection_id") else None
        ),
        manifest_digest=str(record["manifest_digest"]) if record.get("manifest_digest") else None,
        recipe_digest=str(record["recipe_digest"]) if record.get("recipe_digest") else None,
    )


def _ensure_project(project_id: str) -> None:
    with get_conn() as conn:
        get_project_or_404(conn, project_id)


@router.get("/projects/{project_id}/executions", response_model=PiExecutionPage)
def list_pi_executions(
    project_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=40, ge=1, le=100),
    phase: str | None = Query(default=None, max_length=80),
) -> PiExecutionPage:
    _ensure_project(project_id)
    directory = _execution_dir(project_id)
    summaries: list[PiExecutionSummary] = []
    if directory.is_dir():
        for candidate in directory.glob("*.json"):
            try:
                record_path = _record_path(project_id, candidate.stem)
                record = _load_record(record_path)
                is_pi, session_id = _is_pi_record(record, record_path)
                if not is_pi:
                    continue
                summary = _summary(record_path, record, session_id)
            except HTTPException:
                continue
            if phase and summary.phase != phase:
                continue
            summaries.append(summary)
    summaries.sort(key=lambda item: (item.started_at, item.id), reverse=True)
    return PiExecutionPage(
        items=summaries[offset:offset + limit],
        total=len(summaries),
        offset=offset,
        limit=limit,
    )


_COST_CATEGORIES = ("reason", "explore", "review", "poc", "unclassified")


def _cost_category(phase: str, run: dict[str, object] | None) -> str:
    task_type = str(run.get("task_type") or "") if run else ""
    intent_type = str(run.get("intent_type") or "") if run else ""
    if (intent_type or "").startswith("poc:isolated") or (task_type or "").startswith("poc:"):
        return "poc"

    phase = phase.lower() or (task_type or "").lower()
    if phase.startswith("reason") or task_type == "reason":
        return "reason"
    if phase.startswith("review") or task_type == "review":
        return "review"
    if (
        phase.startswith(("explore", "scope_adjudication", "recon_", "semantic_recipe"))
        or task_type == "explore"
    ):
        return "explore"
    if phase.startswith("poc"):
        return "poc"
    return "unclassified"


@router.get("/projects/{project_id}/cost", response_model=ProjectCostLedger)
def get_project_cost(project_id: str) -> ProjectCostLedger:
    """Aggregate persisted worker invocation archives for one project."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        runs = {
            row["run_id"]: {
                "task_type": row["task_type"],
                "intent_type": row["intent_type"],
                "stage": row["stage"],
                "status": row["status"],
                "error_id": row["error_id"],
            }
            for row in conn.execute(
                "SELECT r.run_id, r.task_type, r.stage, i.type AS intent_type, r.status, r.error_id "
                "FROM runs r LEFT JOIN intents i "
                "ON i.project_id = r.project_id AND i.id = r.intent_id "
                "WHERE r.project_id = ?",
                (project_id,),
            )
        }
        attempt_metadata: dict[tuple[str, str], dict] = {}
        for row in conn.execute(
            "SELECT e.run_id, e.payload, r.stage FROM audit_events e "
            "JOIN runs r ON r.project_id = e.project_id AND r.run_id = e.run_id "
            "WHERE e.project_id = ? AND e.event_type = 'execution_attempt_finished' "
            "AND e.actor = 'dispatcher.execution' "
            "AND e.source_generation = r.source_generation "
            "AND e.plan_revision = r.plan_revision",
            (project_id,),
        ):
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            phase = payload.get("phase") if isinstance(payload, dict) else None
            attempt_status = payload.get("attempt_status") if isinstance(payload, dict) else None
            process_started = payload.get("process_started") if isinstance(payload, dict) else None
            failure_code = payload.get("failure_code") if isinstance(payload, dict) else None
            if (
                isinstance(phase, str) and phase
                and attempt_status in {"completed", "failed", "cancelled", "timed_out", "setup_failed", "blocked"}
                and isinstance(process_started, bool)
                and (failure_code is None or failure_code in {
                    "execution_policy_denied", "process_setup_failed", "process_start_failed",
                    "process_communication_failed", "cancelled", "worker_timeout", "worker_exit_nonzero",
                })
                and phase == row["stage"]
            ):
                attempt_metadata[(row["run_id"], phase)] = payload

    totals = {category: WorkerCallCost() for category in _COST_CATEGORIES}
    total = WorkerCallCost()
    archived_run_ids: set[str] = set()
    directory = _execution_dir(project_id)
    if directory.is_dir():
        for candidate in directory.glob("*.json"):
            try:
                record_path = _record_path(project_id, candidate.stem)
                record = _load_record(record_path)
            except HTTPException:
                continue
            # Each archive represents one launched worker process. Keep counting
            # calls with absent/invalid timing, but treat their duration as zero.
            if not isinstance(record.get("worker"), str) or not isinstance(record.get("phase"), str):
                continue
            run_id = str(record.get("run_id")) if record.get("run_id") else None
            if run_id in runs:
                archived_run_ids.add(run_id)
            category = _cost_category(
                record["phase"],
                runs.get(run_id) if run_id else None,
            )
            duration = _nonnegative_int(record.get("duration_ms"))
            process_started = record.get("process_started", True)
            if not isinstance(process_started, bool):
                process_started = True
            status = record.get("attempt_status")
            if not isinstance(status, str) or not status:
                status = _legacy_attempt_status(record)
            failure_code = record.get("failure_code")
            if not isinstance(failure_code, str) or not failure_code:
                failure_code = _legacy_failure_code(record)
            usage = record.get("usage")
            for bucket in (totals[category], total):
                bucket.duration_ms += duration
                if process_started:
                    bucket.calls += 1
                elif status == "setup_failed":
                    bucket.setup_failures += 1
                _increment(bucket.attempt_status_counts, status)
                if failure_code:
                    _increment(bucket.failure_code_counts, failure_code)
                if process_started:
                    _add_usage(bucket, usage)

    # Runs are registered before process startup. Track runs without an archive
    # separately so setup failures are not presented as worker invocations.
    for run_id, run in runs.items():
        if run_id in archived_run_ids:
            continue
        category = _cost_category("", run)
        metadata = attempt_metadata.get((run_id, str(run.get("stage") or "")))
        attempt_status = metadata.get("attempt_status") if metadata else None
        run_status = str(run.get("status") or "unknown")
        # Lifecycle metadata can prove that the worker process started even if
        # archive persistence failed. It cannot recover duration or provider
        # usage, so those remain zero/unknown in that case.
        process_started = metadata.get("process_started") is True if metadata else False
        status = (
            str(attempt_status)
            if attempt_status == "setup_failed"
            else f"unarchived_{attempt_status}_result_missing"
            if isinstance(attempt_status, str) and attempt_status
            else {
            "running": "unarchived_running_or_interrupted",
            "failed": "unarchived_failed_result_missing",
            "timed_out": "unarchived_timed_out_result_missing",
            "cancelled": "unarchived_cancelled_result_missing",
            "blocked": "unarchived_blocked_result_missing",
            "interrupted": "unarchived_interrupted_result_missing",
            "completed": "unarchived_completed_result_missing",
            "succeeded": "unarchived_succeeded_result_missing",
            }.get(run_status, "unarchived_unknown_status")
        )
        code_value = metadata.get("failure_code") if metadata else None
        code = (
            str(code_value) if isinstance(code_value, str) and code_value
            else "run_error_recorded" if run.get("error_id")
            else "archive_missing"
        )
        for bucket in (totals[category], total):
            bucket.unarchived_attempts += 1
            if process_started:
                bucket.calls += 1
                bucket.usage_unknown_calls += 1
            if attempt_status == "setup_failed":
                bucket.setup_failures += 1
            _increment(bucket.attempt_status_counts, status)
            _increment(bucket.failure_code_counts, code)

    return ProjectCostLedger(
        project_id=project_id,
        total=total,
        by_category=totals,
    )


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _add_usage(bucket: WorkerCallCost, usage: object) -> None:
    if not isinstance(usage, dict):
        bucket.usage_unknown_calls += 1
        return
    token_keys = (
        "input_tokens", "output_tokens", "cached_input_tokens",
        "cache_creation_input_tokens", "total_tokens",
    )
    parsed: dict[str, int] = {}
    incomplete = False
    for key in token_keys:
        value = usage.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            incomplete = True
        else:
            parsed[key] = value
            _increment(bucket.usage_coverage_calls, key)
    if incomplete:
        bucket.usage_unknown_calls += 1
    if "input_tokens" in parsed and "output_tokens" in parsed:
        bucket.usage_recorded_calls += 1
    for key, value in parsed.items():
        prior = getattr(bucket, key)
        setattr(bucket, key, (prior or 0) + value)


def _legacy_attempt_status(record: dict) -> str:
    if record.get("cancelled"):
        return "cancelled"
    if record.get("timed_out"):
        return "timed_out"
    try:
        return "completed" if int(record.get("returncode")) == 0 else "failed"
    except (TypeError, ValueError):
        return "unknown"


def _legacy_failure_code(record: dict) -> str | None:
    status = _legacy_attempt_status(record)
    if status == "completed":
        return None
    return {"failed": "worker_exit_nonzero", "timed_out": "worker_timeout", "cancelled": "cancelled"}.get(status, "unknown")


@router.get("/projects/{project_id}/executions/{execution_id}", response_model=PiExecutionDetail)
def get_pi_execution(project_id: str, execution_id: str) -> PiExecutionDetail:
    _ensure_project(project_id)
    record_path = _record_path(project_id, execution_id)
    record = _load_record(record_path)
    is_pi, probed_session_id = _is_pi_record(record, record_path)
    if not is_pi:
        raise HTTPException(404, "Pi execution record not found")

    stdout = _read_text(_text_path(record_path, "stdout"))
    session_id, legacy_prompt, response = _parse_pi_stream(stdout)
    prompt_path = _text_path(record_path, "prompt")
    prompt = _read_text(prompt_path) if prompt_path.is_file() else legacy_prompt
    summary = _summary(record_path, record, session_id or probed_session_id)
    return PiExecutionDetail(
        **summary.model_dump(),
        prompt=prompt,
        response=response,
        stderr=_read_text(_text_path(record_path, "stderr")),
    )


@router.get("/projects/{project_id}/executions/{execution_id}/streams/{stream}")
def get_pi_execution_stream(
    project_id: str,
    execution_id: str,
    stream: Literal["stdout", "stderr"],
) -> FileResponse:
    _ensure_project(project_id)
    record_path = _record_path(project_id, execution_id)
    record = _load_record(record_path)
    is_pi, _ = _is_pi_record(record, record_path)
    if not is_pi:
        raise HTTPException(404, "Pi execution record not found")
    path = _text_path(record_path, stream)
    if not path.is_file():
        raise HTTPException(404, f"{stream} stream not found")
    return FileResponse(path, media_type="text/plain; charset=utf-8", filename=path.name)
