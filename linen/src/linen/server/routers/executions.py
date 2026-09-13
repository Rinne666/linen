from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from linen.server.db import get_conn
from linen.server.models import PiExecutionDetail, PiExecutionPage, PiExecutionSummary
from linen.server.services import get_project_or_404


router = APIRouter(tags=["executions"])

DEFAULT_WORKSPACE_ROOT = Path.home() / ".local" / "share" / "linen" / "workspaces"
_workspace_root_override: Path | None = None
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


def configure_workspace_root(path: Path | None) -> None:
    global _workspace_root_override
    _workspace_root_override = path.expanduser().resolve() if path is not None else None


def workspace_root() -> Path:
    if _workspace_root_override is not None:
        return _workspace_root_override
    configured = os.environ.get("LINEN_WORKSPACE_ROOT")
    return Path(configured).expanduser().resolve() if configured else DEFAULT_WORKSPACE_ROOT.resolve()


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
