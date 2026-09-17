"""Compatibility endpoints for the versioned dispatcher/server contracts."""
from __future__ import annotations

import sqlite3
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from stat import S_ISREG

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response
from pydantic import ValidationError

from linen.contracts import ArtifactMetadata, AuditEventEnvelope, BlackboardSnapshot, ContextProjection, RunEnvelope
from linen.server.db import get_conn
from linen.server.routers.executions import workspace_root
from linen.server.store import (
    append_contract_event,
    artifact_from_row,
    context_from_row,
    list_artifacts,
    list_contexts,
    list_runs,
    register_artifact,
    register_context,
    run_from_row,
    snapshot_from_db,
)
from linen.server.kernel import (
    KernelConflict,
    KernelNotFound,
    recover_expired_runs,
    register_run,
    transition_run,
)
from linen.server.services import get_project_or_404, utcnow


router = APIRouter(tags=["vnext"])


def _path_project(body_project: str, project_id: str) -> None:
    if body_project != project_id:
        raise HTTPException(422, "project_id must match the URL path")


def _value_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    if (
        "already exists" in message
        or "already belongs" in message
        or "cannot change" in message
        or "differs" in message
        or "terminal run mutation" in message
        or "illegal run transition" in message
    ):
        return HTTPException(409, message)
    return HTTPException(422, message)


@router.get("/projects/{project_id}/snapshot", response_model=BlackboardSnapshot)
def get_blackboard_snapshot(project_id: str):
    with get_conn() as conn:
        return snapshot_from_db(conn, project_id)


@router.post("/projects/{project_id}/events", response_model=AuditEventEnvelope, status_code=status.HTTP_201_CREATED)
def append_audit_event(project_id: str, body: AuditEventEnvelope):
    _path_project(body.project_id, project_id)
    with get_conn() as conn:
        try:
            # The envelope carries the client's revisions.  Do not silently
            # rewrite them: consumers can detect stale or cross-generation
            # events while legacy internal writers continue to use defaults.
            project = get_project_or_404(conn, project_id)
            if body.source_generation != project["source_generation"] or body.plan_revision != project["plan_revision"]:
                raise HTTPException(409, "event source/plan revision is stale")
            return append_contract_event(conn, body)
        except ValueError as exc:
            raise _value_error(exc) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "event_id or idempotency_key already exists") from exc


@router.post("/projects/{project_id}/artifacts", response_model=ArtifactMetadata, status_code=status.HTTP_201_CREATED)
def post_artifact(project_id: str, body: ArtifactMetadata):
    _path_project(body.project_id, project_id)
    with get_conn() as conn:
        try:
            return register_artifact(conn, body)
        except ValueError as exc:
            raise _value_error(exc) from exc


@router.get("/projects/{project_id}/artifacts", response_model=list[ArtifactMetadata])
def get_artifacts(project_id: str):
    with get_conn() as conn:
        return list_artifacts(conn, project_id)


@router.get("/projects/{project_id}/artifacts/{artifact_id}", response_model=ArtifactMetadata)
def get_artifact(project_id: str, artifact_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute("SELECT * FROM artifacts WHERE project_id = ? AND artifact_id = ?", (project_id, artifact_id)).fetchone()
        if row is None:
            raise HTTPException(404, "artifact not found")
        return artifact_from_row(row)


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
_SAFE_MEDIA_TYPE = re.compile(r"^[A-Za-z0-9!#$&^_.+*/-]+$")


def _artifact_path(project_id: str, artifact: ArtifactMetadata) -> Path:
    """Resolve an artifact without permitting traversal or symlink escape."""
    raw = artifact.workspace_path.replace("\\", "/")
    relative = PurePosixPath(raw)
    if not raw or not relative.parts or raw.startswith("/") or ":" in relative.parts[0] or ".." in relative.parts:
        raise HTTPException(422, "artifact workspace_path must be relative and confined to the project workspace")

    root = workspace_root().resolve()
    project_dir = root / project_id
    try:
        project_real = project_dir.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(404, "artifact workspace is unavailable") from exc
    if not project_dir.is_dir() or project_dir.is_symlink():
        raise HTTPException(409, "artifact project workspace is not a regular directory")
    try:
        project_real.relative_to(root)
    except ValueError as exc:
        raise HTTPException(409, "artifact project workspace escapes the workspace root") from exc

    candidate = project_dir.joinpath(*relative.parts)
    cursor = project_dir
    # Reject symlinks in any path component, including a final symlink that
    # happens to point back inside the workspace.  This closes TOCTOU-style
    # aliasing and keeps the content endpoint limited to ordinary files.
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise HTTPException(409, "artifact path must not contain symlinks")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(404, "artifact content not found") from exc
    except OSError as exc:
        raise HTTPException(409, "artifact content is unavailable") from exc
    try:
        resolved.relative_to(project_real)
    except ValueError as exc:
        raise HTTPException(409, "artifact path escapes the project workspace") from exc
    try:
        if not S_ISREG(resolved.stat().st_mode) or resolved.is_symlink():
            raise HTTPException(409, "artifact content is not a regular file")
    except OSError as exc:
        raise HTTPException(409, "artifact content is unavailable") from exc
    return resolved


@router.get("/projects/{project_id}/artifacts/{artifact_id}/content")
def get_artifact_content(project_id: str, artifact_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM artifacts WHERE project_id = ? AND artifact_id = ?",
            (project_id, artifact_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "artifact not found")
        try:
            artifact = artifact_from_row(row)
        except ValidationError as exc:
            raise HTTPException(409, "artifact metadata is invalid") from exc

    try:
        path = _artifact_path(project_id, artifact)
    except ValueError as exc:
        # Path APIs can reject malformed platform-specific input (notably
        # embedded NULs) before they get as far as an OSError.  Never let that
        # become an unhandled exception from a read endpoint.
        raise HTTPException(422, "artifact path is invalid") from exc
    try:
        before_size = path.stat().st_size
        if artifact.byte_size is not None and before_size != artifact.byte_size:
            raise HTTPException(409, "artifact byte_size does not match metadata")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_stat = os.fstat(descriptor)
            if not S_ISREG(opened_stat.st_mode):
                raise HTTPException(409, "artifact content is not a regular file")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                content = stream.read()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(404, "artifact content is unavailable") from exc
    if artifact.byte_size is not None and len(content) != artifact.byte_size:
        raise HTTPException(409, "artifact byte_size does not match metadata")
    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        raise HTTPException(409, "artifact sha256 does not match metadata")
    if not _SAFE_MEDIA_TYPE.fullmatch(artifact.media_type):
        raise HTTPException(409, "artifact media_type is invalid")
    filename = _SAFE_FILENAME.sub("_", PurePosixPath(artifact.workspace_path).name).strip("._")
    if not filename:
        filename = _SAFE_FILENAME.sub("_", artifact.artifact_id).strip("._") or "artifact"
    return Response(
        content=content,
        media_type=artifact.media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/projects/{project_id}/runs", response_model=RunEnvelope, status_code=status.HTTP_201_CREATED)
def post_run(project_id: str, body: RunEnvelope):
    _path_project(body.project_id, project_id)
    with get_conn() as conn:
        try:
            result = register_run(conn, body)
            append_contract_event(conn, AuditEventEnvelope(
                event_id=f"run-{body.run_id}-created", project_id=project_id, run_id=body.run_id,
                idempotency_key=f"run:{body.run_id}:created", event_type="run_registered", actor="dispatcher",
                entity_kind="run", entity_id=body.run_id, graph_revision=body.graph_revision,
                source_generation=body.source_generation, plan_revision=body.plan_revision,
                payload={"status": result.status}, created_at=result.started_at or utcnow(),
            ))
            return result
        except ValueError as exc:
            raise _value_error(exc) from exc
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "run_id or idempotency_key already exists") from exc


@router.get("/projects/{project_id}/runs", response_model=list[RunEnvelope])
def get_runs(project_id: str):
    with get_conn() as conn:
        return list_runs(conn, project_id)


@router.post(
    "/projects/{project_id}/runs/recover",
    response_model=list[RunEnvelope],
)
def recover_runs(project_id: str):
    with get_conn() as conn:
        try:
            return recover_expired_runs(conn, project_id)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


@router.get("/projects/{project_id}/runs/{run_id}", response_model=RunEnvelope)
def get_run(project_id: str, run_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute("SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (project_id, run_id)).fetchone()
        if row is None:
            raise HTTPException(404, "run not found")
        return run_from_row(row)


@router.put("/projects/{project_id}/runs/{run_id}", response_model=RunEnvelope)
def put_run(project_id: str, run_id: str, body: RunEnvelope):
    _path_project(body.project_id, project_id)
    if body.run_id != run_id:
        raise HTTPException(422, "run_id must match the URL path")
    with get_conn() as conn:
        try:
            result = transition_run(conn, body)
            append_contract_event(conn, AuditEventEnvelope(
                event_id=f"run-{run_id}-{result.status}", project_id=project_id, run_id=run_id,
                idempotency_key=f"run:{run_id}:{result.status}:{result.idempotency_key}", event_type="run_status_changed",
                actor="dispatcher", entity_kind="run", entity_id=run_id, graph_revision=result.graph_revision,
                source_generation=result.source_generation, plan_revision=result.plan_revision,
                payload={"status": result.status}, created_at=result.finished_at or result.started_at or utcnow(),
            ))
            return result
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise _value_error(exc) from exc
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


@router.post("/projects/{project_id}/context-projections", response_model=ContextProjection, status_code=status.HTTP_201_CREATED)
def post_context_projection(project_id: str, body: ContextProjection):
    _path_project(body.project_id, project_id)
    with get_conn() as conn:
        try:
            get_project_or_404(conn, project_id)
            if conn.execute("SELECT 1 FROM snapshots WHERE project_id = ? AND snapshot_id = ?", (project_id, body.snapshot_id)).fetchone() is None:
                raise ValueError("snapshot_id does not belong to this project")
            return register_context(conn, body)
        except ValueError as exc:
            raise _value_error(exc) from exc


@router.get("/projects/{project_id}/context-projections", response_model=list[ContextProjection])
def get_context_projections(project_id: str):
    with get_conn() as conn:
        return list_contexts(conn, project_id)


@router.get("/projects/{project_id}/context-projections/{projection_id}", response_model=ContextProjection)
def get_context_projection(project_id: str, projection_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute("SELECT * FROM context_projections WHERE project_id = ? AND projection_id = ?", (project_id, projection_id)).fetchone()
        if row is None:
            raise HTTPException(404, "context projection not found")
        return context_from_row(row)
