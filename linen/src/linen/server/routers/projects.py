from __future__ import annotations

import logging
import hashlib
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException

from linen.server.db import get_conn
from linen.server.audit_state import (
    append_event,
    completion_gate_from_db,
    create_graph_edge,
    fact_display_title,
    list_audit_stages,
    list_graph_edges,
    list_human_decisions,
)

_DEFAULT_CLONES_ROOT = Path.home() / ".local" / "share" / "linen" / "clones"
_CLONE_TIMEOUT_SECONDS = 600
_CREATE_PROJECT_LOCK = threading.Lock()
LOG = logging.getLogger(__name__)


def _clones_root() -> Path:
    """Where `clone_url` projects are checked out on the server.

    Override with the `LINEN_CLONES_ROOT` env var (e.g. for tests, or to put
    clones on a different disk). The directory is created lazily on first
    clone; we never delete clones automatically.
    """
    override = os.environ.get("LINEN_CLONES_ROOT")
    return Path(override).expanduser() if override else _DEFAULT_CLONES_ROOT


def _clone_target_occupied(project_id: str) -> bool:
    """Treat files, directories, and broken symlinks as reserved targets."""
    target = _clones_root() / project_id
    return target.exists() or target.is_symlink()


def _resolve_project_repo_root(
    pid: str, clone_url: str | None, repo_root: str | None
) -> str | None:
    """Materialize the per-project `repo_root` for a new project.

    - `clone_url` triggers a synchronous `git clone` into `<clones_root>/<pid>/`.
      The clone is run with `check=True`; on failure (bad URL, auth, network,
      partial state) we raise HTTP 422 with the git stderr tail and clean up
      any half-written directory.
    - `repo_root` is validated to an existing directory. Symlinks are
      resolved. HTTP 422 if missing or not a directory.
    - Both None: no per-project repo_root, dispatcher falls back to config.
    """
    if clone_url is None and repo_root is None:
        return None

    if clone_url is not None:
        target = _clones_root() / pid
        if _clone_target_occupied(pid):
            raise HTTPException(
                409,
                f"clone target already exists: {target} "
                "(the project id allocator should skip retained clone targets)",
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                ["git", "clone", "--", clone_url, str(target)],
                check=False,
                capture_output=True,
                text=True,
                timeout=_CLONE_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            shutil.rmtree(target, ignore_errors=True)
            raise HTTPException(
                422,
                "git is not installed on the server; cannot auto-clone",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(target, ignore_errors=True)
            raise HTTPException(
                422,
                f"git clone timed out after {_CLONE_TIMEOUT_SECONDS}s: {clone_url}",
            ) from exc
        if proc.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
            detail = "\n".join(stderr_tail) if stderr_tail else "git clone failed with no stderr"
            raise HTTPException(
                422,
                f"git clone failed for {clone_url}: {detail}",
            )
        return str(target.resolve())

    assert repo_root is not None
    resolved = Path(repo_root).expanduser().resolve()
    if not resolved.exists():
        raise HTTPException(422, f"repo_root does not exist: {resolved}")
    if not resolved.is_dir():
        raise HTTPException(422, f"repo_root is not a directory: {resolved}")
    return str(resolved)
from linen.server.models import (
    CompleteRequest,
    CreateProjectRequest,
    Fact,
    Hint,
    Intent,
    ProjectDetail,
    ProjectMeta,
    ProjectSummary,
    ReopenRequest,
    ReopenResponse,
    ReasonClaimRequest,
    ReasonHeartbeatRequest,
    UpdateProjectTitleRequest,
    UpdateProjectStatusRequest,
)
from linen.server.services import (
    build_intents,
    list_intent_errors,
    audit_completion_blockers_from_db,
    bump_graph_revision,
    check_project_completed,
    check_project_active,
    clear_project_reason,
    expire_reason_leases,
    expire_workers,
    get_completion_intent_or_409,
    get_project_or_404,
    intent_to_model,
    next_fact_id,
    next_hint_id,
    next_intent_id,
    next_project_id,
    next_report_snapshot_id,
    peek_next_project_id,
    project_meta_from_row,
    project_reason_from_row,
    utcnow,
    validate_facts_exist,
    validate_goal_not_in_sources,
)

router = APIRouter(tags=["projects"])


@router.get("/projects", response_model=list[ProjectSummary])
def list_projects():
    with get_conn() as conn:
        expire_workers(conn)
        expire_reason_leases(conn)
        rows = conn.execute("""
            SELECT p.*,
                (SELECT COUNT(*) FROM facts WHERE project_id = p.id) AS fact_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id) AS intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NOT NULL) AS working_intent_count,
                (SELECT COUNT(*) FROM intents WHERE project_id = p.id AND concluded_at IS NULL AND worker IS NULL) AS unclaimed_intent_count,
                (SELECT COUNT(*) FROM hints WHERE project_id = p.id) AS hint_count,
                (SELECT COUNT(*) FROM reviews WHERE project_id = p.id) AS review_count,
                (SELECT COUNT(*) FROM intent_errors e
                    JOIN intents i ON i.id = e.intent_id AND i.project_id = e.project_id
                    WHERE e.project_id = p.id AND e.resolved_at IS NULL
                      AND e.classification = 'blocked'
                      AND i.to_fact_id IS NULL AND i.concluded_at IS NULL
                ) AS blocked_intent_count,
                (SELECT COUNT(*) FROM intent_errors e
                    JOIN intents i ON i.id = e.intent_id AND i.project_id = e.project_id
                    WHERE e.project_id = p.id AND e.resolved_at IS NULL
                      AND e.classification = 'transient'
                      AND i.to_fact_id IS NULL AND i.concluded_at IS NULL
                ) AS retrying_intent_count
            FROM projects p
            ORDER BY p.created_at
        """).fetchall()
        summaries = []
        for row in rows:
            legacy_activity_status = (
                row["status"]
                if row["status"] != "active"
                else "reasoning"
                if row["reason_worker"] is not None
                else "working"
                if row["working_intent_count"] > 0
                else "blocked"
                if row["blocked_intent_count"] > 0
                else "retrying"
                if row["retrying_intent_count"] > 0
                else "queued"
                if row["unclaimed_intent_count"] > 0
                else "idle"
            )
            gate = completion_gate_from_db(conn, row["id"])
            summaries.append(ProjectSummary(
                id=row["id"],
                title=row["title"],
                status=row["status"],
                graph_revision=row["graph_revision"],
                source_generation=row["source_generation"] if "source_generation" in row.keys() else 1,
                plan_revision=row["plan_revision"] if "plan_revision" in row.keys() else 1,
                bootstrap_enabled=bool(row["bootstrap_enabled"]),
                audit_mode=row["audit_mode"] if "audit_mode" in row.keys() else "none",
                created_at=row["created_at"],
                reason=project_reason_from_row(row),
                fact_count=row["fact_count"],
                intent_count=row["intent_count"],
                working_intent_count=row["working_intent_count"],
                unclaimed_intent_count=row["unclaimed_intent_count"],
                hint_count=row["hint_count"],
                review_count=row["review_count"],
                blocked_intent_count=row["blocked_intent_count"],
                retrying_intent_count=row["retrying_intent_count"],
                activity_status=legacy_activity_status,
                execution_status=gate.execution_status,
                repo_root=row["repo_root"] if "repo_root" in row.keys() else None,
            ))
        return summaries


@router.post("/projects", response_model=ProjectDetail, status_code=201)
def create_project(body: CreateProjectRequest):
    # FastAPI executes synchronous handlers in a thread pool. Serialize the
    # peek/clone/commit sequence so two requests in this server process cannot
    # select the same target while the (potentially slow) clone runs. The DB
    # connection is still opened only after cloning, so other API operations
    # are not blocked by a long-lived SQLite transaction.
    with _CREATE_PROJECT_LOCK:
        preview_pid = peek_next_project_id(
            occupied=_clone_target_occupied if body.clone_url is not None else None
        )
        preview_value = int(preview_pid.removeprefix("proj_"))
        resolved_repo_root = _resolve_project_repo_root(
            preview_pid, body.clone_url, body.repo_root
        )

        with get_conn() as conn:
            pid = next_project_id(conn, minimum_value=preview_value)
            if pid != preview_pid:
                # This requires another server process to have advanced the
                # shared database during the clone. The explicit repo_root is
                # still correct; unlike the old behavior, never rename a
                # user-provided local source directory to match an id.
                LOG.warning(
                    "project counter advanced during source preparation preview=%s actual=%s repo_root=%s",
                    preview_pid,
                    pid,
                    resolved_repo_root,
                )
            now = utcnow()

            conn.execute(
                "INSERT INTO projects (id, title, status, graph_revision, source_generation, plan_revision, "
                "bootstrap_enabled, audit_mode, created_at, repo_root) "
                "VALUES (?, ?, 'active', 1, 1, 1, ?, ?, ?, ?)",
                (pid, body.title, body.bootstrap_enabled, body.audit_mode, now, resolved_repo_root),
            )
            conn.execute(
                "INSERT INTO facts (id, project_id, description, display_title, semantic_type, source_generation) "
                "VALUES (?, ?, ?, ?, 'audit_target', 1)",
                ("origin", pid, body.origin, "Audit target"),
            )
            conn.execute(
                "INSERT INTO facts (id, project_id, description, display_title, semantic_type, source_generation) "
                "VALUES (?, ?, ?, ?, 'audit_objective', 1)",
                ("goal", pid, body.goal, "Audit objective"),
            )

            hints = []
            if body.hints:
                for h in body.hints:
                    hid = next_hint_id(conn, pid)
                    conn.execute(
                        "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
                        (hid, pid, h.content, h.creator, now),
                    )
                    hints.append(Hint(id=hid, content=h.content, creator=h.creator, created_at=now))

            append_event(
                conn,
                pid,
                "project_created",
                "human",
                entity_kind="project",
                entity_id=pid,
                payload={
                    "title": body.title,
                    "audit_mode": body.audit_mode,
                    "bootstrap_enabled": body.bootstrap_enabled,
                },
                created_at=now,
            )

            return ProjectDetail(
                project=ProjectMeta(
                    id=pid,
                    title=body.title,
                    status="active",
                    graph_revision=1,
                    source_generation=1,
                    plan_revision=1,
                    bootstrap_enabled=body.bootstrap_enabled,
                    audit_mode=body.audit_mode,
                    created_at=now,
                    reason=None,
                    repo_root=resolved_repo_root,
                ),
                facts=[
                    Fact(
                        id="origin", description=body.origin, display_title="Audit target",
                        semantic_type="audit_target",
                    ),
                    Fact(
                        id="goal", description=body.goal, display_title="Audit objective",
                        semantic_type="audit_objective",
                    ),
                ],
                intents=[],
                hints=hints,
            )


@router.get("/projects/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str):
    with get_conn() as conn:
        expire_workers(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)

        facts = conn.execute(
            "SELECT * FROM facts WHERE project_id = ?", (project_id,)
        ).fetchall()
        hints = conn.execute(
            "SELECT * FROM hints WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()

        from linen.server.services import list_reviews_for_project
        return ProjectDetail(
            project=project_meta_from_row(row),
            facts=[Fact(**dict(f)) for f in facts],
            intents=build_intents(conn, project_id),
            hints=[Hint(**dict(h)) for h in hints],
            reviews=list_reviews_for_project(conn, project_id),
            errors=list_intent_errors(conn, project_id),
            edges=list_graph_edges(conn, project_id),
            stages=list_audit_stages(conn, project_id),
            decisions=list_human_decisions(conn, project_id),
        )


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))


@router.put("/projects/{project_id}/title", response_model=ProjectMeta)
def update_project_title(project_id: str, body: UpdateProjectTitleRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            "UPDATE projects SET title = ? WHERE id = ?",
            (body.title, project_id),
        )
        bump_graph_revision(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.put("/projects/{project_id}/status", response_model=ProjectMeta)
def update_project_status(project_id: str, body: UpdateProjectStatusRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_status = row["status"]
        if current_status == "completed":
            raise HTTPException(409, "Completed projects cannot change status")
        if current_status == body.status:
            return project_meta_from_row(row)

        conn.execute(
            "UPDATE projects SET status = ? WHERE id = ?",
            (body.status, project_id),
        )
        bump_graph_revision(conn, project_id)
        if body.status == "stopped":
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE project_id = ? AND concluded_at IS NULL",
                (project_id,),
            )
            clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/claim", response_model=ProjectMeta)
def claim_project_reason(project_id: str, body: ReasonClaimRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        current_lease_id = row["reason_lease_id"]
        if current_worker is not None:
            if current_worker == body.worker and current_lease_id == body.lease_id:
                return project_meta_from_row(row)
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")

        now = utcnow()
        conn.execute(
            """
            UPDATE projects
            SET reason_worker = ?,
                reason_lease_id = ?,
                reason_trigger = ?,
                reason_started_at = ?,
                reason_last_heartbeat_at = ?
            WHERE id = ?
            """,
            (body.worker, body.lease_id, body.trigger, now, now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/heartbeat", response_model=ProjectMeta)
def heartbeat_project_reason(project_id: str, body: ReasonHeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            raise HTTPException(409, "Project reason is not currently claimed")
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
        if row["reason_lease_id"] != body.lease_id:
            raise HTTPException(409, "Project reason lease token does not match")

        now = utcnow()
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = ? WHERE id = ?",
            (now, project_id),
        )
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/reason/release", response_model=ProjectMeta)
def release_project_reason(project_id: str, body: ReasonHeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        row = get_project_or_404(conn, project_id)
        current_worker = row["reason_worker"]
        if current_worker is None:
            return project_meta_from_row(row)
        if current_worker != body.worker:
            raise HTTPException(409, f"Project reason is currently claimed by {current_worker}")
        if row["reason_lease_id"] != body.lease_id:
            raise HTTPException(409, "Project reason lease token does not match")

        clear_project_reason(conn, project_id)
        updated = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return project_meta_from_row(updated)


@router.post("/projects/{project_id}/complete", response_model=Intent)
def complete_project(project_id: str, body: CompleteRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        expire_reason_leases(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        gate = completion_gate_from_db(conn, project_id, from_ids=body.from_)
        if not gate.ready:
            raise HTTPException(409, "Audit completion blocked: " + " ".join(gate.blockers))

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        project = get_project_or_404(conn, project_id)

        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, display_title, type, "
            "semantic_type, relation_type, phase, source_generation, plan_revision, creator, worker, "
            "last_heartbeat_at, created_at, concluded_at) "
            "VALUES (?, ?, 'goal', ?, ?, 'complete', 'audit_task', 'produces', 'report', ?, ?, ?, ?, ?, ?, ?)",
            (
                iid,
                project_id,
                body.description,
                "Complete audit",
                project["source_generation"],
                project["plan_revision"],
                body.worker,
                body.worker,
                now,
                now,
                now,
            ),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
            create_graph_edge(
                conn,
                project_id,
                source_kind="fact",
                source_id=fid,
                target_kind="fact",
                target_id="goal",
                relation_type="produces",
                created_by=body.worker,
                metadata={"intent_id": iid},
                created_at=now,
            )
        conn.execute(
            """
            UPDATE projects
            SET status = 'completed',
                graph_revision = graph_revision + 1,
                reason_worker = NULL,
                reason_lease_id = NULL,
                reason_trigger = NULL,
                reason_started_at = NULL,
                reason_last_heartbeat_at = NULL
            WHERE id = ?
            """,
            (project_id,),
        )

        append_event(
            conn,
            project_id,
            "project_completed",
            body.worker,
            entity_kind="project",
            entity_id=project_id,
            payload={"intent_id": iid, "from": body.from_, "description": body.description},
            created_at=now,
        )

        # The report snapshot is part of the same transaction as completion:
        # a project can never be completed without a reproducible report for
        # the exact source/plan/graph revision committed here.
        from linen.server.routers.export import _export_report

        report_text = _export_report(conn, project_id)
        completed_project = get_project_or_404(conn, project_id)
        report_id = next_report_snapshot_id(conn, project_id)
        conn.execute(
            "INSERT INTO report_snapshots (id, project_id, source_generation, plan_revision, "
            "graph_revision, format, content, sha256, created_at) VALUES (?, ?, ?, ?, ?, 'report', ?, ?, ?)",
            (
                report_id,
                project_id,
                completed_project["source_generation"],
                completed_project["plan_revision"],
                completed_project["graph_revision"],
                report_text,
                hashlib.sha256(report_text.encode("utf-8")).hexdigest(),
                now,
            ),
        )

        return Intent(
            id=iid,
            **{"from": body.from_},
            to="goal",
            description=body.description,
            display_title="Complete audit",
            type="complete",
            semantic_type="audit_task",
            relation_type="produces",
            phase="report",
            source_generation=project["source_generation"],
            plan_revision=project["plan_revision"],
            creator=body.worker,
            worker=body.worker,
            last_heartbeat_at=now,
            created_at=now,
            concluded_at=now,
        )


@router.post("/projects/{project_id}/reopen", response_model=ReopenResponse)
def reopen_project(project_id: str, body: ReopenRequest):
    with get_conn() as conn:
        expire_reason_leases(conn, project_id)
        check_project_completed(conn, project_id)
        completion = get_completion_intent_or_409(conn, project_id)

        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (completion["id"], project_id),
        ).fetchall()
        source_ids = [row["fact_id"] for row in source_rows]
        if not source_ids:
            raise HTTPException(409, "Completion intent is missing its source facts")

        now = utcnow()
        fact_id = next_fact_id(conn, project_id)
        intent_id = next_intent_id(conn, project_id)
        description = body.description
        creator = body.creator

        conn.execute(
            "DELETE FROM intents WHERE id = ? AND project_id = ?",
            (completion["id"], project_id),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            (fact_id, project_id, description),
        )
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (intent_id, project_id, fact_id, "external_feedback", creator, creator, now, now, now),
        )
        for source_id in source_ids:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (intent_id, project_id, source_id),
            )
        clear_project_reason(conn, project_id)
        conn.execute(
            "UPDATE projects SET status = 'active', graph_revision = graph_revision + 1 WHERE id = ?",
            (project_id,),
        )

        updated_project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        updated_intent = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        assert updated_project is not None
        assert updated_intent is not None
        return ReopenResponse(
            project=project_meta_from_row(updated_project),
            fact=Fact(id=fact_id, description=description),
            intent=intent_to_model(conn, updated_intent, project_id),
        )
