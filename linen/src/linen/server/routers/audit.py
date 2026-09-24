from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from linen.server.audit_state import (
    append_event,
    completion_gate_from_db,
    list_audit_events,
    list_audit_stages,
)
from linen.server.db import get_conn
from linen.server.models import (
    AuditEvent,
    AuditStage,
    CompletionGate,
    ReplanAuditRequest,
    ReconcileAuditStagesRequest,
)
from linen.server.services import (
    bump_graph_revision,
    check_project_active,
    get_project_or_404,
    utcnow,
)


router = APIRouter(tags=["audit"])


@router.get(
    "/projects/{project_id}/completion-gate",
    response_model=CompletionGate,
)
def get_completion_gate(
    project_id: str,
    from_id: list[str] = Query(default=[]),
):
    with get_conn() as conn:
        return completion_gate_from_db(
            conn,
            project_id,
            from_ids=from_id or None,
        )


@router.get(
    "/projects/{project_id}/events",
    response_model=list[AuditEvent],
)
def get_audit_events(
    project_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=2000),
):
    with get_conn() as conn:
        return list_audit_events(conn, project_id, after=after, limit=limit)


@router.get(
    "/projects/{project_id}/stages",
    response_model=list[AuditStage],
)
def get_audit_stages(project_id: str):
    with get_conn() as conn:
        return list_audit_stages(conn, project_id)


@router.put(
    "/projects/{project_id}/stages",
    response_model=list[AuditStage],
)
def reconcile_audit_stages(
    project_id: str,
    body: ReconcileAuditStagesRequest,
):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        generation = project["source_generation"]
        revision = project["plan_revision"]
        if body.source_generation != generation:
            raise HTTPException(409, "Stage source_generation is stale")
        if body.plan_revision != revision:
            raise HTTPException(409, "Stage plan_revision is stale")
        existing_rows = conn.execute(
            "SELECT * FROM audit_stages WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ? ORDER BY stage_id",
            (project_id, generation, revision),
        ).fetchall()
        requested = {stage.stage_id: stage for stage in body.stages}
        existing = {row["stage_id"]: row for row in existing_rows}
        if existing and set(existing) != set(requested):
            raise HTTPException(
                409,
                "Audit stage set is frozen for this plan; explicitly replan to change obligations",
            )
        now = utcnow()
        changed = False
        for stage_id, stage in requested.items():
            prior = existing.get(stage_id)
            if prior is None:
                conn.execute(
                    "INSERT INTO audit_stages (project_id, source_generation, plan_revision, stage_id, "
                    "label, phase_order, required, status, capability, detail, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id, generation, revision, stage_id, stage.label,
                        stage.phase_order, int(stage.required), stage.status,
                        stage.capability, stage.detail, now,
                    ),
                )
                label, required, capability = stage.label, stage.required, stage.capability
                changed = True
            else:
                label, required, capability = prior["label"], bool(prior["required"]), prior["capability"]
                if prior["status"] == stage.status and prior["detail"] == stage.detail:
                    continue
                conn.execute(
                    "UPDATE audit_stages SET status = ?, detail = ?, updated_at = ? "
                    "WHERE project_id = ? AND source_generation = ? AND plan_revision = ? AND stage_id = ?",
                    (stage.status, stage.detail, now, project_id, generation, revision, stage_id),
                )
                changed = True
            append_event(
                conn, project_id, "audit_stage_updated", body.actor,
                entity_kind="stage", entity_id=stage_id,
                payload={
                    "label": label, "status": stage.status,
                    "required": required, "capability": capability,
                    "detail": stage.detail,
                },
                created_at=now,
            )
        if changed:
            bump_graph_revision(conn, project_id)
        return list_audit_stages(conn, project_id)


@router.post("/projects/{project_id}/replan")
def replan_audit(project_id: str, body: ReplanAuditRequest):
    """Advance the audit plan only after all work from the current plan is settled."""
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        if body.source_generation != project["source_generation"]:
            raise HTTPException(409, "Replan source_generation is stale")
        if body.plan_revision != project["plan_revision"]:
            raise HTTPException(409, "Replan plan_revision is stale")
        open_intent = conn.execute(
            "SELECT id FROM intents WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ? AND to_fact_id IS NULL AND concluded_at IS NULL LIMIT 1",
            (project_id, project["source_generation"], project["plan_revision"]),
        ).fetchone()
        if open_intent is not None:
            raise HTTPException(409, "Cannot replan while current-plan intents are unresolved")
        next_revision = project["plan_revision"] + 1
        conn.execute(
            "UPDATE projects SET plan_revision = ? WHERE id = ?",
            (next_revision, project_id),
        )
        bump_graph_revision(conn, project_id)
        append_event(
            conn, project_id, "audit_plan_replanned", body.actor,
            entity_kind="plan", entity_id=str(next_revision),
            payload={"previous_plan_revision": project["plan_revision"], "rationale": body.rationale},
            created_at=utcnow(),
        )
        return {
            "project_id": project_id,
            "source_generation": project["source_generation"],
            "plan_revision": next_revision,
        }
