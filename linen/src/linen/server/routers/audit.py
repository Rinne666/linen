from __future__ import annotations

import sqlite3

from fastapi import APIRouter, HTTPException, Query

from linen.server.audit_state import (
    append_event,
    completion_gate_from_db,
    create_graph_edge,
    effective_human_decisions,
    list_audit_events,
    list_audit_stages,
    list_human_decisions,
)
from linen.server.db import get_conn
from linen.server.models import (
    AuditEvent,
    AuditStage,
    CompletionGate,
    ReplanAuditRequest,
    ReconcileAuditStagesRequest,
    CreateHumanDecisionRequest,
    HumanDecision,
)
from linen.server.services import (
    bump_graph_revision,
    check_project_active,
    get_project_or_404,
    next_human_decision_id,
    utcnow,
)


router = APIRouter(tags=["audit"])


def _validate_decision_target(
    conn: sqlite3.Connection,
    project_id: str,
    target_kind: str,
    target_id: str,
    project: sqlite3.Row,
) -> None:
    """Ensure a manual decision cannot create an orphan graph edge.

    Decisions are intentionally generic, but the target still has to be a
    real node in this project (and a stage must belong to the current plan).
    This keeps typoed IDs from becoming permanently effective gate state.
    """
    if target_kind == "project":
        valid = target_id == project_id
    elif target_kind == "fact":
        valid = conn.execute(
            "SELECT 1 FROM facts WHERE project_id = ? AND id = ? AND source_generation = ?",
            (project_id, target_id, project["source_generation"]),
        ).fetchone() is not None
    elif target_kind == "intent":
        valid = conn.execute(
            "SELECT 1 FROM intents WHERE project_id = ? AND id = ? AND source_generation = ?",
            (project_id, target_id, project["source_generation"]),
        ).fetchone() is not None
    elif target_kind == "stage":
        valid = conn.execute(
            "SELECT 1 FROM audit_stages WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ? AND stage_id = ?",
            (project_id, project["source_generation"], project["plan_revision"], target_id),
        ).fetchone() is not None
    else:
        raise HTTPException(422, "target_kind must be one of: project, fact, intent, stage")
    if not valid:
        raise HTTPException(404, f"Decision target {target_kind}:{target_id} not found")


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


@router.get(
    "/projects/{project_id}/decisions",
    response_model=list[HumanDecision],
)
def get_human_decisions(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        return list_human_decisions(conn, project_id)


@router.post(
    "/projects/{project_id}/decisions",
    response_model=HumanDecision,
    status_code=201,
)
def create_human_decision(
    project_id: str,
    body: CreateHumanDecisionRequest,
):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        _validate_decision_target(conn, project_id, body.target_kind, body.target_id, project)
        if body.supersedes_id:
            superseded = conn.execute(
                "SELECT * FROM human_decisions WHERE project_id = ? AND id = ?",
                (project_id, body.supersedes_id),
            ).fetchone()
            if superseded is None:
                raise HTTPException(404, "Superseded decision not found")
            if superseded["target_kind"] != body.target_kind or superseded["target_id"] != body.target_id:
                raise HTTPException(409, "A decision may supersede only the same target")
            already = conn.execute(
                "SELECT 1 FROM human_decisions WHERE project_id = ? AND supersedes_id = ?",
                (project_id, body.supersedes_id),
            ).fetchone()
            if already is not None:
                raise HTTPException(409, "Decision was already superseded")
        else:
            current = effective_human_decisions(conn, project_id).get(
                (body.target_kind, body.target_id)
            )
            if current is not None:
                raise HTTPException(409, f"Supersede current decision {current.id} instead")
        decision_id = next_human_decision_id(conn, project_id)
        now = utcnow()
        conn.execute(
            "INSERT INTO human_decisions (id, project_id, target_kind, target_id, decision, "
            "rationale, basis_quote, revival_condition, actor, supersedes_id, source_generation, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision_id,
                project_id,
                body.target_kind,
                body.target_id,
                body.decision,
                body.rationale,
                body.basis_quote,
                body.revival_condition,
                body.actor,
                body.supersedes_id,
                project["source_generation"],
                now,
            ),
        )
        relation = {
            "confirm": "confirms",
            "reject": "rejects",
            "waive": "waives",
            "exclude": "waives",
        }[body.decision]
        create_graph_edge(
            conn,
            project_id,
            source_kind="decision",
            source_id=decision_id,
            target_kind=body.target_kind,
            target_id=body.target_id,
            relation_type=relation,
            created_by=body.actor,
            created_at=now,
        )
        append_event(
            conn,
            project_id,
            "human_decision_created",
            body.actor,
            entity_kind="decision",
            entity_id=decision_id,
            payload=body.model_dump(exclude_none=True),
            created_at=now,
        )
        bump_graph_revision(conn, project_id)
        row = conn.execute(
            "SELECT * FROM human_decisions WHERE project_id = ? AND id = ?",
            (project_id, decision_id),
        ).fetchone()
        assert row is not None
        return HumanDecision(**dict(row))
