from datetime import datetime, timedelta, timezone
import json

from fastapi import APIRouter, HTTPException

from linen.server.db import get_conn
from linen.server.audit_state import (
    append_event,
    create_graph_edge,
    fact_display_title,
    fact_semantic_type,
    intent_metadata,
)
from linen.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CompactCoverageIntentsRequest,
    CompactCoverageIntentsResponse,
    CreateIntentRequest,
    Fact,
    HeartbeatRequest,
    Intent,
    IntentError,
    ReportIntentErrorRequest,
    RetryIntentRequest,
)
from linen.server.services import (
    bump_graph_revision,
    check_project_active,
    get_claimable_open_intent_or_404,
    get_intent_or_404,
    get_releasable_open_intent_or_404,
    intent_error_from_row,
    intent_to_model,
    next_fact_id,
    next_hint_id,
    next_intent_error_id,
    next_intent_id,
    resolve_intent_errors,
    utcnow,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_goal_not_in_sources,
)
from linen.server.uvpg import validate_proof_payload

router = APIRouter(tags=["intents"])

COVERAGE_PREFIX = "@coverage:"
AUDIT_CREATOR = "dispatcher.audit"
COMPACTED_INTENT_TYPE = "cancelled:coverage-compaction"


@router.post(
    "/projects/{project_id}/intents/compact-coverage",
    response_model=CompactCoverageIntentsResponse,
)
def compact_coverage_intents(
    project_id: str,
    body: CompactCoverageIntentsRequest,
):
    """Retire surplus queued coverage intents without deleting board history."""
    with get_conn() as conn:
        project = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,),
        ).fetchone()
        if project is None:
            raise HTTPException(404, "Project not found")
        if project["status"] != "stopped":
            raise HTTPException(409, "Coverage queue compaction requires a stopped project")

        rows = conn.execute(
            """
            SELECT id, created_at, last_heartbeat_at
            FROM intents
            WHERE project_id = ?
              AND creator = ?
              AND description LIKE ?
              AND to_fact_id IS NULL
              AND concluded_at IS NULL
              AND worker IS NULL
            """,
            (project_id, AUDIT_CREATOR, f"{COVERAGE_PREFIX}%"),
        ).fetchall()
        ordered = sorted(
            rows,
            key=lambda row: (
                row["last_heartbeat_at"] or row["created_at"],
                row["created_at"],
                row["id"],
            ),
        )
        retained = [row["id"] for row in ordered[:body.keep]]
        retired = [row["id"] for row in ordered[body.keep:]]
        if not body.dry_run and retired:
            now = utcnow()
            placeholders = ",".join("?" for _ in retired)
            conn.execute(
                f"""
                UPDATE intents
                SET type = ?, concluded_at = ?
                WHERE project_id = ? AND id IN ({placeholders})
                  AND worker IS NULL AND to_fact_id IS NULL AND concluded_at IS NULL
                """,
                (COMPACTED_INTENT_TYPE, now, project_id, *retired),
            )
            hint_id = next_hint_id(conn, project_id)
            conn.execute(
                "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    hint_id,
                    project_id,
                    f"Coverage queue compaction retired {len(retired)} surplus graph-derived "
                    f"intents and retained {len(retained)} queued intents. Retired records remain "
                    "in the blackboard with type cancelled:coverage-compaction.",
                    "dispatcher.compaction",
                    now,
                ),
            )
            bump_graph_revision(conn, project_id)
        return CompactCoverageIntentsResponse(
            project_id=project_id,
            dry_run=body.dry_run,
            eligible_count=len(ordered),
            retained_ids=retained,
            retired_ids=retired,
        )


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        inferred_title, inferred_semantic_type, inferred_phase, inferred_relation = intent_metadata(
            body.description, body.type,
        )
        display_title = body.display_title or inferred_title
        semantic_type = body.semantic_type or inferred_semantic_type
        relation_type = body.relation_type or inferred_relation
        phase = body.phase or inferred_phase
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, display_title, type, "
            "semantic_type, relation_type, phase, source_generation, plan_revision, creator, worker, "
            "last_heartbeat_at, created_at, concluded_at) "
            "VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (
                iid,
                project_id,
                body.description,
                display_title,
                body.type,
                semantic_type,
                relation_type,
                phase,
                project["source_generation"],
                project["plan_revision"],
                body.creator,
                body.worker,
                now if claimed else None,
                now,
            ),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        bump_graph_revision(conn, project_id)
        append_event(
            conn,
            project_id,
            "audit_task_created",
            body.creator,
            entity_kind="intent",
            entity_id=iid,
            payload={
                "display_title": display_title,
                "semantic_type": semantic_type,
                "relation_type": relation_type,
                "phase": phase,
                "from": body.from_,
            },
            created_at=now,
        )

        return Intent(
            id=iid,
            **{"from": body.from_},
            to=None,
            description=body.description,
            display_title=display_title,
            type=body.type,
            semantic_type=semantic_type,
            relation_type=relation_type,
            phase=phase,
            source_generation=project["source_generation"],
            plan_revision=project["plan_revision"],
            creator=body.creator,
            worker=body.worker,
            last_heartbeat_at=now if claimed else None,
            created_at=now,
            concluded_at=None,
        )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        conn.execute(
            "UPDATE intents SET worker = ?, last_heartbeat_at = ? WHERE id = ? AND project_id = ?",
            (body.worker, now, intent_id, project_id),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        if row["worker"] == body.worker:
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/fail",
    response_model=IntentError,
)
def report_failure(
    project_id: str,
    intent_id: str,
    body: ReportIntentErrorRequest,
):
    """Persist a failed task attempt and release its Intent lease.

    Transient failures receive bounded exponential backoff. Repeating the
    same error eventually promotes it to ``blocked`` so an invalid
    precondition cannot create an infinite dispatcher loop.
    """
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_releasable_open_intent_or_404(
            conn, project_id, intent_id, body.worker,
        )
        existing = conn.execute(
            "SELECT * FROM intent_errors WHERE project_id = ? AND intent_id = ? "
            "AND resolved_at IS NULL ORDER BY last_failed_at DESC, id DESC LIMIT 1",
            (project_id, intent_id),
        ).fetchone()
        now = utcnow()
        same_episode = existing is not None and existing["code"] == body.code
        if existing is not None and not same_episode:
            resolve_intent_errors(
                conn,
                project_id,
                intent_id,
                resolution=f"superseded by {body.code}",
                resolved_at=now,
            )

        attempt_count = existing["attempt_count"] + 1 if same_episode else 1
        classification = body.classification
        remediation = body.remediation
        if same_episode and existing["classification"] == "blocked":
            classification = "blocked"
            retry_at = None
        elif classification == "transient" and attempt_count >= body.max_attempts:
            classification = "blocked"
            retry_at = None
            if remediation is None:
                remediation = (
                    "Inspect the recorded error, correct its cause, then choose Retry intent."
                )
        elif classification == "transient":
            retry_seconds = min(
                body.base_retry_seconds * (2 ** (attempt_count - 1)),
                body.max_retry_seconds,
            )
            retry_at = (
                datetime.now(timezone.utc) + timedelta(seconds=retry_seconds)
            ).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            retry_at = None

        if same_episode:
            error_id = existing["id"]
            conn.execute(
                "UPDATE intent_errors SET task_type = ?, worker = ?, classification = ?, "
                "message = ?, remediation = ?, attempt_count = ?, last_failed_at = ?, "
                "retry_at = ? WHERE project_id = ? AND id = ?",
                (
                    body.task_type,
                    body.worker,
                    classification,
                    body.message,
                    remediation,
                    attempt_count,
                    now,
                    retry_at,
                    project_id,
                    error_id,
                ),
            )
        else:
            error_id = next_intent_error_id(conn, project_id)
            conn.execute(
                "INSERT INTO intent_errors (id, project_id, intent_id, task_type, worker, "
                "code, classification, message, remediation, attempt_count, "
                "first_failed_at, last_failed_at, retry_at, resolved_at, resolution) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    error_id,
                    project_id,
                    intent_id,
                    body.task_type,
                    body.worker,
                    body.code,
                    classification,
                    body.message,
                    remediation,
                    attempt_count,
                    now,
                    now,
                    retry_at,
                ),
            )

        conn.execute(
            "UPDATE intents SET worker = NULL, last_heartbeat_at = ? "
            "WHERE project_id = ? AND id = ?",
            (now, project_id, intent_id),
        )
        bump_graph_revision(conn, project_id)
        create_graph_edge(
            conn,
            project_id,
            source_kind="error",
            source_id=error_id,
            target_kind="intent",
            target_id=intent_id,
            relation_type="blocks",
            created_by=body.worker,
            metadata={"code": body.code, "classification": classification},
            created_at=now,
        )
        append_event(
            conn,
            project_id,
            "audit_task_failed",
            body.worker,
            entity_kind="intent",
            entity_id=intent_id,
            payload={
                "error_id": error_id,
                "code": body.code,
                "classification": classification,
                "message": body.message,
                "attempt_count": attempt_count,
                "retry_at": retry_at,
            },
            created_at=now,
        )
        row = conn.execute(
            "SELECT * FROM intent_errors WHERE project_id = ? AND id = ?",
            (project_id, error_id),
        ).fetchone()
        return intent_error_from_row(row)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/retry",
    response_model=Intent,
)
def retry_intent(
    project_id: str,
    intent_id: str,
    body: RetryIntentRequest,
):
    """Resolve the current error episode and return an Intent to the queue."""
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_intent_or_404(conn, project_id, intent_id)
        if row["to_fact_id"] is not None or row["concluded_at"] is not None:
            raise HTTPException(409, "Concluded intents cannot be retried")
        if row["worker"] is not None:
            raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
        resolved = resolve_intent_errors(
            conn,
            project_id,
            intent_id,
            resolution=f"manual retry requested by {body.actor}",
        )
        if not resolved:
            raise HTTPException(409, "Intent has no unresolved error")
        bump_graph_revision(conn, project_id)
        append_event(
            conn,
            project_id,
            "audit_task_retry_requested",
            body.actor,
            entity_kind="intent",
            entity_id=intent_id,
            payload={"resolved_error_count": resolved},
        )
        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        intent_row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        fid = next_fact_id(conn, project_id)
        semantic_type = body.semantic_type or fact_semantic_type(fid, body.type, body.status)
        if semantic_type == "confirmed_finding" or body.type == "confirmed_finding":
            raise HTTPException(
                422,
                {"code": "CONFIRMED_FINDING_REQUIRES_TECHNICAL_GATE"},
            )
        display_title = body.display_title or fact_display_title(
            fid, body.type, body.description, status=body.status,
        )
        proof_errors = validate_proof_payload(conn, project_id, body.proof)
        if proof_errors:
            raise HTTPException(422, {"code": "INVALID_PROVENANCE", "details": proof_errors})

        conn.execute(
            "INSERT INTO facts (id, project_id, description, display_title, type, semantic_type, "
            "evidence, proof, source_generation, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fid,
                project_id,
                body.description,
                display_title,
                body.type,
                semantic_type,
                body.evidence,
                json.dumps(body.proof.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
                if body.proof is not None else None,
                project["source_generation"],
                body.status,
            ),
        )
        conn.execute(
            "UPDATE intents SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ? WHERE id = ? AND project_id = ?",
            (fid, body.worker, now, now, intent_id, project_id),
        )
        resolve_intent_errors(
            conn,
            project_id,
            intent_id,
            resolution="intent concluded successfully",
            resolved_at=now,
        )
        bump_graph_revision(conn, project_id)
        sources = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ? ORDER BY rowid",
            (project_id, intent_id),
        ).fetchall()
        relation_type = intent_row["relation_type"] if "relation_type" in intent_row.keys() else "produces"
        for source in sources:
            create_graph_edge(
                conn,
                project_id,
                source_kind="fact",
                source_id=source["fact_id"],
                target_kind="fact",
                target_id=fid,
                relation_type=relation_type,
                created_by=body.worker,
                metadata={"intent_id": intent_id},
                created_at=now,
            )
        append_event(
            conn,
            project_id,
            "audit_task_concluded",
            body.worker,
            entity_kind="intent",
            entity_id=intent_id,
            payload={
                "fact_id": fid,
                "display_title": display_title,
                "semantic_type": semantic_type,
                "relation_type": relation_type,
            },
            created_at=now,
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()

        return ConcludeResponse(
            fact=Fact(
                id=fid,
                description=body.description,
                display_title=display_title,
                type=body.type,
                semantic_type=semantic_type,
                evidence=body.evidence,
                source_generation=project["source_generation"],
                status=body.status,
            ),
            intent=intent_to_model(conn, updated, project_id),
        )
