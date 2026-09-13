from __future__ import annotations

import logging
import json

from fastapi import APIRouter, HTTPException

from linen.server.db import get_conn
from linen.server.audit_state import append_event, create_graph_edge
from linen.server.models import (
    CreateReviewRequest,
    Review,
    REVIEW_DIAGNOSTIC_FIELDS,
)
from linen.server.services import (
    aggregate_fact_status_from_reviews,
    bump_graph_revision,
    next_review_id,
    resolve_intent_errors,
    review_from_row,
    utcnow,
    check_project_active,
    get_project_or_404,
)

router = APIRouter()

LOG = logging.getLogger(__name__)


@router.post(
    "/projects/{project_id}/facts/{fact_id}/reviews",
    response_model=Review,
    status_code=201,
)
def create_review(project_id: str, fact_id: str, body: CreateReviewRequest):
    """Create a Review for a fact.

    The fact's `status` is recomputed after the insert via the aggregation
    rules in `aggregate_fact_status_from_reviews`. Multiple reviews on the
    same fact are allowed; later reviews may flip the status.
    """
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        check_project_active(conn, project_id)
        fact_row = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        if fact_row is None:
            raise HTTPException(404, f"fact {fact_id} not found in project {project_id}")

        rid = next_review_id(conn, project_id)
        now = utcnow()
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, intent_id, verdict, "
            "confidence, summary, reasoning, created_at, created_by, diagnostics, source_generation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rid,
                project_id,
                fact_id,
                body.intent_id,
                body.verdict,
                body.confidence,
                body.summary,
                body.reasoning,
                now,
                body.created_by,
                json.dumps(body.model_dump(include=set(REVIEW_DIAGNOSTIC_FIELDS), exclude_none=True)),
                fact_row["source_generation"] if "source_generation" in fact_row.keys() else 1,
            ),
        )

        # Re-aggregate and persist status (fail-fast on disproof).
        new_status = aggregate_fact_status_from_reviews(
            conn, project_id, fact_id, fact_row["status"]
        )
        if new_status != fact_row["status"]:
            conn.execute(
                "UPDATE facts SET status = ? WHERE id = ? AND project_id = ?",
                (new_status, fact_id, project_id),
            )
        if fact_row["type"] == "vulnerability":
            if body.verdict == "INVALID":
                semantic_type = "rejected_finding"
            elif body.verdict == "VALID" and body.confidence in {"firm", "certain"}:
                semantic_type = "confirmed_finding"
            else:
                semantic_type = "candidate_finding"
            conn.execute(
                "UPDATE facts SET semantic_type = ?, display_title = CASE "
                "WHEN display_title IS NULL OR display_title IN ('Candidate finding', 'Confirmed finding') "
                "THEN ? ELSE display_title END WHERE id = ? AND project_id = ?",
                (
                    semantic_type,
                    "Confirmed finding" if semantic_type == "confirmed_finding" else "Candidate finding",
                    fact_id,
                    project_id,
                ),
            )

        row = conn.execute(
            "SELECT * FROM reviews WHERE id = ? AND project_id = ?",
            (rid, project_id),
        ).fetchone()
        review_obj = review_from_row(row)

        # If a review intent is associated, conclude it as part of the same
        # write. We mirror the behavior of /intents/{id}/conclude but only
        # for review-shaped completion (no fact is produced here). The
        # worker's lease is released by the dispatcher after the response
        # returns; we just need to mark the intent done so the scheduler
        # stops re-claiming it.
        if body.intent_id:
            intent_row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (body.intent_id, project_id),
            ).fetchone()
            if intent_row is None:
                raise HTTPException(404, f"intent {body.intent_id} not found in project {project_id}")
            if intent_row["concluded_at"] is None:
                if intent_row["worker"] is None or (
                    body.created_by and intent_row["worker"] != body.created_by
                ):
                    LOG.warning(
                        "review concluded intent but worker mismatch intent_id=%s expected=%s got=%s",
                        body.intent_id, intent_row["worker"], body.created_by,
                    )
                now_iso = utcnow()
                conn.execute(
                    "UPDATE intents SET concluded_at = ?, worker = COALESCE(worker, ?) "
                    "WHERE id = ? AND project_id = ?",
                    (now_iso, body.created_by, body.intent_id, project_id),
                )
                resolve_intent_errors(
                    conn,
                    project_id,
                    body.intent_id,
                    resolution="review intent concluded successfully",
                    resolved_at=now_iso,
                )

        bump_graph_revision(conn, project_id)
        relation_type = (
            "confirms"
            if body.verdict == "VALID" and body.confidence in {"firm", "certain"}
            else "rejects"
            if body.verdict == "INVALID"
            else "reviews"
        )
        create_graph_edge(
            conn,
            project_id,
            source_kind="review",
            source_id=rid,
            target_kind="fact",
            target_id=fact_id,
            relation_type=relation_type,
            created_by=body.created_by or "reviewer",
            metadata={"verdict": body.verdict, "confidence": body.confidence},
            created_at=now,
        )
        append_event(
            conn,
            project_id,
            "review_created",
            body.created_by or "reviewer",
            entity_kind="review",
            entity_id=rid,
            payload={
                "fact_id": fact_id,
                "intent_id": body.intent_id,
                "verdict": body.verdict,
                "confidence": body.confidence,
                "relation_type": relation_type,
                "summary": body.summary,
            },
            created_at=now,
        )

        return review_obj


@router.get(
    "/projects/{project_id}/facts/{fact_id}/reviews",
    response_model=list[Review],
)
def list_reviews_for_fact_endpoint(project_id: str, fact_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        fact_row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        if fact_row is None:
            raise HTTPException(404, f"fact {fact_id} not found in project {project_id}")
        from linen.server.services import list_reviews_for_fact as _list
        return _list(conn, project_id, fact_id)


@router.get(
    "/projects/{project_id}/reviews",
    response_model=list[Review],
)
def list_reviews_for_project_endpoint(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        from linen.server.services import list_reviews_for_project as _list_proj
        return _list_proj(conn, project_id)
