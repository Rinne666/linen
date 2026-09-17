"""Authoritative server-side state transitions.

Routers translate HTTP requests and map kernel errors to status codes.  This
module owns the Review mutation so its lifecycle, candidate semantics, graph
edge, and audit event cannot drift across endpoints.
"""
from __future__ import annotations

import json
import logging
import sqlite3

from linen.server.audit_state import append_event, create_graph_edge
from linen.server.models import CreateReviewRequest, REVIEW_DIAGNOSTIC_FIELDS, Review
from linen.server.services import (
    aggregate_fact_status_from_reviews,
    bump_graph_revision,
    check_project_active,
    next_review_id,
    resolve_intent_errors,
    review_from_row,
    utcnow,
)
from linen.server.uvpg import UNIFIED_REVIEW_KIND, proof_graph_fingerprint

LOG = logging.getLogger(__name__)


class KernelNotFound(LookupError):
    """The requested project, fact, or intent does not exist."""


class KernelForbidden(PermissionError):
    """The requested mutation is not legal for the current project state."""


class KernelConflict(ValueError):
    """The request conflicts with current authoritative state."""


def create_review(
    conn: sqlite3.Connection,
    project_id: str,
    fact_id: str,
    body: CreateReviewRequest,
) -> Review:
    """Persist one Review and all server-owned side effects atomically."""
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {project_id} not found")
    if project["status"] != "active":
        raise KernelForbidden(f"Project is {project['status']}")
    fact_row = conn.execute(
        "SELECT * FROM facts WHERE id = ? AND project_id = ?", (fact_id, project_id)
    ).fetchone()
    if fact_row is None:
        raise KernelNotFound(f"fact {fact_id} not found in project {project_id}")

    diagnostics = body.model_dump(include=set(REVIEW_DIAGNOSTIC_FIELDS), exclude_none=True)
    verification = diagnostics.get("cold_verification")
    if (
        fact_row["type"] == "vulnerability"
        and isinstance(verification, dict)
        and verification.get("review_kind") == UNIFIED_REVIEW_KIND
    ):
        if verification.get("candidate_id") not in (None, fact_id):
            raise KernelConflict("unified proof review is bound to another candidate")
        verification = dict(verification)
        verification["review_kind"] = UNIFIED_REVIEW_KIND
        verification["candidate_id"] = fact_id
        verification["proof_evidence_sha256"] = proof_graph_fingerprint(conn, project_id, fact_id)
        diagnostics["cold_verification"] = verification

    rid = next_review_id(conn, project_id)
    now = utcnow()
    conn.execute(
        "INSERT INTO reviews (id, project_id, fact_id, intent_id, verdict, "
        "confidence, summary, reasoning, created_at, created_by, diagnostics, source_generation) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            rid, project_id, fact_id, body.intent_id, body.verdict, body.confidence,
            body.summary, body.reasoning, now, body.created_by, json.dumps(diagnostics),
            fact_row["source_generation"] if "source_generation" in fact_row.keys() else 1,
        ),
    )

    new_status = aggregate_fact_status_from_reviews(conn, project_id, fact_id, fact_row["status"])
    if new_status != fact_row["status"]:
        conn.execute(
            "UPDATE facts SET status = ? WHERE id = ? AND project_id = ?",
            (new_status, fact_id, project_id),
        )
    if fact_row["type"] == "vulnerability":
        if fact_row["semantic_type"] == "confirmed_finding":
            semantic_type = "confirmed_finding"
        elif body.verdict == "INVALID":
            semantic_type = "rejected_finding"
        else:
            # Review attests evidence quality; Technical Confirmation remains
            # the sole candidate -> confirmed transition.
            semantic_type = "candidate_finding"
        conn.execute(
            "UPDATE facts SET semantic_type = ?, display_title = CASE "
            "WHEN display_title IS NULL OR display_title IN ('Candidate finding', 'Confirmed finding') "
            "THEN ? ELSE display_title END WHERE id = ? AND project_id = ?",
            (semantic_type, "Candidate finding" if semantic_type == "candidate_finding" else "Rejected finding", fact_id, project_id),
        )

    if body.intent_id:
        intent_row = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?", (body.intent_id, project_id)
        ).fetchone()
        if intent_row is None:
            raise KernelNotFound(f"intent {body.intent_id} not found in project {project_id}")
        if intent_row["concluded_at"] is None:
            if intent_row["worker"] is None or (body.created_by and intent_row["worker"] != body.created_by):
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
            resolve_intent_errors(conn, project_id, body.intent_id, resolution="review intent concluded successfully", resolved_at=now_iso)

    bump_graph_revision(conn, project_id)
    relation_type = (
        "confirms" if body.verdict == "VALID" and body.confidence in {"firm", "certain"}
        else "rejects" if body.verdict == "INVALID" else "reviews"
    )
    create_graph_edge(
        conn, project_id, source_kind="review", source_id=rid,
        target_kind="fact", target_id=fact_id, relation_type=relation_type,
        created_by=body.created_by or "reviewer",
        metadata={"verdict": body.verdict, "confidence": body.confidence}, created_at=now,
    )
    append_event(
        conn, project_id, "review_created", body.created_by or "reviewer",
        entity_kind="review", entity_id=rid,
        payload={
            "fact_id": fact_id, "intent_id": body.intent_id, "verdict": body.verdict,
            "confidence": body.confidence, "relation_type": relation_type, "summary": body.summary,
        }, created_at=now,
    )
    row = conn.execute("SELECT * FROM reviews WHERE id = ? AND project_id = ?", (rid, project_id)).fetchone()
    assert row is not None
    return review_from_row(row)
