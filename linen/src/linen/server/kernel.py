"""Authoritative server-side state transitions.

Routers translate HTTP requests and map kernel errors to status codes.  This
module owns the Review mutation so its lifecycle, candidate semantics, graph
edge, and audit event cannot drift across endpoints.
"""
from __future__ import annotations

import json
import hashlib
import logging
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone

from linen.server.audit_state import append_event, create_graph_edge, intent_metadata
from linen.server.models import (
    CreateIntentRequest, CreateReviewRequest, HeartbeatRequest, Intent, REVIEW_DIAGNOSTIC_FIELDS, Review,
)
from linen.server.services import (
    aggregate_fact_status_from_reviews,
    bump_graph_revision,
    check_project_active,
    next_review_id,
    resolve_intent_errors,
    review_from_row,
    intent_to_model,
    next_intent_id,
    validate_facts_exist,
    validate_goal_not_in_sources,
    validate_intent_creator_worker,
    expire_workers,
    utcnow,
)
from linen.server.store import (
    append_contract_event,
    run_from_row,
    register_run as store_register_run,
    transition_run as store_transition_run,
)
from linen.contracts import AuditEventEnvelope, RunEnvelope
from linen.server.uvpg import UNIFIED_REVIEW_KIND, proof_graph_fingerprint

LOG = logging.getLogger(__name__)


class KernelNotFound(LookupError):
    """The requested project, fact, or intent does not exist."""


class KernelForbidden(PermissionError):
    """The requested mutation is not legal for the current project state."""


class KernelConflict(ValueError):
    """The request conflicts with current authoritative state."""


TERMINAL_RUN_STATUSES = frozenset({
    "completed", "succeeded", "failed", "cancelled", "timed_out", "interrupted", "blocked",
})
LEGAL_RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"queued", "running", "cancelled", "interrupted", "blocked"}),
    "running": frozenset(TERMINAL_RUN_STATUSES | {"running"}),
}
for _status in TERMINAL_RUN_STATUSES:
    LEGAL_RUN_TRANSITIONS[_status] = frozenset({_status})

IMMUTABLE_RUN_FIELDS = (
    "run_id", "project_id", "idempotency_key", "task_type", "intent_id", "stage", "attempt",
    "graph_revision", "source_generation", "plan_revision", "context_projection_id",
    "worker_manifest_digest", "timeout_seconds",
)


def register_run(conn: sqlite3.Connection, run: RunEnvelope) -> RunEnvelope:
    """Validate the runtime contract, then delegate persistence to Store."""
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (run.project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {run.project_id} not found")
    if run.intent_id is not None and conn.execute(
        "SELECT 1 FROM intents WHERE project_id = ? AND id = ?", (run.project_id, run.intent_id)
    ).fetchone() is None:
        raise KernelConflict("intent_id does not belong to this project")
    if any(conn.execute(
        "SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?", (run.project_id, aid)
    ).fetchone() is None for aid in run.artifact_ids):
        raise KernelConflict("run references an unknown artifact")
    if run.context_projection_id is not None and conn.execute(
        "SELECT 1 FROM context_projections WHERE project_id = ? AND projection_id = ?",
        (run.project_id, run.context_projection_id),
    ).fetchone() is None:
        raise KernelConflict("context_projection_id does not belong to this project")
    existing = conn.execute(
        "SELECT * FROM runs WHERE project_id = ? AND (run_id = ? OR idempotency_key = ?)",
        (run.project_id, run.run_id, run.idempotency_key),
    ).fetchone()
    if existing is not None:
        current = run_from_row(existing)
        for field in IMMUTABLE_RUN_FIELDS:
            if getattr(current, field) != getattr(run, field):
                raise KernelConflict(f"run {field} differs from the existing idempotent run")
    try:
        return store_register_run(conn, run)
    except ValueError as exc:
        raise KernelConflict(str(exc)) from exc


def transition_run(conn: sqlite3.Connection, run: RunEnvelope) -> RunEnvelope:
    """Enforce Run lifecycle policy before Store performs the update."""
    row = conn.execute(
        "SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (run.project_id, run.run_id)
    ).fetchone()
    if row is None:
        raise KernelNotFound(f"run {run.run_id} not found")
    current = run_from_row(row)
    for field in IMMUTABLE_RUN_FIELDS:
        if getattr(current, field) != getattr(run, field):
            raise KernelConflict(f"run {field} cannot change")
    if run.status not in LEGAL_RUN_TRANSITIONS[current.status]:
        raise KernelConflict(f"illegal run transition: {current.status} -> {run.status}")
    for artifact_id in run.artifact_ids:
        if conn.execute(
            "SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?",
            (run.project_id, artifact_id),
        ).fetchone() is None:
            raise KernelConflict("run references an unknown artifact")
    if current.status in TERMINAL_RUN_STATUSES:
        for field in ("worker_name", "worker_type", "artifact_ids", "error_id"):
            if getattr(run, field) != getattr(current, field):
                raise KernelConflict("terminal run mutation is not allowed")
        for field in ("started_at", "finished_at"):
            requested = getattr(run, field)
            if requested is not None and requested != getattr(current, field):
                raise KernelConflict("terminal run mutation is not allowed")
        return current
    try:
        return store_transition_run(conn, run)
    except ValueError as exc:
        raise KernelConflict(str(exc)) from exc


def _parse_utc_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def recover_expired_runs(conn: sqlite3.Connection, project_id: str, *, now: str | None = None) -> list[RunEnvelope]:
    project = conn.execute("SELECT 1 FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {project_id} not found")
    now_text = now or utcnow()
    current_time = _parse_utc_timestamp(now_text)
    if current_time is None:
        raise KernelConflict("recovery now must be a valid ISO timestamp")
    recovered: list[RunEnvelope] = []
    for row in conn.execute("SELECT * FROM runs WHERE project_id = ? AND status = 'running' ORDER BY run_id", (project_id,)).fetchall():
        run = run_from_row(row)
        started = _parse_utc_timestamp(run.started_at)
        if started is None or started + timedelta(seconds=run.timeout_seconds) > current_time:
            continue
        result = transition_run(conn, run.model_copy(update={"status": "interrupted", "finished_at": now_text}))
        append_contract_event(conn, AuditEventEnvelope(
            event_id=f"run-{run.run_id}-orphan-recovery", project_id=project_id, run_id=run.run_id,
            idempotency_key=f"run:{run.run_id}:orphan-recovery:{run.idempotency_key}", event_type="run_orphan_recovered",
            actor="server", entity_kind="run", entity_id=run.run_id, graph_revision=result.graph_revision,
            source_generation=result.source_generation, plan_revision=result.plan_revision,
            payload={"previous_status": "running", "status": "interrupted", "reason": "timeout"}, created_at=now_text,
        ))
        recovered.append(result)
    return recovered


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

    intent_row = None
    if body.intent_id:
        intent_row = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?", (body.intent_id, project_id)
        ).fetchone()
        if intent_row is None:
            raise KernelNotFound(f"intent {body.intent_id} not found in project {project_id}")
        if intent_row["type"] != "review" and not intent_row["type"].startswith("review:"):
            raise KernelConflict("review must target a review intent")
        source_ids = {
            row["fact_id"] for row in conn.execute(
                "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ?",
                (project_id, body.intent_id),
            )
        }
        if fact_id not in source_ids:
            raise KernelConflict("review fact is not an intended review source")
        if intent_row["worker"] is not None and intent_row["worker"] != body.created_by:
            raise KernelConflict("review worker does not own the claimed intent")

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
        if intent_row["concluded_at"] is None:
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


def create_intent(conn: sqlite3.Connection, project_id: str, body: CreateIntentRequest) -> Intent:
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {project_id} not found")
    if project["status"] != "active":
        raise KernelForbidden(f"Project is {project['status']}")
    for fact_id in body.from_:
        if conn.execute("SELECT 1 FROM facts WHERE id = ? AND project_id = ?", (fact_id, project_id)).fetchone() is None:
            raise KernelNotFound(f"Fact {fact_id} not found")
    if "goal" in body.from_:
        raise KernelConflict("goal cannot be used in from")
    try:
        validate_intent_creator_worker(body.creator, body.worker)
    except Exception as exc:
        raise KernelConflict(str(exc)) from exc
    now = utcnow()
    iid = next_intent_id(conn, project_id)
    claimed = body.worker is not None
    inferred_title, inferred_semantic_type, inferred_phase, inferred_relation = intent_metadata(body.description, body.type)
    display_title = body.display_title or inferred_title
    semantic_type = body.semantic_type or inferred_semantic_type
    relation_type = body.relation_type or inferred_relation
    phase = body.phase or inferred_phase
    def canonical(value: str) -> str:
        return " ".join(unicodedata.normalize("NFKC", value).strip().casefold().split())

    action = body.action or body.type or semantic_type
    target = body.target or body.description
    scope = body.scope or ",".join(sorted(body.from_))
    intent_key = hashlib.sha256(
        json.dumps(
            {"action": canonical(action), "target": canonical(target), "scope": canonical(scope)},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    existing = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? AND intent_key = ?",
        (project_id, intent_key),
    ).fetchone()
    if existing is not None:
        return intent_to_model(conn, existing, project_id)
    try:
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, display_title, type, semantic_type, relation_type, phase, source_generation, plan_revision, creator, worker, last_heartbeat_at, created_at, concluded_at, intent_key) "
            "VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (iid, project_id, body.description, display_title, body.type, semantic_type, relation_type, phase,
             project["source_generation"], project["plan_revision"], body.creator, body.worker, now if claimed else None, now, intent_key),
        )
    except sqlite3.IntegrityError:
        # A concurrent creator may win the unique (project_id, intent_key)
        # race.  The existing row is the idempotent result, not an error.
        existing = conn.execute(
            "SELECT * FROM intents WHERE project_id = ? AND intent_key = ?",
            (project_id, intent_key),
        ).fetchone()
        if existing is None:
            raise
        return intent_to_model(conn, existing, project_id)
    for fact_id in body.from_:
        conn.execute("INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)", (iid, project_id, fact_id))
    bump_graph_revision(conn, project_id)
    append_event(conn, project_id, "audit_task_created", body.creator, entity_kind="intent", entity_id=iid,
                 payload={"display_title": display_title, "semantic_type": semantic_type, "relation_type": relation_type,
                          "phase": phase, "from": body.from_}, created_at=now)
    row = conn.execute("SELECT * FROM intents WHERE id = ? AND project_id = ?", (iid, project_id)).fetchone()
    return intent_to_model(conn, row, project_id)


def _claimable_intent(conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = conn.execute("SELECT * FROM intents WHERE id = ? AND project_id = ?", (intent_id, project_id)).fetchone()
    if row is None:
        raise KernelNotFound("Intent not found")
    if row["to_fact_id"] is not None:
        raise KernelConflict("Intent already concluded")
    if row["worker"] is not None and row["worker"] != worker:
        raise KernelConflict(f"Intent is currently claimed by {row['worker']}")
    error = conn.execute("SELECT code, classification, message, retry_at FROM intent_errors WHERE project_id = ? AND intent_id = ? AND resolved_at IS NULL ORDER BY last_failed_at DESC, id DESC LIMIT 1", (project_id, intent_id)).fetchone()
    if error is not None and row["worker"] is None:
        if error["classification"] == "blocked":
            raise KernelConflict(f"Intent is blocked [{error['code']}]: {error['message']}")
        if error["retry_at"] and error["retry_at"] > utcnow():
            raise KernelConflict(f"Intent retry is deferred until {error['retry_at']} [{error['code']}]: {error['message']}")
    return row


def heartbeat_intent(conn: sqlite3.Connection, project_id: str, intent_id: str, body: HeartbeatRequest) -> Intent:
    project = conn.execute("SELECT status FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {project_id} not found")
    if project["status"] != "active":
        raise KernelForbidden(f"Project is {project['status']}")
    _claimable_intent(conn, project_id, intent_id, body.worker)
    now = utcnow()
    conn.execute("UPDATE intents SET worker = ?, last_heartbeat_at = ? WHERE id = ? AND project_id = ?", (body.worker, now, intent_id, project_id))
    return intent_to_model(conn, conn.execute("SELECT * FROM intents WHERE id = ? AND project_id = ?", (intent_id, project_id)).fetchone(), project_id)


def release_intent(conn: sqlite3.Connection, project_id: str, intent_id: str, body: HeartbeatRequest) -> Intent:
    project = conn.execute("SELECT status FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        raise KernelNotFound(f"Project {project_id} not found")
    if project["status"] != "active":
        raise KernelForbidden(f"Project is {project['status']}")
    expire_workers(conn, project_id)
    row = conn.execute("SELECT * FROM intents WHERE id = ? AND project_id = ?", (intent_id, project_id)).fetchone()
    if row is None:
        raise KernelNotFound("Intent not found")
    if row["to_fact_id"] is not None:
        raise KernelConflict("Intent already concluded")
    if row["worker"] is not None and row["worker"] != body.worker:
        raise KernelConflict(f"Intent is currently claimed by {row['worker']}")
    if row["worker"] == body.worker:
        conn.execute("UPDATE intents SET worker = NULL WHERE id = ? AND project_id = ?", (intent_id, project_id))
    return intent_to_model(conn, conn.execute("SELECT * FROM intents WHERE id = ? AND project_id = ?", (intent_id, project_id)).fetchone(), project_id)
