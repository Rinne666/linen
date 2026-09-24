from __future__ import annotations

from collections.abc import Callable
import json

import sqlite3
from datetime import datetime, timezone

from fastapi import HTTPException

from linen.server.db import get_conn
from linen.server.models import (
    FACT_TYPE_COVERAGE_PLAN,
    FACT_STATUS_DRAFT,
    FACT_STATUS_FALSE_POSITIVE,
    FACT_STATUS_TRIAGED,
    Intent,
    IntentError,
    ProjectMeta,
    ProjectReason,
    Review,
    REVIEWLESS_INTERMEDIATE_FACT_TYPES,
)

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_project_id(conn: sqlite3.Connection, *, minimum_value: int | None = None) -> str:
    """Advance and return the project counter.

    ``minimum_value`` lets callers reserve a later id after deliberately
    skipping unavailable filesystem-backed ids.  Gaps are intentional: a
    retained clone must never be silently adopted by an unrelated project.
    """
    row = conn.execute("SELECT value FROM counters WHERE name = 'project'").fetchone()
    current = row["value"] if row else 0
    value = max(current + 1, minimum_value or 0)
    conn.execute("UPDATE counters SET value = ? WHERE name = 'project'", (value,))
    return f"proj_{value:03d}"


def peek_next_project_id(*, occupied: Callable[[str], bool] | None = None) -> str:
    """Read the next project_id WITHOUT incrementing the counter.

    Used by the create-project handler to compute a clone destination
    before opening the main DB transaction.  ``occupied`` can additionally
    reserve ids backed by external state, such as retained clone directories.
    Existing database rows are always skipped defensively in case a restored
    database has a stale counter.
    """
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM counters WHERE name = 'project'").fetchone()
        value = (row["value"] if row else 0) + 1
        while True:
            project_id = f"proj_{value:03d}"
            exists = conn.execute(
                "SELECT 1 FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if exists is None and (occupied is None or not occupied(project_id)):
                return project_id
            value += 1


def _next_scoped_id(
    conn: sqlite3.Connection, kind: str, prefix: str, project_id: str
) -> str:
    conn.execute(
        "INSERT OR IGNORE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, 0)",
        (project_id, kind),
    )
    conn.execute(
        "UPDATE scoped_counters SET value = value + 1 WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    )
    row = conn.execute(
        "SELECT value FROM scoped_counters WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    ).fetchone()
    assert row is not None
    return f"{prefix}{row['value']:03d}"


def next_fact_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "fact", "f", project_id)


def next_intent_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "intent", "i", project_id)


def next_hint_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "hint", "h", project_id)


def next_intent_error_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "intent_error", "e", project_id)


def next_graph_edge_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "graph_edge", "g", project_id)


def next_human_decision_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "human_decision", "d", project_id)


def next_report_snapshot_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "report_snapshot", "rp", project_id)


def get_project_or_404(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT p.*, COALESCE((SELECT MAX(sequence) FROM audit_events "
        "WHERE project_id = p.id), 0) AS latest_event_seq "
        "FROM projects p WHERE p.id = ?",
        (project_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Project not found")
    return row


def check_project_active(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "active":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_hint_writable(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] not in ("active", "stopped", "completed"):
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_completed(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "completed":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def validate_facts_exist(
    conn: sqlite3.Connection, project_id: str, fact_ids: list[str]
) -> None:
    for fid in fact_ids:
        row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?", (fid, project_id)
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Fact {fid} not found")


def validate_goal_not_in_sources(fact_ids: list[str]) -> None:
    if "goal" in fact_ids:
        raise HTTPException(400, "goal cannot be used in from")


def bump_graph_revision(conn: sqlite3.Connection, project_id: str) -> None:
    """Advance the semantic blackboard version once per atomic mutation."""
    conn.execute(
        "UPDATE projects SET graph_revision = graph_revision + 1 WHERE id = ?",
        (project_id,),
    )


def validate_intent_creator_worker(creator: str, worker: str | None) -> None:
    if worker is not None and worker != creator:
        raise HTTPException(400, "worker must be null or equal to creator")


def get_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Intent not found")
    return row


def get_claimable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is not None and row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    error = conn.execute(
        "SELECT code, classification, message, retry_at FROM intent_errors "
        "WHERE project_id = ? AND intent_id = ? AND resolved_at IS NULL "
        "ORDER BY last_failed_at DESC, id DESC LIMIT 1",
        (project_id, intent_id),
    ).fetchone()
    if error is not None and row["worker"] is None:
        if error["classification"] == "blocked":
            raise HTTPException(
                409,
                f"Intent is blocked [{error['code']}]: {error['message']}",
            )
        retry_at = error["retry_at"]
        if retry_at and retry_at > utcnow():
            raise HTTPException(
                409,
                f"Intent retry is deferred until {retry_at} [{error['code']}]: "
                f"{error['message']}",
            )
    return row


def get_releasable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is None:
        return row
    if row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_completion_intent_or_409(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? AND to_fact_id = 'goal'",
        (project_id,),
    ).fetchall()
    if not rows:
        raise HTTPException(409, "Completed project is missing its completion intent")
    if len(rows) != 1:
        raise HTTPException(409, "Completed project has multiple completion intents")
    return rows[0]


def intent_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> Intent:
    sources = conn.execute(
        "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
        (row["id"], project_id),
    ).fetchall()
    return Intent(
        id=row["id"],
        **{"from": [s["fact_id"] for s in sources]},
        to=row["to_fact_id"],
        description=row["description"],
        display_title=row["display_title"] if "display_title" in row.keys() else None,
        type=row["type"],
        semantic_type=row["semantic_type"] if "semantic_type" in row.keys() else "audit_task",
        relation_type=row["relation_type"] if "relation_type" in row.keys() else "produces",
        phase=row["phase"] if "phase" in row.keys() else "investigate",
        source_generation=row["source_generation"] if "source_generation" in row.keys() else 1,
        plan_revision=row["plan_revision"] if "plan_revision" in row.keys() else 1,
        legacy=bool(row["legacy"]) if "legacy" in row.keys() else True,
        creator=row["creator"],
        worker=row["worker"],
        last_heartbeat_at=row["last_heartbeat_at"],
        created_at=row["created_at"],
        concluded_at=row["concluded_at"],
        intent_key=row["intent_key"] if "intent_key" in row.keys() else None,
    )


def build_intents(conn: sqlite3.Connection, project_id: str) -> list[Intent]:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    return [intent_to_model(conn, r, project_id) for r in rows]


def intent_error_from_row(row: sqlite3.Row) -> IntentError:
    return IntentError(
        id=row["id"],
        intent_id=row["intent_id"],
        task_type=row["task_type"],
        worker=row["worker"],
        code=row["code"],
        classification=row["classification"],
        message=row["message"],
        remediation=row["remediation"],
        attempt_count=row["attempt_count"],
        first_failed_at=row["first_failed_at"],
        last_failed_at=row["last_failed_at"],
        retry_at=row["retry_at"],
        resolved_at=row["resolved_at"],
        resolution=row["resolution"],
    )


def list_intent_errors(
    conn: sqlite3.Connection, project_id: str,
) -> list[IntentError]:
    rows = conn.execute(
        "SELECT * FROM intent_errors WHERE project_id = ? "
        "ORDER BY first_failed_at, id",
        (project_id,),
    ).fetchall()
    return [intent_error_from_row(row) for row in rows]


def resolve_intent_errors(
    conn: sqlite3.Connection,
    project_id: str,
    intent_id: str,
    *,
    resolution: str,
    resolved_at: str | None = None,
) -> int:
    now = resolved_at or utcnow()
    cursor = conn.execute(
        "UPDATE intent_errors SET resolved_at = ?, resolution = ? "
        "WHERE project_id = ? AND intent_id = ? AND resolved_at IS NULL",
        (now, resolution, project_id, intent_id),
    )
    return cursor.rowcount


def get_intent_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT intent_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["intent_timeout"]


def get_reason_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT reason_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["reason_timeout"]


def project_reason_from_row(row: sqlite3.Row) -> ProjectReason | None:
    # Rows created before lease tokens were introduced may still contain a
    # worker claim without an authenticating token.  Treat those as released
    # rather than exposing an invalid ProjectReason model.
    if row["reason_worker"] is None or row["reason_lease_id"] is None:
        return None
    return ProjectReason(
        worker=row["reason_worker"],
        lease_id=row["reason_lease_id"],
        trigger=row["reason_trigger"],
        started_at=row["reason_started_at"],
        last_heartbeat_at=row["reason_last_heartbeat_at"],
    )


def project_meta_from_row(row: sqlite3.Row) -> ProjectMeta:
    return ProjectMeta(
        id=row["id"],
        title=row["title"],
        status=row["status"],
        graph_revision=row["graph_revision"],
        source_generation=row["source_generation"] if "source_generation" in row.keys() else 1,
        plan_revision=row["plan_revision"] if "plan_revision" in row.keys() else 1,
        completion_policy=row["completion_policy"] if "completion_policy" in row.keys() else "goal_based",
        reason_last_seen_event_seq=(
            row["reason_last_seen_event_seq"]
            if "reason_last_seen_event_seq" in row.keys() else 0
        ),
        event_seq=row["latest_event_seq"] if "latest_event_seq" in row.keys() else 0,
        audit_mode=row["audit_mode"] if "audit_mode" in row.keys() else "none",
        worker_preference=(
            row["worker_preference"] if "worker_preference" in row.keys() else "auto"
        ),
        created_at=row["created_at"],
        reason=project_reason_from_row(row),
        repo_root=row["repo_root"] if "repo_root" in row.keys() else None,
    )


def audit_completion_blockers_from_db(
    conn: sqlite3.Connection, project_id: str, from_ids: list[str]
) -> list[str]:
    """Return non-bypassable evidence blockers for an audit completion.

    The dispatcher owns filesystem-backed scope verification, but the server
    owns the board lifecycle.  Keeping this minimum proof check at the API
    boundary prevents a caller from completing an audit with a draft terminal
    fact (the failure mode that affected proj_003).
    """
    project = get_project_or_404(conn, project_id)
    audit_mode = project["audit_mode"] if "audit_mode" in project.keys() else "none"
    if audit_mode == "none":
        return []

    generation = project["source_generation"] if "source_generation" in project.keys() else 1
    facts = {
        row["id"]: row
        for row in conn.execute(
            "SELECT id, type, semantic_type, legacy, evidence, proof, status FROM facts "
            "WHERE project_id = ? AND source_generation = ?",
            (project_id, generation),
        )
    }
    parents: dict[str, list[str]] = {}
    for row in conn.execute(
        """
        SELECT i.to_fact_id, s.fact_id
        FROM intents i JOIN intent_sources s
          ON s.intent_id = i.id AND s.project_id = i.project_id
        WHERE i.project_id = ? AND i.to_fact_id IS NOT NULL
          AND i.source_generation = ?
        """,
        (project_id, generation),
    ):
        parents.setdefault(row["to_fact_id"], []).append(row["fact_id"])
    # A Technical Confirmation promotion is an evidence-chain edge, not an
    # Intent conclusion. Include it so confirmed findings can be completed
    # without making Completion perform confirmation itself.
    for row in conn.execute(
        "SELECT target_id, source_id FROM graph_edges WHERE project_id = ? "
        "AND relation_type = 'promotes_to' AND source_kind = 'fact' AND target_kind = 'fact' "
        "AND source_generation = ?",
        (project_id, generation),
    ):
        parents.setdefault(row["target_id"], []).append(row["source_id"])
    review_rows = conn.execute(
        "SELECT fact_id, verdict, confidence FROM reviews WHERE project_id = ? "
        "ORDER BY created_at, id", (project_id,)
    ).fetchall()
    reviews: dict[str, list[sqlite3.Row]] = {}
    for review in review_rows:
        reviews.setdefault(review["fact_id"], []).append(review)

    blockers: list[str] = []
    required_types = {"audit_summary"} if audit_mode == "scope" else {"negative_assurance"}
    required_ids = [
        fid for fid in from_ids
        if facts.get(fid) and (
            facts[fid]["type"] in required_types
            or facts[fid]["semantic_type"] == "confirmed_finding"
            or (facts[fid]["type"] == "vulnerability" and bool(facts[fid]["legacy"]))
        )
    ]
    if not required_ids:
        if audit_mode == "scope":
            blockers.append("Scope audit completion must reference an audit_summary fact.")
        else:
            blockers.append(
                "Hypothesis audit completion must reference a confirmed finding, legacy vulnerability, or negative_assurance fact."
            )
    if audit_mode == "scope" and (len(required_ids) != 1 or from_ids != required_ids):
        blockers.append("Scope audit completion must reference exactly one audit_summary fact.")
    visited: set[str] = set()
    active: set[str] = set()

    def visit(fact_id: str) -> None:
        if fact_id in active:
            blockers.append(f"Cyclic evidence chain at {fact_id}.")
            return
        if fact_id in visited or fact_id == "origin":
            return
        visited.add(fact_id)
        fact = facts.get(fact_id)
        if fact is None or fact_id == "goal":
            blockers.append(f"Invalid evidence reference: {fact_id}.")
            return
        if fact["status"] not in {"triaged", "false_positive", "fixed", "accepted_risk"}:
            blockers.append(f"{fact_id} has unresolved status {fact['status']}.")
        if not fact["evidence"] or not fact["evidence"].strip():
            blockers.append(f"{fact_id} lacks evidence.")
        fact_reviews = reviews.get(fact_id, [])
        latest_review = fact_reviews[-1] if fact_reviews else None
        technical_confirmation = False
        if fact["semantic_type"] == "confirmed_finding":
            try:
                technical_confirmation = json.loads(fact["proof"] or "{}").get("attributes", {}).get("gate_version") == "uvpg-proof-v1"
            except (TypeError, ValueError):
                technical_confirmation = False
        deterministic_intermediate = (
            fact["status"] == "triaged"
            and fact["type"] in REVIEWLESS_INTERMEDIATE_FACT_TYPES
        )
        if not technical_confirmation and not deterministic_intermediate and (
            latest_review is None
            or latest_review["verdict"] != "VALID"
            or latest_review["confidence"] not in {"firm", "certain"}
        ):
            blockers.append(f"{fact_id} needs VALID review(s) with firm/certain confidence.")
        if not parents.get(fact_id):
            blockers.append(f"{fact_id} has no incoming evidence chain.")
        active.add(fact_id)
        for parent in parents.get(fact_id, []):
            visit(parent)
        active.remove(fact_id)

    for fact_id in from_ids:
        visit(fact_id)
    if audit_mode == "scope":
        for fact_id, fact in facts.items():
            if fact_id in {"origin", "goal"} or fact["status"] in {
                "false_positive", "fixed", "accepted_risk",
            }:
                continue
            if not (
                fact["type"] in {"vulnerability", "candidate_disposition"}
                or fact["semantic_type"] in {
                    "candidate_finding", "confirmed_finding", "rejected_finding",
                }
            ):
                continue
            if fact_id not in visited:
                blockers.append(
                    f"Scope finding or disposition {fact_id} is not included in audit_summary ancestry."
                )
    return blockers


def clear_project_reason(conn: sqlite3.Connection, project_id: str) -> None:
    conn.execute(
        """
        UPDATE projects
        SET reason_worker = NULL,
            reason_lease_id = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE id = ?
        """,
        (project_id,),
    )


def expire_workers(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_intent_timeout(conn)
    now = utcnow()
    query = """
        UPDATE intents
        SET worker = NULL
        WHERE to_fact_id IS NULL
          AND worker IS NOT NULL
          AND last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        query = query.replace("WHERE ", "WHERE project_id = ? AND ", 1)
        params = (project_id, now, timeout)
    conn.execute(query, params)


def expire_reason_leases(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_reason_timeout(conn)
    now = utcnow()
    query = """
        UPDATE projects
        SET reason_worker = NULL,
            reason_lease_id = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE reason_worker IS NOT NULL
          AND reason_last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(reason_last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        query = query.replace("WHERE ", "WHERE id = ? AND ", 1)
        params = (project_id, now, timeout)
    conn.execute(query, params)


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------

def next_review_id(conn: sqlite3.Connection, project_id: str) -> str:
    """Review id scoped to project: r001, r002, ... — matches the worker
    convention of fact ids (`fNNN`) and intent ids (`iNNN`)."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM reviews WHERE project_id = ?", (project_id,)
    ).fetchone()
    return f"r{(row['n'] if row else 0) + 1:03d}"


def review_from_row(row: sqlite3.Row) -> Review:
    try:
        diagnostics = json.loads(row["diagnostics"] or "{}") if "diagnostics" in row.keys() else {}
    except (json.JSONDecodeError, TypeError):
        # Preserve readability of legacy rows with malformed/null optional
        # diagnostics; the review's core verdict and summary remain usable.
        diagnostics = {}
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    return Review(
        id=row["id"],
        fact_id=row["fact_id"],
        verdict=row["verdict"],
        confidence=row["confidence"],
        summary=row["summary"],
        reasoning=row["reasoning"],
        intent_id=row["intent_id"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        source_generation=row["source_generation"] if "source_generation" in row.keys() else 1,
        **diagnostics,
    )


def aggregate_fact_status_from_reviews(
    conn: sqlite3.Connection, project_id: str, fact_id: str, current_status: str
) -> str:
    """Compute the new `facts.status` after a review is added/updated.

    Aggregation rules (fail-fast on disproof, latest decisive review resolves
    earlier uncertainty):
    - Any review with verdict=INVALID                     -> 'false_positive'
    - Latest review VALID with firm/certain confidence    -> 'triaged'
    - Latest review NEEDS_REVIEW or tentative VALID       -> 'draft'
    - No reviews                                           -> keep current_status

    Manual states ('fixed', 'accepted_risk') are sticky — we never overwrite
    a user-set terminal state.
    """
    if current_status in ("fixed", "accepted_risk"):
        return current_status
    fact_row = conn.execute(
        "SELECT type FROM facts WHERE project_id = ? AND id = ?",
        (project_id, fact_id),
    ).fetchone()
    rows = conn.execute(
        "SELECT verdict, confidence, diagnostics FROM reviews WHERE project_id = ? AND fact_id = ? "
        "ORDER BY created_at, id",
        (project_id, fact_id),
    ).fetchall()
    if fact_row is not None and fact_row["type"] == FACT_TYPE_COVERAGE_PLAN:
        # Before coverage_plan used the attestation prompt, a reviewer could
        # correctly say "this is not a vulnerability" and accidentally poison
        # the entire scope DAG. Keep that review in history, but only reviews
        # carrying the attestation contract may drive plan lifecycle state.
        def has_attestation(row: sqlite3.Row) -> bool:
            try:
                diagnostics = json.loads(row["diagnostics"] or "{}")
            except (json.JSONDecodeError, TypeError):
                return False
            return isinstance(diagnostics.get("attestation_check"), dict)

        rows = [row for row in rows if has_attestation(row)]
    if not rows:
        return current_status
    if any(row["verdict"] == "INVALID" for row in rows):
        return FACT_STATUS_FALSE_POSITIVE
    latest = rows[-1]
    if latest["verdict"] == "VALID" and latest["confidence"] in {"firm", "certain"}:
        return FACT_STATUS_TRIAGED
    return FACT_STATUS_DRAFT


def list_reviews_for_fact(
    conn: sqlite3.Connection, project_id: str, fact_id: str
) -> list[Review]:
    get_project_or_404(conn, project_id)
    if conn.execute(
        "SELECT 1 FROM facts WHERE project_id = ? AND id = ?", (project_id, fact_id)
    ).fetchone() is None:
        raise HTTPException(404, f"fact {fact_id} not found in project {project_id}")
    rows = conn.execute(
        "SELECT * FROM reviews WHERE project_id = ? AND fact_id = ? ORDER BY created_at, id",
        (project_id, fact_id),
    ).fetchall()
    return [review_from_row(r) for r in rows]


def list_reviews_for_project(
    conn: sqlite3.Connection, project_id: str
) -> list[Review]:
    rows = conn.execute(
        "SELECT * FROM reviews WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    return [review_from_row(r) for r in rows]
