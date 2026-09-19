from __future__ import annotations

import logging
import hashlib
import json
from dataclasses import replace
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

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
from linen.server.uvpg import (
    PROOF_GATE_VERSION,
    evaluate_proof_gate,
    evaluate_shadow_gate,
    derive_proof_gaps,
    NON_INVESTIGATIVE_GAPS,
    NON_AUTOMATIC_REPAIR_GAPS,
    proof_graph_fingerprint,
)
from linen.server.dynamic_verification import (
    DYNAMIC_GATE_VERSION,
    effective_verification_level,
    evaluate_dynamic_verification,
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
                (SELECT COALESCE(MAX(sequence), 0) FROM audit_events WHERE project_id = p.id) AS latest_event_seq,
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
                completion_policy=row["completion_policy"] if "completion_policy" in row.keys() else "goal_based",
                reason_last_seen_event_seq=row["reason_last_seen_event_seq"] if "reason_last_seen_event_seq" in row.keys() else 0,
                event_seq=row["latest_event_seq"] if "latest_event_seq" in row.keys() else 0,
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
                "completion_policy, audit_mode, created_at, repo_root) "
                "VALUES (?, ?, 'active', 1, 1, 1, ?, ?, ?, ?)",
                (pid, body.title, body.completion_policy, body.audit_mode, now, resolved_repo_root),
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
                    "completion_policy": body.completion_policy,
                },
                created_at=now,
            )
            project_row = get_project_or_404(conn, pid)

            return ProjectDetail(
                project=project_meta_from_row(project_row),
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
        row = conn.execute(
            "SELECT p.*, COALESCE((SELECT MAX(sequence) FROM audit_events WHERE project_id = p.id), 0) AS latest_event_seq "
            "FROM projects p WHERE p.id = ?", (project_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Project not found")

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


@router.get("/projects/{project_id}/facts/{fact_id}/uvpg-shadow")
def get_uvpg_shadow(project_id: str, fact_id: str):
    """Evaluate the additive UVPG gate without changing project state."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        return evaluate_shadow_gate(conn, project_id, fact_id).as_dict()


def _confirmation_result(result, *, status: str, candidate_id: str, confirmed_fact_id: str | None = None, fingerprint: str | None = None, verification_level: str = "static_confirmed") -> dict:
    payload = {
        "mode": "enforcement",
        "status": status,
        "candidate_id": candidate_id,
        "confirmed_fact_id": confirmed_fact_id,
        "gate_version": PROOF_GATE_VERSION,
        "proof_graph_sha256": fingerprint,
        "verification_level": verification_level,
        "reason_codes": list(result.reason_codes),
        "proof_summary": result.proof_summary,
    }
    return payload


@router.get("/projects/{project_id}/facts/{fact_id}/technical-confirmation")
def get_technical_confirmation(project_id: str, fact_id: str):
    """Dry-run the same proof core used by the enforcing promotion path."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        result = evaluate_proof_gate(conn, project_id, fact_id)
        fingerprint = proof_graph_fingerprint(conn, project_id, fact_id)
        confirmed = conn.execute(
            "SELECT f.id FROM facts f JOIN graph_edges e ON e.target_id = f.id "
            "WHERE e.project_id = ? AND e.source_id = ? AND e.relation_type = 'promotes_to' "
            "AND f.semantic_type = 'confirmed_finding' ORDER BY f.id LIMIT 1",
            (project_id, fact_id),
        ).fetchone()
        return _confirmation_result(
            result,
            status="eligible" if result.status == "PASS" else "not_confirmed",
            candidate_id=fact_id,
            confirmed_fact_id=confirmed["id"] if confirmed else None,
            fingerprint=fingerprint,
            verification_level=(effective_verification_level(conn, project_id, confirmed["id"]) if confirmed else "static_confirmed"),
        )


@router.get("/projects/{project_id}/facts/{fact_id}/dynamic-verification")
def get_dynamic_verification(project_id: str, fact_id: str):
    """Evaluate optional dynamic evidence without executing a reproduction."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        result = evaluate_dynamic_verification(conn, project_id, fact_id)
        level = (
            effective_verification_level(conn, project_id, result.confirmed_fact_id)
            if result.confirmed_fact_id else "unconfirmed"
        )
        payload = result.as_dict()
        payload["effective_verification_level"] = level
        return payload


@router.post("/projects/{project_id}/facts/{fact_id}/dynamic-verification")
def finalize_dynamic_verification(project_id: str, fact_id: str):
    """Persist one idempotent PASS receipt for already-produced evidence."""
    with get_conn() as conn:
        check_project_active(conn, project_id)
        project = get_project_or_404(conn, project_id)
        result = evaluate_dynamic_verification(conn, project_id, fact_id)
        payload = result.as_dict()
        if result.status != "PASS":
            payload["effective_verification_level"] = (
                effective_verification_level(conn, project_id, result.confirmed_fact_id)
                if result.confirmed_fact_id else "unconfirmed"
            )
            return payload
        if result.confirmed_fact_id is None:
            payload["receipt_created"] = False
            payload["receipt_reason"] = "technical_confirmation_required"
            payload["effective_verification_level"] = "unconfirmed"
            return payload
        receipt = dict(result.receipt)
        receipt["confirmed_fact_id"] = result.confirmed_fact_id
        receipt["dynamic_verification_sha256"] = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        fingerprint = receipt["static_proof_graph_sha256"]
        idempotency_key = (
            f"dynamic:{fact_id}:g{project['source_generation']}:{fingerprint}:"
            f"{receipt['positive_run_id']}:{receipt['negative_run_id']}:{DYNAMIC_GATE_VERSION}"
        )
        sequence = append_event(
            conn, project_id, "dynamic_verification_pass", "dynamic_verification",
            entity_kind="fact", entity_id=result.confirmed_fact_id,
            run_id=receipt["positive_run_id"], idempotency_key=idempotency_key,
            payload=receipt,
        )
        payload.update({
            "receipt": receipt,
            "receipt_created": True,
            "receipt_sequence": sequence,
            "effective_verification_level": "dynamic_confirmed",
        })
        return payload


def _proof_status_payload(conn, project_id: str, fact_id: str) -> dict:
    result = evaluate_proof_gate(conn, project_id, fact_id)
    gaps = derive_proof_gaps(conn, project_id, fact_id)
    active = {}
    for row in conn.execute(
        "SELECT id, description, type, phase, source_generation FROM intents "
        "WHERE project_id = ? AND to_fact_id IS NULL AND concluded_at IS NULL "
        "AND description LIKE '@uvpg:proof:%' ORDER BY id", (project_id,),
    ):
        for gap in gaps:
            if gap.key in row["description"]:
                active[gap.key] = {"intent_id": row["id"], "status": "in_progress", "description": row["description"]}
    serialized = []
    for gap in gaps:
        item = gap.as_dict()
        item["status"] = "blocked" if gap.code in NON_INVESTIGATIVE_GAPS else active.get(gap.key, {}).get("status", "missing")
        if gap.key in active:
            item["intent_id"] = active[gap.key]["intent_id"]
        serialized.append(item)
    return {
        "candidate_id": fact_id,
        "gate": result.as_dict(),
        "gate_status": result.status,
        "proof_summary": result.proof_summary,
        "gaps": serialized,
        "active_gap_intents": sorted(active.values(), key=lambda item: item["intent_id"]),
    }


@router.get("/projects/{project_id}/facts/{fact_id}/proof-status")
def get_proof_status(project_id: str, fact_id: str):
    """Read-only candidate-centric gate and proof-gap projection."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        return _proof_status_payload(conn, project_id, fact_id)


@router.post("/projects/{project_id}/facts/{fact_id}/proof-gaps/plan")
def plan_proof_gap(project_id: str, fact_id: str):
    """Create at most one deterministic, candidate-bound proof obligation."""
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        status = _proof_status_payload(conn, project_id, fact_id)
        selected = next((gap for gap in derive_proof_gaps(conn, project_id, fact_id) if gap.code not in NON_INVESTIGATIVE_GAPS and gap.code not in NON_AUTOMATIC_REPAIR_GAPS), None)
        if selected is None:
            return {"created": False, "reason": "no_investigative_gap", **status}
        existing = conn.execute(
            "SELECT id FROM intents WHERE project_id = ? AND to_fact_id IS NULL AND concluded_at IS NULL "
            "AND source_generation = ? AND description LIKE ? ORDER BY id LIMIT 1",
            (project_id, project["source_generation"], f"@uvpg:proof:{selected.key}:%"),
        ).fetchone()
        if existing is not None:
            return {"created": False, "reason": "duplicate_open_obligation", "intent_id": existing["id"], **status}
        now = utcnow()
        intent_id = next_intent_id(conn, project_id)
        description = f"@uvpg:proof:{selected.key}:{selected.suggested_intent_type}:{selected.expected_fact_type or 'evidence'} {selected.description}"
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, display_title, type, semantic_type, relation_type, phase, source_generation, plan_revision, creator, worker, last_heartbeat_at, created_at, concluded_at) "
            "VALUES (?, ?, NULL, ?, ?, ?, 'audit_task', ?, 'verification', ?, ?, 'dispatcher.proof-gap', NULL, NULL, ?, NULL)",
            (intent_id, project_id, description, f"Proof obligation: {selected.code}", selected.suggested_intent_type, selected.suggested_relation_type or "supports", project["source_generation"], project["plan_revision"], now),
        )
        source_fact_id = selected.target_fact_id or fact_id
        conn.execute("INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)", (intent_id, project_id, source_fact_id))
        bump_graph_revision(conn, project_id)
        append_event(conn, project_id, "proof_gap_intent_created", "dispatcher.proof-gap", entity_kind="intent", entity_id=intent_id, payload={"candidate_id": fact_id, "gap": selected.as_dict()}, created_at=now)
        return {"created": True, "intent_id": intent_id, "gap": selected.as_dict(), **_proof_status_payload(conn, project_id, fact_id)}


@router.post("/projects/{project_id}/facts/{fact_id}/technical-confirmation")
def confirm_technical_finding(project_id: str, fact_id: str):
    """Atomically promote one candidate after deterministic proof validation."""
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        project = get_project_or_404(conn, project_id)
        candidate = conn.execute(
            "SELECT * FROM facts WHERE project_id = ? AND id = ?", (project_id, fact_id),
        ).fetchone()
        if candidate is None:
            raise HTTPException(404, "Candidate fact not found")
        if candidate["semantic_type"] != "candidate_finding":
            raise HTTPException(409, "Technical confirmation requires a candidate_finding")
        existing = conn.execute(
            "SELECT f.id FROM facts f JOIN graph_edges e ON e.project_id = f.project_id "
            "AND e.target_id = f.id WHERE f.project_id = ? AND e.source_id = ? "
            "AND e.target_kind = 'fact' AND e.source_kind = 'fact' "
            "AND e.relation_type = 'promotes_to' AND f.semantic_type = 'confirmed_finding' "
            "ORDER BY f.id LIMIT 1", (project_id, fact_id),
        ).fetchone()
        if existing is not None:
            fingerprint = proof_graph_fingerprint(conn, project_id, fact_id)
            result = evaluate_proof_gate(conn, project_id, fact_id)
            return _confirmation_result(result, status="confirmed", candidate_id=fact_id, confirmed_fact_id=existing["id"], fingerprint=fingerprint, verification_level=effective_verification_level(conn, project_id, existing["id"]))

        result = evaluate_proof_gate(conn, project_id, fact_id)
        fingerprint = proof_graph_fingerprint(conn, project_id, fact_id)
        dynamic_result = evaluate_dynamic_verification(conn, project_id, fact_id)
        if result.status != "PASS":
            return JSONResponse(
                status_code=409,
                content=_confirmation_result(result, status="not_confirmed", candidate_id=fact_id, fingerprint=fingerprint),
            )
        if fingerprint != proof_graph_fingerprint(conn, project_id, fact_id):
            result = replace(result, reason_codes=(*result.reason_codes, "PROOF_GRAPH_CHANGED"))
            return JSONResponse(status_code=409, content=_confirmation_result(result, status="not_confirmed", candidate_id=fact_id, fingerprint=fingerprint))

        now = utcnow()
        confirmed_id = next_fact_id(conn, project_id)
        proof = {
            "schema_version": 1,
            "claim_kind": "confirmed_finding",
            "subject_ids": [fact_id],
            "object_ids": result.proof_summary.get("fact_ids", []),
            "attributes": {
                "candidate_id": fact_id,
                "gate_version": PROOF_GATE_VERSION,
                "proof_graph_sha256": fingerprint,
                "verification_level": "dynamic_confirmed" if dynamic_result.status == "PASS" else "static_confirmed",
                "confirmed_at": now,
            },
        }
        conn.execute(
            "INSERT INTO facts (id, project_id, description, display_title, type, semantic_type, evidence, proof, source_generation, status) "
            "VALUES (?, ?, ?, ?, ?, 'confirmed_finding', ?, ?, ?, 'triaged')",
            (confirmed_id, project_id, candidate["description"], f"Confirmed finding: {candidate['description'][:80]}", candidate["type"] or "vulnerability", candidate["evidence"], json.dumps(proof, sort_keys=True), project["source_generation"]),
        )
        create_graph_edge(conn, project_id, source_kind="fact", source_id=fact_id, target_kind="fact", target_id=confirmed_id, relation_type="promotes_to", created_by="technical_confirmation", metadata={"gate_version": PROOF_GATE_VERSION, "proof_graph_sha256": fingerprint}, created_at=now)
        bump_graph_revision(conn, project_id)
        append_event(conn, project_id, "technical_confirmation", "technical_confirmation", entity_kind="fact", entity_id=confirmed_id, payload={"candidate_id": fact_id, "confirmed_fact_id": confirmed_id, "gate_version": PROOF_GATE_VERSION, "proof_graph_sha256": fingerprint}, created_at=now)
        if dynamic_result.status == "PASS":
            receipt = dict(dynamic_result.receipt)
            receipt["confirmed_fact_id"] = confirmed_id
            receipt["dynamic_verification_sha256"] = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            append_event(
                conn, project_id, "dynamic_verification_pass", "dynamic_verification",
                entity_kind="fact", entity_id=confirmed_id, run_id=receipt.get("positive_run_id"),
                idempotency_key=(
                    f"dynamic:{fact_id}:g{project['source_generation']}:{fingerprint}:"
                    f"{receipt.get('positive_run_id')}:{receipt.get('negative_run_id')}:{DYNAMIC_GATE_VERSION}"
                ), payload=receipt, created_at=now,
            )
        return _confirmation_result(result, status="confirmed", candidate_id=fact_id, confirmed_fact_id=confirmed_id, fingerprint=fingerprint, verification_level="dynamic_confirmed" if dynamic_result.status == "PASS" else "static_confirmed")


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
        return project_meta_from_row(get_project_or_404(conn, project_id))


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
        return project_meta_from_row(get_project_or_404(conn, project_id))


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
        return project_meta_from_row(get_project_or_404(conn, project_id))


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
        return project_meta_from_row(get_project_or_404(conn, project_id))


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

        if body.seen_event_seq is not None:
            conn.execute(
                "UPDATE projects SET reason_last_seen_event_seq = MAX(reason_last_seen_event_seq, ?) WHERE id = ?",
                (body.seen_event_seq, project_id),
            )
        clear_project_reason(conn, project_id)
        return project_meta_from_row(get_project_or_404(conn, project_id))


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
        if project["completion_policy"] == "goal_based":
            redundant = conn.execute(
                "SELECT id FROM intents WHERE project_id = ? AND concluded_at IS NULL AND id != ?",
                (project_id, iid),
            ).fetchall()
            conn.execute(
                "UPDATE intents SET worker = NULL, concluded_at = ? "
                "WHERE project_id = ? AND concluded_at IS NULL AND id != ?",
                (now, project_id, iid),
            )
            for row in redundant:
                append_event(
                    conn, project_id, "audit_task_cancelled", body.worker,
                    entity_kind="intent", entity_id=row["id"],
                    payload={"reason": "goal_satisfied", "completion_intent_id": iid},
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

        updated_project = get_project_or_404(conn, project_id)
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
