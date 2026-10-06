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

from linen.audit_charter import AUDIT_CHARTER_VERSION, project_goal
from linen.server.db import get_conn
from linen.server.audit_state import (
    append_event,
    completion_gate_from_db,
    create_graph_edge,
    fact_display_title,
    latest_finding_assessment,
    list_audit_stages,
    list_graph_edges,
    reportability_reason,
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
    ProofPayload,
    ReopenRequest,
    ReopenResponse,
    ReasonClaimRequest,
    ReasonHeartbeatRequest,
    ReportProjectWorkerIssueRequest,
    UpdateProjectTitleRequest,
    UpdateProjectStatusRequest,
    UpdateProjectWorkerPreferenceRequest,
)
from linen.server.uvpg import (
    PROOF_GATE_VERSION,
    evaluate_proof_gate,
    evaluate_shadow_gate,
    derive_proof_gaps,
    candidate_proof_facts,
    candidate_proof_review,
    NON_INVESTIGATIVE_GAPS,
    NON_AUTOMATIC_REPAIR_GAPS,
    STRATEGY_REPLAN_AFTER_FAILURES,
    UNIFIED_REVIEW_KIND,
    proof_graph_fingerprint,
    proof_recipe_fingerprint,
    ready_strategy_replan_resolutions,
    validate_proof_payload,
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
                worker_preference=(
                    row["worker_preference"] if "worker_preference" in row.keys() else "auto"
                ),
                worker_issues=project_meta_from_row(row).worker_issues,
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
        resolved_goal = project_goal(body.audit_mode, body.goal)
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
                "completion_policy, audit_mode, worker_preference, created_at, repo_root) "
                "VALUES (?, ?, 'active', 1, 1, 1, ?, ?, ?, ?, ?)",
                (
                    pid, body.title, body.completion_policy, body.audit_mode,
                    body.worker_preference, now, resolved_repo_root,
                ),
            )
            conn.execute(
                "INSERT INTO facts (id, project_id, description, display_title, semantic_type, source_generation) "
                "VALUES (?, ?, ?, ?, 'audit_target', 1)",
                ("origin", pid, body.origin, "Audit target"),
            )
            conn.execute(
                "INSERT INTO facts (id, project_id, description, display_title, semantic_type, source_generation) "
                "VALUES (?, ?, ?, ?, 'audit_objective', 1)",
                (
                    "goal",
                    pid,
                    resolved_goal,
                    "Security audit charter" if body.audit_mode != "none" else "Goal",
                ),
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
                    "audit_charter_version": (
                        AUDIT_CHARTER_VERSION if body.audit_mode != "none" else None
                    ),
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
                        id="goal", description=resolved_goal,
                        display_title=(
                            "Security audit charter" if body.audit_mode != "none" else "Goal"
                        ),
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
        )


@router.get("/projects/{project_id}/facts/{fact_id}/uvpg-shadow")
def get_uvpg_shadow(project_id: str, fact_id: str):
    """Evaluate the additive UVPG gate without changing project state."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        return evaluate_shadow_gate(conn, project_id, fact_id).as_dict()


def _confirmation_result(result, *, status: str, candidate_id: str, confirmed_fact_id: str | None = None, fingerprint: str | None = None, verification_level: str = "dynamic_confirmed", dynamic_result=None) -> dict:
    reason_codes = list(result.reason_codes)
    if dynamic_result is not None and dynamic_result.status != "PASS":
        reason_codes.extend(dynamic_result.reason_codes)
    payload = {
        "mode": "enforcement",
        "status": status,
        "candidate_id": candidate_id,
        "confirmed_fact_id": confirmed_fact_id,
        "gate_version": PROOF_GATE_VERSION,
        "proof_graph_sha256": fingerprint,
        "verification_level": verification_level,
        "reason_codes": sorted(set(reason_codes)),
        "proof_summary": result.proof_summary,
    }
    if dynamic_result is not None:
        payload["dynamic_verification"] = dynamic_result.as_dict()
    return payload


@router.get("/projects/{project_id}/facts/{fact_id}/technical-confirmation")
def get_technical_confirmation(project_id: str, fact_id: str):
    """Dry-run the same proof core used by the enforcing promotion path."""
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        result = evaluate_proof_gate(conn, project_id, fact_id)
        fingerprint = proof_graph_fingerprint(conn, project_id, fact_id)
        dynamic_result = evaluate_dynamic_verification(conn, project_id, fact_id)
        confirmed = conn.execute(
            "SELECT f.id FROM facts f JOIN graph_edges e ON e.target_id = f.id "
            "WHERE e.project_id = ? AND e.source_id = ? AND e.relation_type = 'promotes_to' "
            "AND f.semantic_type = 'confirmed_finding' ORDER BY f.id LIMIT 1",
            (project_id, fact_id),
        ).fetchone()
        return _confirmation_result(
            result,
            status="eligible" if result.status == "PASS" and dynamic_result.status == "PASS" else "not_confirmed",
            candidate_id=fact_id,
            confirmed_fact_id=confirmed["id"] if confirmed else None,
            fingerprint=fingerprint,
            verification_level=(effective_verification_level(conn, project_id, confirmed["id"]) if confirmed else ("dynamic_confirmed" if dynamic_result.status == "PASS" else "unconfirmed")),
            dynamic_result=dynamic_result,
        )


@router.get("/projects/{project_id}/facts/{fact_id}/dynamic-verification")
def get_dynamic_verification(project_id: str, fact_id: str):
    """Evaluate required dynamic confirmation evidence without executing a run."""
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
    dynamic_result = None
    if result.status == "PASS":
        dynamic_result = evaluate_dynamic_verification(conn, project_id, fact_id)
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
        "confirmation_status": (
            "eligible"
            if result.status == "PASS" and dynamic_result is not None and dynamic_result.status == "PASS"
            else "not_confirmed"
        ),
        "dynamic_verification": dynamic_result.as_dict() if dynamic_result is not None else None,
        "proof_summary": result.proof_summary,
        "gaps": serialized,
        "active_gap_intents": sorted(active.values(), key=lambda item: item["intent_id"]),
    }


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json_object(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _negative_control_key(source_fact, source_proof: ProofPayload) -> str:
    """Identify a reusable unreachable path by its stable location and cause."""
    attributes = source_proof.attributes
    path_keys = (
        "path_signature", "route_signature", "recipe_id", "path_id",
        "endpoint_id", "entrypoint_id", "source_signature", "sink_signature",
        "call_path", "source_location", "sink_location",
    )
    cause_keys = (
        "failure_code", "cause_id", "condition_signature",
        "reachability_condition", "principal",
        "trust_boundary",
    )
    candidate_ids = [identifier for identifier in source_proof.subject_ids if identifier != source_fact["id"]]

    def scrub(value):
        if isinstance(value, str):
            for candidate_id in candidate_ids:
                value = re.sub(
                    rf"(?<![A-Za-z0-9_-]){re.escape(candidate_id)}(?![A-Za-z0-9_-])",
                    "<candidate>", value,
                )
            return value
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        return value

    path = {key: scrub(attributes[key]) for key in path_keys if key in attributes}
    cause = {key: scrub(attributes[key]) for key in cause_keys if key in attributes}
    evidence_refs = [
        {
            key: getattr(ref, key)
            for key in (
                "file", "line_start", "line_end", "excerpt_sha256",
                "tool", "tool_version", "rule_id",
            )
            if getattr(ref, key) is not None
        }
        for ref in source_proof.evidence_refs
    ]
    evidence_refs.sort(key=lambda item: json.dumps(item, sort_keys=True))
    if not path and not evidence_refs:
        # Legacy evidence without structured locations still gets a stable key,
        # but candidate and run identifiers never participate in the identity.
        path = {
            "description": scrub(" ".join(source_fact["description"].split())),
            "evidence": scrub(" ".join((source_fact["evidence"] or "").split())),
        }
    return _canonical_sha256({
        "schema": "linen-negative-control-v1",
        "path": path,
        "evidence_refs": evidence_refs,
        "cause": cause or {"failure_code": "UNREACHABLE"},
    })


def _strategy_recipe_key(failure_code: str, fact_row, proof_data: dict) -> str:
    """Use the same stable recipe identity for cooldown and replan resolution."""
    return proof_recipe_fingerprint(
        failure_code, fact_row["id"], fact_row["description"],
        fact_row["evidence"], proof_data,
    )


def _persist_unreachable_refutation(conn, project_id: str, candidate_id: str, gap) -> dict | None:
    """Refute a candidate only from reviewed reachability evidence and persist its negative control."""
    project = get_project_or_404(conn, project_id)
    generation = project["source_generation"]
    candidate = conn.execute(
        "SELECT * FROM facts WHERE project_id = ? AND id = ? AND source_generation = ?",
        (project_id, candidate_id, generation),
    ).fetchone()
    if candidate is None or candidate["semantic_type"] not in {"candidate_finding", "rejected_finding"}:
        return None

    package_review_valid, _, package_verification = candidate_proof_review(
        conn, project_id, candidate_id,
    )
    package_fact_ids = set(candidate_proof_facts(conn, project_id, candidate_id))
    qualified = []
    for source_id in gap.related_fact_ids:
        source = conn.execute(
            "SELECT * FROM facts WHERE project_id = ? AND id = ? AND source_generation = ?",
            (project_id, source_id, generation),
        ).fetchone()
        if source is None or source["type"] != "reachability":
            continue
        source_proof_data = _json_object(source["proof"])
        try:
            source_proof = ProofPayload.model_validate(source_proof_data)
        except Exception:
            continue
        if (
            source_proof.claim_kind != "reachability"
            or source_proof.attributes.get("failure_code") != "UNREACHABLE"
            or candidate_id not in source_proof.subject_ids
            or validate_proof_payload(
                conn, project_id, source_proof, subject_fact_id=source_id,
            )
        ):
            continue
        review = conn.execute(
            "SELECT * FROM reviews WHERE project_id = ? AND fact_id = ? "
            "AND source_generation = ? ORDER BY created_at DESC, id DESC LIMIT 1",
            (project_id, source_id, generation),
        ).fetchone()
        review_fact_id = source_id
        review_kind = "reachability_fact"
        if review is not None:
            if (
                review["verdict"] != "VALID"
                or review["confidence"] not in {"firm", "certain"}
            ):
                continue
        else:
            # New proof workflows record one unified review on the candidate.
            # Accept it only when candidate_proof_review confirms the current
            # graph digest and this reachability Fact is in that graph.
            if (
                not package_review_valid
                or package_verification is None
                or source_id not in package_fact_ids
            ):
                continue
            review = None
            for candidate_review in conn.execute(
                "SELECT * FROM reviews WHERE project_id = ? AND fact_id = ? "
                "AND source_generation = ? ORDER BY created_at DESC, id DESC",
                (project_id, candidate_id, generation),
            ):
                diagnostics = _json_object(candidate_review["diagnostics"])
                verification = diagnostics.get("cold_verification")
                if (
                    isinstance(verification, dict)
                    and verification.get("review_kind") == UNIFIED_REVIEW_KIND
                    and verification == package_verification
                ):
                    review = candidate_review
                    break
            if (
                review is None
                or review["verdict"] != "VALID"
                or review["confidence"] not in {"firm", "certain"}
            ):
                continue
            review_fact_id = candidate_id
            review_kind = UNIFIED_REVIEW_KIND
        qualified.append((source, source_proof, review, review_fact_id, review_kind))

    if not qualified:
        return {
            "candidate_refuted": False,
            "negative_control_created": False,
            "reason": "unreachable_evidence_not_independently_validated",
        }

    source, source_proof, review, review_fact_id, review_kind = sorted(
        qualified, key=lambda item: item[0]["id"],
    )[0]
    artifact_hashes = {}
    artifact_ids = sorted({
        *source_proof.artifact_ids,
        *(ref.artifact_id for ref in source_proof.evidence_refs if ref.artifact_id),
    })
    if artifact_ids:
        placeholders = ",".join("?" for _ in artifact_ids)
        artifact_hashes = {
            row["artifact_id"]: row["sha256"]
            for row in conn.execute(
                f"SELECT artifact_id, sha256 FROM artifacts WHERE project_id = ? "
                f"AND artifact_id IN ({placeholders}) ORDER BY artifact_id",
                (project_id, *artifact_ids),
            )
        }
    source_proof_data = source_proof.model_dump(mode="json")
    source_fact_digest = _canonical_sha256({
        "id": source["id"], "source_generation": source["source_generation"],
        "type": source["type"], "semantic_type": source["semantic_type"],
        "display_title": source["display_title"], "status": source["status"],
        "description": source["description"], "evidence": source["evidence"],
        "proof": source_proof_data, "artifact_hashes": artifact_hashes,
    })
    source_proof_digest = _canonical_sha256(source_proof_data)
    review_diagnostics = _json_object(review["diagnostics"])
    review_digest = _canonical_sha256({
        "id": review["id"], "source_generation": review["source_generation"],
        "created_at": review["created_at"], "intent_id": review["intent_id"],
        "reviewed_fact_id": review_fact_id, "review_kind": review_kind,
        "verdict": review["verdict"], "confidence": review["confidence"],
        "summary": review["summary"], "reasoning": review["reasoning"],
        "created_by": review["created_by"], "diagnostics": review_diagnostics,
    })
    graph_digest = proof_graph_fingerprint(conn, project_id, candidate_id)
    reusable_key = _negative_control_key(source, source_proof)
    event_key = f"uvpg-unreachable:{candidate_id}:g{generation}:{reusable_key}"
    prior_event = conn.execute(
        "SELECT sequence, payload FROM audit_events WHERE project_id = ? AND idempotency_key = ?",
        (project_id, event_key),
    ).fetchone()
    if prior_event is not None:
        payload = _json_object(prior_event["payload"])
        return {
            "candidate_refuted": True,
            "negative_control_created": False,
            "reason": "candidate_already_refuted",
            "negative_control_fact_id": payload.get("negative_control_fact_id"),
        }

    trusted_negative_ids = set()
    for row in conn.execute(
        "SELECT payload FROM audit_events WHERE project_id = ? AND source_generation = ? "
        "AND event_type = 'candidate_refuted_by_unreachable_path'",
        (project_id, generation),
    ):
        event_payload = _json_object(row["payload"])
        if event_payload.get("negative_control_key") == reusable_key:
            trusted_negative_ids.add(event_payload.get("negative_control_fact_id"))
    reusable = conn.execute(
        "SELECT id, proof FROM facts WHERE project_id = ? AND source_generation = ? "
        "AND type = 'negative_control' ORDER BY id",
        (project_id, generation),
    ).fetchall()
    negative_control_id = None
    for row in reusable:
        existing_proof = _json_object(row["proof"])
        existing_attributes = existing_proof.get("attributes", {})
        if (
            row["id"] in trusted_negative_ids
            and existing_attributes.get("mode") == "reviewed_unreachable_path"
            and existing_attributes.get("reusable") is True
            and existing_attributes.get("negative_control_key") == reusable_key
        ):
            negative_control_id = row["id"]
            break

    now = utcnow()
    reused = negative_control_id is not None
    source_candidate_id = candidate_id
    if negative_control_id is None:
        negative_control_id = next_fact_id(conn, project_id)
        negative_attributes = {
            "mode": "reviewed_unreachable_path",
            "failure_code": "UNREACHABLE",
            "negative_control_key": reusable_key,
            "reusable": True,
            "source_candidate_id": source_candidate_id,
            "source_fact_id": source["id"],
            "source_fact_sha256": source_fact_digest,
            "source_proof_sha256": source_proof_digest,
            "source_review_id": review["id"],
            "source_review_sha256": review_digest,
            "source_review_fact_id": review_fact_id,
            "source_review_kind": review_kind,
            "source_artifact_sha256s": artifact_hashes,
            "proof_graph_sha256": graph_digest,
            "source_generation": generation,
        }
        negative_proof_body = {
            "schema_version": 1,
            "claim_kind": "negative_control",
            "subject_ids": sorted({source_candidate_id, source["id"]}),
            "object_ids": [],
            "applicability": source_proof.applicability,
            "attributes": negative_attributes,
            "evidence_refs": [ref.model_dump(mode="json") for ref in source_proof.evidence_refs],
            "artifact_ids": source_proof.artifact_ids,
        }
        negative_attributes["provenance_sha256"] = _canonical_sha256(negative_proof_body)
        negative_proof = ProofPayload.model_validate(negative_proof_body)
        errors = validate_proof_payload(
            conn, project_id, negative_proof, subject_fact_id=negative_control_id,
        )
        if errors:
            return {
                "candidate_refuted": False,
                "negative_control_created": False,
                "reason": "unreachable_provenance_invalid",
                "details": errors,
            }
        conn.execute(
            "INSERT INTO facts (id, project_id, description, display_title, type, semantic_type, "
            "evidence, proof, source_generation, status) VALUES (?, ?, ?, ?, 'negative_control', "
            "'observation', ?, ?, ?, 'triaged')",
            (
                negative_control_id, project_id,
                f"Reviewed unreachable path: {source['description']}",
                "Reusable unreachable-path negative control", source["evidence"],
                json.dumps(negative_proof.model_dump(mode="json"), sort_keys=True, ensure_ascii=False),
                generation,
            ),
        )

    refutation_body = {
        "candidate_id": candidate_id,
        "negative_control_fact_id": negative_control_id,
        "source_reachability_fact_id": source["id"],
        "source_fact_sha256": source_fact_digest,
        "source_proof_sha256": source_proof_digest,
        "source_review_id": review["id"],
        "source_review_sha256": review_digest,
        "source_review_fact_id": review_fact_id,
        "source_review_kind": review_kind,
        "proof_graph_sha256": graph_digest,
        "negative_control_key": reusable_key,
        "source_generation": generation,
        "reused": reused,
    }
    refutation_digest = _canonical_sha256(refutation_body)
    candidate_proof = _json_object(candidate["proof"])
    candidate_proof.setdefault("schema_version", 1)
    candidate_proof.setdefault("claim_kind", "candidate_finding")
    candidate_proof.setdefault("subject_ids", [])
    candidate_proof.setdefault("object_ids", [])
    candidate_proof.setdefault("applicability", {})
    candidate_attributes = candidate_proof.get("attributes")
    if not isinstance(candidate_attributes, dict):
        candidate_attributes = {}
    candidate_attributes.update({
        "candidate_outcome": "refuted",
        "refutation_reason": "unreachable",
        "negative_control_fact_id": negative_control_id,
        "negative_control_key": reusable_key,
        "refutation_sha256": refutation_digest,
        "refutation_proof_graph_sha256": graph_digest,
    })
    candidate_proof["attributes"] = candidate_attributes
    conn.execute(
        "UPDATE facts SET status = 'false_positive', semantic_type = 'rejected_finding', proof = ? "
        "WHERE project_id = ? AND id = ?",
        (json.dumps(candidate_proof, sort_keys=True, ensure_ascii=False), project_id, candidate_id),
    )
    create_graph_edge(
        conn, project_id, source_kind="fact", source_id=negative_control_id,
        target_kind="fact", target_id=candidate_id, relation_type="refutes",
        created_by="server.uvpg",
        metadata={"negative_control_key": reusable_key, "refutation_sha256": refutation_digest},
        created_at=now,
    )
    bump_graph_revision(conn, project_id)
    append_event(
        conn, project_id,
        "candidate_refuted_by_unreachable_path" if not reused else "candidate_refuted_by_reused_negative_control",
        "server.uvpg", entity_kind="fact", entity_id=candidate_id,
        idempotency_key=event_key,
        payload={**refutation_body, "refutation_sha256": refutation_digest},
        created_at=now,
    )
    return {
        "candidate_refuted": True,
        "negative_control_created": not reused,
        "reason": "candidate_refuted" if not reused else "candidate_refuted_by_reused_negative_control",
        "negative_control_fact_id": negative_control_id,
        "negative_control_key": reusable_key,
        "refutation_sha256": refutation_digest,
        "reused": reused,
    }


def _consume_ready_strategy_replans(conn, project_id: str, candidate_id: str) -> int:
    """Append an immutable receipt when independently reviewed alternate evidence is ready."""
    consumed = 0
    for resolution in ready_strategy_replan_resolutions(conn, project_id, candidate_id):
        event_key = (
            "uvpg-strategy-replan-resolved:"
            f"{resolution['required_event_sequence']}"
        )
        append_event(
            conn, project_id, "proof_strategy_replan_resolved", "dispatcher.proof-gap",
            entity_kind="fact", entity_id=candidate_id,
            idempotency_key=event_key,
            payload=resolution,
        )
        consumed += 1
    return consumed


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
        _consume_ready_strategy_replans(conn, project_id, fact_id)
        status = _proof_status_payload(conn, project_id, fact_id)
        gaps = derive_proof_gaps(conn, project_id, fact_id)
        unreachable_gap = next((gap for gap in gaps if gap.code == "UNREACHABLE"), None)
        if unreachable_gap is not None:
            refutation = _persist_unreachable_refutation(
                conn, project_id, fact_id, unreachable_gap,
            )
            if refutation is not None and refutation.get("candidate_refuted"):
                return {
                    "created_intent": False,
                    **refutation,
                    "candidate_id": fact_id,
                    **_proof_status_payload(conn, project_id, fact_id),
                }
            if refutation is not None:
                unreachable_sources = set(unreachable_gap.related_fact_ids)
                has_dispatchable_review = any(
                    gap.code == "UNREVIEWED_EVIDENCE"
                    and gap.status == "missing"
                    and gap.suggested_intent_type in {
                        "review:devils-advocate", "review:cold-verifier",
                    }
                    and (
                        gap.target_fact_id in unreachable_sources
                        or (
                            gap.target_fact_id == fact_id
                            and gap.suggested_intent_type == "review:cold-verifier"
                        )
                    )
                    for gap in gaps
                )
                if not has_dispatchable_review:
                    return {
                        "created_intent": False,
                        **refutation,
                        "candidate_id": fact_id,
                        **status,
                    }
        assessment = latest_finding_assessment(conn, project_id, fact_id)
        if assessment is not None:
            verdict, confidence, details = assessment
            if (
                verdict == "VALID"
                and confidence in {"firm", "certain"}
                and details.get("classification")
                in {"false_positive", "design_weakness", "hardening_advice"}
            ):
                # The proof package is a vulnerability-evidence workflow. A
                # decisive review that classifies a candidate outside the
                # vulnerability category is terminal for this planner; keep
                # the proof-status diagnostics visible without creating an
                # unbounded chain of exploitability obligations.
                return {
                    "created_intent": False,
                    "reason": "candidate_assessed_as_non_vulnerability",
                    **status,
                }
        strategy_gap = next((
            gap for gap in gaps
            if gap.failure_class in {"wrong_path", "wrong_boundary_assumption"}
        ), None)
        semantic_review_pending = any(
            gap.code == "UNREVIEWED_EVIDENCE"
            and gap.role == "failure_claim"
            and gap.target_fact_id is not None
            for gap in gaps
        )
        if strategy_gap is not None:
            proof_prefix = f"@uvpg:proof:{fact_id}:"
            related_ids = set(strategy_gap.related_fact_ids)
            recipe_keys = set()
            failed_fact_ids = set()
            if related_ids:
                placeholders = ",".join("?" for _ in related_ids)
                failure_rows = conn.execute(
                    f"SELECT id, description, evidence, proof FROM facts WHERE project_id = ? "
                    f"AND source_generation = ? AND id IN ({placeholders}) ORDER BY id",
                    (project_id, project["source_generation"], *sorted(related_ids)),
                ).fetchall()
                for row in failure_rows:
                    proof_data = _json_object(row["proof"])
                    attrs = proof_data.get("attributes", {})
                    if isinstance(attrs, dict) and attrs.get("failure_code") == strategy_gap.code:
                        recipe_keys.add(_strategy_recipe_key(strategy_gap.code, row, proof_data))
                        failed_fact_ids.add(row["id"])
            if not recipe_keys or not failed_fact_ids:
                return {"created_intent": False, "reason": "strategy_recipe_identity_missing", **status}
            failed_fact_ids = sorted(failed_fact_ids)
            recipe_set_sha256 = _canonical_sha256({
                "recipe_keys": sorted(recipe_keys),
                "failed_fact_ids": failed_fact_ids,
            })
            event_key = f"uvpg-strategy-replan:{strategy_gap.key}:{recipe_set_sha256}"
            prior_replan = conn.execute(
                "SELECT sequence FROM audit_events WHERE project_id = ? AND idempotency_key = ?",
                (project_id, event_key),
            ).fetchone()
            if prior_replan is not None and not semantic_review_pending:
                return {"created_intent": False, "reason": "strategy_replan_already_requested", **status}
            failures = 0
            if recipe_keys:
                matching_fact_ids = failed_fact_ids
                if matching_fact_ids:
                    placeholders = ",".join("?" for _ in matching_fact_ids)
                    failures = conn.execute(
                        f"SELECT COUNT(DISTINCT i.id) AS attempts FROM intents i "
                        f"JOIN facts f ON f.project_id = i.project_id AND f.id = i.to_fact_id "
                        f"LEFT JOIN intent_errors e ON e.project_id = i.project_id AND e.intent_id = i.id "
                        f"WHERE i.project_id = ? AND i.source_generation = ? "
                        f"AND i.to_fact_id IN ({placeholders}) AND i.description LIKE ? "
                        f"AND (i.concluded_at IS NOT NULL OR e.id IS NOT NULL)",
                        (
                            project_id, project["source_generation"],
                            *matching_fact_ids, f"{proof_prefix}%",
                        ),
                    ).fetchone()["attempts"]
            if failures >= STRATEGY_REPLAN_AFTER_FAILURES:
                hint = (
                    f"@uvpg:strategy-replan candidate={fact_id} code={strategy_gap.code} "
                    f"generation={project['source_generation']}: Rebuild the attack path from "
                    "the source graph. Choose a different entry point or trust-boundary model "
                    "and do not repeat the failed recipe. Record why the previous path failed."
                )
                duplicate_hint = conn.execute(
                    "SELECT 1 FROM hints WHERE project_id = ? AND content = ? LIMIT 1",
                    (project_id, hint),
                ).fetchone()
                if duplicate_hint is None:
                    hint_id = next_hint_id(conn, project_id)
                    conn.execute(
                        "INSERT INTO hints (id, project_id, content, creator, created_at) "
                        "VALUES (?, ?, ?, 'dispatcher.proof-gap', ?)",
                        (hint_id, project_id, hint, utcnow()),
                    )
                    bump_graph_revision(conn, project_id)
                append_event(
                    conn, project_id, "proof_strategy_replan_required", "dispatcher.proof-gap",
                    entity_kind="fact", entity_id=fact_id,
                    payload={
                        "candidate_id": fact_id,
                        "gap_code": strategy_gap.code,
                        "failure_class": strategy_gap.failure_class,
                        "source_generation": project["source_generation"],
                        "failed_attempts": failures,
                        "failed_recipe_keys": sorted(recipe_keys),
                        "failed_fact_ids": failed_fact_ids,
                        "failed_recipe_set_sha256": recipe_set_sha256,
                        "previous_intent_prefix": proof_prefix,
                    },
                    idempotency_key=event_key,
                )
                if not semantic_review_pending:
                    return {"created_intent": False, "reason": "strategy_replan_required", **_proof_status_payload(conn, project_id, fact_id)}
        eligible_gaps = [
            gap for gap in gaps
            if gap.code not in NON_INVESTIGATIVE_GAPS
            and gap.code not in NON_AUTOMATIC_REPAIR_GAPS
            and gap.failure_class not in {"wrong_path", "wrong_boundary_assumption"}
        ]
        if strategy_gap is not None and not eligible_gaps:
            return {"created_intent": False, "reason": "strategy_retry_cooldown", **status}
        selected = eligible_gaps[0] if eligible_gaps else None
        if selected is None:
            return {"created_intent": False, "reason": "no_investigative_gap", **status}
        existing = conn.execute(
            "SELECT id FROM intents WHERE project_id = ? AND to_fact_id IS NULL AND concluded_at IS NULL "
            "AND source_generation = ? AND description LIKE ? ORDER BY id LIMIT 1",
            (project_id, project["source_generation"], f"@uvpg:proof:{selected.key}:%"),
        ).fetchone()
        if existing is not None:
            return {"created_intent": False, "reason": "duplicate_open_obligation", "intent_id": existing["id"], **status}
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
        return {"created_intent": True, "intent_id": intent_id, "gap": selected.as_dict(), **_proof_status_payload(conn, project_id, fact_id)}


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
        reportability_block = reportability_reason(conn, project_id, fact_id)
        if reportability_block is not None:
            assessment = latest_finding_assessment(conn, project_id, fact_id)
            return JSONResponse(
                status_code=409,
                content={
                    "status": "not_confirmed",
                    "candidate_id": fact_id,
                    "reason_codes": [reportability_block],
                    "finding_assessment": assessment[2] if assessment else None,
                },
            )
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
                content=_confirmation_result(result, status="not_confirmed", candidate_id=fact_id, fingerprint=fingerprint, verification_level="unconfirmed", dynamic_result=dynamic_result),
            )
        if dynamic_result.status != "PASS":
            return JSONResponse(
                status_code=409,
                content=_confirmation_result(result, status="not_confirmed", candidate_id=fact_id, fingerprint=fingerprint, verification_level="unconfirmed", dynamic_result=dynamic_result),
            )
        if fingerprint != proof_graph_fingerprint(conn, project_id, fact_id):
            result = replace(result, reason_codes=(*result.reason_codes, "PROOF_GRAPH_CHANGED"))
            return JSONResponse(status_code=409, content=_confirmation_result(result, status="not_confirmed", candidate_id=fact_id, fingerprint=fingerprint, verification_level="unconfirmed", dynamic_result=dynamic_result))

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
                "verification_level": "dynamic_confirmed",
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
        return _confirmation_result(result, status="confirmed", candidate_id=fact_id, confirmed_fact_id=confirmed_id, fingerprint=fingerprint, verification_level="dynamic_confirmed", dynamic_result=dynamic_result)


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

        open_worker_issues = []
        if body.status == "active" and "worker_issues" in row.keys():
            try:
                open_worker_issues = json.loads(row["worker_issues"] or "[]")
            except (TypeError, json.JSONDecodeError):
                open_worker_issues = []
        conn.execute(
            "UPDATE projects SET status = ?, worker_issues = ? WHERE id = ?",
            (body.status, "[]" if body.status == "active" else row["worker_issues"], project_id),
        )
        bump_graph_revision(conn, project_id)
        if body.status == "stopped":
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE project_id = ? AND concluded_at IS NULL",
                (project_id,),
            )
            clear_project_reason(conn, project_id)
        elif open_worker_issues:
            append_event(
                conn,
                project_id,
                "project_worker_issue_resumed",
                "Human",
                entity_kind="project",
                entity_id=project_id,
                payload={
                    "issue_count": len(open_worker_issues),
                    "worker_issues": [
                        {"worker": issue.get("worker"), "code": issue.get("code")}
                        for issue in open_worker_issues
                        if isinstance(issue, dict)
                    ],
                },
            )
        return project_meta_from_row(get_project_or_404(conn, project_id))


@router.post("/projects/{project_id}/worker-issue", response_model=ProjectMeta)
def pause_project_for_worker_issue(
    project_id: str, body: ReportProjectWorkerIssueRequest,
):
    """Persist a deterministic CLI failure and pause the project for recovery."""
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        if row["status"] == "completed":
            raise HTTPException(409, "Completed projects cannot be paused for a worker issue")
        try:
            issues = json.loads(row["worker_issues"] or "[]")
        except (TypeError, json.JSONDecodeError):
            issues = []
        issue = {
            **body.model_dump(),
            "created_at": utcnow(),
        }
        duplicate = any(
            isinstance(existing, dict)
            and existing.get("worker") == issue["worker"]
            and existing.get("code") == issue["code"]
            and existing.get("task_type") == issue["task_type"]
            and existing.get("intent_id") == issue["intent_id"]
            for existing in issues
        )
        if duplicate:
            return project_meta_from_row(row)
        issues.append(issue)
        was_active = row["status"] == "active"
        if body.intent_id:
            conn.execute(
                "UPDATE intent_errors SET resolved_at = ?, resolution = ? "
                "WHERE project_id = ? AND intent_id = ? AND resolved_at IS NULL",
                (issue["created_at"], f"superseded by {body.code}; resume after CLI repair", project_id, body.intent_id),
            )
        conn.execute(
            "UPDATE projects SET status = 'stopped', worker_issues = ? WHERE id = ?",
            (json.dumps(issues, ensure_ascii=False), project_id),
        )
        if was_active:
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE project_id = ? AND concluded_at IS NULL",
                (project_id,),
            )
            clear_project_reason(conn, project_id)
            bump_graph_revision(conn, project_id)
        append_event(
            conn,
            project_id,
            "project_worker_issue_blocked",
            "dispatcher",
            entity_kind="intent" if body.intent_id else "project",
            entity_id=body.intent_id or project_id,
            payload={
                "worker": body.worker,
                "task_type": body.task_type,
                "code": body.code,
                "message": body.message,
                "remediation": body.remediation,
            },
        )
        return project_meta_from_row(get_project_or_404(conn, project_id))


@router.put("/projects/{project_id}/worker-preference", response_model=ProjectMeta)
def update_project_worker_preference(
    project_id: str, body: UpdateProjectWorkerPreferenceRequest,
):
    with get_conn() as conn:
        row = get_project_or_404(conn, project_id)
        if row["worker_preference"] == body.worker_preference:
            return project_meta_from_row(row)
        conn.execute(
            "UPDATE projects SET worker_preference = ? WHERE id = ?",
            (body.worker_preference, project_id),
        )
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
