from datetime import datetime, timedelta, timezone
import json

from fastapi import APIRouter, HTTPException

from linen.candidate_attempts import is_candidate_attempt
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
    ResolveIntentRequest,
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
from linen.server.uvpg import (
    DYNAMIC_PROOF_GAPS,
    GAP_CONTRACTS,
    candidate_proof_facts,
    canonical_proof_edges,
    parse_proof_obligation,
    validate_proof_payload,
)
from linen.server.kernel import (
    KernelConflict,
    KernelForbidden,
    KernelNotFound,
    create_intent as create_intent_kernel,
    heartbeat_intent as heartbeat_intent_kernel,
    release_intent as release_intent_kernel,
    resolve_intent as resolve_intent_kernel,
)

router = APIRouter(tags=["intents"])

COVERAGE_PREFIX = "@coverage:"
AUDIT_CREATOR = "dispatcher.audit"
COMPACTED_INTENT_TYPE = "cancelled:coverage-compaction"
CANDIDATE_BUDGET_RESIDUAL_KIND = "candidate_budget_residual"


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
        try:
            return create_intent_kernel(conn, project_id, body)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelForbidden as exc:
            raise HTTPException(403, str(exc)) from exc
        except KernelConflict as exc:
            status_code = 400 if any(message in str(exc) for message in (
                "goal cannot be used in from",
                "worker must be null or equal to creator",
            )) else 409
            raise HTTPException(status_code, str(exc)) from exc


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        try:
            return heartbeat_intent_kernel(conn, project_id, intent_id, body)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelForbidden as exc:
            raise HTTPException(403, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        try:
            return release_intent_kernel(conn, project_id, intent_id, body)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelForbidden as exc:
            raise HTTPException(403, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


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

        historical_attempts = conn.execute(
            "SELECT COALESCE(SUM(attempt_count), 0) AS attempts "
            "FROM intent_errors WHERE project_id = ? AND intent_id = ? "
            "AND code = ? AND resolved_at IS NOT NULL",
            (project_id, intent_id, body.code),
        ).fetchone()["attempts"]
        attempt_count = (
            (existing["attempt_count"] if same_episode else historical_attempts) + 1
        )
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
    "/projects/{project_id}/intents/{intent_id}/resolve",
    response_model=Intent,
)
def resolve(project_id: str, intent_id: str, body: ResolveIntentRequest):
    with get_conn() as conn:
        try:
            return resolve_intent_kernel(conn, project_id, intent_id, body)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelForbidden as exc:
            raise HTTPException(403, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


def _candidate_attempt_count(conn, project_id: str, source_generation: int) -> int:
    """Count vulnerability Facts created during this source generation.

    Reviews and UVPG refutations can change semantic_type after a candidate is
    created. Those settled attempts still consume the generation's budget.
    """
    rows = conn.execute(
        "SELECT type, semantic_type FROM facts WHERE project_id = ? "
        "AND type = 'vulnerability' AND source_generation = ?",
        (project_id, source_generation),
    ).fetchall()
    return sum(
        is_candidate_attempt(row["type"], row["semantic_type"])
        for row in rows
    )


def _record_candidate_budget_residual(
    conn,
    project,
    intent_row,
    body: ConcludeRequest,
    *,
    candidate_count: int,
    candidate_budget: int,
    created_at: str,
) -> ConcludeResponse:
    """Conclude an overflow candidate into one provenance-bearing residual Fact."""
    project_id = project["id"]
    generation = project["source_generation"]
    source_rows = conn.execute(
        "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ? ORDER BY rowid",
        (project_id, intent_row["id"]),
    ).fetchall()
    source_ids = [row["fact_id"] for row in source_rows]
    record = {
        "source_intent_id": intent_row["id"],
        "source_intent_description": intent_row["description"],
        "source_fact_ids": source_ids,
        "candidate_description": body.description,
        "candidate_evidence": body.evidence,
        "candidate_proof": (
            body.proof.model_dump(mode="json") if body.proof is not None else None
        ),
        "recorded_at": created_at,
    }

    residual_row = None
    for row in conn.execute(
        "SELECT id, description, evidence FROM facts WHERE project_id = ? "
        "AND type = 'coverage_result' AND source_generation = ? ORDER BY id",
        (project_id, generation),
    ).fetchall():
        try:
            payload = json.loads(row["evidence"] or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        if (
            isinstance(payload, dict)
            and payload.get("kind") == CANDIDATE_BUDGET_RESIDUAL_KIND
            and payload.get("dedupe_key") == f"candidate-budget-residual:g{generation}"
        ):
            residual_row = row
            break

    if residual_row is None:
        residual_id = next_fact_id(conn, project_id)
        residual = {
            "schema_version": 1,
            "kind": CANDIDATE_BUDGET_RESIDUAL_KIND,
            "dedupe_key": f"candidate-budget-residual:g{generation}",
            "source_generation": generation,
            "max_candidate_findings": candidate_budget,
            "candidate_count_at_overflow": candidate_count,
            "overflow_leads": [record],
        }
        residual_description = (
            f"Candidate budget residual: 1 lead retained beyond the configured limit "
            f"of {candidate_budget}."
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description, display_title, type, semantic_type, "
            "evidence, source_generation, status) VALUES (?, ?, ?, ?, 'coverage_result', "
            "'coverage', ?, ?, 'triaged')",
            (
                residual_id, project_id, residual_description,
                "Candidate budget residual",
                json.dumps(residual, ensure_ascii=False, sort_keys=True), generation,
            ),
        )
    else:
        residual_id = residual_row["id"]
        try:
            residual = json.loads(residual_row["evidence"] or "{}")
        except (TypeError, json.JSONDecodeError):
            residual = {}
        if not isinstance(residual, dict) or residual.get("kind") != CANDIDATE_BUDGET_RESIDUAL_KIND:
            residual = {
                "schema_version": 1,
                "kind": CANDIDATE_BUDGET_RESIDUAL_KIND,
                "dedupe_key": f"candidate-budget-residual:g{generation}",
                "source_generation": generation,
                "max_candidate_findings": candidate_budget,
                "candidate_count_at_overflow": candidate_count,
                "overflow_leads": [],
            }
        leads = residual.setdefault("overflow_leads", [])
        if not isinstance(leads, list):
            leads = []
            residual["overflow_leads"] = leads
        residual["dedupe_key"] = f"candidate-budget-residual:g{generation}"
        if not any(
            isinstance(item, dict) and item.get("source_intent_id") == intent_row["id"]
            for item in leads
        ):
            leads.append(record)
        residual["max_candidate_findings"] = candidate_budget
        residual_description = (
            f"Candidate budget residual: {len(leads)} lead(s) retained beyond the configured "
            f"limit of {candidate_budget}."
        )
        conn.execute(
            "UPDATE facts SET description = ?, display_title = ?, semantic_type = 'coverage', "
            "evidence = ?, status = 'triaged' WHERE project_id = ? AND id = ?",
            (
                residual_description, "Candidate budget residual",
                json.dumps(residual, ensure_ascii=False, sort_keys=True), project_id,
                residual_id,
            ),
        )

    conn.execute(
        "UPDATE intents SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ? "
        "WHERE id = ? AND project_id = ?",
        (residual_id, body.worker, created_at, created_at, intent_row["id"], project_id),
    )
    resolve_intent_errors(
        conn,
        project_id,
        intent_row["id"],
        resolution="candidate overflow retained as residual coverage evidence",
        resolved_at=created_at,
    )
    relation_type = intent_row["relation_type"] or "produces"
    for source_id in source_ids:
        create_graph_edge(
            conn,
            project_id,
            source_kind="fact",
            source_id=source_id,
            target_kind="fact",
            target_id=residual_id,
            relation_type=relation_type,
            created_by="server.candidate-budget",
            metadata={
                "intent_id": intent_row["id"],
                "candidate_budget_overflow": True,
            },
            created_at=created_at,
        )
    bump_graph_revision(conn, project_id)
    append_event(
        conn,
        project_id,
        "candidate_budget_overflow_recorded",
        "server.candidate-budget",
        entity_kind="fact",
        entity_id=residual_id,
        payload={
            "source_intent_id": intent_row["id"],
            "overflow_lead_source_fact_ids": source_ids,
            "candidate_budget": candidate_budget,
            "candidate_count_before_overflow": candidate_count,
        },
        created_at=created_at,
    )
    append_event(
        conn,
        project_id,
        "audit_task_concluded",
        body.worker,
        entity_kind="intent",
        entity_id=intent_row["id"],
        payload={
            "fact_id": residual_id,
            "type": "coverage_result",
            "semantic_type": "coverage",
            "relation_type": relation_type,
            "candidate_budget_overflow": True,
        },
        created_at=created_at,
    )
    updated = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_row["id"], project_id),
    ).fetchone()
    return ConcludeResponse(
        fact=Fact(
            id=residual_id,
            description=residual_description,
            display_title="Candidate budget residual",
            type="coverage_result",
            semantic_type="coverage",
            evidence=json.dumps(residual, ensure_ascii=False, sort_keys=True),
            source_generation=generation,
            status="triaged",
        ),
        intent=intent_to_model(conn, updated, project_id),
    )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        # Candidate count and Fact write form one serialized policy decision.
        # Without IMMEDIATE, two concurrent workers could both observe room
        # below the configured cap and exceed it together.
        conn.execute("BEGIN IMMEDIATE")
        project = check_project_active(conn, project_id)
        intent_row = get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        if (
            body.type == "vulnerability"
            and project["audit_mode"] != "none"
        ):
            candidate_count = _candidate_attempt_count(
                conn, project_id, project["source_generation"],
            )
            if candidate_count >= body.candidate_budget:
                return _record_candidate_budget_residual(
                    conn,
                    project,
                    intent_row,
                    body,
                    candidate_count=candidate_count,
                    candidate_budget=body.candidate_budget,
                    created_at=now,
                )
        fid = next_fact_id(conn, project_id)
        obligation = parse_proof_obligation(intent_row["description"])
        dynamic_proof = False
        proof_payload = body.proof
        if obligation is not None:
            candidate_id, gap_code, generation, target_fact_id = obligation
            if gap_code in {"UNREVIEWED_EVIDENCE", "UNREVIEWED_DYNAMIC_EVIDENCE"}:
                raise HTTPException(409, {"code": "REVIEW_OBLIGATION_REQUIRES_REVIEW_ENDPOINT"})
            contract = GAP_CONTRACTS.get(gap_code)
            source_ids = {row["fact_id"] for row in conn.execute(
                "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ?",
                (project_id, intent_id),
            )}
            if generation != project["source_generation"] or candidate_id not in source_ids or contract is None:
                raise HTTPException(409, {"code": "STALE_PROOF_OBLIGATION"})
            expected_type = contract[0]
            if body.type != expected_type:
                raise HTTPException(422, {"code": "PROOF_OBLIGATION_FACT_TYPE_MISMATCH", "expected_fact_type": expected_type})
            if body.proof is None or body.proof.claim_kind != expected_type:
                raise HTTPException(422, {"code": "PROOF_FACT_REQUIRES_PROVENANCE", "expected_claim_kind": expected_type})
            if gap_code == "MISSING_CAPABILITY_DELTA":
                before = candidate_proof_facts(conn, project_id, candidate_id, "capability_before")
                after = candidate_proof_facts(conn, project_id, candidate_id, "capability_after")
                if len(before) != 1 or len(after) != 1:
                    raise HTTPException(409, {"code": "CAPABILITY_DELTA_REQUIRES_LOCAL_BEFORE_AFTER"})
            if gap_code in DYNAMIC_PROOF_GAPS:
                assert proof_payload is not None
                run = conn.execute(
                    "SELECT r.*, i.type AS intent_type FROM runs r LEFT JOIN intents i "
                    "ON i.project_id = r.project_id AND i.id = r.intent_id "
                    "WHERE r.project_id = ? AND r.intent_id = ? "
                    "ORDER BY r.started_at DESC, r.run_id DESC LIMIT 1",
                    (project_id, intent_id),
                ).fetchone()
                if (
                    run is None
                    or run["source_generation"] != project["source_generation"]
                    or run["status"] not in {"completed", "succeeded"}
                    or not (run["intent_type"] or "").startswith("poc:isolated")
                ):
                    raise HTTPException(409, {"code": "DYNAMIC_PROOF_REQUIRES_SUCCESSFUL_ISOLATED_RUN"})
                try:
                    artifact_ids = json.loads(run["artifact_ids"] or "[]")
                except (TypeError, json.JSONDecodeError):
                    artifact_ids = []
                if not isinstance(artifact_ids, list) or not artifact_ids:
                    raise HTTPException(409, {"code": "DYNAMIC_PROOF_REQUIRES_RUN_ARTIFACTS"})
                attributes = dict(proof_payload.attributes)
                observed_outcome = attributes.get("observed_outcome")
                capability_observed = attributes.get("capability_observed")
                if capability_observed is None and isinstance(observed_outcome, dict):
                    capability_observed = observed_outcome.get(
                        "capability_observed", observed_outcome.get("capability"),
                    )
                if (
                    not isinstance(attributes.get("oracle_kind"), str)
                    or not attributes["oracle_kind"].strip()
                    or observed_outcome is None
                    or capability_observed is None
                ):
                    raise HTTPException(422, {"code": "DYNAMIC_PROOF_REQUIRES_ORACLE_AND_CAPABILITY_OBSERVATION"})
                attributes.update({
                    "mode": "dynamic",
                    "candidate_id": candidate_id,
                    "run_id": run["run_id"],
                    "artifact_ids": artifact_ids,
                    "capability_observed": capability_observed,
                })
                proof_payload = proof_payload.model_copy(update={
                    "subject_ids": [candidate_id],
                    "artifact_ids": artifact_ids,
                    "attributes": attributes,
                })
                dynamic_proof = True
        semantic_type = (
            fact_semantic_type(fid, body.type, body.status)
            if body.type == "vulnerability"
            else body.semantic_type or fact_semantic_type(fid, body.type, body.status)
        )
        if semantic_type == "confirmed_finding" or body.type == "confirmed_finding":
            raise HTTPException(
                422,
                {"code": "CONFIRMED_FINDING_REQUIRES_TECHNICAL_GATE"},
            )
        display_title = body.display_title or fact_display_title(
            fid, body.type, body.description, status=body.status,
        )
        proof_errors = validate_proof_payload(conn, project_id, proof_payload)
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
                json.dumps(proof_payload.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
                if proof_payload is not None else None,
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
        if obligation is not None and not dynamic_proof:
            canonical_proof_edges(
                conn, project_id, obligation[0], fid, obligation[1],
                created_by="server.proof-contract", created_at=now,
            )
        else:
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
                proof=body.proof,
                source_generation=project["source_generation"],
                status=body.status,
            ),
            intent=intent_to_model(conn, updated, project_id),
        )
