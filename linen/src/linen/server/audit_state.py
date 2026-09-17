"""Semantic blackboard projections and the server-owned Completion Gate.

The dispatcher remains the only protocol writer for workers.  This module is
the deterministic boundary that turns worker output into stable UI semantics,
typed graph relations, phase receipts, and a queryable completion decision.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from typing import Any

from linen.server.models import (
    AuditEvent,
    AuditStage,
    CompletionCheck,
    CompletionGate,
    GraphEdge,
    HumanDecision,
    SkillRun,
)
from linen.server.services import (
    audit_completion_blockers_from_db,
    get_project_or_404,
    next_graph_edge_id,
    next_human_decision_id,
    next_skill_run_id,
    utcnow,
)


FACT_SEMANTIC_TYPES: dict[str, str] = {
    "policy_evidence": "scope",
    "scope_adjudication": "scope",
    "coverage_plan": "coverage",
    "coverage_result": "coverage",
    "scan_batch": "observation",
    "route_scan": "observation",
    "source": "observation",
    "sink": "observation",
    "dataflow": "observation",
    "sanitizer": "observation",
    "validation": "observation",
    "reachability": "observation",
    "architecture_map": "observation",
    "authz_matrix": "observation",
    "state_model": "observation",
    "cross_service_map": "observation",
    "contract_map": "observation",
    "hypothesis_batch": "hypothesis",
    "variant_batch": "hypothesis",
    "candidate_triage": "hypothesis",
    "candidate_disposition": "candidate_finding",
    "vulnerability": "candidate_finding",
    "negative_assurance": "negative_assurance",
    "module_summary": "summary",
    "semantic_summary": "summary",
    "audit_summary": "summary",
}

FACT_TITLES: dict[str, str] = {
    "policy_evidence": "Scope evidence",
    "scope_adjudication": "Scope decision",
    "coverage_plan": "Coverage plan",
    "coverage_result": "Coverage result",
    "scan_batch": "Scanner evidence",
    "route_scan": "Route evidence",
    "architecture_map": "Architecture map",
    "authz_matrix": "Authorization map",
    "state_model": "State model",
    "cross_service_map": "Trust map",
    "contract_map": "Contract map",
    "hypothesis_batch": "Hypotheses",
    "variant_batch": "Variant search",
    "candidate_triage": "Triage decision",
    "candidate_disposition": "Candidate verdict",
    "vulnerability": "Candidate finding",
    "negative_assurance": "Negative assurance",
    "module_summary": "Coverage summary",
    "semantic_summary": "Reasoning summary",
    "audit_summary": "Audit summary",
}

INTENT_METADATA: tuple[tuple[str, str, str, str], ...] = (
    ("@analysis:scope-evidence", "Collect scope evidence", "scope", "defines"),
    ("@analysis:scope-adjudication", "Decide audit scope", "scope", "defines"),
    ("@analysis:coverage-plan", "Plan coverage", "coverage", "defines"),
    ("@analysis:semgrep", "Run Semgrep", "baseline_scan", "produces"),
    ("@analysis:spotbugs-findsecbugs", "Run SpotBugs", "baseline_scan", "produces"),
    ("@analysis:osv-scanner", "Run OSV-Scanner", "baseline_scan", "produces"),
    ("@analysis:gitleaks", "Run Gitleaks", "baseline_scan", "produces"),
    ("@analysis:trivy", "Run Trivy", "baseline_scan", "produces"),
    ("@analysis:audit-summary", "Build audit summary", "report", "produces"),
    ("@analysis:semantic-summary", "Summarize reasoning", "hypothesis", "produces"),
)


def _title_from_description(description: str, fallback: str) -> str:
    text = " ".join((description or "").strip().split())
    if not text:
        return fallback
    if text.startswith("@"):
        return fallback
    first = re.split(r"(?<=[.!?])\s+|\n", text, maxsplit=1)[0]
    return first if len(first) <= 88 else first[:85].rstrip() + "…"


def fact_semantic_type(fact_id: str, fact_type: str | None, status: str) -> str:
    if fact_id == "origin":
        return "audit_target"
    if fact_id == "goal":
        return "audit_objective"
    if fact_type == "vulnerability":
        if status == "false_positive":
            return "rejected_finding"
        return "candidate_finding"
    return FACT_SEMANTIC_TYPES.get(fact_type or "", "observation")


def fact_display_title(
    fact_id: str,
    fact_type: str | None,
    description: str,
    *,
    status: str = "triaged",
) -> str:
    if fact_id == "origin":
        return "Audit target"
    if fact_id == "goal":
        return "Audit objective"
    fallback = FACT_TITLES.get(fact_type or "", "Observation")
    # ``triaged`` alone does not prove a vulnerability.  A confirmed title is
    # projected only after a decisive review, so newly written candidates keep
    # the candidate label.
    if fact_type == "vulnerability":
        fallback = "Candidate finding"
    return _title_from_description(description, fallback)


def intent_metadata(description: str, intent_type: str | None) -> tuple[str, str, str, str]:
    value = (description or "").strip()
    for exact, title, phase, relation in INTENT_METADATA:
        if value == exact:
            return title, "audit_task", phase, relation
    if value.startswith("@coverage:"):
        return "Verify coverage unit", "audit_task", "coverage", "produces"
    if value.startswith("@analysis:review:") or (intent_type or "").startswith("review"):
        return "Review finding", "review_task", "review", "reviews"
    if value.startswith("@candidate-triage:"):
        return "Triage candidates", "audit_task", "hypothesis", "produces"
    if value.startswith("@candidate-verify:"):
        return "Verify candidate", "audit_task", "verification", "supports"
    if value.startswith("@analysis:semantic:variant_search"):
        return "Search for variants", "audit_task", "variants", "variant_of"
    if value.startswith("@analysis:semantic-verify:"):
        return "Verify hypothesis", "audit_task", "verification", "supports"
    if value.startswith("@analysis:semantic:"):
        return "Build security model", "audit_task", "threat_model", "produces"
    return _title_from_description(value, "Audit task"), "audit_task", "investigate", "produces"


def append_event(
    conn: sqlite3.Connection,
    project_id: str,
    event_type: str,
    actor: str,
    *,
    entity_kind: str | None = None,
    entity_id: str | None = None,
    payload: dict[str, Any] | None = None,
    created_at: str | None = None,
    event_id: str | None = None,
    run_id: str | None = None,
    idempotency_key: str | None = None,
    graph_revision: int | None = None,
) -> int:
    project = get_project_or_404(conn, project_id)
    if idempotency_key:
        existing = conn.execute(
            "SELECT sequence FROM audit_events WHERE project_id = ? AND idempotency_key = ?",
            (project_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            return int(existing["sequence"])
    event_id = event_id or f"evt-{uuid.uuid4().hex}"
    conn.execute(
        "INSERT INTO audit_events (event_id, project_id, run_id, idempotency_key, schema_version, "
        "event_type, actor, entity_kind, entity_id, source_generation, plan_revision, graph_revision, payload, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            project_id,
            run_id,
            idempotency_key,
            event_type,
            actor,
            entity_kind,
            entity_id,
            project["source_generation"] if "source_generation" in project.keys() else 1,
            project["plan_revision"] if "plan_revision" in project.keys() else 1,
            graph_revision if graph_revision is not None else project["graph_revision"] if "graph_revision" in project.keys() else 0,
            json.dumps(payload or {}, ensure_ascii=False, sort_keys=True),
            created_at or utcnow(),
        ),
    )
    return int(conn.execute("SELECT last_insert_rowid() AS sequence").fetchone()["sequence"])


def create_graph_edge(
    conn: sqlite3.Connection,
    project_id: str,
    *,
    source_kind: str,
    source_id: str,
    target_kind: str,
    target_id: str,
    relation_type: str,
    created_by: str,
    metadata: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> str:
    project = get_project_or_404(conn, project_id)
    existing = conn.execute(
        "SELECT id FROM graph_edges WHERE project_id = ? AND source_kind = ? AND source_id = ? "
        "AND target_kind = ? AND target_id = ? AND relation_type = ? AND source_generation = ?",
        (
            project_id,
            source_kind,
            source_id,
            target_kind,
            target_id,
            relation_type,
            project["source_generation"] if "source_generation" in project.keys() else 1,
        ),
    ).fetchone()
    if existing is not None:
        return existing["id"]
    edge_id = next_graph_edge_id(conn, project_id)
    conn.execute(
        "INSERT INTO graph_edges (id, project_id, source_kind, source_id, target_kind, target_id, "
        "relation_type, source_generation, created_at, created_by, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            edge_id,
            project_id,
            source_kind,
            source_id,
            target_kind,
            target_id,
            relation_type,
            project["source_generation"] if "source_generation" in project.keys() else 1,
            created_at or utcnow(),
            created_by,
            json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
        ),
    )
    return edge_id


def _edge_from_row(row: sqlite3.Row) -> GraphEdge:
    return GraphEdge(
        id=row["id"],
        source_kind=row["source_kind"],
        source_id=row["source_id"],
        target_kind=row["target_kind"],
        target_id=row["target_id"],
        relation_type=row["relation_type"],
        source_generation=row["source_generation"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        metadata=json.loads(row["metadata"] or "{}"),
    )


def list_graph_edges(conn: sqlite3.Connection, project_id: str) -> list[GraphEdge]:
    rows = conn.execute(
        "SELECT * FROM graph_edges WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    return [_edge_from_row(row) for row in rows]


def _stage_from_row(row: sqlite3.Row) -> AuditStage:
    return AuditStage(
        stage_id=row["stage_id"],
        label=row["label"],
        phase_order=row["phase_order"],
        required=bool(row["required"]),
        status=row["status"],
        capability=row["capability"],
        skill_id=row["skill_id"],
        run_id=row["run_id"],
        detail=row["detail"],
        source_generation=row["source_generation"],
        plan_revision=row["plan_revision"],
        updated_at=row["updated_at"],
    )


def list_audit_stages(conn: sqlite3.Connection, project_id: str) -> list[AuditStage]:
    project = get_project_or_404(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM audit_stages WHERE project_id = ? AND source_generation = ? "
        "AND plan_revision = ? ORDER BY phase_order, stage_id",
        (project_id, project["source_generation"], project["plan_revision"]),
    ).fetchall()
    return [_stage_from_row(row) for row in rows]


def list_human_decisions(conn: sqlite3.Connection, project_id: str) -> list[HumanDecision]:
    rows = conn.execute(
        "SELECT * FROM human_decisions WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    return [HumanDecision(**dict(row)) for row in rows]


def list_skill_runs(conn: sqlite3.Connection, project_id: str) -> list[SkillRun]:
    rows = conn.execute(
        "SELECT * FROM skill_runs WHERE project_id = ? ORDER BY started_at, id",
        (project_id,),
    ).fetchall()
    return [SkillRun(**dict(row)) for row in rows]


def list_audit_events(
    conn: sqlite3.Connection,
    project_id: str,
    *,
    after: int = 0,
    limit: int = 500,
) -> list[AuditEvent]:
    get_project_or_404(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM audit_events WHERE project_id = ? AND sequence > ? "
        "ORDER BY sequence LIMIT ?",
        (project_id, after, limit),
    ).fetchall()
    return [
        AuditEvent(
            sequence=row["sequence"],
            event_type=row["event_type"],
            actor=row["actor"],
            entity_kind=row["entity_kind"],
            entity_id=row["entity_id"],
            source_generation=row["source_generation"],
            plan_revision=row["plan_revision"],
            payload=json.loads(row["payload"] or "{}"),
            created_at=row["created_at"],
        )
        for row in rows
    ]


def effective_human_decisions(
    conn: sqlite3.Connection, project_id: str,
) -> dict[tuple[str, str], HumanDecision]:
    project = get_project_or_404(conn, project_id)
    generation = project["source_generation"] if "source_generation" in project.keys() else 1
    # Decisions are attestations of one source/plan generation.  Historical
    # decisions remain in the API, but must not waive or confirm a new graph.
    decisions = [
        decision for decision in list_human_decisions(conn, project_id)
        if decision.source_generation == generation
    ]
    superseded = {decision.supersedes_id for decision in decisions if decision.supersedes_id}
    return {
        (decision.target_kind, decision.target_id): decision
        for decision in decisions
        if decision.id not in superseded
    }


def _strongly_reviewed(conn: sqlite3.Connection, project_id: str, fact_id: str) -> bool:
    confirmed = conn.execute(
        "SELECT semantic_type, proof FROM facts WHERE project_id = ? AND id = ?",
        (project_id, fact_id),
    ).fetchone()
    if confirmed is not None and confirmed["semantic_type"] == "confirmed_finding":
        proof = json.loads(confirmed["proof"] or "{}")
        if proof.get("attributes", {}).get("gate_version") == "uvpg-proof-v1":
            return True
    rows = conn.execute(
        "SELECT verdict, confidence FROM reviews WHERE project_id = ? AND fact_id = ?",
        (project_id, fact_id),
    ).fetchall()
    return bool(rows) and all(
        row["verdict"] == "VALID" and row["confidence"] in {"firm", "certain"}
        for row in rows
    )


def _decisively_reviewed(conn: sqlite3.Connection, project_id: str, fact_id: str) -> bool:
    """Whether a candidate has a terminal review decision.

    INVALID is itself a decisive disposition; requiring VALID for every
    candidate would make correctly rejected findings permanently block an
    audit.  Confirmed evidence still uses ``_strongly_reviewed`` below.
    """
    confirmed = conn.execute(
        "SELECT semantic_type, proof FROM facts WHERE project_id = ? AND id = ?",
        (project_id, fact_id),
    ).fetchone()
    if confirmed is not None and confirmed["semantic_type"] == "confirmed_finding":
        proof = json.loads(confirmed["proof"] or "{}")
        if proof.get("attributes", {}).get("gate_version") == "uvpg-proof-v1":
            return True
    rows = conn.execute(
        "SELECT verdict, confidence FROM reviews WHERE project_id = ? AND fact_id = ?",
        (project_id, fact_id),
    ).fetchall()
    if not rows:
        return False
    if any(row["verdict"] == "INVALID" for row in rows):
        return True
    return all(
        row["verdict"] == "VALID" and row["confidence"] in {"firm", "certain"}
        for row in rows
    )


def completion_gate_from_db(
    conn: sqlite3.Connection,
    project_id: str,
    *,
    from_ids: list[str] | None = None,
) -> CompletionGate:
    project = get_project_or_404(conn, project_id)
    generation = project["source_generation"] if "source_generation" in project.keys() else 1
    plan_revision = project["plan_revision"] if "plan_revision" in project.keys() else 1
    checks: list[CompletionCheck] = []
    blockers: list[str] = []

    def add(
        check_id: str,
        label: str,
        passed: bool,
        detail: str,
        *,
        evidence_ids: list[str] | None = None,
        blocking: bool = True,
        status: str | None = None,
    ) -> None:
        check_status = status or ("pass" if passed else "fail")
        checks.append(CompletionCheck(
            id=check_id,
            label=label,
            status=check_status,
            blocking=blocking,
            detail=detail,
            evidence_ids=evidence_ids or [],
        ))
        if blocking and check_status == "fail":
            blockers.append(detail)

    open_rows = conn.execute(
        "SELECT id FROM intents WHERE project_id = ? AND concluded_at IS NULL",
        (project_id,),
    ).fetchall()
    exhaustive = (project["completion_policy"] if "completion_policy" in project.keys() else "goal_based") == "exhaustive"
    add(
        "open_work",
        "All audit tasks reached a terminal state",
        not open_rows if exhaustive else True,
        "No open audit tasks remain." if not open_rows else (
            f"{len(open_rows)} audit task(s) remain open." if exhaustive
            else "Open work is allowed after the goal is satisfied."
        ),
        evidence_ids=[row["id"] for row in open_rows],
        blocking=exhaustive,
        status="pass" if not open_rows or not exhaustive else "fail",
    )

    error_rows = conn.execute(
        "SELECT e.id, e.code FROM intent_errors e JOIN intents i "
        "ON i.project_id = e.project_id AND i.id = e.intent_id "
        "WHERE e.project_id = ? AND e.resolved_at IS NULL AND i.source_generation = ?",
        (project_id, generation),
    ).fetchall()
    add(
        "operational_errors",
        "No unresolved execution errors",
        not error_rows,
        "No unresolved execution errors." if not error_rows
        else f"{len(error_rows)} unresolved execution error(s) block completion.",
        evidence_ids=[row["id"] for row in error_rows],
    )

    decisions = effective_human_decisions(conn, project_id)
    stages = list_audit_stages(conn, project_id)
    if stages:
        incomplete_stages: list[AuditStage] = []
        for stage in stages:
            if not stage.required or stage.status in {"satisfied", "not_applicable"}:
                continue
            decision = decisions.get(("stage", stage.stage_id))
            if decision is not None and decision.decision == "waive":
                continue
            incomplete_stages.append(stage)
        add(
            "pipeline_stages",
            "Required audit stages completed",
            not incomplete_stages,
            "All required audit stages are satisfied." if not incomplete_stages
            else "Incomplete stages: " + ", ".join(
                f"{stage.label} ({stage.status})" for stage in incomplete_stages
            ) + ".",
            evidence_ids=[stage.stage_id for stage in incomplete_stages],
        )
        receipt_rows = conn.execute(
            "SELECT * FROM skill_runs WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ?",
            (project_id, generation, plan_revision),
        ).fetchall()
        receipts_by_id = {row["id"]: row for row in receipt_rows}
        invalid_receipt_stages: list[AuditStage] = []
        valid_receipt_ids: list[str] = []
        for stage in stages:
            if not stage.required or not stage.skill_id:
                continue
            decision = decisions.get(("stage", stage.stage_id))
            if decision is not None and decision.decision == "waive":
                continue
            receipt = receipts_by_id.get(stage.run_id or "")
            valid = bool(
                receipt is not None
                and receipt["stage_id"] == stage.stage_id
                and receipt["skill_id"] == stage.skill_id
                and receipt["status"] in {"completed", "not_applicable"}
                and (
                    receipt["status"] == "not_applicable"
                    or (
                        bool(receipt["artifact_ref"])
                        and isinstance(receipt["artifact_sha256"], str)
                        and len(receipt["artifact_sha256"]) == 64
                    )
                )
            )
            if valid:
                valid_receipt_ids.append(receipt["id"])
            else:
                invalid_receipt_stages.append(stage)
        add(
            "skill_receipts",
            "Managed Skill runs have verified receipts",
            not invalid_receipt_stages,
            "All required managed Skill runs have terminal receipts and verified artifact hashes."
            if not invalid_receipt_stages
            else "Missing or invalid Skill receipts: " + ", ".join(
                stage.label for stage in invalid_receipt_stages
            ) + ".",
            evidence_ids=valid_receipt_ids,
        )
    else:
        add(
            "pipeline_stages",
            "Required audit stages completed",
            True,
            "Legacy board: no stage ledger was registered; evidence checks remain authoritative.",
            status="not_applicable",
        )
        add(
            "skill_receipts",
            "Managed Skill runs have verified receipts",
            True,
            "Legacy board: no managed Skill stages were registered.",
            status="not_applicable",
        )

    audit_mode = project["audit_mode"] if "audit_mode" in project.keys() else "none"
    current_facts = conn.execute(
        "SELECT id, type, semantic_type, legacy, status FROM facts WHERE project_id = ? "
        "AND source_generation = ? AND id NOT IN ('origin', 'goal')",
        (project_id, generation),
    ).fetchall()
    candidate_rows = [
        row for row in current_facts
        if row["type"] == "vulnerability"
        or row["semantic_type"] in {"candidate_finding", "confirmed_finding", "rejected_finding"}
    ]
    unresolved_candidates = [
        row for row in candidate_rows
        if row["status"] == "draft" or not _decisively_reviewed(conn, project_id, row["id"])
    ]
    add(
        "finding_reviews",
        "Every candidate has an independent decision",
        not unresolved_candidates,
        "All candidates have decisive independent review." if not unresolved_candidates
        else f"{len(unresolved_candidates)} candidate finding(s) still require decisive review.",
        evidence_ids=[row["id"] for row in unresolved_candidates],
        # Generic blackboards retain candidate facts but have no adversarial
        # finding gate; this preserves the legacy completion contract.
        status="not_applicable" if audit_mode == "none" else None,
    )

    selected_ids = list(from_ids or [])
    if not selected_ids and project["status"] == "completed":
        completion = conn.execute(
            "SELECT id FROM intents WHERE project_id = ? AND to_fact_id = 'goal' "
            "ORDER BY concluded_at DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        if completion is not None:
            selected_ids = [
                row["fact_id"] for row in conn.execute(
                    "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ? ORDER BY rowid",
                    (project_id, completion["id"]),
                )
            ]
    if not selected_ids and audit_mode == "scope":
        summary = conn.execute(
            "SELECT id FROM facts WHERE project_id = ? AND source_generation = ? "
            "AND type = 'audit_summary' ORDER BY rowid DESC LIMIT 1",
            (project_id, generation),
        ).fetchone()
        if summary is not None:
            selected_ids = [summary["id"]]
    if not selected_ids and audit_mode == "hypothesis":
        selected_ids = [
            row["id"] for row in current_facts
            if (
            row["type"] == "negative_assurance"
            or (row["type"] == "vulnerability" and bool(row["legacy"]))
                or row["semantic_type"] in {"confirmed_finding", "negative_assurance"}
            )
            and row["status"] == "triaged"
            and _strongly_reviewed(conn, project_id, row["id"])
        ]
    if audit_mode != "none" and selected_ids:
        evidence_blockers = audit_completion_blockers_from_db(conn, project_id, selected_ids)
        add(
            "evidence_chain",
            "Completion evidence is reviewed and connected",
            not evidence_blockers,
            "Completion evidence is reviewed and connected." if not evidence_blockers
            else " ".join(evidence_blockers),
            evidence_ids=selected_ids,
        )
    elif audit_mode != "none":
        add(
            "evidence_chain",
            "Completion evidence is reviewed and connected",
            False,
            "Select the reviewed terminal audit evidence for completion.",
        )
    else:
        add(
            "evidence_chain",
            "Completion evidence is reviewed and connected",
            True,
            "No audit evidence gate is configured for this project.",
            status="not_applicable",
        )

    if project["status"] == "completed":
        # Completed projects may still receive operator Hints, which advance
        # graph_revision but do not invalidate the committed final report.
        snapshot = conn.execute(
            "SELECT id FROM report_snapshots WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ? AND format = 'report' ORDER BY created_at DESC, id DESC LIMIT 1",
            (project_id, generation, plan_revision),
        ).fetchone()
    else:
        snapshot = conn.execute(
            "SELECT id FROM report_snapshots WHERE project_id = ? AND source_generation = ? "
            "AND plan_revision = ? AND graph_revision = ? AND format = 'report' "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (project_id, generation, plan_revision, project["graph_revision"]),
        ).fetchone()
    add(
        "final_report",
        "Final report snapshot",
        snapshot is not None,
        "Final report snapshot is current." if snapshot is not None
        else "A final report snapshot will be generated atomically when completion is committed.",
        evidence_ids=[snapshot["id"]] if snapshot is not None else [],
        blocking=False,
        status="pass" if snapshot is not None else "pending",
    )

    execution_status = "complete" if project["status"] == "completed" else (
        "paused" if project["status"] in {"paused", "stopped"} else
        "blocked" if error_rows else
        "running" if open_rows or project["reason_worker"] else
        "idle_attention_required" if blockers else
        "idle"
    )
    return CompletionGate(
        project_id=project_id,
        lifecycle_status=project["status"],
        execution_status=execution_status,
        audit_mode=audit_mode,
        source_generation=generation,
        plan_revision=plan_revision,
        ready=not blockers,
        checks=checks,
        blockers=blockers,
    )
