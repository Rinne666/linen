"""Deterministic audit-stage projection.

Stages are a read-model of the blackboard, never a second queue.  This module
only derives rows; the scheduler is the sole caller that writes them through
the protocol client.  Re-running the derivation after a restart yields the
same stage ids and statuses for the same graph and artifact set.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from linen.dispatcher.analysis.artifacts import load_artifact
from linen.dispatcher.analysis.external_scanners import scanner_specs
from linen.dispatcher.analysis import audit_recipes, coverage, scope_gate
from linen.dispatcher.analysis.spring_scan import SPRING_SCAN_INTENT
from linen.dispatcher.skills import skill_for_scanner
from linen.dispatcher.config import AuditConfig
from linen.server.models import AuditStage, Fact, Intent, ProjectDetail


@dataclass(frozen=True, slots=True)
class StageDefinition:
    stage_id: str
    label: str
    phase_order: int
    capability: str
    required: bool
    skill_id: str | None = None


def stage_definitions(config: AuditConfig, audit_mode: str) -> list[StageDefinition]:
    """Return the stable stage skeleton for one persisted audit profile."""
    if not config.enabled or audit_mode == "none":
        return []
    result: list[StageDefinition] = []
    if audit_mode == "scope" and config.scope_adjudication.enabled:
        result.extend([
            StageDefinition("scope-evidence", "Scope evidence", 10, "scope.evidence", True),
            StageDefinition("scope-adjudication", "Scope adjudication", 20, "scope.adjudication", True),
        ])
    if audit_mode == "scope":
        result.append(StageDefinition("coverage-plan", "Coverage plan", 30, "coverage.plan", True))
    for offset, spec in enumerate(scanner_specs(config, enabled_only=False), start=40):
        skill = skill_for_scanner(spec.name)
        result.append(StageDefinition(
            spec.name,
            spec.label,
            offset,
            skill.capability,
            bool(spec.config.enabled),
            skill.id,
        ))
    if audit_mode == "scope" and config.spring.enabled:
        result.append(StageDefinition("spring-routes", "Spring route scan", 90, "route.extract", True))
    if audit_mode == "scope" and config.semantic.enabled:
        result.append(StageDefinition("semantic-analysis", "Semantic analysis", 100, "semantic.analysis", True))
    if audit_mode == "scope":
        result.append(StageDefinition("audit-summary", "Audit summary", 110, "audit.summary", True))
    return result


def _intent(project: ProjectDetail, description: str) -> Intent | None:
    return next((item for item in project.intents if item.description.strip() == description), None)


def _fact(project: ProjectDetail, intent: Intent | None) -> Fact | None:
    if intent is None or not intent.to:
        return None
    return next((item for item in project.facts if item.id == intent.to), None)


def _manifest_for(fact: Fact | None, workdir: Path) -> dict[str, Any] | None:
    if fact is None:
        return None
    try:
        _, record = load_artifact(fact, workdir)
        return record
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _result_status(intent: Intent | None, fact: Fact | None, workdir: Path) -> tuple[str, str | None, str | None]:
    if intent is None:
        return "pending", None, None
    if intent.to is None and intent.concluded_at is None:
        return ("running" if intent.worker else "pending"), None, None
    if fact is None:
        return "failed", None, "Intent concluded without a result Fact"
    manifest = _manifest_for(fact, workdir)
    if manifest is not None and manifest.get("status") == "failed":
        return "failed", None, "Managed execution failed; review the immutable manifest"
    if manifest is not None and manifest.get("applicability", {}).get("status") == "not_applicable":
        return "not_applicable", None, manifest.get("applicability", {}).get("reason")
    return "satisfied", None, None


def _definition_status(
    definition: StageDefinition,
    config: AuditConfig,
    project: ProjectDetail,
    workdir: Path,
) -> dict[str, Any]:
    if not definition.required:
        existing = next((stage for stage in project.stages if stage.stage_id == definition.stage_id), None)
        return {
            "stage_id": definition.stage_id,
            "label": definition.label,
            "phase_order": definition.phase_order,
            "required": False,
            "status": "not_applicable",
            "capability": definition.capability,
            "skill_id": definition.skill_id,
            "run_id": existing.run_id if existing is not None else None,
            "detail": "Disabled in the persisted dispatcher configuration",
        }
    description = {
        "scope-evidence": scope_gate.EVIDENCE_INTENT,
        "scope-adjudication": scope_gate.ADJUDICATION_INTENT,
        "coverage-plan": coverage.PLAN_INTENT,
        "audit-summary": "@analysis:audit-summary",
        "semantic-analysis": audit_recipes.SUMMARY_INTENT,
    }.get(definition.stage_id, None)
    if definition.stage_id == "spring-routes":
        description = SPRING_SCAN_INTENT
    if description is None:
        description = next(
            (spec.intent for spec in scanner_specs(config, enabled_only=False)
             if spec.name == definition.stage_id),
            f"@analysis:{definition.stage_id}",
        )
    intent = _intent(project, description)
    fact = _fact(project, intent)
    status, run_id, detail = _result_status(intent, fact, workdir)
    if intent is not None:
        errors = [
            error for error in project.errors
            if error.intent_id == intent.id and error.resolved_at is None
        ]
        if errors:
            error = errors[-1]
            status = "blocked" if error.classification == "blocked" else "failed"
            detail = error.message
    existing = next((stage for stage in project.stages if stage.stage_id == definition.stage_id), None)
    if run_id is None and existing is not None:
        # The run id is owned by the skill receipt endpoint. Preserve it when
        # deriving from a graph snapshot that does not expose skill_runs.
        run_id = existing.run_id
    return {
        "stage_id": definition.stage_id,
        "label": definition.label,
        "phase_order": definition.phase_order,
        "required": definition.required,
        "status": status,
        "capability": definition.capability,
        "skill_id": definition.skill_id,
        "run_id": run_id,
        "detail": detail,
    }


def reconcile(config: AuditConfig, project: ProjectDetail, workdir: Path) -> list[dict[str, Any]]:
    """Derive the complete stage projection, with no network or writes."""
    if not config.enabled or project.project.audit_mode == "none":
        return []
    return [
        _definition_status(definition, config, project, workdir)
        for definition in stage_definitions(config, project.project.audit_mode)
    ]


def changed_rows(project: ProjectDetail, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter PUTs to actual changes so reconciliation is graph-revision stable."""
    current = {stage.stage_id: stage for stage in project.stages}
    changed = []
    for row in rows:
        old: AuditStage | None = current.get(row["stage_id"])
        if old is None or any(getattr(old, key) != row.get(key) for key in (
            "label", "phase_order", "required", "status", "capability", "skill_id", "run_id", "detail",
        )):
            changed.append(row)
    return changed
