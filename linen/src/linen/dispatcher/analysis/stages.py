"""Deterministic audit-stage projection.

Stages are a read-model of the blackboard, never a second queue.  This module
only derives rows; the scheduler is the sole caller that writes them through
the protocol client.  Re-running the derivation after a restart yields the
same stage ids and statuses for the same graph and artifact set.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from linen.dispatcher.analysis.artifacts import load_artifact
from linen.dispatcher.analysis import audit_recipes, coverage, recon, scope_gate
from linen.dispatcher.config import AuditConfig
from linen.server.models import AuditStage, Fact, Intent, ProjectDetail


@dataclass(frozen=True, slots=True)
class StageDefinition:
    stage_id: str
    label: str
    phase_order: int
    capability: str
    required: bool
    enabled: bool = True


def stage_definitions(config: AuditConfig, audit_mode: str) -> list[StageDefinition]:
    """Return the stable stage skeleton for one persisted audit profile."""
    if not config.enabled or audit_mode == "none":
        return []
    result: list[StageDefinition] = []
    if audit_mode == "scope":
        result.extend([
            StageDefinition("scope-evidence", "Scope evidence", 10, "scope.evidence", config.scope_adjudication.enabled, config.scope_adjudication.enabled),
            StageDefinition("scope-adjudication", "Scope adjudication", 20, "scope.adjudication", config.scope_adjudication.enabled, config.scope_adjudication.enabled),
        ])
    if audit_mode == "scope" and config.recon.enabled:
        result.append(StageDefinition("recon-snapshot", "Frozen source snapshot", 30, "recon.snapshot", True))
        result.extend(
            StageDefinition(
                f"recon-{category}", f"Recon: {category}", 40 + index,
                f"recon.{category}", True,
            )
            for index, category in enumerate(config.recon.categories)
        )
    elif audit_mode == "scope":
        result.append(StageDefinition("coverage-plan", "Coverage plan", 30, "coverage.plan", True))
    if audit_mode == "scope":
        result.append(StageDefinition("semantic-analysis", "Semantic analysis", 100, "semantic.analysis", config.semantic.enabled, config.semantic.enabled))
    if audit_mode == "scope":
        result.append(StageDefinition("audit-summary", "Audit summary", 110, "audit.summary", True))
    return result


def _intent(project: ProjectDetail, description: str) -> Intent | None:
    matches = [
        item for item in project.intents
        if item.description.strip() == description
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
    ]
    return max(matches, key=lambda item: (item.created_at, item.id), default=None)


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
    if not definition.enabled:
        return {
            "stage_id": definition.stage_id,
            "label": definition.label,
            "phase_order": definition.phase_order,
            "required": False,
            "status": "not_applicable",
            "capability": definition.capability,
            "detail": "Disabled in the persisted dispatcher configuration",
        }
    description = {
        "scope-evidence": scope_gate.EVIDENCE_INTENT,
        "scope-adjudication": scope_gate.ADJUDICATION_INTENT,
        "coverage-plan": coverage.PLAN_INTENT,
        "audit-summary": "@analysis:audit-summary",
        "semantic-analysis": "@analysis:audit-summary",
        "recon-snapshot": recon.SNAPSHOT_INTENT,
    }.get(definition.stage_id, None)
    if definition.stage_id.startswith("recon-") and definition.stage_id != "recon-snapshot":
        description = recon.category_description(definition.stage_id.removeprefix("recon-"))
    if description is None:
        description = f"@analysis:{definition.stage_id}"
    intent = _intent(project, description)
    fact = _fact(project, intent)
    status, _unused_run_id, detail = _result_status(intent, fact, workdir)
    if definition.stage_id.startswith("recon-") and definition.stage_id != "recon-snapshot":
        matches = [
            item for item in project.intents
            if recon.category_from_description(item.description) == definition.stage_id.removeprefix("recon-")
            and item.source_generation == project.project.source_generation
            and item.plan_revision == project.project.plan_revision
        ]
        latest = max(matches, key=lambda item: (item.created_at, item.id), default=None)
        intent = latest
        fact = _fact(project, latest)
        if fact is None:
            status = (
                "running" if latest and latest.worker else
                "failed" if latest and latest.concluded_at else "pending"
            )
            detail = "Latest reconnaissance attempt has no result Fact." if status == "failed" else None
        else:
            try:
                record = recon.result_record(fact, workdir)
                status = "satisfied" if record.get("status") == "complete" else "blocked"
                detail = record.get("summary") or "Recon coverage is partial."
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                status, detail = "failed", f"Invalid recon artifact: {exc}"
    if intent is not None:
        errors = [
            error for error in project.errors
            if error.intent_id == intent.id and error.resolved_at is None
        ]
        if errors:
            error = errors[-1]
            status = "blocked" if error.classification == "blocked" else "failed"
            detail = error.message
    return {
        "stage_id": definition.stage_id,
        "label": definition.label,
        "phase_order": definition.phase_order,
        "required": definition.required,
        "status": status,
        "capability": definition.capability,
        "detail": detail,
    }


def reconcile(config: AuditConfig, project: ProjectDetail, workdir: Path) -> list[dict[str, Any]]:
    """Derive mutable stage status while keeping a plan's obligations frozen.

    The first reconciliation for a (source_generation, plan_revision) records
    the stage set. Later dispatcher configuration changes may update status
    and detail, but cannot add, remove, or weaken obligations. Replanning is
    represented by a new plan_revision and therefore a new stage set.
    """
    if not config.enabled or project.project.audit_mode == "none":
        return []
    effective_config = config
    current_plan_fact_ids = {
        fact.id for fact in project.facts
        if fact.type == "coverage_plan"
        and fact.source_generation == project.project.source_generation
    }
    if config.recon.enabled and (
        any(
            intent.to in current_plan_fact_ids
            and intent.source_generation == project.project.source_generation
            and intent.plan_revision == project.project.plan_revision
            for intent in project.intents
        )
        or any(
            intent.description.strip() == coverage.PLAN_INTENT
            and intent.source_generation == project.project.source_generation
            and intent.plan_revision == project.project.plan_revision
            for intent in project.intents
        )
    ):
        # A project's first registered stage set is frozen. Keep legacy
        # coverage projects on that contract when a dispatcher is upgraded.
        effective_config = config.model_copy(update={
            "recon": config.recon.model_copy(update={"enabled": False}),
        })
    derived = [
        _definition_status(definition, effective_config, project, workdir)
        for definition in stage_definitions(effective_config, project.project.audit_mode)
    ]
    if not project.stages:
        return derived

    # Once any rows exist for the current generation/revision, their IDs and
    # obligation metadata are authoritative. Config-only stages are ignored;
    # persisted stages removed from config remain in the frozen set.
    definitions = {
        definition.stage_id: definition
        for definition in stage_definitions(effective_config, project.project.audit_mode)
    }
    by_id = {row["stage_id"]: row for row in derived}
    rows = []
    for stage in project.stages:
        definition = definitions.get(stage.stage_id)
        if definition is not None:
            # Current config controls first registration only. For an existing
            # plan, continue observing its frozen stage even if the matching
            # capability is now disabled in dispatcher config.
            definition = replace(definition, required=stage.required, enabled=True)
            row = _definition_status(definition, effective_config, project, workdir)
        else:
            row = by_id.get(stage.stage_id)
            if row is None and not stage.required:
                row = {
                    "status": "not_applicable",
                    "detail": "Retired stage is no longer implemented by this dispatcher.",
                }
        rows.append({
            "stage_id": stage.stage_id,
            "label": stage.label,
            "phase_order": stage.phase_order,
            "required": stage.required,
            "status": row["status"] if row is not None else stage.status,
            "capability": stage.capability,
            "detail": row["detail"] if row is not None else stage.detail,
        })
    return rows


def changed_rows(project: ProjectDetail, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter PUTs to actual changes so reconciliation is graph-revision stable."""
    current = {stage.stage_id: stage for stage in project.stages}
    changed = []
    for row in rows:
        old: AuditStage | None = current.get(row["stage_id"])
        if old is None or any(getattr(old, key) != row.get(key) for key in (
            "label", "phase_order", "required", "status", "capability", "detail",
        )):
            changed.append(row)
    return changed
