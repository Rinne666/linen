"""Shared dispatcher scope constraints for execution and strategy waiting."""

from __future__ import annotations

from linen.dispatcher.analysis import audit_graph, coverage, recon, scope_gate
from linen.dispatcher.config import AuditConfig
from linen.server.models import Intent, ProjectDetail


def scope_allows_intent(project: ProjectDetail, intent: Intent, config: AuditConfig) -> bool:
    if project.project.audit_mode != "scope" or not config.scope_adjudication.enabled:
        return True
    evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
    evidence_ready = bool(evidence and evidence.type == scope_gate.POLICY_EVIDENCE_TYPE and coverage.reviewed(project, evidence.id))
    if not evidence_ready and scope_gate.is_adjudication_intent(intent):
        return False
    adjudication = scope_gate.result_for_intent(project, scope_gate.ADJUDICATION_INTENT)
    scope_ready = bool(evidence_ready and adjudication and adjudication.type == scope_gate.SCOPE_ADJUDICATION_TYPE and coverage.reviewed(project, adjudication.id))
    needs_scope = (
        intent.description.strip() in {recon.SNAPSHOT_INTENT, recon.COVERAGE_REVIEW_INTENT, audit_graph.AUDIT_SUMMARY_INTENT}
        or recon.category_from_description(intent.description) is not None
    )
    return scope_ready or not needs_scope
