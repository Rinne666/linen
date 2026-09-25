"""Pure graph-derived orchestration for managed audits.

No queue or mutable audit state lives here.  Given the exported blackboard and
immutable artifacts, ``required_intents`` always derives the same missing graph
edges.  The dispatcher remains the only component that writes those edges.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from linen.dispatcher.analysis import audit_recipes, coverage, recon, scope_gate
from linen.dispatcher.analysis.artifacts import ancestor_ids, digest, write_json
from linen.dispatcher.config import AuditConfig
from linen.server.models import Fact, ProjectDetail, REVIEWLESS_INTERMEDIATE_FACT_TYPES
from linen.server.uvpg import REQUIRED_ROLES


CREATOR = "dispatcher.audit"
AUDIT_SUMMARY_INTENT = "@analysis:audit-summary"
MAX_STAGE_INTENT_ATTEMPTS = 3
def managed_description(description: str) -> bool:
    value = description.strip()
    return (
        value.startswith("@analysis:")
        or value.startswith("@uvpg:proof:")
        or value.startswith(coverage.CELL_PREFIX)
    )


def _open(project: ProjectDetail, description: str) -> bool:
    return any(
        intent.description.strip() == description
        and intent.source_generation == project.project.source_generation
        and intent.plan_revision == project.project.plan_revision
        and intent.to is None
        and intent.concluded_at is None
        for intent in project.intents
    )


def _intent(project: ProjectDetail, description: str):
    matches = [
        intent for intent in project.intents
        if intent.description.strip() == description
        and intent.source_generation == project.project.source_generation
        and intent.plan_revision == project.project.plan_revision
    ]
    return max(matches, key=lambda item: (item.created_at, item.id), default=None)


def _result(project: ProjectDetail, description: str) -> Fact | None:
    intent = _intent(project, description)
    if intent is None or not intent.to:
        return None
    return next((fact for fact in project.facts if fact.id == intent.to), None)


def _reviewed(project: ProjectDetail, fact_id: str) -> bool:
    return coverage.reviewed(project, fact_id)


def _has_unified_vulnerability_review(project: ProjectDetail, fact_id: str) -> bool:
    """Whether a candidate has the candidate-local proof attestation."""
    for review in project.reviews:
        if review.fact_id != fact_id:
            continue
        diagnostics = review.cold_verification or {}
        if (
            diagnostics.get("review_kind") == "vulnerability_proof"
            and diagnostics.get("candidate_id") == fact_id
            and review.verdict == "VALID"
            and review.confidence in {"firm", "certain"}
        ):
            return True
    return False


def _review_proposals(project: ProjectDetail) -> list[dict]:
    proposals = []
    open_reviews = {
        intent.from_[0]
        for intent in project.intents
        if intent.from_
        and (intent.type or "").startswith("review")
        and intent.to is None
        and intent.concluded_at is None
    }
    reviews_by_fact: dict[str, list] = {}
    for review in project.reviews:
        reviews_by_fact.setdefault(review.fact_id, []).append(review)
    prior_modes: dict[str, set[str]] = {}
    for intent in project.intents:
        if len(intent.from_) == 1 and (intent.type or "").startswith("review"):
            prior_modes.setdefault(intent.from_[0], set()).add(intent.type or "review")
    for fact in project.facts:
        if fact.id in {"origin", "goal"} or fact.type == "recon":
            continue
        if fact.type in REVIEWLESS_INTERMEDIATE_FACT_TYPES:
            continue
        if not (
            fact.type in {
                "coverage_result", "policy_evidence", "scope_adjudication", "vulnerability",
            }
            or fact.semantic_type in {
                "candidate_finding", "confirmed_finding", "rejected_finding",
            }
        ):
            continue
        all_reviews = sorted(
            reviews_by_fact.get(fact.id, []), key=lambda review: (review.created_at, review.id),
        )
        reviews = coverage.effective_reviews(project, fact.id)
        if (
            fact.type == "vulnerability"
            and fact.semantic_type == "candidate_finding"
            and not _has_unified_vulnerability_review(project, fact.id)
            and fact.id not in open_reviews
        ):
            description = f"@analysis:review:{fact.id}:vulnerability-proof"
            if not _proposal_exists(project, description):
                proposals.append({
                    "from": [fact.id],
                    "type": "review:cold-verifier",
                    "description": description,
                })
            continue
        if fact.status in {"false_positive", "fixed", "accepted_risk"} or fact.id in open_reviews:
            continue
        # UVPG proof atoms are inputs to the candidate-local proof-package
        # review.  Do not create a second, generic per-Fact review path for
        # them; derive_proof_gaps() retains the legacy targeted fallback.
        if fact.proof is not None and fact.proof.claim_kind in REQUIRED_ROLES:
            continue
        if not reviews and fact.status == "draft":
            mode = "cold-verifier" if fact.type == "vulnerability" else "devils-advocate"
            proposals.append({
                "from": [fact.id],
                "type": f"review:{mode}",
                "description": f"@analysis:review:{fact.id}",
            })
            continue
        if not reviews or _reviewed(project, fact.id) or len(reviews) >= 2:
            continue
        modes = prior_modes.get(fact.id, set())
        if any(review.verdict == "NEEDS_REVIEW" for review in reviews):
            mode = "contradiction-reasoner"
        else:
            mode = "cold-verifier"
        review_type = f"review:{mode}"
        if review_type not in modes:
            proposals.append({
                "from": [fact.id],
                "type": review_type,
                "description": f"@analysis:review:{fact.id}:{mode}",
            })
    return proposals


def _proposal_exists(project: ProjectDetail, description: str) -> bool:
    return _open(project, description)


def _stage_intent_proposal(
    project: ProjectDetail,
    from_ids: list[str],
    intent_type: str,
    description: str,
) -> dict | None:
    """Return a bounded, idempotent retry for a stage with no result Fact.

    A concluded intent without a result must not permanently satisfy the
    existence check. Each replacement gets a distinct target, while an open
    attempt remains the single owner of that stage obligation.
    """
    if _open(project, description):
        return None
    prior = [
        item for item in project.intents
        if item.description.strip() == description
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
    ]
    if len(prior) >= MAX_STAGE_INTENT_ATTEMPTS:
        return None
    attempt = len(prior) + 1
    historical = any(
        item.description.strip() == description for item in project.intents
    )
    if attempt == 1 and not historical:
        target = description
    else:
        target = (
            f"{description}:generation:{project.project.source_generation}"
            f":plan:{project.project.plan_revision}:attempt:{attempt}"
        )
    return {
        "from": from_ids,
        "type": intent_type,
        "description": description,
        "target": target,
    }


def _coverage_summary_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[dict]:
    proposals = []
    for group in coverage.module_summary_groups(project, workdir, config.coverage):
        if not _proposal_exists(project, group["description"]):
            proposals.append({
                "from": [group["plan_fact_id"], *group["result_ids"]],
                "type": "synthesize",
                "description": group["description"],
            })
    return proposals


def audit_summary_inputs(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[str] | None:
    try:
        recon_mode = recon.active_for_project(project, config.recon)
        if recon_mode:
            unresolved_work = [
                intent for intent in project.intents
                if intent.source_generation == project.project.source_generation
                and intent.plan_revision == project.project.plan_revision
                and intent.to is None
                and intent.concluded_at is None
                and intent.description.strip() != AUDIT_SUMMARY_INTENT
            ]
            if unresolved_work:
                return None
            plan_fact = recon.snapshot_fact(project)
            if plan_fact is None:
                return None
            snapshot_record = recon.result_record(plan_fact, workdir)
            if snapshot_record.get("kind") != "recon_snapshot":
                return None
            category_facts = recon.expected_category_facts(project, config.recon)
            if category_facts is None:
                return None
            for fact in category_facts:
                record = recon.result_record(fact, workdir)
                if record.get("kind") != "category_reconnaissance" or record.get("status") != "complete":
                    return None
            module_ids = [plan_fact.id, *(fact.id for fact in category_facts)]
        else:
            plan_fact, _, plan = coverage.get_plan(project, workdir)
            expected_modules = {cell["module"] for cell in plan["cells"]}
            module_ids = []
            for group in coverage.module_summary_groups(project, workdir, config.coverage):
                fact = _result(project, group["description"])
                if fact is None or fact.type != "module_summary" or not _reviewed(project, fact.id):
                    return None
                module_ids.append(fact.id)
            if len(module_ids) != len(expected_modules) or not _reviewed(project, plan_fact.id):
                return None
        gate_ids = []
        if config.scope_adjudication.enabled:
            adjudication = scope_gate.result_for_intent(
                project, scope_gate.ADJUDICATION_INTENT,
            )
            if (
                adjudication is None
                or adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE
                or not _reviewed(project, adjudication.id)
            ):
                return None
            scope_gate.adjudication_record(adjudication, workdir)
            gate_ids.append(adjudication.id)
        required_ids = set(gate_ids + module_ids)
        for fact in project.facts:
            if fact.id in {"origin", "goal"} or fact.type == "audit_summary":
                continue
            if recon_mode and fact.id in module_ids:
                continue
            if fact.status in {"false_positive", "fixed", "accepted_risk"}:
                continue
            if not (
                fact.type == "vulnerability"
                or fact.semantic_type in {
                    "candidate_finding", "confirmed_finding", "rejected_finding",
                }
            ):
                continue
            if not _reviewed(project, fact.id):
                return None
            required_ids.add(fact.id)
        return sorted(required_ids)
    except (ValueError, OSError, KeyError, TypeError):
        return None


def audit_summary_fact(
    project: ProjectDetail,
    intent,
    workdir: Path,
    config: AuditConfig,
) -> dict[str, str]:
    inputs = audit_summary_inputs(project, workdir, config)
    if (intent.description.strip() != AUDIT_SUMMARY_INTENT or (intent.type or "") != "synthesize"
        or inputs is None or set(intent.from_) != set(inputs)):
        raise ValueError("Audit summary requires every validated reconnaissance or coverage result")
    vulnerabilities = [
        fact.id for fact in project.facts
        if fact.type == "vulnerability" and fact.status == "triaged" and _reviewed(project, fact.id)
        and fact.id in ancestor_ids(project, inputs)
    ]
    record = {
        "schema_version": 1,
        "kind": "scope_audit_summary",
        "input_fact_ids": inputs,
        "confirmed_vulnerability_ids": sorted(vulnerabilities),
        "statement": (
            ("The scope gate and configured category reconnaissance branches completed on "
             if recon.active_for_project(project, config.recon) else "The scope gate and required coverage branches completed on ")
            + "frozen evidence. Policy eligibility remains separate from technical exploitability."
        ),
    }
    directory = workdir / ".linen-analysis" / ("audit-summary-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    path = directory / "audit-summary.json"
    write_json(path, record)
    return {
        "type": "audit_summary",
        "description": (
            f"Scope audit synthesis completed with {len(vulnerabilities)} confirmed vulnerabilities. "
            + ("All configured category reconnaissance branches completed. "
               if recon.active_for_project(project, config.recon) else "All required coverage branches reached validated summaries. ")
            + "This does not prove the repository universally safe."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            "status: completed"
        ),
    }


def required_intents(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
    *,
    limit: int = 8,
) -> list[dict]:
    """Derive missing graph edges in stable priority order."""
    if not config.enabled or project.project.audit_mode == "none":
        return []
    plan_anchor = "origin"
    # Keep policy collection and adjudication high in the ready window, while
    # allowing independent technical work to proceed if these bounded stages
    # cannot produce a reviewed result. Final reporting remains scope-gated.
    if (
        project.project.audit_mode == "scope"
        and config.scope_adjudication.enabled
    ):
        evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
        if evidence is None or evidence.type != scope_gate.POLICY_EVIDENCE_TYPE:
            proposal = _stage_intent_proposal(
                project, ["origin"], "search", scope_gate.EVIDENCE_INTENT,
            )
            if proposal is not None:
                return [proposal]
            # Exhausted scope collection remains a final-report blocker, but
            # it must not prevent source-grounded technical exploration.
            plan_anchor = "origin"
        else:
            if not _reviewed(project, evidence.id):
                review_proposals = [
                    proposal for proposal in _review_proposals(project)
                    if proposal["from"] == [evidence.id]
                ][:limit]
                if review_proposals:
                    return review_proposals
            adjudication = scope_gate.result_for_intent(
                project, scope_gate.ADJUDICATION_INTENT,
            )
            if adjudication is None or adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE:
                proposal = _stage_intent_proposal(
                    project, [evidence.id], "verify", scope_gate.ADJUDICATION_INTENT,
                )
                if proposal is not None:
                    return [proposal]
                # Keep policy uncertainty explicit and continue coverage.
                plan_anchor = evidence.id
            elif not _reviewed(project, adjudication.id):
                review_proposals = [
                    proposal for proposal in _review_proposals(project)
                    if proposal["from"] == [adjudication.id]
                ][:limit]
                if review_proposals:
                    return review_proposals
                plan_anchor = evidence.id
            else:
                try:
                    scope_gate.adjudication_record(adjudication, workdir)
                except (ValueError, OSError, KeyError, TypeError):
                    # Invalid adjudication is a reportability blocker, not a
                    # reason to stop independent source analysis.
                    plan_anchor = evidence.id
                else:
                    plan_anchor = adjudication.id
    reviews = _review_proposals(project)
    if reviews:
        return reviews[:limit]

    if project.project.audit_mode == "hypothesis":
        # Baseline execution is selected by the unified Reason loop from the
        # trusted Skill registry. The deterministic gate still requires every
        # configured stage and a validated receipt.
        return []

    if recon.active_for_project(project, config.recon):
        snapshot = recon.snapshot_fact(project)
        if snapshot is None:
            proposal = _stage_intent_proposal(
                project, [plan_anchor], "search", recon.SNAPSHOT_INTENT,
            )
            return [proposal] if proposal is not None else []
        for category in config.recon.categories:
            if recon.latest_category_fact(project, category) is not None:
                continue
            description = recon.category_description(category)
            category_attempted = any(
                intent.description.strip() == description
                and intent.source_generation == project.project.source_generation
                and intent.plan_revision == project.project.plan_revision
                for intent in project.intents
            )
            if not category_attempted:
                return [{
                    "from": [snapshot.id],
                    "type": "search",
                    "description": description,
                }]
        # The high-level Reason worker owns decisions about partial searches
        # and targeted follow-ups. Never expand them into per-file cells.
        inputs = audit_summary_inputs(project, workdir, config)
        if inputs is not None:
            proposal = _stage_intent_proposal(
                project, inputs, "synthesize", AUDIT_SUMMARY_INTENT,
            )
            return [proposal] if proposal is not None else []
        return []

    proposals: list[dict] = []
    if not any(fact.type == "coverage_plan" for fact in project.facts):
        proposal = _stage_intent_proposal(
            project, [plan_anchor], "search", coverage.PLAN_INTENT,
        )
        if proposal is not None:
            proposals.append(proposal)
    if proposals:
        return proposals[:limit]

    plan_fact = next((fact for fact in project.facts if fact.type == "coverage_plan"), None)
    if plan_fact is None or not _reviewed(project, plan_fact.id):
        return []

    try:
        semantic_verifications = audit_recipes.verification_proposals(
            project, workdir, config.semantic,
        )
    except (ValueError, OSError, KeyError, TypeError):
        semantic_verifications = []

    proposals.extend(semantic_verifications)
    if proposals:
        return proposals[:limit]

    plan = plan_fact
    if plan is not None and _reviewed(project, plan.id):
        try:
            state = coverage.coverage_state(project, workdir, config.coverage)
            for row in state["cells"]:
                if row["status"] in {"pending", "blocked", "invalid", "needs_followup"} and not row["retry_exhausted"]:
                    from_ids = [state["plan_fact_id"]]
                    if row["result_id"]:
                        result = next((fact for fact in project.facts if fact.id == row["result_id"]), None)
                        if result is None or not coverage.review_resolved(project, result.id):
                            continue
                        from_ids.append(result.id)
                    if not _open(project, row["description"]):
                        attempt_anchor = row["result_id"] or "initial"
                        proposals.append({
                            "from": from_ids,
                            "type": "verify",
                            "description": row["description"],
                            "target": f"{row['description']}:attempt:{attempt_anchor}",
                        })
        except (ValueError, OSError, KeyError, TypeError):
            pass

    if proposals:
        return proposals[:limit]
    proposals.extend(_coverage_summary_proposals(project, workdir, config))
    if proposals:
        return proposals[:limit]
    inputs = audit_summary_inputs(project, workdir, config)
    if inputs is not None:
        proposal = _stage_intent_proposal(
            project, inputs, "synthesize", AUDIT_SUMMARY_INTENT,
        )
        if proposal is not None:
            return [proposal]
    return []


def scope_blockers(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
    from_ids: list[str],
) -> list[str]:
    recon_mode = recon.active_for_project(project, config.recon)
    blockers = [] if recon_mode else coverage.scope_blockers(
        project, workdir, config.coverage, from_ids,
    )
    if config.scope_adjudication.enabled:
        evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
        adjudication = scope_gate.result_for_intent(
            project, scope_gate.ADJUDICATION_INTENT,
        )
        if evidence is None or evidence.type != scope_gate.POLICY_EVIDENCE_TYPE:
            blockers.append("Scope completion requires a policy_evidence Fact.")
        elif not _reviewed(project, evidence.id):
            blockers.append(f"{evidence.id} requires a firm/certain VALID review.")
        if adjudication is None or adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE:
            blockers.append("Scope completion requires a scope_adjudication Fact.")
        elif not _reviewed(project, adjudication.id):
            blockers.append(f"{adjudication.id} requires a firm/certain VALID review.")
        else:
            try:
                scope_gate.adjudication_record(adjudication, workdir)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                blockers.append(f"Invalid scope adjudication evidence {adjudication.id}: {exc}")
    summary = next((fact for fact in project.facts if fact.id in from_ids and fact.type == "audit_summary"), None)
    if summary is None:
        blockers.append("Scope completion must reference a validated audit_summary fact.")
    elif not _reviewed(project, summary.id):
        blockers.append(f"{summary.id} requires a firm/certain VALID review.")
    if audit_summary_inputs(project, workdir, config) is None:
        blockers.append(
            "Configured reconnaissance branches have not produced complete validated results."
            if recon_mode else "Coverage branches have not reached validated module summaries."
        )
    return list(dict.fromkeys(blockers))
