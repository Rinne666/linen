"""Pure graph-derived orchestration for managed audits.

No queue or mutable audit state lives here.  Given the exported blackboard and
immutable artifacts, ``required_intents`` always derives the same missing graph
edges.  The dispatcher remains the only component that writes those edges.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from linen.dispatcher.analysis import audit_recipes, coverage, scope_gate, triage
from linen.dispatcher.analysis.artifacts import ancestor_ids, evidence_fields, load_artifact
from linen.dispatcher.analysis.external_scanners import scanner_specs
from linen.dispatcher.analysis.semgrep import digest, write_json
from linen.dispatcher.analysis.spring_scan import SPRING_SCAN_INTENT
from linen.dispatcher.config import AuditConfig
from linen.dispatcher.skills import skill_for_scanner
from linen.server.models import Fact, ProjectDetail


CREATOR = "dispatcher.audit"
AUDIT_SUMMARY_INTENT = "@analysis:audit-summary"


def managed_description(description: str) -> bool:
    value = description.strip()
    return (
        value.startswith("@analysis:")
        or value.startswith("@uvpg:proof:")
        or value.startswith(coverage.CELL_PREFIX)
        or value.startswith(triage.TRIAGE_PREFIX)
        or value.startswith(triage.VERIFY_PREFIX)
    )


def _open(project: ProjectDetail, description: str) -> bool:
    return any(
        intent.description.strip() == description
        and intent.to is None
        and intent.concluded_at is None
        for intent in project.intents
    )


def _intent(project: ProjectDetail, description: str):
    return next((intent for intent in project.intents if intent.description.strip() == description), None)


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


def _completed_sources(project: ProjectDetail, workdir: Path, fact_type: str) -> list[Fact]:
    result = []
    for fact in project.facts:
        if fact.type != fact_type:
            continue
        try:
            _, manifest = load_artifact(fact, workdir)
            if manifest.get("status") == "completed":
                result.append(fact)
        except (ValueError, OSError, KeyError, TypeError):
            continue
    return result


def _scanner_sources(
    project: ProjectDetail,
    workdir: Path,
    scanner_name: str,
    *,
    completed_only: bool = False,
) -> list[Fact]:
    result = []
    for fact in project.facts:
        if fact.type != "scan_batch":
            continue
        try:
            _, manifest = load_artifact(fact, workdir)
            if manifest.get("scanner", {}).get("name") != scanner_name:
                continue
            if completed_only and manifest.get("status") != "completed":
                continue
            result.append(fact)
        except (ValueError, OSError, KeyError, TypeError):
            recorded = evidence_fields(fact.evidence).get("scanner")
            legacy_semgrep = scanner_name == "semgrep" and fact.description.startswith("Semgrep scan ")
            if not completed_only and (recorded == scanner_name or legacy_semgrep):
                result.append(fact)
    return result


def _scanner_attempt_consumes_budget(fact: Fact, workdir: Path) -> bool:
    """Ignore records produced by the pre-execution SARIF adapter bug.

    Older Linen versions tried to open raw.sarif before persisting the process
    result. A real scanner failure was therefore recorded as a missing-file
    adapter error with a command but no execution object. Retrying those facts
    under the fixed adapter is safe and keeps existing projects recoverable.
    Configuration/preflight failures have no command and still consume budget.
    """
    try:
        _, manifest = load_artifact(fact, workdir)
    except (ValueError, OSError, KeyError, TypeError):
        return True
    return not (
        manifest.get("status") == "failed"
        and isinstance(manifest.get("command"), list)
        and "execution" not in manifest
    )


def _scanner_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
    anchor_fact_id: str,
) -> list[dict]:
    proposals = []
    for spec in scanner_specs(config):
        attempts = _scanner_sources(project, workdir, spec.name)
        budgeted_attempts = [
            fact for fact in attempts if _scanner_attempt_consumes_budget(fact, workdir)
        ]
        completed = _scanner_sources(project, workdir, spec.name, completed_only=True)
        max_attempts = spec.config.max_attempts
        if (not completed
                and len(budgeted_attempts) < max_attempts
                and (not attempts or _reviewed(project, attempts[-1].id))
                and not _open(project, spec.intent)):
            proposals.append({
                "from": [anchor_fact_id, *(fact.id for fact in attempts[-1:])],
                "type": "search",
                "description": spec.intent,
            })
    return proposals


def selectable_skill_choices(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[dict[str, Any]]:
    """Return pending, trusted scanner capabilities the model may select next.

    Applicability, retry budget, source anchors, and executable descriptions
    remain deterministic.  The LLM chooses only the next registry id/order.
    """
    if project.project.audit_mode == "hypothesis":
        anchor = "origin"
    elif project.project.audit_mode == "scope":
        plan = next((fact for fact in project.facts if fact.type == "coverage_plan"), None)
        if plan is None or not _reviewed(project, plan.id):
            return []
        anchor = plan.id
    else:
        return []
    proposals = _scanner_proposals(project, workdir, config, anchor)
    specs_by_intent = {spec.intent: spec for spec in scanner_specs(config)}
    choices: list[dict[str, Any]] = []
    for proposal in proposals:
        spec = specs_by_intent.get(proposal["description"])
        if spec is None:
            continue
        skill = skill_for_scanner(spec.name)
        choices.append({
            "skill_id": skill.id,
            "version": skill.version,
            "capability": skill.capability,
            "stage_id": skill.stage_id,
            "label": spec.label,
            "description": spec.intent,
            "from": list(proposal["from"]),
        })
    return choices


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
        all_reviews = sorted(
            reviews_by_fact.get(fact.id, []), key=lambda review: (review.created_at, review.id),
        )
        reviews = coverage.effective_reviews(project, fact.id)
        # Legacy coverage plans were accidentally sent through the vulnerability
        # review prompt.  Their rows remain visible, but one new attestation is
        # needed before the plan may fan out scanner, recipe, or coverage work.
        if (
            fact.type == "coverage_plan"
            and all_reviews
            and not reviews
            and fact.id not in open_reviews
        ):
            description = f"@analysis:review:{fact.id}:attestation"
            if not _proposal_exists(project, description):
                proposals.append({
                    "from": [fact.id],
                    "type": "review:devils-advocate",
                    "description": description,
                })
            continue
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
    return any(intent.description.strip() == description for intent in project.intents)


def _candidate_verify_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[dict]:
    proposals = []
    for triage_fact in project.facts:
        if triage_fact.type != "candidate_triage" or not _reviewed(project, triage_fact.id):
            continue
        record = triage.triage_record(triage_fact, workdir)
        source_id = record["source_fact_id"]
        for decision in record["decisions"]:
            if decision["outcome"] != "keep":
                continue
            fingerprint = decision["fingerprint"]
            terminal = triage.terminal_verification(project, source_id, fingerprint)
            if terminal is not None and _reviewed(project, terminal.id):
                continue
            attempts = triage.verification_attempts(project, source_id, fingerprint)
            if attempts:
                latest = attempts[-1]
                if latest.to is None and latest.concluded_at is None:
                    continue
                latest_fact = next((fact for fact in project.facts if fact.id == latest.to), None)
                if latest_fact is None or not _reviewed(project, latest_fact.id):
                    continue
                try:
                    outcome = json.loads(latest_fact.evidence or "").get("outcome")
                except (ValueError, TypeError):
                    outcome = None
                if outcome != "blocked" or len(attempts) >= config.triage.max_verify_attempts:
                    continue
                from_ids = [triage_fact.id, latest_fact.id]
            else:
                from_ids = [triage_fact.id]
            attempt = len(attempts) + 1
            description = triage.verify_description(source_id, fingerprint, attempt)
            if not _proposal_exists(project, description):
                proposals.append({
                    "from": from_ids,
                    "type": f"verify:{decision['category']}",
                    "description": description,
                })
    return proposals


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


def _scanner_summary_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[dict]:
    proposals = []
    for source in project.facts:
        if source.type not in triage.CANDIDATE_FACT_TYPES or not _reviewed(project, source.id):
            continue
        inputs = triage.scanner_summary_inputs(project, source, workdir, config.triage)
        description = triage.scanner_summary_description(source.id)
        if inputs is None or _proposal_exists(project, description):
            continue
        proposals.append({
            "from": [
                source.id,
                *(fact.id for fact in inputs["triage_facts"]),
                *(fact.id for fact in inputs["terminal_facts"]),
            ],
            "type": "synthesize",
            "description": description,
        })
    return proposals


def audit_summary_inputs(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[str] | None:
    try:
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
        scanner_ids = []
        expected_scanners = [
            *(
                fact
                for spec in scanner_specs(config)
                for fact in _scanner_sources(project, workdir, spec.name, completed_only=True)
            ),
            *_completed_sources(project, workdir, "route_scan"),
        ]
        for source in expected_scanners:
            fact = _result(project, triage.scanner_summary_description(source.id))
            if fact is None or fact.type != "module_summary" or not _reviewed(project, fact.id):
                return None
            scanner_ids.append(fact.id)
        if any(
            len(_scanner_sources(project, workdir, spec.name, completed_only=True)) != 1
            for spec in scanner_specs(config)
        ):
            return None
        if config.spring.enabled and not any(fact.type == "route_scan" for fact in expected_scanners):
            return None
        for source in expected_scanners:
            _, manifest = load_artifact(source, workdir)
            if manifest.get("snapshot", {}).get("id") != plan["snapshot"]["id"]:
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
        semantic_ids = []
        if config.semantic.enabled:
            semantic = _result(project, audit_recipes.SUMMARY_INTENT)
            if (
                semantic is None
                or semantic.type != "semantic_summary"
                or not _reviewed(project, semantic.id)
            ):
                return None
            semantic_ids.append(semantic.id)
        summary_ids = sorted(set(gate_ids + module_ids + scanner_ids + semantic_ids))
        if any(
            intent.to is None
            and intent.concluded_at is None
            and intent.description.strip() != AUDIT_SUMMARY_INTENT
            for intent in project.intents
        ):
            return None
        covered = ancestor_ids(project, summary_ids)
        extra_ids = []
        for fact in project.facts:
            if (fact.id in {"origin", "goal"} or fact.type in {"recon", "audit_summary"}
                    or fact.id in covered):
                continue
            if fact.status in {"false_positive", "fixed", "accepted_risk"}:
                continue
            if not _reviewed(project, fact.id):
                return None
            extra_ids.append(fact.id)
        return sorted(set(summary_ids + extra_ids))
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
        raise ValueError("Audit summary requires every reviewed coverage/scanner module summary")
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
            "The scope gate and configured coverage, scanner, and semantic recipe branches "
            "completed on frozen evidence; policy eligibility remains separate from technical "
            "exploitability and this is not proof of repository safety."
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
            "All configured coverage, scanner, and semantic recipe branches reached reviewed summaries; "
            "declared exclusions remain part of the evidence and this does not prove the repository safe."
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
    # Keep the entire gate ahead of unrelated legacy work. This is important
    # when enabling the gate on an active board whose ready window is already
    # full: collection, both attestations, and adjudication must still become
    # visible instead of waiting behind coverage or scanner branches.
    if (
        project.project.audit_mode == "scope"
        and config.scope_adjudication.enabled
    ):
        evidence = scope_gate.result_for_intent(project, scope_gate.EVIDENCE_INTENT)
        if evidence is None:
            if _proposal_exists(project, scope_gate.EVIDENCE_INTENT):
                return []
            return [{
                "from": ["origin"],
                "type": "search",
                "description": scope_gate.EVIDENCE_INTENT,
            }]
        if evidence.type != scope_gate.POLICY_EVIDENCE_TYPE:
            return []
        if not _reviewed(project, evidence.id):
            return [
                proposal for proposal in _review_proposals(project)
                if proposal["from"] == [evidence.id]
            ][:limit]
        adjudication = scope_gate.result_for_intent(
            project, scope_gate.ADJUDICATION_INTENT,
        )
        if adjudication is None:
            if _proposal_exists(project, scope_gate.ADJUDICATION_INTENT):
                return []
            return [{
                "from": [evidence.id],
                "type": "verify",
                "description": scope_gate.ADJUDICATION_INTENT,
            }]
        if adjudication.type != scope_gate.SCOPE_ADJUDICATION_TYPE:
            return []
        if not _reviewed(project, adjudication.id):
            return [
                proposal for proposal in _review_proposals(project)
                if proposal["from"] == [adjudication.id]
            ][:limit]
        try:
            scope_gate.adjudication_record(adjudication, workdir)
        except (ValueError, OSError, KeyError, TypeError):
            return []
        plan_anchor = adjudication.id
    reviews = _review_proposals(project)
    if reviews:
        return reviews[:limit]

    if project.project.audit_mode == "hypothesis":
        # Baseline execution order is selected by the cold AuditGraph model
        # from the trusted Skill registry. The deterministic Gate still
        # requires every configured stage and a validated receipt.
        return []

    proposals: list[dict] = []
    if not any(fact.type == "coverage_plan" for fact in project.facts) and not _open(project, coverage.PLAN_INTENT):
        proposals.append({"from": [plan_anchor], "type": "search", "description": coverage.PLAN_INTENT})
    if proposals:
        return proposals[:limit]

    plan_fact = next((fact for fact in project.facts if fact.type == "coverage_plan"), None)
    if plan_fact is None or not _reviewed(project, plan_fact.id):
        return []

    try:
        semantic_proposals = audit_recipes.recipe_proposals(
            project, workdir, config.semantic,
        )
        semantic_verifications = audit_recipes.verification_proposals(
            project, workdir, config.semantic,
        )
    except (ValueError, OSError, KeyError, TypeError):
        semantic_proposals = []
        semantic_verifications = []

    spring_attempts = [fact for fact in project.facts if fact.type == "route_scan"]
    if (config.spring.enabled and not _completed_sources(project, workdir, "route_scan")
            and len(spring_attempts) < config.spring.max_attempts
            and (not spring_attempts or _reviewed(project, spring_attempts[-1].id))
            and not _open(project, SPRING_SCAN_INTENT)):
        proposals.append({
            "from": [plan_fact.id, *(fact.id for fact in spring_attempts[-1:])],
            "type": "search",
            "description": SPRING_SCAN_INTENT,
        })
    proposals.extend(semantic_proposals)
    proposals.extend(semantic_verifications)
    if proposals:
        return proposals[:limit]

    # Scanner candidates are time-sensitive, high-signal branches. Triage
    # them before fanning out the much larger deterministic coverage grid.
    if config.triage.enabled:
        for source in project.facts:
            if source.type not in triage.CANDIDATE_FACT_TYPES or not _reviewed(project, source.id):
                continue
            try:
                for batch in triage.batches(source, workdir, config.triage):
                    if not _proposal_exists(project, batch["description"]):
                        proposals.append({
                            "from": [source.id], "type": "triage", "description": batch["description"],
                        })
            except (ValueError, OSError, KeyError, TypeError):
                pass
        proposals.extend(_candidate_verify_proposals(project, workdir, config))
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
                        proposals.append({"from": from_ids, "type": "verify", "description": row["description"]})
        except (ValueError, OSError, KeyError, TypeError):
            pass

    if proposals:
        return proposals[:limit]
    proposals.extend(_coverage_summary_proposals(project, workdir, config))
    if config.triage.enabled:
        proposals.extend(_scanner_summary_proposals(project, workdir, config))
    if config.semantic.enabled:
        semantic_summary = audit_recipes.summary_proposal(
            project, workdir, config.semantic,
        )
        if semantic_summary is not None:
            proposals.append(semantic_summary)
    if proposals:
        return proposals[:limit]
    inputs = audit_summary_inputs(project, workdir, config)
    if inputs is not None and not _proposal_exists(project, AUDIT_SUMMARY_INTENT):
        return [{"from": inputs, "type": "synthesize", "description": AUDIT_SUMMARY_INTENT}]
    return []


def scope_blockers(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
    from_ids: list[str],
) -> list[str]:
    blockers = coverage.scope_blockers(project, workdir, config.coverage, from_ids)
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
        blockers.append("Scope completion must reference a reviewed audit_summary fact.")
    elif not _reviewed(project, summary.id):
        blockers.append(f"{summary.id} requires a firm/certain VALID review.")
    for spec in scanner_specs(config):
        scans = _scanner_sources(project, workdir, spec.name, completed_only=True)
        if len(scans) != 1:
            attempts = len(_scanner_sources(project, workdir, spec.name))
            blockers.append(
                f"Scope audit requires one completed {spec.label} scan_batch "
                f"(attempts {attempts}/{spec.config.max_attempts})."
            )
        for fact in scans:
            try:
                _, manifest = load_artifact(fact, workdir)
                if manifest.get("status") != "completed":
                    blockers.append(
                        f"{spec.label} {fact.id} is {manifest.get('status')}; completed is required."
                    )
            except (ValueError, OSError, KeyError, TypeError) as exc:
                blockers.append(f"Invalid {spec.label} evidence {fact.id}: {exc}")
    if config.spring.enabled:
        routes = _completed_sources(project, workdir, "route_scan")
        if len(routes) != 1:
            attempts = len([fact for fact in project.facts if fact.type == "route_scan"])
            blockers.append(
                f"Scope audit requires one completed Spring route_scan (attempts {attempts}/{config.spring.max_attempts})."
            )
        for fact in routes:
            try:
                _, manifest = load_artifact(fact, workdir)
                if manifest.get("status") != "completed":
                    blockers.append(f"Spring route scan {fact.id} is not completed.")
            except (ValueError, OSError, KeyError, TypeError) as exc:
                blockers.append(f"Invalid Spring route evidence {fact.id}: {exc}")
    if config.semantic.enabled:
        semantic = next(
            (
                fact for fact in project.facts
                if fact.id in from_ids and fact.type == "semantic_summary"
            ),
            None,
        )
        if semantic is None:
            blockers.append(
                "Scope completion must reference the reviewed semantic recipe summary."
            )
        elif not _reviewed(project, semantic.id):
            blockers.append(f"{semantic.id} requires a firm/certain VALID review.")
        try:
            if audit_recipes.semantic_summary_inputs(
                project, workdir, config.semantic,
            ) is None:
                blockers.append(
                    "Semantic recipe hypotheses and variants have not reached reviewed dispositions."
                )
        except (ValueError, OSError, KeyError, TypeError) as exc:
            blockers.append(f"Invalid semantic recipe evidence: {exc}")
    if audit_summary_inputs(project, workdir, config) is None:
        blockers.append("Coverage/scanner branches have not reached reviewed module summaries.")
    return list(dict.fromkeys(blockers))
