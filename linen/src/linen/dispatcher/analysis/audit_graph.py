"""Pure graph-derived orchestration for managed audits.

No queue or mutable audit state lives here.  Given the exported blackboard and
immutable artifacts, ``required_intents`` always derives the same missing graph
edges.  The dispatcher remains the only component that writes those edges.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from linen.dispatcher.analysis import codeql, coverage, recon, scope_gate
from linen.dispatcher.analysis.artifacts import ancestor_ids, digest, write_json
from linen.dispatcher.config import AuditConfig
from linen.server.models import Fact, ProjectDetail, REVIEWLESS_INTERMEDIATE_FACT_TYPES
from linen.server.uvpg import PROOF_GATE_VERSION, REQUIRED_ROLES


CREATOR = "dispatcher.audit"
AUDIT_SUMMARY_INTENT = "@analysis:audit-summary"
MAX_STAGE_INTENT_ATTEMPTS = 4
def managed_description(description: str) -> bool:
    value = description.strip()
    return (
        value.startswith("@analysis:")
        or value.startswith("@uvpg:proof:")
    )


def _open(project: ProjectDetail, description: str) -> bool:
    return any(
        (
            intent.description.strip() == description
            or intent.description.strip().startswith(description + ":generation:")
        )
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


def _reviewed(project: ProjectDetail, fact_id: str) -> bool:
    return coverage.reviewed(project, fact_id)


def _technical_confirmation(project: ProjectDetail, fact: Fact) -> bool:
    """Whether the server promoted this finding through the current proof gate."""
    proof = fact.proof
    if (
        fact.semantic_type != "confirmed_finding"
        or fact.type != "vulnerability"
        or fact.status != "triaged"
        or proof is None
        or proof.claim_kind != "confirmed_finding"
        or proof.attributes.get("gate_version") != PROOF_GATE_VERSION
    ):
        return False
    candidate_id = proof.attributes.get("candidate_id")
    fingerprint = proof.attributes.get("proof_graph_sha256")
    candidate = next((item for item in project.facts if item.id == candidate_id), None)
    return bool(
        isinstance(candidate_id, str)
        and fact.source_generation == project.project.source_generation
        and candidate is not None
        and candidate.type == "vulnerability"
        and candidate.semantic_type == "candidate_finding"
        and candidate.source_generation == fact.source_generation
        and candidate_id in proof.subject_ids
        and isinstance(fingerprint, str)
        and len(fingerprint) == 64
        and all(char in "0123456789abcdef" for char in fingerprint)
        and any(
            edge.source_kind == "fact"
            and edge.target_kind == "fact"
            and edge.source_id == candidate_id
            and edge.target_id == fact.id
            and edge.relation_type == "promotes_to"
            and edge.source_generation == fact.source_generation
            for edge in project.edges
        )
    )


def _summary_dispositioned(project: ProjectDetail, fact: Fact) -> bool:
    """Whether a follow-up Fact can safely be a parent of the final summary."""
    if (
        fact.status == "triaged"
        and fact.type in REVIEWLESS_INTERMEDIATE_FACT_TYPES
        and fact.evidence
        and fact.evidence.strip()
    ):
        return True
    reviews = coverage.effective_reviews(project, fact.id)
    latest = reviews[-1] if reviews else None
    return bool(
        fact.evidence
        and fact.evidence.strip()
        and latest
        and latest.confidence in {"firm", "certain"}
        and (
            latest.verdict == "VALID"
            or (fact.status == "false_positive" and latest.verdict == "INVALID")
        )
    )


def _external_feedback_fact_ids(project: ProjectDetail) -> set[str]:
    """External reopen notes guide orchestration; they are not source evidence."""
    return {
        intent.to for intent in project.intents
        if intent.description.strip() == "external_feedback" and intent.to
    }


def _unresolved_followups(project: ProjectDetail, input_ids: list[str]) -> list[dict]:
    """Retain inconclusive descendants in the report without treating them as findings."""
    input_id_set = set(input_ids)
    feedback_ids = _external_feedback_fact_ids(project)
    unresolved = []
    for fact in project.facts:
        if (
            fact.id in {"origin", "goal"}
            or fact.id in input_id_set
            or fact.id in feedback_ids
            or fact.type == "audit_summary"
            or _technical_confirmation(project, fact)
            or not (ancestor_ids(project, [fact.id]) & input_id_set)
            or _summary_dispositioned(project, fact)
        ):
            continue
        reviews = sorted(
            (review for review in project.reviews if review.fact_id == fact.id),
            key=lambda review: (review.created_at, review.id),
        )
        parents = [
            {"intent_id": intent.id, "fact_ids": list(intent.from_)}
            for intent in project.intents if intent.to == fact.id
        ]
        unresolved.append({
            "fact_id": fact.id,
            "type": fact.type,
            "semantic_type": fact.semantic_type,
            "status": fact.status,
            "description": fact.description,
            "evidence": fact.evidence,
            "source_intents": parents,
            "reviews": [
                {
                    "verdict": review.verdict,
                    "confidence": review.confidence,
                    "summary": review.summary,
                }
                for review in reviews
            ],
            "disposition": "unresolved; retained as uncertainty, not a confirmed finding",
        })
    return sorted(unresolved, key=lambda item: item["fact_id"])


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
                # Repository-wide recon follow-ups are source-grounded claims
                # that can feed the final summary. They are intentionally not
                # candidate findings, but the evidence chain still requires an
                # independent disposition before the summary can be committed.
                "reachability", "dataflow", "validation",
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
        if not reviews or _reviewed(project, fact.id):
            continue
        modes = prior_modes.get(fact.id, set())
        review_text = "\n".join(
            f"{review.summary}\n{review.reasoning or ''}" for review in all_reviews
        ).lower()
        source_text_missing = any(
            marker in review_text
            for marker in (
                "source files are absent",
                "source unavailable",
                "source files unavailable",
                "no source text",
                "could not inspect source",
                "could not verify the code",
            )
        )
        # A bounded third opinion is allowed only when both prior reviews
        # were inconclusive because the projection omitted cited source text.
        # The cold verifier receives an explicit read-only source-inspection
        # instruction; ordinary disagreements still stop at two reviews.
        if len(reviews) >= 2:
            if not source_text_missing or len(reviews) >= 3 or "review:cold-verifier" in modes:
                continue
            mode = "cold-verifier"
        elif any(review.verdict == "NEEDS_REVIEW" for review in reviews):
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
    """Return an idempotent stage attempt, retrying only when work is missing.

    A result for the same inputs is terminal. A concluded intent without a
    result must not permanently satisfy the existence check, while changed
    graph inputs may legitimately require a refreshed result. The retry cap
    applies to attempts that produced no result Fact; an open attempt remains
    the single owner of that stage obligation.
    """
    if _open(project, description):
        return None
    prior = [
        item for item in project.intents
        if (
            item.description.strip() == description
            or item.description.strip().startswith(description + ":generation:")
        )
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
    ]
    result_fact_ids = {fact.id for fact in project.facts}
    if any(
        item.to in result_fact_ids and item.from_ == from_ids
        for item in prior
    ):
        return None
    attempts_without_result = sum(
        item.to not in result_fact_ids for item in prior
    )
    if attempts_without_result >= MAX_STAGE_INTENT_ATTEMPTS:
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


def _recon_coverage_ready(project: ProjectDetail, workdir: Path, config: AuditConfig) -> bool:
    """Whether configured and Reason-discovered Recon lenses reached bounded terminal states."""
    try:
        categories = recon.expected_category_facts(project, config.recon)
        if categories is None:
            return False
        for fact in categories:
            record = recon.result_record(fact, workdir)
            if record.get("kind") != "category_reconnaissance":
                return False
            if record.get("status") == "complete":
                continue
            category = next((
                recon.category_from_description(intent.description)
                for intent in project.intents if intent.to == fact.id
            ), None)
            runs = sum(
                1 for intent in project.intents
                if recon.category_from_description(intent.description) == category
                and intent.source_generation == project.project.source_generation
                and intent.plan_revision == project.project.plan_revision
            )
            if not (
                record.get("status") == "partial"
                and category is not None
                and runs >= config.recon.max_runs_per_category
                and isinstance(record.get("gaps"), list)
                and record["gaps"]
            ):
                return False
        if codeql.active_for_project(project, config.codeql):
            machine_fact = codeql.latest_fact(project)
            if machine_fact is None:
                return False
            machine_record = codeql.result_record(machine_fact, workdir)
            if machine_record.get("status") != "complete":
                return False
        return True
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        return False


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
            blindspot_fact = recon.coverage_review_fact(project)
            if blindspot_fact is None or blindspot_fact.type != recon.COVERAGE_REVIEW_FACT_TYPE:
                return None
            blindspot_record = recon.coverage_review_record(blindspot_fact, workdir)
            review_categories = {
                item.get("category") for item in blindspot_record.get("items", [])
                if item.get("disposition") == "recon" and isinstance(item.get("category"), str)
            }
            category_facts = recon.expected_category_facts(
                project, config.recon, allow_missing_categories=review_categories,
            )
            if category_facts is None:
                return None
            for fact in category_facts:
                record = recon.result_record(fact, workdir)
                if record.get("kind") != "category_reconnaissance":
                    return None
                if record.get("status") == "complete":
                    continue
                category = next((
                    recon.category_from_description(intent.description)
                    for intent in project.intents
                    if intent.to == fact.id
                ), None)
                category_runs = sum(
                    1 for intent in project.intents
                    if recon.category_from_description(intent.description) == category
                    and intent.source_generation == project.project.source_generation
                    and intent.plan_revision == project.project.plan_revision
                )
                # Recon's bounded contract says a partial result at the run
                # cap is reportable as an explicit residual gap. Requiring
                # `complete` here made that documented outcome impossible to
                # summarize and permanently blocked otherwise-finished audits.
                if not (
                    record.get("status") == "partial"
                    and category is not None
                    and category_runs >= config.recon.max_runs_per_category
                    and isinstance(record.get("gaps"), list)
                    and record["gaps"]
                ):
                    return None
            if (
                blindspot_record.get("snapshot_fact_id") != plan_fact.id
                or not set(blindspot_record.get("input_fact_ids", [])) <= ({
                    fact.id for fact in project.facts
                    if fact.type in {"recon", recon.COVERAGE_REVIEW_FACT_TYPE}
                } | {plan_fact.id})
            ):
                return None
            module_ids = [plan_fact.id, *(fact.id for fact in category_facts), blindspot_fact.id]
            if codeql.active_for_project(project, config.codeql):
                machine_fact = codeql.latest_fact(project)
                if machine_fact is None:
                    return None
                machine_record = codeql.result_record(machine_fact, workdir)
                if (
                    machine_record.get("status") != "complete"
                    or machine_record.get("snapshot_id") != snapshot_record["snapshot"]["id"]
                ):
                    return None
                module_ids.append(machine_fact.id)
                module_ids.extend(fact.id for _category, fact in codeql.query_results(project))
        else:
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
        module_id_set = set(module_ids)
        external_feedback_ids = _external_feedback_fact_ids(project)
        # Include terminal follow-up evidence descended from the configured
        # reconnaissance branches. This makes the summary's evidence chain
        # cover validated graph-level verification work, not just initial leads.
        # Inconclusive observations remain in the immutable summary artifact
        # as residual uncertainty, but do not become unsupported ancestors of
        # the terminal Fact. Reopen feedback is orchestration context, not code
        # evidence, and must never be required to pass the source-review gate.
        for fact in project.facts:
            if (
                fact.id in {"origin", "goal"}
                or fact.id in external_feedback_ids
                or fact.type == "audit_summary"
            ):
                continue
            if (
                ancestor_ids(project, [fact.id]) & module_id_set
                and _summary_dispositioned(project, fact)
            ):
                required_ids.add(fact.id)
        for fact in project.facts:
            if fact.id in {"origin", "goal"} or fact.type == "audit_summary":
                continue
            if recon_mode and fact.id in module_ids:
                continue
            if fact.status in {"false_positive", "fixed", "accepted_risk"}:
                continue
            if fact.semantic_type == "confirmed_finding":
                if not _technical_confirmation(project, fact):
                    return None
                required_ids.add(fact.id)
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
        raise ValueError("Audit summary requires every validated reconnaissance result")
    vulnerabilities = [
        fact.id for fact in project.facts
        if _technical_confirmation(project, fact)
        and fact.id in inputs
    ]
    unresolved_followups = _unresolved_followups(project, inputs)
    blindspot_fact = recon.coverage_review_fact(project)
    blindspot_record = recon.coverage_review_record(blindspot_fact, workdir) if blindspot_fact else {}
    review_categories = {
        item.get("category") for item in blindspot_record.get("items", [])
        if item.get("disposition") == "recon" and isinstance(item.get("category"), str)
    }
    category_facts = recon.expected_category_facts(
        project, config.recon, allow_missing_categories=review_categories,
    )
    categories = []
    for fact in category_facts or []:
        record = recon.result_record(fact, workdir)
        category = next((
            recon.category_from_description(intent.description)
            for intent in project.intents
            if intent.to == fact.id
        ), "unknown")
        categories.append({
            "category": category,
            "status": record.get("status"),
            "summary": record.get("summary"),
            "gaps": list(record.get("gaps", [])),
            "coverage_dimensions": record.get("coverage_dimensions", {}),
            # Keep partial-scan leads visible as hypotheses even when a
            # follow-up narrowed them; they must not disappear into a
            # zero-finding summary.
            "leads": [
                {
                    "title": lead.get("title"),
                    "hypothesis": lead.get("hypothesis"),
                    "source": lead.get("source"),
                    "sink": lead.get("sink"),
                    "path": lead.get("path", []),
                    "citations": lead.get("citations", lead.get("citation_ids", [])),
                    "missing_evidence": lead.get("missing_evidence", []),
                    "next_step": lead.get("next_step"),
                    "security_checks": lead.get("security_checks", {}),
                }
                for lead in record.get("leads", [])
            ],
        })
    partial_categories = [item for item in categories if item["status"] == "partial"]
    residual_gaps = [
        {"category": item["category"], "gap": gap}
        for item in categories for gap in item["gaps"]
    ]
    for item in categories:
        for uncovered in item.get("coverage_dimensions", {}).get("uncovered_items", []):
            if uncovered.get("status") == "unresolved":
                residual_gaps.append({
                    "category": item["category"],
                    "gap": f"{uncovered.get('item')}: {uncovered.get('rationale')}",
                })
    blindspot_gaps = []
    if blindspot_record:
        for item in blindspot_record.get("items", []):
            if item.get("disposition") == "residual_gap":
                blindspot_gaps.append({
                    "category": "coverage-blindspot-review",
                    "gap": f"{item.get('description')}: {item.get('rationale')}",
                })
                continue
            category, subject = item.get("category"), item.get("subject") or None
            review_item_id = item.get("id")
            description = recon.category_description(category, subject)
            matching = sorted([
                candidate for candidate in project.intents
                if candidate.description.strip() == description
                and candidate.source_generation == project.project.source_generation
                and candidate.plan_revision == project.project.plan_revision
            ], key=lambda candidate: (candidate.created_at, candidate.id), reverse=True)
            resolution = None
            for candidate in matching:
                result_fact = next((
                    fact for fact in project.facts
                    if candidate.to == fact.id and fact.type == "recon"
                ), None)
                if result_fact is None:
                    continue
                try:
                    recon_record = recon.result_record(result_fact, workdir)
                except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                    continue
                resolution = next((
                    resolution_item for resolution_item in recon_record.get(
                        "coverage_review_resolutions", [],
                    ) if resolution_item.get("item_id") == review_item_id
                ), None)
                if resolution is not None:
                    break
            handled = resolution is not None and resolution.get("status") == "addressed"
            if not handled:
                reason = (
                    resolution.get("rationale") if resolution is not None
                    else "Recon did not confirm that this specific omission was addressed"
                )
                blindspot_gaps.append({
                    "category": category,
                    "gap": f"{item.get('description')}: {reason} "
                           "(retained as a residual coverage gap)",
                })
    residual_gaps.extend(blindspot_gaps)
    residual_gaps.extend(
        {
            "category": "unresolved-follow-up",
            "gap": (
                f"{item['fact_id']} has no firm/certain VALID disposition; "
                "its evidence and review history are retained as uncertainty, not a confirmed finding"
            ),
        }
        for item in unresolved_followups
    )
    record = {
        "schema_version": 3,
        "kind": "scope_audit_summary",
        "input_fact_ids": inputs,
        "confirmed_vulnerability_ids": sorted(vulnerabilities),
        "unresolved_followups": unresolved_followups,
        "reconnaissance": categories,
        "independent_coverage_review": {
            "fact_id": blindspot_fact.id if blindspot_fact else None,
            "summary": blindspot_record.get("summary"),
            "dimensions": blindspot_record.get("dimensions", {}),
            "items": blindspot_record.get("items", []),
        },
        # This is closure over the finite configured/discovered lens set only.
        # No finite set of category passes proves that the assumed threat space
        # itself was exhaustive.
        "configured_lenses_complete": not partial_categories and not residual_gaps,
        # Backward-compatible alias; its scope is explicitly labeled below.
        "coverage_complete": not partial_categories and not residual_gaps,
        "coverage_basis": "configured_and_evidence_discovered_lenses_only",
        "assumption_space_exhaustiveness": "not_proven",
        "residual_gaps": residual_gaps,
        "statement": (
            "The scope gate and configured or evidence-discovered category reconnaissance branches reached "
            "their terminal result on frozen evidence. Category closure applies only to those recorded lenses; "
            "the completeness of the threat-class assumption space is not proven. "
            + ("Some category coverage remains partial; " if partial_categories else "")
            + ("Residual uncertainty or unexplored paths remain recorded below. "
               if residual_gaps else "")
            + ("CodeQL machine-path collection also reached its required terminal state. "
               if codeql.active_for_project(project, config.codeql) else "")
            + " Policy eligibility remains separate from technical exploitability. "
            "This is not evidence that the repository is universally safe."
        ),
    }
    directory = workdir / ".linen-analysis" / ("audit-summary-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    path = directory / "audit-summary.json"
    write_json(path, record)
    visible_gap_lines = [
        f"- {item['category']}: {item['gap']}"
        for item in residual_gaps[:12]
    ]
    if len(residual_gaps) > len(visible_gap_lines):
        visible_gap_lines.append(
            f"- {len(residual_gaps) - len(visible_gap_lines)} additional gap(s); see the artifact"
        )
    summary_evidence = (
        f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
        "status: completed\n"
        f"coverage_complete: {str(record['coverage_complete']).lower()}\n"
        f"configured_lenses_complete: {str(record['configured_lenses_complete']).lower()}\n"
        "coverage_basis: configured_and_evidence_discovered_lenses_only\n"
        "assumption_space_exhaustiveness: not_proven\n"
        f"residual_gaps: {len(residual_gaps)}\n"
        + ("\n".join(visible_gap_lines) if visible_gap_lines else "residual_gaps: none")
    )
    return {
        "type": "audit_summary",
        "description": (
            f"Scope audit synthesis completed with {len(vulnerabilities)} confirmed vulnerabilities; "
            f"{len(partial_categories)} partial category result(s), "
            f"{len(residual_gaps)} explicit residual gap(s), "
            f"{len(unresolved_followups)} unresolved follow-up fact(s), and "
            f"{sum(len(item['leads']) for item in categories)} reconnaissance lead(s) are retained. "
            + ("Reconnaissance branches reached their required terminal state. "
               if not codeql.active_for_project(project, config.codeql) else "Reconnaissance branches and CodeQL collection reached their required terminal state. ")
            + "Closure applies to recorded lenses; threat-class completeness is not proven."
        ),
        "evidence": summary_evidence,
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
                # Keep policy uncertainty explicit while source recon proceeds.
                plan_anchor = evidence.id
            elif not _reviewed(project, adjudication.id):
                review_proposals = [
                    proposal for proposal in _review_proposals(project)
                    if proposal["from"] == [adjudication.id]
                ][:limit]
                if review_proposals:
                    return review_proposals
                pending_review = any(
                    intent.from_ == [adjudication.id]
                    and (intent.type or "").startswith("review")
                    and intent.to is None
                    and intent.concluded_at is None
                    for intent in project.intents
                )
                if not pending_review:
                    # A failed independent review must not permanently poison
                    # the only scope-adjudication result. Regenerate the
                    # bounded stage so corrected evidence can be reviewed;
                    # never weaken the gate or duplicate an in-flight review.
                    retry = _stage_intent_proposal(
                        project, [evidence.id], "verify", scope_gate.ADJUDICATION_INTENT,
                    )
                    if retry is not None:
                        return [retry]
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
        if codeql.active_for_project(project, config.codeql) and codeql.latest_fact(project) is None:
            attempted = any(
                intent.description.strip() == codeql.INTENT
                and intent.source_generation == project.project.source_generation
                and intent.plan_revision == project.project.plan_revision
                for intent in project.intents
            )
            if not attempted:
                return [{
                    "from": [snapshot.id],
                    "type": "search",
                    "description": codeql.INTENT,
                }]
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
        categories = recon.expected_category_facts(project, config.recon)
        blindspot_fact = recon.coverage_review_fact(project)
        if blindspot_fact is None:
            pending = any(
                intent.source_generation == project.project.source_generation
                and intent.plan_revision == project.project.plan_revision
                and intent.to is None
                and intent.concluded_at is None
                and intent.description.strip() != AUDIT_SUMMARY_INTENT
                for intent in project.intents
            )
            if not pending and categories is not None and _recon_coverage_ready(project, workdir, config):
                review_sources = [snapshot.id, *(fact.id for fact in categories)]
                if codeql.active_for_project(project, config.codeql):
                    machine_fact = codeql.latest_fact(project)
                    if machine_fact is not None:
                        review_sources.append(machine_fact.id)
                        review_sources.extend(
                            fact.id for _category, fact in codeql.query_results(project)
                        )
                review_intent = _stage_intent_proposal(
                    project,
                    review_sources,
                    "verify",
                    recon.COVERAGE_REVIEW_INTENT,
                )
                if review_intent is not None:
                    return [review_intent]
        else:
            try:
                review_record = recon.coverage_review_record(blindspot_fact, workdir)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                review_record = {"items": []}
            scheduled = []
            current_categories = set(recon.categories_for_project(project, config.recon))
            discovered_categories = current_categories - set(config.recon.categories)
            for item in review_record.get("items", []):
                if item.get("disposition") != "recon":
                    continue
                category = item.get("category")
                subject = item.get("subject") or None
                if not isinstance(category, str):
                    continue
                is_new_category = category not in current_categories
                if is_new_category and len(discovered_categories) >= config.recon.max_discovered_categories:
                    continue
                description = recon.category_description(category, subject)
                prior_attempts = sorted([
                    candidate for candidate in project.intents
                    if candidate.description.strip() == description
                    and candidate.source_generation == project.project.source_generation
                    and candidate.plan_revision == project.project.plan_revision
                ], key=lambda candidate: (candidate.created_at, candidate.id), reverse=True)
                latest_resolution = None
                for prior in prior_attempts:
                    prior_fact = next((
                        fact for fact in project.facts
                        if prior.to == fact.id and fact.type == "recon"
                    ), None)
                    if prior_fact is None:
                        continue
                    try:
                        prior_record = recon.result_record(prior_fact, workdir)
                    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                        continue
                    latest_resolution = next((
                        result for result in prior_record.get("coverage_review_resolutions", [])
                        if result.get("item_id") == item.get("id")
                    ), None)
                    if latest_resolution is not None:
                        break
                if latest_resolution is not None and latest_resolution.get("status") == "addressed":
                    continue
                runs = sum(
                    1 for candidate in project.intents
                    if recon.category_from_description(candidate.description) == category
                    and candidate.source_generation == project.project.source_generation
                    and candidate.plan_revision == project.project.plan_revision
                )
                if runs >= config.recon.max_runs_per_category:
                    continue
                from_ids = [snapshot.id, blindspot_fact.id]
                if subject:
                    prior_category_fact = recon.latest_category_fact(project, category)
                    if prior_category_fact is None:
                        continue
                    from_ids.append(prior_category_fact.id)
                proposal = _stage_intent_proposal(
                    project, from_ids, "search", description,
                )
                if proposal is not None:
                    scheduled.append(proposal)
                    if is_new_category:
                        current_categories.add(category)
                        discovered_categories.add(category)
                elif not any(
                    candidate.description.strip() == description and candidate.to is None
                    and candidate.concluded_at is None for candidate in project.intents
                ):
                    # A stage that exhausted retries is preserved by the summary
                    # as a residual gap; continue scheduling other independent items.
                    continue
            if scheduled:
                return scheduled[:limit]
        # The high-level Reason worker owns decisions about partial searches
        # and targeted follow-ups. Never expand them into per-file cells.
        inputs = audit_summary_inputs(project, workdir, config)
        if inputs is not None:
            proposal = _stage_intent_proposal(
                project, inputs, "synthesize", AUDIT_SUMMARY_INTENT,
            )
            return [proposal] if proposal is not None else []
        return []

    if not recon.active_for_project(project, config.recon):
        return []
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
    blockers = []
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
    if recon.active_for_project(project, config.recon) and codeql.active_for_project(project, config.codeql):
        machine_fact = codeql.latest_fact(project)
        if machine_fact is None:
            blockers.append("CodeQL machine-path analysis has no completed result Fact.")
        else:
            try:
                machine_record = codeql.result_record(machine_fact, workdir)
                if machine_record.get("status") != "complete":
                    blockers.append("CodeQL machine-path analysis did not complete successfully.")
            except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
                blockers.append(f"Invalid CodeQL machine-path evidence {machine_fact.id}: {exc}")
        snapshot = recon.snapshot_fact(project)
        for intent in project.intents:
            category = codeql.query_category(intent.description)
            if (
                category is None
                or intent.source_generation != project.project.source_generation
                or intent.plan_revision != project.project.plan_revision
            ):
                continue
            fact = next((item for item in project.facts if item.id == intent.to), None)
            if fact is None:
                blockers.append(
                    f"Requested CodeQL query profile {category} did not produce a result Fact; "
                    "inspect its execution error and retry within the configured attempt limit."
                )
                continue
            try:
                query_record = codeql.result_record(fact, workdir)
                if (
                    query_record.get("status") != "complete"
                    or snapshot is None
                    or query_record.get("snapshot_fact_id") != snapshot.id
                ):
                    blockers.append(
                        f"CodeQL query profile {category} did not complete against the current frozen snapshot."
                    )
            except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
                blockers.append(f"Invalid CodeQL query evidence {fact.id}: {exc}")
    summary = next((fact for fact in project.facts if fact.id in from_ids and fact.type == "audit_summary"), None)
    if summary is None:
        blockers.append("Scope completion must reference a validated audit_summary fact.")
    elif not _reviewed(project, summary.id):
        blockers.append(f"{summary.id} requires a firm/certain VALID review.")
    if audit_summary_inputs(project, workdir, config) is None:
        blockers.append(
            "Configured reconnaissance branches have not produced validated results or capped partial results with explicit residual gaps."
        )
    return list(dict.fromkeys(blockers))
