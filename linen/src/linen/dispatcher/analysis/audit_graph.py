"""Pure graph-derived orchestration for managed audits.

No queue or mutable audit state lives here.  Given the exported blackboard and
immutable artifacts, ``required_intents`` always derives the same missing graph
edges.  The dispatcher remains the only component that writes those edges.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from linen.dispatcher.analysis import codeql, coverage, recon, scope_gate
from linen.dispatcher.analysis.artifacts import ancestor_ids, digest, write_json
from linen.dispatcher.config import AuditConfig
from linen.candidate_attempts import is_candidate_attempt
from linen.server.models import Fact, ProjectDetail, REVIEWLESS_INTERMEDIATE_FACT_TYPES
from linen.server.uvpg import (
    MAX_UNIFIED_PROOF_REVIEW_ATTEMPTS,
    PROOF_GATE_VERSION,
    REQUIRED_ROLES,
)


CREATOR = "dispatcher.audit"
AUDIT_SUMMARY_INTENT = "@analysis:audit-summary"
MAX_STAGE_INTENT_ATTEMPTS = 4
MAX_CANDIDATE_PROOF_REVIEW_ATTEMPTS = MAX_UNIFIED_PROOF_REVIEW_ATTEMPTS
CANDIDATE_BUDGET_RESIDUAL_KIND = "candidate_budget_residual"


def candidate_budget_overflow_ids(
    project: ProjectDetail,
    max_candidate_findings: int,
) -> set[str]:
    """Return current-generation candidate attempts beyond the stable budget."""
    attempts = []
    for fact in project.facts:
        if (
            not is_candidate_attempt(fact.type, fact.semantic_type)
            or fact.source_generation != project.project.source_generation
        ):
            continue
        attempts.append(fact)
    def order(fact: Fact) -> tuple[int, int | str, str]:
        suffix = fact.id[1:] if fact.id.startswith("f") else ""
        if suffix.isdecimal():
            return (0, int(suffix), fact.id)
        return (1, fact.id, fact.id)

    attempts.sort(key=order)
    return {fact.id for fact in attempts[max_candidate_findings:]}


def _candidate_budget_residual_payload(fact: Fact) -> dict | None:
    if fact.type != "coverage_result" or fact.semantic_type != "coverage":
        return None
    try:
        payload = json.loads(fact.evidence or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("kind") != CANDIDATE_BUDGET_RESIDUAL_KIND:
        return None
    return payload


def _lead_disposition_ledger(
    project: ProjectDetail,
    workdir: Path,
    config: AuditConfig,
) -> list[dict]:
    """Keep each source-grounded Recon/CodeQL lead visible through synthesis.

    A lead is dispositioned only when its own source Fact has a descendant
    candidate or an independently reviewed rejection. Mere inclusion in a
    summary input list, or a sibling lead from the same Recon run, is not
    evidence that this particular lead was handled.
    """
    sources: list[tuple[Fact, str, dict, dict]] = []
    for fact in recon.result_facts(project, config.recon):
        source_intent = next((intent for intent in project.intents if intent.to == fact.id), None)
        if (
            fact.source_generation != project.project.source_generation
            or source_intent is None
            or source_intent.source_generation != project.project.source_generation
            or source_intent.plan_revision != project.project.plan_revision
        ):
            continue
        record = recon.result_record(fact, workdir)
        category = recon.category_from_description(next((
            intent.description for intent in project.intents if intent.to == fact.id
        ), "")) or "unknown"
        for lead in record.get("leads", []):
            if isinstance(lead, dict):
                sources.append((fact, category, lead, record))
    if codeql.active_for_project(project, config.codeql):
        machine_facts = []
        initial = codeql.latest_fact(project)
        initial_intent = next((
            intent for intent in project.intents if intent.to == initial.id
        ), None) if initial is not None else None
        if (
            initial is not None
            and initial.source_generation == project.project.source_generation
            and initial_intent is not None
            and initial_intent.source_generation == project.project.source_generation
            and initial_intent.plan_revision == project.project.plan_revision
        ):
            machine_facts.append(("codeql", initial))
        machine_facts.extend(codeql.query_results(project))
        for category, fact in machine_facts:
            result_intent = next((
                intent for intent in project.intents if intent.to == fact.id
            ), None)
            if (
                fact.source_generation != project.project.source_generation
                or result_intent is None
                or result_intent.source_generation != project.project.source_generation
                or result_intent.plan_revision != project.project.plan_revision
            ):
                continue
            record = codeql.result_record(fact, workdir)
            for lead in record.get("leads", []):
                if isinstance(lead, dict):
                    sources.append((fact, f"codeql:{category}", lead, record))

    ledger = []
    for source_fact, category, lead, record in sources:
        source_location = _source_location(lead.get("source"))
        sink_location = _source_location(lead.get("sink"))
        citation_map = {
            item["id"]: item for item in record.get("citations", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        lead_citations = [
            citation_map[citation_id]
            for citation_id in lead.get("citation_ids", lead.get("citations", []))
            if citation_id in citation_map
        ]
        citation_locations = {
            (item.get("file"), item.get("line")) for item in lead_citations
            if isinstance(item.get("file"), str) and isinstance(item.get("line"), int)
        }
        sibling_count = sum(1 for row in sources if row[0].id == source_fact.id)
        related = []
        for candidate in project.facts:
            if (
                source_fact.id not in ancestor_ids(project, [candidate.id])
                or candidate.source_generation != source_fact.source_generation
                or candidate.semantic_type not in {"candidate_finding", "rejected_finding"}
            ):
                continue
            candidate_text = f"{candidate.description}\n{candidate.evidence or ''}"
            if not _candidate_is_bound_to_lead(
                candidate_text, source_location, sink_location,
                citation_locations, lead, sibling_count, source_fact.id,
            ):
                continue
            related.append(candidate)
        reviewed_rejections = []
        for candidate in related:
            if candidate.status != "false_positive":
                continue
            reviews = coverage.effective_reviews(project, candidate.id)
            if any(
                review.verdict == "INVALID" and review.confidence in {"firm", "certain"}
                for review in reviews
            ):
                reviewed_rejections.append(candidate)
        candidates = [item for item in related if item not in reviewed_rejections]
        citation_ids = lead.get("citation_ids", lead.get("citations", []))
        if reviewed_rejections and not candidates:
            disposition = "rejected_with_independent_evidence"
        elif candidates:
            disposition = "candidate_tracked"
        else:
            disposition = "unresolved_gap"
        ledger.append({
            "source_fact_id": source_fact.id,
            "category": category,
            "lead_id": lead.get("id"),
            "title": lead.get("title", "Unlabeled source lead"),
            "hypothesis": lead.get("hypothesis", ""),
            "source": lead.get("source", ""),
            "sink": lead.get("sink", ""),
            "citations": list(citation_ids) if isinstance(citation_ids, list) else [],
            "disposition": disposition,
            "candidate_fact_ids": [item.id for item in candidates],
            "rejected_fact_ids": [item.id for item in reviewed_rejections],
        })
    return ledger


def _source_location(value: object) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    match = re.match(r"^(.*?):(\d+)(?:\b|\s|$)", value.strip())
    return (match.group(1), int(match.group(2))) if match else None


def _candidate_cites_location(text: str, location: tuple[str, int]) -> bool:
    file, line = location
    escaped_file = re.escape(file)
    escaped_line = re.escape(str(line))
    return bool(re.search(
        rf"(?<![A-Za-z0-9_./-]){escaped_file}:{escaped_line}(?!\d)",
        text,
    ) or re.search(
        rf"file:\s*{escaped_file}\s*\n\s*line:\s*{escaped_line}(?!\d)",
        text,
    ) or re.search(
        rf"(?<!\d){escaped_line}:\s*{escaped_file}(?![A-Za-z0-9_./-])",
        text,
    ))


def _candidate_is_bound_to_lead(
    candidate_text: str,
    source: tuple[str, int] | None,
    sink: tuple[str, int] | None,
    citations: set[tuple[object, object]],
    lead: dict,
    sibling_count: int,
    source_fact_id: str,
) -> bool:
    """Associate a candidate with exact path evidence, never just a shared file.

    Candidate text is an attribution hint for the graph ledger, not a trusted
    security verdict. Ambiguous sibling paths remain unresolved until Reason
    emits a candidate whose evidence names their specific source/sink lines.
    """
    lead_id = lead.get("id")
    if isinstance(lead_id, str) and lead_id and re.search(
        rf"(?m)^\s*lead_ref\s*:\s*{re.escape(source_fact_id)}/{re.escape(lead_id)}\s*$",
        candidate_text,
    ):
        return True
    exact_anchors = [item for item in (source, sink) if item is not None]
    if exact_anchors:
        return all(_candidate_cites_location(candidate_text, item) for item in exact_anchors)
    matched_citations = [
        (file, line) for file, line in citations
        if isinstance(file, str) and isinstance(line, int)
        and _candidate_cites_location(candidate_text, (file, line))
    ]
    if matched_citations:
        return len(matched_citations) >= (2 if sibling_count > 1 else 1)
    return False


def _candidate_budget_overflow_records(
    project: ProjectDetail,
    max_candidate_findings: int,
) -> list[dict]:
    overflow_ids = candidate_budget_overflow_ids(project, max_candidate_findings)
    records = []
    for fact in sorted(project.facts, key=lambda item: item.id):
        if fact.id not in overflow_ids:
            continue
        records.append({
            "candidate_fact_id": fact.id,
            "description": fact.description,
            "evidence": fact.evidence,
            "source_intents": [
                {"intent_id": intent.id, "source_fact_ids": list(intent.from_)}
                for intent in project.intents if intent.to == fact.id
            ],
        })
    return records


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
    residual = _candidate_budget_residual_payload(fact)
    if (
        fact.status == "triaged"
        and residual is not None
        and fact.evidence
        and fact.evidence.strip()
    ):
        return True
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


def _review_exhaustion(project: ProjectDetail, fact: Fact) -> dict | None:
    """Return an explicit unresolved disposition when no bounded review remains.

    A review cap only closes the orchestration loop. It never changes the
    candidate's semantic type or turns an inconclusive review into a verdict.
    Candidate proof-package reviews have their own retry route; other Facts
    follow the bounded mode sequence in ``_review_proposals``.
    """
    if fact.status in {"false_positive", "fixed", "accepted_risk"}:
        return None

    all_reviews = sorted(
        (review for review in project.reviews if review.fact_id == fact.id),
        key=lambda review: (review.created_at, review.id),
    )
    if (
        fact.type == "vulnerability"
        and fact.semantic_type == "candidate_finding"
        and not _has_unified_vulnerability_review(project, fact.id)
    ):
        proof_reviews = [
            review for review in all_reviews
            if review.source_generation == fact.source_generation
            and isinstance(review.cold_verification, dict)
            and review.cold_verification.get("review_kind") == "vulnerability_proof"
            and review.cold_verification.get("candidate_id") == fact.id
        ]
        if len(proof_reviews) < MAX_CANDIDATE_PROOF_REVIEW_ATTEMPTS:
            return None
        return _review_exhaustion_record(
            project, fact, proof_reviews, MAX_CANDIDATE_PROOF_REVIEW_ATTEMPTS,
        )

    if _reviewed(project, fact.id):
        return None

    reviews = coverage.effective_reviews(project, fact.id)
    if not reviews:
        return None
    modes = {
        intent.type or "review" for intent in project.intents
        if len(intent.from_) == 1 and intent.from_[0] == fact.id
        and (intent.type or "").startswith("review")
    }
    review_text = "\n".join(
        f"{review.summary}\n{review.reasoning or ''}" for review in all_reviews
    ).lower()
    source_text_missing = any(
        marker in review_text
        for marker in (
            "source files are absent", "source unavailable", "source files unavailable",
            "no source text", "could not inspect source", "could not verify the code",
        )
    )
    if len(reviews) >= 2:
        may_receive_source_retry = (
            source_text_missing
            and len(reviews) < 3
            and "review:cold-verifier" not in modes
        )
        if may_receive_source_retry:
            return None
        limit = 3 if source_text_missing and "review:cold-verifier" not in modes else 2
    else:
        next_mode = (
            "review:contradiction-reasoner"
            if any(review.verdict == "NEEDS_REVIEW" for review in reviews)
            else "review:cold-verifier"
        )
        if next_mode not in modes:
            return None
        # The only available independent mode was already used. Treat this as
        # the terminal bound rather than leaving a review obligation dangling.
        limit = len(reviews)
    return _review_exhaustion_record(project, fact, reviews, limit)


def _review_exhaustion_record(
    project: ProjectDetail,
    fact: Fact,
    reviews: list,
    attempt_limit: int,
) -> dict:
    return {
        "fact_id": fact.id,
        "type": fact.type,
        "semantic_type": fact.semantic_type,
        "status": fact.status,
        "description": fact.description,
        "evidence": fact.evidence,
        "attempt_count": len(reviews),
        "attempt_limit": attempt_limit,
        "latest_verdict": reviews[-1].verdict,
        "disposition": "review_exhausted",
        "source_intents": [
            {"intent_id": intent.id, "fact_ids": list(intent.from_)}
            for intent in project.intents if intent.to == fact.id
        ],
        "reviews": [
            {
                "verdict": review.verdict,
                "confidence": review.confidence,
                "summary": review.summary,
            }
            for review in reviews
        ],
    }


def _review_proposals(
    project: ProjectDetail,
    max_candidate_findings: int = 8,
) -> list[dict]:
    proposals = []
    over_budget_candidates = candidate_budget_overflow_ids(
        project, max_candidate_findings,
    )
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
        if (
            fact.type == "vulnerability"
            and fact.id in over_budget_candidates
        ):
            continue
        if fact.type in REVIEWLESS_INTERMEDIATE_FACT_TYPES:
            continue
        if not (
            fact.type in {
                "coverage_result", "policy_evidence", "scope_adjudication", "vulnerability",
                # Sanitizer assessments can carry a negative-control claim
                # (for example, whether parameter binding blocks tainted SQL
                # input). Review them independently before relying on that
                # claim in the final audit summary.
                "sanitizer",
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
        ):
            # Candidate-local proof-package reviews are planned only by the
            # server's proof-gap projection, which can verify closure and
            # source provenance before requesting the cold-verifier pass.
            continue
        if fact.status in {"false_positive", "fixed", "accepted_risk"} or fact.id in open_reviews:
            continue
        if _review_exhaustion(project, fact) is not None:
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

    A valid result for the same inputs is terminal. A concluded intent without
    a result must not permanently satisfy the existence check, while a Fact
    rejected by independent review is also eligible for bounded regeneration.
    Changed graph inputs may legitimately require a refreshed result. An open
    attempt remains the single owner of that stage obligation.
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
    facts_by_id = {fact.id: fact for fact in project.facts}
    result_attempts = [
        item for item in prior
        if item.to in facts_by_id and item.from_ == from_ids
    ]
    usable_result_attempts = [
        item for item in result_attempts
        if facts_by_id[item.to].status not in {"false_positive", "fixed"}
    ]
    if usable_result_attempts:
        return None
    attempts_without_result = sum(
        item not in result_attempts
        or facts_by_id[item.to].status in {"false_positive", "fixed"}
        for item in prior
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
            module_ids = [
                plan_fact.id,
                *(fact.id for fact in category_facts),
                *(
                    fact.id for fact in recon.result_facts(project, config.recon)
                    if fact.source_generation == project.project.source_generation
                    and any(
                        intent.to == fact.id
                        and intent.source_generation == project.project.source_generation
                        and intent.plan_revision == project.project.plan_revision
                        for intent in project.intents
                    )
                ),
                blindspot_fact.id,
            ]
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
        over_budget_candidates = candidate_budget_overflow_ids(
            project, config.max_candidate_findings,
        )
        for fact in project.facts:
            if fact.id in {"origin", "goal"} or fact.type == "audit_summary":
                continue
            if (
                fact.type == "vulnerability"
                and fact.id in over_budget_candidates
            ):
                # Historical candidates created before the hard writer gate
                # remain visible in the residual artifact, but do not fan out
                # into per-candidate review or proof work.
                required_ids.add(fact.id)
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
            exhaustion = _review_exhaustion(project, fact)
            if not _reviewed(project, fact.id) and exhaustion is None:
                return None
            if exhaustion is not None:
                # A generic review of the candidate does not replace the
                # candidate-local proof-package review. Preserve that failed
                # proof review even when another review made the Fact triaged.
                required_ids.add(fact.id)
                continue
            required_ids.add(fact.id)
        required_ids.update(
            fact.id for fact in project.facts
            if _candidate_budget_residual_payload(fact) is not None
            and fact.source_generation == project.project.source_generation
        )
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
    unresolved_reviews = [
        disposition for fact in project.facts
        if fact.id in inputs
        and (disposition := _review_exhaustion(project, fact)) is not None
    ]
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
    lead_disposition_ledger = _lead_disposition_ledger(project, workdir, config)
    residual_gaps = [
        {"category": item["category"], "gap": gap}
        for item in categories for gap in item["gaps"]
    ]
    candidate_budget_residual_facts = [
        fact for fact in project.facts
        if fact.source_generation == project.project.source_generation
        and _candidate_budget_residual_payload(fact) is not None
    ]
    candidate_budget_overflow_candidates = _candidate_budget_overflow_records(
        project, config.max_candidate_findings,
    )
    candidate_budget_overflow_leads = [
        {
            "residual_fact_id": fact.id,
            **lead,
        }
        for fact in candidate_budget_residual_facts
        for lead in (_candidate_budget_residual_payload(fact) or {}).get(
            "overflow_leads", [],
        )
        if isinstance(lead, dict)
    ]
    if candidate_budget_overflow_candidates or candidate_budget_overflow_leads:
        overflow_count = (
            len(candidate_budget_overflow_candidates)
            + len(candidate_budget_overflow_leads)
        )
        residual_gaps.append({
            "category": "candidate-budget",
            "gap": (
                f"{overflow_count} candidate lead(s) exceeded the configured limit of "
                f"{config.max_candidate_findings}; original claims, evidence, source intents, "
                "and provenance are retained in the candidate-budget residual Fact(s)."
            ),
        })
    for item in categories:
        dimensions = item.get("coverage_dimensions", {})
        # An `unresolved` row is a declared blind spot, not a coverage claim. It
        # is non-terminal for every axis, so surface all four rather than only
        # `uncovered_items`; dropping the others would silently discard exactly
        # the "could not verify" evidence the report is supposed to preserve.
        for axis in ("uncovered_items", "parallel_paths", "lifecycle", "exclusion_rationales"):
            for row in dimensions.get(axis, []):
                if not isinstance(row, dict) or row.get("status") != "unresolved":
                    continue
                residual_gaps.append({
                    "category": item["category"],
                    "gap": f"[{axis}] {row.get('item')}: {row.get('rationale')}",
                })
    for lead in lead_disposition_ledger:
        if lead["disposition"] == "unresolved_gap":
            residual_gaps.append({
                "category": lead["category"],
                "gap": (
                    f"Unresolved source lead {lead['lead_id'] or lead['title']}: "
                    f"{lead['hypothesis']} (source Fact {lead['source_fact_id']}; "
                    "no linked candidate or independently reviewed rejection was found)"
                ),
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
    residual_gaps.extend(
        {
            "category": "review-exhausted",
            "gap": (
                f"{item['fact_id']} remains unresolved after "
                f"{item['attempt_count']} of {item['attempt_limit']} bounded review attempt(s) "
                f"(latest verdict: {item['latest_verdict']}); it is retained as a candidate, "
                "not a confirmed or rejected finding"
            ),
        }
        for item in unresolved_reviews
    )
    record = {
        "schema_version": 4,
        "kind": "scope_audit_summary",
        "input_fact_ids": inputs,
        "confirmed_vulnerability_ids": sorted(vulnerabilities),
        "unresolved_reviews": unresolved_reviews,
        "unresolved_followups": unresolved_followups,
        "candidate_budget_residual": {
            "max_candidate_findings": config.max_candidate_findings,
            "residual_fact_ids": [fact.id for fact in candidate_budget_residual_facts],
            "overflow_leads": candidate_budget_overflow_leads,
            "historical_overflow_candidates": candidate_budget_overflow_candidates,
        },
        "reconnaissance": categories,
        "lead_disposition_ledger": lead_disposition_ledger,
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
        + (
            "\n" + "\n".join(
                f"review_exhausted_candidate_id:{item['fact_id']}"
                for item in unresolved_reviews
                if item["type"] == "vulnerability"
                and item["semantic_type"] == "candidate_finding"
            )
            if any(
                item["type"] == "vulnerability"
                and item["semantic_type"] == "candidate_finding"
                for item in unresolved_reviews
            ) else ""
        )
        + (
            "\n" + "\n".join(
                f"candidate_budget_overflow_id:{item['candidate_fact_id']}"
                for item in candidate_budget_overflow_candidates
            )
            if candidate_budget_overflow_candidates else ""
        )
    )
    return {
        "type": "audit_summary",
        "description": (
            f"Scope audit synthesis completed with {len(vulnerabilities)} confirmed vulnerabilities; "
            f"{len(partial_categories)} partial category result(s), "
            f"{len(residual_gaps)} explicit residual gap(s), "
            f"{len(unresolved_reviews)} exhausted review(s), "
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
                    proposal for proposal in _review_proposals(
                        project, config.max_candidate_findings,
                    )
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
                    proposal for proposal in _review_proposals(
                        project, config.max_candidate_findings,
                    )
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
    reviews = _review_proposals(project, config.max_candidate_findings)
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
