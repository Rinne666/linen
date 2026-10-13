"""Evaluator-only case attribution and preregistered benchmark observations.

Nothing in this module writes the audit graph or promotes a finding. Evaluator
assessments measure reviewed case coverage separately from finding semantics.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from linen.dispatcher.analysis.benchmark import evaluate
from linen.dispatcher.analysis.evaluation import _field, observation


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def identifiers(values: list[str], label: str) -> set[str]:
    if any(not isinstance(v, str) or not v.strip() or v != v.strip() for v in values):
        raise ValueError(f"{label} requires non-empty, unpadded identifiers")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} identifiers must be unique")
    return set(values)


class CaseLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    category: str = Field(min_length=1)
    vulnerable: StrictBool
    cwe: str | None = None
    source_path: str | None = None
    dimensions: list[str] = Field(default_factory=list)


class TruthSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected: list[str]
    negative_controls: list[str]
    labels: list[CaseLabel]

    @model_validator(mode="after")
    def coherent_labels(self) -> TruthSet:
        positives = identifiers(self.expected, "expected")
        negatives = identifiers(self.negative_controls, "negative_controls")
        if not positives or not negatives or positives & negatives:
            raise ValueError("Case benchmarks require disjoint, non-empty positive and negative sets")
        label_ids = identifiers([label.id for label in self.labels], "labels")
        if label_ids != positives | negatives:
            raise ValueError("Labels must describe every positive and negative case exactly once")
        for label in self.labels:
            if label.vulnerable != (label.id in positives):
                raise ValueError(f"Truth label contradicts expected/negative_controls: {label.id}")
            identifiers(label.dimensions, f"dimensions for {label.id}")
        return self


class BenchmarkPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    registered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    suite_id: str = Field(min_length=1)
    source_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    truth_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    config_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    planned_runs: list[str] = Field(min_length=3, max_length=3)
    detection_level: Literal["candidate", "confirmed"] = "confirmed"
    min_recall: float = Field(default=0.8, ge=0, le=1, allow_inf_nan=False)
    min_stability: float = Field(default=0.7, ge=0, le=1, allow_inf_nan=False)
    max_false_positive_rate: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    min_case_coverage: float = Field(default=1, ge=0, le=1, allow_inf_nan=False)
    min_category_recall: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)
    max_run_records: int = Field(gt=0)
    wall_clock_budget_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def unique_runs(self) -> BenchmarkPlan:
        identifiers(self.planned_runs, "planned_runs")
        registered = datetime.fromisoformat(self.registered_at.replace("Z", "+00:00"))
        if registered.tzinfo is None:
            raise ValueError("Plan registration needs a timezone-aware timestamp")
        return self


class CaseAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: Literal["vulnerable", "protected", "unassessed"]
    fact_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def coherent_assessment(self) -> CaseAssessment:
        identifiers(self.fact_ids, "assessment facts")
        if not self.rationale.strip():
            raise ValueError("Assessment rationale must not be blank")
        if self.disposition != "unassessed" and not self.fact_ids:
            raise ValueError("A conclusive assessment requires supporting Fact IDs")
        return self


TECHNICAL_FACT_TYPES = {
    "vulnerability", "dataflow", "sanitizer", "refutation", "negative_assurance",
    "validation", "attacker_control", "reachability", "security_boundary",
    "security_invariant", "capability_before", "capability_after",
    "reproduction", "negative_control",
}


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def score_cases(rows: list[dict], level: str, unexpected: list[str]) -> dict:
    field = "confirmed" if level == "confirmed" else "candidate"
    positives = [r for r in rows if r["vulnerable"]]
    negatives = [r for r in rows if not r["vulnerable"]]
    tp = [r["id"] for r in positives if r[field]]
    fp = [r["id"] for r in negatives if r[field]]
    tn = [r["id"] for r in negatives if not r[field] and r["disposition"] == "protected"]
    fn = [r["id"] for r in positives if not r[field] and r["disposition"] == "protected"]
    unassessed = [r["id"] for r in rows if r["disposition"] == "unassessed"]
    return {
        "case_count": len(rows), "positive_count": len(positives), "negative_count": len(negatives),
        "true_positive_ids": tp, "false_positive_ids": fp,
        "true_negative_ids": tn, "false_negative_ids": fn,
        "undetected_positive_ids": [r["id"] for r in positives if not r[field]],
        "unassessed_ids": unassessed, "unexpected_detection_ids": unexpected,
        "recall": _ratio(len(tp), len(positives)),
        "precision": _ratio(len(tp), len(tp) + len(fp) + len(unexpected)),
        "false_positive_rate": _ratio(len(fp), len(negatives)),
        "case_coverage": _ratio(len(rows) - len(unassessed), len(rows)),
    }


def grouped_scores(rows: list[dict], level: str, axis: str) -> dict:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        values = row[axis] if axis == "dimensions" else [row[axis] or "unspecified"]
        for value in values:
            groups.setdefault(value, []).append(row)
    return {name: score_cases(group, level, []) for name, group in sorted(groups.items())}


def _run_span_ms(runs: list[dict]) -> int | None:
    def timestamp(value: Any) -> float | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.timestamp() if parsed.tzinfo is not None else None

    starts = [v for r in runs if (v := timestamp(r.get("started_at"))) is not None]
    finishes = [v for r in runs if (v := timestamp(r.get("finished_at"))) is not None]
    if not starts or not finishes or any(r.get("status") in {"queued", "running"} for r in runs):
        return None
    if max(finishes) < min(starts):
        return None
    return round((max(finishes) - min(starts)) * 1000)


def case_observation(
    board: dict, gate: dict, cost: dict, runs: list[dict], truth: TruthSet,
    plan: BenchmarkPlan, run_label: str, config_digest: str,
    case_map: dict[str, list[str]], assessments: dict[str, Any], *, allow_incomplete: bool = False,
) -> dict:
    meta = board["project"]
    completed = meta.get("status") == "completed" and gate.get("ready") is True
    if not completed and not allow_incomplete:
        raise ValueError("Case export requires completion; use --allow-incomplete for a blocked diagnostic")
    if run_label not in plan.planned_runs:
        raise ValueError("Run label is not preregistered in the benchmark plan")
    if digest(truth.model_dump()) != plan.truth_digest or config_digest != plan.config_digest:
        raise ValueError("Truth or dispatcher configuration differs from the benchmark plan")
    if any(gate.get(k) != v for k, v in (
        ("project_id", meta["id"]), ("source_generation", meta.get("source_generation")),
        ("plan_revision", meta.get("plan_revision")),
    )):
        raise ValueError("Completion gate does not match the project generation")
    facts = {f["id"]: f for f in board.get("facts", [])
             if f.get("source_generation", 1) == meta.get("source_generation", 1) and not f.get("legacy")}
    sources = {_field(str(f.get("evidence") or ""), "snapshot")
               for f in facts.values() if f.get("type") == "recon_snapshot"}
    source_verified = sources == {plan.source_digest}
    if not source_verified and (sources or completed or not allow_incomplete):
        raise ValueError("Frozen source differs from the benchmark plan")
    if not isinstance(case_map, dict) or any(
        fid not in facts or not isinstance(ids, list) or not ids
        or len(identifiers(ids, f"case map {fid}")) != len(ids)
        for fid, ids in case_map.items()
    ):
        raise ValueError("Case map must explicitly attribute current Fact IDs to case IDs")
    findings = {fid for fid, f in facts.items()
                if f.get("semantic_type") in {"candidate_finding", "confirmed_finding"}}
    if findings - case_map.keys():
        raise ValueError("Every current candidate and confirmed finding needs case attribution")
    completed_observation = observation(
        board, gate, cost, {fid: case_map[fid] for fid in findings},
    ) if completed else None
    case_ids = set(truth.expected) | set(truth.negative_controls)
    if not isinstance(assessments, dict) or assessments.keys() - case_ids:
        raise ValueError("Assessments must name cases from the truth set")
    latest_reviews: dict[str, dict] = {}
    for review in sorted(board.get("reviews", []), key=lambda item: (item.get("created_at") or "", item["id"])):
        if review.get("source_generation", 1) == meta.get("source_generation", 1):
            latest_reviews[review.get("fact_id")] = review
    accepted_reviews = {
        fid: [review["id"]] for fid, review in latest_reviews.items()
        if review.get("verdict") == "VALID" and review.get("confidence") in {"firm", "certain"}
    }
    rows = []
    detected = {"candidate": set(), "confirmed": set()}
    for label in truth.labels:
        linked = sorted(fid for fid, ids in case_map.items() if label.id in ids)
        confirmed = [fid for fid in linked if facts[fid].get("semantic_type") == "confirmed_finding"]
        candidate = [fid for fid in linked if facts[fid].get("semantic_type") == "candidate_finding"
                     and facts[fid].get("status") != "false_positive"]
        if confirmed:
            detected["confirmed"].add(label.id)
        if candidate or confirmed:
            detected["candidate"].add(label.id)
        assessment = CaseAssessment.model_validate(assessments.get(label.id, {
            "disposition": "unassessed", "rationale": "No evaluator case assessment supplied.",
        }))
        support_reviews = []
        for fid in assessment.fact_ids:
            if fid not in linked:
                raise ValueError(f"Assessment Fact {fid} is not explicitly mapped to {label.id}")
            fact = facts[fid]
            if not str(fact.get("evidence") or "").strip() or fact.get("type") not in TECHNICAL_FACT_TYPES:
                raise ValueError(f"Case assessment requires technical evidence: {fid}")
            if assessment.disposition != "unassessed" and not accepted_reviews.get(fid):
                raise ValueError(f"Conclusive case assessment needs a current firm/certain VALID review: {fid}")
            support_reviews.extend(accepted_reviews.get(fid, []))
        if assessment.disposition == "protected" and confirmed:
            raise ValueError(f"Protected assessment contradicts a confirmed finding: {label.id}")
        rows.append({
            **label.model_dump(), "fact_ids": linked,
            "candidate": bool(candidate or confirmed), "confirmed": bool(confirmed),
            "candidate_fact_ids": candidate, "confirmed_fact_ids": confirmed,
            **assessment.model_dump(exclude={"fact_ids"}),
            "assessment_fact_ids": assessment.fact_ids, "review_ids": sorted(set(support_reviews)),
        })
    unexpected = {}
    for level in ("candidate", "confirmed"):
        unexpected[level] = sorted({cid for fid in findings for cid in case_map[fid]
            if cid not in case_ids and (facts[fid].get("semantic_type") == "confirmed_finding"
                or (level == "candidate" and facts[fid].get("status") != "false_positive"))})
    instance_id = digest([meta["id"], meta.get("created_at")])
    total = cost.get("total", {})
    coverage_metrics = completed_observation["metrics"] if completed_observation else {}
    return {
        "schema_version": 1, "kind": "audit_case_observation", "plan_digest": digest(plan.model_dump()),
        "truth_digest": plan.truth_digest, "config_digest": config_digest,
        "source_digest": plan.source_digest if source_verified else None, "source_verified": source_verified,
        "run_label": run_label, "project_id": meta["id"], "project_instance_id": instance_id,
        "project_created_at": meta.get("created_at"),
        "run_id": digest([instance_id, meta.get("source_generation"), meta.get("plan_revision")]),
        "source_generation": meta.get("source_generation"), "plan_revision": meta.get("plan_revision"),
        "graph_revision": meta.get("graph_revision"), "board_digest": digest(board),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "completed": completed, "lifecycle_status": meta.get("status"),
        "execution_status": gate.get("execution_status"), "blockers": gate.get("blockers", []),
        "pipeline": {
            "stages": [{k: stage.get(k) for k in ("stage_id", "status", "detail")}
                       for stage in board.get("stages", [])],
            "fact_types": dict(Counter(f.get("type") or "workflow_context" for f in facts.values())),
            "review_verdicts": dict(Counter(review.get("verdict") for review in board.get("reviews", []))),
            "open_errors": [{k: error.get(k) for k in ("intent_id", "code", "classification", "message")}
                            for error in board.get("errors", []) if error.get("resolved_at") is None],
        },
        "cases": rows, "unexpected": unexpected,
        "scores": {level: score_cases(rows, level, unexpected[level]) for level in detected},
        "by_category": {level: grouped_scores(rows, level, "category") for level in detected},
        "by_cwe": {level: grouped_scores(rows, level, "cwe") for level in detected},
        "by_dimension": {level: grouped_scores(rows, level, "dimensions") for level in detected},
        "metrics": {
            "calls": total.get("calls"), "run_records": len(runs), "run_span_ms": _run_span_ms(runs),
            "input_tokens": total.get("input_tokens"), "output_tokens": total.get("output_tokens"),
            "usage_unknown_calls": total.get("usage_unknown_calls"),
            "worker_duration_ms": total.get("duration_ms"),
            "coverage_complete": coverage_metrics.get("coverage_complete"),
            "residual_gaps": coverage_metrics.get("residual_gaps"),
        },
        "annotation_digest": digest({"case_map": case_map, "assessments": assessments}),
        "interpretation": "Case coverage uses evaluator annotations backed by independently reviewed facts. "
                          "Annotations do not promote candidates. Candidate scores are discovery diagnostics. "
                          "Blocked observations are not completed benchmark passes; undetected cases can be unassessed. "
                          "Run span measures first started to last finished run, not summed worker time.",
    }


def compare_case_runs(truth: TruthSet, plan: BenchmarkPlan, observations: list[dict]) -> dict:
    if len(observations) != 3:
        raise ValueError("Pass exactly three preregistered observations, including blocked runs")
    if digest(truth.model_dump()) != plan.truth_digest:
        raise ValueError("Truth set differs from the benchmark plan")
    if {r.get("run_label") for r in observations} != set(plan.planned_runs):
        raise ValueError("Observations must match all three preregistered run labels exactly")
    for key in ("run_id", "project_instance_id"):
        ids = [r.get(key) for r in observations]
        if any(not isinstance(v, str) or not v for v in ids) or len(set(ids)) != 3:
            raise ValueError("Three fresh projects are required; snapshots or replans cannot replace runs")
    labels = {label.id: label.model_dump() for label in truth.labels}
    scores = []
    detections = []
    for run in observations:
        if any(run.get(k) != v for k, v in {
            "kind": "audit_case_observation", "plan_digest": digest(plan.model_dump()),
            "truth_digest": plan.truth_digest,
            "config_digest": plan.config_digest,
        }.items()):
            raise ValueError("Observation provenance differs from the registered plan")
        if run.get("project_instance_id") != digest([run.get("project_id"), run.get("project_created_at")]):
            raise ValueError("Project instance identity does not match its provenance")
        rows = run.get("cases")
        if (not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows)
                or len(rows) != len(labels) or {r.get("id") for r in rows} != labels.keys()):
            raise ValueError("Every observation must retain all planned cases")
        for row in rows:
            if any(row.get(k) != v for k, v in labels[row["id"]].items()):
                raise ValueError("Observation changed a ground-truth case label")
            if any(type(row.get(k)) is not bool for k in ("candidate", "confirmed")):
                raise ValueError("Detection flags must be booleans")
            if row["confirmed"] and not row["candidate"]:
                raise ValueError("Confirmed findings must also count as discovered")
            if row.get("disposition") not in {"vulnerable", "protected", "unassessed"}:
                raise ValueError("Invalid case disposition")
            if row["disposition"] != "unassessed" and (not row.get("assessment_fact_ids") or not row.get("review_ids")):
                raise ValueError("Conclusive case coverage needs reviewed supporting evidence")
        unexpected = run.get("unexpected", {}).get(plan.detection_level, [])
        identifiers(unexpected, "unexpected detections")
        score = score_cases(rows, plan.detection_level, unexpected)
        scores.append({"run_label": run["run_label"], "completed": run.get("completed") is True,
                       **score, "by_category": grouped_scores(rows, plan.detection_level, "category")})
        detections.append({r["id"] for r in rows if r[plan.detection_level]} | set(unexpected))
    quality = evaluate(set(truth.expected), detections)

    def within_budget(run: dict) -> bool:
        metrics = run.get("metrics", {})
        records, span = metrics.get("run_records"), metrics.get("run_span_ms")
        return (type(records) is int and 0 <= records <= plan.max_run_records
                and isinstance(span, (int, float)) and not isinstance(span, bool)
                and math.isfinite(span) and 0 <= span <= plan.wall_clock_budget_seconds * 1000)

    def created_after_registration(run: dict) -> bool:
        try:
            created = datetime.fromisoformat(run["project_created_at"].replace("Z", "+00:00"))
            registered = datetime.fromisoformat(plan.registered_at.replace("Z", "+00:00"))
            return created.tzinfo is not None and created >= registered
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    checks = {
        "all_planned_runs_completed": all(row["completed"] for row in scores),
        "registered_before_projects": all(created_after_registration(run) for run in observations),
        "frozen_source_verified": all(run.get("source_verified") is True
                                      and run.get("source_digest") == plan.source_digest for run in observations),
        "case_coverage": all(row["case_coverage"] >= plan.min_case_coverage for row in scores),
        "positive_detections_observed": all(row["true_positive_ids"] for row in scores),
        "minimum_recall": all(row["recall"] >= plan.min_recall for row in scores),
        "category_recall": all(group["recall"] >= plan.min_category_recall
                               for row in scores for group in row["by_category"].values()
                               if group["positive_count"]),
        "false_positive_rate": all(row["false_positive_rate"] <= plan.max_false_positive_rate for row in scores),
        "no_unexpected_detections": all(not row["unexpected_detection_ids"] for row in scores),
        "stability": quality["stability"]["all_run_jaccard"] >= plan.min_stability,
        "budgets_respected": all(within_budget(run) for run in observations),
    }
    return {
        "schema_version": 1, "kind": "audit_case_benchmark", "suite_id": plan.suite_id,
        "detection_level": plan.detection_level, "plan_digest": digest(plan.model_dump()),
        "accepted": all(checks.values()), "checks": checks,
        "completion_rate": sum(row["completed"] for row in scores) / 3,
        "runs": scores, "stability": quality["stability"],
        "costs": [{"run_label": r["run_label"], **r.get("metrics", {})} for r in observations],
        "interpretation": "Acceptance covers the registered cases and detection level. "
                          "It does not prove exhaustive repository security or dynamic exploitability. "
                          "Candidate acceptance is not confirmed-vulnerability acceptance.",
    }
