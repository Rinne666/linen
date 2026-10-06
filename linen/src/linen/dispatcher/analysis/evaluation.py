"""Read-only, provenance-bearing observations and measured ablation reports.

Case attribution is supplied by the evaluator, outside worker prompts. A source
citation mentioning a case is not itself a detection of that case.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

from linen.dispatcher.analysis.benchmark import evaluate


def _field(evidence: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", evidence, re.MULTILINE)
    return match.group(1).strip() if match else None


def observation(board: dict, gate: dict, cost: dict, case_map: dict | None = None) -> dict:
    """Export one completed board without inferring truth from model prose."""
    meta = board["project"]
    if meta.get("status") != "completed" or not gate.get("ready"):
        raise ValueError("Evaluation export requires a completed project with a ready gate")
    for key in ("project_id", "source_generation", "plan_revision"):
        expected = meta.get("id") if key == "project_id" else meta.get(key)
        if gate.get(key) != expected:
            raise ValueError("Completion gate does not match the project generation")
    facts = [f for f in board.get("facts", [])
             if f.get("source_generation", 1) == meta.get("source_generation", 1)
             and not f.get("legacy")]
    digests = {_field(str(f.get("evidence") or ""), "snapshot")
               for f in facts if f.get("type") == "recon_snapshot"}
    if len(digests) != 1 or not re.fullmatch(r"[a-f0-9]{64}", next(iter(digests)) or ""):
        raise ValueError("Evaluation requires one unambiguous frozen source digest")
    source_digest = next(iter(digests))
    concluded = {i.get("to"): i.get("concluded_at") or "" for i in board.get("intents", [])
                 if i.get("type") == "synthesize" and i.get("description") == "@analysis:audit-summary"
                 and i.get("source_generation") == meta.get("source_generation")
                 and i.get("plan_revision") == meta.get("plan_revision")}
    summaries = [f for f in facts if f.get("type") == "audit_summary" and f["id"] in concluded]
    if not summaries:
        raise ValueError("Evaluation requires an audit summary")
    summary = max(summaries, key=lambda f: concluded.get(f["id"], ""))
    evidence = str(summary.get("evidence") or "")
    coverage = _field(evidence, "coverage_complete")
    gaps = _field(evidence, "residual_gaps")
    if coverage not in {"true", "false"} or gaps is None or not gaps.isdigit():
        raise ValueError("Audit summary lacks explicit coverage and residual gap counts")
    if coverage == "true" and int(gaps) != 0:
        raise ValueError("Complete coverage cannot have residual gaps")
    confirmed = {f["id"] for f in facts if f.get("semantic_type") == "confirmed_finding"}
    candidates = {f["id"] for f in facts if f.get("semantic_type") == "candidate_finding"}
    rejected = {f["id"] for f in facts if f.get("status") == "false_positive"
                and f.get("semantic_type") == "candidate_finding"}
    labels = case_map or {}
    known = confirmed | candidates
    if not isinstance(labels, dict) or any(
        fid not in known or not isinstance(ids, list) or not ids
        or any(not isinstance(i, str) or not i.strip() or i != i.strip() for i in ids)
        or len(ids) != len(set(ids)) for fid, ids in labels.items()
    ):
        raise ValueError("Case map must map current finding fact IDs to unique non-empty case IDs")
    if case_map is not None and confirmed - labels.keys():
        raise ValueError("Every confirmed finding needs evaluator case attribution")

    def attributed(ids: set[str]) -> list[str]:
        return sorted({label for fid in ids for label in labels.get(fid, [])})

    total = cost.get("total", {})
    project_identity = [meta["id"], meta.get("created_at")]
    instance_id = hashlib.sha256(json.dumps(project_identity, separators=(",", ":")).encode()).hexdigest()
    identity = [*project_identity, meta.get("source_generation"), meta.get("plan_revision"), source_digest]
    run_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    categories = cost.get("by_category", {})
    metrics = {
        "calls": total.get("calls"),
        "reason_calls": categories.get("reason", {}).get("calls"),
        "review_calls": categories.get("review", {}).get("calls"),
        "worker_duration_ms": total.get("duration_ms"),
        "unarchived_attempts": total.get("unarchived_attempts"),
        "input_tokens": total.get("input_tokens"),
        "output_tokens": total.get("output_tokens"),
        "usage_recorded_calls": total.get("usage_recorded_calls"),
        "usage_unknown_calls": total.get("usage_unknown_calls"),
        "facts": len(facts), "intents": len(board.get("intents", [])),
        "residual_gaps": int(gaps), "coverage_complete": coverage == "true",
        "completion_correct": True,
    }
    return {
        "schema_version": 1, "kind": "audit_evaluation_observation", "run_id": run_id,
        "project_id": meta["id"], "project_instance_id": instance_id, "source_digest": source_digest,
        "graph_revision": meta.get("graph_revision"),
        "source_generation": meta.get("source_generation"),
        "plan_revision": meta.get("plan_revision"),
        "identifier_basis": "case_id" if case_map is not None else "fact_id",
        "confirmed": attributed(confirmed) if case_map is not None else sorted(confirmed),
        "candidates": attributed(candidates) if case_map is not None else sorted(candidates),
        "rejected": attributed(rejected) if case_map is not None else sorted(rejected),
        "unmapped_candidate_fact_ids": sorted(candidates - labels.keys()) if case_map is not None else [],
        "metrics": metrics,
        "attribution_sha256": hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest(),
        "interpretation": "Process completion is distinct from coverage and detection quality. "
                          "Case mapping is evaluator annotation, not worker evidence.",
    }


def _number(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite non-negative number")
    return float(value)


def compare_ablations(expected: set[str], baseline: list[dict], variant: list[dict], *,
                      min_recall: float = 0.8, max_recall_loss: float = 0.0,
                      require_fewer_facts: bool = False, allow_partial_coverage: bool = False) -> dict:
    """Compare real independent observations; fail closed on missing provenance."""
    if not expected:
        raise ValueError("Ablation requires a non-empty truth set")
    if not 0 <= min_recall <= 1 or not 0 <= max_recall_loss <= 1:
        raise ValueError("Recall thresholds must be between zero and one")
    if len(baseline) != 3 or len(variant) != 3:
        raise ValueError("Ablation requires three independent runs in each lane")
    rows = baseline + variant
    identities = [r.get("run_id") for r in rows]
    if any(not isinstance(i, str) or not i for i in identities) or len(set(identities)) != 6:
        raise ValueError("All six observations must have distinct run identities")
    instances = [r.get("project_instance_id") for r in rows]
    if any(not isinstance(i, str) or not i for i in instances) or len(set(instances)) != 6:
        raise ValueError("Independent ablation requires six fresh project instances")
    digests = {r.get("source_digest") for r in rows}
    if len(digests) != 1 or not re.fullmatch(r"[a-f0-9]{64}", next(iter(digests)) or ""):
        raise ValueError("All observations must use the same frozen source")
    metrics = ("calls", "reason_calls", "review_calls", "worker_duration_ms", "facts", "intents", "residual_gaps")
    lanes = {}
    for name, runs in (("baseline", baseline), ("variant", variant)):
        for row in runs:
            if row.get("kind") != "audit_evaluation_observation" or row.get("identifier_basis") != "case_id":
                raise ValueError("Use evaluation exports with evaluator case attribution")
            if row.get("unmapped_candidate_fact_ids"):
                raise ValueError("Attribute all candidate facts before comparing candidate recall")
            for key in ("confirmed", "candidates", "rejected"):
                values = row.get(key)
                if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values) or len(values) != len(set(values)):
                    raise ValueError(f"Invalid {key} case IDs")
            if set(row["confirmed"]) & set(row["rejected"]):
                raise ValueError("A case cannot be both confirmed and rejected")
            for metric in metrics:
                _number(row.get("metrics", {}).get(metric), metric)
            if row["metrics"].get("completion_correct") is not True or not isinstance(row["metrics"].get("coverage_complete"), bool):
                raise ValueError("Completion and coverage must be explicitly measured")
        lanes[name] = {
            "quality": evaluate(expected, [set(r["confirmed"]) for r in runs]),
            "candidate_quality": evaluate(expected, [set(r["candidates"]) | set(r["confirmed"]) for r in runs]),
            "mean_metrics": {k: round(sum(float(r["metrics"][k]) for r in runs) / 3, 3) for k in metrics},
            "coverage_complete_runs": sum(r["metrics"]["coverage_complete"] for r in runs),
        }
    before, after = lanes["baseline"], lanes["variant"]
    br = before["quality"]["stability"]["minimum_recall"]
    vr = after["quality"]["stability"]["minimum_recall"]
    checks = {
        "detections_observed": all(set(r["confirmed"]) & expected for r in rows),
        "minimum_recall": vr >= min_recall,
        "recall_preserved": vr + max_recall_loss >= br,
        "precision_preserved": min(r["precision"] for r in after["quality"]["runs"]) >= min(r["precision"] for r in before["quality"]["runs"]),
        "stability_preserved": after["quality"]["stability"]["all_run_jaccard"] >= before["quality"]["stability"]["all_run_jaccard"],
        "candidate_recall_preserved": after["candidate_quality"]["stability"]["minimum_recall"] >= before["candidate_quality"]["stability"]["minimum_recall"],
        "coverage_preserved": after["coverage_complete_runs"] >= before["coverage_complete_runs"] and after["mean_metrics"]["residual_gaps"] <= before["mean_metrics"]["residual_gaps"],
        "fewer_intents": after["mean_metrics"]["intents"] < before["mean_metrics"]["intents"],
        "fewer_facts": after["mean_metrics"]["facts"] < before["mean_metrics"]["facts"] if require_fewer_facts else after["mean_metrics"]["facts"] <= before["mean_metrics"]["facts"],
        "calls_not_increased": after["mean_metrics"]["calls"] <= before["mean_metrics"]["calls"],
    }
    if not allow_partial_coverage:
        checks["complete_recorded_coverage"] = all(r["metrics"]["coverage_complete"] and r["metrics"]["residual_gaps"] == 0 for r in rows)
    return {"schema_version": 1, "source_digest": next(iter(digests)), "expected": sorted(expected),
            "lanes": lanes, "checks": checks, "accepted": all(checks.values()),
            "acceptance_scope": "partial_coverage_comparison" if allow_partial_coverage else "complete_recorded_coverage",
            "cost_basis": "archived_calls_and_aggregate_worker_duration_only",
            "token_measurements_complete": all(r["metrics"].get("usage_unknown_calls") == 0 and r["metrics"].get("usage_recorded_calls") == r["metrics"]["calls"] for r in rows),
            "interpretation": "Candidate recall is diagnostic, not confirmed vulnerability recall. "
                              "Call-count acceptance is not token or currency savings. "
                              "Fixture observations do not establish real model performance."}


def load_observation(path: Path) -> dict:
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Observation must be a JSON object")
    return result
