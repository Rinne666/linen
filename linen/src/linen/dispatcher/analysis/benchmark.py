"""Small truth-set benchmark for three independent audit runs."""
from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path

import yaml


def _load(path: Path):
    text = path.read_text(encoding="utf-8")
    value = yaml.safe_load(text) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"Benchmark document must be an object: {path}")
    return value


def expected_ids(path: Path) -> set[str]:
    value = _load(path).get("expected")
    if not isinstance(value, list):
        raise ValueError("Truth set requires an expected array")
    result = set()
    for item in value:
        identifier = item if isinstance(item, str) else item.get("id") if isinstance(item, dict) else None
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("Every expected vulnerability requires a non-empty id")
        result.add(identifier.strip())
    if len(result) != len(value):
        raise ValueError("Expected vulnerability ids must be unique")
    return result


def confirmed_ids(path: Path) -> set[str]:
    value = _load(path).get("confirmed")
    if not isinstance(value, list):
        raise ValueError(f"Run requires a confirmed array: {path}")
    result = set()
    for item in value:
        identifier = item if isinstance(item, str) else item.get("id") if isinstance(item, dict) else None
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError(f"Every confirmed result requires a non-empty id: {path}")
        result.add(identifier.strip())
    if len(result) != len(value):
        raise ValueError(f"Confirmed ids must be unique: {path}")
    return result


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 1.0


def evaluate(expected: set[str], runs: list[set[str]]) -> dict:
    """Return recall, precision, and cross-run Jaccard stability.

    Exactly three runs are required so a one-off lucky hit cannot be presented
    as stable analysis behavior.
    """
    if len(runs) != 3:
        raise ValueError("Audit benchmark requires exactly three independent runs")
    per_run = []
    for index, found in enumerate(runs, start=1):
        true_positive = expected & found
        per_run.append({
            "run": index,
            "confirmed": sorted(found),
            "true_positives": sorted(true_positive),
            "missed": sorted(expected - found),
            "unexpected": sorted(found - expected),
            "confirmed_count": len(found),
            "recall": _ratio(len(true_positive), len(expected)),
            "precision": _ratio(len(true_positive), len(found)),
        })
    pairwise = []
    for (left_index, left), (right_index, right) in combinations(enumerate(runs, start=1), 2):
        pairwise.append({
            "runs": [left_index, right_index],
            "jaccard": _ratio(len(left & right), len(left | right)),
        })
    union = set().union(*runs)
    intersection = set.intersection(*runs)
    return {
        "schema_version": 1,
        "expected": sorted(expected),
        "runs": per_run,
        "stability": {
            "all_run_intersection": sorted(intersection),
            "all_run_union": sorted(union),
            "all_run_jaccard": _ratio(len(intersection), len(union)),
            "mean_pairwise_jaccard": round(sum(row["jaccard"] for row in pairwise) / len(pairwise), 6),
            "pairwise": pairwise,
            "minimum_recall": min(row["recall"] for row in per_run),
        },
    }


def evaluate_files(expected_path: Path, run_paths: tuple[Path, ...]) -> dict:
    return evaluate(expected_ids(expected_path), [confirmed_ids(path) for path in run_paths])


_WORKFLOW_METRICS = (
    "review_calls", "pi_calls", "tokens", "wall_time_ms", "repeated_reads",
    "cross_endpoint_chains",
)


def compare_strategies(
    expected: set[str],
    file_topic_runs: list[dict],
    trust_boundary_runs: list[dict],
) -> dict:
    """Compare three runs per coverage strategy using the same truth set.

    Each run contains ``confirmed`` IDs and measured ``metrics``. This keeps
    the comparison in the existing truth-set benchmark instead of adding a
    second coverage planner or test-only workflow.
    """
    strategies = {
        "file_topic": file_topic_runs,
        "trust_boundary": trust_boundary_runs,
    }
    report = {"schema_version": 1, "expected": sorted(expected), "strategies": {}}
    for name, runs in strategies.items():
        if len(runs) != 3:
            raise ValueError(f"{name} requires exactly three independent runs")
        confirmed = []
        metric_rows = []
        for index, run in enumerate(runs, start=1):
            if not isinstance(run.get("confirmed"), list):
                raise ValueError(f"{name} run {index} requires confirmed IDs")
            if not isinstance(run.get("rejected"), list):
                raise ValueError(f"{name} run {index} requires rejected IDs")
            if len(set(run["confirmed"])) != len(run["confirmed"]):
                raise ValueError(f"{name} run {index} contains duplicate confirmed IDs")
            if len(set(run["rejected"])) != len(run["rejected"]):
                raise ValueError(f"{name} run {index} contains duplicate rejected IDs")
            if set(run["confirmed"]) & set(run["rejected"]):
                raise ValueError(f"{name} run {index} cannot confirm and reject the same ID")
            metrics = run.get("metrics")
            if not isinstance(metrics, dict):
                raise ValueError(f"{name} run {index} requires metrics")
            missing = [key for key in _WORKFLOW_METRICS if not isinstance(metrics.get(key), (int, float))]
            if missing:
                raise ValueError(f"{name} run {index} is missing metrics: {', '.join(missing)}")
            if not isinstance(metrics.get("completion_correct"), bool):
                raise ValueError(f"{name} run {index} requires completion_correct")
            confirmed.append(set(run["confirmed"]))
            metric_rows.append(metrics)
        quality = evaluate(expected, confirmed)
        averages = {
            key: round(sum(float(row[key]) for row in metric_rows) / len(metric_rows), 3)
            for key in _WORKFLOW_METRICS
        }
        averages["completion_correct_runs"] = sum(
            bool(row["completion_correct"]) for row in metric_rows
        )
        averages["confirmed_findings"] = round(
            sum(len(run["confirmed"]) for run in runs) / len(runs), 3,
        )
        averages["rejected_findings"] = round(
            sum(len(run["rejected"]) for run in runs) / len(runs), 3,
        )
        report["strategies"][name] = {
            **quality,
            "mean_metrics": averages,
            "completion_stability": all(row["completion_correct"] for row in metric_rows),
        }
    return report


def evaluate_strategy_files(
    expected_path: Path,
    file_topic_paths: tuple[Path, ...],
    trust_boundary_paths: tuple[Path, ...],
) -> dict:
    return compare_strategies(
        expected_ids(expected_path),
        [_load(path) for path in file_topic_paths],
        [_load(path) for path in trust_boundary_paths],
    )
