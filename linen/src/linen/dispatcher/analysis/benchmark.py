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
    as stable scanner behavior.
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
