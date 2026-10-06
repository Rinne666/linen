from copy import deepcopy
import json

from click.testing import CliRunner
import pytest

from linen.cli import main
from linen.dispatcher.analysis.evaluation import compare_ablations, observation


def snapshot():
    board = {
        "project": {"id": "p", "created_at": "2026-10-05T00:00:00Z", "status": "completed",
                    "source_generation": 1, "plan_revision": 1, "graph_revision": 6},
        "facts": [
            {"id": "snapshot", "type": "recon_snapshot", "source_generation": 1,
             "evidence": "snapshot: " + "a" * 64},
            {"id": "summary", "type": "audit_summary", "source_generation": 1,
             "evidence": "coverage_complete: false\nresidual_gaps: 2"},
            {"id": "confirmed", "semantic_type": "confirmed_finding", "source_generation": 1},
            {"id": "candidate", "semantic_type": "candidate_finding", "source_generation": 1},
            {"id": "legacy", "semantic_type": "confirmed_finding", "source_generation": 1, "legacy": True},
        ], "intents": [{"to": "summary", "concluded_at": "2026-10-05T01:00:00Z",
                        "type": "synthesize", "description": "@analysis:audit-summary",
                        "source_generation": 1, "plan_revision": 1}],
    }
    gate = {"project_id": "p", "ready": True, "source_generation": 1, "plan_revision": 1}
    cost = {"total": {"calls": 10, "duration_ms": 500, "unarchived_attempts": 1},
            "by_category": {"reason": {"calls": 3}, "review": {"calls": 2}}}
    return board, gate, cost


def test_export_separates_candidates_from_confirmation_and_preserves_unknown_tokens():
    board, gate, cost = snapshot()
    result = observation(board, gate, cost, {"confirmed": ["case-a"], "candidate": ["case-b"]})
    assert result["confirmed"] == ["case-a"]
    assert result["candidates"] == ["case-b"]
    assert result["metrics"]["coverage_complete"] is False
    assert result["metrics"]["input_tokens"] is None
    assert result["metrics"]["unarchived_attempts"] == 1
    assert "legacy" not in result["confirmed"]
    assert result["run_id"] == observation(board, gate, cost, {"confirmed": ["case-a"], "candidate": ["case-b"]})["run_id"]


@pytest.mark.parametrize("change", ["active", "wrong_generation", "ambiguous_snapshot", "contradictory_coverage"])
def test_export_rejects_incomplete_or_unbound_observations(change):
    board, gate, cost = snapshot()
    if change == "active":
        board["project"]["status"] = "active"
    elif change == "wrong_generation":
        gate["source_generation"] = 2
    elif change == "ambiguous_snapshot":
        board["facts"].append({"id": "s2", "type": "recon_snapshot", "source_generation": 1, "evidence": "snapshot: " + "b" * 64})
    else:
        board["facts"][1]["evidence"] = "coverage_complete: true\nresidual_gaps: 2"
    with pytest.raises(ValueError):
        observation(board, gate, cost)


def test_case_attribution_cannot_promote_candidate_or_omit_confirmed_findings():
    board, gate, cost = snapshot()
    with pytest.raises(ValueError, match="Every confirmed"):
        observation(board, gate, cost, {"candidate": ["case-a"]})
    with pytest.raises(ValueError, match="Case map"):
        observation(board, gate, cost, {"summary": ["case-a"]})


def lanes():
    board, gate, cost = snapshot()
    result = observation(board, gate, cost, {"confirmed": ["case-a"], "candidate": ["case-b"]})
    baseline, variant = [], []
    for index in range(6):
        row = deepcopy(result)
        row["run_id"] = f"independent-{index}"
        row["project_instance_id"] = f"fresh-project-{index}"
        row["metrics"].update(facts=20 if index < 3 else 10, intents=25 if index < 3 else 12,
                               coverage_complete=True, residual_gaps=0)
        (baseline if index < 3 else variant).append(row)
    return baseline, variant


def test_ablation_accepts_measured_reduction_without_weakening_detection_or_coverage():
    baseline, variant = lanes()
    report = compare_ablations({"case-a"}, baseline, variant, require_fewer_facts=True)
    assert report["accepted"] is True
    assert report["lanes"]["variant"]["mean_metrics"]["facts"] == 10


@pytest.mark.parametrize("change", ["recall", "precision", "coverage", "intents", "facts"])
def test_ablation_rejects_quality_loss_and_unmeasured_simplification(change):
    baseline, variant = lanes()
    for row in variant:
        if change == "recall":
            row["confirmed"] = []
        elif change == "precision":
            row["confirmed"].append("unexpected")
        elif change == "coverage":
            row["metrics"]["residual_gaps"] = 3
        else:
            row["metrics"][change] = 30
    assert compare_ablations({"case-a"}, baseline, variant, require_fewer_facts=True)["accepted"] is False


@pytest.mark.parametrize("change", ["duplicate", "source", "nan", "unknown", "unmapped"])
def test_ablation_rejects_replayed_runs_and_missing_measurements(change):
    baseline, variant = lanes()
    if change == "duplicate":
        variant[0]["run_id"] = baseline[0]["run_id"]
    elif change == "source":
        variant[0]["source_digest"] = "b" * 64
    elif change == "unmapped":
        variant[0]["unmapped_candidate_fact_ids"] = ["f4"]
    else:
        variant[0]["metrics"]["calls"] = float("nan") if change == "nan" else None
    with pytest.raises(ValueError):
        compare_ablations({"case-a"}, baseline, variant)


def test_evaluation_cli_rejects_changing_board_and_never_overwrites_output(tmp_path, monkeypatch):
    board, gate, cost = snapshot()

    class Response:
        def __init__(self, value):
            self.value = value
        def raise_for_status(self):
            pass
        def json(self):
            return self.value

    values = [board, gate, cost, board]
    monkeypatch.setattr("linen.cli.requests.get", lambda *args, **kwargs: Response(values.pop(0)))
    output = tmp_path / "keep.json"
    output.write_text("existing")
    result = CliRunner().invoke(main, ["audit-evaluation-export", "--project-id", "p", "--output", str(output)])
    assert result.exit_code == 1
    assert output.read_text() == "existing"
    after = deepcopy(board)
    after["project"]["graph_revision"] = 7
    values.extend([board, gate, cost, after] * 3)
    result = CliRunner().invoke(main, ["audit-evaluation-export", "--project-id", "p"])
    assert result.exit_code == 1
    assert "changed during export" in result.output


def test_ablation_cli_fails_three_empty_detections_even_if_they_are_stable(tmp_path):
    expected = tmp_path / "truth.json"
    expected.write_text(json.dumps({"expected": ["case-a"]}))
    baseline, variant = lanes()
    args = ["audit-ablation", "--expected", str(expected)]
    for lane, rows in (("baseline", baseline), ("variant", variant)):
        for index, row in enumerate(rows):
            row["confirmed"] = []
            path = tmp_path / f"{lane}-{index}.json"
            path.write_text(json.dumps(row))
            args.extend([f"--{lane}", str(path)])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert '"accepted": false' in result.output
    assert "minimum_recall" in result.output


def test_export_does_not_select_old_plan_summary_with_later_timestamp():
    board, gate, cost = snapshot()
    board["facts"].append({"id": "old-summary", "type": "audit_summary", "source_generation": 1,
                           "evidence": "coverage_complete: true\nresidual_gaps: 0"})
    board["intents"].append({**board["intents"][0], "to": "old-summary", "plan_revision": 2,
                             "concluded_at": "2026-10-06T01:00:00Z"})
    assert observation(board, gate, cost)["metrics"]["residual_gaps"] == 2
    board["intents"][0]["plan_revision"] = 3
    with pytest.raises(ValueError, match="summary"):
        observation(board, gate, cost)


def test_partial_coverage_requires_explicit_mode_and_zero_detections_never_pass():
    baseline, variant = lanes()
    for row in baseline + variant:
        row["metrics"].update(coverage_complete=False, residual_gaps=2)
    assert not compare_ablations({"case-a"}, baseline, variant)["accepted"]
    partial = compare_ablations({"case-a"}, baseline, variant, allow_partial_coverage=True)
    assert partial["accepted"]
    assert partial["acceptance_scope"] == "partial_coverage_comparison"
    assert not partial["token_measurements_complete"]
    for row in baseline + variant:
        row["confirmed"] = []
    assert not compare_ablations({"case-a"}, baseline, variant, min_recall=0,
                                 allow_partial_coverage=True)["accepted"]


def test_same_project_replans_do_not_count_as_independent_runs():
    baseline, variant = lanes()
    variant[0]["project_instance_id"] = baseline[0]["project_instance_id"]
    with pytest.raises(ValueError, match="fresh project"):
        compare_ablations({"case-a"}, baseline, variant)
