from copy import deepcopy
import hashlib
import json

from click.testing import CliRunner
import pytest

from linen.cli import main
from linen.dispatcher.analysis.case_benchmark import (
    BenchmarkPlan, TruthSet, case_observation, compare_case_runs, digest,
)


def scenario():
    truth = TruthSet.model_validate({
        "expected": ["case-a", "case-b"], "negative_controls": ["case-c", "case-d"],
        "labels": [
            {"id": case, "category": category, "vulnerable": positive,
             "cwe": cwe, "dimensions": ["cross-file"]}
            for case, category, positive, cwe in (
                ("case-a", "sqli", True, "89"), ("case-b", "authz", True, "639"),
                ("case-c", "sqli", False, "89"), ("case-d", "authz", False, "639"),
            )
        ],
    })
    plan = BenchmarkPlan(
        registered_at="2026-10-06T00:00:00Z",
        suite_id="controlled", source_digest="a" * 64, truth_digest=digest(truth.model_dump()),
        config_digest="b" * 64, planned_runs=["trial-1", "trial-2", "trial-3"],
        detection_level="candidate", max_run_records=20, wall_clock_budget_seconds=30,
    )
    board = {
        "project": {"id": "p", "created_at": "2026-10-07T00:00:00Z", "status": "completed",
                    "source_generation": 1, "plan_revision": 1, "graph_revision": 8},
        "facts": [
            {"id": "snapshot", "type": "recon_snapshot", "source_generation": 1,
             "evidence": "snapshot: " + "a" * 64},
            {"id": "summary", "type": "audit_summary", "source_generation": 1,
             "evidence": "coverage_complete: true\nresidual_gaps: 0"},
            {"id": "f1", "type": "vulnerability", "semantic_type": "confirmed_finding",
             "source_generation": 1, "evidence": "file: api.py:3",
             "description": "The prose mentions case-a, case-b and case-c."},
            {"id": "f2", "type": "vulnerability", "semantic_type": "candidate_finding",
             "source_generation": 1, "status": "triaged", "evidence": "file: policy.py:4"},
            {"id": "f3", "type": "sanitizer", "source_generation": 1, "evidence": "file: api.py:8"},
            {"id": "f4", "type": "dataflow", "source_generation": 1, "evidence": "file: policy.py:10"},
        ],
        "intents": [{"to": "summary", "type": "synthesize", "description": "@analysis:audit-summary",
                     "source_generation": 1, "plan_revision": 1, "concluded_at": "2026-10-07T00:00:15Z"}],
        "reviews": [{"id": f"r{i}", "fact_id": f"f{i}", "verdict": "VALID", "confidence": "firm",
                     "source_generation": 1} for i in range(1, 5)],
    }
    gate = {"project_id": "p", "source_generation": 1, "plan_revision": 1, "ready": True,
            "execution_status": "completed", "blockers": []}
    cost = {"total": {"calls": 12, "duration_ms": 20_000, "input_tokens": 100, "output_tokens": 20}}
    runs = [
        {"status": "succeeded", "started_at": "2026-10-07T00:00:00Z", "finished_at": "2026-10-07T00:00:10Z"},
        {"status": "succeeded", "started_at": "2026-10-07T00:00:05Z", "finished_at": "2026-10-07T00:00:15Z"},
    ]
    mapping = {f"f{i}": [case] for i, case in enumerate(("case-a", "case-b", "case-c", "case-d"), 1)}
    assessments = {
        case: {"disposition": "vulnerable" if i < 3 else "protected", "fact_ids": [f"f{i}"],
               "rationale": "Evaluator inspected the independently reviewed technical evidence."}
        for i, case in enumerate(("case-a", "case-b", "case-c", "case-d"), 1)
    }
    return truth, plan, board, gate, cost, runs, mapping, assessments


def observe(data, *, label="trial-1", allow_incomplete=False):
    truth, plan, board, gate, cost, runs, mapping, assessments = data
    return case_observation(board, gate, cost, runs, truth, plan, label, plan.config_digest,
                            mapping, assessments, allow_incomplete=allow_incomplete)


def three_runs():
    data = scenario()
    observations = []
    for i in range(1, 4):
        data[2]["project"]["id"] = f"p-{i}"
        data[2]["project"]["created_at"] = data[1].registered_at
        data[3]["project_id"] = f"p-{i}"
        observations.append(observe(data, label=f"trial-{i}"))
    return data[0], data[1], observations


def test_explicit_attribution_separates_candidates_confirmation_and_coverage():
    result = observe(scenario())
    assert result["scores"]["candidate"]["recall"] == 1
    assert result["scores"]["confirmed"]["recall"] == 0.5
    assert result["scores"]["confirmed"]["true_positive_ids"] == ["case-a"]
    assert result["scores"]["confirmed"]["true_negative_ids"] == ["case-c", "case-d"]
    assert result["scores"]["candidate"]["case_coverage"] == 1
    assert result["by_category"]["confirmed"]["authz"]["recall"] == 0
    assert result["by_cwe"]["candidate"]["89"]["false_positive_rate"] == 0
    assert result["by_dimension"]["candidate"]["cross-file"]["case_count"] == 4
    assert result["metrics"]["run_span_ms"] == 15_000
    assert result["metrics"]["worker_duration_ms"] == 20_000


def test_missing_negative_assessment_is_not_a_true_negative():
    data = scenario()
    del data[7]["case-d"]
    result = observe(data)["scores"]["confirmed"]
    assert result["true_negative_ids"] == ["case-c"]
    assert result["unassessed_ids"] == ["case-d"]
    assert result["case_coverage"] == 0.75


def test_static_review_does_not_promote_a_candidate():
    data = scenario()
    data[2]["facts"][3]["description"] = "Confirmed exploit in case-b"
    result = observe(data)
    assert result["cases"][1]["disposition"] == "vulnerable"
    assert result["cases"][1]["confirmed"] is False
    assert result["scores"]["confirmed"]["recall"] == 0.5


@pytest.mark.parametrize("change", ["unreviewed", "stale_review", "legacy_fact", "policy_fact", "wrong_mapping"])
def test_conclusive_coverage_requires_current_reviewed_technical_evidence(change):
    data = scenario()
    if change == "unreviewed":
        data[2]["reviews"] = []
    elif change == "stale_review":
        data[2]["reviews"][0]["source_generation"] = 0
    elif change == "legacy_fact":
        data[2]["facts"][2]["legacy"] = True
    elif change == "policy_fact":
        data[2]["facts"][4]["type"] = "policy_evidence"
    else:
        data[7]["case-c"]["fact_ids"] = ["f4"]
    with pytest.raises(ValueError):
        observe(data)


def test_candidate_false_positive_is_separate_from_final_false_positive():
    data = scenario()
    data[6]["f2"].append("case-c")
    result = observe(data)
    assert result["scores"]["candidate"]["false_positive_rate"] == 0.5
    assert result["scores"]["confirmed"]["false_positive_rate"] == 0


@pytest.mark.parametrize("verdict,confidence", [("INVALID", "firm"), ("NEEDS_REVIEW", "firm"), ("VALID", "tentative")])
def test_new_review_cannot_be_hidden_by_an_older_valid_assessment(verdict, confidence):
    data = scenario()
    data[2]["reviews"].append({"id": "r-new", "fact_id": "f3", "verdict": verdict,
                                "confidence": confidence, "source_generation": 1, "created_at": "2026-10-08T00:00:00Z"})
    with pytest.raises(ValueError, match="current firm/certain VALID"):
        observe(data)


def test_repaired_case_assessment_uses_only_the_latest_valid_review():
    data = scenario()
    data[2]["reviews"].extend([
        {"id": "r-invalid", "fact_id": "f3", "verdict": "INVALID", "confidence": "firm", "source_generation": 1, "created_at": "2026-10-08T00:00:00Z"},
        {"id": "r-repair", "fact_id": "f3", "verdict": "VALID", "confidence": "firm", "source_generation": 1, "created_at": "2026-10-08T00:01:00Z"},
    ])
    assert observe(data)["cases"][2]["review_ids"] == ["r-repair"]
    data[6]["f1"].append("unknown-case")
    result = observe(data)
    assert result["scores"]["confirmed"]["precision"] == 0.5
    assert result["scores"]["confirmed"]["unexpected_detection_ids"] == ["unknown-case"]


def test_unmapped_findings_cannot_disappear_from_scoring():
    data = scenario()
    del data[6]["f2"]
    with pytest.raises(ValueError, match="Every current candidate"):
        observe(data)


def test_three_registered_runs_pass_discovery_without_claiming_confirmation():
    truth, plan, observations = three_runs()
    report = compare_case_runs(truth, plan, observations)
    assert report["accepted"] is True
    assert report["completion_rate"] == 1
    confirmed_plan = plan.model_copy(update={"detection_level": "confirmed"})
    for row in observations:
        row["plan_digest"] = digest(confirmed_plan.model_dump())
    report = compare_case_runs(truth, confirmed_plan, observations)
    assert report["accepted"] is False
    assert report["checks"]["minimum_recall"] is False
    assert report["checks"]["category_recall"] is False


def test_blocked_run_is_retained_in_completion_rate():
    truth, plan, observations = three_runs()
    data = scenario()
    data[2]["project"]["id"] = "p-2"
    data[3]["project_id"] = "p-2"
    data[2]["project"]["status"] = "stopped"
    data[3].update(ready=False, execution_status="blocked", blockers=["worker routing failed"])
    with pytest.raises(ValueError, match="--allow-incomplete"):
        observe(data, label="trial-2")
    observations[1] = observe(data, label="trial-2", allow_incomplete=True)
    report = compare_case_runs(truth, plan, observations)
    assert report["completion_rate"] == pytest.approx(2 / 3)
    assert not report["accepted"]
    assert observations[1]["blockers"] == ["worker routing failed"]
    assert observations[1]["metrics"]["coverage_complete"] is None


def test_failure_before_snapshot_can_be_exported_without_inventing_source_binding():
    data = scenario()
    data[2].update(facts=[], reviews=[], intents=[])
    data[2]["project"]["status"] = "stopped"
    data[3].update(ready=False, execution_status="blocked")
    data[6].clear()
    data[7].clear()
    result = observe(data, allow_incomplete=True)
    assert result["source_digest"] is None
    assert result["source_verified"] is False
    assert result["scores"]["confirmed"]["case_coverage"] == 0
    assert result["scores"]["confirmed"]["true_negative_ids"] == []


@pytest.mark.parametrize("change", ["reuse", "replacement", "source", "label", "flags", "unreviewed", "budget", "unknown_time"])
def test_replay_replacement_provenance_and_measurement_failures_are_rejected(change):
    truth, plan, observations = three_runs()
    if change == "reuse":
        observations[1]["project_instance_id"] = observations[0]["project_instance_id"]
    elif change == "replacement":
        observations[1]["run_label"] = "a-later-success"
    elif change == "source":
        observations[1]["config_digest"] = "c" * 64
    elif change == "label":
        observations[1]["cases"][2]["vulnerable"] = True
    elif change == "flags":
        observations[1]["cases"][2]["confirmed"] = "false"
    elif change == "unreviewed":
        observations[1]["cases"][2]["review_ids"] = []
    else:
        observations[1]["metrics"]["run_span_ms"] = 31_000 if change == "budget" else None
        assert not compare_case_runs(truth, plan, observations)["accepted"]
        return
    with pytest.raises(ValueError):
        compare_case_runs(truth, plan, observations)


def test_truth_set_rejects_contradictions_and_duplicates():
    truth = scenario()[0].model_dump()
    truth["labels"][0]["vulnerable"] = False
    with pytest.raises(ValueError, match="contradicts"):
        TruthSet.model_validate(truth)
    truth = scenario()[0].model_dump()
    truth["negative_controls"].append("case-c")
    with pytest.raises(ValueError, match="unique"):
        TruthSet.model_validate(truth)


def test_registration_after_the_projects_cannot_accept_a_retrospective_batch():
    truth, plan, observations = three_runs()
    late_plan = plan.model_copy(update={"registered_at": "2026-10-08T00:00:00Z"})
    for observation in observations:
        observation["plan_digest"] = digest(late_plan.model_dump())
    result = compare_case_runs(truth, late_plan, observations)
    assert not result["accepted"]
    assert result["checks"]["registered_before_projects"] is False


def test_three_empty_detection_sets_are_not_capability_acceptance():
    truth, plan, observations = three_runs()
    permissive = plan.model_copy(update={"min_recall": 0, "min_category_recall": 0})
    for observation in observations:
        observation["plan_digest"] = digest(permissive.model_dump())
        for row in observation["cases"]:
            row["candidate"] = row["confirmed"] = False
    result = compare_case_runs(truth, permissive, observations)
    assert result["stability"]["all_run_jaccard"] == 1
    assert result["checks"]["positive_detections_observed"] is False
    assert not result["accepted"]


def test_case_export_reads_saved_inputs_without_network_or_overwriting(tmp_path, monkeypatch):
    data = scenario()
    config = tmp_path / "dispatch.yaml"
    config.write_text("configuration fingerprint only\n")
    data = list(data)
    data[1] = data[1].model_copy(update={"config_digest": hashlib.sha256(config.read_bytes()).hexdigest()})
    documents = {
        "truth.json": data[0].model_dump(), "plan.json": data[1].model_dump(),
        "map.json": data[6], "assessments.json": data[7],
        "snapshot.json": dict(zip(("board", "gate", "cost", "runs"), data[2:6])),
    }
    for name, document in documents.items():
        (tmp_path / name).write_text(json.dumps(document))
    monkeypatch.setattr("linen.cli.requests.get", lambda *_args, **_kwargs: pytest.fail("offline export contacted API"))
    output = tmp_path / "result.json"
    args = ["audit-case-export", "--snapshot", str(tmp_path / "snapshot.json"),
            "--expected", str(tmp_path / "truth.json"), "--plan", str(tmp_path / "plan.json"),
            "--config", str(config), "--case-map", str(tmp_path / "map.json"),
            "--case-assessments", str(tmp_path / "assessments.json"),
            "--run-label", "trial-1", "--output", str(output)]
    runner = CliRunner()
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["scores"]["candidate"]["recall"] == 1
    original = output.read_bytes()
    assert runner.invoke(main, args).exit_code == 1
    assert output.read_bytes() == original


def test_source_root_plan_predicts_the_dispatcher_snapshot_without_mutating_source(tmp_path):
    from conftest import make_config
    from linen.dispatcher.analysis.recon import create_snapshot

    target = tmp_path / "target"
    target.mkdir()
    source = "def endpoint(value):\n    return value\n"
    (target / "app.py").write_text(source)
    config = make_config()
    config.local.workspace_root = str(tmp_path / "workers")
    config_path = tmp_path / "dispatch.json"
    config_path.write_text(json.dumps(config.model_dump(mode="json")))
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(scenario()[0].model_dump()))
    plan_path = tmp_path / "plan.json"
    result = CliRunner().invoke(main, [
        "audit-case-plan", "--expected", str(truth_path), "--config", str(config_path),
        "--source-root", str(target), "--suite-id", "controlled", "--output", str(plan_path),
    ])
    assert result.exit_code == 0, result.output
    fact = create_snapshot(target, tmp_path / "workers" / "p", 1, config.audit.recon)
    plan = json.loads(plan_path.read_text())
    assert f"snapshot: {plan['source_digest']}" in fact["evidence"]
    assert (target / "app.py").read_text() == source
    assert sorted(p.name for p in target.iterdir()) == ["app.py"]


def test_plan_and_three_run_cli_never_overwrite_or_accept_blocked_runs(tmp_path, monkeypatch):
    from conftest import make_config

    data = scenario()
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(data[0].model_dump()))
    config_path = tmp_path / "dispatch.json"
    config_path.write_text(json.dumps(make_config().model_dump(mode="json")))
    plan_path = tmp_path / "plan.json"
    runner = CliRunner()
    args = ["audit-case-plan", "--expected", str(truth_path), "--config", str(config_path),
            "--source-digest", "a" * 64, "--suite-id", "controlled", "--level", "candidate",
            "--output", str(plan_path)]
    assert runner.invoke(main, args).exit_code == 0
    original = plan_path.read_bytes()
    assert runner.invoke(main, args).exit_code == 1
    assert plan_path.read_bytes() == original
    plan = BenchmarkPlan.model_validate_json(original)
    mapping = tmp_path / "map.json"
    mapping.write_text(json.dumps(data[6]))
    assessments = tmp_path / "assessments.json"
    assessments.write_text(json.dumps(data[7]))

    class Response:
        def __init__(self, value):
            self.value = deepcopy(value)
        def raise_for_status(self):
            pass
        def json(self):
            return self.value

    values = []
    monkeypatch.setattr("linen.cli.requests.get", lambda *_args, **_kwargs: Response(values.pop(0)))
    paths = []
    for i in range(1, 4):
        data[2]["project"]["id"] = f"p-{i}"
        data[3]["project_id"] = f"p-{i}"
        if i == 2:
            data[2]["project"]["status"] = "stopped"
            data[3]["ready"] = False
        else:
            data[2]["project"]["status"] = "completed"
            data[3]["ready"] = True
        data[2]["project"]["created_at"] = plan.registered_at
        values.extend([data[2], data[3], data[4], data[5], data[2]])
        output = tmp_path / f"run-{i}.json"
        result = runner.invoke(main, [
            "audit-case-export", "--project-id", f"p-{i}", "--expected", str(truth_path),
            "--plan", str(plan_path), "--config", str(config_path), "--run-label", f"run-{i}",
            "--case-map", str(mapping), "--case-assessments", str(assessments),
            "--allow-incomplete", "--output", str(output),
        ])
        assert result.exit_code == 0, result.output
        assert json.loads(output.read_text())["config_digest"] == hashlib.sha256(config_path.read_bytes()).hexdigest()
        paths.append(output)
    args = ["audit-benchmark", "--expected", str(truth_path), "--plan", str(plan_path)]
    for path in paths:
        args.extend(["--run", str(path)])
    result = runner.invoke(main, args)
    assert result.exit_code == 1
    assert '"completion_rate": 0.666' in result.output
    assert '"accepted": false' in result.output
