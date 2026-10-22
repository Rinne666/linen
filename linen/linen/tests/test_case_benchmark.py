from copy import deepcopy
import errno
import hashlib
import json
from pathlib import Path
import threading

from click.testing import CliRunner
import pytest

from linen.cli import main
from linen.dispatcher.analysis import case_benchmark
from linen.dispatcher.analysis.case_benchmark import (
    CASE_EXPORT_KEYS, CASE_EXPORT_ROW_KEYS, BenchmarkPlan, ExportPublishError,
    ExportValidationError, TruthSet, case_observation, compare_case_runs, digest,
    publish_case_export, validate_case_export,
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


# --- CF-S1-G3: the export boundary validates before it publishes ------------
# The audit-case-export artifact is a benchmark case observation.  It carries
# no Cloudflare checks and no coverage identity, so the boundary validates its
# own real schema, publishes atomically, and never lets --allow-incomplete
# excuse a structural failure.


def export_candidate(data, *, allow_incomplete=False):
    truth, plan, board, gate, cost, runs, mapping, assessments = data
    observation = case_observation(board, gate, cost, runs, truth, plan, "trial-1",
                                   plan.config_digest, mapping, assessments,
                                   allow_incomplete=allow_incomplete)
    return observation, truth, plan, board


def check_export(observation, truth, plan, board, *, allow_incomplete=False):
    return validate_case_export(observation, truth=truth, registered=plan, board=board,
                                 allow_incomplete=allow_incomplete)


def blocked_run():
    data = scenario()
    data[2]["project"]["status"] = "stopped"
    data[3].update(ready=False, execution_status="blocked",
                   blockers=["worker routing failed"])
    return data


def export_documents(tmp_path, data):
    config = tmp_path / "dispatch.yaml"
    config.write_text("configuration fingerprint only\n")
    plan = data[1].model_copy(update={
        "config_digest": hashlib.sha256(config.read_bytes()).hexdigest()})
    documents = {
        "truth.json": data[0].model_dump(), "plan.json": plan.model_dump(),
        "map.json": data[6], "assessments.json": data[7],
        "snapshot.json": dict(zip(("board", "gate", "cost", "runs"), data[2:6])),
    }
    for name, document in documents.items():
        (tmp_path / name).write_text(json.dumps(document))
    return ["audit-case-export", "--snapshot", str(tmp_path / "snapshot.json"),
            "--expected", str(tmp_path / "truth.json"), "--plan", str(tmp_path / "plan.json"),
            "--config", str(config), "--case-map", str(tmp_path / "map.json"),
            "--case-assessments", str(tmp_path / "assessments.json"),
            "--run-label", "trial-1", "--output", str(tmp_path / "result.json")]


def test_g3_t01_a_valid_complete_export_is_accepted():
    observation, truth, plan, board = export_candidate(scenario())
    assert check_export(observation, truth, plan, board) == "complete"


def test_g3_t02_missing_or_mistyped_fields_are_rejected():
    observation, truth, plan, board = export_candidate(scenario())
    del observation["kind"]
    with pytest.raises(ExportValidationError) as invalid:
        check_export(observation, truth, plan, board)
    assert invalid.value.classification == "invalid"

    observation, truth, plan, board = export_candidate(scenario())
    observation["completed"] = "true"
    with pytest.raises(ExportValidationError):
        check_export(observation, truth, plan, board)


def test_g3_t03_a_case_may_not_reference_an_unrecorded_fact():
    observation, truth, plan, board = export_candidate(scenario())
    observation["cases"][0]["confirmed_fact_ids"] = ["ghost-fact"]
    with pytest.raises(ExportValidationError, match="confirmation authority"):
        check_export(observation, truth, plan, board)

    observation, truth, plan, board = export_candidate(scenario())
    observation["cases"][1]["assessment_fact_ids"] = ["f4"]
    with pytest.raises(ExportValidationError, match="not mapped to the case"):
        check_export(observation, truth, plan, board)


def test_g3_t04_duplicate_or_conflicting_assessments_are_rejected():
    observation, truth, plan, board = export_candidate(scenario())
    observation["cases"].append(dict(observation["cases"][0]))
    with pytest.raises(ExportValidationError, match="unique"):
        check_export(observation, truth, plan, board)

    observation, truth, plan, board = export_candidate(scenario())
    observation["cases"][0]["review_ids"] = []
    with pytest.raises(ExportValidationError, match="reviewed supporting evidence"):
        check_export(observation, truth, plan, board)


def test_g3_t05_to_t07_coverage_identity_is_not_part_of_this_export():
    """EX03 is not applicable here: this artifact carries no coverage identity."""

    observation, truth, plan, board = export_candidate(scenario())
    assert "coverage_id" not in observation
    assert all("coverage_id" not in row for row in observation["cases"])

    polluted = dict(observation)
    polluted["coverage_id"] = ["cov-0001"]
    with pytest.raises(ExportValidationError):
        check_export(polluted, truth, plan, board)

    polluted = dict(observation)
    polluted["cases"] = [dict(row) for row in observation["cases"]]
    polluted["cases"][0]["coverage_id"] = "cov-0001"
    with pytest.raises(ExportValidationError):
        check_export(polluted, truth, plan, board)


def test_g3_t08_an_incomplete_export_is_refused_without_explicit_permission():
    observation, truth, plan, board = export_candidate(blocked_run(), allow_incomplete=True)
    with pytest.raises(ExportValidationError) as refused:
        check_export(observation, truth, plan, board)
    assert refused.value.classification == "incomplete"


def test_g3_t09_an_explicitly_permitted_incomplete_export_stays_marked_incomplete():
    observation, truth, plan, board = export_candidate(blocked_run(), allow_incomplete=True)
    assert check_export(observation, truth, plan, board, allow_incomplete=True) == "incomplete"
    assert observation["completed"] is False
    assert observation["execution_status"] == "blocked"
    assert observation["blockers"] == ["worker routing failed"]


def test_g3_t10_allow_incomplete_never_excuses_an_invalid_structure():
    observation, truth, plan, board = export_candidate(blocked_run(), allow_incomplete=True)
    del observation["kind"]
    with pytest.raises(ExportValidationError) as invalid:
        check_export(observation, truth, plan, board, allow_incomplete=True)
    assert invalid.value.classification == "invalid"


def test_g3_t11_the_export_may_not_claim_unverified_local_evidence():
    observation, truth, plan, board = export_candidate(scenario())
    for field in ("artifact", "local_checks", "checks", "agent_id"):
        polluted = dict(observation)
        polluted["metrics"] = dict(observation["metrics"])
        polluted["metrics"][field] = ["agents/ag-1/artifacts/evidence.json"]
        with pytest.raises(ExportValidationError, match="local evidence"):
            check_export(polluted, truth, plan, board)

    polluted = dict(observation)
    polluted["cases"] = [dict(row) for row in observation["cases"]]
    polluted["cases"][0]["local_checks"] = []
    with pytest.raises(ExportValidationError):
        check_export(polluted, truth, plan, board)


def test_g3_t12_a_rejected_export_leaves_an_existing_artifact_untouched(tmp_path, monkeypatch):
    args = export_documents(tmp_path, scenario())
    output = tmp_path / "result.json"
    runner = CliRunner()
    assert runner.invoke(main, args).exit_code == 0
    original = output.read_bytes()

    builder = case_benchmark.case_observation

    def broken(*positional, **keywords):
        observation = builder(*positional, **keywords)
        observation["cases"][0]["confirmed_fact_ids"] = ["ghost-fact"]
        return observation

    monkeypatch.setattr(case_benchmark, "case_observation", broken)
    result = runner.invoke(main, args)
    assert result.exit_code == 1
    assert output.read_bytes() == original
    assert [p.name for p in tmp_path.glob("*.partial")] == []


def test_g3_t13_a_rejected_export_creates_no_artifact(tmp_path, monkeypatch):
    args = export_documents(tmp_path, scenario())
    output = tmp_path / "never.json"
    args[args.index("--output") + 1] = str(output)
    builder = case_benchmark.case_observation

    def broken(*positional, **keywords):
        observation = builder(*positional, **keywords)
        observation["cases"][0]["confirmed_fact_ids"] = ["ghost-fact"]
        return observation

    monkeypatch.setattr(case_benchmark, "case_observation", broken)
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert not output.exists()
    assert [p.name for p in tmp_path.glob("*.partial")] == []


def test_g3_t14_a_valid_export_is_published_and_readable(tmp_path):
    args = export_documents(tmp_path, scenario())
    output = tmp_path / "result.json"
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["kind"] == "audit_case_observation"
    assert payload["completed"] is True
    assert payload["scores"]["candidate"]["recall"] == 1


def test_g3_t15_the_command_has_no_stream_mode(tmp_path):
    args = export_documents(tmp_path, scenario())
    index = args.index("--output")
    del args[index:index + 2]
    result = CliRunner().invoke(main, args)
    assert result.exit_code != 0


def test_g3_t16_the_same_input_produces_the_same_export():
    first, *_ = export_candidate(scenario())
    second, *_ = export_candidate(scenario())
    volatile = {"observed_at"}
    assert {k: v for k, v in first.items() if k not in volatile} == \
           {k: v for k, v in second.items() if k not in volatile}


def test_g3_t08_cli_refuses_an_incomplete_export_without_permission(tmp_path):
    args = export_documents(tmp_path, blocked_run())
    output = tmp_path / "result.json"
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1
    assert not output.exists()


def test_g3_t09_cli_publishes_an_explicitly_permitted_incomplete_export(tmp_path):
    args = export_documents(tmp_path, blocked_run())
    args.append("--allow-incomplete")
    output = tmp_path / "result.json"
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["completed"] is False
    assert payload["blockers"] == ["worker routing failed"]


def test_audit_case_export_preserves_existing_schema():
    observation, *_ = export_candidate(scenario())
    assert set(observation) == CASE_EXPORT_KEYS
    assert all(set(row) == CASE_EXPORT_ROW_KEYS for row in observation["cases"])


def test_g3_ex09_the_export_boundary_needs_no_node_runtime():
    import inspect

    source = inspect.getsource(case_benchmark)
    assert "subprocess" not in source
    server = Path(case_benchmark.__file__).resolve().parents[2] / "server"
    for path in server.rglob("*.py"):
        assert "case_benchmark" not in path.read_text(encoding="utf-8")


def test_g3_publication_is_atomic_and_never_overwrites(tmp_path):
    observation, *_ = export_candidate(scenario())
    output = tmp_path / "result.json"
    publish_case_export(observation, output)
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        publish_case_export(observation, output)
    assert output.read_bytes() == original
    assert [p.name for p in tmp_path.glob("*.partial")] == []


# --- G3-T17..G3-T20: the publication boundary is exclusive, not just atomic ---
# A replace is atomic but not exclusive: a target created between the check
# and the publish would be clobbered.  The publication therefore creates the
# target with an atomic exclusive link.


def test_export_concurrent_publish_only_one_succeeds(tmp_path):
    first, *_ = export_candidate(scenario())
    second, *_ = export_candidate(scenario())
    second["observed_at"] = "2026-01-01T00:00:00+00:00"
    output = tmp_path / "result.json"
    results: list[str] = []
    barrier = threading.Barrier(2)

    def publish(observation):
        barrier.wait()
        try:
            publish_case_export(observation, output)
            results.append("ok")
        except FileExistsError:
            results.append("exists")

    workers = [threading.Thread(target=publish, args=(first,)),
               threading.Thread(target=publish, args=(second,))]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert sorted(results) == ["exists", "ok"]
    published = json.loads(output.read_text(encoding="utf-8"))
    assert published["observed_at"] in {first["observed_at"], second["observed_at"]}
    assert [p.name for p in tmp_path.glob("*.partial")] == []


def test_export_concurrent_target_creation_is_not_overwritten(tmp_path):
    observation, *_ = export_candidate(scenario())
    output = tmp_path / "result.json"
    output.write_text("written by another writer", encoding="utf-8")
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        publish_case_export(observation, output)
    assert output.read_bytes() == original
    assert [p.name for p in tmp_path.glob("*.partial")] == []


def test_export_publish_failure_cleans_up_temporary_files(tmp_path):
    observation, *_ = export_candidate(scenario())
    output = tmp_path / "result.json"
    output.write_text("occupied", encoding="utf-8")
    with pytest.raises(FileExistsError):
        publish_case_export(observation, output)
    assert list(tmp_path.glob("*.partial")) == []


def test_export_published_content_is_complete(tmp_path):
    observation, *_ = export_candidate(scenario())
    output = tmp_path / "result.json"
    publish_case_export(observation, output)
    assert json.loads(output.read_text(encoding="utf-8")) == observation


def test_export_publication_fails_closed_without_hard_link_support(tmp_path, monkeypatch):
    observation, *_ = export_candidate(scenario())
    output = tmp_path / "result.json"

    def unsupported(*args, **kwargs):
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr("linen.dispatcher.analysis.case_benchmark.os.link", unsupported)
    with pytest.raises(ExportPublishError):
        publish_case_export(observation, output)
    assert not output.exists()
    assert list(tmp_path.glob("*.partial")) == []
