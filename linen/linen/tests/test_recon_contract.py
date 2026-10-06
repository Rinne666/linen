from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.dispatcher.analysis import recon
from linen.dispatcher.config import ReconConfig
from linen.dispatcher.contracts import parse_json_output
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta


@pytest.fixture
def frozen_recon(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = request.args['value']\nhandle(value)\n")
    workdir = tmp_path / "work"
    config = ReconConfig(enabled=True)
    snapshot = recon.create_snapshot(repo, workdir, 1, config)
    fact = Fact(id="f001", **snapshot)
    now = "2026-01-01T00:00:00Z"
    snapshot_intent = Intent(
        id="i001", from_=["origin"], to=fact.id, type="search",
        description=recon.SNAPSHOT_INTENT, creator="reasoner", created_at=now,
    )
    intent = Intent(
        id="i002", from_=[fact.id], type="search",
        description=recon.category_description("input-validation"),
        creator="reasoner", created_at=now,
    )
    project = ProjectDetail(
        project=ProjectMeta(id="proj_recon", title="recon", status="active", created_at=now),
        facts=[fact], intents=[snapshot_intent, intent], hints=[], reviews=[],
    )
    return project, intent, workdir, config


def response():
    return {"accepted": True, "data": {
        "type": "recon", "description": "Partial input trace", "evidence": "source inspection",
        "recon_result": {
            "status": "partial", "summary": "Input observed; handler unresolved",
            "gaps": ["handle implementation is unavailable"],
            "citations": [{"id": "c1", "file": "app.py", "line": 1,
                           "code": "value = request.args['value']"}],
            "coverage_dimensions": {
                axis: [{"item": "input boundary", "status": status,
                        "rationale": "Only the input assignment is visible", "citation_ids": ["c1"]}]
                for axis, status in {
                    "parallel_paths": "unresolved", "lifecycle": "not_applicable",
                    "uncovered_items": "unresolved", "exclusion_rationales": "none_identified",
                }.items()
            },
            "coverage_review_resolutions": [], "leads": [],
        },
    }}


def test_recon_prompt_example_nests_all_required_result_fields(frozen_recon):
    prompt = recon.execution_prompt(*frozen_recon)
    example = prompt.split("Return exactly one JSON object:\n", 1)[1].split("\n\n", 1)[0]
    payload = json.loads(example)
    assert set(payload["data"]) == {"description", "type", "evidence", "recon_result"}
    assert set(payload["data"]["recon_result"]) == set(response()["data"]["recon_result"])
    assert "Nesting preflight" in prompt


def test_recon_validates_complete_envelope_against_frozen_source(frozen_recon):
    project, intent, workdir, config = frozen_recon
    output = json.dumps(response())
    fact = recon.outcome_fact(parse_json_output(output), project, intent, workdir, config)
    assert fact["type"] == "recon"
    assert "status: partial" in fact["evidence"]
    records = list((workdir / ".linen-recon/results").glob("*/recon.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["citations"][0]["code"] == "value = request.args['value']"


def test_recon_rejects_leads_at_wrong_nesting_level(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    payload["data"]["leads"] = payload["data"]["recon_result"].pop("leads")
    with pytest.raises(ValueError, match="Recon result requires"):
        recon.outcome_fact(payload, project, intent, workdir, config)


def test_recon_rejects_invented_citation_without_writing_result(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    payload["data"]["recon_result"]["citations"][0]["code"] = "invented_code()"
    with pytest.raises(ValueError, match="does not match frozen source"):
        recon.outcome_fact(payload, project, intent, workdir, config)
    assert not (workdir / ".linen-recon/results").exists()


def test_recon_canonicalizes_trailing_whitespace_citation_drift(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    citation = payload["data"]["recon_result"]["citations"][0]
    citation["code"] = f"{citation['code']} "
    fact = recon.outcome_fact(payload, project, intent, workdir, config)
    assert fact["type"] == "recon"
    records = list((workdir / ".linen-recon/results").glob("*/recon.json"))
    assert json.loads(records[0].read_text())["citations"][0]["code"] == (
        "value = request.args['value']"
    )


def test_recon_still_rejects_non_whitespace_citation_drift(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    citation = payload["data"]["recon_result"]["citations"][0]
    citation["code"] = f"{citation['code']} x"
    with pytest.raises(ValueError, match="does not match frozen source"):
        recon.outcome_fact(payload, project, intent, workdir, config)


def test_exhausted_recon_correction_records_only_an_unresolved_gap(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = recon.unresolved_correction_payload(
        "input-validation",
        "citation c1 is only a partial line prefix",
        correction_limit=3,
    )

    fact = recon.outcome_fact(payload, project, intent, workdir, config)

    assert fact["type"] == "recon"
    assert "no model claims were retained" in fact["description"].lower()
    record = json.loads(next((workdir / ".linen-recon/results").glob("*/recon.json")).read_text())
    assert record["status"] == "partial"
    assert record["leads"] == []
    assert record["citations"] == []
    assert "partial line prefix" in record["gaps"][0]
    assert all(
        rows[0]["status"] == "unresolved" and rows[0]["citation_ids"] == []
        for rows in record["coverage_dimensions"].values()
    )


def test_invalid_outer_json_reports_location_without_accepting_citation():
    output = '{"data":{"citations":[{"code":"quoted\\ncode","},{"id":"c2"}]}}'
    with pytest.raises(ValueError, match=r"Expecting ':' delimiter at line 1, column .*offset") as error:
        parse_json_output(output)
    assert "context:" in str(error.value)
    assert len(str(error.value)) < 350


def test_native_recon_schema_accepts_partial_and_rejects_wrong_nesting():
    from jsonschema import validate, ValidationError
    schema = recon.response_schema()
    validate(response(), schema)
    payload = response()
    payload["data"]["leads"] = payload["data"]["recon_result"].pop("leads")
    with pytest.raises(ValidationError):
        validate(payload, schema)


def test_codex_schema_argument_applies_to_execute_and_resume():
    from linen.dispatcher.config import WorkerConfig
    from linen.dispatcher.workers.adapters.codex import CodexDriver
    worker = WorkerConfig(name="codex", type="codex", task_types=["explore"], max_running=1, sandbox_mode="read-only",
                          env={"CODEX_MODEL": "gpt-6-luna"})
    driver = CodexDriver(local=True)
    for argv in (driver.build_execute(worker, "prompt", None).argv,
                 driver.build_conclude(worker, "prompt", "session")):
        constrained = driver.with_output_schema(argv, "/tmp/schema.json")
        assert constrained[constrained.index("--") - 2:constrained.index("--")] == ["--output-schema", "/tmp/schema.json"]
        assert constrained[-1] == "prompt"


def test_claude_schema_is_inlined_because_the_cli_rejects_a_path():
    from linen.dispatcher.config import WorkerConfig
    from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
    worker = WorkerConfig(name="claude", type="claudecode", task_types=["explore"], max_running=1,
                          sandbox_mode="read-only", env={"ANTHROPIC_MODEL": "MiniMax-M3"})
    driver = ClaudeCodeDriver()
    schema_text = '{"type":"object","properties":{"ok":{"type":"boolean"}}}'
    for argv in (driver.build_execute(worker, "prompt", "session").argv,
                 driver.build_conclude(worker, "prompt", "session")):
        constrained = driver.with_output_schema(argv, "/tmp/schema.json", schema_text=schema_text)
        assert constrained[constrained.index("--") - 2:constrained.index("--")] == [
            "--json-schema", schema_text,
        ]
        assert constrained[-1] == "prompt"
    # A bare path is not valid inline JSON, so it must never be forwarded.
    argv = driver.build_execute(worker, "prompt", "session").argv
    assert driver.with_output_schema(argv, "/tmp/schema.json") == argv


def test_execution_record_recovers_the_prompt_despite_an_inline_schema():
    """The inline `--json-schema <schema>` lands between `-p` and `--`, so the
    old `-p <value>` heuristic returned the literal `--json-schema` as the
    prompt and every controlled claude run lost its prompt in the record."""
    from linen.dispatcher.tasks.common import _prompt_from_argv
    from linen.dispatcher.tasks.explore import _constrain_recon_output
    from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver

    class Backend:
        def write_text_file(self, handle, path, text):
            pass

    driver = ClaudeCodeDriver()
    argv = ["claude", "-p", "--", "the real prompt"]
    constrained = _constrain_recon_output(Backend(), "handle", driver, argv)
    assert constrained.index("--json-schema") < constrained.index("--")
    recovered = _prompt_from_argv(constrained)
    assert recovered == "the real prompt"
    assert recovered != "--json-schema"

    # pi keeps its prompt as the value of `-p` with no option terminator.
    assert _prompt_from_argv(["pi", "-p", "pi prompt"]) == "pi prompt"
    # codex terminates options before the prompt, exactly like claude.
    assert _prompt_from_argv(
        ["codex", "exec", "--output-schema", "/tmp/s.json", "--", "codex prompt"]
    ) == "codex prompt"


def test_output_schema_capability_flags_match_the_adapters():
    from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
    from linen.dispatcher.workers.adapters.codex import CodexDriver
    from linen.dispatcher.workers.base import WorkerDriver
    assert WorkerDriver.supports_output_schema is False
    assert CodexDriver.supports_output_schema is True
    assert ClaudeCodeDriver.supports_output_schema is True


def test_recon_output_constraint_inlines_a_parseable_schema_for_claude():
    from linen.dispatcher.tasks.explore import _constrain_recon_output
    from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver

    class Backend:
        def __init__(self):
            self.writes = []

        def write_text_file(self, handle, path, text):
            self.writes.append((path, text))

    backend = Backend()
    driver = ClaudeCodeDriver()
    argv = ["claude", "-p", "--", "prompt"]
    constrained = _constrain_recon_output(backend, "handle", driver, argv)

    inline = constrained[constrained.index("--json-schema") + 1]
    # The CLI parses this argument as JSON, so it must survive a round trip.
    assert json.loads(inline) == recon.response_schema()
    assert constrained[-1] == "prompt"
    assert len(backend.writes) == 1


def test_recon_output_constraint_skips_drivers_without_schema_support():
    from linen.dispatcher.tasks.explore import _constrain_recon_output
    from linen.dispatcher.workers.adapters.pi import PiDriver

    class Backend:
        def __init__(self):
            self.writes = []

        def write_text_file(self, handle, path, text):
            self.writes.append((path, text))

    backend = Backend()
    argv = ["pi", "-p", "--", "prompt"]
    assert _constrain_recon_output(backend, "handle", PiDriver(), argv) == argv
    assert backend.writes == []



COVERAGE_AXES = ("parallel_paths", "lifecycle", "uncovered_items", "exclusion_rationales")

# Candidate status tokens a model plausibly emits for a coverage dimension. The
# first five are the validator's real vocabulary; the rest are near-misses that
# earlier runs produced because the prompt advertised a conflicting token set.
COVERAGE_STATUS_CANDIDATES = (
    "traced", "unresolved", "not_applicable", "excluded", "none_identified",
    "none_found", "checked", "complete", "not applicable", "none identified",
)


def _dimension_payload(overrides: dict[str, str]) -> dict:
    """Build a fully populated coverage_dimensions block with per-axis statuses."""
    baseline = {
        "parallel_paths": "traced",
        "lifecycle": "traced",
        "uncovered_items": "unresolved",
        "exclusion_rationales": "excluded",
    }
    baseline.update(overrides)
    return {
        axis: [{"item": "boundary", "status": status, "rationale": "checked", "citation_ids": ["c1"]}]
        for axis, status in baseline.items()
    }


def _accepted_statuses(axis: str) -> set[str]:
    """Derive the validator's accepted vocabulary for one axis by probing it."""
    accepted = set()
    for token in COVERAGE_STATUS_CANDIDATES:
        try:
            recon._validate_coverage_dimensions(_dimension_payload({axis: token}), {"c1"})
        except ValueError:
            continue
        accepted.add(token)
    return accepted


def test_coverage_status_vocabulary_is_axis_specific():
    # Guards the probe helper itself: the axes really do differ, so a prompt that
    # advertises one flat status list cannot satisfy every axis.
    assert _accepted_statuses("uncovered_items") == {"unresolved", "none_identified"}
    assert _accepted_statuses("exclusion_rationales") == {
        "excluded", "none_identified", "unresolved",
    }
    assert _accepted_statuses("parallel_paths") == {
        "traced", "unresolved", "not_applicable", "excluded",
    }
    assert _accepted_statuses("lifecycle") == _accepted_statuses("parallel_paths")


def test_every_axis_has_a_citation_free_unresolved_escape_hatch():
    # Without this, a worker that cannot read the frozen source has no valid way
    # to say so on any axis, and retries forever on an honest answer.
    for axis in COVERAGE_AXES:
        assert "unresolved" in _accepted_statuses(axis), axis


def test_unresolved_dimension_rows_may_be_citation_free():
    payload = _dimension_payload({axis: "unresolved" for axis in COVERAGE_AXES})
    for rows in payload.values():
        for row in rows:
            row["citation_ids"] = []
    normalized = recon._validate_coverage_dimensions(payload, set())
    for axis in COVERAGE_AXES:
        assert normalized[axis][0]["citation_ids"] == []


@pytest.mark.parametrize("axis,status", [
    ("parallel_paths", "traced"),
    ("parallel_paths", "not_applicable"),
    ("parallel_paths", "excluded"),
    ("lifecycle", "traced"),
    ("uncovered_items", "none_identified"),
    ("exclusion_rationales", "excluded"),
    ("exclusion_rationales", "none_identified"),
])
def test_positive_coverage_claims_still_require_citations(axis, status):
    payload = _dimension_payload({axis: status})
    for row in payload[axis]:
        row["citation_ids"] = []
    with pytest.raises(ValueError, match="must cite frozen source"):
        recon._validate_coverage_dimensions(payload, {"c1"})


def test_dimension_rows_cannot_cite_an_undefined_citation_id():
    payload = _dimension_payload({})
    payload["parallel_paths"][0]["citation_ids"] = ["c9"]
    with pytest.raises(ValueError, match="must cite frozen source"):
        recon._validate_coverage_dimensions(payload, {"c1"})


def test_recon_accepts_an_honest_blocked_result_without_fabricated_citations(frozen_recon):
    """Regression for the observed codex refusal: it returned valid JSON asserting
    that the read-only sandbox denied all source access, with no citations. That
    honest answer was rejected as `must cite frozen source` and retried until the
    intent blocked. It must now be accepted and preserved as residual gaps."""
    project, intent, workdir, config = frozen_recon
    payload = {"accepted": True, "data": {
        "type": "recon",
        "description": "Reconnaissance blocked before source inspection.",
        "evidence": "The read-only shell and Node listing both failed.",
        "recon_result": {
            "status": "partial",
            "summary": "No paths could be traced because the source was unreadable.",
            "gaps": ["The frozen source root could not be listed."],
            "citations": [],
            "coverage_dimensions": {
                axis: [{
                    "item": "uninspected surface",
                    "status": "unresolved",
                    "rationale": "No frozen source file could be read.",
                    "citation_ids": [],
                }]
                for axis in COVERAGE_AXES
            },
            "coverage_review_resolutions": [],
            "leads": [],
        },
    }}
    fact = recon.outcome_fact(payload, project, intent, workdir, config)
    assert fact["type"] == "recon"
    assert "status: partial" in fact["evidence"]


@pytest.mark.parametrize("axis", COVERAGE_AXES)
def test_recon_prompt_advertises_every_accepted_coverage_status(frozen_recon, axis):
    prompt = recon.execution_prompt(*frozen_recon)
    for status in sorted(_accepted_statuses(axis)):
        assert f"`{status}`" in prompt, f"{axis} status {status!r} is accepted but undocumented"


@pytest.mark.parametrize("axis", COVERAGE_AXES)
def test_recon_prompt_never_advertises_rejected_coverage_status(frozen_recon, axis):
    prompt = recon.execution_prompt(*frozen_recon)
    accepted = _accepted_statuses(axis)
    for token in COVERAGE_STATUS_CANDIDATES:
        if token in accepted:
            continue
        # Rejected tokens may legitimately appear as another section's vocabulary
        # (for example `none_found` for protection_checks), so only the spaced
        # spelling of an accepted token is an unconditional defect.
        if token.replace("_", " ") in {value.replace("_", " ") for value in accepted}:
            assert f"`{token}`" not in prompt, f"prompt advertises rejected {token!r}"


def test_recon_prompt_documents_row_shape_and_citation_binding(frozen_recon):
    prompt = recon.execution_prompt(*frozen_recon)
    assert "`none identified`" not in prompt
    for key in ("`item`", "`status`", "`rationale`", "`citation_ids`"):
        assert key in prompt
    assert "1-32 rows" in prompt
    assert "at most 16 IDs" in prompt
    assert "`status: unresolved`" in prompt
    assert "residual gaps" in prompt


def test_native_schema_allows_every_dimension_status_the_validator_accepts(frozen_recon):
    """The generated JSON schema and the imperative validator must agree, or a
    schema-conforming worker produces output the validator rejects."""
    from jsonschema import validate

    schema = recon.response_schema()
    for axis in COVERAGE_AXES:
        for status in sorted(_accepted_statuses(axis)):
            payload = response()
            payload["data"]["recon_result"]["coverage_dimensions"] = _dimension_payload(
                {axis: status}
            )
            validate(payload, schema)


def _security_checks(
    result: str,
    predicate_result: str,
    *,
    check_sink: str = "no",
    case_sink: str = "unknown",
    attacker_case_id: str = "case1",
) -> dict:
    return {
        "attacker_cases": [{
            "case_id": "case1", "input_class": "path parameter",
            "representative_value": "../private/config.yml", "attacker_control": "yes",
            "sink_reachable": case_sink, "security_effect": "read of an unintended file",
            "citation_ids": ["c1"],
        }],
        "protection_checks": [{
            "protection": "path containment", "predicate": "resolved starts with root",
            "attacker_case_id": attacker_case_id, "predicate_result": predicate_result,
            "resulting_value": "resolved path", "result": result,
            "sink_reachable": check_sink, "citation_ids": ["c1"],
        }],
        "configuration_analysis": {
            "default_mode": "enabled", "ordinary_enabled_mode": "analyzed",
            "requires_admin_misconfiguration": "no", "summary": "ordinary defaults",
            "citation_ids": ["c1"],
        },
    }


def test_no_guard_requires_not_applicable_predicate():
    recon._validate_lead_security_checks(
        _security_checks("none_found", "not_applicable"), {"c1"}
    )
    for wrong in ("accepts", "rejects", "transforms", "unknown"):
        with pytest.raises(ValueError, match="cannot claim result"):
            recon._validate_lead_security_checks(_security_checks("none_found", wrong), {"c1"})


def test_no_guard_error_names_the_correct_alternative():
    """i007 regression: the model wrote result `none_found` with predicate_result
    `accepts`. The message must name the observed value and the right fix so the
    retry can self-correct instead of repeating the run."""
    with pytest.raises(ValueError) as error:
        recon._validate_lead_security_checks(_security_checks("none_found", "accepts"), {"c1"})
    message = str(error.value)
    assert "'accepts'" in message
    assert '"none_found"' in message
    assert '"bypassable"' in message
    assert '"not_applicable"' in message


def test_blocks_accepts_a_refusing_or_neutralizing_predicate():
    # `rejects` refuses the value outright ...
    recon._validate_lead_security_checks(
        _security_checks("blocks", "rejects", check_sink="no", case_sink="no"), {"c1"}
    )
    # ... and `transforms` neutralizes it (parameter binding, escaping). The
    # i012 payload used exactly this pairing for BenchmarkTest00011's bound
    # parameters, which is a real block, not a contradiction.
    recon._validate_lead_security_checks(
        _security_checks("blocks", "transforms", check_sink="no", case_sink="no"), {"c1"}
    )
    # A guard that passed the value through unchanged did not block the path.
    for wrong in ("accepts", "unknown", "not_applicable"):
        with pytest.raises(ValueError, match='can claim result "blocks" only with'):
            recon._validate_lead_security_checks(
                _security_checks("blocks", wrong, check_sink="no", case_sink="no"), {"c1"}
            )
    # ... nor may it leave its own linked attacker case reaching the sink.
    with pytest.raises(ValueError, match="is still sink_reachable=yes"):
        recon._validate_lead_security_checks(
            _security_checks("blocks", "rejects", check_sink="no", case_sink="yes"), {"c1"}
        )


def test_protection_check_must_reference_a_defined_attacker_case():
    with pytest.raises(ValueError, match="must reference an attacker case"):
        recon._validate_lead_security_checks(
            _security_checks("none_found", "not_applicable", attacker_case_id="case9"), {"c1"}
        )


def test_recon_prompt_documents_security_check_cross_field_invariants(frozen_recon):
    prompt = recon.execution_prompt(*frozen_recon)
    assert "cross-field" in prompt
    # the exact couplings the validator enforces
    assert '`protection_checks[].result: "none_found"` is a positive claim that no' in prompt
    assert "be `not_applicable`" in prompt
    # the disambiguation that the i007 run needed: accepts => bypassable
    assert '`predicate_result: "accepts"` with `result: "bypassable"`' in prompt
    assert '`protection_checks[].result: "blocks"` requires `sink_reachable` `no`' in prompt
    assert "`transforms` (the guard neutralizes it before the sink" in prompt
    # i012 regression: `sink_reachable` was read two ways (operation on path vs
    # attack carrying through), so the prompt now pins one meaning.
    assert "`sink_reachable` answers one question everywhere" in prompt
    assert "attacker_case_id` must equal a `case_id`" in prompt


def test_recon_prompt_states_lead_field_arities(frozen_recon):
    prompt = recon.execution_prompt(*frozen_recon)
    assert "`next_step` is a single string" in prompt
    assert "`missing_evidence` and `path`" in prompt


def _lead(**overrides) -> dict:
    base = {
        "id": "l1", "title": "title", "hypothesis": "hypothesis",
        "source": "app.py:1", "sink": "handle()", "path": ["app.py:1"],
        "citation_ids": ["c1"], "missing_evidence": ["handler body"],
        "next_step": "Read handle()",
        "security_checks": _security_checks("none_found", "not_applicable"),
    }
    base.update(overrides)
    return base


def test_lead_text_field_reports_the_offending_field_not_the_whole_contract(frozen_recon):
    """i007 regression: `next_step` arrived as an array and the old message
    ('Recon lead summary, source, sink, and next step are required') restated the
    whole contract, so five retries could not locate their own defect."""
    project, intent, workdir, config = frozen_recon
    payload = response()
    payload["data"]["recon_result"]["leads"] = [
        _lead(next_step=["Read handle()", "and its callers"]),
    ]
    with pytest.raises(ValueError) as error:
        recon.outcome_fact(payload, project, intent, workdir, config)
    message = str(error.value)
    assert "lead l1" in message
    assert "field next_step" in message
    assert "got list" in message
    # names the sibling array field so the retry can transpose it correctly
    assert "missing_evidence is the array field" in message
    # ... and never falls back to the unlocatable generic wording
    assert "are required" not in message


def test_lead_array_field_rejects_a_bare_string(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    payload["data"]["recon_result"]["leads"] = [_lead(missing_evidence="handler body")]
    with pytest.raises(ValueError, match="field missing_evidence must be a list of strings"):
        recon.outcome_fact(payload, project, intent, workdir, config)


def test_lead_rejects_blank_required_text(frozen_recon):
    project, intent, workdir, config = frozen_recon
    payload = response()
    payload["data"]["recon_result"]["leads"] = [_lead(title="   ")]
    with pytest.raises(
        ValueError, match=r"lead l1 field title must be a non-empty string, got str"
    ):
        recon.outcome_fact(payload, project, intent, workdir, config)
