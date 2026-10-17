"""Contracts for the skill-driven audit mode (docs/skills/skill-driven-mode.md).

Core invariants under test:
- verdict records are mutually exclusive by construction (missing fields, not
  merely forbidden ones);
- records pass the vendored upstream validate-findings.cjs unchanged;
- coverage-unit state machines reject silent gaps (deferred requires reason);
- traces must read entrypoint -> propagation* -> sink;
- parse errors carry the shape example so workers can self-correct.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from linen.contracts.skill_audit import (
    ConfirmedRecord,
    CoverageUnit,
    NeedsValidationRecord,
    RejectedRecord,
    parse_finding_record,
)

UPSTREAM_VALIDATOR = Path(
    ".linen-runtime/cf-security-audit-skill/skills/security-audit/validate-findings.cjs"
)


def _trace() -> list[dict]:
    return [
        {"kind": "entrypoint", "file": "app.py", "line": 12, "scope": "POST handler",
         "description": "unauthenticated form submit"},
        {"kind": "propagation", "file": "helpers/db.py", "line": 40, "scope": "query builder",
         "description": "string interpolation"},
        {"kind": "sink", "file": "helpers/db.py", "line": 41, "scope": "sqlite execute",
         "description": "executes the built query"},
    ]


def _confirmed_data() -> dict:
    return {
        "verdict": "confirmed",
        "fingerprint": "abc12345-def",
        "title": "SQL injection in BenchmarkTest00099",
        "description": "Form value is interpolated into a SQLite SELECT.",
        "trace": _trace(),
        "root_cause": "f-string interpolation into execute()",
        "intended_behavior": "parameter binding at the sink",
        "evidence": [{"file": "helpers/db.py", "line": 41,
                      "description": "execute() over the interpolated string"}],
        "conditions": [
            {"kind": "authentication_level",
             "description": "endpoint requires no authentication"},
        ],
        "execution": {
            "attacker_perspective": "anonymous HTTP client",
            "payloads": ["testvalue' OR 1=1"],
            "instructions": ["POST the payload to the local test server"],
            "observed_result": "SQLite error echoes the attacker-controlled value",
        },
        "remediation": {"strategy": "use bound parameters at helpers/db.py:41"},
        "severity": {
            "likelihood": {"score": "high", "reason": "unauthenticated, trivially reachable"},
            "impact": {"score": "high", "reason": "full database read access"},
            "overall_severity": "high",
        },
        "confidence": {"score": "high", "reason": "reproduced locally against frozen source"},
    }


def _needs_validation_data() -> dict:
    return {
        "verdict": "needs_validation",
        "fingerprint": "fff98765-abc",
        "title": "Possible traversal via backslash handling",
        "description": "Cookie value reaches open() without traversal guard.",
        "trace": [_trace()[0]],
        "claimed_root_cause": "no separator normalization before open()",
        "evidence": [{"file": "testcode/BenchmarkTest00005.py", "line": 52,
                      "description": "substring check for '../' only"}],
        "blockers": ["deployment OS path semantics unknown"],
        "validation_plan": {"local": "fixture open() with 'a\\b' on the target OS"},
    }


def test_confirmed_record_has_no_blockers_field() -> None:
    record = ConfirmedRecord.model_validate(_confirmed_data())
    assert record.verdict == "confirmed"
    with pytest.raises(ValidationError):
        ConfirmedRecord.model_validate({**_confirmed_data(), "blockers": ["x"]})


def test_needs_validation_cannot_carry_severity() -> None:
    record = NeedsValidationRecord.model_validate(_needs_validation_data())
    assert record.verdict == "needs_validation"
    with pytest.raises(ValidationError):
        NeedsValidationRecord.model_validate(
            {**_needs_validation_data(), "severity": {"score": "high"}}
        )


def test_rejected_record_round_trip() -> None:
    data = {
        "verdict": "rejected",
        "fingerprint": "aaa11111-bbb",
        "title": "Dead-branch taint in BenchmarkTest00004",
        "description": "Constant condition makes the tainted branch unreachable.",
        "trace": [{"kind": "sink", "file": "testcode/BenchmarkTest00004.py", "line": 49,
                   "scope": "codecs.open", "description": "file open"}],
        "claimed_root_cause": "tainted assignment claimed on an unreachable branch",
        "evidence": [{"file": "testcode/BenchmarkTest00004.py", "line": 43,
                      "description": "232 > 200 is always true"}],
        "reason": "bar is always the constant string, so the taint is dead",
    }
    record = RejectedRecord.model_validate(data)
    assert record.verdict == "rejected"


def test_parse_finding_record_error_carries_shape_example() -> None:
    with pytest.raises(ValueError, match="needs_validation"):
        parse_finding_record({"verdict": "maybe"})
    with pytest.raises(ValueError, match="Example shape"):
        parse_finding_record({"verdict": None})


def test_parse_finding_record_dispatches() -> None:
    assert isinstance(parse_finding_record(_confirmed_data()), ConfirmedRecord)
    assert isinstance(parse_finding_record(_needs_validation_data()), NeedsValidationRecord)


def test_multi_step_trace_must_be_entrypoint_to_sink() -> None:
    data = _confirmed_data()
    data["trace"] = list(reversed(data["trace"]))
    with pytest.raises(ValidationError, match="entrypoint"):
        ConfirmedRecord.model_validate(data)


def test_single_step_trace_cannot_be_propagation() -> None:
    data = _needs_validation_data()
    data["trace"] = [{"kind": "propagation", "file": "a.py", "line": 1,
                      "scope": "s", "description": "d"}]
    with pytest.raises(ValidationError, match="one-line trace"):
        NeedsValidationRecord.model_validate(data)


def test_overall_severity_cannot_exceed_impact() -> None:
    data = _confirmed_data()
    data["severity"]["impact"]["score"] = "low"
    data["severity"]["overall_severity"] = "critical"
    with pytest.raises(ValidationError, match="overall severity"):
        ConfirmedRecord.model_validate(data)


def test_coverage_unit_deferred_requires_reason() -> None:
    base = {
        "coverage_id": "cov-0001",
        "surface": "POST /benchmark/sqli-00/BenchmarkTest00099",
        "boundary": "anonymous HTTP -> SQLite",
        "attack_class": "injection",
        "subsystem": "sqli handlers",
        "starting_paths": ["testcode/BenchmarkTest00099.py"],
    }
    assert CoverageUnit.model_validate({**base, "state": "planned"}).state == "planned"
    with pytest.raises(ValidationError, match="deferred_reason"):
        CoverageUnit.model_validate({**base, "state": "deferred"})
    unit = CoverageUnit.model_validate(
        {**base, "state": "deferred",
         "deferred_reason": "budget_cannot_reserve_critics_and_validation"}
    )
    assert unit.deferred_reason.startswith("budget_")


def test_coverage_unit_state_evidence_pairs() -> None:
    base = {
        "coverage_id": "cov-0002",
        "surface": "GET /x",
        "boundary": "anonymous -> fs",
        "attack_class": "injection",
        "subsystem": "pathtraver",
    }
    with pytest.raises(ValidationError, match="reviewed_paths"):
        CoverageUnit.model_validate({**base, "state": "covered"})
    with pytest.raises(ValidationError, match="fingerprints"):
        CoverageUnit.model_validate({**base, "state": "candidate"})
    with pytest.raises(ValidationError, match="unresolved"):
        CoverageUnit.model_validate({**base, "state": "blocked"})


@pytest.mark.skipif(not UPSTREAM_VALIDATOR.exists(), reason="vendored skill not present")
def test_records_pass_upstream_validator_unchanged() -> None:
    records = [
        json.loads(ConfirmedRecord.model_validate(_confirmed_data()).model_dump_json(exclude_none=True)),
        json.loads(NeedsValidationRecord.model_validate(_needs_validation_data()).model_dump_json(exclude_none=True)),
    ]
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(records, handle, ensure_ascii=False)
        path = handle.name
    result = subprocess.run(
        ["node", str(UPSTREAM_VALIDATOR), path], capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
