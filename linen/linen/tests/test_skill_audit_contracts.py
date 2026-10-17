"""Contracts for the skill-driven audit mode (docs/skills/skill-driven-mode.md).

Core invariants under test:
- verdict records are mutually exclusive by construction (missing fields, not
  merely forbidden ones);
- coverage-unit state machines reject silent gaps (deferred requires reason);
- traces must read entrypoint -> propagation* -> sink;
- parse errors carry the shape example so workers can self-correct.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from linen.contracts.skill_audit import (
    ConfirmedRecord,
    CoverageUnit,
    NeedsValidationRecord,
    RejectedRecord,
    parse_finding_record,
)


def _trace() -> list[dict]:
    return [
        {"step": "entrypoint", "path": "app.py", "line": 12, "description": "POST handler"},
        {"step": "propagation", "path": "helpers/db.py", "line": 40, "description": "string build"},
        {"step": "sink", "path": "helpers/db.py", "line": 41, "description": "execute"},
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
        "conditions": ["unauthenticated POST to the endpoint"],
        "execution": "curl the local dev server with a dummy payload",
        "observed_result": "SQLite error echoes attacker-controlled value",
        "remediation": "use bound parameters at helpers/db.py:41",
        "severity": "high",
        "confidence": "certain",
    }


def _needs_validation_data() -> dict:
    return {
        "verdict": "needs_validation",
        "fingerprint": "fff98765-abc",
        "title": "Possible traversal via backslash handling",
        "description": "Cookie value reaches open() without traversal guard.",
        "trace": _trace(),
        "claimed_root_cause": "no separator normalization before open()",
        "evidence": ["testcode/BenchmarkTest00005.py:52"],
        "blockers": ["deployment OS path semantics unknown"],
        "validation_plan": {"local": "fixture open() with 'a\\b' on target OS"},
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
        NeedsValidationRecord.model_validate({**_needs_validation_data(), "severity": "high"})


def test_rejected_record_round_trip() -> None:
    data = {
        "verdict": "rejected",
        "fingerprint": "aaa11111-bbb",
        "title": "Dead-branch taint in BenchmarkTest00004",
        "description": "Constant condition makes the tainted branch unreachable.",
        "trace": _trace(),
        "claimed_root_cause": "tainted assignment claimed on an unreachable branch",
        "evidence": ["testcode/BenchmarkTest00004.py:43"],
        "reason": "232 > 200 is always true, so bar is a constant",
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
        {**base, "state": "deferred", "deferred_reason": "budget_cannot_reserve_critics_and_validation"}
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
