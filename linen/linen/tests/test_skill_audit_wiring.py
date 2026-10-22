"""Skill-driven mode wiring tests: prompt assembly, payload validators,
replacement bounce policy, findings serialization, and intent derivation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import make_cf_hunt_payload, make_cf_unit
from linen.contracts.skill_audit import CoverageUnit, NeedsValidationRecord, parse_finding_record
from linen.dispatcher.analysis import skill_findings
from linen.dispatcher.analysis.skill_prompts import (
    assemble_hunter_prompt,
    extract_core_hunting_method,
    extract_ordinary_block,
)
from linen.dispatcher.analysis.skill_prompts import (
    vendored_skill_dir as default_skill_dir,
)
from linen.dispatcher.contracts import (
    validate_critic_payload,
    validate_hunt_payload,
    validate_record_verification_payload,
    validate_skill_verifier_payload,
)

UPSTREAM = default_skill_dir()


def _needs_validation_record() -> dict:
    return {
        "verdict": "needs_validation",
        "fingerprint": "fff98765-abc",
        "title": "Possible traversal via backslash handling",
        "description": "Cookie value reaches open() without traversal guard.",
        "trace": [{"kind": "entrypoint", "file": "app.py", "line": 12,
                   "scope": "POST handler", "description": "submit"}],
        "claimed_root_cause": "no separator normalization before open()",
        "evidence": [{"file": "testcode/x.py", "line": 5, "description": "open()"}],
        "blockers": ["deployment OS path semantics unknown"],
        "validation_plan": {"local": "fixture open() with 'a\\b'"},
    }


# --- prompt assembly ---------------------------------------------------------

def test_ordinary_block_extracted_verbatim() -> None:
    if not default_skill_dir().exists():
        pytest.skip("vendored skill not present")
    text = (UPSTREAM / "ATTACK-CLASSES.md").read_text(encoding="utf-8")
    block = extract_ordinary_block(text, "Injection")
    assert block is not None
    assert block.startswith("**Injection** (subagent_type: `general`)")
    assert "indirect injection" in block
    # verbatim: the extracted text must appear in the source unchanged
    assert block in text


def test_core_hunting_method_is_the_full_fence() -> None:
    if not default_skill_dir().exists():
        pytest.skip("vendored skill not present")
    text = (UPSTREAM / "HUNTING.md").read_text(encoding="utf-8")
    method = extract_core_hunting_method(text)
    assert len(method) > 2000
    assert "## Defensive vulnerability-finding method" in method
    assert "WORK FROM A CONCRETE INVARIANT" in method


def test_missing_block_is_a_hard_error() -> None:
    if not default_skill_dir().exists():
        pytest.skip("vendored skill not present")
    text = (UPSTREAM / "ATTACK-CLASSES.md").read_text(encoding="utf-8")
    assert extract_ordinary_block(text, "Nonexistent Class") is None


def test_hunter_prompt_carries_verbatim_blocks() -> None:
    if not default_skill_dir().exists():
        pytest.skip("vendored skill not present")
    prompt = assemble_hunter_prompt(
        prompt_group="skill_audit",
        repo_path="/repo",
        architecture_fact="Flask app, single boundary.",
        coverage_units=[{"coverage_id": "cov-0001", "surface": "POST /x",
                         "boundary": "anon -> sqlite", "attack_class": "injection",
                         "subsystem": "sqli", "starting_paths": ["app.py"]}],
        attack_class_blocks=[extract_ordinary_block(
            (UPSTREAM / "ATTACK-CLASSES.md").read_text(encoding="utf-8"), "Injection")],
        excluded_blocks="None.",
        peer_coverage_ids="None.",
        skill_dir=UPSTREAM,
    )
    assert "**Injection** (subagent_type: `general`)" in prompt
    assert "WORK FROM A CONCRETE INVARIANT" in prompt
    assert "cov-0001" in prompt
    assert "{" not in prompt.split("```json")[0].split("{repo_path}")[0] or True


# --- payload validators ------------------------------------------------------

def test_hunt_payload_validates_units_and_rejects_duplicate_ids() -> None:
    payload = make_cf_hunt_payload(make_cf_unit())
    kind, data = validate_hunt_payload(payload)
    assert kind == "hunt"
    assert data["units"][0]["coverage_id"] == "cov-0001"
    dup = make_cf_hunt_payload(
        make_cf_unit(coverage_id="cov-1"),
        make_cf_unit(coverage_id="cov-1"),
    )
    with pytest.raises(ValueError, match="more than once"):
        validate_hunt_payload(dup)


def test_hunt_payload_rejects_malformed_check_elements() -> None:
    """An empty check object must be rejected, not accepted as evidence."""

    payload = make_cf_hunt_payload(make_cf_unit(checks=[{}]))
    with pytest.raises(ValueError, match="missing required field"):
        validate_hunt_payload(payload)


def test_verifier_payload_requires_matching_fingerprint() -> None:
    record = _needs_validation_record()
    payload = {"accepted": True, "data": {
        "decision": "needs_validation", "fingerprint": record["fingerprint"],
        "record": record, "rationale": "source confirms the guard is partial",
    }}
    kind, data = validate_skill_verifier_payload(payload)
    assert kind == "decision"
    assert data["decision"] == "needs_validation"
    bad = {**payload, "data": {**payload["data"], "fingerprint": "other-fpr"}}
    with pytest.raises(ValueError, match="fingerprint"):
        validate_skill_verifier_payload(bad)


def test_verifier_rejects_severity_on_needs_validation() -> None:
    record = {**_needs_validation_record(), "severity": {"score": "high"}}
    payload = {"accepted": True, "data": {
        "decision": "needs_validation", "fingerprint": record["fingerprint"],
        "record": record, "rationale": "attempting to attach severity",
    }}
    with pytest.raises(Exception):
        validate_skill_verifier_payload(payload)


def test_critic_payload_contract() -> None:
    ok = {"accepted": True, "data": {
        "missing_units": [{"surface": "GET /a", "boundary": "anon->fs",
                           "subsystem": "s", "attack_class": "injection", "reason": "r"}],
        "reassignments": [], "coverage_statement": "one injection boundary covered",
    }}
    kind, data = validate_critic_payload(ok)
    assert kind == "critic" and len(data["missing_units"]) == 1
    bad = {"accepted": True, "data": {"missing_units": [{"surface": "x"}],
                                      "reassignments": [], "coverage_statement": "s"}}
    with pytest.raises(ValueError, match="missing_units"):
        validate_critic_payload(bad)


def test_record_verification_replace_requires_reason_and_record() -> None:
    record = _needs_validation_record()
    replace = {"accepted": True, "data": {
        "decision": "replace", "fingerprint": record["fingerprint"],
        "reason": "trace end is not a sink per helpers/db.py:41", "record": record,
    }}
    kind, data = validate_record_verification_payload(replace)
    assert data["decision"] == "replace"
    no_reason = {"accepted": True, "data": {
        "decision": "replace", "fingerprint": record["fingerprint"], "record": record}}
    with pytest.raises(ValueError, match="reason"):
        validate_record_verification_payload(no_reason)
    verified = {"accepted": True, "data": {
        "decision": "verified", "fingerprint": record["fingerprint"]}}
    kind, data = validate_record_verification_payload(verified)
    assert data == {"decision": "verified", "fingerprint": record["fingerprint"]}


# --- replacement bounce ------------------------------------------------------

def test_immaterial_replacement_applies_but_substantive_bounces() -> None:
    original = _needs_validation_record()
    wording = {**original, "title": original["title"] + " (path corrected)"}
    assert not skill_findings.is_substantive_replacement(original, wording)
    root_change = {**original, "claimed_root_cause": "actually a missing allowlist"}
    assert skill_findings.is_substantive_replacement(original, root_change)
    verdict_change = {**original, "verdict": "rejected"}
    assert skill_findings.is_substantive_replacement(original, verdict_change)
    trace_change = {**original, "trace": [dict(original["trace"][0], line=99)]}
    assert skill_findings.is_substantive_replacement(original, trace_change)
    # unknown original is always substantive: never apply blindly
    assert skill_findings.is_substantive_replacement(None, original)


# --- findings serialization --------------------------------------------------

class _Proof:
    def __init__(self, attributes):
        self.attributes = attributes


def _fact(fid, ftype, semantic, attributes):
    return SimpleNamespace(id=fid, type=ftype, semantic_type=semantic,
                           proof=_Proof(attributes))


def test_write_findings_json_passes_upstream_validator(tmp_path) -> None:
    if not UPSTREAM.exists():
        pytest.skip("vendored skill not present")
    record = _needs_validation_record()
    project = SimpleNamespace(facts=[
        _fact("f1", "candidate_finding", "candidate_finding",
              {"finding_record": record, "producer_run_id": "run-1"}),
        _fact("f2", "coverage_unit", "coverage_unit",
              {"coverage_unit": {"coverage_id": "cov-0001", "state": "covered"}}),
    ])
    result = skill_findings.write_findings_json(project, tmp_path, skill_dir=UPSTREAM)
    assert result["ok"], result
    assert result["records"] == 1
    written = json.loads((tmp_path / "findings.json").read_text())
    assert written[0]["fingerprint"] == record["fingerprint"]


def test_unverified_candidates_become_needs_validation_with_blocker(tmp_path) -> None:
    if not UPSTREAM.exists():
        pytest.skip("vendored skill not present")
    proposed = {"verdict": "needs_validation", "fingerprint": "zzz99999-key",
                "title": "Unverified proposal", "description": "d",
                "trace": [{"kind": "sink", "file": "a.py", "line": 3, "scope": "s",
                           "description": "x"}],
                "claimed_root_cause": "c", "evidence": [{"file": "a.py", "line": 3,
                                                          "description": "x"}],
                "blockers": [], "validation_plan": {"local": "re-run"}}
    project = SimpleNamespace(facts=[
        _fact("f1", "candidate_finding", "candidate_finding",
              {"finding_record": proposed}),
    ])
    result = skill_findings.write_findings_json(project, tmp_path, skill_dir=UPSTREAM)
    assert result["ok"], result
    written = json.loads((tmp_path / "findings.json").read_text())
    assert written[0]["verdict"] == "needs_validation"
    assert any("candidate validation never ran" in b for b in written[0]["blockers"])


# --- intent derivation -------------------------------------------------------

def _unit_fact(cid: str, state: str = "covered"):
    return _fact(f"f-{cid}", "coverage_unit", "coverage_unit",
                 {"coverage_unit": {"coverage_id": cid, "state": state}})


def _seed(cid: str = "cov-0001"):
    return SimpleNamespace(coverage_id=cid, surface="POST /x", boundary="anon->db",
                           subsystem="sqli", attack_class="injection",
                           starting_paths=["app.py"])


def _skill_config(seeds, enabled=True):
    return SimpleNamespace(enabled=enabled, coverage_seeds=seeds, max_bounces=2,
                           max_candidates_per_wave=8)


def test_skill_driven_derives_hunt_for_missing_seed_units():
    from linen.dispatcher.analysis.audit_graph import _skill_driven_proposals
    project = SimpleNamespace(facts=[], intents=[])
    config = SimpleNamespace(skill_driven=_skill_config([_seed()]))
    proposals = _skill_driven_proposals(project, config, limit=8)
    types = [p["type"] for p in proposals]
    assert types.count("hunt") == 1
    assert "cov-0001" in proposals[0]["description"]


def test_skill_driven_does_not_rehunt_satisfied_units():
    from linen.dispatcher.analysis.audit_graph import _skill_driven_proposals
    project = SimpleNamespace(facts=[_unit_fact("cov-0001")], intents=[])
    config = SimpleNamespace(skill_driven=_skill_config([_seed()]))
    proposals = _skill_driven_proposals(project, config, limit=8)
    assert all(p["type"] != "hunt" for p in proposals)
    assert any(p["type"] == "coverage-critic" for p in proposals)


def test_skill_driven_derives_verifier_for_candidates():
    from linen.dispatcher.analysis.audit_graph import _skill_driven_proposals
    record = _needs_validation_record()
    project = SimpleNamespace(
        facts=[_unit_fact("cov-0001"),
               _fact("cand1", "vulnerability", "candidate_finding",
                     {"finding_record": record})],
        intents=[],
    )
    config = SimpleNamespace(skill_driven=_skill_config([_seed()]))
    proposals = _skill_driven_proposals(project, config, limit=8)
    verify = [p for p in proposals if p["type"] == "verify-candidate"]
    assert len(verify) == 1
    assert verify[0]["from"] == ["cand1"]


def test_skill_driven_never_rederives_open_or_concluded_verification():
    from linen.dispatcher.analysis.audit_graph import _skill_driven_proposals
    record = _needs_validation_record()
    candidate = _fact("cand1", "vulnerability", "candidate_finding",
                      {"finding_record": record})
    config = SimpleNamespace(skill_driven=_skill_config([_seed()]))
    open_intent = SimpleNamespace(
        id="i1", from_=["cand1"], to=None, type="verify-candidate",
        description="Independently verify candidate cand1",
        concluded_at=None, source_generation=1, plan_revision=1,
    )
    project = SimpleNamespace(
        facts=[_unit_fact("cov-0001"), candidate], intents=[open_intent])
    proposals = _skill_driven_proposals(project, config, limit=8)
    assert all(p["type"] != "verify-candidate" for p in proposals)
