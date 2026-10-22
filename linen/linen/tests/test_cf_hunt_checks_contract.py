"""CF-S1-A: the coverage-check contract that gates model output before the graph.

The pinned upstream validator (cloudflare/security-audit-skill @ c1c8a8c) defines
the six fields a coverage check must carry.  This module pins linen's Python
implementation to that contract:

- structure: every check element is validated field by field;
- paths: repository-relative path safety and unit/check path ownership;
- identity: agent id syntax, including the Windows reserved names;
- admission: a local artifact that cannot be trusted yields ``incomplete`` and
  is never rewritten into a source check.

The equivalence test compares the Python decisions against the pinned Node
validator itself, so the two implementations cannot drift apart silently.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import make_cf_check, make_cf_hunt_payload, make_cf_unit
from linen.dispatcher.analysis.cf_skill_assets import cf_skill_file
from linen.dispatcher.contracts import (
    CF_ADMISSION_ACCEPTED,
    CF_ADMISSION_INCOMPLETE,
    CF_ARTIFACT_NOT_VERIFIED,
    CF_ARTIFACT_PROMOTION_FAILED,
    CF_ARTIFACT_VERIFIED,
    CF_INCOMPLETE_ARTIFACT_NOT_VERIFIED,
    CF_INCOMPLETE_ARTIFACT_PROMOTION_FAILED,
    CF_INCOMPLETE_ASSIGNMENT_UNAVAILABLE,
    CF_INCOMPLETE_MISSING_LOCAL_ARTIFACT,
    CF_MAX_LIST_ITEMS,
    admit_hunt_payload,
    validate_hunt_payload,
)

ARTIFACT = "agents/hunter-e/artifacts/check.txt"


# --- fixtures ----------------------------------------------------------------

def _without(field: str) -> dict:
    return {key: value for key, value in make_cf_check().items() if key != field}


MALFORMED_CHECKS: list[tuple[str, object, str]] = [
    ("empty_object", {}, "missing required field"),
    ("null_element", None, "expected object"),
    ("string_element", "checked", "expected object"),
    ("list_element", ["checked"], "expected object"),
    ("number_element", 7, "expected object"),
    ("missing_agent_id", _without("agent_id"), "missing required field agent_id"),
    ("missing_reviewed_paths", _without("reviewed_paths"), "missing required field reviewed_paths"),
    ("missing_invariant", _without("invariant"), "missing required field invariant"),
    ("missing_method", _without("method"), "missing required field method"),
    ("missing_result", _without("result"), "missing required field result"),
    ("missing_artifact", _without("artifact"), "missing required field artifact"),
    ("empty_reviewed_paths", make_cf_check(reviewed_paths=[]), "must not be empty"),
    ("reviewed_paths_not_array", make_cf_check(reviewed_paths="src/app.py"), "expected array"),
    ("unknown_method", make_cf_check(method="dynamic"), "method: expected"),
    ("source_with_artifact", make_cf_check(method="source", artifact=ARTIFACT), "must use null"),
    ("source_with_empty_artifact", make_cf_check(method="source", artifact=""), "must use null"),
    ("local_without_artifact", make_cf_check(method="local", artifact=None), "owned by agent"),
    ("local_without_owner_prefix", make_cf_check(method="local", artifact="artifacts/x.txt"), "owned by agent"),
    ("local_with_other_owner", make_cf_check(method="local", artifact="agents/hunter-f/artifacts/x.txt"), "owned by agent"),
    ("local_without_relative_part", make_cf_check(method="local", artifact="agents/hunter-e/artifacts/"), "owned by agent"),
    ("empty_invariant", make_cf_check(invariant=""), "invariant: invalid text"),
    ("blank_invariant", make_cf_check(invariant="   "), "invariant: invalid text"),
    ("leading_space_invariant", make_cf_check(invariant=" leading"), "invariant: invalid text"),
    ("trailing_space_result", make_cf_check(result="trailing "), "result: invalid text"),
    ("non_string_result", make_cf_check(result=123), "result: invalid text"),
    ("null_invariant", make_cf_check(invariant=None), "invariant: invalid text"),
    ("uppercase_agent_id", make_cf_check(agent_id="Hunter"), "canonical lowercase agent ID"),
    ("leading_underscore_agent_id", make_cf_check(agent_id="_agent"), "canonical lowercase agent ID"),
    ("reserved_agent_id_con", make_cf_check(agent_id="con"), "canonical lowercase agent ID"),
    ("reserved_agent_id_com1", make_cf_check(agent_id="com1"), "canonical lowercase agent ID"),
    ("overlong_agent_id", make_cf_check(agent_id="a" * 65), "canonical lowercase agent ID"),
]


# --- A-T01 / A-T02: valid contracts -----------------------------------------

def test_hunt_checks_valid_contract() -> None:
    source_unit = make_cf_unit()
    kind, data = validate_hunt_payload(make_cf_hunt_payload(source_unit))
    assert kind == "hunt"
    assert data is not None
    assert data["units"][0]["checks"][0]["method"] == "source"

    local_unit = make_cf_unit(
        checks=[make_cf_check(method="local", artifact=ARTIFACT)],
    )
    kind, data = validate_hunt_payload(make_cf_hunt_payload(local_unit))
    assert kind == "hunt"
    assert data is not None
    assert data["units"][0]["checks"][0]["artifact"] == ARTIFACT


def test_hunt_checks_allow_mixed_owners_in_one_unit() -> None:
    """A unit may carry evidence from different legitimate owners."""

    unit = make_cf_unit(
        reviewed_paths=["src/app.py", "src/auth.py"],
        checks=[
            make_cf_check(reviewed_paths=["src/app.py"]),
            make_cf_check(
                agent_id="verifier-1",
                reviewed_paths=["src/auth.py"],
                invariant="Ownership must be enforced",
                result="Ownership check passed",
            ),
        ],
    )
    kind, _ = validate_hunt_payload(make_cf_hunt_payload(unit))
    assert kind == "hunt"


# --- A-T03 .. A-T09: malformed elements --------------------------------------

@pytest.mark.parametrize(
    "label,check,fragment",
    MALFORMED_CHECKS,
    ids=[case[0] for case in MALFORMED_CHECKS],
)
def test_hunt_checks_reject_malformed_elements(label: str, check: object, fragment: str) -> None:
    payload = make_cf_hunt_payload(make_cf_unit(checks=[check]))
    with pytest.raises(ValueError, match=fragment):
        validate_hunt_payload(payload)


def test_hunt_checks_reject_empty_and_oversized_lists() -> None:
    with pytest.raises(ValueError, match="checks must be a non-empty array"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(checks=[])))

    oversized = [make_cf_check() for _ in range(CF_MAX_LIST_ITEMS + 1)]
    with pytest.raises(ValueError, match="exceeds"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(checks=oversized)))


# --- A-T14 / A-T15 / A-T16 / A-T17: paths and identity ----------------------

def test_hunt_checks_path_and_owner_invariants() -> None:
    with pytest.raises(ValueError, match="duplicate entry"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            checks=[make_cf_check(reviewed_paths=["src/app.py", "src/app.py"])],
        )))

    with pytest.raises(ValueError, match="invalid repository-relative path"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            reviewed_paths=["../etc/passwd"],
            checks=[make_cf_check(reviewed_paths=["../etc/passwd"])],
        )))

    with pytest.raises(ValueError, match="invalid repository-relative path"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            reviewed_paths=["con/app.py"],
            checks=[make_cf_check(reviewed_paths=["con/app.py"])],
        )))

    with pytest.raises(ValueError, match="has no check owner"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            reviewed_paths=["src/app.py", "src/other.py"],
            checks=[make_cf_check(reviewed_paths=["src/app.py"])],
        )))

    with pytest.raises(ValueError, match="is absent from aggregate reviewed_paths"):
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            reviewed_paths=["src/app.py"],
            checks=[make_cf_check(reviewed_paths=["src/app.py", "src/other.py"])],
        )))


def test_hunt_checks_accept_upstream_legal_agent_ids() -> None:
    """Real corpus slugs and upstream-legal underscores must not be rejected."""

    for agent_id in ("hunter-e", "w2-public-and-auth", "agent_1"):
        kind, _ = validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            checks=[make_cf_check(agent_id=agent_id)],
        )))
        assert kind == "hunt", agent_id


# --- A-T12 / A-T13 / A-T19 / A-T21: admission -------------------------------

def _local_payload() -> dict:
    return make_cf_hunt_payload(make_cf_unit(
        checks=[make_cf_check(method="local", artifact=ARTIFACT)],
    ))


def test_hunt_checks_local_artifact_incomplete() -> None:
    state, data = admit_hunt_payload(_local_payload(), known_agent_ids=["hunter-e"])
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    assert CF_INCOMPLETE_MISSING_LOCAL_ARTIFACT in data["admission"]["reason_codes"]

    state, data = admit_hunt_payload(
        _local_payload(),
        known_agent_ids=["hunter-e"],
        verified_artifacts={ARTIFACT: CF_ARTIFACT_PROMOTION_FAILED},
    )
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    assert CF_INCOMPLETE_ARTIFACT_PROMOTION_FAILED in data["admission"]["reason_codes"]

    state, data = admit_hunt_payload(
        _local_payload(),
        known_agent_ids=["hunter-e"],
        verified_artifacts={ARTIFACT: CF_ARTIFACT_NOT_VERIFIED},
    )
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    assert CF_INCOMPLETE_ARTIFACT_NOT_VERIFIED in data["admission"]["reason_codes"]

    state, data = admit_hunt_payload(
        _local_payload(),
        known_agent_ids=["hunter-e"],
        verified_artifacts={ARTIFACT: CF_ARTIFACT_VERIFIED},
    )
    assert state == CF_ADMISSION_ACCEPTED
    assert data is not None
    assert data["admission"]["reason_codes"] == []


def test_hunt_checks_local_artifact_never_downgrades_to_source() -> None:
    """A local check that cannot be trusted keeps its own method and artifact."""

    state, data = admit_hunt_payload(_local_payload(), known_agent_ids=["hunter-e"])
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    check = data["units"][0]["checks"][0]
    assert check["method"] == "local"
    assert check["artifact"] == ARTIFACT


def test_hunt_checks_unbound_owner_is_never_trusted_evidence() -> None:
    state, data = admit_hunt_payload(_local_payload(), known_agent_ids=[])
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    assert CF_INCOMPLETE_ASSIGNMENT_UNAVAILABLE in data["admission"]["reason_codes"]

    state, data = admit_hunt_payload(_local_payload())
    assert state == CF_ADMISSION_INCOMPLETE
    assert data is not None
    assert CF_INCOMPLETE_ASSIGNMENT_UNAVAILABLE in data["admission"]["reason_codes"]


def test_hunt_checks_source_only_unit_is_accepted_when_owner_is_bound() -> None:
    state, data = admit_hunt_payload(
        make_cf_hunt_payload(),
        known_agent_ids=["hunter-e"],
    )
    assert state == CF_ADMISSION_ACCEPTED
    assert data is not None
    assert data["admission"]["units"][0]["state"] == CF_ADMISSION_ACCEPTED


# --- A-T22 / E24: the contract blocks the graph ----------------------------

def test_malformed_hunt_checks_never_reach_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hunt handler must reject malformed checks before appending a fact."""

    from linen.dispatcher.tasks import skill_audit

    appended: list[dict] = []

    def _record(*args: Any, **kwargs: Any) -> bool:
        appended.append(kwargs)
        return True

    monkeypatch.setattr(skill_audit, "_append_fact", _record)
    payload = make_cf_hunt_payload(make_cf_unit(checks=[{}]))
    with pytest.raises(ValueError):
        skill_audit._handle_hunt(None, None, None, None, payload, "run-1", 1, None)
    assert appended == []


# --- E26: equivalence with the pinned Node validator ------------------------

PROBE_SOURCE = """
const fs = require("node:fs");
const { isSafeAgentId, isSafeRelativePath, hasVisibleProse } = require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const MAX_TEXT_LENGTH = 4096;
// Mirrors validate-coverage-ledger.cjs isVisibleText verbatim; the upstream
// module does not export it.
function isVisibleText(value, maxLength = MAX_TEXT_LENGTH) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    value.trim() === value &&
    hasVisibleProse(value);
}
process.stdout.write(JSON.stringify({
  agentIds: input.agentIds.map((value) => isSafeAgentId(value)),
  paths: input.paths.map((value) => isSafeRelativePath(value)),
  texts: input.texts.map((value) => isVisibleText(value)),
}));
"""

EQUIVALENCE_CASES: dict[str, list[Any]] = {
    "agentIds": [
        "hunter-e", "w2-public-and-auth", "agent_1", "Agent-1", "_agent", "con",
        "prn", "nul", "com1", "lpt9", "a" * 64, "a" * 65, "", "agent-1 ",
        "agent-1\n",
    ],
    "paths": [
        "src/app.py", "src/a b.py", "../x", "a/../b", "/abs", "C:/x", "C:\\x",
        "\\\\srv\\share", "~/x", "a//b", "a/./b", "a/..", "con/file.py", "con",
        "dir./x", "dir /x", "a:b", "a\\b", "a\x00b", "a\u00adb", "trailing ",
        "trailing.", "src/app.py ", ".", "..",
    ],
    "texts": [
        "", "   ", " result", "result ", "ok", "a\x00b", "a\u00adb", "a\u200bb",
        "\u00a0", "\u65e5\u672c\u8a9e\u30c6\u30ad\u30b9\u30c8", "a" * 4096,
        "a" * 4097, "\U0001f600" * 2048, "\U0001f600" * 3000,
        "\u001cabc", "abc\u001c",
    ],
}


def _accepts_agent_id(value: Any) -> bool:
    try:
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            checks=[make_cf_check(agent_id=value)],
        )))
    except ValueError:
        return False
    return True


def _accepts_path(value: Any) -> bool:
    try:
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            reviewed_paths=[value],
            checks=[make_cf_check(reviewed_paths=[value])],
        )))
    except ValueError:
        return False
    return True


def _accepts_text(value: Any) -> bool:
    try:
        validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
            checks=[make_cf_check(invariant=value, result=value)],
        )))
    except ValueError:
        return False
    return True


def test_upstream_probe_mirror_is_still_faithful() -> None:
    """Guard the probe copy against silent drift in the vendored validator."""

    source = cf_skill_file("validate-coverage-ledger.cjs").read_text(encoding="utf-8")
    assert "value.length <= maxLength &&" in source
    assert "value.trim() === value &&" in source
    assert "hasVisibleProse(value);" in source


@pytest.mark.parametrize("kind", ["agentIds", "paths", "texts"])
def test_hunt_checks_upstream_contract_equivalence(tmp_path: Path, kind: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    validator = cf_skill_file("validate-coverage-ledger.cjs")
    probe = tmp_path / "probe.cjs"
    probe.write_text(PROBE_SOURCE, encoding="utf-8")
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps(EQUIVALENCE_CASES), encoding="utf-8")

    result = subprocess.run(
        [node, str(probe), str(validator), str(inputs)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    assert result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    upstream = json.loads(result.stdout)

    acceptors = {
        "agentIds": _accepts_agent_id,
        "paths": _accepts_path,
        "texts": _accepts_text,
    }
    accept = acceptors[kind]
    for value, expected in zip(EQUIVALENCE_CASES[kind], upstream[kind]):
        assert accept(value) is bool(expected), (
            f"{kind} divergence for {value!r}: upstream={expected} linen={accept(value)}"
        )


# --- E28: real corpus re-verification ---------------------------------------

def _corpus_root() -> Path | None:
    configured = os.environ.get("LINEN_CF_CORPUS")
    root = Path(configured) if configured else Path.home() / "security-audit-skill"
    return root if root.is_dir() else None


@pytest.mark.skipif(_corpus_root() is None, reason="CF corpus is not available")
def test_real_coverage_checks_pass_linen_contract() -> None:
    root = _corpus_root()
    assert root is not None
    ledgers = sorted(root.glob("*/run-1/coverage-ledger.json"))
    assert ledgers, f"no coverage ledgers under {root}"

    artifacts = 0
    units = 0
    checks = 0
    failures: list[str] = []
    for path in ledgers:
        artifacts += 1
        document = json.loads(path.read_text(encoding="utf-8"))
        for unit in document:
            units += 1
            unit_checks = unit.get("local_checks") or unit.get("checks") or []
            owned: set[str] = set()
            for check in unit_checks:
                checks += 1
                try:
                    validate_hunt_payload(make_cf_hunt_payload(make_cf_unit(
                        coverage_id=unit.get("coverage_id", "cov-0001"),
                        reviewed_paths=list(check.get("reviewed_paths", [])),
                        checks=[check],
                    )))
                except ValueError as exc:
                    failures.append(f"{path.name}:{unit.get('coverage_id')}: {exc}")
                    continue
                owned.update(check.get("reviewed_paths", []))
            if owned != set(unit.get("reviewed_paths", [])):
                failures.append(f"{path.name}:{unit.get('coverage_id')}: path ownership mismatch")

    assert not failures, failures[:10]
    assert units > 0 and checks > 0
