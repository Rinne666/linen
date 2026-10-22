"""CF-S1-B: canonical coverage identity and read-only legacy aliases.

The retired ``cov-<n>`` activity identifier is replaced by a canonical id that
is *derived* from the four descriptive dimensions of a coverage unit
(surface x boundary x subsystem x attack class), encoded exactly like the
pinned upstream validator does.

Checks:
- the derived id matches the upstream encoder, byte for byte;
- the real corpus reproduces its own recorded ids (366/366);
- a hand-written id is accepted only when it equals the derived id;
- the legacy scheme survives only as an explicit, read-only alias (D-017).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from linen.contracts.common import (
    CF_CANONICAL_REF_FIELDS,
    cf_canonical_coverage_id,
    cf_encode_canonical_ref,
    cf_is_legacy_coverage_id,
    cf_resolve_legacy_coverage_id,
)
from linen.contracts.skill_audit import CoverageUnit
from linen.dispatcher.analysis.cf_skill_assets import cf_skill_file
from linen.dispatcher.config import CoverageUnitSeed

CORPUS_ENV = "LINEN_CF_CORPUS"

REFS = {
    "surface": "src/router.ts#POST /users/:id",
    "boundary": "src/authz.ts#requireOwner",
    "subsystem": "packages/api",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}

ADVERSARIAL_REFS: list[dict[str, Any]] = [
    dict(REFS),
    {"surface": "a b", "boundary": "c/d", "subsystem": "e", "attack_class": "f"},
    {"surface": "ünïcødé", "boundary": "日本語", "subsystem": "s", "attack_class": "a"},
    {"surface": "emoji \U0001f600", "boundary": "b", "subsystem": "s", "attack_class": "a"},
    {"surface": "tilde~dash-dot.under_", "boundary": "b", "subsystem": "s", "attack_class": "a"},
    {"surface": "100%", "boundary": "b", "subsystem": "s", "attack_class": "a"},
    {"surface": "", "boundary": "b", "subsystem": "s", "attack_class": "a"},
    {"surface": " leading", "boundary": "b", "subsystem": "s", "attack_class": "a"},
    {"surface": "a", "boundary": "b", "subsystem": "s"},
    {"surface": "a", "boundary": "b", "subsystem": "s", "attack_class": "a", "extra": "x"},
]

CANONICAL_PROBE = """
const fs = require("node:fs");
const { canonicalCoverageId } = require(process.argv[2]);
const input = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
process.stdout.write(JSON.stringify(input.map((refs) => {
  try {
    return { ok: true, id: canonicalCoverageId(refs) };
  } catch (error) {
    return { ok: false };
  }
})));
"""


def _corpus_root() -> Path | None:
    configured = __import__("os").environ.get(CORPUS_ENV)
    root = Path(configured) if configured else Path.home() / "security-audit-skill"
    return root if root.is_dir() else None


# --- B01 / B02 / B03: derivation and encoding --------------------------------

def test_canonical_id_is_derived_from_the_four_dimensions() -> None:
    coverage_id = cf_canonical_coverage_id(REFS)
    parts = coverage_id.split("::")
    assert len(parts) == len(CF_CANONICAL_REF_FIELDS)
    assert parts == [cf_encode_canonical_ref(REFS[field]) for field in CF_CANONICAL_REF_FIELDS]


def test_canonical_ref_encoding_uses_upper_case_percent_escapes() -> None:
    assert cf_encode_canonical_ref("POST /users/:id") == "POST%20%2Fusers%2F%3Aid"
    assert cf_encode_canonical_ref("a-b._~") == "a-b._~"
    assert cf_encode_canonical_ref("ü") == "%C3%BC"


def test_canonical_ref_rejects_non_normalized_and_empty_references() -> None:
    with pytest.raises(ValueError, match="invalid canonical reference"):
        cf_encode_canonical_ref("")
    with pytest.raises(ValueError, match="invalid canonical reference"):
        cf_encode_canonical_ref(" leading")
    with pytest.raises(ValueError, match="invalid canonical reference"):
        cf_encode_canonical_ref("a" * 1025)


def test_canonical_ref_rejects_missing_or_unexpected_dimensions() -> None:
    with pytest.raises(ValueError, match="missing or unexpected fields"):
        cf_canonical_coverage_id({"surface": "a", "boundary": "b", "subsystem": "c"})
    with pytest.raises(ValueError, match="missing or unexpected fields"):
        cf_canonical_coverage_id({**REFS, "extra": "x"})


def test_canonical_ref_accepts_the_upstream_lifecycle_dimension() -> None:
    with_lifecycle = cf_canonical_coverage_id({**REFS, "lifecycle": "wave-1"})
    assert with_lifecycle.count("::") == 4
    assert with_lifecycle != cf_canonical_coverage_id(REFS)


# --- B13: the upstream fifth dimension never enters the active protocol -----
# N1 froze linen's active coverage identity at four dimensions.  The generic
# helper stays upstream-compatible, but the two active entry points must not
# accept a fifth dimension as an activity identity.

def test_upstream_canonical_helper_supports_lifecycle() -> None:
    """The compatibility helper keeps the upstream five-dimension encoding."""

    four = cf_canonical_coverage_id(REFS)
    five = cf_canonical_coverage_id({**REFS, "lifecycle": "wave-1"})
    assert len(four.split("::")) == len(CF_CANONICAL_REF_FIELDS) == 4
    assert len(five.split("::")) == 5
    assert five.startswith(f"{four}::")
    assert five != four


def test_active_coverage_rejects_lifecycle_dimension() -> None:
    """A fifth dimension must not reach an active coverage unit or seed."""

    with pytest.raises(ValidationError):
        CoverageUnitSeed(
            surface=REFS["surface"],
            boundary=REFS["boundary"],
            subsystem=REFS["subsystem"],
            attack_class=REFS["attack_class"],
            lifecycle="wave-1",
        )

    with pytest.raises(ValidationError):
        CoverageUnit.model_validate({
            "surface": REFS["surface"],
            "boundary": REFS["boundary"],
            "subsystem": REFS["subsystem"],
            "attack_class": REFS["attack_class"],
            "lifecycle": "wave-1",
        })

    # The four-dimensional forms stay valid and keep their derived id.
    seed = CoverageUnitSeed(
        surface=REFS["surface"],
        boundary=REFS["boundary"],
        subsystem=REFS["subsystem"],
        attack_class=REFS["attack_class"],
    )
    assert seed.coverage_id == cf_canonical_coverage_id(REFS)
    unit = CoverageUnit.model_validate({
        "surface": REFS["surface"],
        "boundary": REFS["boundary"],
        "subsystem": REFS["subsystem"],
        "attack_class": REFS["attack_class"],
    })
    assert unit.coverage_id == cf_canonical_coverage_id(REFS)


# --- B04 / B05 / B06: identity properties ------------------------------------

def test_canonical_id_carries_no_execution_fields() -> None:
    coverage_id = cf_canonical_coverage_id(REFS)
    for forbidden in ("wave", "agent", "severity", "verdict"):
        assert forbidden not in coverage_id.lower()


def test_canonical_id_is_stable_across_runs() -> None:
    assert cf_canonical_coverage_id(REFS) == cf_canonical_coverage_id(dict(REFS))


def test_canonical_identity_collision_rejected() -> None:
    """Different dimensions never share an id, and a wrong id is rejected."""

    other = {**REFS, "subsystem": "packages/web"}
    assert cf_canonical_coverage_id(REFS) != cf_canonical_coverage_id(other)

    with pytest.raises(ValidationError, match="must equal the canonical id"):
        CoverageUnitSeed(
            coverage_id=cf_canonical_coverage_id(other),
            surface=REFS["surface"],
            boundary=REFS["boundary"],
            subsystem=REFS["subsystem"],
            attack_class=REFS["attack_class"],
        )


# --- B07 / D-017: the legacy scheme is read-only ----------------------------

def test_legacy_coverage_id_is_read_only() -> None:
    assert cf_is_legacy_coverage_id("cov-0001")
    assert not cf_is_legacy_coverage_id(cf_canonical_coverage_id(REFS))

    with pytest.raises(ValidationError, match="retired cov-<n> scheme"):
        CoverageUnitSeed(
            coverage_id="cov-0001",
            surface=REFS["surface"],
            boundary=REFS["boundary"],
            subsystem=REFS["subsystem"],
            attack_class=REFS["attack_class"],
        )

    with pytest.raises(ValidationError, match="retired cov-<n> scheme"):
        CoverageUnit.model_validate({
            "coverage_id": "cov-0001",
            "surface": REFS["surface"],
            "boundary": REFS["boundary"],
            "subsystem": REFS["subsystem"],
            "attack_class": REFS["attack_class"],
        })


def test_legacy_coverage_id_resolves_only_through_an_explicit_alias() -> None:
    canonical = cf_canonical_coverage_id(REFS)
    aliases = {("run-1", "cov-0001"): canonical}
    assert cf_resolve_legacy_coverage_id(
        "cov-0001", aliases, legacy_source_id="run-1",
    ) == canonical

    with pytest.raises(ValueError, match="unresolved_alias"):
        cf_resolve_legacy_coverage_id(
            "cov-0002", aliases, legacy_source_id="run-1",
        )

    with pytest.raises(ValueError, match="not a legacy coverage id"):
        cf_resolve_legacy_coverage_id(
            canonical, aliases, legacy_source_id="run-1",
        )


def test_coverage_seed_derives_its_identifier() -> None:
    seed = CoverageUnitSeed(
        surface=REFS["surface"],
        boundary=REFS["boundary"],
        subsystem=REFS["subsystem"],
        attack_class=REFS["attack_class"],
    )
    assert seed.coverage_id == cf_canonical_coverage_id(REFS)


# --- B08 / equivalence with the pinned Node validator ------------------------

def test_canonical_id_matches_upstream(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    probe = tmp_path / "probe.cjs"
    probe.write_text(CANONICAL_PROBE, encoding="utf-8")
    inputs = tmp_path / "refs.json"
    inputs.write_text(json.dumps(ADVERSARIAL_REFS), encoding="utf-8")
    result = subprocess.run(
        [node, str(probe), str(cf_skill_file("validate-coverage-ledger.cjs")), str(inputs)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    assert result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    upstream = json.loads(result.stdout)

    for refs, expected in zip(ADVERSARIAL_REFS, upstream):
        if expected["ok"]:
            assert cf_canonical_coverage_id(refs) == expected["id"], refs
        else:
            with pytest.raises(ValueError):
                cf_canonical_coverage_id(refs)


@pytest.mark.skipif(_corpus_root() is None, reason="CF corpus is not available")
def test_real_corpus_coverage_ids_match_upstream() -> None:
    """The 366 recorded upstream ids must be reproducible from their dimensions."""

    root = _corpus_root()
    assert root is not None
    ledgers = sorted(root.glob("*/run-1/coverage-ledger.json"))
    assert ledgers, f"no coverage ledgers under {root}"

    units = 0
    matched = 0
    mismatches: list[str] = []
    for path in ledgers:
        for unit in json.loads(path.read_text(encoding="utf-8")):
            units += 1
            refs = unit.get("canonical_refs")
            recorded = unit.get("coverage_id")
            if not isinstance(refs, dict) or not isinstance(recorded, str):
                mismatches.append(f"{path.name}: missing canonical_refs or coverage_id")
                continue
            if cf_canonical_coverage_id(refs) == recorded:
                matched += 1
            else:
                mismatches.append(
                    f"{path.name}: {recorded} != {cf_canonical_coverage_id(refs)}"
                )

    assert not mismatches, mismatches[:5]
    assert units == 366, units
    assert matched == 366, matched
