"""Regression tests for the trusted coverage block map (CF-S2-A).

The block map a wave is handed has to be a decision the *plan* made, and it
has to be traceable to the pinned upstream snapshot.  These tests pin that
behaviour, and they also pin the extraction of every ordinary attack class
in the snapshot: the last block of the file has no following header, and a
block that can never be selected is a class that can never be audited.

The closing assertions of CF-S2-A are marked with their acceptance ids
(R-T01, R-T02, R-T04, R-T05); R-T03 and R-T06 live with the projection in
``test_skill_coverage_waves.py``.
"""

from __future__ import annotations

import re
from typing import get_args

import pytest
from pydantic import ValidationError

from linen.contracts.skill_audit import (
    AttackClass,
    CoverageBlockSelection,
    CoverageCanonicalRefs,
)
from linen.dispatcher.analysis.coverage_blocks import (
    BlockSelectionUnresolved,
    coverage_unit_block_selection,
    ordinary_block_reference,
    ordinary_block_titles,
    resolve_ordinary_block,
)
from linen.dispatcher.analysis.skill_prompts import (
    extract_ordinary_block,
    vendored_skill_dir,
)


@pytest.fixture
def attack_classes_text() -> str:
    return (vendored_skill_dir() / "ATTACK-CLASSES.md").read_text(encoding="utf-8")


def _block_names(text: str) -> list[str]:
    return re.findall(r"^\*\*([A-Z][A-Za-z /-]+)\*\* \(", text, re.MULTILINE)


def test_every_ordinary_block_of_the_snapshot_can_be_selected(attack_classes_text):
    """Every ordinary block in the snapshot is reachable.

    The final block of the file runs to the end of the file, so the
    extraction has to fall back to the end of the text instead of requiring
    a following header.
    """

    names = _block_names(attack_classes_text)
    assert names, "the snapshot carries no ordinary block"
    for name in names:
        block = extract_ordinary_block(attack_classes_text, name)
        assert block is not None, name
        assert block.startswith(f"**{name}** ("), name


def test_the_last_ordinary_block_is_not_truncated(attack_classes_text):
    """The last block is a real block, not a missing one."""

    names = _block_names(attack_classes_text)
    last = names[-1]
    block = extract_ordinary_block(attack_classes_text, last)
    assert block is not None
    assert len(block) > 200


def test_block_selection_is_traceable_to_the_snapshot():
    """The selection names the block it came from."""

    selection = coverage_unit_block_selection("Access control")
    assert selection.ordinary_attack_class_block == "ATTACK-CLASSES.md#Access control"
    assert selection.source == "ATTACK-CLASSES.md#Access control"
    assert ordinary_block_reference("Wildcard") == "ATTACK-CLASSES.md#Wildcard"


def test_companion_blocks_are_an_explicit_empty_list():
    """No companion playbook is vendored, so the selection says so."""

    selection = coverage_unit_block_selection("Injection")
    assert selection.selected_companion_blocks == []
    assert selection.excluded_blocks == []


def test_an_unknown_attack_class_is_refused():
    """A class the snapshot does not carry is an error, not an empty selection."""

    with pytest.raises(BlockSelectionUnresolved):
        coverage_unit_block_selection("No Such Attack Class")


# --- R-T01: an unavailable companion catalog means an empty selection -------


def test_rt01_an_unavailable_catalog_must_be_an_empty_selection():
    """R-T01: ``unavailable`` and "something was selected" cannot both be true."""

    with pytest.raises(ValidationError):
        CoverageBlockSelection(
            selected_companion_blocks=["WEB-PROTOCOL-AND-AUTH.md#Cache behavior"],
            companion_catalog_state="unavailable",
            source="plan",
        )


def test_rt01_linen_reports_the_catalog_as_unavailable():
    """R-T01: the snapshot ships no companion playbooks, so it says so.

    An empty list alone would be ambiguous: "the catalog was there and
    nothing was chosen" and "there was no catalog" are different facts.
    """

    selection = coverage_unit_block_selection("Injection")
    assert selection.companion_catalog_state == "unavailable"
    assert selection.selected_companion_blocks == []


# --- R-T02: an available catalog may legitimately select nothing ------------


def test_rt02_an_available_catalog_may_select_nothing():
    """R-T02: "the catalog was there and nothing was chosen" is a valid record."""

    selection = CoverageBlockSelection(
        companion_catalog_state="available",
        source="dispatcher/tasks/skill_audit.py:317",
    )
    assert selection.selected_companion_blocks == []
    assert selection.companion_catalog_state == "available"


def test_rt02_an_available_catalog_needs_a_traceable_selection_record():
    """R-T02: an empty selection still has to say where it was decided."""

    with pytest.raises(ValidationError):
        CoverageBlockSelection(
            companion_catalog_state="available",
            source="",
        )


def test_rt02_an_available_catalog_may_select_blocks():
    """R-T02: the state describes the catalog, not the size of the selection."""

    selection = CoverageBlockSelection(
        selected_companion_blocks=["WEB-PROTOCOL-AND-AUTH.md#Cache behavior"],
        companion_catalog_state="available",
        source="plan",
    )
    assert selection.selected_companion_blocks == [
        "WEB-PROTOCOL-AND-AUTH.md#Cache behavior"
    ]


# --- R-T04: the AttackClass alias stays compatible but stops being authority --


def test_rt04_the_attack_class_alias_is_still_importable():
    """R-T04: the public alias keeps working for existing importers."""

    values = get_args(AttackClass)
    assert "injection" in values
    assert "access_control" in values
    assert len(values) == 8


def test_rt04_the_attack_class_alias_does_not_restrict_the_canonical_refs():
    """R-T04: the descriptive dimension is not narrowed to the old list.

    The canonical refs are a *description* of what was audited; they are
    not a classification label, so a value that the legacy alias never
    carried is still a legal reference.
    """

    refs = CoverageCanonicalRefs(
        surface="http-public-api",
        boundary="anonymous-to-authenticated",
        subsystem="authorization",
        attack_class="access-control",
    )
    assert refs.attack_class == "access-control"
    assert "access-control" not in get_args(AttackClass)
    assert refs.derived_coverage_id().endswith("::access-control")


# --- R-T05: the ordinary block is one of the nine upstream titles -----------


def test_rt05_the_snapshot_carries_nine_ordinary_titles():
    """R-T05: the valid titles are exactly the ones the snapshot has."""

    titles = ordinary_block_titles()
    assert len(titles) == 9
    assert titles[0] == "Injection"
    assert titles[-1] == "Obvious things"


def test_rt05_an_exact_title_resolves():
    """R-T05: the exact upstream title is selected."""

    assert resolve_ordinary_block("Access control") == "Access control"


def test_rt05_a_descriptive_reference_does_not_resolve():
    """R-T05: a descriptive reference is not converted into a block title.

    Guessing a block would put a block in front of a hunter that the plan
    never chose, and the evidence would then claim a coverage the
    assignment never established.
    """

    with pytest.raises(BlockSelectionUnresolved) as excinfo:
        resolve_ordinary_block("access-control")
    assert excinfo.value.code == "block_selection_unresolved"


def test_rt05_snake_case_is_not_rewritten_into_a_title():
    """R-T05: no snake_case conversion, and no case folding either."""

    for reference in ("access_control", "Access_Control", "access control"):
        with pytest.raises(BlockSelectionUnresolved):
            resolve_ordinary_block(reference)


def test_rt05_an_explicitly_selected_block_wins():
    """R-T05: the trusted plan may name the block, and only a real one."""

    assert resolve_ordinary_block("access-control", ordinary_block="Wildcard") == (
        "Wildcard"
    )


def test_rt05_an_explicit_selection_of_a_missing_block_is_refused():
    """R-T05: an explicit selection is checked against the snapshot too."""

    with pytest.raises(BlockSelectionUnresolved):
        resolve_ordinary_block("Access control", ordinary_block="No Such Block")


def test_rt05_the_unresolved_failure_carries_a_machine_readable_code():
    """R-T05: the failure state is decidable, not a message to guess from."""

    with pytest.raises(BlockSelectionUnresolved) as excinfo:
        coverage_unit_block_selection("access-control")
    assert excinfo.value.code == "block_selection_unresolved"
    assert isinstance(excinfo.value, LookupError)
