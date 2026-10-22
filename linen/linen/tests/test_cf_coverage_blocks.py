"""Regression tests for the trusted coverage block map (CF-S2-A).

The block map a wave is handed has to be a decision the *plan* made, and it
has to be traceable to the pinned upstream snapshot.  These tests pin that
behaviour, and they also pin the extraction of every ordinary attack class
in the snapshot: the last block of the file has no following header, and a
block that can never be selected is a class that can never be audited.
"""

from __future__ import annotations

import re

import pytest

from linen.dispatcher.analysis.coverage_blocks import (
    coverage_unit_block_selection,
    ordinary_block_reference,
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

    with pytest.raises(ValueError):
        coverage_unit_block_selection("No Such Attack Class")
