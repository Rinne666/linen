"""The trusted block map of a coverage unit (CF-S2-A).

Which blocks a hunter receives is the plan's decision, not the model's.  The
dispatcher cuts the blocks verbatim out of the pinned upstream snapshot and
puts them into the hunter prompt; upstream treats the assignment block map
the same way, and the hunter's own result never carries block fields.

Up to now that decision only existed inside a rendered prompt string, so
nothing could record *which* blocks a wave was given.  This module makes the
decision a first-class value: the same computation that fills the prompt can
be stored in the coverage event ledger, and the stored value is traceable to
the exact place in the pinned snapshot it came from.

The companion playbooks are a separate upstream artifact that is not part of
the vendored snapshot, so linen's block map has no companion blocks.  That is
recorded as an *explicit* empty list rather than a missing field: "no
companion was selected" and "we did not record the companion selection" are
different statements, and only the first one is true here.
"""

from __future__ import annotations

from pathlib import Path

from linen.contracts.skill_audit import CoverageBlockSelection
from linen.dispatcher.analysis.cf_skill_assets import ATTACK_CLASSES
from linen.dispatcher.analysis.skill_prompts import (
    load_attack_classes_block,
    vendored_skill_dir,
)


def ordinary_block_reference(attack_class: str) -> str:
    """The upstream-style reference of one ordinary attack-class block.

    Upstream identifies a block by ``FILE.md#section``, so the reference is
    file qualified even though linen's seeds name the block by its bare
    title.
    """

    return f"{ATTACK_CLASSES}#{attack_class}"


def coverage_unit_block_selection(
    attack_class: str,
    *,
    skill_dir: Path | None = None,
) -> CoverageBlockSelection:
    """The trusted block map of one coverage unit.

    The block has to exist verbatim in the pinned snapshot: a class that the
    snapshot does not carry is an error, not a silently empty selection.
    """

    directory = skill_dir or vendored_skill_dir()
    load_attack_classes_block(attack_class, directory)
    return CoverageBlockSelection(
        ordinary_attack_class_block=ordinary_block_reference(attack_class),
        selected_companion_blocks=[],
        excluded_blocks=[],
        source=ordinary_block_reference(attack_class),
    )
