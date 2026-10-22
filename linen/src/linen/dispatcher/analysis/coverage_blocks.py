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

Two things are deliberately kept apart (D-033):

``canonical_refs.attack_class``
    a *descriptive* identity reference.  It is one of the four dimensions a
    coverage id is derived from, so it must not be narrowed to a fixed
    classification list.

``ordinary_attack_class_block``
    the ordinary block the plan *selected*.  It has to be one of the titles
    the pinned snapshot actually carries.

They happen to coincide for some seeds, but that is a coincidence, not a
rule: a descriptive reference is never converted into a block title by
guessing, by case folding or by rewriting snake_case.  When the two do not
coincide, the trusted plan has to name the block, and without that the
selection is *unresolved* rather than approximate.

The companion playbooks are a separate upstream artifact that is not part of
the vendored snapshot, so linen's block map has no companion blocks.  That is
recorded as an *explicit* capability state rather than an empty array alone:
"the catalog was there and nothing was chosen" and "there was no catalog" are
different statements, and only the second one is true here.
"""

from __future__ import annotations

import re
from pathlib import Path

from linen.contracts.skill_audit import CoverageBlockSelection
from linen.dispatcher.analysis.cf_skill_assets import ATTACK_CLASSES
from linen.dispatcher.analysis.skill_prompts import (
    load_attack_classes_block,
    vendored_skill_dir,
)

#: The header shape of an ordinary block in ATTACK-CLASSES.md.
_BLOCK_TITLE_RE = re.compile(r"^\*\*([A-Z][A-Za-z /-]+)\*\* \(", re.MULTILINE)


class BlockSelectionUnresolved(LookupError):
    """The wave was not given an ordinary block, and none can be derived.

    The failure is explicit on purpose: an approximate match would put a
    block in front of a hunter that the plan never chose, and the resulting
    evidence would claim a coverage the assignment never established.
    """

    code = "block_selection_unresolved"


def ordinary_block_titles(skill_dir: Path | None = None) -> list[str]:
    """The ordinary block titles of the pinned snapshot, in file order."""

    directory = skill_dir or vendored_skill_dir()
    text = (directory / ATTACK_CLASSES).read_text(encoding="utf-8")
    return list(_BLOCK_TITLE_RE.findall(text))


def resolve_ordinary_block(
    attack_class: str,
    *,
    ordinary_block: str | None = None,
    skill_dir: Path | None = None,
) -> str:
    """The ordinary block title this wave is assigned.

    An explicitly named block wins, as long as the snapshot really carries
    it.  Otherwise the descriptive attack class is used only when it is
    *exactly* a block title.  Anything else is unresolved.
    """

    titles = ordinary_block_titles(skill_dir)
    if ordinary_block is not None:
        if ordinary_block not in titles:
            raise BlockSelectionUnresolved(
                f"the selected ordinary block {ordinary_block!r} is not one of the "
                "ordinary blocks of the pinned snapshot"
            )
        return ordinary_block
    if attack_class in titles:
        return attack_class
    raise BlockSelectionUnresolved(
        f"attack class {attack_class!r} is a descriptive reference, not one of the "
        "ordinary block titles of the pinned snapshot; the trusted plan has to "
        "select the ordinary block explicitly"
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
    ordinary_block: str | None = None,
    skill_dir: Path | None = None,
) -> CoverageBlockSelection:
    """The trusted block map of one coverage unit.

    The block has to exist verbatim in the pinned snapshot: a class that the
    snapshot does not carry is an error, not a silently empty selection.
    """

    directory = skill_dir or vendored_skill_dir()
    block = resolve_ordinary_block(
        attack_class, ordinary_block=ordinary_block, skill_dir=directory
    )
    load_attack_classes_block(block, directory)
    reference = ordinary_block_reference(block)
    return CoverageBlockSelection(
        ordinary_attack_class_block=reference,
        selected_companion_blocks=[],
        excluded_blocks=[],
        companion_catalog_state="unavailable",
        source=reference,
    )
