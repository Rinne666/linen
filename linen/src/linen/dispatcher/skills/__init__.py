"""Trusted, dispatcher-owned skill metadata.

Skills are capability labels, not worker roles.  A worker may use a skill, but
only the dispatcher can issue a receipt for an execution.  Keeping this
registry in the dispatcher also means an LLM cannot invent a skill id or claim
that a command ran by writing prose.
"""

from .registry import (
    SkillDefinition,
    SkillReceipt,
    build_receipt,
    get_skill,
    skill_for_scanner,
    validate_receipt,
)

__all__ = [
    "SkillDefinition",
    "SkillReceipt",
    "build_receipt",
    "get_skill",
    "skill_for_scanner",
    "validate_receipt",
]
