"""Prompt assembly for the skill-driven audit mode.

Adapted from cloudflare/security-audit-skill @ c1c8a8c:
- attack-class blocks are copied VERBATIM into hunter prompts
  ("Do not send block or companion names alone" — HUNTING.md prompt part 4);
- the core hunting method is copied verbatim into every hunter prompt.

The vendored skill ships inside the package
(``linen/third_party/cloudflare_security_audit_skill``); its location is
resolved from the installed package, never from the working directory. A
missing copy is a configuration error for skill_driven audits, not something
to silently downgrade: the hunter prompt would lose its verbatim blocks.
"""

from __future__ import annotations

import re
from pathlib import Path

from linen.dispatcher.analysis.cf_skill_assets import (
    ATTACK_CLASSES,
    HUNTING,
    cf_skill_dir,
)
from linen.dispatcher.prompting import load_prompt, render_prompt

# Ordinary attack-class block headers in ATTACK-CLASSES.md, e.g.
# "**Injection** (subagent_type: `general`)". Companion files use
# "#### Attack classes" style headers instead and are included whole.
_BLOCK_HEADER_RE = re.compile(r"^\*\*(?P<name>[A-Z][A-Za-z /-]+)\*\* \(", re.MULTILINE)

# Core hunting method extraction from HUNTING.md.
_CORE_METHOD_HEADER = "#### Core hunting method — include in every hunter prompt"


def vendored_skill_dir(override: str | None = None) -> Path:
    """Return the directory of the pinned upstream snapshot.

    ``override`` is only for tests that need a different copy; the runtime
    always resolves the snapshot shipped inside the package.
    """
    if override:
        return Path(override)
    return cf_skill_dir()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_ordinary_block(text: str, class_name: str) -> str | None:
    """Return the verbatim block for one ordinary attack class.

    Blocks run from their ``**Name** (`` header to the next ordinary header
    or the next ``####`` section.  The last block of the file has no
    following header, so it runs to the end of the file; without that
    fallback the final ordinary class could never be selected.
    Matching is case-insensitive on the name.
    """
    pattern = re.compile(
        r"^\*\*" + re.escape(class_name) + r"\*\* \(.*?"
        r"(?=^\*\*[A-Z][A-Za-z /-]+\*\* \(|^\#{3,4} |\Z)",
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(text)
    if match is None:
        return None
    return match.group(0).rstrip()


def extract_core_hunting_method(hunting_text: str) -> str:
    """Return the verbatim core hunting method block from HUNTING.md.

    The block is a ```text fence; its body contains its own ``##`` headers,
    so the fence boundary (not headers) is the delimiter.
    """
    start = hunting_text.find(_CORE_METHOD_HEADER)
    if start < 0:
        raise ValueError("HUNTING.md is missing the core hunting method header")
    open_fence = hunting_text.find("```text", start)
    if open_fence < 0:
        raise ValueError("core hunting method block is missing its ```text fence")
    body_start = hunting_text.find("\n", open_fence) + 1
    close_fence = hunting_text.find("\n```", body_start)
    if close_fence < 0:
        raise ValueError("core hunting method block is not closed")
    return hunting_text[body_start:close_fence].strip()


def load_attack_classes_block(class_name: str, skill_dir: Path) -> str:
    text = _read(skill_dir / ATTACK_CLASSES)
    block = extract_ordinary_block(text, class_name)
    if block is None:
        raise ValueError(
            f"ATTACK-CLASSES.md has no ordinary block named {class_name!r}; "
            "coverage seeds must name a block that exists verbatim"
        )
    return block


def assemble_hunter_prompt(
    *,
    prompt_group: str,
    repo_path: str,
    architecture_fact: str,
    coverage_units: list[dict],
    attack_class_blocks: list[str],
    excluded_blocks: str,
    peer_coverage_ids: str,
    skill_dir: Path | None = None,
    core_hunting_method: str | None = None,
) -> str:
    """Render prompts/skill_audit/hunter.md with verbatim upstream blocks."""
    template = load_prompt(prompt_group, "hunter.md")
    directory = skill_dir or vendored_skill_dir()
    method = core_hunting_method or extract_core_hunting_method(
        _read(directory / HUNTING)
    )
    return render_prompt(template, {
        "repo_path": repo_path,
        "architecture_fact": architecture_fact,
        "coverage_units_json": _json_blob(coverage_units),
        "attack_class_blocks": "\n\n".join(attack_class_blocks),
        "excluded_blocks": excluded_blocks,
        "peer_coverage_ids": peer_coverage_ids,
        "core_hunting_method": method,
    })


def assemble_simple_prompt(
    *,
    prompt_group: str,
    name: str,
    replacements: dict[str, str],
) -> str:
    return render_prompt(load_prompt(prompt_group, name), replacements)


def _json_blob(value: object) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, indent=2)
