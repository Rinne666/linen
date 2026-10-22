"""Locate the pinned Cloudflare security-audit-skill snapshot shipped with linen.

The snapshot lives inside the package (``linen/third_party/cloudflare_security_audit_skill``)
so that a source checkout and an installed wheel resolve exactly the same
files, independently of the process working directory. Nothing is ever
downloaded, and no ``.linen-runtime`` copy is required at runtime.

The upstream files are byte-identical to the pinned commit recorded in
``UPSTREAM_COMMIT``; ``SHA256SUMS`` lists their digests and
``linen/tests/test_cf_vendor_resources.py`` enforces both facts.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Directory name of the vendored snapshot inside the ``linen`` package.
VENDORED_DIR_NAME = "cloudflare_security_audit_skill"

#: Upstream files the runtime reads out of the snapshot.
ATTACK_CLASSES = "ATTACK-CLASSES.md"
HUNTING = "HUNTING.md"
REPORT_SCHEMA = "report-schema.json"
VALIDATE_FINDINGS = "validate-findings.cjs"
VALIDATE_COVERAGE_LEDGER = "validate-coverage-ledger.cjs"

#: linen-authored runner that restores the upstream CLI on platforms without
#: POSIX ``O_NOFOLLOW``/``O_NONBLOCK`` (Windows).
WINDOWS_RUNNER = "run-validator.windows.cjs"

#: Files that must exist for the snapshot to be usable.
REQUIRED_FILES = (
    ATTACK_CLASSES,
    HUNTING,
    REPORT_SCHEMA,
    VALIDATE_FINDINGS,
    VALIDATE_COVERAGE_LEDGER,
)


def cf_skill_dir() -> Path:
    """Return the directory of the pinned upstream snapshot.

    The path is anchored to the installed ``linen`` package, never to the
    process working directory, so dispatching from any directory resolves the
    same files.
    """
    return Path(__file__).resolve().parents[2] / "third_party" / VENDORED_DIR_NAME


def cf_skill_file(name: str) -> Path:
    """Return one file of the pinned upstream snapshot."""
    return cf_skill_dir() / name


def missing_cf_skill_files() -> list[str]:
    """Return the names of required snapshot files that are absent."""
    directory = cf_skill_dir()
    if not directory.is_dir():
        return list(REQUIRED_FILES)
    return [name for name in REQUIRED_FILES if not (directory / name).is_file()]


def validator_command(validator: Path, target: Path) -> list[str]:
    """Return the argv that runs an upstream validator against ``target``.

    Upstream opens its input with ``O_NOFOLLOW | O_NONBLOCK``. Node on win32
    does not expose those constants, so the upstream CLI rejects every input
    on Windows. There the linen-authored runner is used instead: it restores
    the two sentinels and strips them again before the real open, preserving
    every other upstream check (regular file, byte limit, strict UTF-8, JSON
    preflight, full document validation).

    The canonical acceptance platform remains Linux; the Windows runner exists
    so the same command can be executed locally and in Windows CI.
    """
    if os.name != "nt":
        return ["node", str(validator), str(target)]
    runner = cf_skill_dir() / WINDOWS_RUNNER
    if not runner.is_file():
        return ["node", str(validator), str(target)]
    return ["node", str(runner), str(validator), str(target)]
