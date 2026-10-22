"""Acceptance tests for the vendored Cloudflare security-audit-skill snapshot.

CF-S0 requires that a clean checkout and an installed wheel both resolve the
pinned upstream files without any ``.linen-runtime`` copy, without a network
fetch, and without depending on the process working directory.

Checks:
- every required snapshot file is present inside the package;
- the upstream files are byte-identical to the pinned commit (SHA-256);
- the recorded upstream commit, licence and attribution are present;
- resource resolution is independent of the current working directory;
- the built wheel carries the same files with the same digests.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from linen.dispatcher.analysis.cf_skill_assets import (
    REQUIRED_FILES,
    WINDOWS_RUNNER,
    cf_skill_dir,
    cf_skill_file,
    missing_cf_skill_files,
)

#: Upstream commit the snapshot is pinned to.
EXPECTED_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"

#: Files that come from upstream and therefore must never be edited locally.
UPSTREAM_FILES = (
    "LICENSE",
    "ATTACK-CLASSES.md",
    "HUNTING.md",
    "report-schema.json",
    "validate-coverage-ledger.cjs",
    "validate-coverage-ledger.test.cjs",
    "validate-findings.cjs",
    "validate-findings.test.cjs",
)

#: Files maintained by linen inside the snapshot directory.
LINEN_FILES = (
    "PROVENANCE.md",
    "SHA256SUMS",
    "UPSTREAM_COMMIT",
    WINDOWS_RUNNER,
)

#: Repository layout: <repo>/linen/linen/tests/test_cf_vendor_resources.py
REPO_ROOT = Path(__file__).resolve().parents[3]
PROJECT_DIR = REPO_ROOT / "linen"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot() -> Path:
    return cf_skill_dir()


def test_required_snapshot_files_are_present() -> None:
    missing = missing_cf_skill_files()
    assert missing == [], f"missing vendored upstream files: {missing}"
    for name in REQUIRED_FILES:
        assert cf_skill_file(name).is_file()


def test_snapshot_lives_inside_the_installed_package() -> None:
    snapshot = _snapshot()
    package_root = Path(__import__("linen").__file__).resolve().parent
    assert package_root in snapshot.parents, (
        f"vendored snapshot {snapshot} is not inside the installed package {package_root}"
    )


def test_resolution_does_not_depend_on_the_working_directory(tmp_path: Path) -> None:
    original = Path.cwd()
    try:
        os.chdir(tmp_path)
        from_tmp = cf_skill_dir()
        os.chdir(REPO_ROOT)
        from_repo = cf_skill_dir()
    finally:
        os.chdir(original)
    assert from_tmp == from_repo
    assert from_tmp.is_absolute()


def test_upstream_commit_is_pinned() -> None:
    recorded = (_snapshot() / "UPSTREAM_COMMIT").read_text(encoding="utf-8").strip()
    assert recorded == EXPECTED_COMMIT


def test_upstream_files_match_recorded_sha256sums() -> None:
    sums_file = _snapshot() / "SHA256SUMS"
    recorded: dict[str, str] = {}
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        recorded[name.strip()] = digest.strip()

    assert set(recorded) == set(UPSTREAM_FILES), (
        f"SHA256SUMS covers {sorted(recorded)}, expected {sorted(UPSTREAM_FILES)}"
    )
    for name, digest in recorded.items():
        assert _digest(_snapshot() / name) == digest, (
            f"{name} does not match the digest recorded in SHA256SUMS; the snapshot "
            f"must keep the canonical upstream bytes (LF line endings, see "
            f".gitattributes) on every platform"
        )


def test_snapshot_keeps_canonical_lf_line_endings() -> None:
    """A CRLF checkout must never diverge from the recorded upstream digests."""
    for name in UPSTREAM_FILES:
        payload = (_snapshot() / name).read_bytes()
        assert b"\r\n" not in payload, (
            f"{name} contains CRLF line endings; the vendored snapshot must keep "
            f"the upstream LF bytes (see .gitattributes and PROVENANCE.md)"
        )


def test_license_and_attribution_are_preserved() -> None:
    licence = (_snapshot() / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in licence
    assert "Cloudflare, Inc." in licence

    provenance = (_snapshot() / "PROVENANCE.md").read_text(encoding="utf-8")
    assert EXPECTED_COMMIT in provenance
    assert "MIT" in provenance


def test_linen_authored_files_are_not_in_the_upstream_digest_list() -> None:
    recorded = (_snapshot() / "SHA256SUMS").read_text(encoding="utf-8")
    for name in LINEN_FILES:
        assert name not in recorded, f"{name} is linen-authored and must not be listed as upstream"
        assert (_snapshot() / name).is_file()


def test_windows_runner_is_executable_by_node() -> None:
    runner = _snapshot() / WINDOWS_RUNNER
    assert runner.is_file()
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available")
    result = subprocess.run(
        [node, str(runner)], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60,
    )
    assert result.returncode == 1
    assert "Usage:" in (result.stdout + result.stderr)


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not available")
def test_built_wheel_carries_the_same_snapshot(tmp_path: Path) -> None:
    out_dir = tmp_path / "dist"
    result = subprocess.run(
        ["uv", "build", "--project", str(PROJECT_DIR), "--out-dir", str(out_dir)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
    )
    assert result.returncode == 0, (result.stdout or "") + (result.stderr or "")

    wheels = sorted(out_dir.glob("*.whl"))
    assert wheels, "uv build produced no wheel"

    snapshot = _snapshot()
    prefix = "linen/third_party/cloudflare_security_audit_skill/"
    with zipfile.ZipFile(wheels[-1]) as archive:
        names = set(archive.namelist())
        for name in UPSTREAM_FILES + LINEN_FILES:
            member = prefix + name
            assert member in names, f"{member} missing from the wheel"
            payload = archive.read(member)
            assert hashlib.sha256(payload).hexdigest() == _digest(snapshot / name), (
                f"{name} differs between the source tree and the wheel"
            )


def test_no_runtime_directory_copy_is_required() -> None:
    """The snapshot must be reachable without any .linen-runtime copy."""
    assert cf_skill_file("validate-findings.cjs").is_file()
    assert cf_skill_file("validate-coverage-ledger.cjs").is_file()
    assert cf_skill_file("ATTACK-CLASSES.md").is_file()
    assert cf_skill_file("HUNTING.md").is_file()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
