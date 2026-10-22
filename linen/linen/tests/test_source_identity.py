"""Regression tests for the file semantics of a source snapshot (D-064).

The verification of an audited source used to compare the **paths** and the
**content** of a tree and nothing else.  Two trees with the same content but
different file types are not the same tree, and a comparison that cannot tell
them apart may claim that nothing changed when something did (D-064).

What is pinned here:

* the mode of a file is part of its identity - ``100755`` is not ``100644``;
* a symlink is a symlink: it is never followed, and its digest is the digest
  of the link target text;
* a submodule is refused, not silently excluded from the comparison;
* a file whose type cannot be determined is refused, not skipped;
* a **v1** manifest keeps its digest and its meaning, and it cannot describe a
  comparable source state - that needs a **v2** manifest.

The tests that need a POSIX file system (the executable bit, symlinks, fifos)
say so instead of pretending that Windows behaves the same way.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from linen.server.source_identity import (
    GIT_MODE_EXECUTABLE,
    GIT_MODE_FILE,
    GIT_MODE_SYMLINK,
    PLATFORM_EXPRESSES_FILE_MODE,
    SOURCE_KIND_FILE,
    SOURCE_KIND_SYMLINK,
    SourceIdentityVerificationFailed,
    read_frozen_source_manifest_bytes,
    source_tree_state,
    verify_frozen_source_manifest,
    verify_git_source_snapshot,
)

requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not available on this machine"
)

requires_posix_mode = pytest.mark.skipif(
    not PLATFORM_EXPRESSES_FILE_MODE,
    reason="this platform cannot express the executable bit of a file",
)

requires_symlinks = pytest.mark.skipif(
    os.name == "nt", reason="this platform cannot create a symlink unprivileged"
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return completed.stdout.strip()


def _repo(root: Path, *, files: dict[str, str]) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "operator@example.invalid")
    _git(root, "config", "user.name", "operator")
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "initial")
    return _git(root, "rev-parse", "HEAD")


def _copy_tree(repo: Path, target: Path) -> Path:
    """A frozen copy of the tracked files, symlinks included."""

    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(repo.rglob("*")):
        if ".git" in path.parts:
            continue
        relative = path.relative_to(repo)
        destination = target / relative
        if path.is_symlink():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(os.readlink(path))
        elif path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
    return target


@requires_git
def test_a_snapshot_keeps_the_mode_of_the_commit(tmp_path):
    """D-064: the mode of a file is part of the identity of the file."""

    repo = tmp_path / "repo"
    commit = _repo(repo, files={"app.py": "print('hi')\n"})
    _git(repo, "update-index", "--chmod=+x", "app.py")
    _git(repo, "commit", "--quiet", "-m", "executable")
    commit = _git(repo, "rev-parse", "HEAD")
    assert "100755" in _git(repo, "ls-tree", "-r", "--full-tree", commit)

    snapshot = _copy_tree(repo, tmp_path / "snapshot")
    if PLATFORM_EXPRESSES_FILE_MODE:
        os.chmod(snapshot / "app.py", 0o644)
        with pytest.raises(SourceIdentityVerificationFailed) as failure:
            verify_git_source_snapshot(
                repo_root=repo, commit=commit, source_dir=snapshot
            )
        assert "mode" in str(failure.value)
    else:
        # the platform cannot express the bit: the check is skipped, and the
        # declared mode of the commit is the mode that is reported
        merged = verify_git_source_snapshot(
            repo_root=repo, commit=commit, source_dir=snapshot
        )
        entry = merged.file("app.py")
        assert entry is not None
        assert entry.mode == GIT_MODE_EXECUTABLE


@requires_git
@requires_symlinks
def test_a_symlink_is_verified_as_a_symlink(tmp_path):
    """D-064: a symlink is never followed and never treated as a file."""

    repo = tmp_path / "repo"
    commit = _repo(repo, files={"app.py": "print('hi')\n"})
    (repo / "link.py").symlink_to("app.py")
    _git(repo, "add", "link.py")
    _git(repo, "commit", "--quiet", "-m", "symlink")
    commit = _git(repo, "rev-parse", "HEAD")

    snapshot = _copy_tree(repo, tmp_path / "snapshot")
    merged = verify_git_source_snapshot(
        repo_root=repo, commit=commit, source_dir=snapshot
    )
    entry = merged.file("link.py")
    assert entry is not None
    assert entry.kind == SOURCE_KIND_SYMLINK
    assert entry.mode == GIT_MODE_SYMLINK
    assert entry.sha256 == hashlib.sha256(b"app.py").hexdigest()

    # a regular file with the same content is not the same thing
    (snapshot / "link.py").unlink()
    (snapshot / "link.py").write_text("app.py", encoding="utf-8")
    with pytest.raises(SourceIdentityVerificationFailed) as failure:
        verify_git_source_snapshot(
            repo_root=repo, commit=commit, source_dir=snapshot
        )
    assert "symlink" in str(failure.value)


@requires_git
def test_a_submodule_is_refused_and_not_excluded(tmp_path):
    """D-064: a submodule cannot be verified, so it is refused."""

    repo = tmp_path / "repo"
    commit = _repo(repo, files={"app.py": "print('hi')\n"})
    # a gitlink entry: the content of a submodule is not part of the tree
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{commit},vendor/lib")
    _git(repo, "commit", "--quiet", "-m", "submodule")
    commit = _git(repo, "rev-parse", "HEAD")
    assert "160000" in _git(repo, "ls-tree", "-r", "--full-tree", commit)

    snapshot = _copy_tree(repo, tmp_path / "snapshot")
    with pytest.raises(SourceIdentityVerificationFailed) as failure:
        verify_git_source_snapshot(
            repo_root=repo, commit=commit, source_dir=snapshot
        )
    assert "submodule" in str(failure.value)


@requires_git
@pytest.mark.skipif(os.name == "nt", reason="this platform has no fifo")
def test_a_file_of_an_unknown_type_is_refused_and_not_skipped(tmp_path):
    """D-064: a file whose type cannot be determined is never skipped."""

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("print('hi')\n", encoding="utf-8")
    os.mkfifo(tree / "pipe")

    state = source_tree_state(tree)
    assert state.undecidable == ("pipe",)
    assert [entry.path for entry in state.entries] == ["app.py"]

    manifest = read_frozen_source_manifest_bytes(
        json.dumps(
            {
                "version": 2,
                "files": [
                    {
                        "path": "app.py",
                        "sha256": hashlib.sha256(b"print('hi')\n").hexdigest(),
                        "mode": GIT_MODE_FILE,
                        "kind": SOURCE_KIND_FILE,
                    }
                ],
            }
        ).encode("utf-8")
    )
    with pytest.raises(SourceIdentityVerificationFailed) as failure:
        verify_frozen_source_manifest(manifest=manifest, source_dir=tree)
    assert "pipe" in str(failure.value)


def test_a_v1_manifest_keeps_its_digest_and_cannot_describe_a_state():
    """D-064: a v1 manifest keeps its meaning, and it cannot be compared."""

    body = json.dumps(
        {"files": [{"path": "app.py", "sha256": "a" * 64}]}
    ).encode("utf-8")
    manifest = read_frozen_source_manifest_bytes(body)
    assert manifest.version == 1
    assert manifest.files == (("app.py", "a" * 64),)
    assert manifest.digest() == hashlib.sha256(
        json.dumps(
            {
                "files": [{"path": "app.py", "sha256": "a" * 64}],
                "kind": "frozen-source-manifest",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(SourceIdentityVerificationFailed) as failure:
        manifest.tree_state()
    assert "file type" in str(failure.value)


def test_a_v2_manifest_carries_the_file_type_and_its_own_digest():
    """D-064: the v2 manifest is a different document with a different digest."""

    v1 = read_frozen_source_manifest_bytes(
        json.dumps({"files": [{"path": "app.py", "sha256": "a" * 64}]}).encode("utf-8")
    )
    v2 = read_frozen_source_manifest_bytes(
        json.dumps(
            {
                "version": 2,
                "files": [
                    {
                        "path": "app.py",
                        "sha256": "a" * 64,
                        "mode": GIT_MODE_EXECUTABLE,
                        "kind": SOURCE_KIND_FILE,
                    }
                ],
            }
        ).encode("utf-8")
    )
    assert v2.version == 2
    assert v2.digest() != v1.digest()
    entry = v2.file("app.py")
    assert entry is not None
    assert entry.mode == GIT_MODE_EXECUTABLE
    assert entry.kind == SOURCE_KIND_FILE
