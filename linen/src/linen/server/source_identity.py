"""The trusted verification of a historical source identity (CF-S2-B2-A).

A source identity is the answer to "which code was this coverage ledger
produced from".  There are two honest ways to answer it, and this module
implements both:

* a **git commit** - the commit has to exist as a commit object in a named
  repository, the repository has to be the one the frozen snapshot was taken
  from, and the worktree has to be clean.  A commit name that merely *looks*
  right is not an answer: ``git rev-parse`` will happily echo a name that does
  not exist, so the object itself is asked (``cat-file -t``), and unrecorded
  working tree changes mean the files on disk are not the commit, so the
  worktree has to be clean;
* a **frozen snapshot digest** - the bytes are re-read and compared with the
  digests that were registered, so the proof says "these are still the very
  bytes that were imported" instead of naming a place that may have moved.

Everything here is an *observation*.  It becomes a trustworthy proof only when
the controlled flow signs it and the server verifies that signature
(``baseline_proofs``); a caller that writes ``verified = true`` into a request
body produces nothing at all.

This module never runs a model, never talks to a network and never writes to
the database.  It only observes the filesystem and the local git repository.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from linen.contracts.common import cf_payload_digest

#: A git object name is forty hex digits and nothing else.
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

#: How long a git invocation may take before it is abandoned.
_GIT_TIMEOUT_SECONDS = 30


class SourceIdentityVerificationFailed(ValueError):
    """The source identity could not be verified."""


@dataclass(frozen=True)
class GitSourceIdentity:
    """What the local repository says about one commit."""

    repository_root: str
    commit: str
    tree_sha: str
    remote: str | None
    worktree_clean: bool


def _git(repo: Path, *args: str) -> str:
    """Run one git command in the repository and return its output."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceIdentityVerificationFailed(
            f"git could not be executed in {repo}: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise SourceIdentityVerificationFailed(
            f"git {' '.join(args)} failed in {repo}: {detail}"
        )
    return completed.stdout.strip()


def remote_owner_repo(remote: str) -> str | None:
    """The ``owner/repository`` a git remote points at, if it says so.

    The formats in the wild are ``https://host/owner/repo.git``,
    ``git@host:owner/repo.git`` and ``ssh://git@host/owner/repo``.  All of them
    name the same two path segments, which is what a frozen snapshot records
    as its origin.
    """

    text = (remote or "").strip().rstrip("/")
    if not text:
        return None
    if text.endswith(".git"):
        text = text[:-4]
    if "@" in text and ":" in text and not text.startswith(("http://", "https://")):
        # scp-like syntax: git@host:owner/repo
        text = text.split(":", 1)[1]
    else:
        for prefix in ("https://", "http://", "ssh://", "git://"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
        if "@" in text.split("/", 1)[0]:
            text = text.split("/", 1)[1] if "/" in text else text
        if "/" in text:
            text = text.split("/", 1)[1]
    parts = [part for part in text.split("/") if part]
    if len(parts) == 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def verify_git_source_identity(*, repo_root: Path, commit: str) -> GitSourceIdentity:
    """Verify that one commit is a real commit of one real repository.

    The verification asks the repository four questions and refuses to answer
    unless all of them have a good answer: does the repository exist, does the
    commit exist *as a commit object*, does the commit resolve to itself, and
    is the worktree free of changes that were never recorded.
    """

    name = (commit or "").strip().lower()
    if not _GIT_COMMIT_RE.fullmatch(name):
        raise SourceIdentityVerificationFailed(
            "a git commit must be a forty hex digit object name"
        )
    root = Path(repo_root).expanduser()
    if not root.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the repository root {root} is not a directory"
        )

    toplevel = _git(root, "rev-parse", "--show-toplevel")
    if not toplevel:
        raise SourceIdentityVerificationFailed(
            f"{root} is not inside a git repository"
        )

    object_type = _git(root, "cat-file", "-t", name)
    if object_type != "commit":
        raise SourceIdentityVerificationFailed(
            f"{name} is not a commit object in {toplevel}"
        )

    resolved = _git(root, "rev-parse", name).strip().lower()
    if resolved != name:
        raise SourceIdentityVerificationFailed(
            f"{name} does not resolve to itself in {toplevel}"
        )

    tree_sha = _git(root, "rev-parse", f"{name}^{{tree}}").strip().lower()
    if not _GIT_COMMIT_RE.fullmatch(tree_sha):
        raise SourceIdentityVerificationFailed(
            f"the tree of {name} is not a git object name"
        )

    status = _git(root, "status", "--porcelain")
    if status.strip():
        raise SourceIdentityVerificationFailed(
            f"the worktree of {toplevel} carries changes that were never recorded"
        )

    try:
        remote = _git(root, "remote", "get-url", "origin")
    except SourceIdentityVerificationFailed:
        remote = ""

    return GitSourceIdentity(
        repository_root=toplevel,
        commit=name,
        tree_sha=tree_sha,
        remote=remote or None,
        worktree_clean=True,
    )


def verify_frozen_source_digest(
    *,
    ledger_path: Path,
    metadata_path: Path,
    ledger_sha256: str,
    metadata_sha256: str,
) -> str:
    """Re-read the frozen bytes and prove that they are the registered ones.

    The returned digest is the identity of the frozen snapshot: it is derived
    from the two registered digests, so it changes when either of them does.
    """

    for path, expected in (
        (Path(ledger_path), ledger_sha256),
        (Path(metadata_path), metadata_sha256),
    ):
        if not path.is_file():
            raise SourceIdentityVerificationFailed(
                f"the frozen artifact {path.name} is not a readable file"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SourceIdentityVerificationFailed(
                f"the frozen artifact {path.name} does not match the registered digest"
            )
    return cf_payload_digest(
        {"ledger_sha256": ledger_sha256, "metadata_sha256": metadata_sha256}
    )
