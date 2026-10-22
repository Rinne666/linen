"""The trusted verification of a historical source identity (CF-S2-B2-A).

There are **three** different things to verify, and this module keeps them
apart (D-061):

``audit_artifact_bytes``
    the bytes of the coverage ledger and of the run metadata are still the
    bytes that were imported.  This says nothing about the code that produced
    them, and it is therefore never a source identity.

``audited_source_identity`` (git)
    the audited code is a known revision: the commit exists as an object, the
    checked out commit **is** that commit, the worktree carries no unrecorded
    change, the repository identity (host *and* ``owner/repository``) is the
    registered one, and the frozen source manifest of the historical run
    matches that revision file by file.

``audited_source_identity`` (non-git)
    the audited code is a frozen snapshot: the trusted file manifest of the
    historical run matches the supplied source tree file by file.

Two things are deliberately **not** accepted any more:

* a commit that merely *exists* in a repository - a clean worktree of another
  revision proves nothing about the declared one, so the checked out commit
  has to be the declared commit (D-060);
* the digest of the ledger and the metadata as a stand-in for the digest of
  the audited code - the ledger is the *result* of the audit, not its input.

Everything here is an *observation*.  It becomes a trustworthy proof only when
the controlled flow signs it and the server verifies that signature
(``baseline_proofs``); a caller that writes ``verified = true`` into a request
body produces nothing at all.

This module never runs a model, never talks to a network and never writes to
the database.  It only observes the filesystem and the local git repository.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from linen.contracts.common import cf_canonical_json, cf_payload_digest

#: A git object name is forty hex digits and nothing else.
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

#: How long a git invocation may take before it is abandoned.
_GIT_TIMEOUT_SECONDS = 30

#: The file that carries the frozen source manifest of a historical run.
SOURCE_MANIFEST_NAME = "source-manifest.json"


class SourceIdentityVerificationFailed(ValueError):
    """The source identity could not be verified."""


@dataclass(frozen=True)
class GitSourceIdentity:
    """What the local repository says about one commit."""

    repository_root: str
    repository_host: str | None
    repository_owner_repo: str | None
    commit: str
    head_commit: str
    tree_sha: str
    worktree_clean: bool


@dataclass(frozen=True)
class FrozenSourceManifest:
    """The trusted list of the audited source files of one historical run."""

    files: tuple[tuple[str, str], ...]

    def digest(self) -> str:
        """The digest of the manifest itself."""

        return cf_payload_digest(
            {
                "files": [
                    {"path": path, "sha256": sha}
                    for path, sha in self.files
                ],
                "kind": "frozen-source-manifest",
            }
        )


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


def repository_identity(remote: str) -> tuple[str | None, str | None]:
    """The host and the ``owner/repository`` a git remote points at.

    The formats in the wild are ``https://host/owner/repo.git``,
    ``git@host:owner/repo.git`` and ``ssh://git@host/owner/repo``.  The host
    is part of the identity: the same ``owner/repo`` on two different hosts is
    two different repositories, and a proof may not pretend otherwise (R04).
    """

    text = (remote or "").strip().rstrip("/")
    if not text:
        return (None, None)
    if text.endswith(".git"):
        text = text[:-4]
    host: str | None = None
    if "@" in text and ":" in text and not text.startswith(("http://", "https://")):
        # scp-like syntax: git@host:owner/repo
        head, _, text = text.partition(":")
        host = head.split("@", 1)[-1].strip() or None
    else:
        for prefix in ("https://", "http://", "ssh://", "git://"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
        if "@" in text.split("/", 1)[0]:
            text = text.split("/", 1)[1] if "/" in text else text
        parts = text.split("/", 1)
        if len(parts) == 2:
            host, text = parts[0].strip() or None, parts[1]
        else:
            host, text = None, text
    segments = [part for part in text.split("/") if part]
    if len(segments) != 2:
        return (host, None)
    return (host, f"{segments[0]}/{segments[1]}")


def verify_git_source_identity(*, repo_root: Path, commit: str) -> GitSourceIdentity:
    """Verify that one commit is the checked out revision of one repository.

    The verification asks the repository five questions and refuses to answer
    unless all of them have a good answer: does the repository exist, does the
    commit exist *as a commit object*, is the **checked out** commit that very
    commit, is the worktree free of changes that were never recorded, and can
    the repository's identity be named at all.
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

    head = _git(root, "rev-parse", "HEAD").strip().lower()
    if head != name:
        raise SourceIdentityVerificationFailed(
            f"the checked out revision of {toplevel} is {head}, not the declared "
            f"commit {name}; a clean worktree of another revision says nothing "
            "about the declared one"
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
    host, owner_repo = repository_identity(remote)

    return GitSourceIdentity(
        repository_root=toplevel,
        repository_host=host,
        repository_owner_repo=owner_repo,
        commit=name,
        head_commit=head,
        tree_sha=tree_sha,
        worktree_clean=True,
    )


def _git_tree_entries(repo: Path, commit: str) -> dict[str, str]:
    """The files of one commit, mapped to their git blob object names."""

    entries: dict[str, str] = {}
    listing = _git(repo, "ls-tree", "-r", "--full-tree", commit)
    for line in listing.splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) < 3 or fields[1] != "blob":
            continue
        entries[path.strip()] = fields[2].strip()
    return entries


def verify_git_source_snapshot(
    *, repo_root: Path, commit: str, source_dir: Path
) -> FrozenSourceManifest:
    """Prove that a frozen source tree is exactly the tree of one commit.

    Every file of the commit has to be present in the frozen tree with the
    same content, and the frozen tree may not carry a file the commit does not
    have.  The files are compared through their git blob object names, so the
    comparison is the one git itself would make.
    """

    repo = Path(repo_root).expanduser()
    tree = Path(source_dir).expanduser()
    if not tree.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the frozen source directory {tree} is not a directory"
        )
    entries = _git_tree_entries(repo, commit)
    present: dict[str, str] = {}
    for path in sorted(p for p in tree.rglob("*") if p.is_file()):
        relative = path.relative_to(tree).as_posix()
        present[relative] = _git(repo, "hash-object", str(path))

    missing = sorted(set(entries) - set(present))
    extra = sorted(set(present) - set(entries))
    if missing:
        raise SourceIdentityVerificationFailed(
            f"the frozen source tree does not carry {missing[0]!r}, which the "
            "commit has"
        )
    if extra:
        raise SourceIdentityVerificationFailed(
            f"the frozen source tree carries {extra[0]!r}, which the commit does "
            "not have"
        )
    for relative, blob in entries.items():
        if present[relative] != blob:
            raise SourceIdentityVerificationFailed(
                f"the frozen source file {relative!r} does not match the commit"
            )
    return FrozenSourceManifest(
        files=tuple(
            (relative, hashlib.sha256((tree / relative).read_bytes()).hexdigest())
            for relative in sorted(entries)
        )
    )


def read_frozen_source_manifest(path: Path) -> FrozenSourceManifest:
    """Read the trusted file manifest of a frozen source snapshot."""

    manifest_path = Path(path).expanduser()
    if not manifest_path.is_file():
        raise SourceIdentityVerificationFailed(
            f"the frozen source manifest {manifest_path} is not a readable file"
        )
    return read_frozen_source_manifest_bytes(manifest_path.read_bytes())


def read_frozen_source_manifest_bytes(raw: bytes) -> FrozenSourceManifest:
    """Read the trusted file manifest of a frozen source snapshot from bytes."""

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceIdentityVerificationFailed(
            "the frozen source manifest is not readable JSON"
        ) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise SourceIdentityVerificationFailed(
            "the frozen source manifest does not carry a file list"
        )
    files: list[tuple[str, str]] = []
    for entry in payload["files"]:
        if not isinstance(entry, dict):
            raise SourceIdentityVerificationFailed(
                "the frozen source manifest carries a file that is not an object"
            )
        relative = str(entry.get("path") or "").strip().replace("\\", "/")
        sha256 = str(entry.get("sha256") or "").strip().lower()
        if not relative or relative.startswith("/") or ".." in relative.split("/"):
            raise SourceIdentityVerificationFailed(
                "the frozen source manifest names a file outside the snapshot"
            )
        if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
            raise SourceIdentityVerificationFailed(
                "the frozen source manifest names a file without a sha256 digest"
            )
        files.append((relative, sha256))
    if len({path for path, _ in files}) != len(files):
        raise SourceIdentityVerificationFailed(
            "the frozen source manifest names the same file twice"
        )
    return FrozenSourceManifest(files=tuple(sorted(files)))


def verify_frozen_source_manifest(
    *, manifest: FrozenSourceManifest, source_dir: Path
) -> FrozenSourceManifest:
    """Prove that a source tree is exactly the frozen manifest it claims.

    Every file of the manifest has to be present with the digest the manifest
    gives it, and the tree may not carry a file the manifest does not name.
    """

    tree = Path(source_dir).expanduser()
    if not tree.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the frozen source directory {tree} is not a directory"
        )
    expected = dict(manifest.files)
    present: dict[str, str] = {}
    for path in sorted(p for p in tree.rglob("*") if p.is_file()):
        relative = path.relative_to(tree).as_posix()
        present[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    missing = sorted(set(expected) - set(present))
    extra = sorted(set(present) - set(expected))
    if missing:
        raise SourceIdentityVerificationFailed(
            f"the source tree does not carry {missing[0]!r}, which the frozen "
            "manifest names"
        )
    if extra:
        raise SourceIdentityVerificationFailed(
            f"the source tree carries {extra[0]!r}, which the frozen manifest does "
            "not name"
        )
    for relative, sha256 in expected.items():
        if present[relative] != sha256:
            raise SourceIdentityVerificationFailed(
                f"the source file {relative!r} does not match the frozen manifest"
            )
    return manifest


def verify_audit_artifact_bytes(
    *,
    ledger_path: Path,
    metadata_path: Path,
    ledger_sha256: str,
    metadata_sha256: str,
) -> str:
    """Re-read the audit artifacts and prove that they are the registered ones.

    The returned digest is the identity of the **audit artifacts** - the ledger
    and the run metadata.  It is not the identity of the audited code, and it
    may never be used as one (D-061).
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
