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
import os
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from linen.contracts.common import cf_canonical_json, cf_payload_digest

#: A git object name is forty hex digits and nothing else.
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

#: How long a git invocation may take before it is abandoned.
_GIT_TIMEOUT_SECONDS = 30

#: The file that carries the frozen source manifest of a historical run.
SOURCE_MANIFEST_NAME = "source-manifest.json"

#: The kinds a source file can have.  A kind is never guessed: a file that is
#: neither a regular file nor a symlink is *undecidable*, and an undecidable
#: file is never silently dropped (D-064).
SOURCE_KIND_FILE = "file"
SOURCE_KIND_SYMLINK = "symlink"
SOURCE_KIND_DIRECTORY = "directory"
SOURCE_KIND_UNSUPPORTED = "unsupported"

#: The git modes of the kinds a tree entry can have.
GIT_MODE_FILE = "100644"
GIT_MODE_EXECUTABLE = "100755"
GIT_MODE_SYMLINK = "120000"
GIT_MODE_GITLINK = "160000"
GIT_MODE_TREE = "040000"

#: The modes a frozen source file may carry.
SUPPORTED_FILE_MODES = (GIT_MODE_FILE, GIT_MODE_EXECUTABLE, GIT_MODE_SYMLINK)

#: Whether this platform can express the executable bit of a file at all.
#:
#: Windows cannot: a file that git records as ``100755`` is a plain file there.
#: The mode of a file is therefore **not verifiable** on such a platform, and
#: the check is skipped instead of pretending that the mode matched.  The
#: declared mode - the mode of the git tree, or the mode of the frozen source
#: manifest - stays the mode the comparison uses (D-064).
PLATFORM_EXPRESSES_FILE_MODE = os.name != "nt"


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
class SourceFileEntry:
    """One file of an audited source tree, with the type and mode it has.

    ``sha256`` is the digest of the file bytes; for a symlink it is the digest
    of the *link target text*, which is what git stores in its tree (D-064).
    """

    path: str
    kind: str
    mode: str
    sha256: str


@dataclass(frozen=True)
class SourceTreeState:
    """The trusted state of one audited source tree.

    ``entries`` are the files and symlinks of the tree.  ``undecidable`` names
    the paths whose file type could not be determined - a fifo, a socket, a
    device.  They are reported instead of being skipped, because a file that
    cannot be classified may not be treated as if it were the same file (D-064).
    """

    entries: tuple[SourceFileEntry, ...] = ()
    undecidable: tuple[str, ...] = ()

    def file(self, path: str) -> SourceFileEntry | None:
        """The entry of one path, if the tree has one."""

        for entry in self.entries:
            if entry.path == path:
                return entry
        return None

    def digest(self) -> str:
        """The digest of the whole state."""

        return cf_payload_digest(
            {
                "entries": [
                    {
                        "kind": entry.kind,
                        "mode": entry.mode,
                        "path": entry.path,
                        "sha256": entry.sha256,
                    }
                    for entry in self.entries
                ],
                "kind": "source-tree-state",
            }
        )


@dataclass(frozen=True)
class GitTreeEntry:
    """One entry of a git tree, with the file type and mode it really has."""

    path: str
    mode: str
    kind: str
    object_name: str


@dataclass(frozen=True)
class FrozenSourceManifest:
    """The trusted list of the audited source files of one historical run.

    A **v1** manifest lists the path and the content digest of every audited
    file.  It says nothing about the file *type* or the file *mode*, so it can
    never support a source comparison (D-064).

    A **v2** manifest adds the mode and the kind of every file.  It is a
    different document with a different digest: the digest of a v1 manifest is
    unchanged, and a v2 manifest can never be mistaken for a v1 one.
    """

    files: tuple[tuple[str, str], ...]
    entries: tuple[SourceFileEntry, ...] = ()
    version: int = 1

    def digest(self) -> str:
        """The digest of the manifest itself."""

        if self.version == 2:
            return cf_payload_digest(
                {
                    "files": [
                        {
                            "kind": entry.kind,
                            "mode": entry.mode,
                            "path": entry.path,
                            "sha256": entry.sha256,
                        }
                        for entry in self.entries
                    ],
                    "kind": "frozen-source-manifest",
                    "version": 2,
                }
            )
        return cf_payload_digest(
            {
                "files": [
                    {"path": path, "sha256": sha}
                    for path, sha in self.files
                ],
                "kind": "frozen-source-manifest",
            }
        )

    def file(self, path: str) -> SourceFileEntry | None:
        """The entry of one path, if the manifest names it."""

        for entry in self.entries:
            if entry.path == path:
                return entry
        return None

    def tree_state(self) -> SourceTreeState:
        """The source state this manifest describes.

        Only a v2 manifest can describe a state: a v1 manifest carries no file
        type, and a state without file types would compare a script and a
        binary as if they were the same thing (D-064).
        """

        if self.version != 2:
            raise SourceIdentityVerificationFailed(
                "the frozen source manifest is a v1 manifest and carries no file "
                "type, so it cannot describe a comparable source state"
            )
        return SourceTreeState(entries=self.entries)


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


def _git_tree_entries(repo: Path, commit: str) -> dict[str, GitTreeEntry]:
    """Every entry of one commit, with the file type and mode it has.

    The old implementation kept the blob entries and dropped everything else,
    which silently excluded submodules and unknown file types from the
    comparison (D-064).  Every entry is kept now, and the caller decides what
    to do with the kinds it cannot verify.
    """

    entries: dict[str, GitTreeEntry] = {}
    listing = _git(repo, "ls-tree", "-r", "--full-tree", commit)
    for line in listing.splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) < 3:
            continue
        mode, object_type, object_name = fields[0], fields[1], fields[2]
        relative = path.strip()
        if object_type == "blob":
            if mode == GIT_MODE_SYMLINK:
                kind = SOURCE_KIND_SYMLINK
            elif mode in (GIT_MODE_FILE, GIT_MODE_EXECUTABLE):
                kind = SOURCE_KIND_FILE
            else:
                kind = SOURCE_KIND_UNSUPPORTED
        elif object_type == "commit" and mode == GIT_MODE_GITLINK:
            kind = "gitlink"
        elif object_type == "tree":
            kind = SOURCE_KIND_DIRECTORY
        else:
            kind = SOURCE_KIND_UNSUPPORTED
        entries[relative] = GitTreeEntry(
            path=relative, mode=mode, kind=kind, object_name=object_name.strip()
        )
    return entries


def _is_within(path: Path, root: Path) -> bool:
    """Whether a path lies inside a directory."""

    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _walk_source_tree(tree: Path, skip: Sequence[Path] = ()) -> list[Path]:
    """Every path under the tree, without ever following a symlink.

    ``Path.rglob`` follows symlinked directories on some platforms, which would
    walk out of the frozen tree; this walk never does.  The directories in
    ``skip`` - the metadata directory of a repository - are left out: they are
    not part of the audited source, and git never tracks them.
    """

    collected: list[Path] = []
    stack = [tree]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as scanner:
                children = list(scanner)
        except OSError as exc:
            raise SourceIdentityVerificationFailed(
                f"the frozen source directory {current} cannot be read: {exc}"
            ) from exc
        for child in children:
            path = Path(child.path)
            if any(_is_within(path, root) for root in skip):
                continue
            collected.append(path)
            if child.is_dir(follow_symlinks=False):
                stack.append(path)
    return sorted(collected)


def source_tree_state(tree: Path, *, skip: Sequence[Path] = ()) -> SourceTreeState:
    """The state of a source tree, with the type and mode of every file.

    A symlink is a symlink: it is never followed, and its digest is the digest
    of the link target text - the same bytes git stores in its tree (D-064).
    """

    root = Path(tree).expanduser()
    if not root.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the frozen source directory {root} is not a directory"
        )
    entries: list[SourceFileEntry] = []
    undecidable: list[str] = []
    for path in _walk_source_tree(root, skip):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            entries.append(
                SourceFileEntry(
                    path=relative,
                    kind=SOURCE_KIND_SYMLINK,
                    mode=GIT_MODE_SYMLINK,
                    sha256=hashlib.sha256(target.encode("utf-8")).hexdigest(),
                )
            )
        elif stat.S_ISREG(info.st_mode):
            mode = GIT_MODE_EXECUTABLE if info.st_mode & 0o111 else GIT_MODE_FILE
            entries.append(
                SourceFileEntry(
                    path=relative,
                    kind=SOURCE_KIND_FILE,
                    mode=mode,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        elif stat.S_ISDIR(info.st_mode):
            continue
        else:
            undecidable.append(relative)
    return SourceTreeState(
        entries=tuple(sorted(entries, key=lambda entry: entry.path)),
        undecidable=tuple(sorted(undecidable)),
    )


def _git_blob(repo: Path, data: bytes) -> str:
    """The git object name of the given bytes."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "--stdin"],
            input=data,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceIdentityVerificationFailed(
            f"git could not be executed in {repo}: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode("utf-8", "replace").strip()
        raise SourceIdentityVerificationFailed(
            f"git hash-object failed in {repo}: {detail}"
        )
    return completed.stdout.decode("ascii", "replace").strip()


def _git_metadata_dirs(repo: Path, tree: Path) -> tuple[Path, ...]:
    """The metadata directories of a repository that lie inside the tree.

    A source tree that *is* a working copy carries the metadata directory of
    the repository.  Git never tracks it, so it is not part of the audited
    source and it is left out of the comparison - but it is left out on
    purpose, not by accident.
    """

    try:
        git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir"))
    except SourceIdentityVerificationFailed:
        return ()
    if not git_dir.is_dir():
        return ()
    root = Path(tree).expanduser().resolve()
    resolved = git_dir.resolve()
    if resolved == root or _is_within(resolved, root):
        return (resolved,)
    return ()


def verify_git_source_snapshot(
    *, repo_root: Path, commit: str, source_dir: Path
) -> FrozenSourceManifest:
    """Prove that a frozen source tree is exactly the tree of one commit.

    Every file of the commit has to be present in the frozen tree with the
    same content, **the same file type and the same mode** (D-064), and the
    frozen tree may not carry a file the commit does not have.  A submodule or
    a file type that cannot be classified is refused: it is never dropped
    from the comparison, because a tree that hides a path cannot prove that
    the path did not change.
    """

    repo = Path(repo_root).expanduser()
    tree = Path(source_dir).expanduser()
    if not tree.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the frozen source directory {tree} is not a directory"
        )
    entries = _git_tree_entries(repo, commit)
    for path, entry in sorted(entries.items()):
        if entry.kind == "gitlink":
            raise SourceIdentityVerificationFailed(
                f"the commit carries a submodule at {path!r}; the content of a "
                "submodule is not part of the tree and cannot be verified"
            )
        if entry.kind not in (SOURCE_KIND_FILE, SOURCE_KIND_SYMLINK):
            raise SourceIdentityVerificationFailed(
                f"the commit carries {path!r} with the mode {entry.mode}, whose "
                "file type cannot be verified"
            )

    state = source_tree_state(tree, skip=_git_metadata_dirs(repo, tree))
    if state.undecidable:
        raise SourceIdentityVerificationFailed(
            f"the frozen source tree carries {state.undecidable[0]!r}, whose "
            "file type cannot be determined"
        )
    present = {entry.path: entry for entry in state.entries}

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
    for relative, entry in sorted(entries.items()):
        local = present[relative]
        if local.kind != entry.kind:
            raise SourceIdentityVerificationFailed(
                f"the frozen source file {relative!r} is a {local.kind}, but the "
                f"commit has it as a {entry.kind}"
            )
        if PLATFORM_EXPRESSES_FILE_MODE and local.mode != entry.mode:
            raise SourceIdentityVerificationFailed(
                f"the frozen source file {relative!r} has the mode {local.mode}, "
                f"but the commit has it as {entry.mode}"
            )
        if entry.kind == SOURCE_KIND_SYMLINK:
            blob = _git_blob(repo, os.readlink(tree / relative).encode("utf-8"))
        else:
            blob = _git(repo, "hash-object", str(tree / relative))
        if blob != entry.object_name:
            raise SourceIdentityVerificationFailed(
                f"the frozen source file {relative!r} does not match the commit"
            )
    merged = tuple(
        SourceFileEntry(
            path=relative,
            kind=entries[relative].kind,
            mode=entries[relative].mode,
            sha256=present[relative].sha256,
        )
        for relative in sorted(entries)
    )
    return FrozenSourceManifest(
        files=tuple((entry.path, entry.sha256) for entry in merged),
        entries=merged,
        version=2,
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
    """Read the trusted file manifest of a frozen source snapshot from bytes.

    A manifest without a ``version`` is a **v1** manifest: it lists the path
    and the content digest of every audited file.  A manifest with
    ``"version": 2`` also lists the mode and the kind of every file, which is
    what a source comparison needs (D-064).  The two versions have different
    digests, and the digest of a v1 manifest is unchanged.
    """

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
    version = payload.get("version")
    if version is None:
        version = 1
    if version not in (1, 2):
        raise SourceIdentityVerificationFailed(
            f"the frozen source manifest has the unsupported version {version!r}"
        )
    files: list[tuple[str, str]] = []
    entries: list[SourceFileEntry] = []
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
        if version == 2:
            mode = str(entry.get("mode") or "").strip()
            kind = str(entry.get("kind") or "").strip()
            if mode not in SUPPORTED_FILE_MODES:
                raise SourceIdentityVerificationFailed(
                    f"the frozen source manifest names {relative!r} with the "
                    f"unsupported mode {mode!r}"
                )
            if kind not in (SOURCE_KIND_FILE, SOURCE_KIND_SYMLINK):
                raise SourceIdentityVerificationFailed(
                    f"the frozen source manifest names {relative!r} with the "
                    f"unsupported file type {kind!r}"
                )
            if kind == SOURCE_KIND_SYMLINK and mode != GIT_MODE_SYMLINK:
                raise SourceIdentityVerificationFailed(
                    f"the frozen source manifest names the symlink {relative!r} "
                    f"with the mode {mode!r}"
                )
            if kind == SOURCE_KIND_FILE and mode == GIT_MODE_SYMLINK:
                raise SourceIdentityVerificationFailed(
                    f"the frozen source manifest names the file {relative!r} with "
                    "the mode of a symlink"
                )
            entries.append(
                SourceFileEntry(path=relative, kind=kind, mode=mode, sha256=sha256)
            )
    if len({path for path, _ in files}) != len(files):
        raise SourceIdentityVerificationFailed(
            "the frozen source manifest names the same file twice"
        )
    return FrozenSourceManifest(
        files=tuple(sorted(files)),
        entries=tuple(sorted(entries, key=lambda entry: entry.path)),
        version=version,
    )


def verify_frozen_source_manifest(
    *, manifest: FrozenSourceManifest, source_dir: Path
) -> FrozenSourceManifest:
    """Prove that a source tree is exactly the frozen manifest it claims.

    Every file of the manifest has to be present with the digest the manifest
    gives it, and the tree may not carry a file the manifest does not name.  A
    **v2** manifest also has to match the file type and the mode of every file
    (D-064); a v1 manifest carries no file type, so it keeps the content-only
    semantics it was defined with.
    """

    tree = Path(source_dir).expanduser()
    if not tree.is_dir():
        raise SourceIdentityVerificationFailed(
            f"the frozen source directory {tree} is not a directory"
        )
    expected = dict(manifest.files)

    if manifest.version == 2:
        state = source_tree_state(tree)
        if state.undecidable:
            raise SourceIdentityVerificationFailed(
                f"the source tree carries {state.undecidable[0]!r}, whose file "
                "type cannot be determined"
            )
        present = {entry.path: entry for entry in state.entries}
        missing = sorted(set(expected) - set(present))
        extra = sorted(set(present) - set(expected))
        if missing:
            raise SourceIdentityVerificationFailed(
                f"the source tree does not carry {missing[0]!r}, which the frozen "
                "manifest names"
            )
        if extra:
            raise SourceIdentityVerificationFailed(
                f"the source tree carries {extra[0]!r}, which the frozen manifest "
                "does not name"
            )
        for entry in manifest.entries:
            local = present[entry.path]
            if local.sha256 != entry.sha256:
                raise SourceIdentityVerificationFailed(
                    f"the source file {entry.path!r} does not match the frozen manifest"
                )
            if local.kind != entry.kind:
                raise SourceIdentityVerificationFailed(
                    f"the source file {entry.path!r} is a {local.kind}, but the "
                    f"frozen manifest names a {entry.kind}"
                )
            if PLATFORM_EXPRESSES_FILE_MODE and local.mode != entry.mode:
                raise SourceIdentityVerificationFailed(
                    f"the source file {entry.path!r} has the mode {local.mode}, "
                    f"but the frozen manifest names the mode {entry.mode}"
                )
        return manifest

    present_files: dict[str, str] = {}
    for path in sorted(p for p in tree.rglob("*") if p.is_file()):
        relative = path.relative_to(tree).as_posix()
        present_files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    missing = sorted(set(expected) - set(present_files))
    extra = sorted(set(present_files) - set(expected))
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
        if present_files[relative] != sha256:
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
