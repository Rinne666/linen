"""Deterministic checks for a worker-visible source repository.

The dispatcher runs this before any model-backed audit task.  Keep the scan
bounded and read only: it only proves that the configured repository is
reachable from the worker workspace and contains at least one readable source
or security-relevant configuration file.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path


MAX_ENTRIES = 50_000
MAX_DEPTH = 32

# Common source, infrastructure, and security configuration formats.  This is
# intentionally broader than the CodeQL language list because audit projects
# can target configuration-only repositories as well.
SOURCE_SUFFIXES = frozenset({
    ".bash", ".c", ".cc", ".clj", ".cljc", ".cljs", ".cjs", ".cs",
    ".cpp", ".cxx", ".dart", ".edn", ".elm", ".erb", ".erl", ".ex",
    ".exs", ".fs", ".fsx", ".go", ".graphql", ".gql", ".groovy",
    ".h", ".hh", ".hpp", ".hrl", ".hs", ".hxx", ".ini", ".java", ".js",
    ".json", ".jsx", ".kt", ".kts", ".lua", ".m", ".mm", ".move", ".mjs",
    ".php", ".pl", ".pm", ".proto", ".py", ".pyi", ".r", ".rb", ".rs",
    ".scala", ".sc", ".sh", ".sol", ".sql", ".swift", ".tf", ".tfvars",
    ".toml", ".ts", ".tsx", ".vb", ".vue", ".vy", ".xml", ".yaml", ".yml",
    ".yul", ".zsh",
    ".bazel", ".bzl", ".conf", ".config", ".gradle", ".hcl", ".nix",
    ".properties",
})
SOURCE_BASENAMES = frozenset({
    "containerfile", "dockerfile", "jenkinsfile", "makefile", "justfile",
})
IGNORED_DIRECTORIES = frozenset({".git"})


def _source_candidate(name: str) -> bool:
    return name.lower() in SOURCE_BASENAMES or Path(name).suffix.lower() in SOURCE_SUFFIXES


def preflight_source_repository(
    workdir: Path,
    configured_root: str | None,
    exclude_patterns: list[str] | tuple[str, ...] = (),
) -> str | None:
    """Return a failure explanation, or ``None`` when source is worker-visible.

    ``workdir/repo`` is the actual path the worker receives.  It must resolve
    to the configured source root, so a stale or user-created replacement
    cannot silently bypass the project's selected repository.
    """
    if not configured_root or not configured_root.strip():
        return "No source repository is configured for this audit project."

    try:
        expected_root = Path(configured_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return f"Configured source repository cannot be resolved: {exc}."
    if not expected_root.is_dir():
        return f"Configured source repository is not a directory: {expected_root}."
    if not os.access(expected_root, os.R_OK | os.X_OK):
        return f"Configured source repository is not readable: {expected_root}."

    worker_repo = workdir / "repo"
    if not worker_repo.is_symlink():
        if worker_repo.exists():
            return f"Worker-visible repo path is not the configured repository link: {worker_repo}."
        return f"Worker-visible repository link is missing: {worker_repo}."
    try:
        visible_root = worker_repo.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return f"Worker-visible repository link is broken or unreadable: {worker_repo}: {exc}."
    if visible_root != expected_root:
        return (
            f"Worker-visible repository link points to {visible_root}, but the configured "
            f"repository is {expected_root}."
        )
    if not visible_root.is_dir() or not os.access(visible_root, os.R_OK | os.X_OK):
        return f"Worker-visible repository is not a readable directory: {visible_root}."

    pending: list[tuple[Path, int]] = [(worker_repo, 0)]
    visited_entries = 0
    source_candidates = 0
    unreadable_sources = 0
    empty_sources = 0
    unreadable_directories = 0
    entry_limit_hit = False
    depth_limit_hit = False
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = []
                remaining = MAX_ENTRIES - visited_entries
                for entry in iterator:
                    if len(entries) >= remaining:
                        entry_limit_hit = True
                        break
                    entries.append(entry)
                entries.sort(key=lambda entry: entry.name, reverse=True)
        except OSError:
            unreadable_directories += 1
            continue
        for entry in entries:
            visited_entries += 1
            try:
                if entry.is_symlink():
                    continue
                relative = Path(entry.path).relative_to(worker_repo).as_posix()
                if entry.name == ".git" or any(
                    fnmatch.fnmatch(relative, pattern)
                    or fnmatch.fnmatch(entry.name, pattern)
                    for pattern in exclude_patterns
                ):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() in IGNORED_DIRECTORIES:
                        continue
                    if depth >= MAX_DEPTH:
                        depth_limit_hit = True
                        continue
                    pending.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False) or not _source_candidate(entry.name):
                    continue
                source_candidates += 1
                try:
                    with open(entry.path, "rb") as source_file:
                        if source_file.read(1):
                            return None
                        empty_sources += 1
                except OSError:
                    unreadable_sources += 1
                    continue
            except OSError:
                continue
        if entry_limit_hit:
            break

    if entry_limit_hit:
        return (
            f"Source preflight reached its bounded scan limit ({MAX_ENTRIES} entries) "
            "before it could confirm a readable source file."
        )
    if source_candidates:
        return (
            f"Repository contains {source_candidates} recognized source/configuration file(s), "
            f"but none contain readable content ({unreadable_sources} unreadable, "
            f"{empty_sources} empty)."
        )
    if unreadable_directories:
        return "Could not enumerate repository directories; source availability cannot be confirmed."
    if depth_limit_hit:
        return (
            f"Source preflight reached its maximum traversal depth ({MAX_DEPTH}) before it "
            "could confirm a readable source file."
        )
    return "Repository contains no recognized source or security-configuration files."
