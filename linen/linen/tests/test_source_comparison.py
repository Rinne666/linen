"""Regression tests for the trusted comparison of the related source (CF-S2-B2-B).

The comparison answers one question - *did the source the history talks about
change?* - and it answers it with ``same``, ``changed`` or ``unknown`` and with
nothing else (D-065).

The boundaries that matter:

* a side that cannot be proven makes the whole comparison ``unknown``
  (B-T01, B-T02): a comparison of two unproven sources is not a comparison;
* the compared paths are the **union** of the current plan paths, the
  historical reviewed paths and the historical finding paths - never an
  intersection (B-T06, B-T07);
* a different commit does not mean a different source: only the related paths
  decide (B-T05);
* a file whose type or mode cannot be determined is never reported as the same
  file (B-T09, D-064);
* the result is a pure function of its trusted inputs: the same inputs give the
  same outcome and the same evidence references (B-T10).

The acceptance ids match the PM's B2-B matrix of PM v2.9 (B-T01 ... B-T10).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from linen.dispatcher.analysis.cf_baseline_validation import (
    attest_historical_source,
    compare_related_sources as compare_related_sources_entry,
)
from linen.server import db
from linen.server.skill_baseline_sources import (
    import_historical_run,
    register_historical_source,
)
from linen.server.source_comparison import (
    CurrentSource,
    RelatedPathSet,
    compare_related_sources,
    finding_paths_from_findings,
    reviewed_paths_from_ledger,
)
from linen.server.source_identity import (
    GIT_MODE_EXECUTABLE,
    GIT_MODE_FILE,
    SOURCE_KIND_FILE,
    SOURCE_KIND_SYMLINK,
    read_frozen_source_manifest_bytes,
    verify_git_source_snapshot,
)

PROJECT = "p-compare"
SOURCE_REF = "acme/app/run-1"
ORIGIN = "github.com/acme/app"
REMOTE = "https://github.com/acme/app.git"

FILES = {
    "app.py": "def run():\n    return 1\n",
    "lib/util.py": "def helper():\n    return 2\n",
}


requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not available on this machine"
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


def _git_repo(root: Path, *, files: dict[str, str], remote: str = REMOTE) -> str:
    """A synthetic repository with one commit - a fixture, not real history."""

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
    if remote:
        _git(root, "remote", "add", "origin", remote)
    return _git(root, "rev-parse", "HEAD")


def _snapshot_of(repo: Path, target: Path) -> Path:
    """A frozen copy of the tracked files of a repository."""

    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(repo.rglob("*")):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(repo)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    return target


def _manifest_v2_of_git(repo: Path, commit: str, snapshot: Path) -> dict:
    """The frozen source manifest of a snapshot: the modes of the commit, the
    content of the copy.

    The mode is a property of the revision, the content is a property of the
    frozen copy, and the manifest has to carry both (D-064).
    """

    merged = verify_git_source_snapshot(
        repo_root=repo, commit=commit, source_dir=snapshot
    )
    return {
        "version": 2,
        "files": [
            {
                "path": entry.path,
                "sha256": entry.sha256,
                "mode": entry.mode,
                "kind": entry.kind,
            }
            for entry in merged.entries
        ],
    }


def _manifest_v2_of_tree(tree: Path) -> dict:
    """The frozen source manifest of a plain source tree."""

    from linen.server.source_identity import source_tree_state

    state = source_tree_state(tree)
    return {
        "version": 2,
        "files": [
            {
                "path": entry.path,
                "sha256": entry.sha256,
                "mode": entry.mode,
                "kind": entry.kind,
            }
            for entry in state.entries
        ],
    }


def _ledger(reviewed_paths: list[str], *, fingerprints: list[str] | None = None) -> list[dict]:
    """A coverage ledger document with one unit."""

    return [
        {
            "coverage_id": "surface::boundary::subsystem::attack-class",
            "canonical_refs": {
                "surface": "surface",
                "boundary": "boundary",
                "subsystem": "subsystem",
                "attack_class": "attack-class",
            },
            "surface": "surface",
            "boundary": "boundary",
            "subsystem": "subsystem",
            "attack_class": "attack-class",
            "starting_paths": list(reviewed_paths),
            "prior_status": "none",
            "attempts": [],
            "wave": 1,
            "status": "covered",
            "agent_id": "ag-hunter-1",
            "reviewed_paths": list(reviewed_paths),
            "local_checks": [
                {
                    "agent_id": "ag-hunter-1",
                    "reviewed_paths": list(reviewed_paths),
                    "invariant": "the invariant",
                    "method": "source",
                    "result": "the result",
                    "artifact": None,
                }
            ],
            "result_fingerprints": list(fingerprints or []),
            "unresolved": [],
        }
    ]


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')",
            (PROJECT,),
        )
    return tmp_path


@pytest.fixture
def import_root(tmp_path) -> Path:
    root = tmp_path / "corpus"
    root.mkdir()
    return root


def _historical(
    board,
    import_root,
    tmp_path,
    *,
    files: dict[str, str] | None = None,
    reviewed_paths: list[str] | None = None,
    attest: bool = True,
    manifest_version: int = 2,
):
    """Register one historical source and prove its audited code.

    It needs four things at once: a repository whose checked out revision is
    the commit the metadata names, a frozen copy of that revision, the frozen
    source manifest that names the copy, and a registered origin that names
    the host of the repository.
    """

    files = FILES if files is None else files
    reviewed_paths = reviewed_paths if reviewed_paths is not None else sorted(files)
    repo = tmp_path / "repo"
    commit = _git_repo(repo, files=files)
    snapshot = _snapshot_of(repo, tmp_path / "snapshot")

    if manifest_version == 2:
        manifest = _manifest_v2_of_git(repo, commit, snapshot)
    else:
        manifest = {
            "files": [
                {"path": path, "sha256": entry["sha256"]}
                for path, entry in (
                    (item["path"], item) for item in _manifest_v2_of_git(repo, commit, snapshot)["files"]
                )
            ]
        }

    directory = import_root / SOURCE_REF
    directory.mkdir(parents=True, exist_ok=True)
    ledger_bytes = json.dumps(_ledger(reviewed_paths), ensure_ascii=False).encode("utf-8")
    (directory / "coverage-ledger.json").write_bytes(ledger_bytes)
    (directory / "run-metadata.json").write_text(
        json.dumps(
            {
                "run_id": "acme-run-1",
                "repo": "acme/app",
                "source_ref": commit,
                "profile": "standard",
            }
        ),
        encoding="utf-8",
    )
    (directory / "source-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref=SOURCE_REF, origin=ORIGIN
    )
    with db.get_conn() as conn:
        record = register_historical_source(conn, candidate)

    if attest:
        with db.get_conn() as conn:
            attest_historical_source(
                conn=conn,
                project_id=PROJECT,
                source_ref=SOURCE_REF,
                observed_at="2026-01-01T00:00:00Z",
                scope="audited_source_identity",
                repo_root=repo,
                commit=commit,
                source_dir=snapshot,
                source_manifest=directory / "source-manifest.json",
            )

    return {
        "repo": repo,
        "commit": commit,
        "snapshot": snapshot,
        "manifest": manifest,
        "manifest_path": directory / "source-manifest.json",
        "ledger_bytes": ledger_bytes,
        "record": record,
    }


def _current_tree(tmp_path, *, files: dict[str, str], name: str = "current") -> tuple[Path, bytes]:
    """A plain source tree and the frozen manifest that names it."""

    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    manifest = json.dumps(_manifest_v2_of_tree(root)).encode("utf-8")
    return root, manifest


def _compare(
    historical,
    *,
    current_root: Path,
    current_manifest: bytes | None = None,
    repo_root: Path | None = None,
    commit: str | None = None,
    plan_paths: tuple[str, ...] = (),
    reviewed_paths: tuple[str, ...] = (),
    findings: bytes | None = None,
):
    with db.get_conn() as conn:
        return compare_related_sources(
            conn=conn,
            project_id=PROJECT,
            historical_source_ref=SOURCE_REF,
            historical_ledger_bytes=historical["ledger_bytes"],
            historical_manifest_bytes=historical["manifest_path"].read_bytes(),
            current_source=CurrentSource(
                root=current_root,
                repo_root=repo_root,
                commit=commit,
                manifest_bytes=current_manifest,
            ),
            relevant_paths=RelatedPathSet(
                current_plan_paths=plan_paths,
                historical_reviewed_paths=reviewed_paths,
            ),
            historical_findings_bytes=findings,
        )


# --- B-T01, B-T02: a side that cannot be proven ------------------------------


@requires_git
def test_b_t01_an_unverified_historical_source_is_unknown(board, import_root, tmp_path, validation_auth_key):
    """B-T01: a historical source without a trusted attestation is unknown."""

    historical = _historical(board, import_root, tmp_path, attest=False)
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
    )
    assert result.outcome == "unknown"
    assert "attestation" in result.reason
    assert result.changed_paths == []


@requires_git
def test_b_t02_an_unverified_current_source_is_unknown(board, import_root, tmp_path, validation_auth_key):
    """B-T02: a current source that cannot be verified is unknown."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    # the manifest does not describe the tree any more
    broken = json.dumps(
        {
            "version": 2,
            "files": [
                {"path": "app.py", "sha256": "0" * 64, "mode": GIT_MODE_FILE, "kind": SOURCE_KIND_FILE}
            ],
        }
    ).encode("utf-8")
    result = _compare(
        historical,
        current_root=root,
        current_manifest=broken,
        plan_paths=("app.py",),
    )
    assert result.outcome == "unknown"
    assert result.changed_paths == []


# --- B-T03, B-T04, B-T05: same, changed, and the same commit ------------------


@requires_git
def test_b_t03_the_same_related_paths_are_same(board, import_root, tmp_path, validation_auth_key):
    """B-T03: every related path is provably the same."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "lib/util.py"),
    )
    assert result.outcome == "same"
    assert result.changed_paths == []
    assert result.unknown_paths == []
    assert result.evidence_refs
    assert set(result.relevant_paths) == {"app.py", "lib/util.py"}


@requires_git
def test_b_t04_a_changed_related_path_is_changed(board, import_root, tmp_path, validation_auth_key):
    """B-T04: one provably different path makes the comparison changed."""

    historical = _historical(board, import_root, tmp_path)
    changed = dict(FILES)
    changed["app.py"] = "def run():\n    return 42\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "lib/util.py"),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["app.py"]
    evidence = {item.path: item for item in result.path_evidence}
    assert evidence["app.py"].current_digest != evidence["app.py"].historical_digest


@requires_git
def test_b_t05_a_different_commit_does_not_mean_a_changed_source(board, import_root, tmp_path, validation_auth_key):
    """B-T05: the commit changed, the related source did not."""

    historical = _historical(board, import_root, tmp_path)
    current_repo = tmp_path / "current-repo"
    current_commit = _git_repo(
        current_repo,
        files={"app.py": FILES["app.py"], "lib/util.py": "def helper():\n    return 3\n"},
    )
    assert current_commit != historical["commit"]
    result = _compare(
        historical,
        current_root=current_repo,
        repo_root=current_repo,
        commit=current_commit,
        plan_paths=("app.py",),
    )
    assert result.outcome == "same"
    assert result.changed_paths == []


# --- B-T06, B-T07: the union is never an intersection ------------------------


@requires_git
def test_b_t06_a_reviewed_path_the_plan_forgot_stays_in_the_comparison(board, import_root, tmp_path, validation_auth_key):
    """B-T06: a path the current plan does not mention is still compared."""

    historical = _historical(
        board, import_root, tmp_path, reviewed_paths=["app.py", "lib/util.py"]
    )
    changed = dict(FILES)
    changed["lib/util.py"] = "def helper():\n    return 99\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
        reviewed_paths=("lib/util.py",),
    )
    assert "lib/util.py" in result.relevant_paths
    assert result.outcome == "changed"
    assert result.changed_paths == ["lib/util.py"]


@requires_git
def test_b_t07_a_finding_evidence_path_stays_in_the_comparison(board, import_root, tmp_path, validation_auth_key):
    """B-T07: the paths a historical finding points at are not dropped."""

    historical = _historical(board, import_root, tmp_path)
    findings = json.dumps(
        [
            {
                "fingerprint": "F-1",
                "title": "a finding",
                "trace": [{"file": "secret.py", "line": 3, "scope": "s", "description": "d"}],
                "evidence": [{"file": "config.py", "line": 1, "description": "d"}],
            }
        ]
    ).encode("utf-8")
    changed = dict(FILES)
    changed["secret.py"] = "SECRET = 'x'\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
        findings=findings,
    )
    assert "secret.py" in result.relevant_paths
    assert result.outcome == "changed"
    assert result.changed_paths == ["secret.py"]


# --- B-T08: what is missing stays unknown ------------------------------------


@requires_git
def test_b_t08_a_v1_manifest_cannot_support_a_comparison(board, import_root, tmp_path, validation_auth_key):
    """B-T08: a manifest without file types cannot prove that nothing changed."""

    historical = _historical(
        board, import_root, tmp_path, manifest_version=1
    )
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
    )
    assert result.outcome == "unknown"
    assert "v1" in result.reason or "file type" in result.reason


@requires_git
def test_b_t08_without_a_related_path_there_is_nothing_to_compare(board, import_root, tmp_path, validation_auth_key):
    """B-T08: an empty related path set is unknown, never same."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
    )
    assert result.outcome == "unknown"
    assert result.relevant_paths == []


# --- B-T09: a file type that cannot be decided is never the same ------------


@requires_git
def test_b_t09_a_different_file_mode_is_not_the_same_file(board, import_root, tmp_path, validation_auth_key):
    """B-T09/D-064: the mode is part of the identity of a file."""

    historical = _historical(board, import_root, tmp_path)
    changed = dict(FILES)
    root, manifest = _current_tree(tmp_path, files=changed)
    # the current side declares the very same file as an executable one
    declared = json.loads(manifest)
    for entry in declared["files"]:
        if entry["path"] == "app.py":
            entry["mode"] = GIT_MODE_EXECUTABLE
    result = _compare(
        historical,
        current_root=root,
        current_manifest=json.dumps(declared).encode("utf-8"),
        plan_paths=("app.py",),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["app.py"]


@requires_git
def test_b_t09_a_symlink_is_not_the_file_it_points_at(board, import_root, tmp_path, validation_auth_key):
    """B-T09/D-064: a symlink and the file it points at are not the same."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    declared = json.loads(manifest)
    for entry in declared["files"]:
        if entry["path"] == "app.py":
            entry["kind"] = SOURCE_KIND_SYMLINK
            entry["mode"] = "120000"
    result = _compare(
        historical,
        current_root=root,
        current_manifest=json.dumps(declared).encode("utf-8"),
        plan_paths=("app.py",),
    )
    assert result.outcome in ("changed", "unknown")
    assert result.outcome != "same"


# --- B-T10: the comparison replays -------------------------------------------


@requires_git
def test_b_t10_the_same_inputs_give_the_same_result(board, import_root, tmp_path, validation_auth_key):
    """B-T10: the comparison is a pure function of its trusted inputs."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    first = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "lib/util.py"),
    )
    second = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "lib/util.py"),
    )
    assert first.outcome == second.outcome
    assert first.evidence_refs == second.evidence_refs
    assert first.relevant_paths == second.relevant_paths
    assert first.path_evidence == second.path_evidence


# --- the controlled entry point ----------------------------------------------


@requires_git
def test_the_controlled_entry_point_compares_the_related_source(board, import_root, tmp_path, validation_auth_key):
    """The dispatcher entry resolves the path set and compares the source."""

    historical = _historical(
        board, import_root, tmp_path, reviewed_paths=["app.py", "lib/util.py"]
    )
    changed = dict(FILES)
    changed["lib/util.py"] = "def helper():\n    return 99\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    with db.get_conn() as conn:
        result = compare_related_sources_entry(
            conn=conn,
            project_id=PROJECT,
            historical_source_ref=SOURCE_REF,
            historical_ledger_bytes=historical["ledger_bytes"],
            historical_manifest_bytes=historical["manifest_path"].read_bytes(),
            current_source_root=root,
            current_manifest_bytes=manifest,
            current_plan_paths=["app.py"],
        )
    assert result.outcome == "changed"
    assert result.changed_paths == ["lib/util.py"]


def test_the_ledger_and_the_findings_name_the_paths():
    """The path collections are read from the documents themselves."""

    ledger = json.dumps(
        _ledger(["app.py", "lib/util.py"], fingerprints=["F-1"])
    ).encode("utf-8")
    assert reviewed_paths_from_ledger(ledger) == ("app.py", "lib/util.py")

    findings = json.dumps(
        [{"trace": [{"file": "secret.py"}], "evidence": [{"file": "config.py"}]}]
    ).encode("utf-8")
    assert finding_paths_from_findings(findings) == ("config.py", "secret.py")
