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

The negative matrix of the product manager's v3.0 review (R01 - R08) closes
the four gaps that made a comparison *too confident*:

* a path that is in neither source tree is not evidence of anything and may
  never support a ``same`` (R01, R02, D-066);
* a proven change wins over an undecided path (R03);
* in two complete, trusted snapshots a source file that exists on one side
  only really did change (R04, Q57);
* an audit output is not a file of the audited code and may never look like a
  source addition (R05, D-067);
* the comparison of one coverage unit may not be decided by the paths of
  another unit (R06, D-068);
* a production scope comes from the server's own run, not from a free list of
  paths (R07, D-068);
* a path hint from findings nobody verified is a diagnostic, never a trusted
  change (R08, D-069).

The acceptance ids match the PM's matrices of v2.9 (B-T01 ... B-T10) and v3.0
(R01 ... R08).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from linen.contracts.skill_audit import (
    CoverageBlockSelection,
    CoverageCanonicalRefs,
    UnitRegisteredPayload,
    WaveStartedPayload,
)
from linen.dispatcher.analysis.cf_baseline_validation import (
    attest_historical_source,
    compare_related_sources as compare_related_sources_entry,
)
from linen.server import db
from linen.server.skill_baseline_sources import (
    import_historical_run,
    register_historical_source,
)
from linen.server.skill_coverage import register_unit
from linen.server.skill_coverage_waves import record_wave_started
from linen.server.source_comparison import (
    PLAN_SOURCE_CALLER,
    PLAN_SOURCE_TRUSTED,
    ComparisonScope,
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
    source_tree_state,
    verify_git_source_snapshot,
)

PROJECT = "p-compare"
SOURCE_REF = "acme/app/run-1"
ORIGIN = "github.com/acme/app"
REMOTE = "https://github.com/acme/app.git"
RUN = "run-current"

FILES = {
    "app.py": "def run():\n    return 1\n",
    "lib/util.py": "def helper():\n    return 2\n",
}

COVERAGE_A = "surface::boundary::subsystem::attack-class"
COVERAGE_B = "surface::boundary::subsystem::other-class"

REFS_A = {
    "surface": "surface",
    "boundary": "boundary",
    "subsystem": "subsystem",
    "attack_class": "attack-class",
}
REFS_B = {
    "surface": "surface",
    "boundary": "boundary",
    "subsystem": "subsystem",
    "attack_class": "other-class",
}

AGENT = "ag-hunter-1"


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


def _unit(
    *,
    coverage_id: str = COVERAGE_A,
    status: str = "covered",
    reviewed_paths: list[str] | None = None,
    check_paths: list[str] | None = None,
    fingerprints: list[str] | None = None,
    artifact: str | None = None,
    check_method: str = "source",
) -> dict:
    """One unit of a coverage ledger.

    The unit level list of reviewed paths is exactly the union of the paths the
    checks own, which is what the upstream contract asks for.  ``check_paths``
    names the paths the check owns; a check that owns a path the unit did not
    list is how a verified finding points at a file (D-069).
    """

    reviewed = list(reviewed_paths or [])
    owned = sorted(set(reviewed) | set(check_paths or []))
    checks: list[dict] = []
    if owned or artifact is not None:
        checks.append(
            {
                "agent_id": AGENT,
                "reviewed_paths": owned,
                "invariant": "the invariant",
                "method": check_method,
                "result": "the result",
                "artifact": artifact,
            }
        )
    return {
        "coverage_id": coverage_id,
        "canonical_refs": dict(REFS_A if coverage_id == COVERAGE_A else REFS_B),
        "surface": "surface",
        "boundary": "boundary",
        "subsystem": "subsystem",
        "attack_class": (
            "attack-class" if coverage_id == COVERAGE_A else "other-class"
        ),
        "starting_paths": list(reviewed),
        "prior_status": "none",
        "attempts": [],
        "wave": 1,
        "status": status,
        "agent_id": None if status == "planned" else AGENT,
        "reviewed_paths": list(owned),
        "local_checks": checks,
        "result_fingerprints": list(fingerprints or []),
        "unresolved": [],
    }


def _ledger(reviewed_paths: list[str], *, fingerprints: list[str] | None = None) -> list[dict]:
    """A coverage ledger document with one unit."""

    return [_unit(reviewed_paths=reviewed_paths, fingerprints=fingerprints)]


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')",
            (PROJECT,),
        )
        conn.execute(
            "INSERT INTO runs (run_id, project_id, task_type, idempotency_key, "
            "timeout_seconds, created_at, updated_at) "
            "VALUES (?, ?, 'hunt', ?, 600, 'now', 'now')",
            (RUN, PROJECT, f"idem-{PROJECT}-{RUN}"),
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
    ledger: list[dict] | None = None,
    reviewed_paths: list[str] | None = None,
    attest: bool = True,
    manifest_version: int = 2,
    executable: tuple[str, ...] = (),
):
    """Register one historical source and prove its audited code.

    It needs four things at once: a repository whose checked out revision is
    the commit the metadata names, a frozen copy of that revision, the frozen
    source manifest that names the copy, and a registered origin that names
    the host of the repository.

    ``executable`` names the files the commit records as executable.  The mode
    is a property of the revision, so it is the *commit* that says so - not
    the file system of the machine that copies the snapshot (D-064).
    """

    files = FILES if files is None else files
    if ledger is None:
        ledger = _ledger(
            reviewed_paths if reviewed_paths is not None else sorted(files)
        )
    repo = tmp_path / "repo"
    commit = _git_repo(repo, files=files)
    if executable:
        for name in executable:
            _git(repo, "update-index", "--chmod=+x", name)
            # the index and the worktree have to agree, or the worktree is
            # "dirty" and the source identity cannot be proven at all
            os.chmod(repo / name, 0o755)
        _git(repo, "commit", "--quiet", "-m", "executable")
        commit = _git(repo, "rev-parse", "HEAD")
    snapshot = _snapshot_of(repo, tmp_path / "snapshot")

    if manifest_version == 2:
        manifest = _manifest_v2_of_git(repo, commit, snapshot)
    else:
        manifest = {
            "files": [
                {"path": item["path"], "sha256": item["sha256"]}
                for item in _manifest_v2_of_git(repo, commit, snapshot)["files"]
            ]
        }

    directory = import_root / SOURCE_REF
    directory.mkdir(parents=True, exist_ok=True)
    ledger_bytes = json.dumps(ledger, ensure_ascii=False).encode("utf-8")
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
    artifact_paths: tuple[str, ...] = (),
    hint_paths: tuple[str, ...] = (),
    findings: bytes | None = None,
    coverage_id: str = "",
    scope: ComparisonScope | None = None,
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
            related_paths=RelatedPathSet(
                current_plan_paths=plan_paths,
                artifact_paths=artifact_paths,
                unverified_hint_paths=hint_paths,
            ),
            historical_findings_bytes=findings,
            scope=scope
            or ComparisonScope(
                plan_source=PLAN_SOURCE_CALLER, coverage_id=coverage_id
            ),
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
    assert result.unmatched_paths == []
    assert result.compared_paths == ["app.py", "lib/util.py"]
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

    historical = _historical(
        board, import_root, tmp_path, reviewed_paths=["app.py"]
    )
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
    """B-T06: a path the current plan does not mention is still compared.

    The historical paths come from the registered ledger itself; a caller may
    not hand in a path list that would widen the historical scope (D-068).
    """

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
    )
    assert "lib/util.py" in result.relevant_paths
    assert result.outcome == "changed"
    assert result.changed_paths == ["lib/util.py"]


@requires_git
def test_b_t07_a_verified_finding_path_stays_in_the_comparison(board, import_root, tmp_path, validation_auth_key):
    """B-T07: the paths a **verified** historical finding points at are not dropped.

    A unit that carries fingerprints found something, and the paths its checks
    own are trusted source paths (D-069).  The path is therefore compared, and
    a change of it is a change of the related source.
    """

    historical = _historical(
        board,
        import_root,
        tmp_path,
        ledger=[
            _unit(
                reviewed_paths=["app.py"],
                check_paths=["app.py", "secret.py"],
                fingerprints=["F-1"],
            )
        ],
    )
    changed = dict(FILES)
    changed["secret.py"] = "SECRET = 'x'\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
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

    historical = _historical(
        board,
        import_root,
        tmp_path,
        ledger=[_unit(status="planned", reviewed_paths=[])],
    )
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
    )
    assert result.outcome == "unknown"
    assert result.relevant_paths == []
    assert result.compared_paths == []


# --- B-T09: a file type that cannot be decided is never the same ------------


@requires_git
def test_b_t09_a_different_file_mode_is_not_the_same_file(board, import_root, tmp_path, validation_auth_key):
    """B-T09/D-064: the mode is part of the identity of a file.

    The historical revision records ``app.py`` as an executable, the current
    source has it as a plain file.  Both sides tell the truth, so the
    comparison is about the mode and not about a broken fixture.
    """

    historical = _historical(
        board, import_root, tmp_path, executable=("app.py",)
    )
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["app.py"]
    evidence = {item.path: item for item in result.path_evidence}
    assert evidence["app.py"].historical_mode == GIT_MODE_EXECUTABLE
    assert evidence["app.py"].current_mode == GIT_MODE_FILE


@requires_git
@pytest.mark.skipif(
    os.name == "nt", reason="this platform cannot create a symlink unprivileged"
)
def test_b_t09_a_symlink_is_not_the_file_it_points_at(board, import_root, tmp_path, validation_auth_key):
    """B-T09/D-064: a symlink and the file it points at are not the same.

    The historical revision has ``app.py`` as a plain file; the current source
    has it as a symlink.  Both sides tell the truth, and the comparison sees
    that the file **type** changed even though the bytes it points at did not.

    The current tree carries every file the historical run reviewed: the
    related paths are the union of both sides (D-065), so a file that is only
    on the historical side would show up as a change of its own and hide what
    this test is about.
    """

    historical = _historical(board, import_root, tmp_path)
    root = tmp_path / "current"
    root.mkdir(parents=True, exist_ok=True)
    (root / "real.py").write_text(FILES["app.py"], encoding="utf-8")
    (root / "app.py").symlink_to("real.py")
    (root / "lib").mkdir(parents=True, exist_ok=True)
    (root / "lib/util.py").write_text(FILES["lib/util.py"], encoding="utf-8")
    manifest = json.dumps(_manifest_v2_of_tree(root)).encode("utf-8")
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["app.py"]
    assert result.compared_paths == ["lib/util.py"]
    evidence = {item.path: item for item in result.path_evidence}
    assert evidence["app.py"].current_kind == SOURCE_KIND_SYMLINK
    assert evidence["app.py"].historical_kind == SOURCE_KIND_FILE


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


# --- R01, R02, R03: the undecided path (D-066) ------------------------------


@requires_git
def test_both_sides_missing_a_related_path_returns_unknown(board, import_root, tmp_path, validation_auth_key):
    """R01/D-066: a path in neither source tree may not support a ``same``.

    The path is found nowhere.  That is not evidence that the source did not
    change - it is evidence that the path is not part of the compared source
    at all - so the comparison stays undecided.
    """

    historical = _historical(
        board,
        import_root,
        tmp_path,
        ledger=[_unit(status="planned", reviewed_paths=[])],
    )
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("src/never_existed.py",),
    )
    assert result.outcome == "unknown"
    assert result.unmatched_paths == ["src/never_existed.py"]
    assert result.compared_paths == []
    assert result.changed_paths == []


@requires_git
def test_one_same_path_and_one_unmatched_path_returns_unknown(board, import_root, tmp_path, validation_auth_key):
    """R02/D-066: one proven equal path does not carry an undecided one.

    ``app.py`` really is the same file, but the second path could not be
    decided, so the comparison as a whole is unknown.
    """

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "src/never_existed.py"),
    )
    assert result.outcome == "unknown"
    assert result.compared_paths == ["app.py", "lib/util.py"]
    assert result.unmatched_paths == ["src/never_existed.py"]


@requires_git
def test_proven_change_still_wins_over_an_unmatched_path(board, import_root, tmp_path, validation_auth_key):
    """R03/D-066: a proven change is a verdict even next to an undecided path.

    "Something related changed" is already enough to say that the history does
    not carry over; the undecided path does not weaken that.
    """

    historical = _historical(board, import_root, tmp_path)
    changed = dict(FILES)
    changed["app.py"] = "def run():\n    return 42\n"
    root, manifest = _current_tree(tmp_path, files=changed)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "src/never_existed.py"),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["app.py"]
    assert result.unmatched_paths == ["src/never_existed.py"]


# --- R04, R05: one side of the source really changed (Q57, D-067) ------------


@requires_git
def test_a_source_file_that_exists_on_one_side_only_is_changed(board, import_root, tmp_path, validation_auth_key):
    """R04/Q57: in two complete snapshots a one sided file is a real change.

    ``lib/util.py`` was deleted and ``new.py`` was added.  Both sides are
    complete, trusted snapshots of the audited source, and both paths are
    source paths, so the difference is a proven change.
    """

    historical = _historical(board, import_root, tmp_path)
    current = {"app.py": FILES["app.py"], "new.py": "def added():\n    return 3\n"}
    root, manifest = _current_tree(tmp_path, files=current)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py", "lib/util.py", "new.py"),
    )
    assert result.outcome == "changed"
    assert result.changed_paths == ["lib/util.py", "new.py"]


@requires_git
def test_an_audit_artifact_cannot_look_like_a_source_addition(board, import_root, tmp_path, validation_auth_key):
    """R05/D-067: an audit output is not a file of the audited code.

    The check of the historical unit owns an artifact, and the current source
    carries a file at that path.  The artifact is recorded as an artifact; it
    never becomes a source path and never produces a change.
    """

    artifact = "agents/ag-hunter-1/artifacts/check-17.json"
    historical = _historical(
        board,
        import_root,
        tmp_path,
        ledger=[
            _unit(
                reviewed_paths=["app.py"],
                artifact=artifact,
                check_method="local",
            )
        ],
    )
    current = dict(FILES)
    current[artifact] = '{"result": "ok"}\n'
    root, manifest = _current_tree(tmp_path, files=current)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
    )
    assert result.artifact_paths == [artifact]
    assert artifact not in result.changed_paths
    assert result.changed_paths == []
    assert result.outcome == "same"


# --- R06: one coverage unit may not be decided by another (D-068) ------------


@requires_git
def test_the_comparison_of_one_unit_ignores_the_paths_of_another(board, import_root, tmp_path, validation_auth_key):
    """R06/D-068: unit A is not changed because unit B changed.

    The historical ledger holds two units.  ``src/logging.py`` belongs to unit
    B and did change - but the question asked about unit A is not about unit
    B, and unit A's own source is untouched.
    """

    files = {
        "src/auth.py": "def auth():\n    return 1\n",
        "src/logging.py": "def log():\n    return 2\n",
    }
    ledger = [
        _unit(coverage_id=COVERAGE_A, reviewed_paths=["src/auth.py"]),
        _unit(coverage_id=COVERAGE_B, reviewed_paths=["src/logging.py"]),
    ]
    historical = _historical(
        board, import_root, tmp_path, files=files, ledger=ledger
    )
    changed = dict(files)
    changed["src/logging.py"] = "def log():\n    return 99\n"
    root, manifest = _current_tree(tmp_path, files=changed)

    scoped = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("src/auth.py",),
        coverage_id=COVERAGE_A,
    )
    assert scoped.outcome == "same"
    assert scoped.compared_paths == ["src/auth.py"]
    assert scoped.changed_paths == []

    other = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("src/logging.py",),
        coverage_id=COVERAGE_B,
    )
    assert other.outcome == "changed"
    assert other.changed_paths == ["src/logging.py"]

    whole_run = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("src/auth.py", "src/logging.py"),
    )
    assert whole_run.outcome == "changed"
    assert whole_run.changed_paths == ["src/logging.py"]


@requires_git
def test_an_unknown_coverage_unit_has_no_historical_scope(board, import_root, tmp_path, validation_auth_key):
    """D-068: a unit the historical ledger does not carry has no scope."""

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
    result = _compare(
        historical,
        current_root=root,
        current_manifest=manifest,
        plan_paths=("app.py",),
        coverage_id="surface::boundary::subsystem::not-in-the-ledger",
    )
    assert result.outcome == "unknown"
    assert "coverage unit" in result.reason
    assert result.changed_paths == []


# --- R07: the scope of a production comparison comes from the server --------


def _register_unit(conn, coverage_id: str, refs: dict[str, str]) -> None:
    register_unit(
        conn,
        project_id=PROJECT,
        run_id=RUN,
        coverage_id=coverage_id,
        payload=UnitRegisteredPayload(
            schema_version=1,
            canonical_refs=CoverageCanonicalRefs(**refs),
            prior_status="none",
            baseline={"kind": "no_compatible_ledger", "lookup_ref": "verified-absence-1"},
        ),
    )


def _start_wave(conn, coverage_id: str, refs: dict[str, str], paths: list[str]) -> None:
    record_wave_started(
        conn,
        project_id=PROJECT,
        run_id=RUN,
        coverage_id=coverage_id,
        payload=WaveStartedPayload(
            schema_version=1,
            canonical_refs=CoverageCanonicalRefs(**refs),
            wave=1,
            agent_id=AGENT,
            block_selection=CoverageBlockSelection(
                ordinary_attack_class_block="ATTACK-CLASSES.md#Access control",
                source="skill_audit.py:317",
            ),
            starting_paths=list(paths),
        ),
    )


@requires_git
def test_a_production_scope_comes_from_the_run_and_not_from_a_free_path_list(board, import_root, tmp_path, validation_auth_key):
    """R07/D-068: the trusted plan of the run decides the scope.

    The caller hands in a path of its own and names the run.  The run wins:
    the server rebuilds the plan from the run's own coverage events, and the
    caller's path never enters the comparison.
    """

    files = {
        "src/auth.py": "def auth():\n    return 1\n",
        "src/logging.py": "def log():\n    return 2\n",
    }
    ledger = [
        _unit(coverage_id=COVERAGE_A, reviewed_paths=["src/auth.py"]),
        _unit(coverage_id=COVERAGE_B, reviewed_paths=["src/logging.py"]),
    ]
    historical = _historical(
        board, import_root, tmp_path, files=files, ledger=ledger
    )
    root, manifest = _current_tree(tmp_path, files=files)

    with db.get_conn() as conn:
        _register_unit(conn, COVERAGE_A, REFS_A)
        _register_unit(conn, COVERAGE_B, REFS_B)
        _start_wave(conn, COVERAGE_A, REFS_A, ["src/auth.py"])
        _start_wave(conn, COVERAGE_B, REFS_B, ["src/logging.py"])

    with db.get_conn() as conn:
        trusted = compare_related_sources_entry(
            conn=conn,
            project_id=PROJECT,
            historical_source_ref=SOURCE_REF,
            historical_ledger_bytes=historical["ledger_bytes"],
            historical_manifest_bytes=historical["manifest_path"].read_bytes(),
            current_source_root=root,
            current_manifest_bytes=manifest,
            run_id=RUN,
            coverage_id=COVERAGE_A,
            current_plan_paths=["src/caller-supplied.py"],
        )
    assert trusted.scope_trusted is True
    assert trusted.scope_source == PLAN_SOURCE_TRUSTED
    assert trusted.coverage_id == COVERAGE_A
    assert trusted.outcome == "same"
    assert trusted.compared_paths == ["src/auth.py"]
    assert "src/caller-supplied.py" not in trusted.relevant_paths
    assert "src/logging.py" not in trusted.relevant_paths


@requires_git
def test_a_free_path_list_is_not_a_trusted_scope(board, import_root, tmp_path, validation_auth_key):
    """R07/D-068: a caller's path list is never a trusted plan.

    The comparison still runs - a free list is useful for a synthetic
    comparison - but the result says out loud that its scope is untrusted, and
    a production resolver has to refuse it.
    """

    historical = _historical(board, import_root, tmp_path)
    root, manifest = _current_tree(tmp_path, files=FILES)
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
    assert result.scope_trusted is False
    assert result.scope_source == PLAN_SOURCE_CALLER


# --- R08: an unverified findings path is a hint, not evidence (D-069) --------


@requires_git
def test_an_unverified_findings_path_cannot_produce_a_trusted_change(board, import_root, tmp_path, validation_auth_key):
    """R08/D-069: a path hint from findings nobody verified is a diagnostic.

    ``secret.py`` is new in the current source and the findings document
    points at it - but nothing verifies that this document belongs to the
    registered historical run.  The path is therefore recorded as unresolved
    evidence: it never produces a change, and it never supports a ``same``.
    """

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
    assert result.changed_paths == []
    assert result.unresolved_paths == ["config.py", "secret.py"]
    assert result.outcome == "unknown"
    assert result.reason


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
