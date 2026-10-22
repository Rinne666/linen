"""Regression tests for the CF-S2-B1 P1-B materialization and reference scope.

P1-A made the *content* of an imported historical source trustworthy: the very
bytes that were read are the bytes the pinned upstream validator judged.  P1-B
is about where those bytes are put down and who is allowed to read them back:

* the directory a source materializes into is named after a content digest,
  so two references cannot be made to share one directory by rewriting path
  characters (CR-T04b);
* every filesystem step is taken relative to an opened directory and never
  follows a symbolic link, so a linked component is refused (CR-T05,
  CR-T05a) and nothing is written outside the trusted workspace (CR-T05c);
* a repeated materialization changes nothing, and a changed file is refused
  rather than replaced (CR-T04, CR-T04a);
* a materialization that fails half way leaves no half written file behind
  (CR-T05b);
* a reference is read within the project it belongs to (CR-T06).

The acceptance ids match the PM's P1-B matrix (PM v2.5, E130 - E133).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from linen.contracts.baseline import BaselineManifestMember
from linen.server import db
from linen.server.baseline_materialization import (
    BASELINE_WORKSPACE_DIR,
    HAS_NO_FOLLOW_OPERATIONS,
    MATERIALIZATION_KEY_DOMAIN,
    BaselineMaterializationFailed,
    materialization_key,
)
from linen.server.skill_baseline_sources import (
    BaselineReferenceUnverifiable,
    import_historical_run,
    list_baseline_sources,
    materialize_baseline_artifacts,
    read_reference,
    referenced_manifest,
    register_historical_source,
    seal_lineage_manifest,
)

PROJECT = "p-baseline"
OTHER_PROJECT = "p-baseline-other"
THIRD_PROJECT = "p-baseline-third"

LEDGER = [{"coverage_id": "http-public-api::anonymous-to-authenticated::authorization::access-control"}]
METADATA = {
    "run_id": "sftpgo-run-1",
    "repo": "drakkan/sftpgo",
    "source_ref": "305ebb875c0eb37ffe970ebf6af80f5f86a7e070",
    "profile": "standard",
}


def _write_run(root: Path, source_ref: str) -> Path:
    directory = root / source_ref
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "coverage-ledger.json").write_text(
        json.dumps(LEDGER), encoding="utf-8"
    )
    (directory / "run-metadata.json").write_text(
        json.dumps(METADATA), encoding="utf-8"
    )
    return directory


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        for project in (PROJECT, OTHER_PROJECT, THIRD_PROJECT):
            conn.execute(
                "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')",
                (project,),
            )
    return tmp_path


@pytest.fixture
def import_root(tmp_path) -> Path:
    root = tmp_path / "corpus"
    root.mkdir()
    return root


@pytest.fixture
def candidate(import_root):
    """A registered-able candidate of one historical run."""

    _write_run(import_root, "sftpgo/run-1")
    return import_historical_run(
        root=import_root,
        project_id=PROJECT,
        source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )


@pytest.fixture
def symlink():
    """Create a symbolic link, or skip when the platform refuses to."""

    def _make(link: Path, target: Path) -> None:
        try:
            os.symlink(target, link, target_is_directory=target.is_dir())
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            pytest.skip(f"this platform does not allow symbolic links: {exc}")

    return _make


requires_no_follow = pytest.mark.skipif(
    not HAS_NO_FOLLOW_OPERATIONS,
    reason="the materialization needs no-follow directory operations",
)


def _artifact_rows(conn: sqlite3.Connection, project_id: str = PROJECT) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT artifact_id, kind, workspace_path, sha256 FROM artifacts "
        "WHERE project_id = ? ORDER BY artifact_id",
        (project_id,),
    ).fetchall()


# --- E130: the directory identity ---------------------------------------------


def test_materialization_directory_uses_full_source_digest():
    """E130: the directory identity is the full source digest.

    The key is the complete SHA-256 of a domain separated digest of the
    source reference - not a prefix of it, and not the reference itself.
    """

    key = materialization_key("sftpgo/run-1")

    assert key == hashlib.sha256(
        MATERIALIZATION_KEY_DOMAIN + "sftpgo/run-1".encode("utf-8")
    ).hexdigest()
    assert len(key) == 64
    assert all(char in "0123456789abcdef" for char in key)


def test_materialization_key_is_stable_and_exact():
    """E130: the key does not move when the reference is re-read.

    No trimming and no case folding: the same reference always produces the
    same key, and a reference that differs in any byte produces another.
    """

    assert materialization_key("sftpgo/run-1") == materialization_key("sftpgo/run-1")
    assert materialization_key("sftpgo/run-1") != materialization_key("sftpgo/run-2")
    assert materialization_key("sftpgo/run-1") != materialization_key("sftpgo/run-1 ")
    assert materialization_key("sftpgo/run-1") != materialization_key("SFTPGO/run-1")


# --- CR-T04b: two references never share a directory --------------------------


@requires_no_follow
def test_materialization_different_source_refs_do_not_alias(board, import_root):
    """CR-T04b: two references cannot be made to share a directory.

    ``a/b`` and ``a__b`` used to land in the same directory, because the
    reference was rewritten into a path name.
    """

    workspace = board / "workspace"
    directories = set()
    for source_ref in ("a/b", "a__b"):
        _write_run(import_root, source_ref)
        candidate = import_historical_run(
            root=import_root, project_id=PROJECT, source_ref=source_ref,
            origin="drakkan/sftpgo",
        )
        with db.get_conn() as conn:
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        directories.add(materialization_key(source_ref))

    assert len(directories) == 2
    baseline = workspace / PROJECT / BASELINE_WORKSPACE_DIR
    assert sorted(path.name for path in baseline.iterdir()) == sorted(directories)
    for key in directories:
        assert (baseline / key / "coverage-ledger.json").is_file()


# --- CR-T04: a repeated materialization changes nothing -----------------------


@requires_no_follow
def test_baseline_materialization_replay_is_safe(board, candidate):
    """CR-T04: materializing the same source twice changes nothing."""

    workspace = board / "workspace"
    with db.get_conn() as conn:
        first = materialize_baseline_artifacts(
            conn, candidate=candidate, workspace_root=workspace
        )
        before = _artifact_rows(conn)
        second = materialize_baseline_artifacts(
            conn, candidate=candidate, workspace_root=workspace
        )
        after = _artifact_rows(conn)

    assert first == second
    assert [dict(row) for row in before] == [dict(row) for row in after]
    assert len(after) == 2

    key = materialization_key(candidate.source_ref)
    directory = workspace / PROJECT / BASELINE_WORKSPACE_DIR / key
    assert sorted(path.name for path in directory.iterdir()) == [
        "coverage-ledger.json",
        "run-metadata.json",
    ]
    assert (directory / "coverage-ledger.json").read_bytes() == candidate.ledger_bytes


@requires_no_follow
def test_baseline_materialization_rejects_changed_existing_file(board, candidate):
    """CR-T04a: a file with another digest is refused, not overwritten."""

    workspace = board / "workspace"
    with db.get_conn() as conn:
        materialize_baseline_artifacts(
            conn, candidate=candidate, workspace_root=workspace
        )

    key = materialization_key(candidate.source_ref)
    ledger = workspace / PROJECT / BASELINE_WORKSPACE_DIR / key / "coverage-ledger.json"
    ledger.write_bytes(b'[{"coverage_id": "tampered"}]')

    with db.get_conn() as conn:
        with pytest.raises(BaselineMaterializationFailed):
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        rows = _artifact_rows(conn)

    assert ledger.read_bytes() == b'[{"coverage_id": "tampered"}]'
    assert len(rows) == 2


# --- CR-T05b: a failed materialization leaves nothing behind ------------------


@requires_no_follow
def test_baseline_materialization_partial_failure_does_not_register_artifact(
    board, candidate
):
    """CR-T05b: a half written materialization registers no artifact.

    The second file cannot be written, so the first one must not be left
    behind as if it were a materialized artifact.
    """

    workspace = board / "workspace"
    key = materialization_key(candidate.source_ref)
    directory = workspace / PROJECT / BASELINE_WORKSPACE_DIR / key
    directory.mkdir(parents=True)
    (directory / "run-metadata.json").mkdir()

    with db.get_conn() as conn:
        with pytest.raises(BaselineMaterializationFailed):
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        rows = _artifact_rows(conn)

    assert rows == []
    assert not (directory / "coverage-ledger.json").exists()


# --- CR-T05/CR-T05a: no symbolic link is ever followed ------------------------


@requires_no_follow
def test_baseline_materialization_rejects_symlinked_parent(board, candidate, symlink):
    """CR-T05: a linked directory component is refused.

    The workspace already holds the project directory; replacing the
    ``baseline`` directory with a symbolic link must not make the
    materialization write into the link target.
    """

    workspace = board / "workspace"
    project_dir = workspace / PROJECT
    project_dir.mkdir(parents=True)
    outside = board / "outside"
    outside.mkdir()
    symlink(project_dir / BASELINE_WORKSPACE_DIR, outside)

    with db.get_conn() as conn:
        with pytest.raises(BaselineMaterializationFailed):
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        rows = _artifact_rows(conn)

    assert rows == []
    assert list(outside.iterdir()) == []


@requires_no_follow
def test_baseline_materialization_rejects_symlinked_target(board, candidate, symlink):
    """CR-T05a: a linked file is refused instead of being written through."""

    workspace = board / "workspace"
    key = materialization_key(candidate.source_ref)
    directory = workspace / PROJECT / BASELINE_WORKSPACE_DIR / key
    directory.mkdir(parents=True)
    outside = board / "outside.json"
    outside.write_text("[]", encoding="utf-8")
    symlink(directory / "coverage-ledger.json", outside)

    with db.get_conn() as conn:
        with pytest.raises(BaselineMaterializationFailed):
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        rows = _artifact_rows(conn)

    assert rows == []
    assert outside.read_text(encoding="utf-8") == "[]"


# --- CR-T05c: nothing is written outside the trusted workspace ----------------


def test_baseline_materialization_rejects_workspace_escape(board, candidate):
    """CR-T05c: a name that is not a single segment is refused.

    The project id becomes a directory name, so a project id that is not a
    single segment could place the files outside the workspace.
    """

    workspace = board / "workspace"
    for project_id in ("../escape", "a/b", "a\\b", "", ".", ".."):
        escaped = replace(candidate, project_id=project_id)
        with db.get_conn() as conn:
            with pytest.raises(BaselineMaterializationFailed):
                materialize_baseline_artifacts(
                    conn, candidate=escaped, workspace_root=workspace
                )
            assert _artifact_rows(conn) == []

    assert not (board / "escape").exists()
    assert not (workspace / ".." / "escape").exists()


@requires_no_follow
def test_baseline_materialization_stays_inside_the_workspace(board, candidate):
    """CR-T05c: the materialized files stay under the trusted workspace."""

    workspace = board / "workspace"
    with db.get_conn() as conn:
        materialize_baseline_artifacts(
            conn, candidate=candidate, workspace_root=workspace
        )

    root = workspace.resolve()
    for path in (workspace / PROJECT).rglob("*"):
        assert path.resolve().is_relative_to(root)


# --- the fail closed policy ---------------------------------------------------


def test_baseline_materialization_fails_closed_without_no_follow_support(
    board, candidate
):
    """A platform that cannot refuse to follow a link fails closed.

    The materialization does not fall back to a weaker check: it refuses,
    because a check that cannot be enforced is not a check.
    """

    workspace = board / "workspace"
    with db.get_conn() as conn:
        if HAS_NO_FOLLOW_OPERATIONS:
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
            assert _artifact_rows(conn)
        else:
            with pytest.raises(BaselineMaterializationFailed):
                materialize_baseline_artifacts(
                    conn, candidate=candidate, workspace_root=workspace
                )
            assert _artifact_rows(conn) == []


# --- CR-T06: the reference is read inside its project ------------------------


def _register_source(project_id: str, import_root: Path, source_ref: str) -> str:
    """Register one source and return its reference."""

    _write_run(import_root, source_ref)
    candidate = import_historical_run(
        root=import_root, project_id=project_id, source_ref=source_ref,
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        register_historical_source(conn, candidate)
        rows = list_baseline_sources(conn, project_id, record_kind="historical_source")
    return str(rows[0]["lookup_ref"])


def test_baseline_reference_is_project_scoped(board, import_root):
    """CR-T06: a reference is read in the project that registered it."""

    reference = _register_source(PROJECT, import_root, "sftpgo/run-1")

    with db.get_conn() as conn:
        body = read_reference(conn, project_id=PROJECT, reference=reference)

    assert body["source_ref"] == "sftpgo/run-1"


def test_baseline_reference_rejects_cross_project_lookup(board, import_root):
    """CR-T06: a reference of another project is not readable here.

    The digest says what a body is, not who may read it, so the project is
    part of the lookup.
    """

    other = _register_source(OTHER_PROJECT, import_root, "sftpgo/run-other")

    with db.get_conn() as conn:
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, project_id=PROJECT, reference=other)
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, project_id=THIRD_PROJECT, reference=other)


def test_baseline_reference_with_the_same_body_stays_project_scoped(
    board, import_root
):
    """CR-T06: the same source in two projects does not open the other one.

    The underlying ledger bytes - and their digest - are the same in both
    projects, but the reference names the record of one project, and the
    lookup stays inside that project.
    """

    mine = _register_source(PROJECT, import_root, "sftpgo/run-1")
    theirs = _register_source(OTHER_PROJECT, import_root, "sftpgo/run-1")

    with db.get_conn() as conn:
        mine_body = read_reference(conn, project_id=PROJECT, reference=mine)
        theirs_body = read_reference(conn, project_id=OTHER_PROJECT, reference=theirs)
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, project_id=OTHER_PROJECT, reference=mine)
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, project_id=PROJECT, reference=theirs)

    assert mine_body["ledger_sha256"] == theirs_body["ledger_sha256"]
    assert mine_body["project_id"] == PROJECT
    assert theirs_body["project_id"] == OTHER_PROJECT


def test_referenced_manifest_preserves_project_scope(board, import_root):
    """CR-T06: the manifest reader inherits the same project scope."""

    _write_run(import_root, "sftpgo/run-other")
    other = import_historical_run(
        root=import_root, project_id=OTHER_PROJECT, source_ref="sftpgo/run-other",
        origin="drakkan/sftpgo",
    )

    with db.get_conn() as conn:
        register_historical_source(conn, other)
        record = list_baseline_sources(
            conn, OTHER_PROJECT, record_kind="historical_source"
        )[0]
        member = BaselineManifestMember(
            source_ref=record["record_ref"],
            ledger_sha256=record["payload"]["ledger_sha256"],
            metadata_sha256=record["payload"]["metadata_sha256"],
        )
        manifest = seal_lineage_manifest(
            conn, project_id=OTHER_PROJECT, members=[member]
        )
        reference = manifest.reference()

        with pytest.raises(BaselineReferenceUnverifiable):
            referenced_manifest(conn, project_id=PROJECT, reference=reference)
        found = referenced_manifest(
            conn, project_id=OTHER_PROJECT, reference=reference
        )

    assert found.project_id == OTHER_PROJECT
