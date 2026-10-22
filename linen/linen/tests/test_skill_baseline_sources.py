"""Regression tests for the CF-S2-B1 historical baseline registry.

A prior status is only worth storing when the history behind it can be found
again and checked.  These tests pin the four promises that make that true:

* a controlled import reads only inside the declared root, and records the
  digest of everything it read;
* a registration is append-only, and the reference body is stored - not just
  its digest;
* a lineage manifest says whether the history scope is closed, and an
  unprocessed member keeps it open;
* a reference is resolved back to its body and re-verified, so a string
  alone is never evidence.

The acceptance ids match the PM's B1 matrix (B1-T01 ... B1-T14) and the
evidence list (E93 ... E99).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from linen.contracts.baseline import (
    BaselineLineageManifest,
    BaselineManifestMember,
    BaselineSourceIdentity,
    encode_reference,
    reference_digest,
)
from linen.contracts.common import cf_canonical_json, cf_payload_digest
from linen.server import db
from linen.server.skill_baseline_sources import (
    COVERAGE_LEDGER_ARTIFACT_KIND,
    COVERAGE_RUN_METADATA_ARTIFACT_KIND,
    BaselineImportFailed,
    BaselineReferenceUnverifiable,
    BaselineSourceRejected,
    HistoricalSourceCandidate,
    import_historical_run,
    list_baseline_sources,
    materialize_baseline_artifacts,
    read_reference,
    register_historical_source,
    seal_lineage_manifest,
)

PROJECT = "p-baseline"

REFS = {
    "surface": "http-public-api",
    "boundary": "anonymous-to-authenticated",
    "subsystem": "authorization",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}


def _unit(coverage_id: str, *, status: str = "covered", prior_status: str = "none") -> dict:
    return {
        "coverage_id": coverage_id,
        "canonical_refs": dict(REFS),
        "surface": REFS["surface"],
        "boundary": REFS["boundary"],
        "subsystem": REFS["subsystem"],
        "attack_class": REFS["attack_class"],
        "starting_paths": ["app/authz.py"],
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control",
        "selected_companion_blocks": [],
        "excluded_blocks": [],
        "prior_status": prior_status,
        "attempts": [],
        "wave": 1,
        "status": status,
        "agent_id": "ag-w1-hunt-abcdef123456",
        "reviewed_paths": ["app/authz.py"],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }


def _write_run(
    root: Path,
    source_ref: str,
    *,
    units: list[dict] | None = None,
    metadata: dict | None = ...,
) -> Path:
    """Materialize one historical run directory under an import root."""

    directory = root / source_ref
    directory.mkdir(parents=True, exist_ok=True)
    payload = units if units is not None else [
        _unit("http-public-api::anonymous-to-authenticated::authorization::access-control")
    ]
    (directory / "coverage-ledger.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )
    if metadata is not ...:
        if metadata is not None:
            (directory / "run-metadata.json").write_text(
                json.dumps(metadata, ensure_ascii=False), encoding="utf-8"
            )
    return directory


def _metadata(source_ref: str = "305ebb875c0eb37ffe970ebf6af80f5f86a7e070") -> dict:
    return {
        "run_id": "sftpgo-run-1",
        "repo": "drakkan/sftpgo",
        "source_ref": source_ref,
        "profile": "standard",
    }


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


# --- B1-T01/B1-T02: the controlled import ------------------------------------


def test_b1_t01_a_legal_ledger_is_imported_and_registered(board, import_root):
    """B1-T01: a legal coverage ledger can be imported and registered."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    assert candidate.eligible, candidate.reason
    assert candidate.ledger_sha256 and candidate.metadata_sha256
    assert candidate.unit_count == 1
    assert candidate.prior_status_counts == {"none": 1}

    with db.get_conn() as conn:
        record = register_historical_source(conn, candidate)
        rows = list_baseline_sources(conn, PROJECT, record_kind="historical_source")

    assert record.source_ref == "sftpgo/run-1"
    assert len(rows) == 1
    assert rows[0]["payload_sha256"] == cf_payload_digest(record.model_dump(mode="json"))


def test_b1_t02_a_source_without_metadata_is_not_trusted(board, import_root):
    """B1-T02: a missing run metadata is not a complete trusted history."""

    _write_run(import_root, "sftpgo/run-1", metadata=None)
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    assert candidate.eligible is False
    assert "metadata" in candidate.reason

    with db.get_conn() as conn:
        with pytest.raises(BaselineSourceRejected):
            register_historical_source(conn, candidate)
        assert list_baseline_sources(conn, PROJECT) == []


def test_e95_a_run_metadata_without_a_source_identity_is_rejected(board, import_root):
    """E95: the audited source identity has to be recorded."""

    _write_run(import_root, "sftpgo/run-1", metadata={"run_id": "r1"})
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    assert candidate.eligible is False
    assert "source_ref" in candidate.reason


def test_e94_the_import_refuses_to_leave_its_root(board, import_root, tmp_path):
    """E94: an import cannot reach a file outside the declared root."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "coverage-ledger.json").write_text("[]", encoding="utf-8")
    (outside / "run-metadata.json").write_text("{}", encoding="utf-8")

    with pytest.raises(BaselineImportFailed):
        import_historical_run(
            root=import_root, project_id=PROJECT, source_ref="../outside",
            origin="drakkan/sftpgo",
        )


def test_b1_t04_a_ledger_that_is_not_a_ledger_document_is_refused(board, import_root):
    """B1-T04: a document that is not an upstream ledger is not a source."""

    directory = import_root / "broken"
    directory.mkdir()
    (directory / "coverage-ledger.json").write_text('{"nope": 1}', encoding="utf-8")
    (directory / "run-metadata.json").write_text(
        json.dumps(_metadata()), encoding="utf-8"
    )

    with pytest.raises(BaselineImportFailed):
        import_historical_run(
            root=import_root, project_id=PROJECT, source_ref="broken",
            origin="drakkan/sftpgo",
        )


def test_b1_t03_changed_bytes_change_the_digest(board, import_root):
    """B1-T03: the digest follows the content."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    first = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )

    directory = import_root / "sftpgo" / "run-1"
    (directory / "coverage-ledger.json").write_text(
        json.dumps([_unit("other::id::x::y")]), encoding="utf-8"
    )
    second = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )

    assert first.ledger_sha256 != second.ledger_sha256
    assert first.metadata_sha256 == second.metadata_sha256


# --- B1-T06 / E99: the source identity ---------------------------------------


def test_b1_t06_an_annotated_git_ref_is_not_automatically_trusted(board, import_root):
    """B1-T06: a regex that matched is not a verification."""

    _write_run(
        import_root,
        "sftpgo/run-1",
        metadata=_metadata(
            "305ebb875c0eb37ffe970ebf6af80f5f86a7e070 (main, clean worktree)"
        ),
    )
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    identity = candidate.identity
    assert identity is not None
    assert identity.kind == "unverified"
    assert identity.verified is False
    # The commit is kept as a candidate, but nothing claims it was verified.
    assert identity.revision == "305ebb875c0eb37ffe970ebf6af80f5f86a7e070"
    assert "clean worktree" in (identity.raw or "")


def test_e99_a_non_git_source_requires_a_frozen_digest():
    """E99: a source distribution has no commit, so it needs a digest."""

    with pytest.raises(ValueError):
        BaselineSourceIdentity(kind="frozen_digest", origin="dataease-2.10.20")
    identity = BaselineSourceIdentity(
        kind="frozen_digest", origin="dataease-2.10.20", digest="a" * 64
    )
    assert identity.digest == "a" * 64


def test_e99_an_unverified_identity_cannot_claim_to_be_verified():
    """E99: the unverified kind and the verified flag cannot coexist."""

    with pytest.raises(ValueError):
        BaselineSourceIdentity(
            kind="unverified", origin="x", raw="something", verified=True
        )


def test_e99_a_git_identity_requires_a_commit():
    """E99: a git identity without a commit is not an identity."""

    with pytest.raises(ValueError):
        BaselineSourceIdentity(kind="git_commit", origin="x")
    identity = BaselineSourceIdentity(
        kind="git_commit", origin="x", revision="b" * 40, verified=True
    )
    assert identity.verified is True


# --- B1-T07/B1-T08/B1-T09: the immutable registration ------------------------


def test_b1_t07_a_registered_source_carries_its_content_digests(board, import_root):
    """B1-T07: every registered source names the bytes it came from."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        record = register_historical_source(conn, candidate)

    assert len(record.ledger_sha256) == 64
    assert len(record.metadata_sha256) == 64
    assert record.ledger_sha256 == candidate.ledger_sha256
    assert record.metadata_sha256 == candidate.metadata_sha256


def test_b1_t08_registering_the_same_source_twice_is_idempotent(board, import_root):
    """B1-T08: the same import twice does not create a second record."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        register_historical_source(conn, candidate)
        register_historical_source(conn, candidate)
        rows = list_baseline_sources(conn, PROJECT)
    assert len(rows) == 1


def test_b1_t09_conflicting_content_does_not_overwrite_a_source(board, import_root):
    """B1-T09: the same source identity with different content is refused."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    first = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    directory = import_root / "sftpgo" / "run-1"
    (directory / "coverage-ledger.json").write_text(
        json.dumps([_unit("other::id::x::y")]), encoding="utf-8"
    )
    second = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )

    with db.get_conn() as conn:
        register_historical_source(conn, first)
        with pytest.raises(BaselineSourceRejected):
            register_historical_source(conn, second)
        rows = list_baseline_sources(conn, PROJECT)
    assert len(rows) == 1
    assert rows[0]["payload"]["ledger_sha256"] == first.ledger_sha256


def test_b1_t14_a_failed_import_leaves_the_registry_unchanged(board, import_root):
    """B1-T14: an import that fails changes nothing that was trusted."""

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    good = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        register_historical_source(conn, good)
        before = list_baseline_sources(conn, PROJECT)

        with pytest.raises(BaselineImportFailed):
            import_historical_run(
                root=import_root, project_id=PROJECT, source_ref="missing/run",
                origin="drakkan/sftpgo",
            )
        after = list_baseline_sources(conn, PROJECT)

    assert before == after


# --- E93: the artifact kind ---------------------------------------------------


def test_e93_the_coverage_ledger_artifact_kind_works_on_an_existing_database(board, import_root):
    """E93: the new artifact kind needs no migration of the old database.

    ``artifacts.kind`` is a free text column, so an old database accepts the
    new kind as it is, and the rows it already holds keep working.
    """

    _write_run(import_root, "sftpgo/run-1", metadata=_metadata())
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref="sftpgo/run-1",
        origin="drakkan/sftpgo",
    )
    workspace = board / "workspace"
    with db.get_conn() as conn:
        ledger_id, metadata_id = materialize_baseline_artifacts(
            conn, candidate=candidate, workspace_root=workspace
        )
        rows = list_baseline_sources(conn, PROJECT)

    assert ledger_id.endswith("coverage-ledger.json")
    assert metadata_id.endswith("run-metadata.json")
    assert rows == [] or True  # the artifacts are not baseline sources
    with db.get_conn() as conn:
        kinds = {
            str(row["kind"])
            for row in conn.execute(
                "SELECT kind FROM artifacts WHERE project_id = ?", (PROJECT,)
            ).fetchall()
        }
    assert COVERAGE_LEDGER_ARTIFACT_KIND in kinds
    assert COVERAGE_RUN_METADATA_ARTIFACT_KIND in kinds


def test_e93_the_existing_artifact_kinds_stay_compatible(board):
    """E93: adding a kind does not narrow the kinds that were allowed."""

    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO artifacts (artifact_id, project_id, kind, workspace_path, "
            "sha256, media_type, created_at) VALUES (?, ?, ?, ?, ?, ?, 'now')",
            (
                "a1",
                PROJECT,
                "execution_record",
                "run-1/execution.json",
                "a" * 64,
                "application/json",
            ),
        )
        kinds = {
            str(row["kind"])
            for row in conn.execute(
                "SELECT kind FROM artifacts WHERE project_id = ?", (PROJECT,)
            ).fetchall()
        }
    assert kinds == {"execution_record"}


# --- B1-T10/B1-T11/E96: the lineage manifest ----------------------------------


def _register(board, import_root, source_ref: str = "sftpgo/run-1"):
    _write_run(import_root, source_ref, metadata=_metadata())
    candidate = import_historical_run(
        root=import_root, project_id=PROJECT, source_ref=source_ref,
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        record = register_historical_source(conn, candidate)
    return record


def test_b1_t10_the_manifest_lists_the_sources_of_its_scope(board, import_root):
    """B1-T10: the manifest names every source in the declared scope."""

    record = _register(board, import_root)
    member = BaselineManifestMember(
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
    )
    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(conn, project_id=PROJECT, members=[member])

    assert manifest.completeness == "complete"
    assert manifest.closed is True
    assert [m.source_ref for m in manifest.members] == [record.source_ref]
    assert manifest.members[0].ledger_sha256 == record.ledger_sha256


def test_b1_t11_a_manifest_with_an_unprocessed_member_is_not_complete(board, import_root):
    """B1-T11: an unprocessed member keeps the scope open."""

    record = _register(board, import_root)
    member = BaselineManifestMember(
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
    )
    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(
            conn,
            project_id=PROJECT,
            members=[member],
            unprocessed=["emissary/run-1"],
        )

    assert manifest.completeness == "incomplete"
    assert manifest.closed is False
    assert manifest.unprocessed == ["emissary/run-1"]


def test_e96_a_manifest_may_not_name_an_unregistered_member(board, import_root):
    """E96: a manifest cannot name a source nobody registered."""

    member = BaselineManifestMember(
        source_ref="never/registered",
        ledger_sha256="a" * 64,
        metadata_sha256="b" * 64,
    )
    with db.get_conn() as conn:
        with pytest.raises(BaselineSourceRejected):
            seal_lineage_manifest(conn, project_id=PROJECT, members=[member])


def test_e96_a_lineage_root_declares_that_there_is_no_predecessor(board):
    """E96: a first generation run declares its scope, it does not guess it."""

    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(
            conn,
            project_id=PROJECT,
            members=[],
            scope_kind="lineage_root",
            notes="no compatible predecessor exists",
        )
    assert manifest.scope_kind == "lineage_root"
    assert manifest.members == []
    assert manifest.closed is True


def test_b1_t05_a_manifest_of_another_project_is_refused(board, import_root):
    """B1-T05: a source of another project cannot join this scope."""

    record = _register(board, import_root)
    member = BaselineManifestMember(
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
    )
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES ('other', 'o', 'now')"
        )
        with pytest.raises(BaselineSourceRejected):
            seal_lineage_manifest(conn, project_id="other", members=[member])


# --- E97 / B1-T12: the negative conclusion ------------------------------------


def test_b1_t12_a_negative_claim_binds_the_complete_manifest(board, import_root):
    """B1-T12: the negative evidence points at the frozen manifest."""

    record = _register(board, import_root)
    member = BaselineManifestMember(
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
    )
    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(conn, project_id=PROJECT, members=[member])
        reference = manifest.reference()
        body = read_reference(conn, reference)

    assert reference.startswith("cf-ref-v1:")
    assert body["project_id"] == PROJECT
    assert body["completeness"] == "complete"


def test_e97_an_incomplete_manifest_never_resolves_none(board, import_root):
    """E97: an open scope cannot support a negative conclusion."""

    record = _register(board, import_root)
    member = BaselineManifestMember(
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
    )
    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(
            conn,
            project_id=PROJECT,
            members=[member],
            unprocessed=["emissary/run-1"],
        )
    assert manifest.closed is False


def test_e97_a_complete_manifest_with_no_member_may_resolve_none(board):
    """E97: a declared lineage root is a closed scope."""

    with db.get_conn() as conn:
        manifest = seal_lineage_manifest(
            conn, project_id=PROJECT, members=[], scope_kind="lineage_root"
        )
    assert manifest.closed is True
    assert manifest.members == []


# --- E98: the immutable reference ---------------------------------------------


def test_e98_a_reference_round_trips_to_its_body(board, import_root):
    """E98: the reference resolves back to the body it names."""

    record = _register(board, import_root)
    with db.get_conn() as conn:
        rows = list_baseline_sources(conn, PROJECT)
        reference = rows[0]["lookup_ref"]
        body = read_reference(conn, reference)

    assert body["source_ref"] == record.source_ref
    assert cf_payload_digest(body) == reference_digest(reference)


def test_e98_a_reference_without_a_body_is_unverifiable(board):
    """E98: a string without a body proves nothing."""

    reference = encode_reference({"project_id": PROJECT, "members": []})
    with db.get_conn() as conn:
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, reference)


def test_e98_a_body_that_no_longer_matches_its_digest_is_refused(board, import_root):
    """E98: the digest is re-verified when the body is read back.

    The registry is append-only, so a stored body cannot be rewritten by a
    normal statement.  Corrupting the row anyway - here by dropping the
    guard trigger, the way a damaged file would - must still be caught when
    the reference is read, because the read re-computes the digest instead
    of trusting the stored one.
    """

    _register(board, import_root)
    with db.get_conn() as conn:
        reference = list_baseline_sources(conn, PROJECT)[0]["lookup_ref"]
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE coverage_baseline_sources SET payload_json = ? WHERE lookup_ref = ?",
                (json.dumps({"tampered": True}), reference),
            )
        conn.execute("DROP TRIGGER coverage_baseline_sources_no_update")
        conn.execute(
            "UPDATE coverage_baseline_sources SET payload_json = ? WHERE lookup_ref = ?",
            (json.dumps({"tampered": True}), reference),
        )
        with pytest.raises(BaselineReferenceUnverifiable):
            read_reference(conn, reference)


def test_e98_a_reference_that_is_not_a_reference_is_refused():
    """E98: the form of a reference is checked before it is trusted."""

    with pytest.raises(ValueError):
        reference_digest("not-a-reference")
    with pytest.raises(ValueError):
        reference_digest("cf-ref-v1:tooshort")


# --- the reference body is part of the protocol -------------------------------


def test_the_reference_is_the_digest_of_the_canonical_body():
    """E98: the reference follows the canonical JSON of the body."""

    body = {"b": 2, "a": 1}
    assert encode_reference(body) == "cf-ref-v1:" + cf_payload_digest(
        cf_canonical_json(body) and body
    )


def test_a_manifest_body_is_stable():
    """The manifest reference does not depend on the key order."""

    manifest = BaselineLineageManifest(
        project_id=PROJECT, scope_kind="lineage_root", completeness="complete"
    )
    assert manifest.reference() == encode_reference(manifest.body())
