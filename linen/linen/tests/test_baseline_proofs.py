"""Regression tests for the trusted proofs about history (CF-S2-B2-A).

Two proofs are pinned here:

* a **source identity attestation** says that one registered historical source
  has a verified identity - a git commit that really exists in a named
  repository with a clean worktree, or a frozen snapshot whose bytes still are
  the registered ones;
* a **lineage seal** says that one historical scope was closed and sealed for
  one run, and it binds every member of that scope to the attestation that
  proved the member's identity.

The tests pin the boundaries that matter:

* a request that *claims* ``verified = true`` produces no trusted identity
  (A-T03) - only a signature made with the controlled flow's key does;
* a complete manifest is not a seal, and a seal is not a negative conclusion
  on its own (A-T11);
* a lineage root - the statement that a project has no predecessor - is an
  authority claim and needs a trusted issuer (A-T12);
* contradictory proofs are kept and reported as a conflict instead of the
  newest one winning (A-T08);
* neither proof opens the production registration by itself (A-T14).

The acceptance ids match the PM's B2-A matrix of PM v2.7 (A-T01 ... A-T14).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from linen.contracts.baseline import (
    BaselineManifestMember,
    BaselineSourceIdentity,
    LineageSeal,
    ProofAuthentication,
    SourceIdentityAttestation,
    SourceIdentityVerification,
    encode_reference,
)
from linen.dispatcher.analysis.cf_baseline_validation import (
    attest_historical_source,
    seal_historical_scope,
)
from linen.server import db
from linen.server.baseline_proof_auth import issue_proof_auth
from linen.server.baseline_proofs import (
    BaselineProofRejected,
    build_lineage_seal,
    build_source_attestation,
    lineage_seal_status,
    register_lineage_seal,
    register_source_attestation,
    source_attestation_status,
)
from linen.server.baseline_validation_auth import VALIDATION_KEYS_ENV
from linen.server.skill_baseline_sources import (
    import_historical_run,
    register_historical_source,
    seal_lineage_manifest,
)

PROJECT = "p-baseline"
OTHER_PROJECT = "p-baseline-other"
KEY_ID = "baseline-validator-key-1"
RUN_ID = "run-current"

REFS = {
    "surface": "http-public-api",
    "boundary": "anonymous-to-authenticated",
    "subsystem": "authorization",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}


def _unit(coverage_id: str = "http-public-api::anonymous-to-authenticated::authorization::access-control") -> dict:
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
        "prior_status": "none",
        "attempts": [],
        "wave": 1,
        "status": "covered",
        "agent_id": "ag-w1-hunt-abcdef123456",
        "reviewed_paths": ["app/authz.py"],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }


def _write_run(root: Path, source_ref: str, *, metadata: dict | None = None) -> Path:
    directory = root / source_ref
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "coverage-ledger.json").write_text(
        json.dumps([_unit()], ensure_ascii=False), encoding="utf-8"
    )
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
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'o', 'now')",
            (OTHER_PROJECT,),
        )
    return tmp_path


@pytest.fixture
def import_root(tmp_path) -> Path:
    root = tmp_path / "corpus"
    root.mkdir()
    return root


def _register(board, import_root, source_ref: str = "sftpgo/run-1", *, metadata: dict | None = None):
    if metadata is None:
        metadata = _metadata()
    _write_run(import_root, source_ref, metadata=metadata)
    candidate = import_historical_run(
        root=import_root,
        project_id=PROJECT,
        source_ref=source_ref,
        origin="drakkan/sftpgo",
    )
    with db.get_conn() as conn:
        return register_historical_source(conn, candidate)


def _run(conn, run_id: str = RUN_ID, project_id: str = PROJECT) -> None:
    conn.execute(
        "INSERT INTO runs (run_id, project_id, task_type, idempotency_key, "
        "timeout_seconds, created_at, updated_at) VALUES (?, ?, 'audit', ?, 60, 'now', 'now')",
        (run_id, project_id, f"idem-{run_id}-{project_id}"),
    )


def _git_repo(root: Path, *, remote: str = "https://github.com/drakkan/sftpgo.git") -> str:
    """A synthetic repository with one commit - a fixture, not real history."""

    root.mkdir(parents=True, exist_ok=True)

    def run(*args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return completed.stdout.strip()

    run("init", "--quiet")
    run("config", "user.email", "operator@example.invalid")
    run("config", "user.name", "operator")
    (root / "server.py").write_text("print('hello')\n", encoding="utf-8")
    run("add", "server.py")
    run("commit", "--quiet", "-m", "initial")
    if remote:
        run("remote", "add", "origin", remote)
    return run("rev-parse", "HEAD")


requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not available on this machine"
)


def _attest(board, import_root, source_ref: str = "sftpgo/run-1", **kwargs):
    """Attest one source through the controlled entry point."""

    with db.get_conn() as conn:
        return attest_historical_source(
            conn=conn,
            project_id=PROJECT,
            source_ref=source_ref,
            observed_at=kwargs.pop("observed_at", "2026-01-01T00:00:00Z"),
            frozen_root=import_root,
            **kwargs,
        )


# --- A-T01 ... A-T03: what an attestation may talk about ---------------------


def test_a_t01_an_attestation_needs_a_registered_source(board, import_root, validation_auth_key):
    """A-T01: an attestation can only be about a registered historical source."""

    with db.get_conn() as conn:
        with pytest.raises(BaselineProofRejected):
            build_source_attestation(
                conn=conn,
                project_id=PROJECT,
                source_ref="sftpgo/run-1",
                observed_at="now",
                frozen_root=import_root,
            )

    record = _register(board, import_root)
    with db.get_conn() as conn:
        attestation = build_source_attestation(
            conn=conn,
            project_id=PROJECT,
            source_ref=record.source_ref,
            observed_at="now",
            frozen_root=import_root,
        )
        envelope = issue_proof_auth(
            proof_kind="source_attestation",
            proof_sha256=attestation.attestation_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        digest = register_source_attestation(
            conn=conn,
            project_id=PROJECT,
            attestation=attestation,
            envelope=envelope,
        )
        assert digest == attestation.attestation_sha256


def test_a_t02_an_attestation_cannot_cross_projects(board, import_root, validation_auth_key):
    """A-T02: a source of one project is not a source of another."""

    _register(board, import_root)
    with db.get_conn() as conn:
        attestation = build_source_attestation(
            conn=conn,
            project_id=PROJECT,
            source_ref="sftpgo/run-1",
            observed_at="now",
            frozen_root=import_root,
        )
        envelope = issue_proof_auth(
            proof_kind="source_attestation",
            proof_sha256=attestation.attestation_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        with pytest.raises(BaselineProofRejected):
            register_source_attestation(
                conn=conn,
                project_id=OTHER_PROJECT,
                attestation=attestation,
                envelope=envelope,
            )


def test_a_t03_a_self_reported_verification_is_not_trusted(board, import_root, validation_auth_key):
    """A-T03: claiming ``verified = true`` in a body proves nothing."""

    record = _register(board, import_root)
    forged = SourceIdentityAttestation.issue(
        project_id=PROJECT,
        source_ref=record.source_ref,
        ledger_sha256=record.ledger_sha256,
        metadata_sha256=record.metadata_sha256,
        identity=BaselineSourceIdentity(
            kind="git_commit",
            origin="drakkan/sftpgo",
            revision="a" * 40,
            verified=True,
        ),
        verification=SourceIdentityVerification(
            method="git_commit",
            repository_root="/nowhere",
            commit="a" * 40,
            tree_sha="b" * 40,
            worktree_clean=True,
            observed_at="now",
        ),
        evidence_ref=encode_reference({"forged": True}),
    )
    forged_envelope = ProofAuthentication(
        proof_kind="source_attestation",
        key_id=KEY_ID,
        proof_sha256=forged.attestation_sha256,
        project_id=PROJECT,
        mac="0" * 64,
    )

    with db.get_conn() as conn:
        with pytest.raises(BaselineProofRejected):
            register_source_attestation(
                conn=conn,
                project_id=PROJECT,
                attestation=forged,
                envelope=forged_envelope,
            )
        status = source_attestation_status(
            conn, project_id=PROJECT, source_ref=record.source_ref
        )
        assert status.state == "unverified"
        assert status.attestations == ()


# --- A-T04 ... A-T05: what the verification actually proves ------------------


@requires_git
def test_a_t04_a_git_commit_must_match_the_frozen_snapshot(board, import_root, tmp_path, validation_auth_key):
    """A-T04: the commit has to be the one the snapshot was taken from."""

    repository = tmp_path / "repo"
    commit = _git_repo(repository)
    _register(board, import_root, metadata=_metadata(commit))

    other = tmp_path / "other-repo"
    other_commit = _git_repo(other, remote="https://github.com/someone/else.git")

    with db.get_conn() as conn:
        # a commit that the snapshot does not name
        with pytest.raises(BaselineProofRejected):
            build_source_attestation(
                conn=conn,
                project_id=PROJECT,
                source_ref="sftpgo/run-1",
                observed_at="now",
                repo_root=repository,
                commit="c" * 40,
            )
        # the right commit, but in a repository that is not the frozen one
        with pytest.raises(BaselineProofRejected):
            build_source_attestation(
                conn=conn,
                project_id=PROJECT,
                source_ref="sftpgo/run-1",
                observed_at="now",
                repo_root=other,
                commit=commit,
            )
        # the right commit in the right repository
        attestation = build_source_attestation(
            conn=conn,
            project_id=PROJECT,
            source_ref="sftpgo/run-1",
            observed_at="now",
            repo_root=repository,
            commit=commit,
        )
        assert attestation.verification.method == "git_commit"
        assert attestation.verification.commit == commit
        assert attestation.verification.worktree_clean is True


@requires_git
def test_a_t04_b_a_dirty_worktree_is_not_a_frozen_snapshot(board, import_root, tmp_path, validation_auth_key):
    """A-T04: unrecorded worktree changes mean the files are not the commit."""

    repository = tmp_path / "repo"
    commit = _git_repo(repository)
    _register(board, import_root, metadata=_metadata(commit))
    (repository / "server.py").write_text("print('changed')\n", encoding="utf-8")

    with db.get_conn() as conn:
        with pytest.raises(BaselineProofRejected):
            build_source_attestation(
                conn=conn,
                project_id=PROJECT,
                source_ref="sftpgo/run-1",
                observed_at="now",
                repo_root=repository,
                commit=commit,
            )


def test_a_t05_a_non_git_source_is_verified_by_its_frozen_digest(board, import_root, validation_auth_key):
    """A-T05: a source without a repository is verified by its frozen bytes."""

    record = _register(board, import_root)
    with db.get_conn() as conn:
        attestation = build_source_attestation(
            conn=conn,
            project_id=PROJECT,
            source_ref=record.source_ref,
            observed_at="now",
            frozen_root=import_root,
        )
        assert attestation.verification.method == "frozen_digest"
        assert attestation.verification.snapshot_sha256
        assert attestation.identity.verified is True
        envelope = issue_proof_auth(
            proof_kind="source_attestation",
            proof_sha256=attestation.attestation_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        register_source_attestation(
            conn=conn,
            project_id=PROJECT,
            attestation=attestation,
            envelope=envelope,
        )
        status = source_attestation_status(
            conn, project_id=PROJECT, source_ref=record.source_ref
        )
        assert status.state == "verified"


def test_a_t05_b_a_changed_frozen_byte_breaks_the_verification(board, import_root, validation_auth_key):
    """A-T05: the frozen bytes have to still be the registered ones."""

    record = _register(board, import_root)
    (import_root / "sftpgo" / "run-1" / "coverage-ledger.json").write_text(
        json.dumps([_unit("http-public-api::anonymous-to-authenticated::authorization::other")]),
        encoding="utf-8",
    )
    with db.get_conn() as conn:
        with pytest.raises(BaselineProofRejected):
            build_source_attestation(
                conn=conn,
                project_id=PROJECT,
                source_ref=record.source_ref,
                observed_at="now",
                frozen_root=import_root,
            )


# --- A-T06 ... A-T09: what the registry guarantees ---------------------------


def test_a_t06_the_proof_tables_are_append_only(board, import_root, validation_auth_key):
    """A-T06: neither proof may be rewritten or removed."""

    manifest = _sealed_scope(board, import_root)
    with db.get_conn() as conn:
        seal = seal_historical_scope(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN_ID,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="now",
        )
        assert seal is not None
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE coverage_source_attestations SET key_id = ? WHERE project_id = ?",
                ("other-key", PROJECT),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM coverage_source_attestations WHERE project_id = ?",
                (PROJECT,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE coverage_lineage_seals SET key_id = ? WHERE project_id = ?",
                ("other-key", PROJECT),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM coverage_lineage_seals WHERE project_id = ?",
                (PROJECT,),
            )


def test_a_t07_registering_the_same_attestation_twice_is_idempotent(board, import_root, validation_auth_key):
    """A-T07: the same proof may be registered again without a second row."""

    _register(board, import_root)
    _attest(board, import_root)
    with db.get_conn() as conn:
        attestation = build_source_attestation(
            conn=conn,
            project_id=PROJECT,
            source_ref="sftpgo/run-1",
            observed_at="2026-01-01T00:00:00Z",
            frozen_root=import_root,
        )
        envelope = issue_proof_auth(
            proof_kind="source_attestation",
            proof_sha256=attestation.attestation_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        first = register_source_attestation(
            conn=conn,
            project_id=PROJECT,
            attestation=attestation,
            envelope=envelope,
        )
        second = register_source_attestation(
            conn=conn,
            project_id=PROJECT,
            attestation=attestation,
            envelope=envelope,
        )
        assert first == second
        rows = conn.execute(
            "SELECT COUNT(*) FROM coverage_source_attestations WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()[0]
        assert rows == 1


def test_a_t08_contradictory_attestations_are_kept_and_reported(board, import_root, validation_auth_key):
    """A-T08: two proofs about one source are a conflict, not a race."""

    _register(board, import_root)
    _attest(board, import_root, observed_at="2026-01-01T00:00:00Z")
    _attest(board, import_root, observed_at="2026-06-01T00:00:00Z")

    with db.get_conn() as conn:
        status = source_attestation_status(
            conn, project_id=PROJECT, source_ref="sftpgo/run-1"
        )
        assert status.state == "conflict"
        assert len(status.attestations) == 2
        rows = conn.execute(
            "SELECT COUNT(*) FROM coverage_source_attestations WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()[0]
        assert rows == 2


def test_a_t09_without_trusted_evidence_the_source_stays_unverified(board, import_root, monkeypatch, validation_auth_key):
    """A-T09: no attestation, or a revoked key, means unverified."""

    record = _register(board, import_root)
    with db.get_conn() as conn:
        status = source_attestation_status(
            conn, project_id=PROJECT, source_ref=record.source_ref
        )
        assert status.state == "unverified"
        assert status.reason

    _attest(board, import_root)
    with db.get_conn() as conn:
        assert (
            source_attestation_status(
                conn, project_id=PROJECT, source_ref=record.source_ref
            ).state
            == "verified"
        )

    # the key is revoked: the proof stays readable, but it is not trusted any more
    monkeypatch.delenv(VALIDATION_KEYS_ENV, raising=False)
    with db.get_conn() as conn:
        status = source_attestation_status(
            conn, project_id=PROJECT, source_ref=record.source_ref
        )
        assert status.state == "unverified"
        assert len(status.attestations) == 1


# --- A-T10 ... A-T14: what a seal may claim ----------------------------------


def _sealed_scope(board, import_root, *, run_id: str = RUN_ID, scope_kind: str = "declared_predecessor_lineage"):
    """Register one source, attest it and freeze the scope around it."""

    record = _register(board, import_root)
    _attest(board, import_root)
    with db.get_conn() as conn:
        _run(conn, run_id)
        member = BaselineManifestMember(
            source_ref=record.source_ref,
            ledger_sha256=record.ledger_sha256,
            metadata_sha256=record.metadata_sha256,
        )
        members = [] if scope_kind == "lineage_root" else [member]
        manifest = seal_lineage_manifest(
            conn, project_id=PROJECT, members=members, scope_kind=scope_kind
        )
        return manifest


def test_a_t10_a_seal_names_a_run_of_the_project(board, import_root, validation_auth_key):
    """A-T10: a seal is about one run of one project."""

    manifest = _sealed_scope(board, import_root)
    with db.get_conn() as conn:
        with pytest.raises(BaselineProofRejected):
            build_lineage_seal(
                conn=conn,
                project_id=PROJECT,
                run_id="run-that-does-not-exist",
                manifest_ref=manifest.reference(),
                issuer="operator",
                issued_at="now",
            )
        _run(conn, "run-of-another-project", project_id=OTHER_PROJECT)
        with pytest.raises(BaselineProofRejected):
            build_lineage_seal(
                conn=conn,
                project_id=PROJECT,
                run_id="run-of-another-project",
                manifest_ref=manifest.reference(),
                issuer="operator",
                issued_at="now",
            )


def test_a_t11_a_complete_manifest_is_not_a_seal(board, import_root, validation_auth_key):
    """A-T11: structure alone may never carry a negative conclusion."""

    manifest = _sealed_scope(board, import_root)
    assert manifest.closed is True
    with db.get_conn() as conn:
        status = lineage_seal_status(conn, project_id=PROJECT, run_id=RUN_ID)
        assert status.sealed is False
        assert status.trusted_negative is False
        assert status.reason


def test_a_t12_a_lineage_root_needs_a_trusted_issuer(board, import_root, validation_auth_key):
    """A-T12: the statement "there is no predecessor" is an authority claim."""

    manifest = _sealed_scope(board, import_root, scope_kind="lineage_root")
    assert manifest.scope_kind == "lineage_root"
    assert manifest.members == []

    with db.get_conn() as conn:
        seal = build_lineage_seal(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN_ID,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="now",
        )
        assert seal.scope_kind == "lineage_root"
        assert seal.members == []

        forged = ProofAuthentication(
            proof_kind="lineage_seal",
            key_id=KEY_ID,
            proof_sha256=seal.seal_sha256,
            project_id=PROJECT,
            mac="0" * 64,
        )
        with pytest.raises(BaselineProofRejected):
            register_lineage_seal(
                conn=conn, project_id=PROJECT, seal=seal, envelope=forged
            )

        envelope = issue_proof_auth(
            proof_kind="lineage_seal",
            proof_sha256=seal.seal_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        register_lineage_seal(
            conn=conn, project_id=PROJECT, seal=seal, envelope=envelope
        )
        status = lineage_seal_status(conn, project_id=PROJECT, run_id=RUN_ID)
        assert status.sealed is True
        assert status.trusted_negative is True


def test_a_t13_every_member_of_a_seal_is_re_verified(board, import_root, validation_auth_key):
    """A-T13: the members of a seal are checked again every time it is read."""

    manifest = _sealed_scope(board, import_root)
    with db.get_conn() as conn:
        seal = build_lineage_seal(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN_ID,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="now",
        )
        envelope = issue_proof_auth(
            proof_kind="lineage_seal",
            proof_sha256=seal.seal_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        register_lineage_seal(
            conn=conn, project_id=PROJECT, seal=seal, envelope=envelope
        )
        status = lineage_seal_status(conn, project_id=PROJECT, run_id=RUN_ID)
        assert status.trusted_negative is True

    # a second, contradictory attestation turns the member into a conflict
    _attest(board, import_root, observed_at="2026-06-01T00:00:00Z")
    with db.get_conn() as conn:
        status = lineage_seal_status(conn, project_id=PROJECT, run_id=RUN_ID)
        assert status.trusted_negative is False
        assert status.reason


def test_a_t13_b_a_seal_may_not_cover_other_members(board, import_root, validation_auth_key):
    """A-T13: the seal has to cover exactly the members of the manifest."""

    manifest = _sealed_scope(board, import_root)
    with db.get_conn() as conn:
        seal = build_lineage_seal(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN_ID,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="now",
        )
        forged = LineageSeal.issue(
            project_id=seal.project_id,
            run_id=seal.run_id,
            lineage_manifest_ref=seal.lineage_manifest_ref,
            manifest_sha256=seal.manifest_sha256,
            scope_kind=seal.scope_kind,
            completeness=seal.completeness,
            members=[],
            issuer=seal.issuer,
            issued_at=seal.issued_at,
        )
        envelope = issue_proof_auth(
            proof_kind="lineage_seal",
            proof_sha256=forged.seal_sha256,
            project_id=PROJECT,
        )
        assert envelope is not None
        with pytest.raises(BaselineProofRejected):
            register_lineage_seal(
                conn=conn, project_id=PROJECT, seal=forged, envelope=envelope
            )


def test_a_t14_a_proof_does_not_open_the_production_registration(board, import_root, validation_auth_key):
    """A-T14: attesting and sealing write no coverage event and no verdict."""

    manifest = _sealed_scope(board, import_root)
    with db.get_conn() as conn:
        seal = seal_historical_scope(
            conn=conn,
            project_id=PROJECT,
            run_id=RUN_ID,
            manifest_ref=manifest.reference(),
            issuer="operator",
            issued_at="now",
        )
        assert seal is not None
        events = conn.execute(
            "SELECT COUNT(*) FROM skill_coverage_events WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()[0]
        assert events == 0
        facts = conn.execute(
            "SELECT COUNT(*) FROM facts WHERE project_id = ?", (PROJECT,)
        ).fetchone()[0]
        assert facts == 0
        status = lineage_seal_status(conn, project_id=PROJECT, run_id=RUN_ID)
        assert status.sealed is True
