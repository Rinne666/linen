"""Regression tests for the trusted issuance of validation receipts (CF-S2-B1 P1-C).

A validation receipt proves that the pinned upstream validator accepted one
exact document.  It does not prove that anybody was *allowed* to issue it: its
own digest only shows that its body was not changed, and anybody who can
construct JSON can construct a body that matches its own digest.

These tests pin the difference.  A receipt becomes trustworthy only when it
carries an authentication envelope - a MAC over the receipt and the source it
is about - that this deployment can verify with a key only the controlled
offline flow holds (D-058).  Everything else about the envelope follows from
that: it is bound to one receipt, one project and one source; it fails closed
when the key is missing or unknown; and a receipt that never had one stays
readable without becoming trustworthy (D-059).

The acceptance ids match the PM's P1-C matrix (P1-C-T01 ... P1-C-T12) and the
CR-T07 ... CR-T09 list of PM v2.6.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from linen.contracts.baseline import (
    LedgerValidationAuth,
    LedgerValidationReceipt,
    LedgerValidationResult,
    LedgerValidatorIdentity,
)
from linen.dispatcher.analysis.cf_baseline_validation import (
    import_validated_historical_run,
    pinned_upstream_commit,
)
from linen.dispatcher.analysis.cf_skill_assets import (
    VALIDATE_COVERAGE_LEDGER,
    cf_skill_file,
)
from linen.server import db
from linen.server.baseline_materialization import (
    BASELINE_WORKSPACE_DIR,
    HAS_NO_FOLLOW_OPERATIONS,
    BaselineMaterializationFailed,
    materialization_key,
)
from linen.server.baseline_validation_auth import (
    VALIDATION_KEYS_ENV,
    BaselineAuthRejected,
    configured_validation_keys,
    register_validation_auth,
    sign_validation_auth,
    signing_key,
    trusted_validation_auth,
)
from linen.server.skill_baseline_sources import (
    BaselineReferenceUnverifiable,
    import_historical_run,
    materialize_baseline_artifacts,
    register_historical_source,
    register_ledger_validation,
    registered_ledger_validation,
    verify_ledger_validation,
)

PROJECT = "p-baseline"
OTHER_PROJECT = "p-baseline-other"

#: The materialization refuses to run where the platform cannot open a file
#: without following a symbolic link (CF-S2-B1 P1-B).
requires_materialization = pytest.mark.skipif(
    not HAS_NO_FOLLOW_OPERATIONS,
    reason="the baseline materialization needs no-follow directory operations",
)

CANON_REFS = {
    "surface": "http-public-api",
    "boundary": "anonymous-to-authenticated",
    "subsystem": "authorization",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}

CANONICAL_ID = (
    "http-public-api::anonymous-to-authenticated::authorization::"
    "ATTACK-CLASSES.md%23Access%20control"
)

AGENT = "ag-w1-hunt-abcdef123456"

KEY_ID = "baseline-validator-key-1"


def _unit(coverage_id: str = CANONICAL_ID) -> dict:
    return {
        "coverage_id": coverage_id,
        "canonical_refs": dict(CANON_REFS),
        "surface": CANON_REFS["surface"],
        "boundary": CANON_REFS["boundary"],
        "subsystem": CANON_REFS["subsystem"],
        "attack_class": CANON_REFS["attack_class"],
        "starting_paths": ["app/authz.py"],
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control",
        "selected_companion_blocks": [],
        "excluded_blocks": [],
        "prior_status": "none",
        "attempts": [],
        "wave": 1,
        "status": "covered",
        "agent_id": AGENT,
        "reviewed_paths": ["app/authz.py"],
        "local_checks": [
            {
                "agent_id": AGENT,
                "reviewed_paths": ["app/authz.py"],
                "invariant": "the authorization check rejects a forged session",
                "method": "source",
                "result": "the forged session is rejected",
                "artifact": None,
            }
        ],
        "result_fingerprints": [],
        "unresolved": [],
    }


def _ledger_bytes(units: list[dict] | dict) -> bytes:
    return json.dumps(units, ensure_ascii=False).encode("utf-8")


def _metadata() -> dict:
    return {
        "run_id": "sftpgo-run-1",
        "repo": "drakkan/sftpgo",
        "source_ref": "305ebb875c0eb37ffe970ebf6af80f5f86a7e070",
        "profile": "standard",
    }


def _write_run(root: Path, source_ref: str, *, ledger: bytes) -> Path:
    directory = root / source_ref
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "coverage-ledger.json").write_bytes(ledger)
    (directory / "run-metadata.json").write_text(
        json.dumps(_metadata(), ensure_ascii=False), encoding="utf-8"
    )
    return directory


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        for project in (PROJECT, OTHER_PROJECT):
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
    """One readable historical run of the project."""

    _write_run(import_root, "sftpgo/run-1", ledger=_ledger_bytes([_unit()]))
    return import_historical_run(
        root=import_root,
        project_id=PROJECT,
        source_ref="sftpgo/run-1",
        origin="offline-import",
    )


def _import_run(conn, root: Path, source_ref: str, *, ledger: bytes, project_id=PROJECT):
    _write_run(root, source_ref, ledger=ledger)
    return import_validated_historical_run(
        conn=conn,
        root=root,
        project_id=project_id,
        source_ref=source_ref,
        origin="offline-import",
        issued_by="operator",
        issued_at="2026-01-01T00:00:00Z",
    )


def _receipt_of(candidate) -> LedgerValidationReceipt:
    assert candidate.validation_receipt is not None
    return candidate.validation_receipt


# --- T01: a self sealed receipt is not a trusted receipt ---------------------


def test_self_sealed_receipt_cannot_bypass_trusted_issuance(board) -> None:
    """CR-T07 / T01: a receipt that only matches its own digest proves nothing.

    The receipt below is perfectly well formed and carries its own digest -
    and it was never issued by the controlled flow.  Registering it must not
    make it trustworthy.
    """

    payload = _ledger_bytes([_unit()])
    digest = hashlib.sha256(payload).hexdigest()
    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    forged = LedgerValidationReceipt.issue(
        validation_kind="cloudflare_coverage_ledger",
        ledger_sha256=digest,
        validator=LedgerValidatorIdentity(
            upstream_commit=pinned_upstream_commit(),
            validator_sha256=hashlib.sha256(
                cf_skill_file(VALIDATE_COVERAGE_LEDGER).read_bytes()
            ).hexdigest(),
            runner="native",
            platform="linux",
        ),
        result=LedgerValidationResult(valid=True, record_count=1),
        project_id=PROJECT,
        source_ref="run-1",
        metadata_sha256=metadata_sha,
        issued_by="somebody",
        issued_at="2026-01-01T00:00:00Z",
    )
    assert forged.sealed() is True

    with db.get_conn() as conn:
        _write_run(board / "root", "run-1", ledger=payload)
        candidate = import_historical_run(
            root=board / "root",
            project_id=PROJECT,
            source_ref="run-1",
            origin="offline-import",
        )
        register_historical_source(conn, candidate)
        register_ledger_validation(
            conn, project_id=PROJECT, source_ref="run-1", receipt=forged
        )

        # The receipt is registered and readable ...
        stored = registered_ledger_validation(
            conn, project_id=PROJECT, receipt_sha256=forged.receipt_sha256
        )
        assert stored.receipt_sha256 == forged.receipt_sha256

        # ... but it is not trusted.
        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn, project_id=PROJECT, source_ref="run-1", ledger_bytes=payload
            )


def test_trusted_ledger_receipt_can_be_registered(board, validation_auth_key) -> None:
    """T02: a receipt the controlled flow issued is registered and trusted."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        verified = verify_ledger_validation(
            conn, project_id=PROJECT, source_ref="run-1", ledger_bytes=payload
        )
        envelope = trusted_validation_auth(
            conn, project_id=PROJECT, receipt=receipt
        )

    assert verified.receipt_sha256 == receipt.receipt_sha256
    assert envelope.key_id == KEY_ID
    assert envelope.receipt_sha256 == receipt.receipt_sha256


def test_validation_receipt_mac_tampering_is_rejected(board, validation_auth_key) -> None:
    """T03: an envelope whose MAC was changed is refused."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        envelope = trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)
        tampered = LedgerValidationAuth.model_validate(
            {**envelope.model_dump(mode="json"), "mac": "0" * 64}
        )
        with pytest.raises(BaselineAuthRejected):
            register_validation_auth(
                conn, project_id=PROJECT, receipt=receipt, envelope=tampered
            )


def test_validation_receipt_unknown_key_id_is_rejected(board, validation_auth_key) -> None:
    """T04: an envelope that names a key this deployment does not know is refused."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        key = configured_validation_keys()[KEY_ID]
        envelope = sign_validation_auth(receipt=receipt, key=key)
        unknown = LedgerValidationAuth.model_validate(
            {**envelope.model_dump(mode="json"), "key_id": "some-other-key"}
        )
        with pytest.raises(BaselineAuthRejected):
            register_validation_auth(
                conn, project_id=PROJECT, receipt=receipt, envelope=unknown
            )


def test_validation_key_shorter_than_32_bytes_is_rejected(monkeypatch) -> None:
    """P1-H1: a key that can be guessed is not a trusted key.

    HMAC-SHA256 stays sound with a short key; the *secret* does not.  A key of
    less than 256 bits can be enumerated, so it must not be able to make a
    validation trustworthy - it is left out of the key ring and every decision
    that depends on it fails closed.
    """

    short = "3f" * 31
    monkeypatch.setenv(
        VALIDATION_KEYS_ENV,
        json.dumps({KEY_ID: short}),
    )
    assert configured_validation_keys() == {}
    # ... so the controlled flow cannot even sign with it ...
    assert signing_key() is None

    # The boundary itself is accepted: 32 bytes is the least that counts.
    exact = "3f" * 32
    monkeypatch.setenv(
        VALIDATION_KEYS_ENV,
        json.dumps({KEY_ID: exact}),
    )
    keys = configured_validation_keys()
    assert list(keys) == [KEY_ID]
    assert len(keys[KEY_ID].secret) == 32


def test_validation_receipt_missing_key_fails_closed(board, monkeypatch) -> None:
    """T04: a deployment without a key trusts nothing."""

    monkeypatch.delenv(VALIDATION_KEYS_ENV, raising=False)
    payload = _ledger_bytes([_unit()])

    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        # The controlled flow could not issue an envelope ...
        assert configured_validation_keys() == {}
        with pytest.raises(BaselineAuthRejected):
            trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)

        # ... so the validation does not pass either.
        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn, project_id=PROJECT, source_ref="run-1", ledger_bytes=payload
            )


def test_validation_receipt_cannot_be_replayed_across_projects(
    board, validation_auth_key
) -> None:
    """T05: an envelope of one project is not an envelope of another."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)
        envelope = trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)

        with pytest.raises(BaselineAuthRejected):
            register_validation_auth(
                conn, project_id=OTHER_PROJECT, receipt=receipt, envelope=envelope
            )


def test_validation_receipt_cannot_be_replayed_across_sources(
    board, validation_auth_key
) -> None:
    """T05: an envelope of one source is not an envelope of another."""

    payload = _ledger_bytes([_unit()])
    other = _ledger_bytes([_unit(coverage_id=CANONICAL_ID + "-other")])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)
        key = configured_validation_keys()[KEY_ID]
        envelope = sign_validation_auth(receipt=receipt, key=key)

        second = _import_run(conn, board / "root", "run-2", ledger=other)
        second_receipt = _receipt_of(second)

        # An envelope that names the second receipt but keeps the first
        # source is refused: the source is part of what it authenticates.
        crossed = LedgerValidationAuth.model_validate(
            {
                **envelope.model_dump(mode="json"),
                "receipt_sha256": second_receipt.receipt_sha256,
                "ledger_sha256": second_receipt.ledger_sha256,
                "metadata_sha256": second_receipt.metadata_sha256,
            }
        )
        with pytest.raises(BaselineAuthRejected):
            register_validation_auth(
                conn, project_id=PROJECT, receipt=second_receipt, envelope=crossed
            )


def test_trusted_validation_registration_is_idempotent(
    board, validation_auth_key
) -> None:
    """T06: the same trusted issuance can be filed twice."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)
        envelope = trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)

        first = register_validation_auth(
            conn, project_id=PROJECT, receipt=receipt, envelope=envelope
        )
        second = register_validation_auth(
            conn, project_id=PROJECT, receipt=receipt, envelope=envelope
        )
        rows = conn.execute(
            "SELECT COUNT(*) AS total FROM coverage_ledger_validation_auths "
            "WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()

    assert first == second
    assert int(rows["total"]) == 1


def test_validation_auth_cannot_carry_another_receipt(board, validation_auth_key) -> None:
    """T07: one envelope cannot authenticate a different receipt."""

    payload = _ledger_bytes([_unit()])
    other = _ledger_bytes([_unit(coverage_id=CANONICAL_ID + "-other")])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)
        envelope = trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)

        second = _import_run(conn, board / "root", "run-2", ledger=other)
        second_receipt = _receipt_of(second)

        with pytest.raises(BaselineAuthRejected):
            register_validation_auth(
                conn, project_id=PROJECT, receipt=second_receipt, envelope=envelope
            )


def test_legacy_unsigned_receipt_is_not_trusted(board, monkeypatch) -> None:
    """T10: a receipt from before the trusted issuance stays readable."""

    # The deployment had no key when the run was imported, so the receipt
    # was registered without an authentication envelope.
    monkeypatch.delenv(VALIDATION_KEYS_ENV, raising=False)
    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        # A later deployment configures a key; the old receipt does not
        # become trusted because of it.
        monkeypatch.setenv(VALIDATION_KEYS_ENV, json.dumps({KEY_ID: "3f" * 32}))

        stored = registered_ledger_validation(
            conn, project_id=PROJECT, receipt_sha256=receipt.receipt_sha256
        )
        assert stored.receipt_sha256 == receipt.receipt_sha256

        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn, project_id=PROJECT, source_ref="run-1", ledger_bytes=payload
            )


def test_existing_validation_receipt_digest_is_unchanged(
    board, validation_auth_key
) -> None:
    """E141: the envelope never changes the receipt."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)
        before = receipt.receipt_sha256

        envelope = trusted_validation_auth(conn, project_id=PROJECT, receipt=receipt)
        register_validation_auth(
            conn, project_id=PROJECT, receipt=receipt, envelope=envelope
        )

        stored = registered_ledger_validation(
            conn, project_id=PROJECT, receipt_sha256=before
        )
        rows = conn.execute(
            "SELECT payload_sha256 FROM coverage_ledger_validations WHERE project_id = ?",
            (PROJECT,),
        ).fetchall()

    assert stored.receipt_sha256 == before
    assert stored.sealed() is True
    assert [str(row["payload_sha256"]) for row in rows] == [before]


def test_validation_auth_table_is_append_only(board, validation_auth_key) -> None:
    """The issuance proofs cannot be rewritten."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        receipt = _receipt_of(candidate)

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE coverage_ledger_validation_auths SET key_id = ? "
                "WHERE project_id = ?",
                ("other-key", PROJECT),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM coverage_ledger_validation_auths WHERE project_id = ?",
                (PROJECT,),
            )


# --- T11: the artifact registration of one materialization is all or nothing --


@requires_materialization
def test_artifact_registration_second_failure_rolls_back_new_rows(board, candidate) -> None:
    """T11: a failure in the middle of the registration adds no row at all.

    The caller catches the failure and commits the connection, so the rows
    the materialization had already written have to be gone - not merely
    uncommitted.
    """

    from linen.server import store

    workspace = board / "workspace"
    original = store.register_artifact
    calls = {"count": 0}

    def failing(conn, artifact):
        calls["count"] += 1
        if calls["count"] == 2:
            raise ValueError("the second registration fails")
        return original(conn, artifact)

    with db.get_conn() as conn:
        import linen.server.skill_baseline_sources as sources

        sources.register_artifact = failing
        try:
            with pytest.raises(ValueError):
                sources.materialize_baseline_artifacts(
                    conn, candidate=candidate, workspace_root=workspace
                )
        finally:
            sources.register_artifact = original
        # The caller swallows the failure and commits.
        conn.commit()
        rows = conn.execute(
            "SELECT artifact_id FROM artifacts WHERE project_id = ?", (PROJECT,)
        ).fetchall()

    assert rows == []


# --- T12: a file that is not a regular file is refused ------------------------


@requires_materialization
def test_materialization_rejects_nonregular_file_after_open(board, candidate) -> None:
    """T12: a fifo in place of the artifact is refused instead of read.

    The check and the open are two steps, so the file can be replaced
    between them.  The descriptor is therefore asked what it really is.
    """

    workspace = board / "workspace"
    key = materialization_key(candidate.source_ref)
    directory = workspace / PROJECT / BASELINE_WORKSPACE_DIR / key
    directory.mkdir(parents=True)
    fifo = directory / "coverage-ledger.json"
    try:
        os.mkfifo(fifo)
    except (AttributeError, OSError) as exc:  # pragma: no cover
        pytest.skip(f"this platform cannot create a fifo: {exc}")

    with db.get_conn() as conn:
        with pytest.raises(BaselineMaterializationFailed):
            materialize_baseline_artifacts(
                conn, candidate=candidate, workspace_root=workspace
            )
        rows = conn.execute(
            "SELECT artifact_id FROM artifacts WHERE project_id = ?", (PROJECT,)
        ).fetchall()

    assert rows == []
