"""Regression tests for the controlled upstream ledger validation (CF-S2-B1 P1-A).

A readable ledger is not a valid upstream ledger, and a valid upstream ledger
is not a verified source identity.  These tests pin the three apart, and pin
the rule that decides them: the pinned upstream validator, run offline on the
exact bytes that are about to be registered.

The acceptance ids match the PM's P1 matrix (CR-T01, CR-T02) and the
validation-boundary list of PM v2.4.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from linen.contracts.baseline import (
    LedgerValidationReceipt,
    LedgerValidationResult,
    LedgerValidatorIdentity,
)
from linen.dispatcher.analysis.cf_baseline_validation import (
    LedgerValidationOutcome,
    import_validated_historical_run,
    issue_ledger_validation_receipt,
    pinned_upstream_commit,
    validate_coverage_ledger_bytes,
    validator_runner,
)
from linen.dispatcher.analysis.cf_skill_assets import (
    VALIDATE_COVERAGE_LEDGER,
    cf_skill_file,
    validator_command,
)
from linen.server import db
from linen.server.skill_baseline_sources import (
    BaselineReferenceUnverifiable,
    BaselineSourceRejected,
    import_historical_run,
    list_baseline_sources,
    register_historical_source,
    register_ledger_validation,
    verify_ledger_validation,
)

PROJECT = "p-baseline"

CANON_REFS = {
    "surface": "http-public-api",
    "boundary": "anonymous-to-authenticated",
    "subsystem": "authorization",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}

#: The canonical identity upstream derives from ``CANON_REFS``.
CANONICAL_ID = (
    "http-public-api::anonymous-to-authenticated::authorization::"
    "ATTACK-CLASSES.md%23Access%20control"
)

AGENT = "ag-w1-hunt-abcdef123456"


def _unit(coverage_id: str = CANONICAL_ID) -> dict:
    """One coverage unit that satisfies the upstream contract."""

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
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')",
            (PROJECT,),
        )
    return tmp_path


def _import_run(conn, root: Path, source_ref: str, *, ledger: bytes):
    _write_run(root, source_ref, ledger=ledger)
    return import_validated_historical_run(
        conn=conn,
        root=root,
        project_id=PROJECT,
        source_ref=source_ref,
        origin="offline-import",
        issued_by="operator",
        issued_at="2026-01-01T00:00:00Z",
    )


def test_validated_ledger_receipt_binds_exact_bytes(board, validation_auth_key) -> None:
    """The receipt is bound to the bytes it was made for, and to nothing else."""

    payload = _ledger_bytes([_unit()])
    outcome = validate_coverage_ledger_bytes(ledger_bytes=payload)
    assert outcome.valid is True
    assert outcome.record_count == 1
    assert outcome.ledger_sha256 == hashlib.sha256(payload).hexdigest()

    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    receipt = issue_ledger_validation_receipt(
        outcome=outcome,
        project_id=PROJECT,
        source_ref="run-1",
        metadata_sha256=metadata_sha,
        issued_by="operator",
        issued_at="2026-01-01T00:00:00Z",
    )
    assert receipt.ledger_sha256 == hashlib.sha256(payload).hexdigest()
    assert receipt.sealed() is True

    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        assert candidate.validation_receipt is not None
        # The receipt the controlled flow filed is the very same proof.
        assert candidate.validation_receipt.receipt_sha256 == receipt.receipt_sha256

        verified = verify_ledger_validation(
            conn,
            project_id=PROJECT,
            source_ref="run-1",
            ledger_bytes=payload,
        )
    assert verified.receipt_sha256 == receipt.receipt_sha256
    assert verified.result.valid is True
    assert verified.ledger_sha256 == hashlib.sha256(payload).hexdigest()


def test_ledger_change_invalidates_validation_receipt(board, validation_auth_key) -> None:
    """A ledger that changed no longer carries the receipt made for it."""

    payload = _ledger_bytes([_unit()])
    changed = _ledger_bytes([_unit(coverage_id=CANONICAL_ID + "-changed")])

    with db.get_conn() as conn:
        _import_run(conn, board / "root", "run-1", ledger=payload)
        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn,
                project_id=PROJECT,
                source_ref="run-1",
                ledger_bytes=changed,
            )


def test_untrusted_validation_json_cannot_promote_source(board, validation_auth_key) -> None:
    """A hand-made receipt is not evidence, however well formed it is."""

    payload = _ledger_bytes([_unit()])
    digest = hashlib.sha256(payload).hexdigest()
    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    # A receipt that is internally consistent - it even carries its own
    # digest - and that claims the very same bytes and source as the
    # registered one, but that no controlled flow ever issued.
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
        # A source that was registered without a controlled validation.
        _write_run(board / "root", "run-2", ledger=payload)
        candidate = import_historical_run(
            root=board / "root",
            project_id=PROJECT,
            source_ref="run-2",
            origin="offline-import",
        )
        register_historical_source(conn, candidate)

        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn,
                project_id=PROJECT,
                source_ref="run-2",
                ledger_bytes=payload,
            )

        # And a presented receipt that is not the registered one is refused
        # even when the bytes match.
        _import_run(conn, board / "root", "run-1", ledger=payload)
        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn,
                project_id=PROJECT,
                source_ref="run-1",
                ledger_bytes=payload,
                presented_receipt=forged,
            )


def test_windows_runner_matches_upstream_schema_decision(tmp_path) -> None:
    """The runner reaches the upstream verdict, and says which runner it was.

    On POSIX the upstream CLI itself runs and both verdicts have to agree.
    On Windows the upstream CLI cannot open its input at all - Node on win32
    does not expose ``O_NOFOLLOW`` - so the linen-authored runner provides
    the schema verdict while the kernel-level file-open guarantee stays
    missing (D-051).
    """

    valid_payload = _ledger_bytes([_unit()])
    invalid_payload = _ledger_bytes([_unit(coverage_id="not-the-canonical-id")])

    valid_outcome = validate_coverage_ledger_bytes(ledger_bytes=valid_payload)
    invalid_outcome = validate_coverage_ledger_bytes(ledger_bytes=invalid_payload)

    assert valid_outcome.valid is True
    assert valid_outcome.record_count == 1
    assert invalid_outcome.valid is False
    assert invalid_outcome.errors
    assert any("coverage_id" in message for message in invalid_outcome.errors)

    assert valid_outcome.runner == validator_runner()
    assert valid_outcome.runner == ("windows_runner" if os.name == "nt" else "native")
    assert valid_outcome.upstream_commit == pinned_upstream_commit()
    assert valid_outcome.validator_sha256 == hashlib.sha256(
        cf_skill_file(VALIDATE_COVERAGE_LEDGER).read_bytes()
    ).hexdigest()

    # What the upstream CLI itself decides, for the same bytes.
    native = _run_native_validator(valid_payload, tmp_path)
    if os.name == "nt":
        # Node on win32 does not expose O_NOFOLLOW, so the upstream CLI
        # cannot open its input at all.  The runner exists for exactly this
        # case, and the file-open guarantee stays missing (D-051).
        assert native.returncode == 1
        assert "no-follow" in (native.stdout + native.stderr)
    else:
        assert native.returncode == 0
        assert "PASS" in native.stdout
        assert str(valid_outcome.record_count) in native.stdout


def test_schema_valid_does_not_imply_source_verified(board) -> None:
    """A valid upstream ledger is still an unverified source identity."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)

        assert candidate.upstream_schema_validated is True
        assert candidate.validation_receipt is not None
        assert candidate.validation_receipt.result.valid is True

        # The format is proven; the source identity is not.
        assert candidate.identity is not None
        assert candidate.identity.kind == "unverified"
        assert candidate.identity.verified is False

        sources = list_baseline_sources(conn, PROJECT, record_kind="historical_source")
        assert len(sources) == 1
        assert sources[0]["payload"]["source_identity"]["verified"] is False
        assert sources[0]["payload"]["source_identity"]["kind"] == "unverified"


def test_b1_import_rejects_invalid_canonical_identity(board) -> None:
    """CR-T01: a wrong canonical identity cannot become upstream-valid."""

    payload = _ledger_bytes([_unit(coverage_id="http-public-api::not-the-canonical-id")])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)

    assert candidate.eligible is True  # the run was readable
    assert candidate.upstream_schema_validated is False
    assert candidate.validation_receipt is not None
    assert candidate.validation_receipt.result.valid is False
    assert any(
        "coverage_id" in message for message in candidate.validation_receipt.result.errors
    )


def test_b1_import_rejects_noncanonical_document_shape(board) -> None:
    """CR-T02: a document that upstream would not accept is not upstream-valid."""

    payload = _ledger_bytes({"units": [_unit()]})
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)

    assert candidate.eligible is True  # the run was readable
    assert candidate.upstream_schema_validated is False
    assert candidate.validation_receipt is not None
    assert candidate.validation_receipt.result.valid is False
    assert any(
        "top-level array" in message for message in candidate.validation_receipt.result.errors
    )


def test_registration_is_idempotent(board) -> None:
    """The same receipt can be filed twice without duplicating anything."""

    payload = _ledger_bytes([_unit()])
    with db.get_conn() as conn:
        candidate = _import_run(conn, board / "root", "run-1", ledger=payload)
        assert candidate.validation_receipt is not None
        first = register_ledger_validation(
            conn,
            project_id=PROJECT,
            source_ref="run-1",
            receipt=candidate.validation_receipt,
        )
        second = register_ledger_validation(
            conn,
            project_id=PROJECT,
            source_ref="run-1",
            receipt=candidate.validation_receipt,
        )
        rows = conn.execute(
            "SELECT COUNT(*) AS total FROM coverage_ledger_validations WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()
    assert first == second
    assert int(rows["total"]) == 1


def test_staging_directory_is_removed_after_validation(tmp_path) -> None:
    """The controlled staging directory does not survive the validation."""

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = _ledger_bytes([_unit()])
    validate_coverage_ledger_bytes(ledger_bytes=payload, workspace=workspace)
    assert list(workspace.iterdir()) == []


def test_registered_receipt_requires_pinned_validator_digest(board) -> None:
    """CR-T08: a receipt has to name the pinned validator, build for build.

    A receipt that carries a digest of its own is self-consistent whatever
    validator it claims - the digest it carries is simply the digest of the
    body that names it.  So the registration compares the claimed validator
    with the digest of the validator that is actually pinned, and refuses a
    receipt that names a different build.
    """

    payload = _ledger_bytes([_unit()])
    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    forged = LedgerValidationReceipt.issue(
        validation_kind="cloudflare_coverage_ledger",
        ledger_sha256=hashlib.sha256(payload).hexdigest(),
        validator=LedgerValidatorIdentity(
            upstream_commit=pinned_upstream_commit(),
            validator_sha256="b" * 64,
            runner="native",
            platform="linux",
        ),
        result=LedgerValidationResult(valid=True, record_count=1),
        project_id=PROJECT,
        source_ref="run-1",
        metadata_sha256=metadata_sha,
        issued_by="operator",
        issued_at="2026-01-01T00:00:00Z",
    )
    assert forged.sealed() is True

    with db.get_conn() as conn:
        with pytest.raises(BaselineSourceRejected):
            register_ledger_validation(
                conn, project_id=PROJECT, source_ref="run-1", receipt=forged
            )
        rows = conn.execute(
            "SELECT COUNT(*) AS total FROM coverage_ledger_validations WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()
    assert int(rows["total"]) == 0


def test_registered_receipt_rejects_wrong_upstream_commit(board) -> None:
    """E142: a receipt that names another upstream commit is refused.

    The commit name is part of the validator identity, so a receipt made by
    a different snapshot is not a receipt about this validator.
    """

    payload = _ledger_bytes([_unit()])
    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    forged = LedgerValidationReceipt.issue(
        validation_kind="cloudflare_coverage_ledger",
        ledger_sha256=hashlib.sha256(payload).hexdigest(),
        validator=LedgerValidatorIdentity(
            upstream_commit="0" * 40,
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
        issued_by="operator",
        issued_at="2026-01-01T00:00:00Z",
    )

    with db.get_conn() as conn:
        with pytest.raises(BaselineSourceRejected):
            register_ledger_validation(
                conn, project_id=PROJECT, source_ref="run-1", receipt=forged
            )


def test_receipt_must_match_registered_source_ledger_digest(board) -> None:
    """CR-T09: the receipt has to be about the registered source's ledger.

    Three digests have to be one and the same: the bytes that are presented,
    the ledger the source was registered with, and the ledger the receipt was
    made for.  A receipt about other bytes - even a properly registered one -
    does not validate this source.
    """

    payload = _ledger_bytes([_unit()])
    other = _ledger_bytes([_unit(coverage_id=CANONICAL_ID + "-other")])
    metadata_sha = hashlib.sha256(
        json.dumps(_metadata(), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    with db.get_conn() as conn:
        _import_run(conn, board / "root", "run-1", ledger=payload)

        # A receipt about other bytes, registered under the same source.
        other_receipt = issue_ledger_validation_receipt(
            outcome=LedgerValidationOutcome(
                valid=True,
                record_count=1,
                errors=(),
                ledger_sha256=hashlib.sha256(other).hexdigest(),
                validator_sha256=hashlib.sha256(
                    cf_skill_file(VALIDATE_COVERAGE_LEDGER).read_bytes()
                ).hexdigest(),
                upstream_commit=pinned_upstream_commit(),
                runner=validator_runner(),
                platform="linux",
            ),
            project_id=PROJECT,
            source_ref="run-1",
            metadata_sha256=metadata_sha,
            issued_by="operator",
            issued_at="2026-01-01T00:00:00Z",
        )
        register_ledger_validation(
            conn, project_id=PROJECT, source_ref="run-1", receipt=other_receipt
        )

        # The registered source's ledger is still the original one.
        source = list_baseline_sources(
            conn, PROJECT, record_kind="historical_source"
        )[0]
        assert source["payload"]["ledger_sha256"] == hashlib.sha256(payload).hexdigest()

        # The other bytes carry a registered receipt, but it is not about this
        # source's ledger.
        with pytest.raises(BaselineReferenceUnverifiable):
            verify_ledger_validation(
                conn,
                project_id=PROJECT,
                source_ref="run-1",
                ledger_bytes=other,
            )


def _run_native_validator(payload: bytes, tmp_path: Path) -> subprocess.CompletedProcess:
    """Run the upstream CLI *itself* against the same bytes.

    This deliberately bypasses ``validator_command()``: that helper routes
    through the linen-authored runner on Windows, and the point of the
    comparison is to see what the upstream CLI can do on this platform.
    """

    staged = tmp_path / "native-sample.json"
    staged.write_bytes(payload)
    return subprocess.run(
        ["node", str(cf_skill_file(VALIDATE_COVERAGE_LEDGER)), str(staged)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
