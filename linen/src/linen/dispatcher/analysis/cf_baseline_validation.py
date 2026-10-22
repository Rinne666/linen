"""Controlled offline validation of a historical coverage ledger (CF-S2-B1 P1-A).

The pinned upstream Cloudflare validator is the authority on what an upstream
coverage ledger looks like.  This module runs it - offline, in the operator's
process - against *the exact bytes* that are about to be registered, and turns
the verdict into a versioned receipt.

Three rules shape the implementation (PM v2.4, D-043):

* the validator runs on a **staged copy of the bytes that were read**, never
  on the path the operator pointed at, so the file cannot be swapped between
  the validation and the registration;
* the receipt binds the **bytes**, the **validator identity**, the **result**
  and the **source it is about** - a receipt without those is not evidence;
* the FastAPI server never runs this module: it only *verifies* a receipt that
  the controlled import flow registered.

Windows note (D-051): the upstream CLI opens its input with
``O_NOFOLLOW | O_NONBLOCK``, which Node on win32 does not expose, so the
validator is executed through the linen-authored ``run-validator.windows.cjs``
there.  That runner reaches the same schema verdict, but it does not have the
same kernel-level file-open guarantee, so the receipt records which runner
produced it.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from linen.contracts.baseline import (
    LedgerValidationReceipt,
    LedgerValidationResult,
    LedgerValidatorIdentity,
)

from .cf_skill_assets import (
    VALIDATE_COVERAGE_LEDGER,
    cf_skill_dir,
    cf_skill_file,
    validator_command,
)

#: The validation kind this module produces.
LEDGER_VALIDATION_KIND = "cloudflare_coverage_ledger"

#: The file name the staged ledger is written under.  The upstream validator
#: only cares about the content, but a stable name keeps the diagnostics
#: readable.
STAGED_LEDGER_NAME = "coverage-ledger.json"

#: How long the pinned validator may run before the validation is abandoned.
VALIDATION_TIMEOUT_SECONDS = 120

#: The upstream validator reports its verdict on stdout.
_PASS_LINE = re.compile(r"PASS:\s*(\d+)\s+(?:coverage units|records)\s+valid")

#: The upstream validator reports every rule violation on stderr.
_ERROR_LINE = re.compile(r"^ERROR:\s*(.+)$", re.MULTILINE)


class LedgerValidationUnavailable(RuntimeError):
    """The pinned validator could not be executed, or could not be trusted."""


@dataclass(frozen=True)
class LedgerValidationOutcome:
    """What the pinned validator decided about one exact document."""

    valid: bool
    record_count: int
    errors: tuple[str, ...]
    ledger_sha256: str
    validator_sha256: str
    upstream_commit: str
    runner: str
    platform: str


def pinned_upstream_commit() -> str:
    """The upstream commit the vendored validator snapshot is pinned to."""

    return (cf_skill_dir() / "UPSTREAM_COMMIT").read_text(encoding="utf-8").strip()


def validator_runner() -> str:
    """The runner that executes the pinned validator on this platform."""

    return "windows_runner" if os.name == "nt" else "native"


def _collect_errors(stderr: str) -> tuple[str, ...]:
    """The rule violations the upstream validator reported."""

    return tuple(match.strip() for match in _ERROR_LINE.findall(stderr or ""))


def validate_coverage_ledger_bytes(
    *, ledger_bytes: bytes, workspace: Path | None = None
) -> LedgerValidationOutcome:
    """Validate one exact ledger document with the pinned upstream validator.

    The document is staged in a directory this process owns, the validator is
    pointed at the staged copy, and the staged copy is read back afterwards to
    confirm that the bytes that were validated are the bytes that were read.
    A document that is not valid upstream is not an error here: the outcome
    simply says so, because the caller has to be able to record *why* a
    candidate is not upstream-valid.
    """

    digest = hashlib.sha256(ledger_bytes).hexdigest()
    validator_path = cf_skill_file(VALIDATE_COVERAGE_LEDGER)
    if not validator_path.is_file():
        raise LedgerValidationUnavailable(
            "the pinned upstream coverage validator is missing from the snapshot"
        )
    validator_digest = hashlib.sha256(validator_path.read_bytes()).hexdigest()
    commit = pinned_upstream_commit()
    runner = validator_runner()

    staging = Path(
        tempfile.mkdtemp(
            prefix="cf-ledger-validation-",
            dir=str(workspace) if workspace is not None else None,
        )
    )
    try:
        staged = staging / STAGED_LEDGER_NAME
        descriptor = os.open(
            staged,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(ledger_bytes)

        staged_digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        if staged_digest != digest:
            raise LedgerValidationUnavailable(
                "the staged ledger does not match the bytes that were read"
            )

        argv = validator_command(validator_path, staged)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=VALIDATION_TIMEOUT_SECONDS,
                cwd=str(staging),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LedgerValidationUnavailable(
                f"the pinned upstream validator could not be executed: {exc}"
            ) from exc

        if completed.returncode == 0:
            match = _PASS_LINE.search(completed.stdout or "")
            if match is None:
                raise LedgerValidationUnavailable(
                    "the pinned upstream validator did not report a record count"
                )
            return LedgerValidationOutcome(
                valid=True,
                record_count=int(match.group(1)),
                errors=(),
                ledger_sha256=digest,
                validator_sha256=validator_digest,
                upstream_commit=commit,
                runner=runner,
                platform=platform.system().lower(),
            )

        return LedgerValidationOutcome(
            valid=False,
            record_count=0,
            errors=_collect_errors(completed.stderr or ""),
            ledger_sha256=digest,
            validator_sha256=validator_digest,
            upstream_commit=commit,
            runner=runner,
            platform=platform.system().lower(),
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def issue_ledger_validation_receipt(
    *,
    outcome: LedgerValidationOutcome,
    project_id: str,
    source_ref: str,
    metadata_sha256: str,
    issued_by: str,
    issued_at: str,
) -> LedgerValidationReceipt:
    """Seal one validation outcome into a receipt that binds its evidence."""

    return LedgerValidationReceipt.issue(
        validation_kind=LEDGER_VALIDATION_KIND,
        ledger_sha256=outcome.ledger_sha256,
        validator=LedgerValidatorIdentity(
            upstream_commit=outcome.upstream_commit,
            validator_sha256=outcome.validator_sha256,
            runner=outcome.runner,
            platform=outcome.platform,
        ),
        result=LedgerValidationResult(
            valid=outcome.valid,
            record_count=outcome.record_count,
            errors=list(outcome.errors),
        ),
        project_id=project_id,
        source_ref=source_ref,
        metadata_sha256=metadata_sha256,
        issued_by=issued_by,
        issued_at=issued_at,
    )


def import_validated_historical_run(
    *,
    conn: Any,
    root: Path,
    project_id: str,
    source_ref: str,
    origin: str,
    issued_by: str,
    issued_at: str,
    workspace: Path | None = None,
    signing_key_id: str | None = None,
) -> Any:
    """Read, validate and register one historical run - the controlled flow.

    This is the only entry point that may turn a historical run into a
    source with an upstream validation attached.  It reads the run out of the
    declared root, validates the very bytes it read with the pinned upstream
    validator, and registers both the source and the validation receipt.

    A run whose ledger is not upstream-valid is still registered as a
    candidate: dropping it silently and then declaring the history complete is
    exactly what must not happen (D-036).  It simply does not gain the
    upstream-valid qualification.

    The flow also issues the *authentication envelope* of the receipt when
    the deployment configured a key for it (D-058).  Without a key there is
    no envelope, and a receipt without an envelope is readable but not
    trustworthy - the server fails closed on it.
    """

    from linen.server.baseline_validation_auth import (
        issue_trusted_authentication,
        register_validation_auth,
    )
    from linen.server.skill_baseline_sources import (
        import_historical_run,
        register_historical_source,
        register_ledger_validation,
    )

    candidate = import_historical_run(
        root=root, project_id=project_id, source_ref=source_ref, origin=origin
    )
    if not candidate.eligible or not candidate.ledger_bytes or not candidate.metadata_sha256:
        return candidate

    outcome = validate_coverage_ledger_bytes(
        ledger_bytes=candidate.ledger_bytes, workspace=workspace
    )
    receipt = issue_ledger_validation_receipt(
        outcome=outcome,
        project_id=project_id,
        source_ref=source_ref,
        metadata_sha256=candidate.metadata_sha256,
        issued_by=issued_by,
        issued_at=issued_at,
    )
    candidate = replace(
        candidate,
        upstream_schema_validated=outcome.valid,
        validation_receipt=receipt,
        reason=(
            "the source was read and its ledger passed the pinned upstream validator"
            if outcome.valid
            else "the source was read, but its ledger is not valid upstream"
        ),
    )

    register_historical_source(conn, candidate)
    register_ledger_validation(
        conn,
        project_id=project_id,
        source_ref=source_ref,
        receipt=receipt,
    )
    envelope = issue_trusted_authentication(receipt=receipt, key_id=signing_key_id)
    if envelope is not None:
        register_validation_auth(
            conn,
            project_id=project_id,
            receipt=receipt,
            envelope=envelope,
        )
    return candidate


def attest_historical_source(
    *,
    conn: Any,
    project_id: str,
    source_ref: str,
    observed_at: str,
    scope: str = "audited_source_identity",
    repo_root: Path | str | None = None,
    commit: str | None = None,
    source_dir: Path | str | None = None,
    source_manifest: Path | str | None = None,
    frozen_root: Path | str | None = None,
    notes: str = "",
    signing_key_id: str | None = None,
) -> Any:
    """Verify one source and register the trusted attestation.

    This is the controlled entry point of CF-S2-B2-A.  It verifies the source
    itself, signs the resulting attestation with the key only the controlled
    flow holds, and lets the server record it - the server verifies the
    signature, it never makes one (D-058).

    The ``scope`` decides what the attestation is about (D-061):
    ``audit_artifact_bytes`` proves that the ledger and the run metadata are
    still the registered bytes, ``audited_source_identity`` proves which code
    the audit ran against.  The second needs the frozen source tree and the
    manifest that names it; without the registered manifest the identity of
    the audited code stays unknown and nothing is proven.

    A deployment without a configured key issues no attestation at all, and
    the source stays unverified.  That is the fail closed case.
    """

    from linen.server.baseline_proof_auth import issue_proof_auth
    from linen.server.baseline_proofs import (
        build_source_attestation,
        register_source_attestation,
    )

    attestation = build_source_attestation(
        conn=conn,
        project_id=project_id,
        source_ref=source_ref,
        observed_at=observed_at,
        scope=scope,
        repo_root=repo_root,
        commit=commit,
        source_dir=source_dir,
        source_manifest=source_manifest,
        frozen_root=frozen_root,
        notes=notes,
    )
    envelope = issue_proof_auth(
        proof_kind="source_attestation",
        proof_sha256=attestation.attestation_sha256,
        project_id=project_id,
        key_id=signing_key_id,
    )
    if envelope is None:
        return None
    register_source_attestation(
        conn=conn,
        project_id=project_id,
        attestation=attestation,
        envelope=envelope,
    )
    return attestation


def seal_historical_scope(
    *,
    conn: Any,
    project_id: str,
    run_id: str,
    manifest_ref: str,
    issuer: str,
    issued_at: str,
    signing_key_id: str | None = None,
) -> Any:
    """Seal one historical scope for one run - the controlled entry point.

    A seal is the only thing that may carry the weight of a negative
    conclusion, so it is signed by the controlled flow and verified by the
    server.  A deployment without a configured key seals nothing, and a
    complete manifest without a seal stays a manifest (D-052).
    """

    from linen.server.baseline_proof_auth import issue_proof_auth
    from linen.server.baseline_proofs import (
        build_lineage_seal,
        register_lineage_seal,
    )

    seal = build_lineage_seal(
        conn=conn,
        project_id=project_id,
        run_id=run_id,
        manifest_ref=manifest_ref,
        issuer=issuer,
        issued_at=issued_at,
    )
    envelope = issue_proof_auth(
        proof_kind="lineage_seal",
        proof_sha256=seal.seal_sha256,
        project_id=project_id,
        key_id=signing_key_id,
    )
    if envelope is None:
        return None
    register_lineage_seal(
        conn=conn, project_id=project_id, seal=seal, envelope=envelope
    )
    return seal
