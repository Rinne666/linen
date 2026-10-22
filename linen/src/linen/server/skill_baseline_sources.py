"""Immutable registration of historical baseline sources (CF-S2-B1).

A prior status is only worth storing when the history behind it can be found
again and checked.  This module is the storage half of that promise:

* a **controlled import** reads a historical run out of a declared root,
  refusing any path that escapes it, and records the content digest of every
  file it read;
* a **registration** is append-only: the reference body is stored, not just
  its digest, so a stored ``lookup_ref`` can always be resolved back to what
  it refers to;
* a **lineage manifest** declares the history scope a baseline may be derived
  from, and says whether that scope is closed;
* a **reference** is the digest of a structured body, and reading it re-verifies
  the digest instead of trusting the string (D-037).

What this module deliberately does *not* do is decide whether a historical run
is compatible with the current run.  The upstream skill has no such rule
either - its own compatibility wording is a single sentence in ``HUNTING.md``
and no upstream code ever reads a prior ledger - so the decision is recorded
as a declaration here, and the resolver of CF-S2-B2 is what applies it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from linen.contracts.artifact import ArtifactMetadata
from linen.contracts.baseline import (
    BaselineLineageManifest,
    BaselineManifestMember,
    BaselineSourceIdentity,
    BaselineSourceRecord,
    LedgerValidationReceipt,
    encode_reference,
    reference_digest,
)
from linen.contracts.common import cf_canonical_json, cf_payload_digest
# ``BaselineMaterializationFailed`` is re-exported here on purpose: it is the
# failure a caller of the baseline registry has to handle, and the registry
# is where that failure is raised.
from linen.server.baseline_materialization import (
    BASELINE_WORKSPACE_DIR,
    BaselineMaterializationFailed,
    materialization_key,
    open_materialization_directory,
)
from linen.server.baseline_validation_auth import (
    BaselineAuthRejected,
    trusted_validation_auth,
)
from linen.server.services import utcnow
from linen.server.store import register_artifact

#: The artifact kinds an imported historical source is registered under.
COVERAGE_LEDGER_ARTIFACT_KIND = "coverage-ledger"
COVERAGE_RUN_METADATA_ARTIFACT_KIND = "coverage-run-metadata"

#: The file names an imported historical run is expected to carry.
LEDGER_FILE_NAME = "coverage-ledger.json"
METADATA_FILE_NAME = "run-metadata.json"

#: The upstream file that validates a coverage ledger.
COVERAGE_VALIDATOR_FILE_NAME = "validate-coverage-ledger.cjs"

#: The directory the imported files are materialized under, inside the
#: project workspace, is ``baseline_materialization.BASELINE_WORKSPACE_DIR``.
#: It lives there because the materialization is what has to place files
#: under it, and that module refuses to do so without no-follow guarantees.

#: The vendored upstream snapshot, resolved from the installed package.
#:
#: The server resolves it on its own instead of importing the dispatcher
#: package: a server process must never depend on the code that drives
#: workers.
_VENDORED_SNAPSHOT_DIR = (
    Path(__file__).resolve().parents[1] / "third_party" / "cloudflare_security_audit_skill"
)

#: The upstream unit statuses that are terminal.
_UPSTREAM_TERMINAL_STATUSES = frozenset(
    {"covered", "candidate", "blocked", "deferred", "out_of_scope", "not_applicable"}
)


class BaselineSourceRejected(ValueError):
    """The source is not eligible to be registered as trusted history."""


class BaselineReferenceUnverifiable(LookupError):
    """The reference cannot be resolved to a body whose digest matches."""


class BaselineImportFailed(RuntimeError):
    """The import could not read the declared source."""


@dataclass(frozen=True)
class HistoricalSourceCandidate:
    """What a controlled import found in one historical run directory.

    ``eligible`` is False when the source cannot be trusted yet - a missing
    metadata file, a source identity that cannot be verified.  An ineligible
    candidate is still reported, because dropping it silently and then
    declaring the history complete is exactly what must not happen (D-036).

    ``eligible`` only says that the run was **readable** and that its source
    identity was recorded.  It is *not* a statement about upstream validity: a
    ledger can be perfectly readable and violate every upstream rule at the
    same time.  Upstream validity comes from a controlled validation receipt
    (``validation_receipt``), and the source identity verification is a
    separate, later act (CF-S2-B2).  The three must never be merged (D-043).
    """

    project_id: str
    source_ref: str
    eligible: bool
    reason: str = ""
    ledger_sha256: str | None = None
    metadata_sha256: str | None = None
    identity: BaselineSourceIdentity | None = None
    unit_count: int = 0
    prior_status_counts: dict[str, int] = field(default_factory=dict)
    ledger_path: str = ""
    metadata_path: str = ""
    ledger_bytes: bytes = b""
    metadata_bytes: bytes = b""
    upstream_schema_validated: bool = False
    validation_receipt: LedgerValidationReceipt | None = None


# --- the controlled import ---------------------------------------------------


def _read_under_root(root: Path, relative: str) -> bytes:
    """Read a file under the declared import root.

    The root is operator-declared, but the path inside it is not: an import
    must never be able to reach a file outside the root, and it must never
    follow a symlink out of it.
    """

    base = root.expanduser().resolve()
    if not base.is_dir():
        raise BaselineImportFailed(f"the import root {base} is not a directory")

    parts = [part for part in relative.replace("\\", "/").split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        raise BaselineImportFailed(
            f"the import path {relative!r} is not a confined relative path"
        )

    cursor = base
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise BaselineImportFailed(
                f"the import path {relative!r} contains a symlink"
            )
    try:
        resolved = cursor.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise BaselineImportFailed(
            f"the import source {relative!r} cannot be read"
        ) from exc
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise BaselineImportFailed(
            f"the import path {relative!r} escapes the import root"
        ) from exc
    if not resolved.is_file():
        raise BaselineImportFailed(
            f"the import source {relative!r} is not a regular file"
        )
    return resolved.read_bytes()


def _ledger_units(payload: Any) -> list[Mapping[str, Any]]:
    """The unit list of an upstream coverage ledger document.

    This helper only proves that the document is **readable** and carries
    units.  It does *not* prove that the document is a valid upstream ledger:
    the upstream contract is far stricter (a top-level array, canonical
    identities derived from ``canonical_refs``, the full required field set,
    the upstream status vocabularies), and only the pinned upstream validator
    decides that.  ``_ledger_units()`` succeeding is therefore not upstream
    validity, and a candidate built from it does not carry the upstream-valid
    qualification (D-043).
    """

    if isinstance(payload, list):
        units = payload
    elif isinstance(payload, Mapping):
        units = payload.get("units")
    else:
        units = None
    if not isinstance(units, list):
        raise BaselineImportFailed(
            "the coverage ledger is not an upstream ledger document"
        )
    for unit in units:
        if not isinstance(unit, Mapping) or not unit.get("coverage_id"):
            raise BaselineImportFailed(
                "the coverage ledger carries a unit without a coverage id"
            )
    return units


def _identity_from_metadata(metadata: Mapping[str, Any], *, origin: str) -> BaselineSourceIdentity:
    """The source identity of a historical run, as far as it can be known.

    A ``source_ref`` is never promoted to a verified identity here: the
    importer cannot check that a commit exists, and a regex that matched is
    not a verification.  What it can do is keep the raw text and record the
    commit name it found, so a later, explicit verification can use it.
    """

    ref = metadata.get("source_ref")
    if isinstance(ref, Mapping):
        commit = str(ref.get("commit") or "").strip()
        raw = commit or cf_canonical_json(dict(ref))
    elif isinstance(ref, str):
        raw = ref.strip()
    else:
        raw = ""
    if not raw:
        raise BaselineImportFailed(
            "the run metadata carries no source_ref, so the audited source "
            "identity is unknown"
        )
    return BaselineSourceIdentity.unverified_from_ref(origin=origin, raw=raw)


def import_historical_run(
    *,
    root: Path,
    project_id: str,
    source_ref: str,
    origin: str,
) -> HistoricalSourceCandidate:
    """Read one historical run out of a declared import root.

    The import never raises for a source that is merely *untrusted*: it
    returns a candidate that says why.  Only a source that cannot be read at
    all is an error.
    """

    if not project_id.strip():
        raise BaselineImportFailed("the project id must not be empty")
    if not source_ref.strip():
        raise BaselineImportFailed("the source ref must not be empty")

    ledger_relative = f"{source_ref}/{LEDGER_FILE_NAME}"
    metadata_relative = f"{source_ref}/{METADATA_FILE_NAME}"

    ledger_bytes = _read_under_root(root, ledger_relative)
    ledger_sha = hashlib.sha256(ledger_bytes).hexdigest()

    try:
        payload = json.loads(ledger_bytes.decode("utf-8"))
        units = _ledger_units(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineImportFailed(
            f"the coverage ledger of {source_ref!r} is not readable JSON"
        ) from exc

    counts: dict[str, int] = {}
    for unit in units:
        status = str(unit.get("prior_status") or "none")
        counts[status] = counts.get(status, 0) + 1

    candidate = HistoricalSourceCandidate(
        project_id=project_id,
        source_ref=source_ref,
        eligible=False,
        ledger_sha256=ledger_sha,
        unit_count=len(units),
        prior_status_counts=counts,
        ledger_bytes=ledger_bytes,
    )

    try:
        metadata_bytes = _read_under_root(root, metadata_relative)
    except BaselineImportFailed as exc:
        return HistoricalSourceCandidate(
            **{
                **candidate.__dict__,
                "reason": (
                    "the run metadata is missing, so the audited source identity "
                    "is unknown"
                ),
                "ledger_path": ledger_relative,
            }
        )

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return HistoricalSourceCandidate(
            **{
                **candidate.__dict__,
                "reason": "the run metadata is not readable JSON",
                "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                "ledger_path": ledger_relative,
                "metadata_path": metadata_relative,
                "metadata_bytes": metadata_bytes,
            }
        )
    if not isinstance(metadata, Mapping):
        return HistoricalSourceCandidate(
            **{
                **candidate.__dict__,
                "reason": "the run metadata is not an object",
                "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                "ledger_path": ledger_relative,
                "metadata_path": metadata_relative,
                "metadata_bytes": metadata_bytes,
            }
        )

    try:
        identity = _identity_from_metadata(metadata, origin=origin)
    except BaselineImportFailed as exc:
        return HistoricalSourceCandidate(
            **{
                **candidate.__dict__,
                "reason": str(exc),
                "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                "ledger_path": ledger_relative,
                "metadata_path": metadata_relative,
                "metadata_bytes": metadata_bytes,
            }
        )

    return HistoricalSourceCandidate(
        **{
            **candidate.__dict__,
            "eligible": True,
            "reason": "the source was read and its identity was recorded",
            "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            "identity": identity,
            "ledger_path": ledger_relative,
            "metadata_path": metadata_relative,
            "metadata_bytes": metadata_bytes,
        }
    )


# --- the immutable registration ---------------------------------------------


def _baseline_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source_id": int(row["source_id"]),
        "record_kind": str(row["record_kind"]),
        "record_ref": str(row["record_ref"]),
        "payload": json.loads(row["payload_json"]),
        "payload_sha256": str(row["payload_sha256"]),
        "lookup_ref": row["lookup_ref"],
        "created_at": str(row["created_at"]),
    }


def list_baseline_sources(
    conn: sqlite3.Connection, project_id: str, *, record_kind: str | None = None
) -> list[dict[str, Any]]:
    """Every registered source of a project, in registration order."""

    sql = (
        "SELECT source_id, record_kind, record_ref, payload_json, payload_sha256, "
        "lookup_ref, created_at FROM coverage_baseline_sources WHERE project_id = ?"
    )
    params: list[Any] = [project_id]
    if record_kind is not None:
        sql += " AND record_kind = ?"
        params.append(record_kind)
    sql += " ORDER BY source_id"
    return [_baseline_row_to_dict(row) for row in conn.execute(sql, params)]


def register_historical_source(
    conn: sqlite3.Connection, candidate: HistoricalSourceCandidate
) -> BaselineSourceRecord:
    """Register one historical source, append-only.

    Registering the same source twice is idempotent; registering the same
    source with different content is a conflict, never an overwrite.
    """

    if not candidate.eligible:
        raise BaselineSourceRejected(
            candidate.reason or "the historical source is not eligible"
        )
    if candidate.identity is None:
        raise BaselineSourceRejected(
            "the historical source carries no source identity"
        )
    if not candidate.ledger_sha256 or not candidate.metadata_sha256:
        raise BaselineSourceRejected(
            "the historical source carries no content digest to register"
        )
    if candidate.upstream_schema_validated and candidate.validation_receipt is None:
        raise BaselineSourceRejected(
            "the historical source claims an upstream validation without a "
            "receipt to back it"
        )
    if candidate.validation_receipt is not None:
        receipt = candidate.validation_receipt
        if not receipt.sealed():
            raise BaselineSourceRejected(
                "the validation receipt does not match its own digest"
            )
        if receipt.ledger_sha256 != candidate.ledger_sha256:
            raise BaselineSourceRejected(
                "the validation receipt is about different ledger bytes"
            )

    record = BaselineSourceRecord(
        project_id=candidate.project_id,
        source_ref=candidate.source_ref,
        ledger_sha256=candidate.ledger_sha256,
        metadata_sha256=candidate.metadata_sha256,
        source_identity=candidate.identity,
        unit_count=candidate.unit_count,
        prior_status_counts=dict(candidate.prior_status_counts),
        ledger_path=candidate.ledger_path,
        metadata_path=candidate.metadata_path,
    )
    body = record.model_dump(mode="json")
    digest = cf_payload_digest(body)
    reference = encode_reference(body)

    existing = conn.execute(
        "SELECT payload_sha256 FROM coverage_baseline_sources WHERE project_id = ? "
        "AND record_kind = 'historical_source' AND record_ref = ?",
        (record.project_id, record.source_ref),
    ).fetchone()
    if existing is not None:
        if str(existing["payload_sha256"]) != digest:
            raise BaselineSourceRejected(
                f"the historical source {record.source_ref!r} is already "
                "registered with different content"
            )
        return record

    conn.execute(
        "INSERT INTO coverage_baseline_sources (project_id, record_kind, record_ref, "
        "payload_json, payload_sha256, lookup_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            record.project_id,
            "historical_source",
            record.source_ref,
            cf_canonical_json(body),
            digest,
            reference,
            utcnow(),
        ),
    )
    return record


def pinned_upstream_commit() -> str:
    """The upstream commit the vendored validator snapshot is pinned to."""

    return (_VENDORED_SNAPSHOT_DIR / "UPSTREAM_COMMIT").read_text(encoding="utf-8").strip()


def pinned_validator_sha256() -> str:
    """The digest of the pinned upstream coverage validator, as it is now.

    A receipt says which validator produced it.  The server does not take
    that sentence for evidence: it reads the pinned validator out of its own
    snapshot and compares the digest.  A receipt that merely *claims* a
    validator - with a digest that fits its own body perfectly - does not
    pass this check (CR-T08).
    """

    path = _VENDORED_SNAPSHOT_DIR / COVERAGE_VALIDATOR_FILE_NAME
    return hashlib.sha256(path.read_bytes()).hexdigest()


def register_ledger_validation(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    source_ref: str,
    receipt: LedgerValidationReceipt,
) -> str:
    """Register one controlled validation receipt, append-only.

    The receipt is the server's copy of a decision that was made offline by
    the pinned upstream validator.  Registering the same receipt twice is
    idempotent.  A *different* receipt for the same source is not a conflict:
    a source may be validated again when its ledger changes - and then the
    older receipt stops being applicable, because it was made for different
    bytes.  The older receipt stays, so the history of the validations
    remains readable.
    """

    if receipt.project_id != project_id or receipt.source_ref != source_ref:
        raise BaselineSourceRejected(
            "the validation receipt is about another source"
        )
    if not receipt.sealed():
        raise BaselineSourceRejected(
            "the validation receipt does not match its own digest"
        )
    try:
        expected_commit = pinned_upstream_commit()
        expected_validator = pinned_validator_sha256()
    except OSError as exc:
        raise BaselineSourceRejected(
            "the pinned upstream coverage validator is not available"
        ) from exc
    if receipt.validator.upstream_commit != expected_commit:
        raise BaselineSourceRejected(
            "the validation receipt was produced by a different upstream commit"
        )
    if receipt.validator.validator_sha256 != expected_validator:
        raise BaselineSourceRejected(
            "the validation receipt was produced by a different validator build"
        )

    digest = receipt.receipt_sha256
    existing = conn.execute(
        "SELECT payload_sha256 FROM coverage_ledger_validations "
        "WHERE project_id = ? AND source_ref = ? AND payload_sha256 = ?",
        (project_id, source_ref, digest),
    ).fetchone()
    if existing is not None:
        return digest

    conn.execute(
        "INSERT INTO coverage_ledger_validations (project_id, source_ref, "
        "ledger_sha256, metadata_sha256, payload_json, payload_sha256, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            project_id,
            source_ref,
            receipt.ledger_sha256,
            receipt.metadata_sha256,
            cf_canonical_json(receipt.model_dump(mode="json")),
            digest,
            utcnow(),
        ),
    )
    return digest


def verify_ledger_validation(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    source_ref: str,
    ledger_bytes: bytes,
    presented_receipt: LedgerValidationReceipt | Mapping[str, Any] | None = None,
) -> LedgerValidationReceipt:
    """Verify that one ledger document carries a registered upstream validation.

    The server does not run the validator: it verifies the receipt that the
    controlled import flow registered.  That is the whole point - a receipt
    that was merely handed in is not evidence, so a presented receipt has to
    be the registered one, byte for byte.

    The checks are:

    1. a validation is registered for this project and source;
    2. every registered receipt still matches its own digest;
    3. a presented receipt is one of the registered ones;
    4. the ledger bytes still hash to the digest the receipt was made for;
    5. the receipt is about the registered historical source - the ledger it
       was made for is the ledger the source was registered with (CR-T09);
    6. the receipt was produced by the pinned upstream validator;
    7. the validator that produced it is the pinned validator, build for
       build - the receipt's own digest is not evidence for that (CR-T08);
    8. the validator accepted the document;
    9. the receipt carries an authentication envelope this deployment can
       verify - a receipt that only matches its own digest proves nothing
       about who issued it (D-058).
    """

    rows = conn.execute(
        "SELECT payload_json FROM coverage_ledger_validations "
        "WHERE project_id = ? AND source_ref = ? ORDER BY validation_id",
        (project_id, source_ref),
    ).fetchall()
    if not rows:
        raise BaselineReferenceUnverifiable(
            f"no controlled validation is registered for the source {source_ref!r}"
        )

    registered: list[LedgerValidationReceipt] = []
    for row in rows:
        receipt = LedgerValidationReceipt.model_validate(json.loads(row["payload_json"]))
        if not receipt.sealed():
            raise BaselineReferenceUnverifiable(
                "the stored validation receipt does not match its digest"
            )
        registered.append(receipt)

    if presented_receipt is not None:
        presented = (
            presented_receipt
            if isinstance(presented_receipt, LedgerValidationReceipt)
            else LedgerValidationReceipt.model_validate(presented_receipt)
        )
        if not any(
            presented.model_dump(mode="json") == candidate.model_dump(mode="json")
            for candidate in registered
        ):
            raise BaselineReferenceUnverifiable(
                "the presented validation receipt is not a registered one"
            )

    digest = hashlib.sha256(ledger_bytes).hexdigest()
    source_row = conn.execute(
        "SELECT payload_json FROM coverage_baseline_sources WHERE project_id = ? "
        "AND record_kind = 'historical_source' AND record_ref = ?",
        (project_id, source_ref),
    ).fetchone()
    if source_row is None:
        raise BaselineReferenceUnverifiable(
            f"the historical source {source_ref!r} is not registered"
        )
    source = json.loads(source_row["payload_json"])

    try:
        expected_commit = pinned_upstream_commit()
        expected_validator = pinned_validator_sha256()
    except OSError as exc:
        raise BaselineReferenceUnverifiable(
            "the pinned upstream validator snapshot is not available"
        ) from exc

    applicable: list[LedgerValidationReceipt] = []
    for receipt in registered:
        if receipt.ledger_sha256 != digest:
            continue
        if receipt.metadata_sha256 != str(source.get("metadata_sha256")):
            continue
        if receipt.ledger_sha256 != str(source.get("ledger_sha256")):
            # The receipt is about bytes that are not the registered source's
            # ledger.  A source may have been validated again after its
            # ledger changed, and then the older receipt stops applying -
            # but it must not pass as the validation of this source (CR-T09).
            continue
        if receipt.validator.upstream_commit != expected_commit:
            raise BaselineReferenceUnverifiable(
                "the validation receipt was produced by a different upstream commit"
            )
        if receipt.validator.validator_sha256 != expected_validator:
            raise BaselineReferenceUnverifiable(
                "the validation receipt was produced by a different validator build"
            )
        if not receipt.result.valid:
            continue
        applicable.append(receipt)

    if not applicable:
        raise BaselineReferenceUnverifiable(
            f"the ledger of {source_ref!r} has no registered upstream validation"
        )

    # A receipt that matches is still not trustworthy: it has to carry an
    # authentication envelope that this deployment can verify (D-058).  A
    # receipt without one stays readable, but it does not pass here.
    for receipt in applicable:
        try:
            trusted_validation_auth(conn, project_id=project_id, receipt=receipt)
        except BaselineAuthRejected:
            continue
        return receipt

    raise BaselineReferenceUnverifiable(
        f"the validation of {source_ref!r} carries no trusted issuance proof"
    )


def registered_ledger_validation(
    conn: sqlite3.Connection, *, project_id: str, receipt_sha256: str
) -> LedgerValidationReceipt:
    """The stored validation receipt, whether or not it is trusted.

    A receipt that was registered without an authentication envelope - one
    from before the trusted issuance existed, or one that was filed by an
    unauthorised path - stays readable.  What it may not do is confer trust:
    that is decided by :func:`verify_ledger_validation`.
    """

    row = conn.execute(
        "SELECT payload_json FROM coverage_ledger_validations "
        "WHERE project_id = ? AND payload_sha256 = ?",
        (project_id, receipt_sha256),
    ).fetchone()
    if row is None:
        raise BaselineReferenceUnverifiable(
            f"no validation receipt {receipt_sha256!r} is registered for the project"
        )
    return LedgerValidationReceipt.model_validate(json.loads(row["payload_json"]))


def materialize_baseline_artifacts(
    conn: sqlite3.Connection,
    *,
    candidate: HistoricalSourceCandidate,
    workspace_root: Path,
) -> tuple[str, str]:
    """Copy the imported files into the project workspace and register them.

    The imported bytes are what the digests were computed from, so the copy
    is verified against them before it is registered.  The artifacts are
    ordinary workspace artifacts and carry the same read-time digest check
    every other artifact does.

    The materialization is safe and repeatable (CF-S2-B1 P1-B):

    * the directory is named after the full SHA-256 of the source reference,
      so two references cannot be made to share a directory by rewriting
      path characters (D-053);
    * every file is created relative to an opened directory, without
      following a symbolic link, so a component that is a link is refused
      rather than used;
    * a file that is already there is reused only when its digest is the
      expected one, and a repeated materialization therefore leaves the
      bytes and the artifact rows exactly as they were;
    * a materialization that fails half way removes the files it created,
      so no half written file is left behind as if it were an artifact.
    """

    key = materialization_key(candidate.source_ref)

    with open_materialization_directory(
        workspace_root=workspace_root,
        project_id=candidate.project_id,
        source_ref=candidate.source_ref,
    ) as directory:
        pending: list[tuple[str, str, str, int]] = []
        try:
            for kind, name, payload, digest in (
                (
                    COVERAGE_LEDGER_ARTIFACT_KIND,
                    LEDGER_FILE_NAME,
                    candidate.ledger_bytes,
                    candidate.ledger_sha256,
                ),
                (
                    COVERAGE_RUN_METADATA_ARTIFACT_KIND,
                    METADATA_FILE_NAME,
                    candidate.metadata_bytes,
                    candidate.metadata_sha256,
                ),
            ):
                if not payload or not digest:
                    continue
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise BaselineSourceRejected(
                        f"the imported {name} does not match its recorded digest"
                    )
                directory.write(name, payload, digest)
                pending.append((kind, name, digest, len(payload)))
        except BaseException:
            directory.discard_created()
            raise

        artifact_ids: list[str] = []
        # The artifact registrations of one materialization are all or
        # nothing: a failure in the middle must not leave the first artifact
        # behind while the second one is missing (PM v2.6, R-A).  The files
        # are still not part of the same transaction - a file that was
        # written stays written and stays verifiable, and the retry reuses
        # it.
        conn.execute("SAVEPOINT baseline_artifact_registration")
        try:
            for kind, name, digest, byte_size in pending:
                artifact_id = f"{key}:{name}"
                workspace_path = f"{BASELINE_WORKSPACE_DIR}/{key}/{name}"
                register_artifact(
                    conn,
                    ArtifactMetadata(
                        artifact_id=artifact_id,
                        project_id=candidate.project_id,
                        kind=kind,
                        workspace_path=workspace_path,
                        sha256=digest,
                        media_type="application/json",
                        byte_size=byte_size,
                        producer_run_id=None,
                    ),
                )
                artifact_ids.append(artifact_id)
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT baseline_artifact_registration")
            conn.execute("RELEASE SAVEPOINT baseline_artifact_registration")
            raise
        conn.execute("RELEASE SAVEPOINT baseline_artifact_registration")
    return tuple(artifact_ids)  # type: ignore[return-value]


def seal_lineage_manifest(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    members: Sequence[BaselineManifestMember],
    unprocessed: Iterable[str] = (),
    scope_kind: str = "declared_predecessor_lineage",
    notes: str = "",
) -> BaselineLineageManifest:
    """Freeze the history scope a baseline may be derived from.

    Every member has to be registered already: a manifest that names a
    source nobody imported is a scope that cannot be searched, and a scope
    that cannot be searched can never support a negative conclusion.

    Every member has to name the digests of the artifacts that were actually
    registered, too.  A manifest that carries a digest the registered source
    does not have would describe a history that was never imported, and a
    scope that describes something else cannot be searched either (D-044).
    """

    registered: dict[str, tuple[str, str]] = {}
    for row in conn.execute(
        "SELECT record_ref, payload_json FROM coverage_baseline_sources "
        "WHERE project_id = ? AND record_kind = 'historical_source'",
        (project_id,),
    ):
        payload = json.loads(row["payload_json"])
        registered[str(row["record_ref"])] = (
            str(payload.get("ledger_sha256", "")),
            str(payload.get("metadata_sha256", "")),
        )
    for member in members:
        if member.source_ref not in registered:
            raise BaselineSourceRejected(
                f"the manifest member {member.source_ref!r} is not registered"
            )
        ledger_sha256, metadata_sha256 = registered[member.source_ref]
        if member.ledger_sha256 != ledger_sha256:
            raise BaselineSourceRejected(
                f"the manifest member {member.source_ref!r} claims a ledger "
                "digest that the registered source does not have"
            )
        if member.metadata_sha256 != metadata_sha256:
            raise BaselineSourceRejected(
                f"the manifest member {member.source_ref!r} claims a metadata "
                "digest that the registered source does not have"
            )

    pending = [str(item) for item in unprocessed if str(item).strip()]
    manifest = BaselineLineageManifest(
        project_id=project_id,
        scope_kind=scope_kind,  # type: ignore[arg-type]
        members=list(members),
        unprocessed=pending,
        completeness="complete" if not pending else "incomplete",
        notes=notes,
    )
    body = manifest.body()
    digest = cf_payload_digest(body)

    existing = conn.execute(
        "SELECT payload_sha256 FROM coverage_baseline_sources WHERE project_id = ? "
        "AND record_kind = 'lineage_manifest' AND record_ref = ?",
        (project_id, digest),
    ).fetchone()
    if existing is not None:
        if str(existing["payload_sha256"]) != digest:
            raise BaselineSourceRejected(
                "the lineage manifest digest is already registered with "
                "different content"
            )
        return manifest

    conn.execute(
        "INSERT INTO coverage_baseline_sources (project_id, record_kind, record_ref, "
        "payload_json, payload_sha256, lookup_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            project_id,
            "lineage_manifest",
            digest,
            cf_canonical_json(body),
            digest,
            manifest.reference(),
            utcnow(),
        ),
    )
    return manifest


def read_lineage_manifest(
    conn: sqlite3.Connection, project_id: str, record_ref: str
) -> BaselineLineageManifest:
    """The manifest registered under a digest."""

    row = conn.execute(
        "SELECT payload_json, payload_sha256 FROM coverage_baseline_sources "
        "WHERE project_id = ? AND record_kind = 'lineage_manifest' AND record_ref = ?",
        (project_id, record_ref),
    ).fetchone()
    if row is None:
        raise BaselineReferenceUnverifiable(
            f"no lineage manifest {record_ref!r} is registered for the project"
        )
    body = json.loads(row["payload_json"])
    if cf_payload_digest(body) != str(row["payload_sha256"]):
        raise BaselineReferenceUnverifiable(
            "the stored lineage manifest does not match its digest"
        )
    return BaselineLineageManifest.model_validate(body)


def read_reference(
    conn: sqlite3.Connection, *, project_id: str, reference: str
) -> dict[str, Any]:
    """Resolve a reference back to the body it names, and re-verify it.

    A reference whose body cannot be found, or whose body no longer matches
    its digest, is not evidence of anything: it is an unverifiable
    reference.

    The lookup is **project scoped**.  A reference is the digest of a body,
    and two projects may well have registered the same body - the digest
    says what the body is, not who is allowed to read it.  Without the
    project in the query, a reference that belongs to one project could be
    resolved by another, and the history behind a baseline would not be the
    history of the project the baseline belongs to (CR-T06).
    """

    digest = reference_digest(reference)
    row = conn.execute(
        "SELECT payload_json, payload_sha256 FROM coverage_baseline_sources "
        "WHERE project_id = ? AND lookup_ref = ?",
        (project_id, reference),
    ).fetchone()
    if row is None:
        raise BaselineReferenceUnverifiable(
            "the reference has no stored body, so the history it names cannot "
            "be verified"
        )
    body = json.loads(row["payload_json"])
    if cf_payload_digest(body) != digest:
        raise BaselineReferenceUnverifiable(
            "the stored body does not match the digest of the reference"
        )
    return body


def referenced_manifest(
    conn: sqlite3.Connection, *, project_id: str, reference: str
) -> BaselineLineageManifest:
    """The manifest a reference names.

    The manifest is read through the same project scoped lookup, so this
    function cannot be used to reach a manifest of another project either.
    """

    body = read_reference(conn, project_id=project_id, reference=reference)
    return BaselineLineageManifest.model_validate(body)
