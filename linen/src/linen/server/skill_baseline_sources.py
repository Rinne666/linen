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
import os
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
    encode_reference,
    reference_digest,
)
from linen.contracts.common import cf_canonical_json, cf_payload_digest
from linen.server.services import utcnow
from linen.server.store import register_artifact

#: The artifact kinds an imported historical source is registered under.
COVERAGE_LEDGER_ARTIFACT_KIND = "coverage-ledger"
COVERAGE_RUN_METADATA_ARTIFACT_KIND = "coverage-run-metadata"

#: The file names an imported historical run is expected to carry.
LEDGER_FILE_NAME = "coverage-ledger.json"
METADATA_FILE_NAME = "run-metadata.json"

#: The directory the imported files are materialized under, inside the
#: project workspace.
BASELINE_WORKSPACE_DIR = "baseline"

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
    """The unit list of an upstream coverage ledger document."""

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
    """

    project_dir = workspace_root / candidate.project_id
    safe_ref = candidate.source_ref.replace("\\", "/").replace("/", "__")
    target_dir = project_dir / BASELINE_WORKSPACE_DIR / safe_ref
    target_dir.mkdir(parents=True, exist_ok=True)

    artifact_ids: list[str] = []
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
        target = target_dir / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o644)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        artifact_id = f"{safe_ref}:{name}"
        workspace_path = f"{BASELINE_WORKSPACE_DIR}/{safe_ref}/{name}"
        register_artifact(
            conn,
            ArtifactMetadata(
                artifact_id=artifact_id,
                project_id=candidate.project_id,
                kind=kind,
                workspace_path=workspace_path,
                sha256=digest,
                media_type="application/json",
                byte_size=len(payload),
                producer_run_id=None,
            ),
        )
        artifact_ids.append(artifact_id)
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
    """

    registered = {
        str(row["record_ref"])
        for row in conn.execute(
            "SELECT record_ref FROM coverage_baseline_sources WHERE project_id = ? "
            "AND record_kind = 'historical_source'",
            (project_id,),
        )
    }
    for member in members:
        if member.source_ref not in registered:
            raise BaselineSourceRejected(
                f"the manifest member {member.source_ref!r} is not registered"
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


def read_reference(conn: sqlite3.Connection, reference: str) -> dict[str, Any]:
    """Resolve a reference back to the body it names, and re-verify it.

    A reference whose body cannot be found, or whose body no longer matches
    its digest, is not evidence of anything: it is an unverifiable
    reference.
    """

    digest = reference_digest(reference)
    row = conn.execute(
        "SELECT payload_json, payload_sha256 FROM coverage_baseline_sources "
        "WHERE lookup_ref = ?",
        (reference,),
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
    conn: sqlite3.Connection, reference: str
) -> BaselineLineageManifest:
    """The manifest a reference names."""

    body = read_reference(conn, reference)
    return BaselineLineageManifest.model_validate(body)
