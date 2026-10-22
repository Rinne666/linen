"""The trusted proofs about history (CF-S2-B2-A).

Two append-only proofs live in this module:

* a **source identity attestation** says that one registered historical source
  has a verified identity - a git commit that exists in a named repository with
  a clean worktree, or a frozen snapshot whose bytes still are the registered
  ones;
* a **lineage seal** says that one historical scope was closed and sealed for
  one run, and it binds every member of that scope to the attestation that
  proved the member's identity.

The split matters (D-043, D-045, D-052, D-054):

* a manifest that is structurally complete only says that a scope *looks*
  closed.  It is not a seal, it has no issuer and no signature, and it may
  never carry the weight of a negative conclusion;
* an attestation says what a source *was*.  It is not a confirmation: no
  attestation may make a finding of the current run confirmed (D-039);
* the two proofs share the immutable proof infrastructure - the canonical
  JSON, the payload digest, the append-only tables, the HMAC envelopes - but
  never share a table.

Every proof is *built* from an observation the server made itself and *signed*
by the controlled offline flow.  The server verifies the signature; it never
mints one.  A deployment without a configured key produces no proof at all,
because a proof nobody signed proves nothing.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from linen.contracts.baseline import (
    BaselineSourceIdentity,
    LineageSeal,
    LineageSealMember,
    ProofAuthentication,
    SourceIdentityAttestation,
    SourceIdentityVerification,
    encode_reference,
)
from linen.contracts.common import cf_canonical_json, cf_payload_digest

from .baseline_proof_auth import verify_proof_auth
from .baseline_validation_auth import configured_validation_keys
from .services import utcnow
from .skill_baseline_sources import referenced_manifest
from .source_identity import (
    SourceIdentityVerificationFailed,
    read_frozen_source_manifest,
    repository_identity,
    verify_audit_artifact_bytes,
    verify_frozen_source_manifest,
    verify_git_source_identity,
    verify_git_source_snapshot,
)


class BaselineProofRejected(ValueError):
    """The proof is not acceptable."""


@dataclass(frozen=True)
class SourceAttestationStatus:
    """What is known about the identity of one historical source.

    ``verified`` means exactly one attestation exists and it carries a valid
    mac.  ``conflict`` means the source carries contradictory attestations -
    both are kept, because an append-only registry may not forget, and the
    resolver reports the conflict instead of picking the newest one (D-045).
    """

    source_ref: str
    state: str
    attestations: tuple[SourceIdentityAttestation, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class LineageSealStatus:
    """What is known about the sealed scope of one run.

    ``trusted_negative`` is the answer to "may this run say that there was
    nothing to find".  It requires a seal that verifies *and* a scope that
    still verifies member by member - a complete manifest without a seal is
    not a negative conclusion (D-052).
    """

    run_id: str
    sealed: bool
    trusted_negative: bool
    seal: LineageSeal | None = None
    reason: str = ""


def _verification(observation: Any) -> Any:
    """Run one verification and report its failure as a proof rejection.

    The verifications themselves raise their own, more specific errors.  The
    caller of this module should not have to know which verification failed to
    learn that the proof cannot be built, so the failure is reported as one
    rejection and the original error is kept as its cause.
    """

    try:
        return observation()
    except SourceIdentityVerificationFailed as exc:
        raise BaselineProofRejected(str(exc)) from exc


def _registered_source(
    conn: sqlite3.Connection, *, project_id: str, source_ref: str
) -> dict[str, Any]:
    """The registered historical source, re-checked against its digest."""

    row = conn.execute(
        "SELECT payload_json, payload_sha256 FROM coverage_baseline_sources "
        "WHERE project_id = ? AND record_kind = 'historical_source' AND record_ref = ?",
        (project_id, source_ref),
    ).fetchone()
    if row is None:
        raise BaselineProofRejected(
            f"no historical source {source_ref!r} is registered for the project"
        )
    payload = json.loads(row["payload_json"])
    if cf_payload_digest(payload) != str(row["payload_sha256"]):
        raise BaselineProofRejected(
            "the registered source does not match the digest it was stored with"
        )
    return payload


def _run_belongs_to_project(
    conn: sqlite3.Connection, *, project_id: str, run_id: str
) -> bool:
    row = conn.execute(
        "SELECT 1 FROM runs WHERE run_id = ? AND project_id = ? LIMIT 1",
        (run_id, project_id),
    ).fetchone()
    return row is not None


def build_source_attestation(
    *,
    conn: sqlite3.Connection,
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
) -> SourceIdentityAttestation:
    """Verify one source and describe what was observed.

    Two scopes, and they are not interchangeable (D-061):

    ``audit_artifact_bytes``
        re-reads the coverage ledger and the run metadata and proves that they
        are still the registered bytes.  This is *not* a source identity: the
        ledger is the result of the audit, not its input.

    ``audited_source_identity``
        proves which code the audit ran against.  It needs the **frozen source
        manifest** of the historical run - the registered list of the audited
        files and their digests - and the source tree it names.  Without that
        manifest the identity of the audited code is unknown, and an unknown
        identity is not a verified one (D-060).

    The verification is done here, by the server, on the machine that holds
    the repository - never by the caller.  A caller may say *which* repository
    and *which* commit it believes the snapshot came from, but it cannot say
    that the answer is "verified".
    """

    source = _registered_source(conn, project_id=project_id, source_ref=source_ref)
    identity = source.get("source_identity")
    identity = identity if isinstance(identity, dict) else {}
    origin = str(identity.get("origin") or "").strip()

    if scope == "audit_artifact_bytes":
        return _build_artifact_attestation(
            source=source,
            project_id=project_id,
            source_ref=source_ref,
            observed_at=observed_at,
            frozen_root=frozen_root,
            notes=notes,
        )

    if scope != "audited_source_identity":
        raise BaselineProofRejected(f"unknown proof scope {scope!r}")

    manifest_digest = str(source.get("source_manifest_sha256") or "")
    if not manifest_digest:
        raise BaselineProofRejected(
            "the registered source carries no frozen source manifest, so the "
            "identity of the audited code cannot be proven"
        )
    if source_dir is None or source_manifest is None:
        raise BaselineProofRejected(
            "an audited source identity needs the frozen source tree and the "
            "manifest that names it"
        )

    manifest = _verification(
        lambda: read_frozen_source_manifest(Path(source_manifest))
    )
    if manifest.digest() != manifest_digest:
        raise BaselineProofRejected(
            "the supplied source manifest is not the one that was registered "
            "with the historical source"
        )
    _verification(
        lambda: verify_frozen_source_manifest(
            manifest=manifest, source_dir=Path(source_dir)
        )
    )

    if repo_root is not None or commit is not None:
        if not commit:
            raise BaselineProofRejected(
                "a git attestation needs the commit it claims"
            )
        recorded = str(identity.get("revision") or "").strip().lower()
        if not recorded:
            raise BaselineProofRejected(
                "the registered source records no commit, so a git attestation "
                "cannot be matched against the frozen snapshot"
            )
        if recorded != commit.strip().lower():
            raise BaselineProofRejected(
                "the commit does not match the frozen snapshot of the source"
            )
        observed = _verification(
            lambda: verify_git_source_identity(
                repo_root=Path(repo_root), commit=commit
            )
        )
        # The repository identity has to be *nameable* on both sides: an
        # unknown or unrecognisable remote fails closed instead of passing
        # (R03), and the host is part of the identity (R04).
        registered_host, registered_owner = repository_identity(origin)
        if not observed.repository_host or not observed.repository_owner_repo:
            raise BaselineProofRejected(
                "the repository has no remote whose identity can be named, so "
                "the source identity cannot be proven"
            )
        if not registered_host or not registered_owner:
            raise BaselineProofRejected(
                "the registered origin does not name a repository host, so the "
                "source identity cannot be proven"
            )
        if (
            observed.repository_host != registered_host
            or observed.repository_owner_repo != registered_owner
        ):
            raise BaselineProofRejected(
                "the repository identity does not match the frozen snapshot of "
                "the source"
            )
        _verification(
            lambda: verify_git_source_snapshot(
                repo_root=Path(repo_root), commit=commit, source_dir=Path(source_dir)
            )
        )
        verification = SourceIdentityVerification(
            scope="audited_source_identity",
            method="git_commit",
            repository_root=observed.repository_root,
            repository_host=observed.repository_host,
            commit=observed.commit,
            head_commit=observed.head_commit,
            tree_sha=observed.tree_sha,
            snapshot_digest=manifest.digest(),
            worktree_clean=observed.worktree_clean,
            observed_at=observed_at,
            notes=notes,
        )
        verified_identity = BaselineSourceIdentity(
            kind="git_commit",
            origin=origin,
            revision=observed.commit,
            verified=True,
            notes=notes,
        )
    else:
        verification = SourceIdentityVerification(
            scope="audited_source_identity",
            method="frozen_manifest",
            snapshot_digest=manifest.digest(),
            observed_at=observed_at,
            notes=notes,
        )
        verified_identity = BaselineSourceIdentity(
            kind="frozen_digest",
            origin=origin or "frozen-snapshot",
            digest=manifest.digest(),
            verified=True,
            notes=notes,
        )

    evidence_ref = encode_reference(verification.model_dump(mode="json"))
    return SourceIdentityAttestation.issue(
        project_id=project_id,
        source_ref=source_ref,
        ledger_sha256=str(source.get("ledger_sha256") or ""),
        metadata_sha256=str(source.get("metadata_sha256") or ""),
        scope="audited_source_identity",
        identity=verified_identity,
        verification=verification,
        evidence_ref=evidence_ref,
    )


def _build_artifact_attestation(
    *,
    source: dict[str, Any],
    project_id: str,
    source_ref: str,
    observed_at: str,
    frozen_root: Path | str | None,
    notes: str,
) -> SourceIdentityAttestation:
    """Prove that the audit artifacts are still the registered bytes.

    This is deliberately **not** a source identity (D-061): the ledger is the
    output of the audit, and its digest says nothing about the code that
    produced it.
    """

    ledger_relative = str(source.get("ledger_path") or "")
    metadata_relative = str(source.get("metadata_path") or "")
    if not ledger_relative or not metadata_relative:
        raise BaselineProofRejected(
            "the registered source records no frozen artifacts to verify"
        )
    base = Path(frozen_root) if frozen_root is not None else None
    ledger_path = (base / ledger_relative) if base else Path(ledger_relative)
    metadata_path = (base / metadata_relative) if base else Path(metadata_relative)
    _verification(
        lambda: verify_audit_artifact_bytes(
            ledger_path=ledger_path,
            metadata_path=metadata_path,
            ledger_sha256=str(source.get("ledger_sha256") or ""),
            metadata_sha256=str(source.get("metadata_sha256") or ""),
        )
    )
    identity = source.get("source_identity")
    identity = identity if isinstance(identity, dict) else {}
    verification = SourceIdentityVerification(
        scope="audit_artifact_bytes",
        method="artifact_bytes",
        observed_at=observed_at,
        notes=notes,
    )
    evidence_ref = encode_reference(verification.model_dump(mode="json"))
    return SourceIdentityAttestation.issue(
        project_id=project_id,
        source_ref=source_ref,
        ledger_sha256=str(source.get("ledger_sha256") or ""),
        metadata_sha256=str(source.get("metadata_sha256") or ""),
        scope="audit_artifact_bytes",
        identity=BaselineSourceIdentity(
            kind="unverified",
            origin=str(identity.get("origin") or "frozen-artifacts"),
            revision=identity.get("revision"),
            raw=str(identity.get("raw") or "the audit artifacts were re-read"),
            verified=False,
            notes=notes,
        ),
        verification=verification,
        evidence_ref=evidence_ref,
    )


def register_source_attestation(
    *,
    conn: sqlite3.Connection,
    project_id: str,
    attestation: SourceIdentityAttestation,
    envelope: ProofAuthentication,
) -> str:
    """Record one attestation, append-only.

    The attestation has to be about a source that is registered *in this
    project*, has to describe the very bytes that were registered, and has to
    carry an envelope that this deployment can verify.  Registering the same
    attestation twice does nothing; registering a *different* envelope for it
    is a conflict and is refused.
    """

    if attestation.project_id != project_id:
        raise BaselineProofRejected("the attestation is about another project")
    if not attestation.sealed():
        raise BaselineProofRejected(
            "the attestation does not match the digest it was sealed with"
        )
    source = _registered_source(
        conn, project_id=project_id, source_ref=attestation.source_ref
    )
    if attestation.ledger_sha256 != str(source.get("ledger_sha256") or "") or (
        attestation.metadata_sha256 != str(source.get("metadata_sha256") or "")
    ):
        raise BaselineProofRejected(
            "the attestation is about other bytes than the registered source"
        )
    if attestation.scope == "audited_source_identity" and not attestation.identity.verified:
        raise BaselineProofRejected(
            "the attestation carries an identity that was never verified"
        )

    if envelope.proof_kind != "source_attestation":
        raise BaselineProofRejected("the envelope is about another kind of proof")
    if envelope.proof_sha256 != attestation.attestation_sha256:
        raise BaselineProofRejected("the envelope is about another proof")
    if envelope.project_id != project_id:
        raise BaselineProofRejected("the envelope is about another project")
    key = configured_validation_keys().get(envelope.key_id)
    if key is None:
        raise BaselineProofRejected(
            "the envelope names a key this deployment does not trust"
        )
    if not verify_proof_auth(envelope=envelope, key=key):
        raise BaselineProofRejected("the envelope does not carry a valid mac")

    digest = attestation.attestation_sha256
    existing = conn.execute(
        "SELECT payload_sha256, mac FROM coverage_source_attestations "
        "WHERE project_id = ? AND source_ref = ? AND payload_sha256 = ?",
        (project_id, attestation.source_ref, digest),
    ).fetchone()
    if existing is not None:
        if str(existing["mac"]) != envelope.mac:
            raise BaselineProofRejected(
                "another envelope is already registered for this attestation"
            )
        return digest

    conn.execute(
        "INSERT INTO coverage_source_attestations (project_id, source_ref, "
        "verification_method, payload_json, payload_sha256, key_id, mac, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            project_id,
            attestation.source_ref,
            attestation.verification.method,
            cf_canonical_json(attestation.model_dump(mode="json")),
            digest,
            envelope.key_id,
            envelope.mac,
            utcnow(),
        ),
    )
    return digest


def _stored_attestations(
    conn: sqlite3.Connection, *, project_id: str, source_ref: str
) -> list[tuple[SourceIdentityAttestation, str, str]]:
    """The attestations of one source, with their key and their mac."""

    rows = conn.execute(
        "SELECT payload_json, payload_sha256, key_id, mac FROM coverage_source_attestations "
        "WHERE project_id = ? AND source_ref = ? ORDER BY attestation_id",
        (project_id, source_ref),
    ).fetchall()
    found: list[tuple[SourceIdentityAttestation, str, str]] = []
    for row in rows:
        try:
            attestation = SourceIdentityAttestation.model_validate(
                json.loads(row["payload_json"])
            )
        except ValueError:
            continue
        if not attestation.sealed():
            continue
        if attestation.attestation_sha256 != str(row["payload_sha256"]):
            continue
        found.append((attestation, str(row["key_id"]), str(row["mac"])))
    return found


def _trusted_attestations(
    attestations: list[tuple[SourceIdentityAttestation, str, str]],
    *,
    project_id: str,
) -> list[SourceIdentityAttestation]:
    """The attestations whose envelope this deployment can verify."""

    keys = configured_validation_keys()
    trusted: list[SourceIdentityAttestation] = []
    for attestation, key_id, mac in attestations:
        key = keys.get(key_id)
        if key is None:
            continue
        envelope = ProofAuthentication(
            proof_kind="source_attestation",
            key_id=key_id,
            proof_sha256=attestation.attestation_sha256,
            project_id=project_id,
            mac=mac,
        )
        if verify_proof_auth(envelope=envelope, key=key):
            trusted.append(attestation)
    return trusted


def source_attestation_status(
    conn: sqlite3.Connection, *, project_id: str, source_ref: str
) -> SourceAttestationStatus:
    """What is known about the identity of the **audited code** of one source.

    Only attestations of the scope ``audited_source_identity`` count here.  A
    proof that the audit artifacts are still the registered bytes says nothing
    about the code that produced them, so it may never be counted as a source
    identity (D-061).

    The newest attestation does **not** win.  A source that carries two
    different attestations is in conflict, and a conflict is reported as a
    conflict until something resolves it - the registry keeps both records
    (D-045).
    """

    stored = [
        item
        for item in _stored_attestations(
            conn, project_id=project_id, source_ref=source_ref
        )
        if item[0].scope == "audited_source_identity"
    ]
    if not stored:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="unverified",
            reason="no attestation of the audited source identity is registered",
        )

    attestations = [item[0] for item in stored]
    trusted = _trusted_attestations(stored, project_id=project_id)

    distinct = {item.attestation_sha256 for item in attestations}
    if len(distinct) > 1:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="conflict",
            attestations=tuple(attestations),
            reason="the source carries contradictory attestations",
        )
    if not trusted:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="unverified",
            attestations=tuple(attestations),
            reason="no attestation of the source carries a valid mac",
        )
    return SourceAttestationStatus(
        source_ref=source_ref, state="verified", attestations=tuple(attestations)
    )


def audit_artifact_status(
    conn: sqlite3.Connection, *, project_id: str, source_ref: str
) -> SourceAttestationStatus:
    """What is known about the **audit artifacts** of one source.

    This is the ledger and the run metadata, not the code.  It is reported
    separately on purpose: the two must never be merged into one number
    (D-061, Q53).
    """

    stored = [
        item
        for item in _stored_attestations(
            conn, project_id=project_id, source_ref=source_ref
        )
        if item[0].scope == "audit_artifact_bytes"
    ]
    if not stored:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="unverified",
            reason="no attestation of the audit artifacts is registered",
        )
    attestations = [item[0] for item in stored]
    trusted = _trusted_attestations(stored, project_id=project_id)
    distinct = {item.attestation_sha256 for item in attestations}
    if len(distinct) > 1:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="conflict",
            attestations=tuple(attestations),
            reason="the source carries contradictory artifact attestations",
        )
    if not trusted:
        return SourceAttestationStatus(
            source_ref=source_ref,
            state="unverified",
            attestations=tuple(attestations),
            reason="no artifact attestation of the source carries a valid mac",
        )
    return SourceAttestationStatus(
        source_ref=source_ref, state="verified", attestations=tuple(attestations)
    )


def build_lineage_seal(
    *,
    conn: sqlite3.Connection,
    project_id: str,
    run_id: str,
    manifest_ref: str,
    issuer: str,
    issued_at: str,
) -> LineageSeal:
    """Describe the sealed scope of one run.

    A scope can only be sealed when it is **closed** (every declared member
    was processed and registered) and when every member has a trusted source
    attestation.  A member without one is a member whose identity is unknown,
    and a scope that contains an unknown member is not a scope that was
    searched (D-052).
    """

    manifest = referenced_manifest(
        conn, project_id=project_id, reference=manifest_ref
    )
    if not manifest.closed:
        raise BaselineProofRejected(
            "an open scope cannot be sealed: the manifest still has unprocessed members"
        )
    if not _run_belongs_to_project(conn, project_id=project_id, run_id=run_id):
        raise BaselineProofRejected("the run is not a run of this project")

    members: list[LineageSealMember] = []
    for member in manifest.members:
        source = _registered_source(
            conn, project_id=project_id, source_ref=member.source_ref
        )
        if str(source.get("ledger_sha256") or "") != member.ledger_sha256 or (
            str(source.get("metadata_sha256") or "") != member.metadata_sha256
        ):
            raise BaselineProofRejected(
                f"the member {member.source_ref!r} does not match the registered source"
            )
        status = source_attestation_status(
            conn, project_id=project_id, source_ref=member.source_ref
        )
        if status.state != "verified" or not status.attestations:
            raise BaselineProofRejected(
                f"the member {member.source_ref!r} has no trusted source attestation"
            )
        members.append(
            LineageSealMember(
                source_ref=member.source_ref,
                ledger_sha256=member.ledger_sha256,
                metadata_sha256=member.metadata_sha256,
                attestation_sha256=status.attestations[0].attestation_sha256,
            )
        )

    return LineageSeal.issue(
        project_id=project_id,
        run_id=run_id,
        lineage_manifest_ref=manifest.reference(),
        manifest_sha256=cf_payload_digest(manifest.body()),
        scope_kind=manifest.scope_kind,
        completeness=manifest.completeness,
        members=members,
        issuer=issuer,
        issued_at=issued_at,
    )


def register_lineage_seal(
    *,
    conn: sqlite3.Connection,
    project_id: str,
    seal: LineageSeal,
    envelope: ProofAuthentication,
) -> str:
    """Record one seal, append-only.

    The seal is checked against the manifest it names, member by member, and
    every member's attestation is verified again at this moment.  A seal that
    was correct when it was issued but whose members have changed since is
    refused, because a seal that no longer describes the history is not
    evidence about the history.
    """

    if seal.project_id != project_id:
        raise BaselineProofRejected("the seal is about another project")
    if not seal.sealed():
        raise BaselineProofRejected("the seal does not match the digest it was sealed with")
    if not _run_belongs_to_project(conn, project_id=project_id, run_id=seal.run_id):
        raise BaselineProofRejected("the run is not a run of this project")

    manifest = referenced_manifest(
        conn, project_id=project_id, reference=seal.lineage_manifest_ref
    )
    if not manifest.closed:
        raise BaselineProofRejected("the sealed scope is not closed")
    if manifest.scope_kind != seal.scope_kind:
        raise BaselineProofRejected("the seal and the manifest disagree about the scope")
    manifest_members = {
        member.source_ref: (member.ledger_sha256, member.metadata_sha256)
        for member in manifest.members
    }
    seal_members = {
        member.source_ref: (member.ledger_sha256, member.metadata_sha256)
        for member in seal.members
    }
    if manifest_members != seal_members:
        raise BaselineProofRejected(
            "the seal does not cover exactly the members of the manifest"
        )

    for member in seal.members:
        source = _registered_source(
            conn, project_id=project_id, source_ref=member.source_ref
        )
        if str(source.get("ledger_sha256") or "") != member.ledger_sha256 or (
            str(source.get("metadata_sha256") or "") != member.metadata_sha256
        ):
            raise BaselineProofRejected(
                f"the member {member.source_ref!r} does not match the registered source"
            )
        status = source_attestation_status(
            conn, project_id=project_id, source_ref=member.source_ref
        )
        if status.state != "verified" or not status.attestations:
            raise BaselineProofRejected(
                f"the member {member.source_ref!r} has no trusted source attestation"
            )
        if status.attestations[0].attestation_sha256 != member.attestation_sha256:
            raise BaselineProofRejected(
                f"the attestation of the member {member.source_ref!r} changed since "
                "the scope was sealed"
            )

    if envelope.proof_kind != "lineage_seal":
        raise BaselineProofRejected("the envelope is about another kind of proof")
    if envelope.proof_sha256 != seal.seal_sha256:
        raise BaselineProofRejected("the envelope is about another proof")
    if envelope.project_id != project_id:
        raise BaselineProofRejected("the envelope is about another project")
    key = configured_validation_keys().get(envelope.key_id)
    if key is None:
        raise BaselineProofRejected(
            "the envelope names a key this deployment does not trust"
        )
    if not verify_proof_auth(envelope=envelope, key=key):
        raise BaselineProofRejected("the envelope does not carry a valid mac")

    digest = seal.seal_sha256
    existing = conn.execute(
        "SELECT payload_sha256, mac FROM coverage_lineage_seals "
        "WHERE project_id = ? AND run_id = ? AND payload_sha256 = ?",
        (project_id, seal.run_id, digest),
    ).fetchone()
    if existing is not None:
        if str(existing["mac"]) != envelope.mac:
            raise BaselineProofRejected(
                "another envelope is already registered for this seal"
            )
        return digest

    conn.execute(
        "INSERT INTO coverage_lineage_seals (project_id, run_id, lineage_manifest_ref, "
        "scope_kind, payload_json, payload_sha256, key_id, mac, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            project_id,
            seal.run_id,
            seal.lineage_manifest_ref,
            seal.scope_kind,
            cf_canonical_json(seal.model_dump(mode="json")),
            digest,
            envelope.key_id,
            envelope.mac,
            utcnow(),
        ),
    )
    return digest


def lineage_seal_status(
    conn: sqlite3.Connection, *, project_id: str, run_id: str
) -> LineageSealStatus:
    """What is known about the sealed scope of one run.

    The scope is trusted for a negative conclusion only when the seal verifies
    *and* the scope still verifies member by member.  A complete manifest
    without a seal is not a negative conclusion, and neither is a seal whose
    members have changed (D-052).
    """

    rows = conn.execute(
        "SELECT payload_json, payload_sha256, key_id, mac FROM coverage_lineage_seals "
        "WHERE project_id = ? AND run_id = ? ORDER BY seal_id",
        (project_id, run_id),
    ).fetchall()
    if not rows:
        return LineageSealStatus(
            run_id=run_id,
            sealed=False,
            trusted_negative=False,
            reason="no lineage seal is registered for the run",
        )

    keys = configured_validation_keys()
    for row in rows:
        try:
            seal = LineageSeal.model_validate(json.loads(row["payload_json"]))
        except ValueError:
            continue
        if not seal.sealed() or seal.seal_sha256 != str(row["payload_sha256"]):
            continue
        key = keys.get(str(row["key_id"]))
        if key is None:
            continue
        envelope = ProofAuthentication(
            proof_kind="lineage_seal",
            key_id=str(row["key_id"]),
            proof_sha256=seal.seal_sha256,
            project_id=project_id,
            mac=str(row["mac"]),
        )
        if not verify_proof_auth(envelope=envelope, key=key):
            continue
        try:
            manifest = referenced_manifest(
                conn, project_id=project_id, reference=seal.lineage_manifest_ref
            )
        except LookupError:
            continue
        if not manifest.closed:
            continue
        if any(
            source_attestation_status(
                conn, project_id=project_id, source_ref=member.source_ref
            ).state
            != "verified"
            for member in manifest.members
        ):
            continue
        return LineageSealStatus(
            run_id=run_id,
            sealed=True,
            trusted_negative=True,
            seal=seal,
            reason="the scope is sealed and every member still verifies",
        )

    return LineageSealStatus(
        run_id=run_id,
        sealed=False,
        trusted_negative=False,
        reason="no registered seal of the run is verifiable",
    )
