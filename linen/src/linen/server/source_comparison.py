"""The trusted comparison of the related audited source (CF-S2-B2-B).

The question this module answers is narrow and it is the only one it answers:

```text
did the source that the history talks about change?
```

The answer is one of three values - ``same``, ``changed`` or ``unknown`` - and
nothing else.  This module deliberately does **not** produce a
``prior_status``, does not create a finding and does not write a coverage
event (D-065); that is the job of the resolver in CF-S2-B2-C, and it may only
use this comparison as one of its inputs.

Three rules shape the implementation:

* **Both sides have to be proven.**  The historical side is proven by a
  registered, signed source identity attestation; the current side is proven by
  a verification the server performs itself, in this process.  A side that
  cannot be proven makes the whole comparison ``unknown`` (B-T01, B-T02).

* **The compared paths are a union, never an intersection** (D-065).  The set
  is the union of the current trusted plan paths, the paths the historical run
  reviewed and the paths the historical findings point at.  A path the current
  plan forgot is still a path the history says something about, so it stays in
  the set (B-T06, B-T07).

* **A path is only called the same when its file type, its mode and its
  content are all proven equal** (D-064).  A file whose type cannot be
  determined makes its path ``unknown``; it is never reported as the same
  file (B-T09).

The result is a pure function of its trusted inputs: the same inputs always
produce the same outcome and the same evidence references (B-T10).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from linen.contracts.baseline import (
    SourceComparisonResult,
    SourcePathEvidence,
    encode_reference,
)
from linen.contracts.common import cf_is_safe_relative_path, cf_payload_digest

from .baseline_proofs import source_attestation_status
from .source_identity import (
    GIT_MODE_TREE,
    SOURCE_KIND_DIRECTORY,
    FrozenSourceManifest,
    SourceFileEntry,
    SourceIdentityVerificationFailed,
    SourceTreeState,
    read_frozen_source_manifest_bytes,
    verify_frozen_source_manifest,
    verify_git_source_identity,
    verify_git_source_snapshot,
)


class SourceComparisonRejected(ValueError):
    """The registered data is broken, so the comparison cannot be made."""


@dataclass(frozen=True)
class RelatedPathSet:
    """The paths a comparison has to look at.

    The set is the **union** of three collections (D-065):

    ``current_plan_paths``
        the paths the current trusted plan points at;
    ``historical_reviewed_paths``
        the paths the historical run reviewed;
    ``historical_finding_paths``
        the paths the historical findings point at.

    It is never an intersection: a path the current plan forgot is still a
    path the history says something about.
    """

    current_plan_paths: tuple[str, ...] = ()
    historical_reviewed_paths: tuple[str, ...] = ()
    historical_finding_paths: tuple[str, ...] = ()

    def union(self) -> tuple[str, ...]:
        """Every related path, sorted and without duplicates."""

        return tuple(
            sorted(
                set(self.current_plan_paths)
                | set(self.historical_reviewed_paths)
                | set(self.historical_finding_paths)
            )
        )


@dataclass(frozen=True)
class CurrentSource:
    """The current audited source, and the way it is proven.

    Either the source is a git revision (``repo_root`` and ``commit``), or it
    is a frozen snapshot (``manifest_bytes``).  A caller may say *which* source
    it believes is being audited; it can never say that the answer is
    "verified" - the verification happens here, in the server.
    """

    root: Path
    repo_root: Path | None = None
    commit: str | None = None
    manifest_bytes: bytes | None = None


@dataclass(frozen=True)
class _PathState:
    """The proven state of one path on one side of the comparison."""

    kind: str
    mode: str
    digest: str


def _entry_digest(entry: SourceFileEntry) -> str:
    """The digest of one file, covering its type, its mode and its content."""

    return cf_payload_digest(
        {
            "kind": entry.kind,
            "mode": entry.mode,
            "sha256": entry.sha256,
        }
    )


def _path_state(state: SourceTreeState, path: str) -> _PathState | None:
    """The state of one path: the file itself, or the tree below it.

    A path that names a directory is compared as the whole subtree below it,
    because a reviewed path is often a directory (``src/main/java``) and
    "the directory did not change" has to mean "nothing below it changed".
    """

    entry = state.file(path)
    if entry is not None:
        return _PathState(kind=entry.kind, mode=entry.mode, digest=_entry_digest(entry))
    prefix = path.rstrip("/") + "/"
    children = [child for child in state.entries if child.path.startswith(prefix)]
    if not children:
        return None
    aggregate = cf_payload_digest(
        {
            "entries": [
                {
                    "kind": child.kind,
                    "mode": child.mode,
                    "path": child.path[len(prefix) :],
                    "sha256": child.sha256,
                }
                for child in sorted(children, key=lambda child: child.path)
            ],
            "kind": SOURCE_KIND_DIRECTORY,
        }
    )
    return _PathState(
        kind=SOURCE_KIND_DIRECTORY, mode=GIT_MODE_TREE, digest=aggregate
    )


def _ledger_units(payload: Any) -> list[Mapping[str, Any]]:
    """The unit list of a coverage ledger document."""

    if isinstance(payload, list):
        units: Any = payload
    elif isinstance(payload, Mapping):
        units = payload.get("units")
    else:
        units = None
    if not isinstance(units, list):
        return []
    return [unit for unit in units if isinstance(unit, Mapping)]


def _ledger_units_of(ledger_bytes: bytes) -> list[Mapping[str, Any]]:
    """The units of a coverage ledger document, read from its bytes."""

    try:
        payload = json.loads(ledger_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    return _ledger_units(payload)


def reviewed_paths_from_ledger(ledger_bytes: bytes) -> tuple[str, ...]:
    """The paths the historical run reviewed.

    Both the unit level list and the paths every check owns are taken: the
    unit level list is the union of the owned paths in a valid ledger, but a
    ledger that is not valid upstream may disagree, and the union is the
    conservative reading.
    """

    paths: set[str] = set()
    for unit in _ledger_units_of(ledger_bytes):
        for path in unit.get("reviewed_paths") or []:
            if isinstance(path, str):
                paths.add(path)
        checks = unit.get("local_checks") or unit.get("checks") or []
        if isinstance(checks, list):
            for check in checks:
                if not isinstance(check, Mapping):
                    continue
                for path in check.get("reviewed_paths") or []:
                    if isinstance(path, str):
                        paths.add(path)
    return tuple(sorted(paths))


def finding_paths_from_ledger(ledger_bytes: bytes) -> tuple[str, ...]:
    """The paths the historical findings point at.

    A unit that carries fingerprints is a unit that found something.  The
    paths that back that finding are the paths its checks own and the evidence
    artifacts they produced.  They are part of the related source even when the
    current plan never mentions them (D-065).
    """

    paths: set[str] = set()
    for unit in _ledger_units_of(ledger_bytes):
        fingerprints = unit.get("result_fingerprints") or []
        if not isinstance(fingerprints, list) or not fingerprints:
            continue
        checks = unit.get("local_checks") or unit.get("checks") or []
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, Mapping):
                continue
            for path in check.get("reviewed_paths") or []:
                if isinstance(path, str):
                    paths.add(path)
            artifact = check.get("artifact")
            if isinstance(artifact, str) and artifact:
                paths.add(artifact)
    return tuple(sorted(paths))


def finding_paths_from_findings(findings_bytes: bytes) -> tuple[str, ...]:
    """The source paths the historical findings point at.

    A finding names the files it walks through (``trace``) and the files it
    cites (``evidence``).  Those are the paths the finding is about, and they
    belong to the related source.

    The findings document is a *hint* about paths, not a proof: it may only
    **add** paths to the compared set.  Adding a path can never turn a proven
    ``changed`` into a ``same``, so a wrong hint can only make the comparison
    more conservative.
    """

    try:
        payload = json.loads(findings_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ()
    if isinstance(payload, Mapping):
        records = payload.get("findings")
        records = records if isinstance(records, list) else [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        return ()
    paths: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            continue
        for key in ("trace", "evidence"):
            items = record.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                file = item.get("file")
                if isinstance(file, str) and file:
                    paths.add(file)
    return tuple(sorted(paths))


def _registered_source(
    conn: sqlite3.Connection, *, project_id: str, source_ref: str
) -> dict[str, Any] | None:
    """The registered historical source, re-checked against its digest."""

    row = conn.execute(
        "SELECT payload_json, payload_sha256 FROM coverage_baseline_sources "
        "WHERE project_id = ? AND record_kind = 'historical_source' AND record_ref = ?",
        (project_id, source_ref),
    ).fetchone()
    if row is None:
        return None
    payload = json.loads(row["payload_json"])
    if cf_payload_digest(payload) != str(row["payload_sha256"]):
        raise SourceComparisonRejected(
            "the registered source does not match the digest it was stored with"
        )
    return payload


def _unknown(
    project_id: str, source_ref: str, reason: str, evidence_refs: Sequence[str] = ()
) -> SourceComparisonResult:
    """The answer when the comparison could not be made."""

    return SourceComparisonResult(
        project_id=project_id,
        historical_source_ref=source_ref,
        outcome="unknown",
        relevant_paths=[],
        changed_paths=[],
        unknown_paths=[],
        unmatched_paths=[],
        evidence_refs=list(evidence_refs),
        path_evidence=[],
        reason=reason,
    )


def _current_state(current: CurrentSource) -> tuple[SourceTreeState, dict[str, Any]]:
    """Verify the current source and describe it.

    The verification happens here, in the server: a caller may name the
    repository and the commit, but it can never say that the answer is
    "verified".  A verification that fails is not an error - it means the
    current side is unknown (B-T02).
    """

    root = Path(current.root).expanduser()
    facts: dict[str, Any] = {}
    if current.repo_root is not None or current.commit is not None:
        if not current.commit:
            raise SourceIdentityVerificationFailed(
                "a git source needs the commit it claims"
            )
        observed = verify_git_source_identity(
            repo_root=Path(current.repo_root), commit=current.commit
        )
        merged = verify_git_source_snapshot(
            repo_root=Path(current.repo_root),
            commit=current.commit,
            source_dir=root,
        )
        facts = {
            "commit": observed.commit,
            "tree_sha": observed.tree_sha,
            "repository_host": observed.repository_host,
            "repository": observed.repository_owner_repo,
        }
    elif current.manifest_bytes is not None:
        merged = read_frozen_source_manifest_bytes(current.manifest_bytes)
        verify_frozen_source_manifest(manifest=merged, source_dir=root)
        facts = {"snapshot_digest": merged.digest()}
    else:
        raise SourceIdentityVerificationFailed(
            "the current source names neither a git revision nor a frozen manifest"
        )
    if merged.version != 2:
        raise SourceIdentityVerificationFailed(
            "the current source carries no file type, so it cannot be compared "
            "with a historical source (D-064)"
        )
    state = merged.tree_state()
    if state.undecidable:
        raise SourceIdentityVerificationFailed(
            f"the current source carries {state.undecidable[0]!r}, whose file "
            "type cannot be determined"
        )
    return state, facts


def current_plan_paths(
    conn: sqlite3.Connection, *, project_id: str, run_id: str
) -> tuple[str, ...]:
    """The paths of the trusted plan of one run, from its own event stream.

    The plan is the server's own record: it is rebuilt from the coverage
    events the run wrote, so the paths are the paths the run really planned -
    not the paths somebody says the run planned.
    """

    from .skill_coverage_waves import list_coverage_events, project_multiwave

    try:
        events = list_coverage_events(conn, project_id=project_id, run_id=run_id)
        units = project_multiwave(events)
    except Exception:  # pragma: no cover - a broken stream is not a plan
        return ()
    paths: set[str] = set()
    for unit in units:
        for path in getattr(unit, "starting_paths", []) or []:
            if isinstance(path, str):
                paths.add(path)
    return tuple(sorted(paths))


def compare_related_sources(
    *,
    conn: sqlite3.Connection,
    project_id: str,
    historical_source_ref: str,
    historical_ledger_bytes: bytes,
    historical_manifest_bytes: bytes | None,
    current_source: CurrentSource,
    relevant_paths: RelatedPathSet,
    historical_findings_bytes: bytes | None = None,
) -> SourceComparisonResult:
    """Compare the related source of the current run and one historical run.

    The result is ``same``, ``changed`` or ``unknown`` and it never is
    anything else.  A trusted difference wins over an undecided path: a path
    that is provably different makes the comparison ``changed`` even when
    another path could not be decided, because "something related changed" is
    already enough to say that the history does not carry over.
    """

    # --- the historical side -------------------------------------------------
    record = _registered_source(
        conn, project_id=project_id, source_ref=historical_source_ref
    )
    if record is None:
        return _unknown(
            project_id,
            historical_source_ref,
            f"the historical source {historical_source_ref!r} is not registered",
        )

    ledger_digest = hashlib.sha256(historical_ledger_bytes).hexdigest()
    if ledger_digest != str(record.get("ledger_sha256") or ""):
        raise SourceComparisonRejected(
            "the historical ledger does not match the digest it was registered with"
        )

    status = source_attestation_status(
        conn, project_id=project_id, source_ref=historical_source_ref
    )
    if status.state != "verified" or not status.attestations:
        return _unknown(
            project_id,
            historical_source_ref,
            "the historical source has no trusted source identity attestation",
        )
    attestation = status.attestations[0]

    manifest: FrozenSourceManifest | None = None
    if historical_manifest_bytes is not None:
        try:
            manifest = read_frozen_source_manifest_bytes(historical_manifest_bytes)
        except SourceIdentityVerificationFailed as exc:
            return _unknown(
                project_id,
                historical_source_ref,
                f"the frozen source manifest cannot be read: {exc}",
            )
    if manifest is None:
        return _unknown(
            project_id,
            historical_source_ref,
            "the historical source carries no frozen source manifest, so the "
            "identity of the audited code is unknown",
        )
    if manifest.digest() != str(record.get("source_manifest_sha256") or ""):
        raise SourceComparisonRejected(
            "the frozen source manifest does not match the digest it was "
            "registered with"
        )
    if manifest.digest() != str(
        attestation.verification.snapshot_digest or ""
    ):
        return _unknown(
            project_id,
            historical_source_ref,
            "the frozen source manifest does not match the attested snapshot",
        )
    if manifest.version != 2:
        return _unknown(
            project_id,
            historical_source_ref,
            "the frozen source manifest is a v1 manifest and carries no file "
            "type, so the related source cannot be compared (D-064)",
        )
    historical_state = manifest.tree_state()

    # --- the current side ----------------------------------------------------
    try:
        current_state, current_facts = _current_state(current_source)
    except SourceIdentityVerificationFailed as exc:
        return _unknown(
            project_id,
            historical_source_ref,
            f"the current source cannot be verified: {exc}",
        )

    # --- the related paths ---------------------------------------------------
    finding_paths = set(finding_paths_from_ledger(historical_ledger_bytes))
    if historical_findings_bytes is not None:
        finding_paths |= set(finding_paths_from_findings(historical_findings_bytes))
    paths = RelatedPathSet(
        current_plan_paths=tuple(relevant_paths.current_plan_paths),
        historical_reviewed_paths=tuple(relevant_paths.historical_reviewed_paths),
        historical_finding_paths=tuple(sorted(finding_paths)),
    )
    union = paths.union()

    unsafe = [path for path in union if not cf_is_safe_relative_path(path)]
    safe = [path for path in union if cf_is_safe_relative_path(path)]

    changed: list[str] = []
    unknown: list[str] = []
    unmatched: list[str] = []
    evidence: list[SourcePathEvidence] = []

    for path in sorted(unsafe):
        unknown.append(path)
        evidence.append(
            SourcePathEvidence(
                path=path,
                outcome="unknown",
                evidence_ref=encode_reference(
                    {"kind": "path-comparison", "path": path, "reason": "unsafe-path"}
                ),
            )
        )

    for path in safe:
        current_path = _path_state(current_state, path)
        historical_path = _path_state(historical_state, path)
        if current_path is None and historical_path is None:
            unmatched.append(path)
            continue
        if (
            current_path is None
            or historical_path is None
            or current_path.digest != historical_path.digest
        ):
            changed.append(path)
            outcome = "changed"
        else:
            outcome = "same"
        evidence.append(
            SourcePathEvidence(
                path=path,
                outcome=outcome,
                current_kind=current_path.kind if current_path else None,
                current_mode=current_path.mode if current_path else None,
                current_digest=current_path.digest if current_path else None,
                historical_kind=historical_path.kind if historical_path else None,
                historical_mode=historical_path.mode if historical_path else None,
                historical_digest=historical_path.digest if historical_path else None,
                evidence_ref=encode_reference(
                    {
                        "current": (
                            {
                                "digest": current_path.digest,
                                "kind": current_path.kind,
                                "mode": current_path.mode,
                            }
                            if current_path
                            else None
                        ),
                        "historical": (
                            {
                                "digest": historical_path.digest,
                                "kind": historical_path.kind,
                                "mode": historical_path.mode,
                            }
                            if historical_path
                            else None
                        ),
                        "kind": "path-comparison",
                        "path": path,
                    }
                ),
            )
        )

    if changed:
        outcome = "changed"
        reason = "at least one related path is provably different"
    elif unknown:
        outcome = "unknown"
        reason = "at least one related path could not be decided"
    elif safe:
        outcome = "same"
        reason = "every related path is provably the same"
    else:
        outcome = "unknown"
        reason = "there is no related path to compare"

    evidence_refs = [
        encode_reference(
            {
                "attestation_sha256": attestation.attestation_sha256,
                "kind": "historical-source-attestation",
            }
        ),
        encode_reference(
            {"digest": manifest.digest(), "kind": "historical-source-manifest"}
        ),
        encode_reference(
            {"kind": "current-source", "state": current_state.digest(), **current_facts}
        ),
    ]
    evidence_refs.extend(item.evidence_ref for item in evidence)

    return SourceComparisonResult(
        project_id=project_id,
        historical_source_ref=historical_source_ref,
        outcome=outcome,
        relevant_paths=list(union),
        changed_paths=sorted(changed),
        unknown_paths=sorted(unknown),
        unmatched_paths=sorted(unmatched),
        evidence_refs=evidence_refs,
        path_evidence=evidence,
        reason=reason,
    )
