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

Four rules shape the implementation:

* **Both sides have to be proven.**  The historical side is proven by a
  registered, signed source identity attestation; the current side is proven by
  a verification the server performs itself, in this process.  A side that
  cannot be proven makes the whole comparison ``unknown`` (B-T01, B-T02).

* **The compared paths are a union, never an intersection** (D-065).  The set
  is the union of the current trusted plan paths and the source paths the
  registered historical ledger names.  A path the current plan forgot is still
  a path the history says something about (B-T06).  The historical half of the
  set is never taken from the caller: it is read from the registered ledger
  bytes and bound to the target coverage unit (D-068).

* **A path is only called the same when its file type, its mode and its
  content are all proven equal** (D-064).  A file whose type cannot be
  determined makes its path ``unknown``; it is never reported as the same
  file (B-T09).

* **"Same" needs stronger evidence than "changed"** (D-066).  A path that is
  found in neither source tree is not evidence of anything: it can neither
  prove a change nor support a ``same``.  A path that is an audit output, not
  a source file, can never prove a change either (D-067).  A path that comes
  from findings nobody verified can only be a hint (D-069).

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

#: The plan paths of a comparison that the server resolved from the run's own
#: event stream.  This is the only source a production resolver may use.
PLAN_SOURCE_TRUSTED = "run_event_stream"

#: The plan paths a caller handed in.  Useful for a synthetic comparison, but
#: **not** a trusted scope: a free path list may not stand in for the plan of
#: a run (D-068, R07).
PLAN_SOURCE_CALLER = "caller_supplied"


class SourceComparisonRejected(ValueError):
    """The registered data is broken, so the comparison cannot be made."""


@dataclass(frozen=True)
class ComparisonScope:
    """Where the compared paths came from (D-068, R07).

    ``plan_source`` says whether the current plan paths were resolved by the
    server from the run's own coverage events (``run_event_stream``) or handed
    in by the caller (``caller_supplied``).  Only the first is a trusted
    scope, and a production resolver has to refuse the second.

    ``coverage_id`` says which coverage unit the historical paths belong to.
    Without it the historical scope is the whole run, which answers a
    different question than "did the source of *this* unit change".
    """

    plan_source: str = PLAN_SOURCE_CALLER
    coverage_id: str = ""

    @property
    def trusted(self) -> bool:
        """Whether the compared scope is a trusted one."""

        return self.plan_source == PLAN_SOURCE_TRUSTED


@dataclass(frozen=True)
class RelatedPathSet:
    """The paths a comparison has to look at, and what kind of evidence they are.

    ``current_plan_paths``
        the paths of the current plan - source paths;
    ``artifact_paths``
        paths that are known audit outputs, not audited source.  They are
        recorded and left out of the comparison: a report that a hunter wrote
        is not a file of the audited code (D-067);
    ``unverified_hint_paths``
        paths that came from findings nobody verified.  They are recorded as
        unresolved evidence: they can never prove a change, and they can never
        support a ``same`` (D-069).
    """

    current_plan_paths: tuple[str, ...] = ()
    artifact_paths: tuple[str, ...] = ()
    unverified_hint_paths: tuple[str, ...] = ()


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


def _scoped_units(
    ledger_bytes: bytes, *, coverage_id: str | None
) -> list[Mapping[str, Any]]:
    """The units of the ledger, bound to one coverage unit when one is named.

    Two units of the same run are two different questions.  A comparison that
    answers "did the source of *this* unit change" may not take the paths of
    every other unit of the run (D-068).
    """

    units = _ledger_units_of(ledger_bytes)
    if not coverage_id:
        return units
    return [
        unit
        for unit in units
        if str(unit.get("coverage_id") or "").strip() == coverage_id
    ]


def reviewed_paths_from_ledger(
    ledger_bytes: bytes, *, coverage_id: str | None = None
) -> tuple[str, ...]:
    """The source paths the historical run reviewed.

    Both the unit level list and the paths every check owns are taken: the
    unit level list is the union of the owned paths in a valid ledger, but a
    ledger that is not valid upstream may disagree, and the union is the
    conservative reading.
    """

    paths: set[str] = set()
    for unit in _scoped_units(ledger_bytes, coverage_id=coverage_id):
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


def finding_paths_from_ledger(
    ledger_bytes: bytes, *, coverage_id: str | None = None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The paths of the historical findings, split by what they are.

    A unit that carries fingerprints is a unit that found something.  The
    paths that back that finding are the paths its checks own - those are
    **source** paths.  The evidence artifacts its checks produced are audit
    **outputs**, not files of the audited code (D-067), and they are returned
    separately so that the comparison never mistakes one for the other.
    """

    source: set[str] = set()
    artifacts: set[str] = set()
    for unit in _scoped_units(ledger_bytes, coverage_id=coverage_id):
        fingerprints = unit.get("result_fingerprints") or []
        found_something = isinstance(fingerprints, list) and bool(fingerprints)
        checks = unit.get("local_checks") or unit.get("checks") or []
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, Mapping):
                continue
            if found_something:
                # A unit that found something has verified findings, and the
                # paths its checks own are trusted source paths (D-069).
                for path in check.get("reviewed_paths") or []:
                    if isinstance(path, str):
                        source.add(path)
            artifact = check.get("artifact")
            if isinstance(artifact, str) and artifact:
                # An artifact is an audit output.  It is an output whether or
                # not the unit found anything, and it is never a file of the
                # audited code (D-067).
                artifacts.add(artifact)
    return tuple(sorted(source)), tuple(sorted(artifacts))


def finding_paths_from_findings(findings_bytes: bytes) -> tuple[str, ...]:
    """The source paths the historical findings point at.

    A finding names the files it walks through (``trace``) and the files it
    cites (``evidence``).

    The findings document is a *hint* about paths, not a proof: nothing
    verifies that these bytes are the findings of the registered historical
    run.  An unverified hint may therefore never produce a ``changed`` and
    never support a ``same``; it is recorded as unresolved evidence (D-069).
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


def current_plan_paths(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    run_id: str,
    coverage_id: str | None = None,
) -> tuple[str, ...]:
    """The paths of the trusted plan of one run, from its own event stream.

    The plan is the server's own record: it is rebuilt from the coverage
    events the run wrote, so the paths are the paths the run really planned -
    not the paths somebody says the run planned.

    ``coverage_id`` narrows the plan to one coverage unit.  A comparison that
    asks "did the source of *this* unit change" may not take the paths of the
    other units of the same run (D-068).
    """

    from .skill_coverage_waves import list_coverage_events, project_multiwave

    try:
        events = list_coverage_events(
            conn, project_id=project_id, run_id=run_id, coverage_id=coverage_id
        )
        units = project_multiwave(events)
    except Exception:  # pragma: no cover - a broken stream is not a plan
        return ()
    paths: set[str] = set()
    for unit in units:
        for path in getattr(unit, "starting_paths", []) or []:
            if isinstance(path, str):
                paths.add(path)
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
    project_id: str,
    source_ref: str,
    reason: str,
    evidence_refs: Sequence[str] = (),
    *,
    relevant_paths: Sequence[str] = (),
    unmatched_paths: Sequence[str] = (),
    unresolved_paths: Sequence[str] = (),
    artifact_paths: Sequence[str] = (),
    scope: ComparisonScope | None = None,
) -> SourceComparisonResult:
    """The answer when the comparison could not be made."""

    scope = scope or ComparisonScope()
    return SourceComparisonResult(
        project_id=project_id,
        historical_source_ref=source_ref,
        outcome="unknown",
        relevant_paths=list(relevant_paths),
        changed_paths=[],
        unknown_paths=[],
        unmatched_paths=list(unmatched_paths),
        unresolved_paths=list(unresolved_paths),
        artifact_paths=list(artifact_paths),
        compared_paths=[],
        scope_trusted=scope.trusted,
        scope_source=scope.plan_source,
        coverage_id=scope.coverage_id,
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


def compare_related_sources(
    *,
    conn: sqlite3.Connection,
    project_id: str,
    historical_source_ref: str,
    historical_ledger_bytes: bytes,
    historical_manifest_bytes: bytes | None,
    current_source: CurrentSource,
    related_paths: RelatedPathSet,
    historical_findings_bytes: bytes | None = None,
    scope: ComparisonScope | None = None,
) -> SourceComparisonResult:
    """Compare the related source of the current run and one historical run.

    The result is ``same``, ``changed`` or ``unknown`` and it never is
    anything else.  A trusted difference wins over an undecided path: a path
    that is provably different makes the comparison ``changed`` even when
    another path could not be decided, because "something related changed" is
    already enough to say that the history does not carry over.

    The historical paths are **always** taken from the registered ledger
    bytes, bound to ``scope.coverage_id`` when one is named.  A caller may not
    widen the historical scope by handing in a path list (D-068).
    """

    scope = scope or ComparisonScope()
    coverage_id = scope.coverage_id or None

    # --- the historical side -------------------------------------------------
    record = _registered_source(
        conn, project_id=project_id, source_ref=historical_source_ref
    )
    if record is None:
        return _unknown(
            project_id,
            historical_source_ref,
            f"the historical source {historical_source_ref!r} is not registered",
            scope=scope,
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
            scope=scope,
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
                scope=scope,
            )
    if manifest is None:
        return _unknown(
            project_id,
            historical_source_ref,
            "the historical source carries no frozen source manifest, so the "
            "identity of the audited code is unknown",
            scope=scope,
        )
    if manifest.digest() != str(record.get("source_manifest_sha256") or ""):
        raise SourceComparisonRejected(
            "the frozen source manifest does not match the digest it was "
            "registered with"
        )
    if manifest.digest() != str(attestation.verification.snapshot_digest or ""):
        return _unknown(
            project_id,
            historical_source_ref,
            "the frozen source manifest does not match the attested snapshot",
            scope=scope,
        )
    if manifest.version != 2:
        return _unknown(
            project_id,
            historical_source_ref,
            "the frozen source manifest is a v1 manifest and carries no file "
            "type, so the related source cannot be compared (D-064)",
            scope=scope,
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
            scope=scope,
        )

    # --- the related paths ---------------------------------------------------
    if coverage_id:
        # The comparison is bound to one coverage unit.  If the historical
        # ledger does not carry that unit, the historical scope of the
        # question is empty - and an empty scope is not a source comparison
        # (D-068).
        scoped = _scoped_units(historical_ledger_bytes, coverage_id=coverage_id)
        if not scoped:
            return _unknown(
                project_id,
                historical_source_ref,
                f"the historical ledger carries no coverage unit {coverage_id!r}",
                scope=scope,
            )
    historical_source_paths = reviewed_paths_from_ledger(
        historical_ledger_bytes, coverage_id=coverage_id
    )
    finding_source_paths, finding_artifact_paths = finding_paths_from_ledger(
        historical_ledger_bytes, coverage_id=coverage_id
    )
    hint_paths = set(related_paths.unverified_hint_paths)
    if historical_findings_bytes is not None:
        hint_paths |= set(finding_paths_from_findings(historical_findings_bytes))
    artifact_paths = tuple(
        sorted(set(related_paths.artifact_paths) | set(finding_artifact_paths))
    )
    source_paths = tuple(
        sorted(
            set(related_paths.current_plan_paths)
            | set(historical_source_paths)
            | set(finding_source_paths)
        )
    )

    unsafe = [path for path in source_paths if not cf_is_safe_relative_path(path)]
    safe = [path for path in source_paths if cf_is_safe_relative_path(path)]
    # An unverified hint is recorded as unresolved evidence: it can never prove
    # a change and it can never support a "same" (D-069).  A hint that is
    # already a known audit output is an artifact, not an unresolved hint.
    unresolved = sorted(
        path
        for path in hint_paths
        if path not in source_paths and path not in artifact_paths
    )

    changed: list[str] = []
    unknown: list[str] = []
    unmatched: list[str] = []
    compared: list[str] = []
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
            # The path is in neither source tree.  That is not evidence that
            # the source did not change: it is evidence that the path is not
            # part of the compared source at all (D-066).
            unmatched.append(path)
            evidence.append(
                SourcePathEvidence(
                    path=path,
                    outcome="unknown",
                    evidence_ref=encode_reference(
                        {
                            "kind": "path-comparison",
                            "path": path,
                            "reason": "in-neither-source",
                        }
                    ),
                )
            )
            continue
        if (
            current_path is None
            or historical_path is None
            or current_path.digest != historical_path.digest
        ):
            changed.append(path)
            outcome = "changed"
        else:
            compared.append(path)
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
    elif unknown or unmatched or unresolved:
        outcome = "unknown"
        reason = "at least one related path could not be decided"
    elif compared:
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

    relevant = sorted(set(source_paths) | set(artifact_paths) | set(unresolved))
    return SourceComparisonResult(
        project_id=project_id,
        historical_source_ref=historical_source_ref,
        outcome=outcome,
        relevant_paths=relevant,
        changed_paths=sorted(changed),
        unknown_paths=sorted(unknown),
        unmatched_paths=sorted(unmatched),
        unresolved_paths=sorted(unresolved),
        artifact_paths=sorted(artifact_paths),
        compared_paths=sorted(compared),
        scope_trusted=scope.trusted,
        scope_source=scope.plan_source,
        coverage_id=scope.coverage_id,
        evidence_refs=evidence_refs,
        path_evidence=evidence,
        reason=reason,
    )
