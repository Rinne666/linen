"""The trusted resolution of one coverage unit's prior status (CF-S2-B2-C).

The resolver answers one question - *what does the history say about this
coverage unit?* - and it answers it with **one** of the eleven upstream
``prior_status`` values, or with nothing at all.

Three states, and only three (D-039 - D-042, N6):

```text
resolved   the history was read and it says exactly one thing
unknown    the history could not be read well enough to say anything
failed     the registered records contradict each other
```

``unknown`` is **not** a twelfth prior status: a resolution that does not know
carries an empty ``prior_status``.  A guess is worse than a gap, because a
guess suppresses work that still has to be done.

Two things shape the implementation:

* **The mapping is the PM's N6 table and nothing else.**  ``none`` and ``new``
  are kept apart: ``none`` says there is no compatible historical ledger at
  all, ``new`` says a compatible ledger exists and this unit is new in it.
  ``none`` and ``new`` both need a **trusted** scope - a verified lineage seal
  over a *complete* history - because "the history does not exist" and "the
  history does not contain this unit" are both negative conclusions.

* **Every input is a proof, never a claim.**  The scope comes from a seal the
  server verified; the historical unit state comes from ledger bytes whose
  digest was checked; the source comparison comes from the comparison of
  CF-S2-B2-B; a historical verdict and a current claim come from named
  evidence references.  A caller may *say* which source it believes in; it can
  never say that the answer is verified.

The module is a pure function of its trusted inputs: the same inputs always
produce the same resolution and the same digest.  Writing the resolution down
is a separate concern (D-048) and is **not** done here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from linen.contracts.baseline import (
    PriorStatusResolution,
    PriorStatusResolutionState,
    SourceComparisonResult,
)
from linen.contracts.common import cf_payload_digest

#: The three states a historical verdict can carry.
VERDICT_CONFIRMED = "confirmed"
VERDICT_NEEDS_VALIDATION = "needs_validation"
VERDICT_REJECTED = "rejected"

#: The coverage states a historical unit can carry.
UNIT_STATUS_DEFERRED = "deferred"
UNIT_STATUS_BLOCKED = "blocked"
UNIT_STATUS_OUT_OF_SCOPE = "out_of_scope"
UNIT_STATUS_COVERED = "covered"
UNIT_STATUS_CANDIDATE = "candidate"


@dataclass(frozen=True)
class TrustedHistoryScope:
    """What a **verified** lineage seal says about the compatible history.

    This is the C1 answer to "which history may I claim to have searched".

    ``trusted_negative``
        the seal verifies and its scope still verifies member by member
        (D-052).  Only then may a negative conclusion be drawn from it;
    ``complete``
        the sealed scope is the **complete** compatible history.  A partial
        scope can prove that something exists, but never that something does
        not (PM v3.0);
    ``member_source_refs``
        the historical sources the scope contains.  An empty scope means
        there was no compatible history at all - which is ``none``, not
        ``new``.
    """

    trusted_negative: bool = False
    complete: bool = False
    scope_kind: str = ""
    member_source_refs: tuple[str, ...] = ()
    seal_ref: str = ""
    conflict: bool = False
    reason: str = ""

    @classmethod
    def from_seal_status(cls, status: Any) -> "TrustedHistoryScope":
        """Build the scope from the server's own lineage seal status."""

        seal = getattr(status, "seal", None)
        state = str(getattr(status, "state", "") or "")
        return cls(
            trusted_negative=bool(getattr(status, "trusted_negative", False)),
            complete=bool(seal is not None and seal.completeness == "complete"),
            scope_kind=str(getattr(seal, "scope_kind", "") or ""),
            member_source_refs=tuple(
                member.source_ref for member in (seal.members if seal else ())
            ),
            seal_ref=str(getattr(seal, "seal_sha256", "") or ""),
            conflict=state == "conflict",
            reason=str(getattr(status, "reason", "") or ""),
        )


@dataclass(frozen=True)
class HistoricalUnitState:
    """The state one historical coverage unit carried.

    It is read from the registered ledger bytes, so it is as trustworthy as
    those bytes: they were digest checked against the registered source
    before they were read.
    """

    coverage_id: str
    present: bool = False
    status: str = ""
    fingerprints: tuple[str, ...] = ()
    source_ref: str = ""


@dataclass(frozen=True)
class TrustedHistoricalVerdict:
    """A historical verdict that a trusted source has confirmed.

    The verdict of a finding is **not** part of the coverage ledger: it lives
    in the findings artifact, which is not registered yet.  Until it is, the
    verdict dependent prior statuses are unreachable in production and the
    resolver answers ``unknown`` instead of guessing.
    """

    coverage_id: str
    fingerprint: str
    verdict: str
    evidence_ref: str = ""
    evidence_sha256: str = ""


@dataclass(frozen=True)
class CurrentClaim:
    """A claim the **current** run makes about one fingerprint."""

    fingerprint: str
    evidence_ref: str = ""
    evidence_sha256: str = ""


@dataclass(frozen=True)
class _Outcome:
    """The decision, before it is written down."""

    state: PriorStatusResolutionState
    prior_status: str = ""
    reason_code: str = ""
    reason: str = ""


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


class BaselineResolutionRejected(ValueError):
    """The registered data is broken, so the resolution cannot be made."""


def verified_historical_ledgers(
    conn: Any, *, project_id: str, ledgers: Mapping[str, bytes]
) -> dict[str, bytes]:
    """Check the given ledger bytes against the registered digests.

    A ledger that is not the registered one may not be read as history: the
    unit state is derived from it, and a unit state that came from unregistered
    bytes would be a statement about nothing.  A mismatch is refused here
    rather than filtered out silently.
    """

    verified: dict[str, bytes] = {}
    for source_ref in sorted(ledgers):
        row = conn.execute(
            "SELECT payload_json FROM coverage_baseline_sources "
            "WHERE project_id = ? AND record_kind = 'historical_source' "
            "AND record_ref = ?",
            (project_id, source_ref),
        ).fetchone()
        if row is None:
            raise BaselineResolutionRejected(
                f"the historical source {source_ref!r} is not registered"
            )
        payload = json.loads(row["payload_json"])
        expected = str(payload.get("ledger_sha256") or "")
        actual = hashlib.sha256(ledgers[source_ref]).hexdigest()
        if actual != expected:
            raise BaselineResolutionRejected(
                f"the ledger of {source_ref!r} does not match the digest it was "
                "registered with"
            )
        verified[source_ref] = ledgers[source_ref]
    return verified


def unit_state_from_ledgers(
    ledgers: Mapping[str, bytes], *, coverage_id: str
) -> tuple[HistoricalUnitState | None, bool]:
    """Read the state of one coverage unit out of the registered ledgers.

    The ledgers are keyed by their source ref and their bytes are the
    registered ones - the caller checked the digests.  The second value of the
    result says whether the ledgers contradict each other about the unit: two
    members that carry the same unit with different states are a conflict, and
    a conflict is never resolved by picking the first one.
    """

    found: list[HistoricalUnitState] = []
    for source_ref in sorted(ledgers):
        try:
            payload = json.loads(ledgers[source_ref].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        for unit in _ledger_units(payload):
            if str(unit.get("coverage_id") or "").strip() != coverage_id:
                continue
            fingerprints = unit.get("result_fingerprints") or []
            found.append(
                HistoricalUnitState(
                    coverage_id=coverage_id,
                    present=True,
                    status=str(unit.get("status") or ""),
                    fingerprints=tuple(
                        str(item) for item in fingerprints if isinstance(item, str)
                    ),
                    source_ref=source_ref,
                )
            )
    if not found:
        return None, False
    statuses = {state.status for state in found}
    if len(statuses) > 1:
        return found[0], True
    return found[0], False


def _comparison_digest(comparison: SourceComparisonResult | None) -> str:
    """The digest of the comparison a resolution relied on."""

    if comparison is None:
        return ""
    return cf_payload_digest(comparison.model_dump(mode="json"))


def _decide(
    *,
    scope: TrustedHistoryScope,
    unit: HistoricalUnitState | None,
    comparison: SourceComparisonResult | None,
    verdict: TrustedHistoricalVerdict | None,
    current_claim: CurrentClaim | None,
    read_source_refs: Sequence[str] = (),
) -> _Outcome:
    """The deterministic mapping of the trusted inputs (C2)."""

    if scope.conflict:
        return _Outcome(
            state=PriorStatusResolutionState.failed,
            reason_code="history_scope_conflict",
            reason=(
                "the registered seals of this run disagree about the historical "
                "scope, so the scope was not searched"
            ),
        )
    if not scope.trusted_negative:
        return _Outcome(
            state=PriorStatusResolutionState.unknown,
            reason_code="history_scope_not_trusted",
            reason=(
                "no verified lineage seal covers the compatible history, so the "
                "absence of history cannot be claimed"
            ),
        )
    if not scope.complete:
        return _Outcome(
            state=PriorStatusResolutionState.unknown,
            reason_code="history_scope_not_trusted",
            reason=(
                "the sealed scope is not the complete compatible history, so a "
                "negative conclusion about the history is not available"
            ),
        )

    if not scope.member_source_refs:
        # There is no compatible historical ledger at all.  This is `none`,
        # and it is only ever reached through a trusted, complete scope.
        return _Outcome(
            state=PriorStatusResolutionState.resolved,
            prior_status="none",
            reason_code="no_compatible_history",
            reason=(
                "the trusted, complete history scope contains no compatible "
                "historical ledger"
            ),
        )

    unread = sorted(
        set(scope.member_source_refs) - set(read_source_refs)
    )
    if unread:
        # "The unit is not in the history" is a claim about **every** member of
        # the history.  A member that was not read is a member that could hold
        # the unit, so the absence is not proven.
        return _Outcome(
            state=PriorStatusResolutionState.unknown,
            reason_code="history_scope_not_read",
            reason=(
                f"the history member {unread[0]!r} was not read, so the absence "
                "of this coverage unit is not proven"
            ),
        )

    if unit is None or not unit.present:
        return _Outcome(
            state=PriorStatusResolutionState.resolved,
            prior_status="new",
            reason_code="unit_absent_from_complete_history",
            reason=(
                "the compatible history exists and does not contain this "
                "coverage unit"
            ),
        )

    if verdict is not None:
        if verdict.verdict == VERDICT_CONFIRMED:
            outcome = comparison.outcome if comparison is not None else "unknown"
            if outcome == "same":
                return _Outcome(
                    state=PriorStatusResolutionState.resolved,
                    prior_status="prior_confirmed_same_source",
                    reason_code="historical_finding_confirmed_same_source",
                    reason=(
                        "the historical finding was confirmed and the related "
                        "source did not change"
                    ),
                )
            if outcome == "changed":
                return _Outcome(
                    state=PriorStatusResolutionState.resolved,
                    prior_status="prior_confirmed_changed_source",
                    reason_code="historical_finding_confirmed_changed_source",
                    reason=(
                        "the historical finding was confirmed and the related "
                        "source changed, so it has to be verified again"
                    ),
                )
            return _Outcome(
                state=PriorStatusResolutionState.unknown,
                reason_code="source_comparison_unknown",
                reason=(
                    "the related source could not be compared, so it is unknown "
                    "whether the confirmed finding still holds"
                ),
            )
        if verdict.verdict == VERDICT_NEEDS_VALIDATION:
            return _Outcome(
                state=PriorStatusResolutionState.resolved,
                prior_status="prior_needs_validation",
                reason_code="historical_finding_needs_validation",
                reason=(
                    "the historical finding still needs validation, so the "
                    "blocking reason is kept and the source is checked again"
                ),
            )
        if verdict.verdict == VERDICT_REJECTED:
            new_evidence = (
                current_claim is not None
                and current_claim.fingerprint == verdict.fingerprint
                and bool(current_claim.evidence_sha256)
                and current_claim.evidence_sha256 != verdict.evidence_sha256
            )
            if (
                new_evidence
                and comparison is not None
                and comparison.outcome == "changed"
            ):
                return _Outcome(
                    state=PriorStatusResolutionState.resolved,
                    prior_status="prior_rejected_claim_changed",
                    reason_code="historical_rejected_claim_has_new_evidence",
                    reason=(
                        "the historical claim was rejected, and the current "
                        "claim carries evidence the rejection did not see"
                    ),
                )
            # A rejection without new evidence only blocks the same claim; the
            # coverage unit itself is judged by its coverage state below.

    status = unit.status
    if status == UNIT_STATUS_DEFERRED:
        return _Outcome(
            state=PriorStatusResolutionState.resolved,
            prior_status="prior_deferred",
            reason_code="historical_unit_deferred",
            reason="the historical coverage was deferred",
        )
    if status == UNIT_STATUS_BLOCKED:
        return _Outcome(
            state=PriorStatusResolutionState.resolved,
            prior_status="prior_blocked",
            reason_code="historical_unit_blocked",
            reason="the historical coverage was blocked",
        )
    if status == UNIT_STATUS_OUT_OF_SCOPE:
        return _Outcome(
            state=PriorStatusResolutionState.resolved,
            prior_status="prior_out_of_scope",
            reason_code="historical_unit_out_of_scope",
            reason="the historical coverage was out of scope",
        )
    if status == UNIT_STATUS_CANDIDATE:
        return _Outcome(
            state=PriorStatusResolutionState.unknown,
            reason_code="no_trusted_historical_verdict",
            reason=(
                "the historical unit carries a finding, but no trusted verdict "
                "says what was decided about it"
            ),
        )
    if status == UNIT_STATUS_COVERED:
        outcome = comparison.outcome if comparison is not None else "unknown"
        if outcome == "same":
            return _Outcome(
                state=PriorStatusResolutionState.resolved,
                prior_status="prior_covered_same_source",
                reason_code="historical_unit_covered_same_source",
                reason=(
                    "the historical coverage is complete and the related source "
                    "did not change"
                ),
            )
        if outcome == "changed":
            return _Outcome(
                state=PriorStatusResolutionState.resolved,
                prior_status="prior_covered_changed_source",
                reason_code="historical_unit_covered_changed_source",
                reason=(
                    "the historical coverage is complete, but the related source "
                    "changed, so the coverage is scheduled again"
                ),
            )
        return _Outcome(
            state=PriorStatusResolutionState.unknown,
            reason_code="source_comparison_unknown",
            reason=(
                "the related source could not be compared, so it is unknown "
                "whether the historical coverage still holds"
            ),
        )
    return _Outcome(
        state=PriorStatusResolutionState.unknown,
        reason_code="historical_unit_has_no_evidence",
        reason=(
            f"the historical unit carries the state {status or 'planned'!r}, "
            "which holds no evidence to derive a prior status from"
        ),
    )


def resolve_prior_status(
    *,
    project_id: str,
    run_id: str,
    coverage_id: str,
    scope: TrustedHistoryScope,
    unit: HistoricalUnitState | None = None,
    comparison: SourceComparisonResult | None = None,
    verdict: TrustedHistoricalVerdict | None = None,
    current_claim: CurrentClaim | None = None,
    lookup_ref: str = "",
    source_attestation_refs: Sequence[str] = (),
    unit_conflict: bool = False,
    read_source_refs: Sequence[str] = (),
) -> PriorStatusResolution:
    """Resolve the ``prior_status`` of one coverage unit.

    The result is a pure function of its trusted inputs: the same inputs
    always produce the same resolution and the same digest.

    ``read_source_refs`` names the history members whose ledger bytes were
    actually read.  A member that was not read could still hold the unit, so
    the absence of the unit is only proven when every member was read.
    """

    if unit_conflict:
        outcome = _Outcome(
            state=PriorStatusResolutionState.failed,
            reason_code="history_scope_conflict",
            reason=(
                "the registered historical sources disagree about the state of "
                "this coverage unit"
            ),
        )
    else:
        outcome = _decide(
            scope=scope,
            unit=unit,
            comparison=comparison,
            verdict=verdict,
            current_claim=current_claim,
            read_source_refs=read_source_refs,
        )

    evidence_refs: list[str] = []
    if scope.seal_ref:
        evidence_refs.append(scope.seal_ref)
    evidence_refs.extend(source_attestation_refs)
    if comparison is not None:
        evidence_refs.extend(comparison.evidence_refs)
    if verdict is not None and verdict.evidence_ref:
        evidence_refs.append(verdict.evidence_ref)
    if current_claim is not None and current_claim.evidence_ref:
        evidence_refs.append(current_claim.evidence_ref)

    return PriorStatusResolution.issue(
        project_id=project_id,
        run_id=run_id,
        coverage_id=coverage_id,
        state=outcome.state,
        prior_status=outcome.prior_status,
        reason_code=outcome.reason_code,
        reason=outcome.reason,
        lookup_ref=lookup_ref,
        lineage_seal_ref=scope.seal_ref,
        source_attestation_refs=list(source_attestation_refs),
        source_comparison_digest=_comparison_digest(comparison),
        historical_unit_status=unit.status if unit is not None else "",
        historical_fingerprints=list(unit.fingerprints) if unit is not None else [],
        evidence_refs=evidence_refs,
    )
