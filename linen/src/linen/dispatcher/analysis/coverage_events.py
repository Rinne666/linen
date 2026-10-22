"""Trusted registration of coverage units (CF-S1-C).

A coverage unit comes into existence from an operator-declared seed, never
from a model payload.  The model reports *on* a unit; it does not bring one
into existence.  That is what makes the coverage ledger a record of the plan
instead of a transcript of the model.

The dispatcher says *what* is registered.  It never says what the historical
prior status is: the server resolves that from its own trusted sources, and
the request contract does not even have a field for it.  A registration can
therefore be refused by the server - because no trusted baseline exists yet,
or because the unit is not part of the run's trusted plan - and the honest
outcome of that refusal is a blocked registration, not a local guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from linen.dispatcher.config import CoverageUnitSeed


#: Server status codes that mean "the write was refused before it happened".
BLOCKED_STATUS_CODES = frozenset({"registration_disabled", "trusted_baseline_unavailable"})


@dataclass(frozen=True)
class CoverageRegistrationOutcome:
    """What happened to one attempted registration."""

    status: str  # "registered" | "replayed" | "rejected" | "blocked"
    coverage_id: str
    event_id: int | None = None
    code: str = ""
    reason: str = ""


def coverage_unit_registration_request(
    seed: CoverageUnitSeed, run_id: str
) -> dict[str, Any]:
    """Build the registration request for one trusted seed.

    Raises ``ValueError`` for anything that is not an operator-declared
    seed: a model payload never creates a coverage unit.
    """

    if not isinstance(seed, CoverageUnitSeed):
        raise ValueError(
            "a coverage unit can only be registered from an operator-declared "
            "CoverageUnitSeed; model payloads never create coverage units"
        )
    return {
        "run_id": run_id,
        "event_type": "unit_registered",
        "payload_version": 1,
        "coverage_id": seed.coverage_id,
        "canonical_refs": {
            "surface": seed.surface,
            "boundary": seed.boundary,
            "subsystem": seed.subsystem,
            "attack_class": seed.attack_class,
        },
    }


def register_trusted_coverage_unit(
    client: Any,
    *,
    project_id: str,
    run_id: str,
    seed: CoverageUnitSeed,
) -> CoverageRegistrationOutcome:
    """Register one coverage unit from a trusted seed.

    The unit is only written when the server accepts it.  A refusal - no
    trusted baseline, an unplanned unit, an untrusted caller - is reported
    as such and leaves the ledger untouched.
    """

    request = coverage_unit_registration_request(seed, run_id)
    response = client.register_coverage_unit(
        project_id,
        run_id,
        request["coverage_id"],
        request["canonical_refs"],
    )
    status_code = getattr(response, "status_code", 0)
    data = getattr(response, "data", None) or {}
    detail = data.get("detail") if isinstance(data.get("detail"), dict) else {}
    code = str(detail.get("code") or "")
    reason = str(detail.get("detail") or "")

    if status_code in (200, 201):
        return CoverageRegistrationOutcome(
            status="replayed" if data.get("replayed") else "registered",
            coverage_id=str(data.get("coverage_id") or request["coverage_id"]),
            event_id=data.get("event_id"),
            code=code,
        )
    if status_code in (403, 503):
        return CoverageRegistrationOutcome(
            status="blocked",
            coverage_id=str(request["coverage_id"]),
            code=code or f"http_{status_code}",
            reason=reason,
        )
    return CoverageRegistrationOutcome(
        status="rejected",
        coverage_id=str(request["coverage_id"]),
        code=code or f"http_{status_code}",
        reason=reason,
    )
