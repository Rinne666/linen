"""HTTP surface for the skill coverage event ledger (CF-S1-C).

Coverage registration is not a fact and not an audit event, so it does not go
through ``append-fact``: a registration is a plan-boundary record with its own
idempotency and immutability rules, and routing it through the fact channel
would both weaken those rules and confuse the graph with ledger state.

The request body may only describe *what* is being registered.  Everything
that decides *whether* it may be registered - the caller's trustworthiness,
the run plan, and the historical prior status - is resolved by the server
from its own trusted sources, because a request body is not a source of
authority (D-026).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from linen.contracts.skill_audit import CoverageCanonicalRefs, UnitRegisteredPayload
from linen.server.db import get_conn
from linen.server.services import check_project_active
from linen.server.skill_coverage import (
    DEFAULT_REGISTRATION_POLICY,
    CoverageBaselineUnavailable,
    CoverageCallerUntrusted,
    CoverageEventConflict,
    CoverageEventRejected,
    CoverageRegistrationDisabled,
    CoverageRegistrationPolicy,
    CoverageRunNotFound,
    CoverageUnitNotPlanned,
    list_registered_units,
    project_registered_units,
    register_unit,
    resolve_registration_payload,
)

router = APIRouter(tags=["skill-coverage"])


class SkillCoverageEventRequest(BaseModel):
    """One ``unit_registered`` request.

    The model is closed: a request that carries ``prior_status``,
    ``baseline``, ``agent_id``, ``wave`` or any other field is rejected
    before it reaches the ledger.  Those are server-side decisions, and
    accepting them from a caller would let that caller declare its own
    historical verdict.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    event_type: Literal["unit_registered"] = "unit_registered"
    payload_version: Literal[1] = 1
    coverage_id: str = Field(min_length=1, max_length=2048)
    canonical_refs: CoverageCanonicalRefs


class SkillCoverageEventResponse(BaseModel):
    """The stored registration event."""

    event_id: int
    project_id: str
    run_id: str
    coverage_id: str
    event_key: str
    payload_sha256: str
    created_at: str
    replayed: bool
    payload: UnitRegisteredPayload


class RegisteredUnitView(BaseModel):
    """One row of the minimal registration projection."""

    project_id: str
    run_id: str
    coverage_id: str
    canonical_refs: dict[str, str]
    prior_status: str
    registration_event_id: int


def registration_policy(request: Request) -> CoverageRegistrationPolicy:
    """The registration policy the running server was installed with.

    A stock server has none, which means registration is refused.  The policy
    is application configuration, never a request field.
    """

    return getattr(request.app.state, "coverage_registration", DEFAULT_REGISTRATION_POLICY)


@router.post(
    "/projects/{project_id}/skill-coverage-events",
    response_model=SkillCoverageEventResponse,
    status_code=201,
)
def register_skill_coverage_event(
    request: Request,
    response: Response,
    project_id: str,
    body: SkillCoverageEventRequest,
) -> SkillCoverageEventResponse:
    """Record one trusted coverage unit registration.

    The write is idempotent inside a run: repeating the same request returns
    the original event with ``200``, while a different payload for the same
    coverage unit is a conflict.
    """

    policy = registration_policy(request)
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            check_project_active(conn, project_id)
            payload = resolve_registration_payload(
                policy,
                project_id=project_id,
                run_id=body.run_id,
                coverage_id=body.coverage_id,
                canonical_refs=body.canonical_refs.model_dump(),
            )
            unit = register_unit(
                conn,
                project_id=project_id,
                run_id=body.run_id,
                coverage_id=body.coverage_id,
                payload=payload,
            )
        except CoverageRegistrationDisabled as exc:
            raise HTTPException(
                503, {"code": "registration_disabled", "detail": str(exc)}
            ) from exc
        except CoverageCallerUntrusted as exc:
            raise HTTPException(
                403, {"code": "untrusted_caller", "detail": str(exc)}
            ) from exc
        except CoverageBaselineUnavailable as exc:
            raise HTTPException(
                503, {"code": "trusted_baseline_unavailable", "detail": str(exc)}
            ) from exc
        except CoverageUnitNotPlanned as exc:
            raise HTTPException(
                422, {"code": "coverage_unit_not_in_plan", "detail": str(exc)}
            ) from exc
        except CoverageRunNotFound as exc:
            raise HTTPException(404, {"code": "run_not_found", "detail": str(exc)}) from exc
        except CoverageEventConflict as exc:
            raise HTTPException(
                409, {"code": "coverage_event_conflict", "detail": str(exc)}
            ) from exc
        except CoverageEventRejected as exc:
            raise HTTPException(
                422, {"code": "coverage_event_rejected", "detail": str(exc)}
            ) from exc
    response.status_code = 200 if unit.replayed else 201
    return SkillCoverageEventResponse(**unit.to_dict())


@router.get(
    "/projects/{project_id}/skill-coverage-events",
    response_model=list[RegisteredUnitView],
)
def read_skill_coverage_events(
    project_id: str, run_id: str
) -> list[RegisteredUnitView]:
    """Rebuild the registration view of one run from its event stream."""

    with get_conn() as conn:
        check_project_active(conn, project_id)
        units = list_registered_units(conn, project_id=project_id, run_id=run_id)
        projection = project_registered_units(
            [
                {
                    "project_id": unit.project_id,
                    "run_id": unit.run_id,
                    "coverage_id": unit.coverage_id,
                    "registration_event_id": unit.event_id,
                    "payload": unit.payload.model_dump(mode="json"),
                }
                for unit in units
            ]
        )
    return [RegisteredUnitView(**row.to_dict()) for row in projection]
