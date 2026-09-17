from __future__ import annotations


from fastapi import APIRouter, HTTPException

from linen.server.db import get_conn
from linen.server.models import (
    CreateReviewRequest,
    Review,
)
from linen.server.kernel import KernelConflict, KernelForbidden, KernelNotFound, create_review as create_review_kernel
from linen.server.services import get_project_or_404

router = APIRouter()

@router.post(
    "/projects/{project_id}/facts/{fact_id}/reviews",
    response_model=Review,
    status_code=201,
)
def create_review(project_id: str, fact_id: str, body: CreateReviewRequest):
    """Create a Review for a fact.

    The fact's `status` is recomputed after the insert via the aggregation
    rules in `aggregate_fact_status_from_reviews`. Multiple reviews on the
    same fact are allowed; later reviews may flip the status.
    """
    with get_conn() as conn:
        try:
            return create_review_kernel(conn, project_id, fact_id, body)
        except KernelNotFound as exc:
            raise HTTPException(404, str(exc)) from exc
        except KernelForbidden as exc:
            raise HTTPException(403, str(exc)) from exc
        except KernelConflict as exc:
            raise HTTPException(409, str(exc)) from exc


@router.get(
    "/projects/{project_id}/facts/{fact_id}/reviews",
    response_model=list[Review],
)
def list_reviews_for_fact_endpoint(project_id: str, fact_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        fact_row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?",
            (fact_id, project_id),
        ).fetchone()
        if fact_row is None:
            raise HTTPException(404, f"fact {fact_id} not found in project {project_id}")
        from linen.server.services import list_reviews_for_fact as _list
        return _list(conn, project_id, fact_id)


@router.get(
    "/projects/{project_id}/reviews",
    response_model=list[Review],
)
def list_reviews_for_project_endpoint(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        from linen.server.services import list_reviews_for_project as _list_proj
        return _list_proj(conn, project_id)
