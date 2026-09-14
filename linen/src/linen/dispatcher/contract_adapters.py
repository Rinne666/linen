"""Adapters from the current server models to storage-independent contracts.

The dispatcher is intentionally the boundary between the server's response
models and ``linen.contracts``.  Consumers of the projector therefore do not
need to know about SQLite response shapes, aliases, or which collections are
currently present in ``ProjectDetail``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from linen.contracts import BlackboardSnapshot, EdgeEnvelope, NodeEnvelope
from linen.server.models import ProjectDetail


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _dump(value: Any) -> dict[str, Any]:
    return value.model_dump(mode="json", by_alias=True, exclude_none=False)


def _node(kind: str, identifier: str, value: Any) -> NodeEnvelope:
    return NodeEnvelope(kind=kind, id=identifier, payload=_dump(value))


def project_detail_to_snapshot(
    project: ProjectDetail,
    *,
    created_at: str | None = None,
) -> BlackboardSnapshot:
    """Create a canonical snapshot from one server ``ProjectDetail``.

    Node identifiers retain the server's identifiers so Intent ``from`` values
    and graph edge endpoints remain directly addressable.  The kind carried by
    each envelope disambiguates the small collections that use a separate
    server-side namespace (stages and the project itself).
    """
    nodes: list[NodeEnvelope] = [
        _node("project", project.project.id, project.project),
        *(_node("fact", item.id, item) for item in project.facts),
        *(_node("intent", item.id, item) for item in project.intents),
        *(_node("hint", item.id, item) for item in project.hints),
        *(_node("review", item.id, item) for item in project.reviews),
        *(_node("intent_error", item.id, item) for item in project.errors),
        *(_node("stage", item.stage_id, item) for item in project.stages),
        *(_node("decision", item.id, item) for item in project.decisions),
    ]
    node_ids = [node.id for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("ProjectDetail contains duplicate node identifiers")

    edges = [
        EdgeEnvelope(
            id=edge.id,
            source_kind=edge.source_kind,
            source_id=edge.source_id,
            target_kind=edge.target_kind,
            target_id=edge.target_id,
            relation_type=edge.relation_type,
            payload={
                "source_generation": edge.source_generation,
                "created_at": edge.created_at,
                "created_by": edge.created_by,
                "metadata": edge.metadata,
            },
        )
        for edge in project.edges
    ]
    edge_ids = [edge.id for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("ProjectDetail contains duplicate graph edge identifiers")

    return BlackboardSnapshot(
        project_id=project.project.id,
        graph_revision=project.project.graph_revision,
        source_generation=project.project.source_generation,
        plan_revision=project.project.plan_revision,
        nodes=nodes,
        edges=edges,
        created_at=created_at or _now(),
    )


# Explicit alias for call sites that prefer the contract's noun first.
blackboard_snapshot_from_project_detail = project_detail_to_snapshot
to_blackboard_snapshot = project_detail_to_snapshot


__all__ = [
    "blackboard_snapshot_from_project_detail",
    "project_detail_to_snapshot",
    "to_blackboard_snapshot",
]
