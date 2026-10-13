"""Check the evidence Reason used rather than unrelated board bookkeeping."""

from __future__ import annotations

from linen.contracts import BlackboardSnapshot, ContextProjection
from linen.dispatcher.contract_adapters import project_detail_to_snapshot
from linen.server.models import ProjectDetail


def _semantic_payload(kind: str, payload: dict) -> dict:
    ignored = {
        "project": {"graph_revision", "event_seq", "latest_event_seq", "reason", "reason_wait", "reason_last_seen_event_seq"},
        "intent": {"worker", "last_heartbeat_at"},
    }.get(kind, set())
    return {key: value for key, value in payload.items() if key not in ignored}


def reason_basis_is_current(projection: ContextProjection, fresh: ProjectDetail, *, complete: bool = False, snapshot: BlackboardSnapshot | None = None) -> bool:
    """Completion keeps its global fence; proposals use the read frontier.

    Existing projected nodes and edges must retain their semantic contents.
    New reviews/contradictions of read facts invalidate a pass even if those
    nodes were absent when it started. Unseen sibling evidence is left for the
    next event batch; accepting a proposal never acknowledges that batch.
    """
    meta = snapshot or fresh.project
    if (projection.source_generation, projection.plan_revision) != (meta.source_generation, meta.plan_revision):
        return False
    if complete:
        return projection.graph_revision == meta.graph_revision
    snapshot = snapshot or project_detail_to_snapshot(fresh)
    nodes = {(node.kind, node.id): node.payload for node in snapshot.nodes}
    original = projection.context.get("nodes", [])
    if not original:
        return projection.graph_revision == meta.graph_revision
    read_facts = set()
    read_reviews = set()
    for node in original:
        kind, identifier = node["kind"], node["id"]
        if kind == "stage":
            # Stage status is a derived scheduling projection, not evidence.
            continue
        current = nodes.get((kind, identifier))
        if current is None or _semantic_payload(kind, node["payload"]) != _semantic_payload(kind, current):
            return False
        if kind == "fact":
            read_facts.add(identifier)
        elif kind == "review":
            read_reviews.add(identifier)
    if any(node.kind == "review" and node.payload.get("fact_id") in read_facts and node.id not in read_reviews for node in snapshot.nodes):
        return False
    edges = {edge.id: edge.model_dump(mode="json") for edge in snapshot.edges}
    original_edges = {edge["id"]: edge for edge in projection.context.get("edges", [])}
    if any(edges.get(identifier) != edge for identifier, edge in original_edges.items()):
        return False
    for edge in snapshot.edges:
        if edge.id not in original_edges and edge.relation_type in {"contradicts", "invalidates", "supersedes", "reviews"}:
            if edge.source_id in read_facts or edge.target_id in read_facts:
                return False
    return True
