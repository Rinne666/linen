from __future__ import annotations

import pytest

from linen.contracts import ArtifactMetadata, BlackboardSnapshot, ContextRequest, EdgeEnvelope, NodeEnvelope
from linen.dispatcher.context import (
    ContextProjector,
    ContextProjectionError,
    InvalidContextRequest,
    StaleContextRevision,
)
from linen.dispatcher.contract_adapters import project_detail_to_snapshot
from linen.server.models import Fact, GraphEdge, Hint, Intent, ProjectDetail, ProjectMeta


def _snapshot(*, neighbor_count: int = 3, graph_revision: int = 4, with_edges: bool = True) -> BlackboardSnapshot:
    nodes = [
        NodeEnvelope(kind="project", id="p1", payload={"title": "project"}),
        NodeEnvelope(kind="intent", id="i1", payload={"id": "i1", "from": ["f1"]}),
        NodeEnvelope(kind="fact", id="f1", payload={"description": "source"}),
        NodeEnvelope(kind="fact", id="unrelated", payload={"description": "unrelated"}),
    ]
    edges = []
    if with_edges:
        edges.extend([
            EdgeEnvelope(id="e-intent", source_kind="fact", source_id="f1", target_kind="intent", target_id="i1", relation_type="produces"),
            EdgeEnvelope(id="e-source", source_kind="fact", source_id="f1", target_kind="fact", target_id="f2", relation_type="supports"),
            EdgeEnvelope(id="e-project-unrelated", source_kind="project", source_id="p1", target_kind="fact", target_id="unrelated", relation_type="supports"),
        ])
        nodes.append(NodeEnvelope(kind="fact", id="f2", payload={"description": "connected"}))
        for index in range(neighbor_count):
            identifier = f"n{index:03d}"
            nodes.append(NodeEnvelope(kind="fact", id=identifier, payload={"description": identifier}))
            edges.append(EdgeEnvelope(id=f"e-{identifier}", source_kind="fact", source_id="f1", target_kind="fact", target_id=identifier, relation_type="depends_on"))
    return BlackboardSnapshot(
        project_id="p1",
        graph_revision=graph_revision,
        source_generation=1,
        plan_revision=1,
        nodes=nodes,
        edges=edges,
        created_at="2026-01-01T00:00:00Z",
    )


def test_project_detail_adapter_preserves_intent_edge_and_is_canonical() -> None:
    intent = Intent(
        id="i001", from_=["f001"], description="investigate", creator="reasoner",
        worker="test-worker", created_at="2026-01-01T00:00:02Z",
    )
    project = ProjectDetail(
        project=ProjectMeta(
            id="proj_001", title="test", status="active", bootstrap_enabled=True,
            created_at="2026-01-01T00:00:00Z",
        ),
        facts=[Fact(id="origin", description="start"), Fact(id="goal", description="finish"), Fact(id="f001", description="known")],
        intents=[intent],
        hints=[Hint(id="h001", content="hint", creator="human", created_at="2026-01-01T00:00:01Z")],
    )
    project = project.model_copy(update={
        "edges": [GraphEdge(
            id="e001",
            source_kind="fact",
            source_id="f001",
            target_kind="intent",
            target_id="i001",
            relation_type="produces",
            created_at="2026-01-01T00:00:03Z",
            created_by="dispatcher",
        )],
    })
    first = project_detail_to_snapshot(project, created_at="2026-01-01T00:00:00Z")
    second = project_detail_to_snapshot(project, created_at="2026-01-02T00:00:00Z")
    assert first.snapshot_id == second.snapshot_id
    assert {node.id for node in first.nodes} >= {"proj_001", "i001", "f001"}
    assert [(edge.source_id, edge.target_id) for edge in first.edges] == [("f001", "i001")]


def test_projection_is_stable_bounded_and_excludes_unrelated_nodes() -> None:
    snapshot = _snapshot(neighbor_count=40)
    projector = ContextProjector(max_nodes=20)
    projection = projector.project(snapshot, Intent(
        id="i1", from_=["f1"], description="verify", creator="dispatcher",
        created_at="2026-01-01T00:00:00Z",
    ))
    assert len(projection.node_ids) == 20
    assert {"p1", "i1", "f1"}.issubset(projection.node_ids)
    assert "unrelated" not in projection.node_ids
    assert "e-intent" in projection.edge_ids
    assert projection.projection_digest is not None

    reordered = snapshot.model_copy(update={
        "nodes": list(reversed(snapshot.nodes)),
        "edges": list(reversed(snapshot.edges)),
    })
    same = projector.project(reordered, "i1")
    assert same.projection_id == projection.projection_id
    assert same.projection_digest == projection.projection_digest


def test_projection_requires_explicit_degraded_for_legacy_graph() -> None:
    snapshot = _snapshot(with_edges=False)
    with pytest.raises(ContextProjectionError, match="degraded=True"):
        ContextProjector().project(snapshot, "i1")
    projection = ContextProjector().project(snapshot, "i1", degraded=True)
    assert projection.context["degraded"] is True
    assert projection.edge_ids == []
    assert set(projection.node_ids) == {"p1", "i1", "f1"}


def test_frontier_projection_is_explicit_stable_and_seed_only_when_empty() -> None:
    snapshot = _snapshot(neighbor_count=40)
    projector = ContextProjector(max_nodes=20)
    projection = projector.project_frontier(snapshot, ["f1"])
    assert len(projection.node_ids) == 20
    assert {"p1", "f1"}.issubset(projection.node_ids)
    assert "i1" in projection.node_ids
    assert "unrelated" not in projection.node_ids
    assert projection.intent_id is None
    reordered = snapshot.model_copy(update={
        "nodes": list(reversed(snapshot.nodes)),
        "edges": list(reversed(snapshot.edges)),
    })
    assert projector.project_frontier(reordered, ["f1"]).projection_id == projection.projection_id

    empty = projector.project_frontier(snapshot, [])
    assert empty.node_ids == ["p1"]
    assert empty.edge_ids == []

    legacy = projector.project_frontier(
        snapshot.model_copy(update={"edges": []}), ["f1"], degraded=True,
    )
    assert legacy.context["degraded"] is True
    assert set(legacy.node_ids) == {"p1", "f1"}

    with pytest.raises(InvalidContextRequest, match="unknown context node"):
        projector.project_frontier(snapshot, ["missing"])


def test_revision_and_context_request_validation() -> None:
    projector = ContextProjector(allowed_relation_types={"produces", "supports"})
    snapshot = _snapshot()
    with pytest.raises(StaleContextRevision):
        projector.project(snapshot, "i1", current_graph_revision=5)
    with pytest.raises(InvalidContextRequest, match="unknown context node"):
        projector.project(snapshot, "i1", request=ContextRequest(
            node_ids=["missing"], reason="need more context",
        ))
    with pytest.raises(InvalidContextRequest, match="unknown context relation"):
        projector.project(snapshot, "i1", request=ContextRequest(
            relation_types=["does_not_exist"], reason="need more context",
        ))
    with pytest.raises(InvalidContextRequest, match="not allowed"):
        projector.project(snapshot, "i1", request=ContextRequest(
            relation_types=["depends_on"], reason="need more context",
        ))


def test_valid_context_request_expands_projection_without_full_graph() -> None:
    snapshot = _snapshot(neighbor_count=2)
    projector = ContextProjector()
    initial = projector.project(snapshot, "i1")
    expanded = projector.expand(
        initial,
        snapshot,
        ContextRequest(node_ids=["f2"], relation_types=["supports"], reason="need source proof"),
    )
    assert "f2" in expanded.node_ids
    assert "e-source" in expanded.edge_ids
    assert "unrelated" not in expanded.node_ids
    with pytest.raises(StaleContextRevision):
        projector.expand(initial, snapshot.model_copy(update={"graph_revision": 5}), ContextRequest(
            node_ids=["f2"], relation_types=["supports"], reason="stale",
        ))


def _artifact(artifact_id: str, *, related_node_ids: list[str], project_id: str = "p1") -> ArtifactMetadata:
    return ArtifactMetadata(
        artifact_id=artifact_id,
        project_id=project_id,
        kind="evidence",
        workspace_path=f"artifacts/{artifact_id}.txt",
        sha256="a" * 64,
        media_type="text/plain",
        byte_size=12,
        related_node_ids=related_node_ids,
    )


def test_artifact_catalog_projects_related_metadata_stably_without_reading_content() -> None:
    snapshot = _snapshot()
    catalog = [
        _artifact("art-unrelated", related_node_ids=["unrelated"]),
        _artifact("art-source", related_node_ids=["f1"]),
    ]
    projector = ContextProjector()
    projection = projector.project(snapshot, "i1", artifact_catalog=reversed(catalog))
    reordered = projector.project(snapshot, "i1", artifact_catalog=catalog)

    assert projection.projection_id == reordered.projection_id
    assert projection.artifact_ids == ["art-source"]
    assert projection.context["artifacts"] == [_artifact("art-source", related_node_ids=["f1"]).model_dump(mode="json")]
    assert "content" not in projection.context["artifacts"][0]


def test_artifact_request_requires_catalog_and_known_same_project_artifact() -> None:
    snapshot = _snapshot()
    request = ContextRequest(artifact_ids=["art-source"], reason="need source proof")
    with pytest.raises(InvalidContextRequest, match="without an artifact catalog"):
        ContextProjector().project(snapshot, "i1", request=request)

    with pytest.raises(InvalidContextRequest, match="unknown artifact IDs"):
        ContextProjector().project(
            snapshot,
            "i1",
            request=request,
            artifact_catalog=[_artifact("other", related_node_ids=["f1"])],
        )
    with pytest.raises(InvalidContextRequest, match="another project"):
        ContextProjector().project(
            snapshot,
            "i1",
            artifact_catalog=[_artifact("art-source", related_node_ids=["f1"], project_id="p2")],
        )


def test_artifact_limit_and_expand_preserve_existing_metadata() -> None:
    snapshot = _snapshot()
    source = _artifact("art-source", related_node_ids=["f1"])
    connected = _artifact("art-connected", related_node_ids=["f2"])
    projector = ContextProjector(max_artifacts=2)
    initial = projector.project(snapshot, "i1", artifact_catalog=[source])
    expanded = projector.expand(
        initial,
        snapshot,
        ContextRequest(artifact_ids=["art-connected"], node_ids=["f2"], reason="need connected proof"),
        artifact_catalog=[source, connected],
    )
    assert expanded.artifact_ids == ["art-connected", "art-source"]
    assert [item["artifact_id"] for item in expanded.context["artifacts"]] == ["art-connected", "art-source"]

    truncated = projector.project(
        snapshot,
        "i1",
        artifact_catalog=[source, connected],
        max_artifacts=1,
    )
    assert truncated.context["artifact_selection_truncated"] is True
    assert truncated.context["artifact_available_count"] == 2
    assert len(truncated.artifact_ids) == 1
    with pytest.raises(ContextProjectionError, match="max_artifacts=1"):
        projector.project(
            snapshot,
            "i1",
            request=ContextRequest(artifact_ids=["art-source", "art-connected"], reason="need both"),
            artifact_catalog=[source, connected],
            max_artifacts=1,
        )
    prioritized = projector.project(
        snapshot,
        "i1",
        request=ContextRequest(artifact_ids=["art-source"], reason="explicit source proof"),
        artifact_catalog=[source, connected],
        max_artifacts=1,
    )
    assert prioritized.artifact_ids == ["art-source"]
    assert prioritized.context["artifact_selection_truncated"] is True


def test_many_auto_related_artifacts_are_stably_truncated() -> None:
    snapshot = _snapshot()
    catalog = [
        _artifact(
            f"art-{index:02d}",
            related_node_ids=["f1"],
        ).model_copy(update={"created_at": f"2026-01-{index + 1:02d}T00:00:00Z"})
        for index in range(25)
    ]
    projector = ContextProjector(max_artifacts=3)
    first = projector.project(snapshot, "i1", artifact_catalog=catalog)
    second = projector.project(snapshot, "i1", artifact_catalog=reversed(catalog))

    assert first.projection_id == second.projection_id
    assert first.context["artifact_selection_truncated"] is True
    assert first.context["artifact_available_count"] == 25
    assert first.artifact_ids == ["art-22", "art-23", "art-24"]
    assert [item["artifact_id"] for item in first.context["artifacts"]] == first.artifact_ids
