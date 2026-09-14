"""Deterministic Context Projector for the dispatcher.

The projector is deliberately pure: it consumes a server response (or an
already adapted snapshot), never queries the server, and never writes state.
That makes the selected context reproducible from a graph revision and keeps a
worker from gaining an implicit full-blackboard read capability.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from linen.contracts import ArtifactMetadata, BlackboardSnapshot, ContextProjection, ContextRequest, EdgeEnvelope, NodeEnvelope
from linen.contracts.common import canonical_digest
from linen.server.models import Intent, ProjectDetail

from linen.dispatcher.contract_adapters import project_detail_to_snapshot


class ContextProjectionError(ValueError):
    """Base error for an invalid or unsafe context projection request."""


class InvalidContextRequest(ContextProjectionError):
    """The worker requested nodes or relations outside the current graph."""


class StaleContextRevision(ContextProjectionError):
    """The supplied snapshot/projection is no longer current."""


class ContextProjector:
    """Select a stable, bounded neighborhood around one Intent.

    ``max_nodes`` is intentionally constrained to a useful bounded range.  A
    graph with no explicit edges is treated as a legacy graph and is rejected
    unless the caller explicitly opts into a degraded seed-only projection.
    This is never a fallback to the complete graph.
    """

    def __init__(
        self,
        *,
        max_nodes: int = 60,
        max_hops: int = 1,
        max_artifacts: int = 20,
        allowed_relation_types: Iterable[str] | None = None,
    ) -> None:
        if not 20 <= max_nodes <= 100:
            raise ValueError("max_nodes must be between 20 and 100")
        if max_hops < 0:
            raise ValueError("max_hops must not be negative")
        self._validate_max_artifacts(max_artifacts)
        self.max_nodes = max_nodes
        self.max_hops = max_hops
        self.max_artifacts = max_artifacts
        self.allowed_relation_types = (
            frozenset(value.strip() for value in allowed_relation_types if value.strip())
            if allowed_relation_types is not None
            else None
        )

    def snapshot(self, project: ProjectDetail, *, created_at: str | None = None) -> BlackboardSnapshot:
        """Adapt a server project response to the stable snapshot contract."""
        return project_detail_to_snapshot(project, created_at=created_at)

    def project(
        self,
        source: ProjectDetail | BlackboardSnapshot,
        intent: Intent | str,
        *,
        stage: str | None = None,
        request: ContextRequest | Mapping[str, Any] | None = None,
        degraded: bool = False,
        current_graph_revision: int | None = None,
        artifact_catalog: Iterable[ArtifactMetadata] | None = None,
        max_artifacts: int | None = None,
    ) -> ContextProjection:
        """Project an Intent and its bounded graph neighborhood.

        ``source`` may be a ``ProjectDetail`` for convenience or a canonical
        ``BlackboardSnapshot`` when callers already own the adaptation step.
        The returned ``ContextProjection.context`` contains the selected node
        and edge envelopes because the public contract stores their IDs for
        indexing while workers need the actual projected data.
        """
        snapshot = self._as_snapshot(source)
        artifact_map = self._artifact_catalog(snapshot, artifact_catalog, max_artifacts)
        self._check_revision(snapshot.graph_revision, current_graph_revision)
        intent_id, from_ids = self._intent_identity(source, intent)
        nodes = self._nodes(snapshot)
        if intent_id not in nodes or nodes[intent_id].kind != "intent":
            raise InvalidContextRequest(f"unknown Intent node: {intent_id}")
        missing = [identifier for identifier in from_ids if identifier not in nodes]
        if missing:
            raise InvalidContextRequest(f"Intent source nodes are missing: {', '.join(sorted(missing))}")

        parsed_request = self._parse_request(request)
        parsed_request = self._normalize_request(parsed_request)
        self.validate_request(
            snapshot,
            parsed_request,
            current_graph_revision=current_graph_revision,
            artifact_catalog=artifact_map.values() if artifact_map is not None else None,
            max_artifacts=max_artifacts,
        )
        if not snapshot.edges and not degraded:
            raise ContextProjectionError(
                "graph has no explicit edges; pass degraded=True for a legacy seed-only projection"
            )
        seed_ids = [snapshot.project_id, intent_id, *from_ids]
        if stage:
            stage_id = stage.strip()
            if not stage_id:
                raise InvalidContextRequest("stage must not be empty")
            if stage_id in nodes:
                seed_ids.append(stage_id)
        if parsed_request is not None:
            seed_ids.extend(parsed_request.node_ids)
        selected, selected_edges = self._select(
            snapshot,
            seed_ids,
            traversal_seeds=[intent_id, *from_ids, *(parsed_request.node_ids if parsed_request else [])],
            relation_types=(parsed_request.relation_types if parsed_request else None),
        )
        return self._make_projection(
            snapshot,
            nodes,
            selected,
            selected_edges,
            intent_id=intent_id,
            stage=stage,
            request=parsed_request,
            degraded=degraded,
            artifact_catalog=artifact_map,
            max_artifacts=max_artifacts,
        )

    def project_frontier(
        self,
        source: ProjectDetail | BlackboardSnapshot,
        seed_ids: Iterable[str],
        *,
        stage: str | None = None,
        request: ContextRequest | Mapping[str, Any] | None = None,
        degraded: bool = False,
        current_graph_revision: int | None = None,
        artifact_catalog: Iterable[ArtifactMetadata] | None = None,
        max_artifacts: int | None = None,
    ) -> ContextProjection:
        """Project a bounded neighborhood from explicit non-Intent seeds.

        This is the multi-root counterpart to :meth:`project` for Reason
        passes that do not have one Intent as their target.  The project node
        is always mandatory; every other root must be explicitly supplied by
        the caller.  In particular, an empty seed list projects only the
        project (plus requested nodes), never the entire blackboard.
        """
        snapshot = self._as_snapshot(source)
        artifact_map = self._artifact_catalog(snapshot, artifact_catalog, max_artifacts)
        self._check_revision(snapshot.graph_revision, current_graph_revision)
        nodes = self._nodes(snapshot)
        if snapshot.project_id not in nodes or nodes[snapshot.project_id].kind != "project":
            raise InvalidContextRequest(f"unknown project node: {snapshot.project_id}")

        roots: list[str] = []
        for identifier in seed_ids:
            if not isinstance(identifier, str) or not identifier.strip():
                raise InvalidContextRequest("frontier seed IDs must be non-empty strings")
            normalized = identifier.strip()
            if normalized not in nodes:
                raise InvalidContextRequest(f"unknown context node ID: {normalized}")
            if normalized not in roots:
                roots.append(normalized)

        parsed_request = self._parse_request(request)
        parsed_request = self._normalize_request(parsed_request)
        self.validate_request(
            snapshot,
            parsed_request,
            current_graph_revision=current_graph_revision,
            artifact_catalog=artifact_map.values() if artifact_map is not None else None,
            max_artifacts=max_artifacts,
        )
        if not snapshot.edges and not degraded:
            raise ContextProjectionError(
                "graph has no explicit edges; pass degraded=True for a legacy seed-only projection"
            )
        if stage is not None:
            stage_id = stage.strip()
            if not stage_id:
                raise InvalidContextRequest("stage must not be empty")
            if stage_id not in nodes:
                raise InvalidContextRequest(f"unknown stage node: {stage_id}")
            roots.append(stage_id)
        if parsed_request is not None:
            roots.extend(parsed_request.node_ids)
        selected, selected_edges = self._select(
            snapshot,
            [snapshot.project_id, *roots],
            # Project is mandatory metadata, not an implicit graph-wide
            # traversal root.  Other roots are explicit caller intent.
            traversal_seeds=[identifier for identifier in roots if identifier != snapshot.project_id],
            relation_types=(parsed_request.relation_types if parsed_request else None),
        )
        return self._make_projection(
            snapshot,
            nodes,
            selected,
            selected_edges,
            intent_id=None,
            stage=stage,
            request=parsed_request,
            degraded=degraded,
            artifact_catalog=artifact_map,
            max_artifacts=max_artifacts,
        )

    def expand(
        self,
        projection: ContextProjection,
        source: ProjectDetail | BlackboardSnapshot,
        request: ContextRequest | Mapping[str, Any],
        *,
        current_graph_revision: int | None = None,
        degraded: bool | None = None,
        artifact_catalog: Iterable[ArtifactMetadata] | None = None,
        max_artifacts: int | None = None,
    ) -> ContextProjection:
        """Validate and apply a worker ``context_request`` to a projection."""
        snapshot = self._as_snapshot(source)
        artifact_map = self._artifact_catalog(snapshot, artifact_catalog, max_artifacts)
        self._check_revision(snapshot.graph_revision, current_graph_revision)
        if projection.project_id != snapshot.project_id or projection.snapshot_id != snapshot.snapshot_id:
            raise StaleContextRevision("context projection does not belong to this snapshot")
        if projection.graph_revision != snapshot.graph_revision:
            raise StaleContextRevision(
                f"projection revision {projection.graph_revision} is stale; current is {snapshot.graph_revision}"
            )
        parsed_request = self._parse_request(request)
        parsed_request = self._normalize_request(parsed_request)
        self.validate_request(
            snapshot,
            parsed_request,
            current_graph_revision=current_graph_revision,
            artifact_catalog=artifact_map.values() if artifact_map is not None else None,
            max_artifacts=max_artifacts,
        )
        is_degraded = bool(projection.context.get("degraded", False)) if degraded is None else degraded
        if not snapshot.edges and not is_degraded:
            raise ContextProjectionError(
                "graph has no explicit edges; pass degraded=True for a legacy seed-only projection"
            )
        nodes = self._nodes(snapshot)
        selected_ids = list(projection.node_ids) + list(parsed_request.node_ids)
        selected, selected_edges = self._select(
            snapshot,
            selected_ids,
            relation_types=parsed_request.relation_types or None,
            initial_selected=projection.node_ids,
            traversal_seeds=parsed_request.node_ids,
        )
        return self._make_projection(
            snapshot,
            nodes,
            selected,
            selected_edges,
            intent_id=projection.intent_id,
            stage=projection.stage,
            request=parsed_request,
            degraded=is_degraded,
            existing_artifact_ids=projection.artifact_ids,
            existing_artifacts=projection.context.get("artifacts", []),
            artifact_catalog=artifact_map,
            max_artifacts=max_artifacts,
        )

    def validate_request(
        self,
        snapshot: BlackboardSnapshot,
        request: ContextRequest | None,
        *,
        current_graph_revision: int | None = None,
        artifact_catalog: Iterable[ArtifactMetadata] | None = None,
        max_artifacts: int | None = None,
    ) -> ContextRequest | None:
        """Validate a request against node/relation existence and policy."""
        self._check_revision(snapshot.graph_revision, current_graph_revision)
        catalog = self._artifact_catalog(snapshot, artifact_catalog, max_artifacts)
        if request is None:
            return None
        nodes = self._nodes(snapshot)
        missing_nodes = sorted(set(request.node_ids) - set(nodes))
        if missing_nodes:
            raise InvalidContextRequest(f"unknown context node IDs: {', '.join(missing_nodes)}")
        known_relations = {edge.relation_type for edge in snapshot.edges}
        unknown_relations = sorted(set(request.relation_types) - known_relations)
        if unknown_relations:
            raise InvalidContextRequest(
                f"unknown context relation types: {', '.join(unknown_relations)}"
            )
        if self.allowed_relation_types is not None:
            disallowed = sorted(set(request.relation_types) - self.allowed_relation_types)
            if disallowed:
                raise InvalidContextRequest(
                    f"context relation types are not allowed: {', '.join(disallowed)}"
                )
        if request.artifact_ids:
            if catalog is None:
                raise InvalidContextRequest("artifact context is unavailable without an artifact catalog")
            missing_artifacts = sorted(set(request.artifact_ids) - set(catalog))
            if missing_artifacts:
                raise InvalidContextRequest(
                    f"unknown artifact IDs: {', '.join(missing_artifacts)}"
                )
            limit = self._effective_max_artifacts(max_artifacts)
            if len(set(request.artifact_ids)) > limit:
                raise ContextProjectionError(
                    f"requested artifacts exceed max_artifacts={limit}"
                )
        return request

    @staticmethod
    def _validate_max_artifacts(value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
            raise ValueError("max_artifacts must be between 1 and 100")

    def _effective_max_artifacts(self, value: int | None) -> int:
        limit = self.max_artifacts if value is None else value
        self._validate_max_artifacts(limit)
        return limit

    def _artifact_catalog(
        self,
        snapshot: BlackboardSnapshot,
        artifact_catalog: Iterable[ArtifactMetadata] | None,
        max_artifacts: int | None,
    ) -> dict[str, ArtifactMetadata] | None:
        """Validate and materialize an optional immutable metadata catalog.

        Catalog materialization is intentionally the only work performed here;
        artifact content is never opened by the pure projector.  Materializing
        once also makes generator inputs deterministic for the subsequent
        request validation and projection steps.
        """
        self._effective_max_artifacts(max_artifacts)
        if artifact_catalog is None:
            return None
        catalog: dict[str, ArtifactMetadata] = {}
        for artifact in artifact_catalog:
            if not isinstance(artifact, ArtifactMetadata):
                raise InvalidContextRequest("artifact catalog must contain ArtifactMetadata")
            if artifact.project_id != snapshot.project_id:
                raise InvalidContextRequest(
                    f"artifact {artifact.artifact_id} belongs to another project"
                )
            previous = catalog.get(artifact.artifact_id)
            if previous is not None and previous != artifact:
                raise InvalidContextRequest(
                    f"artifact catalog contains conflicting metadata for {artifact.artifact_id}"
                )
            catalog[artifact.artifact_id] = artifact
        return {identifier: catalog[identifier] for identifier in sorted(catalog)}

    @staticmethod
    def _as_snapshot(source: ProjectDetail | BlackboardSnapshot) -> BlackboardSnapshot:
        return source if isinstance(source, BlackboardSnapshot) else project_detail_to_snapshot(source)

    @staticmethod
    def _parse_request(
        request: ContextRequest | Mapping[str, Any] | None,
    ) -> ContextRequest | None:
        if request is None:
            return None
        return request if isinstance(request, ContextRequest) else ContextRequest.model_validate(request)

    @staticmethod
    def _normalize_request(request: ContextRequest | None) -> ContextRequest | None:
        """Apply the contract's set-like semantics before hashing a projection."""
        if request is None:
            return None
        return request.model_copy(update={
            "node_ids": sorted(set(request.node_ids)),
            "relation_types": sorted(set(request.relation_types)),
            "artifact_ids": sorted(set(request.artifact_ids)),
        })

    @staticmethod
    def _check_revision(snapshot_revision: int, current_revision: int | None) -> None:
        if current_revision is not None and snapshot_revision != current_revision:
            raise StaleContextRevision(
                f"snapshot revision {snapshot_revision} is stale; current is {current_revision}"
            )

    @staticmethod
    def _nodes(snapshot: BlackboardSnapshot) -> dict[str, NodeEnvelope]:
        return {node.id: node for node in snapshot.nodes}

    @staticmethod
    def _intent_identity(
        source: ProjectDetail | BlackboardSnapshot,
        intent: Intent | str,
    ) -> tuple[str, list[str]]:
        if isinstance(intent, Intent):
            return intent.id, list(intent.from_)
        intent_id = intent.strip()
        if not intent_id:
            raise InvalidContextRequest("intent_id must not be empty")
        if isinstance(source, ProjectDetail):
            item = next((item for item in source.intents if item.id == intent_id), None)
            if item is None:
                raise InvalidContextRequest(f"unknown Intent: {intent_id}")
            return item.id, list(item.from_)
        node = next((node for node in source.nodes if node.id == intent_id and node.kind == "intent"), None)
        if node is None:
            raise InvalidContextRequest(f"unknown Intent: {intent_id}")
        raw = node.payload.get("from", node.payload.get("from_", []))
        if not isinstance(raw, list) or any(not isinstance(value, str) for value in raw):
            raise InvalidContextRequest(f"Intent {intent_id} has invalid source references")
        return intent_id, raw

    def _select(
        self,
        snapshot: BlackboardSnapshot,
        seed_ids: Iterable[str],
        *,
        relation_types: Iterable[str] | None = None,
        initial_selected: Iterable[str] = (),
        traversal_seeds: Iterable[str] | None = None,
    ) -> tuple[set[str], set[str]]:
        nodes = self._nodes(snapshot)
        selected = {identifier for identifier in [*initial_selected, *seed_ids] if identifier in nodes}
        frontier = {
            identifier for identifier in (traversal_seeds if traversal_seeds is not None else seed_ids)
            if identifier in nodes
        }
        if len(selected) > self.max_nodes:
            raise ContextProjectionError(
                f"mandatory context nodes exceed max_nodes={self.max_nodes}"
            )
        edges = sorted(snapshot.edges, key=self._edge_key)
        relation_filter = set(relation_types or ())
        for _ in range(self.max_hops):
            candidates: set[str] = set()
            for edge in edges:
                if relation_filter and edge.relation_type not in relation_filter:
                    continue
                if edge.source_id in frontier and edge.target_id in nodes:
                    candidates.add(edge.target_id)
                if edge.target_id in frontier and edge.source_id in nodes:
                    candidates.add(edge.source_id)
            candidates -= selected
            room = self.max_nodes - len(selected)
            if room <= 0 or not candidates:
                break
            added = set(sorted(candidates)[:room])
            selected.update(added)
            frontier = added
        # A request's relation types constrain which edges may be traversed to
        # expand the neighborhood.  Once a node is selected, retain every
        # explicit edge between selected nodes so the original Intent/source
        # connection is never silently dropped during expansion.
        selected_edges = {
            edge.id
            for edge in edges
            if edge.source_id in selected
            and edge.target_id in selected
        }
        return selected, selected_edges

    @staticmethod
    def _edge_key(edge: EdgeEnvelope) -> tuple[str, str, str, str, str, str]:
        return (
            edge.id,
            edge.source_kind,
            edge.source_id,
            edge.target_kind,
            edge.target_id,
            edge.relation_type,
        )

    def _make_projection(
        self,
        snapshot: BlackboardSnapshot,
        nodes: dict[str, NodeEnvelope],
        selected: set[str],
        selected_edges: set[str],
        *,
        intent_id: str | None,
        stage: str | None,
        request: ContextRequest | None,
        degraded: bool,
        existing_artifact_ids: Iterable[str] = (),
        existing_artifacts: Iterable[Any] = (),
        artifact_catalog: Mapping[str, ArtifactMetadata] | None = None,
        max_artifacts: int | None = None,
    ) -> ContextProjection:
        selected_nodes = sorted((nodes[identifier] for identifier in selected), key=lambda node: (node.kind, node.id))
        edge_by_id = {edge.id: edge for edge in snapshot.edges}
        edges = sorted((edge_by_id[identifier] for identifier in selected_edges), key=self._edge_key)
        node_ids = [node.id for node in selected_nodes]
        edge_ids = [edge.id for edge in edges]
        existing_metadata = {
            item["artifact_id"]: item
            for item in existing_artifacts
            if isinstance(item, Mapping) and isinstance(item.get("artifact_id"), str)
        }
        limit = self._effective_max_artifacts(max_artifacts)
        existing_ids = {
            identifier for identifier in existing_artifact_ids if isinstance(identifier, str)
        }
        requested_ids = set(request.artifact_ids) if request is not None else set()
        protected_ids = existing_ids | requested_ids
        if len(protected_ids) > limit:
            raise ContextProjectionError(
                f"explicit/existing artifacts exceed max_artifacts={limit}"
            )
        available_artifacts: list[ArtifactMetadata] = []
        if artifact_catalog is not None:
            selected_ids = set(node_ids)
            available_artifacts = [
                artifact
                for artifact in artifact_catalog.values()
                if selected_ids.intersection(artifact.related_node_ids)
            ]
        available_ids = {artifact.artifact_id for artifact in available_artifacts}
        if artifact_catalog is not None:
            # An explicitly requested catalog member is available even when
            # it has no relationship to one of the selected nodes.
            available_ids.update(
                artifact_id for artifact_id in protected_ids if artifact_id in artifact_catalog
            )
        automatic_ids = available_ids - protected_ids
        room = limit - len(protected_ids)
        if len(automatic_ids) > room:
            # Explicitly requested and previously selected artifacts are never
            # silently evicted.  Auto-associated artifacts use a stable,
            # metadata-only priority so a large historical catalog remains
            # projectable under the small context bound.
            dated = sorted(
                (artifact for artifact in available_artifacts if artifact.artifact_id in automatic_ids
                 and artifact.created_at is not None),
                key=lambda artifact: artifact.artifact_id,
            )
            dated.sort(key=lambda artifact: artifact.created_at or "", reverse=True)
            undated = sorted(
                (artifact for artifact in available_artifacts if artifact.artifact_id in automatic_ids
                 and artifact.created_at is None),
                key=lambda artifact: artifact.artifact_id,
            )
            automatic_ids = {artifact.artifact_id for artifact in [*dated, *undated][:room]}
            artifact_selection_truncated = True
        else:
            artifact_selection_truncated = False
        artifact_ids = protected_ids | automatic_ids
        artifacts: list[dict[str, Any]] = []
        for artifact_id in sorted(artifact_ids):
            if artifact_catalog is not None and artifact_id in artifact_catalog:
                metadata = artifact_catalog[artifact_id].model_dump(mode="json")
            elif artifact_id in existing_metadata:
                # Preserve metadata already present in an earlier projection
                # when a caller supplies a partial catalog during expansion.
                metadata = dict(existing_metadata[artifact_id])
            else:
                raise InvalidContextRequest(
                    f"artifact metadata is unavailable for {artifact_id}"
                )
            artifacts.append(metadata)
        stage_node = next((node for node in selected_nodes if node.kind == "stage" and node.id == stage), None)
        context: dict[str, Any] = {
            "project": nodes[snapshot.project_id].model_dump(mode="json"),
            "nodes": [node.model_dump(mode="json") for node in selected_nodes],
            "edges": [edge.model_dump(mode="json") for edge in edges],
            "stage": stage_node.model_dump(mode="json") if stage_node is not None else ({"id": stage} if stage else None),
            "degraded": degraded,
            "artifacts": artifacts,
            "artifact_selection_truncated": artifact_selection_truncated,
            "artifact_available_count": len(available_ids),
        }
        identity = {
            "project_id": snapshot.project_id,
            "snapshot_id": snapshot.snapshot_id,
            "graph_revision": snapshot.graph_revision,
            "source_generation": snapshot.source_generation,
            "plan_revision": snapshot.plan_revision,
            "intent_id": intent_id,
            "stage": stage,
            "node_ids": node_ids,
            "edge_ids": edge_ids,
            "artifact_ids": sorted(artifact_ids),
            "context": context,
            "request": request.model_dump(mode="json") if request else None,
            "selection_policy": (
                "intent-neighborhood-v1:degraded" if intent_id is not None and degraded
                else "intent-neighborhood-v1" if intent_id is not None
                else "frontier-v1:degraded" if degraded
                else "frontier-v1"
            ),
        }
        projection_id = f"ctx-{canonical_digest(identity)}"
        return ContextProjection(
            projection_id=projection_id,
            project_id=snapshot.project_id,
            snapshot_id=snapshot.snapshot_id or "",
            graph_revision=snapshot.graph_revision,
            source_generation=snapshot.source_generation,
            plan_revision=snapshot.plan_revision,
            intent_id=intent_id,
            stage=stage,
            node_ids=node_ids,
            edge_ids=edge_ids,
            artifact_ids=sorted(artifact_ids),
            context=context,
            selection_policy=identity["selection_policy"],
            request=request,
            created_at=snapshot.created_at,
        )


def project_context(
    source: ProjectDetail | BlackboardSnapshot,
    intent: Intent | str,
    **kwargs: Any,
) -> ContextProjection:
    """Convenience wrapper around :class:`ContextProjector`."""
    return ContextProjector().project(source, intent, **kwargs)


__all__ = [
    "ContextProjectionError",
    "ContextProjector",
    "InvalidContextRequest",
    "StaleContextRevision",
    "project_context",
]
