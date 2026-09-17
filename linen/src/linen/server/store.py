"""SQLite persistence adapters for runtime contracts.

SQLite remains the current-state source of truth; events are only an
append-only trace of mutations.  This module is the storage boundary for the
runtime contract path.  The remaining validation in this compatibility path
will move to ``server.kernel`` incrementally; no second repository or vNext
storage path should be added.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from linen.contracts import (
    ArtifactMetadata,
    AuditEventEnvelope,
    BlackboardSnapshot,
    ContextProjection,
    EdgeEnvelope,
    NodeEnvelope,
    RunEnvelope,
)
from linen.server.audit_state import append_event
from linen.server.services import get_project_or_404, utcnow


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def artifact_from_row(row: sqlite3.Row) -> ArtifactMetadata:
    return ArtifactMetadata(
        schema_version=row["schema_version"], artifact_id=row["artifact_id"], project_id=row["project_id"],
        kind=row["kind"], workspace_path=row["workspace_path"], sha256=row["sha256"],
        media_type=row["media_type"], byte_size=row["byte_size"], producer_run_id=row["producer_run_id"],
        related_node_ids=_loads(row["related_node_ids"], []), created_at=row["created_at"],
    )


def run_from_row(row: sqlite3.Row) -> RunEnvelope:
    return RunEnvelope(
        schema_version=row["schema_version"], run_id=row["run_id"], project_id=row["project_id"],
        intent_id=row["intent_id"], task_type=row["task_type"], stage=row["stage"], attempt=row["attempt"],
        idempotency_key=row["idempotency_key"], graph_revision=row["graph_revision"],
        source_generation=row["source_generation"], plan_revision=row["plan_revision"],
        context_projection_id=row["context_projection_id"], worker_manifest_digest=row["worker_manifest_digest"],
        timeout_seconds=row["timeout_seconds"], status=row["status"], worker_name=row["worker_name"],
        worker_type=row["worker_type"], started_at=row["started_at"], finished_at=row["finished_at"],
        artifact_ids=_loads(row["artifact_ids"], []), error_id=row["error_id"],
    )


def context_from_row(row: sqlite3.Row) -> ContextProjection:
    request = _loads(row["request"], None)
    return ContextProjection(
        schema_version=row["schema_version"], projection_id=row["projection_id"], project_id=row["project_id"],
        snapshot_id=row["snapshot_id"], graph_revision=row["graph_revision"],
        source_generation=row["source_generation"], plan_revision=row["plan_revision"], intent_id=row["intent_id"],
        stage=row["stage"], node_ids=_loads(row["node_ids"], []), edge_ids=_loads(row["edge_ids"], []),
        artifact_ids=_loads(row["artifact_ids"], []), context=_loads(row["context"], {}),
        selection_policy=row["selection_policy"], request=request, created_at=row["created_at"],
        projection_digest=row["projection_digest"],
    )


def event_from_row(row: sqlite3.Row) -> AuditEventEnvelope:
    return AuditEventEnvelope(
        schema_version=row["schema_version"] or 1, event_id=row["event_id"] or f"evt-{row['sequence']}",
        project_id=row["project_id"], run_id=row["run_id"], idempotency_key=row["idempotency_key"],
        event_type=row["event_type"], actor=row["actor"], entity_kind=row["entity_kind"], entity_id=row["entity_id"],
        sequence=row["sequence"], graph_revision=row["graph_revision"] or 0,
        source_generation=row["source_generation"] or 1, plan_revision=row["plan_revision"] or 1,
        payload=_loads(row["payload"], {}), created_at=row["created_at"],
    )


def register_artifact(conn: sqlite3.Connection, artifact: ArtifactMetadata) -> ArtifactMetadata:
    get_project_or_404(conn, artifact.project_id)
    if artifact.producer_run_id is not None and conn.execute(
        "SELECT 1 FROM runs WHERE project_id = ? AND run_id = ?", (artifact.project_id, artifact.producer_run_id)
    ).fetchone() is None:
        raise ValueError("producer_run_id does not belong to this project")
    value = artifact.model_dump(mode="json")
    value["created_at"] = artifact.created_at or utcnow()
    conn.execute(
        "INSERT OR IGNORE INTO artifacts (artifact_id, project_id, schema_version, kind, workspace_path, sha256, media_type, "
        "byte_size, producer_run_id, related_node_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (value["artifact_id"], value["project_id"], value["schema_version"], value["kind"], value["workspace_path"],
         value["sha256"], value["media_type"], value["byte_size"], value["producer_run_id"], _json(value["related_node_ids"]), value["created_at"]),
    )
    current = artifact_from_row(conn.execute(
        "SELECT * FROM artifacts WHERE project_id = ? AND artifact_id = ?", (artifact.project_id, artifact.artifact_id)
    ).fetchone())
    # Server-assigned creation time is not part of the caller's identity;
    # retrying the same registration without ``created_at`` is idempotent.
    current_data = current.model_dump(mode="json")
    requested_data = artifact.model_dump(mode="json")
    current_data.pop("created_at", None)
    requested_data.pop("created_at", None)
    if current_data != requested_data:
        raise ValueError("artifact_id already exists with different metadata")
    return current


def list_artifacts(conn: sqlite3.Connection, project_id: str) -> list[ArtifactMetadata]:
    get_project_or_404(conn, project_id)
    return [artifact_from_row(row) for row in conn.execute(
        "SELECT * FROM artifacts WHERE project_id = ? ORDER BY artifact_id", (project_id,)
    )]


def register_run(conn: sqlite3.Connection, run: RunEnvelope) -> RunEnvelope:
    now = utcnow()
    value = run.model_dump(mode="json")
    conn.execute(
        "INSERT OR IGNORE INTO runs (run_id, project_id, schema_version, intent_id, task_type, stage, attempt, idempotency_key, "
        "graph_revision, source_generation, plan_revision, context_projection_id, worker_manifest_digest, timeout_seconds, "
        "status, worker_name, worker_type, started_at, finished_at, artifact_ids, error_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (value["run_id"], value["project_id"], value["schema_version"], value["intent_id"], value["task_type"], value["stage"],
         value["attempt"], value["idempotency_key"], value["graph_revision"], value["source_generation"], value["plan_revision"],
         value["context_projection_id"], value["worker_manifest_digest"], value["timeout_seconds"], value["status"], value["worker_name"],
         value["worker_type"], value["started_at"], value["finished_at"], _json(value["artifact_ids"]), value["error_id"], now, now),
    )
    existing = conn.execute(
        "SELECT * FROM runs WHERE project_id = ? AND (run_id = ? OR idempotency_key = ?)",
        (run.project_id, run.run_id, run.idempotency_key),
    ).fetchone()
    if existing is None:
        raise RuntimeError("run registration did not produce a row")
    current = run_from_row(existing)
    return current


def list_runs(conn: sqlite3.Connection, project_id: str) -> list[RunEnvelope]:
    get_project_or_404(conn, project_id)
    return [run_from_row(row) for row in conn.execute("SELECT * FROM runs WHERE project_id = ? ORDER BY created_at, run_id", (project_id,))]


def transition_run(conn: sqlite3.Connection, run: RunEnvelope) -> RunEnvelope:
    row = conn.execute("SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (run.project_id, run.run_id)).fetchone()
    now = utcnow()
    current = run_from_row(row)
    started = run.started_at or (now if run.status == "running" else current.started_at)
    finished = run.finished_at or (now if run.status in {"completed", "succeeded", "failed", "cancelled", "timed_out", "interrupted", "blocked"} else current.finished_at)
    conn.execute(
        "UPDATE runs SET status = ?, worker_name = ?, worker_type = ?, started_at = ?, finished_at = ?, "
        "artifact_ids = ?, error_id = ?, updated_at = ? WHERE project_id = ? AND run_id = ?",
        (run.status, run.worker_name, run.worker_type, started, finished, _json(run.artifact_ids), run.error_id, now, run.project_id, run.run_id),
    )
    return run_from_row(conn.execute("SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (run.project_id, run.run_id)).fetchone())


def register_context(conn: sqlite3.Connection, projection: ContextProjection) -> ContextProjection:
    get_project_or_404(conn, projection.project_id)
    snapshot = conn.execute(
        "SELECT * FROM snapshots WHERE project_id = ? AND snapshot_id = ?",
        (projection.project_id, projection.snapshot_id),
    ).fetchone()
    if snapshot is None:
        raise ValueError("snapshot_id does not belong to this project")
    for field in ("graph_revision", "source_generation", "plan_revision"):
        if getattr(projection, field) != snapshot[field]:
            raise ValueError(f"context projection {field} does not match its snapshot")
    snapshot_nodes = _loads(snapshot["nodes"], [])
    snapshot_edges = _loads(snapshot["edges"], [])
    known_node_ids = {node.get("id") for node in snapshot_nodes if isinstance(node, dict)}
    known_edges = {
        edge.get("id"): edge for edge in snapshot_edges
        if isinstance(edge, dict) and isinstance(edge.get("id"), str)
    }
    missing_nodes = sorted(set(projection.node_ids) - known_node_ids)
    if missing_nodes:
        raise ValueError(f"context projection references unknown nodes: {', '.join(missing_nodes)}")
    missing_edges = sorted(set(projection.edge_ids) - set(known_edges))
    if missing_edges:
        raise ValueError(f"context projection references unknown edges: {', '.join(missing_edges)}")
    selected_nodes = set(projection.node_ids)
    for edge_id in projection.edge_ids:
        edge = known_edges[edge_id]
        if edge.get("source_id") not in selected_nodes or edge.get("target_id") not in selected_nodes:
            raise ValueError("context projection edge endpoints must be selected nodes")
    if any(conn.execute("SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?", (projection.project_id, aid)).fetchone() is None for aid in projection.artifact_ids):
        raise ValueError("context projection references an unknown artifact")
    value = projection.model_dump(mode="json")
    conn.execute(
        "INSERT OR IGNORE INTO context_projections (projection_id, project_id, schema_version, snapshot_id, graph_revision, source_generation, plan_revision, intent_id, stage, node_ids, edge_ids, artifact_ids, context, selection_policy, request, created_at, projection_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (value["projection_id"], value["project_id"], value["schema_version"], value["snapshot_id"], value["graph_revision"], value["source_generation"], value["plan_revision"], value["intent_id"], value["stage"], _json(value["node_ids"]), _json(value["edge_ids"]), _json(value["artifact_ids"]), _json(value["context"]), value["selection_policy"], _json(value["request"]) if value["request"] is not None else None, value["created_at"], value["projection_digest"]),
    )
    current = context_from_row(conn.execute(
        "SELECT * FROM context_projections WHERE project_id = ? AND projection_id = ?",
        (projection.project_id, projection.projection_id),
    ).fetchone())
    if current.canonical_json() != projection.canonical_json():
        raise ValueError("projection_id already exists with different content")
    return current


def list_contexts(conn: sqlite3.Connection, project_id: str) -> list[ContextProjection]:
    get_project_or_404(conn, project_id)
    return [context_from_row(row) for row in conn.execute("SELECT * FROM context_projections WHERE project_id = ? ORDER BY created_at, projection_id", (project_id,))]


def snapshot_from_db(conn: sqlite3.Connection, project_id: str) -> BlackboardSnapshot:
    project = get_project_or_404(conn, project_id)
    project_payload = {column: project[column] for column in project.keys() if column != "reason_worker"}
    project_payload["bootstrap_enabled"] = bool(project_payload.get("bootstrap_enabled"))
    # Lease columns are operational state and are intentionally not exposed
    # as part of the graph snapshot.  This keeps snapshots stable across
    # heartbeats while preserving all semantic ProjectMeta revisions.
    for column in ("reason_trigger", "reason_started_at", "reason_last_heartbeat_at", "reason_lease_id"):
        project_payload.pop(column, None)
    nodes: list[NodeEnvelope] = [NodeEnvelope(kind="project", id=project_id, payload=project_payload)]
    for table, kind, key in (("facts", "fact", "id"), ("intents", "intent", "id"), ("hints", "hint", "id"), ("reviews", "review", "id"), ("intent_errors", "intent_error", "id"), ("audit_stages", "stage", "stage_id"), ("human_decisions", "decision", "id")):
        rows = conn.execute(f"SELECT * FROM {table} WHERE project_id = ?", (project_id,)).fetchall()
        for row in rows:
            payload = {column: row[column] for column in row.keys() if column != "project_id"}
            for name in ("diagnostics", "metadata"):
                if name in payload:
                    payload[name] = _loads(payload[name], {})
            if "required" in payload:
                payload["required"] = bool(payload["required"])
            if kind == "intent":
                payload["from"] = [item["fact_id"] for item in conn.execute(
                    "SELECT fact_id FROM intent_sources WHERE project_id = ? AND intent_id = ? ORDER BY fact_id",
                    (project_id, row[key]),
                )]
                payload["to"] = payload.pop("to_fact_id", None)
            nodes.append(NodeEnvelope(kind=kind, id=row[key], payload=payload))
    nodes.sort(key=lambda node: (node.kind, node.id))
    edges: list[EdgeEnvelope] = []
    for edge in conn.execute("SELECT * FROM graph_edges WHERE project_id = ?", (project_id,)).fetchall():
        edges.append(EdgeEnvelope(id=edge["id"], source_kind=edge["source_kind"], source_id=edge["source_id"], target_kind=edge["target_kind"], target_id=edge["target_id"], relation_type=edge["relation_type"], payload={"source_generation": edge["source_generation"], "created_at": edge["created_at"], "created_by": edge["created_by"], "metadata": _loads(edge["metadata"], {})}))
    edges.sort(key=lambda edge: (edge.source_kind, edge.source_id, edge.target_kind, edge.target_id, edge.relation_type, edge.id))
    snapshot = BlackboardSnapshot(project_id=project_id, graph_revision=project["graph_revision"], source_generation=project["source_generation"], plan_revision=project["plan_revision"], nodes=nodes, edges=edges, created_at=utcnow())
    conn.execute(
        "INSERT OR IGNORE INTO snapshots (snapshot_id, project_id, schema_version, graph_revision, source_generation, plan_revision, nodes, edges, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (snapshot.snapshot_id, project_id, snapshot.schema_version, snapshot.graph_revision, snapshot.source_generation, snapshot.plan_revision, _json([node.model_dump(mode="json") for node in snapshot.nodes]), _json([edge.model_dump(mode="json") for edge in snapshot.edges]), snapshot.created_at),
    )
    return snapshot


def append_contract_event(conn: sqlite3.Connection, event: AuditEventEnvelope) -> AuditEventEnvelope:
    get_project_or_404(conn, event.project_id)
    if event.idempotency_key:
        row = conn.execute("SELECT * FROM audit_events WHERE project_id = ? AND idempotency_key = ?", (event.project_id, event.idempotency_key)).fetchone()
        if row is not None:
            current = event_from_row(row)
            current_data = current.model_dump(mode="json", exclude={"sequence"})
            requested_data = event.model_dump(mode="json", exclude={"sequence"})
            if current_data != requested_data:
                raise ValueError("event idempotency_key already exists with different content")
            return current
    try:
        sequence = append_event(conn, event.project_id, event.event_type, event.actor, entity_kind=event.entity_kind, entity_id=event.entity_id, payload=event.payload, created_at=event.created_at, event_id=event.event_id, run_id=event.run_id, idempotency_key=event.idempotency_key, graph_revision=event.graph_revision)
        current = event_from_row(conn.execute("SELECT * FROM audit_events WHERE sequence = ?", (sequence,)).fetchone())
        if current.model_dump(mode="json", exclude={"sequence"}) != event.model_dump(mode="json", exclude={"sequence"}):
            raise ValueError("event identity already exists with different content")
        return current
    except sqlite3.IntegrityError:
        # Another connection may have won the same idempotent insert.  Read
        # the committed row and apply the same identity comparison as a
        # normal replay instead of surfacing a spurious conflict.
        if event.idempotency_key:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE project_id = ? AND idempotency_key = ?",
                (event.project_id, event.idempotency_key),
            ).fetchone()
            if row is not None:
                current = event_from_row(row)
                if current.model_dump(mode="json", exclude={"sequence"}) == event.model_dump(mode="json", exclude={"sequence"}):
                    return current
        raise
