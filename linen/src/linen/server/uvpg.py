"""Read-only, deterministic UVPG shadow validation.

The Blackboard remains authoritative. This module projects persisted Facts,
GraphEdges, Reviews, and vNext provenance records; it never writes findings,
edges, statuses, or completion state.

Canonical proof direction is proof -> candidate for ``violates``, ``crosses``
and ``observed_by``; candidate -> proof for ``depends_on`` and ``supports``.
Capability relations are proof -> proof: delta depends_on before/after and
negative_control baseline_for before.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from linen.server.models import Fact, GraphEdge, ProofPayload

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LIBRARY = Path(__file__).resolve().parents[3] / "rules" / "invariant-library.yaml"
PROOF_GATE_VERSION = "uvpg-proof-v1"
GATE_VERSION = PROOF_GATE_VERSION  # compatibility alias for callers of Phase 1.5
MAX_NODES = 128
MAX_EDGES = 256

REASON_CODES = frozenset({
    "MISSING_ATTACKER_CONTROL", "MISSING_REACHABILITY", "MISSING_INVARIANT",
    "MISSING_BOUNDARY", "MISSING_CAPABILITY_BEFORE", "MISSING_CAPABILITY_AFTER",
    "MISSING_CAPABILITY_DELTA", "MISSING_NEGATIVE_CONTROL", "MISSING_IMPACT",
    "INVALID_PROVENANCE", "UNREVIEWED_EVIDENCE", "CONTRADICTED_EVIDENCE",
    "MISSING_PROOF_EDGE", "DISCONNECTED_PROOF_FACT", "AMBIGUOUS_CAPABILITY_DELTA",
    "PROOF_CYCLE", "CROSS_CANDIDATE_EVIDENCE", "ROLE_TYPE_MISMATCH",
    "INVALID_EDGE_RELATION", "STALE_PROOF_GENERATION", "INVALID_SOURCE_EXCERPT",
    "ARTIFACT_HASH_MISMATCH", "PROOF_GRAPH_TOO_LARGE",
    "PROOF_GRAPH_CHANGED",
})
REQUIRED_ROLES = {
    "attacker_control": "MISSING_ATTACKER_CONTROL", "reachability": "MISSING_REACHABILITY",
    "security_invariant": "MISSING_INVARIANT", "security_boundary": "MISSING_BOUNDARY",
    "capability_before": "MISSING_CAPABILITY_BEFORE", "capability_after": "MISSING_CAPABILITY_AFTER",
    "capability_delta": "MISSING_CAPABILITY_DELTA", "negative_control": "MISSING_NEGATIVE_CONTROL",
    "impact_observation": "MISSING_IMPACT",
}
REVIEW_REQUIRED = frozenset({"candidate", "security_invariant", "security_boundary", "capability_delta", "impact_observation", "negative_control"})
TERMINAL_BAD = frozenset({"false_positive", "fixed", "accepted_risk"})

# The relation matrix is intentionally closed: arbitrary edges cannot close a proof.
EDGE_MATRIX = frozenset({
    ("candidate", "attacker_control", "depends_on"), ("candidate", "reachability", "depends_on"),
    ("candidate", "security_invariant", "violates"), ("candidate", "security_boundary", "crosses"),
    ("candidate", "capability_delta", "depends_on"), ("candidate", "negative_control", "depends_on"),
    ("candidate", "impact_observation", "observed_by"),
    ("security_invariant", "candidate", "violates"), ("security_boundary", "candidate", "crosses"),
    ("impact_observation", "candidate", "observed_by"),
    ("attacker_control", "candidate", "supports"), ("reachability", "candidate", "supports"),
    ("capability_delta", "capability_before", "depends_on"), ("capability_delta", "capability_after", "depends_on"),
    ("negative_control", "capability_before", "baseline_for"), ("capability_before", "negative_control", "baseline_for"),
})


def _loads(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default


def _role(fact: Fact, candidate_id: str) -> str | None:
    if fact.id == candidate_id or fact.semantic_type in {"candidate_finding", "confirmed_finding"}:
        return "candidate"
    return fact.type if fact.type in REQUIRED_ROLES else None


@dataclass
class ProofGraphView:
    candidate_fact_id: str
    proof_fact_ids: list[str] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    facts_by_role: dict[str, list[str]] = field(default_factory=dict)
    reviews_by_fact: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    missing_roles: list[str] = field(default_factory=list)
    invalid_edges: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    provenance_errors: list[str] = field(default_factory=list)
    cycle: bool = False
    too_large: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "roles": {key: list(value) for key, value in sorted(self.facts_by_role.items())},
            "fact_ids": list(self.proof_fact_ids), "edge_ids": [edge.id for edge in self.edges],
            "reviewed_fact_ids": sorted(key for key, value in self.reviews_by_fact.items() if value),
            "missing_roles": list(self.missing_roles), "provenance_errors": list(self.provenance_errors),
        }


def collect_candidate_proof_subgraph(conn: sqlite3.Connection, project_id: str, candidate_fact_id: str, *, max_nodes: int = MAX_NODES, max_edges: int = MAX_EDGES) -> ProofGraphView:
    view = ProofGraphView(candidate_fact_id)
    project = conn.execute("SELECT source_generation FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        view.provenance_errors.append("INVALID_PROVENANCE")
        return view
    generation = project["source_generation"]
    rows = conn.execute("SELECT * FROM facts WHERE project_id = ? AND source_generation = ? ORDER BY id", (project_id, generation)).fetchall()
    facts = {row["id"]: Fact(**dict(row)) for row in rows}
    if candidate_fact_id not in facts:
        view.provenance_errors.append("INVALID_PROVENANCE")
        return view
    edge_rows = conn.execute("SELECT * FROM graph_edges WHERE project_id = ? AND source_generation = ? ORDER BY id", (project_id, generation)).fetchall()
    if len(edge_rows) > max_edges:
        view.too_large = True
        return view
    edges = []
    for row in edge_rows:
        data = dict(row)
        data["metadata"] = _loads(row["metadata"], {})
        edges.append(GraphEdge(**data))
    adjacency: dict[str, list[tuple[str, GraphEdge]]] = {}
    for edge in edges:
        if edge.source_kind != "fact" or edge.target_kind != "fact" or edge.source_id not in facts or edge.target_id not in facts:
            continue
        adjacency.setdefault(edge.source_id, []).append((edge.target_id, edge))
        adjacency.setdefault(edge.target_id, []).append((edge.source_id, edge))
    seen = {candidate_fact_id}; queue = [candidate_fact_id]; used: dict[str, GraphEdge] = {}
    parent: dict[str, str | None] = {candidate_fact_id: None}
    while queue:
        current = queue.pop(0)
        for other, edge in adjacency.get(current, []):
            used[edge.id] = edge
            if other in seen:
                continue
            if len(seen) >= max_nodes:
                view.too_large = True
                return view
            seen.add(other); parent[other] = current; queue.append(other)
    view.proof_fact_ids = sorted(seen)
    view.edges = [used[key] for key in sorted(used)]
    directed: dict[str, list[str]] = {}
    for edge in view.edges:
        if edge.source_id in seen and edge.target_id in seen:
            directed.setdefault(edge.source_id, []).append(edge.target_id)
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(identifier: str) -> None:
        if identifier in visiting:
            view.cycle = True
            return
        if identifier in visited:
            return
        visiting.add(identifier)
        for target in sorted(directed.get(identifier, [])):
            visit(target)
        visiting.remove(identifier)
        visited.add(identifier)
    for identifier in sorted(seen):
        visit(identifier)
    for identifier in view.proof_fact_ids:
        role = _role(facts[identifier], candidate_fact_id)
        if role:
            view.facts_by_role.setdefault(role, []).append(identifier)
    for ids in view.facts_by_role.values():
        ids.sort()
    for row in conn.execute("SELECT fact_id, verdict, confidence FROM reviews WHERE project_id = ? ORDER BY created_at, id", (project_id,)):
        if row["fact_id"] in seen:
            view.reviews_by_fact.setdefault(row["fact_id"], []).append(dict(row))
    return view


def _safe_artifact_path(project: sqlite3.Row, row: sqlite3.Row) -> Path:
    path = Path(row["workspace_path"])
    resolved = path.resolve(strict=True)
    if resolved.is_symlink():
        raise ValueError("symlink")
    root = Path(project["repo_root"]).resolve() if project["repo_root"] else resolved.parent
    if not resolved.is_relative_to(root):
        raise ValueError("outside workspace")
    return resolved


def validate_proof_payload(conn: sqlite3.Connection, project_id: str, proof: ProofPayload | None, *, subject_fact_id: str | None = None) -> list[str]:
    """Verify provenance identity and content, not the truth of a claim."""
    if proof is None:
        return []
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        return ["INVALID_PROVENANCE"]
    errors: set[str] = set()
    known = {row["id"] for row in conn.execute("SELECT id FROM facts WHERE project_id = ? UNION SELECT id FROM intents WHERE project_id = ?", (project_id, project_id))}
    if subject_fact_id:
        known.add(subject_fact_id)
    if any(identifier not in known for identifier in [*proof.subject_ids, *proof.object_ids]):
        errors.add("INVALID_PROVENANCE")
    for artifact_id in proof.artifact_ids:
        if conn.execute("SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?", (project_id, artifact_id)).fetchone() is None:
            errors.add("INVALID_PROVENANCE")
    for ref in proof.evidence_refs:
        snapshot = conn.execute("SELECT * FROM snapshots WHERE project_id = ? AND snapshot_id = ?", (project_id, ref.snapshot_id)).fetchone() if ref.snapshot_id else None
        if ref.snapshot_id and snapshot is None:
            errors.add("INVALID_PROVENANCE")
        elif snapshot is not None and snapshot["source_generation"] != project["source_generation"]:
            errors.add("STALE_PROOF_GENERATION")
        artifact = conn.execute("SELECT * FROM artifacts WHERE project_id = ? AND artifact_id = ?", (project_id, ref.artifact_id)).fetchone() if ref.artifact_id else None
        if ref.artifact_id and artifact is None:
            errors.add("INVALID_PROVENANCE")
        if artifact is not None:
            try:
                path = _safe_artifact_path(project, artifact)
                if artifact["sha256"] and hashlib.sha256(path.read_bytes()).hexdigest() != artifact["sha256"]:
                    errors.add("ARTIFACT_HASH_MISMATCH")
            except (OSError, ValueError):
                errors.add("INVALID_PROVENANCE")
        if ref.run_id:
            run = conn.execute("SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (project_id, ref.run_id)).fetchone()
            if run is None or (ref.artifact_id and ref.artifact_id not in _loads(run["artifact_ids"], [])):
                errors.add("INVALID_PROVENANCE")
            elif run["source_generation"] != project["source_generation"]:
                errors.add("STALE_PROOF_GENERATION")
        if ref.line_start is not None or ref.line_end is not None:
            valid_name = bool(ref.file) and not PurePosixPath(ref.file).is_absolute() and ".." not in PurePosixPath(ref.file).parts and "\\" not in ref.file
            if not (ref.snapshot_id and ref.line_start and ref.line_end and ref.line_end >= ref.line_start and artifact is not None and valid_name):
                errors.add("INVALID_SOURCE_EXCERPT")
            else:
                try:
                    lines = _safe_artifact_path(project, artifact).read_text(encoding="utf-8").splitlines()
                    excerpt = "\n".join(lines[ref.line_start - 1:ref.line_end]).encode()
                    if ref.line_end > len(lines) or not ref.excerpt_sha256 or hashlib.sha256(excerpt).hexdigest() != ref.excerpt_sha256:
                        errors.add("INVALID_SOURCE_EXCERPT")
                except (OSError, UnicodeError, ValueError):
                    errors.add("INVALID_SOURCE_EXCERPT")
        elif ref.excerpt_sha256 and not _SHA256.fullmatch(ref.excerpt_sha256):
            errors.add("INVALID_SOURCE_EXCERPT")
    return sorted(errors)


def _edge_valid(edge: GraphEdge, roles: dict[str, str], candidate_id: str) -> bool:
    source = "candidate" if edge.source_id == candidate_id else roles.get(edge.source_id)
    target = "candidate" if edge.target_id == candidate_id else roles.get(edge.target_id)
    return (source, target, edge.relation_type) in EDGE_MATRIX


def proof_graph_fingerprint(conn: sqlite3.Connection, project_id: str, candidate_fact_id: str) -> str:
    """Hash the exact current proof inputs, excluding the promotion record."""
    view = collect_candidate_proof_subgraph(conn, project_id, candidate_fact_id)
    facts = []
    for identifier in view.proof_fact_ids:
        row = conn.execute(
            "SELECT id, source_generation, type, semantic_type, status, proof FROM facts "
            "WHERE project_id = ? AND id = ?", (project_id, identifier),
        ).fetchone()
        if row is not None and row["semantic_type"] != "confirmed_finding":
            facts.append({key: row[key] for key in row.keys()})
    edges = [
        {key: row[key] for key in row.keys()}
        for row in conn.execute(
            "SELECT id, source_id, target_id, relation_type, source_generation, metadata "
            "FROM graph_edges WHERE project_id = ? AND source_generation = ? "
            "AND relation_type != 'promotes_to' ORDER BY id", (project_id, conn.execute("SELECT source_generation FROM projects WHERE id = ?", (project_id,)).fetchone()[0]),
        )
        if row["source_id"] in view.proof_fact_ids and row["target_id"] in view.proof_fact_ids
    ]
    generation = conn.execute("SELECT source_generation FROM projects WHERE id = ?", (project_id,)).fetchone()[0]
    reviews = [
        {key: row[key] for key in row.keys()}
        for row in conn.execute(
            "SELECT id, fact_id, verdict, confidence, source_generation FROM reviews "
            "WHERE project_id = ? AND fact_id IN ({}) ORDER BY id".format(",".join("?" for _ in view.proof_fact_ids)),
            (project_id, *view.proof_fact_ids),
        )
    ] if view.proof_fact_ids else []
    payload = {"candidate_id": candidate_fact_id, "generation": generation, "gate_version": PROOF_GATE_VERSION, "facts": facts, "edges": edges, "reviews": reviews}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True)
class ShadowGateResult:
    status: str
    reason_codes: tuple[str, ...]
    fact_id: str
    proof_summary: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"mode": "shadow", "gate_version": PROOF_GATE_VERSION, "proof_gate_version": PROOF_GATE_VERSION, "status": self.status, "reason_codes": list(self.reason_codes), "fact_id": self.fact_id, "proof_summary": self.proof_summary}


def evaluate_shadow_gate(conn: sqlite3.Connection, project_id: str, fact_id: str) -> ShadowGateResult:
    view = collect_candidate_proof_subgraph(conn, project_id, fact_id)
    reasons = set(view.provenance_errors)
    if view.too_large: reasons.add("PROOF_GRAPH_TOO_LARGE")
    if view.cycle: reasons.add("PROOF_CYCLE")
    rows = conn.execute("SELECT * FROM facts WHERE project_id = ?", (project_id,)).fetchall()
    facts = {row["id"]: Fact(**dict(row)) for row in rows}
    roles = {identifier: role for role, ids in view.facts_by_role.items() for identifier in ids}
    if any(identifier != fact_id and facts[identifier].semantic_type in {"candidate_finding", "confirmed_finding", "rejected_finding"} for identifier in view.proof_fact_ids):
        reasons.add("CROSS_CANDIDATE_EVIDENCE")
    if any(not _edge_valid(edge, roles, fact_id) for edge in view.edges):
        reasons.add("INVALID_EDGE_RELATION")
    for identifier in list(roles):
        if facts[identifier].status in TERMINAL_BAD:
            reasons.add("CONTRADICTED_EVIDENCE")
            view.facts_by_role[roles.pop(identifier)].remove(identifier)
    connected = set(view.facts_by_role) - {"candidate"}
    for role, code in REQUIRED_ROLES.items():
        if role not in connected: reasons.add(code)
        elif not any(
            _edge_valid(edge, roles, fact_id)
            and (roles.get(edge.source_id) == role or roles.get(edge.target_id) == role)
            for edge in view.edges
        ):
            reasons.add("MISSING_PROOF_EDGE")
    if len(view.facts_by_role.get("capability_delta", [])) != 1:
        reasons.add("AMBIGUOUS_CAPABILITY_DELTA")
    candidate = facts.get(fact_id)
    hinted = {str(value) for value in (candidate.proof.attributes.get("proof_roles", []) if candidate and candidate.proof else [])}
    if hinted - connected: reasons.add("DISCONNECTED_PROOF_FACT")
    for role in REVIEW_REQUIRED:
        for proof_id in view.facts_by_role.get(role, []):
            reviews = view.reviews_by_fact.get(proof_id, [])
            if any(item["verdict"] == "INVALID" for item in reviews): reasons.add("CONTRADICTED_EVIDENCE")
            if not reviews or reviews[-1]["verdict"] != "VALID" or reviews[-1]["confidence"] not in {"firm", "certain"}: reasons.add("UNREVIEWED_EVIDENCE")
    for proof_id, reviews in view.reviews_by_fact.items():
        if any(item["verdict"] == "INVALID" for item in reviews): reasons.add("CONTRADICTED_EVIDENCE")
    for identifier in view.proof_fact_ids:
        proof = facts[identifier].proof
        if proof is not None and proof.claim_kind in REQUIRED_ROLES and facts[identifier].type != proof.claim_kind:
            reasons.add("ROLE_TYPE_MISMATCH")
        reasons.update(validate_proof_payload(conn, project_id, proof, subject_fact_id=identifier))
    summary = view.as_dict()
    summary["legacy_role_result"] = sorted(hinted)
    summary["graph_closure_result"] = sorted(connected)
    unique = tuple(sorted(reasons))
    return ShadowGateResult("PASS" if not unique else "FAIL", unique, fact_id, summary)


# Enforcement and shadow are intentionally aliases to one deterministic core.
evaluate_proof_gate = evaluate_shadow_gate


def load_invariant_library(path: Path | None = None) -> dict[str, Any]:
    """Load configuration only; this library has no authority over dispatch."""
    import yaml
    return yaml.safe_load((path or _LIBRARY).read_text(encoding="utf-8")) or {}
