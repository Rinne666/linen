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
GAP_PRIORITY = {
    "CONTRADICTED_EVIDENCE": 1, "INVALID_PROVENANCE": 2, "INVALID_SOURCE_EXCERPT": 2,
    "STALE_PROOF_GENERATION": 2, "UNREVIEWED_EVIDENCE": 3,
    "MISSING_ATTACKER_CONTROL": 4, "MISSING_INVARIANT": 5, "MISSING_BOUNDARY": 6,
    "MISSING_REACHABILITY": 7, "MISSING_CAPABILITY_BEFORE": 9,
    "MISSING_CAPABILITY_AFTER": 10, "MISSING_CAPABILITY_DELTA": 11,
    "MISSING_NEGATIVE_CONTROL": 12, "MISSING_IMPACT": 13,
    "AMBIGUOUS_CAPABILITY_DELTA": 11, "ROLE_TYPE_MISMATCH": 2,
}
GAP_CONTRACTS = {
    "MISSING_ATTACKER_CONTROL": ("attacker_control", "verify", "depends_on", "Verify attacker-controlled input, identity, or state."),
    "MISSING_REACHABILITY": ("reachability", "reach", "depends_on", "Verify that the candidate path is reachable by the relevant principal."),
    "MISSING_INVARIANT": ("security_invariant", "validate", "violates", "Establish the security property the candidate path would violate."),
    "MISSING_BOUNDARY": ("security_boundary", "characterize", "crosses", "Characterize the trust or authorization boundary crossed by the candidate."),
    "MISSING_CAPABILITY_BEFORE": ("capability_before", "characterize", "depends_on", "Characterize the principal capability before the candidate path."),
    "MISSING_CAPABILITY_AFTER": ("capability_after", "verify", "depends_on", "Verify the capability obtained if the candidate path succeeds."),
    "MISSING_CAPABILITY_DELTA": ("capability_delta", "characterize", "depends_on", "Characterize the capability delta and cite its before/after facts."),
    "MISSING_NEGATIVE_CONTROL": ("negative_control", "validate", "depends_on", "Establish a safe baseline, deny rule, or other negative control."),
    "MISSING_IMPACT": ("impact_observation", "characterize", "observed_by", "Characterize the concrete security impact of the candidate."),
}
NON_INVESTIGATIVE_GAPS = frozenset({
    "CONTRADICTED_EVIDENCE",
    "PROOF_CYCLE", "CROSS_CANDIDATE_EVIDENCE", "INVALID_EDGE_RELATION", "PROOF_GRAPH_TOO_LARGE",
    "PROOF_GRAPH_CHANGED",
})
NON_AUTOMATIC_REPAIR_GAPS = frozenset({
    "INVALID_PROVENANCE", "INVALID_SOURCE_EXCERPT", "STALE_PROOF_GENERATION", "ROLE_TYPE_MISMATCH",
})
_OBLIGATION_RE = re.compile(r"^@uvpg:proof:(?P<candidate>[^:]+):(?P<code>[A-Z0-9_]+)(?::f(?P<target>[^:]+))?:g(?P<generation>[0-9]+)\b")
REVIEW_REQUIRED = frozenset({"candidate", "security_invariant", "security_boundary", "capability_delta", "impact_observation", "negative_control"})
TERMINAL_BAD = frozenset({"false_positive", "fixed", "accepted_risk"})

# The relation matrix is intentionally closed: arbitrary edges cannot close a proof.
EDGE_MATRIX = frozenset({
    ("candidate", "attacker_control", "depends_on"), ("candidate", "reachability", "depends_on"),
    ("candidate", "security_invariant", "violates"), ("candidate", "security_boundary", "crosses"),
    ("candidate", "capability_delta", "depends_on"), ("candidate", "negative_control", "depends_on"),
    ("candidate", "capability_before", "depends_on"), ("candidate", "capability_after", "depends_on"),
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
    foreign_fact_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "roles": {key: list(value) for key, value in sorted(self.facts_by_role.items())},
            "fact_ids": list(self.proof_fact_ids), "edge_ids": [edge.id for edge in self.edges],
            "reviewed_fact_ids": sorted(key for key, value in self.reviews_by_fact.items() if value),
            "missing_roles": list(self.missing_roles), "provenance_errors": list(self.provenance_errors),
            "invalid_edge_ids": list(self.invalid_edges),
            "foreign_fact_ids": list(self.foreign_fact_ids),
        }


@dataclass(frozen=True)
class ProofGap:
    candidate_id: str
    code: str
    role: str | None
    priority: int
    related_fact_ids: tuple[str, ...]
    suggested_intent_type: str
    suggested_relation_type: str | None
    expected_fact_type: str | None
    description: str
    status: str = "missing"
    source_generation: int = 0
    target_fact_id: str | None = None

    @property
    def key(self) -> str:
        target = f":f{self.target_fact_id}" if self.target_fact_id else ""
        return f"{self.candidate_id}:{self.code}{target}:g{self.source_generation}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id, "code": self.code, "role": self.role,
            "priority": self.priority, "related_fact_ids": list(self.related_fact_ids),
            "suggested_intent_type": self.suggested_intent_type,
            "suggested_relation_type": self.suggested_relation_type,
            "expected_fact_type": self.expected_fact_type, "description": self.description,
            "status": self.status, "source_generation": self.source_generation, "key": self.key,
            "target_fact_id": self.target_fact_id,
        }


_IGNORED_BLACKBOARD_RELATIONS = frozenset({
    "promotes_to", "produces", "reviews", "variant_of", "supersedes",
})


def _fact_roles(facts: dict[str, Fact], candidate_id: str) -> dict[str, str]:
    roles: dict[str, str] = {}
    for identifier, fact in facts.items():
        if identifier == candidate_id:
            roles[identifier] = "candidate"
        elif fact.semantic_type in {"candidate_finding", "confirmed_finding", "rejected_finding"}:
            roles[identifier] = "foreign_candidate"
        elif fact.type in REQUIRED_ROLES:
            roles[identifier] = fact.type
    return roles


def is_proof_edge(edge: GraphEdge, facts: dict[str, Fact], candidate_id: str) -> bool:
    """Return whether a Blackboard edge belongs to this candidate's proof view."""
    if edge.source_kind != "fact" or edge.target_kind != "fact":
        return False
    if edge.source_id not in facts or edge.target_id not in facts:
        return False
    edge_candidate = edge.metadata.get("candidate_id") if isinstance(edge.metadata, dict) else None
    if edge_candidate is not None and edge_candidate != candidate_id:
        return False
    roles = _fact_roles(facts, candidate_id)
    source = roles.get(edge.source_id)
    target = roles.get(edge.target_id)
    if "foreign_candidate" in {source, target}:
        return False
    return (source, target, edge.relation_type) in EDGE_MATRIX


def _edge_is_uvpg_candidate_edge(edge: GraphEdge, roles: dict[str, str]) -> bool:
    source = roles.get(edge.source_id)
    target = roles.get(edge.target_id)
    if source is None or target is None:
        return False
    return source in REQUIRED_ROLES or target in REQUIRED_ROLES or source in {"candidate", "foreign_candidate"} or target in {"candidate", "foreign_candidate"}


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
    edges = []
    for row in edge_rows:
        data = dict(row)
        data["metadata"] = _loads(row["metadata"], {})
        edges.append(GraphEdge(**data))
    roles = _fact_roles(facts, candidate_fact_id)
    adjacency: dict[str, list[tuple[str, GraphEdge]]] = {}
    for edge in edges:
        if edge.source_kind != "fact" or edge.target_kind != "fact" or edge.source_id not in facts or edge.target_id not in facts:
            continue
        if edge.relation_type in _IGNORED_BLACKBOARD_RELATIONS:
            continue
        edge_candidate = edge.metadata.get("candidate_id") if isinstance(edge.metadata, dict) else None
        if edge_candidate and edge_candidate != candidate_fact_id:
            continue
        if is_proof_edge(edge, facts, candidate_fact_id):
            adjacency.setdefault(edge.source_id, []).append((edge.target_id, edge))
            adjacency.setdefault(edge.target_id, []).append((edge.source_id, edge))
            continue
    seen = {candidate_fact_id}; queue = [candidate_fact_id]; used: dict[str, GraphEdge] = {}
    while queue:
        current = queue.pop(0)
        for other, edge in adjacency.get(current, []):
            if edge.id not in used:
                used[edge.id] = edge
                if len(used) > max_edges:
                    view.proof_fact_ids = sorted(seen)
                    view.edges = [used[key] for key in sorted(used)]
                    view.too_large = True
                    return view
            if other in seen:
                continue
            if len(seen) >= max_nodes:
                view.proof_fact_ids = sorted(seen)
                view.edges = [used[key] for key in sorted(used)]
                view.too_large = True
                return view
            seen.add(other); queue.append(other)
    view.proof_fact_ids = sorted(seen)
    view.edges = [used[key] for key in sorted(used)]
    reachable = set(view.proof_fact_ids)
    local_invalid_edges: list[GraphEdge] = []
    for edge in edges:
        if edge.source_id not in reachable and edge.target_id not in reachable:
            continue
        if edge.relation_type in _IGNORED_BLACKBOARD_RELATIONS or edge.id in used:
            continue
        edge_candidate = edge.metadata.get("candidate_id") if isinstance(edge.metadata, dict) else None
        if edge_candidate and edge_candidate != candidate_fact_id:
            view.foreign_fact_ids.extend(
                identifier for identifier in (edge.source_id, edge.target_id)
                if identifier in facts and identifier != candidate_fact_id
            )
            if _edge_is_uvpg_candidate_edge(edge, roles):
                view.invalid_edges.append(edge.id)
                local_invalid_edges.append(edge)
            continue
        if roles.get(edge.source_id) == "foreign_candidate" or roles.get(edge.target_id) == "foreign_candidate":
            view.foreign_fact_ids.extend(
                identifier for identifier in (edge.source_id, edge.target_id)
                if roles.get(identifier) == "foreign_candidate"
            )
        if _edge_is_uvpg_candidate_edge(edge, roles):
            view.invalid_edges.append(edge.id)
            local_invalid_edges.append(edge)
    directed: dict[str, list[str]] = {}
    for edge in [*view.edges, *local_invalid_edges]:
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
        role = roles.get(identifier)
        if role:
            if role == "foreign_candidate":
                view.foreign_fact_ids.append(identifier)
                continue
            view.facts_by_role.setdefault(role, []).append(identifier)
    for ids in view.facts_by_role.values():
        ids.sort()
    view.foreign_fact_ids = sorted(set(view.foreign_fact_ids))
    for row in conn.execute("SELECT fact_id, verdict, confidence FROM reviews WHERE project_id = ? ORDER BY created_at, id", (project_id,)):
        if row["fact_id"] in seen:
            view.reviews_by_fact.setdefault(row["fact_id"], []).append(dict(row))
    return view


_REVIEW_ROLE_ORDER = (
    "candidate", "security_invariant", "security_boundary", "capability_delta",
    "impact_observation", "negative_control",
)


def unreviewed_required_facts(view: ProofGraphView) -> list[str]:
    """Return concrete proof Facts whose decisive review is missing."""
    targets: list[str] = []
    for role in _REVIEW_ROLE_ORDER:
        for fact_id in sorted(view.facts_by_role.get(role, [])):
            reviews = view.reviews_by_fact.get(fact_id, [])
            latest = reviews[-1] if reviews else None
            if latest is None or latest["verdict"] != "VALID" or latest["confidence"] not in {"firm", "certain"}:
                targets.append(fact_id)
    return targets


def candidate_proof_facts(conn: sqlite3.Connection, project_id: str, candidate_id: str, role: str | None = None) -> list[str]:
    """Return only Facts in the candidate's deterministic proof projection."""
    view = collect_candidate_proof_subgraph(conn, project_id, candidate_id)
    if role is not None:
        return list(view.facts_by_role.get(role, []))
    return list(view.proof_fact_ids)


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
    if view.foreign_fact_ids or any(identifier != fact_id and facts[identifier].semantic_type in {"candidate_finding", "confirmed_finding", "rejected_finding"} for identifier in view.proof_fact_ids):
        reasons.add("CROSS_CANDIDATE_EVIDENCE")
    if view.invalid_edges:
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
    for proof_id in unreviewed_required_facts(view):
        reviews = view.reviews_by_fact.get(proof_id, [])
        if any(item["verdict"] == "INVALID" for item in reviews):
            reasons.add("CONTRADICTED_EVIDENCE")
        else:
            reasons.add("UNREVIEWED_EVIDENCE")
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


def derive_proof_gaps(conn: sqlite3.Connection, project_id: str, candidate_fact_id: str) -> list[ProofGap]:
    """Derive bounded investigative obligations from the shared proof result."""
    result = evaluate_proof_gate(conn, project_id, candidate_fact_id)
    view = collect_candidate_proof_subgraph(conn, project_id, candidate_fact_id)
    generation_row = conn.execute("SELECT source_generation FROM projects WHERE id = ?", (project_id,)).fetchone()
    generation = generation_row["source_generation"] if generation_row else 0
    gaps: list[ProofGap] = []
    for code in sorted(set(result.reason_codes), key=lambda value: (GAP_PRIORITY.get(value, 99), value)):
        if code in NON_INVESTIGATIVE_GAPS:
            role, intent_type, relation, description, expected = None, "blocked", None, "Repair the proof graph integrity before further investigation.", None
        elif code == "UNREVIEWED_EVIDENCE":
            targets = unreviewed_required_facts(view)
            for target in targets:
                role = next((candidate_role for candidate_role, ids in view.facts_by_role.items() if target in ids), None)
                description = "Independently review this candidate-specific proof Fact."
                gaps.append(ProofGap(
                    candidate_fact_id, code, role, GAP_PRIORITY.get(code, 99), (target,),
                    "review:devils-advocate", "reviews", None, description, "missing", generation, target,
                ))
            continue
        elif code in NON_AUTOMATIC_REPAIR_GAPS:
            role, intent_type, relation, description, expected = None, "blocked", None, "Repair this proof evidence manually before further investigation.", None
        elif code == "ROLE_TYPE_MISMATCH":
            role, intent_type, relation, description, expected = None, "validate", None, "Repair the proof claim type and re-verify its evidence.", None
        else:
            contract = GAP_CONTRACTS.get(code)
            if contract is None:
                continue
            role, intent_type, relation, description = contract
            expected = role
        if code == "CONTRADICTED_EVIDENCE":
            related = tuple(sorted(
                fact_id for fact_id, reviews in view.reviews_by_fact.items()
                if any(item["verdict"] == "INVALID" for item in reviews)
            ))
        elif code == "CROSS_CANDIDATE_EVIDENCE":
            related = tuple(view.foreign_fact_ids)
        elif code == "INVALID_EDGE_RELATION":
            related = tuple(view.invalid_edges)
        elif code in {"INVALID_PROVENANCE", "INVALID_SOURCE_EXCERPT", "STALE_PROOF_GENERATION", "ROLE_TYPE_MISMATCH"}:
            rows = conn.execute(
                "SELECT * FROM facts WHERE project_id = ? AND id IN ({}) ORDER BY id".format(",".join("?" for _ in view.proof_fact_ids)),
                (project_id, *view.proof_fact_ids),
            ).fetchall() if view.proof_fact_ids else []
            related = tuple(
                row["id"] for row in rows
                if (code in validate_proof_payload(conn, project_id, Fact(**dict(row)).proof, subject_fact_id=row["id"]))
                or (code == "ROLE_TYPE_MISMATCH" and Fact(**dict(row)).proof is not None and Fact(**dict(row)).proof.claim_kind in REQUIRED_ROLES and Fact(**dict(row)).type != Fact(**dict(row)).proof.claim_kind)
            )
        elif code == "AMBIGUOUS_CAPABILITY_DELTA":
            related = tuple(sorted(view.facts_by_role.get("capability_delta", [])))
        elif code.startswith("MISSING_"):
            dependency_roles = {
                "MISSING_ATTACKER_CONTROL": (), "MISSING_REACHABILITY": (),
                "MISSING_INVARIANT": ("security_invariant",), "MISSING_BOUNDARY": ("security_boundary",),
                "MISSING_CAPABILITY_BEFORE": ("capability_before",), "MISSING_CAPABILITY_AFTER": ("capability_after",),
                "MISSING_CAPABILITY_DELTA": ("capability_before", "capability_after"),
                "MISSING_NEGATIVE_CONTROL": ("capability_before",), "MISSING_IMPACT": ("impact_observation",),
            }
            related = tuple(sorted({candidate_fact_id, *(
                identifier for dependency_role in dependency_roles.get(code, ())
                for identifier in view.facts_by_role.get(dependency_role, [])
            )}))
        else:
            related = tuple(sorted(view.proof_fact_ids))
        gap_status = "blocked" if code in NON_INVESTIGATIVE_GAPS or code in NON_AUTOMATIC_REPAIR_GAPS else "missing"
        gaps.append(ProofGap(candidate_fact_id, code, role, GAP_PRIORITY.get(code, 99), related, intent_type, relation, expected, description, gap_status, generation))
    return gaps


def parse_proof_obligation(description: str) -> tuple[str, str, int, str | None] | None:
    match = _OBLIGATION_RE.match(description.strip())
    if match is None:
        return None
    return match.group("candidate"), match.group("code"), int(match.group("generation")), match.group("target")


def canonical_proof_edges(conn: sqlite3.Connection, project_id: str, candidate_id: str, fact_id: str, code: str, *, created_by: str, created_at: str) -> list[str]:
    """Create only the server-owned edges allowed by one obligation contract."""
    from linen.server.audit_state import create_graph_edge
    contract = GAP_CONTRACTS.get(code)
    if contract is None:
        return []
    role, _intent, relation, _description = contract
    edge_pairs: list[tuple[str, str, str]] = []
    if role in {"security_invariant", "security_boundary", "impact_observation"}:
        edge_pairs.append((fact_id, candidate_id, relation))
    else:
        edge_pairs.append((candidate_id, fact_id, relation or "depends_on"))
    view = collect_candidate_proof_subgraph(conn, project_id, candidate_id)
    if role == "capability_delta":
        before = view.facts_by_role.get("capability_before", [])
        after = view.facts_by_role.get("capability_after", [])
        if len(before) == 1 and len(after) == 1:
            edge_pairs.extend((fact_id, other, "depends_on") for other in (before[0], after[0]))
    if role in {"capability_before", "capability_after"}:
        for delta in view.facts_by_role.get("capability_delta", []):
            edge_pairs.append((delta, fact_id, "depends_on"))
    if role == "negative_control":
        before = view.facts_by_role.get("capability_before", [])
        if len(before) == 1:
            edge_pairs.append((fact_id, before[0], "baseline_for"))
    edge_ids = []
    for source, target, edge_relation in sorted(set(edge_pairs)):
        edge_ids.append(create_graph_edge(conn, project_id, source_kind="fact", source_id=source, target_kind="fact", target_id=target, relation_type=edge_relation, created_by=created_by, metadata={"proof_gap_code": code, "candidate_id": candidate_id}, created_at=created_at))
    return edge_ids


def load_invariant_library(path: Path | None = None) -> dict[str, Any]:
    """Load configuration only; this library has no authority over dispatch."""
    import yaml
    return yaml.safe_load((path or _LIBRARY).read_text(encoding="utf-8")) or {}
