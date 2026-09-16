"""Deterministic, read-only verification of optional dynamic evidence.

Dynamic verification strengthens the existing UVPG result.  It never creates
Facts, changes Fact state, executes a command, or promotes a candidate.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from linen.server.models import Fact
from linen.server.routers.executions import workspace_root
from linen.server.uvpg import PROOF_GATE_VERSION, evaluate_proof_gate, proof_graph_fingerprint

DYNAMIC_GATE_VERSION = "uvpg-dynamic-v1"
_RUN_SUCCESS = frozenset({"completed", "succeeded"})


@dataclass(frozen=True)
class DynamicVerificationResult:
    status: str
    candidate_id: str
    confirmed_fact_id: str | None
    source_generation: int
    reason_codes: tuple[str, ...] = ()
    positive_reproduction_fact_id: str | None = None
    negative_control_fact_id: str | None = None
    positive_run_id: str | None = None
    negative_run_id: str | None = None
    static_proof_graph_sha256: str | None = None
    dynamic_verification_sha256: str | None = None
    receipt: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "candidate_id": self.candidate_id,
            "confirmed_fact_id": self.confirmed_fact_id,
            "source_generation": self.source_generation,
            "dynamic_gate_version": DYNAMIC_GATE_VERSION,
            "static_proof_gate_version": PROOF_GATE_VERSION,
            "reason_codes": list(self.reason_codes),
            "positive_reproduction_fact_id": self.positive_reproduction_fact_id,
            "negative_control_fact_id": self.negative_control_fact_id,
            "positive_run_id": self.positive_run_id,
            "negative_run_id": self.negative_run_id,
            "static_proof_graph_sha256": self.static_proof_graph_sha256,
            "dynamic_verification_sha256": self.dynamic_verification_sha256,
            "receipt": self.receipt,
        }


def _loads(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default


def _fact(row: sqlite3.Row) -> Fact:
    return Fact(**dict(row))


def _attributes(fact: Fact) -> dict[str, Any]:
    return fact.proof.attributes if fact.proof is not None else {}


def _authoritative_confirmation(conn: sqlite3.Connection, project_id: str, candidate_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT confirmed.* FROM facts confirmed JOIN graph_edges edge "
        "ON edge.project_id = confirmed.project_id AND edge.target_id = confirmed.id "
        "AND edge.source_id = ? AND edge.source_kind = 'fact' AND edge.target_kind = 'fact' "
        "AND edge.relation_type = 'promotes_to' WHERE confirmed.project_id = ? "
        "AND confirmed.semantic_type = 'confirmed_finding' ORDER BY confirmed.id LIMIT 1",
        (candidate_id, project_id),
    ).fetchone()


def _dynamic_facts(conn: sqlite3.Connection, project_id: str, candidate_id: str, generation: int) -> tuple[list[Fact], list[Fact]]:
    rows = conn.execute(
        "SELECT * FROM facts WHERE project_id = ? AND source_generation = ? "
        "AND type IN ('reproduction', 'negative_control') ORDER BY id",
        (project_id, generation),
    ).fetchall()
    positive: list[Fact] = []
    negative: list[Fact] = []
    for row in rows:
        fact = _fact(row)
        attrs = _attributes(fact)
        if attrs.get("mode") != "dynamic" or attrs.get("candidate_id") != candidate_id:
            continue
        if candidate_id not in (fact.proof.subject_ids if fact.proof else []):
            continue
        if fact.type == "reproduction":
            positive.append(fact)
        elif fact.type == "negative_control":
            negative.append(fact)
    return positive, negative


def _artifact_path(project: sqlite3.Row, artifact: sqlite3.Row) -> Path | None:
    root = Path(project["repo_root"]).expanduser().resolve() if project["repo_root"] else (workspace_root() / project["id"]).resolve()
    raw = Path(artifact["workspace_path"])
    candidate = raw if raw.is_absolute() else root / raw
    try:
        if candidate.is_symlink():
            return None
        path = candidate.resolve()
        if not path.is_file() or not path.is_relative_to(root):
            return None
    except OSError:
        return None
    return path


def _validate_run_and_artifacts(
    conn: sqlite3.Connection,
    project: sqlite3.Row,
    fact: Fact,
) -> tuple[set[str], list[str]]:
    attrs = _attributes(fact)
    run_id = attrs.get("run_id")
    artifact_ids = attrs.get("artifact_ids")
    errors: list[str] = []
    if not isinstance(run_id, str) or not run_id:
        errors.append("MISSING_ISOLATED_RUN")
        return set(), errors
    if not isinstance(artifact_ids, list) or not artifact_ids:
        errors.append("DYNAMIC_ARTIFACT_MISSING")
        return set(), errors
    run = conn.execute(
        "SELECT r.*, i.type AS intent_type FROM runs r LEFT JOIN intents i "
        "ON i.project_id = r.project_id AND i.id = r.intent_id "
        "WHERE r.project_id = ? AND r.run_id = ?", (project["id"], run_id),
    ).fetchone()
    if run is None or run["source_generation"] != project["source_generation"]:
        errors.append("STALE_DYNAMIC_EVIDENCE")
        return set(), errors
    if run["status"] not in _RUN_SUCCESS:
        errors.append("MISSING_ISOLATED_RUN")
    if not (run["task_type"] == "poc:isolated" or (run["intent_type"] or "").startswith("poc:isolated")):
        errors.append("UNSAFE_DYNAMIC_EXECUTION")
    run_artifacts = set(_loads(run["artifact_ids"], []))
    declared_artifacts = {value for value in artifact_ids if isinstance(value, str)}
    if not declared_artifacts or not declared_artifacts <= run_artifacts:
        errors.append("DYNAMIC_ARTIFACT_MISSING")
    for artifact_id in sorted(declared_artifacts):
        artifact = conn.execute(
            "SELECT * FROM artifacts WHERE project_id = ? AND artifact_id = ?",
            (project["id"], artifact_id),
        ).fetchone()
        if artifact is None:
            errors.append("DYNAMIC_ARTIFACT_MISSING")
            continue
        if artifact["producer_run_id"] != run_id:
            errors.append("DYNAMIC_ARTIFACT_MISSING")
            continue
        path = _artifact_path(project, artifact)
        if path is None:
            errors.append("DYNAMIC_ARTIFACT_MISSING")
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            errors.append("DYNAMIC_ARTIFACT_MISSING")
            continue
        if digest != artifact["sha256"]:
            errors.append("DYNAMIC_ARTIFACT_HASH_MISMATCH")
    return declared_artifacts, errors


def _reviewed(conn: sqlite3.Connection, project_id: str, fact_id: str) -> bool:
    rows = conn.execute(
        "SELECT verdict, confidence FROM reviews WHERE project_id = ? AND fact_id = ? "
        "ORDER BY created_at, id", (project_id, fact_id),
    ).fetchall()
    return bool(rows) and rows[-1]["verdict"] == "VALID" and rows[-1]["confidence"] in {"firm", "certain"}


def _observed_capability(attributes: dict[str, Any]) -> Any:
    value = attributes.get("capability_observed")
    if value is not None:
        return value
    outcome = attributes.get("observed_outcome")
    if isinstance(outcome, dict):
        return outcome.get("capability_observed", outcome.get("capability"))
    return None


def evaluate_dynamic_verification(
    conn: sqlite3.Connection,
    project_id: str,
    candidate_id: str,
    *,
    confirmed_fact_id: str | None = None,
    positive_fact_id: str | None = None,
    negative_fact_id: str | None = None,
    expected_static_digest: str | None = None,
) -> DynamicVerificationResult:
    """Evaluate existing dynamic evidence without mutating the Blackboard."""
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    generation = int(project["source_generation"]) if project else 0
    if project is None:
        return DynamicVerificationResult("FAIL", candidate_id, confirmed_fact_id, generation, ("STALE_DYNAMIC_EVIDENCE",))
    static = evaluate_proof_gate(conn, project_id, candidate_id)
    static_digest = proof_graph_fingerprint(conn, project_id, candidate_id)
    reasons: set[str] = set()
    if static.status != "PASS":
        reasons.add("STATIC_PROOF_NOT_CONFIRMED")
    confirmed = _authoritative_confirmation(conn, project_id, candidate_id)
    if confirmed_fact_id is not None and (confirmed is None or confirmed["id"] != confirmed_fact_id):
        reasons.add("STALE_DYNAMIC_EVIDENCE")
    positive, negative = _dynamic_facts(conn, project_id, candidate_id, generation)
    pos = next((fact for fact in positive if fact.id == positive_fact_id), positive[0] if positive else None)
    neg = next((fact for fact in negative if fact.id == negative_fact_id), negative[0] if negative else None)
    if pos is None:
        reasons.add("MISSING_DYNAMIC_REPRODUCTION")
    if neg is None:
        reasons.add("MISSING_DYNAMIC_NEGATIVE_CONTROL")
    if pos is None or neg is None:
        return DynamicVerificationResult("incomplete", candidate_id, confirmed["id"] if confirmed else confirmed_fact_id, generation, tuple(sorted(reasons)), pos.id if pos else None, neg.id if neg else None, _attributes(pos).get("run_id") if pos else None, _attributes(neg).get("run_id") if neg else None, static_digest)
    if expected_static_digest is not None and expected_static_digest != static_digest:
        reasons.add("STALE_DYNAMIC_EVIDENCE")
    pos_attrs = _attributes(pos)
    neg_attrs = _attributes(neg)
    if pos_attrs.get("run_id") == neg_attrs.get("run_id"):
        reasons.add("DYNAMIC_BASELINE_MISMATCH")
    if set(pos_attrs.get("artifact_ids", [])) & set(neg_attrs.get("artifact_ids", [])):
        reasons.add("DYNAMIC_BASELINE_MISMATCH")
    if pos_attrs.get("oracle_kind") != neg_attrs.get("oracle_kind") or not pos_attrs.get("oracle_kind"):
        reasons.add("DYNAMIC_ORACLE_MISSING")
    if "observed_outcome" not in pos_attrs or "observed_outcome" not in neg_attrs:
        reasons.add("DYNAMIC_ORACLE_MISSING")
    if _observed_capability(pos_attrs) is None or _observed_capability(neg_attrs) is None:
        reasons.add("DYNAMIC_ORACLE_MISSING")
    elif json.dumps(_observed_capability(pos_attrs), sort_keys=True) == json.dumps(_observed_capability(neg_attrs), sort_keys=True):
        reasons.add("NO_DYNAMIC_CAPABILITY_DELTA")
    for key in ("environment_fingerprint", "harness_id", "target_id", "snapshot_id", "config_fingerprint"):
        if key in pos_attrs or key in neg_attrs:
            if pos_attrs.get(key) != neg_attrs.get(key):
                reasons.add("DYNAMIC_BASELINE_MISMATCH")
    for fact in (pos, neg):
        _, fact_errors = _validate_run_and_artifacts(conn, project, fact)
        reasons.update(fact_errors)
        if not _reviewed(conn, project_id, fact.id):
            reasons.add("UNREVIEWED_DYNAMIC_EVIDENCE")
    status = "PASS" if not reasons else "FAIL"
    receipt: dict[str, Any] = {}
    dynamic_digest = None
    if status == "PASS":
        artifact_hashes: dict[str, str] = {}
        for artifact_id in sorted(set(pos_attrs["artifact_ids"]) | set(neg_attrs["artifact_ids"])):
            artifact = conn.execute(
                "SELECT sha256 FROM artifacts WHERE project_id = ? AND artifact_id = ?",
                (project_id, artifact_id),
            ).fetchone()
            if artifact is not None:
                artifact_hashes[artifact_id] = artifact["sha256"]
        receipt = {
            "candidate_id": candidate_id,
            "confirmed_fact_id": confirmed["id"] if confirmed else confirmed_fact_id,
            "source_generation": generation,
            "dynamic_rule_version": DYNAMIC_GATE_VERSION,
            "static_proof_gate_version": PROOF_GATE_VERSION,
            "static_proof_graph_sha256": static_digest,
            "positive_reproduction_fact_id": pos.id,
            "negative_control_fact_id": neg.id,
            "positive_run_id": pos_attrs["run_id"],
            "negative_run_id": neg_attrs["run_id"],
            "artifact_ids": sorted(set(pos_attrs["artifact_ids"]) | set(neg_attrs["artifact_ids"])),
            "artifact_hashes": artifact_hashes,
            "oracle_kind": pos_attrs["oracle_kind"],
            "observed_delta": {"positive": pos_attrs["observed_outcome"], "negative": neg_attrs["observed_outcome"]},
            "status": "PASS",
        }
        dynamic_digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        receipt["dynamic_verification_sha256"] = dynamic_digest
    return DynamicVerificationResult(status, candidate_id, confirmed["id"] if confirmed else confirmed_fact_id, generation, tuple(sorted(reasons)), pos.id, neg.id, pos_attrs.get("run_id"), neg_attrs.get("run_id"), static_digest, dynamic_digest, receipt)


def effective_verification_level(conn: sqlite3.Connection, project_id: str, confirmed_fact_id: str) -> str:
    row = conn.execute("SELECT * FROM facts WHERE project_id = ? AND id = ? AND semantic_type = 'confirmed_finding'", (project_id, confirmed_fact_id)).fetchone()
    if row is None:
        return "unconfirmed"
    candidate = conn.execute(
        "SELECT source_id FROM graph_edges WHERE project_id = ? AND target_id = ? AND relation_type = 'promotes_to' ORDER BY id LIMIT 1",
        (project_id, confirmed_fact_id),
    ).fetchone()
    if candidate is None:
        return "static_confirmed"
    receipt_rows = conn.execute(
        "SELECT payload FROM audit_events WHERE project_id = ? AND event_type = 'dynamic_verification_pass' "
        "AND source_generation = ? ORDER BY sequence DESC", (project_id, row["source_generation"]),
    ).fetchall()
    for receipt_row in receipt_rows:
        payload = _loads(receipt_row["payload"], {})
        if payload.get("candidate_id") == candidate["source_id"] and payload.get("confirmed_fact_id") == confirmed_fact_id:
            result = evaluate_dynamic_verification(
                conn, project_id, candidate["source_id"], confirmed_fact_id=confirmed_fact_id,
                positive_fact_id=payload.get("positive_reproduction_fact_id"),
                negative_fact_id=payload.get("negative_control_fact_id"),
                expected_static_digest=payload.get("static_proof_graph_sha256"),
            )
            if result.status == "PASS":
                return "dynamic_confirmed"
    return "static_confirmed"
