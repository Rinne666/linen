"""First-stage Unified Vulnerability Proof Graph infrastructure.

This module is deliberately a read-only validation and shadow-evaluation layer.
It does not create a finding, mutate a Fact status, or participate in the
existing Completion Gate.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from linen.server.models import Fact, ProofPayload

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LIBRARY = Path(__file__).resolve().parents[3] / "rules" / "invariant-library.yaml"

REASON_CODES = {
    "MISSING_ATTACKER_CONTROL", "MISSING_REACHABILITY", "MISSING_INVARIANT",
    "MISSING_BOUNDARY", "MISSING_CAPABILITY_BEFORE", "MISSING_CAPABILITY_AFTER",
    "MISSING_CAPABILITY_DELTA", "MISSING_NEGATIVE_CONTROL", "MISSING_IMPACT",
    "INVALID_PROVENANCE", "UNREVIEWED_EVIDENCE", "CONTRADICTED_EVIDENCE",
}


def validate_proof_payload(
    conn: sqlite3.Connection, project_id: str, proof: ProofPayload | None,
    *, subject_fact_id: str | None = None,
) -> list[str]:
    """Return deterministic errors; an empty list means the payload is valid."""
    if proof is None:
        return []
    errors: list[str] = []
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        return ["INVALID_PROVENANCE"]
    known_ids = {
        row["id"] for row in conn.execute(
            "SELECT id FROM facts WHERE project_id = ? UNION SELECT id FROM intents WHERE project_id = ?",
            (project_id, project_id),
        )
    }
    if subject_fact_id:
        known_ids.add(subject_fact_id)
    if any(identifier not in known_ids for identifier in [*proof.subject_ids, *proof.object_ids]):
        errors.append("INVALID_PROVENANCE")
    for artifact_id in proof.artifact_ids:
        if conn.execute("SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?", (project_id, artifact_id)).fetchone() is None:
            errors.append("INVALID_PROVENANCE")
    for ref in proof.evidence_refs:
        if ref.artifact_id and conn.execute("SELECT 1 FROM artifacts WHERE project_id = ? AND artifact_id = ?", (project_id, ref.artifact_id)).fetchone() is None:
            errors.append("INVALID_PROVENANCE")
        if ref.run_id:
            run = conn.execute("SELECT * FROM runs WHERE project_id = ? AND run_id = ?", (project_id, ref.run_id)).fetchone()
            if run is None or (ref.artifact_id and ref.artifact_id not in json.loads(run["artifact_ids"] or "[]")):
                errors.append("INVALID_PROVENANCE")
        if ref.snapshot_id:
            snapshot = conn.execute("SELECT * FROM snapshots WHERE project_id = ? AND snapshot_id = ?", (project_id, ref.snapshot_id)).fetchone()
            if snapshot is None or snapshot["source_generation"] != project["source_generation"]:
                errors.append("INVALID_PROVENANCE")
        if ref.line_start is not None and ref.line_end is not None and ref.line_end < ref.line_start:
            errors.append("INVALID_PROVENANCE")
        if ref.excerpt_sha256 and not _SHA256.fullmatch(ref.excerpt_sha256):
            errors.append("INVALID_PROVENANCE")
    return sorted(set(errors))


@dataclass(frozen=True)
class ShadowGateResult:
    status: str
    reason_codes: tuple[str, ...]
    fact_id: str

    def as_dict(self) -> dict[str, Any]:
        return {"mode": "shadow", "status": self.status, "reason_codes": list(self.reason_codes), "fact_id": self.fact_id}


def evaluate_shadow_gate(conn: sqlite3.Connection, project_id: str, fact_id: str) -> ShadowGateResult:
    row = conn.execute("SELECT * FROM facts WHERE project_id = ? AND id = ?", (project_id, fact_id)).fetchone()
    if row is None:
        return ShadowGateResult("FAIL", ("INVALID_PROVENANCE",), fact_id)
    proof = Fact(**dict(row)).proof
    errors = validate_proof_payload(conn, project_id, proof, subject_fact_id=fact_id)
    roles = {proof.claim_kind} if proof else set()
    if proof:
        roles.update(str(value) for value in proof.attributes.get("proof_roles", []))
    required = {
        "attacker_control": "MISSING_ATTACKER_CONTROL", "reachability": "MISSING_REACHABILITY",
        "security_invariant": "MISSING_INVARIANT", "security_boundary": "MISSING_BOUNDARY",
        "capability_before": "MISSING_CAPABILITY_BEFORE", "capability_after": "MISSING_CAPABILITY_AFTER",
        "capability_delta": "MISSING_CAPABILITY_DELTA", "negative_control": "MISSING_NEGATIVE_CONTROL",
        "impact_observation": "MISSING_IMPACT",
    }
    errors.extend(code for role, code in required.items() if role not in roles)
    reviews = conn.execute("SELECT verdict, confidence FROM reviews WHERE project_id = ? AND fact_id = ?", (project_id, fact_id)).fetchall()
    if not any(r["verdict"] == "VALID" and r["confidence"] in {"firm", "certain"} for r in reviews):
        errors.append("UNREVIEWED_EVIDENCE")
    if any(r["verdict"] == "INVALID" for r in reviews):
        errors.append("CONTRADICTED_EVIDENCE")
    unique = tuple(sorted(set(errors)))
    return ShadowGateResult("PASS" if not unique else "FAIL", unique, fact_id)


def load_invariant_library(path: Path | None = None) -> dict[str, Any]:
    """Load configuration only; this library has no authority over dispatch."""
    import yaml
    target = path or _LIBRARY
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}
