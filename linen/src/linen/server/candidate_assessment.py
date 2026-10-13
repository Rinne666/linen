"""Read-only input binding for an early candidate reportability assessment."""

from __future__ import annotations

import hashlib
import json
import sqlite3


ASSESSMENT_KIND = "candidate_assessment"
ASSESSMENT_PREFIX = "@analysis:candidate-assessment:"


def candidate_assessment_input(conn: sqlite3.Connection, project_id: str, candidate_id: str) -> dict:
    project = conn.execute("SELECT source_generation,plan_revision FROM projects WHERE id = ?", (project_id,)).fetchone()
    row = conn.execute("SELECT id,type,description,evidence,proof,source_generation FROM facts WHERE project_id = ? AND id = ?", (project_id, candidate_id)).fetchone()
    if project is None or row is None or row["type"] != "vulnerability" or row["source_generation"] != project["source_generation"]:
        raise ValueError("Assessment requires a current candidate finding")
    scope = [dict(item) for item in conn.execute(
        "SELECT id,type,status,description,evidence,proof,source_generation FROM facts WHERE project_id = ? AND source_generation = ? "
        "AND type IN ('policy_evidence','scope_adjudication') ORDER BY id", (project_id, project["source_generation"]),
    )]
    # Review identities bind changes in policy judgments without exposing
    # previous Reviews to the independent reviewer.
    policy_reviews = []
    for fact in scope:
        review = conn.execute("SELECT id,verdict,confidence FROM reviews WHERE project_id = ? AND fact_id = ? ORDER BY created_at DESC,id DESC LIMIT 1", (project_id, fact["id"])).fetchone()
        policy_reviews.append({"fact_id": fact["id"], "review": dict(review) if review else None})
    data = {"kind": ASSESSMENT_KIND, "candidate_id": candidate_id, **dict(project),
            "candidate": dict(row), "scope_facts": scope}
    digest_input = {**data, "policy_review_bindings": policy_reviews}
    data["assessment_input_sha256"] = hashlib.sha256(json.dumps(digest_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return data


def assessment_binding_is_current(conn: sqlite3.Connection, project_id: str, candidate_id: str, verification: dict) -> bool:
    if verification.get("review_kind") != ASSESSMENT_KIND:
        return True  # Legacy and unified proof reviews retain their own checks.
    try:
        current = candidate_assessment_input(conn, project_id, candidate_id)
    except ValueError:
        return False
    return verification.get("candidate_id") == candidate_id and verification.get("assessment_input_sha256") == current["assessment_input_sha256"]
