"""Resolve board-referenced snapshots without exposing other host directories."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from linen.dispatcher.analysis.semgrep import digest
from linen.server.models import Fact, ProjectDetail


def evidence_fields(evidence: str | None) -> dict[str, str]:
    return dict(line.split(": ", 1) for line in (evidence or "").splitlines() if ": " in line)


def load_artifact(fact: Fact, workdir: Path) -> tuple[Path, dict]:
    fields = evidence_fields(fact.evidence)
    path = Path(fields.get("artifact", "")).resolve()
    roots = [(workdir / name).resolve() for name in (".linen-analysis", ".linen-coverage")]
    if not any(path.is_relative_to(root) for root in roots):
        raise ValueError("Artifact must be inside this project's analysis directories")
    data = path.read_bytes()
    if digest(data) != fields.get("manifest_sha256"):
        raise ValueError("Artifact hash does not match the board evidence")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Artifact must be an object")
    return path, value


def source_bytes(source: Path, name: str, expected: str) -> bytes:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name:
        raise ValueError("Invalid snapshot file name")
    path = source / name
    if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
        raise ValueError("Snapshot file escapes its source directory")
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"Snapshot file changed: {name}")
    return data


def ancestor_ids(project: ProjectDetail, from_ids: list[str]) -> set[str]:
    parents: dict[str, list[str]] = {}
    for intent in project.intents:
        if intent.to:
            parents.setdefault(intent.to, []).extend(intent.from_)
    seen: set[str] = set()
    pending = list(from_ids)
    while pending:
        fid = pending.pop()
        if fid not in seen:
            seen.add(fid)
            pending.extend(parents.get(fid, []))
    return seen


def select_snapshot(project: ProjectDetail, fact_id: str, workdir: Path) -> tuple[Path, dict]:
    ancestors = ancestor_ids(project, [fact_id])
    target = next((fact for fact in project.facts if fact.id == fact_id), None)
    policy_review = target is not None and target.type in {
        "policy_evidence", "scope_adjudication",
    }
    candidates = []
    for fact in project.facts:
        allowed_types = (
            {"policy_evidence"}
            if policy_review
            else {"scan_batch", "route_scan", "coverage_plan"}
        )
        if fact.id in ancestors and fact.type in allowed_types:
            path, artifact = load_artifact(fact, workdir)
            snapshot = artifact.get("snapshot", {})
            if snapshot.get("id") and isinstance(snapshot.get("files"), dict):
                candidates.append((path.parent / "source", snapshot))
    if not candidates:
        raise ValueError("Isolated execution requires an ancestor scanner or coverage snapshot")
    if len({snapshot["id"] for _, snapshot in candidates}) != 1:
        raise ValueError("Review chain references different snapshots; split the finding before review")
    return candidates[0]


def review_inputs(project: ProjectDetail, fact: Fact, workdir: Path) -> dict[str, bytes]:
    """Selected execution records, never other reviews or graph history."""
    inputs: dict[str, bytes] = {}
    artifact_fact_types = {
        "scan_batch", "route_scan", "coverage_plan", "module_summary", "audit_summary",
        "architecture_map", "authz_matrix", "state_model", "cross_service_map",
        "contract_map", "hypothesis_batch", "variant_batch", "semantic_summary",
        "policy_evidence", "scope_adjudication",
    }
    if fact.type in artifact_fact_types:
        path, artifact = load_artifact(fact, workdir)
        record = {key: artifact[key] for key in (
            "id", "kind", "snapshot", "cells", "config", "status", "scanner", "coverage",
            "candidate_count", "route_count", "guard_patterns", "counts", "results",
            "input_fact_ids", "confirmed_vulnerability_ids", "errors", "recipe",
            "subject_fact_id", "citations", "items", "recipe_fact_ids", "worker_evidence",
            "statement", "repository", "sources", "gaps", "trust_boundaries",
            "pre_exclusions", "conflicts", "decision_scope",
            "technical_exploitability_unchanged", "evidence_gaps",
        ) if key in artifact}
        inputs["record.json"] = json.dumps(record, ensure_ascii=False).encode()
        if fact.type in {"scan_batch", "route_scan"}:
            names = (
                ("raw.sarif", "report.json", "candidates.json")
                if fact.type == "scan_batch"
                else ("routes.json", "guards.json", "candidates.json")
            )
            for name in names:
                expected = artifact.get("artifact_hashes", {}).get(name)
                if expected:
                    data = (path.parent / name).read_bytes()
                    if digest(data) != expected:
                        raise ValueError(f"Scan evidence changed: {name}")
                    inputs[name] = data
    elif fact.type == "coverage_result":
        result = json.loads(fact.evidence or "")
        for parent in project.facts:
            if parent.id in ancestor_ids(project, [fact.id]) and parent.type == "coverage_plan":
                _, plan = load_artifact(parent, workdir)
                if plan["id"] == result.get("plan_id"):
                    cell = next(cell for cell in plan["cells"] if cell["id"] == result["cell_id"])
                    inputs["scope.json"] = json.dumps(cell).encode()
    return inputs
