"""Validate frozen-source evidence and resolve board-referenced artifacts."""
from __future__ import annotations

import json
import fnmatch
import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from linen.server.models import Fact, ProjectDetail


TRACE_RELATIONS = frozenset({
    "entry", "calls", "flows_to", "crosses", "guards", "reaches", "impact",
})
_ENDPOINT_ID = re.compile(r"^[a-z][a-z0-9+.-]*:\S{1,191}$")
_CITATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def snapshot_source(repo: Path, destination: Path, config: object, output_root: Path) -> dict:
    """Copy regular files into a bounded immutable source snapshot."""
    files: dict[str, str] = {}
    skipped: list[dict] = []
    destination.mkdir(parents=True)
    exclude = getattr(config, "exclude", [])
    max_target_bytes = getattr(config, "max_target_bytes", 2_000_000)
    for directory, dirs, names in os.walk(repo, followlinks=False):
        directory = Path(directory)
        for name in sorted(dirs + names):
            path = directory / name
            relative = path.relative_to(repo).as_posix()
            reason = None
            if path.is_symlink():
                reason = "symlink"
            elif path == output_root or output_root in path.parents:
                reason = "analysis_artifacts"
            elif name == ".git" or any(
                fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
                for pattern in exclude
            ):
                reason = "excluded"
            elif path.is_file() and path.stat().st_size > max_target_bytes:
                reason = "max_target_bytes"
            if reason:
                skipped.append({"path": relative, "reason": reason})
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            if not path.is_file():
                skipped.append({"path": relative, "reason": "not_regular_file"})
                continue
            content = path.read_bytes()
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            files[relative] = digest(content)
    identity = json.dumps(
        {"files": files, "skipped": sorted(skipped, key=lambda x: x["path"])},
        sort_keys=True,
    )
    return {"id": digest(identity.encode()), "files": files, "skipped": skipped}


def snapshot_canonical_source(repo: Path, destination: Path, canonical_snapshot: dict) -> dict:
    """Copy exactly the regular files named by a prior immutable snapshot."""
    expected = canonical_snapshot.get("files")
    snapshot_id = canonical_snapshot.get("id")
    skipped = canonical_snapshot.get("skipped", [])
    if (not isinstance(expected, dict) or not expected or not isinstance(snapshot_id, str)
            or not isinstance(skipped, list)):
        raise ValueError("Invalid canonical source snapshot")
    for name, expected_hash in expected.items():
        if not isinstance(name, str) or not name or not isinstance(expected_hash, str):
            raise ValueError("Invalid canonical snapshot file entry")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("Invalid canonical snapshot file entry")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not isinstance(item.get("reason"), str)
        for item in skipped
    ):
        raise ValueError("Invalid canonical snapshot skip entry")
    identity = json.dumps(
        {"files": expected, "skipped": sorted(skipped, key=lambda item: item["path"])},
        sort_keys=True,
    )
    if digest(identity.encode()) != snapshot_id:
        raise ValueError("Canonical source snapshot id does not match its manifest")
    actual: set[str] = set()
    for directory, dirs, names in os.walk(repo, followlinks=False):
        directory = Path(directory)
        for name in sorted(dirs + names):
            path = directory / name
            relative = path.relative_to(repo).as_posix()
            if path.is_symlink():
                raise ValueError(f"Canonical source contains a symlink: {relative}")
            if name in dirs:
                continue
            if not path.is_file():
                raise ValueError(f"Canonical source contains a non-regular file: {relative}")
            actual.add(relative)
    if actual != set(expected):
        raise ValueError("Source input differs from the canonical coverage snapshot")
    destination.mkdir(parents=True)
    for name, expected_hash in sorted(expected.items()):
        source = repo / name
        data = source.read_bytes()
        if digest(data) != expected_hash:
            raise ValueError(f"Canonical snapshot file changed: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return {"id": snapshot_id, "files": dict(expected), "skipped": list(skipped)}


def canonical_endpoint_id(value: Any) -> str:
    """Validate an LLM-normalized logical endpoint identity."""
    if not isinstance(value, str) or not _ENDPOINT_ID.fullmatch(value.strip()):
        raise ValueError("endpoint_id must be a compact scheme-prefixed identity")
    return value.strip()


def canonical_source_citations(
    raw: Any, source: Path, snapshot: dict, *, label: str,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} result requires citations")
    if len(raw) > 2000:
        raise ValueError(f"{label} citation limit exceeded")
    result = []
    ids: set[str] = set()
    mismatches: list[str] = []
    files = snapshot.get("files", {})
    for citation in raw:
        if not isinstance(citation, dict) or set(citation) != {"id", "file", "line", "code"}:
            raise ValueError(f"Every {label.lower()} citation requires exactly id, file, line, and code")
        citation_id = citation["id"]
        filename = citation["file"]
        line = citation["line"]
        code = citation["code"]
        if (
            not isinstance(citation_id, str)
            or not _CITATION_ID.fullmatch(citation_id)
            or citation_id in ids
            or not isinstance(filename, str)
            or filename not in files
            or type(line) is not int
            or line < 1
            or not isinstance(code, str)
            or not code.strip()
            or len(code) > 8000
        ):
            raise ValueError(f"Invalid {label.lower()} citation")
        content = source_bytes(source, filename, files[filename]).decode(
            "utf-8", errors="replace",
        )
        lines = content.splitlines()
        excerpt = code.splitlines()
        actual = lines[line - 1:line - 1 + len(excerpt)]
        if actual != excerpt:
            # Models occasionally lose one indentation level while copying an
            # otherwise exact excerpt.  Canonicalize only that harmless case;
            # every non-whitespace byte, file, and line must still match the
            # immutable snapshot.  Content or line drift remains a hard error.
            indentation_only = (
                len(actual) == len(excerpt)
                and all(
                    source_line.lstrip(" \t") == cited_line.lstrip(" \t")
                    for source_line, cited_line in zip(actual, excerpt, strict=True)
                )
            )
            if indentation_only:
                code = "\n".join(actual)
            else:
                mismatches.append(f"{citation_id}={filename}:{line}")
        ids.add(citation_id)
        result.append({"id": citation_id, "file": filename, "line": line, "code": code})
    if mismatches:
        raise ValueError(
            f"{label} citation does not match frozen source "
            f"({len(mismatches)} mismatch(es)): {', '.join(mismatches)}"
        )
    return result


def canonical_vulnerability_trace(
    raw: Any,
    citations: list[dict[str, Any]],
    source: Path,
    snapshot: dict,
    *,
    outcome: str,
) -> list[dict[str, Any]]:
    """Validate trace structure and frozen-source citation bindings only."""
    if not isinstance(raw, list) or len(raw) > 100:
        raise ValueError("Vulnerability trace must be a bounded ordered array")
    if outcome == "confirmed" and not raw:
        raise ValueError("Confirmed vulnerability requires a trace")
    if outcome == "refuted" and not raw:
        raise ValueError("Refuted vulnerability requires its decisive protection path")
    citation_by_id = {citation["id"]: citation for citation in citations}
    files = snapshot.get("files", {})
    normalized: list[dict[str, Any]] = []
    for step in raw:
        if not isinstance(step, dict) or set(step) != {
            "file", "line", "symbol", "relation", "observation", "citation_id",
        }:
            raise ValueError(
                "Every trace step requires exactly file, line, symbol, relation, "
                "observation, and citation_id"
            )
        filename = step["file"]
        line = step["line"]
        symbol = step["symbol"]
        relation = step["relation"]
        observation = step["observation"]
        citation_id = step["citation_id"]
        citation = citation_by_id.get(citation_id)
        if (
            not isinstance(filename, str)
            or filename not in files
            or type(line) is not int
            or line < 1
            or not isinstance(symbol, str)
            or not symbol.strip()
            or relation not in TRACE_RELATIONS
            or not isinstance(observation, str)
            or not observation.strip()
            or citation is None
        ):
            raise ValueError("Invalid vulnerability trace step")
        content = source_bytes(source, filename, files[filename]).decode(
            "utf-8", errors="replace",
        )
        citation_lines = citation["code"].splitlines()
        citation_start = citation["line"]
        if (
            line > len(content.splitlines())
            or citation["file"] != filename
            or not citation_start <= line < citation_start + len(citation_lines)
        ):
            raise ValueError("Trace step conflicts with its frozen-source citation")
        normalized.append({
            "file": filename,
            "line": line,
            "symbol": symbol.strip(),
            "relation": relation,
            "observation": observation.strip(),
            "citation_id": citation_id,
        })
    return normalized


def vulnerability_trace_proof(
    trace: list[dict[str, Any]], endpoint_id: str | None, outcome: str, snapshot_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "claim_kind": "vulnerability_trace",
        "attributes": {
            "trace": trace,
            "endpoint_id": endpoint_id,
            "trace_status": "closed" if outcome == "confirmed" else "partial",
            "candidate_outcome": outcome,
            "snapshot_id": snapshot_id,
        },
    }


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
            else {"route_scan", "coverage_plan"}
        )
        if fact.id in ancestors and fact.type in allowed_types:
            path, artifact = load_artifact(fact, workdir)
            snapshot = artifact.get("snapshot", {})
            if snapshot.get("id") and isinstance(snapshot.get("files"), dict):
                candidates.append((path.parent / "source", snapshot))
    if not candidates:
        raise ValueError("Isolated execution requires an ancestor evidence or coverage snapshot")
    if len({snapshot["id"] for _, snapshot in candidates}) != 1:
        raise ValueError("Review chain references different snapshots; split the finding before review")
    return candidates[0]


def review_inputs(project: ProjectDetail, fact: Fact, workdir: Path) -> dict[str, bytes]:
    """Selected execution records, never other reviews or graph history."""
    inputs: dict[str, bytes] = {}
    artifact_fact_types = {
        "route_scan", "coverage_plan", "module_summary", "audit_summary",
        "architecture_map", "authz_matrix", "state_model", "cross_service_map",
        "contract_map", "hypothesis_batch", "variant_batch", "semantic_summary",
        "policy_evidence", "scope_adjudication",
    }
    if fact.type in artifact_fact_types:
        path, artifact = load_artifact(fact, workdir)
        record = {key: artifact[key] for key in (
            "id", "kind", "snapshot", "cells", "config", "status", "producer", "coverage",
            "candidate_count", "route_count", "guard_patterns", "counts", "results",
            "input_fact_ids", "confirmed_vulnerability_ids", "errors", "recipe",
            "subject_fact_id", "citations", "items", "recipe_fact_ids", "worker_evidence",
            "statement", "repository", "sources", "gaps", "trust_boundaries",
            "pre_exclusions", "conflicts", "decision_scope",
            "technical_exploitability_unchanged", "evidence_gaps",
        ) if key in artifact}
        inputs["record.json"] = json.dumps(record, ensure_ascii=False).encode()
        if fact.type == "route_scan":
            names = ("routes.json", "guards.json", "candidates.json")
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
