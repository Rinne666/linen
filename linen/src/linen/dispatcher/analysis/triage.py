"""Graph-derived candidate triage and per-candidate verification contracts."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from linen.dispatcher.analysis.artifacts import (
    canonical_endpoint_id,
    canonical_source_citations,
    canonical_vulnerability_trace,
    load_artifact,
    vulnerability_trace_proof,
)
from linen.dispatcher.analysis.artifacts import digest, write_json
from linen.dispatcher.config import CandidateTriageConfig
from linen.server.models import Fact, Intent, ProjectDetail


TRIAGE_PREFIX = "@candidate-triage:"
VERIFY_PREFIX = "@candidate-verify:"
CANDIDATE_FACT_TYPES = {"route_scan"}
TRIAGE_OUTCOMES = {"keep", "drop", "duplicate"}
VERIFY_OUTCOMES = {"confirmed", "refuted", "blocked"}


def _artifact_file(path: Path, manifest: dict, name: str) -> bytes:
    expected = manifest.get("artifact_hashes", {}).get(name)
    target = path.parent / name
    if not expected or not target.is_file():
        raise ValueError(f"Candidate artifact is missing {name}")
    data = target.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"Candidate artifact changed: {name}")
    return data


def candidate_sources(fact: Fact, workdir: Path) -> tuple[Path, dict, list[dict]]:
    if fact.type not in CANDIDATE_FACT_TYPES:
        raise ValueError("Candidate source must be a route_scan fact")
    path, manifest = load_artifact(fact, workdir)
    if manifest.get("status") != "completed":
        raise ValueError(f"Candidate source {fact.id} is not complete: {manifest.get('status')}")
    candidates = json.loads(_artifact_file(path, manifest, "candidates.json"))
    if not isinstance(candidates, list):
        raise ValueError("candidates.json must contain an array")
    fingerprints = [candidate.get("fingerprint") for candidate in candidates]
    if any(not isinstance(value, str) or not value for value in fingerprints):
        raise ValueError("Every candidate requires a fingerprint")
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("Candidate fingerprints must be unique within a candidate batch")
    return path, manifest, sorted(candidates, key=lambda item: item["fingerprint"])


def batch_description(fact_id: str, start: int, stop: int) -> str:
    return f"{TRIAGE_PREFIX}{fact_id}:{start}-{stop}"


def batches(fact: Fact, workdir: Path, config: CandidateTriageConfig) -> list[dict]:
    _, _, candidates = candidate_sources(fact, workdir)
    result = []
    for start in range(0, len(candidates), config.candidates_per_batch):
        stop = min(start + config.candidates_per_batch, len(candidates))
        result.append({
            "description": batch_description(fact.id, start, stop),
            "source_fact_id": fact.id,
            "start": start,
            "stop": stop,
            "candidates": candidates[start:stop],
        })
    if len(result) > config.max_batches:
        raise ValueError(
            f"Candidate triage needs {len(result)} batches (limit {config.max_batches}); nothing was truncated"
        )
    return result


def _batch_for_intent(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CandidateTriageConfig,
) -> tuple[Fact, dict]:
    for fact in project.facts:
        if fact.id in intent.from_ and fact.type in CANDIDATE_FACT_TYPES:
            match = next(
                (batch for batch in batches(fact, workdir, config)
                 if batch["description"] == intent.description.strip()),
                None,
            )
            if match is not None and (intent.type or "").startswith("triage"):
                return fact, match
    raise ValueError("Triage intent must reference its candidate source and exact batch")


def triage_context_prompt(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CandidateTriageConfig,
) -> str:
    source, batch = _batch_for_intent(project, intent, workdir, config)
    path, manifest = load_artifact(source, workdir)
    return "\nManaged candidate triage (the graph remains the task ledger):\n" + json.dumps({
        "source_fact_id": source.id,
        "snapshot": manifest.get("snapshot", {}).get("id"),
        "source_root": str(path.parent / "source"),
        "candidates": batch["candidates"],
    }, ensure_ascii=False) + """
Read the cited source for every candidate. Return accepted:true with data.description,
data.type="candidate_triage", data.evidence, and data.triage containing exactly one
object per fingerprint: {fingerprint, outcome, category, rationale, duplicate_of?}.
outcome is keep, drop, or duplicate. keep means a plausible trust-boundary crossing
that needs a dedicated verification branch. drop requires a concrete source-grounded
reason such as test-only, unreachable, safe API, or source mismatch. duplicate requires
duplicate_of naming another fingerprint in this batch or a clearly cited earlier graph
candidate. This task classifies candidates; it does not claim a vulnerability.
"""


def triage_outcome_fact(
    payload: dict,
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CandidateTriageConfig,
) -> dict[str, str]:
    source, batch = _batch_for_intent(project, intent, workdir, config)
    data = payload.get("data", payload)
    rows = data.get("triage") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Managed triage requires data.triage")
    expected = {candidate["fingerprint"] for candidate in batch["candidates"]}
    actual = [row.get("fingerprint") for row in rows if isinstance(row, dict)]
    if len(actual) != len(rows) or set(actual) != expected or len(actual) != len(set(actual)):
        raise ValueError("Triage output must cover every assigned fingerprint exactly once")
    normalized = []
    for row in rows:
        outcome = row.get("outcome")
        rationale = row.get("rationale")
        category = row.get("category")
        if outcome not in TRIAGE_OUTCOMES:
            raise ValueError(f"Unknown triage outcome: {outcome}")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ValueError("Every triage decision requires a rationale")
        if not isinstance(category, str) or not category.strip():
            raise ValueError("Every triage decision requires a category")
        duplicate_of = row.get("duplicate_of")
        if outcome == "duplicate" and (not isinstance(duplicate_of, str) or not duplicate_of):
            raise ValueError("duplicate triage decisions require duplicate_of")
        normalized.append({
            "fingerprint": row["fingerprint"],
            "outcome": outcome,
            "category": category.strip(),
            "rationale": rationale.strip(),
            **({"duplicate_of": duplicate_of} if duplicate_of else {}),
        })
    record = {
        "schema_version": 1,
        "source_fact_id": source.id,
        "batch": {"start": batch["start"], "stop": batch["stop"]},
        "decisions": sorted(normalized, key=lambda row: row["fingerprint"]),
    }
    directory = workdir / ".linen-analysis" / ("triage-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    path = directory / "result.json"
    write_json(path, record)
    counts = {outcome: sum(row["outcome"] == outcome for row in normalized) for outcome in sorted(TRIAGE_OUTCOMES)}
    return {
        "type": "candidate_triage",
        "description": f"Candidate triage for {source.id} [{batch['start']}:{batch['stop']}]: {counts}.",
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            f"source_fact_id: {source.id}\nstatus: completed"
        ),
    }


def triage_record(fact: Fact, workdir: Path) -> dict:
    if fact.type != "candidate_triage":
        raise ValueError("Expected candidate_triage fact")
    _, record = load_artifact(fact, workdir)
    if not isinstance(record.get("decisions"), list) or not record.get("source_fact_id"):
        raise ValueError("Invalid candidate triage artifact")
    return record


def verify_description(source_fact_id: str, fingerprint: str, attempt: int) -> str:
    return f"{VERIFY_PREFIX}{source_fact_id}:{fingerprint}:{attempt}"


def _verification_target(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
) -> tuple[Fact, dict, dict, Path, dict]:
    triage_fact = next(
        (fact for fact in project.facts if fact.id in intent.from_ and fact.type == "candidate_triage"),
        None,
    )
    if triage_fact is None or not intent.description.startswith(VERIFY_PREFIX):
        raise ValueError("Candidate verification must reference a candidate_triage fact")
    record = triage_record(triage_fact, workdir)
    parts = intent.description.split(":")
    if len(parts) < 4:
        raise ValueError("Invalid candidate verification description")
    fingerprint = parts[-2]
    decision = next(
        (row for row in record["decisions"] if row["fingerprint"] == fingerprint and row["outcome"] == "keep"),
        None,
    )
    if decision is None:
        raise ValueError("Candidate verification must target a kept candidate")
    source_fact = next((fact for fact in project.facts if fact.id == record["source_fact_id"]), None)
    if source_fact is None:
        raise ValueError("Candidate source fact is missing")
    path, manifest, candidates = candidate_sources(source_fact, workdir)
    candidate = next((item for item in candidates if item["fingerprint"] == fingerprint), None)
    if candidate is None:
        raise ValueError("Candidate fingerprint is missing from candidate evidence")
    return triage_fact, decision, candidate, path, manifest


def verification_context_prompt(project: ProjectDetail, intent: Intent, workdir: Path) -> str:
    _, decision, candidate, _, _ = _verification_target(project, intent, workdir)
    return "\nManaged candidate verification:\n" + json.dumps({
        "candidate": candidate,
        "triage": decision,
    }, ensure_ascii=False) + """
Independently verify this one candidate end to end. Return accepted:true with the normal
data.description/type/evidence fields plus data.candidate_disposition containing:
{fingerprint, outcome, rationale}. outcome must be confirmed, refuted, or blocked.
Also return data.endpoint_id, data.citations, and data.trace. endpoint_id is the
stable logical entry identity (for example http:DELETE:/users/{id}) when the
candidate has a logical HTTP, RPC, queue, or similar entry; otherwise return
null. citations use exact frozen-source {id, file, line, code} objects. trace is
an ordered array of {file, line, symbol, relation, observation, citation_id};
    Trace seeds are unverified hints and every retained step must be
independently checked.
confirmed means the worker believes a vulnerability candidate is ready for the
server-side Technical Confirmation Gate; it does not create a confirmed finding.
Use type=vulnerability for compatibility and provide the independently verified
relevant path without adding steps merely to fit a fixed topology. refuted
preserves the decisive protection path. blocked may use a partial or empty trace
but its rationale must name the missing hop.
refuted requires type=candidate_disposition and decisive counter-evidence. blocked is
reserved for missing build/runtime/dependency evidence and also uses candidate_disposition.
Do not silently switch to another candidate.
"""


def verification_outcome_fact(
    payload: dict,
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
) -> dict[str, object]:
    _, _, candidate, path, manifest = _verification_target(project, intent, workdir)
    data = payload.get("data", payload)
    expected_keys = {
        "description", "type", "evidence", "citations", "endpoint_id", "trace",
        "candidate_disposition",
    }
    if not isinstance(data, dict) or set(data) != expected_keys:
        raise ValueError(
            "Candidate verification requires exactly description, type, evidence, "
            "citations, endpoint_id, trace, and candidate_disposition"
        )
    disposition = data.get("candidate_disposition") if isinstance(data, dict) else None
    if not isinstance(disposition, dict):
        raise ValueError("Candidate verification requires data.candidate_disposition")
    if disposition.get("fingerprint") != candidate["fingerprint"]:
        raise ValueError("Candidate disposition fingerprint does not match the assigned candidate")
    outcome = disposition.get("outcome")
    rationale = disposition.get("rationale")
    if outcome not in VERIFY_OUTCOMES or not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("Candidate disposition requires a valid outcome and rationale")
    fact_type = data.get("type")
    if outcome == "confirmed" and fact_type != "vulnerability":
        raise ValueError("A confirmed candidate must produce a vulnerability candidate")
    if outcome != "confirmed" and fact_type != "candidate_disposition":
        raise ValueError("A non-confirmed candidate must produce type=candidate_disposition")
    evidence = data.get("evidence")
    if not isinstance(evidence, str) or not evidence.strip():
        raise ValueError("Candidate verification requires evidence")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("Candidate verification requires a description")
    snapshot = manifest.get("snapshot", {})
    citations = canonical_source_citations(
        data.get("citations"), path.parent / "source", snapshot, label="Candidate verification",
    )
    if not citations:
        raise ValueError("Candidate verification requires at least one frozen-source citation")
    raw_endpoint_id = data.get("endpoint_id")
    endpoint_id = (
        None if raw_endpoint_id is None else canonical_endpoint_id(raw_endpoint_id)
    )
    trace = canonical_vulnerability_trace(
        data.get("trace"), citations, path.parent / "source", snapshot, outcome=outcome,
    )
    envelope = {
        "schema_version": 1,
        "fingerprint": candidate["fingerprint"],
        "outcome": outcome,
        "rationale": rationale.strip(),
        "endpoint_id": endpoint_id,
        "citations": citations,
        "worker_evidence": evidence.strip(),
    }
    return {
        "type": fact_type,
        "description": description.strip(),
        "evidence": json.dumps(envelope, ensure_ascii=False),
        "proof": vulnerability_trace_proof(
            trace, endpoint_id, outcome, snapshot["id"],
        ),
    }


def verification_attempts(project: ProjectDetail, source_fact_id: str, fingerprint: str) -> list[Intent]:
    prefix = f"{VERIFY_PREFIX}{source_fact_id}:{fingerprint}:"
    return sorted(
        [intent for intent in project.intents if intent.description.startswith(prefix)],
        key=lambda intent: (intent.created_at, intent.id),
    )


def terminal_verification(
    project: ProjectDetail,
    source_fact_id: str,
    fingerprint: str,
) -> Fact | None:
    facts = {fact.id: fact for fact in project.facts}
    for intent in reversed(verification_attempts(project, source_fact_id, fingerprint)):
        fact = facts.get(intent.to or "")
        if fact is None:
            continue
        if fact.type == "vulnerability":
            return fact
        if fact.type == "candidate_disposition":
            try:
                if json.loads(fact.evidence or "").get("outcome") == "refuted":
                    return fact
            except (ValueError, TypeError):
                pass
    return None
