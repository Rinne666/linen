"""Coverage plans and outcomes are ordinary blackboard facts, not a second queue."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from linen.dispatcher.analysis.artifacts import ancestor_ids, load_artifact, source_bytes
from linen.dispatcher.analysis.semgrep import digest, snapshot_source, write_json
from linen.dispatcher.config import CoverageConfig, SemgrepConfig
from linen.server.models import Fact, Intent, ProjectDetail

PLAN_INTENT = "@analysis:coverage-plan"
CELL_PREFIX = "@coverage:"
MODULE_SUMMARY_PREFIX = "@analysis:module-summary:"
TERMINAL_OUTCOMES = {"checked", "not_applicable"}


def create_plan(repo: Path, workdir: Path, config: CoverageConfig) -> dict[str, str]:
    root = (workdir / ".linen-coverage").resolve()
    directory = root / uuid.uuid4().hex
    directory.mkdir(parents=True)
    if not repo.is_dir():
        raise ValueError("Coverage requires an existing repository")
    snapshot = snapshot_source(repo.resolve(), directory / "source", SemgrepConfig(
        max_target_bytes=config.max_target_bytes, exclude=config.exclude,
    ), workdir.resolve())
    # Top-level modules then bounded file chunks. Every included file belongs
    # to exactly one chunk for each configured topic, including non-code files.
    modules: dict[str, list[str]] = {}
    for name in sorted(snapshot["files"]):
        module = name.split("/", 1)[0] if "/" in name else "."
        modules.setdefault(module, []).append(name)
    cells = []
    for module, files in sorted(modules.items()):
        for start in range(0, len(files), config.files_per_cell):
            for topic in config.topics:
                cell = {"module": module, "topic": topic, "files": files[start:start + config.files_per_cell]}
                cell["id"] = digest(json.dumps(cell, sort_keys=True).encode())[:20]
                cells.append(cell)
    if not cells:
        raise ValueError("No files in coverage scope; inspect exclusions")
    if len(cells) > config.max_cells:
        raise ValueError(f"Coverage needs {len(cells)} cells (limit {config.max_cells}); nothing was silently truncated")
    plan = {"schema_version": 1, "snapshot": snapshot, "cells": cells,
            "config": config.model_dump(), "source": str(directory / "source")}
    plan["id"] = digest(json.dumps({"snapshot": snapshot["id"], "cells": cells}, sort_keys=True).encode())[:24]
    path = directory / "plan.json"
    write_json(path, plan)
    return {
        "type": "coverage_plan",
        "description": f"Coverage plan {plan['id']}: {len(snapshot['files'])} files, {len(cells)} cells; "
                       f"{len(snapshot['skipped'])} recorded exclusions/skips. Completion means planned checks, not absence of bugs.",
        "evidence": f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\nsnapshot: {snapshot['id']}",
    }


def get_plan(project: ProjectDetail, workdir: Path) -> tuple[Fact, Path, dict]:
    facts = [fact for fact in project.facts if fact.type == "coverage_plan"]
    if len(facts) != 1:
        raise ValueError("Scope audit requires exactly one coverage_plan; create a new project to replan")
    fact = facts[0]
    path, plan = load_artifact(fact, workdir)
    if not plan.get("cells") or not plan.get("snapshot", {}).get("files"):
        raise ValueError("Invalid coverage plan")
    return fact, path, plan


def cell_description(plan: dict, cell: dict) -> str:
    return f"{CELL_PREFIX}{plan['id']}:{cell['id']}"


def cell_context(project: ProjectDetail, intent: Intent, workdir: Path) -> tuple[dict, dict, Path]:
    fact, path, plan = get_plan(project, workdir)
    cell = next((cell for cell in plan["cells"] if intent.description.strip() == cell_description(plan, cell)), None)
    if cell is None or intent.type != "verify" or fact.id not in ancestor_ids(project, intent.from_):
        raise ValueError("Coverage intent must be verify, match a plan cell, and reference its plan ancestry")
    for name in cell["files"]:
        source_bytes(path.parent / "source", name, plan["snapshot"]["files"][name])
    return plan, cell, path.parent / "source"


def execution_prompt(project: ProjectDetail, intent: Intent, workdir: Path) -> str:
    plan, cell, source = cell_context(project, intent, workdir)
    return """# Managed coverage task

This is one deterministic source-coverage cell, not a general audit and not a
generic Fact task. Read every assigned file from the frozen source root. Assess
only the assigned topic and do not inspect mutable repository files outside it.

Task context:
""" + json.dumps({
        "plan_id": plan["id"], "snapshot": plan["snapshot"]["id"], "cell": cell, "source_root": str(source),
    }, ensure_ascii=False, indent=2) + """

Return exactly one raw JSON object, with no markdown fences or commentary:
{"accepted":true,"data":{"description":"...","coverage":{...}}}

data.coverage must contain:
  outcome: checked | not_applicable | needs_followup | blocked
  inspected_files: list of assigned relative file paths actually read
  citations: list of {file, line, code}, with a one-based line and an exact,
             preferably single-line excerpt copied from that source line
  leads: list of {file, line, summary, next_step}; mandatory and non-empty for
         needs_followup, otherwise an empty list
  rationale: non-empty explanation of checks, protections, findings, or blockers

checked means the planned check is finished with NO unresolved leads, not proof of safety.
not_applicable needs a concrete rationale. Both require every file to be inspected and
cited (empty files need no citation). Use one short citation per routine file; do
not narrate every file separately. If you discover unresolved candidates, return
needs_followup and put every bounded follow-up in leads. blocked and needs_followup
remain uncovered. Do not claim repository-wide safety or emit a generic
type/evidence Fact.
"""


def context_prompt(project: ProjectDetail, intent: Intent, workdir: Path) -> str:
    """Backward-compatible alias for callers that need coverage instructions."""
    return execution_prompt(project, intent, workdir)


def conclusion_prompt(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    validation_error: str | None = None,
) -> str:
    error = (validation_error or "The initial response did not satisfy the coverage contract").strip()
    return execution_prompt(project, intent, workdir) + """

# Conclusion repair

Do not restart the audit. Use the analysis already completed in this conversation
and return the final JSON now. The previous response failed validation for this reason:
""" + json.dumps(error[:2000], ensure_ascii=False) + """

Before answering, verify each citation against the frozen source with a line-numbered
read such as `nl -ba`. The `line` must identify the copied excerpt exactly. Include one
citation for every assigned non-empty file when outcome is checked or not_applicable.
Return only the raw JSON object.
"""


def normalize_payload(payload: dict) -> dict:
    """Accept the documented unwrapped coverage shape without weakening generic tasks."""
    if (isinstance(payload, dict) and "accepted" not in payload
            and isinstance(payload.get("description"), str)
            and isinstance(payload.get("coverage"), dict)):
        return {"accepted": True, "data": payload}
    return payload


def _canonical_citation(citation: dict, inspected: list[str], contents: dict[str, str]) -> dict:
    if not isinstance(citation, dict) or citation.get("file") not in inspected:
        raise ValueError("Citation must reference an inspected file")
    filename = citation["file"]
    lines = contents[filename].splitlines()
    line = citation.get("line")
    code = citation.get("code")
    if type(line) is not int or not isinstance(code, str) or not code.strip():
        raise ValueError("Citation does not match the frozen source")

    snippet = code.splitlines()

    def matches(index: int) -> bool:
        if not 0 <= index < len(lines):
            return False
        if len(snippet) == 1:
            return code in lines[index]
        actual = "\n".join(lines[index:index + len(snippet)])
        return len(lines[index:index + len(snippet)]) == len(snippet) and actual.strip() == code.strip()

    claimed = line - 1
    if matches(claimed):
        return {"file": filename, "line": line, "code": code}

    # A model can preserve an exact excerpt but report the line from a grep
    # result or a zero-based count. Relocate only when the excerpt has one
    # unambiguous source location; invented and ambiguous citations still fail.
    candidates = [index for index in range(len(lines)) if matches(index)]
    if len(candidates) != 1:
        raise ValueError("Citation does not match the frozen source")
    index = candidates[0]
    canonical_code = lines[index] if len(snippet) == 1 else "\n".join(lines[index:index + len(snippet)])
    return {"file": filename, "line": index + 1, "code": canonical_code}


def outcome_fact(payload: dict, project: ProjectDetail, intent: Intent, workdir: Path) -> dict[str, str]:
    plan, cell, source = cell_context(project, intent, workdir)
    data = payload.get("data", payload)
    outcome = data.get("coverage")
    if not isinstance(outcome, dict) or outcome.get("outcome") not in TERMINAL_OUTCOMES | {"blocked", "needs_followup"}:
        raise ValueError("Coverage task requires a structured coverage outcome")
    rationale = outcome.get("rationale")
    inspected = outcome.get("inspected_files")
    citations = outcome.get("citations")
    persisted = "schema_version" in outcome and "cell_id" in outcome
    raw_leads = outcome.get("leads", [])
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("Coverage outcome requires rationale")
    if (not isinstance(inspected, list) or any(not isinstance(name, str) for name in inspected)
            or not set(inspected).issubset(cell["files"]) or not isinstance(citations, list)
            or not isinstance(raw_leads, list)):
        raise ValueError("Invalid inspected_files, citations, or leads")
    cited = set()
    normalized_citations = []
    contents = {name: source_bytes(source, name, plan["snapshot"]["files"][name]).decode("utf-8", errors="replace")
                for name in cell["files"]}
    for citation in citations:
        normalized = _canonical_citation(citation, inspected, contents)
        normalized_citations.append(normalized)
        cited.add(normalized["file"])
    leads = []
    for lead in raw_leads:
        if not isinstance(lead, dict):
            raise ValueError("Every coverage lead must be an object")
        filename = lead.get("file")
        line = lead.get("line")
        summary = lead.get("summary")
        next_step = lead.get("next_step")
        if (
            filename not in cell["files"]
            or type(line) is not int
            or not 1 <= line <= max(1, len(contents[filename].splitlines()))
            or not isinstance(summary, str)
            or not summary.strip()
            or not isinstance(next_step, str)
            or not next_step.strip()
        ):
            raise ValueError("Coverage lead must cite an assigned file/line and a concrete next step")
        leads.append({
            "file": filename,
            "line": line,
            "summary": summary.strip(),
            "next_step": next_step.strip(),
        })
    if outcome["outcome"] in TERMINAL_OUTCOMES:
        required = {name for name, content in contents.items() if content.strip()}
        if set(inspected) != set(cell["files"]) or not required.issubset(cited):
            raise ValueError("Terminal coverage must inspect and cite all non-empty files")
        if leads:
            raise ValueError("Terminal coverage cannot retain unresolved leads")
    if outcome["outcome"] == "needs_followup" and not leads and not persisted:
        raise ValueError("needs_followup coverage requires at least one structured lead")
    schema_version = outcome.get("schema_version", 1) if persisted else 2
    evidence = {"schema_version": schema_version, "plan_id": plan["id"], "cell_id": cell["id"],
                "snapshot": plan["snapshot"]["id"], "outcome": outcome["outcome"],
                "inspected_files": inspected, "citations": normalized_citations,
                "rationale": rationale}
    if schema_version >= 2 or "leads" in outcome:
        evidence["leads"] = leads
    return {"type": "coverage_result", "description": f"{cell['module']} / {cell['topic']}: {outcome['outcome']}. {rationale}",
            "evidence": json.dumps(evidence, ensure_ascii=False)}


def reviewed(project: ProjectDetail, fid: str) -> bool:
    fact = next((fact for fact in project.facts if fact.id == fid), None)
    reviews = effective_reviews(project, fid)
    return bool(
        fact
        and fact.status == "triaged"
        and reviews
        and not any(review.verdict == "INVALID" for review in reviews)
        and reviews[-1].verdict == "VALID"
        and reviews[-1].confidence in {"firm", "certain"}
    )


def effective_reviews(project: ProjectDetail, fid: str) -> list:
    """Return reviews whose schema matches the fact's review contract.

    Coverage plans created before the attestation profile existed may carry a
    vulnerability-style INVALID review whose only complaint is that a plan is
    not itself a vulnerability.  Preserve those rows for audit history, but do
    not let them satisfy or poison the plan-attestation gate.
    """
    fact = next((fact for fact in project.facts if fact.id == fid), None)
    reviews = sorted(
        (review for review in project.reviews if review.fact_id == fid),
        key=lambda review: (review.created_at, review.id),
    )
    if fact is not None and fact.type == "coverage_plan":
        return [review for review in reviews if review.attestation_check is not None]
    return reviews


def review_resolved(project: ProjectDetail, fid: str) -> bool:
    """Return whether review reached a decisive result suitable for ancestry."""
    fact = next((fact for fact in project.facts if fact.id == fid), None)
    reviews = effective_reviews(project, fid)
    if fact is None or not reviews:
        return False
    if fact.status == "false_positive":
        return any(review.verdict == "INVALID" for review in reviews)
    return reviewed(project, fid)


def coverage_state(project: ProjectDetail, workdir: Path, config: CoverageConfig) -> dict:
    plan_fact, path, plan = get_plan(project, workdir)
    for key in ("topics", "files_per_cell", "max_target_bytes", "exclude"):
        if plan["config"][key] != config.model_dump()[key]:
            raise ValueError("Coverage scope configuration changed; create a new project to replan")
    rows = []
    for cell in plan["cells"]:
        description = cell_description(plan, cell)
        attempts = [
            intent for intent in project.intents
            if intent.description.strip() == description
            and not (
                (intent.type or "").startswith("cancelled:")
                and intent.to is None
                and intent.concluded_at is not None
            )
        ]
        # Use board edges and timestamps, not model claims about cell IDs.
        attempts.sort(key=lambda intent: (intent.created_at, intent.id))
        latest = attempts[-1] if attempts else None
        status, result_id = "pending", None
        if latest:
            status = (
                "running" if latest.to is None and latest.concluded_at is None and latest.worker
                else "queued" if latest.to is None and latest.concluded_at is None
                else "blocked"
            )
            result = next((fact for fact in project.facts if fact.id == latest.to), None)
            if result and result.type == "coverage_result":
                try:
                    # Revalidate citations and snapshot, including manually supplied results.
                    outcome = json.loads(result.evidence or "")
                    normalized = outcome_fact({"coverage": outcome}, project, latest, workdir)
                    if json.loads(normalized["evidence"]) != outcome:
                        raise ValueError("Coverage result metadata mismatch")
                    prior_ids = {i.to for i in attempts[:-1] if i.to}
                    if not prior_ids.issubset(ancestor_ids(project, latest.from_)):
                        raise ValueError("Repeated coverage must reference prior results")
                    if any(not review_resolved(project, fid) for fid in prior_ids):
                        raise ValueError("Prior coverage outcomes must have a decisive review before retry")
                    if result.status == "false_positive" and review_resolved(project, result.id):
                        status = "invalid"
                    else:
                        status = outcome["outcome"] if reviewed(project, result.id) else "awaiting_review"
                    result_id = result.id
                except (ValueError, TypeError, KeyError, OSError):
                    status = "invalid"
        rows.append({"cell_id": cell["id"], "description": description, "topic": cell["topic"],
                     "module": cell["module"], "status": status, "result_id": result_id,
                     "attempts": len(attempts), "retry_exhausted": len(attempts) >= config.max_attempts_per_cell})
    counts = {status: sum(row["status"] == status for row in rows) for status in sorted({row["status"] for row in rows})}
    return {"plan_id": plan["id"], "plan_fact_id": plan_fact.id, "cells": rows,
            "summary": {"total": len(rows), "covered": sum(row["status"] in TERMINAL_OUTCOMES for row in rows), "by_status": counts},
            "skipped": plan["snapshot"]["skipped"], "snapshot": plan["snapshot"]["id"]}


def scope_blockers(project: ProjectDetail, workdir: Path, config: CoverageConfig, from_ids: list[str]) -> list[str]:
    try:
        state = coverage_state(project, workdir, config)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return [str(exc)]
    blockers = []
    if state["plan_fact_id"] not in ancestor_ids(project, from_ids):
        blockers.append("Completion must reference the coverage plan ancestry.")
    if not reviewed(project, state["plan_fact_id"]):
        blockers.append("Coverage plan requires a firm/certain VALID review.")
    for cell in state["cells"]:
        if cell["status"] not in TERMINAL_OUTCOMES:
            blockers.append(f"Coverage {cell['cell_id']}: {cell['status']} (attempts {cell['attempts']}).")
    for skipped in state["skipped"]:
        if skipped["reason"] not in {"excluded", "analysis_artifacts"}:
            blockers.append(f"Unresolved skipped input: {skipped['path']} ({skipped['reason']}).")
    if any(intent.to is None and intent.concluded_at is None for intent in project.intents):
        blockers.append("Open intents must finish before scope completion.")
    for fact in project.facts:
        # Recon is an optional prioritization aid.  It is never evidence for
        # a vulnerability and must not turn an otherwise complete scope audit
        # into an unfinishable project merely because it was not reviewed.
        if fact.type == "recon":
            continue
        if fact.id not in {"origin", "goal"} and fact.type not in {"coverage_plan", "coverage_result"}:
            if fact.status not in {"false_positive", "fixed", "accepted_risk"} and not reviewed(project, fact.id):
                blockers.append(f"Unresolved finding/evidence: {fact.id}.")
            if fact.type == "vulnerability" and fact.status == "triaged":
                from linen.dispatcher.analysis.policy import completion_blockers
                blockers.extend(completion_blockers(project, [fact.id]))
    return blockers


def validate_intent(project: ProjectDetail, workdir: Path, config: CoverageConfig, data: dict) -> None:
    description = data["description"].strip()
    if description == PLAN_INTENT:
        if data.get("type") != "search" or any(f.type == "coverage_plan" for f in project.facts):
            raise ValueError("Only one search coverage-plan intent is allowed per project")
    elif description.startswith(CELL_PREFIX):
        state = coverage_state(project, workdir, config)
        row = next((row for row in state["cells"] if row["description"] == description), None)
        if row is None or data.get("type") != "verify":
            raise ValueError("Unknown coverage cell or task type")
        if row["status"] in TERMINAL_OUTCOMES | {"queued", "running", "awaiting_review"} or row["retry_exhausted"]:
            raise ValueError("Coverage cell is done, pending review, queued/running, or retry budget exhausted")
        if state["plan_fact_id"] not in ancestor_ids(project, data["from"]):
            raise ValueError("Coverage intent must reference its plan ancestry")
        if row["result_id"] and row["result_id"] not in ancestor_ids(project, data["from"]):
            raise ValueError("Coverage retry must reference its prior outcome")
    else:
        return
    if any(i.description.strip() == description and i.to is None and i.concluded_at is None for i in project.intents):
        raise ValueError("Duplicate open coverage intent")


def reason_instructions(project: ProjectDetail, workdir: Path, config: CoverageConfig) -> str:
    if not any(f.type == "coverage_plan" for f in project.facts):
        state = {"next": f"Emit search from origin with description exactly {PLAN_INTENT}"}
    else:
        state = coverage_state(project, workdir, config)
    return """
Scope audit policy (overrides hypothesis completion): Finding one vulnerability does
NOT finish this project. Reserved @analysis, @coverage, @candidate-triage, and
@candidate-verify intents are derived from the blackboard and materialized by the
dispatcher; do not emit or duplicate them. The only exception is an exact
`search:skill` choice supplied separately by the dispatcher: select one when its
trusted scanner would materially improve the investigation. Review results as graph facts.
checked/not_applicable only count after VALID review. For needs_followup, trace every
lead with an ordinary source-grounded intent; the dispatcher will schedule a repeat
that references the prior result. Retry exhaustion and unexplained skips mean
INCOMPLETE, not safe. Do not complete until a reviewed audit_summary exists, every
required branch has fanned into it, and no intent or unresolved finding remains.
Completion may report zero findings and must reference that audit_summary. State
precisely that this covers configured checks on frozen snapshots with declared
exclusions, not that the entire repository is safe.
State derived from board facts/intents/reviews:
""" + json.dumps(state, ensure_ascii=False)


def review_prompt(
    project: ProjectDetail,
    fact: Fact,
    workdir: Path,
    *,
    source_root: str | None = None,
) -> str:
    """Build a coverage-attestation review, not a vulnerability review."""
    source_intent = next(
        (
            intent for intent in project.intents
            if intent.to == fact.id and intent.description.startswith(CELL_PREFIX)
        ),
        None,
    )
    if source_intent is None:
        raise ValueError("Coverage result is not connected to a coverage intent")
    plan, cell, source = cell_context(project, source_intent, workdir)
    outcome = json.loads(fact.evidence or "")
    normalized = outcome_fact({"coverage": outcome}, project, source_intent, workdir)
    if json.loads(normalized["evidence"]) != outcome:
        raise ValueError("Coverage result metadata mismatch")
    review_source = source_root or str(source)
    return """# Managed coverage review

You are independently reviewing one coverage attestation, not a vulnerability
hypothesis. The result claims that a bounded set of frozen files was inspected
for one topic. Read the files yourself and try to falsify that claim.

Review context:
""" + json.dumps({
        "fact_id": fact.id,
        "plan_id": plan["id"],
        "snapshot": plan["snapshot"]["id"],
        "cell": cell,
        "source_root": review_source,
        "claimed_result": outcome,
    }, ensure_ascii=False, indent=2) + """

Verification rules:
- Read every assigned file from source_root; use line-numbered reads for evidence.
- Verify every claimed citation and every objective statement in the rationale.
- Re-run claimed searches where practical. A statement such as "no matching
  definition exists" is INVALID if any assigned file contains that definition,
  even when the cited source lines themselves are genuine.
- For checked/not_applicable, confirm that all non-empty files were cited and
  that no unresolved lead contradicts the terminal outcome.
- For needs_followup, verify every structured lead's file/line and next step.
  For blocked, confirm that the rationale precisely identifies the blocker.
  Neither outcome establishes coverage.
- Do not infer correctness from the previous worker's confidence or from a
  syntactically valid evidence envelope.

Return exactly one raw JSON object with no markdown:
{"verdict":"VALID|INVALID|NEEDS_REVIEW","confidence":"certain|firm|tentative","summary":"decisive result with file:line evidence","reasoning":"independent checks performed"}

Use VALID with firm/certain confidence only when the attestation and rationale
survive independent source checks. Use INVALID for a concrete contradiction and
name it with file:line evidence. Use NEEDS_REVIEW when the frozen inputs cannot be
read or the claim cannot be decided. Do not emit Facts or Intents.
"""


def module_summary_description(plan_id: str, module: str) -> str:
    return f"{MODULE_SUMMARY_PREFIX}{plan_id}:{digest(module.encode())[:16]}"


def module_summary_groups(
    project: ProjectDetail,
    workdir: Path,
    config: CoverageConfig,
) -> list[dict]:
    """Return graph-ready fan-in groups once every cell in a module is reviewed."""
    plan_fact, _, plan = get_plan(project, workdir)
    state = coverage_state(project, workdir, config)
    by_module: dict[str, list[dict]] = {}
    for row in state["cells"]:
        by_module.setdefault(row["module"], []).append(row)
    groups = []
    for module, rows in sorted(by_module.items()):
        if any(row["status"] not in TERMINAL_OUTCOMES for row in rows):
            continue
        result_ids = [row["result_id"] for row in rows]
        if any(not result_id for result_id in result_ids):
            continue
        groups.append({
            "module": module,
            "plan_id": plan["id"],
            "plan_fact_id": plan_fact.id,
            "description": module_summary_description(plan["id"], module),
            "result_ids": result_ids,
            "rows": rows,
        })
    return groups


def module_summary_fact(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CoverageConfig,
) -> dict[str, str]:
    group = next(
        (item for item in module_summary_groups(project, workdir, config)
         if item["description"] == intent.description.strip()),
        None,
    )
    if group is None or (intent.type or "") != "synthesize":
        raise ValueError("Module summary intent does not match a completed coverage module")
    expected = {group["plan_fact_id"], *group["result_ids"]}
    if set(intent.from_) != expected:
        raise ValueError("Module summary must fan in the plan and every module coverage result")
    record = {
        "schema_version": 1,
        "kind": "coverage_module_summary",
        "plan_id": group["plan_id"],
        "module": group["module"],
        "results": [{
            "cell_id": row["cell_id"],
            "topic": row["topic"],
            "outcome": row["status"],
            "result_id": row["result_id"],
        } for row in group["rows"]],
    }
    directory = workdir / ".linen-coverage" / ("summary-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    path = directory / "module-summary.json"
    write_json(path, record)
    counts = {outcome: sum(row["status"] == outcome for row in group["rows"])
              for outcome in sorted(TERMINAL_OUTCOMES)}
    return {
        "type": "module_summary",
        "description": f"Coverage module {group['module']} completed: {counts}.",
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            f"plan_id: {group['plan_id']}\nstatus: completed"
        ),
    }
