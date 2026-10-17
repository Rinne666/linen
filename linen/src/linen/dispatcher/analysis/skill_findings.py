"""Findings serialization, validation, and helpers for the skill-driven mode.

- findings.json is derived from ``finding_record`` facts and validated with the
  vendored zero-dependency upstream validator (validate-findings.cjs). A failed
  validation must not be silently shipped: callers surface the error and the
  report is marked incomplete rather than trusted.
- Replacement bounce: a substantive replacement (root cause, trace, execution,
  observed result, or severity changed) requires a fresh independent verifier;
  immaterial wording/line-number corrections apply directly (VALIDATION-AND-REPORTING.md).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from linen.contracts.skill_audit import parse_finding_record

VENDORED_SKILL_DIR = Path(".linen-runtime/cf-security-audit-skill/skills/security-audit")

SUBSTANTIVE_FIELDS = (
    "root_cause", "claimed_root_cause", "trace", "execution",
    "observed_result", "severity", "conditions", "verdict",
)


def coverage_seeds_from_config(config) -> list[dict]:
    """Return the configured seed coverage units as plain dicts."""
    audit = getattr(config, "audit", None)
    skill = getattr(audit, "skill_driven", None) if audit is not None else None
    if skill is None:
        return []
    return [dict(seed) for seed in getattr(skill, "coverage_seeds", [])]


def max_bounces(config) -> int:
    audit = getattr(config, "audit", None)
    skill = getattr(audit, "skill_driven", None) if audit is not None else None
    return int(getattr(skill, "max_bounces", 2)) if skill is not None else 2


def is_substantive_replacement(original: dict | None, replacement: dict) -> bool:
    """True when a record verification replacement must itself be re-verified.

    An unknown original (missing proof payload) is always substantive: never
    apply a replacement blindly just because we lost the baseline.
    """
    if not isinstance(original, dict):
        return True
    if original.get("verdict") != replacement.get("verdict"):
        return True
    for field in SUBSTANTIVE_FIELDS:
        if field == "verdict":
            continue
        if field == "trace":
            if _trace_signature(original.get("trace")) != _trace_signature(replacement.get("trace")):
                return True
            continue
        if original.get(field) != replacement.get(field):
            return True
    return False


def _trace_signature(trace: object) -> list:
    if not isinstance(trace, list):
        return []
    return [
        (step.get("step"), step.get("path"), step.get("line"))
        for step in trace if isinstance(step, dict)
    ]


def collect_finding_records(project) -> list[dict]:
    """Collect verdict records from ``finding_record`` facts plus hunt candidates.

    Records from verify-candidate (semantic_type in confirmed_finding /
    candidate_finding / false_positive with a finding_record payload) win over
    the hunt-time proposal for the same fingerprint; hunt proposals that were
    never verified are emitted as needs_validation with a blocker noting that
    candidate validation never ran (honest-incomplete rule).
    """
    verified: dict[str, dict] = {}
    unverified: list[dict] = []
    for fact in project.facts:
        attributes = (fact.proof.attributes if fact.proof else None) or {}
        record = attributes.get("finding_record")
        if not isinstance(record, dict):
            continue
        fingerprint = str(record.get("fingerprint") or "")
        if fact.semantic_type in {"confirmed_finding", "candidate_finding", "false_positive"} \
                and fact.type == "finding_record":
            verified[fingerprint] = record
        elif fact.type == "candidate_finding":
            unverified.append(record)
    for record in unverified:
        fingerprint = str(record.get("fingerprint") or "")
        if fingerprint in verified:
            continue
        record = dict(record)
        record["verdict"] = "needs_validation"
        blockers = list(record.get("blockers") or [])
        blockers.append("candidate validation never ran for this fingerprint (run incomplete)")
        record["blockers"] = blockers
        if not record.get("validation_plan"):
            record["validation_plan"] = {
                "local": "Re-run candidate validation against the frozen source.",
            }
        verified[fingerprint] = record
    return list(verified.values())


def write_findings_json(project, out_dir: Path, skill_dir: Path | None = None) -> dict:
    """Write findings.json from graph facts and validate it with the upstream checker.

    Returns {"ok": bool, "path": str, "records": int, "error": str | None,
    "validator_output": str | None}. ``ok`` is False when validation fails;
    callers must treat the report as incomplete in that case.
    """
    directory = skill_dir or VENDORED_SKILL_DIR
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    records = collect_finding_records(project)
    # upstream validate-findings.cjs expects a top-level array of records
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    validator = directory / "validate-findings.cjs"
    if not validator.exists():
        return {"ok": False, "path": str(path), "records": len(records),
                "error": f"upstream validator missing at {validator}", "validator_output": None}
    try:
        result = subprocess.run(
            ["node", str(validator), str(path)],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return {"ok": False, "path": str(path), "records": len(records),
                "error": "node is not available for the findings validator",
                "validator_output": None}
    except subprocess.TimeoutExpired:
        return {"ok": False, "path": str(path), "records": len(records),
                "error": "findings validator timed out", "validator_output": None}
    if result.returncode != 0:
        return {"ok": False, "path": str(path), "records": len(records),
                "error": "findings validator rejected findings.json",
                "validator_output": (result.stdout + result.stderr)[-4000:]}
    return {"ok": True, "path": str(path), "records": len(records),
            "error": None, "validator_output": result.stdout[-1000:]}


def coverage_units_summary(project) -> list[dict]:
    """Summarize coverage-unit facts for the critic prompt."""
    units = []
    for fact in project.facts:
        if fact.type != "coverage_unit":
            continue
        attributes = (fact.proof.attributes if fact.proof else None) or {}
        unit = attributes.get("coverage_unit")
        if isinstance(unit, dict):
            units.append(unit)
    return units


def candidates_summary(project) -> list[dict]:
    """Summarize candidate fingerprints for the critic prompt."""
    return [
        {
            "fact_id": fact.id,
            "fingerprint": (_attr_record(fact) or {}).get("fingerprint"),
            "title": (_attr_record(fact) or {}).get("title"),
            "semantic_type": fact.semantic_type,
        }
        for fact in project.facts
        if fact.type in {"candidate_finding", "finding_record"}
    ]


def _attr_record(fact) -> dict | None:
    attributes = (fact.proof.attributes if fact.proof else None) or {}
    record = attributes.get("finding_record")
    return record if isinstance(record, dict) else None


# re-export so tasks/skill_audit.py can share the canonical parser
from linen.contracts.skill_audit import parse_finding_record  # noqa: E402,F401
