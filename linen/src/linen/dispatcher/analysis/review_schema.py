"""Native response shapes for review profiles; semantic checks stay separate."""

from __future__ import annotations

from typing import Any

from linen.dispatcher.contracts import REVIEW_DIAGNOSTIC_REQUIRED_KEYS


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def review_response_schema(required: tuple[str, ...], *, candidate: bool) -> dict[str, Any]:
    string = {"type": "string"}
    strings = {"type": "array", "items": string}
    properties: dict[str, Any] = {
        "verdict": {"type": "string", "enum": ["VALID", "INVALID", "NEEDS_REVIEW"]},
        "confidence": {"type": "string", "enum": ["certain", "firm", "tentative"]},
        "summary": {"type": "string", "minLength": 1},
        "reasoning": string,
    }
    for key in required:
        fields = {name: string for name in sorted(REVIEW_DIAGNOSTIC_REQUIRED_KEYS[key])}
        if key == "protection_search":
            layer = _object({"found": string, "blocks": string, "evidence": string})
            fields = {name: layer for name in fields}
        elif key == "attestation_check":
            fields["contradictions"] = strings
        elif key == "summary_check":
            fields = {name: strings for name in fields}
            fields["fan_in_complete"] = {"type": "boolean"}
        elif key == "cold_verification":
            fields["sub_claims"] = _object({"items": {"type": "array", "items": _object({
                "fact_id": string, "claim": string, "evidence": string,
                "status": {"type": "string", "enum": ["supported", "refuted", "unresolved"]},
            })}})
            fields["static_status"] = {"type": "string", "enum": ["ok", "blocked"]}
        elif key == "contradiction_analysis":
            fields = {
                "triz": _object({"tension_found": string, "sacrifice": string, "exploitable": string, "evidence": string}),
                "game_theory": _object({"mechanism_found": string, "adaptive_attacker_path": string, "evidence": string}),
            }
        properties[key] = _object(fields)
    if candidate:
        properties["finding_assessment"] = _object({
            "classification": {"type": "string", "enum": ["vulnerability", "design_weakness", "hardening_advice", "false_positive", "inconclusive"]},
            "threat_model_status": {"type": "string", "enum": ["in_scope", "explicitly_excluded", "acknowledged_design_weakness", "unknown"]},
            "threat_model_evidence": strings,
            "attacker_preconditions": _object({name: {"type": "boolean"} for name in (
                "requires_admin_action", "requires_social_engineering", "requires_out_of_scope_privilege", "requires_insecure_configuration",
            )}),
            "direct_impact": _object({
                **{name: {"type": "boolean"} for name in ("confidentiality", "integrity", "availability", "documented_trust_boundary_violation")},
                "impact_path": string,
            }),
        })
    return _object(properties)
