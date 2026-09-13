from __future__ import annotations

from typing import Any

from linen.dispatcher.output_parser import extract_json_object
from linen.server.models import REVIEW_DIAGNOSTIC_FIELDS


REVIEW_DIAGNOSTIC_REQUIRED_KEYS: dict[str, frozenset[str]] = {
    "protection_search": frozenset({
        "language", "framework", "middleware", "application", "documentation",
    }),
    "fp_pattern_check": frozenset({
        "1_unsafe_no_path_trace", "2_phantom_validation", "3_framework_blindness",
        "4_same_origin", "5_cve_no_reachability", "6_config_as_vuln",
        "7_test_code", "8_double_counting",
    }),
    "cold_verification": frozenset({
        "sub_claims", "sub_claim_failure", "static_status", "poc_status",
        "prosecution", "defense", "severity_challenged", "isolation_observed",
    }),
    "contradiction_analysis": frozenset({"triz", "game_theory"}),
    "attestation_check": frozenset({
        "artifact_integrity", "source_consistency", "scope_complete", "contradictions",
    }),
    "summary_check": frozenset({
        "expected_input_ids", "referenced_input_ids", "missing_input_ids",
        "contradictions", "fan_in_complete",
    }),
}


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


def _unwrap_wrapped_payload(payload: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys == {"complete"}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if keys == {"intents"}:
        return isinstance(payload["intents"], list)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact")) and (
        "complete" not in payload or _is_dict(payload.get("complete"))
    )


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    return isinstance(payload, dict) and set(payload) == {"description"}


def validate_reason_payload(
    payload: dict[str, Any], open_intents_empty: bool, max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from LLMs
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if not isinstance(complete, dict) or "from" not in complete or "description" not in complete:
            raise ValueError("invalid complete payload")
        if (not isinstance(complete["from"], list) or not complete["from"]
                or any(not isinstance(fid, str) or not fid.strip() for fid in complete["from"])
                or not isinstance(complete["description"], str) or not complete["description"].strip()):
            raise ValueError("complete requires non-empty fact IDs and description")
        return "complete", complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        if not intents and open_intents_empty:
            raise ValueError("intents must not be empty when open_intents is empty")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None
        return "intents", intents
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def validate_bootstrap_execute_payload(payload: dict[str, Any]) -> tuple[str, dict[str, str | None] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result: dict[str, str | None] = {"fact_description": fact_description.strip()}
    fact_type = _optional_text(fact.get("type"))
    if fact.get("type") is not None and fact_type is None:
        raise ValueError("fact.type must be a non-empty string when provided")
    fact_evidence = _optional_text(fact.get("evidence"))
    if fact.get("evidence") is not None and fact_evidence is None:
        raise ValueError("fact.evidence must be a non-empty string when provided")
    result["fact_type"] = fact_type
    result["fact_evidence"] = fact_evidence

    complete = data.get("complete")
    if complete is None:
        result["complete_description"] = None
        return "fact", result
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", fact_description.strip()


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, dict[str, str | None] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    fact_type = _optional_text(data.get("type"))
    if data.get("type") is not None and fact_type is None:
        raise ValueError("type must be a non-empty string when provided")
    fact_evidence = _optional_text(data.get("evidence"))
    if data.get("evidence") is not None and fact_evidence is None:
        raise ValueError("evidence must be a non-empty string when provided")
    return "fact", {
        "description": description.strip(),
        "type": fact_type,
        "evidence": fact_evidence,
    }


def validate_review_payload(
    payload: dict[str, Any],
    *,
    required_diagnostics: tuple[str, ...] = (),
) -> tuple[str, dict[str, Any] | None]:
    """Validate a review task's structured output.

    Wrapped form (the form `vuln_audit/review.md` teaches):
        {"accepted": true, "data": {"verdict": "...", "summary": "...", ...}}
    Unwrapped form (LLM dropped the envelope):
        {"verdict": "...", "summary": "..."}

    Phase 1a (3 review modes) — the payload may additionally carry
    mode-specific diagnostic fields, which we preserve through validation
    but do not constrain:

    - `protection_search`     — devils-advocate (5-layer table)
    - `fp_pattern_check`      — devils-advocate (8 Claude FP patterns)
    - `cold_verification`     — cold-verifier (sub-claims, briefs, etc.)
    - `contradiction_analysis` — contradiction-reasoner (TRIZ + Game Theory)

    These fields are stored as opaque dicts on the returned review record
    so downstream consumers (UI, future analyzers) can read them. They
    MUST be JSON objects when present; non-dict values are rejected.
    """
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        # No `accepted` key — treat the whole payload as the review data.
        if not isinstance(payload, dict):
            raise ValueError("accepted must be true or false")
        if "verdict" not in payload or "summary" not in payload:
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    verdict = data.get("verdict")
    if not isinstance(verdict, str) or verdict not in {"VALID", "INVALID", "NEEDS_REVIEW"}:
        raise ValueError(
            "verdict must be one of: VALID, INVALID, NEEDS_REVIEW"
        )
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary is required")
    confidence = data.get("confidence")
    if confidence is not None and confidence not in {"certain", "firm", "tentative"}:
        raise ValueError("confidence must be one of: certain, firm, tentative")
    reasoning = data.get("reasoning")
    if reasoning is not None and not isinstance(reasoning, str):
        raise ValueError("reasoning must be a string when provided")

    # Mode-specific diagnostic fields — pass through when valid, reject
    # malformed ones. Type is widened to dict[str, Any] in the return
    # because of these optional fields.
    extras: dict[str, Any] = {}
    for key in REVIEW_DIAGNOSTIC_FIELDS:
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be an object when provided")
        extras[key] = value

    unknown_required = set(required_diagnostics) - set(REVIEW_DIAGNOSTIC_REQUIRED_KEYS)
    if unknown_required:
        raise ValueError(
            "unknown required review diagnostics: " + ", ".join(sorted(unknown_required))
        )
    for key in required_diagnostics:
        value = extras.get(key)
        if value is None:
            raise ValueError(f"{key} is required for this review profile")
        missing = REVIEW_DIAGNOSTIC_REQUIRED_KEYS[key] - set(value)
        if missing:
            raise ValueError(
                f"{key} missing required fields: " + ", ".join(sorted(missing))
            )
    attestation = extras.get("attestation_check")
    if attestation is not None and not isinstance(attestation.get("contradictions"), list):
        raise ValueError("attestation_check.contradictions must be an array")
    summary_check = extras.get("summary_check")
    if summary_check is not None:
        for key in (
            "expected_input_ids", "referenced_input_ids", "missing_input_ids", "contradictions",
        ):
            if not isinstance(summary_check.get(key), list):
                raise ValueError(f"summary_check.{key} must be an array")
        if type(summary_check.get("fan_in_complete")) is not bool:
            raise ValueError("summary_check.fan_in_complete must be a boolean")

    return "review", {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary.strip(),
        "reasoning": (reasoning.strip() if isinstance(reasoning, str) and reasoning.strip() else None),
        **extras,
    }
