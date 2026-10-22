from __future__ import annotations

import json
from typing import Any, Collection, Mapping

from linen.contracts import ContextRequest, ReasonWait
from linen.contracts import common
from linen.contracts.skill_audit import parse_finding_record
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


def extract_context_request(payload: Any) -> ContextRequest | None:
    """Extract one explicitly wrapped worker context request.

    Context expansion is intentionally opt-in: ordinary task payloads (and
    the legacy unwrapped forms) return ``None``.  Once a worker declares
    ``status=context_required``, the envelope is closed and validated so a
    worker cannot smuggle an unvalidated request or task result alongside it.
    """
    if not isinstance(payload, dict) or payload.get("accepted") is not True:
        return None
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("status") != "context_required":
        return None
    if set(payload) != {"accepted", "data"}:
        raise ValueError("context_required response must contain exactly accepted and data")
    if set(data) != {"status", "context_request"}:
        raise ValueError(
            "context_required data must contain exactly status and context_request"
        )
    raw_request = data.get("context_request")
    if not isinstance(raw_request, dict):
        raise ValueError("context_request must be an object")
    try:
        return ContextRequest.model_validate(raw_request)
    except ValueError as exc:
        raise ValueError(f"invalid context_request: {exc}") from exc


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
    if keys == {"resolve"}:
        return isinstance(payload["resolve"], list)
    if keys == {"wait"}:
        return isinstance(payload["wait"], dict)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


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
    if not data:
        # The Reason prompt explicitly permits a no-op when no useful
        # investigation or completion action remains. Requiring an Intent
        # whenever the queue is empty turns that valid decision into a false
        # task failure and can restart the same blocked audit indefinitely.
        return "noop", None
    if "wait" in data:
        if set(data) != {"wait"}:
            raise ValueError("wait must be supplied by itself")
        return "wait", ReasonWait.model_validate(data["wait"]).model_dump(mode="json")
    complete = data.get("complete")
    intents = data.get("intents")
    resolve = data.get("resolve")
    if resolve is not None:
        if not isinstance(resolve, list) or not resolve:
            raise ValueError(
                "resolve must be a non-empty array; "
                'example: {"resolve": [{"intent_id": "i006", "action": "abandon"}]}'
            )
        for i, item in enumerate(resolve):
            if not isinstance(item, dict) or set(item) != {"intent_id", "action"}:
                raise ValueError(
                    f"invalid resolve action at index {i}; each item must be "
                    '{"intent_id": "...", "action": "retry" | "abandon"}'
                )
            if not isinstance(item["intent_id"], str) or not item["intent_id"].strip():
                raise ValueError(f"resolve intent_id must be non-empty at index {i}")
            if item["action"] not in {"retry", "abandon"}:
                raise ValueError(
                    f"invalid resolve action at index {i}; action must be 'retry' or 'abandon'"
                )
        # A resolve disposition may be combined with follow-up intent
        # proposals in the same response (models routinely emit
        # {"resolve": [...], "intents": [...]}); dispositions are applied
        # first, then the proposals are registered.
        allowed_with_resolve = {"resolve"} | ({"intents"} if intents is not None else set())
        if not set(data) <= allowed_with_resolve:
            raise ValueError(
                "resolve may only be combined with intents; "
                'example: {"resolve": [{"intent_id": "i006", "action": "abandon"}], '
                '"intents": [{"from": [...], "action": "...", "target": "...", "description": "..."}]}'
            )
        followup_intents = None
        if intents is not None:
            followup_intents = _validate_intents_list(intents, open_intents_empty, max_intents)
        return "resolve", {"resolve": resolve, "intents": followup_intents}
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
        validated = _validate_intents_list(intents, open_intents_empty, max_intents)
        if not validated:
            return "noop", None
        return "intents", validated
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def _validate_intents_list(
    intents: Any, open_intents_empty: bool, max_intents: int,
) -> list[dict[str, Any]]:
    if not isinstance(intents, list):
        raise ValueError("intents must be an array")
    for i, intent in enumerate(intents):
        if (
            not isinstance(intent, dict)
            or "from" not in intent
            or "description" not in intent
            or "action" not in intent
            or "target" not in intent
        ):
            raise ValueError(f"invalid intent at index {i}")
        for field in ("action", "target"):
            if not isinstance(intent[field], str) or not intent[field].strip():
                raise ValueError(f"intent {field} must be a non-empty string at index {i}")
    if not intents and open_intents_empty:
        raise ValueError("intents must not be empty when open_intents is empty")
    intents = intents[:max_intents]
    if not intents:
        return []
    return intents


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
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
    fact: dict[str, Any] = {
        "description": description.strip(),
        "type": fact_type,
        "evidence": fact_evidence,
    }
    if data.get("proof") is not None:
        if not isinstance(data["proof"], dict):
            raise ValueError("proof must be an object when provided")
        fact["proof"] = data["proof"]
    return "fact", fact


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


# --- skill-driven audit mode (docs/skills/skill-driven-mode.md) -------------


# --- upstream-compatible coverage check contract (CF-S1-A) --------------------
# The upstream-equivalent primitives live in linen.contracts.common, because the
# coverage identity layer (CF-S1-B) must derive ids with exactly the same rules
# this contract layer uses to admit model output.  Equivalence here means "same
# accept / reject decision as the pinned Node validator", including its Unicode
# handling.
#
# These primitives are intentionally *not* the same contract as
# linen.contracts.common.validate_workspace_relative_path, whose weaker
# semantics (backslash normalisation, tolerated "." segments, tolerated drive
# letters) are not upstream-compatible.

CF_MAX_LIST_ITEMS = common.CF_MAX_LIST_ITEMS
CF_MAX_TEXT_LENGTH = common.CF_MAX_TEXT_LENGTH

CF_ADMISSION_ACCEPTED = "accepted"
CF_ADMISSION_REJECTED = "rejected"
CF_ADMISSION_INCOMPLETE = "incomplete"

CF_INCOMPLETE_MISSING_LOCAL_ARTIFACT = "missing_local_artifact"
CF_INCOMPLETE_ARTIFACT_PROMOTION_FAILED = "artifact_promotion_failed"
CF_INCOMPLETE_ARTIFACT_NOT_VERIFIED = "artifact_not_verified"
CF_INCOMPLETE_ASSIGNMENT_UNAVAILABLE = "assignment_unavailable"

CF_ARTIFACT_VERIFIED = "verified"
CF_ARTIFACT_NOT_VERIFIED = "not_verified"
CF_ARTIFACT_PROMOTION_FAILED = "promotion_failed"

_cf_js_trim = common.cf_js_trim
_cf_utf16_length = common.cf_utf16_length
_cf_has_forbidden_path_character = common.cf_has_forbidden_path_character
_cf_has_visible_character = common.cf_has_visible_character
_cf_is_visible_text = common.cf_is_visible_text
_cf_is_safe_relative_path = common.cf_is_safe_relative_path
_cf_is_safe_agent_id = common.cf_is_safe_agent_id
_cf_is_owned_artifact_path = common.cf_is_owned_artifact_path

_CF_CHECK_REQUIRED_FIELDS = (
    "agent_id",
    "reviewed_paths",
    "invariant",
    "method",
    "result",
    "artifact",
)


def _cf_validate_path_array(value: list[Any], *, location: str) -> None:
    if len(value) > CF_MAX_LIST_ITEMS:
        raise ValueError(f"{location}: exceeds {CF_MAX_LIST_ITEMS} entries")
    seen: set[str] = set()
    for index, entry in enumerate(value):
        if not _cf_is_safe_relative_path(entry):
            raise ValueError(f"{location}[{index}]: invalid repository-relative path")
        if entry in seen:
            raise ValueError(f"{location}[{index}]: duplicate entry")
        seen.add(entry)


def _cf_validate_check(check: object, *, location: str) -> None:
    """Validate one coverage check against the pinned upstream contract."""

    if not isinstance(check, dict):
        raise ValueError(f"{location}: expected object")
    for field in _CF_CHECK_REQUIRED_FIELDS:
        if field not in check:
            raise ValueError(f"{location}: missing required field {field}")
    agent_id = check["agent_id"]
    if not _cf_is_safe_agent_id(agent_id):
        raise ValueError(f"{location}.agent_id: expected a canonical lowercase agent ID")
    reviewed_paths = check["reviewed_paths"]
    if not isinstance(reviewed_paths, list):
        raise ValueError(f"{location}.reviewed_paths: expected array")
    if not reviewed_paths:
        raise ValueError(f"{location}.reviewed_paths: must not be empty")
    _cf_validate_path_array(reviewed_paths, location=f"{location}.reviewed_paths")
    if not _cf_is_visible_text(check["invariant"]):
        raise ValueError(f"{location}.invariant: invalid text")
    method = check["method"]
    if method not in {"source", "local"}:
        raise ValueError(f'{location}.method: expected "source" or "local"')
    if not _cf_is_visible_text(check["result"]):
        raise ValueError(f"{location}.result: invalid text")
    artifact = check["artifact"]
    if method == "source":
        if artifact is not None:
            raise ValueError(f"{location}.artifact: source-only check must use null")
    elif not _cf_is_owned_artifact_path(artifact, agent_id):
        raise ValueError(
            f"{location}.artifact: local check requires an artifact owned by agent {agent_id}"
        )


def _cf_validate_reviewed_path_ownership(
    unit_reviewed_paths: list[Any],
    checks: list[Any],
    *,
    location: str,
) -> None:
    """Upstream validateReviewedPathOwnership: unit paths equal the check union."""

    aggregate = {path for path in unit_reviewed_paths if isinstance(path, str)}
    owned: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            continue
        reviewed_paths = check.get("reviewed_paths")
        if not isinstance(reviewed_paths, list):
            continue
        for path in reviewed_paths:
            if isinstance(path, str):
                owned.add(path)
    for path in sorted(aggregate - owned):
        raise ValueError(f"{location}.reviewed_paths: {path!r} has no check owner")
    for path in sorted(owned - aggregate):
        raise ValueError(
            f"{location}.checks: owned path {path!r} is absent from aggregate reviewed_paths"
        )


def validate_hunt_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Validate a hunter's structured result (HUNTING.md contract, linen envelope).

    Returns ("hunt", data) with normalized keys: units, candidates, hardening,
    uncovered. Candidates keep their proposed_verdict record shape; verdict
    field exclusivity is enforced later by parse_finding_record at verify time.
    """
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if not isinstance(data, dict):
        raise ValueError(
            'hunt result must be {"accepted": true, "data": {"units": [...], '
            '"candidates": [...], "hardening": [...], "uncovered": [...]}}'
        )
    units = data.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError(
            'hunt data.units must be a non-empty array of '
            '{"coverage_id", "disposition", "reviewed_paths", "checks"} objects'
        )
    seen_ids: set[str] = set()
    for i, unit in enumerate(units):
        if not isinstance(unit, dict) or not isinstance(unit.get("coverage_id"), str):
            raise ValueError(f"invalid unit at index {i}: coverage_id is required")
        cid = unit["coverage_id"].strip()
        if not cid:
            raise ValueError(f"invalid unit at index {i}: empty coverage_id")
        if cid in seen_ids:
            raise ValueError(f"coverage_id {cid!r} appears more than once in units")
        seen_ids.add(cid)
        if unit.get("disposition") not in {"covered", "candidate", "blocked"}:
            raise ValueError(
                f"unit {cid}: disposition must be covered|candidate|blocked"
            )
        if not isinstance(unit.get("reviewed_paths"), list) or not unit["reviewed_paths"]:
            raise ValueError(f"unit {cid}: reviewed_paths must be a non-empty array")
        _cf_validate_path_array(
            unit["reviewed_paths"],
            location=f"units[{i}].reviewed_paths",
        )
        checks = unit.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ValueError(f"unit {cid}: checks must be a non-empty array")
        if len(checks) > CF_MAX_LIST_ITEMS:
            raise ValueError(f"unit {cid}: checks exceeds {CF_MAX_LIST_ITEMS} entries")
        for index, check in enumerate(checks):
            _cf_validate_check(check, location=f"units[{i}].checks[{index}]")
        _cf_validate_reviewed_path_ownership(
            unit["reviewed_paths"],
            checks,
            location=f"units[{i}]",
        )
    candidates = data.get("candidates", [])
    if not isinstance(candidates, list):
        raise ValueError("hunt data.candidates must be an array when provided")
    hardening = data.get("hardening", [])
    if not isinstance(hardening, list):
        raise ValueError("hunt data.hardening must be an array when provided")
    uncovered = data.get("uncovered", [])
    if not isinstance(uncovered, list):
        raise ValueError("hunt data.uncovered must be an array when provided")
    return "hunt", {
        "units": units,
        "candidates": candidates,
        "hardening": hardening,
        "uncovered": uncovered,
    }


def admit_hunt_payload(
    payload: dict[str, Any],
    *,
    verified_artifacts: Mapping[str, str] | None = None,
    known_agent_ids: Collection[str] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Trusted admission layer for a hunter payload (CF-S1-A).

    ``validate_hunt_payload`` has already decided that the payload is
    structurally valid.  This layer judges only whether the recorded evidence
    is *ready*, and it fails closed:

    * a check whose owner is not bound to a trusted assignment is never
      treated as trusted evidence (``assignment_unavailable``);
    * a local check whose artifact is missing, unpromoted or unverified is
      reported as ``incomplete`` with a machine-readable reason code.

    The model's own ``method`` and ``artifact`` values are never rewritten and
    ``disposition`` is never extended, so a missing local artifact can never
    silently downgrade into a source check.

    ``verified_artifacts`` maps an artifact path to one of ``verified``,
    ``not_verified`` or ``promotion_failed``; ``known_agent_ids`` is the set of
    agent ids a trusted dispatcher actually assigned.  ``None`` means "no
    trusted registry is available", which fails closed.
    """

    kind, data = validate_hunt_payload(payload)
    if kind != "hunt" or data is None:
        return CF_ADMISSION_REJECTED, None

    artifacts = verified_artifacts or {}
    reasons: list[str] = []
    per_unit: list[dict[str, Any]] = []
    for unit in data["units"]:
        unit_reasons: list[str] = []
        for check in unit.get("checks", []):
            agent_id = check.get("agent_id")
            if known_agent_ids is None or agent_id not in known_agent_ids:
                unit_reasons.append(CF_INCOMPLETE_ASSIGNMENT_UNAVAILABLE)
            if check.get("method") != "local":
                continue
            artifact_state = artifacts.get(check.get("artifact"))
            if artifact_state is None:
                unit_reasons.append(CF_INCOMPLETE_MISSING_LOCAL_ARTIFACT)
            elif artifact_state == CF_ARTIFACT_PROMOTION_FAILED:
                unit_reasons.append(CF_INCOMPLETE_ARTIFACT_PROMOTION_FAILED)
            elif artifact_state != CF_ARTIFACT_VERIFIED:
                unit_reasons.append(CF_INCOMPLETE_ARTIFACT_NOT_VERIFIED)
        unique = sorted(set(unit_reasons))
        reasons.extend(unique)
        per_unit.append({
            "coverage_id": unit.get("coverage_id"),
            "state": CF_ADMISSION_INCOMPLETE if unique else CF_ADMISSION_ACCEPTED,
            "reason_codes": unique,
        })

    overall = CF_ADMISSION_INCOMPLETE if reasons else CF_ADMISSION_ACCEPTED
    admitted = dict(data)
    admitted["admission"] = {
        "state": overall,
        "reason_codes": sorted(set(reasons)),
        "units": per_unit,
    }
    return overall, admitted


def validate_skill_verifier_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Validate a candidate verifier output.

    Returns ("decision", data) where data carries decision, fingerprint,
    record (parsed into the verdict-exclusive contract via
    parse_finding_record), and rationale.
    """
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if not isinstance(data, dict):
        raise ValueError(
            'verifier output must be {"accepted": true, "data": {"decision": '
            '"confirmed|needs_validation|rejected", "fingerprint": "...", '
            '"record": {...}, "rationale": "..."}}'
        )
    decision = data.get("decision")
    if decision not in {"confirmed", "needs_validation", "rejected"}:
        raise ValueError(
            'verifier decision must be one of confirmed|needs_validation|rejected; '
            "got {!r}".format(decision)
        )
    record_data = data.get("record")
    if not isinstance(record_data, dict):
        raise ValueError("verifier record must be an object matching the verdict contract")
    record = parse_finding_record(record_data)
    fingerprint = data.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise ValueError("verifier fingerprint must be a non-empty string")
    if str(record.fingerprint).strip() != fingerprint.strip():
        raise ValueError(
            "verifier fingerprint must match the record fingerprint unless a "
            "genuinely different root cause was found (then say so in rationale)"
        )
    rationale = data.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("verifier rationale must be a non-empty string")
    return "decision", {
        "decision": decision,
        "fingerprint": fingerprint.strip(),
        "record": json.loads(record.model_dump_json(exclude_none=True)),
        "rationale": rationale.strip()[:2000],
    }


def validate_critic_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Validate a coverage critic's output (missing units / reassignments)."""
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if not isinstance(data, dict):
        raise ValueError(
            'critic output must be {"accepted": true, "data": {"missing_units": '
            "[...], \"reassignments\": [...], \"coverage_statement\": \"...\"}}"
        )
    missing = data.get("missing_units", [])
    reassignments = data.get("reassignments", [])
    statement = data.get("coverage_statement")
    if not isinstance(missing, list) or not isinstance(reassignments, list):
        raise ValueError("critic missing_units and reassignments must be arrays")
    if not isinstance(statement, str) or not statement.strip():
        raise ValueError("critic coverage_statement must be a non-empty string")
    for i, unit in enumerate(missing):
        if not isinstance(unit, dict) or not all(
            isinstance(unit.get(key), str) and unit[key].strip()
            for key in ("surface", "boundary", "subsystem", "attack_class", "reason")
        ):
            raise ValueError(
                f"invalid missing_units entry at index {i}: surface, boundary, "
                "subsystem, attack_class, and reason are required strings"
            )
    return "critic", {
        "missing_units": missing,
        "reassignments": reassignments,
        "coverage_statement": statement.strip()[:4000],
    }


def validate_record_verification_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Validate a Phase-5 record verifier's output (verified | replace)."""
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if not isinstance(data, dict):
        raise ValueError(
            'record verification output must be {"accepted": true, "data": '
            '{"decision": "verified|replace", "fingerprint": "...", '
            '"reason": "...", "record": {...}}} — record only for replace'
        )
    decision = data.get("decision")
    if decision not in {"verified", "replace"}:
        raise ValueError(
            f'record verification decision must be "verified" or "replace"; got {decision!r}'
        )
    fingerprint = data.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise ValueError("record verification fingerprint must be a non-empty string")
    if decision == "replace":
        record_data = data.get("record")
        if not isinstance(record_data, dict):
            raise ValueError("a replace decision requires a full corrected record object")
        record = parse_finding_record(record_data)
        reason = data.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a replace decision requires a reason citing file:line")
        return "record_verification", {
            "decision": "replace",
            "fingerprint": fingerprint.strip(),
            "record": json.loads(record.model_dump_json(exclude_none=True)),
            "reason": reason.strip()[:2000],
        }
    return "record_verification", {"decision": "verified", "fingerprint": fingerprint.strip()}
