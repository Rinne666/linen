"""Strict input/output contracts for dispatcher-owned isolated PoC execution.

The generated program is untrusted data. This module never evaluates it on the
dispatcher host; callers pass it to a disposable offline sandbox backend.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from linen.dispatcher.config import ReviewSandboxConfig
from linen.dispatcher.runtime.review_sandbox import ReviewSandboxBackend
from linen.dispatcher.runtime.process import ProcessResult

MAX_PROGRAM_BYTES = 64 * 1024
MAX_CASE_BYTES = 8 * 1024
MAX_OBSERVATION_BYTES = 16 * 1024
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")


class PocContractError(ValueError):
    """Generated PoC or sandbox observation violated the bounded contract."""


@dataclass(frozen=True)
class PocObservation:
    case_id: str
    oracle_kind: str
    capability_observed: Any
    observed_outcome: dict[str, Any]


def validate_program(program: str) -> bytes:
    """Bound generated Python source; never compile or execute it here."""
    if not isinstance(program, str):
        raise PocContractError("PoC program must be text")
    try:
        encoded = program.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise PocContractError("PoC program must be valid UTF-8") from exc
    if not encoded or len(encoded) > MAX_PROGRAM_BYTES:
        raise PocContractError("PoC program is empty or exceeds the size limit")
    return encoded


def encode_case(case: dict[str, Any]) -> bytes:
    if not isinstance(case, dict) or set(case) - {"case_id", "input", "expected"}:
        raise PocContractError("PoC case contains unsupported fields")
    if not isinstance(case.get("case_id"), str) or not _IDENTIFIER.fullmatch(case["case_id"]):
        raise PocContractError("PoC case requires a bounded case_id")
    data = json.dumps(case, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > MAX_CASE_BYTES:
        raise PocContractError("PoC case exceeds the size limit")
    return data


def parse_observation(stdout: str) -> PocObservation:
    try:
        raw = stdout.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise PocContractError("PoC output is not valid UTF-8") from exc
    if not raw or len(raw) > MAX_OBSERVATION_BYTES:
        raise PocContractError("PoC output is empty or exceeds the size limit")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PocContractError("PoC must emit one JSON observation") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "case_id", "oracle_kind", "capability_observed", "observed_outcome",
    }:
        raise PocContractError("PoC observation has an invalid schema")
    if not isinstance(payload["case_id"], str) or not _IDENTIFIER.fullmatch(payload["case_id"]):
        raise PocContractError("PoC observation requires a bounded case_id")
    if not isinstance(payload["oracle_kind"], str) or not _IDENTIFIER.fullmatch(payload["oracle_kind"]):
        raise PocContractError("PoC observation requires a bounded oracle_kind")
    outcome = payload["observed_outcome"]
    if not isinstance(outcome, dict) or not outcome:
        raise PocContractError("PoC observation requires a non-empty observed_outcome object")
    capability = payload["capability_observed"]
    if capability is None or isinstance(capability, (dict, list)):
        raise PocContractError("capability_observed must be a scalar")
    return PocObservation(payload["case_id"], payload["oracle_kind"], capability, outcome)


def validate_pair(
    positive: PocObservation,
    negative: PocObservation,
    *,
    positive_case_id: str,
    negative_case_id: str,
) -> dict[str, Any]:
    """Require distinct cases, a shared oracle, and an observed capability delta."""
    if positive_case_id == negative_case_id:
        raise PocContractError("positive and negative controls must use distinct cases")
    if positive.case_id != positive_case_id or negative.case_id != negative_case_id:
        raise PocContractError("PoC observation does not match its assigned control case")
    if positive.oracle_kind != negative.oracle_kind:
        raise PocContractError("positive and negative controls must use the same oracle")
    if positive.capability_observed == negative.capability_observed:
        raise PocContractError("positive and negative controls show no capability delta")
    return {
        "oracle_kind": positive.oracle_kind,
        "positive": positive.observed_outcome,
        "negative": negative.observed_outcome,
        "program_sha256": None,
    }


def program_digest(program: bytes) -> str:
    return hashlib.sha256(program).hexdigest()


def execute_control_pair(
    config: ReviewSandboxConfig,
    source: Path,
    snapshot: dict[str, Any],
    run_root: Path,
    program: str,
    positive_case: dict[str, Any],
    negative_case: dict[str, Any],
    *,
    timeout_seconds: int,
) -> tuple[dict[str, Any], PocObservation, PocObservation]:
    """Run both cases in separate offline containers against one frozen snapshot.

    The caller is responsible for using dispatcher-owned, unique run paths and
    registering the returned provenance through the normal execution protocol.
    """
    if not config.enabled or config.network != "none" or config.env_allowlist:
        raise PocContractError("PoC execution requires enabled network=none sandbox with empty env allowlist")
    if timeout_seconds <= 0:
        raise PocContractError("PoC timeout must be positive")
    program_bytes = validate_program(program)
    pos_input = encode_case(positive_case)
    neg_input = encode_case(negative_case)
    if positive_case["case_id"] == negative_case["case_id"]:
        raise PocContractError("positive and negative controls must use distinct case IDs")
    observations: list[PocObservation] = []
    for case in (positive_case, negative_case):
        backend = ReviewSandboxBackend(
            config, source, snapshot, run_root / case["case_id"],
            {"poc.py": program_bytes, "case.json": encode_case(case)},
        )
        process = backend.build_exec_process(
            str(run_root.parent), {}, ["python3", "-I", "/input/poc.py", "/input/case.json"],
            timeout_seconds=timeout_seconds,
        )
        try:
            process.start()
            result: ProcessResult = process.communicate(timeout_seconds)
        finally:
            if process.created:
                process.kill()
        if result.cancelled:
            raise PocContractError("PoC control execution was cancelled")
        if result.timed_out:
            raise PocContractError(f"PoC control {case['case_id']} timed out")
        if result.returncode != 0:
            raise PocContractError(f"PoC control {case['case_id']} exited with {result.returncode}")
        observation = parse_observation(result.stdout)
        if observation.case_id != case["case_id"]:
            raise PocContractError("PoC observation does not match its assigned control case")
        observations.append(observation)
    pair = validate_pair(
        observations[0], observations[1],
        positive_case_id=positive_case["case_id"],
        negative_case_id=negative_case["case_id"],
    )
    pair["program_sha256"] = program_digest(program_bytes)
    pair["snapshot_id"] = snapshot.get("id")
    return pair, observations[0], observations[1]
