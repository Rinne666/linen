from __future__ import annotations

import json

import pytest

from linen.dispatcher.runtime.poc_runner import (
    PocContractError,
    encode_case,
    parse_observation,
    validate_pair,
    validate_program,
)


def observation(case_id: str, capability: object) -> str:
    return json.dumps({
        "case_id": case_id,
        "oracle_kind": "response-status",
        "capability_observed": capability,
        "observed_outcome": {"status": capability},
    })


def test_poc_program_and_case_are_bounded_data():
    assert validate_program("print('hello')") == b"print('hello')"
    assert json.loads(encode_case({"case_id": "positive", "input": {"role": "admin"}}))[
        "case_id"
    ] == "positive"
    with pytest.raises(PocContractError):
        validate_program("x" * (64 * 1024 + 1))
    with pytest.raises(PocContractError):
        encode_case({"case_id": "../escape", "input": {}})
    with pytest.raises(PocContractError):
        encode_case({"case_id": "positive", "input": {}, "command": "rm -rf /"})


def test_pair_requires_matching_oracle_and_observed_capability_delta():
    positive = parse_observation(observation("positive", "allowed"))
    negative = parse_observation(observation("negative", "denied"))
    result = validate_pair(
        positive, negative, positive_case_id="positive", negative_case_id="negative",
    )
    assert result["oracle_kind"] == "response-status"
    with pytest.raises(PocContractError, match="no capability delta"):
        validate_pair(
            positive, parse_observation(observation("negative", "allowed")),
            positive_case_id="positive", negative_case_id="negative",
        )


def test_observation_rejects_bad_json_extra_fields_and_case_substitution():
    with pytest.raises(PocContractError):
        parse_observation("not json")
    malformed = json.loads(observation("positive", "allowed"))
    malformed["success"] = True
    with pytest.raises(PocContractError):
        parse_observation(json.dumps(malformed))
