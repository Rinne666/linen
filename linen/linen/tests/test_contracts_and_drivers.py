from __future__ import annotations

import json

import pytest

from linen.dispatcher.contracts import (
    extract_context_request,
    parse_json_output,
    validate_explore_payload,
    validate_reason_payload,
)
from linen.contracts import ContextRequest
from linen.dispatcher.runtime.process import LocalProcess
from linen.dispatcher.workers.adapters.pi import PiDriver


def test_parse_json_output_extracts_object_from_markdown_noise() -> None:
    assert parse_json_output('result:\n```json\n{"accepted": true, "data": {}}\n```') == {
        "accepted": True,
        "data": {},
    }


def test_extract_context_request_accepts_only_closed_context_required_envelope() -> None:
    payload = {
        "accepted": True,
        "data": {
            "status": "context_required",
            "context_request": {
                "node_ids": ["f2"],
                "relation_types": ["supports"],
                "reason": "need source proof",
            },
        },
    }
    request = extract_context_request(payload)
    assert isinstance(request, ContextRequest)
    assert request.node_ids == ["f2"]

    assert extract_context_request({"accepted": True, "data": {}}) is None
    assert extract_context_request({"node_ids": ["f2"], "reason": "legacy"}) is None


@pytest.mark.parametrize(
    "payload, message",
    [
        (
            {
                "accepted": True,
                "data": {
                    "status": "context_required",
                    "context_request": {"node_ids": [], "reason": "x"},
                    "unexpected": True,
                },
            },
            "exactly status and context_request",
        ),
        (
            {
                "accepted": True,
                "data": {"status": "context_required", "context_request": {"node_ids": []}},
            },
            "invalid context_request",
        ),
        (
            {
                "accepted": True,
                "data": {"status": "context_required", "context_request": "not-an-object"},
            },
            "context_request must be an object",
        ),
    ],
)
def test_extract_context_request_rejects_malformed_context_required(payload, message) -> None:
    with pytest.raises(ValueError, match=message):
        extract_context_request(payload)


def test_reason_payload_limits_number_of_intents() -> None:
    kind, intents = validate_reason_payload(
        {
            "accepted": True,
            "data": {
                "intents": [
                    {"from": ["f001"], "action": "trace", "target": "one", "description": "one"},
                    {"from": ["f001"], "action": "trace", "target": "two", "description": "two"},
                ]
            },
        },
        open_intents_empty=True,
        max_intents=1,
    )

    assert kind == "intents"
    assert intents == [{"from": ["f001"], "action": "trace", "target": "one", "description": "one"}]


def test_reason_payload_validates_blocked_intent_resolution() -> None:
    kind, actions = validate_reason_payload(
        {
            "accepted": True,
            "data": {"resolve": [{"intent_id": "i123", "action": "abandon"}]},
        },
        open_intents_empty=False,
        max_intents=3,
    )
    assert kind == "resolve"
    assert actions == [{"intent_id": "i123", "action": "abandon"}]


def test_reason_payload_rejects_unknown_resolution_action() -> None:
    with pytest.raises(ValueError, match="invalid resolve action"):
        validate_reason_payload(
            {"accepted": True, "data": {"resolve": [{"intent_id": "i123", "action": "replace"}]}},
            open_intents_empty=False,
            max_intents=3,
        )


def test_reason_payload_requires_intent_when_none_are_open() -> None:
    with pytest.raises(ValueError, match="intents is required"):
        validate_reason_payload(
            {"accepted": True, "data": {}},
            open_intents_empty=True,
            max_intents=3,
        )


def test_explore_payload_rejects_planning_text() -> None:
    with pytest.raises(ValueError):
        validate_explore_payload(parse_json_output("Need inspect files and keep working."))


def test_pi_driver_extracts_session_and_last_assistant_text() -> None:
    driver = PiDriver()
    stdout = "\n".join(
        [
            json.dumps({"type": "session", "id": "session-123"}),
            json.dumps(
                {
                    "type": "turn_end",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": '{"accepted":true,"data":{}}'}],
                    },
                }
            ),
        ]
    )

    assert driver.extract_session(None, stdout, "") == "session-123"
    assert driver.extract_response_text(stdout, "") == '{"accepted":true,"data":{}}'


def test_local_process_drain_closes_stream_after_read_failure() -> None:
    class Stream:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _size: int) -> str:
            raise OSError("stream failed")

        def close(self) -> None:
            self.closed = True

    stream = Stream()
    LocalProcess._drain(stream, [])

    assert stream.closed
