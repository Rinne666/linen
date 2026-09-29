from __future__ import annotations

import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    seen: set[str] = set()

    for candidate in _candidate_segments(text):
        segment = candidate.strip()
        if not segment or segment in seen:
            continue
        seen.add(segment)

        try:
            parsed = json.loads(segment)
        except json.JSONDecodeError:
            recovered = _close_truncated_json(segment)
            if recovered is not None:
                return recovered
        else:
            if isinstance(parsed, dict):
                return parsed

        for start in _object_start_positions(segment):
            try:
                parsed, _end = decoder.raw_decode(segment[start:])
            except json.JSONDecodeError:
                recovered = _close_truncated_json(segment[start:])
                if recovered is None:
                    continue
                parsed = recovered
            if isinstance(parsed, dict):
                return parsed

    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    segments = [text.strip()]
    segments.extend(match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(text))
    return segments


def _object_start_positions(text: str) -> list[int]:
    return [index for index, char in enumerate(text) if char == "{"]


def _close_truncated_json(text: str) -> dict[str, Any] | None:
    """Recover a JSON object cut off only after a complete value.

    Worker CLIs can truncate otherwise valid JSON at an output-size boundary.
    Close only unmatched containers; never repair strings, scalar tokens, or
    missing separators, so malformed model output still fails closed.
    """
    stack: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            stack.append("}")
        elif char == "[":
            stack.append("]")
        elif char in "}]":
            if not stack or stack.pop() != char:
                return None

    if in_string or not stack or not text.rstrip().endswith(("}", "]", '"')):
        return None
    try:
        parsed = json.loads(text.rstrip() + "".join(reversed(stack)))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
