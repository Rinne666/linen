from __future__ import annotations

import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    seen: set[str] = set()
    failure: json.JSONDecodeError | None = None

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
            continue

        for start in _object_start_positions(segment):
            try:
                parsed, _end = decoder.raw_decode(segment[start:])
            except json.JSONDecodeError as exc:
                if failure is None:
                    failure = exc
                recovered = _close_truncated_json(segment[start:])
                if recovered is None:
                    continue
                parsed = recovered
            if isinstance(parsed, dict):
                return parsed

    if failure is not None:
        # Describe the outer response, never a nested citation fragment. Keep
        # the excerpt bounded and JSON-escaped so a repair prompt is readable.
        context = json.dumps(
            failure.doc[max(0, failure.pos - 60):failure.pos + 60],
            ensure_ascii=False,
        )
        raise ValueError(
            f"no JSON object found in output: {failure.msg} at line "
            f"{failure.lineno}, column {failure.colno} (offset {failure.pos}); "
            f"context: {context}"
        ) from failure
    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    segments = [text.strip()]
    segments.extend(match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(text))
    return segments


def _object_start_positions(text: str) -> list[int]:
    # Only complete outer objects are candidates. Scanning every opening brace
    # could turn a citation inside a malformed response into the task result.
    starts: list[int] = []
    stack: list[str] = []
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            if not stack and char == "{":
                starts.append(index)
            stack.append("}" if char == "{" else "]")
        elif char in "}]" and stack and stack[-1] == char:
            stack.pop()
    return starts


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
