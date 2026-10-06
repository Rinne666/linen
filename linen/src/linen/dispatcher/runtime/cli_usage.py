"""Extract provider-reported token usage from structured CLI output.

The parser deliberately recognizes only documented/known structured envelopes.
Plain text, malformed output, and unfamiliar schemas return ``None`` so an
unknown usage figure is never mistaken for zero.
"""

from __future__ import annotations

import json
from typing import Any


def extract_cli_usage(worker_type: str, stdout: str) -> dict[str, int] | None:
    """Return normalized usage from the last structured usage record, if any."""
    if worker_type not in {"claudecode", "codex", "pi"} or not stdout:
        return None
    objects: list[dict[str, Any]] = []
    try:
        whole = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        whole = None
    if isinstance(whole, dict):
        objects.append(whole)
    else:
        for line in stdout.splitlines():
            try:
                value = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                objects.append(value)
    if not objects:
        return None

    candidates: list[dict[str, Any]] = []
    pi_message_ids: set[str] = set()
    pi_missing_usage = False
    for value in objects:
        if worker_type == "claudecode":
            if value.get("type") in {"result", "message"} and isinstance(value.get("usage"), dict):
                candidates.append(value["usage"])
        elif worker_type == "codex":
            kind = value.get("type")
            info = value.get("info") if isinstance(value.get("info"), dict) else {}
            if kind == "token_count" and isinstance(info.get("total_token_usage"), dict):
                candidates.append(info["total_token_usage"])
            elif kind == "turn.completed" and isinstance(value.get("usage"), dict):
                candidates.append(value["usage"])
        else:  # Pi JSON mode message_end records
            if value.get("type") == "message_end":
                message = value.get("message") if isinstance(value.get("message"), dict) else {}
                if message.get("role") != "assistant":
                    continue
                message_id = message.get("id") or value.get("message_id")
                if isinstance(message_id, str) and message_id in pi_message_ids:
                    continue
                if isinstance(message_id, str):
                    pi_message_ids.add(message_id)
                usage = message.get("usage", value.get("usage"))
                if isinstance(usage, dict):
                    candidates.append(usage)
                else:
                    pi_missing_usage = True
    if not candidates:
        return None
    if worker_type == "pi":
        if pi_missing_usage:
            return None
        normalized = [_normalize_usage(worker_type, usage) for usage in candidates]
        if any(item is None for item in normalized):
            return None
        return _sum_usage(normalized)
    return _normalize_usage(worker_type, candidates[-1])


def _normalize_usage(worker_type: str, usage: dict[str, Any]) -> dict[str, int | None] | None:
    if worker_type == "claudecode":
        input_tokens = _nonnegative_int(usage.get("input_tokens"))
        output_tokens = _nonnegative_int(usage.get("output_tokens"))
        cached = _nonnegative_int(usage.get("cache_read_input_tokens"))
        cache_write = _nonnegative_int(usage.get("cache_creation_input_tokens"))
    elif worker_type == "codex":
        input_tokens = _nonnegative_int(usage.get("input_tokens"))
        output_tokens = _nonnegative_int(usage.get("output_tokens"))
        cached = _nonnegative_int(usage.get("cached_input_tokens"))
        cache_write = None
    else:
        input_tokens = _nonnegative_int(usage.get("input"))
        output_tokens = _nonnegative_int(usage.get("output"))
        cached = _nonnegative_int(usage.get("cacheRead"))
        cache_write = _nonnegative_int(usage.get("cacheWrite"))
    reported_total = _nonnegative_int(usage.get("totalTokens")) if worker_type == "pi" else None
    if input_tokens is None or output_tokens is None:
        return None
    result = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": cached,
        "cache_creation_input_tokens": cache_write,
        "total_tokens": reported_total if reported_total is not None else (
            input_tokens + output_tokens + (cached or 0) + (cache_write or 0)
            if cached is not None and cache_write is not None
            else input_tokens + output_tokens
            if worker_type == "codex"
            else None
        ),
    }
    return result


def _sum_usage(items: list[dict[str, int | None] | None]) -> dict[str, int | None] | None:
    values = [item for item in items if item is not None]
    if not values:
        return None
    result: dict[str, int | None] = {}
    for key in ("input_tokens", "output_tokens", "cached_input_tokens", "cache_creation_input_tokens", "total_tokens"):
        observed = [item[key] for item in values if isinstance(item.get(key), int)]
        result[key] = sum(observed) if observed and len(observed) == len(values) else None
    return result


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
