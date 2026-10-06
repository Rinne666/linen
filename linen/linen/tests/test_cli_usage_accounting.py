from __future__ import annotations

import json

from linen.dispatcher.runtime.cli_usage import extract_cli_usage
from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
from linen.dispatcher.workers.adapters.codex import CodexDriver
from linen.dispatcher.workers.adapters.pi import PiDriver
from linen.dispatcher.config import WorkerConfig


def test_claude_structured_result_extracts_usage_and_task_text() -> None:
    stdout = json.dumps({
        "type": "result",
        "result": '{"decision":"continue"}',
        "usage": {
            "input_tokens": 120,
            "output_tokens": 31,
            "cache_read_input_tokens": 80,
            "cache_creation_input_tokens": 10,
        },
    })
    assert extract_cli_usage("claudecode", stdout) == {
        "input_tokens": 120,
        "output_tokens": 31,
        "cached_input_tokens": 80,
        "cache_creation_input_tokens": 10,
        "total_tokens": 241,
    }
    assert ClaudeCodeDriver().extract_response_text(stdout, "") == '{"decision":"continue"}'


def test_codex_jsonl_keeps_event_metadata_out_of_task_payload() -> None:
    stdout = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "t1"}),
        json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": '{"decision":"continue"}'}}),
        json.dumps({"type": "token_count", "info": {"total_token_usage": {
            "input_tokens": 500, "output_tokens": 45, "cached_input_tokens": 200,
        }}}),
        json.dumps({"type": "turn.completed"}),
    ])
    assert extract_cli_usage("codex", stdout) == {
        "input_tokens": 500,
        "output_tokens": 45,
        "cached_input_tokens": 200,
        "cache_creation_input_tokens": None,
        "total_tokens": 545,
    }
    assert CodexDriver().extract_response_text(stdout, "") == '{"decision":"continue"}'


def test_codex_jsonl_extracts_valid_session_and_preserves_malformed_task_body() -> None:
    session_id = "9bb18069-1eb0-48fe-9d35-791f2ddc311e"
    stdout = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": session_id}),
        json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": '{"incomplete":'}}),
    ])
    driver = CodexDriver(local=True)
    session = driver.extract_session(None, stdout, "")
    assert session == session_id
    assert driver.extract_response_text(stdout, "") == '{"incomplete":'
    resume_argv = driver.build_conclude(
        WorkerConfig(name="codex", type="codex", task_types=["reason"], max_running=1),
        "continue", session,
    )
    assert resume_argv[:4] == ["codex", "exec", "resume", session_id]


def test_pi_json_mode_usage_and_unknown_plain_text() -> None:
    stdout = json.dumps({"type": "message_end", "message": {
        "role": "assistant", "content": [{"type": "text", "text": '{"ok":true}'}],
        "usage": {"input": 81, "output": 12, "cacheRead": 20, "cacheWrite": 3},
    }})
    assert extract_cli_usage("pi", stdout) == {
        "input_tokens": 81,
        "output_tokens": 12,
        "cached_input_tokens": 20,
        "cache_creation_input_tokens": 3,
        "total_tokens": 116,
    }
    assert extract_cli_usage("codex", "plain response of 20 words") is None
    assert extract_cli_usage("claudecode", '{"usage":{"input_tokens":0,"output_tokens":0}}') is None
    assert extract_cli_usage("pi", '{not json') is None
    missing_pi_usage = json.dumps({"type": "message_end", "message": {
        "id": "assistant-without-usage", "role": "assistant", "content": [],
    }})
    assert extract_cli_usage("pi", missing_pi_usage) is None


def test_missing_cache_fields_stay_unknown_and_pi_turn_usage_sums_once_per_message() -> None:
    claude = json.dumps({"type": "result", "result": "ok", "usage": {
        "input_tokens": 5, "output_tokens": 7,
    }}, indent=2)
    assert extract_cli_usage("claudecode", claude) == {
        "input_tokens": 5, "output_tokens": 7, "cached_input_tokens": None,
        "cache_creation_input_tokens": None, "total_tokens": None,
    }

    events = [
        {"type": "message_end", "message": {"id": "m1", "role": "assistant",
         "usage": {"input": 10, "output": 3, "cacheRead": 2, "cacheWrite": 1}}},
        # A duplicate event for the same message must not double count.
        {"type": "message_end", "message": {"id": "m1", "role": "assistant",
         "usage": {"input": 10, "output": 3, "cacheRead": 2, "cacheWrite": 1}}},
        {"type": "message_end", "message": {"id": "m2", "role": "assistant",
         "usage": {"input": 20, "output": 4, "cacheRead": 5, "cacheWrite": 0}}},
        {"type": "message_end", "message": {"id": "u1", "role": "user",
         "usage": {"input": 999, "output": 0, "cacheRead": 0, "cacheWrite": 0}}},
    ]
    usage = extract_cli_usage("pi", "\n".join(json.dumps(event) for event in events))
    assert usage == {
        "input_tokens": 30, "output_tokens": 7, "cached_input_tokens": 7,
        "cache_creation_input_tokens": 1, "total_tokens": 45,
    }


def test_structured_output_options_preserve_json_contract() -> None:
    worker = WorkerConfig(name="codex", type="codex", task_types=["reason"], max_running=1)
    argv = CodexDriver(local=True).build_execute(worker, '{"task":"x"}', None).argv
    assert "--json" in argv
    assert argv[argv.index("--") + 1] == '{"task":"x"}'

    claude = WorkerConfig(name="claude", type="claudecode", task_types=["reason"], max_running=1)
    argv = ClaudeCodeDriver().build_execute(claude, '{"task":"x"}', "session").argv
    assert argv[argv.index("--output-format") + 1] == "json"
    assert argv[argv.index("--") + 1] == '{"task":"x"}'

    pi = WorkerConfig(name="pi", type="pi", task_types=["reason"], max_running=1)
    argv = PiDriver(local=True).build_execute(pi, '{"task":"x"}', None).argv
    assert argv[argv.index("--mode") + 1] == "json"
