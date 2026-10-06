from __future__ import annotations

import json
import os
import re
from pathlib import Path

from linen.dispatcher.config import WorkerConfig
from linen.dispatcher.workers.base import DriverResult, SeedSessionDriver
from linen.dispatcher.workers.health import HealthResult, http_ping, local_cli_health, proxies_from_env


ANTHROPIC_VERSION = "2023-06-01"
CONTEXT_REFERENCE_ROOT = "/tmp/linen-prompts"
CONTEXT_REFERENCE_RE = re.compile(
    r"(/tmp/linen-prompts/[a-z][a-z0-9_-]*-ctx-[0-9a-f]{64})/context\.json"
)
SAFE_SETTINGS_ENV = frozenset({
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME", "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME", "API_TIMEOUT_MS",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT",
})


class ClaudeCodeDriver(SeedSessionDriver):
    type_name = "claudecode"
    supports_output_schema = True

    def local_binary(self) -> str | None:
        return "claude"

    def execution_env(self, worker: WorkerConfig, argv: list[str]) -> dict[str, str]:
        if "--safe-mode" not in argv:
            return dict(worker.env)
        # Safe mode ignores settings.env, including the host's provider login.
        # Restore only provider settings from the trusted user config, never
        # project settings, hooks, permissions, or arbitrary environment keys.
        config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
        try:
            settings = json.loads((config_dir / "settings.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            settings = {}
        configured = settings.get("env", {}) if isinstance(settings, dict) else {}
        overrides = {
            key: value for key, value in configured.items()
            if key in SAFE_SETTINGS_ENV and isinstance(value, str) and key not in os.environ
        } if isinstance(configured, dict) else {}
        return {**overrides, **worker.env}

    def check_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        if not {"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL"}.issubset(env):
            return local_cli_health("claude", timeout)
        return http_ping(
            f"{env['ANTHROPIC_BASE_URL']}/v1/messages",
            headers={
                "Authorization": f"Bearer {env['ANTHROPIC_AUTH_TOKEN']}",
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json_body={
                "model": env["ANTHROPIC_MODEL"],
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "ping"}],
            },
            timeout=timeout,
            proxies=proxies_from_env(env),
        )

    def describe_health(self, worker: WorkerConfig) -> str:
        if "ANTHROPIC_BASE_URL" not in worker.env:
            return "claude --help (host CLI configuration)"
        return f"POST {worker.env['ANTHROPIC_BASE_URL']}/v1/messages (model={worker.env['ANTHROPIC_MODEL']})"

    def with_output_schema(
        self,
        argv: list[str],
        schema_path: str,
        *,
        schema_text: str | None = None,
    ) -> list[str]:
        """Constrain the final response to the task's JSON schema.

        ``claude --json-schema`` takes the schema inline and rejects both a bare
        path and an ``@file`` reference, so the serialized schema is inserted
        directly. Without this the CLI has no structural constraint and an
        intermittently malformed large JSON object costs a full repeated run.
        """
        if not schema_text or "--" not in argv:
            return argv
        separator = argv.index("--")
        return [*argv[:separator], "--json-schema", schema_text, *argv[separator:]]

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        """Unwrap Claude's single-result JSON envelope for task validators."""
        try:
            value = json.loads(stdout)
        except (TypeError, json.JSONDecodeError):
            return stdout
        if not isinstance(value, dict) or value.get("type") != "result":
            return stdout
        structured = value.get("structured_output")
        if isinstance(structured, dict):
            return json.dumps(structured, ensure_ascii=False)
        result = value.get("result")
        return result if isinstance(result, str) else ""

    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        assert session is not None
        return DriverResult(
            argv=[
                "claude",
                "--session-id",
                session,
                *self._permission_args(worker, prompt),
                "-p",
                "--output-format",
                "json",
                "--",
                prompt,
            ],
            session=session,
        )

    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        return [
            "claude",
            "-r",
            session,
            *self._permission_args(worker, prompt),
            "-p",
            "--output-format",
            "json",
            "--",
            prompt,
        ]

    @staticmethod
    def _permission_args(worker: WorkerConfig, prompt: str) -> list[str]:
        if prompt.lstrip().startswith("# ISOLATED POC EXECUTION TASK"):
            # The disposable PoC container is the security boundary; the worker
            # needs write and execution tools to run the reproduction program.
            return ["--dangerously-skip-permissions"]
        read_only = worker.sandbox_mode == "read-only" or prompt.lstrip().startswith((
            "# READ-ONLY RECON TASK",
            "# READ-ONLY RECON COVERAGE REVIEW",
        ))
        if not read_only:
            return ["--dangerously-skip-permissions"]
        # Read-only enforcement comes from safe mode plus the tool allowlist:
        # with only Read/Grep/Glob available the worker cannot modify anything.
        # Do not add ``--permission-mode plan``: plan mode instructs the CLI to
        # write a plan file and call ExitPlanMode, which the allowlist does not
        # provide, so strict-output tasks (recon, coverage review, adjudication)
        # dead-end in prose instead of returning their JSON contract.
        return [
            "--safe-mode",
            "--restricted",
            "--tools",
            "Read,Grep,Glob",
            "--permission-prompts",
            "none",
            *ClaudeCodeDriver._context_directory_args(prompt),
        ]

    @staticmethod
    def _context_directory_args(prompt: str) -> list[str]:
        """Allow only the unique dispatcher-generated projection directory.

        Claude Code's restricted file tools are confined to its working
        directories. Context projections live under ``/tmp`` so they are
        otherwise inaccessible to read-only workers. Restrict the additional
        directory to a single generated ``*-ctx-<sha256>`` folder and fail
        closed if the prompt contains more than one such path.
        """
        directories = {
            match.group(1)
            for match in CONTEXT_REFERENCE_RE.finditer(prompt)
            if Path(match.group(1)).parent == Path(CONTEXT_REFERENCE_ROOT)
        }
        if len(directories) != 1:
            return []
        return ["--add-dir", next(iter(directories))]
