from __future__ import annotations

import json
from uuid import UUID

from linen.dispatcher.config import WorkerConfig
from linen.dispatcher.workers.base import DriverResult, RegexSessionDriver
from linen.dispatcher.workers.health import HealthResult, http_ping, local_cli_health, proxies_from_env


class CodexDriver(RegexSessionDriver):
    type_name = "codex"
    supports_output_schema = True

    def __init__(self, local: bool = False):
        self.local = local

    def local_binary(self) -> str | None:
        return "codex"

    def with_output_schema(
        self,
        argv: list[str],
        schema_path: str,
        *,
        schema_text: str | None = None,
    ) -> list[str]:
        separator = argv.index("--")
        return [*argv[:separator], "--output-schema", schema_path, *argv[separator:]]

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        """Extract the assistant body from ``codex exec --json`` events."""
        events = []
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)
        for event in reversed(events):
            if event.get("type") != "item.completed":
                continue
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") == "agent_message":
                text = item.get("text")
                return text if isinstance(text, str) else ""
        if any(event.get("type") in {"thread.started", "turn.started", "item.started", "item.completed", "turn.completed"} for event in events):
            return ""
        return stdout

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        if session:
            return session
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(event, dict) or event.get("type") != "thread.started":
                continue
            thread_id = event.get("thread_id")
            if isinstance(thread_id, str):
                try:
                    return str(UUID(thread_id))
                except ValueError:
                    continue
        return super().extract_session(session, stdout, stderr)

    def check_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        if self.local or not {"CODEX_BASE_URL", "OPENAI_API_KEY", "CODEX_MODEL"}.issubset(env):
            return local_cli_health("codex", timeout)
        return http_ping(
            f"{env['CODEX_BASE_URL']}/responses",
            headers={
                "Authorization": f"Bearer {env['OPENAI_API_KEY']}",
                "content-type": "application/json",
            },
            json_body={
                "model": env["CODEX_MODEL"],
                "input": [{"role": "user", "content": "ping"}],
                "stream": False,
            },
            timeout=timeout,
            proxies=proxies_from_env(env),
        )

    def describe_health(self, worker: WorkerConfig) -> str:
        if self.local or "CODEX_BASE_URL" not in worker.env:
            return "codex --help (host CLI configuration)"
        return f"POST {worker.env['CODEX_BASE_URL']}/responses (model={worker.env['CODEX_MODEL']})"

    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        prefix = ["codex"]
        if worker.sandbox_mode:
            # Approval policy is a root option and must precede `exec`.
            prefix.extend(["--ask-for-approval", "never"])
            # Audit calls are read-only and should leave enough CLI capacity
            # for repository-wide reconnaissance; `high` reasoning made
            # scheduler Reason calls routinely consume their full timeout.
            sandbox_args = [
                "--sandbox", worker.sandbox_mode,
                "--skip-git-repo-check",
                "-c", 'model_reasoning_effort="medium"',
            ]
        else:
            sandbox_args = ["--dangerously-bypass-approvals-and-sandbox"]
        if self.local:
            model = worker.env.get("CODEX_MODEL")
            model_args = ["--model", model] if model else []
            return DriverResult(
                argv=[*prefix, "exec", *sandbox_args, *model_args, "--json", "--", prompt]
            )
        env = worker.env
        return DriverResult(
            argv=[
                *prefix,
                "exec",
                *sandbox_args,
                "--model",
                env["CODEX_MODEL"],
                "-c",
                'model_provider="linen"',
                "-c",
                'model_providers.linen.name="linen"',
                "-c",
                'model_providers.linen.wire_api="responses"',
                "-c",
                'model_reasoning_effort="high"',
                "-c",
                f'model_providers.linen.base_url="{env["CODEX_BASE_URL"]}"',
                "-c",
                'model_providers.linen.env_key="OPENAI_API_KEY"',
                "--json",
                "--",
                prompt,
            ]
        )

    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        prefix = ["codex"]
        if worker.sandbox_mode:
            prefix.extend(["--ask-for-approval", "never"])
            # `exec resume` has no --sandbox option; carry the sandbox policy
            # through the same Codex config override used by the resumed CLI.
            sandbox_args = [
                "--skip-git-repo-check",
                "-c", f'sandbox_mode="{worker.sandbox_mode}"',
                "-c", 'model_reasoning_effort="medium"',
            ]
        else:
            sandbox_args = ["--dangerously-bypass-approvals-and-sandbox"]
        if self.local:
            model = worker.env.get("CODEX_MODEL")
            model_args = ["--model", model] if model else []
            return [
                *prefix,
                "exec",
                "resume",
                session,
                *sandbox_args,
                *model_args,
                "--json",
                "--",
                prompt,
            ]
        env = worker.env
        return [
            *prefix,
            "exec",
            "resume",
            session,
            *sandbox_args,
            "--model",
            env["CODEX_MODEL"],
            "-c",
            'model_provider="linen"',
            "-c",
            'model_providers.linen.name="linen"',
            "-c",
            'model_providers.linen.wire_api="responses"',
            "-c",
            'model_reasoning_effort="medium"' if worker.sandbox_mode else 'model_reasoning_effort="high"',
            "-c",
            f'model_providers.linen.base_url="{env["CODEX_BASE_URL"]}"',
            "-c",
            'model_providers.linen.env_key="OPENAI_API_KEY"',
            "--json",
            "--",
            prompt,
        ]
