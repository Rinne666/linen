from __future__ import annotations

import abc
import json
import math
import os
import re
import tempfile
import uuid
from dataclasses import dataclass

from linen.dispatcher.config import WorkerConfig
from linen.dispatcher.runtime.process import LocalProcess
from linen.dispatcher.workers.health import HealthResult


@dataclass(slots=True)
class DriverResult:
    argv: list[str]
    session: str | None = None


class WorkerDriver(abc.ABC):
    type_name: str
    # Whether this CLI can constrain its final response to a supplied JSON
    # schema. Drivers that leave this False must not be handed a schema.
    supports_output_schema = False

    def supports_conclude(self) -> bool:
        return True

    def local_binary(self) -> str | None:
        """Executable this driver invokes in local mode, checked on PATH at startup.

        None means the driver has no host binary to verify (or is not used locally).
        """
        return None

    def prepare_session(self) -> str | None:
        return None

    def execution_env(self, worker: WorkerConfig, argv: list[str]) -> dict[str, str]:
        """Environment overrides for a CLI invocation; never persisted in argv."""
        return dict(worker.env)

    def with_output_schema(
        self,
        argv: list[str],
        schema_path: str,
        *,
        schema_text: str | None = None,
    ) -> list[str]:
        """Add native final-response constraints when the CLI supports them.

        ``schema_path`` is a backend-readable path for CLIs that accept a file.
        ``schema_text`` is the serialized schema for CLIs that accept the schema
        inline only (codex uses the path; claude's ``--json-schema`` rejects both
        a bare path and an ``@file`` reference).
        """
        return argv

    def check_response_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        """Opt-in model probe using the same adapter and environment as audit work."""
        if self.local_binary() is None:
            return self.check_health(worker, timeout=timeout)
        probe_worker = worker.model_copy(update={"sandbox_mode": "read-only"})
        prompt = 'Return exactly {"health":"ok"}. Do not use tools or read files.'
        invocation = self.build_execute(probe_worker, prompt, self.prepare_session())
        env = {**os.environ, **self.execution_env(probe_worker, invocation.argv)}
        with tempfile.TemporaryDirectory(prefix="linen-health-") as cwd:
            process = LocalProcess(
                invocation.argv, cwd, env,
                timeout_seconds=max(1, math.ceil(timeout)), term_grace_seconds=1,
            )
            try:
                process.start()
                result = process.communicate(timeout=timeout)
            except (OSError, ValueError) as exc:
                process.kill()
                return HealthResult(False, None, f"CLI probe failed: {type(exc).__name__}")
        if result.timed_out:
            return HealthResult(False, None, "CLI model response timed out")
        if result.returncode != 0:
            # Provider output can contain credentials or repository context.
            # Keep raw output out of the startup report.
            return HealthResult(False, None, f"CLI model probe exited {result.returncode}")
        text = self.extract_response_text(result.stdout, result.stderr)
        try:
            valid = json.loads(text) == {"health": "ok"}
        except (TypeError, ValueError):
            valid = False
        return HealthResult(valid, 200 if valid else None,
                            "" if valid else "CLI model returned an invalid health response")

    @abc.abstractmethod
    def check_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        """Verify this worker's LLM config is usable, in-process (no container, no curl)."""
        raise NotImplementedError

    def describe_health(self, worker: WorkerConfig) -> str:
        return "in-process API ping"

    @abc.abstractmethod
    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        raise NotImplementedError

    @abc.abstractmethod
    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        raise NotImplementedError

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        return session

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        return stdout


class SeedSessionDriver(WorkerDriver):
    def prepare_session(self) -> str | None:
        return str(uuid.uuid4())


class RegexSessionDriver(WorkerDriver):
    session_pattern = re.compile(r"session id:\s*([0-9a-fA-F-]+)")

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        if session:
            return session
        match = self.session_pattern.search(stderr)
        if match:
            return match.group(1)
        return None
