"""One disposable Docker container per review; no host execution fallback."""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

from linen.dispatcher.analysis.artifacts import source_bytes
from linen.dispatcher.analysis.semgrep import write_json
from linen.dispatcher.config import ReviewSandboxConfig
from linen.dispatcher.runtime.process import LocalProcess, ProcessResult


class DockerReviewProcess:
    """ExecProcess adapter that also destroys daemon-side processes on exit."""

    def __init__(self, config: ReviewSandboxConfig, source: Path, snapshot: dict,
                 run_dir: Path, argv: list[str], env: dict[str, str], timeout: int,
                 inputs: dict[str, bytes] | None = None):
        self.config = config
        self.source = source
        self.snapshot = snapshot
        self.run_dir = run_dir
        self.argv = argv
        self.worker_env = env
        self.timeout = timeout
        self.inputs = inputs or {}
        self.name = "linen-review-" + uuid.uuid4().hex
        self.process: LocalProcess | None = None
        self.executable = shutil.which(config.executable)
        self.created = False
        self.image_id: str | None = None

    def start(self) -> None:
        if self.executable is None:
            raise RuntimeError("Review sandbox requires Docker; refusing host fallback")
        if not self.argv or not self.argv[0] or self.argv[0].startswith("-"):
            raise ValueError("Review command must have an executable")
        self.run_dir.mkdir(parents=True, exist_ok=False)
        staged = self.run_dir / "source"
        staged.mkdir()
        # Only manifest-listed regular-file bytes cross the isolation boundary.
        for name, expected in self.snapshot["files"].items():
            content = source_bytes(self.source, name, expected)
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o444)
        for directory, dirs, _ in os.walk(staged):
            Path(directory).chmod(0o755)
        input_dir = self.run_dir / "input"
        input_dir.mkdir(mode=0o755)
        for name, data in self.inputs.items():
            if name not in {
                "record.json", "scope.json", "raw.sarif", "report.json", "candidates.json",
                "routes.json", "guards.json",
            }:
                raise ValueError("Unknown isolated review input")
            (input_dir / name).write_bytes(data)
            (input_dir / name).chmod(0o444)
        if "," in str(staged):
            raise ValueError("Docker bind source paths cannot contain commas")
        inspected = subprocess.run(
            [self.executable, "image", "inspect", "--format", "{{.Id}}", self.config.image],
            capture_output=True, text=True, timeout=15,
        )
        if inspected.returncode or not inspected.stdout.strip():
            raise RuntimeError("Review image is not available locally; refusing pull/host fallback")
        self.image_id = inspected.stdout.strip()
        container_env = {
            "HOME": "/work/home", "TMPDIR": "/tmp", "CODEX_HOME": "/work/home/.codex",
            "XDG_CONFIG_HOME": "/work/home/.config", "XDG_CACHE_HOME": "/work/home/.cache",
        }
        for name in self.config.env_allowlist:
            value = self.worker_env.get(name, os.environ.get(name))
            if value is not None:
                container_env[name] = value
        # --env NAME reads values from the Docker client's environment; secrets
        # never appear in argv or the persisted execution metadata.
        create_env = dict(os.environ)
        for name in self.config.env_allowlist:
            if name in container_env:
                create_env[name] = container_env[name]
        command = [
            self.executable, "create", "--name", self.name, "--pull=never",
            "--read-only", "--init", "--user", self.config.user,
            "--network", self.config.network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit", str(self.config.pids_limit),
            "--memory", self.config.memory, "--cpus", str(self.config.cpus),
            "--workdir", "/work", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--tmpfs", "/work:rw,nosuid,nodev,size=256m,mode=1777",
            "--mount", f"type=bind,source={staged},target=/repo,readonly,bind-recursive=disabled",
            "--mount", f"type=bind,source={input_dir},target=/input,readonly,bind-recursive=disabled",
        ]
        for name, value in container_env.items():
            command.extend(["--env", name if name in self.config.env_allowlist else f"{name}={value}"])
        # Override image entrypoints; no image startup script is needed to
        # mount credentials or discover host state.
        command.extend(["--entrypoint", self.argv[0], self.image_id, *self.argv[1:]])
        metadata = {"backend": "docker", "container": self.name, "image_id": self.image_id,
                    "snapshot": self.snapshot["id"], "network": self.config.network,
                    "user": self.config.user, "environment_names": sorted(container_env),
                    "source_mount": "/repo", "source_read_only": True}
        write_json(self.run_dir / "execution.json", metadata)
        try:
            created = subprocess.run(command, env=create_env, capture_output=True, text=True, timeout=30)
            if created.returncode:
                raise RuntimeError("Cannot create review sandbox: " + created.stderr[:1000])
            self.created = True
            self.process = LocalProcess(
                [self.executable, "start", "--attach", self.name], cwd=str(self.run_dir),
                env=dict(os.environ), timeout_seconds=self.timeout, term_grace_seconds=1,
            )
            self.process.start()
        except Exception:
            self._remove()
            raise

    def communicate(self, timeout: float | None) -> ProcessResult:
        if self.process is None:
            raise RuntimeError("Sandbox was not started")
        try:
            result = self.process.communicate(timeout)
            (self.run_dir / "stdout.log").write_text(result.stdout)
            (self.run_dir / "stderr.log").write_text(result.stderr)
            return result
        finally:
            self._remove()

    def _remove(self) -> None:
        if self.executable is None:
            return
        result = subprocess.run([self.executable, "rm", "--force", "--volumes", self.name],
                                capture_output=True, text=True, timeout=15)
        if result.returncode and "No such container" not in result.stderr:
            raise RuntimeError(f"Review container cleanup failed for {self.name}: {result.stderr[:500]}")
        self.created = False

    def cancel(self, reason: str) -> None:
        # Mark the local result cancelled before removing the daemon process.
        if self.process is not None:
            self.process.cancel(reason)
        self._remove()

    def kill(self) -> None:
        if self.process is not None:
            self.process.kill()
        self._remove()


class ReviewSandboxBackend:
    """Minimal process factory used by run_worker_process and its lease hooks."""

    def __init__(self, config: ReviewSandboxConfig, source: Path, snapshot: dict, root: Path,
                 inputs: dict[str, bytes] | None = None):
        self.config, self.source, self.snapshot, self.root = config, source, snapshot, root
        self.inputs = inputs or {}
        self.last_process: DockerReviewProcess | None = None

    def build_exec_process(self, container_name: str, env: dict[str, str], command: list[str],
                           timeout_seconds: int | None = None, kill_after_seconds: int = 5):
        self.last_process = DockerReviewProcess(
            self.config, self.source, self.snapshot, self.root / uuid.uuid4().hex,
            command, env, timeout_seconds or 300, self.inputs,
        )
        return self.last_process
