"""One disposable Docker container per review; no host execution fallback."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from linen.dispatcher.analysis.artifacts import source_bytes, write_json
from linen.dispatcher.config import ReviewSandboxConfig
from linen.dispatcher.runtime.process import LocalProcess, ProcessResult


def isolated_review_argv(argv: list[str]) -> list[str]:
    """Prepare a CLI for DockerReviewProcess, never for host execution.

    Docker supplies the isolation boundary: non-root, read-only root/source,
    dropped capabilities and no host mounts beyond the declared inputs.
    Codex's nested bubblewrap sandbox cannot create namespaces under that
    policy. Use the outer sandbox without relaxing any Docker restrictions.
    """
    if argv and argv[0] == "codex" and "exec" in argv:
        separator = argv.index("--") if "--" in argv else len(argv)
        options, prompt = argv[:separator], argv[separator:]
        prepared = []
        index = 0
        while index < len(options):
            option = options[index]
            if option in {"--sandbox", "-s"}:
                index += 2
                continue
            if option in {"-c", "--config"} and index + 1 < len(options):
                if options[index + 1].split("=", 1)[0].strip() == "sandbox_mode":
                    index += 2
                    continue
            prepared.append(option)
            index += 1
        if "--skip-git-repo-check" not in prepared:
            prepared.append("--skip-git-repo-check")
        return [*prepared, "-c", 'sandbox_mode="danger-full-access"', *prompt]
    if argv and argv[0] == "claude":
        separator = argv.index("--") if "--" in argv else len(argv)
        return [*argv[:separator], "--add-dir", "/repo", "--add-dir", "/input", *argv[separator:]]
    return list(argv)


class DockerReviewProcess:
    """ExecProcess adapter that also destroys daemon-side processes on exit."""

    def __init__(self, config: ReviewSandboxConfig, source: Path, snapshot: dict,
                 run_dir: Path, argv: list[str], env: dict[str, str], timeout: int,
                 inputs: dict[str, bytes] | None = None, *, writable_workdir: bool = False,
                 persistent_workdir: Path | None = None, network_container: str | None = None):
        self.config = config
        self.source = source
        self.snapshot = snapshot
        self.run_dir = run_dir
        self.argv = argv
        self.worker_env = env
        self.timeout = timeout
        self.inputs = inputs or {}
        self.writable_workdir = writable_workdir
        self.persistent_workdir = persistent_workdir
        self.network_container = network_container
        self.name = "linen-review-" + uuid.uuid4().hex
        self.process: LocalProcess | None = None
        self.executable = shutil.which(config.executable)
        self.created = False
        self.image_id: str | None = None
        self.auth_seed: tempfile.TemporaryDirectory | None = None

    def start(self) -> None:
        if self.network_container is not None:
            import re
            if self.config.network != "none" or not re.fullmatch(r"linen-review-[a-f0-9]{32}", self.network_container):
                raise ValueError("Oracle observer may only join its dispatcher-owned offline target namespace")
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
                "routes.json", "guards.json", "semantic_recipe.json",
                "semantic_recipe_runner.py",
                "poc.py", "case.json",
                "oracle_observer.py", "oracle_target.py", "oracle_case.json",
                "response-schema.json",
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
            value = self.config.env.get(name, self.worker_env.get(name, os.environ.get(name)))
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
            "--network", f"container:{self.network_container}" if self.network_container else self.config.network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit", str(self.config.pids_limit),
            "--memory", self.config.memory, "--cpus", str(self.config.cpus),
            "--workdir", "/work", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--mount", f"type=bind,source={staged},target=/repo,readonly,bind-recursive=disabled",
            "--mount", f"type=bind,source={input_dir},target=/input,readonly,bind-recursive=disabled",
        ]
        if self.writable_workdir:
            output_dir = self.run_dir / "work"
            output_dir.mkdir(mode=0o700)
            # The analysis container gets one fresh, dispatcher-owned writable
            # directory so large analysis artifacts can exceed tmpfs limits. Source and
            # input remain separate read-only mounts.
            output_dir.chmod(0o777)
            if "," in str(output_dir):
                raise ValueError("Docker bind source paths cannot contain commas")
            command.extend([
                "--mount",
                # Bind mounts are writable by default. Docker's --mount parser
                # accepts `readonly`, but not the `rw` shorthand used by -v.
                f"type=bind,source={output_dir},target=/work,bind-recursive=disabled",
            ])
        else:
            command.extend(["--tmpfs", "/work:rw,nosuid,nodev,size=256m,mode=1777"])
        if self.persistent_workdir is not None:
            persistent = self.persistent_workdir.resolve()
            persistent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Prepared analysis databases survive disposable query containers.
            persistent.chmod(0o777)
            if "," in str(persistent):
                raise ValueError("Docker bind source paths cannot contain commas")
            command.extend([
                "--mount",
                f"type=bind,source={persistent},target=/cache,bind-recursive=disabled",
            ])
        for name, value in container_env.items():
            command.extend(["--env", name if name in self.config.env_allowlist else f"{name}={value}"])
        argv = self.argv
        if argv[0] == "codex" and self.config.codex_auth_file is not None:
            # Only the explicitly selected login cache crosses this boundary.
            # Keep the seed outside persisted run artifacts and remove it on
            # every exit. Token refresh stays in the disposable /work HOME.
            import json
            with Path(self.config.codex_auth_file).open("rb") as auth_file:
                auth = auth_file.read(100_001)
            if len(auth) > 100_000 or not isinstance(json.loads(auth), dict):
                raise ValueError("Invalid Codex auth cache")
            self.auth_seed = tempfile.TemporaryDirectory(prefix="linen-codex-auth-")
            seed = Path(self.auth_seed.name) / "auth.json"
            seed.write_bytes(auth)
            seed.chmod(0o444)
            command.extend(["--mount", f"type=bind,source={seed},target=/auth-seed.json,readonly"])
            argv = ["sh", "-c", 'umask 077; mkdir -p "$CODEX_HOME" && cp /auth-seed.json "$CODEX_HOME/auth.json" && exec "$@"',
                    "linen-codex-auth", *argv]
        # Override image entrypoints; no image startup script is needed to
        # mount credentials or discover host state.
        command.extend(["--entrypoint", argv[0], self.image_id, *argv[1:]])
        metadata = {"backend": "docker", "container": self.name, "image_id": self.image_id,
                    "snapshot": self.snapshot["id"], "network": f"container:{self.network_container}" if self.network_container else self.config.network,
                    "user": self.config.user, "environment_names": sorted(container_env),
                    "source_mount": "/repo", "source_read_only": True,
                    "codex_auth_seeded": self.auth_seed is not None}
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
        try:
            result = subprocess.run([self.executable, "rm", "--force", "--volumes", self.name],
                                    capture_output=True, text=True, timeout=15)
        finally:
            if self.auth_seed is not None:
                self.auth_seed.cleanup()
                self.auth_seed = None
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
                 inputs: dict[str, bytes] | None = None, *, writable_workdir: bool = False,
                 persistent_workdir: Path | None = None):
        self.config, self.source, self.snapshot, self.root = config, source, snapshot, root
        self.inputs = inputs or {}
        self.writable_workdir = writable_workdir
        self.persistent_workdir = persistent_workdir
        self.last_process: DockerReviewProcess | None = None

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        """Archive dispatcher-owned results on the host, outside the container.

        Only flat execution archive files in this project's managed directory
        are accepted. This does not expose host writes to the review process.
        """
        project = self.root.parent.resolve()
        if Path(container_name).resolve() != project:
            raise ValueError("Review archive belongs to a different project")
        archive = project / ".linen-executions"
        target = Path(path)
        if not target.is_absolute() or target.parent != archive:
            raise ValueError("Review archive path must stay inside .linen-executions")
        if target.suffix not in {".json", ".prompt", ".stdout", ".stderr"}:
            raise ValueError("Unsupported review archive file")
        if archive.is_symlink():
            raise ValueError("Review archive directory must not be a symlink")
        archive.mkdir(mode=0o700, exist_ok=True)
        directory = os.open(archive, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(
                target.name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600, dir_fd=directory,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
        finally:
            os.close(directory)

    def build_exec_process(self, container_name: str, env: dict[str, str], command: list[str],
                           timeout_seconds: int | None = None, kill_after_seconds: int = 5):
        self.last_process = DockerReviewProcess(
            self.config, self.source, self.snapshot, self.root / uuid.uuid4().hex,
            command, env, timeout_seconds or 300, self.inputs,
            writable_workdir=self.writable_workdir,
            persistent_workdir=self.persistent_workdir,
        )
        return self.last_process
