"""Small, fail-closed Docker execution backend.

This module intentionally implements only the isolation profile that can be
proved by the Docker CLI arguments below: both the control and tool channels
are disabled.  A model provider therefore cannot be made to work by silently
turning the container into a host process or by forwarding host credentials.
The dispatcher can add a real proxy/split backend later without changing the
``ExecutionBackend`` surface.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
import re
import subprocess
import uuid
from collections.abc import Callable, Mapping

from linen.contracts import SandboxProfile
from linen.dispatcher.runtime.backend import ExecutionBackend
from linen.dispatcher.runtime.policy import BackendCapabilities
from linen.dispatcher.runtime.process import LocalProcess, ProcessResult


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_DEFAULT_MEMORY_MB = 2048
_DEFAULT_CPUS = 2.0
_DEFAULT_PIDS = 256
LOG = logging.getLogger(__name__)


class DockerSandboxProcess(LocalProcess):
    """An :class:`ExecProcess` whose worker command is always ``docker exec``.

    It is useful to keep this as a named type rather than returning a bare
    ``LocalProcess``: callers and tests can distinguish the Docker client
    process from a worker accidentally launched on the host.
    """

    def __init__(
        self,
        command: list[str],
        env: dict[str, str],
        *,
        timeout_seconds: int,
        kill_after_seconds: int = 5,
        cleanup: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(
            command,
            cwd="/",
            env=env,
            timeout_seconds=timeout_seconds,
            term_grace_seconds=kill_after_seconds,
        )
        self._cleanup = cleanup
        self._cleanup_done = False

    def _cleanup_container(self) -> None:
        if self._cleanup is not None and not self._cleanup_done:
            self._cleanup_done = True
            try:
                self._cleanup()
            except Exception as exc:
                # Preserve the worker result and the backend's tracking entry;
                # lifecycle cleanup can retry a transient Docker failure.
                LOG.error("Docker sandbox cleanup deferred: %s", exc)

    def start(self) -> None:
        try:
            super().start()
        except BaseException:
            self._cleanup_container()
            raise

    def communicate(self, timeout: float | None) -> ProcessResult:
        try:
            result = super().communicate(timeout)
        except BaseException:
            self._cleanup_container()
            raise
        if result.timed_out or result.cancelled:
            self._cleanup_container()
        return result

    def kill(self) -> None:
        try:
            super().kill()
        finally:
            self._cleanup_container()

    def cancel(self, reason: str) -> None:
        try:
            super().cancel(reason)
        finally:
            self._cleanup_container()


class DockerSandboxBackend:
    """Disposable project containers with no host-process fallback.

    ``repo_path`` and ``workspace_path`` are host paths supplied by the
    trusted dispatcher.  The repo is mounted read-only only when the profile
    requests it; the workspace is mounted read-write only when requested.
    ``deny`` means no corresponding host path is ever included in Docker
    argv.  Credentials are names-only at this boundary: values are placed in
    the Docker client's private environment and passed using ``docker exec
    --env NAME`` so they do not occur in argv or execution metadata.
    """

    def __init__(
        self,
        executable: str,
        image: str,
        profile: SandboxProfile,
        repo_path: str | Path | None = None,
        workspace_path: str | Path | None = None,
        user: str = "1000:1000",
    ) -> None:
        if not isinstance(profile, SandboxProfile):
            raise TypeError("DockerSandboxBackend requires a SandboxProfile")
        if (
            profile.network.control_channel != "deny"
            or profile.network.tool_channel != "deny"
        ):
            raise ValueError(
                "DockerSandboxBackend only supports control_channel=deny and tool_channel=deny; "
                "configured_provider requires a real control/tool split"
            )
        if profile.filesystem.repo not in {"deny", "read-only"}:
            raise ValueError("DockerSandboxBackend supports repo access deny or read-only only")
        if profile.filesystem.workspace not in {"deny", "read-write"}:
            raise ValueError("DockerSandboxBackend supports workspace access deny or read-write only")
        if not Path(executable).is_absolute():
            raise ValueError("Docker executable must be an absolute path")
        if not image or image.startswith("-") or any(
            char.isspace() or ord(char) < 0x20 for char in image
        ):
            raise ValueError("Docker image must be a non-empty image reference")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user):
            raise ValueError("Docker user must be a non-root numeric UID:GID")

        self.executable = executable
        self.image = image
        self.profile = profile
        self.repo_path = Path(repo_path).expanduser() if repo_path is not None else None
        self.workspace_path = (
            Path(workspace_path).expanduser() if workspace_path is not None else None
        )
        self.user = user
        self._containers: dict[str, str] = {}
        self._handles: dict[str, str] = {}
        self._image_id: str | None = None

        for label, path in (("repo", self.repo_path), ("workspace", self.workspace_path)):
            if path is not None and not path.is_absolute():
                raise ValueError(f"Docker {label} path must be absolute")

    def capabilities(self) -> BackendCapabilities:
        """Return only capabilities this implementation actually enforces."""

        return BackendCapabilities(
            backend_name="docker",
            host_process=False,
            filesystem_isolation=True,
            network_isolation=True,
            # Deliberately false.  deny/deny does not need a split; a
            # configured provider must be rejected by the constructor.
            control_tool_split=False,
            credential_filtering=True,
            resource_limits=True,
            repo_access=["deny", "read-only"],
            workspace_access=["deny", "read-write"],
            control_channels=["deny"],
            tool_channels=["deny"],
        )

    def get_capabilities(self) -> BackendCapabilities:
        return self.capabilities()

    @staticmethod
    def _name(project_id: str) -> str:
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id must not be empty")
        digest = hashlib.sha256(project_id.encode("utf-8")).hexdigest()[:24]
        return f"linen-sandbox-{digest}-{uuid.uuid4().hex[:8]}"

    def container_name(self, project_id: str) -> str:
        if project_id in self._handles:
            return self._handles[project_id]
        if self.workspace_path is not None:
            return str(self.workspace_path.resolve(strict=False))
        return self._name(project_id)

    def _client_env(self, credentials: Mapping[str, str] | None = None) -> dict[str, str]:
        # Never inherit os.environ.  In particular, Docker configuration and
        # unrelated host secrets must not cross this boundary.
        result = {"PATH": os.defpath}
        if credentials:
            result.update(credentials)
        return result

    def _run(self, argv: list[str], **kwargs):
        try:
            return subprocess.run(argv, **kwargs)
        except OSError as exc:
            raise RuntimeError("Docker is unavailable; refusing host fallback") from exc

    def _inspect_image(self) -> str:
        inspected = self._run(
            [self.executable, "image", "inspect", "--format", "{{.Id}}", self.image],
            capture_output=True,
            text=True,
            timeout=30,
            env=self._client_env(),
        )
        image_id = inspected.stdout.strip()
        if inspected.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image_id):
            raise RuntimeError(
                "Docker image is not available locally; refusing pull/host fallback"
            )
        self._image_id = image_id
        return image_id

    def _mount_args(self) -> list[str]:
        args: list[str] = []
        if self.profile.filesystem.repo == "read-only":
            if self.repo_path is None or not self.repo_path.is_dir():
                raise RuntimeError("read-only repo access requires an existing repo_path")
            repo_path = self.repo_path.resolve(strict=True)
            if "," in str(repo_path):
                raise ValueError("Docker bind source paths cannot contain commas")
            args += [
                "--mount",
                f"type=bind,source={repo_path},target=/repo,readonly,bind-recursive=disabled",
            ]
            if self.profile.filesystem.workspace == "read-write":
                # Existing audit prompts use ``cd repo`` from the workspace.
                # A second read-only bind shadows any untrusted workspace
                # symlink at that location without granting another mode.
                args += [
                    "--mount",
                    f"type=bind,source={repo_path},target=/work/repo,readonly,bind-recursive=disabled",
                ]
        if self.profile.filesystem.workspace == "read-write":
            if self.workspace_path is None:
                raise RuntimeError("read-write workspace access requires workspace_path")
            if "," in str(self.workspace_path):
                raise ValueError("Docker bind source paths cannot contain commas")
            self.workspace_path.mkdir(parents=True, exist_ok=True)
            workspace_path = self.workspace_path.resolve(strict=True)
            if self.profile.filesystem.repo == "read-only":
                assert self.repo_path is not None
                repo_path = self.repo_path.resolve(strict=True)
                repo_link = workspace_path / "repo"
                if repo_link.exists() or repo_link.is_symlink():
                    try:
                        existing_repo = repo_link.resolve(strict=True)
                    except OSError as exc:
                        raise RuntimeError("workspace repo link is invalid") from exc
                    if existing_repo != repo_path:
                        raise RuntimeError("workspace repo path does not match the sandbox repo")
                else:
                    repo_link.symlink_to(repo_path, target_is_directory=True)
            args += [
                "--mount",
                f"type=bind,source={workspace_path},target=/work,rw,bind-recursive=disabled",
            ]
        return args

    def ensure_running(self, project_id: str) -> str:
        if project_id in self._containers:
            return self._handles[project_id]
        name = self._name(project_id)
        handle = self.container_name(project_id)

        image_id = self._inspect_image()
        create = [
            self.executable,
            "create",
            "--name",
            name,
            "--pull=never",
            "--read-only",
            "--init",
            "--user",
            self.user,
            "--network",
            "none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit",
            str(self.profile.process.pids_limit or _DEFAULT_PIDS),
            "--memory",
            f"{self.profile.process.memory_limit_mb or _DEFAULT_MEMORY_MB}m",
            "--cpus",
            str(self.profile.process.cpu_limit or _DEFAULT_CPUS),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        ]
        if self.profile.filesystem.workspace == "read-write":
            create += ["--workdir", "/work"]
        else:
            create += ["--workdir", "/tmp"]
        create += self._mount_args()
        # Override image entrypoint for a harmless idle process.  The worker
        # itself is always launched later through docker exec.
        create += ["--entrypoint", "sleep", image_id, "infinity"]

        try:
            created = self._run(
                create,
                capture_output=True,
                text=True,
                timeout=30,
                env=self._client_env(),
            )
            if created.returncode != 0:
                raise RuntimeError("Docker container create failed: " + created.stderr[:1000])
            started = self._run(
                [self.executable, "start", name],
                capture_output=True,
                text=True,
                timeout=30,
                env=self._client_env(),
            )
            if started.returncode != 0:
                raise RuntimeError("Docker container start failed: " + started.stderr[:1000])
            self._containers[project_id] = name
            self._handles[project_id] = handle
            return handle
        except Exception:
            # A failed create/start must not leave a daemon-side container.
            self._remove_name(name, suppress_missing=True)
            raise

    def _remove_name(self, name: str, *, suppress_missing: bool = False) -> bool:
        try:
            removed = self._run(
                [self.executable, "rm", "--force", "--volumes", name],
                capture_output=True,
                text=True,
                timeout=30,
                env=self._client_env(),
            )
        except RuntimeError:
            if suppress_missing:
                return False
            raise
        if removed.returncode and "No such container" in (removed.stderr or ""):
            return True
        if removed.returncode:
            raise RuntimeError("Docker container cleanup failed: " + (removed.stderr or "")[:500])
        return True

    def _forget(self, project_id: str) -> bool:
        name = self._containers.get(project_id)
        if name is None:
            return True
        removed = self._remove_name(name)
        if removed:
            self._containers.pop(project_id, None)
            self._handles.pop(project_id, None)
        return removed

    def needs_completed_cleanup(self, project_id: str) -> bool:
        return project_id in self._containers

    def needs_stopped_cleanup(self, project_id: str) -> bool:
        return project_id in self._containers

    def cleanup_completed(self, project_id: str) -> bool:
        return self._forget(project_id)

    def cleanup_stopped(self, project_id: str) -> bool:
        return self._forget(project_id)

    def close(self) -> None:
        for project_id in list(self._containers):
            self._forget(project_id)

    def _approved_env(self, worker_env: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
        approved = set(self.profile.credentials.allowed)
        values: dict[str, str] = {}
        names: list[str] = []
        for name, value in worker_env.items():
            if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
                continue
            # CredentialPolicy is the sole authority.  No host lookup and no
            # implicit pass-through of model credentials occur here.
            if name not in approved:
                continue
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError(f"invalid credential value for {name}")
            values[name] = value
            names.append(name)
        return values, sorted(names)

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> DockerSandboxProcess:
        project_id = next(
            (identifier for identifier, handle in self._handles.items() if handle == container_name),
            None,
        )
        if project_id is None:
            raise RuntimeError("Docker sandbox is not running; refusing host fallback")
        daemon_name = self._containers[project_id]
        if not command or not command[0] or any("\x00" in part for part in command):
            raise ValueError("Docker worker command must be non-empty and NUL-free")
        credentials, names = self._approved_env(env or {})
        command_argv = [
            self.executable,
            "exec",
            "--env",
            (
                "HOME=/work/home"
                if self.profile.filesystem.workspace == "read-write"
                else "HOME=/tmp/home"
            ),
            "--env",
            "TMPDIR=/tmp",
            "--env",
            (
                "CODEX_HOME=/work/home/.codex"
                if self.profile.filesystem.workspace == "read-write"
                else "CODEX_HOME=/tmp/home/.codex"
            ),
            "--workdir",
            "/work" if self.profile.filesystem.workspace == "read-write" else "/tmp",
        ]
        for name in names:
            # Docker reads the value from the explicitly constructed client
            # environment; the secret value is absent from argv.
            command_argv += ["--env", name]
        command_argv += [daemon_name, *command]
        process_env = self._client_env(credentials)
        effective_timeout = self.profile.process.timeout_seconds
        if timeout_seconds is not None:
            effective_timeout = min(effective_timeout, timeout_seconds)
        return DockerSandboxProcess(
            command_argv,
            process_env,
            timeout_seconds=effective_timeout,
            kill_after_seconds=kill_after_seconds,
            cleanup=lambda: self._forget_by_name(daemon_name),
        )

    def _forget_by_name(self, container_name: str) -> None:
        project_id = next(
            (identifier for identifier, name in self._containers.items() if name == container_name),
            None,
        )
        if project_id is not None:
            self._forget(project_id)

    def execution_record_root(self, container_name: str) -> str:
        """Return a host Artifact path that survives container cleanup."""

        if self.profile.filesystem.workspace != "read-write":
            raise RuntimeError("execution records require a read-write workspace")
        assert self.workspace_path is not None
        return str(self.workspace_path / ".linen-executions")

    def artifact_workspace_path(self, container_name: str, path: str) -> str:
        """Translate a container Artifact path into host-workspace metadata."""

        if self.workspace_path is None:
            raise RuntimeError("Docker workspace is unavailable")
        root = self.workspace_path.resolve()
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("Docker artifact path must be absolute")
        try:
            return candidate.resolve(strict=False).relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("Docker artifact path escapes /work") from exc

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        target = Path(path)
        if not target.is_absolute() or "\x00" in path or any(
            ord(char) < 0x20 for char in path
        ):
            raise ValueError("Docker file path must be absolute and control-character free")
        if not isinstance(content, str) or "\x00" in content:
            raise ValueError("Docker file content must be NUL-free text")
        if self.workspace_path is not None:
            workspace = self.workspace_path.resolve()
            resolved = target.resolve(strict=False)
            try:
                resolved.relative_to(workspace)
            except ValueError:
                pass
            else:
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_text(content, encoding="utf-8")
                return
        project_id = next(
            (identifier for identifier, handle in self._handles.items() if handle == container_name),
            None,
        )
        if project_id is None:
            raise RuntimeError("Docker sandbox is not running")
        daemon_name = self._containers[project_id]
        try:
            target.relative_to(Path("/tmp/linen-prompts"))
        except ValueError as exc:
            raise ValueError("Docker worker input path must be under /tmp/linen-prompts") from exc
        # Prompt/artifact paths are written through stdin, never interpolated
        # as shell source.  The path is a positional argument to sh.
        result = self._run(
            [
                self.executable,
                "exec",
                "-i",
                daemon_name,
                "/bin/sh",
                "-c",
                "mkdir -p -- \"$(dirname -- \"$1\")\" && cat > \"$1\"",
                "linen",
                str(target),
            ],
            input=content,
            capture_output=True,
            text=True,
            timeout=30,
            env=self._client_env(),
        )
        if result.returncode:
            raise RuntimeError("Docker file write failed: " + (result.stderr or "")[:500])


__all__ = ["DockerSandboxBackend", "DockerSandboxProcess"]
