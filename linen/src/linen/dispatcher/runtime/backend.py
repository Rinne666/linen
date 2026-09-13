"""Local host backend for worker execution.

Each project gets an isolated working directory under
``runtime.local.workspace_root`` (defaulting to the dispatcher's current
working directory) and every worker invocation is a host subprocess spawned
from that directory. The pre-configured ``claude`` / ``codex`` / ``pi`` /
``mock`` CLIs on PATH are reused as-is; no API keys are injected.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from linen.dispatcher.config import LocalConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.process import ExecProcess, LocalProcess

LOG = logging.getLogger(__name__)


@runtime_checkable
class ExecutionBackend(Protocol):
    """Surface every project-scoped execution backend exposes.

    The scheduler, task runners and startup healthcheck only depend on this
    contract, so the local host implementation below can be swapped for
    another backend without touching them. ``container_name`` returns the
    backend's project-scoped identifier — for the local backend this is the
    absolute path of the project's working directory.
    """

    def container_name(self, project_id: str) -> str: ...

    def ensure_running(self, project_id: str) -> str: ...

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> ExecProcess: ...

    def write_text_file(self, container_name: str, path: str, content: str) -> None: ...

    def needs_completed_cleanup(self, project_id: str) -> bool: ...

    def needs_stopped_cleanup(self, project_id: str) -> bool: ...

    def cleanup_completed(self, project_id: str) -> bool: ...

    def cleanup_stopped(self, project_id: str) -> bool: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class ProjectWorkdir:
    project_id: str
    path: Path

    @property
    def agents_md(self) -> Path:
        return self.path / "AGENTS.md"

    @property
    def claude_md(self) -> Path:
        return self.path / "CLAUDE.md"


class LocalBackend:
    """Run workers directly on the dispatcher host inside per-project workdirs.

    Worker processes inherit the host environment so the pre-configured
    CLIs and their credentials are used as-is. There are no containers to
    build or tear down, so the container-lifecycle methods are inert.
    """

    def __init__(self, config: LocalConfig, client: LinenClient | None = None):
        self._config = config
        # Optional server client. When provided, the per-project symlink target
        # is read from `Project.repo_root` first (so a project can clone/pick
        # its own source at creation time). Falls back to the config-level
        # `repo_root` when the project has no override. Fetched at most once
        # per workdir; cached on the ProjectWorkdir for the lifetime of this
        # backend instance.
        self._client = client
        self._repo_root_cache: dict[str, str | None] = {}
        root = config.workspace_root
        self._root = Path(root).expanduser() if root else Path.cwd()

    def close(self) -> None:
        return None

    def _project_dir(self, project_id: str) -> Path:
        return self._root / project_id

    def _project(self, project_id: str) -> ProjectWorkdir:
        return ProjectWorkdir(project_id=project_id, path=self._project_dir(project_id))

    def container_name(self, project_id: str) -> str:
        return str(self._project_dir(project_id))

    def ensure_running(self, project_id: str) -> str:
        workdir = self._project(project_id)
        workdir.path.mkdir(parents=True, exist_ok=True)
        self._ensure_agent_brief(workdir)
        self._ensure_target_link(workdir)
        LOG.debug("local project workdir ready project=%s dir=%s", project_id, workdir.path)
        return str(workdir.path)

    def _resolve_target(self, workdir: ProjectWorkdir) -> str | None:
        """Pick the symlink target for `<workdir>/repo`.

        Order:
        1. Project-level override (`Project.repo_root`), fetched once via the
           server client. Used when the project was created with `clone_url`
           (auto-cloned) or `repo_root` (validated local dir).
        2. Dispatcher-level config (`local.repo_root`). Used when a single
           repo is being audited by every project.
        3. None — no symlink is created.
        """
        pid = workdir.project_id
        if pid in self._repo_root_cache:
            cached = self._repo_root_cache[pid]
            if cached is not None:
                return cached
        elif self._client is not None:
            try:
                detail = self._client.get_project(pid)
                self._repo_root_cache[pid] = detail.project.repo_root
                if detail.project.repo_root is not None:
                    return detail.project.repo_root
            except Exception as exc:  # network/404/etc — fall through to config
                LOG.debug(
                    "could not fetch project repo_root project=%s error=%s; using config",
                    pid, exc,
                )
                self._repo_root_cache[pid] = None
        return self._config.repo_root

    def _ensure_target_link(self, workdir: ProjectWorkdir) -> None:
        """Symlink `<workdir>/repo` to the resolved target if any.

        Used by source-code audit projects so the worker (CWD = workdir)
        can `cd repo` to reach the target source tree. Pure additive
        behavior — if no target is resolved (no per-project override and
        no config-level repo_root) or the link is already in place, this
        is a no-op.
        """
        target = self._resolve_target(workdir)
        if not target:
            return
        link = workdir.path / "repo"
        if link.is_symlink() or link.exists():
            return
        target_path = Path(target)
        if not target_path.exists():
            LOG.warning(
                "target repo path does not exist project=%s target=%s — skipping symlink",
                workdir.project_id, target,
            )
            return
        try:
            link.symlink_to(target_path)
            LOG.info("linked target repo project=%s link=%s -> %s", workdir.project_id, link, target_path)
        except OSError as exc:
            LOG.warning("failed to link target repo project=%s link=%s -> %s error=%s",
                        workdir.project_id, link, target_path, exc)

    def _ensure_agent_brief(self, workdir: ProjectWorkdir) -> None:
        """Write a per-project AGENTS.md / CLAUDE.md if one isn't already there.

        The brief is auto-generated the first time a project is opened, so
        workers see consistent context across runs. Users can replace it; we
        never overwrite an existing file.
        """
        existing = self._config.agents_md
        if not existing or not existing.is_file():
            return
        content = existing.read_text(encoding="utf-8")
        for target in (workdir.agents_md, workdir.claude_md):
            if not target.exists():
                target.write_text(content, encoding="utf-8")

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> LocalProcess:
        merged_env = {**os.environ, **(env or {})}
        return LocalProcess(
            command,
            cwd=container_name,
            env=merged_env,
            timeout_seconds=timeout_seconds,
            term_grace_seconds=kill_after_seconds,
        )

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        target = Path(path)
        if not target.is_absolute():
            raise ValueError(f"local file path must be absolute: {path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def needs_completed_cleanup(self, project_id: str) -> bool:
        return self._config.completed_action == "remove" and self._project_dir(project_id).exists()

    def needs_stopped_cleanup(self, project_id: str) -> bool:
        return False

    def cleanup_completed(self, project_id: str) -> bool:
        if self._config.completed_action == "remove":
            project_dir = self._project_dir(project_id)
            LOG.info("removing completed project workdir project=%s dir=%s", project_id, project_dir)
            shutil.rmtree(project_dir, ignore_errors=True)
        return True

    def cleanup_stopped(self, project_id: str) -> bool:
        return True


ExecutionMode = Literal["local"]
