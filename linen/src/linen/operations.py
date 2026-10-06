"""Read-only operations preflight and safe SQLite backup helpers."""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from linen.dispatcher.config import DispatchConfig

_CLI_VERSION_ARGS: dict[str, tuple[str, ...]] = {
    "claudecode": ("--version",),
    "codex": ("--version",),
    "pi": ("--version",),
}
_WORKER_EXECUTABLES = {"claudecode": "claude", "codex": "codex", "pi": "pi"}
_VERSION = re.compile(r"(?<![A-Za-z0-9])v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?")
_BACKUP_TIMEOUT_SECONDS = 120.0


def _processes_using(paths: list[Path]) -> set[str]:
    """Return PIDs holding SQLite files, failing closed when lsof is unavailable."""
    lsof = shutil.which("lsof")
    if lsof is None:
        raise RuntimeError("Cannot prove database is inactive: lsof is unavailable")
    users: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        result = subprocess.run(
            [lsof, "-t", "--", str(path)], capture_output=True, text=True,
            timeout=10, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        if result.returncode not in (0, 1):
            raise RuntimeError("Cannot prove database is inactive")
        users.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    return users


def _assert_inactive(source: Path) -> None:
    users = _processes_using([source, Path(str(source) + "-wal"), Path(str(source) + "-shm")])
    if users:
        raise RuntimeError("Database appears active; stop Linen before making an offline backup")


def _sqlite_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro"


def _docker_environment() -> dict[str, str]:
    """Preserve only settings the trusted Docker client uses to find its daemon."""
    allowed = ("HOME", "PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _online_backup(source: sqlite3.Connection, destination: sqlite3.Connection,
                   timeout_seconds: float = _BACKUP_TIMEOUT_SECONDS) -> None:
    if timeout_seconds <= 0:
        raise ValueError("Backup timeout must be positive")
    deadline = time.monotonic() + timeout_seconds

    def progress(status: int, remaining: int, total: int) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("SQLite backup exceeded its time limit")

    source.backup(destination, pages=128, progress=progress, sleep=0.05)


def backup_database(source: Path | str, destination: Path | str) -> dict[str, Any]:
    """Create an atomic, verified SQLite online backup without replacing files.

    SQLite's backup API includes committed WAL pages. A sibling temporary file
    is verified before an exclusive hard-link publishes it at the destination.
    """
    src = Path(source).expanduser().absolute()
    dest = Path(destination).expanduser().absolute()
    if src == dest:
        raise ValueError("Backup destination must differ from the source database")
    if not src.is_file() or src.is_symlink():
        raise ValueError("Source database must be an existing regular file")
    if dest.exists() or dest.is_symlink():
        raise FileExistsError("Backup destination already exists; refusing to overwrite")
    if not dest.parent.is_dir():
        raise ValueError("Backup destination directory must already exist")
    _assert_inactive(src)

    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".partial", dir=dest.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        source_conn = sqlite3.connect(_sqlite_uri(src), uri=True, timeout=5)
        try:
            destination_conn = sqlite3.connect(tmp, timeout=5)
            try:
                _online_backup(source_conn, destination_conn)
                check = destination_conn.execute("PRAGMA integrity_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError("Backup integrity check failed")
                destination_conn.commit()
            finally:
                destination_conn.close()
        finally:
            source_conn.close()

        # Recheck before publication in case a service opened the source during
        # the copy. Removing the temporary file leaves source and destination
        # untouched when an active process is detected.
        _assert_inactive(src)
        backup_conn = sqlite3.connect(_sqlite_uri(tmp), uri=True, timeout=5)
        try:
            if backup_conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("Backup integrity check failed")
        finally:
            backup_conn.close()
        os.chmod(tmp, 0o600)
        with tmp.open("rb") as stream:
            os.fsync(stream.fileno())
        os.link(tmp, dest)  # exclusive: fails if a destination appeared meanwhile
        os.unlink(tmp)
        dir_fd = os.open(dest.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return {
            "source": str(src), "destination": str(dest), "bytes": dest.stat().st_size,
            "integrity_check": "ok", "method": "sqlite_online_backup", "mode": "0600",
        }
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def restore_database(backup: Path | str, destination: Path | str) -> dict[str, Any]:
    """Restore a verified backup to a new path; never overwrite an existing DB."""
    result = backup_database(backup, destination)
    result["method"] = "sqlite_online_restore"
    return result


def _cli_status(worker_type: str) -> dict[str, Any]:
    executable_name = _WORKER_EXECUTABLES.get(worker_type)
    if executable_name is None:
        return {"type": worker_type, "available": True, "version": "builtin"}
    executable = shutil.which(executable_name)
    if executable is None:
        return {"type": worker_type, "available": False}
    status: dict[str, Any] = {"type": worker_type, "available": True}
    args = _CLI_VERSION_ARGS.get(worker_type)
    if args is None:
        status["version"] = "not checked"
        return status
    try:
        result = subprocess.run(
            [executable, *args], capture_output=True, text=True, timeout=8,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir()},
        )
    except (OSError, subprocess.TimeoutExpired):
        status["version"] = "unavailable"
        return status
    output = (result.stdout + "\n" + result.stderr)[:2048]
    match = _VERSION.search(output)
    status["version"] = match.group(0) if result.returncode == 0 and match else "unavailable"
    return status


def _image_status(executable_name: str, image: str | None) -> dict[str, Any]:
    if not image:
        return {"image": None, "available": None}
    executable = shutil.which(executable_name)
    if not executable:
        return {"available": False, "reason": "container CLI unavailable"}
    try:
        result = subprocess.run(
            [executable, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=8,
            env=_docker_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "Docker image inspect failed"}
    image_id = result.stdout.strip()
    if result.returncode == 0 and image_id:
        return {"available": True, "image_id": image_id[:128]}
    error = result.stderr.casefold()
    if any(marker in error for marker in (
        "cannot connect to the docker daemon", "error during connect",
        "is the docker daemon running", "failed to connect to docker",
    )):
        reason = "Docker daemon unavailable"
    elif "no such image" in error or "not found" in error:
        reason = "configured image not found locally"
    else:
        reason = "Docker image inspect failed"
    return {"available": False, "image_id": None, "reason": reason}


def inspect_environment(
    config_path: Path | str, *, database_path: Path | str | None = None,
) -> dict[str, Any]:
    """Inspect local prerequisites without invoking a model or changing state."""
    try:
        config = DispatchConfig.load(Path(config_path))
    except Exception as exc:
        return {"ok": False, "config": {
            "valid": False, "error": type(exc).__name__,
            "reason": "configuration could not be loaded or validated",
        }, "failures": ["config: configuration could not be loaded or validated"]}
    checks: dict[str, Any] = {"config": {
        "valid": True,
        "audit_enabled": config.audit.enabled,
        "audit_mode": config.audit.mode,
        "prompt_group": config.runtime.prompt_group,
        "worker_count": len(config.workers),
        "worker_healthcheck": config.runtime.worker_healthcheck,
    }}
    workers = []
    seen: set[str] = set()
    for worker in config.workers:
        if worker.type not in seen:
            seen.add(worker.type)
            workers.append(_cli_status(worker.type))
    checks["workers"] = workers

    workspace = Path(config.local.workspace_root).expanduser() if config.local.workspace_root else Path.cwd()
    parent = workspace
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    parent_writable = parent.is_dir() and os.access(parent, os.W_OK | os.X_OK)
    workspace_exists = workspace.is_dir()
    workspace_writable = workspace_exists and os.access(workspace, os.W_OK | os.X_OK)
    checks["workspace"] = {
        "path": str(workspace), "exists": workspace_exists,
        "writable": workspace_writable if workspace_exists else parent_writable,
        "ok": workspace_writable if workspace_exists else parent_writable,
        "reason": None if (workspace_writable if workspace_exists else parent_writable)
        else "workspace or nearest existing parent is not writable",
    }

    configured_source = config.local.repo_root
    source_exists = bool(configured_source and Path(configured_source).expanduser().is_dir())
    checks["source"] = {
        "configured": configured_source is not None,
        "path": configured_source,
        "exists": source_exists if configured_source is not None else None,
        "ok": source_exists if configured_source is not None else True,
        "reason": "configured source directory is missing" if configured_source is not None and not source_exists else None,
    }
    images = []
    for component, sandbox in (
        ("review_sandbox", config.audit.review_sandbox),
        ("poc_sandbox", config.audit.poc_sandbox),
    ):
        if sandbox.enabled and sandbox.image:
            images.append({"component": component, **_image_status(sandbox.executable, sandbox.image)})
    codeql = config.audit.codeql
    if codeql.enabled and codeql.image:
        images.append({"component": "codeql", **_image_status(codeql.executable, codeql.image)})
    checks["images"] = images
    for worker_status in checks["workers"]:
        worker_status["ok"] = bool(worker_status.get("available")) and worker_status.get("version") not in {None, "unavailable"}
        if not worker_status["ok"]:
            worker_status["reason"] = "configured worker CLI is missing or version check failed"
    for image_status in images:
        image_status["ok"] = bool(image_status.get("available"))
        if not image_status["ok"]:
            image_status["reason"] = image_status.get("reason") or "configured image is not available locally"
    if database_path is not None:
        path = Path(database_path).expanduser().absolute()
        db_check: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
        if path.is_file():
            try:
                conn = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=3)
                try:
                    db_check["integrity_check"] = conn.execute("PRAGMA quick_check").fetchone()[0]
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                db_check["integrity_check"] = type(exc).__name__
        db_check["ok"] = db_check.get("integrity_check") == "ok"
        if not db_check["ok"]:
            db_check["reason"] = "database is missing or its read-only integrity check failed"
        checks["database"] = db_check
    checks["ok"] = (
        checks["config"]["valid"] and checks["workspace"]["ok"] and checks["source"]["ok"]
        and all(item["ok"] for item in checks["workers"])
        and all(item["ok"] for item in checks["images"])
        and (checks.get("database", {}).get("ok", True))
    )
    failures = []
    for name in ("workspace", "source", "database"):
        item = checks.get(name)
        if item is not None and not item.get("ok", True):
            failures.append(f"{name}: {item.get('reason', 'check failed')}")
    for name in ("workers", "images"):
        for item in checks[name]:
            if not item["ok"]:
                failures.append(f"{name}: {item.get('reason', 'check failed')}")
    checks["failures"] = failures
    return checks


def operations_json(result: dict[str, Any]) -> str:
    """Stable JSON rendering helper for the CLI integration."""
    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
