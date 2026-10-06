from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
import yaml

from linen.dispatcher.config import DispatchConfig
from linen.operations import (
    _online_backup,
    _image_status,
    backup_database,
    inspect_environment,
    restore_database,
)


def inactive(monkeypatch):
    monkeypatch.setattr("linen.operations._processes_using", lambda paths: set())


def test_backup_includes_committed_wal_rows_and_is_readable(tmp_path, monkeypatch):
    inactive(monkeypatch)
    source = tmp_path / "board.db"
    conn = sqlite3.connect(source)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE sample (value TEXT)")
    conn.execute("INSERT INTO sample VALUES ('wal value')")
    conn.commit()
    try:
        result = backup_database(source, tmp_path / "backup.db")
        assert result["method"] == "sqlite_online_backup"
        assert result["integrity_check"] == "ok"
        with sqlite3.connect(tmp_path / "backup.db") as restored:
            assert restored.execute("SELECT value FROM sample").fetchone() == ("wal value",)
    finally:
        conn.close()


def test_backup_refuses_existing_destination_without_modifying_it(tmp_path, monkeypatch):
    inactive(monkeypatch)
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
    destination = tmp_path / "existing.db"
    destination.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        backup_database(source, destination)
    assert destination.read_bytes() == b"keep me"


def test_backup_refuses_active_database_and_cleans_partial_files(tmp_path, monkeypatch):
    source = tmp_path / "active.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
    monkeypatch.setattr("linen.operations._processes_using", lambda paths: {"123"})
    destination = tmp_path / "backup.db"
    with pytest.raises(RuntimeError, match="appears active"):
        backup_database(source, destination)
    assert not destination.exists()
    assert list(tmp_path.glob("*.partial")) == []


def test_corrupt_database_does_not_publish_backup(tmp_path, monkeypatch):
    inactive(monkeypatch)
    source = tmp_path / "corrupt.db"
    source.write_bytes(b"not a sqlite database")
    destination = tmp_path / "backup.db"
    with pytest.raises(sqlite3.DatabaseError):
        backup_database(source, destination)
    assert not destination.exists()


def test_restore_refuses_to_replace_existing_database(tmp_path, monkeypatch):
    inactive(monkeypatch)
    backup = tmp_path / "backup.db"
    with sqlite3.connect(backup) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
        conn.execute("INSERT INTO sample VALUES ('safe')")
    destination = tmp_path / "live.db"
    destination.write_bytes(b"original database")
    with pytest.raises(FileExistsError):
        restore_database(backup, destination)
    assert destination.read_bytes() == b"original database"


def test_preflight_does_not_expose_worker_secrets(tmp_path, monkeypatch):
    config = DispatchConfig.model_validate({
        "server": "http://127.0.0.1:9000",
        "runtime": {"interval": 60, "max_workers": 1, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "mock"},
        "tasks": {"reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path / "work")},
        "workers": [{"name": "tester", "type": "mock", "task_types": ["explore"],
                     "max_running": 1, "env": {"API_KEY": "do-not-print-this"}}],
        "audit": {"enabled": False},
    })
    path = tmp_path / "dispatch.yaml"
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")))
    output = str(inspect_environment(path))
    assert "do-not-print-this" not in output
    assert "API_KEY" not in output


def test_preflight_allows_first_workspace_creation_and_unconfigured_source(tmp_path):
    config = DispatchConfig.model_validate({
        "server": "http://127.0.0.1:9000",
        "runtime": {"interval": 60, "max_workers": 1, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "mock"},
        "tasks": {"reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path / "new" / "workspace")},
        "workers": [{"name": "tester", "type": "mock", "task_types": ["explore"],
                     "max_running": 1}],
        "audit": {"enabled": False},
    })
    path = tmp_path / "dispatch.yaml"
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")))
    result = inspect_environment(path)
    assert result["ok"] is True
    assert result["workspace"]["exists"] is False
    assert result["workspace"]["writable"] is True
    assert result["source"]["configured"] is False
    assert result["source"]["ok"] is True


def test_preflight_fails_when_configured_cli_is_missing(tmp_path, monkeypatch):
    config = DispatchConfig.model_validate({
        "server": "http://127.0.0.1:9000",
        "runtime": {"interval": 60, "max_workers": 1, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "mock"},
        "tasks": {"reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path)},
        "workers": [{"name": "tester", "type": "codex", "task_types": ["explore"],
                     "max_running": 1}],
        "audit": {"enabled": False},
    })
    path = tmp_path / "dispatch.yaml"
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")))
    monkeypatch.setattr("linen.operations.shutil.which", lambda _: None)
    result = inspect_environment(path)
    assert result["ok"] is False
    assert result["workers"][0]["reason"]
    assert any("workers:" in reason for reason in result["failures"])


def test_preflight_inspects_enabled_codeql_image(tmp_path, monkeypatch):
    config = DispatchConfig.model_validate({
        "server": "http://127.0.0.1:9000",
        "runtime": {"interval": 60, "max_workers": 1, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5, "prompt_group": "mock"},
        "tasks": {"reason": {"timeout": 5}, "explore": {"timeout": 5, "conclude_timeout": 5}},
        "local": {"workspace_root": str(tmp_path)},
        "workers": [{"name": "tester", "type": "mock", "task_types": ["explore"],
                     "max_running": 1}],
        "audit": {"enabled": False},
    })
    codeql = config.audit.codeql.model_copy(update={"enabled": True, "image": "private/image:tag"})
    audit = config.audit.model_copy(update={"codeql": codeql})
    config = config.model_copy(update={"audit": audit})
    monkeypatch.setattr("linen.operations.DispatchConfig.load", lambda _: config)
    monkeypatch.setattr(
        "linen.operations._image_status",
        lambda executable, image: {"available": True, "image_id": "sha256:local"},
    )
    result = inspect_environment(tmp_path / "unused.yaml")
    assert {item["component"] for item in result["images"]} == {"codeql"}


def test_destination_connect_failure_closes_open_source_connection(tmp_path, monkeypatch):
    inactive(monkeypatch)
    source = tmp_path / "source.db"
    source.write_bytes(b"placeholder")
    state = {"closed": False, "calls": 0}

    class SourceConnection:
        def close(self):
            state["closed"] = True

    def connect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return SourceConnection()
        raise sqlite3.OperationalError("destination unavailable")

    monkeypatch.setattr("linen.operations.sqlite3.connect", connect)
    with pytest.raises(sqlite3.OperationalError):
        backup_database(source, tmp_path / "backup.db")
    assert state["closed"] is True
    assert not (tmp_path / "backup.db").exists()


def test_docker_inspection_preserves_only_allowed_context_env(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr("linen.operations.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("DOCKER_CONTEXT", "desktop-linux")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker-config"))
    monkeypatch.setenv("DOCKER_AUTH_CONFIG", "secret-token")

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="sha256:localimage\n", stderr="")

    monkeypatch.setattr("linen.operations.subprocess.run", fake_run)
    result = _image_status("docker", "local/image:tag")
    assert result["available"] is True
    assert seen["env"] == {
        "HOME": str(tmp_path / "home"), "PATH": "/usr/bin:/bin",
        "DOCKER_CONTEXT": "desktop-linux", "DOCKER_CONFIG": str(tmp_path / "docker-config"),
    }
    assert "secret-token" not in str(result)
    assert "pull" not in seen["argv"]


def test_docker_daemon_unavailable_is_distinguished_without_stderr_leak(monkeypatch):
    monkeypatch.setattr("linen.operations.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr("linen.operations.subprocess.run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="Cannot connect to the Docker daemon. credential=secret",
    ))
    result = _image_status("docker", "local/image:tag")
    assert result == {"available": False, "image_id": None, "reason": "Docker daemon unavailable"}
    assert "secret" not in str(result)


def test_backup_progress_timeout_is_enforced(monkeypatch):
    class Source:
        def backup(self, destination, **kwargs):
            kwargs["progress"](0, 1, 1)

    ticks = iter((1.0, 3.0))
    monkeypatch.setattr("linen.operations.time.monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="time limit"):
        _online_backup(Source(), object(), timeout_seconds=1.0)
