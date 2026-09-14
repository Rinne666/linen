from __future__ import annotations

from types import SimpleNamespace

import pytest

from linen.contracts import (
    CredentialPolicy,
    ExecutionRequest,
    FilesystemPolicy,
    NetworkPolicy,
    SandboxProfile,
)
from linen.dispatcher.runtime import docker_backend
from linen.dispatcher.runtime.process import LocalProcess, ProcessResult
from linen.dispatcher.runtime.policy import evaluate_execution


def _result(*, returncode: int = 0, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _profile(*, repo: str = "read-only", workspace: str = "read-write") -> SandboxProfile:
    return SandboxProfile(
        filesystem=FilesystemPolicy(repo=repo, workspace=workspace),
        network=NetworkPolicy(control_channel="deny", tool_channel="deny"),
        credentials=CredentialPolicy(allowed=["SAFE_TOKEN"]),
    )


def test_backend_rejects_unsupported_network_channels(tmp_path) -> None:
    profile = SandboxProfile(
        network=NetworkPolicy(control_channel="configured_provider", tool_channel="deny"),
    )
    with pytest.raises(ValueError, match="only supports"):
        docker_backend.DockerSandboxBackend(
            "/usr/bin/docker", "linen:test", profile, tmp_path, tmp_path / "work",
        )

    with pytest.raises(ValueError, match="repo access"):
        docker_backend.DockerSandboxBackend(
            "/usr/bin/docker", "linen:test", _profile(repo="read-write"),
            tmp_path, tmp_path / "work",
        )
    with pytest.raises(ValueError, match="workspace access"):
        docker_backend.DockerSandboxBackend(
            "/usr/bin/docker", "linen:test", _profile(workspace="read-only"),
            tmp_path, tmp_path / "work",
        )


def test_ensure_running_uses_pinned_image_and_isolation_flags(tmp_path, monkeypatch) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1:3] == ["image", "inspect"]:
            return _result(stdout="sha256:" + "a" * 64 + "\n")
        return _result()

    monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
    repo = tmp_path / "repo"
    repo.mkdir()
    backend = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", _profile(), repo, tmp_path / "work",
    )

    handle = backend.ensure_running("project-1")
    inspect, inspect_kwargs = calls[0]
    create, create_kwargs = calls[1]
    daemon_name = create[create.index("--name") + 1]
    assert handle == str((tmp_path / "work").resolve())
    assert daemon_name.startswith("linen-sandbox-")
    assert inspect == ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", "linen:test"]
    assert create[0:4] == ["/usr/bin/docker", "create", "--name", daemon_name]
    assert "--pull=never" in create
    assert "--read-only" in create
    assert "--network" in create and create[create.index("--network") + 1] == "none"
    assert "--user" in create and create[create.index("--user") + 1] == "1000:1000"
    assert "--cap-drop=ALL" in create
    assert "--security-opt=no-new-privileges" in create
    assert "--tmpfs" in create
    assert "--pids-limit" in create
    assert "--memory" in create
    assert "--cpus" in create
    assert f"source={repo}" in " ".join(create)
    assert "readonly" in " ".join(create)
    assert inspect_kwargs["env"] == {"PATH": docker_backend.os.defpath}
    assert create_kwargs["env"] == {"PATH": docker_backend.os.defpath}


def test_build_exec_process_filters_environment_and_bounds_timeout(tmp_path, monkeypatch) -> None:
    def fake_run(argv, **kwargs):
        if argv[1:3] == ["image", "inspect"]:
            return _result(stdout="sha256:" + "b" * 64)
        return _result()

    monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
    backend = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", _profile(), tmp_path / "repo", tmp_path / "work",
    )
    (tmp_path / "repo").mkdir()
    handle = backend.ensure_running("project-1")
    process = backend.build_exec_process(
        handle,
        {"SAFE_TOKEN": "secret-value", "HOST_SECRET": "must-not-cross"},
        ["/bin/sh", "-c", "true"],
        timeout_seconds=30,
    )

    assert process.command[:2] == ["/usr/bin/docker", "exec"]
    assert "SAFE_TOKEN" in process.command
    assert "secret-value" not in process.command
    assert "HOST_SECRET" not in process.command
    assert process.env == {"PATH": docker_backend.os.defpath, "SAFE_TOKEN": "secret-value"}
    assert process._timeout_seconds == 30
    record_root = backend.execution_record_root(handle)
    assert record_root == str(tmp_path / "work" / ".linen-executions")
    record_path = str(tmp_path / "work" / ".linen-executions" / "run.json")
    backend.write_text_file(handle, record_path, "{}\n")
    assert (tmp_path / "work" / ".linen-executions" / "run.json").read_text() == "{}\n"
    assert backend.artifact_workspace_path(handle, record_path) == ".linen-executions/run.json"


def test_denied_filesystem_paths_are_not_mounted(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1:3] == ["image", "inspect"]:
            return _result(stdout="sha256:" + "c" * 64)
        return _result()

    monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
    backend = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", _profile(repo="deny", workspace="deny"),
        tmp_path / "repo", tmp_path / "work",
    )
    backend.ensure_running("project-1")
    create = next(argv for argv in calls if len(argv) > 1 and argv[1] == "create")
    assert "--mount" not in create
    assert "/repo" not in create
    assert "/work" not in create


def test_capabilities_describe_docker_isolation(tmp_path) -> None:
    profile = _profile()
    capabilities = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", profile, tmp_path / "repo", tmp_path / "work",
    ).capabilities()
    assert capabilities.backend_name == "docker"
    assert capabilities.host_process is False
    assert capabilities.filesystem_isolation is True
    assert capabilities.network_isolation is True
    assert capabilities.credential_filtering is True
    assert capabilities.resource_limits is True
    assert capabilities.repo_access == ["deny", "read-only"]
    assert capabilities.workspace_access == ["deny", "read-write"]
    assert capabilities.control_channels == ["deny"]
    assert capabilities.tool_channels == ["deny"]
    request = ExecutionRequest(
        run_id="run-docker",
        worker_manifest_digest="sha256:" + "a" * 64,
        sandbox_profile_digest=profile.profile_digest,
        attempt=1,
    )
    assert evaluate_execution(profile, request, capabilities).allowed


def test_missing_image_fails_closed_without_starting_host_process(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return _result(returncode=1, stderr="missing")

    monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
    backend = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", _profile(), tmp_path / "repo", tmp_path / "work",
    )
    (tmp_path / "repo").mkdir()
    with pytest.raises(RuntimeError, match="refusing pull/host fallback"):
        backend.ensure_running("project-1")
    assert len(calls) == 1
    assert calls[0][1:3] == ["image", "inspect"]


def test_timeout_and_cancel_cleanup_are_idempotent(monkeypatch) -> None:
    cleaned: list[bool] = []
    process = docker_backend.DockerSandboxProcess(
        ["/usr/bin/docker", "exec", "sandbox", "true"],
        {"PATH": docker_backend.os.defpath},
        timeout_seconds=1,
        cleanup=lambda: cleaned.append(True),
    )
    monkeypatch.setattr(
        LocalProcess,
        "communicate",
        lambda self, timeout: ProcessResult(137, "", "", timed_out=True),
    )
    assert process.communicate(1).timed_out
    process.kill()
    process.cancel("operator")
    assert cleaned == [True]


def test_failed_cleanup_remains_tracked_for_retry(tmp_path, monkeypatch) -> None:
    backend = docker_backend.DockerSandboxBackend(
        "/usr/bin/docker", "linen:test", _profile(),
        tmp_path / "repo", tmp_path / "work",
    )
    backend._containers["project-1"] = "linen-sandbox-owned"

    def fail_cleanup(name: str) -> bool:
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr(backend, "_remove_name", fail_cleanup)
    with pytest.raises(RuntimeError, match="daemon unavailable"):
        backend.cleanup_stopped("project-1")
    assert backend.needs_stopped_cleanup("project-1")
