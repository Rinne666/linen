from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from linen.dispatcher.config import DispatchConfig, LocalConfig, WorkerConfig
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.contracts import build_execution_contracts
from linen.dispatcher.runtime.process import LocalProcess
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.scheduler import loop as loop_module
from linen.dispatcher.tasks import common, explore
from linen.dispatcher.runtime.cancellation import (
    CANCELLATION_CLEANUP_GRACE_SECONDS,
    TaskCancellation,
)
from linen.dispatcher.workers.adapters.codex import CodexDriver
from linen.dispatcher.workers.adapters.claudecode import ClaudeCodeDriver
from linen.dispatcher.workers.adapters.pi import PiDriver
from linen.dispatcher.workers.registry import get_driver

from conftest import FakeClient, make_config, make_intent, make_project


REPO_ROOT = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------- LocalProcess


def test_local_process_captures_stdout_and_exit_code() -> None:
    process = LocalProcess(
        ["python3", "-c", "import sys; print('hello'); sys.exit(3)"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert result.stdout.strip() == "hello"
    assert result.returncode == 3
    assert not result.timed_out


def test_local_process_inherits_cwd(tmp_path: Path) -> None:
    process = LocalProcess(
        ["python3", "-c", "import os; print(os.getcwd())"],
        cwd=str(tmp_path),
        env=dict(os.environ),
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()


def test_local_process_times_out_and_kills_within_grace() -> None:
    process = LocalProcess(
        ["sh", "-c", "sleep 30"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=1,
        term_grace_seconds=2,
    )
    process.start()
    started = time.monotonic()
    result = process.communicate(timeout=30)
    elapsed = time.monotonic() - started

    assert result.timed_out
    assert elapsed < 10  # killed on its own timeout, not the 30s outer backstop


def test_local_process_kill_terminates_child_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    script = f"sleep 30 & echo $! > {pid_file}; wait"
    process = LocalProcess(
        ["sh", "-c", script],
        cwd=str(tmp_path),
        env=dict(os.environ),
        timeout_seconds=1,
        term_grace_seconds=2,
    )
    process.start()
    result = process.communicate(timeout=30)

    assert result.timed_out
    child_pid = int(pid_file.read_text().strip())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        raise AssertionError(f"child process {child_pid} survived the group kill")


def test_local_process_cancel_records_reason() -> None:
    process = LocalProcess(
        ["sh", "-c", "sleep 30"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=30,
        term_grace_seconds=2,
    )
    process.start()
    process.cancel("project stopped")
    result = process.communicate(timeout=30)

    assert result.cancelled
    assert result.cancel_reason == "project stopped"


def test_audit_deadline_cancels_running_worker_within_cleanup_grace() -> None:
    process = LocalProcess(
        ["python3", "-c", "import time; time.sleep(30)"],
        cwd=os.getcwd(),
        env=dict(os.environ),
        timeout_seconds=30,
        term_grace_seconds=1,
    )
    cancellation = TaskCancellation(deadline_epoch=time.time() + 0.35)
    process.start()
    cancellation.attach_process(process)
    started = time.monotonic()
    try:
        result = process.communicate(timeout=10)
    finally:
        cancellation.attach_process(None)
        cancellation.close()

    assert result.cancelled
    assert result.cancel_reason == "audit_wall_clock_budget_exhausted"
    assert time.monotonic() - started < CANCELLATION_CLEANUP_GRACE_SECONDS


def test_pre_cancelled_run_is_terminal_without_starting_worker(tmp_path: Path) -> None:
    project = make_project(intents=[make_intent()])
    worker = DispatchConfig.model_validate(make_config()).workers[0]
    manifest, run = build_execution_contracts(
        project,
        worker,
        "explore_execute",
        timeout_seconds=30,
        attempt=1,
        intent_id="i001",
        logical_scope="deadline-acceptance",
        recipe_id="test",
        recipe_version=1,
        prompt="test worker invocation",
    )

    class RecordingClient:
        def __init__(self):
            self.registered = None
            self.terminal = None
            self.events = []

        def register_run(self, envelope):
            self.registered = envelope
            return ApiResult(201, {})

        def transition_run(self, envelope):
            self.terminal = envelope
            return ApiResult(200, {})

        def register_artifact(self, _artifact):
            return _artifact

        def append_audit_event(self, event):
            self.events.append(event)
            return ApiResult(201, {})

    class NoWorkerBackend(LocalBackend):
        def __init__(self, root):
            super().__init__(LocalConfig(workspace_root=str(root)))
            self.worker_starts = 0

        def build_exec_process(self, *args, **kwargs):
            self.worker_starts += 1
            raise AssertionError("cancelled worker must never be started")

    backend = NoWorkerBackend(tmp_path)
    project_handle = backend.ensure_running("proj_001")
    client = RecordingClient()
    cancellation = TaskCancellation(deadline_epoch=time.time() + 10)
    cancellation.cancel("audit_wall_clock_budget_exhausted")
    try:
        result = common.run_worker_process(
            backend,
            project_handle,
            worker,
            ["never-run"],
            phase="explore_execute",
            timeout_seconds=30,
            cancellation=cancellation,
            client=client,
            run_envelope=run,
            worker_manifest=manifest,
            recipe_content_digest=manifest.recipe.digest,
        )
    finally:
        cancellation.close()
        backend.close()

    assert result.cancelled
    assert client.registered.status == "running"
    assert client.terminal.status == "cancelled"
    assert len(client.terminal.artifact_ids) == 3
    assert backend.worker_starts == 0
    finished = [event for event in client.events if event.event_type == "execution_attempt_finished"]
    assert len(finished) == 1
    assert finished[0].payload["process_started"] is False
    assert finished[0].payload["attempt_status"] == "cancelled"


def test_deadline_expiring_during_process_setup_never_starts_worker(tmp_path: Path) -> None:
    worker = DispatchConfig.model_validate(make_config()).workers[0]
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    project_handle = backend.ensure_running("proj_001")

    class NeverStartedProcess:
        def __init__(self):
            self.started = False

        def start(self):
            self.started = True

        def communicate(self, timeout):
            raise AssertionError("process should not be communicated")

        def cancel(self, _reason):
            return None

        def kill(self):
            return None

    processes = []

    def slow_process_setup(*_args, **_kwargs):
        time.sleep(1.2)
        process = NeverStartedProcess()
        processes.append(process)
        return process

    backend.build_exec_process = slow_process_setup
    cancellation = TaskCancellation(deadline_epoch=time.time() + 1.1)
    try:
        result = common.run_worker_process(
            backend,
            project_handle,
            worker,
            ["never-run"],
            phase="explore_execute",
            timeout_seconds=30,
            cancellation=cancellation,
        )
    finally:
        cancellation.close()
        backend.close()

    assert result.cancelled
    assert result.cancel_reason == "audit_wall_clock_budget_exhausted"
    assert len(processes) == 1
    assert processes[0].started is False


# --------------------------------------------------------------------------- LocalBackend


def test_local_backend_creates_isolated_project_dir(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    handle = backend.ensure_running("proj_001")

    assert Path(handle) == tmp_path / "proj_001"
    assert Path(handle).is_dir()
    assert backend.container_name("proj_001") == str(tmp_path / "proj_001")


def test_local_backend_merges_host_env_with_worker_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LINEN_HOST_VAR", "host")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    handle = backend.ensure_running("proj_001")

    process = backend.build_exec_process(
        handle,
        {"LINEN_WORKER_VAR": "worker"},
        ["sh", "-c", 'printf "%s-%s" "$LINEN_HOST_VAR" "$LINEN_WORKER_VAR"'],
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    assert result.stdout == "host-worker"


def test_local_common_env_reaches_worker_subprocess(tmp_path: Path, monkeypatch) -> None:
    # common_env (e.g. an outbound proxy) merges into every worker's env and must survive
    # all the way to the host subprocess in local mode.
    payload = _local_payload()
    payload["local"] = {"workspace_root": str(tmp_path)}
    payload["common_env"] = {
        "https_proxy": "http://127.0.0.1:7897",
        "http_proxy": "http://127.0.0.1:7897",
        "all_proxy": "http://127.0.0.1:7897",
    }
    config = DispatchConfig.model_validate(payload)
    worker = next(w for w in config.workers if w.type == "claudecode")
    assert worker.env["https_proxy"] == "http://127.0.0.1:7897"

    assert config.local is not None
    backend = LocalBackend(config.local)
    handle = backend.ensure_running("proj_001")
    process = backend.build_exec_process(
        handle,
        dict(worker.env),
        ["sh", "-c", 'printf "%s|%s|%s" "$https_proxy" "$http_proxy" "$all_proxy"'],
        timeout_seconds=10,
    )
    process.start()
    result = process.communicate(timeout=20)

    proxy = "http://127.0.0.1:7897"
    assert result.stdout == f"{proxy}|{proxy}|{proxy}"


def test_local_backend_write_text_file_writes_to_host(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    target = tmp_path / "snapshots" / "graph.yaml"

    backend.write_text_file("ignored", str(target), "facts: []\n")

    assert target.read_text() == "facts: []\n"


def test_local_backend_keep_leaves_dir_and_reports_no_cleanup(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path), completed_action="keep"))
    handle = backend.ensure_running("proj_001")

    assert backend.needs_completed_cleanup("proj_001") is False
    assert backend.cleanup_completed("proj_001") is True
    assert Path(handle).is_dir()


def test_local_backend_remove_deletes_dir_on_completion(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path), completed_action="remove"))
    handle = backend.ensure_running("proj_001")

    assert backend.needs_completed_cleanup("proj_001") is True
    assert backend.cleanup_completed("proj_001") is True
    assert not Path(handle).exists()


def test_local_backend_stopped_cleanup_is_noop(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    backend.ensure_running("proj_001")

    assert backend.needs_stopped_cleanup("proj_001") is False
    assert backend.cleanup_stopped("proj_001") is True


# --------------------------------------------------------------------------- config


def _local_payload() -> dict:
    return {
        "server": "http://127.0.0.1:8000",
        "runtime": {
            "worker_healthcheck": "disabled",
            "interval": 3,
            "max_workers": 2,
            "max_running_projects": 1,
            "max_project_workers": 2,
            "healthcheck_timeout": 5,
            "prompt_group": "default",
        },
        "tasks": {
            "bootstrap": {"timeout": 10, "conclude_timeout": 5},
            "reason": {"timeout": 10, "max_intents": 3},
            "explore": {"timeout": 10, "conclude_timeout": 5},
        },
        "workers": [
            {"name": "local-claude", "type": "claudecode", "task_types": ["explore"], "max_running": 1, "priority": 0},
            {"name": "local-codex", "type": "codex", "task_types": ["explore"], "max_running": 1, "priority": 1},
            {"name": "local-pi", "type": "pi", "task_types": ["reason"], "max_running": 1, "priority": 2},
        ],
    }


def test_local_execution_needs_no_container_or_worker_env() -> None:
    config = DispatchConfig.model_validate(_local_payload())

    assert config.local is not None
    assert config.local.completed_action == "keep"
    assert all(worker.env == {} for worker in config.workers)


def test_local_workspace_root_is_optional_and_defaults_null() -> None:
    payload = _local_payload()
    payload["local"] = {"completed_action": "remove"}
    config = DispatchConfig.model_validate(payload)

    assert config.local is not None
    assert config.local.workspace_root is None
    assert config.local.completed_action == "remove"


def test_removed_container_execution_fields_are_rejected() -> None:
    payload = _local_payload()
    payload["runtime"]["execution"] = "container"
    payload["container"] = {"image": "img", "network_mode": "host", "completed_action": "stop"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DispatchConfig.model_validate(payload)


def test_shipped_local_example_config_is_valid() -> None:
    config = DispatchConfig.load(REPO_ROOT / "dispatch.local.example.yaml")

    assert config.local is not None
    assert config.local.completed_action == "keep"


# --------------------------------------------------------------------------- startup CLI check


def _bare_loop(config: DispatchConfig) -> loop_module.DispatcherLoop:
    loop = loop_module.DispatcherLoop.__new__(loop_module.DispatcherLoop)
    loop.config = config
    return loop


def test_local_cli_check_passes_when_cli_present() -> None:
    payload = _local_payload()
    payload["workers"] = [{"name": "m", "type": "mock", "task_types": ["reason"], "max_running": 1, "priority": 0}]
    config = DispatchConfig.model_validate(payload)

    _bare_loop(config)._run_local_binary_check()  # mock -> python3 --help runs; must not raise


def test_local_cli_check_exits_when_no_cli_installed(monkeypatch) -> None:
    monkeypatch.setattr(loop_module.shutil, "which", lambda _binary: None)
    config = DispatchConfig.model_validate(_local_payload())

    with pytest.raises(RuntimeError, match="none of the configured worker CLIs"):
        _bare_loop(config)._run_local_binary_check()


# --------------------------------------------------------------------------- drivers


def _bare_worker(worker_type: str) -> WorkerConfig:
    return WorkerConfig.model_validate(
        {"name": worker_type, "type": worker_type, "task_types": ["explore"], "max_running": 1, "priority": 0}
    )


def test_codex_local_driver_omits_provider_injection() -> None:
    worker = _bare_worker("codex")
    argv = CodexDriver(local=True).build_execute(worker, "PROMPT", None).argv

    assert argv == ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--json", "--", "PROMPT"]
    assert not any("model_providers" in part for part in argv)
    assert "--model" not in argv

    conclude = CodexDriver(local=True).build_conclude(worker, "PROMPT", "sess-1")
    assert conclude[:4] == ["codex", "exec", "resume", "sess-1"]
    assert conclude[-2:] == ["--", "PROMPT"]
    assert not any("model_providers" in part for part in conclude)


def test_pi_local_driver_omits_models_json_and_provider() -> None:
    worker = _bare_worker("pi")
    argv = PiDriver(local=True).build_execute(worker, "PROMPT", None).argv

    assert argv[0] == "/bin/sh"
    assert "exec pi" in argv[2]
    assert "--provider" not in argv
    assert "--model" not in argv
    assert argv[-2:] == ["-p", "PROMPT"]


def test_registry_returns_local_driver_variants() -> None:
    assert get_driver("codex").local is True
    assert get_driver("pi").local is True
    assert get_driver("claudecode") is get_driver("claudecode")
    assert get_driver("mock") is get_driver("mock")


POC_PROMPT = "# ISOLATED POC EXECUTION TASK\nReproduce the candidate in the sandbox.\n"
READONLY_RECON_PROMPT = "# READ-ONLY RECON TASK\nSurvey the repository.\n"


def test_claude_poc_prompt_grants_execution_tools_in_read_only_worker() -> None:
    worker = _bare_worker("claudecode").model_copy(update={"sandbox_mode": "read-only"})
    argv = get_driver("claudecode").build_execute(worker, POC_PROMPT, "sess-1").argv

    assert "--dangerously-skip-permissions" in argv
    assert "--safe-mode" not in argv
    assert "--restricted" not in argv


def test_claude_read_only_prompt_still_restricts_tools() -> None:
    worker = _bare_worker("claudecode")
    argv = get_driver("claudecode").build_execute(worker, READONLY_RECON_PROMPT, "sess-1").argv

    assert "--safe-mode" in argv
    assert "--restricted" in argv
    assert argv[argv.index("--tools") + 1] == "Read,Grep,Glob"
    # Plan mode would make strict-output tasks present a plan instead of their
    # JSON contract; read-only enforcement already comes from the tool allowlist.
    assert "--permission-mode" not in argv


def test_claude_read_only_prompt_allows_only_its_generated_context_projection() -> None:
    worker = _bare_worker("claudecode").model_copy(update={"sandbox_mode": "read-only"})
    projection_dir = "/tmp/linen-prompts/explore_execute-ctx-" + "a" * 64
    prompt = READONLY_RECON_PROMPT + f"\nContext: {projection_dir}/context.json"
    driver = ClaudeCodeDriver()

    for argv in (
        driver.build_execute(worker, prompt, "sess-1").argv,
        driver.build_conclude(worker, prompt, "sess-1"),
    ):
        assert argv[argv.index("--add-dir") + 1] == projection_dir
        assert argv[argv.index("--tools") + 1] == "Read,Grep,Glob"
        assert "--dangerously-skip-permissions" not in argv


def test_claude_read_only_prompt_fails_closed_on_ambiguous_context_paths() -> None:
    worker = _bare_worker("claudecode").model_copy(update={"sandbox_mode": "read-only"})
    path_a = "/tmp/linen-prompts/explore_execute-ctx-" + "a" * 64 + "/context.json"
    path_b = "/tmp/linen-prompts/reason_execute-ctx-" + "b" * 64 + "/context.json"
    argv = get_driver("claudecode").build_execute(
        worker, READONLY_RECON_PROMPT + f"\n{path_a}\n{path_b}", "sess-1",
    ).argv

    assert "--add-dir" not in argv


def test_pi_poc_prompt_grants_write_and_bash_tools_in_read_only_worker() -> None:
    worker = _bare_worker("pi").model_copy(update={"sandbox_mode": "read-only"})
    argv = PiDriver(local=True).build_execute(worker, POC_PROMPT, None).argv

    tools = argv[argv.index("--tools") + 1]
    assert "bash" in tools and "write" in tools

    recon_argv = PiDriver(local=True).build_execute(worker, READONLY_RECON_PROMPT, None).argv
    assert recon_argv[recon_argv.index("--tools") + 1] == "read,grep,find,ls"


# --------------------------------------------------------------------------- end to end


def _local_config_for_worker(name: str, worker_type: str) -> DispatchConfig:
    return DispatchConfig.model_validate(
        {
            "server": "in-process",
            "runtime": {
                "worker_healthcheck": "disabled",
                "interval": 60,
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 5,
                "prompt_group": "default",
            },
            "tasks": {
                "bootstrap": {"timeout": 30, "conclude_timeout": 10},
                "reason": {"timeout": 30, "max_intents": 3},
                "explore": {"timeout": 30, "conclude_timeout": 10},
            },
            "workers": [
                {"name": name, "type": worker_type, "task_types": ["explore"], "max_running": 1, "priority": 0}
            ],
        }
    )


def _install_fake_cli(tmp_path: Path, monkeypatch, name: str, body: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / name
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_explore_runs_real_local_cli_end_to_end(tmp_path: Path, monkeypatch) -> None:
    # A fake `claude` on PATH stands in for the real CLI: the whole local path is exercised
    # for real — driver argv -> LocalBackend -> LocalProcess subprocess -> stdout parsing.
    _install_fake_cli(
        tmp_path,
        monkeypatch,
        "claude",
        "echo '{\"accepted\":true,\"data\":{\"description\":\"local fake fact\"}}'",
    )
    monkeypatch.setattr(common, "GRAPH_SNAPSHOT_ROOT", str(tmp_path / "prompts"))

    config = _local_config_for_worker("test-worker", "claudecode")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    intent = make_intent()
    project = make_project(intents=[intent])
    client = FakeClient(project)

    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "facts:\n- id: f001\n",
        intent,
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "success"
    assert client.concluded == [("proj_001", "i001", "test-worker", "local fake fact")]
    # Only the bounded context projection is materialised on the host; the
    # legacy full graph export must not be written for an LLM worker.
    snapshot_root = tmp_path / "prompts"
    context_files = list(snapshot_root.rglob("context.json"))
    assert context_files
    assert not list(snapshot_root.rglob("graph.yaml"))


def test_explore_local_cli_rejection_releases_intent(tmp_path: Path, monkeypatch) -> None:
    _install_fake_cli(
        tmp_path,
        monkeypatch,
        "claude",
        "echo '{\"accepted\":false,\"reason\":\"policy_refusal\"}'",
    )
    monkeypatch.setattr(common, "GRAPH_SNAPSHOT_ROOT", str(tmp_path / "prompts"))

    config = _local_config_for_worker("test-worker", "claudecode")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    intent = make_intent()
    project = make_project(intents=[intent])
    client = FakeClient(project)

    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "facts:\n- id: f001\n",
        intent,
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "rejected"
    assert client.concluded == []
    assert client.released == [("proj_001", "i001", "test-worker")]


def test_explore_retry_collision_with_terminal_run_fails_without_crashing(
    tmp_path: Path, monkeypatch,
) -> None:
    """A replayed attempt reuses a deterministic run id. When that id already
    exists in a terminal state the protocol raises; the task must surface a
    normal failed attempt so the scheduler advances the attempt counter and
    derives a fresh run id, instead of dying with an unhandled traceback."""
    _install_fake_cli(
        tmp_path,
        monkeypatch,
        "claude",
        "echo '{\"accepted\":true,\"data\":{\"description\":\"local fake fact\"}}'",
    )
    monkeypatch.setattr(common, "GRAPH_SNAPSHOT_ROOT", str(tmp_path / "prompts"))

    config = _local_config_for_worker("test-worker", "claudecode")
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    intent = make_intent()
    project = make_project(intents=[intent])

    class TerminalRunClient(FakeClient):
        def register_run(self, run):
            return run.model_copy(update={"status": "succeeded"})

    client = TerminalRunClient(project)

    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "facts:\n- id: f001\n",
        intent,
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome == "failed"
    assert client.concluded == []
    assert client.released == [("proj_001", "i001", "test-worker")]
