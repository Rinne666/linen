from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.contracts import (
    ArtifactMetadata,
    AuditEventEnvelope,
    ContextProjection,
    ExecutionRequest,
    NodeEnvelope,
    RunEnvelope,
    SandboxProfile,
)
from linen.dispatcher.config import LocalConfig, WorkerConfig
from linen.dispatcher.protocol.client import ApiResult, LinenClient
from linen.dispatcher.runtime.contracts import (
    build_execution_contracts,
    build_run_envelope,
    build_worker_manifest,
    recipe_digest,
)
from linen.dispatcher.tasks.common import (
    DuplicateTerminalRun,
    ExecutionPolicyDenied,
    _finish_contract_run,
    _start_contract_run,
    run_worker_process,
)
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.policy import BackendCapabilities, legacy_local_profile
from linen.server.models import ProjectDetail, ProjectMeta


def _project() -> ProjectDetail:
    return ProjectDetail(
        project=ProjectMeta(
            id="p1", title="runtime", status="active", bootstrap_enabled=True,
            graph_revision=7, source_generation=2, plan_revision=3,
            created_at="2026-01-01T00:00:00Z",
        ),
        facts=[], intents=[], hints=[], reviews=[], errors=[], edges=[], stages=[], decisions=[],
    )


def _worker() -> WorkerConfig:
    return WorkerConfig(
        name="worker-1", type="mock", task_types=["explore"], max_running=1, priority=0,
    )


def _run() -> RunEnvelope:
    return build_run_envelope(
        _project(), _worker(), "explore_execute", timeout_seconds=30,
        intent_id="i1", recipe_id="audit.verify", recipe_version=2,
        recipe_label="Verify", prompt="trusted recipe",
    )


def test_client_vnext_methods_serialize_and_validate_contracts(monkeypatch) -> None:
    client = LinenClient("http://server")
    calls: list[tuple[str, str, dict]] = []
    artifact = ArtifactMetadata(
        artifact_id="a1", project_id="p1", kind="log", workspace_path=".linen/run.log",
        sha256="a" * 64, media_type="text/plain",
    )
    run = _run()
    projection = ContextProjection(
        projection_id="ctx-1", project_id="p1", snapshot_id="snap-1", graph_revision=7,
        source_generation=2, plan_revision=3, context={"nodes": []},
        selection_policy="test", created_at="2026-01-01T00:00:00Z",
    )
    event = AuditEventEnvelope(
        event_id="e1", project_id="p1", event_type="run.started", actor="dispatcher",
        graph_revision=7, source_generation=2, plan_revision=3,
        created_at="2026-01-01T00:00:00Z",
    )

    def request(method: str, path: str, *, json: dict) -> ApiResult:
        calls.append((method, path, json))
        if path.endswith("/snapshot"):
            return ApiResult(200, {
                "project_id": "p1", "graph_revision": 7, "source_generation": 2,
                "plan_revision": 3, "nodes": [], "edges": [],
                "created_at": "2026-01-01T00:00:00Z",
            })
        if "/artifacts" in path:
            payload = artifact.model_dump(mode="json")
            return ApiResult(200, [payload] if method == "GET" and path.endswith("/artifacts") else payload)
        if path.endswith("/runs/recover"):
            return ApiResult(200, [run.model_dump(mode="json")])
        if "/runs" in path:
            payload = run.model_dump(mode="json")
            return ApiResult(200, [payload] if method == "GET" and path.endswith("/runs") else payload)
        if "context-projections" in path:
            payload = projection.model_dump(mode="json")
            return ApiResult(200, [payload] if method == "GET" and path.endswith("context-projections") else payload)
        return ApiResult(200, event.model_dump(mode="json"))

    monkeypatch.setattr(client, "_request_json", request)
    assert client.get_snapshot("p1").project_id == "p1"
    assert client.register_artifact(artifact).artifact_id == "a1"
    assert client.get_artifact("p1", "a1").artifact_id == "a1"
    assert client.list_artifacts("p1")[0].artifact_id == "a1"
    assert client.register_run(run).run_id == run.run_id
    assert client.get_run("p1", run.run_id).run_id == run.run_id
    assert client.list_runs("p1")[0].run_id == run.run_id
    assert client.recover_runs("p1")[0].run_id == run.run_id
    assert client.transition_run(run).run_id == run.run_id
    assert client.register_context_projection(projection).projection_id == "ctx-1"
    assert client.get_context_projection("p1", "ctx-1").projection_id == "ctx-1"
    assert client.list_context_projections("p1")[0].projection_id == "ctx-1"
    assert client.append_event(event).event_id == "e1"
    assert calls[0][:2] == ("GET", "/projects/p1/snapshot")
    assert any(path.endswith("/runs") and body["idempotency_key"] == run.idempotency_key for _, path, body in calls)


def test_runtime_contract_helpers_have_stable_identity_and_recipe_digest() -> None:
    first = build_worker_manifest(
        _project(), _worker(), "explore_execute", recipe_id="audit.verify",
        recipe_version=2, recipe_label="Verify", prompt="recipe",
        recipe_metadata={"b": 2, "a": 1}, intent_id="i1",
    )
    second = build_worker_manifest(
        _project(), _worker(), "explore_execute", recipe_id="audit.verify",
        recipe_version=2, recipe_label="Verify", prompt="recipe",
        recipe_metadata={"a": 1, "b": 2}, intent_id="i1",
    )
    assert first.manifest_digest == second.manifest_digest
    assert first.permissions == {}
    left = _run()
    right = _run()
    assert left.run_id == right.run_id
    assert left.idempotency_key == right.idempotency_key
    for component in (
        "project=p1", "intent=i1", "scope=intent:i1", "phase=explore_execute",
        "source_generation=2", "plan_revision=3", "graph_revision=7", "attempt=1",
    ):
        assert component in left.idempotency_key
    assert build_run_envelope(
        _project(), _worker(), "explore_execute", timeout_seconds=30,
        intent_id="i1", attempt=2,
    ).run_id != left.run_id
    assert build_run_envelope(
        _project(), _worker(), "review", timeout_seconds=30,
        intent_id="i1",
    ).run_id != left.run_id
    changed_intent = build_run_envelope(
        _project(), _worker(), "explore_execute", timeout_seconds=30,
        intent_id="i2",
    )
    assert changed_intent.run_id != left.run_id
    changed_project = _project().model_copy(update={
        "project": _project().project.model_copy(update={"graph_revision": 8}),
    })
    assert build_run_envelope(
        changed_project, _worker(), "explore_execute", timeout_seconds=30,
        intent_id="i1",
    ).run_id != left.run_id
    no_intent_left = build_run_envelope(
        _project(), _worker(), "reason", timeout_seconds=30,
        logical_scope="reason:lease-1",
    )
    no_intent_right = build_run_envelope(
        _project(), _worker(), "reason", timeout_seconds=30,
        logical_scope="reason:lease-1",
    )
    assert no_intent_left.run_id == no_intent_right.run_id
    assert "scope=reason:lease-1" in no_intent_left.idempotency_key
    assert build_run_envelope(
        _project(), _worker(), "reason", timeout_seconds=30,
        logical_scope="reason:lease-2",
    ).run_id != no_intent_left.run_id
    assert recipe_digest("phase", metadata={"x": 1}) == recipe_digest("phase", metadata={"x": 1})


def test_execution_contracts_reject_cross_identity_and_share_stable_run() -> None:
    manifest, envelope = build_execution_contracts(
        _project(), _worker(), "explore_execute", timeout_seconds=30, intent_id="i1",
    )
    rebuilt_manifest, rebuilt_envelope = build_execution_contracts(
        _project(), _worker(), "explore_execute", timeout_seconds=30, intent_id="i1",
    )
    assert manifest.manifest_digest == rebuilt_manifest.manifest_digest
    assert envelope.run_id == rebuilt_envelope.run_id
    assert envelope.idempotency_key == rebuilt_envelope.idempotency_key

    mismatched = build_worker_manifest(
        _project(), _worker(), "explore_execute", intent_id="i1", run_id="run-other",
    )
    with pytest.raises(ValueError, match="run_id"):
        build_run_envelope(
            _project(), _worker(), "explore_execute", timeout_seconds=30,
            intent_id="i1", run_id="run-explicit", worker_manifest=mismatched,
        )


class _Process:
    def __init__(self, result: ProcessResult):
        self.result = result

    def start(self) -> None:
        return None

    def communicate(self, timeout: float | None) -> ProcessResult:
        return self.result

    def kill(self) -> None:
        return None

    def cancel(self, reason: str) -> None:
        return None


class _Backend:
    def __init__(self, result: ProcessResult):
        self.result = result

    def build_exec_process(self, container_name, env, command, timeout_seconds=None, kill_after_seconds=5):
        return _Process(self.result)

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


class _ContractClient:
    def __init__(self, *, failing: bool = False):
        self.failing = failing
        self.registered: list[RunEnvelope] = []
        self.transitions: list[RunEnvelope] = []
        self.artifacts: list[ArtifactMetadata] = []

    def register_run(self, run: RunEnvelope):
        self.registered.append(run)
        return ApiResult(503, text="unavailable") if self.failing else run

    def transition_run(self, run: RunEnvelope):
        self.transitions.append(run)
        return ApiResult(503, text="unavailable") if self.failing else run

    def register_artifact(self, artifact: ArtifactMetadata):
        self.artifacts.append(artifact)
        return artifact


class _PolicyClient(_ContractClient):
    def __init__(self):
        super().__init__()
        self.events: list[AuditEventEnvelope] = []

    def append_event(self, event: AuditEventEnvelope):
        self.events.append(event)
        return event


class _PolicyBackend(_Backend):
    def __init__(self, result: ProcessResult, capabilities: BackendCapabilities):
        super().__init__(result)
        self._capabilities = capabilities
        self.build_calls = 0

    def get_capabilities(self) -> BackendCapabilities:
        return self._capabilities

    def build_exec_process(self, *args, **kwargs):
        self.build_calls += 1
        return super().build_exec_process(*args, **kwargs)


def test_worker_record_and_status_mapping_survive_protocol_failures(tmp_path, caplog) -> None:
    result = ProcessResult(returncode=0, stdout="worker output", stderr="")
    client = _ContractClient(failing=True)
    run = _run()
    manifest = build_worker_manifest(
        _project(), _worker(), "explore_execute", intent_id="i1", run_id=run.run_id,
        recipe_id="audit.verify", recipe_version=2, recipe_label="Verify",
        prompt="trusted recipe",
    )
    returned = run_worker_process(
        _Backend(result), str(tmp_path), _worker(), ["mock"], phase="explore_execute",
        timeout_seconds=30, client=client, run_envelope=run, worker_manifest=manifest,
        context_projection_id="ctx-1",
    )
    assert returned is result
    assert client.registered[0].status == "running"
    assert client.transitions[0].status == "succeeded"
    assert len(client.artifacts) == 3
    assert {artifact.kind for artifact in client.artifacts} == {
        "execution_record", "stdout", "stderr",
    }
    assert all(artifact.workspace_path.startswith(".linen-executions/") for artifact in client.artifacts)
    assert all(artifact.producer_run_id == run.run_id for artifact in client.artifacts)
    record = next(path for path in (tmp_path / ".linen-executions").glob("*.json"))
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 4
    assert payload["run_id"] == run.run_id
    assert payload["attempt"] == 1
    assert payload["idempotency_key"] == run.idempotency_key
    assert payload["context_projection_id"] == "ctx-1"
    assert payload["manifest_digest"] == manifest.manifest_digest
    assert payload["recipe_digest"].startswith("sha256:")
    assert "vNext run registration failed" in caplog.text
    assert "vNext run transition failed" in caplog.text


def test_contract_execution_registers_prompt_and_stable_artifacts(tmp_path) -> None:
    result = ProcessResult(returncode=0, stdout="out", stderr="err")
    client = _ContractClient()
    worker = _worker().model_copy(update={"type": "pi"})
    run = build_run_envelope(
        _project(), worker, "explore_execute", timeout_seconds=30,
        intent_id="i1", recipe_id="audit.verify", recipe_version=2,
        recipe_label="Verify", prompt="prompt",
    )
    manifest = build_worker_manifest(
        _project(), worker, "explore_execute",
        intent_id="i1", run_id=run.run_id, recipe_id="audit.verify", recipe_version=2,
        recipe_label="Verify", prompt="prompt",
    )
    backend = _Backend(result)
    first = run_worker_process(
        backend, str(tmp_path), worker, ["pi", "-p", "prompt"],
        phase="explore_execute", timeout_seconds=30, client=client,
        run_envelope=run, worker_manifest=manifest,
    )
    first_ids = [artifact.artifact_id for artifact in client.artifacts]
    assert first is result
    assert len(first_ids) == 4
    assert any(artifact.kind == "prompt" for artifact in client.artifacts)
    terminal = client.transitions[-1]
    assert terminal.artifact_ids == first_ids
    assert all(len(artifact.sha256) == 64 for artifact in client.artifacts)

    # A retry with the same run identity produces the same filenames and IDs;
    # a real idempotent server would return the existing metadata rows.
    client.transitions.clear()
    run_worker_process(
        backend, str(tmp_path), worker, ["pi", "-p", "prompt"],
        phase="explore_execute", timeout_seconds=30, client=client,
        run_envelope=run, worker_manifest=manifest,
    )
    assert [artifact.artifact_id for artifact in client.artifacts[4:]] == first_ids
    assert client.transitions[-1].artifact_ids == first_ids


def test_non_pi_contract_record_keeps_prompt_artifact_without_pi_command(tmp_path) -> None:
    result = ProcessResult(returncode=0, stdout="out", stderr="err")
    client = _ContractClient()
    worker = _worker().model_copy(update={"type": "codex"})
    manifest, run = build_execution_contracts(
        _project(), worker, "explore_execute", timeout_seconds=30, intent_id="i1",
        recipe_id="audit.verify", recipe_version=2, recipe_label="Verify", prompt="prompt",
    )
    run_worker_process(
        _Backend(result), str(tmp_path), worker, ["codex", "exec", "--", "prompt"],
        phase="explore_execute", timeout_seconds=30, client=client,
        run_envelope=run, worker_manifest=manifest,
    )
    record = json.loads(next((tmp_path / ".linen-executions").glob("*.json")).read_text())
    assert record["schema_version"] == 4
    assert record["command"] == "codex"
    assert record["prompt"]
    assert any(artifact.kind == "prompt" for artifact in client.artifacts)


def test_contract_registration_uses_authoritative_run_and_rejects_terminal() -> None:
    class Authoritative(_ContractClient):
        def register_run(self, run: RunEnvelope):
            self.registered.append(run)
            return run.model_copy(update={"status": "running", "started_at": "server-time"})

    client = Authoritative()
    returned = _start_contract_run(client, _run(), worker_manifest=None, context_projection_id=None)
    assert returned is not None
    assert returned.started_at == "server-time"

    class Terminal(Authoritative):
        def register_run(self, run: RunEnvelope):
            return run.model_copy(update={"status": "succeeded"})

    with pytest.raises(DuplicateTerminalRun, match="already terminal"):
        _start_contract_run(Terminal(), _run(), worker_manifest=None, context_projection_id=None)


def test_process_setup_failure_closes_registered_run(tmp_path) -> None:
    class BrokenBackend(_Backend):
        def build_exec_process(self, *args, **kwargs):
            raise OSError("cannot spawn worker")

    client = _ContractClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30,
        recipe_id="audit.verify", recipe_version=2, recipe_label="Verify", prompt="trusted",
    )
    with pytest.raises(OSError, match="cannot spawn"):
        run_worker_process(
            BrokenBackend(ProcessResult(1, "", "")), str(tmp_path), _worker(), ["mock"],
            phase="explore_execute", timeout_seconds=30, client=client,
            run_envelope=run, worker_manifest=manifest,
        )
    assert client.transitions[-1].status == "failed"
    assert len(client.artifacts) == 3


def test_worker_start_rejects_manifest_or_context_identity_mismatch() -> None:
    run = _run()
    wrong_manifest = build_worker_manifest(
        _project(), _worker(), "explore_execute", intent_id="i1", run_id="run-other",
        recipe_id="audit.verify", recipe_version=2, recipe_label="Verify",
        prompt="trusted recipe",
    )
    with pytest.raises(ValueError, match="run_id"):
        _start_contract_run(None, run, worker_manifest=wrong_manifest, context_projection_id=None)

    matching_manifest = build_worker_manifest(
        _project(), _worker(), "explore_execute", intent_id="i1", run_id=run.run_id,
        recipe_id="audit.verify", recipe_version=2, recipe_label="Verify",
        prompt="trusted recipe",
    )
    with pytest.raises(ValueError, match="context projection"):
        _start_contract_run(
            None,
            run.model_copy(update={"context_projection_id": "ctx-1"}),
            worker_manifest=matching_manifest,
            context_projection_id="ctx-2",
        )


@pytest.mark.parametrize(
    ("result", "status"),
    [
        (ProcessResult(1, "", ""), "failed"),
        (ProcessResult(124, "", "", timed_out=True), "timed_out"),
        (ProcessResult(1, "", "", cancelled=True, cancel_reason="operator"), "cancelled"),
    ],
)
def test_worker_status_mapping(result: ProcessResult, status: str) -> None:
    client = _ContractClient()
    _finish_contract_run(client, _run(), result)
    assert client.transitions[-1].status == status


def _execution_request(run: RunEnvelope, manifest_digest: str, profile: SandboxProfile) -> ExecutionRequest:
    assert profile.profile_digest is not None
    return ExecutionRequest(
        run_id=run.run_id,
        worker_manifest_digest=manifest_digest,
        sandbox_profile_digest=profile.profile_digest,
        attempt=run.attempt,
    )


def test_policy_denial_blocks_run_without_starting_process(tmp_path) -> None:
    client = _PolicyClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30, prompt="trusted",
    )
    profile = SandboxProfile()
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    build_calls: list[bool] = []

    def must_not_build(*args, **kwargs):
        build_calls.append(True)
        raise AssertionError("policy denial must happen before process construction")

    backend.build_exec_process = must_not_build

    with pytest.raises(ExecutionPolicyDenied, match="insufficient_capabilities"):
        run_worker_process(
            backend, str(tmp_path), _worker(), ["mock"], phase="explore_execute",
            timeout_seconds=30, client=client, run_envelope=run,
            worker_manifest=manifest,
            execution_request=_execution_request(run, manifest.manifest_digest, profile),
            sandbox_profile=profile,
        )

    assert build_calls == []
    assert client.transitions[-1].status == "blocked"
    assert {artifact.kind for artifact in client.artifacts} == {
        "execution_record", "stdout", "stderr",
    }
    assert len(client.events) == 1
    assert client.events[0].event_type == "execution_policy_denied"
    record = json.loads(next((tmp_path / ".linen-executions").glob("*.json")).read_text())
    assert record["execution_mode"] == "policy-gated"
    assert record["isolation"] == "denied"
    assert record["policy_decision"]["reason"] == "insufficient_capabilities"


@pytest.mark.parametrize("missing", ["request", "profile"])
def test_incomplete_policy_contract_fails_closed(tmp_path, missing: str) -> None:
    client = _PolicyClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30, prompt="trusted",
    )
    profile = SandboxProfile()
    backend = _PolicyBackend(
        ProcessResult(0, "", ""),
        BackendCapabilities(backend_name="sandbox"),
    )
    request = _execution_request(run, manifest.manifest_digest, profile)

    with pytest.raises(ExecutionPolicyDenied, match="execution_request_and_profile_required"):
        run_worker_process(
            backend, str(tmp_path), _worker(), ["mock"], phase="explore_execute",
            timeout_seconds=30, client=client, run_envelope=run,
            worker_manifest=manifest,
            execution_request=None if missing == "request" else request,
            sandbox_profile=None if missing == "profile" else profile,
        )
    assert backend.build_calls == 0
    assert client.transitions[-1].status == "blocked"


def test_policy_identity_mismatch_fails_closed(tmp_path) -> None:
    client = _PolicyClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30, prompt="trusted",
    )
    profile = SandboxProfile()
    request = _execution_request(run, "sha256:" + "f" * 64, profile)
    backend = _PolicyBackend(
        ProcessResult(0, "", ""),
        BackendCapabilities(backend_name="sandbox"),
    )

    with pytest.raises(ExecutionPolicyDenied, match="worker_manifest_digest_mismatch"):
        run_worker_process(
            backend, str(tmp_path), _worker(), ["mock"], phase="explore_execute",
            timeout_seconds=30, client=client, run_envelope=run,
            worker_manifest=manifest, execution_request=request,
            sandbox_profile=profile,
        )
    assert backend.build_calls == 0
    assert client.transitions[-1].status == "blocked"


def test_explicit_legacy_policy_is_allowed_but_not_marked_isolated(tmp_path) -> None:
    client = _PolicyClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30, prompt="trusted",
    )
    profile = legacy_local_profile()
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    build_calls: list[bool] = []

    def build(*args, **kwargs):
        build_calls.append(True)
        return _Process(ProcessResult(0, "ok", ""))

    backend.build_exec_process = build
    result = run_worker_process(
        backend, str(tmp_path), _worker(), ["mock"], phase="explore_execute",
        timeout_seconds=30, client=client, run_envelope=run,
        worker_manifest=manifest,
        execution_request=_execution_request(run, manifest.manifest_digest, profile),
        sandbox_profile=profile,
    )
    assert result.stdout == "ok"
    assert build_calls == [True]
    assert client.transitions[-1].status == "succeeded"
    record = json.loads(next((tmp_path / ".linen-executions").glob("*.json")).read_text())
    assert record["execution_mode"] == "legacy-policy-gated"
    assert record["isolation"] == "unverified"


def test_untrusted_backend_cannot_self_assert_secure_capabilities(tmp_path) -> None:
    client = _PolicyClient()
    manifest, run = build_execution_contracts(
        _project(), _worker(), "explore_execute", intent_id="i1",
        timeout_seconds=30, prompt="trusted",
    )
    profile = SandboxProfile()
    fake = _PolicyBackend(
        ProcessResult(0, "must not run", ""),
        BackendCapabilities(
            backend_name="docker", filesystem_isolation=True,
            network_isolation=True, control_tool_split=True,
            credential_filtering=True, resource_limits=True,
            repo_access=["read-only"], workspace_access=["read-write"],
            control_channels=["configured_provider"], tool_channels=["deny"],
        ),
    )
    with pytest.raises(ExecutionPolicyDenied, match="unknown_capabilities"):
        run_worker_process(
            fake, str(tmp_path), _worker(), ["mock"], phase="explore_execute",
            timeout_seconds=30, client=client, run_envelope=run,
            worker_manifest=manifest,
            execution_request=_execution_request(run, manifest.manifest_digest, profile),
            sandbox_profile=profile,
        )
    assert fake.build_calls == 0
