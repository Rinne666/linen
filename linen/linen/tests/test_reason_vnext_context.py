from __future__ import annotations

import json
from pathlib import Path

from linen.contracts import (
    ArtifactMetadata,
    BlackboardSnapshot,
    ContextProjection,
    ContextRequest,
    RunEnvelope,
)
from linen.dispatcher.contracts import validate_reason_payload
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks import reason
from linen.dispatcher.tasks.common import (
    expand_context_projection,
    prepare_context_projection,
)
from linen.dispatcher.tasks.reason import _reason_contracts
from linen.server.models import AuditEvent, Fact, GraphEdge, Intent, ProofPayload

from conftest import (
    FakeClient,
    FakeContainerManager,
    FakeDriver,
    FakeLease,
    make_config,
    make_intent,
    make_project,
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


class _SequenceDriver(FakeDriver):
    def __init__(self) -> None:
        super().__init__()
        self.sessions: list[str] = []

    def prepare_session(self) -> str:
        session = f"session-{len(self.sessions) + 1}"
        self.sessions.append(session)
        return session


class _Backend(FakeContainerManager):
    def __init__(self, root: Path, result: ProcessResult):
        super().__init__()
        self.root = root
        self.result = result

    def ensure_running(self, project_id: str) -> str:
        return str(self.root)

    def build_exec_process(self, container_name, env, command, timeout_seconds=None, kill_after_seconds=5):
        return _Process(self.result)

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        if path.startswith("/tmp/linen-prompts/"):
            self.writes.append((container_name, path, content))
            return
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


class _ContractClient(FakeClient):
    def __init__(self, project, *, register_status: int = 201):
        super().__init__(project)
        self.register_status = register_status
        self.snapshots: list[BlackboardSnapshot] = []
        self.projections: list[ContextProjection] = []
        self.runs: list[RunEnvelope] = []
        self.transitions: list[RunEnvelope] = []

    def get_snapshot(self, _project_id: str) -> BlackboardSnapshot:
        from linen.dispatcher.contract_adapters import project_detail_to_snapshot

        snapshot = project_detail_to_snapshot(self.project, created_at="2026-01-01T00:00:00Z")
        self.snapshots.append(snapshot)
        return snapshot

    def register_context_projection(self, projection: ContextProjection):
        if self.register_status != 201:
            return ApiResult(self.register_status, text="context unavailable")
        self.projections.append(projection)
        return projection

    def register_run(self, run: RunEnvelope):
        self.runs.append(run)
        return run

    def transition_run(self, run: RunEnvelope):
        self.transitions.append(run)
        return run


class _CatalogClient(_ContractClient):
    def __init__(self, project, *, artifacts=None, fail_catalog: bool = False, register_status: int = 201):
        super().__init__(project, register_status=register_status)
        self.artifacts = list(artifacts or [])
        self.fail_catalog = fail_catalog
        self.catalog_calls = 0
        self.events: list[str] = []

    def list_artifacts(self, _project_id: str) -> list[ArtifactMetadata]:
        self.events.append("catalog")
        self.catalog_calls += 1
        if self.fail_catalog:
            raise RuntimeError("catalog unavailable")
        return self.artifacts

    def get_snapshot(self, project_id: str) -> BlackboardSnapshot:
        self.events.append("snapshot")
        return super().get_snapshot(project_id)

    def register_context_projection(self, projection: ContextProjection):
        self.events.append("register")
        return super().register_context_projection(projection)


def _registered_source_artifact(project_id: str = "p001") -> ArtifactMetadata:
    return ArtifactMetadata(
        artifact_id="artifact-source-f001",
        project_id=project_id,
        kind="evidence",
        workspace_path="artifacts/source-f001.json",
        sha256="a" * 64,
        media_type="application/json",
        byte_size=12,
        related_node_ids=["f001"],
    )


def _project_with_edge():
    project = make_project()
    return project.model_copy(update={
        "edges": [GraphEdge(
            id="edge-origin-goal",
            source_kind="fact",
            source_id="f001",
            target_kind="fact",
            target_id="goal",
            relation_type="supports",
            created_at="2026-01-01T00:00:03Z",
            created_by="dispatcher",
        )],
    })


def _project_with_two_edges():
    project = _project_with_edge()
    second_fact = project.facts[0].model_copy(update={
        "id": "f002",
        "description": "second connected fact",
    })
    return project.model_copy(update={
        "facts": [*project.facts, second_fact],
        "edges": [*project.edges, GraphEdge(
            id="edge-goal-f002",
            source_kind="fact",
            source_id="goal",
            target_kind="fact",
            target_id="f002",
            relation_type="supports",
            created_at="2026-01-01T00:00:04Z",
            created_by="dispatcher",
        )],
    })


def test_reason_uses_registered_projection_and_vnext_execution_record(tmp_path, monkeypatch) -> None:
    config = make_config()
    project = _project_with_edge()
    client = _ContractClient(project)
    backend = _Backend(
        tmp_path,
        ProcessResult(
            0,
            '{"accepted":true,"data":{"intents":[{"from":["f001"],'
            '"action":"inspect","target":"next","description":"next"}]}}',
            "",
        ),
    )
    driver = FakeDriver()
    lease = FakeLease()
    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)

    full_export = "FULL-EXPORT-MUST-NOT-REACH-WORKER"
    assert reason.run_reason_task(
        config, client, backend, project, full_export, config.workers[0],
        reason.TaskCancellation(), lease_id="lease-1",
    ) == "success"

    assert len(client.snapshots) == 1
    assert len(client.projections) == 1
    projection = client.projections[0]
    assert projection.context["degraded"] is False
    assert len(client.runs) == 1
    assert client.runs[0].status == "running"
    assert client.transitions[0].status == "succeeded"
    assert full_export not in driver.execute_prompts[0]
    assert "/context.json" in driver.execute_prompts[0]
    context_write = next(content for _, path, content in backend.writes if path.endswith("/context.json"))
    assert full_export not in context_write
    assert json.loads(context_write)["identity"]["projection_id"] == projection.projection_id
    record = next((tmp_path / ".linen-executions").glob("*.json"))
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 4
    assert payload["run_id"] == client.runs[0].run_id
    assert payload["context_projection_id"] == projection.projection_id


def test_reason_projection_includes_registered_related_artifacts(tmp_path) -> None:
    project = _project_with_edge()
    artifact = _registered_source_artifact(project.project.id)
    client = _CatalogClient(project, artifacts=[artifact])

    projection = prepare_context_projection(
        client,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
    )

    assert projection is not None
    assert client.catalog_calls == 1
    assert projection.artifact_ids == [artifact.artifact_id]
    assert projection.context["artifacts"] == [artifact.model_dump(mode="json")]


def test_reason_projection_catalog_failure_is_explicit_and_retryable(tmp_path, caplog) -> None:
    project = _project_with_edge()
    client = _CatalogClient(project, fail_catalog=True)

    projection = prepare_context_projection(
        client,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
    )

    assert projection is None
    assert client.catalog_calls == 1
    assert "artifact catalog fetch/validation failed" in caplog.text
    assert "catalog unavailable" in caplog.text


def test_expand_projection_refreshes_catalog_before_registering_bounded_context(tmp_path) -> None:
    project = _project_with_two_edges()
    client = _CatalogClient(project)
    initial = prepare_context_projection(
        client,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
    )
    assert initial is not None

    client.events.clear()
    expanded = expand_context_projection(
        client,
        initial,
        ContextRequest(
            node_ids=["f002"],
            relation_types=["supports"],
            reason="need the connected fact",
        ),
    )

    assert expanded is not None
    assert "f002" in expanded.node_ids
    assert "edge-goal-f002" in expanded.edge_ids
    assert client.events == ["snapshot", "catalog", "register"]


def test_expand_projection_rejects_stale_or_invalid_requests_without_registration(tmp_path, caplog) -> None:
    project = _project_with_two_edges()
    artifact_one = _registered_source_artifact(project.project.id)
    artifact_two = artifact_one.model_copy(update={
        "artifact_id": "artifact-second-f002",
        "workspace_path": "artifacts/second-f002.json",
        "related_node_ids": ["f002"],
    })
    client = _CatalogClient(project, artifacts=[artifact_one, artifact_two])
    initial = prepare_context_projection(
        client,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
    )
    assert initial is not None

    client.events.clear()
    stale = initial.model_copy(update={"graph_revision": initial.graph_revision + 1})
    assert expand_context_projection(
        client,
        stale,
        ContextRequest(node_ids=["f002"], reason="stale request"),
    ) is None
    assert client.events == ["snapshot", "catalog"]
    assert "expansion fetch/validation failed" in caplog.text

    client.events.clear()
    assert expand_context_projection(
        client,
        initial,
        ContextRequest(node_ids=["does-not-exist"], reason="invalid request"),
    ) is None
    assert client.events == ["snapshot", "catalog"]

    client.events.clear()
    assert expand_context_projection(
        client,
        initial,
        ContextRequest(
            artifact_ids=[artifact_one.artifact_id, artifact_two.artifact_id],
            reason="too many artifacts",
        ),
        max_artifacts=1,
    ) is None
    assert client.events == ["snapshot", "catalog"]

    client.register_status = 503
    client.events.clear()
    assert expand_context_projection(
        client,
        initial,
        ContextRequest(node_ids=["f002"], reason="registration failure"),
    ) is None
    assert client.events == ["snapshot", "catalog", "register"]
    assert "expansion registration failed" in caplog.text


def test_projection_registration_failure_is_retryable_and_legacy_is_explicit(tmp_path, caplog) -> None:
    project = _project_with_edge()
    failing = _ContractClient(project, register_status=503)
    assert prepare_context_projection(
        failing,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
        current_graph_revision=project.project.graph_revision,
    ) is None
    assert "registration failed" in caplog.text

    legacy = FakeClient(project)
    projection = prepare_context_projection(
        legacy,
        FakeContainerManager(),
        project,
        str(tmp_path),
        seed_ids=["f001"],
        phase="reason_execute",
        current_graph_revision=project.project.graph_revision,
    )
    assert projection is not None
    assert projection.context["degraded"] is True
    assert "unpersisted" in caplog.text


def test_reason_identity_is_stable_for_trigger_attempt_and_prompt_digest_changes() -> None:
    project = _project_with_edge()
    client = _ContractClient(project)
    projection = prepare_context_projection(
        client,
        FakeContainerManager(),
        project,
        "/tmp/reason-contract-test",
        seed_ids=["f001"],
        phase="reason_execute",
    )
    assert projection is not None
    worker = make_config().workers[0]
    first_manifest, first_run = _reason_contracts(
        project, worker, projection,
        phase="reason_execute", timeout_seconds=10, trigger="manual", attempt=2,
        prompt="prompt-a",
    )
    second_manifest, second_run = _reason_contracts(
        project, worker, projection,
        phase="reason_execute", timeout_seconds=10, trigger="manual", attempt=2,
        prompt="prompt-a",
    )
    changed_manifest, changed_run = _reason_contracts(
        project, worker, projection,
        phase="reason_execute", timeout_seconds=10, trigger="manual", attempt=2,
        prompt="prompt-b",
    )
    other_trigger_manifest, other_trigger_run = _reason_contracts(
        project, worker, projection,
        phase="reason_execute", timeout_seconds=10, trigger="operator", attempt=2,
        prompt="prompt-a",
    )
    assert first_run.run_id == second_run.run_id
    assert first_run.idempotency_key == second_run.idempotency_key
    assert first_manifest.recipe.digest == second_manifest.recipe.digest
    assert changed_manifest.recipe.digest != first_manifest.recipe.digest
    assert changed_run.run_id == first_run.run_id
    assert other_trigger_run.run_id != first_run.run_id


def test_reason_context_required_runs_one_cold_continuation_without_writing_before_validation(tmp_path, monkeypatch) -> None:
    project = _project_with_two_edges()
    client = _CatalogClient(project)
    backend = FakeContainerManager()
    driver = _SequenceDriver()
    lease = FakeLease()
    calls = []
    results = iter([
        ProcessResult(
            0,
            '{"accepted":true,"data":{"status":"context_required",'
            '"context_request":{"node_ids":["f002"],"relation_types":["supports"],'
            '"reason":"need connected fact"}}}',
            "",
        ),
        ProcessResult(
            0,
            '{"accepted":true,"data":{"intents":[{"from":["f001"],'
            '"action":"inspect","target":"final-continuation",'
            '"description":"final continuation intent"}]}}',
            "",
        ),
    ])

    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)

    def run_process(*_args, **kwargs):
        calls.append(kwargs)
        return next(results)

    monkeypatch.setattr(reason, "run_worker_process", run_process)
    outcome = reason.run_reason_task(
        make_config(), client, backend, project, "FULL-EXPORT", make_config().workers[0],
        reason.TaskCancellation(), trigger="manual", attempt=3,
    )

    assert outcome == "success"
    assert client.created_intents == [(
        "proj_001", ["f001"], "final continuation intent", "test-worker",
    )]
    assert len(calls) == 2
    assert [call["phase"] for call in calls] == [
        "reason_execute", "reason_context_continuation",
    ]
    assert calls[0]["run_envelope"].run_id != calls[1]["run_envelope"].run_id
    assert calls[0]["run_envelope"].attempt == calls[1]["run_envelope"].attempt == 3
    assert "scope=reason_context_continuation:initial-run-" in calls[1]["run_envelope"].idempotency_key
    assert driver.sessions == ["session-1", "session-2"]
    assert "FULL-EXPORT" not in driver.execute_prompts[1]
    assert "context_required" in driver.execute_prompts[1]
    expanded_context = [
        json.loads(content) for _, path, content in backend.writes
        if path.startswith("/tmp/linen-prompts/reason_context_continuation-")
    ][0]
    assert "f002" in expanded_context["identity"]["node_ids"]


def test_reason_context_continuation_preserves_rate_limited_provider_status(tmp_path, monkeypatch) -> None:
    project = _project_with_two_edges()
    client = _CatalogClient(project)
    backend = FakeContainerManager()
    driver = _SequenceDriver()
    lease = FakeLease()
    results = iter([
        ProcessResult(
            0,
            '{"accepted":true,"data":{"status":"context_required",'
            '"context_request":{"node_ids":["f002"],"reason":"need connected fact"}}}',
            "",
        ),
        ProcessResult(0, '{"error":{"message":"rate limit"}}', ""),
    ])
    calls = []
    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)
    monkeypatch.setattr(
        reason,
        "run_worker_process",
        lambda *_args, **kwargs: (calls.append(kwargs) or next(results)),
    )

    assert reason.run_reason_task(
        make_config(), client, backend, project, "FULL-EXPORT", make_config().workers[0],
        reason.TaskCancellation(),
    ) == "rate_limited"
    assert len(calls) == 2
    assert client.created_intents == []


def test_reason_context_continuation_rejects_second_request_and_does_not_write_blackboard(tmp_path, monkeypatch) -> None:
    project = _project_with_two_edges()
    client = _CatalogClient(project)
    backend = FakeContainerManager()
    driver = _SequenceDriver()
    lease = FakeLease()
    results = iter([
        ProcessResult(
            0,
            '{"accepted":true,"data":{"status":"context_required",'
            '"context_request":{"node_ids":["f002"],"reason":"first request"}}}',
            "",
        ),
        ProcessResult(
            0,
            '{"accepted":true,"data":{"status":"context_required",'
            '"context_request":{"node_ids":["f001"],"reason":"second request"}}}',
            "",
        ),
    ])
    calls = []
    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)
    monkeypatch.setattr(
        reason,
        "run_worker_process",
        lambda *_args, **kwargs: (calls.append(kwargs) or next(results)),
    )

    assert reason.run_reason_task(
        make_config(), client, backend, project, "FULL-EXPORT", make_config().workers[0],
        reason.TaskCancellation(),
    ) == "failed"
    assert len(calls) == 2
    assert client.created_intents == []


def test_reason_context_continuation_stale_snapshot_is_controlled_failure(tmp_path, monkeypatch) -> None:
    project = _project_with_two_edges()
    client = _CatalogClient(project)
    backend = FakeContainerManager()
    driver = _SequenceDriver()
    lease = FakeLease()
    calls = []
    original_get_snapshot = client.get_snapshot
    snapshot_calls = 0

    def stale_after_initial(project_id: str):
        nonlocal snapshot_calls
        snapshot = original_get_snapshot(project_id)
        snapshot_calls += 1
        if snapshot_calls > 1:
            snapshot = snapshot.model_copy(update={"graph_revision": snapshot.graph_revision + 1})
        return snapshot

    client.get_snapshot = stale_after_initial
    results = iter([
        ProcessResult(
            0,
            '{"accepted":true,"data":{"status":"context_required",'
            '"context_request":{"node_ids":["f002"],"reason":"stale expansion"}}}',
            "",
        ),
    ])
    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)
    monkeypatch.setattr(
        reason,
        "run_worker_process",
        lambda *_args, **kwargs: (calls.append(kwargs) or next(results)),
    )

    assert reason.run_reason_task(
        make_config(), client, backend, project, "FULL-EXPORT", make_config().workers[0],
        reason.TaskCancellation(),
    ) == "failed"
    assert len(calls) == 1
    assert client.created_intents == []


def test_reason_prompt_filters_open_intents_to_projected_frontier(monkeypatch) -> None:
    project = make_project(intents=[make_intent(f"i{index:03d}") for index in range(40)])
    client = FakeClient(project)
    backend = FakeContainerManager()
    driver = FakeDriver()
    lease = FakeLease()
    monkeypatch.setattr(reason, "get_driver", lambda *_a, **_k: driver)
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *_a, **_k: lease)
    monkeypatch.setattr(
        reason,
        "run_worker_process",
        lambda *_args, **_kwargs: ProcessResult(0, '{"accepted":true,"data":{}}', ""),
    )

    assert reason.run_reason_task(
        make_config(), client, backend, project, "FULL-EXPORT", make_config().workers[0],
        reason.TaskCancellation(), lease_id="lease-filter",
    ) == "success"
    prompt = driver.execute_prompts[0]
    assert "i000" in prompt
    assert "i039" not in prompt
    assert '"i039"' not in prompt


def test_triggering_root_cause_fact_precedes_open_intents_without_more_seeds() -> None:
    project = make_project(intents=[make_intent("i001")])
    project.facts.extend([
        Fact(id="f010", description="HTTP session accepts a caller-controlled role", type="source"),
        Fact(
            id="f011",
            description="Root cause: role is persisted without an authorization invariant",
            type="vulnerability",
            semantic_type="candidate_finding",
            proof=ProofPayload(
                claim_kind="vulnerability_trace",
                attributes={"trace": [{"kind": "state_write", "symbol": "Session.role"}]},
            ),
        ),
    ])
    producer = Intent(
        id="i010", from_=["f010"], description="Trace role storage", creator="explore",
        worker="test-worker", created_at="2026-01-01T00:00:03Z", to="f011",
        concluded_at="2026-01-01T00:00:04Z",
    )
    project.intents.append(producer)
    event = AuditEvent(
        sequence=12, event_type="audit_task_concluded", actor="local-pi",
        entity_kind="intent", entity_id="i010", payload={"fact_id": "f011"},
        created_at="2026-01-01T00:00:04Z",
    )

    seeds = reason._reason_frontier_seed_ids(project, trigger_events=[event])

    assert seeds[:3] == ["f011", "i010", "f010"]
    assert seeds.index("f011") < seeds.index("i001")
    assert len(seeds) <= reason.REASON_SEED_BUDGET
    projection = reason._prepare_reason_contracts(
        _ContractClient(project), FakeContainerManager(), project, "/tmp/reason-context",
        phase="reason_execute", trigger_events=[event],
    )
    assert projection is not None
    assert projection.node_ids.index("f011") < projection.node_ids.index("i001")
    root_cause_node = next(node for node in projection.context["nodes"] if node["id"] == "f011")
    assert "Root cause" in root_cause_node["payload"]["description"]
    intent_kind, sibling_intents = validate_reason_payload({
        "accepted": True,
        "data": {"intents": [{
            "from": ["f011"], "action": "search", "target": "sibling endpoint",
            "type": "search", "description": "Check sibling endpoints for the same role invariant",
        }]},
    }, open_intents_empty=False, max_intents=make_config().tasks.reason.max_intents)
    assert intent_kind == "intents"
    assert sibling_intents[0]["type"] == "search"
