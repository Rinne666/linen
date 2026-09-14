from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from linen.contracts import (
    ArtifactMetadata,
    AuditEventEnvelope,
    BlackboardSnapshot,
    ComponentRef,
    ComponentManifest,
    ContextProjection,
    ContextRequest,
    CredentialPolicy,
    EdgeEnvelope,
    ExecutionRequest,
    FilesystemPolicy,
    NetworkPolicy,
    NodeEnvelope,
    ProcessPolicy,
    RecipeRef,
    RunEnvelope,
    SandboxProfile,
    WorkerManifest,
)
from linen.contracts.common import canonical_digest, canonical_json


_DIGEST = "0" * 64
_NAMESPACED_DIGEST = f"sha256:{_DIGEST}"


def test_canonical_json_sorts_dicts_and_all_collections() -> None:
    left = {"z": ["b", "a"], "nested": {"two": 2, "one": 1}}
    right = {"nested": {"one": 1, "two": 2}, "z": ["b", "a"]}

    assert canonical_json(left) == canonical_json(right)
    assert canonical_digest(left) == canonical_digest(right)

    # Sequence order is semantic by default (for example, a call chain).
    assert canonical_digest(["source", "sink"]) != canonical_digest(["sink", "source"])


def test_snapshot_id_and_digest_are_stable_and_order_insensitive() -> None:
    node_a = NodeEnvelope(kind="fact", id="f001", payload={"description": "known"})
    node_b = NodeEnvelope(kind="fact", id="f002", payload={"description": "other"})
    edge = EdgeEnvelope(
        id="e001",
        source_kind="fact",
        source_id="f001",
        target_kind="fact",
        target_id="f002",
        relation_type="supports",
    )
    first = BlackboardSnapshot(
        project_id="p1",
        graph_revision=3,
        source_generation=1,
        plan_revision=2,
        nodes=[node_a, node_b],
        edges=[edge],
        created_at="2026-01-01T00:00:00Z",
    )
    second = BlackboardSnapshot(
        project_id="p1",
        graph_revision=3,
        source_generation=1,
        plan_revision=2,
        nodes=[node_b, node_a],
        edges=[edge],
        created_at="2026-01-01T00:00:00Z",
    )

    assert first.snapshot_id == second.snapshot_id
    assert first.snapshot_digest() == second.snapshot_digest()
    assert first.snapshot_id is not None
    assert first.snapshot_id.startswith("snap-")

    changed_timestamp = first.model_copy(update={"created_at": "2026-01-02T00:00:00Z"})
    assert changed_timestamp.snapshot_id == first.snapshot_id
    assert changed_timestamp.snapshot_digest() == first.snapshot_digest()
    assert changed_timestamp.canonical_digest() == first.canonical_digest()


def test_contracts_reject_unknown_fields_and_unsupported_versions() -> None:
    with pytest.raises(ValidationError):
        NodeEnvelope(kind="fact", id="f001", unknown=True)
    with pytest.raises(ValidationError):
        BlackboardSnapshot(
            schema_version=2,
            project_id="p1",
            graph_revision=0,
            source_generation=1,
            plan_revision=1,
            created_at="now",
        )


def test_snapshot_rejects_forged_snapshot_id() -> None:
    with pytest.raises(ValidationError, match="snapshot_id does not match"):
        BlackboardSnapshot(
            snapshot_id="snap-forged",
            project_id="p1",
            graph_revision=0,
            source_generation=1,
            plan_revision=1,
            created_at="now",
        )


def test_artifact_metadata_normalizes_hash_and_rejects_unsafe_paths() -> None:
    artifact = ArtifactMetadata(
        artifact_id="art-1",
        project_id="p1",
        kind="sarif",
        workspace_path=".linen-analysis/results.sarif",
        sha256=_DIGEST.upper(),
        media_type="application/sarif+json",
    )
    assert artifact.sha256 == _DIGEST

    for path in (
        "/tmp/results.sarif",
        "../results.sarif",
        "a/../../results.sarif",
        r"C:\\results.sarif",
        r"a\\..\\results.sarif",
    ):
        with pytest.raises(ValidationError):
            ArtifactMetadata(
                artifact_id="art-1",
                project_id="p1",
                kind="sarif",
                workspace_path=path,
                sha256=_DIGEST,
                media_type="application/sarif+json",
            )


def test_event_envelope_exposes_type_compatibility_and_run_identity() -> None:
    event = AuditEventEnvelope(
        event_id="evt-1",
        project_id="p1",
        run_id="run-1",
        event_type="worker.completed",
        actor="dispatcher",
        graph_revision=4,
        source_generation=1,
        plan_revision=1,
        created_at="2026-01-01T00:00:00Z",
    )
    assert event.type == "worker.completed"
    assert AuditEventEnvelope.model_validate(
        {
            "event_id": "evt-2",
            "project_id": "p1",
            "type": "fact.created",
            "actor": "dispatcher",
            "graph_revision": 5,
            "source_generation": 1,
            "plan_revision": 1,
            "created_at": "2026-01-01T00:00:00Z",
        }
    ).event_type == "fact.created"


@pytest.mark.parametrize("status", ["queued", "running", "completed", "succeeded", "failed", "cancelled", "timed_out", "interrupted", "blocked"])
def test_run_envelope_accepts_supported_statuses(status: str) -> None:
    run = RunEnvelope(
        run_id="run-1",
        project_id="p1",
        task_type="explore",
        attempt=1,
        idempotency_key="p1:i1:explore:1",
        graph_revision=0,
        source_generation=1,
        plan_revision=1,
        timeout_seconds=60,
        status=status,
    )
    assert run.status == status


def test_run_envelope_rejects_invalid_attempt_revision_and_digest() -> None:
    base = dict(
        run_id="run-1",
        project_id="p1",
        task_type="explore",
        idempotency_key="p1:i1:explore:1",
        graph_revision=0,
        source_generation=1,
        plan_revision=1,
        timeout_seconds=60,
    )
    with pytest.raises(ValidationError):
        RunEnvelope(**base, attempt=0)
    with pytest.raises(ValidationError):
        RunEnvelope(**base, attempt=1, worker_manifest_digest="bad")


def test_worker_manifest_is_frozen_and_digest_is_canonical() -> None:
    ref_a = ComponentRef(id="security.a", version="1", digest=_NAMESPACED_DIGEST)
    ref_b = ComponentRef(id="security.b", version="1", digest=_NAMESPACED_DIGEST)
    manifest = WorkerManifest(
        runtime="pi",
        intent_id="i1",
        recipe=RecipeRef(id="audit.verify", digest=_NAMESPACED_DIGEST),
        required_capabilities=["security.sast", "security.authz"],
        skills=[ref_a, ref_b],
        tools=["grep", "read"],
    )
    same = WorkerManifest(
        runtime="pi",
        intent_id="i1",
        recipe=RecipeRef(id="audit.verify", digest=_NAMESPACED_DIGEST),
        required_capabilities=["security.authz", "security.sast"],
        skills=[ref_b, ref_a],
        tools=["read", "grep"],
    )
    assert manifest.manifest_digest == same.manifest_digest
    assert manifest.canonical_digest() == same.canonical_digest()
    with pytest.raises(ValidationError):
        manifest.runtime = "codex"
    with pytest.raises(ValidationError):
        WorkerManifest(
            runtime="pi",
            recipe=RecipeRef(id="audit.verify", digest=_NAMESPACED_DIGEST),
            manifest_digest=_NAMESPACED_DIGEST,
        )


def test_contract_nested_collections_are_immutable_and_serializable() -> None:
    node = NodeEnvelope(
        kind="fact",
        id="f001",
        payload={"nested": [{"tags": {"security"}}]},
    )
    snapshot = BlackboardSnapshot(
        project_id="p1",
        graph_revision=0,
        source_generation=1,
        plan_revision=1,
        nodes=[node],
        created_at="now",
    )
    manifest = WorkerManifest(
        runtime="pi",
        recipe=RecipeRef(id="audit.verify", digest=_NAMESPACED_DIGEST),
        permissions={"repo.read": True},
        required_capabilities=["security.sast"],
    )
    projection = ContextProjection(
        projection_id="ctx-1",
        project_id="p1",
        snapshot_id=snapshot.snapshot_id,
        graph_revision=0,
        source_generation=1,
        plan_revision=1,
        context={"nodes": [{"id": "f001"}]},
        selection_policy="explicit",
        created_at="now",
    )
    artifact = ArtifactMetadata(
        artifact_id="a-1", project_id="p1", kind="report",
        workspace_path="report.json", sha256=_DIGEST, media_type="application/json",
        related_node_ids=["f001"],
    )
    run = RunEnvelope(
        run_id="run-1", project_id="p1", task_type="scan", attempt=1,
        idempotency_key="run-key", graph_revision=0, source_generation=1,
        plan_revision=1, timeout_seconds=30, artifact_ids=["a-1"],
    )
    event = AuditEventEnvelope(
        event_id="evt-1", project_id="p1", event_type="fact.created", actor="worker",
        graph_revision=0, source_generation=1, plan_revision=1,
        payload={"changes": [{"field": "status"}]}, created_at="now",
    )

    for collection, operation in (
        (node.payload, lambda: node.payload.__setitem__("new", True)),
        (node.payload["nested"], lambda: node.payload["nested"].append({})),
        (node.payload["nested"][0]["tags"], lambda: node.payload["nested"][0]["tags"].add("new")),
        (snapshot.nodes, lambda: snapshot.nodes.append(node)),
        (manifest.permissions, lambda: manifest.permissions.__setitem__("repo.write", True)),
        (manifest.required_capabilities, lambda: manifest.required_capabilities.append("new")),
        (projection.context["nodes"], lambda: projection.context["nodes"].append({})),
        (artifact.related_node_ids, lambda: artifact.related_node_ids.append("f002")),
        (run.artifact_ids, lambda: run.artifact_ids.append("a-2")),
        (event.payload["changes"], lambda: event.payload["changes"].append({})),
    ):
        with pytest.raises(TypeError):
            operation()
        assert collection == collection

    # Pydantic's JSON mode remains a normal JSON-compatible shape.
    assert json.loads(snapshot.model_dump_json())["nodes"][0]["payload"]["nested"][0]["tags"] == ["security"]
    assert json.loads(projection.model_dump_json())["context"]["nodes"] == [{"id": "f001"}]


def test_workspace_paths_reject_nul_and_control_characters() -> None:
    for path in ("reports\x00.json", "reports\n.json", "reports\x1b.json", "reports\x7f.json"):
        with pytest.raises(ValidationError, match="control characters"):
            ArtifactMetadata(
                artifact_id="art-1", project_id="p1", kind="report",
                workspace_path=path, sha256=_DIGEST, media_type="application/json",
            )


def test_component_and_context_contracts_are_closed_and_traceable() -> None:
    component = ComponentManifest(
        id="security.semgrep",
        kind="scanner",
        version="1",
        provides=["static-analysis.sarif", "security.sast"],
        required_permissions=["repo.read", "process.execute"],
    )
    component_reordered = component.model_copy(
        update={
            "provides": ["security.sast", "static-analysis.sarif"],
            "required_permissions": ["process.execute", "repo.read"],
        }
    )
    assert component.canonical_digest() == component_reordered.canonical_digest()
    request = ContextRequest(
        node_ids=["f001", "f002"],
        relation_types=["supports", "depends_on"],
        reason="need authorization evidence",
    )
    request_reordered = request.model_copy(
        update={
            "node_ids": ["f002", "f001"],
            "relation_types": ["depends_on", "supports"],
        }
    )
    assert request.canonical_digest() == request_reordered.canonical_digest()

    projection = ContextProjection(
        projection_id="ctx-1",
        project_id="p1",
        snapshot_id="snap-1",
        graph_revision=5,
        source_generation=1,
        plan_revision=1,
        intent_id="i1",
        stage="validate",
        node_ids=["f001", "f002"],
        edge_ids=["e001", "e002"],
        artifact_ids=["art-1", "art-2"],
        context={"components": [json.loads(component.model_dump_json())]},
        selection_policy="intent-neighborhood-v1",
        request=request,
        created_at="2026-01-01T00:00:00Z",
    )
    assert projection.request == request
    assert projection.context["components"][0]["id"] == "security.semgrep"
    projection_reordered = ContextProjection(
        **{
            **projection.model_dump(),
            "node_ids": ["f002", "f001"],
            "edge_ids": ["e002", "e001"],
            "artifact_ids": ["art-2", "art-1"],
            "created_at": "2026-01-02T00:00:00Z",
            "projection_digest": None,
        }
    )
    assert projection.projection_digest == projection_reordered.projection_digest


def test_sandbox_profile_is_deny_default_and_canonical() -> None:
    profile = SandboxProfile()
    assert profile.filesystem.repo == "read-only"
    assert profile.filesystem.workspace == "read-write"
    assert profile.network.control_channel == "configured_provider"
    assert profile.network.tool_channel == "deny"
    assert profile.credentials.allowed == []
    assert profile.profile_digest.startswith("sha256:")

    reordered = SandboxProfile(
        credentials=CredentialPolicy(allowed=["Z_TOKEN", "A_TOKEN"]),
        process=ProcessPolicy(timeout_seconds=120, memory_limit_mb=512),
    )
    same = SandboxProfile(
        credentials=CredentialPolicy(allowed=["A_TOKEN", "Z_TOKEN"]),
        process=ProcessPolicy(timeout_seconds=120, memory_limit_mb=512),
    )
    assert reordered.profile_digest == same.profile_digest
    with pytest.raises(ValidationError):
        profile.network.tool_channel = "allow"


def test_sandbox_policies_reject_invalid_resources_and_dangerous_fields() -> None:
    with pytest.raises(ValidationError):
        ProcessPolicy(timeout_seconds=0)
    with pytest.raises(ValidationError):
        ProcessPolicy(cpu_limit=-1)
    with pytest.raises(ValidationError):
        CredentialPolicy(allowed=["OPENAI_API_KEY", "openai_api_key"])
    for provider_name in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "PI_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    ):
        with pytest.raises(ValidationError):
            CredentialPolicy(allowed=[provider_name])
    assert CredentialPolicy(allowed=["SNYK_TOKEN"]).allowed == ["SNYK_TOKEN"]
    with pytest.raises(ValidationError):
        CredentialPolicy(allowed=["HOME"])
    with pytest.raises(ValidationError):
        SandboxProfile(api_key="secret")
    with pytest.raises(ValidationError):
        NetworkPolicy(tool_network="bridge")


def test_execution_request_is_secret_free_and_digest_addressable() -> None:
    request = ExecutionRequest(
        run_id="run-1",
        worker_manifest_digest=_NAMESPACED_DIGEST,
        sandbox_profile_digest=_NAMESPACED_DIGEST,
        attempt=1,
    )
    assert request.model_dump(mode="json")["worker_manifest_digest"] == _NAMESPACED_DIGEST
    with pytest.raises(ValidationError):
        ExecutionRequest(
            run_id="run-1",
            worker_manifest_digest="not-a-digest",
            sandbox_profile_digest=_NAMESPACED_DIGEST,
            attempt=1,
        )
    with pytest.raises(ValidationError):
        ExecutionRequest(
            run_id="run-1",
            worker_manifest_digest=_NAMESPACED_DIGEST,
            sandbox_profile_digest=_NAMESPACED_DIGEST,
            attempt=1,
            api_key="secret",
        )
def test_artifact_related_node_ids_are_unordered_for_contract_digest() -> None:
    first = ArtifactMetadata(
        artifact_id="art-1",
        project_id="p1",
        kind="json",
        workspace_path=".linen-analysis/results.json",
        sha256=_DIGEST,
        media_type="application/json",
        related_node_ids=["f001", "f002"],
    )
    second = first.model_copy(update={"related_node_ids": ["f002", "f001"]})
    assert first.canonical_digest() == second.canonical_digest()
