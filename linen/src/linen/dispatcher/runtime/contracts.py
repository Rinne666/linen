"""Dispatcher-side construction of vNext execution contracts.

These helpers describe an execution boundary; they do not perform capability
resolution or policy evaluation.  Those decisions belong to the later
Capability Registry and Policy Gate phases.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import uuid
from typing import Any

from linen.contracts import RecipeRef, RunEnvelope, WorkerManifest
from linen.contracts.common import canonical_digest
from linen.dispatcher.config import WorkerConfig
from linen.server.models import ProjectDetail


# This namespace is part of the dispatcher identity contract.  Never replace it
# with uuid4: rebuilding the same logical attempt must address the same server
# run record.
RUN_ID_NAMESPACE = uuid.UUID("6f4e6f5e-5f2a-4fc5-9cb4-8f65cbe8fd7d")


def _project_meta(project: ProjectDetail | Any) -> Any:
    return getattr(project, "project", project)


def _logical_scope(
    phase: str,
    intent_id: str | None,
    logical_scope: str | None,
) -> str:
    value = logical_scope or (f"intent:{intent_id}" if intent_id else f"task:{phase}")
    value = str(value).strip()
    if not value:
        raise ValueError("logical_scope must not be empty")
    return value


def _idempotency_key(
    project: Any,
    phase: str,
    *,
    attempt: int,
    intent_id: str | None,
    logical_scope: str | None,
) -> str:
    phase = str(phase).strip()
    if not phase:
        raise ValueError("phase must not be empty")
    intent_id = str(intent_id).strip() if intent_id is not None else None
    scope = _logical_scope(phase, intent_id, logical_scope)
    # Keep the key inspectable for server logs while including every revision
    # dimension that can change the meaning of an attempt.  Intent is retained
    # even when a caller supplies a broader logical scope so changing intent
    # can never alias an earlier run.
    return ":".join((
        f"project={meta_value(project, 'id')}",
        f"intent={intent_id or '-'}",
        f"scope={scope}",
        f"phase={phase}",
        f"source_generation={meta_value(project, 'source_generation')}",
        f"plan_revision={meta_value(project, 'plan_revision')}",
        f"graph_revision={meta_value(project, 'graph_revision')}",
        f"attempt={attempt}",
    ))


def meta_value(project: Any, field: str) -> Any:
    """Read a project revision from either ProjectDetail or ProjectMeta."""
    return getattr(_project_meta(project), field)


def _derived_run_id(idempotency_key: str) -> str:
    return f"run-{uuid.uuid5(RUN_ID_NAMESPACE, idempotency_key).hex}"


def _validate_manifest_identity(
    manifest: WorkerManifest,
    *,
    project_id: str,
    intent_id: str | None,
    run_id: str,
) -> None:
    checks = (
        ("project_id", manifest.project_id, project_id),
        ("intent_id", manifest.intent_id, intent_id),
        ("run_id", manifest.run_id, run_id),
    )
    for field, actual, expected in checks:
        if actual is not None and actual != expected:
            raise ValueError(
                f"worker manifest {field}={actual!r} does not match envelope {expected!r}"
            )


def _recipe_metadata(
    *,
    phase: str,
    recipe_id: str | None,
    recipe_version: int | str | None,
    recipe_label: str | None,
    prompt: str | None,
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": recipe_id or f"phase.{phase}",
        "version": recipe_version,
        "label": recipe_label,
        "phase": phase,
    }
    if prompt is not None:
        value["prompt_sha256"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    if metadata:
        value["metadata"] = dict(metadata)
    return value


def recipe_digest(
    phase: str,
    *,
    recipe_id: str | None = None,
    recipe_version: int | str | None = None,
    recipe_label: str | None = None,
    prompt: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    """Return a stable content digest for trusted recipe metadata.

    Prompt contents are represented by a hash rather than persisted in the
    manifest.  Mapping keys are canonicalized by the contracts helper, so
    equivalent metadata has the same digest.
    """
    return f"sha256:{canonical_digest(_recipe_metadata(
        phase=phase,
        recipe_id=recipe_id,
        recipe_version=recipe_version,
        recipe_label=recipe_label,
        prompt=prompt,
        metadata=metadata,
    ))}"


def build_worker_manifest(
    project: ProjectDetail | Any,
    worker: WorkerConfig | Any,
    phase: str,
    *,
    recipe_id: str | None = None,
    recipe_version: int | str | None = None,
    recipe_label: str | None = None,
    prompt: str | None = None,
    recipe_metadata: Mapping[str, Any] | None = None,
    intent_id: str | None = None,
    run_id: str | None = None,
) -> WorkerManifest:
    """Build a descriptive, immutable manifest for one dispatcher attempt.

    Phase 1 intentionally leaves capabilities, tools, and permissions empty:
    populating those fields would claim Phase 4 Policy Gate authority that is
    not yet implemented.
    """
    meta = _project_meta(project)
    return WorkerManifest(
        runtime=str(worker.type),
        project_id=str(meta.id),
        intent_id=intent_id,
        run_id=run_id,
        recipe=RecipeRef(
            id=recipe_id or f"phase.{phase}",
            digest=recipe_digest(
                phase,
                recipe_id=recipe_id,
                recipe_version=recipe_version,
                recipe_label=recipe_label,
                prompt=prompt,
                metadata=recipe_metadata,
            ),
        ),
        required_capabilities=[],
        permissions={},
    )


def build_run_envelope(
    project: ProjectDetail | Any,
    worker: WorkerConfig | Any,
    phase: str,
    *,
    timeout_seconds: int,
    attempt: int = 1,
    intent_id: str | None = None,
    logical_scope: str | None = None,
    context_projection_id: str | None = None,
    worker_manifest: WorkerManifest | None = None,
    run_id: str | None = None,
    recipe_id: str | None = None,
    recipe_version: int | str | None = None,
    recipe_label: str | None = None,
    prompt: str | None = None,
    recipe_metadata: Mapping[str, Any] | None = None,
) -> RunEnvelope:
    """Construct the stable identity and bounds for one execution attempt."""
    if attempt < 1:
        raise ValueError("attempt must be at least 1")
    intent_id = str(intent_id).strip() if intent_id is not None else None
    intent_id = intent_id or None
    run_id = str(run_id).strip() if run_id is not None else None
    run_id = run_id or None
    meta = _project_meta(project)
    idempotency_key = _idempotency_key(
        project,
        phase,
        attempt=attempt,
        intent_id=intent_id,
        logical_scope=logical_scope,
    )
    # A manifest carrying an explicit run identity is itself an explicit
    # caller choice.  Otherwise derive the identity from the complete logical
    # key, making reconstruction of an attempt deterministic.
    resolved_run_id = run_id or (
        worker_manifest.run_id if worker_manifest is not None and worker_manifest.run_id else None
    ) or _derived_run_id(idempotency_key)
    manifest = worker_manifest or build_worker_manifest(
        project,
        worker,
        phase,
        recipe_id=recipe_id,
        recipe_version=recipe_version,
        recipe_label=recipe_label,
        prompt=prompt,
        recipe_metadata=recipe_metadata,
        intent_id=intent_id,
        run_id=resolved_run_id,
    )
    _validate_manifest_identity(
        manifest,
        project_id=str(meta.id),
        intent_id=intent_id,
        run_id=resolved_run_id,
    )
    return RunEnvelope(
        run_id=resolved_run_id,
        project_id=str(meta.id),
        intent_id=intent_id,
        task_type=phase,
        stage=phase,
        attempt=attempt,
        idempotency_key=idempotency_key,
        graph_revision=int(meta.graph_revision),
        source_generation=int(meta.source_generation),
        plan_revision=int(meta.plan_revision),
        context_projection_id=context_projection_id,
        worker_manifest_digest=manifest.manifest_digest,
        timeout_seconds=timeout_seconds,
        status="queued",
        worker_name=str(worker.name),
        worker_type=str(worker.type),
    )


def build_execution_contracts(
    project: ProjectDetail | Any,
    worker: WorkerConfig | Any,
    phase: str,
    **kwargs: Any,
) -> tuple[WorkerManifest, RunEnvelope]:
    """Build a manifest and envelope with one shared run identity."""
    kwargs = dict(kwargs)
    requested_run_id = kwargs.pop("run_id", None)
    supplied_manifest = kwargs.pop("worker_manifest", None)
    if supplied_manifest is not None and requested_run_id is None:
        requested_run_id = supplied_manifest.run_id

    # First construct the envelope so its deterministic run id can be used in
    # the manifest we create.  A supplied manifest is then checked by the
    # envelope builder for project/intent/run identity consistency.
    envelope = build_run_envelope(
        project,
        worker,
        phase,
        worker_manifest=supplied_manifest,
        run_id=requested_run_id,
        **kwargs,
    )
    if supplied_manifest is not None:
        return supplied_manifest, envelope

    manifest = build_worker_manifest(
        project,
        worker,
        phase,
        run_id=envelope.run_id,
        **{
            key: value for key, value in kwargs.items()
            if key in {
                "recipe_id", "recipe_version", "recipe_label", "prompt",
                "recipe_metadata", "intent_id",
            }
        },
    )
    envelope = build_run_envelope(
        project,
        worker,
        phase,
        worker_manifest=manifest,
        run_id=envelope.run_id,
        **kwargs,
    )
    return manifest, envelope


__all__ = [
    "build_execution_contracts",
    "build_run_envelope",
    "build_worker_manifest",
    "recipe_digest",
]
