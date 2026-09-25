from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import logging
from pathlib import Path
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.contracts import (
    ArtifactMetadata,
    AuditEventEnvelope,
    BlackboardSnapshot,
    ContextProjection,
    ContextRequest,
    ExecutionRequest,
    RunEnvelope,
    SandboxProfile,
    WorkerManifest,
)
from linen.dispatcher.context import ContextProjector
from linen.dispatcher.runtime.contracts import (
    build_execution_contracts,
    recipe_digest as build_recipe_digest,
)
from linen.dispatcher.runtime.backend import ExecutionBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.runtime.policy import (
    BackendCapabilities,
    PolicyDecision,
    evaluate_execution,
)
from linen.server.models import Intent

PROCESS_COMMUNICATE_GRACE_SECONDS = 15
LOG_PREVIEW_LIMIT = 1200
GRAPH_SNAPSHOT_ROOT = "/tmp/linen-prompts"
LOG = logging.getLogger(__name__)


class DuplicateTerminalRun(RuntimeError):
    """The idempotent run already has a terminal server-owned result."""

    def __init__(self, run: RunEnvelope):
        self.run = run
        super().__init__(f"run {run.run_id} is already terminal ({run.status})")


class ExecutionPolicyDenied(RuntimeError):
    """A vNext execution was blocked before a process could be created."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(f"execution policy denied: {decision.reason}")


@dataclass(slots=True, frozen=True)
class ExecutionRecordResult:
    """Files emitted for one worker attempt, with their exact byte content."""

    record_path: str
    record_content: str
    prompt_path: str | None
    prompt_content: str | None
    stdout_path: str
    stdout_content: str
    stderr_path: str
    stderr_content: str


def write_context_projection_reference(
    backend: ExecutionBackend,
    project_handle: str,
    projection: ContextProjection,
    *,
    phase: str,
) -> str:
    """Write only projected context and identity for a worker reference.

    The source graph/export is deliberately absent.  A worker can read this
    immutable, bounded JSON reference but cannot use the prompt to obtain an
    implicit full-blackboard capability.
    """
    path = f"{GRAPH_SNAPSHOT_ROOT}/{phase}-{projection.projection_id}/context.json"
    payload = {
        "identity": projection.model_dump(mode="json", exclude={"context"}),
        "context": projection.context,
    }
    backend.write_text_file(
        project_handle,
        path,
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    return (
        "The bounded ContextProjection is stored in this file on the dispatcher host:\n\n"
        f"{path}\n\n"
        "Read only this projected context JSON. It is the complete context for this pass; "
        "do not infer or request the full blackboard."
    )


def append_context_projection_reference(prompt: str, reference: str) -> str:
    """Add a bounded context reference without corrupting JSON worker prompts.

    The mock driver (and a few embedders) use a JSON prompt envelope.  A raw
    markdown suffix would make that envelope invalid and hide regressions in
    the worker protocol.  Preserve JSON prompts as JSON; human-oriented
    prompts retain the readable reference text.
    """
    try:
        payload = json.loads(prompt)
    except (TypeError, json.JSONDecodeError):
        return prompt + "\n\n" + reference
    if not isinstance(payload, dict):
        return prompt + "\n\n" + reference
    payload["context_projection_reference"] = reference
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def _fetch_artifact_catalog(
    client: LinenClient,
    project_id: str,
    *,
    phase: str,
) -> list[ArtifactMetadata] | None:
    """Fetch and validate the immutable catalog when the client supports it.

    ``None`` means an older fake/client has no catalog API.  Once the method is
    present, however, every response is authoritative: malformed data,
    cross-project metadata, or a transport failure is a hard projection
    failure rather than a reason to widen context or silently omit artifacts.
    """
    list_artifacts = getattr(client, "list_artifacts", None)
    if not callable(list_artifacts):
        return None
    try:
        values = list_artifacts(project_id)
        if not isinstance(values, (list, tuple)):
            raise ValueError("list_artifacts must return a list")
        by_id: dict[str, ArtifactMetadata] = {}
        for value in values:
            artifact = value if isinstance(value, ArtifactMetadata) else ArtifactMetadata.model_validate(value)
            if artifact.project_id != project_id:
                raise ValueError(
                    f"artifact {artifact.artifact_id} belongs to another project"
                )
            previous = by_id.get(artifact.artifact_id)
            if previous is not None and previous != artifact:
                raise ValueError(
                    f"artifact catalog contains conflicting metadata for {artifact.artifact_id}"
                )
            by_id[artifact.artifact_id] = artifact
        return [by_id[artifact_id] for artifact_id in sorted(by_id)]
    except Exception as exc:
        LOG.error(
            "artifact catalog fetch/validation failed project=%s phase=%s error=%s",
            project_id, phase, exc,
        )
        raise


def expand_context_projection(
    client: LinenClient,
    current_projection: ContextProjection,
    request: ContextRequest,
    *,
    max_nodes: int = 60,
    max_artifacts: int = 20,
) -> ContextProjection | None:
    """Apply one bounded worker ContextRequest against a fresh server view.

    This helper deliberately has no retry or recursion semantics.  The
    caller may decide whether the returned projection should be used for a
    separate continuation attempt, but a failed refresh/validation/registration
    never widens context or falls back to a local full-graph view.
    """
    get_snapshot = getattr(client, "get_snapshot", None) or getattr(client, "snapshot", None)
    list_artifacts = getattr(client, "list_artifacts", None)
    register = (
        getattr(client, "register_context_projection", None)
        or getattr(client, "register_context", None)
    )
    if not all(callable(method) for method in (get_snapshot, list_artifacts, register)):
        LOG.error(
            "context projection expansion unavailable project=%s; fresh snapshot/catalog/registration are required",
            current_projection.project_id,
        )
        return None

    try:
        snapshot = get_snapshot(current_projection.project_id)
        if not isinstance(snapshot, BlackboardSnapshot):
            snapshot = BlackboardSnapshot.model_validate(snapshot)
        artifact_catalog = _fetch_artifact_catalog(
            client,
            current_projection.project_id,
            phase="context_expand",
        )
        if not isinstance(request, ContextRequest):
            request = ContextRequest.model_validate(request)
        projector = ContextProjector(
            max_nodes=max_nodes,
            max_artifacts=max_artifacts,
        )
        expanded = projector.expand(
            current_projection,
            snapshot,
            request,
            # Compare both the projection and the fresh snapshot against the
            # same revision.  This rejects stale continuations before any
            # expanded context can be registered.
            current_graph_revision=snapshot.graph_revision,
            artifact_catalog=artifact_catalog,
            max_artifacts=max_artifacts,
        )
    except Exception as exc:
        LOG.error(
            "context projection expansion fetch/validation failed project=%s projection=%s error=%s",
            current_projection.project_id,
            current_projection.projection_id,
            exc,
        )
        return None

    try:
        response = register(expanded)
        if hasattr(response, "ok") and not response.ok:
            LOG.error(
                "context projection expansion registration failed project=%s projection=%s status=%s body=%s",
                expanded.project_id,
                expanded.projection_id,
                getattr(response, "status_code", None),
                getattr(response, "text", ""),
            )
            return None
        return response if isinstance(response, ContextProjection) else expanded
    except Exception as exc:
        LOG.error(
            "context projection expansion registration raised project=%s projection=%s error=%s",
            expanded.project_id,
            expanded.projection_id,
            exc,
        )
        return None


def prepare_context_projection(
    client: LinenClient,
    backend: ExecutionBackend,
    project: object,
    project_handle: str,
    *,
    seed_ids: list[str],
    phase: str,
    stage: str | None = None,
    current_graph_revision: int | None = None,
    max_nodes: int = 60,
) -> ContextProjection | None:
    """Build and, when supported, persist one bounded ContextProjection.

    New protocol clients must obtain the server snapshot before projection and
    registration.  A client without both methods is an explicit legacy-local
    compatibility path: it projects the supplied ProjectDetail, marks it
    degraded, and leaves it unpersisted.  Protocol failures return ``None`` so
    callers can report a retryable task failure rather than widening context.
    """
    get_snapshot = getattr(client, "get_snapshot", None) or getattr(client, "snapshot", None)
    register = (
        getattr(client, "register_context_projection", None)
        or getattr(client, "register_context", None)
    )
    projector = ContextProjector(max_nodes=max_nodes)
    if callable(get_snapshot) and callable(register):
        try:
            snapshot = get_snapshot(project.project.id)
            if not isinstance(snapshot, BlackboardSnapshot):
                snapshot = BlackboardSnapshot.model_validate(snapshot)
        except Exception as exc:
            LOG.error(
                "context projection snapshot fetch failed project=%s phase=%s error=%s",
                project.project.id, phase, exc,
            )
            return None
        try:
            # This happens before the worker run is constructed/executed, so
            # artifacts produced by that run cannot leak into its own initial
            # projection.  The server catalog remains the authority.
            artifact_catalog = _fetch_artifact_catalog(
                client, project.project.id, phase=phase,
            )
            projection = projector.project_frontier(
                snapshot,
                seed_ids,
                stage=stage,
                degraded=not bool(snapshot.edges),
                # The just-fetched server snapshot is authoritative.  The
                # ProjectDetail held by the scheduler may predate a harmless
                # blackboard refresh that happened before this task started.
                current_graph_revision=None,
                artifact_catalog=artifact_catalog,
            )
        except Exception as exc:
            LOG.error(
                "context projection snapshot/build failed project=%s phase=%s error=%s",
                project.project.id, phase, exc,
            )
            return None
        try:
            response = register(projection)
            if hasattr(response, "ok") and not response.ok:
                LOG.error(
                    "context projection registration failed project=%s phase=%s projection=%s status=%s body=%s",
                    project.project.id,
                    phase,
                    projection.projection_id,
                    getattr(response, "status_code", None),
                    getattr(response, "text", ""),
                )
                return None
            if isinstance(response, ContextProjection):
                projection = response
            return projection
        except Exception as exc:
            LOG.error(
                "context projection registration raised project=%s phase=%s projection=%s error=%s",
                project.project.id, phase, projection.projection_id, exc,
            )
            return None

    LOG.warning(
        "using legacy-local degraded context projection project=%s phase=%s; projection is unpersisted",
        project.project.id, phase,
    )
    try:
        snapshot = projector.snapshot(project)
        # Legacy compatibility is deliberately seed-only even if a fake
        # happens to expose some edges.
        legacy_projector = ContextProjector(max_nodes=max_nodes, max_hops=0)
        return legacy_projector.project_frontier(
            snapshot,
            seed_ids,
            stage=stage,
            degraded=True,
            current_graph_revision=current_graph_revision,
        )
    except Exception as exc:
        LOG.error(
            "legacy-local context projection failed project=%s phase=%s error=%s",
            project.project.id, phase, exc,
        )
        return None


def prepare_intent_projection(
    client: LinenClient,
    project: object,
    *,
    intent_id: str,
    phase: str,
    current_graph_revision: int | None = None,
    max_nodes: int = 60,
) -> ContextProjection | None:
    """Prepare a projection rooted at one Intent for an LLM worker.

    A complete protocol client always uses its canonical server snapshot.  A
    legacy fake has no snapshot/registration authority, so it receives only a
    local, explicitly degraded seed-only projection.
    """
    get_snapshot = getattr(client, "get_snapshot", None) or getattr(client, "snapshot", None)
    register = (
        getattr(client, "register_context_projection", None)
        or getattr(client, "register_context", None)
    )
    projector = ContextProjector(max_nodes=max_nodes)
    if callable(get_snapshot) and callable(register):
        try:
            snapshot = get_snapshot(project.project.id)
            if not isinstance(snapshot, BlackboardSnapshot):
                snapshot = BlackboardSnapshot.model_validate(snapshot)
        except Exception as exc:
            LOG.error(
                "intent context snapshot fetch failed project=%s intent=%s phase=%s error=%s",
                project.project.id, intent_id, phase, exc,
            )
            return None
        try:
            # Fetch before the run is built so this pass cannot include its own
            # not-yet-produced execution artifacts.
            artifact_catalog = _fetch_artifact_catalog(
                client, project.project.id, phase=phase,
            )
            projection = projector.project(
                snapshot,
                intent_id,
                degraded=not bool(snapshot.edges),
                current_graph_revision=None,
                artifact_catalog=artifact_catalog,
            )
            response = register(projection)
            if hasattr(response, "ok") and not response.ok:
                LOG.error(
                    "context projection registration failed project=%s phase=%s projection=%s status=%s body=%s",
                    project.project.id,
                    phase,
                    projection.projection_id,
                    getattr(response, "status_code", None),
                    getattr(response, "text", ""),
                )
                return None
            return response if isinstance(response, ContextProjection) else projection
        except Exception as exc:
            LOG.error(
                "intent context projection failed project=%s intent=%s phase=%s error=%s",
                project.project.id, intent_id, phase, exc,
            )
            return None

    LOG.warning(
        "using legacy-local degraded intent projection project=%s intent=%s phase=%s; projection is unpersisted",
        project.project.id, intent_id, phase,
    )
    try:
        # Legacy clients cannot refresh a canonical snapshot, so add only the
        # explicit seed intent to the local compatibility view.
        if not any(item.id == intent_id for item in project.intents):
            fact_ids = {item.id for item in project.facts}
            compatibility_intent = Intent(
                id=intent_id,
                from_=["origin"] if "origin" in fact_ids else [],
                description="dispatcher compatibility intent",
                creator="dispatcher",
                worker=None,
                created_at="1970-01-01T00:00:00Z",
            )
            project = project.model_copy(update={
                "intents": [*project.intents, compatibility_intent],
            })
        snapshot = projector.snapshot(project)
        # Legacy compatibility is deliberately seed-only even if a fake
        # happens to expose some edges.
        legacy_projector = ContextProjector(max_nodes=max_nodes, max_hops=0)
        return legacy_projector.project(
            snapshot,
            intent_id,
            degraded=True,
            current_graph_revision=current_graph_revision,
        )
    except Exception as exc:
        LOG.error(
            "legacy-local intent projection failed project=%s intent=%s phase=%s error=%s",
            project.project.id, intent_id, phase, exc,
        )
        return None


def build_context_execution_contracts(
    project: object,
    worker: WorkerConfig,
    projection: ContextProjection,
    *,
    phase: str,
    timeout_seconds: int,
    prompt: str,
    logical_scope: str,
    attempt: int = 1,
    intent_id: str | None = None,
    recipe_id: str | None = None,
    recipe_label: str | None = None,
    recipe_version: int | str | None = None,
) -> tuple[WorkerManifest, RunEnvelope]:
    """Build worker/run contracts from the final prompt and snapshot revision."""
    contract_project = project.model_copy(update={
        "project": project.project.model_copy(update={
            "graph_revision": projection.graph_revision,
            "source_generation": projection.source_generation,
            "plan_revision": projection.plan_revision,
        }),
    })
    return build_execution_contracts(
        contract_project,
        worker,
        phase,
        timeout_seconds=timeout_seconds,
        attempt=attempt,
        intent_id=intent_id,
        logical_scope=logical_scope,
        context_projection_id=projection.projection_id,
        recipe_id=recipe_id,
        recipe_label=recipe_label,
        recipe_version=recipe_version,
        prompt=prompt,
    )


@dataclass(slots=True)
class ConcludeWriteResult:
    status: str
    fact_id: str | None = None


def preview(text: str, limit: int = LOG_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def did_timeout(result: ProcessResult) -> bool:
    return not result.cancelled and (result.timed_out or result.returncode in (124, 137))


def classify_provider_failure(result: ProcessResult) -> str | None:
    """Classify explicit provider errors without scanning echoed prompt text.

    Pi emits JSONL event records and may exit with status 0 even when every
    provider attempt failed.  Its stdout also contains user/model text, so a
    broad substring check would let an audit target or prompt forge a cooldown.
    Only structured error fields are inspected; stderr is considered only for
    non-zero exits used by other worker CLIs.
    """
    messages: list[str] = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(event, dict):
            _collect_provider_errors(event, messages)
    if result.returncode != 0:
        if result.stderr:
            messages.append(result.stderr[-4000:])
        # Claude-style CLIs may emit a provider rejection as one plain-text
        # stdout line while reserving stderr for an SDK diagnostic.  Do not
        # scan arbitrary stdout (it can contain prompt/model text); accept
        # only explicit provider-error prefixes on a failed process.
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if re.match(r"^(?:api|provider|request)\s+error\s*:", stripped, re.IGNORECASE):
                messages.append(stripped[-4000:])

    normalized = "\n".join(messages).casefold()
    if not normalized:
        return None
    quota_markers = (
        "quota_exceeded",
        "insufficient_quota",
        "usage limit",
        "usage_limit",
        "token plan",
        "用量上限",
        "购买积分",
        "额度已用尽",
    )
    if any(marker in normalized for marker in quota_markers):
        return "quota_exhausted"
    rate_limit_markers = (
        "rate_limit",
        "rate limit",
        "too many requests",
        "http 429",
        "429 {",
    )
    if any(marker in normalized for marker in rate_limit_markers):
        return "rate_limited"
    if (
        "model is not supported when using codex with a chatgpt account" in normalized
        or "model is not supported for this account" in normalized
        or "unsupported model" in normalized
    ):
        return "cli_model_unsupported"
    if "unrecognized_model" in normalized or "unknown model" in normalized:
        return "cli_model_unrecognized"
    if any(marker in normalized for marker in (
        "authentication_error", "unauthorized", "invalid api key",
        "not logged in", "authentication required", "token expired",
    )):
        return "cli_auth_failed"
    if any(marker in normalized for marker in (
        "executable file not found", "command not found",
    )):
        return "cli_executable_missing"
    return None


def _collect_provider_errors(value: object, messages: list[str]) -> None:
    if not isinstance(value, dict):
        return
    for key in ("errorMessage", "finalError"):
        message = value.get(key)
        if isinstance(message, str):
            messages.append(message)
    error = value.get("error")
    if isinstance(error, str):
        messages.append(error)
    elif isinstance(error, dict):
        for key in ("type", "message", "code"):
            message = error.get(key)
            if isinstance(message, str):
                messages.append(message)
    message = value.get("message")
    if isinstance(message, dict):
        _collect_provider_errors(message, messages)
    nested_messages = value.get("messages")
    if isinstance(nested_messages, list):
        for nested in nested_messages:
            if isinstance(nested, dict):
                _collect_provider_errors(nested, messages)


def cancel_reason(result: ProcessResult, cancellation: TaskCancellation | None = None) -> str | None:
    if result.cancelled:
        return result.cancel_reason or "cancelled"
    if cancellation is not None:
        return cancellation.reason
    return None


def communicate_timeout(timeout_seconds: int, grace_seconds: int = PROCESS_COMMUNICATE_GRACE_SECONDS) -> int:
    return timeout_seconds + grace_seconds


def task_healthcheck_enabled(config: DispatchConfig) -> bool:
    return config.runtime.worker_healthcheck == "startup_and_task"


def write_graph_snapshot_reference(
    backend: ExecutionBackend,
    project_handle: str,
    graph_yaml: str,
    *,
    phase: str,
) -> str:
    path = f"{GRAPH_SNAPSHOT_ROOT}/{phase}-{uuid.uuid4().hex[:12]}/graph.yaml"
    backend.write_text_file(project_handle, path, graph_yaml)
    return (
        "The graph YAML snapshot is stored in this file on the dispatcher host:\n\n"
        f"{path}\n\n"
        "Before using the graph, read the entire file and treat its contents as the YAML snapshot "
        "for this Graph section."
    )


def _backend_capabilities(backend: ExecutionBackend) -> BackendCapabilities | None:
    """Read only a trusted backend adapter's typed capability declaration."""

    # Capability declarations are authority, not ordinary duck-typed data.
    # Only exact built-in adapter classes are trusted here; a plugin/fake that
    # merely implements ``capabilities()`` must not self-assert isolation.
    from linen.dispatcher.runtime.backend import LocalBackend
    from linen.dispatcher.runtime.docker_backend import DockerSandboxBackend

    if type(backend) not in {LocalBackend, DockerSandboxBackend}:
        return None
    getter = getattr(backend, "get_capabilities", None)
    if getter is None:
        getter = getattr(backend, "capabilities", None)
    if getter is None or not callable(getter):
        return None
    try:
        value = getter()
    except Exception as exc:
        LOG.error("backend capability query failed backend=%s error=%s", type(backend).__name__, exc)
        return None
    return value if isinstance(value, BackendCapabilities) else None


def _policy_denial(
    reason: str,
    *,
    run: RunEnvelope | None,
    profile: SandboxProfile | None,
    capabilities: BackendCapabilities | None,
) -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        reason=reason,
        profile_digest=profile.profile_digest if profile is not None else None,
        run_id=run.run_id if run is not None else None,
        backend_name=capabilities.backend_name if capabilities is not None else None,
    )


def _evaluate_worker_execution_policy(
    backend: ExecutionBackend,
    run: RunEnvelope | None,
    manifest: WorkerManifest | None,
    request: ExecutionRequest | None,
    profile: SandboxProfile | None,
) -> tuple[PolicyDecision, BackendCapabilities | None]:
    """Validate contract identity and then evaluate backend enforcement.

    Any missing or inconsistent contract becomes a denial.  This helper is
    deliberately side-effect-free so it can run before process construction.
    """

    capabilities = _backend_capabilities(backend)
    if request is None or profile is None:
        return _policy_denial(
            "execution_request_and_profile_required",
            run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    if run is None or manifest is None:
        return _policy_denial(
            "run_and_manifest_required",
            run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    if request.run_id != run.run_id:
        return _policy_denial(
            "run_id_mismatch", run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    if request.attempt != run.attempt:
        return _policy_denial(
            "attempt_mismatch", run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    if request.worker_manifest_digest != manifest.manifest_digest:
        return _policy_denial(
            "worker_manifest_digest_mismatch",
            run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    if request.sandbox_profile_digest != profile.profile_digest:
        return _policy_denial(
            "sandbox_profile_digest_mismatch",
            run=run, profile=profile, capabilities=capabilities,
        ), capabilities
    return evaluate_execution(profile, request, capabilities), capabilities


def _append_policy_denied_event(
    client: LinenClient | None,
    run: RunEnvelope | None,
    decision: PolicyDecision,
) -> None:
    """Best-effort append-only trace for a fail-closed policy decision."""

    if client is None or run is None:
        return
    append = getattr(client, "append_event", None)
    if append is None:
        return
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    event = AuditEventEnvelope(
        event_id=f"run-{run.run_id}-policy-denied",
        project_id=run.project_id,
        run_id=run.run_id,
        idempotency_key=f"run:{run.run_id}:policy-denied",
        event_type="execution_policy_denied",
        actor="dispatcher",
        entity_kind="run",
        entity_id=run.run_id,
        graph_revision=run.graph_revision,
        source_generation=run.source_generation,
        plan_revision=run.plan_revision,
        payload={
            "reason": decision.reason,
            "backend": decision.backend_name,
            "profile_digest": decision.profile_digest,
        },
        created_at=now,
    )
    try:
        append(event)
    except Exception as exc:
        LOG.error("policy denial event append failed run_id=%s error=%s", run.run_id, exc)


def run_worker_process(
    backend: ExecutionBackend,
    project_handle: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
    recipe_id: str | None = None,
    recipe_label: str | None = None,
    recipe_version: int | None = None,
    client: LinenClient | None = None,
    run_envelope: RunEnvelope | None = None,
    worker_manifest: WorkerManifest | None = None,
    context_projection_id: str | None = None,
    recipe_content_digest: str | None = None,
    recipe_digest: str | None = None,
    execution_request: ExecutionRequest | None = None,
    sandbox_profile: SandboxProfile | None = None,
) -> ProcessResult:
    effective_recipe_digest = recipe_content_digest or recipe_digest
    if (run_envelope is not None or worker_manifest is not None) and effective_recipe_digest is None:
        effective_recipe_digest = build_recipe_digest(
            phase,
            recipe_id=recipe_id,
            recipe_version=recipe_version,
            recipe_label=recipe_label,
        )
    contract_run = _start_contract_run(
        client,
        run_envelope,
        worker_manifest=worker_manifest,
        context_projection_id=context_projection_id,
    )
    LOG.info(
        "starting worker project=%s worker=%s phase=%s timeout=%ss",
        project_handle,
        worker.name,
        phase,
        timeout_seconds,
    )
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    process = None

    policy_decision: PolicyDecision | None = None
    backend_capabilities: BackendCapabilities | None = None

    def finalize(result: ProcessResult, *, terminal_status: str | None = None) -> None:
        """Persist/register evidence before publishing the terminal run."""
        record = _write_execution_record(
            backend,
            project_handle,
            worker,
            argv,
            phase,
            started_at,
            int((time.perf_counter() - started) * 1000),
            timeout_seconds,
            result,
            recipe_id=recipe_id,
            recipe_label=recipe_label,
            recipe_version=recipe_version,
            run_envelope=contract_run,
            worker_manifest=worker_manifest,
            recipe_content_digest=effective_recipe_digest,
            context_projection_id=context_projection_id,
            execution_request=execution_request,
            sandbox_profile=sandbox_profile,
            policy_decision=policy_decision,
            backend_capabilities=backend_capabilities,
        )
        artifact_ids = _register_execution_artifacts(
            client, contract_run, backend, project_handle, record,
        )
        terminal_run = (
            contract_run.model_copy(update={"artifact_ids": artifact_ids})
            if contract_run is not None
            else None
        )
        _finish_contract_run(client, terminal_run, result, status_override=terminal_status)

    try:
        if execution_request is not None or sandbox_profile is not None:
            policy_decision, backend_capabilities = _evaluate_worker_execution_policy(
                backend,
                contract_run,
                worker_manifest,
                execution_request,
                sandbox_profile,
            )
            if not policy_decision.allowed:
                failure = ProcessResult(
                    returncode=126,
                    stdout="",
                    stderr=f"ExecutionPolicyDenied: {policy_decision.reason}",
                )
                finalize(failure, terminal_status="blocked")
                _append_policy_denied_event(client, contract_run, policy_decision)
                raise ExecutionPolicyDenied(policy_decision)
        try:
            process = backend.build_exec_process(
                project_handle,
                dict(worker.env),
                argv,
                timeout_seconds=timeout_seconds,
            )
            process.start()
            if lease is not None:
                lease.attach_process(process)
            if cancellation is not None:
                cancellation.attach_process(process)
        except BaseException as exc:
            # A registered run must not be left running if process setup fails.
            failure = ProcessResult(returncode=1, stdout="", stderr=f"{type(exc).__name__}: {exc}")
            finalize(failure)
            raise
        try:
            result = process.communicate(timeout=communicate_timeout(timeout_seconds))
        except BaseException as exc:
            failure = ProcessResult(returncode=1, stdout="", stderr=f"{type(exc).__name__}: {exc}")
            finalize(failure)
            raise
        finalize(result)
        return result
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)


def _write_execution_record(
    backend: ExecutionBackend,
    project_handle: str,
    worker: WorkerConfig,
    argv: list[str],
    phase: str,
    started_at: datetime,
    duration_ms: int,
    timeout_seconds: int,
    result: ProcessResult,
    *,
    recipe_id: str | None = None,
    recipe_label: str | None = None,
    recipe_version: int | None = None,
    run_envelope: RunEnvelope | None = None,
    worker_manifest: WorkerManifest | None = None,
    recipe_content_digest: str | None = None,
    context_projection_id: str | None = None,
    execution_request: ExecutionRequest | None = None,
    sandbox_profile: SandboxProfile | None = None,
    policy_decision: PolicyDecision | None = None,
    backend_capabilities: BackendCapabilities | None = None,
) -> ExecutionRecordResult | None:
    """Persist the raw process result with stable metadata for later audit.

    Local execution uses the project workdir as its handle.  We intentionally
    store an argv digest rather than the argv itself because the latter embeds
    the full model prompt and may contain user-provided secrets.  The model's
    complete stdout/stderr, exit state, and timing are preserved alongside the
    board evidence so a finding can be reconstructed after the CLI session
    cache has been pruned.
    """
    try:
        record_root = getattr(backend, "execution_record_root", None)
        root = (
            Path(record_root(project_handle))
            if callable(record_root)
            else Path(project_handle).resolve() / ".linen-executions"
        )
        stamp = started_at.strftime("%Y%m%dT%H%M%S.%fZ")
        if run_envelope is not None:
            # Run identity is deterministic; filenames must remain stable
            # across retries and responses lost after a successful write.
            safe_run_id = re.sub(r"[^A-Za-z0-9._-]", "_", run_envelope.run_id)
            record_id = f"{safe_run_id}-{phase}"
        else:
            record_id = f"{stamp}-{phase}-{uuid.uuid4().hex[:8]}"
        record_path = root / f"{record_id}.json"
        prompt_path = root / f"{record_id}.prompt"
        stdout_path = root / f"{record_id}.stdout"
        stderr_path = root / f"{record_id}.stderr"
        prompt = _prompt_from_argv(argv) if worker.type in {"pi", "codex", "claudecode"} else None
        if prompt is not None:
            backend.write_text_file(project_handle, str(prompt_path), prompt)
        backend.write_text_file(project_handle, str(stdout_path), result.stdout)
        backend.write_text_file(project_handle, str(stderr_path), result.stderr)
        command_digest = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        contract_fields = (
            run_envelope is not None
            or worker_manifest is not None
            or recipe_content_digest is not None
            or context_projection_id is not None
        )
        record = {
            # Keep legacy records readable and preserve old callers' schema
            # while contract-aware executions get the vNext schema.
            "schema_version": 4 if contract_fields else 3,
            "phase": phase,
            "recipe_id": recipe_id,
            "recipe_label": recipe_label,
            "recipe_version": recipe_version,
            "worker": worker.name,
            "worker_type": worker.type,
            # Prompt extraction is useful for every CLI, but the executions
            # compatibility router must only classify genuine Pi records as
            # the legacy Pi archive.
            "command": "pi -p" if worker.type == "pi" else worker.type,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "timeout_seconds": timeout_seconds,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "cancel_reason": result.cancel_reason,
            "argv_sha256": command_digest,
            "prompt": str(prompt_path) if prompt is not None else None,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
        if contract_fields:
            record.update({
                "run_id": run_envelope.run_id if run_envelope else None,
                "attempt": run_envelope.attempt if run_envelope else None,
                "idempotency_key": run_envelope.idempotency_key if run_envelope else None,
                "context_projection_id": context_projection_id or (
                    run_envelope.context_projection_id if run_envelope else None
                ),
                "manifest_digest": (
                    (worker_manifest.manifest_digest if worker_manifest else None)
                    or (run_envelope.worker_manifest_digest if run_envelope else None)
                ),
                "recipe_digest": recipe_content_digest,
                "execution_mode": (
                    "legacy-policy-gated"
                    if policy_decision is not None and policy_decision.reason == "explicit_legacy_local"
                    else "policy-gated" if policy_decision is not None
                    else "legacy-unverified"
                ),
                "isolation": (
                    "unverified"
                    if policy_decision is not None and policy_decision.reason == "explicit_legacy_local"
                    else "enforced" if policy_decision is not None and policy_decision.allowed
                    else "denied" if policy_decision is not None
                    else "unverified"
                ),
                "backend": (
                    backend_capabilities.backend_name if backend_capabilities is not None
                    else type(backend).__name__
                ),
                "execution_request": (
                    execution_request.model_dump(mode="json") if execution_request is not None else None
                ),
                "sandbox_profile_digest": (
                    sandbox_profile.profile_digest if sandbox_profile is not None else None
                ),
                "policy_decision": (
                    policy_decision.model_dump(mode="json") if policy_decision is not None else None
                ),
            })
        record_content = json.dumps(record, indent=2) + "\n"
        backend.write_text_file(project_handle, str(record_path), record_content)
        return ExecutionRecordResult(
            record_path=str(record_path),
            record_content=record_content,
            prompt_path=str(prompt_path) if prompt is not None else None,
            prompt_content=prompt,
            stdout_path=str(stdout_path),
            stdout_content=result.stdout,
            stderr_path=str(stderr_path),
            stderr_content=result.stderr,
        )
    except Exception as exc:  # Execution evidence must never hide task output.
        LOG.warning("execution record write failed project=%s phase=%s error=%s", project_handle, phase, exc)
        return None


def _start_contract_run(
    client: LinenClient | None,
    run_envelope: RunEnvelope | None,
    *,
    worker_manifest: WorkerManifest | None,
    context_projection_id: str | None,
) -> RunEnvelope | None:
    """Register a run without making protocol availability affect execution."""
    if run_envelope is None:
        return None
    if worker_manifest is not None:
        _validate_contract_identity(run_envelope, worker_manifest, context_projection_id)
    elif (
        context_projection_id is not None
        and run_envelope.context_projection_id is not None
        and context_projection_id != run_envelope.context_projection_id
    ):
        raise ValueError("context projection does not match run envelope")
    updates: dict[str, object] = {"status": "running"}
    if run_envelope.started_at is None:
        updates["started_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if context_projection_id is not None:
        updates["context_projection_id"] = context_projection_id
    if worker_manifest is not None:
        updates["worker_manifest_digest"] = worker_manifest.manifest_digest
    running = run_envelope.model_copy(update=updates)
    if client is None:
        return running
    register = getattr(client, "register_run", None)
    if register is None:
        LOG.error("vNext run registration unavailable run_id=%s", running.run_id)
        return running
    try:
        response = register(running)
        if isinstance(response, RunEnvelope):
            if response.status in _TERMINAL_RUN_STATUSES:
                raise DuplicateTerminalRun(response)
            # The server owns timestamps, status and any idempotent existing
            # row.  Never continue with the caller's pre-registration copy.
            if response.status == "queued":
                promote = getattr(client, "transition_run", None)
                if promote is None:
                    raise RuntimeError(f"run {response.run_id} remained queued after registration")
                promoted = promote(response.model_copy(update={
                    "status": "running",
                    "started_at": response.started_at or running.started_at,
                }))
                if isinstance(promoted, RunEnvelope):
                    if promoted.status in _TERMINAL_RUN_STATUSES:
                        raise DuplicateTerminalRun(promoted)
                    return promoted
                LOG.error(
                    "vNext queued run promotion failed run_id=%s status=%s body=%s",
                    response.run_id, getattr(promoted, "status_code", None),
                    getattr(promoted, "text", ""),
                )
                raise RuntimeError(f"run {response.run_id} could not be promoted to running")
            return response
        if hasattr(response, "ok") and not response.ok:
            LOG.error(
                "vNext run registration failed run_id=%s status=%s body=%s",
                running.run_id,
                getattr(response, "status_code", None),
                getattr(response, "text", ""),
            )
            if getattr(response, "status_code", None) == 409:
                existing = _get_registered_run(client, running)
                if existing is not None:
                    if existing.status in _TERMINAL_RUN_STATUSES:
                        raise DuplicateTerminalRun(existing)
                    return existing
    except Exception as exc:  # pragma: no cover - defensive network boundary
        if isinstance(exc, DuplicateTerminalRun):
            raise
        LOG.error("vNext run registration raised run_id=%s error=%s", running.run_id, exc)
    return running


_TERMINAL_RUN_STATUSES = frozenset({
    "completed", "succeeded", "failed", "cancelled", "timed_out", "interrupted", "blocked",
})


def _get_registered_run(client: LinenClient, run: RunEnvelope) -> RunEnvelope | None:
    getter = getattr(client, "get_run", None)
    if getter is None:
        return None
    try:
        existing = getter(run.project_id, run.run_id)
        return existing if isinstance(existing, RunEnvelope) else None
    except Exception as exc:  # best effort only after a conflict response
        LOG.warning("vNext duplicate run lookup failed run_id=%s error=%s", run.run_id, exc)
        return None


def _validate_contract_identity(
    run_envelope: RunEnvelope,
    worker_manifest: WorkerManifest,
    context_projection_id: str | None,
) -> None:
    """Reject mismatched contract pieces before writing a worker run.

    The dispatcher is the sole protocol writer, so accepting a manifest from a
    different project/run would create audit evidence that cannot be joined to
    the registered envelope.  Optional manifest identifiers remain compatible
    with legacy callers, but any identifier that is present must agree.
    """
    checks = (
        ("project_id", worker_manifest.project_id, run_envelope.project_id),
        ("intent_id", worker_manifest.intent_id, run_envelope.intent_id),
        ("run_id", worker_manifest.run_id, run_envelope.run_id),
    )
    for field, actual, expected in checks:
        if actual is not None and actual != expected:
            raise ValueError(
                f"worker manifest {field}={actual!r} does not match run envelope {expected!r}"
            )
    if (
        run_envelope.worker_manifest_digest is not None
        and run_envelope.worker_manifest_digest != worker_manifest.manifest_digest
    ):
        raise ValueError("worker manifest digest does not match run envelope")
    if (
        context_projection_id is not None
        and run_envelope.context_projection_id is not None
        and context_projection_id != run_envelope.context_projection_id
    ):
        raise ValueError("context projection does not match run envelope")


def _finish_contract_run(
    client: LinenClient | None,
    run_envelope: RunEnvelope | None,
    result: ProcessResult,
    *,
    status_override: str | None = None,
) -> None:
    if run_envelope is None or client is None:
        return
    status = status_override or (
        "cancelled" if result.cancelled
        else "timed_out" if did_timeout(result)
        else "succeeded" if result.returncode == 0
        else "failed"
    )
    finished = run_envelope.model_copy(update={
        "status": status,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    })
    transition = getattr(client, "transition_run", None)
    if transition is None:
        LOG.error("vNext run transition unavailable run_id=%s status=%s", finished.run_id, status)
        return
    try:
        response = transition(finished)
        if hasattr(response, "ok") and not response.ok:
            LOG.error(
                "vNext run transition failed run_id=%s status=%s response_status=%s body=%s",
                finished.run_id,
                status,
                getattr(response, "status_code", None),
                getattr(response, "text", ""),
            )
    except Exception as exc:  # pragma: no cover - defensive network boundary
        LOG.error("vNext run transition raised run_id=%s status=%s error=%s", finished.run_id, status, exc)


def _register_execution_artifacts(
    client: LinenClient | None,
    run_envelope: RunEnvelope | None,
    backend: ExecutionBackend,
    project_handle: str,
    record: ExecutionRecordResult | None,
) -> list[str]:
    """Register execution evidence before a run becomes terminal.

    Artifact IDs are derived solely from ``run_id`` and role.  A lost HTTP
    response can therefore be retried with identical metadata and the server's
    idempotent artifact insert returns the same row.
    """
    if client is None or run_envelope is None or record is None:
        return []
    register = getattr(client, "register_artifact", None) or getattr(client, "create_artifact", None)
    if register is None:
        LOG.error("vNext artifact registration unavailable run_id=%s", run_envelope.run_id)
        return []
    relative_path_for = getattr(backend, "artifact_workspace_path", None)
    root = Path(project_handle).resolve()
    related = [run_envelope.intent_id] if run_envelope.intent_id else []
    files: list[tuple[str, str, str, str]] = [
        ("execution_record", record.record_path, record.record_content, "application/json"),
        ("stdout", record.stdout_path, record.stdout_content, "text/plain"),
        ("stderr", record.stderr_path, record.stderr_content, "text/plain"),
    ]
    if record.prompt_path is not None and record.prompt_content is not None:
        files.insert(1, ("prompt", record.prompt_path, record.prompt_content, "text/plain"))
    artifact_ids: list[str] = []
    for role, path, content, media_type in files:
        try:
            relative_path = (
                relative_path_for(project_handle, path)
                if callable(relative_path_for)
                else Path(path).resolve().relative_to(root).as_posix()
            )
            content_bytes = content.encode("utf-8")
            artifact = ArtifactMetadata(
                artifact_id="artifact-" + hashlib.sha256(
                    f"{run_envelope.run_id}:{role}".encode("utf-8")
                ).hexdigest(),
                project_id=run_envelope.project_id,
                kind=role,
                workspace_path=relative_path,
                sha256=hashlib.sha256(content_bytes).hexdigest(),
                media_type=media_type,
                byte_size=len(content_bytes),
                producer_run_id=run_envelope.run_id,
                related_node_ids=related,
            )
            response = register(artifact)
            if isinstance(response, ArtifactMetadata):
                artifact_ids.append(response.artifact_id)
            elif hasattr(response, "ok") and not response.ok:
                LOG.error(
                    "vNext artifact registration failed run_id=%s role=%s status=%s body=%s",
                    run_envelope.run_id, role, getattr(response, "status_code", None),
                    getattr(response, "text", ""),
                )
            else:
                LOG.error(
                    "vNext artifact registration returned no validated metadata run_id=%s role=%s",
                    run_envelope.run_id, role,
                )
        except Exception as exc:
            LOG.error(
                "vNext artifact registration raised run_id=%s role=%s error=%s",
                run_envelope.run_id, role, exc,
            )
    return artifact_ids


def _pi_prompt_from_argv(argv: list[str]) -> str | None:
    """Return the payload passed to Pi's final ``-p`` flag without persisting argv.

    Pi may be wrapped by ``/bin/sh`` and model-provider setup arguments. Looking
    backwards finds the actual Pi prompt while keeping API keys and injected
    provider configuration out of the execution record.
    """
    for index in range(len(argv) - 2, -1, -1):
        if argv[index] == "-p":
            return argv[index + 1]
    return None


def _prompt_from_argv(argv: list[str]) -> str | None:
    """Extract a worker prompt without persisting the complete argv."""
    # Pi places the prompt after ``-p`` directly. Claude uses ``-p --`` and
    # places it after the option terminator, so skip the terminator here.
    for index in range(len(argv) - 2, -1, -1):
        if argv[index] == "-p" and argv[index + 1] != "--":
            return argv[index + 1]
    # Codex/Claude adapters terminate options with ``--`` and place the
    # prompt immediately after it.  Their session/provider arguments are not
    # copied into the execution record.
    for index in range(len(argv) - 2, -1, -1):
        if argv[index] == "--" and index + 1 < len(argv):
            candidate = argv[index + 1]
            if candidate != "-p":
                return candidate
    return None


def project_allows_conclude_fallback(client: LinenClient, project_id: str, *, worker_name: str, intent_id: str) -> bool:
    project = client.get_project(project_id)
    if project.project.status == "active":
        return True
    LOG.info(
        "skip conclude fallback because project is no longer active project=%s intent=%s worker=%s status=%s",
        project_id,
        intent_id,
        worker_name,
        project.project.status,
    )
    return False


def best_effort_release_reason(
    client: LinenClient, project_id: str, worker_name: str, lease_id: str,
    seen_event_seq: int | None = None,
    *,
    ack: bool = False,
) -> None:
    if not ack:
        seen_event_seq = None
    try:
        response = client.release_reason(project_id, worker_name, lease_id, seen_event_seq)
    except TypeError:
        # Legacy protocol fakes do not expose the additive cursor field.
        response = client.release_reason(project_id, worker_name, lease_id)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "reason release failed project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released reason project=%s worker=%s", project_id, worker_name)
    else:
        LOG.info(
            "reason release skipped project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )


def write_conclude_result(
    client: LinenClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_type: str | None = None,
    evidence: str | None = None,
    fact_status: str = "draft",
    proof: dict[str, Any] | None = None,
) -> str:
    return write_conclude_result_with_fact_id(
        client,
        project_id,
        intent_id,
        worker_name,
        description,
        source=source,
        phase_ms=phase_ms,
        total_ms=total_ms,
        fact_type=fact_type,
        evidence=evidence,
        fact_status=fact_status,
        proof=proof,
    ).status


def write_conclude_result_with_fact_id(
    client: LinenClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    fact_type: str | None = None,
    evidence: str | None = None,
    fact_status: str = "draft",
    proof: dict[str, Any] | None = None,
) -> ConcludeWriteResult:
    conclude_options: dict[str, Any] = {
        "fact_type": fact_type,
        "evidence": evidence,
        "status": fact_status,
    }
    if proof is not None:
        conclude_options["proof"] = proof
    response = client.conclude(
        project_id,
        intent_id,
        worker_name,
        description,
        **conclude_options,
    )
    if response.ok:
        fact_id: str | None = None
        if isinstance(response.data, dict):
            fact = response.data.get("fact")
            if isinstance(fact, dict):
                candidate = fact.get("id")
                if isinstance(candidate, str) and candidate:
                    fact_id = candidate
        if total_ms is None:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
            )
        else:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s total_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
                total_ms,
            )
        return ConcludeWriteResult(status="success", fact_id=fact_id)
    if response.status_code == 403:
        LOG.info(
            "project became inactive during conclude project=%s intent=%s worker=%s",
            project_id,
            intent_id,
            worker_name,
        )
    else:
        LOG.warning(
            "conclude write failed project=%s intent=%s worker=%s status=%s body=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
            response.text,
        )
    best_effort_release(client, project_id, intent_id, worker_name)
    return ConcludeWriteResult(status="failed", fact_id=None)


def best_effort_release(client: LinenClient, project_id: str, intent_id: str, worker_name: str) -> None:
    response = client.release(project_id, intent_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "release failed project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released intent project=%s intent=%s worker=%s", project_id, intent_id, worker_name)
    else:
        LOG.info(
            "release skipped project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
