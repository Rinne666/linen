from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from linen.dispatcher.analysis import audit_graph, coverage
from linen.dispatcher.analysis.external_scanners import scanner_reason_instructions, scanner_specs

from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.analysis.policy import (
    AUDIT_REASON_INSTRUCTIONS,
    SOURCE_DATA_BOUNDARY,
    completion_blockers,
)
from linen.dispatcher.contracts import (
    extract_context_request,
    parse_json_output,
    validate_reason_payload,
)
from linen.dispatcher.prompting import (
    format_fact_ids,
    format_open_intents,
    load_prompt,
    render_prompt,
)
from linen.dispatcher.protocol.client import LinenClient
from linen.contracts import ContextProjection, RunEnvelope, WorkerManifest
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.backend import ExecutionBackend
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.tasks.common import (
    best_effort_release_reason,
    cancel_reason,
    classify_provider_failure,
    did_timeout,
    expand_context_projection,
    preview,
    run_worker_process,
    prepare_context_projection,
    task_healthcheck_enabled,
    write_context_projection_reference,
)
from linen.dispatcher.workers.registry import get_driver
from linen.server.models import ProjectDetail

LOG = logging.getLogger(__name__)

REASON_SEED_BUDGET = 32
REASON_HINT_SEED_LIMIT = 4
HIGH_VALUE_FACT_TYPES = (
    "scope", "summary", "candidate_finding", "confirmed_finding",
    "negative_assurance", "coverage", "coverage_plan", "coverage_result",
    "candidate_triage", "candidate_disposition", "audit_summary",
)


def _reason_frontier_seed_ids(project: ProjectDetail, *, budget: int = REASON_SEED_BUDGET) -> list[str]:
    """Return deterministic, high-value roots for a no-Intent Reason pass."""
    available = {
        project.project.id,
        *(fact.id for fact in project.facts),
        *(intent.id for intent in project.intents),
        *(hint.id for hint in project.hints),
    }
    hint_ids = {hint.id for hint in project.hints}
    seeds: list[str] = []

    def add(identifier: str) -> None:
        identifier = identifier.strip()
        if identifier and identifier in available and identifier not in seeds and len(seeds) < budget:
            seeds.append(identifier)

    # Project is also injected by ContextProjector; retaining it here makes
    # the caller's priority order explicit and observable in tests/logging.
    add(project.project.id)
    for special in ("origin", "goal"):
        add(special)

    open_intents = sorted(
        (intent for intent in project.intents if intent.to is None and intent.concluded_at is None),
        key=lambda intent: intent.id,
    )
    for intent in open_intents:
        add(intent.id)
        for source_id in sorted(set(intent.from_)):
            add(source_id)

    for fact_type in HIGH_VALUE_FACT_TYPES:
        for fact in sorted(project.facts, key=lambda item: item.id):
            if fact.status in {"false_positive", "fixed", "accepted_risk"}:
                continue
            if fact.source_generation != project.project.source_generation:
                continue
            if fact_type in {fact.type, fact.semantic_type}:
                add(fact.id)

    # Hints can be useful but are deliberately capped so an unbounded hint
    # stream cannot crowd out current graph evidence.
    for hint in sorted(project.hints, key=lambda item: item.id)[:REASON_HINT_SEED_LIMIT]:
        add(hint.id)

    # Stable ID fill makes selection reproducible without silently widening to
    # the complete graph when the priority roots are sparse.
    for identifier in sorted(available):
        if identifier in hint_ids and identifier not in seeds:
            continue
        fact = next((item for item in project.facts if item.id == identifier), None)
        if fact is not None and (
            fact.source_generation != project.project.source_generation
            or fact.status in {"false_positive", "fixed", "accepted_risk"}
        ):
            continue
        add(identifier)
    return seeds


def _prepare_reason_contracts(
    client: LinenClient,
    backend: ExecutionBackend,
    project: ProjectDetail,
    container_name: str,
    *,
    phase: str,
) -> ContextProjection | None:
    projection = prepare_context_projection(
        client,
        backend,
        project,
        container_name,
        seed_ids=_reason_frontier_seed_ids(project),
        phase=phase,
        current_graph_revision=project.project.graph_revision,
    )
    if projection is None:
        return None
    return projection


def _reason_contracts(
    project: ProjectDetail,
    worker: WorkerConfig,
    projection: ContextProjection,
    *,
    phase: str,
    timeout_seconds: int,
    trigger: str | None,
    attempt: int,
    prompt: str,
    logical_scope: str | None = None,
) -> tuple[WorkerManifest, RunEnvelope]:
    from linen.dispatcher.runtime.contracts import build_execution_contracts

    trigger_value = (trigger or "scheduler").strip() or "scheduler"
    scope = logical_scope or f"{phase}:graph-{projection.graph_revision}:trigger-{trigger_value}"
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
        logical_scope=scope,
        context_projection_id=projection.projection_id,
        recipe_id="audit_graph_reason" if phase.startswith("audit_graph_reason") else "reason",
        recipe_version=1,
        recipe_label="AuditGraph Reason" if phase.startswith("audit_graph_reason") else "Reason",
        prompt=prompt,
    )


def _run_context_continuation(
    *,
    client: LinenClient,
    backend: ExecutionBackend,
    project: ProjectDetail,
    container_name: str,
    worker: WorkerConfig,
    driver: object,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
    initial_run: RunEnvelope,
    projection: ContextProjection,
    request: object,
    timeout_seconds: int,
    attempt: int,
    audit_graph_reason: bool,
) -> tuple[str, dict[str, object] | None]:
    """Run the sole allowed ContextRequest continuation pass.

    A continuation is a new cold worker session and a new server-owned run.
    It receives only the expanded projection reference and must produce the
    original task schema.  This helper intentionally has no loop: a second
    context request is a controlled failure.
    """
    expanded = expand_context_projection(client, projection, request)
    if expanded is None:
        LOG.error(
            "context continuation expansion failed project=%s initial_run=%s",
            project.project.id,
            initial_run.run_id,
        )
        return "failed", None
    continuation_phase = (
        "audit_graph_reason_context_continuation"
        if audit_graph_reason
        else "reason_context_continuation"
    )
    try:
        context_reference = write_context_projection_reference(
            backend,
            container_name,
            expanded,
            phase=continuation_phase,
        )
    except Exception as exc:
        LOG.error(
            "context continuation reference write failed project=%s initial_run=%s error=%s",
            project.project.id,
            initial_run.run_id,
            exc,
        )
        return "failed", None

    if not hasattr(request, "canonical_digest"):
        LOG.error(
            "context continuation request is not a validated ContextRequest project=%s initial_run=%s",
            project.project.id,
            initial_run.run_id,
        )
        return "failed", None
    request_digest = request.canonical_digest()
    logical_scope = (
        f"{continuation_phase}:initial-run-{initial_run.run_id}:request-{request_digest}"
    )
    label = "AuditGraph Reason" if audit_graph_reason else "Reason"
    continuation_prompt = (
        "The previous pass requested one bounded context expansion. Use only the "
        "expanded ContextProjection at this dispatcher-managed path:\n\n"
        f"{context_reference}\n\n"
        f"Return the final original {label} response schema now. Do not return "
        "status=context_required and do not request more context. The dispatcher "
        "will validate the response against the current graph before any write."
    )
    try:
        worker_manifest, run_envelope = _reason_contracts(
            project,
            worker,
            expanded,
            phase=continuation_phase,
            timeout_seconds=timeout_seconds,
            trigger=None,
            attempt=attempt,
            prompt=continuation_prompt,
            logical_scope=logical_scope,
        )
        # Deliberately prepare a new session; never inherit the first pass.
        session = driver.prepare_session()
        command = driver.build_execute(worker, continuation_prompt, session)
        result = run_worker_process(
            backend,
            container_name,
            worker,
            command.argv,
            phase=continuation_phase,
            timeout_seconds=timeout_seconds,
            lease=lease,
            cancellation=cancellation,
            client=client,
            run_envelope=run_envelope,
            worker_manifest=worker_manifest,
            context_projection_id=run_envelope.context_projection_id,
            recipe_content_digest=worker_manifest.recipe.digest,
        )
    except Exception as exc:
        LOG.error(
            "context continuation worker failed project=%s initial_run=%s error=%s",
            project.project.id,
            initial_run.run_id,
            exc,
        )
        return "failed", None

    if cancellation.is_cancelled:
        return "cancelled", None
    if lease.failure is not None:
        return "failed", None
    if did_timeout(result) or result.returncode != 0:
        LOG.warning(
            "context continuation process failed project=%s initial_run=%s code=%s",
            project.project.id,
            initial_run.run_id,
            result.returncode,
        )
        return "failed", None
    provider_failure = classify_provider_failure(result)
    if provider_failure is not None:
        LOG.warning(
            "context continuation provider unavailable project=%s initial_run=%s outcome=%s",
            project.project.id,
            initial_run.run_id,
            provider_failure,
        )
        return provider_failure, None
    try:
        payload = parse_json_output(driver.extract_response_text(result.stdout, result.stderr))
        if extract_context_request(payload) is not None:
            raise ValueError("worker requested context more than once")
    except Exception as exc:
        LOG.warning(
            "context continuation response invalid project=%s initial_run=%s error=%s",
            project.project.id,
            initial_run.run_id,
            exc,
        )
        return "failed", None
    return "success", payload


def run_audit_graph_reason_task(
    config: DispatchConfig,
    client: LinenClient,
    backend: ExecutionBackend,
    project: ProjectDetail,
    export_yaml: str,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
    lease_id: str | None = None,
    trigger: str | None = None,
    attempt: int = 1,
) -> str:
    """Run a fresh, constrained Reason conversation over one graph revision.

    The model never receives protocol credentials or write authority. Its
    output is parsed against the same revision it read, validated by
    ``audit_graph.validate_model_intents``, and only then written by the
    dispatcher as ordinary blackboard intents.
    """
    lease_id = lease_id or uuid.uuid4().hex
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    graph_config = config.audit.graph_reason
    lease = HeartbeatLease.for_reason(
        client, project.project.id, worker.name, lease_id, config.runtime.interval,
    )
    lease.start()
    try:
        container_name = backend.ensure_running(project.project.id)
        if task_healthcheck_enabled(config):
            health = driver.check_health(worker, timeout=config.runtime.healthcheck_timeout)
            if cancellation.is_cancelled:
                return "cancelled"
            if lease.failure is not None:
                return "failed"
            if not health.ok:
                LOG.warning(
                    "audit graph worker unhealthy project=%s worker=%s status=%s detail=%s",
                    project.project.id, worker.name, health.status, health.detail,
                )
                return "unhealthy"

        prepared_contracts = _prepare_reason_contracts(
            client,
            backend,
            project,
            container_name,
            phase="audit_graph_reason",
        )
        if prepared_contracts is None:
            return "failed"
        projection = prepared_contracts
        try:
            context_reference = write_context_projection_reference(
                backend, container_name, projection, phase="audit_graph_reason",
            )
        except Exception as exc:
            LOG.error(
                "context projection reference write failed project=%s phase=%s error=%s",
                project.project.id, "audit_graph_reason", exc,
            )
            return "failed"
        projected_ids = set(projection.node_ids)

        open_intents = [
            {
                "id": intent.id,
                "from": [source_id for source_id in intent.from_ if source_id in projected_ids],
                "type": intent.type,
                "description": intent.description,
                "worker": intent.worker,
            }
            for intent in project.intents
            if intent.to is None and intent.concluded_at is None and intent.id in projected_ids
        ]
        allowed_fact_ids = [
            fact.id for fact in project.facts
            if fact.id != "goal" and fact.id in projected_ids
        ]
        skill_choices = audit_graph.selectable_skill_choices(
            project, Path(container_name), config.audit,
        )
        skill_contract_path = Path(__file__).resolve().parents[1] / "skills" / "SKILL.md"
        skill_contract = skill_contract_path.read_text(encoding="utf-8")
        public_skill_choices = [
            {
                "skill_id": choice["skill_id"],
                "version": choice["version"],
                "capability": choice["capability"],
                "label": choice["label"],
            }
            for choice in skill_choices
        ]
        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "audit_graph.md"),
            {
                "graph_yaml": context_reference,
                "graph_revision": str(projection.graph_revision),
                "fact_ids": format_fact_ids(allowed_fact_ids),
                "open_intents": format_open_intents(open_intents),
                "max_intents": str(graph_config.max_intents),
                "skill_contract": skill_contract,
                "available_skills": json.dumps(public_skill_choices, ensure_ascii=False),
            },
        )
        prompt += "\n" + SOURCE_DATA_BOUNDARY

        worker_manifest, run_envelope = _reason_contracts(
            project,
            worker,
            projection,
            phase="audit_graph_reason",
            timeout_seconds=graph_config.timeout,
            trigger=trigger,
            attempt=attempt,
            prompt=prompt,
        )

        # Every audit-graph pass is deliberately cold-started. Drivers that
        # need an explicit seed/session id create one here; drivers whose
        # execute command starts a conversation leave this as None.
        session = driver.prepare_session()
        command = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            backend,
            container_name,
            worker,
            command.argv,
            phase="audit_graph_reason",
            timeout_seconds=graph_config.timeout,
            lease=lease,
            cancellation=cancellation,
            client=client,
            run_envelope=run_envelope,
            worker_manifest=worker_manifest,
            context_projection_id=run_envelope.context_projection_id,
            recipe_content_digest=worker_manifest.recipe.digest,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        total_ms = int((time.perf_counter() - task_started) * 1000)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            return "cancelled"
        if lease.failure is not None:
            return "failed"
        provider_failure = classify_provider_failure(result)
        if provider_failure is not None:
            LOG.warning(
                "audit graph provider unavailable project=%s worker=%s outcome=%s",
                project.project.id, worker.name, provider_failure,
            )
            return provider_failure
        if did_timeout(result):
            LOG.warning(
                "audit graph reason timed out project=%s worker=%s execute_ms=%s total_ms=%s",
                project.project.id, worker.name, execute_ms, total_ms,
            )
            return "failed"
        if result.returncode != 0:
            LOG.warning(
                "audit graph reason command failed project=%s worker=%s code=%s stderr_preview=%s",
                project.project.id, worker.name, result.returncode, preview(result.stderr),
            )
            return "failed"
        continuation_used = False
        try:
            payload = parse_json_output(driver.extract_response_text(result.stdout, result.stderr))
            context_request = extract_context_request(payload)
            if context_request is not None:
                continuation_used = True
                continuation_status, continuation_payload = _run_context_continuation(
                    client=client,
                    backend=backend,
                    project=project,
                    container_name=container_name,
                    worker=worker,
                    driver=driver,
                    lease=lease,
                    cancellation=cancellation,
                    initial_run=run_envelope,
                    projection=projection,
                    request=context_request,
                    timeout_seconds=graph_config.timeout,
                    attempt=attempt,
                    audit_graph_reason=True,
                )
                if continuation_status != "success" or continuation_payload is None:
                    return continuation_status
                payload = continuation_payload
            fresh = client.get_project(project.project.id)
            kind, proposals = audit_graph.validate_model_intents(
                payload,
                fresh,
                expected_revision=run_envelope.graph_revision,
                max_intents=graph_config.max_intents,
                skill_choices=skill_choices,
            )
        except Exception as exc:
            LOG.warning(
                "audit graph reason validation failed project=%s worker=%s error=%s stdout_preview=%s",
                project.project.id,
                worker.name,
                exc,
                None if continuation_used else preview(result.stdout),
            )
            return "failed"
        if kind == "rejected":
            return "rejected"

        created = 0
        for proposal in proposals:
            response = client.create_intent(
                project.project.id,
                proposal["from"],
                proposal["description"],
                audit_graph.MODEL_CREATOR,
                intent_type=proposal["type"],
                display_title=proposal.get("display_title"),
                semantic_type=proposal.get("semantic_type"),
                relation_type=proposal.get("relation_type"),
                phase=proposal.get("phase"),
            )
            if response.status_code in {403, 409}:
                continue
            if not response.ok:
                LOG.warning(
                    "audit graph intent write failed project=%s worker=%s status=%s body=%s",
                    project.project.id, worker.name, response.status_code, response.text,
                )
                continue
            created += 1
            if proposal.get("skill_id"):
                client.create_hint(
                    project.project.id,
                    (
                        f"AuditGraph selected {proposal['skill_id']} from the trusted Skill registry. "
                        f"Reason: {proposal['selection_reason']}"
                    ),
                    audit_graph.MODEL_CREATOR,
                )
        if proposals and created == 0:
            return "failed"
        LOG.info(
            "audit graph reason finished project=%s worker=%s revision=%s created_intents=%s/%s execute_ms=%s total_ms=%s",
            project.project.id,
            worker.name,
            project.project.graph_revision,
            created,
            len(proposals),
            execute_ms,
            total_ms,
        )
        return "success"
    finally:
        lease.stop()
        best_effort_release_reason(client, project.project.id, worker.name, lease_id)


def run_reason_task(
    config: DispatchConfig,
    client: LinenClient,
    backend: ExecutionBackend,
    project: ProjectDetail,
    export_yaml: str,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
    lease_id: str | None = None,
    trigger: str | None = None,
    attempt: int = 1,
) -> str:
    lease_id = lease_id or uuid.uuid4().hex
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_reason(
        client, project.project.id, worker.name, lease_id, config.runtime.interval,
    )
    lease.start()
    try:
        container_name = backend.ensure_running(project.project.id)

        if task_healthcheck_enabled(config):
            LOG.info(
                "checking worker health project=%s worker=%s timeout=%ss",
                project.project.id,
                worker.name,
                healthcheck_timeout,
            )
            health = driver.check_health(worker, timeout=healthcheck_timeout)
            if cancellation.is_cancelled:
                LOG.info(
                    "reason cancelled during healthcheck project=%s worker=%s reason=%s",
                    project.project.id,
                    worker.name,
                    cancellation.reason,
                )
                return "cancelled"
            if lease.failure is not None:
                LOG.warning(
                    "heartbeat lost during reason healthcheck project=%s worker=%s status=%s",
                    project.project.id,
                    worker.name,
                    lease.failure.status_code,
                )
                return "failed"
            if not health.ok:
                LOG.warning(
                    "worker unhealthy project=%s worker=%s status=%s detail=%s",
                    project.project.id,
                    worker.name,
                    health.status,
                    health.detail,
                )
                return "unhealthy"

        prepared_contracts = _prepare_reason_contracts(
            client,
            backend,
            project,
            container_name,
            phase="reason_execute",
        )
        if prepared_contracts is None:
            return "failed"
        projection = prepared_contracts
        try:
            context_reference = write_context_projection_reference(
                backend, container_name, projection, phase="reason_execute",
            )
        except Exception as exc:
            LOG.error(
                "context projection reference write failed project=%s phase=%s error=%s",
                project.project.id, "reason_execute", exc,
            )
            return "failed"
        projected_ids = set(projection.node_ids)
        open_intents = [
            {
                "id": intent.id,
                "from": [source_id for source_id in intent.from_ if source_id in projected_ids],
                "description": intent.description,
                "worker": intent.worker,
            }
            for intent in project.intents
            if intent.to is None and intent.concluded_at is None and intent.id in projected_ids
        ]
        allowed_fact_ids = [
            fact.id for fact in project.facts
            if fact.id != "goal" and fact.id in projected_ids
        ]
        LOG.debug(
            "reason context prepared project=%s worker=%s facts=%s allowed_fact_ids=%s hints=%s open_intents=%s",
            project.project.id,
            worker.name,
            len(project.facts),
            len(allowed_fact_ids),
            len(project.hints),
            len(open_intents),
        )
        audit_enabled = config.audit.enabled and project.project.audit_mode != "none"
        scope_audit = audit_enabled and project.project.audit_mode == "scope"
        prompt_name = (
            "reason_scope.md"
            if scope_audit and config.runtime.prompt_group == "vuln_audit"
            else "reason.md"
        )
        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, prompt_name),
            {
                "graph_yaml": context_reference,
                "fact_ids": format_fact_ids(allowed_fact_ids),
                "open_intents": format_open_intents(open_intents),
                "max_intents": str(config.tasks.reason.max_intents),
            },
        )
        if audit_enabled:
            prompt += "\n" + SOURCE_DATA_BOUNDARY

        if audit_enabled:
            if scope_audit:
                prompt += coverage.reason_instructions(project, Path(container_name), config.audit.coverage)
                if not config.audit.poc_sandbox.enabled:
                    prompt += (
                        "\nThe isolated PoC sandbox is disabled. Do not propose "
                        "poc:isolated intents for this project."
                    )
            else:
                prompt += "\n" + AUDIT_REASON_INSTRUCTIONS
            if scanner_specs(config.audit):
                prompt += "\n" + scanner_reason_instructions(config.audit)
        worker_manifest, run_envelope = _reason_contracts(
            project,
            worker,
            projection,
            phase="reason_execute",
            timeout_seconds=config.tasks.reason.timeout,
            trigger=trigger,
            attempt=attempt,
            prompt=prompt,
        )
        session = driver.prepare_session()
        command = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            backend,
            container_name,
            worker,
            command.argv,
            phase="reason_execute",
            timeout_seconds=config.tasks.reason.timeout,
            lease=lease,
            cancellation=cancellation,
            client=client,
            run_envelope=run_envelope,
            worker_manifest=worker_manifest,
            context_projection_id=run_envelope.context_projection_id,
            recipe_content_digest=worker_manifest.recipe.digest,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        total_ms = int((time.perf_counter() - task_started) * 1000)
        session = driver.extract_session(session, result.stdout, result.stderr)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            LOG.info(
                "reason cancelled project=%s worker=%s reason=%s execute_ms=%s",
                project.project.id,
                worker.name,
                cancelled,
                execute_ms,
            )
            return "cancelled"
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during reason project=%s worker=%s status=%s execute_ms=%s",
                project.project.id,
                worker.name,
                lease.failure.status_code,
                execute_ms,
            )
            return "failed"
        provider_failure = classify_provider_failure(result)
        if provider_failure is not None:
            LOG.warning(
                "reason provider unavailable project=%s worker=%s outcome=%s execute_ms=%s",
                project.project.id, worker.name, provider_failure, execute_ms,
            )
            return provider_failure
        if did_timeout(result):
            LOG.warning(
                "reason timed out project=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return "failed"
        if result.returncode != 0:
            LOG.warning(
                "reason command failed project=%s worker=%s code=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                result.returncode,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return "failed"
        continuation_used = False
        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            context_request = extract_context_request(payload)
            if context_request is not None:
                continuation_used = True
                continuation_status, continuation_payload = _run_context_continuation(
                    client=client,
                    backend=backend,
                    project=project,
                    container_name=container_name,
                    worker=worker,
                    driver=driver,
                    lease=lease,
                    cancellation=cancellation,
                    initial_run=run_envelope,
                    projection=projection,
                    request=context_request,
                    timeout_seconds=config.tasks.reason.timeout,
                    attempt=attempt,
                    audit_graph_reason=False,
                )
                if continuation_status != "success" or continuation_payload is None:
                    return continuation_status
                payload = continuation_payload
            kind, data = validate_reason_payload(
                payload, open_intents_empty=not open_intents, max_intents=config.tasks.reason.max_intents,
            )
        except Exception as exc:
            LOG.warning(
                "reason parse failed project=%s worker=%s error=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                exc,
                execute_ms,
                total_ms,
                None if continuation_used else preview(result.stdout),
                None if continuation_used else preview(result.stderr),
            )
            return "failed"
        if kind == "rejected":
            LOG.warning(
                "reason rejected project=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(result.stdout),
            )
            return "rejected"
        if kind == "complete":
            if config.audit.enabled:
                fresh = client.get_project(project.project.id)
                blockers = (
                    audit_graph.scope_blockers(fresh, Path(container_name), config.audit, data["from"])
                    if scope_audit else completion_blockers(fresh, data["from"])
                )
                if blockers:
                    message = "Audit completion blocked:\n" + "\n".join(blockers)
                    LOG.warning("%s project=%s", message, project.project.id)
                    if not any(hint.content == message for hint in fresh.hints):
                        response = client.create_hint(project.project.id, message, "audit-policy")
                        if not response.ok:
                            return "failed"
                    return "success"
            response = client.complete(project.project.id, data["from"], data["description"], worker.name)
            if response.status_code == 403:
                LOG.info("project became inactive during reason complete project=%s worker=%s", project.project.id, worker.name)
                return "success"
            if not response.ok:
                LOG.warning(
                    "reason complete write failed project=%s worker=%s status=%s body=%s",
                    project.project.id,
                    worker.name,
                    response.status_code,
                    response.text,
                )
                return "failed"
            LOG.info(
                "project completed project=%s worker=%s from=%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                data["from"],
                execute_ms,
                total_ms,
            )
            return "success"
        if kind == "intents":
            created = 0
            for intent_data in data:
                if scope_audit:
                    fresh = client.get_project(project.project.id)
                    try:
                        coverage.validate_intent(fresh, Path(container_name), config.audit.coverage, intent_data)
                        if audit_graph.managed_description(intent_data["description"]):
                            raise ValueError(
                                "Reserved audit intents are materialized from graph state by the dispatcher"
                            )
                    except ValueError as exc:
                        message = f"Coverage intent blocked: {exc} ({intent_data['description']})"
                        if not any(h.content == message for h in fresh.hints):
                            client.create_hint(project.project.id, message, "audit-policy")
                        continue
                # `type` is optional in the validate_reason_payload contract; the
                # reason worker may emit a `review`-typed intent to challenge a
                # draft candidate finding, alongside the canonical search/trace/
                # validate/reach/characterize intents. Pass it through so the
                # scheduler can route review intents to the review dispatcher
                # (loop.py: `if intent.type == "review"`).
                intent_type = intent_data.get("type")
                response = client.create_intent(
                    project.project.id,
                    intent_data["from"],
                    intent_data["description"],
                    worker.name,
                    intent_type=intent_type,
                )
                if response.status_code == 403:
                    LOG.info("project became inactive during reason intent create project=%s worker=%s created=%s", project.project.id, worker.name, created)
                    return "success"
                if response.status_code == 409:
                    LOG.info("reason intent lost race project=%s worker=%s from=%s", project.project.id, worker.name, intent_data["from"])
                    continue
                if not response.ok:
                    LOG.warning(
                        "reason intent write failed project=%s worker=%s status=%s body=%s",
                        project.project.id,
                        worker.name,
                        response.status_code,
                        response.text,
                    )
                    continue
                created += 1
                LOG.info(
                    "reason created intent project=%s worker=%s from=%s description=%s",
                    project.project.id,
                    worker.name,
                    intent_data["from"],
                    intent_data["description"],
                )
            LOG.info(
                "reason finished project=%s worker=%s created_intents=%s/%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                created,
                len(data),
                execute_ms,
                total_ms,
            )
            if created == 0:
                LOG.warning(
                    "reason created no intents project=%s worker=%s attempted=%s execute_ms=%s total_ms=%s",
                    project.project.id,
                    worker.name,
                    len(data),
                    execute_ms,
                    total_ms,
                )
                return "failed"
            return "success"
        LOG.info(
            "reason finished without graph change project=%s worker=%s execute_ms=%s total_ms=%s",
            project.project.id,
            worker.name,
            execute_ms,
            total_ms,
        )
        return "success"
    finally:
        lease.stop()
        best_effort_release_reason(client, project.project.id, worker.name, lease_id)
