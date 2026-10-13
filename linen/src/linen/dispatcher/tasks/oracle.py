"""Dispatcher-only publication of registered independent observations."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
import uuid

from pydantic import BaseModel
from typing import Literal

from linen.contracts import ArtifactMetadata, RecipeRef, RunEnvelope, WorkerManifest
from linen.contracts.oracle import OracleCatalog
from linen.dispatcher.analysis.artifacts import select_snapshot
from linen.dispatcher.config import DispatchConfig, WorkerConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import ExecutionBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.runtime.oracle_runner import RegisteredOracleProcess, oracle_checker_digest
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks.common import (
    _finish_contract_run, _register_execution_artifacts, _write_execution_record,
    best_effort_release, write_conclude_result,
)
from linen.server.models import Intent, ProjectDetail
from linen.server.uvpg import parse_proof_obligation


class _OracleWorker(BaseModel):
    name: str
    type: Literal["builtin-oracle"] = "builtin-oracle"
    env: dict[str, str] = {}


def parse_oracle_intent(intent: Intent) -> tuple[str, str] | None:
    description = intent.description.strip()
    # Preserve the server's proof-obligation prefix so conclude still enforces
    # the candidate, generation and expected proof role.
    if description.startswith("@uvpg:proof:"):
        obligation = parse_proof_obligation(description)
        roles = {"MISSING_DYNAMIC_REPRODUCTION": "positive", "MISSING_DYNAMIC_NEGATIVE_CONTROL": "negative"}
        if obligation is None or obligation[1] not in roles:
            return None
        description = description.rsplit(" ", 1)[-1]
        if not description.endswith(":" + roles[obligation[1]]):
            return None
    parts = description.split(":")
    if len(parts) == 3 and parts[0] == "@oracle" and parts[2] in {"positive", "negative"}:
        return parts[1], parts[2]
    return None


def run_oracle_task(
    config: DispatchConfig, client: LinenClient, backend: ExecutionBackend,
    project: ProjectDetail, intent: Intent, worker: WorkerConfig,
    cancellation: TaskCancellation, *, attempt: int = 1,
) -> str:
    parsed = parse_oracle_intent(intent)
    if parsed is None or not config.audit.oracles.enabled or not intent.from_:
        return "failed"
    name, role = parsed
    candidate_id = intent.from_[0]
    lease = HeartbeatLease.for_intent(client, project.project.id, intent.id, worker.name, config.runtime.interval)
    lease.start()
    process = None
    run = None
    handle = None
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    result = ProcessResult(1, "", "oracle setup did not complete")
    finalized = False
    process_started = False
    builtin = _OracleWorker(name=worker.name)
    try:
        catalog = OracleCatalog.model_validate_json(config.audit.oracles.catalog_path.read_bytes())
        definition = catalog.bound_definition(project.project.id, candidate_id, project.project.source_generation, project.project.plan_revision)
        if definition.id != name:
            raise ValueError("Intent differs from the operator-approved oracle binding")
        handle = backend.ensure_running(project.project.id)
        source, snapshot = select_snapshot(project, candidate_id, Path(handle))
        if snapshot.get("id") != definition.source_digest:
            raise ValueError("Oracle source digest does not match the candidate's frozen source")
        key = f"oracle:{project.project.id}:{intent.id}:{name}:{role}:g{project.project.source_generation}:p{project.project.plan_revision}:a{attempt}"
        run_id = "run-" + uuid.uuid5(uuid.NAMESPACE_URL, key).hex
        manifest = WorkerManifest(runtime="builtin-oracle", project_id=project.project.id, intent_id=intent.id, run_id=run_id,
                                  recipe=RecipeRef(id="registered-oracle", digest="sha256:" + oracle_checker_digest()))
        timeout = cancellation.clamp_timeout(min(definition.timeout_seconds, config.tasks.explore.timeout))
        run = RunEnvelope(run_id=run_id, project_id=project.project.id, intent_id=intent.id, task_type="poc:oracle",
                          stage=f"oracle-{role}", attempt=attempt, idempotency_key=key,
                          graph_revision=project.project.graph_revision, source_generation=project.project.source_generation,
                          plan_revision=project.project.plan_revision, worker_manifest_digest=manifest.manifest_digest,
                          timeout_seconds=timeout, worker_name=worker.name, worker_type="builtin-oracle",
                          status="running", started_at=started.isoformat().replace("+00:00", "Z"))
        registered = client.register_run(run)
        if not isinstance(registered, RunEnvelope) or registered.status != "running":
            raise ValueError("Oracle attempt could not be registered as a fresh running attempt")
        run = registered
        process = RegisteredOracleProcess(definition, role, source, snapshot, Path(handle) / ".linen-oracles" / run_id,
                                          project_id=project.project.id, candidate_id=candidate_id, run_id=run_id,
                                          source_generation=project.project.source_generation, plan_revision=project.project.plan_revision,
                                          timeout_seconds=timeout)
        if not cancellation.start_process(process):
            result = ProcessResult(130, "", "", cancelled=True, cancel_reason=cancellation.reason)
        else:
            process_started = True
            lease.attach_process(process)
            result = process.communicate(timeout)
        if cancellation.is_cancelled or lease.failure is not None:
            reason = cancellation.reason or HeartbeatLease._cancel_reason(lease.failure)
            result = ProcessResult(130, result.stdout, result.stderr, cancelled=True, cancel_reason=reason)
        if result.returncode != 0 or result.cancelled or result.timed_out or process.receipt is None:
            if result.cancelled:
                return "cancelled"
            client.report_intent_error(
                project.project.id, intent.id, worker.name, task_type="explore",
                code="independent_oracle_failed", classification="blocked",
                message=result.stderr[:2000] or "Registered oracle did not produce a valid bounded observation",
                remediation="Inspect the registered target and control. Crashes, timeouts and malformed observations cannot serve as negative evidence.",
            )
            return "blocked"
        receipt = process.receipt
        path = Path(handle) / ".linen-oracles" / run_id / "observation.json"
        artifact = ArtifactMetadata(artifact_id="oracle-observation-" + run_id, project_id=project.project.id,
                                    kind="independent-oracle-observation", workspace_path=path.relative_to(handle).as_posix(),
                                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(), media_type="application/json",
                                    byte_size=path.stat().st_size, producer_run_id=run_id, related_node_ids=[candidate_id, intent.id])
        response = client.register_artifact(artifact)
        if not isinstance(response, ArtifactMetadata):
            raise ValueError("Independent oracle artifact registration failed")
        run = run.model_copy(update={"artifact_ids": [artifact.artifact_id]})
        record = _write_execution_record(backend, handle, builtin, ["builtin-oracle", name, role], "oracle_execute", started,
                                         int((time.perf_counter() - clock) * 1000), run.timeout_seconds, result,
                                         run_envelope=run, worker_manifest=manifest, recipe_content_digest=manifest.recipe.digest,
                                         process_started=True)
        artifacts = _register_execution_artifacts(client, run, backend, handle, record)
        run = run.model_copy(update={"artifact_ids": [*run.artifact_ids, *artifacts]})
        _finish_contract_run(client, run, result, phase="oracle_execute")
        finalized = True
        # Publish only observations from the trusted transport process, never
        # values copied from a model response or generated PoC printout.
        proof_kind = "reproduction" if role == "positive" else "negative_control"
        proof = {"schema_version": 1, "claim_kind": proof_kind, "subject_ids": [candidate_id],
                 "attributes": {"mode": "dynamic", "candidate_id": candidate_id, "run_id": run_id,
                                "artifact_ids": [artifact.artifact_id], "oracle_kind": definition.id,
                                "observed_outcome": receipt["raw_observation"], "capability_observed": receipt["capability_observed"],
                                "snapshot_id": snapshot["id"], "harness_id": definition.id,
                                "config_fingerprint": definition.canonical_digest()}}
        return write_conclude_result(client, project.project.id, intent.id, worker.name,
                                     f"Independent registered {role} observation for {candidate_id}; capability={receipt['capability_observed']}",
                                     source="registered_independent_oracle", phase_ms=int((time.perf_counter() - clock) * 1000),
                                     fact_type=proof_kind, evidence=f"artifact: {path}\nmanifest_sha256: {artifact.sha256}\nsnapshot: {snapshot['id']}",
                                     fact_status="draft", proof=proof)
    except Exception as exc:
        result = ProcessResult(1, "", f"IndependentOracleExecutionFailed: {type(exc).__name__}: {exc}")
        client.report_intent_error(project.project.id, intent.id, worker.name, task_type="explore", code="independent_oracle_failed",
                                   classification="blocked", message=str(exc)[:2000], remediation="Inspect the approved catalog, source digest, offline image and raw observer records. Host fallback is disabled.")
        return "blocked"
    finally:
        lease.stop()
        if process is not None:
            process.kill()
        cancellation.attach_process(None)
        if run is not None and handle is not None and not finalized:
            record = _write_execution_record(backend, handle, builtin, ["builtin-oracle", name, role], "oracle_execute", started,
                                             int((time.perf_counter() - clock) * 1000), run.timeout_seconds, result,
                                             run_envelope=run, worker_manifest=manifest, recipe_content_digest=manifest.recipe.digest,
                                             process_started=process_started)
            artifacts = _register_execution_artifacts(client, run, backend, handle, record)
            run = run.model_copy(update={"artifact_ids": [*run.artifact_ids, *artifacts]})
            _finish_contract_run(client, run, result, phase="oracle_execute")
        best_effort_release(client, project.project.id, intent.id, worker.name)
