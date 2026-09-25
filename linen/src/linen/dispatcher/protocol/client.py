from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging
import threading

from pydantic import TypeAdapter
import requests
from requests.adapters import HTTPAdapter

from linen.server.models import (
    AuditEvent,
    AuditStage,
    CompletionGate,
    Intent,
    ProjectDetail,
    ProjectSummary,
    Settings,
)
from linen.contracts import (
    ArtifactMetadata,
    AuditEventEnvelope,
    BlackboardSnapshot,
    ContextProjection,
    RunEnvelope,
)

LOG = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, status_code: int, response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class ApiResult:
    status_code: int
    data: Any | None = None
    text: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class LinenClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._summary_adapter = TypeAdapter(list[ProjectSummary])
        self._audit_event_adapter = TypeAdapter(list[AuditEvent])
        self._local = threading.local()
        self._sessions: dict[int, requests.Session] = {}
        self._sessions_lock = threading.Lock()

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def list_projects(self) -> list[ProjectSummary]:
        response = self._session().get(self._url("/projects"), timeout=self._timeout)
        response.raise_for_status()
        return self._summary_adapter.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(self._url(f"/projects/{project_id}"), timeout=self._timeout)
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_audit_events(self, project_id: str, *, after: int = 0, limit: int = 2000) -> list[AuditEvent]:
        response = self._session().get(
            self._url(f"/projects/{project_id}/events"),
            params={"after": after, "limit": limit},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return self._audit_event_adapter.validate_python(response.json())

    def get_settings(self) -> Settings:
        response = self._session().get(self._url("/settings"), timeout=self._timeout)
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def get_snapshot(self, project_id: str) -> BlackboardSnapshot:
        """Fetch and validate the canonical Blackboard snapshot."""
        return self._contract_request(
            "GET", f"/projects/{project_id}/snapshot", model=BlackboardSnapshot,
        )

    # Noun-first alias used by dispatcher adapters.
    snapshot = get_snapshot

    def register_artifact(self, artifact: ArtifactMetadata) -> ArtifactMetadata | ApiResult:
        """Register immutable Artifact metadata; return ApiResult on HTTP failure."""
        return self._contract_request(
            "POST", f"/projects/{artifact.project_id}/artifacts",
            model=ArtifactMetadata, json=artifact.model_dump(mode="json"), strict=False,
        )

    create_artifact = register_artifact

    def get_artifact(self, project_id: str, artifact_id: str) -> ArtifactMetadata:
        return self._contract_request(
            "GET", f"/projects/{project_id}/artifacts/{artifact_id}", model=ArtifactMetadata,
        )

    def list_artifacts(self, project_id: str) -> list[ArtifactMetadata]:
        return self._contract_request(
            "GET", f"/projects/{project_id}/artifacts",
            model=TypeAdapter(list[ArtifactMetadata]),
        )

    def register_run(self, run: RunEnvelope) -> RunEnvelope | ApiResult:
        """Register one dispatcher attempt, including its running status."""
        return self._contract_request(
            "POST", f"/projects/{run.project_id}/runs", model=RunEnvelope,
            json=run.model_dump(mode="json"), strict=False,
        )

    create_run = register_run

    def get_run(self, project_id: str, run_id: str) -> RunEnvelope:
        return self._contract_request(
            "GET", f"/projects/{project_id}/runs/{run_id}", model=RunEnvelope,
        )

    def list_runs(self, project_id: str) -> list[RunEnvelope]:
        return self._contract_request(
            "GET", f"/projects/{project_id}/runs", model=TypeAdapter(list[RunEnvelope]),
        )

    def recover_runs(self, project_id: str) -> list[RunEnvelope]:
        """Mark orphaned running attempts interrupted during dispatcher recovery."""
        return self._contract_request(
            "POST", f"/projects/{project_id}/runs/recover",
            model=TypeAdapter(list[RunEnvelope]),
        )

    def transition_run(self, run: RunEnvelope) -> RunEnvelope | ApiResult:
        """Transition a run; server remains authoritative for the state machine."""
        return self._contract_request(
            "PUT", f"/projects/{run.project_id}/runs/{run.run_id}", model=RunEnvelope,
            json=run.model_dump(mode="json"), strict=False,
        )

    def register_context_projection(
        self, projection: ContextProjection,
    ) -> ContextProjection | ApiResult:
        return self._contract_request(
            "POST", f"/projects/{projection.project_id}/context-projections",
            model=ContextProjection, json=projection.model_dump(mode="json"), strict=False,
        )

    register_context = register_context_projection
    create_context_projection = register_context_projection

    def get_context_projection(self, project_id: str, projection_id: str) -> ContextProjection:
        return self._contract_request(
            "GET", f"/projects/{project_id}/context-projections/{projection_id}",
            model=ContextProjection,
        )

    def list_context_projections(self, project_id: str) -> list[ContextProjection]:
        return self._contract_request(
            "GET", f"/projects/{project_id}/context-projections",
            model=TypeAdapter(list[ContextProjection]),
        )

    list_contexts = list_context_projections

    def append_event(self, event: AuditEventEnvelope) -> AuditEventEnvelope | ApiResult:
        return self._contract_request(
            "POST", f"/projects/{event.project_id}/events", model=AuditEventEnvelope,
            json=event.model_dump(mode="json"), strict=False,
        )

    append_audit_event = append_event

    def get_completion_gate(
        self, project_id: str, from_ids: list[str] | None = None,
    ) -> CompletionGate:
        response = self._session().get(
            self._url(f"/projects/{project_id}/completion-gate"),
            params=[("from_id", fact_id) for fact_id in (from_ids or [])],
            timeout=self._timeout,
        )
        response.raise_for_status()
        return CompletionGate.model_validate(response.json())

    def get_proof_status(self, project_id: str, fact_id: str) -> ApiResult:
        return self._request_json("GET", f"/projects/{project_id}/facts/{fact_id}/proof-status", json={})

    def plan_proof_gap(self, project_id: str, fact_id: str) -> ApiResult:
        return self._request_json("POST", f"/projects/{project_id}/facts/{fact_id}/proof-gaps/plan", json={})

    def reconcile_audit_stages(
        self,
        project_id: str,
        stages: list[dict[str, Any]],
        *,
        source_generation: int,
        plan_revision: int,
        actor: str = "dispatcher",
    ) -> ApiResult:
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/stages",
            json={
                "stages": stages,
                "source_generation": source_generation,
                "plan_revision": plan_revision,
                "actor": actor,
            },
        )

    def list_audit_stages(self, project_id: str) -> list[AuditStage]:
        """Read the server-owned stage projection for reconciliation."""
        response = self._session().get(
            self._url(f"/projects/{project_id}/stages"), timeout=self._timeout,
        )
        response.raise_for_status()
        return TypeAdapter(list[AuditStage]).validate_python(response.json())

    def export_project(self, project_id: str) -> str:
        response = self._session().get(
            self._url(f"/projects/{project_id}/export"),
            params={"format": "yaml"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/heartbeat",
            json={"worker": worker},
        )

    def claim_reason(self, project_id: str, worker: str, lease_id: str, trigger: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/claim",
            json={"worker": worker, "lease_id": lease_id, "trigger": trigger},
        )

    def reason_heartbeat(self, project_id: str, worker: str, lease_id: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/heartbeat",
            json={"worker": worker, "lease_id": lease_id},
        )

    def release_reason(self, project_id: str, worker: str, lease_id: str, seen_event_seq: int | None = None) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/release",
            json={"worker": worker, "lease_id": lease_id, "seen_event_seq": seen_event_seq},
        )

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/release",
            json={"worker": worker},
        )

    def report_intent_error(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        *,
        task_type: str,
        code: str,
        classification: str,
        message: str,
        remediation: str | None = None,
        base_retry_seconds: int = 15,
        max_retry_seconds: int = 900,
        max_attempts: int = 5,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "worker": worker,
            "task_type": task_type,
            "code": code,
            "classification": classification,
            "message": message,
            "base_retry_seconds": base_retry_seconds,
            "max_retry_seconds": max_retry_seconds,
            "max_attempts": max_attempts,
        }
        if remediation is not None:
            body["remediation"] = remediation
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/fail",
            json=body,
        )

    def report_project_worker_issue(
        self,
        project_id: str,
        worker: str,
        task_type: str,
        code: str,
        message: str,
        remediation: str,
        intent_id: str | None = None,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/worker-issue",
            json={
                "worker": worker,
                "task_type": task_type,
                "code": code,
                "message": message,
                "remediation": remediation,
                "intent_id": intent_id,
            },
        )

    def retry_intent(
        self, project_id: str, intent_id: str, actor: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/retry",
            json={"actor": actor},
        )

    def resolve_intent(
        self, project_id: str, intent_id: str, actor: str, action: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/resolve",
            json={"actor": actor, "action": action},
        )

    def compact_coverage_intents(
        self,
        project_id: str,
        *,
        keep: int = 4,
        dry_run: bool = True,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/compact-coverage",
            json={"keep": keep, "dry_run": dry_run},
        )

    def conclude(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        description: str,
        *,
        fact_type: str | None = None,
        evidence: str | None = None,
        status: str = "draft",
        display_title: str | None = None,
        semantic_type: str | None = None,
        proof: dict[str, Any] | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "worker": worker,
            "description": description,
            "status": status,
        }
        if fact_type is not None:
            body["type"] = fact_type
        if evidence is not None:
            body["evidence"] = evidence
        if display_title is not None:
            body["display_title"] = display_title
        if semantic_type is not None:
            body["semantic_type"] = semantic_type
        if proof is not None:
            body["proof"] = proof
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            json=body,
        )

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/complete",
            json={"from": from_ids, "description": description, "worker": worker},
        )

    def create_review(
        self,
        project_id: str,
        fact_id: str,
        verdict: str,
        summary: str,
        *,
        confidence: str | None = None,
        reasoning: str | None = None,
        intent_id: str | None = None,
        created_by: str | None = None,
        diagnostics: dict[str, Any] | None = None,
    ) -> ApiResult:
        """Submit an adversarial Review for a fact. Returns ApiResult with
        the server-aggregated fact status in the response body."""
        body: dict[str, Any] = {
            "verdict": verdict,
            "summary": summary,
        }
        if confidence is not None:
            body["confidence"] = confidence
        if reasoning is not None:
            body["reasoning"] = reasoning
        if intent_id is not None:
            body["intent_id"] = intent_id
        if created_by is not None:
            body["created_by"] = created_by
        if diagnostics:
            from linen.server.models import ReviewDiagnostics
            body.update(ReviewDiagnostics.model_validate(diagnostics).model_dump(exclude_none=True))
        return self._request_json(
            "POST",
            f"/projects/{project_id}/facts/{fact_id}/reviews",
            json=body,
        )

    def create_hint(self, project_id: str, content: str, creator: str) -> ApiResult:
        return self._request_json(
            "POST", f"/projects/{project_id}/hints",
            json={"content": content, "creator": creator},
        )

    def create_intent(
        self,
        project_id: str,
        from_ids: list[str],
        description: str,
        creator: str,
        *,
        action: str | None = None,
        target: str | None = None,
        intent_type: str | None = None,
        display_title: str | None = None,
        semantic_type: str | None = None,
        relation_type: str | None = None,
        phase: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "from": from_ids,
            "description": description,
            "creator": creator,
            "worker": None,
        }
        if action is not None:
            body["action"] = action
        if target is not None:
            body["target"] = target
        if intent_type is not None:
            body["type"] = intent_type
        if display_title is not None:
            body["display_title"] = display_title
        if semantic_type is not None:
            body["semantic_type"] = semantic_type
        if relation_type is not None:
            body["relation_type"] = relation_type
        if phase is not None:
            body["phase"] = phase
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents",
            json=body,
        )

    def _request_json(self, method: str, path: str, json: dict[str, Any]) -> ApiResult:
        try:
            response = self._session().request(
                method,
                self._url(path),
                json=json,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            LOG.warning("request failed method=%s path=%s error=%s", method, path, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(status_code=response.status_code, data=data, text=response.text)

    def _contract_request(
        self,
        method: str,
        path: str,
        *,
        model: Any,
        json: dict[str, Any] | None = None,
        strict: bool = True,
    ) -> Any:
        """Decode successful vNext responses through their contract model.

        Read methods retain the existing client's raising behavior.  Write
        methods return ApiResult on HTTP failure so callers can log the
        protocol problem without changing the underlying Worker result.
        """
        result = self._request_json(method, path, json=json or {})
        if not result.ok:
            if strict:
                raise ProtocolError(
                    f"vNext request failed: {method} {path}", result.status_code, result.text,
                )
            return result
        try:
            return model.validate_python(result.data) if isinstance(model, TypeAdapter) else model.model_validate(result.data)
        except Exception as exc:
            raise ProtocolError(
                f"invalid vNext response: {method} {path}", result.status_code, result.text,
            ) from exc

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        with self._sessions_lock:
            self._sessions[threading.get_ident()] = session
        return session
