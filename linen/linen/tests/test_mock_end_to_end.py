from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import threading
from typing import Any

from fastapi.testclient import TestClient
from pydantic import TypeAdapter
import pytest

from linen.dispatcher.config import DispatchConfig
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.server import db
from linen.server.app import app
from linen.server.models import ProjectDetail, ProjectSummary, Settings


class InProcessClient:
    def __init__(self, http: TestClient):
        self.http = http
        self._summaries = TypeAdapter(list[ProjectSummary])

    def close(self) -> None:
        return None

    def list_projects(self) -> list[ProjectSummary]:
        response = self.http.get("/projects")
        response.raise_for_status()
        return self._summaries.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self.http.get(f"/projects/{project_id}")
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_settings(self) -> Settings:
        response = self.http.get("/settings")
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def export_project(self, project_id: str) -> str:
        response = self.http.get(f"/projects/{project_id}/export?format=yaml")
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/intents/{intent_id}/heartbeat", {"worker": worker})

    def claim_reason(self, project_id: str, worker: str, lease_id: str, trigger: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/reason/claim",
            {"worker": worker, "lease_id": lease_id, "trigger": trigger},
        )

    def reason_heartbeat(self, project_id: str, worker: str, lease_id: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/reason/heartbeat",
            {"worker": worker, "lease_id": lease_id},
        )

    def release_reason(self, project_id: str, worker: str, lease_id: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/reason/release",
            {"worker": worker, "lease_id": lease_id},
        )

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._post(f"/projects/{project_id}/intents/{intent_id}/release", {"worker": worker})

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
    ) -> ApiResult:
        payload: dict[str, Any] = {
            "worker": worker,
            "description": description,
            "status": status,
        }
        if fact_type is not None:
            payload["type"] = fact_type
        if evidence is not None:
            payload["evidence"] = evidence
        return self._post(
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            payload,
        )

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._post(
            f"/projects/{project_id}/complete",
            {"from": from_ids, "description": description, "worker": worker},
        )

    def create_intent(
        self,
        project_id: str,
        from_ids: list[str],
        description: str,
        creator: str,
        *,
        intent_type: str | None = None,
        display_title: str | None = None,
        semantic_type: str | None = None,
        relation_type: str | None = None,
        phase: str | None = None,
    ) -> ApiResult:
        payload: dict[str, Any] = {
            "from": from_ids,
            "description": description,
            "creator": creator,
            "worker": None,
        }
        if intent_type is not None:
            payload["type"] = intent_type
        if display_title is not None:
            payload["display_title"] = display_title
        if semantic_type is not None:
            payload["semantic_type"] = semantic_type
        if relation_type is not None:
            payload["relation_type"] = relation_type
        if phase is not None:
            payload["phase"] = phase
        return self._post(
            f"/projects/{project_id}/intents",
            payload,
        )

    def _post(self, path: str, payload: dict[str, Any]) -> ApiResult:
        response = self.http.post(path, json=payload)
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else None
        return ApiResult(response.status_code, data, response.text)


class LocalProcess:
    def __init__(self, command: list[str], env: dict[str, str]):
        self.command = command
        self.env = env
        self._process: subprocess.Popen[str] | None = None
        self._cancel_reason: str | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            self._process = subprocess.Popen(
                self.command,
                env={**os.environ, **self.env},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._process is not None
        timed_out = False
        try:
            stdout, stderr = self._process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.kill()
            stdout, stderr = self._process.communicate()
        return ProcessResult(
            returncode=self._process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            cancelled=self._cancel_reason is not None,
            cancel_reason=self._cancel_reason,
        )

    def kill(self) -> None:
        with self._lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.kill()

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self.kill()


class LocalContainerManager:
    def __init__(self) -> None:
        self.writes: list[tuple[str, str, str]] = []

    def close(self) -> None:
        return None

    def container_name(self, project_id: str) -> str:
        return f"local-{project_id}"

    def ensure_running(self, project_id: str) -> str:
        return self.container_name(project_id)

    def build_exec_process(
        self,
        _container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> LocalProcess:
        assert timeout_seconds is not None
        assert kill_after_seconds == 5
        return LocalProcess(command, env)

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        self.writes.append((container_name, path, content))

    def needs_completed_cleanup(self, _project_id: str) -> bool:
        return False

    def needs_stopped_cleanup(self, _project_id: str) -> bool:
        return False

    def managed_container_names(self) -> list[str]:
        return []


@pytest.fixture
def http_client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as client:
        yield client


def _phase(
    outcome: str,
    *,
    rules: list[dict[str, Any]] | None = None,
    zero_outcomes: list[str] | None = None,
) -> str:
    outcomes = {name: 0 for name in zero_outcomes or []}
    outcomes[outcome] = 1
    payload: dict[str, Any] = {"delay": [0, 0], "outcomes": outcomes}
    if rules is not None:
        payload["rules"] = rules
    return json.dumps(payload)


def _config(
    *,
    reason: str,
    explore: str,
    task_types: list[str] | None = None,
    worker_healthcheck: str = "startup_only",
    healthcheck: str | None = None,
) -> DispatchConfig:
    return DispatchConfig.model_validate(
        {
            "server": "in-process",
            "runtime": {
                "interval": 1,
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 2,
                "worker_healthcheck": worker_healthcheck,
                "prompt_group": "mock",
            },
            "tasks": {
                "reason": {"timeout": 2, "max_intents": 1},
                "explore": {"timeout": 2, "conclude_timeout": 2},
            },
            "workers": [
                {
                    "name": "mock-worker",
                    "type": "mock",
                    "task_types": task_types or ["reason", "explore"],
                    "max_running": 1,
                    "priority": 0,
                    "env": {
                        "MOCK_HEALTHCHECK": healthcheck or _phase("ok"),
                        "MOCK_REASON": reason,
                        "MOCK_EXPLORE_EXECUTE": explore,
                    },
                }
            ],
        }
    )


def _loop(config: DispatchConfig, client: InProcessClient, containers: LocalContainerManager) -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = config
    loop.client = client
    loop.container_manager = containers
    loop.executor = ThreadPoolExecutor(max_workers=config.runtime.max_workers)
    loop.cleanup_executor = ThreadPoolExecutor(max_workers=1)
    loop.futures = {}
    loop.cleanup_futures = {}
    loop.runtime_project_ids = set()
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop._log_state = {}
    loop._cleanup_pending = set()
    loop._inactive_cleanup_done = {}
    loop.project_cursor = 0
    return loop


def _dispatch_and_wait(loop: DispatcherLoop) -> None:
    loop._reap_futures()
    summaries = loop.client.list_projects()
    loop._refresh_runtime_projects(summaries)
    loop._cancel_inactive_tasks(summaries)
    loop._queue_container_cleanups(summaries)
    loop._dispatch_available(summaries)
    assert loop.futures
    for future in list(loop.futures):
        future.result(timeout=5)
    loop._reap_futures()


def _create_project(http: TestClient) -> str:
    response = http.post(
        "/projects",
        json={"title": "integration", "origin": "start", "goal": "finish"},
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def test_task_healthcheck_healthy_worker_completes_end_to_end(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = _loop(
        _config(
            reason=_phase("complete", zero_outcomes=["intent"]),
            explore=_phase("fact"),
            worker_healthcheck="startup_and_task",
        ),
        client,
        containers,
    )
    project_id = _create_project(http_client)

    try:
        _dispatch_and_wait(loop)
        project = client.get_project(project_id)
    finally:
        loop.close()

    # code-based check_health runs before the first Reason task and passes.
    assert project.project.status == "completed"


def test_task_healthcheck_failure_aborts_task_and_cools_down_worker(http_client: TestClient) -> None:
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = _loop(
        _config(
            reason=_phase("complete", zero_outcomes=["intent"]),
            explore=_phase("fact"),
            worker_healthcheck="startup_and_task",
            healthcheck=_phase("fail", zero_outcomes=["ok"]),
        ),
        client,
        containers,
    )
    project_id = _create_project(http_client)

    try:
        _dispatch_and_wait(loop)
        project = client.get_project(project_id)
    finally:
        loop.close()

    # unhealthy worker -> task aborted before execution, no facts written, worker put on cooldown
    assert project.project.status == "active"
    assert [fact.id for fact in project.facts] == ["origin", "goal"]
    assert "mock-worker" in loop.worker_unhealthy_until


def _failover_config() -> DispatchConfig:
    def worker(name: str, healthcheck: str) -> dict:
        return {
            "name": name,
            "type": "mock",
            "task_types": ["reason", "explore"],
            "max_running": 1,
            "env": {
                "MOCK_HEALTHCHECK": healthcheck,
                "MOCK_REASON": _phase("complete", zero_outcomes=["intent"]),
                "MOCK_EXPLORE_EXECUTE": _phase("fact"),
            },
        }

    return DispatchConfig.model_validate(
        {
            "server": "in-process",
            "runtime": {
                "interval": 1,
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 2,
                "worker_healthcheck": "startup_and_task",
                "prompt_group": "mock",
            },
            "tasks": {
                "reason": {"timeout": 2, "max_intents": 1},
                "explore": {"timeout": 2, "conclude_timeout": 2},
            },
            "workers": [
                worker("bad", _phase("fail", zero_outcomes=["ok"])),
                worker("good", _phase("ok")),
            ],
        }
    )


def test_unhealthy_worker_fails_over_to_healthy_worker(
    http_client: TestClient, monkeypatch,
) -> None:
    monkeypatch.setattr(
        "linen.dispatcher.scheduler.loop.choose_worker",
        lambda candidates, _running: sorted(candidates, key=lambda worker: worker.name),
    )
    client = InProcessClient(http_client)
    containers = LocalContainerManager()
    loop = _loop(_failover_config(), client, containers)
    project_id = _create_project(http_client)

    try:
        # The controlled tie order picks 'bad' first; health check failure puts it on cooldown.
        _dispatch_and_wait(loop)
        assert "bad" in loop.worker_unhealthy_until
        assert client.get_project(project_id).project.status == "active"

        # round 2: 'bad' still cooling down -> 'good' takes over and completes the project
        _dispatch_and_wait(loop)
        project = client.get_project(project_id)
    finally:
        loop.close()

    assert project.project.status == "completed"
    assert any(intent.worker == "good" for intent in project.intents)
