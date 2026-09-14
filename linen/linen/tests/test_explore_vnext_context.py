from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FakeClient, FakeContainerManager, FakeDriver, FakeLease, make_config, make_intent, make_project
from linen.contracts import BlackboardSnapshot, ContextProjection
from linen.dispatcher.protocol.client import ApiResult
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.tasks import explore


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
    def __init__(self, root: Path):
        super().__init__()
        self.root = root

    def ensure_running(self, project_id: str) -> str:
        return str(self.root)

    def build_exec_process(self, container_name, env, command, timeout_seconds=None, kill_after_seconds=5):
        return _Process(self.result)

    def set_result(self, result: ProcessResult) -> None:
        self.result = result

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        if path.startswith("/tmp/linen-prompts/"):
            self.writes.append((container_name, path, content))
            return
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


class _ContractClient(FakeClient):
    def __init__(self, project):
        super().__init__(project)
        self.projections: list[ContextProjection] = []
        self.runs = []
        self.transitions = []

    def get_snapshot(self, _project_id: str) -> BlackboardSnapshot:
        from linen.dispatcher.contract_adapters import project_detail_to_snapshot

        return project_detail_to_snapshot(self.project, created_at="2026-01-01T00:00:00Z")

    def list_artifacts(self, _project_id: str) -> list:
        return []

    def register_context_projection(self, projection: ContextProjection):
        self.projections.append(projection)
        return projection

    def register_run(self, run):
        self.runs.append(run)
        return run

    def transition_run(self, run):
        self.transitions.append(run)
        return run


def _lease_factory(lease):
    return lambda *_args, **_kwargs: lease


def _context_required(node_id: str = "f002", reason: str = "need more context") -> ProcessResult:
    return ProcessResult(
        0,
        json.dumps({
            "accepted": True,
            "data": {
                "status": "context_required",
                "context_request": {"node_ids": [node_id], "reason": reason},
            },
        }),
        "",
    )


def _final_fact(description: str = "final explore fact") -> ProcessResult:
    return ProcessResult(0, json.dumps({"accepted": True, "data": {"description": description}}), "")


def _run(monkeypatch, tmp_path, project, results, *, config=None, client=None):
    config = config or make_config()
    if not any(fact.id == "f002" for fact in project.facts):
        project = project.model_copy(update={
            "facts": [
                *project.facts,
                project.facts[0].model_copy(update={
                    "id": "f002", "description": "expanded context fact",
                }),
            ],
        })
    client = client or _ContractClient(project)
    backend = _Backend(tmp_path)
    driver = _SequenceDriver()
    lease = FakeLease()
    calls = []
    values = iter(results)

    monkeypatch.setattr(explore, "get_driver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(explore.HeartbeatLease, "for_intent", _lease_factory(lease))

    def run_process(*_args, **kwargs):
        calls.append(kwargs)
        result = next(values)
        backend.set_result(result)
        return result

    monkeypatch.setattr(explore, "_run_process", run_process)
    outcome = explore.run_explore_task(
        config,
        client,
        backend,
        project,
        "FULL-EXPORT-MUST-NOT-REACH-WORKER",
        project.intents[0],
        config.workers[0],
        TaskCancellation(),
        attempt=3,
        trigger="manual",
    )
    return outcome, client, backend, driver, calls


def test_explore_context_required_runs_one_cold_continuation_and_concludes(tmp_path, monkeypatch) -> None:
    intent = make_intent()
    project = make_project(intents=[intent])
    outcome, client, backend, driver, calls = _run(
        monkeypatch,
        tmp_path,
        project,
        [_context_required(), _final_fact()],
    )

    assert outcome == "success"
    assert len(calls) == 2
    assert [call["phase"] for call in calls] == [
        "explore_execute", "explore_context_continuation",
    ]
    assert calls[0]["run_envelope"].run_id != calls[1]["run_envelope"].run_id
    assert calls[0]["run_envelope"].attempt == calls[1]["run_envelope"].attempt == 3
    assert driver.sessions == ["session-1", "session-2"]
    assert len(client.projections) == 2
    assert client.concluded == [("proj_001", "i001", "test-worker", "final explore fact")]
    assert "FULL-EXPORT-MUST-NOT-REACH-WORKER" not in driver.execute_prompts[1]
    assert "one permitted context continuation" in driver.execute_prompts[1]
    assert any("explore_context_continuation-" in path for _, path, _ in backend.writes)


def test_explore_context_required_is_allowed_for_ordinary_scope_audit_intent(tmp_path, monkeypatch) -> None:
    config = make_config()
    config.audit.enabled = True
    project = make_project(intents=[make_intent()])
    project.project.audit_mode = "scope"
    outcome, client, _, driver, calls = _run(
        monkeypatch,
        tmp_path,
        project,
        [_context_required(), _final_fact("scope fact")],
        config=config,
    )

    assert outcome == "success"
    assert len(calls) == 2
    assert client.concluded[-1][-1] == "scope fact"
    assert "one permitted context continuation" in driver.execute_prompts[1]


@pytest.mark.parametrize("restricted", ["coverage", "scope_adjudication", "semantic_recipe", "poc_isolated"])
def test_explore_managed_and_isolated_paths_reject_context_required_without_second_run(
    restricted, tmp_path, monkeypatch,
) -> None:
    config = make_config()
    project = make_project(intents=[make_intent()])
    if restricted == "coverage":
        config.audit.enabled = True
        project.project.audit_mode = "scope"
        project.intents[0].description = "@coverage:plan:cell"
        monkeypatch.setattr(explore.coverage, "execution_prompt", lambda *_args, **_kwargs: "coverage prompt")
    elif restricted == "scope_adjudication":
        config.audit.enabled = True
        config.audit.scope_adjudication.enabled = True
        project.project.audit_mode = "scope"
        project.intents[0].creator = "dispatcher.audit"
        project.intents[0].type = "verify"
        project.intents[0].description = "@analysis:scope-adjudication"
        monkeypatch.setattr(
            explore.scope_gate,
            "execution_prompt",
            lambda *_args, **_kwargs: ("adjudication prompt", "scope_adjudication", type("Recipe", (), {"label": "x", "version": 1})()),
        )
    elif restricted == "semantic_recipe":
        config.audit.enabled = True
        config.audit.semantic.enabled = True
        project.project.audit_mode = "scope"
        project.intents[0].creator = "dispatcher.audit"
        project.intents[0].type = "search"
        project.intents[0].description = "@analysis:semantic:architecture_map:v1"
        monkeypatch.setattr(
            explore.audit_recipes,
            "parse_recipe_intent",
            lambda *_args, **_kwargs: ("architecture_map", type("Recipe", (), {"label": "x", "version": 1})(), None),
        )
        monkeypatch.setattr(
            explore.audit_recipes,
            "execution_prompt",
            lambda *_args, **_kwargs: ("semantic prompt", "architecture_map", type("Recipe", (), {"label": "x", "version": 1})()),
        )
    else:
        config.audit.poc_sandbox.enabled = True
        project.intents[0].type = "poc:isolated"
        project.intents[0].from_ = ["f001"]
        monkeypatch.setattr(explore, "select_snapshot", lambda *_args, **_kwargs: ("source", {"id": "snapshot"}))
        monkeypatch.setattr(explore, "ReviewSandboxBackend", lambda *args, **kwargs: object())

    outcome, client, _, _, calls = _run(
        monkeypatch,
        tmp_path,
        project,
        [_context_required()],
        config=config,
    )

    assert outcome == "failed"
    assert len(calls) == 1
    assert client.concluded == []


@pytest.mark.parametrize("message,expected", [("rate limit", "rate_limited"), ("insufficient_quota", "quota_exhausted")])
def test_explore_context_continuation_propagates_provider_outcome(tmp_path, monkeypatch, message, expected) -> None:
    project = make_project(intents=[make_intent()])
    provider_result = ProcessResult(1, "", message)
    outcome, client, _, _, calls = _run(
        monkeypatch,
        tmp_path,
        project,
        [_context_required(), provider_result],
    )

    assert outcome == expected
    assert len(calls) == 2
    assert client.concluded == []


def test_explore_context_continuation_rejects_second_request_without_blackboard_write(tmp_path, monkeypatch) -> None:
    project = make_project(intents=[make_intent()])
    outcome, client, _, driver, calls = _run(
        monkeypatch,
        tmp_path,
        project,
        [_context_required(), _context_required("f001", "second request")],
    )

    assert outcome == "failed"
    assert len(calls) == 2
    assert driver.sessions == ["session-1", "session-2"]
    assert client.concluded == []
