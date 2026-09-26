from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from linen.dispatcher.analysis import codeql
from linen.dispatcher.config import DispatchConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.dispatcher.tasks.explore import run_explore_task
from linen.server import db
from linen.server.app import app


@pytest.mark.skipif(
    not os.environ.get("LINEN_CODEQL_TEST_IMAGE")
    or not os.environ.get("LINEN_CODEQL_TEST_SUITE"),
    reason="set LINEN_CODEQL_TEST_IMAGE and LINEN_CODEQL_TEST_SUITE for Docker E2E",
)
def test_codeql_candidate_reaches_persisted_graph_and_reason(tmp_path, monkeypatch):
    """Exercise the real Docker scanner, Linen API write, and Reason reader."""
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.sqlite")
    repository = tmp_path / "repo"
    (repository / "app").mkdir(parents=True)
    (repository / "app" / "__init__.py").write_text("", encoding="utf-8")
    (repository / "app" / "source.py").write_text(
        "def get_user_input():\n    return input('search: ')\n",
        encoding="utf-8",
    )
    (repository / "app" / "service.py").write_text(
        "import sqlite3\nfrom app.source import get_user_input\n"
        "def lookup(connection: sqlite3.Connection):\n"
        "    value = get_user_input()\n"
        "    connection.execute(\"SELECT * FROM users WHERE name = '\" + value + \"'\")\n",
        encoding="utf-8",
    )

    config = DispatchConfig.model_validate({
        "server": "http://testserver",
        "runtime": {
            "interval": 60, "max_workers": 1, "max_running_projects": 1,
            "max_project_workers": 1, "healthcheck_timeout": 5,
            "prompt_group": "vuln_audit",
        },
        "tasks": {
            "explore": {"timeout": 1800, "conclude_timeout": 300},
            "reason": {"timeout": 30, "conclude_timeout": 30},
            "review": {"timeout": 30, "conclude_timeout": 30},
        },
        "local": {"workspace_root": str(tmp_path / "workspaces")},
        "workers": [{
            "name": "codeql-e2e", "type": "pi",
            "task_types": ["explore", "reason", "review"], "max_running": 1,
        }],
        "audit": {
            "enabled": True,
            "mode": "scope",
            "recon": {"enabled": True, "categories": ["dangerous-api"]},
            "codeql": {
                "enabled": True,
                "terms_acknowledged": True,
                "image": os.environ["LINEN_CODEQL_TEST_IMAGE"],
                "network": "none",
                "languages": ["python"],
                "query_suites": {
                    "python": [os.environ["LINEN_CODEQL_TEST_SUITE"]],
                },
                "query_profiles": {
                    "input-validation": {
                        "python": [os.environ["LINEN_CODEQL_TEST_SUITE"]],
                    },
                },
            },
        },
    })

    with TestClient(app) as http:
        client = LinenClient("http://testserver")
        monkeypatch.setattr(client, "_session", lambda: http)
        created = http.post("/projects", json={
            "title": "CodeQL Docker E2E",
            "origin": "local fixture",
            "goal": "verify CodeQL candidate flow",
            "audit_mode": "scope",
            "repo_root": str(repository),
        })
        assert created.status_code == 201, created.text
        project_id = created.json()["project"]["id"]
        backend = LocalBackend(config.local, client)
        worker = config.workers[0]
        dispatcher = object.__new__(DispatcherLoop)
        dispatcher.config = config
        dispatcher.client = client
        dispatcher.container_manager = backend

        project = client.get_project(project_id)
        assert dispatcher._materialize_audit_intents(project)
        project = client.get_project(project_id)
        snapshot_intent = next(
            item for item in project.intents
            if item.description == "@analysis:recon-snapshot"
        )
        assert client.heartbeat(project_id, snapshot_intent.id, worker.name).ok
        project = client.get_project(project_id)
        snapshot_task = next(item for item in project.intents if item.id == snapshot_intent.id)
        assert run_explore_task(
            config, client, backend, project, client.export_project(project_id),
            snapshot_task, worker, TaskCancellation(),
        ) == "success"

        project = client.get_project(project_id)
        snapshot_fact = next(fact for fact in project.facts if fact.type == "recon_snapshot")
        assert dispatcher._materialize_audit_intents(project)
        project = client.get_project(project_id)
        codeql_intent = next(item for item in project.intents if item.description == codeql.INTENT)
        assert codeql.active_for_project(project, config.audit.codeql)
        assert dispatcher._reconcile_audit_stages(project)
        project = client.get_project(project_id)
        assert any(stage.stage_id == "codeql-candidates" and stage.required for stage in project.stages)
        assert client.heartbeat(project_id, codeql_intent.id, worker.name).ok
        project = client.get_project(project_id)
        task = next(item for item in project.intents if item.id == codeql_intent.id)
        assert run_explore_task(
            config, client, backend, project, client.export_project(project_id),
            task, worker, TaskCancellation(),
        ) == "success"

        persisted = client.get_project(project_id)
        result_fact = next(
            fact for fact in persisted.facts
            if fact.type == "recon" and fact.description.startswith("CodeQL machine-path candidates:")
        )
        artifact_path = Path(result_fact.evidence.splitlines()[0].removeprefix("artifact: "))
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        workdir = Path(backend.ensure_running(project_id))
        reason_context = codeql.reason_instructions(persisted, workdir, config.audit.codeql)

        assert artifact["status"] == "complete"
        assert artifact["candidate_count"] >= 1
        assert any(
            "app/source.py" in lead["path"][0]
            and "app/service.py" in lead["path"][-1]
            for lead in artifact["leads"] if len(lead["path"]) >= 2
        )
        assert artifact["citations"]
        assert str(artifact_path).startswith(str(workdir / ".linen-codeql"))
        assert "CodeQL machine-path evidence" in reason_context
        assert "app/source.py" in reason_context and "app/service.py" in reason_context

        profile_data = {
            "from": [snapshot_fact.id, result_fact.id],
            "type": "search",
            "action": "search",
            "description": f"{codeql.QUERY_PREFIX}input-validation",
            "target": "codeql-query:input-validation:attempt:1",
        }
        assert codeql.validate_query_intent(
            persisted, config.audit.codeql, profile_data,
        ) == "input-validation"
        profile_intent = client.create_intent(
            project_id, profile_data["from"], profile_data["description"], "reasoner",
            action=profile_data["action"], target=profile_data["target"],
            intent_type=profile_data["type"],
        )
        assert profile_intent.ok, profile_intent.text
        profile_intent_id = profile_intent.data["id"]
        assert client.heartbeat(project_id, profile_intent_id, worker.name).ok
        persisted = client.get_project(project_id)
        profile_task = next(item for item in persisted.intents if item.id == profile_intent_id)
        assert run_explore_task(
            config, client, backend, persisted, client.export_project(project_id),
            profile_task, worker, TaskCancellation(),
        ) == "success"
        persisted = client.get_project(project_id)
        profile_result_intent = next(
            item for item in persisted.intents if item.id == profile_intent_id
        )
        profile_fact = next(fact for fact in persisted.facts if fact.id == profile_result_intent.to)
        profile_record = codeql.result_record(profile_fact, workdir)
        assert profile_record["query_category"] == "input-validation"
        assert profile_record["snapshot_fact_id"] == snapshot_fact.id
        assert profile_record["database_cache_id"] == artifact["database_cache_id"]
        assert "Category query results" in codeql.reason_instructions(
            persisted, workdir, config.audit.codeql,
        )
        assert dispatcher._reconcile_audit_stages(persisted)
        persisted = client.get_project(project_id)
        codeql_stage = next(
            stage for stage in persisted.stages if stage.stage_id == "codeql-candidates"
        )
        assert codeql_stage.status == "satisfied"
        backend.close()
