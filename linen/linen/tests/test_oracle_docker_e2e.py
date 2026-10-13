"""Opt-in real Docker transport and dispatcher/API publication; no LLM calls."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from linen.contracts.oracle import OracleDefinition
from linen.dispatcher.analysis.artifacts import snapshot_source, digest
from linen.dispatcher.analysis.oracle_review import oracle_review_record
from linen.dispatcher.config import ReconConfig, OracleConfig
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.tasks.oracle import run_oracle_task
from linen.server import db, oracle_registry
from linen.server.routers import executions
from linen.server.dynamic_verification import evaluate_dynamic_verification
from test_audit_pipeline import api, config
from test_uvpg import _strict_board


pytestmark = pytest.mark.skipif(os.environ.get("LINEN_ORACLE_DOCKER_E2E") != "1", reason="opt-in real offline Docker oracle")


@pytest.mark.parametrize("bad_baseline,cancel_before_start", [(False, False), (True, False), (False, True)])
def test_real_probe_publishes_registered_runs_and_independent_evidence(api, tmp_path, monkeypatch, bad_baseline, cancel_before_start):
    _, client = api
    _strict_board(tmp_path, monkeypatch)
    source = tmp_path / "target"
    source.mkdir()
    (source / "server.py").write_text(
        "from http.server import BaseHTTPRequestHandler,HTTPServer\nimport json,sys\n"
        "with open(sys.argv[1]) as f: case=json.load(f)\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  data={'resource':'protected:B'} if case['allow'] else {'error':'denied'}\n"
        "  self.send_response(200 if case['allow'] else case.get('status',403));self.end_headers();self.wfile.write(json.dumps(data).encode())\n"
        " def log_message(self,*args): pass\n"
        "HTTPServer(('127.0.0.1',8073),Handler).serve_forever()\n"
    )
    workspaces = tmp_path / "workspaces"
    workdir = workspaces / "p"
    directory = workdir / ".linen-recon/test"
    directory.mkdir(parents=True)
    snapshot = snapshot_source(source, directory / "source", ReconConfig(), directory)
    manifest = directory / "snapshot.json"
    manifest.write_text(json.dumps({"snapshot": snapshot}))
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET repo_root = ? WHERE id = 'p'", (str(source),))
        conn.execute("INSERT INTO facts (id,project_id,description,type,evidence) VALUES ('snapshot','p','frozen','recon_snapshot',?)",
                     (f"artifact: {manifest}\nmanifest_sha256: {digest(manifest.read_bytes())}",))
        conn.execute("INSERT INTO intents (id,project_id,to_fact_id,description,creator,created_at,concluded_at) VALUES ('fixture-source','p','candidate','source binding','fixture','now','now')")
        conn.execute("INSERT INTO intent_sources (intent_id,project_id,fact_id) VALUES ('fixture-source','p','snapshot')")
    definition = OracleDefinition(id="resource-read", source_digest=snapshot["id"], image="python:3.12-slim-bookworm",
                                  target_argv=["python3", "-I", "/repo/server.py", "/input/oracle_case.json"],
                                  positive={"request": {"path": "/"}, "target_data": {"allow": True}},
                                  negative={"request": {"path": "/"}, "target_data": {"allow": False, "status": 500 if bad_baseline else 403}},
                                  predicate={"kind": "json_equals", "json_pointer": "/resource", "expected": "protected:B"},
                                  rationale="Matched access guard control for the same protected resource.", timeout_seconds=20)
    catalog = tmp_path / "operator-catalog.json"
    catalog.write_text(json.dumps({"definitions": [definition.model_dump()], "bindings": [{"project_id": "p", "candidate_id": "candidate", "oracle_id": definition.id, "source_generation": 1, "plan_revision": 1}]}))
    monkeypatch.setattr(oracle_registry, "_catalog_path", catalog)
    monkeypatch.setattr(executions, "_workspace_root_override", workspaces)
    cfg = config(tmp_path)
    cfg.local.workspace_root = str(workspaces)
    cfg.audit.oracles = OracleConfig(enabled=True, catalog_path=catalog)
    backend = LocalBackend(cfg.local, client)
    for role in ("negative", "positive"):
        created = client.plan_proof_gap("p", "candidate")
        assert created.ok, created.text
        assert created.data["created_intent"], created.data
        iid = created.data["intent_id"]
        assert client.heartbeat("p", iid, "tester").ok
        project = client.get_project("p")
        intent = next(item for item in project.intents if item.id == iid)
        assert intent.description.startswith("@uvpg:proof:")
        assert intent.description.endswith(f"@oracle:{definition.id}:{role}")
        cancellation = TaskCancellation()
        if cancel_before_start:
            cancellation.cancel("audit_wall_clock_budget_exhausted")
        outcome = run_oracle_task(cfg, client, backend, project, intent, cfg.workers[0], cancellation)
        if cancel_before_start:
            assert outcome == "cancelled"
            runs = client.list_runs("p")
            assert len(runs) == 1 and runs[0].status == "cancelled"
            assert not list(workdir.rglob("observation.json"))
            assert next(item for item in client.get_project("p").intents if item.id == iid).to is None
            return
        if bad_baseline:
            assert outcome == "blocked"
            runs = client.list_runs("p")
            assert len(runs) == 1 and runs[0].status == "failed"
            failed = client.get_project("p")
            assert any(error.code == "independent_oracle_failed" and error.classification == "blocked" for error in failed.errors)
            assert next(item for item in failed.intents if item.id == iid).to is None
            return
        assert outcome == "success"
        current = client.get_project("p")
        fact = next(item for item in current.facts if item.id == next(item.to for item in current.intents if item.id == iid))
        packet = oracle_review_record(cfg.audit.oracles, client, current, fact, workdir)
        assert packet["observation"]["role"] == role
        assert packet["definition"]["rationale"] == definition.rationale
        assert set(packet) == {"kind", "definition", "observation"}
        assert client.create_review("p", fact.id, "VALID", "Raw independent witness checked", confidence="firm").ok
    runs = client.list_runs("p")
    assert len(runs) == 2 and all(run.status == "succeeded" and run.worker_type == "builtin-oracle" for run in runs)
    with db.get_conn() as conn:
        result = evaluate_dynamic_verification(conn, "p", "candidate")
    assert result.status == "PASS", result.reason_codes
    assert result.receipt["independent_oracle"]["id"] == definition.id
