"""Review loop tests.

Covers the four boundaries that connect a candidate fact to a verdict and
back to the graph:
  1. validate_reason_payload accepts `intents[*].type` (review-typed intents
     pass the contract that reason.py will then dispatch to the scheduler).
  2. run_reason_task passes `intent_type` through to client.create_intent
     (so the scheduler's `if intent.type == "review"` branch in loop.py
     can route to `_dispatch_review`).
  3. The server's aggregate_fact_status_from_reviews flips fact.status on
     each verdict (VALID -> triaged, INVALID -> false_positive, a later
     decisive VALID resolves NEEDS_REVIEW, no reviews -> unchanged).
  4. End-to-end: create_project -> create_intent(type=review) ->
     create_review(VALID) -> fact.status flips to triaged, and the
     review intent is auto-concluded by the same write.

These tests are deliberately self-contained: they don't import
test_worker_tasks' broken conftest (which still uses the old
`container:` schema, predating the local-mode DispatchConfig).
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ---- Test 1 + 2: reason task contract + dispatcher pass-through ---------


def test_validate_reason_payload_preserves_intent_type():
    """A reason task may emit `intents[*].type = "review"`. The contract
    must not strip it, otherwise reason.py cannot forward it to
    client.create_intent(intent_type=...)."""
    from linen.dispatcher.contracts import validate_reason_payload

    payload = {
        "accepted": True,
        "data": {
            "intents": [
                {
                    "from": ["f001"],
                    "type": "review",
                    "description": "Adversarially review f001",
                },
                {
                    "from": ["f002", "f003"],
                    "type": "trace",
                    "description": "Trace from f002 to f003",
                },
            ]
        },
    }
    kind, data = validate_reason_payload(
        payload, open_intents_empty=False, max_intents=3,
    )
    assert kind == "intents"
    assert data is not None
    assert data[0]["type"] == "review"
    assert data[1]["type"] == "trace"


def test_run_reason_task_passes_intent_type_to_create_intent(monkeypatch):
    """run_reason_task must call client.create_intent(intent_type=...)
    for each emitted intent, so the server stores it on `intents.type`
    and the scheduler can route on it."""
    from linen.dispatcher.config import DispatchConfig
    from linen.dispatcher.protocol.client import ApiResult
    from linen.dispatcher.runtime.cancellation import TaskCancellation
    from linen.dispatcher.tasks import reason
    from linen.server.models import Fact, ProjectDetail, ProjectMeta

    config = DispatchConfig.model_validate(
        {
            "server": "http://127.0.0.1:8000",
            "runtime": {
                "interval": 60,
                "max_workers": 2,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "healthcheck_timeout": 5,
                "prompt_group": "vuln_audit",
            },
            "tasks": {
                "bootstrap": {"timeout": 10, "conclude_timeout": 5},
                "reason": {"timeout": 10, "max_intents": 3},
                "explore": {"timeout": 10, "conclude_timeout": 5},
                "review": {"timeout": 10, "conclude_timeout": 5},
            },
            "local": {"workspace_root": "/tmp/test", "completed_action": "keep"},
            "workers": [
                {
                    "name": "test-worker",
                    "type": "pi",
                    "task_types": ["bootstrap", "reason", "explore", "review"],
                    "max_running": 1,
                    "priority": 0,
                }
            ],
        }
    )

    project = ProjectDetail(
        project=ProjectMeta(
            id="proj_test",
            title="t",
            status="active",
            bootstrap_enabled=False,
            created_at="2026-01-01T00:00:00Z",
        ),
        facts=[Fact(id="origin", description="x"), Fact(id="goal", description="y")],
        intents=[],
        hints=[],
    )

    class _Lease:
        failure = None
        def start(self): pass
        def stop(self): pass

    captured: list[dict[str, Any]] = []

    class _Client:
        def create_intent(self, project_id, from_ids, description, creator, **kw):
            captured.append({
                "project_id": project_id,
                "from": from_ids,
                "description": description,
                "creator": creator,
                "intent_type": kw.get("intent_type"),
            })
            return ApiResult(201, {})
        def complete(self, *a, **k): return ApiResult(200, {})
        def reason_heartbeat(self, *a, **k): return ApiResult(200, {})
        def release_reason(self, *a, **k): return ApiResult(200, {})

    class _Backend:
        def ensure_running(self, pid): return f"c-{pid}"
        def write_text_file(self, *a, **k): return None

    class _Driver:
        def prepare_session(self): return "s"
        def check_health(self, *a, **k): return None
        def build_execute(self, w, prompt, session):
            from linen.dispatcher.workers.base import DriverResult
            return DriverResult(["true"], session=session)
        def extract_session(self, s, *a): return s
        def extract_response_text(self, stdout, stderr): return stdout

    monkeypatch.setattr(reason, "get_driver", lambda *a, **k: _Driver())
    monkeypatch.setattr(reason.HeartbeatLease, "for_reason", lambda *a, **k: _Lease())

    # Worker stdout: a reason payload that emits ONE review intent + ONE
    # trace intent. Both should pass through with their `type` intact.
    worker_stdout = (
        '{"accepted":true,"data":{"intents":['
        '{"from":["f001"],"type":"review","description":"Review f001"},'
        '{"from":["f002"],"type":"trace","description":"Trace f002"}'
        ']}}'
    )

    class _ProcessResult:
        returncode = 0
        stdout = worker_stdout
        stderr = ""
        timed_out = False
        cancelled = False
        cancel_reason = None
        def __init__(self): pass

    monkeypatch.setattr(
        reason, "run_worker_process",
        lambda *a, **k: _ProcessResult(),
    )

    outcome = reason.run_reason_task(
        config, _Client(), _Backend(), project, "graph:\n  - {}\n",
        config.workers[0], TaskCancellation(),
    )
    assert outcome == "success"
    assert len(captured) == 2, captured
    assert captured[0]["intent_type"] == "review", captured
    assert captured[1]["intent_type"] == "trace", captured


# ---- Test 3 + 4: server-side review aggregation + e2e create_review -----


@pytest.fixture()
def app_with_temp_db():
    """A FastAPI app backed by a temp SQLite DB. Bypasses db.DEFAULT_DB.

    `db._db_path` is module-level global with first-wins semantics
    (`configure()` returns early if already set), so we have to
    explicitly reset it between tests — otherwise the second test
    inherits a path to an already-deleted tmp dir from the first.
    """
    from fastapi.testclient import TestClient

    from linen.server import db

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "linen.db"
        db._db_path = None
        db.configure(db_path)

        from linen.server.app import app
        with TestClient(app) as client:
            yield client, db_path

        db._db_path = None


def test_aggregate_fact_status_for_each_verdict(app_with_temp_db):
    """The fact.status aggregator is the heart of the review loop. It
    must flip status correctly for VALID, INVALID, NEEDS_REVIEW, and
    mixed cases. These rules are what makes the loop self-driving:
    reason.md's rules (consume reviews) only work if the status
    actually changes server-side."""
    from linen.server import db
    from linen.server.services import aggregate_fact_status_from_reviews

    client, _ = app_with_temp_db
    # Create a project + a fact directly via SQL (skip the bootstrap flow
    # since the aggregator is what we're testing).
    pid = "proj_agg"
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, bootstrap_enabled, created_at) "
            "VALUES (?, 't', 'active', 0, '2026-01-01T00:00:00Z')",
            (pid,),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description, type, evidence, status) "
            "VALUES (?, ?, 'candidate', 'reachability', 'evidence', 'draft')",
            ("f001", pid),
        )

    with db.get_conn() as conn:
        # No reviews -> status stays as-is.
        assert aggregate_fact_status_from_reviews(conn, pid, "f001", "draft") == "draft"

        # Insert one VALID review -> triaged.
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, "
            "summary, created_at) VALUES ('r1', ?, 'f001', 'VALID', 'firm', "
            "'reads clean', '2026-01-01T00:00:01Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f001", "draft") == "triaged"

        # Add INVALID -> false_positive (fail-fast on disproof).
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, "
            "summary, created_at) VALUES ('r2', ?, 'f001', 'INVALID', 'certain', "
            "'sanitizer at file.py:42', '2026-01-01T00:00:02Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f001", "draft") == "false_positive"

    # Second fact: NEEDS_REVIEW only -> draft; a bounded independent follow-up
    # with a decisive VALID verdict resolves it.
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO facts (id, project_id, description, type, evidence, status) "
            "VALUES (?, ?, 'candidate 2', 'sanitizer', 'ev', 'draft')",
            ("f002", pid),
        )
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, "
            "summary, created_at) VALUES ('r3', ?, 'f002', 'NEEDS_REVIEW', "
            "'tentative', 'need config', '2026-01-01T00:00:03Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f002", "draft") == "draft"
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, "
            "summary, created_at) VALUES ('r4', ?, 'f002', 'VALID', 'firm', "
            "'ok', '2026-01-01T00:00:04Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f002", "draft") == "triaged"

    # Sticky terminal status: never overwritten.
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO facts (id, project_id, description, type, evidence, status) "
            "VALUES (?, ?, 'fixed bug', 'vulnerability', 'ev', 'fixed')",
            ("f003", pid),
        )
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, "
            "summary, created_at) VALUES ('r5', ?, 'f003', 'INVALID', 'certain', "
            "'x', '2026-01-01T00:00:05Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f003", "fixed") == "fixed"


def test_coverage_plan_status_ignores_legacy_vulnerability_review(app_with_temp_db):
    """A historical "not a vulnerability" review must not poison scope work."""
    from linen.server import db
    from linen.server.services import aggregate_fact_status_from_reviews

    pid = "proj_plan_attestation"
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, bootstrap_enabled, created_at) "
            "VALUES (?, 't', 'active', 0, '2026-01-01T00:00:00Z')",
            (pid,),
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description, type, evidence, status) "
            "VALUES ('f001', ?, 'plan', 'coverage_plan', 'artifact', 'draft')",
            (pid,),
        )
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, "
            "diagnostics, created_at) VALUES ('r001', ?, 'f001', 'INVALID', 'certain', "
            "'not a vulnerability', '{}', '2026-01-01T00:00:01Z')",
            (pid,),
        )
        assert aggregate_fact_status_from_reviews(conn, pid, "f001", "draft") == "draft"

        diagnostics = '{"attestation_check":{"artifact_integrity":"valid"}}'
        conn.execute(
            "INSERT INTO reviews (id, project_id, fact_id, verdict, confidence, summary, "
            "diagnostics, created_at) VALUES ('r002', ?, 'f001', 'VALID', 'firm', "
            "'plan verified', ?, '2026-01-01T00:00:02Z')",
            (pid, diagnostics),
        )
        assert aggregate_fact_status_from_reviews(
            conn, pid, "f001", "false_positive"
        ) == "triaged"


def test_review_loop_e2e_create_project_intent_review(app_with_temp_db):
    """Full review loop, no mocks, in-process:

      1. POST /projects       -> active project
      2. POST /projects/{}/intents  with type=review -> review intent
      3. POST /projects/{}/facts/{}/reviews with verdict=VALID
                              -> review row inserted
                              -> intent auto-concluded
                              -> fact.status flips draft -> triaged
      4. GET /projects/{}/facts/{}/reviews -> review visible
    """
    client, _ = app_with_temp_db

    pid = "proj_e2e"
    r = client.post(
        "/projects",
        json={"title": "e2e", "origin": "/tmp/x", "goal": "find bug",
              "bootstrap_enabled": False},
    )
    assert r.status_code == 201, r.text
    pid = r.json()["project"]["id"]

    # Seed a fact and an intent directly via SQL — the review task only
    # needs (fact, intent with type=review, intent.from=[fact_id]).
    from linen.server import db
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO facts (id, project_id, description, type, evidence, status) "
            "VALUES (?, ?, 'candidate sink', 'sink', 'file.py:10', 'draft')",
            ("f100", pid),
        )
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, type, "
            "creator, worker, last_heartbeat_at, created_at, concluded_at) "
            "VALUES ('i100', ?, NULL, 'Review f100', 'review', 'reasoner', NULL, "
            "NULL, '2026-01-01T00:00:00Z', NULL)",
            (pid,),
        )
        conn.execute(
            "INSERT INTO intent_sources (intent_id, project_id, fact_id) "
            "VALUES ('i100', ?, 'f100')",
            (pid,),
        )

    # Submit the Review.
    rr = client.post(
        f"/projects/{pid}/facts/f100/reviews",
        json={
            "verdict": "VALID",
            "confidence": "firm",
            "summary": "Read code, no guard at file.py:10.",
            "intent_id": "i100",
            "created_by": "local-pi",
        },
    )
    assert rr.status_code == 201, rr.text
    body = rr.json()
    assert body["verdict"] == "VALID"
    assert body["fact_id"] == "f100"

    # Fact status flipped draft -> triaged.
    r2 = client.get(f"/projects/{pid}")
    assert r2.status_code == 200
    facts = {f["id"]: f for f in r2.json()["facts"]}
    assert facts["f100"]["status"] == "triaged", facts["f100"]

    # Review intent was auto-concluded by the create_review write.
    intents = {i["id"]: i for i in r2.json()["intents"]}
    assert intents["i100"]["concluded_at"] is not None, intents["i100"]

    # Review is visible via the list endpoint.
    rl = client.get(f"/projects/{pid}/facts/f100/reviews")
    assert rl.status_code == 200
    assert len(rl.json()) == 1
    assert rl.json()[0]["verdict"] == "VALID"


def test_reason_md_teaches_emit_review_intent():
    """The reason prompt must explicitly tell the LLM to emit a
    `type=review:<mode>` intent when an unreviewed draft fact exists.
    Without this rule the loop never closes: reason only proposes
    search/trace/validate/reach/characterize, the candidate finding
    is never challenged, and the project either completes too
    confidently or gets stuck waiting on chain-gap steps that the
    candidate finding already satisfies."""
    prompt = (
        Path(__file__).parent.parent.parent
        / "src" / "linen" / "dispatcher" / "prompts"
        / "vuln_audit" / "reason.md"
    ).read_text(encoding="utf-8")
    # The new section heading + the type=review:<mode> JSON example.
    assert "Emit a review intent" in prompt, "reason.md missing 'Emit a review intent' section"
    assert '"type": "review:devils-advocate"' in prompt, "reason.md missing devils-advocate JSON example"
    assert '"type": "review:cold-verifier"' in prompt, "reason.md missing cold-verifier JSON example"
    assert '"type": "review:contradiction-reasoner"' in prompt, "reason.md missing contradiction-reasoner JSON example"
    # Canonical review type listed in the vocabulary.
    assert "review" in prompt.split("Vocabulary")[1].split("# Task")[0]
