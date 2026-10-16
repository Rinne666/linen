from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from conftest import make_config, make_intent, make_project
from linen.dispatcher.context.projector import ContextProjector
from linen.dispatcher.contracts import validate_reason_payload
from linen.dispatcher.runtime.awake import IdleSleepGuard
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.tasks.reason_freshness import reason_basis_is_current
from linen.server import db
from linen.server.app import app
from linen.server.models import AuditEvent, Fact, ProjectDetail, ReasonWaitState, Review
from test_scheduler_logic import _loop, _summary
from test_audit_pipeline import api, config, project as create_board


def _wait(project, **changes):
    state = dict(intent_ids=["i001"], reason="await trace result", max_wait_seconds=300,
                 after_event_seq=10, source_generation=1, plan_revision=1,
                 deadline_at=(datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat())
    state.update(changes)
    project.project.reason_wait = ReasonWaitState(**state)
    return project.project.reason_wait


def _event(sequence=11, event_type="audit_task_concluded", entity_id="i001"):
    return AuditEvent(sequence=sequence, event_type=event_type, actor="worker", entity_kind="intent",
                      entity_id=entity_id, created_at="2026-01-01T00:00:00Z", payload={})


@pytest.mark.parametrize("wait", [
    {"reason": "no condition"}, {"intent_ids": [" "], "reason": "missing"},
    {"event_types": ["run_status_changed"], "reason": "churn"},
    {"intent_ids": ["i001"], "reason": "infinite", "max_wait_seconds": 901},
    {"intent_ids": ["i001"], "reason": " ", "max_wait_seconds": 5},
])
def test_wait_rejects_missing_invalid_or_unbounded_conditions(wait):
    with pytest.raises(ValueError):
        validate_reason_payload({"accepted": True, "data": {"wait": wait}}, False, 3)


def test_wait_contract_excludes_other_actions():
    wait = {"intent_ids": ["i001"], "reason": "await evidence"}
    assert validate_reason_payload({"accepted": True, "data": {"wait": wait}}, False, 3)[0] == "wait"
    with pytest.raises(ValueError):
        validate_reason_payload({"accepted": True, "data": {"wait": wait, "intents": []}}, False, 3)


def test_wait_ignores_churn_but_wakes_on_target_deadline_and_generation():
    loop = _loop()
    project = make_project(intents=[make_intent()])
    _wait(project)
    project.project.event_seq = 50
    assert not loop._reason_may_run(project, [_event(event_type="run_status_changed")])
    assert not loop._reason_may_run(project, [_event(entity_id="unrelated")])
    assert not loop._reason_may_run(project, [_event(sequence=10)])
    assert not loop._reason_may_run(project, [_event()])  # Fresh board must show the target's conclusion.
    assert loop._reason_may_run(project, [_event(event_type="human_hint_created")])
    project.intents[0].to = "f002"
    assert loop._reason_trigger(project) == "events:0->50"
    project.project.reason_last_seen_event_seq = 50
    assert loop._reason_trigger(project).startswith("wait:")
    project.intents[0].to = None
    _wait(project, deadline_at="2000-01-01T00:00:00Z")
    project.project.event_seq = project.project.reason_last_seen_event_seq
    assert loop._reason_trigger(project).startswith("wait:")
    assert loop._reason_may_run(project, [])
    _wait(project)
    project.project.source_generation = 2
    assert loop._reason_may_run(project, [])


def test_reason_deferral_still_dispatches_work_it_waits_for():
    loop = _loop()
    loop.config = make_config()
    loop.futures = {}
    loop.container_manager = SimpleNamespace(container_name=lambda pid: pid)
    loop._reason_cooldown_restored = set()
    loop._reason_cooldown_until = {}
    loop._honor_manual_provider_retries = lambda _p: None
    loop._honor_project_worker_issue_resumes = lambda _p: None
    loop._materialize_audit_intents = lambda _p: False
    loop._reconcile_audit_stages = lambda _p: False
    loop._observe_audit_idle_health = lambda _p: None
    project = make_project(intents=[make_intent().model_copy(update={"worker": None})])
    _wait(project)
    project.project.event_seq = 12
    project.project.reason_last_seen_event_seq = 10
    loop.client = SimpleNamespace(get_project=lambda _id: project, export_project=lambda _id: "graph",
                                  get_audit_events=lambda *_a, **_k: [_event(event_type="run_status_changed")])
    dispatched = []
    loop._dispatch_reason = lambda *_a: pytest.fail("strategy should be waiting")
    loop._dispatch_explore = lambda _p, _e, intent: dispatched.append(intent.id) or True
    assert loop._try_dispatch_project(_summary("proj_001", "active"))
    assert dispatched == ["i001"]


def test_scope_adjudication_does_not_preempt_its_queued_independent_review():
    project = make_project(intents=[make_intent().model_copy(update={"worker": None, "type": "review"})])
    project.facts.append(Fact(id="scope-result", type="scope_adjudication", semantic_type="scope", description="scope proposal"))
    event = _event()
    event.payload["fact_id"] = "scope-result"
    assert not _loop()._reason_may_run(project, [event])


def test_candidate_with_queued_proof_work_does_not_buy_duplicate_strategy():
    pending = make_intent().model_copy(update={"worker": None, "from_": ["candidate"], "type": "verify"})
    project = make_project(intents=[pending])
    project.facts.append(Fact(id="candidate", type="vulnerability", semantic_type="candidate_finding", description="new candidate"))
    event = _event()
    event.payload["fact_id"] = "candidate"
    assert not _loop()._reason_may_run(project, [event])
    hint = _event(event_type="human_hint_created")
    assert _loop()._reason_may_run(project, [event, hint])


def test_coverage_bookkeeping_cannot_force_duplicate_candidate_strategy():
    pending = make_intent().model_copy(update={"worker": None, "from_": ["candidate"], "type": "verify"})
    project = make_project(intents=[pending])
    project.facts.extend([
        Fact(id="candidate", type="vulnerability", semantic_type="candidate_finding", description="new candidate"),
        Fact(id="coverage", type="coverage_result", description="routine coverage record"),
    ])
    candidate, bookkeeping = _event(), _event(sequence=12)
    candidate.payload["fact_id"], bookkeeping.payload["fact_id"] = "candidate", "coverage"
    assert not _loop()._reason_may_run(project, [candidate, bookkeeping])


def test_fresh_human_hint_enters_reason_frontier_before_old_hint_fill():
    from linen.dispatcher.tasks.reason import _reason_frontier_seed_ids
    from linen.server.models import Hint

    project = make_project()
    project.hints = [Hint(id=f"h{i:03d}", content=f"hint {i}", creator="human", created_at="2026-10-08T00:00:00Z") for i in range(10)]
    event = _event(event_type="human_hint_created", entity_id="h009")
    seeds = _reason_frontier_seed_ids(project, trigger_events=[event])
    assert seeds[0] == "h009"
    assert len([identifier for identifier in seeds if identifier.startswith("h")]) <= 4


def test_multi_intent_wait_requires_all_results_unless_any_is_explicit():
    loop = _loop()
    project = make_project(intents=[make_intent(), make_intent("i002")])
    _wait(project, intent_ids=["i001", "i002"])
    project.intents[0].to = "f002"
    assert not loop._reason_may_run(project, [_event()])
    _wait(project, intent_ids=["i001", "i002"], intent_policy="any")
    assert loop._reason_may_run(project, [])
    _wait(project, intent_ids=["i001", "i002"])
    project.intents[1].concluded_at = "2026-10-08T00:00:00Z"
    assert loop._reason_may_run(project, [])


def test_wait_release_is_persisted_and_observes_concurrent_conclusion(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as http:
        pid = http.post("/projects", json={"title": "test", "origin": "start", "goal": "end"}).json()["project"]["id"]
        iid = http.post(f"/projects/{pid}/intents", json={"from": ["origin"], "description": "trace", "creator": "reason"}).json()["id"]
        cursor = http.get(f"/projects/{pid}").json()["project"]["event_seq"]
        assert http.post(f"/projects/{pid}/reason/claim", json={"worker": "reason", "lease_id": "current", "trigger": "initial"}).status_code == 200
        # Result arrives during the pass; releasing the old cursor cannot lose it.
        assert http.post(f"/projects/{pid}/intents/{iid}/heartbeat", json={"worker": "explore"}).status_code == 200
        assert http.post(f"/projects/{pid}/intents/{iid}/conclude", json={"worker": "explore", "description": "trace complete"}).status_code == 200
        released = http.post(f"/projects/{pid}/reason/release", json={"worker": "reason", "lease_id": "current", "seen_event_seq": cursor,
                              "source_generation": 1, "plan_revision": 1,
                              "wait": {"intent_ids": [iid], "reason": "await trace", "max_wait_seconds": 300}})
        assert released.status_code == 200, released.text
        restored = ProjectDetail.model_validate(http.get(f"/projects/{pid}").json())
        assert restored.project.reason is None
        assert restored.project.reason_wait.after_event_seq == cursor
        assert restored.project.reason_last_seen_event_seq == cursor
        assert _loop()._reason_may_run(restored, [])
        # Lease-free stale release cannot replace the persisted wait.
        assert http.post(f"/projects/{pid}/reason/claim", json={"worker": "reason", "lease_id": "new", "trigger": "wake"}).status_code == 200
        assert http.post(f"/projects/{pid}/reason/release", json={"worker": "reason", "lease_id": "current", "seen_event_seq": cursor, "source_generation": 1, "plan_revision": 1, "wait": {"event_types": ["review_created"], "reason": "stale"}}).status_code == 409
        assert http.get(f"/projects/{pid}").json()["project"]["reason_wait"] is None


def test_lease_diagnosis_distinguishes_expired_released_and_mismatched(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "linen.db")
    with TestClient(app) as http:
        pid = http.post("/projects", json={"title": "test", "origin": "start", "goal": "end"}).json()["project"]["id"]
        base = f"/projects/{pid}/reason"
        body = {"worker": "reason", "lease_id": "old"}
        http.post(base + "/claim", json={**body, "trigger": "initial"})
        with db.get_conn() as conn:
            conn.execute("UPDATE projects SET reason_last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?", (pid,))
        # A poll can expire it before the heartbeat reaches the server.
        http.get(f"/projects/{pid}")
        response = http.post(base + "/heartbeat", json=body)
        assert response.json()["detail"]["code"] == "reason_lease_expired"
        http.post(base + "/claim", json={"worker": "reason", "lease_id": "new", "trigger": "wake"})
        assert http.post(base + "/heartbeat", json=body).json()["detail"]["code"] == "reason_token_mismatch"
        assert http.post(base + "/heartbeat", json={"worker": "other", "lease_id": "new"}).json()["detail"]["code"] == "reason_worker_mismatch"
        http.post(base + "/release", json={"worker": "reason", "lease_id": "new"})
        assert http.post(base + "/heartbeat", json={"worker": "reason", "lease_id": "new"}).json()["detail"]["code"] == "reason_lease_not_claimed"


def test_heartbeat_loss_cancels_even_if_process_attaches_after_failure():
    cancelled = []
    lease = HeartbeatLease(lambda: None, "reason", "worker", 3)
    lease._fail(409, json.dumps({"detail": {"code": "reason_lease_expired"}}))
    lease.attach_process(SimpleNamespace(cancel=cancelled.append))
    assert cancelled == ["heartbeat_lease_lost:409:reason_lease_expired"]
    assert lease.failure.code == "reason_lease_expired"


def test_reason_accepts_unrelated_updates_but_rejects_changed_basis_and_completion():
    project = make_project(intents=[make_intent()])
    projector = ContextProjector(max_hops=0)
    projection = projector.project_frontier(project, ["f001", "i001"], degraded=True)
    fresh = project.model_copy(deep=True)
    fresh.project.graph_revision += 10
    fresh.project.event_seq += 30
    fresh.intents[0].last_heartbeat_at = "2026-10-08T10:00:00Z"
    fresh.facts.append(Fact(id="unrelated", description="other branch"))
    assert reason_basis_is_current(projection, fresh)
    assert not reason_basis_is_current(projection, fresh, complete=True)
    fresh.facts[2].evidence = "changed source"
    assert not reason_basis_is_current(projection, fresh)


def test_reason_new_review_invalidates_the_read_fact_even_when_status_unchanged():
    project = make_project()
    projection = ContextProjector(max_hops=0).project_frontier(project, ["f001"], degraded=True)
    project.reviews.append(Review(id="r001", fact_id="f001", reviewer="reviewer", verdict="NEEDS_REVIEW", confidence="tentative", summary="missing guard", created_at="2099-01-01T00:00:00Z"))
    assert not reason_basis_is_current(projection, project)


def test_reason_review_predating_projection_does_not_invalidate_read_fact():
    """Reviews excluded from the projection but created before it are baseline
    evidence, not new invalidations (the frontier-v1 selection policy never
    projects review nodes; without this rule every pass is permanently stale)."""
    project = make_project()
    projection = ContextProjector(max_hops=0).project_frontier(project, ["f001"], degraded=True)
    project.reviews.append(Review(id="r001", fact_id="f001", reviewer="reviewer", verdict="VALID", confidence="certain", summary="pre-existing review", created_at="2000-01-01T00:00:00Z"))
    assert reason_basis_is_current(projection, project)


def test_reason_review_with_unknown_timestamp_stays_conservative():
    project = make_project()
    projection = ContextProjector(max_hops=0).project_frontier(project, ["f001"], degraded=True)
    review = Review(id="r001", fact_id="f001", reviewer="reviewer", verdict="VALID", confidence="certain", summary="bad timestamp", created_at="not-a-timestamp")
    review.created_at = ""
    project.reviews.append(review)
    assert not reason_basis_is_current(projection, project)


def test_legacy_empty_output_is_bound_to_real_open_work(api, tmp_path, monkeypatch):
    from linen.dispatcher.runtime.backend import LocalBackend
    from linen.dispatcher.runtime.cancellation import TaskCancellation
    from linen.dispatcher.runtime.process import ProcessResult
    from linen.dispatcher.tasks import reason
    from conftest import FakeDriver

    _, client = api
    board = create_board(api)
    iid = client.create_intent(board.project.id, ["origin"], "trace the pending lead", "dispatcher", action="trace", target="lead").data["id"]
    board = client.get_project(board.project.id)
    cursor = board.project.event_seq
    cfg = config(tmp_path, audit=False)
    assert client.claim_reason(board.project.id, "tester", "lease", "initial").ok
    monkeypatch.setattr(reason, "get_driver", lambda _type: FakeDriver())
    monkeypatch.setattr(reason, "run_worker_process", lambda *_a, **_k: ProcessResult(0, '{"accepted":true,"data":{}}', ""))
    assert reason.run_reason_task(cfg, client, LocalBackend(cfg.local, client), board, "unused", cfg.workers[0], TaskCancellation(), lease_id="lease") == "waiting"
    restored = client.get_project(board.project.id)
    assert restored.project.reason_wait.intent_ids == [iid]
    assert restored.project.reason_wait.intent_policy == "all"
    assert restored.project.reason_wait.after_event_seq == cursor
    assert not _loop()._reason_may_run(restored, [])


def test_reason_retry_of_scheduled_transient_error_preserves_budget_and_waits(api, tmp_path, monkeypatch):
    from linen.dispatcher.runtime.backend import LocalBackend
    from linen.dispatcher.runtime.cancellation import TaskCancellation
    from linen.dispatcher.runtime.process import ProcessResult
    from linen.dispatcher.tasks import reason
    from conftest import FakeDriver

    _, client = api
    board = create_board(api)
    pid = board.project.id
    iid = client.create_intent(pid, ["origin"], "pending retry", "dispatcher", action="trace", target="lead").data["id"]
    assert client.heartbeat(pid, iid, "tester").ok
    assert client.report_intent_error(pid, iid, "tester", task_type="explore", code="invalid_blackboard_result", classification="transient", message="malformed JSON", remediation="bounded retry").ok
    board = client.get_project(pid)
    original = board.errors[0]
    assert original.classification == "transient" and original.retry_at is not None
    cfg = config(tmp_path, audit=False)
    assert client.claim_reason(pid, "tester", "lease", "initial").ok
    monkeypatch.setattr(reason, "get_driver", lambda _type: FakeDriver())
    output = json.dumps({"accepted": True, "data": {"resolve": [{"intent_id": iid, "action": "retry"}]}})
    monkeypatch.setattr(reason, "run_worker_process", lambda *_a, **_k: ProcessResult(0, output, ""))
    monkeypatch.setattr(client, "resolve_intent", lambda *_a, **_k: pytest.fail("automatic retry state must remain unchanged"))
    assert reason.run_reason_task(cfg, client, LocalBackend(cfg.local, client), board, "unused", cfg.workers[0], TaskCancellation(), lease_id="lease") == "waiting"
    fresh = client.get_project(pid)
    assert fresh.project.reason_wait.intent_ids == [iid]
    assert fresh.errors[0].attempt_count == original.attempt_count
    assert fresh.errors[0].retry_at == original.retry_at and fresh.errors[0].resolved_at is None


def test_server_snapshot_basis_accepts_unrelated_write_and_rejects_new_review(api):
    from linen.contracts import ContextRequest

    http, client = api
    board = create_board(api)
    client.create_intent(board.project.id, ["origin"], "pending", "dispatcher", action="trace", target="target")
    initial = client.get_snapshot(board.project.id)
    projection = ContextProjector(max_hops=0).project_frontier(initial, ["origin"], degraded=True)
    client.create_hint(board.project.id, "unrelated scheduling hint", "dispatcher")
    fresh = client.get_project(board.project.id)
    assert initial.graph_revision != fresh.project.graph_revision
    assert reason_basis_is_current(projection, fresh, snapshot=client.get_snapshot(board.project.id))
    http.post(f"/projects/{board.project.id}/facts/origin/reviews", json={"reviewer": "reviewer", "verdict": "NEEDS_REVIEW", "confidence": "tentative", "summary": "source needs validation"})
    fresh = client.get_project(board.project.id)
    assert not reason_basis_is_current(projection, fresh, snapshot=client.get_snapshot(board.project.id))


def test_idle_sleep_guard_lifecycle_is_scoped_to_dispatcher(monkeypatch):
    from linen.dispatcher.runtime import awake
    commands, signals = [], []
    process = SimpleNamespace(pid=123, poll=lambda: None, terminate=lambda: signals.append("terminate"), wait=lambda **_k: 0)
    monkeypatch.setattr(awake.sys, "platform", "darwin")
    monkeypatch.setattr(awake.subprocess, "Popen", lambda command, **kwargs: commands.append(command) or process)
    guard = IdleSleepGuard()
    guard.start()
    guard.start()
    guard.close()
    guard.close()
    assert len(commands) == 1 and commands[0][:3] == ["/usr/bin/caffeinate", "-i", "-w"]
    assert signals == ["terminate"]
