from __future__ import annotations

from copy import deepcopy
import pytest
from fastapi import HTTPException

from linen.server import db
from linen.server.audit_state import latest_finding_assessment
from linen.server.models import CreateReviewRequest
from linen.server.routers.projects import get_candidate_assessment_input, plan_proof_gap, confirm_technical_finding
from linen.server.routers.reviews import create_review
from linen.server.uvpg import evaluate_proof_gate
from test_uvpg import _setup, REPORTABLE_ASSESSMENT
from test_audit_pipeline import api, config, FakeDriver


def setup_candidate(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute("UPDATE projects SET audit_mode = 'scope' WHERE id = 'p'")
        conn.execute("DELETE FROM reviews")
        conn.execute("UPDATE facts SET semantic_type = 'candidate_finding',status = 'draft',evidence = 'api.py:1' WHERE id = 'f1'")
    return plan_proof_gap('p', 'f1')


def assessment_request(intent_id, *, classification='design_weakness', verdict='VALID'):
    inputs = get_candidate_assessment_input('p', 'f1')
    details = deepcopy(REPORTABLE_ASSESSMENT)
    if classification == 'design_weakness':
        details.update(classification=classification, threat_model_status='acknowledged_design_weakness')
    elif classification == 'unknown':
        details.update(classification=classification, threat_model_status='unknown')
    return CreateReviewRequest(
        intent_id=intent_id, verdict=verdict, confidence='firm', summary='independent scope and source assessment', created_by='reviewer',
        finding_assessment=details, cold_verification={'review_kind':'candidate_assessment','candidate_id':'f1',
                                                   'assessment_input_sha256':inputs['assessment_input_sha256']},
    )


def test_scope_candidate_gets_one_early_review_before_proof_construction(tmp_path, monkeypatch):
    first = setup_candidate(tmp_path, monkeypatch)
    assert first['reason'] == 'early_candidate_assessment' and first['created_intent']
    second = plan_proof_gap('p', 'f1')
    assert not second['created_intent'] and second['reason'] == 'candidate_assessment_pending'
    assert second['intent_id'] == first['intent_id']


def test_non_reportable_review_stops_proof_work_without_confirmation(tmp_path, monkeypatch):
    first = setup_candidate(tmp_path, monkeypatch)
    create_review('p', 'f1', assessment_request(first['intent_id']))
    result = plan_proof_gap('p', 'f1')
    assert not result['created_intent'] and result['reason'] == 'candidate_assessed_as_non_vulnerability'
    with db.get_conn() as conn:
        assert evaluate_proof_gate(conn, 'p', 'f1').status == 'FAIL'
        assert conn.execute("SELECT COUNT(*) FROM intents WHERE description LIKE '@uvpg:proof:%'").fetchone()[0] == 0
    response = confirm_technical_finding('p', 'f1')
    assert response.status_code == 409


@pytest.mark.parametrize('classification,verdict', [('vulnerability','VALID'), ('unknown','NEEDS_REVIEW')])
def test_reportable_or_uncertain_candidate_still_needs_the_full_proof(tmp_path, monkeypatch, classification, verdict):
    first = setup_candidate(tmp_path, monkeypatch)
    create_review('p', 'f1', assessment_request(first['intent_id'], classification=classification, verdict=verdict))
    result = plan_proof_gap('p', 'f1')
    assert result['created_intent']
    assert result.get('reason') != 'early_candidate_assessment'
    with db.get_conn() as conn:
        assert evaluate_proof_gate(conn, 'p', 'f1').status == 'FAIL'
        assert conn.execute("SELECT description FROM intents WHERE id = ?", (result['intent_id'],)).fetchone()[0].startswith('@uvpg:proof:')


def test_changed_claim_rejects_stale_assessment_before_persistence(tmp_path, monkeypatch):
    first = setup_candidate(tmp_path, monkeypatch)
    request = assessment_request(first['intent_id'])
    with db.get_conn() as conn:
        conn.execute("UPDATE facts SET description = 'different claim' WHERE id = 'f1'")
    with pytest.raises(HTTPException) as caught:
        create_review('p', 'f1', request)
    assert caught.value.status_code == 409
    with db.get_conn() as conn:
        assert conn.execute('SELECT COUNT(*) FROM reviews').fetchone()[0] == 0


def test_replan_reopens_assessment_and_unrelated_updates_do_not(tmp_path, monkeypatch):
    first = setup_candidate(tmp_path, monkeypatch)
    create_review('p', 'f1', assessment_request(first['intent_id']))
    with db.get_conn() as conn:
        conn.execute("INSERT INTO facts (id,project_id,description) VALUES ('sibling','p','other branch')")
        assert latest_finding_assessment(conn, 'p', 'f1') is not None
        conn.execute("UPDATE projects SET plan_revision = plan_revision + 1 WHERE id = 'p'")
        assert latest_finding_assessment(conn, 'p', 'f1') is None
    reopened = plan_proof_gap('p', 'f1')
    assert reopened['created_intent'] and reopened['reason'] == 'early_candidate_assessment'


def test_dispatcher_publishes_the_assessment_binding_after_independent_review(api, tmp_path, monkeypatch):
    import json
    from linen.dispatcher.runtime.backend import LocalBackend
    from linen.dispatcher.runtime.cancellation import TaskCancellation
    from linen.dispatcher.runtime.process import ProcessResult
    from linen.dispatcher.tasks import review

    _, client = api
    first = setup_candidate(tmp_path, monkeypatch)
    assert client.heartbeat('p', first['intent_id'], 'tester').ok
    current = client.get_project('p')
    intent = next(item for item in current.intents if item.id == first['intent_id'])
    cfg = config(tmp_path)
    driver = FakeDriver()
    monkeypatch.setattr(review, 'get_driver', lambda _: driver)
    request = assessment_request(first['intent_id'])
    output = {'verdict':'VALID', 'confidence':'firm', 'summary':'bounded design weakness', 'finding_assessment':request.finding_assessment}
    output['protection_search'] = {key:'source checked' for key in ('language','framework','middleware','application','documentation')}
    output['fp_pattern_check'] = {key:'source checked' for key in (
        '1_unsafe_no_path_trace','2_phantom_validation','3_framework_blindness','4_same_origin',
        '5_cve_no_reachability','6_config_as_vuln','7_test_code','8_double_counting',
    )}
    monkeypatch.setattr(review, 'run_worker_process', lambda *a, **k: ProcessResult(0, json.dumps(output), ''))
    assert review.run_review_task(cfg, client, LocalBackend(cfg.local, client), current, 'graph', intent, cfg.workers[0], TaskCancellation()) == 'success'
    recorded = client.get_project('p').reviews[-1]
    assert recorded.cold_verification['review_kind'] == 'candidate_assessment'
    assert recorded.cold_verification['assessment_input_sha256']
    assert 'Early independent candidate assessment' in driver.prompts[0]
    assert plan_proof_gap('p', 'f1')['reason'] == 'candidate_assessed_as_non_vulnerability'


def test_early_assessment_does_not_enable_legacy_atom_reviews(tmp_path, monkeypatch):
    from test_uvpg import _strict_board
    from linen.server.uvpg import derive_proof_gaps

    _strict_board(tmp_path, monkeypatch)
    with db.get_conn() as conn:
        conn.execute('DELETE FROM reviews')
    inputs = get_candidate_assessment_input('p', 'candidate')
    create_review('p', 'candidate', CreateReviewRequest(
        verdict='VALID', confidence='firm', summary='reportable candidate needs proof', created_by='reviewer',
        finding_assessment=REPORTABLE_ASSESSMENT,
        cold_verification={'review_kind':'candidate_assessment','candidate_id':'candidate',
                           'assessment_input_sha256':inputs['assessment_input_sha256']},
    ))
    with db.get_conn() as conn:
        gaps = derive_proof_gaps(conn, 'p', 'candidate')
    reviews = [gap for gap in gaps if gap.code == 'UNREVIEWED_EVIDENCE']
    assert len(reviews) == 1
    assert reviews[0].target_fact_id == 'candidate'
    assert reviews[0].suggested_intent_type == 'review:cold-verifier'
