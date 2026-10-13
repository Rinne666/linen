from __future__ import annotations

import json

import pytest

from linen.dispatcher.analysis.attestation import attestation_integrity_checks, policy_integrity_checks
from linen.dispatcher.analysis.artifacts import load_artifact
from linen.dispatcher.analysis import scope_gate
from linen.server.models import Fact, Intent, Review
from test_scope_adjudication import _collect, _board, _adjudication_payload, NOW
from test_scheduler_logic import _loop
from conftest import make_config


def test_policy_integrity_recomputes_bytes_and_preserves_partial_scope(tmp_path):
    payload, _ = _collect(tmp_path)
    fact = Fact(id="f001", **payload)
    checks = policy_integrity_checks(fact, tmp_path)
    assert checks["checks"] == {"manifest_digest": "valid", "frozen_file_digests": "valid",
                                "snapshot_digest": "valid", "captured_collector_configuration": "valid"}
    assert checks["frozen_file_sha256"]["local/SECURITY.md"]
    assert "verdict" not in checks
    _, record = load_artifact(fact, tmp_path)
    assert record["status"] == "partial" and record["gaps"]


@pytest.mark.parametrize("tamper", ["manifest", "source", "config_header"])
def test_attestation_never_passes_tampered_frozen_inputs(tmp_path, tamper):
    payload, _ = _collect(tmp_path)
    fact = Fact(id="f001", **payload)
    path, _ = load_artifact(fact, tmp_path)
    if tamper == "manifest":
        path.write_text(path.read_text() + " ")
    elif tamper == "source":
        (path.parent / "source/local/SECURITY.md").write_text("changed policy")
    else:
        fact.evidence = fact.evidence.replace('"github_advisories": false', '"github_advisories": true')
    with pytest.raises(ValueError):
        policy_integrity_checks(fact, tmp_path)


def test_scope_integrity_binds_adjudication_to_the_policy_bytes(tmp_path):
    payload, _ = _collect(tmp_path)
    policy = Fact(id="f001", **payload)
    intent = Intent(id="i002", from_=[policy.id], type="verify", description=scope_gate.ADJUDICATION_INTENT,
                    creator=scope_gate.CREATOR, created_at=NOW)
    board = _board(facts=[policy], intents=[intent])
    result = scope_gate.outcome_fact(_adjudication_payload(quote="Requests from the public Internet cross into the authenticated service."), board, intent, tmp_path)
    fact = Fact(id="f002", **result)
    board.facts.append(fact)
    checks = attestation_integrity_checks(board, fact, tmp_path)
    assert checks["policy_evidence_fact_id"] == "f001"
    assert checks["fact_id"] == "f002"
    assert checks["manifest_sha256"] != checks["policy_manifest_sha256"]


def test_scope_held_intents_are_not_counted_as_actionable_or_suppress_strategy():
    loop = _loop()
    loop.config = make_config()
    loop.config.audit.scope_adjudication.enabled = True
    policy = Fact(id="f001", type="policy_evidence", description="policy")
    board = _board(facts=[policy], intents=[
        Intent(id="i001", from_=["origin"], to="f001", type="search", description=scope_gate.EVIDENCE_INTENT,
               creator=scope_gate.CREATOR, created_at=NOW),
        Intent(id="i003", from_=["f001"], type="verify", description=scope_gate.ADJUDICATION_INTENT,
               creator=scope_gate.CREATOR, created_at=NOW),
        Intent(id="i004", from_=["f001"], type="search", description="@analysis:recon-snapshot",
               creator="dispatcher", created_at=NOW),
    ], reviews=[Review(id="r001", fact_id="f001", verdict="NEEDS_REVIEW", confidence="firm",
                       summary="missing evidence", created_at=NOW)])
    assert loop._dispatchable_open_intent_count(board) == 0
    from linen.server.models import AuditEvent
    event = AuditEvent(sequence=12, event_type="review_created", actor="reviewer", entity_kind="review", entity_id="r001",
                       payload={"fact_id": "f001"}, created_at=NOW)
    assert loop._reason_may_run(board, [event])
