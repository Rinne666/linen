from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from linen.dispatcher.analysis import audit_graph, recon
from linen.dispatcher.config import AuditConfig
from linen.dispatcher.contracts import parse_json_output
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta


@pytest.fixture
def frozen_recon(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = request.args['value']\nopen(value)\n")
    workdir = tmp_path / "work"
    recon_config = recon.ReconConfig(enabled=True)
    snapshot = recon.create_snapshot(repo, workdir, 1, recon_config)
    fact = Fact(id="f001", **snapshot)
    now = "2026-01-01T00:00:00Z"
    snapshot_intent = Intent(
        id="i001", **{"from": ["origin"]}, to=fact.id, type="search",
        description=recon.SNAPSHOT_INTENT, creator="reasoner", created_at=now,
    )
    category_intent = Intent(
        id="i002", **{"from": [fact.id]}, type="search",
        description=recon.category_description("input-validation"),
        creator="reasoner", created_at=now,
    )
    project = ProjectDetail(
        project=ProjectMeta(id="proj_recon", title="recon", status="active", created_at=now),
        facts=[fact], intents=[snapshot_intent, category_intent], hints=[], reviews=[],
    )
    return project, category_intent, workdir, recon_config


def _lead_payload():
    return {
        "id": "lead-path-1",
        "title": "Request value reaches file open",
        "hypothesis": "A request value reaches open without a containment check.",
        "source": "app.py:request.args",
        "sink": "app.py:open",
        "path": ["app.py:request.args", "app.py:open"],
        "citation_ids": ["c1"],
        "missing_evidence": ["Confirm the resolved path and impact."],
        "next_step": "Trace path resolution and impact.",
        "security_checks": {
            "attacker_cases": [{
                "case_id": "case1", "input_class": "query value",
                "representative_value": "../../secret", "attacker_control": "yes",
                "sink_reachable": "yes", "security_effect": "Potential file read",
                "citation_ids": ["c1"],
            }],
            "protection_checks": [{
                "protection": "path containment", "predicate": "No containment check shown",
                "attacker_case_id": "case1", "predicate_result": "not_applicable",
                "resulting_value": "../../secret", "result": "none_found",
                "sink_reachable": "yes", "citation_ids": ["c1"],
            }],
            "configuration_analysis": {
                "default_mode": "enabled", "ordinary_enabled_mode": "analyzed",
                "requires_admin_misconfiguration": "no",
                "summary": "The route is enabled in the ordinary application path.",
                "citation_ids": ["c1"],
            },
        },
    }


def _persist_lead(project, intent, workdir, recon_config):
    payload = {"accepted": True, "data": {
        "type": "recon", "description": "Partial input trace", "evidence": "source inspection",
        "recon_result": {
            "status": "partial", "summary": "The input reaches a file operation.",
            "gaps": ["Runtime path resolution is unavailable."],
            "citations": [{"id": "c1", "file": "app.py", "line": 1,
                           "code": "value = request.args['value']"}],
            "coverage_dimensions": {
                axis: [{"item": "input boundary", "status": status,
                        "rationale": "The source-only pass cannot establish runtime behavior.",
                        "citation_ids": ["c1"]}]
                for axis, status in {
                    "parallel_paths": "unresolved", "lifecycle": "not_applicable",
                    "uncovered_items": "unresolved", "exclusion_rationales": "none_identified",
                }.items()
            },
            "coverage_review_resolutions": [], "leads": [_lead_payload()],
        },
    }}
    persisted = recon.outcome_fact(
        parse_json_output(json.dumps(payload)),
        project, intent, workdir, recon_config,
    )
    project.facts.append(Fact(id="f002", **persisted))
    completed = next(row for row in project.intents if row.id == intent.id)
    completed.to = "f002"
    return project.facts[-1]


def test_unhandled_recon_lead_stays_in_residual_ledger(frozen_recon):
    project, intent, workdir, recon_config = frozen_recon
    source_fact = _persist_lead(project, intent, workdir, recon_config)

    ledger = audit_graph._lead_disposition_ledger(
        project, workdir, AuditConfig(),
    )

    assert ledger == [{
        "source_fact_id": source_fact.id,
        "category": "input-validation",
        "lead_id": "lead-path-1",
        "title": "Request value reaches file open",
        "hypothesis": "A request value reaches open without a containment check.",
        "source": "app.py:request.args",
        "sink": "app.py:open",
        "citations": ["c1"],
        "disposition": "unresolved_gap",
        "candidate_fact_ids": [],
        "rejected_fact_ids": [],
    }]


def test_candidate_finding_tracks_only_its_cited_lead(frozen_recon):
    project, intent, workdir, recon_config = frozen_recon
    source_fact = _persist_lead(project, intent, workdir, recon_config)
    candidate = Fact(
        id="f003", type="vulnerability", semantic_type="candidate_finding",
        description="Candidate: app.py shows request.args reaches open.",
        evidence="file: app.py:1\nsource: request.args\nsink: open",
        source_generation=1,
    )
    project.facts.append(candidate)
    project.intents.append(Intent(
        id="i003", **{"from": [source_fact.id]}, to=candidate.id,
        type="trace", description="Verify cited lead", creator="reasoner",
        created_at="2026-01-01T00:00:01Z",
    ))

    ledger = audit_graph._lead_disposition_ledger(
        project, workdir, AuditConfig(),
    )

    assert ledger[0]["disposition"] == "candidate_tracked"
    assert ledger[0]["candidate_fact_ids"] == [candidate.id]
    assert ledger[0]["rejected_fact_ids"] == []


def test_lead_location_matching_requires_full_line_number():
    assert audit_graph._candidate_cites_location(
        "evidence: app.py:12", ("app.py", 12),
    )
    assert not audit_graph._candidate_cites_location(
        "evidence: app.py:120", ("app.py", 12),
    )


def test_sibling_leads_need_exact_anchor_or_source_fact_lead_pair():
    lead = {"id": "same-id", "title": "Shared title"}
    assert not audit_graph._candidate_is_bound_to_lead(
        "Shared title", None, None, set(), lead, 2, "f020",
    )
    assert audit_graph._candidate_is_bound_to_lead(
        "lead_ref: f020/same-id", None, None, set(), lead, 2, "f020",
    )
    assert not audit_graph._candidate_is_bound_to_lead(
        "lead_ref: f021/same-id", None, None, set(), lead, 1, "f020",
    )


def test_reason_context_projects_recon_lead_and_unresolved_rows(frozen_recon):
    project, intent, workdir, recon_config = frozen_recon
    _persist_lead(project, intent, workdir, recon_config)

    prompt = recon.reason_instructions(project, workdir, recon_config)

    assert "lead_ref: f002/lead-path-1" in prompt
    assert "app.py:1" in prompt
    assert "unresolved coverage rows" in prompt.lower()
    assert "candidate_finding" in prompt


