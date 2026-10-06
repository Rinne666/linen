from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from linen.dispatcher.analysis import audit_graph, codeql, recon
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


def test_machine_leads_are_tracked_individually_and_unmatched_paths_remain_gaps(
    frozen_recon, monkeypatch,
):
    project, intent, workdir, recon_config = frozen_recon
    source_fact = _persist_lead(project, intent, workdir, recon_config)
    machine_fact = Fact(
        id="f004", type="recon", description="CodeQL machine paths",
        evidence="artifact: machine.json\nmanifest_sha256: placeholder",
    )
    project.facts.append(machine_fact)
    project.intents.append(Intent(
        id="i004", **{"from": ["f001"]}, to=machine_fact.id, type="search",
        description=codeql.INTENT, creator="dispatcher", created_at="2026-01-01T00:00:02Z",
    ))
    machine_leads = [{
        "id": "machine-app", "title": "Machine app path",
        "hypothesis": "app.py input reaches open", "source": "app.py:1 <source>",
        "sink": "app.py:2 <sink>", "citation_ids": ["c1", "c2"],
    }, {
        "id": "machine-other", "title": "Machine other path",
        "hypothesis": "app.py alternate input reaches open", "source": "app.py:3 <source>",
        "sink": "app.py:4 <sink>", "citation_ids": ["c3", "c4"],
    }]
    monkeypatch.setattr(codeql, "active_for_project", lambda *_args: True)
    monkeypatch.setattr(codeql, "latest_fact", lambda _project: machine_fact)
    monkeypatch.setattr(codeql, "query_results", lambda _project: [])
    monkeypatch.setattr(codeql, "result_record", lambda _fact, _workdir: {
        "leads": machine_leads,
        "citations": [
            {"id": "c1", "file": "app.py", "line": 1, "code": "value = request.args['x']"},
            {"id": "c2", "file": "app.py", "line": 2, "code": "open(value)"},
            {"id": "c3", "file": "app.py", "line": 3, "code": "value = request.args['y']"},
            {"id": "c4", "file": "app.py", "line": 4, "code": "open(value)"},
        ],
    })
    machine_candidate = Fact(
        id="f005", type="vulnerability", semantic_type="candidate_finding",
        description="Candidate for app.py:1 input reaching app.py:2 open.",
        evidence="file: app.py:1\nfile: app.py:2", source_generation=1,
    )
    project.facts.append(machine_candidate)
    project.intents.append(Intent(
        id="i005", **{"from": [machine_fact.id]}, to=machine_candidate.id,
        type="trace", description="Verify CodeQL app path", creator="reasoner",
        created_at="2026-01-01T00:00:03Z",
    ))

    ledger = audit_graph._lead_disposition_ledger(project, workdir, AuditConfig())
    machine_rows = [row for row in ledger if row["category"].startswith("codeql:")]

    assert [(row["lead_id"], row["disposition"]) for row in machine_rows] == [
        ("machine-app", "candidate_tracked"),
        ("machine-other", "unresolved_gap"),
    ]
    assert machine_rows[0]["candidate_fact_ids"] == [machine_candidate.id]
    assert machine_rows[1]["candidate_fact_ids"] == []


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


def test_old_plan_codeql_results_are_excluded_from_lead_ledger(frozen_recon, monkeypatch):
    project, intent, workdir, recon_config = frozen_recon
    _persist_lead(project, intent, workdir, recon_config)
    stale_fact = Fact(
        id="f006", type="recon", description="old plan machine paths",
        evidence="artifact: old.json\nmanifest_sha256: placeholder",
    )
    project.facts.append(stale_fact)
    project.intents.append(Intent(
        id="i006", **{"from": ["f001"]}, to=stale_fact.id, type="search",
        description=codeql.INTENT, creator="dispatcher", created_at="2025-12-31T00:00:00Z",
        plan_revision=0,
    ))
    monkeypatch.setattr(codeql, "active_for_project", lambda *_args: True)
    monkeypatch.setattr(codeql, "latest_fact", lambda _project: stale_fact)
    monkeypatch.setattr(codeql, "query_results", lambda _project: [("old-profile", stale_fact)])
    monkeypatch.setattr(
        codeql, "result_record",
        lambda *_args: (_ for _ in ()).throw(AssertionError("stale result was loaded")),
    )

    ledger = audit_graph._lead_disposition_ledger(project, workdir, AuditConfig())

    assert all(not row["category"].startswith("codeql:") for row in ledger)


def test_reason_context_projects_recon_lead_and_unresolved_rows(frozen_recon):
    project, intent, workdir, recon_config = frozen_recon
    _persist_lead(project, intent, workdir, recon_config)

    prompt = recon.reason_instructions(project, workdir, recon_config)

    assert "lead_ref: f002/lead-path-1" in prompt
    assert "app.py:1" in prompt
    assert "unresolved coverage rows" in prompt.lower()
    assert "candidate_finding" in prompt


def test_codeql_reason_context_projects_every_bounded_machine_lead(monkeypatch):
    fact = Fact(id="f050", type="recon", description="machine paths",
                evidence="artifact: codeql.json\nmanifest_sha256: x")
    leads = [{
        "id": f"machine-{index}", "source_type": "codeql",
        "source_ref": f"app{index}.py:1", "title": f"Machine lead {index}",
        "hypothesis": "A source reaches a sensitive operation.",
        "source": f"app{index}.py:1", "sink": f"app{index}.py:9",
        "path": [f"app{index}.py:1", f"app{index}.py:9"],
        "citation_ids": [f"c{index}"],
    } for index in range(7)]
    monkeypatch.setattr(codeql, "active_for_project", lambda *_args: True)
    monkeypatch.setattr(codeql, "latest_fact", lambda _project: fact)
    monkeypatch.setattr(codeql, "query_results", lambda _project: [])
    monkeypatch.setattr(codeql, "result_record", lambda *_args: {
        "candidate_count": len(leads), "snapshot_id": "snapshot-1", "status": "complete",
        "citations": [
            {"id": f"c{index}", "file": f"app{index}.py", "line": 1,
             "code": "value = request.args['value']"}
            for index in range(len(leads))
        ],
        "leads": leads, "gaps": [],
    })

    prompt = codeql.reason_instructions(
        SimpleNamespace(intents=[], project=SimpleNamespace(source_generation=1, plan_revision=1)),
        object(), SimpleNamespace(max_candidates=7, query_profiles={}),
    )

    assert all(f"lead_ref: f050/machine-{index}" in prompt for index in range(7))
    assert "source=app6.py:1" in prompt
    assert "sink=app6.py:9" in prompt
