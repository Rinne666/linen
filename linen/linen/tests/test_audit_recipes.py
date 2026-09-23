from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.dispatcher.analysis import audit_graph, audit_recipes, coverage
from linen.dispatcher.analysis.artifacts import (
    canonical_vulnerability_trace,
    vulnerability_trace_proof,
)
from linen.dispatcher.config import AuditConfig, CoverageConfig, SemanticAuditConfig
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, ProofPayload, Review


NOW = "2026-09-09T00:00:00Z"


def _review(fact_id: str) -> Review:
    return Review(
        id=f"r-{fact_id}",
        fact_id=fact_id,
        verdict="VALID",
        confidence="firm",
        summary="source and artifact independently checked",
        attestation_check={
            "artifact_integrity": "valid",
            "source_consistency": "consistent",
            "scope_complete": "yes",
            "contradictions": [],
        },
        created_at=NOW,
    )


def _intent(
    intent_id: str,
    from_ids: list[str],
    description: str,
    intent_type: str,
    *,
    to: str | None = None,
) -> Intent:
    return Intent(
        id=intent_id,
        **{"from": from_ids},
        to=to,
        description=description,
        type=intent_type,
        creator=audit_recipes.CREATOR,
        created_at=NOW,
        concluded_at=NOW if to else None,
    )


def _board_with_plan(tmp_path: Path) -> tuple[ProjectDetail, Path, str]:
    source = tmp_path / "repo"
    source.mkdir()
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (source / "Api.java").write_text(
        'class Api { void remove(String owner) { authorize(owner); delete(owner); } }\n',
        encoding="utf-8",
    )
    (source / "Controller.java").write_text(
        "class Controller { void delete(String id) { service.delete(id); } }\n",
        encoding="utf-8",
    )
    (source / "Service.java").write_text(
        "class Service { void delete(String id) { repository.delete(id); } }\n",
        encoding="utf-8",
    )
    (source / "Repository.java").write_text(
        "class Repository { void delete(String id) { db.delete(id); } }\n",
        encoding="utf-8",
    )
    plan = coverage.create_plan(
        source,
        workdir,
        CoverageConfig(topics=["authorization"], files_per_cell=20),
    )
    plan_id = "f-plan"
    board = ProjectDetail(
        project=ProjectMeta(
            id="proj_recipe",
            title="recipe audit",
            status="active",
            bootstrap_enabled=False,
            audit_mode="scope",
            created_at=NOW,
        ),
        facts=[
            Fact(id="origin", description="source"),
            Fact(id="goal", description="audit"),
            Fact(id=plan_id, status="triaged", **plan),
        ],
        intents=[_intent(
            "i-plan", ["origin"], coverage.PLAN_INTENT, "search", to=plan_id,
        )],
        hints=[],
        reviews=[_review(plan_id)],
    )
    return board, workdir, plan_id


def _semantic_config() -> SemanticAuditConfig:
    return SemanticAuditConfig(
        enabled=True,
        architecture=True,
        authorization=False,
        state_concurrency=False,
        cross_service=False,
        contract=False,
        hypothesis_profiles=["backward"],
        variant_search=False,
        max_verify_attempts=2,
    )


def test_recipe_bundle_selects_only_the_graph_assigned_prompt(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    proposal = audit_recipes.recipe_proposals(board, workdir, config)[0]
    assert proposal == {
        "from": [plan_id],
        "type": "search",
        "description": "@analysis:semantic:architecture_map:v1",
    }

    intent = _intent("i-architecture", **{
        "from_ids": proposal["from"],
        "description": proposal["description"],
        "intent_type": proposal["type"],
    })
    prompt, recipe_id, recipe = audit_recipes.execution_prompt(board, intent, workdir)
    assert recipe_id == "architecture_map"
    assert recipe.label == "Architecture map"
    assert "security-oriented architecture model" in prompt
    assert "TRIZ contradiction" not in prompt
    assert "hypothesis_backward" not in prompt


def test_semantic_recipe_result_is_cited_then_verified_and_summarized(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    citation = {
        "id": "c1",
        "file": "Api.java",
        "line": 1,
        "code": 'class Api { void remove(String owner) { authorize(owner); delete(owner); } }',
    }

    architecture_description = audit_recipes.recipe_description("architecture_map")
    architecture_intent = _intent(
        "i-architecture", [plan_id], architecture_description, "search",
    )
    architecture = audit_recipes.outcome_fact(
        {
            "accepted": True,
            "data": {
                "description": "one privileged component",
                "type": "architecture_map",
                "evidence": "inspected the only source file",
                "recipe_result": {
                    "coverage": {"status": "complete", "summary": "all files", "gaps": []},
                    "citations": [citation],
                    "items": [{
                        "id": "component-api",
                        "kind": "component",
                        "title": "API component",
                        "summary": "contains a privileged delete operation",
                        "citations": ["c1"],
                    }],
                },
            },
        },
        board,
        architecture_intent,
        workdir,
        config,
    )
    architecture_fact = Fact(id="f-architecture", status="triaged", **architecture)
    architecture_intent.to = architecture_fact.id
    architecture_intent.concluded_at = NOW
    board.facts.append(architecture_fact)
    board.intents.append(architecture_intent)
    board.reviews.append(_review(architecture_fact.id))

    hypothesis_proposal = audit_recipes.recipe_proposals(board, workdir, config)[0]
    assert hypothesis_proposal["description"] == "@analysis:semantic:hypothesis_backward:v1"
    hypothesis_intent = _intent(
        "i-hypothesis",
        hypothesis_proposal["from"],
        hypothesis_proposal["description"],
        hypothesis_proposal["type"],
    )
    hypothesis = audit_recipes.outcome_fact(
        {
            "accepted": True,
            "data": {
                "description": "one authorization hypothesis",
                "type": "hypothesis_batch",
                "evidence": "reasoned backward from delete",
                "recipe_result": {
                    "coverage": {"status": "complete", "summary": "mapped operation", "gaps": []},
                    "citations": [citation],
                    "items": [{
                        "id": "hyp-delete",
                        "kind": "hypothesis",
                        "title": "owner confusion",
                        "summary": "the caller may select another owner",
                        "category": "authorization",
                        "reasoning_model": "pre_mortem",
                        "attacker_capability": "supply owner",
                        "trust_boundary": "API input",
                        "violated_invariant": "only owners delete",
                        "endpoint_id": "http:DELETE:/users/{id}",
                        "entry_point": "remove",
                        "operation": "delete",
                        "consequence": "cross-owner deletion",
                        "confidence": "medium",
                        "next_step": "trace authorize semantics",
                        "citations": ["c1"],
                    }],
                },
            },
        },
        board,
        hypothesis_intent,
        workdir,
        config,
    )
    batch = Fact(id="f-hypothesis", status="triaged", **hypothesis)
    hypothesis_intent.to = batch.id
    hypothesis_intent.concluded_at = NOW
    board.facts.append(batch)
    board.intents.append(hypothesis_intent)
    board.reviews.append(_review(batch.id))

    verification = audit_recipes.verification_proposals(board, workdir, config)
    assert len(verification) == 1
    verify_intent = _intent(
        "i-verify",
        verification[0]["from"],
        verification[0]["description"],
        verification[0]["type"],
    )
    _, candidate = audit_recipes.verification_target(board, verify_intent, workdir)
    disposition = audit_recipes.outcome_fact(
        {
            "accepted": True,
            "data": {
                "description": "attacker-selected user reaches deletion",
                "type": "vulnerability",
                "evidence": "traced the request through controller, service, and repository",
                "endpoint_id": "http:DELETE:/users/{id}",
                "provenance": {"source_type": "synthetic_static", "source_ref": "fixture/path-1"},
                "root_cause": "The object selector is not bound to the caller's ownership invariant.",
                "variants_checked": ["DELETE /groups/{id}", "DELETE /tokens/{id}"],
                "citations": [
                    {"id": "t1", "file": "Controller.java", "line": 1,
                     "code": "class Controller { void delete(String id) { service.delete(id); } }"},
                    {"id": "t2", "file": "Service.java", "line": 1,
                     "code": "class Service { void delete(String id) { repository.delete(id); } }"},
                    {"id": "t3", "file": "Repository.java", "line": 1,
                     "code": "class Repository { void delete(String id) { db.delete(id); } }"},
                ],
                "trace": [
                    {"file": "Controller.java", "line": 1, "symbol": "Controller.delete",
                     "kind": "source", "observation": "id is request controlled", "citation_id": "t1"},
                    {"file": "Service.java", "line": 1, "symbol": "Service.delete",
                     "kind": "propagation", "observation": "id crosses into service", "citation_id": "t2"},
                    {"file": "Repository.java", "line": 1, "symbol": "Repository.delete",
                     "kind": "sink", "observation": "id selects the delete target", "citation_id": "t3"},
                ],
                "candidate_disposition": {
                    "fingerprint": candidate["fingerprint"],
                    "outcome": "confirmed",
                    "rationale": "no ownership predicate exists on the closed path",
                },
            },
        },
        board,
        verify_intent,
        workdir,
        config,
    )
    disposition_fact = Fact(id="f-disposition", status="triaged", **disposition)
    assert disposition_fact.proof is not None
    assert [step["symbol"] for step in disposition_fact.proof.attributes["trace"]] == [
        "Controller.delete", "Service.delete", "Repository.delete",
    ]
    assert disposition_fact.proof.attributes["provenance"]["source_type"] == "synthetic_static"
    assert disposition_fact.proof.attributes["root_cause"].startswith("The object selector")
    assert disposition_fact.proof.attributes["variants_checked"] == [
        "DELETE /groups/{id}", "DELETE /tokens/{id}",
    ]
    assert "semgrep" not in json.dumps(disposition_fact.proof.model_dump(mode="json")).lower()
    verify_intent.to = disposition_fact.id
    verify_intent.concluded_at = NOW
    board.facts.append(disposition_fact)
    board.intents.append(verify_intent)
    board.reviews.append(_review(disposition_fact.id))
    follow_up = _intent(
        "i-follow-up", [disposition_fact.id], "verify the missing sibling hop", "trace",
    )
    source_context = audit_recipes._source_context(board, follow_up, workdir)
    assert source_context[0]["proof"]["attributes"]["trace"] == disposition_fact.proof.attributes["trace"]

    inputs = audit_recipes.semantic_summary_inputs(board, workdir, config)
    assert inputs == sorted([architecture_fact.id, batch.id, disposition_fact.id])
    summary_proposal = audit_recipes.summary_proposal(board, workdir, config)
    summary_intent = _intent(
        "i-summary",
        summary_proposal["from"],
        summary_proposal["description"],
        summary_proposal["type"],
    )
    summary = audit_recipes.summary_fact(board, summary_intent, workdir, config)
    assert summary["type"] == "semantic_summary"


def test_confirmed_trace_has_no_deterministic_topology_requirement(tmp_path):
    board, workdir, _ = _board_with_plan(tmp_path)
    _, source, plan = audit_recipes._plan_context(board, workdir)
    citations = [{
        "id": "c1", "file": "Controller.java", "line": 1,
        "code": "class Controller { void delete(String id) { service.delete(id); } }",
    }]
    trace = [{
        "file": "Controller.java", "line": 1, "symbol": "Controller.delete",
        "relation": "flows_to", "observation": "direct flow", "citation_id": "c1",
    }]

    assert canonical_vulnerability_trace(
        trace, citations, source, plan["snapshot"], outcome="confirmed",
    ) == [{
        "file": "Controller.java", "line": 1, "symbol": "Controller.delete",
        "kind": "propagation", "observation": "direct flow", "citation_id": "c1",
    }]
    with pytest.raises(ValueError, match="requires a trace"):
        canonical_vulnerability_trace(
            [], citations, source, plan["snapshot"], outcome="confirmed",
        )


def test_provider_neutral_persistent_trace_round_trips_through_fact_proof(tmp_path):
    board, workdir, _ = _board_with_plan(tmp_path)
    _, source, plan = audit_recipes._plan_context(board, workdir)
    citations = [
        {"id": "c1", "file": "Api.java", "line": 1,
         "code": 'class Api { void remove(String owner) { authorize(owner); delete(owner); } }'},
        {"id": "c2", "file": "Controller.java", "line": 1,
         "code": "class Controller { void delete(String id) { service.delete(id); } }"},
        {"id": "c3", "file": "Service.java", "line": 1,
         "code": "class Service { void delete(String id) { repository.delete(id); } }"},
    ]
    raw_trace = [
        {"file": "Api.java", "line": 1, "symbol": "POST /session", "kind": "source",
         "observation": "caller supplies role", "endpoint_id": "http:POST:/session", "citation_id": "c1"},
        {"file": "Api.java", "line": 1, "symbol": "Session.role", "kind": "state_write",
         "observation": "role is persisted", "endpoint_id": "http:POST:/session", "citation_id": "c1"},
        {"file": "Controller.java", "line": 1, "symbol": "GET /admin/export", "kind": "boundary",
         "observation": "privileged HTTP endpoint reads the session", "endpoint_id": "http:GET:/admin/export", "citation_id": "c2"},
        {"file": "Service.java", "line": 1, "symbol": "Session.role", "kind": "state_read",
         "observation": "persisted role is consumed without revalidation", "endpoint_id": "http:GET:/admin/export", "citation_id": "c3"},
        {"file": "Service.java", "line": 1, "symbol": "executePrivilegedExport", "kind": "sink",
         "observation": "privileged export operation executes", "endpoint_id": "http:GET:/admin/export", "citation_id": "c3"},
    ]
    trace = canonical_vulnerability_trace(
        raw_trace, citations, source, plan["snapshot"], outcome="confirmed",
    )
    proof = vulnerability_trace_proof(
        trace, "http:POST:/session", "confirmed", plan["snapshot"]["id"],
        provenance={"source_type": "synthetic_static", "source_ref": "fixture/path-1"},
        root_cause="Persisted role state is trusted at a privileged sibling endpoint.",
        variants_checked=["GET /admin/export", "GET /admin/status"],
    )
    fact = Fact.model_validate({
        "id": "f-machine-trace", "description": "Synthetic provider-neutral path",
        "type": "vulnerability", "proof": proof,
    })
    round_tripped = ProofPayload.model_validate(fact.proof.model_dump(mode="json"))

    assert [step["kind"] for step in round_tripped.attributes["trace"]] == [
        "source", "state_write", "boundary", "state_read", "sink",
    ]
    assert round_tripped.attributes["trace"][2]["endpoint_id"] == "http:GET:/admin/export"
    assert round_tripped.attributes["provenance"] == {
        "source_type": "synthetic_static", "source_ref": "fixture/path-1",
    }
    assert "semgrep" not in json.dumps(round_tripped.model_dump(mode="json")).lower()


def test_causal_lead_does_not_satisfy_required_coverage_obligations(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    board.facts.append(Fact(
        id="f-causal-lead", description="Cross-endpoint state handoff to privileged sink",
        type="dataflow", status="triaged",
    ))
    config = CoverageConfig(topics=["authorization"], files_per_cell=20)

    state = coverage.coverage_state(board, workdir, config)
    blockers = coverage.scope_blockers(board, workdir, config, [plan_id])

    assert state["summary"]["covered"] == 0
    assert any(item.startswith("Coverage ") for item in blockers)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"file": "Outside.java"}, "Invalid vulnerability trace step"),
        ({"line": 99}, "conflicts with its frozen-source citation"),
        ({"citation_id": "missing"}, "Invalid vulnerability trace step"),
    ],
)
def test_cross_file_trace_rejects_invalid_source_bindings(tmp_path, change, message):
    board, workdir, _ = _board_with_plan(tmp_path)
    _, source, plan = audit_recipes._plan_context(board, workdir)
    citations = [{
        "id": "c1", "file": "Controller.java", "line": 1,
        "code": "class Controller { void delete(String id) { service.delete(id); } }",
    }]
    step = {
        "file": "Controller.java", "line": 1, "symbol": "Controller.delete",
        "relation": "guards", "observation": "decisive ownership check", "citation_id": "c1",
        **change,
    }
    with pytest.raises(ValueError, match=message):
        canonical_vulnerability_trace(
            [step], citations, source, plan["snapshot"], outcome="refuted",
        )


def test_semantic_recipe_rejects_citation_not_in_frozen_snapshot(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    intent = _intent(
        "i-architecture",
        [plan_id],
        audit_recipes.recipe_description("architecture_map"),
        "search",
    )
    with pytest.raises(ValueError, match="does not match frozen source"):
        audit_recipes.outcome_fact(
            {
                "accepted": True,
                "data": {
                    "description": "bad citation",
                    "type": "architecture_map",
                    "evidence": "claimed inspection",
                    "recipe_result": {
                        "coverage": {"status": "complete", "summary": "all", "gaps": []},
                        "citations": [{
                            "id": "c1", "file": "Api.java", "line": 1,
                            "code": "class Api { not the frozen source }",
                        }],
                        "items": [],
                    },
                },
            },
            board,
            intent,
            workdir,
            config,
        )


def test_semantic_recipe_canonicalizes_indentation_only_citation_drift(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    intent = _intent(
        "i-architecture",
        [plan_id],
        audit_recipes.recipe_description("architecture_map"),
        "search",
    )
    result = audit_recipes.outcome_fact(
        {
            "accepted": True,
            "data": {
                "description": "canonical citation",
                "type": "architecture_map",
                "evidence": "inspected the frozen source",
                "recipe_result": {
                    "coverage": {"status": "complete", "summary": "all", "gaps": []},
                    "citations": [{
                        "id": "c1",
                        "file": "Api.java",
                        "line": 1,
                        "code": '  class Api { void remove(String owner) { authorize(owner); delete(owner); } }',
                    }],
                    "items": [{
                        "id": "component-api",
                        "kind": "component",
                        "title": "API",
                        "summary": "one API component",
                        "citations": ["c1"],
                    }],
                },
            },
        },
        board,
        intent,
        workdir,
        config,
    )
    artifact = Path(result["evidence"].splitlines()[0].removeprefix("artifact: "))
    record = json.loads(artifact.read_text())
    assert record["citations"][0]["code"].startswith("class Api")


def test_semantic_recipe_reports_all_citation_mismatches(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    intent = _intent(
        "i-architecture",
        [plan_id],
        audit_recipes.recipe_description("architecture_map"),
        "search",
    )
    payload = {
        "accepted": True,
        "data": {
            "description": "bad citations",
            "type": "architecture_map",
            "evidence": "claimed inspection",
            "recipe_result": {
                "coverage": {"status": "complete", "summary": "all", "gaps": []},
                "citations": [
                    {"id": "c1", "file": "Api.java", "line": 1, "code": "wrong one"},
                    {"id": "c2", "file": "Api.java", "line": 1, "code": "wrong two"},
                ],
                "items": [],
            },
        },
    }
    with pytest.raises(ValueError) as captured:
        audit_recipes.outcome_fact(payload, board, intent, workdir, config)
    assert "c1=Api.java:1" in str(captured.value)
    assert "c2=Api.java:1" in str(captured.value)


def test_sibling_endpoints_keep_stable_identities_for_hypotheses(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = _semantic_config()
    citation = {
        "id": "c1", "file": "Api.java", "line": 1,
        "code": 'class Api { void remove(String owner) { authorize(owner); delete(owner); } }',
    }
    endpoint_ids = [
        "http:GET:/users/{id}",
        "http:PUT:/users/{id}",
        "http:DELETE:/users/{id}",
    ]
    authz_intent = _intent(
        "i-authz", [plan_id], audit_recipes.recipe_description("authz_matrix"), "verify",
    )
    authz = audit_recipes.outcome_fact({
        "accepted": True,
        "data": {
            "description": "three sibling user endpoints",
            "type": "authz_matrix",
            "evidence": "compared sibling operations",
            "recipe_result": {
                "coverage": {"status": "complete", "summary": "siblings", "gaps": []},
                "citations": [citation],
                "items": [{
                    "id": f"endpoint-{index}",
                    "kind": "authorization_surface",
                    "title": endpoint_id,
                    "summary": "ownership present" if index < 2 else "ownership missing",
                    "endpoint_id": endpoint_id,
                    "transport": "http",
                    "operation": endpoint_id.split(":", 2)[1],
                    "handler": "Api.remove",
                    "expected_scope": "owner",
                    "guards": {"declarative": [], "in_body": [], "router": [], "hidden_channels": []},
                    "object_identifier": "id",
                    "ownership_check": "present" if index < 2 else "missing",
                    "tenant_filter": "not_applicable",
                    "candidate": index == 2,
                    "next_step": "verify delete" if index == 2 else "none",
                    "citations": ["c1"],
                } for index, endpoint_id in enumerate(endpoint_ids)],
            },
        },
    }, board, authz_intent, workdir, config)
    authz_fact = Fact(id="f-authz", **authz)
    _, authz_record = audit_recipes.load_artifact(authz_fact, workdir)
    assert [item["endpoint_id"] for item in authz_record["items"]] == endpoint_ids

    hypothesis_intent = _intent(
        "i-delete-hypothesis", [plan_id],
        audit_recipes.recipe_description("hypothesis_backward"), "search",
    )
    hypothesis = audit_recipes.outcome_fact({
        "accepted": True,
        "data": {
            "description": "delete ownership hypothesis",
            "type": "hypothesis_batch",
            "evidence": "compared the delete sibling",
            "recipe_result": {
                "coverage": {"status": "complete", "summary": "delete", "gaps": []},
                "citations": [citation],
                "items": [{
                    "id": "delete-missing-owner", "kind": "hypothesis",
                    "title": "delete lacks ownership", "summary": "DELETE differs from siblings",
                    "category": "authorization", "reasoning_model": "abductive",
                    "attacker_capability": "choose id", "trust_boundary": "HTTP request",
                    "violated_invariant": "owner-only mutation",
                    "endpoint_id": "http:DELETE:/users/{id}", "entry_point": "Api.remove",
                    "operation": "delete", "consequence": "cross-user deletion",
                    "confidence": "high", "next_step": "trace DELETE", "citations": ["c1"],
                }],
            },
        },
    }, board, hypothesis_intent, workdir, config)
    hypothesis_fact = Fact(id="f-delete-hypothesis", **hypothesis)
    assert audit_recipes.candidate_items(hypothesis_fact, workdir)[0]["endpoint_id"] == endpoint_ids[2]


def test_audit_graph_materializes_semantic_recipe_without_a_new_worker_role(tmp_path):
    board, workdir, plan_id = _board_with_plan(tmp_path)
    config = AuditConfig(
        enabled=True,
        mode="scope",
        semantic=_semantic_config(),
        coverage=CoverageConfig(topics=["authorization"], files_per_cell=20),
    )
    proposals = audit_graph.required_intents(board, workdir, config)
    assert {
        "from": [plan_id],
        "type": "search",
        "description": "@analysis:semantic:architecture_map:v1",
    } in proposals
