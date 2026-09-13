from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.dispatcher.analysis import audit_graph, audit_recipes, coverage
from linen.dispatcher.config import AuditConfig, CoverageConfig, SemanticAuditConfig
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, Review


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
                "description": "authorization is enforced before deletion",
                "type": "candidate_disposition",
                "evidence": "the same owner value is checked and deleted",
                "citations": [citation],
                "candidate_disposition": {
                    "fingerprint": candidate["fingerprint"],
                    "outcome": "refuted",
                    "rationale": "the operation uses the value accepted by authorize",
                },
            },
        },
        board,
        verify_intent,
        workdir,
        config,
    )
    disposition_fact = Fact(id="f-disposition", status="triaged", **disposition)
    verify_intent.to = disposition_fact.id
    verify_intent.concluded_at = NOW
    board.facts.append(disposition_fact)
    board.intents.append(verify_intent)
    board.reviews.append(_review(disposition_fact.id))

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
