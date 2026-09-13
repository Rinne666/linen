from __future__ import annotations

import json
from pathlib import Path

import pytest

from linen.dispatcher.analysis import audit_graph, scope_gate
from linen.dispatcher.analysis.artifacts import load_artifact
from linen.dispatcher.config import AuditConfig, ScopeAdjudicationConfig
from linen.server.models import Fact, Intent, ProjectDetail, ProjectMeta, Review


NOW = "2026-01-01T00:00:00Z"


def _board(*, facts=None, intents=None, reviews=None) -> ProjectDetail:
    return ProjectDetail(
        project=ProjectMeta(
            id="proj_001",
            title="scope gate",
            status="active",
            bootstrap_enabled=False,
            audit_mode="scope",
            created_at=NOW,
        ),
        facts=facts or [
            Fact(id="origin", description="repository"),
            Fact(id="goal", description="complete audit"),
        ],
        intents=intents or [],
        hints=[],
        reviews=reviews or [],
    )


def _valid_review(fact_id: str, index: int = 1) -> Review:
    return Review(
        id=f"r{index:03d}",
        fact_id=fact_id,
        verdict="VALID",
        confidence="firm",
        summary="artifact and exact quotations independently checked",
        attestation_check={
            "artifact_integrity": "valid",
            "source_consistency": "consistent",
            "scope_complete": "yes",
            "contradictions": [],
        },
        created_at=NOW,
    )


def _collect(tmp_path: Path) -> tuple[dict[str, str], ScopeAdjudicationConfig]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text(
        "# Security\n"
        "Requests from the public Internet cross into the authenticated service.\n"
        "Self-XSS is out of scope unless it crosses into another user's session.\n",
        encoding="utf-8",
    )
    config = ScopeAdjudicationConfig(
        enabled=True,
        local_paths=["SECURITY.md", "MISSING.md"],
        policy_urls=["https://policy.example.test/rules"],
    )

    def fetch(_url: str):
        raise ValueError("upstream unavailable")

    return scope_gate.collect_evidence(repo, tmp_path, config, fetcher=fetch), config


def _adjudication_payload(*, quote: str) -> dict:
    return {
        "accepted": True,
        "data": {
            "description": "policy scope resolved",
            "type": "scope_adjudication",
            "evidence": "Read the frozen SECURITY.md and retained all collection gaps.",
            "scope_adjudication": {
                "coverage": {
                    "status": "partial",
                    "summary": "Local policy was read; one local and one remote source are unavailable.",
                    "gaps": ["MISSING.md was absent", "configured policy URL was unavailable"],
                },
                "citations": [{
                    "id": "c1",
                    "source_id": "policy-001",
                    "file": "local/SECURITY.md",
                    "line": 2,
                    "quote": quote,
                }, {
                    "id": "c2",
                    "source_id": "policy-001",
                    "file": "local/SECURITY.md",
                    "line": 3,
                    "quote": "Self-XSS is out of scope unless it crosses into another user's session.",
                }],
                "trust_boundaries": [{
                    "id": "tb1",
                    "from": "public Internet",
                    "to": "authenticated service",
                    "security_invariant": "Unauthenticated input cannot acquire an authenticated identity.",
                    "security_state_dimensions": ["authentication", "authorization"],
                    "citations": ["c1"],
                }],
                "pre_exclusions": [{
                    "id": "pe1",
                    "bug_class": "self-XSS",
                    "decision": "conditional",
                    "rationale": "The policy excludes isolated self-XSS but names a cross-user exception.",
                    "citations": ["c2"],
                    "revival_conditions": ["Show that the payload executes in another user's session."],
                }],
                "conflicts": [],
            },
        },
    }


def test_policy_collection_freezes_documents_and_records_every_gap(tmp_path):
    payload, _ = _collect(tmp_path)
    fact = Fact(id="f001", status="draft", **payload)
    path, manifest = load_artifact(fact, tmp_path)

    assert path.name == "manifest.json"
    assert manifest["status"] == "partial"
    assert manifest["sources"][0]["location"] == "SECURITY.md"
    assert (path.parent / "source" / "local" / "SECURITY.md").is_file()
    assert {(gap["source"], gap["reason"]) for gap in manifest["gaps"]} == {
        ("MISSING.md", "not_found"),
        ("https://policy.example.test/rules", "fetch_failed"),
    }
    assert manifest["snapshot"]["files"] == {
        "local/SECURITY.md": manifest["sources"][0]["sha256"],
    }


def test_scope_adjudication_accepts_exact_quotes_and_rejects_invention(tmp_path):
    evidence_payload, _ = _collect(tmp_path)
    evidence = Fact(id="f001", status="triaged", **evidence_payload)
    intent = Intent(
        id="i002",
        from_=[evidence.id],
        description=scope_gate.ADJUDICATION_INTENT,
        type="verify",
        creator=scope_gate.CREATOR,
        created_at=NOW,
    )
    board = _board(
        facts=[
            Fact(id="origin", description="repository"),
            Fact(id="goal", description="complete audit"),
            evidence,
        ],
        intents=[intent],
    )
    prompt, recipe_id, recipe = scope_gate.execution_prompt(board, intent, tmp_path)
    assert recipe_id == "scope_adjudication"
    assert recipe.label == "Scope adjudication"
    assert "Policy eligibility and technical exploitability are separate axes" in " ".join(
        prompt.split()
    )

    result = scope_gate.outcome_fact(
        _adjudication_payload(
            quote="Requests from the public Internet cross into the authenticated service."
        ),
        board,
        intent,
        tmp_path,
    )
    assert result["type"] == "scope_adjudication"
    _, record = load_artifact(Fact(id="f002", status="draft", **result), tmp_path)
    assert record["decision_scope"] == "policy_eligibility_only"
    assert record["technical_exploitability_unchanged"] is True
    assert record["pre_exclusions"][0]["revival_conditions"]

    with pytest.raises(ValueError, match="does not match frozen source"):
        scope_gate.outcome_fact(
            _adjudication_payload(quote="Invented maintainer policy"),
            board,
            intent,
            tmp_path,
        )


def test_graph_places_reviewed_scope_gate_before_coverage_plan(tmp_path):
    evidence_payload, _ = _collect(tmp_path)
    config = AuditConfig(
        enabled=True,
        mode="scope",
        scope_adjudication=ScopeAdjudicationConfig(
            enabled=True,
            local_paths=["SECURITY.md"],
        ),
    )
    board = _board()
    assert audit_graph.required_intents(board, tmp_path, config) == [{
        "from": ["origin"],
        "type": "search",
        "description": scope_gate.EVIDENCE_INTENT,
    }]

    evidence = Fact(id="f001", status="triaged", **evidence_payload)
    evidence_intent = Intent(
        id="i001",
        from_=["origin"],
        to=evidence.id,
        description=scope_gate.EVIDENCE_INTENT,
        type="search",
        creator=scope_gate.CREATOR,
        created_at=NOW,
        concluded_at=NOW,
    )
    board.facts.append(evidence)
    board.intents.append(evidence_intent)
    board.reviews.append(_valid_review(evidence.id))
    assert audit_graph.required_intents(board, tmp_path, config) == [{
        "from": [evidence.id],
        "type": "verify",
        "description": scope_gate.ADJUDICATION_INTENT,
    }]

    adjudication_intent = Intent(
        id="i002",
        from_=[evidence.id],
        description=scope_gate.ADJUDICATION_INTENT,
        type="verify",
        creator=scope_gate.CREATOR,
        created_at=NOW,
    )
    board.intents.append(adjudication_intent)
    adjudication_payload = scope_gate.outcome_fact(
        _adjudication_payload(
            quote="Requests from the public Internet cross into the authenticated service."
        ),
        board,
        adjudication_intent,
        tmp_path,
    )
    adjudication = Fact(id="f002", status="triaged", **adjudication_payload)
    board.facts.append(adjudication)
    adjudication_intent.to = adjudication.id
    adjudication_intent.concluded_at = NOW
    board.reviews.append(_valid_review(adjudication.id, 2))

    assert audit_graph.required_intents(board, tmp_path, config) == [{
        "from": [adjudication.id],
        "type": "search",
        "description": "@analysis:coverage-plan",
    }]


def test_scope_adjudication_config_rejects_unsafe_sources():
    with pytest.raises(ValueError, match="safe relative glob"):
        ScopeAdjudicationConfig(enabled=True, local_paths=["../SECURITY.md"])
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        ScopeAdjudicationConfig(
            enabled=True,
            policy_urls=["http://127.0.0.1/policy"],
        )
