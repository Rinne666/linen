"""Tests for Phase 1a — review task 3-mode dispatch.

The review task now picks a prompt based on `intent.type`:
  - `"review"`                  -> devils-advocate (default, prompt `review.md`)
  - `"review:devils-advocate"`  -> devils-advocate
  - `"review:cold-verifier"`    -> cold-verifier  (prompt `review_cold_verifier.md`)
  - `"review:contradiction-reasoner"` -> contradiction-reasoner (prompt `review_contradiction_reasoner.md`)

Unknown / malformed mode falls back to the config-default (devils-advocate
if not configured otherwise).

The scheduler must route any intent whose type starts with `"review"` to
the review dispatcher.
"""
from __future__ import annotations

import json

import pytest

from linen.server.models import Intent, ProjectMeta, ProjectDetail, Fact


# ---- Mode resolution -----------------------------------------------------


def _intent(intent_type: str = "review", description: str = "x") -> Intent:
    return Intent(
        id="i001",
        **{"from": ["f001"]},
        to=None,
        description=description,
        type=intent_type,
        creator="reasoner",
        worker="local-pi",
        last_heartbeat_at=None,
        created_at="2026-01-01T00:00:00Z",
        concluded_at=None,
    )


def test_resolve_review_mode_default_review_type():
    """`intent.type == "review"` (no suffix) -> default mode (devils-advocate)."""
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent("review"), default="devils-advocate") == "devils-advocate"


def test_resolve_review_mode_explicit_devils_advocate():
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent("review:devils-advocate")) == "devils-advocate"


def test_resolve_review_mode_explicit_cold_verifier():
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent("review:cold-verifier")) == "cold-verifier"


def test_resolve_review_mode_explicit_contradiction_reasoner():
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent("review:contradiction-reasoner")) == "contradiction-reasoner"


def test_resolve_review_mode_unknown_falls_back():
    """An intent with `review:<unknown>` should NOT crash; it should fall
    back to the default mode. The unknown mode is logged but the task
    still runs with the default prompt."""
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent("review:nonexistent")) == "devils-advocate"


def test_resolve_review_mode_none_type():
    """An intent with `type=None` (legacy data) should still resolve to
    the default mode, not crash."""
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert resolve_review_mode(_intent(None)) == "devils-advocate"


def test_resolve_review_mode_respects_non_default_config():
    """`config.tasks.review.mode` (when valid) wins as the default when
    intent.type is just `review`."""
    from linen.dispatcher.tasks.review import resolve_review_mode
    assert (
        resolve_review_mode(_intent("review"), default="cold-verifier")
        == "cold-verifier"
    )
    # But an explicit per-intent mode still wins over the config default.
    assert (
        resolve_review_mode(_intent("review:devils-advocate"), default="cold-verifier")
        == "devils-advocate"
    )


# ---- Prompt filename lookup ---------------------------------------------


def test_review_prompt_filename_devils_advocate():
    """The default mode uses the historical `review.md` filename (no
    suffix) so older dispatch.yaml configs / mock test setups continue
    to work without renaming files."""
    from linen.dispatcher.tasks.review import review_prompt_filename
    assert review_prompt_filename("devils-advocate") == "review.md"


def test_review_prompt_filename_other_modes():
    from linen.dispatcher.tasks.review import review_prompt_filename
    assert review_prompt_filename("cold-verifier") == "review_cold_verifier.md"
    assert (
        review_prompt_filename("contradiction-reasoner")
        == "review_contradiction_reasoner.md"
    )


# ---- Prompt file presence in vuln_audit group ---------------------------


def test_all_three_review_prompts_exist_and_have_required_placeholders():
    """All 3 review-mode prompts must exist and pass the placeholder
    validator (4 tokens: {graph_yaml}, {intent_id}, {fact_block},
    {intent_description}). A prompt file dropped during a refactor would
    only surface as a runtime KeyError on review task dispatch — this
    test catches it at config-load time."""
    from linen.dispatcher.config import validate_prompt_resources
    # Should not raise — validates existence + placeholders for all 3.
    validate_prompt_resources("vuln_audit")


def test_review_profiles_separate_findings_attestations_and_summaries():
    from linen.dispatcher.tasks.review import review_profile

    assert review_profile("vulnerability") == "vulnerability"
    assert review_profile("policy_evidence") == "attestation"
    assert review_profile("scope_adjudication") == "attestation"
    assert review_profile("coverage_plan") == "vulnerability"
    assert review_profile("coverage_result") == "coverage"
    assert review_profile("candidate_disposition") == "vulnerability"
    assert review_profile("module_summary") == "summary"
    assert review_profile("audit_summary") == "summary"


def test_review_prompts_have_mode_specific_content():
    """Each prompt must contain its mode-specific anchors. Catches the
    case where someone copy-pastes a prompt without rewriting the body."""
    from pathlib import Path
    prompts_dir = (
        Path(__file__).parent.parent.parent
        / "src" / "linen" / "dispatcher" / "prompts" / "vuln_audit"
    )

    da = (prompts_dir / "review.md").read_text(encoding="utf-8")
    assert "5-Layer Protection Search" in da
    assert "8 Claude False-Positive Patterns" in da

    cv = (prompts_dir / "review_cold_verifier.md").read_text(encoding="utf-8")
    assert "7-Step Protocol" in cv
    assert "Cold verifier" in cv or "cold verifier" in cv
    assert "Static-Status" in cv or "Static Reasoning" in cv
    assert "Severity Challenge" in cv

    cr = (prompts_dir / "review_contradiction_reasoner.md").read_text(encoding="utf-8")
    assert "TRIZ" in cr
    assert "Game Theory" in cr
    assert "Contradiction Reasoner" in cr or "contradiction reasoner" in cr


def test_review_fact_block_includes_structured_trace_and_citations():
    from linen.dispatcher.tasks.review import format_review_fact

    evidence = json.dumps({
        "citations": [{"id": "c1", "file": "Controller.java", "line": 1,
                       "code": "controller.delete(id)"}],
        "trace": [{"file": "Controller.java", "line": 1,
                   "symbol": "Controller.delete", "relation": "entry",
                   "observation": "id is attacker controlled", "citation_id": "c1"}],
    })
    fact = Fact(
        id="f-trace", description="cross-file delete", type="vulnerability",
        evidence=evidence,
        proof={
            "claim_kind": "vulnerability_trace",
            "attributes": {
                "endpoint_id": "http:DELETE:/users/{id}",
                "trace": [{"file": "Controller.java", "line": 1,
                           "symbol": "Controller.delete", "relation": "entry",
                           "observation": "id is attacker controlled", "citation_id": "c1"}],
            },
        },
    )
    block = format_review_fact(fact)
    assert "Controller.delete" in block
    assert '"citation_id": "c1"' in block
    assert '"endpoint_id": "http:DELETE:/users/{id}"' in block


# ---- validate_review_payload: mode-specific extras ----------------------


def test_validate_review_payload_accepts_protection_search():
    """devils-advocate mode emits a `protection_search` dict. The
    validator must pass it through (not drop it) without type-checking
    its inner shape (linen doesn't care, downstream consumers do)."""
    from linen.dispatcher.contracts import validate_review_payload
    payload = {
        "accepted": True,
        "data": {
            "verdict": "VALID",
            "summary": "no defense found",
            "protection_search": {
                "language": {"found": "none", "blocks": "no"},
                "framework": {"found": "none", "blocks": "no"},
            },
            "fp_pattern_check": {
                "1_unsafe_no_path_trace": "not applicable",
            },
        },
    }
    kind, data = validate_review_payload(payload)
    assert kind == "review"
    assert data["verdict"] == "VALID"
    assert "protection_search" in data
    assert "fp_pattern_check" in data


def test_validate_review_payload_accepts_cold_verification():
    from linen.dispatcher.contracts import validate_review_payload
    payload = {
        "verdict": "CONFIRMED",
        "summary": "independent trace confirms",
        "cold_verification": {
            "sub_claims": {"A": "input", "B": "reach", "C": "effect"},
            "sub_claim_failure": "none",
            "prosecution": "...",
            "defense": "...",
        },
    }
    # CONFIRMED is not a valid verdict here — use VALID (the verdict enum
    # is the same across modes; "CONFIRMED" was the cold-verifier's
    # old vocabulary and we re-map to VALID at the prompt level).
    payload["verdict"] = "VALID"
    kind, data = validate_review_payload(payload)
    assert kind == "review"
    assert "cold_verification" in data
    assert data["cold_verification"]["prosecution"] == "..."


def test_validate_review_payload_accepts_contradiction_analysis():
    from linen.dispatcher.contracts import validate_review_payload
    payload = {
        "verdict": "INVALID",
        "summary": "TRIZ identifies the developer's resolution",
        "contradiction_analysis": {
            "triz": {
                "tension_found": "compatibility",
                "sacrifice": "...",
                "exploitable": "no",
            },
            "game_theory": {
                "mechanism_found": "rate_limit",
                "adaptive_attacker_path": "blocked",
            },
        },
    }
    kind, data = validate_review_payload(payload)
    assert kind == "review"
    assert data["verdict"] == "INVALID"
    assert "contradiction_analysis" in data


def test_validate_review_payload_rejects_non_dict_extras():
    """If the worker emits `protection_search: "ok"` (string instead of
    dict), the validator must reject — opaque strings would corrupt the
    downstream review record."""
    from linen.dispatcher.contracts import validate_review_payload
    payload = {
        "verdict": "VALID",
        "summary": "ok",
        "protection_search": "ok",  # not a dict
    }
    import pytest
    with pytest.raises(ValueError, match="protection_search must be an object"):
        validate_review_payload(payload)


def test_validate_review_payload_legacy_still_works():
    """Backwards compat — a review payload with only the 4 base fields
    (no extras) must still validate, so old workers / mock setups
    don't break."""
    from linen.dispatcher.contracts import validate_review_payload
    kind, data = validate_review_payload(
        {"verdict": "VALID", "summary": "ok", "confidence": "firm"}
    )
    assert kind == "review"
    assert data["verdict"] == "VALID"
    assert "protection_search" not in data
    assert "cold_verification" not in data


def test_validate_review_payload_enforces_selected_diagnostic_contract():
    from linen.dispatcher.contracts import validate_review_payload

    with pytest.raises(ValueError, match="cold_verification is required"):
        validate_review_payload(
            {"verdict": "VALID", "summary": "looks sound", "confidence": "firm"},
            required_diagnostics=("cold_verification",),
        )

    diagnostic = {
        "sub_claims": {"source": "request", "path": "handler", "effect": "write"},
        "sub_claim_failure": "none",
        "static_status": "confirmed",
        "poc_status": "not required",
        "prosecution": "reachable without a guard",
        "defense": "no effective defense found",
        "severity_challenged": "impact remains high",
        "isolation_observed": "read-only source",
    }
    kind, data = validate_review_payload(
        {
            "verdict": "VALID",
            "summary": "independent trace confirms",
            "confidence": "firm",
            "cold_verification": diagnostic,
        },
        required_diagnostics=("cold_verification",),
    )
    assert kind == "review"
    assert data["cold_verification"] == diagnostic


# ---- Scheduler route trigger --------------------------------------------


def test_scheduler_loop_routes_review_colon_intents():
    """The scheduler's `_try_dispatch_project` must treat
    `intent.type == 'review'` AND any `intent.type` starting with
    `review:` as review intents. This is the dispatch trigger — if
    the prefix match is missing, the mode-aware review tasks would
    never be scheduled."""
    import re
    from pathlib import Path
    loop_src = (
        Path(__file__).resolve().parents[2]
        / "src/linen/dispatcher/scheduler/loop.py"
    ).read_text(encoding="utf-8")
    # Two flavors of the trigger should both be present in the same block.
    block = re.search(
        r"review_intents\s*=\s*\[.*?\]\s*",
        loop_src,
        re.DOTALL,
    )
    assert block is not None, "loop.py missing review_intents filter"
    text = block.group(0)
    assert '"review"' in text, "loop.py filter does not check for type=='review''"
    assert 'startswith("review:")' in text, "loop.py filter does not check for type starting with 'review:'"


def test_scheduler_loop_filters_concluded_intents():
    """Phase 1a follow-up: the scheduler's `unclaimed_intents` filter
    previously only checked `intent.to is None`, but review tasks
    conclude intents by setting `concluded_at` (not `to_fact_id`).
    Without filtering on `concluded_at`, the scheduler re-dispatches
    the same concluded review intent every tick — observed as 9
    review rows all sharing the same `intent_id`. This test pins the
    fix in place so a future refactor doesn't reintroduce the bug.
    """
    import re
    from pathlib import Path
    loop_src = (
        Path(__file__).resolve().parents[2]
        / "src/linen/dispatcher/scheduler/loop.py"
    ).read_text(encoding="utf-8")
    # The unclaimed_intents filter must check concluded_at.
    block = re.search(
        r"unclaimed_intents\s*=\s*\[.*?\]\s*",
        loop_src,
        re.DOTALL,
    )
    assert block is not None, "loop.py missing unclaimed_intents filter"
    text = block.group(0)
    assert "concluded_at" in text, (
        "loop.py unclaimed_intents filter must check concluded_at "
        "(review tasks conclude via concluded_at, not to_fact_id)"
    )
    # Sanity: also still checks `intent.to is None` (explore tasks use it).
    assert "intent.to is None" in text


# ---- Config integration -------------------------------------------------


def test_review_task_config_default_mode():
    """`TasksConfig.review.mode` defaults to devils-advocate so older
    dispatch.yaml files that don't set it keep working."""
    from linen.dispatcher.config import DispatchConfig
    config = DispatchConfig.model_validate(
        {
            "server": "http://127.0.0.1:8000",
            "runtime": {
                "interval": 60, "max_workers": 2, "max_running_projects": 1,
                "max_project_workers": 1, "healthcheck_timeout": 5,
                "prompt_group": "vuln_audit",
            },
            "tasks": {
                "reason": {"timeout": 10, "max_intents": 3},
                "explore": {"timeout": 10, "conclude_timeout": 5},
                "review": {"timeout": 10, "conclude_timeout": 5},
                # Note: no `mode` key — should default to devils-advocate.
            },
            "local": {"workspace_root": "/tmp", "completed_action": "keep"},
            "workers": [
                {
                    "name": "w", "type": "pi",
                    "task_types": ["reason", "explore", "review"],
                    "max_running": 1, "priority": 0,
                }
            ],
        }
    )
    assert config.tasks.review.mode == "devils-advocate"


def test_review_task_config_rejects_unknown_mode():
    """A typo in dispatch.yaml (`mode: devls-advocate`) should fail at
    config load, not silently fall back at task time."""
    from linen.dispatcher.config import DispatchConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        DispatchConfig.model_validate(
            {
                "server": "http://127.0.0.1:8000",
                "runtime": {
                    "interval": 60, "max_workers": 2, "max_running_projects": 1,
                    "max_project_workers": 1, "healthcheck_timeout": 5,
                    "prompt_group": "vuln_audit",
                },
                "tasks": {
                    "reason": {"timeout": 10, "max_intents": 3},
                    "explore": {"timeout": 10, "conclude_timeout": 5},
                    "review": {
                        "timeout": 10, "conclude_timeout": 5,
                        "mode": "devls-advocate",  # typo
                    },
                },
                "local": {"workspace_root": "/tmp", "completed_action": "keep"},
                "workers": [
                    {
                        "name": "w", "type": "pi",
                    "task_types": ["reason", "explore", "review"],
                        "max_running": 1, "priority": 0,
                    }
                ],
            }
        )
