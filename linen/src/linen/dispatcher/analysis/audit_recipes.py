"""Prompt-bundle-backed semantic audit recipes.

The blackboard remains the workflow ledger: this module derives no mutable
queue, and workers never receive protocol credentials.  It selects one prompt
recipe for one dispatcher-created Intent, validates the result against the
frozen scope snapshot, and stores the larger record as an immutable artifact.
"""
from __future__ import annotations

from functools import lru_cache
import json
import re
import uuid
from importlib import resources
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml

from linen.dispatcher.analysis import coverage
from linen.dispatcher.analysis.artifacts import ancestor_ids, load_artifact, source_bytes
from linen.dispatcher.analysis.semgrep import digest, write_json
from linen.dispatcher.config import SemanticAuditConfig
from linen.server.models import Fact, Intent, ProjectDetail


CREATOR = "dispatcher.audit"
RECIPE_PREFIX = "@analysis:semantic:"
VERIFY_PREFIX = "@analysis:semantic-verify:"
SUMMARY_INTENT = "@analysis:semantic-summary"
PROMPT_BUNDLE_NAME = "audit_recipes.yaml"

MAP_RECIPES = (
    "authz_matrix",
    "state_model",
    "cross_service_map",
    "contract_map",
)
PROFILE_RECIPES = {
    "backward": "hypothesis_backward",
    "contradiction": "hypothesis_contradiction",
    "attack-composition": "hypothesis_attack_composition",
}
RECIPE_FACT_TYPES = frozenset({
    "architecture_map",
    "authz_matrix",
    "state_model",
    "cross_service_map",
    "contract_map",
    "hypothesis_batch",
    "variant_batch",
})
SEMANTIC_ARTIFACT_FACT_TYPES = RECIPE_FACT_TYPES | {"semantic_summary"}
CANDIDATE_BATCH_TYPES = frozenset({"hypothesis_batch", "variant_batch"})
VERIFY_OUTCOMES = frozenset({"confirmed", "refuted", "blocked"})

_RECIPE_DESCRIPTION = re.compile(
    r"^@analysis:semantic:(?P<recipe>[a-z][a-z0-9_]*):v(?P<version>[1-9][0-9]*)(?::(?P<subject>[A-Za-z0-9._-]+))?$"
)
_VERIFY_DESCRIPTION = re.compile(
    r"^@analysis:semantic-verify:(?P<fact>[A-Za-z0-9][A-Za-z0-9._-]{0,127}):"
    r"(?P<fingerprint>[0-9a-f]{64}):(?P<attempt>[1-9][0-9]*)$"
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CommonPrompts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_policy: str = Field(min_length=1)
    evidence_contract: str = Field(min_length=1)
    output_contract: str = Field(min_length=1)


class RecipeDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(gt=0)
    label: str = Field(min_length=1, max_length=120)
    phase: Literal[
        "scope_adjudication", "semantic_map", "hypothesis_generation",
        "hypothesis_verification", "post_confirmation",
    ]
    intent_type: Literal["search", "verify", "trace"]
    fact_type: str = Field(min_length=1, max_length=80)
    max_items: int = Field(gt=0, le=1000)
    uses_common_output_contract: bool = True
    prompt: str = Field(min_length=1)


class AuditRecipeBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    common: CommonPrompts
    recipes: dict[str, RecipeDefinition]

    @field_validator("recipes")
    @classmethod
    def valid_recipe_ids(cls, value: dict[str, RecipeDefinition]) -> dict[str, RecipeDefinition]:
        if not value:
            raise ValueError("audit recipe bundle must contain recipes")
        invalid = [name for name in value if not re.fullmatch(r"[a-z][a-z0-9_]*", name)]
        if invalid:
            raise ValueError(f"invalid audit recipe ids: {', '.join(sorted(invalid))}")
        return value

    @model_validator(mode="after")
    def required_recipes(self) -> "AuditRecipeBundle":
        required = {
            "scope_adjudication", "architecture_map", *MAP_RECIPES,
            *PROFILE_RECIPES.values(),
            "variant_search", "hypothesis_verify",
        }
        missing = sorted(required - set(self.recipes))
        if missing:
            raise ValueError(f"audit recipe bundle is missing: {', '.join(missing)}")
        return self


@lru_cache(maxsize=8)
def load_bundle(prompt_group: str = "vuln_audit") -> AuditRecipeBundle:
    path = resources.files("linen.dispatcher.prompts").joinpath(prompt_group).joinpath(
        PROMPT_BUNDLE_NAME
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(
            f"prompt group {prompt_group} missing resource: {PROMPT_BUNDLE_NAME}"
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError("audit recipe bundle must contain one YAML object")
    return AuditRecipeBundle.model_validate(raw)


def recipe_description(recipe_id: str, *, subject: str | None = None,
                       prompt_group: str = "vuln_audit") -> str:
    recipe = load_bundle(prompt_group).recipes[recipe_id]
    suffix = f":{subject}" if subject else ""
    return f"{RECIPE_PREFIX}{recipe_id}:v{recipe.version}{suffix}"


def parse_recipe_intent(intent: Intent, prompt_group: str = "vuln_audit") -> tuple[str, RecipeDefinition, str | None] | None:
    if intent.creator != CREATOR:
        return None
    description = intent.description.strip()
    verification = _VERIFY_DESCRIPTION.fullmatch(description)
    if verification:
        recipe = load_bundle(prompt_group).recipes["hypothesis_verify"]
        if not (intent.type or "").startswith("verify"):
            raise ValueError("Semantic verification intent must use a verify type")
        return "hypothesis_verify", recipe, verification.group("fact")
    match = _RECIPE_DESCRIPTION.fullmatch(description)
    if not match:
        return None
    recipe_id = match.group("recipe")
    recipe = load_bundle(prompt_group).recipes.get(recipe_id)
    if recipe is None or recipe.version != int(match.group("version")):
        raise ValueError("Unknown semantic audit recipe or version")
    if intent.type != recipe.intent_type:
        raise ValueError("Semantic recipe intent type does not match its registered recipe")
    subject = match.group("subject")
    expected = recipe_description(recipe_id, subject=subject, prompt_group=prompt_group)
    if description != expected:
        raise ValueError("Semantic recipe intent is not canonical")
    if recipe_id == "variant_search" and not subject:
        raise ValueError("Variant search requires a vulnerability subject")
    if recipe_id != "variant_search" and subject:
        raise ValueError("Only variant search accepts a recipe subject")
    return recipe_id, recipe, subject


def _fact(project: ProjectDetail, fact_id: str) -> Fact | None:
    return next((fact for fact in project.facts if fact.id == fact_id), None)


def _intent(project: ProjectDetail, description: str) -> Intent | None:
    return next(
        (intent for intent in project.intents if intent.description.strip() == description),
        None,
    )


def _result(project: ProjectDetail, description: str) -> Fact | None:
    intent = _intent(project, description)
    return _fact(project, intent.to) if intent is not None and intent.to else None


def _proposal_exists(project: ProjectDetail, description: str) -> bool:
    return any(intent.description.strip() == description for intent in project.intents)


def _enabled_map_recipes(config: SemanticAuditConfig) -> list[str]:
    enabled = []
    if config.authorization:
        enabled.append("authz_matrix")
    if config.state_concurrency:
        enabled.append("state_model")
    if config.cross_service:
        enabled.append("cross_service_map")
    if config.contract:
        enabled.append("contract_map")
    return enabled


def required_recipe_ids(config: SemanticAuditConfig) -> list[str]:
    if not config.enabled:
        return []
    result = ["architecture_map"] if config.architecture else []
    result.extend(_enabled_map_recipes(config))
    result.extend(PROFILE_RECIPES[name] for name in config.hypothesis_profiles)
    return result


def recipe_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: SemanticAuditConfig,
    *,
    prompt_group: str = "vuln_audit",
) -> list[dict[str, Any]]:
    """Derive the next semantic recipe layer from reviewed recipe facts."""
    if not config.enabled or project.project.audit_mode != "scope":
        return []
    plan_fact, _, _ = coverage.get_plan(project, workdir)
    if not coverage.reviewed(project, plan_fact.id):
        return []

    bundle = load_bundle(prompt_group)
    architecture_description = recipe_description(
        "architecture_map", prompt_group=prompt_group,
    )
    architecture = _result(project, architecture_description)
    if config.architecture:
        if architecture is None:
            if not _proposal_exists(project, architecture_description):
                recipe = bundle.recipes["architecture_map"]
                return [{
                    "from": [plan_fact.id],
                    "type": recipe.intent_type,
                    "description": architecture_description,
                }]
            return []
        if not coverage.reviewed(project, architecture.id):
            return []

    map_facts: list[Fact] = []
    map_proposals = []
    for recipe_id in _enabled_map_recipes(config):
        description = recipe_description(recipe_id, prompt_group=prompt_group)
        result = _result(project, description)
        if result is None:
            if not _proposal_exists(project, description):
                recipe = bundle.recipes[recipe_id]
                map_proposals.append({
                    "from": [architecture.id if architecture is not None else plan_fact.id],
                    "type": recipe.intent_type,
                    "description": description,
                })
            continue
        if not coverage.reviewed(project, result.id):
            return map_proposals
        map_facts.append(result)
    if map_proposals:
        return map_proposals

    inputs = [
        architecture.id if architecture is not None else plan_fact.id,
        *(fact.id for fact in map_facts),
    ]
    profile_proposals = []
    for profile in config.hypothesis_profiles:
        recipe_id = PROFILE_RECIPES[profile]
        description = recipe_description(recipe_id, prompt_group=prompt_group)
        result = _result(project, description)
        if result is None:
            if not _proposal_exists(project, description):
                recipe = bundle.recipes[recipe_id]
                profile_proposals.append({
                    "from": inputs,
                    "type": recipe.intent_type,
                    "description": description,
                })
            continue
        if not coverage.reviewed(project, result.id):
            return profile_proposals
    if profile_proposals:
        return profile_proposals

    if not config.variant_search:
        return []
    variant_proposals = []
    for vulnerability in project.facts:
        if (
            vulnerability.type != "vulnerability"
            or not coverage.reviewed(project, vulnerability.id)
            or _is_variant_vulnerability(project, vulnerability.id)
            or plan_fact.id not in ancestor_ids(project, [vulnerability.id])
        ):
            continue
        description = recipe_description(
            "variant_search", subject=vulnerability.id, prompt_group=prompt_group,
        )
        if not _proposal_exists(project, description):
            recipe = bundle.recipes["variant_search"]
            variant_proposals.append({
                "from": [vulnerability.id],
                "type": recipe.intent_type,
                "description": description,
            })
    return variant_proposals


def _canonical_citations(raw: Any, source: Path, snapshot: dict) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("Semantic recipe result requires citations")
    if len(raw) > 2000:
        raise ValueError("Semantic recipe citation limit exceeded")
    result = []
    ids: set[str] = set()
    files = snapshot.get("files", {})
    for citation in raw:
        if not isinstance(citation, dict) or set(citation) != {"id", "file", "line", "code"}:
            raise ValueError("Every semantic citation requires exactly id, file, line, and code")
        citation_id = citation["id"]
        filename = citation["file"]
        line = citation["line"]
        code = citation["code"]
        if (
            not isinstance(citation_id, str)
            or not _ID.fullmatch(citation_id)
            or citation_id in ids
            or not isinstance(filename, str)
            or filename not in files
            or type(line) is not int
            or line < 1
            or not isinstance(code, str)
            or not code.strip()
            or len(code) > 8000
        ):
            raise ValueError("Invalid semantic citation")
        content = source_bytes(source, filename, files[filename]).decode(
            "utf-8", errors="replace",
        )
        lines = content.splitlines()
        excerpt = code.splitlines()
        if line > len(lines) or lines[line - 1:line - 1 + len(excerpt)] != excerpt:
            raise ValueError(f"Semantic citation does not match frozen source: {filename}:{line}")
        ids.add(citation_id)
        result.append({"id": citation_id, "file": filename, "line": line, "code": code})
    return result


_COMMON_ITEM_KEYS = {"id", "kind", "title", "summary", "citations"}
_REQUIRED_ITEM_KEYS: dict[str, set[str]] = {
    "architecture_map": _COMMON_ITEM_KEYS,
    "authz_matrix": _COMMON_ITEM_KEYS | {
        "transport", "operation", "handler", "expected_scope", "guards",
        "object_identifier", "ownership_check", "tenant_filter", "candidate", "next_step",
    },
    "state_model": _COMMON_ITEM_KEYS | {
        "entity", "transition", "precondition", "mutation", "transaction",
        "concurrency_control", "idempotency", "candidate", "next_step",
    },
    "cross_service_map": _COMMON_ITEM_KEYS | {
        "producer", "channel", "consumer", "attacker_control",
        "channel_authentication", "producer_validation", "consumer_validation",
        "candidate", "next_step",
    },
    "contract_map": _COMMON_ITEM_KEYS | {
        "contract_source", "requirement", "implementation", "comparison",
        "candidate", "next_step",
    },
    "hypothesis_batch": _COMMON_ITEM_KEYS | {
        "category", "reasoning_model", "attacker_capability", "trust_boundary",
        "violated_invariant", "entry_point", "operation", "consequence",
        "confidence", "next_step",
    },
    "variant_batch": _COMMON_ITEM_KEYS | {
        "category", "reasoning_model", "attacker_capability", "trust_boundary",
        "violated_invariant", "entry_point", "operation", "consequence",
        "confidence", "next_step", "similarity", "parent_vulnerability",
    },
}


def _normalize_recipe_result(
    raw: Any,
    recipe_id: str,
    recipe: RecipeDefinition,
    source: Path,
    snapshot: dict,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"coverage", "citations", "items"}:
        raise ValueError("recipe_result requires exactly coverage, citations, and items")
    coverage_record = raw["coverage"]
    if not isinstance(coverage_record, dict) or set(coverage_record) != {
        "status", "summary", "gaps",
    }:
        raise ValueError("Semantic coverage requires exactly status, summary, and gaps")
    if coverage_record["status"] not in {"complete", "partial", "not_applicable"}:
        raise ValueError("Invalid semantic coverage status")
    if not isinstance(coverage_record["summary"], str) or not coverage_record["summary"].strip():
        raise ValueError("Semantic coverage summary is required")
    gaps = coverage_record["gaps"]
    if (
        not isinstance(gaps, list)
        or len(gaps) > 200
        or any(not isinstance(gap, str) or not gap.strip() for gap in gaps)
    ):
        raise ValueError("Semantic coverage gaps must be a bounded text array")
    citations = _canonical_citations(raw["citations"], source, snapshot)
    citation_ids = {citation["id"] for citation in citations}
    items = raw["items"]
    if not isinstance(items, list) or len(items) > recipe.max_items:
        raise ValueError(f"Semantic recipe items exceed {recipe.max_items}")
    normalized_items = []
    item_ids: set[str] = set()
    required = _REQUIRED_ITEM_KEYS[recipe.fact_type]
    for item in items:
        if not isinstance(item, dict) or not required.issubset(item):
            raise ValueError(f"{recipe.fact_type} item is missing required fields")
        item_id = item.get("id")
        title = item.get("title")
        summary = item.get("summary")
        refs = item.get("citations")
        if (
            not isinstance(item_id, str)
            or not _ID.fullmatch(item_id)
            or item_id in item_ids
            or not isinstance(title, str)
            or not title.strip()
            or not isinstance(summary, str)
            or not summary.strip()
            or not isinstance(refs, list)
            or any(not isinstance(ref, str) or ref not in citation_ids for ref in refs)
            or (not refs and item.get("kind") != "coverage_gap")
        ):
            raise ValueError("Invalid semantic recipe item identity, text, or citations")
        if recipe.fact_type != "architecture_map" and item.get("kind") == "coverage_gap":
            pass
        elif recipe.fact_type in {"authz_matrix", "state_model", "cross_service_map", "contract_map"}:
            if not isinstance(item.get("candidate"), bool):
                raise ValueError("Semantic matrix candidate must be boolean")
        if recipe.fact_type in CANDIDATE_BATCH_TYPES:
            if item.get("kind") not in {"hypothesis", "variant"}:
                raise ValueError("Semantic candidate batch has an invalid kind")
            if item.get("confidence") not in {"low", "medium", "high"}:
                raise ValueError("Semantic hypothesis confidence must be low, medium, or high")
        item_ids.add(item_id)
        normalized = dict(item)
        if recipe.fact_type in CANDIDATE_BATCH_TYPES:
            signature = {
                key: normalized.get(key) for key in (
                    "category", "attacker_capability", "trust_boundary",
                    "violated_invariant", "entry_point", "operation", "consequence",
                    "similarity", "parent_vulnerability",
                )
            }
            normalized["fingerprint"] = digest(
                json.dumps(signature, ensure_ascii=False, sort_keys=True).encode("utf-8")
            )
        normalized_items.append(normalized)
    fingerprints = [item.get("fingerprint") for item in normalized_items if item.get("fingerprint")]
    if len(fingerprints) != len(set(fingerprints)):
        raise ValueError("Semantic recipe produced duplicate hypothesis fingerprints")
    return {
        "coverage": {
            "status": coverage_record["status"],
            "summary": coverage_record["summary"].strip(),
            "gaps": [gap.strip() for gap in gaps],
        },
        "citations": citations,
        "items": normalized_items,
    }


def _plan_context(project: ProjectDetail, workdir: Path) -> tuple[Fact, Path, dict]:
    plan_fact, plan_path, plan = coverage.get_plan(project, workdir)
    source = plan_path.parent / "source"
    for filename, expected in plan["snapshot"]["files"].items():
        source_bytes(source, filename, expected)
    return plan_fact, source, plan


def _source_context(project: ProjectDetail, intent: Intent, workdir: Path) -> list[dict[str, Any]]:
    records = []
    for fact_id in intent.from_:
        fact = _fact(project, fact_id)
        if fact is None:
            raise ValueError(f"Semantic recipe input fact is missing: {fact_id}")
        entry: dict[str, Any] = {
            "id": fact.id,
            "type": fact.type,
            "status": fact.status,
            "description": fact.description,
            "evidence": fact.evidence,
        }
        try:
            path, artifact = load_artifact(fact, workdir)
            entry["artifact"] = str(path)
            entry["artifact_kind"] = artifact.get("kind") or artifact.get("scanner", {}).get("name")
        except (ValueError, OSError, KeyError, TypeError):
            pass
        records.append(entry)
    return records


def execution_prompt(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    prompt_group: str = "vuln_audit",
    *,
    validation_error: str | None = None,
) -> tuple[str, str, RecipeDefinition]:
    parsed = parse_recipe_intent(intent, prompt_group)
    if parsed is None:
        raise ValueError("Intent is not a registered semantic recipe")
    recipe_id, recipe, subject = parsed
    plan_fact, source, plan = _plan_context(project, workdir)
    if plan_fact.id not in ancestor_ids(project, intent.from_):
        raise ValueError("Semantic recipe must descend from the frozen coverage plan")

    context: dict[str, Any] = {
        "recipe": {
            "id": recipe_id,
            "label": recipe.label,
            "version": recipe.version,
            "phase": recipe.phase,
        },
        "intent": {
            "id": intent.id,
            "type": intent.type,
            "description": intent.description,
            "input_fact_ids": intent.from_,
        },
        "expected_fact_type": recipe.fact_type,
        "snapshot": {
            "id": plan["snapshot"]["id"],
            "file_count": len(plan["snapshot"]["files"]),
            "skipped": plan["snapshot"].get("skipped", []),
        },
        "source_root": str(source),
        "input_facts": _source_context(project, intent, workdir),
    }
    if subject:
        context["subject_fact_id"] = subject
    if recipe_id == "hypothesis_verify":
        _, candidate = verification_target(project, intent, workdir)
        context["assigned_candidate"] = candidate
    if validation_error:
        context["previous_validation_error"] = validation_error

    bundle = load_bundle(prompt_group)
    sections = [
        f"# Audit recipe: {recipe.label} ({recipe_id} v{recipe.version})",
        bundle.common.source_policy,
        bundle.common.evidence_contract,
        "# Assignment context\n" + json.dumps(context, ensure_ascii=False, indent=2),
        "# Recipe instructions\n" + recipe.prompt,
    ]
    if recipe.uses_common_output_contract:
        sections.append("# Output contract\n" + bundle.common.output_contract)
    return "\n\n".join(sections).strip() + "\n", recipe_id, recipe


def outcome_fact(
    payload: dict[str, Any],
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: SemanticAuditConfig,
    prompt_group: str = "vuln_audit",
) -> dict[str, str]:
    if not config.enabled:
        raise ValueError("Semantic audit recipes are disabled")
    parsed = parse_recipe_intent(intent, prompt_group)
    if parsed is None:
        raise ValueError("Intent is not a registered semantic recipe")
    recipe_id, recipe, subject = parsed
    if recipe_id == "hypothesis_verify":
        return verification_outcome_fact(payload, project, intent, workdir)
    data = payload.get("data", payload)
    if not isinstance(data, dict) or data.get("type") != recipe.fact_type:
        raise ValueError(f"Semantic recipe must produce type={recipe.fact_type}")
    if not isinstance(data.get("description"), str) or not data["description"].strip():
        raise ValueError("Semantic recipe description is required")
    if not isinstance(data.get("evidence"), str) or not data["evidence"].strip():
        raise ValueError("Semantic recipe evidence is required")
    plan_fact, source, plan = _plan_context(project, workdir)
    if plan_fact.id not in ancestor_ids(project, intent.from_):
        raise ValueError("Semantic recipe result is not attached to its coverage plan")
    normalized = _normalize_recipe_result(
        data.get("recipe_result"), recipe_id, recipe, source, plan["snapshot"],
    )
    record = {
        "schema_version": 1,
        "kind": recipe.fact_type,
        "status": "completed",
        "recipe": {
            "id": recipe_id,
            "label": recipe.label,
            "version": recipe.version,
            "phase": recipe.phase,
        },
        "snapshot": {"id": plan["snapshot"]["id"]},
        "input_fact_ids": list(intent.from_),
        "subject_fact_id": subject,
        "coverage": normalized["coverage"],
        "citations": normalized["citations"],
        "items": normalized["items"],
        "worker_evidence": data["evidence"].strip(),
    }
    directory = workdir / ".linen-analysis" / f"semantic-{recipe_id}-{uuid.uuid4().hex}"
    directory.mkdir(parents=True)
    path = directory / "result.json"
    write_json(path, record)
    gap_count = len(record["coverage"]["gaps"])
    return {
        "type": recipe.fact_type,
        "description": (
            f"{recipe.label} completed: {len(record['items'])} items, "
            f"{gap_count} coverage gaps ({record['coverage']['status']})."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            f"recipe: {recipe_id}\nrecipe_label: {recipe.label}\n"
            f"snapshot: {plan['snapshot']['id']}\nstatus: completed"
        ),
    }


def candidate_items(fact: Fact, workdir: Path) -> list[dict[str, Any]]:
    if fact.type not in CANDIDATE_BATCH_TYPES:
        raise ValueError("Semantic candidate source must be a hypothesis_batch or variant_batch")
    _, record = load_artifact(fact, workdir)
    if record.get("status") != "completed" or record.get("kind") != fact.type:
        raise ValueError("Semantic candidate artifact is not completed")
    items = record.get("items")
    if not isinstance(items, list):
        raise ValueError("Semantic candidate artifact items are invalid")
    return sorted(items, key=lambda item: item["fingerprint"])


def verification_description(batch_fact_id: str, fingerprint: str, attempt: int) -> str:
    return f"{VERIFY_PREFIX}{batch_fact_id}:{fingerprint}:{attempt}"


def verification_attempts(project: ProjectDetail, batch_fact_id: str,
                          fingerprint: str) -> list[Intent]:
    prefix = f"{VERIFY_PREFIX}{batch_fact_id}:{fingerprint}:"
    return sorted(
        [intent for intent in project.intents if intent.description.startswith(prefix)],
        key=lambda intent: (intent.created_at, intent.id),
    )


def verification_target(
    project: ProjectDetail, intent: Intent, workdir: Path,
) -> tuple[Fact, dict[str, Any]]:
    match = _VERIFY_DESCRIPTION.fullmatch(intent.description.strip())
    if match is None or not (intent.type or "").startswith("verify"):
        raise ValueError("Invalid semantic verification intent")
    batch = _fact(project, match.group("fact"))
    if batch is None or batch.id not in intent.from_ or batch.type not in CANDIDATE_BATCH_TYPES:
        raise ValueError("Semantic verification must reference its candidate batch")
    candidate = next(
        (item for item in candidate_items(batch, workdir)
         if item["fingerprint"] == match.group("fingerprint")),
        None,
    )
    if candidate is None:
        raise ValueError("Semantic candidate fingerprint is missing")
    return batch, candidate


def verification_outcome_fact(
    payload: dict[str, Any], project: ProjectDetail, intent: Intent, workdir: Path,
) -> dict[str, str]:
    batch, candidate = verification_target(project, intent, workdir)
    data = payload.get("data", payload)
    expected_keys = {
        "description", "type", "evidence", "citations", "candidate_disposition",
    }
    if not isinstance(data, dict) or set(data) != expected_keys:
        raise ValueError(
            "Semantic verification requires exactly description, type, evidence, "
            "citations, and candidate_disposition"
        )
    disposition = data.get("candidate_disposition")
    if not isinstance(disposition, dict):
        raise ValueError("Semantic verification requires candidate_disposition")
    if set(disposition) != {"fingerprint", "outcome", "rationale"}:
        raise ValueError(
            "candidate_disposition requires exactly fingerprint, outcome, and rationale"
        )
    if disposition.get("fingerprint") != candidate["fingerprint"]:
        raise ValueError("Semantic disposition fingerprint does not match its candidate")
    outcome = disposition.get("outcome")
    rationale = disposition.get("rationale")
    fact_type = data.get("type")
    evidence = data.get("evidence")
    description = data.get("description")
    if outcome not in VERIFY_OUTCOMES or not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("Semantic disposition requires a valid outcome and rationale")
    if outcome == "confirmed" and fact_type != "vulnerability":
        raise ValueError("A confirmed hypothesis result must produce a vulnerability candidate")
    if outcome != "confirmed" and fact_type != "candidate_disposition":
        raise ValueError("Non-confirmed semantic hypothesis must produce candidate_disposition")
    if not isinstance(evidence, str) or not evidence.strip():
        raise ValueError("Semantic verification requires evidence")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("Semantic verification requires a description")
    _, source, plan = _plan_context(project, workdir)
    citations = _canonical_citations(data.get("citations"), source, plan["snapshot"])
    if not citations:
        raise ValueError("Semantic verification requires at least one frozen-source citation")
    envelope = {
        "schema_version": 1,
        "source": "semantic_recipe",
        "batch_fact_id": batch.id,
        "fingerprint": candidate["fingerprint"],
        "outcome": outcome,
        "rationale": rationale.strip(),
        "candidate": candidate,
        "citations": citations,
        "worker_evidence": evidence.strip(),
    }
    return {
        "type": fact_type,
        "description": description.strip(),
        "evidence": json.dumps(envelope, ensure_ascii=False),
    }


def terminal_verification(
    project: ProjectDetail, batch_fact_id: str, fingerprint: str,
) -> Fact | None:
    for intent in reversed(verification_attempts(project, batch_fact_id, fingerprint)):
        fact = _fact(project, intent.to or "")
        if fact is None:
            continue
        if fact.type == "vulnerability":
            return fact
        if fact.type == "candidate_disposition":
            try:
                if json.loads(fact.evidence or "").get("outcome") == "refuted":
                    return fact
            except (ValueError, TypeError):
                pass
    return None


def verification_proposals(
    project: ProjectDetail,
    workdir: Path,
    config: SemanticAuditConfig,
    *,
    prompt_group: str = "vuln_audit",
) -> list[dict[str, Any]]:
    if not config.enabled:
        return []
    proposals = []
    seen_fingerprints: set[str] = set()
    for batch in project.facts:
        if batch.type not in CANDIDATE_BATCH_TYPES or not coverage.reviewed(project, batch.id):
            continue
        producer = next((intent for intent in project.intents if intent.to == batch.id), None)
        if producer is None:
            continue
        try:
            parsed = parse_recipe_intent(producer, prompt_group)
        except ValueError:
            continue
        if parsed is None or parsed[1].fact_type != batch.type:
            continue
        for candidate in candidate_items(batch, workdir):
            fingerprint = candidate["fingerprint"]
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            terminal = terminal_verification(project, batch.id, fingerprint)
            if terminal is not None and coverage.reviewed(project, terminal.id):
                continue
            attempts = verification_attempts(project, batch.id, fingerprint)
            if attempts:
                latest = attempts[-1]
                if latest.to is None and latest.concluded_at is None:
                    continue
                latest_fact = _fact(project, latest.to or "")
                if latest_fact is None or not coverage.reviewed(project, latest_fact.id):
                    continue
                try:
                    outcome = json.loads(latest_fact.evidence or "").get("outcome")
                except (ValueError, TypeError):
                    outcome = None
                if outcome != "blocked" or len(attempts) >= config.max_verify_attempts:
                    continue
                from_ids = [batch.id, latest_fact.id]
            else:
                from_ids = [batch.id]
            attempt = len(attempts) + 1
            description = verification_description(batch.id, fingerprint, attempt)
            if not _proposal_exists(project, description):
                proposals.append({
                    "from": from_ids,
                    "type": f"verify:{candidate['category']}",
                    "description": description,
                })
    return proposals


def _is_variant_vulnerability(project: ProjectDetail, fact_id: str) -> bool:
    incoming = next((intent for intent in project.intents if intent.to == fact_id), None)
    if incoming is None or not incoming.description.startswith(VERIFY_PREFIX):
        return False
    return any(
        (source := _fact(project, source_id)) is not None and source.type == "variant_batch"
        for source_id in incoming.from_
    )


def semantic_summary_inputs(
    project: ProjectDetail,
    workdir: Path,
    config: SemanticAuditConfig,
    *,
    prompt_group: str = "vuln_audit",
) -> list[str] | None:
    if not config.enabled:
        return []
    plan_fact, _, _ = coverage.get_plan(project, workdir)
    inputs: list[str] = []
    for recipe_id in required_recipe_ids(config):
        fact = _result(project, recipe_description(recipe_id, prompt_group=prompt_group))
        if fact is None or fact.type not in RECIPE_FACT_TYPES or not coverage.reviewed(project, fact.id):
            return None
        inputs.append(fact.id)

    for vulnerability in project.facts:
        if (
            not config.variant_search
            or vulnerability.type != "vulnerability"
            or not coverage.reviewed(project, vulnerability.id)
            or _is_variant_vulnerability(project, vulnerability.id)
            or plan_fact.id not in ancestor_ids(project, [vulnerability.id])
        ):
            continue
        description = recipe_description(
            "variant_search", subject=vulnerability.id, prompt_group=prompt_group,
        )
        batch = _result(project, description)
        if batch is None or batch.type != "variant_batch" or not coverage.reviewed(project, batch.id):
            return None
        inputs.append(batch.id)

    expected_batch_ids = {
        fact.id for fact in project.facts
        if fact.id in inputs and fact.type in CANDIDATE_BATCH_TYPES
    }
    seen_fingerprints: set[str] = set()
    for batch in project.facts:
        if batch.id not in expected_batch_ids:
            continue
        try:
            items = candidate_items(batch, workdir)
        except (ValueError, OSError, KeyError, TypeError):
            return None
        for candidate in items:
            if candidate["fingerprint"] in seen_fingerprints:
                continue
            seen_fingerprints.add(candidate["fingerprint"])
            terminal = terminal_verification(project, batch.id, candidate["fingerprint"])
            if terminal is None or not coverage.reviewed(project, terminal.id):
                attempts = verification_attempts(project, batch.id, candidate["fingerprint"])
                if len(attempts) < config.max_verify_attempts:
                    return None
                latest = _fact(project, attempts[-1].to or "") if attempts else None
                if latest is None or not coverage.reviewed(project, latest.id):
                    return None
                inputs.append(latest.id)
            else:
                inputs.append(terminal.id)
    return sorted(set(inputs))


def summary_proposal(
    project: ProjectDetail,
    workdir: Path,
    config: SemanticAuditConfig,
    *,
    prompt_group: str = "vuln_audit",
) -> dict[str, Any] | None:
    inputs = semantic_summary_inputs(
        project, workdir, config, prompt_group=prompt_group,
    )
    if inputs is None or _proposal_exists(project, SUMMARY_INTENT):
        return None
    return {"from": inputs, "type": "synthesize", "description": SUMMARY_INTENT}


def summary_fact(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: SemanticAuditConfig,
    *,
    prompt_group: str = "vuln_audit",
) -> dict[str, str]:
    inputs = semantic_summary_inputs(
        project, workdir, config, prompt_group=prompt_group,
    )
    if (
        intent.description.strip() != SUMMARY_INTENT
        or intent.type != "synthesize"
        or inputs is None
        or set(intent.from_) != set(inputs)
    ):
        raise ValueError("Semantic summary requires every reviewed semantic branch")
    batches = [fact for fact in project.facts if fact.id in inputs and fact.type in CANDIDATE_BATCH_TYPES]
    candidate_count = len({
        item["fingerprint"]
        for fact in batches
        for item in candidate_items(fact, workdir)
    })
    vulnerabilities = sorted(
        fact.id for fact in project.facts
        if fact.id in inputs and fact.type == "vulnerability" and coverage.reviewed(project, fact.id)
    )
    record = {
        "schema_version": 1,
        "kind": "semantic_summary",
        "status": "completed",
        "input_fact_ids": inputs,
        "recipe_fact_ids": sorted(
            fact.id for fact in project.facts if fact.id in inputs and fact.type in RECIPE_FACT_TYPES
        ),
        "candidate_count": candidate_count,
        "confirmed_vulnerability_ids": vulnerabilities,
        "statement": (
            "Configured semantic recipes and candidate branches completed on the frozen snapshot; "
            "coverage gaps remain evidence and this is not proof of repository safety."
        ),
    }
    directory = workdir / ".linen-analysis" / f"semantic-summary-{uuid.uuid4().hex}"
    directory.mkdir(parents=True)
    path = directory / "semantic-summary.json"
    write_json(path, record)
    return {
        "type": "semantic_summary",
        "description": (
            f"Semantic audit synthesis completed: {candidate_count} candidates, "
            f"{len(vulnerabilities)} confirmed vulnerabilities."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            "status: completed"
        ),
    }
