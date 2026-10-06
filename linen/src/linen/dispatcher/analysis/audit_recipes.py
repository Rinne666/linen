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

from linen.dispatcher.analysis import codeql, coverage, exploitability, recon
from linen.dispatcher.analysis.artifacts import (
    ancestor_ids,
    canonical_endpoint_id,
    canonical_source_citations,
    canonical_vulnerability_trace,
    load_artifact,
    source_bytes,
    vulnerability_trace_proof,
)
from linen.dispatcher.analysis.artifacts import digest, write_json
from linen.dispatcher.config import AuditConfig, SemanticAuditConfig
from linen.server.models import Fact, Intent, ProjectDetail


CREATOR = "dispatcher.audit"
RECIPE_PREFIX = "@analysis:semantic:"
VERIFY_PREFIX = "@analysis:semantic-verify:"
DYNAMIC_RECIPE_PROPOSAL = "@analysis:semantic-generated:v1"
DYNAMIC_RECIPE_PREFIX = DYNAMIC_RECIPE_PROPOSAL + ":"
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
_DYNAMIC_RECIPE_FACT_TYPE = "dynamic_recipe_result"
SEMANTIC_ARTIFACT_FACT_TYPES = RECIPE_FACT_TYPES | {
    "semantic_summary", _DYNAMIC_RECIPE_FACT_TYPE,
}
CANDIDATE_BATCH_TYPES = frozenset({"hypothesis_batch", "variant_batch"})
VERIFY_OUTCOMES = frozenset({"confirmed", "refuted", "blocked"})

_RECIPE_DESCRIPTION = re.compile(
    r"^@analysis:semantic:(?P<recipe>[a-z][a-z0-9_]*):v(?P<version>[1-9][0-9]*)(?::(?P<subject>[A-Za-z0-9._-]+))?$"
)
_VERIFY_DESCRIPTION = re.compile(
    r"^@analysis:semantic-verify:(?P<fact>[A-Za-z0-9][A-Za-z0-9._-]{0,127}):"
    r"(?P<fingerprint>[0-9a-f]{64}):(?P<attempt>[1-9][0-9]*)$"
)
_DYNAMIC_RECIPE_DESCRIPTION = re.compile(
    r"^@analysis:semantic-generated:v1:(?P<digest>[0-9a-f]{64})$"
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DYNAMIC_RECIPE_MAP_TYPES = frozenset({"architecture_map", "contract_map"})
_DYNAMIC_RECIPE_MAX_BYTES = 16_000
_DYNAMIC_RECIPE_MAX_OPERATIONS = 6
_DYNAMIC_RECIPE_MAX_MATCHES = 300
_DYNAMIC_RECIPE_HASH = re.compile(r"^[0-9a-f]{64}$")


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


class DynamicRecipeProposal(BaseModel):
    """Closed, data-only recipe contract proposed by Reason."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)
    question: str = Field(min_length=1, max_length=1000)
    operations: list[dict[str, Any]] = Field(min_length=1, max_length=_DYNAMIC_RECIPE_MAX_OPERATIONS)


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


def _proposal_exists(project: ProjectDetail, description: str) -> bool:
    return any(intent.description.strip() == description for intent in project.intents)


def enabled_recipe_ids(config: SemanticAuditConfig) -> list[str]:
    if not config.enabled:
        return []
    enabled = ["architecture_map"] if config.architecture else []
    if config.authorization:
        enabled.append("authz_matrix")
    if config.state_concurrency:
        enabled.append("state_model")
    if config.cross_service:
        enabled.append("cross_service_map")
    if config.contract:
        enabled.append("contract_map")
    enabled.extend(PROFILE_RECIPES[name] for name in config.hypothesis_profiles)
    if config.variant_search:
        enabled.append("variant_search")
    return enabled


def dynamic_recipe_reason_instructions(
    project: ProjectDetail, config: AuditConfig,
) -> str:
    """Describe the closed generated-recipe proposal format to Reason."""
    if not config.semantic.enabled:
        return ""
    capabilities = []
    if (
        config.review_sandbox.enabled
        and config.review_sandbox.image
        and config.review_sandbox.network == "none"
        and not config.review_sandbox.env_allowlist
    ):
        capabilities.append("frozen_grep.literal")
    if (
        codeql.active_for_project(project, config.codeql)
        and config.codeql.query_profiles
    ):
        capabilities.append("codeql.profile")
    if not capabilities:
        return ""
    capability_text = " and ".join(f"`{item}`" for item in capabilities)
    operation_example = (
        '{"capability":"frozen_grep.literal","literal":"tenant_id",'
        '"path_globs":["src/**/*.py"],"max_results":40}'
        if "frozen_grep.literal" in capabilities else
        '{"capability":"codeql.profile","profile":"<configured-category>","max_results":40}'
    )
    if len(capabilities) > 1:
        operation_example += ',\n   {"capability":"codeql.profile","profile":"<configured-category>","max_results":40}'
    capability_descriptions = []
    if "frozen_grep.literal" in capabilities:
        capability_descriptions.append(
            "`frozen_grep.literal` runs literal UTF-8 searches against the frozen source "
            "snapshot in an isolated offline container. `path_globs` stay within that snapshot."
        )
    if "codeql.profile" in capabilities:
        capability_descriptions.append(
            "`codeql.profile` selects only an operator-configured CodeQL profile ID; "
            "never provide a query path or query body."
        )
    return """

Dynamic semantic recipes (optional, bounded):
When an architecture_map or contract_map Fact exposes a concrete unanswered
source question, you may request one dispatcher-generated recipe. Prefer the
registered architecture_map and contract_map passes first when those Facts do
not exist. A generated recipe is a typed data plan, never a command. Emit the
ordinary Intent fields plus a `semantic_recipe` object exactly in this form:

{"from":["<architecture_map_or_contract_map_fact_id>"],"action":"search",
 "target":"dynamic-semantic-recipe",
 "type":"search","description":"@analysis:semantic-generated:v1",
 "semantic_recipe":{"label":"...","question":"...","operations":[
   """ + operation_example + """
 ]}}

The executable capabilities are """ + capability_text + """.
""" + "\n".join(capability_descriptions) + """
Do not invent shell, scripts, regular expressions, query text, package names,
or filesystem paths. If a profile is not visible, do not propose that capability.
Tree-sitter is unavailable in this runtime.
Keep operations directly relevant to the cited architecture/contract item,
bounded to six operations and at most 300 matches per operation. The dispatcher
stores and hashes a validated recipe artifact before it creates the Intent.
""".strip()


def dynamic_recipe_reason_context(project: ProjectDetail, workdir: Path) -> str:
    """Give Reason a bounded, hash-checked view of the latest typed recipe results."""
    sections = []
    facts = [
        fact for fact in project.facts
        if fact.type == _DYNAMIC_RECIPE_FACT_TYPE
        and fact.source_generation == project.project.source_generation
    ][-6:]
    for fact in facts:
        try:
            _path, record = load_artifact(fact, workdir)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if (
            record.get("kind") != _DYNAMIC_RECIPE_FACT_TYPE
            or record.get("status") != "completed"
        ):
            continue
        citations = {
            item.get("id"): item for item in record.get("citations", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        recipe = record.get("recipe", {})
        rows = [
            f"Dynamic recipe Fact {fact.id}: {str(recipe.get('label', ''))[:120]} — "
            f"{str(recipe.get('question', ''))[:240]}"
        ]
        for operation in record.get("operations", [])[:6]:
            if not isinstance(operation, dict):
                continue
            if operation.get("capability") == "frozen_grep.literal":
                refs = [
                    citations[ref]
                    for ref in operation.get("match_citation_ids", [])[:8]
                    if ref in citations
                ]
                rows.append(
                    f"- literal {str(operation.get('literal', ''))[:100]}: "
                    f"{len(operation.get('match_citation_ids', []))} match(es), "
                    f"{operation.get('files_searched', 0)} file(s) searched"
                )
                for citation in refs:
                    rows.append(
                        f"  frozen source {citation['file']}:{citation['line']}: "
                        f"{citation['code'][:500]}"
                    )
            elif operation.get("capability") == "codeql.profile":
                rows.append(
                    f"- CodeQL profile {operation.get('profile')}: "
                    f"{operation.get('candidate_count', 0)} candidate path(s)"
                )
                for lead in operation.get("leads", [])[:4]:
                    if isinstance(lead, dict):
                        rows.append(
                            f"  {str(lead.get('source', ''))[:200]} -> "
                            f"{str(lead.get('sink', ''))[:200]}: "
                            f"{str(lead.get('hypothesis', ''))[:300]}"
                        )
        rows.append(
            "Treat these bounded tool results as candidate evidence. Verify the complete "
            "path and its guards before drawing a vulnerability conclusion."
        )
        sections.append("\n".join(rows))
    if not sections:
        return ""
    return "\n\nDispatcher-generated semantic recipe results (untrusted candidate evidence):\n" + "\n\n".join(sections)


def _canonical_citations(raw: Any, source: Path, snapshot: dict) -> list[dict[str, Any]]:
    return canonical_source_citations(raw, source, snapshot, label="Semantic")


_COMMON_ITEM_KEYS = {"id", "kind", "title", "summary", "citations"}
_REQUIRED_ITEM_KEYS: dict[str, set[str]] = {
    "architecture_map": _COMMON_ITEM_KEYS,
    "authz_matrix": _COMMON_ITEM_KEYS | {
        "transport", "operation", "handler", "expected_scope", "guards",
        "object_identifier", "ownership_check", "tenant_filter", "candidate", "next_step",
        "endpoint_id",
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
        "confidence", "next_step", "endpoint_id",
    },
    "variant_batch": _COMMON_ITEM_KEYS | {
        "category", "reasoning_model", "attacker_capability", "trust_boundary",
        "violated_invariant", "entry_point", "operation", "consequence",
        "confidence", "next_step", "similarity", "parent_vulnerability", "endpoint_id",
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
        if recipe.fact_type == "architecture_map" and item.get("kind") == "entrypoint":
            item["endpoint_id"] = canonical_endpoint_id(item.get("endpoint_id"))
        elif recipe.fact_type in {"authz_matrix", *CANDIDATE_BATCH_TYPES}:
            item["endpoint_id"] = canonical_endpoint_id(item.get("endpoint_id"))
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
                    "similarity", "parent_vulnerability", "endpoint_id",
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
    snapshot_fact = recon.snapshot_fact(project)
    if snapshot_fact is not None:
        plan_fact, source, plan = recon._snapshot_context(project, workdir)
    else:
        plan_fact, plan_path, plan = coverage.get_plan(project, workdir)
        source = plan_path.parent / "source"
    for filename, expected in plan["snapshot"]["files"].items():
        source_bytes(source, filename, expected)
    return plan_fact, source, plan


def is_dynamic_recipe_proposal(description: str) -> bool:
    return description.strip() == DYNAMIC_RECIPE_PROPOSAL


def is_dynamic_recipe_intent(intent: Intent) -> bool:
    return _DYNAMIC_RECIPE_DESCRIPTION.fullmatch(intent.description.strip()) is not None


def _safe_recipe_dir(workdir: Path, *, create: bool) -> Path:
    root = workdir.resolve(strict=True)
    current = root
    for part in (".linen-analysis", "dynamic-recipes"):
        current = current / part
        if current.is_symlink():
            raise ValueError("Dynamic recipe artifact path contains a symlink")
        if create:
            current.mkdir(mode=0o700, exist_ok=True)
        if current.exists() and (not current.is_dir() or current.resolve().parent != current.parent.resolve()):
            raise ValueError("Dynamic recipe artifact path escaped its dispatcher-owned directory")
    return current


def _plain_text(value: Any, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 and character not in "\t" for character in value)
    ):
        raise ValueError(f"Dynamic recipe {label} must be bounded plain text")
    return value.strip()


def _normalize_dynamic_operations(raw: Any, config: AuditConfig) -> list[dict[str, Any]]:
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > _DYNAMIC_RECIPE_MAX_OPERATIONS
    ):
        raise ValueError("Dynamic recipe operations must contain one to six entries")
    result = []
    seen_profiles: set[str] = set()
    for operation in raw:
        if not isinstance(operation, dict):
            raise ValueError("Dynamic recipe operation must be an object")
        capability = operation.get("capability")
        if capability == "frozen_grep.literal":
            if set(operation) != {"capability", "literal", "path_globs", "max_results"}:
                raise ValueError("Literal-search operation has unexpected fields")
            literal = _plain_text(operation["literal"], "literal", maximum=512)
            if "\n" in literal or "\r" in literal:
                raise ValueError("Literal-search query must fit on one line")
            globs = operation["path_globs"]
            if (
                not isinstance(globs, list) or not globs or len(globs) > 8
                or any(
                    not isinstance(pattern, str)
                    or not pattern.strip()
                    or len(pattern) > 200
                    or pattern.startswith("/")
                    or "\\" in pattern
                    or ".." in pattern.split("/")
                    or any(ord(character) < 0x20 for character in pattern)
                    for pattern in globs
                )
            ):
                raise ValueError("Literal-search path_globs must be bounded snapshot-relative globs")
            maximum = operation["max_results"]
            if type(maximum) is not int or not 1 <= maximum <= _DYNAMIC_RECIPE_MAX_MATCHES:
                raise ValueError("Literal-search max_results must be between 1 and 300")
            result.append({
                "capability": capability,
                "literal": literal,
                "path_globs": list(dict.fromkeys(pattern.strip() for pattern in globs)),
                "max_results": maximum,
            })
        elif capability == "codeql.profile":
            if set(operation) != {"capability", "profile", "max_results"}:
                raise ValueError("CodeQL profile operation has unexpected fields")
            profile = operation["profile"]
            if (
                not isinstance(profile, str)
                or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", profile)
                or not config.codeql.enabled
            ):
                raise ValueError("CodeQL recipe must select an enabled configured profile")
            if profile not in config.codeql.query_profiles:
                raise ValueError("CodeQL profile is not in the operator allowlist")
            if profile in seen_profiles:
                raise ValueError("Dynamic recipe cannot repeat a CodeQL profile")
            seen_profiles.add(profile)
            maximum = operation["max_results"]
            if type(maximum) is not int or not 1 <= maximum <= config.codeql.max_candidates:
                raise ValueError("CodeQL max_results exceeds the configured candidate bound")
            result.append({"capability": capability, "profile": profile, "max_results": maximum})
        else:
            raise ValueError("Dynamic recipe capability is not allowlisted")
    return result


def _map_inputs(
    project: ProjectDetail, source_ids: Any, workdir: Path, snapshot_id: str,
) -> list[str]:
    if (
        not isinstance(source_ids, list) or not source_ids or len(source_ids) > 16
        or any(not isinstance(value, str) for value in source_ids)
    ):
        raise ValueError("Dynamic recipe must reference architecture_map or contract_map Facts")
    selected = []
    found_map = False
    for fact_id in dict.fromkeys(source_ids):
        fact = _fact(project, fact_id)
        if fact is None or fact.source_generation != project.project.source_generation:
            raise ValueError("Dynamic recipe input is not a current-generation Fact")
        if fact.type not in _DYNAMIC_RECIPE_MAP_TYPES:
            continue
        _, record = load_artifact(fact, workdir)
        if record.get("kind") != fact.type or record.get("status") != "completed":
            raise ValueError("Dynamic recipe map input has an invalid artifact")
        if record.get("snapshot", {}).get("id") != snapshot_id:
            raise ValueError("Dynamic recipe map input belongs to a different frozen snapshot")
        selected.append(fact.id)
        found_map = True
    if not found_map:
        raise ValueError("Dynamic recipe must derive from architecture_map or contract_map evidence")
    return selected


def _dynamic_artifact_path(workdir: Path, artifact_hash: str) -> Path:
    if not _DYNAMIC_RECIPE_HASH.fullmatch(artifact_hash):
        raise ValueError("Invalid generated recipe artifact digest")
    return _safe_recipe_dir(workdir, create=False) / f"{artifact_hash}.json"


def store_dynamic_recipe_proposal(
    project: ProjectDetail,
    intent_data: dict[str, Any],
    workdir: Path,
    config: AuditConfig,
    *,
    run_id: str,
    producer: str,
) -> str:
    """Validate Reason's data-only proposal, persist it, and bind its digest."""
    if not config.semantic.enabled or project.project.audit_mode != "scope":
        raise ValueError("Dynamic semantic recipes are disabled for this audit")
    if (
        intent_data.get("action") != "search"
        or intent_data.get("type") != "search"
        or not is_dynamic_recipe_proposal(intent_data.get("description", ""))
    ):
        raise ValueError("Dynamic recipe proposal requires its canonical search Intent")
    plan_fact, _source, plan = _plan_context(project, workdir)
    map_fact_ids = _map_inputs(
        project, intent_data.get("from"), workdir, plan["snapshot"]["id"],
    )
    if plan_fact.id not in ancestor_ids(project, map_fact_ids):
        raise ValueError("Dynamic recipe map inputs must descend from the current frozen snapshot")
    proposal = DynamicRecipeProposal.model_validate(intent_data.get("semantic_recipe"))
    operations = _normalize_dynamic_operations(proposal.operations, config)
    label = _plain_text(proposal.label, "label", maximum=120)
    question = _plain_text(proposal.question, "question", maximum=1000)
    if any(item["capability"] == "frozen_grep.literal" for item in operations):
        if (
            not config.review_sandbox.enabled
            or config.review_sandbox.network != "none"
            or config.review_sandbox.env_allowlist
        ):
            raise ValueError(
                "frozen_grep.literal requires audit.review_sandbox enabled with network=none "
                "and an empty environment allowlist"
            )
    if any(item["capability"] == "codeql.profile" for item in operations):
        if not codeql.active_for_project(project, config.codeql):
            raise ValueError("Dynamic CodeQL recipes require the configured active CodeQL stage")
        for operation in operations:
            if operation["capability"] == "codeql.profile":
                attempts = _profile_attempts(project, workdir, operation["profile"])
                if attempts >= config.codeql.max_query_attempts_per_profile:
                    raise ValueError("Dynamic CodeQL profile reached its configured attempt limit")
    data = {
        "schema_version": 1,
        "kind": "dispatcher_dynamic_semantic_recipe",
        "status": "validated",
        "recipe": {
            "id": digest(json.dumps({
                "label": label,
                "question": question,
                "operations": operations,
                "source_fact_ids": map_fact_ids,
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")),
            "label": label,
            "question": question,
            "operations": operations,
        },
        "provenance": {
            "producer": producer,
            "run_id": run_id,
            "source_generation": project.project.source_generation,
            "plan_revision": project.project.plan_revision,
            "snapshot_fact_id": plan_fact.id,
            "snapshot_id": plan["snapshot"]["id"],
            "snapshot_manifest_sha256": digest(json.dumps(
                plan["snapshot"], ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")),
            "source_fact_ids": map_fact_ids,
        },
    }
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > _DYNAMIC_RECIPE_MAX_BYTES:
        raise ValueError("Generated semantic recipe artifact exceeds its size limit")
    artifact_hash = digest(encoded)
    generated_description = DYNAMIC_RECIPE_PREFIX + artifact_hash
    if _proposal_exists(project, generated_description):
        raise ValueError("An Intent already references this generated recipe artifact")
    directory = _safe_recipe_dir(workdir, create=True)
    path = directory / f"{artifact_hash}.json"
    if path.exists():
        if path.is_symlink() or digest(path.read_bytes()) != artifact_hash:
            raise ValueError("Existing generated recipe artifact failed integrity validation")
    else:
        path.write_bytes(encoded)
        path.chmod(0o444)
    intent_data["from"] = list(dict.fromkeys([*map_fact_ids, plan_fact.id]))
    intent_data["description"] = DYNAMIC_RECIPE_PREFIX + artifact_hash
    intent_data["target"] = "semantic-recipe:" + artifact_hash
    intent_data.pop("semantic_recipe", None)
    return artifact_hash


def _profile_attempts(project: ProjectDetail, workdir: Path, profile: str) -> int:
    count = sum(
        1 for item in project.intents
        if codeql.query_category(item.description) == profile
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
    )
    for item in project.intents:
        match = _DYNAMIC_RECIPE_DESCRIPTION.fullmatch(item.description.strip())
        if (
            match is None or item.source_generation != project.project.source_generation
            or item.plan_revision != project.project.plan_revision
        ):
            continue
        try:
            path = _dynamic_artifact_path(workdir, match.group("digest"))
            raw = path.read_bytes()
            if digest(raw) != match.group("digest"):
                continue
            record = json.loads(raw)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
        operations = record.get("recipe", {}).get("operations", [])
        count += sum(
            1 for operation in operations
            if isinstance(operation, dict)
            and operation.get("capability") == "codeql.profile"
            and operation.get("profile") == profile
        )
    return count


def load_dynamic_recipe(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: AuditConfig,
) -> tuple[str, dict[str, Any], Fact, Path, dict[str, Any]]:
    """Resolve only the hashed, dispatcher-stored recipe for this snapshot."""
    match = _DYNAMIC_RECIPE_DESCRIPTION.fullmatch(intent.description.strip())
    if match is None or intent.type != "search" or not config.semantic.enabled:
        raise ValueError("Intent is not an enabled generated semantic recipe")
    artifact_hash = match.group("digest")
    path = _dynamic_artifact_path(workdir, artifact_hash)
    if path.is_symlink():
        raise ValueError("Generated semantic recipe artifact must not be a symlink")
    raw = path.read_bytes()
    if digest(raw) != artifact_hash:
        raise ValueError("Generated semantic recipe artifact hash mismatch")
    if len(raw) > _DYNAMIC_RECIPE_MAX_BYTES:
        raise ValueError("Generated semantic recipe artifact exceeds its size limit")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Generated semantic recipe artifact is not valid JSON") from exc
    if (
        not isinstance(record, dict)
        or record.get("schema_version") != 1
        or record.get("kind") != "dispatcher_dynamic_semantic_recipe"
        or record.get("status") != "validated"
    ):
        raise ValueError("Generated semantic recipe artifact has an unsupported contract")
    provenance = record.get("provenance")
    recipe = record.get("recipe")
    if not isinstance(provenance, dict) or not isinstance(recipe, dict):
        raise ValueError("Generated semantic recipe artifact is incomplete")
    plan_fact, source, plan = _plan_context(project, workdir)
    if (
        intent.target != "semantic-recipe:" + artifact_hash
        or provenance.get("producer") != intent.creator
        or intent.source_generation != project.project.source_generation
        or intent.plan_revision != project.project.plan_revision
        or provenance.get("source_generation") != project.project.source_generation
        or provenance.get("plan_revision") != project.project.plan_revision
        or provenance.get("snapshot_fact_id") != plan_fact.id
        or provenance.get("snapshot_id") != plan["snapshot"]["id"]
        or provenance.get("snapshot_manifest_sha256") != digest(json.dumps(
            plan["snapshot"], ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        or plan_fact.id not in ancestor_ids(project, intent.from_)
    ):
        raise ValueError("Generated semantic recipe is detached from the current frozen snapshot")
    map_fact_ids = _map_inputs(
        project, provenance.get("source_fact_ids"), workdir, plan["snapshot"]["id"],
    )
    if any(fact_id not in intent.from_ for fact_id in map_fact_ids):
        raise ValueError("Generated semantic recipe Intent omits one of its source map Facts")
    operations = _normalize_dynamic_operations(recipe.get("operations"), config)
    if operations != recipe.get("operations"):
        raise ValueError("Generated semantic recipe operations are not canonical")
    if any(item["capability"] == "codeql.profile" for item in operations):
        if not codeql.active_for_project(project, config.codeql):
            raise ValueError("Generated CodeQL recipe is outside the active CodeQL stage")
        for operation in operations:
            if operation["capability"] == "codeql.profile":
                if _profile_attempts(project, workdir, operation["profile"]) > config.codeql.max_query_attempts_per_profile:
                    raise ValueError("Generated CodeQL profile exceeds its configured attempt limit")
    return artifact_hash, record, plan_fact, source, plan


def dynamic_recipe_outcome_fact(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: AuditConfig,
    cancellation,
    lease,
) -> dict[str, str]:
    """Execute a stored recipe using only the dispatcher-owned typed runners."""
    artifact_hash, definition, snapshot_fact, source, plan = load_dynamic_recipe(
        project, intent, workdir, config,
    )
    operations = definition["recipe"]["operations"]
    grep_operations = [
        operation for operation in operations
        if operation["capability"] == "frozen_grep.literal"
    ]
    grep_result = None
    if grep_operations:
        from linen.dispatcher.analysis.semantic_recipe_execution import run_frozen_grep

        grep_result = run_frozen_grep(
            grep_operations,
            source,
            plan["snapshot"],
            workdir,
            config.review_sandbox,
            cancellation,
            lease,
        )

    codeql_results = []
    for operation in operations:
        if operation["capability"] != "codeql.profile":
            continue
        if cancellation.is_cancelled or lease.failure is not None:
            raise ValueError("Dynamic CodeQL recipe was cancelled")
        query_intent = intent.model_copy(update={
            "description": f"{codeql.QUERY_PREFIX}{operation['profile']}",
            "from_": list(dict.fromkeys([snapshot_fact.id, *intent.from_])),
        })
        query_config = config.codeql.model_copy(update={
            "max_candidates": operation["max_results"],
        })
        record, _snapshot, _citations = codeql._execute(
            project, query_intent, workdir, query_config, cancellation, lease,
        )
        codeql_results.append({"profile": operation["profile"], "record": record})

    citations = []
    operation_results = []
    if grep_result is not None:
        source_index = 0
        grep_index = 0
        for source_index, operation in enumerate(operations):
            if operation["capability"] != "frozen_grep.literal":
                continue
            matches = grep_result["operations"][grep_index]
            citation_rows = []
            for match in matches["matches"]:
                citation_id = f"c{len(citations) + 1}"
                citation = {
                    "id": citation_id,
                    "file": match["file"],
                    "line": match["line"],
                    "code": match["code"],
                }
                citations.append(citation)
                citation_rows.append(citation_id)
            operation_results.append({
                "operation": source_index,
                "capability": operation["capability"],
                "literal": operation["literal"],
                "files_searched": matches["files_searched"],
                "match_citation_ids": citation_rows,
                "skipped_long_lines": matches["skipped_long_lines"],
            })
            grep_index += 1
    canonical = canonical_source_citations(
        citations, source, plan["snapshot"], label="Dynamic semantic recipe",
    )
    if codeql_results:
        for operation_index, result in enumerate(codeql_results):
            operation_results.append({
                "capability": "codeql.profile",
                "operation": next(
                    index for index, item in enumerate(operations)
                    if item["capability"] == "codeql.profile"
                    and item["profile"] == result["profile"]
                ),
                "profile": result["profile"],
                "candidate_count": result["record"].get("candidate_count", 0),
                "snapshot_id": result["record"].get("snapshot_id"),
                "leads": result["record"].get("leads", []),
                "citations": result["record"].get("citations", []),
                "gaps": result["record"].get("gaps", []),
            })
    record = {
        "schema_version": 1,
        "kind": _DYNAMIC_RECIPE_FACT_TYPE,
        "status": "completed",
        "recipe_artifact_sha256": artifact_hash,
        "recipe": definition["recipe"],
        "provenance": definition["provenance"],
        "snapshot": {"id": plan["snapshot"]["id"]},
        "snapshot_fact_id": snapshot_fact.id,
        "input_fact_ids": list(intent.from_),
        "producer": {
            "name": "dispatcher.dynamic_semantic_recipe",
            "sandbox_image_id": grep_result["sandbox"]["image_id"]
            if grep_result is not None else None,
            "network": "none",
            "source_read_only": True,
            "fixed_tools": sorted({item["capability"] for item in operations}),
        },
        "operations": operation_results,
        "citations": canonical,
        "codeql_profiles": codeql_results,
    }
    directory = _safe_recipe_dir(workdir, create=True)
    result_dir = directory / "results"
    if result_dir.is_symlink():
        raise ValueError("Dynamic recipe result path contains a symlink")
    result_dir.mkdir(mode=0o700, exist_ok=True)
    if result_dir.resolve().parent != directory.resolve():
        raise ValueError("Dynamic recipe result escaped its dispatcher-owned directory")
    path = result_dir / f"{uuid.uuid4().hex}.json"
    write_json(path, record)
    return {
        "type": _DYNAMIC_RECIPE_FACT_TYPE,
        "description": (
            f"Generated semantic recipe completed: {len(operation_results)} bounded operation(s), "
            f"{len(canonical)} frozen-source citation(s)."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            f"recipe_sha256: {artifact_hash}\nsnapshot: {plan['snapshot']['id']}\n"
            "status: completed"
        ),
    }


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
            "proof": fact.proof.model_dump(mode="json") if fact.proof is not None else None,
        }
        try:
            path, artifact = load_artifact(fact, workdir)
            entry["artifact"] = str(path)
            entry["artifact_kind"] = artifact.get("kind") or artifact.get("producer", {}).get("name")
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
        context["previous_validation_error"] = validation_error[:8000]

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
) -> dict[str, object]:
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


def _security_check_refs(raw: Any, citation_ids: set[str], label: str) -> list[str]:
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > 16
        or any(not isinstance(item, str) or item not in citation_ids for item in raw)
    ):
        raise ValueError(f"{label} must reference one or more frozen-source citations")
    return list(dict.fromkeys(raw))


def _normalize_security_checks(
    raw: Any, citation_ids: set[str], outcome: str,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {
        "attacker_cases", "protection_checks", "configuration_analysis",
    }:
        raise ValueError(
            "Security checks require attacker_cases, protection_checks, and configuration_analysis"
        )
    cases = raw["attacker_cases"]
    if not isinstance(cases, list) or not cases or len(cases) > 16:
        raise ValueError("Security checks require a bounded non-empty attacker_cases list")
    normalized_cases = []
    case_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "case_id", "input_class", "representative_value", "attacker_control",
            "sink_reachable", "security_effect", "citation_ids",
        }:
            raise ValueError(
                "Each attacker case requires an ID, concrete input, control, sink, effect, and citations"
            )
        if (
            not isinstance(case["case_id"], str)
            or not _ID.fullmatch(case["case_id"])
            or case["case_id"] in case_ids
            or any(not isinstance(case[key], str) or not case[key].strip() or len(case[key]) > 1200
                   for key in ("input_class", "representative_value", "security_effect"))
            or not isinstance(case["attacker_control"], str)
            or case["attacker_control"] not in {"yes", "no", "unknown"}
            or not isinstance(case["sink_reachable"], str)
            or case["sink_reachable"] not in {"yes", "no", "unknown"}
        ):
            raise ValueError("Attacker case has an invalid value or sink outcome")
        case_ids.add(case["case_id"])
        normalized_cases.append({
            "case_id": case["case_id"],
            "input_class": case["input_class"].strip(),
            "representative_value": case["representative_value"].strip(),
            "attacker_control": case["attacker_control"],
            "sink_reachable": case["sink_reachable"],
            "security_effect": case["security_effect"].strip(),
            "citation_ids": _security_check_refs(case["citation_ids"], citation_ids, "Attacker case"),
        })

    protection_checks = raw["protection_checks"]
    if not isinstance(protection_checks, list) or not protection_checks or len(protection_checks) > 24:
        raise ValueError("protection_checks must explicitly assess at least one relevant guard or its absence")
    normalized_protections = []
    for check in protection_checks:
        if not isinstance(check, dict) or set(check) != {
            "protection", "predicate", "attacker_case_id", "predicate_result",
            "resulting_value", "result", "sink_reachable", "citation_ids",
        }:
            raise ValueError("Each protection check requires a predicate, test case, result, and citations")
        text_fields = ("protection", "predicate", "attacker_case_id", "resulting_value")
        if (
            any(not isinstance(check[key], str) or not check[key].strip() or len(check[key]) > 1200
                for key in text_fields)
            or check["attacker_case_id"] not in case_ids
            or not isinstance(check["predicate_result"], str)
            or check["predicate_result"] not in {"accepts", "rejects", "transforms", "not_applicable", "unknown"}
            or not isinstance(check["result"], str)
            or check["result"] not in {"blocks", "bypassable", "not_on_path", "none_found", "unknown"}
            or not isinstance(check["sink_reachable"], str)
            or check["sink_reachable"] not in {"yes", "no", "unknown"}
        ):
            raise ValueError("Protection check has an invalid assessment")
        normalized_protections.append({
            **{key: check[key].strip() for key in text_fields},
            "predicate_result": check["predicate_result"],
            "result": check["result"],
            "sink_reachable": check["sink_reachable"],
            "citation_ids": _security_check_refs(check["citation_ids"], citation_ids, "Protection check"),
        })

    configuration = raw["configuration_analysis"]
    if not isinstance(configuration, dict) or set(configuration) != {
        "default_mode", "ordinary_enabled_mode", "requires_admin_misconfiguration", "summary", "citation_ids",
    }:
        raise ValueError("configuration_analysis does not match the required contract")
    modes = {
        "default_mode": {"enabled", "disabled", "conditional", "unknown", "not_applicable"},
        "ordinary_enabled_mode": {"analyzed", "not_applicable", "unknown"},
        "requires_admin_misconfiguration": {"yes", "no", "unknown", "not_applicable"},
    }
    if (
        any(not isinstance(configuration[key], str) or configuration[key] not in allowed
            for key, allowed in modes.items())
        or not isinstance(configuration["summary"], str)
        or not configuration["summary"].strip()
        or len(configuration["summary"]) > 2000
    ):
        raise ValueError("configuration_analysis has an invalid mode or summary")
    normalized_configuration = {
        **{key: configuration[key] for key in modes},
        "summary": configuration["summary"].strip(),
        "citation_ids": _security_check_refs(
            configuration["citation_ids"], citation_ids, "Configuration analysis",
        ),
    }

    for check in normalized_protections:
        if check["result"] == "blocks" and (
            check["predicate_result"] != "rejects" or check["sink_reachable"] != "no"
        ):
            raise ValueError("A protection only blocks when its tested predicate rejects before the sink")
        case = next(
            item for item in normalized_cases if item["case_id"] == check["attacker_case_id"]
        )
        if check["result"] == "blocks" and case["sink_reachable"] == "yes":
            raise ValueError("A blocked protection cannot also leave its linked attacker case reaching the sink")
        if check["result"] == "none_found" and check["predicate_result"] != "not_applicable":
            raise ValueError("A no-protection result must mark the predicate not_applicable")

    if normalized_configuration["default_mode"] in {"enabled", "disabled", "conditional"}:
        if normalized_configuration["ordinary_enabled_mode"] == "not_applicable":
            raise ValueError("A configurable feature cannot mark its ordinary enabled mode not_applicable")
        if normalized_configuration["requires_admin_misconfiguration"] == "not_applicable":
            raise ValueError("A configurable feature must state whether admin misconfiguration is required")
    elif normalized_configuration["default_mode"] == "unknown":
        if normalized_configuration["ordinary_enabled_mode"] != "unknown":
            raise ValueError("Unknown configuration defaults must retain enabled-mode uncertainty")
    elif normalized_configuration["default_mode"] == "not_applicable":
        if normalized_configuration["ordinary_enabled_mode"] != "not_applicable":
            raise ValueError("A configuration-independent path cannot claim an enabled mode was analyzed")
        if normalized_configuration["requires_admin_misconfiguration"] not in {"no", "not_applicable"}:
            raise ValueError("A configuration-independent path cannot require admin misconfiguration")

    if outcome in {"confirmed", "refuted"}:
        if any(
            case["attacker_control"] == "unknown" or case["sink_reachable"] == "unknown"
            for case in normalized_cases
        ):
            raise ValueError("Unresolved attacker control or sink reachability must remain blocked")
        if any(check["result"] == "unknown" for check in normalized_protections):
            raise ValueError("Unresolved protection effects must remain blocked")
        if (
            normalized_configuration["default_mode"] == "unknown"
            or normalized_configuration["ordinary_enabled_mode"] == "unknown"
            or normalized_configuration["requires_admin_misconfiguration"] == "unknown"
        ):
            raise ValueError("Unresolved configuration facts must remain blocked")

    if outcome == "confirmed":
        if normalized_configuration["requires_admin_misconfiguration"] == "yes":
            raise ValueError("An admin-misconfiguration prerequisite cannot establish a confirmed vulnerability")
        if not any(
            case["attacker_control"] == "yes" and case["sink_reachable"] == "yes"
            for case in normalized_cases
        ):
            raise ValueError("Confirmed outcome needs a cited attacker-controlled case that reaches the sink")
    elif (
        outcome == "refuted"
        and normalized_configuration["requires_admin_misconfiguration"] != "yes"
        and any(
            case["attacker_control"] == "yes" and case["sink_reachable"] == "yes"
            for case in normalized_cases
        )
    ):
        raise ValueError("A refuted result cannot retain an attacker-controlled path to the sink")
    return {
        "attacker_cases": normalized_cases,
        "protection_checks": normalized_protections,
        "configuration_analysis": normalized_configuration,
    }


def verification_outcome_fact(
    payload: dict[str, Any], project: ProjectDetail, intent: Intent, workdir: Path,
) -> dict[str, object]:
    batch, candidate = verification_target(project, intent, workdir)
    data = payload.get("data", payload)
    expected_keys = {
        "description", "type", "evidence", "citations", "candidate_disposition",
        "endpoint_id", "trace", "security_checks",
    }
    optional_keys = {
        "provenance", "root_cause", "variants_checked", "vulnerability_class",
        "sink_context", "path_conditions",
    }
    if not isinstance(data, dict) or not expected_keys <= set(data) or set(data) - expected_keys - optional_keys:
        raise ValueError(
            "Semantic verification requires exactly description, type, evidence, "
            "citations, endpoint_id, trace, security_checks, and candidate_disposition; provenance, "
            "root_cause, and variants_checked are optional"
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
    if (
        not isinstance(outcome, str)
        or outcome not in VERIFY_OUTCOMES
        or not isinstance(rationale, str)
        or not rationale.strip()
    ):
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
    security_checks = _normalize_security_checks(
        data.get("security_checks"), {item["id"] for item in citations}, outcome,
    )
    endpoint_id = canonical_endpoint_id(data.get("endpoint_id"))
    trace = canonical_vulnerability_trace(
        data.get("trace"), citations, source, plan["snapshot"], outcome=outcome,
    )
    vulnerability_class, sink_context, path_conditions = _normalize_prescreen_inputs(
        data, source, plan["snapshot"], citations, trace,
    )
    prescreen = None
    if outcome == "confirmed" and vulnerability_class and sink_context and path_conditions is not None:
        prescreen = _evaluate_semantic_prescreen(
            vulnerability_class, sink_context, path_conditions, trace,
            source, plan["snapshot"], workdir, candidate["fingerprint"],
        )
    if (
        prescreen is not None
        and prescreen["result"].status == exploitability.PrescreenStatus.FAIL
    ):
        result = prescreen["result"]
        screen_ref = prescreen["artifact"]
        screen_summary = {
            "artifact": screen_ref["path"],
            "manifest_sha256": screen_ref["sha256"],
            "result": result.as_dict(),
        }
        refutation = {
            "schema_version": 1,
            "source": "semantic_recipe_prescreen",
            "batch_fact_id": batch.id,
            "fingerprint": candidate["fingerprint"],
            "outcome": "refuted",
            "rationale": (
                "Deterministic exploitability pre-screen proved the supplied path "
                "infeasible or protected."
            ),
            "candidate": candidate,
            "exploitability_prescreen": screen_summary,
        }
        return {
            "type": "candidate_disposition",
            "description": (
                "Candidate refuted by deterministic exploitability pre-screen: "
                + ", ".join(result.reason_codes)
            ),
            "evidence": json.dumps(refutation, ensure_ascii=False),
        }

    envelope = {
        "schema_version": 1,
        "source": "semantic_recipe",
        "batch_fact_id": batch.id,
        "fingerprint": candidate["fingerprint"],
        "outcome": outcome,
        "rationale": rationale.strip(),
        "candidate": candidate,
        "endpoint_id": endpoint_id,
        "citations": citations,
        "security_checks": security_checks,
        "worker_evidence": evidence.strip(),
    }
    proof = vulnerability_trace_proof(
        trace, endpoint_id, outcome, plan["snapshot"]["id"],
        provenance=data.get("provenance"),
        root_cause=data.get("root_cause"),
        variants_checked=data.get("variants_checked"),
        security_checks=security_checks,
        vulnerability_class=vulnerability_class,
        sink_context=sink_context,
        path_conditions=path_conditions,
    )
    if prescreen is not None:
        result = prescreen["result"]
        screen_ref = prescreen["artifact"]
        receipt = {
            "artifact": screen_ref["path"],
            "manifest_sha256": screen_ref["sha256"],
            "result": result.as_dict(),
        }
        envelope["exploitability_prescreen"] = receipt
        proof["attributes"]["exploitability_prescreen"] = receipt
    return {
        "type": fact_type,
        "description": description.strip(),
        "evidence": json.dumps(envelope, ensure_ascii=False),
        "proof": proof,
    }


def _normalize_prescreen_inputs(
    data: dict[str, Any], source: Path, snapshot: dict[str, Any],
    citations: list[dict[str, Any]], trace: list[dict[str, Any]],
) -> tuple[str | None, str | None, list[dict[str, Any]] | None]:
    keys = {"vulnerability_class", "sink_context", "path_conditions"}
    present = keys & set(data)
    if not present:
        return None, None, None
    if present != keys:
        return None, None, None
    allowed = {
        "xss": "html_text",
        "cross_site_scripting": "html_text",
        "command_injection": "posix_shell_argument",
        "os_command_injection": "posix_shell_argument",
    }
    vulnerability_class = data["vulnerability_class"]
    sink_context = data["sink_context"]
    if (
        not isinstance(vulnerability_class, str)
        or vulnerability_class not in allowed
        or not isinstance(sink_context, str)
        or allowed[vulnerability_class] != sink_context
    ):
        return None, None, None
    conditions = data["path_conditions"]
    if (
        not isinstance(conditions, list)
        or len(conditions) > exploitability.MAX_PATH_CONDITIONS
    ):
        return None, None, None
    cited_lines = {
        (item["file"], item["line"]) for item in citations
    }
    trace_lines = {(item["file"], item["line"]) for item in trace}
    normalized = []
    for condition in conditions:
        if not isinstance(condition, dict) or set(condition) != {
            "file", "line", "expression", "branch_taken",
        }:
            return None, None, None
        filename = condition["file"]
        line = condition["line"]
        expression = condition["expression"]
        branch_taken = condition["branch_taken"]
        if (
            not isinstance(filename, str)
            or filename not in snapshot.get("files", {})
            or type(line) is not int
            or line < 1
            or not isinstance(expression, str)
            or not expression.strip()
            or len(expression) > 512
            or any(ord(character) < 0x20 for character in expression)
            or type(branch_taken) is not bool
            or (filename, line) not in cited_lines
            or (filename, line) not in trace_lines
        ):
            return None, None, None
        try:
            content = source_bytes(source, filename, snapshot["files"][filename]).decode(
                "utf-8", errors="replace",
            )
        except (OSError, ValueError, TypeError):
            return None, None, None
        source_lines = content.splitlines()
        if line > len(source_lines) or expression not in source_lines[line - 1]:
            return None, None, None
        normalized.append({
            "file": filename,
            "line": line,
            "expression": expression.strip(),
            "branch_taken": branch_taken,
        })
    return vulnerability_class, sink_context, normalized


def _evaluate_semantic_prescreen(
    vulnerability_class: str,
    sink_context: str,
    path_conditions: list[dict[str, Any]],
    trace: list[dict[str, Any]],
    source: Path,
    snapshot: dict[str, Any],
    workdir: Path,
    candidate_id: str,
) -> dict[str, Any] | None:
    """Evaluate and persist only fully typed, source-bound semantic inputs."""
    try:
        request = exploitability.PrescreenInput(
            source=exploitability.FrozenSource(
                root=source,
                snapshot_id=snapshot["id"],
                files=dict(snapshot["files"]),
                skipped=tuple(snapshot.get("skipped", [])),
            ),
            vulnerability_class=vulnerability_class,
            sink_context=sink_context,
            trace=tuple(exploitability.TraceStep(
                file=item["file"], line=item["line"],
                symbol=item["symbol"], kind=item["kind"],
            ) for item in trace),
            path_conditions=tuple(exploitability.PathCondition(
                file=item["file"], line=item["line"],
                expression=item["expression"], branch_taken=item["branch_taken"],
            ) for item in path_conditions),
            trace_complete=True,
        )
        result = exploitability.evaluate_prescreen(request)
    except (KeyError, TypeError, ValueError, OSError, UnicodeError, RecursionError):
        # Screening is optional. If its typed contract cannot be formed, the
        # ordinary candidate remains eligible for review.
        return None

    try:
        directory = _prescreen_artifact_directory(workdir)
        if directory is None:
            return None
        path = directory / f"{uuid.uuid4().hex}.json"
        record = {
            "schema_version": 1,
            "kind": "exploitability_prescreen",
            "status": result.status.value,
            "candidate_id": candidate_id,
            "snapshot_id": result.snapshot_id,
            "input_sha256": result.input_sha256,
            "result": result.as_dict(),
            "provenance": {
                "producer": "dispatcher.exploitability_prescreen",
                "version": exploitability.PRESCREEN_VERSION,
                "source_snapshot_id": snapshot["id"],
            },
        }
        write_json(path, record)
        path.chmod(0o444)
        artifact_hash = digest(path.read_bytes())
    except OSError:
        return None
    return {"result": result, "artifact": {"path": str(path), "sha256": artifact_hash}}


def _prescreen_artifact_directory(workdir: Path) -> Path | None:
    """Create the bounded screen artifact directory under dispatcher analysis data."""
    root = workdir.resolve(strict=True)
    analysis = root / ".linen-analysis"
    if analysis.is_symlink():
        return None
    analysis.mkdir(mode=0o700, exist_ok=True)
    if analysis.resolve().parent != root:
        return None
    directory = analysis / "prescreen"
    if directory.is_symlink():
        return None
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.resolve().parent != analysis.resolve():
        return None
    return directory


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
