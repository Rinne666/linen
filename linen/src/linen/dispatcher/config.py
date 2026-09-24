from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from importlib import resources
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


TaskType = Literal["reason", "explore", "review"]
WorkerType = Literal["claudecode", "codex", "pi", "mock"]
WorkerHealthcheckMode = Literal["startup_and_task", "startup_only", "disabled"]
LocalCompletedAction = Literal["keep", "remove"]


DEFAULT_PROMPT_REQUIRED_TOKENS: dict[str, tuple[str, ...]] = {
    "reason.md": ("{graph_yaml}", "{fact_ids}", "{open_intents}", "{max_intents}"),
    "explore.md": ("{graph_yaml}", "{intent_id}", "{intent_description}"),
    "explore_conclude.md": ("{graph_yaml}", "{intent_id}", "{intent_description}"),
    "review.md": ("{graph_yaml}", "{intent_id}", "{fact_block}", "{intent_description}"),
    "review_cold_verifier.md": ("{graph_yaml}", "{intent_id}", "{fact_block}", "{intent_description}"),
    "review_contradiction_reasoner.md": ("{graph_yaml}", "{intent_id}", "{fact_block}", "{intent_description}"),
}

PROMPT_REQUIRED_TOKENS_BY_GROUP: dict[str, dict[str, tuple[str, ...]]] = {
    "mock": {
        "reason.md": ("{fact_ids}", "{open_intents}", "{max_intents}"),
        "explore.md": ("{intent_id}",),
        "explore_conclude.md": ("{intent_id}",),
        "review.md": ("{intent_id}", "{fact_block}", "{intent_description}"),
        "review_cold_verifier.md": ("{intent_id}", "{fact_block}", "{intent_description}"),
        "review_contradiction_reasoner.md": ("{intent_id}", "{fact_block}", "{intent_description}"),
    },
    "vuln_audit": {
        **DEFAULT_PROMPT_REQUIRED_TOKENS,
        "reason_scope.md": ("{graph_yaml}", "{fact_ids}", "{open_intents}", "{max_intents}"),
        "review_attestation.md": ("{graph_yaml}", "{intent_id}", "{fact_block}", "{intent_description}"),
        "review_summary.md": ("{graph_yaml}", "{intent_id}", "{fact_block}", "{intent_description}"),
    },
}

MOCK_ALLOWED_OUTCOMES: dict[str, frozenset[str]] = {
    "healthcheck": frozenset({"ok", "fail"}),
    "reason": frozenset({"complete", "intent", "noop", "rejected", "invalid_json", "invalid_payload", "command_fail"}),
    "explore_execute": frozenset({"fact", "rejected", "invalid_json", "invalid_payload", "command_fail"}),
    "explore_conclude": frozenset({"fact", "rejected", "invalid_json", "invalid_payload", "command_fail"}),
}

MOCK_DEFAULT_BEHAVIOR: dict[str, dict[str, Any]] = {
    "healthcheck": {
        "delay": [0.05, 0.15],
        "outcomes": {"ok": "1.0", "fail": "0.0"},
    },
    "reason": {
        "delay": [0.05, 0.3],
        "outcomes": {
            "complete": "0.0",
            "intent": "1.0",
            "noop": "0.0",
            "rejected": "0.0",
            "invalid_json": "0.0",
            "invalid_payload": "0.0",
            "command_fail": "0.0",
        },
    },
    "explore_execute": {
        "delay": [0.05, 0.3],
        "outcomes": {
            "fact": "1.0",
            "rejected": "0.0",
            "invalid_json": "0.0",
            "invalid_payload": "0.0",
            "command_fail": "0.0",
        },
    },
    "explore_conclude": {
        "delay": [0.05, 0.3],
        "outcomes": {
            "fact": "1.0",
            "rejected": "0.0",
            "invalid_json": "0.0",
            "invalid_payload": "0.0",
            "command_fail": "0.0",
        },
    },
}

MOCK_ALLOWED_ENV_KEYS = frozenset(
    {f"MOCK_{phase.upper()}" for phase in MOCK_ALLOWED_OUTCOMES}
)


class ReasonTaskConfig(BaseModel):
    timeout: int = Field(gt=0)
    max_intents: int = Field(gt=0, default=3)


class ExploreTaskConfig(BaseModel):
    timeout: int = Field(gt=0)
    conclude_timeout: int = Field(gt=0)


class ReviewTaskConfig(BaseModel):
    """Review task — adversarially validates a candidate fact.

    Mirrors ExploreTaskConfig's shape so the worker-driver code path can
    reuse the same per-phase timeout machinery. Kept optional in
    TasksConfig; when missing, `tasks/review.py` falls back to
    `explore.timeout` so older dispatch.yaml files keep working.

    `mode` is the default review mode used when an intent's `type` is
    just `"review"` (no `review:<mode>` suffix). Per-intent mode
    overrides win when the reason worker emits a `review:<mode>` intent.
    """

    timeout: int = Field(gt=0)
    conclude_timeout: int = Field(gt=0)
    mode: Literal["devils-advocate", "cold-verifier", "contradiction-reasoner"] = "devils-advocate"


class TasksConfig(BaseModel):
    reason: ReasonTaskConfig
    explore: ExploreTaskConfig
    # Optional for backwards-compat. If absent, the review task reuses
    # `explore.timeout` (see `tasks/review.py`).
    review: ReviewTaskConfig | None = None


class LocalConfig(BaseModel):
    workspace_root: str | None = None
    completed_action: LocalCompletedAction = "keep"
    agents_md: Path | None = None
    # When set, every new project workdir gets a `<workdir>/repo` symlink
    # pointing at this path. This is how source-code audit projects expose
    # the target repository to the worker (the worker's CWD is the workdir,
    # and `repo/` is the symlink it should `cd` into to read source).
    repo_root: str | None = None


class RuntimeConfig(BaseModel):
    max_workers: int = Field(gt=0)
    max_running_projects: int = Field(gt=0)
    max_project_workers: int = Field(gt=0)
    interval: int = Field(gt=0)
    healthcheck_timeout: int = Field(gt=0)
    worker_healthcheck: WorkerHealthcheckMode = "startup_only"
    prompt_group: str = Field(min_length=1)


class WorkerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: WorkerType
    task_types: list[TaskType]
    max_running: int = Field(gt=0)
    priority: int = Field(ge=0)
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("task_types")
    @classmethod
    def validate_task_types(cls, value: list[TaskType]) -> list[TaskType]:
        if not value:
            raise ValueError("task_types must not be empty")
        if len(set(value)) != len(value):
            raise ValueError("task_types must be unique")
        return value

    @model_validator(mode="after")
    def validate_env(self) -> "WorkerConfig":
        # Required LLM env keys (base_url / key / model) are enforced per execution mode by
        # DispatchConfig: container mode needs them, local mode reuses the host CLI config.
        # The checks below are mode-independent and always apply.
        if self.type == "pi":
            _validate_optional_positive_int_env(self.name, self.env, "PI_MODEL_CONTEXT_WINDOW")
        if self.type == "mock":
            resolve_mock_behavior(self.name, self.env)
        return self


class CoverageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    topics: list[str] = Field(default_factory=lambda: ["input-validation", "authorization", "dangerous-operations"])
    files_per_cell: int = Field(default=40, gt=0, le=200)
    max_cells: int = Field(default=1000, gt=0)
    max_attempts_per_cell: int = Field(default=3, gt=0)
    max_target_bytes: int = Field(default=2_000_000, gt=0)
    exclude: list[str] = Field(default_factory=lambda: [".git", ".venv", "node_modules", "__pycache__"])

    @field_validator("topics")
    @classmethod
    def valid_topics(cls, value: list[str]) -> list[str]:
        import re
        if not value or len(set(value)) != len(value) or any(
            not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item) for item in value
        ):
            raise ValueError("coverage.topics must contain unique non-empty lowercase topic IDs")
        return value


class ReviewSandboxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    image: str | None = None
    executable: str = "docker"
    network: Literal["none", "bridge"] = "none"
    user: str = "1000:1000"
    memory: str = "2g"
    cpus: float = Field(default=2, gt=0)
    pids_limit: int = Field(default=256, gt=0)
    # Only these names cross from worker.env / host env into the container.
    env_allowlist: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sandbox(self) -> "ReviewSandboxConfig":
        import re
        if self.enabled and (not self.image or self.image.startswith("-")):
            raise ValueError("review_sandbox.image is required")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user):
            raise ValueError("review_sandbox.user must be a non-root numeric UID:GID")
        if not re.fullmatch(r"[1-9][0-9]*[bkmg]?", self.memory.lower()):
            raise ValueError("review_sandbox.memory must be a Docker memory size")
        for name in self.env_allowlist:
            if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", name)
                    or name in {"HOME", "PATH", "TMPDIR", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}
                    or name.startswith("DOCKER_")):
                raise ValueError(f"Invalid sandbox environment name: {name}")
        return self


class ReconConfig(BaseModel):
    """Optional, non-authoritative reconnaissance before scope coverage.

    Recon is deliberately opt-in.  It may prioritize the first coverage cells,
    but it never contributes evidence to a vulnerability proof and can never
    complete an audit project.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class ScopeAdjudicationConfig(BaseModel):
    """Evidence-backed policy gate that precedes scope coverage planning.

    Collection is deterministic and host-owned.  The existing Explore worker
    only adjudicates the frozen documents; it never receives network access or
    protocol-write authority from this feature.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    local_paths: list[str] = Field(default_factory=lambda: [
        "SECURITY.md",
        ".github/SECURITY.md",
        "README.md",
        "CONTRIBUTING.md",
        "docs/**/security*.md",
        "docs/**/threat*.md",
        "docs/**/architecture*.md",
        "docs/**/deployment*.md",
    ])
    policy_urls: list[str] = Field(default_factory=list)
    github_advisories: bool = False
    fetch_timeout: int = Field(default=15, gt=0, le=120)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_documents: int = Field(default=64, gt=0, le=500)
    max_document_bytes: int = Field(default=1_000_000, gt=0, le=10_000_000)

    @field_validator("local_paths")
    @classmethod
    def validate_local_paths(cls, value: list[str]) -> list[str]:
        if not value or len(value) != len(set(value)):
            raise ValueError("scope_adjudication.local_paths must be non-empty and unique")
        for pattern in value:
            path = Path(pattern)
            if (
                not pattern.strip()
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in pattern
                or "\x00" in pattern
            ):
                raise ValueError(
                    "scope_adjudication.local_paths must contain safe relative glob patterns"
                )
        return value

    @field_validator("policy_urls")
    @classmethod
    def validate_policy_urls(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("scope_adjudication.policy_urls must be unique")
        for url in value:
            parsed = urlparse(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError(
                    "scope_adjudication.policy_urls must be credential-free HTTPS URLs without fragments"
                )
        return value


class PocSandboxConfig(ReviewSandboxConfig):
    """Disposable isolation used by ``poc:isolated`` explore intents."""


class SemanticAuditConfig(BaseModel):
    """LLM recipe passes materialized as ordinary blackboard work.

    Recipes are execution profiles of the existing Explore worker. They do not
    introduce new worker roles or grant the model protocol-write authority.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    architecture: bool = True
    authorization: bool = True
    state_concurrency: bool = True
    cross_service: bool = True
    contract: bool = True
    hypothesis_profiles: list[Literal[
        "backward", "contradiction", "attack-composition",
    ]] = Field(default_factory=lambda: [
        "backward", "contradiction", "attack-composition",
    ])
    variant_search: bool = True
    max_verify_attempts: int = Field(default=2, gt=0, le=5)

    @field_validator("hypothesis_profiles")
    @classmethod
    def unique_hypothesis_profiles(cls, value: list[str]) -> list[str]:
        if not value or len(value) != len(set(value)):
            raise ValueError("semantic.hypothesis_profiles must be non-empty and unique")
        return value


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Opt-in audit policies; generic projects are unchanged.  A source audit
    # defaults to scope coverage rather than stopping after one hypothesis.
    enabled: bool = False
    mode: Literal["hypothesis", "scope"] = "scope"
    coverage: CoverageConfig = Field(default_factory=CoverageConfig)
    review_sandbox: ReviewSandboxConfig = Field(default_factory=ReviewSandboxConfig)
    poc_sandbox: PocSandboxConfig = Field(default_factory=PocSandboxConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    scope_adjudication: ScopeAdjudicationConfig = Field(
        default_factory=ScopeAdjudicationConfig
    )
    semantic: SemanticAuditConfig = Field(default_factory=SemanticAuditConfig)


class DispatchConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    runtime: RuntimeConfig
    tasks: TasksConfig
    local: LocalConfig = Field(default_factory=LocalConfig)
    common_env: dict[str, str] = Field(default_factory=dict)
    workers: list[WorkerConfig]
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @model_validator(mode="before")
    @classmethod
    def merge_common_env(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        common_env = data.get("common_env")
        if common_env is None:
            common_env = {}
        workers = data.get("workers")
        if not isinstance(common_env, dict) or not isinstance(workers, list):
            return data

        merged = dict(data)
        merged_workers: list[Any] = []
        for worker in workers:
            if not isinstance(worker, dict):
                merged_workers.append(worker)
                continue
            worker_env = worker.get("env")
            if worker_env is None:
                worker_env = {}
            if not isinstance(worker_env, dict):
                merged_workers.append(worker)
                continue
            worker_copy = dict(worker)
            worker_copy["env"] = {**common_env, **worker_env}
            merged_workers.append(worker_copy)
        merged["workers"] = merged_workers
        return merged

    @model_validator(mode="after")
    def validate_workers(self) -> "DispatchConfig":
        names = [worker.name for worker in self.workers]
        if len(set(names)) != len(names):
            raise ValueError("worker names must be unique")
        if not self.workers:
            raise ValueError("workers must not be empty")
        if self.audit.enabled:
            if self.audit.recon.enabled and self.audit.mode != "scope":
                raise ValueError("audit recon requires scope mode")
            if not any("review" in worker.task_types for worker in self.workers):
                raise ValueError("audit mode requires at least one review worker")
        if self.audit.scope_adjudication.enabled and not self.audit.enabled:
            raise ValueError("scope adjudication requires audit.enabled")
        if self.audit.scope_adjudication.enabled and self.audit.mode != "scope":
            raise ValueError("scope adjudication requires scope audit mode")
        if (
            self.audit.scope_adjudication.enabled
            and self.runtime.prompt_group != "vuln_audit"
        ):
            raise ValueError("scope adjudication requires runtime.prompt_group: vuln_audit")
        if self.audit.scope_adjudication.enabled and not any(
            "explore" in worker.task_types for worker in self.workers
        ):
            raise ValueError("scope adjudication requires at least one explore worker")
        if self.audit.semantic.enabled and not self.audit.enabled:
            raise ValueError("semantic recipes require audit.enabled")
        if self.audit.semantic.enabled and self.audit.mode != "scope":
            raise ValueError("semantic recipes currently require scope audit mode")
        if self.audit.semantic.enabled and self.runtime.prompt_group != "vuln_audit":
            raise ValueError("semantic recipes require runtime.prompt_group: vuln_audit")
        if self.audit.semantic.enabled and not any(
            "explore" in worker.task_types for worker in self.workers
        ):
            raise ValueError("semantic recipes require at least one explore worker")
        # `mode` is inert while audit is disabled (and defaults to scope for
        # the next audit run).  An enabled sandbox, however, must never be
        # silently ignored.
        if self.audit.review_sandbox.enabled and not self.audit.enabled:
            raise ValueError("review sandbox requires audit.enabled")
        if self.audit.poc_sandbox.enabled and not self.audit.enabled:
            raise ValueError("PoC sandbox requires audit.enabled")
        if self.audit.poc_sandbox.enabled and not any("explore" in worker.task_types for worker in self.workers):
            raise ValueError("PoC sandbox requires at least one explore worker")
        if self.runtime.max_project_workers > self.runtime.max_workers:
            raise ValueError("max_project_workers cannot exceed max_workers")
        return self

    @classmethod
    def load(cls, path: Path) -> "DispatchConfig":
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        config = cls.model_validate(data)
        validate_prompt_resources(config.runtime.prompt_group)
        return config


def _validate_optional_positive_int_env(worker_name: str, env: dict[str, str], key: str) -> None:
    value = env.get(key)
    if value is None or not value.strip():
        return
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"worker {worker_name} env {key} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"worker {worker_name} env {key} must be greater than 0")


def validate_prompt_resources(prompt_group: str) -> None:
    prompts_dir = resources.files("linen.dispatcher.prompts")
    group_dir = prompts_dir.joinpath(prompt_group)
    if not group_dir.is_dir():
        raise ValueError(f"missing prompt group: {prompt_group}")
    required_tokens = PROMPT_REQUIRED_TOKENS_BY_GROUP.get(prompt_group, DEFAULT_PROMPT_REQUIRED_TOKENS)
    for name, tokens in required_tokens.items():
        try:
            content = group_dir.joinpath(name).read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ValueError(f"prompt group {prompt_group} missing resource: {name}") from exc
        missing = [token for token in tokens if token not in content]
        if missing:
            raise ValueError(f"prompt group {prompt_group} resource {name} missing placeholders: {', '.join(missing)}")
    if prompt_group == "vuln_audit":
        from linen.dispatcher.analysis.audit_recipes import load_bundle

        load_bundle(prompt_group)


def resolve_mock_behavior(worker_name: str, env: dict[str, str]) -> dict[str, dict[str, Any]]:
    unknown = sorted(key for key in env if key.startswith("MOCK_") and key not in MOCK_ALLOWED_ENV_KEYS)
    if unknown:
        raise ValueError(f"worker {worker_name} has unsupported mock env keys: {', '.join(unknown)}")

    behavior: dict[str, dict[str, Any]] = {}
    for phase, allowed_outcomes in MOCK_ALLOWED_OUTCOMES.items():
        prefix = _mock_env_prefix(phase)
        payload = _parse_mock_phase_payload(worker_name, env, prefix, MOCK_DEFAULT_BEHAVIOR[phase])
        min_delay, max_delay = _parse_mock_delay_range(worker_name, prefix, payload.get("delay"))
        if max_delay < min_delay:
            raise ValueError(f"worker {worker_name} {prefix}.delay[1] must be greater than or equal to delay[0]")
        raw_outcomes = payload.get("outcomes")
        if not isinstance(raw_outcomes, dict):
            raise ValueError(f"worker {worker_name} {prefix}.outcomes must be an object")
        unknown_outcomes = sorted(set(raw_outcomes) - allowed_outcomes)
        if unknown_outcomes:
            raise ValueError(f"worker {worker_name} {prefix}.outcomes has unsupported keys: {', '.join(unknown_outcomes)}")
        outcomes: dict[str, float] = {}
        total = Decimal("0")
        for outcome in sorted(allowed_outcomes):
            weight = _parse_mock_probability(
                worker_name,
                prefix,
                raw_outcomes,
                outcome,
            )
            outcomes[outcome] = float(weight)
            total += weight
        if total != Decimal("1"):
            raise ValueError(f"worker {worker_name} {prefix}.outcomes probabilities must sum to 1.0, got {total}")
        behavior[phase] = {
            "delay": {"min": min_delay, "max": max_delay},
            "outcomes": outcomes,
        }
        rules = payload.get("rules")
        if rules is not None:
            if not isinstance(rules, list):
                raise ValueError(f"worker {worker_name} {prefix}.rules must be an array")
            normalized_rules: list[dict[str, Any]] = []
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    raise ValueError(f"worker {worker_name} {prefix}.rules[{index}] must be an object")
                force = rule.get("force")
                if not isinstance(force, str) or force not in allowed_outcomes:
                    raise ValueError(
                        f"worker {worker_name} {prefix}.rules[{index}].force must be one of: {', '.join(sorted(allowed_outcomes))}"
                    )
                entry: dict[str, Any] = {"force": force}
                if "fact_ids_gte" in rule:
                    value = rule["fact_ids_gte"]
                    if not isinstance(value, int) or value < 0:
                        raise ValueError(f"worker {worker_name} {prefix}.rules[{index}].fact_ids_gte must be a non-negative integer")
                    entry["fact_ids_gte"] = value
                if "fact_ids_lte" in rule:
                    value = rule["fact_ids_lte"]
                    if not isinstance(value, int) or value < 0:
                        raise ValueError(f"worker {worker_name} {prefix}.rules[{index}].fact_ids_lte must be a non-negative integer")
                    entry["fact_ids_lte"] = value
                if "open_intents_empty" in rule:
                    value = rule["open_intents_empty"]
                    if not isinstance(value, bool):
                        raise ValueError(f"worker {worker_name} {prefix}.rules[{index}].open_intents_empty must be boolean")
                    entry["open_intents_empty"] = value
                normalized_rules.append(entry)
            behavior[phase]["rules"] = normalized_rules
    return behavior


def _mock_env_prefix(phase: str) -> str:
    return f"MOCK_{phase.upper()}"


def _parse_mock_phase_payload(worker_name: str, env: dict[str, str], key: str, default: dict[str, Any]) -> dict[str, Any]:
    raw = env.get(key)
    if raw is None:
        return json.loads(json.dumps(default))
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"worker {worker_name} {key} must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"worker {worker_name} {key} must be a JSON object")
    return value


def _parse_mock_delay_range(worker_name: str, key: str, value: Any) -> tuple[float, float]:
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError(f"worker {worker_name} {key}.delay must be a two-element number array")
    min_delay = _coerce_mock_seconds(worker_name, f"{key}.delay[0]", value[0])
    max_delay = _coerce_mock_seconds(worker_name, f"{key}.delay[1]", value[1])
    return min_delay, max_delay


def _coerce_mock_seconds(worker_name: str, key: str, value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError(f"worker {worker_name} {key} must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"worker {worker_name} {key} must be a number") from exc
    if parsed < 0:
        raise ValueError(f"worker {worker_name} {key} must be non-negative")
    return parsed


def _parse_mock_probability(worker_name: str, phase_key: str, outcomes: dict[str, Any], outcome: str) -> Decimal:
    raw = outcomes.get(outcome, MOCK_DEFAULT_BEHAVIOR[phase_key.removeprefix("MOCK_").lower()]["outcomes"][outcome])
    try:
        value = Decimal(str(raw))
    except InvalidOperation as exc:
        raise ValueError(f"worker {worker_name} {phase_key}.outcomes.{outcome} must be a decimal probability") from exc
    if value < 0 or value > 1:
        raise ValueError(f"worker {worker_name} {phase_key}.outcomes.{outcome} must be between 0 and 1")
    return value
