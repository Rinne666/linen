from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Fact type vocabulary
# ---------------------------------------------------------------------------
# These are semantic tags the source-code-audit prompt set attaches to facts
# to express a vulnerability-hypothesis verification chain. They are NOT
# enforced by the server (a worker can emit any string, including freeform
# observations) — they are conventions surfaced to the LLM through prompts
# and AGENTS.md so the reason/explore tasks can reason over the graph.
#
# The chain reads top-to-bottom:
#   source  -- where untrusted input enters the program
#   sink    -- where a dangerous operation is called
#   dataflow -- a confirmed (partial) data-flow edge between two of the above
#   sanitizer  -- a function that filters/encodes input before it reaches a sink
#   validation -- input-validation check present
#   reachability -- the call site is reachable from outside
#   vulnerability -- the chain is closed: source -> ... -> sink with no
#                    effective sanitizer; a finding is fully characterized
FACT_TYPE_SOURCE = "source"
FACT_TYPE_SINK = "sink"
FACT_TYPE_DATAFLOW = "dataflow"
FACT_TYPE_SANITIZER = "sanitizer"
FACT_TYPE_VALIDATION = "validation"
FACT_TYPE_REACHABILITY = "reachability"
FACT_TYPE_VULNERABILITY = "vulnerability"
FACT_TYPE_RECON = "recon"
FACT_TYPE_SCAN_BATCH = "scan_batch"
FACT_TYPE_ROUTE_SCAN = "route_scan"
FACT_TYPE_COVERAGE_PLAN = "coverage_plan"
FACT_TYPE_COVERAGE_RESULT = "coverage_result"
FACT_TYPE_CANDIDATE_TRIAGE = "candidate_triage"
FACT_TYPE_CANDIDATE_DISPOSITION = "candidate_disposition"
FACT_TYPE_MODULE_SUMMARY = "module_summary"
FACT_TYPE_ARCHITECTURE_MAP = "architecture_map"
FACT_TYPE_AUTHZ_MATRIX = "authz_matrix"
FACT_TYPE_STATE_MODEL = "state_model"
FACT_TYPE_CROSS_SERVICE_MAP = "cross_service_map"
FACT_TYPE_CONTRACT_MAP = "contract_map"
FACT_TYPE_HYPOTHESIS_BATCH = "hypothesis_batch"
FACT_TYPE_VARIANT_BATCH = "variant_batch"
FACT_TYPE_SEMANTIC_SUMMARY = "semantic_summary"
FACT_TYPE_AUDIT_SUMMARY = "audit_summary"
FACT_TYPE_POLICY_EVIDENCE = "policy_evidence"
FACT_TYPE_SCOPE_ADJUDICATION = "scope_adjudication"
FACT_TYPE_NEGATIVE_ASSURANCE = "negative_assurance"
FACT_TYPE_PRINCIPAL = "principal"
FACT_TYPE_ATTACKER_CONTROL = "attacker_control"
FACT_TYPE_PRECONDITION = "precondition"
FACT_TYPE_SECURITY_INVARIANT = "security_invariant"
FACT_TYPE_SECURITY_BOUNDARY = "security_boundary"
FACT_TYPE_SECURITY_CONTROL_ASSESSMENT = "security_control_assessment"
FACT_TYPE_CAPABILITY_BEFORE = "capability_before"
FACT_TYPE_CAPABILITY_AFTER = "capability_after"
FACT_TYPE_CAPABILITY_DELTA = "capability_delta"
FACT_TYPE_IMPACT_OBSERVATION = "impact_observation"
FACT_TYPE_NEGATIVE_CONTROL = "negative_control"
FACT_TYPE_CONFIG_SOURCE = "config_source"
FACT_TYPE_CONFIG_RESOLUTION = "config_resolution"
FACT_TYPE_EFFECTIVE_CONFIG = "effective_config"
FACT_TYPE_REPRODUCTION = "reproduction"

SEMANTIC_TYPE_AUDIT_TARGET = "audit_target"
SEMANTIC_TYPE_AUDIT_OBJECTIVE = "audit_objective"
SEMANTIC_TYPE_OBSERVATION = "observation"
SEMANTIC_TYPE_SCOPE = "scope"
SEMANTIC_TYPE_COVERAGE = "coverage"
SEMANTIC_TYPE_HYPOTHESIS = "hypothesis"
SEMANTIC_TYPE_CANDIDATE_FINDING = "candidate_finding"
SEMANTIC_TYPE_CONFIRMED_FINDING = "confirmed_finding"
SEMANTIC_TYPE_REJECTED_FINDING = "rejected_finding"
SEMANTIC_TYPE_NEGATIVE_ASSURANCE = "negative_assurance"
SEMANTIC_TYPE_SUMMARY = "summary"
SEMANTIC_TYPE_AUDIT_TASK = "audit_task"

GRAPH_RELATION_TYPES: frozenset[str] = frozenset(
    {
        "produces",
        "defines",
        "supports",
        "refutes",
        "promotes_to",
        "reviews",
        "confirms",
        "rejects",
        "blocks",
        "waives",
        "variant_of",
        "supersedes",
        "depends_on",
        "unclassified",
        "controls", "enters_at", "flows_to", "guards", "authorizes", "denies",
        "owns", "targets", "transitions_to", "precedes", "interleaves_with",
        "resolves_to", "violates", "protects", "crosses", "grants", "observed_by",
        "baseline_for",
    }
)

# Audit-process records are reviewed as attestations: reviewers verify artifact
# integrity, snapshot consistency, and declared scope rather than looking for an
# attacker-to-sink path.  Keep this vocabulary in the shared protocol model so
# the server and dispatcher cannot silently disagree about review semantics.
AUDIT_ATTESTATION_FACT_TYPES: frozenset[str] = frozenset(
    {
        FACT_TYPE_COVERAGE_PLAN,
        FACT_TYPE_SCAN_BATCH,
        FACT_TYPE_ROUTE_SCAN,
        FACT_TYPE_CANDIDATE_TRIAGE,
        FACT_TYPE_CANDIDATE_DISPOSITION,
        FACT_TYPE_ARCHITECTURE_MAP,
        FACT_TYPE_AUTHZ_MATRIX,
        FACT_TYPE_STATE_MODEL,
        FACT_TYPE_CROSS_SERVICE_MAP,
        FACT_TYPE_CONTRACT_MAP,
        FACT_TYPE_HYPOTHESIS_BATCH,
        FACT_TYPE_VARIANT_BATCH,
        FACT_TYPE_POLICY_EVIDENCE,
        FACT_TYPE_SCOPE_ADJUDICATION,
        FACT_TYPE_NEGATIVE_ASSURANCE,
        FACT_TYPE_PRINCIPAL,
        FACT_TYPE_ATTACKER_CONTROL,
        FACT_TYPE_PRECONDITION,
        FACT_TYPE_SECURITY_INVARIANT,
        FACT_TYPE_SECURITY_BOUNDARY,
        FACT_TYPE_SECURITY_CONTROL_ASSESSMENT,
        FACT_TYPE_CAPABILITY_BEFORE,
        FACT_TYPE_CAPABILITY_AFTER,
        FACT_TYPE_CAPABILITY_DELTA,
        FACT_TYPE_IMPACT_OBSERVATION,
        FACT_TYPE_NEGATIVE_CONTROL,
        FACT_TYPE_CONFIG_SOURCE,
        FACT_TYPE_CONFIG_RESOLUTION,
        FACT_TYPE_EFFECTIVE_CONFIG,
        FACT_TYPE_REPRODUCTION,
    }
)

ALL_FACT_TYPES: frozenset[str] = frozenset(
    {
        FACT_TYPE_SOURCE,
        FACT_TYPE_SINK,
        FACT_TYPE_DATAFLOW,
        FACT_TYPE_SANITIZER,
        FACT_TYPE_VALIDATION,
        FACT_TYPE_REACHABILITY,
        FACT_TYPE_VULNERABILITY,
        FACT_TYPE_RECON,
        FACT_TYPE_SCAN_BATCH,
        FACT_TYPE_ROUTE_SCAN,
        FACT_TYPE_COVERAGE_PLAN,
        FACT_TYPE_COVERAGE_RESULT,
        FACT_TYPE_CANDIDATE_TRIAGE,
        FACT_TYPE_CANDIDATE_DISPOSITION,
        FACT_TYPE_MODULE_SUMMARY,
        FACT_TYPE_ARCHITECTURE_MAP,
        FACT_TYPE_AUTHZ_MATRIX,
        FACT_TYPE_STATE_MODEL,
        FACT_TYPE_CROSS_SERVICE_MAP,
        FACT_TYPE_CONTRACT_MAP,
        FACT_TYPE_HYPOTHESIS_BATCH,
        FACT_TYPE_VARIANT_BATCH,
        FACT_TYPE_SEMANTIC_SUMMARY,
        FACT_TYPE_AUDIT_SUMMARY,
        FACT_TYPE_POLICY_EVIDENCE,
        FACT_TYPE_SCOPE_ADJUDICATION,
        FACT_TYPE_NEGATIVE_ASSURANCE,
        FACT_TYPE_ATTACKER_CONTROL,
        FACT_TYPE_PRINCIPAL,
        FACT_TYPE_PRECONDITION,
        FACT_TYPE_SECURITY_INVARIANT,
        FACT_TYPE_SECURITY_BOUNDARY,
        FACT_TYPE_SECURITY_CONTROL_ASSESSMENT,
        FACT_TYPE_CAPABILITY_BEFORE,
        FACT_TYPE_CAPABILITY_AFTER,
        FACT_TYPE_CAPABILITY_DELTA,
        FACT_TYPE_IMPACT_OBSERVATION,
        FACT_TYPE_NEGATIVE_CONTROL,
        FACT_TYPE_CONFIG_SOURCE,
        FACT_TYPE_CONFIG_RESOLUTION,
        FACT_TYPE_EFFECTIVE_CONFIG,
        FACT_TYPE_REPRODUCTION,
    }
)

# Intent type vocabulary (what kind of verification step)
INTENT_TYPE_VERIFY = "verify"          # generic verification step
INTENT_TYPE_TRACE = "trace"            # trace taint between two known points
INTENT_TYPE_SEARCH = "search"          # find candidates (sinks, sources, sanitizers)
INTENT_TYPE_VALIDATE = "validate"      # validate a sanitizer / guard
INTENT_TYPE_REACH = "reach"            # determine if a call site is reachable
INTENT_TYPE_CHARACTERIZE = "characterize"  # fully characterize a confirmed vuln
INTENT_TYPE_TRIAGE = "triage"          # classify a bounded scanner-candidate batch
INTENT_TYPE_SYNTHESIZE = "synthesize"  # fan-in reviewed graph branches

ALL_INTENT_TYPES: frozenset[str] = frozenset(
    {
        INTENT_TYPE_VERIFY,
        INTENT_TYPE_TRACE,
        INTENT_TYPE_SEARCH,
        INTENT_TYPE_VALIDATE,
        INTENT_TYPE_REACH,
        INTENT_TYPE_CHARACTERIZE,
        INTENT_TYPE_TRIAGE,
        INTENT_TYPE_SYNTHESIZE,
    }
)


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


# Review verdict vocabulary. Enum, not freeform, so the DB can CHECK it
# and queries don't need to parse free-text verdict out of evidence.
REVIEW_VERDICT_VALID = "VALID"
REVIEW_VERDICT_INVALID = "INVALID"
REVIEW_VERDICT_NEEDS_REVIEW = "NEEDS_REVIEW"
ALL_REVIEW_VERDICTS: frozenset[str] = frozenset(
    {REVIEW_VERDICT_VALID, REVIEW_VERDICT_INVALID, REVIEW_VERDICT_NEEDS_REVIEW}
)

# Per-fact lifecycle. Aggregated from reviews + manual user action.
FACT_STATUS_DRAFT = "draft"
FACT_STATUS_TRIAGED = "triaged"
FACT_STATUS_FIXED = "fixed"
FACT_STATUS_FALSE_POSITIVE = "false_positive"
FACT_STATUS_ACCEPTED_RISK = "accepted_risk"
ALL_FACT_STATUSES: frozenset[str] = frozenset(
    {
        FACT_STATUS_DRAFT,
        FACT_STATUS_TRIAGED,
        FACT_STATUS_FIXED,
        FACT_STATUS_FALSE_POSITIVE,
        FACT_STATUS_ACCEPTED_RISK,
    }
)


class EvidenceRef(BaseModel):
    snapshot_id: str | None = None
    artifact_id: str | None = None
    run_id: str | None = None
    file: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    excerpt_sha256: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    rule_id: str | None = None

    @field_validator(
        "snapshot_id", "artifact_id", "run_id", "file", "excerpt_sha256",
        "tool", "tool_version", "rule_id",
    )
    @classmethod
    def _clean_optional(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class ProofPayload(BaseModel):
    schema_version: int = Field(default=1, ge=1)
    claim_kind: str = Field(min_length=1)
    subject_ids: list[str] = Field(default_factory=list)
    object_ids: list[str] = Field(default_factory=list)
    applicability: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)

    @field_validator("claim_kind")
    @classmethod
    def _clean_claim_kind(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("claim_kind must not be empty")
        return value

    @field_validator("subject_ids", "object_ids", "artifact_ids")
    @classmethod
    def _clean_ids(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("proof identifiers must not be empty")
        return cleaned


class Fact(BaseModel):
    id: str
    description: str
    # Human-readable graph title. `description` remains the complete claim;
    # the UI must not invent a lossy title from it on every render.
    display_title: str | None = None
    # Semantic tag for vulnerability-hypothesis verification. Freeform string
    # so the model is not locked into the canonical vocabulary; constants
    # above are the recommended set.
    type: str | None = None
    # Stable product-level layer used by the graph and Completion Gate. This
    # is intentionally separate from the detailed audit recipe `type` above.
    semantic_type: str = "observation"
    # Free-text evidence: file:line, code excerpts, tool output, PoC trace.
    # Kept as a single string to avoid a separate table or sub-relations.
    evidence: str | None = None
    proof: ProofPayload | None = None
    source_generation: int = 1
    legacy: bool = False
    # Lifecycle status. Default 'triaged' (fact was created by a worker, but
    # not yet adversarially reviewed). Reviews flip draft->triaged or
    # triaged->false_positive. See aggregate_fact_status_from_reviews().
    status: str = FACT_STATUS_TRIAGED

    @field_validator("proof", mode="before")
    @classmethod
    def _decode_proof(cls, value: Any) -> Any:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("proof must contain valid JSON") from exc
        return value


REVIEW_DIAGNOSTIC_FIELDS = (
    "protection_search",
    "fp_pattern_check",
    "cold_verification",
    "contradiction_analysis",
    "attestation_check",
    "summary_check",
)


class ReviewDiagnostics(BaseModel):
    protection_search: dict[str, Any] | None = None
    fp_pattern_check: dict[str, Any] | None = None
    cold_verification: dict[str, Any] | None = None
    contradiction_analysis: dict[str, Any] | None = None
    attestation_check: dict[str, Any] | None = None
    summary_check: dict[str, Any] | None = None


class Review(ReviewDiagnostics):
    id: str
    fact_id: str
    verdict: str  # one of REVIEW_VERDICT_*
    confidence: str | None = None  # 'certain' | 'firm' | 'tentative'
    summary: str
    reasoning: str | None = None
    intent_id: str | None = None
    created_at: str
    created_by: str | None = None
    source_generation: int = 1


class CreateReviewRequest(ReviewDiagnostics):
    verdict: str
    confidence: str | None = None
    summary: str
    reasoning: str | None = None
    intent_id: str | None = None
    created_by: str | None = None

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, value: str) -> str:
        v = (value or "").strip()
        if v not in ALL_REVIEW_VERDICTS:
            raise ValueError(
                f"verdict must be one of {sorted(ALL_REVIEW_VERDICTS)}; got {value!r}"
            )
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: str | None) -> str | None:
        if value is None:
            return None
        v = value.strip()
        if v not in {"certain", "firm", "tentative"}:
            raise ValueError("confidence must be one of: certain, firm, tentative")
        return v

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        text = (value or "").strip()
        if not text:
            raise ValueError("summary must not be empty")
        return text


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    display_title: str | None = None
    # Verification step kind. Freeform; constants above are the recommended set.
    type: str | None = None
    semantic_type: str = "audit_task"
    relation_type: str = "produces"
    phase: str = "investigate"
    source_generation: int = 1
    plan_revision: int = 1
    legacy: bool = False
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None
    intent_key: str | None = None

    model_config = {"populate_by_name": True}


class IntentError(BaseModel):
    """Persistent control-plane failure attached to one Intent.

    Errors are deliberately separate from Facts: a worker/runtime failure is
    operational state, not audit evidence.  Resolved rows remain available as
    an append-only activity trail while only unresolved rows gate dispatch.
    """

    id: str
    intent_id: str
    task_type: str
    worker: str | None = None
    code: str
    classification: Literal["transient", "blocked"]
    message: str
    remediation: str | None = None
    attempt_count: int = 1
    first_failed_at: str
    last_failed_at: str
    retry_at: str | None = None
    resolved_at: str | None = None
    resolution: str | None = None


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


class ProjectReason(BaseModel):
    worker: str
    lease_id: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ProjectMeta(BaseModel):
    id: str
    title: str
    status: Literal["active", "stopped", "completed"]
    graph_revision: int = 0
    source_generation: int = 1
    plan_revision: int = 1
    bootstrap_enabled: bool
    completion_policy: Literal["goal_based", "exhaustive"] = "goal_based"
    reason_last_seen_event_seq: int = 0
    event_seq: int = 0
    # Server-side audit profile.  This is persisted with the project so a
    # client cannot bypass completion evidence checks merely by using a
    # different dispatcher configuration later.
    audit_mode: Literal["none", "hypothesis", "scope"] = "none"
    created_at: str
    reason: ProjectReason | None = None
    # Resolved source-tree path for the project. Set when the project is
    # created with `clone_url` (clone lands here) or `repo_root` (validated
    # local directory). None means no per-project override — the dispatcher
    # falls back to its `local.repo_root` config.
    repo_root: str | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int
    review_count: int = 0
    blocked_intent_count: int = 0
    retrying_intent_count: int = 0
    activity_status: Literal[
        "idle", "queued", "working", "reasoning", "retrying", "blocked",
        "stopped", "completed",
    ] = "idle"
    # New user-facing name. `activity_status` remains during the compatibility
    # window for older frontends and dispatcher clients.
    execution_status: str = "idle"


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]
    reviews: list[Review] = Field(default_factory=list)
    errors: list[IntentError] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    stages: list[AuditStage] = Field(default_factory=list)
    decisions: list[HumanDecision] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source_kind: str
    source_id: str
    target_kind: str
    target_id: str
    relation_type: str
    source_generation: int = 1
    created_at: str
    created_by: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditStage(BaseModel):
    stage_id: str
    label: str
    phase_order: int
    required: bool = True
    status: Literal[
        "pending", "running", "satisfied", "blocked", "failed", "not_applicable",
    ] = "pending"
    capability: str | None = None
    skill_id: str | None = None
    run_id: str | None = None
    detail: str | None = None
    source_generation: int = 1
    plan_revision: int = 1
    updated_at: str


class UpsertAuditStageRequest(BaseModel):
    label: str
    phase_order: int = Field(ge=0)
    required: bool = True
    status: Literal[
        "pending", "running", "satisfied", "blocked", "failed", "not_applicable",
    ] = "pending"
    capability: str | None = None
    skill_id: str | None = None
    run_id: str | None = None
    detail: str | None = None
    source_generation: int | None = Field(default=None, ge=1)
    plan_revision: int | None = Field(default=None, ge=1)
    actor: str = "dispatcher"


class SkillRun(BaseModel):
    id: str
    stage_id: str
    intent_id: str | None = None
    skill_id: str
    skill_version: str
    capability: str
    status: Literal["running", "completed", "failed", "not_applicable"]
    command: str | None = None
    artifact_ref: str | None = None
    artifact_sha256: str | None = None
    detail: str | None = None
    source_generation: int = 1
    plan_revision: int = 1
    started_at: str
    finished_at: str | None = None


class UpsertSkillRunRequest(BaseModel):
    stage_id: str
    intent_id: str | None = None
    skill_id: str
    skill_version: str
    capability: str
    status: Literal["running", "completed", "failed", "not_applicable"]
    command: str | None = None
    artifact_ref: str | None = None
    artifact_sha256: str | None = None
    detail: str | None = None
    source_generation: int | None = Field(default=None, ge=1)
    plan_revision: int | None = Field(default=None, ge=1)
    actor: str = "dispatcher"


class HumanDecision(BaseModel):
    id: str
    target_kind: str
    target_id: str
    decision: Literal["confirm", "reject", "waive", "exclude"]
    rationale: str
    basis_quote: str | None = None
    revival_condition: str | None = None
    actor: str
    supersedes_id: str | None = None
    source_generation: int = 1
    created_at: str


class CreateHumanDecisionRequest(BaseModel):
    target_kind: str
    target_id: str
    decision: Literal["confirm", "reject", "waive", "exclude"]
    rationale: str
    basis_quote: str | None = None
    revival_condition: str | None = None
    actor: str
    supersedes_id: str | None = None

    @field_validator("target_kind", "target_id", "rationale", "actor")
    @classmethod
    def validate_decision_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class AuditEvent(BaseModel):
    sequence: int
    event_type: str
    actor: str
    entity_kind: str | None = None
    entity_id: str | None = None
    source_generation: int = 1
    plan_revision: int = 1
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class CompletionCheck(BaseModel):
    id: str
    label: str
    status: Literal["pass", "fail", "pending", "not_applicable"]
    blocking: bool = True
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class CompletionGate(BaseModel):
    project_id: str
    lifecycle_status: str
    execution_status: str
    audit_mode: str
    source_generation: int
    plan_revision: int
    ready: bool
    checks: list[CompletionCheck]
    blockers: list[str]


class PiExecutionSummary(BaseModel):
    id: str
    # Schema 3 records remain valid; schema 4 adds the optional contract
    # identity below so the UI can join an execution archive entry with a
    # persisted RunEnvelope without changing the legacy archive format.
    schema_version: int = 3
    command: str = "pi -p"
    phase: str
    recipe_id: str | None = None
    recipe_label: str | None = None
    recipe_version: int | None = None
    worker: str
    started_at: str
    duration_ms: int = 0
    timeout_seconds: int = 0
    returncode: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    cancel_reason: str | None = None
    session_id: str | None = None
    prompt_available: bool = False
    response_available: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    run_id: str | None = None
    attempt: int | None = None
    idempotency_key: str | None = None
    context_projection_id: str | None = None
    manifest_digest: str | None = None
    recipe_digest: str | None = None


class PiExecutionPage(BaseModel):
    items: list[PiExecutionSummary]
    total: int
    offset: int
    limit: int


class PiExecutionDetail(PiExecutionSummary):
    prompt: str = ""
    response: str = ""
    stderr: str = ""


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateProjectRequest(BaseModel):
    title: str
    origin: str
    goal: str
    bootstrap_enabled: bool = True
    completion_policy: Literal["goal_based", "exhaustive"] = "goal_based"
    audit_mode: Literal["none", "hypothesis", "scope"] = "none"
    hints: list[CreateHintInline] | None = None
    # Mutually exclusive. `clone_url` triggers a synchronous `git clone` on
    # the server into a clones_root (default `~/.local/share/linen/clones/`),
    # skipping retained clone paths by assigning the next free project id. The
    # resulting path is stored as the project's `repo_root`. `repo_root` is a
    # pre-validated local directory; the project symlinks its workdir to it.
    # Exactly one of the two may be set; if neither, the project has no
    # per-project repo_root and the dispatcher falls back to config.
    clone_url: str | None = None
    repo_root: str | None = None

    @field_validator("title", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("clone_url", "repo_root")
    @classmethod
    def validate_optional_source(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        return text

    @field_validator("clone_url")
    @classmethod
    def validate_clone_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.lower()
        if not (
            lowered.startswith("http://")
            or lowered.startswith("https://")
            or lowered.startswith("git://")
            or lowered.startswith("ssh://")
            or lowered.startswith("git@")
        ):
            raise ValueError(
                "clone_url must start with http://, https://, git://, ssh://, or git@"
            )
        return value

    def model_post_init(self, __context: object) -> None:
        if self.clone_url is not None and self.repo_root is not None:
            raise ValueError("clone_url and repo_root are mutually exclusive")


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    creator: str
    worker: str | None = None
    type: str | None = None
    display_title: str | None = None
    # ``None`` means "infer from the reserved description/type".  Keeping
    # these optional is important for legacy callers: an omitted field must
    # not silently override the server's semantic projection.
    semantic_type: str | None = None
    relation_type: str | None = None
    phase: str | None = None
    action: str | None = None
    target: str | None = None
    scope: str | None = None
    rationale: str | None = None
    reopen: bool = False

    model_config = {"populate_by_name": True}

    @field_validator("description", "creator", "worker", "display_title")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("type", "semantic_type", "relation_type", "phase")
    @classmethod
    def validate_optional_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        return text

    @field_validator("relation_type")
    @classmethod
    def validate_relation_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in GRAPH_RELATION_TYPES:
            raise ValueError(f"relation_type must be one of {sorted(GRAPH_RELATION_TYPES)}")
        return value

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class HeartbeatRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReportIntentErrorRequest(BaseModel):
    worker: str
    task_type: str
    code: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")
    classification: Literal["transient", "blocked"]
    message: str = Field(max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)
    base_retry_seconds: int = Field(default=15, ge=1, le=3600)
    max_retry_seconds: int = Field(default=900, ge=1, le=86400)
    max_attempts: int = Field(default=5, ge=1, le=15)

    @field_validator("worker", "task_type", "message")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("remediation")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class RetryIntentRequest(BaseModel):
    actor: str

    @field_validator("actor")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompactCoverageIntentsRequest(BaseModel):
    keep: int = Field(default=4, ge=0, le=100)
    dry_run: bool = True


class CompactCoverageIntentsResponse(BaseModel):
    project_id: str
    dry_run: bool
    eligible_count: int
    retained_ids: list[str]
    retired_ids: list[str]


class ReasonClaimRequest(BaseModel):
    worker: str
    lease_id: str
    trigger: str

    @field_validator("worker", "lease_id", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonHeartbeatRequest(BaseModel):
    worker: str
    lease_id: str
    seen_event_seq: int | None = Field(default=None, ge=0)

    @field_validator("worker", "lease_id")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    worker: str
    description: str
    type: str | None = None
    evidence: str | None = None
    proof: ProofPayload | None = None
    display_title: str | None = None
    semantic_type: str | None = None
    # Lifecycle status of the new fact. Defaults to 'draft' — the explore
    # task writes a candidate, a later review decides whether it becomes
    # 'triaged' (VALID) or 'false_positive' (INVALID). The user can also
    # pass 'triaged' directly for low-risk observations that don't need
    # adversarial validation.
    status: str = "draft"

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        v = (value or "").strip()
        if v not in ALL_FACT_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALL_FACT_STATUSES)}")
        return v

    @field_validator("worker", "description")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("type", "evidence", "display_title", "semantic_type")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        return text


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str

    model_config = {"populate_by_name": True}

    @field_validator("description", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent
