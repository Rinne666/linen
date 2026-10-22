"""Skill-driven audit mode contracts.

Field-for-field alignment with the vendored Cloudflare schema
(.linen-runtime/cf-security-audit-skill/skills/security-audit/report-schema.json
@ c1c8a8c), so ``write_findings_json`` output passes
``validate-findings.cjs`` unchanged. See docs/skills/skill-driven-mode.md.

The three verdict record classes are deliberately separate models with no
shared optional fields: a NeedsValidationRecord has no severity field and a
ConfirmedRecord has no blockers field, so "a guess with a severity attached"
cannot be represented, let alone stored.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .common import (
    CF_ATTEMPT_STATUSES,
    CF_BASELINE_KINDS,
    CF_PRIOR_STATUSES,
    ContractModel,
    cf_canonical_coverage_id,
    cf_is_legacy_coverage_id,
    cf_is_safe_agent_id,
    cf_is_visible_text,
    cf_validate_check,
    cf_validate_fingerprint_array,
    cf_validate_path_array,
    cf_validate_reviewed_path_ownership,
    cf_validate_text_array,
)

Verdict = Literal["confirmed", "needs_validation", "rejected"]

#: Deprecated compatibility alias (D-033).
#:
#: The eight values below predate the coverage protocol and never became the
#: upstream attack-class taxonomy: the pinned snapshot carries nine ordinary
#: blocks whose titles are title case, and ``canonical_refs.attack_class`` is
#: a *descriptive* identity reference rather than a classification label.
#: The alias stays exported so existing importers keep working, but it is no
#: longer a protocol authority: it must not restrict the canonical refs and
#: it must not be used to pick an upstream block.  Removing it is only
#: allowed in an explicitly approved breaking API change.
AttackClass = Literal[
    "injection", "access_control", "resource_and_file_handling",
    "cryptography_and_secrets", "business_logic", "chained_vulnerabilities",
    "wildcard", "obvious_things",
]
SeverityScore = Literal["informational", "low", "medium", "high", "critical"]
CoverageUnitState = Literal[
    "planned", "in_progress", "covered", "candidate", "blocked", "deferred",
]


def _repo_relative(value: str) -> str:
    if not value or value.strip() != value:
        raise ValueError("paths must be non-empty and unpadded")
    if value.startswith("/") or value.startswith("..") or "/../" in value:
        raise ValueError(f"source paths must be repository-relative: {value!r}")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("paths must not contain control characters")
    return value


class TraceStep(ContractModel):
    kind: Literal["entrypoint", "propagation", "sink"]
    file: str
    line: int = Field(ge=1)
    scope: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=2000)

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str) -> str:
        return _repo_relative(value)


class EvidenceItem(ContractModel):
    file: str
    line: int = Field(ge=1)
    description: str = Field(min_length=1, max_length=2000)

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str) -> str:
        return _repo_relative(value)


class ConditionItem(ContractModel):
    kind: Literal[
        "authentication_level", "authorization_role", "user_interaction",
        "system_configuration", "network_routing", "environmental_dependency",
        "data_state", "timing_dependency", "third_party_dependency",
    ]
    description: str = Field(min_length=1, max_length=2000)


class Execution(ContractModel):
    """Target-neutral reproduction in the target's native interface."""

    attacker_perspective: str = Field(min_length=1, max_length=4000)
    payloads: list[str] = Field(min_length=1, max_length=20)
    instructions: list[str] = Field(min_length=1, max_length=40)
    observed_result: str = Field(min_length=1, max_length=4000)


class Remediation(ContractModel):
    strategy: str = Field(min_length=1, max_length=4000)
    code_changes: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


class ScoredLevel(ContractModel):
    score: SeverityScore
    reason: str = Field(min_length=1, max_length=2000)


class Severity(ContractModel):
    likelihood: ScoredLevel
    impact: ScoredLevel
    # upstream schema: overall_severity is a bare enum string, not an object
    overall_severity: SeverityScore

    _SCORE_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @model_validator(mode="after")
    def overall_cannot_exceed_impact(self) -> "Severity":
        if self._SCORE_RANK[self.overall_severity] > self._SCORE_RANK[self.impact.score]:
            raise ValueError(
                "overall severity must not exceed proven impact "
                "(likelihood x impact, not a checklist deviation)"
            )
        return self


class Confidence(ContractModel):
    score: Literal["low", "medium", "high"]
    reason: str = Field(min_length=1, max_length=2000)


class ValidationPlan(ContractModel):
    local: str | None = Field(default=None, max_length=4000)
    deployment: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def validate_plan(self) -> "ValidationPlan":
        if not (self.local or "").strip() and not (self.deployment or "").strip():
            raise ValueError(
                "validation_plan requires at least one applicable local or "
                "deployment step; do not invent an inapplicable context"
            )
        return self


class _FindingBase(ContractModel):
    fingerprint: str = Field(min_length=8, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=8000)
    trace: list[TraceStep] = Field(min_length=1, max_length=60)

    @model_validator(mode="after")
    def validate_trace_ends(self) -> "_FindingBase":
        if len(self.trace) == 1:
            if self.trace[0].kind == "propagation":
                raise ValueError(
                    'a one-line trace must be "entrypoint" or "sink"'
                )
            return self
        if self.trace[0].kind != "entrypoint" or self.trace[-1].kind != "sink":
            raise ValueError(
                "a multi-step trace must begin at entrypoint and end at sink"
            )
        if any(step.kind != "propagation" for step in self.trace[1:-1]):
            raise ValueError("intermediate trace steps must be propagation")
        return self


class ConfirmedRecord(_FindingBase):
    """Source-grounded finding with complete bounded evidence. No blockers field."""

    verdict: Literal["confirmed"] = "confirmed"
    root_cause: str = Field(min_length=1, max_length=8000)
    intended_behavior: str = Field(min_length=1, max_length=4000)
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=40)
    conditions: list[ConditionItem] = Field(min_length=1, max_length=20)
    execution: Execution
    remediation: Remediation
    severity: Severity
    confidence: Confidence


class NeedsValidationRecord(_FindingBase):
    """Source-grounded lead with an exact blocker. Deliberately has NO severity
    field: unresolved work must never carry a severity into reports."""

    verdict: Literal["needs_validation"] = "needs_validation"
    claimed_root_cause: str = Field(min_length=1, max_length=8000)
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=40)
    blockers: list[str] = Field(min_length=1, max_length=20)
    validation_plan: ValidationPlan

    @field_validator("blockers")
    @classmethod
    def validate_blockers(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("blockers must be non-empty")
        return values


class RejectedRecord(_FindingBase):
    """A disproved candidate, kept so future runs do not repeat the claim."""

    verdict: Literal["rejected"] = "rejected"
    claimed_root_cause: str = Field(min_length=1, max_length=8000)
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=40)
    reason: str = Field(min_length=1, max_length=4000)


FindingRecord = ConfirmedRecord | NeedsValidationRecord | RejectedRecord


def parse_finding_record(data: dict) -> FindingRecord:
    """Parse a verdict-tagged dict into the matching record class.

    Raises with the verdict name and the shape so the worker can self-correct
    on retry instead of repeating the same envelope error.
    """
    verdict = (data or {}).get("verdict")
    model = {
        "confirmed": ConfirmedRecord,
        "needs_validation": NeedsValidationRecord,
        "rejected": RejectedRecord,
    }.get(verdict)
    if model is None:
        raise ValueError(
            "finding verdict must be one of confirmed|needs_validation|rejected; "
            f"got {verdict!r}. Example shape: "
            '{"verdict": "needs_validation", "fingerprint": "...", "title": "...", '
            '"description": "...", "claimed_root_cause": "...", "trace": [{"kind": '
            '"entrypoint", "file": "app.py", "line": 9, "scope": "GET handler", '
            '"description": "..."}], "evidence": [{"file": "x.py", "line": 1, '
            '"description": "..."}], "blockers": ["..."], "validation_plan": '
            '{"local": "..."}}'
        )
    return model.model_validate(data)


class CoverageUnit(ContractModel):
    """One deterministic audit unit: surface x boundary x attack class."""

    coverage_id: str | None = Field(default=None, max_length=2048)
    state: CoverageUnitState = "planned"
    surface: str = Field(min_length=1, max_length=300)
    boundary: str = Field(min_length=1, max_length=300)
    attack_class: str = Field(min_length=1, max_length=60)
    subsystem: str = Field(min_length=1, max_length=200)
    starting_paths: list[str] = Field(default_factory=list, max_length=40)
    owner_run_id: str | None = None
    reviewed_paths: list[str] = Field(default_factory=list, max_length=200)
    fingerprints: list[str] = Field(default_factory=list, max_length=50)
    unresolved: list[str] = Field(default_factory=list, max_length=50)
    deferred_reason: str | None = Field(default=None, max_length=1000)
    wave: int = Field(default=1, ge=1, le=50)

    @model_validator(mode="before")
    @classmethod
    def derive_coverage_id(cls, data: Any) -> Any:
        """Derive the canonical coverage id from the four descriptive dimensions.

        The four dimensions are the source of truth (N1): a hand-written id is
        accepted only when it equals the derived canonical id, and the retired
        ``cov-<n>`` scheme is rejected as an active id (D-017).
        """

        if not isinstance(data, dict):
            return data
        refs = {
            field: data.get(field)
            for field in ("surface", "boundary", "subsystem", "attack_class")
        }
        if not all(isinstance(value, str) and value for value in refs.values()):
            return data
        expected = cf_canonical_coverage_id(refs)
        provided = data.get("coverage_id")
        if provided is None:
            return {**data, "coverage_id": expected}
        if cf_is_legacy_coverage_id(provided):
            raise ValueError(
                "coverage_id must be a canonical id; the retired cov-<n> scheme is "
                "read-only through an explicit alias map (D-017)"
            )
        if provided != expected:
            raise ValueError(
                "coverage_id must equal the canonical id derived from the four "
                f"dimensions: {expected!r}"
            )
        return data

    @field_validator("starting_paths", "reviewed_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        for value in values:
            _repo_relative(value)
        return values

    @model_validator(mode="after")
    def validate_state_fields(self) -> "CoverageUnit":
        if self.state == "deferred" and not (self.deferred_reason or "").strip():
            raise ValueError(
                "deferred coverage unit requires a deferred_reason: a silent "
                "wave or agent cap is never evidence of complete coverage"
            )
        if self.state == "covered" and not self.reviewed_paths:
            raise ValueError("covered unit requires nonempty reviewed_paths")
        if self.state == "candidate" and not self.fingerprints:
            raise ValueError("candidate unit requires linked fingerprints")
        if self.state == "blocked" and not self.unresolved:
            raise ValueError("blocked unit requires unresolved facts")
        return self


class CoverageCanonicalRefs(ContractModel):
    """The four descriptive dimensions a coverage id is derived from (N1)."""

    surface: str = Field(min_length=1, max_length=300)
    boundary: str = Field(min_length=1, max_length=300)
    subsystem: str = Field(min_length=1, max_length=200)
    attack_class: str = Field(min_length=1, max_length=60)

    def derived_coverage_id(self) -> str:
        """The canonical id these four dimensions produce."""

        return cf_canonical_coverage_id(self.model_dump())


class CoverageBaseline(ContractModel):
    """The historical baseline a registration was derived from.

    ``kind`` distinguishes a *verified absence* of a compatible ledger from a
    ledger that was found and inspected.  ``lookup_ref`` is the traceable
    reference to that check; it is never a placeholder, because a fabricated
    reference would make the stored prior status unfalsifiable.
    """

    kind: str = Field(min_length=1, max_length=64)
    lookup_ref: str = Field(min_length=1, max_length=1024)

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, value: str) -> str:
        if value not in CF_BASELINE_KINDS:
            raise ValueError(
                "baseline kind must be one of: " + ", ".join(CF_BASELINE_KINDS)
            )
        return value

    @field_validator("lookup_ref")
    @classmethod
    def validate_lookup_ref(cls, value: str) -> str:
        if value.strip() != value or not value.strip():
            raise ValueError("baseline lookup_ref must be a non-empty trimmed reference")
        return value


class UnitRegisteredPayload(ContractModel):
    """The v1 ``unit_registered`` event payload (CF-S1-C).

    The payload is the whole business content of a registration event.  The
    database timestamp is deliberately absent: it is storage metadata and must
    not take part in the idempotency decision, otherwise a legitimate retry
    would look like a conflict.
    """

    schema_version: int = 1
    canonical_refs: CoverageCanonicalRefs
    prior_status: str = Field(min_length=1, max_length=64)
    baseline: CoverageBaseline

    @field_validator("prior_status")
    @classmethod
    def validate_prior_status(cls, value: str) -> str:
        if value not in CF_PRIOR_STATUSES:
            raise ValueError(
                "prior_status must be one of the upstream values: "
                + ", ".join(CF_PRIOR_STATUSES)
            )
        return value

    @model_validator(mode="after")
    def validate_baseline_claim(self) -> "UnitRegisteredPayload":
        """Keep the prior status and the baseline kind telling the same story.

        ``none`` is a claim of verified absence, so it requires a baseline that
        verified the absence.  A found ledger can never justify ``none``.
        """

        if self.baseline.kind == "no_compatible_ledger" and self.prior_status != "none":
            raise ValueError(
                "prior_status must be 'none' when no compatible ledger exists"
            )
        if self.baseline.kind == "compatible_ledger" and self.prior_status == "none":
            raise ValueError(
                "prior_status 'none' requires a verified absent baseline "
                "(no_compatible_ledger); an unknown history is not 'none'"
            )
        return self

    def derived_coverage_id(self) -> str:
        """The canonical id this payload registers."""

        return self.canonical_refs.derived_coverage_id()

    def digest_content(self) -> dict[str, Any]:
        """The content the ledger digests for this payload."""

        return self.model_dump(mode="json")


# --- CF-S2-A: the multiwave event contracts --------------------------------


class CoverageLocalCheck(ContractModel):
    """One coverage check, exactly the six upstream fields (S1-A).

    The artifact of a ``local`` check has to live under its own agent, and a
    ``source`` check must not name an artifact at all.  Reusing an artifact
    that an earlier attempt already used is rejected by the ledger, not here:
    the ledger is the only place that sees every attempt of a unit.
    """

    agent_id: str
    reviewed_paths: list[str]
    invariant: str
    method: Literal["source", "local"]
    result: str
    artifact: str | None = None

    @model_validator(mode="after")
    def validate_check_shape(self) -> "CoverageLocalCheck":
        cf_validate_check(self.model_dump(), location="local_checks[]")
        return self


class CoverageExcludedBlock(ContractModel):
    """A block that was deliberately left out, and why."""

    block: str
    reason: str

    @model_validator(mode="after")
    def validate_block_text(self) -> "CoverageExcludedBlock":
        if not cf_is_visible_text(self.block):
            raise ValueError("excluded block must be visible text")
        if not cf_is_visible_text(self.reason):
            raise ValueError("excluded block requires a reason")
        return self


class CoverageBlockSelection(ContractModel):
    """The block map a wave was assigned, with a traceable source.

    The blocks are the plan's decision, not the model's: upstream treats the
    assignment block map as something the parent process puts into the hunter
    prompt, and the hunter's own result never carries block fields.  The
    ``source`` reference is therefore mandatory - a block map that cannot be
    traced back to the decision that produced it is not a trusted record.

    ``companion_catalog_state`` says whether the companion playbooks were
    available to the decision at all.  An empty ``selected_companion_blocks``
    is ambiguous on its own: it can mean "the catalog was there and nothing
    was chosen" or "there was no catalog", and an audit system has to tell
    those apart.  The state is part of linen's trusted provenance only: it is
    not part of the upstream ledger, the canonical refs, the coverage id, or
    anything a model may fill in.
    """

    ordinary_attack_class_block: str | None = None
    selected_companion_blocks: list[str] = Field(default_factory=list, max_length=1000)
    excluded_blocks: list[CoverageExcludedBlock] = Field(default_factory=list, max_length=1000)
    companion_catalog_state: Literal["available", "unavailable", "unknown"] | None = None
    source: str = Field(min_length=1, max_length=1024)

    @field_validator("ordinary_attack_class_block")
    @classmethod
    def validate_ordinary_block(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not cf_is_visible_text(value):
            raise ValueError("ordinary_attack_class_block must be null or visible text")
        return value

    @field_validator("selected_companion_blocks")
    @classmethod
    def validate_companion_blocks(cls, values: list[str]) -> list[str]:
        cf_validate_text_array(values, location="selected_companion_blocks")
        return values

    @model_validator(mode="after")
    def validate_exclusions(self) -> "CoverageBlockSelection":
        seen: set[str] = set()
        for entry in self.excluded_blocks:
            if entry.block in seen:
                raise ValueError(f"excluded block {entry.block!r} appears more than once")
            seen.add(entry.block)
        selected = set(self.selected_companion_blocks)
        for entry in self.excluded_blocks:
            if entry.block in selected:
                raise ValueError(
                    f"block {entry.block!r} is both selected and excluded"
                )
        if self.companion_catalog_state == "unavailable" and self.selected_companion_blocks:
            raise ValueError(
                "an unavailable companion catalog cannot have selected companion blocks"
            )
        return self

    def digest_content(self) -> dict[str, Any]:
        """The content the ledger digests for this block selection.

        The capability state is omitted when it was never recorded, so a
        record written before the field existed keeps the digest it was
        stored with (D-032).  The projection reports such a record as
        ``unknown`` rather than backfilling ``unavailable``.
        """

        content = self.model_dump(mode="json")
        if self.companion_catalog_state is None:
            content.pop("companion_catalog_state", None)
        return content


class WaveStartedPayload(ContractModel):
    """The v1 ``wave_started`` event payload (CF-S2-A).

    A wave start records who took the unit over and which blocks they were
    given.  The ``reassignment_reason`` belongs to the *previous* wave: the
    reason a hunter was replaced is often only known once the next wave is
    dispatched, so the ledger stores it here and the projection attaches it to
    the archived attempt.  Wave 1 has no previous wave and therefore no
    reason.
    """

    schema_version: int = 1
    canonical_refs: CoverageCanonicalRefs
    wave: int = Field(ge=1, le=50)
    agent_id: str
    block_selection: CoverageBlockSelection
    starting_paths: list[str] = Field(default_factory=list, max_length=1000)
    reassignment_reason: str | None = Field(default=None, max_length=4096)

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        if not cf_is_safe_agent_id(value):
            raise ValueError("agent_id must be a canonical lowercase agent ID")
        return value

    @field_validator("starting_paths")
    @classmethod
    def validate_starting_paths(cls, values: list[str]) -> list[str]:
        cf_validate_path_array(values, location="starting_paths")
        return values

    @model_validator(mode="after")
    def validate_reassignment(self) -> "WaveStartedPayload":
        if self.wave == 1:
            if self.reassignment_reason is not None:
                raise ValueError(
                    "the first wave has no previous attempt, so it cannot carry a "
                    "reassignment reason"
                )
        elif self.reassignment_reason is None or not cf_is_visible_text(
            self.reassignment_reason
        ):
            raise ValueError(
                f"wave {self.wave} must record a visible reassignment reason for the "
                "attempt it replaces"
            )
        return self

    def derived_coverage_id(self) -> str:
        return self.canonical_refs.derived_coverage_id()

    def digest_content(self) -> dict[str, Any]:
        """The content the ledger digests for this wave.

        The block selection decides how its own capability state is
        serialized, so a record written before that field existed keeps the
        digest it was stored with (D-032).
        """

        content = self.model_dump(mode="json")
        content["block_selection"] = self.block_selection.digest_content()
        return content


class AttemptRecordedPayload(ContractModel):
    """The v1 ``attempt_recorded`` event payload (CF-S2-A).

    An attempt is a terminal record of one wave: ``covered``, ``candidate``
    or ``blocked``.  The state invariants mirror the upstream ones exactly, so
    a projected attempt is accepted by the pinned validator without
    translation.
    """

    schema_version: int = 1
    canonical_refs: CoverageCanonicalRefs
    wave: int = Field(ge=1, le=50)
    agent_id: str
    status: Literal["covered", "candidate", "blocked"]
    reviewed_paths: list[str] = Field(default_factory=list, max_length=1000)
    local_checks: list[CoverageLocalCheck] = Field(default_factory=list, max_length=1000)
    result_fingerprints: list[str] = Field(default_factory=list, max_length=1000)
    unresolved: list[str] = Field(default_factory=list, max_length=1000)

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        if not cf_is_safe_agent_id(value):
            raise ValueError("agent_id must be a canonical lowercase agent ID")
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in CF_ATTEMPT_STATUSES:
            raise ValueError(
                "an attempt must record a terminal status: " + ", ".join(CF_ATTEMPT_STATUSES)
            )
        return value

    @field_validator("reviewed_paths")
    @classmethod
    def validate_reviewed_paths(cls, values: list[str]) -> list[str]:
        cf_validate_path_array(values, location="reviewed_paths")
        return values

    @field_validator("result_fingerprints")
    @classmethod
    def validate_fingerprints(cls, values: list[str]) -> list[str]:
        cf_validate_fingerprint_array(values, location="result_fingerprints")
        return values

    @field_validator("unresolved")
    @classmethod
    def validate_unresolved(cls, values: list[str]) -> list[str]:
        cf_validate_text_array(values, location="unresolved")
        return values

    @model_validator(mode="after")
    def validate_state_invariants(self) -> "AttemptRecordedPayload":
        checks = [check.model_dump() for check in self.local_checks]
        cf_validate_reviewed_path_ownership(
            self.reviewed_paths, checks, location="attempt"
        )
        if self.status == "covered":
            if not self.reviewed_paths or not self.local_checks:
                raise ValueError("a covered attempt requires reviewed paths and checks")
            if self.unresolved:
                raise ValueError("a covered attempt must not carry unresolved facts")
            if self.result_fingerprints:
                raise ValueError("a covered attempt must not carry result fingerprints")
        elif self.status == "blocked":
            if not self.reviewed_paths or not self.local_checks:
                raise ValueError("a blocked attempt requires reviewed paths and checks")
            if not self.unresolved:
                raise ValueError("a blocked attempt requires unresolved facts")
            if self.result_fingerprints:
                raise ValueError("a blocked attempt must not carry result fingerprints")
        else:  # candidate
            if not self.reviewed_paths or not self.local_checks:
                raise ValueError("a candidate attempt requires reviewed paths and checks")
            if not self.result_fingerprints:
                raise ValueError("a candidate attempt requires result fingerprints")
        return self

    def derived_coverage_id(self) -> str:
        return self.canonical_refs.derived_coverage_id()

    def digest_content(self) -> dict[str, Any]:
        """The content the ledger digests for this attempt."""

        return self.model_dump(mode="json")

