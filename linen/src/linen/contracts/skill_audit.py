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
    ContractModel,
    cf_canonical_coverage_id,
    cf_is_legacy_coverage_id,
)

Verdict = Literal["confirmed", "needs_validation", "rejected"]
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
