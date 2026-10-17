"""Skill-driven audit mode contracts.

Adapted from cloudflare/security-audit-skill @ c1c8a8c
(skills/security-audit/report-schema.json + HUNTING.md coverage units).
See docs/skills/skill-driven-mode.md for the mapping to linen tasks.

The three verdict record classes are deliberately separate models with no
shared optional fields: a NeedsValidationRecord has no severity field and a
ConfirmedRecord has no blockers field, so "a guess with a severity attached"
cannot be represented, let alone stored.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from .common import ContractModel, validate_workspace_relative_path

CoverageUnitState = Literal[
    "planned", "in_progress", "covered", "candidate", "blocked", "deferred",
]
Verdict = Literal["confirmed", "needs_validation", "rejected"]

AttackClass = Literal[
    "injection", "access_control", "resource_and_file_handling",
    "cryptography_and_secrets", "business_logic", "chained_vulnerabilities",
    "wildcard", "obvious_things", "target_specific",
]


class CoverageUnit(ContractModel):
    """One deterministic audit unit: surface x boundary x attack class."""

    coverage_id: str = Field(min_length=4, max_length=64, pattern=r"^cov-[0-9a-z-]+$")
    state: CoverageUnitState = "planned"
    surface: str = Field(min_length=1, max_length=300)
    boundary: str = Field(min_length=1, max_length=300)
    attack_class: AttackClass
    subsystem: str = Field(min_length=1, max_length=200)
    starting_paths: list[str] = Field(default_factory=list, max_length=40)
    owner_run_id: str | None = None
    reviewed_paths: list[str] = Field(default_factory=list, max_length=200)
    fingerprints: list[str] = Field(default_factory=list, max_length=50)
    unresolved: list[str] = Field(default_factory=list, max_length=50)
    deferred_reason: str | None = Field(default=None, max_length=1000)
    wave: int = Field(default=1, ge=1, le=50)

    @field_validator("starting_paths", "reviewed_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        for value in values:
            validate_workspace_relative_path(value)
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


class TraceStep(ContractModel):
    step: Literal["entrypoint", "propagation", "sink"]
    path: str
    line: int | None = Field(default=None, ge=1)
    description: str = Field(min_length=1, max_length=2000)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_workspace_relative_path(value)


class ValidationPlan(ContractModel):
    local: str | None = Field(default=None, max_length=2000)
    deployment: str | None = Field(default=None, max_length=2000)

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
    description: str = Field(min_length=1, max_length=6000)
    trace: list[TraceStep] = Field(min_length=1, max_length=60)

    @model_validator(mode="after")
    def validate_trace_ends(self) -> "_FindingBase":
        if len(self.trace) > 1:
            if self.trace[0].step != "entrypoint" or self.trace[-1].step != "sink":
                raise ValueError(
                    "a multi-step trace must begin at entrypoint and end at sink"
                )
            if any(step.step not in {"propagation"} for step in self.trace[1:-1]):
                raise ValueError("intermediate trace steps must be propagation")
        return self


class ConfirmedRecord(_FindingBase):
    """Source-grounded finding with complete bounded evidence. No blockers field."""

    verdict: Literal["confirmed"] = "confirmed"
    root_cause: str = Field(min_length=1, max_length=4000)
    intended_behavior: str = Field(min_length=1, max_length=2000)
    conditions: list[str] = Field(min_length=1, max_length=20)
    execution: str = Field(min_length=1, max_length=4000)
    observed_result: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["tentative", "firm", "certain"]


class NeedsValidationRecord(_FindingBase):
    """Source-grounded lead with an exact blocker. Deliberately has NO severity
    field: unresolved work must never carry a severity into reports."""

    verdict: Literal["needs_validation"] = "needs_validation"
    claimed_root_cause: str = Field(min_length=1, max_length=4000)
    evidence: list[str] = Field(min_length=1, max_length=40)
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
    claimed_root_cause: str = Field(min_length=1, max_length=4000)
    evidence: list[str] = Field(min_length=1, max_length=40)
    reason: str = Field(min_length=1, max_length=4000)


FindingRecord = ConfirmedRecord | NeedsValidationRecord | RejectedRecord


def parse_finding_record(data: dict) -> FindingRecord:
    """Parse a verdict-tagged dict into the matching record class.

    Raises with the verdict name and the missing/forbidden-field names so the
    worker can self-correct on retry instead of repeating the same shape error.
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
            '"claimed_root_cause": "...", "trace": [...], "evidence": [...], '
            '"blockers": ["..."], "validation_plan": {"local": "..."}}'
        )
    return model.model_validate(data)
