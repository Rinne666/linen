"""Executable, bounded strategy waits, separate from audit evidence."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from .common import ContractModel

REASON_WAKE_EVENTS = frozenset({
    "audit_task_concluded", "audit_task_failed", "audit_task_abandoned",
    "review_created", "technical_confirmation", "dynamic_verification_pass",
    "proof_strategy_replan_required", "human_hint_created",
})


class ReasonWait(ContractModel):
    intent_ids: list[str] = Field(default_factory=list, max_length=60)
    intent_policy: Literal["all", "any"] = "all"
    event_types: list[str] = Field(default_factory=list, max_length=16)
    reason: str = Field(min_length=1, max_length=4000)
    max_wait_seconds: int = Field(default=300, ge=1, le=900)

    @field_validator("intent_ids", "event_types")
    @classmethod
    def validate_ids(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized) or len(set(normalized)) != len(normalized):
            raise ValueError("wait selectors must be non-empty and unique")
        return normalized

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, values: list[str]) -> list[str]:
        if set(values) - REASON_WAKE_EVENTS:
            raise ValueError("unknown strategy wake event")
        return values

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("wait reason must not be blank")
        return value

    @model_validator(mode="after")
    def validate_condition(self) -> "ReasonWait":
        if not self.intent_ids and not self.event_types:
            raise ValueError("wait requires an Intent or event condition")
        return self
