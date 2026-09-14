"""Append-only audit event envelope."""

from __future__ import annotations

from typing import Any

from pydantic import AliasChoices, Field, field_validator

from .common import ContractModel


class AuditEventEnvelope(ContractModel):
    schema_version: int = 1
    event_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    run_id: str | None = None
    idempotency_key: str | None = None
    # ``event_type`` is the storage/API spelling; ``type`` is accepted as a
    # wire compatibility spelling used by the vNext design examples.
    event_type: str = Field(
        min_length=1,
        validation_alias=AliasChoices("event_type", "type"),
    )
    actor: str = Field(min_length=1)
    entity_kind: str | None = None
    entity_id: str | None = None
    sequence: int | None = Field(default=None, ge=1)
    graph_revision: int = Field(ge=0)
    source_generation: int = Field(ge=1)
    plan_revision: int = Field(ge=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(min_length=1)

    @field_validator("event_id", "project_id", "event_type", "actor", "created_at")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @field_validator("run_id", "idempotency_key", "entity_kind", "entity_id")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @property
    def type(self) -> str:
        """Compatibility spelling used by the vNext JSON examples."""

        return self.event_type
