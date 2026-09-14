"""Stable identity and lifecycle envelope for one dispatcher attempt."""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, field_validator

from .common import ContractModel, validate_content_digest

RunStatus = Literal[
    "queued",
    "running",
    "completed",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "interrupted",
    "blocked",
]


class RunEnvelope(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({"artifact_ids"})
    schema_version: int = 1
    run_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    intent_id: str | None = None
    task_type: str = Field(min_length=1)
    stage: str | None = None
    attempt: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1)
    graph_revision: int = Field(ge=0)
    source_generation: int = Field(ge=1)
    plan_revision: int = Field(ge=1)
    context_projection_id: str | None = None
    worker_manifest_digest: str | None = None
    timeout_seconds: int = Field(ge=1)
    status: RunStatus = "queued"
    worker_name: str | None = None
    worker_type: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    artifact_ids: list[str] = Field(default_factory=list)
    error_id: str | None = None

    @field_validator("run_id", "project_id", "task_type", "idempotency_key")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @field_validator(
        "intent_id", "stage", "context_projection_id", "worker_name", "worker_type",
        "started_at", "finished_at", "error_id",
    )
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("worker_manifest_digest")
    @classmethod
    def _validate_manifest_digest(cls, value: str | None) -> str | None:
        return validate_content_digest(value) if value is not None else None

    @field_validator("artifact_ids")
    @classmethod
    def _validate_artifact_ids(cls, values: list[str]) -> list[str]:
        values = [value.strip() for value in values]
        if any(not value for value in values):
            raise ValueError("artifact_ids must not contain empty ids")
        return values
