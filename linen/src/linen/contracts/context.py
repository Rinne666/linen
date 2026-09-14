"""Bounded, reproducible context projection contracts."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field, field_validator

from .common import ContractModel


class ContextRequest(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "node_ids",
        "relation_types",
        "artifact_ids",
    })
    schema_version: int = 1
    node_ids: list[str] = Field(default_factory=list)
    relation_types: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1)

    @field_validator("node_ids", "relation_types", "artifact_ids")
    @classmethod
    def _validate_lists(cls, values: list[str]) -> list[str]:
        values = [value.strip() for value in values]
        if any(not value for value in values):
            raise ValueError("context request lists must not contain empty values")
        return values

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason must not be empty")
        return value


class ContextProjection(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "node_ids",
        "edge_ids",
        "artifact_ids",
    })
    CANONICAL_EXCLUDE_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "projection_digest",
        "created_at",
    })
    schema_version: int = 1
    projection_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    graph_revision: int = Field(ge=0)
    source_generation: int = Field(ge=1)
    plan_revision: int = Field(ge=1)
    intent_id: str | None = None
    stage: str | None = None
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    selection_policy: str = Field(min_length=1)
    request: ContextRequest | None = None
    created_at: str = Field(min_length=1)
    projection_digest: str | None = None

    @field_validator("projection_id", "project_id", "snapshot_id", "selection_policy", "created_at")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @field_validator("intent_id", "stage")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("node_ids", "edge_ids", "artifact_ids")
    @classmethod
    def _validate_ids(cls, values: list[str]) -> list[str]:
        values = [value.strip() for value in values]
        if any(not value for value in values):
            raise ValueError("projection ids must not contain empty values")
        return values

    @field_validator("projection_digest")
    @classmethod
    def _validate_projection_digest(cls, value: str | None) -> str | None:
        from .common import validate_content_digest

        return validate_content_digest(value) if value is not None else None

    def model_post_init(self, __context: object) -> None:
        from .common import canonical_digest

        digest = f"sha256:{canonical_digest(self, exclude={'projection_digest', 'created_at'}, unordered_fields=self.CANONICAL_UNORDERED_FIELDS)}"
        if self.projection_digest is None:
            object.__setattr__(self, "projection_digest", digest)
        elif self.projection_digest != digest:
            raise ValueError("projection_digest does not match canonical projection content")
