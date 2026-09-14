"""Metadata index for workspace-backed immutable evidence."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator

from .common import ContractModel, validate_sha256, validate_workspace_relative_path


class ArtifactMetadata(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({"related_node_ids"})
    schema_version: int = 1
    artifact_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    workspace_path: str
    sha256: str
    media_type: str = Field(min_length=1)
    byte_size: int | None = Field(default=None, ge=0)
    producer_run_id: str | None = None
    related_node_ids: list[str] = Field(default_factory=list)
    created_at: str | None = None

    @field_validator("artifact_id", "project_id", "kind", "media_type")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @field_validator("workspace_path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return validate_workspace_relative_path(value)

    @field_validator("sha256")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("producer_run_id", "created_at")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("related_node_ids")
    @classmethod
    def _validate_related_ids(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("related_node_ids must not contain empty ids")
        return cleaned
