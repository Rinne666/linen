"""Immutable dispatcher-to-worker execution manifest."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator, model_validator

from .common import ContractModel, canonical_digest, validate_content_digest


class RecipeRef(ContractModel):
    id: str = Field(min_length=1)
    digest: str

    @field_validator("id")
    @classmethod
    def _strip_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("recipe id must not be empty")
        return value

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        return validate_content_digest(value)


class ComponentRef(ContractModel):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    digest: str

    @field_validator("id", "version")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("component reference text must not be empty")
        return value

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        return validate_content_digest(value)


class WorkerManifest(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "required_capabilities",
        "skills",
        "plugins",
        "mcp",
        "tools",
    })
    CANONICAL_EXCLUDE_FIELDS: ClassVar[frozenset[str]] = frozenset({"manifest_digest"})
    schema_version: int = 1
    runtime: str = Field(min_length=1)
    project_id: str | None = None
    intent_id: str | None = None
    run_id: str | None = None
    recipe: RecipeRef
    required_capabilities: list[str] = Field(default_factory=list)
    skills: list[ComponentRef] = Field(default_factory=list)
    plugins: list[ComponentRef] = Field(default_factory=list)
    mcp: list[ComponentRef] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    permissions: dict[str, bool] = Field(default_factory=dict)
    manifest_digest: str | None = None

    @field_validator("runtime")
    @classmethod
    def _strip_runtime(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("runtime must not be empty")
        return value

    @field_validator("project_id", "intent_id", "run_id")
    @classmethod
    def _strip_optional_ids(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("required_capabilities", "tools")
    @classmethod
    def _validate_name_lists(cls, values: list[str]) -> list[str]:
        values = [value.strip() for value in values]
        if any(not value for value in values):
            raise ValueError("manifest names must not be empty")
        return values

    @field_validator("manifest_digest")
    @classmethod
    def _validate_manifest_digest(cls, value: str | None) -> str | None:
        return validate_content_digest(value) if value is not None else None

    @model_validator(mode="after")
    def _assign_or_verify_digest(self) -> "WorkerManifest":
        digest = f"sha256:{canonical_digest(self, exclude={'manifest_digest'}, unordered_fields=self.CANONICAL_UNORDERED_FIELDS)}"
        if self.manifest_digest is None:
            object.__setattr__(self, "manifest_digest", digest)
        elif self.manifest_digest != digest:
            raise ValueError("manifest_digest does not match canonical manifest content")
        return self
