"""Trusted component descriptor used by the capability plane."""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import ContractModel

ComponentKind = Literal["skill", "plugin", "mcp", "tool", "prompt", "policy_pack"]


class ComponentRisk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    filesystem_write: bool = False
    network: bool = False
    shell: bool = False


class ComponentManifest(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "provides",
        "requires_capabilities",
        "required_permissions",
    })
    schema_version: int = 1
    id: str = Field(min_length=1)
    kind: ComponentKind
    version: str = Field(min_length=1)
    provides: list[str] = Field(default_factory=list)
    requires_capabilities: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    runtime_compatibility: dict[str, str] = Field(default_factory=dict)
    risk: ComponentRisk = Field(default_factory=ComponentRisk)

    @field_validator("id", "version")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @field_validator("provides", "requires_capabilities", "required_permissions")
    @classmethod
    def _validate_name_lists(cls, values: list[str]) -> list[str]:
        values = [value.strip() for value in values]
        if any(not value for value in values):
            raise ValueError("component names must not be empty")
        return values
