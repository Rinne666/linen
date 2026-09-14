"""Storage-independent Blackboard snapshot contract."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field, field_validator, model_validator

from .common import ContractModel, canonical_digest


class NodeEnvelope(ContractModel):
    kind: str = Field(min_length=1)
    id: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class EdgeEnvelope(ContractModel):
    id: str = Field(min_length=1)
    source_kind: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    target_kind: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    relation_type: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class BlackboardSnapshot(ContractModel):
    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({"nodes", "edges"})
    CANONICAL_EXCLUDE_FIELDS: ClassVar[frozenset[str]] = frozenset({"snapshot_id", "created_at"})
    schema_version: int = 1
    snapshot_id: str | None = None
    project_id: str = Field(min_length=1)
    graph_revision: int = Field(ge=0)
    source_generation: int = Field(ge=1)
    plan_revision: int = Field(ge=1)
    nodes: list[NodeEnvelope] = Field(default_factory=list)
    edges: list[EdgeEnvelope] = Field(default_factory=list)
    created_at: str = Field(min_length=1)

    @field_validator("project_id", "created_at")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @model_validator(mode="after")
    def _assign_stable_id(self) -> "BlackboardSnapshot":
        digest = canonical_digest(
            self,
            exclude={"snapshot_id", "created_at"},
            unordered_fields=self.CANONICAL_UNORDERED_FIELDS,
        )
        expected_id = f"snap-{digest}"
        if self.snapshot_id is None:
            object.__setattr__(self, "snapshot_id", expected_id)
        elif self.snapshot_id != expected_id:
            raise ValueError("snapshot_id does not match canonical snapshot content")
        return self

    def snapshot_digest(self) -> str:
        """Hash snapshot content without the derived identity field."""

        return canonical_digest(
            self,
            exclude={"snapshot_id", "created_at"},
            unordered_fields=self.CANONICAL_UNORDERED_FIELDS,
        )
