"""Closed contracts for secure worker execution profiles.

These models describe an execution policy; they do not create a sandbox or
grant a worker any capability.  Backend enforcement is intentionally a later
boundary, so the safe defaults remain useful even when a caller is running in
legacy local mode.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from .common import ContractModel, canonical_digest, validate_content_digest


FilesystemAccess = Literal["deny", "read-only", "read-write"]
ControlChannel = Literal["deny", "configured_provider"]
ToolChannel = Literal["deny", "allow"]


class FilesystemPolicy(ContractModel):
    """Filesystem access modes for the target repository and worker workspace."""

    repo: FilesystemAccess = "read-only"
    workspace: FilesystemAccess = "read-write"


class NetworkPolicy(ContractModel):
    """Separate control-provider semantics from tool network semantics."""

    control_channel: ControlChannel = "configured_provider"
    tool_channel: ToolChannel = "deny"


_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_FORBIDDEN_ENV_NAMES = frozenset({
    "HOME",
    "PATH",
    "TMPDIR",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "DOCKER_HOST",
})
_MODEL_CREDENTIAL_ENV_NAMES = frozenset({
    # Providers used by the current Pi/Claude/Codex adapters.
    "PI_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_KEY",
    # Common model-provider aliases that must never cross into tool policy.
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "XAI_API_KEY",
})


class CredentialPolicy(ContractModel):
    """Names-only credential allowlist; values never cross this contract."""

    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset({"allowed"})

    allowed: list[str] = Field(default_factory=list)

    @field_validator("allowed")
    @classmethod
    def _validate_allowed_names(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip().upper() for value in values]
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("credential names must be unique")
        if any(
            not _ENV_NAME_RE.fullmatch(value)
            or value in _FORBIDDEN_ENV_NAMES
            or value.startswith("DOCKER_")
            or value in _MODEL_CREDENTIAL_ENV_NAMES
            for value in cleaned
        ):
            raise ValueError("credential policy contains an unsafe environment name")
        return sorted(cleaned)


class ProcessPolicy(ContractModel):
    """Positive resource limits for one worker process."""

    timeout_seconds: int = Field(default=900, gt=0)
    memory_limit_mb: int | None = Field(default=None, gt=0)
    cpu_limit: float | None = Field(default=None, gt=0)
    pids_limit: int | None = Field(default=None, gt=0)


class SandboxProfile(ContractModel):
    """Immutable, digest-addressable policy bundle for a sandbox backend."""

    CANONICAL_EXCLUDE_FIELDS: ClassVar[frozenset[str]] = frozenset({"profile_digest"})

    schema_version: int = 1
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    credentials: CredentialPolicy = Field(default_factory=CredentialPolicy)
    process: ProcessPolicy = Field(default_factory=ProcessPolicy)
    profile_digest: str | None = None

    @field_validator("profile_digest")
    @classmethod
    def _validate_profile_digest(cls, value: str | None) -> str | None:
        return validate_content_digest(value) if value is not None else None

    @model_validator(mode="after")
    def _assign_or_verify_digest(self) -> "SandboxProfile":
        digest = "sha256:" + canonical_digest(
            self,
            exclude={"profile_digest"},
        )
        if self.profile_digest is None:
            object.__setattr__(self, "profile_digest", digest)
        elif self.profile_digest != digest:
            raise ValueError("profile_digest does not match canonical profile content")
        return self


class ExecutionRequest(ContractModel):
    """Secret-free authorization reference for one backend execution."""

    schema_version: int = 1
    run_id: str = Field(min_length=1)
    worker_manifest_digest: str
    sandbox_profile_digest: str
    attempt: int = Field(ge=1)

    @field_validator("run_id")
    @classmethod
    def _strip_run_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("run_id must not be empty")
        return value

    @field_validator("worker_manifest_digest", "sandbox_profile_digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        return validate_content_digest(value)
