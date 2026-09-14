"""Fail-closed policy checks for vNext execution backends.

The policy gate is deliberately a small, side-effect-free boundary.  It
doesn't start a process and it doesn't alter the legacy dispatcher path.  A
backend declares what it can enforce, and an execution is admitted only when
the declaration satisfies the selected profile.

``LocalBackend`` is useful for compatibility, but it is a host-process
backend: it cannot enforce filesystem/network/credential isolation.  The
explicit :data:`LEGACY_LOCAL_PROFILE` is therefore the only profile that may
be evaluated against it.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator

from linen.contracts import (
    CredentialPolicy,
    ExecutionRequest,
    ControlChannel,
    FilesystemAccess,
    FilesystemPolicy,
    NetworkPolicy,
    SandboxProfile,
    ToolChannel,
)
from linen.contracts.common import ContractModel


class BackendCapabilities(ContractModel):
    """Immutable, serializable declaration of backend enforcement features.

    The booleans describe enforcement, not what a worker happens to be able
    to do.  In particular, ``host_process=True`` is not an isolation feature;
    it is a warning that the worker runs directly on the dispatcher host.
    """

    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset()

    backend_name: Literal["local", "docker", "sandbox"]
    host_process: bool = False
    filesystem_isolation: bool = False
    network_isolation: bool = False
    control_tool_split: bool = False
    credential_filtering: bool = False
    resource_limits: bool = False
    repo_access: list[FilesystemAccess] = Field(default_factory=list)
    workspace_access: list[FilesystemAccess] = Field(default_factory=list)
    control_channels: list[ControlChannel] = Field(default_factory=list)
    tool_channels: list[ToolChannel] = Field(default_factory=list)

    @field_validator("backend_name")
    @classmethod
    def _strip_backend_name(cls, value: str) -> str:
        value = value.strip().lower()
        if not value:
            raise ValueError("backend_name must not be empty")
        return value


class PolicyDecision(ContractModel):
    """Immutable result of one execution policy evaluation."""

    allowed: bool
    reason: str = Field(min_length=1)
    profile_digest: str | None = None
    run_id: str | None = None
    backend_name: str | None = None
    required_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)

    @property
    def decision(self) -> str:
        """Human-readable stable decision label for logs and API adapters."""

        return "allow" if self.allowed else "deny"


# A host-process execution must be an explicit compatibility choice.  Keep
# this value narrow and deterministic: policy must not infer a legacy bypass
# from an arbitrary profile that happens to request broad access.
LEGACY_LOCAL_PROFILE = SandboxProfile(
    filesystem=FilesystemPolicy(repo="read-write", workspace="read-write"),
    network=NetworkPolicy(control_channel="configured_provider", tool_channel="allow"),
    credentials=CredentialPolicy(allowed=[]),
)


def legacy_local_profile() -> SandboxProfile:
    """Return the explicit profile for the pre-sandbox local execution path."""

    # Contract models are immutable; model_copy also keeps callers from
    # sharing a mutable nested value if this implementation changes later.
    return LEGACY_LOCAL_PROFILE.model_copy(deep=True)


_SECURE_REQUIRED = (
    "filesystem_isolation",
    "network_isolation",
    "credential_filtering",
)


def _deny(
    reason: str,
    *,
    profile: SandboxProfile | None = None,
    request: ExecutionRequest | None = None,
    capabilities: BackendCapabilities | None = None,
    required: tuple[str, ...] = (),
    missing: tuple[str, ...] = (),
) -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        reason=reason,
        profile_digest=profile.profile_digest if profile is not None else None,
        run_id=request.run_id if request is not None else None,
        backend_name=capabilities.backend_name if capabilities is not None else None,
        required_capabilities=list(required),
        missing_capabilities=list(missing),
    )


def _allow(
    reason: str,
    *,
    profile: SandboxProfile,
    request: ExecutionRequest,
    capabilities: BackendCapabilities,
    required: tuple[str, ...] = (),
) -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        reason=reason,
        profile_digest=profile.profile_digest,
        run_id=request.run_id,
        backend_name=capabilities.backend_name,
        required_capabilities=list(required),
        missing_capabilities=[],
    )


def evaluate_execution(
    profile: SandboxProfile | Any,
    execution_request: ExecutionRequest | Any,
    capabilities: BackendCapabilities | Any,
) -> PolicyDecision:
    """Evaluate whether a backend may execute one request under ``profile``.

    The function is intentionally total for untrusted boundary inputs: bad
    types, unknown backends, digest mismatches, and missing capabilities all
    return a denied immutable decision.  No fallback to host execution is
    performed.
    """

    if not isinstance(profile, SandboxProfile):
        return _deny("unknown_profile")
    if not isinstance(execution_request, ExecutionRequest):
        return _deny("invalid_execution_request", profile=profile)

    # Capability declarations are produced by registered backend adapters.
    # Do not accept a loose mapping from an untrusted config/worker boundary:
    # it could self-assert enforcement simply by setting booleans to true.
    if not isinstance(capabilities, BackendCapabilities):
        return _deny("unknown_capabilities", profile=profile, request=execution_request)
    declared = capabilities
    if execution_request.sandbox_profile_digest != profile.profile_digest:
        return _deny(
            "profile_digest_mismatch",
            profile=profile,
            request=execution_request,
            capabilities=declared,
        )

    # Compatibility is an explicit, known profile.  Never infer it from a
    # single permissive field, because doing so would turn malformed secure
    # profiles into a host-process bypass.
    if profile.profile_digest == LEGACY_LOCAL_PROFILE.profile_digest:
        if declared.backend_name != "local":
            return _deny(
                "legacy_local_requires_local_backend",
                profile=profile,
                request=execution_request,
                capabilities=declared,
            )
        if not declared.host_process or any(
            getattr(declared, capability) for capability in _SECURE_REQUIRED
        ):
            return _deny(
                "legacy_local_capability_mismatch",
                profile=profile,
                request=execution_request,
                capabilities=declared,
            )
        return _allow(
            "explicit_legacy_local",
            profile=profile,
            request=execution_request,
            capabilities=declared,
        )

    # The normal profile is secure-by-default.  Any backend that claims to
    # execute it must provide all enforcement boundaries and must not run a
    # worker directly as a host process.
    required = _SECURE_REQUIRED
    missing = tuple(
        capability
        for capability in required
        if not getattr(declared, capability, False)
    )
    if declared.host_process:
        missing = (*missing, "host_process=false")
    if profile.filesystem.repo not in declared.repo_access:
        missing = (*missing, f"repo_access={profile.filesystem.repo}")
    if profile.filesystem.workspace not in declared.workspace_access:
        missing = (*missing, f"workspace_access={profile.filesystem.workspace}")
    if profile.network.control_channel not in declared.control_channels:
        missing = (*missing, f"control_channel={profile.network.control_channel}")
    if profile.network.tool_channel not in declared.tool_channels:
        missing = (*missing, f"tool_channel={profile.network.tool_channel}")
    split_required = (
        profile.network.control_channel == "configured_provider"
        and profile.network.tool_channel == "deny"
    )
    if split_required and not declared.control_tool_split:
        missing = (*missing, "control_tool_split")
    process_limits_requested = any((
        profile.process.memory_limit_mb is not None,
        profile.process.cpu_limit is not None,
        profile.process.pids_limit is not None,
    ))
    if process_limits_requested and not declared.resource_limits:
        missing = (*missing, "resource_limits")
    if missing:
        return _deny(
            "insufficient_capabilities",
            profile=profile,
            request=execution_request,
            capabilities=declared,
            required=required,
            missing=missing,
        )
    return _allow(
        "sandbox_capabilities_satisfied",
        profile=profile,
        request=execution_request,
        capabilities=declared,
        required=required,
    )


__all__ = [
    "BackendCapabilities",
    "LEGACY_LOCAL_PROFILE",
    "PolicyDecision",
    "evaluate_execution",
    "legacy_local_profile",
]
