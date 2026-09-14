from __future__ import annotations

import pytest

from linen.contracts import ExecutionRequest, SandboxProfile
from linen.dispatcher.config import LocalConfig
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.policy import (
    BackendCapabilities,
    LEGACY_LOCAL_PROFILE,
    evaluate_execution,
    legacy_local_profile,
)


_DIGEST = "sha256:" + "a" * 64


def _request(profile: SandboxProfile) -> ExecutionRequest:
    assert profile.profile_digest is not None
    return ExecutionRequest(
        run_id="run-policy-1",
        worker_manifest_digest=_DIGEST,
        sandbox_profile_digest=profile.profile_digest,
        attempt=1,
    )


def test_default_secure_profile_is_rejected_by_local_backend(tmp_path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    profile = SandboxProfile()

    decision = evaluate_execution(profile, _request(profile), backend.capabilities())

    assert decision.allowed is False
    assert decision.reason == "insufficient_capabilities"
    assert "network_isolation" in decision.missing_capabilities
    assert "control_tool_split" in decision.missing_capabilities
    assert "credential_filtering" in decision.missing_capabilities
    assert "host_process=false" in decision.missing_capabilities


def test_unknown_or_insufficient_capabilities_fail_closed() -> None:
    profile = SandboxProfile()
    request = _request(profile)

    unknown = evaluate_execution(profile, request, {"backend_name": "docker"})
    assert not unknown.allowed
    assert unknown.reason == "unknown_capabilities"

    insufficient = evaluate_execution(
        profile,
        request,
        BackendCapabilities(backend_name="sandbox"),
    )
    assert not insufficient.allowed
    assert insufficient.reason == "insufficient_capabilities"

    malformed = evaluate_execution(profile, request, object())
    assert not malformed.allowed
    assert malformed.reason == "unknown_capabilities"


def test_only_explicit_legacy_local_profile_is_decided_for_local_backend(tmp_path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    capabilities = backend.capabilities()

    legacy = legacy_local_profile()
    allowed = evaluate_execution(legacy, _request(legacy), capabilities)
    assert allowed.allowed is True
    assert allowed.reason == "explicit_legacy_local"
    assert legacy.profile_digest == LEGACY_LOCAL_PROFILE.profile_digest

    # A profile with broad access that is not the exported, explicit profile
    # must not silently become a local compatibility bypass.
    arbitrary = SandboxProfile(
        filesystem=legacy.filesystem.model_copy(update={"repo": "read-only"}),
    )
    denied = evaluate_execution(arbitrary, _request(arbitrary), capabilities)
    assert denied.allowed is False
    assert denied.reason == "insufficient_capabilities"


def test_capability_and_decision_models_are_frozen_and_serializable() -> None:
    capabilities = BackendCapabilities(backend_name="local", host_process=True)
    assert capabilities.model_dump(mode="json")["host_process"] is True
    with pytest.raises((TypeError, ValueError)):
        capabilities.host_process = False


def test_secure_backend_must_match_filesystem_and_resource_policy() -> None:
    profile = SandboxProfile.model_validate({
        "process": {"timeout_seconds": 30, "memory_limit_mb": 512},
    })
    base = {
        "backend_name": "docker",
        "filesystem_isolation": True,
        "network_isolation": True,
        "control_tool_split": True,
        "credential_filtering": True,
        "repo_access": ["read-only"],
        "workspace_access": ["read-write"],
        "control_channels": ["configured_provider"],
        "tool_channels": ["deny"],
        "control_tool_split": True,
    }
    missing_limits = evaluate_execution(
        profile, _request(profile), BackendCapabilities(**base),
    )
    assert not missing_limits.allowed
    assert "resource_limits" in missing_limits.missing_capabilities

    wrong_filesystem = evaluate_execution(
        profile,
        _request(profile),
        BackendCapabilities(
            **{**base, "resource_limits": True, "repo_access": ["read-write"]},
        ),
    )
    assert not wrong_filesystem.allowed
    assert "repo_access=read-only" in wrong_filesystem.missing_capabilities

    allowed = evaluate_execution(
        profile,
        _request(profile),
        BackendCapabilities(**{**base, "resource_limits": True}),
    )
    assert allowed.allowed
    assert allowed.reason == "sandbox_capabilities_satisfied"
