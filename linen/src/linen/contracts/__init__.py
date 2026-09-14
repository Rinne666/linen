"""Versioned, storage-independent contracts for the Linen kernel.

The contracts package deliberately has no dependency on the server or
dispatcher packages.  Adapters at those boundaries can translate the current
SQLite/Pydantic models into these stable DTOs without making consumers depend
on a database schema.
"""

from .artifact import ArtifactMetadata
from .component import ComponentKind, ComponentManifest, ComponentRisk
from .context import ContextProjection, ContextRequest
from .event import AuditEventEnvelope
from .run import RunEnvelope, RunStatus
from .sandbox import (
    ControlChannel,
    CredentialPolicy,
    ExecutionRequest,
    FilesystemAccess,
    FilesystemPolicy,
    NetworkPolicy,
    ProcessPolicy,
    SandboxProfile,
    ToolChannel,
)
from .snapshot import BlackboardSnapshot, EdgeEnvelope, NodeEnvelope
from .worker_manifest import ComponentRef, RecipeRef, WorkerManifest

__all__ = [
    "ArtifactMetadata",
    "AuditEventEnvelope",
    "BlackboardSnapshot",
    "ComponentKind",
    "ComponentManifest",
    "ComponentRef",
    "ComponentRisk",
    "ContextProjection",
    "ContextRequest",
    "ControlChannel",
    "CredentialPolicy",
    "EdgeEnvelope",
    "ExecutionRequest",
    "FilesystemAccess",
    "FilesystemPolicy",
    "NetworkPolicy",
    "NodeEnvelope",
    "ProcessPolicy",
    "RecipeRef",
    "RunEnvelope",
    "RunStatus",
    "SandboxProfile",
    "ToolChannel",
    "WorkerManifest",
]
