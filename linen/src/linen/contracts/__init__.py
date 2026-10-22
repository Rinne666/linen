"""Versioned, storage-independent contracts for the Linen kernel.

The contracts package deliberately has no dependency on the server or
dispatcher packages.  Adapters at those boundaries can translate the current
SQLite/Pydantic models into these stable DTOs without making consumers depend
on a database schema.
"""

from .artifact import ArtifactMetadata
from .baseline import (
    BaselineLineageManifest,
    BaselineManifestMember,
    BaselineSourceIdentity,
    BaselineSourceRecord,
    LedgerValidationAuth,
    LedgerValidationReceipt,
    LedgerValidationResult,
    LedgerValidatorIdentity,
    encode_reference,
    reference_digest,
    validation_auth_mac_input,
)
from .component import ComponentKind, ComponentManifest, ComponentRisk
from .context import ContextProjection, ContextRequest
from .event import AuditEventEnvelope
from .run import RunEnvelope, RunStatus
from .reason import ReasonWait
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
from .skill_audit import (
    AttackClass,
    ConfirmedRecord,
    CoverageUnit,
    CoverageUnitState,
    FindingRecord,
    NeedsValidationRecord,
    RejectedRecord,
    TraceStep,
    ValidationPlan,
    Verdict,
    parse_finding_record,
)
from .snapshot import BlackboardSnapshot, EdgeEnvelope, NodeEnvelope
from .worker_manifest import ComponentRef, RecipeRef, WorkerManifest

__all__ = [
    "ArtifactMetadata",
    "AuditEventEnvelope",
    "BaselineLineageManifest",
    "BaselineManifestMember",
    "BaselineSourceIdentity",
    "BaselineSourceRecord",
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
    "LedgerValidationAuth",
    "LedgerValidationReceipt",
    "LedgerValidationResult",
    "LedgerValidatorIdentity",
    "NetworkPolicy",
    "NodeEnvelope",
    "ProcessPolicy",
    "RecipeRef",
    "ReasonWait",
    "RunEnvelope",
    "RunStatus",
    "SandboxProfile",
    "ToolChannel",
    "WorkerManifest",
    "AttackClass",
    "ConfirmedRecord",
    "CoverageUnit",
    "CoverageUnitState",
    "FindingRecord",
    "NeedsValidationRecord",
    "RejectedRecord",
    "TraceStep",
    "ValidationPlan",
    "Verdict",
    "encode_reference",
    "parse_finding_record",
    "reference_digest",
    "validation_auth_mac_input",
]
