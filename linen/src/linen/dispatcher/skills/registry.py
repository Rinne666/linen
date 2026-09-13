"""Small SDK-style registry for deterministic audit capabilities.

The registry is deliberately data-only.  It does not load executable code
from a repository and it does not give a worker protocol-write authority.
Receipts are accepted only when they refer to an artifact produced below the
dispatcher work directory and the recorded SHA-256 matches the bytes on disk.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    id: str
    version: str
    capability: str
    stage_id: str
    scanner_name: str | None = None


@dataclass(frozen=True, slots=True)
class SkillReceipt:
    """Validated execution receipt suitable for the server skill-run API."""

    skill_id: str
    skill_version: str
    capability: str
    stage_id: str
    status: str
    artifact_ref: str | None = None
    artifact_sha256: str | None = None
    command: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "skill_id": self.skill_id,
                "skill_version": self.skill_version,
                "capability": self.capability,
                "stage_id": self.stage_id,
                "status": self.status,
                "artifact_ref": self.artifact_ref,
                "artifact_sha256": self.artifact_sha256,
                "command": self.command,
                "detail": self.detail,
            }.items()
            if value is not None
        }


# Version changes are intentional: they invalidate old receipts in a new run,
# while the artifact itself remains replayable.  IDs are stable UI/protocol
# identifiers and are not derived from user-controlled descriptions.
_SKILLS: tuple[SkillDefinition, ...] = (
    SkillDefinition("security.semgrep", "1", "static-analysis.sarif", "semgrep", "semgrep"),
    SkillDefinition("security.spotbugs-findsecbugs", "1", "jvm-security.sarif", "spotbugs-findsecbugs", "spotbugs-findsecbugs"),
    SkillDefinition("security.osv-scanner", "1", "dependency-vulnerability.sarif", "osv-scanner", "osv-scanner"),
    SkillDefinition("security.gitleaks", "1", "secret-detection.sarif", "gitleaks", "gitleaks"),
    SkillDefinition("security.trivy", "1", "filesystem-security.sarif", "trivy", "trivy"),
)
REGISTRY: Mapping[str, SkillDefinition] = {skill.id: skill for skill in _SKILLS}
SCANNER_REGISTRY: Mapping[str, SkillDefinition] = {
    skill.scanner_name: skill for skill in _SKILLS if skill.scanner_name is not None
}


def get_skill(skill_id: str) -> SkillDefinition:
    """Return a trusted skill or reject an unregistered capability."""
    try:
        return REGISTRY[skill_id]
    except KeyError as exc:
        raise ValueError(f"unknown audit skill: {skill_id}") from exc


def skill_for_scanner(scanner_name: str) -> SkillDefinition:
    try:
        return SCANNER_REGISTRY[scanner_name]
    except KeyError as exc:
        raise ValueError(f"no registered skill for scanner: {scanner_name}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_receipt(
    skill: SkillDefinition,
    *,
    status: str,
    artifact_ref: str | Path | None = None,
    command: list[str] | str | None = None,
    detail: str | None = None,
    allowed_root: Path | None = None,
) -> SkillReceipt:
    """Create a receipt after checking status and, when present, its artifact."""
    if status not in {"running", "completed", "failed", "not_applicable"}:
        raise ValueError(f"unsupported skill receipt status: {status}")
    reference: str | None = None
    artifact_hash: str | None = None
    if artifact_ref is not None:
        path = Path(artifact_ref).expanduser().resolve()
        if allowed_root is not None:
            root = allowed_root.expanduser().resolve()
            if not path.is_relative_to(root):
                raise ValueError("skill receipt artifact is outside the dispatcher workdir")
        if not path.is_file():
            raise ValueError(f"skill receipt artifact does not exist: {path}")
        reference = str(path)
        artifact_hash = _sha256(path)
    command_text = None
    if command is not None:
        command_text = command if isinstance(command, str) else json.dumps(command, ensure_ascii=False)
    return SkillReceipt(
        skill_id=skill.id,
        skill_version=skill.version,
        capability=skill.capability,
        stage_id=skill.stage_id,
        status=status,
        artifact_ref=reference,
        artifact_sha256=artifact_hash,
        command=command_text,
        detail=detail,
    )


def validate_receipt(
    receipt: SkillReceipt | Mapping[str, Any],
    *,
    allowed_root: Path | None = None,
) -> SkillReceipt:
    """Re-validate a receipt before it crosses the dispatcher/server boundary."""
    values = receipt.as_dict() if isinstance(receipt, SkillReceipt) else dict(receipt)
    for key in ("skill_id", "skill_version", "capability", "stage_id", "status"):
        if not isinstance(values.get(key), str) or not values[key].strip():
            raise ValueError(f"skill receipt requires {key}")
    skill = get_skill(values["skill_id"])
    if values["skill_version"] != skill.version or values["stage_id"] != skill.stage_id:
        raise ValueError("skill receipt does not match the registered skill version or stage")
    if values["capability"] != skill.capability:
        raise ValueError("skill receipt capability does not match the registry")
    artifact_ref = values.get("artifact_ref")
    artifact_sha256 = values.get("artifact_sha256")
    if artifact_ref is not None:
        if not isinstance(artifact_ref, str) or not isinstance(artifact_sha256, str):
            raise ValueError("artifact_ref and artifact_sha256 must be provided together")
        path = Path(artifact_ref).expanduser().resolve()
        if allowed_root is not None and not path.is_relative_to(allowed_root.expanduser().resolve()):
            raise ValueError("skill receipt artifact is outside the dispatcher workdir")
        if not path.is_file() or _sha256(path) != artifact_sha256:
            raise ValueError("skill receipt artifact hash does not match the on-disk artifact")
    elif artifact_sha256 is not None:
        raise ValueError("artifact_sha256 requires artifact_ref")
    return SkillReceipt(
        skill_id=skill.id,
        skill_version=skill.version,
        capability=skill.capability,
        stage_id=skill.stage_id,
        status=values["status"],
        artifact_ref=artifact_ref,
        artifact_sha256=artifact_sha256,
        command=values.get("command"),
        detail=values.get("detail"),
    )
