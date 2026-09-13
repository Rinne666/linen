from pathlib import Path

import pytest

from linen.dispatcher.analysis.stages import stage_definitions
from linen.dispatcher.config import AuditConfig, SemgrepConfig
from linen.dispatcher.skills import build_receipt, skill_for_scanner, validate_receipt


def test_registered_scanner_receipt_is_hash_bound(tmp_path: Path) -> None:
    artifact = tmp_path / "manifest.json"
    artifact.write_text('{"status":"completed"}', encoding="utf-8")
    skill = skill_for_scanner("trivy")

    receipt = build_receipt(
        skill,
        status="completed",
        artifact_ref=artifact,
        command=["trivy", "fs", "."],
        allowed_root=tmp_path,
    )
    assert validate_receipt(receipt, allowed_root=tmp_path).artifact_sha256

    artifact.write_text('{"status":"tampered"}', encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        validate_receipt(receipt, allowed_root=tmp_path)


def test_receipt_rejects_unregistered_skill(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown audit skill"):
        validate_receipt({
            "skill_id": "local.shell",
            "skill_version": "1",
            "capability": "shell",
            "stage_id": "shell",
            "status": "completed",
        }, allowed_root=tmp_path)


def test_stage_skeleton_is_stable_and_marks_disabled_scanners_optional() -> None:
    config = AuditConfig(enabled=True, semgrep=SemgrepConfig(enabled=False))
    first = stage_definitions(config, "hypothesis")
    second = stage_definitions(config, "hypothesis")
    assert first == second
    semgrep = next(stage for stage in first if stage.stage_id == "semgrep")
    assert semgrep.required is False
    assert semgrep.skill_id == "security.semgrep"
