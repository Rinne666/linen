"""Mechanical integrity checks performed outside a read-only LLM reviewer."""

from __future__ import annotations

import json
from pathlib import Path

from linen.dispatcher.analysis.artifacts import digest, evidence_fields, load_artifact, source_bytes
from linen.server.models import Fact, ProjectDetail


def policy_integrity_checks(fact: Fact, workdir: Path) -> dict | None:
    """Re-read the immutable bytes; never assign a review verdict.

    The collector's hashes are claims. Recompute them here in the later review
    invocation, independently of collector execution and worker assertions.
    Semantic completeness and scope interpretation remain the reviewer's job.
    """
    if fact.type != "policy_evidence":
        return None
    path, manifest = load_artifact(fact, workdir)
    if manifest.get("kind") != "policy_evidence":
        raise ValueError("Policy attestation artifact has the wrong kind")
    snapshot = manifest.get("snapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("files"), dict):
        raise ValueError("Policy attestation has no frozen file inventory")
    source = path.parent / "source"
    files = {}
    for name, expected in snapshot["files"].items():
        files[name] = digest(source_bytes(source, name, expected))
    skipped = snapshot.get("skipped", [])
    identity = json.dumps({"files": files, "skipped": sorted(skipped, key=lambda item: (item["path"], item["reason"]))},
                          ensure_ascii=False, sort_keys=True).encode()
    if digest(identity) != snapshot.get("id"):
        raise ValueError("Policy frozen snapshot digest does not match its inventory")
    fields = evidence_fields(fact.evidence)
    result = {
        "checker": "linen.dispatcher.analysis.attestation.policy_integrity_checks/v1",
        "fact_id": fact.id, "source_generation": fact.source_generation,
        "manifest_sha256": digest(path.read_bytes()), "snapshot_id": snapshot["id"],
        "frozen_file_sha256": files, "source_root": str(source),
        "checks": {"manifest_digest": "valid", "frozen_file_digests": "valid", "snapshot_digest": "valid"},
        "claim_limit": "Byte integrity only. No semantic review verdict or global completeness claim.",
    }
    if manifest.get("schema_version", 1) >= 2:
        captured = json.loads(fields.get("collector_config_snapshot", "null"))
        if not isinstance(captured, dict):
            raise ValueError("Policy attestation has no captured collector configuration")
        actual = digest(json.dumps(captured, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
        if actual != fields.get("collector_config_sha256") or actual != manifest.get("active_source_config_sha256"):
            raise ValueError("Policy collector configuration digest does not match")
        if captured != manifest.get("active_source_config") or any(
            manifest.get("config", {}).get(key) != value for key, value in captured.items()
        ):
            raise ValueError("Policy collector configuration differs from its recorded manifest")
        result["collector_config_sha256"] = actual
        result["checks"]["captured_collector_configuration"] = "valid"
    else:
        result["checks"]["captured_collector_configuration"] = "legacy_unavailable"
    return result


def attestation_integrity_checks(project: ProjectDetail, fact: Fact, workdir: Path) -> dict | None:
    if fact.type != "scope_adjudication":
        return policy_integrity_checks(fact, workdir)
    path, record = load_artifact(fact, workdir)
    if record.get("kind") != "scope_adjudication":
        raise ValueError("Scope attestation artifact has the wrong kind")
    policy = next((item for item in project.facts if item.id == record.get("policy_evidence_fact_id")), None)
    if policy is None or policy.source_generation != fact.source_generation:
        raise ValueError("Scope attestation has no current policy source")
    result = policy_integrity_checks(policy, workdir)
    if result is None or result["manifest_sha256"] != record.get("policy_evidence_manifest_sha256"):
        raise ValueError("Scope attestation policy manifest digest does not match")
    if record.get("snapshot", {}).get("id") != result["snapshot_id"]:
        raise ValueError("Scope attestation refers to a different frozen policy snapshot")
    return {**result, "fact_id": fact.id, "policy_evidence_fact_id": policy.id,
            "policy_manifest_sha256": result["manifest_sha256"],
            "manifest_sha256": digest(path.read_bytes())}
