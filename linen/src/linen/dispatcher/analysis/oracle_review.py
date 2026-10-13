"""Candidate-local oracle records for independent semantic Review."""

from __future__ import annotations

import hashlib
from pathlib import Path

from linen.contracts.oracle import OracleCatalog, OracleObservation, judge_http_observation
from linen.dispatcher.config import OracleConfig
from linen.dispatcher.protocol.client import LinenClient
from linen.dispatcher.runtime.oracle_runner import oracle_checker_digest
from linen.server.models import Fact, ProjectDetail


def oracle_review_record(
    config: OracleConfig, client: LinenClient, project: ProjectDetail,
    fact: Fact, workdir: Path,
) -> dict | None:
    attrs = fact.proof.attributes if fact.proof else {}
    if attrs.get("mode") != "dynamic" or not isinstance(attrs.get("run_id"), str):
        return None
    run = client.get_run(project.project.id, attrs["run_id"])
    if run.worker_type != "builtin-oracle":
        return None
    if not config.enabled or config.catalog_path is None:
        raise ValueError("Review of a registered observation requires its approved catalog")
    candidate_id = attrs.get("candidate_id")
    if candidate_id not in fact.proof.subject_ids or (run.source_generation, run.plan_revision) != (
        project.project.source_generation, project.project.plan_revision,
    ):
        raise ValueError("Oracle proof does not belong to the current candidate generation and plan")
    definition = OracleCatalog.model_validate_json(config.catalog_path.read_bytes()).bound_definition(
        project.project.id, candidate_id, project.project.source_generation, project.project.plan_revision,
    )
    role = {"reproduction": "positive", "negative_control": "negative"}.get(fact.type)
    if role is None or run.task_type != "poc:oracle" or run.status not in {"completed", "succeeded"}:
        raise ValueError("Oracle review requires a successful run and matching proof role")
    observations = []
    artifact_ids = attrs.get("artifact_ids", [])
    if not isinstance(artifact_ids, list) or not artifact_ids or any(not isinstance(item, str) for item in artifact_ids):
        raise ValueError("Oracle proof requires registered observation artifact IDs")
    for artifact_id in artifact_ids:
        artifact = client.get_artifact(project.project.id, artifact_id)
        if artifact.kind != "independent-oracle-observation":
            continue
        if artifact.producer_run_id != run.run_id or artifact_id not in run.artifact_ids:
            raise ValueError("Oracle observation does not belong to this registered run")
        path = workdir / artifact.workspace_path
        if path.is_symlink() or not path.resolve().is_relative_to(workdir.resolve()):
            raise ValueError("Oracle observation escapes the project workspace")
        with path.open("rb") as stream:
            data = stream.read(100001)
        if len(data) > 100000 or hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise ValueError("Oracle observation bytes differ from their registered artifact")
        record = OracleObservation.model_validate_json(data).model_dump(mode="json")
        expected = dict(project_id=project.project.id, candidate_id=candidate_id, run_id=run.run_id, role=role,
                        source_generation=project.project.source_generation, plan_revision=project.project.plan_revision,
                        oracle_id=definition.id, oracle_definition_sha256=definition.canonical_digest(),
                        checker_sha256=oracle_checker_digest(), snapshot_id=definition.source_digest)
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError("Oracle review record has a stale or mismatched binding")
        if judge_http_observation(definition.predicate, record["raw_observation"]) != record["capability_observed"]:
            raise ValueError("Oracle capability differs from the raw transport witness")
        observations.append(record)
    if len(observations) != 1:
        raise ValueError("Oracle review requires exactly one independent observation")
    # Only this definition crosses into Review; never the catalog, bindings,
    # evaluator labels, other candidates, previous Reviews or model history.
    return {"kind": "registered_oracle_review", "definition": definition.model_dump(mode="json"),
            "observation": observations[0]}
