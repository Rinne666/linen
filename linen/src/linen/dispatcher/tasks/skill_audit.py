"""Skill-driven audit tasks: hunt, verify-candidate, coverage-critic, verify-record.

Each intent type maps to one phase of the vendored Cloudflare security-audit-skill
method (docs/skills/skill-driven-mode.md). The worker session is always fresh per
run, which is what makes finder != verifier hold: independence comes from the
session boundary plus input isolation, never from trusting a role label.

Facts written by this module:
- ``coverage_unit``     — one per assigned unit disposition (hunt)
- ``candidate_finding`` — one per proposed candidate record (hunt)
- ``coverage_gap``      — one per uncovered boundary the hunter reported (hunt)
- ``finding_record``    — verdict-exclusive record (verify-candidate)
- ``coverage_critic``   — critic statement, missing units, reassignments (critic)
- ``finding_verified`` / ``finding_dropped`` — Phase-5 outcomes (verify-record)

Candidate/finding records ride in ``proof.attributes.finding_record`` so the
findings serializer (analysis/skill_findings.py) can collect them without a
schema migration.
"""

from __future__ import annotations

import json
import logging
import time

from linen.dispatcher.analysis import skill_findings
from linen.dispatcher.analysis.policy import SOURCE_DATA_BOUNDARY
from linen.dispatcher.analysis.skill_prompts import (
    assemble_hunter_prompt,
    assemble_simple_prompt,
    load_attack_classes_block,
    vendored_skill_dir,
)
from linen.dispatcher.contracts import (
    extract_context_request,
    parse_json_output,
    validate_critic_payload,
    validate_hunt_payload,
    validate_record_verification_payload,
    validate_skill_verifier_payload,
)
from linen.dispatcher.tasks.common import (
    HeartbeatLease,
    best_effort_release,
    build_context_execution_contracts,
    did_timeout,
    prepare_intent_projection,
    run_worker_process,
    task_healthcheck_enabled,
    write_context_projection_reference,
)
from linen.dispatcher.workers.registry import get_driver

LOG = logging.getLogger(__name__)

SKILL_AUDIT_PROMPT_GROUP = "skill_audit"

HUNT_INTENT_TYPE = "hunt"
VERIFY_CANDIDATE_INTENT_TYPE = "verify-candidate"
CRITIC_INTENT_TYPE = "coverage-critic"
VERIFY_RECORD_INTENT_TYPE = "verify-record"

SKILL_AUDIT_INTENT_TYPES = frozenset({
    HUNT_INTENT_TYPE,
    VERIFY_CANDIDATE_INTENT_TYPE,
    CRITIC_INTENT_TYPE,
    VERIFY_RECORD_INTENT_TYPE,
})

INTENT_TO_TASK_TYPE = {
    HUNT_INTENT_TYPE: "hunt",
    VERIFY_CANDIDATE_INTENT_TYPE: "verify_candidate",
    CRITIC_INTENT_TYPE: "critic",
    VERIFY_RECORD_INTENT_TYPE: "verify_record",
}


def _preview(text: str | None, limit: int = 300) -> str:
    text = text or ""
    return text[:limit].replace("\n", "\\n")


def _proof(**attributes: object) -> dict:
    return {"claim_kind": "skill_audit", "attributes": attributes}


def _attr(fact, key: str) -> object:
    if fact.proof is None:
        return None
    attributes = getattr(fact.proof, "attributes", None) or {}
    return attributes.get(key)


def _record_block(fact) -> str:
    record = _attr(fact, "finding_record")
    if record is None:
        raise ValueError(f"fact {fact.id} carries no finding_record payload")
    return json.dumps(record, ensure_ascii=False, indent=2)


def _bounce_count(intent) -> int:
    marker = "|bounce:"
    if intent.description and marker in intent.description:
        tail = intent.description.rsplit(marker, 1)[-1].strip().split()[0]
        try:
            return int(tail)
        except ValueError:
            return 0
    return 0


def _create_followup(client, project_id: str, from_ids: list[str], description: str, intent_type: str) -> bool:
    response = client.create_intent(
        project_id, from_ids, description, creator="dispatcher.skill_audit",
        action="analyze", target="graph", intent_type=intent_type,
    )
    if not response.ok:
        LOG.warning(
            "skill_audit followup intent creation failed project=%s type=%s status=%s body=%s",
            project_id, intent_type, response.status_code, response.text[:200],
        )
        return False
    return True


def _conclude_fact(client, project_id: str, intent_id: str, worker_name: str, *, fact_type: str,
                   description: str, evidence: str, semantic_type: str, proof: dict) -> bool:
    response = client.conclude(
        project_id, intent_id, worker_name,
        description=description, fact_type=fact_type, evidence=evidence,
        status="triaged", semantic_type=semantic_type, proof=proof,
    )
    if not response.ok:
        LOG.warning(
            "skill_audit conclude failed project=%s intent=%s type=%s status=%s body=%s",
            project_id, intent_id, fact_type, response.status_code, response.text[:200],
        )
        return False
    return True


def run_skill_audit_task(
    config,
    client,
    backend,
    project,
    export_yaml: str,
    intent,
    worker,
    cancellation,
    attempt: int = 1,
    trigger: str | None = None,
) -> str:
    intent_type = (intent.type or "").strip()
    if intent_type not in SKILL_AUDIT_INTENT_TYPES:
        LOG.error("skill_audit task got unexpected intent type %r", intent_type)
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"

    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    lease = HeartbeatLease.for_intent(
        client, project.project.id, intent.id, worker.name, config.runtime.interval
    )
    lease.start()
    try:
        container_name = backend.ensure_running(project.project.id)

        if task_healthcheck_enabled(config):
            health = driver.check_health(worker, timeout=config.runtime.healthcheck_timeout)
            if cancellation.is_cancelled:
                return "cancelled"
            if lease.failure is not None:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "unhealthy"
            if not health.ok:
                LOG.warning(
                    "skill_audit worker unhealthy project=%s intent=%s worker=%s detail=%s",
                    project.project.id, intent.id, worker.name, health.detail,
                )
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "unhealthy"

        projection = prepare_intent_projection(
            client, project, intent_id=intent.id, phase="skill_audit_execute",
            current_graph_revision=project.project.graph_revision,
        )
        if projection is None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        context_reference = write_context_projection_reference(
            backend, container_name, projection, phase="skill_audit_execute",
        )

        timeout_seconds = config.tasks.explore.timeout
        prompt = _assemble_prompt(config, project, intent, intent_type)
        prompt += "\n" + SOURCE_DATA_BOUNDARY

        worker_manifest, run_envelope = build_context_execution_contracts(
            project, worker, projection, phase="skill_audit_execute",
            timeout_seconds=timeout_seconds, prompt=prompt,
            logical_scope=f"skill:{intent_type}:{intent.id}",
            attempt=attempt, intent_id=intent.id,
            recipe_id=f"skill_audit.{intent_type}",
            recipe_label=f"Skill audit {intent_type}",
            recipe_version=1,
        )
        session = driver.prepare_session()
        execute = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            backend, container_name, worker, execute.argv,
            phase="skill_audit_execute", timeout_seconds=timeout_seconds,
            lease=lease, cancellation=cancellation, client=client,
            run_envelope=run_envelope, worker_manifest=worker_manifest,
            context_projection_id=run_envelope.context_projection_id,
            recipe_content_digest=worker_manifest.recipe.digest,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        if cancellation.is_cancelled:
            return "cancelled"
        if lease.failure is not None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "unhealthy"
        if did_timeout(result):
            LOG.warning("skill_audit timed out project=%s intent=%s execute_ms=%s",
                        project.project.id, intent.id, execute_ms)
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        if result.returncode != 0:
            LOG.warning("skill_audit command failed project=%s intent=%s code=%s stdout=%s",
                        project.project.id, intent.id, result.returncode, _preview(result.stdout))
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"

        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            if extract_context_request(payload) is not None:
                LOG.error("skill_audit requested unsupported context expansion project=%s intent=%s",
                          project.project.id, intent.id)
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "failed"
            if intent_type == HUNT_INTENT_TYPE:
                return _handle_hunt(client, project, intent, worker, payload,
                                    run_envelope.run_id, execute_ms, task_started)
            if intent_type == VERIFY_CANDIDATE_INTENT_TYPE:
                return _handle_verify_candidate(client, project, intent, worker, payload,
                                                run_envelope.run_id, execute_ms, task_started)
            if intent_type == CRITIC_INTENT_TYPE:
                return _handle_critic(client, project, intent, worker, payload,
                                      execute_ms, task_started)
            return _handle_verify_record(config, client, project, intent, worker, payload,
                                         execute_ms, task_started)
        except Exception as exc:
            LOG.warning(
                "skill_audit parse failed project=%s intent=%s type=%s error=%s stdout=%s",
                project.project.id, intent.id, intent_type, exc, _preview(result.stdout),
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
    except Exception:
        LOG.exception("skill_audit task crashed project=%s intent=%s worker=%s",
                      project.project.id, intent.id, worker.name)
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    finally:
        lease.stop()


def _assemble_prompt(config, project, intent, intent_type: str) -> str:
    if intent_type == HUNT_INTENT_TYPE:
        seeds = skill_findings.coverage_seeds_from_config(config)
        if not seeds:
            raise ValueError(
                "skill_driven hunt requires audit.skill_driven.coverage_seeds in dispatch.yaml"
            )
        units = []
        for seed in seeds:
            unit = dict(seed)
            unit.setdefault("disposition", "planned")
            units.append(unit)
        skill_dir = vendored_skill_dir()
        blocks: list[str] = []
        seen_classes: set[str] = set()
        for unit in units:
            class_name = str(unit.get("attack_class", ""))
            if class_name and class_name not in seen_classes:
                blocks.append(load_attack_classes_block(class_name, skill_dir))
                seen_classes.add(class_name)
        architecture = next(
            (fact.description for fact in project.facts if fact.type == "recon_snapshot"),
            "No architecture summary fact yet; read the repository layout directly.",
        )
        return assemble_hunter_prompt(
            prompt_group=SKILL_AUDIT_PROMPT_GROUP,
            repo_path="/repo",
            architecture_fact=architecture,
            coverage_units=units,
            attack_class_blocks=blocks,
            excluded_blocks="None — every selected block is in scope for this assignment.",
            peer_coverage_ids="None (single-hunter wave).",
            skill_dir=skill_dir,
        )
    if intent_type == VERIFY_CANDIDATE_INTENT_TYPE:
        fact = _from_fact(project, intent)
        return assemble_simple_prompt(
            prompt_group=SKILL_AUDIT_PROMPT_GROUP, name="verifier.md",
            replacements={
                "candidate_record_json": _record_block(fact),
                "fact_id": fact.id,
                "architecture_fact": "Read the target source directly from the frozen workspace.",
            },
        )
    if intent_type == CRITIC_INTENT_TYPE:
        return assemble_simple_prompt(
            prompt_group=SKILL_AUDIT_PROMPT_GROUP, name="critic.md",
            replacements={
                "coverage_units_json": json.dumps(
                    skill_findings.coverage_units_summary(project), ensure_ascii=False, indent=2),
                "candidates_json": json.dumps(
                    skill_findings.candidates_summary(project), ensure_ascii=False, indent=2),
            },
        )
    fact = _from_fact(project, intent)
    bounce = _bounce_count(intent)
    return assemble_simple_prompt(
        prompt_group=SKILL_AUDIT_PROMPT_GROUP, name="record_verifier.md",
        replacements={
            "record_json": _record_block(fact),
            "fact_id": fact.id,
            "bounce_note": (
                f"This is re-verification round {bounce}: a previous record verifier proposed "
                "a substantive replacement. Judge the corrected record on its own evidence."
                if bounce
                else "This is the first independent verification of this record."
            ),
        },
    )


def _from_fact(project, intent):
    if not intent.from_:
        raise ValueError(f"intent {intent.id} has no from fact")
    fact = next((f for f in project.facts if f.id == intent.from_[0]), None)
    if fact is None:
        raise ValueError(f"intent {intent.id} references missing fact {intent.from_[0]}")
    return fact


def _handle_hunt(client, project, intent, worker, payload, run_id, execute_ms, task_started) -> str:
    kind, data = validate_hunt_payload(payload)
    if kind == "rejected":
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "rejected"
    project_id = project.project.id
    for unit in data["units"]:
        ok = _conclude_fact(
            client, project_id, intent.id, worker.name,
            fact_type="coverage_unit",
            description=f"Coverage unit {unit['coverage_id']} disposition={unit['disposition']}: "
                        + "; ".join(unit.get("reviewed_paths", [])[:4]),
            evidence=json.dumps(unit, ensure_ascii=False),
            semantic_type="coverage_unit",
            proof=_proof(coverage_unit=unit, producer_run_id=run_id),
        )
        if not ok:
            best_effort_release(client, project_id, intent.id, worker.name)
            return "failed"
    for candidate in data["candidates"]:
        record = candidate.get("record") if isinstance(candidate, dict) else None
        if record is None and isinstance(candidate, dict):
            record = {key: value for key, value in candidate.items() if key != "proposed_verdict"}
            record["verdict"] = candidate.get("proposed_verdict", "needs_validation")
        if not isinstance(record, dict):
            LOG.warning("hunt candidate is not an object project=%s intent=%s", project_id, intent.id)
            continue
        record.setdefault("verdict", "needs_validation")
        try:
            skill_findings.parse_finding_record(record)
        except Exception as exc:
            LOG.warning(
                "hunt candidate record invalid project=%s intent=%s error=%s", project_id, intent.id, exc,
            )
            best_effort_release(client, project_id, intent.id, worker.name)
            return "failed"
        ok = _conclude_fact(
            client, project_id, intent.id, worker.name,
            fact_type="candidate_finding",
            description=str(record.get("title") or record.get("description") or "proposed finding")[:300],
            evidence=json.dumps(record, ensure_ascii=False),
            semantic_type="candidate_finding",
            proof=_proof(finding_record=record, producer_run_id=run_id),
        )
        if not ok:
            best_effort_release(client, project_id, intent.id, worker.name)
            return "failed"
    for gap in data["uncovered"]:
        _conclude_fact(
            client, project_id, intent.id, worker.name,
            fact_type="coverage_gap",
            description=f"Uncovered boundary: {gap.get('boundary', '?')} at {gap.get('surface', '?')}",
            evidence=json.dumps(gap, ensure_ascii=False),
            semantic_type="coverage_unit",
            proof=_proof(coverage_gap=gap, producer_run_id=run_id),
        )
    followup_ok = _create_followup(
        client, project_id, [],
        f"Coverage critic wave after hunt run {intent.id}",
        CRITIC_INTENT_TYPE,
    )
    LOG.info(
        "skill_audit hunt finished project=%s intent=%s units=%d candidates=%d execute_ms=%s total_ms=%s critic=%s",
        project_id, intent.id, len(data["units"]), len(data["candidates"]), execute_ms,
        int((time.perf_counter() - task_started) * 1000), followup_ok,
    )
    return "success"


def _handle_verify_candidate(client, project, intent, worker, payload, run_id, execute_ms, task_started) -> str:
    kind, data = validate_skill_verifier_payload(payload)
    if kind == "rejected":
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "rejected"
    record = data["record"]
    semantic = {
        "confirmed": "confirmed_finding",
        "needs_validation": "candidate_finding",
        "rejected": "false_positive",
    }[data["decision"]]
    ok = _conclude_fact(
        client, project.project.id, intent.id, worker.name,
        fact_type="finding_record",
        description=str(record.get("title") or "verified finding")[:300],
        evidence=json.dumps(record, ensure_ascii=False),
        semantic_type=semantic,
        proof=_proof(finding_record=record, producer_run_id=run_id,
                     verifier_rationale=data["rationale"]),
    )
    if not ok:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    _create_followup(
        client, project.project.id,
        [intent.from_[0]] if intent.from_ else [],
        f"Independent record verification for {data['fingerprint']}",
        VERIFY_RECORD_INTENT_TYPE,
    )
    LOG.info("skill_audit verify-candidate finished project=%s intent=%s decision=%s execute_ms=%s",
             project.project.id, intent.id, data["decision"], execute_ms)
    return "success"


def _handle_critic(client, project, intent, worker, payload, execute_ms, task_started) -> str:
    kind, data = validate_critic_payload(payload)
    if kind == "rejected":
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "rejected"
    ok = _conclude_fact(
        client, project.project.id, intent.id, worker.name,
        fact_type="coverage_critic",
        description=data["coverage_statement"][:300],
        evidence=json.dumps(data, ensure_ascii=False),
        semantic_type="coverage_unit",
        proof=_proof(coverage_critic=data),
    )
    if not ok:
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    for unit in data["missing_units"]:
        _create_followup(
            client, project.project.id, [],
            f"Hunt missing coverage unit: surface={unit['surface']} boundary={unit['boundary']} "
            f"subsystem={unit['subsystem']} attack_class={unit['attack_class']} "
            f"starting_paths={unit.get('starting_paths', [])} reason={unit['reason']}",
            HUNT_INTENT_TYPE,
        )
    LOG.info("skill_audit critic finished project=%s intent=%s missing=%d reassign=%d execute_ms=%s",
             project.project.id, intent.id, len(data["missing_units"]),
             len(data["reassignments"]), execute_ms)
    return "success"


def _handle_verify_record(config, client, project, intent, worker, payload, execute_ms, task_started) -> str:
    kind, data = validate_record_verification_payload(payload)
    if kind == "rejected":
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "rejected"
    fact = _from_fact(project, intent)
    original = _attr(fact, "finding_record")
    if data["decision"] == "verified":
        _conclude_fact(
            client, project.project.id, intent.id, worker.name,
            fact_type="finding_verified",
            description=f"Record {data['fingerprint']} independently verified.",
            evidence=json.dumps(data, ensure_ascii=False),
            semantic_type=str((original or {}).get("verdict", "confirmed")) + "_final",
            proof=_proof(verification=data),
        )
        LOG.info("skill_audit record verified project=%s intent=%s fingerprint=%s execute_ms=%s",
                 project.project.id, intent.id, data["fingerprint"], execute_ms)
        return "success"
    # replace path: bounce unless the replacement is immaterial or the budget is exhausted
    bounce = _bounce_count(intent) + 1
    max_bounces = skill_findings.max_bounces(config)
    substantive = skill_findings.is_substantive_replacement(original, data["record"])
    if substantive and bounce <= max_bounces:
        _create_followup(
            client, project.project.id,
            [intent.from_[0]] if intent.from_ else [],
            f"Independent record verification for {data['fingerprint']} |bounce:{bounce}",
            VERIFY_RECORD_INTENT_TYPE,
        )
        LOG.info("skill_audit record replacement bounced project=%s intent=%s bounce=%d/%d",
                 project.project.id, intent.id, bounce, max_bounces)
        return "success"
    if substantive:
        LOG.warning(
            "skill_audit record dropped after bounce budget project=%s intent=%s fingerprint=%s",
            project.project.id, intent.id, data["fingerprint"],
        )
        _conclude_fact(
            client, project.project.id, intent.id, worker.name,
            fact_type="finding_dropped",
            description=f"Record {data['fingerprint']} dropped: verification did not converge "
                        f"after {max_bounces} replacement rounds.",
            evidence=json.dumps(data, ensure_ascii=False),
            semantic_type="observation",
            proof=_proof(dropped_record=data["record"], reason=data["reason"]),
        )
        return "success"
    _conclude_fact(
        client, project.project.id, intent.id, worker.name,
        fact_type="finding_verified",
        description=f"Record {data['fingerprint']} verified with immaterial corrections.",
        evidence=json.dumps(data, ensure_ascii=False),
        semantic_type=str(data["record"].get("verdict", "needs_validation")) + "_final",
        proof=_proof(verification=data),
    )
    return "success"
