from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import hashlib
import html
import json
import yaml

from linen.server.audit_state import (
    completion_gate_from_db,
    list_audit_events,
    list_audit_stages,
    list_graph_edges,
    list_human_decisions,
    list_skill_runs,
)
from linen.server.db import get_conn
from linen.server.services import (
    expire_reason_leases,
    expire_workers,
    get_project_or_404,
    list_intent_errors,
    list_reviews_for_project,
)

router = APIRouter(tags=["export"])


def format_export_timestamp(value: str | None) -> str | None:
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _load_project_data(conn, project_id: str):
    expire_workers(conn, project_id)
    expire_reason_leases(conn, project_id)
    proj = get_project_or_404(conn, project_id)

    facts = conn.execute(
        "SELECT id, description, display_title, type, semantic_type, evidence, status, "
        "source_generation, legacy FROM facts WHERE project_id = ?",
        (project_id,),
    ).fetchall()
    hints = conn.execute(
        "SELECT content, creator, created_at FROM hints WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    intents = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()

    sources_by_intent = {}
    for i in intents:
        rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (i["id"], project_id),
        ).fetchall()
        sources_by_intent[i["id"]] = [r["fact_id"] for r in rows]

    return proj, facts, hints, intents, sources_by_intent


def _export_yaml(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)

    origin_desc = ""
    goal_desc = ""
    for f in facts:
        if f["id"] == "origin":
            origin_desc = f["description"]
        elif f["id"] == "goal":
            goal_desc = f["description"]

    data: dict = {
        "project": {
            "id": proj["id"],
            "title": proj["title"],
            "status": proj["status"],
            "graph_revision": proj["graph_revision"],
            "source_generation": proj["source_generation"],
            "plan_revision": proj["plan_revision"],
            "origin": origin_desc,
            "goal": goal_desc,
            "bootstrap_enabled": bool(proj["bootstrap_enabled"]),
            "audit_mode": proj["audit_mode"] if "audit_mode" in proj.keys() else "none",
        }
    }

    if hints:
        data["hints"] = [
            {
                "content": h["content"],
                "creator": h["creator"],
                "created_at": format_export_timestamp(h["created_at"]),
            }
            for h in hints
        ]

    data["facts"] = [
        {
            "id": f["id"],
            "display_title": f["display_title"],
            "description": f["description"],
            "status": f["status"],
            "semantic_type": f["semantic_type"],
            "source_generation": f["source_generation"],
            "legacy": bool(f["legacy"]),
            **({"type": f["type"]} if f["type"] else {}),
            **({"evidence": f["evidence"]} if f["evidence"] else {}),
        }
        for f in facts
    ]

    intent_list = []
    cancelled_intent_ids = []
    for i in intents:
        if (i["type"] or "").startswith("cancelled:") and not i["to_fact_id"]:
            cancelled_intent_ids.append(i["id"])
            continue
        entry: dict = {
            "id": i["id"],
            "from": sources_by_intent.get(i["id"], []),
            "to": i["to_fact_id"],
            "description": i["description"],
            "display_title": i["display_title"],
            "semantic_type": i["semantic_type"],
            "relation_type": i["relation_type"] or "unclassified",
            "phase": i["phase"],
            "source_generation": i["source_generation"],
            "plan_revision": i["plan_revision"],
            "legacy": bool(i["legacy"]),
            "creator": i["creator"],
            "worker": i["worker"],
            "created_at": format_export_timestamp(i["created_at"]),
            "concluded_at": format_export_timestamp(i["concluded_at"]),
        }
        if i["type"]:
            entry["type"] = i["type"]
        intent_list.append(entry)

    if intent_list:
        data["intents"] = intent_list
    if cancelled_intent_ids:
        data["cancelled_intents"] = {
            "count": len(cancelled_intent_ids),
            "ids": cancelled_intent_ids,
            "reason": "coverage queue compaction",
        }

    reviews = list_reviews_for_project(conn, project_id)
    if reviews:
        data["reviews"] = [review.model_dump(exclude_none=True) for review in reviews]

    errors = list_intent_errors(conn, project_id)
    if errors:
        data["intent_errors"] = [
            {
                **error.model_dump(exclude_none=True),
                "first_failed_at": format_export_timestamp(error.first_failed_at),
                "last_failed_at": format_export_timestamp(error.last_failed_at),
                **(
                    {"retry_at": format_export_timestamp(error.retry_at)}
                    if error.retry_at else {}
                ),
                **(
                    {"resolved_at": format_export_timestamp(error.resolved_at)}
                    if error.resolved_at else {}
                ),
            }
            for error in errors
        ]

    data["graph_edges"] = [
        edge.model_dump(exclude_none=True) for edge in list_graph_edges(conn, project_id)
    ]
    data["audit_stages"] = [
        stage.model_dump(exclude_none=True) for stage in list_audit_stages(conn, project_id)
    ]
    data["skill_runs"] = [
        run.model_dump(exclude_none=True) for run in list_skill_runs(conn, project_id)
    ]
    data["human_decisions"] = [
        decision.model_dump(exclude_none=True)
        for decision in list_human_decisions(conn, project_id)
    ]
    data["completion_gate"] = completion_gate_from_db(
        conn, project_id
    ).model_dump(exclude_none=True)
    data["audit_events"] = [
        event.model_dump(exclude_none=True)
        for event in list_audit_events(conn, project_id, limit=5000)
    ]

    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _export_json(conn, project_id: str) -> str:
    """Return the full YAML snapshot contract as deterministic JSON."""
    data = yaml.safe_load(_export_yaml(conn, project_id))
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _export_sarif(conn, project_id: str) -> str:
    """Export candidate and confirmed security findings as SARIF 2.1.0."""
    proj, facts, _hints, _intents, _sources = _load_project_data(conn, project_id)
    finding_facts = [
        fact
        for fact in facts
        if fact["type"] == "vulnerability"
        or fact["semantic_type"] in {"candidate_finding", "confirmed_finding"}
    ]
    rules = []
    results = []
    for fact in finding_facts:
        rule_id = f"LINEN-{fact['id']}"
        title = fact["display_title"] or fact["description"].splitlines()[0][:120]
        rules.append(
            {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "properties": {
                    "semanticType": fact["semantic_type"],
                    "linenFactId": fact["id"],
                },
            }
        )
        result: dict = {
            "ruleId": rule_id,
            "level": "error" if fact["semantic_type"] == "confirmed_finding" else "warning",
            "message": {"text": fact["description"]},
            "partialFingerprints": {
                "linen/v1": hashlib.sha256(
                    f"{project_id}\0{fact['id']}\0{fact['description']}".encode()
                ).hexdigest()
            },
            "properties": {
                "linenProjectId": project_id,
                "linenFactId": fact["id"],
                "status": fact["status"],
                "semanticType": fact["semantic_type"],
                "sourceGeneration": fact["source_generation"],
            },
        }
        if fact["status"] in {"false_positive", "accepted_risk"}:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f"linen status: {fact['status']}",
                }
            ]
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "linen",
                        "semanticVersion": "1.0.0",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"{proj['id']}/generation/{proj['source_generation']}"},
                "results": results,
                "properties": {
                    "projectTitle": proj["title"],
                    "graphRevision": proj["graph_revision"],
                    "planRevision": proj["plan_revision"],
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _export_timeline(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)

    facts_by_id = {f["id"]: f["description"] for f in facts}

    events: list[tuple[str, int, str]] = []  # (timestamp, order, text)
    order = 0

    origin_desc = facts_by_id.get("origin", "")
    goal_desc = facts_by_id.get("goal", "")
    ts = format_export_timestamp(proj["created_at"]) or ""
    block = f"[{ts}] PROJECT CREATED\n  origin: {origin_desc}\n  goal: {goal_desc}"
    events.append((proj["created_at"] or "", order, block))
    order += 1

    for h in hints:
        ts = format_export_timestamp(h["created_at"]) or ""
        block = f"[{ts}] HINT by {h['creator']}\n  {h['content']}"
        events.append((h["created_at"] or "", order, block))
        order += 1

    for error in list_intent_errors(conn, project_id):
        ts = format_export_timestamp(error.last_failed_at) or ""
        state = "BLOCKED" if error.classification == "blocked" else "RETRY DEFERRED"
        block = (
            f"[{ts}] INTENT {state} {error.intent_id} [{error.code}]\n"
            f"  task: {error.task_type}; worker: {error.worker or 'unknown'}; "
            f"attempts: {error.attempt_count}\n"
            f"  {error.message}"
        )
        if error.retry_at:
            block += f"\n  retry at: {format_export_timestamp(error.retry_at)}"
        if error.remediation:
            block += f"\n  remediation: {error.remediation}"
        events.append((error.last_failed_at, order, block))
        order += 1
        if error.resolved_at:
            resolved_ts = format_export_timestamp(error.resolved_at) or ""
            events.append((
                error.resolved_at,
                order,
                f"[{resolved_ts}] INTENT ERROR RESOLVED {error.intent_id}\n"
                f"  {error.resolution or 'resolved'}",
            ))
            order += 1

    for i in intents:
        src = sources_by_intent.get(i["id"], [])
        from_str = ", ".join(src)

        ts = format_export_timestamp(i["created_at"]) or ""
        meta = f"  from: {from_str}"
        if i["worker"] and not i["concluded_at"]:
            meta += f"\n  worker: {i['worker']} (in progress)"
        block = f"[{ts}] INTENT DECLARED {i['id']} by {i['creator']}\n{meta}\n  {i['description']}"
        events.append((i["created_at"] or "", order, block))
        order += 1

        if (i["type"] or "").startswith("cancelled:") and i["concluded_at"]:
            ts = format_export_timestamp(i["concluded_at"]) or ""
            block = (
                f"[{ts}] INTENT RETIRED {i['id']} by dispatcher.compaction\n"
                f"  from: {from_str}\n  {i['description']}"
            )
            events.append((i["concluded_at"] or "", order, block))
            order += 1
            continue
        if not i["concluded_at"] or not i["to_fact_id"]:
            continue

        ts = format_export_timestamp(i["concluded_at"]) or ""
        actor = i["worker"] or i["creator"]

        if i["to_fact_id"] == "goal":
            block = f"[{ts}] PROJECT COMPLETED by {actor}\n  via: {i['id']} from {from_str}"
        else:
            fact_desc = facts_by_id.get(i["to_fact_id"], "")
            block = f"[{ts}] INTENT CONCLUDED {i['id']} by {actor}\n  from: {from_str}\n  produced: {i['to_fact_id']}\n  {fact_desc}"

        events.append((i["concluded_at"] or "", order, block))
        order += 1

    events.sort(key=lambda e: (e[0], e[1]))

    return "\n\n".join(e[2] for e in events) + "\n"


def _markdown_text(value: object | None) -> str:
    """Render untrusted board text safely inside a Markdown paragraph."""
    if value is None:
        return "—"
    return html.escape(str(value), quote=False).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _markdown_table_cell(value: object | None) -> str:
    return _markdown_text(value).replace("|", "\\|")


def _markdown_code_block(value: str) -> str:
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(f"    {line}" if line else "    " for line in lines)


def _export_report(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent = _load_project_data(conn, project_id)
    reviews = list_reviews_for_project(conn, project_id)
    intent_errors = list_intent_errors(conn, project_id)
    open_errors = [error for error in intent_errors if error.resolved_at is None]
    facts_by_id = {fact["id"]: fact for fact in facts}
    reviews_by_fact: dict[str, list] = {}
    for review in reviews:
        reviews_by_fact.setdefault(review.fact_id, []).append(review)

    origin = facts_by_id.get("origin")
    goal = facts_by_id.get("goal")
    completion_intent = next(
        (
            intent
            for intent in reversed(intents)
            if intent["to_fact_id"] == "goal" and intent["concluded_at"]
        ),
        None,
    )
    completion_sources = sources_by_intent.get(completion_intent["id"], []) if completion_intent else []
    domain_facts = [fact for fact in facts if fact["id"] not in {"origin", "goal"}]
    vulnerability_facts = [fact for fact in domain_facts if fact["type"] == "vulnerability"]
    negative_assurance_facts = [
        fact for fact in domain_facts
        if fact["type"] == "negative_assurance" or fact["semantic_type"] == "negative_assurance"
    ]
    audit_summaries = [fact for fact in domain_facts if fact["type"] == "audit_summary"]
    scope_gate_facts = [
        fact for fact in domain_facts
        if fact["type"] in {"policy_evidence", "scope_adjudication"}
    ]
    open_intents = [intent for intent in intents if not intent["concluded_at"]]
    reviewed_fact_ids = {review.fact_id for review in reviews}
    strong_valid_reviews = [
        review
        for review in reviews
        if review.verdict == "VALID" and review.confidence in {"firm", "certain"}
    ]

    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    audit_mode = proj["audit_mode"] if "audit_mode" in proj.keys() else "none"
    status_label = {
        "completed": "Completed",
        "active": "In progress",
        "stopped": "Stopped",
    }.get(proj["status"], proj["status"])

    lines = [
        f"# {_markdown_text(proj['title'])} — Final Result Report",
        "",
        f"> Generated from the linen blackboard on {generated_at}. Graph revision `{proj['graph_revision']}`.",
        "",
        "## Executive result",
        "",
        f"**{status_label}.** "
        + (
            _markdown_text(completion_intent["description"])
            if completion_intent
            else "This is a point-in-time report; the blackboard has no current completion decision."
        ),
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Project | `{_markdown_table_cell(proj['id'])}` |",
        f"| Lifecycle | {_markdown_table_cell(proj['status'])} |",
        f"| Audit mode | {_markdown_table_cell(audit_mode)} |",
        f"| Created | {_markdown_table_cell(format_export_timestamp(proj['created_at']))} |",
        f"| Goal | {_markdown_table_cell(goal['description'] if goal else '')} |",
        f"| Facts | {len(domain_facts)} result facts |",
        f"| Intents | {len(intents) - len(open_intents)} concluded / {len(open_intents)} open |",
        f"| Reviews | {len(reviews)} total / {len(strong_valid_reviews)} firm-or-certain VALID |",
        f"| Task errors | {len(open_errors)} unresolved / {len(intent_errors)} recorded |",
        "",
    ]

    if open_errors:
        lines.extend(["## Operational blockers", ""])
        for error in open_errors:
            retry = (
                f"; retry scheduled {_markdown_text(format_export_timestamp(error.retry_at))}"
                if error.retry_at else ""
            )
            lines.extend(
                [
                    f"### `{_markdown_text(error.intent_id)}` · `{_markdown_text(error.code)}`",
                    "",
                    f"**{_markdown_text(error.classification)}**, "
                    f"{error.attempt_count} attempt(s){retry}.",
                    "",
                    _markdown_text(error.message),
                    "",
                ]
            )
            if error.remediation:
                lines.extend(
                    ["**Recovery:** " + _markdown_text(error.remediation), ""]
                )

    if completion_sources:
        lines.extend(["### Completion basis", ""])
        for fact_id in completion_sources:
            fact = facts_by_id.get(fact_id)
            if fact:
                lines.append(
                    f"- `{_markdown_text(fact_id)}` · {_markdown_text(fact['type'] or 'fact')} · "
                    f"{_markdown_text(fact['status'])} — {_markdown_text(fact['description'])}"
                )
        lines.append("")

    if scope_gate_facts:
        lines.extend(
            [
                "## Scope adjudication gate",
                "",
                "Policy eligibility and technical exploitability are recorded as separate axes. "
                "An exclusion here does not make a technically reachable issue a false positive.",
                "",
            ]
        )
        for fact in scope_gate_facts:
            fact_reviews = reviews_by_fact.get(fact["id"], [])
            lines.extend(
                [
                    f"### `{_markdown_text(fact['id'])}` · {_markdown_text(fact['type'])}",
                    "",
                    _markdown_text(fact["description"]),
                    "",
                    f"**Lifecycle:** {_markdown_text(fact['status'])}; "
                    f"**Reviews:** {len(fact_reviews)}",
                    "",
                ]
            )
            if fact["evidence"]:
                lines.extend(["Evidence record:", "", _markdown_code_block(fact["evidence"]), ""])

    if audit_summaries:
        lines.extend(["## Audit summary", ""])
        for fact in audit_summaries:
            lines.extend(
                [
                    f"### `{_markdown_text(fact['id'])}`",
                    "",
                    _markdown_text(fact["description"]),
                    "",
                ]
            )

    lines.extend(["## Security findings", ""])
    if not vulnerability_facts:
        lines.extend(
            [
                "No `type=vulnerability` facts are currently recorded. This does not by itself prove the absence of vulnerabilities.",
                "",
            ]
        )
    else:
        for index, fact in enumerate(vulnerability_facts, 1):
            fact_reviews = reviews_by_fact.get(fact["id"], [])
            lines.extend(
                [
                    f"### Finding {index}: `{_markdown_text(fact['id'])}`",
                    "",
                    f"**Status:** {_markdown_text(fact['status'])}",
                    "",
                    _markdown_text(fact["description"]),
                    "",
                    "#### Independent review",
                    "",
                ]
            )
            if fact_reviews:
                for review in fact_reviews:
                    reviewer = review.created_by or "unknown"
                    confidence = review.confidence or "unspecified"
                    lines.append(
                        f"- **{_markdown_text(review.verdict)} / {_markdown_text(confidence)}** "
                        f"by {_markdown_text(reviewer)} — {_markdown_text(review.summary)}"
                    )
            else:
                lines.append("- No independent review is attached to this finding.")
            lines.append("")
            if fact["evidence"]:
                lines.extend(
                    [
                        "#### Evidence",
                        "",
                        _markdown_code_block(fact["evidence"]),
                        "",
                    ]
                )

    if negative_assurance_facts:
        lines.extend(["## Negative assurance", ""])
        lines.append(
            "The following reviewed records describe bounded checks that found no qualifying issue; "
            "they do not prove absence outside the declared scope."
        )
        lines.append("")
        for fact in negative_assurance_facts:
            lines.extend([
                f"- `{_markdown_text(fact['id'])}` · {_markdown_text(fact['status'])} — "
                f"{_markdown_text(fact['description'])}",
            ])
            if fact["evidence"]:
                lines.extend(["", _markdown_code_block(fact["evidence"])])
        lines.append("")

    lines.extend(["## Review assurance", ""])
    lines.append(
        f"{len(reviewed_fact_ids)} of {len(domain_facts)} result facts have at least one Review. "
        f"The report contains {len(strong_valid_reviews)} firm-or-certain VALID review(s)."
    )
    lines.append("")
    if reviews:
        lines.extend(
            [
                "| Fact | Verdict | Confidence | Reviewer | Summary |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for review in reviews:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_table_cell(review.fact_id)}`",
                        _markdown_table_cell(review.verdict),
                        _markdown_table_cell(review.confidence),
                        _markdown_table_cell(review.created_by),
                        _markdown_table_cell(review.summary),
                    ]
                )
                + " |"
            )
        lines.append("")

    lines.extend(["## Remaining work", ""])
    if open_intents:
        for intent in open_intents:
            sources = ", ".join(sources_by_intent.get(intent["id"], [])) or "—"
            lines.append(
                f"- `{_markdown_text(intent['id'])}` from `{_markdown_text(sources)}` "
                f"({ _markdown_text(intent['type'] or 'general') }) — {_markdown_text(intent['description'])}"
            )
    else:
        lines.append("No open intents remain.")
    lines.append("")

    lines.extend(["## Evidence trail", ""])
    if domain_facts:
        for fact in domain_facts:
            review_count = len(reviews_by_fact.get(fact["id"], []))
            lines.append(
                f"- `{_markdown_text(fact['id'])}` · {_markdown_text(fact['type'] or 'fact')} · "
                f"{_markdown_text(fact['status'])} · {review_count} review(s) — {_markdown_text(fact['description'])}"
            )
    else:
        lines.append("No result facts have been written yet.")

    if hints:
        lines.extend(["", "## Operator notes", ""])
        for hint in hints:
            lines.append(
                f"- {_markdown_text(hint['content'])} — {_markdown_text(hint['creator'])}, "
                f"{_markdown_text(format_export_timestamp(hint['created_at']))}"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "This report summarizes recorded blackboard evidence and reviews. It does not independently re-execute the target or prove that unexamined vulnerability classes are absent.",
            "",
        ]
    )
    return "\n".join(lines)


@router.get("/projects/{project_id}/export")
def export_project(project_id: str, format: str = "yaml"):
    if format not in ("yaml", "timeline", "report", "json", "sarif"):
        raise HTTPException(400, "Supported formats: yaml, timeline, report, json, sarif")

    with get_conn() as conn:
        if format == "report":
            project = get_project_or_404(conn, project_id)
            snapshot = None
            if project["status"] == "completed":
                # Completion stores an immutable report for the exact graph
                # revision.  Hints remain writable after completion, so
                # regenerating here would make the advertised final report
                # drift from the committed artifact.
                snapshot = conn.execute(
                    "SELECT content, sha256 FROM report_snapshots "
                    "WHERE project_id = ? AND source_generation = ? "
                    "AND plan_revision = ? AND format = 'report' "
                    "ORDER BY created_at DESC, id DESC LIMIT 1",
                    (
                        project_id,
                        project["source_generation"],
                        project["plan_revision"],
                    ),
                ).fetchone()
            text = snapshot["content"] if snapshot is not None else _export_report(conn, project_id)
            media_type = "text/markdown"
        elif format == "timeline":
            text = _export_timeline(conn, project_id)
            media_type = "text/plain"
        elif format == "json":
            text = _export_json(conn, project_id)
            media_type = "application/json"
        elif format == "sarif":
            text = _export_sarif(conn, project_id)
            media_type = "application/sarif+json"
        else:
            text = _export_yaml(conn, project_id)
            media_type = "application/yaml"

        response = Response(content=text, media_type=media_type)
        if format == "report" and snapshot is not None:
            response.headers["ETag"] = f'"{snapshot["sha256"]}"'
            response.headers["X-Linen-Report-Snapshot"] = snapshot["sha256"]
        return response
