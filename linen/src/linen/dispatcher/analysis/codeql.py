"""Isolated CodeQL path-candidate collection over a frozen Recon snapshot."""
from __future__ import annotations

import json
import fcntl
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import time
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from linen.dispatcher.analysis.artifacts import (
    canonical_source_citations,
    digest,
    load_artifact,
    source_bytes,
    write_json,
)
from linen.dispatcher.analysis import recon
from linen.dispatcher.config import CodeQLConfig
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.runtime.review_sandbox import ReviewSandboxBackend
from linen.server.models import Fact, Intent, ProjectDetail


INTENT = "@analysis:codeql-path-candidates"
QUERY_PREFIX = "@analysis:codeql-query:"
_BEGIN = "===LINEN_CODEQL_BEGIN:{}==="
_END = "===LINEN_CODEQL_END:{}==="
_SYMBOL = re.compile(r"[^\s\x00-\x1f]{1,300}")


class CodeQLRunError(RuntimeError):
    """CodeQL could not produce a complete, bounded SARIF result set."""


def is_intent(intent: Intent) -> bool:
    description = intent.description.strip()
    return intent.type == "search" and (
        description == INTENT or query_category(description) is not None
    )


def query_category(description: str) -> str | None:
    value = description.strip()
    if not value.startswith(QUERY_PREFIX):
        return None
    category = value.removeprefix(QUERY_PREFIX)
    return category if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", category) else None


def validate_query_intent(
    project: ProjectDetail, config: CodeQLConfig, intent_data: dict[str, Any],
) -> str:
    description = intent_data.get("description")
    category = query_category(description) if isinstance(description, str) else None
    if intent_data.get("type") != "search" or intent_data.get("action") != "search":
        raise ValueError("CodeQL query profile must be a search Intent")
    if not config.enabled or category not in config.query_profiles:
        raise ValueError("CodeQL query category is not enabled in query_profiles")
    if not active_for_project(project, config):
        raise ValueError("CodeQL query profiles are not active for this audit")
    source_ids = intent_data.get("from")
    snapshot = recon.snapshot_fact(project)
    scan = latest_fact(project)
    if (
        not isinstance(source_ids, list) or snapshot is None or scan is None
        or snapshot.id not in source_ids or scan.id not in source_ids
    ):
        raise ValueError("CodeQL query Intent must descend from the frozen snapshot and initial scan")
    prior = [
        query_category(item.description) == category
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
        for item in project.intents
    ]
    attempts = sum(prior)
    if attempts >= config.max_query_attempts_per_profile:
        raise ValueError(f"CodeQL query profile {category} reached its attempt limit")
    expected_target = f"codeql-query:{category}:attempt:{attempts + 1}"
    if intent_data.get("target") != expected_target:
        raise ValueError("CodeQL query Intent target must use the next bounded attempt number")
    if any(
        query_category(item.description) == category
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
        and item.to is None and item.concluded_at is None
        for item in project.intents
    ):
        raise ValueError(f"CodeQL query profile {category} is already queued or running")
    return category


def active_for_project(project: ProjectDetail, config: CodeQLConfig) -> bool:
    """Honor the audit-stage set frozen when this plan began."""
    if not config.enabled:
        return False
    if not project.stages:
        return True
    return any(
        stage.stage_id == "codeql-candidates" and stage.required
        for stage in project.stages
    )


def latest_fact(project: ProjectDetail) -> Fact | None:
    attempts = sorted(
        (
            item for item in project.intents
            if item.description.strip() == INTENT
            and item.source_generation == project.project.source_generation
            and item.plan_revision == project.project.plan_revision
        ),
        key=lambda item: (item.created_at, item.id),
    )
    if not attempts or not attempts[-1].to:
        return None
    return next((fact for fact in project.facts if fact.id == attempts[-1].to), None)


def query_results(project: ProjectDetail) -> list[tuple[str, Fact]]:
    """Return successful or failed category-query result Facts in plan order."""
    rows = []
    intents = sorted(project.intents, key=lambda item: (item.created_at, item.id))
    for intent in intents:
        category = query_category(intent.description)
        if (
            category is None or intent.source_generation != project.project.source_generation
            or intent.plan_revision != project.project.plan_revision or not intent.to
        ):
            continue
        fact = next((item for item in project.facts if item.id == intent.to), None)
        if fact is not None:
            rows.append((category, fact))
    return rows


def result_record(fact: Fact, workdir: Path) -> dict[str, Any]:
    _, record = load_artifact(fact, workdir)
    if record.get("kind") != "codeql_path_candidates":
        raise ValueError("Unexpected CodeQL artifact kind")
    return record


def _owned_directory(workdir: Path, *parts: str) -> Path:
    """Create a dispatcher directory without following repository symlinks."""
    current = workdir.resolve()
    for part in parts:
        if part in {"", ".", ".."} or "/" in part or "\\" in part:
            raise CodeQLRunError("Invalid dispatcher-owned directory component")
        candidate = current / part
        if candidate.is_symlink():
            raise CodeQLRunError(f"Refusing symlink in CodeQL work path: {candidate}")
        candidate.mkdir(exist_ok=True, mode=0o700)
        if not candidate.is_dir() or candidate.resolve().parent != current:
            raise CodeQLRunError(f"CodeQL work path escaped its dispatcher root: {candidate}")
        current = candidate
    return current


@contextmanager
def _database_lock(
    lock_path: Path, timeout: int, cancellation: TaskCancellation, lease: HeartbeatLease,
):
    """Serialize query processes sharing a prepared CodeQL database."""
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancellation.is_cancelled or lease.failure is not None:
                raise CodeQLRunError("CodeQL query was cancelled while waiting for the database lock")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CodeQLRunError("Timed out waiting for the frozen-snapshot CodeQL database lock")
                time.sleep(0.2)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _shell_command(
    config: CodeQLConfig, category: str | None = None,
) -> list[str]:
    cli = shlex.quote(config.cli_path)
    threads = str(config.threads)
    max_bytes = str(config.max_sarif_bytes)
    chunks = ["set -eu", "mkdir -p /cache/db /work/home /work/results"]
    profile = config.query_profiles.get(category, {}) if category else {}
    languages = [
        language for language in config.languages
        if category is None or language in profile
    ]
    for language in languages:
        queries = profile.get(language, []) if category else config.query_suites.get(language, [])
        db = f"/cache/db/{language}"
        ready = f"{db}/.linen-ready-v1"
        sarif = f"/work/results/{language}.sarif"
        chunks.extend([
            f"if [ ! -f {shlex.quote(ready)} ] || "
            f"[ ! -f {shlex.quote(db + '/codeql-database.yml')} ]; then "
            f"rm -rf -- {shlex.quote(db)}; "
            f"{cli} database create --language={shlex.quote(language)} "
            f"--build-mode=none --source-root=/repo --threads={threads} -- {shlex.quote(db)} >&2; "
            f"printf 'ready\\n' > {shlex.quote(ready)}; "
            "fi",
            f"{cli} database analyze {shlex.quote(db)} --format=sarifv2.1.0 "
            f"--output={shlex.quote(sarif)} --max-paths=12 "
            "--no-sarif-add-file-contents --no-sarif-add-snippets --no-download "
            + " ".join(shlex.quote(query) for query in queries) + " >&2",
            f"size=$(wc -c < {shlex.quote(sarif)})",
            f"[ \"$size\" -le {max_bytes} ] || {{ echo 'CodeQL SARIF limit exceeded' >&2; exit 73; }}",
            f"printf '\\n{_BEGIN.format(language)}\\n'",
            f"cat {shlex.quote(sarif)}",
            f"printf '\\n{_END.format(language)}\\n'",
        ])
    return ["/bin/sh", "-c", "\n".join(chunks)]


def _execute(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CodeQLConfig,
    cancellation: TaskCancellation,
    lease: HeartbeatLease,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    snapshot_fact, source, snapshot_record = recon._snapshot_context(project, workdir, intent)
    if not config.enabled:
        raise CodeQLRunError("CodeQL candidate generation is disabled")
    category = query_category(intent.description)
    if category is not None and category not in config.query_profiles:
        raise CodeQLRunError(f"CodeQL query profile {category} is not configured")
    languages = (
        [language for language in config.languages if language in config.query_profiles[category]]
        if category is not None else list(config.languages)
    )
    if not languages:
        raise CodeQLRunError(f"CodeQL query profile {category} has no configured languages")
    image_id = _inspect_image(config)
    cache_key = digest(json.dumps({
        "snapshot": snapshot_record["snapshot"]["id"],
        "image_id": image_id,
        "cli_path": config.cli_path,
        "languages": config.languages,
    }, sort_keys=True).encode())
    cache_root = _owned_directory(workdir, ".linen-codeql", "cache", cache_key)
    run_root = _owned_directory(workdir, ".linen-codeql", "runtime")
    lock_root = _owned_directory(workdir, ".linen-codeql", "locks")
    started = time.perf_counter()
    monitoring_done = threading.Event()
    work_limit_exceeded = threading.Event()
    monitor_thread = None
    with _database_lock(
        lock_root / f"{cache_key}.lock", config.timeout, cancellation, lease,
    ):
        sandbox = ReviewSandboxBackend(
            config,
            source,
            snapshot_record["snapshot"],
            run_root,
            writable_workdir=True,
            persistent_workdir=cache_root,
        )
        process = sandbox.build_exec_process(
            "",
            {},
            _shell_command(config, category),
            timeout_seconds=config.timeout,
        )
        try:
            if cancellation.is_cancelled or lease.failure is not None:
                raise CodeQLRunError("CodeQL execution was cancelled before container start")
            process.start()
            cancellation.attach_process(process)
            lease.attach_process(process)
            process_run_dir = sandbox.last_process.run_dir if sandbox.last_process else None
            if process_run_dir is not None:
                monitor_thread = threading.Thread(
                    target=_monitor_workdir,
                    args=(process, process_run_dir / "work", cache_root, config.max_work_bytes,
                          monitoring_done, work_limit_exceeded),
                    daemon=True,
                )
                monitor_thread.start()
            result = process.communicate(config.timeout)
        except Exception as exc:
            raise CodeQLRunError(f"Isolated CodeQL execution failed: {type(exc).__name__}: {exc}") from exc
        finally:
            monitoring_done.set()
            if monitor_thread is not None:
                monitor_thread.join(timeout=1)
            cancellation.attach_process(None)
            lease.attach_process(None)
            if sandbox.last_process is not None:
                shutil.rmtree(sandbox.last_process.run_dir, ignore_errors=True)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if result.timed_out:
        raise CodeQLRunError(f"Isolated CodeQL analysis timed out after {config.timeout}s")
    if work_limit_exceeded.is_set():
        raise CodeQLRunError(
            f"CodeQL working data exceeded max_work_bytes={config.max_work_bytes}"
        )
    if result.cancelled:
        raise CodeQLRunError("Isolated CodeQL process was cancelled")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()[-4000:]
        raise CodeQLRunError(f"Isolated CodeQL analysis failed: {detail}")
    if len(result.stdout.encode("utf-8", errors="replace")) > config.max_sarif_bytes * len(config.languages) + 4096:
        raise CodeQLRunError("CodeQL output exceeded the configured aggregate size limit")
    sarif_by_language = _parse_outputs(result.stdout, languages)
    leads: list[dict[str, Any]] = []
    citations: list[dict[str, Any]] = []
    gaps: list[str] = []
    source_manifest = snapshot_record["snapshot"]
    seen: set[str] = set()
    for language, sarif in sarif_by_language.items():
        for run in sarif["runs"]:
            if not isinstance(run, dict):
                raise CodeQLRunError(f"CodeQL SARIF for {language} contains an invalid run")
            for result_item in run.get("results", []):
                if not isinstance(result_item, dict):
                    gaps.append(f"{language}: skipped a malformed SARIF result")
                    continue
                rule_id = str(result_item.get("ruleId") or "unknown-rule")[:200]
                fingerprints = result_item.get("partialFingerprints") or {}
                primary = (
                    fingerprints.get("primaryLocationLineHash")
                    if isinstance(fingerprints, dict) else None
                )
                result_id = str(primary or result_item.get("guid") or "result")[:200]
                source_ref = f"{rule_id}/{result_id}"
                message_obj = result_item.get("message") or {}
                message = str(message_obj.get("text") or message_obj.get("markdown") or rule_id)
                message = " ".join(message.split())[:1200]
                code_flows = result_item.get("codeFlows", [])
                if not code_flows:
                    gaps.append(f"{language} {source_ref}: SARIF result had no interprocedural path")
                for code_flow in code_flows:
                    for thread_flow in code_flow.get("threadFlows", []):
                        raw_steps = thread_flow.get("locations", [])
                        if len(raw_steps) < 2:
                            continue
                        if len(raw_steps) > 100:
                            gaps.append(f"{language} {source_ref}: a path exceeded the 100-hop evidence limit")
                        normalized_steps = []
                        for raw_step in raw_steps[:100]:
                            location = raw_step.get("location", {})
                            resolved = _location(location, run)
                            if resolved is None:
                                normalized_steps = []
                                gaps.append(f"{language} {source_ref}: path contains a location outside the frozen source")
                                break
                            filename, line, symbol = resolved
                            if filename not in source_manifest["files"]:
                                normalized_steps = []
                                gaps.append(f"{language} {source_ref}: path references a file absent from the frozen snapshot")
                                break
                            try:
                                content = source_bytes(source, filename, source_manifest["files"][filename])
                                lines = content.decode("utf-8").splitlines()
                                excerpt = lines[line - 1]
                            except (OSError, UnicodeDecodeError, ValueError, IndexError):
                                normalized_steps = []
                                gaps.append(f"{language} {source_ref}: location could not be cited as frozen text")
                                break
                            if len(excerpt) > 8000:
                                normalized_steps = []
                                gaps.append(f"{language} {source_ref}: a source line exceeded the citation limit")
                                break
                            citation_id = f"c{len(citations) + 1}"
                            citations.append({
                                "id": citation_id, "file": filename, "line": line,
                                "code": excerpt,
                            })
                            normalized_steps.append({
                                "file": filename, "line": line, "symbol": symbol,
                                "citation_id": citation_id,
                            })
                        if len(normalized_steps) < 2:
                            continue
                        path = [
                            f"{step['file']}:{step['line']} {step['symbol']}"
                            for step in normalized_steps
                        ]
                        dedupe = digest(json.dumps(
                            [source_ref, path], ensure_ascii=False, sort_keys=True,
                        ).encode())
                        if dedupe in seen:
                            continue
                        seen.add(dedupe)
                        leads.append({
                            "id": f"{language}:{source_ref}:{len(leads) + 1}"[:80],
                            "source_type": "codeql",
                            "source_ref": source_ref,
                            "title": f"CodeQL {rule_id}: {path[0]} → {path[-1]}",
                            "hypothesis": f"CodeQL reported a data-flow path: {message}",
                            "source": path[0],
                            "sink": path[-1],
                            "path": path,
                            "citation_ids": [step["citation_id"] for step in normalized_steps],
                            "missing_evidence": [
                                "Confirm attacker control and path reachability.",
                                "Check trust-boundary and authorization semantics.",
                                "Verify sanitizers, guards, and the security impact.",
                            ],
                            "next_step": "Trace the path in the application context and verify its guards.",
                        })
                        if len(leads) >= config.max_candidates:
                            gaps.append("CodeQL candidates were truncated at the configured maximum.")
                            break
                    if len(leads) >= config.max_candidates:
                        break
                if len(leads) >= config.max_candidates:
                    break
            if len(leads) >= config.max_candidates:
                break
        if len(leads) >= config.max_candidates:
            break
    canonical = canonical_source_citations(
        citations, source, source_manifest, label="CodeQL",
    )
    record = {
        "schema_version": 1,
        "kind": "codeql_path_candidates",
        "status": "complete",
        "producer": "CodeQL CLI in isolated Docker analysis image",
        "image_id": image_id,
        "cli_path": config.cli_path,
        "network": "none",
        "build_mode": "none",
        "database_cache_id": cache_key,
        "max_work_bytes": config.max_work_bytes,
        "languages": languages,
        "query_category": category,
        "query_profile": config.query_profiles.get(category, {}) if category else {},
        "elapsed_ms": elapsed_ms,
        "snapshot_id": source_manifest["id"],
        "snapshot_fact_id": snapshot_fact.id,
        "candidate_count": len(leads),
        "leads": leads,
        "citations": canonical,
        "gaps": list(dict.fromkeys(gaps))[:100],
    }
    return record, source_manifest, canonical


def _monitor_workdir(
    process,
    workdir: Path,
    cache_root: Path,
    limit_bytes: int,
    stop: threading.Event,
    exceeded: threading.Event,
) -> None:
    while not stop.wait(5):
        total = 0
        for root in (workdir, cache_root):
            for directory, _dirs, names in os.walk(root, followlinks=False):
                for name in names:
                    path = Path(directory) / name
                    try:
                        if path.is_symlink():
                            continue
                        total += path.stat().st_size
                    except OSError:
                        continue
                    if total > limit_bytes:
                        exceeded.set()
                        process.cancel("CodeQL workdir size limit exceeded")
                        return


def _inspect_image(config: CodeQLConfig) -> str:
    executable = shutil.which(config.executable)
    if executable is None:
        raise CodeQLRunError("CodeQL analysis requires Docker; refusing host fallback")
    try:
        inspected = subprocess.run(
            [executable, "image", "inspect", "--format", "{{.Id}}", config.image or ""],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CodeQLRunError(f"Cannot inspect the local CodeQL image: {exc}") from exc
    if inspected.returncode or not inspected.stdout.strip():
        raise CodeQLRunError("CodeQL image is not available locally; refusing pull/host fallback")
    return inspected.stdout.strip()


def _parse_outputs(stdout: str, languages: list[str]) -> dict[str, dict[str, Any]]:
    output = {}
    for language in languages:
        begin = _BEGIN.format(language)
        end = _END.format(language)
        if stdout.count(begin) != 1 or stdout.count(end) != 1:
            raise CodeQLRunError(f"CodeQL did not return exactly one SARIF result for {language}")
        payload = stdout.split(begin, 1)[1].split(end, 1)[0].strip()
        try:
            sarif = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise CodeQLRunError(f"CodeQL returned invalid SARIF for {language}: {exc}") from exc
        if (
            not isinstance(sarif, dict)
            or sarif.get("version") != "2.1.0"
            or not isinstance(sarif.get("runs"), list)
        ):
            raise CodeQLRunError(f"CodeQL SARIF for {language} has an unsupported structure")
        output[language] = sarif
    return output


def _location(location: dict[str, Any], run: dict[str, Any]) -> tuple[str, int, str] | None:
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri")
    region = physical.get("region") or {}
    line = region.get("startLine")
    if not isinstance(uri, str) or type(line) is not int or line < 1:
        return None
    bases = run.get("originalUriBaseIds") or {}
    base_id = artifact.get("uriBaseId")
    base_uri = (bases.get(base_id) or {}).get("uri") if isinstance(base_id, str) else None
    if base_uri and not urlparse(uri).scheme:
        uri = base_uri.rstrip("/") + "/" + uri.lstrip("/")
    parsed = urlparse(uri)
    if parsed.scheme:
        if parsed.scheme != "file":
            return None
        absolute = Path(unquote(parsed.path))
        try:
            filename = absolute.relative_to(Path("/repo")).as_posix()
        except ValueError:
            return None
    else:
        filename = posixpath.normpath(unquote(uri).split("?", 1)[0])
        if filename.startswith("/repo/"):
            filename = filename[len("/repo/"):]
        filename = filename.removeprefix("./")
    if not filename or filename.startswith("/") or ".." in Path(filename).parts or "\\" in filename:
        return None
    logical = location.get("logicalLocations") or []
    symbol = None
    if logical and isinstance(logical[0], dict):
        symbol = logical[0].get("fullyQualifiedName") or logical[0].get("name")
    if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol):
        symbol = "<location>"
    return filename, line, symbol


def outcome_fact(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    config: CodeQLConfig,
    cancellation: TaskCancellation,
    lease: HeartbeatLease,
) -> dict[str, str]:
    if not is_intent(intent) or not recon.snapshot_fact(project):
        raise ValueError("CodeQL requires its canonical Intent and a frozen reconnaissance snapshot")
    record, _snapshot, _citations = _execute(
        project, intent, workdir, config, cancellation, lease,
    )
    directory = _owned_directory(
        workdir, ".linen-codeql", "results", uuid.uuid4().hex,
    )
    path = directory / "candidates.json"
    write_json(path, record)
    evidence = (
        f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
        f"snapshot: {record['snapshot_id']}\nstatus: {record['status']}\n"
        f"candidates: {record['candidate_count']}"
    )
    category = record.get("query_category")
    label = f"profile {category}" if category else "default query suite"
    return {
        "type": "recon",
        "description": (
            f"CodeQL machine-path candidates: {record['candidate_count']} candidate(s) "
            f"across {', '.join(record['languages'])} from {label}; "
            "all require Reason verification."
        ),
        "evidence": evidence,
    }


def reason_instructions(project: ProjectDetail, workdir: Path, config: CodeQLConfig) -> str:
    if not active_for_project(project, config):
        return ""
    fact = latest_fact(project)
    if fact is None:
        return "\nCodeQL machine-path evidence is pending. Do not wait to investigate independent Recon evidence.\n"
    try:
        record = result_record(fact, workdir)
        citation_map = {
            item["id"]: item for item in record.get("citations", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        candidates = []
        for lead in record.get("leads", [])[:5]:
            if not isinstance(lead, dict):
                continue
            path = " → ".join(lead.get("path", [])[:12])
            refs = []
            for citation_id in lead.get("citation_ids", [])[:8]:
                citation = citation_map.get(citation_id)
                if citation:
                    refs.append(
                        f"{citation.get('file')}:{citation.get('line')}: "
                        f"{str(citation.get('code', ''))[:160]}"
                    )
            candidates.append(
                f"- {lead.get('source_type')} {lead.get('source_ref')}: "
                f"{path}; machine message: {lead.get('hypothesis', '')[:240]}\n"
                f"  frozen citations: {' | '.join(refs)[:800]}\n"
                "  verify attacker control, trust boundary, authorization, sanitizers, "
                "reachability, and impact before creating or rejecting a finding."
            )
        candidate_text = "\n".join(candidates) or "- No multi-hop path candidates were returned."
        gap_text = "\n".join(
            f"- {str(item)[:500]}" for item in record.get("gaps", [])[:12]
        ) or "- No parser, path, or truncation gaps were recorded."
        query_rows = query_results(project)
        query_summaries = []
        for category, query_fact in query_rows:
            try:
                query_record = result_record(query_fact, workdir)
                query_citation_map = {
                    item["id"]: item for item in query_record.get("citations", [])
                    if isinstance(item, dict) and isinstance(item.get("id"), str)
                }
                query_leads = []
                for lead in query_record.get("leads", [])[:3]:
                    if not isinstance(lead, dict):
                        continue
                    path = " → ".join(lead.get("path", [])[:8])
                    refs = [
                        f"{query_citation_map[cid].get('file')}:{query_citation_map[cid].get('line')}"
                        for cid in lead.get("citation_ids", [])[:6]
                        if cid in query_citation_map
                    ]
                    query_leads.append(f"  - {path}; citations: {', '.join(refs)}")
                query_summaries.append(
                    f"- {category}: {query_record.get('candidate_count', 0)} path(s), "
                    f"Fact {query_fact.id}, snapshot {query_record.get('snapshot_id')}"
                    + ("\n" + "\n".join(query_leads) if query_leads else "")
                )
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                query_summaries.append(f"- {category}: invalid result artifact, Fact {query_fact.id}")
        profile_lines = []
        attempted = {category for category, _fact in query_rows}
        pending = {
            query_category(item.description)
            for item in project.intents
            if query_category(item.description)
            and item.source_generation == project.project.source_generation
            and item.plan_revision == project.project.plan_revision
            and item.to is None and item.concluded_at is None
        }
        for category in config.query_profiles:
            attempts = sum(
                1 for item in project.intents
                if query_category(item.description) == category
                and item.source_generation == project.project.source_generation
                and item.plan_revision == project.project.plan_revision
            )
            if (
                category in attempted or category in pending
                or attempts >= config.max_query_attempts_per_profile
            ):
                continue
            profile_lines.append(
                f"- {category}: if useful, submit an Intent with `action: search`, "
                f"`type: search`, description `{QUERY_PREFIX}{category}`, and `from` "
                f"containing both snapshot Fact and initial CodeQL Fact {fact.id}; set "
                f"`target` to `codeql-query:{category}:attempt:{attempts + 1}`. "
                f"Configured languages: {', '.join(config.query_profiles[category])}."
            )
        query_text = "\n".join(query_summaries) or "- No category-specific CodeQL queries have run."
        profile_text = "\n".join(profile_lines) or "- No unrequested configured profiles remain."
        return (
            "\n# CodeQL machine-path evidence\n"
            f"CodeQL Fact {fact.id} has {record.get('candidate_count', 0)} path candidate(s) "
            f"for frozen snapshot {record.get('snapshot_id')}. First candidates follow; "
            "remaining results and gaps are in the artifact. Treat every path as a lead, "
            "not as a vulnerability finding. Inspect its artifact citations, then verify "
            "attacker control, trust boundaries, authorization, sanitizers, reachability, "
            "and impact in application context. Use ordinary Verify Intents for that work.\n"
            f"{candidate_text}\n"
            "Category query results:\n"
            f"{query_text}\n"
            "Optional agent-directed CodeQL query profiles (choose only when they answer a "
            "specific unresolved question; these run against the reusable frozen-snapshot "
            "database in the isolated analysis container):\n"
            f"{profile_text}\n"
            "Never write shell commands or arbitrary query paths into an Intent. Profile names "
            "are the only query selector; dispatcher validates and executes their configured "
            "query suites. Each profile can be requested at most once per plan.\n"
            "CodeQL gaps and limits:\n"
            f"{gap_text}\n"
            "A completed scan or zero returned paths is not proof that the project is safe.\n"
            f"Artifact: {fact.evidence}\n"
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return f"\nCodeQL Fact {fact.id} has an invalid artifact; report a blocker and request retry.\n"
