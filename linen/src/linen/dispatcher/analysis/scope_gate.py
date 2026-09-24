"""Evidence-backed scope adjudication before coverage fan-out.

The host freezes policy material and records every collection gap.  An
existing Explore worker then performs one constrained adjudication pass.  The
model never fetches sources, writes the protocol, or changes a Fact lifecycle;
this module validates exact quotations and materializes the result as an
ordinary reviewed blackboard Fact.
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import socket
import subprocess
import uuid
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests

from linen.dispatcher.analysis import audit_recipes
from linen.dispatcher.analysis.artifacts import digest, load_artifact, source_bytes, write_json
from linen.dispatcher.config import ScopeAdjudicationConfig
from linen.server.models import Fact, Intent, ProjectDetail


EVIDENCE_INTENT = "@analysis:scope-evidence"
ADJUDICATION_INTENT = "@analysis:scope-adjudication"
POLICY_EVIDENCE_TYPE = "policy_evidence"
SCOPE_ADJUDICATION_TYPE = "scope_adjudication"
CREATOR = "dispatcher.audit"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GITHUB_REMOTE = re.compile(
    r"(?:github\.com[:/])(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
_DECISIONS = frozenset({"included", "excluded", "conditional", "unknown"})
RemoteFetcher = Callable[[str], dict[str, Any]]


class _ReadableHTML(HTMLParser):
    _BLOCKS = frozenset({
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt",
        "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
        "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table",
        "td", "th", "tr", "ul",
    })

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "svg"}:
            self.ignored_depth += 1
        elif not self.ignored_depth and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg"} and self.ignored_depth:
            self.ignored_depth -= 1
        elif not self.ignored_depth and tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)

    def text(self) -> str:
        lines = []
        for line in "".join(self.parts).splitlines():
            normalized = re.sub(r"\s+", " ", line).strip()
            if normalized:
                lines.append(normalized)
        return "\n".join(lines) + ("\n" if lines else "")


def is_evidence_intent(intent: Intent) -> bool:
    return (
        intent.creator == CREATOR
        and intent.type == "search"
        and intent.description.strip() == EVIDENCE_INTENT
    )


def is_adjudication_intent(intent: Intent) -> bool:
    return (
        intent.creator == CREATOR
        and intent.type == "verify"
        and intent.description.strip() == ADJUDICATION_INTENT
    )


def _git_value(repo: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _github_repository(remote: str | None) -> tuple[str, str] | None:
    if not remote:
        return None
    match = _GITHUB_REMOTE.search(remote.rstrip("/"))
    if not match:
        return None
    return match.group("owner"), match.group("repo")


def _repository_record(repo: Path) -> dict[str, Any]:
    remote = _git_value(repo, "remote", "get-url", "origin")
    github = _github_repository(remote)
    return {
        "path": str(repo),
        "commit": _git_value(repo, "rev-parse", "HEAD"),
        "remote": remote,
        "github": (
            {"owner": github[0], "repository": github[1]} if github else None
        ),
    }


def _safe_remote_url(url: str) -> None:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("Remote policy source must be a credential-free HTTPS URL")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError(f"Remote policy host cannot be resolved: {parsed.hostname}") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Remote policy source resolves to a non-public address")


def _fetch_remote(url: str, config: ScopeAdjudicationConfig) -> dict[str, Any]:
    session = requests.Session()
    session.trust_env = False
    current = url
    try:
        for redirect in range(config.max_redirects + 1):
            _safe_remote_url(current)
            hostname = (urlparse(current).hostname or "").casefold()
            headers = {
                "Accept": "application/json, text/markdown, text/plain, text/html;q=0.8",
                "User-Agent": "linen-scope-adjudication/1",
            }
            token = os.environ.get("GITHUB_TOKEN")
            if token and hostname == "api.github.com":
                headers["Authorization"] = f"Bearer {token}"
                headers["X-GitHub-Api-Version"] = "2022-11-28"
            with session.get(
                current,
                headers=headers,
                timeout=config.fetch_timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location or redirect >= config.max_redirects:
                        raise ValueError("Remote policy redirect limit exceeded")
                    current = urljoin(current, location)
                    continue
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    body.extend(chunk)
                    if len(body) > config.max_document_bytes:
                        raise ValueError("Remote policy document exceeds max_document_bytes")
                return {
                    "body": bytes(body),
                    "content_type": response.headers.get("Content-Type", ""),
                    "final_url": current,
                    "status_code": response.status_code,
                }
    finally:
        session.close()
    raise ValueError("Remote policy fetch did not produce a document")


def _normalize_remote_document(body: bytes, content_type: str) -> bytes:
    text = body.decode("utf-8", errors="replace")
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if media_type in {"application/json", "application/vnd.github+json"}:
        try:
            text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except (ValueError, TypeError):
            pass
    elif media_type in {"text/html", "application/xhtml+xml"} or "<html" in text[:1000].casefold():
        parser = _ReadableHTML()
        parser.feed(text)
        text = parser.text()
    else:
        text = html.unescape(text).replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def _gap(source: str, reason: str, *, detail: str | None = None) -> dict[str, str]:
    result = {"source": source, "reason": reason}
    if detail:
        result["detail"] = detail[:1000]
    return result


def collect_evidence(
    repo: Path,
    workdir: Path,
    config: ScopeAdjudicationConfig,
    *,
    fetcher: RemoteFetcher | None = None,
) -> dict[str, str]:
    """Freeze configured policy sources and return one draft Fact payload."""
    if not config.enabled:
        raise ValueError("Scope adjudication is disabled")
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError("Scope adjudication requires an existing repository")
    directory = (workdir / ".linen-analysis" / f"scope-evidence-{uuid.uuid4().hex}").resolve()
    source_root = directory / "source"
    source_root.mkdir(parents=True)
    repository = _repository_record(repo)
    sources: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    snapshot_files: dict[str, str] = {}
    seen: set[Path] = set()

    def store(content: bytes, snapshot_file: str, record: dict[str, Any]) -> None:
        target = source_root / snapshot_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        checksum = digest(content)
        snapshot_files[snapshot_file] = checksum
        sources.append({
            "id": f"policy-{len(sources) + 1:03d}",
            **record,
            "snapshot_file": snapshot_file,
            "sha256": checksum,
            "bytes": len(content),
            "status": "collected",
        })

    limit_recorded = False
    for pattern in config.local_paths:
        matches = sorted(repo.glob(pattern), key=lambda path: path.as_posix().casefold())
        regular_matches = [path for path in matches if path.is_file()]
        eligible = []
        for path in regular_matches:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            eligible.append(path)
        if not regular_matches:
            gaps.append(_gap(pattern, "not_found"))
            continue
        if not eligible:
            continue
        for path in eligible:
            relative = path.relative_to(repo).as_posix()
            resolved = path.resolve()
            if path.is_symlink() or not resolved.is_relative_to(repo):
                gaps.append(_gap(relative, "symlink_or_escape"))
                continue
            if len(sources) >= config.max_documents:
                if not limit_recorded:
                    gaps.append(_gap("local_paths", "max_documents_reached"))
                    limit_recorded = True
                continue
            content = path.read_bytes()
            if len(content) > config.max_document_bytes:
                gaps.append(_gap(relative, "max_document_bytes"))
                continue
            if b"\x00" in content:
                gaps.append(_gap(relative, "binary_document"))
                continue
            store(content, f"local/{relative}", {
                "kind": "repository_document",
                "location": relative,
                "content_type": "text/plain",
            })

    remote_sources: list[tuple[str, str]] = [(url, "configured_policy_url") for url in config.policy_urls]
    if config.github_advisories:
        github = repository.get("github")
        if github:
            remote_sources.append((
                "https://api.github.com/repos/"
                f"{github['owner']}/{github['repository']}/security-advisories?per_page=100",
                "github_security_advisories",
            ))
        else:
            gaps.append(_gap("github_security_advisories", "github_repository_unresolved"))

    fetch = fetcher or (lambda url: _fetch_remote(url, config))
    for url, kind in remote_sources:
        if len(sources) >= config.max_documents:
            if not limit_recorded:
                gaps.append(_gap("remote_sources", "max_documents_reached"))
                limit_recorded = True
            break
        try:
            response = fetch(url)
            body = response.get("body")
            if isinstance(body, str):
                body = body.encode("utf-8")
            if not isinstance(body, bytes):
                raise ValueError("Remote fetcher returned no byte body")
            if len(body) > config.max_document_bytes:
                raise ValueError("Remote policy document exceeds max_document_bytes")
            content_type = str(response.get("content_type") or "text/plain")
            normalized = _normalize_remote_document(body, content_type)
            if not normalized.strip():
                raise ValueError("Remote policy document is empty after normalization")
            index = len([item for item in sources if item["kind"] != "repository_document"]) + 1
            store(normalized, f"remote/policy-{index:03d}.txt", {
                "kind": kind,
                "location": url,
                "final_url": str(response.get("final_url") or url),
                "content_type": content_type,
                "http_status": int(response.get("status_code") or 200),
                "normalized": True,
            })
        except (OSError, ValueError, TypeError, requests.RequestException) as exc:
            gaps.append(_gap(url, "fetch_failed", detail=str(exc)))

    skipped = [
        {"path": item["source"], "reason": item["reason"]}
        for item in gaps
    ]
    snapshot_identity = json.dumps(
        {"files": snapshot_files, "skipped": sorted(skipped, key=lambda item: (item["path"], item["reason"]))},
        ensure_ascii=False,
        sort_keys=True,
    )
    snapshot = {
        "id": digest(snapshot_identity.encode("utf-8")),
        "files": snapshot_files,
        "skipped": skipped,
    }
    manifest = {
        "schema_version": 1,
        "id": f"policy-evidence-{uuid.uuid4().hex}",
        "kind": POLICY_EVIDENCE_TYPE,
        "status": "completed" if sources and not gaps else "partial",
        "repository": repository,
        "config": config.model_dump(mode="json"),
        "snapshot": snapshot,
        "source": str(source_root),
        "sources": sources,
        "gaps": gaps,
    }
    path = directory / "manifest.json"
    write_json(path, manifest)
    return {
        "type": POLICY_EVIDENCE_TYPE,
        "description": (
            f"Policy evidence frozen: {len(sources)} documents, {len(gaps)} explicit gaps "
            f"({manifest['status']}). No missing source was interpreted as an absence of policy."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            f"snapshot: {snapshot['id']}\nstatus: {manifest['status']}\n"
            f"source: {source_root}"
        ),
    }


def _fact(project: ProjectDetail, fact_id: str) -> Fact | None:
    return next((fact for fact in project.facts if fact.id == fact_id), None)


def _evidence_context(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
) -> tuple[Fact, Path, dict[str, Any]]:
    if not is_adjudication_intent(intent) or len(intent.from_) != 1:
        raise ValueError("Scope adjudication requires its exact graph-derived Intent")
    fact = _fact(project, intent.from_[0])
    if fact is None or fact.type != POLICY_EVIDENCE_TYPE:
        raise ValueError("Scope adjudication must directly reference policy_evidence")
    path, manifest = load_artifact(fact, workdir)
    if manifest.get("kind") != POLICY_EVIDENCE_TYPE:
        raise ValueError("Scope adjudication policy evidence has an invalid kind")
    source = path.parent / "source"
    for filename, expected in manifest.get("snapshot", {}).get("files", {}).items():
        source_bytes(source, filename, expected)
    return fact, source, manifest


def execution_prompt(
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
    prompt_group: str = "vuln_audit",
    *,
    validation_error: str | None = None,
) -> tuple[str, str, audit_recipes.RecipeDefinition]:
    evidence_fact, source, manifest = _evidence_context(project, intent, workdir)
    recipe = audit_recipes.load_bundle(prompt_group).recipes["scope_adjudication"]
    context: dict[str, Any] = {
        "intent": {
            "id": intent.id,
            "type": intent.type,
            "description": intent.description,
            "input_fact_ids": intent.from_,
        },
        "policy_evidence_fact_id": evidence_fact.id,
        "expected_fact_type": SCOPE_ADJUDICATION_TYPE,
        "snapshot": manifest["snapshot"],
        "source_root": str(source),
        "repository": manifest.get("repository"),
        "sources": manifest.get("sources", []),
        "collection_gaps": manifest.get("gaps", []),
    }
    if validation_error:
        context["previous_validation_error"] = validation_error[:2000]
    output_contract = """Return exactly one raw JSON object and no prose or markdown:
{
  "accepted": true,
  "data": {
    "description": "concise adjudication summary",
    "type": "scope_adjudication",
    "evidence": "what policy material was evaluated",
    "scope_adjudication": {
      "coverage": {"status": "complete | partial", "summary": "...", "gaps": ["..."]},
      "citations": [
        {"id": "c1", "source_id": "policy-001", "file": "local/SECURITY.md",
         "line": 10, "quote": "exact quotation from the frozen document"}
      ],
      "trust_boundaries": [
        {"id": "tb1", "from": "...", "to": "...", "security_invariant": "...",
         "security_state_dimensions": ["authorization"], "citations": ["c1"]}
      ],
      "pre_exclusions": [
        {"id": "pe1", "bug_class": "...",
         "decision": "included | excluded | conditional | unknown",
         "rationale": "...", "citations": ["c1"],
         "revival_conditions": ["concrete evidence that changes the policy decision"]}
      ],
      "conflicts": [
        {"id": "cf1", "summary": "...", "citations": ["c1", "c2"],
         "resolution": "unresolved or evidence-backed precedence decision"}
      ]
    }
  }
}

Every trust boundary and pre-exclusion needs at least one citation. Every
excluded, conditional, or unknown item needs a non-empty revival_conditions
array. collection_gaps must remain visible in coverage; do not turn an absent
document into an exclusion. Policy eligibility and technical exploitability
are separate axes. Use accepted=false only for a genuine policy refusal."""
    sections = [
        f"# Audit recipe: {recipe.label} (scope_adjudication v{recipe.version})",
        audit_recipes.load_bundle(prompt_group).common.source_policy,
        "# Assignment context\n" + json.dumps(context, ensure_ascii=False, indent=2),
        "# Recipe instructions\n" + recipe.prompt,
        "# Output contract\n" + output_contract,
    ]
    return "\n\n".join(sections).strip() + "\n", "scope_adjudication", recipe


def _text(value: Any, label: str, *, maximum: int = 8000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _text_list(value: Any, label: str, *, maximum: int = 200, allow_empty: bool = True) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item.strip() or len(item) > 2000 for item in value)
    ):
        raise ValueError(f"{label} must be a bounded text array")
    return [item.strip() for item in value]


def _references(value: Any, citation_ids: set[str], label: str, *, minimum: int = 1) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) < minimum
        or len(value) != len(set(value))
        or any(not isinstance(item, str) or item not in citation_ids for item in value)
    ):
        raise ValueError(f"{label} must reference known unique citations")
    return list(value)


def _item_id(value: Any, seen: set[str], label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or value in seen:
        raise ValueError(f"Invalid or duplicate {label} id")
    seen.add(value)
    return value


def _canonical_citations(
    raw: Any,
    source: Path,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > 1000:
        raise ValueError("Scope adjudication citations must be a bounded array")
    source_records = {
        item["id"]: item
        for item in manifest.get("sources", [])
        if isinstance(item, dict) and item.get("status") == "collected"
    }
    files = manifest.get("snapshot", {}).get("files", {})
    result = []
    ids: set[str] = set()
    for citation in raw:
        if not isinstance(citation, dict) or set(citation) != {
            "id", "source_id", "file", "line", "quote",
        }:
            raise ValueError("Every policy citation requires exactly id, source_id, file, line, quote")
        citation_id = _item_id(citation.get("id"), ids, "citation")
        source_id = citation.get("source_id")
        filename = citation.get("file")
        line = citation.get("line")
        quote = citation.get("quote")
        record = source_records.get(source_id)
        if (
            record is None
            or filename != record.get("snapshot_file")
            or filename not in files
            or type(line) is not int
            or line < 1
            or not isinstance(quote, str)
            or not quote.strip()
            or len(quote) > 8000
        ):
            raise ValueError("Invalid policy citation")
        contents = source_bytes(source, filename, files[filename]).decode(
            "utf-8", errors="replace",
        ).splitlines()
        excerpt = quote.splitlines()
        if line > len(contents):
            raise ValueError(f"Policy citation does not match frozen source: {filename}:{line}")
        if len(excerpt) == 1:
            matches = excerpt[0] in contents[line - 1]
        else:
            matches = contents[line - 1:line - 1 + len(excerpt)] == excerpt
        if not matches:
            raise ValueError(f"Policy citation does not match frozen source: {filename}:{line}")
        result.append({
            "id": citation_id,
            "source_id": source_id,
            "file": filename,
            "line": line,
            "quote": quote,
        })
    return result


def _normalize_adjudication(
    raw: Any,
    source: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {
        "coverage", "citations", "trust_boundaries", "pre_exclusions", "conflicts",
    }:
        raise ValueError(
            "scope_adjudication requires exactly coverage, citations, trust_boundaries, "
            "pre_exclusions, and conflicts"
        )
    coverage = raw["coverage"]
    if not isinstance(coverage, dict) or set(coverage) != {"status", "summary", "gaps"}:
        raise ValueError("Scope adjudication coverage requires status, summary, and gaps")
    if coverage.get("status") not in {"complete", "partial"}:
        raise ValueError("Scope adjudication coverage status must be complete or partial")
    gaps = _text_list(coverage.get("gaps"), "Scope adjudication gaps")
    if manifest.get("gaps") and coverage["status"] != "partial":
        raise ValueError("Collected policy evidence gaps require partial adjudication coverage")
    citations = _canonical_citations(raw["citations"], source, manifest)
    citation_ids = {citation["id"] for citation in citations}

    boundaries = raw["trust_boundaries"]
    if not isinstance(boundaries, list) or len(boundaries) > 240:
        raise ValueError("trust_boundaries must be a bounded array")
    normalized_boundaries = []
    boundary_ids: set[str] = set()
    for item in boundaries:
        if not isinstance(item, dict) or set(item) != {
            "id", "from", "to", "security_invariant", "security_state_dimensions", "citations",
        }:
            raise ValueError("Invalid trust boundary fields")
        normalized_boundaries.append({
            "id": _item_id(item.get("id"), boundary_ids, "trust boundary"),
            "from": _text(item.get("from"), "trust boundary from"),
            "to": _text(item.get("to"), "trust boundary to"),
            "security_invariant": _text(item.get("security_invariant"), "security invariant"),
            "security_state_dimensions": _text_list(
                item.get("security_state_dimensions"),
                "security_state_dimensions",
                allow_empty=False,
            ),
            "citations": _references(item.get("citations"), citation_ids, "trust boundary citations"),
        })

    exclusions = raw["pre_exclusions"]
    if not isinstance(exclusions, list) or len(exclusions) > 240:
        raise ValueError("pre_exclusions must be a bounded array")
    normalized_exclusions = []
    exclusion_ids: set[str] = set()
    for item in exclusions:
        if not isinstance(item, dict) or set(item) != {
            "id", "bug_class", "decision", "rationale", "citations", "revival_conditions",
        }:
            raise ValueError("Invalid pre-exclusion fields")
        decision = item.get("decision")
        if decision not in _DECISIONS:
            raise ValueError("Invalid pre-exclusion decision")
        revival = _text_list(
            item.get("revival_conditions"),
            "revival_conditions",
            allow_empty=decision == "included",
        )
        normalized_exclusions.append({
            "id": _item_id(item.get("id"), exclusion_ids, "pre-exclusion"),
            "bug_class": _text(item.get("bug_class"), "bug_class"),
            "decision": decision,
            "rationale": _text(item.get("rationale"), "pre-exclusion rationale"),
            "citations": _references(item.get("citations"), citation_ids, "pre-exclusion citations"),
            "revival_conditions": revival,
        })

    conflicts = raw["conflicts"]
    if not isinstance(conflicts, list) or len(conflicts) > 100:
        raise ValueError("conflicts must be a bounded array")
    normalized_conflicts = []
    conflict_ids: set[str] = set()
    for item in conflicts:
        if not isinstance(item, dict) or set(item) != {
            "id", "summary", "citations", "resolution",
        }:
            raise ValueError("Invalid policy conflict fields")
        normalized_conflicts.append({
            "id": _item_id(item.get("id"), conflict_ids, "conflict"),
            "summary": _text(item.get("summary"), "conflict summary"),
            "citations": _references(item.get("citations"), citation_ids, "conflict citations", minimum=2),
            "resolution": _text(item.get("resolution"), "conflict resolution"),
        })
    used = {
        citation_id
        for item in [*normalized_boundaries, *normalized_exclusions, *normalized_conflicts]
        for citation_id in item["citations"]
    }
    if used != citation_ids:
        raise ValueError("Every policy citation must support a trust boundary, exclusion, or conflict")
    return {
        "coverage": {
            "status": coverage["status"],
            "summary": _text(coverage.get("summary"), "Scope adjudication coverage summary"),
            "gaps": gaps,
        },
        "citations": citations,
        "trust_boundaries": normalized_boundaries,
        "pre_exclusions": normalized_exclusions,
        "conflicts": normalized_conflicts,
    }


def outcome_fact(
    payload: dict[str, Any],
    project: ProjectDetail,
    intent: Intent,
    workdir: Path,
) -> dict[str, str]:
    evidence_fact, source, manifest = _evidence_context(project, intent, workdir)
    data = payload.get("data", payload)
    if not isinstance(data, dict) or set(data) != {
        "description", "type", "evidence", "scope_adjudication",
    }:
        raise ValueError(
            "Scope adjudication requires exactly description, type, evidence, scope_adjudication"
        )
    if data.get("type") != SCOPE_ADJUDICATION_TYPE:
        raise ValueError("Scope adjudication must produce type=scope_adjudication")
    normalized = _normalize_adjudication(data.get("scope_adjudication"), source, manifest)
    record = {
        "schema_version": 1,
        "kind": SCOPE_ADJUDICATION_TYPE,
        "status": "completed",
        "decision_scope": "policy_eligibility_only",
        "technical_exploitability_unchanged": True,
        "recipe": {
            "id": "scope_adjudication",
            "label": "Scope adjudication",
            "version": 1,
            "phase": "scope_adjudication",
        },
        "snapshot": {"id": manifest["snapshot"]["id"]},
        "input_fact_ids": list(intent.from_),
        "policy_evidence_fact_id": evidence_fact.id,
        "policy_evidence_manifest_sha256": digest(
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        ),
        "evidence_gaps": manifest.get("gaps", []),
        **normalized,
        "worker_evidence": _text(data.get("evidence"), "Scope adjudication evidence"),
    }
    directory = workdir / ".linen-analysis" / f"scope-adjudication-{uuid.uuid4().hex}"
    directory.mkdir(parents=True)
    path = directory / "result.json"
    write_json(path, record)
    return {
        "type": SCOPE_ADJUDICATION_TYPE,
        "description": (
            f"Scope adjudicated from {len(manifest.get('sources', []))} frozen policy documents: "
            f"{len(record['trust_boundaries'])} trust boundaries, "
            f"{len(record['pre_exclusions'])} pre-exclusion decisions, "
            f"{len(record['evidence_gaps']) + len(record['coverage']['gaps'])} recorded gaps. "
            "Decisions affect policy eligibility only, not technical exploitability."
        ),
        "evidence": (
            f"artifact: {path}\nmanifest_sha256: {digest(path.read_bytes())}\n"
            "recipe: scope_adjudication\nrecipe_label: Scope adjudication\n"
            f"snapshot: {manifest['snapshot']['id']}\nstatus: completed"
        ),
    }


def result_for_intent(project: ProjectDetail, description: str) -> Fact | None:
    matches = [
        item for item in project.intents
        if item.description.strip() == description
        and item.source_generation == project.project.source_generation
        and item.plan_revision == project.project.plan_revision
    ]
    intent = max(matches, key=lambda item: (item.created_at, item.id), default=None)
    fact = _fact(project, intent.to) if intent is not None and intent.to else None
    if fact is None or fact.source_generation != project.project.source_generation:
        return None
    return fact


def adjudication_record(fact: Fact, workdir: Path) -> dict[str, Any]:
    if fact.type != SCOPE_ADJUDICATION_TYPE:
        raise ValueError("Fact is not a scope adjudication")
    _, record = load_artifact(fact, workdir)
    if (
        record.get("kind") != SCOPE_ADJUDICATION_TYPE
        or record.get("decision_scope") != "policy_eligibility_only"
        or record.get("technical_exploitability_unchanged") is not True
    ):
        raise ValueError("Invalid scope adjudication artifact")
    return record
