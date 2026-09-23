"""Deterministic Spring MVC route/interceptor candidate extraction.

This is deliberately a candidate generator, not a security oracle.  It finds
literal controller routes that are not covered by literal MVC interceptor
patterns and records explicit coverage gaps for filters and generated routes.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from linen.dispatcher.analysis.artifacts import (
    digest,
    load_artifact,
    snapshot_canonical_source,
    snapshot_source,
    write_json,
)
from linen.dispatcher.config import CoverageConfig, SpringScanConfig
from linen.server.models import ProjectDetail


SPRING_SCAN_INTENT = "@analysis:spring-route-auth"


def has_java_sources(project: ProjectDetail, workdir: Path) -> bool:
    """Return whether the frozen coverage snapshot contains Java source.

    Spring route extraction is deterministic and only understands Java MVC.
    Skip it for snapshots with no Java files, while failing open if the plan
    cannot be inspected so a missing artifact never silently drops coverage.
    """
    plans = [fact for fact in project.facts if fact.type == "coverage_plan"]
    if len(plans) != 1:
        return True
    try:
        _path, plan = load_artifact(plans[0], workdir)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return True
    files = plan.get("snapshot", {}).get("files")
    if not isinstance(files, dict):
        return True
    return any(str(name).lower().endswith(".java") for name in files)

_MAPPING = re.compile(
    r"@(?P<kind>Request|Get|Post|Put|Delete|Patch)Mapping\s*(?:\((?P<args>.*?)\))?",
    re.DOTALL,
)
_CLASS = re.compile(r"\b(?:class|interface)\s+[A-Za-z_$][\w$]*")
_METHOD = re.compile(
    r"(?:public|protected|private|default|static|final|synchronized|abstract|native|\s)+"
    r"[\w<>, ?\[\].@]+\s+[A-Za-z_$][\w$]*\s*\(",
)
_STRING = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
_AUTH_ANNOTATION = re.compile(r"@(PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b")


def _strings(value: str | None) -> list[str]:
    if not value:
        return []
    return [bytes(match.group(1), "utf-8").decode("unicode_escape") for match in _STRING.finditer(value)]


def _path(value: str) -> str:
    normalized = "/" + value.strip().strip("/")
    return normalized if normalized != "//" else "/"


def _join(prefix: str, suffix: str) -> str:
    if not prefix:
        return _path(suffix)
    if not suffix:
        return _path(prefix)
    return _path(prefix.strip("/") + "/" + suffix.strip("/"))


def _ant_match(pattern: str, route: str) -> bool:
    escaped = re.escape(_path(pattern))
    escaped = escaped.replace(r"/\*\*", r"(?:/.*)?").replace(r"\*\*", r".*").replace(r"\*", r"[^/]*")
    return re.fullmatch(escaped, _path(route)) is not None


def _line(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _without_comments(content: str) -> str:
    """Replace Java comments with spaces while preserving strings and offsets."""
    result = list(content)
    state = "code"
    index = 0
    while index < len(content):
        char = content[index]
        nxt = content[index + 1] if index + 1 < len(content) else ""
        if state == "code" and char == '"':
            state = "string"
        elif state == "code" and char == "'":
            state = "char"
        elif state == "code" and char == "/" and nxt == "/":
            result[index] = result[index + 1] = " "
            state = "line"
            index += 1
        elif state == "code" and char == "/" and nxt == "*":
            result[index] = result[index + 1] = " "
            state = "block"
            index += 1
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block":
            if char == "*" and nxt == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 1
            elif char != "\n":
                result[index] = " "
        elif state in {"string", "char"} and char == "\\":
            index += 1
        elif state == "string" and char == '"':
            state = "code"
        elif state == "char" and char == "'":
            state = "code"
        index += 1
    return "".join(result)


def _mapping_paths(args: str | None) -> list[str]:
    if not args:
        return [""]
    named = re.search(r"\b(?:value|path)\s*=\s*(\{.*?\}|\"(?:\\.|[^\"\\])*\")", args, re.DOTALL)
    if named:
        return _strings(named.group(1)) or [""]
    if re.search(r"\b[A-Za-z_$][\w$]*\s*=", args):
        return [""]
    return _strings(args) or [""]


def _class_prefixes(content: str, class_offset: int) -> list[str]:
    boundary = max(content.rfind("}", 0, class_offset), content.rfind(";", 0, class_offset))
    annotations = [match for match in _MAPPING.finditer(content[boundary + 1:class_offset])]
    if not annotations:
        return [""]
    match = annotations[-1]
    return _mapping_paths(match.group("args"))


def extract_routes(name: str, content: str) -> list[dict]:
    routes: list[dict] = []
    parsed = _without_comments(content)
    class_matches = list(_CLASS.finditer(parsed))
    if not class_matches:
        return routes
    for class_index, class_match in enumerate(class_matches):
        stop = class_matches[class_index + 1].start() if class_index + 1 < len(class_matches) else len(parsed)
        prefixes = _class_prefixes(parsed, class_match.start())
        header_boundary = max(parsed.rfind("}", 0, class_match.start()), parsed.rfind(";", 0, class_match.start()))
        class_auth = bool(_AUTH_ANNOTATION.search(parsed[header_boundary + 1:class_match.start()]))
        for mapping in _MAPPING.finditer(parsed, class_match.end(), stop):
            after = parsed[mapping.end():min(stop, mapping.end() + 1200)]
            method = _METHOD.search(after)
            if method is None:
                continue
            values = _mapping_paths(mapping.group("args"))
            method_boundary = max(
                parsed.rfind("}", class_match.end(), mapping.start()),
                parsed.rfind(";", class_match.end(), mapping.start()),
            )
            method_auth = bool(_AUTH_ANNOTATION.search(
                parsed[max(class_match.end(), method_boundary + 1):mapping.start()]
            ))
            if mapping.group("kind") == "Request":
                methods = re.findall(r"RequestMethod\.([A-Z]+)", mapping.group("args") or "") or ["ANY"]
            else:
                methods = [mapping.group("kind").upper()]
            for prefix in prefixes:
                for value in values:
                    for http_method in methods:
                        routes.append({
                            "file": name,
                            "line": _line(content, mapping.start()),
                            "path": _join(prefix, value),
                            "http_method": http_method,
                            "security_annotation": class_auth or method_auth,
                            "test_only": "/src/test/" in f"/{name}",
                        })
    return routes


def extract_interceptor_patterns(files: dict[str, str]) -> dict:
    registrations = []
    auth_name = re.compile(r"(?:auth|security|token|apikey|api_key|permission|login)", re.IGNORECASE)
    for name, raw in files.items():
        content = _without_comments(raw)
        for match in re.finditer(r"\.addInterceptor\s*\((.*?)\)(.*?);", content, re.DOTALL):
            interceptor = match.group(1).strip()
            if not auth_name.search(interceptor):
                continue
            chain = match.group(2)
            include_match = re.search(r"\.addPathPatterns\s*\((.*?)\)", chain, re.DOTALL)
            exclude_match = re.search(r"\.excludePathPatterns\s*\((.*?)\)", chain, re.DOTALL)
            registrations.append({
                "file": name,
                "interceptor": interceptor,
                "include": _strings(include_match.group(1)) if include_match else ["/**"],
                "exclude": _strings(exclude_match.group(1)) if exclude_match else [],
            })
    return {
        "include": sorted({pattern for row in registrations for pattern in row["include"]}),
        "exclude": sorted({pattern for row in registrations for pattern in row["exclude"]}),
        "registrations": registrations,
    }


def run_spring_scan(
    repo: Path,
    output_root: Path,
    config: SpringScanConfig,
    *,
    canonical_snapshot: dict | None = None,
) -> dict[str, str]:
    repo = repo.resolve()
    output_root = output_root.resolve()
    run_dir = output_root / ("spring-" + uuid.uuid4().hex)
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "manifest.json"
    manifest: dict = {
        "schema_version": 1,
        "status": "failed",
        "producer": {"name": "spring-route-auth", "version": 1},
        "errors": [],
        "candidate_count": 0,
    }
    try:
        if not config.enabled:
            raise ValueError("Spring route scan is disabled")
        captured = (
            snapshot_canonical_source(repo, run_dir / "source", canonical_snapshot)
            if canonical_snapshot is not None
            else snapshot_source(
                repo,
                run_dir / "source",
                CoverageConfig(max_target_bytes=2_000_000),
                output_root,
            )
        )
        manifest["snapshot"] = captured
        java_files: dict[str, str] = {}
        routes: list[dict] = []
        for name in sorted(manifest["snapshot"]["files"]):
            if not name.endswith(".java"):
                continue
            content = (run_dir / "source" / name).read_text(encoding="utf-8", errors="replace")
            java_files[name] = content
            routes.extend(extract_routes(name, content))
        guards = extract_interceptor_patterns(java_files)
        candidates: list[dict] = []
        for route in routes:
            covering = []
            excluded_by = []
            for registration in guards["registrations"]:
                included = [
                    pattern for pattern in registration["include"] if _ant_match(pattern, route["path"])
                ]
                excluded = [
                    pattern for pattern in registration["exclude"] if _ant_match(pattern, route["path"])
                ]
                if included and not excluded:
                    covering.append(registration["interceptor"])
                if included and excluded:
                    excluded_by.append(registration["interceptor"])
            if route["security_annotation"] or covering:
                continue
            identity = {
                "rule": "spring-route-mvc-guard-gap",
                "file": route["file"],
                "line": route["line"],
                "path": route["path"],
                "method": route["http_method"],
            }
            candidates.append({
                "fingerprint": digest(json.dumps(identity, sort_keys=True).encode()),
                "rule_id": identity["rule"],
                "message": {"text": (
                    f"{route['http_method']} {route['path']} is not covered by a discovered MVC "
                    "interceptor include, or is explicitly excluded; verify SecurityFilterChain, "
                    "proxy policy, and whether the route is intentionally public."
                )},
                "level": "warning",
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": route["file"]},
                    "region": {"startLine": route["line"]},
                }}],
                "code_flows": [],
                "properties": {
                    "category": "authorization",
                    "route": route["path"],
                    "http_method": route["http_method"],
                    "mvc_covering_interceptors": covering,
                    "mvc_excluded_by": excluded_by,
                    "test_only": route["test_only"],
                    "coverage_gap": "Spring Security filters and runtime proxy policy are not statically resolved",
                },
                "route_fingerprints": {},
                "occurrences": 1,
                "status": "unverified",
            })
        write_json(run_dir / "routes.json", routes)
        write_json(run_dir / "guards.json", guards)
        write_json(run_dir / "candidates.json", candidates)
        manifest["candidate_count"] = len(candidates)
        manifest["route_count"] = len(routes)
        manifest["guard_patterns"] = guards
        manifest["status"] = "completed"
    except (OSError, ValueError, TypeError, KeyError) as exc:
        manifest["errors"].append({"message": str(exc)})
    manifest["artifact_hashes"] = {
        name: digest((run_dir / name).read_bytes())
        for name in ("routes.json", "guards.json", "candidates.json")
        if (run_dir / name).is_file()
    }
    write_json(manifest_path, manifest)
    return {
        "type": "route_scan",
        "description": (
            f"Spring route/auth scan {manifest['status']}: {manifest.get('route_count', 0)} literal routes, "
            f"{manifest['candidate_count']} unverified guard-gap candidates. This is candidate generation, "
            "not proof that routes are unauthenticated."
        ),
        "evidence": (
            f"artifact: {manifest_path}\n"
            f"manifest_sha256: {digest(manifest_path.read_bytes())}\n"
            f"snapshot: {manifest.get('snapshot', {}).get('id', 'unavailable')}\n"
            f"status: {manifest['status']}\n"
            f"candidates: {run_dir / 'candidates.json'}"
        ),
    }
