"""Local Semgrep execution with immutable inputs and board-independent artifacts."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path, PurePosixPath
from typing import Callable

from linen.dispatcher.config import SemgrepConfig
from linen.dispatcher.runtime.process import ProcessResult


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_sarif(document: dict) -> list[dict]:
    """Preserve locations/flows; merge identical alerts, never merge distinct paths."""
    if (not isinstance(document, dict) or document.get("version") != "2.1.0"
            or not isinstance(document.get("runs"), list)):
        raise ValueError("Expected SARIF 2.1.0 runs")
    if not document["runs"]:
        raise ValueError("SARIF contains no scan runs")
    candidates: dict[str, dict] = {}
    for run in document["runs"]:
        if not isinstance(run, dict):
            raise ValueError("Invalid SARIF run")
        driver = run.get("tool", {}).get("driver", {})
        rules = {rule["id"]: rule for rule in driver.get("rules", [])}
        if not isinstance(run.get("results", []), list):
            raise ValueError("Invalid SARIF results")
        for result in run.get("results", []):
            if not isinstance(result, dict):
                raise ValueError("Invalid SARIF result")
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError("SARIF result missing ruleId")
            locations = result.get("locations", [])
            if not locations:
                raise ValueError("SARIF result missing locations")
            flows = result.get("codeFlows", [])
            identity = {
                "tool": driver.get("name"), "rule": rule_id,
                "locations": locations, "flows": flows,
            }
            # Snapshot-scoped fallback includes locations. We do not claim
            # line-shift-stable cross-revision deduplication.
            fingerprint = digest(json.dumps(identity, sort_keys=True).encode())
            if fingerprint in candidates:
                candidates[fingerprint]["occurrences"] += 1
                continue
            candidates[fingerprint] = {
                "fingerprint": fingerprint,
                "rule_id": rule_id,
                "message": result.get("message", {}),
                "level": result.get("level"),
                "locations": locations,
                "code_flows": flows,
                "properties": rules.get(rule_id, {}).get("properties", {}),
                "scanner_fingerprints": result.get("partialFingerprints", {}),
                "occurrences": 1,
                "status": "unverified",
            }
    return list(candidates.values())


def snapshot_source(repo: Path, destination: Path, config: SemgrepConfig, output_root: Path) -> dict:
    """Copy regular files; excluded/symlink/oversize inputs remain in the manifest."""
    files: dict[str, str] = {}
    skipped: list[dict] = []
    destination.mkdir(parents=True)
    for directory, dirs, names in os.walk(repo, followlinks=False):
        directory = Path(directory)
        for name in sorted(dirs + names):
            path = directory / name
            relative = path.relative_to(repo).as_posix()
            reason = None
            if path.is_symlink():
                reason = "symlink"
            elif path == output_root or output_root in path.parents:
                reason = "analysis_artifacts"
            elif name == ".git" or any(
                fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
                for pattern in config.exclude
            ):
                reason = "excluded"
            elif path.is_file() and path.stat().st_size > config.max_target_bytes:
                reason = "max_target_bytes"
            if reason:
                skipped.append({"path": relative, "reason": reason})
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            if not path.is_file():
                skipped.append({"path": relative, "reason": "not_regular_file"})
                continue
            content = path.read_bytes()
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            files[relative] = digest(content)
    identity = json.dumps({"files": files, "skipped": sorted(skipped, key=lambda x: x["path"])}, sort_keys=True)
    return {"id": digest(identity.encode()), "files": files, "skipped": skipped}


def snapshot_canonical_source(
    repo: Path,
    destination: Path,
    canonical_snapshot: dict,
) -> dict:
    """Copy exactly the regular files named by a prior immutable snapshot.

    Scope scanners consume the coverage plan's frozen source. Scanner-specific
    exclude or size settings must not silently narrow that source a second time.
    Any missing, changed, additional, or symlinked input fails the scan instead.
    """
    expected = canonical_snapshot.get("files")
    snapshot_id = canonical_snapshot.get("id")
    skipped = canonical_snapshot.get("skipped", [])
    if (not isinstance(expected, dict) or not expected or not isinstance(snapshot_id, str)
            or not isinstance(skipped, list)):
        raise ValueError("Invalid canonical coverage snapshot")
    for name, expected_hash in expected.items():
        if not isinstance(name, str) or not name or not isinstance(expected_hash, str):
            raise ValueError("Invalid canonical snapshot file entry")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("Invalid canonical snapshot file entry")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not isinstance(item.get("reason"), str)
        for item in skipped
    ):
        raise ValueError("Invalid canonical snapshot skip entry")
    identity = json.dumps(
        {"files": expected, "skipped": sorted(skipped, key=lambda item: item["path"])},
        sort_keys=True,
    )
    if digest(identity.encode()) != snapshot_id:
        raise ValueError("Canonical coverage snapshot id does not match its manifest")
    actual: set[str] = set()
    for directory, dirs, names in os.walk(repo, followlinks=False):
        directory = Path(directory)
        for name in sorted(dirs + names):
            path = directory / name
            relative = path.relative_to(repo).as_posix()
            if path.is_symlink():
                raise ValueError(f"Canonical source contains a symlink: {relative}")
            if name in dirs:
                continue
            if not path.is_file():
                raise ValueError(f"Canonical source contains a non-regular file: {relative}")
            actual.add(relative)
    if actual != set(expected):
        raise ValueError("Scanner input differs from the canonical coverage snapshot")
    destination.mkdir(parents=True)
    for name, expected_hash in sorted(expected.items()):
        source = repo / name
        data = source.read_bytes()
        if digest(data) != expected_hash:
            raise ValueError(f"Canonical snapshot file changed: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return {
        "id": snapshot_id,
        "files": dict(expected),
        "skipped": list(skipped),
    }


def batch_fact(manifest_path: Path, manifest: dict, *, cache_hit: bool = False) -> dict[str, str]:
    return {
        "type": "scan_batch",
        "description": (
            f"Semgrep scan {manifest['status']}: {manifest.get('candidate_count', 0)} "
            f"unverified candidates. Cache hit: {cache_hit}. "
            "This records scan execution, not confirmed vulnerabilities or repository safety."
        ),
        "evidence": (
            f"artifact: {manifest_path}\n"
            f"manifest_sha256: {digest(manifest_path.read_bytes())}\n"
            f"snapshot: {manifest.get('snapshot', {}).get('id', 'unavailable')}\n"
            f"status: {manifest['status']}\n"
            f"candidates: {manifest_path.parent / 'candidates.json'}\n"
            f"source: {manifest_path.parent / 'source'}\n"
            f"errors: {json.dumps(manifest.get('errors', []), ensure_ascii=False)}"
        ),
    }


def run_scan(
    repo: Path,
    output_root: Path,
    config: SemgrepConfig,
    execute: Callable[[Path, list[str]], ProcessResult],
    *,
    canonical_snapshot: dict | None = None,
) -> dict[str, str]:
    """Return one fact payload. Never call the server or modify the target tree."""
    repo = repo.resolve()
    output_root = output_root.resolve()
    run_dir = output_root / uuid.uuid4().hex
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "manifest.json"
    manifest: dict = {
        "schema_version": 1,
        "kind": "managed_scanner_batch",
        "status": "failed",
        "errors": [],
        "candidate_count": 0,
        "scanner": {
            "name": "semgrep",
            "label": "Semgrep",
            "version": "unavailable",
            "executable": config.executable,
        },
    }
    cache_key = None
    try:
        if not repo.is_dir():
            raise ValueError(f"Repository does not exist: {repo}")
        rules = config.rules.expanduser().resolve() if config.rules else None
        if rules is None or not rules.is_file():
            raise ValueError("Semgrep requires an existing local rule file")
        rule_bytes = rules.read_bytes()
        (run_dir / "rules.yaml").write_bytes(rule_bytes)
        manifest["rules_sha256"] = digest(rule_bytes)
        captured = (
            snapshot_canonical_source(repo, run_dir / "source", canonical_snapshot)
            if canonical_snapshot is not None
            else snapshot_source(repo, run_dir / "source", config, output_root)
        )
        manifest["snapshot"] = captured
        executable = shutil.which(config.executable)
        if executable is None:
            raise ValueError(f"Semgrep executable unavailable: {config.executable}")
        probe = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=10,
            env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"},
        )
        if probe.returncode or not probe.stdout.strip():
            raise ValueError("Semgrep version probe failed: " + probe.stderr[:1000])
        manifest["scanner"].update({"version": probe.stdout.strip(), "executable": executable})
        manifest["config"] = config.model_dump(mode="json")
        cache_key = digest(json.dumps({
            "adapter": 1, "snapshot": manifest["snapshot"]["id"],
            "rules": manifest["rules_sha256"], "scanner": manifest["scanner"],
            "config": manifest["config"],
        }, sort_keys=True).encode())
        cache_path = output_root / f"cache-{cache_key}.json"
        if config.cache and cache_path.is_file():
            try:
                entry = json.loads(cache_path.read_text())
                cached_dir = output_root / entry["run_id"]
                if cached_dir.parent != output_root:
                    raise ValueError("Invalid cache path")
                cached_path = cached_dir / "manifest.json"
                if digest(cached_path.read_bytes()) != entry["manifest_sha256"]:
                    raise ValueError("Cache manifest changed")
                cached = json.loads(cached_path.read_text())
                expected_files = {**cached["artifact_hashes"], **{
                    "source/" + name: value for name, value in cached["snapshot"]["files"].items()
                }}
                if cached["status"] == "completed" and all(
                    digest((cached_dir / name).read_bytes()) == value
                    for name, value in expected_files.items()
                ):
                    shutil.rmtree(run_dir)
                    return batch_fact(cached_path, cached, cache_hit=True)
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Corrupt/incomplete cache is a miss; preserve the prior artifacts.
        argv = [
            executable, "scan", "--config", str(run_dir / "rules.yaml"),
            "--sarif", "--json-output", str(run_dir / "report.json"),
            "--metrics=off", "--disable-version-check", "--disable-nosem",
            "--no-git-ignore", "--max-target-bytes", str(config.max_target_bytes),
            "--verbose", ".",
        ]
        manifest["command"] = argv
        result = execute(run_dir / "source", argv)
        (run_dir / "raw.sarif").write_text(result.stdout, encoding="utf-8")
        (run_dir / "stderr.log").write_text(result.stderr, encoding="utf-8")
        manifest["execution"] = {
            "returncode": result.returncode, "timed_out": result.timed_out,
            "cancelled": result.cancelled,
        }
        candidates = normalize_sarif(json.loads(result.stdout))
        write_json(run_dir / "candidates.json", candidates)
        manifest["candidate_count"] = len(candidates)
        report = json.loads((run_dir / "report.json").read_text())
        if not isinstance(report.get("paths", {}).get("scanned"), list):
            raise ValueError("Semgrep report missing scanned file list")
        manifest["coverage"] = report["paths"]
        manifest["errors"] = report.get("errors", [])
        if result.cancelled or result.timed_out:
            manifest["status"] = "partial"
            manifest["errors"].append({"message": "Scan cancelled or timed out"})
        elif result.returncode != 0:
            manifest["errors"].append({"message": f"Scanner exited {result.returncode}"})
        else:
            manifest["status"] = "partial" if manifest["errors"] else "completed"
        # A copied snapshot is identified by its bytes, independent of later
        # changes to the live repository. Reject writes to the copied inputs.
        if any(digest((run_dir / "source" / name).read_bytes()) != value
               for name, value in manifest["snapshot"]["files"].items()):
            manifest["status"] = "partial"
            manifest["errors"].append({"message": "Source snapshot changed during scan"})
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as exc:
        manifest["status"] = "failed"
        manifest["errors"].append({"message": str(exc)})
    manifest["artifact_hashes"] = {
        name: digest((run_dir / name).read_bytes())
        for name in ("rules.yaml", "raw.sarif", "report.json", "candidates.json", "stderr.log")
        if (run_dir / name).is_file()
    }
    write_json(manifest_path, manifest)
    if config.cache and cache_key and manifest["status"] == "completed":
        temporary = output_root / f"cache-{cache_key}-{run_dir.name}.tmp"
        write_json(temporary, {"run_id": run_dir.name, "manifest_sha256": digest(manifest_path.read_bytes())})
        temporary.replace(output_root / f"cache-{cache_key}.json")
    return batch_fact(manifest_path, manifest)
