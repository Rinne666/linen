"""Managed adapters for security tools that emit SARIF scan batches.

The adapters never write the blackboard and never execute a target build.  They
scan an immutable copy, persist replayable evidence below ``.linen-analysis``,
and return the same ``scan_batch`` contract used by Semgrep.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from linen.dispatcher.analysis.policy import SCAN_INTENT_DESCRIPTION
from linen.dispatcher.analysis.semgrep import (
    digest,
    normalize_sarif,
    snapshot_canonical_source,
    snapshot_source,
    write_json,
)
from linen.dispatcher.config import AuditConfig, SemgrepConfig
from linen.dispatcher.runtime.process import ProcessResult


SPOTBUGS_INTENT = "@analysis:spotbugs-findsecbugs"
OSV_INTENT = "@analysis:osv-scanner"
GITLEAKS_INTENT = "@analysis:gitleaks"
TRIVY_INTENT = "@analysis:trivy"


@dataclass(frozen=True, slots=True)
class ScannerSpec:
    name: str
    label: str
    intent: str
    phase: str
    config: object
    version_args: tuple[str, ...]
    success_codes: tuple[int, ...] = (0,)


def scanner_specs(config: AuditConfig, *, enabled_only: bool = True) -> list[ScannerSpec]:
    specs = [
        ScannerSpec(
            "semgrep", "Semgrep", SCAN_INTENT_DESCRIPTION, "semgrep_scan",
            config.semgrep, ("--version",),
        ),
        ScannerSpec(
            "spotbugs-findsecbugs", "SpotBugs + FindSecBugs", SPOTBUGS_INTENT,
            "spotbugs_scan", config.spotbugs, ("-version",),
        ),
        ScannerSpec(
            "osv-scanner", "OSV-Scanner", OSV_INTENT, "osv_scan",
            config.osv, ("--version",), (0, 1),
        ),
        ScannerSpec(
            "gitleaks", "Gitleaks", GITLEAKS_INTENT, "gitleaks_scan",
            config.gitleaks, ("version",),
        ),
        ScannerSpec(
            "trivy", "Trivy", TRIVY_INTENT, "trivy_scan",
            config.trivy, ("--version",),
        ),
    ]
    return [spec for spec in specs if getattr(spec.config, "enabled", False)] if enabled_only else specs


def scanner_for_intent(config: AuditConfig, description: str) -> ScannerSpec | None:
    value = description.strip()
    return next((spec for spec in scanner_specs(config) if spec.intent == value), None)


def scanner_reason_instructions(config: AuditConfig) -> str:
    labels = ", ".join(spec.label for spec in scanner_specs(config))
    return f"""
On-demand scanners available: {labels}. Select a scanner only through an exact Trusted
Skill choice supplied by the dispatcher; do not invent or duplicate reserved @analysis
intents. Scanners strengthen an investigation but are not completion requirements.
Every scan_batch is an execution record containing unverified candidates, not a
vulnerability or proof of safety. Read the manifest and candidates artifact, then
create bounded trace/validate intents for promising fingerprints without repeating
covered candidates. A scanner that was not run, failed, or returned a partial batch
establishes neither coverage nor safety.
"""


def batch_fact(manifest_path: Path, manifest: dict, *, cache_hit: bool = False) -> dict[str, str]:
    scanner = manifest.get("scanner", {})
    label = scanner.get("label") or scanner.get("name") or "Managed scanner"
    applicability = manifest.get("applicability", {})
    display_status = applicability.get("status") or manifest["status"]
    return {
        "type": "scan_batch",
        "description": (
            f"{label} scan {display_status}: {manifest.get('candidate_count', 0)} "
            f"unverified candidates. Cache hit: {cache_hit}. "
            "This records scan execution, not confirmed vulnerabilities or repository safety."
        ),
        "evidence": (
            f"artifact: {manifest_path}\n"
            f"manifest_sha256: {digest(manifest_path.read_bytes())}\n"
            f"scanner: {scanner.get('name', 'unavailable')}\n"
            f"snapshot: {manifest.get('snapshot', {}).get('id', 'unavailable')}\n"
            f"status: {manifest['status']}\n"
            f"applicability: {json.dumps(applicability, ensure_ascii=False)}\n"
            f"candidates: {manifest_path.parent / 'candidates.json'}\n"
            f"source: {manifest_path.parent / 'source'}\n"
            f"errors: {json.dumps(manifest.get('errors', []), ensure_ascii=False)}"
        ),
    }


def _snapshot_policy(config: object) -> SemgrepConfig:
    return SemgrepConfig(
        max_target_bytes=getattr(config, "max_target_bytes"),
        exclude=list(getattr(config, "exclude")),
    )


def _copy_optional_file(source: Path | None, destination: Path, purpose: str) -> str | None:
    if source is None:
        return None
    resolved = source.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"{purpose} does not exist: {resolved}")
    destination.write_bytes(resolved.read_bytes())
    return digest(destination.read_bytes())


def _spotbugs_targets(source: Path, patterns: list[str]) -> list[str]:
    targets: set[str] = set()
    for pattern in patterns:
        for path in source.glob(pattern):
            resolved = path.resolve()
            if (path.is_dir() or path.is_file()) and resolved.is_relative_to(source.resolve()):
                targets.add(path.relative_to(source).as_posix())
    if not targets:
        raise ValueError(
            "SpotBugs requires pre-built bytecode under one of spotbugs.targets; "
            "Linen will not execute untrusted Maven/Gradle builds implicitly"
        )
    return sorted(targets)


def _has_spotbugs_source(source: Path) -> bool:
    """Distinguish a non-JVM repository from a JVM project missing bytecode."""
    build_markers = {
        "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    }
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        if path.name in build_markers or path.suffix.lower() in {".java", ".kt", ".class"}:
            return True
    return False


def _prepare_command(spec: ScannerSpec, source: Path, run_dir: Path) -> tuple[list[str], dict[str, str]]:
    executable = str(spec.config.executable)
    report = run_dir / "raw.sarif"
    extra_hashes: dict[str, str] = {}
    if spec.name == "spotbugs-findsecbugs":
        plugin = run_dir / "findsecbugs-plugin.jar"
        plugin_hash = _copy_optional_file(spec.config.plugin, plugin, "FindSecBugs plugin")
        assert plugin_hash is not None
        extra_hashes[plugin.name] = plugin_hash
        targets = _spotbugs_targets(source, spec.config.targets)
        return [
            executable,
            "-textui",
            f"-effort:{spec.config.effort}",
            f"-{spec.config.confidence}",
            "-bugCategories", "SECURITY",
            "-pluginList", str(plugin),
            f"-sourcepath={source}",
            f"-sarif={report}",
            *targets,
        ], extra_hashes
    if spec.name == "osv-scanner":
        return [
            executable, "scan", "source", "--format=sarif", "--verbosity=error",
            "--output-file", str(report),
            *(["--recursive"] if spec.config.recursive else []),
            ".",
        ], extra_hashes
    if spec.name == "gitleaks":
        command = [
            executable, "dir", "--no-banner", "--no-color",
            f"--redact={spec.config.redact_percent}",
            "--report-format", "sarif", "--report-path", str(report),
            "--exit-code", "0",
            "--max-target-megabytes", str(max(1, math.ceil(spec.config.max_target_bytes / 1_000_000))),
        ]
        if spec.config.config is not None:
            copied = run_dir / "gitleaks.toml"
            config_hash = _copy_optional_file(spec.config.config, copied, "Gitleaks config")
            assert config_hash is not None
            extra_hashes[copied.name] = config_hash
            command.extend(["--config", str(copied)])
        command.append(".")
        return command, extra_hashes
    if spec.name == "trivy":
        command = [
            executable, "fs", "--quiet", "--format", "sarif", "--output", str(report),
            "--exit-code", "0", "--scanners", ",".join(spec.config.scanners), ".",
        ]
        if spec.config.db_repository:
            command[1:1] = [
                argument
                for repository in spec.config.db_repository
                for argument in ("--db-repository", repository)
            ]
        return command, extra_hashes
    raise ValueError(f"Unsupported external scanner: {spec.name}")


def _probe(spec: ScannerSpec, executable: str) -> str:
    result = subprocess.run(
        [executable, *spec.version_args],
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "NO_COLOR": "1"},
    )
    version = (result.stdout or result.stderr).strip()
    # Finding-oriented exit codes apply to scans, not to capability probes.
    # Requiring a normal success here prevents a broken installation from
    # being mistaken for a usable scanner.
    if result.returncode != 0 or not version:
        raise ValueError(f"{spec.label} version probe failed: {result.stderr[:1000]}")
    return version.splitlines()[0]


def _cache_hit(output_root: Path, run_dir: Path, cache_key: str) -> tuple[Path, dict] | None:
    cache_path = output_root / f"cache-{cache_key}.json"
    if not cache_path.is_file():
        return None
    try:
        entry = json.loads(cache_path.read_text(encoding="utf-8"))
        cached_dir = output_root / entry["run_id"]
        if cached_dir.parent != output_root:
            raise ValueError("Invalid cache path")
        manifest_path = cached_dir / "manifest.json"
        if digest(manifest_path.read_bytes()) != entry["manifest_sha256"]:
            raise ValueError("Cache manifest changed")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {
            **manifest["artifact_hashes"],
            **{"source/" + name: value for name, value in manifest["snapshot"]["files"].items()},
        }
        if manifest["status"] != "completed" or not all(
            digest((cached_dir / name).read_bytes()) == value for name, value in expected.items()
        ):
            raise ValueError("Cached scan is incomplete or changed")
        shutil.rmtree(run_dir)
        return manifest_path, manifest
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def run_scan(
    repo: Path,
    output_root: Path,
    spec: ScannerSpec,
    execute: Callable[[Path, list[str]], ProcessResult],
    *,
    canonical_snapshot: dict | None = None,
) -> dict[str, str]:
    """Execute one external scanner and return one board-ready fact payload."""
    if spec.name == "semgrep":
        raise ValueError("Semgrep uses its dedicated adapter")
    repo = repo.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = output_root / f"{spec.name}-{uuid.uuid4().hex}"
    run_dir.mkdir()
    manifest_path = run_dir / "manifest.json"
    manifest: dict = {
        "schema_version": 1,
        "kind": "managed_scanner_batch",
        "status": "failed",
        "errors": [],
        "candidate_count": 0,
        "scanner": {
            "name": spec.name,
            "label": spec.label,
            "version": "unavailable",
            "executable": str(spec.config.executable),
        },
    }
    cache_key: str | None = None
    try:
        if not repo.is_dir():
            raise ValueError(f"Repository does not exist: {repo}")
        captured = (
            snapshot_canonical_source(repo, run_dir / "source", canonical_snapshot)
            if canonical_snapshot is not None
            else snapshot_source(repo, run_dir / "source", _snapshot_policy(spec.config), output_root)
        )
        manifest["snapshot"] = captured
        executable = shutil.which(spec.config.executable)
        if executable is None:
            raise ValueError(f"{spec.label} executable unavailable: {spec.config.executable}")
        manifest["scanner"].update({"version": _probe(spec, executable), "executable": executable})
        manifest["config"] = spec.config.model_dump(mode="json")
        if spec.name == "spotbugs-findsecbugs" and not _has_spotbugs_source(run_dir / "source"):
            # Applicability is itself a completed, reviewable branch result.
            # Treating a Python/JS/etc. repository as a failed SpotBugs run
            # would otherwise make a correctly configured scope audit
            # impossible to finish.
            manifest["status"] = "completed"
            manifest["applicability"] = {
                "status": "not_applicable",
                "reason": "Frozen snapshot contains no JVM source, bytecode, or JVM build markers",
            }
            manifest["coverage"] = {
                "input_file_count": len(captured["files"]),
                "input_skip_count": len(captured["skipped"]),
                "spotbugs_targets": [],
            }
            write_json(run_dir / "candidates.json", [])
            manifest["artifact_hashes"] = {
                path.name: digest(path.read_bytes())
                for path in run_dir.iterdir()
                if path.is_file() and path.name != "manifest.json"
            }
            write_json(manifest_path, manifest)
            return batch_fact(manifest_path, manifest)
        command, extra_hashes = _prepare_command(spec, run_dir / "source", run_dir)
        command[0] = executable
        manifest["command"] = command
        manifest["coverage"] = {
            "input_file_count": len(captured["files"]),
            "input_skip_count": len(captured["skipped"]),
            "spotbugs_targets": command[command.index(f"-sarif={run_dir / 'raw.sarif'}") + 1:]
            if spec.name == "spotbugs-findsecbugs" else [],
        }
        cache_key = digest(json.dumps({
            "adapter": 1,
            "scanner": manifest["scanner"],
            "snapshot": captured["id"],
            "config": manifest["config"],
            "extra_hashes": extra_hashes,
        }, sort_keys=True).encode())
        if spec.config.cache:
            cached = _cache_hit(output_root, run_dir, cache_key)
            if cached is not None:
                return batch_fact(*cached, cache_hit=True)
        result = execute(run_dir / "source", command)
        (run_dir / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (run_dir / "stderr.log").write_text(result.stderr, encoding="utf-8")
        manifest["execution"] = {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
        }
        write_json(run_dir / "candidates.json", [])
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > 2000:
            detail = "..." + detail[-2000:]
        if result.cancelled or result.timed_out:
            manifest["status"] = "partial"
            message = "Scan cancelled or timed out"
            if detail:
                message += f": {detail}"
            manifest["errors"].append({"message": message})
        elif result.returncode not in spec.success_codes:
            message = f"Scanner exited {result.returncode}"
            if detail:
                message += f": {detail}"
            manifest["errors"].append({"message": message})
        else:
            manifest["status"] = "completed"

        report_path = run_dir / "raw.sarif"
        if report_path.is_file():
            try:
                document = json.loads(report_path.read_text(encoding="utf-8"))
                candidates = normalize_sarif(document)
                write_json(run_dir / "candidates.json", candidates)
                manifest["candidate_count"] = len(candidates)
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                manifest["status"] = "failed"
                manifest["errors"].append({"message": f"Invalid SARIF output: {exc}"})
        elif manifest["status"] == "completed":
            manifest["status"] = "failed"
            manifest["errors"].append({"message": "Scanner completed without SARIF output"})
        if any(
            digest((run_dir / "source" / name).read_bytes()) != value
            for name, value in captured["files"].items()
        ):
            if manifest["status"] != "failed":
                manifest["status"] = "partial"
            manifest["errors"].append({"message": "Source snapshot changed during scan"})
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        manifest["status"] = "failed"
        manifest["errors"].append({"message": str(exc)})
    manifest["artifact_hashes"] = {
        path.name: digest(path.read_bytes())
        for path in run_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    write_json(manifest_path, manifest)
    if spec.config.cache and cache_key and manifest["status"] == "completed":
        temporary = output_root / f"cache-{cache_key}-{run_dir.name}.tmp"
        write_json(temporary, {
            "run_id": run_dir.name,
            "manifest_sha256": digest(manifest_path.read_bytes()),
        })
        temporary.replace(output_root / f"cache-{cache_key}.json")
    return batch_fact(manifest_path, manifest)
