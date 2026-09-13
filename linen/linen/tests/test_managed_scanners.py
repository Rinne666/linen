from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from linen.dispatcher.analysis import audit_graph
from linen.dispatcher.analysis import coverage
from linen.dispatcher.analysis.external_scanners import (
    GITLEAKS_INTENT,
    OSV_INTENT,
    SPOTBUGS_INTENT,
    TRIVY_INTENT,
    run_scan,
    scanner_specs,
)
from linen.dispatcher.analysis.policy import SCAN_INTENT_DESCRIPTION
from linen.dispatcher.analysis.semgrep import digest
from linen.dispatcher.config import (
    GitleaksConfig,
    OsvScannerConfig,
    SpotBugsConfig,
    TrivyConfig,
)
from linen.dispatcher.runtime.backend import LocalBackend
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.scheduler.loop import DispatcherLoop

from test_audit_pipeline import api, config, manifest, project
from test_audit_graph_pipeline import _approve, _conclude


def _sarif(scanner: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": scanner,
                "rules": [{"id": "rule-1", "properties": {"security-severity": "8.0"}}],
            }},
            "results": [{
                "ruleId": "rule-1",
                "level": "error",
                "message": {"text": "unverified candidate"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/App.java"},
                    "region": {"startLine": 1},
                }}],
            }],
        }],
    }


@pytest.fixture
def configured_scanners(tmp_path):
    plugin = tmp_path / "findsecbugs-plugin.jar"
    plugin.write_bytes(b"plugin")
    cfg = config(tmp_path, scan=True, mode="scope")
    cfg.audit.spotbugs = SpotBugsConfig(enabled=True, plugin=plugin, cache=False)
    cfg.audit.osv = OsvScannerConfig(enabled=True, cache=False)
    cfg.audit.gitleaks = GitleaksConfig(enabled=True, cache=False)
    cfg.audit.trivy = TrivyConfig(enabled=True, cache=False)
    return cfg


@pytest.mark.parametrize(
    ("scanner_name", "expected_arg"),
    [
        ("spotbugs-findsecbugs", "-bugCategories"),
        ("osv-scanner", "--format=sarif"),
        ("gitleaks", "--redact=100"),
        ("trivy", "vuln,misconfig,secret"),
    ],
)
def test_external_scanners_emit_uniform_scan_batches(
    configured_scanners, tmp_path, monkeypatch, scanner_name, expected_arg,
):
    repo = tmp_path / f"repo-{scanner_name}"
    (repo / "src").mkdir(parents=True)
    (repo / "src/App.java").write_text("class App {}\n")
    classes = repo / "module/target/classes"
    classes.mkdir(parents=True)
    (classes / "App.class").write_bytes(b"bytecode")
    spec = next(spec for spec in scanner_specs(configured_scanners.audit) if spec.name == scanner_name)
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.shutil.which",
        lambda executable: f"/fake/{executable}",
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="scanner 1.0\n", stderr=""),
    )
    calls = []

    def execute(source: Path, argv: list[str]) -> ProcessResult:
        calls.append((source, argv))
        report = json.dumps(_sarif(scanner_name))
        if scanner_name == "spotbugs-findsecbugs":
            target = next(value.removeprefix("-sarif=") for value in argv if value.startswith("-sarif="))
        else:
            flag = {
                "osv-scanner": "--output-file",
                "gitleaks": "--report-path",
                "trivy": "--output",
            }[scanner_name]
            target = argv[argv.index(flag) + 1]
        Path(target).write_text(report)
        # OSV-Scanner returns 1 when valid scan output contains findings.
        return ProcessResult(1 if scanner_name == "osv-scanner" else 0, "", "")

    fact = run_scan(repo, tmp_path / "analysis", spec, execute)
    path, record = manifest(fact)

    assert fact["type"] == "scan_batch"
    assert record["status"] == "completed"
    assert record["scanner"]["name"] == scanner_name
    assert record["candidate_count"] == 1
    assert expected_arg in record["command"]
    assert json.loads((path.parent / "candidates.json").read_text())[0]["status"] == "unverified"
    assert calls[0][0] != repo
    assert (calls[0][0] / "src/App.java").read_text() == "class App {}\n"
    if scanner_name == "spotbugs-findsecbugs":
        assert "findsecbugs-plugin.jar" in record["artifact_hashes"]


def test_spotbugs_never_builds_target_and_reports_missing_bytecode(configured_scanners, tmp_path, monkeypatch):
    repo = tmp_path / "source-only"
    repo.mkdir()
    (repo / "pom.xml").write_text("<project/>\n")
    spec = next(
        spec for spec in scanner_specs(configured_scanners.audit)
        if spec.name == "spotbugs-findsecbugs"
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.shutil.which", lambda _: "/fake/spotbugs",
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="SpotBugs 1.0", stderr=""),
    )
    called = False

    def execute(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("scanner must not run without bytecode")

    _, record = manifest(run_scan(repo, tmp_path / "analysis", spec, execute))

    assert record["status"] == "failed"
    assert "will not execute untrusted Maven/Gradle builds" in record["errors"][0]["message"]
    assert not called


def test_spotbugs_non_jvm_snapshot_is_explicitly_not_applicable(
    configured_scanners, tmp_path, monkeypatch,
):
    repo = tmp_path / "python-only"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    spec = next(
        spec for spec in scanner_specs(configured_scanners.audit)
        if spec.name == "spotbugs-findsecbugs"
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.shutil.which", lambda _: "/fake/spotbugs",
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="SpotBugs 1.0", stderr=""),
    )

    fact = run_scan(
        repo,
        tmp_path / "analysis-not-applicable",
        spec,
        lambda *_: (_ for _ in ()).throw(AssertionError("SpotBugs must not execute")),
    )
    path, record = manifest(fact)

    assert record["status"] == "completed"
    assert record["applicability"]["status"] == "not_applicable"
    assert "not_applicable" in fact["description"]
    assert json.loads((path.parent / "candidates.json").read_text()) == []


def test_hypothesis_scanners_are_selected_from_a_bounded_trusted_registry(api, configured_scanners):
    _, client = api
    board = project(api, audit_mode="hypothesis")
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = configured_scanners
    loop.client = client
    loop.container_manager = LocalBackend(configured_scanners.local, client)

    assert not loop._materialize_audit_intents(board)
    choices = audit_graph.selectable_skill_choices(
        board,
        Path(loop.container_manager.ensure_running(board.project.id)),
        configured_scanners.audit,
    )
    assert {choice["skill_id"] for choice in choices} == {
        "security.semgrep",
        "security.spotbugs-findsecbugs",
        "security.osv-scanner",
        "security.gitleaks",
        "security.trivy",
    }
    _, proposals = audit_graph.validate_model_intents(
        {
            "accepted": True,
            "data": {
                "skills": [{
                    "skill_id": "security.semgrep",
                    "reason": "Run the broad static baseline before deeper hypothesis tracing.",
                }],
            },
        },
        board,
        expected_revision=board.project.graph_revision,
        max_intents=2,
        skill_choices=choices,
    )
    assert proposals[0]["description"] == SCAN_INTENT_DESCRIPTION
    assert proposals[0]["type"] == "search:skill"


def test_failed_scanner_preserves_root_error_without_missing_sarif_noise(
    configured_scanners, tmp_path, monkeypatch,
):
    repo = tmp_path / "repo-failed"
    repo.mkdir()
    (repo / "requirements.txt").write_text("example==1\n")
    spec = next(spec for spec in scanner_specs(configured_scanners.audit) if spec.name == "trivy")
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.shutil.which", lambda _: "/fake/trivy",
    )
    monkeypatch.setattr(
        "linen.dispatcher.analysis.external_scanners.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="Trivy 1.0", stderr=""),
    )

    fact = run_scan(
        repo,
        tmp_path / "analysis-failed",
        spec,
        lambda *_: ProcessResult(1, "", "failed to download vulnerability DB: Bad Gateway"),
    )
    path, record = manifest(fact)

    assert record["status"] == "failed"
    assert record["execution"]["returncode"] == 1
    assert "Bad Gateway" in record["errors"][0]["message"]
    assert all("raw.sarif" not in error["message"] for error in record["errors"])
    assert json.loads((path.parent / "candidates.json").read_text()) == []


def test_legacy_pre_execution_scanner_failure_does_not_exhaust_retry_budget(
    api, configured_scanners, tmp_path,
):
    _, client = api
    current = project(api, audit_mode="hypothesis")
    pid = current.project.id
    workdir = Path(LocalBackend(configured_scanners.local, client).ensure_running(pid))
    previous = "origin"
    for index in range(configured_scanners.audit.trivy.max_attempts):
        run = workdir / ".linen-analysis" / f"legacy-trivy-{index}"
        run.mkdir(parents=True)
        record = {
            "schema_version": 1,
            "status": "failed",
            "scanner": {"name": "trivy", "label": "Trivy"},
            "command": ["trivy", "fs", "."],
            "errors": [{"message": "raw.sarif does not exist"}],
            "artifact_hashes": {},
        }
        (run / "manifest.json").write_text(json.dumps(record))
        evidence = (
            f"artifact: {run / 'manifest.json'}\n"
            f"manifest_sha256: {digest((run / 'manifest.json').read_bytes())}\n"
            "scanner: trivy\nstatus: failed"
        )
        previous = _conclude(
            client, pid, [previous], TRIVY_INTENT, "scan_batch", evidence,
        )
        _approve(client, pid, previous)

    choices = audit_graph.selectable_skill_choices(
        client.get_project(pid), workdir, configured_scanners.audit,
    )
    retry = next(item for item in choices if item["description"] == TRIVY_INTENT)
    assert retry["from"] == ["origin", previous]


def test_scope_fans_out_and_gates_each_scanner_by_identity(api, configured_scanners, tmp_path):
    _, client = api
    current = project(api, audit_mode="scope")
    pid = current.project.id
    backend = LocalBackend(configured_scanners.local, client)
    workdir = Path(backend.ensure_running(pid))
    repo = tmp_path / "scope-repo"
    repo.mkdir()
    (repo / "App.java").write_text("class App {}\n")
    plan = coverage.create_plan(repo, workdir, configured_scanners.audit.coverage)
    plan_id = _conclude(
        client, pid, ["origin"], coverage.PLAN_INTENT, plan["type"], plan["evidence"],
    )
    _approve(client, pid, plan_id)

    current = client.get_project(pid)
    choices = audit_graph.selectable_skill_choices(current, workdir, configured_scanners.audit)
    assert {choice["description"] for choice in choices} == {
        SCAN_INTENT_DESCRIPTION,
        SPOTBUGS_INTENT,
        OSV_INTENT,
        GITLEAKS_INTENT,
        TRIVY_INTENT,
    }
    blockers = audit_graph.scope_blockers(current, workdir, configured_scanners.audit, [])
    for label in ("Semgrep", "SpotBugs + FindSecBugs", "OSV-Scanner", "Gitleaks", "Trivy"):
        assert any(label in blocker for blocker in blockers)


def test_startup_rejects_enabled_missing_scanner(configured_scanners, monkeypatch):
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = configured_scanners
    monkeypatch.setattr(
        "linen.dispatcher.scheduler.loop.shutil.which",
        lambda executable: None if executable == "trivy" else f"/fake/{executable}",
    )

    with pytest.raises(RuntimeError, match="Trivy executable `trivy`"):
        loop._run_managed_scanner_check()
