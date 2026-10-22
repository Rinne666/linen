from pathlib import Path
import hashlib
import json
import sqlite3
import tempfile
from urllib.parse import quote

import click
import requests
import uvicorn

from linen.dispatcher.logging import configure_logging
from linen.dispatcher.scheduler.loop import DispatcherLoop
from linen.server import db


@click.group()
def main():
    """linen - Fact-graph based collaborative exploration protocol."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=9000, show_default=True, help="Bind port")
@click.option(
    "--db-path",
    type=click.Path(),
    default=str(db.DEFAULT_DB),
    show_default=True,
    help="SQLite database path",
)
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
@click.option("--access-log/--no-access-log", default=True, show_default=True, help="Enable Uvicorn access log")
@click.option("--oracle-catalog", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
              help="Operator-approved independent oracle definitions and candidate bindings")
@click.option(
    "--workspace-root",
    type=click.Path(path_type=Path),
    envvar="LINEN_WORKSPACE_ROOT",
    default=None,
    help="Project workspace root used to read execution archives",
)
def serve(
    host: str,
    port: int,
    db_path: str,
    log_level: str,
    access_log: bool,
    workspace_root: Path | None,
    oracle_catalog: Path | None,
):
    """Start the linen API server."""
    db.configure(Path(db_path))
    from linen.server.routers import executions

    executions.configure_workspace_root(workspace_root)
    from linen.server.oracle_registry import configure_oracle_catalog
    configure_oracle_catalog(oracle_catalog)
    from linen.server.app import app

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Dispatcher config path",
)
@click.option("--once", is_flag=True, help="Run one scheduling iteration and exit")
@click.option(
    "--startup-healthcheck-only",
    is_flag=True,
    help="Run startup worker healthchecks and exit",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def dispatch(config_path: Path, once: bool, startup_healthcheck_only: bool, log_level: str):
    """Run the linen dispatcher."""
    configure_logging(log_level, bare=startup_healthcheck_only)
    loop = DispatcherLoop(config_path)
    try:
        if startup_healthcheck_only:
            loop.run_startup_healthchecks_only()
            return
        loop.run(once=once)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("audit-export")
@click.option("--project-id", required=True)
@click.option("--server", "server_url", default="http://127.0.0.1:9000", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="ZIP containing reports, SVG graph, snapshot, SARIF and integrity manifest")
def audit_export(project_id: str, server_url: str, output: Path):
    """Export a consistent audit snapshot, including unfinished or stopped work."""
    import io
    import zipfile

    temporary = None
    try:
        response = requests.get(
            f"{server_url.rstrip('/')}/projects/{quote(project_id, safe='')}/export",
            params={"format": "bundle"}, timeout=60,
        )
        response.raise_for_status()
        content = response.content
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            if manifest["project"]["id"] != project_id:
                raise ValueError("Bundle project does not match the requested project")
            for name in ("report.md", "summary.md", "graph.svg", "snapshot.json", "findings.sarif"):
                body = archive.read(name)
                expected = manifest["files"][name]
                if hashlib.sha256(body).hexdigest() != expected["sha256"] or len(body) != expected["bytes"]:
                    raise ValueError(f"Bundle integrity check failed: {name}")
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".linen-export-", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        temporary.replace(output)
        click.echo(json.dumps({"output": str(output.resolve()), "project_id": project_id,
                               "status": manifest["project"]["status"],
                               "graph_revision": manifest["project"]["graph_revision"],
                               "completion_ready": manifest["completion_gate"]["ready"]}, indent=2))
    except (requests.RequestException, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        raise click.ClickException(f"Audit export failed: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@main.command("audit-oracle")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--project-id", required=True)
@click.option("--candidate-id", required=True)
def audit_oracle(config_path: Path, project_id: str, candidate_id: str):
    """Run both controls of an operator-bound oracle through dispatcher protocol."""
    from linen.contracts.oracle import OracleCatalog
    from linen.dispatcher.runtime.cancellation import TaskCancellation
    from linen.dispatcher.tasks.oracle import run_oracle_task

    loop = DispatcherLoop(config_path)
    try:
        if not loop.config.audit.oracles.enabled:
            raise ValueError("audit.oracles.enabled and a trusted catalog_path are required")
        project = loop.client.get_project(project_id)
        if project.project.status != "active":
            raise ValueError("independent observations require an active project")
        definition = OracleCatalog.model_validate_json(loop.config.audit.oracles.catalog_path.read_bytes()).bound_definition(
            project_id, candidate_id, project.project.source_generation, project.project.plan_revision,
        )
        worker = loop.config.workers[0]
        outcomes = {}
        for role in ("positive", "negative"):
            project = loop.client.get_project(project_id)
            if loop._audit_project_budget_state(project) is not None:
                raise ValueError("project audit budget does not allow another oracle run")
            created = loop.client.create_intent(project_id, [candidate_id], f"@oracle:{definition.id}:{role}", "dispatcher.oracle",
                                                action="verify", target=f"registered oracle {definition.id} {role} for {candidate_id}",
                                                intent_type="poc:isolated")
            if not created.ok or not isinstance(created.data, dict) or "id" not in created.data:
                raise ValueError(f"could not create the {role} oracle obligation")
            intent_id = created.data["id"]
            project = loop.client.get_project(project_id)
            intent = next(item for item in project.intents if item.id == intent_id)
            claim = loop.client.heartbeat(project_id, intent_id, worker.name)
            if not claim.ok:
                raise ValueError("oracle obligation lease could not be acquired")
            cancellation = loop._task_cancellation(project)
            try:
                outcomes[role] = run_oracle_task(loop.config, loop.client, loop.container_manager, project, intent, worker, cancellation,
                                                  attempt=loop._next_intent_attempt(project, intent, task_type="explore"))
            finally:
                cancellation.close()
            if outcomes[role] != "success":
                break
        click.echo(json.dumps({"project_id": project_id, "candidate_id": candidate_id, "oracle_id": definition.id, "outcomes": outcomes}, indent=2))
        if set(outcomes) != {"positive", "negative"} or any(value != "success" for value in outcomes.values()):
            raise click.ClickException("Independent oracle did not complete both controls; recorded attempts are preserved")
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        loop.close()


@main.command("audit-single-agent")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--worker", "worker_name", required=True)
@click.option("--source-root", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
def audit_single_agent(config_path: Path, worker_name: str, source_root: Path, output: Path):
    """Run one fresh isolated auditor session without graph planning or peers."""
    from linen.dispatcher.analysis.single_agent import run_single_agent
    from linen.dispatcher.config import DispatchConfig

    try:
        record = run_single_agent(DispatchConfig.load(config_path), config_path, worker_name, source_root, output)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(record, ensure_ascii=False, indent=2))
    if record["status"] != "completed":
        raise click.ClickException("Single-agent execution blocked; its recorded attempt is preserved")


@main.command("coverage")
@click.option("--config", "config_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--project-id", required=True)
def coverage_report(config_path: Path, project_id: str):
    """Print coverage derived from the board; never schedules or changes tasks."""
    from linen.dispatcher.analysis.coverage import coverage_state
    from linen.dispatcher.config import DispatchConfig
    from linen.dispatcher.protocol.client import LinenClient
    from linen.dispatcher.runtime.backend import LocalBackend

    config = DispatchConfig.load(config_path)
    client = LinenClient(config.server)
    try:
        project = client.get_project(project_id)
        workdir = Path(LocalBackend(config.local).container_name(project_id))
        click.echo(json.dumps(coverage_state(project, workdir, config.audit.coverage), ensure_ascii=False, indent=2))
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        client.close()


@main.command("cost")
@click.option("--project-id", required=True, help="Project whose worker calls to summarize")
@click.option(
    "--server-url",
    default="http://127.0.0.1:9000",
    envvar="LINEN_SERVER_URL",
    show_default=True,
    help="Base URL of the linen API server",
)
def cost_report(project_id: str, server_url: str):
    """Print persisted worker call counts and durations for a project."""
    url = f"{server_url.rstrip('/')}/projects/{quote(project_id, safe='')}/cost"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not fetch project cost ledger: {exc}") from exc
    try:
        click.echo(json.dumps(response.json(), ensure_ascii=False, indent=2))
    except ValueError as exc:
        raise click.ClickException("Server returned invalid JSON for the cost ledger") from exc


@main.command("audit-benchmark")
@click.option(
    "--expected", "expected_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True, help="JSON/YAML truth set containing an expected array",
)
@click.option(
    "--run", "run_paths", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True, help="Independent run result containing a confirmed array; pass exactly three",
)
@click.option(
    "--file-topic-run", "file_topic_paths",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True, help="A/B lane using file × topic coverage; pass exactly three measured runs",
)
@click.option(
    "--trust-boundary-run", "trust_boundary_paths",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True, help="A/B lane using trust-boundary coverage; pass exactly three measured runs",
)
@click.option("--min-recall", type=click.FloatRange(0, 1), default=0.0, show_default=True)
@click.option("--min-stability", type=click.FloatRange(0, 1), default=0.0, show_default=True)
@click.option("--plan", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Registered case benchmark plan; includes blocked observations and fixed thresholds")
def audit_benchmark(
    expected_path: Path,
    run_paths: tuple[Path, ...],
    file_topic_paths: tuple[Path, ...],
    trust_boundary_paths: tuple[Path, ...],
    min_recall: float,
    min_stability: float,
    plan: Path | None,
):
    """Compare audit runs against a truth set, optionally in two A/B lanes."""
    from linen.dispatcher.analysis.benchmark import evaluate_files, evaluate_strategy_files

    try:
        if plan:
            from linen.dispatcher.analysis.benchmark import _load
            from linen.dispatcher.analysis.case_benchmark import BenchmarkPlan, TruthSet, compare_case_runs

            if file_topic_paths or trust_boundary_paths:
                raise ValueError("Case plans use three --run observations, not strategy lanes")
            registered = BenchmarkPlan.model_validate(_load(plan))
            if ((min_recall and min_recall != registered.min_recall)
                    or (min_stability and min_stability != registered.min_stability)):
                raise ValueError("Case thresholds are fixed by --plan; register changes before running")
            report = compare_case_runs(TruthSet.model_validate(_load(expected_path)), registered,
                                       [_load(path) for path in run_paths])
            click.echo(json.dumps(report, ensure_ascii=False, indent=2))
            if not report["accepted"]:
                raise click.ClickException("Case benchmark failed: " + ", ".join(
                    name for name, passed in report["checks"].items() if not passed))
            return
        if file_topic_paths or trust_boundary_paths:
            if run_paths or not file_topic_paths or not trust_boundary_paths:
                raise ValueError("A/B mode requires both strategy lanes and no plain --run inputs")
            report = evaluate_strategy_files(
                expected_path, file_topic_paths, trust_boundary_paths,
            )
            minimum_recall = min(
                value["stability"]["minimum_recall"]
                for value in report["strategies"].values()
            )
            stability = min(
                value["stability"]["all_run_jaccard"]
                for value in report["strategies"].values()
            )
        else:
            if not run_paths:
                raise ValueError("Pass three --run inputs or both A/B strategy lanes")
            report = evaluate_files(expected_path, run_paths)
            minimum_recall = report["stability"]["minimum_recall"]
            stability = report["stability"]["all_run_jaccard"]
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    if minimum_recall < min_recall or stability < min_stability:
        raise click.ClickException(
            f"benchmark thresholds failed: minimum_recall={minimum_recall}, stability={stability}"
        )


@main.command("audit-case-plan")
@click.option("--expected", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--source-root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--source-digest", help="Previously frozen source SHA-256; alternative to --source-root")
@click.option("--suite-id", required=True)
@click.option("--run-prefix", default="run", show_default=True)
@click.option("--level", type=click.Choice(["candidate", "confirmed"]), default="confirmed", show_default=True)
@click.option("--min-recall", type=click.FloatRange(0, 1), default=0.8, show_default=True)
@click.option("--min-category-recall", type=click.FloatRange(0, 1), default=0.5, show_default=True)
@click.option("--min-stability", type=click.FloatRange(0, 1), default=0.7, show_default=True)
@click.option("--max-false-positive-rate", type=click.FloatRange(0, 1), default=0.0, show_default=True)
@click.option("--min-case-coverage", type=click.FloatRange(0, 1), default=1.0, show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def audit_case_plan(expected: Path, config_path: Path, source_root: Path | None,
                    source_digest: str | None, suite_id: str, run_prefix: str, level: str,
                    min_recall: float, min_category_recall: float, min_stability: float,
                    max_false_positive_rate: float, min_case_coverage: float, output: Path):
    """Register three runs, their source, configuration, budgets and scoring rules."""
    from linen.dispatcher.analysis.artifacts import snapshot_source
    from linen.dispatcher.analysis.benchmark import _load
    from linen.dispatcher.analysis.case_benchmark import BenchmarkPlan, TruthSet, digest
    from linen.dispatcher.config import DispatchConfig

    try:
        if bool(source_root) == bool(source_digest):
            raise ValueError("Provide exactly one of --source-root and --source-digest")
        truth = TruthSet.model_validate(_load(expected))
        config = DispatchConfig.load(config_path)
        if source_root:
            with tempfile.TemporaryDirectory(prefix="linen-benchmark-source-") as temporary:
                snapshot = snapshot_source(source_root.resolve(), Path(temporary) / "source",
                                           config.audit.recon,
                                           Path(config.local.workspace_root or temporary).resolve())
                if not snapshot["files"]:
                    raise ValueError("Benchmark source contains no readable files")
                source_digest = snapshot["id"]
        plan = BenchmarkPlan(
            suite_id=suite_id, source_digest=source_digest,
            truth_digest=digest(truth.model_dump()),
            config_digest=hashlib.sha256(config_path.read_bytes()).hexdigest(),
            planned_runs=[f"{run_prefix}-{i}" for i in range(1, 4)], detection_level=level,
            min_recall=min_recall, min_category_recall=min_category_recall,
            min_stability=min_stability, max_false_positive_rate=max_false_positive_rate,
            min_case_coverage=min_case_coverage,
            max_run_records=config.audit.max_runs_per_project,
            wall_clock_budget_seconds=config.audit.wall_clock_budget_seconds,
        )
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(plan.model_dump(), ensure_ascii=False, indent=2) + "\n")
        click.echo(str(output.resolve()))
    except (ValueError, OSError) as exc:
        raise click.ClickException(f"Benchmark plan failed: {exc}") from exc


@main.command("audit-case-export")
@click.option("--project-id", help="Live project ID; optional when reading --snapshot")
@click.option("--server-url", default="http://127.0.0.1:9000", show_default=True)
@click.option("--snapshot", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Saved JSON object containing board, gate, cost and runs; performs no API calls")
@click.option("--expected", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--plan", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--run-label", required=True)
@click.option("--case-map", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--case-assessments", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--allow-incomplete", is_flag=True, help="Retain an incomplete run as a failed diagnostic observation")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def audit_case_export(project_id: str | None, server_url: str, snapshot: Path | None, expected: Path, plan: Path,
                      config_path: Path, run_label: str, case_map: Path,
                      case_assessments: Path | None, allow_incomplete: bool, output: Path):
    """Export reviewed per-case coverage and detections without guessing case IDs."""
    from linen.dispatcher.analysis.benchmark import _load
    from linen.dispatcher.analysis.case_benchmark import (
        BenchmarkPlan, TruthSet, case_observation, publish_case_export,
        validate_case_export,
    )

    base = f"{server_url.rstrip('/')}/projects/{quote(project_id or '', safe='')}"

    def fetch(suffix=""):
        response = requests.get(base + suffix, timeout=15)
        response.raise_for_status()
        return response.json()

    try:
        truth = TruthSet.model_validate(_load(expected))
        registered = BenchmarkPlan.model_validate(_load(plan))
        mapping = _load(case_map)
        assessments = _load(case_assessments) if case_assessments else {}
        if snapshot:
            saved = _load(snapshot)
            board, gate, cost, runs = (saved[k] for k in ("board", "gate", "cost", "runs"))
            if project_id and board["project"]["id"] != project_id:
                raise ValueError("Saved snapshot belongs to another project")
        else:
            if not project_id:
                raise ValueError("Provide --project-id or --snapshot")
            for _ in range(3):
                board = fetch()
                gate, cost, runs = fetch("/completion-gate"), fetch("/cost"), fetch("/runs")
                if board["project"] == fetch()["project"]:
                    break
            else:
                raise ValueError("Project changed during case export; retry after work has stopped")
        result = case_observation(
            board, gate, cost, runs, truth, registered, run_label,
            hashlib.sha256(config_path.read_bytes()).hexdigest(), mapping, assessments,
            allow_incomplete=allow_incomplete,
        )
        validate_case_export(result, truth=truth, registered=registered, board=board,
                             allow_incomplete=allow_incomplete)
        publish_case_export(result, output)
        click.echo(str(output.resolve()))
    except (requests.RequestException, ValueError, OSError, KeyError, TypeError) as exc:
        raise click.ClickException(f"Case export failed: {exc}") from exc


@main.command("audit-evaluation-export")
@click.option("--project-id", required=True)
@click.option("--server-url", default="http://127.0.0.1:9000", show_default=True)
@click.option("--case-map", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Evaluator-only JSON mapping finding fact IDs to stable case IDs")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path),
              help="Write to a new JSON file instead of stdout")
def audit_evaluation_export(project_id: str, server_url: str, case_map: Path | None, output: Path | None):
    """Export a completed run's quality, coverage and measured cost for evaluation."""
    from linen.dispatcher.analysis.evaluation import observation

    base = f"{server_url.rstrip('/')}/projects/{quote(project_id, safe='')}"

    def fetch(suffix=""):
        response = requests.get(base + suffix, timeout=15)
        response.raise_for_status()
        return response.json()

    try:
        labels = json.loads(case_map.read_text(encoding="utf-8")) if case_map else None
        for _ in range(3):
            board = fetch()
            gate = fetch("/completion-gate")
            cost = fetch("/cost")
            after = fetch()
            if board["project"] == after["project"]:
                result = observation(board, gate, cost, labels)
                break
        else:
            raise ValueError("Project changed during export; retry after work has stopped")
        content = json.dumps(result, ensure_ascii=False, indent=2)
        if output:
            with output.open("x", encoding="utf-8") as stream:
                stream.write(content + "\n")
            click.echo(str(output.resolve()))
        else:
            click.echo(content)
    except (requests.RequestException, ValueError, OSError, KeyError) as exc:
        raise click.ClickException(f"Evaluation export failed: {exc}") from exc


@main.command("audit-ablation")
@click.option("--expected", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--baseline", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--variant", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--min-recall", type=click.FloatRange(0, 1), default=0.8, show_default=True)
@click.option("--max-recall-loss", type=click.FloatRange(0, 1), default=0.0, show_default=True)
@click.option("--require-fewer-facts", is_flag=True, help="Require a strict Fact reduction as well as Intent reduction")
@click.option("--allow-partial-coverage", is_flag=True, help="Compare incomplete recorded coverage explicitly; not a full-coverage acceptance")
def audit_ablation(expected: Path, baseline: tuple[Path, ...], variant: tuple[Path, ...],
                   min_recall: float, max_recall_loss: float, require_fewer_facts: bool,
                   allow_partial_coverage: bool):
    """Accept simplification only when measured quality and coverage are preserved."""
    from linen.dispatcher.analysis.benchmark import expected_ids
    from linen.dispatcher.analysis.evaluation import compare_ablations, load_observation

    try:
        report = compare_ablations(expected_ids(expected), [load_observation(p) for p in baseline],
                                   [load_observation(p) for p in variant], min_recall=min_recall,
                                   max_recall_loss=max_recall_loss, require_fewer_facts=require_fewer_facts,
                                   allow_partial_coverage=allow_partial_coverage)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["accepted"]:
        raise click.ClickException("Ablation failed: " + ", ".join(k for k, ok in report["checks"].items() if not ok))


@main.group()
def ops():
    """Inspect prerequisites and safely back up or restore local databases."""


@ops.command("check")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--database", type=click.Path(dir_okay=False, path_type=Path))
def ops_check(config_path: Path, database: Path | None):
    from linen.operations import inspect_environment, operations_json

    result = inspect_environment(config_path, database_path=database)
    click.echo(operations_json(result))
    if result.get("ok") is False or not result.get("config", {}).get("valid"):
        raise click.ClickException("Environment preflight failed; inspect the checks above")


@ops.command("backup")
@click.option("--database", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--destination", type=click.Path(dir_okay=False, path_type=Path), required=True)
def ops_backup(database: Path, destination: Path):
    from linen.operations import backup_database, operations_json

    try:
        click.echo(operations_json(backup_database(database, destination)))
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        raise click.ClickException(str(exc)) from exc


@ops.command("restore")
@click.option("--backup", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--destination", type=click.Path(dir_okay=False, path_type=Path), required=True)
def ops_restore(backup: Path, destination: Path):
    from linen.operations import restore_database, operations_json

    try:
        click.echo(operations_json(restore_database(backup, destination)))
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        raise click.ClickException(str(exc)) from exc
