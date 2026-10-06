from pathlib import Path
import json
import sqlite3
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
):
    """Start the linen API server."""
    db.configure(Path(db_path))
    from linen.server.routers import executions

    executions.configure_workspace_root(workspace_root)
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
def audit_benchmark(
    expected_path: Path,
    run_paths: tuple[Path, ...],
    file_topic_paths: tuple[Path, ...],
    trust_boundary_paths: tuple[Path, ...],
    min_recall: float,
    min_stability: float,
):
    """Compare audit runs against a truth set, optionally in two A/B lanes."""
    from linen.dispatcher.analysis.benchmark import evaluate_files, evaluate_strategy_files

    try:
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
