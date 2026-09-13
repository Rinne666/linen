from pathlib import Path
import json

import click
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


@main.command("audit-benchmark")
@click.option(
    "--expected", "expected_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True, help="JSON/YAML truth set containing an expected array",
)
@click.option(
    "--run", "run_paths", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True, required=True, help="Independent run result containing a confirmed array; pass exactly three",
)
@click.option("--min-recall", type=click.FloatRange(0, 1), default=0.0, show_default=True)
@click.option("--min-stability", type=click.FloatRange(0, 1), default=0.0, show_default=True)
def audit_benchmark(
    expected_path: Path,
    run_paths: tuple[Path, ...],
    min_recall: float,
    min_stability: float,
):
    """Compare exactly three independent audit runs against a truth set."""
    from linen.dispatcher.analysis.benchmark import evaluate_files

    try:
        report = evaluate_files(expected_path, run_paths)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    minimum_recall = report["stability"]["minimum_recall"]
    stability = report["stability"]["all_run_jaccard"]
    if minimum_recall < min_recall or stability < min_stability:
        raise click.ClickException(
            f"benchmark thresholds failed: minimum_recall={minimum_recall}, stability={stability}"
        )
