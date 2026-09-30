"""Execute approved semantic grep operations in the offline review sandbox."""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

from linen.dispatcher.config import ReviewSandboxConfig
from linen.dispatcher.runtime.cancellation import TaskCancellation
from linen.dispatcher.runtime.heartbeat import HeartbeatLease
from linen.dispatcher.runtime.review_sandbox import ReviewSandboxBackend


MAX_OUTPUT_BYTES = 16_000_000
RUNNER_PATH = Path(__file__).with_name("semantic_recipe_runner.py")


class SemanticRecipeExecutionError(RuntimeError):
    """The fixed isolated recipe runner failed or returned invalid output."""


def run_frozen_grep(
    operations: list[dict[str, Any]],
    source: Path,
    snapshot: dict[str, Any],
    workdir: Path,
    sandbox_config: ReviewSandboxConfig,
    cancellation: TaskCancellation,
    lease: HeartbeatLease,
    *,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Run the fixed literal-search program with immutable source and no egress."""
    if (
        not sandbox_config.enabled
        or not sandbox_config.image
        or sandbox_config.network != "none"
        or sandbox_config.env_allowlist
    ):
        raise SemanticRecipeExecutionError(
            "Dynamic semantic grep requires an enabled local sandbox image, network=none, "
            "and an empty environment allowlist"
        )
    if not RUNNER_PATH.is_file():
        raise SemanticRecipeExecutionError("The dispatcher semantic recipe runner is missing")
    if len(operations) > 6:
        raise SemanticRecipeExecutionError("Semantic recipe operation limit exceeded")

    root = workdir.resolve(strict=True)
    analysis_root = root / ".linen-semantic-recipes"
    if analysis_root.is_symlink():
        raise SemanticRecipeExecutionError("Refusing a symlinked semantic recipe work root")
    analysis_root.mkdir(mode=0o700, exist_ok=True)
    if analysis_root.resolve().parent != root:
        raise SemanticRecipeExecutionError("Semantic recipe work root escaped the project")
    run_root = analysis_root / "runtime"
    if run_root.is_symlink():
        raise SemanticRecipeExecutionError("Refusing a symlinked semantic recipe runtime")
    run_root.mkdir(mode=0o700, exist_ok=True)
    if run_root.resolve().parent != analysis_root.resolve():
        raise SemanticRecipeExecutionError("Semantic recipe runtime escaped its work root")

    backend = ReviewSandboxBackend(
        sandbox_config,
        source,
        snapshot,
        run_root,
        inputs={
            "semantic_recipe.json": json.dumps(
                {"operations": operations}, ensure_ascii=True, separators=(",", ":"),
            ).encode("utf-8"),
            "semantic_recipe_runner.py": RUNNER_PATH.read_bytes(),
        },
    )
    process = backend.build_exec_process(
        "",
        {},
        ["/usr/bin/python3", "-I", "/input/semantic_recipe_runner.py", "/input/semantic_recipe.json"],
        timeout_seconds=timeout_seconds,
    )
    try:
        if cancellation.is_cancelled or lease.failure is not None:
            raise SemanticRecipeExecutionError("Semantic recipe cancelled before sandbox start")
        process.start()
        cancellation.attach_process(process)
        lease.attach_process(process)
        result = process.communicate(timeout_seconds)
    except SemanticRecipeExecutionError:
        raise
    except Exception as exc:
        raise SemanticRecipeExecutionError(
            f"Isolated semantic recipe execution failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        cancellation.attach_process(None)
        lease.attach_process(None)
        if backend.last_process is not None:
            shutil.rmtree(backend.last_process.run_dir, ignore_errors=True)

    if result.timed_out:
        raise SemanticRecipeExecutionError(
            f"Isolated semantic recipe exceeded {timeout_seconds}s"
        )
    if result.cancelled or cancellation.is_cancelled:
        raise SemanticRecipeExecutionError("Isolated semantic recipe was cancelled")
    if lease.failure is not None:
        raise SemanticRecipeExecutionError("Semantic recipe lost its dispatcher heartbeat")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()[-2000:]
        raise SemanticRecipeExecutionError(f"Fixed semantic recipe runner failed: {detail}")
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise SemanticRecipeExecutionError("Semantic recipe output exceeded its size limit")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SemanticRecipeExecutionError("Semantic recipe runner returned invalid JSON") from exc
    if (
        not isinstance(output, dict)
        or set(output) != {"operations"}
        or not isinstance(output["operations"], list)
        or len(output["operations"]) != len(operations)
    ):
        raise SemanticRecipeExecutionError("Semantic recipe runner returned an invalid result shape")
    for index, operation in enumerate(output["operations"]):
        if (
            not isinstance(operation, dict)
            or set(operation) != {"operation", "files_searched", "matches", "skipped_long_lines"}
            or operation["operation"] != index
            or type(operation["files_searched"]) is not int
            or operation["files_searched"] < 0
            or type(operation["skipped_long_lines"]) is not int
            or operation["skipped_long_lines"] < 0
            or not isinstance(operation["matches"], list)
            or len(operation["matches"]) > operations[index]["max_results"]
        ):
            raise SemanticRecipeExecutionError("Semantic recipe runner returned invalid operation data")
        for match in operation["matches"]:
            if (
                not isinstance(match, dict)
                or set(match) != {"file", "line", "code"}
                or not isinstance(match["file"], str)
                or type(match["line"]) is not int
                or match["line"] < 1
                or not isinstance(match["code"], str)
            ):
                raise SemanticRecipeExecutionError("Semantic recipe runner returned an invalid match")
    process_handle = backend.last_process
    return {
        "operations": output["operations"],
        "sandbox": {
            "backend": "docker",
            "image_id": process_handle.image_id if process_handle is not None else None,
            "network": "none",
            "source_mount": "/repo",
            "source_read_only": True,
            "runner": "dispatcher.semantic_recipe_runner/v1",
        },
    }
