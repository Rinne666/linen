# Repository Guidelines

## Project Structure & Module Organization

The Python 3.12+ package is named `linen` and lives under `linen/`.
- `linen/src/linen/server/`: FastAPI routes, Pydantic models, SQLite persistence, and services. Browser assets live in `server/static/`, including bundled vendor scripts.
- `linen/src/linen/dispatcher/`: scheduling, task execution, runtime management, worker adapters, protocol client, and Markdown prompt groups.
- `linen/linen/tests/`: regression tests and shared helpers in `conftest.py`.
- `docs/specs/` and `docs/REVIEW-MODES.md`: protocol, dispatcher design, and review behavior.
- Root `dispatch.*.example.yaml` files: configuration templates.

Keep graph consistency in the server and scheduling in the dispatcher. Preserve the dispatcher's role as the sole protocol writer for workers.

## Build, Test, and Development Commands

Run these commands from the repository root:

- `uv sync --project linen --group dev`: install application and test dependencies.
- `uv run --project linen linen serve`: start the API and browser UI at `http://127.0.0.1:9000`.
- `cp dispatch.local.example.yaml dispatch.yaml`: create local configuration; edit worker settings before starting.
- `uv run --project linen linen dispatch --config dispatch.yaml`: run the dispatcher.
- Add `--startup-healthcheck-only` to check configured worker CLIs and exit.
- `uv run --project linen --group dev pytest linen/linen/tests`: run the regression suite.
- `uv build --project linen`: build distribution artifacts.

Use `linen`, the entry point declared in `pyproject.toml`, in all commands and examples.

## Coding Style & Naming Conventions

Follow existing Python style: four-space indentation, snake_case modules/functions, PascalCase classes, and UPPER_SNAKE_CASE constants. Use type annotations for new interfaces and Pydantic models for validated contracts. No formatter or linter is configured; keep changes consistent with surrounding code and avoid unrelated reformatting.

## Testing Guidelines

Use pytest with `test_*.py` files and `test_<behavior>` functions. Reuse shared fakes, temporary paths, and mocked worker responses; regression tests should not require real LLM endpoints. Cover changed behavior, failure paths, and backward compatibility for API or database changes. No coverage threshold is configured. Append `-k review` to the test command for focused review tests.

## Commit & Pull Request Guidelines

Git history is unavailable in this snapshot. Use imperative subjects, such as `Fix review mode fallback`. Keep changes focused. PRs should describe the problem, resulting behavior, related issues, and validation; include screenshots for UI changes and update documentation when contracts or configuration change.

## Configuration Hygiene

Keep credentials, generated databases, and worker workspaces out of commits. `dispatch.yaml` is ignored; share portable settings through example files. Local workers inherit host permissions, so use a dedicated workspace and authorized targets.
