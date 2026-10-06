# Local Operations Runbook

Linen's single-machine setup has two processes: the API server and the dispatcher. The server owns the SQLite blackboard; the dispatcher schedules work and starts local worker CLIs. Run them in separate shells and keep the dispatcher workspace and target repositories on local storage.

## First setup and preflight

Install the locked project dependencies and create a private config from the example:

```sh
uv sync --project linen --locked --group dev
cp dispatch.local.example.yaml dispatch.yaml
```

Edit `dispatch.yaml` to enable only the worker CLIs installed and authenticated on this machine. Keep it private; it may contain environment values. Check the configuration, configured CLI versions, source/workspace directories, local sandbox images and optionally the database:

```sh
uv run --project linen linen ops check --config dispatch.yaml --database ~/.local/share/linen/linen.db
```

The check runs each configured CLI's version command only. It does not contact a model provider or test credentials. A missing CLI or local image appears as an unavailable check; images are never pulled.

## Start and stop

Start the API server in one shell and the dispatcher in another:

```sh
uv run --project linen linen serve --host 127.0.0.1 --port 9000
uv run --project linen linen dispatch --config dispatch.yaml
```

Use `--host 127.0.0.1` for a single-machine setup. Stop the dispatcher first with Ctrl-C and wait for it to exit, then stop the server with Ctrl-C. Do not copy or restore a database while either process is running.

For a dispatcher health check without scheduling tasks, use:

```sh
uv run --project linen linen dispatch --config dispatch.yaml --startup-healthcheck-only
```

This checks worker availability according to the configured healthcheck mode. It does not send a model request when `healthcheck_probe` is `availability`.

## Back up the blackboard

Stop both processes before creating an offline backup. The backup command refuses an active source database, requires the destination not to exist, uses SQLite's online backup API (so committed WAL data is included), verifies the copy, then publishes it atomically:

```sh
uv run --project linen linen ops backup \
  --database ~/.local/share/linen/linen.db \
  --destination ~/linen-backups/linen-2026-10-05.db
```

The destination directory must already exist. On macOS/Linux, `lsof` must be installed so the command can reject a database or WAL/SHM file held open by a process. It fails closed if that check is unavailable. Backups are created with mode `0600`; choose a directory with appropriate disk encryption and retention controls.

The SQLite file contains blackboard metadata, not the complete audit evidence set. It does not include project workspaces, target source trees, frozen source snapshots, `.linen-executions` records, or immutable analysis artifacts. Back those paths up in the same stopped-service window, preserving ownership and file permissions, and record which workspace/source copy belongs with each database backup. A database-only restore can leave artifact rows pointing at missing files; do not describe it as a complete evidence restore.

## Restore safely

Restore only to a new path. The restore command verifies the backup and refuses to replace any existing file or active database:

```sh
uv run --project linen linen ops restore \
  --backup ~/linen-backups/linen-2026-10-05.db \
  --destination ~/.local/share/linen/linen-restored.db
```

Run the preflight against the restored file and keep the current database untouched until you have inspected the result. The check verifies database integrity and local prerequisites; it cannot validate that every restored artifact reference points at its workspace file. Compare restored artifact paths and hashes with the separately restored workspace/source copies before relying on audit evidence:

```sh
uv run --project linen linen ops check --config dispatch.yaml \
  --database ~/.local/share/linen/linen-restored.db
```

To replace a live database, stop both Linen processes, preserve the old file under a new name, restore to a fresh path, and only then point the server at the restored path. The restore command itself never overwrites the old file.

## Upgrade

Before upgrading, stop both processes and make a verified backup. Review the release changes, update the checkout, then install dependencies from the checked-in lock file:

```sh
uv sync --project linen --locked --group dev
uv run --project linen --group dev pytest linen/linen/tests
uv build --project linen
```

Start the API and dispatcher again only after those checks pass. Database schema upgrades run when the server opens the database; retain the pre-upgrade backup until the upgraded instance has been checked.

## Automated checks

GitHub Actions uses Python 3.12 and Node 22, installs the locked dev dependencies, runs the pytest suite without real LLM requests, and builds the distribution.
