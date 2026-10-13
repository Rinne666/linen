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

For dynamic Technical Confirmation, register an operator-owned oracle catalog
on both server and dispatcher. See [independent oracles](INDEPENDENT-ORACLES.md)
for the supported transport, isolation, compatibility change and real Docker
test. A working target container or a model-produced PoC verdict does not
establish this capability. Preflight reviewer images separately from host CLIs;
they can contain incompatible CLI versions despite successful host probes.
Isolated Claude review grants reads of `/repo` and `/input` explicitly while
retaining its read-only tool restrictions and read-only mounts. Native output
schemas constrain both Recon category and coverage-review execute/conclude
responses; exact frozen-source citations still undergo the ordinary validator.

Scope candidates receive one early independent source, threat-model and impact
assessment before proof construction. The input is bound to the candidate,
current policy evidence and plan. A decisive non-vulnerability assessment stops
further proof obligations; a reportable or uncertain assessment continues to the
static package and registered dynamic gates. This assessment cannot confirm a
finding. Changed candidate or policy inputs reopen assessment; unrelated branch
writes do not. An unresolved first assessment does not create an endless review
loop: proof collection can continue to supply the missing evidence.

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

## Recover from execution failures

Terminal CLI connection errors, including Codex's `workspace routing discovery
failed`, open a worker provider circuit. The first two failures defer new model
calls for 60 and 120 seconds. The third failure pauses the affected project and
blocks further model calls on that worker until an explicit project resume.
Deterministic tasks that do not require a provider remain eligible for worker
selection; a stopped project still requires resume before any new work starts.
Successful model responses clear the worker's transport failure count. Recovered
stream retries and error strings quoted in assistant text do not open a circuit.

Reason also has a project-level limit for ordinary execution, rejection, crash,
and result-validation failures, even though it has no Intent to attach an error
to. Consecutive failures use the same delays and pause after the third failure.
Before that pause, healthy Explore and Review work can continue. A successful
Reason result clears this count; routine graph changes and priority wakeups do
not reset it. A new source generation or plan revision starts a new Reason
failure episode.

Reason proposals are checked against the nodes and edges in their read
projection. Changes to read evidence, new reviews/contradictions of read Facts,
or a new source/plan revision invalidate the result. Unrelated branch updates,
stage bookkeeping and heartbeats do not discard an otherwise current proposal.
Completion still requires the full graph revision and the server completion
gate. A valid outdated response returns `stale`; only its observed event cursor
is acknowledged, so newer evidence remains available to wake strategy.

Reason can return `data.wait` with visible open `intent_ids` and/or selected
`event_types`, a concrete `reason`, and `max_wait_seconds` (1–900). Multiple
Intent IDs default to waiting for all results; `intent_policy: any` explicitly
wakes on the first result. The server
persists the condition, source/plan basis, observed cursor and deadline when
the dispatcher releases its authenticated lease. Explore/Review continue while
Reason waits. Target conclusion/blocking failure, a matching new event, human
hint, strategy replan, technical confirmation, generation change or deadline
wakes Reason. Old event batches and run lifecycle churn alone do not wake it.
Legacy empty data is bound to projected pending Intents for 300 seconds, or
new evidence for 60 seconds when none remain. Waiting on an already blocked
Intent is rejected; Reason must choose retry/abandon. A wait is workflow state
and never evidence of a disposed lead or a completed audit.
Valid waits return `waiting` and clear execution-failure/no-op streaks. They
do not produce a `reason_noop_streak` stall event; a legacy empty response
with no pending work still returns `noop` for bounded stall detection.

Scope-gated Intents are excluded from actionable-work counts. They cannot
suppress a strategy pass merely by remaining in the graph, and a wait whose
only targets are withheld by the scope gate is rejected as non-progressing.
Read-only attestation reviewers receive dispatcher integrity checks that
re-read policy artifacts and frozen documents and recompute the manifest,
snapshot and captured-config digests. Scope adjudication is bound back to the
same policy bytes. A failed check blocks the task before a model call. These
mechanical checks supply no Review verdict; reviewers still independently
judge document content, configured-source scope and contradictions.

On macOS `runtime.prevent_idle_sleep` defaults to `true`: the dispatcher owns
a `caffeinate -i -w <dispatcher-pid>` helper until shutdown. This prevents idle
sleep without changing system settings or keeping the display on. Explicit
sleep and lid closure can still suspend workers. Set it to `false` to disable.
Other platforms do not launch a helper. The helper's process is logged; a
failure to launch is reported as a warning.

Reason heartbeat 409 details identify `reason_lease_expired`,
`reason_lease_not_claimed`, `reason_worker_mismatch` or `reason_token_mismatch`.
Expiry is retained as a server event with a lease digest, worker and last
heartbeat. The heartbeat log includes wall time since its last success; the
execution cancellation code retains the specific cause. A lost lease still
cancels execution and is never silently reclaimed by the old worker.

Circuits and Reason failure counts are saved in
`<workspace_root>/.linen-provider-circuits.json` and survive dispatcher restarts.
After repairing connectivity or the reported contract error, verify a real
response using the same CLI and environment, then resume the project from the
UI. Resume clears only the corresponding recorded failure episode; an older
resume event cannot clear a later block. Resume does not reset an expired audit
deadline, extend the run budget, or resolve unrelated blocked Intents.

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
