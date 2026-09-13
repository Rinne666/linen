# Blackboard audit pipeline

The audit pipeline retains Fact, Intent, Hint, Review and the existing task loop.
Tools never write the board. A managed scan executes inside an Explore task;
the dispatcher concludes its intent with one `scan_batch` fact. Reason reads
that batch and selects candidates for ordinary trace/validate intents.

## Enable

Run from the repository root with Python 3.12+ and uv:

```bash
uv sync --project linen --group dev
cp dispatch.vuln.example.yaml dispatch.yaml
```

Edit the target repository, workspace and worker CLIs in `dispatch.yaml`.
Enable the managed scanners that are installed on the dispatcher host:

```yaml
audit:
  enabled: true
  graph_reason:
    enabled: true
    timeout: 120
    max_intents: 3
    max_attempts_per_revision: 2
  semantic:
    enabled: true
    architecture: true
    authorization: true
    state_concurrency: true
    cross_service: true
    contract: true
    hypothesis_profiles: [backward, contradiction, attack-composition]
    variant_search: true
    max_verify_attempts: 2
  semgrep:
    enabled: true
    executable: semgrep
    rules: linen/rules/audit-baseline.yaml
    timeout: 300
    max_target_bytes: 1000000
    exclude: [".git", ".venv", "node_modules"]
    cache: true
  spotbugs:
    enabled: true
    executable: spotbugs
    plugin: /absolute/path/to/findsecbugs-plugin.jar
    # Linen scans existing bytecode and never runs a target build implicitly.
    targets: ["**/target/classes", "**/build/classes/java/main"]
    timeout: 600
  osv:
    enabled: true
    executable: osv-scanner
    recursive: true
  gitleaks:
    enabled: true
    executable: gitleaks
    redact_percent: 100
  trivy:
    enabled: true
    executable: trivy
    scanners: [vuln, misconfig, secret]
```

Rules must be an existing **local file**, resolved relative to the dispatcher's
working directory. The included Python/Java/JavaScript rules are a candidate
baseline, not a comprehensive security ruleset. Replace or extend them with
reviewed rules appropriate to the target. Managed scans disable metrics, version
checks and `nosem` suppression.
They do not run autofix or install tools. Startup fails clearly when an enabled
scanner executable or the configured FindSecBugs plugin is unavailable.

SpotBugs is bytecode-based. Build the target in a separate trusted or isolated
build lane and point `spotbugs.targets` at the resulting class directories.
Linen never executes Maven or Gradle automatically because repository build
plugins are executable code. A snapshot with no JVM source, bytecode, or build
markers records an explicit reviewed `not_applicable` result; a JVM project
without bytecode still fails and remains visible as incomplete. Gitleaks uses
`dir` mode against the frozen current tree; Git-history scanning is outside the
canonical scope snapshot.

At least one worker must support `review`. By default audit workers do not
support `bootstrap`; create projects with `bootstrap_enabled: false` and
`audit_mode: scope` so the server can enforce the audit completion gate.

```bash
uv run --project linen linen serve
# In another terminal:
uv run --project linen linen dispatch --config dispatch.yaml
```

Code deterministically owns the enabled scanner set, applicability, retry budget,
source anchors, adapters, and required stage ledger. The AuditGraph LLM may select
exactly one pending registered Skill per pass and explain its ordering choice.
The dispatcher then materializes the exact reserved `search` intent
(`@analysis:semgrep`, `@analysis:spotbugs-findsecbugs`, `@analysis:osv-scanner`,
`@analysis:gitleaks`, or `@analysis:trivy`). Scope scans wait for the reviewed
coverage plan and share its canonical snapshot. No model-supplied shell command,
plugin path, rule location, receipt, or not-applicable claim is trusted.

When `audit.graph_reason.enabled=true`, the scheduler adds a constrained
interpretation pass after deterministic graph work is exhausted. It reuses a
worker that already supports `reason` and the existing project-level Reason
lease, but starts a fresh conversation for the current `graph_revision`. The
model may only propose typed semantic verification Intents or select one Skill
from the pending trusted registry. It cannot complete
the project, create reserved mechanical descriptions, reference missing or
terminal Facts, or write the protocol directly. Invalid, stale, duplicate, or
oversized batches are discarded without changing the blackboard. Attempts are
bounded per revision; normal Reason remains responsible for completion.

When `audit.semantic.enabled=true`, the dispatcher also materializes a bounded
semantic branch from the reviewed coverage plan. Existing Explore workers start
a fresh conversation for exactly one registered recipe from
`prompts/vuln_audit/audit_recipes.yaml`: architecture, authorization, state and
concurrency, cross-service trust, local contracts, three hypothesis-generation
lenses, candidate verification, and confirmed-root-cause variant search. The
whole bundle is never sent to a worker; the dispatcher composes only the common
policy plus the selected recipe and frozen input Facts. Results must carry exact
snapshot citations, become ordinary draft Facts, and pass the existing Review
flow. A reviewed `semantic_summary` is required by scope completion when this
feature is enabled. This adds no worker role, mutable side queue, or model write
access to the protocol.

## Artifacts and evidence

Each run writes `<project-workdir>/.linen-analysis/<run-id>/`:

- `source/`: copied regular files, with per-file hashes in the manifest.
- `rules.yaml`: the exact Semgrep rules used for a Semgrep run.
- `findsecbugs-plugin.jar`: the exact plugin used for a SpotBugs run.
- `raw.sarif`, optional scanner-native reports, `stdout.log`, and `stderr.log`: raw outputs.
- `candidates.json`: deduplicated, **unverified** alerts with locations and flows.
- `manifest.json`: source/rule hashes, tool version, command, execution state,
  scanned/skipped inputs and artifact hashes.

Every manifest records the scanner identity independently, so a completed batch
from one tool cannot satisfy another tool's scope gate. Source symlinks,
configured exclusions and oversized files are recorded as
skipped. The scanner may additionally skip unsupported or ignored files; inspect
`coverage` in the manifest. The copied files define the snapshot, which can
differ from a concurrently changing live checkout. Use an idle checkout when
a coherent commit-level snapshot is required.

`completed` means the scanner executed without reported errors on its selected
inputs, or that a deterministic applicability check explicitly resolved that
tool as not applicable. The latter is separately recorded in `applicability` and
does **not** masquerade as an executed scan. Neither means the entire repository
is safe. Partial runs, timeouts, invalid outputs and missing tools produce
partial/failed batches and retain the bounded scanner error output in the
manifest. They are not cached. Source content, rules, scanner version and
configuration affect the cache key; saved inputs and outputs are hash-checked
before reuse. Fingerprints deduplicate identical alerts within a snapshot, not
across line-shifting edits.

Reason should read the candidate artifact and propose one trace/validate intent
per selected fingerprint, with `from` referencing the batch. Review a batch as
an execution record, not as a vulnerability. Evidence should identify whether
it refers to the saved snapshot or the live repository.

Every Pi process also writes a replay record under `.linen-executions`. Semantic
calls include `recipe_id`, `recipe_label`, and `recipe_version`; the UI shows
them beside the phase
and keeps the exact `pi -p` prompt and response available on expansion. Older
records without recipe metadata remain readable.

## Completion and reviews

`audit.enabled` enables the audit capabilities, while each project's
`audit_mode` selects its actual workflow and prompt policy. A `scope` project
requires a reviewed coverage plan, one completed and reviewed batch plus terminal
candidate summary for every enabled scanner, every cell covered, no open intents
and no unresolved findings. A `hypothesis` project retains every enabled baseline
scanner as a deterministic required stage, while the AuditGraph LLM chooses their
execution order from the trusted registry; it keeps hypothesis-driven completion
semantics.
The dispatcher additionally requires a vulnerability reference, evidence on
every supporting fact, `triaged` status and firm/certain VALID reviews throughout
the ancestor chain. Origin is exempt. Blocked completion writes a deduplicated
Hint explaining what is missing.

Projects created with `audit_mode: hypothesis` or `audit_mode: scope` also have
a server-side completion boundary: the terminal vulnerability and every ancestor
must be evidence-backed, `triaged` and firm/certain VALID-reviewed. This prevents
a direct API call from completing an audit with a `draft` final finding. The
dispatcher remains responsible for filesystem-backed scope-cell verification.
Lifecycle checks establish evidence presence and review state, not proof that
the reported code path is correct or that all manual citations match a snapshot.

The server exposes a structured Completion Gate rather than inferring completion
from an empty queue. It requires terminal open-work/error state, satisfied required
stages, stage-bound hash-verified Skill receipts, decisive independent reviews,
and a connected reviewed terminal evidence chain. An active project can therefore
be `idle_attention_required`; once the Gate becomes ready, the dispatcher commits
completion atomically and freezes the final report snapshot.

Review diagnostics survive database storage, project reads and YAML exports.
YAML also includes fact status, reviews and intent IDs. Existing databases gain
an additive JSON diagnostics column; old API requests remain valid. The managed
`vuln_audit` worker contract is stricter: devil's-advocate, cold-verifier and
contradiction reviews must return their full mode-specific diagnostics;
scanner/triage execution records use `attestation_check`, while module and final
summaries use `summary_check`. Missing keys reject the worker output instead of
silently storing an unsubstantiated verdict.

An initial `NEEDS_REVIEW` or tentative verdict no longer leaves a Fact permanently
stuck. The deterministic graph creates at most one follow-up review in a different
mode (`contradiction-reasoner` after uncertainty, otherwise `cold-verifier`). A
later firm/certain VALID resolves the Fact; any INVALID remains fail-fast. This is
a two-review budget, not an unbounded model debate.

Cold reviews omit graph history, candidate evidence and prior intent reasoning
from their supplied context. With sandboxing disabled they still share host
permissions; enable the Docker backend below for filesystem isolation. Failed
reproduction without a concrete blocker should result in NEEDS_REVIEW.

## Whole-repository coverage planning

When `audit.scope_adjudication.enabled` is set, coverage planning is preceded
by a reviewed `policy_evidence → scope_adjudication` chain. The dispatcher
freezes configured repository documents and HTTPS policy/advisory responses,
records inaccessible sources as gaps, and then gives an existing Explore worker
one constrained recipe. Host validation checks every quotation against the
frozen bytes. Each policy exclusion carries citations and revival conditions;
it controls eligibility only and never changes a technical Fact to
`false_positive`.

```yaml
audit:
  scope_adjudication:
    enabled: true
    local_paths: [SECURITY.md, .github/SECURITY.md, README.md]
    policy_urls: ["https://example.org/security/rewards"]
    github_advisories: true
```

Remote collection rejects non-HTTPS credentials/fragments, non-public address
targets, oversized responses, and unbounded redirects. Failures remain visible
in the immutable evidence manifest and force partial adjudication coverage.

```yaml
audit:
  enabled: true
  mode: scope
  coverage:
    topics: [input-validation, authorization, dangerous-operations]
    files_per_cell: 20
    max_cells: 1000
    max_attempts_per_cell: 3
    max_target_bytes: 2000000
    exclude: [".git", ".venv", "node_modules", "__pycache__"]
```

Reason requests a `search` intent with description `@analysis:coverage-plan`.
Explore copies a snapshot into `.linen-coverage/<run-id>/source`, groups files by
top-level module and bounded chunks, and creates one cell per chunk/topic pair.
Every included file is assigned once per configured topic, including non-code
files. It writes the plan as one `coverage_plan` Fact. If the cell limit would be
exceeded or no files remain, planning fails explicitly rather than truncating.

The deterministic audit graph selects pending cells and emits `verify` intents with description exactly
`@coverage:<plan-id>:<cell-id>` and `from` referencing the plan. These descriptions
are shown in the derived coverage state. The ordinary Explore worker reads the
specified snapshot and returns one `coverage_result` Fact. Its structured
evidence records outcome, inspected files, exact source citations, structured
follow-up leads and rationale. Each lead contains `file`, one-based `line`, a
bounded `summary`, and a concrete `next_step`; a new `needs_followup` result with
no lead is rejected.
For terminal outcomes every file must be inspected and every non-empty file
cited; the dispatcher verifies line/excerpt matches against the saved bytes. It
may repair a wrong line number only when the exact excerpt occurs once in that
file; ambiguous or invented citations fail validation.

The derived states distinguish:

- `pending` / `queued` / `running`: not materialized, waiting for a worker, or claimed.
- `awaiting_review`: result exists but lacks firm/certain VALID review.
- `checked` / `not_applicable`: the planned check is covered after review.
- `needs_followup` / `blocked` / `invalid`: uncovered; investigate before retry.

`needs_followup` must encode all unresolved leads. After review, the audit graph
derives another coverage pass that references and preserves the prior result;
ordinary trace intents can add more evidence between passes. The dispatcher keeps
a bounded ready window, dispatches the least-recently attempted item, and rejects
duplicate open intents, retries of covered/awaiting-review cells, and requests
beyond the per-cell attempt budget. Exhausted attempts remain incomplete. This is
an execution-attempt budget, not a token or currency budget.

Projects created by older dispatchers can compact an eagerly materialized queue
while stopped through `POST /projects/<id>/intents/compact-coverage`. Compaction
marks surplus result-less intents as `cancelled:coverage-compaction` with a
conclusion timestamp instead of deleting them. They remain auditable in the
database/timeline, are summarized in YAML export, and no longer count as open
work or coverage attempts.

Coverage results use a dedicated attestation review prompt rather than the generic
vulnerability defense prompt. The reviewer rereads every assigned frozen file,
checks both citations and objective rationale claims, and must invalidate concrete
contradictions. An INVALID coverage review derives `invalid` state and a new pass
whose ancestry includes the rejected result; it does not remain stuck as
`awaiting_review`.

Scope completion requires a reviewed plan, every cell covered, no open intents,
and no unresolved findings/evidence. It can finish with zero findings. Symlink
and size-limit skips block completion; explicit configured exclusions are
reported as exclusions. Decide exclusions before planning. One project has one
frozen plan; changing scope/topics requires a new project. Changes to live source
do not redefine an active plan.

Inspect progress without mutating the board:

```bash
uv run --project linen linen coverage --config dispatch.yaml --project-id PROJECT_ID
```

Coverage means the configured checks were executed and reviewed on the selected
snapshot. It does not prove every possible vulnerability class, runtime path or
business invariant was examined. The default three topics are starting points;
choose topics appropriate to the target. Citation checks prove consistency with
stored source, not correctness of an LLM's security reasoning. Scope mode starts
with its plan; every enabled scanner then consumes that same frozen snapshot.

## Optional reconnaissance

Reconnaissance is disabled by default because coverage planning is the source of
audit completeness. To map attack surface before the plan, opt in explicitly:

```yaml
audit:
  enabled: true
  mode: scope
  recon:
    enabled: true
workers:
  - name: audit-recon
    task_types: [bootstrap, reason, explore, review]
```

Set `bootstrap_enabled: true` only for that project. Its output is forced to a
`recon` fact and cannot complete the audit or serve as vulnerability evidence;
Reason may use it to prioritize cells while the scope plan still checks every
included file × topic.

For other workflows the bootstrap main phase may return either `fact + complete`
when the goal is genuinely solved, or a fact-only progress result. Fact-only output
concludes the reserved bootstrap Intent and hands control to normal Reason/Explore;
it does not complete the project.

## Source-data boundary

Every audit prompt states that target-repository files—including `AGENTS.md`,
`CLAUDE.md`, README text, comments and prompt-shaped fixtures—are untrusted source
data, not instructions. Ordinary audit tasks are read-only and must not execute
the target's builds, tests, installers, hooks or generated programs, access host
credentials, or make network calls. Only an explicitly derived `poc:isolated`
Intent may execute a bounded reproduction in its configured sandbox.

## Execution records

Every worker invocation writes a non-secret metadata record plus raw stdout and
stderr to `<project-workdir>/.linen-executions/`. Records include phase, worker,
timestamps, duration, exit/timeout/cancellation status and a SHA-256 of the full
argv. The argv itself is not persisted because it embeds the model prompt.
Together with frozen scan/coverage snapshots, these files make a completed audit
reconstructable after the worker CLI's own session cache is gone.

Pi can emit a structured provider error while still exiting with code `0`.
The dispatcher therefore inspects only explicit JSONL error fields (never echoed
prompt/content text). A transient rate limit opens a five-minute worker-provider
circuit; an exhausted quota opens it for one hour. Model-backed Reason, Explore,
Bootstrap and Review calls wait behind that circuit, while deterministic coverage,
synthesis and managed scanner work remains dispatchable. This prevents a 429 retry
storm without turning an LLM outage into a scanner outage. The expiry is persisted
as dispatcher runtime state in `<workspace_root>/.linen-provider-circuits.json`, not
as a blackboard node, so restarts preserve backoff without changing graph semantics.

`coverage_plan` uses the artifact-attestation review profile. The reviewer checks
the manifest digest, frozen snapshot, cell partition, and declared exclusions; it
does not judge whether the plan itself is a vulnerability. Legacy reviews without
an `attestation_check` remain visible for audit history but do not drive plan
lifecycle state, and the dispatcher derives one fresh attestation review.

## Filesystem-isolated reviews

Prepare a trusted **local** Docker image containing the worker CLI and its runtime.
Use an image without baked-in credentials/history; version or pin it for deployment.
The host still runs Reason/Explore. Only Review switches its execution backend:

```yaml
audit:
  enabled: true
  review_sandbox:
    enabled: true
    image: linen-worker-review:latest
    user: "1000:1000"
    network: none
    memory: 2g
    cpus: 2
    pids_limit: 256
    env_allowlist: []
```

The backend resolves the candidate's ancestor scan/coverage snapshot, checks
manifest hashes and copies only listed, hash-matching files into a new staging
directory. Missing or conflicting snapshots fail the review; the backend never
silently substitutes the live repository.

Each review uses a new non-root container with:

- `/repo`: selected source, mounted read-only.
- `/input`: only selected scan records or coverage scope, mounted read-only.
- `/work` and `/tmp`: fresh, size-limited writable tmpfs; HOME is under `/work`.
- Read-only root filesystem, dropped capabilities, no-new-privileges and resource limits.
- No host HOME, graph/history directory, Docker socket, device or privileged mount.

For cold reviews neither the prompt nor `/input` contains previous reviews or
graph history. Other review modes receive their requested graph context in the
prompt. Source files remain untrusted data and may contain instruction-like text.

Container creation uses a locally resolved image ID with no pull, and overrides
the image entrypoint with the worker command. Host CLI login state is not copied.
Configure authentication supported by the chosen CLI through explicit environment
names in `env_allowlist` (values come from worker.env first, then host environment).
Only allowlisted values cross this boundary; secret values are not placed in
Docker argv or execution metadata. They are visible to the reviewer inside the
container, so use credentials intended for this workload.

`network: none` is the default and suitable for offline tools/tests. Cloud model
CLIs normally need `network: bridge`. Bridge allows outbound and potentially
host/LAN access; it is **not** a network allowlist or a guarantee that the worker
cannot query a reachable board API. Use an external controlled API gateway/network
policy if network-level separation is required. Docker isolation also assumes a
trusted daemon/image and is not a defense against kernel/daemon vulnerabilities.

After normal exit, timeout, cancellation or heartbeat loss, the backend removes
the container and anonymous volumes. It retains source staging, stdout/stderr and
non-secret execution metadata in `.linen-reviews/<run-id>/` for auditability. A
host crash can still leave a container; operators can identify it by the
`linen-review-` prefix. Missing Docker/image, invalid snapshots or startup failures
fail closed; there is no automatic host execution fallback.

Review diagnostics record the actual image ID, snapshot, network mode and metadata
path. These are dispatcher observations, separate from the worker's claimed verdict.

## Validate

```bash
uv run --project linen --group dev pytest \
  linen/linen/tests/test_audit_pipeline.py \
  linen/linen/tests/test_scope_and_sandbox.py \
  linen/linen/tests/test_review_loop.py \
  linen/linen/tests/test_review_modes.py
```

Tests exercise persistence, migration, graph exports, completion gates, scan
errors, cache invalidation and the scan → fact → review → completion loop using
mocked scanner/model outputs. A real Semgrep scan can be requested through the
same managed intent above; it requires Semgrep installed separately.

To run real Docker negative tests using an already-present image with `/bin/sh`:

```bash
LINEN_DOCKER_TEST_IMAGE=node:20-bookworm-slim uv run --project linen --group dev pytest \
  linen/linen/tests/test_scope_and_sandbox.py -q
```

These verify permitted source reads, denied host/history access and writes, and
container removal on timeout/cancel. They do not call a live model provider.
