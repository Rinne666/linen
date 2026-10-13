# Case coverage and capability benchmarks

Use a registered three-run plan to measure a finite set of positive examples
and negative controls. Run completion, case assessment, candidate discovery and
confirmed findings are separate measurements. A partial or blocked run stays in
the registered batch and lowers completion rate.

## Prepare the target and private evaluator data

Pin the source revision and copy only the selected source into a dedicated
target directory. Keep truth labels, case maps, assessments, plans and result
files outside both that directory and worker workspaces. Do not put expected
answers into project hints or worker prompts. Local read-only workers are not a
filesystem-isolation guarantee; use an appropriate sandbox when strict evaluator
data isolation is required.

Truth JSON/YAML contains `expected`, `negative_controls` and `labels`. Positive
and negative IDs must be non-empty, disjoint and unique. Every case has exactly
one label containing `id`, `category` and boolean `vulnerable`; optional fields
are `cwe`, `source_path` and `dimensions`. Dimensions can describe cross-file
flows, tenant boundaries, concurrency, centralized guards or other difficulty
axes. Every label must agree with the positive/negative sets.

`examples/benchmark-capabilities/evaluator/truth.json` is a portable eight-case
suite. Its target is only `examples/benchmark-capabilities/target/`. It covers
object permissions, tenant-local identity, server-owned prices and concurrent
withdrawals, with a positive and a negative control for each category. Pytest
checks the specified behavior using the same inputs/probe for each pair. Those
checks validate the fixture oracles; they do not measure an LLM or accept the
dispatcher PoC lane. Audit this suite separately from the existing 12-case
BenchmarkPython subset so category-specific results remain visible.

## Register three runs before creating projects

First check the configured worker versions and a real response through the same
environment. An availability/version check alone does not test provider access.
Use `runtime.healthcheck_probe: response` for the explicit startup probe.
Retain heartbeat conflict details and host suspend/wake evidence when a run is
cancelled. A reachable provider cannot keep a lease alive while the host is
asleep. On macOS the dispatcher's scoped idle-sleep guard is enabled by default;
record `runtime.prevent_idle_sleep` in the preregistered configuration.

Create `evaluator/` and register a plan before creating any of the three fresh
projects. Example commands run from the repository root:

```sh
uv run --project linen linen audit-case-plan \
  --expected examples/benchmark-capabilities/evaluator/truth.json \
  --config dispatch.yaml \
  --source-root examples/benchmark-capabilities/target \
  --suite-id capability-core-8 \
  --level candidate \
  --output evaluator/plan.json
```

The source option freezes a temporary inventory using the dispatcher Recon
exclusions and byte limits, records its digest, and removes the temporary copy.
It does not execute the target. Alternatively, pass `--source-digest` with an
already verified frozen-source digest. The actual runs must bind that same
digest. Put the target path in `local.repo_root` or the project's `repo_root`.

The plan captures the configuration file hash, source and truth digests, three
run labels, registration time, evaluation level and thresholds. It takes the
phase-record and wall-clock limits from the dispatcher configuration. Configure
those budgets before registration and keep the same configuration for all runs.
The configuration hash does not attest to CLI versions, credentials or host
configuration; retain the operational preflight and invocation records too.

Default thresholds are minimum recall 0.8, per-category recall 0.5, cross-run
stability 0.7, case assessment coverage 1.0 and false-positive rate 0.0. Set
different thresholds in the plan command before seeing outcomes. Candidate
mode measures discovery; confirmed mode counts only `confirmed_finding`
semantics. A successful Review never promotes a candidate by itself.

Use three new projects without inherited Facts, hints, Reviews or sessions.
Run sequentially when sharing one constrained worker so queue contention does
not dominate the measured run span. Record each run as `run-1`, `run-2` or
`run-3`. Do not extend budgets or replace a failed run with a later success.
Register a new batch when deliberately changing settings.

## Attribute and assess cases after execution

`case-map.json` maps current Fact IDs to case IDs. Unlike the historical local
score script, the exporter does not search descriptions or citations for case
names. Independently inspect each finding's actual source/sink and affected
case before writing the map. A mention of another case is not attribution.
Every current candidate and confirmed finding must be mapped, including
unexpected findings. IDs outside the suite are reported as unexpected detections
and reduce precision; they are not silently discarded.

```json
{"f012": ["case_001"], "f018": ["case_002"]}
```

Also map supporting technical Facts for negative controls. An evaluator supplies
`case-assessments.json` separately:

```json
{
  "case_001": {
    "disposition": "vulnerable",
    "fact_ids": ["f012"],
    "rationale": "The reviewed path grants another principal the private document body."
  },
  "case_002": {
    "disposition": "protected",
    "fact_ids": ["f018"],
    "rationale": "The reviewed helper rejects the same request at the principal boundary."
  },
  "case_007": {
    "disposition": "unassessed",
    "fact_ids": [],
    "rationale": "No reviewed concurrency evidence was produced before the budget expired."
  }
}
```

Replace these illustrative Fact IDs and rationales with the actual results.
Conclusive assessments require mapped, non-legacy, current-generation technical
evidence and the latest current-generation `VALID` Review with firm/certain confidence for every
supporting Fact. Policy, Recon and summary Facts cannot establish a case verdict.
An older valid review cannot conceal a later invalid, tentative or unresolved review.
Evaluator annotations are trusted judgments of case relevance and scope: the
tool checks links and Review records, not the truth of the rationale. They never
write the graph or promote a finding. An absent assessment becomes unassessed.
Protected controls without evidence are not true negatives.

```sh
uv run --project linen linen audit-case-export \
  --project-id proj_000001 \
  --server-url http://127.0.0.1:9000 \
  --expected examples/benchmark-capabilities/evaluator/truth.json \
  --plan evaluator/plan.json --config dispatch.yaml --run-label run-1 \
  --case-map evaluator/case-map-1.json \
  --case-assessments evaluator/case-assessments-1.json \
  --output evaluator/run-1.json
```

Use `--allow-incomplete` to retain a blocked run as a diagnostic observation;
the final benchmark still fails completion. If execution stopped before a
snapshot was produced, the observation records source binding as unavailable.
Do not substitute the planned digest for an observed one.

You can export after the server shuts down using `--snapshot saved.json` instead
of `--project-id`. The saved JSON must contain the raw `board`, `gate`, `cost`
and `runs` API responses. Offline export uses the same validation rules and does
not contact the API. The snapshot and annotation digests identify inputs, but
are not signatures or proof of independent human annotation.

## Compare the registered batch

```sh
uv run --project linen linen audit-benchmark \
  --expected examples/benchmark-capabilities/evaluator/truth.json \
  --plan evaluator/plan.json \
  --run evaluator/run-1.json \
  --run evaluator/run-2.json \
  --run evaluator/run-3.json > evaluator/benchmark.json
```

The command fails on incomplete runs, missing case coverage, low recall or
stability, excess false positives, unexpected detections, source mismatch, or
budget excess. It checks all registered labels, fresh project identities and
creation after plan registration. It recomputes scores from case rows rather
than trusting stored score totals. Labels cannot be changed in observations.
Missing run span cannot pass budget validation.

Each observation reports both candidate and confirmed scores, plus per-category,
per-CWE and per-dimension breakdowns. Precision includes unexpected detections;
false-positive rate uses the known negative controls. True negatives require an
explicit protected assessment. `undetected_positive_ids` includes unfinished
or unconfirmed positives; `false_negative_ids` is narrower and requires an
explicit protected assessment of a positive. Report unassessed cases alongside
recall instead of describing blocked work as a model classification error.

Run span is first started run to last finished run, not summed worker duration
or the time an idle project remains open. Concurrent/unfinished rows yield an
unknown span. Project completion and recorded audit coverage are separate from
registered case assessment coverage: residual audit gaps remain visible and
must not be described as exhaustive security coverage.

Without `--plan`, `audit-benchmark` retains its legacy three-result behavior.
The existing completed-project evaluation exporter and six-run ablation flow
also remain available; see ABLATION-RUNBOOK.md. Synthetic observations and
fixture oracle tests are regression validation, not real-model benchmark runs.

For a confirmed-level batch, configure [registered independent dynamic
oracles](INDEPENDENT-ORACLES.md) before execution. Approved definitions and
candidate bindings stay outside the worker-visible target. The dynamic gate
recomputes capability from isolated raw transport records; a worker's
self-reported observation cannot supply a confirmed detection.
