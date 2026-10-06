# Measured simplification acceptance

Process completion, recorded source coverage, candidate discovery and confirmed
vulnerability recall are different outcomes. A completed run with zero findings
does not establish that a target is safe. Three empty detection sets have perfect
set stability, but fail the default recall threshold on a non-empty truth set.

## Capture an independent run

Keep the target commit, frozen source digest, scope, query packs, model and CLI
versions constant. Start each run in a **new project**, with no inherited graph,
reviews, hints, or previous worker session. Keep the evaluator's truth set and
case annotations outside the target and worker workspace. Record the exact
configuration and the `linen ops check` output with the experiment.

Change one mechanism at a time: for example, deferred package review, bounded
Reason wakeups, or compact lead projection. Do not combine unrelated changes and
attribute the result to one mechanism. A baseline is a separately run prior
configuration/version, not a relabeled export of the same project.

The exporter requires a completed project and a matching ready completion gate.
It checks that the board did not change during export, records its generation,
graph revision and frozen source digest, and generates a stable run identity.
Coverage and gap counts come from the dispatcher summary. No arbitrary local
artifact path returned by a worker is opened by this exporter.

An evaluator supplies a JSON map from **current finding Fact IDs** to stable
case IDs. For example:

```json
{"f012": ["case-a"], "f019": ["case-b"]}
```

Only a Fact with `confirmed_finding` semantics counts as confirmed. Mapping a
candidate does not promote it; a source citation that happens to mention another
case is not a detection of that case. Annotate the affected source path and
finding independently before mapping it. All confirmed Facts must be mapped;
all candidate Facts must be mapped before a candidate-recall comparison. An
empty map `{}` is valid when the run contains no findings. Without `--case-map`,
the exporter uses project-local Fact IDs for inspection only; the ablation
command rejects those exports as incomparable.

```sh
uv run --project linen linen audit-evaluation-export \
  --project-id proj_000001 --case-map evaluator/case-map-1.json \
  --output evaluator/baseline-1.json
```

The output path must not already exist. Repeat for three baseline projects and
three variant projects. Costs include archived calls, aggregate worker duration
(which is not wall-clock time), unarchived registered attempts, Reason/review
calls, and token counts when measured. Missing token counts remain `null`.

## Compare six measured observations

Use the existing JSON/YAML truth format with an `expected` array. Unmatched
confirmed IDs reduce precision. Candidate recall is a diagnostic for the
discovery pipeline, not confirmed recall or a false-positive verdict.

```sh
uv run --project linen linen audit-ablation --expected evaluator/truth.json \
  --baseline evaluator/baseline-1.json --baseline evaluator/baseline-2.json \
  --baseline evaluator/baseline-3.json \
  --variant evaluator/variant-1.json --variant evaluator/variant-2.json \
  --variant evaluator/variant-3.json --require-fewer-facts
```

Acceptance requires distinct run identities and identical frozen sources,
minimum confirmed recall of 0.8, no recall/precision/stability loss, preserved
candidate recall, complete recorded coverage with zero residual gaps in all six
runs, no additional residual gaps or reduction in covered runs,
strictly fewer Intents, fewer Facts with the option above (otherwise no Fact
increase), and no increase in model calls. Invalid/missing measurements and
failed acceptance exit nonzero. The JSON result names each failing check.

For a diagnostic comparison of partial coverage, pass `--allow-partial-coverage`.
The report labels that narrower acceptance scope; it is not full-coverage
acceptance. Zero detections of expected positives cannot pass even with a
zero recall threshold. Replans of one project do not count as independent runs.

The default recall-loss allowance is zero; change it only as an explicit
experiment decision. Review token and elapsed-time measurements alongside call
counts. Partial token sums carry their measurement counts and do not establish
currency or token savings. Distinct identities are a replay check, not mathematical proof that
operators ran independent experiments or that evaluator annotations are correct.

## When dynamic execution is deliberately excluded

Keep the existing confirmation gates. Use candidate-recall and lead-disposition
data to diagnose static discovery and residual gaps, and verify fixtures for
graph/scheduling regressions. Do not relabel candidates as confirmed to make the
recall threshold pass. A confirmed-detection ablation can remain unaccepted
while the static implementation and its regression checks are working.

The repository's `test_uvpg_ablation.py` demonstrates a controlled graph
replay: deferred review reduces review calls from 10 to 1 and Intents from 19
to 10 while retaining 10 Facts and the same static proof roles. This is a
regression result, not a measured real-LLM benchmark or evidence of Fact
reduction. Newly added evaluation tests also use controlled observations.
