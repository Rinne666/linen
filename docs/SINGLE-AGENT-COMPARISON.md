# Single-agent comparison protocol

Run this comparison after the two-case smoke meets its preregistered completion
conditions. Retain failed smoke rounds and blocked benchmark runs. A serial
dispatcher or one worker name is not a single-agent baseline: it still performs
Reason, Explore and separate Review tasks.

The baseline is one fresh auditor session reading the same frozen source and
producing a finite report directly, with no Linen graph planning, other worker
sessions, previous results, truth labels or reviewer feedback. Its tools and
provider model must match the corresponding audit lane. Record a separate
configuration for it before running, including CLI/image versions, allowed
tools, source digest, wall-clock budget and maximum attempts.

For an architecture comparison, pin the same model for all model-backed Linen
roles and the baseline. Comparing Codex plus Claude against one Codex session
measures the whole configured system, including the extra reviewer model; label
that result accordingly. Fresh disposable reviewer filesystems remain necessary
to isolate graph history and private evaluator data. Host read-only execution
alone does not provide that isolation.

Use three fresh executions per lane. Start them sequentially when they share a
constrained provider or worker, with identical target snapshots and independent
session IDs. Pre-register all six labels, limits and acceptance thresholds. Do
not extend a failing run, reuse findings from an earlier project or replace a
blocked result with a successful retry. Deliberate settings changes form a new
batch. Record every attempt, including failures, cancellations and unknown usage.

Both reports need independent evaluator attribution to cases. The evaluator
checks exact source paths and evidence for positive findings and explicit
protected assessments for negative controls. Apply the same registered dynamic
oracle to both lanes when measuring capability; auditor self-reports do not
establish confirmation. Keep evaluator time and calls separate from the auditor
budget and report that overhead for both lanes. Do not create synthetic Linen
Reviews to make a baseline export satisfy the graph's completion rules.

Compare candidate recall, false-positive rate, assessed-case coverage and the
category/CWE/difficulty breakdowns first. Report dynamic capability separately
from candidate discovery. Include total model calls, measured tokens with their
unknown counts, execution span and completion/blocked status. A baseline's report
completion is not Linen's independently reviewed pipeline completion.

Existing `audit-case-export` validates Linen observations. The standalone
single-session report needs its own evaluator adapter and provenance record;
it must not be relabeled as an existing project export. Until that adapter and
the six real executions exist, this protocol is preparation, not a measured
single-agent comparison or evidence that orchestration improves accuracy.
