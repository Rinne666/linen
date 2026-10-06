# Execution cost and attempt accounting

`GET /projects/{project_id}/cost` aggregates dispatcher execution archives and
registered run lifecycles. The ledger reports provider token usage when a CLI
emits a recognized structured usage record. It does not estimate usage from
prompt length, output length, duration, or model names. Unknown usage is `null`
in an execution archive and increments `usage_unknown_calls`; it is never
reported as zero. The ledger does not calculate currency because model,
provider, cache, and subscription prices vary and no price schedule is
configured.

Codex is invoked with its native `exec --json` event output, Claude Code with
`--output-format json`, and Pi already runs in `--mode json`. The task parser
extracts only the final assistant response from those envelopes. The accounting
parser reads provider-reported usage separately:

- Claude: `input_tokens`, `output_tokens`, cache read, and cache creation.
- Codex: cumulative `token_count.info.total_token_usage` (or a structured
  completed-turn usage object).
- Pi: assistant `message_end.message.usage` input, output, cache read, and cache
  write counts, summed once per message ID so tool-call turns are included.

The normalized `total_tokens` follows the provider's reported accounting
fields: Claude and Pi add cache read/write tokens where those fields are
reported, while Codex uses its cumulative input/output totals because cached
input is a breakdown of input. Missing cache fields remain `null`; they are not
assumed to be zero. Each aggregate has `usage_recorded_calls`,
`usage_unknown_calls`, and per-field `usage_coverage_calls`. A call is recorded
when input and output are known; unknown calls can overlap recorded calls when
cache or total fields are absent. Token sums include observed values, and the
coverage map shows how many calls contributed to each field. Legacy
archives remain readable; because older records did not
save a process-start marker, they retain their prior call-count treatment.

New execution records include `process_started`, `attempt_status`, and
`failure_code`. `calls` counts attempts whose worker process started; setup
failures are recorded as `setup_failures` and are excluded from that count.
Process start does not prove that a provider billed the attempt.
Unarchived runs are counted as `unarchived_attempts`. When persisted lifecycle
metadata confirms `process_started`, they also contribute one to `calls` and
`usage_unknown_calls`; their duration remains zero because no archive recorded
it. A process-start marker does not establish whether a provider request ran or
was billed. Runs without that marker do not contribute to `calls`. Their
lifecycle status and a missing-result/error code appear in
`attempt_status_counts` and `failure_code_counts`.

Execution archive fields are additive. Existing archives without usage or
attempt metadata remain valid and are interpreted as legacy records.
