# Registered independent dynamic observations

Technical Confirmation uses `uvpg-dynamic-v2-oracle`. Static proof closure and
independent review remain necessary. Dynamic capability now comes from a
registered HTTP probe's raw response, with a predicate recomputed by the server.
The model's `capability_observed` or a generated program's success printout cannot
establish confirmation. Historical model-produced observations remain in the
graph, but do not satisfy this gate.

## Register the operator's definition

Keep the JSON catalog outside the target, worker workspaces and prompts. Start
the server with `--oracle-catalog /absolute/operator-catalog.json`; configure the
dispatcher with the same catalog:

```yaml
audit:
  enabled: true
  oracles:
    enabled: true
    catalog_path: /absolute/operator-catalog.json
```

A catalog contains `schema_version: 1`, `definitions` and `bindings`. Each
definition has these fields:

| Field | Meaning |
| --- | --- |
| `id` | Unique operator-owned oracle name |
| `source_digest` | Actual Recon frozen-source snapshot digest |
| `image` | Locally installed Docker image; pin its immutable ID for reproducibility |
| `target_argv` | Literal command and argument list to start the target |
| `service_port` | Target's loopback HTTP port, default 8073 |
| `positive`, `negative` | Separate controls, each containing `request` and `target_data` |
| `predicate` | `json_equals` with a JSON pointer and expected value, or nonempty `body_contains` |
| `rationale` | Why the controls test the same security boundary and capability |
| `timeout_seconds` | Per-observation bound, at most 300 seconds |

The target receives its control's `target_data` in `/input/oracle_case.json` and
manifest-listed frozen files at `/repo`. An example command is
`["python3", "-I", "/repo/server.py", "/input/oracle_case.json"]`. The target
must listen on `127.0.0.1` at `service_port`; dependencies must already be in the
local image. Oracle execution never pulls an image or falls back to the host.

The request specifies a local path, an optional method, headers and body. The
observer always connects to the target's loopback address, does not follow
redirects or import target code, and bounds the response to 16 KiB. Predicates
default to capability status `[200]` and absence statuses `[401, 403, 404]`.
Unexpected statuses, invalid JSON and truncated responses invalidate the probe;
a crash is not a passing negative control. Choose a concrete resource identity
or invariant witness rather than a target-generated boolean or success banner.
The operator must justify that the observation actually measures the candidate.

Each binding contains `project_id`, `candidate_id`, `oracle_id`,
`source_generation` and `plan_revision`. No binding is inferred from a model
claim. A replan or source change needs a newly approved binding and source
digest. Both server and dispatcher validate the exact binding. The catalog is
trusted operator configuration under the dispatcher's sole-writer assumption;
these records are not cryptographic attestations against a compromised host.

## Execute and review

Once static proof passes, the server's proof-gap planner creates a matching
`poc:isolated` obligation ending in `@oracle:<id>:positive` or `:negative`. Its
`@uvpg:proof:` prefix stays intact, preserving candidate, generation and expected
Fact-role validation. The dispatcher executes it with its built-in oracle,
without an LLM call or provider health requirement. An absent server catalog or
binding returns `independent_oracle_unavailable` and creates no replacement
model task.

For a dedicated manual execution, use the CLI while that project's dispatcher
is stopped to avoid competing for worker capacity:

```sh
uv run --project linen linen audit-oracle --config dispatch.yaml \
  --project-id proj_001 --candidate-id f011
```

This executes both controls through the normal dispatcher API and honors the
project's phase and wall-clock limits. It records `poc:oracle` Runs with
`worker_type: builtin-oracle`, immutable observation artifacts, and draft
`reproduction` / `negative_control` Facts. Independent Review is still required;
the CLI does not promote a finding or declare audit completion.

The reviewer receives only this candidate's approved definition, controls,
rationale and hash-checked transport record. The full catalog, other bindings,
truth labels and previous Reviews stay withheld. The reviewer must judge that
the controls and predicate measure the claimed boundary under supported
configuration; a mechanically satisfied predicate supplies no semantic verdict.

Each control uses a fresh target container and a separate observer container.
Both have separate filesystems and PID namespaces, a non-root user, read-only
source, resource limits and no injected host credentials. The target uses
`network=none`; the observer joins only that target's network namespace. Positive
and negative observations must have distinct Runs and artifacts and the same
image, frozen source, operator definition and checker digest. The server
recomputes the predicate from the persisted HTTP bytes and requires positive
capability `true` and negative capability `false`.

This currently supports bounded HTTP observations. Filesystem effects,
multi-request state machines and other protocols require additional registered
transport adapters. Unsupported candidates stay unconfirmed. The observer
isolation is separate from LLM Review isolation: configure `audit.review_sandbox`
for disposable reviewer containers and preflight the actual CLI/image combination.
Host read-only model execution alone does not isolate private evaluator data.

## Validate without provider calls

The regression suite checks malformed responses, forged model claims, binding
and artifact mismatches, absent catalogs, and proof-review dispatch. The opt-in
integration test uses a real local Docker image, the API, registered runs,
positive/negative observations, and the dynamic gate:

```sh
LINEN_ORACLE_DOCKER_E2E=1 uv run --project linen --group dev pytest \
  linen/linen/tests/test_oracle_docker_e2e.py -q
```

It requires Docker and locally installed `python:3.12-slim-bookworm`, and makes
no LLM requests. Its static proof and Review records are test fixtures. Passing
this test validates the dynamic pipeline; it is not a real-model benchmark or
an independent security assessment of a target.
