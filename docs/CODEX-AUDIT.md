# Codex CLI audits and portable results

Run from the repository root with Python 3.12+, `uv`, and an authenticated
`codex` on PATH. The adapter uses non-interactive JSON events and native output
schemas for Recon and review; the dispatcher validates the resulting evidence.
The integration is tested with Codex CLI 0.156.1. See the
[official non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode).

```bash
uv sync --project linen --group dev
uv run --project linen linen dispatch --config dispatch.codex.example.yaml --startup-healthcheck-only
uv run --project linen linen serve --workspace-root ./workspaces
# In a second terminal:
uv run --project linen linen dispatch --config dispatch.codex.example.yaml
```

The response healthcheck makes a small model request. If it fails, first check
`codex login status`, network/proxy access, and model availability. Set
`workers[].env.CODEX_MODEL` to a model supported by that CLI account when the
host default is unavailable. A successful text probe does not establish that
an isolated reviewer can read its source mounts.

Create a scope audit in the UI at `http://127.0.0.1:9000`, or via the API:

```bash
curl -fsS http://127.0.0.1:9000/projects \
  -H 'Content-Type: application/json' \
  -d '{"title":"Local source audit","origin":"/absolute/path/to/target","repo_root":"/absolute/path/to/target","audit_mode":"scope","worker_preference":"codex"}'
```

The supplied profile uses only Codex, retains execution archives, bounds task
timeouts and retries, and leaves optional Docker/CodeQL executors disabled until
configured. Local CLI read-only mode is not filesystem isolation from the host.
Technical confirmation still requires the existing proof and independent
execution gates. Missing evidence remains pending or blocked, not confirmed.
When both gates pass, the dispatcher requests Technical Confirmation from the
server, which rechecks the proof, dynamic receipts and reportability atomically.
This allows an eligible finding to reach completion without a manual UI click;
the completion endpoint itself still cannot promote candidates.

## Isolated Codex reviews

Enable `audit.review_sandbox` only with a prepared local image containing Codex.
Use `network: bridge` when the model provider needs network access. The network
mode is not an egress allowlist. To use account login, explicitly set
`codex_auth_file` to the absolute login-cache path; only that cache is seeded
into a disposable HOME. Provider environment variables must be allowlisted.
Docker Desktop proxies normally need `host.docker.internal`, not `127.0.0.1`.

Within this backend, Docker enforces the read-only root and source/input mounts,
non-root user, dropped capabilities and resource limits. Codex uses that outer
isolation boundary instead of starting a nested bubblewrap sandbox, which can
fail with `No permissions to create a new namespace`. Host Codex commands keep
their read-only policy. Linen does not enable privileged Docker execution or
fall back to the host when container startup fails.

## Export report and graph together

```bash
uv run --project linen linen audit-export \
  --project-id proj_001 --server http://127.0.0.1:9000 \
  --output ./audit-results/proj_001.zip
```

The ZIP contains:

| File | Contents |
| --- | --- |
| `report.md` | Detailed facts, reviews, evidence and operational blockers |
| `summary.md` | Candidate dispositions and confirmed findings |
| `graph.svg` | Standalone evidence graph with task and review relationships |
| `snapshot.json` | Structured board, stages and completion gate |
| `findings.sarif` | Findings for code-scanning tools |
| `manifest.json` | Project/revision identity and SHA-256/size of each artifact |

All files are captured in one database transaction. The CLI validates the
manifest before atomically replacing the destination ZIP. SVG generation needs
no browser, network, Graphviz or model request; it includes disconnected nodes
and tolerates cycles. Node labels are escaped, and the graph never upgrades a
candidate to a confirmed finding.

In the UI, open **Export**, then choose **Graph SVG** or **Full bundle**.

Exports work while a project is active or stopped, preserving partial evidence
and blockers. Check lifecycle and completion-gate state in the manifest before
treating a bundle as a finished audit. Bundles are point-in-time snapshots;
the existing `format=report` endpoint continues serving the immutable completion
report after completion.

Direct API downloads:

```text
GET /projects/{project_id}/export?format=svg
GET /projects/{project_id}/export?format=bundle
```

The original Markdown, JSON, YAML, SARIF and timeline formats remain available.

See [the validation record](CODEX-AUDIT-VALIDATION.md) for the real Codex runs,
recovery steps, test results and limits of the local sample verification.
Configure target-specific dynamic checks using [independent oracles](INDEPENDENT-ORACLES.md).
