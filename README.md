<div align="center">

# linen

### Blackboard-based exploration for open-ended technical problems

Linen coordinates AI workers through a shared, evidence-bearing graph. It is
currently used for collaborative penetration testing and source-code security
audits, while keeping the underlying protocol domain-agnostic.

</div>

## Overview

Many technical problems have the same shape:

```text
known origin → incomplete evidence → unknown path → verifiable goal
```

Linen represents that search as a blackboard containing three primary objects:

| Object | Meaning |
| --- | --- |
| **Fact** | An observation or result recorded with evidence. |
| **Intent** | A proposed next step, optionally claimed by one worker. |
| **Hint** | Human guidance injected into the shared state. |

Workers repeatedly read the graph, choose or receive an Intent, perform one
bounded investigation, and write the result back as a Fact. Coordination is
through shared state rather than direct worker-to-worker messaging.

For security audits, the graph can additionally express sources, sinks,
dataflow, validation, reachability, proof obligations, review evidence, and
technical confirmation. See [the audit pipeline](docs/AUDIT-PIPELINE.md) and
the [UVPG implementation note](docs/UVPG-IMPLEMENTATION-NOTE.md).

## Architecture

```text
┌──────────────────────────────┐
│          Linen Server         │
│  HTTP API · graph · SQLite   │
└──────────────┬───────────────┘
               │
        read / write protocol
               │
┌──────────────▼───────────────┐
│          Dispatcher           │
│ planning · scheduling · leases│
│ prompts · worker adapters     │
└──────────────┬───────────────┘
               │
      ┌────────▼────────┐
      │ local AI workers │
      │ claude / codex / │
      │ pi               │
      └──────────────────┘
```

The Server is the authority for graph consistency and mutation rules. Its
mutation paths are being consolidated around:

```text
HTTP Router → Kernel → Store → SQLite / artifacts
```

The Dispatcher owns task scheduling and worker execution. It is the protocol
writer for worker interactions; workers receive prompts and return structured
results.

## Requirements

- macOS or Linux
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/)
- At least one supported worker CLI, already installed and authenticated:
  - [Claude Code](https://docs.claude.com/claude-code) (`claude`)
  - [Codex CLI](https://github.com/openai/codex) (`codex`)
  - [Pi](https://github.com/badlogic/pi-mono) (`pi`)

Workers run locally. Linen does not store provider API keys in its YAML
configuration.

## Quick start

From the repository root:

```bash
uv sync --project linen
cp dispatch.local.example.yaml dispatch.yaml
```

Start the Server:

```bash
uv run --project linen linen serve
```

The API and web UI are available at <http://127.0.0.1:9000>.

In a second terminal, start the Dispatcher:

```bash
uv run --project linen linen dispatch --config dispatch.yaml
```

To validate configured worker CLIs without starting the Dispatcher:

```bash
uv run --project linen linen dispatch \
  --config dispatch.yaml \
  --startup-healthcheck-only
```

Create a project in the UI by supplying an origin and a goal. The Dispatcher
will schedule bootstrap, reasoning, review, and exploration work as the graph
evolves.

## Source-code audit mode

Linen includes a coverage-driven audit mode for authorized source trees:

```bash
cp dispatch.vuln.example.yaml dispatch.yaml
# edit local.repo_root in dispatch.yaml
uv run --project linen linen dispatch --config dispatch.yaml
```

Create an audit project through the API:

```bash
curl -X POST http://127.0.0.1:9000/projects \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "audit-example",
    "origin": "/absolute/path/to/source",
    "goal": "Find exploitable SQL injection paths",
    "bootstrap_enabled": false,
    "audit_mode": "scope"
  }'
```

Audit mode can provide:

- frozen scope and policy evidence;
- coverage plans over included files and configured topics;
- managed scanner results and reproducible execution records;
- evidence-bearing vulnerability candidates;
- independent proof review and technical-confirmation gates;
- preserved worker output and artifacts under the project work directory.

Use this only against systems and source code you are authorized to test.

## Configuration

The portable configuration examples are:

- `dispatch.local.example.yaml` for general exploration;
- `dispatch.vuln.example.yaml` for source-code auditing.

Useful local settings include:

```yaml
local:
  workspace_root: "/Users/you/.local/share/linen/workspaces"
  agents_md: "/path/to/worker-brief.md"
  completed_action: keep # or remove
```

`agents_md`, when configured, is copied into new project workspaces as the
worker brief. Existing files are not overwritten.

## Development

Install development dependencies and run the regression suite:

```bash
uv sync --project linen --group dev
uv run --project linen --group dev pytest linen/linen/tests
```

Build the package:

```bash
uv build --project linen
```

The test suite covers the HTTP API, graph invariants, leases, review modes,
proof validation, dynamic verification, artifacts, and Dispatcher behavior.

## Documentation

- [Audit pipeline](docs/AUDIT-PIPELINE.md)
- [Review modes](docs/REVIEW-MODES.md)
- [UVPG implementation note](docs/UVPG-IMPLEMENTATION-NOTE.md)
- [Repository guidelines](AGENTS.md)

## Project status

Linen is an actively evolving research and engineering project. The general
blackboard protocol and local execution path are usable; audit semantics,
review gates, and server ownership boundaries continue to be tightened.

The repository intentionally keeps some compatibility paths while they are
being migrated. They should be treated as implementation details rather than
new public abstractions.

## License

See the repository for the applicable license and third-party notices.
