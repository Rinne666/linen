<div align="center">

# linen
### More Than Just AI Penetration Testing — Towards General State-Space Search

linen is a general-purpose problem-solving engine. <br/>It defines no roles, no workflows. Given an origin and a goal, it searches for a path through an unknown state space. <br/>AI Penetration Testing is one such problem — and a proven one.

</div>

## What is linen?

Penetration testing is fundamentally a **directed search through a near-infinite state space**:

- **Origin**: known (target IP, target system)
- **Goal**: defined (get a shell, capture the flag)
- **Path**: unknown

This structure is not unique to penetration testing. Vulnerability research, mathematical proof, CTF challenges — any problem with a clear starting point, a clear success condition, and an unknown path in between shares the same shape.

linen is built for this class of problems. Penetration testing is the first domain it has been validated on.

The engine is built on a **Blackboard Architecture** with an explicit fact-intent graph. Three primitives are all it needs:

| Concept | Meaning |
|---------|---------|
| **Fact** | A confirmed, objective finding written to the board |
| **Intent** | A declared direction of exploration, not yet executed |
| **Hint** | Human judgment injected at any time; absorbed by agents on the next read |

The graph grows from `origin` toward `goal`. Every new Fact is a stepping stone; every Intent is a step into the unknown.

Agent Workers run an OODA loop — Observe the full graph, Orient to the current state, Decide on next intents, Act to explore — and write their findings back as new Facts. Workers have no fixed roles. Tasks are generated at runtime from the graph's current state, not from predefined job descriptions.

Agents coordinate exclusively through the shared board (Stigmergy). No direct communication. No information silos.

## How It Works

Three task types, all executed by the same Worker:

| Task | What it does | Output |
|------|-------------|--------|
| **Bootstrap** | At project start, attempts to solve the problem directly | Fact + possible Complete |
| **Reason** | Reads the full graph: is the goal met? What should be explored next? | Complete / new Intents / no-op |
| **Explore** | Claims one Intent, executes the exploration, reports findings | One Fact |

System architecture:

```
          ┌──────────────────────────────────┐
          │           linen Server           │
          │    Facts + Intents + Hints       │
          └─────────────────┬────────────────┘
                            │
                     Read / Write API
                            │
          ┌─────────────────┴────────────────┐
          │             Dispatcher           │
          │   Schedules tasks, manages       │
          │   per-project workdirs, writes   │
          │   protocol                       │
          └──────────┬───────────────┬───────┘
                     │               │
     ┌───────────────┴──┐     ┌──────┴──────────────┐
     │  local worker    │     │  local worker       │
     │  (Project A)     │     │  (Project B)        │
     │  ┌────┐  ┌────┐  │     │  ┌────┐  ┌────┐     │
     │  │ W. │  │ W. │  │     │  │ W. │  │ W. │     │
     │  └────┘  └────┘  │     │  └────┘  └────┘     │
     └──────────────────┘     └─────────────────────┘
```

**linen Server** maintains graph consistency only.

**linen Dispatcher** reads the graph, schedules tasks, creates per-project working directories, and is the sole writer to the protocol. Each project gets its own directory under `local.workspace_root`; multiple Agent Workers run concurrently across projects. Agent Workers only receive a prompt and return structured output.

Workers run directly on the dispatcher host, reusing the machine's already-configured `claude` / `codex` / `pi` CLIs — no Docker, no API keys in the config.

## Results

**Tencent Cloud Hackathon · AI Penetration Testing Challenge · 2nd Edition**

610 teams · 1,345 participants · top universities and security firms across China

| Metric | Value |
|--------|-------|
| Problems solved | **54 / 54 — only team to AK** |
| Final ranking | 3rd |

> The system had never been tested before the competition. The full pipeline came online for the first time at 4 AM on race day. No training, no tuning, no domain-specific tooling. Zero MCP tools, zero RAG, zero predefined agent roles.

## Getting Started

**Prerequisites**

- macOS or Linux
- Python ≥ 3.12
- [`uv`](https://docs.astral.sh/uv/) package manager
- At least one of these CLIs installed and logged in:
  - [Claude Code](https://docs.claude.com/claude-code) (`claude`)
  - [Codex CLI](https://github.com/openai/codex) (`codex`)
  - [Pi](https://github.com/badlogic/pi-mono) (`pi`)

### Setup

Clone the repo and install the Python package:

```bash
git clone https://github.com/Rinne666/linen.git
cd linen
uv sync --project linen
```

Create your dispatcher config:

```bash
cp dispatch.local.example.yaml dispatch.yaml
# edit dispatch.yaml if you want to add/remove workers, change workspace_root, etc.
```

### Run

In one terminal, start the server:

```bash
uv run --project linen linen serve
# → http://127.0.0.1:9000
```

In another terminal, start the dispatcher:

```bash
uv run --project linen linen dispatch --config dispatch.yaml
```

The dispatcher's startup will check that every configured worker CLI is on `PATH` and runnable; if not, it will fail fast with a clear error.

Open the UI at `http://127.0.0.1:9000` to create a project (an `origin` and a `goal`) and watch the engine grow the graph toward the goal.

### Optional: per-project worker context

If you want every project workdir to start with a custom `AGENTS.md` / `CLAUDE.md` (for example, a CTF environment brief or your team's preferred worker style), set `local.agents_md` in `dispatch.yaml` to a file on disk. linen copies it into each new project workdir on first use. Existing files are never overwritten.

```yaml
local:
  workspace_root: "/Users/you/.local/share/linen/workspaces"
  agents_md: "/etc/linen/workers.md"
  completed_action: keep   # or "remove" to delete finished project dirs
```

### Health check only

Verify all worker CLIs are reachable without starting the full dispatcher:

```bash
uv run --project linen linen dispatch --config dispatch.yaml --startup-healthcheck-only
```

## Use as a source-code vulnerability auditor

For coverage-driven scope plans, managed Semgrep, reproducible execution records,
review diagnostics, and completion gates, see [Blackboard audit pipeline](docs/AUDIT-PIPELINE.md).

The architecture is domain-agnostic — the same OODA loop that walks a network during a CTF also walks a source tree looking for vulns. Only the **prompts and the workdir layout** change; nothing in the server, dispatcher, tasks, or worker adapters needs to know what the worker is looking at.

To switch into vuln-audit mode:

1. Copy the vuln-audit config:
   ```bash
   cp dispatch.vuln.example.yaml dispatch.yaml
   ```
2. Edit `local.repo_root` to point at the source tree you want audited.
3. (Optional) Tweak `local.agents_md` to your own worker brief.
4. Start the server and dispatcher as usual.
5. Create projects with `bootstrap_enabled: false` and `audit_mode: scope`. With
   `audit.scope_adjudication.enabled`, Linen first freezes policy evidence and
   requires a reviewed scope decision before it creates the coverage plan.

```bash
curl -X POST http://127.0.0.1:9000/projects -H "Content-Type: application/json" -d '{
  "title": "audit-todoapp",
  "origin": "/Users/you/code/todoapp",
  "goal": "SQL injection in any user-input -> DB query path; also XSS in any HTML render",
  "bootstrap_enabled": false,
  "audit_mode": "scope"
}'
```

What you get:

- Each new project workdir contains a `repo/` symlink to your source tree, so workers can `cd repo` to read code.
- A `AGENTS.md` / `CLAUDE.md` (from `local.agents_md`) is auto-copied on first use, telling the worker about the available tools (`rg`, `cat`, `semgrep`, etc.) and the expected finding format (`file:line:code:class:severity:taint:fix`).
- The `reason` task type becomes the strategist: it reads the current state of the audit and proposes new audit intents. The `explore` task type executes one intent and returns a finding.
- Scope mode first freezes policy/maintainer evidence, records trust boundaries
  and pre-exclusions with exact quotes and revival conditions, then freezes the
  source tree and covers every included file × configured topic. Policy
  eligibility never overwrites technical exploitability or marks a finding as a
  false positive.
- Raw worker stdout/stderr and execution metadata are retained in `<workdir>/.linen-executions/` alongside frozen scan and coverage artifacts.

The bundled prompt set lives at `linen/src/linen/dispatcher/prompts/vuln_audit/`.
Markdown task prompts keep their required placeholders; semantic audit passes are
registered and schema-validated in the single `audit_recipes.yaml` bundle. The
dispatcher sends only the recipe selected by the current blackboard Intent.

### Hypothesis-verification semantics (Phase 1)

The vuln-audit prompt set models the audit as an explicit **hypothesis verification chain** expressed through existing linen data — no new tables, no new state machine, no schema rewrite. The change is three optional fields on the existing `Fact` and `Intent` models:

| Field | On | Type | Purpose |
|---|---|---|---|
| `type` | Fact | string (free) | semantic tag: `source` / `sink` / `dataflow` / `sanitizer` / `validation` / `reachability` / `vulnerability` |
| `evidence` | Fact | string (free) | structured citations: `file:`, `line:`, `code:`, `tool:`, `taint:`, … |
| `type` | Intent | string (free) | verification step kind: `verify` / `trace` / `search` / `validate` / `reach` / `characterize` |

The chain reads top-to-bottom:

```
source  -- where untrusted input enters
   ↓  (dataflow steps: where the data flows, what transforms)
   ↓  (sanitizer / validation: guards the data passes through)
sink    -- where a dangerous operation is called
   ↓  (reachability: is the sink actually callable from outside)
vulnerability  -- the chain is closed; the finding is fully characterized
```

**Reason** reads the typed graph and decides, in order: is the hypothesis **proven** (a `type=vulnerability` fact exists with a sound chain)? **refuted** (a fact explicitly records a counter-condition)? Or what is the **next verification step** needed to advance the chain — a `search` for entry points, a `trace` from source to sink, a `validate` of a sanitizer, a `reach` for a call site, or a `characterize` to emit the final `vulnerability` fact.

**Explore** executes exactly the verification step indicated by the intent's `type`, returns one typed fact with evidence, and stops. It does NOT propose new intents — reason does that. It does NOT emit `type=vulnerability` unless the intent explicitly asks it to (`type=characterize`).

This means the existing Fact → Intent → Worker → Fact loop is preserved exactly. The dispatcher, scheduler, leases, heartbeats, and worker adapters see no domain-specific code. The semantics live entirely in:
- the three optional model fields,
- the prompt set under `linen/src/linen/dispatcher/prompts/vuln_audit/`,
- and a few minor additive contract/API changes (type/evidence are optional everywhere; legacy callers and old DBs keep working).

#### Example: a SQLi chain in three steps

```
Goal: SQL injection in any user-input -> DB query path

(reason, turn 1: no source found yet → propose search)
Intent I001 (type=search, from=[origin])
   "find untrusted-input entry points in src/api/"

(explore) → Fact F001 (type=source)
   "request.args['id'] enters at src/api/users.py:41"
   evidence: "file: src/api/users.py\nline: 41\ncode: uid = request.args['id']"

(reason, turn 2: have source, need sink → propose search)
Intent I002 (type=search, from=[F001])
   "find SQL execution sinks reachable from request.args['id']"

(explore) → Fact F002 (type=sink)
   "db.execute at src/api/users.py:42; no params argument"
   evidence: "file: src/api/users.py\nline: 42\ncode: db.execute(f'SELECT * FROM users WHERE id={uid}')"

(reason, turn 3: have source + sink, no dataflow → propose trace)
Intent I003 (type=trace, from=[F001, F002])
   "trace uid from request.args into the f-string at users.py:42"

(explore) → Fact F003 (type=dataflow)
   "uid is interpolated into the f-string at line 42; no parameterization"
   evidence: "taint: request.args['id'] -> uid -> f-string -> db.execute"

(reason, turn 4: chain closed, no sanitizer/validation in path → characterize)
Intent I004 (type=characterize, from=[F003])
   "characterize the SQLi with full evidence"

(explore) → Fact F004 (type=vulnerability)
   "SQL injection in src/api/users.py:42; unauthenticated remote"
   evidence: file + line + code + taint + severity:high + fix (parameterized query)

(reason, turn 5: cold-review the terminal fact; only a triaged, firm/certain VALID-reviewed chain may complete)
→ project completed
```

A reviewer reading `GET /projects/{id}/export?format=yaml` sees the whole chain at a glance: each fact's `type` tells what role it played; each `evidence` block has the file:line, code excerpt, and tool used; each intent's `type` tells what kind of verification step it was.

### Tests

Run the fast regression suite without real LLM endpoints:

```bash
uv run --project linen --group dev pytest
```

## Further Reading

- <a href="https://mp.weixin.qq.com/s/DlpEH7bVr0xi0VawPJs3XA" target="_blank" rel="noopener noreferrer">The Strongest AI Penetration Testing Agent: Postmortem of the Only Team to Achieve AK at the TCH Tencent Cloud Hackathon Intelligent Penetration Testing Challenge (2nd Edition)</a>
- <a href="https://mp.weixin.qq.com/s/2rEqFLvkxvYWM3gW170C2w" target="_blank" rel="noopener noreferrer">The Pathless Path: linen AI from Penetration Testing to General Problem Solving</a>

## Disclaimer

linen is a general-purpose problem-solving engine. Although it supports penetration testing, CTF solving, security assessment, and vulnerability research workflows, it is intended to be used only in environments where you have explicit authorization to operate.

You are solely responsible for how you use this project. Do not use linen against systems, networks, applications, or data without clear prior permission from the owner or operator. Unauthorized security testing, exploitation, or data access may be illegal and may cause harm.

The developers and contributors of this project do not endorse or accept responsibility for any misuse, abuse, damage, loss, or legal consequences arising from its use. By using this project, you agree to ensure that your activities comply with all applicable laws, regulations, contractual obligations, and professional or organizational policies in your jurisdiction.

## ⚖️ License
This project is licensed under **GNU AGPLv3** for personal and educational use.

**Commercial Use**: If you wish to use this project in a commercial or proprietary environment without the AGPL-3.0 open-source obligations, **please contact me to obtain a commercial license.**

**Contributions**: By submitting a Pull Request, you agree that your contributions may be used under both the AGPL-3.0 and the project's commercial license.
