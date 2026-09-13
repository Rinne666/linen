# Conclude phase — finalize the hypothesis map

This is the **conclude** phase for a previous bootstrap pass. The session so far has been spent doing a broad read of the source repository. You must now stop exploring, stop running new tools, stop planning, and return a single JSON fact summarizing the **hypothesis map**.

Do not start a new audit. Do not run more tools. Use what is already in your session memory and on disk in this workdir.

# Output Requirements

Return only one raw JSON object. No prose, no markdown.

When rejecting (avoid unless truly impossible):
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal output:
```json
{"accepted": true, "data": {"fact": {"description": "...", "type": "<one of source/sink/dataflow>", "evidence": "..."}}}
```

# Rules

- The `fact.description` is a concise **hypothesis map**: languages, entry points, dangerous calls, trust boundaries, and — most importantly — the **candidate chains** (source → sink pairs) that look most promising to pursue.
- Tag the fact with the most informative single type (`source` for entry points, `sink` for dangerous calls, `dataflow` for any obvious direct flow, `sanitizer`/`validation` for guards noticed).
- Put detail (file:line citations, code excerpts) in `evidence`.
- If the bootstrap phase is being concluded because the audit timed out, capture what you have so far — the next reason call will pick it up.

# Context

## Origin
```
{origin}
```

## Goal
```
{goal}
```

## Hints
```
{hints}
```
