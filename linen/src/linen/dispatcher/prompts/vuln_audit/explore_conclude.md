# Conclude phase — finalize your typed fact for the Current Intent

This is the **conclude** phase for a previous exploration. The session so far has been spent performing one verification step (per the intent's `type`) on the source code. You must now stop exploring, stop running new tools, stop planning, and return a single JSON fact summarizing what you actually confirmed.

Do not start a new exploration. Do not re-read large code blocks. Use what is already in your session memory and on disk in this workdir.

# Output Requirements

Return only one raw JSON object. No prose, no markdown.

When rejecting (avoid unless truly impossible):
```json
{"accepted": false, "reason": "policy_refusal"}
```

Normal output — one typed fact with evidence (or an explicit "no finding"):
```json
{"accepted": true, "data": {
  "description": "...",
  "type": "dataflow",
  "evidence": "file:...line:...code:...tool:..."
}}
```

# Rules

- `description` MUST be a fully characterized fact. Either it advances the chain (typed: `source` / `sink` / `dataflow` / `sanitizer` / `validation` / `reachability`) or it explicitly closes a chain (typed: a "no path" or "blocked by sanitizer" observation, with reason).
- Do NOT include information already in the graph snapshot. Each fact is incremental.
- Do NOT return a vague summary. Either characterize the finding with evidence, or state a clear no-finding with the reason.
- Do not propose new intents. Reason is the strategist.
- If the Current Intent's type is `characterize` and the chain is fully closed, you may emit `type=vulnerability`. Otherwise do not — let the reason task do that final step.

# Context

## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Type
```
{intent_type}
```

## Current Intent Description
```
{intent_description}
```
