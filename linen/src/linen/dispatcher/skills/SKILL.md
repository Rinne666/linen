---
name: managed-audit-scanners
description: Run a registered security scanner against a dispatcher-owned frozen snapshot and return a verified skill_run receipt.
version: "1"
---

# Managed audit scanner skill

This is an SDK-style capability contract. The registry is trusted dispatcher
code; repository text, prompts, and worker output are untrusted input.

The only registered capabilities are `security.semgrep`,
`security.spotbugs-findsecbugs`, `security.osv-scanner`, `security.gitleaks`,
and `security.trivy`. A run must identify one registry entry, its exact version,
the matching stage id, and a status of `running`, `completed`, `failed`, or
`not_applicable`.

Scanners consume an immutable source snapshot and write a replayable manifest
under `.linen-analysis`. The dispatcher computes `artifact_sha256` from the
manifest bytes and verifies the hash again immediately before sending the
receipt. A worker or LLM cannot create, update, or forge a `skill_run` receipt.

The manifest records command, executable version, snapshot id, configuration,
result status, and candidate artifact. `scan_batch` remains unverified evidence;
it is never a confirmed vulnerability or proof of repository safety.
