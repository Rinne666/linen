# UVPG shadow implementation note

Linen remains a Blackboard kernel. Workers return proposals; the server validates and persists Facts, Intents, Reviews and typed GraphEdges. The dispatcher derives scheduling and audit work from the current graph through `audit_graph`, while Context Projector builds bounded Snapshots/Projections. Artifacts and Run/Skill receipts hold large or tool-generated evidence.

Candidate findings are produced by an Intent conclusion (`POST .../conclude`) as ordinary Facts. Reviews aggregate to the existing Fact lifecycle, and the existing Completion Gate checks the selected evidence ancestry, review state, open work and audit-specific blockers. None of those rules is changed by UVPG.

The current shadow increment adds:

- additive Fact proof vocabulary and GraphEdge relation vocabulary;
- optional validated `ProofPayload` persisted as JSON on the existing `facts` table;
- a bounded `ProofGraphView` over current-generation Fact/GraphEdge ancestry. `proof_roles` is retained only as a legacy hint and cannot satisfy closure;
- a fixed relation matrix for candidate dependencies, invariant/boundary violations, impact observations, capability before/after/delta, and negative-control baselines;
- deterministic provenance validation against existing snapshots, artifacts, runs and project nodes, including workspace confinement, artifact hashes, source-generation checks, and frozen excerpt hashes;
- configurable `rules/invariant-library.yaml` metadata for common vulnerability classes;
- a read-only `/projects/{project_id}/facts/{fact_id}/uvpg-shadow` endpoint and `evaluate_shadow_gate()` result. It reports `gate_version=uvpg-shadow-v2`, PASS/FAIL, deterministic reason codes, and a proof summary; it cannot create a confirmed finding, mutate state, or block completion;
- export-compatible `proof` data and a migration for legacy databases.

The proof field is intentionally optional, so legacy Facts and exports continue to work. Legacy boards may receive a deterministic FAIL with missing closure reasons; their APIs remain readable. Large evidence remains in Artifact storage; `Fact.evidence` remains human-readable. `poc:isolated` and sandbox policy are untouched.

The strict closure requires independent Facts for attacker control, reachability,
security invariant, security boundary, capability before/after/delta, negative
control, and impact observation. Candidate, invariant, boundary, delta, impact,
and negative-control Facts require the existing decisive review quality
(`VALID` plus `firm`/`certain`); any invalid review is a contradiction. A
candidate review does not attest its ancestors.

TechnicalConfirmationGate remains shadow-only. It does not create confirmed
findings and it does not affect Completion.

Golden tests cover strict PASS, disconnected/missing invariant, cross-candidate
contamination, invalid/missing review, and directed proof cycles. The next safe
increment is richer end-to-end fixtures for real frozen source manifests,
without wiring the shadow result into completion or dispatcher authorization.
