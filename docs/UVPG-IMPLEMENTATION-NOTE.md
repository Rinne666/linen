# UVPG first-stage implementation note

Linen remains a Blackboard kernel. Workers return proposals; the server validates and persists Facts, Intents, Reviews and typed GraphEdges. The dispatcher derives scheduling and audit work from the current graph through `audit_graph`, while Context Projector builds bounded Snapshots/Projections. Artifacts and Run/Skill receipts hold large or tool-generated evidence.

Candidate findings are produced by an Intent conclusion (`POST .../conclude`) as ordinary Facts. Reviews aggregate to the existing Fact lifecycle, and the existing Completion Gate checks the selected evidence ancestry, review state, open work and audit-specific blockers. None of those rules is changed by UVPG.

The first increment adds:

- additive Fact proof vocabulary and GraphEdge relation vocabulary;
- optional validated `ProofPayload` persisted as JSON on the existing `facts` table;
- deterministic provenance validation against existing snapshots, artifacts, runs and project nodes;
- configurable `rules/invariant-library.yaml` metadata for common vulnerability classes;
- a read-only `/projects/{project_id}/facts/{fact_id}/uvpg-shadow` endpoint and `evaluate_shadow_gate()` result. It reports PASS/FAIL and reason codes only; it cannot create a confirmed finding, mutate state, or block completion;
- export-compatible `proof` data and a migration for legacy databases.

The proof field is intentionally optional, so legacy Facts and exports continue to work. Large evidence remains in Artifact storage; `Fact.evidence` remains human-readable. `poc:isolated` and sandbox policy are untouched.

The next safe increment is to add end-to-end golden fixtures for the proof roles and shadow result, without wiring the shadow result into completion or dispatcher authorization.
