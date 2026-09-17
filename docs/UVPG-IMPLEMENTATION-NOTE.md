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
- a read-only `/projects/{project_id}/facts/{fact_id}/uvpg-shadow` endpoint and `evaluate_shadow_gate()` result. It reports `gate_version=uvpg-proof-v1`, PASS/FAIL, deterministic reason codes, and a proof summary; it cannot create a confirmed finding, mutate state, or block completion;
- export-compatible `proof` data and a migration for legacy databases.

The proof field is intentionally optional, so legacy Facts and exports continue to work. Legacy boards may receive a deterministic FAIL with missing closure reasons; their APIs remain readable. Large evidence remains in Artifact storage; `Fact.evidence` remains human-readable. `poc:isolated` and sandbox policy are untouched.

The strict closure requires independent Facts for attacker control, reachability,
security invariant, security boundary, capability before/after/delta, negative
control, and impact observation. New vulnerability candidates receive one
`review:cold-verifier` Intent for the complete candidate-local proof package.
The Review is stored on the candidate with `review_kind=vulnerability_proof`,
the candidate id, and a server-computed `proof_evidence_sha256`; it is accepted
only when it is `VALID`, `firm`/`certain`, and still matches the current proof
Facts and edges. Reviews do not enter that fingerprint, so recording a Review
cannot invalidate itself. A proof mutation makes the old Review stale and
requires another whole-package review. Existing per-Fact review boards remain
readable through a compatibility path while they migrate.

Finding lifecycle is now explicitly split:

`hypothesis / scanner / worker` may create a `candidate_finding`; the shared
deterministic proof core evaluates its proof graph; the only confirmation
authority is the server-side Technical Confirmation operation, which creates a
new `confirmed_finding` Fact and a `candidate --promotes_to--> confirmed`
GraphEdge. Ordinary `conclude` rejects an explicit `confirmed_finding` request
with `CONFIRMED_FINDING_REQUIRES_TECHNICAL_GATE`. Existing `type=vulnerability`
rows remain readable as candidates, and old rows marked `legacy` remain
completion-compatible.

`evaluate_proof_gate()` is the shared core used by both the read-only shadow
endpoint and the enforcing confirmation endpoint. Its protocol version is
`uvpg-proof-v1`; shadow/enforcement are modes, not separate rule sets. A
confirmation stores the candidate id, gate version, proof graph SHA-256,
verification level (`static_confirmed`), and timestamp in the confirmed Fact
proof payload and audit event. Promotion is atomic and idempotent.

Completion does not auto-confirm. New candidates do not satisfy hypothesis
completion; a confirmed Fact does, through its promotion ancestry. Legacy
vulnerability Facts remain accepted only for compatibility. Technical
Confirmation does not inspect bounty scope, CVE eligibility, or reporting
policy; those remain downstream concerns.

## Proof-gap production

This correctness phase hardens the existing projection and planner; it does
not add a second proof database, lifecycle state machine, or confirmation
authority. `ProofGraphView` is a deterministic projection of eligible UVPG
Fact-to-Fact edges only. Process, discovery, review, lifecycle, and promotion
edges are ignored, while malformed edges between recognized UVPG roles are
reported as integrity blockers. In particular, `promotes_to` and workflow
`supports` edges cannot contaminate a candidate's proof closure.
ProofGraphView limits and integrity errors are candidate-local: unreachable
Blackboard edges cannot fail another candidate's proof.

Reason currently sees the Blackboard projection and creates ordinary bounded
Intents through AuditGraph; before this phase it did not consume Technical Gate
reason codes. Proof-gap planning derives a transient `ProofGap` list from the
shared gate result and current-generation proof subgraph. No `proof_gaps` table
or second graph is introduced. The deterministic key is
`candidate_id:code[:target_fact_id]:generation`; an open Intent with that key suppresses a
duplicate, while blocked/failed work remains subject to the existing Intent
retry path.

The planner emits at most one highest-priority investigative obligation per
planning call. Integrity failures (`PROOF_CYCLE`, cross-candidate evidence,
invalid edge, and graph-size overflow) are non-investigative blockers and do
not dispatch a Worker. Missing roles map to a bounded Intent with an expected
Fact type and canonical relation. The Server validates that contract on
conclusion and creates the canonical GraphEdge; the Worker cannot choose an
arbitrary edge or close another candidate's gap. Capability and negative-control
edges resolve only against the same candidate's proof projection; a capability
delta is not produced until exactly one local before and after Fact exists.
Evidence, not the planner, creates the proof Fact. For a new candidate review
gap, the planner creates exactly one candidate-sourced cold-verifier Intent
(`UNREVIEWED_EVIDENCE`) rather than one Intent per proof role. Deterministic
code checks graph structure, provenance, generation, and hashes; the cold
verifier handles only semantic falsification such as attacker control,
reachability, defenses, and capability change.
Provenance/type/excerpt repair gaps remain non-automatic blockers until a
complete replacement/rebinding lifecycle exists.

`GET .../proof-status` is read-only. `POST .../proof-gaps/plan` creates only a
bounded Intent and never creates a proof Fact, confirms a finding, or changes
Completion. Candidate context is limited to the candidate's current proof
subgraph, Gate summary, and derived gaps. Generation changes naturally remove
old facts/edges from the current view; old proof work cannot close a new
generation obligation.

Proof work is part of the existing managed ready window and is not planned when
the window has no capacity. Candidate selection and review targets are sorted
deterministically. Contradicted candidates and graph-integrity failures stop
proof production and surface a blocker instead of dispatching a Worker.

Golden tests cover strict PASS, disconnected/missing invariant, workflow and
promotion-edge isolation, cross-candidate capability/negative-control
contamination, targeted review progression, repair blockers, proof bounding,
gap priority, planner deduplication, and canonical proof-edge production.

## Static and dynamic verification

Review is an evidence-quality decision only. A `VALID` decisive Review keeps a
vulnerability candidate as `candidate_finding`; only Technical Confirmation can
create the single authoritative `confirmed_finding` and its `promotes_to` edge.

Technical Confirmation remains static by default and does not require a PoC.
Its immutable creation proof records `verification_level=static_confirmed`.
The optional dynamic layer is versioned separately as `uvpg-dynamic-v1` and
evaluates existing `reproduction` and dynamic `negative_control` Facts. Each
must bind the exact candidate, current generation, an authorized `poc:isolated`
Run, hashed Artifacts, structured oracle observations, and decisive independent
Reviews. Positive and negative observations must demonstrate a deterministic
capability delta; a successful process exit or positive PoC alone is
insufficient.

`evaluate_dynamic_verification()` is read-only. The status and finalize
endpoints never execute commands; finalization appends one idempotent
`dynamic_verification_pass` audit event. `effective_verification_level()`
derives `dynamic_confirmed` only while that current-generation receipt and its
Run/Artifact hashes still validate; otherwise an authoritative confirmation
remains `static_confirmed`. No second confirmed Fact is created and dynamic
verification is not part of mandatory static ProofGap production.
