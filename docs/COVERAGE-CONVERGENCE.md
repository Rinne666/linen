# Coverage convergence

Linen records source reconnaissance as hypotheses and unresolved coverage rows;
neither a Recon lead nor a CodeQL path is a vulnerability verdict. Reason receives
bounded lead summaries with the validated source citations and must give every
lead one disposition: create a source-supported `candidate_finding` for ordinary
independent review, reject it with source evidence, or leave it in the residual
gap ledger. Candidate findings still pass the existing review and proof gates.

The terminal audit artifact includes a `lead_disposition_ledger` covering each
validated Recon result and CodeQL result in the current source generation. A
lead is `candidate_tracked` only when a candidate is a graph descendant of its
source Fact and its cited source/sink path supports that association. It is
`rejected_with_independent_evidence` only after a firm or certain independent
`INVALID` review. Every other lead is an `unresolved_gap`; that state adds a
residual gap and keeps `coverage_complete` false. An analyzer returning no paths
does not establish that a category is safe.

Lead association uses exact source/sink line references when the analyzer
provides them. For siblings without line references, the candidate must cite the
lead's frozen evidence; a shared Recon ancestor or filename alone is ambiguous.
Reason can also bind a candidate explicitly with `lead_ref: <source_fact_id>/<lead_id>`.
Candidate text only helps track which evidence chain it addresses. Review and
proof gates remain authoritative for the finding.

Recon follow-ups should read named files from the frozen snapshot when those
files are available. A source-level gap can close only through a bounded follow-
up whose evidence is tied to the same snapshot and has exact validated citations.
Framework-version behavior, deployed working directory, filesystem contents,
process permissions, and other absent runtime facts remain residual gaps. A
completed finite set of configured lenses does not prove the assumed threat
space is exhaustive.

Validation performed for this change: focused tests exercise lead projection,
candidate versus unresolved ledger states, and coverage residual behavior using
synthetic graph/artifact data. They do not execute target code, contact a real
LLM, or re-run the live `proj_004` audit. Actual detection and candidate quality
remain subject to acceptance in a fresh isolated audit run.
