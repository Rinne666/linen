# Audit pipeline contract

The audit pipeline has one policy loop. Events wake Reason; Reason proposes
ordinary intents; the Kernel validates and persists them; workers produce facts
or errors, which produce the next event.

Deterministic modules enforce scope, evidence provenance, review, and proof
invariants. They do not create a second planner. In category-recon mode, one
frozen source snapshot feeds repository-wide Pi searches and, optionally, an
isolated CodeQL path scan. Both produce read-only machine evidence. CodeQL
databases are cached by frozen snapshot, language, CLI path, and immutable local
image ID; subsequent category queries reuse those databases. Reason, running on
the project's selected CLI, may request a configured category query profile by
name. The dispatcher validates the category and executes only the operator's
preinstalled query suite; the model cannot pass shell commands or arbitrary
query paths. Reason interprets machine evidence in application and
threat-model context and may create ordinary verification Intents; neither
producer can create a vulnerability verdict by itself.

CodeQL is opt-in and runs in a preinstalled analysis image with no network,
read-only source and input mounts, no host credentials, and a separate writable
analysis directory with a bounded work size. The configured language set is
restricted to no-build languages; Linen does not run target build commands. SARIF paths are
canonicalized against the frozen snapshot and stored using the Recon artifact
contract. CodeQL results are candidates only and do not add a second finding,
review, or completion lifecycle.
Each enabled language must have an explicit initial `.qls` suite configured in
`audit.codeql.query_suites`; an empty query list is rejected instead of
silently producing a database without useful analysis. Reason-selected
`query_profiles` are additional bounded suites, not a replacement for the
initial scan.
Category query profiles are optional and live inside the trusted analysis
image. Configure `audit.codeql.query_profiles` as category IDs mapped to
language-specific query-suite references in that image (CodeQL pack references
or absolute paths under trusted image directories). The Reason worker
may select a profile when it has a concrete unresolved question; each profile has a bounded attempt
count. The query task is deterministic, isolated, and does not require the Pi
or Codex CLI process itself to hold database or Docker access. The resulting
paths return to Reason as Recon evidence.
Other query engines can follow the same contract: read the same frozen
snapshot, run a preconfigured query in isolation, and return bounded paths with
canonical citations and `source_type`/`source_ref` provenance. Joern is not yet
implemented.
The operator must verify the CodeQL CLI terms for the repository and intended
automated use; `terms_acknowledged` records that operator check but does not
grant rights or override upstream terms.

`scripts/build_codeql_image.sh` builds the local image from an operator-supplied
official Linux CodeQL bundle. The bundle must match the Docker engine's target
architecture and include query packs for every configured language. No bundle,
query pack, or image is downloaded during audit execution. A Python starter
suite can be configured as
`codeql/python-queries:codeql-suites/python-security-extended.qls`.

Repository-wide Recon is the only scope-audit execution mode. New scope audits
never create coverage plans or per-file cells. Older dispatch files may still
contain `coverage` settings; they are retained only so existing queued cells
can finish, while the graph and Reason no longer create new ones. Historical
coverage Facts remain visible as graph history.
