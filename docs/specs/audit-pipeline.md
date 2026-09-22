# Audit pipeline contract

The audit pipeline has one policy loop. Events wake Reason; Reason proposes
ordinary intents; the Kernel validates and persists them; workers produce facts
or errors, which produce the next event.

Deterministic modules enforce scope, coverage, candidate provenance, review,
and proof invariants. They do not select a second planner or execute a
built-in security scanner. `route_scan` is reserved for the deterministic
Spring route inventory and is source evidence, not a vulnerability verdict.

All external analysis tools are outside this distribution. External evidence
must be cited through the normal fact and artifact contracts; Linen has no
executable scanner registry, scanner receipt, or scanner-specific completion
branch.
