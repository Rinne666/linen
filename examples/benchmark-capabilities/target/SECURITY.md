# Audit scope

All eight `case_001` through `case_008` functions in `api.py` are in scope,
together with `policy.py` and `store.py`. The contracts in README.md define the
accepted principal, document, catalog and account boundaries.

Analyze ordinary calls and concurrent withdrawal calls under those contracts.
Caller-supplied principals, stores and account objects are trusted service
context, not attacker-created objects. No network deployment or other package
is part of this target. An absent HTTP wrapper is not an authorization claim.
