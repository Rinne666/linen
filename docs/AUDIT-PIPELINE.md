# Audit pipeline

Linen's audit loop is event-driven and model-guided:

```text
source snapshot → Reason → Intent → Explore/Review → Fact/Error → Event
```

The dispatcher no longer ships or executes built-in security scanners. It does
not run Semgrep, SpotBugs/FindSecBugs, OSV-Scanner, Gitleaks, or Trivy, and it
does not maintain a scanner registry or scanner receipts.

Retained deterministic evidence paths are deliberately narrow: source
snapshots and digests, coverage planning, optional semantic analysis methods,
scope adjudication, review attestations, and proof gates. Workers inspect the
frozen source and report through the normal Explore contract; candidate
findings still require unified proof review and technical gates.

Scope policy evidence inventories only the configured local patterns, policy
URLs, and GitHub advisories when enabled and resolvable. The manifest records
each configured source and whether collection succeeded or produced a gap;
unconfigured sources are explicit, and global external-policy completeness is
not assessed. A zero-gap collection therefore means only that the configured
sources were collected successfully.

Use `dispatch.vuln.example.yaml` for the current configuration. Existing
databases may retain historical `skill_runs` schema from old migrations, but
the current runtime does not read or write it.
