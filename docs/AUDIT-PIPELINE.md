# Audit pipeline

Linen's audit loop is event-driven and model-guided:

```text
source snapshot → Reason → Intent → Explore/Review → Fact/Error → Event
```

The dispatcher no longer ships or executes built-in security scanners. It does
not run Semgrep, SpotBugs/FindSecBugs, OSV-Scanner, Gitleaks, or Trivy, and it
does not maintain a scanner registry or scanner receipts.

Retained deterministic evidence paths are deliberately narrow: source
snapshots and digests, coverage planning, bounded candidate triage, optional
Spring route inventory, semantic recipes, review attestations, and proof gates.
Workers inspect the frozen source and report through the normal Explore
contract; candidate findings still require review and technical gates.

Use `dispatch.vuln.example.yaml` for the current configuration. Existing
databases may retain historical `skill_runs` schema from old migrations, but
the current runtime does not read or write it.
