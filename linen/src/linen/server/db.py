from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "linen" / "linen.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    -- Monotonic version for semantic blackboard mutations. Lease/heartbeat
    -- updates deliberately do not advance it because they are control-plane
    -- state rather than graph knowledge.
    graph_revision INTEGER NOT NULL DEFAULT 0,
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    audit_mode TEXT NOT NULL DEFAULT 'none'
        CHECK (audit_mode IN ('none', 'hypothesis', 'scope')),
    -- Source and plan revisions are separate from graph_revision. A new
    -- checkout invalidates prior evidence without deleting it; replanning the
    -- same checkout advances only plan_revision.
    source_generation INTEGER NOT NULL DEFAULT 1,
    plan_revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT,
    reason_lease_id TEXT,
    -- Optional per-project source tree override. When set, the dispatcher
    -- symlinks <workdir>/repo to this path; otherwise it falls back to the
    -- dispatcher's `local.repo_root` config, or no symlink at all. Set by
    -- the server when a project is created with `clone_url` (clone lands
    -- here) or `repo_root` (validated to an existing directory).
    repo_root TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    display_title TEXT,
    type TEXT,
    semantic_type TEXT NOT NULL DEFAULT 'observation',
    evidence TEXT,
    proof TEXT,
    source_generation INTEGER NOT NULL DEFAULT 1,
    legacy INTEGER NOT NULL DEFAULT 0,
    -- Per-fact lifecycle, driven by Reviews + manual user action.
    -- 'draft' = newly written, awaiting review; 'triaged' = accepted but
    -- not yet characterized; 'false_positive' = some review said INVALID;
    -- 'fixed' = user reported remediation; 'accepted_risk' = user accepted.
    status TEXT NOT NULL DEFAULT 'triaged'
        CHECK (status IN ('draft', 'triaged', 'fixed', 'false_positive', 'accepted_risk')),
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    display_title TEXT,
    type TEXT,
    semantic_type TEXT NOT NULL DEFAULT 'audit_task',
    relation_type TEXT NOT NULL DEFAULT 'produces',
    phase TEXT NOT NULL DEFAULT 'investigate',
    source_generation INTEGER NOT NULL DEFAULT 1,
    plan_revision INTEGER NOT NULL DEFAULT 1,
    legacy INTEGER NOT NULL DEFAULT 0,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

-- Persistent dispatcher/runtime failures. These records are control-plane
-- state attached to an Intent, never audit Facts. At most one unresolved
-- error episode may gate an Intent; resolved episodes remain as history.
CREATE TABLE IF NOT EXISTS intent_errors (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    intent_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    worker TEXT,
    code TEXT NOT NULL,
    classification TEXT NOT NULL
        CHECK (classification IN ('transient', 'blocked')),
    message TEXT NOT NULL,
    remediation TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    first_failed_at TEXT NOT NULL,
    last_failed_at TEXT NOT NULL,
    retry_at TEXT,
    resolved_at TEXT,
    resolution TEXT,
    PRIMARY KEY (id, project_id),
    FOREIGN KEY (intent_id, project_id)
        REFERENCES intents(id, project_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS intent_errors_intent_idx
    ON intent_errors (project_id, intent_id, resolved_at, last_failed_at);
CREATE UNIQUE INDEX IF NOT EXISTS intent_errors_one_open_idx
    ON intent_errors (project_id, intent_id) WHERE resolved_at IS NULL;

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

-- Adversarial review: a verdict on a fact (VALID / INVALID / NEEDS_REVIEW).
-- One fact can have multiple reviews (multiple workers, majority vote).
-- fact_id and intent_id are stored as plain text (no FK) because facts
-- and intents use composite primary keys (id, project_id) and SQLite
-- doesn't allow FKs that don't reference the full composite. The
-- project_id FK to projects is what gives us cascade-delete on parent
-- project removal, which is what we actually need.
CREATE TABLE IF NOT EXISTS reviews (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fact_id TEXT NOT NULL,
    intent_id TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('VALID', 'INVALID', 'NEEDS_REVIEW')),
    confidence TEXT CHECK (confidence IN ('certain', 'firm', 'tentative')),
    summary TEXT NOT NULL,
    reasoning TEXT,
    diagnostics TEXT NOT NULL DEFAULT '{}',
    source_generation INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    created_by TEXT,
    PRIMARY KEY (id, project_id)
);
CREATE INDEX IF NOT EXISTS reviews_fact_idx ON reviews (project_id, fact_id);

-- Explicit semantic relationships. Existing projects can continue to derive
-- edges from Intents; new writes additionally materialize typed edges so the
-- UI never has to use a full task description as an edge label.
CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    source_generation INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, project_id)
);
CREATE INDEX IF NOT EXISTS graph_edges_project_idx
    ON graph_edges (project_id, source_generation, source_kind, source_id);

-- Deterministic audit phase ledger. Dispatcher reconciles this projection;
-- workers never write it directly.
CREATE TABLE IF NOT EXISTS audit_stages (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_generation INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    stage_id TEXT NOT NULL,
    label TEXT NOT NULL,
    phase_order INTEGER NOT NULL,
    required INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'satisfied', 'blocked', 'failed', 'not_applicable')),
    capability TEXT,
    skill_id TEXT,
    run_id TEXT,
    detail TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, source_generation, plan_revision, stage_id)
);

-- SDK-style Skill execution receipts. Completion trusts these receipts and
-- their artifact hashes, never an LLM's prose claim that a tool ran.
CREATE TABLE IF NOT EXISTS skill_runs (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage_id TEXT NOT NULL,
    intent_id TEXT,
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    capability TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('running', 'completed', 'failed', 'not_applicable')),
    command TEXT,
    artifact_ref TEXT,
    artifact_sha256 TEXT,
    detail TEXT,
    source_generation INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY (id, project_id)
);
CREATE INDEX IF NOT EXISTS skill_runs_project_idx
    ON skill_runs (project_id, source_generation, plan_revision, stage_id, started_at);

-- Human scope/finding decisions are append-only. Reversal creates a newer
-- decision linked through supersedes_id; history is never overwritten.
CREATE TABLE IF NOT EXISTS human_decisions (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('confirm', 'reject', 'waive', 'exclude')),
    rationale TEXT NOT NULL,
    basis_quote TEXT,
    revival_condition TEXT,
    actor TEXT NOT NULL,
    supersedes_id TEXT,
    source_generation INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);
CREATE INDEX IF NOT EXISTS human_decisions_target_idx
    ON human_decisions (project_id, source_generation, target_kind, target_id, created_at);

-- Append-only trace of semantic and control-plane mutations. Current state
-- remains in relational tables; this ledger powers Activities and forensics.
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT,
    idempotency_key TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    entity_kind TEXT,
    entity_id TEXT,
    source_generation INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    graph_revision INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_project_idx
    ON audit_events (project_id, sequence);
-- Versioned dispatcher/runtime projections.  These tables are deliberately
-- additive: the legacy execution and skill ledgers remain authoritative for
-- their existing APIs while vNext clients use these structured contracts.
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    kind TEXT NOT NULL,
    workspace_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    byte_size INTEGER,
    producer_run_id TEXT,
    related_node_ids TEXT NOT NULL DEFAULT '[]',
    created_at TEXT,
    PRIMARY KEY (artifact_id, project_id)
);
CREATE INDEX IF NOT EXISTS artifacts_project_idx ON artifacts(project_id, created_at, artifact_id);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    intent_id TEXT,
    task_type TEXT NOT NULL,
    stage TEXT,
    attempt INTEGER NOT NULL DEFAULT 1,
    idempotency_key TEXT NOT NULL,
    graph_revision INTEGER NOT NULL DEFAULT 0,
    source_generation INTEGER NOT NULL DEFAULT 1,
    plan_revision INTEGER NOT NULL DEFAULT 1,
    context_projection_id TEXT,
    worker_manifest_digest TEXT,
    timeout_seconds INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    worker_name TEXT,
    worker_type TEXT,
    started_at TEXT,
    finished_at TEXT,
    artifact_ids TEXT NOT NULL DEFAULT '[]',
    error_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, project_id),
    UNIQUE (project_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS runs_project_idx ON runs(project_id, created_at, run_id);

CREATE TABLE IF NOT EXISTS context_projections (
    projection_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    snapshot_id TEXT NOT NULL,
    graph_revision INTEGER NOT NULL DEFAULT 0,
    source_generation INTEGER NOT NULL DEFAULT 1,
    plan_revision INTEGER NOT NULL DEFAULT 1,
    intent_id TEXT,
    stage TEXT,
    node_ids TEXT NOT NULL DEFAULT '[]',
    edge_ids TEXT NOT NULL DEFAULT '[]',
    artifact_ids TEXT NOT NULL DEFAULT '[]',
    context TEXT NOT NULL DEFAULT '{}',
    selection_policy TEXT NOT NULL,
    request TEXT,
    created_at TEXT NOT NULL,
    projection_digest TEXT,
    PRIMARY KEY (projection_id, project_id)
);
CREATE INDEX IF NOT EXISTS context_projections_project_idx
    ON context_projections(project_id, created_at, projection_id);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    graph_revision INTEGER NOT NULL,
    source_generation INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    nodes TEXT NOT NULL DEFAULT '[]',
    edges TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, project_id)
);
CREATE INDEX IF NOT EXISTS snapshots_project_idx ON snapshots(project_id, created_at, snapshot_id);

CREATE TABLE IF NOT EXISTS report_snapshots (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_generation INTEGER NOT NULL,
    plan_revision INTEGER NOT NULL,
    graph_revision INTEGER NOT NULL,
    format TEXT NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_project_columns(conn)
        _ensure_fact_columns(conn)
        _ensure_intent_columns(conn)
        _ensure_review_columns(conn)
        _ensure_vnext_columns(conn)


def _ensure_project_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    # A few early databases did not carry the reason lease bookkeeping at all.
    # Add those nullable control-plane columns before the lease invalidation
    # below so migration remains safe for the smallest legacy schema.
    for name in ("reason_worker", "reason_trigger", "reason_started_at", "reason_last_heartbeat_at"):
        if name not in columns:
            conn.execute(f"ALTER TABLE projects ADD COLUMN {name} TEXT")
    if "bootstrap_enabled" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN bootstrap_enabled INTEGER NOT NULL DEFAULT 1")
    if "repo_root" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN repo_root TEXT")
        if "bootstrap_mode" in columns:
            conn.execute(
                "UPDATE projects SET bootstrap_enabled = CASE WHEN bootstrap_mode = 'disabled' THEN 0 ELSE 1 END"
            )
    if "audit_mode" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN audit_mode TEXT NOT NULL DEFAULT 'none'")
    if "graph_revision" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN graph_revision INTEGER NOT NULL DEFAULT 0")
    if "source_generation" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN source_generation INTEGER NOT NULL DEFAULT 1")
    if "plan_revision" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN plan_revision INTEGER NOT NULL DEFAULT 1")
    if "reason_lease_id" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN reason_lease_id TEXT")
        # Legacy reason claims cannot be authenticated with a per-run token.
        # Drop them during migration so the next dispatcher run can reclaim
        # safely instead of inheriting an ambiguous worker-name-only lease.
        conn.execute(
            "UPDATE projects SET reason_worker = NULL, reason_trigger = NULL, "
            "reason_started_at = NULL, reason_last_heartbeat_at = NULL"
        )
    # A partially migrated database may already have the column while still
    # carrying an old worker-only claim.  Such a claim cannot be safely
    # heartbeated or released, so invalidate it just like the additive
    # migration above.
    conn.execute(
        "UPDATE projects SET reason_worker = NULL, reason_trigger = NULL, "
        "reason_started_at = NULL, reason_last_heartbeat_at = NULL "
        "WHERE reason_worker IS NOT NULL AND reason_lease_id IS NULL"
    )


def _ensure_fact_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(facts)")}
    if "type" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN type TEXT")
    if "evidence" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN evidence TEXT")
    if "proof" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN proof TEXT")
    if "display_title" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN display_title TEXT")
    if "semantic_type" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN semantic_type TEXT NOT NULL DEFAULT 'observation'")
        conn.execute(
            "UPDATE facts SET semantic_type = CASE "
            "WHEN id = 'origin' THEN 'audit_target' "
            "WHEN id = 'goal' THEN 'audit_objective' "
            "WHEN type = 'vulnerability' THEN 'candidate_finding' "
            "WHEN type IN ('hypothesis_batch', 'variant_batch') THEN 'hypothesis' "
            "WHEN type IN ('coverage_plan', 'coverage_result') THEN 'coverage' "
            "WHEN type IN ('policy_evidence', 'scope_adjudication') THEN 'scope' "
            "WHEN type IN ('module_summary', 'semantic_summary', 'audit_summary') THEN 'summary' "
            "ELSE 'observation' END"
        )
    if "source_generation" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN source_generation INTEGER NOT NULL DEFAULT 1")
    if "legacy" not in columns:
        conn.execute("ALTER TABLE facts ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE facts SET legacy = 1")
    if "status" not in columns:
        # Additive: all existing facts get 'triaged' as the default. The CHECK
        # constraint on the table enforces the enum from new rows onward; ALTER
        # TABLE on older SQLite (< 3.37) wouldn't add CHECK, so we add the
        # value constraint here too.
        conn.execute("ALTER TABLE facts ADD COLUMN status TEXT NOT NULL DEFAULT 'triaged'")
        # Best-effort backfill: don't touch rows that already have a status-like
        # value (legacy data may have nulls after this ALTER due to the NOT
        # NULL default).
        conn.execute(
            "UPDATE facts SET status = 'triaged' "
            "WHERE status IS NULL OR status NOT IN ('draft', 'triaged', 'fixed', 'false_positive', 'accepted_risk')"
        )
    # Some installations were started from an intermediate schema where the
    # semantic columns existed but all historical rows retained their generic
    # defaults. Keep this backfill idempotent and limited to rows explicitly
    # marked legacy so user-authored semantics are never overwritten.
    conn.execute(
        "UPDATE facts SET semantic_type = CASE "
        "WHEN id = 'origin' THEN 'audit_target' "
        "WHEN id = 'goal' THEN 'audit_objective' "
        "WHEN type IN ('policy_evidence', 'scope_adjudication') THEN 'scope' "
        "WHEN type IN ('coverage_plan', 'coverage_result') THEN 'coverage' "
        "WHEN type IN ('hypothesis_batch', 'variant_batch', 'candidate_triage') THEN 'hypothesis' "
        "WHEN type IN ('vulnerability', 'candidate_disposition') THEN 'candidate_finding' "
        "WHEN type = 'negative_assurance' THEN 'negative_assurance' "
        "WHEN type IN ('module_summary', 'semantic_summary', 'audit_summary') THEN 'summary' "
        "ELSE semantic_type END "
        "WHERE legacy = 1"
    )
    conn.execute(
        "UPDATE facts SET display_title = CASE "
        "WHEN id = 'origin' THEN 'Audit target' "
        "WHEN id = 'goal' THEN 'Audit objective' "
        "WHEN type = 'policy_evidence' THEN 'Scope evidence' "
        "WHEN type = 'scope_adjudication' THEN 'Scope decision' "
        "WHEN type = 'coverage_plan' THEN 'Coverage plan' "
        "WHEN type = 'coverage_result' THEN 'Coverage result' "
        "WHEN type = 'scan_batch' THEN 'Scanner evidence' "
        "WHEN type = 'route_scan' THEN 'Route evidence' "
        "WHEN type = 'source' THEN 'Input source' "
        "WHEN type = 'sink' THEN 'Sensitive sink' "
        "WHEN type = 'dataflow' THEN 'Data flow' "
        "WHEN type = 'reachability' THEN 'Reachability' "
        "WHEN type IN ('hypothesis_batch', 'variant_batch') THEN 'Security hypothesis' "
        "WHEN type = 'candidate_triage' THEN 'Triage decision' "
        "WHEN type IN ('vulnerability', 'candidate_disposition') THEN 'Candidate finding' "
        "WHEN type = 'negative_assurance' THEN 'Negative assurance' "
        "WHEN type = 'module_summary' THEN 'Coverage summary' "
        "WHEN type = 'semantic_summary' THEN 'Reasoning summary' "
        "WHEN type = 'audit_summary' THEN 'Audit summary' "
        "ELSE substr(trim(description), 1, 88) END "
        "WHERE legacy = 1 AND (display_title IS NULL OR trim(display_title) = '')"
    )


def _ensure_review_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(reviews)")}
    if "diagnostics" not in columns:
        conn.execute("ALTER TABLE reviews ADD COLUMN diagnostics TEXT NOT NULL DEFAULT '{}'")
    if "source_generation" not in columns:
        conn.execute("ALTER TABLE reviews ADD COLUMN source_generation INTEGER NOT NULL DEFAULT 1")


def _ensure_vnext_columns(conn: sqlite3.Connection) -> None:
    """Migrate installations created before the structured server contracts.

    Every change is additive and all backfills are deterministic.  In
    particular, old audit rows receive an identity derived from their stable
    autoincrement sequence; no historical payload is rewritten.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_events)")}
    additions = (
        ("event_id", "TEXT"),
        ("run_id", "TEXT"),
        ("idempotency_key", "TEXT"),
        ("schema_version", "INTEGER NOT NULL DEFAULT 1"),
        ("graph_revision", "INTEGER NOT NULL DEFAULT 0"),
    )
    for name, definition in additions:
        if name not in columns:
            conn.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {definition}")
    conn.execute(
        "UPDATE audit_events SET event_id = 'evt-' || sequence WHERE event_id IS NULL OR trim(event_id) = ''"
    )
    conn.execute("UPDATE audit_events SET schema_version = 1 WHERE schema_version IS NULL")
    conn.execute("UPDATE audit_events SET graph_revision = 0 WHERE graph_revision IS NULL")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS audit_events_idempotency_idx "
        "ON audit_events (project_id, idempotency_key) WHERE idempotency_key IS NOT NULL"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS audit_events_event_id_idx "
        "ON audit_events (project_id, event_id)"
    )
    # CREATE TABLE IF NOT EXISTS is safe for both fresh and legacy databases;
    # keep the definitions in one place by executing only the vNext tail.
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_id TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        schema_version INTEGER NOT NULL DEFAULT 1, kind TEXT NOT NULL, workspace_path TEXT NOT NULL,
        sha256 TEXT NOT NULL, media_type TEXT NOT NULL, byte_size INTEGER, producer_run_id TEXT,
        related_node_ids TEXT NOT NULL DEFAULT '[]', created_at TEXT,
        PRIMARY KEY (artifact_id, project_id)
    );
    CREATE INDEX IF NOT EXISTS artifacts_project_idx ON artifacts(project_id, created_at, artifact_id);
    CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        schema_version INTEGER NOT NULL DEFAULT 1, intent_id TEXT, task_type TEXT NOT NULL, stage TEXT,
        attempt INTEGER NOT NULL DEFAULT 1, idempotency_key TEXT NOT NULL, graph_revision INTEGER NOT NULL DEFAULT 0,
        source_generation INTEGER NOT NULL DEFAULT 1, plan_revision INTEGER NOT NULL DEFAULT 1,
        context_projection_id TEXT, worker_manifest_digest TEXT, timeout_seconds INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued', worker_name TEXT, worker_type TEXT, started_at TEXT,
        finished_at TEXT, artifact_ids TEXT NOT NULL DEFAULT '[]', error_id TEXT, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, PRIMARY KEY (run_id, project_id), UNIQUE (project_id, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS runs_project_idx ON runs(project_id, created_at, run_id);
    CREATE TABLE IF NOT EXISTS context_projections (
        projection_id TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        schema_version INTEGER NOT NULL DEFAULT 1, snapshot_id TEXT NOT NULL, graph_revision INTEGER NOT NULL DEFAULT 0,
        source_generation INTEGER NOT NULL DEFAULT 1, plan_revision INTEGER NOT NULL DEFAULT 1, intent_id TEXT, stage TEXT,
        node_ids TEXT NOT NULL DEFAULT '[]', edge_ids TEXT NOT NULL DEFAULT '[]', artifact_ids TEXT NOT NULL DEFAULT '[]',
        context TEXT NOT NULL DEFAULT '{}', selection_policy TEXT NOT NULL, request TEXT, created_at TEXT NOT NULL,
        projection_digest TEXT, PRIMARY KEY (projection_id, project_id)
    );
    CREATE INDEX IF NOT EXISTS context_projections_project_idx ON context_projections(project_id, created_at, projection_id);
    CREATE TABLE IF NOT EXISTS snapshots (
        snapshot_id TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        schema_version INTEGER NOT NULL DEFAULT 1, graph_revision INTEGER NOT NULL, source_generation INTEGER NOT NULL,
        plan_revision INTEGER NOT NULL, nodes TEXT NOT NULL DEFAULT '[]', edges TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, project_id)
    );
    CREATE INDEX IF NOT EXISTS snapshots_project_idx ON snapshots(project_id, created_at, snapshot_id);
    """)


def _ensure_intent_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(intents)")}
    if "type" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN type TEXT")
    if "display_title" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN display_title TEXT")
    if "semantic_type" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN semantic_type TEXT NOT NULL DEFAULT 'audit_task'")
    if "relation_type" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN relation_type TEXT NOT NULL DEFAULT 'produces'")
    if "phase" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN phase TEXT NOT NULL DEFAULT 'investigate'")
    if "source_generation" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN source_generation INTEGER NOT NULL DEFAULT 1")
    if "plan_revision" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN plan_revision INTEGER NOT NULL DEFAULT 1")
    if "legacy" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE intents SET legacy = 1")
    conn.execute(
        "UPDATE intents SET "
        "semantic_type = CASE WHEN type LIKE 'review%' THEN 'review_task' ELSE semantic_type END, "
        "relation_type = CASE WHEN type LIKE 'review%' THEN 'reviews' ELSE relation_type END, "
        "phase = CASE WHEN type LIKE 'review%' THEN 'review' ELSE phase END "
        "WHERE legacy = 1"
    )
    conn.execute(
        "UPDATE intents SET display_title = CASE "
        "WHEN description = 'bootstrap' THEN 'Prepare audit context' "
        "WHEN description = '@analysis:scope-evidence' THEN 'Collect scope evidence' "
        "WHEN description = '@analysis:scope-adjudication' THEN 'Decide audit scope' "
        "WHEN description = '@analysis:coverage-plan' THEN 'Plan coverage' "
        "WHEN description = '@analysis:semgrep' THEN 'Run Semgrep' "
        "WHEN description = '@analysis:spotbugs-findsecbugs' THEN 'Run SpotBugs' "
        "WHEN description = '@analysis:osv-scanner' THEN 'Run OSV-Scanner' "
        "WHEN description = '@analysis:gitleaks' THEN 'Run Gitleaks' "
        "WHEN description = '@analysis:trivy' THEN 'Run Trivy' "
        "WHEN description LIKE '@analysis:review:%' OR type LIKE 'review%' THEN 'Review evidence' "
        "WHEN description LIKE '@coverage:%' THEN 'Verify coverage unit' "
        "WHEN description LIKE '@candidate-triage:%' THEN 'Triage candidates' "
        "WHEN description LIKE '@candidate-verify:%' THEN 'Verify candidate' "
        "ELSE substr(trim(description), 1, 88) END "
        "WHERE legacy = 1 AND (display_title IS NULL OR trim(display_title) = '')"
    )


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
