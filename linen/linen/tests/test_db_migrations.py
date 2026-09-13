from __future__ import annotations

import sqlite3

from linen.server import db


def test_configure_adds_project_columns_and_invalidates_ambiguous_legacy_reason_lease(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO projects (
                id, title, created_at, reason_worker, reason_trigger,
                reason_started_at, reason_last_heartbeat_at
            ) VALUES (
                'proj_001', 'legacy', '2026-01-01T00:00:00Z', 'legacy-worker',
                'legacy-trigger', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z'
            )
            """
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT bootstrap_enabled, graph_revision, reason_worker, reason_lease_id
            FROM projects WHERE id = 'proj_001'
            """
        ).fetchone()
    assert row["bootstrap_enabled"] == 1
    assert row["graph_revision"] == 0
    assert row["reason_worker"] is None
    assert row["reason_lease_id"] is None


def test_configure_maps_disabled_bootstrap_mode_to_false(tmp_path, monkeypatch) -> None:
    path = tmp_path / "intermediate.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                bootstrap_mode TEXT NOT NULL DEFAULT 'auto',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_001', 'disabled', 'disabled', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_002', 'enabled', 'enabled', '2026-01-01T00:00:00Z')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        rows = conn.execute("SELECT id, bootstrap_enabled FROM projects ORDER BY id").fetchall()
    assert [(row["id"], row["bootstrap_enabled"]) for row in rows] == [
        ("proj_001", 0),
        ("proj_002", 1),
    ]


def test_configure_invalidates_worker_only_claim_even_when_lease_column_exists(tmp_path, monkeypatch) -> None:
    path = tmp_path / "partially_migrated.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY, title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
                reason_worker TEXT, reason_trigger TEXT, reason_started_at TEXT,
                reason_last_heartbeat_at TEXT, reason_lease_id TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, created_at, reason_worker, reason_lease_id) "
            "VALUES ('proj_001', 'legacy', 'now', 'worker', NULL)"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT reason_worker, reason_lease_id FROM projects WHERE id = 'proj_001'"
        ).fetchone()
    assert row["reason_worker"] is None
    assert row["reason_lease_id"] is None


def test_configure_backfills_semantics_for_partially_migrated_legacy_rows(
    tmp_path, monkeypatch,
) -> None:
    path = tmp_path / "semantic-legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY, title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
                reason_worker TEXT, reason_trigger TEXT, reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            );
            CREATE TABLE facts (
                id TEXT NOT NULL, project_id TEXT NOT NULL,
                description TEXT NOT NULL, display_title TEXT, type TEXT,
                semantic_type TEXT NOT NULL DEFAULT 'observation',
                evidence TEXT, source_generation INTEGER NOT NULL DEFAULT 1,
                legacy INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'triaged',
                PRIMARY KEY (id, project_id)
            );
            CREATE TABLE intents (
                id TEXT NOT NULL, project_id TEXT NOT NULL, to_fact_id TEXT,
                description TEXT NOT NULL, display_title TEXT, type TEXT,
                semantic_type TEXT NOT NULL DEFAULT 'audit_task',
                relation_type TEXT NOT NULL DEFAULT 'produces',
                phase TEXT NOT NULL DEFAULT 'investigate',
                source_generation INTEGER NOT NULL DEFAULT 1,
                plan_revision INTEGER NOT NULL DEFAULT 1,
                legacy INTEGER NOT NULL DEFAULT 1,
                creator TEXT NOT NULL, worker TEXT, last_heartbeat_at TEXT,
                created_at TEXT NOT NULL, concluded_at TEXT,
                PRIMARY KEY (id, project_id)
            );
            INSERT INTO projects (id, title, created_at)
            VALUES ('proj_001', 'legacy', 'now');
            INSERT INTO facts (id, project_id, description, type)
            VALUES ('f001', 'proj_001', 'request parameter reaches handler', 'source');
            INSERT INTO intents (
                id, project_id, description, type, creator, created_at
            ) VALUES (
                'i001', 'proj_001', '@analysis:review:f001',
                'review:cold-verifier', 'dispatcher.audit', 'now'
            );
            """
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        fact = conn.execute(
            "SELECT display_title, semantic_type FROM facts WHERE id = 'f001'"
        ).fetchone()
        intent = conn.execute(
            "SELECT display_title, semantic_type, relation_type, phase "
            "FROM intents WHERE id = 'i001'"
        ).fetchone()
    assert dict(fact) == {
        "display_title": "Input source",
        "semantic_type": "observation",
    }
    assert dict(intent) == {
        "display_title": "Review evidence",
        "semantic_type": "review_task",
        "relation_type": "reviews",
        "phase": "review",
    }
