"""Regression tests for the CF-S1-C coverage event ledger.

The acceptance names follow the product manager's E54-E60 list; the C-M and
C-A identifiers name the frozen migration and API conditions.

The trusted baseline provider and the trusted run plan used here live in this
file on purpose.  They are test preconditions installed through application
dependency injection, never request fields: production code carries no
"assume no history" resolver that could be wired in by accident (R2).
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from linen.contracts.common import CF_PRIOR_STATUSES, cf_payload_digest
from linen.contracts.skill_audit import UnitRegisteredPayload
from linen.dispatcher.analysis.coverage_events import (
    coverage_unit_registration_request,
    register_trusted_coverage_unit,
)
from linen.dispatcher.config import CoverageUnitSeed
from linen.server import db
from linen.server.app import app
from linen.server.skill_coverage import (
    DEFAULT_REGISTRATION_POLICY,
    CoverageBaselineResolution,
    CoverageEventConflict,
    CoverageEventRejected,
    CoverageRegistrationPolicy,
    list_registered_units,
    project_registered_units,
    register_unit,
)

PROJECT = "p1"
OTHER_PROJECT = "p2"
RUN = "run-1"
OTHER_RUN = "run-2"
FOREIGN_RUN = "run-x"

#: The frozen v1 field set (PM v1.7 section 2.6, restated in v1.8 section 3.1).
EXPECTED_COLUMNS = [
    "event_id",
    "project_id",
    "run_id",
    "coverage_id",
    "event_type",
    "payload_version",
    "agent_id",
    "wave",
    "event_key",
    "payload_json",
    "payload_sha256",
    "created_at",
]


# --- test doubles ----------------------------------------------------------


class BaselineResolverDouble:
    """A test-only historical baseline provider.

    It distinguishes a verified absence, a compatible history that was
    found, an unknown history, and a failed lookup, because those four
    situations must not collapse into each other.
    """

    def __init__(self, *, ledger: dict[str, str] | None = None, state: str = "resolved") -> None:
        self.ledger = ledger
        self.state = state
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, *, project_id: str, run_id: str, coverage_id: str) -> CoverageBaselineResolution:
        self.calls.append((project_id, run_id, coverage_id))
        if self.state == "failed":
            return CoverageBaselineResolution.failed("the ledger lookup failed")
        if self.state == "unknown":
            return CoverageBaselineResolution.unknown("the history was never established")
        if self.ledger is None:
            return CoverageBaselineResolution.resolved_status(
                prior_status="none",
                kind="no_compatible_ledger",
                lookup_ref="verified-absence-check-1",
            )
        prior = self.ledger.get(coverage_id)
        if prior is None:
            return CoverageBaselineResolution.resolved_status(
                prior_status="new",
                kind="compatible_ledger",
                lookup_ref="compatible-ledger-1",
            )
        return CoverageBaselineResolution.resolved_status(
            prior_status=prior,
            kind="compatible_ledger",
            lookup_ref="compatible-ledger-1",
        )


def _plan(*coverage_ids: str):
    """A trusted plan resolver that only knows the listed coverage units."""

    allowed = set(coverage_ids)

    def _resolve(*, project_id: str, run_id: str, coverage_id: str) -> bool:
        return coverage_id in allowed

    return _resolve


def _insert_run(conn: sqlite3.Connection, project_id: str, run_id: str) -> None:
    conn.execute(
        "INSERT INTO runs (run_id, project_id, task_type, idempotency_key, "
        "timeout_seconds, created_at, updated_at) "
        "VALUES (?, ?, 'hunt', ?, 600, 'now', 'now')",
        (run_id, project_id, f"idem-{project_id}-{run_id}"),
    )


@pytest.fixture
def board(tmp_path, monkeypatch):
    """A configured database with two projects and three runs."""

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "board.db")
    with db.get_conn() as conn:
        conn.execute("INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')", (PROJECT,))
        conn.execute("INSERT INTO projects (id, title, created_at) VALUES (?, 'p', 'now')", (OTHER_PROJECT,))
        _insert_run(conn, PROJECT, RUN)
        _insert_run(conn, PROJECT, OTHER_RUN)
        _insert_run(conn, OTHER_PROJECT, FOREIGN_RUN)
    return tmp_path


@pytest.fixture
def install_policy():
    """Install a registration policy on the running application."""

    def _install(policy: CoverageRegistrationPolicy) -> None:
        app.state.coverage_registration = policy

    yield _install
    if hasattr(app.state, "coverage_registration"):
        del app.state.coverage_registration


def _seed(**overrides) -> CoverageUnitSeed:
    data = {
        "surface": "http-public-api",
        "boundary": "anonymous-to-authenticated",
        "subsystem": "authorization",
        "attack_class": "access-control",
    }
    data.update(overrides)
    return CoverageUnitSeed(**data)


def _payload(
    seed: CoverageUnitSeed | None = None,
    *,
    prior_status: str = "none",
    kind: str = "no_compatible_ledger",
    lookup_ref: str = "verified-absence-check-1",
) -> UnitRegisteredPayload:
    seed = seed or _seed()
    return UnitRegisteredPayload(
        schema_version=1,
        canonical_refs={
            "surface": seed.surface,
            "boundary": seed.boundary,
            "subsystem": seed.subsystem,
            "attack_class": seed.attack_class,
        },
        prior_status=prior_status,
        baseline={"kind": kind, "lookup_ref": lookup_ref},
    )


def _request_body(seed: CoverageUnitSeed, run_id: str = RUN) -> dict:
    return coverage_unit_registration_request(seed, run_id)


def _count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM skill_coverage_events").fetchone()[0]


def _strip_coverage_objects(conn: sqlite3.Connection) -> None:
    """Make the database look like one created before the ledger existed."""

    conn.executescript(
        "DROP TRIGGER IF EXISTS skill_coverage_events_no_update;"
        "DROP TRIGGER IF EXISTS skill_coverage_events_no_delete;"
        "DROP INDEX IF EXISTS uq_skill_coverage_unit_registered;"
        "DROP INDEX IF EXISTS skill_coverage_events_run_idx;"
        "DROP TABLE IF EXISTS skill_coverage_events;"
    )


# --- E54: migration and the first triggers ---------------------------------


def test_skill_coverage_events_new_database(board):
    """C-M01: a fresh database gets the table, the index and the triggers."""

    with db.get_conn() as conn:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(skill_coverage_events)")]
        assert columns == EXPECTED_COLUMNS
        objects = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'skill_coverage_events%' "
                "OR name LIKE 'uq_skill_coverage_unit_registered'"
            )
        }
        assert "skill_coverage_events" in objects
        assert "uq_skill_coverage_unit_registered" in objects
        assert "skill_coverage_events_no_update" in objects
        assert "skill_coverage_events_no_delete" in objects
        triggers = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='skill_coverage_events'"
            )
        }
        assert triggers == {"skill_coverage_events_no_update", "skill_coverage_events_no_delete"}


def test_skill_coverage_events_existing_database_migration(board, monkeypatch):
    """C-M02: an existing database keeps its data and gains the new objects."""

    with db.get_conn() as conn:
        _strip_coverage_objects(conn)
        conn.execute("INSERT INTO facts (id, project_id, description) VALUES ('f1', ?, 'fact')", (PROJECT,))
    with db.get_conn() as conn:
        assert "skill_coverage_events" not in {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(board / "board.db")

    with db.get_conn() as conn:
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "skill_coverage_events" in tables
        row = conn.execute("SELECT description FROM facts WHERE id = 'f1'").fetchone()
        assert row["description"] == "fact"
        run = conn.execute("SELECT run_id FROM runs WHERE run_id = ?", (RUN,)).fetchone()
        assert run["run_id"] == RUN


def test_skill_coverage_events_repeated_configure(board, monkeypatch):
    """C-M03: configuring the same database again neither fails nor duplicates."""

    with db.get_conn() as conn:
        conn.execute("INSERT INTO projects (id, title, created_at) VALUES ('p3', 'p', 'now')")
    db.configure(board / "board.db")  # the stock path returns early

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(board / "board.db")  # forced re-run of the whole migration

    with db.get_conn() as conn:
        tables = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='skill_coverage_events'"
            )
        ]
        assert tables == ["skill_coverage_events"]
        indexes = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='skill_coverage_events' AND name='uq_skill_coverage_unit_registered'"
            )
        ]
        assert indexes == ["uq_skill_coverage_unit_registered"]


def test_skill_coverage_events_existing_events_survive_reconfigure(board, monkeypatch):
    """C-M04: re-running the migration leaves stored events untouched."""

    seed = _seed()
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=_payload(seed)
        )
        before = conn.execute(
            "SELECT event_id, payload_json, payload_sha256, created_at FROM skill_coverage_events"
        ).fetchall()
        assert len(before) == 1

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(board / "board.db")

    with db.get_conn() as conn:
        after = conn.execute(
            "SELECT event_id, payload_json, payload_sha256, created_at FROM skill_coverage_events"
        ).fetchall()
    assert [dict(row) for row in after] == [dict(row) for row in before]


def test_skill_coverage_events_append_only(board):
    """C-M05/C-M06: the database itself refuses to rewrite a stored event."""

    seed = _seed()
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=_payload(seed)
        )
        assert _count(conn) == 1

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE skill_coverage_events SET payload_json = '{}' WHERE project_id = ?",
                (PROJECT,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM skill_coverage_events WHERE project_id = ?", (PROJECT,))

        row = conn.execute(
            "SELECT event_id, payload_sha256 FROM skill_coverage_events WHERE project_id = ?",
            (PROJECT,),
        ).fetchone()
        assert row["event_id"] == 1
        assert row["payload_sha256"] == cf_payload_digest(_payload(seed).model_dump(mode="json"))


def test_skill_coverage_events_foreign_key_rejected(board):
    """C-M07: SQLite really rejects a run that belongs to another project."""

    with db.get_conn() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO skill_coverage_events (project_id, run_id, coverage_id, event_type, "
                "payload_version, event_key, payload_json, payload_sha256, created_at) "
                "VALUES (?, 'run-missing', 'x::y::z::w', 'unit_registered', 1, 'k', '{}', 'd', 'now')",
                (PROJECT,),
            )
        assert _count(conn) == 0


def test_skill_coverage_events_foreign_keys_pragma_is_on(board):
    """C-M08: the pragma is actually on for the connections the server uses."""

    with db.get_conn() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_skill_coverage_events_migration_failure_leaves_usable_database(board, monkeypatch):
    """C-M09: a failed migration leaves no unusable half schema behind.

    ``executescript`` is not atomic in SQLite, so the test states the real
    behaviour instead of assuming a rollback: the statements that already ran
    stay applied, the database remains usable, and a later migration run
    completes the missing objects.
    """

    with db.get_conn() as conn:
        _strip_coverage_objects(conn)
        # A view of the same name makes the table statement fail.
        conn.execute("CREATE VIEW skill_coverage_events AS SELECT 1 AS marker")

    monkeypatch.setattr(db, "_db_path", None)
    with pytest.raises(sqlite3.Error):
        db.configure(board / "board.db")

    # The database is still usable and its business data is intact.
    with db.get_conn() as conn:
        project = conn.execute("SELECT title FROM projects WHERE id = ?", (PROJECT,)).fetchone()
        assert project["title"] == "p"
        conn.execute("DROP VIEW skill_coverage_events")

    # A later migration run completes the ledger.
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(board / "board.db")
    with db.get_conn() as conn:
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "skill_coverage_events" in tables
        triggers = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='skill_coverage_events'"
            )
        }
        assert triggers == {"skill_coverage_events_no_update", "skill_coverage_events_no_delete"}


def test_skill_coverage_events_legacy_business_paths_unchanged(board):
    """C-M10: the other business tables keep working next to the ledger."""

    with TestClient(app) as http:
        created = http.post("/projects", json={"title": "legacy", "origin": "start", "goal": "end"})
        assert created.status_code in (200, 201)
        project_id = created.json()["project"]["id"]
        fetched = http.get(f"/projects/{project_id}")
        assert fetched.status_code == 200


# --- E55: transaction, idempotency and conflict ----------------------------


def test_unit_registered_idempotent_replay(board):
    """C-T09: the same request twice returns the original event."""

    seed = _seed()
    payload = _payload(seed)
    with db.get_conn() as conn:
        first = register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
        )
        second = register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
        )
        assert first.event_id == second.event_id
        assert first.replayed is False
        assert second.replayed is True
        assert _count(conn) == 1


def test_unit_registered_conflicting_payload_rejected(board):
    """C-T10: a different payload for the same unit is a conflict, not an overwrite."""

    seed = _seed()
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=_payload(seed)
        )
        with pytest.raises(CoverageEventConflict):
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=seed.coverage_id,
                payload=_payload(seed, prior_status="new", kind="compatible_ledger", lookup_ref="ledger-9"),
            )
        with pytest.raises(CoverageEventConflict):
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=seed.coverage_id,
                payload=_payload(seed, lookup_ref="another-baseline"),
            )
        assert _count(conn) == 1


def test_unit_registered_same_identity_across_runs(board):
    """C-T11: the same canonical unit may be registered in a different run."""

    seed = _seed()
    payload = _payload(seed)
    with db.get_conn() as conn:
        first = register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
        )
        second = register_unit(
            conn, project_id=PROJECT, run_id=OTHER_RUN, coverage_id=seed.coverage_id, payload=payload
        )
        assert first.event_id != second.event_id
        assert _count(conn) == 2


def test_unit_registered_transaction_rollback(board, monkeypatch):
    """C-T14: a failure inside the transaction leaves no half-finished registration."""

    seed = _seed()
    payload = _payload(seed)

    def _boom(*args, **kwargs):
        raise RuntimeError("response construction failed")

    with monkeypatch.context() as scoped:
        scoped.setattr("linen.server.skill_coverage.RegisteredUnit", _boom)
        with db.get_conn() as conn:
            with pytest.raises(RuntimeError):
                register_unit(
                    conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
                )
    with db.get_conn() as conn:
        assert _count(conn) == 0

    # A caller-owned transaction that is rolled back leaves nothing behind.
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        unit = register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
        )
        assert unit.event_id == 1
        conn.rollback()
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_unit_registered_event_key_collision_rejected(board):
    """E55: a second event key for the same unit is still refused by the index."""

    seed = _seed()
    payload = _payload(seed)
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=payload
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO skill_coverage_events (project_id, run_id, coverage_id, event_type, "
                "payload_version, event_key, payload_json, payload_sha256, created_at) "
                "VALUES (?, ?, ?, 'unit_registered', 1, 'unit_registered:other-key', ?, ?, 'now')",
                (PROJECT, RUN, seed.coverage_id, payload.model_dump_json(), "digest"),
            )
        assert _count(conn) == 1


def test_unit_registered_legacy_coverage_id_rejected(board):
    """C-T12: the retired cov-<n> scheme is not an active id."""

    with db.get_conn() as conn:
        with pytest.raises(CoverageEventRejected):
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id="cov-7",
                payload=_payload(),
            )
        assert _count(conn) == 0


def test_unit_registered_mismatched_coverage_id_rejected(board):
    """C-T04: the coverage id must equal the id derived from the four dimensions."""

    seed = _seed()
    with db.get_conn() as conn:
        with pytest.raises(CoverageEventRejected):
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id="http-public-api::other::authorization::access-control",
                payload=_payload(seed),
            )
        assert _count(conn) == 0


def test_unit_registration_rejects_cross_project_run(board):
    """C-T02: a run of another project can never host a registration."""

    from linen.server.skill_coverage import CoverageRunNotFound

    with db.get_conn() as conn:
        with pytest.raises(CoverageRunNotFound):
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=FOREIGN_RUN,
                coverage_id=_seed().coverage_id,
                payload=_payload(),
            )
        assert _count(conn) == 0


def test_registration_event_has_no_agent_or_wave(board):
    """C-T05: a registration belongs to no agent and no wave."""

    seed = _seed()
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=_payload(seed)
        )
        row = conn.execute(
            "SELECT agent_id, wave, event_type, payload_version FROM skill_coverage_events"
        ).fetchone()
        assert row["agent_id"] is None
        assert row["wave"] is None
        assert row["event_type"] == "unit_registered"
        assert row["payload_version"] == 1


# --- E56: trusted seed and plan binding ------------------------------------


class _RecordingClient:
    def __init__(self, status_code: int = 201, data: dict | None = None) -> None:
        self.calls: list[dict] = []
        self._status_code = status_code
        self._data = data or {}

    def register_coverage_unit(self, project_id, run_id, coverage_id, canonical_refs):
        self.calls.append(
            {
                "project_id": project_id,
                "run_id": run_id,
                "coverage_id": coverage_id,
                "canonical_refs": canonical_refs,
            }
        )
        return type(
            "Result",
            (),
            {
                "status_code": self._status_code,
                "data": {
                    "coverage_id": coverage_id,
                    "event_id": 1,
                    "replayed": False,
                    **self._data,
                },
            },
        )()


def test_unit_registration_uses_trusted_seed():
    """C-T15: only an operator-declared seed can register a unit."""

    seed = _seed()
    client = _RecordingClient()
    outcome = register_trusted_coverage_unit(
        client, project_id=PROJECT, run_id=RUN, seed=seed
    )
    assert outcome.status == "registered"
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["coverage_id"] == seed.coverage_id
    assert call["canonical_refs"] == {
        "surface": seed.surface,
        "boundary": seed.boundary,
        "subsystem": seed.subsystem,
        "attack_class": seed.attack_class,
    }
    # The dispatcher never states a prior status.
    assert "prior_status" not in call
    assert "baseline" not in call


def test_hunt_payload_cannot_register_unit():
    """C-T15: a model payload is not a seed and never creates a coverage unit."""

    seed = _seed()
    client = _RecordingClient()
    with pytest.raises(ValueError):
        register_trusted_coverage_unit(
            client,
            project_id=PROJECT,
            run_id=RUN,
            seed={"coverage_id": seed.coverage_id},  # type: ignore[arg-type]
        )
    assert client.calls == []


# --- E57/E58: the HTTP trust gates and the baseline provider ---------------


def test_skill_event_registration_disabled_by_default(board):
    """C-A10: a stock server refuses every registration."""

    seed = _seed()
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "registration_disabled"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_requires_trusted_caller(board, install_policy):
    """C-A11: an untrusted caller is refused before anything is written."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=False,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "untrusted_caller"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_without_baseline_provider(board, install_policy):
    """C-A09: no trusted baseline provider means no registration."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "trusted_baseline_unavailable"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_rejects_client_prior_status(board, install_policy):
    """C-A07/C-A08: the request may not state a prior status, agent or wave."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    body = _request_body(seed)
    for extra in (
        {"prior_status": "none"},
        {"baseline": {"kind": "no_compatible_ledger", "lookup_ref": "forged"}},
        {"agent_id": "ag-w1-task-abcdef123456"},
        {"wave": 1},
        {"test_mode": True},
    ):
        with TestClient(app) as http:
            response = http.post(
                f"/projects/{PROJECT}/skill-coverage-events", json={**body, **extra}
            )
            assert response.status_code == 422, extra
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_rejects_cross_project_run(board, install_policy):
    """C-A06: a run of another project is not found here."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed, FOREIGN_RUN)
        )
        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "run_not_found"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_rejects_unplanned_coverage_id(board, install_policy):
    """E56: a coverage unit outside the trusted plan is refused."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan("something::else::entirely::different"),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "coverage_unit_not_in_plan"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_rejects_inconsistent_canonical_id(board, install_policy):
    """C-A04: the coverage id must equal the id derived from the dimensions."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan("http-public-api::other::authorization::access-control"),
        )
    )
    body = _request_body(seed)
    body["coverage_id"] = "http-public-api::other::authorization::access-control"
    with TestClient(app) as http:
        response = http.post(f"/projects/{PROJECT}/skill-coverage-events", json=body)
        assert response.status_code == 422
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_rejects_legacy_coverage_id(board, install_policy):
    """C-A05: the retired cov-<n> scheme is refused as an active id."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan("cov-0001"),
        )
    )
    body = _request_body(seed)
    body["coverage_id"] = "cov-0001"
    with TestClient(app) as http:
        response = http.post(f"/projects/{PROJECT}/skill-coverage-events", json=body)
        assert response.status_code == 422
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_skill_event_registration_round_trip(board, install_policy):
    """C-A01/C-A02/C-A03/C-A12: create, replay, conflict, and a second run."""

    seed = _seed()
    resolver = BaselineResolverDouble()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=resolver,
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        created = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert created.status_code == 201
        body = created.json()
        assert body["coverage_id"] == seed.coverage_id
        assert body["replayed"] is False
        assert body["payload"]["prior_status"] == "none"

        replayed = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert replayed.status_code == 200
        assert replayed.json()["replayed"] is True
        assert replayed.json()["event_id"] == body["event_id"]

        # The same identity with a different resolved history is a conflict.
        resolver.ledger = {seed.coverage_id: "prior_deferred"}
        conflict = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "coverage_event_conflict"

        # The same canonical unit in another run is a separate registration.
        resolver.ledger = None
        other = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed, OTHER_RUN)
        )
        assert other.status_code == 201
        assert other.json()["event_id"] != body["event_id"]

    with db.get_conn() as conn:
        assert _count(conn) == 2


def test_skill_event_registration_projection_endpoint(board, install_policy):
    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        http.post(f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed))
        listed = http.get(
            f"/projects/{PROJECT}/skill-coverage-events", params={"run_id": RUN}
        )
        assert listed.status_code == 200
        rows = listed.json()
        assert len(rows) == 1
        assert rows[0]["coverage_id"] == seed.coverage_id
        assert rows[0]["prior_status"] == "none"
        assert rows[0]["registration_event_id"] == 1
        assert set(rows[0]["canonical_refs"]) == {
            "surface",
            "boundary",
            "subsystem",
            "attack_class",
        }


# --- E58: the baseline mapping ---------------------------------------------


def test_unit_registration_none_requires_verified_absence():
    """C-T08: 'none' is a verified absence, not an unknown."""

    seed = _seed()
    with pytest.raises(ValidationError):
        _payload(seed, prior_status="none", kind="compatible_ledger", lookup_ref="ledger-1")
    with pytest.raises(ValidationError):
        _payload(seed, prior_status="new", kind="no_compatible_ledger", lookup_ref="ledger-1")
    payload = _payload(seed, prior_status="none", kind="no_compatible_ledger", lookup_ref="ledger-1")
    assert payload.prior_status == "none"


def test_unit_registration_maps_new_with_compatible_history(board, install_policy):
    """E58: a compatible history that does not contain the unit means 'new'."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(ledger={"other::unit::here::value": "prior_deferred"}),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 201
        assert response.json()["payload"]["prior_status"] == "new"
        assert response.json()["payload"]["baseline"]["kind"] == "compatible_ledger"


def test_unit_registration_rejects_unknown_baseline(board, install_policy):
    """E58: an unknown history blocks the registration instead of becoming none."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(state="unknown"),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "trusted_baseline_unavailable"
    with db.get_conn() as conn:
        assert _count(conn) == 0


def test_unit_registration_rejects_baseline_lookup_failure(board, install_policy):
    """E58: a failed lookup blocks the registration as well."""

    seed = _seed()
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(state="failed"),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "trusted_baseline_unavailable"
    with db.get_conn() as conn:
        assert _count(conn) == 0


# --- E59: the eleven upstream prior statuses -------------------------------


def test_unit_registered_accepts_all_prior_status_values():
    """E59: all eleven upstream prior statuses are contractually valid."""

    for status in CF_PRIOR_STATUSES:
        kind = "no_compatible_ledger" if status == "none" else "compatible_ledger"
        payload = _payload(_seed(), prior_status=status, kind=kind, lookup_ref="ledger-1")
        assert payload.prior_status == status


def test_unit_registered_rejects_invalid_prior_status():
    """E59: a value outside the upstream domain is rejected."""

    with pytest.raises(ValidationError):
        _payload(_seed(), prior_status="maybe", kind="compatible_ledger", lookup_ref="ledger-1")


def test_unit_registered_prior_status_is_immutable(board):
    """E59: a stored prior status cannot be rewritten."""

    seed = _seed()
    with db.get_conn() as conn:
        register_unit(
            conn, project_id=PROJECT, run_id=RUN, coverage_id=seed.coverage_id, payload=_payload(seed)
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE skill_coverage_events SET payload_json = ? WHERE project_id = ?",
                ('{"schema_version":1}', PROJECT),
            )
        stored = conn.execute(
            "SELECT payload_json FROM skill_coverage_events WHERE project_id = ?", (PROJECT,)
        ).fetchone()["payload_json"]
    assert '"prior_status":"none"' in stored.replace(" ", "")


# --- E60: the minimal registration projection ------------------------------


def _projection_events(board, seeds):
    with db.get_conn() as conn:
        for seed in seeds:
            register_unit(
                conn,
                project_id=PROJECT,
                run_id=RUN,
                coverage_id=seed.coverage_id,
                payload=_payload(seed),
            )
        units = list_registered_units(conn, project_id=PROJECT, run_id=RUN)
    return [
        {
            "project_id": unit.project_id,
            "run_id": unit.run_id,
            "coverage_id": unit.coverage_id,
            "registration_event_id": unit.event_id,
            "payload": unit.payload.model_dump(mode="json"),
        }
        for unit in units
    ]


def test_unit_registered_projection_replay(board):
    """E60: the registration view is rebuilt from the event stream alone."""

    first = _seed()
    second = _seed(subsystem="session", attack_class="session-fixation")
    projection = project_registered_units(_projection_events(board, [first, second]))
    assert [row.coverage_id for row in projection] == [first.coverage_id, second.coverage_id]
    assert projection[0].prior_status == "none"
    assert projection[0].registration_event_id == 1
    assert set(projection[0].canonical_refs) == {
        "surface",
        "boundary",
        "subsystem",
        "attack_class",
    }


def test_unit_registered_projection_is_deterministic(board):
    """E60: replaying the same events yields the same view."""

    seed = _seed()
    events = _projection_events(board, [seed])
    first = project_registered_units(events)
    second = project_registered_units(events)
    assert [row.to_dict() for row in first] == [row.to_dict() for row in second]
    # The projection invents no wave, attempt or agent.
    assert all("wave" not in row.to_dict() for row in first)
    assert all("agent_id" not in row.to_dict() for row in first)
    assert all("attempts" not in row.to_dict() for row in first)


def test_unit_registered_projection_rejects_invalid_payload(board):
    """E60: a payload that contradicts its coverage id is refused."""

    seed = _seed()
    events = _projection_events(board, [seed])
    with pytest.raises(CoverageEventRejected):
        project_registered_units([{**events[0], "coverage_id": "other::unit::here::value"}])
    with pytest.raises(CoverageEventConflict):
        project_registered_units([events[0], events[0]])
    with pytest.raises(ValidationError):
        project_registered_units(
            [{**events[0], "payload": {**events[0]["payload"], "prior_status": "maybe"}}]
        )


# --- E63: the audit history is not deletable through the normal paths -------


def _plan_accepting_everything():
    """A trusted plan resolver that trusts every coverage id.

    It exists so the canonical identity check can be exercised on its own:
    with a narrow plan the plan check answers first, and the reported reason
    would be the plan instead of the identity.
    """

    def _resolve(*, project_id: str, run_id: str, coverage_id: str) -> bool:
        return True

    return _resolve


def _install_trusted_policy(install_policy, *coverage_ids: str) -> None:
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(*coverage_ids),
        )
    )


def test_project_with_skill_coverage_events_cannot_be_deleted(board, install_policy):
    """E63: a project that owns append-only events is not deletable.

    The refusal comes from the foreign key, not from a trigger: the ledger
    references both the project and the run, and both references are NO
    ACTION, so the delete is rejected by the database constraint layer.
    """

    seed = _seed()
    _install_trusted_policy(install_policy, seed.coverage_id)
    with TestClient(app) as http:
        registered = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
        assert registered.status_code == 201

        refused = http.delete(f"/projects/{PROJECT}")
        assert refused.status_code == 409
        assert refused.json()["detail"]["code"] == "PROJECT_HAS_COVERAGE_EVENTS"

    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT 1 FROM projects WHERE id = ?", (PROJECT,)
        ).fetchone() is not None
        assert _count(conn) == 1


def test_run_with_skill_coverage_events_cannot_be_deleted(board, install_policy):
    """E63: the run that owns the history is not deletable either."""

    seed = _seed()
    _install_trusted_policy(install_policy, seed.coverage_id)
    with TestClient(app) as http:
        assert http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        ).status_code == 201

    with db.get_conn() as conn:
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute("DELETE FROM runs WHERE run_id = ?", (RUN,))
        assert "FOREIGN KEY" in str(excinfo.value)

    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ?", (RUN,)
        ).fetchone() is not None
        assert _count(conn) == 1


def test_project_without_skill_coverage_events_preserves_delete_behavior(board):
    """E63: the delete behaviour only changes for projects that own history."""

    with TestClient(app) as http:
        assert http.delete(f"/projects/{OTHER_PROJECT}").status_code == 204
        assert http.get(f"/projects/{OTHER_PROJECT}").status_code == 404

    with db.get_conn() as conn:
        assert conn.execute(
            "SELECT 1 FROM projects WHERE id = ?", (OTHER_PROJECT,)
        ).fetchone() is None
        assert conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ?", (FOREIGN_RUN,)
        ).fetchone() is None


# --- E64: the HTTP v1 contract is a frozen, documented interface -----------


def test_skill_coverage_event_http_contract_status_codes(board, install_policy):
    """E64: every documented status code and reason code is reachable."""

    seed = _seed()
    body = _request_body(seed)

    # 503: production registration is switched off.
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "registration_disabled"

    # 403: the caller is not an accepted writer.
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=False,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "untrusted_caller"

    # 503: no trusted historical baseline is installed.
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "trusted_baseline_unavailable"

    # 422: the coverage unit is not part of the trusted plan.
    _install_trusted_policy(install_policy, "some::other::coverage::unit")
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "coverage_unit_not_in_plan"

    # 404: the run does not belong to the project.
    _install_trusted_policy(install_policy, seed.coverage_id)
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events",
            json={**body, "run_id": FOREIGN_RUN},
        )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "run_not_found"

    # 422: the canonical identity does not hold.  The check order is frozen
    # (v1.8 section 3.1): the trusted plan is consulted before the canonical
    # identity, so the inconsistent id has to be planned for the internal
    # contradiction to be the reported reason.
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(),
            plan_resolver=_plan_accepting_everything(),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events",
            json={**body, "coverage_id": "not::the::derived::id"},
        )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "coverage_event_rejected"

    # 201: the first registration.
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 201
    first_event_id = response.json()["event_id"]

    # 200: the same payload replays onto the original event.
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 200
    assert response.json()["event_id"] == first_event_id
    assert response.json()["replayed"] is True

    # 409: the same identity with a different payload.  The baseline is a
    # server-side decision, so the only way to change the payload of the same
    # coverage unit is to change what the trusted baseline resolves to.
    install_policy(
        CoverageRegistrationPolicy(
            enabled=True,
            trusted_caller=True,
            baseline_resolver=BaselineResolverDouble(
                ledger={seed.coverage_id: "new"}
            ),
            plan_resolver=_plan(seed.coverage_id),
        )
    )
    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=body
        )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "coverage_event_conflict"


def test_skill_coverage_event_http_contract_rejects_extra_fields(board, install_policy):
    """E64: the request model is closed; authority is never a request field."""

    seed = _seed()
    _install_trusted_policy(install_policy, seed.coverage_id)
    body = _request_body(seed)

    for field, value in (
        ("prior_status", "none"),
        ("baseline", {"kind": "no_compatible_ledger", "lookup_ref": "forged"}),
        ("agent_id", "ag-w1-task-abcdef123456"),
        ("wave", 1),
        ("payload", {"prior_status": "none"}),
    ):
        with TestClient(app) as http:
            response = http.post(
                f"/projects/{PROJECT}/skill-coverage-events", json={**body, field: value}
            )
        assert response.status_code == 422, field

    with db.get_conn() as conn:
        assert _count(conn) == 0


# --- E65: the production gate and the test injection stay separate ---------


def test_skill_event_production_policy_remains_disabled(board):
    """E65: a stock server has no writer, no plan and no baseline."""

    assert DEFAULT_REGISTRATION_POLICY.enabled is False
    assert DEFAULT_REGISTRATION_POLICY.trusted_caller is False
    assert DEFAULT_REGISTRATION_POLICY.baseline_resolver is None
    assert DEFAULT_REGISTRATION_POLICY.plan_resolver is None

    with TestClient(app) as http:
        assert not hasattr(app.state, "coverage_registration")
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(_seed())
        )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "registration_disabled"


def test_skill_event_test_provider_is_not_exposed_over_http(board, install_policy):
    """E65: a test provider is not a public capability and does not persist."""

    seed = _seed()
    _install_trusted_policy(install_policy, seed.coverage_id)

    with TestClient(app) as http:
        response = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
    assert response.status_code == 201
    # The provider identity never reaches the client.
    assert "BaselineResolverDouble" not in response.text
    assert "baseline_resolver" not in response.text
    assert "plan_resolver" not in response.text
    # And the published schema exposes no provider field either.
    schema = app.openapi()
    component = schema["components"]["schemas"]["SkillCoverageEventRequest"]
    assert set(component["properties"]) == {
        "run_id",
        "event_type",
        "payload_version",
        "coverage_id",
        "canonical_refs",
    }

    # A fresh process without the installed policy refuses again: the test
    # injection cannot survive into a production-shaped process.
    if hasattr(app.state, "coverage_registration"):
        del app.state.coverage_registration
    with TestClient(app) as http:
        refused = http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        )
    assert refused.status_code == 503
    assert refused.json()["detail"]["code"] == "registration_disabled"


# --- E66: the read side is scoped to one project ---------------------------


def test_skill_coverage_projection_is_project_scoped(board, install_policy):
    """E66: one project never sees another project's registration."""

    seed = _seed()
    _install_trusted_policy(install_policy, seed.coverage_id)
    with TestClient(app) as http:
        assert http.post(
            f"/projects/{PROJECT}/skill-coverage-events", json=_request_body(seed)
        ).status_code == 201

        listed = http.get(
            f"/projects/{PROJECT}/skill-coverage-events", params={"run_id": RUN}
        )
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        # The same run id under another project exposes nothing.
        scoped = http.get(
            f"/projects/{OTHER_PROJECT}/skill-coverage-events",
            params={"run_id": RUN},
        )
        assert scoped.status_code == 200
        assert scoped.json() == []


def test_skill_coverage_projection_rejects_unknown_project(board, install_policy):
    """E66: an unknown project is refused instead of returning an empty view."""

    _install_trusted_policy(install_policy, _seed().coverage_id)
    with TestClient(app) as http:
        response = http.get(
            f"/projects/does-not-exist/skill-coverage-events", params={"run_id": RUN}
        )
    assert response.status_code == 404

