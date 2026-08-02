"""
tests/test_migrations.py
────────────────────────
Versioned schema migration guarantees (v4.2.0).

Runs against jen_test (schema already migrated by conftest's
init_jen_db call), so these verify recorded state, idempotency,
registry integrity, and the admin-role regression fix.
"""

import pytest

from jen.models.db import jen_db
from jen.models.migrations import (
    MIGRATIONS, applied_versions, latest_version, run_migrations,
)


class TestRegistry:

    def test_versions_strictly_increasing(self):
        versions = [v for v, _, _ in MIGRATIONS]
        assert versions == sorted(set(versions))

    def test_descriptions_present(self):
        assert all(d.strip() for _, d, _ in MIGRATIONS)

    def test_latest_version_matches_registry(self):
        assert latest_version() == MIGRATIONS[-1][0]


class TestAppliedState:

    def test_schema_migrations_table_exists(self):
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SHOW TABLES LIKE 'schema_migrations'")
                assert cur.fetchone() is not None

    def test_all_versions_recorded(self):
        assert applied_versions() == {v for v, _, _ in MIGRATIONS}

    def test_rerun_is_noop(self):
        assert run_migrations() == 0
        assert applied_versions() == {v for v, _, _ in MIGRATIONS}

    def test_recorded_descriptions_match_registry(self):
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT version, description FROM schema_migrations")
                recorded = {r["version"]: r["description"] for r in cur.fetchall()}
        for version, description, _ in MIGRATIONS:
            assert recorded[version] == description


class TestAdminRoleRegression:
    """
    Prior to v4.2.0, init_jen_db promoted every 'admin' user to superadmin
    on each startup — silently escalating deliberate mid-tier RBAC accounts.
    Migration 6 is version-gated and pre-3.5-schema-scoped, so an 'admin'
    user must survive any number of migration runs (i.e. app restarts).
    """

    def test_admin_user_survives_migration_rerun(self):
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_mig_admin_probe'")
                cur.execute(
                    "INSERT INTO users (username, password, role) "
                    "VALUES ('_mig_admin_probe', 'x', 'admin')"
                )
            db.commit()
        try:
            run_migrations()   # simulates a restart
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "SELECT role FROM users WHERE username='_mig_admin_probe'"
                    )
                    assert cur.fetchone()["role"] == "admin"
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username='_mig_admin_probe'")
                db.commit()
