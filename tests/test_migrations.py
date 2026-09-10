"""
tests/test_migrations.py
────────────────────────
Versioned schema migration guarantees (v4.2.0).

Runs against jen_test (schema already migrated by conftest's
init_jen_db call), so these verify recorded state, idempotency,
registry integrity, and the admin-role regression fix.
"""

from jen.models.db import jen_db
from jen.models.migrations import (
    MIGRATIONS,
    applied_versions,
    latest_version,
    run_migrations,
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
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW TABLES LIKE 'schema_migrations'")
            assert cur.fetchone() is not None

    def test_all_versions_recorded(self):
        assert applied_versions() == {v for v, _, _ in MIGRATIONS}

    def test_rerun_is_noop(self):
        assert run_migrations() == 0
        assert applied_versions() == {v for v, _, _ in MIGRATIONS}

    def test_recorded_descriptions_match_registry(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT version, description FROM schema_migrations")
            recorded = {r["version"]: r["description"] for r in cur.fetchall()}
        for version, description, _ in MIGRATIONS:
            assert recorded[version] == description


class TestDashboardWidgetsPortability:
    """v5.8.0 / migration 19 — dashboard_prefs.widgets must be VARCHAR,
    not TEXT: MySQL 8 rejects a literal DEFAULT on a TEXT column (the CI
    MySQL leg caught the baseline failing to build)."""

    def test_widgets_column_is_varchar_with_a_default(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM dashboard_prefs LIKE 'widgets'")
            col = cur.fetchone()
        assert "varchar" in col["Type"].lower(), col["Type"]
        assert col["Default"] and "subnet_stats" in col["Default"]

    def test_migration_19_recorded(self):
        assert 19 in applied_versions()


class TestKeaConfigRevisionsTable:
    """v5.16.0 / migration 20 — the Kea config history table."""

    def test_migration_20_recorded(self):
        assert 20 in applied_versions()

    def test_table_shape(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM kea_config_revisions")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert set(cols) == {
            "id",
            "server_id",
            "service",
            "sha256",
            "config",
            "summary",
            "username",
            "source",
            "created_at",
        }
        assert "mediumtext" in cols["config"]["Type"].lower()
        assert cols["service"]["Type"].lower() == "varchar(8)"
        assert cols["source"]["Default"] == "jen"


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
                cur.execute("INSERT INTO users (username, password, role) VALUES ('_mig_admin_probe', 'x', 'admin')")
            db.commit()
        try:
            run_migrations()  # simulates a restart
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE username='_mig_admin_probe'")
                assert cur.fetchone()["role"] == "admin"
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username='_mig_admin_probe'")
                db.commit()


class TestBackfillMustChangePasswordMigration:
    """
    v5.3.3 — migration 15 only added the must_change_password column
    with DEFAULT 0, which left every row that already existed at the
    time it ran flagged as "already fine" — including a user whose
    password genuinely still was, and still is, the literal string
    "admin". This couldn't be fixed by editing migration 15's own
    function body, since the migration runner never re-invokes an
    already-applied migration; a new migration (16) is the only way to
    reach installations that already applied 15 (which by now is most
    of the deployed base — anything on v5.2.7 or later).
    """

    def test_pure_logic_only_flags_users_still_on_literal_admin(self):
        """Direct test of the migration function's own logic against a
        fake cursor, independent of the live jen_test database — lets
        this specifically verify the SELECT/UPDATE decision logic
        (using REAL password hashing/verification, not mocked) without
        needing to seed and clean up real rows for every case."""
        from jen.models.migrations import _m016_backfill_must_change_password_for_existing_admin_admin
        from jen.models.user import hash_password

        class FakeCursor:
            def __init__(self, rows):
                self.rows = rows
                self.executed = []

            def execute(self, sql, params=None):
                self.executed.append((sql, params))

            def fetchall(self):
                return self.rows

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeDB:
            def __init__(self, cursor):
                self._cursor = cursor

            def cursor(self):
                return self._cursor

        admin_hash = hash_password("admin")
        real_hash = hash_password("SomeRealPassword123!")
        rows = [
            {"id": 1, "password": admin_hash},
            {"id": 2, "password": real_hash},
            {"id": 3, "password": None},
        ]
        cur = FakeCursor(rows)
        _m016_backfill_must_change_password_for_existing_admin_admin(FakeDB(cur))

        update_calls = [e for e in cur.executed if e[0].startswith("UPDATE")]
        assert len(update_calls) == 1, f"expected exactly 1 UPDATE, got {update_calls}"
        assert update_calls[0][1] == (1,), "only the user still on literal 'admin' should be flagged"

        select_calls = [e for e in cur.executed if e[0].startswith("SELECT")]
        assert len(select_calls) == 1
        assert "must_change_password = 0" in select_calls[0][0], (
            "must scope to unflagged rows — no need to re-check users already flagged"
        )

    def test_end_to_end_against_real_database(self):
        """Real-DB integration test: an existing user (simulating an
        upgraded, not fresh, install) whose password is still the
        literal default gets flagged when the migration function runs
        directly against jen_test, and one with a real, changed
        password is left alone."""
        from jen.models.migrations import _m016_backfill_must_change_password_for_existing_admin_admin
        from jen.models.user import hash_password

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username IN ('_mig16_stale_default', '_mig16_real_pw')")
                cur.execute(
                    "INSERT INTO users (username, password, role, must_change_password) "
                    "VALUES ('_mig16_stale_default', %s, 'admin', 0)",
                    (hash_password("admin"),),
                )
                cur.execute(
                    "INSERT INTO users (username, password, role, must_change_password) "
                    "VALUES ('_mig16_real_pw', %s, 'admin', 0)",
                    (hash_password("ActuallyChangedThis456!"),),
                )
            db.commit()
        try:
            with jen_db() as db:
                _m016_backfill_must_change_password_for_existing_admin_admin(db)
                db.commit()

            with jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "SELECT username, must_change_password FROM users "
                    "WHERE username IN ('_mig16_stale_default', '_mig16_real_pw')"
                )
                results = {r["username"]: r["must_change_password"] for r in cur.fetchall()}
            assert results["_mig16_stale_default"] == 1, "user still on literal 'admin' must be flagged"
            assert results["_mig16_real_pw"] == 0, "user with a real, changed password must not be flagged"
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username IN ('_mig16_stale_default', '_mig16_real_pw')")
                db.commit()
