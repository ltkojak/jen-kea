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
            "hash_kind",
            "config",
            "summary",
            "username",
            "source",
            "created_at",
        }
        assert "mediumtext" in cols["config"]["Type"].lower()
        assert cols["service"]["Type"].lower() == "varchar(8)"
        assert cols["source"]["Default"] == "jen"


class TestConfigRevisionHashKindAndEncryption:
    """v5.20.0 / migration 21 — hash_kind distinguishes a raw-bytes sha
    (helper v2) from a canonical-JSON one (v1/legacy), and config bodies
    are encrypted at rest with the same Fernet key as MFA secrets and
    alert-channel config (migrations 17/18)."""

    def test_migration_21_recorded(self):
        assert 21 in applied_versions()

    def test_hash_kind_column_defaults_to_legacy(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM kea_config_revisions LIKE 'hash_kind'")
            col = cur.fetchone()
        assert "varchar" in col["Type"].lower()
        assert col["Default"] == "legacy"

    def test_encrypts_plaintext_body_preserves_content_and_is_idempotent(self):
        import json

        from jen.models.migrations import _m021_config_revision_hash_kind_and_encrypt
        from jen.services.crypto import PREFIX

        sid = 90211  # a server id no other test seeds
        body = json.dumps({"Dhcp4": {"subnet4": [{"id": 1}]}}, indent=2, sort_keys=True)
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (sid,))
                cur.execute(
                    "INSERT INTO kea_config_revisions (server_id, service, sha256, hash_kind, config, source) "
                    "VALUES (%s, 'dhcp4', 'plainsha', 'legacy', %s, 'jen')",
                    (sid, body),
                )
            db.commit()
        try:
            with jen_db() as db:
                _m021_config_revision_hash_kind_and_encrypt(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM kea_config_revisions WHERE server_id=%s", (sid,))
                after_first = cur.fetchone()["config"]
            assert after_first.startswith(PREFIX)
            assert "subnet4" not in after_first  # ciphertext hides the plaintext

            # Re-run: already-encrypted row left byte-for-byte alone
            with jen_db() as db:
                _m021_config_revision_hash_kind_and_encrypt(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM kea_config_revisions WHERE server_id=%s", (sid,))
                assert cur.fetchone()["config"] == after_first
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (sid,))
                db.commit()


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


class TestForeignKeys:
    """v5.25.0 / migration 23 (Q21, folded in from Q8C) — every table
    that names a user by id gets a real foreign key. Run on both
    MariaDB and MySQL 8 CI legs."""

    _CASCADE_TABLES = (
        "mfa_methods",
        "mfa_backup_codes",
        "mfa_trusted_devices",
        "mfa_attempts",
        "webauthn_credentials",
        "saved_searches",
        "dashboard_prefs",
    )

    def _fk_exists(self, cur, table, constraint):
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM information_schema.TABLE_CONSTRAINTS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND CONSTRAINT_NAME = %s "
            "AND CONSTRAINT_TYPE = 'FOREIGN KEY'",
            (table, constraint),
        )
        return cur.fetchone()["cnt"] > 0

    def test_migration_recorded(self):
        assert 23 in applied_versions()

    def test_foreign_keys_present_on_every_cascade_table(self):
        with jen_db() as db, db.cursor() as cur:
            for table in self._CASCADE_TABLES:
                assert self._fk_exists(cur, table, f"fk_{table}_user_id"), table

    def test_api_keys_created_by_is_nullable_with_set_null_fk(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM api_keys LIKE 'created_by'")
            assert cur.fetchone()["Null"] == "YES"
            assert self._fk_exists(cur, "api_keys", "fk_api_keys_created_by")

    def test_deleting_a_user_cascades_to_mfa_methods(self):
        from jen.models.user import hash_password

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES ('_fk_cascade_test1', %s, 'viewer')",
                    (hash_password("testpass123"),),
                )
                user_id = cur.lastrowid
                cur.execute("INSERT INTO mfa_methods (user_id, method_type, name) VALUES (%s, 'totp', 'x')", (user_id,))
            db.commit()
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
            db.commit()
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM mfa_methods WHERE user_id=%s", (user_id,))
            assert cur.fetchone()["cnt"] == 0

    def test_deleting_a_user_sets_api_keys_created_by_null(self):
        from jen.models.user import hash_password

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES ('_fk_setnull_test1', %s, 'viewer')",
                    (hash_password("testpass123"),),
                )
                user_id = cur.lastrowid
                cur.execute(
                    "INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES (%s, %s, %s, %s)",
                    ("fk test key", f"_fk_test_hash_{user_id}", "fktest01", user_id),
                )
                key_id = cur.lastrowid
            db.commit()
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT created_by FROM api_keys WHERE id=%s", (key_id,))
                assert cur.fetchone()["created_by"] is None
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM api_keys WHERE id=%s", (key_id,))
                db.commit()

    def test_rerun_seeds_and_cleans_an_orphan(self):
        """The real pre-migration-23 scenario, reproduced: drop the FK,
        insert a row pointing at a user_id that doesn't exist (the ADD
        CONSTRAINT would refuse this once the FK is live), then re-run
        the migration function directly and confirm it deletes the
        orphan AND re-adds the constraint — not just an idempotent
        skip when the FK is already present."""
        from jen.models.migrations import _m023_user_foreign_keys

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("ALTER TABLE mfa_attempts DROP FOREIGN KEY fk_mfa_attempts_user_id")
                cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (999999)")
            db.commit()

        with jen_db() as db:
            _m023_user_foreign_keys(db)
            db.commit()

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM mfa_attempts WHERE user_id=999999")
            assert cur.fetchone()["cnt"] == 0
            assert self._fk_exists(cur, "mfa_attempts", "fk_mfa_attempts_user_id")

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m023_user_foreign_keys

        with jen_db() as db:
            _m023_user_foreign_keys(db)  # must not raise when every FK already exists


class TestMigration24WebauthnColumns:
    """v5.31.0 (Q31) — passkeys as a second factor. The table itself is
    from the v4.2.0 baseline; migration 24 adds the two optional columns
    the enrolment flow records. Both must be nullable so the rows that
    predate them (none in practice — the feature was never live) and a
    downgrade stay valid."""

    def test_migration_recorded(self):
        assert 24 in applied_versions()

    def test_columns_present_and_nullable(self):
        with jen_db() as db, db.cursor() as cur:
            for col, typ in (("transports", "varchar(100)"), ("aaguid", "varchar(36)")):
                cur.execute("SHOW COLUMNS FROM webauthn_credentials LIKE %s", (col,))
                row = cur.fetchone()
                assert row is not None, f"webauthn_credentials.{col} missing"
                assert row["Null"] == "YES", col
                assert str(row["Type"]).lower() == typ, (col, row["Type"])

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m024_webauthn_transports_aaguid

        with jen_db() as db:
            _m024_webauthn_transports_aaguid(db)  # must not raise when both columns already exist
            db.commit()


class TestMigration25ApiKeysCanWrite:
    """v5.34.0 (Q33) — API keys gain `can_write`, off by default: every
    key that existed before the write endpoints stays read-only."""

    def test_migration_recorded(self):
        assert 25 in applied_versions()

    def test_column_present_not_null_default_zero(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM api_keys LIKE 'can_write'")
            row = cur.fetchone()
            assert row is not None
            assert row["Null"] == "NO" and str(row["Default"]) == "0"

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m025_api_keys_can_write

        with jen_db() as db:
            _m025_api_keys_can_write(db)
            db.commit()


class TestMigration26ServerStats:
    """v5.41.0 (Q42) — packet health snapshots, one row per Kea server per
    snapshot pass, alongside lease_history."""

    def test_migration_recorded(self):
        assert 26 in applied_versions()

    def test_table_shape(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM server_stats")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert set(cols) == {"id", "server_id", "snapshot_time", "stats"}
        # MySQL 8 reports a real "json" type; MariaDB implements JSON as
        # LONGTEXT + an implicit json_valid() CHECK (see CLAUDE.md's
        # MariaDB JSON gotcha) and SHOW COLUMNS reports it as "longtext".
        assert cols["stats"]["Type"].lower() in ("json", "longtext")
        assert cols["server_id"]["Null"] == "NO"

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m026_server_stats

        with jen_db() as db:
            _m026_server_stats(db)  # must not raise when the table already exists
            db.commit()


class TestMigration27Events:
    """v5.42.0 (Q43) — the event stream `jen.services.events.emit()` writes to."""

    def test_migration_recorded(self):
        assert 27 in applied_versions()

    def test_table_shape(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM events")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert set(cols) == {"id", "ts", "kind", "mac", "ip", "subnet_id", "hostname", "server", "actor", "detail"}
        assert cols["kind"]["Type"].lower() == "varchar(40)"
        assert cols["kind"]["Null"] == "NO"
        for nullable in ("mac", "ip", "subnet_id", "hostname", "server", "actor"):
            assert cols[nullable]["Null"] == "YES", nullable
        assert cols["detail"]["Null"] == "NO"

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m027_events

        with jen_db() as db:
            _m027_events(db)  # must not raise when the table already exists
            db.commit()


class TestMigration29PluginTables:
    """v5.67.0-beta.14 (Q128) — persisted plugin table ownership, so an uninstalled plugin's tables stay in every
    backup."""

    def test_migration_recorded(self):
        assert 29 in applied_versions()

    def test_table_shape(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM plugin_tables")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert set(cols) == {
            "plugin_id",
            "table_name",
            "first_seen_version",
            "code_installed",
            "retained",
            "recorded_at",
        }
        assert cols["plugin_id"]["Key"] == "PRI" and cols["table_name"]["Key"] == "PRI"
        assert cols["first_seen_version"]["Null"] == "YES"
        assert cols["code_installed"]["Default"] == "1" and cols["retained"]["Default"] == "0"
        assert "varchar(64)" in cols["table_name"]["Type"].lower()

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m029_plugin_tables

        with jen_db() as db:
            _m029_plugin_tables(db)  # must not raise when the table already exists
            db.commit()

    def test_it_is_a_new_numbered_migration_not_an_edit_of_an_old_one(self):
        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert by_version[29] == "_m029_plugin_tables"


class TestMigration30ClientProblems:
    """v5.68.0-beta.5 (Q140) - the Problems inbox table, with the unique key the sweep's upsert depends on."""

    def test_migration_recorded_and_it_is_the_newest(self):
        assert 30 in applied_versions()
        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert by_version[30] == "_m030_client_problems" and MIGRATIONS[-1][0] >= 30

    def test_table_shape(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM client_problems")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert (
            set(cols)
            == {
                "id",
                "server_id",
                "kind",
                "mac",
                "ip",
                "subnet_id",
                "first_seen",
                "last_seen",
                "count",
                "detail",
                "alerted_at",
                "alert_attempted_at",
                "qualified_at",
                "qualified_count",
                "scope_key",
                "resolved_at",
            }
        )  # fmt: skip  (alert_attempted_at: migration 31, v5.68.0-beta.9; qualified_*: migration 32, v5.68.0-beta.13; scope_key: 33)
        # mac and ip are NOT NULL with an empty default: a NULL would make the unique key useless (MySQL treats NULLs as distinct)
        assert cols["mac"]["Null"] == "NO" and cols["ip"]["Null"] == "NO"
        assert cols["subnet_id"]["Null"] == "YES" and cols["resolved_at"]["Null"] == "YES"
        assert cols["server_id"]["Default"] == "0"

    def test_the_unique_key_is_server_kind_mac_ip_and_the_scope_key(self):
        # migration 33 (v5.68.0-beta.14, Q149) added `scope_key`: the subnet is part of a row's identity
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW INDEX FROM client_problems WHERE Key_name='uq_client_problem'")
            parts = sorted((r["Seq_in_index"], r["Column_name"]) for r in cur.fetchall())
            cur.execute("SHOW INDEX FROM client_problems WHERE Key_name='uq_client_problem' AND Non_unique=0")
            unique = cur.fetchall()
        assert [c for _s, c in parts] == ["server_id", "kind", "mac", "ip", "scope_key"] and unique

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m030_client_problems

        with jen_db() as db:
            _m030_client_problems(db)  # must not raise when the table already exists
            db.commit()


class TestMigration31ClientProblemsAlertAttempted:
    """v5.68.0-beta.9 (Q144) - `alert_attempted_at`: when the sweep last TRIED to send a Problems alert, apart from `alerted_at` (when one
    was DELIVERED). Additive: a new numbered migration, never an edit of migration 30."""

    def test_migration_recorded_and_it_is_a_new_numbered_one(self):
        assert 31 in applied_versions()
        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert by_version[31] == "_m031_client_problems_alert_attempted" and by_version[30] == "_m030_client_problems"
        assert MIGRATIONS[-1][0] >= 31

    def test_the_column_is_a_nullable_datetime_next_to_alerted_at(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM client_problems LIKE 'alert_attempted_at'")
            col = cur.fetchone()
        assert col is not None and col["Type"].lower().startswith("datetime") and col["Null"] == "YES"

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m031_client_problems_alert_attempted

        with jen_db() as db:
            _m031_client_problems_alert_attempted(db)  # must not raise when the column already exists
            db.commit()

    def test_it_adds_the_column_to_a_table_that_lacks_it_and_keeps_the_rows(self):
        from jen.models.migrations import _m031_client_problems_alert_attempted

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM client_problems WHERE server_id=99")
            cur.execute(
                "INSERT INTO client_problems (server_id, kind, mac, ip, first_seen, last_seen) "
                "VALUES (99, 'nak', 'aa:bb:cc:dd:ee:31', '', NOW(), NOW())"
            )
            cur.execute("ALTER TABLE client_problems DROP COLUMN alert_attempted_at")
            db.commit()
            _m031_client_problems_alert_attempted(db)
            db.commit()
            cur.execute("SELECT alert_attempted_at FROM client_problems WHERE server_id=99")
            assert cur.fetchone() == {"alert_attempted_at": None}
            cur.execute("DELETE FROM client_problems WHERE server_id=99")
            db.commit()


class TestMigration32ClientProblemsQualified:
    """v5.68.0-beta.13 (Q148) - `qualified_at` / `qualified_count`: when a (kind, client, subnet) first crossed the alert threshold and how
    many events it had then, read by the retry of an undelivered alert instead of the log tail. Additive: a new numbered migration, never
    an edit of migration 30 or 31."""

    def test_migration_recorded_and_it_is_a_new_numbered_one(self):
        assert 32 in applied_versions()
        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert (
            by_version[32] == "_m032_client_problems_qualified"
            and by_version[31] == "_m031_client_problems_alert_attempted"
        )
        assert MIGRATIONS[-1][0] >= 32

    def test_the_columns_are_nullable_and_after_alert_attempted_at(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM client_problems")
            fields = [c["Field"] for c in cur.fetchall()]
            cur.execute("SHOW COLUMNS FROM client_problems WHERE Field IN ('qualified_at', 'qualified_count')")
            cols = {c["Field"]: c for c in cur.fetchall()}
        assert cols["qualified_at"]["Type"].lower().startswith("datetime") and cols["qualified_at"]["Null"] == "YES"
        assert cols["qualified_count"]["Type"].lower().startswith("int") and cols["qualified_count"]["Null"] == "YES"
        assert fields.index("qualified_at") == fields.index("alert_attempted_at") + 1

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m032_client_problems_qualified

        with jen_db() as db:
            _m032_client_problems_qualified(db)  # must not raise when the columns already exist
            db.commit()

    def test_it_adds_the_columns_to_a_table_that_lacks_them_and_keeps_the_rows(self):
        from jen.models.migrations import _m032_client_problems_qualified

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM client_problems WHERE server_id=99")
            cur.execute(
                "INSERT INTO client_problems (server_id, kind, mac, ip, first_seen, last_seen) "
                "VALUES (99, 'nak', 'aa:bb:cc:dd:ee:32', '', NOW(), NOW())"
            )
            cur.execute("ALTER TABLE client_problems DROP COLUMN qualified_count, DROP COLUMN qualified_at")
            db.commit()
            _m032_client_problems_qualified(db)
            db.commit()
            cur.execute("SELECT qualified_at, qualified_count FROM client_problems WHERE server_id=99")
            assert cur.fetchone() == {"qualified_at": None, "qualified_count": None}
            cur.execute("DELETE FROM client_problems WHERE server_id=99")
            db.commit()


class TestMigration33ClientProblemsScopeKey:
    """v5.68.0-beta.14 (Q149) - the subnet is part of a Problems row's identity. `scope_key` = COALESCE(subnet_id, -1) is in the unique key
    (a NULL cannot be: MySQL treats NULLs as distinct); the migration DELETES the existing rows (they may be cross-contaminated) and resets
    the per-server watermarks, and runs only when the column is absent."""

    def _insert(self, cur, subnet, scope, server=98, ip=""):
        cur.execute(
            "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, scope_key, first_seen, last_seen) "
            "VALUES (%s, 'nak', 'aa:bb:cc:dd:ee:33', %s, %s, %s, NOW(), NOW())",
            (server, ip, subnet, scope),
        )

    def test_migration_recorded_and_it_is_a_new_numbered_one(self):
        assert 33 in applied_versions()
        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert (
            by_version[33] == "_m033_client_problems_scope_key" and by_version[32] == "_m032_client_problems_qualified"
        )
        assert MIGRATIONS[-1][0] >= 33

    def test_scope_key_is_a_not_null_int_in_the_unique_key(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM client_problems LIKE 'scope_key'")
            col = cur.fetchone()
        assert col["Type"].lower().startswith("int") and col["Null"] == "NO"

    def test_the_same_client_kind_and_empty_address_may_exist_once_per_subnet_including_none(self):
        import pymysql
        import pytest

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM client_problems WHERE server_id=98")
            self._insert(cur, 2, 2)
            self._insert(cur, 1, 1)
            self._insert(cur, None, -1)
            db.commit()
            cur.execute("SELECT COUNT(*) AS n FROM client_problems WHERE server_id=98")
            assert cur.fetchone()["n"] == 3
            for subnet, scope in ((2, 2), (None, -1)):
                with pytest.raises(pymysql.err.IntegrityError):
                    self._insert(cur, subnet, scope)  # the same key twice is still refused, NULL subnet included
                db.rollback()
            cur.execute("DELETE FROM client_problems WHERE server_id=98")
            db.commit()

    def test_rerun_changes_nothing(self):
        from jen.models.migrations import _m033_client_problems_scope_key

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM client_problems WHERE server_id=98")
            self._insert(cur, 2, 2)
            cur.execute("REPLACE INTO settings (setting_key, setting_value) VALUES ('client_problems_wm:98', 'x')")
            db.commit()
            _m033_client_problems_scope_key(db)  # the column exists: nothing is cleared
            db.commit()
            cur.execute("SELECT COUNT(*) AS n FROM client_problems WHERE server_id=98")
            assert cur.fetchone()["n"] == 1
            cur.execute("SELECT setting_value FROM settings WHERE setting_key='client_problems_wm:98'")
            assert cur.fetchone() is not None
            cur.execute("DELETE FROM client_problems WHERE server_id=98")
            cur.execute("DELETE FROM settings WHERE setting_key='client_problems_wm:98'")
            db.commit()

    def test_it_clears_rows_and_watermarks_but_keeps_clock_offsets_when_it_adds_the_column(self):
        from jen.models.migrations import _m033_client_problems_scope_key

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM client_problems")
            self._insert(cur, 2, 2, server=97)
            self._insert(cur, 1, 1, server=96)
            cur.execute("REPLACE INTO settings (setting_key, setting_value) VALUES ('client_problems_wm:97', 'x')")
            cur.execute(
                "REPLACE INTO settings (setting_key, setting_value) VALUES ('client_problems_clock:97', '-18000')"
            )
            db.commit()
            cur.execute("ALTER TABLE client_problems DROP INDEX uq_client_problem")
            cur.execute("ALTER TABLE client_problems DROP COLUMN scope_key")
            cur.execute("ALTER TABLE client_problems ADD UNIQUE KEY uq_client_problem (server_id, kind, mac, ip)")
            db.commit()
            _m033_client_problems_scope_key(db)
            db.commit()
            cur.execute("SELECT COUNT(*) AS n FROM client_problems")
            assert cur.fetchone()["n"] == 0, "every existing row may be cross-contaminated: the inbox starts again"
            cur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE 'client_problems_%'")
            keys = {r["setting_key"] for r in cur.fetchall()}
            assert "client_problems_wm:97" not in keys and "client_problems_clock:97" in keys
            cur.execute("DELETE FROM settings WHERE setting_key LIKE 'client_problems_clock:97'")
            db.commit()
            cur.execute("SHOW INDEX FROM client_problems WHERE Key_name='uq_client_problem'")
            assert [r["Column_name"] for r in sorted(cur.fetchall(), key=lambda r: r["Seq_in_index"])] == [
                "server_id",
                "kind",
                "mac",
                "ip",
                "scope_key",
            ]


class TestMigration28DashboardPrefsWiden:
    """v5.54.0 (Q61) — dashboard_prefs.widgets widened for the v2 prefs
    shape (panel widths + subnet order/pinned/hidden), same VARCHAR-not-TEXT
    reasoning as migration 19 (MySQL 8 forbids a literal DEFAULT on TEXT)."""

    def test_migration_recorded(self):
        assert 28 in applied_versions()

    def test_column_widened(self):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM dashboard_prefs LIKE 'widgets'")
            col = cur.fetchone()
        assert "varchar(4000)" in col["Type"].lower()
        assert col["Null"] == "NO"

    def test_rerun_is_idempotent(self):
        from jen.models.migrations import _m028_dashboard_prefs_widgets_widen

        with jen_db() as db:
            _m028_dashboard_prefs_widgets_widen(db)  # must not raise once already widened
            db.commit()

    def test_a_v2_sized_value_fits(self):
        import json

        # dashboard_prefs.user_id has a foreign key onto users(id) (migration 23) —
        # use the seeded admin (id 1, always present) rather than a made-up id.
        big = {
            "v": 2,
            "panels": [{"id": k, "w": "third"} for k in ("totals", "server_status", "alert_summary")],
            "subnets": {"order": list(range(1, 80)), "pinned": [1, 2], "hidden": [3]},
            "compact": False,
        }
        payload = json.dumps(big)
        assert len(payload) < 4000
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT widgets FROM dashboard_prefs WHERE user_id=1")
            original = cur.fetchone()
            try:
                cur.execute(
                    "INSERT INTO dashboard_prefs (user_id, widgets) VALUES (1, %s) ON DUPLICATE KEY UPDATE widgets=%s",
                    (payload, payload),
                )
                db.commit()
                cur.execute("SELECT widgets FROM dashboard_prefs WHERE user_id=1")
                row = cur.fetchone()
            finally:
                if original is None:
                    cur.execute("DELETE FROM dashboard_prefs WHERE user_id=1")
                else:
                    cur.execute("UPDATE dashboard_prefs SET widgets=%s WHERE user_id=1", (original["widgets"],))
                db.commit()
        assert json.loads(row["widgets"]) == big
