"""
tests/test_plugin_migrations.py
──────────────────────────────────
jen/services/plugins.py's DB migration runner had zero test coverage
before this — same gap as self_update() had before v4.4.16, and the
same root cause: no test meant no automated proof the actual behavior
matched what the docstring claimed. Every assertion here was first
proven by hand against real MariaDB before being written as a test, not
the other way around — see CHANGELOG v4.4.18 for the manual verification
this mirrors.
"""

import json

from jen.services.plugins import _plugin_applied_versions, run_plugin_migrations


def _t1_manifest(plugin_id="test_plugin_a"):
    return {
        "id": plugin_id,
        "db_migrations": [
            {
                "version": 1,
                "description": "first table",
                "sql": f"CREATE TABLE IF NOT EXISTS {plugin_id}_t1 (id INT PRIMARY KEY)",
            },
            {
                "version": 2,
                "description": "second table",
                "sql": f"CREATE TABLE IF NOT EXISTS {plugin_id}_t2 (id INT PRIMARY KEY)",
            },
        ],
    }


class TestTrackingAndIdempotency:
    def test_first_run_applies_all_pending(self, db):
        ok, msg, count = run_plugin_migrations(_t1_manifest("test_plugin_b"))
        assert ok is True
        assert count == 2

    def test_second_run_applies_nothing(self, db):
        manifest = _t1_manifest("test_plugin_c")
        run_plugin_migrations(manifest)
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 0, "already-applied migrations must not be re-run"

    def test_applied_versions_tracked_correctly(self, db):
        run_plugin_migrations(_t1_manifest("test_plugin_d"))
        assert _plugin_applied_versions("test_plugin_d") == {1, 2}

    def test_new_migration_added_later_gets_picked_up(self, db):
        manifest = _t1_manifest("test_plugin_e")
        run_plugin_migrations(manifest)
        manifest["db_migrations"].append(
            {
                "version": 3,
                "description": "third table",
                "sql": "CREATE TABLE IF NOT EXISTS test_plugin_e_t3 (id INT PRIMARY KEY)",
            }
        )
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 1, "only the new migration should apply, not 1 and 2 again"
        assert _plugin_applied_versions("test_plugin_e") == {1, 2, 3}

    def test_plugins_are_tracked_independently(self, db):
        run_plugin_migrations(_t1_manifest("test_plugin_f"))
        # A different plugin_id with the same version numbers must not
        # be considered "already applied" just because another plugin
        # happens to be at the same version.
        assert _plugin_applied_versions("test_plugin_g") == set()


class TestFailureHandling:
    """The actual bug this whole system exists to fix: a failing
    migration used to silently abort the whole batch with nothing but
    a log line, while the caller was told the install succeeded."""

    def test_broken_migration_stops_processing_and_reports_failure(self, db):
        manifest = {
            "id": "failing_plugin_x",
            "db_migrations": [
                {
                    "version": 1,
                    "description": "good table",
                    "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_x_t1 (id INT PRIMARY KEY)",
                },
                {"version": 2, "description": "broken", "sql": "CREATE TABLE THIS IS NOT VALID SQL AT ALL"},
                {
                    "version": 3,
                    "description": "never reached",
                    "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_x_t3 (id INT PRIMARY KEY)",
                },
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is False
        assert count == 1, "only migration 1 (before the broken one) should have applied"
        assert "migration 2" in msg, "error message must identify which migration failed"

    def test_migration_after_the_broken_one_never_runs(self, db):
        manifest = {
            "id": "failing_plugin_y",
            "db_migrations": [
                {"version": 1, "description": "broken", "sql": "NOT VALID SQL"},
                {
                    "version": 2,
                    "description": "should never run",
                    "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_y_t2 (id INT PRIMARY KEY)",
                },
            ],
        }
        run_plugin_migrations(manifest)
        with db.cursor() as cur:
            cur.execute("SHOW TABLES LIKE 'failing_plugin_y_t2'")
            assert cur.fetchone() is None

    def test_failed_migration_is_not_recorded_as_applied(self, db):
        manifest = {
            "id": "failing_plugin_z",
            "db_migrations": [
                {"version": 1, "description": "broken", "sql": "NOT VALID SQL"},
            ],
        }
        run_plugin_migrations(manifest)
        assert _plugin_applied_versions("failing_plugin_z") == set()


class TestManifestValidation:
    def test_missing_db_migrations_key_is_a_no_op(self, db):
        ok, msg, count = run_plugin_migrations({"id": "no_migrations_plugin"})
        assert ok is True
        assert count == 0

    def test_empty_db_migrations_list_is_a_no_op(self, db):
        ok, msg, count = run_plugin_migrations({"id": "empty_migrations_plugin", "db_migrations": []})
        assert ok is True
        assert count == 0

    def test_rejects_old_flat_string_format(self, db):
        """v4.4.19 correction: the old flat-string format is now
        accepted, not rejected — see TestBackwardCompatibility below.
        Kept as a marker that malformed non-string, non-dict entries
        are still correctly rejected."""
        manifest = {
            "id": "genuinely_malformed_plugin",
            "db_migrations": [12345],  # neither a string nor a valid dict
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is False
        assert count == 0

    def test_rejects_duplicate_version_numbers(self, db):
        manifest = {
            "id": "dup_version_plugin",
            "db_migrations": [
                {"version": 1, "description": "a", "sql": "CREATE TABLE IF NOT EXISTS dup_a (id INT)"},
                {"version": 1, "description": "b", "sql": "CREATE TABLE IF NOT EXISTS dup_b (id INT)"},
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is False
        assert count == 0

    def test_migrations_applied_in_version_order_regardless_of_list_order(self, db):
        """Manifest lists them out of order — the runner must still
        apply by version number, not list position."""
        manifest = {
            "id": "out_of_order_plugin",
            "db_migrations": [
                {"version": 2, "description": "second", "sql": "CREATE TABLE IF NOT EXISTS ooo_t2 (id INT)"},
                {"version": 1, "description": "first", "sql": "CREATE TABLE IF NOT EXISTS ooo_t1 (id INT)"},
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 2
        assert _plugin_applied_versions("out_of_order_plugin") == {1, 2}


class TestRealShippedManifests:
    """The actual ipam and network-discovery manifests shipped in this
    repo, not synthetic test data — confirms the v4.4.18 conversion
    from the old flat-string format didn't break either real plugin."""

    def test_ipam_manifest_applies_correctly(self, db):
        with open("plugins/ipam/manifest.json") as f:
            manifest = json.load(f)
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True, f"ipam manifest failed: {msg}"
        # v5.28.2 — the bundled copy is the real v1.4.4 manifest: 13
        # explicit, portable migrations. 8 (`DROP INDEX ip`) has nothing
        # to drop on a fresh table and is recorded via the runner's
        # already-in-effect tolerance — on MySQL 8 as well as MariaDB.
        assert count == 13
        assert _plugin_applied_versions("ipam") == set(range(1, 14))
        with db.cursor() as cur:
            for tbl in ("ipam_static_entries", "ipam_assignment_history", "ipam_subnets"):
                cur.execute(f"SHOW TABLES LIKE '{tbl}'")
                assert cur.fetchone() is not None, f"{tbl} was not created"
            cur.execute("SHOW COLUMNS FROM ipam_static_entries LIKE 'entry_status'")
            assert cur.fetchone() is not None, "migration 12 (entry_status) must have applied after 8's tolerated DROP"

    def test_network_discovery_manifest_applies_correctly(self, db):
        with open("plugins/network-discovery/manifest.json") as f:
            manifest = json.load(f)
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True, f"network-discovery manifest failed: {msg}"
        assert count == 2
        with db.cursor() as cur:
            for tbl in ("nd_scan_jobs", "nd_scan_results"):
                cur.execute(f"SHOW TABLES LIKE '{tbl}'")
                assert cur.fetchone() is not None, f"{tbl} was not created"

    def test_both_real_manifests_are_idempotent_on_second_run(self, db):
        for path in ("plugins/ipam/manifest.json", "plugins/network-discovery/manifest.json"):
            with open(path) as f:
                manifest = json.load(f)
            run_plugin_migrations(manifest)
            ok, msg, count = run_plugin_migrations(manifest)
            assert ok is True
            assert count == 0, f"{path} was not idempotent on second run"


class TestBackwardCompatWithOldFlatFormat:
    """v4.4.19 regression guard — v4.4.18 correctly rejected the old
    flat-string manifest format, but load_plugins() then skipped the
    entire plugin (blueprint + nav, not just migrations) whenever that
    happened. A real installed plugin from its own separate repo, still
    on the old format, disappeared from the UI entirely even though its
    tables and data were completely fine. Both halves of that bug are
    guarded here: old-format manifests must now parse successfully, and
    a migration failure of any kind must never be load_plugins()'s
    reason to skip loading a plugin."""

    def test_old_flat_string_format_now_succeeds(self, db):
        manifest = {
            "id": "old_format_ok_plugin",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS old_format_ok_t1 (id INT PRIMARY KEY)",
                "CREATE TABLE IF NOT EXISTS old_format_ok_t2 (id INT PRIMARY KEY)",
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 2

    def test_old_format_strings_get_sequential_implicit_versions(self, db):
        manifest = {
            "id": "old_format_versions_plugin",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS ofv_t1 (id INT PRIMARY KEY)",
                "CREATE TABLE IF NOT EXISTS ofv_t2 (id INT PRIMARY KEY)",
                "CREATE TABLE IF NOT EXISTS ofv_t3 (id INT PRIMARY KEY)",
            ],
        }
        run_plugin_migrations(manifest)
        assert _plugin_applied_versions("old_format_versions_plugin") == {1, 2, 3}

    def test_old_format_is_idempotent_on_second_run(self, db):
        manifest = {
            "id": "old_format_idempotent_plugin",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS ofi_t1 (id INT PRIMARY KEY)",
            ],
        }
        run_plugin_migrations(manifest)
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 0

    def test_mixed_old_and_new_format_entries_both_work(self, db):
        manifest = {
            "id": "mixed_format_plugin",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS mixed_t1 (id INT PRIMARY KEY)",
                {
                    "version": 2,
                    "description": "new-format entry",
                    "sql": "CREATE TABLE IF NOT EXISTS mixed_t2 (id INT PRIMARY KEY)",
                },
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True
        assert count == 2

    def test_matthews_real_diverged_ipam_manifest(self, db):
        """The actual real-world manifest content that surfaced this bug
        — three tables, old flat-string format, one table
        (ipam_subnets) that isn't even in the version jen-kea ships,
        since the installed plugin comes from its own separate repo.
        Uses a distinct plugin_id from the "ipam" used elsewhere in this
        file (TestRealShippedManifests) — plugin_schema_migrations is
        tracked per plugin_id, and tests in this file share one database
        across the session, so reusing "ipam" here would see partial
        state left over from that other test rather than a clean run."""
        manifest = {
            "id": "ipam_real_world_diverged",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS ipamrwd_static_entries (id INT AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(15) NOT NULL, subnet_id INT NOT NULL, label VARCHAR(100), owner VARCHAR(100), notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)",
                "CREATE TABLE IF NOT EXISTS ipamrwd_assignment_history (id INT AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(15) NOT NULL, subnet_id INT NOT NULL, label VARCHAR(100), owner VARCHAR(100), action VARCHAR(20), acted_at DATETIME DEFAULT CURRENT_TIMESTAMP, acted_by VARCHAR(100))",
                "CREATE TABLE IF NOT EXISTS ipamrwd_subnets (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, cidr VARCHAR(18) NOT NULL, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)",
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True, f"real ipam manifest should succeed: {msg}"
        assert count == 3
        with db.cursor() as cur:
            for tbl in ("ipamrwd_static_entries", "ipamrwd_assignment_history", "ipamrwd_subnets"):
                cur.execute(f"SHOW TABLES LIKE '{tbl}'")
                assert cur.fetchone() is not None, f"{tbl} was not created"


class TestLoadPluginsMigrationGate:
    """v5.28.1 (Q26, C3-iii) narrows the v4.4.19 fix: a migration
    failure only loads the plugin anyway when THIS EXACT VERSION has
    already migrated cleanly once before (`plugin_migrated_ok:<id>`
    matches `plugin["version"]`) — that's the original v4.4.19 case
    (an unrelated/format quirk on an already-working install). A
    version that has never migrated cleanly, or a newer version whose
    migration just failed for the first time, is not loaded — running
    new code against a schema its own migration never reached is worse
    than the plugin vanishing from the nav until it's fixed."""

    def _fake_manifest(self, plugin_id, version):
        return {
            "id": plugin_id,
            "path": f"/tmp/nonexistent_{plugin_id}",
            "enabled": True,
            "version_ok": True,
            "version": version,
            "db_migrations": [
                {"version": 1, "description": "broken", "sql": "NOT VALID SQL AT ALL"},
            ],
        }

    def _cleanup(self, db, plugin_id):
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM settings WHERE setting_key IN (%s, %s)",
                (f"plugin_migrated_ok:{plugin_id}", f"plugin_migration_failed:{plugin_id}"),
            )
        db.commit()

    def test_never_migrated_cleanly_is_skipped(self, db, monkeypatch, app):
        from jen.models.user import get_global_setting
        from jen.services import plugins as plugins_mod

        plugin_id = "q26_never_migrated_plugin"
        self._cleanup(db, plugin_id)
        fake_manifest = self._fake_manifest(plugin_id, "1.0.0")
        monkeypatch.setattr(plugins_mod, "discover_plugins", lambda: [fake_manifest])

        load_attempted = {}
        monkeypatch.setattr(
            plugins_mod, "_load_plugin", lambda app_arg, manifest: load_attempted.setdefault("called", True)
        )

        try:
            plugins_mod.load_plugins(app)
            assert "called" not in load_attempted, (
                "a version that has never migrated cleanly must not be loaded — its "
                "migration failure is set as plugin_migration_failed for the Plugins page"
            )
            stored = get_global_setting(f"plugin_migration_failed:{plugin_id}")
            assert stored and "failed" in stored
        finally:
            self._cleanup(db, plugin_id)

    def test_newer_version_whose_migration_just_failed_is_skipped(self, db, monkeypatch, app):
        from jen.models.user import get_global_setting, set_global_setting
        from jen.services import plugins as plugins_mod

        plugin_id = "q26_newer_version_plugin"
        self._cleanup(db, plugin_id)
        set_global_setting(f"plugin_migrated_ok:{plugin_id}", "1.0.0")
        fake_manifest = self._fake_manifest(plugin_id, "2.0.0")
        monkeypatch.setattr(plugins_mod, "discover_plugins", lambda: [fake_manifest])

        load_attempted = {}
        monkeypatch.setattr(
            plugins_mod, "_load_plugin", lambda app_arg, manifest: load_attempted.setdefault("called", True)
        )

        try:
            plugins_mod.load_plugins(app)
            assert "called" not in load_attempted
            assert get_global_setting(f"plugin_migration_failed:{plugin_id}")
        finally:
            self._cleanup(db, plugin_id)

    def test_this_exact_version_already_migrated_cleanly_loads_anyway(self, db, monkeypatch, app):
        from jen.models.user import set_global_setting
        from jen.services import plugins as plugins_mod

        plugin_id = "q26_already_clean_plugin"
        self._cleanup(db, plugin_id)
        set_global_setting(f"plugin_migrated_ok:{plugin_id}", "1.0.0")
        fake_manifest = self._fake_manifest(plugin_id, "1.0.0")
        monkeypatch.setattr(plugins_mod, "discover_plugins", lambda: [fake_manifest])

        load_attempted = {}

        def fake_load_plugin(app_arg, manifest):
            load_attempted["called"] = True
            load_attempted["plugin_id"] = manifest["id"]

        monkeypatch.setattr(plugins_mod, "_load_plugin", fake_load_plugin)

        try:
            plugins_mod.load_plugins(app)
            assert load_attempted.get("called") is True, (
                "this exact version already migrated cleanly once before — the v4.4.19 "
                "case — so today's failure is an unrelated/format quirk, not a broken "
                "migration for the code that's about to run"
            )
            assert load_attempted.get("plugin_id") == plugin_id
        finally:
            self._cleanup(db, plugin_id)

    def test_clean_migration_stamps_migrated_ok_and_clears_failed_key(self, db, monkeypatch, app):
        from jen.models.user import get_global_setting, set_global_setting
        from jen.services import plugins as plugins_mod

        plugin_id = "q26_clean_migration_plugin"
        self._cleanup(db, plugin_id)
        set_global_setting(f"plugin_migration_failed:{plugin_id}", "a stale earlier failure")
        fake_manifest = {
            "id": plugin_id,
            "path": f"/tmp/nonexistent_{plugin_id}",
            "enabled": True,
            "version_ok": True,
            "version": "1.0.0",
        }
        monkeypatch.setattr(plugins_mod, "discover_plugins", lambda: [fake_manifest])
        monkeypatch.setattr(plugins_mod, "_load_plugin", lambda app_arg, manifest: True)

        try:
            plugins_mod.load_plugins(app)
            assert get_global_setting(f"plugin_migrated_ok:{plugin_id}") == "1.0.0"
            assert get_global_setting(f"plugin_migration_failed:{plugin_id}") == ""
        finally:
            self._cleanup(db, plugin_id)


class TestAlreadyInEffectDdlIsRecordedAsApplied:
    """v5.28.2 — plugin migrations are plain SQL, and the only idempotent
    ALTER was MariaDB's `IF [NOT] EXISTS` form, which MySQL 8 lacks: the
    shipped ipam plugin was MariaDB-only for a year without anyone
    noticing. The runner now treats "duplicate column" (1060),
    "duplicate key name" (1061) and "can't DROP; doesn't exist" (1091)
    as the schema already being where the migration puts it, records
    the migration, and continues — on both databases CI runs."""

    def test_duplicate_column_key_and_missing_index_are_recorded(self, db):
        run_plugin_migrations(
            {
                "id": "tol_base",
                "db_migrations": [
                    {
                        "version": 1,
                        "description": "t",
                        "sql": "CREATE TABLE IF NOT EXISTS tol_t (id INT PRIMARY KEY, a INT)",
                    },
                    {"version": 2, "description": "idx", "sql": "ALTER TABLE tol_t ADD INDEX idx_a (a)"},
                ],
            }
        )
        manifest = {
            "id": "tol_again",
            "db_migrations": [
                {"version": 1, "description": "dup column", "sql": "ALTER TABLE tol_t ADD COLUMN a INT"},
                {"version": 2, "description": "dup key", "sql": "ALTER TABLE tol_t ADD INDEX idx_a (a)"},
                {"version": 3, "description": "drop missing", "sql": "ALTER TABLE tol_t DROP INDEX never_existed"},
                {"version": 4, "description": "real change after", "sql": "ALTER TABLE tol_t ADD COLUMN b INT"},
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True, msg
        assert count == 4
        assert _plugin_applied_versions("tol_again") == {1, 2, 3, 4}
        with db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM tol_t LIKE 'b'")
            assert cur.fetchone() is not None, "the migration after the tolerated ones must still run"

    def test_a_genuinely_wrong_statement_still_fails(self, db):
        manifest = {
            "id": "tol_wrong",
            "db_migrations": [
                {"version": 1, "description": "no such table", "sql": "ALTER TABLE tol_no_such_table ADD COLUMN a INT"},
            ],
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is False
        assert count == 0
        assert _plugin_applied_versions("tol_wrong") == set()

    def test_shipped_ipam_manifest_is_portable_and_explicitly_versioned(self):
        """The ALTERs must be plain (no MariaDB-only IF [NOT] EXISTS) and
        every entry an explicit {version, sql} — the positional flat-list
        form is what let a re-ordered edit silently renumber history."""
        with open("plugins/ipam/manifest.json") as f:
            migrations = json.load(f)["db_migrations"]
        assert all(isinstance(m, dict) and {"version", "sql"} <= m.keys() for m in migrations)
        assert [m["version"] for m in migrations] == list(range(1, len(migrations) + 1))
        for m in migrations:
            assert "IF EXISTS" not in m["sql"].upper().replace("IF NOT EXISTS", ""), m["sql"]
            if not m["sql"].upper().startswith("CREATE TABLE"):
                assert "IF NOT EXISTS" not in m["sql"].upper(), m["sql"]
