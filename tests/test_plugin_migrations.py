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

import pymysql
import pytest

from jen.services.plugins import run_plugin_migrations, _plugin_applied_versions


def _t1_manifest(plugin_id="test_plugin_a"):
    return {
        "id": plugin_id,
        "db_migrations": [
            {"version": 1, "description": "first table",
             "sql": f"CREATE TABLE IF NOT EXISTS {plugin_id}_t1 (id INT PRIMARY KEY)"},
            {"version": 2, "description": "second table",
             "sql": f"CREATE TABLE IF NOT EXISTS {plugin_id}_t2 (id INT PRIMARY KEY)"},
        ]
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
        manifest["db_migrations"].append({
            "version": 3, "description": "third table",
            "sql": "CREATE TABLE IF NOT EXISTS test_plugin_e_t3 (id INT PRIMARY KEY)"
        })
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
                {"version": 1, "description": "good table",
                 "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_x_t1 (id INT PRIMARY KEY)"},
                {"version": 2, "description": "broken",
                 "sql": "CREATE TABLE THIS IS NOT VALID SQL AT ALL"},
                {"version": 3, "description": "never reached",
                 "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_x_t3 (id INT PRIMARY KEY)"},
            ]
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is False
        assert count == 1, "only migration 1 (before the broken one) should have applied"
        assert "migration 2" in msg, "error message must identify which migration failed"

    def test_migration_after_the_broken_one_never_runs(self, db):
        manifest = {
            "id": "failing_plugin_y",
            "db_migrations": [
                {"version": 1, "description": "broken",
                 "sql": "NOT VALID SQL"},
                {"version": 2, "description": "should never run",
                 "sql": "CREATE TABLE IF NOT EXISTS failing_plugin_y_t2 (id INT PRIMARY KEY)"},
            ]
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
            ]
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
            "db_migrations": [12345]  # neither a string nor a valid dict
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
            ]
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
            ]
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
        assert count == 2
        with db.cursor() as cur:
            for tbl in ("ipam_static_entries", "ipam_assignment_history"):
                cur.execute(f"SHOW TABLES LIKE '{tbl}'")
                assert cur.fetchone() is not None, f"{tbl} was not created"

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
            ]
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
            ]
        }
        run_plugin_migrations(manifest)
        assert _plugin_applied_versions("old_format_versions_plugin") == {1, 2, 3}

    def test_old_format_is_idempotent_on_second_run(self, db):
        manifest = {
            "id": "old_format_idempotent_plugin",
            "db_migrations": [
                "CREATE TABLE IF NOT EXISTS ofi_t1 (id INT PRIMARY KEY)",
            ]
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
                {"version": 2, "description": "new-format entry",
                 "sql": "CREATE TABLE IF NOT EXISTS mixed_t2 (id INT PRIMARY KEY)"},
            ]
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
            ]
        }
        ok, msg, count = run_plugin_migrations(manifest)
        assert ok is True, f"real ipam manifest should succeed: {msg}"
        assert count == 3
        with db.cursor() as cur:
            for tbl in ("ipamrwd_static_entries", "ipamrwd_assignment_history", "ipamrwd_subnets"):
                cur.execute(f"SHOW TABLES LIKE '{tbl}'")
                assert cur.fetchone() is not None, f"{tbl} was not created"


class TestLoadPluginsDoesNotSkipOnMigrationFailure:
    """The second half of the v4.4.19 fix: even a genuine migration
    failure (not just an old-format manifest) must not prevent
    load_plugins() from still attempting to load the plugin's blueprint
    and nav entry."""

    def test_migration_failure_does_not_prevent_plugin_load(self, db, monkeypatch, app):
        from jen import extensions
        from jen.services import plugins as plugins_mod

        fake_manifest = {
            "id": "broken_migration_plugin",
            "path": "/tmp/nonexistent_broken_migration_plugin",
            "enabled": True,
            "version_ok": True,
            "db_migrations": [
                {"version": 1, "description": "broken", "sql": "NOT VALID SQL AT ALL"},
            ],
        }
        monkeypatch.setattr(plugins_mod, "discover_plugins", lambda: [fake_manifest])

        load_attempted = {}
        def fake_load_plugin(app_arg, manifest):
            load_attempted["called"] = True
            load_attempted["plugin_id"] = manifest["id"]
            return True
        monkeypatch.setattr(plugins_mod, "_load_plugin", fake_load_plugin)

        plugins_mod.load_plugins(app)

        assert load_attempted.get("called") is True, (
            "load_plugins() must still attempt to load a plugin even when "
            "its migrations fail — this is exactly the v4.4.19 regression: "
            "a migration problem used to skip the whole plugin, hiding an "
            "otherwise-working plugin's UI over an unrelated schema issue."
        )
        assert load_attempted.get("plugin_id") == "broken_migration_plugin"
