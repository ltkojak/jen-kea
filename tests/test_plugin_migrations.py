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
        """v4.4.18 changed the manifest format from a flat list of SQL
        strings to versioned {"version", "description", "sql"} objects
        — a manifest still in the old format must fail clearly rather
        than crash with a confusing KeyError."""
        manifest = {
            "id": "old_format_plugin",
            "db_migrations": ["CREATE TABLE IF NOT EXISTS old_format_plugin_t1 (id INT)"]
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
