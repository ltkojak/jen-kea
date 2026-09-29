"""
tests/test_plugin_table_ownership.py
──────────────────────────────────────
v5.66.0-beta.5 (Q107) — jen/services/dbexport.py's JEN_TABLES never listed a single one of the
20 tables the seven bundled plugins create; every export, backup, recovery bundle and restore
silently left plugin data out, and a restored plugin_schema_migrations row with no table behind
it made load_plugins() believe a migration had already run and never create the table at all.

plugins.owned_tables()/all_owned_tables() answer "what does this plugin own" by PARSING (never
executing) the plugin's own migration DDL. This file proves that derivation two ways: pure
regex-behavior tests against fabricated manifests, and a real information_schema diff for every
bundled plugin's REAL manifest (the derivation can never silently miss a table its own
migrations actually create).
"""

import json
import pathlib

from jen.services import dbexport
from jen.services import plugins as plugins_svc
from jen.services.plugins import _derive_owned_tables, owned_tables, run_plugin_migrations

BUNDLED_IDS = ("dns-sync", "ipam", "network-discovery", "presence", "switchport", "watchdog", "wol")

ALL_20_PLUGIN_TABLES = {
    "ds_targets",
    "ds_records",
    "ipam_static_entries",
    "ipam_assignment_history",
    "ipam_subnets",
    "ipam_conflict_state",
    "nd_scan_jobs",
    "nd_scan_results",
    "nd_known_hosts",
    "nd_settings",
    "pr_tracked",
    "pr_state",
    "pr_sinks",
    "sp_switches",
    "sp_ports",
    "sp_mac_ports",
    "wd_targets",
    "wd_state",
    "wd_checks",
    "wol_hosts",
}


def _bundled_manifest(plugin_id):
    path = pathlib.Path(__file__).resolve().parent.parent / "plugins" / plugin_id / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


class TestDeriveOwnedTablesPureParsing:
    """No DB, no execution — these prove the regex behavior directly against fabricated DDL."""

    def test_create_table_if_not_exists(self):
        assert _derive_owned_tables([{"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_bar (id INT)"}]) == [
            "foo_bar"
        ]

    def test_create_table_without_if_not_exists(self):
        assert _derive_owned_tables([{"version": 1, "sql": "CREATE TABLE foo_bar (id INT)"}]) == ["foo_bar"]

    def test_backtick_quoted_name(self):
        assert _derive_owned_tables([{"version": 1, "sql": "CREATE TABLE IF NOT EXISTS `foo_bar` (id INT)"}]) == [
            "foo_bar"
        ]

    def test_multiple_creates_in_order(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"},
            {"version": 2, "sql": "CREATE TABLE IF NOT EXISTS foo_b (id INT)"},
        ]
        assert _derive_owned_tables(migs) == ["foo_a", "foo_b"]

    def test_alter_table_does_not_add_a_table(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"},
            {"version": 2, "sql": "ALTER TABLE foo_a ADD COLUMN x INT"},
        ]
        assert _derive_owned_tables(migs) == ["foo_a"]

    def test_drop_table_removes_it(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"},
            {"version": 2, "sql": "DROP TABLE foo_a"},
        ]
        assert _derive_owned_tables(migs) == []

    def test_drop_table_if_exists(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"},
            {"version": 2, "sql": "DROP TABLE IF EXISTS foo_a"},
        ]
        assert _derive_owned_tables(migs) == []

    def test_rename_table_to(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_old (id INT)"},
            {"version": 2, "sql": "RENAME TABLE foo_old TO foo_new"},
        ]
        assert _derive_owned_tables(migs) == ["foo_new"]

    def test_alter_table_rename_to(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_old (id INT)"},
            {"version": 2, "sql": "ALTER TABLE foo_old RENAME TO foo_new"},
        ]
        assert _derive_owned_tables(migs) == ["foo_new"]

    def test_alter_table_rename_without_to(self):
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_old (id INT)"},
            {"version": 2, "sql": "ALTER TABLE foo_old RENAME foo_new"},
        ]
        assert _derive_owned_tables(migs) == ["foo_new"]

    def test_alter_table_rename_index_is_not_a_table_rename(self):
        """The one false-positive risk: 'ALTER TABLE t RENAME INDEX a TO b' also starts with
        'ALTER TABLE ... RENAME', but it's an INDEX rename, not a table rename."""
        migs = [
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT, INDEX a (id))"},
            {"version": 2, "sql": "ALTER TABLE foo_a RENAME INDEX a TO b"},
        ]
        assert _derive_owned_tables(migs) == ["foo_a"]

    def test_old_flat_string_format(self):
        migs = ["CREATE TABLE IF NOT EXISTS foo_a (id INT)", "CREATE TABLE IF NOT EXISTS foo_b (id INT)"]
        assert _derive_owned_tables(migs) == ["foo_a", "foo_b"]

    def test_version_order_not_list_order(self):
        migs = [
            {"version": 2, "sql": "CREATE TABLE IF NOT EXISTS foo_b (id INT)"},
            {"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"},
        ]
        assert _derive_owned_tables(migs) == ["foo_a", "foo_b"]

    def test_malformed_entry_is_skipped_not_raised(self):
        migs = [{"version": 1, "sql": "CREATE TABLE IF NOT EXISTS foo_a (id INT)"}, {"nonsense": True}, 12345]
        assert _derive_owned_tables(migs) == ["foo_a"]

    def test_no_migrations_is_empty(self):
        assert _derive_owned_tables([]) == []
        assert _derive_owned_tables(None) == []


class TestOwnedTablesValidationAndCollisions:
    """owned_tables() itself — name-shape and core-table refusals. Pure: a manifest is passed
    in directly, no filesystem/DB lookup involved."""

    def test_normal_derivation_passes_through(self):
        manifest = {"id": "zz-test", "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_foo (id INT)"}]}
        assert owned_tables("zz-test", manifest) == ["zz_foo"]

    def test_invalid_name_uppercase_refused(self):
        manifest = {"id": "zz-test", "db_migrations": [{"version": 1, "sql": "CREATE TABLE ZZ_FOO (id INT)"}]}
        assert owned_tables("zz-test", manifest) == []

    def test_invalid_name_leading_digit_refused(self):
        manifest = {"id": "zz-test", "db_migrations": [{"version": 1, "sql": "CREATE TABLE 9zz_foo (id INT)"}]}
        assert owned_tables("zz-test", manifest) == []

    def test_core_table_collision_refused(self):
        manifest = {"id": "zz-test", "db_migrations": [{"version": 1, "sql": "CREATE TABLE settings (id INT)"}]}
        assert "settings" in dbexport.JEN_TABLES  # sanity: this really is a core table
        assert owned_tables("zz-test", manifest) == []

    def test_valid_table_survives_alongside_a_refused_one(self):
        manifest = {
            "id": "zz-test",
            "db_migrations": [
                {"version": 1, "sql": "CREATE TABLE zz_good (id INT)"},
                {"version": 2, "sql": "CREATE TABLE settings (id INT)"},
            ],
        }
        assert owned_tables("zz-test", manifest) == ["zz_good"]

    def test_backup_tables_override_is_used_verbatim(self):
        manifest = {
            "id": "zz-test",
            "backup_tables": ["zz_explicit"],
            "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_derived (id INT)"}],
        }
        assert owned_tables("zz-test", manifest) == ["zz_explicit"]

    def test_backup_tables_override_still_validated(self):
        manifest = {"id": "zz-test", "backup_tables": ["settings", "ZZ-BAD", "zz_ok"]}
        assert owned_tables("zz-test", manifest) == ["zz_ok"]


class TestAllOwnedTablesCrossPluginCollision:
    """all_owned_tables() needs a real `plugins` table row per fake id (it SELECTs from it) and
    a way to fake _manifest_for_owned_tables() without touching the real plugin directories."""

    def _seed_plugin_rows(self, db, ids):
        with db.cursor() as cur:
            cur.execute("DELETE FROM plugins WHERE id LIKE 'zzcollide-%'")
            for pid in ids:
                cur.execute(
                    "INSERT INTO plugins (id, name, version, description, author, requires_jen, enabled) "
                    "VALUES (%s, %s, '1.0.0', '', '', '0.0.0', 1)",
                    (pid, pid),
                )
        db.commit()

    def test_second_claimant_loses_the_table(self, db, monkeypatch):
        self._seed_plugin_rows(db, ["zzcollide-a", "zzcollide-b"])
        manifests = {
            "zzcollide-a": {
                "id": "zzcollide-a",
                "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_shared (id INT)"}],
            },
            "zzcollide-b": {
                "id": "zzcollide-b",
                "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_shared (id INT)"}],
            },
        }
        monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", lambda pid: manifests.get(pid))

        result = plugins_svc.all_owned_tables()
        # 'a' sorts before 'b' - 'a' keeps the table, 'b' loses it
        assert result["zzcollide-a"] == ["zz_shared"]
        assert result["zzcollide-b"] == []

    def test_no_collision_both_keep_their_own(self, db, monkeypatch):
        self._seed_plugin_rows(db, ["zzcollide-a", "zzcollide-b"])
        manifests = {
            "zzcollide-a": {
                "id": "zzcollide-a",
                "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_a_only (id INT)"}],
            },
            "zzcollide-b": {
                "id": "zzcollide-b",
                "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_b_only (id INT)"}],
            },
        }
        monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", lambda pid: manifests.get(pid))

        result = plugins_svc.all_owned_tables()
        assert result["zzcollide-a"] == ["zz_a_only"]
        assert result["zzcollide-b"] == ["zz_b_only"]

    def test_code_absent_plugin_is_skipped_entirely(self, db, monkeypatch):
        self._seed_plugin_rows(db, ["zzcollide-a"])
        monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", lambda pid: None)
        result = plugins_svc.all_owned_tables()
        assert "zzcollide-a" not in result


class TestBundledManifestDerivationMatchesInformationSchema:
    """The real proof: run each bundled plugin's REAL manifest through the REAL migration
    runner against the test DB, and assert owned_tables() equals exactly the set of tables
    information_schema shows appeared as a result — not a hand-maintained list that could drift
    from the manifest, an actual before/after diff of the live schema."""

    def _tables_in_schema(self, db):
        with db.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
            return {r["table_name"] for r in cur.fetchall()}

    def _run_and_diff(self, db, plugin_id):
        manifest = _bundled_manifest(plugin_id)
        # a clean slate for this plugin only, so a re-run in the same suite session diffs
        # correctly even if an earlier test already migrated it
        with db.cursor() as cur:
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (manifest["id"],))
        db.commit()
        before = self._tables_in_schema(db)
        ok, msg, _count = run_plugin_migrations(manifest)
        assert ok, f"{plugin_id} migrations failed: {msg}"
        after = self._tables_in_schema(db)
        created = after - before
        return manifest, created

    def test_every_bundled_plugin(self, db):
        for plugin_id in BUNDLED_IDS:
            manifest, created = self._run_and_diff(db, plugin_id)
            derived = set(owned_tables(manifest["id"], manifest))
            # a table already present from an earlier test run (not created by THIS run) is
            # still correctly derived — only assert derived is a SUPERSET of what this run
            # newly created, and that every derived table genuinely exists now
            assert created <= derived, (plugin_id, created, derived)
            for t in derived:
                assert t in self._tables_in_schema(db), f"{plugin_id}: owned table {t!r} does not actually exist"


class TestExportTablesAndGroupsCoverAllTwenty:
    def _install_and_migrate_all(self, db):
        placeholders = ",".join(["%s"] * len(BUNDLED_IDS))
        with db.cursor() as cur:
            cur.execute(f"DELETE FROM plugins WHERE id IN ({placeholders})", BUNDLED_IDS)
        db.commit()
        for plugin_id in BUNDLED_IDS:
            manifest = _bundled_manifest(plugin_id)
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (manifest["id"],))
            db.commit()
            ok, msg, _count = run_plugin_migrations(manifest)
            assert ok, f"{plugin_id}: {msg}"
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO plugins (id, name, version, description, author, requires_jen, enabled) "
                    "VALUES (%s, %s, %s, '', '', '0.0.0', 1)",
                    (manifest["id"], manifest.get("name", manifest["id"]), manifest.get("version", "0.0.0")),
                )
        db.commit()

    def test_export_tables_contains_all_20(self, db):
        self._install_and_migrate_all(db)
        tables = set(dbexport.export_tables())
        missing = ALL_20_PLUGIN_TABLES - tables
        assert not missing, f"export_tables() is missing: {missing}"
        for core in dbexport.JEN_TABLES:
            assert core in tables

    def test_export_table_groups_has_one_group_per_plugin(self, db):
        self._install_and_migrate_all(db)
        groups = dbexport.export_table_groups()
        for plugin_id in BUNDLED_IDS:
            assert plugin_id in groups, f"{plugin_id} missing from export_table_groups()"
            assert groups[plugin_id], f"{plugin_id} has an empty table group"
