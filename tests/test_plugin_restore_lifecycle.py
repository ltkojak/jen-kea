"""
tests/test_plugin_restore_lifecycle.py
─────────────────────────────────────────
v5.66.0-beta.5 (Q107) — the actual property this Q exists for: representative rows in every
one of the 20 tables the seven bundled plugins own, exported, the schema wiped (tables dropped,
migration rows cleared — the state a fresh restore target is in), restored, and every row is
back with the invariant holding (a recorded migration always implies its table exists). Also
the format-1 path (an export from before this Q, no plugin_tables meta at all), the code-absent
path (a plugin named in the export whose code isn't on this machine), and the self-heal path
(jen.services.plugins.load_plugins()'s own repair for an install already left broken by an
older restore).
"""

import gzip
import json
import os
import pathlib

import pytest

from jen import extensions
from jen.services import dbexport
from jen.services import plugins as plugins_svc

BUNDLED_IDS = ("dns-sync", "ipam", "network-discovery", "presence", "switchport", "watchdog", "wol")


@pytest.fixture(autouse=True)
def _real_bundled_plugins(monkeypatch):
    """import_jen() and self_heal_missing_tables() both go through plugins._plugin_dir(), which
    reads extensions.PLUGIN_DIR_BUNDLED — conftest.py deliberately points that at a nonexistent
    path everywhere else, for test isolation from the real bundled plugin tree. Repoint it back
    for this file, the same way tests/test_plugin_loading.py already does."""
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))


PLUGIN_TABLES_BY_PLUGIN = {
    "dns-sync": ["ds_targets", "ds_records"],
    "ipam": ["ipam_subnets", "ipam_static_entries", "ipam_assignment_history", "ipam_conflict_state"],
    "network-discovery": ["nd_scan_jobs", "nd_scan_results", "nd_known_hosts", "nd_settings"],
    "presence": ["pr_tracked", "pr_state", "pr_sinks"],
    "switchport": ["sp_switches", "sp_ports", "sp_mac_ports"],
    "watchdog": ["wd_targets", "wd_state", "wd_checks"],
    "wol": ["wol_hosts"],
}
ALL_20 = [t for tables in PLUGIN_TABLES_BY_PLUGIN.values() for t in tables]


def _bundled_manifest(plugin_id):
    path = pathlib.Path(__file__).resolve().parent.parent / "plugins" / plugin_id / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _install_and_migrate(db, plugin_id):
    manifest = _bundled_manifest(plugin_id)
    with db.cursor() as cur:
        cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (manifest["id"],))
        cur.execute("DELETE FROM plugins WHERE id=%s", (manifest["id"],))
    db.commit()
    ok, msg, _count = plugins_svc.run_plugin_migrations(manifest)
    assert ok, f"{plugin_id}: {msg}"
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO plugins (id, name, version, description, author, requires_jen, enabled) "
            "VALUES (%s, %s, %s, '', '', '0.0.0', 1)",
            (manifest["id"], manifest.get("name", manifest["id"]), manifest.get("version", "1.0.0")),
        )
    db.commit()
    return manifest


def _install_and_migrate_all(db):
    for pid in BUNDLED_IDS:
        _install_and_migrate(db, pid)


def _seed_all_20_tables(db):
    """One representative, fixed-id row per plugin table — id 9001 (or the natural PK) so a
    restored row can be found again by its exact identity, not just a row count."""
    with db.cursor() as cur:
        for t in ALL_20:
            cur.execute(f"DELETE FROM `{t}`")
        cur.execute(
            "INSERT INTO ds_targets (id, name, kind, url, domain, sources, enabled) VALUES "
            "(9001, 'zz-target', 'pihole', 'http://pihole.local', 'lan', 'leases,reservations', 1)"
        )
        cur.execute(
            "INSERT INTO ds_records (target_id, name, ip, source) VALUES (9001, 'zz-host', '10.0.0.1', 'lease')"
        )

        cur.execute("INSERT INTO ipam_subnets (id, name, cidr) VALUES (9001, 'zz-subnet', '10.0.0.0/24')")
        cur.execute(
            "INSERT INTO ipam_static_entries (id, ip, subnet_id, label) VALUES (9001, '10.0.0.5', 1, 'zz-entry')"
        )
        cur.execute(
            "INSERT INTO ipam_assignment_history (id, ip, subnet_id, action) VALUES (9001, '10.0.0.5', 1, 'assign')"
        )
        cur.execute(
            "INSERT INTO ipam_conflict_state (id, ip, subnet_kind, subnet_id) VALUES (9001, '10.0.0.9', 'kea', 1)"
        )

        cur.execute("INSERT INTO nd_scan_jobs (id, subnet_id, status) VALUES (9001, 1, 'done')")
        cur.execute(
            "INSERT INTO nd_scan_results (id, job_id, ip, mac) VALUES (9001, 9001, '10.0.0.7', 'de:ad:be:ef:00:01')"
        )
        cur.execute("INSERT INTO nd_known_hosts (id, mac, ip) VALUES (9001, 'de:ad:be:ef:00:02', '10.0.0.8')")
        cur.execute("INSERT INTO nd_settings (subnet_id, every_hours) VALUES (1, 6)")

        cur.execute("INSERT INTO pr_tracked (mac, label) VALUES ('de:ad:be:ef:00:03', 'zz-tracked')")
        cur.execute("INSERT INTO pr_state (mac, online) VALUES ('de:ad:be:ef:00:03', 1)")
        cur.execute(
            "INSERT INTO pr_sinks (id, name, kind, url) VALUES (9001, 'zz-sink', 'http', 'http://example/hook')"
        )

        cur.execute("INSERT INTO sp_switches (id, name, host) VALUES (9001, 'zz-switch', '10.0.0.10')")
        cur.execute("INSERT INTO sp_ports (switch_id, ifindex, ifname) VALUES (9001, 1, 'Gi0/1')")
        cur.execute("INSERT INTO sp_mac_ports (mac, switch_id, ifindex) VALUES ('de:ad:be:ef:00:04', 9001, 1)")

        cur.execute("INSERT INTO wd_targets (id, ip, label) VALUES (9001, '10.0.0.20', 'zz-target')")
        cur.execute("INSERT INTO wd_state (target_id, state) VALUES (9001, 'up')")
        cur.execute("INSERT INTO wd_checks (id, target_id, ok) VALUES (9001, 9001, 1)")

        cur.execute("INSERT INTO wol_hosts (id, mac, label) VALUES (9001, 'de:ad:be:ef:00:05', 'zz-wol')")
    db.commit()


def _wipe_plugin_schema(db, plugin_ids, tables):
    """The state a restore TARGET is actually in: the plugin's tables don't exist at all (not
    just empty), and its migration history is unknown — matching the invariant this Q protects:
    a recorded migration implies its tables exist, so before restore neither is true."""
    with db.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for t in tables:
            cur.execute(f"DROP TABLE IF EXISTS `{t}`")
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
        for pid in plugin_ids:
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (pid,))
    db.commit()


def _table_present(db, table):
    # Every read in this file goes through the `db` fixture's one connection, while the actual
    # writes under test (import_jen(), write_jen_export(), run_plugin_migrations()) each use
    # their OWN, separate connection and commit independently. Under MySQL 8, a read on an
    # already-open REPEATABLE READ transaction on `db` can still see the snapshot from before
    # one of those other connections' commit (see tests/test_plugin_table_ownership.py's
    # _tables_in_schema() for the same fix, caught first) - commit here so every check starts
    # a fresh snapshot.
    db.commit()
    with db.cursor() as cur:
        cur.execute("SHOW TABLES LIKE %s", (table,))
        return cur.fetchone() is not None


class TestFullPluginRestoreLifecycle:
    def test_export_wipe_restore_every_table_comes_back(self, db, tmp_path):
        _install_and_migrate_all(db)
        _seed_all_20_tables(db)

        path = tmp_path / "full-export.json.gz"
        meta = dbexport.write_jen_export(str(path))
        assert meta["format"] == 2
        assert set(meta["plugin_tables"].keys()) == set(BUNDLED_IDS)

        _wipe_plugin_schema(db, BUNDLED_IDS, ALL_20)
        for t in ALL_20:
            assert not _table_present(db, t), f"{t} should not exist after the wipe"

        results = dbexport.import_jen(path.read_bytes())
        warnings = [r for r in results if r.startswith("⚠️")]
        assert not warnings, warnings

        db.commit()  # a fresh snapshot for the reads below - import_jen() wrote via its own connections
        with db.cursor() as cur:
            for t in ALL_20:
                cur.execute(f"SELECT COUNT(*) AS cnt FROM `{t}`")
                assert cur.fetchone()["cnt"] >= 1, f"{t} has no rows after restore"
            cur.execute("SELECT name FROM ds_targets WHERE id=9001")
            assert cur.fetchone()["name"] == "zz-target"
            cur.execute("SELECT label FROM wol_hosts WHERE id=9001")
            assert cur.fetchone()["label"] == "zz-wol"

        assert dbexport._plugin_invariant_violations(db) == []

    def test_tables_to_restore_scoped_to_one_plugin_leaves_others_alone(self, db, tmp_path):
        _install_and_migrate_all(db)
        _seed_all_20_tables(db)
        path = tmp_path / "scoped-export.json.gz"
        dbexport.write_jen_export(str(path))
        _wipe_plugin_schema(db, BUNDLED_IDS, ALL_20)

        dbexport.import_jen(path.read_bytes(), tables_to_restore=["wol_hosts"])

        assert _table_present(db, "wol_hosts")
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM wol_hosts")
            assert cur.fetchone()["cnt"] == 1
        # a table never asked for stays absent - the scoping genuinely limited the restore
        assert not _table_present(db, "ds_targets")


class TestFormatOnePath:
    def test_no_plugin_tables_meta_recreates_every_installed_plugins_schema(self, db):
        """A format-1 export (everything before this Q) never carried plugin row data — but
        restoring one must still leave every currently-installed plugin's schema intact, not
        broken, which is exactly what clearing and re-running every installed plugin's
        migrations (with no per-plugin scope to go by) achieves."""
        _install_and_migrate_all(db)
        _wipe_plugin_schema(db, BUNDLED_IDS, ALL_20)
        for t in ALL_20:
            assert not _table_present(db, t)

        payload = {
            "data": {"settings": []},
            "_meta": {"database": "jen", "jen_export_version": 1, "row_counts": {"settings": 0}},
        }
        content = gzip.compress(json.dumps(payload).encode("utf-8"))

        dbexport.import_jen(content)

        for t in ALL_20:
            assert _table_present(db, t), f"{t} should have been recreated by the format-1 fallback"
        assert dbexport._plugin_invariant_violations(db) == []


class TestCodeAbsentPluginPath:
    def test_a_plugin_named_in_the_export_with_no_code_here_is_skipped_and_named(self, db, monkeypatch, tmp_path):
        _install_and_migrate_all(db)
        _seed_all_20_tables(db)
        path = tmp_path / "export.json.gz"
        dbexport.write_jen_export(str(path))
        _wipe_plugin_schema(db, BUNDLED_IDS, ALL_20)

        real = plugins_svc._manifest_for_owned_tables

        def fake(pid):
            return None if pid == "wol" else real(pid)

        monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", fake)

        results = dbexport.import_jen(path.read_bytes())
        named = [r for r in results if "wol" in r and "not installed here" in r]
        assert named, results

        assert not _table_present(db, "wol_hosts")  # never recreated - its code isn't here
        with db.cursor() as cur:  # every OTHER plugin still restored fine
            cur.execute("SELECT COUNT(*) AS cnt FROM ds_targets")
            assert cur.fetchone()["cnt"] >= 1


class TestSelfHealPath:
    def test_missing_table_with_a_recorded_migration_is_recreated(self, db):
        manifest = _install_and_migrate(db, "wol")
        with db.cursor() as cur:
            cur.execute("DROP TABLE wol_hosts")
        db.commit()

        missing = plugins_svc.self_heal_missing_tables(manifest)
        assert missing == ["wol_hosts"]
        assert _table_present(db, "wol_hosts")

    def test_nothing_missing_is_a_no_op(self, db):
        manifest = _install_and_migrate(db, "wol")
        assert plugins_svc.self_heal_missing_tables(manifest) == []

    def test_a_plugin_that_never_migrated_is_not_touched(self, db):
        manifest = {
            "id": "zz-never-migrated",
            "db_migrations": [{"version": 1, "sql": "CREATE TABLE zz_never_migrated (id INT)"}],
        }
        with db.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS zz_never_migrated")
        db.commit()
        assert plugins_svc.self_heal_missing_tables(manifest) == []
        assert not _table_present(db, "zz_never_migrated")

    def test_heal_emits_an_event_and_an_audit_row(self, db):
        manifest = _install_and_migrate(db, "wol")
        with db.cursor() as cur:
            cur.execute("DROP TABLE wol_hosts")
            cur.execute("DELETE FROM events WHERE kind='plugin.schema_repaired'")
            cur.execute("DELETE FROM audit_log WHERE action='PLUGIN_SCHEMA_REPAIRED'")
        db.commit()

        plugins_svc.self_heal_missing_tables(manifest)

        db.commit()  # a fresh snapshot - self_heal_missing_tables() wrote via its own connections
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM events WHERE kind='plugin.schema_repaired'")
            assert cur.fetchone()["cnt"] == 1
            cur.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action='PLUGIN_SCHEMA_REPAIRED'")
            assert cur.fetchone()["cnt"] == 1
