"""
tests/test_plugin_retained_data.py
──────────────────────────────────
v5.67.0-beta.14 (Q128, item c) — an uninstalled plugin's data stays in every backup. The Plugins page promised
"your database tables and data will be preserved", and they were — in the live database — until the next backup:
ownership was answered only by parsing the migration DDL of plugin CODE on disk, so removing the code removed the
tables from the one table set every backup, bundle, snapshot and migration uses. Ownership is now persisted
(`plugin_tables`, migration 29) by the migration runner and flipped to retained on uninstall.

Against the real MariaDB, with a throwaway registry-style plugin (a directory with a manifest, like an installed
one) so that "uninstall" really removes the code.
"""

import json
import shutil

import pytest

from jen import extensions
from jen.services import dbexport
from jen.services import plugins as plugins_svc

PID, TABLE = "zz-retain", "zzr_things"


def _manifest():
    return {
        "id": PID,
        "name": "ZZ Retain",
        "version": "1.0.0",
        "description": "test",
        "author": "t",
        "db_migrations": [
            {
                "version": 1,
                "description": "things",
                "sql": f"CREATE TABLE IF NOT EXISTS {TABLE} (id INT PRIMARY KEY, label VARCHAR(40) NOT NULL)",
            }
        ],
    }


@pytest.fixture
def plugin_world(db, monkeypatch, tmp_path):
    """A writable plugin directory (extensions.PLUGIN_DIR) and nothing shipped or root-owned."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    monkeypatch.setattr(extensions, "PLUGIN_DIR", str(plugin_dir))
    monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(tmp_path / "no-root-plugins"))
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "no-bundled-plugins"))
    monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path / "backups"))

    def clean():
        with db.cursor() as cur:
            cur.execute(f"DROP TABLE IF EXISTS {TABLE}")
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (PID,))
            cur.execute("DELETE FROM plugin_tables WHERE plugin_id LIKE 'zz-%' OR plugin_id LIKE '%zz'")
        db.commit()

    clean()
    yield plugin_dir
    clean()


def _install(plugin_dir):
    d = plugin_dir / PID
    d.mkdir(exist_ok=True)
    (d / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    ok, msg, _n = plugins_svc.run_plugin_migrations(_manifest())
    assert ok, msg


def _q(db, sql, args=()):
    db.commit()
    with db.cursor() as cur:
        cur.execute(sql, args)
        return list(cur.fetchall())


def _record(db):
    rows = _q(db, "SELECT * FROM plugin_tables WHERE plugin_id=%s", (PID,))
    return rows[0] if rows else None


def _backup(tmp_path, name="backup.json.gz"):
    """(the backup's bytes, the _meta written)"""
    path = tmp_path / name
    meta = dbexport.write_jen_export(str(path))
    return path.read_bytes(), meta


class TestOwnershipIsRecorded:
    def test_the_migration_runner_records_what_a_plugin_owns(self, db, plugin_world):
        assert _record(db) is None
        _install(plugin_world)
        rec = _record(db)
        assert rec["table_name"] == TABLE and rec["first_seen_version"] == "1.0.0"
        assert (rec["code_installed"], rec["retained"]) == (1, 0)

    def test_a_second_run_changes_nothing_and_keeps_the_first_seen_version(self, db, plugin_world):
        _install(plugin_world)
        newer = _manifest()
        newer["version"] = "2.0.0"
        assert plugins_svc.run_plugin_migrations(newer)[0]
        assert len(_q(db, "SELECT 1 FROM plugin_tables WHERE plugin_id=%s", (PID,))) == 1
        assert _record(db)["first_seen_version"] == "1.0.0"

    def test_a_plugin_that_owns_nothing_records_nothing(self, db, plugin_world):
        plugins_svc.record_owned_tables({"id": "zz-empty", "version": "1", "db_migrations": []})
        assert _q(db, "SELECT 1 FROM plugin_tables WHERE plugin_id='zz-empty'") == []

    def test_an_invalid_plugin_id_is_never_recorded(self, db, plugin_world):
        plugins_svc.record_owned_tables({"id": "../x", "version": "1", "db_migrations": _manifest()["db_migrations"]})
        plugins_svc.mark_plugin_uninstalled("../x")
        assert _q(db, "SELECT 1 FROM plugin_tables WHERE plugin_id LIKE '%x'") == []

    def test_plugin_tables_is_itself_in_every_backup(self):
        assert "plugin_tables" in dbexport.JEN_TABLES and "plugin_tables" in dbexport.export_tables()


class TestUninstallKeepsTheDataInEveryBackup:
    def _installed_with_data(self, db, plugin_world):
        _install(plugin_world)
        with db.cursor() as cur:
            cur.execute(f"INSERT INTO {TABLE} (id, label) VALUES (1, 'kept-1'), (2, 'kept-2')")
        db.commit()

    def test_uninstalling_removes_the_code_and_marks_the_tables_retained(self, db, plugin_world):
        self._installed_with_data(db, plugin_world)
        assert PID in [p["id"] for p in plugins_svc.discover_plugins()]

        ok, _msg = plugins_svc.uninstall_plugin(PID)

        assert ok and not (plugin_world / PID).exists()
        assert PID not in [p["id"] for p in plugins_svc.discover_plugins()]
        assert plugins_svc.all_owned_tables().get(PID) is None, "code ownership is gone, as it always was"
        rec = _record(db)
        assert (rec["code_installed"], rec["retained"]) == (0, 1)
        assert [r["label"] for r in _q(db, f"SELECT label FROM {TABLE} ORDER BY id")] == ["kept-1", "kept-2"]

    def test_the_table_set_every_backup_uses_still_has_the_retained_table(self, db, plugin_world):
        self._installed_with_data(db, plugin_world)
        plugins_svc.uninstall_plugin(PID)
        assert TABLE in dbexport.export_tables()
        assert dbexport.export_table_groups().get(PID) == [TABLE]

    def test_a_full_backup_after_the_uninstall_carries_the_rows(self, db, plugin_world, tmp_path):
        self._installed_with_data(db, plugin_world)
        plugins_svc.uninstall_plugin(PID)
        blob, meta = _backup(tmp_path)
        assert meta["plugin_tables"][PID]["tables"] == [TABLE]
        assert meta["row_counts"][TABLE] == 2
        parsed = dbexport.parse_import_file(blob)
        assert [r["label"] for r in parsed[1][TABLE]] == ["kept-1", "kept-2"] and parsed[2] is None

    def test_the_migration_asks_the_same_set(self, db, plugin_world):
        """migrate_jen builds its table list with export_tables(), so a retained table migrates too."""
        import inspect

        self._installed_with_data(db, plugin_world)
        plugins_svc.uninstall_plugin(PID)
        assert "export_tables(src)" in inspect.getsource(dbexport.migrate_jen)
        conn = dbexport._direct_jen_conn()
        try:
            assert TABLE in dbexport.export_tables(conn)
        finally:
            conn.close()

    def test_a_table_nothing_recorded_is_never_exported(self, db, plugin_world):
        with db.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS zzr_unowned (id INT PRIMARY KEY)")
        db.commit()
        try:
            assert "zzr_unowned" not in dbexport.export_tables()
        finally:
            with db.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS zzr_unowned")
            db.commit()

    def test_a_recorded_name_that_is_a_core_table_or_not_a_name_is_ignored(self, db, plugin_world):
        with db.cursor() as cur:
            cur.executemany(
                "INSERT INTO plugin_tables (plugin_id, table_name) VALUES (%s, %s)",
                [("zz-evil", "users"), ("zz-evil", "bad name; DROP TABLE users"), ("../zz", "settings_x")],
            )
        db.commit()
        tables = dbexport.export_tables()
        assert tables.count("users") == 1
        assert not [t for t in tables if "DROP" in t or t == "settings_x"]

    def test_a_shipped_copy_that_takes_over_is_still_code_so_nothing_is_retained(self, db, plugin_world, monkeypatch):
        self._installed_with_data(db, plugin_world)
        shipped = plugin_world.parent / "bundled"
        (shipped / PID).mkdir(parents=True)
        (shipped / PID / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(shipped))
        plugins_svc.uninstall_plugin(PID)  # removes the writable copy; the shipped one remains
        assert (_record(db)["code_installed"], _record(db)["retained"]) == (1, 0)


class TestLifecycle:
    """install -> data -> uninstall -> full backup -> restore -> reinstall -> the data is there."""

    def _through_uninstall(self, db, plugin_world, tmp_path):
        _install(plugin_world)
        with db.cursor() as cur:
            cur.execute(f"INSERT INTO {TABLE} (id, label) VALUES (1, 'kept-1'), (2, 'kept-2')")
        db.commit()
        plugins_svc.uninstall_plugin(PID)
        return _backup(tmp_path)[0]

    def test_restoring_the_backup_on_the_same_box_loses_nothing_and_reinstalling_reconnects(
        self, db, plugin_world, tmp_path
    ):
        blob = self._through_uninstall(db, plugin_world, tmp_path)

        results = dbexport.import_jen(blob, strict=True)  # a clean, strict, full restore

        assert any(PID in r and "not installed here" in r for r in results), results
        assert [r["label"] for r in _q(db, f"SELECT label FROM {TABLE} ORDER BY id")] == ["kept-1", "kept-2"]
        assert (_record(db)["code_installed"], _record(db)["retained"]) == (0, 1), "ownership came back with the file"

        _install(plugin_world)  # reinstall
        assert [r["label"] for r in _q(db, f"SELECT label FROM {TABLE} ORDER BY id")] == ["kept-1", "kept-2"]
        assert (_record(db)["code_installed"], _record(db)["retained"]) == (1, 0)
        assert TABLE in plugins_svc.all_owned_tables()[PID]

    def test_restoring_onto_a_clean_box_keeps_the_data_in_the_file_until_the_plugin_is_back(
        self, db, plugin_world, tmp_path
    ):
        blob = self._through_uninstall(db, plugin_world, tmp_path)
        with db.cursor() as cur:  # a new box: no table, no migration rows, no ownership rows
            cur.execute(f"DROP TABLE {TABLE}")
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (PID,))
            cur.execute("DELETE FROM plugin_tables WHERE plugin_id=%s", (PID,))
        db.commit()

        results = dbexport.import_jen(blob)
        assert any(PID in r and "not installed here" in r and "still inside this export" in r for r in results)
        assert not _q(db, "SHOW TABLES LIKE %s", (TABLE,)), "no code, so no table — never DDL from the file"
        assert (_record(db)["code_installed"], _record(db)["retained"]) == (0, 1)

        _install(plugin_world)  # reinstall: the schema is back, empty
        assert _q(db, f"SELECT COUNT(*) AS n FROM {TABLE}")[0]["n"] == 0
        dbexport.import_jen(blob, strict=True)  # restore again with the plugin present
        assert [r["label"] for r in _q(db, f"SELECT label FROM {TABLE} ORDER BY id")] == ["kept-1", "kept-2"]

    def test_the_import_pages_pre_import_snapshot_carries_the_retained_table(self, db, plugin_world, tmp_path):
        """a failed replace import rolls back from a snapshot built from the same table set."""
        self._through_uninstall(db, plugin_world, tmp_path)
        snap = dbexport.take_pre_import_snapshot()
        try:
            assert snap["row_counts"][TABLE] == 2
        finally:
            shutil.rmtree(snap["dir"], ignore_errors=True)


class TestThePluginsPage:
    def test_the_page_says_where_the_data_goes(self, logged_in_client):
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        page = r.data.decode()
        assert "kept in the database and in every backup, and shown again when the plugin is reinstalled" in page
        assert "will be preserved" not in page

    def test_the_uninstall_confirmation_says_it_too(self):
        import pathlib

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "plugins.html").read_text(
            encoding="utf-8"
        )
        assert (
            html.count("kept in the database and in every backup, and shown again when the plugin is reinstalled") == 2
        )
