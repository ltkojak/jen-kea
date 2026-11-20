"""
tests/test_a_lost_plugin_commit_does_not_stop_the_plugins_after_it.py
─────────────────────────────────────────────────────────────────────
Q244 (BB3 and BB4 of the pass on v7.1.0-beta.11).

`import_jen` restores the plugins one at a time on one connection, with one commit each. Q242 gave a plugin commit that raised its own line ("the database
did not confirm the commit"). Two things were left:

- BB3: a connection a commit was lost on is closed. The NEXT plugin's `begin()` raised on it, its handler's `rollback()` raised too, a raw driver error left
  `import_jen`, the line for the first plugin never reached the page and no later plugin was restored.
- BB4: when the LAST plugin's commit was lost, `import_jen` returned its lines and the route wrote `DB_IMPORT`, the audit action of an import that worked.

The connections are the real ones `dbexport` opens, against the real database. One thing is in the test's hands: at the N-th commit the server applies it
and then ends that connection (`KILL`, from a second one), so everything sent on it afterward really fails.
"""

import base64
import gzip
import json
import os
import tempfile

import pymysql
import pytest

from jen import extensions
from jen.services import dbexport
from tests import test_plugin_restore_lifecycle as L

#: the core tables' commit is the first; then one for each plugin that has rows, in sorted order
ORDER = sorted(L.BUNDLED_IDS)
COMMIT_OF = {pid: 2 + at for at, pid in enumerate(ORDER)}


class LostAt(pymysql.connections.Connection):
    seen = 0
    lose = 0

    def commit(self):
        cls = LostAt
        cls.seen += 1
        super().commit()
        if cls.seen != cls.lose:
            return
        other = pymysql.connect(host=self.host, port=self.port, user=self.user, password=self.password, autocommit=True)
        try:
            with other.cursor() as cur:
                cur.execute(f"KILL {int(self.thread_id())}")
        finally:
            other.close()
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")


@pytest.fixture
def world(db, monkeypatch, tmp_path):
    """Every bundled plugin installed with one row per table, exported, and its tables dropped: the state a restore target is in. The yield is the file."""
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
    L._install_and_migrate_all(db)
    L._seed_all_20_tables(db)
    path = tmp_path / "full.json.gz"
    dbexport.write_jen_export(str(path))
    L._wipe_plugin_schema(db, L.BUNDLED_IDS, L.ALL_20)
    real = dbexport._direct_jen_conn

    def opened():
        conn = real()
        conn.__class__ = LostAt
        return conn

    monkeypatch.setattr(dbexport, "_direct_jen_conn", opened)
    LostAt.seen = LostAt.lose = 0
    yield path.read_bytes()
    LostAt.seen = LostAt.lose = 0


def _rows(db):
    """{plugin: rows in all its tables, or "absent" when a table is not there}."""
    db.commit()
    out = {}
    with db.cursor() as cur:
        for pid, tables in L.PLUGIN_TABLES_BY_PLUGIN.items():
            total = 0
            for t in tables:
                cur.execute("SHOW TABLES LIKE %s", (t,))
                if cur.fetchone() is None:
                    total = "absent"
                    break
                cur.execute(f"SELECT COUNT(*) AS n FROM `{t}`")
                total += cur.fetchone()["n"]
            out[pid] = total
    return out


EVERY_ROW = {pid: len(tables) for pid, tables in L.PLUGIN_TABLES_BY_PLUGIN.items()}


class TestTheFunction:
    def test_the_control_world_restores_every_plugin(self, db, world):
        results = dbexport.import_jen(world, truncate=False)
        assert _rows(db) == EVERY_ROW
        assert not any(r.startswith("❌") for r in results), results
        assert LostAt.seen == 1 + len(ORDER), (
            "one commit for the core tables and one for each plugin: the count the worlds below rely on"
        )

    def test_the_plugins_after_a_lost_commit_are_restored(self, db, world):
        """v7.2.0-beta.1 raises `InterfaceError`/`OperationalError` here and restores no plugin after the first."""
        LostAt.lose = COMMIT_OF[ORDER[0]]
        results = dbexport.import_jen(world, truncate=False)
        assert f"❌ {ORDER[0]}: {dbexport.COMMIT_NOT_CONFIRMED}" in results, results
        assert _rows(db) == EVERY_ROW, "the first plugin's commit was applied, and every plugin after it was restored"
        assert [r for r in results if r.startswith("❌")] == [f"❌ {ORDER[0]}: {dbexport.COMMIT_NOT_CONFIRMED}"]

    def test_a_lost_commit_in_the_middle(self, db, world):
        LostAt.lose = COMMIT_OF[ORDER[3]]
        results = dbexport.import_jen(world, truncate=False)
        assert [r for r in results if r.startswith("❌")] == [f"❌ {ORDER[3]}: {dbexport.COMMIT_NOT_CONFIRMED}"]
        assert _rows(db) == EVERY_ROW

    def test_the_restore_tool_is_told_by_its_own_exception(self, db, world):
        """`jen/tools/restore.py` calls with `strict_plugins=True`: it got a raw driver error and now gets the `PluginRestoreError` that names the plugin."""
        LostAt.lose = COMMIT_OF[ORDER[0]]
        with pytest.raises(dbexport.PluginRestoreError) as e:
            dbexport.import_jen(world, truncate=False, strict_plugins=True)
        assert [f[0] for f in e.value.failures] == [ORDER[0]]


def _staged(file_bytes):
    os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, suffix=".jen-import")
    with os.fdopen(fd, "wb") as f:
        f.write(file_bytes)
    return base64.b64encode(path.encode()).decode()


def _last_audit(db):
    db.commit()
    with db.cursor() as cur:
        cur.execute(
            "SELECT action, entity, details FROM audit_log WHERE action LIKE 'DB_IMPORT%%' ORDER BY id DESC LIMIT 1"
        )
        return cur.fetchone()


class TestTheRouteAndItsAuditRow:
    def _confirm(self, client):
        # the page sends every box that is ticked; a merge with none ticked is refused before anything is read
        tables = list(json.loads(gzip.decompress(self.blob))["data"])
        return client.post(
            "/database/import/confirm",
            data={"tmp_path": _staged(self.blob), "mode": "merge", "tables": tables},
            follow_redirects=True,
        )

    @pytest.fixture(autouse=True)
    def _the_file(self, world):
        self.blob = world

    def test_an_import_that_worked_is_db_import(self, logged_in_client, db):
        self._confirm(logged_in_client)
        row = _last_audit(db)
        assert (row["action"], row["entity"]) == ("DB_IMPORT", "jen")
        assert row["details"].startswith("tables=[") and row["details"].endswith(" mode=merge")

    def test_the_last_plugins_lost_commit_is_not_audited_as_an_import_that_worked(self, logged_in_client, db):
        """BB4. v7.2.0-beta.1 writes `DB_IMPORT` under a page that says the outcome is not known."""
        LostAt.lose = COMMIT_OF[ORDER[-1]]
        r = self._confirm(logged_in_client)
        row = _last_audit(db)
        assert (row["action"], row["entity"]) == ("DB_IMPORT_FAILED", "jen")
        assert row["details"].startswith("tables=[")
        assert row["details"].endswith(" mode=merge; a plugin's commit was not confirmed; the outcome is not known")
        assert f"{ORDER[-1]}: the database did not confirm the commit".encode() in r.data

    def test_the_first_plugins_lost_commit_reaches_the_page_with_its_line(self, logged_in_client, db):
        """BB3 through the route. v7.2.0-beta.1 says only `Import failed`, and the plugins after the first are not restored."""
        LostAt.lose = COMMIT_OF[ORDER[0]]
        r = self._confirm(logged_in_client)
        row = _last_audit(db)
        assert row["action"] == "DB_IMPORT_FAILED" and row["details"].endswith("the outcome is not known")
        assert f"{ORDER[0]}: the database did not confirm the commit".encode() in r.data
        assert _rows(db) == EVERY_ROW
