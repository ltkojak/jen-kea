"""
tests/test_import_guarded.py
────────────────────────────
v5.67.0-beta.14 (Q128, item b) — the Databases import page's replace mode takes a snapshot first and puts the
database back on ANY failure, so the confirmation page's promise ("if anything fails … rolls back") is true. Until
now core tables committed together and each plugin's migration rows, DDL (which auto-commits) and rows committed
separately, so a failure in plugin N left the core tables and plugins 1..N-1 restored. Against the real MariaDB,
with the real bundled plugins' schemas (`dns-sync` restores before `wol`; the failure is injected in `wol`).
"""

import base64
import gzip
import json
import os
import pathlib

import pytest

from jen import extensions
from jen.services import dbexport
from jen.services import plugins as plugins_svc

A = "zz_q128g_a"


@pytest.fixture(autouse=True)
def _world(db, monkeypatch, tmp_path):
    """The real bundled plugin tree (conftest points it at nothing), a private backups directory, and one scratch
    Jen table registered for the test."""
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
    monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setitem(dbexport.JEN_TABLES, A, "scratch")
    with db.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS `{A}`")
        cur.execute(f"CREATE TABLE `{A}` (id INT PRIMARY KEY, label VARCHAR(20) NOT NULL)")
        cur.execute(f"INSERT INTO `{A}` (id, label) VALUES (1, 'exported-1'), (2, 'exported-2')")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS `{A}`")
    db.commit()


def _manifest(pid):
    p = pathlib.Path(__file__).resolve().parent.parent / "plugins" / pid / "manifest.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _install(db, pid):
    manifest = _manifest(pid)
    with db.cursor() as cur:
        cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (pid,))
    db.commit()
    ok, msg, _n = plugins_svc.run_plugin_migrations(manifest)
    assert ok, msg


def _drop_plugin(db, pid, table):
    with db.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS `{table}`")
        cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (pid,))
    db.commit()


def _export(tmp_path) -> bytes:
    path = tmp_path / "export.json.gz"
    dbexport.write_jen_export(str(path))
    return path.read_bytes()


def _q(db, sql, args=()):
    db.commit()  # the code under test wrote through its own connections
    with db.cursor() as cur:
        cur.execute(sql, args)
        return list(cur.fetchall())


def _migration_rows(db):
    return {(r["plugin_id"], r["version"]) for r in _q(db, "SELECT plugin_id, version FROM plugin_schema_migrations")}


def _snapshots(tmp_path):
    root = tmp_path / "backups"
    return sorted(p.name for p in root.glob("pre-import-*")) if root.is_dir() else []


def _fail_wol_once(monkeypatch):
    """The first time wol's migrations are replayed, fail; afterwards behave (the rollback replays them again)."""
    real = plugins_svc.run_plugin_migrations
    state = {"failed": 0}

    def fake(manifest):
        if manifest["id"] == "wol" and not state["failed"]:
            state["failed"] = 1
            return False, "simulated", 0
        return real(manifest)

    monkeypatch.setattr(plugins_svc, "run_plugin_migrations", fake)
    return state


class TestReplaceModeRollsBack:
    def test_a_failure_in_a_late_plugin_puts_the_core_tables_and_earlier_plugins_back(self, db, tmp_path, monkeypatch):
        _install(db, "dns-sync")
        _install(db, "wol")
        with db.cursor() as cur:
            cur.execute("DELETE FROM ds_targets")
            cur.execute("DELETE FROM wol_hosts")
            cur.execute(
                "INSERT INTO ds_targets (id, name, kind, url, domain, sources, enabled) "
                "VALUES (9001, 'exported-target', 'pihole', 'http://p', 'lan', 'leases', 1)"
            )
            cur.execute("INSERT INTO wol_hosts (id, mac, label) VALUES (9001, 'de:ad:be:ef:00:05', 'exported-wol')")
        db.commit()
        blob = _export(tmp_path)

        # the live state AFTER the export — what a failed import must leave exactly as it is
        with db.cursor() as cur:
            cur.execute(f"UPDATE `{A}` SET label = 'live-1' WHERE id = 1")
            cur.execute(f"INSERT INTO `{A}` (id, label) VALUES (3, 'live-3')")
            cur.execute("UPDATE ds_targets SET name = 'live-target' WHERE id = 9001")
            cur.execute("DELETE FROM wol_hosts")
            cur.execute("INSERT INTO wol_hosts (id, mac, label) VALUES (9002, 'de:ad:be:ef:00:06', 'live-wol')")
        db.commit()
        migrations_before = _migration_rows(db)
        assert ("wol", 1) in migrations_before and ("dns-sync", 1) in migrations_before
        state = _fail_wol_once(monkeypatch)

        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(blob)

        assert state["failed"] == 1, "the injected failure never fired — the test proved nothing"
        assert e.value.state == "rolled_back"
        assert "put back exactly as it was" in e.value.public
        assert [(r["id"], r["label"]) for r in _q(db, f"SELECT * FROM `{A}` ORDER BY id")] == [
            (1, "live-1"),
            (2, "exported-2"),
            (3, "live-3"),
        ]
        assert _q(db, "SELECT name FROM ds_targets WHERE id = 9001")[0]["name"] == "live-target", (
            "an earlier plugin's tables were left restored from the file"
        )
        assert [r["label"] for r in _q(db, "SELECT label FROM wol_hosts")] == ["live-wol"]
        assert _migration_rows(db) == migrations_before
        assert dbexport._plugin_invariant_violations(db) == []
        assert _snapshots(tmp_path) == [], "the snapshot directory was left behind"

    def test_a_plugin_table_the_failed_import_created_is_dropped_again(self, db, tmp_path, monkeypatch):
        _install(db, "wol")
        with db.cursor() as cur:
            cur.execute("DELETE FROM wol_hosts")
            cur.execute("INSERT INTO wol_hosts (id, mac, label) VALUES (9001, 'de:ad:be:ef:00:05', 'exported-wol')")
        db.commit()
        blob = _export(tmp_path)
        _drop_plugin(db, "wol", "wol_hosts")  # this box has never migrated wol: no table, no migration rows
        migrations_before = _migration_rows(db)

        real = dbexport._decode_import_rows

        def boom(table, *a, **k):
            if table == "wol_hosts":
                raise dbexport.BinaryValueError("wol_hosts.mac (row 1): simulated")
            return real(table, *a, **k)

        monkeypatch.setattr(dbexport, "_decode_import_rows", boom)
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(blob)

        assert e.value.state == "rolled_back"
        assert not _q(db, "SHOW TABLES LIKE 'wol_hosts'"), "a table the failed import created was left behind"
        assert _migration_rows(db) == migrations_before
        assert [r["label"] for r in _q(db, f"SELECT label FROM `{A}` ORDER BY id")] == ["exported-1", "exported-2"]

    def test_a_core_table_failure_rolls_back_too(self, db, tmp_path):
        bad = gzip.compress(
            json.dumps(
                {
                    "data": {A: [{"id": 9, "label": None}]},
                    "_meta": {"database": "jen", "jen_export_version": 1, "format": 3, "tables": [A]},
                }
            ).encode()
        )
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(bad, [A])
        assert e.value.state == "rolled_back"
        assert [r["id"] for r in _q(db, f"SELECT id FROM `{A}` ORDER BY id")] == [1, 2]
        assert _snapshots(tmp_path) == []

    def test_a_clean_import_succeeds_and_leaves_no_snapshot(self, db, tmp_path):
        ok = gzip.compress(
            json.dumps(
                {
                    "data": {A: [{"id": 7, "label": "from-file"}]},
                    "_meta": {"database": "jen", "jen_export_version": 1, "format": 3, "tables": [A]},
                }
            ).encode()
        )
        results = dbexport.import_jen_guarded(ok, [A])
        assert results == [f"✅ {A}: 1 rows restored"]
        assert [r["label"] for r in _q(db, f"SELECT label FROM `{A}`")] == ["from-file"]
        assert _snapshots(tmp_path) == []


class TestTheSafetyNet:
    def test_a_snapshot_that_cannot_be_taken_means_nothing_is_imported(self, db, monkeypatch):
        def no(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(dbexport, "write_jen_export", no)
        monkeypatch.setattr(
            dbexport, "import_jen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("imported without a snapshot"))
        )
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(b"{}")
        assert e.value.state == "unchanged" and "nothing was imported" in e.value.public

    def test_a_rollback_that_fails_keeps_the_snapshot_and_says_where(self, db, tmp_path, monkeypatch):
        bad = gzip.compress(
            json.dumps({"data": {A: [{"id": 9, "label": None}]}, "_meta": {"database": "jen"}}).encode()
        )
        monkeypatch.setattr(dbexport, "_roll_back_to", lambda snap: (_ for _ in ()).throw(RuntimeError("no way back")))
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(bad, [A])
        assert e.value.state == "rollback_failed"
        snap_dir = e.value.snapshot
        assert snap_dir in e.value.public and os.path.isfile(os.path.join(snap_dir, "jen_db.json.gz"))
        if os.name != "nt":
            assert (os.stat(snap_dir).st_mode & 0o777) == 0o700
            assert (os.stat(os.path.join(snap_dir, "jen_db.json.gz")).st_mode & 0o777) == 0o600
        # the kept snapshot is an ordinary export: it parses
        with open(os.path.join(snap_dir, "jen_db.json.gz"), "rb") as f:
            assert dbexport.parse_import_file(f.read())[2] is None

    def test_a_refusal_before_the_first_write_leaves_nothing_to_undo(self, db, tmp_path):
        blob = gzip.compress(
            json.dumps({"data": {"users": [], "mfa_methods": []}, "_meta": {"database": "jen", "format": 3}}).encode()
        )
        with pytest.raises(dbexport.ScopeRefused):
            dbexport.import_jen_guarded(blob, ["users"])
        assert _snapshots(tmp_path) == []
        with pytest.raises(ValueError):
            dbexport.import_jen_guarded(gzip.compress(json.dumps({"data": {}, "_meta": {"database": "kea"}}).encode()))
        assert _snapshots(tmp_path) == []


class TestTheImportPage:
    def _stage(self, payload):
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        path = os.path.join(extensions.CONTENT_TMP_DIR, "jen_import_q128guard.json.gz")
        with open(path, "wb") as f:
            f.write(gzip.compress(json.dumps(payload).encode()))
        return base64.b64encode(path.encode()).decode()

    def test_replace_mode_goes_through_the_snapshot_and_merge_mode_does_not(self, logged_in_client, monkeypatch):
        calls = []
        monkeypatch.setattr(dbexport, "import_jen_guarded", lambda b, t=None: calls.append(("guarded", t)) or [])
        monkeypatch.setattr(
            dbexport, "import_jen", lambda b, t=None, truncate=True, **k: calls.append(("plain", t, truncate)) or []
        )
        payload = {"data": {A: []}, "_meta": {"database": "jen", "tables": [A]}}
        logged_in_client.post(
            "/database/import/confirm", data={"tmp_path": self._stage(payload), "tables": [A], "mode": "replace"}
        )
        logged_in_client.post(
            "/database/import/confirm", data={"tmp_path": self._stage(payload), "tables": [A], "mode": "merge"}
        )
        assert calls == [("guarded", [A]), ("plain", [A], False)]

    @pytest.mark.parametrize(
        "state,words",
        [
            ("rolled_back", "put back exactly as it was"),
            ("rollback_failed", "putting the database back did not complete"),
            ("unchanged", "nothing was imported"),
        ],
    )
    def test_each_outcome_is_said_plainly(self, logged_in_client, monkeypatch, state, words):
        text = {
            "rolled_back": "The import failed and was rolled back: the database was put back exactly as it was before.",
            "rollback_failed": "The import failed, and putting the database back did not complete. Kept in /x.",
            "unchanged": "Could not take the safety snapshot, so nothing was imported.",
        }[state]

        def boom(b, t=None):
            raise dbexport.GuardedImportError(text, state)

        monkeypatch.setattr(dbexport, "import_jen_guarded", boom)
        payload = {"data": {A: []}, "_meta": {"database": "jen", "tables": [A]}}
        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": self._stage(payload), "tables": [A], "mode": "replace"},
            follow_redirects=True,
        )
        assert r.status_code == 200 and words.encode() in r.data

    def test_the_confirmation_page_makes_only_promises_the_code_keeps(self, logged_in_client):
        import io

        payload = {"data": {"settings": []}, "_meta": {"database": "jen", "tables": ["settings"]}}
        r = logged_in_client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(gzip.compress(json.dumps(payload).encode())), "e.json.gz")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        page = r.data.decode()
        assert "Replace</strong> mode first saves a snapshot" in page
        assert "puts it back if anything fails" in page
        assert "Merge</strong> mode takes no snapshot" in page
        assert (
            "each plugin's tables one plugin at a time" in page
            or "each plugin&#39;s tables one plugin at a time" in page
        )
        assert "rolls back completely" not in page, "the Jen import never makes the unconditional promise again"

        kea = {"data": {"hosts": []}, "_meta": {"database": "kea", "tables": ["hosts"]}}
        r = logged_in_client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(gzip.compress(json.dumps(kea).encode())), "k.json.gz")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"single transaction" in r.data and b"rolls back completely" in r.data
