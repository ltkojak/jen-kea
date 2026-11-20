"""
tests/test_a_commit_that_raised_is_not_a_rollback.py
────────────────────────────────────────────────────
Q242 (finding 2 of the independent review of v7.1.0-beta.10).

`import_kea` and `import_jen` sent their `commit()` inside the `try` whose handler rolls back. A commit that raised was answered with a rollback, the
rollback returned without an error, and the import was reported as "failed and was rolled back". When the server had applied the commit and the reply was
lost, the rows were there and Jen said they were not: a rollback sent after a commit undoes nothing.

A commit that raised now has one answer, `ImportOutcomeUnknown`: no rollback is sent and none is claimed. A failure BEFORE the commit whose rollback
returned is `ImportRolledBack`, and the audit row says so; it used to say "the outcome is not known" of the one failure whose outcome is known.

The connections here are the real ones `dbexport` opens, against the real database. One thing is put in the test's hands: what happens to the commit.
"""

import ast
import base64
import json
import os
import pathlib
import tempfile

import pymysql
import pytest

from jen import extensions
from jen.services import dbexport

ROOT = pathlib.Path(__file__).resolve().parent.parent
M1 = bytes.fromhex("02cc00000042")


@pytest.fixture
def kea(db):
    def wipe():
        db.commit()
        with db.cursor() as cur:
            for t in ("ipv6_reservations", "dhcp6_options", "dhcp4_options", "hosts", "lease4"):
                cur.execute(f"DELETE FROM `{t}`")
        db.commit()

    wipe()
    yield db
    wipe()


def _hosts(conn):
    conn.commit()
    with conn.cursor() as cur:
        cur.execute("SELECT hostname FROM hosts")
        return [r["hostname"] for r in cur.fetchall()]


def _a_kea_file(name="from-file"):
    row = {
        "host_id": 1,
        "dhcp_identifier": {"$bin": M1.hex()},
        "dhcp_identifier_type": 0,
        "dhcp4_subnet_id": 1,
        "dhcp6_subnet_id": None,
        "ipv4_address": None,
        "hostname": name,
    }
    meta = {"database": "kea", "jen_export_version": 1, "format": 3, "tables": ["hosts"]}
    return json.dumps({"_meta": meta, "data": {"hosts": [row]}}).encode("utf-8")


class ReplyLost(pymysql.connections.Connection):
    """The server applies the commit and the client never hears: the real commit runs, then the error a lost connection gives."""

    rollbacks = 0

    def commit(self):
        super().commit()
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")

    def rollback(self):
        type(self).rollbacks += 1
        super().rollback()


class KilledBeforeTheCommit(pymysql.connections.Connection):
    """Nothing is faked: the server ends this connection (`KILL`, from a second one) and the real commit then finds it gone."""

    def commit(self):
        other = pymysql.connect(
            host=self.host, port=self.port, user=self.user, password=self.password, database=self.db, autocommit=True
        )
        try:
            with other.cursor() as cur:
                cur.execute(f"KILL {int(self.thread_id())}")
        finally:
            other.close()
        super().commit()


def _opened_as(monkeypatch, name, cls):
    real = getattr(dbexport, name)

    def opened():
        conn = real()
        conn.__class__ = cls
        return conn

    monkeypatch.setattr(dbexport, name, opened)


class TestTheKeaImport:
    def test_a_commit_the_server_applied_and_could_not_confirm_is_not_called_a_rollback(self, kea, monkeypatch):
        """The review's world. The row IS in the table. 7.1.0-beta.10 answers `Kea import failed and was rolled back`."""
        ReplyLost.rollbacks = 0
        _opened_as(monkeypatch, "_direct_kea_conn", ReplyLost)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            dbexport.import_kea(_a_kea_file(), "skip")
        assert _hosts(kea) == ["from-file"], "the commit was applied"
        said = str(e.value) + e.value.public
        assert "rolled back" not in said and "othing was changed" not in said
        assert "the outcome is not known" in e.value.public and "Look at the data before importing again" in said
        assert ReplyLost.rollbacks == 0, "no rollback is sent after a commit: it would prove nothing"

    def test_a_connection_the_server_ended_before_the_commit_is_not_known_either(self, kea, monkeypatch):
        """The same exception class from the client's side, and here nothing was applied: the client cannot tell the two apart, which is the point."""
        _opened_as(monkeypatch, "_direct_kea_conn", KilledBeforeTheCommit)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            dbexport.import_kea(_a_kea_file(), "skip")
        assert _hosts(kea) == []
        assert "rolled back" not in str(e.value)

    def test_the_cause_is_named_by_its_type_and_never_by_its_text(self, kea, monkeypatch):
        _opened_as(monkeypatch, "_direct_kea_conn", ReplyLost)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            dbexport.import_kea(_a_kea_file(), "skip")
        assert "(OperationalError)" in str(e.value) and "Lost connection" not in str(e.value)
        assert "OperationalError" not in e.value.public

    def test_a_failure_before_the_commit_is_rolled_back_and_says_so(self, kea, monkeypatch):
        def stop(*a, **k):
            raise KeyError("x")

        monkeypatch.setattr(dbexport, "_table_exists", stop)
        with pytest.raises(dbexport.ImportRolledBack) as e:
            dbexport.import_kea(_a_kea_file(), "skip")
        assert "Kea import failed and was rolled back" in str(e.value) and isinstance(e.value, RuntimeError)
        assert not isinstance(e.value, dbexport.ImportOutcomeUnknown)
        assert _hosts(kea) == []

    def test_an_import_that_works_still_works(self, kea):
        out = dbexport.import_kea(_a_kea_file(), "skip")
        assert _hosts(kea) == ["from-file"] and any("hosts: 1 inserted" in line for line in out), out


@pytest.fixture
def a_setting(db):
    """One row in `settings`, so the export of that table carries a row whatever the suite left there."""
    with db.cursor() as cur:
        cur.execute("REPLACE INTO settings (setting_key, setting_value) VALUES ('q242_probe', '1')")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM settings WHERE setting_key='q242_probe'")
    db.commit()


def _a_jen_file(tmp_path, tables):
    path = tmp_path / "export.json.gz"
    dbexport.write_jen_export(str(path), tables)
    return path.read_bytes()


class TestTheJenImport:
    def test_the_core_tables_commit_that_raised_is_not_called_a_rollback(self, db, a_setting, monkeypatch, tmp_path):
        """Merge mode, the Databases page's own call. (Replace mode takes a snapshot first and puts it back whatever the commit did.)"""
        blob = _a_jen_file(tmp_path, ["settings"])
        ReplyLost.rollbacks = 0
        _opened_as(monkeypatch, "_direct_jen_conn", ReplyLost)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            dbexport.import_jen(blob, ["settings"], truncate=False)
        assert "rolled back" not in str(e.value) and e.value.public.startswith("Import: the database did not confirm")
        assert ReplyLost.rollbacks == 0

    def test_a_failure_before_that_commit_is_rolled_back_and_says_so(self, db, a_setting, monkeypatch, tmp_path):
        blob = _a_jen_file(tmp_path, ["settings"])

        def stop(*a, **k):
            raise dbexport.BinaryValueError("settings.setting_value (row 1): simulated")

        monkeypatch.setattr(dbexport, "_decode_import_rows", stop)
        with pytest.raises(dbexport.ImportRolledBack) as e:
            dbexport.import_jen(blob, ["settings"], truncate=False)
        assert str(e.value).startswith("Import failed and was rolled back: ")


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


class TestThePageAndTheAuditRowSayWhichOfTheThreeItWas:
    """The real route. Before this Q the audit row of a definite rollback and of a lost commit were the same words, and the page said `Import failed` twice."""

    def _confirm(self, client):
        token = _staged(_a_kea_file())
        return client.post(
            "/database/import/confirm", data={"tmp_path": token, "duplicate_mode": "skip"}, follow_redirects=True
        )

    def test_a_commit_that_was_not_confirmed(self, logged_in_client, kea, monkeypatch):
        _opened_as(monkeypatch, "_direct_kea_conn", ReplyLost)
        r = self._confirm(logged_in_client)
        row = _last_audit(kea)
        assert (row["action"], row["entity"]) == ("DB_IMPORT_FAILED", "kea")
        assert row["details"] == "the commit was not confirmed; the outcome is not known"
        assert b"Kea import: the database did not confirm the commit, so the outcome is not known" in r.data
        assert b"Look at the data before importing again." in r.data
        assert b"rolled back" not in r.data and b"Nothing was changed" not in r.data
        assert _hosts(kea) == ["from-file"]

    def test_a_failure_before_the_commit(self, logged_in_client, kea, monkeypatch):
        def stop(*a, **k):
            raise KeyError("x")

        monkeypatch.setattr(dbexport, "_table_exists", stop)
        r = self._confirm(logged_in_client)
        row = _last_audit(kea)
        assert row["details"] == "rolled back; nothing was changed"
        assert b"Import failed and was rolled back. Nothing was changed." in r.data
        assert _hosts(kea) == []

    def test_an_import_that_worked(self, logged_in_client, kea):
        self._confirm(logged_in_client)
        row = _last_audit(kea)
        assert (row["action"], row["details"]) == ("DB_IMPORT", "duplicate_mode=skip")
        assert _hosts(kea) == ["from-file"]


#: a `try` that sends a commit and whose handler says "rolled back" or "nothing was changed", and is not changed by Q242. Each with why.
REVIEWED = {
    # its handler deletes what the run inserted, by primary key on a fresh connection, when the rollback is not confirmed: after a commit whose reply was
    # lost the rollback fails on the dead connection, the delete runs and "the target was rolled back" is true. (Q244, BB8, BB30) The reason written here
    # by Q242 said the sentence was wrong after a lost commit; it was wrong only when that DELETE failed, and that case now has a sentence of its own
    # (`KEA_MIGRATION_NOT_UNDONE`; `tests/test_migrate_contract.py::TestAMigrationThatCouldNotBeUndoneDoesNotSayItWas`)
    ("jen/services/dbexport.py", "migrate_kea"),
}


def _claims_after_a_commit(path):
    source = path.read_text(encoding="utf-8")
    found = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Try):
                continue
            sends = any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "commit"
                for stmt in node.body
                for c in ast.walk(stmt)
            )
            for handler in node.handlers if sends else []:
                text = (ast.get_source_segment(source, handler) or "").lower()
                if ("rolled back" in text or "nothing was changed" in text) and "committing" not in text:
                    found.append(fn.name)
    return found


class TestNoHandlerOfACommitClaimsARollback:
    def test_over_the_whole_tree(self):
        """Every `try` under `jen/`, `plugins/` and `tools/` that sends a commit: a handler of it that says "rolled back" or "nothing was changed" asks
        first whether the commit had been sent (`committing`), or the commit is outside the `try`."""
        found = set()
        for top in ("jen", "plugins", "tools"):
            for path in sorted((ROOT / top).rglob("*.py")):
                rel = path.relative_to(ROOT).as_posix()
                found |= {(rel, name) for name in _claims_after_a_commit(path)}
        assert found == REVIEWED

    def test_the_sweep_sees_the_shape_it_was_written_for(self, tmp_path):
        old = tmp_path / "old.py"
        old.write_text(
            "def f(conn):\n    try:\n        conn.commit()\n    except Exception as e:\n"
            "        conn.rollback()\n        raise RuntimeError(f'failed and was rolled back: {e}') from e\n",
            encoding="utf-8",
        )
        assert _claims_after_a_commit(old) == ["f"]

    def test_the_kea_import_asks_before_it_claims(self):
        source = (ROOT / "jen/services/dbexport.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "import_kea")
        text = ast.get_source_segment(source, fn)
        assert text.count("committing = True\n        conn.commit()") == 1 and text.count("conn.commit()") == 1
        assert text.index("if committing:") < text.index("if not _rolled_back(conn):\n            raise RuntimeError(f")
