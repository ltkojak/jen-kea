"""
tests/test_q252_a.py
────────────────────
Q252 (Jen 7.2.1): three findings of the independent review of v7.2.0-beta.9 that had each come back for the third time. Each earlier fix closed the instance
the review named. These close the class: a rule, every site of it, and a source test over the whole tree.

Row 1. A `commit()` is never inside a `try` whose handler rolls back, deletes what the run wrote or says it was undone. `migrate_kea` and `migrate_jen`
       sent theirs inside that `try`; a commit the target applied and could not confirm was reported as "rolled back" or "removed". And a failed migration
       left no audit row and one sentence on the page whatever had happened.
Row 2. One status for the result of an import (`dbexport.import_status`). The audit row asked only whether a plugin's commit was lost, so a plugin whose
       migration replay failed was audited `DB_IMPORT`, the action of an import that worked.
Row 3. Every string of the support bundle goes through one mask (`secret_keys.without_credentials`). A string under a key that does not end in `url` kept
       the query values and the fragment of an address inside it.

The connections are the real ones `dbexport` opens, against the real database and a scratch one beside it. What is in a test's hands is named in it.
"""

import ast
import base64
import gzip
import io
import json
import os
import pathlib
import re
import tempfile
import time
import zipfile
from datetime import datetime, timezone

import pymysql
import pytest

from jen import extensions
from jen.routes import database as database_routes
from jen.services import dbexport
from jen.services import plugins as plugins_svc
from jen.services import support_bundle as sb
from tests import test_a_lost_plugin_commit_does_not_stop_the_plugins_after_it as P
from tests import test_migrate_contract as M
from tests.conftest import TEST_DB

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRATCH = "jen_test_q252a_target"
PORT = int(os.environ.get("JEN_DB_PORT", 3306))

# ══ Row 1: the source rule ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

#: what a handler says when it claims an undo
CLAIMS = ("rolled back", "was touched")


def _reached(stmts):
    """Every node a `try`'s BODY runs itself: not the body of a function, a lambda or a class defined there, and not the body of a `try` nested in it,
    which is judged on its own (its handlers, its `else` and its `finally` raise into this one, so they are read)."""
    todo = list(stmts)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Try):
            todo.extend(node.handlers)
            todo.extend(node.orelse)
            todo.extend(node.finalbody)
            continue
        yield node
        todo.extend(ast.iter_child_nodes(node))


def _calls_of(nodes, method):
    """The names `<x>` of every call `<x>.<method>()` among `nodes`."""
    return {
        ast.unparse(n.func.value)
        for n in nodes
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == method and not n.args
    }


def commits_inside_the_try_that_undoes_them(source):
    """[(function, why)] for every `try` in `source` whose body sends `<x>.commit()` and one of whose handlers sends `<x>.rollback()` on the same name, or
    holds a string that says "rolled back" or "was touched"."""
    tree = ast.parse(source)
    owner = {}
    for fn in ast.walk(
        tree
    ):  # breadth-first: a function nested in another is met later and its name replaces the outer one
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if isinstance(node, ast.Try):
                    owner[node] = fn.name
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        commits = _calls_of(_reached(node.body), "commit")
        if not commits:
            continue
        inside = [n for handler in node.handlers for n in ast.walk(handler)]
        undone = sorted(commits & _calls_of(inside, "rollback"))
        said = sorted(
            {
                c
                for n in inside
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                for c in CLAIMS
                if c in n.value
            }
        )
        if undone or said:
            found.append((owner.get(node, "<module>"), ", ".join([f"{x}.rollback()" for x in undone] + said)))
    return found


#: every site outside `jen/services/dbexport.py` the rule finds on v7.2.0, NOT edited by Q252 (it changes `dbexport` only), each with what it does. None of
#: them tells a person that anything was undone; each sends a rollback after a commit that raised, which is harmless after a commit the server refused and
#: does nothing after one it applied. Listed for the author of the Q to judge.
REVIEWED = {
    # the pool's three context managers: `yield db; db.commit()` in one `try`, the handler sends `db.rollback()` under `suppress` and re-raises the error
    # as it is. The caller gets the driver's own exception; no sentence is made here. Every `with jen_db()` block in the tree ends through this commit
    ("jen/models/db.py", "jen_db"),
    ("jen/models/db.py", "kea_db"),
    ("jen/models/db.py", "kea6_db"),
    # the conflict check's tracking rows: a commit that raises leaves `committed` False, the handler logs and rolls back, and no alert is sent for this
    # run. If the server had applied the commit, the rows are stored and the conflicts they name are not announced by this run
    ("plugins/ipam/plugin.py", "_check_conflicts"),
    # a scan's first commit (the job marked "running") and its results' commit are in the `try`; the handler rolls back and marks the job "error" with
    # "scan failed", a sentence about the scan and not about the rows
    ("plugins/network-discovery/plugin.py", "_run_scan_job"),
    # one tick's checks and states: a commit that raises leaves `committed` False, the handler logs and rolls back, and no alert is sent. If the server
    # had applied it, the transition is stored and this tick does not announce it
    ("plugins/watchdog/plugin.py", "_record_results"),
}


def _written(tmp_path, text):
    path = tmp_path / "case.py"
    path.write_text(text, encoding="utf-8")
    return commits_inside_the_try_that_undoes_them(path.read_text(encoding="utf-8"))


class TestACommitIsNeverInsideTheTryThatUndoesIt:
    """The checker's own cases first: what it refuses and what it accepts. Then the whole tree."""

    def test_a_commit_under_a_flag_is_refused(self, tmp_path):
        """The shape `import_kea` had until this Q: right in substance, and a reader had to trust the flag."""
        found = _written(
            tmp_path,
            "def f(conn):\n"
            "    committing = False\n"
            "    try:\n"
            "        work(conn)\n"
            "        committing = True\n"
            "        conn.commit()\n"
            "    except Exception as e:\n"
            "        if committing:\n"
            "            raise Unknown(e) from e\n"
            "        raise RuntimeError(f'failed and was rolled back: {e}') from e\n",
        )
        assert found == [("f", "rolled back")]

    def test_a_commit_and_a_rollback_on_the_same_name_are_refused(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(dst):\n    try:\n        dst.commit()\n    except Exception:\n        dst.rollback()\n        raise\n",
        )
        assert found == [("f", "dst.rollback()")]

    def test_a_handler_that_says_nothing_was_touched_is_refused(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(dst):\n    try:\n        dst.commit()\n    except Exception as e:\n"
            "        raise RuntimeError('the tables were removed and nothing that was there was touched') from e\n",
        )
        assert found == [("f", "was touched")]

    def test_a_commit_inside_a_with_block_of_the_try_is_seen(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(pool):\n    try:\n        with pool() as db:\n            db.commit()\n"
            "    except Exception:\n        db.rollback()\n",
        )
        assert found == [("f", "db.rollback()")]

    def test_a_commit_after_the_try_is_accepted(self, tmp_path):
        """The shape `import_jen` has since Q242."""
        found = _written(
            tmp_path,
            "def f(conn):\n"
            "    try:\n        work(conn)\n    except Exception as e:\n        conn.rollback()\n"
            "        raise RuntimeError(f'failed and was rolled back: {e}') from e\n"
            "    try:\n        conn.commit()\n    except Exception as e:\n        raise Unknown(e) from e\n",
        )
        assert found == []

    def test_a_commit_in_the_else_of_the_try_is_accepted(self, tmp_path):
        """The shape `import_kea` has now: an `else` runs after the body and its error does not reach the handlers."""
        found = _written(
            tmp_path,
            "def f(conn):\n"
            "    try:\n        work(conn)\n    except Exception as e:\n        conn.rollback()\n"
            "        raise RuntimeError(f'failed and was rolled back: {e}') from e\n"
            "    else:\n        try:\n            conn.commit()\n        except Exception as e:\n            raise Unknown(e) from e\n"
            "    finally:\n        conn.close()\n",
        )
        assert found == []

    def test_a_nested_functions_commit_is_not_counted(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(conn):\n    try:\n        def later():\n            conn.commit()\n        work(later)\n"
            "    except Exception:\n        conn.rollback()\n        raise\n",
        )
        assert found == []

    def test_a_nested_try_is_judged_on_its_own(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(conn):\n"
            "    try:\n"
            "        try:\n            conn.commit()\n        except Exception as e:\n            raise Unknown(e) from e\n"
            "    except ValueError:\n        conn.rollback()\n",
        )
        assert found == []

    def test_a_rollback_on_another_connection_is_accepted(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(a, b):\n    try:\n        a.commit()\n    except Exception:\n        b.rollback()\n        raise\n",
        )
        assert found == []

    def test_a_commit_in_the_handler_is_not_a_commit_of_the_body(self, tmp_path):
        found = _written(
            tmp_path,
            "def f(conn):\n    try:\n        work(conn)\n    except Exception:\n        conn.rollback()\n        conn.commit()\n",
        )
        assert found == []

    def test_the_function_named_is_the_innermost_one(self, tmp_path):
        found = _written(
            tmp_path,
            "def outer(conn):\n    def inner():\n        try:\n            conn.commit()\n"
            "        except Exception:\n            conn.rollback()\n    return inner\n",
        )
        assert found == [("inner", "conn.rollback()")]

    def test_over_the_whole_tree(self):
        """Every `.py` under `jen/` and `plugins/`, walked: never a list of files."""
        found = set()
        read = 0
        for top in ("jen", "plugins"):
            for path in sorted((ROOT / top).rglob("*.py")):
                read += 1
                rel = path.relative_to(ROOT).as_posix()
                found |= {
                    (rel, name) for name, _why in commits_inside_the_try_that_undoes_them(path.read_text("utf-8"))
                }
        assert read > 100, "the walk read the tree"
        assert found == REVIEWED, sorted(found ^ REVIEWED)

    def test_no_site_of_the_export_module_is_on_the_reviewed_list(self):
        assert not [site for site in REVIEWED if site[0] == "jen/services/dbexport.py"]
        source = (ROOT / "jen/services/dbexport.py").read_text(encoding="utf-8")
        assert commits_inside_the_try_that_undoes_them(source) == []


# ══ Row 1: what a lost commit does ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════


def _kill(conn):
    """The server ends `conn`, asked from a second connection: everything sent on `conn` afterward really fails."""
    other = pymysql.connect(host=conn.host, port=conn.port, user=conn.user, password=conn.password, autocommit=True)
    try:
        with other.cursor() as cur:
            cur.execute(f"KILL {int(conn.thread_id())}")
    finally:
        other.close()


class Lost(pymysql.connections.Connection):
    """The server applies the commit, then ends this connection, and the client gets the error of a lost one. The class counts what is sent afterward."""

    committed = False
    rollbacks = 0
    after = []

    def commit(self):
        super().commit()
        _kill(self)
        Lost.committed = True
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")

    def rollback(self):
        Lost.rollbacks += 1
        super().rollback()

    def query(self, sql, unbuffered=False):
        if Lost.committed:
            Lost.after.append(sql)
        return super().query(sql, unbuffered)


@pytest.fixture(autouse=True)
def _nothing_counted_yet():
    Lost.committed, Lost.rollbacks, Lost.after = False, 0, []
    yield
    Lost.committed, Lost.rollbacks, Lost.after = False, 0, []


@pytest.fixture
def target():
    """An empty scratch database on the same server, gone again afterward."""
    admin = M._conn()
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{SCRATCH}`")
        cur.execute(f"CREATE DATABASE `{SCRATCH}`")
    admin.close()
    yield SCRATCH
    admin = M._conn()
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{SCRATCH}`")
    admin.close()


#: three reservations in the source, two with an option, one with an IPv6 reservation; the tables are emptied before and after
kea_source = M.kea_source


def _lose(monkeypatch, second_connection_fails=False):
    """The first connection `dbexport` opens to the target loses its commit; a second one is refused when asked. Returns the list that counts them."""
    real = dbexport._direct_conn
    opened = []

    def direct(host, port, user, password, database, ssl_ca=""):
        if database == SCRATCH:
            opened.append(1)
            if len(opened) == 2 and second_connection_fails:
                raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server")
        conn = real(host, port, user, password, database, ssl_ca)
        if database == SCRATCH and len(opened) == 1:
            conn.__class__ = Lost
        return conn

    monkeypatch.setattr(dbexport, "_direct_conn", direct)
    return opened


def _migrate_kea():
    return dbexport.migrate_kea(TEST_DB["host"], PORT, TEST_DB["user"], TEST_DB["password"], SCRATCH)


def _migrate_jen(tables):
    return dbexport.migrate_jen(TEST_DB["host"], PORT, TEST_DB["user"], TEST_DB["password"], SCRATCH, tables=tables)


def _on_target(table):
    tgt = M._conn(SCRATCH)
    try:
        return M.snapshot(tgt, [table])[table]
    finally:
        tgt.close()


def _tables_on_target():
    tgt = M._conn(SCRATCH)
    try:
        return M.tables_of(tgt)
    finally:
        tgt.close()


NOT_KNOWN = (
    "the database did not confirm the commit, so the outcome is not known: the rows may all be there or none of them. "
    "Look at the data before migrating again."
)


class TestTheSentenceOfALostCommit:
    def test_an_import_says_what_it_said(self):
        e = dbexport.ImportOutcomeUnknown("Import", OSError("x"))
        assert e.public == f"Import: {dbexport.COMMIT_NOT_CONFIRMED}." and e.public.endswith("before importing again.")
        assert str(e) == f"Import: {dbexport.COMMIT_NOT_CONFIRMED} (OSError)"

    def test_a_migration_says_migrating(self):
        e = dbexport.ImportOutcomeUnknown("Kea migration", OSError("secret text"), again="migrating again")
        assert e.public == f"Kea migration: {NOT_KNOWN}"
        assert "importing" not in e.public and "secret text" not in str(e) and str(e).endswith("(OSError)")

    def test_the_constant_is_as_it_was(self):
        assert dbexport.COMMIT_NOT_CONFIRMED.endswith("Look at the data before importing again")


class TestAKeaMigrationWhoseCommitWasLost:
    def test_it_is_not_called_a_rollback_and_nothing_is_sent_after_it(self, db, target, kea_source, monkeypatch):
        """v7.2.0: the handler's rollback fails on the lost connection, the rows the target had committed are deleted by primary key on a second
        connection and the run is reported as "the target was rolled back". A reply lost on a connection that stays up got the same sentence with the
        rows still there. Now nothing is sent and nothing is claimed."""
        M.initialize_kea_target(db, SCRATCH).close()
        opened = _lose(monkeypatch)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            _migrate_kea()
        said = str(e.value) + e.value.public
        assert e.value.public == f"Kea migration: {NOT_KNOWN}"
        assert "rolled back" not in said and "was touched" not in said and "othing was changed" not in said
        assert len(_on_target("hosts")) == 3, "the commit was applied: the rows ARE on the target"
        assert Lost.rollbacks == 0, "no rollback is sent after a commit"
        assert Lost.after == [], "nothing more is sent on the connection the commit was lost on"
        assert len(opened) == 1, "and no second connection is opened to delete what was copied"

    def test_the_cause_is_named_by_its_type_and_never_by_its_text(self, db, target, kea_source, monkeypatch):
        M.initialize_kea_target(db, SCRATCH).close()
        _lose(monkeypatch)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            _migrate_kea()
        assert "(OperationalError)" in str(e.value) and "Lost connection" not in str(e.value)
        assert "OperationalError" not in e.value.public

    def test_a_failure_before_the_commit_is_rolled_back_and_says_so(self, db, target, kea_source):
        tgt = M.initialize_kea_target(db, SCRATCH)
        M.add_host(tgt, 12, bytes.fromhex("02bb00000012"), "q252-the-target-owns-id-12")
        before = M.snapshot(tgt, M.KEA_ORDER)
        with pytest.raises(RuntimeError) as e:
            _migrate_kea()
        assert not isinstance(e.value, dbexport.ImportOutcomeUnknown)
        assert "Kea migration failed — the target was rolled back and nothing that was there was touched." in str(
            e.value
        )
        assert M.snapshot(tgt, M.KEA_ORDER) == before, "the rows are gone and what was there is as it was"
        tgt.close()

    def test_a_migration_that_works_still_works(self, db, target, kea_source):
        M.initialize_kea_target(db, SCRATCH).close()
        results = _migrate_kea()
        assert any(r.startswith("✅ hosts: 3 rows") for r in results), results
        assert len(_on_target("hosts")) == 3


@pytest.fixture
def a_setting(db):
    with db.cursor() as cur:
        cur.execute("REPLACE INTO settings (setting_key, setting_value) VALUES ('_q252_probe', 'one')")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM settings WHERE setting_key='_q252_probe'")
    db.commit()


REMOVED_AFTER_A_LOST_COMMIT = (
    "Migration failed: the database did not confirm the commit. The tables it created on the target were removed and nothing that was there "
    "was touched."
)


class TestAJenMigrationWhoseCommitWasLost:
    def test_the_tables_it_created_are_removed_on_a_connection_of_their_own(self, db, target, a_setting, monkeypatch):
        """v7.2.0 sent the drop on the lost connection under `suppress` and said "removed" with the table and its rows on the target."""
        opened = _lose(monkeypatch)
        with pytest.raises(RuntimeError) as e:
            _migrate_jen(["settings"])
        assert not isinstance(e.value, dbexport.ImportOutcomeUnknown)
        assert str(e.value) == REMOVED_AFTER_A_LOST_COMMIT
        assert _tables_on_target() == [], "removed, as the sentence says"
        assert Lost.rollbacks == 0 and Lost.after == [], "nothing was sent on the connection the commit was lost on"
        assert len(opened) == 2, "the removal had a connection of its own"

    def test_a_removal_that_failed_is_not_called_one(self, db, target, a_setting, monkeypatch):
        opened = _lose(monkeypatch, second_connection_fails=True)
        with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
            _migrate_jen(["settings"])
        said = str(e.value) + e.value.public
        assert e.value.public == f"Migration: {NOT_KNOWN}"
        assert "removed" not in said and "was touched" not in said and "rolled back" not in said
        assert _tables_on_target() == ["settings"], "the table is there"
        assert "_q252_probe" in [r["setting_key"] for r in _on_target("settings")], (
            "and the rows ARE there: the commit was applied"
        )
        assert Lost.rollbacks == 0 and Lost.after == [] and len(opened) == 2

    def test_a_failure_before_the_commit_drops_what_it_created_and_says_so(self, db, target, a_setting, monkeypatch):
        def stop(*a, **k):
            raise RuntimeError("simulated")

        monkeypatch.setattr(dbexport, "_verify_copy", stop)
        with pytest.raises(RuntimeError) as e:
            _migrate_jen(["settings"])
        assert str(e.value) == (
            "Migration failed — the tables it created on the target were removed and nothing that was there was touched. Error: simulated"
        )
        assert _tables_on_target() == []

    def test_a_drop_that_could_not_run_is_not_called_removed(self, db, target, a_setting, monkeypatch):
        """The failure is before the commit, and the connection to the target is gone when the handler runs (the server ended it): the rollback and the
        drop both really fail. v7.2.0 ran both under `suppress` and said "the tables it created on the target were removed"."""

        def the_target_goes_away(src, dst, *a, **k):
            _kill(dst)
            raise RuntimeError("simulated")

        monkeypatch.setattr(dbexport, "_verify_copy", the_target_goes_away)
        with pytest.raises(RuntimeError) as e:
            _migrate_jen(["settings"])
        assert str(e.value) == (
            "Migration failed and the tables it created on the target could not be removed: settings. Drop them before migrating again. "
            "Error: simulated"
        )
        assert "were removed" not in str(e.value) and "was touched" not in str(e.value)
        assert _tables_on_target() == ["settings"], "the table is there, as the sentence says"

    def test_a_migration_that_works_still_works(self, db, target, a_setting):
        results = _migrate_jen(["settings"])
        assert any(r.startswith("✅ settings:") for r in results), results
        assert "_q252_probe" in [r["setting_key"] for r in _on_target("settings")]


class Counted(pymysql.connections.Connection):
    """A commit whose reply is lost on a connection that stays up; `close()` is counted."""

    closed = 0

    def commit(self):
        super().commit()
        raise pymysql.err.OperationalError(2013, "Lost connection to MySQL server during query")

    def close(self):
        Counted.closed += 1
        super().close()


class TestTheKeaImportKeptWhatItDid:
    """`import_kea` already answered a lost commit with `ImportOutcomeUnknown` (Q242, tests/test_a_commit_that_raised_is_not_a_rollback.py). Its commit moved
    out of the `try` whose handlers roll back; what it does is unchanged."""

    def test_its_connection_is_still_closed_after_a_lost_commit(self, db, monkeypatch):
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts")
        db.commit()
        real = dbexport._direct_kea_conn

        def opened():
            conn = real()
            conn.__class__ = Counted
            return conn

        Counted.closed = 0
        monkeypatch.setattr(dbexport, "_direct_kea_conn", opened)
        row = {
            "host_id": 1,
            "dhcp_identifier": {"$bin": "02cc00000252"},
            "dhcp_identifier_type": 0,
            "dhcp4_subnet_id": 1,
            "dhcp6_subnet_id": None,
            "ipv4_address": None,
            "hostname": "q252-from-file",
        }
        meta = {"database": "kea", "jen_export_version": 1, "format": 3, "tables": ["hosts"]}
        blob = json.dumps({"_meta": meta, "data": {"hosts": [row]}}).encode("utf-8")
        try:
            with pytest.raises(dbexport.ImportOutcomeUnknown) as e:
                dbexport.import_kea(blob, "skip")
            assert e.value.public == f"Kea import: {dbexport.COMMIT_NOT_CONFIRMED}."
            assert Counted.closed == 1, "the `finally` ran"
        finally:
            db.commit()
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts")
            db.commit()

    def test_no_flag_is_left_in_it(self):
        source = (ROOT / "jen/services/dbexport.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "import_kea")
        text = ast.get_source_segment(source, fn)
        assert "committing" not in text and text.count("conn.commit()") == 1


# ══ Row 1: the page and the audit row of a migration that failed ═════════════════════════════════════════════════════════════════════════════════════


def _last_audit_id(db):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) AS n FROM audit_log")
        return cur.fetchone()["n"]


def _migrate_rows(db, since, wait_for=0):
    """The DB_MIGRATE% rows written after `since`. A run that worked writes its row after the stream's last event, so that one is waited for."""
    deadline = time.monotonic() + 10
    while True:
        db.commit()
        with db.cursor() as cur:
            cur.execute(
                "SELECT action, entity, details FROM audit_log WHERE id > %s AND action LIKE 'DB_MIGRATE%%' ORDER BY id",
                (since,),
            )
            rows = cur.fetchall()
        if len(rows) >= wait_for or time.monotonic() > deadline:
            return rows
        time.sleep(0.1)


def _run(client, which, **more):
    """The page's own request, to the real route: the worker thread, the real migration, the real stream."""
    data = {
        "which": which,
        "host": TEST_DB["host"],
        "port": str(PORT),
        "user": TEST_DB["user"],
        "password": TEST_DB["password"],
        "database": SCRATCH,
        **more,
    }
    return client.post("/database/migrate/run", data=data).data.decode("utf-8")


def _error_of(stream):
    found = re.findall(r"event: error\ndata: (.*)\n\n", stream)
    assert len(found) == 1, stream
    return found[0]


WHERE = f"target={TEST_DB['host']}/{SCRATCH} tables=all"


class TestAMigrationThatFailedLeavesARowAndItsOwnSentence:
    """v7.2.0: every failure reached the page as "failed: see the Jen log" and no audit row was written for a migration that failed."""

    def test_a_refusal(self, logged_in_client, db, target, kea_source):
        since = _last_audit_id(db)
        said = _error_of(_run(logged_in_client, "kea"))
        assert said.startswith(f"The target ({SCRATCH}) is not an initialized Kea database") and said.endswith(
            "Nothing was changed."
        )
        assert _migrate_rows(db, since) == [
            {"action": "DB_MIGRATE_FAILED", "entity": "kea", "details": f"{WHERE}; refused"}
        ]

    def test_nothing_ticked_is_a_refusal_too(self, logged_in_client, db, target):
        since = _last_audit_id(db)
        said = _error_of(_run(logged_in_client, "jen"))
        assert said.startswith("No table was selected")
        assert _migrate_rows(db, since) == [
            {"action": "DB_MIGRATE_FAILED", "entity": "jen", "details": f"{WHERE}; refused"}
        ]

    def test_a_commit_that_was_not_confirmed(self, logged_in_client, db, target, kea_source, monkeypatch):
        M.initialize_kea_target(db, SCRATCH).close()
        _lose(monkeypatch)
        since = _last_audit_id(db)
        said = _error_of(_run(logged_in_client, "kea"))
        assert said == f"Kea migration: {NOT_KNOWN}"
        assert _migrate_rows(db, since) == [
            {
                "action": "DB_MIGRATE_FAILED",
                "entity": "kea",
                "details": f"{WHERE}; the commit was not confirmed; the outcome is not known",
            }
        ]
        assert len(_on_target("hosts")) == 3

    def test_any_other_failure_keeps_the_drivers_text_off_the_page_and_out_of_the_row(
        self, logged_in_client, db, target, kea_source
    ):
        tgt = M.initialize_kea_target(db, SCRATCH)
        M.add_host(tgt, 12, bytes.fromhex("02bb00000012"), "q252-the-target-owns-id-12")
        tgt.close()
        since = _last_audit_id(db)
        stream = _run(logged_in_client, "kea")
        assert _error_of(stream) == "failed: see the Jen log"
        assert "Duplicate" not in stream and "1062" not in stream
        rows = _migrate_rows(db, since)
        assert rows == [{"action": "DB_MIGRATE_FAILED", "entity": "kea", "details": f"{WHERE}; failed"}]

    def test_a_migration_that_worked_is_db_migrate_and_nothing_else(self, logged_in_client, db, target, kea_source):
        M.initialize_kea_target(db, SCRATCH).close()
        since = _last_audit_id(db)
        stream = _run(logged_in_client, "kea")
        assert "event: done" in stream and "event: error" not in stream
        assert _migrate_rows(db, since, wait_for=1) == [{"action": "DB_MIGRATE", "entity": "kea", "details": WHERE}]

    def test_the_page_claims_no_undo_for_a_run_that_ended_in_an_error(self, logged_in_client):
        page = logged_in_client.get("/settings/databases/migrate").data.decode("utf-8")
        assert "nothing was changed on the target" not in page and "what the run wrote was removed" not in page
        assert "Migration did not complete." in page

    def test_the_audit_row_never_holds_the_exceptions_text(self):
        source = (ROOT / "jen/routes/database.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "migrate_run")
        failed = [
            c
            for c in ast.walk(fn)
            if isinstance(c, ast.Call)
            and getattr(c.func, "attr", "") == "audit"
            and isinstance(c.args[0], ast.Constant)
            and c.args[0].value == "DB_MIGRATE_FAILED"
        ]
        assert len(failed) == 1
        names = {n.id for n in ast.walk(failed[0].args[2]) if isinstance(n, ast.Name)}
        assert names == {"host", "db", "tables", "how"}, names


# ══ Row 2: one status for the result of an import ════════════════════════════════════════════════════════════════════════════════════════════════════

#: the marks as they are written, not read from the module: `test_the_mark_is_the_one_the_module_writes` holds the two together
OK, WARN, ERR = "✅", "⚠️", "❌"


class TestImportStatus:
    def test_every_line_ok(self):
        assert (
            dbexport.import_status([f"{OK} settings: 3 rows restored", "ℹ️ hosts: no rows in export — skipped"]) == "ok"
        )

    def test_nothing_at_all_is_ok(self):
        assert dbexport.import_status([]) == "ok" and dbexport.import_status(None) == "ok"

    def test_a_warning_is_not_a_failure(self):
        assert (
            dbexport.import_status([f"{OK} a: 1 rows added", f"{WARN} wol: plugin code is not installed here"]) == "ok"
        )

    def test_a_part_that_failed(self):
        lines = [f"{OK} a: 1 rows added", f"{ERR} wol: migration replay failed (x) — its tables/data may be incomplete"]
        assert dbexport.import_status(lines) == "partial"

    def test_rows_that_were_rolled_back_are_a_part_that_failed(self):
        assert dbexport.import_status([f"{ERR} wol.wol_hosts: row import failed and was rolled back (x)"]) == "partial"

    def test_a_commit_that_was_not_confirmed(self):
        assert dbexport.import_status([f"{ERR} wol: {dbexport.COMMIT_NOT_CONFIRMED}"]) == "unknown"

    def test_not_known_is_said_before_a_part_that_failed(self):
        lines = [
            f"{ERR} ipam: migration replay failed (x)",
            f"{ERR} wol: {dbexport.COMMIT_NOT_CONFIRMED}",
            f"{OK} a: 1",
        ]
        assert dbexport.import_status(lines) == "unknown"

    def test_the_mark_counts_only_where_a_line_starts(self):
        assert dbexport.import_status([f"{OK} notes: 1 rows added (one of them says {ERR})"]) == "ok"

    def test_the_mark_is_the_one_the_module_writes(self):
        assert dbexport.ERR_MARK == "❌" and len(dbexport.ERR_MARK) == 1
        source = (ROOT / "jen/services/dbexport.py").read_text(encoding="utf-8")
        assert 'f"❌' not in source, "no line is written with a mark of its own"
        assert source.count('results.append(f"{ERR_MARK} ') == 3, (
            "the three lines `import_jen` writes for a part that failed"
        )

    def test_the_page_has_no_mark_of_its_own(self):
        assert not hasattr(database_routes, "_ERR_MARK")
        source = (ROOT / "jen/routes/database.py").read_text(encoding="utf-8")
        assert "0x274C" not in source and "\\u274c" not in source.lower() and "❌" not in source
        assert source.count("dbexport.ERR_MARK") == 3, (
            "the audit row's count, the color of the line and the glyphs a line is shown without"
        )


def _functions_that_audit(action):
    """[(file, function, does it call import_status)] for every call `audit("<action>", ...)` under `jen/` and `plugins/`."""
    out = []
    for top in ("jen", "plugins"):
        for path in sorted((ROOT / top).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)]
                audits = [
                    c
                    for c in calls
                    if (getattr(c.func, "attr", "") or getattr(c.func, "id", "")).endswith("audit")
                    and c.args
                    and isinstance(c.args[0], ast.Constant)
                    and c.args[0].value == action
                ]
                if audits:
                    asks = any(getattr(c.func, "attr", "") == "import_status" for c in calls)
                    out.append((path.relative_to(ROOT).as_posix(), fn.name, asks))
    return out


class TestWhoeverRecordsAnImportThatWorkedAsksFirst:
    def test_over_the_whole_tree(self):
        sites = _functions_that_audit("DB_IMPORT")
        assert sites, "the sweep found the row it was written for"
        assert [s for s in sites if not s[2]] == []
        assert sites == [("jen/routes/database.py", "import_confirm", True)]

    def test_the_literal_is_written_nowhere_else(self):
        """A row written through a name the sweep above does not know (a wrapper, a SQL insert) would carry the literal."""
        holders = []
        for top in ("jen", "plugins"):
            for path in sorted((ROOT / top).rglob("*.py")):
                if re.search(r"""["']DB_IMPORT["']""", path.read_text(encoding="utf-8")):
                    holders.append(path.relative_to(ROOT).as_posix())
        assert holders == ["jen/routes/database.py"]


#: every bundled plugin installed with a row in each table, exported, its tables dropped; the yield is the file, and what was found is put back afterward
world = P.world


def _staged(file_bytes):
    os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, suffix=".jen-import")
    with os.fdopen(fd, "wb") as f:
        f.write(file_bytes)
    return base64.b64encode(path.encode()).decode()


def _import_rows(db, since):
    db.commit()
    with db.cursor() as cur:
        cur.execute(
            "SELECT action, entity, details FROM audit_log WHERE id > %s AND action LIKE 'DB_IMPORT%%' ORDER BY id",
            (since,),
        )
        return cur.fetchall()


def _red_lines(page):
    return re.findall(
        r'<div class="alert alert-error alert-flash" role="alert">.*?<span class="alert-text">(.*?)</span>', page
    )


class TestTheAuditRowOfAnImportSaysWhatThePageSays:
    """The real route and the real `import_jen`, in merge mode (replace mode puts a snapshot back on any failure and has its own row)."""

    def _confirm(self, client, blob):
        tables = list(json.loads(gzip.decompress(blob))["data"])
        r = client.post(
            "/database/import/confirm",
            data={"tmp_path": _staged(blob), "mode": "merge", "tables": tables},
            follow_redirects=True,
        )
        return r.data.decode("utf-8")

    def test_a_plugin_whose_migration_replay_failed(self, logged_in_client, db, world, monkeypatch):
        """In the test's hands: the manifest `wol` is read from carries a statement the database refuses. The runner and the database are the real ones.
        v7.2.0 writes `DB_IMPORT` here."""
        real = plugins_svc._manifest_for_owned_tables

        def manifest(plugin_id):
            found = real(plugin_id)
            if plugin_id != "wol" or found is None:
                return found
            broken = [
                {
                    "version": m["version"] if isinstance(m, dict) else at,
                    "description": "",
                    "sql": "CREATE TABLE `wol_hosts` (",
                }
                for at, m in enumerate(found.get("db_migrations", []), 1)
            ]
            return dict(found, db_migrations=broken)

        monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", manifest)
        since = _last_audit_id(db)
        page = self._confirm(logged_in_client, world)
        rows = _import_rows(db, since)
        assert len(rows) == 1 and (rows[0]["action"], rows[0]["entity"]) == ("DB_IMPORT_FAILED", "jen"), rows
        details = rows[0]["details"]
        assert details.startswith("tables=[") and details.endswith(
            " mode=merge; 1 part failed and the rest was imported"
        )
        assert "replay" not in details and "wol:" not in details and "SQL" not in details, (
            "no line's text is in the row"
        )
        red = _red_lines(page)
        assert len(red) == 1 and red[0].startswith("wol: migration replay failed ("), red
        restored = P._rows(db)
        assert restored.pop("wol") == "absent"
        assert restored == {pid: n for pid, n in P.EVERY_ROW.items() if pid != "wol"}, "the rest was imported"

    def test_a_plugin_whose_rows_were_rolled_back(self, logged_in_client, db, world, monkeypatch):
        """In the test's hands: the decoding of one table's rows raises, as the tests of that line do it (tests/test_plugin_restore_lifecycle.py)."""
        real = dbexport._decode_import_rows

        def boom(table, *a, **k):
            if table == "wol_hosts":
                raise dbexport.BinaryValueError("wol_hosts.mac (row 1): simulated")
            return real(table, *a, **k)

        monkeypatch.setattr(dbexport, "_decode_import_rows", boom)
        since = _last_audit_id(db)
        page = self._confirm(logged_in_client, world)
        rows = _import_rows(db, since)
        assert [(r["action"], r["entity"]) for r in rows] == [("DB_IMPORT_FAILED", "jen")]
        assert rows[0]["details"].endswith(" mode=merge; 1 part failed and the rest was imported")
        assert "simulated" not in rows[0]["details"]
        assert len(_red_lines(page)) == 1 and "wol.wol_hosts: row import failed and was rolled back" in page

    def test_an_import_that_worked(self, logged_in_client, db, world):
        since = _last_audit_id(db)
        page = self._confirm(logged_in_client, world)
        rows = _import_rows(db, since)
        assert [(r["action"], r["entity"]) for r in rows] == [("DB_IMPORT", "jen")]
        assert rows[0]["details"].startswith("tables=[") and rows[0]["details"].endswith(" mode=merge")
        assert _red_lines(page) == [] and P._rows(db) == P.EVERY_ROW

    def test_a_lost_plugin_commit_keeps_the_row_it_had(self, logged_in_client, db, world):
        P.LostAt.lose = P.COMMIT_OF[P.ORDER[-1]]
        since = _last_audit_id(db)
        self._confirm(logged_in_client, world)
        rows = _import_rows(db, since)
        assert [(r["action"], r["entity"]) for r in rows] == [("DB_IMPORT_FAILED", "jen")]
        assert rows[0]["details"].endswith(" mode=merge; a plugin's commit was not confirmed; the outcome is not known")


# ══ Row 2, the put-back: an import that puts a snapshot back is an import too ═════════════════════════════════════════════════════════════════════════


def _wol_cannot_migrate(monkeypatch):
    """In the test's hands: the manifest `wol` is read from. Its statements are the plugin's own with words after them that the database refuses, so the
    plugin still owns its tables and its migrations fail every time they are replayed. The runner and the database are the real ones."""
    real = plugins_svc._manifest_for_owned_tables

    def manifest(plugin_id):
        found = real(plugin_id)
        if plugin_id != "wol" or found is None:
            return found
        broken = [
            {
                "version": m["version"] if isinstance(m, dict) else at,
                "description": "",
                "sql": (m["sql"] if isinstance(m, dict) else m).rstrip().rstrip(";") + " THIS IS NOT SQL",
            }
            for at, m in enumerate(found.get("db_migrations", []), 1)
        ]
        return dict(found, db_migrations=broken)

    monkeypatch.setattr(plugins_svc, "_manifest_for_owned_tables", manifest)


def _wol_rows_cannot_be_read(monkeypatch):
    """In the test's hands: the decoding of `wol_hosts` rows raises (as tests/test_plugin_restore_lifecycle.py does it). The file carries such rows and the
    snapshot of a database without the plugins' tables carries none, so the import fails and the put-back meets nothing that fails."""
    real = dbexport._decode_import_rows

    def boom(table, *a, **k):
        if table == "wol_hosts":
            raise dbexport.BinaryValueError("wol_hosts.mac (row 1): simulated")
        return real(table, *a, **k)

    monkeypatch.setattr(dbexport, "_decode_import_rows", boom)


PUT_BACK_EXACTLY = "The import failed and was rolled back: the database was put back exactly as it was before. See the server log for the cause."


class TestAPutBackThatFailedInPartIsNotCalledExact:
    """`import_jen_guarded` (the Databases page's replace mode) puts its snapshot back with a lenient `import_jen` and dropped the lines it returned.
    v7.2.0 says "put back exactly as it was before" when a plugin's migrations could not be replayed during the put-back."""

    @pytest.fixture(autouse=True)
    def _private_backups(self, monkeypatch, tmp_path):
        self.backups = tmp_path / "backups"
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(self.backups))

    def test_a_plugin_that_could_not_be_replayed_during_the_put_back(self, db, world, monkeypatch):
        _wol_cannot_migrate(monkeypatch)
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(world)
        assert e.value.state == "rollback_failed", e.value.public
        assert "put back exactly" not in e.value.public and "was rolled back" not in e.value.public
        assert e.value.public.startswith("The import failed, and putting the database back did not complete.")
        assert e.value.snapshot and os.path.isfile(os.path.join(e.value.snapshot, "jen_db.json.gz")), (
            "the snapshot is kept"
        )
        cause = str(e.value.__cause__)
        assert cause.startswith("the snapshot was put back only in part: wol: migration replay failed ("), cause
        assert dbexport.ERR_MARK not in cause

    def test_the_page_and_the_audit_row(self, logged_in_client, db, world, monkeypatch):
        _wol_cannot_migrate(monkeypatch)
        tables = list(json.loads(gzip.decompress(world))["data"])
        since = _last_audit_id(db)
        page = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": _staged(world), "mode": "replace", "tables": tables},
            follow_redirects=True,
        ).data.decode("utf-8")
        assert _import_rows(db, since) == [
            {"action": "DB_IMPORT_FAILED", "entity": "jen", "details": "state=rollback_failed"}
        ]
        assert "putting the database back did not complete" in page and "put back exactly" not in page
        assert "THIS IS NOT SQL" not in page and "1064" not in page, (
            "the lines of the put-back are in the log, not on the page"
        )

    def test_a_clean_put_back_says_what_it_said(self, db, world, monkeypatch):
        _wol_rows_cannot_be_read(monkeypatch)
        with pytest.raises(dbexport.GuardedImportError) as e:
            dbexport.import_jen_guarded(world)
        assert e.value.state == "rolled_back" and e.value.public == PUT_BACK_EXACTLY
        assert not self.backups.exists() or list(self.backups.iterdir()) == [], "and its snapshot is gone"

    def test_each_line_of_the_sentence_is_cut(self, db, monkeypatch):
        """The sentence goes to the log. A line is the plugin's name and the database's own message: cut, so one long message is not the whole log.
        In the test's hands: the lines the put-back's import returns (the real one is in the first test). The snapshot and the rest of the put-back
        are real, and put back what is there."""
        snap = dbexport.take_pre_import_snapshot()
        long = f"{dbexport.ERR_MARK} wol: migration replay failed (" + "y" * 500 + ")"
        monkeypatch.setattr(
            dbexport, "import_jen", lambda *a, **k: ["✅ settings: 1 rows restored", long, f"{dbexport.ERR_MARK} b: c"]
        )
        with pytest.raises(RuntimeError) as e:
            dbexport._roll_back_to(snap)
        first = "wol: migration replay failed (" + "y" * 170
        assert str(e.value) == f"the snapshot was put back only in part: {first}; b: c"
        assert len(first) == 200


class TestTheRestoreToolsPutBack:
    """`jen/tools/restore.py::rollback_snapshot` (a failed restore's rollback, and `install.sh --rollback`) imports the snapshot's database with the lenient
    `import_jen` and dropped its lines: v7.2.0 prints "rolled back — Jen is as it was before the restore" and exits 1 (or "rolled back from" and 0)."""

    @pytest.fixture
    def snap(self, world, tmp_path):
        """A real pre-restore snapshot of this database (the plugins' tables are not there), a config dir with no jen.config in it and a content dir."""
        from jen.tools import restore

        self.etc, self.content = tmp_path / "etc_jen", tmp_path / "content"
        (self.etc / "ssl").mkdir(parents=True)
        (self.content / "icons").mkdir(parents=True)
        return restore.take_snapshot(self.etc, self.content)

    def test_a_failed_restores_rollback_that_came_back_in_part(self, db, snap, monkeypatch, capsys):
        from jen.tools import restore

        _wol_cannot_migrate(monkeypatch)
        code = restore._fail_with_rollback(snap, self.etc, self.content, "apply failed: x", manage=False, restart=False)
        out = capsys.readouterr()
        assert code == 2, "the exit of a rollback that failed"
        assert "as it was before the restore" not in out.err + out.out and "rolled back —" not in out.err + out.out
        assert f"ROLLBACK FAILED: the database was put back only in part. The snapshot is kept at {snap}" in out.err
        assert f"{dbexport.ERR_MARK} wol: migration replay failed (" in out.err
        assert f"The snapshot is intact at {snap}." in out.err and (snap / "jen_db.json.gz").is_file()

    def test_a_rollback_by_hand_that_came_back_in_part(self, db, snap, monkeypatch, capsys):
        from jen.tools import restore

        _wol_cannot_migrate(monkeypatch)
        code = restore.run_rollback(str(snap), etc_jen=str(self.etc), content_dir=str(self.content), no_stop=True)
        out = capsys.readouterr()
        assert code == 2
        assert "rolled back from" not in out.out
        assert f"ROLLBACK FAILED: the database was put back only in part. The snapshot is kept at {snap}" in out.err

    def test_a_clean_rollback_says_what_it_said(self, db, snap, capsys):
        from jen.tools import restore

        code = restore._fail_with_rollback(snap, self.etc, self.content, "apply failed: x", manage=False, restart=False)
        out = capsys.readouterr()
        assert code == 1
        assert f"rolled back — Jen is as it was before the restore. Snapshot kept at {snap}" in out.err
        assert "ROLLBACK FAILED" not in out.err

    def test_a_clean_rollback_by_hand_says_what_it_said(self, db, snap, capsys):
        from jen.tools import restore

        code = restore.run_rollback(str(snap), etc_jen=str(self.etc), content_dir=str(self.content), no_stop=True)
        out = capsys.readouterr()
        assert code == 0 and f"rolled back from {snap}" in out.out and "ROLLBACK FAILED" not in out.err

    def test_the_tool_imports_nothing_new_when_it_is_loaded(self):
        """`python3 -m jen.tools.restore` loads this module before anything of Jen's: what it needs of `dbexport` it imports inside the function."""
        tree = ast.parse((ROOT / "jen/tools/restore.py").read_text(encoding="utf-8"))
        top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        assert not [n for n in top if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("jen")]
        assert not [
            a for n in top if isinstance(n, ast.Import) for a in n.names if a.name.startswith(("jen", "pymysql"))
        ]


def _calls_of_import_jen():
    """{(file, function): the cases that hold} for every call of `import_jen` under `jen/` (its tools among them) and `plugins/`: "status" when the
    function also calls `import_status`, "returns" when the call's lines are returned to the caller, "strict" when it is `strict=True` and not
    `strict_plugins=False` (every failure then raises and there is no line to read)."""
    out = {}
    for top in ("jen", "plugins"):
        for path in sorted((ROOT / top).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                inner = {n for d in ast.walk(fn) if d is not fn and isinstance(d, ast.FunctionDef) for n in ast.walk(d)}
                nodes = [n for n in ast.walk(fn) if n not in inner]
                calls = [
                    n
                    for n in nodes
                    if isinstance(n, ast.Call)
                    and (getattr(n.func, "attr", "") or getattr(n.func, "id", "")) == "import_jen"
                ]
                for call in calls:
                    cases = set()
                    if any(
                        isinstance(n, ast.Call)
                        and getattr(n.func, "attr", getattr(n.func, "id", "")) == "import_status"
                        for n in nodes
                    ):
                        cases.add("status")
                    returned = {n.value for n in nodes if isinstance(n, ast.Return) and n.value is not None}
                    names = {r.id for r in returned if isinstance(r, ast.Name)}
                    assigned = {
                        t.id
                        for n in nodes
                        if isinstance(n, ast.Assign) and n.value is call
                        for t in n.targets
                        if isinstance(t, ast.Name)
                    }
                    if call in returned or assigned & names:
                        cases.add("returns")
                    kw = {k.arg: k.value for k in call.keywords}
                    strict = isinstance(kw.get("strict"), ast.Constant) and kw["strict"].value is True
                    lenient = isinstance(kw.get("strict_plugins"), ast.Constant) and kw["strict_plugins"].value is False
                    if strict and not lenient:
                        cases.add("strict")
                    out.setdefault((path.relative_to(ROOT).as_posix(), fn.name), set()).update(cases or {"NONE"})
    return out


class TestEveryCallOfTheImportIsAnswered:
    def test_over_the_whole_tree(self):
        assert _calls_of_import_jen() == {
            ("jen/routes/database.py", "import_confirm"): {"status"},
            ("jen/services/dbexport.py", "_roll_back_to"): {"status"},
            ("jen/services/dbexport.py", "import_jen_guarded"): {"returns", "strict"},
            ("jen/tools/restore.py", "restore_jen_db"): {"returns", "strict"},
            ("jen/tools/restore.py", "_import_db"): {"returns"},
        }

    def test_the_one_caller_of_the_lenient_wrapper_asks(self):
        """`restore._import_db` hands its lines on. Its caller is the put-back, and it asks."""
        tree = ast.parse((ROOT / "jen/tools/restore.py").read_text(encoding="utf-8"))
        callers = [
            fn.name
            for fn in ast.walk(tree)
            if isinstance(fn, ast.FunctionDef)
            and any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_import_db" for n in ast.walk(fn))
        ]
        assert callers == ["rollback_snapshot"]
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "rollback_snapshot")
        assert any(isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "import_status" for n in ast.walk(fn))


# ══ Row 3: every string of the support bundle goes through one mask ══════════════════════════════════════════════════════════════════════════════════

SENTINELS = ("PWSENTINEL", "QSENTINEL", "SSENTINEL", "FSENTINEL")
SENTENCE = "see https://u:PWSENTINEL@h.example:8004/x?token=QSENTINEL&sig=SSENTINEL#FSENTINEL now"
KEPT = "h.example:8004/x"
NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


def _three():
    """The sentence under a key that is not an address key: once as a value, once inside a list, once as a dict KEY."""
    return {"remark": SENTENCE, "remarks": ["first", SENTENCE], SENTENCE: "a key"}


def _collected(**overrides):
    """Every section `build_bundle` reads from `collected`, each holding the sentence three ways (the INI and the two texts hold it as a value: a line of
    an INI file or of a log has no list and no key that could be a sentence)."""
    base = {
        "notes": [f"health: TimeoutError: {SENTENCE}"],
        "jen": {"version": "7.2.1", "channel": "stable", "hostname": "jen-box", **_three()},
        "config_text": f"[server]\nhttp_port = 5050\nmotd = {SENTENCE}\n",
        "servers": [{"id": 1, "name": "Primary", "api_url": "http://10.0.0.5:8000", **_three()}],
        "health": {
            "summary": {"ok": 1, **_three()},
            "checks": [{"id": "kea_reachable", "status": "fail", "detail": SENTENCE}],
        },
        "drift": [_three()],
        "kea_configs": [
            {
                "server_id": 1,
                "server": "Primary",
                "service": "dhcp4",
                "revision_id": 7,
                "summary": SENTENCE,
                "config": {
                    "Dhcp4": {
                        "comment": SENTENCE,
                        "user-context": {"comment": SENTENCE, **_three()},
                        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "user-context": {"note": SENTENCE}}],
                    }
                },
            }
        ],
        "plugins": [{"id": "ipam", "version": "1.8.4", **_three()}],
        "db": {"schema_latest": 40, **_three()},
        "audit": [{"id": 1, "action": "EDIT_DEVICE", "details": SENTENCE, **_three()}],
        "alerts": [{"id": 1, "channel_type": "webhook", "status": "failed", "error": SENTENCE, **_three()}],
        "lease_history": [{"subnet_id": 1, "name": SENTENCE, **_three()}],
        "log_text": f"2026-11-25T11:59:01Z ERROR jen: {SENTENCE}\n2026-11-25T11:59:02Z INFO jen: a plain line\n",
    }
    base.update(overrides)
    return base


def _members(collected):
    data, names = sb.build_bundle(collected, now=NOW)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return data, {n: zf.read(n).decode("utf-8") for n in zf.namelist()}, names


def _strings(node):
    """Every string of a parsed JSON member: the values and the keys."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


JSON_MEMBERS = (
    "jen.json",
    "servers.json",
    "health.json",
    "drift.json",
    "kea/1-dhcp4.json",
    "plugins.json",
    "db.json",
    "audit-tail.json",
    "alerts-tail.json",
    "lease-history-7d.json",
)
TEXT_MEMBERS = ("config.ini.redacted", "logs/jen.log.tail", "README.txt")


class TestNoAddressInASentenceKeepsItsQuery:
    """v7.2.0 finds QSENTINEL, SSENTINEL and FSENTINEL: a string under a key that does not end in `url` went through `scrub_urls`, which removes a
    user name and a password and nothing else."""

    def test_no_sentinel_is_anywhere_in_the_archive(self):
        data, members, names = _members(_collected())
        assert set(JSON_MEMBERS) | set(TEXT_MEMBERS) == set(names), names
        for word in SENTINELS:
            assert word.encode() not in data, f"{word} in the archive's bytes"
            for name, text in members.items():
                assert word not in text, f"{word} in {name}"
                assert word not in name

    def test_the_host_and_the_names_are_kept_in_every_member(self):
        _data, members, _names = _members(_collected())
        for name in JSON_MEMBERS + TEXT_MEMBERS:
            assert KEPT in members[name], f"the sentence did not reach {name}: the seeding is wrong"
            assert "token=" in members[name], name

    def test_the_sentence_is_there_three_ways_and_keeps_the_word_after_its_address(self):
        """As a value, in a list and as a key, in each JSON member; and the mask stops at the white space."""
        _data, members, _names = _members(_collected())
        for name in JSON_MEMBERS:
            carrying = [s for s in _strings(json.loads(members[name])) if KEPT in s]
            assert len(carrying) >= 3, (name, carrying)
            for s in carrying:
                assert s.startswith("see https://h.example:8004/x?token=") and s.endswith(" now"), (name, s)
                assert "sig=" in s, (name, s)

    def test_a_dict_key_that_is_a_sentence_is_masked_as_a_key(self):
        _data, members, _names = _members(_collected())
        keys = [k for k in json.loads(members["db.json"]) if KEPT in k]
        assert keys == ["see https://h.example:8004/x?token=********&sig=********#******** now"]

    def test_the_log_note_of_a_box_that_logs_to_the_journal(self):
        data, members, names = _members(_collected(log_text=None, log_note=f"{SENTENCE}\n"))
        assert "logs/README.txt" in names and "logs/jen.log.tail" not in names
        assert KEPT in members["logs/README.txt"] and "token=" in members["logs/README.txt"]
        for word in SENTINELS:
            assert word.encode() not in data and all(word not in text for text in members.values())

    def test_every_json_member_still_parses(self):
        _data, members, names = _members(_collected())
        parsed = [n for n in names if n.endswith(".json")]
        assert sorted(parsed) == sorted(JSON_MEMBERS)
        for name in parsed:
            json.loads(members[name])

    def test_an_object_the_encoder_prints_is_masked_too(self):
        out = json.loads(sb._json({"when": ValueError(SENTENCE)}))
        assert (
            all(word not in out["when"] for word in SENTINELS) and KEPT in out["when"] and out["when"].endswith(" now")
        )

    def test_a_log_line(self):
        line = sb.scrub_log_line(f"ERROR jen: {SENTENCE}")
        assert all(word not in line for word in SENTINELS) and KEPT in line and line.endswith(" now")
        # the patterns after it mask what follows `token=`, a name they know; a value under a name nobody listed is this mask's alone
        line = sb.scrub_log_line(
            "ERROR jen: GET https://h.example:8004/x?page=QSENTINEL&sig=SSENTINEL#FSENTINEL refused"
        )
        assert line == "ERROR jen: GET https://h.example:8004/x?page=********&sig=********#******** refused"

    def test_a_free_text_value_of_the_config(self):
        """`redact_ini_text` already did this before Q252 (`without_credentials` since Q244); pinned here beside the members that did not."""
        out = sb.redact_ini_text(f"[server]\nmotd = {SENTENCE}\n")
        assert "motd = see https://h.example:8004/x?token=********&sig=********#******** now" in out

    def test_the_readme_says_what_is_not_there(self):
        text = sb.readme_text("7.2.1", "stable", "jen", "now", [])
        assert "a user name or password inside an address (an address is host and port)," in text
        assert "the value of a query parameter and the fragment of an address," in text


class TestOneMaskForEveryString:
    def _tree(self):
        return ast.parse((ROOT / "jen/services/support_bundle.py").read_text(encoding="utf-8"))

    def test_the_narrow_reader_is_used_once_and_only_over_a_serialized_member(self):
        """`scrub_urls` removes a user name and a password only. Its one use is `put`, the pass over a member's whole serialized text, where the wide
        reader would take a JSON string's closing quote with the address."""
        tree = self._tree()
        loads = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Name) and n.id == "scrub_urls" and isinstance(n.ctx, ast.Load)
        ]
        assert len(loads) == 1
        put = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "put"]
        assert len(put) == 1
        assert [n for n in ast.walk(put[0]) if n is loads[0]], "and that use is inside `put`"

    def test_no_earlier_reader_is_named_at_all(self):
        tree = self._tree()
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
        }
        assert "without_userinfo" not in names and "_address_key" not in names

    def test_the_wide_reader_over_a_serialized_document_is_why(self):
        """What `put` would do with the wide reader: the address runs to the next white space, and in a JSON document that is past the closing quote."""
        from jen.services.secret_keys import scrub_urls, without_credentials

        document = json.dumps({"a": "https://h.example/x?token=QSENTINEL", "b": 1})
        with pytest.raises(ValueError):
            json.loads(without_credentials(document))
        assert json.loads(scrub_urls(document)) == json.loads(document)
