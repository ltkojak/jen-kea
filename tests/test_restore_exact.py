"""
tests/test_restore_exact.py
───────────────────────────
v5.67.0-beta.14 (Q128, items a and e) — a restore says "restored" only when it is. Against the real
MariaDB: replace mode is a PLAIN INSERT (an error is an error, never a coerced value counted as restored),
the reported count is the server's and must be the file's, `strict` turns every case a restore cannot be
exact about into a failure, merge mode reports what it really did, and a scoped restore of a parent table
refuses to leave its dependents orphaned.

The tables restored here are two scratch tables registered as Jen tables for the test (a restore into the
session database's real `settings` or `users` would wipe the rows every other test relies on).
"""

import base64
import gzip
import json
import os

import pymysql.cursors
import pytest

from jen import extensions
from jen.services import dbexport

A, B = "zz_q128_a", "zz_q128_b"


@pytest.fixture
def scratch(db, monkeypatch):
    """Two real tables the import will accept as Jen tables: A has a NOT NULL column and a primary key."""
    monkeypatch.setitem(dbexport.JEN_TABLES, A, "scratch a")
    monkeypatch.setitem(dbexport.JEN_TABLES, B, "scratch b")
    with db.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS `{A}`")
        cur.execute(f"DROP TABLE IF EXISTS `{B}`")
        cur.execute(f"CREATE TABLE `{A}` (id INT PRIMARY KEY, label VARCHAR(20) NOT NULL, note VARCHAR(10) NULL)")
        cur.execute(f"CREATE TABLE `{B}` (id INT PRIMARY KEY, label VARCHAR(20) NOT NULL)")
        cur.execute(f"INSERT INTO `{A}` (id, label) VALUES (1, 'kept-1'), (2, 'kept-2')")
        cur.execute(f"INSERT INTO `{B}` (id, label) VALUES (7, 'b-kept')")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS `{A}`")
        cur.execute(f"DROP TABLE IF EXISTS `{B}`")
    db.commit()


def _file(data, fmt=3):
    payload = {
        "data": data,
        "_meta": {"database": "jen", "jen_export_version": 1, "format": fmt, "tables": list(data)},
    }
    return gzip.compress(json.dumps(payload).encode("utf-8"))


def _rows(db, table):
    db.commit()  # the import wrote through its own connection
    with db.cursor() as cur:
        cur.execute(f"SELECT * FROM `{table}` ORDER BY id")
        return list(cur.fetchall())


class TestReplaceModeIsExact:
    def test_a_clean_file_replaces_the_table_and_the_count_is_the_files(self, db, scratch):
        results = dbexport.import_jen(
            _file({A: [{"id": 10, "label": "new-10"}, {"id": 11, "label": "new-11", "note": "n"}]}),
            tables_to_restore=[A],
        )
        assert results == [f"✅ {A}: 2 rows restored"]
        assert [r["label"] for r in _rows(db, A)] == ["new-10", "new-11"]

    def test_a_null_in_a_not_null_column_fails_and_the_table_is_untouched(self, db, scratch):
        """INSERT IGNORE turned this into a warning, stored an empty string and counted the row restored."""
        with pytest.raises(RuntimeError, match="rolled back"):
            dbexport.import_jen(
                _file({A: [{"id": 10, "label": "fine"}, {"id": 11, "label": None}]}), tables_to_restore=[A]
            )
        assert [r["label"] for r in _rows(db, A)] == ["kept-1", "kept-2"]

    def test_a_key_twice_in_the_file_fails_instead_of_being_silently_dropped(self, db, scratch):
        with pytest.raises(RuntimeError, match="rolled back"):
            dbexport.import_jen(
                _file({A: [{"id": 5, "label": "first"}, {"id": 5, "label": "second"}]}), tables_to_restore=[A]
            )
        assert [r["id"] for r in _rows(db, A)] == [1, 2]

    def test_a_value_too_long_for_its_column_fails(self, db, scratch):
        with pytest.raises(RuntimeError, match="rolled back"):
            dbexport.import_jen(_file({A: [{"id": 5, "label": "x" * 200}]}), tables_to_restore=[A])
        assert [r["id"] for r in _rows(db, A)] == [1, 2]

    def test_one_bad_table_rolls_every_core_table_back(self, db, scratch):
        with pytest.raises(RuntimeError, match="rolled back"):
            dbexport.import_jen(
                _file({B: [{"id": 70, "label": "ok"}], A: [{"id": 5, "label": None}]}), tables_to_restore=[B, A]
            )
        assert [r["id"] for r in _rows(db, B)] == [7]

    def test_a_count_the_server_does_not_confirm_raises(self, db, scratch, monkeypatch):
        real = pymysql.cursors.Cursor.executemany

        def short(self, query, args):
            return (real(self, query, args) or 0) - 1

        with monkeypatch.context() as m:
            m.setattr(pymysql.cursors.Cursor, "executemany", short)
            with pytest.raises(RuntimeError, match="reports 1 inserted"):
                dbexport.import_jen(
                    _file({A: [{"id": 10, "label": "a"}, {"id": 11, "label": "b"}]}), tables_to_restore=[A]
                )
        assert [r["id"] for r in _rows(db, A)] == [1, 2]

    def test_a_table_with_no_rows_in_the_file_is_emptied(self, db, scratch):
        results = dbexport.import_jen(_file({A: []}), tables_to_restore=[A])
        assert results == [f"✅ {A}: 0 rows restored"]
        assert _rows(db, A) == []


class TestStrict:
    def test_a_table_missing_here_is_a_warning_normally_and_fatal_when_strict(self, db, scratch, monkeypatch):
        monkeypatch.setitem(dbexport.JEN_TABLES, "zz_q128_ghost", "no such table")
        blob = _file({"zz_q128_ghost": [{"id": 1}], A: [{"id": 10, "label": "a"}]})
        results = dbexport.import_jen(blob)
        assert any(r.startswith("⚠️ zz_q128_ghost: table does not exist") for r in results)
        with pytest.raises(RuntimeError, match="zz_q128_ghost: table does not exist"):
            dbexport.import_jen(blob, strict=True)
        # strict rolled the whole core transaction back — A is what the first (lenient) import left
        assert [r["id"] for r in _rows(db, A)] == [10]

    def test_no_recognised_column_leaves_the_table_alone_and_strict_fails(self, db, scratch):
        blob = _file({A: [{"nonsense": 1, "more_nonsense": 2}]})
        results = dbexport.import_jen(blob)
        assert any(r.startswith(f"⚠️ {A}: no recognized columns") and "left unchanged" in r for r in results)
        assert [r["id"] for r in _rows(db, A)] == [1, 2], "a restore that inserts nothing must not empty the table"
        with pytest.raises(RuntimeError, match="no recognized columns"):
            dbexport.import_jen(blob, strict=True)
        assert [r["id"] for r in _rows(db, A)] == [1, 2]

    def test_a_selected_table_the_file_does_not_carry_is_left_alone(self, db, scratch):
        blob = _file({B: [{"id": 70, "label": "b"}]})
        results = dbexport.import_jen(blob, tables_to_restore=[A])
        assert any(f"{A}: this file carries no rows for it" in r for r in results)
        assert [r["id"] for r in _rows(db, A)] == [1, 2]
        with pytest.raises(RuntimeError, match="carries no rows"):
            dbexport.import_jen(blob, tables_to_restore=[A], strict=True)

    def test_strict_covers_plugins_unless_told_otherwise(self):
        """strict_plugins defaults to `strict` itself; an explicit value (--lenient-plugins) wins."""
        import inspect

        sig = inspect.signature(dbexport.import_jen)
        assert sig.parameters["strict"].default is False
        assert sig.parameters["strict_plugins"].default is None
        assert "strict_plugins = strict" in inspect.getsource(dbexport.import_jen)

    def test_the_restore_tool_is_strict_about_core_tables_and_only_relaxes_plugins(self):
        import inspect

        from jen.tools import restore

        src = inspect.getsource(restore.restore_jen_db)
        assert "strict=True, strict_plugins=not lenient_plugins" in src

    def test_a_clean_full_strict_import_succeeds(self, db, scratch):
        results = dbexport.import_jen(_file({A: [{"id": 10, "label": "a"}], B: []}), strict=True)
        assert results == [f"✅ {A}: 1 rows restored", f"✅ {B}: 0 rows restored"]
        assert _rows(db, B) == []


class TestMergeModeReportsWhatItDid:
    def test_added_and_skipped_are_counted_from_the_server(self, db, scratch):
        results = dbexport.import_jen(
            _file({A: [{"id": 1, "label": "dupe"}, {"id": 30, "label": "new"}]}), tables_to_restore=[A], truncate=False
        )
        assert results == [
            f"⚠️ {A}: 1 added, 1 skipped (the same key was already there, or the database refused the row)"
        ]
        assert [(r["id"], r["label"]) for r in _rows(db, A)] == [(1, "kept-1"), (2, "kept-2"), (30, "new")]

    def test_nothing_skipped_is_a_plain_success_line(self, db, scratch):
        results = dbexport.import_jen(_file({A: [{"id": 30, "label": "new"}]}), tables_to_restore=[A], truncate=False)
        assert results == [f"✅ {A}: 1 rows added"]

    def test_a_skipped_row_is_fatal_when_strict_and_nothing_is_added(self, db, scratch):
        with pytest.raises(RuntimeError, match="1 skipped"):
            dbexport.import_jen(
                _file({A: [{"id": 1, "label": "dupe"}, {"id": 30, "label": "new"}]}),
                tables_to_restore=[A],
                truncate=False,
                strict=True,
            )
        assert [r["id"] for r in _rows(db, A)] == [1, 2]


class TestScopedRestoreOfAParent:
    def test_the_map_is_the_live_schemas_own_foreign_keys(self, db):
        """JEN_DEPENDENTS cannot drift from migration 23: every table with a foreign key to users is in it, and
        no foreign key points at a core table the map does not know about."""
        db.commit()
        with db.cursor() as cur:
            cur.execute(
                "SELECT table_name AS child, referenced_table_name AS parent FROM information_schema.key_column_usage "
                "WHERE table_schema = DATABASE() AND referenced_table_name IS NOT NULL"
            )
            fks = {(r["child"], r["parent"]) for r in cur.fetchall()}
        core = {(c, p) for c, p in fks if c in dbexport.JEN_TABLES and p in dbexport.JEN_TABLES}
        assert core == {(d, parent) for parent, deps in dbexport.JEN_DEPENDENTS.items() for d in deps}

    def test_missing_dependents_names_only_what_the_file_carries(self):
        full = {"users", "mfa_methods", "saved_searches", "api_keys"}
        assert dbexport._missing_dependents({"users"}, full) == {"users": ["mfa_methods", "saved_searches", "api_keys"]}
        assert dbexport._missing_dependents({"users", "mfa_methods", "saved_searches", "api_keys"}, full) == {}
        assert dbexport._missing_dependents({"users"}, {"users"}) == {}, "a table the file lacks cannot be demanded"
        assert dbexport._missing_dependents({"mfa_methods"}, full) == {}, "a child alone is fine"

    def test_users_alone_is_refused_before_anything_is_touched(self, db):
        blob = _file({"users": [], "mfa_methods": [], "api_keys": []})
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM users")
            before = cur.fetchone()["n"]
        db.commit()
        with pytest.raises(dbexport.ScopeRefused) as e:
            dbexport.import_jen(blob, tables_to_restore=["users"])
        assert "mfa_methods, api_keys" in e.value.public
        assert "Tick" in e.value.public
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM users")
            assert cur.fetchone()["n"] == before

    def test_merge_mode_is_not_guarded(self, db, scratch):
        # merge never deletes, so nothing can be orphaned; the explicit-selection rule only guards replace mode
        blob = _file({"users": [], "mfa_methods": []})
        results = dbexport.import_jen(blob, tables_to_restore=["users"], truncate=False)
        assert any(r.startswith(("✅ users", "⚠️ users")) for r in results)

    def test_the_import_page_says_so_and_changes_nothing(self, logged_in_client):
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        path = os.path.join(extensions.CONTENT_TMP_DIR, "jen_import_q128scope.json.gz")
        with open(path, "wb") as f:
            f.write(_file({"users": [], "mfa_methods": []}))
        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": base64.b64encode(path.encode()).decode(), "tables": ["users"], "mode": "replace"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"on its own would leave mfa_methods" in r.data
        assert b"Nothing was changed" in r.data
