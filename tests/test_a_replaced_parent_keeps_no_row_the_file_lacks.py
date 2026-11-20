"""
tests/test_a_replaced_parent_keeps_no_row_the_file_lacks.py
───────────────────────────────────────────────────────────
Q244 (BD1 of the pass on v7.2.0-beta.1).

A restore in replace mode deletes each table the file carries and inserts the file's rows. A table that hangs on `users` (`dbexport.JEN_DEPENDENTS`) and that
the file does NOT carry was left as it was: an export made before 7.2.0 has no `user_nav`, so after it replaced `users` each saved navigation stayed on its
user id and was shown to whoever held that id after the restore. Foreign key checks are off during an import, so the cascade does not run.

Now the dependent the file lacks is emptied in the import's own transaction, and a line says so.

The connections are the real ones, against the real database. `users` is replaced from an export of itself made a moment earlier, so the suite's accounts
are the same rows afterward.
"""

import pytest

from jen.services import dbexport
from tests.test_a_lost_plugin_commit_does_not_stop_the_plugins_after_it import _installed, _put_back

OTHERS = [d for d in dbexport.JEN_DEPENDENTS["users"] if d != "user_nav"]
LINE = (
    "⚠️ user_nav: this file carries no rows for it and users was replaced, so its 1 row here was removed: "
    "it belonged to the users that were replaced"
)


def _nav(db):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT user_id, top_row FROM user_nav ORDER BY user_id")
        return [(r["user_id"], r["top_row"]) for r in cur.fetchall()]


@pytest.fixture(autouse=True)
def the_plugins_are_left_as_they_were(db):
    """A restore of a whole file runs every plugin's migrations again and leaves their tables: put back, so the next file finds what this one found."""
    before = _installed(db)
    yield
    _put_back(db, before)


@pytest.fixture
def one_list(db):
    """One saved navigation, on the first account there is."""

    def wipe():
        with db.cursor() as cur:
            cur.execute("DELETE FROM user_nav")
        db.commit()

    wipe()
    with db.cursor() as cur:
        cur.execute("SELECT MIN(id) AS id FROM users")
        user_id = cur.fetchone()["id"]
        cur.execute("INSERT INTO user_nav (user_id, top_row) VALUES (%s, %s)", (user_id, '["/reports"]'))
    db.commit()
    yield user_id
    wipe()


def _file(tmp_path, tables):
    path = tmp_path / "export.json.gz"
    dbexport.write_jen_export(str(path), tables)
    return path.read_bytes()


class TestAFileFromBeforeTheTableExisted:
    def test_replacing_users_empties_the_dependent_the_file_lacks(self, db, one_list, tmp_path):
        """v7.2.0-beta.1 leaves the row: `[(user_id, '["/reports"]')]`."""
        blob = _file(tmp_path, ["users", *OTHERS])
        results = dbexport.import_jen(blob)
        assert _nav(db) == []
        assert LINE in results, results

    def test_the_guarded_import_of_the_databases_page_does_the_same(self, db, one_list, tmp_path):
        blob = _file(tmp_path, ["users", *OTHERS])
        results = dbexport.import_jen_guarded(blob)
        assert _nav(db) == []
        assert LINE in results, results

    def test_nothing_is_said_when_there_was_no_row(self, db, one_list, tmp_path):
        with db.cursor() as cur:
            cur.execute("DELETE FROM user_nav")
        db.commit()
        results = dbexport.import_jen(_file(tmp_path, ["users", *OTHERS]))
        assert not any("user_nav" in r for r in results), results


class TestWhatIsLeftAlone:
    def test_a_file_that_carries_the_table_restores_it(self, db, one_list, tmp_path):
        blob = _file(tmp_path, ["users", *dbexport.JEN_DEPENDENTS["users"]])
        with db.cursor() as cur:
            cur.execute("UPDATE user_nav SET top_row='[\"/problems\"]'")
        db.commit()
        results = dbexport.import_jen(blob)
        assert _nav(db) == [(one_list, '["/reports"]')]
        assert "✅ user_nav: 1 rows restored" in results and not any("was removed" in r for r in results), results

    def test_merge_mode_removes_nothing(self, db, one_list, tmp_path):
        blob = _file(tmp_path, ["users", *OTHERS])
        results = dbexport.import_jen(blob, truncate=False)
        assert _nav(db) == [(one_list, '["/reports"]')]
        assert not any("was removed" in r for r in results), results

    def test_a_restore_that_does_not_replace_users_removes_nothing(self, db, one_list, tmp_path):
        blob = _file(tmp_path, ["settings"])
        results = dbexport.import_jen(blob)
        assert _nav(db) == [(one_list, '["/reports"]')]
        assert not any("was removed" in r for r in results), results


class TestTheHelper:
    def test_it_reads_the_map_and_never_a_name_of_its_own(self):
        """Every dependent of every parent in `JEN_DEPENDENTS`: a table added to the map tomorrow is covered by being there."""
        import inspect

        source = inspect.getsource(dbexport._empty_dependents_the_file_lacks)
        assert "JEN_DEPENDENTS.items()" in source and "user_nav" not in source.split('"""')[2]

    def test_it_is_called_in_replace_mode_only_and_inside_the_transaction(self):
        import inspect

        source = inspect.getsource(dbexport.import_jen)
        call = "_empty_dependents_the_file_lacks(conn, core_selected, set(data), results)"
        assert source.count(call) == 1
        before = source.split(call)[0]
        assert before.rstrip().endswith("if truncate:")
        assert before.rfind("conn.begin()") > before.rfind("conn.commit()")
