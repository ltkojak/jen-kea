"""
tests/test_a_replaced_parent_keeps_no_row_the_file_lacks.py
───────────────────────────────────────────────────────────
Q245 (BE1, BE2 and BE3 of the pass on v7.2.0-beta.2), over Q244 (BD1 of the pass on v7.2.0-beta.1).

A restore in replace mode deletes each table the file carries and inserts the file's rows. A table that hangs on `users` (`dbexport.JEN_DEPENDENTS`) and that
the file does NOT carry is not in the file to be restored, and foreign key checks are off during an import, so the database does nothing for it.

v7.2.0-beta.1 left such a table as it was: a row stayed on its user id whoever held that id afterward. v7.2.0-beta.2 emptied it whole: a restore of `users`
alone, from an export of `users` alone, deleted every API key, MFA method and passkey of accounts that were the same before and after.

Now the restore does what the table's own foreign key says, and only for the rows whose account is no longer the same one: the id is gone, or it holds a
different username. `CASCADE` removes the row; `SET NULL` (an API key and its creator, migration 23) keeps the row and clears the column. The rows of an
account that is the same before and after are kept.

The connections are the real ones, against the real database. `users` is replaced from an export of itself made a moment earlier, so the suite's own accounts
are the same rows afterward; the two accounts these tests add are the ones a file leaves out or renames.
"""

import gzip
import inspect
import json

import pytest

from jen.services import dbexport
from tests.test_a_lost_plugin_commit_does_not_stop_the_plugins_after_it import _installed, _put_back

DEPS = list(dbexport.JEN_DEPENDENTS["users"])
CASCADE = [d for d in DEPS if d != "api_keys"]
STAYS, LEAVES, ARRIVES = "q245-stays", "q245-leaves", "q245-arrives"
# the columns each dependent needs beside its key to the account
FILL = {
    "api_keys": {"name": "q245", "key_hash": "{who}" + "q" * 54, "key_prefix": "{who}"},
    "mfa_backup_codes": {"code_hash": "{who}" + "c" * 54},
    "mfa_methods": {"method_type": "totp", "enabled": 1},
    "mfa_trusted_devices": {"token_hash": "{who}" + "t" * 54},
    "saved_searches": {"name": "q245", "page": "leases", "params": "{}"},
    "webauthn_credentials": {"credential_id": "{who}", "public_key": "q245"},
    "user_nav": {"top_row": '["/reports"]'},
    "dashboard_prefs": {},
    "mfa_attempts": {},
}


def _q(db, sql, args=()):
    db.commit()
    with db.cursor() as cur:
        cur.execute(sql, args)
        rows = cur.fetchall()
    db.commit()
    return rows


def _key(db, dep):
    """The column of `dep` that points at `users` (written out here, so that these tests do not lean on the code they test)."""
    return "created_by" if dep == "api_keys" else "user_id"


def _rows_of(db, dep, user_id):
    return _q(db, f"SELECT COUNT(*) AS n FROM `{dep}` WHERE `{_key(db, dep)}` = %s", (user_id,))[0]["n"]


def _wipe(db):
    for dep in DEPS:
        _q(db, f"DELETE FROM `{dep}`")
    _q(db, "DELETE FROM users WHERE username IN (%s, %s, %s)", (STAYS, LEAVES, ARRIVES))


@pytest.fixture(autouse=True)
def the_plugins_are_left_as_they_were(db):
    """A restore of a whole file runs every plugin's migrations again and leaves their tables: put back, so the next file finds what this one found."""
    before = _installed(db)
    yield
    _put_back(db, before)


@pytest.fixture
def two(db):
    """Two accounts beside the suite's own, each with one row in every dependent table: `(id of the one that stays, id of the one that leaves)`."""
    _wipe(db)
    ids = []
    for who in (STAYS, LEAVES):
        _q(
            db,
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (who, "x", "viewer", json.dumps("all")),
        )
        user_id = _q(db, "SELECT id FROM users WHERE username = %s", (who,))[0]["id"]
        ids.append(user_id)
        for dep in DEPS:
            tag = who[5:9] + str(user_id)
            row = {k: (v.replace("{who}", tag) if isinstance(v, str) else v) for k, v in FILL[dep].items()}
            row[_key(db, dep)] = user_id
            cols = ", ".join(f"`{c}`" for c in row)
            _q(db, f"INSERT INTO `{dep}` ({cols}) VALUES ({', '.join(['%s'] * len(row))})", list(row.values()))
    yield tuple(ids)
    _wipe(db)


def _file(tmp_path, tables, patch=None):
    path = tmp_path / "export.json.gz"
    dbexport.write_jen_export(str(path), tables)
    if patch is None:
        return path.read_bytes()
    doc = json.loads(gzip.decompress(path.read_bytes()))
    patch(doc["data"])
    return gzip.compress(json.dumps(doc).encode())


def _without(name):
    def patch(data):
        data["users"] = [u for u in data["users"] if u["username"] != name]

    return patch


def _renamed(old, new):
    def patch(data):
        for u in data["users"]:
            if u["username"] == old:
                u["username"] = new

    return patch


def _settled(results):
    return [r for r in results if "was replaced." in r]


class TestTheSameAccountsKeepEverything:
    """BE1 and BE2: `users` alone, from an export of `users` alone made on this box. v7.2.0-beta.2 emptied all nine tables."""

    def test_users_alone_from_an_export_of_users_alone(self, db, two, tmp_path):
        results = dbexport.import_jen(_file(tmp_path, ["users"]), ["users"])
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in DEPS} == dict.fromkeys(DEPS, (1, 1))
        assert _settled(results) == [], results

    def test_the_guarded_import_of_the_databases_page_does_the_same(self, db, two, tmp_path):
        results = dbexport.import_jen_guarded(_file(tmp_path, ["users"]), ["users"])
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in DEPS} == dict.fromkeys(DEPS, (1, 1))
        assert _settled(results) == [], results

    def test_a_file_from_before_a_dependent_existed_keeps_the_lists_of_the_same_accounts(self, db, two, tmp_path):
        """An export made before 7.2.0 has no `user_nav`: v7.2.0-beta.2 deleted every person's saved navigation on such a restore."""
        results = dbexport.import_jen(_file(tmp_path, ["users", *[d for d in DEPS if d != "user_nav"]]))
        assert (_rows_of(db, "user_nav", two[0]), _rows_of(db, "user_nav", two[1])) == (1, 1)
        assert _settled(results) == [], results


class TestAnAccountTheFileDoesNotBring:
    """The account is gone after the restore: its rows get what the database's own foreign key would have done."""

    def test_its_rows_are_removed_and_its_api_key_is_kept(self, db, two, tmp_path):
        dbexport.import_jen(_file(tmp_path, ["users"], _without(LEAVES)), ["users"])
        assert _q(db, "SELECT COUNT(*) AS n FROM users WHERE username = %s", (LEAVES,))[0]["n"] == 0
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in CASCADE} == dict.fromkeys(
            CASCADE, (1, 0)
        )
        keys = _q(db, "SELECT created_by FROM api_keys ORDER BY created_by IS NULL, created_by")
        assert [k["created_by"] for k in keys] == [two[0], None]

    def test_the_page_is_told_which_and_how_many(self, db, two, tmp_path):
        results = dbexport.import_jen(_file(tmp_path, ["users"], _without(LEAVES)), ["users"])
        assert (
            "⚠️ mfa_methods: this file carries no rows for it and users was replaced. 1 row here was removed: the users row it belonged to is "
            "gone or now has a different name. Rows that belong to users the file brought back under the same name were kept"
        ) in results, results
        assert (
            "⚠️ api_keys: this file carries no rows for it and users was replaced. 1 row here was kept and no longer names the users it pointed at, "
            "which are gone or now have a different name"
        ) in results, results
        assert sorted(r.split(":")[0] for r in _settled(results)) == sorted(f"⚠️ {d}" for d in DEPS)

    def test_a_file_that_brings_no_account_back_does_not_say_rows_were_kept(self, db, two, monkeypatch):
        """BF4: when no account is the same before and after, nothing was kept, and the line no longer says something was.
        The settle step is called on the real connection with an empty `users` after the restore, and rolled back: a restore
        that really emptied `users` would take the suite's own accounts with it."""
        monkeypatch.setattr(dbexport, "_holders", lambda conn, parent: {})
        results = []
        db.commit()
        try:
            dbexport._settle_dependents_the_file_lacks(
                db, {"users": {two[0]: STAYS, two[1]: LEAVES}}, {"users"}, set(), results
            )
        finally:
            db.rollback()
        line = next(r for r in results if r.startswith("⚠️ mfa_methods:"))
        assert line == (
            "⚠️ mfa_methods: this file carries no rows for it and users was replaced. 2 rows here were removed: the users rows they belonged to "
            "are gone or now have a different name"
        ), line
        assert not any("brought back under the same name were kept" in r for r in results), results


class TestAnIdThatNowHoldsADifferentName:
    """A file from a different box: the id is there after the restore and it is not the same account. Nothing of the earlier holder stays on it."""

    def test_no_factor_and_no_list_of_the_earlier_holder_stays_on_the_id(self, db, two, tmp_path):
        dbexport.import_jen(_file(tmp_path, ["users"], _renamed(LEAVES, ARRIVES)), ["users"])
        assert _q(db, "SELECT username FROM users WHERE id = %s", (two[1],))[0]["username"] == ARRIVES
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in CASCADE} == dict.fromkeys(
            CASCADE, (1, 0)
        )
        assert _rows_of(db, "api_keys", two[1]) == 0 and _q(db, "SELECT COUNT(*) AS n FROM api_keys")[0]["n"] == 2


class TestWhatIsLeftAlone:
    def test_a_file_that_carries_the_table_restores_it(self, db, two, tmp_path):
        blob = _file(tmp_path, ["users", *DEPS])
        _q(db, "UPDATE user_nav SET top_row = '[\"/problems\"]'")
        results = dbexport.import_jen(blob)
        assert [r["top_row"] for r in _q(db, "SELECT top_row FROM user_nav")] == ['["/reports"]'] * 2
        assert "✅ user_nav: 2 rows restored" in results and _settled(results) == [], results

    def test_merge_mode_changes_nothing(self, db, two, tmp_path):
        results = dbexport.import_jen(_file(tmp_path, ["users"], _without(LEAVES)), ["users"], truncate=False)
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in DEPS} == dict.fromkeys(DEPS, (1, 1))
        assert _settled(results) == [], results

    def test_a_restore_that_does_not_replace_users_changes_nothing(self, db, two, tmp_path):
        results = dbexport.import_jen(_file(tmp_path, ["settings"]))
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in DEPS} == dict.fromkeys(DEPS, (1, 1))
        assert _settled(results) == [], results

    def test_users_asked_for_and_left_unchanged_changes_nothing(self, db, two, tmp_path):
        """BE3: the file's `users` rows carry no column this schema has, so the table is left unchanged; v7.2.0-beta.2 emptied its dependents anyway."""

        def unknown_columns(data):
            data["users"] = [{"q245_not_a_column": 1}]

        results = dbexport.import_jen(_file(tmp_path, ["users", "settings"], unknown_columns), strict=False)
        assert any(r.startswith("⚠️ users: no recognized columns") for r in results), results
        assert {d: (_rows_of(db, d, two[0]), _rows_of(db, d, two[1])) for d in DEPS} == dict.fromkeys(DEPS, (1, 1))
        assert _settled(results) == [], results


class TestTheSchemaSaysWhatHappensToARow:
    def test_an_api_key_outlives_its_creator_and_every_other_dependent_goes_with_its_account(self, db):
        """The rule reads these from the live schema; this pins what it reads today (migration 23)."""
        rules = {d: [rule for _col, rule in dbexport._foreign_keys(db, d, "users")] for d in DEPS}
        assert rules == {**dict.fromkeys(CASCADE, ["CASCADE"]), "api_keys": ["SET NULL"]}


class TestTheHelper:
    def test_it_reads_the_map_and_never_a_name_of_its_own(self):
        """Every dependent of every parent in `JEN_DEPENDENTS`: a table added to the map tomorrow is covered by being there."""
        source = inspect.getsource(dbexport._settle_dependents_the_file_lacks)
        body = source.split('"""')[2]
        assert "JEN_DEPENDENTS.items()" in source and not any(d in body for d in DEPS)

    def test_every_parent_of_the_map_has_an_identity(self):
        assert set(dbexport.JEN_DEPENDENTS) == set(dbexport.JEN_PARENT_IDENTITY)

    def test_it_is_called_once_in_replace_mode_inside_the_transaction_with_what_was_replaced(self):
        source = inspect.getsource(dbexport.import_jen)
        call = "_settle_dependents_the_file_lacks(conn, before, replaced, set(data), results)"
        assert source.count(call) == 1
        ahead = source.split(call)[0]
        assert ahead.rstrip().endswith("if truncate:")
        assert ahead.rfind("conn.begin()") > ahead.rfind("conn.commit()")
        # the accounts are read before the first table is touched, and `replaced` is what `_import_rows` says it replaced
        assert ahead.rfind("_holders(conn, p)") < ahead.rfind(
            "replaced = {tbl for tbl in core_selected if _import_rows(conn, tbl)}"
        )
        assert "_empty_dependents_the_file_lacks" not in inspect.getsource(dbexport)
