"""
tests/test_migrate_contract.py
───────────────────────────────
v5.67.0-beta.13 (Q127, item a) — a database migration can no longer destroy what was already there.

Until now `migrate_jen` and `migrate_kea` ran `CREATE TABLE IF NOT EXISTS` from the SOURCE's DDL, marked every
table "created" whether it was or not, copied with `INSERT IGNORE`, and on ANY failure ran `DROP TABLE IF
EXISTS` over that list. A collision in a non-empty target was nearly guaranteed to fail the final count check —
so the common case "ran `kea-admin db-init` on the new server, then migrated" dropped the new server's own
`hosts`, `dhcp4_options`, `dhcp6_options` and `ipv6_reservations`. The contract now (checked before anything is
written):

  * Jen:  every selected table must be ABSENT on the target; an empty or unknown selection is refused (it used to
          be widened to everything); a failure drops only what this run created.
  * Kea:  the target must be an INITIALISED Kea database (schema_version row, same major, the group's tables) and
          Jen copies DATA ONLY — it never issues DDL against Kea's schema; plain INSERT, rollback, and a fallback
          that deletes exactly the rows this run inserted.

DB-backed; the second database is a scratch one (`jen_test_%`, which the pytest job grants — and these tests
FAIL under CI rather than skip if it cannot be created). The same scenarios run against ISC's real schema in
tests/kea_compat/test_db_moves.py.
"""

import inspect
import os

import pymysql
import pymysql.cursors
import pytest

from jen.services import dbexport
from tests.conftest import TEST_DB

SCRATCH = "jen_test_q127_target"
PORT = int(os.environ.get("JEN_DB_PORT", 3306))
KEA_ORDER = (
    "host_identifier_type",
    "dhcp_option_scope",
    "schema_version",
    "lease4",
    "hosts",
    "dhcp4_options",
    "dhcp6_options",
    "lease6",
    "ipv6_reservations",
)
KEA_DATA_TABLES = ("hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations")
MAC1, MAC2, MAC3 = (bytes.fromhex(h) for h in ("02aa00000001", "02aa00000002", "02aa00000003"))


def _conn(database=None):
    kw = {k: v for k, v in TEST_DB.items() if k != "database"}
    if database:
        kw["database"] = database
    return pymysql.connect(**kw, cursorclass=pymysql.cursors.DictCursor, autocommit=True, charset="utf8mb4")


@pytest.fixture
def scratch():
    """An empty scratch database on the same server."""
    try:
        admin = _conn()
        with admin.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{SCRATCH}`")
            cur.execute(f"CREATE DATABASE `{SCRATCH}`")
        admin.close()
    except pymysql.err.OperationalError as e:
        if os.environ.get("CI"):
            pytest.fail(f"CI must let the test user create `jen_test_%` scratch databases ({e})")
        pytest.skip(f"this database user cannot create a scratch database: {e}")
    yield SCRATCH
    admin = _conn()
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{SCRATCH}`")
    admin.close()


def migrate_jen(**kw):
    return dbexport.migrate_jen(TEST_DB["host"], PORT, TEST_DB["user"], TEST_DB["password"], SCRATCH, **kw)


def migrate_kea(**kw):
    return dbexport.migrate_kea(TEST_DB["host"], PORT, TEST_DB["user"], TEST_DB["password"], SCRATCH, **kw)


def tables_of(conn):
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        return sorted(next(iter(r.values())) for r in cur.fetchall())


def snapshot(conn, tables, where=None):
    """{table: rows with bytes as hex} — or "<missing>" for a table that is not there. `where` limits the rows."""
    out = {}
    for t in tables:
        with conn.cursor() as cur:
            cur.execute("SHOW TABLES LIKE %s", (t,))
            if not cur.fetchone():
                out[t] = "<missing>"
                continue
            cur.execute(f"SELECT * FROM `{t}`" + (f" WHERE {where}" if where else ""))
            rows = [
                {k: (bytes(v).hex() if isinstance(v, (bytes, bytearray)) else v) for k, v in r.items()}
                for r in cur.fetchall()
            ]
        out[t] = sorted(rows, key=lambda r: sorted((k, str(v)) for k, v in r.items()))
    return out


# ── Jen ──────────────────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def jen_rows(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM settings WHERE setting_key LIKE '_q127_%'")
        cur.executemany(
            "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)",
            [("_q127_a", "one"), ("_q127_b", "ünï")],
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM settings WHERE setting_key LIKE '_q127_%'")
    db.commit()


class TestMigrateJenTargetContract:
    def test_a_selected_table_that_already_exists_refuses_the_migration_and_changes_nothing(
        self, db, scratch, jen_rows
    ):
        tgt = _conn(scratch)
        with tgt.cursor() as cur:
            cur.execute("CREATE TABLE settings (setting_key VARCHAR(10) PRIMARY KEY, extra INT)")
            cur.execute("INSERT INTO settings VALUES ('keep', 7)")
        before = snapshot(tgt, ["settings"])
        with pytest.raises(dbexport.MigrationRefused, match="already has settings"):
            migrate_jen(tables=["settings", "reservation_notes"])
        assert snapshot(tgt, ["settings"]) == before, "the target's own table, structure and row, must be untouched"
        assert tables_of(tgt) == ["settings"], "no table was created either"
        tgt.close()

    @pytest.mark.parametrize("selection", [[], ["not_a_jen_table"], ["../etc", "users; DROP TABLE x"]])
    def test_an_empty_or_unknown_selection_is_refused_not_widened_to_everything(self, scratch, selection):
        with pytest.raises(dbexport.MigrationRefused, match="No table was selected"):
            migrate_jen(tables=selection)
        tgt = _conn(scratch)
        assert tables_of(tgt) == []
        tgt.close()

    def test_none_means_everything_the_source_universe_holds(self, db, scratch, jen_rows, monkeypatch):
        monkeypatch.setattr(dbexport, "export_tables", lambda conn=None: ["settings", "reservation_notes"])
        results = migrate_jen()
        tgt = _conn(scratch)
        assert tables_of(tgt) == ["reservation_notes", "settings"]
        assert any(r.startswith("✅ settings:") for r in results), results
        tgt.close()

    def test_a_clean_migration_copies_the_rows_and_verifies_them(self, db, scratch, jen_rows):
        results = migrate_jen(tables=["settings"])
        tgt = _conn(scratch)
        with tgt.cursor() as cur:
            cur.execute("SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE '_q127_%' ORDER BY 1")
            assert [(r["setting_key"], r["setting_value"]) for r in cur.fetchall()] == [
                ("_q127_a", "one"),
                ("_q127_b", "ünï"),
            ]
        assert any(r.startswith("✅ settings:") for r in results)
        tgt.close()

    def test_a_failure_drops_only_the_tables_this_run_created(self, db, scratch, jen_rows, monkeypatch):
        tgt = _conn(scratch)
        with tgt.cursor() as cur:
            cur.execute("CREATE TABLE keepme (id INT PRIMARY KEY, note VARCHAR(20))")
            cur.execute("INSERT INTO keepme VALUES (1, 'precious')")
        before = snapshot(tgt, ["keepme"])
        real = dbexport._copy_table_rows
        calls = []

        def second_table_fails(src, dst, tbl, *a, **k):
            calls.append(tbl)
            if len(calls) == 2:
                raise RuntimeError("simulated failure on the second table")
            return real(src, dst, tbl, *a, **k)

        monkeypatch.setattr(dbexport, "_copy_table_rows", second_table_fails)
        with pytest.raises(RuntimeError, match="Migration failed"):
            migrate_jen(tables=["settings", "reservation_notes"])
        assert tables_of(tgt) == ["keepme"], "both tables this run created are gone, and nothing else was dropped"
        assert snapshot(tgt, ["keepme"]) == before
        tgt.close()

    def test_the_cleanup_never_names_a_table_that_was_not_created(self):
        src = inspect.getsource(dbexport.migrate_jen)
        assert "IF NOT EXISTS" not in src, (
            "CREATE TABLE IF NOT EXISTS is what hid the difference between ours and theirs"
        )
        assert "created_tables.append(tbl)  # only now is it ours to drop" in src


# ── Kea ──────────────────────────────────────────────────────────────────────────────────────────────────


def initialise_kea_target(db, name=SCRATCH, *, rows=True):
    """A scratch database that looks like what `kea-admin db-init` leaves: every Kea table's DDL, the lookup
    rows and the schema_version row — copied from this suite's own (Kea's real) definitions."""
    tgt = _conn(name)
    with tgt.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for t in KEA_ORDER:
            with db.cursor() as scur:
                scur.execute(f"SHOW CREATE TABLE `{t}`")
                r = scur.fetchone()
            cur.execute(next(v for k, v in r.items() if "Create" in k))
        if rows:
            for t in ("host_identifier_type", "dhcp_option_scope", "schema_version"):
                with db.cursor() as scur:
                    scur.execute(f"SELECT * FROM `{t}`")
                    for r in scur.fetchall():
                        cur.execute(
                            f"INSERT INTO `{t}` ({', '.join(f'`{k}`' for k in r)}) "
                            f"VALUES ({', '.join(['%s'] * len(r))})",
                            list(r.values()),
                        )
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
    db.commit()
    return tgt


def add_host(conn, host_id, mac, hostname):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, "
            "hostname) VALUES (%s, %s, 0, 1, %s, %s)",
            (host_id, mac, 3232235776 + host_id, hostname),
        )


def add_option(conn, option_id, host_id, value):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "client_classes) VALUES (%s, 6, %s, 'q127', 'dhcp4', %s, 3, '')",
            (option_id, value, host_id),
        )


def add_config_backend_options(conn):
    """What a source that uses Kea's config backend holds besides a reservation's own options (Q131): a GLOBAL option
    (scope 0, no host) and a SUBNET-scoped one that names a dhcp4_subnet_id/dhcp6_subnet_id. Neither belongs to a
    reservation move; on the REAL schema the second one's foreign key into dhcp4_subnet (empty on a freshly
    initialised target) is what failed the whole migration."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "client_classes) VALUES (201, 3, %s, 'q131-global', 'dhcp4', NULL, 0, '')",
            (bytes([10, 0, 0, 1]),),
        )
        cur.execute(
            "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "dhcp4_subnet_id, client_classes) VALUES (202, 6, %s, 'q131-subnet', 'dhcp4', NULL, 1, 9999, '')",
            (bytes([10, 0, 0, 53]),),
        )
        cur.execute(
            "INSERT INTO dhcp6_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "client_classes) VALUES (301, 23, %s, 'q131-global6', 'dhcp6', NULL, 0, '')",
            (bytes(16),),
        )
    conn.commit()


@pytest.fixture
def kea_source(db):
    """Three reservations in the source (the unit database), two with options, one with an IPv6 reservation."""
    with db.cursor() as cur:
        for t in ("ipv6_reservations", "dhcp6_options", "dhcp4_options", "hosts"):
            cur.execute(f"DELETE FROM `{t}`")
    db.commit()
    add_host(db, 11, MAC1, "q127-one")
    add_host(db, 12, MAC2, "q127-two")
    add_host(db, 13, MAC3, "q127-three")
    add_option(db, 101, 11, bytes([0xFF, 0xFE, 0x00, 0x80]))
    add_option(db, 102, 12, bytes([1, 2, 3, 4]))
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO ipv6_reservations (reservation_id, address, prefix_len, type, host_id) "
            "VALUES (1, INET6_ATON('2001:db8::11'), 128, 0, 11)"
        )
    db.commit()
    yield
    with db.cursor() as cur:
        for t in ("ipv6_reservations", "dhcp6_options", "dhcp4_options", "hosts"):
            cur.execute(f"DELETE FROM `{t}`")
    db.commit()


class TestMigrateKeaTargetContract:
    def test_an_uninitialised_target_is_refused_and_nothing_is_created_in_it(self, db, scratch, kea_source):
        with pytest.raises(dbexport.MigrationRefused, match="not an initialised Kea database"):
            migrate_kea()
        tgt = _conn(scratch)
        assert tables_of(tgt) == [], "Jen must never create Kea's tables"
        tgt.close()

    def test_a_target_whose_schema_major_differs_is_refused(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        with tgt.cursor() as cur:
            cur.execute("UPDATE schema_version SET version = version + 1")
        before = snapshot(tgt, KEA_ORDER)
        with pytest.raises(dbexport.MigrationRefused, match="major versions must match"):
            migrate_kea()
        assert snapshot(tgt, KEA_ORDER) == before
        tgt.close()

    def test_a_target_missing_a_table_the_source_has_is_refused(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        with tgt.cursor() as cur:
            cur.execute("DROP TABLE dhcp6_options")
        with pytest.raises(dbexport.MigrationRefused, match="missing dhcp6_options"):
            migrate_kea()
        assert "dhcp4_options" in tables_of(tgt) and "hosts" in tables_of(tgt)
        tgt.close()

    def test_data_goes_into_an_initialised_target_byte_for_byte_and_no_ddl_is_issued(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        results = migrate_kea()
        assert any(r.startswith("✅ hosts: 3 rows") for r in results), results
        db.commit()
        for t in KEA_DATA_TABLES:
            assert snapshot(tgt, [t]) == snapshot(db, [t]), f"{t} did not copy exactly"
        tgt.close()

    def test_only_a_reservations_own_options_are_copied_never_the_config_backends(self, db, scratch, kea_source):
        """Q131 — the migration used to SELECT * the options tables: the global and subnet rows travelled by their
        option_ids (and, on the real schema, the subnet row's foreign key failed the whole migration)."""
        add_config_backend_options(db)
        tgt = initialise_kea_target(db)
        results = migrate_kea()
        db.commit()
        host_scoped = "host_id IS NOT NULL AND scope_id = 3"
        for t in ("dhcp4_options", "dhcp6_options"):
            src_rows = snapshot(db, [t], where=host_scoped)[t]
            assert snapshot(tgt, [t])[t] == src_rows, f"{t}: exactly the host-scoped rows, byte for byte"
        assert [r["option_id"] for r in snapshot(tgt, ["dhcp4_options"])["dhcp4_options"]] == [101, 102]
        assert snapshot(tgt, ["dhcp6_options"])["dhcp6_options"] == []
        for t in ("hosts", "ipv6_reservations"):
            assert snapshot(tgt, [t]) == snapshot(db, [t]), f"{t} did not copy exactly"
        # the source is never modified: its config-backend rows are still there
        assert len(snapshot(db, ["dhcp4_options"])["dhcp4_options"]) == 4
        assert any(
            r == "✅ dhcp4_options: 2 host-scoped option rows (a reservation's own options; global, subnet, pool and "
            "class options are not part of a reservation move)"
            for r in results
        ), results
        assert any(r.startswith("ℹ️ dhcp4_options: 2 option row(s) of Kea's config backend") for r in results), results
        assert any(r.startswith("ℹ️ dhcp6_options: 0 host-scoped option rows") for r in results), results
        assert any(r.startswith("ℹ️ dhcp6_options: 1 option row(s) of Kea's config backend") for r in results), results
        tgt.close()

    def test_no_left_behind_line_when_there_is_nothing_left_behind(self, db, scratch, kea_source):
        initialise_kea_target(db).close()
        results = migrate_kea()
        assert any(r.startswith("✅ dhcp4_options: 2 host-scoped option rows") for r in results)
        assert not any("left behind" in r for r in results), results

    def test_the_leases_group_copies_hwaddr_and_client_id_byte_for_byte(self, db, scratch, kea_source):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, client_id, valid_lifetime, subnet_id, hostname) VALUES "
                "(3232236001, %s, %s, 3600, 1, 'q127-a'), (3232236002, NULL, NULL, 3600, 1, 'q127-b')",
                (MAC1, b"\x01" + MAC1),
            )
        db.commit()
        try:
            tgt = initialise_kea_target(db)
            migrate_kea(group="leases")
            assert snapshot(tgt, ["lease4"]) == snapshot(db, ["lease4"])
            tgt.close()
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4")
            db.commit()

    def test_rows_that_were_already_in_the_target_stay_when_nothing_collides(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        add_host(tgt, 500, bytes.fromhex("02bb00000500"), "q127-already-there")
        migrate_kea()
        with tgt.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts ORDER BY host_id")
            assert [r["host_id"] for r in cur.fetchall()] == [11, 12, 13, 500]
        tgt.close()

    def test_a_collision_fails_the_migration_and_leaves_a_populated_target_byte_for_byte_as_it_was(
        self, db, scratch, kea_source
    ):
        tgt = initialise_kea_target(db)
        add_host(tgt, 12, bytes.fromhex("02bb00000012"), "q127-target-owns-id-12")  # the same host_id as source host 12
        add_option(tgt, 900, 12, bytes([9, 9, 9, 9]))
        before = snapshot(tgt, KEA_ORDER)
        with pytest.raises(RuntimeError, match="rolled back"):
            migrate_kea()
        assert snapshot(tgt, KEA_ORDER) == before, "no table dropped, no row added, none removed"
        tgt.close()

    def test_migrate_kea_never_issues_ddl(self):
        src = inspect.getsource(dbexport.migrate_kea)
        for forbidden in ("CREATE TABLE", "SHOW CREATE", "DROP TABLE", "ALTER TABLE", "TRUNCATE"):
            assert forbidden not in src, f"Jen never changes Kea's schema ({forbidden})"

    def test_a_group_with_no_table_on_the_source_is_refused(self, db, scratch, kea_source, monkeypatch):
        initialise_kea_target(db).close()
        monkeypatch.setattr(dbexport, "KEA_EXPORT_GROUPS", {"x": {"label": "x", "description": "", "tables": ["nope"]}})
        with pytest.raises(dbexport.MigrationRefused, match="None of this group's tables"):
            migrate_kea(group="x")

    def test_an_unknown_group_is_a_value_error(self, scratch):
        with pytest.raises(ValueError):
            migrate_kea(group="nonsense")


class TestTheCopyHelpers:
    def test_a_plain_insert_collision_is_an_error_not_a_silent_skip(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        add_host(tgt, 11, bytes.fromhex("02bb00000011"), "q127-collides")
        with pytest.raises(pymysql.err.IntegrityError):
            dbexport._copy_table_rows(db, tgt, "hosts")
        tgt.close()

    def test_the_count_is_what_the_server_reports(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        track = []
        n = dbexport._copy_table_rows(db, tgt, "hosts", batch=2, track=track, pk_cols=["host_id"])
        assert n == 3 and sorted(track) == [(11,), (12,), (13,)]
        tgt.close()

    def test_delete_tracked_removes_exactly_the_rows_a_run_inserted_children_first(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        add_host(tgt, 700, bytes.fromhex("02cc00000700"), "q127-was-here")
        add_option(tgt, 701, 700, bytes([7]))
        # a run inserted hosts 11, 12 and option 101, then (pretend) could not confirm its rollback
        add_host(tgt, 11, MAC1, "q127-one")
        add_host(tgt, 12, MAC2, "q127-two")
        add_option(tgt, 101, 11, bytes([1]))
        dbexport._delete_tracked(
            tgt,
            ["hosts", "dhcp4_options"],
            {"hosts": ["host_id"], "dhcp4_options": ["option_id"]},
            {"hosts": [(11,), (12,)], "dhcp4_options": [(101,)]},
        )
        with tgt.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts")
            assert [r["host_id"] for r in cur.fetchall()] == [700]
            cur.execute("SELECT option_id FROM dhcp4_options")
            assert [r["option_id"] for r in cur.fetchall()] == [701]
        tgt.close()

    def test_copy_table_rows_with_a_query_copies_exactly_what_it_selects(self, db, scratch, kea_source):
        add_config_backend_options(db)
        tgt = initialise_kea_target(db)
        dbexport._copy_table_rows(db, tgt, "hosts")
        track = []
        n = dbexport._copy_table_rows(
            db, tgt, "dhcp4_options", pk_cols=["option_id"], track=track, sql=dbexport.KEA_EXPORT_SQL["dhcp4_options"]
        )
        assert n == 2 and sorted(track) == [(101,), (102,)]
        with tgt.cursor() as cur:
            cur.execute("SELECT option_id FROM dhcp4_options ORDER BY option_id")
            assert [r["option_id"] for r in cur.fetchall()] == [101, 102]
        # no query: every row, as before
        with tgt.cursor() as cur:
            cur.execute("DELETE FROM dhcp4_options")
        assert dbexport._copy_table_rows(db, tgt, "dhcp4_options") == 4
        tgt.close()

    def test_row_count_and_pk_sample_apply_the_predicate_to_the_side_they_are_given(self, db, scratch, kea_source):
        add_config_backend_options(db)
        where = dbexport.KEA_TABLE_WHERE["dhcp4_options"]
        assert dbexport._row_count(db, "dhcp4_options") == 4
        assert dbexport._row_count(db, "dhcp4_options", where) == 2
        assert dbexport._pk_sample(db, "dhcp4_options", ["option_id"]) == [(101,), (102,), (201,), (202,)]
        assert dbexport._pk_sample(db, "dhcp4_options", ["option_id"], where=where) == [(101,), (102,)]

    def test_verify_copy_with_the_predicate_passes_a_correct_copy_and_without_it_fails_it(
        self, db, scratch, kea_source
    ):
        add_config_backend_options(db)
        tgt = initialise_kea_target(db)
        dbexport._copy_table_rows(db, tgt, "hosts")
        dbexport._copy_table_rows(db, tgt, "dhcp4_options", sql=dbexport.KEA_EXPORT_SQL["dhcp4_options"])
        where = dbexport.KEA_TABLE_WHERE["dhcp4_options"]
        dbexport._verify_copy(db, tgt, "dhcp4_options", 0, ["option_id"], where=where)  # does not raise
        with pytest.raises(RuntimeError, match="Row count mismatch on dhcp4_options: source 4, target gained 2"):
            dbexport._verify_copy(db, tgt, "dhcp4_options", 0, ["option_id"])
        # the target's side is never filtered: rows that were already there are subtracted, not hidden
        add_host(tgt, 500, bytes.fromhex("02bb00000500"), "q131-already-there")
        add_option(tgt, 900, 500, bytes([9]))
        dbexport._verify_copy(db, tgt, "dhcp4_options", 1, ["option_id"], where=where)
        tgt.close()

    def test_a_sampled_key_missing_from_the_target_is_still_caught_with_the_predicate(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        dbexport._copy_table_rows(db, tgt, "hosts")
        dbexport._copy_table_rows(db, tgt, "dhcp4_options", sql=dbexport.KEA_EXPORT_SQL["dhcp4_options"])
        with tgt.cursor() as cur:
            cur.execute("DELETE FROM dhcp4_options WHERE option_id = 101")
            cur.execute(
                "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
                "client_classes) VALUES (777, 6, %s, 'x', 'dhcp4', 12, 3, '')",
                (bytes([1]),),
            )
        with pytest.raises(RuntimeError, match="sampled primary key"):
            dbexport._verify_copy(
                db, tgt, "dhcp4_options", 0, ["option_id"], where=dbexport.KEA_TABLE_WHERE["dhcp4_options"]
            )
        tgt.close()

    def test_pk_sample_and_missing(self, db, scratch, kea_source):
        tgt = initialise_kea_target(db)
        assert dbexport._pk_sample(db, "hosts", ["host_id"]) == [(11,), (12,), (13,)]
        add_host(tgt, 11, MAC1, "x")
        assert dbexport._pks_missing(tgt, "hosts", ["host_id"], [(11,), (12,)]) == [(12,)]
        assert dbexport._pk_columns(db, "hosts") == ["host_id"]
        tgt.close()

    def test_the_schema_version_reader(self, db, scratch):
        assert dbexport._kea_schema_version(db) == (35, 0)
        tgt = _conn(scratch)
        assert dbexport._kea_schema_version(tgt) is None
        tgt.close()
