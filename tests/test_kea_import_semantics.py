"""
tests/test_kea_import_semantics.py
───────────────────────────────────
v5.67.0-beta.13 (Q127, items b, c, d) — what a Kea import does to a database that already has reservations,
against this suite's Kea tables (which now carry Kea's real unique keys, cascading and NO ACTION foreign keys,
lookup tables and NOT NULL-without-default columns — see tests/conftest.py). The same scenarios run against
ISC's real schema in tests/kea_compat/test_db_moves.py.

  (b) a host_id in a file is never an identity: hosts are matched by (identifier, type, dhcp4 subnet, dhcp6
      subnet), inserted without a host_id, and every child row is attached through the id map;
  (c) overwrite updates in place — no REPLACE — and replaces only the child tables the file contains;
  (d) only a duplicate key in skip mode is "skipped": anything else aborts and rolls the whole import back.

DB-backed (needs the real MariaDB/MySQL, like every test that touches the Kea tables).
"""

import json

import pymysql
import pytest

from jen.services import dbexport

M1, M2, M3, M4 = (bytes.fromhex(f"02cc0000000{n}") for n in (1, 2, 3, 4))


def tag(b: bytes) -> dict:
    return {"$bin": b.hex()}


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


def host(conn, mac, *, sub4=1, sub6=None, name=None, ip=None):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, dhcp6_subnet_id, "
            "ipv4_address, hostname) VALUES (%s, 0, %s, %s, %s, %s)",
            (mac, sub4, sub6, ip, name or mac.hex()),
        )
        hid = cur.lastrowid
    conn.commit()
    return hid


def opt4(conn, host_id, value: bytes, text):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dhcp4_options (code, value, formatted_value, space, host_id, scope_id, client_classes) "
            "VALUES (6, %s, %s, 'dhcp4', %s, 3, '')",
            (value, text, host_id),
        )
    conn.commit()


def v6res(conn, host_id, address):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO ipv6_reservations (address, prefix_len, type, host_id) VALUES (%s, 128, 0, %s)",
            (address, host_id),
        )
    conn.commit()


def opt6(conn, host_id, text):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dhcp6_options (code, value, formatted_value, space, host_id, scope_id, client_classes) "
            "VALUES (23, %s, %s, 'dhcp6', %s, 3, '')",
            (b"\x20\x01", text, host_id),
        )
    conn.commit()


def q(conn, sql, *params):
    conn.commit()
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def file_host(mac, host_id, *, sub4=1, sub6=None, name="from-file", ip=None):
    return {
        "host_id": host_id,
        "dhcp_identifier": tag(mac),
        "dhcp_identifier_type": 0,
        "dhcp4_subnet_id": sub4,
        "dhcp6_subnet_id": sub6,
        "ipv4_address": ip,
        "hostname": name,
    }


def file_opt(option_id, host_id, text, *, scope=3):
    return {
        "option_id": option_id,
        "code": 6,
        "value": tag(bytes([1, 2, 3, 4])),
        "formatted_value": text,
        "space": "dhcp4",
        "host_id": host_id,
        "scope_id": scope,
    }


def make_file(**tables):
    meta = {"database": "kea", "jen_export_version": 1, "format": 3, "tables": list(tables)}
    return json.dumps({"_meta": meta, "data": tables}).encode("utf-8")


class TestAHostIdInAFileIsNeverAnIdentity:
    def test_a_colliding_id_neither_swallows_the_file_host_nor_attaches_its_options_to_the_targets(self, kea):
        camera = host(kea, M1, name="camera")
        opt4(kea, camera, bytes([10, 0, 0, 53]), "camera-dns")
        f = make_file(
            hosts=[file_host(M2, camera, name="printer")], dhcp4_options=[file_opt(900, camera, "printer-dns")]
        )
        out = dbexport.import_kea(f, "skip")
        hosts = {r["hostname"]: r["host_id"] for r in q(kea, "SELECT host_id, hostname FROM hosts")}
        assert set(hosts) == {"camera", "printer"} and hosts["printer"] != camera
        assert [
            r["formatted_value"] for r in q(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id=%s", camera)
        ] == ["camera-dns"]
        assert [
            r["formatted_value"]
            for r in q(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id=%s", hosts["printer"])
        ] == ["printer-dns"]
        assert any("hosts: 1 inserted" in line for line in out), out

    def test_the_options_own_id_is_never_carried(self, kea):
        f = make_file(hosts=[file_host(M1, 5)], dhcp4_options=[file_opt(424242, 5, "x")])
        dbexport.import_kea(f, "skip")
        assert q(kea, "SELECT option_id FROM dhcp4_options")[0]["option_id"] != 424242

    def test_a_host_already_in_the_target_under_another_id_is_skipped_with_its_children(self, kea):
        existing = host(kea, M1, name="existing")
        f = make_file(
            hosts=[file_host(M1, existing + 100, name="file-copy")],
            dhcp4_options=[file_opt(1, existing + 100, "file-copy-dns")],
        )
        out = dbexport.import_kea(f, "skip")
        assert [r["hostname"] for r in q(kea, "SELECT hostname FROM hosts")] == ["existing"]
        assert q(kea, "SELECT 1 FROM dhcp4_options") == (), "the skipped host's children must be skipped with it"
        assert any("1 duplicates skipped" in line for line in out) and any(
            "1 skipped with their host" in line for line in out
        ), out

    def test_the_same_identifier_in_a_different_subnet_is_a_different_reservation(self, kea):
        host(kea, M1, sub4=1, name="in-subnet-1")
        dbexport.import_kea(make_file(hosts=[file_host(M1, 7, sub4=2, name="in-subnet-2")]), "skip")
        assert sorted(r["hostname"] for r in q(kea, "SELECT hostname FROM hosts")) == ["in-subnet-1", "in-subnet-2"]

    def test_options_that_belong_to_no_reservation_in_the_file_are_not_written_and_are_counted(self, kea):
        f = make_file(
            hosts=[file_host(M1, 5)],
            dhcp4_options=[
                file_opt(1, 5, "mine"),
                file_opt(2, None, "global-one", scope=0),
                file_opt(3, 999, "dangling"),
            ],
        )
        out = dbexport.import_kea(f, "skip")
        assert [r["formatted_value"] for r in q(kea, "SELECT formatted_value FROM dhcp4_options")] == ["mine"]
        assert any("2 not attached to a reservation in this file" in line for line in out), out

    def test_children_of_a_file_whose_hosts_were_not_imported_are_skipped_not_attached_anywhere(self, kea):
        host(kea, M1, name="innocent")
        out = dbexport.import_kea(make_file(dhcp4_options=[file_opt(1, 1, "orphan")]), "skip")
        assert q(kea, "SELECT 1 FROM dhcp4_options") == ()
        assert any("nothing to attach them to" in line for line in out), out

    def test_an_older_file_without_the_columns_a_newer_schema_requires_still_imports(self, kea):
        """client_classes (LONGTEXT NOT NULL, no default) did not exist when older backups were made; scope_id
        is a host's 3 by construction. The importer supplies both rather than failing (or, as INSERT IGNORE did,
        quietly succeeding with a warning)."""
        bare_opt = {"option_id": 1, "code": 6, "value": tag(b"\x01\x02\x03\x04"), "space": "dhcp4", "host_id": 5}
        dbexport.import_kea(make_file(hosts=[file_host(M1, 5)], dhcp4_options=[bare_opt]), "skip")
        row = q(kea, "SELECT scope_id, client_classes FROM dhcp4_options")[0]
        assert row["scope_id"] == dbexport.KEA_HOST_OPTION_SCOPE and row["client_classes"] == ""


class TestOverwriteUpdatesInPlace:
    def _target(self, kea):
        h = host(kea, M1, sub6=5, name="old", ip=167772200)
        opt4(kea, h, bytes([1, 1, 1, 1]), "old-v4-dns")
        v6res(kea, h, "2001:db8::1")
        opt6(kea, h, "old-v6-dns")
        return h

    def test_an_ipv4_only_file_keeps_the_hosts_ipv6_rows_and_options(self, kea):
        h = self._target(kea)
        f = make_file(hosts=[file_host(M1, 999, sub6=5, name="new")], dhcp4_options=[file_opt(7, 999, "new-v4-dns")])
        out = dbexport.import_kea(f, "overwrite")
        assert [(r["host_id"], r["hostname"]) for r in q(kea, "SELECT host_id, hostname FROM hosts")] == [(h, "new")]
        assert [
            r["formatted_value"] for r in q(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id=%s", h)
        ] == ["new-v4-dns"]
        assert [r["address"] for r in q(kea, "SELECT address FROM ipv6_reservations WHERE host_id=%s", h)] == [
            "2001:db8::1"
        ]
        assert [
            r["formatted_value"] for r in q(kea, "SELECT formatted_value FROM dhcp6_options WHERE host_id=%s", h)
        ] == ["old-v6-dns"]
        assert any("1 existing updated in place" in line for line in out), out

    def test_a_child_table_the_file_carries_replaces_the_hosts_rows_even_when_the_file_has_none_for_it(self, kea):
        h = self._target(kea)
        f = make_file(hosts=[file_host(M1, 999, sub6=5, name="new")], dhcp4_options=[], ipv6_reservations=[])
        dbexport.import_kea(f, "overwrite")
        assert q(kea, "SELECT 1 FROM dhcp4_options WHERE host_id=%s", h) == ()
        assert q(kea, "SELECT 1 FROM ipv6_reservations WHERE host_id=%s", h) == ()
        assert len(q(kea, "SELECT 1 FROM dhcp6_options WHERE host_id=%s", h)) == 1, "dhcp6_options is not in the file"

    def test_overwrite_never_uses_replace(self):
        import inspect

        src = inspect.getsource(dbexport.import_kea)
        assert "REPLACE" not in src.replace("replace", "")  # no REPLACE INTO (the word `replace` in prose is fine)

    def test_a_new_host_in_overwrite_mode_is_inserted_with_its_children(self, kea):
        f = make_file(hosts=[file_host(M3, 55, name="brand-new")], dhcp4_options=[file_opt(1, 55, "its-dns")])
        dbexport.import_kea(f, "overwrite")
        hid = q(kea, "SELECT host_id FROM hosts WHERE hostname='brand-new'")[0]["host_id"]
        assert [
            r["formatted_value"] for r in q(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id=%s", hid)
        ] == ["its-dns"]


class TestErrorsAreErrors:
    def test_a_foreign_key_failure_aborts_and_rolls_back_the_good_rows_too(self, kea):
        good, bad = file_host(M1, 1, name="good"), file_host(M2, 2, name="bad")
        bad["dhcp_identifier_type"] = 99  # not in host_identifier_type
        with pytest.raises(dbexport.ImportAborted) as e:
            dbexport.import_kea(make_file(hosts=[good, bad]), "skip")
        assert "hosts row 2" in e.value.public and "IntegrityError" in str(e.value)
        assert q(kea, "SELECT 1 FROM hosts") == (), "the whole import is rolled back"

    def test_a_value_too_long_for_its_column_aborts(self, kea):
        too_long = file_host(M1, 1, name="x" * 400)
        with pytest.raises((dbexport.ImportAborted, pymysql.err.DataError)):
            dbexport.import_kea(make_file(hosts=[too_long]), "skip")
        assert q(kea, "SELECT 1 FROM hosts") == ()

    def test_a_duplicate_in_skip_mode_is_the_one_thing_that_is_skipped(self, kea):
        host(kea, M1, name="there")
        out = dbexport.import_kea(make_file(hosts=[file_host(M1, 1), file_host(M2, 2, name="added")]), "skip")
        assert sorted(r["hostname"] for r in q(kea, "SELECT hostname FROM hosts")) == ["added", "there"]
        assert any(line == "✅ hosts: 1 inserted, 1 duplicates skipped" for line in out), out

    def test_a_duplicate_in_overwrite_mode_on_a_different_unique_key_is_an_error(self, kea):
        host(kea, M1, sub4=1, sub6=9, name="holder")
        # a NEW identity (different identifier) that collides on the dhcp6 unique key? make it collide on the v4 address
        # no unique key on the address in 3.x, so collide on (identifier, type, dhcp6_subnet_id) via a second row in the file
        f = make_file(hosts=[file_host(M2, 1, sub4=3, sub6=7, name="a"), file_host(M2, 2, sub4=4, sub6=7, name="b")])
        with pytest.raises(dbexport.ImportAborted):
            dbexport.import_kea(f, "overwrite")
        assert [r["hostname"] for r in q(kea, "SELECT hostname FROM hosts")] == ["holder"]

    def test_the_public_message_names_table_and_row_and_never_a_value(self, kea):
        bad = file_host(M1, 1, name="secret-value-xyz")
        bad["dhcp_identifier_type"] = 99
        with pytest.raises(dbexport.ImportAborted) as e:
            dbexport.import_kea(make_file(hosts=[bad]), "skip")
        assert "secret-value-xyz" not in e.value.public and "hosts row 1" in e.value.public

    def test_an_unknown_duplicate_mode_is_refused(self):
        with pytest.raises(ValueError):
            dbexport.import_kea(make_file(hosts=[file_host(M1, 1)]), "replace")


class TestLeases:
    def _file(self, n=1):
        rows = [
            {
                "address": 3232236100 + i,
                "hwaddr": tag(M1),
                "client_id": None,
                "valid_lifetime": 3600,
                "subnet_id": 1,
                "hostname": f"h{i}",
            }
            for i in range(n)
        ]
        return make_file(lease4=rows)

    def test_a_lease_file_imports_and_a_duplicate_is_skipped_in_skip_mode(self, kea):
        dbexport.import_kea(self._file(2), "skip")
        out = dbexport.import_kea(self._file(3), "skip")
        assert len(q(kea, "SELECT 1 FROM lease4")) == 3
        assert any(line == "✅ lease4: 1 inserted, 2 duplicates skipped" for line in out), out

    def test_overwrite_updates_a_lease_in_place(self, kea):
        dbexport.import_kea(self._file(1), "skip")
        changed = json.loads(self._file(1))
        changed["data"]["lease4"][0]["hostname"] = "renamed"
        out = dbexport.import_kea(json.dumps(changed).encode(), "overwrite")
        assert q(kea, "SELECT hostname FROM lease4")[0]["hostname"] == "renamed"
        assert any("updated in place" in line for line in out), out
