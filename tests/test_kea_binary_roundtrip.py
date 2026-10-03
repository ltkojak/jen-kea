"""
tests/test_kea_binary_roundtrip.py
───────────────────────────────────
v5.67.0-beta.11 (Q123) — release-gating: Kea's binary columns come back as the BYTES they were.

Until this release an export wrote a binary value as bare hex text, nothing decoded it, and an import, a
restore of any Kea backup and a database migration all stored that text: the six-byte MAC
34:13:43:e6:0e:2a came back as the twelve bytes of "341343e60e2a", and Kea never matched the client again.
The reservation row still looked right in every listing — which is why this needs a test that compares
`HEX(original)` to `HEX(restored)` for every binary column, against a real database, and not an assertion
on a Python round trip that could pass while the stored bytes were wrong.

DB-backed (real MariaDB/MySQL); does not run under --noconftest locally — CI is the arbiter. The migration
tests need a second database on the same server: the pytest job grants the test user `jen_test\\_%`, and a
test that cannot create its scratch database FAILS under CI (never skips) so the guard can't silently vanish.
"""

import gzip
import json
import os

import pymysql
import pymysql.cursors
import pytest

from jen.services import dbexport, health, kea_identifiers
from tests.conftest import TEST_DB

MAC = bytes.fromhex("341343e60e2a")
MAC2 = bytes.fromhex("0011223344ff")
CLIENT_ID = b"\x01" + MAC
DUID = bytes.fromhex("00030001") + MAC  # DUID-LL
NOT_UTF8 = b"\xff\xfe\x00\x80\xc3\x28\xa0\xa1"
FLEX = bytes([0, 1, 2, 250, 251, 252, 253, 254, 255])
TEXTISH_HEX = b"abcdef123456"  # a circuit-id an operator typed as hex text — NOT damage, must never be touched


def _conn(database=None):
    kw = {k: v for k, v in TEST_DB.items() if k != "database"}
    if database is not False:
        kw["database"] = database or TEST_DB["database"]
    return pymysql.connect(**kw, cursorclass=pymysql.cursors.DictCursor)


@pytest.fixture
def kea_tables(db):
    """The Kea-side tables, emptied before AND after: these tests own whatever is in them."""
    # children before parents: Kea's own foreign keys (Q127: this suite's schema has them now) say so
    tables = ["ipv6_reservations", "dhcp6_options", "dhcp4_options", "hosts", "lease4"]

    def wipe():
        db.commit()
        with db.cursor() as cur:
            for t in tables:
                cur.execute(f"DELETE FROM `{t}`")
        db.commit()

    wipe()
    yield db
    wipe()


def _seed(db):
    with db.cursor() as cur:
        cur.executemany(
            "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, "
            "hostname) VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (1, MAC, 0, 1, 167772161, "printer"),
                (2, DUID, 1, 1, 167772162, "deadbeef"),  # a hostname that LOOKS like hex stays text
                (3, CLIENT_ID, 3, 1, 167772163, "laptop"),
                (4, b"Gi0/0/1:vlan5", 2, 1, 167772164, "circuit"),
                (5, FLEX, 4, 1, 167772165, "flex"),
                (6, TEXTISH_HEX, 2, 1, 167772166, "texty"),
            ],
        )
        cur.executemany(
            "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "client_classes) VALUES (%s, %s, %s, %s, %s, %s, 3, '')",
            [
                (1, 6, NOT_UTF8, None, "dhcp4", 1),
                (2, 43, None, "text-value", "dhcp4", 2),
                (3, 3, bytes.fromhex("0a000001"), None, "dhcp4", 3),
            ],
        )
        cur.executemany(
            "INSERT INTO lease4 (address, hwaddr, client_id, valid_lifetime, subnet_id, hostname) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (167772300, MAC, CLIENT_ID, 3600, 1, "a"),
                (167772301, None, None, 3600, 1, "b"),
                (167772302, MAC2, b"\xde\xad\xbe\xef", 3600, 1, "c"),
            ],
        )
        # v6 (Q123 step 2): a DHCPv6 reservation by DUID, its address, and a v6 option whose value is not UTF-8
        cur.execute(
            "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname) "
            "VALUES (7, %s, 1, 2, 'v6host')",
            (bytes.fromhex("0001000127e4aa00") + MAC2,),
        )
        cur.execute(
            "INSERT INTO ipv6_reservations (reservation_id, address, prefix_len, type, dhcp6_iaid, host_id) "
            "VALUES (1, '2001:db8::10', 128, 0, 7, 7), (2, '2001:db8:1::', 56, 2, NULL, 7)"
        )
        cur.execute(
            "INSERT INTO dhcp6_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
            "client_classes) VALUES (1, 23, %s, NULL, 'dhcp6', 7, 3, ''), (2, 24, NULL, 'example.org', 'dhcp6', 7, 3, '')",
            (NOT_UTF8 + bytes([0]),),
        )
    db.commit()


def _snapshot(db):
    """Every column that matters, binary ones through HEX() so the comparison is on stored bytes."""
    db.commit()  # end the connection's read snapshot — another connection wrote since
    out = {}
    with db.cursor() as cur:
        cur.execute(
            "SELECT host_id, HEX(dhcp_identifier) AS ident, dhcp_identifier_type AS t, dhcp4_subnet_id AS s, "
            "ipv4_address AS ip, hostname FROM hosts ORDER BY host_id"
        )
        out["hosts"] = cur.fetchall()
        cur.execute(
            "SELECT option_id, code, HEX(value) AS val, formatted_value AS fv, space, host_id FROM dhcp4_options "
            "ORDER BY option_id"
        )
        out["dhcp4_options"] = cur.fetchall()
        cur.execute(
            "SELECT address, HEX(hwaddr) AS hw, HEX(client_id) AS cid, valid_lifetime AS vl, subnet_id AS s, "
            "hostname FROM lease4 ORDER BY address"
        )
        out["lease4"] = cur.fetchall()
        cur.execute(
            "SELECT option_id, code, HEX(value) AS val, formatted_value AS fv, space, host_id FROM dhcp6_options "
            "ORDER BY option_id"
        )
        out["dhcp6_options"] = cur.fetchall()
        cur.execute(
            "SELECT reservation_id, address, prefix_len, type, dhcp6_iaid, host_id FROM ipv6_reservations "
            "ORDER BY reservation_id"
        )
        out["ipv6_reservations"] = cur.fetchall()
    return out


def _read_gz(path) -> str:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return f.read()


def _payload(content: bytes) -> dict:
    return json.loads(gzip.decompress(content).decode("utf-8") if content[:2] == b"\x1f\x8b" else content)


class TestExportFormat3:
    def test_a_binary_value_is_a_tagged_object_and_text_that_looks_like_hex_stays_text(self, kea_tables):
        _seed(kea_tables)
        content, _ = dbexport.export_kea("reservations")
        payload = _payload(content)
        meta = payload["_meta"]
        assert meta["format"] == 3
        assert meta["binary_columns"]["hosts"] == ["dhcp_identifier"]
        assert "value" in meta["binary_columns"]["dhcp4_options"]
        h1 = next(r for r in payload["data"]["hosts"] if r["host_id"] == 1)
        assert h1["dhcp_identifier"] == {"$bin": MAC.hex()}
        h2 = next(r for r in payload["data"]["hosts"] if r["host_id"] == 2)
        assert h2["hostname"] == "deadbeef"  # a plain string that merely looks like hex is never converted
        opt1 = next(r for r in payload["data"]["dhcp4_options"] if r["option_id"] == 1)
        assert opt1["value"] == {"$bin": NOT_UTF8.hex()}

    def test_the_leases_group_tags_hwaddr_and_client_id(self, kea_tables):
        _seed(kea_tables)
        payload = _payload(dbexport.export_kea("leases")[0])
        assert set(payload["_meta"]["binary_columns"]["lease4"]) == {"hwaddr", "client_id"}


class TestRoundTripThroughExportAndImport:
    @pytest.mark.parametrize("group", ["reservations", "reservations_all", "leases"])
    def test_hex_of_every_binary_column_is_identical_after_wipe_and_import(self, kea_tables, group):
        _seed(kea_tables)
        before = _snapshot(kea_tables)
        content, _ = dbexport.export_kea(group)
        kea_tables.commit()
        with kea_tables.cursor() as cur:
            for t in ("ipv6_reservations", "dhcp6_options", "dhcp4_options", "lease4", "hosts"):
                cur.execute(f"DELETE FROM `{t}`")
        kea_tables.commit()

        results = dbexport.import_kea(content, "skip")

        assert not any(r.startswith("❌") for r in results), results
        after = _snapshot(kea_tables)
        tables = {
            "reservations": ["hosts", "dhcp4_options"],
            "reservations_all": ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"],
            "leases": ["lease4"],
        }[group]
        for t in tables:
            assert after[t] == before[t], f"{t} did not survive the round trip byte for byte"
        # the specific shape of the original bug: the MAC must be SIX bytes, not twelve characters of text
        if group != "leases":
            row = next(r for r in after["hosts"] if r["host_id"] == 1)
            assert row["ident"] == MAC.hex().upper()
            with kea_tables.cursor() as cur:
                cur.execute("SELECT LENGTH(dhcp_identifier) AS n FROM hosts WHERE host_id = 1")
                assert cur.fetchone()["n"] == 6

    def test_a_blob_that_is_not_valid_utf8_survives(self, kea_tables):
        _seed(kea_tables)
        content, _ = dbexport.export_kea("reservations")
        with kea_tables.cursor() as cur:
            cur.execute("DELETE FROM dhcp4_options")
            cur.execute("DELETE FROM hosts")
        kea_tables.commit()
        dbexport.import_kea(content, "skip")
        kea_tables.commit()
        with kea_tables.cursor() as cur:
            cur.execute("SELECT value FROM dhcp4_options WHERE option_id = 1")
            assert cur.fetchone()["value"] == NOT_UTF8

    def test_importing_over_existing_rows_in_skip_mode_changes_nothing(self, kea_tables):
        _seed(kea_tables)
        before = _snapshot(kea_tables)
        content, _ = dbexport.export_kea("reservations")
        dbexport.import_kea(content, "skip")
        assert _snapshot(kea_tables) == before


class TestTheBackupGroupIsEveryReservationV4AndV6:
    """Q123 (b): the scheduled and manual 'Kea' backup was two tables and no IPv6 at all."""

    def test_the_group_names_all_four_tables_in_foreign_key_order(self):
        grp = dbexport.KEA_EXPORT_GROUPS[dbexport.KEA_BACKUP_GROUP]
        assert dbexport.KEA_BACKUP_GROUP == "reservations_all"
        assert grp["tables"] == ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"]
        assert grp["label"] == "Kea host reservations (IPv4 and IPv6)"
        assert "lease4" not in grp["tables"], "leases are transient and never part of a backup"
        assert "Kea's database" not in grp["label"] + grp["description"]

    def test_the_export_carries_v6_reservations_and_options(self, kea_tables):
        _seed(kea_tables)
        payload = _payload(dbexport.export_kea("reservations_all")[0])
        assert payload["_meta"]["tables"] == ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"]
        assert payload["_meta"]["row_counts"]["ipv6_reservations"] == 2
        assert payload["_meta"]["row_counts"]["dhcp6_options"] == 2
        v6 = next(r for r in payload["data"]["hosts"] if r["host_id"] == 7)
        assert v6["dhcp_identifier"]["$bin"] == (bytes.fromhex("0001000127e4aa00") + MAC2).hex()
        assert "value" in payload["_meta"]["binary_columns"]["dhcp6_options"]

    def test_a_table_missing_on_this_kea_is_left_out_not_exported_empty(self, kea_tables):
        _seed(kea_tables)
        with kea_tables.cursor() as cur:
            cur.execute("RENAME TABLE dhcp6_options TO q123_gone")
        try:
            payload = _payload(dbexport.export_kea("reservations_all")[0])
        finally:
            with kea_tables.cursor() as cur:
                cur.execute("RENAME TABLE q123_gone TO dhcp6_options")
        assert "dhcp6_options" not in payload["data"] and "dhcp6_options" not in payload["_meta"]["tables"]
        assert "ipv6_reservations" in payload["data"]

    def test_an_import_restores_parents_before_the_rows_that_point_at_them(self, kea_tables):
        content = json.dumps(
            {
                "_meta": {"database": "kea", "jen_export_version": 1, "format": 3},
                "data": {  # deliberately in the WRONG order
                    "ipv6_reservations": [{"reservation_id": 1, "address": "2001:db8::1", "host_id": 7}],
                    "dhcp6_options": [{"option_id": 1, "code": 23, "value": {"$bin": "00ff"}, "host_id": 7}],
                    "hosts": [{"host_id": 7, "dhcp_identifier": {"$bin": MAC2.hex()}, "dhcp_identifier_type": 1}],
                },
            }
        ).encode("utf-8")
        results = dbexport.import_kea(content, "skip")
        tables = [r.split(":")[0].split()[-1] for r in results]
        assert tables == ["hosts", "dhcp6_options", "ipv6_reservations"]

    def test_migrate_kea_carries_the_v6_tables_by_default(self):
        import inspect

        assert inspect.signature(dbexport.migrate_kea).parameters["group"].default == "reservations_all"


class TestTheKeaExportIsStreamed:
    """Q123 (c): write_kea_export is the Kea twin of write_jen_export — rows one at a time, `_meta` last."""

    def test_writes_a_readable_gzip_document_with_meta_after_data(self, kea_tables, tmp_path):
        _seed(kea_tables)
        path = tmp_path / "kea.json.gz"
        meta = dbexport.write_kea_export(str(path), "reservations_all")
        raw = _read_gz(path)
        assert raw.index('"_meta"') > raw.index('"data"'), "_meta is written last, after every row"
        doc = json.loads(raw)
        assert doc["_meta"]["row_counts"] == meta["row_counts"]
        assert doc["_meta"]["format"] == 3
        assert meta["uncompressed_bytes"] == len(raw.encode("utf-8"))
        assert meta["row_counts"]["hosts"] == 7

    def test_the_file_is_0600(self, kea_tables, tmp_path):
        path = tmp_path / "kea.json.gz"
        dbexport.write_kea_export(str(path), "reservations_all")
        if os.name == "posix":
            assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def test_export_kea_is_a_thin_wrapper_that_still_returns_uncompressed_json_bytes(self, kea_tables):
        _seed(kea_tables)
        content, filename = dbexport.export_kea("reservations")
        assert filename.startswith("kea-reservations-export-") and filename.endswith(".json.gz")
        assert json.loads(content)["_meta"]["group"] == "reservations"

    def test_an_unknown_group_is_refused(self, tmp_path):
        with pytest.raises(ValueError):
            dbexport.write_kea_export(str(tmp_path / "x.json.gz"), "nope")

    def test_the_export_never_materialises_the_table_dict_again(self):
        import inspect

        src = inspect.getsource(dbexport.export_kea) + inspect.getsource(dbexport.write_kea_export)
        assert "_dump_table" not in src and 'payload["data"]' not in src

    def test_the_download_route_streams_and_leaves_no_tmp_file(
        self, logged_in_client, kea_tables, tmp_path, monkeypatch
    ):
        from jen import extensions

        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(tmp_path))
        _seed(kea_tables)
        r = logged_in_client.post("/database/export/kea", data={"group": "reservations_all"})
        assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
        doc = json.loads(gzip.decompress(r.data))
        assert doc["_meta"]["tables"] == ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"]
        assert list(tmp_path.iterdir()) == [], "the streamed download must remove its temp file"


class TestBackupsWriteTheReservationsGroup:
    def _schedule(self, db):
        with db.cursor() as cur:
            cur.execute(
                "REPLACE INTO backup_schedule (id, enabled, frequency, hour, keep_count, include_jen, include_kea) "
                "VALUES (1, 1, 'daily', 3, 7, 0, 1)"
            )
        db.commit()

    def test_the_scheduled_backup_is_the_v4_and_v6_group_with_a_sidecar_and_the_right_label(
        self, kea_tables, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        _seed(kea_tables)
        self._schedule(kea_tables)
        dbexport.run_scheduled_backup()
        backup = next(tmp_path.glob("kea-scheduled-*.json.gz"))
        doc = json.loads(_read_gz(backup))
        assert doc["_meta"]["group"] == "reservations_all"
        assert doc["data"]["ipv6_reservations"], "the v6 reservations are in the scheduled backup now"
        with open(dbexport._sidecar_path(str(backup)), encoding="utf-8") as f:
            side = json.load(f)
        assert side["database"] == "kea" and side["uncompressed_bytes"] > 0
        assert side["tables"] == ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"]
        kea_tables.commit()
        with kea_tables.cursor() as cur:
            cur.execute("SELECT last_status FROM backup_schedule WHERE id=1")
            assert dbexport.KEA_BACKUP_LABEL in cur.fetchone()["last_status"]

    def test_a_failing_kea_backup_leaves_no_file(self, kea_tables, monkeypatch, tmp_path):
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        self._schedule(kea_tables)

        def boom(*a, **k):
            raise RuntimeError("simulated")

        monkeypatch.setattr(dbexport, "write_kea_export", boom)
        dbexport.run_scheduled_backup()
        assert list(tmp_path.glob("kea-scheduled-*")) == [] and not list(tmp_path.glob(".part-*"))

    def test_the_manual_backup_writes_the_same_group(self, logged_in_client, kea_tables, monkeypatch, tmp_path):
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        _seed(kea_tables)
        r = logged_in_client.post("/database/backup/now", data={"include": ["kea"]}, follow_redirects=True)
        assert r.status_code == 200
        backup = next(tmp_path.glob("kea-manual-*.json.gz"))
        assert json.loads(_read_gz(backup))["_meta"]["group"] == "reservations_all"
        assert b"Kea host reservations (IPv4 and IPv6)" in r.data
        assert next(tmp_path.glob("kea-manual-*.meta.json")).is_file()

    def test_no_backup_label_says_kea_database(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        assert "Kea's database" not in (root / "templates/setup_recovery.html").read_text(encoding="utf-8")
        db_page = (root / "templates/database.html").read_text(encoding="utf-8")

        def tab(name):  # from this tab's opening marker to the next tab's — never to the first {% endif %}
            start = db_page.index("{% if active_tab == '" + name + "' %}")
            nxt = db_page.find("{% if active_tab ==", start + 1)
            return db_page[start : nxt if nxt != -1 else len(db_page)]

        for t in (tab("schedule"), tab("backups")):
            assert "Kea Database" not in t and "Kea host reservations (IPv4 and IPv6)" in t


class TestAFileWrittenBeforeThisFix:
    """Formats 1 and 2 wrote a binary value as a bare hex string. Those files exist on every box that ever
    took a backup; they must import correctly now, decoded by the TARGET's own column types."""

    def _old_file(self, fmt, hosts, options=None):
        meta = {"database": "kea", "jen_export_version": 1, "tables": ["hosts", "dhcp4_options"]}
        if fmt:
            meta["format"] = fmt
        return json.dumps({"_meta": meta, "data": {"hosts": hosts, "dhcp4_options": options or []}}).encode("utf-8")

    @pytest.mark.parametrize("fmt", [None, 2])
    def test_hex_strings_in_binary_columns_are_decoded(self, kea_tables, fmt):
        content = self._old_file(
            fmt,
            [
                {
                    "host_id": 1,
                    "dhcp_identifier": MAC.hex(),
                    "dhcp_identifier_type": 0,
                    "dhcp4_subnet_id": 1,
                    "ipv4_address": 167772161,
                    "hostname": "deadbeef",
                }
            ],
            [{"option_id": 1, "code": 6, "value": NOT_UTF8.hex(), "space": "dhcp4", "host_id": 1}],
        )
        results = dbexport.import_kea(content, "skip")
        assert not any(r.startswith("❌") for r in results), results
        snap = _snapshot(kea_tables)
        assert snap["hosts"][0]["ident"] == MAC.hex().upper()
        assert snap["hosts"][0]["hostname"] == "deadbeef"  # a string bound for a TEXT column is never decoded
        assert snap["dhcp4_options"][0]["val"] == NOT_UTF8.hex().upper()

    def test_a_value_that_is_not_valid_hex_refuses_that_table_by_name_and_inserts_nothing(self, kea_tables):
        content = self._old_file(
            2,
            [
                {"host_id": 1, "dhcp_identifier": MAC.hex(), "dhcp_identifier_type": 0},
                {"host_id": 2, "dhcp_identifier": "zz11", "dhcp_identifier_type": 0},
            ],
            [
                {
                    "option_id": 1,
                    "code": 3,
                    "value": "0a000001",
                    "space": "dhcp4",
                    "host_id": 1,
                    "scope_id": 3,
                    "client_classes": "",
                }
            ],
        )
        results = dbexport.import_kea(content, "skip")
        refused = [r for r in results if r.startswith("❌")]
        assert len(refused) == 1 and "hosts.dhcp_identifier" in refused[0] and "row 2" in refused[0]
        snap = _snapshot(kea_tables)
        assert not snap["hosts"], "the table with an undecodable value must be refused whole, not half-restored"
        assert snap["dhcp4_options"][0]["val"] == "0A000001", "an unrelated table is still imported"

    def test_odd_length_hex_is_refused_too(self, kea_tables):
        content = self._old_file(2, [{"host_id": 1, "dhcp_identifier": "abc", "dhcp_identifier_type": 0}])
        assert any(r.startswith("❌") for r in dbexport.import_kea(content, "skip"))
        assert not _snapshot(kea_tables)["hosts"]

    def test_a_format3_file_with_a_bare_string_in_a_binary_column_is_refused(self, kea_tables):
        content = json.dumps(
            {
                "_meta": {"database": "kea", "jen_export_version": 1, "format": 3, "tables": ["hosts"]},
                "data": {"hosts": [{"host_id": 1, "dhcp_identifier": "341343e60e2a", "dhcp_identifier_type": 0}]},
            }
        ).encode("utf-8")
        results = dbexport.import_kea(content, "skip")
        assert any(r.startswith("❌") and "tags every binary value" in r for r in results), results
        assert not _snapshot(kea_tables)["hosts"]

    def test_a_tagged_value_with_invalid_hex_is_refused(self, kea_tables):
        content = json.dumps(
            {
                "_meta": {"database": "kea", "jen_export_version": 1, "format": 3, "tables": ["hosts"]},
                "data": {"hosts": [{"host_id": 1, "dhcp_identifier": {"$bin": "xyz"}, "dhcp_identifier_type": 0}]},
            }
        ).encode("utf-8")
        assert any(r.startswith("❌") for r in dbexport.import_kea(content, "skip"))


class TestMigration:
    """A migration is a copy between two live databases: bytes as bytes, nothing through JSON. (The Kea
    migration — which needs an INITIALISED Kea target since Q127 — is in tests/test_migrate_contract.py.)"""

    @pytest.fixture
    def scratch(self):
        name = "jen_test_q123_target"
        try:
            admin = _conn(False)
            with admin.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
                cur.execute(f"CREATE DATABASE `{name}`")
            admin.commit()
            admin.close()
        except pymysql.err.OperationalError as e:
            if os.environ.get("CI"):
                pytest.fail(f"CI must let the test user create `jen_test_%` scratch databases ({e})")
            pytest.skip(f"this database user cannot create a scratch database: {e}")
        yield name
        admin = _conn(False)
        with admin.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
        admin.commit()
        admin.close()

    def _target(self, name):
        return _conn(name)

    def test_copy_table_rows_keeps_bytes_datetimes_and_decimals_exact(self, db, scratch):
        ddl = "CREATE TABLE q123_copy (id INT PRIMARY KEY, b BLOB, ts DATETIME(6), n DECIMAL(10,2), t VARCHAR(20))"
        with db.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS q123_copy")
            cur.execute(ddl)
            cur.executemany(
                "INSERT INTO q123_copy VALUES (%s, %s, %s, %s, %s)",
                [
                    (i, NOT_UTF8 * ((i % 3) + 1), f"2026-10-02 12:00:00.{i:06d}", f"{i}.50", "deadbeef")
                    for i in range(2500)
                ],
            )
        db.commit()
        tgt = self._target(scratch)
        try:
            with tgt.cursor() as cur:
                cur.execute(ddl)
            tgt.commit()
            count = dbexport._copy_table_rows(db, tgt, "q123_copy", batch=1000)  # three batches
            tgt.commit()
            assert count == 2500
            q = "SELECT id, HEX(b) AS b, ts, n, t FROM q123_copy ORDER BY id"
            with tgt.cursor() as cur:
                cur.execute(q)
                copied = cur.fetchall()
            db.commit()
            with db.cursor() as cur:
                cur.execute(q)
                original = cur.fetchall()
            assert copied == original
            assert copied[1]["t"] == "deadbeef"
        finally:
            tgt.close()
            with db.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS q123_copy")
            db.commit()

    def test_migrate_jen_copies_rows_through_the_same_helper(self, db, scratch):
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key = '_q123_migrate_probe'")
            cur.execute("INSERT INTO settings (setting_key, setting_value) VALUES ('_q123_migrate_probe', 'ünï')")
        db.commit()
        try:
            dbexport.migrate_jen(
                TEST_DB["host"],
                int(os.environ.get("JEN_DB_PORT", 3306)),
                TEST_DB["user"],
                TEST_DB["password"],
                scratch,
                tables=["settings"],
            )
            tgt = self._target(scratch)
            try:
                with tgt.cursor() as cur:
                    cur.execute("SELECT setting_value FROM settings WHERE setting_key = '_q123_migrate_probe'")
                    assert cur.fetchone()["setting_value"] == "ünï"
            finally:
                tgt.close()
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM settings WHERE setting_key = '_q123_migrate_probe'")
            db.commit()


class TestRecognisingDamage:
    def test_find_damaged_flags_exactly_the_damaged_rows(self, kea_tables):
        _seed(kea_tables)
        with kea_tables.cursor() as cur:
            cur.executemany(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, "
                "hostname) VALUES (%s, %s, %s, %s, %s, %s)",
                [
                    (20, MAC2.hex().encode(), 0, 1, 167772400, "damaged-mac"),
                    (21, DUID.hex().encode(), 1, 1, 167772401, "damaged-duid"),
                    (22, CLIENT_ID.hex().encode(), 3, 1, 167772402, "damaged-clientid"),
                ],
            )
        kea_tables.commit()
        conn = dbexport._direct_kea_conn()
        try:
            found = kea_identifiers.find_damaged(conn)
        finally:
            conn.close()
        assert [d["host_id"] for d in found] == [20, 21, 22]
        d = found[0]
        assert d["stored_text"] == MAC2.hex() and d["repaired"] == "00:11:22:33:44:ff" and d["repaired_bytes"] == 6
        assert d["ipv4"] == "10.0.0.240" and d["type_name"] == "hw-address"

    def test_repair_converts_exactly_those_rows_and_nothing_else(self, kea_tables):
        _seed(kea_tables)
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, hostname) "
                "VALUES (20, %s, 0, 1, 'damaged'), (21, %s, 1, 3, 'damaged-duid')",
                (MAC2.hex().encode(), DUID.hex().encode()),
            )
        kea_tables.commit()
        untouched = [r for r in _snapshot(kea_tables)["hosts"] if r["host_id"] < 20]
        conn = dbexport._direct_kea_conn()
        try:
            results = kea_identifiers.repair(conn)
            assert kea_identifiers.find_damaged(conn) == []
        finally:
            conn.close()
        assert [r["status"] for r in results] == ["repaired", "repaired"]
        snap = _snapshot(kea_tables)
        by_id = {r["host_id"]: r for r in snap["hosts"]}
        assert by_id[20]["ident"] == MAC2.hex().upper()
        assert by_id[21]["ident"] == DUID.hex().upper()
        assert [r for r in snap["hosts"] if r["host_id"] < 20] == untouched, "a healthy row was modified"

    def test_repair_limited_to_the_rows_the_operator_chose(self, kea_tables):
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type) VALUES (20, %s, 0), (21, %s, 0)",
                (MAC.hex().encode(), MAC2.hex().encode()),
            )
        kea_tables.commit()
        conn = dbexport._direct_kea_conn()
        try:
            results = kea_identifiers.repair(conn, host_ids=[21])
        finally:
            conn.close()
        assert [r["host_id"] for r in results] == [21]
        by_id = {r["host_id"]: r["ident"] for r in _snapshot(kea_tables)["hosts"]}
        assert by_id[21] == MAC2.hex().upper()
        assert by_id[20] == MAC.hex().encode().hex().upper(), "the unchosen damaged row must stay exactly as it was"

    def test_a_row_edited_after_the_preview_is_left_alone(self, kea_tables, monkeypatch):
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type) VALUES (20, %s, 0)",
                (MAC.hex().encode(),),
            )
        kea_tables.commit()
        conn = dbexport._direct_kea_conn()
        try:
            real = kea_identifiers.find_damaged

            def stale(c):
                found = real(c)
                with c.cursor() as cur:  # somebody fixes the row by hand between preview and repair
                    cur.execute("UPDATE hosts SET dhcp_identifier = %s WHERE host_id = 20", (MAC,))
                return found

            monkeypatch.setattr(kea_identifiers, "find_damaged", stale)
            results = kea_identifiers.repair(conn)
        finally:
            conn.close()
        assert results[0]["status"] == "skipped" and "changed since" in results[0]["detail"]
        assert _snapshot(kea_tables)["hosts"][0]["ident"] == MAC.hex().upper()

    def test_a_collision_with_the_correct_row_is_skipped_and_the_damaged_row_left_as_it_was(self, kea_tables):
        with kea_tables.cursor() as cur:
            cur.execute("ALTER TABLE hosts ADD UNIQUE KEY q123_tmp_uniq (dhcp_identifier, dhcp_identifier_type)")
        try:
            with kea_tables.cursor() as cur:
                cur.execute(
                    "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type) VALUES "
                    "(20, %s, 0), (21, %s, 0)",
                    (MAC.hex().encode(), MAC),  # the operator already re-created the reservation correctly
                )
            kea_tables.commit()
            conn = dbexport._direct_kea_conn()
            try:
                results = kea_identifiers.repair(conn)
            finally:
                conn.close()
            assert results[0]["status"] == "skipped" and "left unchanged" in results[0]["detail"]
            by_id = {r["host_id"]: r["ident"] for r in _snapshot(kea_tables)["hosts"]}
            assert by_id[20] == MAC.hex().encode().hex().upper()
            assert by_id[21] == MAC.hex().upper()
        finally:
            kea_tables.commit()
            with kea_tables.cursor() as cur:
                cur.execute("DELETE FROM hosts")
                cur.execute("ALTER TABLE hosts DROP INDEX q123_tmp_uniq")
            kea_tables.commit()


class TestHealthCheck:
    def test_ok_when_nothing_is_damaged(self, kea_tables):
        _seed(kea_tables)
        c = health._kea_identifiers({"unrestricted": True})
        assert c.id == "kea_identifiers" and c.status == "ok", c.detail

    def test_fails_naming_the_count_when_a_row_is_damaged(self, kea_tables):
        _seed(kea_tables)
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type) VALUES (20, %s, 0)",
                (MAC.hex().encode(),),
            )
        kea_tables.commit()
        c = health._kea_identifiers({"unrestricted": True})
        assert c.status == "fail" and "1 of 8" in c.detail  # seven seeded hosts + the damaged one
        assert c.fix_url == "/database/kea-identifiers"

    def test_a_restricted_caller_never_sees_the_fleet_wide_count(self, kea_tables):
        assert health._kea_identifiers({"unrestricted": False}).status == "skip"

    def test_it_is_registered_in_the_jen_group_beside_the_kea_database_check(self):
        ids = health.CHECK_IDS
        assert ids.index("kea_identifiers") == ids.index("db_kea") + 1
        assert health._CHECK_META["kea_identifiers"][1] == "jen"


class TestRepairPage:
    def test_get_is_a_read_only_preview_with_before_and_after(self, logged_in_client, kea_tables):
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, ipv4_address, hostname) "
                "VALUES (20, %s, 0, 167772400, 'oldprinter')",
                (MAC.hex().encode(),),
            )
        kea_tables.commit()
        r = logged_in_client.get("/database/kea-identifiers")
        body = r.data.decode()
        assert r.status_code == 200
        assert "oldprinter" in body and MAC.hex() in body and "34:13:43:e6:0e:2a" in body
        assert _snapshot(kea_tables)["hosts"][0]["ident"] == MAC.hex().encode().hex().upper(), "GET must not repair"

    def test_post_repairs_the_ticked_rows(self, logged_in_client, kea_tables):
        with kea_tables.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type) VALUES (20, %s, 0), (21, %s, 0)",
                (MAC.hex().encode(), MAC2.hex().encode()),
            )
        kea_tables.commit()
        r = logged_in_client.post("/database/kea-identifiers/repair", data={"host_id": ["20"]})
        assert r.status_code == 200
        by_id = {x["host_id"]: x["ident"] for x in _snapshot(kea_tables)["hosts"]}
        assert by_id[20] == MAC.hex().upper()
        assert by_id[21] == MAC2.hex().encode().hex().upper()

    def test_post_with_nothing_ticked_changes_nothing(self, logged_in_client, kea_tables):
        r = logged_in_client.post("/database/kea-identifiers/repair", data={}, follow_redirects=False)
        assert r.status_code == 302

    def test_a_clean_database_says_there_is_nothing_to_repair(self, logged_in_client, kea_tables):
        _seed(kea_tables)
        assert b"Nothing to repair" in logged_in_client.get("/database/kea-identifiers").data
