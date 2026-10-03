"""
tests/kea_compat/test_db_moves.py
──────────────────────────────────
Q127 — Jen's database moves (import, merge, overwrite, migrate, the reservation export) against the REAL
Kea schema: the database `kea-admin db-init` created in kea-compat.yml, with ISC's own unique keys, foreign
keys, lookup tables and `schema_version` row. Jen's unit suite had the Kea tables trimmed to the columns its
queries touch — no unique key but the primary key, no foreign key, no lookup table — which is why none of
the following could ever have failed there.

Everything here runs against throwaway rows of this suite's own (identifiers starting 02:71…, subnets 71/72,
every option's `formatted_value` starting "q127") and, for migrations, a scratch database initialised from
the real one. Nothing is ever sent to the daemon except the one reservation-add that discovers which
`scope_id` Kea itself gives a host's options.

When this module was written (Q127 step 1) the cases the code of that day got wrong were held as `known_bug`
(xfail, strict, raises=AssertionError — a setup mistake still failed loudly) and showed as a known bug in the
summary table; they came off, one step at a time, as the migration contract (step 2) and the import / export
fixes (step 3) landed, and none remain: every test here passes on Kea 3.0.3, 3.2.0 and 3.3.1. A new real-schema
case that exposes a bug in the code should be added the same way — marked, then unmarked by its fix.

Every test skips unless KEA_COMPAT_URL AND KEA_COMPAT_DB_HOST are set (kea-compat.yml sets both).
"""

import json
import os
import re
import socket

import pymysql
import pymysql.cursors
import pytest

from jen.services import dbexport
from jen.services import kea as __kea

DB_HOST = os.environ.get("KEA_COMPAT_DB_HOST", "")
DB_PORT = int(os.environ.get("KEA_COMPAT_DB_PORT", "3306") or 3306)
DB_USER = os.environ.get("KEA_COMPAT_DB_USER", "kea")
DB_PASS = os.environ.get("KEA_COMPAT_DB_PASS", "kea_pw")
DB_NAME = os.environ.get("KEA_COMPAT_DB_NAME", "kea")
ROOT_PASS = os.environ.get("KEA_COMPAT_DB_ROOT_PASS", "ci_root_pw")
SCHEMA_OUT = os.environ.get("KEA_COMPAT_SCHEMA_OUT", "")

pytestmark = [
    pytest.mark.kea_compat,
    pytest.mark.skipif(not DB_HOST, reason="KEA_COMPAT_DB_HOST not set - the database half of the real-Kea suite"),
]


# ── connections, the schema the daemon's database really has ───────────────────────────────────────


def _connect(database=DB_NAME, user=DB_USER, password=DB_PASS):
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        charset="utf8mb4",
    )


def _root(database=None):
    return _connect(database=database, user="root", password=ROOT_PASS)


@pytest.fixture(scope="module", autouse=True)
def _point_jen_at_the_compat_database():
    from jen import extensions

    names = ("KEA_DB_HOST", "KEA_DB_PORT", "KEA_DB_USER", "KEA_DB_PASS", "KEA_DB_NAME", "KEA_DB_SSL_CA")
    saved = {n: getattr(extensions, n, None) for n in names}
    extensions.KEA_DB_HOST, extensions.KEA_DB_PORT = DB_HOST, DB_PORT
    extensions.KEA_DB_USER, extensions.KEA_DB_PASS = DB_USER, DB_PASS
    extensions.KEA_DB_NAME, extensions.KEA_DB_SSL_CA = DB_NAME, ""
    yield
    for n, v in saved.items():
        setattr(extensions, n, v)


@pytest.fixture
def kea():
    c = _connect()
    _clean(c)
    yield c
    _clean(c)
    c.close()


def _clean(c):
    """Remove exactly what this module creates (children before parents: Kea's own foreign keys say so)."""
    with c.cursor() as cur:
        cur.execute("SET @disable_audit = 1")  # global/subnet/class rows fire the config-backend audit trigger
        cur.execute("SELECT host_id FROM hosts WHERE HEX(dhcp_identifier) LIKE '0271%'")
        ids = [r["host_id"] for r in cur.fetchall()]
        for tbl in ("dhcp4_options", "dhcp6_options"):
            cur.execute(f"DELETE FROM {tbl} WHERE formatted_value LIKE 'q127%'")
        if ids:
            marks = ", ".join(["%s"] * len(ids))
            for tbl in ("dhcp4_options", "dhcp6_options", "ipv6_reservations"):
                cur.execute(f"DELETE FROM {tbl} WHERE host_id IN ({marks})", ids)
            cur.execute(f"DELETE FROM hosts WHERE host_id IN ({marks})", ids)


def _mac(n: int) -> bytes:
    return bytes([0x02, 0x71, 0, 0, 0, n])


def _ip(n: int) -> int:
    return (10 << 24) | (71 << 16) | n  # 10.71.0.n


def add_host(c, n, *, itype=0, sub4=71, sub6=None, hostname=None, host_id=None):
    cols = {
        "dhcp_identifier": _mac(n),
        "dhcp_identifier_type": itype,
        "dhcp4_subnet_id": sub4,
        "dhcp6_subnet_id": sub6,
        "ipv4_address": _ip(n) if sub4 is not None else None,
        "hostname": hostname or f"q127-h{n}",
    }
    if host_id is not None:
        cols["host_id"] = host_id
    with c.cursor() as cur:
        cur.execute(
            f"INSERT INTO hosts ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})", list(cols.values())
        )
        return host_id if host_id is not None else cur.lastrowid


def _requires_a_value(c, table, column):
    """True when the REAL table has `column` NOT NULL without a default — the 3.x options tables' `client_classes`
    (longtext NOT NULL) is the one this found: an INSERT that omits it is an error in strict mode."""
    r = rows(
        c,
        "SELECT is_nullable, column_default FROM information_schema.columns "
        "WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s",
        table,
        column,
    )
    return bool(r) and r[0]["is_nullable"] == "NO" and r[0]["column_default"] is None


def add_option(c, table, host_id, code, value: bytes, *, scope=3, tag="q127", **extra):
    cols = {"code": code, "value": value, "formatted_value": tag, "space": "dhcp4", "scope_id": scope}
    cols["host_id"] = host_id
    if _requires_a_value(c, table, "client_classes"):
        cols["client_classes"] = ""
    cols.update(extra)
    with c.cursor() as cur:
        if host_id is None:
            # a global/subnet/class option fires Kea's config-backend audit trigger, which needs a revision the
            # session has not opened; Kea's own tooling sets this session variable to write such rows directly
            cur.execute("SET @disable_audit = 1")
        cur.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})", list(cols.values())
        )
        return cur.lastrowid


def v6(address: str) -> bytes:
    """The REAL schema stores ipv6_reservations.address as binary(16) (every Kea 3.x this suite runs against)."""
    return socket.inet_pton(socket.AF_INET6, address)


def add_v6(c, host_id, address):
    with c.cursor() as cur:
        cur.execute(
            "INSERT INTO ipv6_reservations (address, prefix_len, type, host_id) VALUES (%s, 128, 0, %s)",
            (v6(address), host_id),
        )
        return cur.lastrowid


def rows(c, sql, *params):
    with c.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def norm(v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def snapshot(c, tables):
    """{table: [row, ...]} with bytes as hex — or "<missing>" for a table that is not there."""
    out = {}
    for t in tables:
        if not rows(c, "SHOW TABLES LIKE %s", t):
            out[t] = "<missing>"
            continue
        out[t] = sorted(
            ({k: norm(v) for k, v in r.items()} for r in rows(c, f"SELECT * FROM `{t}`")),
            key=lambda r: json.dumps(r, sort_keys=True, default=str),
        )
    return out


def kea_file(*, hosts=(), dhcp4_options=(), dhcp6_options=(), ipv6_reservations=(), fmt=3):
    """An export file in format 3: what a Jen backup of these rows looks like."""
    data = {}
    for name, rs in (
        ("hosts", hosts),
        ("dhcp4_options", dhcp4_options),
        ("dhcp6_options", dhcp6_options),
        ("ipv6_reservations", ipv6_reservations),
    ):
        if rs:
            data[name] = list(rs)
    meta = {"database": "kea", "jen_export_version": 1, "format": fmt, "tables": list(data)}
    return json.dumps({"_meta": meta, "data": data}).encode("utf-8")


def tag(b: bytes) -> dict:
    return {"$bin": b.hex()}


def host_row(n, host_id, *, itype=0, sub4=71, sub6=None, hostname=None):
    return {
        "host_id": host_id,
        "dhcp_identifier": tag(_mac(n)),
        "dhcp_identifier_type": itype,
        "dhcp4_subnet_id": sub4,
        "dhcp6_subnet_id": sub6,
        "ipv4_address": _ip(n) if sub4 is not None else None,
        "hostname": hostname or f"q127-h{n}",
    }


def option_row(option_id, host_id, code, value: bytes, *, scope=3, tag_text="q127"):
    return {
        "option_id": option_id,
        "code": code,
        "value": tag(value),
        "formatted_value": tag_text,
        "space": "dhcp4",
        "persistent": 0,
        "host_id": host_id,
        "scope_id": scope,
    }


# ── the schema facts the rest of Q127 is built on ────────────────────────────────────────────


KEA_TABLES = (
    "hosts",
    "dhcp4_options",
    "dhcp6_options",
    "ipv6_reservations",
    "lease4",
    "lease6",
    "host_identifier_type",
    "dhcp_option_scope",
    "schema_version",
)


def schema_facts(c):
    facts = {"kea_version": os.environ.get("KEA_COMPAT_VERSION", ""), "create": {}}
    for t in KEA_TABLES:
        r = rows(c, f"SHOW CREATE TABLE `{t}`")
        facts["create"][t] = next(v for k, v in r[0].items() if "Create" in k)
    facts["foreign_keys"] = [
        {k.lower(): v for k, v in r.items()}
        for r in rows(
            c,
            "SELECT constraint_name, table_name, referenced_table_name, delete_rule, update_rule "
            "FROM information_schema.referential_constraints WHERE constraint_schema = DATABASE() "
            "ORDER BY table_name, constraint_name",
        )
    ]
    facts["indexes"] = [
        {k.lower(): v for k, v in r.items()}
        for r in rows(
            c,
            "SELECT table_name, index_name, non_unique, GROUP_CONCAT(column_name ORDER BY seq_in_index) AS cols "
            "FROM information_schema.statistics WHERE table_schema = DATABASE() "
            "AND table_name IN ('hosts','dhcp4_options','dhcp6_options','ipv6_reservations') "
            "GROUP BY table_name, index_name, non_unique ORDER BY table_name, index_name",
        )
    ]
    # v5.67.0-beta.16 (Q130) — the address and identifier columns Jen READS, as information_schema reports them
    # for THIS Kea version: lease6.address (and ipv6_reservations.address / excluded_prefix) is what decides whether
    # jen/services/kea6.py must convert 16 raw bytes to text, hosts.dhcp_identifier and lease6.duid are the
    # varbinary identifiers, lease4.address the unsigned int. Recorded per version in the schema artifact, and
    # asserted by test_the_v6_address_columns_are_binary_sixteen.
    facts["address_columns"] = {
        f"{r['tname']}.{r['cname']}": {"data_type": r["dtype"], "column_type": r["ctype"]}
        for r in rows(
            c,
            "SELECT table_name AS tname, column_name AS cname, data_type AS dtype, column_type AS ctype "
            "FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND ("
            "(table_name = 'lease6' AND column_name IN ('address', 'duid', 'hwaddr')) OR "
            "(table_name = 'lease4' AND column_name IN ('address', 'hwaddr', 'client_id')) OR "
            "(table_name = 'ipv6_reservations' AND column_name IN ('address', 'excluded_prefix')) OR "
            "(table_name = 'hosts' AND column_name = 'dhcp_identifier')) "
            "ORDER BY table_name, column_name",
        )
    }
    facts["option_scope"] = rows(c, "SELECT scope_id, scope_name FROM dhcp_option_scope ORDER BY scope_id")
    facts["host_identifier_type"] = rows(c, "SELECT type, name FROM host_identifier_type ORDER BY type")
    facts["schema_version"] = rows(c, "SELECT version, minor FROM schema_version")
    return facts


def test_schema_facts_and_the_scope_kea_gives_a_hosts_options(kea):
    """Records what ISC's schema really is (uploaded with the run's results) and discovers, through the
    daemon's own reservation-add, which scope_id Kea writes for a HOST's options — the number the reservation
    backup filters on. Everything Q127 assumes about foreign-key delete rules and unique keys is read from
    here, never remembered."""
    facts = schema_facts(kea)
    mac = "02:71:00:00:00:f1"
    by_mac = {"subnet-id": 1, "identifier-type": "hw-address", "identifier": mac}
    __kea.kea_command("reservation-del", arguments=by_mac)
    reply = __kea.kea_command(
        "reservation-add",
        arguments={
            "reservation": {
                "subnet-id": 1,
                "hw-address": mac,
                "ip-address": "10.99.0.171",
                "hostname": "q127-scope",
                "option-data": [{"name": "domain-name-servers", "data": "10.99.0.53"}],
            }
        },
    )
    try:
        assert reply.get("result") == 0, reply
        found = rows(
            kea,
            "SELECT o.scope_id, o.code, o.host_id FROM dhcp4_options o JOIN hosts h ON h.host_id = o.host_id "
            "WHERE h.hostname = 'q127-scope'",
        )
        facts["host_option_rows_written_by_kea"] = found
    finally:
        __kea.kea_command("reservation-del", arguments=by_mac)
    if SCHEMA_OUT:
        with open(SCHEMA_OUT, "w", encoding="utf-8") as f:
            json.dump(facts, f, indent=2, default=str)
    assert facts["schema_version"], "an initialised Kea database has a schema_version row"
    assert found, "Kea wrote no dhcp4_options row for the reservation's option"
    scopes = {r["scope_id"] for r in found}
    assert len(scopes) == 1, f"one scope for a host's options, got {scopes}"
    named = {r["scope_id"]: r["scope_name"] for r in facts["option_scope"]}
    assert named.get(scopes.pop()) == "host", (named, found)


# ── (b) a merge attaches reservations to the wrong host ──────────────────────────────────────────


def test_merge_never_attaches_a_reservation_to_a_different_host(kea):
    camera = add_host(kea, 1, hostname="q127-camera")
    add_option(kea, "dhcp4_options", camera, 6, bytes([10, 71, 0, 53]), tag="q127-camera-dns")
    # the file's printer has the SAME host_id as the camera in the target, a different identity
    f = kea_file(
        hosts=[host_row(2, camera, hostname="q127-printer")],
        dhcp4_options=[option_row(900, camera, 6, bytes([10, 71, 0, 99]), tag_text="q127-printer-dns")],
    )
    dbexport.import_kea(f, "skip")
    hs = {
        r["hostname"]: r["host_id"]
        for r in rows(kea, "SELECT host_id, hostname FROM hosts WHERE hostname LIKE 'q127-%%'")
    }
    assert set(hs) == {"q127-camera", "q127-printer"}, f"the printer must be inserted as a new host: {hs}"
    assert hs["q127-printer"] != hs["q127-camera"]
    cam_opts = [
        r["formatted_value"]
        for r in rows(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id = %s", hs["q127-camera"])
    ]
    prn_opts = [
        r["formatted_value"]
        for r in rows(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id = %s", hs["q127-printer"])
    ]
    assert cam_opts == ["q127-camera-dns"], f"the camera's options changed: {cam_opts}"
    assert prn_opts == ["q127-printer-dns"], f"the printer's option landed elsewhere: {prn_opts}"


# ── (c) overwrite is REPLACE INTO ────────────────────────────────────────────────────────────────────


def test_overwrite_updates_in_place_and_keeps_the_children_the_file_does_not_carry(kea):
    h = add_host(kea, 3, sub6=72, hostname="q127-old")
    add_option(kea, "dhcp4_options", h, 6, bytes([10, 71, 0, 1]), tag="q127-old-dns")
    add_v6(kea, h, "2001:db8:71::3")
    add_option(kea, "dhcp6_options", h, 23, bytes([0x20, 0x01]), tag="q127-v6-dns", space="dhcp6")
    # an IPv4-only file (the `reservations` group): the same host, a new hostname, a new IPv4 option
    f = kea_file(
        hosts=[host_row(3, 9999, sub6=72, hostname="q127-new")],
        dhcp4_options=[option_row(901, 9999, 6, bytes([10, 71, 0, 2]), tag_text="q127-new-dns")],
    )
    dbexport.import_kea(f, "overwrite")
    hs = rows(kea, "SELECT host_id, hostname FROM hosts WHERE HEX(dhcp_identifier) LIKE '0271%%'")
    assert [(r["host_id"], r["hostname"]) for r in hs] == [(h, "q127-new")], f"updated in place, id stable: {hs}"
    v4 = [r["formatted_value"] for r in rows(kea, "SELECT formatted_value FROM dhcp4_options WHERE host_id = %s", h)]
    assert v4 == ["q127-new-dns"], f"the file's IPv4 options replace the host's: {v4}"
    kept = rows(kea, "SELECT address FROM ipv6_reservations WHERE host_id = %s", h)
    assert [bytes(r["address"]) for r in kept] == [v6("2001:db8:71::3")], f"the IPv6 reservation must survive: {kept}"
    o6 = rows(kea, "SELECT formatted_value FROM dhcp6_options WHERE host_id = %s", h)
    assert [r["formatted_value"] for r in o6] == ["q127-v6-dns"], f"the DHCPv6 option must survive: {o6}"


# ── (d) errors are not duplicates ─────────────────────────────────────────────────────────────────────


def test_a_foreign_key_failure_aborts_the_import_and_rolls_everything_back(kea):
    good = host_row(4, 7001, hostname="q127-good")
    bad = host_row(5, 7002, itype=99, hostname="q127-bad")  # no such row in host_identifier_type
    raised = None
    try:
        dbexport.import_kea(kea_file(hosts=[good, bad]), "skip")
    except Exception as e:
        raised = e
    assert raised is not None, "an FK violation is an error, not a 'skipped' row"
    left = rows(kea, "SELECT hostname FROM hosts WHERE hostname LIKE 'q127-%%'")
    assert not left, f"the import must roll back whole, the good row too: {left}"


def test_a_duplicate_in_skip_mode_is_skipped_and_counted_not_an_error(kea):
    add_host(kea, 6, hostname="q127-existing")
    out = dbexport.import_kea(kea_file(hosts=[host_row(6, 8001, hostname="q127-file-copy")]), "skip")
    assert any(line.startswith("✅") and "hosts" in line for line in out), out
    assert [
        r["hostname"] for r in rows(kea, "SELECT hostname FROM hosts WHERE HEX(dhcp_identifier) LIKE '0271%%'")
    ] == ["q127-existing"]


# ── (e) the reservation backup carries host options only ───────────────────────────────────────────


def test_the_backup_carries_host_scoped_options_only(kea):
    h = add_host(kea, 7)
    add_option(kea, "dhcp4_options", h, 6, bytes([1, 1, 1, 1]), tag="q127-host-scope", scope=3)
    add_option(kea, "dhcp4_options", None, 6, bytes([2, 2, 2, 2]), tag="q127-global-scope", scope=0)
    # the subnet and class rows carry no subnet id / class name: those are foreign keys into the config-backend
    # tables, which this database has no rows for; what the backup must filter on is scope_id and host_id
    add_option(kea, "dhcp4_options", None, 6, bytes([3, 3, 3, 3]), tag="q127-subnet-scope", scope=1)
    add_option(kea, "dhcp4_options", None, 6, bytes([4, 4, 4, 4]), tag="q127-class-scope", scope=2)
    content, _ = dbexport.export_kea("reservations_all")
    payload = json.loads(content)
    mine = [
        r["formatted_value"]
        for r in payload["data"]["dhcp4_options"]
        if str(r.get("formatted_value")).startswith("q127")
    ]
    assert mine == ["q127-host-scope"], f"only the host-scoped option belongs in a reservation backup: {mine}"


# ── (a) a migration never drops what was there ───────────────────────────────────────────────────────

MOVE_TABLES = (
    "hosts",
    "dhcp4_options",
    "dhcp6_options",
    "ipv6_reservations",
    "host_identifier_type",
    "dhcp_option_scope",
    "schema_version",
)


@pytest.fixture
def scratch():
    """A scratch database initialised from the real one: every table's real DDL, plus the lookup rows and the
    schema_version row — what `kea-admin db-init` leaves, which is what a migration's target must be."""
    name = "kea_q127_target"
    root = _root()
    with root.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
        cur.execute(f"CREATE DATABASE `{name}`")
    yield name
    with root.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
    root.close()


def initialise(name, *, with_data=True):
    src, tgt = _connect(), _root(name)
    with tgt.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for r in rows(src, "SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'"):
            t = next(iter(r.values()))
            ddl = next(v for k, v in rows(src, f"SHOW CREATE TABLE `{t}`")[0].items() if "Create" in k)
            cur.execute(ddl)
        if with_data:
            for t in ("host_identifier_type", "dhcp_option_scope", "schema_version"):
                for r in rows(src, f"SELECT * FROM `{t}`"):
                    cols = ", ".join(f"`{k}`" for k in r)
                    cur.execute(f"INSERT INTO `{t}` ({cols}) VALUES ({', '.join(['%s'] * len(r))})", list(r.values()))
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
    src.close()
    return tgt


def migrate(name, group="reservations_all"):
    return dbexport.migrate_kea(DB_HOST, DB_PORT, "root", ROOT_PASS, name, group=group)


def test_a_migration_into_an_initialised_empty_target_copies_every_row_byte_for_byte(kea, scratch):
    h = add_host(kea, 8, sub6=72)
    add_option(kea, "dhcp4_options", h, 6, bytes([0xFF, 0xFE, 0x00, 0x80]), tag="q127-bin")
    add_v6(kea, h, "2001:db8:71::8")
    tgt = initialise(scratch)
    migrate(scratch)
    for t in ("hosts", "dhcp4_options", "ipv6_reservations"):
        src_rows = list(snapshot(kea, [t])[t])
        dst_rows = snapshot(tgt, [t])[t]
        assert dst_rows == src_rows, f"{t} did not copy exactly"
    tgt.close()


def test_a_failed_migration_leaves_a_populated_target_byte_for_byte_as_it_was(kea, scratch):
    h = add_host(kea, 9, hostname="q127-source-host")
    add_option(kea, "dhcp4_options", h, 6, bytes([9, 9, 9, 9]), tag="q127-source-opt")
    tgt = initialise(scratch)
    # the target already has a DIFFERENT reservation under the same host_id: the copy must collide
    add_host(tgt, 99, hostname="q127-target-host", host_id=h)
    before = snapshot(tgt, MOVE_TABLES)
    failed = False
    try:
        migrate(scratch)
    except Exception:
        failed = True
    assert failed, "a primary-key collision in the target must fail the migration"
    after = snapshot(tgt, MOVE_TABLES)
    assert after == before, "the target must be exactly as it was — no table dropped, no row added or removed"
    tgt.close()


def test_a_target_that_is_not_an_initialised_kea_database_is_refused_and_left_empty(kea, scratch):
    add_host(kea, 10)
    refused = False
    try:
        migrate(scratch)  # the scratch database is empty: no schema, no schema_version
    except Exception:
        refused = True
    tgt = _root(scratch)
    left = [next(iter(r.values())) for r in rows(tgt, "SHOW TABLES")]
    tgt.close()
    assert refused and left == [], f"refused={refused}, tables created in the target: {left}"


def test_a_target_with_an_incompatible_schema_major_is_refused(kea, scratch):
    add_host(kea, 11)
    tgt = initialise(scratch)
    with tgt.cursor() as cur:
        cur.execute("UPDATE schema_version SET version = version + 1")
    before = snapshot(tgt, MOVE_TABLES)
    refused = False
    try:
        migrate(scratch)
    except Exception:
        refused = True
    assert refused, "a target whose schema major differs from the source's must be refused"
    assert snapshot(tgt, MOVE_TABLES) == before
    tgt.close()


def test_the_v6_address_columns_are_binary_sixteen(kea):
    """Q130 — what Jen's IPv6 readers have to cope with, read from ISC's real schema for the Kea version under
    test (never remembered): lease6.address and ipv6_reservations.address are BINARY(16) — sixteen raw bytes, not
    the VARCHAR(39) text kea6.py's comments used to assume — and the database has INET6_ATON/INET6_NTOA. The columns
    are recorded in the run's schema artifact (facts["address_columns"]). If a future Kea changes a type, THIS test
    says so first, and the conversion in jen/services/kea6.py (which also passes text through unchanged) is the one
    place to look."""
    cols = schema_facts(kea)["address_columns"]
    for key in ("lease6.address", "ipv6_reservations.address"):
        assert cols[key]["column_type"].lower() == "binary(16)", (key, cols[key])
    assert cols["ipv6_reservations.excluded_prefix"]["column_type"].lower() == "binary(16)"
    assert cols["lease4.address"]["data_type"].lower() == "int"
    assert cols["hosts.dhcp_identifier"]["column_type"].lower() == "varbinary(255)"
    assert cols["lease6.duid"]["data_type"].lower() == "varbinary"
    packed = rows(kea, "SELECT HEX(INET6_ATON('2001:db8::10')) AS h, INET6_NTOA(INET6_ATON('2001:db8::10')) AS t")[0]
    assert packed["h"].upper() == "20010DB8000000000000000000000010" and packed["t"] == "2001:db8::10"


def test_jens_ipv6_readers_return_addresses_from_iscs_binary_columns(kea, monkeypatch):
    """Q130 — the read check against the REAL schema. Rows are written the way Kea's own schema stores them
    (INET6_ATON into binary(16)) and Jen's readers must return TEXT: before this fix the IPv6 pages showed sixteen
    raw bytes and an address search on lease6 matched nothing. kea-compat runs kea-dhcp4 only (there is no
    kea-dhcp6 in the matrix), so the reservation and the lease are inserted directly rather than created through
    `reservation-add` / a real DHCPv6 exchange."""
    import jen.models.db as db_mod
    from jen.services import kea6

    monkeypatch.setattr(db_mod, "get_kea6_db", lambda: kea)
    monkeypatch.setattr(kea, "close", lambda: None)
    h = add_host(kea, 61, itype=1, sub4=None, sub6=71, hostname="q130-v6")
    with kea.cursor() as cur:
        cur.execute(
            "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id) "
            "VALUES (INET6_ATON('2001:db8:71::10'), 128, 0, 1, %s)",
            (h,),
        )
        cur.execute(
            "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id, excluded_prefix, "
            "excluded_prefix_len) VALUES (INET6_ATON('2001:db8:71:1000::'), 56, 2, 2, %s, "
            "INET6_ATON('2001:db8:71:10ff::'), 64)",
            (h,),
        )
        cur.execute("DELETE FROM lease6 WHERE hostname LIKE 'q130%'")
        cur.execute(
            "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "
            "prefix_len, hostname, state) VALUES (INET6_ATON('2001:db8:71::5'), %s, 3600, "
            "DATE_ADD(NOW(), INTERVAL 1 HOUR), 71, 1800, 0, 1, 128, 'q130-lease', 0)",
            (bytes.fromhex("00030001001a2b3c4d5e"),),
        )
    try:
        host = next(x for x in kea6.get_ipv6_reservations(subnet_id=71) if x["host_id"] == h)
        by_type = {r["type_name"]: r for r in host["reservations"]}
        assert by_type["IA_NA"]["address"] == "2001:db8:71::10", by_type
        assert by_type["IA_PD"]["address"] == "2001:db8:71:1000::", by_type
        assert by_type["IA_PD"]["excluded_prefix"] == "2001:db8:71:10ff::", by_type

        found = [r for r in kea6.list_lease6(subnet_id=71) if r["hostname"] == "q130-lease"]
        assert [r["address"] for r in found] == ["2001:db8:71::5"], found
        # the exact search (INET6_ATON) and a fragment (filtered in Python) both find it; a neighbour does not
        assert [r["address"] for r in kea6.list_lease6(search="2001:db8:71::5")] == ["2001:db8:71::5"]
        assert [r["address"] for r in kea6.list_lease6(search="db8:71")] == ["2001:db8:71::5"]
        assert kea6.list_lease6(search="2001:db8:71::50") == []
    finally:
        with kea.cursor() as cur:
            cur.execute("DELETE FROM lease6 WHERE hostname LIKE 'q130%'")


def test_the_real_unique_keys_and_foreign_keys_are_what_the_import_has_to_survive(kea):
    """Not a bug check — the facts, asserted loosely so a schema change in a future Kea shows up here first."""
    facts = schema_facts(kea)
    fk_tables = {f["table_name"] for f in facts["foreign_keys"]}
    assert {"hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"} <= fk_tables, fk_tables
    unique = {(i["table_name"], i["index_name"]) for i in facts["indexes"] if int(i["non_unique"]) == 0}
    assert any(t == "hosts" for t, _ in unique), "hosts has at least one unique key besides its primary key"
    assert re.fullmatch(r"\d+", str(facts["schema_version"][0]["version"]))
