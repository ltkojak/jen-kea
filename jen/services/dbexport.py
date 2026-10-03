"""
jen/services/dbexport.py
────────────────────────
Database export, import, backup scheduling, and migration logic.
All operations clearly labeled by which database they touch (Jen or Kea).
"""

import contextlib
import gzip
import json
import logging
import os
import re
import tempfile
from datetime import datetime

import pymysql
import pymysql.cursors

from jen import extensions

logger = logging.getLogger(__name__)

BACKUP_DIR = extensions.CONTENT_BACKUP_DIR
SCHEMA_VERSION = 1  # bump when export format changes

# v5.67.0-beta.11 (Q123) — export FORMAT 3 (`_meta.format`, separate from SCHEMA_VERSION above, which gates
# "is this file from a newer Jen"). Formats 1 and 2 wrote a binary column's bytes as a bare hex STRING, and
# nothing anywhere decoded it: Kea's hosts.dhcp_identifier, lease4.hwaddr, dhcp4_options.value and the v6
# duid/hwaddr came back from an import, a restore or a migration as the ASCII of their own hex — the
# six-byte MAC 34:13:43:e6:0e:2a restored as the twelve bytes of the text "341343e60e2a", and Kea no longer
# matched the client. Format 3 writes a binary value as {"$bin": "<hex>"}: a typed, self-describing
# object, so a plain string that merely LOOKS like hex stays a string. `_meta.binary_columns` records which
# columns information_schema called binary/varbinary/blob at export time (for a human and for a test — the
# importer decodes by the TARGET's own schema, never by trusting this).
EXPORT_FORMAT = 3
BIN_TAG = "$bin"
_BINARY_DATA_TYPES = ("binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob")
_HEX_PAIRS = re.compile(r"^(?:[0-9A-Fa-f]{2})*$")

# ── Jen tables available for export ──────────────────────────────────────────
JEN_TABLES = {
    "users": "User accounts (includes password hashes — handle with care)",
    "devices": "Device inventory (MAC, hostname, manufacturer, notes)",
    "reservation_notes": "Notes attached to Kea reservations",
    "settings": "All Jen application settings",
    "alert_channels": (
        "Alert channel configuration (Telegram etc.). Delivery tokens in the "
        "config column are encrypted at rest; the key lives in the config directory, NOT in "
        "this export — channels will not deliver after restore onto a different "
        "install until their tokens are re-entered."
    ),
    "alert_templates": "Custom alert message templates",
    "alert_log": "Historical alert delivery log",
    "saved_searches": "Saved filter presets",
    "dashboard_prefs": "Per-user dashboard widget layout",
    "mfa_methods": "MFA method records (TOTP secrets encrypted at rest; the key lives in the config directory, NOT in this export — secrets will not restore onto a different install)",
    "mfa_backup_codes": "MFA backup/recovery codes",
    "mfa_trusted_devices": "Trusted device tokens for MFA bypass",
    "api_keys": "API key records (hashed — raw keys not recoverable)",
    "audit_log": "Full audit trail (can be large)",
    "lease_history": "Historical lease count snapshots",
    "subnet_notes": "Notes attached to subnets",
    "backup_schedule": "Backup scheduler configuration",
    # v5.44.0 (Q45) — added while auditing this list against every table a
    # migration creates (PENDING.md's Q45: "check _validate_tables' known
    # list covers everything migrations create"). These were always
    # missing from a "full" export, not just from the new recovery
    # bundle — this fixes the pre-existing regular Backups feature too.
    "webauthn_credentials": "Passkey credentials (public keys only — nothing here lets a passkey be replayed elsewhere)",
    "login_attempts": "Rate-limiting log of recent login attempts, by IP and username",
    "mfa_attempts": "MFA brute-force throttling log",
    "plugins": "Installed plugin records (id, version, enabled state)",
    "plugin_schema_migrations": "Per-plugin schema migration tracking",
    "kea_config_revisions": (
        "Kea config history Jen has pushed or noticed — config bodies are encrypted at rest; "
        "the key lives in the config directory, NOT in this export"
    ),
    "lease6_history": "Historical IPv6 lease count snapshots",
    "server_stats": "Packet health snapshots (statistic-get-all counters per server)",
    "events": "The event stream (lease/reservation/config/HA/drift/alert activity)",
    # v5.49.0-beta.3 — schema_migrations travels with the data. Left out, a
    # restored database looked brand new to the migration runner and every
    # migration re-ran on the next boot (idempotent, but slow and noisy, and
    # a restore onto a NEWER Jen applied later migrations twice over).
    "schema_migrations": "Which schema migrations this database has applied (tiny)",
}

# ── Kea tables available for export ──────────────────────────────────────────
# v5.67.0-beta.11 (Q123, item b) — the scheduled and manual "Kea" backup used to be TWO tables (hosts and
# dhcp4_options): no IPv6 reservation, no v6 option, no lease — yet the setup page called the box "Kea's
# database". The backup group is now `reservations_all` and is labelled for what it holds, everywhere. Tables
# are listed in FOREIGN-KEY order (hosts before the option and v6 rows that point at it); the importer
# restores in this order whatever order a file lists them in. A table that does not exist on this Kea is
# left out of the export (never an empty stand-in).
KEA_BACKUP_GROUP = "reservations_all"
KEA_BACKUP_LABEL = "Kea host reservations (IPv4 and IPv6)"
KEA_EXPORT_GROUPS = {
    "reservations_all": {
        "label": KEA_BACKUP_LABEL,
        "description": "Every permanent host reservation, IPv4 and IPv6, with its host-scoped options (the options set on a reservation — not global, subnet or class options): hosts, dhcp4_options, dhcp6_options, ipv6_reservations. This is what the scheduled and manual backups save, and what you want to migrate. It is not Kea's leases and not Kea's configuration.",
        "tables": ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"],
    },
    "reservations": {
        "label": "Kea host reservations — IPv4 only",
        "description": "The IPv4 half of the group above (hosts + per-host DHCP options), kept for exports that predate it.",
        "tables": ["hosts", "dhcp4_options"],
    },
    "leases": {
        "label": "Active Leases (lease4)",
        "description": "Dynamic leases currently active. These are transient — they expire and renew automatically — so they are never part of a backup. Only export if you need a point-in-time snapshot.",
        "tables": ["lease4"],
    },
}

KEA_ALL_TABLES = {t for grp in KEA_EXPORT_GROUPS.values() for t in grp["tables"]}
# the order an import restores in: parents before the rows that reference them
KEA_RESTORE_ORDER = ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations", "lease4"]

# v5.67.0-beta.13 (Q127, item e) — Kea's dhcp_option_scope numbers a HOST's options 3 (0 global, 1 subnet,
# 2 client-class, 3 host, 4 shared-network, 5 pool, 6 pd-pool). Read from the real table AND from the scope_id
# Kea's own reservation-add writes, on 3.0.3, 3.2.0 and 3.3.1 (tests/kea_compat/test_db_moves.py).
KEA_HOST_OPTION_SCOPE = 3

# One fixed query per exportable table — never `SELECT *` over a table that holds more than the group is about.
# The options tables also hold the global, subnet, class, shared-network and pool options of Kea's config
# backend; a RESERVATION backup carries the options set on a reservation only (host_id set AND the host scope),
# because restoring the rest by their auto-increment ids would write them over whatever options the target has.
# hosts, ipv6_reservations and lease4 are wholly what their group says they are. tests/test_kea_export_queries.py
# refuses an unfiltered options query and a table with no entry here.
KEA_EXPORT_SQL = {
    "hosts": "SELECT * FROM `hosts`",  # nosec B608 - a fixed per-table query: the table is a literal and the one interpolated value is a module constant
    "dhcp4_options": f"SELECT * FROM `dhcp4_options` WHERE host_id IS NOT NULL AND scope_id = {KEA_HOST_OPTION_SCOPE}",  # nosec B608 - a fixed per-table query: the table is a literal and the one interpolated value is a module constant
    "dhcp6_options": f"SELECT * FROM `dhcp6_options` WHERE host_id IS NOT NULL AND scope_id = {KEA_HOST_OPTION_SCOPE}",  # nosec B608 - a fixed per-table query: the table is a literal and the one interpolated value is a module constant
    "ipv6_reservations": "SELECT * FROM `ipv6_reservations`",  # nosec B608 - a fixed per-table query: the table is a literal and the one interpolated value is a module constant
    "lease4": "SELECT * FROM `lease4`",  # nosec B608 - a fixed per-table query: the table is a literal and the one interpolated value is a module constant
}


def _validate_tables(requested, known):
    """Filter requested table names down to only those in `known`.

    This is the single choke point protecting every f-string table-name
    interpolation in this module (SELECT * FROM `{table}`,
    DELETE FROM `{tbl}`, DROP TABLE IF EXISTS `{tbl}`, etc.) from SQL
    injection via crafted form data or a maliciously-edited uploaded export
    file. Anything not in the known whitelist is silently dropped rather than
    passed through to a query.
    """
    if requested is None:
        return None
    known_set = set(known)
    return [t for t in requested if t in known_set]


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _direct_jen_conn():
    from jen.models.db import _ssl_kwargs

    return pymysql.connect(
        host=extensions.JEN_DB_HOST,
        user=extensions.JEN_DB_USER,
        password=extensions.JEN_DB_PASS,
        database=extensions.JEN_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.JEN_DB_SSL_CA),
    )


def _direct_kea_conn():
    from jen.models.db import _ssl_kwargs

    return pymysql.connect(
        host=extensions.KEA_DB_HOST,
        port=extensions.KEA_DB_PORT,
        user=extensions.KEA_DB_USER,
        password=extensions.KEA_DB_PASS,
        database=extensions.KEA_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.KEA_DB_SSL_CA),
    )


def _direct_conn(host, port, user, password, database, ssl_ca=""):
    """`ssl_ca` (v5.67.0-beta.8, Q120, item g) — empty (every migration target, as before) passes no ssl
    kwarg at all; the setup wizard's Connect test passes [kea_db] ssl_ca so it tests the connection the
    pool will actually make."""
    from jen.models.db import _ssl_kwargs

    return pymysql.connect(
        host=host,
        port=int(port),
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(ssl_ca),
    )


def _clean_row(row):
    """One row, datetimes ISO-formatted and binary values written as a TAGGED object — the cleanup
    every streamed export (_stream_table_rows) applies to a row (v5.66.0-beta.4, Q106). Until v5.67.0-beta.11 (Q123) a
    binary value became a bare hex string here, which nothing ever decoded (see EXPORT_FORMAT above);
    it is `{"$bin": "<hex>"}` now. Used for EXPORT only: a database-to-database migration copies the
    driver's own values (bytes as bytes) and never goes through this."""
    clean = {}
    for k, v in row.items():
        if isinstance(v, (datetime,)):
            clean[k] = v.isoformat() if v else None
        elif isinstance(v, (bytes, bytearray)):
            clean[k] = {BIN_TAG: bytes(v).hex()}
        else:
            clean[k] = v
    return clean


def _binary_columns(conn, tables) -> dict[str, list[str]]:
    """{table: [column, ...]} — every column of the given tables that information_schema says is
    binary/varbinary/blob in the CURRENT database. Only tables with at least one are returned."""
    tables = list(tables)
    if not tables:
        return {}
    placeholders = ", ".join(["%s"] * len(tables))
    types = ", ".join(f"'{t}'" for t in _BINARY_DATA_TYPES)
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT table_name AS tbl, column_name AS col FROM information_schema.columns "
            f"WHERE table_schema = DATABASE() AND table_name IN ({placeholders}) "
            f"AND data_type IN ({types}) ORDER BY table_name, ordinal_position",
            tables,
        )
        found: dict[str, list[str]] = {}
        for r in cur.fetchall():
            found.setdefault(r["tbl"], []).append(r["col"])
    return found


class BinaryValueError(ValueError):
    """A value bound for a binary column that cannot be decoded safely. Names the table and column so the
    result line tells the operator exactly what to look at; never raised for a value that decodes."""


def _target_binary_columns(conn, table) -> set[str]:
    """The columns of `table` that the TARGET database says are binary — the importer's only source of
    truth for what a bare string in an older export must be decoded as."""
    return set(_binary_columns(conn, [table]).get(table, []))


def _decode_import_rows(table, rows, cols, binary_cols, fmt):
    """The rows' values for `cols`, ready to bind: a `{"$bin": hex}` object becomes bytes (in ANY column — the
    tag is self-describing); a bare string bound for a column the target says is binary is decoded as hex in a
    format-1/2 file (that is what those formats wrote) and REFUSED in a format-3 file (which tags every
    binary value, so a bare string there is a hand-edited file). Anything not valid hex raises
    BinaryValueError naming the column — text is never inserted into a binary column. A string bound for a
    non-binary column is never touched, whatever it looks like."""
    out = []
    for n, row in enumerate(rows, 1):
        vals = []
        for c in cols:
            v = row.get(c)
            if isinstance(v, dict) and set(v) == {BIN_TAG}:
                h = v[BIN_TAG]
                if not isinstance(h, str) or not _HEX_PAIRS.match(h):
                    raise BinaryValueError(f"{table}.{c} (row {n}): the tagged binary value is not valid hex")
                vals.append(bytes.fromhex(h))
            elif c in binary_cols and isinstance(v, str):
                if fmt >= 3:
                    raise BinaryValueError(
                        f"{table}.{c} (row {n}): a format-{fmt} export tags every binary value, "
                        f"but this one is a bare string"
                    )
                if not _HEX_PAIRS.match(v):
                    raise BinaryValueError(f"{table}.{c} (row {n}): {v[:24]!r} is not valid hex for a binary column")
                vals.append(bytes.fromhex(v))
            else:
                vals.append(v)
        out.append(vals)
    return out


def _table_exists(conn, table):
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE %s", (table,))
        return bool(cur.fetchone())


def _get_table_columns(conn, table):
    """Return the real column names for `table` from the live schema.

    `table` must already be validated against a known-table whitelist by the
    caller (SQL identifiers can't be parameterised with %s). Used to filter
    untrusted column names — e.g. from an uploaded import file — down to
    columns that actually exist, before they're interpolated into an INSERT.
    """
    with conn.cursor() as cur:
        cur.execute(f"SHOW COLUMNS FROM `{table}`")
        return {row["Field"] for row in cur.fetchall()}


def _row_count(conn, table):
    if not _table_exists(conn, table):
        return 0
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) as cnt FROM `{table}`")
        return cur.fetchone()["cnt"]


def _make_metadata(db_label, tables_included, extra=None):
    meta = {
        "jen_export_version": SCHEMA_VERSION,
        "jen_app_version": extensions.cfg.get("jen", "version", fallback="unknown") if extensions.cfg else "unknown",
        "database": db_label,  # "jen" or "kea"
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "tables": tables_included,
    }
    if extra:
        meta.update(extra)
    return meta


def publish_backup(final_path, write_fn):
    """Write a backup atomically: `write_fn(fileobj)` into a 0600 temp file in the SAME
    directory as `final_path` (so the final `os.replace` is a same-filesystem rename, never
    a copy), fsync'd before the rename, with the directory entry fsync'd afterward (best
    effort — not every filesystem/platform supports it). On any exception the temp file is
    removed and `final_path` is never created or modified at all — a writer that dies
    halfway, or an ENOSPC mid-write, leaves nothing that could ever list as a backup
    (v5.66.0-beta.6, Q108: this and the streamed export finally line up — a partial backup
    used to be exactly as visible as a good one). `write_fn`'s return value, if any, is
    passed straight through, so a caller that needs it (write_jen_export's meta dict) doesn't
    have to smuggle it out through a closure."""
    directory = os.path.dirname(final_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".part-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            result = write_fn(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, final_path)
    except Exception:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise
    with contextlib.suppress(OSError):
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    return result


def _sidecar_path(backup_path: str) -> str:
    if backup_path.endswith(".json.gz"):
        return backup_path[: -len(".json.gz")] + ".meta.json"
    return backup_path + ".meta.json"


def _write_meta_sidecar(backup_path: str, meta: dict) -> None:
    """The `<name>.meta.json` sidecar `list_backups()` reads INSTEAD of opening the
    (possibly huge) backup file itself (v5.66.0-beta.6, Q108) — written right after the
    backup is published, through the same `publish_backup()` as the backup itself, so a
    sidecar can never half-exist either."""
    sidecar = _sidecar_path(backup_path)
    payload = {
        "database": meta.get("database"),
        "tables": meta.get("tables"),
        "plugin_tables": meta.get("plugin_tables") or {},
        "exported_at": meta.get("exported_at"),
        "jen_version": meta.get("jen_app_version") or meta.get("jen_version"),
        "compressed_bytes": os.path.getsize(backup_path) if os.path.isfile(backup_path) else None,
        "uncompressed_bytes": meta.get("jen_db_uncompressed_bytes") or meta.get("uncompressed_bytes"),
        "row_counts": meta.get("row_counts") or {},
    }

    def write_fn(f):
        f.write(json.dumps(payload, default=str).encode("utf-8"))

    publish_backup(sidecar, write_fn)


def _write_backup(payload_dict, filename):
    """Writes `payload_dict` as gzip JSON, atomically (v5.66.0-beta.6, Q108 — through
    `publish_backup()`, so a failure mid-write leaves no final file at all, the same
    guarantee `write_jen_export`-based backups now have) and writes its `.meta.json`
    sidecar right after. Return value is unchanged (the final path) — every existing caller
    keeps working without a change."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    final_path = os.path.join(BACKUP_DIR, filename)
    uncompressed_len = {}

    def write_fn(f):
        text = json.dumps(payload_dict, default=str)
        uncompressed_len["n"] = len(text.encode("utf-8"))
        with gzip.open(f, "wt", encoding="utf-8") as gz:
            gz.write(text)

    publish_backup(final_path, write_fn)
    meta = dict(payload_dict.get("_meta") or {})
    meta["uncompressed_bytes"] = uncompressed_len.get("n")
    _write_meta_sidecar(final_path, meta)
    return final_path


def _read_backup(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Try uncompressed (older exports)
        with open(path, encoding="utf-8") as f:
            return json.load(f)


def read_legacy_backup_details(filename: str) -> dict | None:
    """Parses a pre-Q108 backup (no sidecar yet) exactly once — the ONE time this ever
    costs opening the full file — and writes its sidecar so `list_backups()` never has to
    do this again for this file. Returns the sidecar dict, or None if the file is missing
    or unreadable."""
    path = os.path.join(BACKUP_DIR, os.path.basename(filename))
    if not os.path.isfile(path):
        return None
    try:
        payload = _read_backup(path)
    except Exception:
        return None
    _write_meta_sidecar(path, dict(payload.get("_meta") or {}))
    try:
        with open(_sidecar_path(path), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────


def _existing_owned_tables(conn) -> dict[str, list[str]]:
    """plugins.all_owned_tables(), filtered to the tables that actually exist right now — a
    plugin whose migrations haven't run yet (or ran partway) never contributes a table nobody
    could actually export rows from (v5.66.0-beta.5, Q107)."""
    from jen.services import plugins as _plugins

    owned = _plugins.all_owned_tables()
    return {pid: [t for t in tables if _table_exists(conn, t)] for pid, tables in owned.items()}


def export_tables(conn=None) -> list[str]:
    """Core JEN_TABLES plus every table a currently-installed plugin owns that actually exists
    right now (v5.66.0-beta.5, Q107) — the ONE table set write_jen_export() (default,
    tables=None), both backup routes, the scheduled backup, the recovery bundle, the restore
    snapshot and migrate_jen all use, so a plugin's data is never silently left out of any of
    them. Reuses `conn` when given (write_jen_export already has one open); opens and closes
    its own otherwise."""
    own_conn = conn is None
    if own_conn:
        conn = _direct_jen_conn()
    try:
        tables = list(JEN_TABLES.keys())
        for plugin_tables in _existing_owned_tables(conn).values():
            tables.extend(plugin_tables)
        return tables
    finally:
        if own_conn:
            conn.close()


def export_table_groups(conn=None) -> dict[str, list[str]]:
    """{plugin_id: [tables]} for the export page's table picker — one group per currently-
    installed plugin whose owned tables actually exist right now (empty-table plugins are left
    out entirely, same as export_tables())."""
    own_conn = conn is None
    if own_conn:
        conn = _direct_jen_conn()
    try:
        return {pid: tables for pid, tables in _existing_owned_tables(conn).items() if tables}
    finally:
        if own_conn:
            conn.close()


def _stream_table_rows(conn, tbl, f, sql=None) -> int:
    """Write one table's rows to `f` as the inside of a JSON array, one at a time from a server-side
    cursor — never the whole table in memory. Returns the row count. The one loop write_jen_export and
    write_kea_export share (v5.67.0-beta.11, Q123): the Kea export used to build `payload["data"][tbl] =
    _dump_table(...)` and json.dumps the lot, and the callers then json.loads it again — a large lease4 was
    the case that bit."""
    count = 0
    with conn.cursor(pymysql.cursors.SSDictCursor) as cur:
        cur.execute(sql or f"SELECT * FROM `{tbl}`")  # nosec B608 - `sql` is one of KEA_EXPORT_SQL's fixed queries or `tbl` is a name from Jen's own table lists; never request data
        first_row = True
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                if not first_row:
                    f.write(", ")
                first_row = False
                f.write(json.dumps(_clean_row(row), default=str))
                count += 1
    return count


def write_jen_export(path, tables=None):
    """Write the exact same JSON document export_jen() returns — `{"data": {...},
    "_meta": {...}}` (key order is free: data first here, _meta with its row_counts last) —
    straight to `path` as gzip text, one row at a time from a server-side cursor
    (`SSDictCursor` + `fetchmany`). Never holds a whole table's rows in memory, unlike the old
    "build one big dict, then json.dumps it" shape — the growth tables (audit_log especially)
    are exactly why (v5.66.0-beta.4, Q106). The recovery bundle, the manual/scheduled backup,
    and the /database/export/jen download route all write here directly now; export_jen()
    below is a thin wrapper for the few callers that still want bytes back.

    v5.66.0-beta.5 (Q107) — `tables=None` now means export_tables() (core + every existing
    plugin table), not just JEN_TABLES; an explicit `tables` list is validated against that
    same wider universe, so a caller can ask for a specific plugin's tables too. `_meta` gains
    `format: 2` and `plugin_tables: {plugin_id: {"version": <installed>, "tables": [...]}}` —
    only for plugins that actually contributed a selected table — so a restore knows exactly
    which plugins this export covers and at what version, without guessing from `data`'s keys.

    Returns the `_meta` dict actually written, plus two figures the WRITTEN document does not
    carry (they can only be known once writing is done): `jen_db_uncompressed_bytes` (the
    document's own decompressed size — `gzip.GzipFile.tell()` reports exactly this in write
    mode) and `jen_db_rows` (the row_counts total) — both for the recovery manifest's size
    guard, never written into the export file itself.

    Written 0600 when `path` is an actual path — chmod needs a filesystem name, so it's
    skipped when `path` is already an open file object (v5.66.0-beta.6, Q108:
    `publish_backup()`'s callers pass their own already-0600 temp file this way; every table
    here can carry secrets — users, api_keys, mfa_*, kea_config_revisions — so a bare-mode
    fallback here would be a real leak, never used)."""
    conn = _direct_jen_conn()
    row_counts = {}
    try:
        owned = _existing_owned_tables(conn)
        universe = list(JEN_TABLES.keys())
        for plugin_tables in owned.values():
            universe.extend(plugin_tables)
        selected = _validate_tables(tables, universe) if tables else universe
        selected_set = set(selected)
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write('{"data": {')
            for i, tbl in enumerate(selected):
                if i:
                    f.write(", ")
                f.write(json.dumps(tbl))
                f.write(": [")
                count = _stream_table_rows(conn, tbl, f) if _table_exists(conn, tbl) else 0
                f.write("]")
                row_counts[tbl] = count
            meta = _make_metadata("jen", selected)
            meta["row_counts"] = row_counts
            meta["format"] = EXPORT_FORMAT
            meta["binary_columns"] = _binary_columns(conn, selected)
            plugin_versions = {}
            with conn.cursor() as cur:
                cur.execute("SELECT id, version FROM plugins")
                for r in cur.fetchall():
                    plugin_versions[r["id"]] = r["version"]
            # a bundled plugin merely enabled (never through the registry install flow that
            # writes a `plugins` row) has no row here at all - fall back to its manifest's own
            # version rather than recording null for every bundled plugin's export metadata.
            from jen.services import plugins as _plugins_for_versions

            for p in _plugins_for_versions.discover_plugins():
                plugin_versions.setdefault(p["id"], p.get("version"))
            plugin_tables_meta = {}
            for pid, tbls in owned.items():
                in_this_export = [t for t in tbls if t in selected_set]
                if in_this_export:
                    plugin_tables_meta[pid] = {"version": plugin_versions.get(pid), "tables": in_this_export}
            meta["plugin_tables"] = plugin_tables_meta
            if plugin_tables_meta:
                # the recovery tab's one-time notice (jen/routes/database.py) reads this: once
                # a real export has actually carried at least one plugin's tables, every earlier
                # bundle/backup taken on this install is provably superseded and the notice
                # never needs to show again.
                from jen.models.user import set_global_setting

                set_global_setting("plugin_backup_notice_seen", "1")
            f.write('}, "_meta": ')
            f.write(json.dumps(meta, default=str))
            f.write("}")
            uncompressed_bytes = f.tell()
    finally:
        conn.close()
    if isinstance(path, (str, os.PathLike)):
        os.chmod(path, 0o600)
    result = dict(meta)
    result["jen_db_uncompressed_bytes"] = uncompressed_bytes
    result["jen_db_rows"] = sum(row_counts.values())
    return result


def export_jen(tables=None):
    """
    Export selected Jen DB tables.
    tables: list of table names, or None for all.
    Returns (json_bytes, filename).

    A thin wrapper around write_jen_export (v5.66.0-beta.4, Q106): writes to a throwaway
    temp file, reads it back, deletes it. Kept for callers that genuinely want the bytes
    (a small export, or a caller with no path to stream to) rather than a memory-safety win.
    """
    import tempfile

    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"jen-export-{ts}.json.gz"
    fd, tmp_path = tempfile.mkstemp(suffix=".json.gz")
    os.close(fd)
    try:
        write_jen_export(tmp_path, tables)
        with gzip.open(tmp_path, "rt", encoding="utf-8") as f:
            content = f.read().encode("utf-8")
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
    return content, filename


def write_kea_export(path, group=KEA_BACKUP_GROUP):
    """The Kea twin of write_jen_export (v5.67.0-beta.11, Q123, item c): the group's tables straight to `path`
    as gzip text, one row at a time from a server-side cursor, `_meta` last — through `publish_backup()` for
    a backup (so a failure leaves no file) or to a temp file for a download. Tables that do not exist on
    this Kea are left out of both `data` and `_meta.tables`. `_meta` carries `format: 3` and
    `binary_columns` (see EXPORT_FORMAT). Returns the `_meta` dict plus `uncompressed_bytes` (known only
    once writing is done; the backup sidecar reads it, the file itself does not carry it). Written 0600
    when `path` is an actual path."""
    if group not in KEA_EXPORT_GROUPS:
        raise ValueError(f"Unknown export group: {group}")
    wanted = KEA_EXPORT_GROUPS[group]["tables"]
    conn = _direct_kea_conn()
    row_counts = {}
    try:
        present = [t for t in wanted if _table_exists(conn, t)]
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write('{"data": {')
            for i, tbl in enumerate(present):
                if i:
                    f.write(", ")
                f.write(json.dumps(tbl))
                f.write(": [")
                row_counts[tbl] = _stream_table_rows(conn, tbl, f, KEA_EXPORT_SQL[tbl])
                f.write("]")
            meta = _make_metadata("kea", present, {"group": group})
            meta["row_counts"] = row_counts
            meta["format"] = EXPORT_FORMAT
            meta["binary_columns"] = _binary_columns(conn, present)
            f.write('}, "_meta": ')
            f.write(json.dumps(meta, default=str))
            f.write("}")
            uncompressed_bytes = f.tell()
    finally:
        conn.close()
    if isinstance(path, (str, os.PathLike)):
        os.chmod(path, 0o600)
    result = dict(meta)
    result["uncompressed_bytes"] = uncompressed_bytes
    return result


def export_kea(group=KEA_BACKUP_GROUP):
    """
    Export Kea DB data.
    group: any key of KEA_EXPORT_GROUPS.
    Returns (json_bytes, filename) — a thin wrapper over write_kea_export (v5.67.0-beta.11, Q123), for
    the callers that genuinely want bytes back; the download and both backup paths stream instead.
    """
    if group not in KEA_EXPORT_GROUPS:
        raise ValueError(f"Unknown export group: {group}")
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"kea-{group}-export-{ts}.json.gz"
    fd, tmp_path = tempfile.mkstemp(suffix=".json.gz")
    os.close(fd)
    try:
        write_kea_export(tmp_path, group)
        with gzip.open(tmp_path, "rt", encoding="utf-8") as f:
            content = f.read().encode("utf-8")
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
    return content, filename


# ─────────────────────────────────────────────────────────────────────────────
# Import / Restore
# ─────────────────────────────────────────────────────────────────────────────


class AdmissionRefused(Exception):
    """Raised by admission_check() — refused before anything is touched. Each caller
    translates this into its own idiom: jen.tools.restore wraps it as RestoreRefused (adding
    the runbook pointer and the free-up-memory suggestions); the ordinary import page catches
    it and flashes the message, same as any other pre-parse refusal."""


def admission_check(
    incoming_bytes: int,
    existing_bytes: int,
    available_bytes: int,
    factor: float,
    free_disk_bytes: int | None = None,
    needed_disk_bytes: int | None = None,
) -> None:
    """The one shared rule behind both the restore's pre-flight check (jen.tools.restore
    .check_memory()) and the ordinary import page's pre-flight check (v5.66.0-beta.6, Q108):
    refuses when `max(incoming_bytes, existing_bytes) × factor` exceeds `available_bytes` —
    weighing the LARGER of the two sides, never the incoming one alone, since a small bundle
    restored onto a box with a large existing database still has to hold that existing
    database's export in memory during the pre-restore snapshot and any later rollback. The
    disk check is entirely optional (skipped unless both `free_disk_bytes` and
    `needed_disk_bytes` are given — the import page's own upload cap already bounds its disk
    use a different way) — when given, refuses if `free_disk_bytes < needed_disk_bytes` too.
    Raises AdmissionRefused naming whichever figure was the problem; never touches anything
    itself."""
    incoming_bytes = incoming_bytes or 0
    existing_bytes = existing_bytes or 0
    larger = max(incoming_bytes, existing_bytes)
    needed_mem = int(larger * factor)
    if needed_mem > available_bytes:
        side = (
            "the database being imported/restored"
            if incoming_bytes >= existing_bytes
            else "the database already on this machine"
        )
        raise AdmissionRefused(
            f"{side} is {larger / (1024 * 1024):.0f} MB uncompressed; this needs roughly "
            f"{needed_mem / (1024 * 1024):.0f} MB of free memory (a measured factor of {factor}x), "
            f"but this machine currently reports only {available_bytes / (1024 * 1024):.0f} MB "
            f"available (/proc/meminfo MemAvailable)."
        )
    if free_disk_bytes is not None and needed_disk_bytes is not None and needed_disk_bytes > free_disk_bytes:
        raise AdmissionRefused(
            f"only {free_disk_bytes / (1024 * 1024):.0f} MB free disk space here, but this needs "
            f"roughly {needed_disk_bytes / (1024 * 1024):.0f} MB free."
        )


def parse_import_file(file_bytes):
    """
    Parse an uploaded export file. Returns (meta, data, error).
    error is None on success.
    """
    try:
        try:
            text = gzip.decompress(file_bytes).decode("utf-8")
        except Exception:
            text = file_bytes.decode("utf-8")
        payload = json.loads(text)
    except Exception as e:
        return None, None, f"Could not parse file: {e}"

    meta = payload.get("_meta", {})
    data = payload.get("data", {})
    if not meta or "database" not in meta:
        return None, None, "File does not appear to be a Jen export (missing metadata)."
    if meta.get("jen_export_version", 0) > SCHEMA_VERSION:
        return (
            meta,
            data,
            f"Export schema version {meta['jen_export_version']} is newer than this Jen supports ({SCHEMA_VERSION}). Upgrade Jen first.",
        )
    return meta, data, None


def _plugin_invariant_violations(conn) -> list[tuple[str, str]]:
    """(plugin_id, table) for every plugin with recorded migrations whose code is on this
    machine but one of its owned tables does not actually exist — the exact broken state a
    pre-5.66.0-beta.5 restore used to leave (v5.66.0-beta.5, Q107). Checked, never raised, at
    the end of every restore/import: jen.services.plugins.load_plugins()'s own self-heal fixes
    this at the next Jen startup regardless, so a violation here is a warning, not a failure."""
    from jen.services import plugins as _plugins

    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT plugin_id FROM plugin_schema_migrations")
        migrated_ids = [r["plugin_id"] for r in cur.fetchall()]
    violations = []
    for pid in migrated_ids:
        manifest = _plugins._manifest_for_owned_tables(pid)
        if manifest is None:
            continue
        for t in _plugins.owned_tables(pid, manifest):
            if not _table_exists(conn, t):
                violations.append((pid, t))
    return violations


class PluginRestoreError(RuntimeError):
    """A plugin whose CODE IS PRESENT on this machine lost data in a restore (v5.67.0-beta.11, Q123, item d).
    Raised by import_jen(strict_plugins=True) after every plugin has been tried, so the message names ALL of
    them; `.failures` is [(plugin_id, [tables], reason), ...]. A plugin whose code is absent is never an
    error — its data is still in the file, for a later install to pick up (Q107)."""

    def __init__(self, failures):
        self.failures = failures
        named = "; ".join(
            f"{pid} (table{'s' if len(tbls) != 1 else ''} {', '.join(tbls) or '?'}): {why}"
            for pid, tbls, why in failures
        )
        super().__init__(f"plugin data was NOT fully restored — {named}")


def import_jen(file_bytes, tables_to_restore=None, truncate=True, strict_plugins=False):
    """
    Restore Jen DB tables from export bytes.
    tables_to_restore: list of table names to restore, or None for all in file.
    truncate: if True, clears existing rows before inserting (replace mode).
    strict_plugins: (v5.67.0-beta.11, Q123, item d) for a plugin whose code is present here, a failed
        migration replay, a failed row import or a failed invariant check RAISES PluginRestoreError (after
        every plugin was tried) instead of being a line in the result list. jen.tools.restore runs strict by
        default and turns the error into a rollback — a recovery that lost plugin data used to print
        "restored", start Jen and exit 0. The Databases import page stays non-strict (the operator is
        watching, and chose a file) but the same failures are now "❌" lines it shows as ERRORS, never a "⚠️"
        among successes.
    Returns list of result strings.

    v5.66.0-beta.5 (Q107) — plugin-owned tables restore in a fixed order, never blindly
    trusting the export's own plugin_schema_migrations rows (a restored "already applied" row
    with no table behind it is exactly the bug this Q closes): (1) core tables import first,
    EXCEPT plugin_schema_migrations — its old rows are never restored as-is; (2) for each
    plugin named in the export (`_meta.plugin_tables`, format 2) whose code is on THIS machine:
    its migration rows are cleared and its migrations re-run through the normal runner — tables
    created at the CODE's own level, never from DDL in the file, rows recorded by the runner
    itself; (3) that plugin's row data is imported the same column-intersection way core tables
    always have been, so a column added since the export just takes its default; (4) a plugin
    named in the export whose code is NOT here is skipped with a named warning — its data stays
    in the file/bundle untouched, for a later install to pick up. A format-1 export (no
    `plugin_tables` — everything before this Q) has no per-plugin scope to go by, so every
    CURRENTLY INSTALLED, code-present plugin gets the same clear-and-rerun treatment for the
    same reason, even though a format-1 export never actually carried plugin row data to
    restore. The invariant this exists for — a recorded migration always implies its tables
    exist — is checked once at the end and reported as a warning line if it's ever still
    violated (jen.services.plugins.load_plugins()'s self-heal is the actual fix, run on Jen's
    next start regardless of what this function does)."""
    from jen.services import plugins as _plugins

    meta, data, err = parse_import_file(file_bytes)
    if err:
        raise ValueError(err)
    if meta.get("database") != "jen":
        raise ValueError(f"This export is for '{meta.get('database')}' — expected 'jen'. Wrong file?")

    fmt = meta.get("format", 1)
    plugin_tables_meta = meta.get("plugin_tables") if fmt >= 2 else None
    owned = _plugins.all_owned_tables()  # {plugin_id: [tables]} - installed + code present, NOW

    if plugin_tables_meta:
        export_plugin_ids = list(plugin_tables_meta.keys())
    else:
        # format 1, or a format-2 export that named no plugins: no per-plugin scope to go by -
        # every currently installed, code-present plugin gets migrations cleared and re-run.
        export_plugin_ids = list(owned.keys())

    known = list(JEN_TABLES.keys())
    for pid in export_plugin_ids:
        if plugin_tables_meta:
            known.extend(plugin_tables_meta.get(pid, {}).get("tables", []))
        else:
            known.extend(owned.get(pid, []))

    selected_raw = tables_to_restore if tables_to_restore else list(data.keys())
    selected = _validate_tables(selected_raw, known)
    selected_set = set(selected)
    results = []
    failures = []  # (plugin_id, [tables], reason) — a plugin whose code is HERE and whose data did not come back

    # Which plugins get their migrations cleared and re-run is a SEPARATE question from which
    # tables have row data to import — a format-1 export (or a format-2 one for a table that
    # simply had zero rows) never has a key for a plugin's table in `data` at all, and schema
    # repair must still happen for it. On a full restore (tables_to_restore=None) every plugin
    # in export_plugin_ids is repaired; an explicitly SCOPED restore only repairs a plugin the
    # caller actually asked for (checked against the wider `known` universe, never `data`).
    if tables_to_restore is None:
        plugin_repair_ids = list(export_plugin_ids)
    else:
        requested = set(_validate_tables(tables_to_restore, known))
        plugin_repair_ids = [
            pid
            for pid in export_plugin_ids
            if requested
            & set(plugin_tables_meta.get(pid, {}).get("tables", []) if plugin_tables_meta else owned.get(pid, []))
        ]

    def _import_rows(conn, tbl):
        rows = data.get(tbl, [])
        if not _table_exists(conn, tbl):
            results.append(f"⚠️ {tbl}: table does not exist in current schema — skipped")
            return
        with conn.cursor() as cur:
            if truncate:
                cur.execute(f"DELETE FROM `{tbl}`")
            if rows:
                real_cols = _get_table_columns(conn, tbl)
                cols = [c for c in rows[0] if c in real_cols]
                if not cols:
                    results.append(f"⚠️ {tbl}: no recognized columns in import data — skipped")
                    return
                col_str = ", ".join(f"`{c}`" for c in cols)
                ph_str = ", ".join(["%s"] * len(cols))
                # v5.67.0-beta.11 (Q123) — decoded by the target's own schema (Jen's own tables have no
                # binary column today; a plugin's might). A value that cannot be decoded raises, which the
                # callers already turn into a rolled-back import.
                params = _decode_import_rows(tbl, rows, cols, _target_binary_columns(conn, tbl), fmt)
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    params,
                )
        results.append(f"✅ {tbl}: {len(rows)} rows restored")

    # ── (1) core tables, EXCEPT plugin_schema_migrations ───────────────────────────────
    core_selected = [t for t in selected if t in JEN_TABLES and t != "plugin_schema_migrations"]
    conn = _direct_jen_conn()
    try:
        conn.begin()
        conn.cursor().execute("SET FOREIGN_KEY_CHECKS=0")
        for tbl in core_selected:
            _import_rows(conn, tbl)
        conn.cursor().execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise RuntimeError(f"Import failed and was rolled back: {e}") from e

    # ── (2) + (3) + (4): plugin tables, one plugin at a time ────────────────────────────
    try:
        for pid in sorted(plugin_repair_ids):
            plugin_tables_all = (
                plugin_tables_meta.get(pid, {}).get("tables", []) if plugin_tables_meta else owned.get(pid, [])
            )
            if not plugin_tables_all:
                continue
            manifest = _plugins._manifest_for_owned_tables(pid)
            if manifest is None:
                results.append(
                    f"⚠️ {pid}: plugin code is not installed here — its data ({len(plugin_tables_all)} table(s)) "
                    f"was not restored; it is still inside this export/bundle. Install the plugin and restore "
                    f"again to bring it back."
                )
                continue

            from jen.models.db import jen_db

            with jen_db() as db, db.cursor() as cur:
                cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id=%s", (pid,))
                db.commit()
            ok, msg, _count = _plugins.run_plugin_migrations(manifest)
            if not ok:
                failures.append((pid, list(plugin_tables_all), f"migration replay failed ({msg})"))
                results.append(f"❌ {pid}: migration replay failed ({msg}) — its tables/data may be incomplete")
                continue

            # Only the tables the export's own `data` actually carries get rows imported — a
            # format-1 export (or a table with zero rows) has nothing here, and that's fine:
            # the schema repair above already put the table back, just empty.
            plugin_tables_to_import = [t for t in plugin_tables_all if t in selected_set]
            if not plugin_tables_to_import:
                continue
            current_tbl = None
            try:
                conn.begin()
                for tbl in plugin_tables_to_import:
                    current_tbl = tbl
                    _import_rows(conn, tbl)
                conn.commit()
            except Exception as e:
                conn.rollback()
                failures.append(
                    (
                        pid,
                        [current_tbl] if current_tbl else list(plugin_tables_to_import),
                        f"row import failed and was rolled back ({e})",
                    )
                )
                results.append(f"❌ {pid}.{current_tbl}: row import failed and was rolled back ({e})")
    finally:
        conn.close()

    conn2 = _direct_jen_conn()
    try:
        violations = _plugin_invariant_violations(conn2)
    finally:
        conn2.close()
    if violations:
        named = ", ".join(f"{pid}.{t}" for pid, t in violations)
        results.append(
            f"⚠️ invariant check: recorded migration(s) with a missing table ({named}) — "
            f"Jen will repair this automatically the next time it starts"
        )
        for pid, tbl in violations:
            failures.append((pid, [tbl], "a recorded migration has no table behind it"))

    if strict_plugins and failures:
        raise PluginRestoreError(failures)

    return results


class ImportAborted(RuntimeError):
    """A Kea import hit something other than an allowed duplicate: the whole import was rolled back.
    `public` is safe to show an operator (table, row and the kind of failure — never a value)."""

    def __init__(self, public, detail=""):
        self.public = public
        super().__init__(f"Kea import failed and was rolled back — {public}" + (f" ({detail})" if detail else ""))


_KEA_HOST_IDENTITY = ("dhcp_identifier", "dhcp_identifier_type", "dhcp4_subnet_id", "dhcp6_subnet_id")
# a child row's own auto-increment id is never carried: it would collide with, or overwrite, the target's rows
_KEA_CHILD_ID = {"dhcp4_options": "option_id", "dhcp6_options": "option_id", "ipv6_reservations": "reservation_id"}
_NUMERIC_TYPES = {
    "tinyint",
    "smallint",
    "mediumint",
    "int",
    "integer",
    "bigint",
    "decimal",
    "numeric",
    "float",
    "double",
}
_BINARY_TYPES = set(_BINARY_DATA_TYPES)


def _is_duplicate_key(e) -> bool:
    return isinstance(e, pymysql.err.IntegrityError) and bool(e.args) and e.args[0] == 1062


def _required_defaults(conn, table, present):
    """The columns the TARGET requires — NOT NULL, no default, not auto-increment — that the file does not carry,
    with the implicit default of their type (0, empty string, empty bytes). A backup made on an older Kea schema
    lacks columns a newer one added: 3.x's `client_classes longtext NOT NULL` on both options tables is exactly
    this. `INSERT IGNORE` used to paper over it with a warning; an import that treats errors as errors cannot."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name AS col, data_type AS dt FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s AND is_nullable = 'NO' "
            "AND column_default IS NULL AND extra NOT LIKE %s",
            (table, "%auto_increment%"),
        )
        found = cur.fetchall()
    out = {}
    for r in found:
        if r["col"] in present:
            continue
        dt = (r["dt"] or "").lower()
        out[r["col"]] = 0 if dt in _NUMERIC_TYPES else b"" if dt in _BINARY_TYPES else ""
    return out


def _insert_row(cur, table, cols, vals):
    col_str = ", ".join(f"`{c}`" for c in cols)
    cur.execute(f"INSERT INTO `{table}` ({col_str}) VALUES ({', '.join(['%s'] * len(cols))})", vals)
    return cur.rowcount


def import_kea(file_bytes, duplicate_mode="skip"):
    """
    Restore Kea reservations from export bytes.
    duplicate_mode: 'skip' or 'overwrite'.
    Returns list of result strings.

    v5.67.0-beta.13 (Q127) — a host_id in a file is never an identity. The old import inserted `hosts` with the
    file's host_id and then every child row by that same id, so a file host whose id collided with a DIFFERENT
    target host was ignored while its options and IPv6 reservations attached to the target's host; overwrite was
    a delete-and-reinsert (MySQL's replace-into), which deletes the host (Kea's options and IPv6 foreign keys either
    cascade that delete or block it — on a real Kea the blocked delete was swallowed as 'skipped'); and any per-row exception was a
    'skipped' row in a transaction that then committed. Now:

      * each file host is matched to a target host by (identifier, type, dhcp4 subnet, dhcp6 subnet) — what Kea's
        own unique keys mean by "the same reservation" — and inserted WITHOUT host_id when absent (the new id is
        read back); the file's id -> the target's id is a map, and every child row's host_id goes through it;
        option_id / reservation_id are never carried (auto-increment);
      * skip: a host that already exists is left as it is and its children with it; overwrite: the matched host
        is UPDATED IN PLACE (its host_id is stable), and for each child table THE FILE CONTAINS that host's rows
        are replaced by the file's — a child table the file does not contain is never touched (an IPv4-only file
        keeps the host's IPv6 reservations and options);
      * options in the file that belong to no reservation in it (older files carried global, subnet and class
        options) are not attached anywhere — counted and reported, never written by option_id;
      * the ONLY thing counted as 'skipped' is MySQL error 1062 (duplicate key) in skip mode; anything else —
        a foreign-key failure, a wrong type, a value too long — aborts the import, rolls the whole transaction
        back and raises ImportAborted naming the table and row. Counts come from the server's row counts.
    """
    meta, data, err = parse_import_file(file_bytes)
    if err:
        raise ValueError(err)
    if meta.get("database") != "kea":
        raise ValueError(f"This export is for '{meta.get('database')}' — expected 'kea'. Wrong file?")
    if duplicate_mode not in ("skip", "overwrite"):
        raise ValueError(f"Unknown duplicate mode: {duplicate_mode!r}")
    overwrite = duplicate_mode == "overwrite"

    fmt = meta.get("format", 1)
    results = []
    conn = _direct_kea_conn()
    try:
        conn.begin()
        order = {t: i for i, t in enumerate(KEA_RESTORE_ORDER)}
        decoded = {}  # table -> (cols, [row dict])
        for tbl in sorted(data, key=lambda t: (order.get(t, len(order)), t)):
            if tbl not in KEA_ALL_TABLES:
                results.append(f"⚠️ {tbl}: not a recognized Kea table — skipped")
                continue
            rows = data.get(tbl) or []
            if not _table_exists(conn, tbl):
                results.append(f"⚠️ {tbl}: table not found in Kea DB — skipped")
                continue
            if not rows:
                if tbl in _KEA_CHILD_ID:
                    decoded[tbl] = ([], [])  # an empty child table IS content: overwrite replaces with nothing
                results.append(f"ℹ️ {tbl}: no rows in export — skipped")
                continue
            real_cols = _get_table_columns(conn, tbl)
            cols = [c for c in rows[0] if c in real_cols]
            if not cols:
                results.append(f"⚠️ {tbl}: no recognized columns in import data — skipped")
                continue
            # every row of the table is decoded BEFORE the first INSERT, by the target's own column types: a table
            # with one undecodable binary value is refused whole (and named), never half-restored
            try:
                vals = _decode_import_rows(tbl, rows, cols, _target_binary_columns(conn, tbl), fmt)
            except BinaryValueError as e:
                results.append(f"❌ {tbl}: refused — {e}. Nothing was imported into this table.")
                continue
            decoded[tbl] = (cols, [dict(zip(cols, v, strict=True)) for v in vals])

        host_map: dict = {}  # file host_id -> target host_id, or None when that host was skipped
        updated_hosts: set = set()

        # ── hosts ───────────────────────────────────────────────────────────────────────────────────────
        if "hosts" in decoded:
            cols, hrows = decoded["hosts"]
            if "dhcp_identifier" not in cols or "dhcp_identifier_type" not in cols:
                results.append(
                    "❌ hosts: refused — the file's hosts carry no identifier. Nothing was imported into it."
                )
                decoded.pop("hosts")
            else:
                insert_cols = [c for c in cols if c != "host_id"]
                extra = _required_defaults(conn, "hosts", set(insert_cols))
                update_cols = [c for c in insert_cols if c not in _KEA_HOST_IDENTITY]
                inserted = updated = skipped = 0
                with conn.cursor() as cur:
                    for n, h in enumerate(hrows, 1):
                        where = " AND ".join(f"`{c}` <=> %s" for c in _KEA_HOST_IDENTITY if c in cols)
                        cur.execute(
                            f"SELECT host_id FROM `hosts` WHERE {where}",
                            [h.get(c) for c in _KEA_HOST_IDENTITY if c in cols],
                        )
                        found = cur.fetchone()
                        file_id = h.get("host_id")
                        if found:
                            if not overwrite:
                                skipped += 1
                                host_map[file_id] = None
                                continue
                            if update_cols:
                                sets = ", ".join(f"`{c}` = %s" for c in update_cols)
                                try:
                                    cur.execute(
                                        f"UPDATE `hosts` SET {sets} WHERE host_id = %s",
                                        [h.get(c) for c in update_cols] + [found["host_id"]],
                                    )
                                except Exception as e:
                                    raise ImportAborted(
                                        f"hosts row {n}: the database refused the update", type(e).__name__
                                    ) from e
                            updated += 1
                            host_map[file_id] = found["host_id"]
                            updated_hosts.add(found["host_id"])
                            continue
                        try:
                            _insert_row(
                                cur,
                                "hosts",
                                insert_cols + list(extra),
                                [h.get(c) for c in insert_cols] + list(extra.values()),
                            )
                        except Exception as e:
                            if _is_duplicate_key(e) and not overwrite:
                                skipped += 1  # another unique key of Kea's (the v4 address, say) already has it
                                host_map[file_id] = None
                                continue
                            raise ImportAborted(
                                f"hosts row {n}: the database refused the insert", type(e).__name__
                            ) from e
                        inserted += 1
                        host_map[file_id] = cur.lastrowid
                line = f"✅ hosts: {inserted} inserted"
                if overwrite:
                    line += f", {updated} existing updated in place"
                results.append(line + f", {skipped} duplicates skipped")

        # ── children, attached through the map ──────────────────────────────────────────────────────
        for tbl in ("dhcp4_options", "dhcp6_options", "ipv6_reservations"):
            if tbl not in decoded:
                continue
            cols, crows = decoded[tbl]
            if "hosts" not in decoded:
                if crows:
                    results.append(
                        f"⚠️ {tbl}: {len(crows)} rows skipped — the file's hosts were not imported, so there is nothing to attach them to"
                    )
                continue
            if overwrite and updated_hosts:
                with (
                    conn.cursor() as cur
                ):  # the file has this table: matched hosts get the file's rows, no more, no fewer
                    marks = ", ".join(["%s"] * len(updated_hosts))
                    cur.execute(f"DELETE FROM `{tbl}` WHERE host_id IN ({marks})", list(updated_hosts))
            if not crows:
                continue
            auto = _KEA_CHILD_ID[tbl]
            insert_cols = [c for c in cols if c not in (auto, "host_id")] + ["host_id"]
            extra = _required_defaults(conn, tbl, set(insert_cols))
            if "scope_id" in extra:  # a row attached to a host is a HOST's option, whatever an older file did not say
                extra["scope_id"] = KEA_HOST_OPTION_SCOPE
            inserted = dup = orphans = with_host = 0
            with conn.cursor() as cur:
                for n, r in enumerate(crows, 1):
                    fid = r.get("host_id")
                    if fid is None or fid not in host_map:
                        orphans += 1
                        continue
                    target = host_map[fid]
                    if target is None:
                        with_host += 1
                        continue
                    row = dict(r, host_id=target)
                    try:
                        _insert_row(
                            cur,
                            tbl,
                            insert_cols + list(extra),
                            [row.get(c) for c in insert_cols] + list(extra.values()),
                        )
                    except Exception as e:
                        if _is_duplicate_key(e) and not overwrite:
                            dup += 1
                            continue
                        raise ImportAborted(f"{tbl} row {n}: the database refused the insert", type(e).__name__) from e
                    inserted += 1
            line = f"✅ {tbl}: {inserted} inserted, {dup} duplicates skipped"
            if with_host:
                line += f", {with_host} skipped with their host"
            if orphans:
                line += f", {orphans} not attached to a reservation in this file (global, subnet or class options are not part of a reservation restore)"
            results.append(line)

        # ── leases (the leases group): the table's own primary key is the identity ──────────────────────
        if "lease4" in decoded:
            cols, lrows = decoded["lease4"]
            pk = [c for c in _pk_columns(conn, "lease4") if c in cols]
            extra = _required_defaults(conn, "lease4", set(cols))
            insert_cols = cols + list(extra)
            inserted = updated = dup = 0
            with conn.cursor() as cur:
                for n, r in enumerate(lrows, 1):
                    vals = [r.get(c) for c in cols] + list(extra.values())
                    try:
                        if overwrite:
                            sets = (
                                ", ".join(f"`{c}` = VALUES(`{c}`)" for c in cols if c not in pk)
                                or f"`{pk[0]}` = `{pk[0]}`"
                            )
                            col_str = ", ".join(f"`{c}`" for c in insert_cols)
                            cur.execute(
                                f"INSERT INTO `lease4` ({col_str}) VALUES ({', '.join(['%s'] * len(insert_cols))}) "
                                f"ON DUPLICATE KEY UPDATE {sets}",
                                vals,
                            )
                            if cur.rowcount == 1:
                                inserted += 1
                            else:
                                updated += 1
                        else:
                            _insert_row(cur, "lease4", insert_cols, vals)
                            inserted += 1
                    except Exception as e:
                        if _is_duplicate_key(e) and not overwrite:
                            dup += 1
                            continue
                        raise ImportAborted(f"lease4 row {n}: the database refused the row", type(e).__name__) from e
            line = f"✅ lease4: {inserted} inserted"
            if overwrite:
                line += f", {updated} updated in place"
            results.append(line + f", {dup} duplicates skipped")
        conn.commit()
    except ImportAborted:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Kea import failed and was rolled back: {e}") from e
    finally:
        conn.close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Migration
# ─────────────────────────────────────────────────────────────────────────────


def test_connection(host, port, user, password, database, ssl_ca=""):
    """Test a DB connection. Returns (True, info_dict) or (False, error_str)."""
    try:
        conn = _direct_conn(host, port, user, password, database, ssl_ca)
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION() as v")
            ver = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_schema=%s", (database,))
            table_count = cur.fetchone()["cnt"]
        conn.close()
        return True, {"version": ver, "table_count": table_count, "database": database, "host": host}
    except Exception as e:
        return False, str(e)


class MigrationRefused(RuntimeError):
    """A migration refused BEFORE it wrote anything: its target is not what the migration needs it to be, or
    nothing was asked for. Nothing was created, copied or removed (v5.67.0-beta.13, Q127)."""


def _pk_columns(conn, table) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name AS col FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s AND column_key = 'PRI' ORDER BY ordinal_position",
            (table,),
        )
        return [r["col"] for r in cur.fetchall()]


def _norm_key(v):
    return bytes(v).hex() if isinstance(v, (bytes, bytearray)) else v


def _pk_sample(conn, table, pk_cols, n=100) -> list[tuple]:
    """The first and last `n` primary keys of `table` (the whole table when it is smaller than 2n)."""
    cols = ", ".join(f"`{c}`" for c in pk_cols)
    out = []
    with conn.cursor() as cur:
        for direction in ("ASC", "DESC"):
            order = ", ".join(f"`{c}` {direction}" for c in pk_cols)
            cur.execute(f"SELECT {cols} FROM `{table}` ORDER BY {order} LIMIT {int(n)}")
            out.extend(tuple(r[c] for c in pk_cols) for r in cur.fetchall())
    return sorted(set(out), key=lambda k: tuple(str(x) for x in k))


def _pks_missing(conn, table, pk_cols, keys) -> list[tuple]:
    """Which of `keys` (primary-key tuples) are NOT in `table`."""
    missing = []
    cols = ", ".join(f"`{c}`" for c in pk_cols)
    with conn.cursor() as cur:
        for i in range(0, len(keys), 200):
            chunk = keys[i : i + 200]
            if len(pk_cols) == 1:
                cur.execute(
                    f"SELECT {cols} FROM `{table}` WHERE `{pk_cols[0]}` IN ({', '.join(['%s'] * len(chunk))})",
                    [k[0] for k in chunk],
                )
            else:
                tup = "(" + ", ".join(["%s"] * len(pk_cols)) + ")"
                cur.execute(
                    f"SELECT {cols} FROM `{table}` WHERE ({cols}) IN ({', '.join([tup] * len(chunk))})",
                    [v for k in chunk for v in k],
                )
            found = {tuple(_norm_key(r[c]) for c in pk_cols) for r in cur.fetchall()}
            missing.extend(k for k in chunk if tuple(_norm_key(v) for v in k) not in found)
    return missing


def _kea_schema_version(conn):
    """(version, minor) from Kea's own `schema_version` row, or None when this is not an initialised Kea
    database (`kea-admin db-init` creates the table and its row)."""
    if not _table_exists(conn, "schema_version"):
        return None
    with conn.cursor() as cur:
        cur.execute("SELECT version, minor FROM schema_version ORDER BY version DESC LIMIT 1")
        r = cur.fetchone()
    return (int(r["version"]), int(r["minor"] or 0)) if r else None


def _copy_table_rows(src, dst, tbl, batch=1000, track=None, pk_cols=None) -> int:
    """Copy every row of `tbl` from `src` to `dst` — the driver's own values straight across, bytes as
    bytes (v5.67.0-beta.11, Q123: a migration is a copy between two live databases, so there is no JSON in the
    middle to clean for) — with a PLAIN INSERT (v5.67.0-beta.13, Q127): a collision is an error, never a row
    silently left out, and the count is what the server says it inserted (`executemany`'s row count), checked
    against the batch. `track`, when given (a list), receives the primary key of every row inserted, so a
    failed run can delete exactly those rows and no others. Streams the source with a server-side cursor in
    `batch`-row slices, so a large lease4 is never held whole. Returns the number of rows inserted."""
    count = 0
    sql = None
    cols = None
    with src.cursor(pymysql.cursors.SSDictCursor) as scur:
        scur.execute(f"SELECT * FROM `{tbl}`")
        while True:
            rows = scur.fetchmany(batch)
            if not rows:
                break
            if cols is None:
                cols = list(rows[0].keys())
                col_str = ", ".join(f"`{c}`" for c in cols)
                ph_str = ", ".join(["%s"] * len(cols))
                sql = f"INSERT INTO `{tbl}` ({col_str}) VALUES ({ph_str})"  # nosec B608 - table/column names come from the source database's own schema and Jen's fixed table lists, never request data; the values are bound parameters
            with dst.cursor() as dcur:
                affected = dcur.executemany(sql, [[r.get(c) for c in cols] for r in rows])
            if affected != len(rows):
                raise RuntimeError(f"{tbl}: {len(rows)} rows were sent but the server reports {affected} inserted")
            if track is not None and pk_cols:
                track.extend(tuple(r[c] for c in pk_cols) for r in rows)
            count += len(rows)
    return count


def _verify_copy(src, dst, tbl, dst_before, pk_cols):
    """Per table: the target holds exactly `dst_before` + what the source has, AND a sample of the source's
    primary keys (the first and last hundred) is present in the target."""
    sc, dc = _row_count(src, tbl), _row_count(dst, tbl)
    if dc - dst_before != sc:
        raise RuntimeError(f"Row count mismatch on {tbl}: source {sc}, target gained {dc - dst_before}")
    if pk_cols:
        missing = _pks_missing(dst, tbl, pk_cols, _pk_sample(src, tbl, pk_cols))
        if missing:
            raise RuntimeError(
                f"{tbl}: {len(missing)} sampled primary key(s) are missing from the target, e.g. {missing[0]}"
            )


def _delete_tracked(conn, order, pk_by_table, inserted):
    """Delete exactly the rows a failed run inserted — by primary key, children before parents (`order` is the
    copy order, reversed here). Used only when a rollback could not be confirmed; a rollback is the normal undo."""
    with conn.cursor() as cur:
        for tbl in reversed(order):
            keys, pk = inserted.get(tbl) or [], pk_by_table.get(tbl)
            if not keys or not pk:
                continue
            for i in range(0, len(keys), 200):
                chunk = keys[i : i + 200]
                if len(pk) == 1:
                    cur.execute(
                        f"DELETE FROM `{tbl}` WHERE `{pk[0]}` IN ({', '.join(['%s'] * len(chunk))})",
                        [k[0] for k in chunk],
                    )
                else:
                    cols = ", ".join(f"`{c}`" for c in pk)
                    tup = "(" + ", ".join(["%s"] * len(pk)) + ")"
                    cur.execute(
                        f"DELETE FROM `{tbl}` WHERE ({cols}) IN ({', '.join([tup] * len(chunk))})",
                        [v for k in chunk for v in k],
                    )
    conn.commit()


def migrate_jen(target_host, target_port, target_user, target_password, target_db, tables=None, progress_cb=None):
    """
    Migrate Jen DB to a new server.

    The target contract (v5.67.0-beta.13, Q127) is checked BEFORE anything is written: every table being
    migrated must be ABSENT on the target — this creates tables, it never replaces or merges into one — and
    something must have been selected: `tables=None` means everything, but an empty list, or names that are
    none of Jen's, is refused rather than quietly widened to everything. A failure drops only the tables THIS run
    created (existence is checked before each CREATE), never one that was there; the data is copied in one
    transaction with plain INSERTs, counted from what the server reports and verified per table against the
    source (counts and a sample of primary keys).
    progress_cb(message): called with progress updates.
    Returns list of result strings.
    """

    def _cb(msg):
        if progress_cb:
            progress_cb(msg)
        logger.info(f"migrate_jen: {msg}")

    results = []

    _cb(f"Connecting to source Jen DB ({extensions.JEN_DB_HOST}/{extensions.JEN_DB_NAME})...")
    src = _direct_jen_conn()
    # v5.66.0-beta.5 (Q107) — the same universe write_jen_export() uses: core JEN_TABLES plus
    # every currently-installed plugin's tables that actually exist on the SOURCE, so a plugin
    # table is never silently left off a migrated-to-a-new-server Jen either.
    universe = export_tables(src)
    if tables is None:
        selected = universe
    else:
        selected = _validate_tables(tables, universe)
        if not selected:
            src.close()
            raise MigrationRefused(
                "No table was selected, or none of the names given is one Jen can migrate — nothing was copied."
            )
    selected = [t for t in selected if _table_exists(src, t)]
    if not selected:
        src.close()
        raise MigrationRefused("None of the selected tables exists on the source — nothing was copied.")
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}") from e

    present = [t for t in selected if _table_exists(dst, t)]
    if present:
        src.close()
        dst.close()
        raise MigrationRefused(
            f"The target database already has {', '.join(present)}. A migration creates tables and never replaces "
            f"or merges into one that exists — point it at an empty database (or drop those tables yourself first). "
            f"Nothing was changed."
        )

    created_tables: list[str] = []
    try:
        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=0")
        _cb("Reading source schema...")
        for tbl in selected:
            if _table_exists(dst, tbl):  # checked again, at the moment of the CREATE
                raise MigrationRefused(f"{tbl} appeared on the target while the migration was starting — stopped.")
            with src.cursor() as cur:
                cur.execute(f"SHOW CREATE TABLE `{tbl}`")
                row = cur.fetchone()
                ddl = row[[k for k in row if "Create" in k][0]]
                ddl = re.sub(r" AUTO_INCREMENT=\d+", "", ddl)
            with dst.cursor() as cur:
                cur.execute(ddl)
            created_tables.append(tbl)  # only now is it ours to drop
            _cb(f"  ✅ Created table: {tbl}")

        _cb("Copying data...")
        dst.begin()
        pk_by_table = {t: _pk_columns(src, t) for t in created_tables}
        for tbl in created_tables:
            count = _copy_table_rows(src, dst, tbl, pk_cols=pk_by_table[tbl])
            if count == 0:
                _cb(f"  ℹ️ {tbl}: empty — skipped")
                results.append(f"ℹ️ {tbl}: 0 rows")
                continue
            _cb(f"  ✅ {tbl}: {count} rows copied")
            results.append(f"✅ {tbl}: {count} rows")

        _cb("Verifying...")
        for tbl in created_tables:
            _verify_copy(src, dst, tbl, 0, pk_by_table[tbl])

        dst.commit()
        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=1")
        _cb("✅ Migration complete — every table's row count and a sample of its primary keys verified.")

    except Exception as e:
        # the rows are one transaction: undone by the rollback; the tables are DDL (auto-committed), so they are
        # dropped — only the ones this run created
        with contextlib.suppress(Exception):
            dst.rollback()
        with contextlib.suppress(Exception), dst.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            for tbl in reversed(created_tables):
                cur.execute(f"DROP TABLE IF EXISTS `{tbl}`")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
            dst.commit()
        src.close()
        dst.close()
        if isinstance(e, MigrationRefused):
            raise
        raise RuntimeError(
            f"Migration failed — the tables it created on the target were removed and nothing that was there was "
            f"touched. Error: {e}"
        ) from e

    src.close()
    dst.close()
    return results


def migrate_kea(
    target_host, target_port, target_user, target_password, target_db, group=KEA_BACKUP_GROUP, progress_cb=None
):
    """
    Migrate Kea reservations (or leases) into another Kea database.

    DATA ONLY (v5.67.0-beta.13, Q127): Jen never creates or alters Kea's schema (CLAUDE.md "Databases"). The
    target must already be an INITIALISED Kea database — `kea-admin db-init` — with a `schema_version` row whose
    major version equals the source's and every table of the group that exists on the source; anything else is
    refused before a row is written, naming what is wrong. Rows are copied in one transaction with plain INSERTs
    (a primary-key or unique-key collision is an error, not a skipped row), counted from what the server
    reports, and verified per table. On any failure the transaction is rolled back; if the rollback cannot be
    confirmed, exactly the rows this run inserted (tracked by primary key) are deleted, children first — never
    a table, never a row that was there.
    """

    def _cb(msg):
        if progress_cb:
            progress_cb(msg)
        logger.info(f"migrate_kea: {msg}")

    if group not in KEA_EXPORT_GROUPS:
        raise ValueError(f"Unknown migration group: {group}")
    results = []

    _cb(f"Connecting to source Kea DB ({extensions.KEA_DB_HOST}/{extensions.KEA_DB_NAME})...")
    src = _direct_kea_conn()
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}") from e

    def _refuse(message):
        src.close()
        dst.close()
        raise MigrationRefused(message + " Nothing was changed.")

    sv_src, sv_dst = _kea_schema_version(src), _kea_schema_version(dst)
    if sv_src is None:
        _refuse("The source is not an initialised Kea database (it has no schema_version row).")
    if sv_dst is None:
        _refuse(
            f"The target ({target_db}) is not an initialised Kea database — it has no schema_version row. "
            f"Run `kea-admin db-init mysql` on it first: Jen copies data only and never creates Kea's tables."
        )
    if sv_dst[0] != sv_src[0]:
        _refuse(
            f"The target's Kea schema is version {sv_dst[0]}.{sv_dst[1]} and the source's is "
            f"{sv_src[0]}.{sv_src[1]}: the major versions must match (upgrade the target with kea-admin, "
            f"or migrate between the same Kea major)."
        )
    tables = [t for t in KEA_EXPORT_GROUPS[group]["tables"] if _table_exists(src, t)]
    missing = [t for t in tables if not _table_exists(dst, t)]
    if missing:
        _refuse(f"The target is missing {', '.join(missing)}, which the source has.")
    if not tables:
        _refuse("None of this group's tables exists on the source.")

    pk_by_table = {t: _pk_columns(dst, t) for t in tables}
    before = {t: _row_count(dst, t) for t in tables}
    inserted: dict[str, list] = {t: [] for t in tables}
    try:
        dst.begin()
        for tbl in tables:
            count = _copy_table_rows(src, dst, tbl, track=inserted[tbl], pk_cols=pk_by_table[tbl])
            if count == 0:
                _cb(f"  ℹ️ {tbl}: empty")
                results.append(f"ℹ️ {tbl}: 0 rows")
                continue
            _cb(f"  ✅ {tbl}: {count} rows copied")
            results.append(f"✅ {tbl}: {count} rows")
        _cb("Verifying...")
        for tbl in tables:
            _verify_copy(src, dst, tbl, before[tbl], pk_by_table[tbl])
        dst.commit()
        _cb("✅ Kea migration complete.")
    except Exception as e:
        rolled_back = True
        try:
            dst.rollback()
        except Exception:
            rolled_back = False
        if not rolled_back:
            # the rollback could not be confirmed (the connection is gone): delete exactly what this run
            # inserted, by primary key, on a fresh connection
            with contextlib.suppress(Exception):
                fresh = _direct_conn(target_host, target_port, target_user, target_password, target_db)
                try:
                    _delete_tracked(fresh, tables, pk_by_table, inserted)
                finally:
                    fresh.close()
        with contextlib.suppress(Exception):
            dst.close()
        src.close()
        raise RuntimeError(
            f"Kea migration failed — the target was rolled back and nothing that was there was touched. Error: {e}"
        ) from e

    dst.close()
    src.close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled Backups
# ─────────────────────────────────────────────────────────────────────────────


def get_schedule():
    """Return current backup schedule config from DB."""
    from jen.models.db import jen_db

    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT * FROM backup_schedule WHERE id=1")
            row = cur.fetchone()
        return row or {}
    except Exception:
        return {}


# v5.67.0-beta.5 (Q117, item j) — scheduler.py's own _run_backup_job only
# ever checks `freq == "weekly"`; every other value runs daily-shaped.
# "daily"/"weekly" is the whole set it actually understands — read from
# there, not guessed, and it's also the only two <option>s
# templates/database.html's own <select> ever offers.
VALID_SCHEDULE_FREQUENCIES = ("daily", "weekly")
_SCHEDULE_HOUR_RANGE = range(24)
_SCHEDULE_KEEP_RANGE = range(1, 31)


def validate_schedule(form) -> tuple[dict, list[str]]:
    """Validate and parse a backup-schedule POST (a Flask `request.form`
    or any `.get(key, default)`-shaped mapping) — shared by
    routes/database.py::save_schedule and routes/setup.py's own
    Recovery-step "schedule" action, which both used to do a bare
    `int(form.get("hour"))` with no try/except: a malformed value
    (empty, non-numeric, out of range) was an unhandled 500 rather than
    a validation error.

    Returns (values, errors). `values` is only complete and safe to pass
    to save_schedule() when `errors` is empty — a field that failed
    validation is left out of `values` entirely rather than guessed at,
    so a caller can't accidentally use a half-valid result."""
    errors = []
    values = {
        "enabled": 1 if form.get("enabled") else 0,
        "include_jen": 1 if form.get("include_jen") else 0,
        "include_kea": 1 if form.get("include_kea") else 0,
    }

    frequency = (form.get("frequency", "daily") or "daily").strip()
    if frequency in VALID_SCHEDULE_FREQUENCIES:
        values["frequency"] = frequency
    else:
        errors.append(f"Frequency must be one of: {', '.join(VALID_SCHEDULE_FREQUENCIES)}.")

    try:
        hour = int(form.get("hour", "2") or "2")
        if hour not in _SCHEDULE_HOUR_RANGE:
            raise ValueError
        values["hour"] = hour
    except (TypeError, ValueError):
        errors.append("Hour must be a whole number from 0 to 23.")

    try:
        keep_count = int(form.get("keep_count", "7") or "7")
        if keep_count not in _SCHEDULE_KEEP_RANGE:
            raise ValueError
        values["keep_count"] = keep_count
    except (TypeError, ValueError):
        errors.append("Keep must be a whole number from 1 to 30.")

    return values, errors


def save_schedule(enabled, frequency, hour, keep_count, include_jen, include_kea):
    from jen.models.db import jen_db

    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO backup_schedule (id, enabled, frequency, hour, keep_count, include_jen, include_kea)
                VALUES (1, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    enabled=%s, frequency=%s, hour=%s,
                    keep_count=%s, include_jen=%s, include_kea=%s
            """,
                (
                    enabled,
                    frequency,
                    hour,
                    keep_count,
                    include_jen,
                    include_kea,
                    enabled,
                    frequency,
                    hour,
                    keep_count,
                    include_jen,
                    include_kea,
                ),
            )
        db.commit()


_STALE_PART_AGE_S = 24 * 60 * 60


def _sweep_stale_part_files():
    """Removes any `.part-*.tmp` left behind by a `publish_backup()` that never got to
    finish (a killed process, a crash) and is now older than a day — nothing else ever
    counts or lists these, so a truly ancient one would otherwise just sit there forever
    (v5.66.0-beta.6, Q108). A young one is left alone: it may belong to a publish that is
    genuinely still in progress right now."""
    if not os.path.isdir(BACKUP_DIR):
        return
    cutoff = datetime.utcnow().timestamp() - _STALE_PART_AGE_S
    for f in os.listdir(BACKUP_DIR):
        if not (f.startswith(".part-") and f.endswith(".tmp")):
            continue
        path = os.path.join(BACKUP_DIR, f)
        with contextlib.suppress(OSError):
            if os.path.getmtime(path) < cutoff:
                os.remove(path)


def run_scheduled_backup():
    """Run a scheduled backup — called by APScheduler or manually."""
    sched = get_schedule()
    if not sched:
        return
    _sweep_stale_part_files()
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    keep = int(sched.get("keep_count", 7))
    results = []
    if sched.get("include_jen"):
        try:
            # v5.66.0-beta.6 (Q108) — publish_backup(): a failure mid-write leaves no final
            # file at all, so pruning (a kind's own backups only, and only because THIS run
            # actually published a new one) can never run against a half-written directory.
            path = os.path.join(BACKUP_DIR, f"jen-scheduled-{ts}.json.gz")
            meta = publish_backup(path, lambda f: write_jen_export(f))
            _write_meta_sidecar(path, meta)
            results.append(f"Jen: {path}")
            _prune_backups(keep, "jen")
        except Exception as e:
            results.append(f"Jen: FAILED — {e}")
    if sched.get("include_kea"):
        try:
            # v5.67.0-beta.11 (Q123) — the reservations_all group (IPv4 AND IPv6), streamed row by row
            # through publish_backup like the Jen half: no whole-table dict, no dumps/loads round trip.
            path = os.path.join(BACKUP_DIR, f"kea-scheduled-{ts}.json.gz")
            meta = publish_backup(path, lambda f: write_kea_export(f, KEA_BACKUP_GROUP))
            _write_meta_sidecar(path, meta)
            results.append(f"{KEA_BACKUP_LABEL}: {path}")
            _prune_backups(keep, "kea")
        except Exception as e:
            results.append(f"{KEA_BACKUP_LABEL}: FAILED — {e}")

    # Update last_run
    from jen.models.db import jen_db

    status = "; ".join(results)
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("UPDATE backup_schedule SET last_run=NOW(), last_status=%s WHERE id=1", (status,))
        db.commit()


def _prune_backups(keep_count, kind):
    """Delete the oldest `<kind>-scheduled-*.json.gz` backups (and their `.meta.json`
    sidecars) beyond `keep_count`, oldest first (v5.66.0-beta.6, Q108). `kind` is 'jen' or
    'kea' — retention is per kind now, never blind to which half of a run actually
    succeeded, and a MANUAL backup (`<kind>-manual-*`, never `-scheduled-`) is not a
    candidate here at all: the schedule only ever prunes what the schedule itself wrote."""
    if not os.path.isdir(BACKUP_DIR):
        return
    prefix = f"{kind}-scheduled-"
    files = sorted(
        (
            os.path.join(BACKUP_DIR, f)
            for f in os.listdir(BACKUP_DIR)
            if f.startswith(prefix) and f.endswith(".json.gz")
        ),
        key=os.path.getmtime,
    )
    for old in files[:-keep_count] if len(files) > keep_count else []:
        with contextlib.suppress(Exception):
            os.remove(old)
        with contextlib.suppress(Exception):
            os.remove(_sidecar_path(old))


def backup_count() -> int:
    """Number of backup files — a directory listing, nothing more."""
    if not os.path.isdir(BACKUP_DIR):
        return 0
    return sum(1 for f in os.listdir(BACKUP_DIR) if f.endswith(".json.gz"))


def list_backups():
    """Return list of backup file dicts for the UI. Reads ONLY each backup's own
    `<name>.meta.json` sidecar (v5.66.0-beta.6, Q108) — never opens, decompresses, or
    JSON-parses the backup file itself, however large it's grown; a directory of daily
    backups now costs one small file read per row, not one full-file parse. A backup from
    before this Q (no sidecar yet) lists with just its size and mtime and `has_sidecar:
    False`, so the page can offer a one-time "Read details" action for it — the cost of
    actually parsing a legacy file is paid at most once, ever, per file."""
    if not os.path.isdir(BACKUP_DIR):
        return []
    results = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not fname.endswith(".json.gz"):
            continue
        path = os.path.join(BACKUP_DIR, fname)
        size = os.path.getsize(path)
        mtime = datetime.utcfromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M UTC")
        db_label = "?"
        tables = []
        exported_at = ""
        has_sidecar = False
        sidecar = _sidecar_path(path)
        if os.path.isfile(sidecar):
            try:
                with open(sidecar, encoding="utf-8") as f:
                    meta = json.load(f)
                db_label = (meta.get("database") or "?").upper()
                tables = meta.get("tables") or []
                exported_at = (meta.get("exported_at") or "")[:19].replace("T", " ")
                has_sidecar = True
            except Exception:
                pass
        results.append(
            {
                "filename": fname,
                "path": path,
                "size_kb": round(size / 1024, 1),
                "modified": mtime,
                "db": db_label,
                "tables": tables,
                "exported_at": exported_at,
                "has_sidecar": has_sidecar,
            }
        )
    return results
