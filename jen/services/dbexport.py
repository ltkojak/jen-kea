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
import tempfile
from datetime import datetime

import pymysql
import pymysql.cursors

from jen import extensions

logger = logging.getLogger(__name__)

BACKUP_DIR = extensions.CONTENT_BACKUP_DIR
SCHEMA_VERSION = 1  # bump when export format changes

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
KEA_EXPORT_GROUPS = {
    "reservations": {
        "label": "Reservations (hosts + per-host DHCP options)",
        "description": "Permanent host reservations — MAC-to-IP assignments, hostnames, per-host options. This is what you want to migrate or back up.",
        "tables": ["hosts", "dhcp4_options"],
    },
    "leases": {
        "label": "Active Leases (lease4)",
        "description": "Dynamic leases currently active. These are transient — they expire and renew automatically. Only export if you need a point-in-time snapshot.",
        "tables": ["lease4"],
    },
}

KEA_ALL_TABLES = {t for grp in KEA_EXPORT_GROUPS.values() for t in grp["tables"]}


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
        user=extensions.KEA_DB_USER,
        password=extensions.KEA_DB_PASS,
        database=extensions.KEA_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.KEA_DB_SSL_CA),
    )


def _direct_conn(host, port, user, password, database):
    return pymysql.connect(
        host=host,
        port=int(port),
        user=user,
        password=password,
        database=database,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
    )


def _clean_row(row):
    """One row, datetimes ISO-formatted and binary columns hex-encoded — the same cleanup
    _dump_table and write_jen_export's streaming path both need, factored out so the
    row-by-row streamer isn't duplicating it (v5.66.0-beta.4, Q106)."""
    clean = {}
    for k, v in row.items():
        if isinstance(v, (datetime,)):
            clean[k] = v.isoformat() if v else None
        elif isinstance(v, (bytes, bytearray)):
            clean[k] = v.hex()
        else:
            clean[k] = v
    return clean


def _dump_table(conn, table):
    """Return all rows from table as a list of dicts, with datetime serialized."""
    with conn.cursor() as cur:
        cur.execute(f"SELECT * FROM `{table}`")
        rows = cur.fetchall()
    return [_clean_row(row) for row in rows]


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
                count = 0
                if _table_exists(conn, tbl):
                    with conn.cursor(pymysql.cursors.SSDictCursor) as cur:
                        cur.execute(f"SELECT * FROM `{tbl}`")
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
                f.write("]")
                row_counts[tbl] = count
            meta = _make_metadata("jen", selected)
            meta["row_counts"] = row_counts
            meta["format"] = 2
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


def export_kea(group="reservations"):
    """
    Export Kea DB data.
    group: 'reservations' or 'leases'
    Returns (json_bytes, filename).
    """
    if group not in KEA_EXPORT_GROUPS:
        raise ValueError(f"Unknown export group: {group}")
    grp_cfg = KEA_EXPORT_GROUPS[group]
    tables = grp_cfg["tables"]
    conn = _direct_kea_conn()
    payload = {"_meta": _make_metadata("kea", tables, {"group": group}), "data": {}}
    try:
        for tbl in tables:
            if _table_exists(conn, tbl):
                payload["data"][tbl] = _dump_table(conn, tbl)
            else:
                payload["data"][tbl] = []
        payload["_meta"]["row_counts"] = {t: len(payload["data"][t]) for t in tables}
    finally:
        conn.close()
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"kea-{group}-export-{ts}.json.gz"
    content = json.dumps(payload, default=str).encode("utf-8")
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


def import_jen(file_bytes, tables_to_restore=None, truncate=True):
    """
    Restore Jen DB tables from export bytes.
    tables_to_restore: list of table names to restore, or None for all in file.
    truncate: if True, clears existing rows before inserting (replace mode).
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
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    [[r.get(c) for c in cols] for r in rows],
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
                results.append(f"⚠️ {pid}: migration replay failed ({msg}) — its tables/data may be incomplete")
                continue

            # Only the tables the export's own `data` actually carries get rows imported — a
            # format-1 export (or a table with zero rows) has nothing here, and that's fine:
            # the schema repair above already put the table back, just empty.
            plugin_tables_to_import = [t for t in plugin_tables_all if t in selected_set]
            if not plugin_tables_to_import:
                continue
            try:
                conn.begin()
                for tbl in plugin_tables_to_import:
                    _import_rows(conn, tbl)
                conn.commit()
            except Exception as e:
                conn.rollback()
                results.append(f"⚠️ {pid}: row import failed and was rolled back ({e})")
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

    return results


def import_kea(file_bytes, duplicate_mode="skip"):
    """
    Restore Kea reservations from export bytes.
    duplicate_mode: 'skip' or 'overwrite'.
    Returns list of result strings.
    """
    meta, data, err = parse_import_file(file_bytes)
    if err:
        raise ValueError(err)
    if meta.get("database") != "kea":
        raise ValueError(f"This export is for '{meta.get('database')}' — expected 'kea'. Wrong file?")

    results = []
    conn = _direct_kea_conn()
    try:
        conn.begin()
        for tbl in data:
            if tbl not in KEA_ALL_TABLES:
                results.append(f"⚠️ {tbl}: not a recognized Kea table — skipped")
                continue
            rows = data.get(tbl, [])
            if not rows:
                results.append(f"ℹ️ {tbl}: no rows in export — skipped")
                continue
            if not _table_exists(conn, tbl):
                results.append(f"⚠️ {tbl}: table not found in Kea DB — skipped")
                continue
            inserted = skipped = 0
            real_cols = _get_table_columns(conn, tbl)
            cols = [c for c in rows[0] if c in real_cols]
            if not cols:
                results.append(f"⚠️ {tbl}: no recognized columns in import data — skipped")
                continue
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str = ", ".join(["%s"] * len(cols))
            verb = "REPLACE" if duplicate_mode == "overwrite" else "INSERT IGNORE"
            with conn.cursor() as cur:
                for row in rows:
                    try:
                        cur.execute(f"{verb} INTO `{tbl}` ({col_str}) VALUES ({ph_str})", [row.get(c) for c in cols])
                        if cur.rowcount > 0:
                            inserted += 1
                        else:
                            skipped += 1
                    except Exception:
                        skipped += 1
            results.append(f"✅ {tbl}: {inserted} inserted, {skipped} skipped")
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Kea import failed and was rolled back: {e}") from e
    finally:
        conn.close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Migration
# ─────────────────────────────────────────────────────────────────────────────


def test_connection(host, port, user, password, database):
    """Test a DB connection. Returns (True, info_dict) or (False, error_str)."""
    try:
        conn = _direct_conn(host, port, user, password, database)
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION() as v")
            ver = cur.fetchone()["v"]
            cur.execute("SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_schema=%s", (database,))
            table_count = cur.fetchone()["cnt"]
        conn.close()
        return True, {"version": ver, "table_count": table_count, "database": database, "host": host}
    except Exception as e:
        return False, str(e)


def migrate_jen(target_host, target_port, target_user, target_password, target_db, tables=None, progress_cb=None):
    """
    Migrate Jen DB to a new server.
    Runs in a transaction on the target — rolls back on failure.
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
    if tables:
        selected = _validate_tables(tables, universe) or universe
    else:
        selected = universe
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}") from e

    try:
        # Get source schema DDL for selected tables and recreate on target
        _cb("Reading source schema...")
        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=0")
        dst.begin()

        created_tables = []
        for tbl in selected:
            if not _table_exists(src, tbl):
                _cb(f"  ⚠️ {tbl}: not in source — skipping")
                continue
            with src.cursor() as cur:
                cur.execute(f"SHOW CREATE TABLE `{tbl}`")
                row = cur.fetchone()
                ddl_key = [k for k in row if "Create" in k][0]
                ddl = row[ddl_key]
                # Ensure IF NOT EXISTS and strip AUTO_INCREMENT value
                ddl = ddl.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")
                import re

                ddl = re.sub(r" AUTO_INCREMENT=\d+", "", ddl)
            with dst.cursor() as cur:
                cur.execute(ddl)
            created_tables.append(tbl)
            _cb(f"  ✅ Created table: {tbl}")

        # Copy data table by table
        _cb("Copying data...")
        for tbl in created_tables:
            rows = _dump_table(src, tbl)
            count = len(rows)
            if count == 0:
                _cb(f"  ℹ️ {tbl}: empty — skipped")
                results.append(f"ℹ️ {tbl}: 0 rows")
                continue
            cols = list(rows[0].keys())
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str = ", ".join(["%s"] * len(cols))
            with dst.cursor() as cur:
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    [[r.get(c) for c in cols] for r in rows],
                )
            _cb(f"  ✅ {tbl}: {count} rows copied")
            results.append(f"✅ {tbl}: {count} rows")

        # Verify row counts match
        _cb("Verifying row counts...")
        mismatches = []
        for tbl in created_tables:
            src_count = _row_count(src, tbl)
            dst_count = _row_count(dst, tbl)
            if src_count != dst_count:
                mismatches.append(f"{tbl} (source: {src_count}, target: {dst_count})")
        if mismatches:
            raise RuntimeError(f"Row count mismatch after copy — rolled back. Tables: {', '.join(mismatches)}")

        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=1")
        dst.commit()
        _cb("✅ Migration complete — all row counts verified.")

    except Exception as e:
        try:
            dst.rollback()
            # Drop the tables we created so the target is left clean
            with dst.cursor() as cur:
                cur.execute("SET FOREIGN_KEY_CHECKS=0")
                for tbl in created_tables:
                    cur.execute(f"DROP TABLE IF EXISTS `{tbl}`")
                cur.execute("SET FOREIGN_KEY_CHECKS=1")
            dst.commit()
        except Exception:
            pass
        src.close()
        dst.close()
        raise RuntimeError(f"Migration failed — target DB rolled back and cleaned up. Error: {e}") from e

    src.close()
    dst.close()
    return results


def migrate_kea(
    target_host, target_port, target_user, target_password, target_db, group="reservations", progress_cb=None
):
    """
    Migrate Kea reservations (or leases) to a new DB server.
    """

    def _cb(msg):
        if progress_cb:
            progress_cb(msg)
        logger.info(f"migrate_kea: {msg}")

    if group not in KEA_EXPORT_GROUPS:
        raise ValueError(f"Unknown migration group: {group}")
    tables = KEA_EXPORT_GROUPS[group]["tables"]
    results = []

    _cb(f"Connecting to source Kea DB ({extensions.KEA_DB_HOST}/{extensions.KEA_DB_NAME})...")
    src = _direct_kea_conn()
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}") from e

    created_tables = []
    try:
        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=0")
        dst.begin()
        import re

        for tbl in tables:
            if not _table_exists(src, tbl):
                _cb(f"  ⚠️ {tbl}: not in source Kea DB — skipping")
                continue
            with src.cursor() as cur:
                cur.execute(f"SHOW CREATE TABLE `{tbl}`")
                row = cur.fetchone()
                ddl_key = [k for k in row if "Create" in k][0]
                ddl = row[ddl_key].replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")
                ddl = re.sub(r" AUTO_INCREMENT=\d+", "", ddl)
            with dst.cursor() as cur:
                cur.execute(ddl)
            created_tables.append(tbl)
            _cb(f"  ✅ Created table: {tbl}")

        for tbl in created_tables:
            rows = _dump_table(src, tbl)
            count = len(rows)
            if count == 0:
                _cb(f"  ℹ️ {tbl}: empty")
                results.append(f"ℹ️ {tbl}: 0 rows")
                continue
            cols = list(rows[0].keys())
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str = ", ".join(["%s"] * len(cols))
            with dst.cursor() as cur:
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    [[r.get(c) for c in cols] for r in rows],
                )
            _cb(f"  ✅ {tbl}: {count} rows copied")
            results.append(f"✅ {tbl}: {count} rows")

        # Verify
        for tbl in created_tables:
            sc = _row_count(src, tbl)
            dc = _row_count(dst, tbl)
            if sc != dc:
                raise RuntimeError(f"Row count mismatch on {tbl} (src={sc} dst={dc})")

        dst.cursor().execute("SET FOREIGN_KEY_CHECKS=1")
        dst.commit()
        _cb("✅ Kea migration complete.")
    except Exception as e:
        try:
            dst.rollback()
            with dst.cursor() as cur:
                cur.execute("SET FOREIGN_KEY_CHECKS=0")
                for tbl in created_tables:
                    cur.execute(f"DROP TABLE IF EXISTS `{tbl}`")
                cur.execute("SET FOREIGN_KEY_CHECKS=1")
            dst.commit()
        except Exception:
            pass
        dst.close()
        src.close()
        raise RuntimeError(f"Kea migration failed — rolled back. Error: {e}") from e

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
            content, fname = export_kea("reservations")
            payload = json.loads(content.decode("utf-8"))
            path = _write_backup(payload, f"kea-scheduled-{ts}.json.gz")
            results.append(f"Kea: {path}")
            _prune_backups(keep, "kea")
        except Exception as e:
            results.append(f"Kea: FAILED — {e}")

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
