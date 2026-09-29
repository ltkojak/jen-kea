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
        "config column are encrypted at rest; the key lives in /etc/jen, NOT in "
        "this export — channels will not deliver after restore onto a different "
        "install until their tokens are re-entered."
    ),
    "alert_templates": "Custom alert message templates",
    "alert_log": "Historical alert delivery log",
    "saved_searches": "Saved filter presets",
    "dashboard_prefs": "Per-user dashboard widget layout",
    "mfa_methods": "MFA method records (TOTP secrets encrypted at rest; the key lives in /etc/jen, NOT in this export — secrets will not restore onto a different install)",
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
        "the key lives in /etc/jen, NOT in this export"
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


def _write_backup(payload_dict, filename):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    path = os.path.join(BACKUP_DIR, filename)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(payload_dict, f, default=str)
    os.chmod(path, 0o600)
    return path


def _read_backup(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Try uncompressed (older exports)
        with open(path, encoding="utf-8") as f:
            return json.load(f)


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

    Written 0600: every table here can carry secrets (users, api_keys, mfa_*, kea_config_revisions)."""
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


def run_scheduled_backup():
    """Run a scheduled backup — called by APScheduler or manually."""
    sched = get_schedule()
    if not sched:
        return
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    results = []
    if sched.get("include_jen"):
        try:
            # v5.66.0-beta.4 (Q106) — straight to disk via write_jen_export(), never a
            # round trip through export_jen()'s bytes + json.loads() + _write_backup()'s
            # own re-serialize.
            os.makedirs(BACKUP_DIR, exist_ok=True)
            path = os.path.join(BACKUP_DIR, f"jen-scheduled-{ts}.json.gz")
            write_jen_export(path)
            results.append(f"Jen: {path}")
        except Exception as e:
            results.append(f"Jen: FAILED — {e}")
    if sched.get("include_kea"):
        try:
            content, fname = export_kea("reservations")
            payload = json.loads(content.decode("utf-8"))
            path = _write_backup(payload, f"kea-scheduled-{ts}.json.gz")
            results.append(f"Kea: {path}")
        except Exception as e:
            results.append(f"Kea: FAILED — {e}")

    # Prune old backups
    keep = int(sched.get("keep_count", 7))
    _prune_backups(keep)

    # Update last_run
    from jen.models.db import jen_db

    status = "; ".join(results)
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("UPDATE backup_schedule SET last_run=NOW(), last_status=%s WHERE id=1", (status,))
        db.commit()


def _prune_backups(keep_count):
    """Delete oldest backup files keeping only the last N."""
    if not os.path.isdir(BACKUP_DIR):
        return
    files = sorted(
        [os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".json.gz")], key=os.path.getmtime
    )
    for old in files[:-keep_count] if len(files) > keep_count else []:
        with contextlib.suppress(Exception):
            os.remove(old)


def backup_count() -> int:
    """Number of backup files — a directory listing, nothing more. The
    Settings landing page needs only this; list_backups() decompresses and
    JSON-parses every file for its `_meta` header, which is far too heavy
    for a status hint once daily backups accumulate (v5.13.0)."""
    if not os.path.isdir(BACKUP_DIR):
        return 0
    return sum(1 for f in os.listdir(BACKUP_DIR) if f.endswith(".json.gz"))


def list_backups():
    """Return list of backup file dicts for the UI."""
    if not os.path.isdir(BACKUP_DIR):
        return []
    results = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not fname.endswith(".json.gz"):
            continue
        path = os.path.join(BACKUP_DIR, fname)
        size = os.path.getsize(path)
        mtime = datetime.utcfromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M UTC")
        # Peek at metadata without loading entire file
        db_label = "?"
        tables = []
        exported_at = ""
        try:
            payload = _read_backup(path)
            meta = payload.get("_meta", {})
            db_label = meta.get("database", "?").upper()
            tables = meta.get("tables", [])
            exported_at = meta.get("exported_at", "")[:19].replace("T", " ")
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
            }
        )
    return results
