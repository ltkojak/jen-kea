"""
jen/services/dbexport.py
────────────────────────
Database export, import, backup scheduling, and migration logic.
All operations clearly labelled by which database they touch (Jen or Kea).
"""

import gzip
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta

import pymysql
import pymysql.cursors

from jen import extensions

logger = logging.getLogger(__name__)

BACKUP_DIR   = "/opt/jen/backups"
SCHEMA_VERSION = 1   # bump when export format changes

# ── Jen tables available for export ──────────────────────────────────────────
JEN_TABLES = {
    "users":               "User accounts (includes password hashes — handle with care)",
    "devices":             "Device inventory (MAC, hostname, manufacturer, notes)",
    "reservation_notes":   "Notes attached to Kea reservations",
    "settings":            "All Jen application settings",
    "alert_channels":      "Alert channel configuration (Telegram etc.)",
    "alert_templates":     "Custom alert message templates",
    "alert_log":           "Historical alert delivery log",
    "saved_searches":      "Saved filter presets",
    "dashboard_prefs":     "Per-user dashboard widget layout",
    "mfa_methods":         "MFA method records (secrets stored hashed)",
    "mfa_backup_codes":    "MFA backup/recovery codes",
    "mfa_trusted_devices": "Trusted device tokens for MFA bypass",
    "api_keys":            "API key records (hashed — raw keys not recoverable)",
    "audit_log":           "Full audit trail (can be large)",
    "lease_history":       "Historical lease count snapshots",
    "subnet_notes":        "Notes attached to subnets",
    "backup_schedule":     "Backup scheduler configuration",
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


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _direct_jen_conn():
    return pymysql.connect(
        host=extensions.JEN_DB_HOST,
        user=extensions.JEN_DB_USER,
        password=extensions.JEN_DB_PASS,
        database=extensions.JEN_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
    )


def _direct_kea_conn():
    return pymysql.connect(
        host=extensions.KEA_DB_HOST,
        user=extensions.KEA_DB_USER,
        password=extensions.KEA_DB_PASS,
        database=extensions.KEA_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
    )


def _direct_conn(host, port, user, password, database):
    return pymysql.connect(
        host=host, port=int(port), user=user, password=password,
        database=database, cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10, charset="utf8mb4",
    )


def _dump_table(conn, table):
    """Return all rows from table as a list of dicts, with datetime serialised."""
    with conn.cursor() as cur:
        cur.execute(f"SELECT * FROM `{table}`")
        rows = cur.fetchall()
    result = []
    for row in rows:
        clean = {}
        for k, v in row.items():
            if isinstance(v, (datetime,)):
                clean[k] = v.isoformat() if v else None
            elif isinstance(v, (bytes, bytearray)):
                clean[k] = v.hex()
            else:
                clean[k] = v
        result.append(clean)
    return result


def _table_exists(conn, table):
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE %s", (table,))
        return bool(cur.fetchone())


def _row_count(conn, table):
    if not _table_exists(conn, table):
        return 0
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) as cnt FROM `{table}`")
        return cur.fetchone()["cnt"]


def _make_metadata(db_label, tables_included, extra=None):
    meta = {
        "jen_export_version": SCHEMA_VERSION,
        "jen_app_version":    extensions.cfg.get("jen", "version", fallback="unknown") if extensions.cfg else "unknown",
        "database":           db_label,          # "jen" or "kea"
        "exported_at":        datetime.utcnow().isoformat() + "Z",
        "tables":             tables_included,
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
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def export_jen(tables=None):
    """
    Export selected Jen DB tables.
    tables: list of table names, or None for all.
    Returns (json_bytes, filename).
    """
    selected = tables if tables else list(JEN_TABLES.keys())
    conn = _direct_jen_conn()
    payload = {"_meta": _make_metadata("jen", selected), "data": {}}
    try:
        for tbl in selected:
            if _table_exists(conn, tbl):
                payload["data"][tbl] = _dump_table(conn, tbl)
            else:
                payload["data"][tbl] = []
        payload["_meta"]["row_counts"] = {t: len(payload["data"][t]) for t in selected}
    finally:
        conn.close()
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"jen-export-{ts}.json.gz"
    content  = json.dumps(payload, default=str).encode("utf-8")
    return content, filename


def export_kea(group="reservations"):
    """
    Export Kea DB data.
    group: 'reservations' or 'leases'
    Returns (json_bytes, filename).
    """
    grp_cfg  = KEA_EXPORT_GROUPS[group]
    tables   = grp_cfg["tables"]
    conn     = _direct_kea_conn()
    payload  = {"_meta": _make_metadata("kea", tables, {"group": group}), "data": {}}
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
    content  = json.dumps(payload, default=str).encode("utf-8")
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
        return meta, data, f"Export schema version {meta['jen_export_version']} is newer than this Jen supports ({SCHEMA_VERSION}). Upgrade Jen first."
    return meta, data, None


def import_jen(file_bytes, tables_to_restore=None, truncate=True):
    """
    Restore Jen DB tables from export bytes.
    tables_to_restore: list of table names to restore, or None for all in file.
    truncate: if True, clears existing rows before inserting (replace mode).
    Returns list of result strings.
    """
    meta, data, err = parse_import_file(file_bytes)
    if err:
        raise ValueError(err)
    if meta.get("database") != "jen":
        raise ValueError(f"This export is for '{meta.get('database')}' — expected 'jen'. Wrong file?")

    selected = tables_to_restore if tables_to_restore else list(data.keys())
    results  = []
    conn     = _direct_jen_conn()
    try:
        conn.begin()
        conn.cursor().execute("SET FOREIGN_KEY_CHECKS=0")
        for tbl in selected:
            rows = data.get(tbl, [])
            if not _table_exists(conn, tbl):
                results.append(f"⚠️ {tbl}: table does not exist in current schema — skipped")
                continue
            with conn.cursor() as cur:
                if truncate:
                    cur.execute(f"DELETE FROM `{tbl}`")
                if rows:
                    cols   = list(rows[0].keys())
                    col_str = ", ".join(f"`{c}`" for c in cols)
                    ph_str  = ", ".join(["%s"] * len(cols))
                    cur.executemany(
                        f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                        [[r.get(c) for c in cols] for r in rows]
                    )
            results.append(f"✅ {tbl}: {len(rows)} rows restored")
        conn.cursor().execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Import failed and was rolled back: {e}")
    finally:
        conn.close()
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
    conn    = _direct_kea_conn()
    try:
        conn.begin()
        for tbl in data:
            rows = data.get(tbl, [])
            if not rows:
                results.append(f"ℹ️ {tbl}: no rows in export — skipped")
                continue
            if not _table_exists(conn, tbl):
                results.append(f"⚠️ {tbl}: table not found in Kea DB — skipped")
                continue
            inserted = skipped = 0
            cols    = list(rows[0].keys())
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str  = ", ".join(["%s"] * len(cols))
            verb    = "REPLACE" if duplicate_mode == "overwrite" else "INSERT IGNORE"
            with conn.cursor() as cur:
                for row in rows:
                    try:
                        cur.execute(
                            f"{verb} INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                            [row.get(c) for c in cols]
                        )
                        if cur.rowcount > 0:
                            inserted += 1
                        else:
                            skipped  += 1
                    except Exception:
                        skipped += 1
            results.append(f"✅ {tbl}: {inserted} inserted, {skipped} skipped")
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"Kea import failed and was rolled back: {e}")
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


def migrate_jen(target_host, target_port, target_user, target_password, target_db,
                tables=None, progress_cb=None):
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

    selected = tables or list(JEN_TABLES.keys())
    results  = []

    _cb(f"Connecting to source Jen DB ({extensions.JEN_DB_HOST}/{extensions.JEN_DB_NAME})...")
    src = _direct_jen_conn()
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}")

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
                row      = cur.fetchone()
                ddl_key  = [k for k in row.keys() if "Create" in k][0]
                ddl      = row[ddl_key]
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
            cols    = list(rows[0].keys())
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str  = ", ".join(["%s"] * len(cols))
            with dst.cursor() as cur:
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    [[r.get(c) for c in cols] for r in rows]
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
        raise RuntimeError(f"Migration failed — target DB rolled back and cleaned up. Error: {e}")

    src.close()
    dst.close()
    return results


def migrate_kea(target_host, target_port, target_user, target_password, target_db,
                group="reservations", progress_cb=None):
    """
    Migrate Kea reservations (or leases) to a new DB server.
    """
    def _cb(msg):
        if progress_cb:
            progress_cb(msg)
        logger.info(f"migrate_kea: {msg}")

    tables  = KEA_EXPORT_GROUPS[group]["tables"]
    results = []

    _cb(f"Connecting to source Kea DB ({extensions.KEA_DB_HOST}/{extensions.KEA_DB_NAME})...")
    src = _direct_kea_conn()
    _cb(f"Connecting to target ({target_host}/{target_db})...")
    try:
        dst = _direct_conn(target_host, target_port, target_user, target_password, target_db)
    except Exception as e:
        src.close()
        raise RuntimeError(f"Cannot connect to target DB: {e}")

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
                row     = cur.fetchone()
                ddl_key = [k for k in row.keys() if "Create" in k][0]
                ddl     = row[ddl_key].replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")
                ddl     = re.sub(r" AUTO_INCREMENT=\d+", "", ddl)
            with dst.cursor() as cur:
                cur.execute(ddl)
            created_tables.append(tbl)
            _cb(f"  ✅ Created table: {tbl}")

        for tbl in created_tables:
            rows  = _dump_table(src, tbl)
            count = len(rows)
            if count == 0:
                _cb(f"  ℹ️ {tbl}: empty"); results.append(f"ℹ️ {tbl}: 0 rows"); continue
            cols    = list(rows[0].keys())
            col_str = ", ".join(f"`{c}`" for c in cols)
            ph_str  = ", ".join(["%s"] * len(cols))
            with dst.cursor() as cur:
                cur.executemany(
                    f"INSERT IGNORE INTO `{tbl}` ({col_str}) VALUES ({ph_str})",
                    [[r.get(c) for c in cols] for r in rows]
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
        src.close(); dst.close()
        raise RuntimeError(f"Kea migration failed — rolled back. Error: {e}")

    src.close(); dst.close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled Backups
# ─────────────────────────────────────────────────────────────────────────────

def get_schedule():
    """Return current backup schedule config from DB."""
    from jen.models.db import get_jen_db
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM backup_schedule WHERE id=1")
            row = cur.fetchone()
        db.close()
        return row or {}
    except Exception:
        return {}


def save_schedule(enabled, frequency, hour, keep_count, include_jen, include_kea):
    from jen.models.db import get_jen_db
    db = get_jen_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO backup_schedule (id, enabled, frequency, hour, keep_count, include_jen, include_kea)
                VALUES (1, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    enabled=%s, frequency=%s, hour=%s,
                    keep_count=%s, include_jen=%s, include_kea=%s
            """, (enabled, frequency, hour, keep_count, include_jen, include_kea,
                  enabled, frequency, hour, keep_count, include_jen, include_kea))
        db.commit()
    finally:
        db.close()


def run_scheduled_backup():
    """Run a scheduled backup — called by APScheduler or manually."""
    sched = get_schedule()
    if not sched:
        return
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    results = []
    if sched.get("include_jen"):
        try:
            content, fname = export_jen()
            path = _write_backup(json.loads(gzip.decompress(content).decode()), f"jen-scheduled-{ts}.json.gz")
            results.append(f"Jen: {path}")
        except Exception as e:
            results.append(f"Jen: FAILED — {e}")
    if sched.get("include_kea"):
        try:
            content, fname = export_kea("reservations")
            path = _write_backup(json.loads(gzip.decompress(content).decode()), f"kea-scheduled-{ts}.json.gz")
            results.append(f"Kea: {path}")
        except Exception as e:
            results.append(f"Kea: FAILED — {e}")

    # Prune old backups
    keep = int(sched.get("keep_count", 7))
    _prune_backups(keep)

    # Update last_run
    from jen.models.db import get_jen_db
    db = get_jen_db()
    status = "; ".join(results)
    try:
        with db.cursor() as cur:
            cur.execute("UPDATE backup_schedule SET last_run=NOW(), last_status=%s WHERE id=1", (status,))
        db.commit()
    finally:
        db.close()


def _prune_backups(keep_count):
    """Delete oldest backup files keeping only the last N."""
    if not os.path.isdir(BACKUP_DIR):
        return
    files = sorted([
        os.path.join(BACKUP_DIR, f)
        for f in os.listdir(BACKUP_DIR)
        if f.endswith(".json.gz")
    ], key=os.path.getmtime)
    for old in files[:-keep_count] if len(files) > keep_count else []:
        try:
            os.remove(old)
        except Exception:
            pass


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
        tables   = []
        exported_at = ""
        try:
            payload = _read_backup(path)
            meta    = payload.get("_meta", {})
            db_label    = meta.get("database", "?").upper()
            tables      = meta.get("tables", [])
            exported_at = meta.get("exported_at", "")[:19].replace("T", " ")
        except Exception:
            pass
        results.append({
            "filename":    fname,
            "path":        path,
            "size_kb":     round(size / 1024, 1),
            "modified":    mtime,
            "db":          db_label,
            "tables":      tables,
            "exported_at": exported_at,
        })
    return results
