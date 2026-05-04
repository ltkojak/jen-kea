"""
jen/routes/database.py
──────────────────────
Database management — export, import, scheduled backup, migration.
Admin-only. Menu item hidden for non-admin users in base.html.
"""

import gzip
import io
import json
import logging
import os
import queue
import threading
from datetime import datetime
from functools import wraps

from flask import (Blueprint, Response, flash, redirect, render_template,
                   request, stream_with_context, url_for)
from flask_login import current_user, login_required

from jen import extensions
from jen.models import db as __db
from jen.models import user as __user
from jen.services import dbexport

logger = logging.getLogger(__name__)
bp = Blueprint("database", __name__)


# ── Admin guard ───────────────────────────────────────────────────────────────
def _admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Main page ─────────────────────────────────────────────────────────────────
@bp.route("/database")
@login_required
@_admin_required
def database():
    backups  = dbexport.list_backups()
    schedule = dbexport.get_schedule()
    return render_template(
        "database.html",
        backups=backups,
        schedule=schedule,
        jen_tables=dbexport.JEN_TABLES,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
        jen_db_host=extensions.JEN_DB_HOST,
        jen_db_name=extensions.JEN_DB_NAME,
        kea_db_host=extensions.KEA_DB_HOST,
        kea_db_name=extensions.KEA_DB_NAME,
    )


# ── Export ────────────────────────────────────────────────────────────────────
@bp.route("/database/export/jen", methods=["POST"])
@login_required
@_admin_required
def export_jen():
    tables = request.form.getlist("tables") or None
    try:
        content, filename = dbexport.export_jen(tables)
        __user.audit("DB_EXPORT", "jen", f"Exported tables: {tables or 'all'}")
        return Response(
            gzip.compress(content),
            mimetype="application/gzip",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        flash(f"Export failed: {e}", "error")
        return redirect(url_for("database.database"))


@bp.route("/database/export/kea", methods=["POST"])
@login_required
@_admin_required
def export_kea():
    group = request.form.get("group", "reservations")
    if group not in dbexport.KEA_EXPORT_GROUPS:
        flash("Invalid export group.", "error")
        return redirect(url_for("database.database"))
    try:
        content, filename = dbexport.export_kea(group)
        __user.audit("DB_EXPORT", "kea", f"Exported group: {group}")
        return Response(
            gzip.compress(content),
            mimetype="application/gzip",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        flash(f"Kea export failed: {e}", "error")
        return redirect(url_for("database.database"))


# ── Backup download / delete ───────────────────────────────────────────────────
@bp.route("/database/backup/download/<path:filename>")
@login_required
@_admin_required
def download_backup(filename):
    safe = os.path.basename(filename)
    path = os.path.join(dbexport.BACKUP_DIR, safe)
    if not os.path.isfile(path):
        flash("Backup file not found.", "error")
        return redirect(url_for("database.database"))
    with open(path, "rb") as f:
        data = f.read()
    __user.audit("DB_BACKUP_DOWNLOAD", safe, "")
    return Response(
        data,
        mimetype="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={safe}"}
    )


@bp.route("/database/backup/delete/<path:filename>", methods=["POST"])
@login_required
@_admin_required
def delete_backup(filename):
    safe = os.path.basename(filename)
    path = os.path.join(dbexport.BACKUP_DIR, safe)
    try:
        os.remove(path)
        __user.audit("DB_BACKUP_DELETE", safe, "")
        flash(f"Backup '{safe}' deleted.", "success")
    except Exception as e:
        flash(f"Could not delete backup: {e}", "error")
    return redirect(url_for("database.database"))


@bp.route("/database/backup/now", methods=["POST"])
@login_required
@_admin_required
def backup_now():
    """Run a manual on-demand backup."""
    include = request.form.getlist("include")
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    results = []
    if "jen" in include:
        try:
            content, _ = dbexport.export_jen()
            payload = json.loads(content.decode("utf-8"))
            path = dbexport._write_backup(payload, f"jen-manual-{ts}.json.gz")
            results.append(f"✅ Jen backup saved: {os.path.basename(path)}")
            __user.audit("DB_BACKUP_MANUAL", "jen", path)
        except Exception as e:
            results.append(f"❌ Jen backup failed: {e}")
    if "kea" in include:
        try:
            content, _ = dbexport.export_kea("reservations")
            payload = json.loads(content.decode("utf-8"))
            path = dbexport._write_backup(payload, f"kea-manual-{ts}.json.gz")
            results.append(f"✅ Kea backup saved: {os.path.basename(path)}")
            __user.audit("DB_BACKUP_MANUAL", "kea", path)
        except Exception as e:
            results.append(f"❌ Kea backup failed: {e}")
    for r in results:
        flash(r, "success" if r.startswith("✅") else "error")
    return redirect(url_for("database.database"))


# ── Import ────────────────────────────────────────────────────────────────────
@bp.route("/database/import/inspect", methods=["POST"])
@login_required
@_admin_required
def import_inspect():
    """Parse uploaded file and return metadata for confirmation page."""
    f = request.files.get("file")
    if not f:
        flash("No file uploaded.", "error")
        return redirect(url_for("database.database"))
    file_bytes = f.read()
    meta, data, err = dbexport.parse_import_file(file_bytes)
    if err:
        flash(f"Cannot read file: {err}", "error")
        return redirect(url_for("database.database"))
    # Store bytes in session-style temp file for the confirm step
    import tempfile, base64
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json.gz",
                                     dir="/tmp", prefix="jen_import_")
    tmp.write(file_bytes)
    tmp.close()
    return render_template(
        "database_import_confirm.html",
        meta=meta,
        data_summary={t: len(v) for t, v in data.items()},
        tmp_path=base64.b64encode(tmp.name.encode()).decode(),
        jen_tables=dbexport.JEN_TABLES,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
    )


@bp.route("/database/import/confirm", methods=["POST"])
@login_required
@_admin_required
def import_confirm():
    import base64, tempfile
    tmp_path = base64.b64decode(request.form.get("tmp_path", "")).decode()
    if not tmp_path or not os.path.isfile(tmp_path):
        flash("Import session expired. Please re-upload.", "error")
        return redirect(url_for("database.database"))
    with open(tmp_path, "rb") as f:
        file_bytes = f.read()
    os.unlink(tmp_path)

    meta = dbexport.parse_import_file(file_bytes)[0]
    db   = meta.get("database")

    try:
        if db == "jen":
            tables = request.form.getlist("tables") or None
            mode   = request.form.get("mode", "replace")
            results = dbexport.import_jen(file_bytes, tables, truncate=(mode == "replace"))
            __user.audit("DB_IMPORT", "jen", f"tables={tables or 'all'} mode={mode}")
        elif db == "kea":
            dup = request.form.get("duplicate_mode", "skip")
            results = dbexport.import_kea(file_bytes, duplicate_mode=dup)
            __user.audit("DB_IMPORT", "kea", f"duplicate_mode={dup}")
        else:
            flash(f"Unknown database type '{db}' in export file.", "error")
            return redirect(url_for("database.database"))
        for r in results:
            flash(r, "success" if r.startswith("✅") else "warning")
    except Exception as e:
        flash(f"Import failed: {e}", "error")
    return redirect(url_for("database.database"))


# ── Schedule ──────────────────────────────────────────────────────────────────
@bp.route("/database/schedule", methods=["POST"])
@login_required
@_admin_required
def save_schedule():
    enabled     = 1 if request.form.get("enabled") else 0
    frequency   = request.form.get("frequency", "daily")
    hour        = int(request.form.get("hour", 2))
    keep_count  = max(1, min(30, int(request.form.get("keep_count", 7))))
    include_jen = 1 if request.form.get("include_jen") else 0
    include_kea = 1 if request.form.get("include_kea") else 0
    try:
        dbexport.save_schedule(enabled, frequency, hour, keep_count, include_jen, include_kea)
        flash("Backup schedule saved.", "success")
        __user.audit("DB_SCHEDULE", "backup", f"enabled={enabled} freq={frequency} hour={hour}")
    except Exception as e:
        flash(f"Could not save schedule: {e}", "error")
    return redirect(url_for("database.database"))


# ── Migration — SSE progress ───────────────────────────────────────────────────
@bp.route("/database/migrate", methods=["GET"])
@login_required
@_admin_required
def migrate_page():
    return render_template(
        "database_migrate.html",
        jen_db_host=extensions.JEN_DB_HOST,
        jen_db_name=extensions.JEN_DB_NAME,
        kea_db_host=extensions.KEA_DB_HOST,
        kea_db_name=extensions.KEA_DB_NAME,
        jen_tables=dbexport.JEN_TABLES,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
    )


@bp.route("/database/migrate/test", methods=["POST"])
@login_required
@_admin_required
def migrate_test():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "3306").strip() or "3306"
    user = request.form.get("user", "").strip()
    pw   = request.form.get("password", "")
    db   = request.form.get("database", "").strip()
    ok, info = dbexport.test_connection(host, port, user, pw, db)
    if ok:
        return {"ok": True,  "info": info}
    return {"ok": False, "error": info}


@bp.route("/database/migrate/run", methods=["POST"])
@login_required
@_admin_required
def migrate_run():
    """SSE endpoint — streams migration progress to the browser."""
    which    = request.form.get("which", "jen")      # "jen" or "kea"
    host     = request.form.get("host", "").strip()
    port     = request.form.get("port", "3306").strip() or "3306"
    user     = request.form.get("user", "").strip()
    pw       = request.form.get("password", "")
    db       = request.form.get("database", "").strip()
    tables   = request.form.getlist("tables") or None
    kea_grp  = request.form.get("kea_group", "reservations")

    q = queue.Queue()

    def _progress(msg):
        q.put(("progress", msg))

    def _run():
        try:
            if which == "jen":
                results = dbexport.migrate_jen(host, port, user, pw, db, tables, _progress)
            else:
                results = dbexport.migrate_kea(host, port, user, pw, db, kea_grp, _progress)
            q.put(("done", results))
            __user.audit("DB_MIGRATE", which,
                         f"target={host}/{db} tables={tables or 'all'}")
        except Exception as e:
            q.put(("error", str(e)))

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    def _generate():
        yield "retry: 1000\n\n"
        while True:
            try:
                kind, payload = q.get(timeout=120)
            except queue.Empty:
                yield "event: error\ndata: Timed out\n\n"
                break
            if kind == "progress":
                yield f"event: progress\ndata: {payload}\n\n"
            elif kind == "done":
                summary = "\n".join(payload)
                yield f"event: done\ndata: {summary}\n\n"
                break
            elif kind == "error":
                yield f"event: error\ndata: {payload}\n\n"
                break

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"}
    )
