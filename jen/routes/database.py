"""
jen/routes/database.py
──────────────────────
Database management — export, import, scheduled backup, migration.
SuperAdmin-only (v4.4.2): a subnet-restricted admin has no business
touching a full-database export/import, since it includes every subnet's
data plus users, password hashes, MFA secrets, and API key records —
none of which "assigned subnets only" scoping can meaningfully apply to.
Menu item hidden for non-superadmin users in base.html.
"""

import contextlib
import gzip
import json
import logging
import os
import queue
import socket
import tempfile
import threading
from datetime import datetime

from flask import Blueprint, Response, flash, redirect, render_template, request, stream_with_context, url_for
from flask_login import login_required

from jen import extensions
from jen.models import user as __user
from jen.services import dbexport
from jen.services.access import admin_required as _admin_required
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("database", __name__)


# ── Admin guard ───────────────────────────────────────────────────────────────


# ── Main page ─────────────────────────────────────────────────────────────────
@bp.route("/settings/databases")
@login_required
@_admin_required
def database():
    """
    v5.9.0 — Settings → Databases. The Connections tab (the Jen / Kea DB
    connection settings that used to sit on the Infrastructure tab) is
    admin-visible; the export/import/backup/schedule/migrate tools are
    superadmin-only, gated per tab in the template AND on every POST route
    below exactly as before — the page moving under Settings changes no
    privilege boundary.
    """
    from flask_login import current_user

    tab = request.args.get("tab", "connections")
    if current_user.role != "superadmin":
        tab = "connections"
    backups = dbexport.list_backups() if current_user.role == "superadmin" else []
    schedule = dbexport.get_schedule() if current_user.role == "superadmin" else None
    cfg = extensions.cfg
    conn = {
        "jen_db_host": cfg.get("jen_db", "host", fallback=""),
        "jen_db_user": cfg.get("jen_db", "user", fallback=""),
        "jen_db_name": cfg.get("jen_db", "database", fallback="jen"),
        "kea_db_host": cfg.get("kea_db", "host", fallback=""),
        "kea_db_user": cfg.get("kea_db", "user", fallback=""),
        "kea_db_name": cfg.get("kea_db", "database", fallback="kea"),
    }
    return render_template(
        "database.html",
        active_tab=tab,
        conn=conn,
        backups=backups,
        schedule=schedule,
        jen_tables=dbexport.JEN_TABLES,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
        jen_db_host=extensions.JEN_DB_HOST,
        jen_db_name=extensions.JEN_DB_NAME,
        kea_db_host=extensions.KEA_DB_HOST,
        kea_db_name=extensions.KEA_DB_NAME,
    )


@bp.route("/database")
@login_required
def database_legacy():
    """Pre-5.9.0 URL — 301 to Settings → Databases, keeping ?tab=."""
    return redirect(url_for("database.database", **request.args.to_dict()), code=301)


@bp.route("/database/migrate")
@login_required
def migrate_legacy():
    return redirect(url_for("database.migrate_page"), code=301)


_OK_MARK = "\u2705"  # the ok/warning glyph dbexport prefixes its per-table result lines with


def _split_mark(line: str) -> tuple[bool, str]:
    """(is_ok, text without the leading status glyph) — the glyph is a service-layer
    convention; the UI shows plain text (icons are the SVG sprite, Q57)."""
    ok = line.startswith(_OK_MARK)
    return ok, line.lstrip(_OK_MARK + "\u26a0\u274c\ufe0f ").strip()


# ── Export ────────────────────────────────────────────────────────────────────
@bp.route("/database/export/jen", methods=["POST"])
@login_required
@_superadmin_required
def export_jen():
    tables = request.form.getlist("tables") or None
    try:
        content, filename = dbexport.export_jen(tables)
        __user.audit("DB_EXPORT", "jen", f"Exported tables: {tables or 'all'}")
        return Response(
            gzip.compress(content),
            mimetype="application/gzip",
            headers={"Content-Disposition": f"attachment; filename={filename}", "Cache-Control": "no-store"},
        )
    except Exception as e:
        logger.error(f"Jen DB export failed: {e}")
        flash("Export failed. Check server logs for details.", "error")
        return redirect(url_for("database.database", tab="export"))


@bp.route("/database/export/kea", methods=["POST"])
@login_required
@_superadmin_required
def export_kea():
    group = request.form.get("group", "reservations")
    if group not in dbexport.KEA_EXPORT_GROUPS:
        flash("Invalid export group.", "error")
        return redirect(url_for("database.database", tab="export"))
    try:
        content, filename = dbexport.export_kea(group)
        __user.audit("DB_EXPORT", "kea", f"Exported group: {group}")
        return Response(
            gzip.compress(content),
            mimetype="application/gzip",
            headers={"Content-Disposition": f"attachment; filename={filename}", "Cache-Control": "no-store"},
        )
    except Exception as e:
        logger.error(f"Kea DB export failed: {e}")
        flash("Kea export failed. Check server logs for details.", "error")
        return redirect(url_for("database.database", tab="export"))


# ── Recovery bundle (v5.44.0, Q45) ──────────────────────────────────────────
# Everything needed to stand Jen back up on a new machine, encrypted with a
# passphrase (jen/services/recovery.py). Deliberately NOT redacted — unlike
# the support bundle (v5.33.0), this is meant to restore the box, not to
# hand to someone else; the page and the admin guide both say so.
#
# Memory (v5.65.0, Q85): the bundle is written as JENREC2 — chunked AES-GCM —
# straight into the tempfile by `recovery.build_stream()`, and every file under
# /etc/jen and the content directory is handed over as a PATH, read in small
# pieces while the tar is written. Peak memory is about two 4 MB chunks plus
# the small in-memory members (manifest, config, keys, the database dump), not
# a multiple of the bundle; the size cap is 2 GB (recovery.SIZE_CAP_BYTES) and
# is checked against the file sizes before anything is written. JENREC1 bundles
# (assembled in memory, 200 MB cap) are still READABLE by restore.py.


def _recovery_manifest() -> dict:
    from jen import JEN_VERSION
    from jen.models.migrations import MIGRATIONS
    from jen.services import kea as __kea
    from jen.services import kea_host as __host
    from jen.services.plugins import discover_plugins

    try:
        hostname = socket.gethostname() or "jen"
    except OSError:
        hostname = "jen"

    kea_versions = {}
    for srv in extensions.KEA_SERVERS:
        try:
            r = __kea.kea_command("version-get", server=srv)
            if r.get("result") == 0:
                v = r.get("arguments", {}).get("extended", r.get("text", ""))
                kea_versions[srv["name"]] = v.splitlines()[0] if v else ""
        except Exception as e:
            logger.warning(f"recovery bundle: version-get failed for {srv.get('name')}: {e}")

    return {
        "jen_version": JEN_VERSION,
        "channel": extensions.UPDATE_CHANNEL,
        "hostname": hostname,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "schema_version": MIGRATIONS[-1][0] if MIGRATIONS else 0,
        "kea_versions": kea_versions,
        "plugins": [{"id": p.get("id"), "version": p.get("version")} for p in discover_plugins()],
        "helper_versions": __host.helper_status(),
    }


def _walk_files(root: str, prefix: str, skip: set[str] | None = None) -> dict[str, str]:
    """Every regular file under `root`, as `{f"{prefix}/{relpath}": path}`
    (forward slashes in the archive name — this goes into a tar, not a Windows
    path; the value is the file's path on disk, which `recovery.build_stream`
    reads in small pieces, so nothing is loaded whole here). `skip` is a set of
    already-`os.path.normpath`'d absolute directories pruned from the walk
    entirely (never even descended into). A file that cannot be read is skipped
    with a warning when the bundle is written."""
    out: dict[str, str] = {}
    if not os.path.isdir(root):
        return out
    skip = skip or set()
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.normpath(dirpath) in skip:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if os.path.normpath(os.path.join(dirpath, d)) not in skip]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if not os.path.isfile(full):  # a dangling symlink, a socket - nothing to archive
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[f"{prefix}/{rel}"] = full
    return out


def _recovery_members() -> dict[str, bytes | str]:
    """Every file the bundle carries, as `{archive path: content}` — `bytes`
    for the small generated members, a filesystem path (str) for files that
    are streamed from disk."""
    members: dict[str, bytes | str] = {"manifest.json": json.dumps(_recovery_manifest(), indent=2).encode("utf-8")}

    if os.path.isfile(extensions.CONFIG_FILE):
        with open(extensions.CONFIG_FILE, "rb") as f:
            members["jen.config"] = f.read()

    # Same two-candidate lookup as jen.services.crypto._key_candidates() —
    # not imported directly since this bundle-building code is deliberately
    # standalone from the app's own runtime key cache.
    for candidate in (extensions.MFA_KEY_PATH, os.path.join(extensions.CONTENT_KEYS_DIR, ".mfa_key")):
        if os.path.isfile(candidate):
            with open(candidate, "rb") as f:
                members["mfa_key"] = f.read()
            break

    # secret_key gets the same treatment as mfa_key: an explicit member,
    # restored 0600, never carried as ordinary content.
    for candidate in (
        os.path.join(os.path.dirname(extensions.MFA_KEY_PATH), "secret_key"),
        os.path.join(extensions.CONTENT_KEYS_DIR, ".secret_key"),
    ):
        if os.path.isfile(candidate):
            with open(candidate, "rb") as f:
                members["secret_key"] = f.read()
            break

    members.update(_walk_files(os.path.dirname(extensions.SSL_CERT), "ssl"))
    members.update(_walk_files(os.path.dirname(extensions.SSH_KEY_PATH), "ssh"))

    content, _fname = dbexport.export_jen()
    members["jen_db.json.gz"] = gzip.compress(content)

    # content/ — CONTENT_DIR minus the scheduled-backup archives (redundant
    # with the fresh jen_db.json.gz above) and the plugin code trees
    # (re-fetched by id+version from the registry on restore, not frozen).
    excluded = {
        os.path.normpath(p)
        for p in (
            extensions.CONTENT_BACKUP_DIR,
            extensions.CONTENT_PLUGIN_DIR,
            extensions.CONTENT_PLUGIN_REQUESTS_DIR,
            extensions.CONTENT_TMP_DIR,
            extensions.CONTENT_KEYS_DIR,  # fallback secret/MFA keys ride as explicit 0600 members
        )
    }
    members.update(_walk_files(extensions.CONTENT_DIR, "content", skip=excluded))

    from jen.services import config_revisions as __rev

    for srv in extensions.KEA_SERVERS:
        for service in ("dhcp4", "dhcp6", "d2"):
            try:
                row = __rev.latest(srv["id"], service)
            except Exception as e:
                logger.warning(f"recovery bundle: config_revisions.latest({srv['id']}, {service}) failed: {e}")
                continue
            if row and row.get("config"):
                members[f"kea-configs/{srv['name']}-{service}.json"] = row["config"].encode("utf-8")

    return members


@bp.route("/settings/databases/recovery-bundle", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required()
def recovery_bundle():
    """v5.44.0 (Q45) — streams `jen-recovery-<host>-<ts>.tar.enc`. Built in
    a tempfile (not held whole in the response), never left on disk after
    the response is sent."""
    from jen.services import recovery

    passphrase = request.form.get("passphrase", "")
    confirm = request.form.get("passphrase_confirm", "")
    if len(passphrase) < recovery.MIN_PASSPHRASE_LEN:
        flash(f"Passphrase must be at least {recovery.MIN_PASSPHRASE_LEN} characters.", "error")
        return redirect(url_for("database.database", tab="recovery"))
    if passphrase != confirm:
        flash("Passphrases did not match.", "error")
        return redirect(url_for("database.database", tab="recovery"))

    hostname = socket.gethostname() or "jen"
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"jen-recovery-{hostname}-{ts}.tar.enc"

    tmp_path = None

    def _discard():
        if tmp_path:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)

    try:
        members = _recovery_members()
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, suffix=".tar.enc")
        with os.fdopen(fd, "wb") as f:
            size = recovery.build_stream(members, passphrase, f)
    except recovery.BundleTooLarge as e:
        _discard()
        logger.warning(f"recovery bundle too large: {e}")
        flash(
            f"Recovery bundle would be over the {recovery.SIZE_CAP_BYTES // (1024 * 1024)} MB size cap — "
            "check server logs for the exact size.",
            "error",
        )
        return redirect(url_for("database.database", tab="recovery"))
    except Exception as e:
        # anything that fails BEFORE streaming starts leaves no file behind
        _discard()
        logger.error(f"recovery bundle build failed: {e}")
        flash("Could not build the recovery bundle — see server logs.", "error")
        return redirect(url_for("database.database", tab="recovery"))

    try:
        __user.audit("RECOVERY_BUNDLE_EXPORT", "settings", f"{filename} ({size} bytes, {len(members)} members)")

        def _stream():
            try:
                with open(tmp_path, "rb") as f:
                    while chunk := f.read(1024 * 1024):
                        yield chunk
            finally:
                with contextlib.suppress(OSError):
                    os.remove(tmp_path)

        return Response(
            stream_with_context(_stream()),
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Length": str(size),
                "Cache-Control": "no-store",  # a secrets file: never cached by a browser or proxy
            },
        )
    except Exception as e:
        _discard()
        logger.error(f"recovery bundle write failed: {e}")
        flash("Could not build the recovery bundle — see server logs.", "error")
        return redirect(url_for("database.database", tab="recovery"))


# ── Backup download / delete ───────────────────────────────────────────────────
@bp.route("/database/backup/download/<path:filename>")
@login_required
@_superadmin_required
def download_backup(filename):
    safe = os.path.basename(filename)
    path = os.path.join(dbexport.BACKUP_DIR, safe)
    if not os.path.isfile(path):
        flash("Backup file not found.", "error")
        return redirect(url_for("database.database", tab="backups"))
    with open(path, "rb") as f:
        data = f.read()
    __user.audit("DB_BACKUP_DOWNLOAD", safe, "")
    return Response(
        data,
        mimetype="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={safe}", "Cache-Control": "no-store"},
    )


@bp.route("/database/backup/delete/<path:filename>", methods=["POST"])
@login_required
@_superadmin_required
def delete_backup(filename):
    safe = os.path.basename(filename)
    path = os.path.join(dbexport.BACKUP_DIR, safe)
    try:
        os.remove(path)
        __user.audit("DB_BACKUP_DELETE", safe, "")
        flash(f"Backup '{safe}' deleted.", "success")
    except Exception as e:
        logger.error(f"Could not delete backup '{safe}': {e}")
        flash("Could not delete backup. Check server logs for details.", "error")
    return redirect(url_for("database.database", tab="backups"))


@bp.route("/database/backup/now", methods=["POST"])
@login_required
@_superadmin_required
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
            results.append((True, f"Jen backup saved: {os.path.basename(path)}"))
            __user.audit("DB_BACKUP_MANUAL", "jen", path)
        except Exception as e:
            results.append((False, f"Jen backup failed: {e}"))
    if "kea" in include:
        try:
            content, _ = dbexport.export_kea("reservations")
            payload = json.loads(content.decode("utf-8"))
            path = dbexport._write_backup(payload, f"kea-manual-{ts}.json.gz")
            results.append((True, f"Kea backup saved: {os.path.basename(path)}"))
            __user.audit("DB_BACKUP_MANUAL", "kea", path)
        except Exception as e:
            results.append((False, f"Kea backup failed: {e}"))
    for ok, msg in results:
        flash(msg, "success" if ok else "error")
    return redirect(url_for("database.database", tab="backups"))


# ── Import ────────────────────────────────────────────────────────────────────
@bp.route("/database/import/inspect", methods=["POST"])
@login_required
@_superadmin_required
def import_inspect():
    """Parse uploaded file and return metadata for confirmation page."""
    f = request.files.get("file")
    if not f:
        flash("No file uploaded.", "error")
        return redirect(url_for("database.database", tab="export"))
    file_bytes = f.read()
    meta, data, err = dbexport.parse_import_file(file_bytes)
    if err:
        flash(f"Cannot read file: {err}", "error")
        return redirect(url_for("database.database", tab="export"))
    # Store bytes in session-style temp file for the confirm step
    import base64
    import tempfile

    # kept past the block on purpose — the path is handed to the confirm step
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json.gz", dir="/tmp", prefix="jen_import_")  # noqa: SIM115
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
@_superadmin_required
def import_confirm():
    import base64

    tmp_path = base64.b64decode(request.form.get("tmp_path", "")).decode()
    # Validate path is within the expected temp directory — prevent path traversal
    if not tmp_path or not tmp_path.startswith("/tmp/jen_import_") or not os.path.isfile(tmp_path):
        flash("Import session expired. Please re-upload.", "error")
        return redirect(url_for("database.database", tab="import"))
    with open(tmp_path, "rb") as f:
        file_bytes = f.read()
    os.unlink(tmp_path)

    meta = dbexport.parse_import_file(file_bytes)[0]
    db = meta.get("database")

    try:
        if db == "jen":
            tables = request.form.getlist("tables") or None
            mode = request.form.get("mode", "replace")
            results = dbexport.import_jen(file_bytes, tables, truncate=(mode == "replace"))
            __user.audit("DB_IMPORT", "jen", f"tables={tables or 'all'} mode={mode}")
        elif db == "kea":
            dup = request.form.get("duplicate_mode", "skip")
            results = dbexport.import_kea(file_bytes, duplicate_mode=dup)
            __user.audit("DB_IMPORT", "kea", f"duplicate_mode={dup}")
        else:
            flash(f"Unknown database type '{db}' in export file.", "error")
            return redirect(url_for("database.database", tab="import"))
        for r in results:
            ok, msg = _split_mark(r)
            flash(msg, "success" if ok else "warning")
    except Exception as e:
        logger.error(f"DB import failed: {e}")
        flash("Import failed. Check server logs for details.", "error")
    return redirect(url_for("database.database", tab="import"))


# ── Schedule ──────────────────────────────────────────────────────────────────
@bp.route("/database/schedule", methods=["POST"])
@login_required
@_superadmin_required
def save_schedule():
    enabled = 1 if request.form.get("enabled") else 0
    frequency = request.form.get("frequency", "daily")
    hour = int(request.form.get("hour", 2))
    keep_count = max(1, min(30, int(request.form.get("keep_count", 7))))
    include_jen = 1 if request.form.get("include_jen") else 0
    include_kea = 1 if request.form.get("include_kea") else 0
    try:
        dbexport.save_schedule(enabled, frequency, hour, keep_count, include_jen, include_kea)
        flash("Backup schedule saved.", "success")
        __user.audit("DB_SCHEDULE", "backup", f"enabled={enabled} freq={frequency} hour={hour}")
    except Exception as e:
        logger.error(f"Could not save backup schedule: {e}")
        flash("Could not save schedule. Check server logs for details.", "error")
    return redirect(url_for("database.database", tab="schedule"))


# ── Migration — SSE progress ───────────────────────────────────────────────────
@bp.route("/settings/databases/migrate", methods=["GET"])
@login_required
@_superadmin_required
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
@_superadmin_required
def migrate_test():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "3306").strip() or "3306"
    user = request.form.get("user", "").strip()
    pw = request.form.get("password", "")
    db = request.form.get("database", "").strip()
    ok, info = dbexport.test_connection(host, port, user, pw, db)
    if ok:
        return {"ok": True, "info": info}
    return {"ok": False, "error": info}


@bp.route("/database/migrate/run", methods=["POST"])
@login_required
@_superadmin_required
def migrate_run():
    """SSE endpoint — streams migration progress to the browser."""
    which = request.form.get("which", "jen")  # "jen" or "kea"
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "3306").strip() or "3306"
    user = request.form.get("user", "").strip()
    pw = request.form.get("password", "")
    db = request.form.get("database", "").strip()
    tables = request.form.getlist("tables") or None
    kea_grp = request.form.get("kea_group", "reservations")

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
            __user.audit("DB_MIGRATE", which, f"target={host}/{db} tables={tables or 'all'}")
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
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )
