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

from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    stream_with_context,
    url_for,
)
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
def _render_database_page(tab: str):
    """The Settings → Databases page body, factored out of database()
    (v5.67.0-beta.5, Q117, item j) so a validation failure elsewhere in
    this module (save_schedule) can re-render the SAME page with its
    error message and a 400 status, landing on the right tab, instead of
    a redirect that can't carry a non-3xx status to the browser."""
    from flask_login import current_user

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
    # v5.66.0-beta.5 (Q107) — one group per plugin, only computed for the export tab (the one
    # DB round trip a superadmin viewing another tab shouldn't pay for).
    plugin_table_groups = (
        dbexport.export_table_groups() if tab == "export" and current_user.role == "superadmin" else {}
    )
    # The recovery card's one-time notice: only a superadmin viewing that tab pays for the
    # lookup, and only while it could possibly still be true — write_jen_export() flips
    # plugin_backup_notice_seen the first time any real export actually carries a plugin's
    # tables, which makes every earlier bundle/backup on this install provably stale.
    # export_table_groups() (not plugins.all_owned_tables() directly) so a plugin whose code is
    # merely present but never enabled/migrated — true for every bundled plugin on a fresh
    # install — doesn't trip the notice for data that was never there to lose.
    show_plugin_backup_notice = False
    if tab == "recovery" and current_user.role == "superadmin":
        already_seen = __user.get_global_setting("plugin_backup_notice_seen", "") == "1"
        show_plugin_backup_notice = not already_seen and any(dbexport.export_table_groups().values())
    return render_template(
        "database.html",
        active_tab=tab,
        conn=conn,
        backups=backups,
        schedule=schedule,
        jen_tables=dbexport.JEN_TABLES,
        plugin_table_groups=plugin_table_groups,
        show_plugin_backup_notice=show_plugin_backup_notice,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
        jen_db_host=extensions.JEN_DB_HOST,
        jen_db_name=extensions.JEN_DB_NAME,
        kea_db_host=extensions.KEA_DB_HOST,
        kea_db_name=extensions.KEA_DB_NAME,
    )


@bp.route("/settings/databases")
@login_required
@_admin_required
def database():
    return _render_database_page(request.args.get("tab", "connections"))


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
    """v5.66.0-beta.4 (Q106) — streams from a tempfile via dbexport.write_jen_export()
    instead of building the whole document (and then a whole second gzip.compress() copy
    of it) in memory first — the same reason the recovery bundle moved onto it."""
    tables = request.form.getlist("tables") or None
    tmp_path = None
    try:
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, suffix=".jen-export.json.gz")
        os.close(fd)
        dbexport.write_jen_export(tmp_path, tables)
        filename = f"jen-export-{datetime.utcnow().strftime('%Y-%m-%d-%H%M%S')}.json.gz"
        __user.audit("DB_EXPORT", "jen", f"Exported tables: {tables or 'all'}")

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
            mimetype="application/gzip",
            headers={"Content-Disposition": f"attachment; filename={filename}", "Cache-Control": "no-store"},
        )
    except Exception as e:
        if tmp_path:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
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
# the config dir and the content directory is handed over as a PATH, read in small
# pieces while the tar is written. Peak memory is about two 4 MB chunks plus
# the small in-memory members (manifest, config, keys, the database dump), not
# a multiple of the bundle; the size cap is 2 GB (recovery.SIZE_CAP_BYTES) and
# is checked against the file sizes before anything is written. JENREC1 bundles
# (assembled in memory, 200 MB cap) are still READABLE by restore.py.


def _recovery_manifest(db_meta: dict, without_audit_history: bool) -> dict:
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
        # v5.66.0-beta.4 (Q106) — jen.tools.restore's pre-restore memory guard reads
        # jen_db_uncompressed_bytes; jen_db_audit_history_included is printed by the restore
        # checklist so an operator who unchecked it isn't surprised the audit trail is empty.
        "jen_db_uncompressed_bytes": db_meta.get("jen_db_uncompressed_bytes"),
        "jen_db_rows": db_meta.get("jen_db_rows"),
        "jen_db_audit_history_included": not without_audit_history,
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


def _recovery_members(tmp_dir: str, without_audit_history: bool = False) -> tuple[dict[str, bytes | str], str | None]:
    """Every file the bundle carries, as `{archive path: content}` — `bytes`
    for the small generated members, a filesystem path (str) for files that
    are streamed from disk. Returns (members, db_export_path): the Jen DB
    export is written to a 0600 temp file in `tmp_dir` (v5.66.0-beta.4,
    Q106, so a large audit_log never holds the whole dump in memory) and
    the caller is responsible for removing it once build_stream has read
    it — the same way it already removes its own bundle tempfile."""
    tables = None
    if without_audit_history:
        # v5.66.0-beta.5 (Q107) — export_tables(), not just JEN_TABLES minus audit_log: a
        # plugin's tables are never dropped just because audit history was left out.
        tables = [t for t in dbexport.export_tables() if t != "audit_log"]
    db_fd, db_export_path = tempfile.mkstemp(dir=tmp_dir, suffix=".jen_db.json.gz")
    os.close(db_fd)
    try:
        db_meta = dbexport.write_jen_export(db_export_path, tables=tables)
    except Exception:
        # the caller only learns db_export_path from this function's return value — a failure
        # here (a DB error mid-export, say) means it never sees it and could never clean it up
        with contextlib.suppress(OSError):
            os.remove(db_export_path)
        raise

    members: dict[str, bytes | str] = {
        "manifest.json": json.dumps(_recovery_manifest(db_meta, without_audit_history), indent=2).encode("utf-8"),
        "jen_db.json.gz": db_export_path,
    }

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

    return members, db_export_path


# v5.67.0-beta.8 (Q120, item i) — where a refused bundle request goes back to. The setup wizard's recovery
# step posts here too, and a passphrase mismatch used to throw its operator out of the wizard into
# Settings -> Databases. `next` is a fixed choice between the two known pages — never a URL taken from the
# request, so it cannot become an open redirect.
_BUNDLE_RETURN_PAGES = ("setup", "databases")


def _bundle_return_target() -> str:
    nxt = request.form.get("next", "databases")
    if nxt not in _BUNDLE_RETURN_PAGES:
        nxt = "databases"
    if nxt == "setup":
        return url_for("setup.setup_recovery")
    return url_for("database.database", tab="recovery")


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
        return redirect(_bundle_return_target())
    if passphrase != confirm:
        flash("Passphrases did not match.", "error")
        return redirect(_bundle_return_target())

    hostname = socket.gethostname() or "jen"
    ts = datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    filename = f"jen-recovery-{hostname}-{ts}.tar.enc"
    without_audit_history = request.form.get("without_audit_history") == "1"

    tmp_path = None
    db_export_path = None

    def _discard():
        for p in (tmp_path, db_export_path):
            if p:
                with contextlib.suppress(OSError):
                    os.remove(p)

    try:
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        members, db_export_path = _recovery_members(extensions.CONTENT_TMP_DIR, without_audit_history)
        fd, tmp_path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, suffix=".tar.enc")
        try:
            with os.fdopen(fd, "wb") as f:
                size = recovery.build_stream(members, passphrase, f)
        finally:
            # the DB export tempfile is throwaway either way — build_stream has already
            # read it (or failed trying), so it's never needed again past this point
            if db_export_path:
                with contextlib.suppress(OSError):
                    os.remove(db_export_path)
    except recovery.BundleTooLarge as e:
        _discard()
        logger.warning(f"recovery bundle too large: {e}")
        flash(
            f"Recovery bundle would be over the {recovery.SIZE_CAP_BYTES // (1024 * 1024)} MB size cap — "
            "check server logs for the exact size.",
            "error",
        )
        return redirect(_bundle_return_target())
    except Exception as e:
        # anything that fails BEFORE streaming starts leaves no file behind
        _discard()
        logger.error(f"recovery bundle build failed: {e}")
        flash("Could not build the recovery bundle — see server logs.", "error")
        return redirect(_bundle_return_target())

    try:
        __user.audit("RECOVERY_BUNDLE_EXPORT", "settings", f"{filename} ({size} bytes, {len(members)} members)")

        def _stream():
            # v5.67.0-beta.5 (Q117, item i) — `sent_fully` only flips True
            # once the whole file has been read and yielded; a client
            # that disconnects mid-stream hits GeneratorExit at the
            # `yield` and skips straight to `finally` without it, so a
            # recorded last_recovery_bundle_at always means a bundle the
            # operator actually finished downloading — not just one
            # Jen finished building.
            sent_fully = False
            try:
                with open(tmp_path, "rb") as f:
                    while chunk := f.read(1024 * 1024):
                        yield chunk
                sent_fully = True
            finally:
                with contextlib.suppress(OSError):
                    os.remove(tmp_path)
                if sent_fully:
                    from jen.models.user import set_global_setting
                    from jen.services.setup_wizard import utc_iso

                    # v5.67.0-beta.7 (Q119, item f) — utc_iso(), not a
                    # bare datetime.utcnow().isoformat(): the latter is
                    # NAIVE, but setup_wizard's own _STARTED_KEY is
                    # timezone-AWARE — comparing the two in
                    # recovery_bundle_status() raised TypeError, not the
                    # ValueError its try/except actually catches.
                    set_global_setting("last_recovery_bundle_at", utc_iso())
                    set_global_setting("last_recovery_bundle_size", str(size))
                    set_global_setting(
                        "last_recovery_bundle_excluded_audit", "true" if without_audit_history else "false"
                    )

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
        return redirect(_bundle_return_target())


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
    __user.audit("DB_BACKUP_DOWNLOAD", safe, "")
    # v5.66.0-beta.6 (Q108) — send_file streams straight from disk; the old `f.read()` +
    # Response(data, ...) held the whole (possibly very large) backup in the worker's memory
    # for the length of the request. conditional=False: no ETag/If-Range machinery for a
    # file that's about to be deleted or replaced by the next backup anyway.
    resp = send_file(path, mimetype="application/gzip", as_attachment=True, download_name=safe, conditional=False)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/database/backup/delete/<path:filename>", methods=["POST"])
@login_required
@_superadmin_required
def delete_backup(filename):
    safe = os.path.basename(filename)
    path = os.path.join(dbexport.BACKUP_DIR, safe)
    try:
        os.remove(path)
        with contextlib.suppress(OSError):
            os.remove(dbexport._sidecar_path(path))
        __user.audit("DB_BACKUP_DELETE", safe, "")
        flash(f"Backup '{safe}' deleted.", "success")
    except Exception as e:
        logger.error(f"Could not delete backup '{safe}': {e}")
        flash("Could not delete backup. Check server logs for details.", "error")
    return redirect(url_for("database.database", tab="backups"))


@bp.route("/database/backup/details/<path:filename>", methods=["POST"])
@login_required
@_superadmin_required
def backup_details(filename):
    """One-time "Read details" for a backup made before v5.66.0-beta.6 — parses it exactly
    once and writes its `.meta.json` sidecar, so list_backups() never has to open it again."""
    safe = os.path.basename(filename)
    if dbexport.read_legacy_backup_details(safe) is None:
        flash(f"Could not read details for '{safe}'.", "error")
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
            # v5.66.0-beta.6 (Q108) — publish_backup(): a failure mid-write leaves no final
            # file at all, so a manual backup can never half-exist and list as good either.
            os.makedirs(dbexport.BACKUP_DIR, exist_ok=True)
            path = os.path.join(dbexport.BACKUP_DIR, f"jen-manual-{ts}.json.gz")
            meta = dbexport.publish_backup(path, lambda f: dbexport.write_jen_export(f))
            dbexport._write_meta_sidecar(path, meta)
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
_IMPORT_READ_CHUNK = 1024 * 1024


@bp.route("/database/import/inspect", methods=["POST"])
@login_required
@_superadmin_required
def import_inspect():
    """Spool the upload straight to a temp file (never `f.read()`), refuse above the
    compressed-size cap while still spooling, measure its real uncompressed size by
    streaming it through gzip exactly once (never trusting the gzip ISIZE trailer — it wraps
    at 4 GB and the file is attacker-controlled either way), run the same admission check a
    restore does, and only THEN parse it for the confirmation page. Every refusal here
    happens before a single table is touched (v5.66.0-beta.6, Q108)."""
    import base64
    import contextlib

    f = request.files.get("file")
    if not f:
        flash("No file uploaded.", "error")
        return redirect(url_for("database.database", tab="export"))

    max_mb = extensions.cfg.getint("backups", "max_import_mb", fallback=512) if extensions.cfg else 512
    max_bytes = max_mb * 1024 * 1024

    os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=extensions.CONTENT_TMP_DIR, prefix="jen_import_", suffix=".json.gz")

    def _abort(message):
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        flash(message, "error")
        return redirect(url_for("database.database", tab="export"))

    compressed_size = 0
    with os.fdopen(fd, "wb") as out:
        while True:
            chunk = f.stream.read(_IMPORT_READ_CHUNK)
            if not chunk:
                break
            compressed_size += len(chunk)
            if compressed_size > max_bytes:
                out.close()
                return _abort(f"That file is over the {max_mb} MB import cap ([backups] max_import_mb in jen.config).")
            out.write(chunk)

    uncompressed_size = 0
    try:
        with gzip.open(tmp_path, "rb") as gz:
            while True:
                chunk = gz.read(_IMPORT_READ_CHUNK)
                if not chunk:
                    break
                uncompressed_size += len(chunk)
    except OSError:
        return _abort("Cannot read file: not a valid gzip export.")

    from jen.tools.restore import RESTORE_MEMORY_FACTOR, _mem_available_bytes

    available = _mem_available_bytes()
    if available is not None:
        try:
            dbexport.admission_check(uncompressed_size, 0, available, RESTORE_MEMORY_FACTOR)
        except dbexport.AdmissionRefused as e:
            return _abort(f"Cannot import: {e}")

    with open(tmp_path, "rb") as fh:
        file_bytes = fh.read()
    meta, data, err = dbexport.parse_import_file(file_bytes)
    if err:
        return _abort(f"Cannot read file: {err}")

    return render_template(
        "database_import_confirm.html",
        meta=meta,
        data_summary={t: len(v) for t, v in data.items()},
        tmp_path=base64.b64encode(tmp_path.encode()).decode(),
        jen_tables=dbexport.JEN_TABLES,
        kea_groups=dbexport.KEA_EXPORT_GROUPS,
    )


@bp.route("/database/import/confirm", methods=["POST"])
@login_required
@_superadmin_required
def import_confirm():
    import base64

    tmp_path = base64.b64decode(request.form.get("tmp_path", "")).decode()
    # Validate the path is within Jen's own scratch directory — prevent path traversal
    real_tmp_dir = os.path.realpath(extensions.CONTENT_TMP_DIR)
    real_tmp_path = os.path.realpath(tmp_path) if tmp_path else ""
    if not tmp_path or not real_tmp_path.startswith(real_tmp_dir + os.sep) or not os.path.isfile(tmp_path):
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
    values, errors = dbexport.validate_schedule(request.form)
    if errors:
        for e in errors:
            flash(e, "error")
        return _render_database_page("schedule"), 400
    try:
        dbexport.save_schedule(
            values["enabled"],
            values["frequency"],
            values["hour"],
            values["keep_count"],
            values["include_jen"],
            values["include_kea"],
        )
        flash("Backup schedule saved.", "success")
        __user.audit(
            "DB_SCHEDULE", "backup", f"enabled={values['enabled']} freq={values['frequency']} hour={values['hour']}"
        )
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
