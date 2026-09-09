"""
jen/routes/settings/security.py
─────────────────────────────
Session timeout, login rate limiting, SSL certificate upload.
"""

import logging
import os
import subprocess
import threading

from flask import flash, redirect, request, url_for
from flask_login import login_required

import jen.models.db as __db
import jen.models.user as __user
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required

logger = logging.getLogger(__name__)


@bp.route("/settings/save-session", methods=["POST"])
@login_required
@_admin_required
def save_session_settings():
    timeout = request.form.get("timeout_minutes", "60").strip()
    enabled = request.form.get("timeout_enabled", "true").strip()
    if enabled not in ("true", "false"):
        enabled = "true"

    if not timeout.isdigit() or not (0 <= int(timeout) <= 1440):
        flash("Session timeout must be between 0 and 1440 minutes (0 = never).", "error")
        return redirect(url_for("settings.settings_security"))

    __user.set_global_setting("session_timeout_minutes", timeout)
    __user.set_global_setting("session_timeout_enabled", enabled)

    if enabled == "false":
        flash("Session timeout disabled — sessions will not expire.", "success")
    elif int(timeout) == 0:
        flash("Session timeout enabled — sessions will never expire.", "success")
    else:
        flash(f"Session timeout set to {timeout} minutes.", "success")
    __user.audit("SAVE_SETTINGS", "session", f"enabled={enabled} timeout={timeout}min")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/save-rate-limit", methods=["POST"])
@login_required
@_admin_required
def save_rate_limit():
    max_attempts = request.form.get("max_attempts", "10").strip()
    lockout_minutes = request.form.get("lockout_minutes", "15").strip()
    mode = request.form.get("mode", "both").strip()

    if not max_attempts.isdigit() or int(max_attempts) < 0:
        flash("Max attempts must be 0 or a positive number.", "error")
        return redirect(url_for("settings.settings_security"))
    if not lockout_minutes.isdigit() or int(lockout_minutes) < 0:
        flash("Lockout duration must be 0 or a positive number.", "error")
        return redirect(url_for("settings.settings_security"))
    if mode not in ("ip", "username", "both", "off"):
        flash("Invalid lockout mode.", "error")
        return redirect(url_for("settings.settings_security"))

    __user.set_global_setting("rl_max_attempts", max_attempts)
    __user.set_global_setting("rl_lockout_minutes", lockout_minutes)
    __user.set_global_setting("rl_mode", mode)
    flash("Rate limiting settings saved.", "success")
    __user.audit("SAVE_SETTINGS", "rate_limit", f"max={max_attempts} lockout={lockout_minutes}min mode={mode}")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/clear-lockouts", methods=["POST"])
@login_required
@_admin_required
def clear_lockouts():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM login_attempts")
            db.commit()
        flash("All login attempt records cleared.", "success")
        __user.audit("CLEAR_LOCKOUTS", "settings", "All login attempts cleared")
    except Exception as e:
        logger.error(f"Error clearing lockouts: {e}")
        flash("Error clearing lockouts. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


def validate_cert_material(cert_data: str, key_data: str, ca_data: str | None) -> str | None:
    """
    v5.9.1 — return None if cert + key (+ CA bundle, when given) load as a
    real TLS server chain, else a short reason. The old check was textual
    ("contains BEGIN CERTIFICATE"), so a valid certificate paired with the
    wrong private key sailed through, got written to /etc/jen/ssl, and
    gunicorn then refused to start — a self-inflicted outage. Loading the
    material with the same API gunicorn uses catches malformed PEMs and a
    mismatched key before anything on disk is touched. Pure — tested in
    tests/test_ssl_material.py.
    """
    import ssl
    import tempfile

    if "BEGIN CERTIFICATE" not in cert_data:
        return "the certificate file is not a PEM certificate"
    if "PRIVATE KEY" not in key_data:
        return "the private key file is not a PEM private key"
    if ca_data and "BEGIN CERTIFICATE" not in ca_data:
        return "the CA bundle is not a PEM certificate bundle"
    with tempfile.TemporaryDirectory() as tmp:
        chain = os.path.join(tmp, "chain.pem")
        key = os.path.join(tmp, "key.pem")
        with open(chain, "w") as f:
            f.write(cert_data)
            if ca_data:
                f.write("\n" if not cert_data.endswith("\n") else "")
                f.write(ca_data)
        with open(key, "w") as f:
            f.write(key_data)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(chain, key)
        except ssl.SSLError as e:
            msg = (e.strerror or str(e)).lower()
            if "mismatch" in msg:
                return "the private key does not match the certificate"
            return f"the certificate/key could not be loaded ({e.strerror or e})"
        except (OSError, ValueError) as e:
            return f"the certificate/key could not be loaded ({e})"
    return None


def _write_atomically(path: str, data: str, mode: int) -> None:
    """Write next to the target then os.replace() it in — a reader (or a
    restart) never sees a half-written PEM. The previous file, if any, is
    kept beside it as `<name>.prev` for a manual recovery."""
    if os.path.exists(path):
        try:
            os.replace(path, path + ".prev")
        except OSError:
            pass
    tmp = path + ".new"
    with open(tmp, "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


@bp.route("/settings/upload-cert", methods=["POST"])
@login_required
@_admin_required
def upload_cert():
    cert_file = request.files.get("certificate")
    key_file = request.files.get("private_key")
    ca_file = request.files.get("ca_bundle")
    if not cert_file or not key_file:
        flash("Certificate and private key are required.", "error")
        return redirect(url_for("settings.settings_security"))
    os.makedirs(os.path.dirname(extensions.SSL_CERT), exist_ok=True)
    try:
        cert_data = cert_file.read().decode("utf-8")
        key_data = key_file.read().decode("utf-8")
        ca_data = ca_file.read().decode("utf-8") if ca_file and ca_file.filename else None
        reason = validate_cert_material(cert_data, key_data, ca_data)
        if reason:
            flash(f"Certificate rejected — {reason}. Nothing was changed.", "error")
            return redirect(url_for("settings.settings_security"))
        combined = cert_data + ("" if cert_data.endswith("\n") else "\n") + (ca_data or "")
        _write_atomically(extensions.SSL_CERT, cert_data, 0o644)
        _write_atomically(extensions.SSL_KEY, key_data, 0o640)
        if ca_data:
            _write_atomically(extensions.SSL_CA, ca_data, 0o644)
        _write_atomically(extensions.SSL_COMBINED, combined, 0o644)
        flash("Certificate validated and installed. Jen is restarting...", "success")
        __user.audit("UPLOAD_CERT", "settings", "SSL certificate uploaded")

        def restart():
            import time

            time.sleep(2)
            subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])

        threading.Thread(target=restart, daemon=True).start()
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        flash("Error uploading certificate. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/remove-cert", methods=["POST"])
@login_required
@_admin_required
def remove_cert():
    for f in [extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_CA, extensions.SSL_COMBINED]:
        if os.path.exists(f):
            os.remove(f)
    flash("Certificate removed. Restarting in HTTP mode...", "success")

    def restart():
        import time

        time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])

    threading.Thread(target=restart, daemon=True).start()
    return redirect(url_for("settings.settings_security"))
