"""
jen/routes/mfa_routes.py
─────────────────────────
MFA enrollment and verification routes.
"""

import hashlib
import io
import json
import logging
import os
import re
import secrets
import subprocess
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, send_from_directory,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from jen import extensions
from jen.config import init_extensions_from_config, load_config
import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.kea as __kea
import jen.services.alerts as __alerts
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("mfa_routes", __name__)


def _load_user(user_id):
    """Load a user by ID — thin wrapper around the login_manager user loader."""
    from jen.models.db import get_jen_db
    from jen.models.user import User
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, username, role, session_timeout FROM users WHERE id=%s",
                (user_id,)
            )
            row = cur.fetchone()
        db.close()
        if row:
            return User(row["id"], row["username"], row["role"], row["session_timeout"])
    except Exception as e:
        logger.error(f"_load_user error: {e}")
    return None


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION


def _admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated


def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    # At this point the user has passed password auth but is not yet logged in.
    # Their user ID is held in the session under mfa_pending_user_id.
    pending_id = session.get("mfa_pending_user_id")
    pending_username = session.get("mfa_pending_username", "unknown")
    if not pending_id:
        # No pending MFA — if already fully logged in, go to dashboard; else back to login
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.dashboard'))
        return redirect(url_for('auth.login'))
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        # Try backup code first (8 hex chars without dash, or with dash stripped)
        clean_code = code.replace("-", "").upper()
        if __mfa.verify_backup_code(pending_id, clean_code):
            user = _load_user(pending_id)
            if user:
                login_user(user)
                session["last_active"] = datetime.now(timezone.utc).isoformat()
                session.pop("mfa_pending_user_id", None)
                session.pop("mfa_pending_username", None)
                next_url = session.pop("mfa_next", url_for('dashboard.dashboard'))
                __user.audit("MFA_BACKUP_CODE", "auth", pending_username)
                return redirect(next_url)
        # Try TOTP
        if __mfa.verify_totp(pending_id, code):
            user = _load_user(pending_id)
            if user:
                login_user(user)
                session["last_active"] = datetime.now(timezone.utc).isoformat()
                session.pop("mfa_pending_user_id", None)
                session.pop("mfa_pending_username", None)
                remember = request.form.get("remember_device")
                next_url = session.pop("mfa_next", url_for('dashboard.dashboard'))
                if remember:
                    days = int(request.form.get("remember_days", 30))
                    device_name = request.user_agent.string[:100] if request.user_agent else "Unknown"
                    token = __mfa.create_trusted_device_token(pending_id, days, device_name)
                    resp = redirect(next_url)
                    resp.set_cookie("jen_trusted", token, max_age=days*86400, httponly=True, samesite="Lax")
                    __user.audit("MFA_VERIFY", "auth", f"{pending_username} trusted={days}d")
                    return resp
                __user.audit("MFA_VERIFY", "auth", pending_username)
                return redirect(next_url)
        flash("Invalid code. Please try again.", "error")
        __user.audit("MFA_FAILED", "auth", pending_username)
    has_totp = __mfa.user_has_mfa(pending_id) if pending_id else False
    return render_template("mfa_challenge.html", username=pending_username, has_totp=has_totp)

@bp.route("/mfa/enroll", methods=["GET", "POST"])
@login_required
def mfa_enroll():
    import pyotp, qrcode, io as _io, base64
    if request.method == "POST":
        action = request.form.get("action")
        if action == "enroll":
            secret = request.form.get("secret", "").strip()
            code = request.form.get("code", "").strip()
            device_name = request.form.get("device_name", "Authenticator").strip()[:100] or "Authenticator"
            if not secret or not code:
                flash("Missing secret or code.", "error")
                return redirect(url_for('mfa_routes.mfa_enroll'))
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                flash("Invalid verification code. Please try again.", "error")
                return redirect(url_for('mfa_routes.mfa_enroll'))
            try:
                db = __db.get_jen_db()
                with db.cursor() as cur:
                    cur.execute("""INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled)
                                   VALUES (%s, 'totp', %s, %s, 1)""",
                                (current_user.id, secret, device_name))
                db.commit()
                # Generate backup codes
                codes = __mfa.generate_backup_codes(current_user.id)
                db.close()
                __user.audit("MFA_ENROLL", "auth", f"{current_user.username} device={device_name}")
                flash("Authenticator enrolled successfully!", "success")
                return render_template("mfa_backup_codes.html", codes=codes)
            except Exception as e:
                flash(f"Enrollment error: {str(e)}", "error")
                return redirect(url_for('mfa_routes.mfa_enroll'))
        elif action in ("remove", "remove_totp"):
            method_id = request.form.get("method_id") or request.form.get("mfa_id")
            try:
                db = __db.get_jen_db()
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE id=%s AND user_id=%s", (method_id, current_user.id))
                db.commit(); db.close()
                __user.audit("MFA_REMOVE", "auth", f"{current_user.username} method_id={method_id}")
                flash("Authenticator removed.", "success")
            except Exception as e:
                flash(f"Error: {str(e)}", "error")
            return redirect(url_for('mfa_routes.mfa_enroll'))
        elif action == "new_backup_codes":
            codes = __mfa.generate_backup_codes(current_user.id)
            __user.audit("MFA_NEW_BACKUP", "auth", current_user.username)
            return render_template("mfa_backup_codes.html", codes=codes)
    # GET - show enrollment page
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="Jen DHCP")
    qr = qrcode.make(uri)
    buf = _io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, name, created_at, last_used FROM mfa_methods WHERE user_id=%s AND method_type='totp' AND enabled=1", (current_user.id,))
            methods = cur.fetchall()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0", (current_user.id,))
            backup_count = cur.fetchone()["cnt"]
        db.close()
    except Exception as e:
        logger.error(f"mfa_enroll fetch error: {e}")
        methods = []; backup_count = 0
    return render_template("mfa_enroll.html", secret=secret, qr_b64=qr_b64,
                           totp_methods=methods, passkeys=[], backup_count=backup_count)

@bp.route("/mfa/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    codes = __mfa.generate_backup_codes(current_user.id)
    __user.audit("MFA_NEW_BACKUP", "auth", current_user.username)
    return render_template("mfa_backup_codes.html", codes=codes)

@bp.route("/mfa/trusted-devices")
@login_required
def mfa_trusted_devices():
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("""SELECT id, device_name, created_at, expires_at, last_used
                           FROM mfa_trusted_devices WHERE user_id=%s
                           ORDER BY created_at DESC""", (current_user.id,))
            devices = cur.fetchall()
        db.close()
    except Exception:
        devices = []
    return render_template("mfa_trusted_devices.html", devices=devices)

@bp.route("/mfa/trusted-devices/remove/<int:device_id>", methods=["POST"])
@bp.route("/mfa/revoke-device/<int:device_id>", methods=["POST"])  # legacy alias
@login_required
def remove_trusted_device(device_id):
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_trusted_devices WHERE id=%s AND user_id=%s", (device_id, current_user.id))
        db.commit(); db.close()
        flash("Trusted device removed.", "success")
        __user.audit("REMOVE_TRUSTED_DEVICE", "auth", f"device_id={device_id}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('mfa_routes.mfa_trusted_devices'))

@bp.route("/mfa/revoke-all-devices", methods=["POST"])
@login_required
def revoke_all_trusted_devices():
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (current_user.id,))
            deleted = cur.rowcount
        db.commit(); db.close()
        flash(f"All {deleted} trusted device(s) revoked.", "success")
        __user.audit("REVOKE_ALL_TRUSTED_DEVICES", "auth", current_user.username)
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('mfa_routes.mfa_trusted_devices'))

@bp.route("/mfa/admin-reset/<int:user_id>", methods=["POST"])
@login_required
@_admin_required
def admin_reset_mfa(user_id):
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (user_id,))
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
            cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (user_id,))
        db.commit(); db.close()
        flash(f"MFA reset for user ID {user_id}.", "success")
        __user.audit("ADMIN_RESET_MFA", str(user_id), f"Reset by {current_user.username}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('users.users'))

# ─────────────────────────────────────────
# User Profile
# ─────────────────────────────────────────
