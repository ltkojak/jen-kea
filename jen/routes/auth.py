"""
jen/routes/auth.py
───────────────────
Authentication routes: login, logout.
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

from flask import (Blueprint, Response, flash, g, jsonify, redirect,
                   render_template, request, send_from_directory,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from jen import extensions
from jen.config import init_extensions_from_config, load_config
import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
from jen.models.user import User
import jen.services.kea as __kea
import jen.services.alerts as __alerts
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("auth", __name__)


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


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        ip = request.remote_addr

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)


        # Single DB connection for the entire login flow
        try:
            db = __db.get_jen_db()
            with db.cursor() as cur:
                # User lookup
                cur.execute(
                    "SELECT id, username, role, session_timeout, password FROM users WHERE username=%s",
                    (username,)
                )
                row = cur.fetchone()

                # Rate limit settings (single query)
                cur.execute(
                    "SELECT setting_key, setting_value FROM settings "
                    "WHERE setting_key IN ('rl_max_attempts','rl_lockout_minutes','rl_mode','mfa_mode')"
                )
                settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

                rl_mode     = settings.get("rl_mode", "both")
                max_att     = int(settings.get("rl_max_attempts", "10"))
                lockout_min = int(settings.get("rl_lockout_minutes", "15"))

                locked = False
                remaining = 0
                if rl_mode != "off" and max_att > 0:
                    window = f"DATE_SUB(NOW(), INTERVAL {lockout_min if lockout_min > 0 else 1440} MINUTE)"
                    count = 0
                    if rl_mode in ("ip", "both"):
                        cur.execute(
                            f"SELECT COUNT(*) as cnt FROM login_attempts "
                            f"WHERE ip_address=%s AND attempted_at >= {window}", (ip,))
                        count = max(count, cur.fetchone()["cnt"])
                    if rl_mode in ("username", "both"):
                        cur.execute(
                            f"SELECT COUNT(*) as cnt FROM login_attempts "
                            f"WHERE username=%s AND attempted_at >= {window}", (username,))
                        count = max(count, cur.fetchone()["cnt"])
                    if count >= max_att:
                        locked = True
                        remaining = lockout_min if lockout_min > 0 else 999

                mfa_enrolled = False
                if row:
                    cur.execute(
                        "SELECT (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) + "
                        "(SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) as cnt",
                        (row["id"], row["id"])
                    )
                    mfa_enrolled = cur.fetchone()["cnt"] > 0

            db.close()
        except Exception as e:
            logger.error(f"Login DB error: {e}")
            flash("Database error. Please try again.", "error")
            return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

        if locked:
            if remaining >= 999:
                flash("Account is locked. Contact an administrator.", "error")
            else:
                flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
            return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

        if row and __user.verify_password(row["password"], password):
            # Upgrade legacy SHA-256 or rehash slow iterations — fire and forget
            needs_upgrade = (
                not row["password"].startswith("pbkdf2:")
                or __user.needs_rehash(row["password"])
            )
            if needs_upgrade:
                _uid = row["id"]
                _new_hash = __user.hash_password(password)
                def _rehash(_uid=_uid, _hash=_new_hash):
                    try:
                        db2 = __db.get_jen_db()
                        with db2.cursor() as cur:
                            cur.execute("UPDATE users SET password=%s WHERE id=%s", (_hash, _uid))
                        db2.commit()
                        db2.close()
                    except Exception as e:
                        logger.error(f"Password rehash error: {e}")
                threading.Thread(target=_rehash, daemon=True).start()

            # Clear rate limit attempts
            __auth.clear_login_attempts(ip, username)

            user = User(row["id"], row["username"], row["role"], row["session_timeout"])

            # MFA check
            mfa_mode = settings.get("mfa_mode", "off")
            needs_mfa = (
                mfa_mode == "required_all" or
                (mfa_mode == "required_admins" and row["role"] == "admin")
            )
            if mfa_enrolled or needs_mfa:
                if mfa_enrolled and not __mfa.is_trusted_device(row["id"], request):
                    session["mfa_pending_user_id"]  = row["id"]
                    session["mfa_pending_username"] = username
                    session["mfa_next"] = request.args.get("next", url_for('dashboard.dashboard'))
                    return redirect(url_for('mfa_routes.mfa_verify'))
                elif needs_mfa and not mfa_enrolled:
                    # MFA required but not enrolled — force enrollment
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    login_user(user)
                    session["last_active"] = datetime.now(timezone.utc).isoformat()
                    session["_user_cache"] = {
                        "id": user.id, "username": user.username,
                        "role": user.role, "session_timeout": user.session_timeout
                    }
                    flash("MFA is required for your account. Please enroll now.", "warning")
                    return redirect(url_for('mfa_routes.mfa_enroll'))

            login_user(user)
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            session["_user_cache"] = {
                "id": user.id, "username": user.username,
                "role": user.role, "session_timeout": user.session_timeout
            }
            __user.audit("LOGIN", "auth", f"User {username} logged in from {ip}")
            return redirect(url_for('dashboard.dashboard'))

        # Failed login — record attempt (async, don't block response)
        __auth.record_login_attempt(ip, username)
        flash("Invalid username or password.", "error")
        return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

    return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username="")

@bp.route("/logout")
@login_required
def logout():
    __user.audit("LOGOUT", "auth", f"User {current_user.username} logged out")
    session.pop("_user_cache", None)
    session.pop("_avatar_url", None)
    logout_user()
    return redirect(url_for('auth.login'))

# ─────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────
