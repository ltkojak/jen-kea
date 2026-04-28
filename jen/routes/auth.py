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

        # Check rate limit
        locked, remaining = __auth.is_locked_out(ip, username)
        if locked:
            if remaining >= 999:
                flash("Account is locked. Contact an administrator.", "error")
            else:
                flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
            return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

        try:
            db = __db.get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "SELECT id, username, role, session_timeout, password FROM users WHERE username=%s",
                    (username,)
                )
                row = cur.fetchone()
            db.close()
        except Exception as e:
            logger.error(f"Login DB error: {e}")
            flash("Database error. Please try again.", "error")
            return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

        if row and __user.verify_password(row["password"], password):
            # Upgrade legacy SHA-256 hash to pbkdf2 on successful login
            if row["password"] and not row["password"].startswith("pbkdf2:"):
                try:
                    db = __db.get_jen_db()
                    with db.cursor() as cur:
                        cur.execute("UPDATE users SET password=%s WHERE id=%s",
                                    (__user.hash_password(password), row["id"]))
                    db.commit()
                    db.close()
                    logger.info(f"Upgraded password hash for user {username} to pbkdf2")
                except Exception as e:
                    logger.error(f"Password hash upgrade error: {e}")
            __auth.clear_login_attempts(ip, username)
            user = User(row["id"], row["username"], row["role"], row["session_timeout"])
            __auth.clear_login_attempts(ip, username)
            user = User(row["id"], row["username"], row["role"], row["session_timeout"])

            # Check if MFA is required and user has it enrolled
            if __mfa.user_has_mfa(row["id"]) or __mfa.user_needs_mfa(user):
                if __mfa.user_has_mfa(row["id"]) and not __mfa.is_trusted_device(row["id"], request):
                    # Store pending auth in session and redirect to MFA
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    session["mfa_next"] = request.args.get("next", url_for('dashboard.dashboard'))
                    return redirect(url_for('mfa_routes.mfa_verify'))
                elif __mfa.user_needs_mfa(user) and not __mfa.user_has_mfa(row["id"]):
                    # MFA required but not enrolled — force enrollment
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    login_user(user)
                    session["last_active"] = datetime.now(timezone.utc).isoformat()
                    flash("MFA is required for your account. Please enroll now.", "warning")
                    return redirect(url_for('mfa_routes.mfa_enroll'))

            login_user(user)
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            __user.audit("LOGIN", "auth", f"User {username} logged in from {ip}")
            return redirect(url_for('dashboard.dashboard'))

        # Failed login — record attempt
        __auth.record_login_attempt(ip, username)
        rl = __auth.get_rate_limit_settings()
        if rl["max_attempts"] > 0 and rl["mode"] != "off":
            # Count remaining attempts
            locked, remaining = __auth.is_locked_out(ip, username)
            if locked:
                flash(f"Too many failed attempts. Account locked for {remaining} minute(s).", "error")
            else:
                try:
                    db = __db.get_jen_db()
                    with db.cursor() as cur:
                        window = f"DATE_SUB(NOW(), INTERVAL {rl['lockout_minutes']} MINUTE)" if rl['lockout_minutes'] > 0 else "'1970-01-01'"
                        cur.execute(f"SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address=%s AND attempted_at >= {window}", (ip,))
                        attempts = cur.fetchone()["cnt"]
                    db.close()
                    remaining_attempts = rl["max_attempts"] - attempts
                    if remaining_attempts <= 3:
                        flash(f"Invalid username or password. {remaining_attempts} attempt(s) remaining.", "error")
                    else:
                        flash("Invalid username or password.", "error")
                except Exception:
                    flash("Invalid username or password.", "error")
        else:
            flash("Invalid username or password.", "error")
        return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username=username)

    return render_template("login.html", jen_version=_JEN_VERSION(), prefill_username="")

@bp.route("/logout")
@login_required
def logout():
    __user.audit("LOGOUT", "auth", f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('auth.login'))

# ─────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────
