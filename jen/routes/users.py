"""
jen/routes/users.py
────────────────────
User management and profile routes.
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
bp = Blueprint("users", __name__)


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


@bp.route("/audit")
@login_required
@_admin_required
def audit_log():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    per_page = 50
    logs = []
    total = 0
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            where = []
            params = []
            if search:
                where.append("(username LIKE %s OR action LIKE %s OR entity LIKE %s OR details LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s, s]
            where_str = " WHERE " + " AND ".join(where) if where else ""
            cur.execute(f"SELECT COUNT(*) as cnt FROM audit_log{where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"SELECT * FROM audit_log{where_str} ORDER BY created_at DESC LIMIT {per_page} OFFSET {offset}", params)
            logs = cur.fetchall()
        db.close()
    except Exception as e:
        flash(f"Could not load audit log: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    return render_template("audit.html", logs=logs, page=page, pages=pages,
                           total=total, search=search)

# ─────────────────────────────────────────
# About
# ─────────────────────────────────────────
@bp.route("/about")
@login_required
def about():
    kea_up = False
    kea_version = ""
    lease_counts = {}
    try:
        ver_result = __kea.kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            for sid in extensions.SUBNET_MAP:
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                lease_counts[sid] = cur.fetchone()["cnt"]
        db.close()
    except Exception:
        pass
    return render_template("about.html", jen_version=_JEN_VERSION(), kea_version=kea_version,
                           kea_up=kea_up, https_port=extensions.HTTPS_PORT, subnet_map=extensions.SUBNET_MAP,
                           lease_counts=lease_counts)

# ─────────────────────────────────────────

@bp.route("/profile")
@login_required
def user_profile():
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout, created_at FROM users WHERE id=%s",
                       (current_user.id,))
            user_data = cur.fetchone()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_methods WHERE user_id=%s AND enabled=1",
                       (current_user.id,))
            totp_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id=%s",
                       (current_user.id,))
            passkey_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0",
                       (current_user.id,))
            backup_count = cur.fetchone()["cnt"]
            cur.execute("""
                SELECT COUNT(*) as cnt FROM mfa_trusted_devices
                WHERE user_id=%s AND (expires_at IS NULL OR expires_at > NOW())
            """, (current_user.id,))
            trusted_count = cur.fetchone()["cnt"]
        db.close()
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "error")
        user_data = None
        totp_count = passkey_count = backup_count = trusted_count = 0
    return render_template("user_profile.html",
                           user_data=user_data,
                           totp_count=totp_count,
                           passkey_count=passkey_count,
                           backup_count=backup_count,
                           device_count=trusted_count,
                           mfa_enrolled=(totp_count + passkey_count) > 0)

# ─────────────────────────────────────────
# Users
# ─────────────────────────────────────────
@bp.route("/users")
@login_required
@_admin_required
def users():
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout, created_at FROM users ORDER BY username")
            all_users = cur.fetchall()
            # Add MFA status
            for u in all_users:
                cur.execute("""
                    SELECT
                        (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) +
                        (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) as mfa_count
                """, (u["id"], u["id"]))
                u["mfa_enrolled"] = cur.fetchone()["mfa_count"] > 0
        db.close()
    except Exception as e:
        flash(f"Could not load users: {str(e)}", "error")
        all_users = []
    global_timeout = __user.get_global_setting("session_timeout_minutes", "60")
    mfa_mode = __mfa.get_mfa_mode()
    return render_template("users.html", users=all_users, global_timeout=global_timeout, mfa_mode=mfa_mode)

@bp.route("/users/add", methods=["POST"])
@login_required
@_admin_required
def add_user():
    username = request.form.get("username", "").strip()[:100]
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for('users.users'))
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,100}$', username):
        flash("Username may only contain letters, numbers, underscores, hyphens, and dots.", "error")
        return redirect(url_for('users.users'))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for('users.users'))
    if role not in ("admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for('users.users'))

    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                        (username, __user.hash_password(password), role))
        db.commit()
        db.close()
        flash(f"User '{username}' created.", "success")
        __user.audit("ADD_USER", username, f"Role={role}")
    except pymysql.IntegrityError:
        flash(f"Username '{username}' already exists.", "error")
    except Exception as e:
        flash(f"Error creating user: {str(e)}", "error")
    return redirect(url_for('users.users'))

@bp.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
@_admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('users.users'))
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if not row:
                flash("User not found.", "error")
                db.close()
                return redirect(url_for('users.users'))
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        db.close()
        flash(f"User '{row['username']}' deleted.", "success")
        __user.audit("DELETE_USER", row["username"], "User deleted")
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "error")
    return redirect(url_for('users.users'))

@bp.route("/users/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    import base64, re
    data_url = request.form.get("avatar_data_url", "").strip()
    if data_url and data_url.startswith("data:image/"):
        # Validate it's a reasonable size (max ~200KB base64)
        if len(data_url) > 280000:
            flash("Image too large. Please use an image under 200KB.", "error")
            return redirect(url_for('users.user_profile'))
        # Validate format
        if not re.match(r'^data:image/(jpeg|png|gif|webp);base64,[A-Za-z0-9+/=]+$', data_url):
            flash("Invalid image format.", "error")
            return redirect(url_for('users.user_profile'))
        try:
            db = __db.get_jen_db()
            with db.cursor() as cur:
                cur.execute("UPDATE users SET avatar_url=%s WHERE id=%s", (data_url, current_user.id))
            db.commit()
            db.close()
            flash("Profile picture updated.", "success")
            __user.audit("UPDATE_AVATAR", "user", current_user.username)
        except Exception as e:
            flash(f"Error saving avatar: {str(e)}", "error")
    elif data_url == "":
        # Remove avatar
        try:
            db = __db.get_jen_db()
            with db.cursor() as cur:
                cur.execute("UPDATE users SET avatar_url=NULL WHERE id=%s", (current_user.id,))
            db.commit()
            db.close()
            flash("Profile picture removed.", "success")
        except Exception as e:
            flash(f"Error removing avatar: {str(e)}", "error")
    return redirect(url_for('users.user_profile'))

@bp.route("/users/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return redirect(url_for('users.users'))
    if len(new_pw) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for('users.users'))

    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, password FROM users WHERE id=%s",
                        (current_user.id,))
            row = cur.fetchone()
            if not row or not __user.verify_password(row["password"], current_pw):
                flash("Current password is incorrect.", "error")
                db.close()
                return redirect(url_for('users.users'))
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        (__user.hash_password(new_pw), current_user.id))
        db.commit()
        db.close()
        flash("Password changed successfully.", "success")
        __user.audit("CHANGE_PASSWORD", current_user.username, "Password changed")
    except Exception as e:
        flash(f"Error changing password: {str(e)}", "error")
    return redirect(url_for('users.users'))

@bp.route("/users/set-timeout/<int:user_id>", methods=["POST"])
@login_required
@_admin_required
def set_user_timeout(user_id):
    timeout = request.form.get("timeout", "").strip()
    if timeout and (not timeout.isdigit() or not (1 <= int(timeout) <= 1440)):
        flash("Timeout must be between 1 and 1440 minutes, or blank for global default.", "error")
        return redirect(url_for('users.users'))
    timeout_val = int(timeout) if timeout.isdigit() else None
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("UPDATE users SET session_timeout=%s WHERE id=%s", (timeout_val, user_id))
        db.commit()
        db.close()
        flash("Session timeout updated.", "success")
    except Exception as e:
        flash(f"Error updating timeout: {str(e)}", "error")
    return redirect(url_for('users.users'))

# ─────────────────────────────────────────
# Devices
# ─────────────────────────────────────────
