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

import pymysql

from jen.services.access import admin_required as _admin_required, superadmin_required as _superadmin_required

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
        with __db.jen_db() as db:
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
        with __db.kea_db() as db:
            with db.cursor() as cur:
                for sid in extensions.SUBNET_MAP:
                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                    lease_counts[sid] = cur.fetchone()["cnt"]
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
        with __db.jen_db() as db:
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
@_superadmin_required
def users():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id, username, role, session_timeout, created_at, subnet_access FROM users ORDER BY username")
                all_users = cur.fetchall()
                for u in all_users:
                    cur.execute("""
                        SELECT
                            (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) +
                            (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) as mfa_count
                    """, (u["id"], u["id"]))
                    u["mfa_enrolled"] = cur.fetchone()["mfa_count"] > 0
                    # Parse subnet_access for display
                    try:
                        import json as _json
                        u["subnet_ids"] = _json.loads(u["subnet_access"]) if u["subnet_access"] else None
                    except Exception:
                        u["subnet_ids"] = None
    except Exception as e:
        flash(f"Could not load users: {str(e)}", "error")
        all_users = []
    global_timeout = __user.get_global_setting("session_timeout_minutes", "60")
    mfa_mode = __mfa.get_mfa_mode()
    return render_template("users.html", users=all_users, global_timeout=global_timeout,
                           mfa_mode=mfa_mode, subnet_map=extensions.SUBNET_MAP)

@bp.route("/users/add", methods=["POST"])
@login_required
@_superadmin_required
def add_user():
    import json as _json
    username = request.form.get("username", "").strip()[:100]
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    timeout_raw = request.form.get("timeout", "").strip()
    subnet_ids_raw = request.form.getlist("subnet_ids")
    subnet_access = None
    if subnet_ids_raw and "all" not in subnet_ids_raw and role != "superadmin":
        try:
            subnet_access = _json.dumps([int(s) for s in subnet_ids_raw])
        except Exception:
            subnet_access = None
    timeout_val = None
    if timeout_raw and timeout_raw.isdigit() and 1 <= int(timeout_raw) <= 1440:
        timeout_val = int(timeout_raw)

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for('users.users'))
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,100}$', username):
        flash("Username may only contain letters, numbers, underscores, hyphens, and dots.", "error")
        return redirect(url_for('users.users'))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for('users.users'))
    if role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for('users.users'))

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password, role, subnet_access, session_timeout) VALUES (%s, %s, %s, %s, %s)",
                    (username, __user.hash_password(password), role, subnet_access, timeout_val)
                )
            db.commit()
        flash(f"User '{username}' created.", "success")
        __user.audit("ADD_USER", username, f"Role={role} subnet_access={subnet_access or 'all'}")
    except pymysql.IntegrityError:
        flash(f"Username '{username}' already exists.", "error")
    except Exception as e:
        flash(f"Error creating user: {str(e)}", "error")
    return redirect(url_for('users.users'))

@bp.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('users.users'))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for('users.users'))
                # Protect: cannot delete the last superadmin
                if row["role"] == "superadmin":
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot delete the last SuperAdmin account.", "error")
                        return redirect(url_for('users.users'))
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
            db.commit()
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
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET avatar_url=%s WHERE id=%s", (data_url, current_user.id))
                db.commit()
            flash("Profile picture updated.", "success")
            __user.audit("UPDATE_AVATAR", "user", current_user.username)
            session.pop("_avatar_url", None)  # invalidate avatar cache
        except Exception as e:
            flash(f"Error saving avatar: {str(e)}", "error")
    elif data_url == "":
        # Remove avatar
        try:
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET avatar_url=NULL WHERE id=%s", (current_user.id,))
                db.commit()
            flash("Profile picture removed.", "success")
            session.pop("_avatar_url", None)  # invalidate avatar cache
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
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id, password FROM users WHERE id=%s",
                            (current_user.id,))
                row = cur.fetchone()
                if not row or not __user.verify_password(row["password"], current_pw):
                    flash("Current password is incorrect.", "error")
                    return redirect(url_for('users.users'))
                cur.execute("UPDATE users SET password=%s WHERE id=%s",
                            (__user.hash_password(new_pw), current_user.id))
            db.commit()
        session.pop("_user_cache", None)
        flash("Password changed successfully.", "success")
        __user.audit("CHANGE_PASSWORD", current_user.username, "Password changed")
    except Exception as e:
        flash(f"Error changing password: {str(e)}", "error")
    return redirect(url_for('users.user_profile'))

@bp.route("/users/set-timeout/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_timeout(user_id):
    timeout = request.form.get("timeout", "").strip()
    if timeout and (not timeout.isdigit() or not (1 <= int(timeout) <= 1440)):
        flash("Timeout must be between 1 and 1440 minutes, or blank for global default.", "error")
        return redirect(url_for('users.users'))
    timeout_val = int(timeout) if timeout.isdigit() else None
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE users SET session_timeout=%s, token_version=token_version+1 WHERE id=%s",
                    (timeout_val, user_id))
            db.commit()
        session.pop("_user_cache", None)
        flash("Session timeout updated.", "success")
    except Exception as e:
        flash(f"Error updating timeout: {str(e)}", "error")
    return redirect(url_for('users.users'))

@bp.route("/users/set-role/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_role(user_id):
    role = request.form.get("role", "viewer")
    if role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for('users.users'))
    if user_id == current_user.id and role != "superadmin":
        flash("You cannot demote your own account from SuperAdmin.", "error")
        return redirect(url_for('users.users'))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for('users.users'))
                # Protect last superadmin
                if row["role"] == "superadmin" and role != "superadmin":
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot demote the last SuperAdmin account.", "error")
                        return redirect(url_for('users.users'))
                cur.execute(
                    "UPDATE users SET role=%s, token_version=token_version+1 WHERE id=%s",
                    (role, user_id))
            db.commit()
        # Invalidate session cache for affected user (see load_user() in
        # jen/__init__.py — token_version is what actually forces a
        # demoted/promoted user's OWN already-open session to re-fetch;
        # this pop only clears the ACTING superadmin's own cache)
        session.pop("_user_cache", None)
        flash(f"Role for '{row['username']}' updated to {role}.", "success")
        __user.audit("SET_ROLE", row["username"], f"role={role}")
    except Exception as e:
        flash(f"Error updating role: {str(e)}", "error")
    return redirect(url_for('users.users'))


@bp.route("/users/set-subnets/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_subnets(user_id):
    import json as _json
    subnet_ids_raw = request.form.getlist("subnet_ids")
    # "all" value means unrestricted (NULL)
    if not subnet_ids_raw or "all" in subnet_ids_raw:
        subnet_access = None
    else:
        try:
            subnet_access = _json.dumps([int(s) for s in subnet_ids_raw if s.isdigit()])
        except Exception:
            subnet_access = None
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for('users.users'))
                cur.execute(
                    "UPDATE users SET subnet_access=%s, token_version=token_version+1 WHERE id=%s",
                    (subnet_access, user_id))
            db.commit()
        session.pop("_user_cache", None)
        label = "all subnets" if subnet_access is None else f"subnets {subnet_access}"
        flash(f"Subnet access for '{row['username']}' set to {label}.", "success")
        __user.audit("SET_SUBNETS", row["username"], f"subnet_access={subnet_access or 'all'}")
    except Exception as e:
        flash(f"Error updating subnet access: {str(e)}", "error")
    return redirect(url_for('users.users'))


# ─────────────────────────────────────────
# Devices
# ─────────────────────────────────────────

@bp.route("/users/edit/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def edit_user(user_id):
    """Unified edit endpoint — handles role, subnets, timeout, and optional password reset."""
    import json as _json

    role        = request.form.get("role", "viewer")
    timeout_raw = request.form.get("timeout", "").strip()
    new_pw      = request.form.get("new_password", "").strip()
    confirm_pw  = request.form.get("confirm_password", "").strip()
    subnet_ids_raw = request.form.getlist("subnet_ids")

    # Validate role
    if role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for('users.users'))

    # Validate timeout
    timeout_val = None
    if timeout_raw:
        if not timeout_raw.isdigit() or not (1 <= int(timeout_raw) <= 1440):
            flash("Timeout must be 1–1440 minutes.", "error")
            return redirect(url_for('users.users'))
        timeout_val = int(timeout_raw)

    # Validate password if provided
    if new_pw:
        if len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "error")
            return redirect(url_for('users.users'))
        if new_pw != confirm_pw:
            flash("New passwords do not match.", "error")
            return redirect(url_for('users.users'))

    # Subnet access
    if not subnet_ids_raw or "all" in subnet_ids_raw or role == "superadmin":
        subnet_access = None
    else:
        try:
            subnet_access = _json.dumps([int(s) for s in subnet_ids_raw if s.isdigit()])
        except Exception:
            subnet_access = None

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for('users.users'))

                # Protect last superadmin from demotion
                if row["role"] == "superadmin" and role != "superadmin":
                    if user_id == current_user.id:
                        flash("You cannot demote your own SuperAdmin account.", "error")
                        return redirect(url_for('users.users'))
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot demote the last SuperAdmin account.", "error")
                        return redirect(url_for('users.users'))

                # Apply all changes in one update
                if new_pw:
                    cur.execute("""
                        UPDATE users SET role=%s, subnet_access=%s, session_timeout=%s, password=%s,
                               token_version=token_version+1
                        WHERE id=%s
                    """, (role, subnet_access, timeout_val, __user.hash_password(new_pw), user_id))
                    __user.audit("EDIT_USER", row["username"],
                                 f"role={role} subnets={subnet_access or 'all'} timeout={timeout_val} password=reset")
                else:
                    cur.execute("""
                        UPDATE users SET role=%s, subnet_access=%s, session_timeout=%s,
                               token_version=token_version+1
                        WHERE id=%s
                    """, (role, subnet_access, timeout_val, user_id))
                    __user.audit("EDIT_USER", row["username"],
                                 f"role={role} subnets={subnet_access or 'all'} timeout={timeout_val}")

            db.commit()
        session.pop("_user_cache", None)
        flash(f"User '{row['username']}' updated.", "success")
    except Exception as e:
        flash(f"Error updating user: {str(e)}", "error")
    return redirect(url_for('users.users'))


@bp.route("/users/reset-mfa/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def reset_user_mfa(user_id):
    """SuperAdmin wipes a user's MFA enrollment so they can re-enroll on next login."""
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for('users.users'))
                cur.execute("UPDATE mfa_methods SET enabled=0 WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (user_id,))
            db.commit()
        flash(f"MFA for '{row['username']}' has been reset. They will need to re-enroll.", "success")
        __user.audit("RESET_MFA", row["username"],
                     f"MFA reset by {current_user.username}")
    except Exception as e:
        flash(f"Error resetting MFA: {str(e)}", "error")
    return redirect(url_for('users.users'))
