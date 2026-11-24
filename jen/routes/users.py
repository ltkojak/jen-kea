"""
jen/routes/users.py
────────────────────
User management and profile routes.
"""

import logging
from datetime import date, timedelta
from urllib.parse import urlencode

import pymysql
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.models.user as __user
import jen.services.alerts as __alerts
import jen.services.auth as __auth
import jen.services.client_subject as __client_subject
import jen.services.kea as __kea
import jen.services.mfa as __mfa
import jen.services.session_timeout as __session_timeout
import jen.services.text as __text
from jen import extensions
from jen.services.access import admin_required as _admin_required
from jen.services.access import superadmin_required as _superadmin_required
from jen.services.forms import flash_field
from jen.services.leases_sql import ACTIVE_LEASE4
from jen.services.text import is_whole

logger = logging.getLogger(__name__)
bp = Blueprint("users", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


@bp.route("/audit")
@login_required
def audit_legacy():
    """Pre-5.9.0 URL — 301 to Settings → Logs, keeping ?page=/?search=."""
    return redirect(url_for("users.audit_log", **request.args.to_dict()), code=301)


def _whole_day(text):
    """A `YYYY-MM-DD` query value as a date, or None for anything else (empty, a time, another format): a day that cannot be read is no filter (Q248)."""
    text = str(text or "").strip()
    if len(text) != 10 or text[4] != "-" or text[7] != "-":
        return None  # the one shape a date field sends; a newer Python's `fromisoformat` reads others too
    try:
        day = date.fromisoformat(text)
        (
            day + timedelta(days=1)
        )  # (Q249) the filter reads up to the next day's first second: the last day a date can hold has none, and is no filter either
    except (ValueError, OverflowError):
        return None
    return day


@bp.route("/settings/logs")
@login_required
@_admin_required
def audit_log():
    """v5.9.0 — Settings → Logs: the audit log (tab=audit, default) and the
    alert delivery log (tab=alerts, which used to be a card at the bottom
    of the Alerts page)."""
    # (Q224, AJ4) rows that carry no subnet - audit and alert-delivery rows - are for unrestricted callers only (docs/ARCHITECTURE.md §2): their text names subnets, clients and
    # servers a scoped admin cannot see. The same rule Doctor and Config history apply, at the route, before the query
    if not current_user.all_subnets:
        flash("Logs need access to all subnets.", "error")
        return redirect(url_for("servers.servers"))
    tab = request.args.get("tab", "audit")
    if tab == "alerts":
        recent_alerts = []
        try:
            with __db.jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "SELECT alert_type, channel_type, status, error, sent_at, message FROM alert_log "
                    "ORDER BY sent_at DESC LIMIT 100"
                )
                recent_alerts = cur.fetchall()
            # v5.68.0-beta.1 (Q134) - an Investigate link on every row whose message names a client. The message is
            # never shown on this page, and it can name a subnet, so the link is for callers who may see every subnet.
            for a in recent_alerts:
                a["client"] = (
                    __client_subject.identifier_in_text(a.pop("message", "")) if current_user.all_subnets else ""
                )
        except Exception as e:
            logger.error(f"Could not load alert log: {e}")
            flash("Could not load the alert log. Check server logs for details.", "error")
        return render_template(
            "logs.html",
            tab="alerts",
            recent_alerts=recent_alerts,
            total=0,
            search="",
            alert_retention_days=__alerts.alert_log_retention_days(),
        )

    page = max(
        1, __text.whole(request.args.get("page", "1"), 1)
    )  # (Q226, AL14) the one whole-number test (DEF-003), never a bare `int()` over a query string
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    # Q248 (audit log filters): by action, by user and by day, beside the search. Each is one more parameterized condition of the same query; a value that is in
    # no row (typed into the address, or an action that has since aged out of the log) matches nothing and raises nothing. A day is a whole day in UTC, the clock
    # the rows are stored on (`created_at`) and the page prints: `from` is that day's first second, `to` is every second of that day.
    action = request.args.get("action", "").strip()[:100]
    user = request.args.get("user", "").strip()[:100]
    day_from = _whole_day(request.args.get("from", ""))
    day_to = _whole_day(request.args.get("to", ""))
    per_page = 50
    logs = []
    total = 0
    actions = []
    users = []
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            where = []
            params = []
            if search:
                where.append("(username LIKE %s OR action LIKE %s OR entity LIKE %s OR details LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s, s]
            if action:
                where.append("action = %s")
                params.append(action)
            if user:
                where.append("username = %s")
                params.append(user)
            if day_from:
                where.append("created_at >= %s")
                params.append(f"{day_from.isoformat()} 00:00:00")
            if day_to:
                where.append("created_at < %s")
                params.append(f"{(day_to + timedelta(days=1)).isoformat()} 00:00:00")
            # what the two selects offer: the actions and the users the log holds now (bounded - a log with more than 200 of either is searched by the text field)
            cur.execute(
                "SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL AND action <> '' ORDER BY action LIMIT 200"
            )
            actions = [r["action"] for r in cur.fetchall()]
            cur.execute(
                "SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL AND username <> '' ORDER BY username LIMIT 200"
            )
            users = [r["username"] for r in cur.fetchall()]
            where_str = " WHERE " + " AND ".join(where) if where else ""
            cur.execute(f"SELECT COUNT(*) as cnt FROM audit_log{where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(
                f"SELECT * FROM audit_log{where_str} ORDER BY created_at DESC LIMIT {per_page} OFFSET {offset}",
                params,
            )
            logs = cur.fetchall()
    except Exception as e:
        logger.error(f"Could not load audit log: {e}")
        flash("Could not load audit log. Check server logs for details.", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    # a filter that is set is always one of its select's choices, so the page shows it as set even when no row carries it
    if action and action not in actions:
        actions = sorted([*actions, action])
    if user and user not in users:
        users = sorted([*users, user])
    filters = {
        "action": action,
        "user": user,
        "from": day_from.isoformat() if day_from else "",
        "to": day_to.isoformat() if day_to else "",
    }
    # what a paging link carries besides its page: the tab, the search and every filter that is set
    query = urlencode({"tab": "audit", "search": search, **{k: v for k, v in filters.items() if v}})
    return render_template(
        "logs.html",
        tab="audit",
        logs=logs,
        page=page,
        pages=pages,
        total=total,
        search=search,
        filters=filters,
        filtered=any(filters.values()),
        actions=actions,
        users=users,
        query=query,
    )


# ─────────────────────────────────────────
# About
# ─────────────────────────────────────────
@bp.route("/about")
@login_required
def about():
    kea_up = False
    kea_version = ""
    lease_counts = {}
    # v5.68.0-beta.21 (Q156): the subnets THEMSELVES are scoped (docs/ARCHITECTURE.md section 2) - this page printed every subnet's id, name, CIDR and
    # active lease count to any logged-in user, a viewer restricted to subnet 1 included. The map, and the lease counts over it, are the user's own.
    visible_subnets = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    try:
        ver_result = __kea.kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = (ver_result.get("arguments") or {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            for sid in visible_subnets:
                cur.execute(
                    f"SELECT COUNT(*) as cnt FROM lease4 WHERE {ACTIVE_LEASE4} AND subnet_id=%s",  # nosec B608 - a fixed constant
                    (sid,),
                )
                lease_counts[sid] = cur.fetchone()["cnt"]
    except Exception:
        pass
    from jen.config import ssl_configured
    from jen.services.changelog import whats_new

    # Q248 (addition 15, V33): the entries as a person reads them - the newest one's lead paragraph, the rest behind "More", no tracking codes
    changelog_entries = whats_new(limit=5)
    return render_template(
        "about.html",
        jen_version=_JEN_VERSION(),
        kea_version=kea_version,
        kea_up=kea_up,
        # v5.10.4 — the template's deployment-detail rows (now admin-only)
        # need these; they were never passed, so admins saw blank cells.
        http_port=extensions.HTTP_PORT,
        https_port=extensions.HTTPS_PORT,
        ssl_on=ssl_configured(),
        kea_ssh_host=extensions.KEA_SSH_HOST,
        subnet_map=visible_subnets,
        lease_counts=lease_counts,
        changelog_entries=changelog_entries,
    )


# ─────────────────────────────────────────


@bp.route("/profile")
@login_required
def user_profile():
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT id, username, role, session_timeout, created_at FROM users WHERE id=%s", (current_user.id,)
            )
            user_data = cur.fetchone()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_methods WHERE user_id=%s AND enabled=1", (current_user.id,))
            totp_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id=%s", (current_user.id,))
            passkey_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0", (current_user.id,))
            backup_count = cur.fetchone()["cnt"]
            cur.execute(
                """
                    SELECT COUNT(*) as cnt FROM mfa_trusted_devices
                    WHERE user_id=%s AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (current_user.id,),
            )
            trusted_count = cur.fetchone()["cnt"]
    except Exception as e:
        logger.error(f"Error loading profile for {current_user.username}: {e}")
        flash("Error loading profile. Check server logs for details.", "error")
        user_data = None
        totp_count = passkey_count = backup_count = trusted_count = 0
    return render_template(
        "user_profile.html",
        user_data=user_data,
        totp_count=totp_count,
        passkey_count=passkey_count,
        backup_count=backup_count,
        device_count=trusted_count,
        mfa_enrolled=(totp_count + passkey_count) > 0,
    )


# ─────────────────────────────────────────
# Users
# ─────────────────────────────────────────
@bp.route("/users")
@login_required
def users_legacy():
    """Pre-5.9.0 URL — 301 to Settings → Access & Security → Users."""
    return redirect(url_for("users.users"), code=301)


@bp.route("/settings/users")
@login_required
@_superadmin_required
def users():
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT id, username, role, session_timeout, created_at, subnet_access, "
                "auth_provider, external_id FROM users ORDER BY username"
            )
            all_users = cur.fetchall()
            for u in all_users:
                cur.execute(
                    """
                        SELECT
                            (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) AS totp_count,
                            (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) AS passkey_count
                    """,
                    (u["id"], u["id"]),
                )
                counts = cur.fetchone()
                # (Q248, addition 8) the account's second factor in words, each method it has: the list says "Authenticator app", "Passkey", both, or "None"
                u["mfa_methods"] = [
                    word
                    for word, n in (("Authenticator app", counts["totp_count"]), ("Passkey", counts["passkey_count"]))
                    if n
                ]
                u["mfa_enrolled"] = bool(u["mfa_methods"])
                # (Q224, AJ15) the minutes the server APPLIES for this account (Q215 Z18's rule, one column over): a stored row outside 0..1440 - a hand edit, an earlier release - reads as
                # the global, and the page says so instead of printing the row
                u["own_minutes"] = __session_timeout.parse_minutes(u.get("session_timeout")) or None
                # (Q249) the stored scope through the reader the account itself is read with (`read_subnet_scope`): NULL is every subnet, and a scope that cannot
                # be read is no subnets - the list shows the dash and the Edit dialog ticks nothing. This page read it its own way, as every subnet.
                u["subnet_ids"] = __user.read_subnet_scope(u["subnet_access"])
    except Exception as e:
        logger.error(f"Could not load users: {e}")
        flash("Could not load users. Check server logs for details.", "error")
        all_users = []
    # Q215 (F3, Z18): the minutes the server APPLIES (a hand-edited row reads as 60 there), the same number the Security form shows
    global_timeout = str(__session_timeout.global_minutes())
    mfa_mode = __mfa.get_mfa_mode()
    # (Q248, V3) what a refused Add User or Edit User form held, for this ONE render: the page opens that dialog again with it
    form_back = session.pop(USERS_FORM_KEY, None)
    if not (isinstance(form_back, dict) and form_back.get("form") in ("add", "edit")):
        form_back = None
    return render_template(
        "users.html",
        users=all_users,
        global_timeout=global_timeout,
        mfa_mode=mfa_mode,
        subnet_map=extensions.SUBNET_MAP,
        form_back=form_back,
    )


USERS_FORM_KEY = "users_form"


def _keep_user_form(which, user_id=None):
    """(Q248, V3) Keep what a refused Add User ("add") or Edit User ("edit") form held, for the next render of the Users page: the username, the role, the ticked
    subnets and the timeout, so the dialog opens again with them and the message lands beside its field. NEVER a password. It travels in the session cookie, so every
    value is cut short; `users()` takes it out again on the next render."""
    session[USERS_FORM_KEY] = {
        "form": which,
        "id": user_id,
        "username": request.form.get("username", "").strip()[:100],
        "role": request.form.get("role", "")[:20],
        "subnet_ids": [s[:12] for s in request.form.getlist("subnet_ids")[:64]],
        "timeout": request.form.get("timeout", "").strip()[:8],
    }
    return redirect(url_for("users.users"))


SUBNETS_NONE_TICKED = "Tick All Subnets or at least one subnet. Nothing was changed."
SUBNETS_ALL_AND_NAMED = "Tick All Subnets or named subnets, not both. Nothing was changed."


def _stored_no_subnets(stored) -> bool:
    """(Q249) Is this account's stored scope "no subnets" - an empty list, or a value that cannot be read (`read_subnet_scope`)? The single-sign-on mapping stores
    `[]` for a sign-in whose groups match nothing."""
    return stored is not None and __user.read_subnet_scope(stored) == []


def _subnet_access_from_form(subnet_ids_raw, role):
    """(Q248, V41, and BH1's rule carried to its siblings) What an account's subnet list of a form means: `(True, value)` with
    `value` None for every subnet or the JSON list of ids, or `(False, sentence)` for a form that is refused whole.

    An account that sees every subnet is made ONLY by "all" alone (or by the superadmin role, which is never restricted).
    Nothing ticked used to read as every subnet, and so did "all" beside a subnet id: with the list a set of checkboxes,
    unticking All Subnets and ticking nothing would have made an unrestricted account in one click. A value that is not a
    whole number refuses the form whole (Q171, Q224 AJ5); each id is stored once, in order (Q225 AK22)."""
    import json as _json

    if role == "superadmin":
        return True, None
    if not subnet_ids_raw:
        return False, SUBNETS_NONE_TICKED
    if "all" in subnet_ids_raw:
        if any(s != "all" for s in subnet_ids_raw):
            return False, SUBNETS_ALL_AND_NAMED
        return True, None
    if not all(is_whole(s) for s in subnet_ids_raw):
        return False, "Subnet ids must be numbers."
    return True, _json.dumps(sorted({int(s) for s in subnet_ids_raw}))


@bp.route("/users/add", methods=["POST"])
@login_required
@_superadmin_required
def add_user():

    username = request.form.get("username", "").strip()[:100]
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    timeout_raw = request.form.get("timeout", "").strip()
    subnet_ids_raw = request.form.getlist("subnet_ids")
    # v5.69.0-beta.2 (Q171): a value that is not a whole number used to raise and fall back to None - an UNRESTRICTED account. Fail closed: the form is refused whole, and
    # what is stored is only ever a list of the numbers submitted. (Q248) nothing ticked, or All Subnets beside a subnet, is refused the same way.
    # (Q248, V3) every refusal goes back to the Users page with the dialog open again, what was typed still in it (`_keep_user_form`: never the password) and the
    # message beside its field. The subnet list's refusal used to answer 400 with the page itself, which a reload would have posted again.
    ok, subnet_access = _subnet_access_from_form(subnet_ids_raw, role)
    if not ok:
        flash_field("subnet_ids", subnet_access)
        return _keep_user_form("add")

    if not username:
        flash_field("username", "Username is required.")
        return _keep_user_form("add")
    if not __auth.valid_username(username):
        flash_field("username", "Username may only contain letters, numbers, underscores, hyphens, and dots.")
        return _keep_user_form("add")
    if len(password) < 8:
        flash_field("password", "Password must be at least 8 characters.")
        return _keep_user_form("add")
    if role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return _keep_user_form("add")
    # Q215: the timeout is refused the way the edit and set-timeout routes refuse it, after the name, the password and the role (an out-of-range or unreadable value used to create the account on the
    # global timeout without a word) - so a form with several things wrong still says the field errors first
    timeout_val = None
    if timeout_raw:
        if (__session_timeout.parse_minutes(timeout_raw) or 0) < 1:
            flash_field("timeout", "Timeout must be 1–1440 minutes.")
            return _keep_user_form("add")
        timeout_val = __session_timeout.parse_minutes(timeout_raw)

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password, role, subnet_access, session_timeout, must_change_password) "
                    "VALUES (%s, %s, %s, %s, %s, 1)",
                    (username, __user.hash_password(password), role, subnet_access, timeout_val),
                )
            db.commit()
        flash(f"User '{username}' created.", "success")
        __user.audit("ADD_USER", username, f"Role={role} subnet_access={subnet_access or 'all'}")
    except pymysql.IntegrityError:
        flash_field("username", f"Username '{username}' already exists.")
        return _keep_user_form("add")
    except Exception as e:
        logger.error(f"Error creating user '{username}': {e}")
        flash("Error creating user. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


@bp.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users.users"))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for("users.users"))
                # Protect: cannot delete the last superadmin
                if row["role"] == "superadmin":
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot delete the last Superadmin account.", "error")
                        return redirect(url_for("users.users"))
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
            db.commit()
        flash(f"User '{row['username']}' deleted.", "success")
        __user.audit("DELETE_USER", row["username"], "User deleted")
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        flash("Error deleting user. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


@bp.route("/users/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    import re

    data_url = request.form.get("avatar_data_url", "").strip()
    if data_url and data_url.startswith("data:image/"):
        # Validate it's a reasonable size (max ~200KB base64)
        if len(data_url) > 280000:
            flash("Image too large. Please use an image under 200KB.", "error")
            return redirect(url_for("users.user_profile"))
        # Validate format
        if not re.match(r"^data:image/(jpeg|png|gif|webp);base64,[A-Za-z0-9+/=]+$", data_url):
            flash("Invalid image format.", "error")
            return redirect(url_for("users.user_profile"))
        try:
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("UPDATE users SET avatar_url=%s WHERE id=%s", (data_url, current_user.id))
                db.commit()
            flash("Profile picture updated.", "success")
            __user.audit("UPDATE_AVATAR", "user", current_user.username)
            session.pop("_avatar_url", None)  # invalidate avatar cache
        except Exception as e:
            logger.error(f"Error saving avatar for {current_user.username}: {e}")
            flash("Error saving avatar. Check server logs for details.", "error")
    elif data_url:
        # anything that is not an image data URL used to fall through with no answer at all (v5.69.0-beta.5, Q174)
        flash("That is not an image. Choose a JPEG, PNG, GIF or WebP file.", "error")
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
            logger.error(f"Error removing avatar for {current_user.username}: {e}")
            flash("Error removing avatar. Check server logs for details.", "error")
    return redirect(url_for("users.user_profile"))


@bp.route("/users/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    # v5.69.0-beta.2 (Q171): a failure goes back to the profile this form lives on - the Users page is superadmin-only, so a viewer or admin got "Superadmin access
    # required" and never saw why their change was refused.
    if new_pw != confirm_pw:
        flash_field("confirm_password", "New passwords do not match.")
        return redirect(url_for("users.user_profile"))
    if len(new_pw) < 8:
        flash_field("new_password", "New password must be at least 8 characters.")
        return redirect(url_for("users.user_profile"))

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id, password FROM users WHERE id=%s", (current_user.id,))
                row = cur.fetchone()
                if not row or not __user.verify_password(row["password"], current_pw):
                    flash_field("current_password", "Current password is incorrect.")
                    return redirect(url_for("users.user_profile"))
                # token_version moves in the same statement, and `load_user` ends every OTHER session whose password fingerprint is no longer the row's
                cur.execute(
                    "UPDATE users SET password=%s, must_change_password=0, token_version=token_version+1 WHERE id=%s",
                    (__user.hash_password(new_pw), current_user.id),
                )
            db.commit()
        session.pop("_user_cache", None)
        flash("Password changed successfully.", "success")
        __user.audit("CHANGE_PASSWORD", current_user.username, "Password changed")
    except Exception as e:
        logger.error(f"Error changing password for {current_user.username}: {e}")
        flash("Error changing password. Check server logs for details.", "error")
    return redirect(url_for("users.user_profile"))


@bp.route("/users/set-timeout/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_timeout(user_id):
    timeout = request.form.get("timeout", "").strip()
    if timeout and (__session_timeout.parse_minutes(timeout) or 0) < 1:
        flash("Timeout must be between 1 and 1440 minutes, or blank for global default.", "error")
        return redirect(url_for("users.users"))
    timeout_val = __session_timeout.parse_minutes(timeout) if timeout else None
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE users SET session_timeout=%s, token_version=token_version+1 WHERE id=%s",
                    (timeout_val, user_id),
                )
                found = cur.rowcount > 0
            db.commit()
        if not found:  # token_version moves on every real row, so no row changed means no such account
            flash("User not found.", "error")
            return redirect(url_for("users.users"))
        session.pop("_user_cache", None)
        flash("Session timeout updated.", "success")
    except Exception as e:
        logger.error(f"Error updating timeout for user {user_id}: {e}")
        flash("Error updating timeout. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


@bp.route("/users/set-role/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_role(user_id):
    role = request.form.get("role", "viewer")
    if role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("users.users"))
    if user_id == current_user.id and role != "superadmin":
        flash("You cannot demote your own account from Superadmin.", "error")
        return redirect(url_for("users.users"))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for("users.users"))
                # Protect last superadmin
                if row["role"] == "superadmin" and role != "superadmin":
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot demote the last Superadmin account.", "error")
                        return redirect(url_for("users.users"))
                cur.execute("UPDATE users SET role=%s, token_version=token_version+1 WHERE id=%s", (role, user_id))
            db.commit()
        # Invalidate session cache for affected user (see load_user() in
        # jen/__init__.py — token_version is what actually forces a
        # demoted/promoted user's OWN already-open session to re-fetch;
        # this pop only clears the ACTING superadmin's own cache)
        session.pop("_user_cache", None)
        flash(f"Role for '{row['username']}' updated to {role}.", "success")
        __user.audit("SET_ROLE", row["username"], f"role={role}")
    except Exception as e:
        logger.error(f"Error updating role for user {user_id}: {e}")
        flash("Error updating role. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


#: (Q251) why a single sign-on account's Subnet Access is not edited: the Edit User dialog shows it where the boxes would be (templates/users.html holds the
#: same words) and `set_user_subnets` refuses with it. "Subnet Mapping" is the field's label on the Access & Security page's Single Sign-On card.
SSO_SUBNETS_SENTENCE = "Set by the identity provider at every sign-in (Subnet Mapping under Settings → Access & Security → Single Sign-On), so it is not edited here."


@bp.route("/users/set-subnets/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def set_user_subnets(user_id):

    subnet_ids_raw = request.form.getlist("subnet_ids")
    # "all" ALONE means unrestricted (NULL). (Q224, AJ5) a value that is not a whole number refuses the form whole; (Q248) so does nothing ticked, and "all" beside an id:
    # nothing here ever falls back to None (an UNRESTRICTED account) or drops one id from a selection. The role is not this form's: it is read from the row.
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role, auth_provider FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for("users.users"))
                if row["auth_provider"] == "oidc":
                    # (Q251) as in `edit_user`: the identity provider sets a single sign-on account's subnets at every sign-in. Refused, nothing changed.
                    flash(SSO_SUBNETS_SENTENCE, "error")
                    return redirect(url_for("users.users"))
                # (Q249) a Superadmin is never restricted: its row stores NULL whatever the list says, as `add_user` and `edit_user` store it. The list used to
                # be stored, and the Users page showed a scope the account does not have.
                ok, subnet_access = _subnet_access_from_form(subnet_ids_raw, row["role"])
                if not ok:
                    flash(subnet_access, "error")
                    return redirect(url_for("users.users"))
                cur.execute(
                    "UPDATE users SET subnet_access=%s, token_version=token_version+1 WHERE id=%s",
                    (subnet_access, user_id),
                )
            db.commit()
        session.pop("_user_cache", None)
        label = "all subnets" if subnet_access is None else f"subnets {subnet_access}"
        flash(f"Subnet access for '{row['username']}' set to {label}.", "success")
        __user.audit("SET_SUBNETS", row["username"], f"subnet_access={subnet_access or 'all'}")
    except Exception as e:
        logger.error(f"Error updating subnet access for user {user_id}: {e}")
        flash("Error updating subnet access. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


@bp.route("/users/link-sso/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def link_user_to_sso(user_id):
    """v5.25.0 (Q21) — the sanctioned way to convert an existing local
    account to OIDC-managed: a superadmin enters the IdP's own subject
    (the `sub`/external_id claim) for that user by hand, after
    confirming it out of band — Jen has no way to verify it here.
    Clears must_change_password (the local password is never used
    again) and, from this point on, /login refuses this username
    entirely (see auth.py's login()), same as any other OIDC account."""
    external_id = request.form.get("external_id", "").strip()
    if not external_id:
        flash("An external ID (the IdP's subject/sub claim) is required to link an account.", "error")
        return redirect(url_for("users.users"))

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, auth_provider FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for("users.users"))
                if row["auth_provider"] == "oidc":
                    flash(f"'{row['username']}' is already linked to SSO.", "error")
                    return redirect(url_for("users.users"))
                cur.execute(
                    "UPDATE users SET auth_provider='oidc', external_id=%s, must_change_password=0, "
                    "token_version=token_version+1 WHERE id=%s",
                    (external_id, user_id),
                )
            db.commit()
        session.pop("_user_cache", None)
        flash(f"'{row['username']}' is now linked to SSO — local login is disabled for this account.", "success")
        __user.audit("LINK_SSO", row["username"], f"external_id={external_id}")
    except pymysql.err.IntegrityError:
        flash("That external ID is already linked to another account.", "error")
    except Exception as e:
        logger.error(f"Error linking user {user_id} to SSO: {e}")
        flash("Error linking account. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


# ─────────────────────────────────────────
# Devices
# ─────────────────────────────────────────


@bp.route("/users/edit/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
def edit_user(user_id):
    """Unified edit endpoint — handles role, subnets, timeout, and optional password reset."""

    # (Q249) a form that carries no role keeps the role the row has. The dialog disables its role select for the account's own row (and for a single-sign-on
    # account), a disabled field is not posted, and the missing role used to read as "viewer": a superadmin could not save their own timeout or password
    # ("You cannot demote your own Superadmin account."). None here is "the row's own", resolved once the row is read.
    role = request.form.get("role")
    timeout_raw = request.form.get("timeout", "").strip()
    new_pw = request.form.get("new_password", "").strip()
    confirm_pw = request.form.get("confirm_password", "").strip()
    subnet_ids_raw = request.form.getlist("subnet_ids")

    # Validate role
    if role is not None and role not in ("superadmin", "admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("users.users"))

    # (Q248, V3) a refusal that names a field of the dialog opens the dialog again for this account, with what was typed (`_keep_user_form`: never a password) and the
    # message beside the field. The Edit User fields carry their own ids (`f-edit-...`): the Add User dialog is on the same page and has a timeout and a subnet list too.
    # Validate timeout
    timeout_val = None
    if timeout_raw:
        if (__session_timeout.parse_minutes(timeout_raw) or 0) < 1:
            flash_field("edit-timeout", "Timeout must be 1–1440 minutes.")
            return _keep_user_form("edit", user_id)
        timeout_val = __session_timeout.parse_minutes(timeout_raw)

    # Validate password if provided
    if new_pw:
        if len(new_pw) < 8:
            flash_field("edit-new_password", "New password must be at least 8 characters.")
            return _keep_user_form("edit", user_id)
        if new_pw != confirm_pw:
            flash_field("edit-confirm_password", "New passwords do not match.")
            return _keep_user_form("edit", user_id)

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT username, role, auth_provider, subnet_access FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    flash("User not found.", "error")
                    return redirect(url_for("users.users"))
                if role is None:
                    role = row["role"]

                # v5.25.0 (Q21) — an OIDC-linked account's role is
                # IdP-managed (recomputed on every login) and it has no
                # usable local password. The edit form disables both
                # controls client-side; ignore them here too rather than
                # trust that a disabled <select>/<input> stays disabled —
                # a disabled field simply isn't submitted by a normal
                # browser, so a submitted role/new_password for this user
                # would otherwise have come from somewhere else.
                if row["auth_provider"] == "oidc":
                    role = row["role"]
                    new_pw = ""

                # Subnet access. (Q224, AJ5) as in `add_user` and `set_user_subnets`: refused whole, never None, never one id short; (Q248) nothing ticked is
                # refused too. (Q249) with ONE exception: an account whose stored scope is already no subnets (what single sign-on stores for a sign-in whose
                # groups match nothing, and what the dialog then shows: nothing ticked) keeps it. Its timeout could not be saved without granting it subnets.
                # (Q251) a single sign-on account's subnets are the identity provider's too: `oidc.find_or_create_user` writes them again at every sign-in,
                # so a scope saved here lasted until the account next signed in. The dialog offers no boxes for such an account; whatever is posted, the
                # stored value goes back untouched (NULL stays NULL) and the rest of the form - the timeout - is saved.
                if row["auth_provider"] == "oidc":
                    ok, subnet_access = True, row["subnet_access"]
                elif not subnet_ids_raw and role != "superadmin" and _stored_no_subnets(row["subnet_access"]):
                    ok, subnet_access = True, "[]"
                else:
                    ok, subnet_access = _subnet_access_from_form(subnet_ids_raw, role)
                if not ok:
                    flash_field("edit-subnet_ids", subnet_access)
                    return _keep_user_form("edit", user_id)

                # Protect last superadmin from demotion
                if row["role"] == "superadmin" and role != "superadmin":
                    if user_id == current_user.id:
                        flash("You cannot demote your own Superadmin account.", "error")
                        return redirect(url_for("users.users"))
                    cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role='superadmin'")
                    if cur.fetchone()["cnt"] <= 1:
                        flash("Cannot demote the last Superadmin account.", "error")
                        return redirect(url_for("users.users"))

                # Apply all changes in one update
                if new_pw:
                    cur.execute(
                        """
                        UPDATE users SET role=%s, subnet_access=%s, session_timeout=%s, password=%s,
                               token_version=token_version+1
                        WHERE id=%s
                    """,
                        (role, subnet_access, timeout_val, __user.hash_password(new_pw), user_id),
                    )
                    __user.audit(
                        "EDIT_USER",
                        row["username"],
                        f"role={role} subnets={subnet_access or 'all'} timeout={timeout_val} password=reset",
                    )
                else:
                    cur.execute(
                        """
                        UPDATE users SET role=%s, subnet_access=%s, session_timeout=%s,
                               token_version=token_version+1
                        WHERE id=%s
                    """,
                        (role, subnet_access, timeout_val, user_id),
                    )
                    __user.audit(
                        "EDIT_USER",
                        row["username"],
                        f"role={role} subnets={subnet_access or 'all'} timeout={timeout_val}",
                    )

            db.commit()
        session.pop("_user_cache", None)
        flash(f"User '{row['username']}' updated.", "success")
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        flash("Error updating user. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


# v5.69.0-beta.2 (Q171): `/users/reset-mfa/<id>` is gone. It was the route the Users page posted to - superadmin, but with no step-up and with different semantics
# (the methods disabled, not deleted) from `/mfa/admin-reset/<id>`, the twin that asks for a recent password. There is one route now, in mfa_routes.py.
