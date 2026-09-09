"""
jen/routes/auth.py
───────────────────
Authentication routes: login, logout.
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.mfa as __mfa
from jen.models.user import User

logger = logging.getLogger(__name__)
bp = Blueprint("auth", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


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
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    # User lookup
                    cur.execute(
                        "SELECT id, username, role, session_timeout, password, subnet_access, token_version, must_change_password FROM users WHERE username=%s",
                        (username,),
                    )
                    row = cur.fetchone()

                    # Rate limit settings (single query)
                    cur.execute(
                        "SELECT setting_key, setting_value FROM settings "
                        "WHERE setting_key IN ('rl_max_attempts','rl_lockout_minutes','rl_mode','mfa_mode')"
                    )
                    settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

                    rl_mode = settings.get("rl_mode", "both")
                    max_att = int(settings.get("rl_max_attempts", "10"))
                    lockout_min = int(settings.get("rl_lockout_minutes", "15"))

                    locked = False
                    remaining = 0
                    if rl_mode != "off" and max_att > 0:
                        window = f"DATE_SUB(NOW(), INTERVAL {lockout_min if lockout_min > 0 else 1440} MINUTE)"
                        count = 0
                        if rl_mode in ("ip", "both"):
                            cur.execute(
                                f"SELECT COUNT(*) as cnt FROM login_attempts "
                                f"WHERE ip_address=%s AND attempted_at >= {window}",
                                (ip,),
                            )
                            count = max(count, cur.fetchone()["cnt"])
                        if rl_mode in ("username", "both"):
                            cur.execute(
                                f"SELECT COUNT(*) as cnt FROM login_attempts "
                                f"WHERE username=%s AND attempted_at >= {window}",
                                (username,),
                            )
                            count = max(count, cur.fetchone()["cnt"])
                        if count >= max_att:
                            locked = True
                            remaining = lockout_min if lockout_min > 0 else 999

                    mfa_enrolled = False
                    if row:
                        cur.execute(
                            "SELECT (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) + "
                            "(SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) as cnt",
                            (row["id"], row["id"]),
                        )
                        mfa_enrolled = cur.fetchone()["cnt"] > 0

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
            # Upgrade legacy SHA-256 / pbkdf2 / off-param scrypt to the current
            # scheme. The expensive part (hashing) is already done above via
            # verify_password + here; the write is a single UPDATE, done
            # synchronously and *conditionally* on the hash we just verified
            # still being the stored one — so a password change that lands
            # between here and the write is never clobbered by a stale rehash
            # (the old fire-and-forget thread did an unconditional UPDATE).
            old_hash = row["password"]
            if not old_hash.startswith("scrypt:") or __user.needs_rehash(old_hash):
                try:
                    with __db.jen_db() as db2:
                        with db2.cursor() as cur:
                            cur.execute(
                                "UPDATE users SET password=%s WHERE id=%s AND password=%s",
                                (__user.hash_password(password), row["id"], old_hash),
                            )
                        db2.commit()
                except Exception as e:
                    logger.error(f"Password rehash error: {e}")

            # Clear rate limit attempts
            __auth.clear_login_attempts(ip, username)

            user = User(
                row["id"],
                row["username"],
                row["role"],
                row["session_timeout"],
                row.get("subnet_access"),
                row.get("must_change_password"),
            )

            # MFA check
            mfa_mode = settings.get("mfa_mode", "off")
            needs_mfa = mfa_mode == "required_all" or (
                mfa_mode == "required_admins" and row["role"] in ("admin", "superadmin")
            )
            if mfa_enrolled or needs_mfa:
                if mfa_enrolled and not __mfa.is_trusted_device(row["id"], request):
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    _next = request.args.get("next", "")
                    if _next and (_next.startswith("//") or "://" in _next or not _next.startswith("/")):
                        _next = ""
                    session["mfa_next"] = _next or url_for("dashboard.dashboard")
                    return redirect(url_for("mfa_routes.mfa_verify"))
                elif needs_mfa and not mfa_enrolled:
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    login_user(user)
                    session["last_active"] = datetime.now(timezone.utc).isoformat()
                    session["_user_cache"] = {
                        "id": user.id,
                        "username": user.username,
                        "role": user.role,
                        "session_timeout": user.session_timeout,
                        "subnet_access": row.get("subnet_access"),
                        "token_version": row.get("token_version", 0),
                        "must_change_password": bool(row.get("must_change_password")),
                    }
                    flash("MFA is required for your account. Please enroll now.", "warning")
                    return redirect(url_for("mfa_routes.mfa_enroll"))

            login_user(user)
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            session["_user_cache"] = {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "session_timeout": user.session_timeout,
                "subnet_access": row.get("subnet_access"),
                "token_version": row.get("token_version", 0),
                "must_change_password": bool(row.get("must_change_password")),
            }
            __user.audit("LOGIN", "auth", f"User {username} logged in from {ip}")
            return redirect(url_for("dashboard.dashboard"))

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
    return redirect(url_for("auth.login"))


@bp.route("/force-password-change", methods=["GET", "POST"])
@login_required
def force_password_change():
    """
    v5.2.7 security fix — the destination the _enforce_password_change()
    before_request hook (jen/__init__.py) sends every request to while
    current_user.must_change_password is set. See the
    users.must_change_password migration's docstring
    (jen/models/migrations.py) for the full rationale: a fresh install's
    default admin/admin credential, and any admin-set initial password
    for a new user, previously had nothing enforcing it ever actually
    gets changed.

    Deliberately does NOT re-verify the current password the way
    users.py's general change_password() route does for an already-
    logged-in user changing their password voluntarily — reaching this
    route at all already proves the user knows the current password
    (they just logged in with it), so asking again has no security
    benefit, only friction.
    """
    if request.method == "GET":
        return render_template("force_password_change.html")

    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return render_template("force_password_change.html")
    # This check must run BEFORE the length check below — "admin" is
    # only 5 characters, so the length check would always catch it
    # first and this one would never fire for its actual intended
    # purpose. Checking the specific, security-relevant case ahead of
    # the generic one ensures the person actually sees why their choice
    # was rejected, not a generic length complaint that happens to
    # also be true.
    if new_pw.lower() == "admin" or new_pw == current_user.username:
        flash("Please choose a password other than the default or your own username.", "error")
        return render_template("force_password_change.html")
    if len(new_pw) < 8:
        flash("New password must be at least 8 characters.", "error")
        return render_template("force_password_change.html")

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password=%s, must_change_password=0 WHERE id=%s",
                    (__user.hash_password(new_pw), current_user.id),
                )
            db.commit()
        session.pop("_user_cache", None)
        __user.audit(
            "CHANGE_PASSWORD",
            current_user.username,
            "Password changed (forced — first login or admin-assigned password)",
        )
        flash("Password changed successfully.", "success")
        return redirect(url_for("dashboard.dashboard"))
    except Exception as e:
        logger.error(f"Forced password change error: {e}")
        flash("Error changing password. Please try again.", "error")
        return render_template("force_password_change.html")


# ─────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────
