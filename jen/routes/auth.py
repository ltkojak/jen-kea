"""
jen/routes/auth.py
───────────────────
Authentication routes: login, logout.
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, logout_user

import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.mfa as __mfa
import jen.services.oidc as __oidc

logger = logging.getLogger(__name__)
bp = Blueprint("auth", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _delete_initial_admin_password_file():
    import os

    from jen import extensions

    path = os.path.join(extensions.CONTENT_DIR, "initial-admin-password")
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as e:
        logger.warning(f"could not remove {path}: {e}")


def _render_login(prefill_username=""):
    """v5.25.0 (Q21) — every login.html render needs the same SSO
    context: whether to show the button (enabled AND actually
    registered — a config typo shouldn't crash the login page), and
    whether the local form shows at all (?local=1 is always the escape
    hatch, even when the operator has hidden it by default)."""
    from jen import extensions

    return render_template(
        "login.html",
        jen_version=_JEN_VERSION(),
        prefill_username=prefill_username,
        oidc_enabled=extensions.OIDC_ENABLED and __oidc.oidc_client() is not None,
        oidc_button_label=extensions.OIDC_BUTTON_LABEL,
        show_local_form=extensions.OIDC_LOCAL_LOGIN or request.args.get("local") == "1",
    )


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        ip = request.remote_addr

        if not username or not password:
            flash("Username and password are required.", "error")
            return _render_login(prefill_username=username)

        # Single DB connection for the entire login flow
        try:
            with __db.jen_db() as db, db.cursor() as cur:
                # User lookup
                cur.execute(
                    "SELECT id, username, role, session_timeout, password, subnet_access, token_version, "
                    "must_change_password, auth_provider FROM users WHERE username=%s",
                    (username,),
                )
                row = cur.fetchone()

                mfa_mode = __user.get_global_setting("mfa_mode", "off")

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
            return _render_login(prefill_username=username)

        # v5.8.4 — one implementation of the lockout rule. This route used
        # to carry its own inline copy of jen.services.auth.is_locked_out()
        # that reported the *whole* window as "minutes remaining" rather
        # than the time left from the oldest attempt (the same bug 5.8.0
        # fixed on the MFA side), leaving the shared function dead code.
        locked, remaining = __auth.is_locked_out(ip, username)

        if locked:
            if remaining >= 999:
                flash("Account is locked. Contact an administrator.", "error")
            else:
                flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
            return _render_login(prefill_username=username)

        # v5.25.0 (Q21) — an OIDC-linked account has no usable local
        # password (a discarded random one — see oidc.find_or_create_user).
        # Refuse BEFORE the password check, with the exact same generic
        # message a wrong password gets: telling a client "this account is
        # SSO-only" would let /login be used to enumerate which accounts
        # are locally-managed and which aren't.
        if row and row.get("auth_provider") == "oidc":
            __auth.record_login_attempt(ip, username)
            __user.audit("oidc_denied", username, "local login attempted for an OIDC-linked account")
            flash("Invalid username or password.", "error")
            return _render_login(prefill_username=username)

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

            # MFA check
            needs_mfa = mfa_mode == "required_all" or (
                mfa_mode == "required_admins" and row["role"] in ("admin", "superadmin")
            )
            if mfa_enrolled or needs_mfa:
                _next = request.args.get("next", "")
                if _next and (_next.startswith("//") or "://" in _next or not _next.startswith("/")):
                    _next = ""
                if mfa_enrolled and not __mfa.is_trusted_device(row["id"], request):
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    session.pop("mfa_pending_enroll", None)
                    session["mfa_next"] = _next or url_for("dashboard.dashboard")
                    session["auth_at"] = _now_iso()  # password done; "pending" counts as fresh
                    return redirect(url_for("mfa_routes.mfa_verify"))
                elif needs_mfa and not mfa_enrolled:
                    # Password is verified, but MFA is mandatory and the
                    # user hasn't set it up. Hold them in a pending state —
                    # NOT a Flask-Login session — so nothing else in the app
                    # is reachable until they enroll and verify a factor.
                    # (Pre-5.8.0 this called login_user() here, leaving a
                    # fully-authenticated session one redirect away from the
                    # enrollment page.)
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    session["mfa_pending_enroll"] = True
                    session["mfa_next"] = _next or url_for("dashboard.dashboard")
                    session["auth_at"] = _now_iso()  # password done; "pending" counts as fresh
                    flash("MFA is required for your account — set up an authenticator to finish signing in.", "warning")
                    return redirect(url_for("mfa_routes.mfa_enroll"))

            # v5.17.0 (Q6 6B) — drop everything the pre-auth session carried
            # (Flask sessions are signed cookies; "rotate" == clear + rebuild).
            # v5.25.0 (Q21) — the clear/login_user/session-keys/audit block
            # moved to oidc.establish_session() so the OIDC callback can
            # share it exactly, rather than keeping its own copy in sync.
            __oidc.establish_session(row, f"User {username} logged in from {ip}")
            return redirect(url_for("dashboard.dashboard"))

        # Failed login — record attempt (async, don't block response)
        __auth.record_login_attempt(ip, username)
        flash("Invalid username or password.", "error")
        return _render_login(prefill_username=username)

    return _render_login()


@bp.route("/login/oidc")
def login_oidc():
    """v5.25.0 (Q21) — kick off the OIDC authorization redirect. 503-style
    flash (not a raw error) when SSO isn't actually enabled/registered —
    a stale bookmark or a race with a config change must not 500."""
    client = __oidc.oidc_client()
    if client is None:
        flash("Single sign-on is not configured.", "error")
        return redirect(url_for("auth.login"))

    from jen import extensions

    _next = request.args.get("next", "")
    if _next and (_next.startswith("//") or "://" in _next or not _next.startswith("/")):
        _next = ""
    session["oidc_next"] = _next

    redirect_uri = extensions.OIDC_REDIRECT_URI or url_for("auth.login_oidc_callback", _external=True)
    return client.authorize_redirect(redirect_uri)


@bp.route("/login/oidc/callback")
def login_oidc_callback():
    """The IdP redirects back here with the authorization code. Locked
    out by IP/the shared "oidc" bucket BEFORE the token exchange — an
    attacker hammering the callback shouldn't get unlimited attempts
    just because there's no password to check here."""
    from jen import extensions

    client = __oidc.oidc_client()
    if client is None:
        flash("Single sign-on is not configured.", "error")
        return redirect(url_for("auth.login"))

    ip = request.remote_addr
    locked, remaining = __auth.is_locked_out(ip, "oidc")
    if locked:
        if remaining >= 999:
            flash("Sign-in is locked. Contact an administrator.", "error")
        else:
            flash(f"Too many failed sign-in attempts. Try again in {remaining} minute(s).", "error")
        return redirect(url_for("auth.login"))

    try:
        token = client.authorize_access_token()
    except Exception as e:
        logger.warning(f"OIDC token exchange failed: {e}")
        __auth.record_login_attempt(ip, "oidc")
        flash("Sign-in with SSO failed. Please try again.", "error")
        return redirect(url_for("auth.login"))

    claims = token.get("userinfo") or {}
    if extensions.OIDC_USERNAME_CLAIM not in claims and extensions.OIDC_ROLE_CLAIM not in claims:
        try:
            claims = client.userinfo(token=token)
        except Exception as e:
            logger.warning(f"OIDC userinfo fetch failed: {e}")

    row, reason = __oidc.find_or_create_user(claims)
    if row is None:
        __auth.record_login_attempt(ip, "oidc")
        messages = {
            "no_role": "Your account has no role mapped — contact an administrator.",
            "username_collision": "An account with that username already exists — ask an admin to rename it or link it.",
            "auto_create_disabled": "Your account isn't provisioned yet — contact an administrator.",
            "no_username": "Could not determine a username from your identity provider.",
            "no_subject": "Your identity provider did not return a subject identifier.",
        }
        flash(messages.get(reason, "Sign-in with SSO failed."), "error")
        return redirect(url_for("auth.login"))

    # v5.25.0 fixup — must read (and pop) oidc_next BEFORE
    # establish_session(), which calls session.clear(): reading it after
    # would always see it already gone, silently discarding `next` for
    # every real login. Same reason local login() computes the MFA
    # `_next` value before it ever gets to that block.
    next_url = session.pop("oidc_next", "") or url_for("dashboard.dashboard")

    __auth.clear_login_attempts(ip, "oidc")
    __oidc.establish_session(row, f"User {row['username']} logged in via SSO from {ip}")
    return redirect(next_url)


@bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    # v5.17.0 (Q6 6C) — GET confirms, POST acts. A stray link / prefetch /
    # <img src> can no longer sign a user out.
    if request.method == "GET":
        return render_template("logout_confirm.html")
    __user.audit("LOGOUT", "auth", f"User {current_user.username} logged out")
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/auth/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    """v5.17.0 (Q6 6A) — password (and MFA, if enrolled) confirmation for
    a route guarded by `recent_auth_required`. On success it stamps a
    fresh `session["auth_at"]` and returns to `session["reauth_next"]`."""
    next_url = session.get("reauth_next") or url_for("mfa_routes.mfa_enroll")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = url_for("mfa_routes.mfa_enroll")
    has_mfa = __mfa.user_has_mfa(current_user.id)

    if request.method == "GET":
        return render_template("reauth.html", has_mfa=has_mfa, next_url=next_url)

    ip = request.remote_addr
    username = current_user.username

    locked, remaining = __auth.is_locked_out(ip, username)
    if locked:
        if remaining >= 999:
            flash("Account is locked. Contact an administrator.", "error")
        else:
            flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
        return render_template("reauth.html", has_mfa=has_mfa, next_url=next_url)

    password = request.form.get("password", "")
    code = request.form.get("code", "").strip().replace(" ", "")

    ok = False
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE id=%s", (current_user.id,))
            row = cur.fetchone()
        if row and __user.verify_password(row["password"], password):
            if has_mfa:
                ok = (len(code) >= 16 and __mfa.verify_backup_code(current_user.id, code)) or __mfa.verify_totp(
                    current_user.id, code
                )
            else:
                ok = True
    except Exception as e:
        logger.error(f"reauth error for {username}: {e}")

    if not ok:
        __auth.record_login_attempt(ip, username)
        flash("Confirmation failed — check your password" + (" and code." if has_mfa else "."), "error")
        return render_template("reauth.html", has_mfa=has_mfa, next_url=next_url)

    __auth.clear_login_attempts(ip, username)
    session["auth_at"] = _now_iso()
    session.pop("reauth_next", None)
    __user.audit("REAUTH", "auth", f"{username} re-confirmed identity")
    return redirect(next_url)


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
        # v5.17.0 (Q6 6G) — the generated bootstrap credential is now
        # useless; remove the file that held it.
        _delete_initial_admin_password_file()
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
