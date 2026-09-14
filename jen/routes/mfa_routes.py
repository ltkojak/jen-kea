"""
jen/routes/mfa_routes.py
─────────────────────────
MFA enrollment and verification routes.
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.crypto as __crypto
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.oidc as __oidc
import jen.services.passkeys as __passkeys
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("mfa_routes", __name__)


def _load_user(user_id):
    """Load a user by ID — thin wrapper around the login_manager user loader."""
    from jen.models.db import jen_db
    from jen.models.user import User

    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
        if row:
            return User(row["id"], row["username"], row["role"], row["session_timeout"])
    except Exception as e:
        logger.error(f"_load_user error: {e}")
    return None


def _pending_enroll_user():
    """The user in the middle of forced MFA enrollment: password verified
    at login, `mfa_pending_enroll` flagged in the session, but NOT a
    Flask-Login session yet (see jen/routes/auth.py). Returns a User or
    None. Only /mfa/enroll and /mfa/verify honor this state — every
    @login_required route still turns them away until enrollment finishes."""
    if not session.get("mfa_pending_enroll"):
        return None
    uid = session.get("mfa_pending_user_id")
    return _load_user(uid) if uid else None


def _complete_pending_login(user):
    """Turn a finished forced-enrollment into a real session."""
    # v5.17.0 (Q6 6B) — rotate the session; clear() also drops the
    # mfa_pending_* keys the old pop loop removed.
    session.clear()
    login_user(user)
    now = datetime.now(timezone.utc).isoformat()
    session["last_active"] = now
    session["auth_at"] = now  # password + first factor just verified
    __user.audit("LOGIN", "auth", f"User {user.username} logged in (after MFA enrollment)")


def _remaining_mfa_factor_count(user_id, excluding_method_id=None, excluding_cred_id=None):
    """Enabled TOTP methods + passkeys the user would still have if the
    given TOTP method (or, v5.31.0, the given passkey) were removed.
    Returns None if it can't be determined — the caller treats that as
    "0", i.e. fail CLOSED: a transient DB error must not be a way to
    drop past the last factor when MFA is mandatory."""
    from jen.models.db import jen_db

    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c FROM mfa_methods WHERE user_id=%s AND enabled=1 AND id <> %s",
                (user_id, excluding_method_id or 0),
            )
            totp = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id=%s AND id <> %s",
                (user_id, excluding_cred_id or 0),
            )
            passkeys = cur.fetchone()["c"]
        return totp + passkeys
    except Exception as e:
        logger.error(f"_remaining_mfa_factor_count error for user {user_id}: {e}")
        return None


def _enrolling_user():
    """(user, is_forced) for the MFA-management surface: a logged-in user,
    or one held in forced enrolment (password verified, no session yet).
    (None, False) for anyone else."""
    if current_user.is_authenticated:
        return current_user, False
    pending = _pending_enroll_user()
    return (pending, True) if pending else (None, False)


def _json_error(message, code):
    return jsonify({"ok": False, "error": message}), code


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


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
            return redirect(url_for("dashboard.dashboard"))
        return redirect(url_for("auth.login"))
    if session.get("mfa_pending_enroll"):
        # This user has no factor yet — there's nothing to verify.
        return redirect(url_for("mfa_routes.mfa_enroll"))
    locked, remaining = __auth.is_mfa_locked_out(pending_id)
    if locked:
        flash(f"Too many failed codes. Try again in {remaining} minute(s).", "error")
        has_totp = __mfa.user_has_mfa(pending_id) if pending_id else False
        return render_template("mfa_challenge.html", username=pending_username, has_totp=has_totp)
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        # Try a backup code first — verify_backup_code() canonicalises it
        # (with/without dash, any case) to the stored XXXXXXXX-XXXXXXXX form.
        if len(code) >= 16 and __mfa.verify_backup_code(pending_id, code):
            user = _load_user(pending_id)
            if user:
                __auth.clear_mfa_attempts(pending_id)
                remember = request.form.get("remember_device")
                next_url = session.pop("mfa_next", url_for("dashboard.dashboard"))
                # v5.17.0 (Q6 6B) — rotate the session now that both factors
                # are verified; read mfa_next above first (clear() drops it).
                session.clear()
                login_user(user)
                _now = datetime.now(timezone.utc).isoformat()
                session["last_active"] = _now
                session["auth_at"] = _now
                if remember:
                    days_raw = request.form.get("remember_days", "30")
                    # Read the header directly: werkzeug 2.1+ UserAgent.__bool__ keys off
                    # the parsed .browser field, which is always None without a UA
                    # parser plugged in — so the object is ALWAYS falsy. (v4.3.3)
                    ua = request.headers.get("User-Agent", "")
                    if not ua:
                        logger.warning(
                            f"Trust creation from {request.remote_addr} with no User-Agent header; "
                            f"headers present: {sorted(k for k, _ in request.headers)}"
                        )
                    device_name = __fp.describe_client_device(request.remote_addr, ua)
                    token = __mfa.create_trusted_device_token(
                        pending_id, days_raw, device_name, ip_address=request.remote_addr, user_agent=ua
                    )
                    resp = redirect(next_url)
                    # v5.2.12 security fix — this cookie is a long-lived
                    # MFA bypass token (up to 10 years for "forever").
                    # It was missing `secure`, unlike the main session
                    # cookie (SESSION_COOKIE_SECURE, set conditionally on
                    # SSL in jen/__init__.py) — meaning a browser could
                    # send this specific token over plain HTTP even on an
                    # instance with HTTPS configured, before any
                    # HTTP→HTTPS redirect takes effect. Matches the same
                    # ssl_configured() condition the session cookie uses.
                    if days_raw == "forever":
                        resp.set_cookie(
                            "jen_trusted",
                            token,
                            max_age=10 * 365 * 86400,
                            httponly=True,
                            samesite="Lax",
                            secure=__config.ssl_configured(),
                        )
                    else:
                        days = int(days_raw)
                        resp.set_cookie(
                            "jen_trusted",
                            token,
                            max_age=days * 86400,
                            httponly=True,
                            samesite="Lax",
                            secure=__config.ssl_configured(),
                        )
                    __user.audit("MFA_BACKUP_CODE", "auth", f"{pending_username} trusted={days_raw}")
                    return resp
                __user.audit("MFA_BACKUP_CODE", "auth", pending_username)
                return redirect(next_url)
        # Try TOTP
        if __mfa.verify_totp(pending_id, code):
            user = _load_user(pending_id)
            if user:
                __auth.clear_mfa_attempts(pending_id)
                remember = request.form.get("remember_device")
                next_url = session.pop("mfa_next", url_for("dashboard.dashboard"))
                # v5.17.0 (Q6 6B) — rotate the session now that both factors
                # are verified; read mfa_next above first (clear() drops it).
                session.clear()
                login_user(user)
                _now = datetime.now(timezone.utc).isoformat()
                session["last_active"] = _now
                session["auth_at"] = _now
                if remember:
                    days_raw = request.form.get("remember_days", "30")
                    # Read the header directly: werkzeug 2.1+ UserAgent.__bool__ keys off
                    # the parsed .browser field, which is always None without a UA
                    # parser plugged in — so the object is ALWAYS falsy. (v4.3.3)
                    ua = request.headers.get("User-Agent", "")
                    if not ua:
                        logger.warning(
                            f"Trust creation from {request.remote_addr} with no User-Agent header; "
                            f"headers present: {sorted(k for k, _ in request.headers)}"
                        )
                    device_name = __fp.describe_client_device(request.remote_addr, ua)
                    token = __mfa.create_trusted_device_token(
                        pending_id, days_raw, device_name, ip_address=request.remote_addr, user_agent=ua
                    )
                    resp = redirect(next_url)
                    # v5.2.12 security fix — this cookie is a long-lived
                    # MFA bypass token (up to 10 years for "forever").
                    # It was missing `secure`, unlike the main session
                    # cookie (SESSION_COOKIE_SECURE, set conditionally on
                    # SSL in jen/__init__.py) — meaning a browser could
                    # send this specific token over plain HTTP even on an
                    # instance with HTTPS configured, before any
                    # HTTP→HTTPS redirect takes effect. Matches the same
                    # ssl_configured() condition the session cookie uses.
                    if days_raw == "forever":
                        resp.set_cookie(
                            "jen_trusted",
                            token,
                            max_age=10 * 365 * 86400,
                            httponly=True,
                            samesite="Lax",
                            secure=__config.ssl_configured(),
                        )
                    else:
                        days = int(days_raw)
                        resp.set_cookie(
                            "jen_trusted",
                            token,
                            max_age=days * 86400,
                            httponly=True,
                            samesite="Lax",
                            secure=__config.ssl_configured(),
                        )
                    __user.audit("MFA_VERIFY", "auth", f"{pending_username} trusted={days_raw}")
                    return resp
                __user.audit("MFA_VERIFY", "auth", pending_username)
                return redirect(next_url)
        __auth.record_mfa_attempt(pending_id)
        flash("Invalid code. Please try again.", "error")
        __user.audit("MFA_FAILED", "auth", pending_username)
    has_totp = __mfa.user_has_mfa(pending_id) if pending_id else False
    return render_template("mfa_challenge.html", username=pending_username, has_totp=has_totp)


@bp.route("/mfa/enroll", methods=["GET", "POST"])
@_recent_auth_required()
def mfa_enroll():
    import base64
    import io as _io

    import pyotp
    import qrcode

    # Either a logged-in user managing their MFA, or a user held in the
    # forced-enrollment pending state (password verified, not yet a
    # session). No third door: anyone else goes back to login.
    is_forced = not current_user.is_authenticated
    enrolling = _pending_enroll_user() if is_forced else current_user
    if enrolling is None:
        return redirect(url_for("auth.login"))
    uid, uname = enrolling.id, enrolling.username

    # v5.25.0 (Q21) — an OIDC-linked account never reaches this page
    # forced (find_or_create_user/establish_session never set the
    # mfa_pending_* keys), but an already-authenticated one can still
    # click through from "My MFA Settings" — the IdP owns MFA for them.
    if not is_forced and __oidc.is_oidc_user(uid):
        return render_template("mfa_enroll.html", oidc_managed=True)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "enroll":
            secret = request.form.get("secret", "").strip()
            code = request.form.get("code", "").strip()
            device_name = request.form.get("device_name", "Authenticator").strip()[:100] or "Authenticator"
            if not secret or not code:
                flash("Missing secret or code.", "error")
                return redirect(url_for("mfa_routes.mfa_enroll"))
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                flash("Invalid verification code. Please try again.", "error")
                return redirect(url_for("mfa_routes.mfa_enroll"))
            try:
                # v5.4.0 — the code was already verified above against the
                # plaintext `secret` from the form; it is stored encrypted
                # at rest (jen/services/crypto.py). verify_totp() decrypts
                # on read.
                stored_secret = __crypto.encrypt_secret(secret)
                with __db.jen_db() as db:
                    with db.cursor() as cur:
                        cur.execute(
                            """INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled)
                                       VALUES (%s, 'totp', %s, %s, 1)""",
                            (uid, stored_secret, device_name),
                        )
                    db.commit()
                    # Generate backup codes
                    codes = __mfa.generate_backup_codes(uid)
                __user.audit("MFA_ENROLL", "auth", f"{uname} device={device_name}")
                if is_forced:
                    # First factor is now in place — promote the pending
                    # state to a real session before showing recovery codes.
                    _complete_pending_login(enrolling)
                flash("Authenticator enrolled successfully!", "success")
                return render_template("mfa_backup_codes.html", codes=codes)
            except Exception as e:
                logger.error(f"MFA enrollment error for {uname}: {e}")
                flash("Enrollment error. Check server logs for details.", "error")
                return redirect(url_for("mfa_routes.mfa_enroll"))
        # Everything past here manages an existing setup — only for a
        # user who is already fully authenticated.
        if is_forced:
            flash("Finish setting up your authenticator first.", "error")
            return redirect(url_for("mfa_routes.mfa_enroll"))
        if action == "remove_passkey":
            # v5.31.0 (Q31) — same last-factor rule as TOTP below.
            cred_id = request.form.get("cred_id", "")
            cred_id = int(cred_id) if cred_id.isdigit() else 0
            if __mfa.user_needs_mfa(enrolling) and not _remaining_mfa_factor_count(uid, excluding_cred_id=cred_id):
                flash("MFA is required for your account — add another factor before removing this passkey.", "error")
                return redirect(url_for("mfa_routes.mfa_enroll"))
            try:
                if __passkeys.remove(uid, cred_id):
                    __user.audit("PASSKEY_REMOVE", "auth", f"{uname} cred_id={cred_id}")
                    flash("Passkey removed.", "success")
                else:
                    flash("That passkey was not found.", "error")
            except Exception as e:
                logger.error(f"Passkey removal error for {uname}: {e}")
                flash("Error removing passkey. Check server logs for details.", "error")
            return redirect(url_for("mfa_routes.mfa_enroll"))
        if action in ("remove", "remove_totp"):
            method_id = request.form.get("method_id") or request.form.get("mfa_id")
            # Don't let the last factor go while MFA is mandatory for this
            # user: it would lock the policy out on the next login, and it
            # hands a stolen session an easy way to switch MFA off entirely.
            # `None` from the count helper = couldn't tell → treat as 0.
            if __mfa.user_needs_mfa(enrolling) and not _remaining_mfa_factor_count(uid, method_id):
                flash("MFA is required for your account — add another authenticator before removing this one.", "error")
                return redirect(url_for("mfa_routes.mfa_enroll"))
            try:
                with __db.jen_db() as db:
                    with db.cursor() as cur:
                        cur.execute("DELETE FROM mfa_methods WHERE id=%s AND user_id=%s", (method_id, uid))
                    db.commit()
                __user.audit("MFA_REMOVE", "auth", f"{uname} method_id={method_id}")
                flash("Authenticator removed.", "success")
            except Exception as e:
                logger.error(f"MFA removal error for {uname}: {e}")
                flash("Error removing authenticator. Check server logs for details.", "error")
            return redirect(url_for("mfa_routes.mfa_enroll"))
        elif action == "new_backup_codes":
            codes = __mfa.generate_backup_codes(uid)
            __user.audit("MFA_NEW_BACKUP", "auth", uname)
            return render_template("mfa_backup_codes.html", codes=codes)
    # GET - show enrollment page
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=uname, issuer_name="Jen DHCP")
    qr = qrcode.make(uri)
    buf = _io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT id, name, created_at, last_used FROM mfa_methods WHERE user_id=%s AND method_type='totp' AND enabled=1",
                (uid,),
            )
            methods = cur.fetchall()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0", (uid,))
            backup_count = cur.fetchone()["cnt"]
    except Exception as e:
        logger.error(f"mfa_enroll fetch error: {e}")
        methods = []
        backup_count = 0
    try:
        passkeys = __passkeys.list_for_user(uid)
    except Exception as e:
        logger.error(f"mfa_enroll passkey fetch error: {e}")
        passkeys = []
    return render_template(
        "mfa_enroll.html",
        secret=secret,
        qr_b64=qr_b64,
        totp_methods=methods,
        passkeys=passkeys,
        backup_count=backup_count,
        is_forced=is_forced,
    )


# ── Passkeys (v5.31.0, Q31) — enrolment ───────────────────────────────────────
#
# Two JSON halves around the browser's navigator.credentials.create():
# /begin hands back the options (and parks the challenge in the session),
# /finish verifies the attestation and stores the public key. Both honour
# the same two doors as /mfa/enroll — a logged-in user, or one held in
# forced enrolment — and the same recent-auth step-up. CSRF: the page
# sends the token in X-CSRFToken (jen/services/csrf.py reads it there).


@bp.route("/mfa/passkey/register/begin", methods=["POST"])
@_recent_auth_required()
def passkey_register_begin():
    enrolling, _forced = _enrolling_user()
    if enrolling is None:
        return _json_error("not signed in", 401)
    if __oidc.is_oidc_user(enrolling.id):
        return _json_error("MFA for this account is managed by your identity provider", 403)
    try:
        options_json, state = __passkeys.begin_registration(enrolling.id, enrolling.username, request)
    except Exception as e:
        logger.error(f"passkey register begin failed for {enrolling.username}: {e}")
        return _json_error("could not start passkey enrolment — see the Jen log", 500)
    session["passkey_reg"] = state
    return jsonify({"ok": True, "options": options_json})


@bp.route("/mfa/passkey/register/finish", methods=["POST"])
@_recent_auth_required()
def passkey_register_finish():
    enrolling, is_forced = _enrolling_user()
    if enrolling is None:
        return _json_error("not signed in", 401)
    if __oidc.is_oidc_user(enrolling.id):
        return _json_error("MFA for this account is managed by your identity provider", 403)
    body = request.get_json(silent=True) or {}
    # Single-use: the challenge leaves the session before verification.
    state = session.pop("passkey_reg", None)
    try:
        out = __passkeys.finish_registration(
            enrolling.id, body.get("response"), state, request, name=str(body.get("name") or "")
        )
    except __passkeys.PasskeyError as e:
        return _json_error(str(e), 400)
    except Exception as e:
        logger.error(f"passkey register finish failed for {enrolling.username}: {e}")
        return _json_error("could not save the passkey — see the Jen log", 500)
    __user.audit("PASSKEY_ENROLL", "auth", f"{enrolling.username} name={out['name']}")
    codes = None
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM mfa_backup_codes WHERE user_id=%s AND used=0", (enrolling.id,))
            has_backup = cur.fetchone()["c"] > 0
        if not has_backup:
            # First factor (or the codes are all spent): issue recovery
            # codes like TOTP enrolment does. An existing unused set is
            # kept — a second factor doesn't invalidate it.
            codes = __mfa.generate_backup_codes(enrolling.id)
    except Exception as e:
        logger.error(f"backup code check after passkey enrolment failed for {enrolling.username}: {e}")
    if is_forced:
        # First factor is in place — promote the pending state to a real
        # session (this clears the session, so stash the codes after).
        _complete_pending_login(enrolling)
    if codes:
        session["passkey_backup_codes"] = codes
    return jsonify({"ok": True, "name": out["name"], "next": url_for("mfa_routes.passkey_enrolled")})


@bp.route("/mfa/passkey/enrolled")
@login_required
def passkey_enrolled():
    """Where the page lands after a successful /finish: shows freshly
    issued backup codes once, else back to the MFA page."""
    codes = session.pop("passkey_backup_codes", None)
    flash("Passkey enrolled successfully!", "success")
    if codes:
        return render_template("mfa_backup_codes.html", codes=codes)
    return redirect(url_for("mfa_routes.mfa_enroll"))


@bp.route("/mfa/regenerate-backup-codes", methods=["POST"])
@login_required
@_recent_auth_required()
def regenerate_backup_codes():
    codes = __mfa.generate_backup_codes(current_user.id)
    __user.audit("MFA_NEW_BACKUP", "auth", current_user.username)
    return render_template("mfa_backup_codes.html", codes=codes)


@bp.route("/mfa/trusted-devices")
@login_required
@_recent_auth_required()
def mfa_trusted_devices():
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                """SELECT id, device_name, created_at, expires_at, last_used,
                                      ip_address, user_agent
                               FROM mfa_trusted_devices WHERE user_id=%s
                               ORDER BY created_at DESC""",
                (current_user.id,),
            )
            devices = cur.fetchall()
        # Render-time fallback (v4.3.1): if a stored name still says Unknown
        # but we have a raw UA on file, show the parsed UA instead.
        for d in devices:
            name = d.get("device_name") or ""
            if ("unknown" in name.lower() or not name.strip()) and d.get("user_agent"):
                d["device_name"] = __fp.describe_client_device(d.get("ip_address") or "", d["user_agent"])
    except Exception:
        devices = []
    return render_template("mfa_trusted_devices.html", devices=devices)


@bp.route("/mfa/trusted-devices/remove/<int:device_id>", methods=["POST"])
@bp.route("/mfa/revoke-device/<int:device_id>", methods=["POST"])  # legacy alias
@login_required
@_recent_auth_required()
def remove_trusted_device(device_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_trusted_devices WHERE id=%s AND user_id=%s", (device_id, current_user.id))
            db.commit()
        flash("Trusted device removed.", "success")
        __user.audit("REMOVE_TRUSTED_DEVICE", "auth", f"device_id={device_id}")
    except Exception as e:
        logger.error(f"Error removing trusted device {device_id}: {e}")
        flash("Error removing trusted device. Check server logs for details.", "error")
    return redirect(url_for("mfa_routes.mfa_trusted_devices"))


@bp.route("/mfa/revoke-all-devices", methods=["POST"])
@login_required
@_recent_auth_required()
def revoke_all_trusted_devices():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (current_user.id,))
                deleted = cur.rowcount
            db.commit()
        flash(f"All {deleted} trusted device(s) revoked.", "success")
        __user.audit("REVOKE_ALL_TRUSTED_DEVICES", "auth", current_user.username)
    except Exception as e:
        logger.error(f"Error revoking all trusted devices for {current_user.username}: {e}")
        flash("Error revoking trusted devices. Check server logs for details.", "error")
    return redirect(url_for("mfa_routes.mfa_trusted_devices"))


@bp.route("/mfa/admin-reset/<int:user_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required()
def admin_reset_mfa(user_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM webauthn_credentials WHERE user_id=%s", (user_id,))  # v5.31.0
                cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (user_id,))
            db.commit()
        flash(f"MFA reset for user ID {user_id}.", "success")
        __user.audit("ADMIN_RESET_MFA", str(user_id), f"Reset by {current_user.username}")
    except Exception as e:
        logger.error(f"Error resetting MFA for user {user_id}: {e}")
        flash("Error resetting MFA. Check server logs for details.", "error")
    return redirect(url_for("users.users"))


# ─────────────────────────────────────────
# User Profile
# ─────────────────────────────────────────
