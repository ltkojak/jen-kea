"""
jen/routes/settings/security.py
─────────────────────────────
Session timeout, login rate limiting, SSL certificate upload.
"""

import logging
import os

from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.oidc as __oidc
import jen.services.runtime as __runtime
import jen.services.session_timeout as __session_timeout
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required
from jen.services.forms import flash_field
from jen.services.text import is_whole

logger = logging.getLogger(__name__)


def _session_looser(enabled: str, minutes: int) -> bool:
    """Would storing (`enabled`, `minutes`) make the idle timeout LESS strict than the one applied now? Off and 0 (never) are the least strict, equal to each other; otherwise fewer minutes is stricter."""

    def rank(on: bool, m: int) -> int:
        return 0 if not on or m == 0 else __session_timeout.MAX_MINUTES + 1 - m  # 1440 min -> 1, 1 min -> 1440

    now_on = __user.get_global_setting("session_timeout_enabled", "true") != "false"
    return rank(enabled == "true", minutes) < rank(now_on, __session_timeout.global_minutes())


#: (Q227, AM3) the three sentences of the lockout controls, named so a test and the page read the same words
PERMANENT_IS_A_SUPERADMINS = "Only a superadmin can set a lockout that lasts until it is cleared (0 minutes)."
CLEARED_SENTENCE = "Cleared {attempts} failed login attempt(s) and ended {lockouts} permanent lockout(s)."
OIDC_ISSUER_CHANGED = "The issuer changed - enter the client secret again."
OIDC_CLIENT_CHANGED = "The client ID changed - enter the client secret again."
#: (Q229) the refusal of an issuer that is not a plain address
OIDC_ISSUER_SHAPE = (
    "The issuer must be an https:// URL with a host and nothing after its path: no query and no fragment "
    "(http:// is only allowed for a local 127.0.0.1/localhost test IdP)."
)
OIDC_SAVED = "Single sign-on settings saved. A change to the issuer, the client ID or the client secret takes effect when Jen restarts."


def _rate_limit_looser(mode: str, max_attempts: int, lockout_minutes: int) -> bool:
    """Would storing these make login rate limiting LESS strict than it is now? `off` (or 0 attempts) is the least strict; more attempts allowed, or a shorter lockout (0 is until cleared, the
    longest), is looser. (Q225, AK2) The mode is part of the strictness: `both` counts the address's attempts AND the account's and locks on the larger (`is_locked_out`), so it is at least as
    strict as either alone - leaving it drops a bucket, and `ip` <-> `username` drops one and adds one, which is not a tightening. An admin may move TO `both` from either and may not leave it
    or trade one bucket for the other. The three measures are judged together and a change is looser when any one of them is (AK24: an admin cannot trade attempts for lockout length in
    either direction; that is the rule's conservative side, and a superadmin makes such a trade)."""
    now = __auth.get_rate_limit_settings()
    now_off = now["mode"] == "off" or now["max_attempts"] == 0
    new_off = mode == "off" or max_attempts == 0
    if new_off:
        return not now_off
    if now_off:
        return False

    def longer(a: int, b: int) -> bool:  # is lockout `a` longer than `b`, with 0 the longest?
        return (a == 0 and b != 0) or (a != 0 and b != 0 and a > b)

    mode_looser = mode != now["mode"] and mode != "both"
    return max_attempts > now["max_attempts"] or longer(now["lockout_minutes"], lockout_minutes) or mode_looser


@bp.route("/settings/save-session", methods=["POST"])
@login_required
@_admin_required
def save_session_settings():
    timeout = request.form.get("timeout_minutes", "60").strip()
    enabled = request.form.get("timeout_enabled", "true").strip()
    if enabled not in ("true", "false"):
        enabled = "true"

    minutes = __session_timeout.parse_minutes(timeout)
    if minutes is None:
        flash_field("timeout_minutes", "Session timeout must be between 0 and 1440 minutes (0 = never).")
        return redirect(url_for("settings.settings_security"))
    timeout = str(minutes)  # the canonical text: `00005` is stored as 5, and what is stored is what the reader applies
    # (Q224, AJ14) an admin makes the policy STRICTER only, as for the MFA mode (Q171): the idle timeout is one of three global authentication knobs on this page. Off, or 0 (never), is the least
    # strict; among timeouts a shorter one is stricter. A superadmin may loosen it
    if current_user.role != "superadmin" and _session_looser(enabled, minutes):
        flash("Only a superadmin can make the session timeout less strict.", "error")
        return redirect(url_for("settings.settings_security"))

    # (Q226, the review's P2 #5) one transaction, and "saved" only when it is: two commits left half a policy applied under a success message
    if not __user.set_global_settings({"session_timeout_minutes": timeout, "session_timeout_enabled": enabled}):
        flash("The session timeout could not be saved. Check server logs for details.", "error")
        return redirect(url_for("settings.settings_security"))

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

    # (Q224, AJ18) bounded, as `save_config_revision_keep` bounds its own: the minutes reach a `DATE_SUB(NOW(), INTERVAL %s MINUTE)` and a count beyond any login's reach is a typo, not a policy
    if not is_whole(max_attempts) or not 0 <= int(max_attempts) <= __auth.MAX_ATTEMPTS_BOUND:
        flash_field(
            "max_attempts", f"Max attempts must be a whole number from 0 (unlimited) to {__auth.MAX_ATTEMPTS_BOUND}."
        )
        return redirect(url_for("settings.settings_security"))
    if not is_whole(lockout_minutes) or not 0 <= int(lockout_minutes) <= __auth.MAX_LOCKOUT_MINUTES:
        flash_field(
            "lockout_minutes",
            f"Lockout duration must be a whole number of minutes from 0 (until cleared) to {__auth.MAX_LOCKOUT_MINUTES} (a week).",
        )
        return redirect(url_for("settings.settings_security"))
    if mode not in __auth.RATE_LIMIT_MODES:
        flash("Invalid lockout mode.", "error")
        return redirect(url_for("settings.settings_security"))
    max_attempts, lockout_minutes = (
        str(int(max_attempts)),
        str(int(lockout_minutes)),
    )  # the canonical text, as the session route stores its minutes
    # (Q224, AJ14) an admin makes the policy STRICTER only (Q171's rule for the MFA mode): rate limiting cannot be turned off, the attempts allowed cannot grow (0 is unlimited) and the lockout
    # cannot shorten (0 is until cleared). A superadmin may loosen it
    if current_user.role != "superadmin" and _rate_limit_looser(mode, int(max_attempts), int(lockout_minutes)):
        flash("Only a superadmin can make login rate limiting less strict.", "error")
        return redirect(url_for("settings.settings_security"))
    # (Q227, AM3) and only a superadmin makes a lockout permanent. 0 is the strictest value, so the ratchet above lets an admin move TO it and never away: an admin could set it, fail a
    # superadmin's name at /login and leave that account locked until someone cleared it. An admin may keep a 0 a superadmin set
    if (
        current_user.role != "superadmin"
        and int(lockout_minutes) == 0
        and __auth.get_rate_limit_settings()["lockout_minutes"] != 0
    ):
        flash_field("lockout_minutes", PERMANENT_IS_A_SUPERADMINS)
        return redirect(url_for("settings.settings_security"))

    if not __user.set_global_settings(
        {"rl_max_attempts": max_attempts, "rl_lockout_minutes": lockout_minutes, "rl_mode": mode}
    ):  # (Q226, the review's P2 #5) one transaction, and "saved" only when it is
        flash("Rate limiting settings could not be saved. Check server logs for details.", "error")
        return redirect(url_for("settings.settings_security"))
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
                attempts = max(cur.rowcount, 0)
                # (Q226) the permanent lockouts: this button is the one way they end
                cur.execute("DELETE FROM login_lockouts")
                lockouts = max(cur.rowcount, 0)
            db.commit()
        # (Q226, AL22 and the review's note) an ADMIN's act, kept so: it resets counters and ends lockouts (a locked-out colleague is the common case), changes no stored policy, and is
        # audited; the ratchet (RBAC-003) is about policy. (Q227, AM3) The flash and the audit row say what it did: it said "All login attempt records cleared." and named no lockout
        flash(CLEARED_SENTENCE.format(attempts=attempts, lockouts=lockouts), "success")
        __user.audit(
            "CLEAR_LOCKOUTS", "settings", f"login attempts cleared={attempts} permanent lockouts ended={lockouts}"
        )
    except Exception as e:
        logger.error(f"Error clearing lockouts: {e}")
        flash("Error clearing lockouts. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


def validate_cert_material(cert_data: str, key_data: str, ca_data: str | None) -> str | None:
    """
    v5.9.1 — return None if cert + key (+ CA bundle, when given) load as a
    real TLS server chain, else a short reason. The old check was textual
    ("contains BEGIN CERTIFICATE"), so a valid certificate paired with the
    wrong private key sailed through, got written to the config dir's ssl/, and
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


@bp.route("/settings/upload-cert", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def upload_cert():
    # Q202 (AR6): Jen's own SSL certificate ends in `runtime.restart_service()` - every restart of Jen is behind the one gate (superadmin + step-up), like `restart_jen`
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
        # v5.68.0-beta.16 (Q151): the whole set (certificate, key, CA bundle, combined chain) is installed ALL-OR-NOTHING - it used to be written one file
        # at a time, so a failure at any step left a new key beside an old certificate (gunicorn then refuses to start). A failure puts every file back.
        from jen.services.certs import commit_file_set

        members = [(extensions.SSL_KEY, key_data, 0o640), (extensions.SSL_CERT, cert_data, 0o644)]
        if ca_data:
            members.append((extensions.SSL_CA, ca_data, 0o644))
        members.append((extensions.SSL_COMBINED, combined, 0o644))
        commit_file_set(members)
        __user.audit("UPLOAD_CERT", "settings", "SSL certificate uploaded")
        # v5.67.0-beta.10 (Q122) — restart by deployment (systemd or Docker); say so when neither.
        if __runtime.restart_service() == "none":
            flash("Certificate validated and installed. " + __runtime.RESTART_BY_HAND, "warning")
        else:
            flash("Certificate validated and installed. Jen is restarting...", "success")
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        flash("Error uploading certificate. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/remove-cert", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def remove_cert():
    # Q202 (AR6): see upload_cert - removing the certificate takes the site back to HTTP and restarts Jen
    for f in [extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_CA, extensions.SSL_COMBINED]:
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError as e:  # (Q226, AL26) a file that will not go is said, never a 500 after the first one went
            logger.error("remove_cert: %s could not be removed: %s", f, type(e).__name__)
            flash("The certificate files could not all be removed. Check server logs for details.", "error")
            return redirect(url_for("settings.settings_security"))
    # v5.69.0-beta.2 (Q171): removing the certificate takes the site back to HTTP - an event the audit log carries like every other change of the serving setup
    __user.audit("REMOVE_CERT", "ssl", f"Certificate removed by {current_user.username}")
    if __runtime.restart_service() == "none":
        flash("Certificate removed. " + __runtime.RESTART_BY_HAND, "warning")
    else:
        flash("Certificate removed. Restarting in HTTP mode...", "success")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/save-oidc", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(
    minutes=10
)  # Q203 AS2: who may sign in, and with what role (`role_map`, `default_role`, `auto_create`), is what RBAC-003 calls deciding who the superadmins are
def save_oidc():
    """v5.25.0 (Q21) — [oidc] single sign-on. Superadmin only: this
    controls who can log in and with what role, a step above the rest
    of this page's admin-editable settings. client_secret behaves like
    every other password field in Jen — blank keeps the existing value,
    non-blank replaces it; there's nothing to "inherit" here, so no
    checkbox."""
    enabled = request.form.get("enabled", "") == "1"
    issuer = request.form.get("issuer", "").strip()
    client_id = request.form.get("client_id", "").strip()
    client_secret = request.form.get("client_secret", "").strip()
    scopes = request.form.get("scopes", "").strip() or "openid profile email"
    username_claim = request.form.get("username_claim", "").strip() or "preferred_username"
    role_claim = request.form.get("role_claim", "").strip() or "groups"
    role_map = request.form.get("role_map", "").strip()
    default_role = request.form.get("default_role", "viewer").strip().lower()
    auto_create = request.form.get("auto_create", "") == "1"
    button_label = request.form.get("button_label", "").strip() or "Sign in with SSO"
    redirect_uri = request.form.get("redirect_uri", "").strip()
    local_login = request.form.get("local_login", "") == "1"
    subnet_map = request.form.get("subnet_map", "").strip()
    subnet_map_default = request.form.get("subnet_map_default", "none").strip().lower()

    # (Q229, AO1, AO2, AO6) asked of every issuer that is saved, not only of an enabled one: a disabled save stored and audited whatever was typed
    if (enabled or issuer) and not __auth.valid_oidc_issuer(issuer):
        flash_field("issuer", __auth.userinfo_sentence(issuer) or OIDC_ISSUER_SHAPE)
        return redirect(url_for("settings.settings_security"))
    if enabled and not client_id:
        flash_field("client_id", "A client ID is required to enable single sign-on.")
        return redirect(url_for("settings.settings_security"))
    if default_role not in ("superadmin", "admin", "viewer", "none"):
        flash_field("default_role", "Default role must be superadmin, admin, viewer, or none.")
        return redirect(url_for("settings.settings_security"))
    if role_map and not __oidc.parse_role_map(role_map):
        flash_field("role_map", "Role mapping could not be parsed — check the format (role=value;role=value,value).")
        return redirect(url_for("settings.settings_security"))
    if subnet_map_default not in ("none", "all"):
        flash_field("subnet_map_default", "Subnet mapping default must be none or all.")
        return redirect(url_for("settings.settings_security"))
    if subnet_map and not __oidc.parse_subnet_map(subnet_map):
        flash(
            "Subnet mapping could not be parsed — check the format (group:id,id;group:*).",
            "error",
        )
        return redirect(url_for("settings.settings_security"))
    bad = __oidc.subnet_map_errors(subnet_map)
    if bad:
        # (Q226, AL4) a segment the parser would SKIP is refused here, with the segment named: a skipped segment is a group the operator meant to scope, and the login treats a map that
        # carries one as naming no default until it is fixed
        flash_field(
            "subnet_map", "Subnet mapping: " + "; ".join(bad[:3]) + ". Every segment is group:id,id or group:*."
        )
        return redirect(url_for("settings.settings_security"))

    # (Q227, AM5; CRED-002) a blank client secret keeps the stored one only while the issuer is the same place. The secret typed for one identity provider was registered against the next
    # one's discovery document and sent to its token endpoint. A stored issuer that is blank is a different place too (two saves would walk the secret across); an emptied issuer sends the secret nowhere and keeps it
    # (Q228, AN2 and the beta.13 review's #1) the issuer is compared WITH its path (`auth.same_destination`): `init_oidc` builds the discovery URL from the path, so the path selects
    # the realm or the tenant whose token endpoint is sent the secret, and `same_endpoint` (scheme, host, port) called two realms of one Keycloak, or two tenants of one cloud
    # login host, the same place. A client secret also belongs to ONE client registration: a changed client ID with a blank secret is refused the same way
    if not client_secret and issuer and extensions.OIDC_CLIENT_SECRET:
        # (Q229) `same_issuer` is `same_destination` of the two as `init_oidc` dials them
        if not __auth.same_issuer(issuer, extensions.OIDC_ISSUER):
            flash_field("client_secret", OIDC_ISSUER_CHANGED)
            return redirect(url_for("settings.settings_security"))
        if client_id != extensions.OIDC_CLIENT_ID:
            flash_field("client_secret", OIDC_CLIENT_CHANGED)
            return redirect(url_for("settings.settings_security"))

    items = [
        ("oidc", "enabled", "true" if enabled else "false"),
        ("oidc", "issuer", issuer),
        ("oidc", "client_id", client_id),
        ("oidc", "scopes", scopes),
        ("oidc", "username_claim", username_claim),
        ("oidc", "role_claim", role_claim),
        ("oidc", "role_map", role_map),
        ("oidc", "default_role", default_role),
        ("oidc", "auto_create", "true" if auto_create else "false"),
        ("oidc", "button_label", button_label),
        ("oidc", "redirect_uri", redirect_uri),
        ("oidc", "local_login", "true" if local_login else "false"),
        ("oidc", "subnet_map", subnet_map),
        ("oidc", "subnet_map_default", subnet_map_default),
    ]
    if client_secret:
        items.append(("oidc", "client_secret", client_secret))

    __config.app_config.write_values(items)
    # (Q228, AN2) the client is registered once, when Jen starts (`init_oidc`): the page said "saved" and the running process kept the old issuer, client and secret until a restart
    flash(OIDC_SAVED, "success")
    __user.audit("SAVE_SETTINGS", "oidc", f"enabled={enabled} issuer={issuer}")
    return redirect(url_for("settings.settings_security"))
