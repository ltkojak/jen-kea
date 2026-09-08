"""
jen/routes/settings/
────────────────────
The Settings blueprint. Split into focused modules (v5.6.1) — all
register on the one `bp` below so every endpoint stays `settings.<fn>`
and every existing `url_for("settings.…")` keeps resolving:

  alerts          — channels, templates, the daily-summary/threshold knobs
  infrastructure  — Kea / DB / SSH / DDNS / HA / ports / metrics
  authoring       — "generate a Kea config over SSH" flow + binary checks
  branding        — icons, favicon, nav logo, nav colour
  security        — session timeout, rate limiting, SSL certs
  updates         — check-for-update, in-app self-update trigger

This module keeps the landing route and the System page.
"""

import logging
import os
import subprocess

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.kea as __kea
import jen.services.mfa as __mfa
from jen import extensions
from jen.services.access import admin_required as _admin_required

logger = logging.getLogger(__name__)
bp = Blueprint("settings", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


@bp.route("/settings")
@login_required
@_admin_required
def settings():
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/system")
@login_required
@_admin_required
def settings_system():
    cert_info = {}
    if __config.ssl_configured():
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    extensions.SSL_COMBINED if os.path.exists(extensions.SSL_COMBINED) else extensions.SSL_CERT,
                    "-noout",
                    "-subject",
                    "-enddate",
                    "-issuer",
                ],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.splitlines():
                if line.startswith("subject="):
                    cert_info["subject"] = line.replace("subject=", "").strip()
                elif line.startswith("notAfter="):
                    cert_info["expires"] = line.replace("notAfter=", "").strip()
                elif line.startswith("issuer="):
                    cert_info["issuer"] = line.replace("issuer=", "").strip()
        except Exception as e:
            logger.error(f"Error reading SSL certificate info: {e}")
            cert_info["error"] = "Could not read certificate info. Check server logs for details."

    ssh_pub_key = ""
    if os.path.exists(extensions.SSH_KEY_PATH + ".pub"):
        try:
            with open(extensions.SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass

    telegram_settings = {
        "enabled": __user.get_global_setting("telegram_enabled", "false"),
        "token": __user.get_global_setting("telegram_token", ""),
        "chat_id": __user.get_global_setting("telegram_chat_id", ""),
        "alert_kea_down": __user.get_global_setting("alert_kea_down", "true"),
        "alert_new_lease": __user.get_global_setting("alert_new_lease", "false"),
        "alert_utilization": __user.get_global_setting("alert_utilization", "true"),
        "alert_threshold_pct": __user.get_global_setting("alert_threshold_pct", "80"),
    }
    session_settings = {
        "timeout": __user.get_global_setting("session_timeout_minutes", "60"),
        "enabled": __user.get_global_setting("session_timeout_enabled", "true"),
    }
    rl_settings = {
        "max_attempts": __user.get_global_setting("rl_max_attempts", "10"),
        "lockout_minutes": __user.get_global_setting("rl_lockout_minutes", "15"),
        "mode": __user.get_global_setting("rl_mode", "both"),
    }

    # Get current lockout counts for admin visibility
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(DISTINCT ip_address) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
                )
                rl_active_ips = cur.fetchone()["cnt"]
                cur.execute(
                    "SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
                )
                rl_attempts_1h = cur.fetchone()["cnt"]
    except Exception:
        rl_active_ips = 0
        rl_attempts_1h = 0

    # Get Kea version
    kea_version = ""
    try:
        ver_result = __kea.kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass

    mfa_mode = __mfa.get_mfa_mode()
    nav_logo_url = None
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        if os.path.exists(f"{extensions.NAV_LOGO_PATH}.{ext}"):
            nav_logo_url = f"/static/nav_logo.{ext}?v={int(os.path.getmtime(f'{extensions.NAV_LOGO_PATH}.{ext}'))}"
            break
    branding = {
        "nav_logo": nav_logo_url,
        "nav_color": __user.get_global_setting("branding_nav_color", ""),
    }
    # Audit log retention
    audit_retention_days = __user.get_global_setting("audit_retention_days", "90")
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM audit_log")
                audit_log_count = cur.fetchone()["cnt"]
    except Exception:
        audit_log_count = "?"

    return render_template(
        "settings_system.html",
        ssl_configured=__config.ssl_configured(),
        cert_info=cert_info,
        has_favicon=os.path.exists(extensions.FAVICON_PATH),
        http_port=extensions.HTTP_PORT,
        https_port=extensions.HTTPS_PORT,
        ssh_pub_key=ssh_pub_key,
        ssh_configured=bool(ssh_pub_key),
        kea_ssh_host=extensions.KEA_SSH_HOST,
        kea_ssh_user=extensions.KEA_SSH_USER,
        telegram=telegram_settings,
        session=session_settings,
        rl=rl_settings,
        rl_active_ips=rl_active_ips,
        rl_attempts_1h=rl_attempts_1h,
        jen_version=_JEN_VERSION(),
        kea_version=kea_version,
        mfa_mode=mfa_mode,
        branding=branding,
        audit_retention_days=audit_retention_days,
        audit_log_count=audit_log_count,
    )


@bp.route("/settings/save-audit-retention", methods=["POST"])
@login_required
@_admin_required
def save_audit_retention():
    days_raw = request.form.get("audit_retention_days", "90").strip()
    try:
        days = max(0, int(days_raw))
    except ValueError:
        flash("Invalid value — must be a number of days.", "error")
        return redirect(url_for("settings.settings_system"))
    __user.set_global_setting("audit_retention_days", str(days))
    # Run cleanup immediately if retention > 0
    if days > 0:
        try:
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM audit_log WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)", (days,))
                    deleted = cur.rowcount
                db.commit()
            flash(f"Audit log retention set to {days} days. {deleted} old entries removed.", "success")
        except Exception as e:
            logger.error(f"Audit log cleanup failed: {e}")
            flash("Setting saved, but cleanup of old entries failed. Check server logs for details.", "warning")
    else:
        flash("Audit log retention set to keep forever (0 = no limit).", "success")
    __user.audit("SETTINGS", "audit_retention", f"retention_days={days}")
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/system/save-mfa-mode", methods=["POST"])
@login_required
@_admin_required
def save_mfa_mode():
    mode = request.form.get("mfa_mode", "off")
    if mode not in ("off", "optional", "required_admins", "required_all"):
        flash("Invalid MFA mode.", "error")
        return redirect(url_for("settings.settings_system"))
    __user.set_global_setting("mfa_mode", mode)
    labels = {
        "off": "Off",
        "optional": "Optional",
        "required_admins": "Required for Admins",
        "required_all": "Required for All",
    }
    flash(f"MFA policy set to: {labels.get(mode, mode)}", "success")
    __user.audit("SAVE_MFA_MODE", "settings", f"mode={mode} by {current_user.username}")
    return redirect(url_for("settings.settings_system"))


# ── Register the split-out route modules (imported for their @bp.route side
# effects; module-name form so nothing shadows a local like settings_system's
# `branding` context dict) ────────────────────────────────────────────────────
import jen.routes.settings.alerts  # noqa: E402, F401
import jen.routes.settings.authoring  # noqa: E402, F401
import jen.routes.settings.branding  # noqa: E402, F401
import jen.routes.settings.infrastructure  # noqa: E402, F401
import jen.routes.settings.security  # noqa: E402, F401
import jen.routes.settings.updates  # noqa: E402, F401

# Re-exported for tests that import these helpers by their old path.
from jen.routes.settings.authoring import (  # noqa: E402
    _parse_subnet_lines,  # noqa: F401
    _subnets_to_lines,  # noqa: F401
)
