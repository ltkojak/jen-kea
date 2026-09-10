"""
jen/routes/settings/
────────────────────
The Settings blueprint. Split into focused modules (v5.6.1) — all
register on the one `bp` below so every endpoint stays `settings.<fn>`
and every existing `url_for("settings.…")` keeps resolving:

  alerts          — channels, templates, thresholds (+ DDNS/metrics cards)
  infrastructure  — the Kea page (Control Agent / SSH / servers / HA)
                    and the save handlers for Kea, DB, SSH, DDNS, HA,
                    ports, metrics
  authoring       — "generate a Kea config over SSH" flow + binary checks
  branding        — icons, favicon, nav logo, nav colour (Appearance page)
  security        — session timeout, rate limiting, SSL certs
  updates         — check-for-update, update-status, self-update trigger
  nav             — the navigation model base.html renders (v5.9.0)

v5.9.0 — Settings was reorganised into seven task-shaped groups (see
nav.py and CHANGELOG). This module keeps the landing page, the System
page (updates hub, ports, restart, retention), and the Access & Security
and Appearance pages. Every POST endpoint URL is unchanged; only GET
pages moved, and the old URLs 301 to their new homes.
"""

import logging
import os

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


def _cert_info():
    """subject / issuer / expires (+ days_left) for the installed cert.
    v5.12.0 — the openssl logic moved to jen/services/certs.py so the
    Health Center and the cert-expiry alert can share it."""
    if not __config.ssl_configured():
        return {}
    from jen.services import certs

    return certs.cert_info(certs.installed_cert_path())


def _count(sql, params=()):
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()["cnt"]
    except Exception:
        return None


# ── Landing page ─────────────────────────────────────────────────────────────


@bp.route("/settings")
@login_required
@_admin_required
def settings():
    """
    v5.9.0 — a grid of the Settings groups with a live hint or two each.
    On a phone this IS the Settings navigation. Hints are deliberately
    cheap: one Kea version-get, one openssl call, a few COUNTs, a
    directory listing — nothing that contacts GitHub or SSHes anywhere.

    v5.13.0 — the backup hint counts `.json.gz` files instead of
    decompressing and JSON-parsing every one, and the version-get runs
    on a 3s timeout so an unreachable Kea can't stall the whole page.
    """
    from jen.services.plugins import discover_plugins

    hints = {}

    # v5.10.0 — one version-get does double duty: reachability + the
    # number we need to warn when ca mode won't survive the running Kea.
    _kea_ver = __kea.kea_command("version-get", timeout=3)
    kea_up = _kea_ver.get("result") == 0
    hints["kea"] = [("Kea: connected", "ok") if kea_up else ("Kea: unreachable", "bad")]
    if kea_up and extensions.KEA_CONNECTION_MODE == "ca":
        _vt = __kea.parse_kea_version(_kea_ver.get("arguments", {}).get("extended", "") or _kea_ver.get("text", ""))
        if _vt is not None and _vt >= (3, 2, 0):
            hints["kea"].append(("Control Agent removed in this Kea — switch to direct mode", "bad"))
        elif _vt is not None and _vt >= (3, 0, 0):
            hints["kea"].append(("Control Agent deprecated — switch to direct mode", "warn"))
    if not extensions.KEA_SSH_HOST:
        hints["kea"].append(("SSH not configured", "warn"))

    cert = _cert_info()
    if __config.ssl_configured():
        days = cert.get("days_left")
        if days is None:
            hints["security"] = [("HTTPS on", "ok")]
        elif days < 0:
            hints["security"] = [("Certificate EXPIRED", "bad")]
        elif days <= 30:
            hints["security"] = [(f"Certificate expires in {days}d", "warn")]
        else:
            hints["security"] = [(f"HTTPS on · cert {days}d", "ok")]
    else:
        hints["security"] = [("HTTP only — no certificate", "warn")]
    users = _count("SELECT COUNT(*) AS cnt FROM users")
    if users is not None:
        hints["security"].append((f"{users} user{'s' if users != 1 else ''}", "muted"))
    mfa_mode = __mfa.get_mfa_mode()
    if mfa_mode == "off":
        hints["security"].append(("MFA off", "warn"))

    channels = _count("SELECT COUNT(*) AS cnt FROM alert_channels WHERE enabled=1")
    hints["alerts"] = [(f"{channels} channel{'s' if channels != 1 else ''} enabled", "ok" if channels else "warn")]
    failed = _count(
        "SELECT COUNT(*) AS cnt FROM alert_log WHERE status NOT IN ('ok','sent') AND sent_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)"
    )
    if failed:
        hints["alerts"].append((f"{failed} failed in 24h", "bad"))

    plugins = discover_plugins()
    hints["system"] = [(f"v{_JEN_VERSION()}", "muted")]
    if plugins:
        enabled = sum(1 for p in plugins if p.get("enabled"))
        hints["system"].append((f"{enabled}/{len(plugins)} plugins enabled", "muted"))
    if __user.get_global_setting("restart_pending", "false") == "true":
        hints["system"].append(("Restart pending", "warn"))

    hints["databases"] = [(f"Jen: {extensions.JEN_DB_HOST}", "muted"), (f"Kea: {extensions.KEA_DB_HOST}", "muted")]
    try:
        from jen.services import dbexport

        n = dbexport.backup_count()
        if n:
            hints["databases"].append((f"{n} backup{'s' if n != 1 else ''}", "ok"))
        else:
            hints["databases"].append(("No backups yet", "warn"))
    except Exception:
        pass

    audit = _count("SELECT COUNT(*) AS cnt FROM audit_log")
    if audit is not None:
        hints["logs"] = [(f"{audit} audit entries", "muted")]

    has_logo = any(os.path.exists(f"{extensions.NAV_LOGO_PATH}.{e}") for e in ("png", "svg", "jpg", "jpeg", "webp"))
    hints["appearance"] = [("Custom logo", "muted")] if has_logo else []

    return render_template("settings_home.html", hints=hints)


# ── System: updates hub, ports, restart, retention ──────────────────────────


@bp.route("/settings/system")
@login_required
@_admin_required
def settings_system():
    from jen.services.plugins import discover_plugins

    audit_retention_days = __user.get_global_setting("audit_retention_days", "90")
    audit_log_count = _count("SELECT COUNT(*) AS cnt FROM audit_log")
    return render_template(
        "settings_system.html",
        jen_version=_JEN_VERSION(),
        plugins=discover_plugins(),
        ssl_configured=__config.ssl_configured(),
        http_port=extensions.HTTP_PORT,
        https_port=extensions.HTTPS_PORT,
        worker_threads=extensions.WORKER_THREADS,
        restart_pending=__user.get_global_setting("restart_pending", "false") == "true",
        audit_retention_days=audit_retention_days,
        audit_log_count=audit_log_count if audit_log_count is not None else "?",
    )


# ── Access & Security: MFA policy, sessions, rate limiting, SSL ─────────────


@bp.route("/settings/security")
@login_required
@_admin_required
def settings_security():
    session_settings = {
        "timeout": __user.get_global_setting("session_timeout_minutes", "60"),
        "enabled": __user.get_global_setting("session_timeout_enabled", "true"),
    }
    rl_settings = {
        "max_attempts": __user.get_global_setting("rl_max_attempts", "10"),
        "lockout_minutes": __user.get_global_setting("rl_lockout_minutes", "15"),
        "mode": __user.get_global_setting("rl_mode", "both"),
    }
    rl_active_ips = _count(
        "SELECT COUNT(DISTINCT ip_address) AS cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    )
    rl_attempts_1h = _count(
        "SELECT COUNT(*) AS cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    )
    return render_template(
        "settings_security.html",
        mfa_mode=__mfa.get_mfa_mode(),
        session=session_settings,
        rl=rl_settings,
        rl_active_ips=rl_active_ips or 0,
        rl_attempts_1h=rl_attempts_1h or 0,
        ssl_configured=__config.ssl_configured(),
        cert_info=_cert_info(),
        http_port=extensions.HTTP_PORT,
        https_port=extensions.HTTPS_PORT,
    )


# ── Appearance: branding, favicon, brand icons ──────────────────────────────


@bp.route("/settings/appearance")
@login_required
@_admin_required
def settings_appearance():
    from jen.routes.settings.branding import icon_lists

    nav_logo_url = None
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        if os.path.exists(f"{extensions.NAV_LOGO_PATH}.{ext}"):
            nav_logo_url = (
                f"/content/branding/nav_logo.{ext}?v={int(os.path.getmtime(f'{extensions.NAV_LOGO_PATH}.{ext}'))}"
            )
            break
    bundled, custom = icon_lists()
    return render_template(
        "settings_appearance.html",
        branding={"nav_logo": nav_logo_url, "nav_color": __user.get_global_setting("branding_nav_color", "")},
        has_favicon=os.path.exists(extensions.FAVICON_PATH),
        bundled=bundled,
        custom=custom,
    )


# ── Save handlers that stay here ────────────────────────────────────────────


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
        return redirect(url_for("settings.settings_security"))
    __user.set_global_setting("mfa_mode", mode)
    labels = {
        "off": "Off",
        "optional": "Optional",
        "required_admins": "Required for Admins",
        "required_all": "Required for All",
    }
    flash(f"MFA policy set to: {labels.get(mode, mode)}", "success")
    __user.audit("SAVE_MFA_MODE", "settings", f"mode={mode} by {current_user.username}")
    return redirect(url_for("settings.settings_security"))


# ── Register the split-out route modules (imported for their @bp.route side
# effects; module-name form so nothing shadows a local) ──────────────────────
import jen.routes.settings.alerts  # noqa: E402
import jen.routes.settings.authoring  # noqa: E402
import jen.routes.settings.branding  # noqa: E402
import jen.routes.settings.infrastructure  # noqa: E402
import jen.routes.settings.security  # noqa: E402
import jen.routes.settings.updates  # noqa: E402, F401

# Re-exported for tests that import these helpers by their old path.
from jen.routes.settings.authoring import (  # noqa: E402
    _parse_subnet_lines,  # noqa: F401
    _subnets_to_lines,  # noqa: F401
)
