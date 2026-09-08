"""
jen/routes/settings.py
───────────────────────
All Settings routes.
"""

import json
import logging
import os
import re
import subprocess
import threading

import requests
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.alerts as __alerts
import jen.services.auth as __auth
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.kea_authoring as __authoring
import jen.services.mfa as __mfa
from jen import extensions
from jen.config import AppConfig
from jen.services.access import admin_required as _admin_required
from jen.services.access import superadmin_required as _superadmin_required
from jen.services.alerts import ALERT_TYPE_LABELS, DEFAULT_TEMPLATES

logger = logging.getLogger(__name__)
bp = Blueprint("settings", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/settings")
@login_required
@_admin_required
def settings():
    return redirect(url_for('settings.settings_system'))

@bp.route("/settings/system")
@login_required
@_admin_required
def settings_system():
    cert_info = {}
    if __config.ssl_configured():
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", extensions.SSL_COMBINED if os.path.exists(extensions.SSL_COMBINED) else extensions.SSL_CERT,
                 "-noout", "-subject", "-enddate", "-issuer"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("subject="): cert_info["subject"] = line.replace("subject=", "").strip()
                elif line.startswith("notAfter="): cert_info["expires"] = line.replace("notAfter=", "").strip()
                elif line.startswith("issuer="): cert_info["issuer"] = line.replace("issuer=", "").strip()
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
                cur.execute("SELECT COUNT(DISTINCT ip_address) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
                rl_active_ips = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
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

    return render_template("settings_system.html",
                           ssl_configured=__config.ssl_configured(), cert_info=cert_info,
                           has_favicon=os.path.exists(extensions.FAVICON_PATH),
                           http_port=extensions.HTTP_PORT,
                           https_port=extensions.HTTPS_PORT, ssh_pub_key=ssh_pub_key,
                           ssh_configured=bool(ssh_pub_key),
                           kea_ssh_host=extensions.KEA_SSH_HOST, kea_ssh_user=extensions.KEA_SSH_USER,
                           telegram=telegram_settings, session=session_settings,
                           rl=rl_settings, rl_active_ips=rl_active_ips,
                           rl_attempts_1h=rl_attempts_1h,
                           jen_version=_JEN_VERSION(),
                           kea_version=kea_version,
                           mfa_mode=mfa_mode,
                           branding=branding,
                           audit_retention_days=audit_retention_days,
                           audit_log_count=audit_log_count)

@bp.route("/settings/save-audit-retention", methods=["POST"])
@login_required
@_admin_required
def save_audit_retention():
    days_raw = request.form.get("audit_retention_days", "90").strip()
    try:
        days = max(0, int(days_raw))
    except ValueError:
        flash("Invalid value — must be a number of days.", "error")
        return redirect(url_for('settings.settings_system'))
    __user.set_global_setting("audit_retention_days", str(days))
    # Run cleanup immediately if retention > 0
    if days > 0:
        try:
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "DELETE FROM audit_log WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)",
                        (days,)
                    )
                    deleted = cur.rowcount
                db.commit()
            flash(f"Audit log retention set to {days} days. {deleted} old entries removed.", "success")
        except Exception as e:
            logger.error(f"Audit log cleanup failed: {e}")
            flash("Setting saved, but cleanup of old entries failed. Check server logs for details.", "warning")
    else:
        flash("Audit log retention set to keep forever (0 = no limit).", "success")
    __user.audit("SETTINGS", "audit_retention", f"retention_days={days}")
    return redirect(url_for('settings.settings_system'))

@bp.route("/settings/system/save-mfa-mode", methods=["POST"])
@login_required
@_admin_required
def save_mfa_mode():
    mode = request.form.get("mfa_mode", "off")
    if mode not in ("off", "optional", "required_admins", "required_all"):
        flash("Invalid MFA mode.", "error")
        return redirect(url_for('settings.settings_system'))
    __user.set_global_setting("mfa_mode", mode)
    labels = {"off": "Off", "optional": "Optional", "required_admins": "Required for Admins", "required_all": "Required for All"}
    flash(f"MFA policy set to: {labels.get(mode, mode)}", "success")
    __user.audit("SAVE_MFA_MODE", "settings", f"mode={mode} by {current_user.username}")
    return redirect(url_for('settings.settings_system'))

@bp.route("/settings/alerts")
@login_required
@_admin_required
def settings_alerts():
    import json
    channels = []
    templates = {}
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM alert_channels ORDER BY channel_type, channel_name")
                channels = cur.fetchall()
                # Parse JSON fields
                for ch in channels:
                    if isinstance(ch.get("config"), str):
                        try: ch["config"] = json.loads(ch["config"])
                        except (json.JSONDecodeError, ValueError): ch["config"] = {}
                    if isinstance(ch.get("alert_types"), str):
                        try: ch["alert_types"] = json.loads(ch["alert_types"])
                        except (json.JSONDecodeError, ValueError): ch["alert_types"] = []
                    # v5.1.16 — per-channel subnet scope for notifications
                    if isinstance(ch.get("subnet_scope"), str):
                        try: ch["subnet_scope"] = json.loads(ch["subnet_scope"])
                        except (json.JSONDecodeError, ValueError): ch["subnet_scope"] = None
                cur.execute("SELECT alert_type, template_text FROM alert_templates")
                for row in cur.fetchall():
                    templates[row["alert_type"]] = row["template_text"]
    except Exception as e:
        logger.error(f"Error loading alert settings: {e}")
        flash("Error loading alert settings. Check server logs for details.", "error")

    # Recent alert log with error details
    recent_alerts = []
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT alert_type, channel_type, status, error, sent_at
                    FROM alert_log
                    ORDER BY sent_at DESC
                    LIMIT 20
                """)
                recent_alerts = cur.fetchall()
    except Exception:
        pass

    summary_time = __user.get_global_setting("daily_summary_time", "07:00")
    pool_exhaustion_free = __user.get_global_setting("pool_exhaustion_free", "5")
    threshold_pct = __user.get_global_setting("alert_threshold_pct", "80")
    reserved_lease_mode = __user.get_global_setting("reserved_lease_mode", "always")
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    return render_template("settings_alerts.html",
                           channels=channels, templates=templates,
                           default_templates=DEFAULT_TEMPLATES,
                           alert_type_labels=ALERT_TYPE_LABELS,
                           summary_time=summary_time,
                           pool_exhaustion_free=pool_exhaustion_free,
                           threshold_pct=threshold_pct,
                           reserved_lease_mode=reserved_lease_mode,
                           subnet_map=accessible_subnet_map,
                           can_grant_all_subnets=current_user.all_subnets,
                           recent_alerts=recent_alerts)

@bp.route("/settings/alerts/save-channel", methods=["POST"])
@login_required
@_admin_required
def save_alert_channel():
    import json
    channel_id = request.form.get("channel_id", "").strip()
    channel_type = request.form.get("channel_type", "").strip()
    channel_name = request.form.get("channel_name", "").strip()[:100]
    enabled = 1 if request.form.get("enabled") else 0
    alert_types = request.form.getlist("alert_types[]")

    # v5.1.16 — per-channel subnet scope, same NULL-means-unrestricted
    # convention and same creator-can't-exceed-their-own-access clamp as
    # API key scoping. Unlike API keys this is a notification
    # preference, not an access boundary, but keeping a subnet-
    # restricted admin from silently scoping a channel to subnets they
    # can't even see themselves avoids a confusing, hard-to-debug config.
    subnet_ids_raw = request.form.getlist("subnet_ids")
    if current_user.all_subnets:
        if not subnet_ids_raw or "all" in subnet_ids_raw:
            subnet_scope = None
        else:
            ids = [int(s) for s in subnet_ids_raw if s.isdigit()]
            subnet_scope = json.dumps(ids) if ids else None
    else:
        allowed = set(current_user.accessible_subnet_ids(extensions.SUBNET_MAP))
        ids = [int(s) for s in subnet_ids_raw if s.isdigit() and int(s) in allowed]
        subnet_scope = json.dumps(ids) if ids else None

    if channel_type not in ("telegram", "email", "slack", "webhook", "ntfy", "discord"):
        flash("Invalid channel type.", "error")
        return redirect(url_for('settings.settings_alerts'))
    if not channel_name:
        flash("Channel name is required.", "error")
        return redirect(url_for('settings.settings_alerts'))

    # Build config based on type
    config = {}
    if channel_type == "telegram":
        config = {
            "token": request.form.get("token", "").strip(),
            "chat_id": request.form.get("chat_id", "").strip(),
        }
    elif channel_type == "email":
        config = {
            "smtp_host": request.form.get("smtp_host", "").strip(),
            "smtp_port": request.form.get("smtp_port", "587").strip(),
            "smtp_user": request.form.get("smtp_user", "").strip(),
            "smtp_pass": request.form.get("smtp_pass", "").strip(),
            "from_addr": request.form.get("from_addr", "").strip(),
            "to_addr": request.form.get("to_addr", "").strip(),
            "use_tls": "true" if request.form.get("use_tls") else "false",
        }
    elif channel_type == "slack":
        config = {"webhook_url": request.form.get("slack_webhook", "").strip()}
    elif channel_type == "webhook":
        config = {
            "webhook_url": request.form.get("webhook_url", "").strip(),
            "payload_type": request.form.get("payload_type", "json").strip(),
            "header_name": request.form.get("header_name", "").strip(),
            "header_value": request.form.get("header_value", "").strip(),
        }
    elif channel_type == "ntfy":
        config = {
            "url": request.form.get("ntfy_url", "https://ntfy.sh").strip(),
            "topic": request.form.get("ntfy_topic", "").strip(),
            "token": request.form.get("ntfy_token", "").strip(),
            "priority": request.form.get("ntfy_priority", "default").strip(),
        }
    elif channel_type == "pushover":
        config = {
            "user_key":  request.form.get("pushover_user_key", "").strip(),
            "api_token": request.form.get("pushover_api_token", "").strip(),
        }
        # Don't overwrite api_token if blank (treat like smtp_pass)
        if channel_id and not config["api_token"]:
            try:
                with __db.jen_db() as db:
                    with db.cursor() as cur:
                        cur.execute("SELECT config FROM alert_channels WHERE id=%s", (channel_id,))
                        row = cur.fetchone()
                        if row:
                            existing = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
                            config["api_token"] = existing.get("api_token", "")
            except Exception:
                pass
    elif channel_type == "discord":
        config = {
            "webhook_url": request.form.get("discord_webhook", "").strip(),
        }

    # Don't overwrite password if blank
    if channel_id and channel_type == "email" and not config["smtp_pass"]:
        try:
            with __db.jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT config FROM alert_channels WHERE id=%s", (channel_id,))
                    row = cur.fetchone()
                    if row:
                        existing = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
                        config["smtp_pass"] = existing.get("smtp_pass", "")
        except Exception:
            pass

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                if channel_id:
                    cur.execute("""
                        UPDATE alert_channels SET channel_name=%s, enabled=%s, config=%s, alert_types=%s, subnet_scope=%s
                        WHERE id=%s
                    """, (channel_name, enabled, json.dumps(config), json.dumps(alert_types), subnet_scope, channel_id))
                else:
                    cur.execute("""
                        INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types, subnet_scope)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (channel_type, channel_name, enabled, json.dumps(config), json.dumps(alert_types), subnet_scope))
            db.commit()
        flash(f"Alert channel '{channel_name}' saved.", "success")
        __user.audit("SAVE_ALERT_CHANNEL", channel_name, f"type={channel_type} enabled={enabled}")
    except Exception as e:
        logger.error(f"Error saving alert channel '{channel_name}': {e}")
        flash("Error saving channel. Check server logs for details.", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/delete-channel/<int:channel_id>", methods=["POST"])
@login_required
@_admin_required
def delete_alert_channel(channel_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT channel_name FROM alert_channels WHERE id=%s", (channel_id,))
                row = cur.fetchone()
                cur.execute("DELETE FROM alert_channels WHERE id=%s", (channel_id,))
            db.commit()
        name = row["channel_name"] if row else str(channel_id)
        flash(f"Alert channel '{name}' deleted.", "success")
        __user.audit("DELETE_ALERT_CHANNEL", str(channel_id), f"name={name}")
    except Exception as e:
        logger.error(f"Error deleting alert channel {channel_id}: {e}")
        flash("Error deleting channel. Check server logs for details.", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/test-channel/<int:channel_id>", methods=["POST"])
@login_required
@_admin_required
def test_alert_channel(channel_id):
    import json
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM alert_channels WHERE id=%s", (channel_id,))
                channel = cur.fetchone()
        if not channel:
            flash("Channel not found.", "error")
            return redirect(url_for('settings.settings_alerts'))
        config = json.loads(channel["config"]) if isinstance(channel["config"], str) else channel["config"]
        ctype = channel["channel_type"]
        test_msg = f"🔔 <b>Jen Test</b>\nTest message from channel: {channel['channel_name']}"
        if ctype == "telegram":
            ok = __alerts._send_telegram_channel(test_msg, config)
        elif ctype == "email":
            ok = __alerts._send_email_channel(test_msg, "test", config)
        elif ctype == "slack":
            ok = __alerts._send_slack_channel(test_msg, config)
        elif ctype == "webhook":
            ok = __alerts._send_webhook_channel(test_msg, "test", config)
        elif ctype == "ntfy":
            ok = __alerts._send_ntfy_channel(test_msg, config)
        elif ctype == "discord":
            ok = __alerts._send_discord_channel(test_msg, config)
        else:
            ok = False
        if ok:
            flash(f"Test message sent successfully to '{channel['channel_name']}'.", "success")
        else:
            flash(f"Test failed for '{channel['channel_name']}'.", "error")
    except Exception as e:
        flash(f"Test error: {str(e)}", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/save-template", methods=["POST"])
@login_required
@_admin_required
def save_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    template_text = request.form.get("template_text", "").strip()
    if alert_type not in DEFAULT_TEMPLATES:
        flash("Invalid alert type.", "error")
        return redirect(url_for('settings.settings_alerts'))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO alert_templates (alert_type, template_text) VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE template_text=%s, updated_at=NOW()
                """, (alert_type, template_text, template_text))
            db.commit()
        flash(f"Template for '{ALERT_TYPE_LABELS.get(alert_type, alert_type)}' saved.", "success")
        __user.audit("SAVE_ALERT_TEMPLATE", alert_type, "Template updated")
    except Exception as e:
        logger.error(f"Error saving alert template '{alert_type}': {e}")
        flash("Error saving template. Check server logs for details.", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/reset-template", methods=["POST"])
@login_required
@_admin_required
def reset_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_templates WHERE alert_type=%s", (alert_type,))
            db.commit()
        flash("Template reset to default.", "success")
    except Exception as e:
        logger.error(f"Error resetting alert template '{alert_type}': {e}")
        flash("Error resetting template. Check server logs for details.", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/save-global", methods=["POST"])
@login_required
@_admin_required
def save_alert_global():
    summary_time = request.form.get("summary_time", "07:00").strip()
    pool_free = request.form.get("pool_exhaustion_free", "5").strip()
    threshold = request.form.get("alert_threshold_pct", "80").strip()
    reserved_lease_mode = request.form.get("reserved_lease_mode", "always").strip()
    if not pool_free.isdigit() or int(pool_free) < 1:
        flash("Pool exhaustion threshold must be a positive number.", "error")
        return redirect(url_for('settings.settings_alerts'))
    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for('settings.settings_alerts'))
    if reserved_lease_mode not in ("always", "once"):
        reserved_lease_mode = "always"
    __user.set_global_setting("daily_summary_time", summary_time)
    __user.set_global_setting("pool_exhaustion_free", pool_free)
    __user.set_global_setting("alert_threshold_pct", threshold)
    __user.set_global_setting("reserved_lease_mode", reserved_lease_mode)
    flash("Global alert settings saved.", "success")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/infrastructure")
@login_required
@_admin_required
def settings_infrastructure():
    kea_up = __kea.kea_is_up()
    ssh_pub_key = ""
    if os.path.exists(extensions.SSH_KEY_PATH + ".pub"):
        try:
            with open(extensions.SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass
    # Load extra servers
    extra_servers = []
    n = 2
    while extensions.cfg.has_section(f"kea_server_{n}"):
        sec = f"kea_server_{n}"
        extra_servers.append({
            "id": n,
            "name": extensions.cfg.get(sec, "name", fallback=f"Kea Server {n}"),
            "api_url": extensions.cfg.get(sec, "api_url", fallback=""),
            "api_user": extensions.cfg.get(sec, "api_user", fallback=""),
            "ssh_host": extensions.cfg.get(sec, "ssh_host", fallback=""),
            "ssh_user": extensions.cfg.get(sec, "ssh_user", fallback=""),
            "kea_conf": extensions.cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
            "role": extensions.cfg.get(sec, "role", fallback="standby"),
        })
        n += 1

    infra = {
        "kea_api_url": extensions.cfg.get("kea", "api_url", fallback=""),
        "kea_api_user": extensions.cfg.get("kea", "api_user", fallback=""),
        "kea_api_pass": extensions.cfg.get("kea", "api_pass", fallback=""),
        "kea_db_host": extensions.cfg.get("kea_db", "host", fallback=""),
        "kea_db_user": extensions.cfg.get("kea_db", "user", fallback=""),
        "kea_db_name": extensions.cfg.get("kea_db", "database", fallback="kea"),
        "jen_db_host": extensions.cfg.get("jen_db", "host", fallback=""),
        "jen_db_user": extensions.cfg.get("jen_db", "user", fallback=""),
        "jen_db_name": extensions.cfg.get("jen_db", "database", fallback="jen"),
        "ssh_host": extensions.cfg.get("kea_ssh", "host", fallback=""),
        "ssh_user": extensions.cfg.get("kea_ssh", "user", fallback=""),
        "kea_conf": extensions.cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
        "ddns_log": extensions.cfg.get("ddns", "log_path", fallback=""),
        "ddns_url": extensions.cfg.get("ddns", "api_url", fallback=""),
        "ddns_user": extensions.cfg.get("ddns", "api_user", fallback=""),
        "ddns_zone": extensions.cfg.get("ddns", "forward_zone", fallback=""),
        "dns_provider": extensions.cfg.get("ddns", "dns_provider", fallback="technitium"),
        "ha_mode": extensions.cfg.get("kea", "ha_mode", fallback=""),
        "server_name": extensions.cfg.get("kea", "name", fallback="Kea Server 1"),
        "subnets": extensions.SUBNET_MAP,
        "extra_servers": extra_servers,
        # v5.0 Phase 1 — IPv6. kea6_api_url etc. show what's ACTUALLY in
        # [kea6] (blank if absent), not extensions.KEA6_API_URL (which is
        # already fallen back to the v4 value) — the settings UI needs to
        # distinguish "explicitly set" from "inheriting the v4 default" so
        # it can show the placeholder/fallback text correctly instead of
        # looking like v6 has its own creds when it doesn't.
        "kea6_api_url": extensions.cfg.get("kea6", "api_url", fallback=""),
        "kea6_api_user": extensions.cfg.get("kea6", "api_user", fallback=""),
        "kea6_db_host": extensions.cfg.get("kea6_db", "host", fallback=""),
        "kea6_db_user": extensions.cfg.get("kea6_db", "user", fallback=""),
        "kea6_db_name": extensions.cfg.get("kea6_db", "database", fallback=""),
    }
    restart_pending = __user.get_global_setting("restart_pending", "false") == "true"
    ipv6_enabled = __kea6.is_ipv6_enabled()
    return render_template("settings_infrastructure.html", infra=infra, kea_up=kea_up,
                           ssh_pub_key=ssh_pub_key, ssh_configured=bool(ssh_pub_key),
                           restart_pending=restart_pending,
                           ipv6_enabled=ipv6_enabled,
                           http_port=extensions.HTTP_PORT,
                           https_port=extensions.HTTPS_PORT,
                           ssl_configured=__config.ssl_configured())

@bp.route("/settings/infrastructure/save-kea", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea():
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    if not api_url:
        flash("API URL is required.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    items = [("kea", "api_url", api_url), ("kea", "api_user", api_user)]
    if api_pass:
        items.append(("kea", "api_pass", api_pass))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea API settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_api", f"url={api_url} user={api_user}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-kea-db", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    items = [("kea_db", "host", host), ("kea_db", "user", user),
             ("kea_db", "database", database)]
    if password:
        items.append(("kea_db", "password", password))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_db", f"host={host}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-kea6", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea6():
    """
    v5.0 Phase 1 — [kea6] API connection override. Every field is
    optional; leaving them blank (or clearing a previously-set value)
    means Jen falls back to the v4 [kea] connection info at load time
    (jen/config.py's AppConfig.apply()) — the common same-CA case. This
    route only ever writes to [kea6]/[kea6_db]; it does not touch the
    ipv6_enabled display flag or the remote kea-dhcp6-server state — see
    toggle_ipv6() for that.
    """
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    db_host = request.form.get("db_host", "").strip()
    db_user = request.form.get("db_user", "").strip()
    db_pass = request.form.get("db_pass", "").strip()
    db_name = request.form.get("db_name", "").strip()

    items = []
    if api_url:
        items.append(("kea6", "api_url", api_url))
    if api_user:
        items.append(("kea6", "api_user", api_user))
    if api_pass:
        items.append(("kea6", "api_pass", api_pass))
    if db_host:
        items.append(("kea6_db", "host", db_host))
    if db_user:
        items.append(("kea6_db", "user", db_user))
    if db_pass:
        items.append(("kea6_db", "password", db_pass))
    if db_name:
        items.append(("kea6_db", "database", db_name))

    if items:
        __config.app_config.write_values(items)
        __user.set_global_setting("restart_pending", "true")
        flash("Kea6 API settings saved. Restart Jen to apply.", "success")
        __user.audit("SAVE_INFRA", "kea6_api", f"url={api_url or '(inherits v4)'}")
    else:
        flash("No Kea6 values provided — leaving [kea6] as inheriting v4 settings.", "info")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/toggle-ipv6", methods=["POST"])
@login_required
@_superadmin_required
def toggle_ipv6():
    """
    v5.0 Phase 1 — the IPv6 enable/disable toggle. Superadmin-gated: unlike
    the other infrastructure save routes (admin-level), this one has real
    infrastructure side effects — starting/stopping a service across
    potentially multiple remote machines over SSH+sudo, not a harmless
    config-file flag flip.

    Two-layer design (see the v5.0 plan doc):
    1. set_ipv6_service_state() does the actual SSH/systemctl work against
       every configured server and reports per-server success/failure.
    2. Only after seeing those results does this route decide whether to
       flip Jen's own ipv6_enabled DISPLAY flag — so a partial failure
       across an HA pair never leaves Jen showing v6 as "on" when some
       servers never actually started serving it.

    Enabling: the flag only flips to true if EVERY server with ssh_host
    configured succeeded. Any failure (including "no kea-dhcp6.conf on
    this server") leaves the flag false and the fleet unmodified.

    Disabling: the flag always flips to false — the user's intent is v6
    off, and Jen should stop showing v6 UI regardless of whether every
    remote systemctl call succeeded. Any server that failed to actually
    stop is reported so it's visible, not silently inconsistent.
    """
    enable = request.form.get("enable", "").strip() == "true"

    if not any(s.get("ssh_host") for s in extensions.KEA_SERVERS):
        flash("No Kea server has SSH configured — nothing to enable/disable remotely. "
              "Configure SSH under Kea Server settings first.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    results = __kea6.set_ipv6_service_state(enable)
    all_ok = bool(results) and all(r["ok"] for r in results)

    for r in results:
        flash(f"{'✅' if r['ok'] else '❌'} {r['name']}: {r['message']}",
              "success" if r["ok"] else "error")

    if enable:
        if all_ok:
            __user.set_global_setting("ipv6_enabled", "true")
            flash("IPv6 support enabled.", "success")
        else:
            flash("IPv6 was NOT enabled — at least one server failed. "
                  "Fix the issue above and try again.", "error")
    else:
        __user.set_global_setting("ipv6_enabled", "false")
        if not all_ok:
            flash("IPv6 display turned off, but at least one server may still be "
                  "running kea-dhcp6-server — see errors above.", "error")
        else:
            flash("IPv6 support disabled.", "success")

    __user.audit("TOGGLE_IPV6", "ipv6_enabled",
                 f"enable={enable} all_ok={all_ok} servers={len(results)}")
    return redirect(url_for('settings.settings_infrastructure'))


# ── Author a starting Kea config (v5.1) ──────────────────────────────────────
#
# For a genuinely missing kea-dhcp4.conf or kea-dhcp6.conf — NOT the same
# operation as editing an existing subnet (see jen/services/kea_authoring.py
# for the full reasoning). Superadmin-only: this writes a whole new config
# file, a bigger blast radius than a single subnet edit.

def _author_kea_detect(service: str):
    """Shared detection logic for the GET form and both POST routes below —
    connects to the first server with ssh_host configured, prefers reading
    the sibling protocol's real config over autodetecting, and only
    autodetects live interfaces when there's nothing to inherit from.
    Returns (target_server, detected, autodetected_interfaces, ca_socket)
    or (None, ...) if no server has SSH configured at all."""
    target_server = next((s for s in extensions.KEA_SERVERS if s.get("ssh_host")), None)
    if not target_server:
        return None, None, [], None
    detected = {"found": False, "interfaces": [], "lease_db_type": "",
               "lease_db_host": "", "lease_db_name": "", "hooks": []}
    autodetected_interfaces = []
    ca_socket = None
    try:
        ssh = __kea6._connect_ssh(target_server)
        try:
            detected = __authoring.detect_sibling_config(ssh, target_server, service)
            if not detected["found"]:
                autodetected_interfaces = __authoring.autodetect_interfaces(ssh, service)
            ca_socket = __authoring.detect_ca_socket_path(ssh, target_server, service)
        finally:
            ssh.close()
    except Exception as e:
        flash(f"Could not connect to {target_server.get('name', target_server.get('ssh_host'))}: {e}", "error")
    return target_server, detected, autodetected_interfaces, ca_socket


def _author_kea_subnets_and_db(service: str):
    """Default DB connection info comes from Jen's own already-
    authoritative config, never re-typed. The EXISTING subnet map
    (possibly empty — that's expected and fine here) is returned too,
    to pre-fill the wizard's editable subnet list; it is NOT the source
    of truth for what gets built into the generated config — see
    _parse_subnet_lines() below for that. Authoring a config from
    scratch is exactly the case where nothing may exist in Jen yet."""
    if service == "dhcp4":
        existing_subnets = extensions.SUBNET_MAP
        db = {"host": extensions.KEA_DB_HOST, "user": extensions.KEA_DB_USER,
             "password": extensions.KEA_DB_PASS, "name": extensions.KEA_DB_NAME}
    else:
        existing_subnets = extensions.SUBNET6_MAP
        db = {"host": extensions.KEA6_DB_HOST, "user": extensions.KEA6_DB_USER,
             "password": extensions.KEA6_DB_PASS, "name": extensions.KEA6_DB_NAME}
    return existing_subnets, db


def _subnets_to_lines(subnets: dict, service: str) -> str:
    """Render Jen's existing subnet map into the same editable line
    format the wizard's textarea uses (and jen.config's own
    [subnets]/[subnets6] line syntax) — id = name, cidr[, paired_id]."""
    lines = []
    for sid, info in subnets.items():
        line = f"{sid} = {info['name']}, {info['cidr']}"
        if service == "dhcp6" and info.get("paired_subnet4_id") is not None:
            line += f", {info['paired_subnet4_id']}"
        lines.append(line)
    return "\n".join(lines)


def _parse_subnet_lines(text: str, service: str):
    """
    Parse the wizard's editable subnet textarea — one subnet per line,
    `id = name, cidr[, paired_v4_subnet_id]`, the exact same syntax
    jen.config's own [subnets]/[subnets6] sections already use.
    Deliberately reuses AppConfig.derive_subnet_map() (already tested
    against malformed lines, invalid CIDRs, etc. in Phase 1/2) rather
    than writing new parsing logic — the wizard is just letting the
    operator define what would otherwise have to be hand-added to
    jen.config directly. Returns (subnet_dict, error).
    """
    import configparser
    section = "subnets" if service == "dhcp4" else "subnets6"
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(f"[{section}]\n{text}\n")
    except configparser.Error as e:
        return None, f"Could not parse subnet list: {e}"
    subnets = AppConfig.derive_subnet_map(parser, section=section)
    if not subnets:
        return None, "At least one subnet is required — one per line, e.g. \"1 = LAN, 192.168.1.0/24\"."
    return subnets, None


@bp.route("/settings/infrastructure/author-kea/<service>")
@login_required
@_superadmin_required
def author_kea_config(service):
    if service not in ("dhcp4", "dhcp6"):
        flash("Invalid service.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    target_server, detected, autodetected_interfaces, ca_socket = _author_kea_detect(service)
    if not target_server:
        flash("No Kea server has SSH configured — nothing to author against. "
              "Configure SSH under Kea Server settings first.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    existing_subnets, default_db = _author_kea_subnets_and_db(service)
    conf_path = __authoring.conf_path_for(target_server, service)
    default_socket = ca_socket or f"/run/kea/kea-{service}-ctrl-socket"
    subnet_lines = _subnets_to_lines(existing_subnets, service)
    return render_template("author_kea_config.html", service=service,
                           target_server=target_server, conf_path=conf_path,
                           detected=detected, autodetected_interfaces=autodetected_interfaces,
                           default_socket=default_socket, subnet_lines=subnet_lines,
                           has_existing_subnets=bool(existing_subnets), default_db=default_db)


def _author_kea_build_config(service, form):
    interfaces = [i.strip() for i in form.get("interfaces", "").replace(",", "\n").splitlines() if i.strip()]
    control_socket_path = form.get("control_socket", "").strip()
    db_host = form.get("db_host", "").strip()
    db_user = form.get("db_user", "").strip()
    db_name = form.get("db_name", "").strip()

    if not interfaces:
        return None, None, "At least one interface is required."
    if not control_socket_path:
        return None, None, "Control socket path is required."
    if not (db_host and db_user and db_name):
        return None, None, "Database host, username, and name are required."

    subnets, error = _parse_subnet_lines(form.get("subnets", ""), service)
    if error:
        return None, None, error

    _, default_db = _author_kea_subnets_and_db(service)
    lease_db = {"host": db_host, "user": db_user, "name": db_name,
               "password": default_db["password"]}  # Jen's own stored password — never re-typed in the form
    config = __authoring.build_new_kea_config(service, interfaces, lease_db,
                                              control_socket_path, subnets)
    return config, subnets, None


@bp.route("/settings/infrastructure/author-kea/<service>/preview", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_preview(service):
    if service not in ("dhcp4", "dhcp6"):
        return jsonify({"ok": False, "error": "Invalid service."}), 400

    config, subnets, error = _author_kea_build_config(service, request.form)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    server_results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            conf_path = __authoring.conf_path_for(server, service)
            script = __authoring.render_author_config_script(
                service, conf_path, config, allow_overwrite=False, dry_run=True)
            ssh = __kea6._connect_ssh(server)
            try:
                import base64
                enc = base64.b64encode(script.encode()).decode()
                _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
            finally:
                ssh.close()
            if out == "preview-ok":
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                server_results.append({
                    "name": name, "ok": False, "missing_binary": binary,
                    "message": f"{binary} is not installed on this server.",
                })
            elif out.startswith("testerror:"):
                server_results.append({"name": name, "ok": False, "message": out[len("testerror:"):]})
            else:
                server_results.append({"name": name, "ok": False, "message": err or out or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "config": config, "servers": server_results, "all_passed": all_passed})


@bp.route("/settings/infrastructure/author-kea/<service>", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_post(service):
    if service not in ("dhcp4", "dhcp6"):
        flash("Invalid service.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    config, subnets, error = _author_kea_build_config(service, request.form)
    if error:
        flash(error, "error")
        return redirect(url_for('settings.author_kea_config', service=service))

    allow_overwrite = request.form.get("allow_overwrite", "") == "true"
    errors, results = [], []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            conf_path = __authoring.conf_path_for(server, service)
            script = __authoring.render_author_config_script(
                service, conf_path, config, allow_overwrite=allow_overwrite, dry_run=False)
            ssh = __kea6._connect_ssh(server)
            try:
                import base64
                enc = base64.b64encode(script.encode()).decode()
                _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
            finally:
                ssh.close()
            if out == "ok":
                results.append(f"✅ {name}: {conf_path} written. Enable/restart the service to use it.")
            elif out == "exists":
                errors.append(f"❌ {name}: {conf_path} already exists — check \"overwrite\" to replace it.")
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                errors.append(f"❌ {name}: {binary} is not installed on this server — install it and try again.")
            elif out.startswith("testerror:"):
                errors.append(f"❌ {name}: config test failed, nothing written. Error: {out[len('testerror:'):]}")
            else:
                errors.append(f"❌ {name}: {err or out}")
        except Exception as e:
            errors.append(f"❌ {name}: {str(e)}")

    # Persist the subnets used to author this config into Jen's own
    # [subnets]/[subnets6] — only when at least one server genuinely
    # wrote the file. This is what closes the loop this whole flow
    # exists for: authoring a config from a blank slate must leave Jen
    # actually able to see/edit those subnets afterward, not just Kea.
    # Merges with (doesn't replace) any subnets Jen already knew about,
    # so authoring never silently drops existing entries.
    if results:
        existing, _ = _author_kea_subnets_and_db(service)
        merged = dict(existing)
        merged.update(subnets)
        if service == "dhcp4":
            __config.write_subnets_config(merged)
        else:
            __config.write_subnets6_config(merged)

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")
    __user.audit("AUTHOR_KEA_CONFIG", service, f"overwrite={allow_overwrite} servers={len(results)+len(errors)}")
    return redirect(url_for('settings.settings_infrastructure'))


@bp.route("/settings/infrastructure/check-kea-binaries", methods=["POST"])
@login_required
@_superadmin_required
def check_kea_binaries():
    """
    Whether kea-dhcp4/kea-dhcp6 are actually installed on each
    configured server — for both protocols, checked together, since a
    reasonable next question after "why did dhcp6 fail" is "is dhcp4
    actually fine, or was I wrong about that too." A manual check
    (button-triggered), not run automatically on every Settings page
    load — an SSH round trip per server isn't something every visitor
    to this page should pay for.
    """
    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            ssh = __kea6._connect_ssh(server)
            try:
                installed = __authoring.detect_installed_kea_services(ssh)
            finally:
                ssh.close()
            results.append({"name": name, "ok": True, **installed})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    return jsonify({"servers": results})


@bp.route("/settings/infrastructure/check-config-drift", methods=["POST"])
@login_required
@_admin_required
def check_config_drift_route():
    """
    Manual, on-demand check of whether Jen's own subnet map still
    agrees with what Kea's live config actually says — a config-get
    call against the active server (same "one representative server"
    convention as every other live-config read in this app; an HA
    pair's config is expected to be identical across nodes, so
    checking one is representative), not run automatically on every
    Settings page load. The background check_alerts() loop already
    runs this continuously and alerts on new/resolved drift — this
    route exists for on-demand verification without waiting for or
    digging through that alert history.
    """
    from jen.services.config_drift import check_config_drift
    try:
        issues = check_config_drift()
        return jsonify({"ok": True, "issues": issues})
    except Exception as e:
        logger.error(f"Error checking config drift: {e}")
        return jsonify({"ok": False, "error": "Could not check config drift. Check server logs for details."})


@bp.route("/settings/infrastructure/install-kea-binary/<service>", methods=["POST"])
@login_required
@_superadmin_required
def install_kea_binary(service):
    """
    Installs kea-{dhcp4,dhcp6}-server via apt on every configured
    server with SSH set up. Superadmin only — this runs a real
    system-level package install with sudo, a bigger blast radius than
    anything else reachable from this page short of the config-authoring
    write itself.
    """
    if service not in ("dhcp4", "dhcp6"):
        return jsonify({"ok": False, "error": "Invalid service."}), 400

    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            ssh = __kea6._connect_ssh(server)
            try:
                ok, output = __authoring.install_kea_service(ssh, service)
            finally:
                ssh.close()
            results.append({"name": name, "ok": ok, "output": output})
        except Exception as e:
            results.append({"name": name, "ok": False, "output": str(e)})

    all_ok = bool(results) and all(r["ok"] for r in results)
    __user.audit("INSTALL_KEA_BINARY", service,
                 f"all_ok={all_ok} servers={len(results)}")
    return jsonify({"ok": all_ok, "servers": results})


@bp.route("/settings/infrastructure/save-jen-db", methods=["POST"])
@login_required
@_admin_required
def save_infra_jen_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    items = [("jen_db", "host", host), ("jen_db", "user", user),
             ("jen_db", "database", database)]
    if password:
        items.append(("jen_db", "password", password))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Jen database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "jen_db", f"host={host}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-ssh", methods=["POST"])
@login_required
@_admin_required
def save_infra_ssh():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    kea_conf = request.form.get("kea_conf", "").strip()
    if host and not __auth.valid_ssh_target(host):
        flash("Invalid SSH host — must be a valid hostname or IP address.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    if user and not __auth.valid_unix_username(user):
        flash("Invalid SSH user — must be a valid unix username.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    if kea_conf and not __auth.valid_remote_path(kea_conf):
        flash("Invalid Kea config path — must be an absolute path with no special characters.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    items = [("kea_ssh", "host", host), ("kea_ssh", "user", user)]
    if kea_conf:
        items.append(("kea_ssh", "kea_conf", kea_conf))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("SSH settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "ssh", f"host={host} user={user}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-extra-servers", methods=["POST"])
@login_required
@_admin_required
def save_extra_servers():
    names = request.form.getlist("extra_name[]")
    roles = request.form.getlist("extra_role[]")
    api_urls = request.form.getlist("extra_api_url[]")
    api_users = request.form.getlist("extra_api_user[]")
    api_passes = request.form.getlist("extra_api_pass[]")
    ssh_hosts = request.form.getlist("extra_ssh_host[]")
    ssh_users = request.form.getlist("extra_ssh_user[]")
    kea_confs = request.form.getlist("extra_kea_conf[]")

    for h in ssh_hosts:
        if h.strip() and not __auth.valid_ssh_target(h.strip()):
            flash(f"Invalid SSH host: {h.strip()}", "error")
            return redirect(url_for('settings.settings_infrastructure'))
    for u in ssh_users:
        if u.strip() and not __auth.valid_unix_username(u.strip()):
            flash(f"Invalid SSH user: {u.strip()}", "error")
            return redirect(url_for('settings.settings_infrastructure'))
    for kc in kea_confs:
        if kc.strip() and not __auth.valid_remote_path(kc.strip()):
            flash(f"Invalid Kea config path: {kc.strip()}", "error")
            return redirect(url_for('settings.settings_infrastructure'))

    def _rewrite_extra_servers(cfg):
        # Remove all existing extra server sections
        n = 2
        while cfg.has_section(f"kea_server_{n}"):
            cfg.remove_section(f"kea_server_{n}")
            n += 1
        # Add new ones
        for i, (name, role, api_url, api_user, api_pass, ssh_host, ssh_user, kea_conf) in enumerate(
            zip(names, roles, api_urls, api_users, api_passes, ssh_hosts, ssh_users, kea_confs, strict=True),
            start=2
        ):
            if not api_url.strip():
                continue
            sec = f"kea_server_{i}"
            cfg.add_section(sec)
            cfg.set(sec, "name", name.strip() or f"Kea Server {i}")
            cfg.set(sec, "role", role.strip() or "standby")
            cfg.set(sec, "api_url", api_url.strip())
            cfg.set(sec, "api_user", api_user.strip())
            if api_pass.strip():
                cfg.set(sec, "api_pass", api_pass.strip())
            else:
                # Preserve existing password from the current config
                try:
                    existing_pass = extensions.cfg.get(sec, "api_pass", fallback=extensions.KEA_API_PASS)
                    cfg.set(sec, "api_pass", existing_pass)
                except Exception:
                    cfg.set(sec, "api_pass", extensions.KEA_API_PASS)
            cfg.set(sec, "ssh_host", ssh_host.strip())
            cfg.set(sec, "ssh_user", ssh_user.strip())
            cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")

    try:
        __config.app_config.mutate(_rewrite_extra_servers)
    except ValueError as e:
        # strict=True on the zip() inside _rewrite_extra_servers means a
        # form submission whose extra_*[] fields don't all have the same
        # number of entries — malformed or tampered, since Jen's own
        # template always submits all eight together per server row —
        # raises here instead of silently truncating to the shortest
        # list and misaligning one server's fields with another's.
        logger.error(f"Mismatched extra-server form field lengths: {e}")
        flash("Could not save additional servers — form data was inconsistent. Please try again.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    count = len(extensions.KEA_SERVERS) - 1
    flash(f"Additional servers saved — {count} extra server(s) configured.", "success")
    __user.set_global_setting("restart_pending", "true")
    __user.audit("SAVE_INFRA", "extra_servers", f"{count} additional servers configured")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-ddns", methods=["POST"])
@login_required
@_admin_required
def save_infra_ddns():
    log_path = request.form.get("log_path", "").strip()
    dns_provider = request.form.get("dns_provider", "technitium").strip()
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_token = request.form.get("api_token", "").strip()
    forward_zone = request.form.get("forward_zone", "").strip()
    if log_path and not __auth.valid_remote_path(log_path):
        flash("Invalid log path — must be an absolute path with no special characters.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    items = [("ddns", "dns_provider", dns_provider)]
    if log_path:
        items.append(("ddns", "log_path", log_path))
    if api_url:
        items.append(("ddns", "api_url", api_url))
    if api_user:
        items.append(("ddns", "api_user", api_user))
    if api_token:
        items.append(("ddns", "api_token", api_token))
    if forward_zone:
        items.append(("ddns", "forward_zone", forward_zone))
    __config.app_config.write_values(items)
    flash("DDNS settings saved.", "success")
    __user.audit("SAVE_INFRA", "ddns", f"log={log_path} provider={dns_provider}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-ha", methods=["POST"])
@login_required
@_admin_required
def save_ha_settings():
    """Save HA mode for primary Kea server."""
    ha_mode = request.form.get("ha_mode", "").strip()
    server_name = request.form.get("server_name", "").strip()
    items = []
    if ha_mode in ("hot-standby", "load-balancing", "passive-backup", ""):
        items.append(("kea", "ha_mode", ha_mode))
    if server_name:
        items.append(("kea", "name", server_name))
    if items:
        __config.app_config.write_values(items)
    flash("HA settings saved.", "success")
    __user.audit("SAVE_INFRA", "ha_settings", f"mode={ha_mode}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/restart", methods=["POST"])
@login_required
@_admin_required
def restart_jen():
    flash("Jen is restarting...", "success")
    __user.set_global_setting("restart_pending", "false")
    __user.audit("RESTART", "jen", "Manual restart triggered from Infrastructure settings")
    def do_restart():
        import time
        time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])
    threading.Thread(target=do_restart, daemon=True).start()
    return redirect(url_for('settings.settings_infrastructure'))


@bp.route("/settings/save-ports", methods=["POST"])
@login_required
@_admin_required
def save_ports():
    ssl_on = __config.ssl_configured()
    try:
        http_port  = int(request.form.get("http_port",  str(extensions.HTTP_PORT)))
        https_port = int(request.form.get("https_port", str(extensions.HTTPS_PORT)))
    except ValueError:
        flash("Ports must be valid numbers.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    if not (1024 <= http_port <= 65535):
        flash("HTTP port must be between 1024 and 65535.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    if ssl_on and not (1024 <= https_port <= 65535):
        flash("HTTPS port must be between 1024 and 65535.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    if ssl_on and http_port == https_port:
        flash("HTTP and HTTPS ports must be different.", "error")
        return redirect(url_for('settings.settings_infrastructure'))

    items = [("server", "http_port", str(http_port))]
    if ssl_on:
        items.append(("server", "https_port", str(https_port)))
    __config.app_config.write_values(items)

    if ssl_on:
        msg = f"Ports updated — HTTP: {http_port} (redirect), HTTPS: {https_port}. Restarting Jen..."
    else:
        msg = f"HTTP port updated to {http_port}. Restarting Jen..."

    __user.audit("SAVE_PORTS", "settings",
                 f"Ports updated to HTTP:{http_port} HTTPS:{https_port} by {current_user.username}")
    flash(msg, "success")

    def do_restart():
        import time; time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])
    threading.Thread(target=do_restart, daemon=True).start()

    return redirect(url_for('settings.settings_infrastructure'))


@bp.route("/settings/generate-ssh-key", methods=["POST"])
@login_required
@_admin_required
def generate_ssh_key():
    os.makedirs("/etc/jen/ssh", exist_ok=True)
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", extensions.SSH_KEY_PATH, "-N", "", "-C", "jen@your-jen-server"],
            capture_output=True, check=True
        )
        os.chmod(extensions.SSH_KEY_PATH, 0o600)
        subprocess.run(["chown", "www-data:www-data", extensions.SSH_KEY_PATH, extensions.SSH_KEY_PATH + ".pub"], capture_output=True)
        with open(extensions.SSH_KEY_PATH + ".pub") as f:
            pub_key = f.read().strip()
        flash(f"SSH key generated. Add this public key to your-kea-server:\n{pub_key}", "success")
        __user.audit("GENERATE_SSH_KEY", "settings", "SSH key pair generated")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SSH key: {e.stderr.decode() if e.stderr else e}")
        flash("Failed to generate SSH key. Check server logs for details.", "error")
    except Exception as e:
        logger.error(f"Error generating SSH key: {e}")
        flash("Error generating SSH key. Check server logs for details.", "error")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/save-telegram", methods=["POST"])
@login_required
@_admin_required
def save_telegram():
    token = request.form.get("token", "").strip()
    chat_id = request.form.get("chat_id", "").strip()
    threshold = request.form.get("threshold_pct", "80").strip()

    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for('settings.settings'))

    settings_map = {
        "telegram_enabled": "true" if request.form.get("enabled") else "false",
        "telegram_token": token,
        "telegram_chat_id": chat_id,
        "alert_kea_down": "true" if request.form.get("alert_kea_down") else "false",
        "alert_new_lease": "true" if request.form.get("alert_new_lease") else "false",
        "alert_utilization": "true" if request.form.get("alert_utilization") else "false",
        "alert_threshold_pct": threshold,
    }
    for k, v in settings_map.items():
        __user.set_global_setting(k, v)
    flash("Telegram settings saved.", "success")
    __user.audit("SAVE_SETTINGS", "telegram", "Telegram settings updated")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/test-telegram", methods=["POST"])
@login_required
@_admin_required
def test_telegram():
    token = __user.get_global_setting("telegram_token")
    chat_id = __user.get_global_setting("telegram_chat_id")
    if not token or not chat_id:
        flash("Telegram not configured — enter a token and chat ID first.", "error")
        return redirect(url_for('settings.settings'))
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": "🔔 <b>Jen Test</b>\nTelegram alerts are working correctly!", "parse_mode": "HTML"},
            timeout=10
        )
        data = resp.json()
        if data.get("ok"):
            flash("Test message sent successfully.", "success")
        else:
            error_desc = data.get("description", "Unknown error")
            error_code = data.get("error_code", "")
            flash(f"Telegram error {error_code}: {error_desc}", "error")
    except requests.exceptions.ConnectionError:
        flash("Could not connect to Telegram API. Check your internet connection.", "error")
    except requests.exceptions.Timeout:
        flash("Telegram API request timed out.", "error")
    except Exception as e:
        logger.error(f"Unexpected error testing Telegram: {e}")
        flash("Unexpected error. Check server logs for details.", "error")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/save-session", methods=["POST"])
@login_required
@_admin_required
def save_session_settings():
    timeout = request.form.get("timeout_minutes", "60").strip()
    enabled = request.form.get("timeout_enabled", "true").strip()
    if enabled not in ("true", "false"):
        enabled = "true"

    if not timeout.isdigit() or not (0 <= int(timeout) <= 1440):
        flash("Session timeout must be between 0 and 1440 minutes (0 = never).", "error")
        return redirect(url_for('settings.settings'))

    __user.set_global_setting("session_timeout_minutes", timeout)
    __user.set_global_setting("session_timeout_enabled", enabled)

    if enabled == "false":
        flash("Session timeout disabled — sessions will not expire.", "success")
    elif int(timeout) == 0:
        flash("Session timeout enabled — sessions will never expire.", "success")
    else:
        flash(f"Session timeout set to {timeout} minutes.", "success")
    __user.audit("SAVE_SETTINGS", "session", f"enabled={enabled} timeout={timeout}min")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/save-rate-limit", methods=["POST"])
@login_required
@_admin_required
def save_rate_limit():
    max_attempts = request.form.get("max_attempts", "10").strip()
    lockout_minutes = request.form.get("lockout_minutes", "15").strip()
    mode = request.form.get("mode", "both").strip()

    if not max_attempts.isdigit() or int(max_attempts) < 0:
        flash("Max attempts must be 0 or a positive number.", "error")
        return redirect(url_for('settings.settings'))
    if not lockout_minutes.isdigit() or int(lockout_minutes) < 0:
        flash("Lockout duration must be 0 or a positive number.", "error")
        return redirect(url_for('settings.settings'))
    if mode not in ("ip", "username", "both", "off"):
        flash("Invalid lockout mode.", "error")
        return redirect(url_for('settings.settings'))

    __user.set_global_setting("rl_max_attempts", max_attempts)
    __user.set_global_setting("rl_lockout_minutes", lockout_minutes)
    __user.set_global_setting("rl_mode", mode)
    flash("Rate limiting settings saved.", "success")
    __user.audit("SAVE_SETTINGS", "rate_limit", f"max={max_attempts} lockout={lockout_minutes}min mode={mode}")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/clear-lockouts", methods=["POST"])
@login_required
@_admin_required
def clear_lockouts():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM login_attempts")
            db.commit()
        flash("All login attempt records cleared.", "success")
        __user.audit("CLEAR_LOCKOUTS", "settings", "All login attempts cleared")
    except Exception as e:
        logger.error(f"Error clearing lockouts: {e}")
        flash("Error clearing lockouts. Check server logs for details.", "error")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/upload-cert", methods=["POST"])
@login_required
@_admin_required
def upload_cert():
    cert_file = request.files.get("certificate")
    key_file = request.files.get("private_key")
    ca_file = request.files.get("ca_bundle")
    if not cert_file or not key_file:
        flash("Certificate and private key are required.", "error")
        return redirect(url_for('settings.settings'))
    os.makedirs("/etc/jen/ssl", exist_ok=True)
    try:
        cert_data = cert_file.read().decode("utf-8")
        key_data = key_file.read().decode("utf-8")
        if "BEGIN CERTIFICATE" not in cert_data:
            flash("Invalid certificate file — does not appear to be a PEM certificate.", "error")
            return redirect(url_for('settings.settings'))
        if "BEGIN" not in key_data or "PRIVATE KEY" not in key_data:
            flash("Invalid private key file.", "error")
            return redirect(url_for('settings.settings'))
        with open(extensions.SSL_CERT, "w") as f: f.write(cert_data)
        with open(extensions.SSL_KEY, "w") as f: f.write(key_data)
        if ca_file and ca_file.filename:
            ca_data = ca_file.read().decode("utf-8")
            with open(extensions.SSL_CA, "w") as f: f.write(ca_data)
            with open(extensions.SSL_COMBINED, "w") as f:
                f.write(cert_data)
                if not cert_data.endswith("\n"): f.write("\n")
                f.write(ca_data)
        else:
            with open(extensions.SSL_COMBINED, "w") as f: f.write(cert_data)
        os.chmod(extensions.SSL_KEY, 0o640)
        os.chmod(extensions.SSL_CERT, 0o644)
        os.chmod(extensions.SSL_COMBINED, 0o644)
        flash("Certificate uploaded. Jen is restarting...", "success")
        __user.audit("UPLOAD_CERT", "settings", "SSL certificate uploaded")
        def restart():
            import time; time.sleep(2)
            subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])
        threading.Thread(target=restart, daemon=True).start()
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        flash("Error uploading certificate. Check server logs for details.", "error")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/remove-cert", methods=["POST"])
@login_required
@_admin_required
def remove_cert():
    for f in [extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_CA, extensions.SSL_COMBINED]:
        if os.path.exists(f): os.remove(f)
    flash("Certificate removed. Restarting in HTTP mode...", "success")
    def restart():
        import time; time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])
    threading.Thread(target=restart, daemon=True).start()
    return redirect(url_for('settings.settings'))

@bp.route("/settings/upload-favicon", methods=["POST"])
@login_required
@_admin_required
def upload_favicon():
    favicon_file = request.files.get("favicon")
    if not favicon_file or not favicon_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for('settings.settings'))
    if not favicon_file.filename.lower().endswith((".ico", ".png")):
        flash("Favicon must be a .ico or .png file.", "error")
        return redirect(url_for('settings.settings'))
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)
    try:
        favicon_file.save(extensions.FAVICON_PATH)
        flash("Favicon updated.", "success")
    except Exception as e:
        logger.error(f"Error saving favicon: {e}")
        flash("Error saving favicon. Check server logs for details.", "error")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/remove-favicon", methods=["POST"])
@login_required
@_admin_required
def remove_favicon():
    if os.path.exists(extensions.FAVICON_PATH): os.remove(extensions.FAVICON_PATH)
    flash("Favicon removed.", "success")
    return redirect(url_for('settings.settings'))

@bp.route("/settings/icons")
@login_required
@_admin_required
def settings_icons():
    """Custom brand icon management page."""
    bundled = []
    for f in sorted(os.listdir(extensions.ICONS_BUNDLED_DIR)):
        if f.endswith(".svg"):
            name = f.replace(".svg", "")
            custom_override = os.path.exists(f"{extensions.ICONS_CUSTOM_DIR}/{f}")
            bundled.append({"name": name, "file": f, "custom_override": custom_override})
    custom = []
    for f in sorted(os.listdir(extensions.ICONS_CUSTOM_DIR)):
        if f.endswith(".svg"):
            custom.append({"name": f.replace(".svg", ""), "file": f})
    return render_template("settings_icons.html", bundled=bundled, custom=custom)

@bp.route("/settings/icons/upload", methods=["POST"])
@login_required
@_admin_required
def upload_custom_icon():
    svg_file = request.files.get("icon")
    icon_name = request.form.get("icon_name", "").strip().lower()
    if not svg_file or not icon_name:
        flash("Icon file and name are required.", "error")
        return redirect(url_for('settings.settings_icons'))
    if not icon_name.replace("-", "").replace("_", "").isalnum():
        flash("Icon name must be alphanumeric (hyphens/underscores allowed).", "error")
        return redirect(url_for('settings.settings_icons'))
    if not svg_file.filename.endswith(".svg"):
        flash("Only SVG files are accepted.", "error")
        return redirect(url_for('settings.settings_icons'))
    svg_file.seek(0, 2)
    size = svg_file.tell()
    svg_file.seek(0)
    if size > 100 * 1024:
        flash("SVG file must be under 100KB.", "error")
        return redirect(url_for('settings.settings_icons'))
    os.makedirs(extensions.ICONS_CUSTOM_DIR, exist_ok=True)
    dest = f"{extensions.ICONS_CUSTOM_DIR}/{icon_name}.svg"
    svg_file.save(dest)
    # Update MANUFACTURER_ICON_MAP if name matches a known manufacturer
    __user.audit("UPLOAD_ICON", "settings", f"Custom icon '{icon_name}.svg' uploaded by {current_user.username}")
    flash(f"Icon '{icon_name}.svg' uploaded. It will be used for any manufacturer mapped to '{icon_name}'.", "success")
    return redirect(url_for('settings.settings_icons'))

@bp.route("/settings/icons/delete/<name>", methods=["POST"])
@login_required
@_admin_required
def delete_custom_icon(name):
    # Same validation as upload_custom_icon — Flask's default <name>
    # converter already rejects any segment containing "/" (encoded or
    # not), so this isn't reachable as a traversal today, but the check
    # belongs here regardless in case the route ever changes to <path:name>.
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        flash("Invalid icon name.", "error")
        return redirect(url_for('settings.settings_icons'))
    path = f"{extensions.ICONS_CUSTOM_DIR}/{name}.svg"
    if os.path.exists(path):
        os.remove(path)
        __user.audit("DELETE_ICON", "settings", f"Custom icon '{name}.svg' deleted by {current_user.username}")
        flash(f"Custom icon '{name}.svg' removed.", "success")
    else:
        flash("Icon not found.", "error")
    return redirect(url_for('settings.settings_icons'))

@bp.route("/settings/upload-nav-logo", methods=["POST"])
@login_required
@_admin_required
def upload_nav_logo():
    logo_file = request.files.get("logo")
    if not logo_file or not logo_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for('settings.settings_system'))
    ext = logo_file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "svg", "jpg", "jpeg", "webp"):
        flash("Logo must be PNG, SVG, JPG, or WebP.", "error")
        return redirect(url_for('settings.settings_system'))
    logo_file.seek(0, 2)
    size = logo_file.tell()
    logo_file.seek(0)
    if size > 200 * 1024:
        flash("Logo file must be under 200KB.", "error")
        return redirect(url_for('settings.settings_system'))
    # Remove any existing logo files
    for old_ext in ("png", "svg", "jpg", "jpeg", "webp"):
        old = f"{extensions.NAV_LOGO_PATH}.{old_ext}"
        if os.path.exists(old): os.remove(old)
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)
    try:
        logo_file.save(f"{extensions.NAV_LOGO_PATH}.{ext}")
        __user.audit("BRANDING", "settings", f"Nav logo uploaded by {current_user.username}")
        flash("Nav logo updated.", "success")
    except Exception as e:
        logger.error(f"Error saving nav logo: {e}")
        flash("Error saving logo. Check server logs for details.", "error")
    return redirect(url_for('settings.settings_system'))

@bp.route("/settings/remove-nav-logo", methods=["POST"])
@login_required
@_admin_required
def remove_nav_logo():
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        f = f"{extensions.NAV_LOGO_PATH}.{ext}"
        if os.path.exists(f): os.remove(f)
    __user.audit("BRANDING", "settings", f"Nav logo removed by {current_user.username}")
    flash("Nav logo removed.", "success")
    return redirect(url_for('settings.settings_system'))

@bp.route("/settings/save-nav-color", methods=["POST"])
@login_required
@_admin_required
def save_nav_color():
    # Accept value from either the color picker or the text field
    color = request.form.get("nav_color_hex", "").strip() or request.form.get("nav_color", "").strip()
    # Validate — must be empty or a valid hex color
    if color and not re.match(r'^#[0-9a-fA-F]{3,6}$', color):
        flash("Invalid color value. Use a hex code like #1a1a2a.", "error")
        return redirect(url_for('settings.settings_system'))
    __user.set_global_setting("branding_nav_color", color)
    __user.audit("BRANDING", "settings", f"Nav color set to '{color}' by {current_user.username}")
    flash("Nav bar color updated." if color else "Nav bar color reset to default.", "success")
    return redirect(url_for('settings.settings_system'))


# ── Self-update ───────────────────────────────────────────────────────────────

GITHUB_REPO          = "ltkojak/jen-kea"
GITHUB_RELEASES_API  = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


@bp.route("/settings/infrastructure/check-update")
@login_required
@_admin_required
def check_update():
    """Check GitHub releases API for a newer version of Jen."""
    import requests as _req

    from jen import JEN_VERSION
    try:
        resp = _req.get(
            GITHUB_RELEASES_API,
            headers={"Accept": "application/vnd.github+json"},
            timeout=8
        )
        if resp.status_code == 404:
            return jsonify({"status": "no_releases", "current": JEN_VERSION})
        if resp.status_code != 200:
            return jsonify({"status": "error", "message": f"GitHub API returned {resp.status_code}"})

        data = resp.json()
        latest_tag  = data.get("tag_name", "").lstrip("v")
        release_url = data.get("html_url", "")
        published   = data.get("published_at", "")[:10]

        def _ver(v):
            try: return tuple(int(x) for x in v.split(".")[:3])
            except Exception: return (0,0,0)

        if _ver(latest_tag) > _ver(JEN_VERSION):
            # Find the tarball asset
            asset_url = ""
            for asset in data.get("assets", []):
                if asset["name"].endswith(".tar.gz") and "jen-v" in asset["name"]:
                    asset_url = asset["browser_download_url"]
                    break
            return jsonify({
                "status":      "update_available",
                "current":     JEN_VERSION,
                "latest":      latest_tag,
                "release_url": release_url,
                "asset_url":   asset_url,
                "published":   published,
            })
        return jsonify({
            "status":  "up_to_date",
            "current": JEN_VERSION,
            "latest":  latest_tag,
        })
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({"status": "error", "message": "Could not check for updates. Check server logs for details."})


@bp.route("/settings/infrastructure/self-update", methods=["POST"])
@login_required
@_superadmin_required
def self_update():
    """
    Trigger the hardened, root-privileged updater.

    v5.2.6 — SECURITY FIX. This route used to perform the entire
    download, checksum verification, extraction, and file-copy
    pipeline itself while running as www-data, then write a helper
    script to /tmp/jen_update_install.sh and sudo-execute it as root.
    Since /tmp is world-writable and www-data is the exact account
    permitted to write that exact path, the real security boundary was
    "gain any code execution as www-data → write that file yourself →
    sudo it → root" — completely bypassing every validation this route
    performed, since an attacker never needed to go through this route
    at all to reach that sudo rule.

    This route now does none of the download/verify/extract/copy work
    itself. It optionally takes a database backup (unchanged — that's
    Jen backing up its own database with credentials it already
    legitimately has, not a privilege-boundary concern) and then
    triggers `sudo systemctl start --no-block jen-update.service` — a
    fixed, hardcoded command with no attacker-controllable input,
    matching the same already-safe pattern used for
    `sudo systemctl restart jen`. `--no-block` matters here: without
    it, this call would wait for the triggered service to fully
    complete, including its own final `systemctl restart jen` step —
    which kills the very Flask worker process that's blocked waiting
    for this call to return. (v5.2.9 fix: the sudoers rule authorizing
    this command must match it byte-for-byte, including --no-block —
    sudo matches commands literally, and the rule originally
    authorized `start jen-update.service` without that flag, which
    meant every self-update attempt failed with a sudo permission
    denial, not the "sudo systemctl restart jen" pattern working as
    intended.) The entire pipeline now runs
    inside /usr/local/sbin/jen-update-root.py, a script owned
    root:root, mode 0700, that www-data cannot read or modify, and
    which re-derives the release information from GitHub itself rather
    than trusting anything from this request. See that script's own
    docstring for the full design, including why it fails closed on
    checksum verification (a separate issue found in the same review
    that produced this fix).

    One consequence: this route can no longer offer "the release
    changed since you checked, please refresh" — the trigger is now
    "install whatever GitHub currently reports as latest," full stop,
    with no version parameter passed through at all. That's deliberate:
    passing a version through here would reintroduce attacker-
    controllable input into the root-privileged path. Explicit version
    selection (e.g. a deliberate downgrade) still works via the manual
    git+tar+install.sh path, run with real administrator access.
    """
    do_db_backup = request.form.get("db_backup", "0") == "1"

    if do_db_backup:
        try:
            from jen.services import dbexport as _dbexport
            content, fname = _dbexport.export_jen()
            payload = json.loads(content.decode("utf-8"))
            backup_path = _dbexport._write_backup(payload, "jen-pre-update.json.gz")
            flash(f"Database backed up to {backup_path}", "success")
        except Exception as e:
            logger.error(f"Pre-update database backup failed: {e}")
            flash("Database backup failed — aborting update. Check server logs for details.", "error")
            return redirect(url_for("settings.settings_infrastructure"))

    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-update.service"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        logger.error(f"Failed to trigger jen-update.service: {e}")
        flash("Could not start the update — check server logs for details.", "error")
        return redirect(url_for("settings.settings_infrastructure"))

    if result.returncode != 0:
        logger.error(f"jen-update.service failed to start: {result.stderr}")
        flash("Could not start the update — check server logs for details.", "error")
        return redirect(url_for("settings.settings_infrastructure"))

    __user.audit("SELF_UPDATE", "jen", "Triggered update via jen-update.service")
    flash("Update started. This page will refresh automatically once Jen is back.", "success")
    return redirect(url_for("settings.settings_infrastructure", updating="1"))

