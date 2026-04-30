"""
jen/routes/settings.py
───────────────────────
All Settings routes.
"""

import hashlib
import io
import json
import logging
import requests
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
from jen.services.alerts import DEFAULT_TEMPLATES, ALERT_TYPE_LABELS
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("settings", __name__)


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
            cert_info["error"] = str(e)

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
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT ip_address) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            rl_active_ips = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            rl_attempts_1h = cur.fetchone()["cnt"]
        db.close()
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
                           branding=branding)

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
        db = __db.get_jen_db()
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
            cur.execute("SELECT alert_type, template_text FROM alert_templates")
            for row in cur.fetchall():
                templates[row["alert_type"]] = row["template_text"]
        db.close()
    except Exception as e:
        flash(f"Error loading alert settings: {e}", "error")

    # Recent alert log with error details
    recent_alerts = []
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT alert_type, channel_type, status, error, sent_at
                FROM alert_log
                ORDER BY sent_at DESC
                LIMIT 20
            """)
            recent_alerts = cur.fetchall()
        db.close()
    except Exception:
        pass

    summary_time = __user.get_global_setting("daily_summary_time", "07:00")
    pool_exhaustion_free = __user.get_global_setting("pool_exhaustion_free", "5")
    threshold_pct = __user.get_global_setting("alert_threshold_pct", "80")
    return render_template("settings_alerts.html",
                           channels=channels, templates=templates,
                           default_templates=DEFAULT_TEMPLATES,
                           alert_type_labels=ALERT_TYPE_LABELS,
                           summary_time=summary_time,
                           pool_exhaustion_free=pool_exhaustion_free,
                           threshold_pct=threshold_pct,
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
    elif channel_type == "discord":
        config = {
            "webhook_url": request.form.get("discord_webhook", "").strip(),
        }

    # Don't overwrite password if blank
    if channel_id and channel_type == "email" and not config["smtp_pass"]:
        try:
            db = __db.get_jen_db()
            with db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE id=%s", (channel_id,))
                row = cur.fetchone()
                if row:
                    existing = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
                    config["smtp_pass"] = existing.get("smtp_pass", "")
            db.close()
        except Exception:
            pass

    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            if channel_id:
                cur.execute("""
                    UPDATE alert_channels SET channel_name=%s, enabled=%s, config=%s, alert_types=%s
                    WHERE id=%s
                """, (channel_name, enabled, json.dumps(config), json.dumps(alert_types), channel_id))
            else:
                cur.execute("""
                    INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types)
                    VALUES (%s, %s, %s, %s, %s)
                """, (channel_type, channel_name, enabled, json.dumps(config), json.dumps(alert_types)))
        db.commit()
        db.close()
        flash(f"Alert channel '{channel_name}' saved.", "success")
        __user.audit("SAVE_ALERT_CHANNEL", channel_name, f"type={channel_type} enabled={enabled}")
    except Exception as e:
        flash(f"Error saving channel: {str(e)}", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/delete-channel/<int:channel_id>", methods=["POST"])
@login_required
@_admin_required
def delete_alert_channel(channel_id):
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT channel_name FROM alert_channels WHERE id=%s", (channel_id,))
            row = cur.fetchone()
            cur.execute("DELETE FROM alert_channels WHERE id=%s", (channel_id,))
        db.commit()
        db.close()
        flash(f"Alert channel deleted.", "success")
        __user.audit("DELETE_ALERT_CHANNEL", str(channel_id), "")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/test-channel/<int:channel_id>", methods=["POST"])
@login_required
@_admin_required
def test_alert_channel(channel_id):
    import json
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels WHERE id=%s", (channel_id,))
            channel = cur.fetchone()
        db.close()
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
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_templates (alert_type, template_text) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE template_text=%s, updated_at=NOW()
            """, (alert_type, template_text, template_text))
        db.commit()
        db.close()
        flash(f"Template for '{ALERT_TYPE_LABELS.get(alert_type, alert_type)}' saved.", "success")
        __user.audit("SAVE_ALERT_TEMPLATE", alert_type, "Template updated")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/reset-template", methods=["POST"])
@login_required
@_admin_required
def reset_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_templates WHERE alert_type=%s", (alert_type,))
        db.commit()
        db.close()
        flash(f"Template reset to default.", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('settings.settings_alerts'))

@bp.route("/settings/alerts/save-global", methods=["POST"])
@login_required
@_admin_required
def save_alert_global():
    summary_time = request.form.get("summary_time", "07:00").strip()
    pool_free = request.form.get("pool_exhaustion_free", "5").strip()
    threshold = request.form.get("alert_threshold_pct", "80").strip()
    if not pool_free.isdigit() or int(pool_free) < 1:
        flash("Pool exhaustion threshold must be a positive number.", "error")
        return redirect(url_for('settings.settings_alerts'))
    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for('settings.settings_alerts'))
    __user.set_global_setting("daily_summary_time", summary_time)
    __user.set_global_setting("pool_exhaustion_free", pool_free)
    __user.set_global_setting("alert_threshold_pct", threshold)
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
    }
    restart_pending = __user.get_global_setting("restart_pending", "false") == "true"
    return render_template("settings_infrastructure.html", infra=infra, kea_up=kea_up,
                           ssh_pub_key=ssh_pub_key, ssh_configured=bool(ssh_pub_key),
                           restart_pending=restart_pending,
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
    __config.write_config_value("kea", "api_url", api_url)
    __config.write_config_value("kea", "api_user", api_user)
    if api_pass:
        __config.write_config_value("kea", "api_pass", api_pass)
    cfg = load_config()
    extensions.KEA_API_URL = extensions.cfg.get("kea", "api_url")
    extensions.KEA_API_USER = extensions.cfg.get("kea", "api_user")
    extensions.KEA_API_PASS = extensions.cfg.get("kea", "api_pass")
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
    __config.write_config_value("kea_db", "host", host)
    __config.write_config_value("kea_db", "user", user)
    if password:
        __config.write_config_value("kea_db", "password", password)
    __config.write_config_value("kea_db", "database", database)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_db", f"host={host}")
    return redirect(url_for('settings.settings_infrastructure'))

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
    __config.write_config_value("jen_db", "host", host)
    __config.write_config_value("jen_db", "user", user)
    if password:
        __config.write_config_value("jen_db", "password", password)
    __config.write_config_value("jen_db", "database", database)
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
    __config.write_config_value("kea_ssh", "host", host)
    __config.write_config_value("kea_ssh", "user", user)
    if kea_conf:
        __config.write_config_value("kea_ssh", "kea_conf", kea_conf)
    __user.set_global_setting("restart_pending", "true")
    flash("SSH settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "ssh", f"host={host} user={user}")
    return redirect(url_for('settings.settings_infrastructure'))

@bp.route("/settings/infrastructure/save-subnets", methods=["POST"])
@login_required
@_admin_required
def save_infra_subnets():
    ids = request.form.getlist("subnet_id[]")
    names = request.form.getlist("subnet_name[]")
    cidrs = request.form.getlist("subnet_cidr[]")
    errors = []
    new_subnets = {}
    for sid, name, cidr in zip(ids, names, cidrs):
        sid = sid.strip()
        name = name.strip()
        cidr = cidr.strip()
        if not sid or not name or not cidr:
            continue
        if not sid.isdigit():
            errors.append(f"Invalid subnet ID: {sid}")
            continue
        if not __auth.valid_cidr(cidr):
            errors.append(f"Invalid CIDR for subnet {sid}: {cidr}")
            continue
        new_subnets[int(sid)] = {"name": name, "cidr": cidr}
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for('settings.settings_infrastructure'))
    if not new_subnets:
        flash("At least one subnet is required.", "error")
        return redirect(url_for('settings.settings_infrastructure'))
    __config.write_subnets_config(new_subnets)
    extensions.SUBNET_MAP = new_subnets
    flash("Subnet map updated successfully.", "success")
    __user.audit("SAVE_INFRA", "subnets", f"{len(new_subnets)} subnets saved")
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

    # Remove all existing extra server sections
    n = 2
    while extensions.cfg.has_section(f"kea_server_{n}"):
        cfg.remove_section(f"kea_server_{n}")
        n += 1

    # Add new ones
    for i, (name, role, api_url, api_user, api_pass, ssh_host, ssh_user, kea_conf) in enumerate(
        zip(names, roles, api_urls, api_users, api_passes, ssh_hosts, ssh_users, kea_confs), start=2
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
            # Try to preserve existing password
            try:
                existing_pass = extensions.cfg.get(sec, "api_pass", fallback=extensions.KEA_API_PASS)
                cfg.set(sec, "api_pass", existing_pass)
            except Exception:
                cfg.set(sec, "api_pass", extensions.KEA_API_PASS)
        cfg.set(sec, "ssh_host", ssh_host.strip())
        cfg.set(sec, "ssh_user", ssh_user.strip())
        cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")

    with open(CONFIG_FILE, 'w') as f:
        cfg.write(f)

    # Reload server list
    extensions.KEA_SERVERS = __config.load_kea_servers(extensions.cfg)
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
    if log_path:
        __config.write_config_value("ddns", "log_path", log_path)
        extensions.DDNS_LOG = log_path
    __config.write_config_value("ddns", "dns_provider", dns_provider)
    if api_url:
        __config.write_config_value("ddns", "api_url", api_url)
    if api_user:
        __config.write_config_value("ddns", "api_user", api_user)
    if api_token:
        __config.write_config_value("ddns", "api_token", api_token)
    if forward_zone:
        __config.write_config_value("ddns", "forward_zone", forward_zone)
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
    if ha_mode in ("hot-standby", "load-balancing", "passive-backup", ""):
        __config.write_config_value("kea", "ha_mode", ha_mode)
    if server_name:
        __config.write_config_value("kea", "name", server_name)
        # Reload server list
        extensions.KEA_SERVERS = __config.load_kea_servers(extensions.cfg)
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
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
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

    __config.write_config_value("server", "http_port", str(http_port))
    extensions.HTTP_PORT = http_port

    if ssl_on:
        __config.write_config_value("server", "https_port", str(https_port))
        extensions.HTTPS_PORT = https_port
        msg = f"Ports updated — HTTP: {http_port} (redirect), HTTPS: {https_port}. Restarting Jen..."
    else:
        msg = f"HTTP port updated to {http_port}. Restarting Jen..."

    __user.audit("SAVE_PORTS", "settings",
                 f"Ports updated to HTTP:{http_port} HTTPS:{https_port} by {current_user.username}")
    flash(msg, "success")

    def do_restart():
        import time; time.sleep(2)
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
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
        flash(f"Failed to generate SSH key: {e.stderr.decode() if e.stderr else str(e)}", "error")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
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
        flash(f"Unexpected error: {str(e)}", "error")
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
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM login_attempts")
        db.commit()
        db.close()
        flash("All login attempt records cleared.", "success")
        __user.audit("CLEAR_LOCKOUTS", "settings", "All login attempts cleared")
    except Exception as e:
        flash(f"Error clearing lockouts: {str(e)}", "error")
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
            subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
        threading.Thread(target=restart, daemon=True).start()
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        flash(f"Error uploading certificate: {str(e)}", "error")
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
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
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
        flash(f"Error saving favicon: {str(e)}", "error")
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
    path = f"{extensions.ICONS_CUSTOM_DIR}/{name}.svg"
    if os.path.exists(path):
        os.remove(path)
        __user.audit("DELETE_ICON", "settings", f"Custom icon '{name}.svg' deleted by {current_user.username}")
        flash(f"Custom icon '{name}.svg' removed.", "success")
    else:
        flash("Icon not found.", "error")
    return redirect(url_for('settings.settings_icons'))
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
        flash(f"Error saving logo: {str(e)}", "error")
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
    import re
    if color and not re.match(r'^#[0-9a-fA-F]{3,6}$', color):
        flash("Invalid color value. Use a hex code like #1a1a2a.", "error")
        return redirect(url_for('settings.settings_system'))
    __user.set_global_setting("branding_nav_color", color)
    __user.audit("BRANDING", "settings", f"Nav color set to '{color}' by {current_user.username}")
    flash("Nav bar color updated." if color else "Nav bar color reset to default.", "success")
    return redirect(url_for('settings.settings_system'))
