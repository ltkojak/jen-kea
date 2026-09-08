"""
jen/routes/settings/alerts.py
───────────────────────────
Alert channels, templates, and the alert-tuning settings.
"""

import json
import logging

import requests
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.models.user as __user
import jen.services.alerts as __alerts
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.alerts import ALERT_TYPE_LABELS, DEFAULT_TEMPLATES

logger = logging.getLogger(__name__)


@bp.route("/settings/alerts")
@login_required
@_admin_required
def settings_alerts():

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
                        try:
                            ch["config"] = json.loads(ch["config"])
                        except (json.JSONDecodeError, ValueError):
                            ch["config"] = {}
                    if isinstance(ch.get("alert_types"), str):
                        try:
                            ch["alert_types"] = json.loads(ch["alert_types"])
                        except (json.JSONDecodeError, ValueError):
                            ch["alert_types"] = []
                    # v5.1.16 — per-channel subnet scope for notifications
                    if isinstance(ch.get("subnet_scope"), str):
                        try:
                            ch["subnet_scope"] = json.loads(ch["subnet_scope"])
                        except (json.JSONDecodeError, ValueError):
                            ch["subnet_scope"] = None
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
    return render_template(
        "settings_alerts.html",
        channels=channels,
        templates=templates,
        default_templates=DEFAULT_TEMPLATES,
        alert_type_labels=ALERT_TYPE_LABELS,
        summary_time=summary_time,
        pool_exhaustion_free=pool_exhaustion_free,
        threshold_pct=threshold_pct,
        reserved_lease_mode=reserved_lease_mode,
        subnet_map=accessible_subnet_map,
        can_grant_all_subnets=current_user.all_subnets,
        recent_alerts=recent_alerts,
    )


@bp.route("/settings/alerts/save-channel", methods=["POST"])
@login_required
@_admin_required
def save_alert_channel():

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
        return redirect(url_for("settings.settings_alerts"))
    if not channel_name:
        flash("Channel name is required.", "error")
        return redirect(url_for("settings.settings_alerts"))

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
            "user_key": request.form.get("pushover_user_key", "").strip(),
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
                    cur.execute(
                        """
                        UPDATE alert_channels SET channel_name=%s, enabled=%s, config=%s, alert_types=%s, subnet_scope=%s
                        WHERE id=%s
                    """,
                        (channel_name, enabled, json.dumps(config), json.dumps(alert_types), subnet_scope, channel_id),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types, subnet_scope)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                        (
                            channel_type,
                            channel_name,
                            enabled,
                            json.dumps(config),
                            json.dumps(alert_types),
                            subnet_scope,
                        ),
                    )
            db.commit()
        flash(f"Alert channel '{channel_name}' saved.", "success")
        __user.audit("SAVE_ALERT_CHANNEL", channel_name, f"type={channel_type} enabled={enabled}")
    except Exception as e:
        logger.error(f"Error saving alert channel '{channel_name}': {e}")
        flash("Error saving channel. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_alerts"))


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
    return redirect(url_for("settings.settings_alerts"))


@bp.route("/settings/alerts/test-channel/<int:channel_id>", methods=["POST"])
@login_required
@_admin_required
def test_alert_channel(channel_id):

    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM alert_channels WHERE id=%s", (channel_id,))
                channel = cur.fetchone()
        if not channel:
            flash("Channel not found.", "error")
            return redirect(url_for("settings.settings_alerts"))
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
    return redirect(url_for("settings.settings_alerts"))


@bp.route("/settings/alerts/save-template", methods=["POST"])
@login_required
@_admin_required
def save_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    template_text = request.form.get("template_text", "").strip()
    if alert_type not in DEFAULT_TEMPLATES:
        flash("Invalid alert type.", "error")
        return redirect(url_for("settings.settings_alerts"))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alert_templates (alert_type, template_text) VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE template_text=%s, updated_at=NOW()
                """,
                    (alert_type, template_text, template_text),
                )
            db.commit()
        flash(f"Template for '{ALERT_TYPE_LABELS.get(alert_type, alert_type)}' saved.", "success")
        __user.audit("SAVE_ALERT_TEMPLATE", alert_type, "Template updated")
    except Exception as e:
        logger.error(f"Error saving alert template '{alert_type}': {e}")
        flash("Error saving template. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_alerts"))


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
    return redirect(url_for("settings.settings_alerts"))


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
        return redirect(url_for("settings.settings_alerts"))
    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for("settings.settings_alerts"))
    if reserved_lease_mode not in ("always", "once"):
        reserved_lease_mode = "always"
    __user.set_global_setting("daily_summary_time", summary_time)
    __user.set_global_setting("pool_exhaustion_free", pool_free)
    __user.set_global_setting("alert_threshold_pct", threshold)
    __user.set_global_setting("reserved_lease_mode", reserved_lease_mode)
    flash("Global alert settings saved.", "success")
    return redirect(url_for("settings.settings_alerts"))


@bp.route("/settings/save-telegram", methods=["POST"])
@login_required
@_admin_required
def save_telegram():
    token = request.form.get("token", "").strip()
    chat_id = request.form.get("chat_id", "").strip()
    threshold = request.form.get("threshold_pct", "80").strip()

    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for("settings.settings"))

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
    return redirect(url_for("settings.settings"))


@bp.route("/settings/test-telegram", methods=["POST"])
@login_required
@_admin_required
def test_telegram():
    token = __user.get_global_setting("telegram_token")
    chat_id = __user.get_global_setting("telegram_chat_id")
    if not token or not chat_id:
        flash("Telegram not configured — enter a token and chat ID first.", "error")
        return redirect(url_for("settings.settings"))
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": "🔔 <b>Jen Test</b>\nTelegram alerts are working correctly!",
                "parse_mode": "HTML",
            },
            timeout=10,
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
    return redirect(url_for("settings.settings"))
