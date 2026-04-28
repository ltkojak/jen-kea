"""
jen/services/alerts.py
──────────────────────
Alert channel management: templates, sending, and the background
check_alerts loop that monitors Kea health and HA state.
"""

import logging
import re
import threading
import time

from jen import extensions

logger = logging.getLogger(__name__)


# ── Lazy service imports (avoids circular imports) ───────────────────────────
def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __get_kea_db():
    from jen.models.db import get_kea_db
    return get_kea_db()

def __kea_command(*a, **kw):
    from jen.services.kea import kea_command
    return kea_command(*a, **kw)

def __kea_is_up(*a, **kw):
    from jen.services.kea import kea_is_up
    return kea_is_up(*a, **kw)

def __get_active_kea_server():
    from jen.services.kea import get_active_kea_server
    return get_active_kea_server()

def __format_mac(*a, **kw):
    from jen.services.kea import format_mac
    return format_mac(*a, **kw)

def __classify_device(*a, **kw):
    from jen.services.fingerprint import classify_device
    return classify_device(*a, **kw)

def __get_device_info_map(*a, **kw):
    from jen.services.fingerprint import get_device_info_map
    return get_device_info_map(*a, **kw)

def __get_global_setting(key, default=None):
    from jen.models.user import get_global_setting
    return get_global_setting(key, default)

def __get_jen_db_direct():
    from jen.models.db import get_jen_db
    return get_jen_db()


DEFAULT_TEMPLATES = {
    "kea_down":           "🚨 <b>Kea Alert</b>\n{server_name} is <b>DOWN</b>!",
    "kea_up":             "✅ <b>Kea Alert</b>\n{server_name} is back <b>UP</b>.",
    "ha_failover":        "⚡ <b>HA Failover</b>\n{server_name} state changed: <b>{old_state}</b> → <b>{new_state}</b>",
    "new_lease":          "🆕 <b>New DHCP Lease</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "new_device":         "🔍 <b>Unknown Device</b>\nNew MAC never seen before\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "utilization_high":   "⚠️ <b>Utilization Alert</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage: <b>{pct}%</b> ({used}/{total} addresses)",
    "utilization_ok":     "✅ <b>Utilization Recovery</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage back to <b>{pct}%</b> ({used}/{total} addresses)",
    "pool_exhaustion":    "🔴 <b>Pool Exhaustion Warning</b>\nSubnet <b>{subnet}</b> ({cidr})\nOnly <b>{free}</b> addresses remaining!",
    "reservation_added":  "📌 <b>Reservation Added</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "reservation_deleted":"🗑️ <b>Reservation Deleted</b>\nIP: {ip}\nMAC: {mac}\nSubnet: {subnet}",
    "stale_reservation":  "⏰ <b>Stale Reservation</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nNot seen in {days} days",
    "kea_config_changed": "⚙️ <b>Kea Config Changed</b>\nSubnet {subnet} was modified via Jen\nChange: {details}",
    "daily_summary":      "📊 <b>Daily Summary</b>\n{summary}",
}

ALERT_TYPE_LABELS = {
    "kea_down":           "Kea goes down",
    "kea_up":             "Kea comes back up",
    "ha_failover":        "HA failover / state change",
    "new_lease":          "New dynamic lease",
    "new_device":         "Unknown device detected",
    "utilization_high":   "Subnet utilization high",
    "utilization_ok":     "Subnet utilization recovery",
    "pool_exhaustion":    "Pool exhaustion warning",
    "reservation_added":  "Reservation added",
    "reservation_deleted":"Reservation deleted",
    "stale_reservation":  "Stale reservation detected",
    "kea_config_changed": "Kea config changed via Jen",
    "daily_summary":      "Daily summary",
}

def get_alert_template(alert_type):
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT template_text FROM alert_templates WHERE alert_type=%s", (alert_type,))
            row = cur.fetchone()
        db.close()
        if row and row["template_text"]:
            return row["template_text"]
    except Exception:
        pass
    return DEFAULT_TEMPLATES.get(alert_type, "")

def render_template_str(template, **kwargs):
    """Render alert template with variable substitution."""
    try:
        return template.format(**kwargs)
    except KeyError:
        return template

def get_active_channels():
    """Get all enabled alert channels."""
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels WHERE enabled=1")
            channels = cur.fetchall()
        db.close()
        return channels
    except Exception as e:
        logger.error(f"get_active_channels error: {e}")
        return []

def channel_handles_alert(channel, alert_type):
    """Check if channel is configured to send this alert type."""
    try:
        alert_types = channel.get("alert_types")
        if not alert_types:
            return False
        if isinstance(alert_types, str):
            import json
            alert_types = json.loads(alert_types)
        return alert_type in alert_types
    except Exception:
        return False

def get_channel_config(channel):
    """Parse channel config JSON."""
    try:
        cfg_data = channel.get("config")
        if not cfg_data:
            return {}
        if isinstance(cfg_data, str):
            import json
            return json.loads(cfg_data)
        return cfg_data
    except Exception:
        return {}

def send_alert(alert_type, log_result=True, **kwargs):
    """Send alert to all enabled channels that handle this alert type."""
    template = get_alert_template(alert_type)
    message = render_template_str(template, **kwargs)
    channels = get_active_channels()
    results = []
    for channel in channels:
        if not channel_handles_alert(channel, alert_type):
            continue
        ctype = channel["channel_type"]
        config = get_channel_config(channel)
        ok = False
        error = ""
        try:
            if ctype == "telegram":
                ok = _send_telegram_channel(message, config)
            elif ctype == "email":
                ok = _send_email_channel(message, alert_type, config)
            elif ctype == "slack":
                ok = _send_slack_channel(message, config)
            elif ctype == "webhook":
                ok = _send_webhook_channel(message, alert_type, config)
            elif ctype == "ntfy":
                ok = _send_ntfy_channel(message, config)
            elif ctype == "discord":
                ok = _send_discord_channel(message, config)
        except Exception as e:
            error = str(e)
            logger.error(f"Alert send error ({ctype}): {e}")
        if log_result:
            try:
                db = __get_jen_db()
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (ctype, alert_type, message[:500], "ok" if ok else "failed", error[:500] if error else None))
                db.commit()
                db.close()
            except Exception as e:
                logger.error(f"Alert log error: {e}")
        results.append((ctype, ok, error))
    return results

def _send_telegram_channel(message, config):
    token = config.get("token", "")
    chat_id = config.get("chat_id", "")
    if not token or not chat_id:
        return False
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
        timeout=10
    )
    data = resp.json()
    if not data.get("ok"):
        raise Exception(f"Telegram error: {data.get('description', 'Unknown')}")
    return True

def _send_email_channel(message, alert_type, config):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587))
    user = config.get("smtp_user", "")
    password = config.get("smtp_pass", "")
    from_addr = config.get("from_addr", user)
    to_addr = config.get("to_addr", "")
    if not host or not to_addr:
        return False
    # Strip HTML tags for email subject, keep for body
    import re
    subject_text = re.sub(r'<[^>]+>', '', message.split('\n')[0])
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Jen Alert: {subject_text}"
    msg["From"] = from_addr
    msg["To"] = to_addr
    # Plain text version
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    # HTML version
    html_body = message.replace('\n', '<br>').replace('<b>', '<strong>').replace('</b>', '</strong>')
    html = f"<html><body style='font-family:sans-serif;'>{html_body}</body></html>"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    use_tls = config.get("use_tls", "true") == "true"
    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.sendmail(from_addr, to_addr, msg.as_string())
    return True

def _send_slack_channel(message, config):
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False
    import re
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    # Convert HTML bold to Slack bold
    slack_text = message.replace('<b>', '*').replace('</b>', '*')
    slack_text = re.sub(r'<[^>]+>', '', slack_text)
    resp = requests.post(webhook_url, json={"text": slack_text}, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"Slack error {resp.status_code}: {resp.text}")
    return True

def _send_webhook_channel(message, alert_type, config):
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False
    import re
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    payload_type = config.get("payload_type", "json")
    headers = {"Content-Type": "application/json"}
    custom_header_name = config.get("header_name", "")
    custom_header_value = config.get("header_value", "")
    if custom_header_name:
        headers[custom_header_name] = custom_header_value
    if payload_type == "json":
        payload = {"alert_type": alert_type, "message": plain, "html": message}
    else:
        payload = {"text": plain}
    resp = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 202, 204):
        raise Exception(f"Webhook error {resp.status_code}: {resp.text[:200]}")
    return True

def _send_ntfy_channel(message, config):
    """Send alert via ntfy.sh or self-hosted ntfy."""
    import re
    url = config.get("url", "https://ntfy.sh").rstrip("/")
    topic = config.get("topic", "")
    token = config.get("token", "")
    priority = config.get("priority", "default")
    if not topic:
        raise Exception("ntfy topic not configured")
    plain = re.sub(r'<[^>]+>', '', message).strip()
    headers = {"Title": "Jen Alert", "Priority": priority, "Tags": "bell"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{url}/{topic}", data=plain.encode("utf-8"),
                         headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 204):
        raise Exception(f"ntfy error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True

def _send_discord_channel(message, config):
    """Send alert via Discord webhook."""
    import re
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise Exception("Discord webhook URL not configured")
    text = message.replace("<b>", "**").replace("</b>", "**")
    text = re.sub(r'<[^>]+>', '', text).strip()
    resp = requests.post(webhook_url, json={"content": text, "username": "Jen DHCP"}, timeout=10)
    if resp.status_code not in (200, 204):
        raise Exception(f"Discord error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True

def take_lease_snapshot():
    """Record current lease counts for all subnets."""
    try:
        retention_days = int(__get_global_setting("history_retention_days", "90"))
        kdb = __get_kea_db()
        jdb = __get_jen_db()

        # Get pool sizes from Kea config
        pool_sizes = {}
        result = __kea_command("config-get", server=__get_active_kea_server())
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[s["id"]] = ip_to_int(end) - ip_to_int(start) + 1

        with kdb.cursor() as kcur:
            with jdb.cursor() as jcur:
                for subnet_id, info in extensions.SUBNET_MAP.items():
                    kcur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    active = kcur.fetchone()["cnt"]
                    kcur.execute("""
                        SELECT COUNT(*) as cnt FROM lease4 l
                        LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                            AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                        WHERE l.state=0 AND l.subnet_id=%s AND h.host_id IS NULL
                    """, (subnet_id,))
                    dynamic = kcur.fetchone()["cnt"]
                    kcur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                    reserved = kcur.fetchone()["cnt"]
                    pool_size = pool_sizes.get(subnet_id, 0)
                    jcur.execute("""
                        INSERT INTO lease_history (subnet_id, active_leases, dynamic_leases, reserved_leases, pool_size)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (subnet_id, active, dynamic, reserved, pool_size))

                # Purge old history
                jcur.execute(f"DELETE FROM lease_history WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL {retention_days} DAY)")
        jdb.commit()
        kdb.close()
        jdb.close()
    except Exception as e:
        logger.error(f"Snapshot error: {e}")

def send_daily_summary():
    """Build and send daily summary."""
    try:
        lines = ["<b>Daily Network Summary</b>"]
        db = __get_kea_db()
        jdb = __get_jen_db()
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                lines.append(f"\n<b>{info['name']}</b> ({info['cidr']}): {active} active, {reserved} reserved")
            # New devices in last 24h
            with jdb.cursor() as jcur:
                jcur.execute("SELECT COUNT(*) as cnt FROM devices WHERE first_seen >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                new_devices = jcur.fetchone()["cnt"]
                jcur.execute("SELECT COUNT(*) as cnt FROM devices")
                total_devices = jcur.fetchone()["cnt"]
        lines.append(f"\nNew devices (24h): <b>{new_devices}</b>")
        lines.append(f"Total known devices: <b>{total_devices}</b>")
        db.close()
        jdb.close()
        summary = "\n".join(lines)
        send_alert("daily_summary", summary=summary)
    except Exception as e:
        logger.error(f"Daily summary error: {e}")

def ip_to_int(ip):
    parts = ip.strip().split(".")
    return sum(int(x) << (8*(3-i)) for i, x in enumerate(parts))

def check_alerts():
    import time
    last_kea_status = True
    last_seen_leases = set()
    known_macs = set()
    alerted_high_subnets = set()
    alerted_stale_macs = set()
    first_run = True
    last_summary_date = None
    last_snapshot_time = 0
    last_ha_states = {}  # server_id -> last known HA state

    while True:
        try:
            # ── Kea up/down — check all servers ──
            for srv in extensions.KEA_SERVERS:
                srv_id = srv["id"]
                srv_up = __kea_is_up(server=srv)
                prev_status = last_kea_status if isinstance(last_kea_status, bool) else last_kea_status.get(srv_id, True)
                if not srv_up and prev_status:
                    send_alert("kea_down", server_name=srv["name"])
                elif srv_up and not prev_status:
                    send_alert("kea_up", server_name=srv["name"])
                if isinstance(last_kea_status, dict):
                    last_kea_status[srv_id] = srv_up
                else:
                    last_kea_status = {s["id"]: __kea_is_up(server=s) for s in extensions.KEA_SERVERS}

                # ── HA state monitoring ──
                if srv_up and len(extensions.KEA_SERVERS) > 1:
                    ha = __kea_command("ha-heartbeat", server=srv)
                    if ha.get("result") == 0:
                        new_state = ha.get("arguments", {}).get("state", "")
                        old_state = last_ha_states.get(srv_id)
                        if old_state is not None and new_state != old_state:
                            send_alert("ha_failover", server_name=srv["name"],
                                      old_state=old_state, new_state=new_state)
                        last_ha_states[srv_id] = new_state

            kea_up = any(isinstance(last_kea_status, dict) and v for v in last_kea_status.values()) if isinstance(last_kea_status, dict) else last_kea_status

            if kea_up:
                db = __get_kea_db()
                try:
                    with db.cursor() as cur:
                        # ── Lease tracking ──
                        cur.execute("""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id
                            FROM lease4 l
                            LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                                AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                            WHERE l.state=0 AND h.host_id IS NULL
                        """)
                        current_leases = set()
                        new_lease_rows = []
                        for row in cur.fetchall():
                            current_leases.add(row["ip"])
                            if not first_run and row["ip"] not in last_seen_leases:
                                new_lease_rows.append(row)

                        # ── Device inventory update ──
                        cur.execute("""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id
                            FROM lease4 l WHERE l.state=0
                        """)
                        all_leases = cur.fetchall()
                        try:
                            jdb = __get_jen_db()
                            with jdb.cursor() as jcur:
                                for row in all_leases:
                                    mac = __format_mac(row["hwaddr"])
                                    manufacturer, device_type, device_icon = __classify_device(mac, row["hostname"] or "")
                                    jcur.execute("""
                                        INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, last_seen,
                                                             manufacturer, device_type, device_icon)
                                        VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
                                        ON DUPLICATE KEY UPDATE
                                            last_ip=%s, last_hostname=%s,
                                            last_subnet_id=%s, last_seen=NOW(),
                                            manufacturer=IF(manufacturer_override IS NULL, %s, manufacturer),
                                            device_type=IF(manufacturer_override IS NULL, %s, device_type),
                                            device_icon=IF(manufacturer_override IS NULL, %s, device_icon)
                                    """, (mac, row["ip"], row["hostname"], row["subnet_id"],
                                          manufacturer, device_type, device_icon,
                                          row["ip"], row["hostname"], row["subnet_id"],
                                          manufacturer, device_type, device_icon))
                            jdb.commit()
                            jdb.close()
                        except Exception as e:
                            logger.error(f"Device tracking error: {e}")

                        # ── New lease alerts ──
                        for row in new_lease_rows:
                            mac = __format_mac(row["hwaddr"])
                            subnet_name = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", f"Subnet {row['subnet_id']}")
                            send_alert("new_lease", ip=row["ip"], mac=mac,
                                      hostname=row["hostname"] or "(none)", subnet=subnet_name)
                            # Unknown device alert
                            if mac not in known_macs:
                                send_alert("new_device", ip=row["ip"], mac=mac,
                                          hostname=row["hostname"] or "(none)", subnet=subnet_name)

                        # Update known MACs
                        for row in all_leases:
                            known_macs.add(__format_mac(row["hwaddr"]))

                        last_seen_leases = current_leases
                        first_run = False

                        # ── Utilization alerts ──
                        kea_cfg = __kea_command("config-get", server=__get_active_kea_server())
                        if kea_cfg.get("result") == 0:
                            threshold = int(__get_global_setting("alert_threshold_pct", "80"))
                            exhaustion_threshold = int(__get_global_setting("pool_exhaustion_free", "5"))
                            for s in kea_cfg["arguments"]["Dhcp4"].get("subnet4", []):
                                sid = s["id"]
                                if sid not in extensions.SUBNET_MAP:
                                    continue
                                info = extensions.SUBNET_MAP[sid]
                                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                                active = cur.fetchone()["cnt"]
                                for pool in s.get("pools", []):
                                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                                    if "-" in p:
                                        start, end = [x.strip() for x in p.split("-")]
                                        pool_size = ip_to_int(end) - ip_to_int(start) + 1
                                        pct = round(active / pool_size * 100) if pool_size > 0 else 0
                                        free = pool_size - active
                                        subnet_key = f"{sid}"
                                        if pct >= threshold and subnet_key not in alerted_high_subnets:
                                            send_alert("utilization_high", subnet=info["name"],
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size)
                                            alerted_high_subnets.add(subnet_key)
                                        elif pct < threshold and subnet_key in alerted_high_subnets:
                                            send_alert("utilization_ok", subnet=info["name"],
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size)
                                            alerted_high_subnets.discard(subnet_key)
                                        if free <= exhaustion_threshold:
                                            send_alert("pool_exhaustion", subnet=info["name"],
                                                      cidr=info["cidr"], free=free)

                        # ── Stale reservation alerts ──
                        try:
                            stale_days = int(__get_global_setting("stale_device_days", "30"))
                            jdb = __get_jen_db()
                            with jdb.cursor() as jcur:
                                jcur.execute(f"""
                                    SELECT mac, last_seen, DATEDIFF(NOW(), last_seen) as days
                                    FROM devices
                                    WHERE last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)
                                """)
                                stale_rows = jcur.fetchall()
                            jdb.close()
                            for row in stale_rows:
                                if row["mac"] not in alerted_stale_macs:
                                    # Check if has reservation
                                    mac_hex = row["mac"].replace(":", "")
                                    cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, hostname FROM hosts WHERE HEX(dhcp_identifier)=%s", (mac_hex,))
                                    res = cur.fetchone()
                                    if res:
                                        send_alert("stale_reservation", ip=res["ip"] or "",
                                                  mac=row["mac"], hostname=res["hostname"] or "",
                                                  days=row["days"])
                                        alerted_stale_macs.add(row["mac"])
                        except Exception as e:
                            logger.error(f"Stale reservation check error: {e}")

                finally:
                    db.close()

            # ── Lease history snapshot ──
            snapshot_interval = int(__get_global_setting("snapshot_interval_minutes", "30")) * 60
            now_ts = time.time()
            if now_ts - last_snapshot_time >= snapshot_interval:
                take_lease_snapshot()
                last_snapshot_time = now_ts

            # ── Daily summary ──
            import datetime as dt
            summary_time = __get_global_setting("daily_summary_time", "07:00")
            now = dt.datetime.now()
            today = now.date()
            try:
                h, m = [int(x) for x in summary_time.split(":")]
                summary_due = now.hour == h and now.minute == m
                if summary_due and last_summary_date != today:
                    send_daily_summary()
                    last_summary_date = today
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Alert thread error: {e}")
        time.sleep(30)

# ─────────────────────────────────────────
# Favicon
# ─────────────────────────────────────────
