"""
jen/services/alerts.py
──────────────────────
Alert channel management: templates, sending, and the background
check_alerts loop that monitors Kea health and HA state.
"""

import json
import logging
import re
import threading
import time
import html

import requests

from jen import extensions

logger = logging.getLogger(__name__)


# ── Lazy service imports (avoids circular imports) ───────────────────────────
def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __jen_db_ctx():
    from jen.models.db import jen_db
    return jen_db()

def __kea_db_ctx():
    from jen.models.db import kea_db
    return kea_db()

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
    "new_reserved_lease": "📌 <b>Reserved Device Online</b>\nA reserved device's IP just went active\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "utilization_high":   "⚠️ <b>Utilization Alert</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage: <b>{pct}%</b> ({used}/{total} addresses)",
    "utilization_ok":     "✅ <b>Utilization Recovery</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage back to <b>{pct}%</b> ({used}/{total} addresses)",
    "pool_exhaustion":    "🔴 <b>Pool Exhaustion Warning</b>\nSubnet <b>{subnet}</b> ({cidr})\nOnly <b>{free}</b> addresses remaining!",
    "reservation_added":  "📌 <b>Reservation Added</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "reservation_deleted":"🗑️ <b>Reservation Deleted</b>\nIP: {ip}\nMAC: {mac}\nSubnet: {subnet}",
    "stale_reservation":  "⏰ <b>Stale Reservation</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nNot seen in {days} days",
    "kea_config_changed": "⚙️ <b>Kea Config Changed</b>\nSubnet {subnet} was modified via Jen\nChange: {details}",
    "daily_summary":      "📊 <b>Daily Summary</b>\n{summary}",
    "rogue_device":       "🚨 <b>{subject}</b>\n{body}",
}

# ── v5.0 Phase 4 — IPv6 alerting: what generalizes, what doesn't ────────────
#
# Decision, not an oversight (per the plan doc's explicit "decide whether
# existing alert types generalize or need v6 variants" checklist item).
# check_alerts() below is a single v4-lease4/hosts-shaped polling loop;
# rather than bolt v6 branches onto it, each alert type was evaluated on
# its own merits:
#
# - kea_down / kea_up / ha_failover: ALREADY protocol-agnostic — these
#   fire on Kea *server* reachability, not on v4 vs v6 leases. No change
#   needed; jen.services.kea6.kea6_is_up() is the v6-specific reachability
#   check already surfaced elsewhere (the /metrics jen_kea6_up gauge), and
#   could feed a v6-specific variant of this alert later if wanted — not
#   done here since it's a genuinely new feature, not a generalization.
# - utilization_high / utilization_ok / pool_exhaustion: DELIBERATELY NOT
#   generalized. Same reasoning as lease6_history's schema (Phase 0/1) and
#   /metrics' missing jen_subnet6_utilization_ratio (Phase 4): a percentage
#   of a /64 pool is not a meaningful signal the way it is for a v4 /24 —
#   "3% used" of 2^64 addresses says nothing useful about exhaustion risk.
#   A genuinely v6-appropriate exhaustion signal (e.g. delegated-prefix
#   pool exhaustion, which IS finite) is a real future feature, not this.
# - new_lease / new_device / stale_reservation: v4-only in this rollout.
#   All three are built on Jen's `devices` table, which the plan's open
#   question #2 explicitly keeps v4-only (device correlation across
#   protocols is out of scope for v5.0 — privacy-extension addresses
#   rotate, DUID-to-MAC extraction only works for 2 of several DUID
#   types). A parallel v6 device-tracking loop would be a real, separate
#   feature, not a small generalization.
# - new_reserved_lease (v5.1.13): same v4-only scope as new_lease/
#   new_device for the same reason — same lease4/hosts query shape.
#   Fires every time a reserved device's lease goes newly active (moved
#   subnets, came back online after being off), using the same
#   last_seen_leases freshness check as new_lease — not a one-time
#   "ever seen" check, since a reserved device coming back after being
#   offline is exactly the case worth knowing about, not just its first
#   appearance ever. Renewals of an already-active reserved lease still
#   don't fire, same as new_lease, since the IP itself doesn't change on
#   a renewal.
# - reservation_added / reservation_deleted / kea_config_changed: found
#   during this audit to NOT actually be wired to fire from any v4 route
#   today (grepped for send_alert() call sites — none exist for these
#   three types; they're defined here as selectable channel filters but
#   currently dead). Nothing to generalize to v6 until the v4 wiring
#   itself exists — adding v6-only alert firing for reservation/subnet
#   writes here would make v6 MORE instrumented than v4, which is
#   backwards and worth fixing on the v4 side first, separately.
# - daily_summary: generalizes cleanly and could include v6 counts as a
#   real future enhancement — not done here to keep this a documentation
#   decision, not new report-building work.
# - rogue_device: Network Discovery plugin only, explicitly documented
#   elsewhere in this rollout as v4-only for v5.0 (see Phase 4's IPAM/
#   network-discovery-plugin note).

ALERT_TYPE_LABELS = {
    "kea_down":           "Kea goes down",
    "kea_up":             "Kea comes back up",
    "ha_failover":        "HA failover / state change",
    "new_lease":          "New dynamic lease",
    "new_device":         "Unknown device detected",
    "new_reserved_lease": "Reserved device's lease goes active",
    "utilization_high":   "Subnet utilization high",
    "utilization_ok":     "Subnet utilization recovery",
    "pool_exhaustion":    "Pool exhaustion warning",
    "reservation_added":  "Reservation added",
    "reservation_deleted":"Reservation deleted",
    "stale_reservation":  "Stale reservation detected",
    "kea_config_changed": "Kea config changed via Jen",
    "daily_summary":      "Daily summary",
    "rogue_device":       "Rogue device detected (Network Discovery plugin)",
}

def get_alert_template(alert_type):
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("SELECT template_text FROM alert_templates WHERE alert_type=%s", (alert_type,))
                row = cur.fetchone()
        if row and row["template_text"]:
            return row["template_text"]
    except Exception:
        pass
    return DEFAULT_TEMPLATES.get(alert_type, "")

def render_template_str(template, **kwargs):
    """Render alert template with variable substitution.

    v5.1.11 — previously only caught KeyError (a placeholder with no
    matching kwarg). str.format() can also raise IndexError (a stray
    positional placeholder like '{0}'), ValueError (an invalid format
    spec, e.g. '{days:d}' against a non-numeric value), or AttributeError
    (a dotted placeholder like '{x.foo}' where the value has no such
    attribute) — any admin-authored template typo in those categories
    used to propagate out of send_alert() uncaught. Since check_alerts()
    wraps its whole loop iteration in one try/except with no per-section
    isolation for these particular calls, that exception skipped every
    remaining check for that cycle — utilization, stale-reservation,
    lease-history snapshot, daily summary — and repeated on every 30s pass
    for as long as the bad template existed, with nothing but a log line
    to show for it. Falling back to the raw template on any formatting
    failure keeps a single bad template from silently disabling unrelated
    monitoring."""
    try:
        return template.format(**kwargs)
    except Exception:
        return template

def safe_text(value):
    """HTML-escape a single untrusted, device-supplied value before it
    goes into an alert template.

    v5.1.15 — hostname (DHCP option 12) is attacker/device-controlled:
    any client on the network can set it to anything, including raw
    '&', '<', '>'. Telegram (parse_mode=HTML) and Pushover (html=1) both
    strictly validate the message as HTML and reject the ENTIRE send if
    it doesn't parse — so a device with an ordinary, not even malicious
    hostname like "AT&T-Hotspot" could silently kill every new_lease/
    new_device alert for that one device, every time, while every other
    device's alerts kept working fine. That's exactly the "some
    notifications never go out" pattern: not a broken channel, not a
    broken alert type — content-dependent, per-message failures with no
    retry and nothing surfaced except a row in alert_log's history that
    nobody's watching in real time.

    This is deliberately applied per-value at each call site, not
    generically to every kwarg inside render_template_str — some kwargs
    (daily_summary's `summary` above all) are pre-built strings that
    already contain deliberate <b> tags from Jen itself, and blanket-
    escaping those would turn the intended bold formatting into visible
    "&lt;b&gt;" text instead of fixing anything."""
    return html.escape(str(value), quote=False)

def get_active_channels():
    """Get all enabled alert channels."""
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM alert_channels WHERE enabled=1")
                channels = cur.fetchall()
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

def channel_allows_subnet(channel, subnet_id):
    """v5.1.16 — per-channel subnet scoping for notifications. NULL/empty
    scope means unrestricted (every channel's existing default, and what
    every channel had implicitly before this existed). subnet_id=None
    means the alert isn't tied to one specific subnet (kea_down,
    ha_failover, daily_summary, etc.) — those always go through
    regardless of scope, since "which subnets do you want lease/device
    alerts for" doesn't apply to them.

    A malformed/unparseable scope value fails OPEN (sends anyway), not
    closed — this is a notification preference, not an access-control
    boundary, and silently going quiet on every alert because of a
    stored JSON typo is a worse outcome here than occasionally
    over-notifying."""
    if subnet_id is None:
        return True
    scope = channel.get("subnet_scope")
    if not scope:
        return True
    try:
        import json
        allowed = json.loads(scope) if isinstance(scope, str) else scope
        if not allowed:
            return True
        return int(subnet_id) in [int(s) for s in allowed]
    except Exception:
        return True

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

def send_alert(alert_type, log_result=True, subnet_id=None, **kwargs):
    """Send alert to all enabled channels that handle this alert type.

    subnet_id (v5.1.16): the raw subnet id an alert relates to, used
    only for per-channel subnet-scope filtering (channel_allows_subnet)
    — never passed into the message template itself. Leave as None for
    alert types that aren't tied to one specific subnet."""
    template = get_alert_template(alert_type)
    message = render_template_str(template, **kwargs)
    channels = get_active_channels()
    results = []
    for channel in channels:
        if not channel_handles_alert(channel, alert_type):
            continue
        if not channel_allows_subnet(channel, subnet_id):
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
            elif ctype == "pushover":
                ok = _send_pushover_channel(message, config)
            elif ctype == "discord":
                ok = _send_discord_channel(message, config)
        except Exception as e:
            error = str(e)
            logger.error(f"Alert send error ({ctype}): {e}")
        if log_result:
            try:
                with __jen_db_ctx() as db:
                    with db.cursor() as cur:
                        cur.execute("""
                            INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (ctype, alert_type, message[:500], "ok" if ok else "failed", error[:500] if error else None))
                    db.commit()
            except Exception as e:
                logger.error(f"Alert log error: {e}")
        results.append((ctype, ok, error))
    return results

def _send_telegram_channel(message, config):
    """v5.1.16 — Telegram's Bot API rate-limits at roughly one message
    per second per chat and returns HTTP 429 with a retry_after value
    when exceeded, with no automatic retry previously. A burst of
    several new leases landing in the same 30-second poll cycle (e.g.
    after an outage, when many devices re-associate at once) sends that
    many sendMessage calls back-to-back with no delay between them —
    easily enough to trip this limit, permanently dropping whichever
    messages got rate-limited with no retry and no distinguishing
    marker beyond a generic "failed" row in alert_log. One retry,
    honoring Telegram's own requested wait (capped at 10s so a single
    alert can't stall the whole 30-second poll loop) covers the
    ordinary burst case without an unbounded retry loop."""
    token = config.get("token", "")
    chat_id = config.get("chat_id", "")
    if not token or not chat_id:
        return False
    last_data = {}
    for attempt in range(2):
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
        data = resp.json()
        if data.get("ok"):
            return True
        last_data = data
        if resp.status_code == 429 and attempt == 0:
            retry_after = data.get("parameters", {}).get("retry_after", 1)
            time.sleep(min(max(retry_after, 1), 10))
            continue
        break
    raise Exception(f"Telegram error: {last_data.get('description', 'Unknown')}")

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
    import html
    # Convert HTML bold to Slack bold
    slack_text = message.replace('<b>', '*').replace('</b>', '*')
    slack_text = re.sub(r'<[^>]+>', '', slack_text)
    # v5.1.15 — message now arrives with untrusted values (hostname, etc.)
    # HTML-escaped (e.g. "AT&amp;T-Hotspot"), so a Slack message would
    # otherwise show the raw escaped entity instead of the actual
    # character. Slack doesn't parse HTML at all, so unescape for display.
    slack_text = html.unescape(slack_text)
    resp = requests.post(webhook_url, json={"text": slack_text}, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"Slack error {resp.status_code}: {resp.text}")
    return True

def _send_webhook_channel(message, alert_type, config):
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False
    import re
    import html
    # v5.1.15 — same unescape-for-plain-text reasoning as Slack/ntfy/
    # Discord. The "html" field below intentionally keeps the raw
    # escaped `message` as-is, for consumers that do want valid HTML.
    plain = html.unescape(re.sub(r'<[^>]+>', '', message).replace('\n', '\n'))
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
    import html
    url = config.get("url", "https://ntfy.sh").rstrip("/")
    topic = config.get("topic", "")
    token = config.get("token", "")
    priority = config.get("priority", "default")
    if not topic:
        raise Exception("ntfy topic not configured")
    # v5.1.15 — unescape for the same reason as Slack/webhook: ntfy
    # doesn't parse HTML, so the raw escaped entity would otherwise show
    # up literally instead of the actual character.
    plain = html.unescape(re.sub(r'<[^>]+>', '', message).strip())
    headers = {"Title": "Jen Alert", "Priority": priority, "Tags": "bell"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{url}/{topic}", data=plain.encode("utf-8"),
                         headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 204):
        raise Exception(f"ntfy error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


def _send_pushover_channel(message, config):
    """Send alert via Pushover."""
    import re
    user_key = config.get("user_key", "")
    api_token = config.get("api_token", "")
    if not user_key or not api_token:
        raise Exception("Pushover user key and API token are required")
    plain = re.sub(r'<[^>]+>', '', message).strip()
    # Use first line as title, rest as message
    lines = plain.split('\n', 1)
    title = lines[0].strip() if lines else "Jen Alert"
    body  = lines[1].strip() if len(lines) > 1 else plain
    resp = requests.post(
        "https://api.pushover.net/1/messages.json",
        data={
            "token":   api_token,
            "user":    user_key,
            "title":   title,
            "message": body,
            "html":    1,
        },
        timeout=10
    )
    data = resp.json()
    if data.get("status") != 1:
        raise Exception(f"Pushover error: {data.get('errors', resp.text)}")
    return True

def _send_discord_channel(message, config):
    """Send alert via Discord webhook."""
    import re
    import html
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise Exception("Discord webhook URL not configured")
    text = message.replace("<b>", "**").replace("</b>", "**")
    text = re.sub(r'<[^>]+>', '', text).strip()
    # v5.1.15 — same unescape-for-plain-text reasoning as Slack/ntfy.
    text = html.unescape(text)
    resp = requests.post(webhook_url, json={"content": text, "username": "Jen DHCP"}, timeout=10)
    if resp.status_code not in (200, 204):
        raise Exception(f"Discord error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True

def take_lease_snapshot():
    """Record current lease counts for all subnets."""
    try:
        retention_days = int(__get_global_setting("history_retention_days", "90"))
        with __kea_db_ctx() as kdb:
            with __jen_db_ctx() as jdb:

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
    except Exception as e:
        logger.error(f"Snapshot error: {e}")

def send_daily_summary():
    """Build and send daily summary."""
    try:
        lines = ["<b>Daily Network Summary</b>"]
        with __kea_db_ctx() as db:
            with __jen_db_ctx() as jdb:
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

    # Seed known_macs from devices table so restarts don't
    # flood with "new device" alerts for every known device
    try:
        with __jen_db_ctx() as jdb:
            with jdb.cursor() as jcur:
                jcur.execute("SELECT mac FROM devices")
                for row in jcur.fetchall():
                    known_macs.add(row["mac"].lower())
        logger.info(f"Seeded {len(known_macs)} known MACs from devices table")
    except Exception as e:
        logger.warning(f"Could not seed known_macs from devices: {e}")

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
                with __kea_db_ctx() as db:
                    with db.cursor() as cur:
                        reserved_lease_mode = __get_global_setting("reserved_lease_mode", "always")
                        # ── Lease tracking ──
                        # v5.1.13 — this used to anti-join out any lease
                        # matching a reservation (WHERE h.host_id IS NULL),
                        # to avoid re-firing "new lease" on every renewal of
                        # every statically-reserved device. But that meant
                        # a reserved device's IP going active — moving
                        # subnets, coming back online after being off — was
                        # invisible forever, not just on its very first
                        # appearance. The fix isn't a separate one-time
                        # "ever seen" check (that would still miss a
                        # reserved device that comes back after being
                        # offline, e.g. moved between subnets) — it's to
                        # keep reservation status as a tag on the SAME
                        # freshness check dynamic leases already use.
                        # last_seen_leases already correctly distinguishes
                        # "this IP is a genuinely new binding" from "this
                        # is just a renewal of an IP already active last
                        # cycle" for the dynamic pool; there's no reason
                        # reserved leases need different freshness logic,
                        # only a different alert type once something IS
                        # fresh.
                        cur.execute("""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id,
                                   (h.host_id IS NOT NULL) AS is_reserved
                            FROM lease4 l
                            LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                                AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                            WHERE l.state=0
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
                            with __jen_db_ctx() as jdb:
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
                        except Exception as e:
                            logger.error(f"Device tracking error: {e}")

                        # ── New lease alerts ──
                        # A row only reaches here once per genuinely new
                        # binding (last_seen_leases already filtered out
                        # renewals) — is_reserved just picks which alert
                        # type describes it. A reserved device gets
                        # new_reserved_lease every time its lease goes
                        # active again, not just once ever; new_device
                        # remains the "genuinely never seen this MAC
                        # before" signal for the dynamic-pool case, since a
                        # reserved MAC is by definition already known.
                        for row in new_lease_rows:
                            mac = __format_mac(row["hwaddr"])
                            subnet_name = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", f"Subnet {row['subnet_id']}")
                            hostname = safe_text(row["hostname"]) if row["hostname"] else "(none)"
                            if row["is_reserved"]:
                                # v5.1.16 — recurrence is now an admin
                                # choice, not something hardcoded either
                                # way. "always" (default, matches the
                                # v5.1.13 fix): fires every time a
                                # reserved lease goes newly active.
                                # "once": fires only the first time a
                                # given reserved MAC is ever seen —
                                # offered as an explicit, documented
                                # option for anyone who actually wants
                                # the old quieter behavior, rather than
                                # that being an accidental bug.
                                if reserved_lease_mode == "once" and mac in known_macs:
                                    continue
                                send_alert("new_reserved_lease", ip=row["ip"], mac=mac,
                                          hostname=hostname, subnet=subnet_name, subnet_id=row["subnet_id"])
                                known_macs.add(mac)
                                continue
                            send_alert("new_lease", ip=row["ip"], mac=mac,
                                      hostname=hostname, subnet=subnet_name, subnet_id=row["subnet_id"])
                            # New device alert — only fire for MACs truly never
                            # seen before (not in devices table, not just unknown
                            # since last restart)
                            if mac not in known_macs:
                                send_alert("new_device", ip=row["ip"], mac=mac,
                                          hostname=hostname, subnet=subnet_name, subnet_id=row["subnet_id"])
                                known_macs.add(mac)  # prevent repeat alerts this session

                        # Update known MACs from all current leases
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
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size,
                                                      subnet_id=sid)
                                            alerted_high_subnets.add(subnet_key)
                                        elif pct < threshold and subnet_key in alerted_high_subnets:
                                            send_alert("utilization_ok", subnet=info["name"],
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size,
                                                      subnet_id=sid)
                                            alerted_high_subnets.discard(subnet_key)
                                        if free <= exhaustion_threshold:
                                            send_alert("pool_exhaustion", subnet=info["name"],
                                                      cidr=info["cidr"], free=free, subnet_id=sid)

                        # ── Stale reservation alerts ──
                        try:
                            stale_days = int(__get_global_setting("stale_device_days", "30"))
                            with __jen_db_ctx() as jdb:
                                with jdb.cursor() as jcur:
                                    jcur.execute(f"""
                                        SELECT mac, last_seen, DATEDIFF(NOW(), last_seen) as days
                                        FROM devices
                                        WHERE last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)
                                    """)
                                    stale_rows = jcur.fetchall()
                            for row in stale_rows:
                                if row["mac"] not in alerted_stale_macs:
                                    # Check if has reservation
                                    mac_hex = row["mac"].replace(":", "")
                                    cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_subnet_id "
                                               "FROM hosts WHERE HEX(dhcp_identifier)=%s", (mac_hex,))
                                    res = cur.fetchone()
                                    if res:
                                        send_alert("stale_reservation", ip=res["ip"] or "",
                                                  mac=row["mac"], hostname=safe_text(res["hostname"]) if res["hostname"] else "",
                                                  days=row["days"], subnet_id=res["dhcp4_subnet_id"])
                                        alerted_stale_macs.add(row["mac"])
                        except Exception as e:
                            logger.error(f"Stale reservation check error: {e}")


            # ── Lease history snapshot ──
            snapshot_interval = int(__get_global_setting("snapshot_interval_minutes", "30")) * 60
            now_ts = time.time()
            if now_ts - last_snapshot_time >= snapshot_interval:
                take_lease_snapshot()
                last_snapshot_time = now_ts

            # ── Daily summary ──
            import datetime as dt
            summary_time = __get_global_setting("daily_summary_time", "07:00")
            now = dt.datetime.now(dt.timezone.utc)
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
