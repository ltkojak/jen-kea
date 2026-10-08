"""
jen/services/alerts.py
──────────────────────
Alert channel management: templates, sending, and the background
check_alerts loop that monitors Kea health and HA state.
"""

import html
import logging
import re
import time

import requests

from jen import extensions
from jen.services import pools as __pools
from jen.services.leases_sql import ACTIVE_LEASE4, active_lease4

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


def __iter_subnet4(dhcp4_cfg):
    from jen.services.kea_config_view import iter_subnet4

    return iter_subnet4(dhcp4_cfg)


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


def __set_global_setting(key, value):
    from jen.models.user import set_global_setting

    return set_global_setting(key, value)


def __emit_event(*a, **kw):
    from jen.services.events import emit

    return emit(*a, **kw)


def __get_jen_db_direct():
    from jen.models.db import get_jen_db

    return get_jen_db()


def __check_config_drift():
    from jen.services.config_drift import check_config_drift

    return check_config_drift()


def __drift_issue_key(*a, **kw):
    from jen.services.config_drift import issue_key

    return issue_key(*a, **kw)


# v5.50.0 (Q57) — the Lucide icon (jen/services/icons.py) the dashboard's Alert
# Summary shows for each alert type. The API returns the NAME; the page builds
# <svg><use> from a fixed whitelist of names (never from server-supplied HTML).
# tests/test_icons.py keeps this, the sprite and the dashboard's whitelist in step.
ALERT_TYPE_ICONS = {
    "kea_down": "circle-x",
    "kea_up": "circle-check",
    "ha_failover": "zap",
    "new_lease": "clipboard-list",
    "new_device": "badge-question-mark",
    "unknown_device": "badge-question-mark",
    "new_reserved_lease": "pin",
    "utilization_high": "triangle-alert",
    "utilization_ok": "circle-check",
    "pool_exhaustion": "circle-x",
    "pool_exhaustion_ok": "circle-check",
    "pool_forecast": "trending-up",
    "packet_health": "triangle-alert",
    "packet_health_ok": "circle-check",
    "reservation_added": "plus",
    "reservation_deleted": "trash",
    "stale_reservation": "clock",
    "kea_config_changed": "info",
    "config_drift_detected": "triangle-alert",
    "config_drift_resolved": "circle-check",
    "client_problems": "triangle-alert",
    "cert_expiring": "lock",
    "daily_summary": "chart-bar",
    "rogue_device": "siren",
}
DEFAULT_ALERT_ICON = "bell"

DEFAULT_TEMPLATES = {
    "kea_down": "🚨 <b>Kea Alert</b>\n{server_name} is <b>DOWN</b>!",
    "kea_up": "✅ <b>Kea Alert</b>\n{server_name} is back <b>UP</b>.",
    "ha_failover": "⚠️ <b>HA Failover</b>\n{server_name} state changed: <b>{old_state}</b> → <b>{new_state}</b>",
    "new_lease": "ℹ️ <b>New DHCP Lease</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "new_device": "⚠️ <b>Unknown Device</b>\nNew MAC never seen before\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "new_reserved_lease": "ℹ️ <b>Reserved Device Online</b>\nA reserved device's IP just went active\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "utilization_high": "⚠️ <b>Utilization Alert</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage: <b>{pct}%</b> ({used}/{total} addresses)",
    "utilization_ok": "✅ <b>Utilization Recovery</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage back to <b>{pct}%</b> ({used}/{total} addresses)",
    "pool_exhaustion": "🚨 <b>Pool Exhaustion Warning</b>\nSubnet <b>{subnet}</b> ({cidr})\nOnly <b>{free}</b> addresses remaining!",
    "pool_exhaustion_ok": "✅ <b>Pool Exhaustion Recovery</b>\nSubnet <b>{subnet}</b> ({cidr})\n<b>{free}</b> addresses free again.",
    "pool_forecast": "⚠️ <b>Pool Exhaustion Forecast</b>\nSubnet <b>{subnet}</b> ({cidr})\nTrend <b>{trend}/day</b> — on track to reach 90% in ~<b>{days}</b> days ({date})\nPeak so far: {peak}/{total}",
    "packet_health": "⚠️ <b>Packet Health Alert</b> ({status})\n{server_name}: {detail}",
    "packet_health_ok": "✅ <b>Packet Health Recovered</b>\n{server_name} is back to clean packet processing.",
    "reservation_added": "ℹ️ <b>Reservation Added</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "reservation_deleted": "ℹ️ <b>Reservation Deleted</b>\nIP: {ip}\nMAC: {mac}\nSubnet: {subnet}",
    "stale_reservation": "⚠️ <b>Stale Reservation</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nNot seen in {days} days",
    "kea_config_changed": "ℹ️ <b>Kea Config Changed</b>\nSubnet {subnet} was modified via Jen\nChange: {details}",
    "config_drift_detected": "⚠️ <b>Config Drift Detected</b>\n{message}",
    "config_drift_resolved": "✅ <b>Config Drift Resolved</b>\n{message}",
    "client_problems": "⚠️ <b>Client had DHCP trouble</b>\nClient: {mac} {ip}\nWhat: {kind}, {count} in the last hour (as of {at} UTC)\nServer: {server}\nInvestigate: {investigate}",
    "cert_expiring": "⚠️ <b>TLS Certificate Expiring</b>\nJen's HTTPS certificate expires in <b>{days_left}</b> day(s).",
    "daily_summary": "ℹ️ <b>Daily Summary</b>\n{summary}",
    "rogue_device": "🚨 <b>{subject}</b>\n{body}",
}


# One glyph, one meaning — the standard set every default alert message opens
# with (the Settings → Alerts page shows this legend). Customised templates in
# the database are never rewritten.
GLYPH_LEGEND = [
    ("🚨", "Critical", "something is down or about to run out"),
    ("⚠️", "Warning", "needs attention soon"),
    ("✅", "Recovered", "an earlier problem cleared"),
    ("ℹ️", "Information", "something happened; no action needed"),
]

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
# - utilization_high / utilization_ok / pool_exhaustion / pool_exhaustion_ok: DELIBERATELY NOT
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
    "kea_down": "Kea goes down",
    "kea_up": "Kea comes back up",
    "ha_failover": "HA failover / state change",
    "new_lease": "New dynamic lease",
    "new_device": "Unknown device detected",
    "new_reserved_lease": "Reserved device's lease goes active",
    "utilization_high": "Subnet utilization high",
    "utilization_ok": "Subnet utilization recovery",
    "pool_exhaustion": "Pool exhaustion warning",
    "pool_exhaustion_ok": "Pool exhaustion recovery",
    "pool_forecast": "Pool exhaustion forecast (90% within 30 days)",
    "packet_health": "Packet health warn/fail (drops, NAKs, allocation failures)",
    "packet_health_ok": "Packet health recovery",
    "reservation_added": "Reservation added",
    "reservation_deleted": "Reservation deleted",
    "stale_reservation": "Stale reservation detected",
    "kea_config_changed": "Kea config changed via Jen",
    "config_drift_detected": "Config drift detected (Jen's subnet map disagrees with Kea)",
    "config_drift_resolved": "Config drift resolved",
    "client_problems": "Client had DHCP trouble",
    "cert_expiring": "TLS certificate expiring soon",
    "daily_summary": "Daily summary",
    # v5.57.1 (Q74) — legacy, kept in 5.x. Network Discovery 1.2.0 moved
    # to its own plugin-registered type, network-discovery_rogue_device
    # (register_alert_type, Q73's API); this core entry stays only so an
    # install whose channels already opted into it keeps working. No
    # plugin sends under it any more.
    "rogue_device": "Rogue device detected (legacy — superseded by Network Discovery's own alert type)",
}


# v5.57.0 (Q73) — plugin-registered alert types. type_id -> plugin_id, so
# Settings → Alerts can group registered types under "From plugins" with
# the owning plugin's name.
PLUGIN_ALERT_TYPES: dict[str, str] = {}

ALERT_TYPE_MAX_LENGTH = 50  # alert_log.alert_type / alert_templates.alert_type VARCHAR(50)


def register_alert_type(plugin_id: str, type_id: str, *, label: str, icon: str, default_template: str) -> None:
    """Merges `type_id` into ALERT_TYPE_LABELS/ALERT_TYPE_ICONS/
    DEFAULT_TEMPLATES at plugin load. `type_id` must start with
    `<plugin_id>_` so two plugins can never collide, and so a type_id
    alone is enough to tell which plugin owns it if the plugin itself is
    ever removed (its rows in alert_log just keep the id, unlabelled).
    A custom template a channel saved earlier survives a plugin upgrade
    unchanged — templates live in the settings-table-backed
    alert_templates table by type id, exactly like a core type's."""
    prefix = f"{plugin_id}_"
    if not type_id.startswith(prefix):
        raise ValueError(f"type_id {type_id!r} must start with {prefix!r}")
    if len(type_id) > ALERT_TYPE_MAX_LENGTH:
        # alert_log.alert_type and alert_templates.alert_type are VARCHAR(50): a longer id makes every
        # INSERT for that type fail. Raised here, so the plugin fails to load with this message
        # instead of silently losing every alert it sends.
        raise ValueError(
            f"type_id {type_id!r} is {len(type_id)} characters; alert type ids are limited to {ALERT_TYPE_MAX_LENGTH}"
        )
    from jen.services.icons import is_icon

    if not is_icon(icon):
        logger.warning(
            f"plugin {plugin_id}: alert type {type_id!r} names icon {icon!r}, which is not in the sprite - using 'bell'"
        )
        icon = "bell"
    ALERT_TYPE_LABELS[type_id] = label
    ALERT_TYPE_ICONS[type_id] = icon
    DEFAULT_TEMPLATES[type_id] = default_template
    PLUGIN_ALERT_TYPES[type_id] = plugin_id


def get_alert_template(alert_type):
    try:
        with __jen_db_ctx() as db, db.cursor() as cur:
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
        with __jen_db_ctx() as db, db.cursor() as cur:
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


# v5.68.0-beta.9 (Q144): alert types about ONE CLIENT. For these an alert with no attributable subnet is not "not tied to a subnet" (the
# kea_down kind of alert, which goes everywhere): it is a client Jen could not place, and a channel that is scoped to some subnets
# must not receive it. The channel scope is the operator's statement of which clients they want to hear about.
SCOPED_ALERT_TYPES = frozenset({"client_problems"})


def channel_allows_subnet(channel, subnet_id, scoped=False):
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
    over-notifying.

    `scoped=True` (v5.68.0-beta.9, Q144) is for an alert about one client: with no subnet_id it FAILS CLOSED for a channel that has a
    scope (a channel with no scope still receives it). A malformed scope still fails open."""
    scope = channel.get("subnet_scope")
    if subnet_id is None and not scoped:
        return True
    if not scope:
        return True
    try:
        import json

        allowed = json.loads(scope) if isinstance(scope, str) else scope
        if not allowed:
            return True
        if subnet_id is None:
            return False
        return int(subnet_id) in [int(s) for s in allowed]
    except Exception:
        return True


def get_channel_config(channel):
    """Return a channel's config as a dict, decrypting it first if it's
    stored in the v5.7.0 encrypted-at-rest form (see jen/services/crypto.py
    and encode_channel_config below). A legacy plaintext JSON object still
    parses unchanged. Any failure (bad key, corrupt row, JSON typo) yields
    `{}` so a misconfigured channel goes quiet rather than crashing
    dispatch — the same fail-soft stance as channel_allows_subnet()."""
    import json

    cfg_data = channel.get("config")
    if not cfg_data:
        return {}
    if isinstance(cfg_data, dict):
        return cfg_data
    try:
        from jen.services import crypto

        value = json.loads(cfg_data)
        # New form: the JSON column holds a *string* — the `v1:` token.
        # Legacy form: it holds the config object directly.
        if isinstance(value, str) and crypto.is_encrypted(value):
            value = json.loads(crypto.decrypt_secret(value, what="alert channel config"))
        return value if isinstance(value, dict) else {}
    except Exception as e:
        logger.error("Could not decode config for alert channel %r: %s", channel.get("channel_name"), e)
        return {}


def encode_channel_config(config):
    """Serialize a channel config dict for storage, encrypted at rest.

    Returns a JSON string *literal* — `json.dumps("v1:…")` — so the value
    still satisfies the `config` column's JSON validity (MariaDB enforces
    `json_valid()` on a JSON column; a bare Fernet token would fail it).

    Raises (MfaKeyUnavailable) if the encryption key can't be loaded —
    callers surface that as a save error rather than silently writing the
    tokens in plaintext.
    """
    import json

    from jen.services import crypto

    return json.dumps(crypto.encrypt_secret(json.dumps(config)))


def send_alert(alert_type, log_result=True, subnet_id=None, scoped=False, **kwargs):
    """Send alert to all enabled channels that handle this alert type.

    subnet_id (v5.1.16): the raw subnet id an alert relates to, used
    only for per-channel subnet-scope filtering (channel_allows_subnet)
    — never passed into the message template itself. Leave as None for
    alert types that aren't tied to one specific subnet. For an alert about one client (SCOPED_ALERT_TYPES, or `scoped=True`) a
    subnet_id of None means the client could not be placed, and a channel with a subnet scope does not receive it.

    Returns [(channel_type, ok, error), ...] - one entry per channel that was ELIGIBLE (handles this type and allows this subnet),
    so a caller can tell "delivered" from "nobody was eligible" from "every eligible channel failed"."""
    scoped = scoped or alert_type in SCOPED_ALERT_TYPES
    template = get_alert_template(alert_type)
    message = render_template_str(template, **kwargs)
    channels = get_active_channels()
    results = []
    for channel in channels:
        if not channel_handles_alert(channel, alert_type):
            continue
        if not channel_allows_subnet(channel, subnet_id, scoped=scoped):
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
                        cur.execute(
                            """
                            INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                            VALUES (%s, %s, %s, %s, %s)
                        """,
                            (
                                ctype,
                                alert_type,
                                message[:500],
                                "ok" if ok else "failed",
                                error[:500] if error else None,
                            ),
                        )
                    db.commit()
            except Exception as e:
                logger.error(f"Alert log error: {e}")
        # v5.42.0 (Q43) — one event per delivery attempt (per channel),
        # not per send_alert() call, so the timeline shows exactly what
        # was tried and whether it landed.
        __emit_event(
            "alert.sent",
            mac=kwargs.get("mac"),
            ip=kwargs.get("ip"),
            subnet_id=subnet_id,
            server=ctype,
            detail=f"{alert_type} -> {'ok' if ok else 'failed'}" + (f": {error}" if error else ""),
        )
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
            timeout=10,
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
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587))
    user = config.get("smtp_user", "")
    password = config.get("smtp_pass", "")
    from_addr = config.get("from_addr", user)
    to_addr = config.get("to_addr", "")
    if not host or not to_addr:
        return False
    # Strip HTML tags for email subject, keep for body
    subject_text = re.sub(r"<[^>]+>", "", message.split("\n")[0])
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Jen Alert: {subject_text}"
    msg["From"] = from_addr
    msg["To"] = to_addr
    # Plain text version
    plain = re.sub(r"<[^>]+>", "", message).replace("\n", "\n")
    # HTML version
    html_body = message.replace("\n", "<br>").replace("<b>", "<strong>").replace("</b>", "</strong>")
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
    import html

    # Convert HTML bold to Slack bold
    slack_text = message.replace("<b>", "*").replace("</b>", "*")
    slack_text = re.sub(r"<[^>]+>", "", slack_text)
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
    import html

    # v5.1.15 — same unescape-for-plain-text reasoning as Slack/ntfy/
    # Discord. The "html" field below intentionally keeps the raw
    # escaped `message` as-is, for consumers that do want valid HTML.
    plain = html.unescape(re.sub(r"<[^>]+>", "", message).replace("\n", "\n"))
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
    plain = html.unescape(re.sub(r"<[^>]+>", "", message).strip())
    headers = {"Title": "Jen Alert", "Priority": priority, "Tags": "bell"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{url}/{topic}", data=plain.encode("utf-8"), headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 204):
        raise Exception(f"ntfy error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


def _send_pushover_channel(message, config):
    """Send alert via Pushover."""
    user_key = config.get("user_key", "")
    api_token = config.get("api_token", "")
    if not user_key or not api_token:
        raise Exception("Pushover user key and API token are required")
    plain = re.sub(r"<[^>]+>", "", message).strip()
    # Use first line as title, rest as message
    lines = plain.split("\n", 1)
    title = lines[0].strip() if lines else "Jen Alert"
    body = lines[1].strip() if len(lines) > 1 else plain
    resp = requests.post(
        "https://api.pushover.net/1/messages.json",
        data={
            "token": api_token,
            "user": user_key,
            "title": title,
            "message": body,
            "html": 1,
        },
        timeout=10,
    )
    data = resp.json()
    if data.get("status") != 1:
        raise Exception(f"Pushover error: {data.get('errors', resp.text)}")
    return True


def _send_discord_channel(message, config):
    """Send alert via Discord webhook."""
    import html

    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise Exception("Discord webhook URL not configured")
    text = message.replace("<b>", "**").replace("</b>", "**")
    text = re.sub(r"<[^>]+>", "", text).strip()
    # v5.1.15 — same unescape-for-plain-text reasoning as Slack/ntfy.
    text = html.unescape(text)
    resp = requests.post(webhook_url, json={"content": text, "username": "Jen DHCP"}, timeout=10)
    if resp.status_code not in (200, 204):
        raise Exception(f"Discord error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


def take_lease_snapshot():
    """Record current lease counts for all subnets."""
    try:
        with __kea_db_ctx() as kdb, __jen_db_ctx() as jdb:
            # Get pool sizes from Kea config
            pool_sizes = {}
            pool_defs = {}  # subnet id -> its pool list, for pool consumption (None for every subnet when Kea's config was not readable)
            result = __kea_command("config-get", server=__get_active_kea_server())
            config_read = result.get("result") == 0
            if config_read:
                for s, _sn in __iter_subnet4(result["arguments"].get("Dhcp4", {})):
                    pool_defs[s["id"]] = s.get("pools", [])
                    # v5.68.0-beta.18 (Q153): the TOTAL of every pool (ranges and CIDRs, merged) - it was the last range's size, and a CIDR
                    # pool was skipped. This number is what lease_history, Health, Reports, Prometheus and the forecast read back.
                    size = __pools.total_pool_size(s.get("pools", []))
                    if size:
                        pool_sizes[s["id"]] = size

            with kdb.cursor() as kcur, jdb.cursor() as jcur:
                for subnet_id, _info in extensions.SUBNET_MAP.items():
                    kcur.execute(
                        f"SELECT COUNT(*) as cnt FROM lease4 WHERE {ACTIVE_LEASE4} AND subnet_id=%s",  # nosec B608 - a fixed constant
                        (subnet_id,),
                    )
                    active = kcur.fetchone()["cnt"]
                    kcur.execute(
                        f"""
                        SELECT COUNT(*) as cnt FROM lease4 l
                        LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                            AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                        WHERE {active_lease4("l")} AND l.subnet_id=%s AND h.host_id IS NULL
                    """,
                        (subnet_id,),
                    )
                    dynamic = kcur.fetchone()["cnt"]
                    kcur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                    reserved = kcur.fetchone()["cnt"]
                    pool_size = pool_sizes.get(subnet_id, 0)
                    # v5.68.0-beta.19 (Q154): the persisted number every derived capacity figure reads - the active leases INSIDE the pools.
                    # NULL (unknown, never 0) when Kea's config could not be read: a zero would be a reading.
                    pool_used = (
                        __pools.consumption(kcur, subnet_id, pool_defs.get(subnet_id, [])) if config_read else None
                    )
                    jcur.execute(
                        """
                        INSERT INTO lease_history (subnet_id, active_leases, dynamic_leases, reserved_leases, pool_size, pool_used)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                        (subnet_id, active, dynamic, reserved, pool_size, pool_used),
                    )

            jdb.commit()
    except Exception as e:
        logger.error(f"Snapshot error: {e}")
    # v5.68.0-beta.17 (Q152): the IPv6 counts are recorded by the same pass, and only when IPv6 is on - a v4-only install does not
    # even reach take_lease6_snapshot's body. Its failure never takes the v4 snapshot above down with it (that is already committed).
    try:
        from jen.services import kea6 as _kea6

        if _kea6.is_ipv6_enabled():
            take_lease6_snapshot()
    except Exception as e:
        logger.error(f"IPv6 snapshot error: {e}")


def take_lease6_snapshot():
    """v5.68.0-beta.17 (Q152) - fill `lease6_history`, which migration 11 created in v5.0 and nothing ever wrote (so every install had
    an empty table, the backup described "historical IPv6 lease counts" that did not exist, and an IPv6 subnet had no history on
    Reports). One row per IPv6 subnet per snapshot: the ACTIVE leases by type (IA_NA addresses, IA_TA, IA_PD delegated prefixes) and the
    reservations by type (address, prefix), counted with the predicate the pages use (`ACTIVE_LEASE6`). There is deliberately no pool size column: a /64 has no finite pool to measure
    utilization against (migration 11). Counted by two aggregate queries (`kea6.count_lease6_by_subnet` / `count_reservations6_by_subnet`,
    v5.68.0-beta.18); old rows are removed by `purge_history` with the IPv4 history's `history_retention_days`."""
    from jen.services import kea6 as _kea6

    # v5.68.0-beta.18 (Q153): two aggregate queries for the whole map (it was `list_lease6` + `get_ipv6_reservations` per subnet,
    # materialising every lease with a MAC lookup each), and no DELETE here: the retention of every history table is one
    # unconditional pass (`take_lease_snapshot`), so turning IPv6 off no longer leaves months of rows behind forever.
    leases = _kea6.count_lease6_by_subnet()
    reservations = _kea6.count_reservations6_by_subnet()
    with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
        for subnet_id in list(extensions.SUBNET6_MAP):
            active = leases.get(subnet_id, {})
            reserved = reservations.get(subnet_id, {})
            active = {"IA_NA": active.get("IA_NA", 0), "IA_TA": active.get("IA_TA", 0), "IA_PD": active.get("IA_PD", 0)}
            reserved = {"IA_NA": reserved.get("IA_NA", 0), "IA_PD": reserved.get("IA_PD", 0)}
            jcur.execute(
                "INSERT INTO lease6_history (subnet_id, active_na, active_ta, active_pd, reserved_na, reserved_pd) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (subnet_id, active["IA_NA"], active["IA_TA"], active["IA_PD"], reserved["IA_NA"], reserved["IA_PD"]),
            )


def _packet_stat_key(key):
    """pkt4-* (all of it — received/sent/drop reasons, present and
    future) plus the two v4-* counters packet health cares about."""
    return key.startswith(("pkt4-", "v4-allocation-fail")) or key == "v4-lease-reuses"


def take_server_stats_snapshot():
    """Record pkt4-*/v4-allocation-fail*/v4-lease-reuses counters for every
    Kea server (packet health, Q42). One row per server per snapshot;
    `stats` captures whatever keys statistic-get-all actually returns, so a
    newer Kea version's counters show up without a Jen upgrade."""
    import json

    try:
        with __jen_db_ctx() as jdb:
            with jdb.cursor() as jcur:
                for srv in extensions.KEA_SERVERS:
                    try:
                        result = __kea_command("statistic-get-all", server=srv)
                    except Exception as e:
                        logger.warning(f"Packet health snapshot ({srv['name']}): {e}")
                        continue
                    if result.get("result") != 0:
                        continue
                    args = result.get("arguments", {})
                    stats = {}
                    for key, samples in args.items():
                        if not _packet_stat_key(key):
                            continue
                        try:
                            stats[key] = int(samples[0][0])
                        except (TypeError, IndexError, ValueError):
                            continue
                    if not stats:
                        continue
                    jcur.execute(
                        "INSERT INTO server_stats (server_id, stats) VALUES (%s, %s)",
                        (srv["id"], json.dumps(stats)),
                    )

            jdb.commit()
    except Exception as e:
        logger.error(f"Server stats snapshot error: {e}")


def run_snapshot_pass() -> None:
    """The periodic snapshot job (v5.68.0-beta.19, Q154): the Kea-facing snapshots, the packet-health alert, then Jen's own retention -
    `purge_history` runs in a `finally`, so a Kea outage (or a snapshot that raised) never stops it."""
    try:
        take_lease_snapshot()
        take_server_stats_snapshot()
        _check_packet_health_alerts()
    finally:
        purge_history()


def purge_history() -> dict:
    """Every history table's retention, in ONE place, on Jen's own database alone (v5.68.0-beta.19, Q154). The deletes of `lease_history` and
    `lease6_history` used to run inside `take_lease_snapshot` after the Kea database was opened - a Kea outage stopped Jen's own retention
    - and `server_stats` inside the stats snapshot. None of them needs Kea: this touches `jen_db` only, each table in its own try (one failure
    never stops the rest), and is called by the snapshot job AFTER the Kea snapshots whatever their outcome and by the daily cleanup job.

        lease_history, lease6_history, server_stats   `history_retention_days`   (default 90)
        events                                        `events_retention_days`    (default 90)
        alert_log                                     `alert_log_retention_days` (default 180)
        audit_log                                     `audit_retention_days`     (default 90; 0 = keep forever) - by `created_at`; the cleanup
                                                      this replaced deleted by a `timestamp` column the table does not have, so it never ran

    Returns {table: rows removed, or None when that table's purge failed}."""
    removed = {}

    def days(key, default):
        try:
            value = int(__get_global_setting(key, str(default)))
        except (TypeError, ValueError):
            return default
        return value

    history = days("history_retention_days", 90)
    plan = (
        ("lease_history", "DELETE FROM lease_history WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL %s DAY)", history),
        (
            "lease6_history",
            "DELETE FROM lease6_history WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL %s DAY)",
            history,
        ),
        ("server_stats", "DELETE FROM server_stats WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL %s DAY)", history),
        ("events", "DELETE FROM events WHERE ts < DATE_SUB(NOW(), INTERVAL %s DAY)", days("events_retention_days", 90)),
        (
            "audit_log",
            "DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
            days("audit_retention_days", 90),
        ),
    )
    for table, sql, keep in plan:
        if table == "audit_log" and keep <= 0:
            continue  # 0 = keep forever
        try:
            with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
                jcur.execute(sql, (keep,))
                removed[table] = jcur.rowcount
        except Exception as e:
            logger.error(f"History retention ({table}): {e}")
            removed[table] = None
    removed["alert_log"] = _purge_old_alert_log()
    return removed


ALERT_LOG_DEFAULT_RETENTION_DAYS = 180
ALERT_LOG_PRUNED_KEY = "alert_log_pruned_totals"


def alert_log_retention_days() -> int:
    """v5.68.0-beta.17 (Q152) - how long a delivery-log row is kept: the `alert_log_retention_days` setting (a settings key beside
    `events_retention_days`), default 180. A value that is not a whole number of days, or is below 1, is the default - a typo must
    not turn into "delete everything" or "keep nothing"."""
    try:
        days = int(__get_global_setting("alert_log_retention_days", str(ALERT_LOG_DEFAULT_RETENTION_DAYS)))
    except (TypeError, ValueError):
        return ALERT_LOG_DEFAULT_RETENTION_DAYS
    return days if days >= 1 else ALERT_LOG_DEFAULT_RETENTION_DAYS


def _purge_old_alert_log():
    """v5.68.0-beta.17 (Q152) - `alert_log` was the one history table nothing pruned: a row on every delivery (and one per client and
    kind per day from the Problems alert), read by the Alerts log, the dashboard, the Timeline and a client's alert status. Rows older
    than `alert_log_retention_days` are removed in the same pass as the other history tables.

    `jen_alerts_sent_total` is a Prometheus COUNTER built from this table, and a counter that drops is read as a reset. So what is
    removed is first counted into `alert_log_pruned_totals` (a JSON object keyed "type|status") in the same transaction, and
    `alert_sent_totals()` adds the two back together: the exported number never goes down.

    v5.68.0-beta.20 (Q155): the pass SERIALISES FIRST and counts after. beta.17 counted the expiring rows and only then took `FOR UPDATE` on the
    totals row, and this runs from the alert thread every `snapshot_interval_minutes` AND from the daily 00:05 cleanup - two overlapping passes
    both counted the same rows, so a counter that by design never decreases was permanently high; and a `FOR UPDATE` on a row that does not exist
    yet (the first purge) serialises nothing. Now: (1) the totals row is created if absent (`INSERT IGNORE`, its own committed statement so its
    shared lock is gone before the next one asks for the exclusive one - two passes would otherwise deadlock on the upgrade); (2) it is locked
    `FOR UPDATE`; (3) only THEN are the expiring rows counted, deleted and added - a second pass waits at (2), then finds the rows already gone;
    (4) the DELETE's rowcount must equal what was counted, else everything rolls back. Stored totals that are not a JSON object are never
    overwritten: the pass fails, the rows stay, the error is logged.

    Returns the number of rows removed, or None when the purge failed (`purge_history` reports that as a failure, never as "nothing to remove")."""
    import json

    try:
        days = alert_log_retention_days()
        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
            jcur.execute(
                "INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (%s, %s)", (ALERT_LOG_PRUNED_KEY, "{}")
            )
        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
            jcur.execute("SELECT setting_value FROM settings WHERE setting_key=%s FOR UPDATE", (ALERT_LOG_PRUNED_KEY,))
            row = jcur.fetchone()
            try:
                totals = json.loads(row["setting_value"]) if row else None
            except (TypeError, ValueError):
                totals = None
            if not isinstance(totals, dict):
                logger.error(
                    f"Alert log retention: the stored {ALERT_LOG_PRUNED_KEY} is not a JSON object - nothing was purged and nothing was overwritten"
                )
                jdb.rollback()
                return None
            jcur.execute("SELECT DATE_SUB(NOW(), INTERVAL %s DAY) AS cutoff", (days,))
            cutoff = jcur.fetchone()["cutoff"]
            jcur.execute(
                "SELECT alert_type, status, COUNT(*) AS cnt FROM alert_log WHERE sent_at < %s GROUP BY alert_type, status",
                (cutoff,),
            )
            gone = jcur.fetchall()
            if not gone:
                jdb.rollback()
                return 0
            counted = 0
            for g in gone:
                key = f"{g['alert_type']}|{g['status']}"
                totals[key] = int(totals.get(key, 0)) + int(g["cnt"])
                counted += int(g["cnt"])
            jcur.execute("DELETE FROM alert_log WHERE sent_at < %s", (cutoff,))
            if jcur.rowcount != counted:
                logger.error(
                    f"Alert log retention: counted {counted} expiring rows but the DELETE removed {jcur.rowcount} - rolled back, nothing changed"
                )
                jdb.rollback()
                return None
            jcur.execute(
                "UPDATE settings SET setting_value=%s WHERE setting_key=%s", (json.dumps(totals), ALERT_LOG_PRUNED_KEY)
            )
            return counted
    except Exception as e:
        logger.error(f"Alert log retention purge error: {e}")
        return None


def alert_sent_totals(cur) -> dict:
    """{(alert_type, status): count} of every delivery ever recorded: the rows still in `alert_log` plus those the retention job has
    already removed. `cur` is an open jen_db cursor. This is what `jen_alerts_sent_total` exports (a counter never decreases)."""
    import json

    totals: dict = {}
    cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (ALERT_LOG_PRUNED_KEY,))
    row = cur.fetchone()
    try:
        pruned = json.loads(row["setting_value"]) if row else {}
    except (TypeError, ValueError):
        pruned = {}
    for key, n in pruned.items() if isinstance(pruned, dict) else ():
        atype, _, status = str(key).partition("|")
        totals[(atype, status)] = int(n)
    cur.execute("SELECT alert_type, status, COUNT(*) AS cnt FROM alert_log GROUP BY alert_type, status")
    for r in cur.fetchall():
        k = (str(r["alert_type"]), str(r["status"]))
        totals[k] = totals.get(k, 0) + int(r["cnt"])
    return totals


# ── Transition state for threshold alerts, in the settings table (v5.68.0-beta.18, Q153) ─────────────────────────────────────────────
# `utilization_high`/`utilization_ok`, `pool_exhaustion`/`pool_exhaustion_ok` and `packet_health`/`packet_health_ok` fire on a TRANSITION, so
# something has to remember which side a condition is on. That memory was a local set of `check_alerts()`: a Jen restart (every upgrade) re-sent
# every alert whose condition was still true and never sent the `_ok` for one that cleared while Jen was down - and pool_exhaustion had no state
# at all and re-sent every cycle. The state is now a settings row per (alert type, key), `alert_state:<type>:<key>` = "1" while the condition
# holds - the same pattern `pool_forecast_alerted_<id>` already used - read on every pass.
#
# v5.68.0-beta.19 (Q154) - the state also knows whether ANYONE WAS TOLD. beta.18 set it after the send whatever the send returned: every channel
# down, or no channel eligible yet, and the condition was marked handled until it recovered - and a later `_ok` went out for a warning nobody
# had received. The value is now a small JSON object: `a` active, `n` notified (true only when at least one ELIGIBLE channel returned ok),
# `t` the time of the last attempt, `c` the attempts since it last changed, `d` when it was notified. A pending notification retries with backoff
# (1, 2, 4 ... 60 minutes) for as long as the condition holds - including after a channel is enabled later; the `_ok` goes out only after a
# delivered warning. One helper, `notify_condition`, does this for utilization, pool_exhaustion, packet_health, cert_expiring and pool_forecast.
#
# v5.68.0-beta.20 (Q155) - three more edges of the same contract. (1) A RECOVERY is state too: `r` (recovery pending) is set when the `_ok` was
# not delivered, the condition is inactive, and each pass retries the `_ok` with the same backoff until a channel takes it - or the condition
# comes back (the earlier warning stands; nothing is re-sent). The warning is never re-sent while a recovery waits. (2) beta.18's "1" is read as
# active and NOT notified: beta.18 wrote it without checking the send, so "delivered" was a guess; one attempt on the next pass (a possible single
# duplicate beats a missed warning). (3) The state is written only when it changed: the quiet path used to upsert a settings row per (type, key)
# on every 30-second pass.

#: v5.68.0-beta.20 (Q155) - how often the certificate and forecast CONDITIONS are evaluated by the alert loop. They ran once per process-day, but
#: `notify_condition` retries a failed delivery after 1, 2, 4 ... minutes: a one-day certificate warning whose channel was down was next tried
#: tomorrow, after the certificate had expired. Evaluating a delivered condition is free (nothing is written, nothing is sent); the EXPENSIVE inputs
#: - the certificate file's days-left and the forecast fit - are cached for `CONDITION_CACHE_MINUTES`.
CONDITION_INTERVAL_MINUTES = 15
CONDITION_CACHE_MINUTES = 60
_CONDITION_CACHE: dict = {}

_BACKOFF_MINUTES = (1, 2, 4, 8, 16, 32, 60)


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(tzinfo=None)


def _alert_state_key(alert_type, key) -> str:
    return f"alert_state:{alert_type}:{key}"


def _load_state(alert_type, key) -> dict:
    """{"a": active, "n": notified, "t": iso | None, "c": attempts, "d": iso | None, "r": recovery pending}. A value written by beta.18 ("1"/"0")
    is read as active-and-NOT-notified / inactive (v5.68.0-beta.20, Q155): beta.18 set "1" after a send whose result nobody checked, so an
    undelivered warning survived the upgrade as "delivered" until the condition recovered. Not notified means one attempt on the next pass - a
    possible single duplicate beats a missed warning."""
    import json

    raw = __get_global_setting(_alert_state_key(alert_type, key), "") or ""
    if raw in ("1", "0"):
        return {"a": raw == "1", "n": False, "t": None, "c": 0, "d": None, "r": False}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        value = None
    if not isinstance(value, dict):
        return {"a": False, "n": False, "t": None, "c": 0, "d": None, "r": False}
    return {
        "a": bool(value.get("a")),
        "n": bool(value.get("n")),
        "t": value.get("t"),
        "c": int(value.get("c") or 0),
        "d": value.get("d"),
        "r": bool(value.get("r")),
    }


def _save_state(alert_type, key, state) -> None:
    import json

    if not __set_global_setting(_alert_state_key(alert_type, key), json.dumps(state, separators=(",", ":"))):
        # v5.68.0-beta.22 (Q157): the write failed (it is logged by the setter); the state is now only in memory of this pass, so a restart may repeat a notification
        logger.warning(f"alert state {alert_type}:{key} could not be stored: a restart may repeat this notification")


def _clear_orphan_states(alert_type, live_keys) -> int:
    """Delete `alert_state:<alert_type>:<key>` rows whose key is no longer configured (v5.68.0-beta.21, Q156). A subnet that left Jen's map (or a server
    that was removed) used to leave its state behind for ever: active, never recovered, loaded on every settings reload. No `_ok` is sent - the thing
    the alert was about is gone. Returns the number of rows removed.

    v5.68.0-beta.22 (Q157): an EMPTY live set is no longer a reason to clear nothing. beta.21 guarded against "a configuration that could not be
    read", but `extensions.SUBNET_MAP` / `KEA_SERVERS` are the LAST APPLIED config (`AppConfig.apply`) - there is no runtime state in which they are
    unreadable - so an empty map is a box whose last subnet was removed, and its state stayed active for ever. The validity gate is whether a config
    has been applied at all (`extensions.cfg`)."""
    if getattr(extensions, "cfg", None) is None:
        return 0
    live = {str(k) for k in live_keys}
    prefix = f"alert_state:{alert_type}:"
    try:
        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
            jcur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE %s", (prefix + "%",))
            stale = [
                r["setting_key"]
                for r in jcur.fetchall()
                if r["setting_key"].startswith(prefix) and r["setting_key"][len(prefix) :] not in live
            ]
            for key in stale:
                jcur.execute("DELETE FROM settings WHERE setting_key=%s", (key,))
        if stale:
            from jen.models.user import _invalidate_settings_cache

            _invalidate_settings_cache()
            logger.info(f"alert state: cleared {len(stale)} {alert_type} row(s) for keys that are no longer configured")
        return len(stale)
    except Exception as e:
        logger.error(f"alert state: orphan cleanup for {alert_type} failed: {e}")
        return 0


def alert_state(alert_type, key) -> bool:
    """Is the condition for (alert_type, key) currently recorded as ACTIVE (alerted or pending, and not yet recovered)?"""
    return _load_state(alert_type, key)["a"]


def alert_delivery(alert_type, key) -> dict:
    """{"active", "notified", "attempts", "last_attempt"} for (alert_type, key) - what the delivery half of the state says."""
    s = _load_state(alert_type, key)
    return {"active": s["a"], "notified": s["n"], "attempts": s["c"], "last_attempt": s["t"]}


def _delivered(results) -> bool:
    """True when at least one ELIGIBLE channel returned ok. `send_alert` answers [(channel, ok, error), ...] - empty when nobody was eligible."""
    return isinstance(results, (list, tuple)) and any(r[1] for r in results)


def _iso(moment) -> str:
    return moment.isoformat()


def _parse(moment):
    from datetime import datetime

    try:
        return datetime.fromisoformat(moment) if moment else None
    except ValueError:
        return None


def mark_notified(alert_type, key, now=None) -> None:
    """Record (alert_type, key) as active AND notified without sending - for a condition that is true but that a TIGHTER alert has already
    spoken for (cert_expiring's 30-day bucket when the 7-day one fires)."""
    now = now or _utcnow()
    s = _load_state(alert_type, key)
    if not (s["a"] and s["n"]):
        _save_state(alert_type, key, {"a": True, "n": True, "t": _iso(now), "c": 0, "d": _iso(now), "r": False})


def notify_condition(
    alert_type, key, active, *, kwargs, ok_type=None, ok_kwargs=None, repeat_after=None, now=None
) -> str:
    """The one place a threshold alert is sent, retried and recovered (v5.68.0-beta.19, Q154). `active` is whether the condition holds NOW.
    Returns what it did: "sent", "pending" (attempted, nobody took it; will retry), "waiting" (backing off), "quiet" (nothing to do),
    "recovered" (the `_ok` was delivered), "recovery-pending" (the `_ok` was attempted and nobody took it; it will be retried), "cleared" (the
    condition ended; no `_ok`: no warning had been delivered, or the type has none).

      * a condition that becomes true starts a pending notification; it is `notified` only when at least one eligible channel returned ok -
        every channel failing, or none eligible, leaves it pending and it is retried with backoff (1, 2, 4 ... 60 min) while it holds;
      * a condition that ends sends `ok_type` ONLY if its warning was delivered (a recovery for a warning nobody got is noise) - and, since
        v5.68.0-beta.20 (Q155), a recovery nobody took is retried with the same backoff until it is delivered (`r`): the operator used to keep
        "high" forever. The warning is NEVER re-sent while a recovery waits; if the condition comes back first, the earlier warning stands;
      * `repeat_after` (a timedelta) re-opens a delivered condition that is still true after that long (the forecast's weekly reminder);
      * the state is written only when it CHANGED (a quiet pass writes nothing).
    """
    from datetime import timedelta

    now = now or _utcnow()
    state = _load_state(alert_type, key)
    original = dict(state)

    def persist():
        if state != original:
            _save_state(alert_type, key, state)

    def backing_off():
        last = _parse(state["t"])
        if last is None or state["c"] <= 0:
            return False
        return now < last + timedelta(minutes=_BACKOFF_MINUTES[min(state["c"] - 1, len(_BACKOFF_MINUTES) - 1)])

    def attempt(send_type, send_kwargs):
        try:
            return _delivered(send_alert(send_type, **send_kwargs))
        except Exception as e:
            logger.error(f"alert {send_type} ({key}): send failed: {e}")
            return False

    inactive = {"a": False, "n": False, "t": None, "c": 0, "d": None, "r": False}
    if not active:
        if state["a"]:  # the condition has just ended
            if state["n"] and ok_type:
                if attempt(ok_type, ok_kwargs if ok_kwargs is not None else kwargs):
                    state.clear()
                    state.update(inactive)
                    persist()
                    return "recovered"
                # not delivered: the condition is over, the recovery is owed
                state.update(a=False, n=False, t=_iso(now), c=1, r=True)
                persist()
                return "recovery-pending"
            state.clear()
            state.update(inactive)
            persist()
            return "cleared"
        if state["r"]:  # a recovery still owed
            if not ok_type:
                state.clear()
                state.update(inactive)
                persist()
                return "cleared"
            if backing_off():
                return "waiting"
            if attempt(ok_type, ok_kwargs if ok_kwargs is not None else kwargs):
                state.clear()
                state.update(inactive)
                persist()
                return "recovered"
            state.update(t=_iso(now), c=state["c"] + 1)
            persist()
            return "recovery-pending"
        return "quiet"
    if state["r"] and not state["a"]:
        # the condition came back before its recovery was delivered: the warning that was delivered earlier still stands - nothing is re-sent
        state.update(a=True, n=True, t=None, c=0, r=False)
    elif not state["a"]:
        state.clear()
        state.update(a=True, n=False, t=None, c=0, d=None, r=False)
    elif state["n"] and repeat_after is not None:
        told = _parse(state["d"])
        if told is not None and now - told >= repeat_after:
            state.update(n=False, t=None, c=0, d=None)
    if state["n"]:
        persist()
        return "quiet"
    if backing_off():
        persist()
        return "waiting"
    delivered = attempt(alert_type, kwargs)
    state["t"] = _iso(now)
    if delivered:
        state.update(n=True, c=0, d=_iso(now))
    else:
        state["c"] += 1
    persist()
    return "sent" if delivered else "pending"


def check_utilization_alerts(cur, dhcp4_cfg) -> None:
    """`utilization_high`/`utilization_ok` and `pool_exhaustion`/`pool_exhaustion_ok`, judged per SUBNET over the union of its pools
    (v5.68.0-beta.18, Q153): capacity is the total of every pool (`pools.total_pool_size`), consumption is the active leases whose address is
    INSIDE a pool (`pools.consumption` - a reservation outside every pool consumes no dynamic capacity). It was the subnet's whole active
    count compared with each pool in turn (100 leases over pools of 50 and 200 read as 200 % and 50 %, and two pools could flip one subnet's
    state twice in a pass). `cur` is an open Kea-database cursor; `dhcp4_cfg` the Dhcp4 section of Kea's config.

    State is persisted (`alert_state`): a repeated pass sends nothing, a restart re-sends nothing, and a condition that cleared while Jen was
    down sends its `_ok` once. `pool_exhaustion` has hysteresis - it fires at `free <= N` (`pool_exhaustion_free`, default 5) and recovers,
    with `pool_exhaustion_ok`, only at `free >= N + max(2, N // 5)` - so a subnet hovering at the line does not flap."""
    threshold = int(__get_global_setting("alert_threshold_pct", "80"))
    exhaustion = int(__get_global_setting("pool_exhaustion_free", "5"))
    recover_at = exhaustion + max(2, exhaustion // 5)
    for s, _sn in __iter_subnet4(dhcp4_cfg):
        sid = s["id"]
        info = extensions.SUBNET_MAP.get(sid)
        if info is None:
            continue
        pool_size = __pools.total_pool_size(s.get("pools", []))
        if pool_size <= 0:
            continue
        used = __pools.consumption(cur, sid, s.get("pools", []))
        pct = round(used / pool_size * 100)
        free = pool_size - used
        details = {
            "subnet": info["name"],
            "cidr": info["cidr"],
            "pct": pct,
            "used": used,
            "total": pool_size,
            "subnet_id": sid,
        }
        notify_condition("utilization_high", sid, pct >= threshold, kwargs=details, ok_type="utilization_ok")
        # hysteresis: once exhausted the condition holds until free climbs back to `recover_at`
        exhausted = free <= exhaustion or (alert_state("pool_exhaustion", sid) and free < recover_at)
        warn = {"subnet": info["name"], "cidr": info["cidr"], "free": free, "subnet_id": sid}
        notify_condition("pool_exhaustion", sid, exhausted, kwargs=warn, ok_type="pool_exhaustion_ok")
    # a subnet that is no longer in Jen's map keeps no state (v5.68.0-beta.21, Q156)
    for orphan_type in ("utilization_high", "pool_exhaustion"):
        _clear_orphan_states(orphan_type, extensions.SUBNET_MAP)


def _check_packet_health_alerts() -> None:
    """Fire `packet_health` (warn/fail) / `packet_health_ok` (recovery)
    once per server per transition — the utilization_high/utilization_ok
    pattern. Reads the server_stats rows take_server_stats_snapshot() just
    wrote; called right after it in the same snapshot pass. The transition
    state is `alert_state:packet_health:<server id>` in the settings table
    (v5.68.0-beta.18, Q153: it was a set local to check_alerts(), lost on
    every restart)."""
    import json

    from jen.services import packet_health

    try:
        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
            for srv in extensions.KEA_SERVERS:
                jcur.execute(
                    "SELECT snapshot_time, stats FROM server_stats WHERE server_id=%s "
                    "AND snapshot_time > DATE_SUB(NOW(), INTERVAL 90 MINUTE) ORDER BY snapshot_time",
                    (srv["id"],),
                )
                rows = []
                for r in jcur.fetchall():
                    stats = r["stats"]
                    if isinstance(stats, str):
                        stats = json.loads(stats)
                    rows.append({"snapshot_time": r["snapshot_time"], "stats": stats})
                if len(rows) < 2:
                    continue
                a = packet_health.assess(packet_health.rates(packet_health.deltas(rows), window_minutes=60))
                sid = srv["id"]
                notify_condition(
                    "packet_health",
                    sid,
                    a["status"] in ("warn", "fail"),
                    kwargs={"server_name": srv["name"], "status": a["status"], "detail": "; ".join(a["notes"])},
                    ok_type="packet_health_ok",
                    ok_kwargs={"server_name": srv["name"]},
                )
    except Exception as e:
        logger.error(f"Packet health alert check error: {e}")
    _clear_orphan_states("packet_health", [srv["id"] for srv in extensions.KEA_SERVERS or []])


_pending_summary = (
    None  # (date, text): a summary that was built and NOT delivered - a retry sends this text, it does not rebuild
)


def _build_daily_summary() -> str:
    lines = ["<b>Daily Network Summary</b>"]
    with __kea_db_ctx() as db, __jen_db_ctx() as jdb:
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute(
                    f"SELECT COUNT(*) as cnt FROM lease4 WHERE {ACTIVE_LEASE4} AND subnet_id=%s",  # nosec B608 - a fixed constant
                    (subnet_id,),
                )
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                lines.append(f"\n<b>{info['name']}</b> ({info['cidr']}): {active} active, {reserved} reserved")
            # New devices in last 24h
            with jdb.cursor() as jcur:
                jcur.execute(
                    "SELECT COUNT(*) as cnt FROM devices WHERE first_seen >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
                )
                new_devices = jcur.fetchone()["cnt"]
                jcur.execute("SELECT COUNT(*) as cnt FROM devices")
                total_devices = jcur.fetchone()["cnt"]
        lines.append(f"\nNew devices (24h): <b>{new_devices}</b>")
        lines.append(f"Total known devices: <b>{total_devices}</b>")
    return "\n".join(lines)


def send_daily_summary() -> str:
    """Build (once per day) and send the daily summary. Returns "delivered" (at least one ELIGIBLE channel took it), "undelivered" (it was built
    and nobody did - every channel failed, or none handles `daily_summary`) or "failed" (it could not be built).

    v5.68.0-beta.22 (Q157): it returned True after `send_alert(...)` whatever the channels answered, and the loop then recorded the day as sent -
    every other notification since beta.19 is judged by `_delivered(...)`, this one was not. The built text is kept in `_pending_summary` so a retry
    sends the same text without rebuilding it; a new day drops it."""
    global _pending_summary
    today = _utcnow().date()
    try:
        if _pending_summary is None or _pending_summary[0] != today:
            _pending_summary = (today, _build_daily_summary())
        results = send_alert("daily_summary", summary=_pending_summary[1])
    except Exception as e:
        logger.error(f"Daily summary error: {e}")
        return "failed"
    if _delivered(results):
        _pending_summary = None
        return "delivered"
    return "undelivered"


def ip_to_int(ip):
    parts = ip.strip().split(".")
    return sum(int(x) << (8 * (3 - i)) for i, x in enumerate(parts))


def _cached(name, compute, now):
    """`compute()` at most once per `CONDITION_CACHE_MINUTES` for `name` (v5.68.0-beta.20, Q155): the alert loop evaluates the certificate and
    forecast conditions every `CONDITION_INTERVAL_MINUTES`, and the file read and the forecast fit behind them are not worth repeating that often."""
    from datetime import timedelta

    held = _CONDITION_CACHE.get(name)
    if held is not None and now - held[0] < timedelta(minutes=CONDITION_CACHE_MINUTES):
        return held[1]
    value = compute()
    _CONDITION_CACHE[name] = (now, value)
    return value


def run_slow_conditions(now=None) -> None:
    """The certificate-expiry and pool-forecast conditions, evaluated by the alert loop every `CONDITION_INTERVAL_MINUTES` (v5.68.0-beta.20, Q155) -
    each guarded on its own, with the expensive inputs cached hourly."""
    now = now or _utcnow()
    try:
        check_cert_expiry_alert(now=now, use_cache=True)
    except Exception as e:
        logger.error(f"Cert expiry check error: {e}")
    try:
        check_pool_forecast_alerts(use_cache=True)
    except Exception as e:
        logger.error(f"Pool forecast check error: {e}")


def check_cert_expiry_alert(now=None, use_cache=False) -> None:
    """Fire `cert_expiring` when Jen's HTTPS certificate's days-left crosses
    into a tighter bucket (30 → 7 → 1). The last-fired bucket lives in the
    settings key `cert_expiry_alerted` so a restart doesn't re-alert; it
    resets to 0 once the cert is renewed (days-left back above 30). No-op
    when HTTPS isn't configured (`cert_days_left()` returns None).
    `use_cache` (the alert loop) reads the certificate's days-left through the hourly cache."""
    from jen.services.health import cert_days_left

    now = now or _utcnow()
    days = _cached("cert_days_left", cert_days_left, now) if use_cache else cert_days_left()
    if days is None:
        return
    bucket = next((b for b in (1, 7, 30) if days <= b), None)
    # v5.68.0-beta.19 (Q154): each bucket is its own condition through `notify_condition` - only the TIGHTEST reached one speaks, a looser one it
    # has passed is recorded as already told, a tighter one not reached is cleared, and a bucket whose notification was not delivered is retried.
    # A `cert_expiry_alerted` value left by an older Jen counts as the buckets it had already fired.
    try:
        legacy = int(__get_global_setting("cert_expiry_alerted", "0") or "0")
    except (TypeError, ValueError):
        legacy = 0
    for b in (30, 7, 1):
        if legacy and b >= legacy and not _load_state("cert_expiring", b)["a"]:
            mark_notified("cert_expiring", b, now=now)
        if bucket is None or b < bucket:
            notify_condition("cert_expiring", b, False, kwargs={}, now=now)
        elif b > bucket:
            mark_notified("cert_expiring", b, now=now)
        else:
            notify_condition("cert_expiring", b, True, kwargs={"days_left": days}, now=now)
    if legacy:
        __set_global_setting("cert_expiry_alerted", "0")


def check_pool_forecast_alerts(today=None, use_cache=False) -> None:
    """v5.36.0 (Q35): fire `pool_forecast` for every subnet whose trend
    reaches 90 % of its pool within 30 days — at most once per subnet per
    7 days, tracked in the settings key `pool_forecast_alerted_<id>` (the
    date last fired) so a restart doesn't re-alert. The forecast itself is
    jen/services/capacity.py; the history read is health.lease_history_window.
    `use_cache` (the alert loop, every `CONDITION_INTERVAL_MINUTES`) reads the history and fits the forecast at most once an hour; the
    notification state of each subnet is still evaluated on every call, which costs nothing for a delivered condition."""
    from datetime import date, datetime, timedelta

    from jen.services import capacity
    from jen.services.health import lease_history_window

    # a caller-supplied `today` (the tests) is the clock; in production it is the real time, so a retry's backoff really elapses
    now = datetime.combine(today, datetime.min.time()) if today is not None else _utcnow()
    today = today or now.date()

    def fit():
        return {
            sid: (capacity.forecast(rows, today=today), capacity.high_water(rows))
            for sid, rows in lease_history_window().items()
        }

    fits = _cached("pool_forecast", fit, now) if use_cache else fit()
    for sid, (f, hw) in fits.items():
        info = extensions.SUBNET_MAP.get(sid)
        if not info:
            continue
        d = f["days_to_90pct"]
        if d is None or d > capacity.WARN_DAYS:
            notify_condition(
                "pool_forecast", sid, False, kwargs={}, now=now
            )  # the trend no longer reaches 90 %: the episode is over
            continue
        # v5.68.0-beta.19 (Q154): one `notify_condition` per subnet - retried while undelivered, a weekly reminder once delivered
        legacy_key = f"pool_forecast_alerted_{sid}"  # an older Jen's "date last fired" counts as a delivered notification on that date
        legacy = __get_global_setting(legacy_key, "") or ""
        if legacy and not _load_state("pool_forecast", sid)["a"]:
            try:
                told = datetime.combine(date.fromisoformat(legacy), datetime.min.time())
                _save_state(
                    "pool_forecast",
                    sid,
                    {"a": True, "n": True, "t": told.isoformat(), "c": 0, "d": told.isoformat(), "r": False},
                )
            except ValueError:
                pass
        if legacy:
            __set_global_setting(legacy_key, "")
        notify_condition(
            "pool_forecast",
            sid,
            True,
            kwargs={
                "subnet": info["name"],
                "cidr": info["cidr"],
                "trend": f"{f['slope_per_day']:+.1f}",
                "days": d,
                "date": f["date_90"],
                "peak": hw["peak"] if hw else f["latest_peak"],
                "total": f["pool_size"],
                "subnet_id": sid,
            },
            repeat_after=timedelta(days=7),
            now=now,
        )
    _clear_orphan_states("pool_forecast", extensions.SUBNET_MAP)


def diff_leases(prev: dict, cur: dict) -> list[dict]:
    """Pure diff between two snapshots of currently-active leases, each
    `{ip: {"mac", "hostname", "subnet_id", "is_reserved"}}` (one entry
    per CURRENT lease4 row - `ACTIVE_LEASE4`, state 0 and not past its
    expiry: v5.68.0-beta.18 moved the whole tree off a bare `state=0`). No I/O — `check_alerts()`'s
    lease-tracking block builds the two dicts and calls this; factored
    out (Q43) so it's unit-testable without a database.

    Returns event dicts (each with `kind` plus the fields above, `ip`,
    and — for `lease.ip_changed` — `old_ip`) in Q43's KINDS vocabulary:

    - `lease.new`: an IP active now that wasn't in `prev` at all.
    - `lease.ip_changed`: a MAC whose IP changed — paired by matching a
      newly-active IP to a now-inactive IP with the SAME mac, rather
      than reporting an unrelated expired+new pair for what is really
      one client moving addresses. Best-effort: if a MAC has more than
      one lease appear/disappear in the same pass, pairing is by
      iteration order, not any stronger correlation.
    - `lease.expired`: an IP that was active in `prev` and isn't now,
      whose mac wasn't matched to a `lease.ip_changed` above.
    - `lease.hostname_changed`: an IP active in both snapshots whose
      hostname differs, and the new hostname isn't empty (a client that
      stops sending option 12 isn't "renamed" to nothing).

    Iteration is sorted by IP throughout, so results are deterministic
    for a given pair of inputs — needed for tests to assert exact order.
    """
    events: list[dict] = []
    prev_ips, cur_ips = set(prev), set(cur)
    new_ips = cur_ips - prev_ips
    gone_ips = prev_ips - cur_ips

    gone_by_mac: dict[str, list[str]] = {}
    for ip in sorted(gone_ips):
        gone_by_mac.setdefault(prev[ip]["mac"], []).append(ip)

    matched_gone_ips = set()
    for ip in sorted(new_ips):
        row = cur[ip]
        candidates = gone_by_mac.get(row["mac"])
        if candidates:
            old_ip = candidates.pop(0)
            matched_gone_ips.add(old_ip)
            events.append(
                {
                    "kind": "lease.ip_changed",
                    "mac": row["mac"],
                    "ip": ip,
                    "old_ip": old_ip,
                    "subnet_id": row["subnet_id"],
                    "hostname": row["hostname"],
                    "is_reserved": row["is_reserved"],
                }
            )
        else:
            events.append(
                {
                    "kind": "lease.new",
                    "mac": row["mac"],
                    "ip": ip,
                    "subnet_id": row["subnet_id"],
                    "hostname": row["hostname"],
                    "is_reserved": row["is_reserved"],
                }
            )

    for ip in sorted(gone_ips - matched_gone_ips):
        row = prev[ip]
        events.append(
            {
                "kind": "lease.expired",
                "mac": row["mac"],
                "ip": ip,
                "subnet_id": row["subnet_id"],
                "hostname": row["hostname"],
                "is_reserved": row["is_reserved"],
            }
        )

    for ip in sorted(cur_ips & prev_ips):
        new_hostname = cur[ip]["hostname"]
        if new_hostname and new_hostname != prev[ip]["hostname"]:
            events.append(
                {
                    "kind": "lease.hostname_changed",
                    "mac": cur[ip]["mac"],
                    "ip": ip,
                    "subnet_id": cur[ip]["subnet_id"],
                    "hostname": new_hostname,
                    "old_hostname": prev[ip]["hostname"],
                    "is_reserved": cur[ip]["is_reserved"],
                }
            )

    return events


UNKNOWN = object()  # `_summary_sent_date()` could not read the settings table at all


def _summary_sent_date():
    """The date the daily summary was last sent (`daily_summary_sent`), read when the alert loop starts. With no record (a fresh install, or the first
    start after the upgrade that added it) a summary time that has already passed today counts as sent today: the loop must not announce a summary at
    an arbitrary hour just because it started after the configured time.

    v5.68.0-beta.22 (Q157): returns `UNKNOWN` when the settings table has never been read (the Jen database was down at start). Reading through the
    empty cache returned `""` and `"07:00"`, so a process that started at 09:00 with the database down decided "07:00 has passed, today is sent" and
    skipped a configured 20:00 summary that day. The loop asks again each cycle until it knows, and sends nothing meanwhile."""
    from datetime import date

    from jen.models.user import settings_ever_loaded

    try:
        raw = __get_global_setting("daily_summary_sent", "") or ""
        if not settings_ever_loaded():
            return UNKNOWN
        if raw:
            return date.fromisoformat(raw)
        now = _utcnow()
        h, m = [int(x) for x in (__get_global_setting("daily_summary_time", "07:00") or "07:00").split(":")]
        return now.date() if (now.hour, now.minute) >= (h, m) else None
    except Exception as e:
        logger.warning(f"Could not read daily_summary_sent: {e}")
        return UNKNOWN


def _seed_known_macs(known_macs: set) -> bool:
    """Add every MAC in the devices table to `known_macs`. True when it worked; False (logged) when the Jen database could not be read."""
    try:
        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
            jcur.execute("SELECT mac FROM devices")
            seeded = [row["mac"].lower() for row in jcur.fetchall()]
    except Exception as e:
        logger.warning(f"Could not seed known_macs from devices (will retry): {e}")
        return False
    known_macs.update(seeded)
    logger.info(f"Seeded {len(known_macs)} known MACs from devices table")
    return True


def check_alerts():
    import time
    from datetime import timedelta

    last_kea_status = {}
    last_seen_leases = {}  # ip -> {mac, hostname, subnet_id, is_reserved} — see diff_leases()
    known_macs = set()
    alerted_stale_macs = set()
    first_run = True
    last_summary_date = (
        _summary_sent_date()
    )  # v5.68.0-beta.21 (Q156): persisted, so a restart after the summary does not send it twice
    last_summary_try = None
    summary_attempts = 0
    summary_wait = timedelta(minutes=15)  # how long after an attempt the next may be made
    last_condition_pass = (
        None  # v5.68.0-beta.20 (Q155): the certificate and forecast conditions run every CONDITION_INTERVAL_MINUTES
    )
    last_snapshot_time = 0
    last_ha_states = {}  # server_id -> last known HA state
    last_drift_issues = {}  # issue_key -> issue dict, for detected-once/resolved-once alerting

    # Seed known_macs from devices table so restarts don't flood with "new device" alerts for every known device. v5.68.0-beta.21 (Q156): the seed
    # is retried at the top of each cycle until it succeeds - it ran once before the loop, so a Jen database that was down at start left it empty for the
    # life of the process and every known device that was offline at start fired `new_device` when it came back - and `new_device` is not sent until it has.
    macs_seeded = False

    while True:
        try:
            if not macs_seeded:
                macs_seeded = _seed_known_macs(known_macs)
            # ── Kea up/down + HA — checked every ~5s (6 times within
            # this outer iteration's ~30s cycle), decoupled from the
            # heavier work below. v5.1.17 — everything in this loop
            # used to share one single 30-second heartbeat. A Kea/
            # server reboot that's actually down for less than ~30
            # seconds (plausible for a fast VM or lightweight OS) could
            # fall entirely between two polls and never register as
            # down at all — not a logic bug in the up/down detection
            # itself (traced it exhaustively; it's correct), just an
            # architectural blind spot from coupling a cheap, fast-
            # changing check to the same cadence as much heavier,
            # far-less time-sensitive work (utilization scans,
            # snapshots, the daily summary). Checking 6x as often
            # shrinks that blind spot to ~5 seconds without changing
            # anything about how often the heavier work below runs.
            for _ in range(6):
                for srv in extensions.KEA_SERVERS:
                    srv_id = srv["id"]
                    srv_up = __kea_is_up(server=srv)
                    prev_status = last_kea_status.get(srv_id, True)
                    if not srv_up and prev_status:
                        send_alert("kea_down", server_name=srv["name"])
                    elif srv_up and not prev_status:
                        send_alert("kea_up", server_name=srv["name"])
                    last_kea_status[srv_id] = srv_up

                    # ── HA state monitoring ──
                    if srv_up and len(extensions.KEA_SERVERS) > 1:
                        ha = __kea_command("ha-heartbeat", server=srv)
                        if ha.get("result") == 0:
                            new_state = ha.get("arguments", {}).get("state", "")
                            old_state = last_ha_states.get(srv_id)
                            if old_state is not None and new_state != old_state:
                                send_alert(
                                    "ha_failover", server_name=srv["name"], old_state=old_state, new_state=new_state
                                )
                                __emit_event(
                                    "ha.state_changed", server=srv["name"], detail=f"{old_state} -> {new_state}"
                                )
                            last_ha_states[srv_id] = new_state
                time.sleep(5)

            kea_up = any(last_kea_status.values()) if last_kea_status else True

            if kea_up:
                with __kea_db_ctx() as db, db.cursor() as cur:
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
                    cur.execute(f"""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id,
                                   (h.host_id IS NOT NULL) AS is_reserved
                            FROM lease4 l
                            LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                                AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                            WHERE {active_lease4("l")}
                        """)
                    # v5.42.0 (Q43) — IP-keyed dict, not just a set of IPs,
                    # so diff_leases() (pure, factored out) can also spot
                    # an IP change or a hostname change on the same MAC,
                    # not just "this IP is newly active".
                    current_leases = {
                        row["ip"]: {
                            "mac": __format_mac(row["hwaddr"]),
                            "hostname": row["hostname"] or "",
                            "subnet_id": row["subnet_id"],
                            "is_reserved": bool(row["is_reserved"]),
                        }
                        for row in cur.fetchall()
                    }
                    lease_events = [] if first_run else diff_leases(last_seen_leases, current_leases)

                    # ── Device inventory update ──
                    cur.execute(f"""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id
                            FROM lease4 l WHERE {active_lease4("l")}
                        """)
                    all_leases = cur.fetchall()
                    try:
                        with __jen_db_ctx() as jdb:
                            with jdb.cursor() as jcur:
                                for row in all_leases:
                                    mac = __format_mac(row["hwaddr"])
                                    manufacturer, device_type, device_icon = __classify_device(
                                        mac, row["hostname"] or ""
                                    )
                                    jcur.execute(
                                        """
                                            INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, last_seen,
                                                                 manufacturer, device_type, device_icon)
                                            VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
                                            ON DUPLICATE KEY UPDATE
                                                last_ip=%s, last_hostname=%s,
                                                last_subnet_id=%s, last_seen=NOW(),
                                                manufacturer=IF(manufacturer_override IS NULL, %s, manufacturer),
                                                device_type=IF(manufacturer_override IS NULL, %s, device_type),
                                                device_icon=IF(manufacturer_override IS NULL, %s, device_icon)
                                        """,
                                        (
                                            mac,
                                            row["ip"],
                                            row["hostname"],
                                            row["subnet_id"],
                                            manufacturer,
                                            device_type,
                                            device_icon,
                                            row["ip"],
                                            row["hostname"],
                                            row["subnet_id"],
                                            manufacturer,
                                            device_type,
                                            device_icon,
                                        ),
                                    )
                            jdb.commit()
                    except Exception as e:
                        logger.error(f"Device tracking error: {e}")

                    # ── Event stream + new-lease alerts (Q43) ──
                    # diff_leases() (pure, factored out) does the actual
                    # comparison; this loop emits every lease/device kind
                    # to the event stream and, for lease.new specifically,
                    # ALSO drives the pre-Q43 new_lease/new_reserved_lease/
                    # new_device alerts — same semantics as before
                    # (is_reserved picks the alert type; a reserved
                    # device's recurrence follows reserved_lease_mode;
                    # new_device only fires for a MAC truly never seen),
                    # just sourced from the pure diff instead of an inline
                    # set comparison.
                    for ev in lease_events:
                        subnet_name = extensions.SUBNET_MAP.get(ev["subnet_id"], {}).get(
                            "name", f"Subnet {ev['subnet_id']}"
                        )
                        hostname = safe_text(ev["hostname"]) if ev["hostname"] else "(none)"
                        if ev["kind"] == "lease.ip_changed":
                            detail = f"was {ev['old_ip']}"
                        elif ev["kind"] == "lease.hostname_changed":
                            detail = f"was {ev['old_hostname']!r}"
                        else:
                            detail = ""
                        __emit_event(
                            ev["kind"],
                            mac=ev["mac"],
                            ip=ev["ip"],
                            subnet_id=ev["subnet_id"],
                            hostname=ev["hostname"] or None,
                            detail=detail,
                        )
                        if ev["kind"] != "lease.new":
                            continue
                        mac = ev["mac"]
                        if ev["is_reserved"]:
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
                            send_alert(
                                "new_reserved_lease",
                                ip=ev["ip"],
                                mac=mac,
                                hostname=hostname,
                                subnet=subnet_name,
                                subnet_id=ev["subnet_id"],
                            )
                            known_macs.add(mac)
                            continue
                        send_alert(
                            "new_lease",
                            ip=ev["ip"],
                            mac=mac,
                            hostname=hostname,
                            subnet=subnet_name,
                            subnet_id=ev["subnet_id"],
                        )
                        # New device alert — only fire for MACs truly never
                        # seen before (not in devices table, not just unknown
                        # since last restart). Not until the devices table has been read
                        # (v5.68.0-beta.21, Q156): an empty known_macs would call every
                        # known device "new" when it comes back online.
                        if mac not in known_macs and macs_seeded:
                            send_alert(
                                "new_device",
                                ip=ev["ip"],
                                mac=mac,
                                hostname=hostname,
                                subnet=subnet_name,
                                subnet_id=ev["subnet_id"],
                            )
                            __emit_event(
                                "device.first_seen",
                                mac=mac,
                                ip=ev["ip"],
                                subnet_id=ev["subnet_id"],
                                hostname=ev["hostname"] or None,
                            )
                            known_macs.add(mac)  # prevent repeat alerts this session
                        elif mac not in known_macs:
                            known_macs.add(mac)  # unseeded: remembered, not announced

                    # Update known MACs from all current leases
                    for row in all_leases:
                        known_macs.add(__format_mac(row["hwaddr"]))

                    last_seen_leases = current_leases
                    first_run = False

                    # ── Utilization alerts ──
                    kea_cfg = __kea_command("config-get", server=__get_active_kea_server())
                    if kea_cfg.get("result") == 0:
                        check_utilization_alerts(cur, kea_cfg["arguments"].get("Dhcp4", {}))

                    # ── Stale reservation alerts ──
                    try:
                        stale_days = int(__get_global_setting("stale_device_days", "30"))
                        with __jen_db_ctx() as jdb, jdb.cursor() as jcur:
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
                                cur.execute(
                                    "SELECT inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_subnet_id "
                                    "FROM hosts WHERE HEX(dhcp_identifier)=%s",
                                    (mac_hex,),
                                )
                                res = cur.fetchone()
                                if res:
                                    send_alert(
                                        "stale_reservation",
                                        ip=res["ip"] or "",
                                        mac=row["mac"],
                                        hostname=safe_text(res["hostname"]) if res["hostname"] else "",
                                        days=row["days"],
                                        subnet_id=res["dhcp4_subnet_id"],
                                    )
                                    alerted_stale_macs.add(row["mac"])
                    except Exception as e:
                        logger.error(f"Stale reservation check error: {e}")

                    # ── Config drift check (v5.2.0) ──
                    # Jen's own subnet map is a manually-maintained
                    # config file, not derived from Kea's live
                    # config at all — it can silently drift out of
                    # sync (this is exactly what caused a real bug:
                    # selecting a subnet by name returned a
                    # different subnet's data, because Jen's stored
                    # id for that name no longer matched what Kea's
                    # live config actually assigned it to). Alerts
                    # once when an issue first appears and once when
                    # it resolves — not every 30-second cycle it
                    # persists — using the same detected/resolved
                    # pairing pattern as kea_down/kea_up and
                    # utilization_high/utilization_ok.
                    try:
                        current_issues = {__drift_issue_key(i): i for i in __check_config_drift()}
                        for key, issue in current_issues.items():
                            if key not in last_drift_issues:
                                send_alert(
                                    "config_drift_detected", message=issue["message"], subnet_id=issue["subnet_id"]
                                )
                                __emit_event("drift.detected", subnet_id=issue["subnet_id"], detail=issue["message"])
                        for key, issue in last_drift_issues.items():
                            if key not in current_issues:
                                send_alert(
                                    "config_drift_resolved", message=issue["message"], subnet_id=issue["subnet_id"]
                                )
                                __emit_event("drift.resolved", subnet_id=issue["subnet_id"], detail=issue["message"])
                        last_drift_issues = current_issues
                    except Exception as e:
                        logger.error(f"Config drift check error: {e}")

            # ── Lease history snapshot ──
            snapshot_interval = int(__get_global_setting("snapshot_interval_minutes", "30")) * 60
            now_ts = time.time()
            if now_ts - last_snapshot_time >= snapshot_interval:
                run_snapshot_pass()
                last_snapshot_time = now_ts

            # ── Daily summary ──
            import datetime as dt

            summary_time = __get_global_setting("daily_summary_time", "07:00")
            now = _utcnow()
            today = now.date()
            try:
                h, m = [int(x) for x in summary_time.split(":")]
                # v5.68.0-beta.21 (Q156): due AT OR AFTER its time, once per day. It was `now.hour == h and now.minute == m`, evaluated once per outer
                # cycle - and a cycle is 6 x (probe + 5 s), 90 s with one server down, plus the heavy block: the one-minute window was missed with no
                # log line. A failed build is retried no more often than every 15 minutes; `daily_summary_sent` (the date) survives a restart.
                # v5.68.0-beta.22 (Q157): the day is recorded only when a channel TOOK the summary. "undelivered" (every channel failed, or none
                # handles it) is retried with the notification backoff (1, 2, 4 ... 60 min) and never recorded; "failed" (it could not be built) is
                # retried every 15 minutes; a record that could not be WRITTEN is logged - a restart may then send one duplicate, the documented
                # trade-off against sending none.
                if last_summary_date is UNKNOWN:
                    last_summary_date = (
                        _summary_sent_date()
                    )  # the settings could not be read at start: ask again until they can, send nothing meanwhile
                summary_due = (
                    last_summary_date is not UNKNOWN and (now.hour, now.minute) >= (h, m) and last_summary_date != today
                )
                if summary_due and (last_summary_try is None or now - last_summary_try >= summary_wait):
                    last_summary_try = now
                    outcome = send_daily_summary()
                    if outcome == "delivered":
                        last_summary_date = today
                        summary_attempts, summary_wait = 0, dt.timedelta(minutes=15)
                        if not __set_global_setting("daily_summary_sent", today.isoformat()):
                            logger.warning(
                                "daily_summary_sent could not be stored: a restart before tomorrow may send today's summary again"
                            )
                    elif outcome == "undelivered":
                        summary_attempts += 1
                        summary_wait = dt.timedelta(
                            minutes=_BACKOFF_MINUTES[min(summary_attempts - 1, len(_BACKOFF_MINUTES) - 1)]
                        )
                        logger.warning(
                            f"daily summary: no channel took it (attempt {summary_attempts}); trying again in {summary_wait}"
                        )
                    else:
                        summary_wait = dt.timedelta(minutes=15)
            except Exception as e:
                logger.error(f"Daily summary scheduling error: {e}")

            # ── TLS certificate expiry (v5.12.0) and pool exhaustion forecast (v5.36.0) ──
            # v5.68.0-beta.20 (Q155): every CONDITION_INTERVAL_MINUTES, no longer once per process-day. `notify_condition` retries a failed
            # delivery after 1, 2, 4 ... minutes, and a one-day certificate warning whose channel was down used to be next tried tomorrow -
            # after the certificate expired. Evaluating a delivered condition writes and sends nothing; the file read and the forecast fit
            # are cached for CONDITION_CACHE_MINUTES.
            condition_now = _utcnow()
            if last_condition_pass is None or condition_now - last_condition_pass >= dt.timedelta(
                minutes=CONDITION_INTERVAL_MINUTES
            ):
                last_condition_pass = condition_now
                run_slow_conditions(condition_now)

        except Exception as e:
            logger.error(f"Alert thread error: {e}")
            # v5.1.17 — the inner 6x5s health-check loop above accounts
            # for normal-path cadence now (no trailing sleep needed on
            # success). This one small sleep is a safety net so a
            # persistent, immediately-raised exception (e.g. a bad
            # config value that throws before ever reaching the inner
            # loop's own sleeps) can't spin the thread at high CPU with
            # no delay at all.
            time.sleep(5)


# ─────────────────────────────────────────
# Favicon
# ─────────────────────────────────────────
