"""
jen/routes/settings/alerts.py
───────────────────────────
Alert channels, templates, and the alert-tuning settings.
"""

import json
import logging
import re

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.models.user as __user
import jen.services.alerts as __alerts
import jen.services.auth as __auth
import jen.services.setting_bounds as __bounds
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.alerts import ALERT_TYPE_LABELS, DEFAULT_TEMPLATES, GLYPH_LEGEND, PLUGIN_ALERT_TYPES
from jen.services.forms import flash_field
from jen.services.text import is_whole

logger = logging.getLogger(__name__)

#: (Q226, AL2) the config keys that are WRITE-ONLY, by channel type: the page never prints them (its inputs say "saved - leave blank to keep"), and a blank on an edit keeps the stored
#: value - only while the channel still names the same place (`_kept_secrets`, CRED-002). A Slack or Discord webhook URL is the secret itself; (Q227, AM1, AM23) a generic webhook's
#: URL is write-only too - services put a token in its path or query, and one key name (`webhook_url`) is then a secret under every type that has it.
WRITE_ONLY_KEYS = {
    "telegram": ("token",),
    "email": ("smtp_pass",),
    "slack": ("webhook_url",),
    "discord": ("webhook_url",),
    "webhook": ("webhook_url", "header_value"),
    "ntfy": ("token",),
    "pushover": ("user_key", "api_token"),
}
#: (Q227, AM1, AM7) what the page MAY carry of a stored config, by channel type: an ALLOWLIST. `_shown` used to blank the declared type's write-only keys and print every key it did
#: not know - so a row whose type does not describe its config (an edit before 5.69.0 wrote the form's config and left the row's type), a type this table does not name, or one extra
#: key printed a stored secret into the page. A key reaches the page only by being named here, and no key named here is write-only under ANY type (the test holds the two tables to it).
SHOWN_KEYS = {
    "telegram": ("chat_id",),
    "email": ("smtp_host", "smtp_port", "smtp_user", "from_addr", "to_addr", "use_tls", "tls_verify"),
    "slack": (),
    "discord": (),
    "webhook": ("payload_type", "header_name"),
    "ntfy": ("url", "topic", "priority"),
    "pushover": (),
}
#: (Q228, the beta.13 review's #3) the write-only keys a channel works WITHOUT: a webhook with no authorization header, an ntfy topic that takes no token, an SMTP relay that asks
#: for no password. A blank one with nothing stored to keep is "none", never "a secret to carry"; every write-only key not named here is one the channel cannot deliver without
OPTIONAL_SECRETS = {"webhook": ("header_value",), "ntfy": ("token",), "email": ("smtp_pass",)}
#: (Q228, AN1) the key that holds the ADDRESS the form names, for the types that have one. A blank address on an edit is the stored one (a webhook's is write-only; an ntfy
#: server's and an SMTP host are withheld from the page when they are not plain), and it is the address a kept secret is judged against.
#: (Q229, AO3) an SMTP server's host is the third address: the display gate was asked of this table, and `smtp_host` was shown without being in it
ADDRESS_KEY = {"webhook": "webhook_url", "ntfy": "url", "email": "smtp_host"}
#: the form field that carries each address, for the refusal that names it
ADDRESS_FIELDS = {"webhook_url": "webhook_url", "url": "ntfy_url", "smtp_host": "smtp_host"}
#: the form field that carries each write-only key, for the refusal that names it
WRITE_ONLY_FIELDS = {
    ("telegram", "token"): "token",
    ("email", "smtp_pass"): "smtp_pass",
    ("slack", "webhook_url"): "slack_webhook",
    ("discord", "webhook_url"): "discord_webhook",
    ("webhook", "webhook_url"): "webhook_url",
    ("webhook", "header_value"): "header_value",
    ("ntfy", "token"): "ntfy_token",
    ("pushover", "user_key"): "pushover_user_key",
    ("pushover", "api_token"): "pushover_api_token",
}


def _endpoint(channel_type: str, config: dict) -> str:
    """Where a channel's secret is SENT, as `auth.same_endpoint` compares places (CRED-002): the SMTP server with its port and whether STARTTLS is on (a password kept onto the same host with
    TLS turned off goes over the wire in clear, so the wire is part of the place), a webhook's URL, the ntfy server. Telegram, Pushover, Slack and Discord deliver to their provider's own
    address, which the form does not name: one fixed place."""
    if channel_type == "email":
        # (Q229) the wire has three states: STARTTLS verified, STARTTLS not verified, and none. A password kept while verification is turned off goes to a server nobody proved
        scheme = "smtp"
        if config.get("use_tls") == "true":
            scheme = "smtps" if config.get("tls_verify", "true") != "false" else "smtps-unverified"
        return f"{scheme}://{config.get('smtp_host', '')}:{config.get('smtp_port', '')}"
    if channel_type == "webhook":
        return config.get("webhook_url", "")
    if channel_type == "ntfy":
        # (Q229) as the sender dials it: `_send_ntfy_channel` drops the trailing slash before it appends the topic, so `https://ntfy.example/base/` and `.../base` are one address
        return str(config.get("url", "")).rstrip("/")
    return "provider.invalid"


def _stored_channel(channel_id):
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT * FROM alert_channels WHERE id=%s", (channel_id,))
        return cur.fetchone()


def _may_act_on(channel: dict) -> bool:
    """(Q226, AL24, AL2) A subnet-restricted admin reads, edits, tests and deletes only a channel whose scope lies inside their own; a channel scoped wider, or to every subnet, is not theirs to see
    (RBAC-001: its config is a secret and its alerts name what they cannot see), and a denial and a not-found are one message (RBAC-002). An unrestricted account acts on every channel."""
    # (Q227, AM25; Q228, AN3) the service's own answer, `alerts.channel_inside`, over the service's own reading of the scope (`alerts.channel_scope`): every count of channels a
    # page prints asks the same function, so a list and a number cannot disagree
    return __alerts.channel_inside(channel, current_user)


#: the two refusals of `_kept_secrets`, each said under the field it names
DESTINATION_CHANGED = "The channel's destination changed - enter the secret again."
STORED_UNREADABLE = "This channel's stored settings cannot be read, so its secret cannot be kept - enter it again."
#: (Q228) said after a save that kept nothing because nothing could be read: the fields that are empty now are named, so "saved" never hides a secret that is gone
NOTHING_KEPT = "This channel's stored settings could not be read, so nothing was kept from them. Empty now: {fields}."
#: (Q228, AN6) the two refusals of a typed address
ADDRESS_NEEDS_SCHEME = "The address must start with http:// or https:// and name a host."
NTFY_ADDRESS_SHAPE = (
    "The ntfy server address is https://host[:port][/path] with nothing after it. The access token has its own field."
)
#: (Q229, AO3) the refusal of a typed SMTP host
SMTP_HOST_SHAPE = "The SMTP host is a host name or an IP address alone: no scheme, no user name, no port and no path. The port and the user name have their own fields."
#: (Q229, the beta.14 review's #4) a password belongs to ONE account: a blank password is not kept for another user name on the same server
SMTP_USER_CHANGED = "The SMTP user name changed - enter its password again."
#: the words the Alerts page uses for each write-only key in `NOTHING_KEPT`
SECRET_LABELS = {
    "header_value": "the authorization header value",
    "token": "the access token",
    "smtp_pass": "the SMTP password",
}


def _kept_secrets(channel_id, channel_type: str, config: dict, stored: dict | None):
    """(Q226, AL3) A write-only key left blank on an EDIT keeps the stored value - only while the channel names the same place (CRED-002, `auth.same_endpoint`); a blank secret for a server, a
    port, a wire or a URL the admin typed anew is REFUSED with the field named, never carried and never silently emptied. Returns the config to store, or `(field, sentence)` to refuse on.

    (Q227) Three things the first version got wrong. A stored config that cannot be read (`get_channel_config` answers `{}` for a row that has one - a database restored without its key)
    kept "" for a provider's token and said "saved" (AM6): it is refused, and the sentence says why. Only a key that HAS a stored value is kept, so only such a key can be refused: a webhook
    with no authorization header could not change its URL, because its always-blank header was "a secret for a changed place". And a webhook's URL is write-only now (AM1): a blank URL
    is the stored one, taken BEFORE the place is compared, so the header beside it is judged against the place it was typed for."""
    if stored is None:
        return config
    keys = WRITE_ONLY_KEYS.get(channel_type, ())
    old = __alerts.get_channel_config(stored)
    # (Q228, the beta.13 review's #3) nothing can be KEPT from a config that cannot be read or from another type of channel, so the only question left is whether the channel can
    # deliver without what is blank. A blank secret the channel needs is refused, as before; a blank OPTIONAL one is "none" - a Telegram channel could not become a webhook with no
    # authorization header, and a channel whose stored settings were unreadable could not be re-entered without inventing a header
    nothing_to_keep = _unreadable(stored, old) or stored.get("channel_type") != channel_type
    if nothing_to_keep:
        needed = [k for k in keys if not config.get(k) and k not in OPTIONAL_SECRETS.get(channel_type, ())]
        if needed:
            sentence = STORED_UNREADABLE if _unreadable(stored, old) else DESTINATION_CHANGED
            return WRITE_ONLY_FIELDS[(channel_type, needed[0])], sentence
        return config
    # a blank ADDRESS is the stored one, taken BEFORE the destination is compared, so the secret beside it is judged against the address it was typed for (Q227 for a webhook's
    # write-only URL; Q228, AN1, for an ntfy server address the page withheld)
    address = ADDRESS_KEY.get(channel_type)
    if address and not config.get(address) and old.get(address):
        config[address] = old[address]
    kept = [k for k in keys if not config.get(k) and old.get(k)]
    if not kept:
        return config
    # (Q228, the beta.13 review's #2) the DESTINATION, path and query included: `same_endpoint` stops at the port, so the header value typed for https://hooks.example/team-a was
    # carried to https://hooks.example/team-b - another receiver on one host
    if not __auth.same_destination(_endpoint(channel_type, config), _endpoint(channel_type, old)):
        return WRITE_ONLY_FIELDS[(channel_type, kept[0])], DESTINATION_CHANGED
    # (Q229, the beta.14 review's #4) the SMTP password is the password OF the stored user name: the same server with another user name is another account, and the stored password
    # was sent to it as that account's. The rule the OIDC save has for a changed client ID
    if channel_type == "email" and config.get("smtp_user", "") != old.get("smtp_user", ""):
        return WRITE_ONLY_FIELDS[("email", "smtp_pass")], SMTP_USER_CHANGED
    for k in kept:
        config[k] = old[k]
    return config


def _unreadable(stored: dict | None, old: dict | None = None) -> bool:
    """A row that HAS a stored config which `get_channel_config` reads as nothing (a database restored without its key)."""
    if stored is None:
        return False
    old = __alerts.get_channel_config(stored) if old is None else old
    return not old and bool(stored.get("config"))


def _emptied(channel_type: str, config: dict, stored: dict | None) -> list:
    """(Q228) The optional secrets that are EMPTY in what is about to be stored over a config that could not be read, in the page's words: the save says so (`NOTHING_KEPT`)."""
    if not _unreadable(stored):
        return []
    return [SECRET_LABELS[k] for k in OPTIONAL_SECRETS.get(channel_type, ()) if not config.get(k)]


def _address_refusal(channel_type: str, config: dict):
    """(Q227, AM23; Q228, AN6) What a TYPED webhook or ntfy address is refused for, as `(field, sentence)`, or None. CRED-005: a URL never carries a password, said with the
    sentence every connection form uses. `userinfo_sentence` reads the authority, and `u:p@host/path` has none (its `u` parses as a scheme), so that value was stored with its
    password: an address is an http(s) URL with a host first. An ntfy server address carries no query either - ntfy reads `?auth=` as a credential. A blank address is not typed
    and is not judged here: on an edit it is the stored one (`_kept_secrets`)."""
    address = ADDRESS_KEY.get(channel_type)
    value = config.get(address, "") if address else ""
    if not value:
        return None
    field = ADDRESS_FIELDS[address]
    if channel_type == "email":
        # (Q229, AO3) a host alone: the save stored whatever was typed here, user-info and a query among it, and the page printed it back
        return None if __auth.host_name(value) else (field, SMTP_HOST_SHAPE)
    if __auth.userinfo_sentence(value):
        return field, __auth.USERINFO_SENTENCE
    if not __auth.http_address(value):
        return field, ADDRESS_NEEDS_SCHEME
    if channel_type == "ntfy" and not __auth.plain_address(value):
        return field, NTFY_ADDRESS_SHAPE
    return None


def _shown(channel_type: str, config: dict) -> dict:
    """The config as the page carries it (Q227, AM1, AM7): the keys `SHOWN_KEYS` names for this type and nothing else. A type the table does not name shows nothing."""
    shown = SHOWN_KEYS.get(channel_type, ())
    out = {k: v for k, v in (config or {}).items() if k in shown}
    # (Q228, AN1; CRED-005 at the display) an address is shown only when it is a plain one. A row an earlier release stored may carry a password before the `@` or a token in the
    # query: Q227 refused such a value on the SAVE and still printed the stored one here. It is withheld, and `url_withheld` tells the card and the edit form to say so
    address = ADDRESS_KEY.get(channel_type)
    if address in out and out[address] and not _printable(channel_type, out[address]):
        del out[address]
        out["url_withheld"] = True
    return out


def _printable(channel_type: str, value) -> bool:
    """May the page print this channel's address (CRED-005 at the display; Q229, AO3): a plain URL for a webhook or an ntfy server, a host alone for an SMTP server."""
    return __auth.host_name(value) if channel_type == "email" else __auth.plain_address(value)


@bp.route("/settings/alerts")
@login_required
@_admin_required
def settings_alerts():

    channels = []
    templates = {}
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels ORDER BY channel_type, channel_name")
            channels = [
                ch for ch in cur.fetchall() if _may_act_on(ch)
            ]  # (Q226, AL24) a restricted admin's list is the channels inside their scope
            # Parse JSON fields
            for ch in channels:
                # config is encrypted at rest (v5.7.0) — decode via the
                # service helper, which also handles legacy plaintext rows
                ch["config"] = _shown(
                    ch.get("channel_type"), __alerts.get_channel_config(ch)
                )  # (Q226, AL2) never a secret into the page
                if isinstance(ch.get("alert_types"), str):
                    try:
                        ch["alert_types"] = json.loads(ch["alert_types"])
                    except (json.JSONDecodeError, ValueError):
                        ch["alert_types"] = []
                # v5.1.16 — per-channel subnet scope for notifications. (Q227, AM24) read by the service's one reader: a damaged scope used to become None here, and the card then
                # said "all subnets" for a channel that receives no subnet-specific alert at all
                scope = __alerts.channel_scope(ch)
                ch["scope_damaged"] = scope == ()
                ch["subnet_scope"] = list(scope) if scope else None
                # (Q227, AM2) the types this channel lists and is not sent, so the card says so
                ch["unsent_types"] = [
                    t
                    for t in (ch.get("alert_types") or [])
                    if scope is not None and t in __alerts.WHOLE_NETWORK_ALERT_TYPES
                ]
            cur.execute("SELECT alert_type, template_text FROM alert_templates")
            for row in cur.fetchall():
                templates[row["alert_type"]] = row["template_text"]
    except Exception as e:
        logger.error(f"Error loading alert settings: {e}")
        flash("Error loading alert settings. Check server logs for details.", "error")

    # v5.9.0 — the delivery log moved to Settings → Logs → Alert log; the Prometheus card moved here from Infrastructure. (The DDNS / DNS-provider card moved to
    # Settings → Kea → DDNS in v5.69.0-beta.7, Q176: it is how Jen reaches the DDNS pipeline on the Kea side, not an alert or an integration.)
    cfg = extensions.cfg

    # v5.57.0 (Q73) — {type_id: plugin display name}, for the Message
    # Templates card's "From plugins" group; empty on every install with
    # no plugin registering an alert type yet.
    from jen.services.plugins import get_loaded_plugins

    loaded = get_loaded_plugins()
    plugin_alert_types = {type_id: loaded.get(pid, {}).get("name", pid) for type_id, pid in PLUGIN_ALERT_TYPES.items()}

    summary_time = __user.get_global_setting("daily_summary_time", "07:00")
    # (Q227, AM10) what the server APPLIES, through the table's one reader - never the stored text
    pool_exhaustion_free = __bounds.bounded_setting("pool_exhaustion_free")
    threshold_pct = __bounds.bounded_setting("alert_threshold_pct")
    reserved_lease_mode = __user.get_global_setting("reserved_lease_mode", "always")
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    return render_template(
        "settings_alerts.html",
        channels=channels,
        templates=templates,
        default_templates=DEFAULT_TEMPLATES,
        alert_type_labels=ALERT_TYPE_LABELS,
        plugin_alert_types=plugin_alert_types,
        glyph_legend=GLYPH_LEGEND,
        summary_time=summary_time,
        pool_exhaustion_free=pool_exhaustion_free,
        threshold_pct=threshold_pct,
        reserved_lease_mode=reserved_lease_mode,
        subnet_map=accessible_subnet_map,
        can_grant_all_subnets=current_user.all_subnets,
        whole_network_alert_types=__alerts.WHOLE_NETWORK_ALERT_TYPES,
        # Q204 (RBAC-005): the token is read off this page only by an account that may see every subnet (the template renders the form on the same condition)
        metrics_token=cfg.get("server", "metrics_token", fallback="") if cfg and current_user.all_subnets else "",
        metrics_open=cfg.getboolean("server", "metrics_open", fallback=False) if cfg else False,
    )


CHANNEL_TYPES = ("telegram", "email", "slack", "webhook", "ntfy", "pushover", "discord")


@bp.route("/settings/alerts/save-channel", methods=["POST"])
@login_required
@_admin_required
def save_alert_channel():

    channel_id = request.form.get("channel_id", "").strip()
    channel_type = request.form.get("channel_type", "").strip()
    channel_name = request.form.get("channel_name", "").strip()[:100]
    enabled = 1 if request.form.get("enabled") else 0
    # (Q228, AN13) each type once, in the order posted: a duplicate was stored and its badge printed twice
    alert_types = list(dict.fromkeys(request.form.getlist("alert_types[]")))
    if channel_type not in CHANNEL_TYPES:
        # the type is written now (it used to be stored only on INSERT, so an edit that changed it saved a config for one type under another) - and it is one of ours
        flash("Choose a channel type from the list.", "error")
        return redirect(url_for("settings.settings_alerts"))
    if any(t not in ALERT_TYPE_LABELS for t in alert_types):
        # (Q227, AM2) the list was stored as posted, with no question asked of it: an id that is no alert type refuses the form whole (DEF-003)
        flash("Choose the alert types from the list.", "error")
        return redirect(url_for("settings.settings_alerts"))
    stored = None
    if channel_id:
        # (Q226, AL24) an edit names a row: it is read FIRST, and a row the caller may not act on - or none - is one message (RBAC-002)
        stored = _stored_channel(channel_id) if is_whole(channel_id) else None
        if stored is None or not _may_act_on(stored):
            flash("Channel not found.", "error")
            return redirect(url_for("settings.settings_alerts"))

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
            # (Q226, AL13) the unrestricted branch has the shape its sibling got in Q225: a value that is not a whole number refuses the form whole (DEF-003), never one id out of the list
            # and never None for an all-garbage selection; each id once, in order
            if not all(is_whole(s) for s in subnet_ids_raw):
                flash_field("subnet_ids", "Subnet ids must be numbers.")
                return redirect(url_for("settings.settings_alerts"))
            subnet_scope = json.dumps(sorted({int(s) for s in subnet_ids_raw}))
    else:
        allowed = set(current_user.accessible_subnet_ids(extensions.SUBNET_MAP))
        ids = sorted({int(s) for s in subnet_ids_raw if is_whole(s) and int(s) in allowed})
        if not ids:
            # (Q225, AK1) the API-key route's rule, which this clamp was copied from without it: a subnet-restricted admin's selection that names none of their subnets - the untouched form,
            # since the "All Subnets" option is rendered only for an unrestricted account - used to store NULL, which `channel_allows_subnet` reads as EVERY subnet, and the channel then
            # carried the lease, device and client alerts of subnets its creator cannot see. The form is refused; nothing is written
            flash_field("subnet_ids", "Select at least one subnet this channel should cover.")
            return redirect(url_for("settings.settings_alerts"))
        subnet_scope = json.dumps(ids)

    if subnet_scope is not None and any(t in __alerts.WHOLE_NETWORK_ALERT_TYPES for t in alert_types):
        # (Q227, AM2) the daily summary lists every subnet in the subnet map and counts every device. A channel limited to some subnets - the only kind a subnet-restricted admin can
        # make - is not sent it (`alerts.channel_handles_alert`), and the form says so here instead of storing a tick that will never deliver
        flash(
            "The daily summary names every subnet, so only a channel for All Subnets can receive it. Untick Daily summary for this channel.",
            "error",
        )
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
        port = request.form.get("smtp_port", "587").strip()
        if not is_whole(port) or not 1 <= int(port) <= 65535:
            # (Q226, AL23) validated where it is typed: `int()` used to raise at send time and the operator read "failed"
            flash_field("smtp_port", "SMTP port must be a whole number from 1 to 65535.")
            return redirect(url_for("settings.settings_alerts"))
        config = {
            "smtp_host": request.form.get("smtp_host", "").strip(),
            "smtp_port": str(int(port)),
            "smtp_user": request.form.get("smtp_user", "").strip(),
            "smtp_pass": request.form.get("smtp_pass", "").strip(),
            "from_addr": request.form.get("from_addr", "").strip(),
            "to_addr": request.form.get("to_addr", "").strip(),
            "use_tls": "true" if request.form.get("use_tls") else "false",
            # (Q229) STARTTLS verifies the server's certificate unless the operator unticked it for this channel
            "tls_verify": "true" if request.form.get("tls_verify") else "false",
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
    elif channel_type == "discord":
        config = {
            "webhook_url": request.form.get("discord_webhook", "").strip(),
        }

    # (Q227, AM23) CRED-005 at the one save path that did not ask it: a URL never carries a password. A webhook's and ntfy's address is dialed as typed, so user-info in it is refused
    # here with the sentence every connection form uses; the secret has its own field (the header value, the ntfy token)
    # (Q228, AN6) and an address is an http(s) URL with a host; an ntfy server address carries no query
    refused = _address_refusal(channel_type, config)
    if refused:
        flash_field(*refused)
        return redirect(url_for("settings.settings_alerts"))

    # (Q226, AL2, AL3) every write-only key left blank on an edit keeps the stored value - while the channel names the same place; the two keys that used to be kept (`smtp_pass`, `api_token`)
    # were kept across a changed SMTP host, which CRED-002 forbids by name
    kept = _kept_secrets(channel_id, channel_type, config, stored)
    if not isinstance(kept, dict):
        flash_field(*kept)  # (field, sentence): the place changed, or the stored settings cannot be read (Q227, AM6)
        return redirect(url_for("settings.settings_alerts"))
    config = kept
    # (Q228) what a save over an unreadable row stores empty, said after the save
    emptied = _emptied(channel_type, config, stored)

    try:
        # config carries the channel's notification tokens — encrypt at rest (v5.7.0)
        config_blob = __alerts.encode_channel_config(config)
        with __db.jen_db() as db:
            with db.cursor() as cur:
                if channel_id:
                    cur.execute(
                        """
                        UPDATE alert_channels SET channel_type=%s, channel_name=%s, enabled=%s, config=%s, alert_types=%s, subnet_scope=%s
                        WHERE id=%s
                    """,
                        (
                            channel_type,
                            channel_name,
                            enabled,
                            config_blob,
                            json.dumps(alert_types),
                            subnet_scope,
                            channel_id,
                        ),
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
                            config_blob,
                            json.dumps(alert_types),
                            subnet_scope,
                        ),
                    )
            db.commit()
        flash(f"Alert channel '{channel_name}' saved.", "success")
        if emptied:
            flash(NOTHING_KEPT.format(fields=", ".join(emptied)), "warning")
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
        row = _stored_channel(channel_id)
        if row is None or not _may_act_on(row):  # (Q226, AL24)
            flash("Channel not found.", "error")
            return redirect(url_for("settings.settings_alerts"))
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE id=%s", (channel_id,))
            db.commit()
        name = row["channel_name"]
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
    config = {}
    name = "that channel"
    try:
        channel = _stored_channel(channel_id)
        if not channel or not _may_act_on(
            channel
        ):  # (Q226, AL24) a test sends the channel's secret: the caller must be one who may act on it
            flash("Channel not found.", "error")
            return redirect(url_for("settings.settings_alerts"))
        config = __alerts.get_channel_config(channel)
        name = channel["channel_name"]
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
        elif ctype == "pushover":
            ok = __alerts._send_pushover_channel(test_msg, config)
        else:
            ok = False
        if ok:
            flash(f"Test message sent successfully to '{channel['channel_name']}'.", "success")
        else:
            flash(f"Test failed for '{channel['channel_name']}'.", "error")
    except Exception as e:
        # v5.69.0-beta.2 (Q171) / v5.69.0-beta.3 (Q172): requests puts the URL (a bot token, a webhook secret) in its error text. The flash says only that it failed; the
        # log keeps the reason with the channel's secrets redacted (a plain `logger.exception` would write the traceback's text, token and all)
        logger.error(f"alert channel test failed ({name}): {__alerts._transport_error_text(e, config)}")
        flash(f"Test failed for '{name}' - the reason is in the Jen log.", "error")
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
    if alert_type not in DEFAULT_TEMPLATES:
        flash("Invalid alert type.", "error")
        return redirect(url_for("settings.settings_alerts"))
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_templates WHERE alert_type=%s", (alert_type,))
            db.commit()
        flash("Template reset to default.", "success")
        __user.audit("RESET_ALERT_TEMPLATE", alert_type, "Template reset to the default")
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
    # v5.69.0-beta.3 (Q172, item 3): the summary time is HH:MM in UTC. "7am" used to be saved and silently never matched, so the summary never came; a refusal is audited
    # like a save (the setting decides whether an alert is ever sent)
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", summary_time):
        flash_field("summary_time", "The daily summary time must be HH:MM in UTC, for example 07:00.")
        __user.audit("SAVE_ALERT_GLOBAL_REFUSED", "settings", f"daily summary time {summary_time[:20]!r} is not HH:MM")
        return redirect(url_for("settings.settings_alerts"))
    # (Q226, AL9) the forms' bounds are the table's (`setting_bounds`), so the way in and the way out agree; the exhaustion threshold had no upper bound
    if not __bounds.in_bounds("pool_exhaustion_free", pool_free):
        flash_field("pool_exhaustion_free", "Pool exhaustion threshold must be a whole number from 1 to 1000000.")
        return redirect(url_for("settings.settings_alerts"))
    if not __bounds.in_bounds("alert_threshold_pct", threshold):
        flash_field("alert_threshold_pct", "Utilization threshold must be between 1 and 100.")
        return redirect(url_for("settings.settings_alerts"))
    pool_free, threshold = str(int(pool_free)), str(int(threshold))
    if reserved_lease_mode not in ("always", "once"):
        reserved_lease_mode = "always"
    if not __user.set_global_settings(
        {
            "daily_summary_time": summary_time,
            "pool_exhaustion_free": pool_free,
            "alert_threshold_pct": threshold,
            "reserved_lease_mode": reserved_lease_mode,
        }
    ):  # (Q226, the review's P2 #5) one transaction, and "saved" only when it is
        flash("Global alert settings could not be saved. Check server logs for details.", "error")
        return redirect(url_for("settings.settings_alerts"))
    flash("Global alert settings saved.", "success")
    __user.audit(
        "SAVE_ALERT_GLOBAL",
        "settings",
        f"summary_time={summary_time} pool_exhaustion_free={pool_free} threshold={threshold}% reserved_lease_mode={reserved_lease_mode}",
    )
    return redirect(url_for("settings.settings_alerts"))


# v5.69.0-beta.2 (Q171): `/settings/save-telegram` and `/settings/test-telegram` are gone. No template has posted to them since the alert channels moved to the channel table, and
# they wrote a plaintext bot token into `settings` that no sender reads.
