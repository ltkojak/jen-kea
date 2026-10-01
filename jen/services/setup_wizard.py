"""
jen/services/setup_wizard.py
─────────────────────────────
v5.67.0 (Q115) — the service layer behind GET/POST /setup, the six-step
guided first-hour wizard. No new capability lives here: every function
below is a thin wrapper around a service Settings already calls
(jen.config.app_config, jen.services.kea/kea6/kea_ha/kea_host/
config_drift/config_revisions/recovery/dbexport) — this module exists
only to give the wizard one place to call them from, and to own the
wizard's own small piece of state (which step is done or skipped, and
whether the one-time post-password-change redirect has already fired).

Step state is a JSON blob in the `settings` key/value table (the same
store onboarding.py's "dismissed" flag and dbexport's schedule use) —
not a new table, since six small booleans don't need one.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# v5.67.0 (Q115) — only the steps THIS commit has a route for. Step 2
# of this Q adds "helper"/"baseline"/"recovery"/"investigate" here once
# their routes exist; current_step()/setup_home() resolve a step name
# straight to a url_for(), so a name with no registered route would
# crash every visit to bare /setup the moment it became "current".
STEPS = ("connect", "found")

_STATE_KEY = "setup_wizard_state"
_REDIRECT_SHOWN_KEY = "setup_wizard_redirect_shown"


# ── step state ────────────────────────────────────────────────────────────────


def get_state() -> dict:
    """`{step: "done"|"skipped"}` for whichever steps have been resolved;
    a step absent from the dict is still pending."""
    from jen.models.user import get_global_setting

    raw = get_global_setting(_STATE_KEY, "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in STEPS and v in ("done", "skipped")}


def set_step(step: str, status: str) -> None:
    """Record one step as "done" or "skipped". Unknown step names are a
    programming error (every caller passes a literal from STEPS), not an
    input to validate against a user-supplied value."""
    from jen.models.user import set_global_setting

    if step not in STEPS:
        raise ValueError(f"unknown setup step: {step!r}")
    if status not in ("done", "skipped"):
        raise ValueError(f"unknown setup status: {status!r}")
    state = get_state()
    state[step] = status
    set_global_setting(_STATE_KEY, json.dumps(state))


def current_step() -> str:
    """The first step not yet done or skipped, or the last one once every
    step has been resolved — /setup itself redirects here."""
    state = get_state()
    for step in STEPS:
        if step not in state:
            return step
    return STEPS[-1]


def all_resolved() -> bool:
    state = get_state()
    return all(step in state for step in STEPS)


# ── entry / one-time redirect ───────────────────────────────────────────────


def kea_connected() -> bool:
    """True once Jen has an API URL AND at least one named subnet — the
    bar "an existing install" clears without ever seeing /setup."""
    from jen import extensions

    return bool(extensions.KEA_API_URL) and bool(extensions.SUBNET_MAP)


def needs_entry_redirect() -> bool:
    """True exactly once per install: Kea isn't connected yet, and the
    one-time redirect hasn't already fired. Never true again afterward,
    even if Kea is later disconnected again — this is a first-run nudge,
    not a standing gate (Getting started links into /setup for anyone
    who wants it later)."""
    from jen.models.user import get_global_setting

    if get_global_setting(_REDIRECT_SHOWN_KEY, "false") == "true":
        return False
    return not kea_connected()


def mark_entry_redirect_shown() -> None:
    from jen.models.user import set_global_setting

    set_global_setting(_REDIRECT_SHOWN_KEY, "true")


# ── step 1: connect ──────────────────────────────────────────────────────────


def _probe_version(url: str, user: str, password: str, *, omit_service: bool, service: str = "dhcp4"):
    """One version-get against a candidate endpoint. Returns (version_text,
    error) — exactly one is non-empty. Deliberately a small, independent
    copy of jen.routes.settings.infrastructure._probe_once's shape rather
    than an import from a routes module (the wrong direction for a
    service to depend on) or a shared refactor of already-working,
    already-tested code — the wizard's own needs are simpler (no TLS
    client-cert override) and this is the whole function."""
    import requests

    payload = {"command": "version-get"}
    if not omit_service:
        payload["service"] = [service]
    try:
        resp = requests.post(url, json=payload, auth=(user, password), timeout=8)
        resp.raise_for_status()
        data = resp.json()
        d = data[0] if isinstance(data, list) else data
        if d.get("result") != 0:
            return "", d.get("text", "Kea returned an error")
        return (d.get("arguments", {}).get("extended", "") or d.get("text", "")).strip(), ""
    except Exception as e:
        return "", str(e)


def test_kea_connection(url: str, user: str, password: str, *, service: str = "dhcp4") -> dict:
    """Try `url` as given (Control Agent style, with a "service" field);
    if nothing answers, retry the same host on the daemon's own default
    direct-socket port (8004/8006) — the same two-step fallback
    jen.routes.settings.infrastructure.probe_kea() uses for an already-
    configured connection, run here against a connection that hasn't
    been saved yet. Returns
    {"ok", "mode": "ca"|"direct"|None, "url", "version", "version_text", "attempts"}."""
    from jen.services.kea import parse_kea_version

    attempts = []
    version_text, err = _probe_version(url, user, password, omit_service=False, service=service)
    attempts.append({"url": url, "mode": "ca", "error": err})
    if version_text:
        v = parse_kea_version(version_text)
        return {
            "ok": True,
            "mode": "ca",
            "url": url,
            "version": ".".join(str(n) for n in v) if v else "",
            "version_text": version_text,
            "attempts": attempts,
        }

    host = urlparse(url).hostname
    scheme = urlparse(url).scheme or "http"
    if host:
        alt = f"{scheme}://{host}:{8006 if service == 'dhcp6' else 8004}"
        version_text2, err2 = _probe_version(alt, user, password, omit_service=True, service=service)
        attempts.append({"url": alt, "mode": "direct", "error": err2})
        if version_text2:
            v = parse_kea_version(version_text2)
            return {
                "ok": True,
                "mode": "direct",
                "url": alt,
                "version": ".".join(str(n) for n in v) if v else "",
                "version_text": version_text2,
                "attempts": attempts,
            }

    return {"ok": False, "mode": None, "url": None, "version": "", "version_text": "", "attempts": attempts}


def test_kea_db(host: str, user: str, password: str, database: str, port: int = 3306):
    """(ok, info_or_error) — jen.services.dbexport.test_connection() is
    the one DB-connectivity tester this codebase already has."""
    from jen.services import dbexport

    return dbexport.test_connection(host, port, user, password, database)


def save_connection(*, api_url, api_user, api_pass, mode, kea_db_host, kea_db_user, kea_db_pass, kea_db_name) -> None:
    """Write both [kea] and [kea_db] in one reload — same choke point
    (app_config.write_values) Settings' own save-kea/save-kea-db routes
    use, just combined into the one write this step needs."""
    from jen.config import app_config

    items = [
        ("kea", "api_url", api_url),
        ("kea", "api_user", api_user),
        ("kea", "connection_mode", mode),
        ("kea_db", "host", kea_db_host),
        ("kea_db", "user", kea_db_user),
        ("kea_db", "database", kea_db_name),
    ]
    if api_pass:
        items.append(("kea", "api_pass", api_pass))
    if kea_db_pass:
        items.append(("kea_db", "password", kea_db_pass))
    app_config.write_values(items)


# ── step 2: what Jen found ──────────────────────────────────────────────────


def discover() -> dict:
    """Live facts about the primary Kea server: version, hooks (and what
    each buys), HA, v6 presence, and the subnet map Kea itself reports
    (named Subnet<id> by default — Kea's own config carries no richer
    name for a subnet than its CIDR; install.sh's own discovery names
    them the same way). Never raises — a failed probe just reports
    "unreachable" fields, same contract as every other live-Kea read in
    this codebase."""
    from jen import extensions
    from jen.services import capabilities, config_drift, kea_ha
    from jen.services import kea as __kea

    caps = capabilities.for_primary(with_config=True)
    dhcp4_cfg = None
    try:
        result = __kea.kea_command("config-get")
        if result.get("result") == 0:
            dhcp4_cfg = result.get("arguments", {}).get("Dhcp4")
    except Exception as e:
        logger.warning(f"setup_wizard.discover: config-get failed: {e}")

    ha = kea_ha.ha_config(dhcp4_cfg) if dhcp4_cfg else None
    live_subnets = config_drift.fetch_live_subnet_map("v4")
    proposed = {sid: {"name": f"Subnet{sid}", "cidr": cidr} for sid, cidr in sorted(live_subnets.items())}

    return {
        "reachable": caps.reachable,
        "kea_version": caps.kea_version_text,
        "connection_mode": extensions.KEA_CONNECTION_MODE,
        "hooks": {
            "host_cmds": caps.host_cmds,
            "lease_cmds": caps.lease_cmds,
            "ha_commands": caps.ha_commands,
            "ddns": caps.ddns,
        },
        "ha": ha,
        "ipv6_enabled": _ipv6_enabled(),
        "proposed_subnets": proposed,
    }


def _ipv6_enabled() -> bool:
    from jen.models.user import get_global_setting

    return get_global_setting("ipv6_enabled", "false") == "true"


def save_subnets(subnets: dict) -> None:
    from jen.config import app_config

    app_config.write_subnets(subnets)


HOOK_LOSS = {
    "host_cmds": "reservations are read-only",
    "lease_cmds": "lease search and lease deletion are unavailable",
    "ha_commands": "HA status and maintenance mode are unavailable",
}
HOOK_LABELS = {
    "host_cmds": "host_cmds",
    "lease_cmds": "lease_cmds",
    "ha_commands": "libdhcp_ha",
    "ddns": "DDNS updates",
}
