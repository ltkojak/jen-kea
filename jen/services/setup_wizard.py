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

import contextlib
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

STEPS = ("connect", "found", "helper", "baseline", "recovery", "investigate")

_STATE_KEY = "setup_wizard_state"
_REDIRECT_SHOWN_KEY = "setup_wizard_redirect_shown"
_STARTED_KEY = "setup_wizard_started_at"
_COMPLETED_KEY = "setup_wizard_completed_at"


# ── step state ────────────────────────────────────────────────────────────────


def get_state() -> dict:
    """`{step: "done"|"skipped"}` for whichever steps have been resolved;
    a step absent from the dict is still pending. Pure (besides the
    settings read) — Getting started's checklist calls this on every page
    load to link into whichever step is still open, so it must never have
    a side effect. mark_started() is the one place that starts the
    wizard's own clock, and only an actual /setup page view calls it."""
    from jen.models.user import get_global_setting

    raw = get_global_setting(_STATE_KEY, "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in STEPS and v in ("done", "skipped")}


def utc_iso() -> str:
    """The one way this module (and any caller outside it that stores a
    timestamp meant to compare against the wizard's own clock —
    routes/database.py's recovery_bundle() is the other one) writes a UTC
    timestamp: always timezone-AWARE, so two stored timestamps can always
    be compared without raising. v5.67.0-beta.7 (Q119, item f) — before
    this, _STARTED_KEY was written aware (datetime.now(timezone.utc)) but
    last_recovery_bundle_at was written naive (datetime.utcnow()) by a
    different module; comparing an aware and a naive datetime raises
    TypeError, not ValueError, so the try/except around that comparison
    never caught it."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str):
    """Parse an ISO timestamp as UTC, whether or not it carries a tzinfo
    offset — a value stored before this fix (naive) must still compare
    safely against one stored after it (aware). Raises ValueError for
    genuinely unparseable text, same as datetime.fromisoformat always
    has — callers that already guard with try/except ValueError need no
    change."""
    from datetime import datetime, timezone

    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def mark_started() -> None:
    """Start the wizard's own clock, the first time an actual /setup page
    is viewed. Called from routes/setup.py's _progress() (every step
    page), never from get_state() — onboarding.py's checklist() reads
    wizard state on every page load and must not start this clock just by
    existing."""
    from jen.models.user import get_global_setting, set_global_setting

    if not get_global_setting(_STARTED_KEY, ""):
        set_global_setting(_STARTED_KEY, utc_iso())


def elapsed_seconds() -> int | None:
    """How long the first hour took: from mark_started() to the moment the
    LAST step resolved (set_step() stores that), or — while a step is still
    open — to now. None if /setup hasn't been opened yet this install.

    v5.67.0-beta.8 (Q120, item j) — this used to measure to "now" always, so
    a finished wizard's "took N minutes" grew every time the page was
    revisited, a week later reading "took 10080 minutes"."""
    from datetime import datetime, timezone

    from jen.models.user import get_global_setting

    started = get_global_setting(_STARTED_KEY, "")
    if not started:
        return None
    try:
        start = parse_utc(started)
    except ValueError:
        return None
    end = datetime.now(timezone.utc)
    completed = get_global_setting(_COMPLETED_KEY, "")
    if completed:
        # an unreadable stored time falls back to measuring to now, as before
        with contextlib.suppress(ValueError):
            end = parse_utc(completed)
    return max(0, int((end - start).total_seconds()))


def set_step(step: str, status: str) -> None:
    """Record one step as "done" or "skipped". Unknown step names are a
    programming error (every caller passes a literal from STEPS), not an
    input to validate against a user-supplied value."""
    from jen.models.user import set_global_setting

    if step not in STEPS:
        raise ValueError(f"unknown setup step: {step!r}")
    if status not in ("done", "skipped"):
        raise ValueError(f"unknown setup status: {status!r}")
    from jen.models.user import get_global_setting

    state = get_state()
    state[step] = status
    set_global_setting(_STATE_KEY, json.dumps(state))
    # v5.67.0-beta.8 (Q120, item j) — the moment the last step resolves is the end of the first hour;
    # stored once, never overwritten by a later revisit.
    if all(name in state for name in STEPS) and not get_global_setting(_COMPLETED_KEY, ""):
        set_global_setting(_COMPLETED_KEY, utc_iso())


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


def test_kea_connection(url: str, user: str, password: str, *, service: str = "dhcp4", verify=None, cert=None) -> dict:
    """Try `url` as given (Control Agent style, with a "service" field);
    if nothing answers, retry the same host on the daemon's own default
    direct-socket port (8004/8006) — the same two-step fallback
    jen.routes.settings.infrastructure.probe_kea() uses for an already-
    configured connection, run here against a connection that hasn't
    been saved yet. Returns
    {"ok", "mode": "ca"|"direct"|None, "url", "version", "version_text", "attempts"}.

    v5.67.0-beta.5 (Q117, item f) — `verify`/`cert` let the Connect
    step's own Advanced TLS fields (not yet saved) override the
    currently-configured material, the same way Settings' own https
    setup flow probes a candidate before adopting it. Both attempts
    below go through kea.test_connection(), the one shared TLS-aware
    probe primitive — this function used to keep its own copy that
    never looked at TLS settings at all."""
    from jen.services.kea import parse_kea_version
    from jen.services.kea import test_connection as _probe

    attempts = []
    version_text, err = _probe(url, user, password, service=service, omit_service=False, verify=verify, cert=cert)
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
        version_text2, err2 = _probe(alt, user, password, service=service, omit_service=True, verify=verify, cert=cert)
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


def save_connection(
    *,
    api_url,
    api_user,
    api_pass,
    mode,
    kea_db_host,
    kea_db_user,
    kea_db_pass,
    kea_db_name,
    api_ca="",
    api_tls_verify=True,
    api_client_cert="",
    api_client_key="",
) -> None:
    """Write both [kea] and [kea_db] in one reload — same choke point
    (app_config.write_values) Settings' own save-kea/save-kea-db routes
    use, just combined into the one write this step needs.

    v5.67.0-beta.5 (Q117, item f) — the four Advanced TLS keys, same as
    save_infra_kea's own writes: always written (not conditional like
    the password fields) since an unchecked expander means "no TLS
    material", which must actively clear any value a previous save left
    behind, not silently keep it."""
    from jen.config import app_config

    items = [
        ("kea", "api_url", api_url),
        ("kea", "api_user", api_user),
        ("kea", "connection_mode", mode),
        ("kea", "api_ca", api_ca),
        ("kea", "api_tls_verify", "true" if api_tls_verify else "false"),
        ("kea", "api_client_cert", api_client_cert),
        ("kea", "api_client_key", api_client_key),
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
    each buys), HA, v6 presence, and the subnet map Kea itself reports.
    Never raises — a failed probe just reports "unreachable" fields,
    same contract as every other live-Kea read in this codebase.

    v5.67.0-beta.5 (Q117, item h) — a subnet Jen already knows by the
    SAME id and CIDR keeps its own name as the proposal (this step used
    to re-propose "Subnet<id>" for every live subnet, renaming away
    whatever the operator had already called it, every time /setup was
    revisited). A changed CIDR under a reused id, or a genuinely new id,
    still proposes "Subnet<id>" — there's no existing name to keep.
    "orphaned_subnets" lists what Jen has that Kea's live report did
    NOT return, for the template to offer as an opt-in removal — never
    dropped silently by the merge in routes/setup.py."""
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
    known = extensions.SUBNET_MAP
    proposed = {}
    for sid, cidr in sorted(live_subnets.items()):
        existing = known.get(sid)
        name = existing["name"] if existing and existing["cidr"] == cidr else f"Subnet{sid}"
        proposed[sid] = {"name": name, "cidr": cidr}
    orphaned = {sid: info for sid, info in known.items() if sid not in live_subnets}

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
        "orphaned_subnets": orphaned,
    }


def _ipv6_enabled() -> bool:
    from jen.models.user import get_global_setting

    return get_global_setting("ipv6_enabled", "false") == "true"


def save_subnets(renamed: dict, remove_ids: set = frozenset()) -> tuple[dict, str | None]:
    """Merge `renamed` (the Found step's own proposed/edited subnets,
    `{sid: {"name", "cidr"}}`) into Jen's FULL existing subnet map —
    never a bare replace (v5.67.0-beta.5, Q117, item h: the old
    behavior silently dropped any subnet Jen knew about that Kea's
    live report didn't return this time). `remove_ids` drops only the
    ids a superadmin explicitly checked for removal among the
    orphaned ones discover() reported — omission never removes
    anything. Returns (final_map, error): error is None on success,
    else the first bad name's reason from the choke point
    (AppConfig.write_subnets) — nothing is written on a bad name."""
    from jen import extensions
    from jen.config import app_config

    merged = dict(extensions.SUBNET_MAP)
    merged.update(renamed)
    for sid in remove_ids:
        merged.pop(sid, None)
    try:
        app_config.write_subnets(merged)
    except ValueError as e:
        return merged, str(e)
    return merged, None


def probe_v6(url: str, user: str, password: str, *, omit_service: bool) -> dict:
    """Explicit, superadmin-pressed check for whether Kea's dhcp6 daemon
    answers at all (v5.67.0-beta.5, Q117, item g) — never run
    automatically: `discover()`'s own `ipv6_enabled` only ever reported
    Jen's OWN switch, but the Found step's old prose implied it also
    meant "Kea has no DHCPv6" on a dual-stack site, which it never
    actually checked. CLAUDE.md "IPv6": nothing v6 fires unless asked —
    this function is the one place that's now true even in the asking.

    `url`/`omit_service` mirror test_kea_connection's own CA-vs-direct
    split: CA mode reuses the already-connected v4 Control Agent URL
    with service=["dhcp6"]; direct mode needs its own per-daemon socket
    URL, since Kea has no way to infer one daemon's control socket from
    another's. Returns {"ok", "version", "version_text",
    "subnet6_count", "proposed_subnets6", "error"} — never raises; a
    failed probe just reports ok: False, same contract as every other
    live-Kea read in this codebase."""
    from jen.services import kea_config_view as _view
    from jen.services.kea import parse_kea_version
    from jen.services.kea import probe_command as _probe_cmd

    version_result, err = _probe_cmd(url, user, password, "version-get", service="dhcp6", omit_service=omit_service)
    if version_result is None:
        return {
            "ok": False,
            "error": err,
            "version": "",
            "version_text": "",
            "subnet6_count": 0,
            "proposed_subnets6": {},
        }

    version_text = (version_result.get("arguments", {}).get("extended", "") or version_result.get("text", "")).strip()
    v = parse_kea_version(version_text)

    proposed6 = {}
    cfg_result, _cfg_err = _probe_cmd(url, user, password, "config-get", service="dhcp6", omit_service=omit_service)
    if cfg_result is not None:
        dhcp6_cfg = cfg_result.get("arguments", {}).get("Dhcp6", {})
        for s, _sn in sorted(_view.iter_subnet6(dhcp6_cfg), key=lambda pair: pair[0]["id"]):
            proposed6[s["id"]] = {"name": f"Subnet{s['id']}", "cidr": s.get("subnet", "")}

    return {
        "ok": True,
        "error": "",
        "version": ".".join(str(n) for n in v) if v else "",
        "version_text": version_text,
        "subnet6_count": len(proposed6),
        "proposed_subnets6": proposed6,
    }


def enable_v6(url: str, subnets6: dict) -> None:
    """ "Manage IPv6 in Jen" — called only after probe_v6() has already
    confirmed dhcp6 answers. Flips Jen's own display flag, saves the
    confirmed dhcp6 endpoint (so later reads use it instead of inheriting
    v4's), and proposes the subnet6 map. Deliberately NOT toggle_ipv6()
    (routes/settings/infrastructure.py): that route's job is
    starting/stopping kea-dhcp6-server over SSH on a server that isn't
    running it yet — here it already IS running and already answered,
    so there's nothing to start."""
    from jen.config import app_config
    from jen.models.user import set_global_setting

    app_config.write_values([("kea6", "api_url", url)])
    app_config.write_subnets6(subnets6)
    set_global_setting("ipv6_enabled", "true")


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


# ── step 3: the Kea host helper ─────────────────────────────────────────────


def primary_server() -> dict:
    """extensions.KEA_SERVERS[0] — server id 1, the primary Kea host the
    connect step just configured. config.py's derive_kea_servers() always
    returns an id-1 entry (even with a blank ssh_host), so this never
    raises."""
    from jen import extensions

    return extensions.KEA_SERVERS[0]


def ssh_target_ready(server: dict) -> bool:
    return bool(server.get("ssh_host") and server.get("ssh_user"))


NO_SSH_TARGET = "Set the SSH host and user for this Kea server first (the helper step) — Jen has nowhere to connect."


def save_ssh_target(host: str, user: str) -> tuple[bool, str]:
    """Validate and write [kea_ssh] host/user — the same validators and
    the same app_config.write_values choke point
    jen.routes.settings.infrastructure.save_infra_ssh() already uses for
    server 1. Returns (ok, error_message)."""
    from jen.config import app_config
    from jen.services import auth as __auth

    host = (host or "").strip()
    user = (user or "").strip()
    if not host or not __auth.valid_ssh_target(host):
        return False, "Enter a valid SSH host (hostname or IP address)."
    if not user or not __auth.valid_unix_username(user):
        return False, "Enter a valid unix username."
    app_config.write_values([("kea_ssh", "host", host), ("kea_ssh", "user", user)])
    return True, ""


def test_ssh(server: dict) -> dict:
    """Open and immediately close an SSH connection — the same primitive
    every other Kea-host feature uses (jen.services.kea6._connect_ssh).
    {"ok": bool, "detail": str}."""
    from jen.services import kea6 as __kea6

    try:
        ssh = __kea6._connect_ssh(server)
        ssh.close()
        return {"ok": True, "detail": ""}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def helper_status(server: dict) -> dict:
    from jen.services import kea_host as __kea_host

    return __kea_host.check_helper(server)


def install_helper_step(server: dict) -> dict:
    """One call to the real installer — {"ok", "version", "code", "detail"}.
    `detail` is already a complete, context-specific message (it covers
    the legacy-sudo-grant bootstrap, a stale sudoers override, and the
    by-hand fallback command on its own), so the route surfaces it
    verbatim rather than re-deriving kea_host.install_helper()'s many
    branches here.

    v5.67.0-beta.8 (Q120, item a) — refused up front without an SSH host
    and user (the step's own "save target" form is what sets them), and a
    connection that cannot be opened (the key not yet authorised — the
    normal first try) comes back as code "unreachable" with the transport's
    own wording, never as an exception out of the route."""
    from jen.services import kea_host as __kea_host

    if not ssh_target_ready(server):
        return {"ok": False, "version": None, "code": "no-ssh", "detail": NO_SSH_TARGET}
    return __kea_host.install_helper(server)


def helper_download_command() -> str:
    """The "verified by-hand" one-liner (docs/runbooks.md's "Online — the
    verified one-liner"). Already called across the routes/services
    boundary from jen.routes.settings.infrastructure, so doing the same
    here from another service follows existing precedent."""
    from jen.services import kea_host as __kea_host

    return __kea_host._helper_download_command()


# ── step 4: baseline ─────────────────────────────────────────────────────────


def capture_baseline(server: dict, service: str = "dhcp4") -> dict:
    """Reading a live config IS how Jen records a baseline revision
    (kea_host.read_config -> _capture_baseline_or_external_change) —
    there's no separate "create baseline" action to call. Returns
    {"ok": bool, "revision": dict|None, "detail": str}.

    v5.67.0-beta.8 (Q120, item a) — refuses early without an SSH host and
    user: "Skip" on the helper step, then "Capture baseline", used to reach
    an SSH connect with nothing to connect to."""
    from jen.services import config_revisions as __rev
    from jen.services import kea_host as __kea_host

    if not ssh_target_ready(server):
        return {"ok": False, "revision": None, "detail": NO_SSH_TARGET}
    why: list[str] = []
    cfg = __kea_host.read_config(server, service, errors=why)
    if cfg is None:
        return {
            "ok": False,
            "revision": None,
            "detail": why[0]
            if why
            else "Could not read Kea's config over SSH — check the helper step above (host, user, and the helper itself).",
        }
    return {"ok": True, "revision": __rev.latest(server.get("id"), service), "detail": ""}


# ── step 5: recovery point ───────────────────────────────────────────────────


def recovery_bundle_status() -> dict:
    """Whether a REAL recovery bundle has actually been downloaded, not
    just whether a button on this step was clicked (v5.67.0-beta.5,
    Q117, item i — the old "I've saved it" button set the step "done"
    unconditionally). `last_recovery_bundle_at` is written by
    routes/database.py's recovery_bundle() route itself, only once its
    streaming response has fully finished sending (never on a build
    failure or a client disconnecting mid-download). "fresh" is true
    only when that bundle is newer than THIS setup run's own start —
    an old bundle from months ago doesn't retroactively complete a
    setup run that never made a new one.
    Returns {"exists", "at", "size", "excluded_audit_history", "fresh"}.
    """
    from jen.models.user import get_global_setting

    at = get_global_setting("last_recovery_bundle_at", "")
    if not at:
        return {"exists": False, "at": "", "size": 0, "excluded_audit_history": False, "fresh": False}

    size = int(get_global_setting("last_recovery_bundle_size", "0") or 0)
    excluded = get_global_setting("last_recovery_bundle_excluded_audit", "false") == "true"

    fresh = False
    started = get_global_setting(_STARTED_KEY, "")
    if started:
        # v5.67.0-beta.7 (Q119, item f) — parse_utc(), not a bare
        # datetime.fromisoformat(): `at` may still be a NAIVE timestamp
        # stored before this fix, which fromisoformat() alone would
        # compare against `started`'s aware value and raise TypeError —
        # not caught by the ValueError guard this comparison has always
        # had (reproduced: this is exactly what made /setup/recovery,
        # its "done" POST, and /getting-started 500 for every admin once
        # a bundle had actually been downloaded).
        try:
            fresh = parse_utc(at) >= parse_utc(started)
        except ValueError:
            fresh = False

    return {"exists": True, "at": at, "size": size, "excluded_audit_history": excluded, "fresh": fresh}


# ── step 6: investigate ──────────────────────────────────────────────────────


def recent_leases(limit: int = 5) -> list[dict]:
    """The `limit` most recent active DHCPv4 leases, subnet-restricted the
    same way dashboard.py's own /api/recent-leases widget is — a small,
    independent query rather than reusing that route's private
    HTML-fragment response, since this step needs a plain row of data to
    link from (to /client's Investigation page — v5.67.0-beta.5, Q117,
    item k, not /tools/explain), not that widget's own markup."""
    from jen import extensions
    from jen.models import db as __db
    from jen.services.access import add_subnet_restriction

    out = []
    try:
        with __db.kea_db() as conn:
            where, params = add_subnet_restriction(["l.state=0"], [], "l", "subnet_id")
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT inet_ntoa(l.address) AS ip, l.hostname,
                           HEX(l.hwaddr) AS mac_hex, l.subnet_id,
                           (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained
                    FROM lease4 l
                    WHERE {" AND ".join(where)}
                    ORDER BY (l.expire - INTERVAL l.valid_lifetime SECOND) DESC
                    LIMIT %s
                    """,
                    (*params, limit),
                )
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    sname = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", str(row["subnet_id"]))
                    out.append(
                        {
                            "ip": row["ip"],
                            "hostname": row["hostname"] or "",
                            "mac": mac,
                            "subnet_name": sname,
                            "obtained": row["obtained"],
                        }
                    )
    except Exception as e:
        logger.warning(f"setup_wizard.recent_leases failed: {e}")
    return out
