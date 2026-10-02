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
from urllib.parse import urlsplit, urlunsplit

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


def _direct_guess(url: str, service: str) -> str | None:
    """The same host on the daemon's own default control-socket port (8004 for dhcp4, 8006 for dhcp6) —
    but ONLY when the typed URL named no port at all (v5.67.0-beta.8, Q120, item k). A typed port is the
    operator's answer; guessing another one on top of it answered the wrong question and put the wrong
    error on screen. Built with urlsplit/urlunsplit and an IPv6 literal re-bracketed (item l):
    `urlparse(url).hostname` strips the brackets, and `f"{scheme}://{host}:{port}"` of the bare
    `2001:db8::1` is `http://2001:db8::1:8004`, which no HTTP client can parse."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return None  # a malformed port: nothing to guess from
    host = parts.hostname
    if port is not None or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    return urlunsplit((parts.scheme or "http", f"{netloc}:{8006 if service == 'dhcp6' else 8004}", "", "", ""))


# What each answer to an identification config-get means for the connection mode.
_DAEMON_KEYS = {"Dhcp4": "dhcp4", "Dhcp6": "dhcp6", "D2": "d2"}


def test_kea_connection(
    url: str,
    user: str,
    password: str,
    *,
    service: str = "dhcp4",
    verify=None,
    cert=None,
    default_mode: str = "ca",
) -> dict:
    """Probe the URL the operator typed — and decide what answered. Returns
    {"ok", "mode": "ca"|"direct"|None, "url", "version", "version_text", "identified", "attempts"};
    each attempt is {"url", "typed", "mode" (the probe's style), "error" ("" when it answered)}.

    v5.67.0-beta.8 (Q120, items b, e, k, l):
    - The typed URL is tried FIRST, in direct style (no `service` field): a Control Agent answers that
      with its own version, a daemon with its own, so reachability does not depend on the daemon behind
      a Control Agent being up. Only a typed URL with NO port also gets the `:8004`/`:8006` guess.
    - The mode comes from kea.identify_daemon() — the one Settings uses — never from "it answered a
      command with a `service` field": verified against real Kea 3.0.3/3.2.0/3.3.1 (tests/kea_compat),
      a daemon answers such a command exactly as it answers one without, so every daemon was being
      saved as Control Agent mode (after which [kea6] and [d2] fell back to the dhcp4 socket, and an
      existing direct-mode install that re-submitted Connect was flipped). "Control-agent" -> ca,
      after confirming the dhcp4 service behind it answers too; a daemon key -> direct; an answer that
      cannot be identified -> `default_mode` (the route passes the CURRENTLY saved mode when the URL is
      the saved one, so a transient identification failure never flips it).

    `verify`/`cert` let the Connect step's own Advanced TLS fields (not yet saved) override the
    configured material (Q117, item f); pass kea.NO_CLIENT_CERT for "no client certificate at all"."""
    from jen.services import kea as __kea
    from jen.services.kea import parse_kea_version

    def _version_of(text: str) -> str:
        v = parse_kea_version(text)
        return ".".join(str(n) for n in v) if v else ""

    attempts: list[dict] = []
    candidates = [(url, True)]
    guess = _direct_guess(url, service)
    if guess:
        candidates.append((guess, False))

    for cand_url, typed in candidates:
        text, err = __kea.test_connection(
            cand_url, user, password, service=service, omit_service=True, verify=verify, cert=cert
        )
        attempt = {"url": cand_url, "typed": typed, "mode": "direct", "error": err}
        attempts.append(attempt)
        if not text:
            continue

        key = __kea.identify_daemon(cand_url, user, password, verify=verify, cert=cert)
        if key in _DAEMON_KEYS and _DAEMON_KEYS[key] != service:
            attempt["error"] = f"{cand_url} is kea-{_DAEMON_KEYS[key]}'s control socket, not kea-{service}'s."
            continue
        if key in _DAEMON_KEYS:
            mode = "direct"
        elif key == "Control-agent":
            mode = "ca"
            # Jen will send every command to a Control Agent with a `service` field, so the daemon
            # behind it has to answer THAT way before this counts as connected.
            text2, err2 = __kea.test_connection(
                cand_url, user, password, service=service, omit_service=False, verify=verify, cert=cert
            )
            attempts.append({"url": cand_url, "typed": typed, "mode": "ca", "error": err2})
            if not text2:
                continue
            text = text2
        else:
            mode = default_mode if default_mode in ("ca", "direct") else "ca"
        return {
            "ok": True,
            "mode": mode,
            "url": cand_url,
            "version": _version_of(text),
            "version_text": text,
            "identified": key,
            "attempts": attempts,
        }

    return {
        "ok": False,
        "mode": None,
        "url": None,
        "version": "",
        "version_text": "",
        "identified": None,
        "attempts": attempts,
    }


def test_kea_db(host: str, user: str, password: str, database: str, port: int | None = None, ssl_ca: str | None = None):
    """(ok, info_or_error) — jen.services.dbexport.test_connection() is
    the one DB-connectivity tester this codebase already has.

    v5.67.0-beta.8 (Q120, item g) — tests with the port and the `[kea_db] ssl_ca` the pool will use:
    this used to dial 3306 in plaintext whatever was configured, so a database that needs TLS (or
    listens elsewhere) failed here, or worse passed here and failed in the app."""
    from jen import extensions
    from jen.services import dbexport

    return dbexport.test_connection(
        host,
        extensions.KEA_DB_PORT if port is None else port,
        user,
        password,
        database,
        extensions.KEA_DB_SSL_CA if ssl_ca is None else ssl_ca,
    )


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
    kea_db_port=None,
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
    behind, not silently keep it.

    v5.67.0-beta.8 (Q120, item g) — the Kea database pools are reset after the write
    (models.db.reset_kea_pools): write_values() re-derives the extensions globals but not a pool that
    already exists, and a pool built while the config still held placeholders kept dialling them until a
    restart — so the very next step's lease query failed against settings the operator had just fixed.
    `kea_db_port` is written only when given."""
    from jen.config import app_config
    from jen.models import db as __db

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
    if kea_db_port is not None:
        items.append(("kea_db", "port", str(int(kea_db_port))))
    if api_pass:
        items.append(("kea", "api_pass", api_pass))
    if kea_db_pass:
        items.append(("kea_db", "password", kea_db_pass))
    app_config.write_values(items)
    __db.reset_kea_pools()


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
        "ha_view": ha_peer_view(ha, extensions.KEA_SERVERS),
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


def _same_network(a: str, b: str) -> bool:
    """Two CIDR strings naming the same network ("2001:db8::/64" vs "2001:DB8:0::/64"); plain text equality
    when either does not parse."""
    import ipaddress

    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b


def merge_subnets6(live: dict, known: dict) -> tuple[dict, dict]:
    """(proposed, orphaned) for Jen's `[subnets6]` — the v6 twin of what discover() does for v4
    (Q117, item h), which "Manage IPv6 in Jen" did not do: it replaced the whole section with
    `Subnet<id>` names and no pairing (v5.67.0-beta.8, Q120, item c).

    `live` is `{id: cidr}` from the daemon; `known` is Jen's current SUBNET6_MAP. A subnet Jen already
    has under the SAME id and network keeps its own entry — name AND paired_subnet4_id; a new id, or a
    reused id on a different network, is proposed as `Subnet<id>` (there is no name to keep). `orphaned`
    is what Jen has that the daemon did not report: offered for removal, never dropped by omission."""
    proposed: dict = {}
    for sid, cidr in sorted(live.items()):
        existing = known.get(sid)
        if existing and _same_network(existing.get("cidr", ""), cidr):
            proposed[sid] = dict(existing)
        else:
            proposed[sid] = {"name": f"Subnet{sid}", "cidr": cidr, "paired_subnet4_id": None}
    orphaned = {sid: dict(info) for sid, info in known.items() if sid not in live}
    return proposed, orphaned


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
    "subnet6_count", "proposed_subnets6", "orphaned_subnets6", "error"} —
    never raises; a failed probe just reports ok: False, same contract as
    every other live-Kea read in this codebase.

    v5.67.0-beta.8 (Q120, item d) — "answered" now means a kea-dhcp6 answered: `config-get` must succeed
    AND carry a `Dhcp6` section. Before, any Kea endpoint passed (a dhcp4 socket pasted into the v6 box
    answers version-get), and a missing `Dhcp6` key read as "0 subnets"; a daemon answering
    `config-get` with an error also still read as ok, so "Manage IPv6 in Jen" could be offered, and
    pressed, with nothing known about what it would write (item c)."""
    from jen import extensions
    from jen.services import kea_config_view as _view
    from jen.services.kea import parse_kea_version
    from jen.services.kea import probe_command as _probe_cmd

    empty = {"version": "", "version_text": "", "subnet6_count": 0, "proposed_subnets6": {}, "orphaned_subnets6": {}}

    version_result, err = _probe_cmd(url, user, password, "version-get", service="dhcp6", omit_service=omit_service)
    if version_result is None:
        return {"ok": False, "error": err, **empty}

    version_text = (version_result.get("arguments", {}).get("extended", "") or version_result.get("text", "")).strip()
    v = parse_kea_version(version_text)
    version = ".".join(str(n) for n in v) if v else ""
    known = {"version": version, "version_text": version_text}

    cfg_result, cfg_err = _probe_cmd(url, user, password, "config-get", service="dhcp6", omit_service=omit_service)
    if cfg_result is None:
        return {"ok": False, "error": f"config-get failed: {cfg_err}", **empty, **known}
    arguments = cfg_result.get("arguments") or {}
    dhcp6_cfg = arguments.get("Dhcp6")
    if not isinstance(dhcp6_cfg, dict):
        found = next((k for k in arguments if k != "hash"), None)
        return {
            "ok": False,
            "error": (
                "that endpoint answered, but it is not kea-dhcp6 — its config-get has no Dhcp6 section"
                + (f" (it is {found})" if found else "")
            ),
            **empty,
            **known,
        }

    live = {s["id"]: s.get("subnet", "") for s, _sn in _view.iter_subnet6(dhcp6_cfg) if s.get("id") is not None}
    proposed6, orphaned6 = merge_subnets6(live, extensions.SUBNET6_MAP)

    return {
        "ok": True,
        "error": "",
        "version": version,
        "version_text": version_text,
        "subnet6_count": len(proposed6),
        "proposed_subnets6": proposed6,
        "orphaned_subnets6": orphaned6,
    }


def enable_v6(url: str, subnets6: dict, remove_ids: set = frozenset()) -> str | None:
    """ "Manage IPv6 in Jen" — called only after probe_v6() has already
    confirmed dhcp6 answered. Flips Jen's own display flag, saves the
    confirmed dhcp6 endpoint (so later reads use it instead of inheriting
    v4's), and merges the proposed subnet6 map into what Jen already has.
    Deliberately NOT toggle_ipv6()
    (routes/settings/infrastructure.py): that route's job is
    starting/stopping kea-dhcp6-server over SSH on a server that isn't
    running it yet — here it already IS running and already answered,
    so there's nothing to start.

    v5.67.0-beta.8 (Q120, item c) — a MERGE, never `write_subnets6(proposed)`: `subnets6` is
    probe_v6()'s proposal (which already keeps the name and pairing of every subnet whose id and network
    match), laid over Jen's current map; whatever Jen has that the daemon did not report stays unless its
    id is in `remove_ids` (the superadmin's explicit, unchecked-by-default choice). The subnets are
    written FIRST: a name the writer refuses comes back as the error text (None on success) before
    anything else has changed, so a failure leaves Jen exactly as it was — no half-enabled IPv6."""
    from jen import extensions
    from jen.config import app_config
    from jen.models.user import set_global_setting

    merged = dict(extensions.SUBNET6_MAP)
    merged.update(subnets6)
    for sid in remove_ids:
        merged.pop(sid, None)
    try:
        app_config.write_subnets6(merged)
    except ValueError as e:
        return str(e)
    app_config.write_values([("kea6", "api_url", url)])
    set_global_setting("ipv6_enabled", "true")
    return None


# ── HA peers (what Kea says) vs servers (what Jen manages) ──────────────────


def _origin(url: str) -> str:
    """`scheme://host[:port]` of a URL — the path dropped, an IPv6 literal re-bracketed. "" if it has no host."""
    parts = urlsplit(url or "")
    host = parts.hostname
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parts.scheme or "http", netloc, "", "", ""))


def _host_of(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower()


def ha_peer_view(ha: dict | None, servers: list) -> dict | None:
    """Two different facts the Found step used to print as one (v5.67.0-beta.8, Q120, item m): how many HA
    peers KEA says it has (`ha.peers`), and how many servers JEN manages (`extensions.KEA_SERVERS`). With
    two Kea peers and one Jen-managed server the page read as if both were connected.

    Returns None without an HA hook, else {"mode", "detected", "managed", "peers": [{"name", "url",
    "role", "managed", "add_url", "add_role"}]}. A peer is "managed" when it is this very server, or when
    its URL's host or its name matches a server Jen manages; every other peer carries `add_url` — its
    origin, for the "Add this peer to Jen" action to prefill on the Servers form. It never carries
    credentials: Jen cannot know them, and does not invent them."""
    if not ha:
        return None
    this_name = (ha.get("this_server_name") or "").lower()
    managed_hosts = {_host_of(s.get("api_url", "")) for s in servers} - {""}
    managed_names = {(s.get("name") or "").lower() for s in servers} - {""}
    mode = ha.get("mode") or ""

    def _jen_role(kea_role: str) -> str:
        if kea_role == "primary":
            return "primary"
        if kea_role == "secondary":
            return "peer" if mode == "load-balancing" else "standby"
        return "standby"

    peers = []
    for peer in ha.get("peers") or []:
        if not isinstance(peer, dict):
            continue
        name = peer.get("name") or ""
        url = peer.get("url") or ""
        managed = (
            name.lower() == this_name
            or (name.lower() in managed_names)
            or (_host_of(url) in managed_hosts and _host_of(url) != "")
        )
        peers.append(
            {
                "name": name,
                "url": url,
                "role": peer.get("role") or "",
                "managed": managed,
                "add_url": "" if managed else _origin(url),
                "add_role": _jen_role(peer.get("role") or ""),
            }
        )
    return {"mode": mode, "detected": len(peers), "managed": len(servers), "peers": peers}


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
