"""
jen/services/capabilities.py
─────────────────────────────
v5.64.0 (Q83) — one place that knows what each Kea server can do.

Before this, every feature decided its own availability from the raw
ingredients — `helper_version >= …`, a Kea version tuple, "is this direct
mode" — and worded the reason its own way; the helper-version gate alone
lived in three places (the SSH card's button, the installer's "already"
answer, the feature's own check), which is what the old rule "change all
three together" was guarding against. `ServerCapabilities` is the answer
to "can this server do X, and if not, why" — derived from the Kea
version, the connection mode, the recorded helper version and the config
Jen already reads, by the pure `derive()`; `for_server()` gathers the
inputs (memoised per request, cached 60 s per server) and calls it.

Facts a server's capabilities can't be derived from are reported honestly
rather than guessed: a server that never answered has no version
(`reachable` False, every version-gated capability False), and the
hook-derived ones (`host_cmds`, `lease_cmds`, `ha_commands`, `ddns`) are
read from the config Jen already caches for the ACTIVE server only —
another server's config isn't fetched for a capability lookup, so those
are False there, with a `why()` that says so.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, fields

from jen import extensions
from jen.services.write_mode import MODE_SENTENCES

logger = logging.getLogger(__name__)

CA_DEPRECATED_FROM = (3, 0, 0)  # ISC deprecated the Control Agent in 3.0…
CA_REMOVED_FROM = (3, 2, 0)  # …and removes it in 3.2
DIRECT_SOCKET_MIN = (2, 7, 2)  # per-daemon control sockets exist from here
DROP_REASONS_FROM = (3, 2, 0)  # the extra pkt4-* drop-reason counters (Q52)

_CACHE_TTL_S = 60.0
_version_cache: dict = {}  # server_id -> {"at": monotonic, "text": str | None}

HOOK_HOST_CMDS = "libdhcp_host_cmds.so"
HOOK_LEASE_CMDS = "libdhcp_lease_cmds.so"
HOOK_HA = "libdhcp_ha.so"


# ── version predicates — the one place the thresholds live ───────────────


def supports_direct_socket(v: tuple | None) -> bool:
    """CONFIRMED: per-daemon control sockets exist from Kea 2.7.2. An unknown
    version is NOT confirmed (v5.65.2, Q91 h): a server Jen never reached must not
    report the capability as on. Setup and preflight paths that re-check before
    writing anything use `may_attempt_direct_socket` instead."""
    return v is not None and v >= DIRECT_SOCKET_MIN


def ships_control_agent(v: tuple | None) -> bool:
    """CONFIRMED: False from Kea 3.2, which removes the Control Agent; an
    unknown version is not confirmed either. See `may_ship_control_agent`."""
    return v is not None and v < CA_REMOVED_FROM


def may_attempt_direct_socket(v: tuple | None) -> bool:
    """The permissive reading for the paths that go on to re-check (a probe, a
    preflight, a write that verifies): an unknown version is worth trying."""
    return v is None or v >= DIRECT_SOCKET_MIN


def may_ship_control_agent(v: tuple | None) -> bool:
    """Permissive twin of `ships_control_agent`: unknown counts as "might"."""
    return v is None or v < CA_REMOVED_FROM


# ── connection mode — the one read of it ──────────────────────────────────


def is_direct() -> bool:
    """True when Jen talks to each daemon's own control socket. Always a
    fresh read of the configured mode (never cached): routes that switch
    the mode read it before AND after the write."""
    return extensions.KEA_CONNECTION_MODE == "direct"


def is_ca() -> bool:
    return not is_direct()


# ── the model ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ServerCapabilities:
    server_id: object = None
    reachable: bool = False
    kea_version: tuple | None = None
    kea_version_text: str = ""
    # transport
    control_agent: bool = False  # ca mode AND a Kea that still ships the Control Agent
    ca_deprecated: bool = False  # ca mode on Kea 3.0.x/3.1.x
    ca_removed: bool = False  # ca mode on Kea >= 3.2 (nothing to talk to)
    direct_control: bool = False
    direct_socket: bool = False  # CONFIRMED: Kea new enough for per-daemon sockets (unknown version: False)
    tls: bool = False  # helper >= 4 (install-tls)
    # the host helper
    helper: bool = False
    helper_version: int | None = None
    helper_known: bool = False  # has Jen ever recorded an answer for this host?
    ssh: bool = False
    trace: bool = False  # helper >= 5 and SSH
    # what the daemon reports / accepts
    packet_stats: bool = False
    packet_drop_reasons: bool = False  # Kea >= 3.2's extra pkt4-* counters
    config_test: bool = False
    # config-derived (active server only — see module docstring)
    hooks_known: bool = False
    ha_commands: bool = False
    lease_cmds: bool = False
    host_cmds: bool = False
    ddns: bool = False
    kea32_ready: bool = False
    # Q212: how a change reaches this server. `config_api` is a capability (the stored probe says the daemon's own API read its configuration with a digest); the transport itself is a
    # plain three-word field OUTSIDE CAPABILITY_NAMES (`why()` tests truthiness and `as_rows()` casts to bool, so a word cannot be a capability) with its own `transport_why()`.
    config_api: bool = False
    config_transport: str = "off"  # api | file | off - what a change set will do (`kea_changeset._transport`)
    config_declared: str = "off"  # the setting as `kea_api_config.declared_transport` reads it
    config_probed: bool = False  # a stored probe exists
    config_probe_error: str = ""  # Kea's own text when the last probe was refused
    config_gate: str = ""  # `kea_api_config.probe_gate`'s answer for this server: why a change over the API would be refused NOW ("" when it would not) - the badge and the sentence read it (Q216 AA13)

    @property
    def transport_blocked(self) -> bool:
        """An `api` server whose gate is closed: the badge and the sentence say so in the same words, never "healthy" over a gate that refuses."""
        return self.config_transport == "api" and bool(self.config_gate)

    def transport_why(self) -> str:
        """ONE word for one state everywhere (badge, result line, sentence): the sentence that goes with `config_transport`. For `api` it is derived from the GATE's answer (Q216 AA13): stale, not
        consented, re-pointed, refused, not readable - the same state the change set will meet."""
        if self.config_transport == "api":
            if self.config_gate:
                return f"Live API is not ready: {self.config_gate}"
            if self.config_probed and not self.config_api:
                return "the daemon did not answer the last readiness check; a change will stop until it does"
            return MODE_SENTENCES["api"]
        if self.config_transport == "file":
            return MODE_SENTENCES["file"]
        if self.config_declared == "file" and not self.ssh:
            return "File over SSH needs an SSH host (Settings → Kea → SSH); until it has one this server is read-only"
        return MODE_SENTENCES["off"]

    def transport_why_for(self, superadmin: bool) -> str:
        """The sentence for a READER of the page (Q218 BH4 a, AC7): a superadmin reads the gate's own words (`transport_why` - they name the daemon's account, the file's mode, an include's path, an
        endpoint with no authentication); an admin or a viewer reads the mode's sentence and, when the gate is closed, that a change to it over the API will stop until a superadmin has read the
        card. No gate text and no host fact reaches them; the badge's ", blocked" is a state, not a fact."""
        if superadmin or not self.transport_blocked:
            return self.transport_why()
        return (
            MODE_SENTENCES[self.config_transport].rstrip(".")
            + ", and a change to it over the API will stop until a superadmin has read its Write mode card."
        )

    def why(self, name: str) -> str:
        """The one sentence the UI shows for capability `name`: what's
        missing and where to fix it when it's off, a plain "available"
        line when it's on."""
        if name not in CAPABILITY_NAMES:
            raise ValueError(f"unknown capability: {name!r}")
        if getattr(self, name):
            return f"{_LABELS[name]} is available on this server."
        return _WHY[name](self)

    def as_rows(self) -> list[tuple[str, str, bool]]:
        """`[(name, label, on)]` for every capability, in display order."""
        return [(n, _LABELS[n], bool(getattr(self, n))) for n in CAPABILITY_NAMES]


CAPABILITY_NAMES = (
    "control_agent",
    "direct_control",
    "direct_socket",
    "tls",
    "helper",
    "trace",
    "packet_stats",
    "packet_drop_reasons",
    "config_test",
    "ha_commands",
    "lease_cmds",
    "host_cmds",
    "ddns",
    "kea32_ready",
    "config_api",
)

_LABELS = {
    "control_agent": "Control Agent",
    "direct_control": "Direct control sockets",
    "direct_socket": "Per-daemon control sockets",
    "tls": "https control sockets",
    "helper": "Kea host helper",
    "trace": "Trace",
    "packet_stats": "Packet statistics",
    "packet_drop_reasons": "Drop-reason counters",
    "config_test": "Config test",
    "ha_commands": "HA commands",
    "lease_cmds": "Lease commands",
    "host_cmds": "Reservation commands",
    "ddns": "DDNS updates",
    "kea32_ready": "Kea 3.2 readiness",
    "config_api": "Configuration over the API",
}

_HELPER_FIX = "Settings → Kea → SSH → Install helper"
_NO_SSH_FIX = "no SSH host is configured for this server (Settings → Kea → SSH)"


def _vstr(v) -> str:
    return ".".join(str(n) for n in v) if v else "unknown"


def _needs_helper(what: str, minimum: int):
    def _why(c: ServerCapabilities) -> str:
        if not c.ssh:
            return f"{what} needs the Kea host helper, which is reached over SSH — {_NO_SSH_FIX}."
        if not c.helper_known or c.helper_version is None:
            return f"{what} needs the Kea host helper v{minimum} — {_HELPER_FIX}."
        return f"{what} needs the Kea host helper v{minimum}; this host has v{c.helper_version} — update it from {_HELPER_FIX}."

    return _why


def _hook(what: str, lib: str):
    def _why(c: ServerCapabilities) -> str:
        if not c.hooks_known:
            return (
                f"{what} — Jen has no config for this server to check {lib} against (only the active server's is read)."
            )
        return f"{what} needs {lib} loaded in kea-dhcp4 (see the admin guide's Kea hooks section)."

    return _why


def _unknown_version(c: ServerCapabilities) -> bool:
    return c.kea_version is None


_UNKNOWN_VERSION = "Kea version unknown — is the server reachable? (Servers)"


def _control_agent_why(c: ServerCapabilities) -> str:
    if c.direct_control:
        return "Jen is in direct mode — this server is reached on its own control socket, not the Control Agent."
    if _unknown_version(c):
        return f"The Control Agent is not confirmed: {_UNKNOWN_VERSION}"
    return f"Kea {_vstr(c.kea_version)} no longer ships the Control Agent — switch to direct mode (Settings → Kea)."


def _direct_control_why(c: ServerCapabilities) -> str:
    return "Jen is in Control Agent mode — switch to direct mode in Settings → Kea to use each daemon's own socket."


def _direct_socket_why(c: ServerCapabilities) -> str:
    if _unknown_version(c):
        return f"Per-daemon control sockets are not confirmed: {_UNKNOWN_VERSION}"
    return f"Kea {_vstr(c.kea_version)} predates per-daemon control sockets (2.7.2) — the Control Agent is the only option there."


def _reachable_why(what: str):
    def _why(c: ServerCapabilities) -> str:
        return f"{what} needs the server to answer — it did not (check Servers)."

    return _why


_WHY = {
    "control_agent": _control_agent_why,
    "direct_control": _direct_control_why,
    "direct_socket": _direct_socket_why,
    "tls": _needs_helper("https control-socket setup", 4),
    "helper": lambda c: (
        f"The Kea host helper is reached over SSH and {_NO_SSH_FIX}."
        if not c.ssh
        else f"The Kea host helper isn't installed on this host — {_HELPER_FIX}."
    ),
    "trace": lambda c: (
        "Trace needs SSH to this server — set it up in Settings → Kea → SSH."
        if not c.ssh
        else _needs_helper("Trace", 5)(c)
    ),
    "packet_stats": _reachable_why("Packet statistics"),
    "packet_drop_reasons": lambda c: (
        f"The drop-reason counters arrive with Kea 3.2; this server is {_vstr(c.kea_version)}."
        if c.kea_version
        else "The drop-reason counters arrive with Kea 3.2 — this server's version isn't known."
    ),
    "config_test": _reachable_why("Config test"),
    "ha_commands": _hook("HA commands", HOOK_HA),
    "lease_cmds": _hook("Lease commands", HOOK_LEASE_CMDS),
    "host_cmds": _hook("Reservation commands", HOOK_HOST_CMDS),
    "ddns": lambda c: (
        "DDNS updates are off in kea-dhcp4 (dhcp-ddns enable-updates) — Network → DDNS."
        if c.hooks_known
        else "Jen has no config for this server to read the DDNS setting from (only the active server's is read)."
    ),
    "config_api": lambda c: (
        f"The last check could not read this daemon's configuration over its API ({c.config_probe_error})."
        if c.config_probed and c.config_probe_error
        else "The daemon's configuration has not been read over its API yet - run the readiness check on the server's Write mode card."
        if not c.config_probed
        else "The daemon did not answer the last check - run the readiness check on the server's Write mode card."
    ),
    "kea32_ready": lambda c: (
        "Not ready for Kea 3.2: "
        + (
            "switch to direct mode (the Control Agent is removed)"
            if not c.direct_control
            else "update the Kea host helper"
        )
        + " — see the Health Center's readiness checks."
    ),
}


# ── the pure derivation ────────────────────────────────────────────────────


def helper_caps(helper_version, *, ssh: bool = True) -> dict:
    """The helper-version-derived capabilities on their own — the SSH
    card's table needs them per host without any Kea round trip."""
    from jen.services import kea_host

    v = helper_version if isinstance(helper_version, int) and not isinstance(helper_version, bool) else None
    # v5.65.10 (Q99 h): a helper is reached over SSH, so every helper-derived capability needs an SSH host.
    # A recorded helper version for a server that has none (a host that had SSH once, or a stale entry) used
    # to read "Kea host helper: on" beside "no Kea host has SSH configured".
    return {
        "helper": v is not None and ssh,
        "tls": v is not None and v >= kea_host.TLS_HELPER_MIN_VERSION and ssh,
        "trace": v is not None and v >= kea_host.TRACE_HELPER_MIN_VERSION and ssh,
        # v5.66.0 (Q103) — "Update helper" needs no legacy grant at all on a host already here.
        "signed_update": v is not None and v >= kea_host.SIGNED_UPDATE_HELPER_MIN_VERSION and ssh,
    }


def derive(
    *,
    server_id=None,
    kea_version: tuple | None = None,
    kea_version_text: str = "",
    reachable: bool | None = None,
    direct: bool = False,
    helper_version=None,
    helper_known: bool = False,
    ssh: bool = False,
    hooks: set | frozenset | None = None,
    ddns_enabled: bool | None = None,
    config_transport: str = "off",
    config_declared: str = "off",
    config_probe: dict | None = None,
    config_gate: str = "",
) -> ServerCapabilities:
    """Every capability from plain inputs — no I/O, no Flask, no DB. Q212: `config_transport` / `config_declared` are what `kea_changeset._transport` and
    `kea_api_config.declared_transport` answered for the server, and `config_probe` is the STORED probe result (never a live call: Health builds capabilities with no Kea call)."""
    from jen.services import kea_host

    if reachable is None:
        reachable = kea_version is not None
    ca = not direct
    ca_removed = ca and kea_version is not None and kea_version >= CA_REMOVED_FROM
    ca_deprecated = ca and kea_version is not None and CA_DEPRECATED_FROM <= kea_version < CA_REMOVED_FROM
    hc = helper_caps(helper_version, ssh=ssh)
    hooks_known = hooks is not None
    hooks = hooks or frozenset()
    helper_int = helper_version if hc["helper"] else None
    ready = direct and (not ssh or (helper_int is not None and helper_int >= kea_host.JEN_HELPER_SHIPPED_VERSION))
    return ServerCapabilities(
        server_id=server_id,
        reachable=bool(reachable),
        kea_version=kea_version,
        kea_version_text=kea_version_text,
        control_agent=ca and ships_control_agent(kea_version),
        ca_deprecated=ca_deprecated,
        ca_removed=ca_removed,
        direct_control=direct,
        direct_socket=supports_direct_socket(kea_version),
        tls=hc["tls"],
        helper=hc["helper"],
        helper_version=helper_int,
        helper_known=helper_known,
        ssh=ssh,
        trace=hc["trace"],
        packet_stats=bool(reachable),
        packet_drop_reasons=kea_version is not None and kea_version >= DROP_REASONS_FROM,
        config_test=bool(reachable),
        hooks_known=hooks_known,
        ha_commands=HOOK_HA in hooks,
        lease_cmds=HOOK_LEASE_CMDS in hooks,
        host_cmds=HOOK_HOST_CMDS in hooks,
        ddns=bool(ddns_enabled),
        kea32_ready=bool(ready),
        config_api=bool((config_probe or {}).get("config_api")),
        config_transport=config_transport if config_transport in ("api", "file", "off") else "off",
        config_declared=config_declared if config_declared in ("api", "file", "off") else "off",
        config_probed=bool(config_probe),
        config_probe_error=str((config_probe or {}).get("refused") or "")[:200],
        config_gate=str(config_gate or "")[:400],
    )


def config_inputs(server: dict | None) -> dict:
    """The three `derive()` inputs for a server's configuration transport, from the server dict and the stored probe (a settings read, never a Kea call)."""
    if not server:
        return {}
    from jen.services import kea_api_config as _api
    from jen.services import kea_changeset as _cs

    return {
        "config_transport": _cs._transport(server, "dhcp4"),
        "config_declared": _api.declared_transport(server),
        "config_probe": _api.stored_probe(server.get("id")),
        "config_gate": _api.probe_gate(server) if _cs._transport(server, "dhcp4") == "api" else "",
    }


# ── gathering the inputs ─────────────────────────────────────────────────────


def _hooks_and_ddns(cfg: dict | None):
    if not isinstance(cfg, dict):
        return None, None
    libs = cfg.get("hooks-libraries") or []
    names = {str(h.get("library", "")).rsplit("/", 1)[-1] for h in libs if isinstance(h, dict)}
    ddns = bool((cfg.get("dhcp-ddns") or {}).get("enable-updates"))
    return frozenset(names), ddns


def _server_dict(server_id) -> dict | None:
    return next((s for s in (extensions.KEA_SERVERS or []) if str(s.get("id")) == str(server_id)), None)


def _fetch_version(server: dict | None, server_id=None) -> str | None:
    """`version-get`, cached 60 s per server (the reply text, or None when
    the server didn't answer). One Kea round trip per server per minute,
    however many pages ask."""
    from jen.services import kea as __kea

    key = str(server_id if server_id is not None else (server or {}).get("id"))
    hit = _version_cache.get(key)
    if hit and time.monotonic() - hit["at"] < _CACHE_TTL_S:
        return hit["text"]
    text = None
    try:
        r = __kea.kea_command("version-get", server=server, timeout=3)
        if r.get("result") == 0:
            text = (((r.get("arguments") or {}).get("extended", "") or r.get("text", "")).splitlines() or [""])[
                0
            ].strip()
    except Exception as e:
        logger.warning(f"capabilities: version-get failed for server {key}: {e}")
    _version_cache[key] = {"at": time.monotonic(), "text": text}
    return text


def invalidate(server_id=None) -> None:
    """Drop the cached version (all servers, or one) — the Health Center's
    own refresh calls this so it reads live. Q212: also the request's memo, so a route that writes a server's transport and reads `for_server` in the
    same request sees the new value."""
    if server_id is None:
        _version_cache.clear()
    else:
        _version_cache.pop(str(server_id), None)
    memo = _request_memo()
    if memo is not None:
        memo.clear()


def gather_kea_facts(server: dict | None = None, dhcp4_cfg: dict | None = None, server_id=None) -> dict:
    """What a live Kea says about itself — version, and (when a Dhcp4
    config is supplied) its hooks and DDNS switch. No Flask, no DB: the
    kea-compat job calls this against a real daemon."""
    text = _fetch_version(server, server_id)
    from jen.services import kea as __kea

    hooks, ddns = _hooks_and_ddns(dhcp4_cfg)
    return {
        "kea_version": __kea.parse_kea_version(text or ""),
        "kea_version_text": text or "",
        "reachable": text is not None,
        "hooks": hooks,
        "ddns_enabled": ddns,
    }


def _request_memo() -> dict | None:
    try:
        from flask import g, has_request_context

        if not has_request_context():
            return None
        memo = getattr(g, "_capabilities_memo", None)
        if memo is None:
            memo = g._capabilities_memo = {}
        return memo
    except Exception:
        return None


def for_server(
    server_id, dhcp4_cfg: dict | None = None, *, with_config: bool = True, probe_kea: bool = True
) -> ServerCapabilities:
    """The capabilities of one configured server. Memoised per request;
    the Kea version is cached 60 s per server. `dhcp4_cfg` (the active
    server's Dhcp4 map, when the caller already has it) supplies the
    hook-derived capabilities; without it the active server's cached
    config is used, and any other server's hooks are reported unknown.
    `with_config=False` skips reading it at all (a page that only needs the
    version/helper/mode capabilities), leaving the hook-derived ones off.
    `probe_kea=False` also skips the version-get: only the recorded helper
    status, SSH and the mode are read (Trace's gate needs nothing more)."""
    memo = _request_memo()
    key = str(server_id)
    memo_key = (key, with_config, probe_kea)
    if memo is not None and memo_key in memo and dhcp4_cfg is None:
        return memo[memo_key]

    from jen.services import kea_host

    server = _server_dict(server_id)
    if probe_kea:
        # The primary is reached the way every page has always reached it —
        # `server=None`, the [kea] globals — not through its derived dict.
        primary = extensions.KEA_SERVERS[0] if extensions.KEA_SERVERS else None
        is_primary = primary is not None and str(primary.get("id")) == key
        facts = gather_kea_facts(None if is_primary else server, server_id=server_id)
    else:
        facts = {"kea_version": None, "kea_version_text": "", "reachable": False}
        with_config = False
    if dhcp4_cfg is None and with_config:
        try:
            from jen.services import kea as __kea
            from jen.services.subnet_context import dhcp4_config

            active = __kea.get_active_kea_server() if extensions.KEA_SERVERS else None
            if active is not None and str(active.get("id")) == key:
                dhcp4_cfg = dhcp4_config()
        except Exception:
            dhcp4_cfg = None
    hooks, ddns = _hooks_and_ddns(dhcp4_cfg)
    status = kea_host.helper_status().get(key)
    caps = derive(
        server_id=server_id,
        kea_version=facts["kea_version"],
        kea_version_text=facts["kea_version_text"],
        reachable=facts["reachable"],
        direct=is_direct(),
        helper_version=(status or {}).get("version"),
        helper_known=status is not None,
        ssh=bool((server or {}).get("ssh_host")),
        hooks=hooks,
        ddns_enabled=ddns,
        **config_inputs(server),
    )
    if memo is not None:
        memo[memo_key] = caps
    return caps


def from_status(status: dict, *, dhcp4_cfg: dict | None = None) -> ServerCapabilities:
    """Capabilities from a row `kea.get_all_server_status()` already
    produced (`{server, up, version, …}`) — no new Kea call. The Health
    Center uses this so its capabilities row costs nothing extra;
    `dhcp4_cfg` is passed only for the server that config belongs to."""
    from jen.services import kea as __kea
    from jen.services import kea_host

    server = status.get("server") or {}
    key = str(server.get("id"))
    text = status.get("version") or ""
    st = kea_host.helper_status().get(key)
    hooks, ddns = _hooks_and_ddns(dhcp4_cfg)
    return derive(
        server_id=server.get("id"),
        kea_version=__kea.parse_kea_version(text),
        kea_version_text=text,
        reachable=bool(status.get("up")),
        direct=is_direct(),
        helper_version=(st or {}).get("version"),
        helper_known=st is not None,
        ssh=bool(server.get("ssh_host")),
        hooks=hooks,
        ddns_enabled=ddns,
        **config_inputs(server),
    )


def for_primary(*, with_config: bool = True) -> ServerCapabilities:
    """The primary server (id 1) — what `kea_command(server=None)` talks to."""
    return for_server((extensions.KEA_SERVERS[0]["id"]) if extensions.KEA_SERVERS else 1, with_config=with_config)


def field_names() -> list[str]:
    return [f.name for f in fields(ServerCapabilities)]
