"""
jen/services/kea_ha.py
───────────────────────
v5.21.0 (Q16) — HA status normalization, HA config summary, and the
per-subnet lease-count comparison behind the /servers HA console.

`ha_status()` and `compare_assigned()` talk to Kea (via `jen.services.kea`);
`ha_config()` is pure, reading the `Dhcp4` config map already fetched by
the caller. `HA_ACTIONS` is the fixed allowlist of HA commands a route can
send — nothing outside it reaches `kea_command()`.
"""

from __future__ import annotations

import re

HA_ACTIONS = {
    "heartbeat": {
        "command": "ha-heartbeat",
        "role": "admin",
        "help": "Check this server's current HA state right now.",
        "confirm": "Send a heartbeat and refresh this server's HA state?",
    },
    "sync": {
        "command": "ha-sync",
        "role": "superadmin",
        "help": "Pull the partner's lease database onto this server.",
        "confirm": "Sync leases from the partner onto this server? This can take a while on a large lease database.",
    },
    "scopes": {
        "command": "ha-scopes",
        "role": "superadmin",
        "help": "Force which server serves which scope.",
        "confirm": "Change which scopes this server serves?",
    },
    "continue": {
        "command": "ha-continue",
        "role": "superadmin",
        "help": "Leave a waiting/terminated state and resume normal HA operation.",
        "confirm": "Tell this server to leave its current waiting/terminated state and continue?",
    },
    "maintenance-start": {
        "command": "ha-maintenance-start",
        "role": "superadmin",
        "help": "Tell the partner to take over from this server for planned maintenance.",
        "confirm": "Start maintenance on this server? The partner will be told to take over.",
    },
    "maintenance-cancel": {
        "command": "ha-maintenance-cancel",
        "role": "superadmin",
        "help": "Cancel a pending or active maintenance handover.",
        "confirm": "Cancel maintenance mode on this server?",
    },
    "reset": {
        "command": "ha-reset",
        "role": "superadmin",
        "help": "Re-run the HA state machine from scratch.",
        "confirm": "Reset the HA state machine on this server? Only do this when Kea's own HA docs direct you to.",
    },
}

_SUBNET_ASSIGNED_RE = re.compile(r"^subnet\[(\d+)\]\.assigned-addresses$")


def ha_status(server: dict) -> dict | None:
    """`status-get`'s `high-availability[0]` block, normalized to a
    local/remote dict. None when the server has no HA hook loaded (a
    non-HA server still answers `status-get` successfully — it just
    carries no `high-availability` key) or the command otherwise fails."""
    from jen.services import kea as __kea

    resp = __kea.kea_command("status-get", server=server)
    if resp.get("result") != 0:
        return None
    ha_list = resp.get("arguments", {}).get("high-availability")
    if not ha_list:
        return None
    servers = ha_list[0].get("ha-servers", {})
    local = servers.get("local", {}) or {}
    remote = servers.get("remote", {}) or {}
    return {
        "local": {
            "role": local.get("role"),
            "scopes": local.get("scopes", []),
            "state": local.get("state"),
        },
        "remote": {
            "role": remote.get("role"),
            "state": remote.get("last-state"),
            "scopes": remote.get("last-scopes", []),
            "age": remote.get("age"),
            "in_touch": remote.get("in-touch"),
            "connecting_clients": remote.get("connecting-clients"),
            "unacked_clients": remote.get("unacked-clients"),
            "unacked_clients_left": remote.get("unacked-clients-left"),
            "analyzed_packets": remote.get("analyzed-packets"),
        },
    }


def ha_config(dhcp4_cfg: dict | None) -> dict | None:
    """The `high-availability[0]` parameters of the `libdhcp_ha.so` hook
    in a `Dhcp4` config map. None when the hook isn't configured. Pure —
    `dhcp4_cfg` is the inner `Dhcp4` map, as returned by `config-get`."""
    if not dhcp4_cfg:
        return None
    for lib in dhcp4_cfg.get("hooks-libraries", []) or []:
        if not isinstance(lib, dict):
            continue
        if lib.get("library", "").rsplit("/", 1)[-1] != "libdhcp_ha.so":
            continue
        ha_list = (lib.get("parameters") or {}).get("high-availability") or []
        if not ha_list:
            return None
        ha = ha_list[0]
        return {
            "this_server_name": ha.get("this-server-name"),
            "mode": ha.get("mode"),
            "heartbeat_delay": ha.get("heartbeat-delay"),
            "max_response_delay": ha.get("max-response-delay"),
            "max_ack_delay": ha.get("max-ack-delay"),
            "max_unacked_clients": ha.get("max-unacked-clients"),
            "peers": ha.get("peers", []) or [],
        }
    return None


def partner_name(cfg: dict) -> str | None:
    """The one peer in `cfg["peers"]` that isn't `this_server_name`.
    None if that isn't exactly one peer (not a 2-node pair, or the
    config doesn't say who this server is) — `ha-sync` then refuses
    rather than guessing."""
    this_name = cfg.get("this_server_name")
    if not this_name:
        return None
    others = [p.get("name") for p in cfg.get("peers", []) if p.get("name") and p.get("name") != this_name]
    return others[0] if len(others) == 1 else None


def compare_assigned(servers: list[dict]) -> list[dict]:
    """Side-by-side `assigned-addresses` per subnet, one row per subnet
    id reported by ANY server, counts keyed by server name. `mismatch`
    flags real disagreement between servers — expected to be zero, or a
    small transient difference is normal for a moment under
    load-balancing, never a hard failure on its own."""
    from jen import extensions
    from jen.services import kea as __kea

    per_server: dict[str, dict[int, int]] = {}
    subnet_ids: set[int] = set()
    for server in servers:
        name = server.get("name") or f"Server {server.get('id')}"
        resp = __kea.kea_command("statistic-get-all", server=server)
        args = resp.get("arguments", {}) if resp.get("result") == 0 else {}
        counts: dict[int, int] = {}
        for key, samples in args.items():
            m = _SUBNET_ASSIGNED_RE.match(key)
            if not m:
                continue
            sid = int(m.group(1))
            try:
                counts[sid] = int(samples[0][0])
            except (TypeError, IndexError, ValueError):
                counts[sid] = 0
            subnet_ids.add(sid)
        per_server[name] = counts

    rows = []
    for sid in sorted(subnet_ids):
        row_counts = {name: counts.get(sid, 0) for name, counts in per_server.items()}
        rows.append(
            {
                "subnet_id": sid,
                "name": extensions.SUBNET_MAP.get(sid, {}).get("name") or f"Subnet {sid}",
                "counts": row_counts,
                "mismatch": len(set(row_counts.values())) > 1,
            }
        )
    return rows
