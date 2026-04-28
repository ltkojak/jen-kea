"""
jen/services/kea.py
───────────────────
All communication with the Kea Control Agent REST API.
"""

import logging
import time

import requests as http

from jen import extensions

logger = logging.getLogger(__name__)


def kea_command(command: str, service: str = "dhcp4",
                arguments: dict = None, server: dict = None) -> dict:
    """
    Send a command to a specific Kea server (or server 1 if None).
    Always returns a dict — never raises.
    """
    if server is None:
        url  = extensions.KEA_API_URL
        user = extensions.KEA_API_USER
        pwd  = extensions.KEA_API_PASS
    else:
        url  = server["api_url"]
        user = server["api_user"]
        pwd  = server["api_pass"]

    payload = {"command": command, "service": [service]}
    if arguments:
        payload["arguments"] = arguments
    try:
        resp = http.post(url, json=payload, auth=(user, pwd), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    except http.exceptions.ConnectionError:
        return {"result": 1, "text": f"Cannot connect to Kea API at {url}"}
    except http.exceptions.Timeout:
        return {"result": 1, "text": "Kea API request timed out."}
    except Exception as e:
        return {"result": 1, "text": str(e)}


def kea_command_all(command: str, service: str = "dhcp4",
                    arguments: dict = None) -> list:
    """Send command to ALL configured servers. Returns [(server, result), ...]."""
    return [
        (server, kea_command(command, service, arguments, server=server))
        for server in extensions.KEA_SERVERS
    ]


def kea_is_up(server: dict = None) -> bool:
    """Return True if the given server (or server 1) responds to version-get."""
    return kea_command("version-get", server=server).get("result") == 0


def get_all_server_status() -> list:
    """
    Return a list of status dicts for every configured server.
    Each dict: {server, up, ha_state, ha_partner, version}
    """
    statuses = []
    for server in extensions.KEA_SERVERS:
        up         = kea_is_up(server=server)
        ha_state   = None
        ha_partner = None
        version    = ""
        if up:
            if len(extensions.KEA_SERVERS) > 1:
                ha_result = kea_command("ha-heartbeat", server=server)
                if ha_result.get("result") == 0:
                    args       = ha_result.get("arguments", {})
                    ha_state   = args.get("state", "unknown")
                    ha_partner = args.get("partner-state", "")
            ver = kea_command("version-get", server=server)
            version = ver.get("arguments", {}).get("extended",
                      ver.get("text", "")).splitlines()[0] if ver.get("result") == 0 else ""
        statuses.append({
            "server":     server,
            "up":         up,
            "ha_state":   ha_state,
            "ha_partner": ha_partner,
            "version":    version,
        })
    return statuses


def get_active_kea_server() -> dict:
    """
    Return the best server to target for config-get and subnet editing.
    - Single server: always returns server 1.
    - HA: returns the primary in hot-standby/load-balancing/partner-down state.
    - Falls back to first reachable server.
    Result is cached for 10 seconds to avoid hammering ha-heartbeat.
    """
    if len(extensions.KEA_SERVERS) == 1:
        return extensions.KEA_SERVERS[0]

    now   = time.time()
    cache = extensions._active_server_cache
    if cache["server"] and (now - cache["ts"]) < 10:
        return cache["server"]

    active_states = ("hot-standby", "load-balancing", "partner-down")
    for server in extensions.KEA_SERVERS:
        if not kea_is_up(server=server):
            continue
        ha = kea_command("ha-heartbeat", server=server)
        if ha.get("result") == 0:
            state = ha.get("arguments", {}).get("state", "")
            role  = server.get("role", "primary")
            if state in active_states and role == "primary":
                cache["server"] = server
                cache["ts"]     = now
                return server

    # Fallback: first reachable
    for server in extensions.KEA_SERVERS:
        if kea_is_up(server=server):
            cache["server"] = server
            cache["ts"]     = now
            return server

    return extensions.KEA_SERVERS[0]


def format_mac(raw_bytes) -> str:
    """Convert raw MAC bytes to colon-separated lowercase hex string."""
    if not raw_bytes:
        return ""
    return ":".join(f"{b:02x}" for b in raw_bytes)
