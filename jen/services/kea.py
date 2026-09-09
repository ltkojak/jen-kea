"""
jen/services/kea.py
───────────────────
The Kea command transport (v5.10.0).

Two connection modes, picked by [kea] connection_mode:

  ca (default)  — one HTTP endpoint (a kea-ctrl-agent) routes every
                  command to kea-dhcp4 / kea-dhcp6 by the JSON "service"
                  field. Byte-identical to every release before 5.10.0.
  direct        — talk to each daemon's own HTTP control socket. ISC
                  deprecated the Control Agent in Kea 3.0 and REMOVED it
                  in 3.2, so a 3.2+ install has nothing to run in ca mode.
                  dhcp4 commands go to KEA_API_URL, dhcp6 commands to
                  KEA6_API_URL (no fallback — a v4 daemon can't answer v6),
                  and the "service" field is omitted (3.2 rejects a wrong
                  one; omitting is the portable choice — the daemon still
                  wraps its reply in a one-element list for compatibility,
                  so the response handling below is unchanged).
"""

import logging
import re
import time

import requests as http

from jen import extensions

logger = logging.getLogger(__name__)


def parse_kea_version(text: str):
    """Pull an (X, Y, Z) integer tuple out of a Kea version string —
    version-get's `arguments.extended` ("3.2.0\\ntarball...") or its
    `text` ("3.2.0"). Returns None when there's no dotted triple to find,
    so callers can say "couldn't tell" rather than guess. The tuple
    compares the obvious way: (3, 0, 0) < (3, 2, 0)."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(g) for g in m.groups()) if m else None


def _tls_verify():
    """The `verify` kwarg for the requests call — only relevant when the
    endpoint URL is https://. A [kea] api_ca path pins verification to that
    CA bundle; otherwise the [kea] api_tls_verify boolean (default True,
    identical to requests' own default)."""
    return extensions.KEA_API_CA or extensions.KEA_API_TLS_VERIFY


def _tls_client_cert():
    """The `cert` kwarg for the requests call — an (cert, key) pair when
    [kea] api_client_cert AND api_client_key are both set, else None
    (requests' own default). Kea's per-daemon https control socket
    defaults cert-required=true, so an https:// endpoint needs this;
    None keeps ca-mode / http:// behaviour byte-identical (v5.10.2)."""
    if extensions.KEA_API_CLIENT_CERT and extensions.KEA_API_CLIENT_KEY:
        return (extensions.KEA_API_CLIENT_CERT, extensions.KEA_API_CLIENT_KEY)
    return None


def _endpoint_for(server: dict, service: str):
    """
    Resolve (url, user, pwd) for one command — or return an error dict
    when a dhcp6 command has nowhere to go in direct mode.

    dhcp4 (and anything that isn't "dhcp6") behaves exactly as it has
    since v4.0.0: the given server dict, or the [kea] globals when server
    is None. Only dhcp6 routing is mode-aware.
    """
    direct = extensions.KEA_CONNECTION_MODE == "direct"

    if service == "dhcp6":
        if server is None:
            url = extensions.KEA6_API_URL
            user = extensions.KEA6_API_USER
            pwd = extensions.KEA6_API_PASS
        else:
            v4_url_fallback = "" if direct else server.get("api_url", "")
            url = server.get("api6_url") or extensions.KEA6_API_URL or v4_url_fallback
            user = server.get("api6_user") or extensions.KEA6_API_USER or server.get("api_user", "")
            pwd = server.get("api6_pass") or extensions.KEA6_API_PASS or server.get("api_pass", "")
        if direct and not url:
            return {
                "result": 1,
                "text": (
                    "IPv6 direct mode needs a kea-dhcp6 control-socket URL — "
                    "set [kea6] api_url (Settings → Kea → Kea6 Control Socket)."
                ),
            }
        return url, user, pwd

    if server is None:
        return extensions.KEA_API_URL, extensions.KEA_API_USER, extensions.KEA_API_PASS
    return server.get("api_url", ""), server.get("api_user", ""), server.get("api_pass", "")


def kea_command(command: str, service: str = "dhcp4", arguments: dict = None, server: dict = None) -> dict:
    """
    Send a command to a specific Kea server (or the primary if None).
    Always returns a dict — never raises.
    """
    endpoint = _endpoint_for(server, service)
    if isinstance(endpoint, dict):  # e.g. direct mode with no [kea6] api_url
        return endpoint
    url, user, pwd = endpoint

    if extensions.KEA_CONNECTION_MODE == "direct":
        payload = {"command": command}
    else:
        payload = {"command": command, "service": [service]}
    if arguments:
        payload["arguments"] = arguments
    try:
        resp = http.post(url, json=payload, auth=(user, pwd), timeout=10, verify=_tls_verify(), cert=_tls_client_cert())
        resp.raise_for_status()
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    except http.exceptions.ConnectionError:
        return {"result": 1, "text": f"Cannot connect to Kea API at {url}"}
    except http.exceptions.Timeout:
        return {"result": 1, "text": "Kea API request timed out."}
    except Exception as e:
        return {"result": 1, "text": str(e)}


def kea_command_all(command: str, service: str = "dhcp4", arguments: dict = None) -> list:
    """Send command to ALL configured servers. Returns [(server, result), ...]."""
    return [(server, kea_command(command, service, arguments, server=server)) for server in extensions.KEA_SERVERS]


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
        up = kea_is_up(server=server)
        ha_state = None
        ha_partner = None
        version = ""
        if up:
            if len(extensions.KEA_SERVERS) > 1:
                ha_result = kea_command("ha-heartbeat", server=server)
                if ha_result.get("result") == 0:
                    args = ha_result.get("arguments", {})
                    ha_state = args.get("state", "unknown")
                    ha_partner = args.get("partner-state", "")
            ver = kea_command("version-get", server=server)
            version = (
                ver.get("arguments", {}).get("extended", ver.get("text", "")).splitlines()[0]
                if ver.get("result") == 0
                else ""
            )
        statuses.append(
            {
                "server": server,
                "up": up,
                "ha_state": ha_state,
                "ha_partner": ha_partner,
                "version": version,
            }
        )
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

    now = time.time()
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
            role = server.get("role", "primary")
            if state in active_states and role == "primary":
                cache["server"] = server
                cache["ts"] = now
                return server

    # Fallback: first reachable
    for server in extensions.KEA_SERVERS:
        if kea_is_up(server=server):
            cache["server"] = server
            cache["ts"] = now
            return server

    return extensions.KEA_SERVERS[0]


def format_mac(raw_bytes) -> str:
    """Convert raw MAC bytes to colon-separated lowercase hex string."""
    if not raw_bytes:
        return ""
    return ":".join(f"{b:02x}" for b in raw_bytes)
