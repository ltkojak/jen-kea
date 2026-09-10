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
                  dhcp4 commands go to KEA_API_URL, dhcp6 commands to that
                  server's api6_url (KEA6_API_URL for the primary) with no
                  fallback — a v4 daemon can't answer v6 — and the
                  "service" field is omitted (3.2 rejects a wrong one;
                  omitting is the portable choice — the daemon still wraps
                  its reply in a one-element list for compatibility, so the
                  response handling below is unchanged).
"""

import logging
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests as http
import urllib3

from jen import extensions

logger = logging.getLogger(__name__)

# v5.10.3 — with [kea] api_tls_verify = false, urllib3 emits an
# InsecureRequestWarning on EVERY request; the dashboard polls, so that
# fills the journal. Say it once per process instead.
_insecure_warned = False


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
    identical to requests' own default).

    v5.10.3 — when verification is deliberately off, suppress urllib3's
    per-request InsecureRequestWarning and log the reason once instead."""
    global _insecure_warned
    verify = extensions.KEA_API_CA or extensions.KEA_API_TLS_VERIFY
    if verify is False and not _insecure_warned:
        _insecure_warned = True
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("Kea TLS verification is disabled ([kea] api_tls_verify = false)")
    return verify


def _tls_client_cert():
    """The `cert` kwarg for the requests call — an (cert, key) pair when
    [kea] api_client_cert AND api_client_key are both set, else None
    (requests' own default). Kea's per-daemon https control socket
    defaults cert-required=true, so an https:// endpoint needs this;
    None keeps ca-mode / http:// behaviour byte-identical (v5.10.2)."""
    if extensions.KEA_API_CLIENT_CERT and extensions.KEA_API_CLIENT_KEY:
        return (extensions.KEA_API_CLIENT_CERT, extensions.KEA_API_CLIENT_KEY)
    return None


def validate_client_tls_material(cert_path: str, key_path: str, ca_path: str) -> str | None:
    """
    v5.10.3 — None if the [kea] mTLS material is usable, else a short
    reason. Loads it with the same API requests/urllib3 will use, AS THIS
    PROCESS (www-data), so a mismatched pair, a non-PEM file, or a key the
    service user can't read is caught at save time instead of turning
    every Kea call into an opaque SSLError. os.path.isfile() — the only
    check before this — is a stat(), which succeeds without read
    permission.

    Pure; tested in tests/test_kea_tls_material.py. Deliberately separate
    from security.py::validate_cert_material, which validates Jen's own
    SERVER certificate with PROTOCOL_TLS_SERVER and takes PEM text; this
    one takes paths (the files already live on the Jen host).
    """
    import ssl

    if not cert_path and not key_path and not ca_path:
        return None
    if bool(cert_path) != bool(key_path):
        return "set both the client certificate and key, or neither"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cert_path:
        try:
            ctx.load_cert_chain(cert_path, key_path)
        except ssl.SSLError as e:
            if "mismatch" in (e.strerror or str(e)).lower():
                return "the client key does not match the client certificate"
            return f"the client certificate/key could not be loaded ({e.strerror or e})"
        except PermissionError:
            return "the client certificate or key is not readable by the Jen service user — chown root:www-data and chmod 640 it"
        except (OSError, ValueError) as e:
            return f"the client certificate/key could not be loaded ({e})"
    if ca_path:
        try:
            ctx.load_verify_locations(cafile=ca_path)
        except PermissionError:
            return "the CA bundle is not readable by the Jen service user"
        except (ssl.SSLError, OSError, ValueError) as e:
            return f"the CA bundle could not be loaded ({getattr(e, 'strerror', None) or e})"
    return None


def _endpoint_for(server: dict, service: str):
    """
    Resolve (url, user, pwd) for one command — or return an error dict
    when a dhcp6 command has nowhere to go in direct mode.

    dhcp4 (and anything that isn't "dhcp6") behaves exactly as it has
    since v4.0.0: the given server dict, or the [kea] globals when server
    is None. Only dhcp6 routing is mode-aware.

    v5.10.3 — a server's v6 endpoint is THAT SERVER's: its api6_* fields,
    else (ca mode) its own api_url/api_user/api_pass. The KEA6_* globals
    are the primary's [kea6] override and are used only for the
    server-is-None (primary) path; derive_kea_servers() bakes [kea6] into
    the primary dict's api6_* so the primary still gets them here. Before
    this, a standby with no api6_url sent its dhcp6 commands to the
    PRIMARY's endpoint with the primary's credentials.
    """
    direct = extensions.KEA_CONNECTION_MODE == "direct"

    if service == "d2":
        # kea-dhcp-ddns (D2). In ca mode the Control Agent forwards a
        # `service: ["d2"]` command to it, so D2 rides the same endpoint
        # as dhcp4. Direct mode needs D2's own control socket URL — the
        # [d2] config section that carries it is Q15's; until then this
        # is a reserved error message, matching the dhcp6 branch below.
        if direct:
            return {
                "result": 1,
                "text": "D2 needs a kea-dhcp-ddns control-socket URL — set [d2] api_url (Settings → Kea).",
            }
        if server is None:
            return extensions.KEA_API_URL, extensions.KEA_API_USER, extensions.KEA_API_PASS
        return server.get("api_url", ""), server.get("api_user", ""), server.get("api_pass", "")

    if service == "dhcp6":
        if server is None:
            url = extensions.KEA6_API_URL
            user = extensions.KEA6_API_USER
            pwd = extensions.KEA6_API_PASS
        else:
            v4_url_fallback = "" if direct else server.get("api_url", "")
            url = server.get("api6_url") or v4_url_fallback
            user = server.get("api6_user") or server.get("api_user", "")
            pwd = server.get("api6_pass") or server.get("api_pass", "")
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


def server_clock_offset(server: dict = None) -> float | None:
    """Seconds the given Kea server's clock is ahead of Jen's, read from
    the HTTP `Date` header on a version-get reply. Positive = Kea ahead.
    Returns None when the server sends no parseable Date header (some
    builds omit it) or the request fails — the caller treats that as
    "couldn't tell", never a failure.

    Built exactly like kea_command's request (same _endpoint_for, auth,
    verify, cert, timeout); never raises. Kea has no clock command, so
    the response header is the only signal available."""
    endpoint = _endpoint_for(server, "dhcp4")
    if isinstance(endpoint, dict):
        return None
    url, user, pwd = endpoint
    if extensions.KEA_CONNECTION_MODE == "direct":
        payload = {"command": "version-get"}
    else:
        payload = {"command": "version-get", "service": ["dhcp4"]}
    try:
        t0 = datetime.now(timezone.utc)
        resp = http.post(url, json=payload, auth=(user, pwd), timeout=10, verify=_tls_verify(), cert=_tls_client_cert())
        t1 = datetime.now(timezone.utc)
    except Exception:
        return None
    date_hdr = resp.headers.get("Date")
    if not date_hdr:
        return None
    try:
        server_time = parsedate_to_datetime(date_hdr)
    except (TypeError, ValueError):
        return None
    if server_time.tzinfo is None:  # e.g. a "-0000" zone parses naive
        server_time = server_time.replace(tzinfo=timezone.utc)
    local_midpoint = t0 + (t1 - t0) / 2
    return (server_time - local_midpoint).total_seconds()


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
