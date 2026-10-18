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
    None keeps ca-mode / http:// behavior byte-identical (v5.10.2)."""
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


class _NoClientCert:
    """The type of NO_CLIENT_CERT — a sentinel with a readable repr."""

    def __repr__(self):
        return "NO_CLIENT_CERT"

    def __bool__(self):
        return False


# v5.67.0-beta.8 (Q120, item f) — "probe with NO client certificate at all". `cert=None` has always meant
# "nothing given, fall back to the SAVED [kea] client certificate", which is right for a caller with no
# opinion and wrong for the setup wizard's Connect step: a form that cleared the certificate fields was
# probed WITH the saved certificate (so the probe passed), then saved the empty fields (so every later call
# failed). A caller that means "none" passes this.
NO_CLIENT_CERT = _NoClientCert()


def _resolve_cert(cert):
    if cert is NO_CLIENT_CERT:
        return None
    return cert if cert is not None else _tls_client_cert()


def test_connection(
    url: str,
    user: str,
    password: str,
    *,
    service: str = "dhcp4",
    omit_service: bool = False,
    verify=None,
    cert=None,
    timeout: int = 8,
):
    """One version-get probe against `url`, independent of the globally
    configured connection. The ONE TLS-aware probe primitive (v5.67.0-beta.5,
    Q117, item f) — Settings' own probe-kea route and /setup's Connect
    step both call this rather than each keeping a separate copy; the
    setup wizard's own prior copy never looked at TLS settings at all,
    so a site with a private CA or Kea's default mTLS socket failed at
    the very first step of the flagship flow.

    `verify`/`cert` explicitly override the configured TLS material —
    for probing a candidate that hasn't been saved yet (as both callers
    above do); omitted (None), they fall back to the current [kea]
    api_ca/api_tls_verify / api_client_cert+api_client_key via
    `_tls_verify()`/`_tls_client_cert()`. Returns (version_text, error):
    exactly one is non-empty.
    """
    result, err = probe_command(
        url,
        user,
        password,
        "version-get",
        service=service,
        omit_service=omit_service,
        verify=verify,
        cert=cert,
        timeout=timeout,
    )
    if result is None:
        return "", err
    return ((result.get("arguments") or {}).get("extended", "") or result.get("text", "")).strip(), ""


def probe_command(
    url: str,
    user: str,
    password: str,
    command: str,
    *,
    service: str = "dhcp4",
    omit_service: bool = False,
    arguments: dict = None,
    verify=None,
    cert=None,
    timeout: int = 8,
):
    """Like test_connection, but for an arbitrary read-only command —
    test_connection's own TLS-aware POST, generalized (v5.67.0-beta.5,
    Q117, item g) so the setup wizard's explicit "Check for DHCPv6" probe
    can follow a successful version-get with a config-get against the
    SAME not-yet-adopted candidate, to list what the daemon actually
    serves before anything is saved. Returns (result_dict, error):
    exactly one is non-empty/non-None — `result_dict` is Kea's own reply
    (`{"result": 0, "arguments": {...}, ...}`), not just its text."""
    payload = {"command": command}
    if not omit_service:
        payload["service"] = [service]
    if arguments:
        payload["arguments"] = arguments
    try:
        resp = http.post(
            url,
            json=payload,
            auth=_auth(user, password),
            timeout=timeout,
            verify=verify if verify is not None else _tls_verify(),
            cert=_resolve_cert(cert),
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and not data:
            return None, "Kea answered with an empty list"
        d = data[0] if isinstance(data, list) else data
        if not isinstance(d, dict):
            return None, "Kea answered with something that is not a reply"
        if d.get("result") != 0:
            return None, d.get("text", "Kea returned an error")
        return d, ""
    except Exception as e:
        from jen.services.auth import scrub_urls

        return None, scrub_urls(str(e))  # (Q190, AF2: a `requests` message may carry the address as it was typed)


# The top-level key a daemon (or the Control Agent) answers a direct-style `config-get` with.
_DAEMON_CONFIG_KEYS = ("Dhcp4", "Dhcp6", "D2", "Control-agent")


def identify_daemon(url: str, user: str, password: str, *, verify=None, cert=None, timeout: int = 8):
    """WHICH process answered at `url`: the reply's top-level config key to a direct-style `config-get`
    (no `service` field) — "Dhcp4"/"Dhcp6"/"D2" for a daemon's own control socket, "Control-agent" for a
    Control Agent — or None on any failure. Advisory only: never raises, and never changes whether a
    probe as a whole succeeded.

    v5.28.1 (Q26, D2) introduced this for Settings' probe-kea (a Control Agent left listening on :8000
    answers `version-get` identically to a real control socket); v5.67.0-beta.8 (Q120, item b) moved it
    here so the setup wizard decides its connection mode the SAME way. It is the only reliable test:
    verified against real kea-dhcp4 3.0.3, 3.2.0 and 3.3.1 (tests/kea_compat), a daemon answers a command
    carrying `service: ["dhcp4"]` exactly as it answers one without, so "it answered a service-style
    probe" says nothing about whether a Control Agent is there.

    A real reply is `{"Dhcp4": {...}, "hash": "..."}` — the known daemon keys are looked for first so the
    trailing `hash` is never mistaken for the answer."""
    result, _err = probe_command(
        url, user, password, "config-get", omit_service=True, verify=verify, cert=cert, timeout=timeout
    )
    if result is None:
        return None
    args = result.get("arguments") or {}
    for key in _DAEMON_CONFIG_KEYS:
        if key in args:
            return key
    return next((k for k in args if k != "hash"), None)


class _NoAuth:
    """An explicit "send no Authorization header". `auth=None` would let `requests` look in the service user's ~/.netrc and send what it finds there to an endpoint that said it has no
    authentication; a callable that leaves the request alone does not."""

    def __call__(self, request):
        return request


_NO_AUTH = _NoAuth()


def _auth(user, password):
    """The Basic credential a request carries (v5.69.0-beta.12, Q181): exactly the endpoint's resolved user and password - and NO Authorization header when both are blank (an endpoint
    that says it has no authentication is sent none, not an empty Basic one)."""
    return (user, password) if (user or password) else _NO_AUTH


def _endpoint_for(server: dict, service: str):
    """
    (url, user, pwd) for one command - or an error dict when the endpoint has no address or no credential it may use.

    v5.69.0-beta.12 (Q181, V1; CRED-004) - THIS FUNCTION DECIDES NOTHING. Every field it returns is what `credentials.resolve` gave the endpoint, carried on the server dict by
    `derive_kea_servers` (`api_url`/`api_user`/`api_pass`, `api6_*`, `api_d2_*`, and `*_withheld`) and on the KEA6_* / D2_* globals by `AppConfig.apply`: url, user and password under
    ONE reading (a value is its own, a present-blank key is explicit, an absent key inherits - the url in CA mode, the user and password on the same host only). There is no `or`
    here and no fallback to the Control Agent's url, because a second place that decides is how a password reached a host its owner never named four times. An endpoint with no
    address answers with a sentence; one whose password was refused (`*_withheld`) answers with a sentence and NOTHING is sent. `tests/test_credential_transport.py` proves the
    transport posts exactly what `resolve` says; a whole-tree test refuses a new fallback.

    dhcp4 (and anything that isn't "dhcp6"/"d2"): the given server dict, or the [kea] globals when server is None. The primary-only KEA6_*/D2_* globals serve server=None.
    """

    def _no_credential(who: str, url: str, withheld: str):
        from jen.services import credentials as _cred

        return {
            "result": 1,
            "text": (
                f"{who} has no credential: {url} is on a different host from the one whose password it would inherit ({_cred.label(withheld)}) - "
                'set its own under Settings → Kea (or tick "No password" there if it has no authentication)'
            ),
        }

    if service in ("d2", "dhcp6"):
        if server is None:
            if service == "d2":
                url, user, pwd = extensions.D2_API_URL, extensions.D2_API_USER, extensions.D2_API_PASS
                withheld, who = extensions.D2_API_WITHHELD, "D2"
            else:
                url, user, pwd = extensions.KEA6_API_URL, extensions.KEA6_API_USER, extensions.KEA6_API_PASS
                withheld, who = extensions.KEA6_API_WITHHELD, "Kea6"
        else:
            prefix, label_ = ("api_d2", "D2") if service == "d2" else ("api6", "IPv6")
            url, user, pwd = (
                server.get(f"{prefix}_url", ""),
                server.get(f"{prefix}_user", ""),
                server.get(f"{prefix}_pass", ""),
            )
            withheld, who = (
                server.get(f"{prefix}_withheld", ""),
                f"{server.get('name', 'This server')}'s {label_} endpoint",
            )
        if not url:
            direct = extensions.KEA_CONNECTION_MODE == "direct"
            if service == "d2":
                text = (
                    "D2 needs a kea-dhcp-ddns control-socket URL — set [d2] api_url (Settings → Kea)."
                    if direct
                    else f"{who} has no address to send to (set one under Settings → Kea)."
                )
            else:
                text = (
                    "IPv6 direct mode needs a kea-dhcp6 control-socket URL — set [kea6] api_url (Settings → Kea → Kea6 Control Socket)."
                    if direct
                    else f"{who} has no address to send to (set one under Settings → Kea)."
                )
            return {"result": 1, "text": text}
        if withheld:
            return _no_credential(who, url, withheld)
        return url, user, pwd

    if server is None:
        return extensions.KEA_API_URL, extensions.KEA_API_USER, extensions.KEA_API_PASS
    if server.get("api_withheld") and server.get("api_url"):
        return _no_credential(server.get("name", "This server"), server["api_url"], server["api_withheld"])
    return server.get("api_url", ""), server.get("api_user", ""), server.get("api_pass", "")


def configured_url(server: dict | None, service: str) -> str:
    """The address Jen is CONFIGURED to dial for this daemon (Q189, second pass, finding 1) - "" when it has none. `_endpoint_for` answers a sentence, not a url, for an endpoint whose password
    the credential rule withheld; but that endpoint still EXISTS and still runs whatever TLS material Jen put on its host. A caller that enumerates endpoints (the rotation's inventory) asks this,
    never `_endpoint_for`, or an endpoint drops out of its set the day its credential is withheld."""
    if service in ("d2", "dhcp6"):
        if server is None:
            return (extensions.D2_API_URL if service == "d2" else extensions.KEA6_API_URL) or ""
        return server.get("api_d2_url" if service == "d2" else "api6_url", "") or ""
    if server is None:
        return extensions.KEA_API_URL or ""
    return server.get("api_url", "") or ""


def kea_command(
    command: str, service: str = "dhcp4", arguments: dict = None, server: dict = None, timeout: int = 10
) -> dict:
    """
    Send a command to a specific Kea server (or the primary if None).
    Always returns a dict — never raises. `timeout` defaults to 10s;
    pass a smaller value on a page that must not stall when Kea is slow
    (the Settings landing hint uses 3s).
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
        resp = http.post(
            url, json=payload, auth=_auth(user, pwd), timeout=timeout, verify=_tls_verify(), cert=_tls_client_cert()
        )
        resp.raise_for_status()
        data = resp.json()
        reply = data[0] if isinstance(data, list) else data
        # v5.28.1 (Q26, D1) — in direct mode, a successful config-get that
        # answers as the WRONG daemon (most often the Control Agent,
        # still listening on :8000 because only its unix socket — not an
        # http one — was ever configured) used to pass straight through
        # as an empty-looking Dhcp4/Dhcp6/DhcpDdns to every silent
        # caller (dashboard, subnets page, drift, Health). Only
        # config-get, only direct mode, only a "successful" reply —
        # ca mode and every other command are untouched.
        if extensions.KEA_CONNECTION_MODE == "direct" and command == "config-get" and reply.get("result") == 0:
            expected = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}.get(service)
            args = reply.get("arguments") or {}
            if expected and expected not in args:
                found_key = "Control-agent" if "Control-agent" in args else next(iter(args), None)
                found = "the Control Agent" if found_key == "Control-agent" else found_key
                return {
                    "result": 1,
                    "text": (
                        f"{url} answered config-get as {found or 'an unknown daemon'}, not kea-{service} — "
                        "direct mode needs each daemon's own http control socket (conventionally :8004 for "
                        "dhcp4, :8006 for dhcp6), not the Control Agent (:8000). Settings → Kea → Probe, "
                        'or let Jen add the socket: Settings → Kea → "Set up direct socket".'
                    ),
                }
        return reply
    except http.exceptions.ConnectionError:
        return {"result": 1, "text": f"Cannot connect to Kea API at {url}"}
    except http.exceptions.Timeout:
        return {"result": 1, "text": "Kea API request timed out."}
    except Exception as e:
        # v5.65.12 (Q101 b): the connect/timeout cases above are canned deliberately (the connect
        # message names the URL - admin-facing and useful, kept). Anything else - a TLS handshake
        # failure, a malformed response, any other transport exception - used to render the raw
        # exception text on the dashboard's config-error banner and the Doctor page. Canned here too;
        # the real text is logged, with the URL and command, for whoever reads Jen's log.
        from jen.services.auth import scrub_urls, shown_url

        logger.error(
            f"kea_command({command!r}) against {shown_url(url)} raised {type(e).__name__}: {scrub_urls(str(e))}"
        )
        return {"result": 1, "text": "Kea API call failed — the details are in Jen's log."}


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
        resp = http.post(
            url, json=payload, auth=_auth(user, pwd), timeout=10, verify=_tls_verify(), cert=_tls_client_cert()
        )
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


# v5.65.6 (Q95) - the last version-get answer per server, remembered by kea_is_up() itself.
# The background alert loop asks every server every ~5 s, so this is fresh whenever the app is
# running under its normal entrypoint; /api/v1/health answers from it instead of a live call
# (see cached_kea_health) so it can never block on a Kea that is down.
_HEALTH_CACHE: dict = {}
_HEALTH_MAX_AGE_S = 120


def _health_key(server):
    if server and server.get("id") is not None:
        return server["id"]
    servers = extensions.KEA_SERVERS
    return servers[0].get("id") if servers else None


def _version_line(reply: dict) -> str:
    text = (reply.get("arguments") or {}).get("extended") or reply.get("text") or ""
    return text.splitlines()[0] if text else ""


def probe_kea_health(server: dict = None) -> dict:
    """THE Kea probe (v5.65.10, Q99): one version-get, remembered. Returns {"up", "version", "at"} and
    writes the health cache entry. kea_is_up, the status page, the API's live probe and the cache
    the public health endpoint reads all go through this, so a probe is one call: it used to be a
    version-get inside kea_is_up and then a second version-get beside it (two calls at the 10 s
    timeout on a dead server, and `up` true with an empty version when only the second one failed)."""
    reply = kea_command("version-get", server=server)
    up = reply.get("result") == 0
    entry = {"up": up, "version": _version_line(reply) if up else None, "at": time.time()}
    _HEALTH_CACHE[_health_key(server)] = entry
    return entry


def kea_is_up(server: dict = None) -> bool:
    """Return True if the given server (or server 1) responds to version-get."""
    return probe_kea_health(server)["up"]


def cached_active_server() -> dict | None:
    """The server Jen is serving from, WITHOUT a probe: the one get_active_kea_server() last chose (its
    10 s cache), else the first configured server. get_active_kea_server() itself probes in an HA pair,
    so the health endpoint, which must never wait on Kea, reads this instead."""
    cached = extensions._active_server_cache.get("server")
    if cached:
        return cached
    servers = extensions.KEA_SERVERS
    return servers[0] if servers else None


def all_cached_kea_health() -> list:
    """Per server, what Jen last learned and when: [{"name", "up", "version", "checked_at"}]. No probe."""
    return [{"name": s.get("name"), **cached_kea_health(s)} for s in extensions.KEA_SERVERS]


def cached_kea_health(server: dict = None, max_age: float = _HEALTH_MAX_AGE_S) -> dict:
    """What Jen last learned about a server, WITHOUT asking Kea: {"up": bool | None, "version":
    str | None, "checked_at": iso | None}. None means "not known" - nothing has probed yet, or the
    last probe is older than `max_age` seconds (the poller stopped) - never a guess. Never blocks."""
    entry = _HEALTH_CACHE.get(_health_key(server if server is not None else cached_active_server()))
    if not entry or (time.time() - entry["at"]) > max_age:
        return {"up": None, "version": None, "checked_at": None}
    return {
        "up": entry["up"],
        "version": entry["version"],
        "checked_at": datetime.fromtimestamp(entry["at"], timezone.utc).isoformat(timespec="seconds"),
    }


def get_all_server_status() -> list:
    """
    Return a list of status dicts for every configured server.
    Each dict: {server, up, ha_state, ha_partner, version}
    """
    statuses = []
    for server in extensions.KEA_SERVERS:
        probe = probe_kea_health(server)  # one version-get: the answer's version is used, not asked for again
        up = probe["up"]
        ha_state = None
        ha_partner = None
        version = probe["version"] or ""
        if up and len(extensions.KEA_SERVERS) > 1:
            ha_result = kea_command("ha-heartbeat", server=server)
            if ha_result.get("result") == 0:
                args = ha_result.get("arguments") or {}
                ha_state = args.get("state", "unknown")
                ha_partner = args.get("partner-state", "")
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


def get_active_kea_server() -> dict | None:
    """
    Return the best server to target for config-get and subnet editing.
    - No server configured: None (it used to raise IndexError).
    - Single server: always returns server 1.
    - HA: returns the primary in hot-standby/load-balancing/partner-down state.
    - Falls back to first reachable server.
    Result is cached for 10 seconds to avoid hammering ha-heartbeat.
    """
    if not extensions.KEA_SERVERS:
        return None
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
            state = (ha.get("arguments") or {}).get("state", "")
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
