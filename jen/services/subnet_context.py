"""
jen/services/subnet_context.py
──────────────────────────────
v5.30.0 (Q30, A4) — everything Jen already knows about one IPv4 subnet,
in one call, for the plugins (IPAM Lite, Network Discovery) and any
page that wants to label an address instead of guessing:

    subnet_context(subnet_id) -> {
        "subnet_id", "name", "cidr", "network", "broadcast",
        "gateways": [...], "dns": [...],               # from the effective options
        "pools": [(first_int, last_int, "10.0.0.20 - 10.0.0.199"), ...],
        "kea_host_ips": {...}, "jen_host_ips": {...},   # inside this subnet only
        "infrastructure": {ip: "gateway" | "dns" | "network" | "broadcast"
                               | "kea-server" | "jen-host"},
        "notes": "<subnet_notes row or ''>",
    }
    classify_address(ctx, ip) -> that label or None
    in_pool(ctx, ip) -> bool

The gateway and DNS come from `dhcp_options.effective_options()` (global
→ shared-network → subnet precedence, so a subnet inheriting the global
`routers` still gets it); pools from the subnet's own `pools` list (Kea
accepts `a - b` and `cidr`). The config is one cached `config-get`
against the active server (30 s — the Dashboard and Health fetch the
same thing on every render, so this never adds a call per plugin page).
Everything is best effort: a config-get that fails yields a context with
empty gateway/DNS/pools rather than an exception, so a plugin page still
renders on a Jen whose Kea is down.

Pure apart from the cached fetch and the optional `subnet_notes` read —
`subnet_context(subnet_id, dhcp4_cfg=...)` with an explicit config
touches neither Kea nor the DB (the tests use that).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse

from jen import extensions

logger = logging.getLogger(__name__)

_CFG_TTL_S = 30.0
_cfg_cache: dict = {"at": 0.0, "cfg": None}
_cfg_lock = threading.Lock()

_HOST_IPS_TTL_S = 300.0
_host_ips_cache: dict = {"at": 0.0, "ips": set()}


def dhcp4_config(force: bool = False) -> dict | None:
    """The active server's inner `Dhcp4` map from a cached config-get, or
    None when Kea didn't answer. Never raises."""
    with _cfg_lock:
        if not force and _cfg_cache["cfg"] is not None and time.monotonic() - _cfg_cache["at"] < _CFG_TTL_S:
            return _cfg_cache["cfg"]
    cfg = None
    try:
        from jen.services import kea as _kea

        r = _kea.kea_command("config-get", server=_kea.get_active_kea_server())
        if r.get("result") == 0:
            cfg = (r.get("arguments") or {}).get("Dhcp4")
    except Exception as e:
        logger.warning(f"subnet_context: config-get failed: {e}")
    if isinstance(cfg, dict):
        with _cfg_lock:
            _cfg_cache["cfg"], _cfg_cache["at"] = cfg, time.monotonic()
        return cfg
    return None


def invalidate_config_cache() -> None:
    with _cfg_lock:
        _cfg_cache["cfg"], _cfg_cache["at"] = None, 0.0


def _ip_or_none(value: str):
    try:
        return ipaddress.IPv4Address(str(value).strip())
    except (ValueError, TypeError):
        return None


def parse_pool(pool: str, network: ipaddress.IPv4Network) -> tuple[int, int, str] | None:
    """Kea pool syntax → (first, last, text). `a - b`, `a-b`, or a CIDR."""
    text = str(pool or "").strip()
    if not text:
        return None
    if "-" in text:
        a, _, b = text.partition("-")
        first, last = _ip_or_none(a), _ip_or_none(b)
        if first is None or last is None or int(first) > int(last):
            return None
        return int(first), int(last), f"{first} - {last}"
    try:
        sub = ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None
    if not sub.subnet_of(network):
        return None
    return int(sub.network_address), int(sub.broadcast_address), str(sub)


def _split_ips(data: str) -> list[str]:
    return [p.strip() for p in str(data or "").split(",") if _ip_or_none(p.strip()) is not None]


def jen_host_ips() -> set[str]:
    """This host's IPv4 addresses, best effort and cached: `ip -4 -o addr`
    when available, else whatever the hostname resolves to."""
    if time.monotonic() - _host_ips_cache["at"] < _HOST_IPS_TTL_S:
        return set(_host_ips_cache["ips"])
    ips: set[str] = set()
    for ip_bin in ("/usr/sbin/ip", "/sbin/ip", "/bin/ip", "ip"):
        try:
            out = subprocess.run([ip_bin, "-4", "-o", "addr"], capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        if out.returncode != 0:
            continue
        for line in out.stdout.splitlines():
            parts = line.split()
            if "inet" in parts:
                cand = parts[parts.index("inet") + 1].split("/")[0]
                if _ip_or_none(cand) is not None:
                    ips.add(cand)
        break
    if not ips:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ips.add(info[4][0])
        except OSError:
            pass
    ips.discard("127.0.0.1")
    _host_ips_cache["ips"], _host_ips_cache["at"] = ips, time.monotonic()
    return set(ips)


def kea_host_ips() -> set[str]:
    """Every IP literal Jen has on file for its Kea servers — SSH host and
    the API URL hosts (hostnames aren't resolved: a DNS name in the URL
    isn't something to label an address with)."""
    ips: set[str] = set()
    for s in extensions.KEA_SERVERS:
        for key in ("ssh_host",):
            if _ip_or_none(s.get(key, "")) is not None:
                ips.add(s[key].strip())
        for key in ("api_url", "api6_url", "api_d2_url"):
            host = urlparse(s.get(key) or "").hostname or ""
            if _ip_or_none(host) is not None:
                ips.add(host)
    return ips


def subnet_context(subnet_id: int, dhcp4_cfg: dict | None = None, with_notes: bool = True) -> dict | None:
    """See the module doc. None when `subnet_id` isn't in SUBNET_MAP."""
    info = extensions.SUBNET_MAP.get(subnet_id)
    if not info:
        return None
    try:
        network = ipaddress.IPv4Network(info["cidr"], strict=False)
    except (ValueError, KeyError):
        return None

    cfg = dhcp4_cfg if dhcp4_cfg is not None else dhcp4_config()
    gateways: list[str] = []
    dns: list[str] = []
    pools: list[tuple[int, int, str]] = []
    if isinstance(cfg, dict):
        try:
            from jen.services import dhcp_options as _opts
            from jen.services import kea_config_view as _view

            for row in _opts.effective_options(cfg, subnet_id):
                if row.get("code") == 3 or row.get("name") == "routers":
                    gateways = _split_ips(row.get("data", ""))
                elif row.get("code") == 6 or row.get("name") == "domain-name-servers":
                    dns = _split_ips(row.get("data", ""))
            found = _view.subnet4_by_id(cfg, subnet_id)
            if found:
                for p in found[0].get("pools") or []:
                    parsed = parse_pool(p.get("pool") if isinstance(p, dict) else p, network)
                    if parsed:
                        pools.append(parsed)
        except Exception as e:
            logger.warning(f"subnet_context: could not read options/pools for subnet {subnet_id}: {e}")

    def _inside(ip: str) -> bool:
        a = _ip_or_none(ip)
        return a is not None and a in network

    infra: dict[str, str] = {}
    if network.prefixlen < 31:
        infra[str(network.network_address)] = "network"
        infra[str(network.broadcast_address)] = "broadcast"
    for ip in gateways:
        if _inside(ip):
            infra.setdefault(ip, "gateway")
    for ip in dns:
        if _inside(ip):
            infra.setdefault(ip, "dns")
    kea_ips = {ip for ip in kea_host_ips() if _inside(ip)}
    for ip in kea_ips:
        infra.setdefault(ip, "kea-server")
    jen_ips = {ip for ip in jen_host_ips() if _inside(ip)}
    for ip in jen_ips:
        infra.setdefault(ip, "jen-host")

    notes = ""
    if with_notes:
        try:
            from jen.models import db as _db

            with _db.jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT notes FROM subnet_notes WHERE subnet_id=%s", (subnet_id,))
                row = cur.fetchone()
                notes = (row or {}).get("notes") or ""
        except Exception:
            notes = ""

    return {
        "subnet_id": subnet_id,
        "name": info.get("name", ""),
        "cidr": str(network),
        "network": str(network.network_address),
        "broadcast": str(network.broadcast_address),
        "gateways": gateways,
        "dns": dns,
        "pools": pools,
        "kea_host_ips": kea_ips,
        "jen_host_ips": jen_ips,
        "infrastructure": infra,
        "notes": notes,
    }


def classify_address(ctx: dict, ip: str) -> str | None:
    return (ctx or {}).get("infrastructure", {}).get(str(ip).strip())


def in_pool(ctx: dict, ip: str) -> bool:
    a = _ip_or_none(ip)
    if a is None:
        return False
    n = int(a)
    return any(first <= n <= last for first, last, _text in (ctx or {}).get("pools", []))
