"""
jen/services/kea_ddns.py
─────────────────────────
v5.23.0 (Q19) — pure, in-memory mutation of D2's OWN config
(kea-dhcp-ddns.conf, top-level key "DhcpDdns") — forward/reverse
ddns-domains and tsig-keys. Deliberately a separate module from
jen/services/kea_config_edit.py: every function there operates on the
Dhcp4/Dhcp6 config shape (subnets, options, classes); D2's config is a
different top-level object entirely, and mixing the two under one
module would blur which shape a given function expects.

Same discipline as kea_config_edit.py: every function deep-copies its
input, no I/O — reading the file, running `kea-dhcp-ddns -t`, and
writing it back go through jen/services/kea_host.py.
"""

from __future__ import annotations

import copy
import ipaddress

TSIG_ALGORITHMS = ("hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512")


def _domains_of(cfg: dict, direction: str) -> list:
    """direction ∈ "forward" | "reverse"."""
    return cfg.setdefault("DhcpDdns", {}).setdefault(f"{direction}-ddns", {}).setdefault("ddns-domains", [])


def _find_domain(domains: list, name: str):
    return next((i for i, d in enumerate(domains) if isinstance(d, dict) and d.get("name") == name), None)


def add_ddns_domain(cfg: dict, direction: str, name: str, key_name: str | None, servers: list[tuple[str, int]]):
    """Insert a new domain, or replace an existing one matched by name —
    same upsert shape as kea_config_edit.upsert_class4. `servers` is a
    list of (ip, port) pairs. Returns (new_cfg, "ok")."""
    cfg = copy.deepcopy(cfg)
    domains = _domains_of(cfg, direction)
    entry: dict = {
        "name": name,
        "dns-servers": [{"ip-address": ip, "port": port} for ip, port in servers],
    }
    if key_name:
        entry["key-name"] = key_name
    idx = _find_domain(domains, name)
    if idx is not None:
        domains[idx] = entry
    else:
        domains.append(entry)
    return cfg, "ok"


def remove_ddns_domain(cfg: dict, direction: str, name: str):
    """Returns (new_cfg, "ok"|"notfound")."""
    cfg = copy.deepcopy(cfg)
    domains = _domains_of(cfg, direction)
    idx = _find_domain(domains, name)
    if idx is None:
        return cfg, "notfound"
    domains.pop(idx)
    return cfg, "ok"


def _tsig_keys_of(cfg: dict) -> list:
    return cfg.setdefault("DhcpDdns", {}).setdefault("tsig-keys", [])


def _find_tsig_key(keys: list, name: str):
    return next((i for i, k in enumerate(keys) if isinstance(k, dict) and k.get("name") == name), None)


def set_tsig_key(cfg: dict, name: str, algorithm: str, secret: str):
    """Create (or fully replace) a TSIG key. There is no partial update —
    the secret is write-only and never re-displayed, so an "edit" that
    didn't also re-supply the secret would have nothing sensible to keep
    it as; the UI only ever offers Add + Remove, matching this. Returns
    (new_cfg, "ok")."""
    cfg = copy.deepcopy(cfg)
    keys = _tsig_keys_of(cfg)
    entry = {"name": name, "algorithm": algorithm, "secret": secret}
    idx = _find_tsig_key(keys, name)
    if idx is not None:
        keys[idx] = entry
    else:
        keys.append(entry)
    return cfg, "ok"


def _key_is_referenced(cfg: dict, key_name: str) -> bool:
    for direction in ("forward", "reverse"):
        for d in _domains_of(cfg, direction):
            if isinstance(d, dict) and d.get("key-name") == key_name:
                return True
    return False


def remove_tsig_key(cfg: dict, name: str):
    """Returns (new_cfg, "ok"|"notfound"|"referenced") — refused while
    any forward or reverse domain still names this key, mirroring how
    kea_config_edit refuses to delete a client class still attached
    somewhere."""
    cfg = copy.deepcopy(cfg)
    if _key_is_referenced(cfg, name):
        return cfg, "referenced"
    keys = _tsig_keys_of(cfg)
    idx = _find_tsig_key(keys, name)
    if idx is None:
        return cfg, "notfound"
    keys.pop(idx)
    return cfg, "ok"


def suggest_reverse_zone(cidr: str) -> str | None:
    """The in-addr.arpa. zone name for a classful /8, /16, or /24 IPv4
    CIDR — the only prefix lengths that map onto a single reverse zone
    without RFC 2317 classless delegation. Returns None for anything
    else (including IPv6 and unparsable input) so the caller can hint
    the operator to name a classless /25-/30 zone by hand — out of
    scope here."""
    try:
        net = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    octets = str(net.network_address).split(".")
    if net.prefixlen == 24:
        return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
    if net.prefixlen == 16:
        return f"{octets[1]}.{octets[0]}.in-addr.arpa."
    if net.prefixlen == 8:
        return f"{octets[0]}.in-addr.arpa."
    return None
