"""
jen/services/kea_config_edit.py
───────────────────────────────
v5.11.0 — pure, in-memory mutation of a parsed Kea config dict.

Before 5.11.0 the subnet add / delete / edit operations each built a
Python script (jen/routes/subnets.py::_build_subnet_patch_script(), two
inline scripts, jen/services/kea6.py::build_subnet6_patch_script()),
base64'd it, and ran it over SSH as `sudo python3` on the Kea host. The
mutation logic and the `kea-dhcpX -t` validation were tangled together
inside a string, untestable except by asserting on the generated text.

5.11.0 splits them:
  * the mutation is here — pure functions, no I/O, they deepcopy their
    input so the caller's dict is never touched;
  * reading the file, running `-t`, and writing it back go through
    jen/services/kea_host.py, which prefers the fixed-function
    `jen-kea-helper` and falls back to the legacy `sudo python3` path.

The behaviour is a verbatim port of what the old remote scripts did —
same option-data upsert (routers code 3, domain-name-servers code 6,
v6 dns-servers code 23, all `csv-format: true`), same "no change" and
"id exists" / "not found" outcomes.
"""

from __future__ import annotations

import copy


def _iter_subnets(cfg, dhcp_key, subnet_key):
    section = cfg.get(dhcp_key)
    if not isinstance(section, dict):
        return []
    subnets = section.get(subnet_key)
    return subnets if isinstance(subnets, list) else []


def _upsert_option(opts, name, code, space, data):
    """Set an existing option-data entry's `data` in place, or append a
    new csv-format entry. Matches the old remote scripts exactly."""
    for o in opts:
        if isinstance(o, dict) and o.get("name") == name:
            o["data"] = data
            return
    opts.append({"name": name, "code": code, "space": space, "csv-format": True, "data": data})


def patch_subnet4(cfg, subnet_id, new_pool, extra_pools, new_lifetime, new_renew, new_rebind, new_routers, new_dns):
    """Apply a subnet4 edit. Returns (new_cfg, changed). `changed` False
    means nothing in the config differs — the caller reports 'nochange'
    and does not push. All the value args are strings (or empty) exactly
    as the edit form delivers them."""
    cfg = copy.deepcopy(cfg)
    changed = False
    for s in _iter_subnets(cfg, "Dhcp4", "subnet4"):
        if s.get("id") != subnet_id:
            continue
        if new_pool:
            s["pools"] = [{"pool": new_pool}] + [{"pool": p} for p in (extra_pools or [])]
            changed = True
        if new_lifetime:
            s["valid-lifetime"] = int(new_lifetime)
            changed = True
        if new_renew:
            s["renew-timer"] = int(new_renew)
            changed = True
        if new_rebind:
            s["rebind-timer"] = int(new_rebind)
            changed = True
        if new_routers or new_dns:
            opts = s.get("option-data", [])
            if new_routers:
                _upsert_option(opts, "routers", 3, "dhcp4", new_routers)
                changed = True
            if new_dns:
                _upsert_option(opts, "domain-name-servers", 6, "dhcp4", new_dns)
                changed = True
            s["option-data"] = opts
        break
    return cfg, changed


def patch_subnet6(cfg, subnet_id, new_pool, extra_pools, new_preferred, new_valid, new_renew, new_rebind, new_dns):
    """Apply a subnet6 edit. Returns (new_cfg, changed)."""
    cfg = copy.deepcopy(cfg)
    changed = False
    for s in _iter_subnets(cfg, "Dhcp6", "subnet6"):
        if s.get("id") != subnet_id:
            continue
        if new_pool:
            s["pools"] = [{"pool": new_pool}] + [{"pool": p} for p in (extra_pools or [])]
            changed = True
        if new_preferred:
            s["preferred-lifetime"] = int(new_preferred)
            changed = True
        if new_valid:
            s["valid-lifetime"] = int(new_valid)
            changed = True
        if new_renew:
            s["renew-timer"] = int(new_renew)
            changed = True
        if new_rebind:
            s["rebind-timer"] = int(new_rebind)
            changed = True
        if new_dns:
            opts = s.get("option-data", [])
            _upsert_option(opts, "dns-servers", 23, "dhcp6", new_dns)
            s["option-data"] = opts
            changed = True
        break
    return cfg, changed


def add_subnet4(cfg, block):
    """Append a new subnet4 block. Returns (new_cfg, "ok"|"idexists")."""
    cfg = copy.deepcopy(cfg)
    new_id = block.get("id")
    if any(s.get("id") == new_id for s in _iter_subnets(cfg, "Dhcp4", "subnet4")):
        return cfg, "idexists"
    cfg.setdefault("Dhcp4", {}).setdefault("subnet4", []).append(block)
    return cfg, "ok"


def delete_subnet4(cfg, subnet_id):
    """Remove a subnet4 block by id. Returns (new_cfg, "ok"|"notfound")."""
    cfg = copy.deepcopy(cfg)
    subnets = _iter_subnets(cfg, "Dhcp4", "subnet4")
    kept = [s for s in subnets if s.get("id") != subnet_id]
    if len(kept) == len(subnets):
        return cfg, "notfound"
    cfg["Dhcp4"]["subnet4"] = kept
    return cfg, "ok"
