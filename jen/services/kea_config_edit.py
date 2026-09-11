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

The behavior is a verbatim port of what the old remote scripts did —
same option-data upsert (routers code 3, domain-name-servers code 6,
v6 dns-servers code 23, all `csv-format: true`), same "no change" and
"id exists" / "not found" outcomes.

v5.15.0 — the subnet iteration now goes through
jen/services/kea_config_view.py, so patch / delete / add reach subnets
nested inside `Dhcp4.shared-networks` too (before, a nested subnet was a
silent no-op on edit). Adds create/delete shared network and move-subnet.
"""

from __future__ import annotations

import copy

from jen.services import dhcp_options as _opts_catalog
from jen.services import kea_config_view as _view


def _iter_subnets(cfg, dhcp_key, subnet_key):
    """Every subnet in `cfg[dhcp_key]` — top-level AND nested in
    shared-networks — as bare dicts (the caller mutates them in place)."""
    section = cfg.get(dhcp_key)
    iter_fn = _view.iter_subnet4 if subnet_key == "subnet4" else _view.iter_subnet6
    return [s for s, _sn in iter_fn(section)]


def _upsert_option(opts, name, code, space, data):
    """Set an existing option-data entry's `data` in place, or append a
    new csv-format entry. Matches the old remote scripts' behavior, plus
    (v5.18.0 / Q12) also matching an entry that carries only `code` (no
    `name`) — e.g. one Jen's own option editor wrote as a custom code
    that happens to coincide with routers/dns-servers — so it gets
    updated instead of duplicated."""
    for o in opts:
        if isinstance(o, dict) and o.get("code") == code:
            o["data"] = data
            return
    for o in opts:
        if isinstance(o, dict) and o.get("code") is None and o.get("name") == name:
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


def add_subnet4(cfg, block, shared_network=None):
    """Append a new subnet4 block. Into the named shared network when
    `shared_network` is given (must already exist). Returns
    (new_cfg, "ok"|"idexists"|"nonetwork"). The new id must be unique
    across every subnet, top-level or nested."""
    cfg = copy.deepcopy(cfg)
    new_id = block.get("id")
    d4 = cfg.setdefault("Dhcp4", {})
    if any(s.get("id") == new_id for s in _iter_subnets(cfg, "Dhcp4", "subnet4")):
        return cfg, "idexists"
    if shared_network:
        for sn in d4.get("shared-networks") or []:
            if isinstance(sn, dict) and sn.get("name") == shared_network:
                sn.setdefault("subnet4", []).append(block)
                return cfg, "ok"
        return cfg, "nonetwork"
    d4.setdefault("subnet4", []).append(block)
    return cfg, "ok"


def delete_subnet4(cfg, subnet_id):
    """Remove a subnet4 block by id, wherever it lives (top-level or
    inside a shared network). Returns (new_cfg, "ok"|"notfound")."""
    cfg = copy.deepcopy(cfg)
    d4 = cfg.get("Dhcp4")
    if not isinstance(d4, dict):
        return cfg, "notfound"
    for container in (d4, *(sn for sn in (d4.get("shared-networks") or []) if isinstance(sn, dict))):
        subs = container.get("subnet4")
        if not isinstance(subs, list):
            continue
        kept = [s for s in subs if s.get("id") != subnet_id]
        if len(kept) != len(subs):
            container["subnet4"] = kept
            return cfg, "ok"
    return cfg, "notfound"


def _shared_networks4(cfg):
    d4 = cfg.get("Dhcp4")
    return d4.get("shared-networks") if isinstance(d4, dict) and isinstance(d4.get("shared-networks"), list) else None


def create_shared_network4(cfg, name, interface=None):
    """Add an empty shared network. Returns (new_cfg, "ok"|"exists")."""
    cfg = copy.deepcopy(cfg)
    nets = cfg.setdefault("Dhcp4", {}).setdefault("shared-networks", [])
    if any(isinstance(n, dict) and n.get("name") == name for n in nets):
        return cfg, "exists"
    block = {"name": name, "subnet4": []}
    if interface:
        block["interface"] = interface
    nets.append(block)
    return cfg, "ok"


def delete_shared_network4(cfg, name):
    """Remove a shared network. Refuses when it still has subnets (moving
    them out is a separate step). Returns
    (new_cfg, "ok"|"notfound"|"notempty")."""
    cfg = copy.deepcopy(cfg)
    nets = _shared_networks4(cfg)
    if nets is None:
        return cfg, "notfound"
    for i, n in enumerate(nets):
        if isinstance(n, dict) and n.get("name") == name:
            if n.get("subnet4"):
                return cfg, "notempty"
            nets.pop(i)
            return cfg, "ok"
    return cfg, "notfound"


def move_subnet4(cfg, subnet_id, to_network):
    """Move a subnet between containers. `to_network` is a shared network
    name, or "" / None for top-level. The subnet dict is carried across
    byte-identical. Returns
    (new_cfg, "ok"|"notfound"|"nonetwork"|"nochange")."""
    cfg = copy.deepcopy(cfg)
    d4 = cfg.get("Dhcp4")
    if not isinstance(d4, dict):
        return cfg, "notfound"
    target = to_network or None

    src = None  # (container_dict, index, current_network_name)
    for container, cur_name in (
        (d4, None),
        *((sn, sn.get("name")) for sn in (d4.get("shared-networks") or []) if isinstance(sn, dict)),
    ):
        subs = container.get("subnet4")
        if not isinstance(subs, list):
            continue
        for idx, s in enumerate(subs):
            if s.get("id") == subnet_id:
                src = (container, idx, cur_name)
                break
        if src:
            break
    if src is None:
        return cfg, "notfound"
    container, idx, cur_name = src
    if target == cur_name:
        return cfg, "nochange"

    dest = None
    if target is not None:
        dest = next(
            (sn for sn in (d4.get("shared-networks") or []) if isinstance(sn, dict) and sn.get("name") == target),
            None,
        )
        if dest is None:
            return cfg, "nonetwork"

    subnet = container["subnet4"].pop(idx)
    if target is None:
        d4.setdefault("subnet4", []).append(subnet)
    else:
        dest.setdefault("subnet4", []).append(subnet)
    return cfg, "ok"


# ── DHCP options hierarchy (v5.18.0 — Q12) ──────────────────────────────────


def _container_for_level4(cfg, level, key):
    """(container_dict, "ok") for `level`/`key`, or (None, "notfound").
    level ∈ {"global", "shared-network", "subnet", "pool"}; key is None /
    a shared-network name / a subnet id / a (subnet_id, pool_str) pair."""
    d4 = cfg.get("Dhcp4")
    if not isinstance(d4, dict):
        return None, "notfound"
    if level == "global":
        return d4, "ok"
    if level == "shared-network":
        for sn in d4.get("shared-networks") or []:
            if isinstance(sn, dict) and sn.get("name") == key:
                return sn, "ok"
        return None, "notfound"
    if level == "subnet":
        found = _view.subnet4_by_id(d4, key)
        return (found[0], "ok") if found else (None, "notfound")
    if level == "pool":
        subnet_id, pool_str = key
        found = _view.subnet4_by_id(d4, subnet_id)
        if found is None:
            return None, "notfound"
        for p in found[0].get("pools") or []:
            if isinstance(p, dict) and p.get("pool") == pool_str:
                return p, "ok"
        return None, "notfound"
    return None, "notfound"


def _match_option_index(opts, code, name=None):
    """Index of the option-data entry matching `code` (resolving a
    name-only entry's code through the catalog first) else `name`. -1 if
    nothing matches."""
    if code is not None:
        for i, o in enumerate(opts):
            if not isinstance(o, dict):
                continue
            o_code = o.get("code")
            if o_code is None and o.get("name") in _opts_catalog.NAME_TO_CODE:
                o_code = _opts_catalog.NAME_TO_CODE[o["name"]]
            if o_code == code:
                return i
    if name is not None:
        for i, o in enumerate(opts):
            if isinstance(o, dict) and o.get("name") == name:
                return i
    return -1


def set_option4(cfg, level, key, code, name, data, csv_format=True):
    """Create or update an option-data entry at `level`/`key`. New/updated
    entries always carry `name`, `code`, `space: "dhcp4"` from the
    caller — never trust an existing entry's own name/code pairing.
    Returns (new_cfg, "ok"|"notfound"|"managed") — "managed" for codes 3
    (routers) / 6 (domain-name-servers) at subnet level, which the Edit
    Subnet form owns."""
    cfg = copy.deepcopy(cfg)
    if level == "subnet" and code in _opts_catalog.MANAGED_AT_SUBNET:
        return cfg, "managed"
    container, status = _container_for_level4(cfg, level, key)
    if status != "ok":
        return cfg, "notfound"
    opts = container.setdefault("option-data", [])
    idx = _match_option_index(opts, code, name)
    entry = {"name": name, "code": code, "space": "dhcp4", "csv-format": bool(csv_format), "data": data}
    if idx >= 0:
        opts[idx] = entry
    else:
        opts.append(entry)
    return cfg, "ok"


def remove_option4(cfg, level, key, code):
    """Remove an option-data entry by code. Returns
    (new_cfg, "ok"|"notfound"|"managed")."""
    cfg = copy.deepcopy(cfg)
    if level == "subnet" and code in _opts_catalog.MANAGED_AT_SUBNET:
        return cfg, "managed"
    container, status = _container_for_level4(cfg, level, key)
    if status != "ok":
        return cfg, "notfound"
    opts = container.get("option-data")
    if not isinstance(opts, list):
        return cfg, "notfound"
    idx = _match_option_index(opts, code)
    if idx < 0:
        return cfg, "notfound"
    opts.pop(idx)
    return cfg, "ok"
