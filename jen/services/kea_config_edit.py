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
from jen.services import kea_classes as _classes
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
    updated instead of duplicated. Returns True when the config now differs (v5.69.0-beta.5, Q174:
    the caller used to say "changed" for every non-empty field, so an unchanged submit rewrote the file and restarted the daemon)."""
    for o in opts:
        if isinstance(o, dict) and o.get("code") == code:
            changed = o.get("data") != data
            o["data"] = data
            return changed
    for o in opts:
        if isinstance(o, dict) and o.get("code") is None and o.get("name") == name:
            changed = o.get("data") != data
            o["data"] = data
            return changed
    opts.append({"name": name, "code": code, "space": space, "csv-format": True, "data": data})
    return True


def _set_if_different(s, key, value) -> bool:
    """`s[key] = value`, reporting whether that changed anything."""
    if s.get(key) == value:
        return False
    s[key] = value
    return True


def _set_pools(s, new_pool, extra_pools) -> bool:
    pools = [{"pool": new_pool}] + [{"pool": p} for p in (extra_pools or [])]
    if s.get("pools") == pools:
        return False
    s["pools"] = pools
    return True


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
            changed |= _set_pools(s, new_pool, extra_pools)
        if new_lifetime:
            changed |= _set_if_different(s, "valid-lifetime", int(new_lifetime))
        if new_renew:
            changed |= _set_if_different(s, "renew-timer", int(new_renew))
        if new_rebind:
            changed |= _set_if_different(s, "rebind-timer", int(new_rebind))
        if new_routers or new_dns:
            opts = s.get("option-data", [])
            if new_routers:
                changed |= _upsert_option(opts, "routers", 3, "dhcp4", new_routers)
            if new_dns:
                changed |= _upsert_option(opts, "domain-name-servers", 6, "dhcp4", new_dns)
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
            changed |= _set_pools(s, new_pool, extra_pools)
        if new_preferred:
            changed |= _set_if_different(s, "preferred-lifetime", int(new_preferred))
        if new_valid:
            changed |= _set_if_different(s, "valid-lifetime", int(new_valid))
        if new_renew:
            changed |= _set_if_different(s, "renew-timer", int(new_renew))
        if new_rebind:
            changed |= _set_if_different(s, "rebind-timer", int(new_rebind))
        if new_dns:
            opts = s.get("option-data", [])
            changed |= _upsert_option(opts, "dns-servers", 23, "dhcp6", new_dns)
            s["option-data"] = opts
        break
    return cfg, changed


def add_subnet4(cfg, block, shared_network=None):
    """Append a new subnet4 block. Into the named shared network when
    `shared_network` is given (must already exist). Returns
    (new_cfg, "ok"|"idexists"|"nonetwork"). The new id must be unique
    across every subnet, top-level or nested."""
    cfg = copy.deepcopy(cfg)
    block = copy.deepcopy(
        block
    )  # the caller keeps its own object (Q174): editing it afterward must not edit the returned config
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
    level ∈ {"global", "shared-network", "subnet", "pool", "class"}; key
    is None / a shared-network name / a subnet id / a
    (subnet_id, pool_str) pair / a class name."""
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
    if level == "class":
        # v5.19.0 (Q13) — a client-class's own option-data.
        for c in d4.get("client-classes") or []:
            if isinstance(c, dict) and c.get("name") == key:
                return c, "ok"
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


# ── Client classes (v5.19.0 — Q13) ──────────────────────────────────────────


def _classes_of(cfg):
    return cfg.setdefault("Dhcp4", {}).setdefault("client-classes", [])


def _find_class(classes, name):
    return next((i for i, c in enumerate(classes) if isinstance(c, dict) and c.get("name") == name), None)


def upsert_class4(cfg, class_dict, position=None):
    """Insert a new class, or replace an existing one (matched by
    `class_dict["name"]`) in place. `position` only applies to a NEW
    class — an update keeps its current position; reordering is
    reorder_class4's job. Returns (new_cfg, "ok") — always succeeds,
    matching the mutate_fn(cfg) -> (cfg, code) shape _apply_dhcp4_change
    expects of every caller."""
    cfg = copy.deepcopy(cfg)
    class_dict = copy.deepcopy(class_dict)  # not aliased into the returned config (Q174)
    classes = _classes_of(cfg)
    name = class_dict.get("name")
    idx = _find_class(classes, name)
    if idx is not None:
        classes[idx] = class_dict
    elif position is not None and 0 <= position <= len(classes):
        classes.insert(position, class_dict)
    else:
        classes.append(class_dict)
    return cfg, "ok"


def delete_class4(cfg, name):
    """Returns (new_cfg, "ok"|"notfound"|"referenced"|"builtin"). Refuses
    a built-in class outright, and any class still referenced by a
    subnet/pool/shared-network attachment or another class's member()."""
    cfg = copy.deepcopy(cfg)
    if _classes.is_builtin(name):
        return cfg, "builtin"
    d4 = cfg.get("Dhcp4")
    classes = d4.get("client-classes") if isinstance(d4, dict) else None
    if not isinstance(classes, list):
        return cfg, "notfound"
    idx = _find_class(classes, name)
    if idx is None:
        return cfg, "notfound"
    if _classes.references(d4, name):
        return cfg, "referenced"
    classes.pop(idx)
    return cfg, "ok"


def reorder_class4(cfg, name, direction):
    """direction ∈ {"up", "down"}. Returns
    (new_cfg, "ok"|"notfound"|"boundary") — evaluation order is list
    order, so this swaps the class with its neighbor; "boundary" when
    there's no neighbor that way."""
    cfg = copy.deepcopy(cfg)
    d4 = cfg.get("Dhcp4")
    classes = d4.get("client-classes") if isinstance(d4, dict) else None
    if not isinstance(classes, list):
        return cfg, "notfound"
    idx = _find_class(classes, name)
    if idx is None:
        return cfg, "notfound"
    new_idx = idx - 1 if direction == "up" else idx + 1
    if new_idx < 0 or new_idx >= len(classes):
        return cfg, "boundary"
    classes[idx], classes[new_idx] = classes[new_idx], classes[idx]
    return cfg, "ok"


def attach_class4(cfg, name, scope_level, scope_key, mode="guard", attach=True, version=None):
    """Attach/detach `name` as a guard ("must match one of these to be
    selected") or an additional class ("also evaluated for this scope
    after selection") on a subnet, pool, or shared network. Returns
    (new_cfg, "ok"|"notfound"). Writes whichever key spelling
    attachment_keys() resolves for this config (reading elsewhere always
    checks both)."""
    cfg = copy.deepcopy(cfg)
    d4 = cfg.get("Dhcp4")
    if not isinstance(d4, dict):
        return cfg, "notfound"
    container, status = _container_for_level4(cfg, scope_level, scope_key)
    if status != "ok":
        return cfg, "notfound"
    keys = _classes.attachment_keys(d4, version)

    if mode == "guard":
        key = keys["guard"]
        if key == _classes.NEW_GUARD:
            lst = [c for c in (container.get(key) or []) if isinstance(c, str)]
            if attach:
                if name not in lst:
                    lst.append(name)
            else:
                lst = [c for c in lst if c != name]
            if lst:
                container[key] = lst
            else:
                container.pop(key, None)
        else:  # OLD_GUARD is a single string, not a list
            if attach:
                container[key] = name
            elif container.get(key) == name:
                container.pop(key, None)
    else:  # "additional" — always a list, either spelling
        key = keys["additional"]
        lst = [c for c in (container.get(key) or []) if isinstance(c, str)]
        if attach:
            if name not in lst:
                lst.append(name)
        else:
            lst = [c for c in lst if c != name]
        if lst:
            container[key] = lst
        else:
            container.pop(key, None)
    return cfg, "ok"


# ── DDNS naming (v5.23.0 — Q19) ──────────────────────────────────────────────

# Dhcp4.dhcp-ddns's own fields (whether Kea talks to D2 at all, and how).
_DDNS_BLOCK_KEYS = frozenset({"enable-updates", "server-ip", "server-port", "ncr-protocol", "ncr-format"})

# Top-level Dhcp4 naming knobs — how a hostname gets built/sent, not
# whether D2 is contacted. Global-only for now (Q12's per-level model
# could extend these to subnet level later — out of scope here).
DDNS_NAMING_KEYS = frozenset(
    {
        "ddns-send-updates",
        "ddns-override-no-update",
        "ddns-override-client-update",
        "ddns-replace-client-name",
        "ddns-generated-prefix",
        "ddns-qualifying-suffix",
        "ddns-update-on-renew",
        "ddns-conflict-resolution-mode",
        "hostname-char-set",
        "hostname-char-replacement",
    }
)


def set_ddns4(cfg, values: dict):
    """Write the `Dhcp4.dhcp-ddns` block plus the global naming knobs.
    `values` carries whichever of _DDNS_BLOCK_KEYS / DDNS_NAMING_KEYS the
    Naming form submitted — a key simply absent from `values` is left
    untouched rather than cleared, since the form always submits every
    field it renders and a missing key only ever means "this caller isn't
    touching that knob," never "clear it." Always succeeds — there's no
    managed/notfound case here, unlike the option/class editors — but
    returns the (cfg, "ok") shape those use, for a consistent call site
    in the route."""
    cfg = copy.deepcopy(cfg)
    values = copy.deepcopy(values)  # not aliased into the returned config (Q174)
    dhcp4 = cfg.setdefault("Dhcp4", {})
    block_values = {k: v for k, v in values.items() if k in _DDNS_BLOCK_KEYS}
    if block_values:
        dhcp4.setdefault("dhcp-ddns", {}).update(block_values)
    for k in DDNS_NAMING_KEYS:
        if k in values:
            dhcp4[k] = values[k]
    return cfg, "ok"


# ── Direct control sockets (v5.29.0, Q29) ────────────────────────────────────

_DAEMON_KEY = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}
_API_SOCKET_TYPES = ("http", "https")


def _replace_key_in_place(section: dict, old: str, new: str, value) -> None:
    """Swap `old` for `new` at the same position — a converted
    `control-socket` → `control-sockets` shouldn't move to the end of the
    daemon block and show up as a whole-file reorder in the revision diff."""
    items = list(section.items())
    section.clear()
    for k, v in items:
        if k == old:
            section[new] = value
        else:
            section[k] = v


def _control_sockets(section: dict) -> list | None:
    """The daemon's `control-sockets` LIST, converting the singular
    pre-2.7.2 `control-socket` map into a one-element list in place if
    that's what the config has (Kea 2.7.2+ accepts the list form, and the
    unix entry it held is kept verbatim). None when the shape is
    something this code doesn't understand — e.g. a Control Agent's
    `control-sockets`, which is a MAP keyed by service, not a list."""
    if "control-sockets" in section:
        lst = section["control-sockets"]
        return lst if isinstance(lst, list) else None
    if "control-socket" in section:
        single = section["control-socket"]
        if not isinstance(single, dict):
            return None
        _replace_key_in_place(section, "control-socket", "control-sockets", [single])
        return section["control-sockets"]
    section["control-sockets"] = []
    return section["control-sockets"]


def set_control_socket(cfg: dict, service: str, socket: dict):
    """Add or replace the daemon's http/https API socket — `socket` is
    what kea_authoring.build_control_socket() returns. The unix entry is
    never touched (kea-shell and some hooks use it). A daemon has at most
    one API socket, so an existing http/https entry is replaced in place
    rather than appended beside. Returns (cfg, code): "ok", "nochange"
    (identical entry already there), or "unsupported" (no `Dhcp4`/
    `Dhcp6`/`DhcpDdns` block for `service`, or a `control-sockets` that
    isn't the daemon list form)."""
    cfg = copy.deepcopy(cfg)
    socket = copy.deepcopy(socket)  # not aliased into the returned config (Q174)
    key = _DAEMON_KEY.get(service)
    section = cfg.get(key) if key else None
    if not isinstance(section, dict):
        return cfg, "unsupported"
    sockets = _control_sockets(section)
    if sockets is None:
        return cfg, "unsupported"
    if sum(1 for s in sockets if _is_api_socket(s)) > 1:
        return (
            cfg,
            "multiple",
        )  # AB1 (Q186): Jen manages ONE API socket; a config with more is not flattened, it is refused (the caller says so before anything is written)
    for i, existing in enumerate(sockets):
        if _is_api_socket(existing):
            if existing == socket:
                return cfg, "nochange"
            sockets[i] = socket
            return cfg, "ok"
    sockets.append(socket)
    return cfg, "ok"


def _is_api_socket(entry) -> bool:
    return isinstance(entry, dict) and entry.get("socket-type") in _API_SOCKET_TYPES


def _daemon_section(cfg: dict, service: str):
    key = _DAEMON_KEY.get(service)
    section = cfg.get(key) if key else None
    return section if isinstance(section, dict) else None


def control_sockets(cfg: dict, service: str) -> list:
    """AB1 (Q186): a deep copy of the daemon's `control-sockets` - EVERY entry, in order - as the snapshot a multi-step route restores whole. The pre-2.7.2 singular `control-socket`
    map reads as a one-element list; a daemon with no block, no sockets, or a shape this code does not understand (a Control Agent's map) reads as `[]`. Never changes `cfg`."""
    section = _daemon_section(cfg, service)
    if section is None:
        return []
    if "control-sockets" in section:
        lst = section["control-sockets"]
        return copy.deepcopy(lst) if isinstance(lst, list) else []
    single = section.get("control-socket")
    return [copy.deepcopy(single)] if isinstance(single, dict) else []


def restore_control_sockets(cfg: dict, service: str, snapshot: list):
    """AB1 (Q186): the ONLY compensation (exact up to what a list cannot say: an empty list and an absent key are both "no sockets", and a singular `control-socket` map comes back in the
    list form Kea 2.7.2+ reads; the TLS files `install_tls` put on the host are not part of a snapshot of the config) for a change to a daemon's control sockets - the list becomes `snapshot` exactly (entries, order, every field), whatever the failed step
    left there: a socket added, replaced or removed, one entry or several. An empty snapshot is a daemon with no sockets: the key is dropped. Returns (cfg, code): "ok", "nochange" (the
    daemon already has exactly that list) or "unsupported" (no daemon block, or a `control-sockets` that is not the list form)."""
    cfg = copy.deepcopy(cfg)
    section = _daemon_section(cfg, service)
    if section is None or not isinstance(snapshot, list) or not all(isinstance(s, dict) for s in snapshot):
        return (
            cfg,
            "unsupported",
        )  # (Q187, AC6) a snapshot that is not a list of entries is not one this function writes
    if "control-sockets" in section and not isinstance(section["control-sockets"], list):
        return cfg, "unsupported"
    if "control-socket" in section and (
        "control-sockets" in section or not isinstance(section["control-socket"], dict)
    ):
        return (
            cfg,
            "unsupported",
        )  # both spellings at once, or a singular that is not a map: not a shape this code restores (a hand edit; said, never guessed at)
    if control_sockets(cfg, service) == snapshot and "control-socket" not in section:
        return cfg, "nochange"
    wanted = copy.deepcopy(snapshot)
    if "control-socket" in section:
        if wanted:
            _replace_key_in_place(section, "control-socket", "control-sockets", wanted)
        else:
            del section["control-socket"]
    elif wanted:
        section["control-sockets"] = wanted
    else:
        section.pop("control-sockets", None)
    return cfg, "ok"


def describe_socket(entry) -> str:
    """AB2 (Q186): the words that name a control socket in a flash, an audit row or a log line - `<type> <address>:<port>` (a unix socket: `unix <path>`). Authentication and TLS
    fields are NEVER printed: a Basic client's password is in the entry, and the entry must never reach text (LEAK-001)."""
    if not isinstance(entry, dict):
        return "an unreadable socket entry"

    def plain(value) -> str:
        """Only a string or an integer is printed (Q187, AC6): a dict, a list or a boolean in a field the entry should carry as text is '?', never its repr (which could be anything)."""
        if isinstance(value, bool) or not isinstance(value, str | int):
            return "?"
        text = "".join(ch if ch.isprintable() else "?" for ch in str(value))[
            :64
        ]  # one short printable line, whatever the file held
        return text or "?"

    kind = (
        plain(entry["socket-type"]) if "socket-type" in entry else "unix"
    )  # Kea's default: a type-less entry is a unix socket
    if kind == "unix":
        return f"unix {plain(entry.get('socket-name'))}"
    address = plain(entry.get("socket-address"))
    host = f"[{address}]" if ":" in address else address
    return f"{kind} {host}:{plain(entry.get('socket-port'))}"


def uses_singular_socket(cfg: dict, service: str) -> bool:
    """Does the daemon still carry the pre-2.7.2 singular `control-socket` map (and no list)? A change that touches its sockets rewrites it in the list form (Q187, AC6); the route says so."""
    section = _daemon_section(cfg, service)
    return section is not None and "control-socket" in section and "control-sockets" not in section


def remove_control_socket(cfg: dict, service: str, address: str | None = None, port: int | None = None):
    """Drop the daemon's http/https API socket (the "switch back to the
    Control Agent" path), keeping the unix entry and the list form.
    AB1 (Q186): ONLY the entry named is removed. With `address` and `port` (the route reads them from the entry it snapshotted) it is the http/https entry with that address and
    port, and any other entry stays; without them it is the daemon's one API socket, and a config with more than one is "multiple" - never flattened.
    Returns (cfg, code): "ok", "nochange" (there wasn't one), "multiple", or
    "unsupported" as set_control_socket."""
    cfg = copy.deepcopy(cfg)
    section = _daemon_section(cfg, service)
    if section is None:
        return cfg, "unsupported"
    if "control-sockets" not in section and "control-socket" not in section:
        return cfg, "nochange"
    sockets = _control_sockets(
        section
    )  # (Q187, AC6) reads - and converts, in place - the singular map the snapshot already reads
    if sockets is None:
        return cfg, "unsupported"
    api = [s for s in sockets if _is_api_socket(s)]
    if address is None and port is None:
        if len(api) > 1:
            return cfg, "multiple"
        named = api
    else:
        named = [s for s in api if s.get("socket-address") == address and s.get("socket-port") == port]
    if not named:
        return cfg, "nochange"
    kept = [s for s in sockets if not any(s is n for n in named)]
    section["control-sockets"] = kept
    return cfg, "ok"


# ── Investigation logging (v5.68.0-beta.3, Q138) ──────────────────────────────
#
# What Trace and Explain can read out of Kea's log depends on its level (measured on Kea 3.0.3, 3.2.0 and 3.3.1 by
# tests/kea_compat/test_log_levels.py): at DEBUG with debuglevel 55 the packet dump and the class assignments are there. A
# production DHCP server should not sit at that level, so Jen turns it on for a bounded time and puts it back itself. The
# change is recorded IN the config - a `user-context` on the logger entry, `{"jen-investigation": {"until": …, "restore":
# …}}` - so a Jen restart, a different Jen, or a person with a text editor can all see what is on and what undoes it, and the
# sweep (jen/services/investigation_logging.py) needs no database to know. Only the `kea-dhcp4` logger entry is ever touched
# (its `output-options` exactly as they were); an entry that did not exist is created and removed again.

INVESTIGATION_KEY = "jen-investigation"
INVESTIGATION_LOGGER = "kea-dhcp4"
INVESTIGATION_SEVERITY = "DEBUG"
INVESTIGATION_DEBUGLEVEL = 55


def _dhcp4_loggers(cfg: dict, create: bool):
    """(`Dhcp4` section, its `loggers` list) - or (None, None) when the config has no Dhcp4 block or `loggers` is not a list.
    With `create`, a missing `loggers` becomes an empty list."""
    section = cfg.get("Dhcp4")
    if not isinstance(section, dict):
        return None, None
    loggers = section.get("loggers")
    if loggers is None:
        if not create:
            return section, []
        loggers = section["loggers"] = []
    return (section, loggers) if isinstance(loggers, list) else (None, None)


def _logger_entry(loggers: list):
    return next((x for x in loggers if isinstance(x, dict) and x.get("name") == INVESTIGATION_LOGGER), None)


def investigation_marker(cfg: dict) -> dict | None:
    """The `jen-investigation` marker on the kea-dhcp4 logger - `{"until": iso, "restore": {…}}` - or None."""
    _section, loggers = _dhcp4_loggers(cfg, create=False)
    entry = _logger_entry(loggers or [])
    marker = (entry.get("user-context") or {}).get(INVESTIGATION_KEY) if isinstance(entry, dict) else None
    return marker if isinstance(marker, dict) else None


def set_investigation_logging(cfg: dict, until_iso: str):
    """Put the kea-dhcp4 logger at DEBUG, debuglevel 55, until `until_iso` (UTC ISO 8601), recording what to put back.
    Returns (cfg, code): "ok", or "unsupported" (no `Dhcp4` block, or `loggers`/`user-context` is not the shape Kea
    documents). Idempotent: when the marker is already there only `until` moves (the ORIGINAL restore is kept, so extending
    never makes DEBUG the thing to "restore" to), and the entry's `output-options` are never touched."""
    cfg = copy.deepcopy(cfg)
    if validate_investigation_marker(cfg):
        # a marker that cannot be read is never overwritten with the logger's CURRENT (DEBUG) values
        return cfg, "marker-invalid"
    section, loggers = _dhcp4_loggers(cfg, create=True)
    if section is None:
        return cfg, "unsupported"
    entry = _logger_entry(loggers)
    created = entry is None
    if created:
        entry = {"name": INVESTIGATION_LOGGER}
        loggers.append(entry)
    context = entry.get("user-context", {})
    if not isinstance(context, dict):
        return cfg, "unsupported"
    marker = context.get(INVESTIGATION_KEY)
    if isinstance(marker, dict):
        # a marker is already there: its ORIGINAL restore object is kept. If it has been damaged there is nothing trustworthy to keep,
        # and re-recording the logger's CURRENT (DEBUG) values as "what to restore" would make DEBUG the thing to put back - refuse
        if restore_problem(marker.get("restore")):
            return cfg, "marker-invalid"
        restore = marker["restore"]
    elif created:
        restore = {"created": True}
    else:
        restore = {
            "severity": entry.get("severity", "absent"),
            "debuglevel": entry.get("debuglevel", "absent"),
        }
    entry["severity"] = INVESTIGATION_SEVERITY
    entry["debuglevel"] = INVESTIGATION_DEBUGLEVEL
    context[INVESTIGATION_KEY] = {"until": until_iso, "restore": restore}
    entry["user-context"] = context
    return cfg, "ok"


def _parse_until(text):
    from datetime import datetime, timezone

    try:
        when = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


_RESTORE_KEYS = ("severity", "debuglevel")


def restore_problem(restore) -> str:
    """ "" when a marker's `restore` object says, unambiguously, how to put the logger back - else a short reason. Valid is exactly
    one of: `{"created": true}` (Jen created the entry; remove it), or an object carrying BOTH `severity` and `debuglevel`, each either
    the literal "absent" (the key was not there; remove it) or a real value (a non-empty string severity, an integer debuglevel).
    Anything else - no `restore`, not an object, a missing key, a `created` that is not `true` - is a marker that has lost the very
    thing it exists to carry, and must not be read as proof that the keys never existed (v5.68.0-beta.13, Q148)."""
    if not isinstance(restore, dict):
        return "its restore object is missing or is not an object"
    if "created" in restore:
        return "" if restore["created"] is True and len(restore) == 1 else "its `created` marker is malformed"
    for key in _RESTORE_KEYS:
        if key not in restore:
            return f"its restore object has no `{key}`"
        value = restore[key]
        if value == "absent":
            continue
        if key == "severity" and not (isinstance(value, str) and value.strip()):
            return "its restored `severity` is not a value"
        if key == "debuglevel" and (isinstance(value, bool) or not isinstance(value, int)):
            return "its restored `debuglevel` is not a value"
    return ""


def validate_investigation_marker(cfg: dict) -> str:
    """ "" when the kea-dhcp4 logger carries no `jen-investigation` marker, or one whose `restore` object says unambiguously how to put the
    logger back; else a short reason (v5.68.0-beta.14, Q149). It answers ONE question - can the way back be trusted - and is separate from
    "is it due": the restore step, the full scan and the turn-on all ask it first, so a damaged marker is found the minute a scan reads it, not
    at its deadline. A marker that is not an object at all (a string, a list) is damaged too: `investigation_marker` cannot see it, and a
    turn-on over it would record the logger's current DEBUG values as what to restore."""
    _section, loggers = _dhcp4_loggers(cfg, create=False)
    entry = _logger_entry(loggers or [])
    context = entry.get("user-context") if isinstance(entry, dict) else None
    if not isinstance(context, dict) or INVESTIGATION_KEY not in context:
        return ""
    marker = context[INVESTIGATION_KEY]
    if not isinstance(marker, dict):
        return "the marker is not an object"
    return restore_problem(marker.get("restore"))


def clear_investigation_logging(cfg: dict, now=None):
    """Put the kea-dhcp4 logger back as `set_investigation_logging` found it. With `now` (a timezone-aware datetime) it does
    so only when the marker's `until` has passed - the sweep's rule; an unreadable `until` counts as passed. With `now=None`
    it restores unconditionally (the button). Returns (cfg, code): "ok" (restored), "nochange" (nothing marked, or not yet
    due), "marker-invalid" (the marker's restore object cannot be trusted: NOTHING is changed - the logger and the marker are left
    exactly as they were, because a damaged marker used to read as "these keys never existed" and delete the logger's severity and
    debuglevel together with it). An entry Jen created is removed again; one that existed gets exactly its old severity and
    debuglevel back (a key that was absent is removed), and its `output-options` and any other `user-context` keys are left alone."""
    cfg = copy.deepcopy(cfg)
    if validate_investigation_marker(cfg):
        # whatever the deadline: a damaged marker is reported when it is seen, not when it is due (Q149)
        return cfg, "marker-invalid"
    _section, loggers = _dhcp4_loggers(cfg, create=False)
    entry = _logger_entry(loggers or [])
    context = entry.get("user-context") if isinstance(entry, dict) else None
    marker = context.get(INVESTIGATION_KEY) if isinstance(context, dict) else None
    if not isinstance(marker, dict):
        return cfg, "nochange"
    if now is not None:
        due = _parse_until(marker.get("until"))
        if due is not None and due > now:
            return cfg, "nochange"
    restore = marker["restore"]
    if restore.get("created"):
        loggers.remove(entry)
        return cfg, "ok"
    for key in ("severity", "debuglevel"):
        old = restore.get(key, "absent")
        if old == "absent":
            entry.pop(key, None)
        else:
            entry[key] = old
    del context[INVESTIGATION_KEY]
    if not context:
        del entry["user-context"]
    return cfg, "ok"


# ── Where Kea writes its log (Q249) ───────────────────────────────────────────────────────────────────────────────────
#
# Measured on kea-dhcp4 3.0.5: `config-set` changes the logger's output live and Kea creates the file itself (its own account, mode 0640); with no `pattern` key the lines
# start with the date and time Jen's parser needs. The Settings -> Kea -> Kea logging card offers three shapes of the `kea-dhcp4` logger's `output-options` and nothing else
# of the entry is ever touched here. What the daemon answers on `config-get` carries its defaults written out (`"flush": true`, `"pattern": ""`), so a comparison is made on
# the normalized option, never on the dict as given.

#: what the package ships: the journal, with the short pattern
LOGGER_OUTPUT_JOURNAL = {"output": "stdout", "pattern": "%-5p %m\n"}
#: the file Jen reads, with Kea's own rotation (no logrotate file is shipped)
LOGGER_OUTPUT_FILE_DEFAULT = {"output": "/var/log/kea/kea-dhcp4.log", "flush": True, "maxsize": 10485760, "maxver": 4}
LOGGER_OUTPUT_CHOICES = ("journal", "file", "both")
_LOGGER_FILE_KEYS = {"output", "flush", "maxsize", "maxver", "pattern"}


def _normal_option(option):
    """One `output-options` entry without the defaults Kea writes out (`flush: true`, an empty `pattern`); None when it is not an object."""
    if not isinstance(option, dict):
        return None
    out = dict(option)
    if out.get("flush") is True:
        del out["flush"]
    if out.get("pattern") == "":
        del out["pattern"]
    return out


def _is_journal_option(option) -> bool:
    return _normal_option(option) == LOGGER_OUTPUT_JOURNAL


def _is_file_option(option) -> bool:
    """A file output this card can describe: a path, Kea's rotation numbers when present, no pattern of its own."""
    normal = _normal_option(option)
    if normal is None or not isinstance(normal.get("output"), str) or not normal["output"].startswith("/"):
        return False
    if set(normal) - _LOGGER_FILE_KEYS or "pattern" in normal or "flush" in normal:
        return False
    return all(
        key not in normal or (isinstance(normal[key], int) and not isinstance(normal[key], bool))
        for key in ("maxsize", "maxver")
    )


def logger_output_options(choice: str, path: str, maxsize: int, maxver: int) -> list:
    """Exactly what a choice stores as the `kea-dhcp4` logger's `output-options`."""
    file_option = {"output": path, "flush": True, "maxsize": maxsize, "maxver": maxver}
    if choice == "journal":
        return [dict(LOGGER_OUTPUT_JOURNAL)]
    if choice == "file":
        return [file_option]
    return [dict(LOGGER_OUTPUT_JOURNAL), file_option]


def describe_logger_output(cfg) -> dict:
    """Where the `kea-dhcp4` logger of `cfg` (a whole `{"Dhcp4": ...}` config) writes: `{"present", "options", "choice", "file", "maxsize", "maxver"}`.
    `present` is whether the config has that logger entry; `options` its `output-options` as given (a list, [] when there is none); `choice` is `journal`, `file` or `both`
    when the options are what that choice stores (Kea's written-out defaults aside), `none` when the entry or its options are absent (Kea then logs to stdout) and `custom`
    for anything else; `file`, `maxsize` and `maxver` describe the file output of a `file` or `both` choice (None otherwise, or when Kea did not say)."""
    _section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    entry = _logger_entry(loggers or [])
    out = {"present": entry is not None, "options": [], "choice": "none", "file": None, "maxsize": None, "maxver": None}
    options = entry.get("output-options") if entry is not None else None
    if options is None or options == []:
        return out
    if not isinstance(options, list):
        out["options"], out["choice"] = [options], "custom"
        return out
    out["options"] = copy.deepcopy(options)
    file_option = None
    if len(options) == 1 and _is_journal_option(options[0]):
        out["choice"] = "journal"
    elif len(options) == 1 and _is_file_option(options[0]):
        out["choice"], file_option = "file", options[0]
    elif len(options) == 2 and _is_journal_option(options[0]) and _is_file_option(options[1]):
        out["choice"], file_option = "both", options[1]
    else:
        out["choice"] = "custom"
    if file_option is not None:
        out.update(file=file_option["output"], maxsize=file_option.get("maxsize"), maxver=file_option.get("maxver"))
    return out


def _output_name(option) -> str:
    """One output as a short printable word: the `output` string only, never anything else of the entry."""
    value = option.get("output") if isinstance(option, dict) else None
    if not isinstance(value, str) or not value:
        return "?"
    return "".join(ch if ch.isprintable() else "?" for ch in value)[:120]


def logger_output_words(described: dict) -> str:
    """`describe_logger_output`'s answer in words, for the card, the flash and the audit row: only the outputs' names are printed."""
    names = [_output_name(o) for o in described.get("options") or []]
    files = [n for n in names if n.startswith("/")]
    rest = [n for n in names if not n.startswith("/")]
    if not names or (not files and all(n == "stdout" for n in rest)):
        return "the system journal (stdout)"
    if len(files) == 1 and not rest:
        return f"the file {files[0]}"
    if len(files) == 1 and all(n == "stdout" for n in rest):
        return f"the system journal and the file {files[0]}"
    if not files and all(n == "syslog" for n in rest):
        return "syslog"
    return ", ".join(names)


def _carries_marker(entry) -> bool:
    context = entry.get("user-context") if isinstance(entry, dict) else None
    return isinstance(context, dict) and INVESTIGATION_KEY in context


def logger_marker_present(cfg) -> bool:
    """Does the `kea-dhcp4` logger of `cfg` carry a `jen-investigation` marker, readable or damaged?"""
    _section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    return _carries_marker(_logger_entry(loggers or []))


def logger_severity_words(cfg) -> str:
    """The `kea-dhcp4` logger's severity as the config says it, for a read-only line: `INFO`, `DEBUG (debuglevel 55)`, or that it is not set."""
    _section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    entry = _logger_entry(loggers or [])
    severity = entry.get("severity") if entry is not None else None
    if not isinstance(severity, str) or not severity.strip():
        return "not set (Kea's default is INFO)"
    text = "".join(ch if ch.isprintable() else "?" for ch in severity.strip())[:20]
    level = entry.get("debuglevel")
    if text.upper() == "DEBUG" and isinstance(level, int) and not isinstance(level, bool):
        return f"{text} (debuglevel {level})"
    return text


#: severities at which Kea writes no line for a command it receives (COMMAND_RECEIVED is INFO): a change of output cannot be proven by asking the daemon something.
#: NONE (Q251) is Kea's own word for a logger that writes nothing at all.
LOGGER_SEVERITIES_ABOVE_INFO = ("WARN", "ERROR", "FATAL", "NONE")


def logger_severity_above_info(cfg) -> str:
    """`WARN`, `ERROR`, `FATAL` or `NONE` when the `kea-dhcp4` logger of `cfg` is set to one of them (compared without case), else "" - absent, INFO, DEBUG and anything else."""
    _section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    entry = _logger_entry(loggers or [])
    severity = entry.get("severity") if entry is not None else None
    text = severity.strip().upper() if isinstance(severity, str) else ""
    return text if text in LOGGER_SEVERITIES_ABOVE_INFO else ""


LOGGER_PROOF_ASKS = ("command", "config-test", "none")
#: the logger each line Jen can ask for is written by (measured on kea-dhcp4 3.0.5 and 3.2.1, Q252)
LOGGER_PROOF_PARTS = {"command": "kea-dhcp4.commands", "config-test": "kea-dhcp4.dhcp4"}


def logger_proof_ask(cfg) -> str:
    """Which line Jen can ask the running kea-dhcp4 to write through its `kea-dhcp4` logger (Q253), one of `LOGGER_PROOF_ASKS`:

    - `"command"`: an unknown command, which Kea's `kea-dhcp4.commands` logger records at INFO. Only when the `kea-dhcp4` logger's severity is INFO or DEBUG (or it
      has none) AND the configuration has no logger entry named `kea-dhcp4.commands`;
    - `"config-test"`: a configuration test Kea refuses, which its `kea-dhcp4.dhcp4` logger records at ERROR. Only when the severity is INFO, DEBUG, WARN or ERROR
      AND the configuration has no logger entry named `kea-dhcp4.dhcp4`;
    - `"none"`: neither (severity FATAL or NONE, or both of those loggers have entries of their own).

    A logger entry of its own can give that logger another severity or other outputs, so its line may never reach the file the `kea-dhcp4` logger writes (measured:
    a working change was put back). Jen does not model what such an entry does: an entry of that name is enough to choose the other line."""
    _section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    named = {x.get("name") for x in loggers or [] if isinstance(x, dict)}
    severity = logger_severity_above_info(cfg)
    if severity == "" and LOGGER_PROOF_PARTS["command"] not in named:
        return "command"
    if severity in ("", "WARN", "ERROR") and LOGGER_PROOF_PARTS["config-test"] not in named:
        return "config-test"
    return "none"


def logger_output_snapshot(cfg) -> dict:
    """What `restore_logger_output` needs to put the `kea-dhcp4` logger's output back exactly: whether the config had a `loggers` list at all, whether the entry was there,
    and its `output-options` (None when it had none)."""
    section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    entry = _logger_entry(loggers or [])
    return {
        "loggers": isinstance(section, dict) and "loggers" in section,
        "entry": entry is not None,
        "options": copy.deepcopy(entry["output-options"]) if entry is not None and "output-options" in entry else None,
    }


def set_logger_output(cfg: dict, choice: str, path: str, maxsize: int, maxver: int):
    """Make the `kea-dhcp4` logger write to the journal, a file, or both (`LOGGER_OUTPUT_CHOICES`). Returns (cfg, code): "ok", "nochange" (it already writes exactly
    that - and a config with no logger, or a logger with no output, already logs to stdout, so `journal` there is "nochange"), "unsupported" (no `Dhcp4`, `loggers` is not a
    list, or a choice this function does not know), "investigation" (the logger carries a `jen-investigation` marker, readable or damaged: the restore of a session that
    created the entry removes the whole entry, and the new output with it). Only `output-options` is touched; the entry is created - as
    `{"name": "kea-dhcp4", "output-options": [...], "severity": "INFO", "debuglevel": 0}` - only when the config has none."""
    cfg = copy.deepcopy(cfg)
    if choice not in LOGGER_OUTPUT_CHOICES or not isinstance(cfg, dict):
        return cfg, "unsupported"
    section, loggers = _dhcp4_loggers(cfg, create=False)
    if section is None:
        return cfg, "unsupported"
    entry = _logger_entry(loggers)
    if _carries_marker(entry):
        return cfg, "investigation"
    wanted = logger_output_options(choice, path, maxsize, maxver)
    current = entry.get("output-options") if entry is not None else None
    if current is None or current == []:
        if choice == "journal":
            return cfg, "nochange"
    elif isinstance(current, list) and [_normal_option(o) for o in current] == [_normal_option(o) for o in wanted]:
        return cfg, "nochange"
    if entry is None:
        _section, loggers = _dhcp4_loggers(cfg, create=True)
        loggers.append({"name": INVESTIGATION_LOGGER, "output-options": wanted, "severity": "INFO", "debuglevel": 0})
    else:
        entry["output-options"] = wanted
    return cfg, "ok"


def restore_logger_output(cfg: dict, snapshot: dict):
    """Put the `kea-dhcp4` logger's output back as `logger_output_snapshot` found it: the old `output-options`, the key removed when there was none, the entry removed when
    this change created it. Returns (cfg, code): "ok", "nochange", "unsupported", "investigation" - as `set_logger_output`."""
    cfg = copy.deepcopy(cfg)
    section, loggers = _dhcp4_loggers(cfg if isinstance(cfg, dict) else {}, create=False)
    if section is None:
        return cfg, "unsupported"
    entry = _logger_entry(loggers)
    if _carries_marker(entry):
        return cfg, "investigation"
    if logger_output_snapshot(cfg) == snapshot:
        return cfg, "nochange"
    if not snapshot.get("entry"):
        if entry is not None:
            loggers.remove(entry)
        if not loggers and not snapshot.get("loggers", True):
            section.pop("loggers", None)  # the change created the list too
        return cfg, "ok"
    if entry is None:
        return cfg, "unsupported"
    if snapshot.get("options") is None:
        entry.pop("output-options", None)
    else:
        entry["output-options"] = copy.deepcopy(snapshot["options"])
    return cfg, "ok"
