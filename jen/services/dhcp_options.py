"""
jen/services/dhcp_options.py
────────────────────────────
v5.18.0 (Q12) — the DHCPv4 option catalog, per-type validation, and the
"effective options" walk.

Kea accepts an `option-data` entry keyed by `name` or `code` (plus
`space`, default `dhcp4`) and rejects one whose name and code disagree —
so anything Jen writes takes BOTH from `V4_OPTIONS`, never from the form.
Codes not in the catalog are "custom": written as raw hex with
`csv-format: false`.

Precedence for a lease (most specific wins): pool > subnet >
shared-network > global. Client classes and reservations are out of
scope here (Q13 / the existing DNS-only reservation field).

Pure — no I/O. `dhcp4_cfg` is the inner `Dhcp4` map.
"""

from __future__ import annotations

import ipaddress
import re

# code -> {name, type, multi}. Names are Kea's canonical dhcp4-space names.
# Lease timers (51/58/59) are NOT option-data in Kea — deliberately absent.
V4_OPTIONS: dict[int, dict] = {
    1: {"name": "subnet-mask", "type": "ip", "multi": False},
    2: {"name": "time-offset", "type": "int32", "multi": False},
    3: {"name": "routers", "type": "ip-list", "multi": True},
    4: {"name": "time-servers", "type": "ip-list", "multi": True},
    6: {"name": "domain-name-servers", "type": "ip-list", "multi": True},
    7: {"name": "log-servers", "type": "ip-list", "multi": True},
    12: {"name": "host-name", "type": "string", "multi": False},
    15: {"name": "domain-name", "type": "fqdn", "multi": False},
    19: {"name": "ip-forwarding", "type": "boolean", "multi": False},
    26: {"name": "interface-mtu", "type": "uint16", "multi": False},
    28: {"name": "broadcast-address", "type": "ip", "multi": False},
    33: {"name": "static-routes", "type": "ip-pair-list", "multi": True},
    40: {"name": "nis-domain", "type": "string", "multi": False},
    41: {"name": "nis-servers", "type": "ip-list", "multi": True},
    42: {"name": "ntp-servers", "type": "ip-list", "multi": True},
    43: {"name": "vendor-encapsulated-options", "type": "hex", "multi": False},
    44: {"name": "netbios-name-servers", "type": "ip-list", "multi": True},
    46: {"name": "netbios-node-type", "type": "uint8", "multi": False},
    47: {"name": "netbios-scope", "type": "string", "multi": False},
    60: {"name": "vendor-class-identifier", "type": "string", "multi": False},
    66: {"name": "tftp-server-name", "type": "string", "multi": False},
    67: {"name": "boot-file-name", "type": "string", "multi": False},
    69: {"name": "smtp-server", "type": "ip-list", "multi": True},
    70: {"name": "pop-server", "type": "ip-list", "multi": True},
    72: {"name": "www-server", "type": "ip-list", "multi": True},
    119: {"name": "domain-search", "type": "fqdn-list", "multi": True},
    121: {"name": "classless-static-route", "type": "classless-routes", "multi": True},
    150: {"name": "tftp-servers", "type": "ip-list", "multi": True},  # RFC 5859; Kea ≥ 2.x dhcp4 space
}

NAME_TO_CODE: dict[str, int] = {v["name"]: k for k, v in V4_OPTIONS.items()}

TYPES = frozenset(
    {
        "ip",
        "ip-list",
        "ip-pair-list",
        "string",
        "fqdn",
        "fqdn-list",
        "boolean",
        "uint8",
        "uint16",
        "uint32",
        "int32",
        "hex",
        "classless-routes",
    }
)

# codes 3 and 6 at SUBNET level belong to the Edit Subnet form
MANAGED_AT_SUBNET = frozenset({3, 6})

LEVELS = ("global", "shared-network", "subnet", "pool")

_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]*$")
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)


def catalog_choices() -> list[dict]:
    """[{code, name, type}] sorted by code — for the Add form's select."""
    return [{"code": c, "name": v["name"], "type": v["type"]} for c, v in sorted(V4_OPTIONS.items())]


def type_for(code) -> str | None:
    entry = V4_OPTIONS.get(code)
    return entry["type"] if entry else None


# ── validation ────────────────────────────────────────────────────────────


def _split(data: str) -> list[str]:
    return [p.strip() for p in (data or "").split(",") if p.strip()]


def _ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _uint(data: str, bits: int) -> str | None:
    try:
        v = int(data.strip())
    except (TypeError, ValueError):
        return "must be a whole number"
    if not 0 <= v < 2**bits:
        return f"must be between 0 and {2**bits - 1}"
    return None


def validate(opt_type: str, data: str) -> str | None:
    """Error text for `data` as `opt_type`, or None when valid."""
    data = (data or "").strip()
    if opt_type not in TYPES:
        return f"unknown option type {opt_type!r}"
    if not data:
        return "a value is required"

    if opt_type == "ip":
        return None if _ipv4(data) else "must be an IPv4 address"
    if opt_type == "ip-list":
        bad = [p for p in _split(data) if not _ipv4(p)]
        return f"not IPv4 address(es): {', '.join(bad)}" if bad else None
    if opt_type == "ip-pair-list":
        parts = _split(data)
        if not parts or len(parts) % 2:
            return "must be an even number of IPv4 addresses (destination, router, …)"
        bad = [p for p in parts if not _ipv4(p)]
        return f"not IPv4 address(es): {', '.join(bad)}" if bad else None
    if opt_type == "string":
        return None
    if opt_type == "fqdn":
        return None if _FQDN_RE.match(data) else "must be a valid domain name"
    if opt_type == "fqdn-list":
        bad = [p for p in _split(data) if not _FQDN_RE.match(p)]
        return f"not valid domain name(s): {', '.join(bad)}" if bad else None
    if opt_type == "boolean":
        return None if data.lower() in ("true", "false") else "must be true or false"
    if opt_type == "uint8":
        return _uint(data, 8)
    if opt_type == "uint16":
        return _uint(data, 16)
    if opt_type == "uint32":
        return _uint(data, 32)
    if opt_type == "int32":
        try:
            v = int(data)
        except ValueError:
            return "must be a whole number"
        return None if -(2**31) <= v < 2**31 else "must fit in a signed 32-bit integer"
    if opt_type == "hex":
        body = data[2:] if data.lower().startswith("0x") else data
        body = body.replace(":", "").replace(" ", "")
        if not body or not _HEX_RE.match(body) or len(body) % 2:
            return "must be an even-length hex string (e.g. 0a1b2c or 0x0a1b2c)"
        return None
    if opt_type == "classless-routes":
        # Kea csv syntax: "192.168.10.0/24 - 10.0.0.1, 10.0.0.0/8 - 10.0.0.2"
        for pair in _split(data):
            if " - " not in pair:
                return f"each route must be 'network/prefix - router': {pair!r}"
            net, _, gw = pair.partition(" - ")
            try:
                ipaddress.IPv4Network(net.strip(), strict=False)
            except ValueError:
                return f"not an IPv4 network: {net.strip()!r}"
            if not _ipv4(gw.strip()):
                return f"not an IPv4 router: {gw.strip()!r}"
        return None
    return None  # pragma: no cover — every TYPES member handled above


def normalize(opt_type: str, data: str) -> str:
    """The canonical form Jen writes: list types joined with ", ", single
    values stripped, booleans lower-cased, hex without 0x/colons."""
    data = (data or "").strip()
    if opt_type in ("ip-list", "ip-pair-list", "fqdn-list"):
        return ", ".join(_split(data))
    if opt_type == "classless-routes":
        out = []
        for pair in _split(data):
            net, _, gw = pair.partition(" - ")
            out.append(f"{net.strip()} - {gw.strip()}")
        return ", ".join(out)
    if opt_type == "boolean":
        return data.lower()
    if opt_type == "hex":
        body = data[2:] if data.lower().startswith("0x") else data
        return body.replace(":", "").replace(" ", "").lower()
    return data


# ── effective options ─────────────────────────────────────────────────────


def entry_key(o: dict) -> tuple:
    """(space, code-or-name) for an option-data entry. Code wins when
    present; a name-only entry resolves through the catalog; otherwise
    the bare name is the key."""
    if not isinstance(o, dict):
        return ("dhcp4", None)
    space = o.get("space") or "dhcp4"
    code = o.get("code")
    if code is None and o.get("name") in NAME_TO_CODE:
        code = NAME_TO_CODE[o["name"]]
    return (space, code if code is not None else o.get("name"))


def _display(o: dict) -> tuple[int | None, str]:
    """(code, name) for display, filling either from the catalog."""
    code = o.get("code")
    name = o.get("name")
    if code is None and name in NAME_TO_CODE:
        code = NAME_TO_CODE[name]
    if name is None and code in V4_OPTIONS:
        name = V4_OPTIONS[code]["name"]
    return code, name or (f"code {code}" if code is not None else "?")


def _opts(container) -> list[dict]:
    lst = container.get("option-data") if isinstance(container, dict) else None
    return [o for o in lst if isinstance(o, dict)] if isinstance(lst, list) else []


def _levels_for(dhcp4_cfg, subnet_id, pool=None) -> list[tuple[str, list[dict]]]:
    from jen.services import kea_config_view as _view

    found = _view.subnet4_by_id(dhcp4_cfg, subnet_id)
    if found is None:
        return []
    subnet, sn_name = found
    levels: list[tuple[str, list[dict]]] = [("global", _opts(dhcp4_cfg))]
    if sn_name is not None:
        sn = next(
            (n for n in (dhcp4_cfg.get("shared-networks") or []) if isinstance(n, dict) and n.get("name") == sn_name),
            None,
        )
        levels.append((f"shared-network:{sn_name}", _opts(sn)))
    levels.append(("subnet", _opts(subnet)))
    if pool is not None:
        p = next(
            (p for p in (subnet.get("pools") or []) if isinstance(p, dict) and p.get("pool") == pool),
            None,
        )
        levels.append(("pool", _opts(p)))
    return levels


def effective_options(dhcp4_cfg, subnet_id, pool=None) -> list[dict]:
    """Walk global → shared-network → subnet → pool; a later level
    overrides an earlier one for the same (space, code). Each row:
    {code, name, data, source, overridden: [source, …]} — `overridden`
    lists the less-specific sources whose value lost, most-general first."""
    winners: dict[tuple, dict] = {}
    for source, opts in _levels_for(dhcp4_cfg, subnet_id, pool):
        for o in opts:
            k = entry_key(o)
            code, name = _display(o)
            prev = winners.get(k)
            row = {
                "code": code,
                "name": name,
                "data": o.get("data", ""),
                "source": source,
                "overridden": (prev["overridden"] + [prev["source"]]) if prev else [],
            }
            winners[k] = row

    def _sort(kv):
        (_space, key), _row = kv
        return (0, key) if isinstance(key, int) else (1, str(key))

    return [row for _k, row in sorted(winners.items(), key=_sort)]


def _container_for_level(dhcp4_cfg, level, key):
    """(container_dict, "ok") for `level`/`key` against `dhcp4_cfg` (the
    bare Dhcp4 map), or (None, "notfound"). Read-only counterpart of
    kea_config_edit._container_for_level4, which operates on the outer
    {"Dhcp4": …} shape needed for mutation — kept separate rather than
    imported, so this read-only module has no dependency on the one that
    writes."""
    from jen.services import kea_config_view as _view

    if level == "global":
        return dhcp4_cfg, "ok"
    if level == "shared-network":
        for sn in dhcp4_cfg.get("shared-networks") or []:
            if isinstance(sn, dict) and sn.get("name") == key:
                return sn, "ok"
        return None, "notfound"
    if level == "subnet":
        found = _view.subnet4_by_id(dhcp4_cfg, key)
        return (found[0], "ok") if found else (None, "notfound")
    if level == "pool":
        subnet_id, pool_str = key
        found = _view.subnet4_by_id(dhcp4_cfg, subnet_id)
        if found is None:
            return None, "notfound"
        for p in found[0].get("pools") or []:
            if isinstance(p, dict) and p.get("pool") == pool_str:
                return p, "ok"
        return None, "notfound"
    return None, "notfound"


def options_at(dhcp4_cfg, level, key) -> list[dict]:
    """The option-data entries physically stored at `level`/`key` — NOT
    the effective view — as display rows: {code, name, data,
    csv_format}. Empty when the level/key doesn't exist in this config."""
    container, status = _container_for_level(dhcp4_cfg, level, key)
    if status != "ok":
        return []
    rows = []
    for o in _opts(container):
        code, name = _display(o)
        rows.append(
            {
                "code": code,
                "name": name,
                "data": o.get("data", ""),
                "csv_format": bool(o.get("csv-format", True)),
            }
        )
    return rows


def count_here_and_inherited(dhcp4_cfg, subnet_id) -> tuple[int, int]:
    """For the subnet card: (options set on this subnet, options it
    inherits from its shared network / global that it does NOT override)."""
    rows = effective_options(dhcp4_cfg, subnet_id)
    here = sum(1 for r in rows if r["source"] == "subnet")
    return here, len(rows) - here
