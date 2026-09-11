"""
jen/services/kea_config_view.py
───────────────────────────────
v5.15.0 — one place that knows a Kea config can nest subnets inside
`shared-networks`.

Before this, every config-get consumer read only the top-level
`Dhcp4.subnet4` / `Dhcp6.subnet6` list. A subnet declared inside
`Dhcp4.shared-networks[].subnet4` was simply invisible: it didn't show
on the Subnets page or the dashboard, its pool wasn't counted, and
config-drift reported it as *missing from Kea* (a false alarm). These
helpers iterate BOTH places, top-level first, so a caller that switches
to them sees every subnet with no behavior change for a config that has
no shared networks at all.

Pure. `dhcp_cfg` here is the inner `Dhcp4` / `Dhcp6` map (`config["Dhcp4"]`),
not the whole config-get result — every call site already holds that
map. All functions tolerate a missing / non-dict / non-list shape and
return empty rather than raise (a config where everything is nested has
no top-level `subnet4` key at all).
"""

from __future__ import annotations


def _subnets_of(container, key):
    subs = container.get(key) if isinstance(container, dict) else None
    return [s for s in subs if isinstance(s, dict)] if isinstance(subs, list) else []


def _shared_networks(dhcp_cfg):
    nets = dhcp_cfg.get("shared-networks") if isinstance(dhcp_cfg, dict) else None
    return [n for n in nets if isinstance(n, dict)] if isinstance(nets, list) else []


def iter_subnet4(dhcp4_cfg) -> list[tuple[dict, str | None]]:
    """Every subnet4 in the config as `(subnet_dict, shared_network_name)`
    — `None` for a top-level subnet. Top-level subnets first, then each
    shared network in config order."""
    out: list[tuple[dict, str | None]] = [(s, None) for s in _subnets_of(dhcp4_cfg, "subnet4")]
    for sn in _shared_networks(dhcp4_cfg):
        name = sn.get("name")
        out.extend((s, name) for s in _subnets_of(sn, "subnet4"))
    return out


def iter_subnet6(dhcp6_cfg) -> list[tuple[dict, str | None]]:
    """v6 twin of iter_subnet4."""
    out: list[tuple[dict, str | None]] = [(s, None) for s in _subnets_of(dhcp6_cfg, "subnet6")]
    for sn in _shared_networks(dhcp6_cfg):
        name = sn.get("name")
        out.extend((s, name) for s in _subnets_of(sn, "subnet6"))
    return out


def subnet4_by_id(dhcp4_cfg, subnet_id) -> tuple[dict, str | None] | None:
    for s, sn_name in iter_subnet4(dhcp4_cfg):
        if s.get("id") == subnet_id:
            return s, sn_name
    return None


def subnet6_by_id(dhcp6_cfg, subnet_id) -> tuple[dict, str | None] | None:
    for s, sn_name in iter_subnet6(dhcp6_cfg):
        if s.get("id") == subnet_id:
            return s, sn_name
    return None


def _shared_networks_summary(dhcp_cfg, subnet_key):
    out = []
    for sn in _shared_networks(dhcp_cfg):
        out.append(
            {
                "name": sn.get("name"),
                "interface": sn.get("interface"),
                "subnet_ids": [s.get("id") for s in _subnets_of(sn, subnet_key)],
                "option_data_count": len(sn.get("option-data") or []) if isinstance(sn.get("option-data"), list) else 0,
            }
        )
    return out


def shared_networks4(dhcp4_cfg) -> list[dict]:
    """Name / interface / member subnet ids / option-data count for each
    v4 shared network, in config order. This entry only *shows* the
    option-data count — editing it is Q12."""
    return _shared_networks_summary(dhcp4_cfg, "subnet4")


def shared_networks6(dhcp6_cfg) -> list[dict]:
    return _shared_networks_summary(dhcp6_cfg, "subnet6")


def shared_networks4_raw(dhcp4_cfg) -> list[dict]:
    """The raw v4 shared-network dicts themselves (v5.19.0 — Q13 needs
    to read/scan class-attachment keys directly on them, not just the
    name/interface/subnet_ids summary shared_networks4() returns)."""
    return _shared_networks(dhcp4_cfg)
