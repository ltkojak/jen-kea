"""
jen/services/config_drift.py
─────────────────────────────
v5.2.0 — Config drift detection.

Jen's own subnet ID → name/CIDR mapping (extensions.SUBNET_MAP /
SUBNET6_MAP, sourced from Jen's [subnets] config file) is NOT derived
from Kea's live config at all — it's a separate, manually-maintained
list, kept in sync only by whoever remembers to update it whenever the
underlying Kea/pfsense subnet layout changes. This is exactly what
caused a real bug found in practice: an admin's config had drifted
enough that selecting "IoT" in a subnet filter silently returned
Production's data instead, because Jen's stored subnet ID for "IoT"
no longer matched what Kea's live config actually assigned that ID
to. There was no way to know this had happened until it produced a
confusing symptom.

This module answers one question — "does Jen's stored subnet map
still agree with what Kea's live config says right now?" — by
comparing subnet ID and CIDR between the two sources. It intentionally
does NOT compare "name", since Kea's own config has no concept of a
subnet name at all; name is purely Jen's own label, and there's
nothing on the Kea side to check it against.

Three ways the two sources can disagree:
  - missing_in_kea:  Jen has a subnet id Kea's live config no longer has
                      (removed from Kea directly, or renumbered away)
  - unknown_to_jen:  Kea's live config has a subnet id Jen has no name
                      for (added to Kea directly, never registered in
                      Jen) — it'll show as "Subnet N" anywhere Jen
                      displays it and can't be selected by name
  - cidr_mismatch:   both sides agree the id exists, but disagree on
                      which network it actually is — the exact failure
                      mode behind the bug this feature exists to catch
"""

import logging

logger = logging.getLogger(__name__)


def detect_subnet_drift(jen_map: dict, live_map: dict, family: str = "v4") -> list:
    """
    Compare Jen's own stored subnet map against Kea's live config-get
    output for one address family. Pure function — no I/O, no Kea/DB
    access — so it's fully unit-testable against hand-built maps.

    jen_map:  {subnet_id: {"name": str, "cidr": str}, ...} — same shape
              as extensions.SUBNET_MAP / SUBNET6_MAP.
    live_map: {subnet_id: cidr_str, ...} — extracted from Kea's live
              config-get. Kea has no concept of a name to compare.
    family:   "v4" or "v6", carried through onto each issue for display
              and for scoping which UI section reports it.

    Returns a list of issue dicts (each with at least "type", "family",
    "subnet_id", and a human-readable "message"). Empty list means no
    drift detected between the two maps given.
    """
    issues = []
    jen_ids = set(jen_map.keys())
    live_ids = set(live_map.keys())

    for sid in sorted(jen_ids - live_ids):
        info = jen_map[sid]
        name = info.get("name") or f"Subnet {sid}"
        cidr = info.get("cidr") or "unknown CIDR"
        issues.append({
            "type": "missing_in_kea",
            "family": family,
            "subnet_id": sid,
            "jen_name": name,
            "jen_cidr": info.get("cidr", ""),
            "message": (
                f"Jen has subnet {sid} ('{name}', {cidr}) configured, but "
                f"Kea's live config has no subnet with that id."
            ),
        })

    for sid in sorted(live_ids - jen_ids):
        cidr = live_map[sid]
        issues.append({
            "type": "unknown_to_jen",
            "family": family,
            "subnet_id": sid,
            "kea_cidr": cidr,
            "message": (
                f"Kea's live config has subnet {sid} ({cidr}) that Jen has "
                f"no name for — it will show as 'Subnet {sid}' anywhere Jen "
                f"displays it, and can't be selected by name in filters, "
                f"alerts, or API key scoping."
            ),
        })

    for sid in sorted(jen_ids & live_ids):
        jen_cidr = jen_map[sid].get("cidr", "")
        kea_cidr = live_map[sid]
        if jen_cidr and kea_cidr and jen_cidr != kea_cidr:
            name = jen_map[sid].get("name") or f"Subnet {sid}"
            issues.append({
                "type": "cidr_mismatch",
                "family": family,
                "subnet_id": sid,
                "jen_name": name,
                "jen_cidr": jen_cidr,
                "kea_cidr": kea_cidr,
                "message": (
                    f"Jen calls subnet {sid} '{name}' ({jen_cidr}), but "
                    f"Kea's live config says subnet {sid} is actually "
                    f"{kea_cidr}. Any subnet filter, alert, or API key "
                    f"scoped to '{name}' is now silently affecting the "
                    f"wrong network."
                ),
            })

    return issues


def fetch_live_subnet_map(family: str = "v4", server: dict = None) -> dict:
    """
    Fetch {subnet_id: cidr} from Kea's live config-get for the given
    address family. Returns an empty dict on ANY failure (Kea
    unreachable, malformed response, missing keys, etc.) — callers
    must treat an empty live_map as "couldn't check right now", not
    "Kea genuinely has zero subnets", since a real Kea deployment
    always has at least one subnet if it's serving DHCP at all.
    """
    try:
        if family == "v6":
            from jen.services.kea6 import kea6_command
            result = kea6_command("config-get", server=server)
            dhcp_key, subnet_key = "Dhcp6", "subnet6"
        else:
            from jen.services.kea import kea_command
            result = kea_command("config-get", server=server)
            dhcp_key, subnet_key = "Dhcp4", "subnet4"
        if result.get("result") != 0:
            return {}
        cfg = result["arguments"][dhcp_key]
        live = {}
        for s in cfg.get(subnet_key, []):
            live[s["id"]] = s.get("subnet", "")
        return live
    except Exception as e:
        logger.error(f"fetch_live_subnet_map({family}) error: {e}")
        return {}


def check_config_drift() -> list:
    """
    Full drift check: compares Jen's SUBNET_MAP against Kea's live v4
    config, and — if IPv6 is enabled and Jen has any v6 subnets
    configured — SUBNET6_MAP against Kea's live v6 config. Returns a
    combined list of issues (v4 + v6), same shape as
    detect_subnet_drift(). Safe to call even when Kea is unreachable:
    if a family's live data can't be fetched, that family is silently
    skipped rather than reported as wholesale drift (an empty live_map
    would otherwise look identical to "Jen has subnets Kea doesn't").
    """
    from jen import extensions

    issues = []

    live_v4 = fetch_live_subnet_map("v4")
    if live_v4:
        issues.extend(detect_subnet_drift(extensions.SUBNET_MAP, live_v4, "v4"))

    try:
        from jen.services.kea6 import is_ipv6_enabled
        if is_ipv6_enabled() and extensions.SUBNET6_MAP:
            live_v6 = fetch_live_subnet_map("v6")
            if live_v6:
                issues.extend(detect_subnet_drift(extensions.SUBNET6_MAP, live_v6, "v6"))
    except Exception as e:
        logger.error(f"check_config_drift v6 check error: {e}")

    return issues


def issue_key(issue: dict) -> str:
    """Stable, unique key for one drift issue — used to track which
    issues are already known (so alerts fire once on detection and
    once on resolution, not every single poll cycle they persist)."""
    return f"{issue['family']}:{issue['type']}:{issue['subnet_id']}"
