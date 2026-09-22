"""
jen/services/dashboard_prefs.py
────────────────────────────────
v5.54.0 (Q61) — the dashboard's arrangement preferences: which panels show, in
what order and width, and the subnet panel's own order/pin/hide. Pure — no
Flask, no DB — so it's testable directly and so `jen/routes/dashboard.py`'s
save and get routes share one validated shape instead of trusting the client.

Shape (v2): {"v": 2, "panels": [{"id": "totals", "w": "full"}, …],
"subnets": {"order": [10, 30], "pinned": [10], "hidden": []}, "compact": false}.
A v1 value (the plain list of widget ids the dashboard stored through 5.53.x)
upgrades to v2 panels of width "full" in that order; an empty or unreadable
value falls back to DEFAULT_PANELS. `validate()` is what both routes call —
it upgrades, then drops anything not in the catalog and any subnet id the
caller cannot access, so a subnet-restricted account's stored prefs can never
reveal (or keep referencing) a subnet it has lost access to.
"""

from __future__ import annotations

WIDTHS = ("full", "half", "third")

# label: shown in the Customize panel's checklist. default_w: the width a
# newly-enabled panel starts at (a user can widen/narrow it in Arrange mode).
WIDGET_CATALOG = {
    "subnet_stats": {"label": "Subnet Statistics", "default_w": "full"},
    "totals": {"label": "Total Summary", "default_w": "full"},
    "lease_history_chart": {"label": "Utilization History (7 days)", "default_w": "full"},
    "lease_sparklines": {"label": "Lease Sparklines per Subnet (30 days)", "default_w": "full"},
    "top_devices": {"label": "Top Active Devices (30 days)", "default_w": "half"},
    "recent_leases": {"label": "Recently Issued Leases", "default_w": "full"},
    "server_status": {"label": "Server Status", "default_w": "half"},
    "alert_summary": {"label": "Alert Summary", "default_w": "half"},
    # v5.54.0 (Q61) catalog additions — each backed by jen/services/dashboard_catalog.py.
    "forecast": {"label": "Pool Exhaustion Forecast", "default_w": "half"},
    "packet_health": {"label": "Packet Health", "default_w": "half"},
    "readiness": {"label": "Kea 3.2 Readiness", "default_w": "third"},
    "events_feed": {"label": "Recent Events", "default_w": "half"},
    "ha_state": {"label": "HA State", "default_w": "third"},
    "ddns_errors": {"label": "DDNS Errors", "default_w": "third"},
    "getting_started": {"label": "Getting Started", "default_w": "third"},
}
VALID_WIDGETS = frozenset(WIDGET_CATALOG)

DEFAULT_PANELS = [
    {"id": "subnet_stats", "w": "full"},
    {"id": "totals", "w": "full"},
    {"id": "recent_leases", "w": "full"},
    {"id": "server_status", "w": "half"},
]


def _as_int_list(value) -> list:
    out = []
    for v in value or []:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def upgrade(raw) -> dict:
    """Read whatever is stored (a v1 list, a v2 dict, or nothing readable) and
    return a v2-shaped dict. Never raises — an unrecognised shape falls back
    to DEFAULT_PANELS, same as an empty dashboard_prefs row always has."""
    if isinstance(raw, dict) and raw.get("v") == 2:
        subnets = raw.get("subnets") if isinstance(raw.get("subnets"), dict) else {}
        panels = raw.get("panels") if isinstance(raw.get("panels"), list) else []
        return {
            "v": 2,
            "panels": [dict(p) for p in panels if isinstance(p, dict)],
            "subnets": {
                "order": _as_int_list(subnets.get("order")),
                "pinned": _as_int_list(subnets.get("pinned")),
                "hidden": _as_int_list(subnets.get("hidden")),
            },
            "compact": bool(raw.get("compact")),
        }
    if isinstance(raw, list):
        # v1: a plain list of widget ids, in the order they were shown, always full width.
        return {
            "v": 2,
            "panels": [{"id": w, "w": "full"} for w in raw if isinstance(w, str)],
            "subnets": {"order": [], "pinned": [], "hidden": []},
            "compact": False,
        }
    return {
        "v": 2,
        "panels": [dict(p) for p in DEFAULT_PANELS],
        "subnets": {"order": [], "pinned": [], "hidden": []},
        "compact": False,
    }


def validate(raw, accessible_subnet_ids) -> dict:
    """`upgrade()` plus the trust boundary: unknown widget ids and duplicate
    entries are dropped, an invalid width falls back to that widget's
    default, and every subnet id is checked against `accessible_subnet_ids`
    (a hidden/pinned/ordered id the caller cannot access is dropped, not
    just hidden from view — it is never written back either, so it can't
    accumulate in a stored value across a subnet-scope change)."""
    prefs = upgrade(raw)
    seen: set[str] = set()
    panels = []
    for p in prefs["panels"]:
        wid = p.get("id")
        if wid not in VALID_WIDGETS or wid in seen:
            continue
        seen.add(wid)
        w = p.get("w")
        if w not in WIDTHS:
            w = WIDGET_CATALOG[wid]["default_w"]
        panels.append({"id": wid, "w": w})
    if not panels:
        panels = [dict(p) for p in DEFAULT_PANELS]

    accessible = set(accessible_subnet_ids)

    def _clean(ids):
        out, dup = [], set()
        for i in ids:
            if i in accessible and i not in dup:
                dup.add(i)
                out.append(i)
        return out

    return {
        "v": 2,
        "panels": panels,
        "subnets": {
            "order": _clean(prefs["subnets"]["order"]),
            "pinned": _clean(prefs["subnets"]["pinned"]),
            "hidden": _clean(prefs["subnets"]["hidden"]),
        },
        "compact": prefs["compact"],
    }


def ordered_subnet_ids(kea_order_ids, subnets_prefs) -> list:
    """Final subnet-card order for rendering: ids named in `order` first (in
    that order, and only if still present in `kea_order_ids`), then every
    other present id appended in Kea's own order, then `pinned` ids pulled
    to the front of that result (stable — pinned ids keep their relative
    order, same for everyone else)."""
    kea_order_ids = list(kea_order_ids)
    present = set(kea_order_ids)
    ordered = [i for i in subnets_prefs.get("order", []) if i in present]
    ordered += [i for i in kea_order_ids if i not in ordered]
    pinned = [i for i in subnets_prefs.get("pinned", []) if i in ordered]
    pinned_set = set(pinned)
    return pinned + [i for i in ordered if i not in pinned_set]


def visible_subnet_ids(ordered_ids, subnets_prefs) -> list:
    """`ordered_subnet_ids()`'s result with `hidden` ids removed — hiding a
    subnet only affects the dashboard card; every other page still shows it."""
    hidden = set(subnets_prefs.get("hidden", []))
    return [i for i in ordered_ids if i not in hidden]
