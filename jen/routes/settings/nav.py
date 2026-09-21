"""
jen/routes/settings/nav.py
──────────────────────────
v5.9.0 — the navigation is defined ONCE here and rendered by base.html:
the top links, the mobile drawer, the per-section tab strips, the
Settings landing grid and the in-group sub-tabs all read from these
tables. Before this every strip was a hand-maintained list of endpoint
names repeated three times in base.html (desktop links, drawer, strip);
adding a page meant editing all three, and the lists quietly drifted.

Item icons are Lucide sprite names (templates/_icon_sprite.html; `nav_icon()` also passes a plugin's own emoji through as text).

Pure data plus tiny helpers — nothing here imports Flask or the app, so
the factory's context processor can import it without a cycle.

Active-state matching is by endpoint *prefix* ("leases." matches every
route in the leases blueprint) or exact endpoint name, so a new route in
an existing blueprint lights up its section without touching this file.
"""

ADMIN_ROLES = ("admin", "superadmin")

# ── Top-level navigation ─────────────────────────────────────────────────────
# Same list for every role; `roles` hides an item entirely. Superadmin-only
# *content* is gated per card on the page, not by hiding the nav — that's
# what made the old nav differ between admin and superadmin.
TOP_NAV = [
    {
        "id": "dashboard",
        "label": "Dashboard",
        "icon": "layout-dashboard",
        "url": "/",
        "match": ("dashboard.dashboard",),
    },
    {
        "id": "management",
        "label": "Management",
        "icon": "list",
        "url": "/leases",
        "match": ("leases.", "reservations.", "devices.", "reports."),
    },
    {
        "id": "network",
        "label": "Network",
        "icon": "network",
        "url": "/subnets",
        "match": ("subnets.", "servers.", "ddns.", "health.", "timeline."),
    },
    {"id": "settings", "label": "Settings", "icon": "settings", "url": "/settings", "roles": ADMIN_ROLES, "match": ()},
    {"id": "about", "label": "About", "icon": "info", "url": "/about", "match": ("users.about",)},
]

# ── Section tab strips (Management / Network) ────────────────────────────────
SECTION_STRIPS = {
    "management": [
        {"icon": "list", "label": "Leases", "url": "/leases", "match": ("leases.",)},
        {"icon": "pin", "label": "Reservations", "url": "/reservations", "match": ("reservations.",)},
        {"icon": "monitor-smartphone", "label": "Devices", "url": "/devices", "match": ("devices.",)},
        {"icon": "chart-line", "label": "Reports", "url": "/reports", "match": ("reports.",)},
    ],
    "network": [
        {"icon": "network", "label": "Subnets", "url": "/subnets", "match": ("subnets.",)},
        {"icon": "server", "label": "Servers", "url": "/servers", "match": ("servers.",)},
        {"icon": "link", "label": "DDNS", "url": "/ddns", "match": ("ddns.",)},
        {"icon": "stethoscope", "label": "Health", "url": "/health-center", "match": ("health.",)},
        {"icon": "compass", "label": "Explain", "url": "/tools/explain", "match": ("explain.",)},
        {
            "icon": "activity",
            "label": "Doctor",
            "url": "/tools/doctor",
            "match": ("doctor.",),
            "requires_all_subnets": True,
        },
        {"icon": "clock", "label": "Timeline", "url": "/timeline", "match": ("timeline.",)},
        # plugin nav items with section == "network" are appended at render time
    ],
}

# ── Settings groups (the strip, the landing grid, and "which group am I in") ─
# ≤5 cards each by design; `blurb` is the landing-tile subtitle.
SETTINGS_GROUPS = [
    {
        "id": "kea",
        "label": "Kea",
        "icon": "plug",
        "url": "/settings/kea",
        "blurb": "Control Agent, servers & HA, SSH, packages, config drift",
        "match": ("settings.settings_kea", "settings.author_kea_config", "settings.settings_infrastructure"),
    },
    {
        "id": "databases",
        "label": "Databases",
        "icon": "database",
        "url": "/settings/databases",
        "blurb": "Jen & Kea connections, export, import, backups, migrate",
        "match": ("database.",),
    },
    {
        "id": "security",
        "label": "Access & Security",
        "icon": "lock",
        "url": "/settings/security",
        "blurb": "Users, API keys, MFA policy, sessions, rate limiting, SSL",
        "match": ("settings.settings_security", "users.users", "api.api_keys", "api.api_docs"),
    },
    {
        "id": "alerts",
        "label": "Alerts & Integrations",
        "icon": "bell",
        "url": "/settings/alerts",
        "blurb": "Channels, templates, thresholds, DDNS/DNS provider, Prometheus",
        "match": ("settings.settings_alerts",),
    },
    {
        "id": "appearance",
        "label": "Appearance",
        "icon": "palette",
        "url": "/settings/appearance",
        "blurb": "Logo, nav color, favicon, brand icons",
        "match": ("settings.settings_appearance", "settings.settings_icons"),
    },
    {
        "id": "system",
        "label": "System",
        "icon": "cog",
        "url": "/settings/system",
        "blurb": "Jen & plugin updates, ports, restart, retention",
        "match": ("settings.settings_system", "plugins."),
    },
    {
        "id": "logs",
        "label": "Logs",
        "icon": "scroll-text",
        "url": "/settings/logs",
        "blurb": "Audit log and alert delivery log",
        "match": ("users.audit_log",),
    },
]

# ── Sub-tabs inside a group (rendered by the page itself, not base.html) ────
SUBTABS = {
    "security": [
        {"id": "policies", "label": "Policies", "url": "/settings/security"},
        {"id": "users", "label": "Users", "url": "/settings/users", "roles": ("superadmin",)},
        {"id": "api-keys", "label": "API Keys", "url": "/settings/api-keys"},
        {"id": "api-docs", "label": "API Docs", "url": "/settings/api-docs"},
    ],
    "databases": [
        {"id": "connections", "label": "Connections", "url": "/settings/databases?tab=connections"},
        {"id": "export", "label": "Export", "url": "/settings/databases?tab=export", "roles": ("superadmin",)},
        {"id": "import", "label": "Import", "url": "/settings/databases?tab=import", "roles": ("superadmin",)},
        {"id": "backups", "label": "Backups", "url": "/settings/databases?tab=backups", "roles": ("superadmin",)},
        {"id": "schedule", "label": "Schedule", "url": "/settings/databases?tab=schedule", "roles": ("superadmin",)},
        {"id": "migrate", "label": "Migrate", "url": "/settings/databases?tab=migrate", "roles": ("superadmin",)},
        {"id": "recovery", "label": "Recovery", "url": "/settings/databases?tab=recovery", "roles": ("superadmin",)},
    ],
    "logs": [
        {"id": "audit", "label": "Audit Log", "url": "/settings/logs?tab=audit"},
        {"id": "alerts", "label": "Alert Log", "url": "/settings/logs?tab=alerts"},
    ],
    "system": [
        {"id": "system", "label": "Updates & System", "url": "/settings/system"},
        {"id": "plugins", "label": "Plugin Manager", "url": "/settings/plugins", "roles": ("superadmin",)},
    ],
}


def _matches(endpoint, patterns):
    if not endpoint:
        return False
    for p in patterns:
        if p.endswith(".") and endpoint.startswith(p):
            return True
        if endpoint == p:
            return True
    return False


def _allowed(item, role):
    roles = item.get("roles")
    return not roles or role in roles


def settings_group_for(endpoint):
    for g in SETTINGS_GROUPS:
        if _matches(endpoint, g["match"]):
            return g
    return None


def all_settings_match():
    """Every pattern that means "you're somewhere under Settings"."""
    pats = ["settings.settings"]
    for g in SETTINGS_GROUPS:
        pats.extend(g["match"])
    return tuple(pats)


def nav_context(endpoint, role, plugin_nav_items=None, all_subnets=True):
    """
    Everything base.html needs for one request. Pure — tested directly in
    tests/test_settings_ia.py.
    """
    plugin_nav_items = plugin_nav_items or []
    # Items flagged requires_all_subnets render the whole Kea config; a
    # subnet-restricted user is not shown them (the route refuses anyway).
    section_strips = {
        k: [t for t in v if all_subnets or not t.get("requires_all_subnets")] for k, v in SECTION_STRIPS.items()
    }
    group = settings_group_for(endpoint)
    in_settings = endpoint == "settings.settings" or group is not None

    top = []
    for item in TOP_NAV:
        if not _allowed(item, role):
            continue
        if item["id"] == "settings":
            active = in_settings
        elif item["id"] == "network":
            active = _matches(endpoint, item["match"]) or any(p.get("endpoint") == endpoint for p in plugin_nav_items)
        else:
            active = _matches(endpoint, item["match"])
        top.append({**item, "active": active})

    strip = []
    if in_settings:
        for g in SETTINGS_GROUPS:
            if _allowed(g, role):
                strip.append({**g, "active": group is not None and g["id"] == group["id"]})
    else:
        for section, tabs in section_strips.items():
            if any(_matches(endpoint, t["match"]) for t in tabs) or (
                section == "network" and any(p.get("endpoint") == endpoint for p in plugin_nav_items)
            ):
                for t in tabs:
                    strip.append({**t, "active": _matches(endpoint, t["match"])})
                if section == "network":
                    for p in plugin_nav_items:
                        if p.get("section") == "network":
                            strip.append(
                                {
                                    "icon": p.get("icon", ""),
                                    "label": p.get("label", ""),
                                    "endpoint": p.get("endpoint"),
                                    "active": p.get("endpoint") == endpoint,
                                }
                            )
                break

    return {
        "top": top,
        "strip": strip,
        "in_settings": in_settings,
        "group": group,
        "settings_groups": [g for g in SETTINGS_GROUPS if _allowed(g, role)],
        "subtabs": {k: [t for t in v if _allowed(t, role)] for k, v in SUBTABS.items()},
    }
