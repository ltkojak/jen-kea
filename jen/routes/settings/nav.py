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
        # Q248 (addition 4): Saved searches is a detail page of Leases (the filter bar that saves them is there); it showed no strip and lit nothing
        {"icon": "list", "label": "Leases", "url": "/leases", "match": ("leases.", "search.saved_searches")},
        {"icon": "pin", "label": "Reservations", "url": "/reservations", "match": ("reservations.",)},
        {"icon": "monitor-smartphone", "label": "Devices", "url": "/devices", "match": ("devices.",)},
        {"icon": "chart-line", "label": "Reports", "url": "/reports", "match": ("reports.",)},
    ],
    "network": [
        {"icon": "network", "label": "Subnets", "url": "/subnets", "match": ("subnets.",)},
        {"icon": "server", "label": "Kea servers", "url": "/servers", "match": ("servers.",)},
        {"icon": "link", "label": "DDNS", "url": "/ddns", "match": ("ddns.",)},
        {"icon": "stethoscope", "label": "Health", "url": "/health-center", "match": ("health.",)},
        # Q248 (addition 4): Trace is a detail page of Investigate (the client page loads it as its own Trace tab, and Explain links to it)
        {"icon": "search", "label": "Investigate", "url": "/client", "match": ("client.", "trace.")},
        {"icon": "triangle-alert", "label": "Problems", "url": "/problems", "match": ("problems.",)},
        {"icon": "compass", "label": "Explain", "url": "/tools/explain", "match": ("explain.",)},
        {
            "icon": "activity",
            "label": "Doctor",
            "url": "/tools/doctor",
            "match": ("doctor.",),
            "requires_all_subnets": True,
            "roles": ADMIN_ROLES,  # the route is admin-only: a viewer was shown a link that bounced them
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
        "blurb": "Control Agent, servers & HA, SSH, DDNS (D2 and DNS provider), packages, config drift",
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
        "blurb": "Channels, templates, thresholds, Prometheus",
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
# Q248 (V38): a tab is listed for the roles its page's route lets in, so nobody is shown a tab that bounces them. API Docs is the one page of a
# group a viewer may open; with these rules a viewer's row there is that single tab, and a row of one tab is not drawn (_settings_subtabs.html).
SUBTABS = {
    "security": [
        {"id": "policies", "label": "Policies", "url": "/settings/security", "roles": ADMIN_ROLES},
        {"id": "users", "label": "Users", "url": "/settings/users", "roles": ("superadmin",)},
        {"id": "api-keys", "label": "API Keys", "url": "/settings/api-keys", "roles": ADMIN_ROLES},
        {"id": "api-docs", "label": "API Docs", "url": "/settings/api-docs"},
    ],
    "databases": [
        {
            "id": "connections",
            "label": "Connections",
            "url": "/settings/databases?tab=connections",
            "roles": ADMIN_ROLES,
        },
        {"id": "export", "label": "Export", "url": "/settings/databases?tab=export", "roles": ("superadmin",)},
        {"id": "import", "label": "Import", "url": "/settings/databases?tab=import", "roles": ("superadmin",)},
        {"id": "backups", "label": "Backups", "url": "/settings/databases?tab=backups", "roles": ("superadmin",)},
        {"id": "schedule", "label": "Schedule", "url": "/settings/databases?tab=schedule", "roles": ("superadmin",)},
        {"id": "migrate", "label": "Migrate", "url": "/settings/databases?tab=migrate", "roles": ("superadmin",)},
        {"id": "recovery", "label": "Recovery", "url": "/settings/databases?tab=recovery", "roles": ("superadmin",)},
    ],
    # Q249: both tabs are one route (`users.audit_log`), and it refuses an account that may not see every subnet before it reads the tab: the rows name subnets,
    # clients and servers. `requires_all_subnets` (the strips' own flag) hides a tab from such an account, and a group whose tabs are all hidden goes with them.
    "logs": [
        {
            "id": "audit",
            "label": "Audit Log",
            "url": "/settings/logs?tab=audit",
            "roles": ADMIN_ROLES,
            "requires_all_subnets": True,
        },
        {
            "id": "alerts",
            "label": "Alert Log",
            "url": "/settings/logs?tab=alerts",
            "roles": ADMIN_ROLES,
            "requires_all_subnets": True,
        },
    ],
    "system": [
        {"id": "system", "label": "Updates & System", "url": "/settings/system", "roles": ADMIN_ROLES},
        {"id": "plugins", "label": "Plugin Manager", "url": "/settings/plugins", "roles": ("superadmin",)},
    ],
}


#: v7.2.0-beta.1 (Q243) - a person's own navigation: at most this many favorites after the fixed top items, and this many slots in the phone's bottom bar (More is always there)
TOP_FAVORITES_MAX = 5
TABBAR_SLOTS = 4


def _plugin_strip(p):
    """v7.2.0-beta.5 (Q247, U2) - the section a plugin's page is shown under: the one its manifest names when that section has a strip (`management` or `network`), else
    Network, which is where every plugin page was shown before. Presence and Wake name `management`, and until this release their pages lit Network, showed the Network strip
    with no tab marked, and had no link anywhere in the desktop navigation."""
    section = p.get("section")
    return section if section in SECTION_STRIPS else "network"


def _plugin_owner(endpoint, plugin_nav_items):
    """Q248 (addition 4) - the plugin navigation item a page belongs to, or None. The item whose endpoint IS the page; else the first item of the same blueprint, so
    every page of a plugin (an IPAM subnet, a Discovery results page) is shown under the plugin's strip with the plugin's tab lit. They used to show no strip and
    light nothing: only the plugin's index matched. One owner at most, so a plugin that lists two pages never lights both."""
    if not endpoint:
        return None
    for p in plugin_nav_items:
        if p.get("endpoint") == endpoint:
            return p
    blueprint = endpoint.split(".", 1)[0]
    for p in plugin_nav_items:
        target = p.get("endpoint") or ""
        if "." in target and target.split(".", 1)[0] == blueprint:
            return p
    return None


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


def _tab_open(tab, role, all_subnets):
    """A sub-tab is listed for the roles its route lets in (Q248, V38) and, when its route needs every subnet, only for an account that has them (Q249)."""
    return (all_subnets or not tab.get("requires_all_subnets")) and _allowed(tab, role)


def _group_open(group, role, all_subnets):
    """A Settings group is listed (the strip, the landing tile, the More sheet, a favorite) unless every one of its tabs needs every subnet and the account does not
    have them (Q249): the Logs tile and tab sent a subnet-restricted admin to a page that sent them back."""
    if not _allowed(group, role):
        return False
    tabs = SUBTABS.get(group["id"])
    return all_subnets or not tabs or any(not t.get("requires_all_subnets") for t in tabs)


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


def _tabbar(endpoint, role, in_settings):
    """The phone's bottom tab bar (v5.51.0, Q58): Dashboard, Leases,
    Reservations, Settings, More. A viewer has no Settings page, so the
    fourth slot is Devices for them — the bar is always four destinations
    plus More. `more_active` lights More when the current page is none of
    the four, so the bar never shows "nowhere"."""
    tabs = [
        {"id": "dashboard", "label": "Dashboard", "icon": "layout-dashboard", "url": "/"},
        {"id": "leases", "label": "Leases", "icon": "list", "url": "/leases"},
        {"id": "reservations", "label": "Reservations", "icon": "pin", "url": "/reservations"},
    ]
    if role in ADMIN_ROLES:
        tabs.append({"id": "settings", "label": "Settings", "icon": "settings", "url": "/settings"})
    else:
        tabs.append({"id": "devices", "label": "Devices", "icon": "monitor-smartphone", "url": "/devices"})
    matches = {
        "dashboard": ("dashboard.dashboard",),
        "leases": ("leases.", "search.saved_searches"),  # the strip's own rule for the Leases tab (Q248, addition 4)
        "reservations": ("reservations.",),
        "devices": ("devices.",),
    }
    out = []
    for t in tabs:
        active = in_settings if t["id"] == "settings" else _matches(endpoint, matches[t["id"]])
        out.append({**t, "active": active})
    return out


def _sheet_groups(endpoint, role, section_strips, plugin_nav_items, all_subnets=True):
    """Every destination, grouped as the desktop nav is (Management / Network
    / Settings / Plugins / About), for the More sheet. Same role and
    subnet-scope filtering as the strips and the settings groups; plugin
    items carry `endpoint` instead of `url` (the template resolves it)."""
    groups = []

    def item(t, active):
        d = {"icon": t.get("icon", ""), "label": t.get("label", ""), "active": active}
        # `id` (v7.2.0-beta.1, Q243) is what a person's own navigation stores: the page's address, or `plugin:<endpoint>` for a plugin's page
        if t.get("url"):
            d["url"] = t["url"]
            d["id"] = t["url"]
        else:
            d["endpoint"] = t.get("endpoint")
            d["id"] = "plugin:" + str(t.get("endpoint"))
        return d

    groups.append(
        {
            "id": "management",
            "label": "Management",
            "items": [item(t, _matches(endpoint, t["match"])) for t in section_strips["management"]],
        }
    )
    network = [item(t, _matches(endpoint, t["match"])) for t in section_strips["network"]]
    plugins = []
    owner = _plugin_owner(endpoint, plugin_nav_items)
    for p in plugin_nav_items:
        it = item(p, p is owner)
        # a plugin is listed where its strip lists it (Q247, U2): the group of the section it names, or Plugins when it names none that has a strip
        if p.get("section") == "management":
            groups[0]["items"].append(it)
        else:
            (network if p.get("section") == "network" else plugins).append(it)
    groups.append({"id": "network", "label": "Network", "items": network})
    if role in ADMIN_ROLES:
        groups.append(
            {
                "id": "settings",
                "label": "Settings",
                "items": [
                    item(g, settings_group_for(endpoint) is not None and settings_group_for(endpoint)["id"] == g["id"])
                    for g in SETTINGS_GROUPS
                    if _group_open(g, role, all_subnets)
                ],
            }
        )
    if plugins:
        groups.append({"id": "plugins", "label": "Plugins", "items": plugins})
    groups.append(
        {
            "id": "about",
            "label": "Jen",
            "items": [item(t, _matches(endpoint, t["match"])) for t in TOP_NAV if t["id"] == "about"],
        }
    )
    return [g for g in groups if g["items"]]


def _destinations(endpoint, role, in_settings, sheet):
    """Every page a person can put in their own navigation, in the More sheet's order, each with a stable `id` (its address, or `plugin:<endpoint>`), its `group` label and whether
    it is the page being shown. The Dashboard comes first and, for the roles that have one, the Settings landing page second: the phone bar may hold either, and neither is in
    the sheet. The list is already filtered by role and subnet scope, because the sheet is: a page the person cannot open is not a destination."""
    out = [
        {
            "id": "/",
            "icon": "layout-dashboard",
            "label": "Dashboard",
            "url": "/",
            "group": "Jen",
            "active": _matches(endpoint, ("dashboard.dashboard",)),
        }
    ]
    if role in ADMIN_ROLES:
        out.append(
            {
                "id": "/settings",
                "icon": "settings",
                "label": "Settings",
                "url": "/settings",
                "group": "Settings",
                "active": in_settings,
            }
        )
    for g in sheet:
        for i in g["items"]:
            out.append({**i, "group": g["label"]})
    return out


#: the addresses the fixed top items already link to: none of them is offered as a top-row favorite (it would be the same link twice)
_FIXED_TOP_URLS = frozenset(t["url"] for t in TOP_NAV)


def _resolve(ids, by_id, limit, skip=()):
    """The stored ids that are destinations for THIS person now, in stored order, each once, at most `limit`. An id that no longer resolves (a plugin switched off, a role
    changed, a page that moved) is skipped and stays stored: it comes back when the page does."""
    out, seen = [], set()
    for i in ids or ():
        if i in seen or i in skip or i not in by_id:
            continue
        seen.add(i)
        out.append(by_id[i])
        if len(out) == limit:
            break
    return out


def pinnable(role, plugin_nav_items=None, all_subnets=True):
    """What the Customize navigation page offers this person: `(top, tabbar)`, two lists of destinations. Pure."""
    ctx = nav_context(None, role, plugin_nav_items, all_subnets)
    return [d for d in ctx["destinations"] if d["id"] not in _FIXED_TOP_URLS], list(ctx["destinations"])


def nav_context(endpoint, role, plugin_nav_items=None, all_subnets=True, prefs=None):
    """
    Everything base.html needs for one request. Pure — tested directly in
    tests/test_settings_ia.py. `prefs` (v7.2.0-beta.1, Q243) is the person's own
    navigation, `{"top": [ids], "tabbar": [ids]}`, or None for the defaults.
    """
    plugin_nav_items = plugin_nav_items or []
    prefs = prefs or {}
    # Items flagged requires_all_subnets render the whole Kea config; a
    # subnet-restricted user is not shown them (the route refuses anyway).
    section_strips = {
        k: [t for t in v if (all_subnets or not t.get("requires_all_subnets")) and _allowed(t, role)]
        for k, v in SECTION_STRIPS.items()
    }
    group = settings_group_for(endpoint)
    # Q248 (V25): a page is "in Settings" only for an account that has a Settings (the roles of the top item). The API documentation is in the Access & Security
    # group and opens for a viewer, who was shown the Settings strip - seven tabs that each refuse a viewer - and the "All settings" link above the page.
    may_open_settings = any(_allowed(t, role) for t in TOP_NAV if t["id"] == "settings")
    in_settings = may_open_settings and (endpoint == "settings.settings" or group is not None)
    # the plugin whose page this is (Q248, addition 4): any page of its blueprint, not only the one its navigation item names
    owner = _plugin_owner(endpoint, plugin_nav_items)

    top = []
    for item in TOP_NAV:
        if not _allowed(item, role):
            continue
        if item["id"] == "settings":
            active = in_settings
        else:
            # Q247 (U3): a section is lit for every page its own strip marks (Investigate, Problems, Explain and Doctor lit nothing: the top item kept a list of its own that
            # they were never added to), and for a plugin page shown under it (U2)
            active = (
                _matches(endpoint, item["match"])
                or any(_matches(endpoint, t["match"]) for t in SECTION_STRIPS.get(item["id"], ()))
                or (owner is not None and _plugin_strip(owner) == item["id"])
            )
        top.append({**item, "active": active})

    strip = []
    if in_settings:
        for g in SETTINGS_GROUPS:
            if _group_open(g, role, all_subnets):
                strip.append({**g, "active": group is not None and g["id"] == group["id"]})
    else:
        for section, tabs in section_strips.items():
            if any(_matches(endpoint, t["match"]) for t in tabs) or (
                owner is not None and _plugin_strip(owner) == section
            ):
                for t in tabs:
                    strip.append({**t, "active": _matches(endpoint, t["match"])})
                for p in plugin_nav_items:
                    if p.get("section") == section:
                        strip.append(
                            {
                                "icon": p.get("icon", ""),
                                "label": p.get("label", ""),
                                "endpoint": p.get("endpoint"),
                                "active": p is owner,
                            }
                        )
                break

    sheet = _sheet_groups(endpoint, role, section_strips, plugin_nav_items, all_subnets)
    destinations = _destinations(endpoint, role, in_settings, sheet)
    by_id = {d["id"]: d for d in destinations}
    favorites = _resolve(prefs.get("top"), by_id, TOP_FAVORITES_MAX, skip=_FIXED_TOP_URLS)
    # the phone bar is the person's own four when they chose any that still resolve, else the default four (never an empty bar)
    tabbar = _resolve(prefs.get("tabbar"), by_id, TABBAR_SLOTS) or _tabbar(endpoint, role, in_settings)
    # the pin button on the section strip acts on the page being shown, when that page can be a favorite
    current = next((d for d in destinations if d["active"] and d["id"] not in _FIXED_TOP_URLS), None)
    pin = None
    if current is not None and strip:
        pin = {
            "id": current["id"],
            "label": current["label"],
            "pinned": any(f["id"] == current["id"] for f in favorites),
        }
    if favorites:
        sheet = [{"id": "favorites", "label": "Favorites", "items": favorites}, *sheet]
    return {
        "top": top,
        "favorites": favorites,
        "pin": pin,
        "destinations": destinations,
        "tabbar": tabbar,
        "tabbar_more_active": not any(t["active"] for t in tabbar),
        "sheet": sheet,
        "strip": strip,
        "in_settings": in_settings,
        # v5.55.1 (Q64) — True on a group *landing* page: inside Settings, but
        # not matched by any group in SETTINGS_GROUPS (today only
        # settings.settings itself). base.html hides the section strip there
        # on a phone — the page already shows the same destinations as cards
        # below it, so the strip is a redundant, unlabeled duplicate. Derived
        # from the same group lookup every other decision here uses, not a
        # hardcoded endpoint string.
        "landing": in_settings and group is None,
        "group": group,
        "settings_groups": [g for g in SETTINGS_GROUPS if _group_open(g, role, all_subnets)],
        "subtabs": {k: [t for t in v if _tab_open(t, role, all_subnets)] for k, v in SUBTABS.items()},
    }
