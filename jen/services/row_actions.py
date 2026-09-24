"""
jen/services/row_actions.py
────────────────────────────
v5.57.0 (Q73) — register_row_action(), the plugin-API v3 hook that adds a
menu item to the lease/reservation/device row action-menus
(templates/_lease_rows.html, _reservation_row.html, _device_rows.html)
without those templates knowing anything about the plugin that added it.
Registered once per plugin at load time (inside register(app)); rendered
fresh on every row via row_actions_for(), a Jinja global
(jen/__init__.py) the three partials call directly.

`roles` is enforced here (the menu never shows an action a viewer
couldn't use) — the plugin's own route enforces it again, since a menu
item hidden client-side is not access control.
"""

import logging
from urllib.parse import quote

logger = logging.getLogger(__name__)

SURFACES = ("lease", "reservation", "device")

_ACTIONS: list[dict] = []  # registration order


def register_row_action(
    plugin_id: str,
    surface: str,
    *,
    label: str,
    icon: str,
    href: str,
    method: str = "GET",
    roles=("admin", "superadmin"),
    confirm: str | None = None,
    when=None,
) -> None:
    """`href` is a format string using {mac}/{ip}/{subnet_id}/{hostname} —
    each is url-encoded when the action is rendered for a real row.
    `method="POST"` renders as a form (with csrf_token) instead of a
    plain link. `when(row) -> bool`, if given, is called per row; a
    raising when() hides the action for that row rather than breaking
    the menu. Re-registering the same (plugin_id, surface, label)
    replaces the earlier entry, so a plugin reload never duplicates."""
    if surface not in SURFACES:
        raise ValueError(f"surface must be one of {SURFACES}, got {surface!r}")
    global _ACTIONS
    _ACTIONS = [
        a for a in _ACTIONS if not (a["plugin_id"] == plugin_id and a["surface"] == surface and a["label"] == label)
    ]
    _ACTIONS.append(
        {
            "plugin_id": plugin_id,
            "surface": surface,
            "label": label,
            "icon": icon,
            "href": href,
            "method": method,
            "roles": tuple(roles),
            "confirm": confirm,
            "when": when,
        }
    )


def registered_row_actions(surface: str | None = None) -> list[dict]:
    if surface is None:
        return list(_ACTIONS)
    return [a for a in _ACTIONS if a["surface"] == surface]


def row_actions_for(surface: str, row: dict, role: str) -> list[dict]:
    """Actions to render for one row: [{label, icon, href, method,
    confirm}], role-filtered and with placeholders substituted. `href`
    substitutes url-encoded values (it's a URL); `confirm` (v5.61.0,
    Q78 — the first caller that needed it) substitutes the SAME
    fields raw, since it's a confirmation sentence a person reads, not
    a URL — "Send a wake packet to aa:bb:cc:dd:ee:ff?", never a
    %-encoded MAC."""
    out = []
    raw_fields = {
        "mac": str(row.get("mac", "")),
        "ip": str(row.get("ip", "")),
        "subnet_id": str(row.get("subnet_id", "")),
        "hostname": str(row.get("hostname", "")),
    }
    for a in registered_row_actions(surface):
        if role not in a["roles"]:
            continue
        if a["when"] is not None:
            try:
                if not a["when"](row):
                    continue
            except Exception as e:
                logger.error(f"row action when() for {a['plugin_id']!r}/{a['label']!r} raised: {e}")
                continue
        try:
            href = a["href"].format(**{k: quote(v, safe="") for k, v in raw_fields.items()})
        except Exception as e:
            logger.error(f"row action href format for {a['plugin_id']!r}/{a['label']!r} raised: {e}")
            continue
        confirm = a["confirm"]
        if confirm is not None:
            try:
                confirm = confirm.format(**raw_fields)
            except Exception as e:
                logger.error(f"row action confirm format for {a['plugin_id']!r}/{a['label']!r} raised: {e}")
                continue
        out.append(
            {
                "plugin_id": a["plugin_id"],
                "label": a["label"],
                "icon": a["icon"],
                "href": href,
                "method": a["method"],
                "confirm": confirm,
            }
        )
    return out
