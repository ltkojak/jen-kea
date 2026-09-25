"""
jen/plugin_api.py
─────────────────
v5.34.0 (Q33) — the ONE import surface a plugin may use.

Both bundled plugins used to reach into `jen.models.db`,
`jen.services.access`, `jen.services.alerts`, … directly. That worked
while the maintainer owned every plugin, but it made every internal
rename a silent plugin break. This module is a thin, versioned
re-export of exactly the things plugins have needed so far — nothing
new lives behind it, and nothing here does work at import time.

Rules (also in plugins/README.md):

* A plugin imports from `jen.plugin_api` and nowhere else inside `jen`.
  `tests/test_plugin_api.py` enforces that for the bundled copies.
* `PLUGIN_API_VERSION` moves when a name is removed or a signature
  changes — a MAJOR for Jen. Adding a name is MINOR and doesn't move it.
* A manifest may declare `"plugin_api": N`; Jen refuses to load a
  plugin whose N is newer than what it offers (a clear chip on the
  Plugins page, not an ImportError at boot).
"""

from flask_login import current_user as _current_user

from jen import extensions as _extensions

# ── Version ──────────────────────────────────────────────────────────────────
PLUGIN_API_VERSION = 3

# ── Database ─────────────────────────────────────────────────────────────────
# Context managers (preferred): `with jen_db() as db, db.cursor() as cur: …`
# — pooled connection, auto commit/rollback/return. The raw `get_*_db()`
# forms remain for plugins written before v5.34.0; they must close() what
# they open.
from jen.models.db import get_jen_db, get_kea_db, jen_db, kea6_db, kea_db  # noqa: E402

# ── Audit log, global settings ───────────────────────────────────────────────
from jen.models.user import audit, get_global_setting, set_global_setting  # noqa: E402

# ── Access control ───────────────────────────────────────────────────────────
from jen.services.access import (  # noqa: E402
    admin_required,
    assert_subnet_access,
    diagnostic_surface,
    get_accessible_subnet_map,
    is_admin_or_above,
    is_superadmin,
    superadmin_required,
    viewer_or_above,
)

# ── Alerts (register_alert_type added v5.57.0, Q73) ──────────────────────────
from jen.services.alerts import register_alert_type, send_alert  # noqa: E402

# ── API-key auth for plugin routes (v5.57.0, Q73) ────────────────────────────
from jen.services.api_auth import api_key_required, filter_subnet_ids  # noqa: E402
from jen.services.api_auth import key_subnet_ids as _key_subnet_ids  # noqa: E402

# ── Background work ──────────────────────────────────────────────────────────
# PERIODIC_MIN_MINUTES added v5.60.1 (Q89) — register_periodic() already
# enforces it and raises below it; exporting the number itself lets a plugin
# read the floor instead of guessing (Host Watchdog 1.0.0 guessed wrong).
from jen.services.background import (  # noqa: E402
    PERIODIC_MIN_MINUTES,
    periodic_jobs,
    register_periodic,
    unregister_periodic,
)

# ── Secrets (v5.57.0, Q73) ────────────────────────────────────────────────────
from jen.services.crypto import decrypt_secret, encrypt_secret  # noqa: E402

# ── CSV formula guard ────────────────────────────────────────────────────────
from jen.services.csv_safe import safe_cell, safe_row  # noqa: E402

# ── Events (v5.42.0, Q43; emit() added v5.57.0, Q73) ─────────────────────────
from jen.services.events import KINDS as event_kinds  # noqa: E402
from jen.services.events import emit, subscribe, unsubscribe  # noqa: E402

# ── Device fingerprinting ────────────────────────────────────────────────────
from jen.services.fingerprint import classify_device  # noqa: E402

# ── Plugin system introspection ──────────────────────────────────────────────
from jen.services.plugins import discover_plugins as installed_plugins  # noqa: E402
from jen.services.plugins import is_systemd_host  # noqa: E402

# ── Row actions (v5.57.0, Q73) ────────────────────────────────────────────────
from jen.services.row_actions import register_row_action  # noqa: E402

# ── Search providers (v5.57.0, Q73) ──────────────────────────────────────────
from jen.services.search_providers import register_search_provider  # noqa: E402

# ── What Jen knows about a subnet ────────────────────────────────────────────
from jen.services.subnet_context import classify_address, dhcp4_config, in_pool, subnet_context  # noqa: E402


def subnet_map() -> dict:
    """{subnet_id: {"name", "cidr"}} for every IPv4 subnet Jen knows,
    unfiltered — use get_accessible_subnet_map() for the caller's view."""
    return _extensions.SUBNET_MAP


def can_access_subnet(subnet_id, *, allow_unattributed: bool = False) -> bool:
    """May the SESSION user see something in `subnet_id`? (v5.65.2, Q91 i.)

    The one place a plugin asks that question, so "no attributable subnet" means
    the same thing everywhere: `None` is False for a subnet-restricted user unless
    the caller passes `allow_unattributed=True` (say why in a comment at the call
    site). An unrestricted user is always True. Core's rule (docs/ARCHITECTURE.md
    §2) is the same: an object with no subnet is for unrestricted callers only. Four
    plugins used to write `if sid is not None and sid not in allowed: deny`, which
    made None mean ALLOW."""
    if not _current_user.is_authenticated:
        return False
    if _current_user.all_subnets:
        return True
    if subnet_id is None:
        return bool(allow_unattributed)
    try:
        return bool(_current_user.can_access_subnet(int(subnet_id)))
    except (TypeError, ValueError):
        return False


def api_key_can_access_subnet(key, subnet_id, *, allow_unattributed: bool = False) -> bool:
    """`can_access_subnet` for an API key row (`flask.g.api_key`): True for an
    unrestricted key, False for `None` on a scoped key unless `allow_unattributed`,
    and a malformed scope fails closed (it reads as "no subnets")."""
    scope = _key_subnet_ids(key)
    if scope is None:
        return True
    if subnet_id is None:
        return bool(allow_unattributed)
    try:
        return int(subnet_id) in scope
    except (TypeError, ValueError):
        return False


def jen_version() -> str:
    from jen import JEN_VERSION

    return JEN_VERSION


__all__ = [
    "PERIODIC_MIN_MINUTES",
    "PLUGIN_API_VERSION",
    "admin_required",
    "api_key_can_access_subnet",
    "api_key_required",
    "assert_subnet_access",
    "audit",
    "can_access_subnet",
    "classify_address",
    "classify_device",
    "decrypt_secret",
    "dhcp4_config",
    "diagnostic_surface",
    "emit",
    "encrypt_secret",
    "event_kinds",
    "filter_subnet_ids",
    "get_accessible_subnet_map",
    "get_global_setting",
    "get_jen_db",
    "get_kea_db",
    "in_pool",
    "installed_plugins",
    "is_admin_or_above",
    "is_superadmin",
    "is_systemd_host",
    "jen_db",
    "jen_version",
    "kea6_db",
    "kea_db",
    "periodic_jobs",
    "register_alert_type",
    "register_periodic",
    "register_row_action",
    "register_search_provider",
    "safe_cell",
    "safe_row",
    "send_alert",
    "set_global_setting",
    "subnet_context",
    "subnet_map",
    "subscribe",
    "superadmin_required",
    "unregister_periodic",
    "unsubscribe",
    "viewer_or_above",
]
