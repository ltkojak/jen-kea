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

# ── Background work ──────────────────────────────────────────────────────────
from jen.services.background import periodic_jobs, register_periodic, unregister_periodic  # noqa: E402

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


def jen_version() -> str:
    from jen import JEN_VERSION

    return JEN_VERSION


__all__ = [
    "PLUGIN_API_VERSION",
    "admin_required",
    "api_key_required",
    "assert_subnet_access",
    "audit",
    "classify_address",
    "classify_device",
    "decrypt_secret",
    "dhcp4_config",
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
