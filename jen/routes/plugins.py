"""
jen/routes/plugins.py
─────────────────────
Settings → Plugins routes.
Browse the registry, install, enable/disable, and uninstall plugins.
SuperAdmin-only (v4.4.2): installing/enabling a plugin runs arbitrary
Python (plugin.py's register(app)) with the full privileges of the Jen
process — DB credentials, sudoers-permitted commands, everything. That's
a much bigger blast radius than a subnet-restricted admin was ever meant
to have, so this follows the same rule as database.py.
"""
import json
import logging

from flask import (Blueprint, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from jen.models import db as __db
from jen.models import user as __user
from jen.services.access import superadmin_required as _superadmin_required
from jen.services import plugins as __plugins

logger = logging.getLogger(__name__)
bp = Blueprint("plugins", __name__)


# ── Plugins page ──────────────────────────────────────────────────────────────

@bp.route("/settings/plugins")
@login_required
@_superadmin_required
def plugins_page():
    installed = __plugins.discover_plugins()
    installed_map = {p["id"]: p for p in installed}

    # Fetch registry (non-blocking — show empty list on failure)
    registry, fetch_error = __plugins.fetch_registry()

    # Build a lookup of registry versions for update checks
    registry_map = {e["id"]: e for e in registry}

    # Annotate installed plugins with update availability and changelog URL
    from jen.services.plugins import _parse_version
    for p in installed:
        reg = registry_map.get(p["id"], {})
        p["registry_version"] = reg.get("version", "")
        p["update_available"] = bool(
            p["registry_version"] and
            _parse_version(p["registry_version"]) > _parse_version(p["version"])
        )
        p["changelog_url"] = reg.get("changelog_url", "")

    # Annotate registry entries with install/update status
    for entry in registry:
        inst = installed_map.get(entry["id"])
        entry["installed"]      = inst is not None
        entry["update_available"] = bool(
            inst and _parse_version(entry.get("version","")) > _parse_version(inst.get("version",""))
        )
        entry["version_ok"]     = __plugins.jen_version_meets(
            entry.get("requires_jen", "0.0.0")
        )

    return render_template("plugins.html",
                           installed=installed,
                           registry=registry,
                           fetch_error=fetch_error)


# ── Install ───────────────────────────────────────────────────────────────────

@bp.route("/settings/plugins/install/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def install_plugin(plugin_id):
    # Validate plugin_id is alphanumeric/hyphen — no path traversal
    import re
    if not re.match(r'^[a-z0-9\-]{1,64}$', plugin_id):
        flash("Invalid plugin ID.", "error")
        return redirect(url_for("plugins.plugins_page"))

    registry, err = __plugins.fetch_registry()
    if err:
        flash(f"Could not fetch registry: {err}", "error")
        return redirect(url_for("plugins.plugins_page"))

    entry = next((e for e in registry if e["id"] == plugin_id), None)
    if not entry:
        flash(f"Plugin '{plugin_id}' not found in registry.", "error")
        return redirect(url_for("plugins.plugins_page"))

    ok, msg = __plugins.install_plugin(plugin_id, entry)
    if ok:
        # Record in plugins DB table
        _record_plugin(entry)
        __user.set_global_setting("restart_pending", "true")
        __user.audit("PLUGIN_INSTALL", plugin_id,
                     f"Installed {entry.get('name')} v{entry.get('version')}")
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("plugins.plugins_page"))


@bp.route("/settings/plugins/update/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def update_plugin(plugin_id):
    """Update an installed plugin to the latest registry version."""
    import re
    if not re.match(r'^[a-z0-9\-]{1,64}$', plugin_id):
        flash("Invalid plugin ID.", "error")
        return redirect(url_for("plugins.plugins_page"))

    registry, err = __plugins.fetch_registry()
    if err:
        flash(f"Could not fetch registry: {err}", "error")
        return redirect(url_for("plugins.plugins_page"))

    entry = next((e for e in registry if e["id"] == plugin_id), None)
    if not entry:
        flash(f"Plugin '{plugin_id}' not found in registry.", "error")
        return redirect(url_for("plugins.plugins_page"))

    ok, msg = __plugins.install_plugin(plugin_id, entry)
    if ok:
        _record_plugin(entry)
        __user.set_global_setting("restart_pending", "true")
        __user.audit("PLUGIN_UPDATE", plugin_id,
                     f"Updated {entry.get('name')} to v{entry.get('version')}")
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("plugins.plugins_page"))


# ── Enable / Disable ──────────────────────────────────────────────────────────

@bp.route("/settings/plugins/enable/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def enable_plugin(plugin_id):
    __plugins.enable_plugin(plugin_id)
    __user.set_global_setting("restart_pending", "true")
    __user.audit("PLUGIN_ENABLE", plugin_id, "Plugin enabled")
    flash(f"Plugin '{plugin_id}' enabled. Restart Jen to activate.", "success")
    return redirect(url_for("plugins.plugins_page"))


@bp.route("/settings/plugins/disable/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def disable_plugin(plugin_id):
    __plugins.disable_plugin(plugin_id)
    __user.set_global_setting("restart_pending", "true")
    __user.audit("PLUGIN_DISABLE", plugin_id, "Plugin disabled")
    flash(f"Plugin '{plugin_id}' disabled. Restart Jen to deactivate.", "success")
    return redirect(url_for("plugins.plugins_page"))


# ── Uninstall ─────────────────────────────────────────────────────────────────

@bp.route("/settings/plugins/uninstall/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def uninstall_plugin(plugin_id):
    ok, msg = __plugins.uninstall_plugin(plugin_id)
    if ok:
        _remove_plugin_record(plugin_id)
        __user.audit("PLUGIN_UNINSTALL", plugin_id, "Plugin uninstalled")
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("plugins.plugins_page"))


# ── Registry refresh (AJAX) ───────────────────────────────────────────────────

@bp.route("/api/plugins/registry")
@login_required
@_superadmin_required
def api_registry():
    entries, err = __plugins.fetch_registry()
    installed_ids = {p["id"] for p in __plugins.discover_plugins()}
    for e in entries:
        e["installed"] = e["id"] in installed_ids
        e["version_ok"] = __plugins.jen_version_meets(
            e.get("requires_jen", "0.0.0")
        )
    return jsonify({"plugins": entries, "error": err})


# ── DB helpers ────────────────────────────────────────────────────────────────

def _record_plugin(entry: dict):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO plugins (id, name, version, description, author, requires_jen, enabled)
                    VALUES (%s, %s, %s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE
                        name=VALUES(name), version=VALUES(version),
                        description=VALUES(description), enabled=1
                """, (entry.get("id"), entry.get("name"), entry.get("version"),
                      entry.get("description"), entry.get("author"),
                      entry.get("requires_jen")))
            db.commit()
    except Exception as e:
        logger.error(f"Failed to record plugin in DB: {e}")


def _remove_plugin_record(plugin_id: str):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", (plugin_id,))
            db.commit()
    except Exception as e:
        logger.error(f"Failed to remove plugin record from DB: {e}")
