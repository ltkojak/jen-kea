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

from flask import Blueprint, flash, jsonify, redirect, render_template, url_for
from flask_login import login_required

from jen.models import user as __user
from jen.services import plugins as __plugins
from jen.services.access import superadmin_required as _superadmin_required

bp = Blueprint("plugins", __name__)


# ── Plugins page ──────────────────────────────────────────────────────────────


@bp.route("/settings/plugins")
@login_required
@_superadmin_required
def plugins_page():
    # v5.28.0 (Q24, A9) — apply any root-run install/remove result that
    # landed since the last time anyone looked, BEFORE discover_plugins()
    # renders the current on-disk state, so this page never shows a
    # plugin as installed-but-not-enabled or removed-but-still-listed
    # just because nobody happened to have the poller running when the
    # result came in.
    for entry in __plugins.consume_plugin_results():
        flash(entry["detail"], "success" if entry["ok"] else "error")

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
            p["registry_version"] and _parse_version(p["registry_version"]) > _parse_version(p["version"])
        )
        p["changelog_url"] = reg.get("changelog_url", "")

    # Annotate registry entries with install/update status
    for entry in registry:
        inst = installed_map.get(entry["id"])
        entry["installed"] = inst is not None
        entry["update_available"] = bool(
            inst and _parse_version(entry.get("version", "")) > _parse_version(inst.get("version", ""))
        )
        entry["version_ok"] = __plugins.jen_version_meets(entry.get("requires_jen", "0.0.0"))

    return render_template(
        "plugins.html",
        installed=installed,
        registry=registry,
        fetch_error=fetch_error,
        is_systemd_host=__plugins.is_systemd_host(),
    )


# ── Install ───────────────────────────────────────────────────────────────────


@bp.route("/settings/plugins/install/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def install_plugin(plugin_id):
    # Validate plugin_id is alphanumeric/hyphen — no path traversal
    if not __plugins.valid_plugin_id(plugin_id):
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
    if not ok:
        flash(msg, "error")
        return redirect(url_for("plugins.plugins_page"))

    # v5.28.0 (Q24, A9) — a "deferred" install (systemd host, marker
    # still pending) hasn't actually happened yet: don't touch the DB
    # row, restart_pending, or the completion audit until
    # consume_plugin_results() confirms it. Docker/dev (and the rare
    # case where the root side finished between install_plugin()
    # returning and this check) fall through to the old in-process
    # behavior below.
    if __plugins.is_systemd_host() and __plugins.request_is_pending(plugin_id, "install"):
        __user.audit("PLUGIN_INSTALL_REQUESTED", plugin_id, f"Requested {entry.get('name')} v{entry.get('version')}")
        flash(msg, "success")
        return redirect(url_for("plugins.plugins_page", plugin_install=plugin_id))

    __plugins.record_plugin_row(entry)
    __user.set_global_setting("restart_pending", "true")
    __user.audit("PLUGIN_INSTALL", plugin_id, f"Installed {entry.get('name')} v{entry.get('version')}")
    flash(msg, "success")
    return redirect(url_for("plugins.plugins_page"))


@bp.route("/settings/plugins/update/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def update_plugin(plugin_id):
    """Update an installed plugin to the latest registry version."""
    if not __plugins.valid_plugin_id(plugin_id):
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
    if not ok:
        flash(msg, "error")
        return redirect(url_for("plugins.plugins_page"))

    if __plugins.is_systemd_host() and __plugins.request_is_pending(plugin_id, "install"):
        __user.audit("PLUGIN_UPDATE_REQUESTED", plugin_id, f"Requested {entry.get('name')} v{entry.get('version')}")
        flash(msg, "success")
        return redirect(url_for("plugins.plugins_page", plugin_install=plugin_id))

    __plugins.record_plugin_row(entry)
    __user.set_global_setting("restart_pending", "true")
    __user.audit("PLUGIN_UPDATE", plugin_id, f"Updated {entry.get('name')} to v{entry.get('version')}")
    flash(msg, "success")
    return redirect(url_for("plugins.plugins_page"))


# ── Enable / Disable ──────────────────────────────────────────────────────────


@bp.route("/settings/plugins/enable/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def enable_plugin(plugin_id):
    if not __plugins.valid_plugin_id(plugin_id):
        flash("Invalid plugin ID.", "error")
        return redirect(url_for("plugins.plugins_page"))
    __plugins.enable_plugin(plugin_id)
    __user.set_global_setting("restart_pending", "true")
    __user.audit("PLUGIN_ENABLE", plugin_id, "Plugin enabled")
    flash(f"Plugin '{plugin_id}' enabled. Restart Jen to activate.", "success")
    return redirect(url_for("plugins.plugins_page"))


@bp.route("/settings/plugins/disable/<plugin_id>", methods=["POST"])
@login_required
@_superadmin_required
def disable_plugin(plugin_id):
    if not __plugins.valid_plugin_id(plugin_id):
        flash("Invalid plugin ID.", "error")
        return redirect(url_for("plugins.plugins_page"))
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
    if not __plugins.valid_plugin_id(plugin_id):
        flash("Invalid plugin ID.", "error")
        return redirect(url_for("plugins.plugins_page"))
    ok, msg = __plugins.uninstall_plugin(plugin_id)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("plugins.plugins_page"))

    # v5.28.0 (Q24, A9) — a deferred removal (root-owned plugin, marker
    # still pending) hasn't actually removed anything yet; the DB row
    # and completion audit wait for consume_plugin_results() to confirm
    # it. A legacy writable uninstall (or Docker/dev) removes in-process
    # and is confirmed immediately, same as before.
    if __plugins.is_systemd_host() and __plugins.request_is_pending(plugin_id, "remove"):
        __user.audit("PLUGIN_UNINSTALL_REQUESTED", plugin_id, "Removal requested")
        flash(msg, "success")
        return redirect(url_for("plugins.plugins_page", plugin_install=plugin_id))

    __plugins.remove_plugin_row(plugin_id)
    __user.audit("PLUGIN_UNINSTALL", plugin_id, "Plugin uninstalled")
    flash(msg, "success")
    return redirect(url_for("plugins.plugins_page"))


# ── Install status polling (v5.27.0, Q23) ──────────────────────────────────────


@bp.route("/settings/plugins/install-status/<plugin_id>")
@login_required
@_superadmin_required
def install_status(plugin_id):
    """Polled by the plugins page after a root-owned install/remove is
    requested — jen-plugin-install.service's own ActiveState/SubState
    plus this plugin's one-line result, if the unit has already
    finished processing it. Mirrors settings/updates.py's
    update_status() route: a read-only systemctl query needs no sudo
    (rule 8 only applies to a command that changes something).

    v5.28.0 (Q24, A9) — "result" calls consume_plugin_results(), which
    both reads it and applies it to Jen's own state (DB row, enable
    marker, restart_pending, audit) — a GET with side effects, but a
    superadmin-only, idempotent one that plugins_page() would apply
    anyway on the next render. `result` is "ok" or the raw error
    string, matching the exact shape the page's poller already checks
    (`s.result === 'ok'`); the friendlier detail text is what
    plugins_page() flashes, not what this route returns. A call for
    plugin B's id can consume and apply a DIFFERENT plugin A's result
    that happened to be sitting there too — harmless, since applying it
    is idempotent and A's own page render would have done the same."""
    if not __plugins.valid_plugin_id(plugin_id):
        return jsonify({"error": "invalid plugin id"}), 400
    status = __plugins.plugin_install_unit_status()
    entry = next((r for r in __plugins.consume_plugin_results() if r["id"] == plugin_id), None)
    status["result"] = ("ok" if entry["ok"] else entry["detail"]) if entry else None
    return jsonify(status)


# ── Registry refresh (AJAX) ───────────────────────────────────────────────────


@bp.route("/api/plugins/registry")
@login_required
@_superadmin_required
def api_registry():
    entries, err = __plugins.fetch_registry()
    installed_ids = {p["id"] for p in __plugins.discover_plugins()}
    for e in entries:
        e["installed"] = e["id"] in installed_ids
        e["version_ok"] = __plugins.jen_version_meets(e.get("requires_jen", "0.0.0"))
    return jsonify({"plugins": entries, "error": err})
