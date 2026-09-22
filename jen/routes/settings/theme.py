"""
jen/routes/settings/theme.py
─────────────────────────────
v5.55.0 (Q63) — Settings -> Appearance -> Theme: the install default
preset, and the install's own validated custom palette.

Superadmin, not admin: unlike nav color/logo (cosmetic per-install
branding an admin can already touch), the install *default* theme
changes what every viewer sees who hasn't picked one for themselves, and
a custom palette is CSS that reaches every page unescaped once saved
(through render_css()'s |safe in base.html) — the same trust tier as
the config-mutating settings elsewhere in this blueprint.

Storage is the existing settings key/value table (jen/models/user.py) —
no migration. theme_default is a plain preset id string; theme_custom is
JSON: {"tokens": {...11 hex...}, "radius": int, "mono_ui": bool}, the
exact shape jen.services.theme.validate_palette() returns, so
jen/__init__.py's inject_theme context processor can json.loads() it and
hand it straight to render_css() without a second validation pass.
"""

import json
import logging

from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

import jen.models.user as __user
from jen.routes.settings import bp
from jen.services import theme as _theme
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)

_APPEARANCE_THEME = "settings.settings_appearance"


def _back():
    return redirect(url_for(_APPEARANCE_THEME) + "#app-theme")


@bp.route("/settings/theme/default", methods=["POST"])
@login_required
@_superadmin_required
def save_theme_default():
    theme_id = request.form.get("theme_default", "").strip()
    valid_ids = set(_theme.PRESET_IDS)
    if __user.get_global_setting("theme_custom", ""):
        valid_ids.add("custom")
    if theme_id not in valid_ids:
        flash("Unknown theme.", "error")
        return _back()
    __user.set_global_setting("theme_default", theme_id)
    __user.audit(
        "SAVE_THEME_DEFAULT", "settings", f"Install default theme set to '{theme_id}' by {current_user.username}"
    )
    flash("Install default theme updated.", "success")
    return _back()


@bp.route("/settings/theme/custom", methods=["POST"])
@login_required
@_superadmin_required
def save_theme_custom():
    result, errors = _theme.validate_palette(request.form)
    if errors:
        for e in errors:
            flash(e, "error")
        return _back()
    __user.set_global_setting("theme_custom", json.dumps(result))
    __user.audit("SAVE_THEME_CUSTOM", "settings", f"Custom theme palette saved by {current_user.username}")
    warnings = _theme.palette_warnings(result["tokens"])
    if warnings:
        for w in warnings:
            flash(w, "warning")
    else:
        flash("Custom theme palette saved.", "success")
    return _back()


@bp.route("/settings/theme/custom/remove", methods=["POST"])
@login_required
@_superadmin_required
def remove_theme_custom():
    __user.set_global_setting("theme_custom", "")
    # A theme_default of "custom" would otherwise point at nothing —
    # inject_theme() already falls back to dark for this, but fix the
    # stored value too so the Settings page's own select isn't stale.
    if __user.get_global_setting("theme_default", "dark") == "custom":
        __user.set_global_setting("theme_default", "dark")
    __user.audit("REMOVE_THEME_CUSTOM", "settings", f"Custom theme palette removed by {current_user.username}")
    flash("Custom theme palette removed.", "success")
    return _back()
