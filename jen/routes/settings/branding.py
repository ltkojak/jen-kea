"""
jen/routes/settings/branding.py
─────────────────────────────
Custom icons, favicon, nav logo, nav colour.
"""

import logging
import os
import re

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.user as __user
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required

logger = logging.getLogger(__name__)


@bp.route("/settings/upload-favicon", methods=["POST"])
@login_required
@_admin_required
def upload_favicon():
    favicon_file = request.files.get("favicon")
    if not favicon_file or not favicon_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("settings.settings"))
    if not favicon_file.filename.lower().endswith((".ico", ".png")):
        flash("Favicon must be a .ico or .png file.", "error")
        return redirect(url_for("settings.settings"))
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)
    try:
        favicon_file.save(extensions.FAVICON_PATH)
        flash("Favicon updated.", "success")
    except Exception as e:
        logger.error(f"Error saving favicon: {e}")
        flash("Error saving favicon. Check server logs for details.", "error")
    return redirect(url_for("settings.settings"))


@bp.route("/settings/remove-favicon", methods=["POST"])
@login_required
@_admin_required
def remove_favicon():
    if os.path.exists(extensions.FAVICON_PATH):
        os.remove(extensions.FAVICON_PATH)
    flash("Favicon removed.", "success")
    return redirect(url_for("settings.settings"))


@bp.route("/settings/icons")
@login_required
@_admin_required
def settings_icons():
    """Custom brand icon management page."""
    bundled = []
    for f in sorted(os.listdir(extensions.ICONS_BUNDLED_DIR)):
        if f.endswith(".svg"):
            name = f.replace(".svg", "")
            custom_override = os.path.exists(f"{extensions.ICONS_CUSTOM_DIR}/{f}")
            bundled.append({"name": name, "file": f, "custom_override": custom_override})
    custom = []
    for f in sorted(os.listdir(extensions.ICONS_CUSTOM_DIR)):
        if f.endswith(".svg"):
            custom.append({"name": f.replace(".svg", ""), "file": f})
    return render_template("settings_icons.html", bundled=bundled, custom=custom)


@bp.route("/settings/icons/upload", methods=["POST"])
@login_required
@_admin_required
def upload_custom_icon():
    svg_file = request.files.get("icon")
    icon_name = request.form.get("icon_name", "").strip().lower()
    if not svg_file or not icon_name:
        flash("Icon file and name are required.", "error")
        return redirect(url_for("settings.settings_icons"))
    if not icon_name.replace("-", "").replace("_", "").isalnum():
        flash("Icon name must be alphanumeric (hyphens/underscores allowed).", "error")
        return redirect(url_for("settings.settings_icons"))
    if not svg_file.filename.endswith(".svg"):
        flash("Only SVG files are accepted.", "error")
        return redirect(url_for("settings.settings_icons"))
    svg_file.seek(0, 2)
    size = svg_file.tell()
    svg_file.seek(0)
    if size > 100 * 1024:
        flash("SVG file must be under 100KB.", "error")
        return redirect(url_for("settings.settings_icons"))
    os.makedirs(extensions.ICONS_CUSTOM_DIR, exist_ok=True)
    dest = f"{extensions.ICONS_CUSTOM_DIR}/{icon_name}.svg"
    svg_file.save(dest)
    # Update MANUFACTURER_ICON_MAP if name matches a known manufacturer
    __user.audit("UPLOAD_ICON", "settings", f"Custom icon '{icon_name}.svg' uploaded by {current_user.username}")
    flash(f"Icon '{icon_name}.svg' uploaded. It will be used for any manufacturer mapped to '{icon_name}'.", "success")
    return redirect(url_for("settings.settings_icons"))


@bp.route("/settings/icons/delete/<name>", methods=["POST"])
@login_required
@_admin_required
def delete_custom_icon(name):
    # Same validation as upload_custom_icon — Flask's default <name>
    # converter already rejects any segment containing "/" (encoded or
    # not), so this isn't reachable as a traversal today, but the check
    # belongs here regardless in case the route ever changes to <path:name>.
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        flash("Invalid icon name.", "error")
        return redirect(url_for("settings.settings_icons"))
    path = f"{extensions.ICONS_CUSTOM_DIR}/{name}.svg"
    if os.path.exists(path):
        os.remove(path)
        __user.audit("DELETE_ICON", "settings", f"Custom icon '{name}.svg' deleted by {current_user.username}")
        flash(f"Custom icon '{name}.svg' removed.", "success")
    else:
        flash("Icon not found.", "error")
    return redirect(url_for("settings.settings_icons"))


@bp.route("/settings/upload-nav-logo", methods=["POST"])
@login_required
@_admin_required
def upload_nav_logo():
    logo_file = request.files.get("logo")
    if not logo_file or not logo_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("settings.settings_system"))
    ext = logo_file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "svg", "jpg", "jpeg", "webp"):
        flash("Logo must be PNG, SVG, JPG, or WebP.", "error")
        return redirect(url_for("settings.settings_system"))
    logo_file.seek(0, 2)
    size = logo_file.tell()
    logo_file.seek(0)
    if size > 200 * 1024:
        flash("Logo file must be under 200KB.", "error")
        return redirect(url_for("settings.settings_system"))
    # Remove any existing logo files
    for old_ext in ("png", "svg", "jpg", "jpeg", "webp"):
        old = f"{extensions.NAV_LOGO_PATH}.{old_ext}"
        if os.path.exists(old):
            os.remove(old)
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)
    try:
        logo_file.save(f"{extensions.NAV_LOGO_PATH}.{ext}")
        __user.audit("BRANDING", "settings", f"Nav logo uploaded by {current_user.username}")
        flash("Nav logo updated.", "success")
    except Exception as e:
        logger.error(f"Error saving nav logo: {e}")
        flash("Error saving logo. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/remove-nav-logo", methods=["POST"])
@login_required
@_admin_required
def remove_nav_logo():
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        f = f"{extensions.NAV_LOGO_PATH}.{ext}"
        if os.path.exists(f):
            os.remove(f)
    __user.audit("BRANDING", "settings", f"Nav logo removed by {current_user.username}")
    flash("Nav logo removed.", "success")
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/save-nav-color", methods=["POST"])
@login_required
@_admin_required
def save_nav_color():
    # Accept value from either the color picker or the text field
    color = request.form.get("nav_color_hex", "").strip() or request.form.get("nav_color", "").strip()
    # Validate — must be empty or a valid hex color
    if color and not re.match(r"^#[0-9a-fA-F]{3,6}$", color):
        flash("Invalid color value. Use a hex code like #1a1a2a.", "error")
        return redirect(url_for("settings.settings_system"))
    __user.set_global_setting("branding_nav_color", color)
    __user.audit("BRANDING", "settings", f"Nav color set to '{color}' by {current_user.username}")
    flash("Nav bar color updated." if color else "Nav bar color reset to default.", "success")
    return redirect(url_for("settings.settings_system"))
