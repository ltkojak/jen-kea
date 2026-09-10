"""
jen/routes/content.py
─────────────────────
v5.13.0 — serves user-uploaded content out of `extensions.CONTENT_DIR`
(`/var/lib/jen`), which is outside the application tree. Replaces the old
custom-icon and nav-logo URLs that lived under the static route.

  GET /content/icons/<name>.svg        — an uploaded brand icon
  GET /content/branding/<filename>     — nav_logo.{png,svg,jpg,jpeg,webp}

Public (no auth): these are page assets referenced from `<img>` tags, same
as anything under `/static`. `send_from_directory` handles traversal; the
name checks below mirror branding.py's upload-time validation.
"""

import logging

from flask import Blueprint, abort, send_from_directory

from jen import extensions

logger = logging.getLogger(__name__)
bp = Blueprint("content", __name__)

_CACHE = {"Cache-Control": "public, max-age=3600"}
_BRANDING_ALLOWED = {f"nav_logo.{ext}" for ext in ("png", "svg", "jpg", "jpeg", "webp")}


def _valid_icon_name(name: str) -> bool:
    # same rule as branding.upload_custom_icon: alnum + '-' + '_'
    return bool(name) and name.replace("-", "").replace("_", "").isalnum()


@bp.route("/content/icons/<name>.svg")
def content_icon(name):
    if not _valid_icon_name(name):
        abort(404)
    resp = send_from_directory(extensions.CONTENT_ICONS_DIR, f"{name}.svg")
    resp.headers.update(_CACHE)
    return resp


@bp.route("/content/branding/<filename>")
def content_branding(filename):
    if filename not in _BRANDING_ALLOWED:
        abort(404)
    resp = send_from_directory(extensions.CONTENT_BRANDING_DIR, filename)
    resp.headers.update(_CACHE)
    return resp
