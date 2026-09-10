"""
jen/routes/health.py
────────────────────
v5.12.0 — the Health Center: `/health-center` runs jen/services/health.py's
read-only check list and shows one row per check with a fix link.
Viewer-visible (it's read-only). `/health-center/data` is the same run in
two representations — JSON for scripts, or `?partial=1` for the HTMX
auto-refresh swap.

Deliberately NOT `/api/v1/health` — that path is the unauthenticated
updater probe (jen/routes/api.py).
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user

import jen.services.health as __health
from jen.services.access import viewer_or_above as _viewer_or_above

logger = logging.getLogger(__name__)
bp = Blueprint("health", __name__)


def _run():
    """Run the checks scoped to what the current user may see, and return
    everything the page/partial/JSON need."""
    checks = __health.run_checks({"subnet_filter": current_user.can_access_subnet})
    return {
        "checks": checks,
        "grouped": __health.group_checks(checks),
        "summary": __health.summarise(checks),
        "checked_at": datetime.now(timezone.utc),
    }


@bp.route("/health-center")
@_viewer_or_above
def health_center():
    return render_template("health_center.html", **_run())


@bp.route("/health-center/data")
@_viewer_or_above
def health_center_data():
    ctx = _run()
    if request.args.get("partial") == "1":
        return render_template("_health_checks.html", **ctx)
    return jsonify(
        {
            "checked_at": ctx["checked_at"].isoformat(),
            "summary": ctx["summary"],
            "checks": [c.as_dict() for c in ctx["checks"]],
        }
    )
