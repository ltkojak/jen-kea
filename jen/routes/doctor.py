"""
jen/routes/doctor.py
─────────────────────
v5.40.0 (Q41) — GET /tools/doctor: semantic checks on the live Kea
config (jen/services/config_doctor.py). Admin/superadmin only, and
deliberately unrestricted by subnet access — the whole config's shape
is what the page shows, the same way Settings → Kea is.
"""

import logging

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

import jen.services.config_doctor as __doctor
import jen.services.health as __health
import jen.services.kea as __kea
from jen.services.access import admin_required as _admin_required

logger = logging.getLogger(__name__)
bp = Blueprint("doctor", __name__)


@bp.route("/tools/doctor")
@login_required
@_admin_required
def doctor_page():
    # Renders the whole Kea config — including subnets a restricted admin
    # cannot otherwise see — so it needs unrestricted subnet access, the
    # same rule as config history (docs/ARCHITECTURE.md §2).
    if not current_user.all_subnets:
        flash("Doctor needs access to all subnets.", "error")
        return redirect(url_for("servers.servers"))

    result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
    cfg = result.get("arguments", {}).get("Dhcp4") if result.get("result") == 0 else None
    error = None if cfg is not None else (result.get("text") or "config-get failed")

    findings = []
    if cfg is not None:
        findings = __doctor.diagnose(cfg, __health._doctor_hosts(), ha_configs=__health._doctor_ha_configs())

    counts = {"fail": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return render_template(
        "doctor.html", findings=findings, groups=__doctor.group_findings(findings), error=error, counts=counts
    )
