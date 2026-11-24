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
from jen import extensions
from jen.services.access import admin_required as _admin_required
from jen.services.access import diagnostic_surface

logger = logging.getLogger(__name__)
bp = Blueprint("doctor", __name__)

#: (Q251) the findings whose Fix link is to the Kea logging card of Settings - Kea (`config_doctor._check_logger_output`)
_KEA_LOGGING_CARD_FINDINGS = ("logger-no-file", "logger-pattern-no-timestamp")


@bp.route("/tools/doctor")
@login_required
@_admin_required
@diagnostic_surface(subject="client")
def doctor_page():
    # Renders the whole Kea config — including subnets a restricted admin
    # cannot otherwise see — so it needs unrestricted subnet access, the
    # same rule as config history (docs/ARCHITECTURE.md §2).
    if not current_user.all_subnets:
        flash("Doctor needs access to all subnets.", "error")
        return redirect(url_for("servers.servers"))

    result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
    cfg = (result.get("arguments") or {}).get("Dhcp4") if result.get("result") == 0 else None
    error = None if cfg is not None else (result.get("text") or "config-get failed")

    findings = []
    if cfg is not None:
        findings = __doctor.diagnose(
            cfg, __health._doctor_hosts(), ha_configs=__health._doctor_ha_configs(), jen_config=extensions.cfg
        )
    else:
        findings = __doctor.diagnose(None, jen_config=extensions.cfg)  # (CRED-003 reads Jen's own file, not Kea's)

    if current_user.role != "superadmin":
        # (Q251) the two logger findings send their reader to the Kea logging card of Settings - Kea, which is drawn for a superadmin only: an admin
        # keeps the finding's sentence (it says who can choose a file) and is handed no link to a card the page does not show them - the rule of Health's
        # "log file missing" row. `config_doctor` is pure and knows no role, so it is done here, where the findings meet a person.
        findings = [{**f, "fix_url": ""} if f["id"] in _KEA_LOGGING_CARD_FINDINGS else f for f in findings]

    counts = {"fail": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return render_template(
        "doctor.html", findings=findings, groups=__doctor.group_findings(findings), error=error, counts=counts
    )
