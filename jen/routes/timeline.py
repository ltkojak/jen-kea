"""
jen/routes/timeline.py
────────────────────────
v5.42.0 (Q43) — GET /timeline?mac=…|?ip=…, one client's merged history
(jen.services.timeline.build_timeline). Thin: validate/normalize the
query, gate on the subject's subnet, render.
"""

import logging

from flask import Blueprint, flash, render_template, request
from flask_login import current_user, login_required

import jen.services.auth as __auth
from jen.services.access import diagnostic_surface, get_accessible_subnet_map
from jen.services.timeline import build_timeline

logger = logging.getLogger(__name__)
bp = Blueprint("timeline", __name__)

# v5.69.0-beta.2 (Q171 fixup, G7): a client the caller may not see and one no table knows are ONE sentence (RBAC-002) - on the page and in the Investigation tab
NO_MATCH = "No client matched that MAC or IP, or you don't have access to it."


@bp.route("/timeline")
@login_required
@diagnostic_surface(subject="client")
def timeline_page():
    raw_mac = (request.args.get("mac") or "").strip().lower()
    raw_ip = (request.args.get("ip") or "").strip()
    mac = raw_mac if raw_mac and __auth.valid_mac(raw_mac) else ""
    ip = raw_ip if raw_ip and __auth.valid_ip(raw_ip) else ""
    is_hx = request.headers.get("HX-Request") == "true"
    notes = []

    def say(message):
        """A page flashes the sentence; an htmx partial returns it in the partial (a flash queued by a partial is shown on the NEXT full page, about something else)."""
        if is_hx:
            notes.append(message)
        else:
            flash(message, "error")

    if raw_mac and not mac:
        say("That isn't a MAC address (expected aa:bb:cc:dd:ee:ff).")
    if raw_ip and not ip:
        say("That isn't an IP address.")

    result = None
    if mac or ip:
        accessible_v4 = None if current_user.all_subnets else set(get_accessible_subnet_map())
        result = build_timeline(mac=mac, ip=ip, accessible_v4_ids=accessible_v4)
        # Rows with no subnet_id (audit_log/alert_log matches, or an
        # events row that predates a subnet, or a genuinely subnet-less
        # client) are visible to an unrestricted user only — same rule
        # the design applies to the page as a whole below.
        if result["subnet_id"] is not None:
            if not current_user.can_access_subnet(result["subnet_id"]):
                say(NO_MATCH)
                result = None
        elif not current_user.all_subnets:
            say(NO_MATCH)
            result = None
        if result is not None and not current_user.all_subnets:
            # Mirrors the API: a restricted user sees only rows that carry a
            # subnet they can access. Subnet-less rows (audit_log/alert_log
            # matches, older events) are for unrestricted users only.
            result["rows"] = [
                r
                for r in result["rows"]
                if r["subnet_id"] is not None and current_user.can_access_subnet(r["subnet_id"])
            ]

    kinds = sorted({r["kind"] for r in result["rows"]}) if result else []

    # v5.63.0 (Q82) — the Investigation page's Timeline tab embeds this
    # exact result via htmx, same pattern as Trace's own HX-partial branch.
    if is_hx:
        if result is None:
            # the sentences are this module's own constants, never request text
            return "".join(f"<p>{n}</p>" for n in (notes or [NO_MATCH]))
        return "".join(f"<p>{n}</p>" for n in notes) + render_template(
            "_timeline_rows.html", result=result, kinds=kinds
        )
    return render_template(
        "timeline.html",
        mac=raw_mac,
        ip=raw_ip,
        result=result,
        kinds=kinds,
    )
