"""
jen/routes/onboarding.py
─────────────────────────
v5.39.0 (Q39) — GET /getting-started: the first-hour checklist. Thin —
everything is computed by jen/services/onboarding.py. Admin or
superadmin can view; only a superadmin can dismiss the nav pill
(POST /getting-started/dismiss), since dismissing is a whole-install
setting, not a per-user preference.
"""

import logging

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.services.onboarding as __onboarding
from jen.services.access import admin_required as _admin_required
from jen.services.access import is_superadmin as _is_superadmin
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("onboarding", __name__)


@bp.route("/getting-started")
@login_required
@_admin_required
def getting_started():
    ctx = __onboarding.build_ctx(current_user, is_superadmin=_is_superadmin())
    summary = __onboarding.checklist(ctx)
    return render_template("getting_started.html", summary=summary, is_superadmin=_is_superadmin())


@bp.route("/getting-started/dismiss", methods=["POST"])
@login_required
@_superadmin_required
def dismiss():
    __onboarding.dismiss()
    return redirect(request.referrer or url_for("onboarding.getting_started"))
