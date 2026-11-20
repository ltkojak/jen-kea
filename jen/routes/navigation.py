"""
jen/routes/navigation.py
────────────────────────
v7.2.0-beta.1 (Q243) - a person's own navigation: the Customize navigation page and
the pin button on the section strip. Every signed-in person has it, a viewer included:
what is stored is a list of shortcuts to pages the person can already open
(`jen/services/nav_prefs.py`), so there is no role to check beyond being signed in and
nothing here reads or writes anyone else's row.
"""

import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.routes.settings.nav as __nav
import jen.services.nav_prefs as __prefs
import jen.services.plugins as __plugins
from jen.routes.auth import _safe_next

logger = logging.getLogger(__name__)
bp = Blueprint("navigation", __name__)

NOT_SAVED = "The change was not saved. Try again."


def _offered():
    """`{"top": [destinations], "tabbar": [destinations]}` for the person asking: what each list may hold."""
    top, tabbar = __nav.pinnable(
        current_user.role,
        __plugins.get_nav_items(),
        all_subnets=bool(getattr(current_user, "all_subnets", True)),
    )
    return {"top": top, "tabbar": tabbar}


def _limit(place):
    return __nav.TOP_FAVORITES_MAX if place == "top" else __nav.TABBAR_SLOTS


def _edit(place, action, dest):
    """Apply one edit to one of the person's lists. True when it was stored; a refusal or a failed write is flashed and answers False."""
    offered = [d["id"] for d in _offered()[place]]
    current = __prefs.load(current_user.id)[place]
    new, refusal = __prefs.apply_edit(current, action, dest, offered, _limit(place), place)
    if refusal:
        flash(refusal, "error")
        return False
    if new == current:
        return True
    try:
        __prefs.save(current_user.id, place, new)
    except Exception as e:
        logger.error(f"could not save the navigation of user {current_user.id}: {type(e).__name__}")
        flash(NOT_SAVED, "error")
        return False
    return True


@bp.route("/navigation")
@login_required
def customize():
    offered = _offered()
    stored = __prefs.load(current_user.id)
    lists = {}
    for place in __prefs.PLACES:
        by_id = {d["id"]: d for d in offered[place]}
        chosen = [by_id[i] for i in dict.fromkeys(stored[place]) if i in by_id][: _limit(place)]
        chosen_ids = {d["id"] for d in chosen}
        lists[place] = {
            "chosen": chosen,
            "available": [d for d in offered[place] if d["id"] not in chosen_ids],
            "limit": _limit(place),
            # (Q244, BD2, BD11) what is stored and resolves to nothing today is counted, and Reset is offered for it: with every stored page gone the card
            # listed nothing and had no Reset, so the person could not clear a list from the page
            "stored": bool(stored[place]),
            "hidden": sum(1 for i in dict.fromkeys(stored[place]) if i not in by_id),
        }
    return render_template("navigation.html", lists=lists)


@bp.route("/navigation/edit", methods=["POST"])
@login_required
def edit():
    place = request.form.get("place", "")
    if place not in __prefs.PLACES:
        flash(__prefs.NOT_OFFERED, "error")
        return redirect(url_for("navigation.customize"))
    _edit(place, request.form.get("action", ""), request.form.get("dest", ""))
    return redirect(url_for("navigation.customize"))


@bp.route("/navigation/pin", methods=["POST"])
@login_required
def pin():
    """The section strip's button: add the page being shown to the top row, or take it out, and come back to that page."""
    action = "remove" if request.form.get("pinned") == "1" else "add"
    _edit("top", action, request.form.get("dest", ""))
    return redirect(_safe_next(request.form.get("next", "")) or url_for("navigation.customize"))
