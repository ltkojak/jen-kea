"""
jen/routes/setup.py
────────────────────
v5.67.0 (Q115) — GET/POST /setup/*, the six-step guided first-hour
wizard: connect, what Jen found, the Kea host helper, baseline,
recovery point, investigate. Superadmin only — every step writes
something only a superadmin should (Kea credentials, the subnet map,
SSH/the helper, a recovery passphrase) — and thin: every real decision
is jen/services/setup_wizard.py calling the same services Settings
already uses. No new `sudo` string exists anywhere behind this file.
"""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

import jen.models.user as __user
import jen.services.setup_wizard as __setup
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("setup", __name__, url_prefix="/setup")

# v5.67.0 (Q115) — only the steps THIS commit has a route for; see the
# comment on setup_wizard.STEPS. Step 2 of this Q adds the remaining
# four entries once those routes exist.
_STEP_URL = {
    "connect": "setup.setup_connect",
    "found": "setup.setup_found",
}


def _progress():
    """{"state": {...}, "steps": [...]} — fed to every step template so
    the six-dot progress indicator is the same partial everywhere."""
    state = __setup.get_state()
    return {
        "state": state,
        "steps": __setup.STEPS,
        "current": __setup.current_step(),
    }


@bp.route("/")
@login_required
@_superadmin_required
def setup_home():
    return redirect(url_for(_STEP_URL[__setup.current_step()]))


# ── step 1: connect ──────────────────────────────────────────────────────────


@bp.route("/connect", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_connect():
    from jen import extensions

    if request.method == "GET":
        return render_template(
            "setup_connect.html",
            progress=_progress(),
            api_url=extensions.KEA_API_URL,
            api_user=extensions.KEA_API_USER,
            kea_db_host=extensions.KEA_DB_HOST,
            kea_db_user=extensions.KEA_DB_USER,
            kea_db_name=extensions.KEA_DB_NAME,
        )

    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "")
    kea_db_host = request.form.get("kea_db_host", "").strip()
    kea_db_user = request.form.get("kea_db_user", "").strip()
    kea_db_pass = request.form.get("kea_db_pass", "")
    kea_db_name = request.form.get("kea_db_name", "").strip() or "kea"

    from jen.services import auth as __auth

    retry_ctx = {
        "api_url": api_url,
        "api_user": api_user,
        "kea_db_host": kea_db_host,
        "kea_db_user": kea_db_user,
        "kea_db_name": kea_db_name,
    }
    if not api_url or not __auth.valid_api_url(api_url, require_port=False):
        flash("Enter a valid Kea API URL (http:// or https://).", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if not kea_db_host or not kea_db_user:
        flash("Kea's database host and username are required.", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)

    kea_result = __setup.test_kea_connection(api_url, api_user, api_pass)
    db_ok, db_info = __setup.test_kea_db(kea_db_host, kea_db_user, kea_db_pass, kea_db_name)

    if not kea_result["ok"] or not db_ok:
        if not kea_result["ok"]:
            last = kea_result["attempts"][-1] if kea_result["attempts"] else {}
            flash(f"Could not reach Kea's API: {last.get('error', 'no response')}.", "error")
        if not db_ok:
            flash(f"Could not reach Kea's database: {db_info}.", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)

    __setup.save_connection(
        api_url=kea_result["url"],
        api_user=api_user,
        api_pass=api_pass,
        mode=kea_result["mode"],
        kea_db_host=kea_db_host,
        kea_db_user=kea_db_user,
        kea_db_pass=kea_db_pass,
        kea_db_name=kea_db_name,
    )
    __user.audit("SETUP_WIZARD", "connect", f"url={kea_result['url']} mode={kea_result['mode']}")
    flash(f"Connected — Kea {kea_result['version'] or 'unknown version'}, {kea_result['mode']} mode.", "success")
    __setup.set_step("connect", "done")
    return redirect(url_for("setup.setup_found"))


# ── step 2: what Jen found ──────────────────────────────────────────────────


@bp.route("/found", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_found():
    found = __setup.discover()

    if request.method == "GET":
        return render_template(
            "setup_found.html",
            progress=_progress(),
            found=found,
            hook_loss=__setup.HOOK_LOSS,
            hook_labels=__setup.HOOK_LABELS,
        )

    # v5.67.0 (Q115) — step 1 of this Q ships only steps 1-2; step 2 of
    # this Q adds setup.setup_helper and this becomes the real hand-off.
    # Getting started already links a superadmin back into whatever
    # step is still open, so landing there meanwhile is never a dead end.
    next_url = url_for("onboarding.getting_started")

    action = request.form.get("action", "")
    if action == "skip":
        __setup.set_step("found", "skipped")
        return redirect(next_url)

    subnets = {}
    for sid, info in found["proposed_subnets"].items():
        name = request.form.get(f"name_{sid}", info["name"]).strip() or info["name"]
        subnets[sid] = {"name": name, "cidr": info["cidr"]}
    if subnets:
        __setup.save_subnets(subnets)
    __user.audit("SETUP_WIZARD", "found", f"subnets={len(subnets)}")
    __setup.set_step("found", "done")
    return redirect(next_url)


@bp.route("/skip/<step>", methods=["POST"])
@login_required
@_superadmin_required
def setup_skip(step):
    """A remembered skip for any step — shown back on Getting started."""
    if step not in __setup.STEPS:
        return jsonify({"ok": False}), 404
    __setup.set_step(step, "skipped")
    next_step = __setup.current_step()
    return redirect(url_for(_STEP_URL.get(next_step, "setup.setup_home")))
