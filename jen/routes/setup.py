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
import os

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

import jen.models.user as __user
import jen.services.setup_wizard as __setup
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("setup", __name__, url_prefix="/setup")

_STEP_URL = {
    "connect": "setup.setup_connect",
    "found": "setup.setup_found",
    "helper": "setup.setup_helper",
    "baseline": "setup.setup_baseline",
    "recovery": "setup.setup_recovery",
    "investigate": "setup.setup_investigate",
}


def _progress():
    """{"state": {...}, "steps": [...]} — fed to every step template so
    the six-dot progress indicator is the same partial everywhere. Also
    the one place that starts the wizard's own elapsed-time clock, since
    every /setup page renders this."""
    __setup.mark_started()
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

    next_url = url_for("setup.setup_helper")

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


# ── step 3: the Kea host helper ──────────────────────────────────────────────


@bp.route("/helper", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_helper():
    from jen import extensions

    server = __setup.primary_server()
    has_key = os.path.isfile(extensions.SSH_KEY_PATH + ".pub")
    pub_key = ""
    if has_key:
        with open(extensions.SSH_KEY_PATH + ".pub") as f:
            pub_key = f.read().strip()

    if request.method == "GET":
        return render_template(
            "setup_helper.html",
            progress=_progress(),
            server=server,
            has_key=has_key,
            pub_key=pub_key,
            target_ready=__setup.ssh_target_ready(server),
            download_command=__setup.helper_download_command(),
        )

    action = request.form.get("action", "")
    if action == "skip":
        __setup.set_step("helper", "skipped")
        return redirect(url_for("setup.setup_baseline"))

    if action == "save_target":
        ok, err = __setup.save_ssh_target(request.form.get("ssh_host", ""), request.form.get("ssh_user", ""))
        flash(err if not ok else "SSH target saved.", "error" if not ok else "success")
        return redirect(url_for("setup.setup_helper"))

    if action == "test_ssh":
        result = __setup.test_ssh(server)
        flash(
            "SSH connection OK." if result["ok"] else f"SSH failed: {result['detail']}",
            "success" if result["ok"] else "error",
        )
        return redirect(url_for("setup.setup_helper"))

    if action == "install":
        result = __setup.install_helper_step(server)
        if result["ok"]:
            __user.audit("SETUP_WIZARD", "helper", f"installed v{result['version']}")
            flash(f"jen-kea-helper v{result['version']} is installed.", "success")
            __setup.set_step("helper", "done")
            return redirect(url_for("setup.setup_baseline"))
        flash(result["detail"] or "Helper install failed.", "error")
        return redirect(url_for("setup.setup_helper"))

    return redirect(url_for("setup.setup_helper"))


# ── step 4: baseline ─────────────────────────────────────────────────────────


@bp.route("/baseline", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_baseline():
    server = __setup.primary_server()

    if request.method == "GET":
        return render_template("setup_baseline.html", progress=_progress(), server=server)

    if request.form.get("action") == "skip":
        __setup.set_step("baseline", "skipped")
        return redirect(url_for("setup.setup_recovery"))

    result = __setup.capture_baseline(server, "dhcp4")
    if result["ok"]:
        __user.audit("SETUP_WIZARD", "baseline", f"server={server.get('id')}")
        flash("Baseline captured.", "success")
        __setup.set_step("baseline", "done")
        return redirect(url_for("setup.setup_recovery"))
    flash("Could not read Kea's config — check the helper step above.", "error")
    return redirect(url_for("setup.setup_baseline"))


# ── step 5: recovery point ───────────────────────────────────────────────────


@bp.route("/recovery", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_recovery():
    from jen.services import dbexport

    if request.method == "GET":
        return render_template("setup_recovery.html", progress=_progress(), schedule=dbexport.get_schedule())

    action = request.form.get("action", "")
    if action == "skip":
        __setup.set_step("recovery", "skipped")
        return redirect(url_for("setup.setup_investigate"))

    if action == "schedule":
        enabled = 1 if request.form.get("enabled") else 0
        frequency = request.form.get("frequency", "daily")
        hour = int(request.form.get("hour", 2) or 2)
        keep_count = max(1, min(30, int(request.form.get("keep_count", 7) or 7)))
        include_jen = 1 if request.form.get("include_jen") else 0
        include_kea = 1 if request.form.get("include_kea") else 0
        dbexport.save_schedule(enabled, frequency, hour, keep_count, include_jen, include_kea)
        __user.audit("SETUP_WIZARD", "recovery", f"schedule enabled={bool(enabled)}")
        flash("Backup schedule saved.", "success")
        return redirect(url_for("setup.setup_recovery"))

    if action == "done":
        __setup.set_step("recovery", "done")
        __user.audit("SETUP_WIZARD", "recovery", "confirmed")
        return redirect(url_for("setup.setup_investigate"))

    return redirect(url_for("setup.setup_recovery"))


# ── step 6: investigate ──────────────────────────────────────────────────────


@bp.route("/investigate", methods=["GET"])
@login_required
@_superadmin_required
def setup_investigate():
    return render_template(
        "setup_investigate.html",
        progress=_progress(),
        leases=__setup.recent_leases(),
        elapsed_seconds=__setup.elapsed_seconds(),
        all_resolved=__setup.all_resolved(),
    )


@bp.route("/investigate/visit", methods=["POST"])
@login_required
@_superadmin_required
def setup_investigate_visit():
    mac = request.form.get("mac", "")
    __setup.set_step("investigate", "done")
    __user.audit("SETUP_WIZARD", "investigate", f"mac={mac}" if mac else "skipped")
    if __setup.all_resolved():
        elapsed = __setup.elapsed_seconds()
        took = f" — took {elapsed // 60} minute(s)" if elapsed is not None else ""
        flash(f"First hour complete{took}.", "success")
    if mac:
        return redirect(url_for("explain.explain_page", mac=mac))
    return redirect(url_for("setup.setup_investigate"))


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
