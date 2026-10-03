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
            kea_db_port=extensions.KEA_DB_PORT,
            kea_db_ssl_ca=extensions.KEA_DB_SSL_CA,
            api_ca=extensions.KEA_API_CA,
            api_tls_verify=extensions.KEA_API_TLS_VERIFY,
            api_client_cert=extensions.KEA_API_CLIENT_CERT,
            api_client_key=extensions.KEA_API_CLIENT_KEY,
            api_pass_saved=bool(extensions.KEA_API_PASS),
            kea_db_pass_saved=bool(extensions.KEA_DB_PASS),
        )

    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "")
    kea_db_host = request.form.get("kea_db_host", "").strip()
    kea_db_user = request.form.get("kea_db_user", "").strip()
    kea_db_pass = request.form.get("kea_db_pass", "")
    kea_db_name = request.form.get("kea_db_name", "").strip() or "kea"
    kea_db_port_raw = request.form.get("kea_db_port", "").strip()
    # v5.67.0-beta.15 (Q129, item d) — the CA bundle for the Kea DATABASE connection; the form value is the
    # whole truth (it is pre-filled with the saved one), so an empty field clears it.
    kea_db_ssl_ca = request.form.get("kea_db_ssl_ca", "").strip()
    # v5.67.0-beta.5 (Q117, item f) — Advanced TLS, same four fields and
    # same validation as Settings' own save_infra_kea.
    api_ca = request.form.get("api_ca", "").strip()
    api_tls_verify = request.form.get("api_tls_verify", "") == "1"
    api_client_cert = request.form.get("api_client_cert", "").strip()
    api_client_key = request.form.get("api_client_key", "").strip()

    from jen.services import auth as __auth
    from jen.services import capabilities as __caps
    from jen.services import kea as __kea

    retry_ctx = {
        "api_url": api_url,
        "api_user": api_user,
        "kea_db_host": kea_db_host,
        "kea_db_user": kea_db_user,
        "kea_db_name": kea_db_name,
        "kea_db_port": kea_db_port_raw or extensions.KEA_DB_PORT,
        "kea_db_ssl_ca": kea_db_ssl_ca,
        "api_ca": api_ca,
        "api_tls_verify": api_tls_verify,
        "api_client_cert": api_client_cert,
        "api_client_key": api_client_key,
        "api_pass_saved": bool(extensions.KEA_API_PASS),
        "kea_db_pass_saved": bool(extensions.KEA_DB_PASS),
    }
    # v5.67.0-beta.8 (Q120, item g) — the Kea database port; blank keeps the saved one.
    kea_db_port = extensions.KEA_DB_PORT
    if kea_db_port_raw:
        try:
            kea_db_port = int(kea_db_port_raw)
        except ValueError:
            kea_db_port = 0
        if not 1 <= kea_db_port <= 65535:
            flash("Enter a valid database port (1–65535).", "error")
            return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if not api_url or not __auth.valid_api_url(api_url, require_port=False):
        flash("Enter a valid Kea API URL (http:// or https://).", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if not kea_db_host or not kea_db_user:
        flash("Kea's database host and username are required.", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if api_ca and not os.path.isfile(api_ca):
        flash(f"CA bundle path not found on the Jen host: {api_ca}", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if kea_db_ssl_ca and not os.path.isfile(kea_db_ssl_ca):
        flash(f"Database CA bundle path not found on the Jen host: {kea_db_ssl_ca}", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    if bool(api_client_cert) != bool(api_client_key):
        flash("Set both the client certificate and key, or neither.", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    for label, path in (("client certificate", api_client_cert), ("client key", api_client_key)):
        if path and not os.path.isfile(path):
            flash(f"Client {label} not found on the Jen host: {path}", "error")
            return render_template("setup_connect.html", progress=_progress(), **retry_ctx)
    tls_err = __kea.validate_client_tls_material(api_client_cert, api_client_key, api_ca)
    if tls_err:
        flash(f"TLS settings not saved: {tls_err}.", "error")
        return render_template("setup_connect.html", progress=_progress(), **retry_ctx)

    # Probe with the candidate TLS material — not yet saved, so the
    # probe must override what's currently configured rather than fall
    # back to it (the same reasoning Settings' own https setup flow
    # already uses for a socket Jen hasn't adopted yet).
    # v5.67.0-beta.8 (Q120, item f) — "no client certificate" is said out loud (kea.NO_CLIENT_CERT), not
    # passed as None: None means "nothing given, use the SAVED certificate", so a form that cleared the
    # fields probed WITH the saved certificate (and passed), then saved the empty fields (and every later
    # call failed).
    probe_verify = api_ca or api_tls_verify
    probe_cert = (api_client_cert, api_client_key) if api_client_cert and api_client_key else __kea.NO_CLIENT_CERT
    # v5.67.0-beta.8 (Q120, item n) — saved passwords are never rendered, so a revisit shows blank
    # fields; save_connection() keeps the stored value for a blank one, and the TEST now does the same
    # instead of failing with an empty password the save would never have written.
    test_api_pass = api_pass or extensions.KEA_API_PASS
    test_db_pass = kea_db_pass or extensions.KEA_DB_PASS
    # An answer that cannot be identified keeps the mode already saved for THIS url (Q120, item b).
    saved_url = (extensions.KEA_API_URL or "").rstrip("/")
    saved_mode = "direct" if __caps.is_direct() else "ca"
    default_mode = saved_mode if saved_url and api_url.rstrip("/") == saved_url else "ca"
    kea_result = __setup.test_kea_connection(
        api_url, api_user, test_api_pass, verify=probe_verify, cert=probe_cert, default_mode=default_mode
    )
    db_ok, db_info = __setup.test_kea_db(
        kea_db_host, kea_db_user, test_db_pass, kea_db_name, port=kea_db_port, ssl_ca=kea_db_ssl_ca
    )

    if not kea_result["ok"] or not db_ok:
        if not kea_result["ok"]:
            # v5.67.0-beta.8 (Q120, item e) — the error for the URL the operator TYPED, first; whatever
            # was guessed on top of it (the :8004/:8006 fallback) as a second line. This used to flash
            # attempts[-1], always the guess, so a wrong password read "connection refused" on a port
            # nobody had typed.
            attempts = kea_result["attempts"]
            typed = [a for a in attempts if a.get("typed") and a.get("error")]
            guessed = [a for a in attempts if not a.get("typed") and a.get("error")]
            first = typed[-1] if typed else (attempts[0] if attempts else {})
            flash(
                f"Could not reach Kea's API at {first.get('url', api_url)}: {first.get('error') or 'no response'}.",
                "error",
            )
            for a in guessed:
                flash(f"Also tried {a['url']} (a control socket's default port): {a['error']}.", "error")
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
        kea_db_port=kea_db_port,
        kea_db_ssl_ca=kea_db_ssl_ca,
        api_ca=api_ca,
        api_tls_verify=api_tls_verify,
        api_client_cert=api_client_cert,
        api_client_key=api_client_key,
    )
    __user.audit("SETUP_WIZARD", "connect", f"url={kea_result['url']} mode={kea_result['mode']}")
    flash(f"Connected — Kea {kea_result['version'] or 'unknown version'}, {kea_result['mode']} mode.", "success")
    if kea_result["identified"] is None:
        flash(
            f"Jen could not tell whether {kea_result['url']} is the Control Agent or a daemon's own control "
            f"socket (it would not answer config-get), so it kept {kea_result['mode']} mode — check "
            "Settings → Kea if that is wrong.",
            "warning",
        )
    __setup.set_step("connect", "done")
    return redirect(url_for("setup.setup_found"))


# ── step 2: what Jen found ──────────────────────────────────────────────────


@bp.route("/found", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_found():
    from jen import extensions

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

    # v5.67.0-beta.5 (Q117, item g) — both v6 actions are a superadmin's
    # own explicit act (CLAUDE.md "IPv6": nothing v6 fires unless
    # asked). CA mode reuses the already-connected v4 Control Agent URL
    # with service=["dhcp6"]; direct mode has no way to infer dhcp6's
    # own control socket from dhcp4's, so it needs the operator's own
    # URL for it.
    if action in ("check_v6", "enable_v6"):
        from jen.services import capabilities as __caps

        if __caps.is_direct():
            v6_url = request.form.get("v6_url", "").strip()
            from jen.services import auth as __auth

            if not v6_url or not __auth.valid_api_url(v6_url, require_port=True):
                flash("Enter a valid DHCPv6 control socket URL (e.g. http://kea:8006).", "error")
                return render_template(
                    "setup_found.html",
                    progress=_progress(),
                    found=found,
                    hook_loss=__setup.HOOK_LOSS,
                    hook_labels=__setup.HOOK_LABELS,
                )
            v6_probe = __setup.probe_v6(v6_url, extensions.KEA_API_USER, extensions.KEA_API_PASS, omit_service=True)
        else:
            v6_url = extensions.KEA_API_URL
            v6_probe = __setup.probe_v6(v6_url, extensions.KEA_API_USER, extensions.KEA_API_PASS, omit_service=False)

        if not v6_probe["ok"]:
            flash(f"DHCPv6 did not answer: {v6_probe['error'] or 'no response'}.", "error")
            return render_template(
                "setup_found.html",
                progress=_progress(),
                found=found,
                hook_loss=__setup.HOOK_LOSS,
                hook_labels=__setup.HOOK_LABELS,
                v6_url=v6_url,
            )

        if action == "check_v6":
            __user.audit(
                "SETUP_WIZARD", "check_v6", f"version={v6_probe['version']} subnets={v6_probe['subnet6_count']}"
            )
            return render_template(
                "setup_found.html",
                progress=_progress(),
                found=found,
                hook_loss=__setup.HOOK_LOSS,
                hook_labels=__setup.HOOK_LABELS,
                v6_probe=v6_probe,
                v6_url=v6_url,
            )

        # action == "enable_v6" — v5.67.0-beta.8 (Q120, item c): a merge; whatever Jen already has under
        # [subnets6] that this daemon did not report stays unless the superadmin ticked its "remove" box.
        remove6 = {sid for sid in v6_probe["orphaned_subnets6"] if request.form.get(f"remove6_{sid}", "") == "1"}
        error = __setup.enable_v6(v6_url, v6_probe["proposed_subnets6"], remove6)
        if error:
            flash(f"IPv6 was not enabled: {error}.", "error")
            return render_template(
                "setup_found.html",
                progress=_progress(),
                found=found,
                hook_loss=__setup.HOOK_LOSS,
                hook_labels=__setup.HOOK_LABELS,
                v6_probe=v6_probe,
                v6_url=v6_url,
            )
        __user.audit(
            "SETUP_WIZARD",
            "enable_v6",
            f"url={v6_url} subnets={v6_probe['subnet6_count']} removed={len(remove6)}",
        )
        flash(f"IPv6 is now managed in Jen — Kea {v6_probe['version'] or 'unknown version'}.", "success")
        return redirect(url_for("setup.setup_found"))

    # v5.67.0-beta.8 (Q120, item j) — with Kea unreachable the proposal above is empty and the typed names
    # have nothing to attach to: this used to drop them silently and mark the step done with subnets=0.
    # Say so, save nothing, leave the step open (Skip is still there).
    if not found["reachable"]:
        flash(
            "Kea did not answer, so nothing was saved and this step is not done — check the connection "
            "(step 1) and try again, or skip it for now.",
            "error",
        )
        return render_template(
            "setup_found.html",
            progress=_progress(),
            found=found,
            hook_loss=__setup.HOOK_LOSS,
            hook_labels=__setup.HOOK_LABELS,
        )

    subnets = {}
    for sid, info in found["proposed_subnets"].items():
        name = request.form.get(f"name_{sid}", info["name"]).strip() or info["name"]
        subnets[sid] = {"name": name, "cidr": info["cidr"]}
    remove_ids = {sid for sid in found["orphaned_subnets"] if request.form.get(f"remove_{sid}", "") == "1"}
    if subnets or remove_ids:
        merged, error = __setup.save_subnets(subnets, remove_ids)
        if error:
            flash(f"Subnets not saved: {error}.", "error")
            return render_template(
                "setup_found.html",
                progress=_progress(),
                found=found,
                hook_loss=__setup.HOOK_LOSS,
                hook_labels=__setup.HOOK_LABELS,
            )
    __user.audit("SETUP_WIZARD", "found", f"subnets={len(subnets)} removed={len(remove_ids)}")
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
        # v5.67.0-beta.5 (Q117, item g) — once a superadmin has actually
        # pressed "Manage IPv6 in Jen" on the Found step (never before —
        # CLAUDE.md "IPv6": nothing v6 fires unless asked), the baseline
        # this step captures should cover dhcp6 too, not just dhcp4.
        # Best-effort: a v6 capture failure doesn't fail the v4 one.
        v6_note = ""
        if __setup._ipv6_enabled():
            v6_result = __setup.capture_baseline(server, "dhcp6")
            v6_note = " (dhcp6 too)" if v6_result["ok"] else " — dhcp6 baseline failed, dhcp4 still captured"
        __user.audit("SETUP_WIZARD", "baseline", f"server={server.get('id')}")
        flash(f"Baseline captured{v6_note}.", "success")
        __setup.set_step("baseline", "done")
        return redirect(url_for("setup.setup_recovery"))
    flash(result["detail"], "error")
    return redirect(url_for("setup.setup_baseline"))


# ── step 5: recovery point ───────────────────────────────────────────────────


@bp.route("/recovery", methods=["GET", "POST"])
@login_required
@_superadmin_required
def setup_recovery():
    from jen.services import dbexport

    if request.method == "GET":
        return render_template(
            "setup_recovery.html",
            progress=_progress(),
            schedule=dbexport.get_schedule(),
            recovery=__setup.recovery_bundle_status(),
        )

    action = request.form.get("action", "")
    if action == "skip":
        __setup.set_step("recovery", "skipped")
        __user.audit("SETUP_WIZARD", "recovery", "skipped")
        return redirect(url_for("setup.setup_investigate"))

    if action == "schedule":
        values, errors = dbexport.validate_schedule(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return (
                render_template(
                    "setup_recovery.html",
                    progress=_progress(),
                    schedule=dbexport.get_schedule(),
                    recovery=__setup.recovery_bundle_status(),
                ),
                400,
            )
        dbexport.save_schedule(
            values["enabled"],
            values["frequency"],
            values["hour"],
            values["keep_count"],
            values["include_jen"],
            values["include_kea"],
        )
        __user.audit("SETUP_WIZARD", "recovery", f"schedule enabled={bool(values['enabled'])}")
        flash("Backup schedule saved.", "success")
        return redirect(url_for("setup.setup_recovery"))

    if action == "done":
        # v5.67.0-beta.5 (Q117, item i) — "done" used to mean only that
        # this button was clicked; now it means a real bundle this setup
        # run itself produced actually finished downloading.
        if not __setup.recovery_bundle_status()["fresh"]:
            flash("No recovery bundle has been downloaded yet in this setup run.", "error")
            return redirect(url_for("setup.setup_recovery"))
        __setup.set_step("recovery", "done")
        __user.audit("SETUP_WIZARD", "recovery", "confirmed")
        return redirect(url_for("setup.setup_investigate"))

    return redirect(url_for("setup.setup_recovery"))


@bp.route("/recovery/status")
@login_required
@_superadmin_required
def setup_recovery_status():
    """v5.67.0-beta.8 (Q120, item i) — what the recovery page polls after a download starts. A bundle
    download is a form POST whose response is a file, so the page never reloads and could never learn that
    the bundle finished; "Continue" (rendered only for a fresh bundle) never appeared and the only way
    forward was "I will do this later". `at` lets the page tell a NEW bundle from one it already knew
    about."""
    status = __setup.recovery_bundle_status()
    response = jsonify({"fresh": status["fresh"], "at": status["at"], "size": status["size"]})
    response.headers["Cache-Control"] = "no-store"
    return response


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
        # v5.67.0-beta.5 (Q117, item k) — the Investigation page
        # (jen/routes/client.py, six tabs: Overview, Explain, Trace,
        # Timeline, DNS, Config) has existed since v5.63.0; this used
        # to open only the narrow Explain tab (Q115's own spec, since
        # corrected). "overview" is client_page()'s own default tab, so
        # it's left implicit here rather than named.
        return redirect(url_for("client.client_page", q=mac))
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
