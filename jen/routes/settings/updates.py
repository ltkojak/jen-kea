"""
jen/routes/settings/updates.py
────────────────────────────
Check for a new release; trigger the in-app self-update.
"""

import io
import json
import logging
import subprocess

from flask import flash, jsonify, redirect, request, url_for
from flask_login import login_required

import jen.models.user as __user
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)

GITHUB_REPO = "ltkojak/jen-kea"
# v5.32.0 (Q38) — the release LIST, filtered per channel by jen.version.pick_release
# (`/releases/latest` is GitHub's own "newest non-prerelease", i.e. stable only).
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=30"


@bp.route("/settings/infrastructure/check-update")
@login_required
@_admin_required
def check_update():
    """Check GitHub releases API for a newer version of Jen."""
    import requests as _req

    from jen import JEN_VERSION, extensions
    from jen.version import parse_version, pick_release

    channel = extensions.UPDATE_CHANNEL
    try:
        resp = _req.get(GITHUB_RELEASES_API, headers={"Accept": "application/vnd.github+json"}, timeout=8)
        if resp.status_code == 404:
            return jsonify({"status": "no_releases", "current": JEN_VERSION, "channel": channel})
        if resp.status_code != 200:
            return jsonify(
                {"status": "error", "message": f"GitHub API returned {resp.status_code}", "channel": channel}
            )

        data = pick_release(resp.json(), channel)
        if data is None:
            return jsonify({"status": "no_releases", "current": JEN_VERSION, "channel": channel})
        latest_tag = data.get("tag_name", "").lstrip("v")
        release_url = data.get("html_url", "")
        published = data.get("published_at", "")[:10]

        if parse_version(latest_tag) > parse_version(JEN_VERSION):
            # Find the tarball asset
            asset_url = ""
            for asset in data.get("assets", []):
                if asset["name"].endswith(".tar.gz") and "jen-v" in asset["name"]:
                    asset_url = asset["browser_download_url"]
                    break
            return jsonify(
                {
                    "status": "update_available",
                    "current": JEN_VERSION,
                    "latest": latest_tag,
                    "release_url": release_url,
                    "asset_url": asset_url,
                    "published": published,
                    "channel": channel,
                    "prerelease": bool(data.get("prerelease")),
                }
            )
        return jsonify(
            {
                "status": "up_to_date",
                "current": JEN_VERSION,
                "latest": latest_tag,
                "channel": channel,
            }
        )
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({"status": "error", "message": "Could not check for updates. Check server logs for details."})


@bp.route("/settings/infrastructure/update-channel", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required()
def save_update_channel():
    """v5.32.0 (Q38) — which release channel this install follows. Written
    to jen.config ([updates] channel) because the root-privileged updater
    reads the INI, never the database; both sides then agree. Superadmin
    + step-up: it changes what root will install next."""
    from jen import extensions
    from jen.config import app_config
    from jen.version import CHANNELS

    channel = request.form.get("channel", "").strip().lower()
    if channel not in CHANNELS:
        flash("Pick stable or beta.", "error")
        return redirect(url_for("settings.settings_system"))
    previous = extensions.UPDATE_CHANNEL
    try:
        app_config.write_value("updates", "channel", channel)
    except Exception as e:
        logger.error(f"could not write [updates] channel: {e}")
        flash("Could not save the channel — is /etc/jen/jen.config writable by Jen?", "error")
        return redirect(url_for("settings.settings_system"))
    __user.audit("UPDATE_CHANNEL", "settings", f"{previous} -> {channel}")
    if channel == "beta":
        flash(
            "This install now follows the beta channel: pre-release builds are offered here as they're published. "
            "Switching back never downgrades — the box keeps what it's running until the next stable release passes it.",
            "success",
        )
    else:
        flash("This install now follows the stable channel.", "success")
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/system/support-bundle")
@login_required
@_superadmin_required
@_recent_auth_required()
def support_bundle():
    """v5.33.0 (Q32) — one zip to attach to a bug report. Built in memory,
    never stored; every secret masked by construction (see
    jen/services/support_bundle.py and its sentinel test). Superadmin +
    step-up: it reveals the whole topology."""
    from flask import send_file

    from jen.services import support_bundle as _sb

    try:
        data, filename, names = _sb.make_bundle()
    except Exception as e:
        logger.error(f"support bundle failed: {e}")
        flash("Could not build the support bundle — see the Jen log.", "error")
        return redirect(url_for("settings.settings_system"))
    __user.audit("SUPPORT_BUNDLE", "settings", f"{filename} ({len(names)} members, {len(data)} bytes)")
    return send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True, download_name=filename)


def _parse_systemctl_show(text: str) -> dict:
    """`systemctl show -p A -p B` prints `Key=Value` lines. Pure — tested
    directly."""
    props = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props


@bp.route("/settings/infrastructure/update-status")
@login_required
@_admin_required
def update_status():
    """
    v5.8.4 — what the update overlay polls next to check-update. The
    overlay used to conclude "Jen restarted but still reports vX" after
    ~50s, which was wrong whenever the updater had *crashed before the
    restart* (bigben, 5.8.2→5.8.3: a snapshot failure). `systemctl show`
    on a system unit is a read-only property query that needs no sudo —
    so no sudoers change (rule 8) — and tells the page whether the unit
    is still running, finished, or failed, and with what exit status.
    """
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "jen-update.service",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "Result",
                "-p",
                "ExecMainStatus",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        props = _parse_systemctl_show(result.stdout)
    except Exception as e:
        logger.error(f"update-status: could not query jen-update.service: {e}")
        props = {}
    active = props.get("ActiveState", "unknown")
    return jsonify(
        {
            "active_state": active,
            "sub_state": props.get("SubState", ""),
            "result": props.get("Result", ""),
            "exit_status": props.get("ExecMainStatus", ""),
            "failed": active == "failed",
        }
    )


@bp.route("/settings/infrastructure/self-update", methods=["POST"])
@login_required
@_superadmin_required
def self_update():
    """
    Trigger the hardened, root-privileged updater.

    v5.2.6 — SECURITY FIX. This route used to perform the entire
    download, checksum verification, extraction, and file-copy
    pipeline itself while running as www-data, then write a helper
    script to /tmp/jen_update_install.sh and sudo-execute it as root.
    Since /tmp is world-writable and www-data is the exact account
    permitted to write that exact path, the real security boundary was
    "gain any code execution as www-data → write that file yourself →
    sudo it → root" — completely bypassing every validation this route
    performed, since an attacker never needed to go through this route
    at all to reach that sudo rule.

    This route now does none of the download/verify/extract/copy work
    itself. It optionally takes a database backup (unchanged — that's
    Jen backing up its own database with credentials it already
    legitimately has, not a privilege-boundary concern) and then
    triggers `sudo systemctl start --no-block jen-update.service` — a
    fixed, hardcoded command with no attacker-controllable input,
    matching the same already-safe pattern used for
    `sudo systemctl restart jen`. `--no-block` matters here: without
    it, this call would wait for the triggered service to fully
    complete, including its own final `systemctl restart jen` step —
    which kills the very Flask worker process that's blocked waiting
    for this call to return. (v5.2.9 fix: the sudoers rule authorizing
    this command must match it byte-for-byte, including --no-block —
    sudo matches commands literally, and the rule originally
    authorized `start jen-update.service` without that flag, which
    meant every self-update attempt failed with a sudo permission
    denial, not the "sudo systemctl restart jen" pattern working as
    intended.) The entire pipeline now runs
    inside /usr/local/sbin/jen-update-root.py, a script owned
    root:root, mode 0700, that www-data cannot read or modify, and
    which re-derives the release information from GitHub itself rather
    than trusting anything from this request. See that script's own
    docstring for the full design, including why it fails closed on
    checksum verification (a separate issue found in the same review
    that produced this fix).

    One consequence: this route can no longer offer "the release
    changed since you checked, please refresh" — the trigger is now
    "install whatever GitHub currently reports as latest," full stop,
    with no version parameter passed through at all. That's deliberate:
    passing a version through here would reintroduce attacker-
    controllable input into the root-privileged path. Explicit version
    selection (e.g. a deliberate downgrade) still works via the manual
    git+tar+install.sh path, run with real administrator access.
    """
    do_db_backup = request.form.get("db_backup", "0") == "1"

    if do_db_backup:
        try:
            from jen.services import dbexport as _dbexport

            content, fname = _dbexport.export_jen()
            payload = json.loads(content.decode("utf-8"))
            backup_path = _dbexport._write_backup(payload, "jen-pre-update.json.gz")
            flash(f"Database backed up to {backup_path}", "success")
        except Exception as e:
            logger.error(f"Pre-update database backup failed: {e}")
            flash("Database backup failed — aborting update. Check server logs for details.", "error")
            return redirect(url_for("settings.settings_system"))

    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-update.service"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception as e:
        logger.error(f"Failed to trigger jen-update.service: {e}")
        flash("Could not start the update — check server logs for details.", "error")
        return redirect(url_for("settings.settings_system"))

    if result.returncode != 0:
        logger.error(f"jen-update.service failed to start: {result.stderr}")
        flash("Could not start the update — check server logs for details.", "error")
        return redirect(url_for("settings.settings_system"))

    __user.audit("SELF_UPDATE", "jen", "Triggered update via jen-update.service")
    flash("Update started. This page will refresh automatically once Jen is back.", "success")
    # v5.10.4 — the update overlay and its ?updating=1 restart-poller live
    # on /settings/system (they have since the 5.9.0 Settings IA rework);
    # this route redirected to /settings/kea, so nothing ever polled and
    # the page never refreshed when the update finished. Send the browser
    # to the page that actually carries the overlay.
    return redirect(url_for("settings.settings_system", updating="1"))
