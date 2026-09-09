"""
jen/routes/settings/updates.py
────────────────────────────
Check for a new release; trigger the in-app self-update.
"""

import json
import logging
import subprocess

from flask import flash, jsonify, redirect, request, url_for
from flask_login import login_required

import jen.models.user as __user
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)

GITHUB_REPO = "ltkojak/jen-kea"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


@bp.route("/settings/infrastructure/check-update")
@login_required
@_admin_required
def check_update():
    """Check GitHub releases API for a newer version of Jen."""
    import requests as _req

    from jen import JEN_VERSION

    try:
        resp = _req.get(GITHUB_RELEASES_API, headers={"Accept": "application/vnd.github+json"}, timeout=8)
        if resp.status_code == 404:
            return jsonify({"status": "no_releases", "current": JEN_VERSION})
        if resp.status_code != 200:
            return jsonify({"status": "error", "message": f"GitHub API returned {resp.status_code}"})

        data = resp.json()
        latest_tag = data.get("tag_name", "").lstrip("v")
        release_url = data.get("html_url", "")
        published = data.get("published_at", "")[:10]

        def _ver(v):
            try:
                return tuple(int(x) for x in v.split(".")[:3])
            except Exception:
                return (0, 0, 0)

        if _ver(latest_tag) > _ver(JEN_VERSION):
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
                }
            )
        return jsonify(
            {
                "status": "up_to_date",
                "current": JEN_VERSION,
                "latest": latest_tag,
            }
        )
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({"status": "error", "message": "Could not check for updates. Check server logs for details."})


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
            return redirect(url_for("settings.settings_infrastructure"))

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
        return redirect(url_for("settings.settings_infrastructure"))

    if result.returncode != 0:
        logger.error(f"jen-update.service failed to start: {result.stderr}")
        flash("Could not start the update — check server logs for details.", "error")
        return redirect(url_for("settings.settings_infrastructure"))

    __user.audit("SELF_UPDATE", "jen", "Triggered update via jen-update.service")
    flash("Update started. This page will refresh automatically once Jen is back.", "success")
    return redirect(url_for("settings.settings_infrastructure", updating="1"))
