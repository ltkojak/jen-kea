"""
jen/routes/servers.py
──────────────────────
Kea server management routes.
"""

import hashlib
import io
import json
import logging
import os
import re
import secrets
import subprocess
import threading
from datetime import datetime, timezone
from jen.services.access import admin_required as _admin_required, superadmin_required as _superadmin_required

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, send_from_directory,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from jen import extensions
from jen.config import init_extensions_from_config, load_config
import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.kea as __kea
import jen.services.alerts as __alerts
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("servers", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/servers")
@login_required
def servers():
    statuses = __kea.get_all_server_status()
    # Get version info for each server
    for s in statuses:
        if s["up"]:
            ver = __kea.kea_command("version-get", server=s["server"])
            s["version"] = ver.get("arguments", {}).get("extended", ver.get("text", ""))
            s["version"] = s["version"].splitlines()[0] if s["version"] else ""
            # Get lease stats per server
            stats_result = __kea.kea_command("stat-lease4-get", server=s["server"])
            s["lease_stats"] = stats_result.get("arguments", {}).get("result-set", {}) if stats_result.get("result") == 0 else {}
        else:
            s["version"] = ""
            s["lease_stats"] = {}
    single_server = len(extensions.KEA_SERVERS) == 1
    ha_mode = extensions.cfg.get("kea", "ha_mode", fallback="")

    # v4.4.17 — HA status view. Two things derived here rather than in
    # the template, both bugs/gaps found while building this:
    #
    # 1. "Active" server detection previously only ever checked
    #    role == 'primary' — meaning if the primary genuinely goes
    #    offline and the standby takes over (the entire point of HA),
    #    no server would ever show as active, since standby's role is
    #    never 'primary'. The correct rule depends on the reported
    #    state, not a blanket "always trust role":
    #      - load-balancing: both nodes serve simultaneously — both
    #        active, regardless of role.
    #      - hot-standby (both partners mutually healthy): only the
    #        primary actually serves traffic — standby is genuinely
    #        idle, ready but not active. (Tested this specific case
    #        directly before trusting it — an earlier draft of this
    #        fix marked BOTH nodes active whenever either reported
    #        hot-standby, which is wrong for the normal, healthy case.)
    #      - partner-down: THIS server is now serving solo, regardless
    #        of its configured role — this is the actual scenario the
    #        old role-only check got wrong.
    #
    # 2. "Healthy backup" vs "no backup" — hot-standby/load-balancing
    #    mean a partner is genuinely ready to take over. Everything
    #    else (partner-down, terminated, waiting, syncing, or no
    #    ha_state at all because a server is offline) means the backup
    #    isn't confirmed working right now. This is a persistent,
    #    always-current status — complementary to the ha_failover
    #    alert (which only fires once, at the moment of a state
    #    transition, and says nothing about the current state to
    #    someone loading this page hours later).
    HEALTHY_BACKUP_STATES = ("hot-standby", "load-balancing")
    for s in statuses:
        state = s["ha_state"]
        role = s["server"].get("role", "")
        if state == "load-balancing":
            s["is_active"] = True
        elif state == "hot-standby":
            s["is_active"] = role == "primary"
        elif state == "partner-down":
            s["is_active"] = True
        else:
            s["is_active"] = False
    ha_degraded = False
    ha_degraded_reason = ""
    if not single_server and ha_mode:
        any_healthy = any(s["ha_state"] in HEALTHY_BACKUP_STATES for s in statuses)
        any_offline = any(not s["up"] for s in statuses)
        if not any_healthy:
            ha_degraded = True
            if any_offline:
                ha_degraded_reason = "at least one configured server is unreachable"
            else:
                reported = {s["ha_state"] for s in statuses if s["ha_state"]}
                ha_degraded_reason = (
                    f"reported state: {', '.join(sorted(reported))}" if reported
                    else "no server has reported an HA state yet"
                )

    return render_template("servers.html", statuses=statuses,
                           single_server=single_server,
                           ha_mode=ha_mode,
                           ha_degraded=ha_degraded,
                           ha_degraded_reason=ha_degraded_reason,
                           subnet_map=extensions.SUBNET_MAP)

@bp.route("/servers/restart/<int:server_id>", methods=["POST"])
@login_required
@_admin_required
def restart_kea_server(server_id):
    server = next((s for s in extensions.KEA_SERVERS if s["id"] == server_id), None)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for('servers.servers'))
    if not server["ssh_host"]:
        flash("SSH not configured for this server.", "error")
        return redirect(url_for('servers.servers'))
    try:
        result = subprocess.run(
            ["ssh"] + __auth.ssh_cli_opts() +
            [f"{server['ssh_user']}@{server['ssh_host']}",
             "sudo systemctl restart isc-kea-dhcp4-server"],
            capture_output=True, timeout=15
        )
        if result.returncode == 0:
            flash(f"Kea restarted on {server['name']}.", "success")
            __user.audit("RESTART_KEA", server["name"], "Remote restart via SSH")
        else:
            flash(f"Restart failed on {server['name']}: {result.stderr.decode()}", "error")
    except Exception as e:
        flash(f"SSH error: {str(e)}", "error")
    return redirect(url_for('servers.servers'))
