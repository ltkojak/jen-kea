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
from functools import wraps

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


def _admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated


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
    return render_template("servers.html", statuses=statuses,
                           single_server=single_server,
                           ha_mode=ha_mode,
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
    SSH_OPTS = ["-i", extensions.SSH_KEY_PATH, "-o", "StrictHostKeyChecking=no",
                "-o", f"UserKnownHostsFile=/etc/jen/ssh/known_hosts"]
    try:
        result = subprocess.run(
            ["ssh"] + SSH_OPTS + [f"{server['ssh_user']}@{server['ssh_host']}",
             "sudo systemctl restart isc-kea-dhcp4-server"],
            capture_output=True, timeout=15
        )
        if result.returncode == 0:
            flash(f"Kea restarted on {server['name']}.", "success")
            __user.audit("RESTART_KEA", server["name"], f"Remote restart via SSH")
        else:
            flash(f"Restart failed on {server['name']}: {result.stderr.decode()}", "error")
    except Exception as e:
        flash(f"SSH error: {str(e)}", "error")
    return redirect(url_for('servers.servers'))

# ─────────────────────────────────────────
# Reports
# ─────────────────────────────────────────
