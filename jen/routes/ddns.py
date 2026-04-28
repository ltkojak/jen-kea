"""
jen/routes/ddns.py
───────────────────
DDNS status and configuration routes.
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
bp = Blueprint("ddns", __name__)


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


@bp.route("/ddns")
@login_required
def ddns():
    lines = []
    log_status = "ok"
    log_message = ""
    if not extensions.KEA_SSH_HOST:
        log_status = "error"
        log_message = "SSH host not configured. Set it in Settings → Infrastructure → SSH."
    else:
        try:
            result = subprocess.run(
                ["ssh", "-i", extensions.SSH_KEY_PATH,
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10",
                 f"{extensions.KEA_SSH_USER}@{extensions.KEA_SSH_HOST}",
                 f"sudo tail -200 {extensions.DDNS_LOG}"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                err = result.stderr.strip()
                if "No such file" in err or "No such file" in result.stdout:
                    log_status = "missing"
                    log_message = f"Log file not found on Kea server: {extensions.DDNS_LOG}"
                else:
                    log_status = "error"
                    log_message = f"SSH error: {err or 'unknown error'}"
                    logger.error(f"DDNS SSH error: {err}")
            else:
                raw_lines = result.stdout.splitlines()
                lines = list(reversed(raw_lines))
                if not lines:
                    log_status = "empty"
                    log_message = "Log file exists but contains no entries yet."
        except subprocess.TimeoutExpired:
            log_status = "error"
            log_message = f"SSH connection timed out. Check that {extensions.KEA_SSH_HOST} is reachable."
            logger.error("DDNS SSH timeout")
        except Exception as e:
            log_status = "error"
            log_message = f"Could not read DDNS log: {str(e)}"
            logger.error(f"DDNS error: {e}")
    lookup_host = request.args.get("host", "")
    lookup_result = ""
    if lookup_host:
        try:
            dns_provider = extensions.cfg.get("ddns", "dns_provider", fallback="technitium")
            if dns_provider == "technitium":
                dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
                dns_token = extensions.cfg.get("ddns", "api_token", fallback="")
                forward_zone = extensions.cfg.get("ddns", "forward_zone", fallback="")
                if dns_url and dns_token:
                    import requests as req
                    r = req.get(f"{dns_url}/api/zones/records/get",
                                params={"token": dns_token, "domain": lookup_host, "zone": forward_zone},
                                timeout=5)
                    data = r.json()
                    records = data.get("response", {}).get("records", [])
                    if records:
                        lookup_result = records
                    else:
                        lookup_result = f"No DNS records found for {lookup_host}"
                else:
                    lookup_result = "Technitium API not configured."

            elif dns_provider == "pihole":
                dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
                dns_pass = extensions.cfg.get("ddns", "api_token", fallback="")
                if dns_url:
                    import requests as req
                    # Try Pi-hole v6 API first
                    try:
                        auth = req.post(f"{dns_url}/api/auth",
                                        json={"password": dns_pass}, timeout=5)
                        if auth.status_code == 200 and auth.json().get("session", {}).get("valid"):
                            sid = auth.json()["session"]["sid"]
                            r = req.get(f"{dns_url}/api/dns/records",
                                        params={"domain": lookup_host},
                                        headers={"X-FTL-SID": sid}, timeout=5)
                            data = r.json()
                            records = data.get("records", [])
                            lookup_result = records if records else f"No DNS records found for {lookup_host}"
                        else:
                            raise Exception("Auth failed")
                    except Exception:
                        # Fallback to Pi-hole v5 API
                        r = req.get(f"{dns_url}/admin/api.php",
                                    params={"customdns": "", "action": "get", "auth": dns_pass},
                                    timeout=5)
                        data = r.json()
                        matches = [e for e in data.get("data", []) if lookup_host in str(e)]
                        lookup_result = matches if matches else f"No records found for {lookup_host} (Pi-hole v5 API)"
                else:
                    lookup_result = "Pi-hole API URL not configured."

            elif dns_provider == "adguard":
                dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
                dns_user = extensions.cfg.get("ddns", "api_user", fallback="")
                dns_pass = extensions.cfg.get("ddns", "api_token", fallback="")
                if dns_url:
                    import requests as req
                    r = req.get(f"{dns_url}/control/rewrite/list",
                                auth=(dns_user, dns_pass), timeout=5)
                    data = r.json()
                    matches = [e for e in data if lookup_host in str(e.get("domain", ""))]
                    lookup_result = matches if matches else f"No rewrite rules found for {lookup_host}"
                else:
                    lookup_result = "AdGuard Home URL not configured."

            elif dns_provider in ("ssh", "generic"):
                # DNS lookup via dig/host over SSH to Kea server
                active = __kea.get_active_kea_server()
                ssh_host = active.get("ssh_host") or extensions.KEA_SSH_HOST
                ssh_user = active.get("ssh_user") or extensions.KEA_SSH_USER
                if ssh_host:
                    result = subprocess.run(
                        ["ssh", "-i", extensions.SSH_KEY_PATH, "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=10",
                         f"{ssh_user}@{ssh_host}",
                         f"dig +short {lookup_host} 2>/dev/null || host {lookup_host} 2>/dev/null"],
                        capture_output=True, text=True, timeout=10
                    )
                    lookup_result = result.stdout.strip() or f"No DNS result for {lookup_host}"
                else:
                    import socket
                    lookup_result = socket.gethostbyname(lookup_host)

            else:
                lookup_result = "DNS lookup not configured."
        except Exception as e:
            lookup_result = f"Lookup error: {str(e)}"
    return render_template("ddns.html", lines=lines, lookup_host=lookup_host,
                           lookup_result=lookup_result, log_status=log_status,
                           log_message=log_message, ddns_log=extensions.DDNS_LOG,
                           dns_provider=extensions.cfg.get("ddns", "dns_provider", fallback="technitium"))

# ─────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────
