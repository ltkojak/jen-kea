"""
jen/routes/subnets.py
──────────────────────
Subnet view and editing routes.
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
bp = Blueprint("subnets", __name__)


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


@bp.route("/subnets")
@login_required
def subnets():
    subnet_data = []
    # Fetch Kea config for lease times, timers, pools
    kea_subnets = {}
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            global_lifetime = cfg.get("valid-lifetime", 0)
            global_renew = cfg.get("renew-timer", 0)
            global_rebind = cfg.get("rebind-timer", 0)
            for s in cfg.get("subnet4", []):
                pools = []
                for p in s.get("pools", []):
                    pool_str = p.get("pool", "") if isinstance(p, dict) else str(p)
                    if pool_str:
                        pools.append(pool_str)
                kea_subnets[s["id"]] = {
                    "valid_lifetime": s.get("valid-lifetime", global_lifetime),
                    "renew_timer": s.get("renew-timer", global_renew),
                    "rebind_timer": s.get("rebind-timer", global_rebind),
                    "pools": pools,
                }
    except Exception:
        pass
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                kea = kea_subnets.get(subnet_id, {})
                subnet_data.append({
                    "id": subnet_id,
                    "name": info["name"],
                    "cidr": info["cidr"],
                    "active": active,
                    "reserved": reserved,
                    "valid_lifetime": kea.get("valid_lifetime", 0),
                    "renew_timer": kea.get("renew_timer", 0),
                    "rebind_timer": kea.get("rebind_timer", 0),
                    "pools": kea.get("pools", []),
                })
        db.close()
    except Exception as e:
        flash(f"Could not load subnet data: {str(e)}", "error")
    ssh_ready = os.path.exists(extensions.SSH_KEY_PATH) and bool(extensions.KEA_SSH_HOST)
    subnet_notes = {}
    try:
        jdb = __db.get_jen_db()
        with jdb.cursor() as jcur:
            jcur.execute("SELECT subnet_id, notes FROM subnet_notes")
            for row in jcur.fetchall():
                subnet_notes[row["subnet_id"]] = row["notes"]
        jdb.close()
    except Exception:
        pass
    return render_template("subnets.html", subnets=subnet_data, ssh_ready=ssh_ready,
                           subnet_notes=subnet_notes)

@bp.route("/subnets/edit/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    return render_template("edit_subnet.html", subnet_id=subnet_id,
                           subnet=extensions.SUBNET_MAP[subnet_id], subnet_map=extensions.SUBNET_MAP)

@bp.route("/subnets/edit/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_post(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    action = request.form.get("action", "")
    config_text = request.form.get("config", "")
    errors = []
    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            import base64, tempfile
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"], username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)
            script = f"""
import json, sys
path = {repr(server.get('kea_conf', '/etc/kea/kea-dhcp4.conf'))}
with open(path) as f: cfg = json.load(f)
for s in cfg.get('Dhcp4', {{}}).get('subnet4', []):
    if s['id'] == {subnet_id}:
        s['subnet'] = {repr(config_text.strip())}
        break
with open(path, 'w') as f: json.dump(cfg, f, indent=2)
print('ok')
"""
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if "ok" in out:
                ssh.exec_command("sudo systemctl restart isc-kea-dhcp4-server")
                results.append(f"✅ {server.get('name', server['ssh_host'])}: updated")
            else:
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {err or out}")
            ssh.close()
        except Exception as e:
            errors.append(f"❌ {server.get('name', server.get('ssh_host','?'))}: {str(e)}")
    for r in results: flash(r, "success")
    for e in errors: flash(e, "error")
    __user.audit("EDIT_SUBNET", str(subnet_id), f"action={action}")
    return redirect(url_for('subnets.subnets'))

# ─────────────────────────────────────────
# DDNS
# ─────────────────────────────────────────

@bp.route("/subnets/save-note", methods=["POST"])
@login_required
@_admin_required
def save_subnet_note():
    try:
        subnet_id = int(request.form.get("subnet_id"))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Invalid subnet ID"})
    notes = request.form.get("notes", "").strip()[:1000]
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO subnet_notes (subnet_id, notes) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE notes=%s, updated_at=NOW()
            """, (subnet_id, notes, notes))
        db.commit()
        db.close()
        __user.audit("SAVE_SUBNET_NOTE", str(subnet_id), f"Note updated")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─────────────────────────────────────────
# HA / Multi-server Status
# ─────────────────────────────────────────
