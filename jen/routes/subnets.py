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

def _get_subnet_kea_data(subnet_id):
    """Fetch current subnet config from Kea for pre-populating the edit form."""
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            global_lifetime = cfg.get("valid-lifetime", 0)
            global_renew    = cfg.get("renew-timer", 0)
            global_rebind   = cfg.get("rebind-timer", 0)
            for s in cfg.get("subnet4", []):
                if s["id"] == subnet_id:
                    pools = []
                    for p in s.get("pools", []):
                        pool_str = p.get("pool", "") if isinstance(p, dict) else str(p)
                        if pool_str:
                            pools.append(pool_str.strip())
                    # Extract option-data
                    routers = ""
                    dns_servers = ""
                    for opt in s.get("option-data", []):
                        if opt.get("name") == "routers":
                            routers = opt.get("data", "")
                        elif opt.get("name") == "domain-name-servers":
                            dns_servers = opt.get("data", "")
                    return {
                        "pools":          pools,
                        "pool_str":       pools[0] if pools else "",
                        "valid_lifetime": s.get("valid-lifetime", global_lifetime) or "",
                        "renew_timer":    s.get("renew-timer",    global_renew)    or "",
                        "rebind_timer":   s.get("rebind-timer",   global_rebind)   or "",
                        "routers":        routers,
                        "dns_servers":    dns_servers,
                    }
    except Exception:
        pass
    return {"pools": [], "pool_str": "", "valid_lifetime": "", "renew_timer": "",
            "rebind_timer": "", "routers": "", "dns_servers": ""}


@bp.route("/subnets/edit/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    kea_data = _get_subnet_kea_data(subnet_id)
    return render_template("edit_subnet.html", subnet_id=subnet_id,
                           subnet=extensions.SUBNET_MAP[subnet_id],
                           kea=kea_data,
                           subnet_map=extensions.SUBNET_MAP)


@bp.route("/subnets/edit/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_post(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))

    # Read form fields — empty string means "don't change this field"
    new_pool     = request.form.get("pool",          "").strip()
    new_lifetime = request.form.get("valid_lifetime","").strip()
    new_renew    = request.form.get("renew_timer",   "").strip()
    new_rebind   = request.form.get("rebind_timer",  "").strip()
    new_routers  = ",".join(s.strip() for s in request.form.get("routers",     "").split(",") if s.strip())
    new_dns      = ",".join(s.strip() for s in request.form.get("dns_servers", "").split(",") if s.strip())

    # ── Input validation — catch bad data BEFORE touching the config ──────────
    import ipaddress

    def _valid_ip(addr):
        try:
            ipaddress.IPv4Address(addr.strip())
            return True
        except Exception:
            return False

    if new_pool and not re.match(r'^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$', new_pool):
        flash("Invalid pool format. Use start–end e.g. 10.0.0.1–10.0.0.250", "error")
        return redirect(url_for('subnets.edit_subnet', subnet_id=subnet_id))

    if new_routers:
        bad = [ip for ip in new_routers.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid router IP(s): {', '.join(bad)}", "error")
            return redirect(url_for('subnets.edit_subnet', subnet_id=subnet_id))

    if new_dns:
        bad = [ip for ip in new_dns.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid DNS server IP(s): {', '.join(bad)} — enter one IP per entry, comma-separated (e.g. 9.9.9.9,149.112.112.112)", "error")
            return redirect(url_for('subnets.edit_subnet', subnet_id=subnet_id))

    for t, label in [(new_lifetime, "Valid Lifetime"), (new_renew, "Renew Timer"), (new_rebind, "Rebind Timer")]:
        if t:
            try:
                if int(t) <= 0:
                    raise ValueError()
            except ValueError:
                flash(f"{label} must be a positive integer (seconds).", "error")
                return redirect(url_for('subnets.edit_subnet', subnet_id=subnet_id))
    # ─────────────────────────────────────────────────────────────────────────

    errors  = []
    results = []

    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            import base64
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"],
                        username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)

            kea_conf = server.get('kea_conf', '/etc/kea/kea-dhcp4.conf')

            # Build remote script: backup → patch → kea-dhcp4 -t test → write or restore
            script = f"""
import json, sys, shutil, subprocess, os, tempfile

path   = {repr(kea_conf)}
backup = path + '.jen_backup'

# Make a backup before touching anything
shutil.copy2(path, backup)

with open(path) as f:
    cfg = json.load(f)

changed = False
for s in cfg.get('Dhcp4', {{}}).get('subnet4', []):
    if s['id'] != {subnet_id}:
        continue
    new_pool = {repr(new_pool)}
    if new_pool:
        s['pools'] = [{{'pool': new_pool}}]
        changed = True
    new_lifetime = {repr(new_lifetime)}
    new_renew    = {repr(new_renew)}
    new_rebind   = {repr(new_rebind)}
    if new_lifetime:
        s['valid-lifetime'] = int(new_lifetime); changed = True
    if new_renew:
        s['renew-timer'] = int(new_renew); changed = True
    if new_rebind:
        s['rebind-timer'] = int(new_rebind); changed = True
    new_routers = {repr(new_routers)}
    new_dns     = {repr(new_dns)}
    if new_routers or new_dns:
        opts = s.get('option-data', [])
        if new_routers:
            found = False
            for o in opts:
                if o.get('name') == 'routers':
                    o['data'] = new_routers; found = True; break
            if not found:
                opts.append({{'name': 'routers', 'code': 3, 'space': 'dhcp4',
                              'csv-format': True, 'data': new_routers}})
            changed = True
        if new_dns:
            found = False
            for o in opts:
                if o.get('name') == 'domain-name-servers':
                    o['data'] = new_dns; found = True; break
            if not found:
                opts.append({{'name': 'domain-name-servers', 'code': 6, 'space': 'dhcp4',
                              'csv-format': True, 'data': new_dns}})
            changed = True
        s['option-data'] = opts
    break

if not changed:
    print('nochange')
    sys.exit(0)

# Write to a temp file first, test it, then move into place
tmp = path + '.jen_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

# Run kea-dhcp4 -t against the temp file
result = subprocess.run(
    ['kea-dhcp4', '-t', tmp],
    capture_output=True, text=True
)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    # Config test failed — clean up temp, leave original untouched
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

# Config test passed — move temp into place
os.replace(tmp, path)
print('ok')
"""
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(
                f"echo {enc} | base64 -d | sudo python3"
            )
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if out == "nochange":
                results.append(f"ℹ️ {server.get('name', server['ssh_host'])}: nothing to change")
            elif out == "ok":
                # Config validated — now restart Kea
                _, rs, re_ = ssh.exec_command(
                    "sudo systemctl restart kea-dhcp4-server 2>/dev/null || "
                    "sudo systemctl restart isc-kea-dhcp4-server 2>/dev/null; echo done"
                )
                rs.read()
                results.append(f"✅ {server.get('name', server['ssh_host'])}: config validated, updated and restarted")
            elif out.startswith("testerror:"):
                error_detail = out[len("testerror:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: config validation failed — Kea NOT restarted, original config preserved. Error: {error_detail}")
            else:
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {err or out}")
            ssh.close()
        except Exception as e:
            errors.append(f"❌ {server.get('name', server.get('ssh_host', '?'))}: {str(e)}")

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    changes = []
    if new_pool:     changes.append(f"pool={new_pool}")
    if new_lifetime: changes.append(f"valid-lifetime={new_lifetime}")
    if new_renew:    changes.append(f"renew-timer={new_renew}")
    if new_rebind:   changes.append(f"rebind-timer={new_rebind}")
    if new_routers:  changes.append(f"routers={new_routers}")
    if new_dns:      changes.append(f"dns={new_dns}")
    __user.audit("EDIT_SUBNET", str(subnet_id), ", ".join(changes) if changes else "no changes")

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
