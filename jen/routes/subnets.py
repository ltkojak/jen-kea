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
bp = Blueprint("subnets", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




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
                routers = ""
                dns_servers = ""
                for opt in s.get("option-data", []):
                    if opt.get("name") == "routers":
                        routers = opt.get("data", "")
                    elif opt.get("name") == "domain-name-servers":
                        dns_servers = opt.get("data", "")
                kea_subnets[s["id"]] = {
                    "valid_lifetime": s.get("valid-lifetime", global_lifetime),
                    "renew_timer": s.get("renew-timer", global_renew),
                    "rebind_timer": s.get("rebind-timer", global_rebind),
                    "pools": pools,
                    "routers": routers,
                    "dns_servers": dns_servers,
                }
    except Exception:
        pass
    try:
        db = __db.get_kea_db()
        accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
        with db.cursor() as cur:
            for subnet_id, info in accessible_subnet_map.items():
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
                    "routers": kea.get("routers", ""),
                    "dns_servers": kea.get("dns_servers", ""),
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


def _get_kea_subnet_ids():
    """Return the set of subnet IDs Kea actually has configured right now."""
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            return {s["id"] for s in result["arguments"]["Dhcp4"].get("subnet4", [])}
    except Exception:
        pass
    return set()


@bp.route("/subnets/add")
@login_required
@_admin_required
def add_subnet():
    existing_ids = _get_kea_subnet_ids() | set(extensions.SUBNET_MAP.keys())
    suggested_id = max(existing_ids, default=0) + 1
    ssh_ready = os.path.exists(extensions.SSH_KEY_PATH) and bool(extensions.KEA_SSH_HOST)
    if not ssh_ready:
        flash("Subnet creation requires SSH to be configured. Go to Settings → Infrastructure to set it up.", "error")
        return redirect(url_for('subnets.subnets'))
    return render_template("add_subnet.html", suggested_id=suggested_id)


@bp.route("/subnets/add", methods=["POST"])
@login_required
@_admin_required
def add_subnet_post():
    import ipaddress

    def _valid_ip(addr):
        try:
            ipaddress.IPv4Address(addr.strip())
            return True
        except Exception:
            return False

    new_id     = request.form.get("subnet_id", "").strip()
    new_name   = request.form.get("name", "").strip()
    new_cidr   = request.form.get("cidr", "").strip()
    new_pool   = request.form.get("pool", "").strip()
    lifetime   = request.form.get("valid_lifetime", "").strip()
    renew      = request.form.get("renew_timer", "").strip()
    rebind     = request.form.get("rebind_timer", "").strip()
    routers    = ",".join(s.strip() for s in request.form.get("routers", "").split(",") if s.strip())
    dns        = ",".join(s.strip() for s in request.form.get("dns_servers", "").split(",") if s.strip())

    # ── Validation — catch everything before touching Kea or Jen's config ─────
    if not new_id or not new_id.isdigit() or int(new_id) <= 0:
        flash("Subnet ID must be a positive whole number.", "error")
        return redirect(url_for('subnets.add_subnet'))
    new_id = int(new_id)

    if new_id in extensions.SUBNET_MAP or new_id in _get_kea_subnet_ids():
        flash(f"Subnet ID {new_id} is already in use.", "error")
        return redirect(url_for('subnets.add_subnet'))

    if not new_name:
        flash("A friendly name is required.", "error")
        return redirect(url_for('subnets.add_subnet'))

    try:
        network = ipaddress.IPv4Network(new_cidr, strict=True)
    except Exception:
        flash(f"Invalid CIDR: {new_cidr} — e.g. 10.10.80.0/24", "error")
        return redirect(url_for('subnets.add_subnet'))

    # Check for CIDR overlap against every subnet Jen already knows about
    for sid, info in extensions.SUBNET_MAP.items():
        try:
            existing_net = ipaddress.IPv4Network(info["cidr"], strict=False)
            if network.overlaps(existing_net):
                flash(f"CIDR {new_cidr} overlaps with existing subnet '{info['name']}' ({info['cidr']}).", "error")
                return redirect(url_for('subnets.add_subnet'))
        except Exception:
            continue

    if not new_pool or not re.match(r'^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$', new_pool):
        flash("Pool range is required — format: start–end e.g. 10.10.80.50-10.10.80.250", "error")
        return redirect(url_for('subnets.add_subnet'))

    pool_start, pool_end = [p.strip() for p in new_pool.split("-")]
    if not _valid_ip(pool_start) or not _valid_ip(pool_end):
        flash("Pool start/end must be valid IP addresses.", "error")
        return redirect(url_for('subnets.add_subnet'))
    if ipaddress.IPv4Address(pool_start) not in network or ipaddress.IPv4Address(pool_end) not in network:
        flash(f"Pool range must fall within the CIDR {new_cidr}.", "error")
        return redirect(url_for('subnets.add_subnet'))

    if routers:
        bad = [ip for ip in routers.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid router IP(s): {', '.join(bad)}", "error")
            return redirect(url_for('subnets.add_subnet'))

    if dns:
        bad = [ip for ip in dns.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid DNS server IP(s): {', '.join(bad)}", "error")
            return redirect(url_for('subnets.add_subnet'))

    for t, label in [(lifetime, "Valid Lifetime"), (renew, "Renew Timer"), (rebind, "Rebind Timer")]:
        if t:
            try:
                if int(t) <= 0:
                    raise ValueError()
            except ValueError:
                flash(f"{label} must be a positive integer (seconds).", "error")
                return redirect(url_for('subnets.add_subnet'))
    # ─────────────────────────────────────────────────────────────────────────

    errors, results = [], []

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

            option_data = []
            if routers:
                option_data.append({"name": "routers", "code": 3, "space": "dhcp4",
                                     "csv-format": True, "data": routers})
            if dns:
                option_data.append({"name": "domain-name-servers", "code": 6, "space": "dhcp4",
                                     "csv-format": True, "data": dns})

            new_subnet_block = {
                "id": new_id,
                "subnet": new_cidr,
                "pools": [{"pool": new_pool}],
                "option-data": option_data,
            }
            if lifetime: new_subnet_block["valid-lifetime"] = int(lifetime)
            if renew:    new_subnet_block["renew-timer"]    = int(renew)
            if rebind:   new_subnet_block["rebind-timer"]   = int(rebind)

            script = f"""
import json, sys, shutil, subprocess, os

path   = {repr(kea_conf)}
backup = path + '.jen_backup'
shutil.copy2(path, backup)

with open(path) as f:
    cfg = json.load(f)

new_block = {json.dumps(new_subnet_block)}

if any(s['id'] == {new_id} for s in cfg.get('Dhcp4', {{}}).get('subnet4', [])):
    print('idexists')
    sys.exit(1)

cfg.setdefault('Dhcp4', {{}}).setdefault('subnet4', []).append(new_block)

tmp = path + '.jen_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

result = subprocess.run(['kea-dhcp4', '-t', tmp], capture_output=True, text=True)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

os.replace(tmp, path)
print('ok')
"""
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if out == "ok":
                _, rs, _ = ssh.exec_command(
                    "sudo systemctl restart kea-dhcp4-server 2>/dev/null || "
                    "sudo systemctl restart isc-kea-dhcp4-server 2>/dev/null; echo done"
                )
                rs.read()
                results.append(f"✅ {server.get('name', server['ssh_host'])}: subnet {new_id} created and Kea restarted")
            elif out == "idexists":
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: subnet ID {new_id} already exists on this server")
            elif out.startswith("testerror:"):
                error_detail = out[len("testerror:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: config validation failed — Kea NOT restarted, original config preserved. Error: {error_detail}")
            else:
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {err or out}")
            ssh.close()
        except Exception as e:
            errors.append(f"❌ {server.get('name', server.get('ssh_host', '?'))}: {str(e)}")

    if errors and not results:
        for e in errors:
            flash(e, "error")
        return redirect(url_for('subnets.add_subnet'))

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    # Register the new subnet with Jen only after Kea accepted it
    new_map = dict(extensions.SUBNET_MAP)
    new_map[new_id] = {"name": new_name, "cidr": new_cidr}
    __config.write_subnets_config(new_map)

    __user.audit("ADD_SUBNET", str(new_id), f"name={new_name} cidr={new_cidr} pool={new_pool}")
    return redirect(url_for('subnets.subnets'))


@bp.route("/subnets/delete/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def delete_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))

    subnet_name = extensions.SUBNET_MAP[subnet_id]["name"]

    # Block deletion if the subnet still has active leases or reservations —
    # deleting Kea config out from under live leases would orphan them.
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
            active_leases = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
            reservations = cur.fetchone()["cnt"]
        db.close()
    except Exception as e:
        flash(f"Could not verify subnet is safe to delete: {e}", "error")
        return redirect(url_for('subnets.subnets'))

    if active_leases > 0 or reservations > 0:
        parts = []
        if active_leases: parts.append(f"{active_leases} active lease(s)")
        if reservations:  parts.append(f"{reservations} reservation(s)")
        flash(f"Cannot delete '{subnet_name}' — it still has {' and '.join(parts)}. "
              f"Release the leases and remove the reservations first.", "error")
        return redirect(url_for('subnets.subnets'))

    errors, results = [], []

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

            script = f"""
import json, sys, shutil, subprocess, os

path   = {repr(kea_conf)}
backup = path + '.jen_backup'
shutil.copy2(path, backup)

with open(path) as f:
    cfg = json.load(f)

subnets = cfg.get('Dhcp4', {{}}).get('subnet4', [])
before = len(subnets)
subnets = [s for s in subnets if s['id'] != {subnet_id}]

if len(subnets) == before:
    print('notfound')
    sys.exit(0)

cfg['Dhcp4']['subnet4'] = subnets

tmp = path + '.jen_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

result = subprocess.run(['kea-dhcp4', '-t', tmp], capture_output=True, text=True)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

os.replace(tmp, path)
print('ok')
"""
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if out == "ok":
                _, rs, _ = ssh.exec_command(
                    "sudo systemctl restart kea-dhcp4-server 2>/dev/null || "
                    "sudo systemctl restart isc-kea-dhcp4-server 2>/dev/null; echo done"
                )
                rs.read()
                results.append(f"✅ {server.get('name', server['ssh_host'])}: subnet {subnet_id} removed and Kea restarted")
            elif out == "notfound":
                results.append(f"ℹ️ {server.get('name', server['ssh_host'])}: subnet {subnet_id} was not in Kea's config")
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

    if errors and not results:
        return redirect(url_for('subnets.subnets'))

    # Remove from Jen's own subnet map now that Kea no longer has it
    new_map = dict(extensions.SUBNET_MAP)
    new_map.pop(subnet_id, None)
    __config.write_subnets_config(new_map)

    __user.audit("DELETE_SUBNET", str(subnet_id), f"name={subnet_name}")
    return redirect(url_for('subnets.subnets'))


@bp.route("/subnets/edit/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for('subnets.subnets'))
    kea_data = _get_subnet_kea_data(subnet_id)
    return render_template("edit_subnet.html", subnet_id=subnet_id,
                           subnet=extensions.SUBNET_MAP[subnet_id],
                           kea=kea_data,
                           subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP))


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
        __user.audit("SAVE_SUBNET_NOTE", str(subnet_id), "Note updated")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─────────────────────────────────────────
# HA / Multi-server Status
# ─────────────────────────────────────────
