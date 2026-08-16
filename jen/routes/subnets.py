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
import jen.services.kea6 as __kea6
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
        with __db.kea_db() as db:
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
    except Exception as e:
        flash(f"Could not load subnet data: {str(e)}", "error")
    ssh_ready = os.path.exists(extensions.SSH_KEY_PATH) and bool(extensions.KEA_SSH_HOST)
    subnet_notes = {}
    try:
        with __db.jen_db() as jdb:
            with jdb.cursor() as jcur:
                jcur.execute("SELECT subnet_id, notes FROM subnet_notes")
                for row in jcur.fetchall():
                    subnet_notes[row["subnet_id"]] = row["notes"]
    except Exception:
        pass
    return render_template("subnets.html", subnets=subnet_data, ssh_ready=ssh_ready,
                           subnet_notes=subnet_notes, subnets6=_get_subnets6_data())

def _get_subnets6_data() -> list:
    """
    v5.0 Phase 2 — read-only IPv6 subnet summary for the Subnets page.
    Deliberately gated on is_ipv6_enabled() rather than only checking
    whether SUBNET6_MAP is non-empty: an admin who has since disabled v6
    shouldn't keep seeing v6 cards just because [subnets6] config entries
    are still on disk — matching the "display gate checked before
    SUBNET6_MAP is ever populated" principle from Phase 1.

    Each entry carries paired_subnet4_id (from config, see
    AppConfig.derive_subnet_map) so the template can nest it as a second
    block on the matching v4 card, or render it standalone when unpaired.
    No live Kea config-get here (unlike the v4 branch above) — Phase 2 is
    read-only against Jen's own DB layer; pool/lifetime detail for v6
    subnets is a Phase 3 write-support item once the v6 config-editing
    path exists.
    """
    if not __kea6.is_ipv6_enabled() or not extensions.SUBNET6_MAP:
        return []
    result = []
    for subnet_id, info in extensions.SUBNET6_MAP.items():
        try:
            active = len(__kea6.list_lease6(subnet_id=subnet_id))
            reserved = len(__kea6.get_ipv6_reservations(subnet_id=subnet_id))
        except Exception:
            active = reserved = 0
        result.append({
            "id": subnet_id,
            "name": info["name"],
            "cidr": info["cidr"],
            "paired_subnet4_id": info.get("paired_subnet4_id"),
            "active": active,
            "reserved": reserved,
        })
    return result


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


def _build_subnet_patch_script(subnet_id, kea_conf, new_pool, extra_pools,
                                new_lifetime, new_renew, new_rebind,
                                new_routers, new_dns, dry_run=False):
    """
    Build the remote Python script that patches subnet_id's config,
    writes it to a temp file, and runs `kea-dhcp4 -t` against it.

    v4.4.24: extracted from edit_subnet_post() so the same tested,
    hardened patch-and-validate logic can be reused by the new preview
    endpoint (dry_run=True — test only, never touch the live config)
    without duplicating it. edit_subnet_post() itself is unchanged
    behaviorally: it calls this with dry_run=False, which produces the
    exact same script it always has.

    dry_run=False (edit_subnet_post's actual apply path, unchanged):
      test passes  -> os.replace(tmp, path), prints 'ok'
      test fails   -> os.unlink(tmp), prints 'testerror:...', original
                       config untouched either way
    dry_run=True (the new preview endpoint):
      test passes  -> os.unlink(tmp) (never applied), prints 'preview-ok'
      test fails   -> os.unlink(tmp), prints 'testerror:...'
      Live config is never touched in either outcome — the backup
      step is skipped entirely too, since nothing is ever written to
      the real path.
    """
    if dry_run:
        backup_step = ""
        on_pass = "os.unlink(tmp)\nprint('preview-ok')"
    else:
        backup_step = "# Make a backup before touching anything\nshutil.copy2(path, backup)\n\n"
        on_pass = "# Config test passed — move temp into place\nos.replace(tmp, path)\nprint('ok')"

    return f"""
import json, sys, shutil, subprocess, os, tempfile

path   = {repr(kea_conf)}
backup = path + '.jen_backup'

{backup_step}with open(path) as f:
    cfg = json.load(f)

changed = False
for s in cfg.get('Dhcp4', {{}}).get('subnet4', []):
    if s['id'] != {subnet_id}:
        continue
    new_pool = {repr(new_pool)}
    if new_pool:
        extra_pools = {repr(extra_pools)}
        s['pools'] = [{{'pool': new_pool}}] + [{{'pool': p}} for p in extra_pools]
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
try:
    result = subprocess.run(
        ['kea-dhcp4', '-t', tmp],
        capture_output=True, text=True
    )
except FileNotFoundError:
    os.unlink(tmp)
    print('missingbinary:kea-dhcp4')
    sys.exit(1)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    # Config test failed — clean up temp, leave original untouched
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

{on_pass}
"""


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
            __auth.paramiko_load_known_hosts(ssh)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"],
                        username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)
            # Persist any newly-accepted host key (AutoAddPolicy only adds
            # it in-memory) so the *next* connection actually checks against
            # it instead of trusting a fresh key blind every single time.
            try:
                ssh.save_host_keys(extensions.SSH_KNOWN_HOSTS)
            except Exception:
                pass

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
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {binary} is not installed on this server — install it and try again.")
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
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for('subnets.subnets'))

    subnet_name = extensions.SUBNET_MAP[subnet_id]["name"]

    # Block deletion if the subnet still has active leases or reservations —
    # deleting Kea config out from under live leases would orphan them.
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active_leases = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reservations = cur.fetchone()["cnt"]
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
            __auth.paramiko_load_known_hosts(ssh)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"],
                        username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)
            # Persist any newly-accepted host key (AutoAddPolicy only adds
            # it in-memory) so the *next* connection actually checks against
            # it instead of trusting a fresh key blind every single time.
            try:
                ssh.save_host_keys(extensions.SSH_KNOWN_HOSTS)
            except Exception:
                pass

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
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {binary} is not installed on this server — install it and try again.")
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


def _parse_and_validate_subnet_edit_form(form):
    """
    Parse and validate the subnet-edit form fields shared by
    edit_subnet_post() and the preview endpoint. Returns
    (fields_dict, None) on success or (None, error_message) on the
    first validation failure. Deliberately returns rather than
    flashing/redirecting itself — each caller decides how to present
    the error (flash+redirect for the real submit, JSON for the
    preview AJAX call) — so the two callers can't drift out of sync
    with each other the way the plugin registry version and the CSRF
    token fields did earlier.
    """
    import ipaddress

    new_pool     = form.get("pool",          "").strip()
    extra_pools  = [p.strip() for p in form.get("extra_pools", "").split("|") if p.strip()]
    new_lifetime = form.get("valid_lifetime","").strip()
    new_renew    = form.get("renew_timer",   "").strip()
    new_rebind   = form.get("rebind_timer",  "").strip()
    new_routers  = ",".join(s.strip() for s in form.get("routers",     "").split(",") if s.strip())
    new_dns      = ",".join(s.strip() for s in form.get("dns_servers", "").split(",") if s.strip())

    def _valid_ip(addr):
        try:
            ipaddress.IPv4Address(addr.strip())
            return True
        except Exception:
            return False

    if new_pool and not re.match(r'^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$', new_pool):
        return None, "Invalid pool format. Use start–end e.g. 10.0.0.1–10.0.0.250"

    if new_routers:
        bad = [ip for ip in new_routers.split(",") if not _valid_ip(ip)]
        if bad:
            return None, f"Invalid router IP(s): {', '.join(bad)}"

    if new_dns:
        bad = [ip for ip in new_dns.split(",") if not _valid_ip(ip)]
        if bad:
            return None, f"Invalid DNS server IP(s): {', '.join(bad)} — enter one IP per entry, comma-separated (e.g. 9.9.9.9,149.112.112.112)"

    for t, label in [(new_lifetime, "Valid Lifetime"), (new_renew, "Renew Timer"), (new_rebind, "Rebind Timer")]:
        if t:
            try:
                if int(t) <= 0:
                    raise ValueError()
            except ValueError:
                return None, f"{label} must be a positive integer (seconds)."

    return {
        "new_pool": new_pool,
        "extra_pools": extra_pools,
        "new_lifetime": new_lifetime,
        "new_renew": new_renew,
        "new_rebind": new_rebind,
        "new_routers": new_routers,
        "new_dns": new_dns,
    }, None


def _compute_subnet_edit_diff(subnet_id, fields):
    """
    Build a human-readable list of {field, old, new} for the preview
    UI — only for fields the user actually submitted a new value for
    (empty means "don't change", per the same convention the rest of
    this form already uses), compared against the subnet's current
    live values from Kea.
    """
    current = _get_subnet_kea_data(subnet_id)
    diff = []
    if fields["new_pool"]:
        diff.append({"field": "Primary Pool",
                      "old": current.get("pool_str") or "(none)",
                      "new": fields["new_pool"]})
    if fields["extra_pools"]:
        old_extra = ", ".join(current.get("pools", [])[1:]) or "(none)"
        diff.append({"field": "Extra Pools", "old": old_extra,
                      "new": ", ".join(fields["extra_pools"])})
    if fields["new_lifetime"]:
        diff.append({"field": "Valid Lifetime",
                      "old": str(current.get("valid_lifetime") or "(unset)"),
                      "new": fields["new_lifetime"]})
    if fields["new_renew"]:
        diff.append({"field": "Renew Timer",
                      "old": str(current.get("renew_timer") or "(unset)"),
                      "new": fields["new_renew"]})
    if fields["new_rebind"]:
        diff.append({"field": "Rebind Timer",
                      "old": str(current.get("rebind_timer") or "(unset)"),
                      "new": fields["new_rebind"]})
    if fields["new_routers"]:
        diff.append({"field": "Routers",
                      "old": current.get("routers") or "(unset)",
                      "new": fields["new_routers"]})
    if fields["new_dns"]:
        diff.append({"field": "DNS Servers",
                      "old": current.get("dns_servers") or "(unset)",
                      "new": fields["new_dns"]})
    return diff


@bp.route("/subnets/edit/<int:subnet_id>/preview", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_preview(subnet_id):
    """
    Dry-run preview for a subnet edit: validates the form (via the
    exact same function edit_subnet_post() itself uses, so the two
    can't drift apart), computes a human-readable diff against the
    subnet's current live config, and runs kea-dhcp4 -t against each
    configured server WITHOUT ever touching the live config file
    (dry_run=True in _build_subnet_patch_script() — see there for
    exactly what that guarantees, verified directly by executing both
    the pass and fail paths and confirming the original file is
    byte-identical before and after either way).

    Never applies anything itself — edit_subnet_post() is the only
    route that ever writes to the live config, completely unchanged,
    reached only after the user reviews this preview and explicitly
    submits the real form.
    """
    if subnet_id not in extensions.SUBNET_MAP:
        return jsonify({"ok": False, "error": "Subnet not found."}), 404
    if not current_user.can_access_subnet(subnet_id):
        return jsonify({"ok": False, "error": "Access denied."}), 403

    fields, error = _parse_and_validate_subnet_edit_form(request.form)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    if not any(fields.values()):
        return jsonify({"ok": True, "no_changes": True, "diff": [], "servers": [], "all_passed": True})

    diff = _compute_subnet_edit_diff(subnet_id, fields)

    server_results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            import base64
            import paramiko
            ssh = paramiko.SSHClient()
            __auth.paramiko_load_known_hosts(ssh)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"],
                        username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)
            try:
                ssh.save_host_keys(extensions.SSH_KNOWN_HOSTS)
            except Exception:
                pass

            kea_conf = server.get('kea_conf', '/etc/kea/kea-dhcp4.conf')
            script = _build_subnet_patch_script(
                subnet_id, kea_conf, fields["new_pool"], fields["extra_pools"],
                fields["new_lifetime"], fields["new_renew"], fields["new_rebind"],
                fields["new_routers"], fields["new_dns"], dry_run=True,
            )
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            ssh.close()

            if out == "preview-ok":
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif out == "nochange":
                server_results.append({"name": name, "ok": True, "message": "No changes for this server"})
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                server_results.append({"name": name, "ok": False, "missing_binary": binary,
                                       "message": f"{binary} is not installed on this server."})
            elif out.startswith("testerror:"):
                server_results.append({"name": name, "ok": False, "message": out[len("testerror:"):]})
            else:
                server_results.append({"name": name, "ok": False, "message": err or out or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "no_changes": False, "diff": diff,
                     "servers": server_results, "all_passed": all_passed})


@bp.route("/subnets/edit/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_post(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for('subnets.subnets'))

    fields, error = _parse_and_validate_subnet_edit_form(request.form)
    if error:
        flash(error, "error")
        return redirect(url_for('subnets.edit_subnet', subnet_id=subnet_id))
    new_pool     = fields["new_pool"]
    extra_pools  = fields["extra_pools"]
    new_lifetime = fields["new_lifetime"]
    new_renew    = fields["new_renew"]
    new_rebind   = fields["new_rebind"]
    new_routers  = fields["new_routers"]
    new_dns      = fields["new_dns"]

    errors  = []
    results = []

    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            import base64
            import paramiko
            ssh = paramiko.SSHClient()
            __auth.paramiko_load_known_hosts(ssh)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"],
                        username=server.get("ssh_user", extensions.KEA_SSH_USER),
                        key_filename=extensions.SSH_KEY_PATH, timeout=10)
            # Persist any newly-accepted host key (AutoAddPolicy only adds
            # it in-memory) so the *next* connection actually checks against
            # it instead of trusting a fresh key blind every single time.
            try:
                ssh.save_host_keys(extensions.SSH_KNOWN_HOSTS)
            except Exception:
                pass

            kea_conf = server.get('kea_conf', '/etc/kea/kea-dhcp4.conf')

            script = _build_subnet_patch_script(
                subnet_id, kea_conf, new_pool, extra_pools,
                new_lifetime, new_renew, new_rebind, new_routers, new_dns,
                dry_run=False,
            )
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
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {binary} is not installed on this server — install it and try again.")
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


# ── v6 subnet editing (Phase 3) ──────────────────────────────────────────────

def _parse_and_validate_subnet6_edit_form(form):
    """
    v5.0 Phase 3 — v6 counterpart of _parse_and_validate_subnet_edit_form().
    Deliberately a separate function rather than a shared one with a v4/v6
    branch inside it: the field sets genuinely differ (preferred-lifetime
    exists only for v6; routers exists only for v4), and a shared function
    trying to cover both would need per-field "does this apply to this
    protocol" conditionals scattered through it — harder to read than two
    small, honest functions.
    """
    import ipaddress
    new_pool       = form.get("pool", "").strip()
    extra_pools    = [p.strip() for p in form.get("extra_pools", "").split("|") if p.strip()]
    new_preferred  = form.get("preferred_lifetime", "").strip()
    new_valid      = form.get("valid_lifetime", "").strip()
    new_renew      = form.get("renew_timer", "").strip()
    new_rebind     = form.get("rebind_timer", "").strip()
    new_dns        = ",".join(s.strip() for s in form.get("dns_servers", "").split(",") if s.strip())

    def _valid_ip6(addr):
        try:
            ipaddress.IPv6Address(addr.strip())
            return True
        except Exception:
            return False

    if new_pool:
        parts = [p.strip() for p in new_pool.split("-")]
        if len(parts) == 2:
            if not (_valid_ip6(parts[0]) and _valid_ip6(parts[1])):
                return None, f"Invalid pool range: {new_pool}"
        else:
            # Not a range — must be a valid CIDR (Kea v6 pools also accept
            # CIDR notation, unlike v4's start-end-only convention).
            try:
                ipaddress.IPv6Network(new_pool, strict=False)
            except ValueError:
                return None, f"Invalid pool — use a range (2001:db8::10-2001:db8::20) or CIDR (2001:db8::/64): {new_pool}"

    if new_dns:
        bad = [ip for ip in new_dns.split(",") if not _valid_ip6(ip)]
        if bad:
            return None, f"Invalid DNS server address(es): {', '.join(bad)}"

    for t, label in [(new_preferred, "Preferred Lifetime"), (new_valid, "Valid Lifetime"),
                     (new_renew, "Renew Timer"), (new_rebind, "Rebind Timer")]:
        if t:
            try:
                if int(t) <= 0:
                    raise ValueError()
            except ValueError:
                return None, f"{label} must be a positive integer (seconds)."

    if new_preferred and new_valid:
        try:
            if int(new_preferred) > int(new_valid):
                return None, "Preferred Lifetime cannot exceed Valid Lifetime."
        except ValueError:
            pass  # already caught above

    return {
        "new_pool": new_pool, "extra_pools": extra_pools,
        "new_preferred": new_preferred, "new_valid": new_valid,
        "new_renew": new_renew, "new_rebind": new_rebind, "new_dns": new_dns,
    }, None


def _compute_subnet6_edit_diff(subnet_id, fields):
    """v6 counterpart of _compute_subnet_edit_diff() — only for fields the
    user actually submitted a new value for, against the subnet's current
    live Kea config."""
    current = __kea6.get_subnet6_kea_data(subnet_id)
    diff = []
    if fields["new_pool"]:
        diff.append({"field": "Primary Pool", "old": current.get("pool_str") or "(none)",
                     "new": fields["new_pool"]})
    if fields["extra_pools"]:
        old_extra = ", ".join(current.get("pools", [])[1:]) or "(none)"
        diff.append({"field": "Extra Pools", "old": old_extra,
                     "new": ", ".join(fields["extra_pools"])})
    if fields["new_preferred"]:
        diff.append({"field": "Preferred Lifetime",
                     "old": str(current.get("preferred_lifetime") or "(unset)"),
                     "new": fields["new_preferred"]})
    if fields["new_valid"]:
        diff.append({"field": "Valid Lifetime",
                     "old": str(current.get("valid_lifetime") or "(unset)"),
                     "new": fields["new_valid"]})
    if fields["new_renew"]:
        diff.append({"field": "Renew Timer", "old": str(current.get("renew_timer") or "(unset)"),
                     "new": fields["new_renew"]})
    if fields["new_rebind"]:
        diff.append({"field": "Rebind Timer", "old": str(current.get("rebind_timer") or "(unset)"),
                     "new": fields["new_rebind"]})
    if fields["new_dns"]:
        diff.append({"field": "DNS Servers", "old": current.get("dns_servers") or "(unset)",
                     "new": fields["new_dns"]})
    return diff


@bp.route("/subnets/edit6/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet6(subnet_id):
    if subnet_id not in extensions.SUBNET6_MAP:
        flash("IPv6 subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))
    kea_data = __kea6.get_subnet6_kea_data(subnet_id)
    return render_template("edit_subnet6.html", subnet_id=subnet_id,
                           subnet=extensions.SUBNET6_MAP[subnet_id], kea=kea_data)


@bp.route("/subnets/edit6/<int:subnet_id>/preview", methods=["POST"])
@login_required
@_admin_required
def edit_subnet6_preview(subnet_id):
    """Dry-run preview for a v6 subnet edit — same guarantee as the v4
    preview endpoint: kea-dhcp6 -t runs against a temp file on each
    configured server, the live kea-dhcp6.conf is never touched under
    any outcome (dry_run=True in build_subnet6_patch_script())."""
    if subnet_id not in extensions.SUBNET6_MAP:
        return jsonify({"ok": False, "error": "IPv6 subnet not found."}), 404

    fields, error = _parse_and_validate_subnet6_edit_form(request.form)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    if not any(fields.values()):
        return jsonify({"ok": True, "no_changes": True, "diff": [], "servers": [], "all_passed": True})

    diff = _compute_subnet6_edit_diff(subnet_id, fields)

    server_results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            import base64
            ssh = __kea6._connect_ssh(server)
            try:
                kea6_conf = __kea6._kea6_conf_path(server)
                script = __kea6.build_subnet6_patch_script(
                    subnet_id, kea6_conf, fields["new_pool"], fields["extra_pools"],
                    fields["new_preferred"], fields["new_valid"], fields["new_renew"],
                    fields["new_rebind"], fields["new_dns"], dry_run=True,
                )
                enc = base64.b64encode(script.encode()).decode()
                _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
            finally:
                ssh.close()

            if out == "preview-ok":
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif out == "nochange":
                server_results.append({"name": name, "ok": True, "message": "No changes for this server"})
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                server_results.append({"name": name, "ok": False, "missing_binary": binary,
                                       "message": f"{binary} is not installed on this server."})
            elif out.startswith("testerror:"):
                server_results.append({"name": name, "ok": False, "message": out[len("testerror:"):]})
            else:
                server_results.append({"name": name, "ok": False, "message": err or out or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "no_changes": False, "diff": diff,
                    "servers": server_results, "all_passed": all_passed})


@bp.route("/subnets/edit6/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet6_post(subnet_id):
    if subnet_id not in extensions.SUBNET6_MAP:
        flash("IPv6 subnet not found.", "error")
        return redirect(url_for('subnets.subnets'))

    fields, error = _parse_and_validate_subnet6_edit_form(request.form)
    if error:
        flash(error, "error")
        return redirect(url_for('subnets.edit_subnet6', subnet_id=subnet_id))

    errors, results = [], []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            import base64
            ssh = __kea6._connect_ssh(server)
            kea6_conf = __kea6._kea6_conf_path(server)
            script = __kea6.build_subnet6_patch_script(
                subnet_id, kea6_conf, fields["new_pool"], fields["extra_pools"],
                fields["new_preferred"], fields["new_valid"], fields["new_renew"],
                fields["new_rebind"], fields["new_dns"], dry_run=False,
            )
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if out == "nochange":
                results.append(f"ℹ️ {server.get('name', server['ssh_host'])}: nothing to change")
            elif out == "ok":
                # Config validated — restart kea-dhcp6-server (dual-name,
                # same fallback the v4 restart and the Phase 1 toggle use).
                out2, err2 = __kea6._dual_name_systemctl(ssh, "restart")
                results.append(f"✅ {server.get('name', server['ssh_host'])}: config validated, updated and restarted")
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:"):]
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {binary} is not installed on this server — install it and try again.")
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
    if fields["new_pool"]:      changes.append(f"pool={fields['new_pool']}")
    if fields["new_preferred"]: changes.append(f"preferred-lifetime={fields['new_preferred']}")
    if fields["new_valid"]:     changes.append(f"valid-lifetime={fields['new_valid']}")
    if fields["new_renew"]:     changes.append(f"renew-timer={fields['new_renew']}")
    if fields["new_rebind"]:    changes.append(f"rebind-timer={fields['new_rebind']}")
    if fields["new_dns"]:       changes.append(f"dns={fields['new_dns']}")
    __user.audit("EDIT_SUBNET6", str(subnet_id), ", ".join(changes) if changes else "no changes")

    return redirect(url_for('subnets.subnets'))


@bp.route("/subnets/save-note", methods=["POST"])
@login_required
@_admin_required
def save_subnet_note():
    try:
        subnet_id = int(request.form.get("subnet_id"))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Invalid subnet ID"})
    if not current_user.can_access_subnet(subnet_id):
        return jsonify({"ok": False, "error": "You do not have access to that subnet."}), 403
    notes = request.form.get("notes", "").strip()[:1000]
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO subnet_notes (subnet_id, notes) VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE notes=%s, updated_at=NOW()
                """, (subnet_id, notes, notes))
            db.commit()
        __user.audit("SAVE_SUBNET_NOTE", str(subnet_id), "Note updated")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
