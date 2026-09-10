"""
jen/routes/subnets.py
──────────────────────
Subnet view and editing routes.
"""

import logging
import os
import re

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.kea_config_edit as __edit
import jen.services.kea_host as __host
from jen import extensions
from jen.services.access import admin_required as _admin_required

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
                    subnet_data.append(
                        {
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
                        }
                    )
    except Exception as e:
        logger.error(f"Could not load subnet data: {e}")
        flash("Could not load subnet data. Check server logs for details.", "error")
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
    return render_template(
        "subnets.html",
        subnets=subnet_data,
        ssh_ready=ssh_ready,
        subnet_notes=subnet_notes,
        subnets6=_get_subnets6_data(),
    )


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
        result.append(
            {
                "id": subnet_id,
                "name": info["name"],
                "cidr": info["cidr"],
                "paired_subnet4_id": info.get("paired_subnet4_id"),
                "active": active,
                "reserved": reserved,
            }
        )
    return result


def _get_subnet_kea_data(subnet_id):
    """Fetch current subnet config from Kea for pre-populating the edit form."""
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            global_lifetime = cfg.get("valid-lifetime", 0)
            global_renew = cfg.get("renew-timer", 0)
            global_rebind = cfg.get("rebind-timer", 0)
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
                        "pools": pools,
                        "pool_str": pools[0] if pools else "",
                        "valid_lifetime": s.get("valid-lifetime", global_lifetime) or "",
                        "renew_timer": s.get("renew-timer", global_renew) or "",
                        "rebind_timer": s.get("rebind-timer", global_rebind) or "",
                        "routers": routers,
                        "dns_servers": dns_servers,
                    }
    except Exception:
        pass
    return {
        "pools": [],
        "pool_str": "",
        "valid_lifetime": "",
        "renew_timer": "",
        "rebind_timer": "",
        "routers": "",
        "dns_servers": "",
    }


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
        flash("Subnet creation requires SSH to be configured. Go to Settings → Kea → SSH to set it up.", "error")
        return redirect(url_for("subnets.subnets"))
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

    new_id = request.form.get("subnet_id", "").strip()
    new_name = request.form.get("name", "").strip()
    new_cidr = request.form.get("cidr", "").strip()
    new_pool = request.form.get("pool", "").strip()
    lifetime = request.form.get("valid_lifetime", "").strip()
    renew = request.form.get("renew_timer", "").strip()
    rebind = request.form.get("rebind_timer", "").strip()
    routers = ",".join(s.strip() for s in request.form.get("routers", "").split(",") if s.strip())
    dns = ",".join(s.strip() for s in request.form.get("dns_servers", "").split(",") if s.strip())

    # ── Validation — catch everything before touching Kea or Jen's config ─────
    if not new_id or not new_id.isdigit() or int(new_id) <= 0:
        flash("Subnet ID must be a positive whole number.", "error")
        return redirect(url_for("subnets.add_subnet"))
    new_id = int(new_id)

    if new_id in extensions.SUBNET_MAP or new_id in _get_kea_subnet_ids():
        flash(f"Subnet ID {new_id} is already in use.", "error")
        return redirect(url_for("subnets.add_subnet"))

    if not new_name:
        flash("A friendly name is required.", "error")
        return redirect(url_for("subnets.add_subnet"))

    try:
        network = ipaddress.IPv4Network(new_cidr, strict=True)
    except Exception:
        flash(f"Invalid CIDR: {new_cidr} — e.g. 10.10.80.0/24", "error")
        return redirect(url_for("subnets.add_subnet"))

    # Check for CIDR overlap against every subnet Jen already knows about
    for _sid, info in extensions.SUBNET_MAP.items():
        try:
            existing_net = ipaddress.IPv4Network(info["cidr"], strict=False)
            if network.overlaps(existing_net):
                flash(f"CIDR {new_cidr} overlaps with existing subnet '{info['name']}' ({info['cidr']}).", "error")
                return redirect(url_for("subnets.add_subnet"))
        except Exception:
            continue

    if not new_pool or not re.match(r"^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$", new_pool):
        flash("Pool range is required — format: start–end e.g. 10.10.80.50-10.10.80.250", "error")
        return redirect(url_for("subnets.add_subnet"))

    pool_start, pool_end = [p.strip() for p in new_pool.split("-")]
    if not _valid_ip(pool_start) or not _valid_ip(pool_end):
        flash("Pool start/end must be valid IP addresses.", "error")
        return redirect(url_for("subnets.add_subnet"))
    if ipaddress.IPv4Address(pool_start) not in network or ipaddress.IPv4Address(pool_end) not in network:
        flash(f"Pool range must fall within the CIDR {new_cidr}.", "error")
        return redirect(url_for("subnets.add_subnet"))

    if routers:
        bad = [ip for ip in routers.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid router IP(s): {', '.join(bad)}", "error")
            return redirect(url_for("subnets.add_subnet"))

    if dns:
        bad = [ip for ip in dns.split(",") if not _valid_ip(ip)]
        if bad:
            flash(f"Invalid DNS server IP(s): {', '.join(bad)}", "error")
            return redirect(url_for("subnets.add_subnet"))

    for t, label in [(lifetime, "Valid Lifetime"), (renew, "Renew Timer"), (rebind, "Rebind Timer")]:
        if t:
            try:
                if int(t) <= 0:
                    raise ValueError()
            except ValueError:
                flash(f"{label} must be a positive integer (seconds).", "error")
                return redirect(url_for("subnets.add_subnet"))
    # ─────────────────────────────────────────────────────────────────────────

    option_data = []
    if routers:
        option_data.append({"name": "routers", "code": 3, "space": "dhcp4", "csv-format": True, "data": routers})
    if dns:
        option_data.append(
            {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "csv-format": True, "data": dns}
        )
    new_subnet_block = {
        "id": new_id,
        "subnet": new_cidr,
        "pools": [{"pool": new_pool}],
        "option-data": option_data,
    }
    if lifetime:
        new_subnet_block["valid-lifetime"] = int(lifetime)
    if renew:
        new_subnet_block["renew-timer"] = int(renew)
    if rebind:
        new_subnet_block["rebind-timer"] = int(rebind)

    errors, results = [], []

    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            cfg = __host.read_config(server, "dhcp4")
            if cfg is None:
                errors.append(f"❌ {name}: kea-dhcp4.conf not found on this server")
                continue
            cfg, code = __edit.add_subnet4(cfg, new_subnet_block)
            if code == "idexists":
                errors.append(f"❌ {name}: subnet ID {new_id} already exists on this server")
                continue
            res = __host.apply_config(server, "dhcp4", cfg)
            if res["code"] == "ok":
                restart = __host.service_action(server, "dhcp4", "restart")
                if restart["ok"]:
                    results.append(f"✅ {name}: subnet {new_id} created and Kea restarted")
                else:
                    results.append(f"✅ {name}: subnet {new_id} created — restart Kea manually ({restart['detail']})")
            elif res["code"] == "missingbinary":
                errors.append(f"❌ {name}: {res['binary']} is not installed on this server — install it and try again.")
            elif res["code"] == "testerror":
                errors.append(
                    f"❌ {name}: config validation failed — Kea NOT restarted, original config preserved. "
                    f"Error: {res['detail']}"
                )
            else:
                errors.append(f"❌ {name}: {res['detail']}")
        except Exception as e:
            errors.append(f"❌ {name}: {e}")

    if errors and not results:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("subnets.add_subnet"))

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    # Register the new subnet with Jen only after Kea accepted it
    new_map = dict(extensions.SUBNET_MAP)
    new_map[new_id] = {"name": new_name, "cidr": new_cidr}
    __config.write_subnets_config(new_map)

    __user.audit("ADD_SUBNET", str(new_id), f"name={new_name} cidr={new_cidr} pool={new_pool}")
    return redirect(url_for("subnets.subnets"))


@bp.route("/subnets/delete/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def delete_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for("subnets.subnets"))

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
        logger.error(f"Could not verify subnet {subnet_id} is safe to delete: {e}")
        flash("Could not verify subnet is safe to delete. Check server logs for details.", "error")
        return redirect(url_for("subnets.subnets"))

    if active_leases > 0 or reservations > 0:
        parts = []
        if active_leases:
            parts.append(f"{active_leases} active lease(s)")
        if reservations:
            parts.append(f"{reservations} reservation(s)")
        flash(
            f"Cannot delete '{subnet_name}' — it still has {' and '.join(parts)}. "
            f"Release the leases and remove the reservations first.",
            "error",
        )
        return redirect(url_for("subnets.subnets"))

    errors, results = [], []

    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            cfg = __host.read_config(server, "dhcp4")
            if cfg is None:
                errors.append(f"❌ {name}: kea-dhcp4.conf not found on this server")
                continue
            cfg, code = __edit.delete_subnet4(cfg, subnet_id)
            if code == "notfound":
                results.append(f"ℹ️ {name}: subnet {subnet_id} was not in Kea's config")
                continue
            res = __host.apply_config(server, "dhcp4", cfg)
            if res["code"] == "ok":
                restart = __host.service_action(server, "dhcp4", "restart")
                if restart["ok"]:
                    results.append(f"✅ {name}: subnet {subnet_id} removed and Kea restarted")
                else:
                    results.append(
                        f"✅ {name}: subnet {subnet_id} removed — restart Kea manually ({restart['detail']})"
                    )
            elif res["code"] == "missingbinary":
                errors.append(f"❌ {name}: {res['binary']} is not installed on this server — install it and try again.")
            elif res["code"] == "testerror":
                errors.append(
                    f"❌ {name}: config validation failed — Kea NOT restarted, original config preserved. "
                    f"Error: {res['detail']}"
                )
            else:
                errors.append(f"❌ {name}: {res['detail']}")
        except Exception as e:
            errors.append(f"❌ {name}: {e}")

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    if errors and not results:
        return redirect(url_for("subnets.subnets"))

    # Remove from Jen's own subnet map now that Kea no longer has it
    new_map = dict(extensions.SUBNET_MAP)
    new_map.pop(subnet_id, None)
    __config.write_subnets_config(new_map)

    __user.audit("DELETE_SUBNET", str(subnet_id), f"name={subnet_name}")
    return redirect(url_for("subnets.subnets"))


@bp.route("/subnets/edit/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for("subnets.subnets"))
    kea_data = _get_subnet_kea_data(subnet_id)
    return render_template(
        "edit_subnet.html",
        subnet_id=subnet_id,
        subnet=extensions.SUBNET_MAP[subnet_id],
        kea=kea_data,
        subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP),
    )


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

    new_pool = form.get("pool", "").strip()
    extra_pools = [p.strip() for p in form.get("extra_pools", "").split("|") if p.strip()]
    new_lifetime = form.get("valid_lifetime", "").strip()
    new_renew = form.get("renew_timer", "").strip()
    new_rebind = form.get("rebind_timer", "").strip()
    new_routers = ",".join(s.strip() for s in form.get("routers", "").split(",") if s.strip())
    new_dns = ",".join(s.strip() for s in form.get("dns_servers", "").split(",") if s.strip())

    def _valid_ip(addr):
        try:
            ipaddress.IPv4Address(addr.strip())
            return True
        except Exception:
            return False

    if new_pool and not re.match(r"^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$", new_pool):
        return None, "Invalid pool format. Use start–end e.g. 10.0.0.1–10.0.0.250"

    if new_routers:
        bad = [ip for ip in new_routers.split(",") if not _valid_ip(ip)]
        if bad:
            return None, f"Invalid router IP(s): {', '.join(bad)}"

    if new_dns:
        bad = [ip for ip in new_dns.split(",") if not _valid_ip(ip)]
        if bad:
            return (
                None,
                f"Invalid DNS server IP(s): {', '.join(bad)} — enter one IP per entry, comma-separated (e.g. 9.9.9.9,149.112.112.112)",
            )

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
        diff.append({"field": "Primary Pool", "old": current.get("pool_str") or "(none)", "new": fields["new_pool"]})
    if fields["extra_pools"]:
        old_extra = ", ".join(current.get("pools", [])[1:]) or "(none)"
        diff.append({"field": "Extra Pools", "old": old_extra, "new": ", ".join(fields["extra_pools"])})
    if fields["new_lifetime"]:
        diff.append(
            {
                "field": "Valid Lifetime",
                "old": str(current.get("valid_lifetime") or "(unset)"),
                "new": fields["new_lifetime"],
            }
        )
    if fields["new_renew"]:
        diff.append(
            {"field": "Renew Timer", "old": str(current.get("renew_timer") or "(unset)"), "new": fields["new_renew"]}
        )
    if fields["new_rebind"]:
        diff.append(
            {"field": "Rebind Timer", "old": str(current.get("rebind_timer") or "(unset)"), "new": fields["new_rebind"]}
        )
    if fields["new_routers"]:
        diff.append({"field": "Routers", "old": current.get("routers") or "(unset)", "new": fields["new_routers"]})
    if fields["new_dns"]:
        diff.append({"field": "DNS Servers", "old": current.get("dns_servers") or "(unset)", "new": fields["new_dns"]})
    return diff


@bp.route("/subnets/edit/<int:subnet_id>/preview", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_preview(subnet_id):
    """
    Dry-run preview for a subnet edit: validates the form (via the exact
    same function edit_subnet_post() uses, so they can't drift), computes
    a human-readable diff against the subnet's current live config, and
    `kea-dhcp4 -t`s the candidate on each server WITHOUT touching the
    live file — jen.services.kea_host.test_config() (helper op
    `test-config`, or the legacy dry_run script) is the only mechanism
    and never writes the live config under any outcome.

    Never applies anything itself — edit_subnet_post() is the only route
    that writes.
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
            cfg = __host.read_config(server, "dhcp4")
            if cfg is None:
                server_results.append({"name": name, "ok": False, "message": "kea-dhcp4.conf not found on this server"})
                continue
            cfg, changed = __edit.patch_subnet4(
                cfg,
                subnet_id,
                fields["new_pool"],
                fields["extra_pools"],
                fields["new_lifetime"],
                fields["new_renew"],
                fields["new_rebind"],
                fields["new_routers"],
                fields["new_dns"],
            )
            if not changed:
                server_results.append({"name": name, "ok": True, "message": "No changes for this server"})
                continue
            res = __host.test_config(server, "dhcp4", cfg)
            if res["ok"]:
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif res["code"] == "missingbinary":
                server_results.append(
                    {
                        "name": name,
                        "ok": False,
                        "missing_binary": res["binary"],
                        "message": f"{res['binary']} is not installed on this server.",
                    }
                )
            else:
                server_results.append({"name": name, "ok": False, "message": res["detail"] or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "no_changes": False, "diff": diff, "servers": server_results, "all_passed": all_passed})


@bp.route("/subnets/edit/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet_post(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for("subnets.subnets"))

    fields, error = _parse_and_validate_subnet_edit_form(request.form)
    if error:
        flash(error, "error")
        return redirect(url_for("subnets.edit_subnet", subnet_id=subnet_id))
    new_pool = fields["new_pool"]
    extra_pools = fields["extra_pools"]
    new_lifetime = fields["new_lifetime"]
    new_renew = fields["new_renew"]
    new_rebind = fields["new_rebind"]
    new_routers = fields["new_routers"]
    new_dns = fields["new_dns"]

    errors = []
    results = []

    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            cfg = __host.read_config(server, "dhcp4")
            if cfg is None:
                errors.append(f"❌ {name}: kea-dhcp4.conf not found on this server")
                continue
            cfg, changed = __edit.patch_subnet4(
                cfg, subnet_id, new_pool, extra_pools, new_lifetime, new_renew, new_rebind, new_routers, new_dns
            )
            if not changed:
                results.append(f"ℹ️ {name}: nothing to change")
                continue
            res = __host.apply_config(server, "dhcp4", cfg)
            if res["code"] == "ok":
                restart = __host.service_action(server, "dhcp4", "restart")
                if restart["ok"]:
                    results.append(f"✅ {name}: config validated, updated and restarted")
                else:
                    results.append(f"✅ {name}: config updated — restart Kea manually ({restart['detail']})")
            elif res["code"] == "missingbinary":
                errors.append(f"❌ {name}: {res['binary']} is not installed on this server — install it and try again.")
            elif res["code"] == "testerror":
                errors.append(
                    f"❌ {name}: config validation failed — Kea NOT restarted, original config preserved. "
                    f"Error: {res['detail']}"
                )
            else:
                errors.append(f"❌ {name}: {res['detail']}")
        except Exception as e:
            errors.append(f"❌ {name}: {e}")

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    changes = []
    if new_pool:
        changes.append(f"pool={new_pool}")
    if new_lifetime:
        changes.append(f"valid-lifetime={new_lifetime}")
    if new_renew:
        changes.append(f"renew-timer={new_renew}")
    if new_rebind:
        changes.append(f"rebind-timer={new_rebind}")
    if new_routers:
        changes.append(f"routers={new_routers}")
    if new_dns:
        changes.append(f"dns={new_dns}")
    __user.audit("EDIT_SUBNET", str(subnet_id), ", ".join(changes) if changes else "no changes")

    return redirect(url_for("subnets.subnets"))


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

    new_pool = form.get("pool", "").strip()
    extra_pools = [p.strip() for p in form.get("extra_pools", "").split("|") if p.strip()]
    new_preferred = form.get("preferred_lifetime", "").strip()
    new_valid = form.get("valid_lifetime", "").strip()
    new_renew = form.get("renew_timer", "").strip()
    new_rebind = form.get("rebind_timer", "").strip()
    new_dns = ",".join(s.strip() for s in form.get("dns_servers", "").split(",") if s.strip())

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
                return (
                    None,
                    f"Invalid pool — use a range (2001:db8::10-2001:db8::20) or CIDR (2001:db8::/64): {new_pool}",
                )

    if new_dns:
        bad = [ip for ip in new_dns.split(",") if not _valid_ip6(ip)]
        if bad:
            return None, f"Invalid DNS server address(es): {', '.join(bad)}"

    for t, label in [
        (new_preferred, "Preferred Lifetime"),
        (new_valid, "Valid Lifetime"),
        (new_renew, "Renew Timer"),
        (new_rebind, "Rebind Timer"),
    ]:
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
        "new_pool": new_pool,
        "extra_pools": extra_pools,
        "new_preferred": new_preferred,
        "new_valid": new_valid,
        "new_renew": new_renew,
        "new_rebind": new_rebind,
        "new_dns": new_dns,
    }, None


def _compute_subnet6_edit_diff(subnet_id, fields):
    """v6 counterpart of _compute_subnet_edit_diff() — only for fields the
    user actually submitted a new value for, against the subnet's current
    live Kea config."""
    current = __kea6.get_subnet6_kea_data(subnet_id)
    diff = []
    if fields["new_pool"]:
        diff.append({"field": "Primary Pool", "old": current.get("pool_str") or "(none)", "new": fields["new_pool"]})
    if fields["extra_pools"]:
        old_extra = ", ".join(current.get("pools", [])[1:]) or "(none)"
        diff.append({"field": "Extra Pools", "old": old_extra, "new": ", ".join(fields["extra_pools"])})
    if fields["new_preferred"]:
        diff.append(
            {
                "field": "Preferred Lifetime",
                "old": str(current.get("preferred_lifetime") or "(unset)"),
                "new": fields["new_preferred"],
            }
        )
    if fields["new_valid"]:
        diff.append(
            {
                "field": "Valid Lifetime",
                "old": str(current.get("valid_lifetime") or "(unset)"),
                "new": fields["new_valid"],
            }
        )
    if fields["new_renew"]:
        diff.append(
            {"field": "Renew Timer", "old": str(current.get("renew_timer") or "(unset)"), "new": fields["new_renew"]}
        )
    if fields["new_rebind"]:
        diff.append(
            {"field": "Rebind Timer", "old": str(current.get("rebind_timer") or "(unset)"), "new": fields["new_rebind"]}
        )
    if fields["new_dns"]:
        diff.append({"field": "DNS Servers", "old": current.get("dns_servers") or "(unset)", "new": fields["new_dns"]})
    return diff


@bp.route("/subnets/edit6/<int:subnet_id>")
@login_required
@_admin_required
def edit_subnet6(subnet_id):
    if subnet_id not in extensions.SUBNET6_MAP:
        flash("IPv6 subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))
    kea_data = __kea6.get_subnet6_kea_data(subnet_id)
    return render_template(
        "edit_subnet6.html", subnet_id=subnet_id, subnet=extensions.SUBNET6_MAP[subnet_id], kea=kea_data
    )


@bp.route("/subnets/edit6/<int:subnet_id>/preview", methods=["POST"])
@login_required
@_admin_required
def edit_subnet6_preview(subnet_id):
    """Dry-run preview for a v6 subnet edit — same guarantee as the v4
    preview endpoint: kea_host.test_config() `kea-dhcp6 -t`s the
    candidate on each server and never touches the live kea-dhcp6.conf
    under any outcome."""
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
            cfg = __host.read_config(server, "dhcp6")
            if cfg is None:
                server_results.append({"name": name, "ok": False, "message": "kea-dhcp6.conf not found on this server"})
                continue
            cfg, changed = __edit.patch_subnet6(
                cfg,
                subnet_id,
                fields["new_pool"],
                fields["extra_pools"],
                fields["new_preferred"],
                fields["new_valid"],
                fields["new_renew"],
                fields["new_rebind"],
                fields["new_dns"],
            )
            if not changed:
                server_results.append({"name": name, "ok": True, "message": "No changes for this server"})
                continue
            res = __host.test_config(server, "dhcp6", cfg)
            if res["ok"]:
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif res["code"] == "missingbinary":
                server_results.append(
                    {
                        "name": name,
                        "ok": False,
                        "missing_binary": res["binary"],
                        "message": f"{res['binary']} is not installed on this server.",
                    }
                )
            else:
                server_results.append({"name": name, "ok": False, "message": res["detail"] or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "no_changes": False, "diff": diff, "servers": server_results, "all_passed": all_passed})


@bp.route("/subnets/edit6/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def edit_subnet6_post(subnet_id):
    if subnet_id not in extensions.SUBNET6_MAP:
        flash("IPv6 subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))

    fields, error = _parse_and_validate_subnet6_edit_form(request.form)
    if error:
        flash(error, "error")
        return redirect(url_for("subnets.edit_subnet6", subnet_id=subnet_id))

    errors, results = [], []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            cfg = __host.read_config(server, "dhcp6")
            if cfg is None:
                errors.append(f"❌ {name}: kea-dhcp6.conf not found on this server")
                continue
            cfg, changed = __edit.patch_subnet6(
                cfg,
                subnet_id,
                fields["new_pool"],
                fields["extra_pools"],
                fields["new_preferred"],
                fields["new_valid"],
                fields["new_renew"],
                fields["new_rebind"],
                fields["new_dns"],
            )
            if not changed:
                results.append(f"ℹ️ {name}: nothing to change")
                continue
            res = __host.apply_config(server, "dhcp6", cfg)
            if res["code"] == "ok":
                restart = __host.service_action(server, "dhcp6", "restart")
                if restart["ok"]:
                    results.append(f"✅ {name}: config validated, updated and restarted")
                else:
                    results.append(f"✅ {name}: config updated — restart Kea manually ({restart['detail']})")
            elif res["code"] == "missingbinary":
                errors.append(f"❌ {name}: {res['binary']} is not installed on this server — install it and try again.")
            elif res["code"] == "testerror":
                errors.append(
                    f"❌ {name}: config validation failed — Kea NOT restarted, original config preserved. "
                    f"Error: {res['detail']}"
                )
            else:
                errors.append(f"❌ {name}: {res['detail']}")
        except Exception as e:
            errors.append(f"❌ {name}: {e}")

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")

    changes = []
    if fields["new_pool"]:
        changes.append(f"pool={fields['new_pool']}")
    if fields["new_preferred"]:
        changes.append(f"preferred-lifetime={fields['new_preferred']}")
    if fields["new_valid"]:
        changes.append(f"valid-lifetime={fields['new_valid']}")
    if fields["new_renew"]:
        changes.append(f"renew-timer={fields['new_renew']}")
    if fields["new_rebind"]:
        changes.append(f"rebind-timer={fields['new_rebind']}")
    if fields["new_dns"]:
        changes.append(f"dns={fields['new_dns']}")
    __user.audit("EDIT_SUBNET6", str(subnet_id), ", ".join(changes) if changes else "no changes")

    return redirect(url_for("subnets.subnets"))


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
                cur.execute(
                    """
                    INSERT INTO subnet_notes (subnet_id, notes) VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE notes=%s, updated_at=NOW()
                """,
                    (subnet_id, notes, notes),
                )
            db.commit()
        __user.audit("SAVE_SUBNET_NOTE", str(subnet_id), "Note updated")
        return jsonify({"ok": True})
    except Exception as e:
        logger.error(f"Error saving note for subnet {subnet_id}: {e}")
        return jsonify({"ok": False, "error": "Could not save note."})
