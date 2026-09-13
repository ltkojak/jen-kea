"""
jen/routes/subnets.py
──────────────────────
Subnet view and editing routes.
"""

import logging
import os
import re
import time
import uuid

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.dhcp_options as __opts
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.kea_changeset as __changeset
import jen.services.kea_classes as __classes
import jen.services.kea_config_edit as __edit
import jen.services.kea_config_view as __view
import jen.services.kea_host as __host
import jen.services.win_dhcp_import as __win
from jen import extensions
from jen.services.access import admin_required as _admin_required
from jen.services.access import assert_subnet_access as _assert_subnet_access
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("subnets", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


# ── Optimistic concurrency (v5.16.0 — Q11; per-server v5.19.1 — Q14) ────────
#
# The edit forms carry one `base_sha_<server id>` per SSH-capable server —
# the SHA of kea-dhcp4/6.conf on THAT server as it was when the form was
# opened. On submit each is passed to kea_host.apply_config as
# expect_sha256 for that same server; a v2 helper refuses the write
# atomically if the file changed underneath, a v1 / legacy host gets a
# best-effort compare. The add / delete / move routes have no earlier
# form, so they pass the SHA read at the top of the same request (a much
# shorter window, still worth guarding) — those are unaffected here.
#
# v5.19.1 fix: this used to be ONE sha (the active server's) sent to
# EVERY SSH server. Two HA nodes never have a byte-identical
# kea-dhcp4.conf (this-server-name, peers, interfaces), so with helper v2
# on both, the second node conflicted on every single edit. Each server
# now gets its own sha, read from its own file.


def _form_base_sha(server):
    return (request.form.get(f"base_sha_{server['id']}") or "").strip() or None


def _config_shas(service):
    """{server id: sha | None} for every SSH-capable server's current
    kea-dhcp4/6.conf — one per row in the edit form's hidden fields. None
    for a v1/legacy host or any read error (that server's guard then
    degrades to a best-effort compare or, with no sha at all, no guard)."""
    shas = {}
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            _cfg, sha = __host.read_config_versioned(server, service)
        except Exception:
            sha = None
        shas[server["id"]] = sha
    return shas


def _conflict_flash(server_name):
    return (
        f"The Kea config on {server_name} changed since you opened this form — "
        "your edit was NOT applied. Reload and try again."
    )


def _reword_edit_restart_lines(lines, summary, daemon_label="Kea"):
    """edit_subnet_post/edit_subnet6_post predate kea_changeset.py and have
    their own long-tested restart wording ("config validated, updated and
    restarted" — see tests/test_kea6_subnets.py::
    test_successful_apply_restarts_kea6) that doesn't match
    kea_changeset's generic "{summary}, {daemon_label} restarted" success
    line. Rewrite just those two known shapes back to the original text
    rather than teaching the shared module a per-caller template."""
    ok_old = f"{summary}, {daemon_label} restarted"
    manual_old = f"{summary} — restart {daemon_label} manually"
    manual_new = f"config updated — restart {daemon_label} manually"
    out = []
    for style, text in lines:
        text = text.replace(ok_old, "config validated, updated and restarted").replace(manual_old, manual_new)
        out.append((style, text))
    return out


@bp.route("/subnets")
@login_required
def subnets():
    subnet_data = []
    # Fetch Kea config for lease times, timers, pools
    kea_subnets = {}
    shared_networks = []
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            shared_networks = __view.shared_networks4(cfg)
            global_lifetime = cfg.get("valid-lifetime", 0)
            global_renew = cfg.get("renew-timer", 0)
            global_rebind = cfg.get("rebind-timer", 0)
            for s, sn_name in __view.iter_subnet4(cfg):
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
                options_here, options_inherited = __opts.count_here_and_inherited(cfg, s["id"])
                kea_subnets[s["id"]] = {
                    "valid_lifetime": s.get("valid-lifetime", global_lifetime),
                    "renew_timer": s.get("renew-timer", global_renew),
                    "rebind_timer": s.get("rebind-timer", global_rebind),
                    "pools": pools,
                    "routers": routers,
                    "dns_servers": dns_servers,
                    "shared_network": sn_name,
                    "options_here": options_here,
                    "options_inherited": options_inherited,
                    "classes": __classes.guard_classes(s),
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
                            "shared_network": kea.get("shared_network"),
                            "options_here": kea.get("options_here", 0),
                            "options_inherited": kea.get("options_inherited", 0),
                            "classes": kea.get("classes", []),
                        }
                    )
    except Exception as e:
        logger.error(f"Could not load subnet data: {e}")
        flash("Could not load subnet data. Check server logs for details.", "error")

    # v5.15.0 — order the cards: top-level subnets first, then grouped by
    # shared network in the order Kea declares them. The template renders a
    # heading whenever `shared_network` changes.
    _net_order = {n["name"]: i for i, n in enumerate(shared_networks)}
    subnet_data.sort(key=lambda d: (d.get("shared_network") is not None, _net_order.get(d.get("shared_network"), 0)))

    ssh_ready = os.path.exists(extensions.SSH_KEY_PATH) and bool(extensions.KEA_SSH_HOST)
    subnet_notes = {}
    try:
        with __db.jen_db() as jdb, jdb.cursor() as jcur:
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
        shared_networks=shared_networks,
        can_manage_networks=current_user.all_subnets,
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
            for s, _sn in __view.iter_subnet4(cfg):
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
            return {s["id"] for s, _sn in __view.iter_subnet4(result["arguments"].get("Dhcp4", {}))}
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
    shared_networks = []
    try:
        _r = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if _r.get("result") == 0:
            shared_networks = [n["name"] for n in __view.shared_networks4(_r["arguments"].get("Dhcp4", {}))]
    except Exception:
        pass
    return render_template("add_subnet.html", suggested_id=suggested_id, shared_networks=shared_networks)


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
    shared_network = request.form.get("shared_network", "").strip()

    # ── Validation — catch everything before touching Kea or Jen's config ─────
    if shared_network and not __auth.valid_shared_network_name(shared_network):
        flash("Invalid shared network name.", "error")
        return redirect(url_for("subnets.add_subnet"))
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

    result = __changeset.apply_change(
        "dhcp4",
        lambda cfg: __edit.add_subnet4(cfg, new_subnet_block, shared_network=shared_network or None),
        f"subnet {new_id} created",
        code_messages={
            "idexists": f"subnet ID {new_id} already exists on this server",
            "nonetwork": f'no shared network named "{shared_network}" on this server',
        },
        conflict_phrase=_conflict_flash,
    )
    for style, text in result.lines:
        flash(text, style)
    if result.status in ("aborted", "rollback_failed"):
        return redirect(url_for("subnets.add_subnet"))

    # Register the new subnet with Jen only after Kea accepted it
    new_map = dict(extensions.SUBNET_MAP)
    new_map[new_id] = {"name": new_name, "cidr": new_cidr}
    __config.write_subnets_config(new_map)

    _net_note = f" network={shared_network}" if shared_network else ""
    __user.audit("ADD_SUBNET", str(new_id), f"name={new_name} cidr={new_cidr} pool={new_pool}{_net_note}")
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
        with __db.kea_db() as db, db.cursor() as cur:
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

    result = __changeset.apply_change(
        "dhcp4",
        lambda cfg: __edit.delete_subnet4(cfg, subnet_id),
        f"subnet {subnet_id} removed",
        code_messages={"notfound": f"subnet {subnet_id} was not in Kea's config"},
        conflict_phrase=_conflict_flash,
    )
    for style, text in result.lines:
        flash(text, style)
    if result.status in ("aborted", "rollback_failed"):
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
    kea_data["base_shas"] = _config_shas("dhcp4")
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
            cfg, live_sha = __host.read_config_versioned(server, "dhcp4")
            if cfg is None:
                server_results.append({"name": name, "ok": False, "message": "kea-dhcp4.conf not found on this server"})
                continue
            base_sha = _form_base_sha(server)
            if base_sha and live_sha and base_sha != live_sha:
                server_results.append({"name": name, "ok": False, "message": _conflict_flash(name)})
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

    def _mutate(cfg):
        new_cfg, changed = __edit.patch_subnet4(
            cfg, subnet_id, new_pool, extra_pools, new_lifetime, new_renew, new_rebind, new_routers, new_dns
        )
        return new_cfg, "ok" if changed else "nochange"

    summary = f"subnet {subnet_id} updated"
    result = __changeset.apply_change(
        "dhcp4",
        _mutate,
        summary,
        code_messages={"nochange": "nothing to change"},
        expected_sha_for=_form_base_sha,
        conflict_phrase=_conflict_flash,
    )
    for style, text in _reword_edit_restart_lines(result.lines, summary):
        flash(text, style)

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


# ── Shared networks (v5.15.0) ───────────────────────────────────────────────


def _apply_dhcp4_change(mutate_fn, done_phrase, code_messages, summary=None):
    """v5.15.0 — read → mutate → apply → restart against every SSH-capable
    Kea server. `mutate_fn(cfg) -> (cfg, code)`; `code_messages` maps a
    non-"ok" code to its flash text. Flashes per-server results; returns
    the last mutate/apply code so the caller can pick a redirect/audit.
    v5.28.0 (Q24, C2) — a thin wrapper over kea_changeset.apply_change(),
    which owns the actual plan/preflight/commit-with-revert/restart logic
    shared with subnets.py's direct callers and ddns.py."""
    result = __changeset.apply_change(
        "dhcp4",
        mutate_fn,
        summary or done_phrase,
        code_messages=code_messages,
        conflict_phrase=_conflict_flash,
    )
    for style, text in result.lines:
        flash(text, style)
    return result.last_code


@bp.route("/subnets/shared-networks/add", methods=["POST"])
@login_required
@_admin_required
def add_shared_network():
    if not current_user.all_subnets:
        flash("Creating a shared network needs access to all subnets.", "error")
        return redirect(url_for("subnets.subnets"))
    name = request.form.get("name", "").strip()
    interface = request.form.get("interface", "").strip() or None
    if not __auth.valid_shared_network_name(name):
        flash("Invalid shared network name — letters, digits, and _.- only (1-64 chars).", "error")
        return redirect(url_for("subnets.subnets"))
    if interface and not re.match(r"^[A-Za-z0-9_.:-]{1,32}$", interface):
        flash("Invalid interface name.", "error")
        return redirect(url_for("subnets.subnets"))

    code = _apply_dhcp4_change(
        lambda cfg: __edit.create_shared_network4(cfg, name, interface),
        f'shared network "{name}" created',
        {"exists": f'a shared network named "{name}" already exists'},
    )
    if code == "ok":
        __user.audit("ADD_SHARED_NETWORK", name, f"interface={interface}" if interface else "")
    return redirect(url_for("subnets.subnets"))


@bp.route("/subnets/shared-networks/delete", methods=["POST"])
@login_required
@_admin_required
def delete_shared_network():
    if not current_user.all_subnets:
        flash("Deleting a shared network needs access to all subnets.", "error")
        return redirect(url_for("subnets.subnets"))
    name = request.form.get("name", "").strip()
    if not __auth.valid_shared_network_name(name):
        flash("Invalid shared network name.", "error")
        return redirect(url_for("subnets.subnets"))

    code = _apply_dhcp4_change(
        lambda cfg: __edit.delete_shared_network4(cfg, name),
        f'shared network "{name}" deleted',
        {
            "notfound": f'no shared network named "{name}"',
            "notempty": f'"{name}" still has subnets — move them out first',
        },
    )
    if code == "ok":
        __user.audit("DELETE_SHARED_NETWORK", name, "")
    return redirect(url_for("subnets.subnets"))


@bp.route("/subnets/move/<int:subnet_id>", methods=["POST"])
@login_required
@_admin_required
def move_subnet(subnet_id):
    if subnet_id not in extensions.SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets.subnets"))
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
        return redirect(url_for("subnets.subnets"))
    target = request.form.get("shared_network", "").strip()
    if target and not __auth.valid_shared_network_name(target):
        flash("Invalid shared network name.", "error")
        return redirect(url_for("subnets.subnets"))

    where = f'to "{target}"' if target else "to the top level"
    code = _apply_dhcp4_change(
        lambda cfg: __edit.move_subnet4(cfg, subnet_id, target),
        f"subnet {subnet_id} moved {where}",
        {
            "notfound": f"subnet {subnet_id} is not in the live Kea config",
            "nonetwork": f'no shared network named "{target}"',
            "nochange": f"subnet {subnet_id} is already there",
        },
    )
    if code == "ok":
        __user.audit("MOVE_SUBNET", str(subnet_id), f"network={target or '(top level)'}")
    return redirect(url_for("subnets.subnets"))


# ── DHCP options hierarchy (v5.18.0 — Q12) ──────────────────────────────────
#
# A catalog-driven editor for option-data at the global, shared-network,
# subnet and pool levels, plus an "effective options" view. Codes 3
# (routers) and 6 (domain-name-servers) at SUBNET level stay owned by the
# Edit Subnet form — jen.services.dhcp_options / kea_config_edit both
# refuse them there ("managed"). v6 is out of scope for this page.


def _parse_option_level_key(level, key_raw):
    """Normalize the level/key pair from a query string or form. Returns
    (level, key) — level in dhcp_options.LEVELS with key shaped the way
    kea_config_edit.set_option4/remove_option4 expect — or (None, None)
    if either is malformed."""
    if level == "global":
        return "global", None
    if level == "shared-network":
        return ("shared-network", key_raw) if key_raw else (None, None)
    if level == "subnet":
        return ("subnet", int(key_raw)) if key_raw.isdigit() else (None, None)
    if level == "pool":
        sid_str, sep, pool_str = (key_raw or "").partition(":")
        if sep and sid_str.isdigit() and pool_str:
            return "pool", (int(sid_str), pool_str)
        return None, None
    if level == "class":
        # v5.19.0 (Q13) — key is the class name, same shape as shared-network.
        return ("class", key_raw) if key_raw else (None, None)
    return None, None


def _option_key_display(level, key):
    """The form/query-string `key` value for a (level, key) pair — the
    inverse of _parse_option_level_key."""
    if level in ("shared-network", "class"):
        return key
    if level == "subnet":
        return str(key)
    if level == "pool":
        return f"{key[0]}:{key[1]}"
    return ""


def _dhcp_options_check_access(level, key):
    """Flashes and returns False when the current user can't manage
    options at this level: global/shared-network/class need unrestricted
    subnet access (classes are global — v5.19.0 / Q13); subnet/pool are
    the usual per-subnet check."""
    if level in ("global", "shared-network", "class"):
        if current_user.all_subnets:
            return True
        flash("DHCP options at this level need access to all subnets.", "error")
        return False
    if level == "subnet":
        return _assert_subnet_access(key)
    if level == "pool":
        return _assert_subnet_access(key[0])
    return False


def _dhcp_options_picker(cfg):
    """The level picker: global + each shared network (unrestricted
    admins only), then every subnet the user can access with its pools."""
    items = []
    if current_user.all_subnets:
        items.append({"kind": "global"})
        for sn in __view.shared_networks4(cfg):
            items.append({"kind": "shared-network", "name": sn["name"]})
    for s, sn_name in __view.iter_subnet4(cfg):
        sid = s.get("id")
        if sid is None or not current_user.can_access_subnet(sid):
            continue
        info = extensions.SUBNET_MAP.get(sid, {})
        pools = [p.get("pool") for p in (s.get("pools") or []) if isinstance(p, dict) and p.get("pool")]
        items.append(
            {
                "kind": "subnet",
                "id": sid,
                "name": info.get("name") or s.get("subnet") or f"subnet {sid}",
                "cidr": info.get("cidr") or s.get("subnet", ""),
                "shared_network": sn_name,
                "pools": pools,
            }
        )
    return items


def _dhcp_options_redirect(level_raw, key_raw):
    return redirect(url_for("subnets.dhcp_options_page", level=level_raw, key=key_raw))


@bp.route("/subnets/options")
@login_required
@_admin_required
def dhcp_options_page():
    level, key = _parse_option_level_key(request.args.get("level", "global"), request.args.get("key", ""))
    if level is None:
        flash("Invalid DHCP options level.", "error")
        return redirect(url_for("subnets.dhcp_options_page"))
    if not _dhcp_options_check_access(level, key):
        return redirect(url_for("subnets.subnets"))

    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        cfg = result["arguments"]["Dhcp4"] if result.get("result") == 0 else {}
    except Exception:
        cfg = {}

    rows = __opts.options_at(cfg, level, key)
    for r in rows:
        r["managed"] = level == "subnet" and r["code"] in __opts.MANAGED_AT_SUBNET
        r["custom"] = r["code"] not in __opts.V4_OPTIONS

    effective = []
    subnet_id = key[0] if level == "pool" else (key if level == "subnet" else None)
    pool_str = key[1] if level == "pool" else None
    subnet_label = None
    if subnet_id is not None:
        effective = __opts.effective_options(cfg, subnet_id, pool=pool_str)
        for r in effective:
            r["is_here"] = r["source"] == level
        info = extensions.SUBNET_MAP.get(subnet_id, {})
        subnet_label = info.get("name") or f"subnet {subnet_id}"

    return render_template(
        "dhcp_options.html",
        level=level,
        key=_option_key_display(level, key),
        picker=_dhcp_options_picker(cfg),
        rows=rows,
        catalog=__opts.catalog_choices(),
        effective=effective,
        show_effective=level in ("subnet", "pool"),
        subnet_label=subnet_label,
        pool_str=pool_str,
        option_defs=[d for d in (cfg.get("option-def") or []) if isinstance(d, dict)],
        can_manage_networks=current_user.all_subnets,
    )


@bp.route("/subnets/options/set", methods=["POST"])
@login_required
@_admin_required
def dhcp_options_set():
    level_raw = request.form.get("level", "")
    key_raw = request.form.get("key", "")
    level, key = _parse_option_level_key(level_raw, key_raw)
    if level is None:
        flash("Invalid DHCP options level.", "error")
        return redirect(url_for("subnets.dhcp_options_page"))
    if not _dhcp_options_check_access(level, key):
        return redirect(url_for("subnets.subnets"))

    code_raw = request.form.get("code", "").strip()
    try:
        code = int(code_raw)
    except ValueError:
        flash("Invalid option code.", "error")
        return _dhcp_options_redirect(level_raw, key_raw)

    if request.form.get("custom") == "1":
        name = (request.form.get("name", "").strip() or f"custom-{code}")[:64]
        opt_type = "hex"
        csv_format = False
    else:
        entry = __opts.V4_OPTIONS.get(code)
        if not entry:
            flash("Unknown catalog option — use Custom code for anything else.", "error")
            return _dhcp_options_redirect(level_raw, key_raw)
        name, opt_type, csv_format = entry["name"], entry["type"], True

    data_raw = request.form.get("data", "").strip()
    err = __opts.validate(opt_type, data_raw)
    if err:
        flash(f"{name}: {err}", "error")
        return _dhcp_options_redirect(level_raw, key_raw)
    data = __opts.normalize(opt_type, data_raw)

    result_code = _apply_dhcp4_change(
        lambda cfg: __edit.set_option4(cfg, level, key, code, name, data, csv_format=csv_format),
        f'option "{name}" (code {code}) set at {level_raw}',
        {
            "managed": f'"{name}" (code {code}) is managed by the Edit Subnet form — edit the subnet instead.',
            "notfound": f"{level_raw} not found in the live Kea config",
        },
        summary=f"set option {name} ({code}) at {level_raw}",
    )
    if result_code == "ok":
        __user.audit("SET_DHCP_OPTION", name, f"level={level_raw} key={key_raw} code={code}")
    return _dhcp_options_redirect(level_raw, key_raw)


@bp.route("/subnets/options/remove", methods=["POST"])
@login_required
@_admin_required
def dhcp_options_remove():
    level_raw = request.form.get("level", "")
    key_raw = request.form.get("key", "")
    level, key = _parse_option_level_key(level_raw, key_raw)
    if level is None:
        flash("Invalid DHCP options level.", "error")
        return redirect(url_for("subnets.dhcp_options_page"))
    if not _dhcp_options_check_access(level, key):
        return redirect(url_for("subnets.subnets"))

    code_raw = request.form.get("code", "").strip()
    try:
        code = int(code_raw)
    except ValueError:
        flash("Invalid option code.", "error")
        return _dhcp_options_redirect(level_raw, key_raw)
    name = __opts.V4_OPTIONS.get(code, {}).get("name", f"code {code}")

    result_code = _apply_dhcp4_change(
        lambda cfg: __edit.remove_option4(cfg, level, key, code),
        f'option "{name}" (code {code}) removed from {level_raw}',
        {
            "managed": f'"{name}" (code {code}) is managed by the Edit Subnet form — edit the subnet instead.',
            "notfound": f"{name} (code {code}) is not set at {level_raw}",
        },
        summary=f"remove option {name} ({code}) at {level_raw}",
    )
    if result_code == "ok":
        __user.audit("REMOVE_DHCP_OPTION", name, f"level={level_raw} key={key_raw} code={code}")
    return _dhcp_options_redirect(level_raw, key_raw)


# ── Client classes (v5.19.0 — Q13) ───────────────────────────────────────────
#
# Dhcp4.client-classes: a guided rule builder (or a raw expression) plus
# where each class is attached (subnet/pool/shared-network, as a guard or
# an additional class). Classes are global, so every route here needs
# unrestricted subnet access, same as the shared-network/global levels of
# the options page above.


def _kea_version():
    """The running Kea's (X, Y, Z) version, or None if it can't be
    determined. Resolved once per request — kea_classes.attachment_keys
    only needs it as a widest-compatible fallback when the config doesn't
    already commit to an old/new key spelling somewhere."""
    try:
        result = __kea.kea_command("version-get", server=__kea.get_active_kea_server())
    except Exception:
        return None
    if result.get("result") != 0:
        return None
    return __kea.parse_kea_version(result.get("arguments", {}).get("extended", "") or result.get("text", ""))


def _live_dhcp4_cfg():
    """The live Dhcp4 config (inner map) via the Control Agent API,
    read-only — same source dhcp_options_page uses. {} on any failure."""
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        return result["arguments"]["Dhcp4"] if result.get("result") == 0 else {}
    except Exception:
        return {}


def _classes_check_access():
    if current_user.all_subnets:
        return True
    flash("Client classes need access to all subnets.", "error")
    return False


def _only_additional_warning(name):
    return (
        f'"{name}" is marked only-in-additional-list but is not attached as an Additional class anywhere yet — '
        "Kea will never evaluate it until you tick Additional on a subnet, pool, or shared network."
    )


def _class_form_identity(form):
    """(name, is_new) from the shared new/edit form fields — editing an
    existing class keeps its name fixed to `orig_name` regardless of what
    a tampered `name` field might carry."""
    is_new = form.get("is_new") == "1"
    orig_name = form.get("orig_name", "").strip()
    name = form.get("name", "").strip() if is_new else orig_name
    return name, is_new


def _class_edit_redirect(is_new, name):
    if is_new:
        return redirect(url_for("subnets.dhcp_class_new_page"))
    return redirect(url_for("subnets.dhcp_class_edit_page", name=name))


def _parse_guided_rules(form):
    fields = form.getlist("rule_field")
    ops = form.getlist("rule_op")
    values = form.getlist("rule_value")
    return [{"field": f, "op": o, "value": v} for f, o, v in zip(fields, ops, values, strict=False)]


def _build_class_expression(form):
    """(expression, user_context, error) from the shared new/edit form's
    Guided/Advanced fields — used by both the preview and save routes so
    they can never disagree about what a submission means."""
    if form.get("mode") == "advanced":
        expr = form.get("test", "").strip()
        if not expr:
            return None, None, "An expression is required."
        return expr, None, None

    rules = _parse_guided_rules(form)
    combinator = form.get("combinator", "all")
    negate = form.get("negate") == "1"
    try:
        expr = __classes.build_expression(rules, combinator, negate)
    except ValueError as e:
        return None, None, str(e)
    user_context = {"jen": {"builder": {"rules": rules, "combinator": combinator, "negate": negate}, "v": 1}}
    return expr, user_context, None


def _class_row(c, dhcp4_cfg):
    name = c.get("name")
    builtin = __classes.is_builtin(name)
    builder = ((c.get("user-context") or {}).get("jen") or {}).get("builder")
    guided = False
    if isinstance(builder, dict):
        try:
            expr = __classes.build_expression(
                builder.get("rules") or [], builder.get("combinator", "all"), bool(builder.get("negate"))
            )
            guided = expr == (c.get("test") or "")
        except ValueError:
            guided = False
    return {
        "name": name,
        "builtin": builtin,
        "guided": guided,
        "test": c.get("test", ""),
        "options_count": len(c.get("option-data") or []),
        "next_server": c.get("next-server"),
        "server_hostname": c.get("server-hostname"),
        "boot_file_name": c.get("boot-file-name"),
        "only_additional": bool(c.get(__classes.NEW_ONLY) or c.get(__classes.OLD_ONLY)),
        "references": [] if builtin else __classes.references(dhcp4_cfg, name),
    }


def _class_scope_rows(dhcp4_cfg, name):
    """Every subnet (incl. nested under a shared network), its pools, and
    every shared network — each carrying its current guard/additional
    state for `name`. The 'Applies to' checklist."""
    rows = []
    for s, _sn_name in __view.iter_subnet4(dhcp4_cfg):
        sid = s.get("id")
        info = extensions.SUBNET_MAP.get(sid, {})
        label = info.get("name") or s.get("subnet") or f"subnet {sid}"
        rows.append(
            {
                "level": "subnet",
                "key": str(sid),
                "label": label,
                "guard": name in __classes.guard_classes(s),
                "additional": name in __classes.additional_classes(s),
            }
        )
        for p in s.get("pools") or []:
            if not isinstance(p, dict) or not p.get("pool"):
                continue
            rows.append(
                {
                    "level": "pool",
                    "key": f"{sid}:{p['pool']}",
                    "label": f"{label} — pool {p['pool']}",
                    "guard": name in __classes.guard_classes(p),
                    "additional": name in __classes.additional_classes(p),
                }
            )
    for sn in __view.shared_networks4_raw(dhcp4_cfg):
        rows.append(
            {
                "level": "shared-network",
                "key": sn.get("name"),
                "label": f"Shared network: {sn.get('name')}",
                "guard": name in __classes.guard_classes(sn),
                "additional": name in __classes.additional_classes(sn),
            }
        )
    return rows


@bp.route("/subnets/classes")
@login_required
@_admin_required
def dhcp_classes_page():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))
    cfg = _live_dhcp4_cfg()
    classes = [c for c in cfg.get("client-classes") or [] if isinstance(c, dict)]
    return render_template("dhcp_classes.html", rows=[_class_row(c, cfg) for c in classes])


@bp.route("/subnets/classes/new", endpoint="dhcp_class_new_page")
@bp.route("/subnets/classes/edit")
@login_required
@_admin_required
def dhcp_class_edit_page():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))

    name = request.args.get("name", "").strip()
    cfg = _live_dhcp4_cfg()
    existing = None
    if name:
        existing = next(
            (c for c in cfg.get("client-classes") or [] if isinstance(c, dict) and c.get("name") == name), None
        )
        if existing is None:
            flash(f'No class named "{name}" in the live config.', "error")
            return redirect(url_for("subnets.dhcp_classes_page"))
        if __classes.is_builtin(name):
            flash(f'"{name}" is a built-in class and cannot be edited.', "error")
            return redirect(url_for("subnets.dhcp_classes_page"))

    builder = None
    advanced_notice = False
    advanced_test = ""
    if existing is not None:
        advanced_test = existing.get("test", "")
        raw_builder = ((existing.get("user-context") or {}).get("jen") or {}).get("builder")
        if isinstance(raw_builder, dict):
            try:
                expr = __classes.build_expression(
                    raw_builder.get("rules") or [],
                    raw_builder.get("combinator", "all"),
                    bool(raw_builder.get("negate")),
                )
            except ValueError:
                expr = None
            if expr == advanced_test:
                builder = raw_builder
            else:
                advanced_notice = True

    rows = []
    if existing is not None:
        rows = __opts.options_at(cfg, "class", name)
        for r in rows:
            r["managed"] = False
            r["custom"] = r["code"] not in __opts.V4_OPTIONS

    only_additional = bool(existing and (existing.get(__classes.NEW_ONLY) or existing.get(__classes.OLD_ONLY)))
    only_additional_unattached = bool(
        existing is not None and only_additional and not __classes.attached_as_additional(cfg, name)
    )

    return render_template(
        "dhcp_class_edit.html",
        name=name,
        existing=existing,
        is_new=existing is None,
        fields=__classes.FIELDS,
        builder=builder,
        advanced_notice=advanced_notice,
        advanced_test=advanced_test,
        initial_mode="advanced" if (existing is not None and builder is None) else "guided",
        only_additional=only_additional,
        only_additional_warning=_only_additional_warning(name) if only_additional_unattached else None,
        rows=rows,
        catalog=__opts.catalog_choices(),
        level="class",
        key=name,
        scope_rows=_class_scope_rows(cfg, name) if existing is not None else [],
    )


@bp.route("/subnets/classes/preview", methods=["POST"])
@login_required
@_admin_required
def dhcp_class_preview():
    if not current_user.all_subnets:
        return render_template("_class_preview.html", expression="", error="Access denied.", test_result=None), 403

    name, _is_new = _class_form_identity(request.form)
    expr, _user_context, error = _build_class_expression(request.form)

    if not error and not __auth.valid_class_name(name):
        error = "A valid class name is required to preview."
    if not error and __classes.is_builtin(name):
        error = f'"{name}" is a built-in class name and cannot be used.'

    test_result = None
    if not error:
        ssh_server = next((s for s in extensions.KEA_SERVERS if s.get("ssh_host")), None)
        if ssh_server is None:
            test_result = {"ok": None, "detail": "No SSH-reachable Kea server to validate against."}
        else:
            try:
                full_cfg, _sha = __host.read_config_versioned(ssh_server, "dhcp4")
                if full_cfg is None:
                    test_result = {"ok": None, "detail": "Couldn't read the live config on that server."}
                else:
                    existing = next(
                        (
                            c
                            for c in (full_cfg.get("Dhcp4", {}).get("client-classes") or [])
                            if isinstance(c, dict) and c.get("name") == name
                        ),
                        None,
                    )
                    candidate = __classes.merge_class_fields(existing, name, expr)
                    preview_cfg, _code = __edit.upsert_class4(full_cfg, candidate)
                    test_result = __host.test_config(ssh_server, "dhcp4", preview_cfg)
            except Exception:
                # v5.19.1 (14G) — an SSH failure on a legacy-path host used
                # to raise straight out of this route, showing a 500 in the
                # htmx preview target instead of an error row.
                logger.warning(
                    f"class preview validation failed against {ssh_server.get('name') or ssh_server.get('ssh_host')}",
                    exc_info=True,
                )
                server_label = ssh_server.get("name") or ssh_server.get("ssh_host")
                test_result = {"ok": None, "detail": f"Couldn't validate against {server_label} — see server logs."}

    return render_template("_class_preview.html", expression=expr or "", error=error, test_result=test_result)


@bp.route("/subnets/classes/save", methods=["POST"])
@login_required
@_admin_required
def dhcp_class_save():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))

    name, is_new = _class_form_identity(request.form)
    if not __auth.valid_class_name(name):
        flash("Invalid class name — letters, digits, _ and - only, must start with a letter, max 64 chars.", "error")
        return _class_edit_redirect(is_new, name)
    if __classes.is_builtin(name):
        flash(f'"{name}" is a built-in class name and cannot be used.', "error")
        return _class_edit_redirect(is_new, name)

    expr, user_context, error = _build_class_expression(request.form)
    if error:
        flash(error, "error")
        return _class_edit_redirect(is_new, name)

    next_server = request.form.get("next_server", "").strip() or None
    server_hostname = request.form.get("server_hostname", "").strip() or None
    boot_file_name = request.form.get("boot_file_name", "").strip() or None
    only_additional = request.form.get("only_additional") == "1"
    version = _kea_version()

    def _mutate(cfg):
        d4 = cfg.get("Dhcp4") or {}
        existing = next(
            (c for c in d4.get("client-classes") or [] if isinstance(c, dict) and c.get("name") == name), None
        )
        keys = __classes.attachment_keys(d4, version)
        merged = __classes.merge_class_fields(
            existing,
            name,
            expr,
            user_context=user_context,
            next_server=next_server,
            server_hostname=server_hostname,
            boot_file_name=boot_file_name,
            only_key=keys["only"],
            only_additional=only_additional,
        )
        return __edit.upsert_class4(cfg, merged)

    # v5.19.1 — read before the push: Kea restarts right after a
    # successful apply, so a fresh API read here could lag or fail, and
    # the attachment state a save is checking against doesn't change
    # during the save itself.
    pre_push_cfg = _live_dhcp4_cfg()
    code = _apply_dhcp4_change(_mutate, f'class "{name}" saved', {}, summary=f'save class "{name}"')
    if code == "ok":
        __user.audit("SAVE_DHCP_CLASS", name, "new" if is_new else "edit")
        if only_additional and not __classes.attached_as_additional(pre_push_cfg, name):
            flash(_only_additional_warning(name), "warning")
    return redirect(url_for("subnets.dhcp_class_edit_page", name=name))


@bp.route("/subnets/classes/delete", methods=["POST"])
@login_required
@_admin_required
def dhcp_class_delete():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))

    name = request.form.get("name", "").strip()
    refs = __classes.references(_live_dhcp4_cfg(), name)
    ref_msg = f'"{name}" is still referenced by: {", ".join(refs)} — detach it first.'

    code = _apply_dhcp4_change(
        lambda cfg: __edit.delete_class4(cfg, name),
        f'class "{name}" deleted',
        {
            "builtin": f'"{name}" is a built-in class and cannot be deleted.',
            "notfound": f'"{name}" is not in the live Kea config.',
            "referenced": ref_msg,
        },
        summary=f'delete class "{name}"',
    )
    if code == "ok":
        __user.audit("DELETE_DHCP_CLASS", name, "")
    return redirect(url_for("subnets.dhcp_classes_page"))


@bp.route("/subnets/classes/reorder", methods=["POST"])
@login_required
@_admin_required
def dhcp_class_reorder():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))

    name = request.form.get("name", "").strip()
    direction = request.form.get("direction", "")
    if direction not in ("up", "down"):
        flash("Invalid reorder direction.", "error")
        return redirect(url_for("subnets.dhcp_classes_page"))

    code = _apply_dhcp4_change(
        lambda cfg: __edit.reorder_class4(cfg, name, direction),
        f'class "{name}" moved {direction}',
        {
            "notfound": f'"{name}" is not in the live Kea config.',
            "boundary": f'"{name}" is already at the {"top" if direction == "up" else "bottom"}.',
        },
        summary=f'reorder class "{name}" {direction}',
    )
    if code == "ok":
        __user.audit("REORDER_DHCP_CLASS", name, direction)
    return redirect(url_for("subnets.dhcp_classes_page"))


@bp.route("/subnets/classes/attach", methods=["POST"])
@login_required
@_admin_required
def dhcp_class_attach():
    if not _classes_check_access():
        return redirect(url_for("subnets.subnets"))

    name = request.form.get("name", "").strip()
    scope_level, scope_key = _parse_option_level_key(
        request.form.get("scope_level", ""), request.form.get("scope_key", "")
    )
    mode = request.form.get("mode", "guard")
    attach = request.form.get("attach") == "1"

    if (
        scope_level not in ("subnet", "pool", "shared-network")
        or scope_key is None
        or mode
        not in (
            "guard",
            "additional",
        )
    ):
        flash("Invalid attachment target.", "error")
        return redirect(url_for("subnets.dhcp_class_edit_page", name=name))

    version = _kea_version()
    verb = "attached to" if attach else "detached from"
    scope_display = _option_key_display(scope_level, scope_key)
    code = _apply_dhcp4_change(
        lambda cfg: __edit.attach_class4(cfg, name, scope_level, scope_key, mode=mode, attach=attach, version=version),
        f'class "{name}" {verb} {scope_level} {scope_display}',
        {"notfound": f"{scope_level} {scope_display} not found in the live Kea config"},
        summary=f'{verb} class "{name}" {scope_level} {scope_display}',
    )
    if code == "ok":
        __user.audit("ATTACH_DHCP_CLASS", name, f"{scope_level}={scope_display} mode={mode} attach={attach}")
    return redirect(url_for("subnets.dhcp_class_edit_page", name=name))


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
    kea_data["base_shas"] = _config_shas("dhcp6")
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
            cfg, live_sha = __host.read_config_versioned(server, "dhcp6")
            if cfg is None:
                server_results.append({"name": name, "ok": False, "message": "kea-dhcp6.conf not found on this server"})
                continue
            base_sha = _form_base_sha(server)
            if base_sha and live_sha and base_sha != live_sha:
                server_results.append({"name": name, "ok": False, "message": _conflict_flash(name)})
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

    def _mutate(cfg):
        new_cfg, changed = __edit.patch_subnet6(
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
        return new_cfg, "ok" if changed else "nochange"

    summary = f"subnet {subnet_id} updated"
    result = __changeset.apply_change(
        "dhcp6",
        _mutate,
        summary,
        code_messages={"nochange": "nothing to change"},
        expected_sha_for=_form_base_sha,
        conflict_phrase=_conflict_flash,
    )
    for style, text in _reword_edit_restart_lines(result.lines, summary):
        flash(text, style)

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


def _diff_rows(diff_lines):
    """Tag each unified-diff line with a CSS class for the preview template.
    Text is escaped by Jinja autoescaping — never rendered raw. Mirrors
    jen/routes/servers.py's _diff_rows (config history); duplicated rather
    than imported across blueprints for one small pure helper."""
    rows = []
    for ln in diff_lines:
        if ln.startswith(("+++", "---")):
            cls = "meta"
        elif ln.startswith("@@"):
            cls = "hunk"
        elif ln.startswith("+"):
            cls = "add"
        elif ln.startswith("-"):
            cls = "del"
        else:
            cls = "ctx"
        rows.append({"cls": cls, "text": ln})
    return rows


# ── Windows DHCP migration wizard (v5.24.0 — Q20) ───────────────────────────
#
# A single gunicorn worker (-w 1, see docs/ARCHITECTURE.md §6) makes a
# module-level in-memory store safe for this: no cross-process races to
# guard against, and the documented tradeoff is that an in-flight import
# is lost on a Jen restart — acceptable for a wizard nobody leaves
# half-finished for 30 minutes. Never applies to more than the PRIMARY
# server's config — an HA partner gets it the same way the operator
# already syncs config today (stated on the page, not automated here).

_WIN_IMPORT_PLANS: dict[str, dict] = {}
_WIN_IMPORT_TTL_SECONDS = 30 * 60
_WIN_IMPORT_MAX_BYTES = 5 * 1024 * 1024


def _prune_win_import_plans():
    now = time.time()
    for token in [t for t, entry in _WIN_IMPORT_PLANS.items() if entry["expires"] < now]:
        _WIN_IMPORT_PLANS.pop(token, None)


def _get_win_import_plan():
    _prune_win_import_plans()
    token = session.get("win_import_token")
    return token, _WIN_IMPORT_PLANS.get(token) if token else None


@bp.route("/subnets/import-windows", methods=["GET", "POST"])
@login_required
@_superadmin_required
def import_windows():
    _prune_win_import_plans()
    if request.method == "GET":
        return render_template("import_windows.html")

    file = request.files.get("xml_file")
    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("subnets.import_windows"))

    data = file.read(_WIN_IMPORT_MAX_BYTES + 1)
    if len(data) > _WIN_IMPORT_MAX_BYTES:
        flash("That file is larger than the 5 MB limit for a DHCP export.", "error")
        return redirect(url_for("subnets.import_windows"))

    try:
        plan = __win.parse_export(data)
    except Exception as e:
        logger.warning(f"Windows DHCP export failed to parse: {e}")
        flash(
            "Could not parse that file as a Windows DHCP export — make sure it's the genuine XML output "
            "of Export-DhcpServer, not something else.",
            "error",
        )
        return redirect(url_for("subnets.import_windows"))

    token = uuid.uuid4().hex
    _WIN_IMPORT_PLANS[token] = {
        "plan": plan,
        "expires": time.time() + _WIN_IMPORT_TTL_SECONDS,
        "subnet_names": None,
        "selections": None,
    }
    session["win_import_token"] = token
    __user.audit(
        "IMPORT_WINDOWS_DHCP", "upload", f"{len(plan.scopes)} scope(s) parsed, {len(plan.warnings)} warning(s)"
    )
    return redirect(url_for("subnets.import_windows_review"))


def _suggested_subnet_names(plan):
    """{scope_id: {"id": <next free>, "name": <sanitized scope name>}} —
    computed fresh every time the review page renders, so ids stay
    contiguous even if the operator unticks/reticks scopes between
    loads (this is a suggestion, not a commitment until Apply)."""
    existing_ids = _get_kea_subnet_ids() | set(extensions.SUBNET_MAP.keys())
    next_id = max(existing_ids, default=0) + 1
    out = {}
    for scope in plan.scopes:
        name = (
            scope.name if __auth.valid_shared_network_name(scope.name) else re.sub(r"[^A-Za-z0-9_.-]", "_", scope.name)
        )
        out[scope.scope_id] = {"id": next_id, "name": name[:64] or scope.scope_id}
        next_id += 1
    return out


@bp.route("/subnets/import-windows/review")
@login_required
@_superadmin_required
def import_windows_review():
    token, entry = _get_win_import_plan()
    if entry is None:
        flash("Your Windows DHCP import expired or was never started — upload the export again.", "error")
        return redirect(url_for("subnets.import_windows"))
    plan = entry["plan"]
    suggested = _suggested_subnet_names(plan)
    rows = []
    for scope in plan.scopes:
        mapped = __win.scope_to_subnet(scope, suggested[scope.scope_id]["id"])
        rows.append(
            {
                "scope": scope,
                "suggested_id": suggested[scope.scope_id]["id"],
                "suggested_name": suggested[scope.scope_id]["name"],
                "cidr": mapped.subnet["subnet"],
                "pool_count": len(mapped.subnet["pools"]),
                "option_count": len(mapped.subnet["option-data"]),
                "reservation_count": len(scope.reservations),
                "policy_total": len(scope.policies),
                "policy_importable": len(mapped.classes),
            }
        )
    return render_template(
        "import_windows_review.html",
        plan=plan,
        rows=rows,
        server_options_count=len(plan.server_options),
    )


def _read_review_form(plan, form):
    """The review/preview form's fields -> (subnet_names, selections),
    the exact shapes win_dhcp_import.to_kea expects."""
    subnet_names = {}
    scope_selected = {}
    for scope in plan.scopes:
        sid = scope.scope_id
        scope_selected[sid] = form.get(f"include_{sid}") == "1"
        try:
            chosen_id = int(form.get(f"id_{sid}", "").strip())
        except (TypeError, ValueError):
            chosen_id = None
        chosen_name = form.get(f"name_{sid}", "").strip() or scope.name
        subnet_names[sid] = {"id": chosen_id, "name": chosen_name}
    selections = {"scopes": scope_selected, "server_options": form.get("server_options") == "1"}
    return subnet_names, selections


@bp.route("/subnets/import-windows/preview", methods=["POST"])
@login_required
@_superadmin_required
def import_windows_preview():
    token, entry = _get_win_import_plan()
    if entry is None:
        flash("Your Windows DHCP import expired or was never started — upload the export again.", "error")
        return redirect(url_for("subnets.import_windows"))
    plan = entry["plan"]

    subnet_names, selections = _read_review_form(plan, request.form)
    bad_ids = [
        sid for sid, sel in selections["scopes"].items() if sel and (subnet_names.get(sid) or {}).get("id") is None
    ]
    if bad_ids:
        flash("Every included scope needs a valid whole-number subnet ID.", "error")
        return redirect(url_for("subnets.import_windows_review"))
    chosen_ids = [v["id"] for k, v in subnet_names.items() if selections["scopes"].get(k) and v["id"] is not None]
    if len(chosen_ids) != len(set(chosen_ids)):
        flash("Two included scopes were given the same subnet ID — make them unique.", "error")
        return redirect(url_for("subnets.import_windows_review"))

    entry["subnet_names"] = subnet_names
    entry["selections"] = selections

    primary = extensions.KEA_SERVERS[0] if extensions.KEA_SERVERS else None
    if primary is None or not primary.get("ssh_host"):
        flash("The primary Kea server needs SSH configured before you can preview or apply an import.", "error")
        return redirect(url_for("subnets.import_windows_review"))

    existing_cfg, _sha = __host.read_config_versioned(primary, "dhcp4")
    if existing_cfg is None:
        flash("Could not read the primary server's kea-dhcp4.conf.", "error")
        return redirect(url_for("subnets.import_windows_review"))

    new_cfg, reservations, subnets_to_declare, report = __win.to_kea(plan, existing_cfg, subnet_names, selections)
    test_result = __host.test_config(primary, "dhcp4", new_cfg)

    # v5.28.0 (Q24, C4) — preview==apply: Apply pushes exactly this
    # candidate config (never a fresh to_kea() call) and refuses unless
    # it was actually test_config()-clean and the live config hasn't
    # moved since this sha was read.
    entry["preview_sha"] = _sha
    entry["candidate_cfg"] = new_cfg
    entry["reservation_rows"] = reservations
    entry["subnets_to_declare"] = subnets_to_declare
    entry["report"] = report
    entry["preview_ok"] = bool(test_result.get("ok"))

    from jen.services import config_revisions as _rev

    config_diff = _rev.diff(_rev.canonical(existing_cfg), _rev.canonical(new_cfg), "current", "after import")

    return render_template(
        "import_windows_preview.html",
        report=report,
        test_result=test_result,
        diff_rows=_diff_rows(config_diff),
        reservation_count=len(reservations),
        subnet_count=len(subnets_to_declare),
    )


def _finish_windows_import(token, entry):
    """The reservation-add + Jen SUBNET_MAP write + audit tail shared by
    import_windows_apply's happy path and import_windows_apply_reservations
    (v5.28.0, Q24, C4) — split out so a restart failure can defer this
    half instead of adding reservations against a Kea that may still be
    serving the OLD config."""
    reservation_rows = entry["reservation_rows"]
    subnets_to_declare = entry["subnets_to_declare"]
    report = entry["report"]

    reservation_results = {"added": 0, "errors": []}
    for res in reservation_rows:
        result = __kea.kea_command("reservation-add", arguments={"reservation": res})
        if result.get("result") == 0:
            reservation_results["added"] += 1
        else:
            reservation_results["errors"].append(
                f"{res['ip-address']} / {res['hw-address']}: {result.get('text', 'unknown error')}"
            )
    report.append(f"Reservations: {reservation_results['added']} added, {len(reservation_results['errors'])} failed.")
    report.extend(f"❌ reservation {e}" for e in reservation_results["errors"])

    if subnets_to_declare:
        new_map = dict(extensions.SUBNET_MAP)
        new_map.update(subnets_to_declare)
        __config.write_subnets_config(new_map)
        report.append(f"{len(subnets_to_declare)} subnet(s) registered with Jen.")

    _WIN_IMPORT_PLANS.pop(token, None)
    session.pop("win_import_token", None)
    __user.audit(
        "IMPORT_WINDOWS_DHCP",
        "apply",
        f"{len(subnets_to_declare)} subnet(s), {reservation_results['added']} reservation(s)",
    )
    return report


@bp.route("/subnets/import-windows/apply", methods=["POST"])
@login_required
@_superadmin_required
def import_windows_apply():
    token, entry = _get_win_import_plan()
    if entry is None or entry.get("selections") is None:
        flash("Your Windows DHCP import expired — upload the export again.", "error")
        return redirect(url_for("subnets.import_windows"))
    # v5.28.0 (Q24, C4) — preview==apply: apply pushes exactly the config
    # import_windows_preview already ran test_config() against, and
    # refuses if either that test failed or the live config has moved
    # since — never a fresh, unvalidated to_kea() call.
    if not entry.get("preview_ok"):
        flash("Preview the import — with a passing config test — before applying it.", "error")
        return redirect(url_for("subnets.import_windows_review"))

    primary = extensions.KEA_SERVERS[0] if extensions.KEA_SERVERS else None
    if primary is None or not primary.get("ssh_host"):
        flash("The primary Kea server needs SSH configured before you can apply an import.", "error")
        return redirect(url_for("subnets.import_windows_review"))

    live_cfg, live_sha = __host.read_config_versioned(primary, "dhcp4")
    if live_cfg is None:
        flash("Could not read the primary server's kea-dhcp4.conf.", "error")
        return redirect(url_for("subnets.import_windows_review"))
    if live_sha != entry["preview_sha"]:
        flash(
            "The Kea config on the primary server changed since you previewed this import — preview it again.", "error"
        )
        return redirect(url_for("subnets.import_windows_review"))

    apply_result = __host.apply_config(
        primary, "dhcp4", entry["candidate_cfg"], expect_sha256=entry["preview_sha"], summary="Windows DHCP import"
    )
    if apply_result["code"] == "conflict":
        flash(_conflict_flash(primary.get("name", "the primary server")), "error")
        return redirect(url_for("subnets.import_windows_review"))
    if apply_result["code"] != "ok":
        flash(f"Kea rejected the imported config: {apply_result.get('detail', apply_result['code'])}", "error")
        return redirect(url_for("subnets.import_windows_review"))

    report = entry["report"]
    restart = __host.service_action(primary, "dhcp4", "restart")
    if not restart["ok"]:
        # Config is live on disk but Kea hasn't picked it up — don't add
        # reservations against a server that may still be serving the OLD
        # subnets, and keep the plan around so the operator can retry
        # once Kea is actually restarted.
        report.append(f"⚠️ Config applied, but Kea did not restart cleanly: {restart['detail']}")
        flash(
            "The config was applied but Kea did not restart cleanly. Fix that on the server, then come back "
            "here to add the reservations.",
            "error",
        )
        return render_template("import_windows_result.html", report=report, restart_failed=True)
    report.append("✅ Kea restarted on the primary server.")

    report = _finish_windows_import(token, entry)
    return render_template("import_windows_result.html", report=report)


@bp.route("/subnets/import-windows/apply-reservations", methods=["POST"])
@login_required
@_superadmin_required
def import_windows_apply_reservations():
    """v5.28.0 (Q24, C4) — the retry path after apply's restart failed:
    the config is already live, this just finishes the reservation-add +
    Jen SUBNET_MAP write + audit that apply deferred."""
    token, entry = _get_win_import_plan()
    if entry is None or entry.get("reservation_rows") is None:
        flash("Your Windows DHCP import expired — upload the export again.", "error")
        return redirect(url_for("subnets.import_windows"))
    report = _finish_windows_import(token, entry)
    return render_template("import_windows_result.html", report=report)
