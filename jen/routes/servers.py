"""
jen/routes/servers.py
──────────────────────
Kea server management routes.
"""

import json
import logging

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.user as __user
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.kea_host as __host
from jen import extensions
from jen.services import config_revisions as __rev
from jen.services.access import admin_required as _admin_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)
bp = Blueprint("servers", __name__)

_HISTORY_SERVICES = ("dhcp4", "dhcp6")


def _find_server(server_id):
    return next((s for s in extensions.KEA_SERVERS if s["id"] == server_id), None)


def _history_service(raw):
    return raw if raw in _HISTORY_SERVICES else "dhcp4"


def _diff_rows(diff_lines):
    """Tag each unified-diff line with a CSS class. The text itself is
    escaped by Jinja autoescaping in the template — never rendered raw."""
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
            s["lease_stats"] = (
                stats_result.get("arguments", {}).get("result-set", {}) if stats_result.get("result") == 0 else {}
            )
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
                    f"reported state: {', '.join(sorted(reported))}"
                    if reported
                    else "no server has reported an HA state yet"
                )

    history_allowed = current_user.all_subnets
    history_counts = {s["server"]["id"]: __rev.count(s["server"]["id"]) for s in statuses} if history_allowed else {}

    return render_template(
        "servers.html",
        statuses=statuses,
        single_server=single_server,
        ha_mode=ha_mode,
        ha_degraded=ha_degraded,
        ha_degraded_reason=ha_degraded_reason,
        subnet_map=extensions.SUBNET_MAP,
        history_allowed=history_allowed,
        history_counts=history_counts,
    )


@bp.route("/servers/restart/<int:server_id>", methods=["POST"])
@login_required
@_admin_required
def restart_kea_server(server_id):
    server = next((s for s in extensions.KEA_SERVERS if s["id"] == server_id), None)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for("servers.servers"))
    if not server["ssh_host"]:
        flash("SSH not configured for this server.", "error")
        return redirect(url_for("servers.servers"))
    try:
        # v5.11.0 — via jen.services.kea_host (helper op `service`, or the
        # legacy dual-name systemctl). Both unit names are tried inside it.
        res = __host.service_action(server, "dhcp4", "restart")
        if res["ok"]:
            flash(f"Kea restarted on {server['name']}.", "success")
            __user.audit("RESTART_KEA", server["name"], "Remote restart via jen-kea-helper")
        else:
            flash(f"Restart failed on {server['name']}: {res['detail']}", "error")
    except Exception as e:
        logger.error(f"SSH error restarting Kea on {server['name']}: {e}")
        flash(f"Could not reach {server['name']} — check server logs for details.", "error")
    return redirect(url_for("servers.servers"))


# ── Config history (v5.16.0 — Q11) ─────────────────────────────────────────
#
# Every config Jen writes to a Kea host is recorded in kea_config_revisions
# (jen/services/config_revisions.py). These pages show that history and let a
# superadmin restore a prior revision. The full config for a server is
# visible here — including subnets a restricted admin can't otherwise see —
# so all three pages require unrestricted subnet access, not just admin.


def _history_gate(server_id):
    """(server, None) when the caller may view this server's history, or
    (None, redirect) when they may not."""
    server = _find_server(server_id)
    if not server:
        flash("Server not found.", "error")
        return None, redirect(url_for("servers.servers"))
    if not current_user.all_subnets:
        flash("Config history needs access to all subnets.", "error")
        return None, redirect(url_for("servers.servers"))
    return server, None


@bp.route("/servers/<int:server_id>/config-history")
@login_required
@_admin_required
def config_history(server_id):
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    service = _history_service(request.args.get("service", "dhcp4"))
    revisions = __rev.list_revisions(server_id, service, limit=200)
    return render_template(
        "config_history.html",
        server=server,
        service=service,
        revisions=revisions,
        ipv6_enabled=__kea6.is_ipv6_enabled(),
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>")
@login_required
@_admin_required
def config_history_detail(server_id, rev_id):
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    rev = __rev.get(rev_id)
    if not rev or rev["server_id"] != server_id:
        flash("Revision not found.", "error")
        return redirect(url_for("servers.config_history", server_id=server_id))
    service = rev["service"]
    prev = __rev.previous(rev_id, server_id, service)
    rows = _diff_rows(
        __rev.diff(
            prev["config"] if prev else "",
            rev["config"],
            a_label=f"#{prev['id']}" if prev else "(nothing before this)",
            b_label=f"#{rev_id}",
        )
    )
    latest = __rev.latest(server_id, service)
    return render_template(
        "config_history_detail.html",
        server=server,
        rev=rev,
        rows=rows,
        is_latest=bool(latest and latest["id"] == rev_id),
        can_restore=current_user.is_superadmin and bool(server.get("ssh_host")),
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>/download")
@login_required
@_admin_required
def config_history_download(server_id, rev_id):
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    rev = __rev.get(rev_id)
    if not rev or rev["server_id"] != server_id:
        abort(404)
    return Response(
        rev["config"],
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="config-{rev["service"]}-rev{rev_id}.json"'},
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>/restore", methods=["POST"])
@login_required
@_superadmin_required
def config_history_restore(server_id, rev_id):
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    rev = __rev.get(rev_id)
    if not rev or rev["server_id"] != server_id:
        flash("Revision not found.", "error")
        return redirect(url_for("servers.config_history", server_id=server_id))
    service = rev["service"]
    back = redirect(url_for("servers.config_history", server_id=server_id, service=service))

    if not server.get("ssh_host"):
        flash("SSH is not configured for this server.", "error")
        return back
    try:
        cfg = json.loads(rev["config"])
    except ValueError:
        flash("This revision's stored config is not valid JSON — cannot restore.", "error")
        return back

    test = __host.test_config(server, service, cfg)
    if not test["ok"]:
        flash(
            f"Restore aborted — {server['name']} rejected revision #{rev_id}: {test.get('detail') or 'unknown error'}",
            "error",
        )
        return back

    latest = __rev.latest(server_id, service)
    res = __host.apply_config(
        server,
        service,
        cfg,
        expect_sha256=(latest["sha256"] if latest and latest.get("sha256") else None),
        summary=f"restore of #{rev_id}",
        source="restore",
    )
    if res.get("code") == "conflict":
        flash(
            f"The Kea config on {server['name']} changed since this page loaded — restore was NOT applied. "
            "Reload and try again.",
            "error",
        )
        return back
    if not res.get("ok"):
        flash(f"Restore failed on {server['name']}: {res.get('detail') or 'unknown error'}", "error")
        return back

    restart = __host.service_action(server, service, "restart")
    if restart["ok"]:
        flash(f"Restored revision #{rev_id} to {server['name']} and restarted Kea.", "success")
    else:
        flash(
            f"Restored revision #{rev_id} to {server['name']} — restart Kea manually ({restart.get('detail') or ''}).",
            "warning",
        )
    __user.audit("RESTORE_KEA_CONFIG", server["name"], f"service={service} revision={rev_id}")
    return back
