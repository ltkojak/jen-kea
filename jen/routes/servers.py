"""
jen/routes/servers.py
──────────────────────
Kea server management routes.
"""

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.models.user as __user
import jen.services.ha_maintenance as __maint
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.kea_authoring as __authoring
import jen.services.kea_ha as __ha
import jen.services.kea_host as __host
import jen.services.packet_health as __packet_health
from jen import extensions
from jen.services import config_revisions as __rev
from jen.services.access import admin_required as _admin_required
from jen.services.access import diagnostic_surface
from jen.services.access import is_admin_or_above as _is_admin_or_above
from jen.services.access import is_superadmin as _is_superadmin
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required
from jen.services.crypto import SecretDecryptError

logger = logging.getLogger(__name__)
bp = Blueprint("servers", __name__)

_HISTORY_SERVICES = ("dhcp4", "dhcp6")


def _find_server(server_id):
    return next((s for s in extensions.KEA_SERVERS if s["id"] == server_id), None)


# Named for the block's "received / offered / acked / naked / dropped /
# parse-failed / allocation-failed" rate rows — every other pkt4-*/v4-*
# key the server reports still shows up in the "all counters" table.
_PACKET_HEALTH_NAMED_KEYS = (
    ("pkt4-received", "Received"),
    ("pkt4-offer-sent", "Offered"),
    ("pkt4-ack-sent", "Acked"),
    ("pkt4-nak-sent", "Naked"),
    ("pkt4-receive-drop", "Dropped"),
    ("pkt4-parse-failed", "Parse failed"),
)


def _packet_health_for_server(server_id, window_minutes=60):
    """None until a server has two snapshots (see
    jen.services.alerts.take_server_stats_snapshot / migration 26)."""
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT snapshot_time, stats FROM server_stats WHERE server_id=%s "
                "AND snapshot_time > DATE_SUB(NOW(), INTERVAL 90 MINUTE) ORDER BY snapshot_time",
                (server_id,),
            )
            raw_rows = cur.fetchall()
    except Exception as e:
        logger.warning(f"packet health for server {server_id}: {e}")
        return None

    rows = []
    for r in raw_rows:
        stats = r["stats"]
        if isinstance(stats, str):
            stats = json.loads(stats)
        rows.append({"snapshot_time": r["snapshot_time"], "stats": stats})
    if len(rows) < 2:
        return None

    deltas = __packet_health.deltas(rows)
    rates = __packet_health.rates(deltas, window_minutes=window_minutes)
    assessment = __packet_health.assess(rates)

    totals = rates["totals"]
    alloc_fail_total = sum(v for k, v in totals.items() if k.startswith("v4-allocation-fail"))
    named = [{"label": label, "key": key, "total": totals.get(key, 0)} for key, label in _PACKET_HEALTH_NAMED_KEYS]
    named.append({"label": "Allocation failed", "key": "v4-allocation-fail*", "total": alloc_fail_total})
    named_keys = {key for key, _label in _PACKET_HEALTH_NAMED_KEYS}
    # Kea 3.2's extra drop reasons: shown only when the server actually
    # reports the key (3.0 reports none of them — a row of zeros there
    # would read as "checked and clean").
    for key, label in __packet_health.DROP_REASON_LABELS.items():
        if key in totals:
            named.append({"label": label, "key": key, "total": totals[key]})
            named_keys.add(key)
    other_counters = sorted((k, v) for k, v in totals.items() if k not in named_keys)

    return {
        "status": assessment["status"],
        "notes": assessment["notes"],
        "window_minutes": round(rates["window_minutes"]),
        "named": named,
        "other_counters": other_counters,
        "sparkline": [{"ts": d["ts"].isoformat(), "received": d["delta"].get("pkt4-received", 0)} for d in deltas],
    }


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
@diagnostic_surface(subject="client")
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
            s["packet_health"] = _packet_health_for_server(s["server"]["id"])
        else:
            s["version"] = ""
            s["lease_stats"] = {}
            s["packet_health"] = None
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

    # v5.21.0 (Q16) — the HA console. status-get / config-get are only
    # worth the extra round trips on a genuine multi-server deployment;
    # a single-server install never has an HA hook to report.
    compare_rows = []
    if not single_server:
        for s in statuses:
            if s["up"]:
                s["ha_status"] = __ha.ha_status(s["server"])
                cfg_result = __kea.kea_command("config-get", server=s["server"])
                dhcp4_cfg = cfg_result.get("arguments", {}).get("Dhcp4", {}) if cfg_result.get("result") == 0 else {}
                s["ha_config"] = __ha.ha_config(dhcp4_cfg)
            else:
                s["ha_status"] = None
                s["ha_config"] = None
        if any(s["ha_status"] for s in statuses):
            compare_rows = __ha.compare_assigned([s["server"] for s in statuses if s["up"]])

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
        ha_actions=__ha.HA_ACTIONS,
        compare_rows=compare_rows,
        packet_health_sparklines={
            s["server"]["id"]: s["packet_health"]["sparkline"] for s in statuses if s["packet_health"]
        },
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


# ── HA console (v5.21.0 — Q16) ────────────────────────────────────────────
#
# Every HA command Jen can send is in kea_ha.HA_ACTIONS — nothing outside
# that allowlist ever reaches kea_command(). "heartbeat" is a read-only
# state check (admin); everything else changes HA state (superadmin).


def _ha_role_denied(role: str) -> bool:
    if role == "superadmin":
        return not _is_superadmin()
    return not _is_admin_or_above()


@bp.route("/servers/ha/<int:server_id>/<action>", methods=["POST"])
@login_required
def ha_action(server_id, action):
    spec = __ha.HA_ACTIONS.get(action)
    if not spec:
        abort(404)
    if _ha_role_denied(spec["role"]):
        message = (
            "SuperAdmin access required for this HA action."
            if spec["role"] == "superadmin"
            else "Admin access required."
        )
        return render_template("error.html", code=403, message=message), 403

    server = _find_server(server_id)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for("servers.servers"))

    args = {}
    if action == "sync":
        cfg_result = __kea.kea_command("config-get", server=server)
        dhcp4_cfg = cfg_result.get("arguments", {}).get("Dhcp4", {}) if cfg_result.get("result") == 0 else {}
        ha_cfg = __ha.ha_config(dhcp4_cfg)
        partner = __ha.partner_name(ha_cfg) if ha_cfg else None
        if not partner:
            flash(f"Could not determine {server['name']}'s HA partner from its config — not syncing.", "error")
            return redirect(url_for("servers.servers"))
        args = {"server-name": partner, "max-period": 60}
    elif action == "scopes":
        scopes = request.form.getlist("scopes")
        if not scopes:
            flash("Select at least one scope to serve.", "error")
            return redirect(url_for("servers.servers"))
        args = {"scopes": scopes}

    result = __kea.kea_command(spec["command"], "dhcp4", args, server=server)
    text = result.get("text") or ("Done." if result.get("result") == 0 else "Failed.")
    level = "success" if result.get("result") == 0 else "error"
    flash(f"{server['name']}: {text}", level)
    __user.audit("ha_" + action, server["name"], text)
    return redirect(url_for("servers.servers"))


# ── Planned maintenance (v5.38.0 — Q37) ────────────────────────────────────
#
# A guided page around the HA maintenance commands, using no new Kea
# command: pick the server to TAKE DOWN (A); Jen resolves its partner B
# from both servers' own HA configs, runs the relevant Health checks as
# a preflight, sends `ha-maintenance-start` to B (the server that keeps
# serving — see kea_ha.HA_ACTIONS), polls both until Kea reports the
# handover, and then waits for A to come back. State lives in the
# session (nothing new in the DB); every transition is audited on both
# server names. The page polls a partial every 5 s — no auto-advance
# past "do your work": the operator clicks Back.

_MAINT_KEY = "ha_maint"


def _maint_state():
    return session.get(_MAINT_KEY)


def _maint_save(state):
    session[_MAINT_KEY] = state
    session.modified = True


def _maint_clear():
    session.pop(_MAINT_KEY, None)


def _maint_servers(state):
    """(down, up) server dicts for a stored state, or (None, None) when
    either has been removed from Settings → Kea since."""
    if not state:
        return None, None
    return _find_server(state.get("down")), _find_server(state.get("up"))


def _ha_configs_for_all():
    out = {}
    for s in extensions.KEA_SERVERS:
        r = __kea.kea_command("config-get", server=s)
        dhcp4 = r.get("arguments", {}).get("Dhcp4", {}) if r.get("result") == 0 else None
        out[s["id"]] = __ha.ha_config(dhcp4) if dhcp4 is not None else None
    return out


def _maint_status(server):
    try:
        return __ha.ha_status(server)
    except Exception as e:
        logger.warning(f"ha maintenance: status of {server.get('name')}: {e}")
        return None


def _maint_audit(step, state, detail=""):
    __user.audit(f"ha_maintenance_{step}", f"{state.get('down_name')} / {state.get('up_name')}", detail)


def _maint_view(state):
    """Everything the status partial needs; advances the stored step when
    the stepper says so."""
    down, up = _maint_servers(state)
    if down is None or up is None:
        return None
    view = __maint.next_step(state, _maint_status(down), _maint_status(up))
    if view["advance"]:
        state["step"] = view["advance"]
        state["step_at"] = datetime.now(timezone.utc).isoformat()
        _maint_save(state)
        _maint_audit(view["advance"], state, view["message"])
        view["step"] = state["step"]
    view["down"] = down
    view["up"] = up
    view["state"] = state
    view["step_index"] = __maint.STEPS.index(state["step"])
    return view


@bp.route("/servers/ha/maintenance")
@login_required
@_superadmin_required
@_recent_auth_required(10)
def ha_maintenance():
    state = _maint_state()
    if state:
        view = _maint_view(state)
        if view is None:
            _maint_clear()
            flash("A server in the running maintenance flow is no longer configured — starting over.", "error")
            return redirect(url_for("servers.ha_maintenance"))
        return render_template("ha_maintenance.html", state=state, view=view, steps=__maint.STEPS, servers=None)
    try:
        preselect = int(request.args.get("down", "0") or 0)
    except ValueError:
        preselect = 0
    return render_template(
        "ha_maintenance.html",
        state=None,
        view=None,
        steps=__maint.STEPS,
        servers=list(extensions.KEA_SERVERS),
        preselect=preselect,
        ha_mode=extensions.cfg.get("kea", "ha_mode", fallback=""),
    )


@bp.route("/servers/ha/maintenance/begin", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(10)
def ha_maintenance_begin():
    try:
        down_id = int(request.form.get("down", ""))
    except ValueError:
        flash("Pick the server to take down.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    down = _find_server(down_id)
    if down is None:
        flash("Server not found.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    configs = _ha_configs_for_all()
    up, reason = __maint.resolve_partner(down, extensions.KEA_SERVERS, configs)
    if up is None:
        flash(reason, "error")
        return redirect(url_for("servers.ha_maintenance"))

    from jen.services import health as _health

    checks = _health.run_checks({"subnet_filter": lambda _sid: True})
    wanted = {c.id: c for c in checks if c.id in __maint.PREFLIGHT_CHECK_IDS}
    preflight = [
        {"id": cid, "title": wanted[cid].title, "status": wanted[cid].status, "detail": wanted[cid].detail[:160]}
        for cid in __maint.PREFLIGHT_CHECK_IDS
        if cid in wanted
    ]
    state = {
        "down": down["id"],
        "up": up["id"],
        "down_name": down["name"],
        "up_name": up["name"],
        "step": "preflight",
        "step_at": datetime.now(timezone.utc).isoformat(),
        "leases_shared": __maint.leases_shared(configs.get(down["id"])),
        "preflight": preflight,
        "preflight_ok": not any(p["status"] == "fail" for p in preflight),
    }
    _maint_save(state)
    _maint_audit("preflight", state, "; ".join(f"{p['id']}={p['status']}" for p in preflight))
    return redirect(url_for("servers.ha_maintenance"))


@bp.route("/servers/ha/maintenance/status")
@login_required
@_superadmin_required
def ha_maintenance_status():
    state = _maint_state()
    view = _maint_view(state) if state else None
    if request.args.get("partial") == "1":
        if view is None:
            return render_template("_ha_maintenance_status.html", view=None)
        return render_template("_ha_maintenance_status.html", view=view)
    if view is None:
        return jsonify({"active": False})
    return jsonify(
        {
            "active": True,
            "step": view["step"],
            "down": {"id": view["down"]["id"], "name": view["down"]["name"], "state": view["down_state"]},
            "up": {"id": view["up"]["id"], "name": view["up"]["name"], "state": view["up_state"]},
            "can_cancel": view["can_cancel"],
            "timed_out": view["timed_out"],
            "message": view["message"],
        }
    )


def _maint_send(server, action):
    spec = __ha.HA_ACTIONS[action]
    result = __kea.kea_command(spec["command"], "dhcp4", {}, server=server)
    ok = result.get("result") == 0
    text = result.get("text") or ("Done." if ok else "Failed.")
    return ok, text


@bp.route("/servers/ha/maintenance/handover", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(10)
def ha_maintenance_handover():
    state = _maint_state()
    down, up = _maint_servers(state)
    if not state or state.get("step") != "preflight" or up is None:
        flash("Start the maintenance flow first.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    if not state.get("preflight_ok"):
        flash("A preflight check failed — fix it (or start over) before handing over.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    # ha-maintenance-start goes to the server that KEEPS serving: B.
    ok, text = _maint_send(up, "maintenance-start")
    _maint_audit("handover", state, f"ha-maintenance-start → {up['name']}: {text}")
    if not ok:
        flash(f"{up['name']} refused ha-maintenance-start: {text}", "error")
        return redirect(url_for("servers.ha_maintenance"))
    state["step"] = "handover"
    state["step_at"] = datetime.now(timezone.utc).isoformat()
    _maint_save(state)
    flash(f"{up['name']} is taking over; waiting for {down['name']} to enter in-maintenance.", "success")
    return redirect(url_for("servers.ha_maintenance"))


@bp.route("/servers/ha/maintenance/cancel", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(10)
def ha_maintenance_cancel():
    state = _maint_state()
    down, up = _maint_servers(state)
    if not state or up is None:
        flash("No maintenance flow is running.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    ok, text = _maint_send(up, "maintenance-cancel")
    _maint_audit("cancel", state, f"ha-maintenance-cancel → {up['name']}: {text}")
    if not ok:
        flash(f"{up['name']} refused ha-maintenance-cancel: {text}", "error")
        return redirect(url_for("servers.ha_maintenance"))
    _maint_clear()
    flash(f"Handover cancelled — {down['name']} and {up['name']} return to their previous states.", "success")
    return redirect(url_for("servers.servers"))


@bp.route("/servers/ha/maintenance/back", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(10)
def ha_maintenance_back():
    state = _maint_state()
    if not state or state.get("step") != "work":
        flash("Nothing to bring back yet.", "error")
        return redirect(url_for("servers.ha_maintenance"))
    state["step"] = "back"
    state["step_at"] = datetime.now(timezone.utc).isoformat()
    _maint_save(state)
    _maint_audit("back", state)
    return redirect(url_for("servers.ha_maintenance"))


@bp.route("/servers/ha/maintenance/finish", methods=["POST"])
@login_required
@_superadmin_required
def ha_maintenance_finish():
    state = _maint_state()
    if state:
        _maint_audit("finish", state, f"ended at step {state.get('step')}")
    _maint_clear()
    return redirect(url_for("servers.servers"))


@bp.route("/servers/ha/<int:server_id>/status.json")
@login_required
@_admin_required
def ha_status_json(server_id):
    server = _find_server(server_id)
    if server is None:
        return jsonify({"error": "not found"}), 404
    status = _maint_status(server)
    if status is None:
        return jsonify({"reachable": False, "id": server_id, "name": server["name"]})
    return jsonify({"reachable": True, "id": server_id, "name": server["name"], **status})


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


def _get_revision_or_flash(server_id, rev_id):
    """(rev, None) or (None, redirect). v5.20.0 — a revision's config is
    encrypted at rest; SecretDecryptError (the wrong /etc/jen/mfa_key for
    this row, typically after restoring a DB from a different install)
    is Jen's own text, so it becomes a flash here instead of a 500."""
    try:
        rev = __rev.get(rev_id)
    except SecretDecryptError as exc:
        flash(str(exc), "error")
        return None, redirect(url_for("servers.config_history", server_id=server_id))
    if not rev or rev["server_id"] != server_id:
        flash("Revision not found.", "error")
        return None, redirect(url_for("servers.config_history", server_id=server_id))
    return rev, None


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
    rev, deny = _get_revision_or_flash(server_id, rev_id)
    if deny:
        return deny
    service = rev["service"]
    rows = []
    is_latest = False
    try:
        prev = __rev.previous(rev_id, server_id, service)
        # v5.20.0 (15E) — the diff shows MASKED bodies on both sides;
        # secrets never appear in an admin-visible diff, only via the
        # step-up-gated raw download below.
        prev_masked = __rev.canonical(__authoring.redact_secrets(json.loads(prev["config"]))) if prev else ""
        rev_masked = __rev.canonical(__authoring.redact_secrets(json.loads(rev["config"])))
        rows = _diff_rows(
            __rev.diff(
                prev_masked,
                rev_masked,
                a_label=f"#{prev['id']}" if prev else "(nothing before this)",
                b_label=f"#{rev_id}",
            )
        )
        latest = __rev.latest(server_id, service)
        is_latest = bool(latest and latest["id"] == rev_id)
    except SecretDecryptError as exc:
        flash(str(exc), "error")
    return render_template(
        "config_history_detail.html",
        server=server,
        rev=rev,
        rows=rows,
        is_latest=is_latest,
        can_restore=current_user.is_superadmin and bool(server.get("ssh_host")),
        can_download_raw=current_user.is_superadmin,
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>/download")
@login_required
@_admin_required
def config_history_download(server_id, rev_id):
    """Masked download — secrets replaced with "********", same as the
    diff view. See config_history_download_raw for the real body."""
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    try:
        rev = __rev.get(rev_id)
    except SecretDecryptError as exc:
        flash(str(exc), "error")
        return redirect(url_for("servers.config_history", server_id=server_id))
    if not rev or rev["server_id"] != server_id:
        abort(404)
    masked = __rev.canonical(__authoring.redact_secrets(json.loads(rev["config"])))
    return Response(
        masked,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="config-{rev["service"]}-rev{rev_id}.json"'},
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>/download-raw")
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def config_history_download_raw(server_id, rev_id):
    """Unmasked download — the real secrets, for a superadmin who has
    authenticated recently (Q6's step-up pattern). Every download is
    audited."""
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    try:
        rev = __rev.get(rev_id)
    except SecretDecryptError as exc:
        flash(str(exc), "error")
        return redirect(url_for("servers.config_history", server_id=server_id))
    if not rev or rev["server_id"] != server_id:
        abort(404)
    __user.audit("DOWNLOAD_KEA_CONFIG_RAW", server["name"], f"service={rev['service']} revision={rev_id}")
    return Response(
        rev["config"],
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="config-{rev["service"]}-rev{rev_id}-unmasked.json"'},
    )


@bp.route("/servers/<int:server_id>/config-history/<int:rev_id>/restore", methods=["POST"])
@login_required
@_superadmin_required
def config_history_restore(server_id, rev_id):
    server, deny = _history_gate(server_id)
    if deny:
        return deny
    rev, deny = _get_revision_or_flash(server_id, rev_id)
    if deny:
        return deny
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

    try:
        latest = __rev.latest(server_id, service)
    except SecretDecryptError as exc:
        flash(str(exc), "error")
        return back
    # v5.20.0 — a "raw" latest sha is directly comparable to what a
    # helper v2 apply-config will re-hash; a "canonical"/"legacy" one is
    # NOT (it hashes a different thing entirely, so comparing it would
    # either always mismatch or coincidentally "match" nothing real).
    # With no raw baseline to check against yet, read the LIVE sha right
    # before the write instead of skipping the guard outright — the same
    # short-window pattern the add/delete routes already use.
    if latest and latest.get("hash_kind") == "raw":
        expect = latest["sha256"]
    else:
        _live_cfg, expect = __host.read_config_versioned(server, service)
    res = __host.apply_config(
        server,
        service,
        cfg,
        expect_sha256=expect,
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
