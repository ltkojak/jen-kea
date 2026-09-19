"""
jen/routes/trace.py
────────────────────
v5.48.0 (Q49) — "what actually happened to this client": /tools/trace tails
a Kea server's kea-dhcp4 log (helper op `tail-log` — no capture, no new
privilege), keeps the lines that name one MAC, and shows them grouped
into exchanges next to Explain's prediction for the same client.

Admin only, and subnet-restricted: the log can contain other clients'
data, so the MAC's current lease/reservation subnet must be one the user
can access (a MAC Jen has never seen leased or reserved is only shown to a
user with access to every subnet — there's no subnet to check against).
Never part of the support bundle.
"""

import logging

from flask import Blueprint, abort, render_template, request
from flask_login import current_user, login_required

import jen.services.auth as __auth
import jen.services.kea_host as __host
import jen.services.kea_log_trace as __trace
from jen import extensions
from jen.routes.explain import _hex_identifier, _load_lease, _load_reservations
from jen.services.access import admin_required as _admin_required
from jen.services.access import get_accessible_subnet_map
from jen.services.dhcp_explain import explain
from jen.services.subnet_context import dhcp4_config

logger = logging.getLogger(__name__)
bp = Blueprint("trace", __name__)

# tail-log's own hard cap (jen-kea-helper op_tail_log) — asking for more
# would just be silently truncated to this.
MAX_LINES = 1000
DEFAULT_LINES = 1000
WATCH_STEP_S = 5
WATCH_MAX_S = 60


def _pick_server(raw: str) -> dict | None:
    servers = extensions.KEA_SERVERS or []
    if raw.isdigit():
        for s in servers:
            if str(s.get("id")) == raw:
                return s
    return servers[0] if servers else None


@bp.route("/tools/trace")
@login_required
@_admin_required
def trace_page():
    mac_raw = (request.args.get("mac") or "").strip().lower()
    server = _pick_server((request.args.get("server") or "").strip())
    try:
        lines = max(50, min(int(request.args.get("lines", DEFAULT_LINES)), MAX_LINES))
    except ValueError:
        lines = DEFAULT_LINES
    watch = request.args.get("watch") == "1"
    try:
        watched_s = max(0, int(request.args.get("t", 0)))
    except ValueError:
        watched_s = 0
    # Watch mode re-tails every WATCH_STEP_S via hx-get, for at most
    # WATCH_MAX_S — enforced here, server-side (the partial simply stops
    # emitting hx-trigger), not by page JS.
    watching = watch and watched_s < WATCH_MAX_S

    ctx = {
        "mac": mac_raw,
        "servers": extensions.KEA_SERVERS or [],
        "server_id": str(server.get("id")) if server else "",
        "lines": lines,
        "watching": watching,
        "next_t": watched_s + WATCH_STEP_S,
        "watch_step": WATCH_STEP_S,
        "log_path": extensions.DHCP4_LOG,
        "error": "",
        "groups": None,
        "note": "",
        "explained": None,
        "subnet_id": None,
        "total_events": 0,
    }

    if mac_raw:
        if not __auth.valid_mac(mac_raw):
            ctx["error"] = "That isn't a MAC address (expected aa:bb:cc:dd:ee:ff)."
        elif server is None:
            ctx["error"] = "No Kea server is configured."
        else:
            mac_hex = _hex_identifier(mac_raw)
            lease = _load_lease(mac_hex)
            reservations = _load_reservations(mac_hex, "")
            subnet_map = get_accessible_subnet_map()
            known_subnets = {int(lease["subnet_id"])} if lease and lease.get("subnet_id") else set()
            known_subnets |= {int(r["subnet_id"]) for r in reservations if r["subnet_id"]}
            if known_subnets:
                if not (known_subnets & set(subnet_map)):
                    abort(403)
            elif not current_user.all_subnets:
                abort(403)

            res = __host.tail_log(server, extensions.DHCP4_LOG, lines)
            if res["code"] == "missing":
                ctx["error"] = (
                    f"Log file not found on the Kea server: {extensions.DHCP4_LOG}. "
                    "Set [kea] dhcp4_log_path in jen.config if kea-dhcp4 logs elsewhere."
                )
            elif not res["ok"]:
                logger.error(f"trace: tail_log failed: {res.get('detail')}")
                ctx["error"] = "Could not read the Kea log. Check server logs for details."
            else:
                log_lines = res.get("lines", [])
                events = __trace.parse_lines(log_lines, mac_raw)
                ctx["groups"] = list(reversed(__trace.group_exchanges(events)))
                ctx["total_events"] = len(events)
                ctx["note"] = __trace.visibility_note(events, len(log_lines))

            chosen = next(iter(known_subnets & set(subnet_map)), None)
            if chosen is not None:
                cfg = dhcp4_config()
                if cfg:
                    result = explain(
                        cfg,
                        {"mac": mac_raw},
                        subnet_id=chosen,
                        reservations=[r for r in reservations if r["subnet_id"] in (0, *subnet_map)],
                        lease=lease,
                    )
                    if result.get("ok"):
                        ctx["explained"] = result
                        ctx["subnet_id"] = chosen

    if request.headers.get("HX-Request") == "true":
        return render_template("_trace_results.html", **ctx)
    return render_template("trace.html", **ctx)
