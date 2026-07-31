"""
jen/routes/dashboard.py
────────────────────────
Dashboard and stats routes.
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
from jen.services.fingerprint import DEVICE_TYPE_DISPLAY
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("dashboard", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/")
@login_required
def dashboard():
    try:
        hours = float(request.args.get("hours", "0.5"))
    except ValueError:
        hours = 0.5
    if hours not in (0.5, 1, 4, 8, 12, 24):
        hours = 0.5
    hours_str = str(int(hours)) if hours == int(hours) else str(hours)

    # Build skeleton stats — filtered to subnets this user can access
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    stats = {
        sid: {"active": "…", "dynamic": "…", "reservations": "…",
              "name": info["name"], "cidr": info["cidr"],
              "routers": "", "dns_servers": ""}
        for sid, info in accessible_subnet_map.items()
    }

    # Enrich with routers + DNS from Kea config (static values, render server-side)
    try:
        kea_cfg = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        kea_subnets = {}
        if isinstance(kea_cfg, dict) and kea_cfg.get("result") == 0:
            for s in kea_cfg.get("arguments", {}).get("Dhcp4", {}).get("subnet4", []):
                sid = s.get("id")
                routers = ""
                dns_servers = ""
                for opt in s.get("option-data", []):
                    if opt.get("name") == "routers":
                        routers = opt.get("data", "")
                    elif opt.get("name") == "domain-name-servers":
                        dns_servers = opt.get("data", "")
                kea_subnets[sid] = {"routers": routers, "dns_servers": dns_servers}
        for sid in stats:
            if sid in kea_subnets:
                stats[sid]["routers"]     = kea_subnets[sid]["routers"]
                stats[sid]["dns_servers"] = kea_subnets[sid]["dns_servers"]
    except Exception:
        pass  # Non-fatal — cards still render without gateway/DNS

    server_statuses = [
        {"server": s, "up": None, "ha_state": None, "ha_partner": None, "version": ""}
        for s in extensions.KEA_SERVERS
    ]

    recent = []
    device_info = {}
    try:
        with __db.kea_db() as db:
            window_seconds = int(hours * 3600)
            with db.cursor() as cur:
                # Filter recent leases to accessible subnets
                subnet_clause = ""
                subnet_params = []
                if not current_user.all_subnets:
                    ids = current_user.accessible_subnet_ids(extensions.SUBNET_MAP)
                    if ids:
                        placeholders = ",".join(["%s"] * len(ids))
                        subnet_clause = f"AND l.subnet_id IN ({placeholders})"
                        subnet_params = ids
                    else:
                        subnet_clause = "AND 1=0"
                cur.execute(f"""
                    SELECT inet_ntoa(l.address) AS ip, l.hostname,
                           HEX(l.hwaddr) AS mac_hex, l.subnet_id,
                           (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained
                    FROM lease4 l
                    WHERE l.state=0
                      AND l.expire > NOW()
                      AND (l.expire - INTERVAL l.valid_lifetime SECOND) > (NOW() - INTERVAL %s SECOND)
                      {subnet_clause}
                    ORDER BY (l.expire - INTERVAL l.valid_lifetime SECOND) DESC
                    LIMIT 50
                """, [window_seconds] + subnet_params)
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    sname = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", str(row["subnet_id"]))
                    recent.append({"ip": row["ip"], "hostname": row["hostname"] or "",
                                    "mac": mac, "subnet_id": row["subnet_id"],
                                    "subnet_name": sname, "obtained": row["obtained"]})
        mac_list = [l["mac"] for l in recent if l.get("mac")]
        device_info = __fp.get_device_info_map(mac_list)
    except Exception as e:
        logger.error(f"Dashboard recent leases error: {e}")

    template_vars = dict(
        stats=stats, recent=recent, kea_up=None,
        subnet_map=accessible_subnet_map, pool_sizes={},
        hours=hours_str, server_statuses=server_statuses,
        device_info=device_info,
        get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
        device_type_display=__fp.DEVICE_TYPE_DISPLAY
    )
    # HTMX time window change — return just the recent leases rows
    if request.headers.get("HX-Request") == "true":
        return render_template("_recent_leases_rows.html", **template_vars), 200
    return render_template("dashboard.html", **template_vars)

# ─────────────────────────────────────────
# Leases
# ─────────────────────────────────────────

@bp.route("/api/saved-searches")
@login_required
def api_saved_searches():
    page = request.args.get("page", "")
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                if page:
                    cur.execute("SELECT * FROM saved_searches WHERE user_id=%s AND page=%s ORDER BY name", (current_user.id, page))
                else:
                    cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY name", (current_user.id,))
                searches = cur.fetchall()
        return jsonify([dict(s) for s in searches])
    except Exception:
        return jsonify([])

# ─────────────────────────────────────────
# Dashboard Preferences
# ─────────────────────────────────────────
@bp.route("/api/dashboard/save-prefs", methods=["POST"])
@login_required
def save_dashboard_prefs():
    import json
    widgets = request.json.get("widgets", ["subnet_stats", "recent_leases"])
    valid = {"subnet_stats", "recent_leases", "top_devices", "lease_sparklines",
             "alert_summary", "server_status", "lease_history_chart", "totals"}
    widgets = [w for w in widgets if w in valid]
    if not widgets:
        widgets = ["subnet_stats", "totals", "recent_leases", "server_status"]
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""INSERT INTO dashboard_prefs (user_id, widgets)
                               VALUES (%s, %s)
                               ON DUPLICATE KEY UPDATE widgets=%s, updated_at=NOW()""",
                            (current_user.id, json.dumps(widgets), json.dumps(widgets)))
            db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route("/api/dashboard/get-prefs")
@login_required
def get_dashboard_prefs():
    import json
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT widgets FROM dashboard_prefs WHERE user_id=%s", (current_user.id,))
                row = cur.fetchone()
        widgets = json.loads(row["widgets"]) if row else ["subnet_stats", "totals", "recent_leases", "server_status"]
        return jsonify({"widgets": widgets})
    except Exception:
        return jsonify({"widgets": ["subnet_stats", "totals", "recent_leases", "server_status"]})

# ─────────────────────────────────────────
# Global Search

@bp.route("/api/stats")
@login_required
def api_stats():
    try:
        with __db.kea_db() as db:
            stats = {}
            accessible = current_user.filter_subnet_map(extensions.SUBNET_MAP)
            with db.cursor() as cur:
                for subnet_id, info in accessible.items():
                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    active = cur.fetchone()["cnt"]
                    cur.execute("""
                        SELECT COUNT(*) as cnt FROM lease4 l
                        LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                            AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                        WHERE l.state=0 AND l.subnet_id=%s AND h.host_id IS NULL
                    """, (subnet_id,))
                    dynamic = cur.fetchone()["cnt"]
                    cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                    reservations = cur.fetchone()["cnt"]
                    stats[str(subnet_id)] = {
                        "active": active,
                        "dynamic": dynamic,
                        "reservations": reservations,
                        "name": info["name"],
                        "cidr": info["cidr"],
                    }
        # Get pool sizes from Kea config
        pool_sizes = {}
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[str(s["id"])] = __ip_to_int(end) - __ip_to_int(start) + 1
        # Get Kea version
        kea_version = ""
        ver_result = __kea.kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
        server_statuses = [{
            "id":       s["id"],
            "name":     s["name"],
            "up":       __kea.kea_is_up(server=s),
            "role":     s.get("role", "primary"),
            "ha_state": None,
            "version":  "",
        } for s in extensions.KEA_SERVERS]
        # Add HA state and version for online servers
        for srv in server_statuses:
            if srv["up"]:
                if len(extensions.KEA_SERVERS) > 1:
                    ha = __kea.kea_command("ha-heartbeat",
                                          server=next(s for s in extensions.KEA_SERVERS if s["id"] == srv["id"]))
                    if ha.get("result") == 0:
                        srv["ha_state"] = ha.get("arguments", {}).get("state", "")
                ver = __kea.kea_command("version-get",
                                        server=next(s for s in extensions.KEA_SERVERS if s["id"] == srv["id"]))
                if ver.get("result") == 0:
                    v = ver.get("arguments", {}).get("extended", ver.get("text", ""))
                    srv["version"] = v.splitlines()[0] if v else ""
        return jsonify({
            "subnets": stats,
            "pool_sizes": pool_sizes,
            "kea_up": any(s["up"] for s in server_statuses),
            "kea_version": kea_version,
            "servers": server_statuses,
        })
    except Exception as e:
        return jsonify({"subnets": {}, "pool_sizes": {}, "kea_up": False,
                        "servers": [], "error": str(e)})


@bp.route("/api/lease-history")
@login_required
def api_lease_history():
    """
    Return 7-day utilization history for all subnets.
    Used by sparkline charts on subnet stat cards.
    Returns hourly buckets (or closest snapshot) for each subnet.
    """
    days = min(int(request.args.get("days", 7)), 90)
    subnet_id = request.args.get("subnet")
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                if subnet_id:
                    cur.execute("""
                        SELECT subnet_id,
                               DATE_FORMAT(snapshot_time, '%%Y-%%m-%%d %%H:00:00') AS hour,
                               AVG(dynamic_leases) AS dynamic,
                               AVG(active_leases)  AS active,
                               MAX(pool_size)      AS pool_size
                        FROM lease_history
                        WHERE subnet_id=%s
                          AND snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                        GROUP BY subnet_id, hour
                        ORDER BY hour ASC
                    """, (subnet_id, days))
                else:
                    cur.execute("""
                        SELECT subnet_id,
                               DATE_FORMAT(snapshot_time, '%%Y-%%m-%%d %%H:00:00') AS hour,
                               AVG(dynamic_leases) AS dynamic,
                               AVG(active_leases)  AS active,
                               MAX(pool_size)      AS pool_size
                        FROM lease_history
                        WHERE snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                        GROUP BY subnet_id, hour
                        ORDER BY subnet_id, hour ASC
                    """, (days,))
                rows = cur.fetchall()

        # Group by subnet_id
        history = {}
        for row in rows:
            sid = str(row["subnet_id"])
            if sid not in history:
                history[sid] = []
            pool = row["pool_size"] or 0
            dynamic = float(row["dynamic"] or 0)
            history[sid].append({
                "t":    row["hour"],
                "d":    round(dynamic, 1),
                "a":    round(float(row["active"] or 0), 1),
                "pct":  round(dynamic / pool * 100, 1) if pool > 0 else 0,
                "pool": pool,
            })
        return jsonify({"history": history, "days": days})
    except Exception as e:
        return jsonify({"history": {}, "error": str(e)})


@bp.route("/api/top-devices")
@login_required
def api_top_devices():
    """
    Top 10 devices by lease activity in the last 30 days.
    Activity = number of distinct lease records seen in lease_history window.
    Falls back to most-recently-seen devices from the devices table.
    """
    try:
        accessible = current_user.filter_subnet_map(extensions.SUBNET_MAP)
        accessible_ids = list(accessible.keys())

        devices = []
        with __db.jen_db() as db, __db.kea_db() as kdb:
            with db.cursor() as cur:
                if not accessible_ids:
                    return jsonify({"devices": []})
                placeholders = ",".join(["%s"] * len(accessible_ids))
                # Top devices by how recently active and how many times seen
                cur.execute(f"""
                    SELECT d.mac, d.device_name, d.last_hostname,
                           d.last_ip, d.last_subnet_id, d.last_seen,
                           COALESCE(d.manufacturer_override, d.manufacturer) AS manufacturer,
                           COALESCE(d.device_type_override, d.device_type) AS device_type,
                           COALESCE(d.device_icon_override, d.device_icon) AS device_icon,
                           DATEDIFF(NOW(), d.last_seen) AS days_inactive
                    FROM devices d
                    WHERE d.last_subnet_id IN ({placeholders})
                      AND d.last_seen >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                    ORDER BY d.last_seen DESC
                    LIMIT 10
                """, accessible_ids)
                rows = cur.fetchall()

            with kdb.cursor() as kcur:
                for row in rows:
                    mac_hex = row["mac"].replace(":", "")
                    kcur.execute(
                        "SELECT host_id FROM hosts WHERE HEX(dhcp_identifier)=%s",
                        (mac_hex,)
                    )
                    has_reservation = bool(kcur.fetchone())
                    subnet_name = accessible.get(row["last_subnet_id"], {}).get("name", "")
                    devices.append({
                        "mac":             row["mac"],
                        "name":            row["device_name"] or row["last_hostname"] or row["mac"],
                        "hostname":        row["last_hostname"] or "",
                        "ip":              row["last_ip"] or "",
                        "subnet":          subnet_name,
                        "manufacturer":    row["manufacturer"] or "",
                        "device_type":     row["device_type"] or "",
                        "device_icon":     row["device_icon"] or "",
                        "last_seen":       row["last_seen"].isoformat() if row["last_seen"] else "",
                        "days_inactive":   row["days_inactive"] or 0,
                        "has_reservation": has_reservation,
                    })
        return jsonify({"devices": devices})
    except Exception as e:
        return jsonify({"devices": [], "error": str(e)})


@bp.route("/api/alert-summary")
@login_required
def api_alert_summary():
    """Recent alerts for the dashboard alert summary widget."""
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT alert_type, channel_type, message, status, error, sent_at
                    FROM alert_log
                    ORDER BY sent_at DESC
                    LIMIT 10
                """)
                rows = cur.fetchall()
        alerts = []
        for row in rows:
            alerts.append({
                "type":    row["alert_type"],
                "channel": row["channel_type"],
                "message": row["message"],
                "status":  row["status"],
                "error":   row["error"] or "",
                "sent_at": row["sent_at"].strftime("%Y-%m-%d %H:%M UTC") if row["sent_at"] else "",
            })
        return jsonify({"alerts": alerts})
    except Exception as e:
        return jsonify({"alerts": [], "error": str(e)})

@bp.route("/api/recent-leases")
@login_required
def api_recent_leases():
    """Recent leases for dashboard widget — returns HTML fragment."""
    from jen.services.fingerprint import get_device_info_map, get_manufacturer_icon_url, DEVICE_TYPE_DISPLAY
    try:
        hours = float(request.args.get("hours", "0.5"))
    except ValueError:
        hours = 0.5
    if hours not in (0.5, 1, 4, 8, 12, 24):
        hours = 0.5

    recent = []
    device_info = {}
    try:
        with __db.kea_db() as db:
            window_seconds = int(hours * 3600)
            with db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(l.address) AS ip, l.hostname,
                           HEX(l.hwaddr) AS mac_hex, l.subnet_id,
                           (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained
                    FROM lease4 l
                    WHERE l.state=0
                      AND l.expire > NOW()
                      AND (l.expire - INTERVAL l.valid_lifetime SECOND) > (NOW() - INTERVAL %s SECOND)
                    ORDER BY (l.expire - INTERVAL l.valid_lifetime SECOND) DESC
                    LIMIT 50
                """, (window_seconds,))
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    sname = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", str(row["subnet_id"]))
                    recent.append({"ip": row["ip"], "hostname": row["hostname"] or "",
                                    "mac": mac, "subnet_id": row["subnet_id"],
                                    "subnet_name": sname, "obtained": row["obtained"]})
        mac_list = [l["mac"] for l in recent if l.get("mac")]
        device_info = get_device_info_map(mac_list)
    except Exception as e:
        logger.error(f"Recent leases error: {e}")

    return render_template("_recent_leases.html",
                           recent=recent, device_info=device_info,
                           get_manufacturer_icon_url=get_manufacturer_icon_url,
                           device_type_display=DEVICE_TYPE_DISPLAY)


@bp.route("/metrics")
def prometheus_metrics():
    """
    Prometheus metrics endpoint. Unauthenticated by design for scraper compatibility.
    Protect with a Bearer token by setting metrics_token in jen.config [jen] section,
    or by restricting /metrics at the reverse proxy level.
    Only exposes aggregate counts — no individual MACs, IPs, or hostnames.
    """
    # Optional token protection — set metrics_token in jen.config [jen] to enable
    expected_token = extensions.cfg.get("server", "metrics_token", fallback="").strip() if extensions.cfg else ""
    if expected_token:
        auth = request.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else request.args.get("token", "")
        if token != expected_token:
            return Response("Unauthorized\n", status=401, mimetype="text/plain")
    lines = []
    lines.append("# HELP jen_subnet_active_leases Number of active leases per subnet")
    lines.append("# TYPE jen_subnet_active_leases gauge")
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                for subnet_id, info in extensions.SUBNET_MAP.items():
                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    cnt = cur.fetchone()["cnt"]
                    lines.append(f'jen_subnet_active_leases{{subnet="{info["name"]}",cidr="{info["cidr"]}"}} {cnt}')
    except Exception:
        pass
    lines.append("# HELP jen_kea_up Whether Kea DHCP is reachable")
    lines.append("# TYPE jen_kea_up gauge")
    lines.append(f"jen_kea_up {1 if __kea.kea_is_up() else 0}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

# ─────────────────────────────────────────
