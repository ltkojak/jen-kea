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
from jen.services.fingerprint import DEVICE_TYPE_DISPLAY
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("dashboard", __name__)


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


@bp.route("/")
@login_required
def dashboard():
    try:
        hours = float(request.args.get("hours", "0.5"))
    except ValueError:
        hours = 0.5
    if hours not in (0.5, 1, 4, 8, 12, 24):
        hours = 0.5
    # hours_str must exactly match the option values in the template (no trailing .0)
    hours_str = str(int(hours)) if hours == int(hours) else str(hours)

    stats = {}
    recent = []
    # First fetch Kea config so we know pool sizes AND lease lifetimes
    pool_sizes = {}
    default_lifetime = 86400
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            default_lifetime = extensions.cfg.get("valid-lifetime", 86400)
            for s in extensions.cfg.get("subnet4", []):
                sid = str(s["id"])
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[sid] = __ip_to_int(end) - __ip_to_int(start) + 1
    except Exception:
        pass

    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM lease4 l
                    WHERE l.state=0 AND l.subnet_id=%s
                    AND NOT EXISTS (
                        SELECT 1 FROM hosts h
                        WHERE h.dhcp4_subnet_id=%s AND h.dhcp_identifier=l.hwaddr
                    )
                """, (subnet_id, subnet_id))
                dynamic = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                stats[subnet_id] = {"active": active, "dynamic": dynamic,
                                    "reservations": reserved,
                                    "name": info["name"], "cidr": info["cidr"]}

            # issued_at = expire - valid_lifetime (valid_lifetime is stored per-lease in Kea)
            # expire is a TIMESTAMP column, so use INTERVAL arithmetic not UNIX_TIMESTAMP()
            window_seconds = int(hours * 3600)
            logger.info(f"Dashboard: hours={hours}, window={window_seconds}s")
            cur.execute("""
                SELECT inet_ntoa(l.address) AS ip, l.hostname,
                       HEX(l.hwaddr) AS mac_hex, l.subnet_id,
                       (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained
                FROM lease4 l
                WHERE l.state=0
                  AND l.expire > NOW()
                  AND (l.expire - INTERVAL l.valid_lifetime SECOND) > (NOW() - INTERVAL %s SECOND)
                ORDER BY (l.expire - INTERVAL l.valid_lifetime SECOND) DESC
                LIMIT 200
            """, (window_seconds,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                sname = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", str(row["subnet_id"]))
                recent.append({"ip": row["ip"], "hostname": row["hostname"] or "",
                                "mac": mac, "subnet_id": row["subnet_id"],
                                "subnet_name": sname,
                                "obtained": row["obtained"]})
        db.close()
    except Exception as e:
        logger.error(f"Dashboard DB error: {e}")
        flash(f"Could not load dashboard data: {str(e)}", "error")
    kea_up = __kea.kea_is_up()
    server_statuses = []
    try:
        server_statuses = __kea.get_all_server_status()
        for s in server_statuses:
            if s["up"]:
                ver = __kea.kea_command("version-get", server=s["server"])
                s["version"] = ver.get("arguments", {}).get("extended", ver.get("text", ""))
                s["version"] = s["version"].splitlines()[0] if s["version"] else ""
            else:
                s["version"] = ""
    except Exception:
        pass
    mac_list = [l["mac"] for l in recent if l.get("mac")]
    device_info = __fp.get_device_info_map(mac_list)
    return render_template("dashboard.html", stats=stats, recent=recent,
                           kea_up=kea_up, subnet_map=extensions.SUBNET_MAP,
                           pool_sizes=pool_sizes, hours=hours_str,
                           server_statuses=server_statuses,
                           device_info=device_info,
                           get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
                           device_type_display=__fp.DEVICE_TYPE_DISPLAY)

# ─────────────────────────────────────────
# Leases
# ─────────────────────────────────────────

@bp.route("/api/saved-searches")
@login_required
def api_saved_searches():
    page = request.args.get("page", "")
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            if page:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s AND page=%s ORDER BY name", (current_user.id, page))
            else:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY name", (current_user.id,))
            searches = cur.fetchall()
        db.close()
        return jsonify([dict(s) for s in searches])
    except Exception as e:
        return jsonify([])

# ─────────────────────────────────────────
# Dashboard Preferences
# ─────────────────────────────────────────
@bp.route("/api/dashboard/save-prefs", methods=["POST"])
@login_required
def save_dashboard_prefs():
    import json
    widgets = request.json.get("widgets", ["subnet_stats", "recent_leases"])
    valid = {"subnet_stats", "recent_leases", "top_devices", "alert_summary", "server_status"}
    widgets = [w for w in widgets if w in valid]
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("""INSERT INTO dashboard_prefs (user_id, widgets)
                           VALUES (%s, %s)
                           ON DUPLICATE KEY UPDATE widgets=%s, updated_at=NOW()""",
                        (current_user.id, json.dumps(widgets), json.dumps(widgets)))
        db.commit()
        db.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route("/api/dashboard/get-prefs")
@login_required
def get_dashboard_prefs():
    import json
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT widgets FROM dashboard_prefs WHERE user_id=%s", (current_user.id,))
            row = cur.fetchone()
        db.close()
        widgets = json.loads(row["widgets"]) if row else ["subnet_stats", "recent_leases"]
        return jsonify({"widgets": widgets})
    except Exception:
        return jsonify({"widgets": ["subnet_stats", "recent_leases"]})

# ─────────────────────────────────────────
# Global Search

@bp.route("/api/stats")
@login_required
def api_stats():
    try:
        db = __db.get_kea_db()
        stats = {}
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
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
        db.close()
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
        kea_up = False
        kea_version = ""
        ver_result = __kea.kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
        server_statuses = [{
            "id": s["id"], "name": s["name"], "up": __kea.kea_is_up(server=s), "role": s["role"]
        } for s in extensions.KEA_SERVERS]
        return jsonify({
            "subnets": stats,
            "pool_sizes": pool_sizes,
            "kea_up": any(s["up"] for s in server_statuses),
            "kea_version": kea_version,
            "servers": server_statuses,
        })
    except Exception as e:
        return jsonify({"subnets": {}, "pool_sizes": {}, "kea_up": False, "error": str(e)})

@bp.route("/metrics")
def prometheus_metrics():
    lines = []
    lines.append("# HELP jen_subnet_active_leases Number of active leases per subnet")
    lines.append("# TYPE jen_subnet_active_leases gauge")
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                cnt = cur.fetchone()["cnt"]
                lines.append(f'jen_subnet_active_leases{{subnet="{info["name"]}",cidr="{info["cidr"]}"}} {cnt}')
        db.close()
    except Exception:
        pass
    lines.append("# HELP jen_kea_up Whether Kea DHCP is reachable")
    lines.append("# TYPE jen_kea_up gauge")
    lines.append(f"jen_kea_up {1 if __kea.kea_is_up() else 0}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

# ─────────────────────────────────────────
