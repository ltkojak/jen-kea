"""
jen/routes/leases.py
─────────────────────
Lease management routes.
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
bp = Blueprint("leases", __name__)


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


@bp.route("/leases")
@login_required
def leases():
    subnet_filter = request.args.get("subnet", "all")
    minutes = request.args.get("minutes", "")
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    show_expired = request.args.get("expired", "0") == "1"
    sort = request.args.get("sort", "expires")
    direction = request.args.get("dir", "desc")
    if direction not in ("asc", "desc"):
        direction = "desc"
    sort_map = {
        "ip": "l.address",
        "hostname": "l.hostname",
        "mac": "l.hwaddr",
        "subnet": "l.subnet_id",
        "obtained": "(l.expire - INTERVAL l.valid_lifetime SECOND)",
        "expires": "l.expire",
    }
    sort_col = sort_map.get(sort, "l.expire")
    # Pagination — default is "all" (no limit). User can opt-in to per-page.
    per_page_param = request.args.get("per_page", "all")
    try:
        per_page = int(per_page_param) if per_page_param != "all" else None
    except ValueError:
        per_page = None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    if per_page is None:
        page = 1   # no pagination = always page 1
    if subnet_filter != "all":
        try:
            if int(subnet_filter) not in extensions.SUBNET_MAP:
                subnet_filter = "all"
        except ValueError:
            subnet_filter = "all"
    leases_list = []
    total = 0
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            where = []
            params = []
            if not show_expired:
                where.append("l.state=0")
            if subnet_filter != "all":
                where.append("l.subnet_id=%s")
                params.append(int(subnet_filter))
            if minutes:
                try:
                    mins = int(minutes)
                    where.append("FROM_UNIXTIME(l.expire) >= DATE_SUB(NOW(), INTERVAL %s MINUTE)")
                    params.append(mins)
                except ValueError:
                    pass
            if search:
                where.append("(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s.replace(":", "")]
            where_str = " AND ".join(where) if where else "1=1"
            cur.execute(f"SELECT COUNT(*) as cnt FROM lease4 l WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            if per_page:
                offset = (page - 1) * per_page
                limit_clause = f"LIMIT {per_page} OFFSET {offset}"
            else:
                limit_clause = ""
            cur.execute(f"""
                SELECT inet_ntoa(l.address) AS ip, l.hostname,
                       HEX(l.hwaddr) AS mac_hex, l.subnet_id, l.state,
                       l.expire,
                       (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained,
                       l.expire AS expires
                FROM lease4 l WHERE {where_str}
                ORDER BY {sort_col} {direction}
                {limit_clause}
            """, params)
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                leases_list.append({**row, "mac": mac,
                                    "subnet_id": row["subnet_id"],
                                    "subnet_name": extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", ""),
                                    "expired": row.get("state", 0) != 0})
        # Build set of MACs that have reservations — single query, O(1) lookup per lease
        reserved_macs = set()
        if leases_list:
            mac_hexes = [l["mac"].replace(":", "") for l in leases_list if l.get("mac")]
            if mac_hexes:
                placeholders = ",".join(["%s"] * len(mac_hexes))
                cur.execute(
                    f"SELECT HEX(dhcp_identifier) AS mac_hex FROM hosts WHERE HEX(dhcp_identifier) IN ({placeholders})",
                    mac_hexes
                )
                reserved_macs = {row["mac_hex"].upper() for row in cur.fetchall()}
        for l in leases_list:
            l["has_reservation"] = l["mac"].replace(":", "").upper() in reserved_macs
        db.close()
    except Exception as e:
        flash(f"Could not load leases: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page) if per_page else 1
    mac_list = [l["mac"] for l in leases_list if l.get("mac")]
    device_info = __fp.get_device_info_map(mac_list)
    template_vars = dict(
        leases=leases_list, page=page, pages=pages, total=total,
        subnet_filter=subnet_filter, minutes=minutes, search=search,
        show_expired=show_expired, subnet_map=extensions.SUBNET_MAP,
        sort=sort, direction=direction, device_info=device_info,
        per_page=per_page_param,
        get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
        device_type_display=__fp.DEVICE_TYPE_DISPLAY
    )
    if request.headers.get("HX-Request") == "true":
        return render_template("_lease_rows.html", **template_vars), 200
    return render_template("leases.html", **template_vars)

@bp.route("/leases/delete-stale", methods=["POST"])
@login_required
@_admin_required
def delete_stale_leases():
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE state != 0")
            deleted = cur.rowcount
        db.commit()
        db.close()
        flash(f"Deleted {deleted} expired/stale lease(s).", "success")
        __user.audit("DELETE_STALE_LEASES", "leases", f"Deleted {deleted}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('leases.leases'))

@bp.route("/leases/release", methods=["POST"])
@login_required
@_admin_required
def release_lease():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("No IP address specified.", "error")
        return redirect(url_for('leases.leases'))
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("UPDATE lease4 SET state=1 WHERE inet_ntoa(address)=%s", (ip,))
            affected = cur.rowcount
        db.commit()
        db.close()
        if affected:
            flash(f"Lease for {ip} released.", "success")
            __user.audit("RELEASE_LEASE", "leases", f"Released {ip} by {current_user.username}")
        else:
            flash(f"No active lease found for {ip}.", "warning")
    except Exception as e:
        flash(f"Error releasing lease: {str(e)}", "error")
    return redirect(url_for('leases.leases'))

@bp.route("/ipmap")
@login_required
def ipmap():
    subnet_filter = request.args.get("subnet", list(extensions.SUBNET_MAP.keys())[0] if extensions.SUBNET_MAP else 1)
    try:
        subnet_filter = int(subnet_filter)
        if subnet_filter not in extensions.SUBNET_MAP:
            subnet_filter = list(extensions.SUBNET_MAP.keys())[0]
    except (ValueError, IndexError):
        subnet_filter = list(extensions.SUBNET_MAP.keys())[0] if extensions.SUBNET_MAP else 1
    leases_by_ip = {}
    reservations_by_ip = {}
    cidr = extensions.SUBNET_MAP.get(subnet_filter, {}).get("cidr", "")
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(address) AS ip, hostname, HEX(hwaddr) AS mac_hex FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_filter,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                leases_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "dynamic"}
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_filter,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                reservations_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "reserved"}
        db.close()
    except Exception as e:
        flash(f"Could not load IP map: {str(e)}", "error")
    return render_template("ipmap.html", leases=leases_by_ip, reservations=reservations_by_ip,
                           subnet_filter=subnet_filter, subnet_map=extensions.SUBNET_MAP, cidr=cidr)

# ─────────────────────────────────────────
# Reservations
# ─────────────────────────────────────────
