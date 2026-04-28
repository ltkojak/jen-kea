"""
jen/routes/devices.py
──────────────────────
Device inventory routes.
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
bp = Blueprint("devices", __name__)


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


@bp.route("/devices")
@login_required
def devices():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    show_stale = request.args.get("stale", "0") == "1"
    type_filter = request.args.get("type", "").strip()
    subnet_filter = request.args.get("subnet", "all")
    sort = request.args.get("sort", "last_seen")
    direction = request.args.get("dir", "desc")
    if direction not in ("asc", "desc"):
        direction = "desc"
    sort_map = {
        "mac": "d.mac",
        "device_name": "d.device_name",
        "owner": "d.owner",
        "last_ip": "d.last_ip",
        "hostname": "d.last_hostname",
        "subnet": "d.last_subnet_id",
        "first_seen": "d.first_seen",
        "last_seen": "d.last_seen",
        "status": "d.last_seen",
    }
    sort_col = sort_map.get(sort, "d.last_seen")
    per_page = 50
    stale_days = int(__user.get_global_setting("stale_device_days", "30"))

    devices_list = []
    total = 0
    try:
        db = __db.get_jen_db()
        kdb = __db.get_kea_db()
        with db.cursor() as cur:
            where = []
            params = []
            if search:
                where.append("(d.mac LIKE %s OR d.device_name LIKE %s OR d.owner LIKE %s OR d.last_ip LIKE %s OR d.last_hostname LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s, s, s]
            if show_stale:
                where.append(f"d.last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)")
            if type_filter:
                where.append("d.device_type=%s")
                params.append(type_filter)
            if subnet_filter != "all":
                try:
                    where.append("d.last_subnet_id=%s")
                    params.append(int(subnet_filter))
                except ValueError:
                    subnet_filter = "all"
            where_str = " AND ".join(where) if where else "1=1"

            cur.execute(f"SELECT COUNT(*) as cnt FROM devices d WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT d.id, d.mac, d.device_name, d.owner, d.notes,
                       d.first_seen, d.last_seen, d.last_ip, d.last_hostname, d.last_subnet_id,
                       COALESCE(d.manufacturer_override, d.manufacturer) AS manufacturer,
                       COALESCE(d.device_type_override, d.device_type) AS device_type,
                       COALESCE(d.device_icon_override, d.device_icon) AS device_icon,
                       d.manufacturer_override IS NOT NULL AS is_manual,
                       d.device_type_override AS type_override_key,
                       d.device_icon_override AS icon_override_key,
                       DATEDIFF(NOW(), d.last_seen) as days_since_seen
                FROM devices d
                WHERE {where_str}
                ORDER BY {sort_col} {direction}
                LIMIT {per_page} OFFSET {offset}
            """, params)
            rows = cur.fetchall()

            # Check which MACs have reservations
            with kdb.cursor() as kcur:
                for row in rows:
                    mac_hex = row["mac"].replace(":", "")
                    kcur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip FROM hosts WHERE HEX(dhcp_identifier)=%s", (mac_hex,))
                    res = kcur.fetchone()
                    row["has_reservation"] = bool(res)
                    row["reservation_ip"] = res["ip"] if res else None
                    row["subnet_name"] = extensions.SUBNET_MAP.get(row["last_subnet_id"], {}).get("name", "") if row["last_subnet_id"] else ""
                    row["is_stale"] = row["days_since_seen"] >= stale_days
                    devices_list.append(row)
        db.close()
        kdb.close()
    except Exception as e:
        logger.error(f"Devices error: {e}")
        flash(f"Could not load device inventory: {str(e)}", "error")

    pages = max(1, (total + per_page - 1) // per_page)
    bundled_icons = sorted([f.replace(".svg","") for f in os.listdir(extensions.ICONS_BUNDLED_DIR) if f.endswith(".svg")]) if os.path.exists(extensions.ICONS_BUNDLED_DIR) else []
    custom_icons = sorted([f.replace(".svg","") for f in os.listdir(extensions.ICONS_CUSTOM_DIR) if f.endswith(".svg")]) if os.path.exists(extensions.ICONS_CUSTOM_DIR) else []
    return render_template("devices.html", devices=devices_list, page=page, pages=pages,
                           total=total, search=search, show_stale=show_stale,
                           stale_days=stale_days, subnet_map=extensions.SUBNET_MAP,
                           sort=sort, direction=direction,
                           type_filter=type_filter, subnet_filter=subnet_filter,
                           device_type_display=__fp.DEVICE_TYPE_DISPLAY,
                           get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
                           bundled_icons=bundled_icons, custom_icons=custom_icons)

@bp.route("/devices/edit/<int:device_id>", methods=["POST"])
@login_required
@_admin_required
def edit_device(device_id):
    device_name = request.form.get("device_name", "").strip()[:200]
    owner = request.form.get("owner", "").strip()[:200]
    notes = request.form.get("notes", "").strip()[:1000]
    type_override = request.form.get("type_override", "").strip()
    icon_override = request.form.get("icon_override", "").strip()  # icon name without .svg
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            if type_override == "auto" or type_override == "":
                # Clear manual override (but keep icon override if set)
                if icon_override:
                    cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                                   manufacturer_override=NULL, device_type_override=NULL,
                                   device_icon_override=%s
                                   WHERE id=%s""",
                                (device_name or None, owner or None, notes or None,
                                 icon_override, device_id))
                else:
                    cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                                   manufacturer_override=NULL, device_type_override=NULL, device_icon_override=NULL
                                   WHERE id=%s""",
                                (device_name or None, owner or None, notes or None, device_id))
                override_info = None
            elif type_override in __fp.DEVICE_TYPE_DISPLAY:
                type_label, _ = __fp.DEVICE_TYPE_DISPLAY[type_override]
                type_icon_map = {
                    "apple": ("Apple", "🍎"), "android": ("Android", "📱"),
                    "windows": ("Windows", "🖥️"), "linux": ("Linux", "🐧"),
                    "amazon": ("Amazon", "📦"), "iot": ("IoT Device", "🔌"),
                    "tv": ("Smart TV", "📺"), "printer": ("Printer", "🖨️"),
                    "nas": ("NAS", "🗄️"), "network": ("Network Device", "🌐"),
                    "gaming": ("Gaming", "🎮"), "raspberry_pi": ("Raspberry Pi", "🥧"),
                    "google": ("Google", "🔍"), "pc": ("PC", "🖥️"),
                    "unknown": ("Unknown", "❓"),
                }
                mfr_override, icon_default = type_icon_map.get(type_override, (type_label, "❓"))
                # Use explicit icon override if set, otherwise default for type
                final_icon = icon_override if icon_override else icon_default
                cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                               manufacturer_override=%s, device_type_override=%s, device_icon_override=%s
                               WHERE id=%s""",
                            (device_name or None, owner or None, notes or None,
                             mfr_override, type_override, final_icon, device_id))
                override_info = {"manufacturer": mfr_override, "device_type": type_override, "device_icon": final_icon}
            else:
                cur.execute("UPDATE devices SET device_name=%s, owner=%s, notes=%s WHERE id=%s",
                            (device_name or None, owner or None, notes or None, device_id))
                override_info = None
        db.commit()
        db.close()
        return jsonify({"ok": True, "override": override_info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@bp.route("/devices/delete/<int:device_id>", methods=["POST"])
@login_required
@_admin_required
def delete_device(device_id):
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE id=%s", (device_id,))
        db.commit()
        db.close()
        flash("Device removed from inventory.", "success")
        __user.audit("DELETE_DEVICE", str(device_id), "Removed from device inventory")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('devices.devices'))

@bp.route("/devices/settings", methods=["POST"])
@login_required
@_admin_required
def save_device_settings():
    stale_days = request.form.get("stale_days", "30").strip()
    if not stale_days.isdigit() or not (1 <= int(stale_days) <= 365):
        flash("Stale threshold must be between 1 and 365 days.", "error")
        return redirect(url_for('devices.devices'))
    __user.set_global_setting("stale_device_days", stale_days)
    flash(f"Stale device threshold set to {stale_days} days.", "success")
    return redirect(url_for('devices.devices'))

# ─────────────────────────────────────────
# Reservations — bulk actions + stale detection
# ─────────────────────────────────────────
