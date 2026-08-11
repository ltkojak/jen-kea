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
bp = Blueprint("devices", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/devices")
@login_required
def devices():
    # Pagination — default is "all". User can opt-in via per_page param.
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
    stale_days = int(__user.get_global_setting("stale_device_days", "30"))

    devices_list = []
    total = 0
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    try:
        with __db.jen_db() as db:
            with __db.kea_db() as kdb:
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
                            sid = int(subnet_filter)
                            if current_user.can_access_subnet(sid):
                                where.append("d.last_subnet_id=%s")
                                params.append(sid)
                            else:
                                subnet_filter = "all"
                        except ValueError:
                            subnet_filter = "all"
                    if subnet_filter == "all" and not current_user.all_subnets:
                        from jen.services.access import add_subnet_restriction
                        where, params = add_subnet_restriction(where, params, "d", "last_subnet_id")
                    where_str = " AND ".join(where) if where else "1=1"

                    cur.execute(f"SELECT COUNT(*) as cnt FROM devices d WHERE {where_str}", params)
                    total = cur.fetchone()["cnt"]
                    if per_page:
                        offset = (page - 1) * per_page
                        limit_clause = f"LIMIT {per_page} OFFSET {offset}"
                    else:
                        limit_clause = ""
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
                        {limit_clause}
                    """, params)
                    rows = cur.fetchall()

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
    except Exception as e:
        logger.error(f"Devices error: {e}")
        flash(f"Could not load device inventory: {str(e)}", "error")

    pages = max(1, (total + per_page - 1) // per_page) if per_page else 1
    bundled_icons = sorted([f.replace(".svg","") for f in os.listdir(extensions.ICONS_BUNDLED_DIR) if f.endswith(".svg")]) if os.path.exists(extensions.ICONS_BUNDLED_DIR) else []
    custom_icons = sorted([f.replace(".svg","") for f in os.listdir(extensions.ICONS_CUSTOM_DIR) if f.endswith(".svg")]) if os.path.exists(extensions.ICONS_CUSTOM_DIR) else []
    template_vars = dict(
        devices=devices_list, page=page, pages=pages,
        total=total, search=search, show_stale=show_stale,
        stale_days=stale_days, subnet_map=accessible_subnet_map,
        sort=sort, direction=direction, per_page=per_page_param,
        type_filter=type_filter, subnet_filter=subnet_filter,
        device_type_display=__fp.DEVICE_TYPE_DISPLAY,
        get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
        bundled_icons=bundled_icons, custom_icons=custom_icons
    )
    if request.headers.get("HX-Request") == "true":
        # v4.4.6 fix: same class of bug fixed in leases.py/reservations.py
        # — headers and pagination live outside the old #devices-table-body
        # swap target and were going stale on every htmx-driven filter
        # change. Render the whole results partial instead.
        return render_template("_devices_results.html", **template_vars), 200
    return render_template("devices.html", **template_vars)

@bp.route("/devices/edit/<int:device_id>", methods=["POST"])
@login_required
@_admin_required
def edit_device(device_id):
    device_name = request.form.get("device_name", "").strip()[:200]
    owner = request.form.get("owner", "").strip()[:200]
    notes = request.form.get("notes", "").strip()[:1000]
    type_override = request.form.get("type_override", "").strip()
    icon_override = request.form.get("icon_override", "").strip()  # icon name without .svg
    # v4.4.9: this value is used to build a filesystem path check in
    # fingerprint.get_device_info_map() — same class of gap already
    # closed for the sibling icon upload/delete routes elsewhere in
    # settings.py. Not independently exploitable (requires admin access,
    # and the actual file-serving is Flask's own static route, which
    # already rejects traversal), but should match the same validation
    # discipline as every other icon-name input in the app.
    if icon_override and not icon_override.replace("-", "").replace("_", "").isalnum():
        return jsonify({"ok": False, "error": "Invalid icon name."}), 400
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT last_subnet_id FROM devices WHERE id=%s", (device_id,))
                existing = cur.fetchone()
                if existing and existing.get("last_subnet_id") is not None \
                        and not current_user.can_access_subnet(existing["last_subnet_id"]):
                    return jsonify({"ok": False, "error": "You do not have access to that subnet."}), 403
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
        return jsonify({"ok": True, "override": override_info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@bp.route("/devices/delete/<int:device_id>", methods=["POST"])
@login_required
@_admin_required
def delete_device(device_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT last_subnet_id FROM devices WHERE id=%s", (device_id,))
                existing = cur.fetchone()
                if existing and existing.get("last_subnet_id") is not None \
                        and not current_user.can_access_subnet(existing["last_subnet_id"]):
                    flash("You do not have access to that subnet.", "error")
                    return redirect(url_for('devices.devices'))
                cur.execute("DELETE FROM devices WHERE id=%s", (device_id,))
            db.commit()
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
