"""
jen/routes/search.py
─────────────────────
Global search and saved searches routes.
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
import jen.services.kea6 as __kea6
import jen.services.alerts as __alerts
import jen.services.fingerprint as __fp
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("search", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/search")
@login_required
def global_search():
    q = __auth.sanitize_search(request.args.get("q", "").strip())
    results = {"leases": [], "reservations": [], "devices": [],
              "leases6": [], "reservations6": []}
    if len(q) >= 2:
        try:
            with __db.kea_db() as kdb:
                with __db.jen_db() as jdb:
                    s = f"%{q}%"
                    s_mac = s.replace(":", "")

                    # Subnet-restricted users only ever see results from
                    # subnets they're assigned — same rule list/detail views
                    # already enforce. Applied identically to all three
                    # result sets below (v4.4.4 — this route previously
                    # leaked leases/reservations/devices across subnets to
                    # restricted admins/viewers).
                    from jen.services.access import add_subnet_restriction

                    # Search leases
                    where, params = ["(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)"], [s, s, s_mac]
                    where, params = add_subnet_restriction(where, params, "l", "subnet_id")
                    with kdb.cursor() as cur:
                        cur.execute(f"""
                            SELECT inet_ntoa(l.address) AS ip,
                                   l.hostname,
                                   HEX(l.hwaddr) AS mac_hex,
                                   l.subnet_id,
                                   l.expire, l.state
                            FROM lease4 l
                            WHERE {' AND '.join(where)}
                            LIMIT 20
                        """, params)
                        for row in cur.fetchall():
                            mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                            results["leases"].append({
                                "ip": row["ip"], "hostname": row["hostname"] or "",
                                "mac": mac, "subnet_id": row["subnet_id"]
                            })

                    # Search reservations
                    where, params = [
                        "h.dhcp4_subnet_id > 0",
                        "(inet_ntoa(h.ipv4_address) LIKE %s OR h.hostname LIKE %s OR HEX(h.dhcp_identifier) LIKE %s)",
                    ], [s, s, s_mac]
                    where, params = add_subnet_restriction(where, params, "h", "dhcp4_subnet_id")
                    with kdb.cursor() as cur:
                        cur.execute(f"""
                            SELECT inet_ntoa(h.ipv4_address) AS ip,
                                   h.hostname,
                                   HEX(h.dhcp_identifier) AS mac_hex,
                                   h.dhcp4_subnet_id AS subnet_id
                            FROM hosts h
                            WHERE {' AND '.join(where)}
                            LIMIT 20
                        """, params)
                        for row in cur.fetchall():
                            mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                            results["reservations"].append({
                                "ip": row["ip"], "hostname": row["hostname"] or "",
                                "mac": mac, "subnet_id": row["subnet_id"]
                            })

                    # Search devices — devices.last_subnet_id is nullable
                    # (a device we've never seen a lease/subnet for yet), so
                    # a restricted user can still find those since they
                    # can't be attributed to any subnet they lack access to.
                    where, params = ["(mac LIKE %s OR last_ip LIKE %s OR device_name LIKE %s OR owner LIKE %s)"], [s, s, s, s]
                    if not current_user.all_subnets:
                        ids = current_user.accessible_subnet_ids(extensions.SUBNET_MAP)
                        if ids:
                            placeholders = ",".join(["%s"] * len(ids))
                            where.append(f"(last_subnet_id IS NULL OR last_subnet_id IN ({placeholders}))")
                            params.extend(ids)
                        else:
                            where.append("last_subnet_id IS NULL")
                    with jdb.cursor() as cur:
                        cur.execute(f"""
                            SELECT mac, last_ip, device_name AS name, owner, notes, last_subnet_id
                            FROM devices
                            WHERE {' AND '.join(where)}
                            LIMIT 20
                        """, params)
                        results["devices"] = cur.fetchall()

                    # v5.0 Phase 4 — IPv6 leases/reservations. Only searched
                    # when v6 is genuinely on (display gate, same as every
                    # other v6 code path) and there's something configured
                    # to search. Subnet restriction here follows the v6
                    # subnet's paired_subnet4_id where one exists (a paired
                    # v6 subnet IS the same network as its v4 counterpart,
                    # so a user with access to that v4 subnet should see
                    # its v6 side too); an UNPAIRED v6 subnet has no v4
                    # subnet to inherit access from, so it's restricted to
                    # all_subnets users only rather than guessing.
                    if __kea6.is_ipv6_enabled() and extensions.SUBNET6_MAP:
                        if current_user.all_subnets:
                            searchable_v6_ids = list(extensions.SUBNET6_MAP.keys())
                        else:
                            accessible_v4_ids = set(current_user.accessible_subnet_ids(extensions.SUBNET_MAP))
                            searchable_v6_ids = [
                                sid for sid, info in extensions.SUBNET6_MAP.items()
                                if info.get("paired_subnet4_id") in accessible_v4_ids
                            ]
                        for sid in searchable_v6_ids:
                            try:
                                for l in __kea6.list_lease6(subnet_id=sid, search=q)[:20]:
                                    results["leases6"].append({
                                        "address": l["address"], "hostname": l["hostname"],
                                        "duid_hex": l["duid_hex"], "subnet_id": l["subnet_id"],
                                        "lease_type_name": l["lease_type_name"],
                                    })
                            except Exception:
                                pass
                        for sid in searchable_v6_ids:
                            try:
                                for h in __kea6.get_ipv6_reservations(subnet_id=sid)[:20]:
                                    ql = q.lower()
                                    if (ql in (h["hostname"] or "").lower()
                                            or ql in (h["duid_hex"] or "").lower()
                                            or any(ql in (r["address"] or "").lower() for r in h["reservations"])):
                                        results["reservations6"].append({
                                            "hostname": h["hostname"], "duid_hex": h["duid_hex"],
                                            "subnet_id": h["subnet_id"],
                                            "addresses": [r["address"] for r in h["reservations"]],
                                        })
                            except Exception:
                                pass

        except Exception as e:
            flash(f"Search error: {str(e)}", "error")

    total = sum(len(v) for v in results.values())
    subnet_names = {sid: info["name"] for sid, info in current_user.filter_subnet_map(extensions.SUBNET_MAP).items()}
    subnet6_names = {sid: info["name"] for sid, info in extensions.SUBNET6_MAP.items()}
    return render_template("search_results.html",
                           q=q, results=results, total=total,
                           subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP),
                           subnet_names=subnet_names, subnet6_names=subnet6_names)

# ─────────────────────────────────────────
# MFA Routes
# ─────────────────────────────────────────

@bp.route("/saved-searches", methods=["GET"])
@login_required
def saved_searches():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY created_at DESC", (current_user.id,))
                searches = cur.fetchall()
    except Exception:
        searches = []
    return render_template("saved_searches.html", searches=searches)

@bp.route("/saved-searches/save", methods=["POST"])
@login_required
def save_search():
    name = request.form.get("name", "").strip()[:100]
    page = request.form.get("page", "").strip()[:50]
    params = request.form.get("params", "").strip()[:1000]
    if not name or not page:
        return jsonify({"error": "Name and page required"}), 400
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                # Max 20 saved searches per user
                cur.execute("SELECT COUNT(*) as cnt FROM saved_searches WHERE user_id=%s", (current_user.id,))
                if cur.fetchone()["cnt"] >= 20:
                    cur.execute("""DELETE FROM saved_searches WHERE user_id=%s
                                   ORDER BY created_at ASC LIMIT 1""", (current_user.id,))
                cur.execute("INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s,%s,%s,%s)",
                            (current_user.id, name, page, params))
            db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route("/saved-searches/delete/<int:search_id>", methods=["POST"])
@login_required
def delete_saved_search(search_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM saved_searches WHERE id=%s AND user_id=%s", (search_id, current_user.id))
            db.commit()
    except Exception:
        pass
    return redirect(url_for('search.saved_searches'))

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
