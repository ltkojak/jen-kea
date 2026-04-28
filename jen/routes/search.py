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
import jen.services.mfa as __mfa
import jen.services.auth as __auth


logger = logging.getLogger(__name__)
bp = Blueprint("search", __name__)


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


@bp.route("/search")
@login_required
def global_search():
    q = __auth.sanitize_search(request.args.get("q", "").strip())
    results = {"leases": [], "reservations": [], "devices": []}
    if len(q) >= 2:
        try:
            kea_db = __db.get_kea_db()
            jen_db = __db.get_jen_db()
            s = f"%{q}%"
            s_mac = s.replace(":", "")

            # Search leases
            with kea_db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(l.address) AS ip,
                           l.hostname,
                           HEX(l.hwaddr) AS mac_hex,
                           l.subnet_id,
                           l.expire, l.state
                    FROM lease4 l
                    WHERE inet_ntoa(l.address) LIKE %s
                       OR l.hostname LIKE %s
                       OR HEX(l.hwaddr) LIKE %s
                    LIMIT 20
                """, (s, s, s_mac))
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    results["leases"].append({
                        "ip": row["ip"], "hostname": row["hostname"] or "",
                        "mac": mac, "subnet_id": row["subnet_id"]
                    })

            # Search reservations
            with kea_db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(h.ipv4_address) AS ip,
                           h.hostname,
                           HEX(h.dhcp_identifier) AS mac_hex,
                           h.dhcp4_subnet_id AS subnet_id
                    FROM hosts h
                    WHERE h.dhcp4_subnet_id > 0
                      AND (inet_ntoa(h.ipv4_address) LIKE %s
                           OR h.hostname LIKE %s
                           OR HEX(h.dhcp_identifier) LIKE %s)
                    LIMIT 20
                """, (s, s, s_mac))
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    results["reservations"].append({
                        "ip": row["ip"], "hostname": row["hostname"] or "",
                        "mac": mac, "subnet_id": row["subnet_id"]
                    })

            # Search devices
            with jen_db.cursor() as cur:
                cur.execute("""
                    SELECT mac, last_ip, name, owner, notes
                    FROM devices
                    WHERE mac LIKE %s OR last_ip LIKE %s
                       OR name LIKE %s OR owner LIKE %s
                    LIMIT 20
                """, (s, s, s, s))
                results["devices"] = cur.fetchall()

            kea_db.close()
            jen_db.close()
        except Exception as e:
            flash(f"Search error: {str(e)}", "error")

    total = sum(len(v) for v in results.values())
    return render_template("search_results.html",
                           q=q, results=results, total=total,
                           subnet_map=extensions.SUBNET_MAP,
                           subnet_names=SUBNET_NAMES)

# ─────────────────────────────────────────
# MFA Routes
# ─────────────────────────────────────────

@bp.route("/saved-searches", methods=["GET"])
@login_required
def saved_searches():
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY created_at DESC", (current_user.id,))
            searches = cur.fetchall()
        db.close()
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
        db = __db.get_jen_db()
        with db.cursor() as cur:
            # Max 20 saved searches per user
            cur.execute("SELECT COUNT(*) as cnt FROM saved_searches WHERE user_id=%s", (current_user.id,))
            if cur.fetchone()["cnt"] >= 20:
                cur.execute("""DELETE FROM saved_searches WHERE user_id=%s
                               ORDER BY created_at ASC LIMIT 1""", (current_user.id,))
            cur.execute("INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s,%s,%s,%s)",
                        (current_user.id, name, page, params))
        db.commit()
        db.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route("/saved-searches/delete/<int:search_id>", methods=["POST"])
@login_required
def delete_saved_search(search_id):
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM saved_searches WHERE id=%s AND user_id=%s", (search_id, current_user.id))
        db.commit()
        db.close()
    except Exception:
        pass
    return redirect(url_for('search.saved_searches'))

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
