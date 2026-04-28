"""
jen/routes/reports.py
──────────────────────
Reports routes.
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
bp = Blueprint("reports", __name__)


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


@bp.route("/reports")
@login_required
def reports():
    days = request.args.get("days", "7")
    try:
        days = max(1, min(int(days), 90))
    except ValueError:
        days = 7

    history = {}
    try:
        db = __db.get_jen_db()
        with db.cursor() as cur:
            for subnet_id, info in extensions.SUBNET_MAP.items():
                cur.execute("""
                    SELECT
                        DATE_FORMAT(snapshot_time, '%%Y-%%m-%%d %%H:%%i') as ts,
                        active_leases, dynamic_leases, reserved_leases, pool_size
                    FROM lease_history
                    WHERE subnet_id=%s
                    AND snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    ORDER BY snapshot_time ASC
                """, (subnet_id, days))
                rows = cur.fetchall()
                history[subnet_id] = {
                    "name": info["name"],
                    "cidr": info["cidr"],
                    "data": rows
                }
        db.close()
    except Exception as e:
        logger.error(f"Reports error: {e}")
        flash(f"Could not load history data: {str(e)}", "error")

    # Summary stats
    summary = {}
    try:
        db = __db.get_kea_db()
        jdb = __db.get_jen_db()
        with db.cursor() as cur:
            with jdb.cursor() as jcur:
                for subnet_id, info in extensions.SUBNET_MAP.items():
                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    active = cur.fetchone()["cnt"]
                    jcur.execute("""
                        SELECT active_leases, pool_size, snapshot_time
                        FROM lease_history WHERE subnet_id=%s
                        ORDER BY snapshot_time DESC LIMIT 1
                    """, (subnet_id,))
                    last = jcur.fetchone()
                    jcur.execute("""
                        SELECT MAX(active_leases) as peak FROM lease_history
                        WHERE subnet_id=%s AND snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    """, (subnet_id, days))
                    peak = jcur.fetchone()
                    summary[subnet_id] = {
                        "name": info["name"],
                        "cidr": info["cidr"],
                        "current": active,
                        "pool_size": last["pool_size"] if last else 0,
                        "peak": peak["peak"] if peak and peak["peak"] else active,
                    }
        db.close()
        jdb.close()
    except Exception as e:
        logger.error(f"Reports summary error: {e}")

    snapshot_interval = __user.get_global_setting("snapshot_interval_minutes", "30")
    retention_days = __user.get_global_setting("history_retention_days", "90")
    data_points = sum(len(h["data"]) for h in history.values())

    return render_template("reports.html",
                           history=history, summary=summary, days=days,
                           subnet_map=extensions.SUBNET_MAP, data_points=data_points,
                           snapshot_interval=snapshot_interval,
                           retention_days=retention_days)

@bp.route("/reports/settings", methods=["POST"])
@login_required
@_admin_required
def save_report_settings():
    interval = request.form.get("snapshot_interval", "30").strip()
    retention = request.form.get("retention_days", "90").strip()
    if not interval.isdigit() or not (5 <= int(interval) <= 1440):
        flash("Snapshot interval must be between 5 and 1440 minutes.", "error")
        return redirect(url_for('reports.reports'))
    if not retention.isdigit() or not (1 <= int(retention) <= 365):
        flash("Retention must be between 1 and 365 days.", "error")
        return redirect(url_for('reports.reports'))
    __user.set_global_setting("snapshot_interval_minutes", interval)
    __user.set_global_setting("history_retention_days", retention)
    flash(f"Report settings saved — snapshots every {interval} minutes, kept for {retention} days.", "success")
    __user.audit("SAVE_SETTINGS", "reports", f"interval={interval}min retention={retention}days")
    return redirect(url_for('reports.reports'))

# ─────────────────────────────────────────
# API
# ─────────────────────────────────────────
