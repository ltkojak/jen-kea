"""
jen/routes/reservations.py
───────────────────────────
Reservation management routes including bulk operations.
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
bp = Blueprint("reservations", __name__)


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


@bp.route("/reservations")
@login_required
def reservations():
    subnet_filter = request.args.get("subnet", "all")
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    sort = request.args.get("sort", "ip")
    direction = request.args.get("dir", "asc")
    if direction not in ("asc", "desc"):
        direction = "asc"
    sort_map = {
        "ip": "h.ipv4_address",
        "hostname": "h.hostname",
        "mac": "h.dhcp_identifier",
        "subnet": "h.dhcp4_subnet_id",
    }
    sort_col = sort_map.get(sort, "h.ipv4_address")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50
    hosts = []
    total = 0
    try:
        kea_db = __db.get_kea_db()
        jen_db = __db.get_jen_db()
        with kea_db.cursor() as cur:
            where = ["h.dhcp4_subnet_id > 0"]
            params = []
            if subnet_filter != "all":
                try:
                    where.append("h.dhcp4_subnet_id=%s")
                    params.append(int(subnet_filter))
                except ValueError:
                    subnet_filter = "all"
            if search:
                where.append("(inet_ntoa(h.ipv4_address) LIKE %s OR h.hostname LIKE %s OR HEX(h.dhcp_identifier) LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s.replace(":", "")]
            cur.execute(f"SELECT COUNT(*) as cnt FROM hosts h WHERE {' AND '.join(where)}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                       h.hostname, HEX(h.dhcp_identifier) AS mac_hex,
                       h.dhcp4_subnet_id AS subnet_id
                FROM hosts h
                WHERE {' AND '.join(where)}
                ORDER BY {sort_col} {direction}
                LIMIT {per_page} OFFSET {offset}
            """, params)
            rows = cur.fetchall()
            with jen_db.cursor() as jcur:
                for row in rows:
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note = jcur.fetchone()
                    hosts.append({**row, "mac": mac,
                                  "notes": note["notes"] if note else "",
                                  "subnet_name": extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")})
        kea_db.close()
        jen_db.close()
    except Exception as e:
        flash(f"Could not load reservations: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    stale_days = int(__user.get_global_setting("stale_device_days", "30"))
    mac_list = [h["mac"] for h in hosts if h.get("mac")]
    device_info = __fp.get_device_info_map(mac_list)
    return render_template("reservations.html", hosts=hosts,
                           subnet_filter=subnet_filter, search=search,
                           subnet_map=extensions.SUBNET_MAP, page=page, pages=pages,
                           total=total, stale_days=stale_days,
                           sort=sort, direction=direction, device_info=device_info,
                           get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
                           device_type_display=__fp.DEVICE_TYPE_DISPLAY)

@bp.route("/reservations/add")
@login_required
@_admin_required
def add_reservation():
    prefill = {
        "ip": request.args.get("ip", ""),
        "mac": request.args.get("mac", ""),
        "hostname": request.args.get("hostname", ""),
        "subnet_id": request.args.get("subnet_id", ""),
    }
    return render_template("add_reservation.html", subnet_map=extensions.SUBNET_MAP, prefill=prefill)

@bp.route("/reservations/add", methods=["POST"])
@login_required
@_admin_required
def add_reservation_post():
    ip = request.form.get("ip", "").strip()
    mac = request.form.get("mac", "").strip().lower()
    hostname = request.form.get("hostname", "").strip()[:253]
    notes = request.form.get("notes", "").strip()[:1000]
    dns_override = request.form.get("dns_override", "").strip()
    try:
        subnet_id = int(request.form.get("subnet_id", 1))
    except ValueError:
        flash("Invalid subnet.", "error")
        return redirect(url_for('reservations.add_reservation'))
    errors = []
    if not __auth.valid_ip(ip): errors.append(f"Invalid IP: {ip}")
    if not __auth.valid_mac(mac): errors.append(f"Invalid MAC: {mac}")
    if hostname and not __auth.valid_hostname(hostname): errors.append(f"Invalid hostname: {hostname}")
    if dns_override and not __auth.valid_dns(dns_override): errors.append(f"Invalid DNS: {dns_override}")
    if errors:
        for e in errors: flash(e, "error")
        return redirect(url_for('reservations.add_reservation'))
    res = {"subnet-id": subnet_id, "hw-address": mac, "ip-address": ip, "hostname": hostname}
    if dns_override:
        res["option-data"] = [{"name": "domain-name-servers", "data": dns_override}]
    result = __kea.kea_command("reservation-add", arguments={"reservation": res})
    if result.get("result") == 0:
        if notes:
            try:
                db = __db.get_kea_db()
                with db.cursor() as cur:
                    cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                    row = cur.fetchone()
                    if row:
                        jdb = __db.get_jen_db()
                        with jdb.cursor() as jcur:
                            jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                                         (row["host_id"], notes, notes))
                        jdb.commit(); jdb.close()
                db.close()
            except Exception:
                pass
        flash(f"Reservation added: {ip} → {mac}", "success")
        __user.audit("ADD_RESERVATION", ip, f"MAC={mac} hostname={hostname}")
        return redirect(url_for('reservations.reservations'))
    else:
        flash(f"Kea error: {result.get('text', 'Unknown error')}", "error")
        return redirect(url_for('reservations.add_reservation'))

@bp.route("/reservations/edit/<int:host_id>")
@login_required
@_admin_required
def edit_reservation(host_id):
    try:
        db = __db.get_kea_db()
        jdb = __db.get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if not host:
                flash("Reservation not found.", "error")
                return redirect(url_for('reservations.reservations'))
            mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
            cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (host_id,))
            dns_row = cur.fetchone()
            host["mac"] = mac
            host["dns_override"] = dns_row["formatted_value"] if dns_row else ""
        with jdb.cursor() as jcur:
            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (host_id,))
            note = jcur.fetchone()
            host["notes"] = note["notes"] if note else ""
        db.close(); jdb.close()
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('reservations.reservations'))
    return render_template("edit_reservation.html", host=host, subnet_map=extensions.SUBNET_MAP)

@bp.route("/reservations/edit/<int:host_id>", methods=["POST"])
@login_required
@_admin_required
def edit_reservation_post(host_id):
    hostname = request.form.get("hostname", "").strip()[:253]
    notes = request.form.get("notes", "").strip()[:1000]
    dns_override = request.form.get("dns_override", "").strip()
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if not host:
                flash("Reservation not found.", "error")
                return redirect(url_for('reservations.reservations'))
            mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
            __kea.kea_command("reservation-del", arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac})
            res = {"subnet-id": host["subnet_id"], "hw-address": mac, "ip-address": host["ip"], "hostname": hostname}
            if dns_override:
                res["option-data"] = [{"name": "domain-name-servers", "data": dns_override}]
            result = __kea.kea_command("reservation-add", arguments={"reservation": res})
            if result.get("result") != 0:
                flash(f"Kea error: {result.get('text')}", "error")
                return redirect(url_for('reservations.edit_reservation', host_id=host_id))
        db.close()
        jdb = __db.get_jen_db()
        with jdb.cursor() as jcur:
            jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                         (host_id, notes, notes))
        jdb.commit(); jdb.close()
        flash("Reservation updated.", "success")
        __user.audit("EDIT_RESERVATION", host["ip"], f"hostname={hostname}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/delete/<int:host_id>", methods=["POST"])
@login_required
@_admin_required
def delete_reservation(host_id):
    try:
        db = __db.get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if host:
                mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
                result = __kea.kea_command("reservation-del", arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac})
                if result.get("result") == 0:
                    jdb = __db.get_jen_db()
                    with jdb.cursor() as jcur:
                        jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                    jdb.commit(); jdb.close()
                    flash(f"Reservation {host['ip']} deleted.", "success")
                    __user.audit("DELETE_RESERVATION", host["ip"], f"MAC={mac}")
                else:
                    flash(f"Kea error: {result.get('text')}", "error")
        db.close()
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/export")
@login_required
def export_reservations():
    try:
        db = __db.get_kea_db()
        jdb = __db.get_jen_db()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "mac", "hostname", "subnet_id", "subnet_name", "dns_override", "notes"])
        with db.cursor() as cur:
            cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp4_subnet_id > 0 ORDER BY ipv4_address")
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                dns_row = cur.fetchone()
                dns = dns_row["formatted_value"] if dns_row else ""
                with jdb.cursor() as jcur:
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note = jcur.fetchone()
                subnet_name = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")
                writer.writerow([row["ip"], mac, row["hostname"] or "", row["subnet_id"], subnet_name, dns, note["notes"] if note else ""])
        db.close(); jdb.close()
        output.seek(0)
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=reservations.csv"})
    except Exception as e:
        flash(f"Export error: {str(e)}", "error")
        return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/import", methods=["POST"])
@login_required
@_admin_required
def import_reservations():
    dry_run = request.args.get("dry_run", "0") == "1"
    csv_file = request.files.get("csv_file")
    if not csv_file or not csv_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for('reservations.reservations'))
    results = {"added": 0, "skipped": 0, "errors": []}
    try:
        stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(stream)
        db = __db.get_kea_db()
        for i, row in enumerate(reader, 1):
            ip = (row.get("ip") or row.get("IP") or "").strip()
            mac = (row.get("mac") or row.get("MAC") or "").strip().lower().replace("-", ":")
            hostname = (row.get("hostname") or row.get("HOSTNAME") or "").strip()
            subnet_id = (row.get("subnet_id") or row.get("SUBNET_ID") or "").strip()
            if not ip or not mac:
                results["errors"].append(f"Row {i}: missing IP or MAC")
                continue
            try:
                subnet_id = int(subnet_id)
                if subnet_id not in extensions.SUBNET_MAP:
                    results["errors"].append(f"Row {i}: unknown subnet_id {subnet_id}")
                    continue
            except (ValueError, TypeError):
                results["errors"].append(f"Row {i}: invalid subnet_id")
                continue
            mac_bytes = mac.replace(":", "")
            if len(mac_bytes) != 12:
                results["errors"].append(f"Row {i}: invalid MAC {mac}")
                continue
            if not dry_run:
                with db.cursor() as cur:
                    # Check for duplicate
                    cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s AND dhcp4_subnet_id=%s", (ip, subnet_id))
                    if cur.fetchone():
                        results["skipped"] += 1
                        continue
                    cur.execute("""INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id,
                                   ipv4_address, hostname, dhcp4_client_classes, dhcp6_client_classes)
                                   VALUES (UNHEX(%s), 1, %s, INET_ATON(%s), %s, '', '')""",
                                (mac_bytes, subnet_id, ip, hostname))
            results["added"] += 1
        if not dry_run:
            db.commit()
        db.close()
        if dry_run:
            flash(f"Dry run: {results['added']} would be added, {results['skipped']} skipped. {len(results['errors'])} error(s).", "info")
        else:
            flash(f"Import complete: {results['added']} added, {results['skipped']} skipped. {len(results['errors'])} error(s).", "success")
            __user.audit("IMPORT_RESERVATIONS", "reservations", f"Added {results['added']} by {current_user.username}")
        for err in results["errors"][:10]:
            flash(err, "warning")
    except Exception as e:
        flash(f"Import error: {str(e)}", "error")
    return redirect(url_for('reservations.reservations'))

# ─────────────────────────────────────────
# Subnets
# ─────────────────────────────────────────

@bp.route("/reservations/bulk-delete", methods=["POST"])
@login_required
@_admin_required
def bulk_delete_reservations():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        flash("No reservations selected.", "error")
        return redirect(url_for('reservations.reservations'))

    deleted = 0
    errors = 0
    try:
        db = __db.get_kea_db()
        jdb = __db.get_jen_db()
        with db.cursor() as cur:
            for host_id in host_ids:
                try:
                    host_id = int(host_id)
                    cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, dhcp_identifier, dhcp4_subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                    host = cur.fetchone()
                    if host:
                        mac = __kea.format_mac(host["dhcp_identifier"])
                        result = __kea.kea_command("reservation-del", arguments={
                            "subnet-id": host["dhcp4_subnet_id"],
                            "identifier-type": "hw-address", "identifier": mac
                        })
                        if result.get("result") == 0:
                            with jdb.cursor() as jcur:
                                jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                            deleted += 1
                        else:
                            errors += 1
                except Exception:
                    errors += 1
        db.close()
        jdb.commit()
        jdb.close()
    except Exception as e:
        flash(f"Bulk delete error: {str(e)}", "error")
        return redirect(url_for('reservations.reservations'))

    flash(f"Deleted {deleted} reservation(s)." + (f" {errors} failed." if errors else ""), 
          "success" if errors == 0 else "warning")
    __user.audit("BULK_DELETE_RESERVATIONS", "reservations", f"Deleted={deleted} Errors={errors}")
    return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/bulk-export", methods=["POST"])
@login_required
def bulk_export_reservations():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        flash("No reservations selected.", "error")
        return redirect(url_for('reservations.reservations'))
    try:
        db = __db.get_kea_db()
        jdb = __db.get_jen_db()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "mac", "hostname", "subnet_id", "subnet_name", "dns_override", "notes"])
        with db.cursor() as cur:
            for host_id in host_ids:
                try:
                    host_id = int(host_id)
                    cur.execute("""
                        SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                               h.dhcp_identifier, h.hostname, h.dhcp4_subnet_id
                        FROM hosts h WHERE h.host_id=%s
                    """, (host_id,))
                    row = cur.fetchone()
                    if row:
                        mac = __kea.format_mac(row["dhcp_identifier"])
                        cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (host_id,))
                        dns_row = cur.fetchone()
                        dns = dns_row["formatted_value"] if dns_row and dns_row["formatted_value"] else ""
                        with jdb.cursor() as jcur:
                            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (host_id,))
                            note_row = jcur.fetchone()
                            notes = note_row["notes"] if note_row else ""
                        subnet_name = extensions.SUBNET_MAP.get(row["dhcp4_subnet_id"], {}).get("name", "")
                        writer.writerow([row["ip"], mac, row["hostname"] or "", row["dhcp4_subnet_id"],
                                         subnet_name, dns, notes])
                except Exception:
                    pass
        db.close()
        jdb.close()
        output.seek(0)
        __user.audit("BULK_EXPORT_RESERVATIONS", "reservations", f"Exported {len(host_ids)} selected")
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=reservations_selected.csv"})
    except Exception as e:
        flash(f"Export error: {str(e)}", "error")
        return redirect(url_for('reservations.reservations'))

# ─────────────────────────────────────────
# Subnet notes
# ─────────────────────────────────────────
