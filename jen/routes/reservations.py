"""
jen/routes/reservations.py
───────────────────────────
Reservation management routes including bulk operations.
"""

import csv
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
bp = Blueprint("reservations", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION
    return JEN_VERSION




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
    hosts = []
    total = 0
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    try:
        with __db.kea_db() as kdb:
            with __db.jen_db() as jdb:
                with kdb.cursor() as cur:
                    where = ["h.dhcp4_subnet_id > 0"]
                    params = []
                    if subnet_filter != "all":
                        try:
                            sid = int(subnet_filter)
                            if current_user.can_access_subnet(sid):
                                where.append("h.dhcp4_subnet_id=%s")
                                params.append(sid)
                            else:
                                subnet_filter = "all"
                        except ValueError:
                            subnet_filter = "all"
                    if subnet_filter == "all" and not current_user.all_subnets:
                        from jen.services.access import add_subnet_restriction
                        where, params = add_subnet_restriction(where, params, "h", "dhcp4_subnet_id")
                    if search:
                        where.append("(inet_ntoa(h.ipv4_address) LIKE %s OR h.hostname LIKE %s OR HEX(h.dhcp_identifier) LIKE %s)")
                        s = f"%{search}%"
                        params += [s, s, s.replace(":", "")]
                    cur.execute(f"SELECT COUNT(*) as cnt FROM hosts h WHERE {' AND '.join(where)}", params)
                    total = cur.fetchone()["cnt"]
                    if per_page:
                        offset = (page - 1) * per_page
                        limit_clause = f"LIMIT {per_page} OFFSET {offset}"
                    else:
                        limit_clause = ""
                    cur.execute(f"""
                        SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                               h.hostname, HEX(h.dhcp_identifier) AS mac_hex,
                               h.dhcp4_subnet_id AS subnet_id
                        FROM hosts h
                        WHERE {' AND '.join(where)}
                        ORDER BY {sort_col} {direction}
                        {limit_clause}
                    """, params)
                    rows = cur.fetchall()
                    with jdb.cursor() as jcur:
                        for row in rows:
                            mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                            note = jcur.fetchone()
                            # Fetch DNS override from Kea options table
                            cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                            dns_row = cur.fetchone()
                            hosts.append({**row, "mac": mac,
                                          "notes": note["notes"] if note else "",
                                          "dns_override": dns_row["formatted_value"] if dns_row else "",
                                          "subnet_name": extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")})
    except Exception as e:
        flash(f"Could not load reservations: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page) if per_page else 1
    stale_days = int(__user.get_global_setting("stale_device_days", "30"))
    mac_list = [h["mac"] for h in hosts if h.get("mac")]
    device_info = __fp.get_device_info_map(mac_list)
    template_vars = dict(
        hosts=hosts, subnet_filter=subnet_filter, search=search,
        subnet_map=accessible_subnet_map, page=page, pages=pages,
        total=total, stale_days=stale_days, sort=sort, direction=direction,
        device_info=device_info, per_page=per_page_param,
        get_manufacturer_icon_url=__fp.get_manufacturer_icon_url,
        device_type_display=__fp.DEVICE_TYPE_DISPLAY
    )
    if request.headers.get("HX-Request") == "true":
        # v4.4.6 fix: previously hand-built just the <tr> rows HTML,
        # leaving the sort-link headers and pagination (rendered outside
        # the htmx swap target) stuck on stale subnet/search/per_page
        # values from the last full page load — same class of bug fixed
        # in leases.py. Rendering the whole results partial keeps
        # everything in sync with the live filter state.
        return render_template("_reservations_results.html", **template_vars), 200
    return render_template("reservations.html", **template_vars)

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
    return render_template("add_reservation.html",
                           subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP),
                           prefill=prefill)

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
    if not current_user.can_access_subnet(subnet_id):
        flash("You do not have access to that subnet.", "error")
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
                with __db.kea_db() as db:
                    with db.cursor() as cur:
                        cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                        row = cur.fetchone()
                        if row:
                            with __db.jen_db() as jdb:
                                with jdb.cursor() as jcur:
                                    jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                                                 (row["host_id"], notes, notes))
                                jdb.commit()
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
        with __db.kea_db() as db:
            with __db.jen_db() as jdb:
                with db.cursor() as cur:
                    cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                    host = cur.fetchone()
                    if not host:
                        flash("Reservation not found.", "error")
                        return redirect(url_for('reservations.reservations'))
                    if not current_user.can_access_subnet(host["subnet_id"]):
                        flash("You do not have access to that subnet.", "error")
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
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('reservations.reservations'))
    return render_template("edit_reservation.html", host=host, subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP))

@bp.route("/reservations/edit/<int:host_id>", methods=["POST"])
@login_required
@_admin_required
def edit_reservation_post(host_id):
    hostname = request.form.get("hostname", "").strip()[:253]
    notes = request.form.get("notes", "").strip()[:1000]
    dns_override = request.form.get("dns_override", "").strip()
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                host = cur.fetchone()
                if not host:
                    flash("Reservation not found.", "error")
                    return redirect(url_for('reservations.reservations'))
                if not current_user.can_access_subnet(host["subnet_id"]):
                    flash("You do not have access to that subnet.", "error")
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
        # Kea's reservation-del + reservation-add churns hosts.host_id — it's an
        # AUTO_INCREMENT primary key, so the recreated row gets a brand new id
        # even though ip/mac/subnet are unchanged. Kea does that write over its
        # own connection (its API, not this process's), so re-querying it needs
        # a FRESH connection/transaction here too — reusing the one above would
        # still see the pre-Kea-write snapshot under REPEATABLE READ and could
        # report the stale host_id even though Kea already committed the new row.
        with __db.kea_db() as db2:
            with db2.cursor() as cur2:
                cur2.execute(
                    "SELECT host_id FROM hosts WHERE dhcp4_subnet_id=%s AND inet_ntoa(ipv4_address)=%s",
                    (host["subnet_id"], host["ip"])
                )
                new_host_row = cur2.fetchone()
                new_host_id = new_host_row["host_id"] if new_host_row else host_id
        with __db.jen_db() as jdb:
            with jdb.cursor() as jcur:
                if new_host_id != host_id:
                    jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                             (new_host_id, notes, notes))
            jdb.commit()
        flash("Reservation updated.", "success")
        __user.audit("EDIT_RESERVATION", host["ip"], f"hostname={hostname}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/delete/<int:host_id>", methods=["POST"])
@login_required
@_admin_required
def delete_reservation(host_id):
    is_htmx = request.headers.get("HX-Request") == "true"
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                host = cur.fetchone()
                if host and not current_user.can_access_subnet(host["subnet_id"]):
                    if is_htmx:
                        return '<tr><td colspan="7" style="color:var(--danger);padding:8px;">You do not have access to that subnet.</td></tr>', 403
                    flash("You do not have access to that subnet.", "error")
                    return redirect(url_for('reservations.reservations'))
                if host:
                    mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
                    result = __kea.kea_command("reservation-del", arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac})
                    if result.get("result") == 0:
                        with __db.jen_db() as jdb:
                            with jdb.cursor() as jcur:
                                jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                            jdb.commit()
                        __user.audit("DELETE_RESERVATION", host["ip"], f"MAC={mac}")
                        if is_htmx:
                            # Return empty string — HTMX swaps row with nothing (removes it)
                            return "", 200
                        flash(f"Reservation {host['ip']} deleted.", "success")
                    else:
                        if is_htmx:
                            return f'<tr id="reservation-{host_id}"><td colspan="7" style="color:var(--danger);padding:8px;">Kea error: {result.get("text")}</td></tr>', 422
                        flash(f"Kea error: {result.get('text')}", "error")
    except Exception as e:
        if is_htmx:
            return f'<tr id="reservation-{host_id}"><td colspan="7" style="color:var(--danger);padding:8px;">Error: {str(e)}</td></tr>', 500
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('reservations.reservations'))

@bp.route("/reservations/export")
@login_required
def export_reservations():
    try:
        with __db.kea_db() as db:
            with __db.jen_db() as jdb:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["ip", "mac", "hostname", "subnet_id", "subnet_name", "dns_override", "notes"])
                with db.cursor() as cur:
                    cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp4_subnet_id > 0 ORDER BY ipv4_address")
                    for row in cur.fetchall():
                        if not current_user.can_access_subnet(row["subnet_id"]):
                            continue
                        mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                        cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                        dns_row = cur.fetchone()
                        dns = dns_row["formatted_value"] if dns_row else ""
                        with jdb.cursor() as jcur:
                            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                            note = jcur.fetchone()
                        subnet_name = extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")
                        writer.writerow([row["ip"], mac, row["hostname"] or "", row["subnet_id"], subnet_name, dns, note["notes"] if note else ""])
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
        with __db.kea_db() as db:
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
                    if not current_user.can_access_subnet(subnet_id):
                        results["errors"].append(f"Row {i}: no access to subnet_id {subnet_id}")
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
        with __db.kea_db() as db:
            with __db.jen_db() as jdb:
                with db.cursor() as cur:
                    for host_id in host_ids:
                        try:
                            host_id = int(host_id)
                            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, dhcp_identifier, dhcp4_subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                            host = cur.fetchone()
                            if host and not current_user.can_access_subnet(host["dhcp4_subnet_id"]):
                                errors += 1
                                continue
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
                jdb.commit()
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
        with __db.kea_db() as db:
            with __db.jen_db() as jdb:
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
                            if row and not current_user.can_access_subnet(row["dhcp4_subnet_id"]):
                                continue
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
