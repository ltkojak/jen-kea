"""
jen/routes/api.py
─────────────────
REST API v1 endpoints and API key management routes.
"""

import hashlib
import secrets
from datetime import datetime

from flask import (Blueprint, jsonify, redirect, render_template,
                   request, session, url_for, flash)
from flask_login import current_user, login_required

from jen import extensions
from jen.models.db import get_jen_db, get_kea_db
from jen.models.user import audit
from jen.services.fingerprint import get_device_info_map
from jen.services.kea import kea_command, kea_is_up, get_active_kea_server

bp = Blueprint("api", __name__)

JEN_VERSION = None   # injected by app factory


# ── Helpers ──────────────────────────────────────────────────────────────────

def _api_auth():
    """Validate Bearer token. Returns key row or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_key  = auth[7:].strip()
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name FROM api_keys WHERE key_hash=%s AND active=1",
                (key_hash,)
            )
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE api_keys SET last_used=NOW() WHERE id=%s", (row["id"],))
                db.commit()
        db.close()
        return row
    except Exception:
        return None


def api_error(message, code=400):
    return jsonify({"error": message}), code


def api_ok(data):
    return jsonify(data)


def _ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


# ── REST API v1 ───────────────────────────────────────────────────────────────

@bp.route("/api/v1/health")
def api_v1_health():
    up      = kea_is_up()
    version = ""
    try:
        ver = kea_command("version-get")
        if ver.get("result") == 0:
            version = ver.get("arguments", {}).get("extended", ver.get("text", ""))
            version = version.splitlines()[0] if version else ""
    except Exception:
        pass
    from jen import JEN_VERSION as _ver
    return api_ok({"jen_version": _ver, "kea_up": up,
                   "kea_version": version, "subnets": len(extensions.SUBNET_MAP)})


@bp.route("/api/v1/subnets")
def api_v1_subnets():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for sid, info in extensions.SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (sid,))
                reserved = cur.fetchone()["cnt"]
                result.append({"id": sid, "name": info["name"], "cidr": info["cidr"],
                                "active_leases": active, "reservations": reserved,
                                "pool_size": 0, "pools": [], "utilization_pct": 0})
        db.close()
        try:
            cfg_result = kea_command("config-get", server=get_active_kea_server())
            if cfg_result.get("result") == 0:
                for s in cfg_result["arguments"]["Dhcp4"].get("subnet4", []):
                    for r in result:
                        if r["id"] == s["id"]:
                            pool_size = 0
                            pools = []
                            for p in s.get("pools", []):
                                ps = p.get("pool", "") if isinstance(p, dict) else str(p)
                                if "-" in ps:
                                    start, end = [x.strip() for x in ps.split("-")]
                                    pool_size += _ip_to_int(end) - _ip_to_int(start) + 1
                                    pools.append(ps)
                            r["pool_size"]       = pool_size
                            r["pools"]           = pools
                            r["utilization_pct"] = round(r["active_leases"] / pool_size * 100, 1) if pool_size else 0
        except Exception:
            pass
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"subnets": result, "count": len(result)})


@bp.route("/api/v1/leases")
def api_v1_leases():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    subnet   = request.args.get("subnet", "")
    mac      = request.args.get("mac", "").lower().replace(":", "").replace("-", "")
    hostname = request.args.get("hostname", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            where  = ["l.state=0", "l.expire > NOW()"]
            params = []
            if subnet:
                sid = next((k for k, v in extensions.SUBNET_MAP.items()
                            if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("l.subnet_id=%s")
                    params.append(sid)
            if mac:
                where.append("HEX(l.hwaddr) LIKE %s")
                params.append("%" + mac + "%")
            if hostname:
                where.append("l.hostname LIKE %s")
                params.append("%" + hostname + "%")
            cur.execute(
                "SELECT inet_ntoa(l.address) AS ip, l.hostname, HEX(l.hwaddr) AS mac_hex, "
                "l.subnet_id, (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained, "
                "l.expire AS expires, l.valid_lifetime "
                "FROM lease4 l WHERE " + " AND ".join(where) + " ORDER BY l.expire DESC LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
                si = extensions.SUBNET_MAP.get(row["subnet_id"], {})
                result.append({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                                "subnet_id": row["subnet_id"], "subnet_name": si.get("name", ""),
                                "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                                "expires":  row["expires"].isoformat()  if row["expires"]  else None,
                                "valid_lifetime": row["valid_lifetime"]})
        db.close()
        di = get_device_info_map([r["mac"] for r in result if r["mac"]])
        for r in result:
            info = di.get(r["mac"], {})
            r["manufacturer"] = info.get("manufacturer", "")
            r["device_type"]  = info.get("device_type",  "unknown")
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"leases": result, "count": len(result)})


@bp.route("/api/v1/leases/<mac>")
def api_v1_lease_by_mac(mac):
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac_clean = mac.lower().replace(":", "").replace("-", "")
    if len(mac_clean) != 12:
        return api_error("Invalid MAC address format.", 400)
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(l.address) AS ip, l.hostname, HEX(l.hwaddr) AS mac_hex, "
                "l.subnet_id, (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained, "
                "l.expire AS expires, l.valid_lifetime, l.state "
                "FROM lease4 l WHERE HEX(l.hwaddr)=%s ORDER BY l.expire DESC LIMIT 1",
                (mac_clean.upper(),)
            )
            row = cur.fetchone()
        db.close()
        if not row:
            return api_error("No lease found for this MAC address.", 404)
        mf     = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
        si     = extensions.SUBNET_MAP.get(row["subnet_id"], {})
        active = row["state"] == 0 and row["expires"] and row["expires"] > datetime.now()
        return api_ok({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                        "subnet_id": row["subnet_id"], "subnet_name": si.get("name", ""),
                        "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                        "expires":  row["expires"].isoformat()  if row["expires"]  else None,
                        "valid_lifetime": row["valid_lifetime"], "active": active})
    except Exception as e:
        return api_error(str(e), 500)


@bp.route("/api/v1/devices")
def api_v1_devices_endpoint():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac    = request.args.get("mac",    "").lower().replace(":", "").replace("-", "")
    name   = request.args.get("name",   "")
    subnet = request.args.get("subnet", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            where  = ["1=1"]
            params = []
            if mac:
                where.append("REPLACE(d.mac, ':', '') LIKE %s")
                params.append("%" + mac + "%")
            if name:
                where.append("(d.device_name LIKE %s OR d.last_hostname LIKE %s)")
                params += ["%" + name + "%", "%" + name + "%"]
            if subnet:
                sid = next((k for k, v in extensions.SUBNET_MAP.items()
                            if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("d.last_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT d.mac, d.device_name, d.owner, d.last_ip, d.last_hostname, "
                "d.last_subnet_id, d.first_seen, d.last_seen, "
                "DATEDIFF(NOW(), d.last_seen) as days_inactive "
                "FROM devices d WHERE " + " AND ".join(where) + " ORDER BY d.last_seen DESC LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                si = extensions.SUBNET_MAP.get(row["last_subnet_id"], {})
                result.append({"mac": row["mac"], "device_name": row["device_name"] or "",
                                "owner": row["owner"] or "", "last_ip": row["last_ip"] or "",
                                "last_hostname": row["last_hostname"] or "",
                                "subnet_name": si.get("name", ""),
                                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                                "last_seen":  row["last_seen"].isoformat()  if row["last_seen"]  else None,
                                "days_inactive": row["days_inactive"]})
        db.close()
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"devices": result, "count": len(result)})


@bp.route("/api/v1/devices/<mac>")
def api_v1_device_by_mac(mac):
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac_fmt = mac.lower().replace("-", ":")
    try:
        db  = get_jen_db()
        kdb = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM devices WHERE mac=%s", (mac_fmt,))
            row = cur.fetchone()
        if not row:
            db.close(); kdb.close()
            return api_error("Device not found.", 404)
        mac_clean = mac_fmt.replace(":", "").upper()
        with kdb.cursor() as kcur:
            kcur.execute(
                "SELECT inet_ntoa(address) AS ip, hostname, state, "
                "(expire - INTERVAL valid_lifetime SECOND) AS obtained, expire AS expires "
                "FROM lease4 WHERE HEX(hwaddr)=%s ORDER BY expire DESC LIMIT 1",
                (mac_clean,)
            )
            lease = kcur.fetchone()
        db.close(); kdb.close()
        si = extensions.SUBNET_MAP.get(row["last_subnet_id"], {})
        result = {"mac": row["mac"], "device_name": row["device_name"] or "",
                  "owner": row["owner"] or "", "last_ip": row["last_ip"] or "",
                  "last_hostname": row["last_hostname"] or "", "subnet_name": si.get("name", ""),
                  "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                  "last_seen":  row["last_seen"].isoformat()  if row["last_seen"]  else None,
                  "online": False, "current_lease": None}
        if lease and lease["state"] == 0 and lease["expires"] and lease["expires"] > datetime.now():
            result["online"] = True
            result["current_lease"] = {
                "ip":       lease["ip"],
                "hostname": lease["hostname"] or "",
                "obtained": lease["obtained"].isoformat() if lease["obtained"] else None,
                "expires":  lease["expires"].isoformat()  if lease["expires"]  else None,
            }
        return api_ok(result)
    except Exception as e:
        return api_error(str(e), 500)


@bp.route("/api/v1/reservations")
def api_v1_reservations():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    subnet = request.args.get("subnet", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            where  = ["dhcp4_subnet_id > 0"]
            params = []
            if subnet:
                sid = next((k for k, v in extensions.SUBNET_MAP.items()
                            if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("dhcp4_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, "
                "HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id "
                "FROM hosts WHERE " + " AND ".join(where) + " ORDER BY ipv4_address LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
                si = extensions.SUBNET_MAP.get(row["subnet_id"], {})
                result.append({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                                "subnet_id": row["subnet_id"], "subnet_name": si.get("name", "")})
        db.close()
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"reservations": result, "count": len(result)})


# ── API Key Management ────────────────────────────────────────────────────────

@bp.route("/settings/api-keys")
@login_required
def api_keys():
    from jen import admin_required as _ar
    if current_user.role != "admin":
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    keys = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used, k.active, "
                "u.username as created_by_name "
                "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by "
                "ORDER BY k.created_at DESC"
            )
            keys = cur.fetchall()
        db.close()
    except Exception as e:
        flash(f"Could not load API keys: {e}", "error")
    return render_template("api_keys.html", keys=keys)


@bp.route("/settings/api-keys/create", methods=["POST"])
@login_required
def api_keys_create():
    if current_user.role != "admin":
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    name = request.form.get("name", "").strip()[:100]
    if not name:
        flash("Key name is required.", "error")
        return redirect(url_for("api.api_keys"))
    raw_key  = "jen_" + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES (%s,%s,%s,%s)",
                (name, key_hash, raw_key[:8], current_user.id)
            )
        db.commit(); db.close()
        audit("API_KEY_CREATE", "api_keys", f"Key '{name}' created by {current_user.username}")
        session["new_api_key"]      = raw_key
        session["new_api_key_name"] = name
        flash("API key created. Copy it now — it won't be shown again.", "success")
    except Exception as e:
        flash(f"Error creating key: {e}", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-keys/revoke/<int:key_id>", methods=["POST"])
@login_required
def api_keys_revoke(key_id):
    if current_user.role != "admin":
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT name FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE api_keys SET active=0 WHERE id=%s", (key_id,))
                db.commit()
                audit("API_KEY_REVOKE", "api_keys", f"Key '{row['name']}' revoked")
                flash(f"API key '{row['name']}' revoked.", "success")
        db.close()
    except Exception as e:
        flash(f"Error revoking key: {e}", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-keys/delete/<int:key_id>", methods=["POST"])
@login_required
def api_keys_delete(key_id):
    if current_user.role != "admin":
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT name FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if row:
                cur.execute("DELETE FROM api_keys WHERE id=%s", (key_id,))
                db.commit()
                audit("API_KEY_DELETE", "api_keys", f"Key '{row['name']}' deleted")
                flash(f"API key '{row['name']}' deleted.", "success")
        db.close()
    except Exception as e:
        flash(f"Error deleting key: {e}", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-docs")
@login_required
def api_docs():
    keys = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, key_prefix FROM api_keys WHERE active=1 "
                "ORDER BY created_at DESC LIMIT 10"
            )
            keys = cur.fetchall()
        db.close()
    except Exception:
        pass
    return render_template("api_docs.html", keys=keys,
                           base_url=request.host_url.rstrip("/"))
