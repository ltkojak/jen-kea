"""
jen/routes/api.py
─────────────────
REST API v1 endpoints and API key management routes.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

import jen.services.auth as __auth
import jen.services.events as __events
import jen.services.kea as __kea
from jen import extensions
from jen.models.db import jen_db, kea_db
from jen.models.user import audit
from jen.services import client_subject as __subject
from jen.services.access import diagnostic_surface
from jen.services.api_auth import api_auth as _api_auth
from jen.services.api_auth import key_subnet_ids as _api_key_subnet_ids
from jen.services.fingerprint import get_device_info_map
from jen.services.kea import get_active_kea_server, kea_command, kea_is_up

bp = Blueprint("api", __name__)

logger = logging.getLogger(__name__)

JEN_VERSION = None  # injected by app factory


# ── Helpers ──────────────────────────────────────────────────────────────────
# _api_auth()/_api_key_subnet_ids() moved to jen/services/api_auth.py
# (v5.57.0, Q73) so api_key_required() — the plugin-API v3 decorator for
# routes under /api/v1/plugins/<plugin_id>/… — can reuse the exact same
# validation. Imported here under their original names so every call
# site below is unchanged.


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
    up = kea_is_up()
    version = ""
    try:
        ver = kea_command("version-get")
        if ver.get("result") == 0:
            version = ver.get("arguments", {}).get("extended", ver.get("text", ""))
            version = version.splitlines()[0] if version else ""
    except Exception:
        pass
    from jen import JEN_VERSION as _ver

    return api_ok({"jen_version": _ver, "kea_up": up, "kea_version": version, "subnets": len(extensions.SUBNET_MAP)})


@bp.route("/api/v1/subnets")
def api_v1_subnets():
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    result = []
    try:
        with kea_db() as db, db.cursor() as cur:
            for sid, info in extensions.SUBNET_MAP.items():
                if scope is not None and sid not in scope:
                    continue
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (sid,))
                reserved = cur.fetchone()["cnt"]
                result.append(
                    {
                        "id": sid,
                        "name": info["name"],
                        "cidr": info["cidr"],
                        "active_leases": active,
                        "reservations": reserved,
                        "pool_size": 0,
                        "pools": [],
                        "utilization_pct": 0,
                        "peak_30d": None,
                        "trend_per_day": None,
                        "days_to_90pct": None,
                        "forecast": "insufficient",
                    }
                )
        # v5.36.0 (Q35): the exhaustion forecast from the lease history.
        # A history read that fails leaves the forecast fields at their
        # "insufficient" defaults rather than failing the whole call.
        try:
            from jen.services import capacity as _capacity
            from jen.services.health import lease_history_window

            history = lease_history_window()
            for r in result:
                rows = history.get(r["id"], [])
                if not rows:
                    continue
                f = _capacity.forecast(rows)
                hw = _capacity.high_water(rows)
                r["peak_30d"] = hw["peak"] if hw else None
                r["trend_per_day"] = f["slope_per_day"] if f["trend"] in ("rising", "flat", "falling") else None
                r["days_to_90pct"] = f["days_to_90pct"]
                r["forecast"] = f["trend"]
        except Exception as e:
            logger.warning(f"api_v1_subnets forecast skipped: {e}")
        try:
            cfg_result = kea_command("config-get", server=get_active_kea_server())
            if cfg_result.get("result") == 0:
                from jen.services.kea_config_view import iter_subnet4

                for s, _sn in iter_subnet4(cfg_result["arguments"].get("Dhcp4", {})):
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
                            r["pool_size"] = pool_size
                            r["pools"] = pools
                            r["utilization_pct"] = round(r["active_leases"] / pool_size * 100, 1) if pool_size else 0
        except Exception:
            pass
    except Exception as e:
        logger.error(f"api_v1_subnets error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"subnets": result, "count": len(result)})


def _packet_health_summary(server_id, window_minutes=60):
    """{status, window_minutes, rates} for GET /api/v1/servers — a lighter
    shape than servers.html's block (jen.routes.servers::
    _packet_health_for_server), which also carries the sparkline and the
    full counters table. None until the server has two snapshots."""
    import json as _json

    from jen.services import packet_health as _packet_health

    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT snapshot_time, stats FROM server_stats WHERE server_id=%s "
                "AND snapshot_time > DATE_SUB(NOW(), INTERVAL 90 MINUTE) ORDER BY snapshot_time",
                (server_id,),
            )
            raw_rows = cur.fetchall()
    except Exception as e:
        logger.warning(f"api_v1_servers packet health for server {server_id}: {e}")
        return None
    rows = []
    for r in raw_rows:
        stats = r["stats"]
        if isinstance(stats, str):
            stats = _json.loads(stats)
        rows.append({"snapshot_time": r["snapshot_time"], "stats": stats})
    if len(rows) < 2:
        return None
    rates = _packet_health.rates(_packet_health.deltas(rows), window_minutes=window_minutes)
    assessment = _packet_health.assess(rates)
    return {
        "status": assessment["status"],
        "window_minutes": round(rates["window_minutes"]),
        "rates": {k: round(v, 2) for k, v in rates["rates"].items()},
    }


@bp.route("/api/v1/servers")
def api_v1_servers():
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    result = []
    try:
        for s in __kea.get_all_server_status():
            result.append(
                {
                    "id": s["server"]["id"],
                    "name": s["server"]["name"],
                    "role": s["server"].get("role", ""),
                    "up": s["up"],
                    "ha_state": s.get("ha_state"),
                    "version": s.get("version", ""),
                    "packet_health": _packet_health_summary(s["server"]["id"]) if s["up"] else None,
                }
            )
    except Exception as e:
        logger.error(f"api_v1_servers error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"servers": result, "count": len(result)})


@bp.route("/api/v1/leases")
def api_v1_leases():
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    subnet = request.args.get("subnet", "")
    mac = request.args.get("mac", "").lower().replace(":", "").replace("-", "")
    hostname = request.args.get("hostname", "")
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        limit = 200
    if scope is not None and not scope:
        return api_ok({"leases": [], "count": 0})
    result = []
    try:
        with kea_db() as db, db.cursor() as cur:
            where = ["l.state=0", "l.expire > NOW()"]
            params = []
            if scope is not None:
                placeholders = ",".join(["%s"] * len(scope))
                where.append(f"l.subnet_id IN ({placeholders})")
                params.extend(scope)
            if subnet:
                sid = next(
                    (
                        k
                        for k, v in extensions.SUBNET_MAP.items()
                        if v["name"].lower() == subnet.lower() or str(k) == subnet
                    ),
                    None,
                )
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
                params + [limit],
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
                si = extensions.SUBNET_MAP.get(row["subnet_id"], {})
                result.append(
                    {
                        "ip": row["ip"],
                        "mac": mf,
                        "hostname": row["hostname"] or "",
                        "subnet_id": row["subnet_id"],
                        "subnet_name": si.get("name", ""),
                        "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                        "expires": row["expires"].isoformat() if row["expires"] else None,
                        "valid_lifetime": row["valid_lifetime"],
                    }
                )
        di = get_device_info_map([r["mac"] for r in result if r["mac"]])
        for r in result:
            info = di.get(r["mac"], {})
            r["manufacturer"] = info.get("manufacturer", "")
            r["device_type"] = info.get("device_type", "unknown")
    except Exception as e:
        logger.error(f"api_v1_leases error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"leases": result, "count": len(result)})


@bp.route("/api/v1/leases/<mac>")
@diagnostic_surface(subject="client")
def api_v1_lease_by_mac(mac):
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    mac_clean = mac.lower().replace(":", "").replace("-", "")
    if len(mac_clean) != 12:
        return api_error("Invalid MAC address format.", 400)
    try:
        with kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(l.address) AS ip, l.hostname, HEX(l.hwaddr) AS mac_hex, "
                "l.subnet_id, (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained, "
                "l.expire AS expires, l.valid_lifetime, l.state "
                "FROM lease4 l WHERE HEX(l.hwaddr)=%s ORDER BY l.expire DESC LIMIT 1",
                (mac_clean.upper(),),
            )
            row = cur.fetchone()
        if not row or (scope is not None and row["subnet_id"] not in scope):
            # Same 404 whether the lease doesn't exist or this key just
            # can't see its subnet — don't reveal which via a different
            # status code.
            return api_error("No lease found for this MAC address.", 404)
        mf = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
        si = extensions.SUBNET_MAP.get(row["subnet_id"], {})
        active = row["state"] == 0 and row["expires"] and row["expires"] > datetime.now()
        return api_ok(
            {
                "ip": row["ip"],
                "mac": mf,
                "hostname": row["hostname"] or "",
                "subnet_id": row["subnet_id"],
                "subnet_name": si.get("name", ""),
                "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                "expires": row["expires"].isoformat() if row["expires"] else None,
                "valid_lifetime": row["valid_lifetime"],
                "active": active,
            }
        )
    except Exception as e:
        logger.error(f"api_v1_lease_by_mac error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)


@bp.route("/api/v1/devices")
@diagnostic_surface(subject="client")
def api_v1_devices_endpoint():
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    mac = request.args.get("mac", "").lower().replace(":", "").replace("-", "")
    name = request.args.get("name", "")
    subnet = request.args.get("subnet", "")
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        limit = 200
    if scope is not None and not scope:
        return api_ok({"devices": [], "count": 0})
    result = []
    try:
        with jen_db() as db, db.cursor() as cur:
            where = ["1=1"]
            params = []
            if scope is not None:
                placeholders = ",".join(["%s"] * len(scope))
                where.append(f"d.last_subnet_id IN ({placeholders})")
                params.extend(scope)
            if mac:
                where.append("REPLACE(d.mac, ':', '') LIKE %s")
                params.append("%" + mac + "%")
            if name:
                where.append("(d.device_name LIKE %s OR d.last_hostname LIKE %s)")
                params += ["%" + name + "%", "%" + name + "%"]
            if subnet:
                sid = next(
                    (
                        k
                        for k, v in extensions.SUBNET_MAP.items()
                        if v["name"].lower() == subnet.lower() or str(k) == subnet
                    ),
                    None,
                )
                if sid:
                    where.append("d.last_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT d.mac, d.device_name, d.owner, d.last_ip, d.last_hostname, "
                "d.last_subnet_id, d.first_seen, d.last_seen, "
                "DATEDIFF(NOW(), d.last_seen) as days_inactive "
                "FROM devices d WHERE " + " AND ".join(where) + " ORDER BY d.last_seen DESC LIMIT %s",
                params + [limit],
            )
            for row in cur.fetchall():
                si = extensions.SUBNET_MAP.get(row["last_subnet_id"], {})
                result.append(
                    {
                        "mac": row["mac"],
                        "device_name": row["device_name"] or "",
                        "owner": row["owner"] or "",
                        "last_ip": row["last_ip"] or "",
                        "last_hostname": row["last_hostname"] or "",
                        "subnet_name": si.get("name", ""),
                        "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                        "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                        "days_inactive": row["days_inactive"],
                    }
                )
    except Exception as e:
        logger.error(f"api_v1_devices_endpoint error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"devices": result, "count": len(result)})


@bp.route("/api/v1/devices/<mac>")
@diagnostic_surface(subject="client")
def api_v1_device_by_mac(mac):
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    mac_fmt = mac.lower().replace("-", ":")
    try:
        # v5.63.0 (Q82) — the device lookup itself is client_subject's now
        # (the same query every other consumer uses); the lease query below
        # stays this route's own — it needs the raw row regardless of
        # lease state (to report `online: false` rather than 404) and a
        # precomputed `obtained` column client_subject.load_leases4 doesn't
        # return, so it isn't a fit for the shared loader.
        row = __subject.load_device(mac_fmt)
        with kea_db() as kdb:
            if not row or (scope is not None and row["last_subnet_id"] not in scope):
                return api_error("Device not found.", 404)
            mac_clean = mac_fmt.replace(":", "").upper()
            with kdb.cursor() as kcur:
                kcur.execute(
                    "SELECT inet_ntoa(address) AS ip, hostname, state, subnet_id, "
                    "(expire - INTERVAL valid_lifetime SECOND) AS obtained, expire AS expires "
                    "FROM lease4 WHERE HEX(hwaddr)=%s ORDER BY expire DESC LIMIT 1",
                    (mac_clean,),
                )
                lease = kcur.fetchone()
        if scope is not None and lease and lease.get("subnet_id") not in scope:
            # the device is in a subnet this key covers, but its newest lease
            # is in one it does not (a client that moved) — never show that
            lease = None
        si = extensions.SUBNET_MAP.get(row["last_subnet_id"], {})
        result = {
            "mac": row["mac"],
            "device_name": row["device_name"] or "",
            "owner": row["owner"] or "",
            "last_ip": row["last_ip"] or "",
            "last_hostname": row["last_hostname"] or "",
            "subnet_name": si.get("name", ""),
            "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            "online": False,
            "current_lease": None,
        }
        if lease and lease["state"] == 0 and lease["expires"] and lease["expires"] > datetime.now():
            result["online"] = True
            result["current_lease"] = {
                "ip": lease["ip"],
                "hostname": lease["hostname"] or "",
                "obtained": lease["obtained"].isoformat() if lease["obtained"] else None,
                "expires": lease["expires"].isoformat() if lease["expires"] else None,
            }
        return api_ok(result)
    except Exception as e:
        logger.error(f"api_v1_device_by_mac error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)


@bp.route("/api/v1/reservations")
def api_v1_reservations():
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    scope = _api_key_subnet_ids(key)
    subnet = request.args.get("subnet", "")
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        limit = 200
    if scope is not None and not scope:
        return api_ok({"reservations": [], "count": 0})
    result = []
    try:
        with kea_db() as db, db.cursor() as cur:
            where = ["dhcp4_subnet_id > 0"]
            params = []
            if scope is not None:
                placeholders = ",".join(["%s"] * len(scope))
                where.append(f"dhcp4_subnet_id IN ({placeholders})")
                params.extend(scope)
            if subnet:
                sid = next(
                    (
                        k
                        for k, v in extensions.SUBNET_MAP.items()
                        if v["name"].lower() == subnet.lower() or str(k) == subnet
                    ),
                    None,
                )
                if sid:
                    where.append("dhcp4_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, "
                "HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id "
                "FROM hosts WHERE " + " AND ".join(where) + " ORDER BY ipv4_address LIMIT %s",
                params + [limit],
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)).lower() if row["mac_hex"] else ""
                si = extensions.SUBNET_MAP.get(row["subnet_id"], {})
                result.append(
                    {
                        "ip": row["ip"],
                        "mac": mf,
                        "hostname": row["hostname"] or "",
                        "subnet_id": row["subnet_id"],
                        "subnet_name": si.get("name", ""),
                    }
                )
    except Exception as e:
        logger.error(f"api_v1_reservations error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"reservations": result, "count": len(result)})


# ── REST API v1 — writes (v5.34.0, Q33) ──────────────────────────────────────
#
# Same Bearer auth and the same per-key subnet scope as the reads, plus the
# key's `can_write` flag (migration 25, off by default). Nothing here
# touches a Kea config file: reservations go through Kea's host_cmds hook
# exactly like the Reservations page, device overrides and subnet notes are
# Jen's own tables. Every write is audited with the key's name as the
# actor — an API request has no Flask-Login user.

_WRITE_RATE_PER_MINUTE = 60
_write_hits: dict = {}


def _write_rate_limited(key_id) -> bool:
    """In-memory per-key limiter for the write endpoints: at most
    _WRITE_RATE_PER_MINUTE calls in any rolling 60 s window."""
    import time as _time

    now = _time.monotonic()
    hits = [t for t in _write_hits.get(key_id, []) if now - t < 60]
    if len(hits) >= _WRITE_RATE_PER_MINUTE:
        _write_hits[key_id] = hits
        return True
    hits.append(now)
    _write_hits[key_id] = hits
    return False


def _api_write_gate():
    """(key, None) when the request may write, else (None, error response)."""
    key = _api_auth()
    if not key:
        return None, api_error("Invalid or missing API key.", 401)
    if not key.get("can_write"):
        return None, api_error(
            "This API key is read-only. Create one with write access under Settings → API Keys.", 403
        )
    if _write_rate_limited(key["id"]):
        return None, api_error("Rate limit: at most 60 write requests per minute per key.", 429)
    return key, None


def _api_scope_allows(key, subnet_id) -> bool:
    scope = _api_key_subnet_ids(key)
    return scope is None or int(subnet_id) in scope


def _api_audit(key, action, entity, details=""):
    audit(action, entity, f"[api-key:{key.get('name')}] {details}".strip())


def _json_body() -> dict:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


@bp.route("/api/v1/reservations", methods=["POST"])
def api_v1_reservation_create():
    key, err = _api_write_gate()
    if err:
        return err
    body = _json_body()
    try:
        subnet_id = int(body.get("subnet_id"))
    except (TypeError, ValueError):
        return api_error("subnet_id (integer) is required.", 400)
    if subnet_id not in extensions.SUBNET_MAP:
        return api_error(f"Unknown subnet_id {subnet_id}.", 404)
    if not _api_scope_allows(key, subnet_id):
        return api_error("This key has no access to that subnet.", 403)
    ip = str(body.get("ip") or "").strip()
    mac = str(body.get("mac") or "").strip().lower()
    hostname = str(body.get("hostname") or "").strip()[:253]
    dns = str(body.get("dns") or "").strip()
    notes = str(body.get("notes") or "").strip()[:1000]
    problems = []
    if not __auth.valid_ip(ip):
        problems.append(f"invalid ip {ip!r}")
    if not __auth.valid_mac(mac):
        problems.append(f"invalid mac {mac!r}")
    if hostname and not __auth.valid_hostname(hostname):
        problems.append("invalid hostname")
    if dns and not __auth.valid_dns(dns):
        problems.append("invalid dns")
    if problems:
        return api_error("; ".join(problems), 400)
    res = {"subnet-id": subnet_id, "hw-address": mac, "ip-address": ip, "hostname": hostname}
    if dns:
        res["option-data"] = [{"name": "domain-name-servers", "data": dns}]
    result = __kea.kea_command("reservation-add", arguments={"reservation": res})
    if result.get("result") != 0:
        return api_error(f"Kea refused the reservation: {result.get('text', 'unknown error')}", 502)
    host_id = None
    try:
        with kea_db() as db, db.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
            row = cur.fetchone()
            host_id = row["host_id"] if row else None
        if notes and host_id is not None:
            with jen_db() as jdb, jdb.cursor() as jcur:
                jcur.execute(
                    "INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                    (host_id, notes, notes),
                )
                jdb.commit()
    except Exception as e:
        logger.warning(f"api reservation create: notes/host_id lookup failed: {e}")
    _api_audit(key, "ADD_RESERVATION", ip, f"MAC={mac} hostname={hostname} subnet={subnet_id}")
    __events.emit(
        "reservation.added", mac=mac, ip=ip, subnet_id=subnet_id, hostname=hostname or None, actor=key["name"]
    )
    return api_ok({"host_id": host_id, "ip": ip, "mac": mac, "hostname": hostname, "subnet_id": subnet_id}), 201


@bp.route("/api/v1/reservations/<int:host_id>", methods=["DELETE"])
def api_v1_reservation_delete(host_id):
    key, err = _api_write_gate()
    if err:
        return err
    try:
        with kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id "
                "FROM hosts WHERE host_id=%s",
                (host_id,),
            )
            host = cur.fetchone()
    except Exception as e:
        logger.error(f"api reservation delete lookup: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    if not host:
        return api_error(f"No reservation with host_id {host_id}.", 404)
    if not _api_scope_allows(key, host["subnet_id"] or 0):
        return api_error("This key has no access to that subnet.", 403)
    mac = ":".join(host["mac_hex"][i : i + 2] for i in range(0, 12, 2)).lower() if host["mac_hex"] else ""
    result = __kea.kea_command(
        "reservation-del",
        arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac},
    )
    if result.get("result") != 0:
        return api_error(f"Kea refused the deletion: {result.get('text', 'unknown error')}", 502)
    try:
        with jen_db() as jdb, jdb.cursor() as jcur:
            jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
            jdb.commit()
    except Exception as e:
        logger.warning(f"api reservation delete: notes cleanup failed: {e}")
    _api_audit(key, "DELETE_RESERVATION", host["ip"], f"MAC={mac} host_id={host_id}")
    __events.emit("reservation.deleted", mac=mac, ip=host["ip"], subnet_id=host["subnet_id"], actor=key["name"])
    return api_ok({"deleted": host_id, "ip": host["ip"], "mac": mac, "subnet_id": host["subnet_id"]})


@bp.route("/api/v1/devices/<mac>", methods=["PATCH"])
@diagnostic_surface(subject="client")
def api_v1_device_patch(mac):
    """The plain-text fields an admin can set on the Devices page: name,
    owner, notes. Type/icon overrides stay UI-only (they map through a
    display table)."""
    key, err = _api_write_gate()
    if err:
        return err
    mac = (mac or "").strip().lower()
    if not __auth.valid_mac(mac):
        return api_error("Invalid MAC address.", 400)
    body = _json_body()
    fields = {}
    for name, column, limit in (("name", "device_name", 200), ("owner", "owner", 200), ("notes", "notes", 1000)):
        if name in body:
            value = body.get(name)
            if value is not None and not isinstance(value, str):
                return api_error(f"{name} must be a string or null.", 400)
            fields[column] = (value or "").strip()[:limit] or None
    if not fields:
        return api_error("Nothing to change: send name, owner and/or notes.", 400)
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT id, last_subnet_id FROM devices WHERE mac=%s", (mac,))
            row = cur.fetchone()
            if not row:
                return api_error(f"No device with MAC {mac}.", 404)
            if _api_key_subnet_ids(key) is not None:
                # A subnet-scoped key may only touch a device Jen has placed in
                # a subnet the key covers; an unplaced device has no subnet to
                # check, so it is refused rather than waved through.
                if row.get("last_subnet_id") is None:
                    return api_error("This key is scoped to subnets and this device has no known subnet.", 403)
                if not _api_scope_allows(key, row["last_subnet_id"]):
                    return api_error("This key has no access to that device's subnet.", 403)
            # One fixed statement: IF(flag, new, old) per column, so no SQL is
            # built from strings and an unsent field is left untouched.
            cur.execute(
                "UPDATE devices SET device_name=IF(%s, %s, device_name), owner=IF(%s, %s, owner), "
                "notes=IF(%s, %s, notes) WHERE id=%s",
                (
                    "device_name" in fields,
                    fields.get("device_name"),
                    "owner" in fields,
                    fields.get("owner"),
                    "notes" in fields,
                    fields.get("notes"),
                    row["id"],
                ),
            )
            db.commit()
            cur.execute(
                "SELECT mac, device_name, owner, notes, last_ip, last_subnet_id FROM devices WHERE id=%s", (row["id"],)
            )
            out = cur.fetchone()
    except Exception as e:
        logger.error(f"api device patch: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    _api_audit(key, "EDIT_DEVICE", mac, ", ".join(f"{k}={v!r}" for k, v in fields.items()))
    return api_ok(
        {
            "mac": out["mac"],
            "name": out["device_name"],
            "owner": out["owner"],
            "notes": out["notes"],
            "last_ip": out["last_ip"],
            "subnet_id": out["last_subnet_id"],
        }
    )


@bp.route("/api/v1/subnets/<int:subnet_id>/notes", methods=["POST"])
def api_v1_subnet_notes(subnet_id):
    key, err = _api_write_gate()
    if err:
        return err
    if subnet_id not in extensions.SUBNET_MAP:
        return api_error(f"Unknown subnet_id {subnet_id}.", 404)
    if not _api_scope_allows(key, subnet_id):
        return api_error("This key has no access to that subnet.", 403)
    body = _json_body()
    text = body.get("text")
    if text is not None and not isinstance(text, str):
        return api_error("text must be a string (empty string clears the note).", 400)
    text = (text or "").strip()[:5000]
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO subnet_notes (subnet_id, notes) VALUES (%s, %s) ON DUPLICATE KEY UPDATE notes=%s, updated_at=NOW()",
                (subnet_id, text, text),
            )
            db.commit()
    except Exception as e:
        logger.error(f"api subnet notes: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    _api_audit(key, "SUBNET_NOTES", str(subnet_id), f"{len(text)} chars")
    return api_ok({"subnet_id": subnet_id, "notes": text})


@bp.route("/api/v1/events")
@diagnostic_surface(subject="client")
def api_v1_events():
    """v5.42.0 (Q43) — raw events rows (jen.services.events.emit()), not
    the merged timeline. mac/ip/kind/since are all optional filters,
    ANDed together; a key scoped to specific subnets never sees another
    subnet's events, and never sees a subnet-less event (config.applied,
    alert.sent to no particular subnet, …) at all."""
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    mac = (request.args.get("mac") or "").strip().lower()
    ip = (request.args.get("ip") or "").strip()
    kind = (request.args.get("kind") or "").strip()
    since_raw = (request.args.get("since") or "").strip()
    # Epoch, not '' — MySQL 8's strict mode rejects casting '' to the
    # ts column outright (error 1525) even inside an "(%s = '' OR …)"
    # branch that would otherwise short-circuit past it; a real,
    # always-valid TIMESTAMP sidesteps that rather than relying on
    # short-circuiting a typed column comparison.
    since = "1970-01-01 00:00:00"
    if since_raw:
        try:
            datetime.fromisoformat(since_raw.replace("Z", "+00:00"))
            since = since_raw
        except ValueError:
            return api_error("since must be an ISO 8601 date or datetime.", 400)
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
    except ValueError:
        limit = 200

    scope = _api_key_subnet_ids(key)
    result = []
    try:
        with jen_db() as db, db.cursor() as cur:
            # One fixed statement (bandit B608) — each filter is
            # "blank means match everything", never string-joined.
            cur.execute(
                "SELECT id, ts, kind, mac, ip, subnet_id, hostname, server, actor, detail FROM events "
                "WHERE (%s = '' OR mac = %s) AND (%s = '' OR ip = %s) AND (%s = '' OR kind = %s) "
                "AND ts >= %s ORDER BY ts DESC LIMIT %s",
                (mac, mac, ip, ip, kind, kind, since, limit),
            )
            for r in cur.fetchall():
                if scope is not None and (r["subnet_id"] is None or r["subnet_id"] not in scope):
                    continue
                result.append(
                    {
                        "id": r["id"],
                        "ts": r["ts"].isoformat() if r["ts"] else None,
                        "kind": r["kind"],
                        "mac": r["mac"],
                        "ip": r["ip"],
                        "subnet_id": r["subnet_id"],
                        "hostname": r["hostname"],
                        "server": r["server"],
                        "actor": r["actor"],
                        "detail": r["detail"],
                    }
                )
    except Exception as e:
        logger.error(f"api_v1_events error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok({"events": result, "count": len(result)})


@bp.route("/api/v1/timeline/<mac>")
@diagnostic_surface(subject="client")
def api_v1_timeline(mac):
    """v5.42.0 (Q43) — the same merged view GET /timeline renders,
    scoped to a single MAC. Subnet rules match the page: a key scoped to
    specific subnets needs access to the client's resolved subnet (or is
    refused outright if it can't be resolved at all), and any individual
    row outside that key's scope — including every subnet-less audit_log/
    alert_log row — is dropped rather than returned."""
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)
    mac = (mac or "").strip().lower()
    if not __auth.valid_mac(mac):
        return api_error("Invalid MAC address.", 400)

    from jen.services.timeline import build_timeline

    scope = _api_key_subnet_ids(key)
    result = build_timeline(mac=mac, accessible_v4_ids=scope)
    if scope is not None:
        if result["subnet_id"] is None or result["subnet_id"] not in scope:
            return api_error("This key has no access to that subnet.", 403)
        result["rows"] = [r for r in result["rows"] if r["subnet_id"] in scope]

    device = result["device"]
    lease = result["lease"]
    if device:
        device = {
            **device,
            "first_seen": device["first_seen"].isoformat(),
            "last_seen": device["last_seen"].isoformat(),
        }
    if lease:
        lease = {**lease, "expire": lease["expire"].isoformat()}
    return api_ok(
        {
            "mac": result["mac"],
            "ip": result["ip"],
            "subnet_id": result["subnet_id"],
            "device": device,
            "lease": lease,
            "reservation": result["reservation"],
            "rows": [{**r, "ts": r["ts"].isoformat() if r["ts"] else None} for r in result["rows"]],
        }
    )


@bp.route("/api/v1/health/checks")
@diagnostic_surface(subject="client")
def api_v1_health_checks():
    """v5.43.0 (Q44) — the Health Center run as JSON, scoped to the key's
    subnet access exactly like a restricted viewer's page load
    (health.run_checks's subnet_filter callable)."""
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)

    from jen.services import health as _health

    scope = _api_key_subnet_ids(key)
    subnet_filter = (lambda _sid: True) if scope is None else (lambda sid: sid in scope)
    try:
        checks = _health.run_checks({"subnet_filter": subnet_filter, "unrestricted": scope is None})
    except Exception as e:
        logger.error(f"api_v1_health_checks error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok(
        {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "summary": _health.summarize(checks),
            "checks": [c.as_dict() for c in checks],
        }
    )


@bp.route("/api/v1/health/readiness")
def api_v1_health_readiness():
    """v5.43.0 (Q44) — just the Kea 3.2 readiness group, the same five
    checks Settings → Kea's "ready for Kea 3.2?" line summarizes."""
    key = _api_auth()
    if not key:
        return api_error("Invalid or missing API key.", 401)

    from jen.services import health as _health
    from jen.services import kea_readiness as _readiness

    try:
        checks = _health.readiness_checks()
    except Exception as e:
        logger.error(f"api_v1_health_readiness error: {e}")
        return api_error("Internal error. Check server logs for details.", 500)
    return api_ok(
        {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "summary": _readiness.summarize(checks),
            "checks": [c.as_dict() for c in checks],
        }
    )


@bp.route("/api/v1/openapi.json")
def api_v1_openapi():
    """v5.34.0 (Q33) — the OpenAPI 3.0 description of this API, from one
    dict in jen/routes/api_spec.py; tests/test_api_spec.py diffs it
    against the URL map. No auth, like /api/v1/health."""
    from jen import JEN_VERSION as _v
    from jen.routes.api_spec import build_spec

    return jsonify(build_spec(_v, request.host_url.rstrip("/")))


# ── API Key Management ────────────────────────────────────────────────────────


@bp.route("/settings/api-keys")
@login_required
def api_keys():
    if current_user.role not in ("superadmin", "admin"):
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    keys = []
    try:
        with jen_db() as db, db.cursor() as cur:
            # v5.2.10 security fix — this previously loaded every
            # key regardless of who created it, and any admin
            # (not just superadmin) could view, revoke, or delete
            # any other admin's key just by knowing or guessing its
            # id, including one with broader subnet access than
            # they themselves have. A plain admin now only ever
            # sees keys they created; superadmins continue to see
            # everything, consistent with how superadmin access
            # works everywhere else in the app.
            if current_user.is_superadmin:
                cur.execute(
                    "SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used, k.active, k.can_write, "
                    "k.subnet_access, k.created_by, u.username as created_by_name "
                    "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by "
                    "ORDER BY k.created_at DESC"
                )
            else:
                cur.execute(
                    "SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used, k.active, k.can_write, "
                    "k.subnet_access, k.created_by, u.username as created_by_name "
                    "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by "
                    "WHERE k.created_by = %s "
                    "ORDER BY k.created_at DESC",
                    (current_user.id,),
                )
            keys = cur.fetchall()
        import json as _json

        for k in keys:
            if k.get("subnet_access"):
                try:
                    ids = _json.loads(k["subnet_access"])
                    k["subnet_names"] = [extensions.SUBNET_MAP.get(i, {}).get("name", str(i)) for i in ids]
                except Exception:
                    k["subnet_names"] = None
            else:
                k["subnet_names"] = None
    except Exception as e:
        logger.error(f"Could not load API keys: {e}")
        flash("Could not load API keys. Check server logs for details.", "error")
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    return render_template(
        "api_keys.html", keys=keys, subnet_map=accessible_subnet_map, can_grant_all_subnets=current_user.all_subnets
    )


@bp.route("/settings/api-keys/create", methods=["POST"])
@login_required
def api_keys_create():
    if current_user.role not in ("superadmin", "admin"):
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    name = request.form.get("name", "").strip()[:100]
    if not name:
        flash("Key name is required.", "error")
        return redirect(url_for("api.api_keys"))

    # Scope: chosen independently per-key at creation time, not inherited
    # from the creating user's own account and not unrestricted by default
    # (v5.1.11 — see migration 13). A key's access can never exceed what
    # the creating user can themselves see: for a subnet-restricted admin,
    # any "all" selection or any subnet id outside their own access is
    # dropped server-side, regardless of what the submitted form contains
    # — the <select> only offers their own subnets in the first place, but
    # this clamp holds even against a hand-crafted request.
    import json as _json

    subnet_ids_raw = request.form.getlist("subnet_ids")
    if current_user.all_subnets:
        if not subnet_ids_raw or "all" in subnet_ids_raw:
            subnet_access = None
        else:
            ids = [int(s) for s in subnet_ids_raw if s.isdigit()]
            subnet_access = _json.dumps(ids) if ids else None
    else:
        allowed = set(current_user.accessible_subnet_ids(extensions.SUBNET_MAP))
        ids = [int(s) for s in subnet_ids_raw if s.isdigit() and int(s) in allowed]
        if not ids:
            flash("Select at least one subnet this key should have access to.", "error")
            return redirect(url_for("api.api_keys"))
        subnet_access = _json.dumps(ids)

    # v5.34.0 (Q33) — write access is opt-in per key, off by default.
    can_write = 1 if request.form.get("can_write") == "1" else 0
    raw_key = "jen_" + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, can_write) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (name, key_hash, raw_key[:8], current_user.id, subnet_access, can_write),
                )
            db.commit()
        scope_desc = "all subnets" if subnet_access is None else f"subnets {subnet_access}"
        audit(
            "API_KEY_CREATE",
            "api_keys",
            f"Key '{name}' created by {current_user.username}, scope={scope_desc}, "
            f"{'read/write' if can_write else 'read-only'}",
        )
        session["new_api_key"] = raw_key
        session["new_api_key_name"] = name
        flash("API key created. Copy it now — it won't be shown again.", "success")
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        flash("Error creating key. Check server logs for details.", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-keys/revoke/<int:key_id>", methods=["POST"])
@login_required
def api_keys_revoke(key_id):
    if current_user.role not in ("superadmin", "admin"):
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT name, created_by FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            # v5.2.10 security fix — this previously let any admin
            # revoke any key by id, including one created by
            # another admin (or a superadmin) with broader subnet
            # access than they themselves have. Now scoped to
            # "you created it, or you're a superadmin" — the same
            # rule the listing query above applies. Deliberately
            # one generic message for both "no such key" and
            # "exists but isn't yours" — distinguishing the two
            # would let someone confirm a specific key id exists
            # even though they can't act on it either way.
            if not row or (not current_user.is_superadmin and row["created_by"] != current_user.id):
                flash("API key not found.", "error")
                return redirect(url_for("api.api_keys"))
            cur.execute("UPDATE api_keys SET active=0 WHERE id=%s", (key_id,))
            db.commit()
            audit("API_KEY_REVOKE", "api_keys", f"Key '{row['name']}' revoked")
            flash(f"API key '{row['name']}' revoked.", "success")
    except Exception as e:
        logger.error(f"Error revoking API key {key_id}: {e}")
        flash("Error revoking key. Check server logs for details.", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-keys/delete/<int:key_id>", methods=["POST"])
@login_required
def api_keys_delete(key_id):
    if current_user.role not in ("superadmin", "admin"):
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.dashboard"))
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT name, created_by FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            # Same ownership rule and same-message-either-way
            # reasoning as api_keys_revoke() above.
            if not row or (not current_user.is_superadmin and row["created_by"] != current_user.id):
                flash("API key not found.", "error")
                return redirect(url_for("api.api_keys"))
            cur.execute("DELETE FROM api_keys WHERE id=%s", (key_id,))
            db.commit()
            audit("API_KEY_DELETE", "api_keys", f"Key '{row['name']}' deleted")
            flash(f"API key '{row['name']}' deleted.", "success")
    except Exception as e:
        logger.error(f"Error deleting API key {key_id}: {e}")
        flash("Error deleting key. Check server logs for details.", "error")
    return redirect(url_for("api.api_keys"))


@bp.route("/settings/api-docs")
@login_required
def api_docs():
    keys = []
    # v5.10.4 — the "pre-fill from your keys" list showed every active
    # key's name and prefix to any logged-in user, including viewers, even
    # though /settings/api-keys itself is admin-only. Viewers get the
    # empty-state ("create one") the template already renders.
    if current_user.is_admin_or_above:
        try:
            with jen_db() as db, db.cursor() as cur:
                # Same ownership predicate as the API Keys page: a plain admin
                # sees only the keys they created, a superadmin sees all. One
                # fixed statement (the flag picks the branch), no string building.
                cur.execute(
                    "SELECT id, name, key_prefix FROM api_keys WHERE active=1 AND (%s OR created_by=%s) "
                    "ORDER BY created_at DESC LIMIT 10",
                    (bool(current_user.is_superadmin), current_user.id),
                )
                keys = cur.fetchall()
        except Exception:
            pass
    return render_template("api_docs.html", keys=keys, base_url=request.host_url.rstrip("/"))
