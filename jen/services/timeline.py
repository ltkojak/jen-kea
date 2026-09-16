"""
jen/services/timeline.py
──────────────────────────
v5.42.0 (Q43) — the merged view for one client's DHCP/reservation/
history: `events` rows, `audit_log` rows mentioning it, `alert_log`
rows mentioning it, its `devices` bookends, and its current lease and
reservation. Both `GET /timeline` (the page) and `GET /api/v1/timeline/
{mac}` (the API) call `build_timeline()` — one merge, two renderings.

No access control here — callers resolve the subject's subnet_id
(`subnet_id_for()`) and gate the whole response themselves; a client
identified only by IP with no lease/device/reservation on record has no
subnet to gate on at all.
"""

import logging

import jen.models.db as __db
import jen.services.kea6 as __kea6

logger = logging.getLogger(__name__)

# A LIKE pattern that can never appear as a substring of any real mac,
# ip, or free-text field — used in place of an absent search term so a
# blank mac/ip never degrades to "LIKE '%%'" (which would match every
# row). Fixed SQL statements only (bandit B608) — never built with an
# f-string/join, even over these fixed values; only parameters vary.
_NEVER_MATCH = "\x00\x00\x00"


def _mac_from_ip(ip: str) -> str:
    """The active lease's MAC for this IP, or ''."""
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute("SELECT HEX(hwaddr) AS mac_hex FROM lease4 WHERE address=inet_aton(%s) AND state=0", (ip,))
            row = cur.fetchone()
    except Exception:
        return ""
    if not row or not row["mac_hex"]:
        return ""
    hexed = row["mac_hex"]
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).lower()


def _current_lease(mac: str, ip: str) -> dict | None:
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            if mac:
                cur.execute(
                    "SELECT inet_ntoa(address) AS ip, subnet_id, IFNULL(hostname,'') AS hostname, expire "
                    "FROM lease4 WHERE HEX(hwaddr)=%s AND state=0 ORDER BY expire DESC LIMIT 1",
                    (mac.replace(":", "").upper(),),
                )
            else:
                cur.execute(
                    "SELECT inet_ntoa(address) AS ip, subnet_id, IFNULL(hostname,'') AS hostname, expire "
                    "FROM lease4 WHERE address=inet_aton(%s) AND state=0",
                    (ip,),
                )
            return cur.fetchone()
    except Exception:
        return None


def _current_reservation(mac: str) -> dict | None:
    if not mac:
        return None
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT host_id, dhcp4_subnet_id AS subnet_id, inet_ntoa(ipv4_address) AS ip, "
                "IFNULL(hostname,'') AS hostname FROM hosts WHERE HEX(dhcp_identifier)=%s AND dhcp_identifier_type=0",
                (mac.replace(":", "").upper(),),
            )
            return cur.fetchone()
    except Exception:
        return None


def _device(mac: str) -> dict | None:
    if not mac:
        return None
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT mac, device_name, first_seen, last_seen, last_ip, last_hostname, last_subnet_id "
                "FROM devices WHERE mac=%s",
                (mac,),
            )
            return cur.fetchone()
    except Exception:
        return None


def subnet_id_for(device, lease, reservation) -> int | None:
    """Best current guess at the subject's subnet — device's last known,
    else the active lease's, else the reservation's. None if the client
    has no record anywhere (a bare mac= that's never leased or reserved)."""
    if device and device.get("last_subnet_id"):
        return device["last_subnet_id"]
    if lease and lease.get("subnet_id"):
        return lease["subnet_id"]
    if reservation and reservation.get("subnet_id"):
        return reservation["subnet_id"]
    return None


def build_timeline(mac: str = "", ip: str = "", limit: int = 300) -> dict:
    """`mac`/`ip` are already validated/normalized by the caller (lowercase
    mac, no colons stripped). At least one must be given. Returns
    `{"mac", "ip", "device", "lease", "reservation", "subnet_id", "rows"}`
    — `rows` is `[{"ts", "kind", "source", "detail", "subnet_id"}, ...]`
    newest-first, capped at `limit`."""
    mac = (mac or "").strip().lower()
    ip = (ip or "").strip()
    if not mac and ip:
        mac = _mac_from_ip(ip)

    device = _device(mac)
    lease = _current_lease(mac, ip)
    reservation = _current_reservation(mac)
    if not ip and lease:
        ip = lease["ip"]
    elif not ip and device:
        ip = device.get("last_ip") or ""

    rows: list[dict] = []
    mac_hex = mac.replace(":", "").upper() if mac else ""

    if mac or ip:
        # Fixed statements throughout (bandit B608) — mac/ip are always
        # both bound, an absent one as '' (matches no `=` row) or
        # _NEVER_MATCH (matches no LIKE row), never joined into the SQL
        # text itself.
        mac_pat = f"%{mac}%" if mac else _NEVER_MATCH
        ip_pat = f"%{ip}%" if ip else _NEVER_MATCH
        try:
            with __db.jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "SELECT ts, kind, subnet_id, detail FROM events WHERE mac=%s OR ip=%s ORDER BY ts DESC LIMIT %s",
                    (mac, ip, limit),
                )
                for r in cur.fetchall():
                    rows.append(
                        {
                            "ts": r["ts"],
                            "kind": r["kind"],
                            "source": "event",
                            "detail": r["detail"] or "",
                            "subnet_id": r["subnet_id"],
                        }
                    )

                cur.execute(
                    "SELECT created_at AS ts, action, details, username FROM audit_log "
                    "WHERE entity LIKE %s OR details LIKE %s OR entity LIKE %s OR details LIKE %s "
                    "ORDER BY created_at DESC LIMIT %s",
                    (mac_pat, mac_pat, ip_pat, ip_pat, limit),
                )
                for r in cur.fetchall():
                    who = f" by {r['username']}" if r["username"] else ""
                    rows.append(
                        {
                            "ts": r["ts"],
                            "kind": f"audit.{r['action']}",
                            "source": "audit",
                            "detail": f"{r['details'] or ''}{who}",
                            "subnet_id": None,
                        }
                    )

                cur.execute(
                    "SELECT sent_at AS ts, alert_type, channel_type, status FROM alert_log "
                    "WHERE message LIKE %s OR message LIKE %s ORDER BY sent_at DESC LIMIT %s",
                    (mac_pat, ip_pat, limit),
                )
                for r in cur.fetchall():
                    rows.append(
                        {
                            "ts": r["ts"],
                            "kind": f"alert.{r['alert_type']}",
                            "source": "alert",
                            "detail": f"via {r['channel_type']} — {r['status']}",
                            "subnet_id": None,
                        }
                    )
        except Exception as e:
            logger.error(f"timeline build failed for mac={mac!r} ip={ip!r}: {e}")

    rows.sort(key=lambda r: r["ts"], reverse=True)
    rows = rows[:limit]

    # v5.45.0 (Q46) — "a device detail/timeline shows both": this client's
    # current v6 address(es), when Kea captured a real hwaddr for one (the
    # same hwaddr-only join the Devices page uses — see
    # kea6.lease6_by_hwaddr_mac()). No access control here either, same
    # as everything else in this function — the caller already gates the
    # whole response on subnet_id_for()'s v4 subnet.
    v6_addresses = []
    if mac:
        try:
            if __kea6.is_ipv6_enabled():
                v6_addresses = __kea6.lease6_by_hwaddr_mac().get(mac, [])
        except Exception as e:
            logger.error(f"timeline v6 address lookup failed for mac={mac!r}: {e}")

    return {
        "mac": mac,
        "ip": ip,
        "mac_hex": mac_hex,
        "device": device,
        "lease": lease,
        "reservation": reservation,
        "subnet_id": subnet_id_for(device, lease, reservation),
        "rows": rows,
        "v6_addresses": v6_addresses,
    }
