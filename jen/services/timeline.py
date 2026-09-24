"""
jen/services/timeline.py
──────────────────────────
v5.42.0 (Q43) — the merged view for one client's DHCP/reservation/
history: `events` rows, `audit_log` rows mentioning it, `alert_log`
rows mentioning it, its `devices` bookends, and its current lease and
reservation. Both `GET /timeline` (the page) and `GET /api/v1/timeline/
{mac}` (the API) call `build_timeline()` — one merge, two renderings.

v5.63.0 (Q82) — the device/lease/reservation/v6-address lookups and the
moved-client subnet filtering are `jen.services.client_subject`'s now
(the same queries, moved verbatim); this module keeps only what's
actually Timeline's own job — merging events/audit/alert rows and
labelling them (`related`, `previous_holder`).

No access control here — callers resolve the subject's subnet_id
(`subnet_id_for()`) and gate the whole response themselves; a client
identified only by IP with no lease/device/reservation on record has no
subnet to gate on at all.
"""

import logging

import jen.models.db as __db
from jen.services import client_subject as __subject

logger = logging.getLogger(__name__)

# A LIKE pattern that can never appear as a substring of any real mac,
# ip, or free-text field — used in place of an absent search term so a
# blank mac/ip never degrades to "LIKE '%%'" (which would match every
# row). Fixed SQL statements only (bandit B608) — never built with an
# f-string/join, even over these fixed values; only parameters vary.
_NEVER_MATCH = "\x00\x00\x00"


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


def _address_only(subject_is_mac: bool, mac: str, text: str):
    """For a free-text row (audit/alert) on a MAC timeline: `"address"` when the
    text does not name the MAC (it matched on the IP alone, so it may concern
    whoever held that address), else None."""
    if subject_is_mac and mac and mac not in text:
        return "address"
    return None


def build_timeline(mac: str = "", ip: str = "", limit: int = 300, accessible_v4_ids=None) -> dict:
    """`mac`/`ip` are already validated/normalized by the caller (lowercase
    mac, no colons stripped). At least one must be given. Returns
    `{"mac", "ip", "device", "lease", "reservation", "subnet_id", "rows"}`
    — `rows` is `[{"ts", "kind", "source", "detail", "subnet_id"}, ...]`
    newest-first, capped at `limit`.

    `accessible_v4_ids` is `None` for an unrestricted caller, else the set of
    v4 subnet ids the caller may see: a v6 address is then kept only when its
    v6 subnet is paired (`paired_subnet4_id`) to one of them — the Devices
    page's rule. The service stays Flask-free; the caller passes the set in."""
    mac = (mac or "").strip().lower()
    ip = (ip or "").strip()
    supplied_ip = ip
    # v5.49.0-beta.5 — who is this timeline ABOUT? A MAC subject is one client;
    # an IP subject is an address, whoever held it. This decides what the
    # address-matched rows below mean (recycled addresses).
    subject_is_mac = bool(mac)
    # `mac` stays the SUBJECT's MAC ('' for an IP subject). The current holder
    # of an address is looked up separately and used only to describe the
    # header (device, reservation) and to label earlier holders — never to
    # widen which rows are matched: an IP timeline is about the ADDRESS, so it
    # must not pull in the holder's activity on other addresses.
    holder_mac = __subject.mac_from_ip(ip) if (not mac and ip) else ""
    ctx_mac = mac or holder_mac

    device = __subject.load_device(ctx_mac)
    leases4 = __subject.load_leases4(mac, ip)
    lease = leases4[0] if leases4 else None
    reservations = __subject.load_reservations4(__subject.mac_hex(ctx_mac)) if ctx_mac else []
    reservation = reservations[0] if reservations else None
    if not ip and lease:
        ip = lease["ip"]
    elif not ip and device:
        ip = device.get("last_ip") or ""

    rows: list[dict] = []
    mac_hex = __subject.mac_hex(ctx_mac) if ctx_mac else ""

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
                    "SELECT ts, kind, mac, subnet_id, detail FROM events WHERE mac=%s OR ip=%s ORDER BY ts DESC LIMIT %s",
                    (mac, ip, limit),
                )
                for r in cur.fetchall():
                    ev_mac = (r["mac"] or "").lower()
                    related = previous = None
                    if subject_is_mac:
                        if ev_mac != mac:  # matched by ADDRESS only
                            if ev_mac:
                                continue  # another client's row: a recycled address
                            related = "address"  # no MAC of its own: kept, marked
                    elif holder_mac and ev_mac and ev_mac != holder_mac:
                        previous = ev_mac  # an IP timeline: an earlier holder
                    rows.append(
                        {
                            "ts": r["ts"],
                            "kind": r["kind"],
                            "source": "event",
                            "detail": r["detail"] or "",
                            "subnet_id": r["subnet_id"],
                            "mac": ev_mac or None,
                            "related": related,
                            "previous_holder": previous,
                        }
                    )

                cur.execute(
                    "SELECT created_at AS ts, action, entity, details, username FROM audit_log "
                    "WHERE entity LIKE %s OR details LIKE %s OR entity LIKE %s OR details LIKE %s "
                    "ORDER BY created_at DESC LIMIT %s",
                    (mac_pat, mac_pat, ip_pat, ip_pat, limit),
                )
                for r in cur.fetchall():
                    who = f" by {r['username']}" if r["username"] else ""
                    text = f"{r['entity'] or ''} {r['details'] or ''}".lower()
                    rows.append(
                        {
                            "ts": r["ts"],
                            "kind": f"audit.{r['action']}",
                            "source": "audit",
                            "detail": f"{r['details'] or ''}{who}",
                            "subnet_id": None,
                            "mac": None,
                            "related": _address_only(subject_is_mac, mac, text),
                            "previous_holder": None,
                        }
                    )

                cur.execute(
                    "SELECT sent_at AS ts, alert_type, channel_type, status, message FROM alert_log "
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
                            "mac": None,
                            "related": _address_only(subject_is_mac, mac, (r["message"] or "").lower()),
                            "previous_holder": None,
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
    # whole response on subnet_id_for()'s v4 subnet, and passes
    # accessible_v4_ids for a restricted caller (the v6-pairing rule now
    # lives in client_subject.load_leases6).
    v6_addresses = []
    if mac:
        try:
            v6_addresses = __subject.load_leases6(mac, accessible_v4_ids)
        except Exception as e:
            logger.error(f"timeline v6 address lookup failed for mac={mac!r}: {e}")

    subnet_id = subnet_id_for(device, lease, reservation)
    if accessible_v4_ids is not None:
        # A client that moved subnets: judge the device, the lease and the
        # reservation each on ITS OWN subnet (Q55/Q56's rule, now
        # client_subject.authorize(rule="per_object")), not all of them on
        # one "subject" subnet.
        subject = __subject.ClientSubject(
            kind="mac",
            device=device,
            leases4=[lease] if lease else [],
            reservations=[reservation] if reservation else [],
        )
        authorized = __subject.authorize(subject, rule="per_object", accessible_ids=accessible_v4_ids)
        device, lease, reservation = authorized.device, authorized.lease, authorized.reservation
        subnet_id = subnet_id_for(device, lease, reservation)
        if not supplied_ip:  # the IP was derived from an object that may now be hidden
            ip = (lease["ip"] if lease else "") or ((device or {}).get("last_ip") or "")

    return {
        "mac": ctx_mac,
        "ip": ip,
        "mac_hex": mac_hex,
        "device": device,
        "lease": lease,
        "reservation": reservation,
        "subnet_id": subnet_id,
        "rows": rows,
        "v6_addresses": v6_addresses,
    }
