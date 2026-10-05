"""
jen/services/client_problems.py
────────────────────────────────
v5.68.0-beta.5 (Q140) — the Problems inbox: "which clients had DHCP trouble lately?", answered without anyone starting from a MAC.

A scheduler job (every five minutes, jen.services.scheduler) does two things:

  * for every SSH-configured Kea server it tails kea-dhcp4's log through `kea_host.tail_log` (the helper's bounded `tail-log`, the
    last 1000 lines) and reads the problem lines with `kea_log_trace.problem_events` - nak, decline, drop, subnet-selection-failed,
    ddns-failed. Only lines NEWER than the last one counted for that server are added (a watermark in the settings table), so the
    same line read by two sweeps is one event. The DEBUG-only ids appear only while the server logs at DEBUG (Q138's investigation
    logging); at Kea's default INFO the NAK Kea sends is still there, as a DHCP4_PACKET_SEND line.
  * from the lease database, with no log at all: `declined-lease` (a lease4 row in state 1 that has not expired - Kea clears the
    declining client's hardware address, so this row is about an ADDRESS) and `reservation-held` (a reservation whose fixed address
    is leased to a different hardware address - Explain's "held" verdict, fleet-wide in one query over hosts x lease4). These are
    STATES, not events: a row's count stays 1 and it resolves at the first sweep that no longer finds it.

One row per (server, kind, client, address) in `client_problems` (migration 30). A row whose kind has not recurred for 24 hours is
marked resolved and leaves the inbox; resolved rows are kept 30 days. A sweep that cannot read a server records nothing for it
(Health Center's server rows already say why); log rotation between sweeps loses nothing already counted, but a server that writes
more than the tail's 1000 lines between two sweeps drops the oldest of them - the inbox is a lead, not a ledger.

The alert: when one client has had the same kind of trouble at least `[alerts] client_problem_threshold` times (3 by default) within
an hour of the newest line of that log, the `client_problems` alert fires - once per client and kind per 24 hours, whatever the
count, so a chattering client is one alert and not sixty. The alert carries the subnet id so a channel scoped to subnets filters it.

A row's `subnet_id` is where its ADDRESS is, else where its MAC is now (`client_subnet_for_mac`); a row with neither has none and,
like every unattributed row, is for callers who may see every subnet (docs/ARCHITECTURE.md §2).
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from jen import extensions
from jen.services import kea_host as _host
from jen.services import kea_log_trace as _klt

logger = logging.getLogger(__name__)

LOG_KINDS = _klt.LOG_PROBLEM_KINDS
DB_KINDS = ("declined-lease", "reservation-held")
ALL_KINDS = LOG_KINDS + DB_KINDS
DB_SERVER_ID = 0  # the two database kinds belong to no one server's log

KIND_LABELS = {
    "nak": "NAK",
    "decline": "Declined an address",
    "drop": "Packet dropped",
    "subnet-selection-failed": "No subnet matched",
    "ddns-failed": "DNS update failed",
    "declined-lease": "Declined lease",
    "reservation-held": "Reservation held by another client",
}
KIND_HELP = {
    "nak": "Kea answered the client's request with a DHCPNAK - it asked for an address it may not have.",
    "decline": "The client told Kea the address it was offered is already in use (DHCPDECLINE).",
    "drop": "Kea dropped the client's packet (DEBUG logging only).",
    "subnet-selection-failed": "Kea could not choose a subnet for the client's packet (DEBUG logging only).",
    "ddns-failed": "Kea could not hand the client's DNS update to kea-dhcp-ddns.",
    "declined-lease": "A lease Kea is holding out of service because a client declined it. Kea clears the client's hardware address, so this is about the address.",
    "reservation-held": "The client has a reservation for an address that is leased to a different client right now.",
}

TAIL_LINES = 1000
TAIL_TIMEOUT_S = 20
THRESHOLD_WINDOW = timedelta(hours=1)
ALERT_EVERY = timedelta(hours=24)
RESOLVE_AFTER = timedelta(hours=24)
KEEP_FOR = timedelta(days=30)
MAX_SUBNET_LOOKUPS = 100  # per sweep: one client_subnet_for_mac query each, for rows whose address names no subnet
MAX_DB_ROWS = 500

_lock = threading.Lock()


def _now() -> datetime:
    """Naive UTC, the way every datetime column of this table is stored."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Pure ─────────────────────────────────────────────────────────────────────────────────────────────────────────────


def threshold() -> int:
    try:
        return max(1, int(extensions.CLIENT_PROBLEM_THRESHOLD))
    except (TypeError, ValueError):
        return 3


def collect(events: list[dict], watermark: datetime | None, window: timedelta = THRESHOLD_WINDOW):
    """Pure: what a sweep adds from one server's `problem_events`. Returns `(groups, recent, new_watermark)`:

      groups  {(kind, mac, ip): {"new": events newer than the watermark, "last_ts", "detail"}}  - only groups with something new
      recent  {(kind, mac): events within `window` of the newest line}  - the count the alert threshold is judged on, across every
              address the client asked for, and including lines an earlier sweep already counted (the window is the log's, not
              the sweep's)
      new_watermark  the newest timestamp seen (never moves backwards)

    The watermark makes the same line, read by two sweeps, one event. A line with exactly the watermark's timestamp counts as
    already seen: the log's resolution is a millisecond and a sweep reads a finished file."""
    if not events:
        return {}, {}, watermark
    newest = max(e["ts"] for e in events)
    groups: dict = {}
    recent: dict = {}
    for e in events:
        if e["ts"] >= newest - window:
            recent[(e["kind"], e["mac"])] = recent.get((e["kind"], e["mac"]), 0) + 1
        if watermark is not None and e["ts"] <= watermark:
            continue
        g = groups.setdefault((e["kind"], e["mac"], e["ip"]), {"new": 0, "last_ts": e["ts"], "detail": e["detail"]})
        g["new"] += 1
        g["last_ts"], g["detail"] = e["ts"], e["detail"]
    new_watermark = newest if (watermark is None or newest > watermark) else watermark
    return groups, recent, new_watermark


def should_alert(recent: int, alerted_at: datetime | None, now: datetime, limit: int | None = None) -> bool:
    """Pure: the threshold is reached in the window, and this (client, kind) has not alerted in the last 24 hours."""
    if recent < (limit if limit is not None else threshold()):
        return False
    return alerted_at is None or (now - alerted_at) >= ALERT_EVERY


def from_declined(rows: list[dict]) -> list[dict]:
    """Pure: `lease4` rows in state 1 -> problem entries. The hardware address is usually empty (Kea clears it on a decline), in
    which case the entry is about the address alone."""
    out = []
    for r in rows:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        out.append(
            {
                "kind": "declined-lease",
                "mac": _klt.norm_mac(r.get("mac_hex") or ""),
                "ip": ip,
                "subnet_id": r.get("subnet_id") or None,
                "detail": f"{ip} was declined by a client and Kea is holding it out of service",
            }
        )
    return out


def from_held(rows: list[dict]) -> list[dict]:
    """Pure: reservation x lease rows -> problem entries, about the client the reservation is FOR (the one being kept out)."""
    out = []
    for r in rows:
        mac = _klt.norm_mac(r.get("res_mac_hex") or "")
        ip = (r.get("ip") or "").strip()
        if not mac or not ip:
            continue
        holder = _klt.norm_mac(r.get("holder_hex") or "")
        out.append(
            {
                "kind": "reservation-held",
                "mac": mac,
                "ip": ip,
                "subnet_id": r.get("subnet_id") or None,
                "detail": f"its reserved {ip} is leased to {holder or 'a different client'}",
            }
        )
    return out


def group_by_client(rows: list[dict]) -> list[dict]:
    """Pure: open problem rows (newest `last_seen` first) -> one entry per client, newest first:
    {who, mac, ip, kinds: [{kind, label, count, server_id, ip, detail, last_seen}], total, last_seen, first_seen, server_ids}.
    A client is its MAC; a row with no MAC (a declined lease) is its address."""
    clients: dict[str, dict] = {}
    for r in rows:
        who = r.get("mac") or r.get("ip") or ""
        if not who:
            continue
        c = clients.setdefault(
            who,
            {
                "who": who,
                "mac": r.get("mac") or "",
                "ip": r.get("ip") or "",
                "kinds": [],
                "total": 0,
                "last_seen": r["last_seen"],
                "first_seen": r["first_seen"],
                "server_ids": [],
            },
        )
        c["kinds"].append(
            {
                "kind": r["kind"],
                "label": KIND_LABELS.get(r["kind"], r["kind"]),
                "count": r["count"],
                "server_id": r["server_id"],
                "ip": r.get("ip") or "",
                "detail": r.get("detail") or "",
                "last_seen": r["last_seen"],
            }
        )
        c["total"] += r["count"]
        c["last_seen"] = max(c["last_seen"], r["last_seen"])
        c["first_seen"] = min(c["first_seen"], r["first_seen"])
        if r["server_id"] not in c["server_ids"]:
            c["server_ids"].append(r["server_id"])
        if not c["ip"] and r.get("ip"):
            c["ip"] = r["ip"]
    return sorted(clients.values(), key=lambda c: c["last_seen"], reverse=True)


def server_name(server_id) -> str:
    if server_id == DB_SERVER_ID:
        return "lease database"
    for s in extensions.KEA_SERVERS or []:
        if s.get("id") == server_id:
            return s.get("name") or s.get("ssh_host") or f"Server {server_id}"
    return f"Server {server_id}"


# ── Impure: the settings-table watermark and the two databases ─────────────────────────────────────────────────────────────


def _wm_key(server_id) -> str:
    return f"client_problems_wm:{server_id}"


def _wm_get(server_id) -> datetime | None:
    from jen.models import db as __db

    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (_wm_key(server_id),))
        row = cur.fetchone()
    if not row or not row.get("setting_value"):
        return None
    try:
        return datetime.fromisoformat(str(row["setting_value"]))
    except ValueError:
        return None


def _wm_set(server_id, value: datetime) -> None:
    from jen.models import db as __db

    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute(
            "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
            (_wm_key(server_id), value.isoformat()),
        )


def _declined_rows() -> list[dict]:
    from jen.models import db as __db

    with __db.kea_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT INET_NTOA(address) AS ip, HEX(hwaddr) AS mac_hex, subnet_id FROM lease4 "
            "WHERE state=1 AND expire > NOW() ORDER BY expire DESC LIMIT %s",
            (MAX_DB_ROWS,),
        )
        return list(cur.fetchall())


def _held_rows() -> list[dict]:
    from jen.models import db as __db

    with __db.kea_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT HEX(h.dhcp_identifier) AS res_mac_hex, INET_NTOA(h.ipv4_address) AS ip, h.dhcp4_subnet_id AS subnet_id, "
            "HEX(l.hwaddr) AS holder_hex FROM hosts h JOIN lease4 l ON l.address = h.ipv4_address "
            "WHERE h.dhcp_identifier_type=0 AND h.ipv4_address IS NOT NULL AND h.ipv4_address <> 0 "
            "AND l.state=0 AND l.expire > NOW() AND l.hwaddr <> h.dhcp_identifier LIMIT %s",
            (MAX_DB_ROWS,),
        )
        return list(cur.fetchall())


class _SubnetResolver:
    """Where a problem's client is: its address's subnet, else its MAC's current subnet (a bounded number of lookups a sweep)."""

    def __init__(self):
        self._by_mac: dict[str, int | None] = {}
        self._lookups = 0

    def __call__(self, ip: str, mac: str) -> int | None:
        from jen.services import client_subject as _cs

        if ip:
            sid = _cs.subnet_for_ip(ip)
            if sid is not None:
                return sid
        if not mac:
            return None
        if mac not in self._by_mac:
            if self._lookups >= MAX_SUBNET_LOOKUPS:
                return None
            self._lookups += 1
            self._by_mac[mac] = _cs.client_subnet_for_mac(mac)
        return self._by_mac[mac]


_UPSERT_LOG = (
    "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, first_seen, last_seen, `count`, detail) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE "
    "`count` = IF(resolved_at IS NULL, `count` + VALUES(`count`), VALUES(`count`)), "
    "first_seen = IF(resolved_at IS NULL, first_seen, VALUES(first_seen)), "
    "alerted_at = IF(resolved_at IS NULL, alerted_at, NULL), "
    "subnet_id = COALESCE(VALUES(subnet_id), subnet_id), "
    "detail = VALUES(detail), last_seen = VALUES(last_seen), resolved_at = NULL"
)  # resolved_at LAST: the assignments above read its old value, and MySQL applies them left to right

_UPSERT_STATE = (
    "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, first_seen, last_seen, `count`, detail) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s) "
    "ON DUPLICATE KEY UPDATE "
    "first_seen = IF(resolved_at IS NULL, first_seen, VALUES(first_seen)), "
    "alerted_at = IF(resolved_at IS NULL, alerted_at, NULL), "
    "subnet_id = COALESCE(VALUES(subnet_id), subnet_id), "
    "detail = VALUES(detail), last_seen = VALUES(last_seen), `count` = 1, resolved_at = NULL"
)


def _send_alert(server_id, kind, mac, ip, subnet_id, recent) -> None:
    from jen.services import alerts as _alerts

    who = mac or ip
    _alerts.send_alert(
        "client_problems",
        subnet_id=subnet_id,
        mac=mac,
        ip=ip,
        kind=KIND_LABELS.get(kind, kind),
        count=recent,
        server=_alerts.safe_text(server_name(server_id)),
        investigate=f"/client?q={who}",
    )


def sweep(now: datetime | None = None, servers: list[dict] | None = None) -> dict:
    """One pass. Returns {"servers": scanned, "events": new events upserted, "state_rows": database-kind rows seen, "alerts": sent,
    "resolved": rows resolved, "pruned": rows deleted, "errors": [text]}. A server that cannot be read adds an error and nothing
    else; one server's failure never stops the next."""
    from jen.models import db as __db

    now = now or _now()
    summary = {"servers": 0, "events": 0, "state_rows": 0, "alerts": 0, "resolved": 0, "pruned": 0, "errors": []}
    with _lock:
        resolver = _SubnetResolver()
        if servers is None:
            servers = [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]
        for server in servers:
            sid = server.get("id")
            try:
                res = _host.tail_log(server, extensions.DHCP4_LOG, TAIL_LINES, timeout=TAIL_TIMEOUT_S, helper_only=True)
                if not res.get("ok"):
                    summary["errors"].append(f"{server.get('name')}: {res.get('code') or 'error'}")
                    continue
                groups, recent, new_wm = collect(_klt.problem_events(res.get("lines", [])), _wm_get(sid))
                alerts_due = []
                with __db.jen_db() as db, db.cursor() as cur:
                    for (kind, mac, ip), g in groups.items():
                        subnet_id = resolver(ip, mac)
                        cur.execute(
                            _UPSERT_LOG, (sid, kind, mac, ip, subnet_id, now, now, g["new"], (g["detail"] or "")[:255])
                        )
                        summary["events"] += g["new"]
                    for kind, mac in {(k, m) for (k, m, _ip) in groups}:
                        if recent.get((kind, mac), 0) < threshold():
                            continue
                        cur.execute(
                            "SELECT ip, subnet_id, alerted_at FROM client_problems WHERE server_id=%s AND kind=%s AND mac=%s "
                            "AND resolved_at IS NULL ORDER BY last_seen DESC",
                            (sid, kind, mac),
                        )
                        rows = cur.fetchall()
                        if not rows or any(
                            r["alerted_at"] is not None and (now - r["alerted_at"]) < ALERT_EVERY for r in rows
                        ):
                            continue
                        alerts_due.append((kind, mac, rows[0]["ip"], rows[0]["subnet_id"], recent[(kind, mac)]))
                for (
                    kind,
                    mac,
                    ip,
                    subnet_id,
                    count,
                ) in alerts_due:  # the network I/O after the connection is back in the pool
                    try:
                        _send_alert(sid, kind, mac, ip, subnet_id, count)
                    except Exception as e:
                        logger.error(f"client_problems: alert failed: {type(e).__name__}: {e}")
                    with __db.jen_db() as db, db.cursor() as cur:
                        cur.execute(
                            "UPDATE client_problems SET alerted_at=%s WHERE server_id=%s AND kind=%s AND mac=%s "
                            "AND resolved_at IS NULL",
                            (now, sid, kind, mac),
                        )
                    summary["alerts"] += 1
                if new_wm is not None:
                    _wm_set(sid, new_wm)
                summary["servers"] += 1
            except Exception as e:
                logger.error(f"client_problems: server {server.get('name')!r}: {type(e).__name__}: {e}")
                summary["errors"].append(f"{server.get('name')}: {type(e).__name__}")
        try:
            state = from_declined(_declined_rows()) + from_held(_held_rows())
            with __db.jen_db() as db, db.cursor() as cur:
                for p in state:
                    subnet_id = p["subnet_id"] or resolver(p["ip"], p["mac"])
                    cur.execute(
                        _UPSERT_STATE,
                        (DB_SERVER_ID, p["kind"], p["mac"], p["ip"], subnet_id, now, now, p["detail"][:255]),
                    )
                # a state that is no longer there is resolved at once - it is a fact about now, not an event that may recur
                marks = ",".join(["%s"] * len(DB_KINDS))
                cur.execute(
                    f"UPDATE client_problems SET resolved_at=%s WHERE server_id=%s AND kind IN ({marks}) "  # nosec B608 - %s placeholders only
                    "AND resolved_at IS NULL AND last_seen < %s",
                    (now, DB_SERVER_ID, *DB_KINDS, now),
                )
            summary["state_rows"] = len(state)
        except Exception as e:
            logger.error(f"client_problems: lease database kinds: {type(e).__name__}: {e}")
            summary["errors"].append(f"lease database: {type(e).__name__}")
        try:
            with __db.jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "UPDATE client_problems SET resolved_at=%s WHERE resolved_at IS NULL AND last_seen < %s",
                    (now, now - RESOLVE_AFTER),
                )
                summary["resolved"] = cur.rowcount
        except Exception as e:
            logger.error(f"client_problems: resolve: {type(e).__name__}: {e}")
    return summary


def prune(now: datetime | None = None) -> int:
    """Delete rows not seen for 30 days (resolved or not). Called from the daily audit cleanup, whatever its retention."""
    from jen.models import db as __db

    now = now or _now()
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM client_problems WHERE last_seen < %s", (now - KEEP_FOR,))
        return cur.rowcount


def run_sweep_job() -> dict:
    return sweep()


# ── Reads for the page and the dashboard widget ─────────────────────────────────────────────────────────────────────────────


def fetch_open(where: list[str], params: list, limit: int = 500) -> list[dict]:
    """Open (unresolved) rows, newest `last_seen` first, restricted by the caller's own clauses on alias `p`
    (`add_subnet_restriction(where, params, "p", "subnet_id")` - an unattributed row never matches a restricted caller)."""
    from jen.models import db as __db

    clauses = ["p.resolved_at IS NULL", *where]
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT p.id, p.server_id, p.kind, p.mac, p.ip, p.subnet_id, p.first_seen, p.last_seen, p.`count`, p.detail "  # nosec B608 - fixed clauses; values bound
            f"FROM client_problems p WHERE {' AND '.join(clauses)} ORDER BY p.last_seen DESC LIMIT %s",
            (*params, limit),
        )
        return list(cur.fetchall())


def widget(accessible_subnet_ids, all_subnets: bool, now: datetime | None = None) -> dict:
    """The dashboard's "Clients with problems": distinct clients that had trouble in the last hour, counted by kind, and the five
    most recent. A restricted caller sees only rows in their own subnets; an unattributed row is for callers who see every one."""
    now = now or _now()
    where: list[str] = ["p.last_seen >= %s"]
    params: list = [now - timedelta(hours=1)]
    if not all_subnets:
        ids = sorted(int(i) for i in (accessible_subnet_ids or []))
        if not ids:
            return {"hours": 1, "total": 0, "counts": {}, "top": []}
        where.append(f"p.subnet_id IN ({','.join(['%s'] * len(ids))})")
        params.extend(ids)
    rows = fetch_open(where, params, limit=500)
    clients = group_by_client(rows)
    counts: dict[str, int] = {}
    for c in clients:
        for kind in {k["kind"] for k in c["kinds"]}:
            counts[kind] = counts.get(kind, 0) + 1
    top = [
        {
            "who": c["who"],
            "mac": c["mac"],
            "ip": c["ip"],
            "kinds": sorted({k["label"] for k in c["kinds"]}),
            "count": c["total"],
            "last_seen": c["last_seen"].isoformat() if hasattr(c["last_seen"], "isoformat") else str(c["last_seen"]),
        }
        for c in clients[:5]
    ]
    return {
        "hours": 1,
        "total": len(clients),
        "counts": {KIND_LABELS.get(k, k): n for k, n in sorted(counts.items(), key=lambda kv: -kv[1])},
        "top": top,
    }
