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
the last hour, the `client_problems` alert fires - once per client and kind per 24 hours, whatever the count, so a chattering client is
one alert and not sixty. The alert carries the subnet id so a channel scoped to subnets filters it; one with NO subnet (a client Jen
could not place) fails closed for a scoped channel (jen.services.alerts.SCOPED_ALERT_TYPES).

A row's `subnet_id` is where the event itself says: the subnet its ADDRESS is in, else the subnet Kea selected for the very transaction
(DEBUG logging only), else none - NEVER where the client is now, which would show a NAK from subnet B to a user of subnet A once
the client moved there. A row with no subnet is, like every unattributed row, for callers who may see every subnet
(docs/ARCHITECTURE.md §2). The newest event of a row decides its subnet.

TIME (v5.68.0-beta.9, Q144). `first_seen` / `last_seen` are the events' OWN timestamps, not the sweep's clock, so a first sweep that
reads a six-hour-old tail records six-hour-old problems. Kea writes its log in the HOST's local time; the sweep converts it to UTC with
an offset it measures from the lease database (the newest allocation lines of the tail against the lease rows' `expire`, to the nearest
quarter hour), remembers per server, and assumes zero for a server that has shown it nothing yet - the Problems page says which. The
alert window is judged against NOW, never against the newest line, and the first sweep on a server sets its watermark and records what
it reads but never alerts: a backlog is not news. The watermark stays in the log's own clock.

DELIVERED vs ATTEMPTED. `alerted_at` is set only when a channel actually took the alert; `alert_attempted_at` (migration 31) records
every try, and a failing alert is retried once per 30 minutes until it lands.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from jen import extensions
from jen.services import kea_host as _host
from jen.services import kea_log_trace as _klt
from jen.services.leases_sql import active_lease4

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
ALERT_RETRY_EVERY = timedelta(minutes=30)  # a failing alert is tried again this often, not every sweep
QUALIFICATION_KEEP = timedelta(
    hours=24
)  # an undelivered alert's persisted qualification is dropped after this (v5.68.0-beta.13, Q148)
CLOCK_STEP_S = 900  # a host's timezone offset is a multiple of a quarter hour
RESOLVE_AFTER = timedelta(hours=24)
KEEP_FOR = timedelta(days=30)
MAX_CLOCK_LEASES = 20  # lease rows read per sweep to learn a host's clock offset
MAX_DB_ROWS = 500
#: v5.68.0-beta.21 (Q156): at most this many NEW (kind, client, address, subnet) keys are recorded per server per sweep. A group is keyed by all four, so
#: a thousand-line tail of NAKs from spoofed MACs and requested addresses added up to a thousand rows every five minutes, kept for 30 days;
#: `MAX_DB_ROWS` bounds only the two lease-database kinds. Keys that already exist always update; the newest new ones are kept and the rest are COUNTED
#: (`summary["dropped_keys"]`, logged once per sweep, shown by the Problems sweep Health row).
MAX_NEW_KEYS_PER_SWEEP = 200

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


def collect(
    events: list[dict],
    watermark: datetime | None,
    window: timedelta = THRESHOLD_WINDOW,
    now: datetime | None = None,
    subnet_of=None,
):
    """Pure: what a sweep adds from one server's `problem_events`. Returns `(groups, recent, new_watermark)`:

      groups  {(kind, mac, ip, subnet_id): {"new": events newer than the watermark, "first_ts", "last_ts", "detail", "subnet_id"}}  - only
              groups with something new; the timestamps are the events' OWN (`uts`, UTC, when the sweep converted them; else `ts`). The
              subnet is part of the key (v5.68.0-beta.14, Q149): it is part of a stored row's identity, so events in different subnets are
              different groups even when the client and the address (often none) are the same, and a row never changes subnet
      recent  {(kind, mac, subnet_id): events within `window` of `now`}  - the count the alert threshold is judged on, per client AND
              subnet (None is a key of its own: "no attributable subnet"), across every address the client asked for in that subnet,
              and including lines an earlier sweep already counted. The page shows a user only the rows in subnets they may see, so
              the count an alert reports for them must be made of those rows alone (v5.68.0-beta.13, Q148: it used to be
              per client across every subnet, so two NAKs in a hidden subnet plus one in the caller's read as three). `subnet_of(event)`
              says where an event happened (the sweep passes `event_subnet`); the default is the event's own `subnet_id`.
              `now=None` anchors the window at the newest event instead (the pure tests); the sweep always passes the real now
      new_watermark  the newest LOG timestamp seen (never moves backwards): the watermark is in the log's own clock, `ts`

    The watermark makes the same line, read by two sweeps, one event. A line with exactly the watermark's timestamp counts as
    already seen: the log's resolution is a millisecond and a sweep reads a finished file."""
    if not events:
        return {}, {}, watermark
    newest = max(e["ts"] for e in events)

    def when(e):
        return e.get("uts", e["ts"])

    anchor = now if now is not None else max(when(e) for e in events)
    where = subnet_of or (lambda event: event.get("subnet_id"))
    groups: dict = {}
    recent: dict = {}
    for e in events:
        if when(e) >= anchor - window:
            key = (e["kind"], e["mac"], where(e))
            recent[key] = recent.get(key, 0) + 1
        if watermark is not None and e["ts"] <= watermark:
            continue
        subnet = where(e)
        g = groups.setdefault(
            (e["kind"], e["mac"], e["ip"], subnet),
            {"new": 0, "first_ts": when(e), "last_ts": when(e), "detail": e["detail"], "subnet_id": subnet},
        )
        g["new"] += 1
        g["first_ts"] = min(g["first_ts"], when(e))
        if when(e) >= g["last_ts"]:
            g["last_ts"], g["detail"] = when(e), e["detail"]
    new_watermark = newest if (watermark is None or newest > watermark) else watermark
    return groups, recent, new_watermark


def shift_events(events: list[dict], offset_s: float, now: datetime) -> list[dict]:
    """Pure: each event gains `uts`, its log timestamp converted to UTC (`ts` minus the host's clock offset, never later than `now`:
    a timestamp from the future is a clock the offset has not caught up with, not an event that has not happened yet)."""
    delta = timedelta(seconds=offset_s)
    return [{**e, "uts": min(e["ts"] - delta, now)} for e in events]


def clock_offset(allocs: list[dict], expiries: dict) -> float | None:
    """Pure: the Kea host's log-clock offset from UTC, in seconds, to the nearest quarter hour - or None when the evidence does not
    settle it. `allocs` are `kea_log_trace.allocations()` ({ts, ip, seconds}, log order); `expiries` maps an address to the lease row's
    `expire` as a naive UTC datetime. A lease allocated at log time T for N seconds expires at T + N in UTC, so `T - (expire - N)` IS the
    offset - as long as the row was not renewed after the tail ended, which is why only the NEWEST allocation of each address counts and
    why one measurement alone is trusted only when it lands within 90 s of a quarter hour; two that agree are enough."""
    newest: dict = {}
    for a in allocs:
        newest[a["ip"]] = a
    steps: dict[float, int] = {}
    singles: list[tuple[float, float]] = []
    for ip, a in newest.items():
        expire = expiries.get(ip)
        if expire is None:
            continue
        d = (a["ts"] - (expire - timedelta(seconds=a["seconds"]))).total_seconds()
        step = float(round(d / CLOCK_STEP_S) * CLOCK_STEP_S)
        steps[step] = steps.get(step, 0) + 1
        singles.append((step, abs(d - step)))
    if not steps:
        return None
    best, count = max(steps.items(), key=lambda kv: (kv[1], -abs(kv[0])))
    if count >= 2:
        return best
    return best if len(singles) == 1 and singles[0][1] <= 90 else None


def describe_offset(offset_s: float | None, source: str) -> str:
    """Pure: "UTC-5 (from the lease records)" / "assumed UTC" for the page's hover."""
    if offset_s is None or (source == "assumed" and not offset_s):
        return "assumed UTC (no lease records to measure it against yet)"
    sign = "+" if offset_s >= 0 else "-"
    minutes = int(abs(offset_s) // 60)
    hhmm = f"{minutes // 60}" + (f":{minutes % 60:02d}" if minutes % 60 else "")
    return f"UTC{sign}{hhmm} (from the lease records)"


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


# ── The sweep's own record of whether it is reading each server (v5.68.0-beta.17, Q152) ──────────────────────────────────────
# A server whose log could not be read added a line to the sweep's summary, which the scheduler logged and nobody reads: the inbox
# stayed quiet because it was blind, indistinguishable from a quiet network. The sweep now keeps, per SSH-configured server, the time
# of its last successful read, the text of its last error and the number of reads missed in a row, and the time the sweep last ran -
# all in the settings table beside the watermark - and the Health Center's "Problems inbox sweep" row reads them (never SSH).

SWEEP_INTERVAL_S = 300  # scheduler.py runs the sweep every five minutes
MISS_LIMIT = 6  # six misses in a row = thirty minutes without reading a server's log: the Health row goes red
_SWEPT_KEY = "client_problems_swept"
_DROPPED_KEY = "client_problems_dropped"


def _cap_new_keys(cur, server_id, groups: dict, limit: int = MAX_NEW_KEYS_PER_SWEEP) -> tuple[dict, int]:
    """(groups to record, number of NEW groups dropped). A group whose (kind, mac, ip, subnet) already has a row for this server is never dropped; of
    the new ones the `limit` with the newest `last_ts` are kept."""
    macs = sorted({key[1] for key in groups if key[1]})
    existing = set()
    for i in range(0, len(macs), 500):
        chunk = macs[i : i + 500]
        marks = ",".join(["%s"] * len(chunk))
        cur.execute(
            f"SELECT kind, mac, ip, scope_key FROM client_problems WHERE server_id=%s AND mac IN ({marks})",  # nosec B608 - %s placeholders only
            (server_id, *chunk),
        )
        existing |= {(r["kind"], r["mac"], r["ip"], r["scope_key"]) for r in cur.fetchall()}
    new = [k for k in groups if (k[0], k[1], k[2], -1 if k[3] is None else k[3]) not in existing]
    if len(new) <= limit:
        return groups, 0
    new.sort(key=lambda k: groups[k]["last_ts"], reverse=True)
    dropped = set(new[limit:])
    return {k: g for k, g in groups.items() if k not in dropped}, len(dropped)


_SERVER_KEY_PREFIXES = (
    "client_problems_wm:",
    "client_problems_read:",
    "client_problems_err:",
    "client_problems_miss:",
    "client_problems_clock:",
)


def _clear_orphan_server_keys() -> int:
    """Delete the per-server settings keys (watermark, last read, last error, misses, clock offset) of a server id that is no longer in `KEA_SERVERS`
    (v5.68.0-beta.21, Q156): a removed server left them behind for ever, loaded on every settings reload. v5.68.0-beta.22 (Q157): the guard that
    cleared nothing for an EMPTY server list is gone - `KEA_SERVERS` is the last APPLIED config, so empty means the last server was removed; the
    gate is whether a config has been applied at all (`extensions.cfg`). Never raises."""
    from jen.models import db as __db

    if getattr(extensions, "cfg", None) is None:
        return 0
    live = {str(srv.get("id")) for srv in extensions.KEA_SERVERS or []}
    removed = 0
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            for prefix in _SERVER_KEY_PREFIXES:
                cur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE %s", (prefix + "%",))
                stale = [
                    r["setting_key"]
                    for r in cur.fetchall()
                    if r["setting_key"].startswith(prefix) and r["setting_key"][len(prefix) :] not in live
                ]
                for key in stale:
                    cur.execute("DELETE FROM settings WHERE setting_key=%s", (key,))
                removed += len(stale)
        if removed:
            from jen.models.user import _invalidate_settings_cache

            _invalidate_settings_cache()
            logger.info(f"client_problems: cleared {removed} setting key(s) of servers that are no longer configured")
    except Exception as e:
        logger.error(f"client_problems: orphan key cleanup failed: {type(e).__name__}: {e}")
    return removed


def _note_dropped(now: datetime, dropped: int) -> None:
    """Record how many new keys the LAST sweep refused (0 clears it). Never raises."""
    from jen.models import db as __db

    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
                (_DROPPED_KEY, str(int(dropped))),
            )
    except Exception as e:
        logger.error(f"client_problems: could not record the dropped-key count: {type(e).__name__}: {e}")


def _note_server(server_id, ok: bool, error: str, now: datetime) -> None:
    """Record one read attempt. Never raises: bookkeeping must not break the sweep it describes."""
    from jen.models import db as __db

    try:
        with __db.jen_db() as db, db.cursor() as cur:
            upsert = (
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)"
            )
            if ok:
                cur.execute(upsert, (f"client_problems_read:{server_id}", now.isoformat()))
                cur.execute(upsert, (f"client_problems_err:{server_id}", ""))
                cur.execute(upsert, (f"client_problems_miss:{server_id}", "0"))
            else:
                cur.execute(upsert, (f"client_problems_err:{server_id}", (error or "error")[:200]))
                cur.execute(
                    "INSERT INTO settings (setting_key, setting_value) VALUES (%s, '1') "
                    "ON DUPLICATE KEY UPDATE setting_value=CAST(setting_value AS UNSIGNED)+1",
                    (f"client_problems_miss:{server_id}",),
                )
    except Exception as e:
        logger.error(f"client_problems: could not record the read of server {server_id}: {type(e).__name__}: {e}")


def _note_swept(now: datetime) -> None:
    from jen.models import db as __db

    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
                (_SWEPT_KEY, now.isoformat()),
            )
    except Exception as e:
        logger.error(f"client_problems: could not record the sweep time: {type(e).__name__}: {e}")


def read_status(servers: list[dict] | None = None) -> dict:
    """What the sweep has recorded: {"swept_at": datetime | None, "servers": [{"id", "name", "last_read": datetime | None,
    "last_error": str, "misses": int}]} for every SSH-configured server (or the given list). Reads the settings table directly (the
    cached reader could be 30 s behind). The Health Center's row is built from this."""
    from jen.models import db as __db

    if servers is None:
        servers = [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE %s", ("client_problems_%",))
        values = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

    def when(raw):
        try:
            return datetime.fromisoformat(str(raw)) if raw else None
        except ValueError:
            return None

    out = []
    for s in servers:
        sid = s.get("id")
        try:
            misses = int(values.get(f"client_problems_miss:{sid}") or 0)
        except ValueError:
            misses = 0
        out.append(
            {
                "id": sid,
                "name": s.get("name") or s.get("ssh_host") or f"Server {sid}",
                "last_read": when(values.get(f"client_problems_read:{sid}")),
                "last_error": values.get(f"client_problems_err:{sid}") or "",
                "misses": misses,
            }
        )
    try:
        dropped = int(values.get(_DROPPED_KEY) or 0)
    except ValueError:
        dropped = 0
    return {"swept_at": when(values.get(_SWEPT_KEY)), "servers": out, "dropped": dropped}


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
            f"AND {active_lease4('l')} AND l.hwaddr <> h.dhcp_identifier LIMIT %s",  # nosec B608 - a fixed constant
            (MAX_DB_ROWS,),
        )
        return list(cur.fetchall())


def event_subnet(ip: str, selected: int | None) -> int | None:
    """Where a problem EVENT happened, by the event's own evidence only: the subnet its address is in, else the subnet Kea selected for
    the very transaction (DEBUG logging), else None. Never where the client is now (v5.68.0-beta.9, Q144): a NAK from subnet B must not
    follow the client into subnet A."""
    from jen.services import client_subject as _cs

    if ip:
        sid = _cs.subnet_for_ip(ip)
        if sid is not None:
            return sid
    return selected if selected is not None else None


def _lease_expiries(ips: list[str]) -> dict:
    """{ip: lease row's `expire` as naive UTC} for up to MAX_CLOCK_LEASES addresses (the clock-offset measurement)."""
    import ipaddress

    from jen.models import db as __db

    wanted = []
    for ip in ips[:MAX_CLOCK_LEASES]:
        try:
            wanted.append(int(ipaddress.IPv4Address(ip)))
        except ValueError:
            continue
    if not wanted:
        return {}
    marks = ",".join(["%s"] * len(wanted))
    with __db.kea_db() as db, db.cursor() as cur:
        cur.execute(
            f"SELECT INET_NTOA(address) AS ip, UNIX_TIMESTAMP(expire) AS ts FROM lease4 WHERE address IN ({marks})",  # nosec B608 - %s placeholders only
            tuple(wanted),
        )
        return {
            r["ip"]: datetime.fromtimestamp(float(r["ts"]), timezone.utc).replace(tzinfo=None)
            for r in cur.fetchall()
            if r.get("ts") is not None
        }


def _clock_key(server_id) -> str:
    return f"client_problems_clock:{server_id}"


def _clock_get(server_id) -> float | None:
    from jen.models import db as __db

    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (_clock_key(server_id),))
        row = cur.fetchone()
    try:
        return float(row["setting_value"]) if row and row.get("setting_value") not in (None, "") else None
    except ValueError:
        return None


def _clock_set(server_id, value: float) -> None:
    from jen.models import db as __db

    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute(
            "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
            (_clock_key(server_id), str(value)),
        )


def server_clock(server_id, lines: list[str]) -> tuple[float, str]:
    """(offset in seconds, source) for one server this sweep: measured from the lease records when the tail settles it (and then
    remembered), else the last measurement, else zero - "assumed". Never raises: a failed measurement is zero or the last good one."""
    from jen.services import kea_log_trace as _k

    stored = None
    try:
        stored = _clock_get(server_id)
        allocs = _k.allocations(lines)[-200:]
        ips = list(dict.fromkeys(a["ip"] for a in reversed(allocs)))[:MAX_CLOCK_LEASES]
        measured = clock_offset(allocs, _lease_expiries(ips)) if ips else None
    except Exception as e:
        logger.warning(f"client_problems: could not measure the clock of server {server_id}: {type(e).__name__}")
        measured = None
    if measured is not None:
        if measured != stored:
            try:
                _clock_set(server_id, measured)
            except Exception as e:
                logger.warning(
                    f"client_problems: could not remember the clock of server {server_id}: {type(e).__name__}"
                )
        return measured, "measured"
    if stored is not None:
        return stored, "measured"
    return 0.0, "assumed"


def clock_notes() -> list[dict]:
    """For the Problems page's hover: [{name, text}] per SSH server - what offset its log times were converted with."""
    out = []
    for s in extensions.KEA_SERVERS or []:
        if not s.get("ssh_host"):
            continue
        try:
            stored = _clock_get(s.get("id"))
        except Exception:
            stored = None
        out.append(
            {
                "name": s.get("name") or s.get("ssh_host"),
                "text": describe_offset(stored, "measured" if stored is not None else "assumed"),
            }
        )
    return out


_UPSERT_LOG = (
    "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, scope_key, first_seen, last_seen, `count`, detail) "
    "VALUES (%s, %s, %s, %s, %s, COALESCE(%s, -1), %s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE "
    "`count` = IF(resolved_at IS NULL, `count` + VALUES(`count`), VALUES(`count`)), "
    "first_seen = IF(resolved_at IS NULL, first_seen, VALUES(first_seen)), "
    "alerted_at = IF(resolved_at IS NULL, alerted_at, NULL), "
    "alert_attempted_at = IF(resolved_at IS NULL, alert_attempted_at, NULL), "
    "qualified_at = IF(resolved_at IS NULL, qualified_at, NULL), "
    "qualified_count = IF(resolved_at IS NULL, qualified_count, NULL), "
    "detail = VALUES(detail), last_seen = GREATEST(last_seen, VALUES(last_seen)), resolved_at = NULL"
)  # resolved_at LAST: the assignments above read its old value, and MySQL applies them left to right
# The subnet is NOT assigned on duplicate (v5.68.0-beta.14, Q149): it is part of the unique key (`scope_key` = COALESCE(subnet_id, -1)), so a
# row's subnet never changes and an event in another subnet - or none - is another row, with its own count, times and alert state.
# (Q144 had the newest event reassign it, which carried one subnet's history and qualification onto another subnet's row.)

_UPSERT_STATE = (
    "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, scope_key, first_seen, last_seen, `count`, detail) "
    "VALUES (%s, %s, %s, %s, %s, COALESCE(%s, -1), %s, %s, 1, %s) "
    "ON DUPLICATE KEY UPDATE "
    "first_seen = IF(resolved_at IS NULL, first_seen, VALUES(first_seen)), "
    "alerted_at = IF(resolved_at IS NULL, alerted_at, NULL), "
    "alert_attempted_at = IF(resolved_at IS NULL, alert_attempted_at, NULL), "
    "qualified_at = IF(resolved_at IS NULL, qualified_at, NULL), "
    "qualified_count = IF(resolved_at IS NULL, qualified_count, NULL), "
    "detail = VALUES(detail), last_seen = VALUES(last_seen), `count` = 1, resolved_at = NULL"
)


def _send_alert(server_id, kind, mac, ip, subnet_id, recent, qualified_at=None) -> list:
    """Send the alert and return what each ELIGIBLE channel answered: [(channel_type, ok, error)] - empty when no channel was eligible.
    `recent` and `qualified_at` are the PERSISTED qualification (the count when the key first crossed the threshold, and when), so a
    retry says what the first attempt would have said."""
    from jen.services import alerts as _alerts

    who = mac or ip
    return _alerts.send_alert(
        "client_problems",
        subnet_id=subnet_id,
        mac=mac,
        ip=ip,
        kind=KIND_LABELS.get(kind, kind),
        count=recent,
        at=(qualified_at or _now()).strftime("%Y-%m-%d %H:%M"),
        server=_alerts.safe_text(server_name(server_id)),
        investigate=f"/client?q={who}",
    )


def sweep(now: datetime | None = None, servers: list[dict] | None = None) -> dict:
    """One pass. Returns {"servers": scanned, "events": new events upserted, "state_rows": database-kind rows seen, "alerts": DELIVERED,
    "alerts_attempted": tried, "alerts_failed": tried and not delivered, "resolved": rows resolved, "pruned": rows deleted,
    "errors": [text]}. A server that cannot be read adds an error and nothing else; one server's failure never stops the next."""
    from jen.models import db as __db

    now = now or _now()
    summary = {
        "servers": 0,
        "events": 0,
        "state_rows": 0,
        "alerts": 0,
        "alerts_attempted": 0,
        "alerts_failed": 0,
        "resolved": 0,
        "pruned": 0,
        "dropped_keys": 0,
        "errors": [],
    }
    with _lock:
        if servers is None:
            servers = [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]
        for server in servers:
            sid = server.get("id")
            try:
                res = _host.tail_log(server, extensions.DHCP4_LOG, TAIL_LINES, timeout=TAIL_TIMEOUT_S, helper_only=True)
                if not res.get("ok"):
                    summary["errors"].append(f"{server.get('name')}: {res.get('code') or 'error'}")
                    _note_server(sid, False, str(res.get("code") or "error"), now)
                    continue
                wm = _wm_get(sid)
                lines = res.get("lines", [])
                offset_s, _how = server_clock(sid, lines)
                # the events' OWN times, in UTC; anything older than a day is history the inbox would resolve at once
                everything = shift_events(_klt.problem_events(lines), offset_s, now)
                events = [e for e in everything if e["uts"] >= now - RESOLVE_AFTER]
                subnets: dict = {}

                def subnet_of(e, subnets=subnets):
                    k = (e["ip"], e.get("subnet_id"))
                    if k not in subnets:
                        subnets[k] = event_subnet(*k)
                    return subnets[k]

                groups, recent, new_wm = collect(events, wm, now=now, subnet_of=subnet_of)
                if wm is None:
                    # the first read sets the watermark from EVERYTHING it saw (old events and ordinary lines too), so the sweep after it
                    # is a normal one and its alerts are not suppressed for want of a mark
                    seen = [e["ts"] for e in everything]
                    newest_line = _klt.newest_ts(lines)
                    if newest_line is not None:
                        seen.append(newest_line)
                    if seen:
                        new_wm = max([*seen, *([new_wm] if new_wm is not None else [])])
                first_sweep = wm is None  # a server's first read sets the watermark and records; a backlog is not news
                alerts_due = []
                with __db.jen_db() as db, db.cursor() as cur:
                    groups, dropped = _cap_new_keys(cur, sid, groups)
                    summary["dropped_keys"] += dropped
                    for (kind, mac, ip, subnet_id), g in groups.items():
                        cur.execute(
                            _UPSERT_LOG,
                            (
                                sid,
                                kind,
                                mac,
                                ip,
                                subnet_id,
                                subnet_id,
                                g["first_ts"],
                                g["last_ts"],
                                g["new"],
                                (g["detail"] or "")[:255],
                            ),
                        )
                        summary["events"] += g["new"]
                    # The alert is decided per (kind, client, SUBNET) - None is a subnet of its own - from the rows in that subnet
                    # alone (v5.68.0-beta.13, Q148), because a channel scoped to a subnet is only ever told about rows it could see on the
                    # page. A key with something new is considered, and so is one whose alert FAILED to land or whose qualification is
                    # still waiting for delivery: it is retried (bounded below) from the PERSISTED qualification, without waiting for the
                    # client to have more trouble and without needing the qualifying lines to still be in the 1000-line tail.
                    keys = {(k, m, s) for (k, m, _ip, s) in groups}
                    cur.execute(
                        "SELECT kind, mac, subnet_id FROM client_problems WHERE server_id=%s AND resolved_at IS NULL "
                        "AND alerted_at IS NULL AND (alert_attempted_at IS NOT NULL OR qualified_at IS NOT NULL)",
                        (sid,),
                    )
                    keys |= {(r["kind"], r["mac"], r["subnet_id"]) for r in cur.fetchall()}
                    for kind, mac, subnet in keys:
                        cur.execute(
                            "SELECT ip, alerted_at, alert_attempted_at, qualified_at, qualified_count FROM client_problems "
                            "WHERE server_id=%s AND kind=%s AND mac=%s AND subnet_id <=> %s AND resolved_at IS NULL "
                            "ORDER BY last_seen DESC",
                            (sid, kind, mac, subnet),
                        )
                        rows = cur.fetchall()
                        if not rows or any(
                            r["alerted_at"] is not None and (now - r["alerted_at"]) < ALERT_EVERY for r in rows
                        ):
                            continue
                        qualified = max(
                            (r for r in rows if r["qualified_at"] is not None),
                            key=lambda r: r["qualified_at"],
                            default=None,
                        )
                        if qualified is not None and now - qualified["qualified_at"] >= QUALIFICATION_KEEP:
                            # 24 hours undelivered: the qualification is dropped, and the key must earn it again from the tail
                            cur.execute(
                                "UPDATE client_problems SET qualified_at=NULL, qualified_count=NULL WHERE server_id=%s AND kind=%s "
                                "AND mac=%s AND subnet_id <=> %s AND resolved_at IS NULL",
                                (sid, kind, mac, subnet),
                            )
                            qualified = None
                        if qualified is not None:
                            q_at, q_count = qualified["qualified_at"], qualified["qualified_count"]
                        else:
                            current = recent.get((kind, mac, subnet), 0)
                            if first_sweep or current < threshold():
                                continue
                            q_at, q_count = now, current
                            cur.execute(
                                "UPDATE client_problems SET qualified_at=%s, qualified_count=%s WHERE server_id=%s AND kind=%s "
                                "AND mac=%s AND subnet_id <=> %s AND resolved_at IS NULL",
                                (q_at, q_count, sid, kind, mac, subnet),
                            )
                        # a delivery that keeps failing is retried, but not every sweep (a row that DID deliver is the 24-hour rule's)
                        if any(
                            r["alerted_at"] is None
                            and r["alert_attempted_at"] is not None
                            and (now - r["alert_attempted_at"]) < ALERT_RETRY_EVERY
                            for r in rows
                        ):
                            continue
                        alerts_due.append((kind, mac, rows[0]["ip"], subnet, q_count, q_at))
                for (
                    kind,
                    mac,
                    ip,
                    subnet_id,
                    count,
                    qualified_at,
                ) in alerts_due:  # the network I/O after the connection is back in the pool
                    try:
                        results = _send_alert(sid, kind, mac, ip, subnet_id, count, qualified_at)
                    except Exception as e:
                        logger.error(f"client_problems: alert failed: {type(e).__name__}: {e}")
                        results = []
                    delivered = any(ok for _ctype, ok, _err in results)
                    summary["alerts_attempted"] += 1
                    summary["alerts" if delivered else "alerts_failed"] += 1
                    with __db.jen_db() as db, db.cursor() as cur:
                        # `alerted_at` ONLY for a delivered alert: it is what the once-a-day rule reads, so a failed
                        # delivery no longer silences the client for 24 hours
                        # a delivered alert leaves NO pending qualification behind (Q149): `qualified_at` / `qualified_count` are what a
                        # retry reads, and there is nothing left to retry. A failed one keeps them for the next try.
                        cur.execute(
                            "UPDATE client_problems SET alert_attempted_at=%s, alerted_at=IF(%s, %s, alerted_at), "
                            "qualified_at=IF(%s, NULL, qualified_at), qualified_count=IF(%s, NULL, qualified_count) "
                            "WHERE server_id=%s AND kind=%s AND mac=%s AND subnet_id <=> %s AND resolved_at IS NULL",
                            (now, delivered, now, delivered, delivered, sid, kind, mac, subnet_id),
                        )
                if new_wm is not None:
                    _wm_set(sid, new_wm)
                summary["servers"] += 1
                _note_server(sid, True, "", now)
            except Exception as e:
                logger.error(f"client_problems: server {server.get('name')!r}: {type(e).__name__}: {e}")
                summary["errors"].append(f"{server.get('name')}: {type(e).__name__}")
                _note_server(sid, False, type(e).__name__, now)
        try:
            state = from_declined(_declined_rows()) + from_held(_held_rows())
            with __db.jen_db() as db, db.cursor() as cur:
                for p in state:
                    subnet_id = p["subnet_id"] or event_subnet(p["ip"], None)
                    cur.execute(
                        _UPSERT_STATE,
                        (DB_SERVER_ID, p["kind"], p["mac"], p["ip"], subnet_id, subnet_id, now, now, p["detail"][:255]),
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
        if summary["dropped_keys"]:
            logger.warning(
                f"client_problems: {summary['dropped_keys']} new problem keys were not recorded this sweep "
                f"(the cap is {MAX_NEW_KEYS_PER_SWEEP} new keys per server) - a NAK storm?"
            )
        _note_dropped(now, summary["dropped_keys"])
        _clear_orphan_server_keys()
        _note_swept(now)
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
