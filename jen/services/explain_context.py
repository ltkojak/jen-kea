"""
jen/services/explain_context.py
────────────────────────────────
v5.68.0-beta.2 (Q135) — the read-only lookups Explain's pure engine is handed, and the one place that wires them up.

`jen.services.dhcp_explain.explain()` is pure; it asks three questions through callables so it can say WHY NOT:

* `pool_used(subnet_id, pool_text)` — how many active leases sit inside a pool (so a full pool is a verdict);
* `holder_of(ip, mac)` — who holds an address a reservation names (a lease on it, unexpired, for a DIFFERENT hardware address);
* what Kea's own log says about the client (`read_log`) — only for a caller who may read the log at all.

Every query here is one fixed statement with bound parameters, over the lease table Jen already reads. Scope: Explain only
runs for a subnet the caller may see, so a holder found inside it is theirs to see; a lease row whose subnet the caller may NOT
see is never reported (the holder is dropped, not blanked), whatever address it holds.

The Kea log is the same tail Trace reads (helper op `tail-log`, 1000 lines, helper only) and carries the same restriction:
a log line has no subnet boundary Jen can trust, so only a caller with access to EVERY subnet gets log-derived inputs
(docs/ARCHITECTURE.md §2). Results are cached for `LOG_TTL_S` seconds per (server, MAC): the Explain tab, the Config tab and the
Overview all ask, and an SSH round trip per request would be a cost nobody asked for.
"""

from __future__ import annotations

import logging
import time

import jen.models.db as __db
from jen import extensions
from jen.services import dhcp_explain as _explain
from jen.services import explain_inputs as _inputs
from jen.services import kea_log_inputs as _li

logger = logging.getLogger(__name__)

LOG_TTL_S = 30
TAIL_LINES = 1000
TAIL_TIMEOUT_S = 15
_log_cache: dict[tuple, tuple[float, dict]] = {}


def pool_used(subnet_id, pool_text) -> int | None:
    """Active (state 0, unexpired) leases of `subnet_id` whose address lies inside the pool, or None when the pool cannot be
    read or the lease table cannot be reached."""
    bounds = _explain.pool_bounds(pool_text)
    if bounds is None:
        return None
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM lease4 WHERE subnet_id=%s AND state=0 AND expire > NOW() "
                "AND address BETWEEN %s AND %s",
                (int(subnet_id), bounds[0], bounds[1]),
            )
            return int(cur.fetchone()["n"])
    except Exception as e:
        logger.warning(f"explain_context: pool occupancy for subnet {subnet_id} {pool_text!r} failed: {e}")
        return None


def holder_of(ip, mac, accessible_ids=None) -> dict | None:
    """The active lease on `ip` held by a hardware address other than `mac`: {"mac", "expire", "linkable": True} or None.
    `accessible_ids` is None for a caller who may see every subnet, else the set of subnet ids they may see; a lease in any
    other subnet is reported as nothing."""
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT HEX(hwaddr) AS mac_hex, expire, subnet_id FROM lease4 "
                "WHERE address=INET_ATON(%s) AND state=0 AND expire > NOW() LIMIT 1",
                (str(ip),),
            )
            row = cur.fetchone()
    except Exception as e:
        logger.warning(f"explain_context: holder lookup for {ip!r} failed: {e}")
        return None
    if not row or not row.get("mac_hex"):
        return None
    holder_mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, len(row["mac_hex"]), 2)).lower()
    if holder_mac == (mac or "").lower():
        return None
    if accessible_ids is not None and int(row["subnet_id"] or 0) not in {int(i) for i in accessible_ids}:
        return None
    expire = row.get("expire")
    return {"mac": holder_mac, "expire": expire.strftime("%Y-%m-%d %H:%M UTC") if expire else "", "linkable": True}


def _pick_server() -> dict | None:
    servers = extensions.KEA_SERVERS or []
    return servers[0] if servers else None


def read_log(mac: str, *, allowed: bool, fetch: bool = True) -> dict:
    """What Kea's log says about `mac`: {"classes", "query", "cid", "state", "message"}. `state` is "ok", "not-allowed" (the
    caller may not read the log), "no-server", "no-helper", "missing" (no log file), "error", or "not-fetched" (`fetch=False`
    and nothing cached: the Overview asks without paying for the round trip)."""
    empty = {"classes": None, "query": None, "cid": None}
    if not allowed:
        return {**empty, "state": "not-allowed", "message": ""}
    server = _pick_server()
    if server is None:
        return {**empty, "state": "no-server", "message": "No Kea server is configured."}
    if not server.get("ssh_host"):
        return {**empty, "state": "no-helper", "message": "Reading Kea's log needs SSH access to the Kea host."}
    key = (server.get("id"), (mac or "").lower())
    cached = _log_cache.get(key)
    if cached and time.monotonic() - cached[0] < LOG_TTL_S:
        return cached[1]
    if not fetch:
        return {**empty, "state": "not-fetched", "message": ""}
    from jen.services import kea_host as _host

    res = _host.tail_log(server, extensions.DHCP4_LOG, TAIL_LINES, timeout=TAIL_TIMEOUT_S, helper_only=True)
    if res.get("code") == "no-helper":
        view = {**empty, "state": "no-helper", "message": "Reading Kea's log needs the Kea host helper."}
    elif res.get("code") == "missing":
        view = {**empty, "state": "missing", "message": f"Kea's log was not found at {extensions.DHCP4_LOG}."}
    elif not res.get("ok"):
        logger.error(f"explain_context: tail_log failed: {res.get('detail')}")
        view = {**empty, "state": "error", "message": "Could not read Kea's log."}
    else:
        lines = res.get("lines", [])
        view = {
            "classes": _li.latest_classes(lines, mac),
            "query": _li.latest_query_data(lines, mac),
            "cid": _li.client_id_from_log(lines, mac),
            "state": "ok",
            "message": "",
        }
    if len(_log_cache) > 256:
        _log_cache.clear()
    _log_cache[key] = (time.monotonic(), view)
    return view


def clear_log_cache() -> None:
    _log_cache.clear()


def run(cfg, built: dict, *, subnet_id, lease, reservations, accessible_ids=None) -> dict:
    """explain() with the lookups wired: the client and class list from `explain_inputs.build()`, the pool and holder
    lookups bound to this caller's scope."""
    return _explain.explain(
        cfg,
        built["client"],
        subnet_id=subnet_id,
        reservations=reservations,
        lease=lease,
        assigned_classes=built["assigned"],
        pool_used=pool_used,
        holder_of=lambda ip, mac: holder_of(ip, mac, accessible_ids),
    )


def hint_for(result: dict, log_view: dict) -> str:
    """The sentence under the 'supply what is missing' form: what is still missing, and — when the cause is the log level —
    the setting that would let Jen read it. '' when nothing is missing."""
    missing = list((result or {}).get("missing_inputs") or [])
    if not missing:
        return ""
    state = (log_view or {}).get("state")
    if state == "not-allowed":
        return "Reading Kea's log for these needs an admin with access to every subnet; type them below."
    if state in ("no-helper", "no-server", "missing", "error"):
        return (log_view.get("message") or "Kea's log is not available.") + " Type what is missing below."
    return _li.level_hint(missing)


# re-exported so callers import one module for the whole Explain input story
build_inputs = _inputs.build
provenance = _inputs.provenance
