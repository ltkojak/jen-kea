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
(docs/ARCHITECTURE.md §2). Results are cached for `LOG_TTL_S` seconds per MAC: the Explain tab, the Config tab and the
Overview all ask, and an SSH round trip per request would be a cost nobody asked for.

v5.68.0-beta.10 (Q145). WHICH exchange and WHICH server the evidence comes from are decided here, and named on the tab:

* the inputs come from ONE transaction (`kea_log_inputs.latest_transaction`: the newest exchange that has a class list or a packet dump),
  never stitched from the newest of each kind;
* the log is read from the server that handled the client, not from "server 0": `_evidence_servers()` puts the HA-ACTIVE server
  first (the one whose HA state serves scopes, as the Servers page shows it), then every other configured server in order, and the
  first one whose log holds an exchange for the MAC supplies it - an unreachable or helper-less server is skipped, with its reason
  kept for the case where none can be read;
* a class list observed BEFORE the live config's newest revision is labelled so - it is what Kea decided under an older config.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time

import jen.models.db as __db
from jen import extensions
from jen.services import client_subject as _cs
from jen.services import dhcp_explain as _explain
from jen.services import explain_inputs as _inputs
from jen.services import kea_log_inputs as _li
from jen.services import log_tail as _log_tail
from jen.services import pools as _pools

logger = logging.getLogger(__name__)

LOG_TTL_S = 30
TAIL_LINES = 1000
TAIL_TIMEOUT_S = 15
#: v5.68.0-beta.23 (Q158, item 4): ONE shared deadline for reading every server's log. beta.22 read each server in turn, each with its own 15 s timeout:
#: one good server and three unreachable ones cost ~45 s on top of the HA probes. The servers are read concurrently and the answers that arrived inside
#: this budget are the evidence; a server that did not answer in time is named ("could not be checked in time"), never silently dropped.
EVIDENCE_BUDGET_S = 20
EVIDENCE_WORKERS = 4
#: v5.68.0-beta.24 (Q159): the pool follows the server count up to this cap, and never shrinks below what it has.
EVIDENCE_WORKERS_MAX = 16
#: v5.68.0-beta.24 (Q159, item 5): the HA probes that order the servers run INSIDE the budget, on the same pool, with their own slice of it. A server whose
#: probe did not answer in time is ordered after the ones that did.
HA_PROBE_BUDGET_S = 5
_evidence_pool: concurrent.futures.ThreadPoolExecutor | None = None
_evidence_pool_lock = threading.Lock()
_log_cache: dict[tuple, tuple[float, dict, float]] = {}  # key -> (monotonic time, view, how long it is kept)


def _pool(ssh_servers: int = 0) -> concurrent.futures.ThreadPoolExecutor:
    """The module-level executor the per-server tails and HA probes run on - created on first use, not at import (the factory and the test suite import
    freely). It needs `max(EVIDENCE_WORKERS, 2 x the SSH servers)` workers (a probe and a tail per server), capped at EVIDENCE_WORKERS_MAX.

    v5.68.0-beta.24 (Q159, item 4): it used to be sized ONCE, at first use: one server at start and eight configured later was still four workers, and
    the later servers queued past the budget. A pool that is too small for the servers now is REPLACED by a larger one; the old one is shut down without
    waiting - its running reads finish on their own threads and their futures were already handed out. It never shrinks."""
    global _evidence_pool
    wanted = min(EVIDENCE_WORKERS_MAX, max(EVIDENCE_WORKERS, 2 * ssh_servers))
    with _evidence_pool_lock:
        if _evidence_pool is None or _evidence_pool._max_workers < wanted:
            old = _evidence_pool
            _evidence_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=wanted, thread_name_prefix="jen-evidence-tail"
            )
            if old is not None:
                old.shutdown(wait=False)
        return _evidence_pool


#: A FIXED phrase per failure code - never the exception text, which can carry a host, a path or a library message (v5.68.0-beta.24, Q159, item 2).
READ_FAILURE_PHRASES = {
    "transport": "SSH failed",
    "no-helper": "the helper is missing",
    "missing": "the log is missing",
    "error": "the read failed",
    "no-ssh": "no SSH host is configured",
}


def _tail_one(server: dict) -> dict:
    # v5.68.0-beta.17 (Q152): the layer below this function's own 30 s per-MAC cache - one read per server and path is shared
    # with Trace's live watch (jen.services.log_tail), so a watcher and an Investigation page do not each tail the log
    return _log_tail.tail(server, extensions.DHCP4_LOG, TAIL_LINES, timeout=TAIL_TIMEOUT_S)


def pool_used(subnet_id, pool_text) -> int | None:
    """Active (state 0, unexpired) leases of `subnet_id` whose address lies inside the pool, or None when the pool cannot be
    read or the lease table cannot be reached."""
    bounds = _pools.parse_pool(pool_text)
    if bounds is None:
        return None
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) AS n FROM lease4 WHERE subnet_id=%s AND {_cs.ACTIVE_LEASE4} "  # nosec B608 - a fixed constant
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
                f"WHERE address=INET_ATON(%s) AND {_cs.ACTIVE_LEASE4} LIMIT 1",  # nosec B608 - a fixed constant
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


HA_ACTIVE_STATES = ("hot-standby", "load-balancing", "partner-down")


def _name(server: dict) -> str:
    return server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"


def _serves_clients(server: dict) -> bool:
    """Does `server`'s HA state say it is answering clients right now (the Servers page's own reading, `kea_ha.ha_status`): it has a
    local state that serves and holds scopes. A standby in hot-standby holds none until its partner is down."""
    from jen.services import kea_ha as _ha

    try:
        status = _ha.ha_status(server)
    except Exception as e:
        logger.warning(f"explain_context: HA status for {_name(server)} failed: {type(e).__name__}")
        return False
    local = (status or {}).get("local") or {}
    return bool(local.get("scopes")) and local.get("state") in HA_ACTIVE_STATES


#: v5.68.0-beta.22 (Q157): two exchanges whose corrected times are this close are "at about the same time" - the first server in order wins and the
#: other is named as also having logged the client.
CLOCK_TIE_S = 5

_evidence_memo: tuple | None = (
    None  # (monotonic time, signature of the configured servers, ordered server KEYS, ha_order)
)


def _server_key(server: dict) -> str:
    """A server's identity across config reloads: its id as text. Never the dict object - a reload that rebuilds `KEA_SERVERS` makes new dicts for the same
    servers, and object identity then names nothing (v5.68.0-beta.25, Q160, item 3)."""
    return str(server.get("id"))


def _signature(servers: list[dict]) -> tuple:
    """What the memoised order is a function of: each server's id, API URL and SSH host. A changed address under the same id invalidates the memo."""
    return tuple((_server_key(s), s.get("api_url"), s.get("ssh_host")) for s in servers)


def _evidence_plan(deadline: float) -> tuple[list[dict], str | None]:
    """(servers in the order to read them, ha_order): the HA-ACTIVE server(s) first, then every other configured server in order. With one server (the
    usual case) that is the server and no HA question is asked. `ha_order` is None when the order is known, "partial" when some servers' HA probes did
    not answer in time (those are ordered after the ones that did, in configured order) and "unknown" when none did.

    v5.68.0-beta.21 (Q156): the answer is MEMOISED for `LOG_TTL_S`, so across every caller - the Overview, Explain, Config and Changes of one
    `/client` render, `/tools/explain`, a second person - there is at most one `status-get` per server per 30 seconds. A server whose Control Agent
    is down costs its 10 s timeout once in that window, not once per call. The memo is keyed by the configured server ids, so adding or removing a
    server is seen at once - and (Q159) it stores whatever was LEARNED, partial or not.

    v5.68.0-beta.24 (Q159, item 5): the probes ran sequentially BEFORE the log budget started - N unreachable Control Agents cost 10 s each on top of
    the 20 s. They now run on the evidence pool concurrently, against the SAME `deadline` the log reads use, capped at HA_PROBE_BUDGET_S."""
    global _evidence_memo
    servers = list(extensions.KEA_SERVERS or [])
    if len(servers) < 2:
        return servers, None
    signature = _signature(servers)
    now = time.monotonic()
    if _evidence_memo is not None and _evidence_memo[1] == signature and now - _evidence_memo[0] < LOG_TTL_S:
        # v5.68.0-beta.25 (Q160, item 3): the memo holds KEYS, and the list is rebuilt from the servers as configured NOW - it used to hold the dict
        # objects of 30 s ago, which `read_log` then looked up in a table built from the current ones (a KeyError after any reload that rebuilt them)
        by_key = {_server_key(s): s for s in servers}
        keys = _evidence_memo[2]
        return [by_key[k] for k in keys if k in by_key] + [
            s for s in servers if _server_key(s) not in keys
        ], _evidence_memo[3]
    probe_deadline = min(deadline, now + HA_PROBE_BUDGET_S)
    pool = _pool(len(servers))
    probes = {_server_key(s): pool.submit(_serves_clients, s) for s in servers}
    active, unanswered = [], []
    for s in servers:
        key = _server_key(s)
        try:
            if probes[key].result(timeout=max(0.0, probe_deadline - time.monotonic())):
                active.append(key)
        except concurrent.futures.TimeoutError:
            probes[key].cancel()
            unanswered.append(key)
        except Exception as e:  # `_serves_clients` catches its own; a pool fault is "did not answer"
            logger.warning(f"explain_context: HA probe for {_name(s)} raised {type(e).__name__}")
            unanswered.append(key)
    answered_rest = [
        _server_key(s) for s in servers if _server_key(s) not in active and _server_key(s) not in unanswered
    ]
    keys = active + answered_rest + unanswered
    ha_order = None if not unanswered else ("unknown" if len(unanswered) == len(servers) else "partial")
    if ha_order == "unknown":
        keys = [_server_key(s) for s in servers]  # nothing was learned: configured order
    _evidence_memo = (time.monotonic(), signature, keys, ha_order)
    by_key = {_server_key(s): s for s in servers}
    return [by_key[k] for k in keys], ha_order


def _evidence_servers() -> list[dict]:
    """The servers in reading order (see `_evidence_plan`), without the `ha_order` note."""
    return _evidence_plan(time.monotonic() + EVIDENCE_BUDGET_S)[0]


def _clock_offset_s(server: dict) -> float | None:
    """The Kea host's log-clock offset from UTC, in seconds, when the Problems sweep has measured it (Q144); else None."""
    try:
        from jen.services import client_problems as _cp

        return _cp._clock_get(server.get("id"))
    except Exception:
        return None


def _utc_of(server: dict, tx: dict):
    """The exchange's last line as a naive UTC time, or None when the host's log-clock offset is unknown (the comparison across servers is then
    not made - never a guess)."""
    offset = _clock_offset_s(server)
    when = _li._when(tx["last"])
    if offset is None or when is None:
        return None
    from datetime import timedelta

    return when - timedelta(seconds=offset)


def _before_config_change(server: dict, at_text: str) -> bool:
    """Was an exchange logged at `at_text` (the Kea host's own clock) BEFORE the newest config revision Jen holds for `server`? Only
    answered when the host's clock offset is known (it is a comparison across two clocks); otherwise False - never a guess."""
    offset = _clock_offset_s(server)
    if offset is None:
        return False
    when = _li._when(at_text)
    if when is None:
        return False
    try:
        from datetime import timedelta

        from jen.services import config_revisions as _rev

        latest = _rev.latest(server.get("id"), "dhcp4")
        created = (latest or {}).get("created_at")
        return bool(created is not None and created > when - timedelta(seconds=offset) + timedelta(seconds=5))
    except Exception as e:
        logger.warning(f"explain_context: config revision lookup failed: {type(e).__name__}")
        return False


def _view_from(server: dict, tx: dict | None) -> dict:
    """The log view for one server's tail: the inputs of the ONE exchange chosen, and where they came from."""
    view = {"classes": None, "query": None, "cid": None, "state": "ok", "message": "", "transaction": None}
    view["server"] = {"id": server.get("id"), "name": _name(server)}
    if tx is None:
        return view
    old = _before_config_change(server, tx["last"])
    classes = dict(tx["classes"], before_config_change=True) if tx["classes"] and old else tx["classes"]
    view.update(
        classes=classes,
        query=tx["query"],
        cid=tx["cid"],
        transaction={
            "tid": tx["tid"],
            "first": tx["first"],
            "at": tx["last"],
            "complete": tx["complete"],
            "before_config_change": old,
        },
    )
    return view


def read_log(mac: str, *, allowed: bool, fetch: bool = True) -> dict:
    """What Kea's log says about `mac`: {"classes", "query", "cid", "transaction", "server", "state", "message"}. The three inputs all
    come from the ONE exchange `transaction` names ({"tid", "first", "at", "complete", "before_config_change"}), read from the
    `server` ({"id", "name"}) that supplied it. `state` is "ok", "not-allowed" (the caller may not read the log), "no-server",
    "no-helper", "missing" (no log file), "error", or "not-fetched" (`fetch=False` and nothing cached: the Overview asks without
    paying for the round trip)."""
    empty = {"classes": None, "query": None, "cid": None, "transaction": None, "server": None}
    if not allowed:
        return {**empty, "state": "not-allowed", "message": ""}
    # v5.68.0-beta.21 (Q156): `allowed`, the cache and `fetch` are decided BEFORE anything asks a server a question. The order of the servers
    # (`_evidence_servers`) needs an HA `status-get` per server - a 10 s timeout for one whose Control Agent is down - and it used to be computed
    # first, so the Overview's "never a fresh round trip" read (`fetch=False`) and every cached read paid for it. The two states that only need the
    # CONFIGURED servers, not their order, are still answered from the configuration alone.
    configured = list(extensions.KEA_SERVERS or [])
    if not configured:
        return {**empty, "state": "no-server", "message": "No Kea server is configured."}
    if not any(s.get("ssh_host") for s in configured):
        return {**empty, "state": "no-helper", "message": "Reading Kea's log needs SSH access to the Kea host."}
    key = ("log", (mac or "").lower())
    cached = _log_cache.get(key)
    if cached and time.monotonic() - cached[0] < cached[2]:
        return cached[1]
    if not fetch:
        return {**empty, "state": "not-fetched", "message": ""}
    # The ONE deadline is taken first (v5.68.0-beta.24, Q159, item 5): it covers the HA probes that order the servers as well as the log reads, which
    # are submitted at once with them - a probe that never answers cannot start the clock late. Every SSH server is asked AT ONCE (v5.68.0-beta.23,
    # Q158); the loop below reads the answers in the order the probes gave, each against the same deadline.
    deadline = time.monotonic() + EVIDENCE_BUDGET_S
    configured_servers = list(extensions.KEA_SERVERS or [])
    ssh_servers = [server for server in configured_servers if server.get("ssh_host")]
    pending = {_server_key(server): _pool(len(configured_servers)).submit(_tail_one, server) for server in ssh_servers}
    servers, ha_order = _evidence_plan(deadline)
    complete = []  # (server, tx, utc time or None) for every reachable server whose log holds a COMPLETE exchange of the client
    first_ok = None  # a server whose log was read but never named the client
    fallback = None  # an exchange that has no class list or packet dump (the client id only)
    problem = None  # why the first server that could not be read could not be
    not_checked = []  # servers whose answer did not arrive inside EVIDENCE_BUDGET_S
    read_failures = []  # servers whose read FAILED (v5.68.0-beta.24, Q159, item 2), whether or not another server's exchange was found
    for server in servers:
        if not server.get("ssh_host"):
            problem = problem or {
                **empty,
                "state": "no-helper",
                "message": "Reading Kea's log needs SSH access to the Kea host.",
            }
            read_failures.append({"server": _name(server), "reason": READ_FAILURE_PHRASES["no-ssh"]})
            continue
        future = pending.get(_server_key(server))
        if future is None:
            # a server in the plan that was not among the ones submitted (the configuration changed between the two reads): not checked, never an exception
            not_checked.append(_name(server))
            logger.warning(
                f"explain_context: {_name(server)} was not in the set of logs submitted; reported as not checked"
            )
            continue
        try:
            res = future.result(timeout=max(0.0, deadline - time.monotonic()))
        except concurrent.futures.TimeoutError:
            future.cancel()  # a read that has not started never will; one that has runs out its own timeout and its result is dropped
            not_checked.append(_name(server))
            logger.warning(f"explain_context: {_name(server)}'s log was not read inside {EVIDENCE_BUDGET_S} s")
            continue
        except Exception as e:
            # the tail never raises by contract; a pool or thread fault must not take the page with it
            logger.error(f"explain_context: reading {_name(server)}'s log raised {type(e).__name__}: {e}")
            problem = problem or {**empty, "state": "error", "message": "Could not read Kea's log."}
            read_failures.append({"server": _name(server), "reason": READ_FAILURE_PHRASES["error"]})
            continue
        if res.get("code") == "no-helper":
            problem = problem or {
                **empty,
                "state": "no-helper",
                "message": "Reading Kea's log needs the Kea host helper.",
            }
            read_failures.append({"server": _name(server), "reason": READ_FAILURE_PHRASES["no-helper"]})
            continue
        if res.get("code") == "missing":
            problem = problem or {
                **empty,
                "state": "missing",
                "message": f"Kea's log was not found at {extensions.DHCP4_LOG}.",
            }
            read_failures.append({"server": _name(server), "reason": READ_FAILURE_PHRASES["missing"]})
            continue
        if not res.get("ok"):
            logger.error(f"explain_context: tail_log failed on {_name(server)}: {res.get('detail')}")
            problem = problem or {**empty, "state": "error", "message": "Could not read Kea's log."}
            read_failures.append(
                {
                    "server": _name(server),
                    "reason": READ_FAILURE_PHRASES["transport" if res.get("transport") else "error"],
                }
            )
            continue
        tx = _li.latest_transaction(res.get("lines", []), mac)
        if tx is None:
            first_ok = first_ok or _view_from(server, None)
            continue
        if tx["complete"]:
            complete.append((server, tx, _utc_of(server, tx)))
            continue
        fallback = fallback or _view_from(server, tx)
    view = None
    if complete:
        # v5.68.0-beta.22 (Q157): the NEWEST complete exchange across the reachable servers, not the first one in server order - after a failover the
        # old active's older exchange used to beat the standby's newer one. Two exchanges are ordered only when both servers' log-clock offsets are
        # known (the Problems sweep measures them); within CLOCK_TIE_S, or with an offset unknown, the first in `_evidence_servers` order (the
        # HA-active server) wins. Fields are never mixed across transactions: the view is built from the ONE exchange chosen.
        best = complete[0]
        for candidate in complete[1:]:
            if (
                best[2] is not None
                and candidate[2] is not None
                and (candidate[2] - best[2]).total_seconds() > CLOCK_TIE_S
            ):
                best = candidate
        view = _view_from(best[0], best[1])
        # v5.68.0-beta.23 (Q158): every OTHER server that logged a complete exchange is named, and whether the two can be COMPARED. beta.22 named
        # a server only when both log-clock offsets were known and the times were within CLOCK_TIE_S, so with an offset unknown the second exchange
        # was silently not mentioned although the docstring said it was: "comparable" True = both offsets known and within the tie window ("at about
        # the same time"); False = a clock could not be compared, so the first in order was chosen by position. Two comparable exchanges more than
        # CLOCK_TIE_S apart are not "also" - the newer one won, and the older one is simply older.
        others = []
        for server, _tx, utc in complete:
            if server is best[0]:
                continue
            if best[2] is None or utc is None:
                others.append({"server": _name(server), "comparable": False})
            elif abs((utc - best[2]).total_seconds()) <= CLOCK_TIE_S:
                others.append({"server": _name(server), "comparable": True})
        if others:
            view["other_complete"] = others
    if view is None:
        view = fallback or first_ok or problem or {**empty, "state": "error", "message": "Could not read Kea's log."}
    if read_failures:
        view["read_failures"] = (
            read_failures  # (item 2) disclosed whenever a server failed, an exchange from another one or not
        )
    if ha_order:
        view["ha_order"] = (
            ha_order  # (item 5) "partial" | "unknown": the tab says the servers were read in configured order
        )
    if not_checked:
        view["not_checked"] = not_checked
        if view.get("state") == "error" and not view.get("transaction"):
            view["message"] = f"{len(not_checked)} server(s) could not be checked in time. " + (
                view.get("message") or ""
            )
    if len(_log_cache) > 256:
        _log_cache.clear()
    # a view built from a failure or from servers that did not answer in time is kept for the short window the shared tail cache keeps a failed read
    # (fixup 4, F7a): 30 s would hide a late answer, and a server that was only slow, for half a minute
    keep = _log_tail.TTL_S if (not_checked or read_failures or view.get("state") == "error") else LOG_TTL_S
    _log_cache[key] = (time.monotonic(), view, keep)
    return view


def clear_log_cache() -> None:
    global _evidence_memo
    _evidence_memo = None
    _log_cache.clear()
    _log_tail.clear()  # the shared 3 s read below this per-MAC cache (v5.68.0-beta.17, Q152)


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
