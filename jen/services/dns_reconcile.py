"""
jen/services/dns_reconcile.py
───────────────────────────────
v5.47.0 (Q48) — read-only DNS ↔ DHCP reconciliation: for every
reservation and active lease that carries a hostname, check whether
the name Jen expects to resolve to that IP (and that IP to resolve
back to that name) actually does, via the box's own resolver — the
same check the DDNS Verify tab already runs one name at a time
(jen/routes/ddns.py::_run_verify), just over the whole fleet at once.

Nothing here writes anything, to Jen's DB or to Kea. `reconcile()` is
pure aside from the injected `resolve` callable, so it's testable
without a real resolver or a real DB — the caller (jen/routes/ddns.py)
is what turns rows/subnet-access/the cached summary into I/O.
"""

from __future__ import annotations

import concurrent.futures
import logging
import math
import socket
import threading
import time

logger = logging.getLogger(__name__)

# `multiple-a` is informational (several A records are a legitimate design)
# and `lookup-failed` means "the resolver could not answer", NOT "the record
# is missing" — neither counts as a mismatch in the Health summary.
VERDICTS = (
    "ok",
    "missing-forward",
    "wrong-forward",
    "missing-ptr",
    "wrong-ptr",
    "stale-ptr",
    "multiple-a",
    "lookup-failed",
)

# resolver errnos that are a DEFINITIVE "no such record": getaddrinfo's
# EAI_NONAME/EAI_NODATA, gethostbyaddr's herror HOST_NOT_FOUND(1)/NO_DATA(4).
# Anything else (EAI_AGAIN, EAI_FAIL, timeouts, other OSErrors) is a
# resolver problem, not an answer.
_DEFINITIVE_ERRNOS = {
    getattr(socket, "EAI_NONAME", None),
    getattr(socket, "EAI_NODATA", None),
    1,
    4,
} - {None}

# Per-lookup wall-clock budget, applied as one overall deadline (see
# reconcile()). concurrent.futures can't forcibly kill a blocked worker
# thread: a resolver call past the deadline is ABANDONED, not joined —
# it keeps running in the background and the request returns anyway —
# and its row is scored `lookup-failed` ("we don't know").
LOOKUP_TIMEOUT_SECONDS = 2
# hard ceiling for the whole run however many rows are hung
TOTAL_BUDGET_SECONDS = 10

# v5.49.0-beta.4 — bound THREADS as well as time. A pool per call abandoned its
# hung threads at every deadline, so repeated runs against a wedged resolver
# piled them up until libc gave up. There is now ONE module-level pool of
# POOL_WORKERS threads, created lazily and never shut down, and a lock so only
# one reconciliation runs at a time: a stuck lookup holds one of the eight
# slots and the next run queues behind it — that is the ceiling.
POOL_WORKERS = 8
_POOL: concurrent.futures.ThreadPoolExecutor | None = None
_POOL_LOCK = threading.Lock()
_RUN_LOCK = threading.Lock()


class ReconcileBusy(RuntimeError):
    """Another reconciliation is already running."""


def _get_pool() -> concurrent.futures.ThreadPoolExecutor:
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = concurrent.futures.ThreadPoolExecutor(max_workers=POOL_WORKERS, thread_name_prefix="dns-reconcile")
        return _POOL


def _qualify(name: str, suffix: str) -> str:
    """`name` + `suffix` -> a single FQDN, without double-appending the
    suffix when the name already carries it (a reservation/lease
    hostname can be stored either bare or already-qualified,
    depending on what wrote it)."""
    name = (name or "").strip().rstrip(".")
    suffix = (suffix or "").strip().strip(".")
    if not suffix or not name:
        return name
    low = name.lower()
    if low == suffix.lower() or low.endswith("." + suffix.lower()):
        return name
    return f"{name}.{suffix}"


def _definitive(errno) -> bool:
    """True when the resolver definitively said "no such record". A dict
    from an older caller with no errno at all keeps the pre-5.49 reading
    (a definitive miss)."""
    return errno is None or errno in _DEFINITIVE_ERRNOS


def _classify(observed: dict, expected_ip: str, expected_name: str, expired_names: set[str]) -> str:
    """`observed` is whatever `resolve(name, ip)` returned — see
    ddns._run_verify's docstring for the exact shape this expects:
    forward_ips (list, absent/empty on error), forward_error,
    reverse_name, reverse_error."""
    if observed.get("lookup_failed"):
        return "lookup-failed"
    if observed.get("forward_error"):
        return "missing-forward" if _definitive(observed.get("forward_errno")) else "lookup-failed"

    forward_ips = observed.get("forward_ips") or []
    if len(forward_ips) > 1:
        return "multiple-a"
    if expected_ip and expected_ip not in forward_ips:
        return "wrong-forward"

    if observed.get("reverse_error"):
        return "missing-ptr" if _definitive(observed.get("reverse_errno")) else "lookup-failed"

    reverse_name = (observed.get("reverse_name") or "").rstrip(".").lower()
    expected = expected_name.rstrip(".").lower()
    if reverse_name and reverse_name != expected:
        bare = reverse_name.split(".", 1)[0]
        if reverse_name in expired_names or bare in expired_names:
            return "stale-ptr"
        return "wrong-ptr"

    return "ok"


def reconcile(
    rows: list[dict],
    resolve,
    suffix: str = "",
    limit: int = 200,
    workers: int = 8,
    expired_names: set[str] | None = None,
) -> list[dict]:
    """
    `rows`: `[{"name": str, "ip": str, "source": "reservation"|"lease"}, ...]`
    — the caller's job to build (reservations first, then active leases
    with a hostname) and subnet-restrict before calling this.

    `resolve(fqdn, ip) -> dict`: forward+reverse lookup, same shape as
    jen.routes.ddns._run_verify — injected so this stays testable
    without a real resolver.

    `expired_names`: lowercased hostnames (bare or qualified) known to
    belong to an expired lease elsewhere — used only to tell a genuinely
    stale PTR record ("stale-ptr") apart from one that was simply never
    right ("wrong-ptr"). Optional; treated as empty when omitted, which
    just means every reverse mismatch reads as wrong-ptr instead.

    Returns one dict per row (input order, capped at `limit`):
    `{"name", "ip", "source", "expected_a", "observed_a",
    "expected_ptr", "observed_ptr", "verdict"}`.
    """
    expired = {str(n).rstrip(".").lower() for n in (expired_names or ())}
    capped = list(rows[:limit])
    if not capped:
        return []

    prepared: list[tuple[dict, str]] = []
    n_workers = POOL_WORKERS  # the shared pool's size; the `workers` argument is kept for old callers
    # Single-flight: a second reconciliation while one runs does no work.
    if not _RUN_LOCK.acquire(blocking=False):
        raise ReconcileBusy("a reconciliation is already running")
    pool = _get_pool()
    futures = []
    try:
        for row in capped:
            fqdn = _qualify(row["name"], suffix)
            prepared.append((row, fqdn))
            futures.append(pool.submit(resolve, fqdn, row["ip"]))

        # One overall deadline: each "round" of `workers` lookups gets
        # LOOKUP_TIMEOUT_SECONDS, capped at TOTAL_BUDGET_SECONDS.
        rounds = math.ceil(len(futures) / n_workers)
        deadline = time.monotonic() + min(LOOKUP_TIMEOUT_SECONDS * rounds, TOTAL_BUDGET_SECONDS)
        concurrent.futures.wait(futures, timeout=max(0.0, deadline - time.monotonic()))

        results = []
        for (row, fqdn), fut in zip(prepared, futures, strict=True):
            if not fut.done():
                logger.warning(f"dns_reconcile lookup for {fqdn} did not finish in time; abandoned")
                observed = {"lookup_failed": True, "forward_error": "timed out", "reverse_error": "timed out"}
            else:
                try:
                    observed = fut.result() or {}
                except Exception as e:
                    # str(a bare TimeoutError()) is "" — always fall back to
                    # the class name so the message is never empty.
                    msg = str(e) or e.__class__.__name__
                    logger.warning(f"dns_reconcile lookup failed for {fqdn}: {msg}")
                    observed = {"lookup_failed": True, "forward_error": msg, "reverse_error": msg}
            verdict = _classify(observed, row["ip"], fqdn, expired)
            forward_ips = observed.get("forward_ips") or []
            results.append(
                {
                    "name": fqdn,
                    "ip": row["ip"],
                    "source": row.get("source", ""),
                    "expected_a": row["ip"],
                    "observed_a": ", ".join(sorted(forward_ips)),
                    "expected_ptr": fqdn,
                    "observed_ptr": observed.get("reverse_name") or "",
                    "verdict": verdict,
                }
            )
    finally:
        # Lookups still QUEUED are cancelled; one already running in the
        # resolver cannot be interrupted and keeps its pool slot until libc
        # returns — that, not a growing thread count, is the ceiling.
        for fut in futures:
            fut.cancel()
        _RUN_LOCK.release()
    return results


def summarize(results: list[dict]) -> dict[str, int]:
    """Verdict -> count, every verdict present (0 for ones that didn't
    occur) so a caller can render a stable set of filter buttons/totals
    without checking membership first."""
    counts = dict.fromkeys(VERDICTS, 0)
    for r in results:
        v = r.get("verdict")
        if v in counts:
            counts[v] += 1
    return counts
