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

logger = logging.getLogger(__name__)

VERDICTS = ("ok", "missing-forward", "wrong-forward", "missing-ptr", "wrong-ptr", "stale-ptr", "duplicate-a")

# Per-lookup wall-clock budget. concurrent.futures can't forcibly kill a
# blocked worker thread — a resolver call past this still runs to
# completion in the background — but it does bound how long the PAGE
# waits: .result(timeout=...) raises and the row is scored as if both
# lookups failed, the same "we genuinely don't know" outcome a real
# NXDOMAIN/timeout from the resolver would produce.
LOOKUP_TIMEOUT_SECONDS = 2


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


def _classify(observed: dict, expected_ip: str, expected_name: str, expired_names: set[str]) -> str:
    """`observed` is whatever `resolve(name, ip)` returned — see
    ddns._run_verify's docstring for the exact shape this expects:
    forward_ips (list, absent/empty on error), forward_error,
    reverse_name, reverse_error."""
    if observed.get("forward_error"):
        return "missing-forward"

    forward_ips = observed.get("forward_ips") or []
    if len(forward_ips) > 1:
        return "duplicate-a"
    if expected_ip and expected_ip not in forward_ips:
        return "wrong-forward"

    if observed.get("reverse_error"):
        return "missing-ptr"

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = []
        for row in capped:
            fqdn = _qualify(row["name"], suffix)
            prepared.append((row, fqdn))
            futures.append(pool.submit(resolve, fqdn, row["ip"]))

        results = []
        for (row, fqdn), fut in zip(prepared, futures, strict=True):
            try:
                observed = fut.result(timeout=LOOKUP_TIMEOUT_SECONDS) or {}
            except Exception as e:
                # str(a bare TimeoutError()) is "" — falsy, which would
                # slip past _classify's `if observed.get("forward_error")`
                # check and get mis-scored as wrong-forward instead of
                # missing-forward. Always fall back to the class name.
                msg = str(e) or e.__class__.__name__
                logger.warning(f"dns_reconcile lookup failed for {fqdn}: {msg}")
                observed = {"forward_error": msg, "reverse_error": msg}
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
