"""
jen/services/pools.py
─────────────────────
v5.68.0-beta.18 (Q153) - what a Kea pool IS and how big a subnet's pools are, ONCE.

Pool size was computed four ways: `take_lease_snapshot` and the dashboard kept only the LAST pool of a subnet (`pool_sizes[id] = ...` per
pool) and skipped a CIDR pool entirely (`if "-" in p`); the API summed the ranges but also skipped CIDR; `check_alerts` compared the
subnet's WHOLE active count against each pool in turn (100 leases over pools of 50 and 200 read as 200 % and 50 %), and counted a
reservation outside every pool as pool consumption. The snapshot's number is what `lease_history`, Health, Reports, Prometheus and the
forecast read back, so a wrong pool size was wrong everywhere. Three parsers existed besides (subnet_context, dhcp_explain,
config_doctor); they are one function now.

  parse_pool(text, network=None)   (first, last) as ints for `a - b`, `a-b` or a CIDR; None when it cannot be read (and, given
                                   `network`, for a CIDR that is not inside it - Kea refuses that pool)
  pool_ranges(pools)               the parsed, sorted and MERGED ranges of a subnet's pool list (strings or {"pool": text} dicts)
  total_pool_size(pools)           the number of addresses in the union of the pools - what every capacity number divides by
  address_in_pools(address, pools) is this address inside any pool
  consumption(cursor, subnet_id, pools)
                                   active, unexpired leases of `subnet_id` whose address is in the pool union - one `address BETWEEN`
                                   count per merged range, summed. An active lease OUTSIDE every pool (a reservation, a static address
                                   handed out by a reservation) never consumes dynamic capacity.

Utilisation and exhaustion are judged per SUBNET over the union of its pools. The Subnets page may list each pool for information.

No Flask: importable anywhere; `consumption` takes the caller's open Kea-database cursor.
"""

import ipaddress

from jen.services.leases_sql import ACTIVE_LEASE4


def _addr(value):
    try:
        return ipaddress.IPv4Address(str(value).strip())
    except (ValueError, TypeError):
        return None


def parse_pool(text, network=None) -> tuple[int, int] | None:
    """(first, last) address of a Kea pool as integers - `a - b`, `a-b` (spaces optional) or a CIDR - or None when it cannot be read:
    anything unparseable, a range whose first address is above its last, and (when `network` is given) a CIDR outside it."""
    text = str(text or "").strip()
    if not text:
        return None
    if "-" in text:
        first, last = (_addr(part) for part in text.split("-", 1))
        if first is None or last is None or int(first) > int(last):
            return None
        return int(first), int(last)
    try:
        sub = ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None
    if network is not None and not sub.subnet_of(network):
        return None
    return int(sub.network_address), int(sub.broadcast_address)


def _pool_text(pool) -> str:
    if isinstance(pool, dict):
        return str(pool.get("pool") or "")
    return str(pool or "")


def pool_ranges(pools) -> list[tuple[int, int]]:
    """The subnet's pools as sorted, non-overlapping (first, last) integer ranges. Pools that cannot be read are left out; overlapping or
    touching ones are merged (Kea refuses overlapping pools, and a merged union is the one thing that cannot double-count an address)."""
    parsed = sorted(r for r in (parse_pool(_pool_text(p)) for p in pools or ()) if r is not None)
    merged: list[list[int]] = []
    for first, last in parsed:
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    return [(a, b) for a, b in merged]


def total_pool_size(pools) -> int:
    """Addresses in the union of `pools` (a CIDR pool counts all of its addresses; two ranges add; 0 when there is no readable pool)."""
    return sum(last - first + 1 for first, last in pool_ranges(pools))


def address_in_pools(address, pools) -> bool:
    """Is `address` (text or int) inside any of `pools`."""
    if isinstance(address, int):
        value = address
    else:
        parsed = _addr(address)
        if parsed is None:
            return False
        value = int(parsed)
    return any(first <= value <= last for first, last in pool_ranges(pools))


def consumption(cur, subnet_id, pools) -> int:
    """Active, unexpired leases of `subnet_id` whose address is inside the union of `pools`: one COUNT per merged range, summed. `cur` is an
    open cursor on the Kea lease database. 0 for a subnet with no readable pool (its capacity is 0 too: nothing to be consumed)."""
    used = 0
    for first, last in pool_ranges(pools):
        cur.execute(
            f"SELECT COUNT(*) AS cnt FROM lease4 WHERE {ACTIVE_LEASE4} AND subnet_id=%s AND address BETWEEN %s AND %s",  # nosec B608 - a fixed constant
            (subnet_id, first, last),
        )
        used += int(cur.fetchone()["cnt"])
    return used
