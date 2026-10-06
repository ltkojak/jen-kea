"""
jen/services/client_dns.py
───────────────────────────
v5.68.0-beta.11 (Q146) — which DNS records the Investigation page's DNS tab checks for one client.

The tab used to build its rows from `view.reservation` and `view.lease` - the FIRST v4 reservation and the newest v4 lease. A
resolved client can carry several of each (a reservation in two subnets, a lease and a reservation with different names, an
older lease that is still current) and, with IPv6 on, v6 reservations and leases of its own, so a record that was wrong for any
but the first was never looked at: the tab said "ok" about the one it happened to pick. Every record the caller may see is now a
row.

A row is a name and an address: A for a v4 address, AAAA for a v6 one (`dns_reconcile.reconcile` reads the record type from the
address). The same name and address named by a reservation and by a lease is one row whose source says both. The subject handed in
is already the caller's authorized view (`client_subject.authorize`), so nothing here filters by subnet; a row for a record the
caller may not see cannot exist. Pure.
"""

import ipaddress

DEFAULT_LIMIT = 20  # records checked per page: each is two resolver lookups, and the reconcile pool is bounded


def _canonical(address) -> str:
    try:
        return str(ipaddress.ip_address(str(address or "").strip()))
    except ValueError:
        return ""


def _candidates(view):
    """(name, address, source) for every record the subject carries, reservations first: v4 reservations and leases, then v6
    reservations (the address entries, not delegated prefixes) and v6 leases (IA_NA, not prefixes)."""
    for res in view.reservations or []:
        yield res.get("hostname"), res.get("ip"), "reservation"
    for lease in view.leases4 or []:
        yield lease.get("hostname"), lease.get("ip"), "lease"
    for host in view.reservations6 or []:
        for entry in host.get("reservations") or []:
            if entry.get("type_name") == "IA_NA" or (entry.get("type_name") is None and entry.get("address")):
                yield host.get("hostname"), entry.get("address"), "reservation"
    for lease in view.leases6 or []:
        if lease.get("type_name") in (None, "IA_NA"):
            yield lease.get("hostname"), lease.get("address"), "lease"


def records_for(view, limit: int = DEFAULT_LIMIT) -> tuple[list[dict], int]:
    """([{"name", "ip", "source"}, ...] capped at `limit`, total before the cap) - one row per distinct (name, address), in the
    order reservations (v4, v6) then leases (v4, v6) name them, the source reading "reservation, lease" when both do."""
    merged: dict[tuple[str, str], dict] = {}
    for name, address, source in _candidates(view):
        name = (name or "").strip()
        address = _canonical(address)
        if not name or not address:
            continue
        key = (name.lower(), address)
        if key in merged:
            sources = merged[key]["source"].split(", ")
            if source not in sources:
                merged[key]["source"] = ", ".join([*sources, source])
        else:
            merged[key] = {"name": name, "ip": address, "source": source}
    rows = list(merged.values())
    return rows[:limit], len(rows)
