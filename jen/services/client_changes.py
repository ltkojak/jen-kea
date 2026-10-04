"""
jen/services/client_changes.py
────────────────────────────────
v5.68.0-beta.1 (Q134 c) — the Investigation page's "Changes" tab: which Kea config changes touched THIS client's path.

`kea_config_revisions` (jen/services/config_revisions.py) holds every config Jen wrote to a Kea host, plus the external
edits it noticed, as encrypted canonical JSON. `/servers/<id>/config-history` shows each revision's whole-config diff; an
operator asking "why did this client's DNS server change on Tuesday" does not want to read forty of those. This module
answers for one client: for each of the newest revisions of each server it compares the revision with the one before it
over only the parts of the config that decide what THIS client gets, and keeps the revisions where something there moved.

The client's path (`ClientPath`, built from the resolved view) is: the subnet it is in (by id OR by CIDR — an id can be
renumbered, a CIDR is what the client is on), the shared network that subnet sits in, the pools its addresses fall in
(every pool of the subnet when it has no address yet), the classes that guard that path or that the client matches, its own
reservation (by MAC/DUID or by address — which carries any host-scoped option with it), and nothing else. A change to
another client's reservation in the same subnet, to another pool, or to a global option is NOT in the path and is not
shown — the tab says "touches this client", and means it. Each hit shows only the lines that moved inside the matching
element (a unified diff of that element alone, 3 lines of context), the revision's summary, who made it, when, and its
`source` (jen / external / restore / baseline).

A reservation kept in Kea's HOST DATABASE (the common Jen setup) is not in the config file at all, so a change to one
is not a config revision and never appears here; the tab shows config-file reservations, and says so on the page.

Access: revisions are admin content today (`/servers/<id>/config-history` needs an admin who may see every subnet) and the
tab follows that rule exactly — the route hides it otherwise; this module trusts its caller on that and shows MASKED
values (kea_authoring.redact_secrets) like the history page does.

COST. Every request decrypts and parses at most `NEWEST` + 1 revisions per (server, service), once each, and walks each
pair once. Measured on a dev box (Python 3.10, Fernet from `cryptography` 50) over 51 revisions of a 200-subnet config with
20 reservations each (about 500 KB in the stored canonical form): decrypt ≈ 0.06 s, JSON parse ≈ 0.05 s, path extraction
and diff over the 50 pairs ≈ 0.11 s — about 0.2 s per (server, service) for a config far bigger than a homelab's, so a
page with two servers and a dhcp6 pass is under a second. That is why the tab is its own tab, loaded only when it is the
active one, and why the window is capped; `tests/test_client_changes.py` times the pure part again on every run and fails
if it ever costs more than three seconds (a generous bound for a slow CI runner: it exists to catch a quadratic walk).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

NEWEST = 50  # revisions compared per (server, service): the newest NEWEST, each against its predecessor
MAX_LINES = 60  # diff lines shown per change; the rest is counted, not dropped silently

_SERVICES = {
    "dhcp4": {"root": "Dhcp4", "subnets": "subnet4", "address_key": "ip-address"},
    "dhcp6": {"root": "Dhcp6", "subnets": "subnet6", "address_key": "ip-addresses"},
}
_CLASS_KEYS = ("client-class", "client-classes", "require-client-classes", "evaluate-additional-classes")


@dataclass(frozen=True)
class ClientPath:
    """What decides what one client gets, in ONE service's numbering. Every identifier is already normalised: hex without
    separators, lowercase; addresses in canonical text; CIDRs canonical."""

    service: str  # "dhcp4" | "dhcp6"
    subnet_ids: frozenset = frozenset()
    cidrs: frozenset = frozenset()
    identifiers: frozenset = frozenset()  # MAC and/or DUID hex
    addresses: frozenset = frozenset()  # leased and reserved addresses
    classes: frozenset = frozenset()  # classes the client is known to match

    def is_empty(self) -> bool:
        return not (self.subnet_ids or self.cidrs or self.identifiers or self.addresses)


# ── normalisation ────────────────────────────────────────────────────────────


def _hex(value) -> str:
    """`aa:bb:cc`, `AA-BB-CC`, `aabbcc` -> `aabbcc`; anything that is not hex -> ''."""
    text = re.sub(r"[:\-. ]", "", str(value or "")).lower()
    return text if text and all(c in "0123456789abcdef" for c in text) else ""


def _addr(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _cidr(value) -> str:
    try:
        return str(ipaddress.ip_network(str(value or "").strip(), strict=False))
    except ValueError:
        return ""


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


# ── building the path from a resolved view ───────────────────────────────────


def path_for(view, service: str, subnet_map: dict, subnet6_map: dict, classes=()) -> ClientPath:
    """The client's path in `service`'s numbering, from an already authorized `ClientSubject`. `subnet_map` /
    `subnet6_map` are `extensions.SUBNET_MAP` / `SUBNET6_MAP` (id -> {"cidr": ...}); `classes` the class names the Explain
    evaluation said the client matches."""
    if service == "dhcp4":
        ids = {int(r["subnet_id"]) for r in [*view.leases4, *view.reservations] if r.get("subnet_id")}
        if view.device and view.device.get("last_subnet_id"):
            ids.add(int(view.device["last_subnet_id"]))
        cidrs = {_cidr((subnet_map.get(i) or {}).get("cidr")) for i in ids} - {""}
        identifiers = {_hex(view.mac)} - {""}
        addresses = {_addr(r.get("ip")) for r in [*view.leases4, *view.reservations]} - {""}
        if view.kind == "ipv4":
            addresses.add(_addr(view.identifier))
            addresses.discard("")
    else:
        rows = [*view.leases6, *view.reservations6]
        ids = {int(r["subnet_id"]) for r in rows if r.get("subnet_id")}
        cidrs = {_cidr((subnet6_map.get(i) or {}).get("cidr")) for i in ids} - {""}
        identifiers = {_hex(view.duid), _hex(view.mac)} - {""}
        addresses = {_addr(a.get("address")) for a in view.leases6}
        for host in view.reservations6:
            addresses |= {_addr(r.get("address")) for r in host.get("reservations", [])}
            identifiers.add(_hex(host.get("duid_hex")))
        addresses -= {""}
        identifiers -= {""}
    return ClientPath(
        service=service,
        subnet_ids=frozenset(ids),
        cidrs=frozenset(cidrs),
        identifiers=frozenset(identifiers),
        addresses=frozenset(addresses),
        classes=frozenset(c for c in classes if c),
    )


# ── the path through ONE config ──────────────────────────────────────────────


def _inner(cfg, service: str) -> dict:
    """The `Dhcp4`/`Dhcp6` map of a stored config (the file's own shape wraps it; an already-inner dict is accepted)."""
    if not isinstance(cfg, dict):
        return {}
    root = cfg.get(_SERVICES[service]["root"])
    return root if isinstance(root, dict) else cfg


def _pool_contains(pool_text: str, addresses) -> bool | None:
    """Does a Kea pool (`a - b` range or a CIDR) contain any of `addresses`? None when the pool cannot be parsed."""
    text = str(pool_text or "").strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return any(ipaddress.ip_address(a) in net for a in addresses if (":" in a) == (net.version == 6))
        lo, hi = (part.strip() for part in text.split("-", 1))
        lo_a, hi_a = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
        return any(lo_a <= ipaddress.ip_address(a) <= hi_a for a in addresses if (":" in a) == (lo_a.version == 6))
    except ValueError:
        return None


def _reservation_matches(res: dict, path: ClientPath) -> bool:
    if not isinstance(res, dict):
        return False
    for key in ("hw-address", "duid", "client-id"):
        if _hex(res.get(key)) and _hex(res.get(key)) in path.identifiers:
            return True
    keys = (_SERVICES[path.service]["address_key"], "ip-address", "ip-addresses", "prefixes")
    for key in keys:
        for value in _as_list(res.get(key)):
            if _addr(str(value).split("/")[0]) in path.addresses:
                return True
    return False


def _classes_named(element: dict) -> set:
    names = set()
    if isinstance(element, dict):
        for key in _CLASS_KEYS:
            names |= {str(c) for c in _as_list(element.get(key)) if c}
    return names


def _without(element: dict, *keys) -> dict:
    return {k: v for k, v in element.items() if k not in keys}


def extract(cfg, path: ClientPath) -> dict:
    """{label: value} — the parts of `cfg` that are on `path`. Pure. Two configs are compared label by label."""
    spec = _SERVICES[path.service]
    inner = _inner(cfg, path.service)
    out: dict = {}
    referenced: set = set(path.classes)

    def matched_subnet(subnet) -> bool:
        if not isinstance(subnet, dict):
            return False
        sid = subnet.get("id")
        cidr = _cidr(subnet.get("subnet"))
        return (isinstance(sid, int) and sid in path.subnet_ids) or (bool(cidr) and cidr in path.cidrs)

    contexts = [(None, s) for s in inner.get(spec["subnets"]) or []]
    for network in inner.get("shared-networks") or []:
        if isinstance(network, dict):
            contexts += [(network, s) for s in network.get(spec["subnets"]) or []]

    seen_networks: set = set()
    for network, subnet in contexts:
        if not matched_subnet(subnet):
            continue
        name = subnet.get("subnet") or subnet.get("id")
        where = (
            f"subnet {subnet.get('id')} ({subnet.get('subnet')})" if subnet.get("id") is not None else f"subnet {name}"
        )
        out[where] = _without(subnet, "pools", "pd-pools", "reservations")
        referenced |= _classes_named(subnet)
        for pool_key in ("pools", "pd-pools"):
            for pool in subnet.get(pool_key) or []:
                text = (pool or {}).get("pool") or (pool or {}).get("prefix") or ""
                inside = _pool_contains(text, path.addresses) if path.addresses and pool_key == "pools" else None
                if inside is False:
                    continue  # a pool the client's addresses are not in (None = cannot tell, or no address yet: keep it)
                out[f"pool {text}"] = pool
                referenced |= _classes_named(pool)
        for res in subnet.get("reservations") or []:
            if _reservation_matches(res, path):
                out[f"reservation {_reservation_label(res)}"] = res
                referenced |= _classes_named(res)
        if network is not None and id(network) not in seen_networks:
            seen_networks.add(id(network))
            out[f"shared network {network.get('name')}"] = _without(network, spec["subnets"])
            referenced |= _classes_named(network)

    for res in inner.get("reservations") or []:  # global reservations, outside any subnet
        if _reservation_matches(res, path):
            out[f"global reservation {_reservation_label(res)}"] = res
            referenced |= _classes_named(res)

    for definition in inner.get("client-classes") or []:
        if isinstance(definition, dict) and definition.get("name") in referenced:
            out[f"class {definition['name']}"] = definition
    return out


def _reservation_label(res: dict) -> str:
    for key in ("hw-address", "duid", "client-id", "ip-address"):
        if res.get(key):
            return str(res[key])
    for key in ("ip-addresses", "prefixes"):
        if res.get(key):
            return str(_as_list(res[key])[0])
    return "(unkeyed)"


# ── comparing two configs ────────────────────────────────────────────────────


def _canonical(value) -> str:
    from jen.services import config_revisions as rev
    from jen.services.kea_authoring import redact_secrets

    return rev.canonical(redact_secrets(value))


def diff_paths(before: dict, after: dict, path: ClientPath) -> list[dict]:
    """The changes on `path` between two parsed configs: [{label, kind: added|removed|changed, lines, more}], in label order,
    `lines` being the unified diff of that ONE element (headers dropped), capped at MAX_LINES with `more` counting the rest."""
    from jen.services import config_revisions as rev

    old, new = extract(before, path), extract(after, path)
    changes = []
    for label in sorted(old.keys() | new.keys()):
        if label in old and label in new:
            if old[label] == new[label]:
                continue
            kind = "changed"
        else:
            kind = "added" if label in new else "removed"
        diff = rev.diff(
            _canonical(old[label]) if label in old else "",
            _canonical(new[label]) if label in new else "",
            "before",
            "after",
        )
        lines = [line for line in diff if not line.startswith(("---", "+++"))]
        changes.append(
            {"label": label, "kind": kind, "lines": lines[:MAX_LINES], "more": max(0, len(lines) - MAX_LINES)}
        )
    return changes


def changes_for_revisions(rows: list[dict], path: ClientPath, limit: int = NEWEST) -> dict:
    """Walk revisions (newest first, each row's `config` already DECRYPTED text) and keep the ones that touched `path`.
    Pure but for the JSON parse. `rows` should hold up to limit + 1 revisions: the oldest has no predecessor in the window
    and is only the 'before' of the one above it. Returns {"scanned": n, "revisions": [...], "oldest_unpaired": bool}."""
    import json

    parsed: dict[int, object] = {}

    def config_of(index: int):
        if index not in parsed:
            try:
                parsed[index] = json.loads(rows[index]["config"])
            except (TypeError, ValueError):
                parsed[index] = None
        return parsed[index]

    hits = []
    scanned = min(limit, max(0, len(rows) - 1))
    for i in range(scanned):
        after, before = config_of(i), config_of(i + 1)
        if after is None or before is None:
            continue
        changes = diff_paths(before, after, path)
        if changes:
            row = rows[i]
            hits.append(
                {
                    "id": row["id"],
                    "created_at": row.get("created_at"),
                    "summary": row.get("summary") or "",
                    "username": row.get("username") or "",
                    "source": row.get("source") or "",
                    "changes": changes,
                }
            )
    return {"scanned": scanned, "revisions": hits, "oldest_unpaired": len(rows) <= limit}


# ── the impure edge ──────────────────────────────────────────────────────────


def for_view(view, servers, *, subnet_map, subnet6_map, ipv6_on: bool, classes=()) -> dict:
    """The Changes tab for an authorized view: one group per (server, service) that has revisions. Never raises — a server
    whose history cannot be read is a group with an `error`, not a broken page. `servers` is `extensions.KEA_SERVERS`."""
    from jen.services import config_revisions as rev
    from jen.services.crypto import SecretDecryptError

    services = ["dhcp4"]
    if ipv6_on and (view.leases6 or view.reservations6):
        services.append("dhcp6")
    groups = []
    for service in services:
        path = path_for(view, service, subnet_map, subnet6_map, classes if service == "dhcp4" else ())
        if path.is_empty():
            continue
        for server in servers or []:
            group = {
                "server_id": server.get("id"),
                "server_name": server.get("name") or f"Server {server.get('id')}",
                "service": service,
                "scanned": 0,
                "revisions": [],
                "oldest_unpaired": False,
                "error": "",
            }
            try:
                rows = rev.recent_with_config(server["id"], service, NEWEST + 1)
                group.update(changes_for_revisions(rows, path))
                group["has_history"] = bool(rows)
            except SecretDecryptError as exc:
                group["error"] = str(exc)
            except Exception as exc:  # a malformed row must not take the page down
                logger.error(f"client_changes: {service} history of server {server.get('id')} failed: {exc}")
                group["error"] = "Could not read this server's config history — see the server log."
            groups.append(group)
    return {"groups": groups, "newest": NEWEST}
