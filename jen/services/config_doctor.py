"""
jen/services/config_doctor.py
──────────────────────────────
v5.40.0 (Q41) — semantic checks on the live Kea config: things
`kea-dhcp4 -t` never catches because they're valid syntax and valid
types, just contradictory or pointless (an overlapping pool, a
reservation two subnets disagree about, a client class nothing ever
attaches, a guard that can never be true). Pure — no I/O, no Flask;
the route/Health check load the config, the reservation rows and (for
one HA check) both servers' configs and hand them in.

Every finding carries its reasoning in `why` — the point of this page
is teaching, not just flagging. Does NOT re-implement expression
evaluation: `class_unreachable` and `class_unknown_member` reuse
jen/services/dhcp_explain.py's parser, so what Jen can and can't
reason about here always matches what Explain can and can't reason
about.
"""

from __future__ import annotations

import ipaddress

from jen.services import dhcp_explain as _explain
from jen.services import dhcp_options as _opts
from jen.services import kea_classes as _classes
from jen.services import kea_config_view as _view
from jen.services import kea_readiness as _readiness

Finding = dict  # {id, severity, title, detail, where, fix_url, why}

_SEVERITY_ORDER = {"fail": 0, "warn": 1, "info": 2}


def _finding(id_, severity, title, detail, where, fix_url="", why="") -> Finding:
    return {
        "id": id_,
        "severity": severity,
        "title": title,
        "detail": detail,
        "where": where,
        "fix_url": fix_url,
        "why": why,
    }


def _pool_range(pool_str: str) -> tuple[int, int] | None:
    """A pool's (first, last) address as ints, or None if unparseable —
    Kea accepts both 'a.b.c.d - a.b.c.e' and a bare CIDR as a pool."""
    s = (pool_str or "").strip()
    if not s:
        return None
    if "-" in s:
        a, b = (p.strip() for p in s.split("-", 1))
        try:
            return int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))
        except ValueError:
            return None
    try:
        net = ipaddress.IPv4Network(s, strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except ValueError:
        return None


def _subnet_range(cidr: str) -> tuple[int, int] | None:
    try:
        net = ipaddress.IPv4Network((cidr or "").strip(), strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except (ValueError, TypeError):
        return None


def _ip_to_int(ip: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address((ip or "").strip()))
    except ValueError:
        return None


def _pools(subnet: dict) -> list[dict]:
    return [p for p in (subnet.get("pools") or []) if isinstance(p, dict)]


# ── pools ─────────────────────────────────────────────────────────────────────


def _check_pools_overlap(dhcp4_cfg, hosts) -> list[Finding]:
    out = []

    def _ranges(subnets):
        rows = []
        for s in subnets:
            for p in _pools(s):
                r = _pool_range(p.get("pool"))
                if r:
                    rows.append((r, s.get("id"), p.get("pool")))
        return sorted(rows, key=lambda row: row[0])

    # Within each subnet, and across the subnets of each shared network —
    # two separate scopes, since a top-level subnet's pools can't collide
    # with another top-level subnet's (different broadcast domains).
    groups: list[list[dict]] = []
    top = [s for s, sn in _view.iter_subnet4(dhcp4_cfg) if sn is None]
    for s in top:
        groups.append([s])
    seen_networks: dict[str, list] = {}
    for s, sn in _view.iter_subnet4(dhcp4_cfg):
        if sn is not None:
            seen_networks.setdefault(sn, []).append(s)
    groups.extend(seen_networks.values())

    for group in groups:
        ranges = _ranges(group)
        for i in range(len(ranges) - 1):
            (start1, end1), sid1, pool1 = ranges[i]
            (start2, end2), sid2, pool2 = ranges[i + 1]
            if start2 <= end1:
                if sid1 == sid2:
                    where = f"subnet {sid1}"
                    detail = f"Pool {pool1!r} overlaps pool {pool2!r} in subnet {sid1}"
                else:
                    where = f"subnets {sid1} and {sid2}"
                    detail = f"Subnet {sid1} pool {pool1!r} overlaps subnet {sid2} pool {pool2!r}"
                out.append(
                    _finding(
                        "pools_overlap",
                        "fail",
                        "Pools overlap",
                        detail,
                        where,
                        "/subnets",
                        "Kea refuses to load a config with overlapping pools — one of these two ranges must be "
                        "narrowed or removed.",
                    )
                )
    return out


def _check_pool_outside_subnet(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    for s, _sn in _view.iter_subnet4(dhcp4_cfg):
        subnet_range = _subnet_range(s.get("subnet"))
        if subnet_range is None:
            continue
        lo, hi = subnet_range
        for p in _pools(s):
            r = _pool_range(p.get("pool"))
            if r is None:
                continue
            if r[0] < lo or r[1] > hi:
                out.append(
                    _finding(
                        "pool_outside_subnet",
                        "fail",
                        "Pool outside its subnet",
                        f"Pool {p.get('pool')!r} is not entirely inside {s.get('subnet')}",
                        f"subnet {s.get('id')}",
                        "/subnets",
                        "Kea refuses to load a config where a pool's range falls outside the subnet prefix that "
                        "declares it.",
                    )
                )
    return out


def _check_contradictory_pool_guards(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    class_tests = {
        c.get("name"): c.get("test")
        for c in (dhcp4_cfg.get("client-classes") or [])
        if isinstance(c, dict) and c.get("name")
    }

    def _ast(name):
        test = class_tests.get(name)
        if not test:
            return None
        try:
            return _explain.parse_expression(test)
        except _explain.ExprError:
            return None

    for s, _sn in _view.iter_subnet4(dhcp4_cfg):
        subnet_guards = _classes.guard_classes(s)
        for p in _pools(s):
            for pool_guard in _classes.guard_classes(p):
                pool_ast = _ast(pool_guard)
                for subnet_guard in subnet_guards:
                    subnet_ast = _ast(subnet_guard)
                    negates = (pool_ast is not None and pool_ast == ("not", subnet_ast)) or (
                        subnet_ast is not None and subnet_ast == ("not", pool_ast)
                    )
                    if negates:
                        out.append(
                            _finding(
                                "contradictory_pool_guards",
                                "fail",
                                "Pool guard contradicts its subnet's guard",
                                f"Pool {p.get('pool')!r} requires class {pool_guard!r} but subnet {s.get('id')} "
                                f"requires class {subnet_guard!r}, whose test is the exact negation of "
                                f"{pool_guard!r}'s — no client can ever satisfy both",
                                f"subnet {s.get('id')}",
                                "/subnets",
                                "A pool's guard classes must be satisfiable at the same time as its subnet's — "
                                "one of them tests the exact negation of the other, so this pool can never be "
                                "reached.",
                            )
                        )
    return out


def _check_subnet_without_pools_or_reservations(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    by_subnet: dict[int, list] = {}
    for h in hosts or []:
        by_subnet.setdefault(h.get("subnet_id"), []).append(h)
    for s, _sn in _view.iter_subnet4(dhcp4_cfg):
        sid = s.get("id")
        if not _pools(s) and not by_subnet.get(sid):
            out.append(
                _finding(
                    "subnet_without_pools_or_reservations",
                    "warn",
                    "Subnet has nothing to hand out",
                    f"Subnet {sid} ({s.get('subnet')}) has no pools and no reservations",
                    f"subnet {sid}",
                    "/subnets",
                    "A subnet with neither a pool nor a reservation never gives out an address — every request "
                    "in it gets no offer.",
                )
            )
    return out


# ── reservations ────────────────────────────────────────────────────────────


def _check_reservation_outside_subnet(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    for h in hosts or []:
        sid, ip = h.get("subnet_id"), h.get("ip")
        if not sid or not ip:
            continue
        found = _view.subnet4_by_id(dhcp4_cfg, sid)
        if found is None:
            continue
        subnet, _sn = found
        subnet_range = _subnet_range(subnet.get("subnet"))
        ip_int = _ip_to_int(ip)
        if subnet_range is None or ip_int is None:
            continue
        if not (subnet_range[0] <= ip_int <= subnet_range[1]):
            out.append(
                _finding(
                    "reservation_outside_subnet",
                    "fail",
                    "Reservation address outside its subnet",
                    f"Reservation {ip} is filed under subnet {sid} ({subnet.get('subnet')}) but is not inside it",
                    f"subnet {sid}",
                    f"/reservations?search={ip}",
                    "Kea matches a reservation's subnet by the request's subnet, not the reserved address — an "
                    "address outside that subnet's prefix can never actually be assigned.",
                )
            )
    return out


def _check_reservation_inside_pool(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    for h in hosts or []:
        sid, ip = h.get("subnet_id"), h.get("ip")
        if not sid or not ip:
            continue
        found = _view.subnet4_by_id(dhcp4_cfg, sid)
        if found is None:
            continue
        subnet, _sn = found
        ip_int = _ip_to_int(ip)
        if ip_int is None:
            continue
        inside_pool = any((r := _pool_range(p.get("pool"))) and r[0] <= ip_int <= r[1] for p in _pools(subnet))
        if not inside_pool:
            continue
        out_of_pool = bool(subnet.get("reservations-out-of-pool", dhcp4_cfg.get("reservations-out-of-pool", False)))
        out.append(
            _finding(
                "reservation_inside_pool",
                "warn" if out_of_pool else "info",
                "Reservation address is inside a dynamic pool",
                f"Reservation {ip} (subnet {sid}) falls inside one of the subnet's pools",
                f"subnet {sid}",
                f"/reservations?search={ip}",
                (
                    "reservations-out-of-pool is on for this subnet, which tells Kea every reservation sits "
                    "outside the dynamic range — this one doesn't, and Kea will refuse to honour it."
                    if out_of_pool
                    else "Common and fine — Kea excludes a reserved address from dynamic allocation automatically. "
                    "Flagged only so you know it's there."
                ),
            )
        )
    return out


def _check_duplicate_reservations(dhcp4_cfg, hosts) -> list[Finding]:
    out = []
    by_identifier: dict[tuple, list] = {}
    by_address: dict[tuple, list] = {}
    for h in hosts or []:
        sid = h.get("subnet_id")
        ident_key = (sid, h.get("identifier_type"), (h.get("identifier") or "").lower())
        by_identifier.setdefault(ident_key, []).append(h)
        if h.get("ip"):
            by_address.setdefault((sid, h["ip"]), []).append(h)

    for (sid, _itype, ident), rows in by_identifier.items():
        if len(rows) > 1 and ident:
            out.append(
                _finding(
                    "duplicate_reservation_identifier",
                    "fail",
                    "Same identifier reserved twice in one subnet",
                    f"{len(rows)} reservations in subnet {sid} share identifier {ident}",
                    f"subnet {sid}",
                    "/reservations",
                    "Kea's host database has a unique constraint per (subnet, identifier) — only one of these "
                    "will actually be in effect; the rest are dead entries or a failed earlier write.",
                )
            )
    for (sid, ip), rows in by_address.items():
        if len(rows) > 1:
            out.append(
                _finding(
                    "duplicate_reservation_address",
                    "fail",
                    "Same address reserved twice in one subnet",
                    f"{len(rows)} reservations in subnet {sid} share address {ip}",
                    f"subnet {sid}",
                    f"/reservations?search={ip}",
                    "Two clients can't both be handed the same fixed address — one of these reservations will "
                    "never actually get it.",
                )
            )
    return out


# ── client classes ───────────────────────────────────────────────────────────


def _collect_members(node, out: set[str]) -> None:
    kind = node[0]
    if kind == "member":
        out.add(node[1])
    elif kind in ("and", "or"):
        _collect_members(node[1], out)
        _collect_members(node[2], out)
    elif kind == "not":
        _collect_members(node[1], out)


def _check_class_unknown_member(dhcp4_cfg) -> list[Finding]:
    out = []
    names = {c.get("name") for c in (dhcp4_cfg.get("client-classes") or []) if isinstance(c, dict)}
    for c in dhcp4_cfg.get("client-classes") or []:
        if not isinstance(c, dict) or not c.get("test"):
            continue
        try:
            ast = _explain.parse_expression(c["test"])
        except _explain.ExprError:
            continue
        members: set[str] = set()
        _collect_members(ast, members)
        for m in sorted(members - names):
            out.append(
                _finding(
                    "class_unknown_member",
                    "fail",
                    "member() references an undefined class",
                    f"Class {c.get('name')!r} tests member({m!r}), but no class named {m!r} is defined",
                    f"class {c.get('name')}",
                    "/subnets/classes",
                    "Kea evaluates member() against classes assigned earlier in the config-order list; a name "
                    "that matches nothing never evaluates true, so this test can never pass through that clause.",
                )
            )
    return out


def _check_class_unreferenced(dhcp4_cfg) -> list[Finding]:
    out = []
    for c in dhcp4_cfg.get("client-classes") or []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        name = c["name"]
        if _classes.is_builtin(name):
            continue
        if _classes.references(dhcp4_cfg, name):
            continue
        out.append(
            _finding(
                "class_unreferenced",
                "info",
                "Class is never attached anywhere",
                f"Class {name!r} is defined but no subnet, pool, shared network or other class's member() uses it",
                f"class {name}",
                "/subnets/classes",
                "Kea still evaluates every defined class's test on every packet even if nothing guards on it — "
                "harmless, but it's dead configuration and a small amount of wasted work per packet.",
            )
        )
    return out


def _check_class_unreachable(dhcp4_cfg) -> list[Finding]:
    """A guard class whose test AND-chains the same accessor against two
    different literal values — no client can ever satisfy both at once.
    Only the flat AND case (no nested or/not) is checked; anything else
    is outside what this can prove constant-false without risking a
    false positive."""
    out = []
    for c in dhcp4_cfg.get("client-classes") or []:
        if not isinstance(c, dict) or not c.get("test") or not c.get("name"):
            continue
        try:
            ast = _explain.parse_expression(c["test"])
        except _explain.ExprError:
            continue
        leaves = []
        stack = [ast]
        flat_and = True
        while stack:
            node = stack.pop()
            if node[0] == "and":
                stack.append(node[1])
                stack.append(node[2])
            elif node[0] == "eq":
                leaves.append(node)
            else:
                flat_and = False
                break
        if not flat_and or len(leaves) < 2:
            continue
        seen: dict[tuple, bytes] = {}
        contradiction = False
        for _eq, operand, lit in leaves:
            key = operand
            if key in seen and seen[key] != lit[1]:
                contradiction = True
                break
            seen[key] = lit[1]
        if contradiction:
            out.append(
                _finding(
                    "class_unreachable",
                    "info",
                    "Class test can never be true",
                    f"Class {c.get('name')!r}'s test requires the same field to equal two different values at once",
                    f"class {c.get('name')}",
                    "/subnets/classes",
                    "Every clause is joined with `and`, and two of them pin the same field to different "
                    "literals — no packet can satisfy both, so this class never matches.",
                )
            )
    return out


# ── lease timers / options / shared networks ─────────────────────────────────


def _effective(scope: dict, key: str, dhcp4_cfg: dict):
    if isinstance(scope, dict) and scope.get(key) is not None:
        return scope[key]
    return dhcp4_cfg.get(key)


def _check_lease_timers(dhcp4_cfg) -> list[Finding]:
    out = []
    scopes = [(dhcp4_cfg, "global")] + [(s, f"subnet {s.get('id')}") for s, _sn in _view.iter_subnet4(dhcp4_cfg)]
    for scope, label in scopes:
        valid = _effective(scope, "valid-lifetime", dhcp4_cfg)
        renew = _effective(scope, "renew-timer", dhcp4_cfg)
        rebind = _effective(scope, "rebind-timer", dhcp4_cfg)
        if valid is not None and renew is not None and rebind is not None and (renew >= rebind or rebind >= valid):
            out.append(
                _finding(
                    "lease_timers",
                    "warn",
                    "Lease timers out of order",
                    f"{label}: renew-timer={renew} rebind-timer={rebind} valid-lifetime={valid} "
                    "(expected renew < rebind < valid)",
                    label,
                    "/subnets",
                    "Kea expects renew-timer < rebind-timer < valid-lifetime — out of order, a client can "
                    "reach rebind or even expiry before it was ever told to renew.",
                )
            )
        if valid is not None:
            if valid < 60:
                out.append(
                    _finding(
                        "lease_timers",
                        "warn",
                        "Lease time very short",
                        f"{label}: valid-lifetime={valid}s",
                        label,
                        "/subnets",
                        "Under a minute means every client is renewing almost constantly — usually a typo (seconds "
                        "vs. minutes) rather than intentional.",
                    )
                )
            elif valid > 30 * 86400:
                out.append(
                    _finding(
                        "lease_timers",
                        "info",
                        "Lease time very long",
                        f"{label}: valid-lifetime={valid}s (~{valid // 86400} days)",
                        label,
                        "/subnets",
                        "Over 30 days means a stale/offline client holds its address for a long time before Kea "
                        "reclaims it — fine if that's intentional for a small, stable network.",
                    )
                )
    return out


def _check_global_option_shadowed(dhcp4_cfg) -> list[Finding]:
    out = []
    subnets = [s for s, _sn in _view.iter_subnet4(dhcp4_cfg)]
    if not subnets:
        return out
    global_opts = _opts._opts(dhcp4_cfg)
    for o in global_opts:
        key = _opts.entry_key(o)
        if all(any(_opts.entry_key(so) == key for so in _opts._opts(s)) for s in subnets):
            code, name = _opts._display(o)
            out.append(
                _finding(
                    "global_option_shadowed_everywhere",
                    "info",
                    "Global option is never actually used",
                    f"Option {name} ({code}) is set globally, but every subnet overrides it with its own value",
                    "global",
                    "/settings/kea",
                    "Every subnet supplies its own value for this option, so the global one never wins for any "
                    "client — safe to remove if it isn't there as a documented fallback.",
                )
            )
    return out


def _check_shared_network_asymmetry(dhcp4_cfg) -> list[Finding]:
    out = []
    for sn in _view.shared_networks4_raw(dhcp4_cfg):
        name = sn.get("name")
        members = [s for s, sn_name in _view.iter_subnet4(dhcp4_cfg) if sn_name == name]
        if len(members) < 2:
            continue
        lifetimes = {_effective(s, "valid-lifetime", dhcp4_cfg) for s in members}
        lifetimes.discard(None)

        def _routers(s):
            for o in _opts._opts(s):
                if o.get("name") == "routers" or o.get("code") == 3:
                    return o.get("data")
            return None

        routers = {_routers(s) for s in members}
        routers.discard(None)
        if len(lifetimes) > 1:
            out.append(
                _finding(
                    "shared_network_asymmetry",
                    "info",
                    "Shared network members disagree on lease time",
                    f"Shared network {name!r} subnets have different valid-lifetime values: {sorted(lifetimes)}",
                    f"shared network {name}",
                    "/subnets",
                    "Members of a shared network usually share client-facing behavior — different lease times "
                    "means a client sees a different renewal cadence purely from which subnet it lands in.",
                )
            )
        if len(routers) > 1:
            out.append(
                _finding(
                    "shared_network_asymmetry",
                    "info",
                    "Shared network members disagree on gateway",
                    f"Shared network {name!r} subnets have different routers option values",
                    f"shared network {name}",
                    "/subnets",
                    "Members of a shared network are meant to be one broadcast domain — different gateways "
                    "usually means one of them is misconfigured, not that it's intentional.",
                )
            )
    return out


# ── HA ────────────────────────────────────────────────────────────────────────

_HA_SCALAR_KEYS = (
    "mode",
    "heartbeat_delay",
    "max_response_delay",
    "max_ack_delay",
    "max_unacked_clients",
    "send_lease_updates",
    "sync_leases",
)


def _check_ha_peer_semantic_diff(ha_configs) -> list[Finding]:
    out = []
    if not ha_configs:
        return out
    configs = [c for c in ha_configs.values() if c]
    if len(configs) != 2:
        return out
    a, b = configs
    diffs = [k for k in _HA_SCALAR_KEYS if a.get(k) != b.get(k)]

    def _peer_roles(cfg):
        return sorted((p.get("role"), p.get("name")) for p in cfg.get("peers", []) if isinstance(p, dict))

    if _peer_roles(a) != _peer_roles(b):
        diffs.append("peers")
    if diffs:
        out.append(
            _finding(
                "ha_peer_semantic_diff",
                "warn",
                "HA peers disagree on configuration",
                f"The two servers' high-availability settings differ: {', '.join(diffs)}",
                "global",
                "/servers",
                "Kea's HA hook expects both peers to run essentially the same high-availability configuration — "
                "a mismatch here (rather than in Kea version) usually means one server's config didn't get "
                "the same edit the other one did.",
            )
        )
    return out


# ── removed keys ─────────────────────────────────────────────────────────────


def _check_removed_keys(dhcp4_cfg) -> list[Finding]:
    out = []
    for f in _readiness.scan_removed_keys(dhcp4_cfg):
        out.append(
            _finding(
                "removed_keys",
                "warn",
                "Config key removed or renamed in a newer Kea",
                f"{f['path']} → replaced by {f['replacement']} (since Kea {f['since']})",
                f["path"],
                "/health-center",
                f["hint"],
            )
        )
    return out


def group_findings(findings: list[Finding]) -> list[dict]:
    """Collapse findings that are the same KIND — same check id and severity — into
    one group, in order of first appearance (diagnose() already sorts most severe
    first). 68 identical "Reservation address is inside a dynamic pool" notes become
    ONE row with a count and a list, sharing the `why` once. Pure; the API keeps
    returning the flat findings.

    Each group: {id, severity, title, why, fix_url, count, items: [{where, detail}]}."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        key = (f["id"], f["severity"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "id": f["id"],
                "severity": f["severity"],
                "title": f["title"],
                "why": f.get("why", ""),
                "fix_url": f.get("fix_url", ""),
                "count": 0,
                "items": [],
            }
        g["count"] += 1
        g["items"].append({"where": f.get("where", ""), "detail": f.get("detail", "")})
    return list(groups.values())


# ── entry point ───────────────────────────────────────────────────────────────


def diagnose(
    dhcp4_cfg: dict | None,
    hosts: list[dict] | None = None,
    lease_history_summary=None,
    ha_configs: dict | None = None,
) -> list[Finding]:
    """Every finding for the given config, most severe first. `hosts` is
    reservation rows from Kea's host database — {subnet_id,
    identifier_type, identifier, ip, hostname} — not the config file's
    own (rare) inline reservations. `ha_configs`, when given, is
    {server_id: kea_ha.ha_config() result} for every configured server;
    the HA-comparison finding only fires with exactly two non-null
    entries. `lease_history_summary` is accepted for forward
    compatibility but not used by any check yet."""
    out: list[Finding] = []
    out += _check_ha_peer_semantic_diff(ha_configs)
    if not dhcp4_cfg:
        out.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 3))
        return out
    hosts = hosts or []
    out += _check_pools_overlap(dhcp4_cfg, hosts)
    out += _check_pool_outside_subnet(dhcp4_cfg, hosts)
    out += _check_contradictory_pool_guards(dhcp4_cfg, hosts)
    out += _check_subnet_without_pools_or_reservations(dhcp4_cfg, hosts)
    out += _check_reservation_outside_subnet(dhcp4_cfg, hosts)
    out += _check_reservation_inside_pool(dhcp4_cfg, hosts)
    out += _check_duplicate_reservations(dhcp4_cfg, hosts)
    out += _check_class_unknown_member(dhcp4_cfg)
    out += _check_class_unreferenced(dhcp4_cfg)
    out += _check_class_unreachable(dhcp4_cfg)
    out += _check_lease_timers(dhcp4_cfg)
    out += _check_global_option_shadowed(dhcp4_cfg)
    out += _check_shared_network_asymmetry(dhcp4_cfg)
    out += _check_removed_keys(dhcp4_cfg)
    out.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 3))
    return out
