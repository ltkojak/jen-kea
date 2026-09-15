"""
jen/services/dhcp_explain.py
────────────────────────────
v5.35.0 (Q34) — "Why did this client get this?": the decision path Kea
takes for one DHCPv4 client, reconstructed from the config Jen already
holds. Pure — no I/O, no Flask; the route loads the config, the
reservations and the lease and hands them in.

What it can and can't evaluate
──────────────────────────────
Kea has no dry-run command, so Jen evaluates class expressions itself —
but ONLY the grammar Jen's own rule builder emits
(jen/services/kea_classes.py::build_expression):

    <accessor> == '<string>'          <accessor> == 0x<hex>
    substring(<accessor>,0,<n>) == '<string>'
    member('<class>')
    (<clause>) and (<clause>) …       (<clause>) or (<clause>) …
    not (<body>)

with accessors option[60].hex, option[77].hex, option[12].text,
pkt4.mac, substring(pkt4.mac,0,3), option[61].hex, relay4[1].hex,
relay4[2].hex. Anything else (ifelse, concat, pkt4.transid, vendor
options, …) is reported verbatim as NOT EVALUABLE — the page says so
rather than guessing. A clause whose input the caller didn't supply is
UNKNOWN (three-valued logic), and the page says which input would
settle it.

Order of the decision (Kea ARM, "DHCPv4 server"):
  1. subnet selection (here: the operator's / the lease's subnet;
     giaddr, when given, is checked against relay addresses)
  2. reservation match → KNOWN / UNKNOWN
  3. class evaluation, config order; member() sees earlier classes;
     only-in-additional-list classes only where listed as additional
  4. subnet guards → eligible subnets in the shared network
  5. pool guards → eligible pools; the answer address
  6. option precedence: host > pool > subnet > shared network > class > global
"""

from __future__ import annotations

import ipaddress
import re

from jen.services import dhcp_options as _opts
from jen.services import kea_classes as _classes
from jen.services import kea_config_view as _view

# ── Expression grammar ────────────────────────────────────────────────────────

ACCESSORS = {
    "option[60].hex": ("vendor_class", "text"),
    "option[77].hex": ("user_class", "text"),
    "option[12].text": ("hostname", "text"),
    "pkt4.mac": ("mac", "mac"),
    "option[61].hex": ("client_id", "hex"),
    "relay4[1].hex": ("circuit_id", "text"),
    "relay4[2].hex": ("remote_id", "hex"),
}
INPUT_LABELS = {
    "vendor_class": "vendor class (option 60)",
    "user_class": "user class (option 77)",
    "hostname": "hostname (option 12)",
    "mac": "MAC address",
    "client_id": "client id (option 61)",
    "circuit_id": "relay circuit id",
    "remote_id": "relay remote id",
}

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<lpar>\()|(?P<rpar>\))|(?P<comma>,)|(?P<eq>==)"
    r"|(?P<str>'[^']*')|(?P<hex>0x[0-9A-Fa-f]+)|(?P<num>\d+)"
    r"|(?P<acc>option\[\d+\]\.(?:hex|text)|pkt4\.mac|relay4\[\d\]\.hex)"
    r"|(?P<kw>and|or|not|member|substring)"
    r")"
)


class ExprError(ValueError):
    """The expression is outside the grammar Jen can evaluate."""


def tokenize(text: str) -> list[tuple[str, str]]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise ExprError(f"unrecognised syntax at: {text[pos : pos + 20]!r}")
        pos = m.end()
        for kind, val in m.groupdict().items():
            if val is not None:
                out.append((kind, val))
                break
    return out


class _Parser:
    def __init__(self, tokens):
        self.t = tokens
        self.i = 0

    def peek(self, kind=None, val=None):
        if self.i >= len(self.t):
            return None
        k, v = self.t[self.i]
        if kind and k != kind:
            return None
        if val and v != val:
            return None
        return v

    def take(self, kind, val=None):
        if self.peek(kind, val) is None:
            raise ExprError(f"expected {val or kind} at token {self.i}")
        v = self.t[self.i][1]
        self.i += 1
        return v

    def parse(self):
        node = self.expr()
        if self.i != len(self.t):
            raise ExprError("trailing tokens")
        return node

    def expr(self):
        left = self.term()
        while self.peek("kw", "or") is not None:
            self.take("kw", "or")
            left = ("or", left, self.term())
        return left

    def term(self):
        left = self.factor()
        while self.peek("kw", "and") is not None:
            self.take("kw", "and")
            left = ("and", left, self.factor())
        return left

    def factor(self):
        if self.peek("kw", "not") is not None:
            self.take("kw", "not")
            return ("not", self.factor())
        if self.peek("lpar") is not None:
            self.take("lpar")
            node = self.expr()
            self.take("rpar")
            return node
        if self.peek("kw", "member") is not None:
            self.take("kw", "member")
            self.take("lpar")
            name = self.take("str")[1:-1]
            self.take("rpar")
            return ("member", name)
        return self.comparison()

    def operand(self):
        if self.peek("kw", "substring") is not None:
            self.take("kw", "substring")
            self.take("lpar")
            acc = self._accessor()
            self.take("comma")
            start = int(self.take("num"))
            self.take("comma")
            length = int(self.take("num"))
            self.take("rpar")
            if start != 0:
                raise ExprError("substring with a non-zero start")
            return ("substr", acc, length)
        return ("acc", self._accessor())

    def _accessor(self):
        acc = self.take("acc")
        if acc not in ACCESSORS:
            raise ExprError(f"accessor {acc} is outside the rule-builder vocabulary")
        return acc

    def comparison(self):
        left = self.operand()
        self.take("eq")
        if self.peek("str") is not None:
            lit = ("bytes", self.take("str")[1:-1].encode())
        elif self.peek("hex") is not None:
            lit = ("bytes", bytes.fromhex(self.take("hex")[2:]))
        else:
            raise ExprError("expected a quoted string or 0x… literal")
        return ("eq", left, lit)


def parse_expression(text: str):
    """AST for a build_expression()-shaped test string; ExprError otherwise."""
    return _Parser(tokenize(text)).parse()


# ── Evaluation (three-valued: True / False / None = unknown) ─────────────────


def _client_bytes(client: dict, accessor: str):
    """(bytes | None, input_name) — None when the caller didn't supply it."""
    if accessor not in ACCESSORS:
        raise ExprError(f"accessor {accessor} is not one Jen knows")
    field, kind = ACCESSORS[accessor]
    raw = client.get(field)
    if raw in (None, ""):
        return None, field
    raw = str(raw).strip()
    if kind == "text":
        return raw.encode(), field
    body = re.sub(r"[:\-\s]", "", raw)
    if kind == "mac":
        if not re.fullmatch(r"[0-9A-Fa-f]{12}", body):
            return None, field
        return bytes.fromhex(body), field
    # hex kind: accept hex (with or without separators); else treat as text
    if re.fullmatch(r"[0-9A-Fa-f]+", body) and len(body) % 2 == 0:
        return bytes.fromhex(body), field
    return raw.encode(), field


def _and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def evaluate(node, client: dict, members: dict, missing: set) -> bool | None:
    """`members` maps class name → True/False/None for classes evaluated
    so far (member() sees only earlier classes, as Kea does); `missing`
    collects the input names that would have settled an unknown."""
    kind = node[0]
    if kind == "and":
        return _and(evaluate(node[1], client, members, missing), evaluate(node[2], client, members, missing))
    if kind == "or":
        return _or(evaluate(node[1], client, members, missing), evaluate(node[2], client, members, missing))
    if kind == "not":
        v = evaluate(node[1], client, members, missing)
        return None if v is None else (not v)
    if kind == "member":
        return members.get(node[1])  # unknown class or later class → None
    if kind == "eq":
        left, lit = node[1], node[2]
        if left[0] == "acc":
            val, field = _client_bytes(client, left[1])
        else:
            val, field = _client_bytes(client, left[1])
            if val is not None:
                val = val[: left[2]]
        if val is None:
            missing.add(field)
            return None
        return val == lit[1]
    raise ExprError(f"unknown node {kind}")


# ── Reservations ─────────────────────────────────────────────────────────────


def reservation_flags(dhcp4_cfg: dict, subnet: dict) -> dict:
    """Effective {global, in_subnet} for a subnet — the 2.x keys with
    their defaults, the legacy `reservation-mode` mapped onto them, the
    subnet overriding the global setting."""
    flags = {"global": False, "in_subnet": True}
    for scope in (dhcp4_cfg, subnet):
        if not isinstance(scope, dict):
            continue
        mode = scope.get("reservation-mode")
        if mode == "global":
            flags = {"global": True, "in_subnet": False}
        elif mode == "disabled":
            flags = {"global": False, "in_subnet": False}
        elif mode in ("all", "out-of-pool"):
            flags = {"global": False, "in_subnet": True}
        if "reservations-global" in scope:
            flags["global"] = bool(scope["reservations-global"])
        if "reservations-in-subnet" in scope:
            flags["in_subnet"] = bool(scope["reservations-in-subnet"])
    return flags


def _norm_mac(mac) -> str:
    return re.sub(r"[:\-\s]", "", str(mac or "")).lower()


def _config_reservations(subnet: dict) -> list[dict]:
    out = []
    for r in subnet.get("reservations") or []:
        if not isinstance(r, dict):
            continue
        if r.get("hw-address"):
            out.append(
                {
                    "subnet_id": subnet.get("id"),
                    "identifier_type": "hw-address",
                    "identifier": _norm_mac(r["hw-address"]),
                    "ip": r.get("ip-address"),
                    "hostname": r.get("hostname", ""),
                    "classes": r.get("client-classes") or [],
                    "options": r.get("option-data") or [],
                    "source": "config file",
                }
            )
        elif r.get("client-id"):
            out.append(
                {
                    "subnet_id": subnet.get("id"),
                    "identifier_type": "client-id",
                    "identifier": _norm_mac(r["client-id"]),
                    "ip": r.get("ip-address"),
                    "hostname": r.get("hostname", ""),
                    "classes": r.get("client-classes") or [],
                    "options": r.get("option-data") or [],
                    "source": "config file",
                }
            )
    return out


def match_reservation(
    client: dict, candidates: list[dict], subnet_id: int, flags: dict, db_rows: list[dict]
) -> dict | None:
    """First reservation Kea would honour for this client in `subnet_id`:
    a subnet reservation (host DB or config file) by hw-address then
    client-id, else a global one when the subnet allows globals."""
    mac = _norm_mac(client.get("mac"))
    cid = _norm_mac(client.get("client_id"))
    rows = list(db_rows or [])
    for s in candidates:
        rows.extend(_config_reservations(s))

    def hit(r):
        if r.get("identifier_type") in ("hw-address", 0, "0") and mac and _norm_mac(r.get("identifier")) == mac:
            return True
        return bool(cid) and r.get("identifier_type") in ("client-id", 3, "3") and _norm_mac(r.get("identifier")) == cid

    if flags["in_subnet"]:
        for r in rows:
            if int(r.get("subnet_id") or 0) == int(subnet_id) and hit(r):
                return {**r, "scope": "subnet"}
    if flags["global"]:
        for r in rows:
            if int(r.get("subnet_id") or 0) == 0 and hit(r):
                return {**r, "scope": "global"}
    return None


# ── The decision ─────────────────────────────────────────────────────────────


def _pools(subnet: dict) -> list[dict]:
    return [p for p in subnet.get("pools") or [] if isinstance(p, dict)]


def _lifetime(dhcp4_cfg, sn, subnet, matched_class_dicts):
    for scope, label in (
        (subnet, "subnet"),
        (sn, "shared network"),
        *[(c, f"class {c.get('name')}") for c in matched_class_dicts],
        (dhcp4_cfg, "global"),
    ):
        if isinstance(scope, dict) and scope.get("valid-lifetime") is not None:
            return scope["valid-lifetime"], label
    return 7200, "Kea default"


def _merge_options(levels: list[tuple[str, list[dict]]]) -> list[dict]:
    """levels in ascending precedence; later wins. Rows carry provenance."""
    winners: dict = {}
    for source, rows in levels:
        for o in rows:
            if not isinstance(o, dict):
                continue
            key = _opts.entry_key(o)
            code, name = _opts._display(o)
            prev = winners.get(key)
            winners[key] = {
                "code": code,
                "name": name,
                "data": o.get("data", ""),
                "source": source,
                "overridden": (prev["overridden"] + [prev["source"]]) if prev else [],
            }

    def _sort(kv):
        (_space, key), _ = kv
        return (0, key) if isinstance(key, int) else (1, str(key))

    return [row for _k, row in sorted(winners.items(), key=_sort)]


def explain(
    dhcp4_cfg: dict, client: dict, *, subnet_id: int, reservations: list[dict] | None = None, lease: dict | None = None
) -> dict:
    """The decision path for `client` if it asked in `subnet_id`.
    `client`: {mac, client_id?, vendor_class?, user_class?, hostname?,
    circuit_id?, remote_id?, giaddr?}. `reservations`: host-DB rows
    {subnet_id, identifier_type ('hw-address'|'client-id' or 0|3),
    identifier, ip, hostname, classes, options} for this client (the
    caller looks them up by identifier). `lease`: the current lease row
    {ip, subnet_id, expires?} or None."""
    steps: list[dict] = []
    found = _view.subnet4_by_id(dhcp4_cfg, subnet_id)
    if found is None:
        return {"ok": False, "error": f"subnet {subnet_id} is not in the Kea config", "steps": steps}
    subnet, sn_name = found
    sn = next(
        (n for n in (dhcp4_cfg.get("shared-networks") or []) if isinstance(n, dict) and n.get("name") == sn_name), None
    )
    candidates = [s for s, name in _view.iter_subnet4(dhcp4_cfg) if name == sn_name] if sn_name else [subnet]
    # The operator's / lease's subnet first, then its siblings in config order.
    candidates = [subnet] + [s for s in candidates if s is not subnet]

    # 1. subnet selection
    how = "the subnet you chose" if not lease else "the subnet of the current lease"
    giaddr = str(client.get("giaddr") or "").strip()
    relay_note = ""
    if giaddr:
        try:
            g = ipaddress.IPv4Address(giaddr)
            relay_ips = []
            r = subnet.get("relay") or {}
            if isinstance(r, dict):
                relay_ips = r.get("ip-addresses") or ([r["ip-address"]] if r.get("ip-address") else [])
            if giaddr in relay_ips:
                relay_note = f"giaddr {giaddr} is listed in this subnet's relay addresses"
            elif g in ipaddress.IPv4Network(subnet.get("subnet"), strict=False):
                relay_note = f"giaddr {giaddr} lies inside {subnet.get('subnet')}"
            else:
                relay_note = f"giaddr {giaddr} is neither a relay address of nor inside {subnet.get('subnet')} — Kea would NOT select this subnet for a relayed request"
        except ValueError:
            relay_note = f"giaddr {giaddr!r} is not an IPv4 address"
    steps.append(
        {
            "stage": "subnet",
            "verdict": "selected",
            "detail": f"Subnet {subnet.get('id')} ({subnet.get('subnet')}) — {how}"
            + (f", in shared network {sn_name!r} with {len(candidates) - 1} sibling subnet(s)" if sn_name else "")
            + ". Kea picks the subnet from the receiving interface or the relay's giaddr; Jen can't see the interface.",
            "evidence": [relay_note] if relay_note else [],
        }
    )

    # 2. reservation
    flags = reservation_flags(dhcp4_cfg, subnet)
    res = match_reservation(client, candidates, subnet.get("id"), flags, reservations or [])
    if res:
        steps.append(
            {
                "stage": "reservation",
                "verdict": "matched",
                "detail": f"{res['scope']} reservation by {res.get('identifier_type')} → {res.get('ip') or 'no fixed address'}"
                + (f", hostname {res.get('hostname')!r}" if res.get("hostname") else "")
                + f" ({res.get('source', 'host database')}). The client is KNOWN.",
                "evidence": [f"reservations-in-subnet={flags['in_subnet']}, reservations-global={flags['global']}"],
            }
        )
    else:
        steps.append(
            {
                "stage": "reservation",
                "verdict": "none",
                "detail": "No reservation for this client's MAC or client id in this subnet"
                + (" or globally" if flags["global"] else " (global reservations are not enabled here)")
                + ". The client is UNKNOWN.",
                "evidence": [f"reservations-in-subnet={flags['in_subnet']}, reservations-global={flags['global']}"],
            }
        )

    # 3. classes
    members: dict[str, bool | None] = {"ALL": True, "KNOWN": bool(res), "UNKNOWN": not res}
    class_rows = []
    additional_lists = (
        set(_classes.additional_classes(subnet))
        | set(_classes.additional_classes(sn) if sn else [])
        | {c for p in _pools(subnet) for c in _classes.additional_classes(p)}
    )
    if res:
        additional_lists |= set(res.get("classes") or [])
    for c in dhcp4_cfg.get("client-classes") or []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        name = c["name"]
        only = bool(c.get(_classes.NEW_ONLY) or c.get(_classes.OLD_ONLY))
        test = c.get("test")
        row = {
            "name": name,
            "expression": test or "",
            "evaluable": True,
            "matched": None,
            "reason": "",
            "only_additional": only,
            "builtin": _classes.is_builtin(name),
        }
        if only and name not in additional_lists:
            row["matched"] = False
            row["reason"] = (
                "only-in-additional-list, and nothing in this subnet/pool/shared network lists it — Kea never evaluates it here"
            )
        elif not test:
            row["matched"] = None
            row["reason"] = "no test expression (assigned by a reservation's client-classes, a hook, or never)"
            if res and name in (res.get("classes") or []):
                row["matched"], row["reason"] = True, "assigned by the matched reservation's client-classes"
        else:
            try:
                ast = parse_expression(test)
            except ExprError as e:
                row["evaluable"] = False
                row["reason"] = f"not evaluable by Jen ({e}); shown verbatim"
            else:
                missing: set[str] = set()
                v = evaluate(ast, client, members, missing)
                row["matched"] = v
                if v is None:
                    row["reason"] = (
                        "undecided — supply " + ", ".join(INPUT_LABELS.get(m, m) for m in sorted(missing))
                        if missing
                        else "undecided — depends on a class Jen can't evaluate"
                    )
                else:
                    row["reason"] = "expression matched" if v else "expression did not match"
        members[name] = row["matched"]
        class_rows.append(row)
    matched_names = [r["name"] for r in class_rows if r["matched"] is True]
    steps.append(
        {
            "stage": "classes",
            "verdict": f"{len(matched_names)} matched",
            "detail": ("Matched: " + ", ".join(matched_names)) if matched_names else "No client class matched.",
            "evidence": [
                f"{r['name']}: {'matched' if r['matched'] else ('did not match' if r['matched'] is False else 'undecided')} — {r['reason']}"
                for r in class_rows
            ],
        }
    )

    # 4. subnet guards
    def _guard_state(container):
        guards = _classes.guard_classes(container)
        if not guards:
            return True, guards
        states = [members.get(g) for g in guards]
        if any(s is False for s in states):
            return False, guards
        if any(s is None for s in states):
            return None, guards
        return True, guards

    sn_state, sn_guards = _guard_state(sn) if sn else (True, [])
    subnet_states = []
    for s in candidates:
        st, guards = _guard_state(s)
        subnet_states.append(
            {"id": s.get("id"), "subnet": s.get("subnet"), "eligible": _and(sn_state, st), "guards": guards}
        )
    selected = next((s for s in subnet_states if s["eligible"] is True), None)
    steps.append(
        {
            "stage": "subnet-guards",
            "verdict": "eligible"
            if selected and selected["id"] == subnet.get("id")
            else (
                "another subnet"
                if selected
                else ("undecided" if any(s["eligible"] is None for s in subnet_states) else "blocked")
            ),
            "detail": (
                f"Subnet {selected['id']} is the first eligible subnet."
                if selected
                else "No candidate subnet's guard classes are satisfied — Kea would give this client NO address here."
            )
            + (f" Shared-network guard: {', '.join(sn_guards)}." if sn_guards else ""),
            "evidence": [
                f"subnet {s['id']} ({s['subnet']}): "
                + (
                    "no guard"
                    if not s["guards"]
                    else f"guard {', '.join(s['guards'])} → "
                    + ("eligible" if s["eligible"] else ("undecided" if s["eligible"] is None else "blocked"))
                )
                for s in subnet_states
            ],
        }
    )
    chosen = next((s for s in candidates if selected and s.get("id") == selected["id"]), subnet)

    # 5. pools + answer
    pool_rows = []
    try:
        net = ipaddress.IPv4Network(chosen.get("subnet"), strict=False)
    except (ValueError, TypeError):
        net = None
    for p in _pools(chosen):
        st, guards = _guard_state(p)
        pool_rows.append({"pool": p.get("pool"), "eligible": st, "guards": guards})
    first_pool = next((p for p in pool_rows if p["eligible"] is True), None)
    answer_ip, answer_how = None, ""
    if res and res.get("ip"):
        answer_ip, answer_how = res["ip"], f"the {res['scope']} reservation's fixed address"
    elif lease and int(lease.get("subnet_id") or 0) == chosen.get("id") and lease.get("ip"):
        answer_ip, answer_how = lease["ip"], "the current lease is renewed (same address while it holds)"
    elif first_pool:
        answer_ip, answer_how = f"from pool {first_pool['pool']}", "the first pool whose guard classes are satisfied"
    elif any(p["eligible"] is None for p in pool_rows):
        answer_how = "undecided — a pool guard depends on an input Jen doesn't have"
    else:
        answer_how = "no eligible pool — Kea would NAK / not offer an address"
    steps.append(
        {
            "stage": "pools",
            "verdict": "reserved"
            if res and res.get("ip")
            else (
                "lease"
                if answer_how.startswith("the current")
                else (
                    "pool" if first_pool else ("undecided" if any(p["eligible"] is None for p in pool_rows) else "none")
                )
            ),
            "detail": (f"Address: {answer_ip} — {answer_how}." if answer_ip else f"No address: {answer_how}."),
            "evidence": [
                f"pool {p['pool']}: "
                + (
                    "no guard"
                    if not p["guards"]
                    else f"guard {', '.join(p['guards'])} → "
                    + ("eligible" if p["eligible"] else ("undecided" if p["eligible"] is None else "blocked"))
                )
                for p in pool_rows
            ]
            + (
                [
                    f"reserved address {res['ip']} is {'inside' if net and ipaddress.IPv4Address(res['ip']) in net else 'OUTSIDE'} {chosen.get('subnet')}"
                ]
                if res and res.get("ip") and net
                else []
            ),
        }
    )

    # 6. options
    matched_class_dicts = [
        c for c in dhcp4_cfg.get("client-classes") or [] if isinstance(c, dict) and c.get("name") in matched_names
    ]
    levels: list[tuple[str, list[dict]]] = [("global", _opts._opts(dhcp4_cfg))]
    for c in matched_class_dicts:
        levels.append((f"class:{c.get('name')}", _opts._opts(c)))
    if sn:
        levels.append((f"shared-network:{sn_name}", _opts._opts(sn)))
    levels.append(("subnet", _opts._opts(chosen)))
    if first_pool:
        pool_dict = next((p for p in _pools(chosen) if p.get("pool") == first_pool["pool"]), None)
        levels.append(("pool", _opts._opts(pool_dict) if pool_dict else []))
    if res and res.get("options"):
        levels.append(("reservation", [o for o in res["options"] if isinstance(o, dict)]))
    options = _merge_options(levels)
    lifetime, lifetime_from = _lifetime(dhcp4_cfg, sn, chosen, matched_class_dicts)
    steps.append(
        {
            "stage": "options",
            "verdict": f"{len(options)} option(s)",
            "detail": f"valid-lifetime {lifetime}s from {lifetime_from}. Precedence: reservation > pool > subnet > shared network > class > global.",
            "evidence": [
                f"{o['name']} ({o['code']}) = {o['data']} — from {o['source']}"
                + (f" (overrides {', '.join(o['overridden'])})" if o["overridden"] else "")
                for o in options
            ],
        }
    )

    evaluable = [
        r
        for r in class_rows
        if r["evaluable"]
        and r["reason"] != "no test expression (assigned by a reservation's client-classes, a hook, or never)"
    ]
    undecided = [r["name"] for r in class_rows if r["matched"] is None and r["evaluable"]]
    return {
        "ok": True,
        "subnet": {
            "id": chosen.get("id"),
            "cidr": chosen.get("subnet"),
            "shared_network": sn_name,
            "candidates": subnet_states,
        },
        "reservation": res,
        "classes": class_rows,
        "pools": pool_rows,
        "options": options,
        "answer": {
            "ip": answer_ip,
            "how": answer_how,
            "lifetime": lifetime,
            "lifetime_from": lifetime_from,
            "hostname": (res or {}).get("hostname") or client.get("hostname") or "",
        },
        "steps": steps,
        "confidence": {
            "classes_total": len(class_rows),
            "classes_evaluable": len(evaluable),
            "classes_undecided": undecided,
            "not_evaluable": [r["name"] for r in class_rows if not r["evaluable"]],
        },
    }
