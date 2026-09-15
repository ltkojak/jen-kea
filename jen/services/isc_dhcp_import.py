"""
jen/services/isc_dhcp_import.py
────────────────────────────────
v5.37.0 (Q36) — parse an ISC `dhcpd.conf` and map it onto the SAME
`Plan` / `Scope` / `Reservation` / `Policy` dataclasses the Windows
importer (jen/services/win_dhcp_import.py, v5.24.0) produces, so the
review → preview → apply wizard is reused rather than duplicated.
`to_kea()` is the Windows one, re-exported.

Two pure stages:
  * `parse_config(data)` — dhcpd.conf bytes -> a Plan. A hand-written
    tokenizer (`#` comments, quoted strings that may contain `;`,
    `{ } ; , ( ) =`) and a generic statement tree (head tokens + optional
    `{ … }` body), interpreted for the subset of the dhcpd grammar Jen
    can express in Kea. Every construct outside that subset becomes a
    `Plan.warnings` line carrying its source line number; nothing is
    silently dropped and nothing raises on a syntactically odd file.
  * `parse_leases(data)` — dhcpd.leases bytes -> the current binding
    per address, so the review page can say how many active leases sit
    in the ranges being imported. Never imported: Kea gets a fresh
    lease database (see the admin guide for why).

What maps where:
  global `option …`            -> Plan.server_options (Kea global option-data)
  `default-lease-time`         -> Scope.lease_seconds (inherited down)
  `subnet A netmask M { … }`   -> Scope; several `range`s -> one pool each,
                                  expressed as one span + the gaps as exclusions
  `shared-network N { … }`     -> Plan.superscopes[N] (a Kea shared network)
  `host H { hardware ethernet; fixed-address; option host-name; }`
                               -> Reservation, matched to a subnet by address
                                  when declared outside one
  `class "C" { match if …; }`  -> kea_classes rule rows (Policy.rules); a
                                  pool's `allow members of "C"` guards the
                                  pool with C, `deny members of "C"` with a
                                  generated `not_C` class
  `next-server` / `filename`   -> Scope.next_server / Scope.boot_file
  `group { … }`                -> flattened, its options inherited, with a note
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from jen.services import auth as _auth
from jen.services import dhcp_options as _opts
from jen.services import win_dhcp_import as _win
from jen.services.win_dhcp_import import Plan, Policy, Reservation, Scope, to_kea  # noqa: F401  (re-exported)

DHCPD_DEFAULT_LEASE_SECONDS = 43200  # dhcpd's own default-lease-time default

# ── tokenizer ────────────────────────────────────────────────────────────────


@dataclass
class Tok:
    text: str
    line: int
    quoted: bool = False


_PUNCT = set("{};,()=")


def tokenize(text: str) -> tuple[list[Tok], dict[int, str]]:
    """(tokens, comments) — comments is {line: text} for every `#`
    comment, so a subnet can borrow the comment on the line above it as
    its friendly name."""
    toks: list[Tok] = []
    comments: dict[int, str] = {}
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        if ch == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments[line] = text[i + 1 : j].strip()
            i = j
            continue
        if ch == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            toks.append(Tok("".join(buf), line, quoted=True))
            i = j + 1
            continue
        if ch in _PUNCT:
            toks.append(Tok(ch, line))
            i += 1
            continue
        j = i
        while j < n and not text[j].isspace() and text[j] not in _PUNCT and text[j] not in '"#':
            j += 1
        toks.append(Tok(text[i:j], line))
        i = j
    return toks, comments


@dataclass
class Stmt:
    head: list[Tok]
    body: list[Stmt] | None  # None for a `…;` statement, a list for `… { … }`
    line: int

    @property
    def kw(self) -> str:
        return self.head[0].text.lower() if self.head else ""

    def words(self) -> list[str]:
        return [t.text for t in self.head]


def parse_statements(toks: list[Tok]) -> tuple[list[Stmt], list[str]]:
    """The generic statement tree. Unbalanced braces and a trailing
    unterminated statement become warnings, never exceptions."""
    warnings: list[str] = []
    pos = 0

    def block(depth: int) -> list[Stmt]:
        nonlocal pos
        out: list[Stmt] = []
        head: list[Tok] = []
        while pos < len(toks):
            t = toks[pos]
            pos += 1
            if t.text == ";" and not t.quoted:
                if head:
                    out.append(Stmt(head, None, head[0].line))
                head = []
            elif t.text == "{" and not t.quoted:
                line = head[0].line if head else t.line
                body = block(depth + 1)
                out.append(Stmt(head or [Tok("", line)], body, line))
                head = []
            elif t.text == "}" and not t.quoted:
                if head:
                    warnings.append(f"line {head[0].line}: statement without a terminating ';' — ignored")
                if depth == 0:
                    warnings.append(f"line {t.line}: unexpected '}}' — ignored")
                    continue
                return out
            else:
                head.append(t)
        if head:
            warnings.append(f"line {head[0].line}: unterminated statement at end of file — ignored")
        if depth > 0:
            warnings.append("end of file: a '{' block was never closed")
        return out

    return block(0), warnings


# ── option statements ────────────────────────────────────────────────────────

# dhcpd option names that differ from Jen's catalog (dhcp_options.py),
# or that need special handling. Everything else goes through
# NAME_TO_CODE unchanged (routers, domain-name-servers, ntp-servers, …).
_ISC_ALIASES = {
    "bootfile-name": 67,
    "rfc3442-classless-static-routes": 121,
    "ms-classless-static-routes": 121,
    "classless-static-routes": 121,
    "dhcp-lease-time": 51,
    "dhcp-renewal-time": 58,
    "dhcp-rebinding-time": 59,
    "dhcp-client-identifier": 61,
    "nis-domain": 40,
    "nis-servers": 41,
    "netbios-name-servers": 44,
    "netbios-node-type": 46,
    "netbios-scope": 47,
}
_OPTION_NAME_RE = re.compile(r"^option-(\d{1,3})$")
_DECIMAL_LIST_RE = re.compile(r"^\d{1,3}(\s*,\s*\d{1,3})*$")


def _option_value_text(toks: list[Tok]) -> str:
    """Join the value tokens the way the Windows export joins multiple
    values: `, ` between comma-separated items, a space inside one."""
    items: list[str] = []
    cur: list[str] = []
    for t in toks:
        if t.text == "," and not t.quoted:
            items.append(" ".join(cur))
            cur = []
        else:
            cur.append(t.text)
    items.append(" ".join(cur))
    return ", ".join(i for i in items if i)


def option_statement(toks: list[Tok], context: str) -> tuple[tuple[int, str] | None, str | None]:
    """The tokens after `option` -> ((code, raw), None) or (None, warning).
    Handles the numeric `option-N` form, dhcpd's decimal-byte RFC 3442
    routes, and `on`/`off` booleans."""
    if not toks:
        return None, f"{context}: empty option statement — ignored"
    line = toks[0].line
    name = toks[0].text.lower()
    texts = [t.text.lower() for t in toks]
    if name == "space":
        return None, f"{context} (line {line}): option space definitions are not supported — skipped"
    if "code" in texts and "=" in texts:
        return None, f"{context} (line {line}): option definition `{name}` is not supported — its uses are skipped"
    if "." in name and not name.replace(".", "").isdigit():
        return None, f"{context} (line {line}): option space `{name.split('.')[0]}` is not supported — skipped"
    m = _OPTION_NAME_RE.match(name)
    if m:
        code = int(m.group(1))
    elif name in _ISC_ALIASES:
        code = _ISC_ALIASES[name]
    elif name in _opts.NAME_TO_CODE:
        code = _opts.NAME_TO_CODE[name]
    else:
        return None, f"{context} (line {line}): option `{name}` is not in Jen's catalog — skipped"
    if code == 1:
        return None, f"{context} (line {line}): option subnet-mask not imported — Kea derives it from the prefix"
    raw = _option_value_text(toks[1:])
    if code == 121 and _DECIMAL_LIST_RE.match(raw):
        # dhcpd writes RFC 3442 routes as decimal bytes: "24, 10,0,1, 10,0,0,1"
        # kept as hex — to_kea() decodes it, exactly as for the Windows export
        hex_text = "".join(f"{int(b) & 0xFF:02x}" for b in re.split(r"\s*,\s*", raw))
        data, decode_warnings = _win._decode_classless_routes_hex(hex_text, context)
        if not data:
            return None, (decode_warnings[0] if decode_warnings else f"{context}: option 121 could not be decoded")
        raw = hex_text
    if _opts.type_for(code) == "boolean":
        raw = {"on": "true", "off": "false", "1": "true", "0": "false"}.get(raw.lower(), raw)
    return (code, raw), None


# ── class `match if` expressions -> kea_classes rule rows ───────────────────

_OPTION_FIELDS = {
    "vendor-class-identifier": ("vendor_class", "string"),
    "user-class": ("user_class", "string"),
    "host-name": ("hostname", "string"),
    "dhcp-client-identifier": ("client_id", "hex"),
    "agent.circuit-id": ("circuit_id", "string"),
    "agent.remote-id": ("remote_id", "hex"),
}
_HEX_WORD_RE = re.compile(r"^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2})+$")


def _hex_colon(word: str) -> str:
    return ":".join(f"{int(p, 16):02x}" for p in word.split(":"))


def _split_top(toks: list[Tok], seps: set[str]) -> list[list[Tok]]:
    """Split on any of `seps` at parenthesis depth 0."""
    parts: list[list[Tok]] = [[]]
    depth = 0
    for t in toks:
        if not t.quoted and t.text == "(":
            depth += 1
        elif not t.quoted and t.text == ")":
            depth -= 1
        if depth == 0 and not t.quoted and t.text.lower() in seps:
            parts.append([])
            continue
        parts[-1].append(t)
    return parts


def _strip_parens(toks: list[Tok]) -> list[Tok]:
    while len(toks) >= 2 and toks[0].text == "(" and toks[-1].text == ")" and not toks[0].quoted:
        depth = 0
        for i, t in enumerate(toks):
            if t.text == "(" and not t.quoted:
                depth += 1
            elif t.text == ")" and not t.quoted:
                depth -= 1
                if depth == 0 and i != len(toks) - 1:
                    return toks  # the outer parens don't enclose the whole thing
        toks = toks[1:-1]
    return toks


def _comparison_to_rule(toks: list[Tok]) -> tuple[dict | None, str | None]:
    """One `lhs = rhs` -> (rule, None) or (None, reason)."""
    sides = _split_top(toks, {"="})
    if len(sides) != 2 or not sides[0] or not sides[1]:
        return None, "only `lhs = rhs` comparisons are supported"
    lhs, rhs = sides
    if len(rhs) != 1:
        return None, "the right-hand side must be a single string or hex value"
    value_tok = rhs[0]

    prefix_len: int | None = None
    if lhs[0].text.lower() == "substring" and len(lhs) >= 4 and lhs[1].text == "(" and lhs[-1].text == ")":
        inner = _split_top(lhs[2:-1], {","})
        if len(inner) != 3 or len(inner[1]) != 1 or len(inner[2]) != 1:
            return None, "substring() needs exactly (what, offset, length)"
        try:
            offset, length = int(inner[1][0].text), int(inner[2][0].text)
        except ValueError:
            return None, "substring() offset and length must be numbers"
        subject = inner[0]
        prefix_len = length
    else:
        subject = lhs
        offset = 0

    words = [t.text.lower() for t in subject]
    if words == ["hardware"]:
        if value_tok.quoted or not _HEX_WORD_RE.match(value_tok.text):
            return None, "hardware must be compared to a colon-hex value"
        octets = _hex_colon(value_tok.text).split(":")
        if prefix_len is None:
            # `hardware = 1:aa:bb:cc:dd:ee:ff` — type byte 1 (ethernet) + MAC
            if len(octets) != 7 or octets[0] != "01":
                return None, "hardware must be `1:` (ethernet) followed by a 6-byte MAC"
            return {"field": "mac", "op": "equals", "value": ":".join(octets[1:])}, None
        if offset != 1:
            return None, "substring(hardware, …) must start at offset 1 (after the type byte)"
        if prefix_len == 6 and len(octets) == 6:
            return {"field": "mac", "op": "equals", "value": ":".join(octets)}, None
        if prefix_len == 3 and len(octets) == 3:
            return {"field": "mac_oui", "op": "equals", "value": ":".join(octets)}, None
        return None, "substring(hardware, 1, n) is supported for n = 6 (MAC) or 3 (OUI) only"

    if len(words) == 2 and words[0] == "option":
        name = words[1]
        if name not in _OPTION_FIELDS:
            return None, f"matching on option `{name}` is not supported"
        field_name, kind = _OPTION_FIELDS[name]
        if kind == "hex":
            if value_tok.quoted:
                value = value_tok.text.encode("utf-8").hex()
            elif _HEX_WORD_RE.match(value_tok.text):
                value = _hex_colon(value_tok.text)
            else:
                return None, f"option {name} must be compared to a string or colon-hex value"
            if prefix_len is not None:
                return None, f"substring() on option {name} is not supported"
            return {"field": field_name, "op": "equals", "value": value}, None
        # string kinds
        if value_tok.quoted:
            value = value_tok.text
        elif _HEX_WORD_RE.match(value_tok.text):
            try:
                value = bytes.fromhex(_hex_colon(value_tok.text).replace(":", "")).decode("ascii")
            except (ValueError, UnicodeDecodeError):
                return None, f"option {name} hex value is not printable text"
        else:
            value = value_tok.text
        if prefix_len is None:
            return {"field": field_name, "op": "equals", "value": value}, None
        if offset != 0:
            return None, "substring() on an option must start at offset 0"
        if len(value) != prefix_len:
            return None, f"substring(…, 0, {prefix_len}) compared to a {len(value)}-character value never matches"
        return {"field": field_name, "op": "starts_with", "value": value}, None

    return None, f"`{' '.join(t.text for t in subject)}` is not a supported match subject"


def match_to_rules(toks: list[Tok]) -> tuple[list[dict], str, bool, str | None]:
    """The tokens after `match if` -> (rules, combinator "all"|"any",
    negate, None) or ([], "all", False, reason)."""
    toks = _strip_parens(toks)
    negate = False
    if toks and toks[0].text.lower() == "not" and not toks[0].quoted:
        negate = True
        toks = _strip_parens(toks[1:])
    if not toks:
        return [], "all", False, "empty match expression"
    ands = _split_top(toks, {"and"})
    ors = _split_top(toks, {"or"})
    if len(ands) > 1 and len(ors) > 1:
        return [], "all", False, "mixed `and` / `or` — only one kind per class is supported"
    if len(ands) > 1:
        parts, combinator = ands, "all"
    elif len(ors) > 1:
        parts, combinator = ors, "any"
    else:
        parts, combinator = [toks], "all"
    rules = []
    for part in parts:
        part = _strip_parens(part)
        if any(t.text.lower() in ("and", "or", "not") and not t.quoted for t in part):
            return [], "all", False, "nested boolean expressions are not supported"
        rule, reason = _comparison_to_rule(part)
        if reason:
            return [], "all", False, reason
        rules.append(rule)
    return rules, combinator, negate, None


# ── interpretation ───────────────────────────────────────────────────────────


@dataclass
class _ClassDef:
    name: str  # the Kea-safe name
    source_name: str
    line: int
    rules: list[dict] = field(default_factory=list)
    combinator: str = "all"
    negate: bool = False
    options: dict[int, str] = field(default_factory=dict)
    reason: str | None = None  # why it can't be a Kea class, when it can't
    referenced: bool = False


@dataclass
class _Ctx:
    """What a nested block inherits: options and timers from an enclosing
    shared-network / group, plus the flags that change how hosts map."""

    options: dict[int, str] = field(default_factory=dict)
    lease: int | None = None
    next_server: str = ""
    boot_file: str = ""
    use_host_decl_names: bool = False
    # options set directly in an enclosing group {} — the only inherited
    # options a host reservation carries (subnet/shared-network ones
    # already apply to it through the subnet)
    group_options: dict[int, str] = field(default_factory=dict)
    in_group: bool = False

    def child(self) -> _Ctx:
        return _Ctx(
            dict(self.options),
            self.lease,
            self.next_server,
            self.boot_file,
            self.use_host_decl_names,
            dict(self.group_options),
            self.in_group,
        )


@dataclass
class _PendingHost:
    reservation: Reservation
    line: int


# Server-tuning directives Kea has no equivalent for, or needs none:
# reported once, as a single summarized line, not one warning each.
_QUIET_DIRECTIVES = {
    "log-facility",
    "pid-file-name",
    "lease-file-name",
    "db-time-format",
    "local-port",
    "local-address",
    "ping-check",
    "ping-timeout",
    "one-lease-per-client",
    "get-lease-hostnames",
    "dynamic-bootp-lease-length",
    "min-lease-time",
    "always-broadcast",
    "always-reply-rfc1048",
    "boot-unknown-clients",
    "ignore-client-uids",
    "server-identifier",
    "server-name",
    "stash-agent-options",
    "update-conflict-detection",
    "update-optimization",
    "do-forward-updates",
    "adaptive-lease-time-threshold",
    "min-secs",
    "lease-limit",
    "infinite-is-reserved",
    "limit-addrs-per-ia",
}
_DDNS_DIRECTIVES = {
    "ddns-update-style",
    "ddns-updates",
    "ddns-domainname",
    "ddns-rev-domainname",
    "ddns-hostname",
    "ddns-ttl",
    "update-static-leases",
    "key",
    "zone",
    "do-reverse-updates",
    "client-updates",
    "ddns-other-guard-updates",
}

_MAC_RE = re.compile(r"^[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}$")


def _norm_mac(word: str) -> str | None:
    if not _MAC_RE.match(word):
        return None
    return _hex_colon(word)


class _Interp:
    def __init__(self, comments: dict[int, str]):
        self.plan = Plan(source="isc")
        self.comments = comments
        self.classes: dict[str, _ClassDef] = {}  # by source name
        self.pending_hosts: list[_PendingHost] = []
        self.quiet: list[str] = []
        self.noted: set[str] = set()
        self.global_ctx = _Ctx()

    # -- helpers ------------------------------------------------------------
    def warn(self, msg: str) -> None:
        self.plan.warnings.append(msg)

    def note_once(self, key: str, msg: str) -> None:
        if key not in self.noted:
            self.noted.add(key)
            self.warn(msg)

    def _name_for_subnet(self, line: int, cidr: str, network: str | None) -> str:
        comment = self.comments.get(line - 1, "").strip(" -—:")
        if comment and len(comment) <= 64 and not comment.lower().startswith(("subnet", "range", "option")):
            return comment
        return f"{network} {cidr}" if network else cidr

    # -- walking -------------------------------------------------------------
    def walk(self, stmts: list[Stmt], ctx: _Ctx, network: str | None, level: str) -> None:
        for st in stmts:
            kw = st.kw
            line = st.line
            words = st.words()
            if kw == "option":
                self.handle_option(st, ctx, level)
            elif kw == "default-lease-time":
                ctx.lease = self._int(st, "default-lease-time")
            elif kw == "max-lease-time":
                self.note_once(
                    "max-lease-time",
                    f"line {line}: max-lease-time is not mapped — Kea's valid-lifetime is what the subnet gets; set max-valid-lifetime by hand if clients may ask for longer",
                )
            elif kw == "authoritative":
                pass  # Kea is always authoritative
            elif kw == "not" and len(words) > 1 and words[1].lower() == "authoritative":
                self.note_once(
                    "not-authoritative",
                    f"line {line}: `not authoritative` has no Kea equivalent — Kea always answers authoritatively",
                )
            elif kw in _DDNS_DIRECTIVES:
                self.note_once(
                    "ddns",
                    f"line {line}: DDNS settings (`{kw}` and friends) are not imported — configure dynamic DNS on Jen's DDNS page",
                )
            elif kw == "subnet":
                self.handle_subnet(st, ctx, network)
            elif kw == "shared-network":
                if st.body is None:
                    self.warn(f"line {line}: shared-network without a block — ignored")
                    continue
                name = words[1] if len(words) > 1 else f"shared-{line}"
                self.plan.superscopes.setdefault(name, [])
                self.walk(st.body, ctx.child(), name, "shared-network")
            elif kw == "host":
                self.handle_host(st, ctx, None)
            elif kw == "class":
                self.handle_class(st)
            elif kw == "subclass":
                self.warn(
                    f"line {line}: subclass is not supported — Kea has no subclass model; write a class per value or a reservation per MAC"
                )
            elif kw == "group":
                if st.body is None:
                    continue
                self.note_once(
                    "group",
                    f"line {line}: group blocks are flattened — their options and timers are applied to what they contain",
                )
                gctx = ctx.child()
                gctx.in_group = True
                self.walk(st.body, gctx, network, "group")
            elif kw == "include":
                self.warn(
                    f"line {line}: include {words[1] if len(words) > 1 else ''!r} is not followed — upload one merged file, or import the included file separately"
                )
            elif kw in ("if", "elsif", "else"):
                self.note_once(
                    "if",
                    f"line {line}: conditional (`if` / `elsif` / `else`) blocks are not supported — express them as Kea client classes after the import",
                )
            elif kw == "failover":
                self.warn(
                    f"line {line}: failover peer is not imported — Kea's equivalent is the HA hook; see the admin guide's Kea Servers and HA section"
                )
            elif kw in ("omapi-port", "omapi-key"):
                self.note_once(
                    "omapi",
                    f"line {line}: OMAPI is not supported — Jen talks to Kea through its control socket instead",
                )
            elif kw == "next-server":
                ctx.next_server = words[1] if len(words) > 1 and _auth.valid_ip(words[1]) else ctx.next_server
                if len(words) > 1 and not _auth.valid_ip(words[1]):
                    self.warn(f"line {line}: next-server {words[1]!r} is not an IPv4 address — skipped")
            elif kw == "filename":
                ctx.boot_file = words[1] if len(words) > 1 else ""
            elif kw == "use-host-decl-names":
                ctx.use_host_decl_names = len(words) > 1 and words[1].lower() in ("on", "true")
            elif kw in ("range", "pool"):
                self.warn(f"line {line}: `{kw}` outside a subnet — ignored")
            elif kw in ("allow", "deny", "ignore"):
                self.handle_allow_deny(st, level, None)
            elif kw in _QUIET_DIRECTIVES:
                self.quiet.append(f"{kw} (line {line})")
            elif kw == "":
                self.warn(f"line {line}: a bare `{{ … }}` block — ignored")
            else:
                self.warn(f"line {line}: `{kw}` is not recognised — not imported")

    def _int(self, st: Stmt, what: str) -> int | None:
        words = st.words()
        try:
            return int(words[1])
        except (IndexError, ValueError):
            self.warn(f"line {st.line}: {what} needs a number — ignored")
            return None

    def handle_option(self, st: Stmt, ctx: _Ctx, level: str) -> None:
        parsed, warning = option_statement(st.head[1:], level)
        if warning:
            self.warn(warning)
            return
        code, raw = parsed
        if level == "global":
            self.plan.server_options[code] = raw
        else:
            ctx.options[code] = raw
            if ctx.in_group:
                ctx.group_options[code] = raw

    def handle_allow_deny(self, st: Stmt, level: str, pool: dict | None) -> None:
        words = [w.lower() for w in st.words()]
        line = st.line
        target = " ".join(words[1:])
        if words[0] in ("allow", "deny") and len(words) >= 4 and words[1] == "members" and words[2] == "of":
            name = st.head[3].text
            if pool is None:
                self.warn(
                    f"line {line}: `{words[0]} members of` outside a pool — Kea guards pools and subnets by class; ignored here"
                )
                return
            pool[words[0]].append((name, line))
        elif target in ("unknown-clients", "unknown clients"):
            if words[0] == "deny":
                self.note_once(
                    "deny-unknown",
                    f"line {line}: `deny unknown-clients` is not imported — in Kea, guard the pool with the built-in KNOWN class after the import",
                )
        elif "bootp" in target or target == "booting":
            self.note_once("bootp", f"line {line}: `{words[0]} {target}` has no effect in Kea (no BOOTP) — ignored")
        elif target in ("client-updates", "duplicates", "declines", "leasequery"):
            self.note_once(target, f"line {line}: `{words[0]} {target}` is not imported")
        else:
            self.warn(f"line {line}: `{words[0]} {target}` is not recognised — ignored")

    # -- subnet --------------------------------------------------------------
    def handle_subnet(self, st: Stmt, ctx: _Ctx, network: str | None) -> None:
        words = st.words()
        line = st.line
        if st.body is None or len(words) < 4 or words[2].lower() != "netmask":
            self.warn(f"line {line}: subnet needs `subnet A netmask M {{ … }}` — skipped")
            return
        addr, mask = words[1], words[3]
        if not _auth.valid_ip(addr) or not _auth.valid_ip(mask):
            self.warn(f"line {line}: subnet {addr} netmask {mask}: not IPv4 addresses — skipped")
            return
        prefix = _win._prefix_len(mask)
        try:
            net = ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            self.warn(f"line {line}: subnet {addr}/{prefix} is not a valid network — skipped")
            return
        cidr = f"{net.network_address}/{prefix}"
        if str(net.network_address) != addr:
            self.warn(f"line {line}: subnet {addr} netmask {mask} is not the network address — using {cidr}")
        if any(s.scope_id == str(net.network_address) for s in self.plan.scopes):
            self.warn(f"line {line}: subnet {cidr} declared twice — the second is skipped")
            return
        sctx = ctx.child()
        sctx.in_group = False
        context = f"subnet {cidr}"
        ranges: list[tuple[int, int, int]] = []  # (start, end, line)
        pools: list[dict] = []
        hosts_here: list[Reservation] = []

        def add_range(rst: Stmt, into: list) -> None:
            rw = [w for w in rst.words()[1:] if w.lower() != "dynamic-bootp"]
            if not rw or not all(_auth.valid_ip(w) for w in rw):
                self.warn(f"{context} (line {rst.line}): range needs one or two IPv4 addresses — skipped")
                return
            lo, hi = int(ipaddress.IPv4Address(rw[0])), int(ipaddress.IPv4Address(rw[-1]))
            if lo > hi:
                lo, hi = hi, lo
            if ipaddress.IPv4Address(lo) not in net or ipaddress.IPv4Address(hi) not in net:
                self.warn(f"{context} (line {rst.line}): range {rw[0]}-{rw[-1]} is outside the subnet — skipped")
                return
            into.append((lo, hi, rst.line))

        for sub in st.body:
            kw = sub.kw
            if kw == "range":
                add_range(sub, ranges)
            elif kw == "pool":
                if sub.body is None:
                    continue
                pool = {"ranges": [], "allow": [], "deny": [], "line": sub.line}
                for p in sub.body:
                    if p.kw == "range":
                        add_range(p, pool["ranges"])
                    elif p.kw in ("allow", "deny", "ignore"):
                        self.handle_allow_deny(p, "pool", pool)
                    elif p.kw == "option":
                        self.warn(
                            f"{context} (line {p.line}): pool-level options are not imported — Kea pools carry no option-data of their own; set it on the subnet or a class"
                        )
                    elif p.kw in ("default-lease-time", "max-lease-time"):
                        self.warn(
                            f"{context} (line {p.line}): pool-level lease times are not imported — set on the subnet"
                        )
                    elif p.kw in ("failover",):
                        self.warn(f"{context} (line {p.line}): `failover peer` in a pool is not imported — see Kea HA")
                    else:
                        self.warn(f"{context} (line {p.line}): `{p.kw}` inside a pool is not supported — ignored")
                if not pool["ranges"]:
                    self.warn(f"{context} (line {sub.line}): pool has no range — ignored")
                    continue
                pools.append(pool)
                ranges.extend(pool["ranges"])
            elif kw == "host":
                self.handle_host(sub, sctx, hosts_here)
            elif kw == "option":
                self.handle_option(sub, sctx, context)
            elif kw == "default-lease-time":
                sctx.lease = self._int(sub, "default-lease-time")
            elif kw == "max-lease-time":
                self.note_once(
                    "max-lease-time",
                    f"line {sub.line}: max-lease-time is not mapped — Kea's valid-lifetime is what the subnet gets; set max-valid-lifetime by hand if clients may ask for longer",
                )
            elif kw == "next-server":
                w = sub.words()
                if len(w) > 1 and _auth.valid_ip(w[1]):
                    sctx.next_server = w[1]
                else:
                    self.warn(f"{context} (line {sub.line}): next-server needs an IPv4 address — skipped")
            elif kw == "filename":
                w = sub.words()
                sctx.boot_file = w[1] if len(w) > 1 else ""
            elif kw in ("allow", "deny", "ignore"):
                self.handle_allow_deny(sub, context, None)
            elif kw == "group":
                if sub.body:
                    self.note_once(
                        "group",
                        f"line {sub.line}: group blocks are flattened — their options and timers are applied to what they contain",
                    )
                    # a group inside a subnet: hosts and options only
                    gctx = sctx.child()
                    gctx.in_group = True
                    for g in sub.body:
                        if g.kw == "host":
                            self.handle_host(g, gctx, hosts_here)
                        elif g.kw == "option":
                            self.handle_option(g, gctx, context)
                        else:
                            self.warn(f"{context} (line {g.line}): `{g.kw}` inside a group inside a subnet — ignored")
            elif kw in _DDNS_DIRECTIVES:
                self.note_once(
                    "ddns",
                    f"line {sub.line}: DDNS settings (`{kw}` and friends) are not imported — configure dynamic DNS on Jen's DDNS page",
                )
            elif kw in _QUIET_DIRECTIVES:
                self.quiet.append(f"{kw} (line {sub.line})")
            elif kw == "authoritative":
                pass
            elif kw in ("if", "elsif", "else"):
                self.note_once(
                    "if",
                    f"line {sub.line}: conditional (`if` / `elsif` / `else`) blocks are not supported — express them as Kea client classes after the import",
                )
            elif kw == "class":
                self.warn(
                    f"{context} (line {sub.line}): a class declared inside a subnet is treated as global (Kea classes are global)"
                )
                self.handle_class(sub)
            else:
                self.warn(f"{context} (line {sub.line}): `{kw}` is not supported inside a subnet — ignored")

        # ranges -> one span plus the gaps as exclusions (the Windows shape)
        ranges.sort()
        merged: list[list[int]] = []
        for lo, hi, rline in ranges:
            if merged and lo <= merged[-1][1] + 1:
                if lo <= merged[-1][1]:
                    self.warn(f"{context} (line {rline}): range overlaps an earlier one — merged")
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        exclusions: list[tuple[str, str]] = []
        if merged:
            start, end = _win._int2ip(merged[0][0]), _win._int2ip(merged[-1][1])
            for (_a, prev_hi), (next_lo, _b) in zip(merged, merged[1:], strict=False):
                exclusions.append((_win._int2ip(prev_hi + 1), _win._int2ip(next_lo - 1)))
        else:
            start = end = str(net.network_address)
            exclusions.append((start, end))
            self.warn(f"{context} (line {line}): no range — imported without pools (reservations only)")

        # pool guards -> policies (one per guarded range, so each carves its own pool)
        policies: list[Policy] = []
        order = 0
        for pool in pools:
            guard = self._pool_guard(pool, context)
            if guard is None:
                continue
            name, rules, combinator, negate, options = guard
            for lo, hi, _rline in pool["ranges"]:
                order += 1
                policies.append(
                    Policy(
                        name=name,
                        enabled=True,
                        processing_order=order,
                        condition="OR" if combinator == "any" else "AND",
                        rules=rules,
                        negate=negate,
                        ip_ranges=[(_win._int2ip(lo), _win._int2ip(hi))],
                        options=options,
                    )
                )

        scope = Scope(
            scope_id=str(net.network_address),
            subnet_mask=str(net.netmask),
            name=self._name_for_subnet(line, cidr, network),
            state="Active",
            start_range=start,
            end_range=end,
            lease_seconds=sctx.lease
            if sctx.lease is not None
            else (ctx.lease if ctx.lease is not None else DHCPD_DEFAULT_LEASE_SECONDS),
            exclusions=exclusions,
            options=sctx.options,
            reservations=hosts_here,
            policies=policies,
            superscope_name=network,
            next_server=sctx.next_server,
            boot_file=sctx.boot_file,
        )
        self.plan.scopes.append(scope)
        if network is not None:
            self.plan.superscopes.setdefault(network, []).append(scope.scope_id)

    def _pool_guard(self, pool: dict, context: str) -> tuple | None:
        """(class name, rules, combinator, negate, options) for a pool's
        allow/deny members lines, or None (unguarded)."""
        line = pool["line"]
        allows = pool["allow"]
        denies = pool["deny"]
        if not allows and not denies:
            return None
        if allows and denies:
            self.warn(
                f"{context} (line {line}): a pool with both `allow members of` and `deny members of` — only the allow list is imported as the guard"
            )
            denies = []
        names = []
        for source_name, nline in allows or denies:
            cdef = self.classes.get(source_name)
            if cdef is None:
                self.warn(
                    f"{context} (line {nline}): class {source_name!r} is not declared before this pool — pool imported unguarded"
                )
                return None
            if cdef.reason:
                self.warn(
                    f"{context} (line {nline}): pool refers to class {source_name!r}, which could not be imported ({cdef.reason}) — pool imported unguarded"
                )
                return None
            cdef.referenced = True
            names.append(cdef)
        if denies:
            # deny members of "C" -> everyone but C: a generated class not_C = not member('C')
            rules = [{"field": "member", "op": "equals", "value": c.name} for c in names]
            combinator = "any"
            gen = "not_" + "_or_".join(c.name for c in names)
            for c in names:
                self._ensure_global(c)
            return _win._sanitize_class_name(gen), rules, combinator, True, {}
        if len(names) == 1:
            c = names[0]
            return c.name, list(c.rules), c.combinator, c.negate, dict(c.options)
        # several allow lines: any of them — a generated class member('A') or member('B')
        rules = [{"field": "member", "op": "equals", "value": c.name} for c in names]
        for c in names:
            self._ensure_global(c)
        gen = "_or_".join(c.name for c in names)
        return _win._sanitize_class_name(gen), rules, "any", False, {}

    def _ensure_global(self, cdef: _ClassDef) -> None:
        """A class referenced via member('…') must exist in Kea on its own."""
        if any(p.name == cdef.name for p in self.plan.global_classes):
            return
        self.plan.global_classes.append(self._class_policy(cdef))

    def _class_policy(self, cdef: _ClassDef) -> Policy:
        return Policy(
            name=cdef.name,
            enabled=True,
            processing_order=0,
            condition="OR" if cdef.combinator == "any" else "AND",
            rules=list(cdef.rules),
            negate=cdef.negate,
            options=dict(cdef.options),
        )

    # -- host ----------------------------------------------------------------
    def handle_host(self, st: Stmt, ctx: _Ctx, into: list[Reservation] | None) -> None:
        words = st.words()
        line = st.line
        decl_name = words[1] if len(words) > 1 else ""
        short = f"host {decl_name or '?'}"
        label = f"{short} (line {line})"
        if st.body is None:
            self.warn(f"{label}: host without a block — skipped")
            return
        mac: str | None = None
        ip: str | None = None
        hostname = ""
        options: dict[int, str] = dict(ctx.group_options)
        blocked = False
        has_client_id = False
        for h in st.body:
            kw = h.kw
            hw = h.words()
            if kw == "hardware":
                if len(hw) >= 3 and hw[1].lower() == "ethernet":
                    mac = _norm_mac(hw[2])
                    if mac is None:
                        self.warn(f"{label}: hardware ethernet {hw[2]!r} is not a MAC — skipped")
                        return
                else:
                    self.warn(f"{label}: hardware type {hw[1] if len(hw) > 1 else '?'!r} is not ethernet — skipped")
                    return
            elif kw == "fixed-address":
                addrs = [w for w in hw[1:] if w != ","]
                if len(addrs) > 1:
                    self.warn(f"{label}: several fixed-address values — the first ({addrs[0]}) is used")
                ip = addrs[0] if addrs else None
            elif kw == "option":
                parsed, warning = option_statement(h.head[1:], short)
                if warning:
                    if "dhcp-client-identifier" in warning or (parsed and parsed[0] == 61):
                        has_client_id = True
                    self.warn(warning)
                    continue
                code, raw = parsed
                if code == 12:
                    hostname = raw
                elif code == 61:
                    has_client_id = True
                else:
                    options[code] = raw
            elif kw in ("deny", "ignore") and len(hw) > 1 and hw[1].lower() == "booting":
                blocked = True
            elif kw in ("filename", "next-server"):
                self.warn(f"{label}: per-host `{kw}` is not imported — set it on the subnet or a class")
            elif kw in _DDNS_DIRECTIVES:
                self.note_once(
                    "ddns",
                    f"line {h.line}: DDNS settings (`{kw}` and friends) are not imported — configure dynamic DNS on Jen's DDNS page",
                )
            elif kw in ("default-lease-time", "max-lease-time"):
                self.warn(f"{label}: per-host lease times are not imported")
            elif kw in _QUIET_DIRECTIVES:
                self.quiet.append(f"{kw} (line {h.line})")
            else:
                self.warn(f"{label}: `{kw}` inside a host is not supported — ignored")
        if blocked:
            self.warn(f"{label}: `deny booting` — not imported (Kea's equivalent is a class that guards every pool)")
            return
        if mac is None:
            if has_client_id:
                self.warn(
                    f"{label}: identified by dhcp-client-identifier, not a MAC — Kea needs a `client-id` reservation; add it by hand after the import"
                )
            else:
                self.warn(f"{label}: no `hardware ethernet` — skipped")
            return
        if not ip:
            self.warn(f"{label}: no fixed-address — Kea reservations need an address; not imported")
            return
        if not _auth.valid_ip(ip):
            self.warn(f"{label}: fixed-address {ip!r} is not an IPv4 address (hostnames are not resolved) — skipped")
            return
        if not hostname and ctx.use_host_decl_names and decl_name:
            hostname = decl_name
        if not hostname and decl_name:
            hostname = decl_name  # the declaration name is the only name there is
        if hostname:
            sanitized = _win._sanitize_hostname(hostname)
            if _auth.valid_hostname(sanitized) and sanitized:
                hostname = sanitized
            else:
                self.warn(f"{label}: hostname {hostname!r} failed validation — imported without it")
                hostname = ""
        res = Reservation(mac=mac, ip=ip, hostname=hostname, options=options)
        if into is not None:
            into.append(res)
        else:
            self.pending_hosts.append(_PendingHost(res, line))

    def place_pending_hosts(self) -> None:
        for ph in self.pending_hosts:
            target = None
            addr = ipaddress.IPv4Address(ph.reservation.ip)
            for scope in self.plan.scopes:
                net = ipaddress.IPv4Network(f"{scope.scope_id}/{_win._prefix_len(scope.subnet_mask)}", strict=False)
                if addr in net:
                    target = scope
                    break
            if target is None:
                self.warn(
                    f"host {ph.reservation.hostname or ph.reservation.mac} (line {ph.line}): fixed-address {ph.reservation.ip} is in no declared subnet — not imported"
                )
                continue
            target.reservations.append(ph.reservation)

    # -- class ---------------------------------------------------------------
    def handle_class(self, st: Stmt) -> None:
        words = st.words()
        line = st.line
        if len(words) < 2 or st.body is None:
            self.warn(f"line {line}: class needs a name and a block — skipped")
            return
        source_name = words[1]
        name = source_name
        if not _auth.valid_class_name(name):
            name = _win._sanitize_class_name(name)
            self.warn(f"line {line}: class {source_name!r} renamed to {name!r} for Kea")
        if source_name in self.classes:
            self.warn(f"line {line}: class {source_name!r} declared twice — the second is skipped")
            return
        cdef = _ClassDef(name=name, source_name=source_name, line=line)
        matched = False
        for c in st.body:
            kw = c.kw
            cw = c.words()
            if kw == "match":
                matched = True
                if len(cw) > 1 and cw[1].lower() == "if":
                    rules, combinator, negate, reason = match_to_rules(c.head[2:])
                    if reason:
                        cdef.reason = reason
                    else:
                        cdef.rules, cdef.combinator, cdef.negate = rules, combinator, negate
                else:
                    cdef.reason = "`match <data>` without `if` is the subclass model, which Kea does not have"
            elif kw == "spawn":
                cdef.reason = "`spawn with` classes have no Kea equivalent"
            elif kw == "option":
                parsed, warning = option_statement(c.head[1:], f"class {source_name}")
                if warning:
                    self.warn(warning)
                else:
                    cdef.options[parsed[0]] = parsed[1]
            elif kw == "filename":
                if len(cw) > 1:
                    cdef.options[67] = cw[1]
            elif kw == "next-server":
                self.warn(
                    f"class {source_name} (line {c.line}): per-class next-server is not imported — set it on the subnet"
                )
            elif kw == "lease":
                self.warn(f"class {source_name} (line {c.line}): `lease limit` is not supported in Kea — ignored")
            elif kw in ("default-lease-time", "max-lease-time"):
                self.warn(f"class {source_name} (line {c.line}): per-class lease times are not imported")
            elif kw in ("allow", "deny", "ignore"):
                self.warn(f"class {source_name} (line {c.line}): `{kw}` inside a class is not imported")
            else:
                self.warn(f"class {source_name} (line {c.line}): `{kw}` inside a class is not supported — ignored")
        if not matched and cdef.reason is None:
            cdef.reason = "no `match if` expression"
        if cdef.reason:
            self.warn(f"line {line}: class {source_name!r} not imported — {cdef.reason}")
        self.classes[source_name] = cdef

    def finish(self) -> Plan:
        self.place_pending_hosts()
        # classes nobody's pool referenced are still worth having (PXE
        # classes with their own filename, say)
        for cdef in self.classes.values():
            if cdef.reason is None and not cdef.referenced:
                self._ensure_global(cdef)
        if self.quiet:
            self.warn("server tuning directives with no Kea equivalent, ignored: " + ", ".join(self.quiet))
        if not self.plan.scopes:
            self.warn("No subnet declarations found — nothing to import.")
        return self.plan


def parse_config(data: bytes) -> Plan:
    """dhcpd.conf bytes -> a Plan. Never raises on odd input; every
    construct Jen can't map is a warning line with its source line."""
    text = data.decode("utf-8", errors="replace")
    toks, comments = tokenize(text)
    stmts, syntax_warnings = parse_statements(toks)
    interp = _Interp(comments)
    interp.plan.warnings.extend(syntax_warnings)
    interp.walk(stmts, interp.global_ctx, None, "global")
    return interp.finish()


# ── dhcpd.leases (read for the review page's count only) ────────────────────


def parse_leases(data: bytes) -> dict[str, dict]:
    """{ip: {"state", "mac"}} — the LAST declaration for an address wins,
    which is how dhcpd itself reads its append-only leases file."""
    text = data.decode("utf-8", errors="replace")
    toks, _comments = tokenize(text)
    stmts, _warnings = parse_statements(toks)
    out: dict[str, dict] = {}
    for st in stmts:
        if st.kw != "lease" or st.body is None or len(st.head) < 2:
            continue
        ip = st.head[1].text
        if not _auth.valid_ip(ip):
            continue
        entry = {"state": "", "mac": ""}
        for b in st.body:
            w = b.words()
            if b.kw == "binding" and len(w) >= 3 and w[1].lower() == "state":
                entry["state"] = w[2].lower()
            elif b.kw == "hardware" and len(w) >= 3 and w[1].lower() == "ethernet":
                entry["mac"] = _norm_mac(w[2]) or w[2]
        out[ip] = entry
    return out


def active_leases_in_ranges(leases: dict[str, dict], plan: Plan) -> dict:
    """{"active": n, "in_ranges": m, "reserved": r} — active bindings
    overall, those inside a range the plan imports, and those whose
    address is one of the plan's reservations."""
    ranges: list[tuple[int, int]] = []
    reserved: set[str] = set()
    for scope in plan.scopes:
        for lo, hi in _win.split_pool_by_exclusions(scope.start_range, scope.end_range, scope.exclusions):
            ranges.append((lo, hi))
        reserved.update(r.ip for r in scope.reservations)
    active = in_ranges = res = 0
    for ip, entry in leases.items():
        if entry.get("state") != "active":
            continue
        active += 1
        n = int(ipaddress.IPv4Address(ip))
        if any(lo <= n <= hi for lo, hi in ranges):
            in_ranges += 1
        if ip in reserved:
            res += 1
    return {"active": active, "in_ranges": in_ranges, "reserved": res}
