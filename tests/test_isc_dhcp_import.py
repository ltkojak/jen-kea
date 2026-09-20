"""
tests/test_isc_dhcp_import.py
─────────────────────────────
v5.37.0 (Q36) — jen/services/isc_dhcp_import.py: parsing an ISC
dhcpd.conf and mapping it onto the Windows importer's Plan so the same
review → preview → apply wizard runs it. Pure:
`python -m pytest --noconftest tests/test_isc_dhcp_import.py`.

tests/fixtures/dhcpd.conf is synthetic: three real subnets plus a
shared network, hosts inside and outside subnets, classes with every
supported `match if` form, pools with allow/deny, ranges expressed
several ways, and every unsupported construct once.
"""

import pathlib

import pytest

from jen.services import isc_dhcp_import as isc
from jen.services import win_dhcp_import as w

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _toks(text: str):
    return isc.tokenize(text)[0]


@pytest.fixture(scope="module")
def plan():
    return isc.parse_config(_read("dhcpd.conf"))


def _scope(plan, network):
    return next(s for s in plan.scopes if s.scope_id == network)


def _has(plan, *fragments):
    return any(all(f in line for f in fragments) for line in plan.warnings)


# ── tokenizer / statement tree ───────────────────────────────────────────────


class TestTokenizer:
    def test_comments_strings_and_punctuation(self):
        toks, comments = isc.tokenize(
            '# hello\noption domain-name "a; b {c}"; # trailing\nsubnet 1.2.3.0 netmask 255.255.255.0 { }'
        )
        assert comments == {1: "hello", 2: "trailing"}
        texts = [(t.text, t.quoted) for t in toks]
        assert texts[:4] == [("option", False), ("domain-name", False), ("a; b {c}", True), (";", False)]
        assert [t.line for t in toks][:4] == [2, 2, 2, 2]
        assert ("{", False) in texts and ("}", False) in texts

    def test_escaped_quote_inside_a_string(self):
        toks = _toks(r'option x "say \"hi\"";')
        assert toks[2].text == 'say "hi"' and toks[2].quoted

    def test_statement_tree_with_line_numbers(self):
        stmts, warnings = isc.parse_statements(_toks("a 1;\nb {\n  c 2;\n}\n"))
        assert warnings == []
        assert [s.kw for s in stmts] == ["a", "b"]
        assert stmts[0].body is None and stmts[0].line == 1
        assert [c.words() for c in stmts[1].body] == [["c", "2"]] and stmts[1].body[0].line == 3

    def test_unbalanced_braces_warn_instead_of_raising(self):
        _stmts, warnings = isc.parse_statements(_toks("a { b; "))
        assert any("never closed" in x for x in warnings)
        _stmts, warnings = isc.parse_statements(_toks("a; } b;"))
        assert any("unexpected '}'" in x for x in warnings)

    def test_missing_semicolon_before_brace_close(self):
        _stmts, warnings = isc.parse_statements(_toks("a {\n b 1\n}"))
        assert any("line 2" in x and "terminating ';'" in x for x in warnings)


# ── option statements ────────────────────────────────────────────────────────


class TestOptionStatement:
    def _opt(self, text):
        toks = _toks(text)[1:]
        if toks and toks[-1].text == ";":
            toks = toks[:-1]  # the statement parser strips the terminator
        return isc.option_statement(toks, "ctx")

    def test_ip_list_joins_like_the_windows_export(self):
        assert self._opt("option domain-name-servers 8.8.8.8, 8.8.4.4;")[0] == (6, "8.8.8.8, 8.8.4.4")

    def test_quoted_string_and_alias(self):
        assert self._opt('option bootfile-name "pxelinux.0";')[0] == (67, "pxelinux.0")
        assert self._opt('option domain-search "a.lan", "b.lan";')[0] == (119, "a.lan, b.lan")

    def test_numeric_form(self):
        assert self._opt("option option-150 10.0.0.1;")[0] == (150, "10.0.0.1")

    def test_boolean_on_off(self):
        assert self._opt("option ip-forwarding on;")[0] == (19, "true")

    def test_rfc3442_decimal_bytes_become_hex_for_to_kea(self):
        parsed, warning = self._opt("option rfc3442-classless-static-routes 24, 10,9,8, 10,0,1,1;")
        assert warning is None and parsed == (121, "180a09080a000101")
        data, _w = w._decode_classless_routes_hex(parsed[1], "x")
        assert data == "10.9.8.0/24 - 10.0.1.1"

    def test_subnet_mask_is_refused(self):
        parsed, warning = self._opt("option subnet-mask 255.255.255.0;")
        assert parsed is None and "derives it from the prefix" in warning

    def test_definition_and_unknown_name_warn_with_line(self):
        parsed, warning = self._opt("option foo code 224 = text;")
        assert parsed is None and "definition" in warning and "(line 1)" in warning
        parsed, warning = self._opt('option foo "x";')
        assert parsed is None and "not in Jen's catalog" in warning
        parsed, warning = self._opt("option cisco.tftp 1.2.3.4;")
        assert parsed is None and "option space" in warning


# ── match if → rules ─────────────────────────────────────────────────────────


class TestMatchToRules:
    def _m(self, expr):
        return isc.match_to_rules(_toks(expr))

    def test_vendor_class_equals(self):
        rules, comb, neg, reason = self._m('option vendor-class-identifier = "X"')
        assert reason is None and rules == [{"field": "vendor_class", "op": "equals", "value": "X"}]
        assert comb == "all" and neg is False

    def test_substring_prefix_is_starts_with(self):
        rules, _c, _n, reason = self._m('substring(option vendor-class-identifier, 0, 9) = "PXEClient"')
        assert reason is None and rules == [{"field": "vendor_class", "op": "starts_with", "value": "PXEClient"}]

    def test_substring_length_mismatch_is_refused(self):
        _r, _c, _n, reason = self._m('substring(option vendor-class-identifier, 0, 3) = "PXEClient"')
        assert reason and "never matches" in reason

    def test_hardware_forms(self):
        assert self._m("hardware = 1:aa:bb:cc:dd:ee:ff")[0] == [
            {"field": "mac", "op": "equals", "value": "aa:bb:cc:dd:ee:ff"}
        ]
        assert self._m("substring(hardware, 1, 3) = 0:80:77")[0] == [
            {"field": "mac_oui", "op": "equals", "value": "00:80:77"}
        ]
        assert self._m("substring(hardware, 1, 6) = 00:80:77:01:02:03")[0] == [
            {"field": "mac", "op": "equals", "value": "00:80:77:01:02:03"}
        ]
        assert "type byte" in (self._m("substring(hardware, 0, 6) = 00:80:77:01:02:03")[3] or "")

    def test_client_id_string_becomes_hex(self):
        rules, _c, _n, reason = self._m('option dhcp-client-identifier = "ab"')
        assert reason is None and rules == [{"field": "client_id", "op": "equals", "value": "6162"}]

    def test_relay_ids(self):
        assert self._m('option agent.circuit-id = "eth0"')[0] == [
            {"field": "circuit_id", "op": "equals", "value": "eth0"}
        ]
        assert self._m("option agent.remote-id = 01:02")[0] == [
            {"field": "remote_id", "op": "equals", "value": "01:02"}
        ]

    def test_and_or_and_not(self):
        rules, comb, neg, reason = self._m('(option user-class = "a") and (option host-name = "b")')
        assert reason is None and comb == "all" and [r["field"] for r in rules] == ["user_class", "hostname"]
        rules, comb, _n, _r = self._m('option user-class = "a" or option user-class = "b"')
        assert comb == "any" and len(rules) == 2
        rules, _c, neg, reason = self._m('not (option user-class = "a")')
        assert reason is None and neg is True and len(rules) == 1

    def test_unsupported_shapes(self):
        assert (
            "mixed"
            in self._m('(option user-class = "a") and (option user-class = "b") or (option user-class = "c")')[3]
        )
        assert "not a supported match subject" in self._m('option vendor-class-identifier ~= "^Foo"')[3]
        assert "matching on option" in self._m('option domain-name = "x"')[3]
        assert "lhs = rhs" in self._m("option user-class")[3]

    def test_build_expression_accepts_every_rule_shape_produced(self):
        from jen.services import kea_classes

        for expr in (
            'substring(option vendor-class-identifier, 0, 9) = "PXEClient"',
            "substring(hardware, 1, 3) = 0:80:77",
            "hardware = 1:aa:bb:cc:dd:ee:ff",
            'option dhcp-client-identifier = "ab"',
            'option agent.circuit-id = "eth0"',
            "option agent.remote-id = 01:02",
        ):
            rules, comb, neg, reason = self._m(expr)
            assert reason is None
            assert kea_classes.build_expression(rules, combinator=comb, negate=neg)


# ── the fixture, parsed ──────────────────────────────────────────────────────


class TestParseFixture:
    def test_source_and_subnet_inventory(self, plan):
        assert plan.source == "isc"
        assert [s.scope_id for s in plan.scopes] == [
            "10.0.1.0",
            "10.0.2.0",
            "10.0.3.0",
            "10.0.4.0",
            "10.0.5.0",
            "192.168.99.0",
        ]
        assert all(s.state == "Active" for s in plan.scopes)

    def test_global_options_and_lease_inheritance(self, plan):
        assert plan.server_options == {
            15: "example.lan",
            6: "10.0.0.53, 10.0.0.54",
            42: "10.0.0.123",
            119: "example.lan, corp.example.lan",
        }
        assert _scope(plan, "10.0.1.0").lease_seconds == 3600  # its own
        assert _scope(plan, "10.0.2.0").lease_seconds == 600  # global default-lease-time
        assert (
            isc.parse_config(b"subnet 10.0.0.0 netmask 255.255.255.0 { range 10.0.0.5 10.0.0.9; }")
            .scopes[0]
            .lease_seconds
            == isc.DHCPD_DEFAULT_LEASE_SECONDS
        )

    def test_subnet_name_from_the_comment_above_it(self, plan):
        assert _scope(plan, "10.0.1.0").name == "Office LAN"
        assert _scope(plan, "10.0.2.0").name == "Students"
        assert _scope(plan, "10.0.3.0").name == "CAMPUS 10.0.3.0/24"
        assert _scope(plan, "10.0.5.0").name == "10.0.5.0/24"

    def test_several_ranges_become_one_span_with_gaps_as_exclusions(self, plan):
        s = _scope(plan, "10.0.1.0")
        assert (s.start_range, s.end_range) == ("10.0.1.100", "10.0.1.253")
        assert s.exclusions == [("10.0.1.150", "10.0.1.159")]  # adjacent ranges 160-199/200-209/210-… merged

    def test_overlapping_and_outside_ranges(self, plan):
        s = _scope(plan, "10.0.5.0")
        assert (s.start_range, s.end_range) == ("10.0.5.10", "10.0.5.40") and s.exclusions == []
        assert _has(plan, "line 148", "overlaps")
        assert _has(plan, "line 150", "outside the subnet")

    def test_subnet_options_next_server_and_filename(self, plan):
        s = _scope(plan, "10.0.1.0")
        assert (
            s.options[3] == "10.0.1.1"
            and s.options[28] == "10.0.1.255"
            and s.options[121] == "180a09080a000101000a000101"
        )
        assert s.next_server == "10.0.0.5" and s.boot_file == "undionly.kpxe"

    def test_shared_network_and_its_options_pushed_down(self, plan):
        assert plan.superscopes == {"CAMPUS": ["10.0.2.0", "10.0.3.0"]}
        for sid in ("10.0.2.0", "10.0.3.0"):
            s = _scope(plan, sid)
            assert s.superscope_name == "CAMPUS" and s.options[15] == "campus.example.lan"
        assert _scope(plan, "10.0.1.0").superscope_name is None

    def test_no_range_subnet_is_reservation_only(self, plan):
        s = _scope(plan, "10.0.4.0")
        assert s.start_range == s.end_range == "10.0.4.0" and s.exclusions == [("10.0.4.0", "10.0.4.0")]
        assert _has(plan, "line 142", "no range")

    def test_duplicate_subnet_is_skipped(self, plan):
        assert _scope(plan, "192.168.99.0").start_range == "192.168.99.10"
        assert _has(plan, "line 156", "declared twice")

    def test_hosts_inside_a_subnet(self, plan):
        res = {r.ip: r for r in _scope(plan, "10.0.1.0").reservations}
        assert res["10.0.1.50"].mac == "00:80:77:01:02:03" and res["10.0.1.50"].hostname == "hp-printer"
        assert res["10.0.1.50"].options == {}  # subnet options are NOT copied onto the reservation
        assert res["10.0.1.51"].hostname == "nas" and res["10.0.1.51"].options == {6: "10.0.1.1"}
        assert _has(plan, "host nas (line 119)", "subnet-mask")

    def test_hosts_outside_a_subnet_are_placed_by_address_with_group_options(self, plan):
        res = {r.ip: r for r in _scope(plan, "10.0.4.0").reservations}
        assert set(res) == {"10.0.4.10", "10.0.4.11"}
        assert res["10.0.4.10"].hostname == "camera-1" and res["10.0.4.10"].options == {6: "10.0.0.55"}
        assert res["10.0.4.11"].hostname == "Camera-Two-rear"
        assert _has(plan, "host camera-2 (line 167)", "several fixed-address")
        assert 6 not in plan.server_options or plan.server_options[6] != "10.0.0.55"  # group option never went global
        assert _has(plan, "host homeless (line 174)", "in no declared subnet")
        assert {r.ip for r in _scope(plan, "10.0.2.0").reservations} == {"10.0.2.6"}

    @pytest.mark.parametrize(
        "line,fragment",
        [
            ("line 179", "hostnames are not resolved"),
            ("line 184", "no fixed-address"),
            ("line 189", "dhcp-client-identifier"),
            ("line 194", "deny booting"),
            ("line 200", "token-ring"),
            ("line 205", "per-host `filename`"),
        ],
    )
    def test_host_shapes_that_cannot_map_warn_with_their_line(self, plan, line, fragment):
        assert _has(plan, line, fragment)

    def test_classes(self, plan):
        by_name = {p.name: p for p in plan.global_classes}
        assert by_name["pxe-clients"].rules == [{"field": "vendor_class", "op": "starts_with", "value": "PXEClient"}]
        assert by_name["pxe-clients"].options == {67: "pxelinux.0", 66: "10.0.0.5"}
        assert by_name["printers"].rules == [{"field": "mac_oui", "op": "equals", "value": "00:80:77"}]
        assert by_name["the_boss_laptop"].rules == [{"field": "mac", "op": "equals", "value": "aa:bb:cc:dd:ee:ff"}]
        assert _has(plan, "line 54", "renamed to 'the_boss_laptop'")
        assert "mixed" not in by_name and _has(plan, "line 58", "mixed `and` / `or`")
        assert _has(plan, "line 62", "regex-class")
        assert _has(plan, "line 66", "spawn with")
        assert _has(plan, "line 71", "subclass model")
        assert _has(plan, "line 74", "subclass is not supported")

    def test_pool_guards(self, plan):
        pols = _scope(plan, "10.0.1.0").policies
        by_range = {p.ip_ranges[0]: p for p in pols}
        allow = by_range[("10.0.1.210", "10.0.1.219")]
        assert (
            allow.name == "voip-phones"
            and allow.rules[0]["field"] == "vendor_class"
            and allow.options == {42: "10.0.0.124"}
        )
        deny = by_range[("10.0.1.220", "10.0.1.229")]
        assert deny.name == "not_printers" and deny.negate is True
        assert deny.rules == [{"field": "member", "op": "equals", "value": "printers"}]
        both = by_range[("10.0.1.230", "10.0.1.239")]
        assert both.name == "pxe-clients_or_voip-phones" and both.condition == "OR" and len(both.rules) == 2
        assert ("10.0.1.240", "10.0.1.249") not in by_range and _has(plan, "line 104", "not declared before this pool")
        assert ("10.0.1.250", "10.0.1.253") not in by_range and _has(plan, "line 108", "could not be imported")
        assert _has(plan, "line 95", "pool-level options")

    @pytest.mark.parametrize(
        "line,fragment",
        [
            ("line 9", "max-lease-time"),
            ("line 11", "DDNS"),
            ("line 17", "option space"),
            ("line 18", "option definition"),
            ("line 22", "include"),
            ("line 24", "failover"),
            ("line 37", "OMAPI"),
            ("line 121", "conditional"),
            ("line 132", "deny unknown-clients"),
            ("line 133", "no BOOTP"),
            ("line 160", "group blocks are flattened"),
            ("line 221", "`frobnicate` is not recognised"),
        ],
    )
    def test_every_unsupported_construct_warns_once_with_its_line(self, plan, line, fragment):
        matches = [x for x in plan.warnings if line in x and fragment in x]
        assert len(matches) == 1, matches

    def test_quiet_directives_are_one_summary_line(self, plan):
        lines = [x for x in plan.warnings if x.startswith("server tuning directives")]
        assert len(lines) == 1 and "log-facility (line 12)" in lines[0] and "ping-check (line 13)" in lines[0]

    def test_garbage_input_never_raises(self):
        for data in (b"", b"}{{{", b"\xff\xfe garbage", b'subnet "x" { range; }', b"host { }", b"class { match if; }"):
            plan = isc.parse_config(data)
            assert isinstance(plan, w.Plan)


# ── to_kea: the same shape as the Windows path ───────────────────────────────


class TestToKea:
    def _names(self, plan):
        return {s.scope_id: {"id": 100 + i, "name": s.name} for i, s in enumerate(plan.scopes)}

    def test_output_shape_matches_the_windows_importer(self, plan):
        win_plan = w.parse_export(_read("windows-dhcp-export.xml"))
        win_names = {s.scope_id: {"id": 10 + i, "name": s.name} for i, s in enumerate(win_plan.scopes)}
        win_cfg, win_res, win_decl, win_report = w.to_kea(
            win_plan, None, win_names, {"scopes": {}, "server_options": True}
        )
        cfg, res, decl, report = isc.to_kea(plan, None, self._names(plan), {"scopes": {}, "server_options": True})
        assert set(cfg) == set(win_cfg) == {"Dhcp4"}
        win_sub = win_cfg["Dhcp4"]["subnet4"][0]
        sub = next(s for s in cfg["Dhcp4"]["subnet4"] if s["id"] == 100)
        guard_keys = {"client-class", "client-classes"}  # a subnet-level guard is per-input, not per-source
        assert set(win_sub) - guard_keys <= set(sub)
        assert set(sub) - set(win_sub) <= {"next-server", "boot-file-name"} | guard_keys
        assert set(res[0]) == set(win_res[0]) and set(decl[100]) == set(next(iter(win_decl.values())))
        assert isinstance(report, list) and isinstance(win_report, list)

    def test_subnets_classes_guards_and_shared_network(self, plan):
        cfg, res, decl, report = isc.to_kea(plan, None, self._names(plan), {"scopes": {}, "server_options": True})
        d4 = cfg["Dhcp4"]
        classes = {c["name"]: c for c in d4["client-classes"]}
        assert classes["pxe-clients"]["test"] == "substring(option[60].hex,0,9) == 'PXEClient'"
        assert classes["printers"]["test"] == "substring(pkt4.mac,0,3) == 0x008077"
        assert classes["not_printers"]["test"] == "not (member('printers'))"
        assert classes["pxe-clients_or_voip-phones"]["test"] == "(member('pxe-clients')) or (member('voip-phones'))"
        # member() classes are declared before the classes that reference them
        order = [c["name"] for c in d4["client-classes"]]
        assert order.index("printers") < order.index("not_printers")
        office = next(s for s in d4["subnet4"] if s["id"] == 100)
        guards = {p["pool"]: p.get("client-class") for p in office["pools"]}
        assert guards["10.0.1.210 - 10.0.1.219"] == "voip-phones"
        assert guards["10.0.1.220 - 10.0.1.229"] == "not_printers"
        assert guards["10.0.1.230 - 10.0.1.239"] == "pxe-clients_or_voip-phones"
        assert guards["10.0.1.100 - 10.0.1.149"] is None and guards["10.0.1.160 - 10.0.1.209"] is None
        assert office["next-server"] == "10.0.0.5" and office["boot-file-name"] == "undionly.kpxe"
        assert office["valid-lifetime"] == 3600
        assert {o["code"]: o["data"] for o in office["option-data"]}[
            121
        ] == "10.9.8.0/24 - 10.0.1.1, 0.0.0.0/0 - 10.0.1.1"
        campus = d4["shared-networks"][0]
        assert campus["name"] == "CAMPUS" and [s["id"] for s in campus["subnet4"]] == [101, 102]
        assert {o["code"] for o in d4["option-data"]} == {15, 6, 42, 119}
        assert {r["ip-address"] for r in res} == {"10.0.1.50", "10.0.1.51", "10.0.2.6", "10.0.4.10", "10.0.4.11"}
        assert next(r for r in res if r["ip-address"] == "10.0.4.10")["option-data"][0]["code"] == 6
        assert decl[103] == {"name": _scope(plan, "10.0.4.0").name, "cidr": "10.0.4.0/24"}
        assert next(s for s in d4["subnet4"] if s["id"] == 103)["pools"] == []

    def test_global_classes_can_be_left_out(self, plan):
        only_one = {s.scope_id: s.scope_id == "10.0.5.0" for s in plan.scopes}
        cfg, _r, _d, _rep = isc.to_kea(plan, None, self._names(plan), {"scopes": only_one, "classes": False})
        assert "client-classes" not in cfg["Dhcp4"] or not cfg["Dhcp4"]["client-classes"]


# ── dhcpd.leases ─────────────────────────────────────────────────────────────


class TestLeases:
    def test_last_declaration_wins_and_counts(self, plan):
        leases = isc.parse_leases(_read("dhcpd.leases"))
        assert leases["10.0.1.102"]["state"] == "free"
        assert leases["10.0.1.50"] == {"state": "active", "mac": "00:80:77:01:02:03"}
        assert isc.active_leases_in_ranges(leases, plan) == {"active": 4, "in_ranges": 2, "reserved": 1}

    def test_garbage_leases_file(self):
        assert isc.parse_leases(b"not a leases file {") == {}


class TestParserFuzzAndRealFiles:
    """v5.49.0-beta.2 (audit M) - a deterministic token-soup fuzz (no new
    dependency) and every file under tests/fixtures/isc/."""

    VOCAB = [
        "subnet",
        "netmask",
        "range",
        "pool",
        "host",
        "class",
        "match",
        "if",
        "option",
        "hardware",
        "ethernet",
        "fixed-address",
        "{",
        "}",
        ";",
        ",",
        '"',
        "(",
        ")",
        "=",
        "10.0.0.0",
        "255.255.255.0",
        "10.0.0.10",
        "10.0.0.20",
        "aa:bb:cc:dd:ee:01",
        '"a;b"',
        '"unterminated',
        ";",
        "}",
        "{",
        "routers",
        "domain-name-servers",
        "default-lease-time",
        "shared-network",
        "allow",
        "deny",
        "members",
        "of",
        "substring",
        "vendor-class-identifier",
    ]

    WELL_FORMED = "subnet 10.9.0.0 netmask 255.255.255.0 {\n  range 10.9.0.10 10.9.0.20;\n}\n"

    @staticmethod
    def _soup(rng, n):
        words = TestParserFuzzAndRealFiles.VOCAB
        out = []
        for _ in range(n):
            w = rng.choice(words)
            out.append(w)
            if rng.random() < 0.15:
                out.append("\n")
        return " ".join(out)

    def test_never_raises_is_deterministic_and_keeps_a_wellformed_subnet(self):
        import random

        rng = random.Random(20260919)
        for _ in range(500):
            soup = self._soup(rng, rng.randint(0, 60))
            for text in (soup, self.WELL_FORMED + soup):
                data = text.encode()
                a = isc.parse_config(data)  # must not raise
                b = isc.parse_config(data)
                assert a == b, text
            plan = isc.parse_config((self.WELL_FORMED + soup).encode())
            assert any(s.scope_id == "10.9.0.0" for s in plan.scopes) or any("line 1" in w for w in plan.warnings), (
                soup,
                plan.warnings,
            )

    @pytest.mark.parametrize("path", sorted((FIXTURES / "isc").glob("*.conf")), ids=lambda p: p.name)
    def test_real_world_file_parses_into_scopes_or_warnings(self, path):
        plan = isc.parse_config(path.read_bytes())
        assert plan.scopes or plan.warnings
