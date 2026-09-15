"""
tests/test_dhcp_explain.py
──────────────────────────
v5.35.0 (Q34) — the DHCP decision explainer. Pure: no database, no
Kea. `python -m pytest --noconftest tests/test_dhcp_explain.py`.

The parser accepts exactly what jen/services/kea_classes.py::build_expression
emits (proved by round-tripping the builder's own output) and refuses
everything else; the evaluator is three-valued; explain() follows Kea's
order — subnet, reservation, classes, subnet guards, pools, options.
"""

import pytest

from jen.services import dhcp_explain as ex
from jen.services.kea_classes import build_expression

MAC = "aa:bb:cc:dd:ee:01"


def _client(**kw):
    base = {"mac": MAC}
    base.update(kw)
    return base


# ── Grammar ──────────────────────────────────────────────────────────────────


class TestParser:
    @pytest.mark.parametrize(
        "rules,combinator,negate",
        [
            ([{"field": "vendor_class", "op": "equals", "value": "MSFT 5.0"}], "all", False),
            ([{"field": "vendor_class", "op": "starts_with", "value": "MSFT"}], "all", False),
            ([{"field": "hostname", "op": "starts_with", "value": "printer"}], "all", True),
            ([{"field": "mac", "op": "equals", "value": "aa:bb:cc:dd:ee:01"}], "all", False),
            ([{"field": "mac_oui", "op": "equals", "value": "aa:bb:cc"}], "all", False),
            ([{"field": "client_id", "op": "equals", "value": "01aabbccddee01"}], "all", False),
            ([{"field": "circuit_id", "op": "equals", "value": "eth1/1"}], "all", False),
            ([{"field": "remote_id", "op": "equals", "value": "0a0b"}], "all", False),
            ([{"field": "member", "op": "equals", "value": "base"}], "all", False),
            (
                [
                    {"field": "vendor_class", "op": "equals", "value": "x"},
                    {"field": "member", "op": "equals", "value": "y"},
                ],
                "any",
                False,
            ),
            (
                [
                    {"field": "user_class", "op": "starts_with", "value": "iPXE"},
                    {"field": "mac_oui", "op": "equals", "value": "001122"},
                    {"field": "hostname", "op": "equals", "value": "h"},
                ],
                "all",
                True,
            ),
        ],
    )
    def test_everything_the_builder_emits_parses(self, rules, combinator, negate):
        text = build_expression(rules, combinator, negate)
        ast = ex.parse_expression(text)
        assert ast

    @pytest.mark.parametrize(
        "text",
        [
            "ifelse(option[60].exists, 'a', 'b') == 'a'",
            "pkt4.transid == 0x01",
            "option[125].hex == 'x'",  # accessor outside the vocabulary
            "substring(option[60].hex,2,3) == 'FT'",  # non-zero start
            "option[60].hex == 'a' and",  # dangling
            "concat('a','b') == 'ab'",
            "vendor[4491].option[2].hex == 0x01",
            "",
        ],
    )
    def test_outside_the_grammar_is_refused_not_guessed(self, text):
        with pytest.raises(ex.ExprError):
            ex.parse_expression(text)


class TestEvaluate:
    def _eval(self, text, client, members=None):
        missing: set = set()
        return ex.evaluate(ex.parse_expression(text), client, members or {}, missing), missing

    def test_string_equals_and_prefix(self):
        c = _client(vendor_class="MSFT 5.0")
        assert self._eval("option[60].hex == 'MSFT 5.0'", c)[0] is True
        assert self._eval("substring(option[60].hex,0,4) == 'MSFT'", c)[0] is True
        assert self._eval("option[60].hex == 'android'", c)[0] is False

    def test_mac_and_oui_compare_as_bytes(self):
        c = _client()
        assert self._eval("pkt4.mac == 0xaabbccddee01", c)[0] is True
        assert self._eval("substring(pkt4.mac,0,3) == 0xaabbcc", c)[0] is True
        assert self._eval("substring(pkt4.mac,0,3) == 0x001122", c)[0] is False

    def test_hex_accessor_accepts_separators(self):
        c = _client(client_id="01:aa:bb:cc:dd:ee:01")
        assert self._eval("option[61].hex == 0x01aabbccddee01", c)[0] is True

    def test_missing_input_is_unknown_and_named(self):
        v, missing = self._eval("option[77].hex == 'iPXE'", _client())
        assert v is None and missing == {"user_class"}

    def test_three_valued_logic(self):
        c = _client(vendor_class="MSFT 5.0")  # user_class unknown
        assert self._eval("(option[60].hex == 'MSFT 5.0') or (option[77].hex == 'x')", c)[0] is True
        assert self._eval("(option[60].hex == 'nope') and (option[77].hex == 'x')", c)[0] is False
        assert self._eval("(option[60].hex == 'MSFT 5.0') and (option[77].hex == 'x')", c)[0] is None
        assert self._eval("not (option[77].hex == 'x')", c)[0] is None
        assert self._eval("not (option[60].hex == 'nope')", c)[0] is True

    def test_member_sees_only_evaluated_classes(self):
        assert self._eval("member('base')", _client(), {"base": True})[0] is True
        assert self._eval("member('base')", _client(), {"base": False})[0] is False
        assert self._eval("member('later')", _client(), {})[0] is None


# ── Reservations ─────────────────────────────────────────────────────────────


class TestReservationFlags:
    def test_defaults(self):
        assert ex.reservation_flags({}, {}) == {"global": False, "in_subnet": True}

    def test_legacy_mode_and_new_keys(self):
        assert ex.reservation_flags({"reservation-mode": "global"}, {}) == {"global": True, "in_subnet": False}
        assert ex.reservation_flags({"reservation-mode": "disabled"}, {}) == {"global": False, "in_subnet": False}
        assert ex.reservation_flags({}, {"reservations-global": True}) == {"global": True, "in_subnet": True}
        assert ex.reservation_flags({"reservations-global": True}, {"reservations-in-subnet": False}) == {
            "global": True,
            "in_subnet": False,
        }


# ── The decision ─────────────────────────────────────────────────────────────

CFG = {
    "valid-lifetime": 4000,
    "option-data": [{"name": "domain-name-servers", "data": "1.1.1.1"}, {"name": "domain-name", "data": "lan"}],
    "client-classes": [
        {
            "name": "windows",
            "test": "substring(option[60].hex,0,4) == 'MSFT'",
            "option-data": [{"name": "domain-name-servers", "data": "9.9.9.9"}],
        },
        {"name": "printers", "test": "substring(pkt4.mac,0,3) == 0xaabbcc"},
        {"name": "vip", "test": "member('printers') and (option[12].text == 'boss-printer')"},
        {"name": "weird", "test": "ifelse(option[60].exists, 'a', 'b') == 'a'"},
        {"name": "late", "test": "option[77].hex == 'iPXE'", "only-in-additional-list": True},
        {"name": "byres"},
    ],
    "subnet4": [
        {
            "id": 1,
            "subnet": "10.0.1.0/24",
            "valid-lifetime": 3600,
            "option-data": [{"name": "routers", "data": "10.0.1.1"}],
            "pools": [
                {
                    "pool": "10.0.1.10 - 10.0.1.99",
                    "client-classes": ["printers"],
                    "option-data": [{"name": "domain-name-servers", "data": "10.0.1.53"}],
                },
                {"pool": "10.0.1.100 - 10.0.1.200"},
            ],
            "reservations": [
                {
                    "hw-address": "aa:bb:cc:dd:ee:02",
                    "ip-address": "10.0.1.250",
                    "hostname": "cfg-res",
                    "client-classes": ["byres"],
                }
            ],
            "relay": {"ip-addresses": ["10.0.1.1"]},
        }
    ],
    "shared-networks": [
        {
            "name": "office",
            "option-data": [{"name": "ntp-servers", "data": "10.0.0.123"}],
            "subnet4": [
                {
                    "id": 2,
                    "subnet": "10.0.2.0/24",
                    "client-classes": ["windows"],
                    "pools": [{"pool": "10.0.2.10 - 10.0.2.99"}],
                },
                {"id": 3, "subnet": "10.0.3.0/24", "pools": [{"pool": "10.0.3.10 - 10.0.3.99"}]},
            ],
        }
    ],
}


def _stage(result, stage):
    return next(s for s in result["steps"] if s["stage"] == stage)


class TestExplain:
    def test_unknown_subnet(self):
        r = ex.explain(CFG, _client(), subnet_id=99)
        assert r["ok"] is False and "subnet 99" in r["error"]

    def test_printer_gets_the_guarded_pool_and_its_options(self):
        r = ex.explain(CFG, _client(vendor_class="HP JetDirect"), subnet_id=1)
        assert r["ok"]
        by = {c["name"]: c for c in r["classes"]}
        assert by["printers"]["matched"] is True
        assert by["windows"]["matched"] is False
        assert by["vip"]["matched"] is None and "hostname" in by["vip"]["reason"]
        assert by["weird"]["evaluable"] is False and "not evaluable" in by["weird"]["reason"]
        assert by["late"]["matched"] is False and "only-in-additional-list" in by["late"]["reason"]
        assert by["byres"]["matched"] is None
        assert r["pools"][0]["eligible"] is True and r["pools"][1]["eligible"] is True
        assert r["answer"]["ip"] == "from pool 10.0.1.10 - 10.0.1.99"
        assert r["answer"]["lifetime"] == 3600 and r["answer"]["lifetime_from"] == "subnet"
        opts = {o["name"]: o for o in r["options"]}
        assert opts["domain-name-servers"]["data"] == "10.0.1.53" and opts["domain-name-servers"]["source"] == "pool"
        assert "global" in opts["domain-name-servers"]["overridden"]
        assert opts["routers"]["source"] == "subnet" and opts["domain-name"]["source"] == "global"
        assert r["confidence"]["not_evaluable"] == ["weird"] and "vip" in r["confidence"]["classes_undecided"]

    def test_non_printer_skips_the_guarded_pool(self):
        r = ex.explain(CFG, _client(mac="00:11:22:33:44:55", vendor_class="MSFT 5.0"), subnet_id=1)
        assert r["pools"][0]["eligible"] is False and r["pools"][1]["eligible"] is True
        assert r["answer"]["ip"] == "from pool 10.0.1.100 - 10.0.1.200"
        opts = {o["name"]: o for o in r["options"]}
        # windows matched → class option beats global, loses to nothing here
        assert (
            opts["domain-name-servers"]["data"] == "9.9.9.9"
            and opts["domain-name-servers"]["source"] == "class:windows"
        )

    def test_config_file_reservation_wins_and_assigns_classes(self):
        r = ex.explain(CFG, _client(mac="aa:bb:cc:dd:ee:02"), subnet_id=1)
        assert r["reservation"]["ip"] == "10.0.1.250" and r["reservation"]["scope"] == "subnet"
        assert _stage(r, "reservation")["verdict"] == "matched"
        assert r["answer"]["ip"] == "10.0.1.250" and "reservation" in r["answer"]["how"]
        assert r["answer"]["hostname"] == "cfg-res"
        by = {c["name"]: c for c in r["classes"]}
        assert by["byres"]["matched"] is True
        assert "KNOWN" not in by  # builtins aren't listed as rows, but drive member()

    def test_host_db_reservation_and_global_rules(self):
        rows = [
            {
                "subnet_id": 0,
                "identifier_type": 0,
                "identifier": "aabbccddee01",
                "ip": "10.0.1.251",
                "hostname": "glob",
                "classes": [],
                "options": [{"name": "domain-name-servers", "data": "8.8.8.8"}],
            }
        ]
        r = ex.explain(CFG, _client(), subnet_id=1, reservations=rows)
        assert r["reservation"] is None  # reservations-global is off by default
        cfg = dict(CFG, **{"reservations-global": True})
        r = ex.explain(cfg, _client(), subnet_id=1, reservations=rows)
        assert r["reservation"]["scope"] == "global" and r["answer"]["ip"] == "10.0.1.251"
        opts = {o["name"]: o for o in r["options"]}
        assert (
            opts["domain-name-servers"]["source"] == "reservation" and opts["domain-name-servers"]["data"] == "8.8.8.8"
        )

    def test_current_lease_is_renewed(self):
        r = ex.explain(CFG, _client(mac="00:11:22:33:44:55"), subnet_id=1, lease={"ip": "10.0.1.150", "subnet_id": 1})
        assert r["answer"]["ip"] == "10.0.1.150" and "renewed" in r["answer"]["how"]

    def test_shared_network_guard_moves_to_a_sibling(self):
        r = ex.explain(CFG, _client(mac="00:11:22:33:44:55", vendor_class="Linux"), subnet_id=2)
        assert r["subnet"]["id"] == 3  # subnet 2 guards on windows → not matched → sibling 3
        assert _stage(r, "subnet-guards")["verdict"] == "another subnet"
        opts = {o["name"]: o for o in r["options"]}
        assert opts["ntp-servers"]["source"] == "shared-network:office"
        r = ex.explain(CFG, _client(mac="00:11:22:33:44:55", vendor_class="MSFT 5.0"), subnet_id=2)
        assert r["subnet"]["id"] == 2 and _stage(r, "subnet-guards")["verdict"] == "eligible"

    def test_undecided_guard_is_reported_not_guessed(self):
        r = ex.explain(CFG, _client(mac="00:11:22:33:44:55"), subnet_id=2)  # vendor class unknown
        states = {s["id"]: s["eligible"] for s in r["subnet"]["candidates"]}
        assert states[2] is None and states[3] is True
        assert r["subnet"]["id"] == 3  # first *known* eligible

    def test_giaddr_is_checked_against_relay_and_range(self):
        r = ex.explain(CFG, _client(giaddr="10.0.1.1"), subnet_id=1)
        assert "listed in this subnet's relay addresses" in _stage(r, "subnet")["evidence"][0]
        r = ex.explain(CFG, _client(giaddr="10.9.9.9"), subnet_id=1)
        assert "would NOT select" in _stage(r, "subnet")["evidence"][0]

    def test_no_eligible_pool_means_no_address(self):
        cfg = {
            "subnet4": [
                {
                    "id": 5,
                    "subnet": "10.0.5.0/24",
                    "pools": [{"pool": "10.0.5.10 - 10.0.5.20", "client-classes": ["KNOWN"]}],
                }
            ]
        }
        r = ex.explain(cfg, _client(), subnet_id=5)
        assert r["answer"]["ip"] is None and "no eligible pool" in r["answer"]["how"]
        assert r["answer"]["lifetime"] == 7200 and r["answer"]["lifetime_from"] == "Kea default"
