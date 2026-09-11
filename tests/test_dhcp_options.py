"""
tests/test_dhcp_options.py
───────────────────────────
v5.18.0 (Q12) — jen/services/dhcp_options.py: the DHCPv4 option catalog,
per-type validation, and the "effective options" walk. Pure — no DB, no
Flask.
"""

from jen.services import dhcp_options as do


class TestCatalog:
    def test_every_code_is_unique(self):
        codes = list(do.V4_OPTIONS.keys())
        assert len(codes) == len(set(codes))

    def test_every_name_is_unique(self):
        names = [v["name"] for v in do.V4_OPTIONS.values()]
        assert len(names) == len(set(names))

    def test_every_type_is_a_known_type(self):
        for code, v in do.V4_OPTIONS.items():
            assert v["type"] in do.TYPES, f"code {code} has unknown type {v['type']!r}"

    def test_lease_timers_are_excluded(self):
        assert 51 not in do.V4_OPTIONS
        assert 58 not in do.V4_OPTIONS
        assert 59 not in do.V4_OPTIONS

    def test_managed_codes_are_routers_and_dns(self):
        assert {3, 6} == do.MANAGED_AT_SUBNET
        assert do.V4_OPTIONS[3]["name"] == "routers"
        assert do.V4_OPTIONS[6]["name"] == "domain-name-servers"

    def test_name_to_code_round_trips(self):
        for code, v in do.V4_OPTIONS.items():
            assert do.NAME_TO_CODE[v["name"]] == code

    def test_catalog_choices_sorted_by_code(self):
        choices = do.catalog_choices()
        assert [c["code"] for c in choices] == sorted(c["code"] for c in choices)
        assert choices[0]["name"] == do.V4_OPTIONS[choices[0]["code"]]["name"]

    def test_type_for_unknown_code_is_none(self):
        assert do.type_for(9999) is None
        assert do.type_for(3) == "ip-list"


class TestValidate:
    def test_ip(self):
        assert do.validate("ip", "10.0.0.1") is None
        assert do.validate("ip", "not-an-ip") is not None
        assert do.validate("ip", "") is not None

    def test_ip_list(self):
        assert do.validate("ip-list", "10.0.0.1, 10.0.0.2") is None
        assert do.validate("ip-list", "10.0.0.1, bad") is not None

    def test_ip_pair_list_must_be_even(self):
        assert do.validate("ip-pair-list", "10.0.0.0, 10.0.0.1") is None
        assert do.validate("ip-pair-list", "10.0.0.0, 10.0.0.1, 10.0.0.2") is not None
        assert do.validate("ip-pair-list", "10.0.0.0") is not None

    def test_string_accepts_anything_nonempty(self):
        assert do.validate("string", "whatever") is None
        assert do.validate("string", "") is not None

    def test_fqdn(self):
        assert do.validate("fqdn", "example.com") is None
        assert do.validate("fqdn", "bad host") is not None

    def test_fqdn_list(self):
        assert do.validate("fqdn-list", "a.example.com, b.example.com") is None
        assert do.validate("fqdn-list", "a.example.com, bad host") is not None

    def test_boolean(self):
        assert do.validate("boolean", "true") is None
        assert do.validate("boolean", "false") is None
        assert do.validate("boolean", "TRUE") is None
        assert do.validate("boolean", "yes") is not None

    def test_uint_ranges(self):
        assert do.validate("uint8", "0") is None
        assert do.validate("uint8", "255") is None
        assert do.validate("uint8", "256") is not None
        assert do.validate("uint8", "-1") is not None
        assert do.validate("uint16", "65535") is None
        assert do.validate("uint16", "65536") is not None
        assert do.validate("uint32", str(2**32 - 1)) is None
        assert do.validate("uint32", str(2**32)) is not None
        assert do.validate("uint8", "abc") is not None

    def test_int32(self):
        assert do.validate("int32", "-5") is None
        assert do.validate("int32", str(2**31 - 1)) is None
        assert do.validate("int32", str(2**31)) is not None

    def test_hex(self):
        assert do.validate("hex", "0a1b2c") is None
        assert do.validate("hex", "0x0a1b2c") is None
        assert do.validate("hex", "0A:1B:2C") is None
        assert do.validate("hex", "zz") is not None
        assert do.validate("hex", "abc") is not None  # odd length

    def test_classless_routes(self):
        assert do.validate("classless-routes", "192.168.10.0/24 - 10.0.0.1") is None
        assert do.validate("classless-routes", "192.168.10.0/24 - 10.0.0.1, 0.0.0.0/0 - 10.0.0.1") is None
        assert do.validate("classless-routes", "192.168.10.0/24 10.0.0.1") is not None
        assert do.validate("classless-routes", "not-a-network/24 - 10.0.0.1") is not None
        assert do.validate("classless-routes", "192.168.10.0/24 - not-an-ip") is not None

    def test_unknown_type_is_rejected(self):
        assert do.validate("something-else", "x") is not None


class TestNormalize:
    def test_list_types_are_comma_space_joined(self):
        assert do.normalize("ip-list", " 10.0.0.1 ,10.0.0.2") == "10.0.0.1, 10.0.0.2"
        assert do.normalize("fqdn-list", "a.com,b.com") == "a.com, b.com"

    def test_boolean_is_lowercased(self):
        assert do.normalize("boolean", "TRUE") == "true"

    def test_hex_strips_prefix_and_separators(self):
        assert do.normalize("hex", "0x0A:1B:2C") == "0a1b2c"
        assert do.normalize("hex", "0A 1B 2C") == "0a1b2c"

    def test_classless_routes_normalized_spacing(self):
        assert do.normalize("classless-routes", "192.168.10.0/24   -   10.0.0.1") == "192.168.10.0/24 - 10.0.0.1"

    def test_string_is_stripped_only(self):
        assert do.normalize("string", "  host  ") == "host"


class TestEffectiveOptions:
    CFG = {
        "option-data": [{"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "1.1.1.1"}],
        "shared-networks": [
            {
                "name": "sn1",
                "option-data": [{"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "2.2.2.2"}],
                "subnet4": [
                    {
                        "id": 10,
                        "option-data": [
                            {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "3.3.3.3"}
                        ],
                        "pools": [
                            {
                                "pool": "10.0.0.10-10.0.0.20",
                                "option-data": [
                                    {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "4.4.4.4"}
                                ],
                            }
                        ],
                    }
                ],
            },
            {"name": "sn2", "subnet4": [{"id": 20}]},
        ],
    }

    def test_subnet_level_wins_over_shared_network_and_global(self):
        rows = do.effective_options(self.CFG, 10)
        assert len(rows) == 1
        assert rows[0]["data"] == "3.3.3.3"
        assert rows[0]["source"] == "subnet"
        assert rows[0]["overridden"] == ["global", "shared-network:sn1"]

    def test_pool_level_wins_over_everything(self):
        rows = do.effective_options(self.CFG, 10, pool="10.0.0.10-10.0.0.20")
        assert rows[0]["data"] == "4.4.4.4"
        assert rows[0]["source"] == "pool"
        assert rows[0]["overridden"] == ["global", "shared-network:sn1", "subnet"]

    def test_a_subnet_with_no_local_override_shows_the_shared_network_value(self):
        rows = do.effective_options(self.CFG, 20)
        assert rows[0]["data"] == "1.1.1.1"
        assert rows[0]["source"] == "global"
        assert rows[0]["overridden"] == []

    def test_unknown_subnet_returns_empty(self):
        assert do.effective_options(self.CFG, 99999) == []

    def test_display_name_is_filled_in_for_a_code_only_entry(self):
        cfg = {
            "option-data": [{"code": 6, "data": "9.9.9.9"}],
            "subnet4": [{"id": 1}],
        }
        rows = do.effective_options(cfg, 1)
        assert rows[0]["name"] == "domain-name-servers"

    def test_display_code_is_filled_in_for_a_name_only_entry(self):
        cfg = {
            "option-data": [{"name": "routers", "data": "10.0.0.1"}],
            "subnet4": [{"id": 1}],
        }
        rows = do.effective_options(cfg, 1)
        assert rows[0]["code"] == 3

    def test_count_here_and_inherited(self):
        here, inherited = do.count_here_and_inherited(self.CFG, 10)
        assert (here, inherited) == (1, 0)
        here2, inherited2 = do.count_here_and_inherited(self.CFG, 20)
        assert (here2, inherited2) == (0, 1)


class TestEntryKey:
    def test_code_wins_over_name(self):
        assert do.entry_key({"name": "custom-thing", "code": 200, "space": "dhcp4"}) == ("dhcp4", 200)

    def test_name_only_resolves_through_the_catalog(self):
        assert do.entry_key({"name": "routers"}) == ("dhcp4", 3)

    def test_unknown_name_only_keys_on_the_name(self):
        assert do.entry_key({"name": "something-custom"}) == ("dhcp4", "something-custom")

    def test_default_space_is_dhcp4(self):
        assert do.entry_key({"code": 3})[0] == "dhcp4"
