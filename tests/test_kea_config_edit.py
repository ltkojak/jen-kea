"""
tests/test_kea_config_edit.py
─────────────────────────────
v5.11.0 — jen/services/kea_config_edit.py replaces the mutation logic
that used to live inside the base64'd `sudo python3` scripts. These
tests exercise the functions directly instead of asserting on generated
script text.
"""

import copy

from jen.services import kea_config_edit as edit

_V4 = {
    "Dhcp4": {
        "subnet4": [
            {
                "id": 10,
                "subnet": "10.0.10.0/24",
                "pools": [{"pool": "10.0.10.50 - 10.0.10.200"}],
                "option-data": [
                    {"name": "routers", "code": 3, "space": "dhcp4", "csv-format": True, "data": "10.0.10.1"}
                ],
            },
            {"id": 20, "subnet": "10.0.20.0/24", "pools": [{"pool": "10.0.20.50 - 10.0.20.200"}]},
        ]
    }
}

_V6 = {
    "Dhcp6": {
        "subnet6": [
            {"id": 100, "subnet": "2001:db8:a::/64", "pools": [{"pool": "2001:db8:a::100-2001:db8:a::1ff"}]},
        ]
    }
}


class TestPatchSubnet4:
    def test_no_fields_is_no_change_and_input_untouched(self):
        original = copy.deepcopy(_V4)
        cfg, changed = edit.patch_subnet4(_V4, 10, "", [], "", "", "", "", "")
        assert changed is False
        assert _V4 == original

    def test_pool_and_extra_pools_replace_the_list(self):
        cfg, changed = edit.patch_subnet4(
            _V4, 10, "10.0.10.10 - 10.0.10.20", ["10.0.10.30 - 10.0.10.40"], "", "", "", "", ""
        )
        assert changed is True
        s = cfg["Dhcp4"]["subnet4"][0]
        assert s["pools"] == [{"pool": "10.0.10.10 - 10.0.10.20"}, {"pool": "10.0.10.30 - 10.0.10.40"}]

    def test_timers_are_coerced_to_int(self):
        cfg, changed = edit.patch_subnet4(_V4, 20, "", [], "3600", "1800", "3150", "", "")
        s = cfg["Dhcp4"]["subnet4"][1]
        assert s["valid-lifetime"] == 3600 and s["renew-timer"] == 1800 and s["rebind-timer"] == 3150

    def test_existing_option_is_updated_in_place_not_duplicated(self):
        cfg, _ = edit.patch_subnet4(_V4, 10, "", [], "", "", "", "10.0.10.254", "")
        opts = cfg["Dhcp4"]["subnet4"][0]["option-data"]
        routers = [o for o in opts if o["name"] == "routers"]
        assert len(routers) == 1 and routers[0]["data"] == "10.0.10.254"

    def test_new_dns_option_is_appended_with_csv_format(self):
        cfg, _ = edit.patch_subnet4(_V4, 20, "", [], "", "", "", "", "1.1.1.1,9.9.9.9")
        opts = cfg["Dhcp4"]["subnet4"][1]["option-data"]
        dns = [o for o in opts if o["name"] == "domain-name-servers"]
        assert dns == [
            {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "csv-format": True, "data": "1.1.1.1,9.9.9.9"}
        ]

    def test_unknown_subnet_id_is_no_change(self):
        cfg, changed = edit.patch_subnet4(_V4, 999, "10.0.99.0 - 10.0.99.9", [], "", "", "", "", "")
        assert changed is False


class TestPatchSubnet6:
    def test_v6_dns_servers_option_code_23(self):
        cfg, changed = edit.patch_subnet6(_V6, 100, "", [], "", "", "", "", "2001:db8::1")
        assert changed is True
        opts = cfg["Dhcp6"]["subnet6"][0]["option-data"]
        assert opts == [
            {"name": "dns-servers", "code": 23, "space": "dhcp6", "csv-format": True, "data": "2001:db8::1"}
        ]

    def test_preferred_and_valid_lifetime(self):
        cfg, _ = edit.patch_subnet6(_V6, 100, "", [], "3000", "7200", "", "", "")
        s = cfg["Dhcp6"]["subnet6"][0]
        assert s["preferred-lifetime"] == 3000 and s["valid-lifetime"] == 7200

    def test_input_not_mutated(self):
        original = copy.deepcopy(_V6)
        edit.patch_subnet6(_V6, 100, "2001:db8:a::5-2001:db8:a::9", [], "", "", "", "", "")
        assert _V6 == original

    def test_no_fields_is_no_change(self):
        _cfg, changed = edit.patch_subnet6(_V6, 100, "", [], "", "", "", "", "")
        assert changed is False

    def test_unknown_subnet6_id_is_no_change(self):
        _cfg, changed = edit.patch_subnet6(_V6, 999, "2001:db8::1-2001:db8::9", [], "", "", "", "", "")
        assert changed is False


class TestAddDeleteSubnet4:
    def test_add_new_block(self):
        block = {"id": 30, "subnet": "10.0.30.0/24", "pools": [{"pool": "10.0.30.10 - 10.0.30.20"}]}
        cfg, code = edit.add_subnet4(_V4, block)
        assert code == "ok"
        assert [s["id"] for s in cfg["Dhcp4"]["subnet4"]] == [10, 20, 30]

    def test_add_duplicate_id_is_idexists(self):
        cfg, code = edit.add_subnet4(_V4, {"id": 10, "subnet": "10.9.9.0/24"})
        assert code == "idexists"
        assert len(cfg["Dhcp4"]["subnet4"]) == 2

    def test_delete_existing(self):
        cfg, code = edit.delete_subnet4(_V4, 20)
        assert code == "ok"
        assert [s["id"] for s in cfg["Dhcp4"]["subnet4"]] == [10]

    def test_delete_missing_is_notfound(self):
        original = copy.deepcopy(_V4)
        cfg, code = edit.delete_subnet4(_V4, 777)
        assert code == "notfound"
        assert _V4 == original

    def test_add_into_empty_config(self):
        cfg, code = edit.add_subnet4({}, {"id": 1, "subnet": "192.168.0.0/24"})
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["id"] == 1
