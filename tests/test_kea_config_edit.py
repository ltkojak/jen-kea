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
        assert original == _V4

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
        assert original == _V6

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
        assert original == _V4

    def test_add_into_empty_config(self):
        cfg, code = edit.add_subnet4({}, {"id": 1, "subnet": "192.168.0.0/24"})
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["id"] == 1


_NESTED = {
    "Dhcp4": {
        "subnet4": [{"id": 10, "subnet": "10.0.10.0/24", "pools": [{"pool": "10.0.10.50 - 10.0.10.200"}]}],
        "shared-networks": [
            {
                "name": "guest-wifi",
                "interface": "eth1",
                "subnet4": [
                    {"id": 70, "subnet": "10.0.70.0/24", "pools": [{"pool": "10.0.70.10 - 10.0.70.99"}]},
                    {"id": 71, "subnet": "10.0.71.0/24"},
                ],
            },
            {"name": "iot", "subnet4": []},
        ],
    }
}


def _net(cfg, name):
    return next(n for n in cfg["Dhcp4"]["shared-networks"] if n["name"] == name)


class TestNestedSubnetEdit:
    """v5.15.0 — patch / delete / add reach subnets inside shared-networks."""

    def test_patch_a_nested_subnet_in_place(self):
        cfg, changed = edit.patch_subnet4(_NESTED, 70, "10.0.70.5 - 10.0.70.250", [], "7200", "", "", "", "")
        assert changed is True
        assert _net(cfg, "guest-wifi")["subnet4"][0]["pools"] == [{"pool": "10.0.70.5 - 10.0.70.250"}]
        assert _net(cfg, "guest-wifi")["subnet4"][0]["valid-lifetime"] == 7200
        # top-level untouched
        assert cfg["Dhcp4"]["subnet4"][0] == _NESTED["Dhcp4"]["subnet4"][0]

    def test_patch_unknown_id_across_both_containers_is_no_change(self):
        _cfg, changed = edit.patch_subnet4(_NESTED, 999, "10.0.0.1-10.0.0.9", [], "", "", "", "", "")
        assert changed is False

    def test_delete_a_nested_subnet(self):
        cfg, code = edit.delete_subnet4(_NESTED, 71)
        assert code == "ok"
        assert [s["id"] for s in _net(cfg, "guest-wifi")["subnet4"]] == [70]
        assert [s["id"] for s in cfg["Dhcp4"]["subnet4"]] == [10]

    def test_input_not_mutated_by_nested_delete(self):
        original = copy.deepcopy(_NESTED)
        edit.delete_subnet4(_NESTED, 70)
        assert original == _NESTED

    def test_add_into_a_named_network(self):
        cfg, code = edit.add_subnet4(_NESTED, {"id": 72, "subnet": "10.0.72.0/24"}, shared_network="guest-wifi")
        assert code == "ok"
        assert [s["id"] for s in _net(cfg, "guest-wifi")["subnet4"]] == [70, 71, 72]

    def test_add_into_a_missing_network_is_nonetwork(self):
        cfg, code = edit.add_subnet4(_NESTED, {"id": 73, "subnet": "10.0.73.0/24"}, shared_network="nope")
        assert code == "nonetwork"

    def test_add_duplicate_id_from_a_nested_subnet_is_idexists(self):
        _cfg, code = edit.add_subnet4(_NESTED, {"id": 70, "subnet": "10.9.9.0/24"})
        assert code == "idexists"


class TestSharedNetworkLifecycle:
    def test_create_ok_then_exists(self):
        cfg, code = edit.create_shared_network4(_NESTED, "cameras", interface="eth2")
        assert code == "ok"
        assert _net(cfg, "cameras") == {"name": "cameras", "subnet4": [], "interface": "eth2"}
        _cfg2, code2 = edit.create_shared_network4(cfg, "cameras")
        assert code2 == "exists"

    def test_create_into_empty_config(self):
        cfg, code = edit.create_shared_network4({}, "n1")
        assert code == "ok"
        assert cfg["Dhcp4"]["shared-networks"] == [{"name": "n1", "subnet4": []}]

    def test_delete_empty_network(self):
        cfg, code = edit.delete_shared_network4(_NESTED, "iot")
        assert code == "ok"
        assert [n["name"] for n in cfg["Dhcp4"]["shared-networks"]] == ["guest-wifi"]

    def test_delete_non_empty_is_notempty(self):
        cfg, code = edit.delete_shared_network4(_NESTED, "guest-wifi")
        assert code == "notempty"
        assert len(cfg["Dhcp4"]["shared-networks"]) == 2

    def test_delete_missing_is_notfound(self):
        _cfg, code = edit.delete_shared_network4(_NESTED, "ghost")
        assert code == "notfound"


class TestMoveSubnet4:
    def test_top_to_network(self):
        cfg, code = edit.move_subnet4(_NESTED, 10, "iot")
        assert code == "ok"
        assert [s["id"] for s in cfg["Dhcp4"].get("subnet4", [])] == []
        assert [s["id"] for s in _net(cfg, "iot")["subnet4"]] == [10]

    def test_network_to_top(self):
        cfg, code = edit.move_subnet4(_NESTED, 71, "")
        assert code == "ok"
        assert 71 in [s["id"] for s in cfg["Dhcp4"]["subnet4"]]
        assert 71 not in [s["id"] for s in _net(cfg, "guest-wifi")["subnet4"]]

    def test_network_to_network_carries_the_dict_identical(self):
        before = copy.deepcopy(_net(_NESTED, "guest-wifi")["subnet4"][0])
        cfg, code = edit.move_subnet4(_NESTED, 70, "iot")
        assert code == "ok"
        assert _net(cfg, "iot")["subnet4"][0] == before

    def test_move_to_current_container_is_nochange(self):
        _cfg, code = edit.move_subnet4(_NESTED, 70, "guest-wifi")
        assert code == "nochange"
        _cfg, code = edit.move_subnet4(_NESTED, 10, "")
        assert code == "nochange"

    def test_move_to_missing_network_is_nonetwork(self):
        _cfg, code = edit.move_subnet4(_NESTED, 10, "ghost")
        assert code == "nonetwork"

    def test_move_unknown_subnet_is_notfound(self):
        _cfg, code = edit.move_subnet4(_NESTED, 999, "iot")
        assert code == "notfound"
