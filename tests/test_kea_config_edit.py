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


class TestSetOption4:
    """v5.18.0 (Q12) — set_option4 / remove_option4 at each level."""

    def test_global_create_then_update_in_place(self):
        cfg, code = edit.set_option4({"Dhcp4": {}}, "global", None, 42, "ntp-servers", "10.0.0.1, 10.0.0.2")
        assert code == "ok"
        assert cfg["Dhcp4"]["option-data"] == [
            {"name": "ntp-servers", "code": 42, "space": "dhcp4", "csv-format": True, "data": "10.0.0.1, 10.0.0.2"}
        ]
        cfg2, code2 = edit.set_option4(cfg, "global", None, 42, "ntp-servers", "9.9.9.9")
        assert code2 == "ok"
        assert len(cfg2["Dhcp4"]["option-data"]) == 1
        assert cfg2["Dhcp4"]["option-data"][0]["data"] == "9.9.9.9"

    def test_shared_network_level(self):
        cfg, code = edit.set_option4(_NESTED, "shared-network", "guest-wifi", 41, "nis-servers", "10.0.0.1")
        assert code == "ok"
        assert _net(cfg, "guest-wifi")["option-data"][0]["name"] == "nis-servers"
        assert "option-data" not in _net(cfg, "iot")

    def test_shared_network_missing_is_notfound(self):
        _cfg, code = edit.set_option4(_NESTED, "shared-network", "ghost", 41, "nis-servers", "10.0.0.1")
        assert code == "notfound"

    def test_subnet_level_reaches_a_nested_subnet(self):
        """Uses Q10's iter_subnet4 under the hood via subnet4_by_id — a
        subnet inside a shared network is reachable the same as a
        top-level one."""
        cfg, code = edit.set_option4(_NESTED, "subnet", 70, 66, "tftp-server-name", "tftp.local")
        assert code == "ok"
        nested_70 = next(s for s in _net(cfg, "guest-wifi")["subnet4"] if s["id"] == 70)
        assert nested_70["option-data"][0]["name"] == "tftp-server-name"

    def test_subnet_missing_is_notfound(self):
        _cfg, code = edit.set_option4(_NESTED, "subnet", 99999, 66, "tftp-server-name", "tftp.local")
        assert code == "notfound"

    def test_pool_level_keyed_by_pool_string(self):
        cfg, code = edit.set_option4(_NESTED, "pool", (70, "10.0.70.10 - 10.0.70.99"), 67, "boot-file-name", "pxe.bin")
        assert code == "ok"
        nested_70 = next(s for s in _net(cfg, "guest-wifi")["subnet4"] if s["id"] == 70)
        assert nested_70["pools"][0]["option-data"][0]["name"] == "boot-file-name"

    def test_pool_missing_is_notfound(self):
        _cfg, code = edit.set_option4(_NESTED, "pool", (70, "no-such-pool"), 67, "boot-file-name", "pxe.bin")
        assert code == "notfound"

    def test_managed_codes_refused_at_subnet_level(self):
        for code_num, name in ((3, "routers"), (6, "domain-name-servers")):
            _cfg, code = edit.set_option4(_NESTED, "subnet", 10, code_num, name, "10.0.0.1")
            assert code == "managed", code_num

    def test_managed_codes_are_not_special_at_other_levels(self):
        """3/6 are only reserved on the Edit Subnet form's own level."""
        cfg, code = edit.set_option4({"Dhcp4": {}}, "global", None, 3, "routers", "10.0.0.1")
        assert code == "ok"
        cfg2, code2 = edit.set_option4(_NESTED, "shared-network", "guest-wifi", 6, "domain-name-servers", "9.9.9.9")
        assert code2 == "ok"
        assert _net(cfg2, "guest-wifi")["option-data"][0]["code"] == 6

    def test_custom_code_is_written_with_csv_format_false(self):
        cfg, code = edit.set_option4({"Dhcp4": {}}, "global", None, 220, "my-custom-option", "0a1b2c", csv_format=False)
        assert code == "ok"
        entry = cfg["Dhcp4"]["option-data"][0]
        assert entry == {
            "name": "my-custom-option",
            "code": 220,
            "space": "dhcp4",
            "csv-format": False,
            "data": "0a1b2c",
        }

    def test_input_config_is_not_mutated(self):
        cfg_before = copy.deepcopy(_NESTED)
        edit.set_option4(_NESTED, "subnet", 10, 42, "ntp-servers", "10.0.0.1")
        assert cfg_before == _NESTED

    def test_matches_an_existing_code_only_entry_instead_of_duplicating(self):
        """The existing entry carries only `code` (no `name`, as a custom
        writer might leave it) — set_option4 must update it, not add a
        second entry for the same option."""
        cfg = {"Dhcp4": {"option-data": [{"code": 41, "data": "1.1.1.1"}]}}
        cfg2, code = edit.set_option4(cfg, "global", None, 41, "nis-servers", "2.2.2.2")
        assert code == "ok"
        assert len(cfg2["Dhcp4"]["option-data"]) == 1
        assert cfg2["Dhcp4"]["option-data"][0]["data"] == "2.2.2.2"
        assert cfg2["Dhcp4"]["option-data"][0]["name"] == "nis-servers"


class TestRemoveOption4:
    _WITH_OPTION = {
        "Dhcp4": {
            "subnet4": [
                {
                    "id": 10,
                    "option-data": [{"name": "ntp-servers", "code": 42, "space": "dhcp4", "data": "10.0.0.1"}],
                }
            ]
        }
    }

    def test_remove_existing(self):
        cfg, code = edit.remove_option4(self._WITH_OPTION, "subnet", 10, 42)
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["option-data"] == []

    def test_remove_missing_is_notfound(self):
        _cfg, code = edit.remove_option4(self._WITH_OPTION, "subnet", 10, 999)
        assert code == "notfound"

    def test_remove_from_a_level_with_no_option_data_at_all_is_notfound(self):
        _cfg, code = edit.remove_option4({"Dhcp4": {"subnet4": [{"id": 10}]}}, "subnet", 10, 42)
        assert code == "notfound"

    def test_managed_codes_refused_at_subnet_level(self):
        _cfg, code = edit.remove_option4(_NESTED, "subnet", 10, 3)
        assert code == "managed"

    def test_input_config_is_not_mutated(self):
        cfg_before = copy.deepcopy(self._WITH_OPTION)
        edit.remove_option4(self._WITH_OPTION, "subnet", 10, 42)
        assert cfg_before == self._WITH_OPTION

    def test_matches_a_code_only_entry(self):
        cfg = {"Dhcp4": {"option-data": [{"code": 41, "data": "1.1.1.1"}]}}
        cfg2, code = edit.remove_option4(cfg, "global", None, 41)
        assert code == "ok"
        assert cfg2["Dhcp4"]["option-data"] == []


class TestUpsertOptionMatchesByCode:
    """Golden test for the v5.18.0 change to _upsert_option (used by
    patch_subnet4 / patch_subnet6 for routers/dns-servers): an existing
    entry with only `code` set (no `name`) must be updated in place, not
    duplicated."""

    def test_code_only_entry_is_updated_not_duplicated(self):
        opts = [{"code": 3, "data": "1.1.1.1"}]
        edit._upsert_option(opts, "routers", 3, "dhcp4", "2.2.2.2")
        assert len(opts) == 1
        assert opts[0]["data"] == "2.2.2.2"

    def test_name_only_entry_still_matches_by_name(self):
        opts = [{"name": "routers", "data": "1.1.1.1"}]
        edit._upsert_option(opts, "routers", 3, "dhcp4", "2.2.2.2")
        assert len(opts) == 1
        assert opts[0]["data"] == "2.2.2.2"

    def test_no_existing_entry_appends_one(self):
        opts = []
        edit._upsert_option(opts, "routers", 3, "dhcp4", "10.0.0.1")
        assert opts == [{"name": "routers", "code": 3, "space": "dhcp4", "csv-format": True, "data": "10.0.0.1"}]

    def test_patch_subnet4_still_updates_a_code_only_routers_entry(self):
        """End-to-end through the real edit form path, not just the
        helper directly."""
        cfg = {
            "Dhcp4": {
                "subnet4": [{"id": 10, "option-data": [{"code": 3, "data": "1.1.1.1"}]}],
            }
        }
        new_cfg, changed = edit.patch_subnet4(cfg, 10, "", [], "", "", "", "10.0.0.9", "")
        assert changed is True
        opts = new_cfg["Dhcp4"]["subnet4"][0]["option-data"]
        assert len(opts) == 1
        assert opts[0]["data"] == "10.0.0.9"


_CLASSES_BASE = {
    "Dhcp4": {
        "subnet4": [{"id": 10}],
        "shared-networks": [{"name": "guest", "subnet4": []}],
        "client-classes": [{"name": "pxe", "test": "option[60].hex == 'PXEClient'"}],
    }
}


class TestUpsertClass4:
    def test_new_class_is_appended(self):
        cfg, code = edit.upsert_class4(copy.deepcopy(_CLASSES_BASE), {"name": "acct", "test": "option[77].hex == 'x'"})
        assert code == "ok"
        assert [c["name"] for c in cfg["Dhcp4"]["client-classes"]] == ["pxe", "acct"]

    def test_existing_class_is_replaced_in_place_not_duplicated(self):
        cfg, code = edit.upsert_class4(copy.deepcopy(_CLASSES_BASE), {"name": "pxe", "test": "NEW"})
        assert code == "ok"
        assert len(cfg["Dhcp4"]["client-classes"]) == 1
        assert cfg["Dhcp4"]["client-classes"][0]["test"] == "NEW"

    def test_position_inserts_a_new_class_there(self):
        cfg, code = edit.upsert_class4(copy.deepcopy(_CLASSES_BASE), {"name": "first", "test": "x"}, position=0)
        assert code == "ok"
        assert [c["name"] for c in cfg["Dhcp4"]["client-classes"]] == ["first", "pxe"]

    def test_position_is_ignored_when_updating_an_existing_class(self):
        cfg, code = edit.upsert_class4(copy.deepcopy(_CLASSES_BASE), {"name": "pxe", "test": "NEW"}, position=0)
        assert [c["name"] for c in cfg["Dhcp4"]["client-classes"]] == ["pxe"]

    def test_input_not_mutated(self):
        original = copy.deepcopy(_CLASSES_BASE)
        edit.upsert_class4(_CLASSES_BASE, {"name": "pxe", "test": "changed"})
        assert original == _CLASSES_BASE

    def test_into_a_config_with_no_classes_yet(self):
        cfg, code = edit.upsert_class4({"Dhcp4": {}}, {"name": "pxe", "test": "x"})
        assert code == "ok"
        assert cfg["Dhcp4"]["client-classes"][0]["name"] == "pxe"


class TestDeleteClass4:
    def test_builtin_is_refused(self):
        _cfg, code = edit.delete_class4(copy.deepcopy(_CLASSES_BASE), "DROP")
        assert code == "builtin"

    def test_missing_class_is_notfound(self):
        _cfg, code = edit.delete_class4(copy.deepcopy(_CLASSES_BASE), "ghost")
        assert code == "notfound"

    def test_referenced_class_is_refused(self):
        referenced = {
            "Dhcp4": {
                "subnet4": [{"id": 10, "client-classes": ["pxe"]}],
                "client-classes": [{"name": "pxe", "test": "x"}],
            }
        }
        cfg, code = edit.delete_class4(copy.deepcopy(referenced), "pxe")
        assert code == "referenced"
        assert cfg["Dhcp4"]["client-classes"] == [{"name": "pxe", "test": "x"}]  # untouched, not deleted

    def test_unreferenced_class_is_deleted(self):
        cfg, code = edit.delete_class4(copy.deepcopy(_CLASSES_BASE), "pxe")
        assert code == "ok"
        assert cfg["Dhcp4"]["client-classes"] == []

    def test_input_not_mutated(self):
        original = copy.deepcopy(_CLASSES_BASE)
        edit.delete_class4(_CLASSES_BASE, "pxe")
        assert original == _CLASSES_BASE


class TestReorderClass4:
    _THREE = {"Dhcp4": {"client-classes": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}}

    def test_up_swaps_with_the_previous_entry(self):
        cfg, code = edit.reorder_class4(copy.deepcopy(self._THREE), "b", "up")
        assert code == "ok"
        assert [c["name"] for c in cfg["Dhcp4"]["client-classes"]] == ["b", "a", "c"]

    def test_down_swaps_with_the_next_entry(self):
        cfg, code = edit.reorder_class4(copy.deepcopy(self._THREE), "b", "down")
        assert code == "ok"
        assert [c["name"] for c in cfg["Dhcp4"]["client-classes"]] == ["a", "c", "b"]

    def test_moving_the_first_entry_up_hits_the_boundary(self):
        _cfg, code = edit.reorder_class4(copy.deepcopy(self._THREE), "a", "up")
        assert code == "boundary"

    def test_moving_the_last_entry_down_hits_the_boundary(self):
        _cfg, code = edit.reorder_class4(copy.deepcopy(self._THREE), "c", "down")
        assert code == "boundary"

    def test_missing_class_is_notfound(self):
        _cfg, code = edit.reorder_class4(copy.deepcopy(self._THREE), "ghost", "up")
        assert code == "notfound"


class TestAttachClass4:
    _SIMPLE = {"Dhcp4": {"subnet4": [{"id": 10}], "shared-networks": [{"name": "guest", "subnet4": []}]}}

    def test_guard_attach_new_spelling(self):
        cfg, code = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "pxe", "subnet", 10, mode="guard", version=(3, 0, 0)
        )
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["client-classes"] == ["pxe"]

    def test_guard_attach_old_spelling_is_a_singular_string(self):
        cfg, code = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "pxe", "subnet", 10, mode="guard", version=(2, 6, 0)
        )
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["client-class"] == "pxe"

    def test_guard_reattach_is_idempotent_new_spelling(self):
        once, _ = edit.attach_class4(copy.deepcopy(self._SIMPLE), "pxe", "subnet", 10, mode="guard", version=(3, 0, 0))
        twice, code = edit.attach_class4(once, "pxe", "subnet", 10, mode="guard", version=(3, 0, 0))
        assert code == "ok"
        assert twice["Dhcp4"]["subnet4"][0]["client-classes"] == ["pxe"]

    def test_guard_detach_new_spelling_removes_the_key_when_empty(self):
        attached, _ = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "pxe", "subnet", 10, mode="guard", version=(3, 0, 0)
        )
        detached, code = edit.attach_class4(
            attached, "pxe", "subnet", 10, mode="guard", attach=False, version=(3, 0, 0)
        )
        assert code == "ok"
        assert "client-classes" not in detached["Dhcp4"]["subnet4"][0]

    def test_guard_detach_old_spelling(self):
        attached, _ = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "pxe", "subnet", 10, mode="guard", version=(2, 6, 0)
        )
        detached, code = edit.attach_class4(
            attached, "pxe", "subnet", 10, mode="guard", attach=False, version=(2, 6, 0)
        )
        assert code == "ok"
        assert "client-class" not in detached["Dhcp4"]["subnet4"][0]

    def test_additional_attach_and_detach(self):
        attached, code = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "acct", "subnet", 10, mode="additional", version=(3, 0, 0)
        )
        assert code == "ok"
        assert attached["Dhcp4"]["subnet4"][0]["evaluate-additional-classes"] == ["acct"]
        detached, code = edit.attach_class4(
            attached, "acct", "subnet", 10, mode="additional", attach=False, version=(3, 0, 0)
        )
        assert code == "ok"
        assert "evaluate-additional-classes" not in detached["Dhcp4"]["subnet4"][0]

    def test_attach_to_a_shared_network(self):
        cfg, code = edit.attach_class4(
            copy.deepcopy(self._SIMPLE), "pxe", "shared-network", "guest", mode="guard", version=(3, 0, 0)
        )
        assert code == "ok"
        assert cfg["Dhcp4"]["shared-networks"][0]["client-classes"] == ["pxe"]

    def test_attach_to_a_pool(self):
        cfg_with_pool = {"Dhcp4": {"subnet4": [{"id": 10, "pools": [{"pool": "a-b"}]}]}}
        cfg, code = edit.attach_class4(cfg_with_pool, "pxe", "pool", (10, "a-b"), mode="guard", version=(3, 0, 0))
        assert code == "ok"
        assert cfg["Dhcp4"]["subnet4"][0]["pools"][0]["client-classes"] == ["pxe"]

    def test_missing_scope_is_notfound(self):
        _cfg, code = edit.attach_class4(copy.deepcopy(self._SIMPLE), "pxe", "subnet", 999, mode="guard")
        assert code == "notfound"

    def test_existing_spelling_anywhere_in_the_config_wins_even_with_no_version(self):
        cfg = {"Dhcp4": {"subnet4": [{"id": 10, "client-classes": ["other"]}, {"id": 20}]}}
        result, code = edit.attach_class4(cfg, "pxe", "subnet", 20, mode="guard", version=None)
        assert code == "ok"
        assert result["Dhcp4"]["subnet4"][1]["client-classes"] == ["pxe"]


class TestClassOptionData:
    """Class option-data via Q12's set_option4/remove_option4 with
    level='class', key=<class name>."""

    def test_set_at_class_level(self):
        cfg, code = edit.set_option4(
            {"Dhcp4": {"client-classes": [{"name": "pxe"}]}}, "class", "pxe", 67, "boot-file-name", "pxelinux.0"
        )
        assert code == "ok"
        assert cfg["Dhcp4"]["client-classes"][0]["option-data"] == [
            {"name": "boot-file-name", "code": 67, "space": "dhcp4", "csv-format": True, "data": "pxelinux.0"}
        ]

    def test_remove_at_class_level(self):
        cfg = {
            "Dhcp4": {
                "client-classes": [
                    {"name": "pxe", "option-data": [{"name": "boot-file-name", "code": 67, "data": "pxelinux.0"}]}
                ]
            }
        }
        cfg2, code = edit.remove_option4(cfg, "class", "pxe", 67)
        assert code == "ok"
        assert cfg2["Dhcp4"]["client-classes"][0]["option-data"] == []

    def test_set_on_a_missing_class_is_notfound(self):
        _cfg, code = edit.set_option4({"Dhcp4": {"client-classes": []}}, "class", "ghost", 67, "boot-file-name", "x")
        assert code == "notfound"

    def test_class_level_is_not_subject_to_the_managed_at_subnet_refusal(self):
        """Codes 3/6 are only special at level='subnet' — a class can
        carry them freely (real Kea configs do, e.g. per-class routers)."""
        cfg, code = edit.set_option4(
            {"Dhcp4": {"client-classes": [{"name": "pxe"}]}}, "class", "pxe", 3, "routers", "10.0.0.1"
        )
        assert code == "ok"
