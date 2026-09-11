"""
tests/test_kea_classes.py
──────────────────────────
v5.19.0 (Q13) — jen/services/kea_classes.py: the guided rule builder's
expression generator, the Kea 2.7.4→3.0 attachment-key rename, and the
reference scanner. Pure — no DB, no Flask.
"""

import pytest

from jen.services import kea_classes as kc


class TestIsBuiltin:
    def test_exact_names(self):
        for name in ("ALL", "KNOWN", "UNKNOWN", "DROP", "BOOTP"):
            assert kc.is_builtin(name)

    def test_prefixed_families(self):
        assert kc.is_builtin("VENDOR_CLASS_DOCSIS3.0")
        assert kc.is_builtin("HA_server1")
        assert kc.is_builtin("AFTER_something")
        assert kc.is_builtin("SPAWN_vendor-class-identifier_docsis")

    def test_an_ordinary_name_is_not_builtin(self):
        assert not kc.is_builtin("printer-vlan")
        assert not kc.is_builtin("pxe-clients")


class TestBuildExpressionPerField:
    def test_vendor_class_equals(self):
        assert (
            kc.build_expression([{"field": "vendor_class", "op": "equals", "value": "PXEClient"}])
            == "option[60].hex == 'PXEClient'"
        )

    def test_vendor_class_starts_with(self):
        assert (
            kc.build_expression([{"field": "vendor_class", "op": "starts_with", "value": "PXEClient"}])
            == "substring(option[60].hex,0,9) == 'PXEClient'"
        )

    def test_user_class_equals(self):
        assert (
            kc.build_expression([{"field": "user_class", "op": "equals", "value": "accounting"}])
            == "option[77].hex == 'accounting'"
        )

    def test_hostname_equals(self):
        assert (
            kc.build_expression([{"field": "hostname", "op": "equals", "value": "printer1"}])
            == "option[12].text == 'printer1'"
        )

    def test_hostname_starts_with(self):
        assert (
            kc.build_expression([{"field": "hostname", "op": "starts_with", "value": "printer"}])
            == "substring(option[12].text,0,7) == 'printer'"
        )

    def test_mac_equals(self):
        assert (
            kc.build_expression([{"field": "mac", "op": "equals", "value": "00:11:22:33:44:55"}])
            == "pkt4.mac == 0x001122334455"
        )

    def test_mac_accepts_bare_hex_no_separators(self):
        assert (
            kc.build_expression([{"field": "mac", "op": "equals", "value": "001122334455"}])
            == "pkt4.mac == 0x001122334455"
        )

    def test_mac_oui_normalizes_colons(self):
        """00:11:22 -> 0x001122 — the exact normalization named in the spec."""
        assert (
            kc.build_expression([{"field": "mac_oui", "op": "equals", "value": "00:11:22"}])
            == "substring(pkt4.mac,0,3) == 0x001122"
        )

    def test_client_id_equals(self):
        assert (
            kc.build_expression([{"field": "client_id", "op": "equals", "value": "01:00:11:22:33:44:55"}])
            == "option[61].hex == 0x01001122334455"
        )

    def test_circuit_id_is_a_quoted_string_not_hex(self):
        assert (
            kc.build_expression([{"field": "circuit_id", "op": "equals", "value": "port-7"}])
            == "relay4[1].hex == 'port-7'"
        )

    def test_remote_id_is_hex(self):
        assert (
            kc.build_expression([{"field": "remote_id", "op": "equals", "value": "0011223344"}])
            == "relay4[2].hex == 0x0011223344"
        )

    def test_member(self):
        assert (
            kc.build_expression([{"field": "member", "op": "equals", "value": "other-class"}])
            == "member('other-class')"
        )


class TestBuildExpressionComposition:
    _TWO = [
        {"field": "vendor_class", "op": "equals", "value": "A"},
        {"field": "hostname", "op": "equals", "value": "B"},
    ]

    def test_all_joins_with_and(self):
        assert (
            kc.build_expression(self._TWO, combinator="all") == "(option[60].hex == 'A') and (option[12].text == 'B')"
        )

    def test_any_joins_with_or(self):
        assert kc.build_expression(self._TWO, combinator="any") == "(option[60].hex == 'A') or (option[12].text == 'B')"

    def test_negate_wraps_the_whole_composed_expression(self):
        assert kc.build_expression(self._TWO, combinator="all", negate=True) == (
            "not ((option[60].hex == 'A') and (option[12].text == 'B'))"
        )

    def test_single_rule_is_not_parenthesized_unless_negated(self):
        one = [{"field": "vendor_class", "op": "equals", "value": "A"}]
        assert kc.build_expression(one) == "option[60].hex == 'A'"
        assert kc.build_expression(one, negate=True) == "not (option[60].hex == 'A')"

    def test_three_rules_any(self):
        three = self._TWO + [{"field": "mac", "op": "equals", "value": "001122334455"}]
        assert kc.build_expression(three, combinator="any") == (
            "(option[60].hex == 'A') or (option[12].text == 'B') or (pkt4.mac == 0x001122334455)"
        )


class TestBuildExpressionRejections:
    def test_quote_in_a_string_value_is_rejected(self):
        with pytest.raises(ValueError, match="quote"):
            kc.build_expression([{"field": "hostname", "op": "equals", "value": "o'brien"}])

    def test_quote_in_a_member_class_name_is_rejected(self):
        with pytest.raises(ValueError, match="quote"):
            kc.build_expression([{"field": "member", "op": "equals", "value": "o'brien"}])

    def test_invalid_hex_is_rejected(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "mac", "op": "equals", "value": "not-hex"}])

    def test_odd_length_hex_is_rejected(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "client_id", "op": "equals", "value": "abc"}])

    def test_mac_must_be_exactly_six_bytes(self):
        with pytest.raises(ValueError, match="6 bytes"):
            kc.build_expression([{"field": "mac", "op": "equals", "value": "0011"}])

    def test_mac_oui_must_be_exactly_three_bytes(self):
        with pytest.raises(ValueError, match="3 bytes"):
            kc.build_expression([{"field": "mac_oui", "op": "equals", "value": "00112233"}])

    def test_contains_is_not_an_offered_op_anywhere(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "hostname", "op": "contains", "value": "x"}])
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "vendor_class", "op": "contains", "value": "x"}])

    def test_starts_with_is_not_offered_for_hex_fields(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "mac", "op": "starts_with", "value": "001122334455"}])

    def test_empty_rule_list_is_rejected(self):
        with pytest.raises(ValueError, match="at least one rule"):
            kc.build_expression([])

    def test_empty_string_value_is_rejected(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "hostname", "op": "equals", "value": "   "}])

    def test_unknown_field_is_rejected(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "bogus", "op": "equals", "value": "x"}])

    def test_unknown_combinator_is_rejected(self):
        with pytest.raises(ValueError):
            kc.build_expression([{"field": "mac", "op": "equals", "value": "001122334455"}], combinator="xor")


class TestAttachmentKeys:
    NEW = {"guard": "client-classes", "additional": "evaluate-additional-classes", "only": "only-in-additional-list"}
    OLD = {"guard": "client-class", "additional": "require-client-classes", "only": "only-if-required"}

    def test_neither_present_falls_back_to_version(self):
        assert kc.attachment_keys({}, None) == self.OLD
        assert kc.attachment_keys({}, (2, 6, 0)) == self.OLD
        assert kc.attachment_keys({}, (2, 7, 4)) == self.NEW
        assert kc.attachment_keys({}, (3, 0, 0)) == self.NEW

    def test_new_spelling_on_a_subnet_wins_regardless_of_version(self):
        cfg = {"subnet4": [{"id": 1, "client-classes": ["foo"]}]}
        assert kc.attachment_keys(cfg, None) == self.NEW
        assert kc.attachment_keys(cfg, (2, 6, 0)) == self.NEW

    def test_old_spelling_on_a_pool_wins_regardless_of_version(self):
        cfg = {"subnet4": [{"id": 1, "pools": [{"pool": "a-b", "client-class": "foo"}]}]}
        assert kc.attachment_keys(cfg, (3, 0, 0)) == self.OLD

    def test_old_spelling_on_a_shared_network_is_detected(self):
        cfg = {"shared-networks": [{"name": "guest", "require-client-classes": ["foo"]}]}
        assert kc.attachment_keys(cfg, (3, 0, 0)) == self.OLD

    def test_only_flag_on_a_class_establishes_the_spelling_too(self):
        cfg = {"client-classes": [{"name": "x", "only-if-required": True}]}
        assert kc.attachment_keys(cfg, (3, 0, 0)) == self.OLD

    def test_mixed_config_prefers_new(self):
        cfg = {
            "subnet4": [
                {"id": 1, "client-classes": ["foo"]},
                {"id": 2, "client-class": "bar"},
            ]
        }
        assert kc.attachment_keys(cfg, None) == self.NEW

    def test_nested_subnet_in_a_shared_network_is_scanned_too(self):
        cfg = {"shared-networks": [{"name": "guest", "subnet4": [{"id": 70, "client-class": "foo"}]}]}
        assert kc.attachment_keys(cfg, (3, 0, 0)) == self.OLD


class TestReferences:
    CFG = {
        "subnet4": [
            {"id": 10, "client-classes": ["pxe"], "pools": [{"pool": "a-b", "evaluate-additional-classes": ["acct"]}]},
            {"id": 20},
        ],
        "shared-networks": [
            {"name": "guest", "client-class": "pxe", "subnet4": [{"id": 70, "require-client-classes": ["acct"]}]}
        ],
        "client-classes": [
            {"name": "pxe", "test": "option[60].hex == 'PXEClient'"},
            {"name": "acct", "test": "option[77].hex == 'accounting'"},
            {"name": "combo", "test": "member('pxe') and member('acct')"},
        ],
    }

    def test_subnet_guard(self):
        assert "subnet 10" in kc.references(self.CFG, "pxe")

    def test_pool_additional(self):
        assert "pool a-b of subnet 10" in kc.references(self.CFG, "acct")

    def test_shared_network_guard(self):
        assert "shared network guest" in kc.references(self.CFG, "pxe")

    def test_nested_subnet_additional(self):
        assert "subnet 70" in kc.references(self.CFG, "acct")

    def test_member_reference(self):
        refs = kc.references(self.CFG, "pxe")
        assert "class combo (member)" in refs
        refs2 = kc.references(self.CFG, "acct")
        assert "class combo (member)" in refs2

    def test_a_class_never_references_itself_via_its_own_name_check(self):
        refs = kc.references(self.CFG, "combo")
        assert "class combo (member)" not in refs

    def test_unreferenced_class_returns_empty(self):
        assert kc.references(self.CFG, "unused") == []


class TestAttachedAsAdditional:
    """v5.19.1 (14F) — backs the only-in-additional-list warning: the
    flag only matters once the class is attached as ADDITIONAL
    (never a guard) somewhere."""

    def test_false_for_guard_only(self):
        assert kc.attached_as_additional(TestReferences.CFG, "pxe") is False

    def test_true_for_pool_additional(self):
        assert kc.attached_as_additional(TestReferences.CFG, "acct") is True

    def test_true_for_nested_subnet_additional(self):
        cfg = {
            "shared-networks": [{"name": "guest", "subnet4": [{"id": 70, "evaluate-additional-classes": ["acct2"]}]}],
            "client-classes": [{"name": "acct2", "test": "1 == 1"}],
        }
        assert kc.attached_as_additional(cfg, "acct2") is True

    def test_true_for_top_level_subnet_additional(self):
        cfg = {
            "subnet4": [{"id": 10, "require-client-classes": ["acct3"]}],
            "client-classes": [{"name": "acct3", "test": "1 == 1"}],
        }
        assert kc.attached_as_additional(cfg, "acct3") is True

    def test_true_for_shared_network_level_additional(self):
        cfg = {
            "shared-networks": [{"name": "guest", "evaluate-additional-classes": ["acct4"], "subnet4": []}],
            "client-classes": [{"name": "acct4", "test": "1 == 1"}],
        }
        assert kc.attached_as_additional(cfg, "acct4") is True

    def test_false_for_unreferenced_class(self):
        assert kc.attached_as_additional(TestReferences.CFG, "unused") is False


class TestMergeClassFields:
    def test_new_class_fields_all_set(self):
        d = kc.merge_class_fields(
            None,
            "pxe",
            "option[60].hex == 'PXEClient'",
            user_context={"jen": {"v": 1}},
            next_server="10.0.0.5",
            server_hostname="boot.local",
            boot_file_name="pxelinux.0",
            only_key="only-in-additional-list",
            only_additional=True,
        )
        assert d == {
            "name": "pxe",
            "test": "option[60].hex == 'PXEClient'",
            "user-context": {"jen": {"v": 1}},
            "next-server": "10.0.0.5",
            "server-hostname": "boot.local",
            "boot-file-name": "pxelinux.0",
            "only-in-additional-list": True,
        }

    def test_preserves_existing_option_data(self):
        existing = {"name": "pxe", "test": "old", "option-data": [{"code": 66, "data": "tftp.local"}]}
        d = kc.merge_class_fields(existing, "pxe", "new-test")
        assert d["option-data"] == [{"code": 66, "data": "tftp.local"}]
        assert d["test"] == "new-test"

    def test_clears_the_other_only_spelling(self):
        existing = {"name": "pxe", "test": "x", "only-if-required": True}
        d = kc.merge_class_fields(existing, "pxe", "x", only_key="only-in-additional-list", only_additional=True)
        assert "only-if-required" not in d
        assert d["only-in-additional-list"] is True

    def test_unset_optional_fields_are_cleared_not_left_stale(self):
        existing = {"name": "pxe", "test": "x", "next-server": "1.2.3.4", "boot-file-name": "old.bin"}
        d = kc.merge_class_fields(existing, "pxe", "x")
        assert "next-server" not in d
        assert "boot-file-name" not in d

    def test_does_not_mutate_the_existing_dict(self):
        import copy

        existing = {"name": "pxe", "test": "old", "option-data": [{"code": 66, "data": "x"}]}
        snapshot = copy.deepcopy(existing)
        kc.merge_class_fields(existing, "pxe", "new")
        assert existing == snapshot
