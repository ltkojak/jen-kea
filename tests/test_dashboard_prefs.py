"""
tests/test_dashboard_prefs.py
──────────────────────────────
v5.54.0 (Q61) — the pure prefs-v2 pipeline: upgrade a v1 list, validate a
posted or stored value against the widget catalog and the caller's accessible
subnets, and compute the final subnet-card order.

Pure (no DB): `py -m pytest --noconftest tests/test_dashboard_prefs.py`.
"""

from jen.services import dashboard_prefs as dp


class TestUpgrade:
    def test_v1_list_becomes_full_width_panels_in_order(self):
        prefs = dp.upgrade(["server_status", "totals"])
        assert prefs == {
            "v": 2,
            "panels": [{"id": "server_status", "w": "full"}, {"id": "totals", "w": "full"}],
            "subnets": {"order": [], "pinned": [], "hidden": []},
            "compact": False,
        }

    def test_none_falls_back_to_the_default_panels(self):
        assert dp.upgrade(None)["panels"] == dp.DEFAULT_PANELS

    def test_a_v2_value_passes_through_with_subnets_and_compact_preserved(self):
        raw = {
            "v": 2,
            "panels": [{"id": "totals", "w": "half"}],
            "subnets": {"order": [3, 1], "pinned": [1], "hidden": [9]},
            "compact": True,
        }
        prefs = dp.upgrade(raw)
        assert prefs["panels"] == [{"id": "totals", "w": "half"}]
        assert prefs["subnets"] == {"order": [3, 1], "pinned": [1], "hidden": [9]}
        assert prefs["compact"] is True

    def test_garbage_input_types_do_not_raise(self):
        for bad in (42, "hello", {"v": 2, "panels": "nope", "subnets": "nope"}, {"v": 1}):
            prefs = dp.upgrade(bad)
            assert prefs["v"] == 2 and isinstance(prefs["panels"], list)


class TestValidate:
    def test_unknown_widget_ids_are_dropped(self):
        prefs = dp.validate(
            {"v": 2, "panels": [{"id": "totals", "w": "full"}, {"id": "not-a-widget", "w": "full"}]}, []
        )
        assert [p["id"] for p in prefs["panels"]] == ["totals"]

    def test_duplicate_widget_ids_keep_only_the_first(self):
        prefs = dp.validate({"v": 2, "panels": [{"id": "totals", "w": "full"}, {"id": "totals", "w": "half"}]}, [])
        assert prefs["panels"] == [{"id": "totals", "w": "full"}]

    def test_an_invalid_width_falls_back_to_the_widgets_default(self):
        prefs = dp.validate({"v": 2, "panels": [{"id": "top_devices", "w": "gigantic"}]}, [])
        assert prefs["panels"] == [{"id": "top_devices", "w": dp.WIDGET_CATALOG["top_devices"]["default_w"]}]

    def test_empty_panels_falls_back_to_the_default_panels(self):
        prefs = dp.validate({"v": 2, "panels": []}, [])
        assert prefs["panels"] == dp.DEFAULT_PANELS

    def test_every_catalog_widget_declares_a_valid_default_width(self):
        for wid, meta in dp.WIDGET_CATALOG.items():
            assert meta["default_w"] in dp.WIDTHS, wid

    def test_a_subnet_id_outside_the_accessible_set_is_dropped_from_order_pinned_and_hidden(self):
        raw = {"v": 2, "panels": [], "subnets": {"order": [1, 2, 3], "pinned": [3], "hidden": [2]}}
        prefs = dp.validate(raw, accessible_subnet_ids=[1, 3])
        assert prefs["subnets"] == {"order": [1, 3], "pinned": [3], "hidden": []}

    def test_a_restricted_users_stored_value_never_smuggles_a_lost_subnet_back_in(self):
        """The scenario the gotcha in the module docstring names directly: a value
        saved while the account still had access to subnet 9 must not keep
        referencing it once that access is revoked."""
        stored = {"v": 2, "panels": [], "subnets": {"order": [9, 1], "pinned": [9], "hidden": []}}
        prefs = dp.validate(stored, accessible_subnet_ids=[1])
        assert 9 not in prefs["subnets"]["order"]
        assert 9 not in prefs["subnets"]["pinned"]

    def test_duplicate_and_non_numeric_subnet_ids_are_cleaned(self):
        raw = {"v": 2, "panels": [], "subnets": {"order": [1, 1, "not-an-id", 2], "pinned": [], "hidden": []}}
        prefs = dp.validate(raw, accessible_subnet_ids=[1, 2])
        assert prefs["subnets"]["order"] == [1, 2]

    def test_compact_is_coerced_to_a_bool(self):
        assert dp.validate({"v": 2, "compact": 1}, [])["compact"] is True
        assert dp.validate({"v": 2, "compact": 0}, [])["compact"] is False

    def test_a_v1_list_still_validates_cleanly(self):
        prefs = dp.validate(["subnet_stats", "bogus", "totals"], [])
        assert [p["id"] for p in prefs["panels"]] == ["subnet_stats", "totals"]
        assert all(p["w"] == "full" for p in prefs["panels"])

    def test_result_is_always_json_serialisable(self):
        import json

        json.dumps(dp.validate({"v": 2, "panels": [{"id": "totals", "w": "full"}]}, [1, 2, 3]))


class TestOrderedSubnetIds:
    def test_unmentioned_ids_append_in_kea_order(self):
        assert dp.ordered_subnet_ids([1, 2, 3], {"order": [3], "pinned": [], "hidden": []}) == [3, 1, 2]

    def test_an_order_entry_no_longer_present_is_skipped(self):
        assert dp.ordered_subnet_ids([1, 2], {"order": [99, 2], "pinned": [], "hidden": []}) == [2, 1]

    def test_pinned_moves_to_the_front_keeping_relative_order(self):
        assert dp.ordered_subnet_ids([1, 2, 3, 4], {"order": [], "pinned": [3, 1], "hidden": []}) == [3, 1, 2, 4]

    def test_no_prefs_at_all_is_a_no_op(self):
        assert dp.ordered_subnet_ids([5, 6, 7], {}) == [5, 6, 7]

    def test_visible_subnet_ids_drops_hidden_after_ordering(self):
        ordered = dp.ordered_subnet_ids([1, 2, 3], {"order": [], "pinned": [3], "hidden": []})
        assert dp.visible_subnet_ids(ordered, {"hidden": [2]}) == [3, 1]

    def test_hiding_a_pinned_subnet_still_hides_it(self):
        ordered = dp.ordered_subnet_ids([1, 2], {"order": [], "pinned": [1], "hidden": []})
        assert dp.visible_subnet_ids(ordered, {"hidden": [1]}) == [2]
