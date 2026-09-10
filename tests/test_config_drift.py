"""
tests/test_config_drift.py
────────────────────────────
v5.2.0 — Config drift detection. See jen/services/config_drift.py's
module docstring for the full rationale: Jen's own subnet map
(extensions.SUBNET_MAP/SUBNET6_MAP) is a manually-maintained config
file, not derived from Kea's live config at all, and can silently
drift out of sync — exactly what caused a real bug where selecting
"IoT" in a subnet filter returned Production's data instead, because
Jen's stored id for "IoT" no longer matched what Kea's live config
actually assigned that id to.

These tests focus heavily on detect_subnet_drift() since it's a pure
function (no I/O) — the actual value of this feature lives entirely in
that comparison logic being correct, so it gets the most thorough
coverage. fetch_live_subnet_map() and check_config_drift() are tested
with mocked Kea responses, matching the mocking convention already
used throughout tests/test_kea6_*.py.
"""

from jen.services.config_drift import (
    check_config_drift,
    detect_subnet_drift,
    fetch_live_subnet_map,
    issue_key,
)


class TestDetectSubnetDrift:
    def test_no_drift_when_maps_agree(self):
        jen_map = {10: {"name": "Production", "cidr": "10.10.10.0/23"}}
        live_map = {10: "10.10.10.0/23"}
        assert detect_subnet_drift(jen_map, live_map) == []

    def test_no_drift_with_multiple_agreeing_subnets(self):
        jen_map = {
            10: {"name": "Production", "cidr": "10.10.10.0/23"},
            20: {"name": "IoT", "cidr": "10.10.30.0/24"},
        }
        live_map = {10: "10.10.10.0/23", 20: "10.10.30.0/24"}
        assert detect_subnet_drift(jen_map, live_map) == []

    def test_missing_in_kea(self):
        """Jen has a subnet id Kea's live config no longer has —
        removed directly in Kea, or renumbered away."""
        jen_map = {20: {"name": "IoT", "cidr": "10.10.30.0/24"}}
        live_map = {}
        issues = detect_subnet_drift(jen_map, live_map)
        assert len(issues) == 1
        assert issues[0]["type"] == "missing_in_kea"
        assert issues[0]["subnet_id"] == 20
        assert issues[0]["jen_name"] == "IoT"
        assert "IoT" in issues[0]["message"]
        assert "10.10.30.0/24" in issues[0]["message"]

    def test_unknown_to_jen(self):
        """Kea has a subnet id Jen has no name for — added directly in
        Kea, never registered in Jen's own config."""
        jen_map = {}
        live_map = {40: "10.10.50.0/24"}
        issues = detect_subnet_drift(jen_map, live_map)
        assert len(issues) == 1
        assert issues[0]["type"] == "unknown_to_jen"
        assert issues[0]["subnet_id"] == 40
        assert issues[0]["kea_cidr"] == "10.10.50.0/24"
        assert "Subnet 40" in issues[0]["message"]

    def test_cidr_mismatch_is_the_critical_case(self):
        """The exact failure mode behind the real bug this feature
        exists to catch: both sides agree the id exists, but disagree
        on which network it actually is."""
        jen_map = {24: {"name": "IoT", "cidr": "10.10.30.0/24"}}
        live_map = {24: "10.10.10.0/23"}  # Kea says this id is actually Production's range
        issues = detect_subnet_drift(jen_map, live_map)
        assert len(issues) == 1
        assert issues[0]["type"] == "cidr_mismatch"
        assert issues[0]["subnet_id"] == 24
        assert issues[0]["jen_name"] == "IoT"
        assert issues[0]["jen_cidr"] == "10.10.30.0/24"
        assert issues[0]["kea_cidr"] == "10.10.10.0/23"
        assert "IoT" in issues[0]["message"]
        assert "silently affecting the wrong network" in issues[0]["message"]

    def test_multiple_simultaneous_issues(self):
        jen_map = {
            10: {"name": "Production", "cidr": "10.10.10.0/23"},  # agrees, no issue
            20: {"name": "IoT", "cidr": "10.10.30.0/24"},  # cidr mismatch below
            30: {"name": "Gone", "cidr": "10.10.99.0/24"},  # missing in kea
        }
        live_map = {
            10: "10.10.10.0/23",
            20: "10.10.31.0/24",  # mismatched
            40: "10.10.70.0/24",  # unknown to jen
        }
        issues = detect_subnet_drift(jen_map, live_map)
        types = sorted(i["type"] for i in issues)
        assert types == ["cidr_mismatch", "missing_in_kea", "unknown_to_jen"]
        assert len(issues) == 3

    def test_missing_cidr_on_jen_side_does_not_false_positive_as_mismatch(self):
        """Defensive: an empty/missing cidr in Jen's own map shouldn't
        be compared as if it were a real value that disagrees."""
        jen_map = {10: {"name": "Weird", "cidr": ""}}
        live_map = {10: "10.10.10.0/23"}
        issues = detect_subnet_drift(jen_map, live_map)
        assert issues == []

    def test_family_tag_carried_onto_every_issue(self):
        jen_map = {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}}
        live_map = {}
        issues = detect_subnet_drift(jen_map, live_map, family="v6")
        assert issues[0]["family"] == "v6"

    def test_empty_maps_on_both_sides_is_not_drift(self):
        assert detect_subnet_drift({}, {}) == []


class TestIssueKey:
    def test_stable_and_unique_per_issue(self):
        issue = {"family": "v4", "type": "cidr_mismatch", "subnet_id": 24}
        assert issue_key(issue) == "v4:cidr_mismatch:24"

    def test_different_family_or_type_produces_different_key(self):
        a = {"family": "v4", "type": "missing_in_kea", "subnet_id": 5}
        b = {"family": "v6", "type": "missing_in_kea", "subnet_id": 5}
        c = {"family": "v4", "type": "unknown_to_jen", "subnet_id": 5}
        assert len({issue_key(a), issue_key(b), issue_key(c)}) == 3


class TestFetchLiveSubnetMap:
    def test_v4_success_extracts_id_and_cidr(self, monkeypatch):
        import jen.services.kea as kea_module

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {"id": 10, "subnet": "10.10.10.0/23"},
                            {"id": 20, "subnet": "10.10.30.0/24"},
                        ]
                    }
                },
            }

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)
        result = fetch_live_subnet_map("v4")
        assert result == {10: "10.10.10.0/23", 20: "10.10.30.0/24"}

    def test_v6_success_uses_dhcp6_and_subnet6_keys(self, monkeypatch):
        import jen.services.kea6 as kea6_module

        def fake_kea6_command(command, arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp6": {
                        "subnet6": [
                            {"id": 1, "subnet": "2001:db8::/64"},
                        ]
                    }
                },
            }

        monkeypatch.setattr(kea6_module, "kea6_command", fake_kea6_command)
        result = fetch_live_subnet_map("v6")
        assert result == {1: "2001:db8::/64"}

    def test_kea_unreachable_returns_empty_dict_not_raises(self, monkeypatch):
        import jen.services.kea as kea_module

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {"result": 1, "text": "Cannot connect to Kea API"}

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)
        assert fetch_live_subnet_map("v4") == {}

    def test_malformed_response_returns_empty_dict_not_raises(self, monkeypatch):
        import jen.services.kea as kea_module

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {"result": 0, "arguments": {}}  # missing "Dhcp4" entirely

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)
        assert fetch_live_subnet_map("v4") == {}

    def test_v4_sees_subnets_nested_in_shared_networks(self, monkeypatch):
        """v5.15.0 — a subnet inside Dhcp4.shared-networks used to be
        absent from the live map, so config-drift reported it as
        'missing from Kea' (a false alarm)."""
        import jen.services.kea as kea_module

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [{"id": 10, "subnet": "10.10.10.0/24"}],
                        "shared-networks": [
                            {"name": "guest", "subnet4": [{"id": 70, "subnet": "10.10.70.0/24"}]},
                        ],
                    }
                },
            }

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)
        assert fetch_live_subnet_map("v4") == {10: "10.10.10.0/24", 70: "10.10.70.0/24"}


class TestCheckConfigDrift:
    def test_v4_drift_detected_end_to_end(self, monkeypatch):
        import jen.services.kea as kea_module
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {24: {"name": "IoT", "cidr": "10.10.30.0/24"}})
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {"id": 24, "subnet": "10.10.10.0/23"},  # drifted
                        ]
                    }
                },
            }

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)

        issues = check_config_drift()
        assert len(issues) == 1
        assert issues[0]["type"] == "cidr_mismatch"
        assert issues[0]["family"] == "v4"

    def test_no_drift_returns_empty_list(self, monkeypatch):
        import jen.services.kea as kea_module
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {10: {"name": "Production", "cidr": "10.10.10.0/23"}})
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {"id": 10, "subnet": "10.10.10.0/23"},
                        ]
                    }
                },
            }

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)

        assert check_config_drift() == []

    def test_kea_unreachable_skips_v4_check_rather_than_reporting_false_drift(self, monkeypatch):
        """An empty live_map from a failed fetch must not be treated as
        'Kea genuinely has zero subnets' — that would report every one
        of Jen's real subnets as 'missing_in_kea', which is false."""
        import jen.services.kea as kea_module
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {10: {"name": "Production", "cidr": "10.10.10.0/23"}})
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {"result": 1, "text": "Cannot connect to Kea API"}

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)

        assert check_config_drift() == []

    def test_v6_checked_when_enabled_and_configured(self, monkeypatch):
        import jen.services.kea as kea_module
        import jen.services.kea6 as kea6_module
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        monkeypatch.setattr(kea6_module, "is_ipv6_enabled", lambda: True)

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}}

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)

        def fake_kea6_command(command, arguments=None, server=None):
            return {
                "result": 0,
                "arguments": {
                    "Dhcp6": {
                        "subnet6": [
                            {"id": 1, "subnet": "2001:db8:9999::/64"},  # drifted
                        ]
                    }
                },
            }

        monkeypatch.setattr(kea6_module, "kea6_command", fake_kea6_command)

        issues = check_config_drift()
        assert len(issues) == 1
        assert issues[0]["family"] == "v6"
        assert issues[0]["type"] == "cidr_mismatch"

    def test_v6_skipped_when_disabled(self, monkeypatch):
        import jen.services.kea as kea_module
        import jen.services.kea6 as kea6_module
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        monkeypatch.setattr(kea6_module, "is_ipv6_enabled", lambda: False)

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            return {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}}

        monkeypatch.setattr(kea_module, "kea_command", fake_kea_command)

        assert check_config_drift() == []
