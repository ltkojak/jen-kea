"""
tests/test_kea_log_inputs.py
─────────────────────────────
v5.68.0-beta.2 (Q135) — jen/services/kea_log_inputs.py against what a REAL kea-dhcp4 wrote. The three fixtures under
tests/fixtures/ are the lines (and, for the packet dump, the continuation lines) that named one probe client in the output of
kea-dhcp4 3.0.3, 3.2.0 and 3.3.1 at debuglevel 55, captured by tests/kea_compat/test_log_levels.py; the numbers in the
assertions are what that probe sent (vendor class "jen-probe-vendor", user class "jen-user", hostname "probe-host", circuit id
"eth0/1/7", remote id 0a:0b:0c:0d:0e:0f). Pure: `pytest --noconftest tests/test_kea_log_inputs.py`.
"""

import pathlib

import pytest

from jen.services import kea_log_inputs as li

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
VERSIONS = ["3.0.3", "3.2.0", "3.3.1"]
MAC = "02:50:00:00:01:06"


def _lines(version):
    return (FIX / f"kea-{version}-debug55.log").read_text(encoding="utf-8").split("\n")


@pytest.mark.parametrize("version", VERSIONS)
class TestAgainstARealKea:
    def test_the_client_id_is_on_every_label(self, version):
        got = li.client_id_from_log(_lines(version), MAC)
        assert got and got["client_id"] == "01:02:50:00:00:01:06"

    def test_the_newest_class_list_carries_the_builtin_vendor_class(self, version):
        # the probe's REQUEST was refused (its address was taken), so the newest list is the REQUEST's AFTER_SUBNET_SELECTION
        # one, not the DISCOVER's final DHCP4_CLASSES_ASSIGNED - newest by position is what Explain wants either way
        got = li.latest_classes(_lines(version), MAC)
        assert got["id"] in li.CLASS_LIST_IDS
        assert got["classes"][:4] == ["ALL", "VENDOR_CLASS_jen-probe-vendor", "jen-probe-vendor", "jen-probe-user"]
        assert li.vendor_class_from(got["classes"]) == "jen-probe-vendor"

    def test_the_final_list_of_the_discover_names_its_message(self, version):
        discover_only = [ln for ln in _lines(version) if "tid=0x20006" not in ln]
        got = li.latest_classes(discover_only, MAC)
        assert got["id"] == "DHCP4_CLASSES_ASSIGNED" and got["message"] == "DHCPDISCOVER"
        assert got["classes"][-1] == "UNKNOWN"

    def test_the_packet_dump_gives_every_input(self, version):
        got = li.latest_query_data(_lines(version), MAC)
        assert got["hostname"] == "probe-host"
        assert got["vendor_class"] == "jen-probe-vendor"
        assert got["client_id"] == "01:02:50:00:00:01:06"
        assert got["user_class"] == "jen-user"
        assert got["circuit_id"] == "eth0/1/7"
        assert got["remote_id"] == "0a0b0c0d0e0f"

    def test_the_dump_taken_is_the_newest_one_for_the_client(self, version):
        lines = _lines(version)
        stamps = [ln[:23] for ln in lines if "DHCP4_QUERY_DATA" in ln]
        assert len(stamps) == 2, "a DISCOVER's dump and a REQUEST's"
        assert li.latest_query_data(lines, MAC)["at"] == stamps[-1]

    def test_another_client_is_not_this_one(self, version):
        assert li.latest_classes(_lines(version), "02:50:00:00:01:99") is None
        assert li.latest_query_data(_lines(version), "02:50:00:00:01:99") is None
        assert li.client_id_from_log(_lines(version), "02:50:00:00:01:99") is None


class TestClassLists:
    LINE = (
        "2026-10-04 15:10:39.670 DEBUG [kea-dhcp4.dhcp4/1.1] DHCP4_CLASSES_ASSIGNED [hwtype=1 aa:bb:cc:dd:ee:01], "
        "cid=[01:aa:bb:cc:dd:ee:01], tid=0x1: client packet has been assigned on DHCPREQUEST message to the following "
        "classes: ALL, KNOWN, iot"
    )
    AFTER = LINE.replace("DHCP4_CLASSES_ASSIGNED ", "DHCP4_CLASSES_ASSIGNED_AFTER_SUBNET_SELECTION ").replace(
        "assigned on DHCPREQUEST message to", "assigned to"
    )

    def test_the_final_list_after_the_subnet_one_wins_by_position(self):
        got = li.latest_classes([self.AFTER, self.LINE], "aa:bb:cc:dd:ee:01")
        assert got["id"] == "DHCP4_CLASSES_ASSIGNED" and got["classes"] == ["ALL", "KNOWN", "iot"]
        assert got["message"] == "DHCPREQUEST"

    def test_the_subnet_stage_list_is_read_too(self):
        got = li.latest_classes([self.AFTER], "aa:bb:cc:dd:ee:01")
        assert got["id"] == "DHCP4_CLASSES_ASSIGNED_AFTER_SUBNET_SELECTION" and got["message"] == ""

    def test_a_singular_class_line_is_not_a_list(self):
        single = self.LINE.replace("DHCP4_CLASSES_ASSIGNED", "DHCP4_CLASS_ASSIGNED")
        assert li.latest_classes([single], "aa:bb:cc:dd:ee:01") is None

    def test_a_vendor_class_needs_a_value(self):
        assert li.vendor_class_from(["ALL", "VENDOR_CLASS_", "VENDOR_CLASS_MSFT 5.0"]) == "MSFT 5.0"
        assert li.vendor_class_from(["ALL", "KNOWN"]) == ""

    @pytest.mark.parametrize(
        "junk", ["", "not a log line", "2026-10-04 DEBUG [x] DHCP4_CLASSES_ASSIGNED no label here"]
    )
    def test_junk_is_skipped_never_raised_on(self, junk):
        assert li.latest_classes([junk], "aa:bb:cc:dd:ee:01") is None
        assert li.latest_query_data([junk], "aa:bb:cc:dd:ee:01") is None
        assert li.client_id_from_log([junk], "aa:bb:cc:dd:ee:01") is None

    def test_no_mac_means_nothing(self):
        assert li.latest_classes([self.LINE], "") is None


class TestTheLeasesExtendedInfo:
    # exactly what kea-dhcp4 3.0.3, 3.2.0 and 3.3.1 stored in lease4.user_context with store-extended-info
    REAL = (
        '{ "ISC": { "relay-agent-info": { "remote-id": "0A0B0C0D0E0F", '
        '"sub-options": "0x0108657468302F312F3702060A0B0C0D0E0F" } } }'
    )

    def test_the_circuit_and_remote_ids_are_read(self):
        assert li.relay_info_from_user_context(self.REAL) == {
            "circuit_id": "eth0/1/7",
            "circuit_id_hex": "657468302f312f37",
            "remote_id": "0a0b0c0d0e0f",
        }

    def test_a_dict_is_accepted_and_a_binary_circuit_id_comes_back_as_hex(self):
        ctx = {"ISC": {"relay-agent-info": {"sub-options": "0x0104deadbeef"}}}
        assert li.relay_info_from_user_context(ctx) == {
            "circuit_id": "deadbeef",
            "circuit_id_hex": "deadbeef",
            "remote_id": "",
        }

    @pytest.mark.parametrize("junk", [None, "", "{", "[]", '{"ISC": 3}', '{"ISC": {"relay-agent-info": "x"}}', 7])
    def test_anything_else_is_empty_not_an_error(self, junk):
        assert li.relay_info_from_user_context(junk) == {"circuit_id": "", "circuit_id_hex": "", "remote_id": ""}

    def test_a_truncated_tlv_stops_the_walk(self):
        ctx = {"ISC": {"relay-agent-info": {"sub-options": "0x010841"}}}
        assert li.relay_info_from_user_context(ctx)["circuit_id"] == ""


class TestTheHint:
    def test_it_names_the_level_that_unlocks_what_is_missing(self):
        hint = li.level_hint(["vendor_class", "circuit_id"])
        assert "debuglevel 55" in hint and "debuglevel 45" in hint and "store-extended-info" in hint

    def test_nothing_missing_nothing_said(self):
        assert li.level_hint([]) == ""
        assert li.level_hint(["mac"]) == ""

    def test_a_missing_hostname_points_only_at_the_packet_dump(self):
        hint = li.level_hint(["hostname"])
        assert "debuglevel 55" in hint and "store-extended-info" not in hint
