"""
tests/test_client_problems.py
──────────────────────────────
v5.68.0-beta.5 (Q140) — the Problems inbox, the parts that need no database: the log reader (`kea_log_trace.problem_events`) on the
REAL log lines the Kea compat probe captured on 3.0.3 / 3.2.0 / 3.3.1 and on lines built from the message ids in ISC's own
dhcp4_messages.mes, the watermark that makes a line read twice one event, the alert rule, the two database-derived kinds' shapes,
the grouping, the optional threshold key and the alert type. `pytest --noconftest tests/test_client_problems.py`.
The sweep, the table and the page are tests/test_client_problems_db.py and tests/test_problems_page.py.
"""

import glob
import logging
import pathlib
from datetime import datetime, timedelta

import pytest

from jen.services import alerts
from jen.services import client_problems as cp
from jen.services import kea_log_trace as klt

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAC = "aa:bb:cc:dd:ee:01"
MAC2 = "aa:bb:cc:dd:ee:02"


def _label(mac, tid="0x1a2b"):
    return f"[hwtype=1 {mac}], cid=[01:{mac}], tid={tid}"


def _line(ts, level, msg_id, body, mac=MAC, tid="0x1a2b", label=True):
    lead = _label(mac, tid) + ": " if label else ""
    return f"2026-10-04 {ts} {level:<5} [kea-dhcp4.test/1.140] {msg_id} {lead}{body}"


class TestTheRealLogsFromThreeKeaVersions:
    """tests/fixtures/kea-<version>-debug55.log are what real kea-dhcp4 3.0.3, 3.2.0 and 3.3.1 wrote for a relayed request the
    server NAKed (tests/kea_compat/test_log_levels.py captures them)."""

    FILES = sorted(glob.glob(str(ROOT / "tests" / "fixtures" / "kea-*-debug55.log")))

    def test_the_fixtures_are_there(self):
        assert len(self.FILES) == 3

    @pytest.mark.parametrize("path", FILES)
    def test_at_debug_the_nak_is_one_event_with_the_requested_address(self, path):
        events = klt.problem_events(pathlib.Path(path).read_text(encoding="utf-8").splitlines())
        assert [(e["kind"], e["mac"], e["ip"]) for e in events] == [("nak", "02:50:00:00:01:06", "10.99.0.150")]

    @pytest.mark.parametrize("path", FILES)
    def test_at_info_the_nak_kea_sent_is_still_there_without_an_address(self, path):
        lines = [x for x in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if " INFO " in x]
        events = klt.problem_events(lines)
        assert [(e["kind"], e["mac"], e["ip"], e["detail"]) for e in events] == [
            ("nak", "02:50:00:00:01:06", "", "Kea sent a DHCPNAK")
        ], "the addresses on the 'from 10.1.0.x:67 to 10.99.0.1:67' line are Kea's and its relay's, never the client's"


class TestEachKind:
    def test_decline_at_info(self):
        events = klt.problem_events(
            [
                _line(
                    "10:00:00.100",
                    "INFO",
                    "DHCP4_DECLINE_LEASE",
                    "Received DHCPDECLINE for addr 10.0.1.55 from client x. The lease will be unavailable for 86400 seconds.",
                )
            ]
        )
        assert [(e["kind"], e["mac"], e["ip"]) for e in events] == [("decline", MAC, "10.0.1.55")]

    @pytest.mark.parametrize("msg_id", ["DHCP4_DECLINE_LEASE_MISMATCH", "DHCP4_DECLINE_LEASE_NOT_FOUND"])
    def test_the_failed_declines_are_declines_too(self, msg_id):
        events = klt.problem_events([_line("10:00:00.100", "WARN", msg_id, "address 10.0.1.55 does not match")])
        assert [e["kind"] for e in events] == ["decline"]

    @pytest.mark.parametrize("msg_id", ["DHCP4_PACKET_DROP_0007", "DHCP4_PACKET_DROP_0008"])
    def test_drops_at_debug(self, msg_id):
        events = klt.problem_events([_line("10:00:00.100", "DEBUG", msg_id, "DHCPDISCOVER dropped")])
        assert [(e["kind"], e["mac"]) for e in events] == [("drop", MAC)]

    def test_a_drop_id_the_table_does_not_list_is_still_a_drop(self):
        events = klt.problem_events([_line("10:00:00.100", "DEBUG", "DHCP4_PACKET_DROP_0099", "dropped")])
        assert [e["kind"] for e in events] == ["drop"]

    def test_subnet_selection_failed_at_debug(self):
        events = klt.problem_events(
            [_line("10:00:00.100", "DEBUG", "DHCP4_SUBNET_SELECTION_FAILED", "failed to select subnet for the packet")]
        )
        assert [(e["kind"], e["mac"]) for e in events] == [("subnet-selection-failed", MAC)]

    @pytest.mark.parametrize(
        "msg_id", ["DHCP4_PACKET_NAK_0001", "DHCP4_PACKET_NAK_0002", "DHCP4_PACKET_NAK_0003", "DHCP4_PACKET_NAK_0004"]
    )
    def test_every_nak_reason(self, msg_id):
        events = klt.problem_events([_line("10:00:00.100", "ERROR", msg_id, "requested-ip-address 10.0.0.9")])
        assert [(e["kind"], e["ip"]) for e in events] == [("nak", "10.0.0.9")]

    def test_ddns_failed_is_attached_to_the_client_the_lines_show_getting_that_address(self):
        lines = [
            _line("10:00:00.100", "INFO", "DHCP4_LEASE_ALLOC", "lease 10.0.0.5 has been allocated for 3600 seconds"),
            _line(
                "10:00:00.900", "ERROR", "DHCP4_DDNS_REQUEST_SEND_FAILED", "failed sending a request to kea-dhcp-ddns, "
                "ncr: address: 10.0.0.5, fqdn: host.example.", label=False,
            ),
        ]  # fmt: skip
        events = klt.problem_events(lines)
        assert [(e["kind"], e["mac"], e["ip"]) for e in events] == [("ddns-failed", MAC, "10.0.0.5")]

    def test_a_ddns_failure_about_an_address_no_client_was_seen_with_is_dropped(self):
        lines = [
            _line("10:00:00.900", "ERROR", "DHCP4_DDNS_REQUEST_SEND_FAILED", "ncr: address: 10.0.0.77", label=False)
        ]
        assert klt.problem_events(lines) == []

    def test_a_problem_line_that_names_no_client_is_skipped(self):
        assert (
            klt.problem_events([_line("10:00:00.100", "DEBUG", "DHCP4_PACKET_DROP_0007", "dropped", label=False)]) == []
        )

    def test_ordinary_traffic_is_not_a_problem(self):
        lines = [
            _line("10:00:00.100", "INFO", "DHCP4_PACKET_RECEIVED", "DHCPDISCOVER (type 1) received from 10.0.0.1"),
            _line("10:00:00.200", "INFO", "DHCP4_LEASE_OFFER", "lease 10.0.0.5 will be offered"),
            _line("10:00:00.300", "INFO", "DHCP4_PACKET_SEND", "trying to send packet DHCPOFFER (type 2) from a to b"),
            "garbage that is not a log line at all",
            "",
        ]
        assert klt.problem_events(lines) == []

    def test_events_come_back_in_time_order(self):
        lines = [
            _line("10:00:09.000", "INFO", "DHCP4_DECLINE_LEASE", "addr 10.0.0.2", mac=MAC2),
            _line("10:00:01.000", "INFO", "DHCP4_DECLINE_LEASE", "addr 10.0.0.1"),
        ]
        assert [e["mac"] for e in klt.problem_events(lines)] == [MAC, MAC2]


class TestANakIsOneEvent:
    def test_the_nak_line_and_the_send_line_with_one_transaction_id_are_one_event_keeping_the_address_and_the_reason(
        self,
    ):
        lines = [
            _line(
                "10:00:00.100",
                "DEBUG",
                "DHCP4_PACKET_NAK_0004",
                "failed to grant a lease, requested-ip-address 10.0.0.9",
            ),
            _line(
                "10:00:00.101", "INFO", "DHCP4_PACKET_SEND", "trying to send packet DHCPNAK (type 6) from a:67 to b:67"
            ),
        ]
        events = klt.problem_events(lines)
        assert len(events) == 1 and events[0]["ip"] == "10.0.0.9" and "grant" in events[0]["detail"]

    def test_the_send_line_first_then_the_nak_line_is_still_one_event_with_the_address(self):
        lines = [
            _line(
                "10:00:00.100", "INFO", "DHCP4_PACKET_SEND", "trying to send packet DHCPNAK (type 6) from a:67 to b:67"
            ),
            _line(
                "10:00:00.101",
                "DEBUG",
                "DHCP4_PACKET_NAK_0004",
                "failed to grant a lease, requested-ip-address 10.0.0.9",
            ),
        ]
        events = klt.problem_events(lines)
        assert len(events) == 1 and events[0]["ip"] == "10.0.0.9"

    def test_two_naks_with_two_transaction_ids_are_two_events(self):
        lines = [
            _line("10:00:00.100", "INFO", "DHCP4_PACKET_SEND", "packet DHCPNAK (type 6)", tid="0x1"),
            _line("10:00:05.100", "INFO", "DHCP4_PACKET_SEND", "packet DHCPNAK (type 6)", tid="0x2"),
        ]
        assert len(klt.problem_events(lines)) == 2

    def test_the_same_transaction_id_from_two_clients_is_two_events(self):
        lines = [
            _line("10:00:00.100", "INFO", "DHCP4_PACKET_SEND", "packet DHCPNAK (type 6)", tid="0x1"),
            _line("10:00:00.200", "INFO", "DHCP4_PACKET_SEND", "packet DHCPNAK (type 6)", tid="0x1", mac=MAC2),
        ]
        assert len(klt.problem_events(lines)) == 2

    def test_a_dhcpack_send_is_not_a_nak(self):
        assert klt.problem_events([_line("10:00:00.100", "INFO", "DHCP4_PACKET_SEND", "packet DHCPACK (type 5)")]) == []


def _ev(kind, mac, ts, ip="", detail="d", subnet_id=None):
    return {
        "kind": kind, "mac": mac, "ts": ts, "ip": ip, "detail": detail, "level": "INFO", "id": "X", "tid": "",
        "subnet_id": subnet_id,
    }  # fmt: skip


T0 = datetime(2026, 10, 4, 10, 0, 0)


class TestCollectAndTheWatermark:
    def test_the_first_sweep_counts_everything_in_the_tail(self):
        events = [_ev("nak", MAC, T0 + timedelta(seconds=i)) for i in range(4)]
        groups, recent, wm = cp.collect(events, None)
        assert groups[("nak", MAC, "")]["new"] == 4 and recent[("nak", MAC)] == 4 and wm == T0 + timedelta(seconds=3)

    def test_a_line_read_by_two_sweeps_is_one_event(self):
        events = [_ev("nak", MAC, T0 + timedelta(seconds=i)) for i in range(3)]
        _g, _r, wm = cp.collect(events, None)
        groups, recent, wm2 = cp.collect(events, wm)
        assert groups == {} and wm2 == wm
        assert recent[("nak", MAC)] == 3, (
            "the alert window is the log's, not the sweep's: old lines still count toward it"
        )

    def test_only_the_newer_lines_are_added(self):
        events = [_ev("nak", MAC, T0 + timedelta(seconds=i)) for i in range(5)]
        groups, _r, wm = cp.collect(events, T0 + timedelta(seconds=2))
        assert groups[("nak", MAC, "")]["new"] == 2 and wm == T0 + timedelta(seconds=4)

    def test_a_line_at_exactly_the_watermark_counts_as_seen(self):
        groups, _r, _wm = cp.collect([_ev("nak", MAC, T0)], T0)
        assert groups == {}

    def test_the_watermark_never_moves_backwards(self):
        _g, _r, wm = cp.collect([_ev("nak", MAC, T0)], T0 + timedelta(hours=1))
        assert wm == T0 + timedelta(hours=1)

    def test_no_events_leaves_the_watermark_alone(self):
        assert cp.collect([], T0) == ({}, {}, T0) and cp.collect([], None) == ({}, {}, None)

    def test_the_hour_window_is_measured_from_the_newest_line_and_spans_addresses(self):
        events = [
            _ev("nak", MAC, T0, ip="10.0.0.1"),
            _ev("nak", MAC, T0 + timedelta(minutes=30), ip="10.0.0.2"),
            _ev("nak", MAC, T0 + timedelta(minutes=59), ip=""),
            _ev("nak", MAC2, T0 + timedelta(minutes=59)),
        ]
        _g, recent, _wm = cp.collect(events, None)
        assert recent[("nak", MAC)] == 3 and recent[("nak", MAC2)] == 1
        events.append(_ev("nak", MAC, T0 + timedelta(minutes=61)))
        _g, recent, _wm = cp.collect(events, None)
        assert recent[("nak", MAC)] == 3, "the 10:00 line fell out of the hour ending at the newest line (11:01)"

    def test_each_kind_and_address_is_its_own_group(self):
        events = [
            _ev("nak", MAC, T0, ip="10.0.0.1"),
            _ev("nak", MAC, T0, ip=""),
            _ev("decline", MAC, T0, ip="10.0.0.1"),
        ]
        groups, _r, _wm = cp.collect(events, None)
        assert set(groups) == {("nak", MAC, "10.0.0.1"), ("nak", MAC, ""), ("decline", MAC, "10.0.0.1")}

    def test_the_group_keeps_the_newest_detail(self):
        events = [_ev("nak", MAC, T0, detail="old"), _ev("nak", MAC, T0 + timedelta(seconds=5), detail="new")]
        groups, _r, _wm = cp.collect(events, None)
        assert groups[("nak", MAC, "")]["detail"] == "new"


class TestShouldAlert:
    NOW = datetime(2026, 10, 4, 12, 0)

    def test_below_the_threshold_never(self):
        assert not cp.should_alert(2, None, self.NOW, limit=3)

    def test_at_the_threshold_once(self):
        assert cp.should_alert(3, None, self.NOW, limit=3)

    def test_not_again_inside_a_day_whatever_the_count(self):
        assert not cp.should_alert(60, self.NOW - timedelta(hours=23, minutes=59), self.NOW, limit=3)

    def test_again_after_a_day(self):
        assert cp.should_alert(3, self.NOW - timedelta(hours=24), self.NOW, limit=3)

    def test_the_default_limit_is_the_configured_threshold(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "CLIENT_PROBLEM_THRESHOLD", 5)
        assert not cp.should_alert(4, None, self.NOW) and cp.should_alert(5, None, self.NOW)


class TestTheTwoDatabaseKinds:
    def test_a_declined_lease_is_about_the_address_when_kea_cleared_the_hardware_address(self):
        out = cp.from_declined([{"ip": "10.0.0.9", "mac_hex": None, "subnet_id": 3}])
        assert out == [
            {
                "kind": "declined-lease",
                "mac": "",
                "ip": "10.0.0.9",
                "subnet_id": 3,
                "detail": "10.0.0.9 was declined by a client and Kea is holding it out of service",
            }
        ]

    def test_a_declined_lease_that_kept_its_hardware_address_names_the_client(self):
        assert cp.from_declined([{"ip": "10.0.0.9", "mac_hex": "AABBCCDDEE01", "subnet_id": 3}])[0]["mac"] == MAC

    def test_a_row_with_no_address_is_skipped(self):
        assert cp.from_declined([{"ip": "", "mac_hex": None, "subnet_id": 1}]) == []

    def test_a_held_reservation_is_about_the_client_it_is_for_and_names_the_holder(self):
        out = cp.from_held(
            [{"res_mac_hex": "AABBCCDDEE01", "ip": "10.0.0.7", "subnet_id": 2, "holder_hex": "AABBCCDDEE02"}]
        )
        assert out[0]["kind"] == "reservation-held" and out[0]["mac"] == MAC and out[0]["subnet_id"] == 2
        assert out[0]["detail"] == f"its reserved 10.0.0.7 is leased to {MAC2}"

    def test_a_reservation_without_a_usable_mac_is_skipped(self):
        assert cp.from_held([{"res_mac_hex": "", "ip": "10.0.0.7", "subnet_id": 2, "holder_hex": "AA"}]) == []

    def test_a_subnet_of_zero_is_no_subnet(self):
        assert (
            cp.from_held([{"res_mac_hex": "AABBCCDDEE01", "ip": "10.0.0.7", "subnet_id": 0, "holder_hex": "x"}])[0][
                "subnet_id"
            ]
            is None
        )


def _row(kind, mac, last, ip="", server=1, count=1, first=None):
    return {
        "kind": kind, "mac": mac, "ip": ip, "server_id": server, "count": count, "detail": "d",
        "last_seen": last, "first_seen": first or last, "subnet_id": 1,
    }  # fmt: skip


class TestGroupByClient:
    def test_one_entry_per_client_newest_first_with_every_kind_it_had(self):
        rows = [
            _row("nak", MAC, T0 + timedelta(minutes=5), count=4),
            _row("decline", MAC, T0 + timedelta(minutes=2), ip="10.0.0.9"),
            _row("drop", MAC2, T0 + timedelta(minutes=9)),
        ]
        out = cp.group_by_client(rows)
        assert [c["who"] for c in out] == [MAC2, MAC]
        mine = out[1]
        assert [k["kind"] for k in mine["kinds"]] == ["nak", "decline"] and mine["total"] == 5
        assert mine["last_seen"] == T0 + timedelta(minutes=5) and mine["ip"] == "10.0.0.9"

    def test_a_row_with_no_mac_is_the_address(self):
        out = cp.group_by_client([_row("declined-lease", "", T0, ip="10.0.0.9", server=0)])
        assert out[0]["who"] == "10.0.0.9" and out[0]["mac"] == ""

    def test_servers_are_listed_once(self):
        out = cp.group_by_client([_row("nak", MAC, T0, server=1), _row("decline", MAC, T0, server=1, ip="1.1.1.1")])
        assert out[0]["server_ids"] == [1]

    def test_the_first_seen_is_the_earliest(self):
        out = cp.group_by_client(
            [_row("nak", MAC, T0 + timedelta(hours=1), first=T0), _row("drop", MAC, T0 + timedelta(hours=2))]
        )
        assert out[0]["first_seen"] == T0

    def test_nothing_is_nothing(self):
        assert cp.group_by_client([]) == []


class TestTheThresholdKey:
    def test_absent_is_three(self):
        from jen.config import _parse_problem_threshold as parse

        assert parse("") == 3 and parse(None) == 3

    def test_a_number_is_taken(self):
        from jen.config import _parse_problem_threshold as parse

        assert parse("5") == 5 and parse(" 10 ") == 10 and parse("100000") == 1000

    @pytest.mark.parametrize("raw", ["0", "-2", "many", "2.5"])
    def test_anything_else_is_three_with_a_warning(self, raw, caplog):
        from jen.config import _parse_problem_threshold as parse

        with caplog.at_level(logging.WARNING):
            assert parse(raw) == 3
        assert "client_problem_threshold" in caplog.text

    def test_the_extension_default(self):
        from jen import extensions

        assert extensions.CLIENT_PROBLEM_THRESHOLD == 3


class TestTheAlertType:
    def test_it_is_a_core_type_with_a_label_an_icon_and_a_standard_glyph(self):
        glyphs = {g for g, _, _ in alerts.GLYPH_LEGEND}
        assert alerts.ALERT_TYPE_LABELS["client_problems"] == "Client had DHCP trouble"
        assert alerts.ALERT_TYPE_ICONS["client_problems"] == "triangle-alert"
        assert alerts.DEFAULT_TEMPLATES["client_problems"].split(" ", 1)[0] in glyphs

    def test_the_template_names_the_client_the_kind_the_count_and_the_investigate_link(self):
        text = alerts.render_template_str(
            alerts.DEFAULT_TEMPLATES["client_problems"],
            mac=MAC, ip="10.0.0.9", kind="NAK", count=4, server="kea-a", investigate=f"/client?q={MAC}",
        )  # fmt: skip
        for needle in (MAC, "10.0.0.9", "NAK", "4 in the last hour", "kea-a", f"/client?q={MAC}"):
            assert needle in text
        assert "{" not in text

    def test_every_kind_has_a_label_and_a_sentence(self):
        for kind in cp.ALL_KINDS:
            assert cp.KIND_LABELS[kind] and cp.KIND_HELP[kind], kind

    def test_the_alert_icon_is_one_the_dashboard_knows(self):
        from jen.services.icons import is_icon

        assert is_icon(alerts.ALERT_TYPE_ICONS["client_problems"])


# ── v5.68.0-beta.9 (Q144): the events' own times, judged against now; the Kea host's clock; the scoped alert ───────────


class TestTheEventsOwnTimes:
    def test_a_group_carries_the_first_and_last_timestamps_of_its_own_events(self):
        events = [_ev("nak", MAC, T0 + timedelta(minutes=m)) for m in (5, 1, 9)]
        groups, _r, _wm = cp.collect(events, None)
        g = groups[("nak", MAC, "")]
        assert g["first_ts"] == T0 + timedelta(minutes=1) and g["last_ts"] == T0 + timedelta(minutes=9)

    def test_the_converted_time_is_what_is_stored_while_the_watermark_stays_in_the_logs_clock(self):
        now = T0 + timedelta(days=1)
        events = cp.shift_events([_ev("nak", MAC, T0 + timedelta(minutes=m)) for m in (1, 2)], -18000, now)
        groups, _r, wm = cp.collect(events, None, now=now)
        g = groups[("nak", MAC, "")]
        assert g["first_ts"] == T0 + timedelta(minutes=1, hours=5) and wm == T0 + timedelta(minutes=2)

    def test_the_alert_window_is_judged_against_now_not_the_newest_line(self):
        six_hours_ago = [_ev("nak", MAC, T0 + timedelta(seconds=i)) for i in range(3)]
        _g, newest_anchored, _wm = cp.collect(six_hours_ago, None)
        assert newest_anchored[("nak", MAC)] == 3, (
            "anchored at the newest line (the pure default): three NAKs just happened"
        )
        _g, recent, _wm = cp.collect(six_hours_ago, None, now=T0 + timedelta(hours=6))
        assert recent.get(("nak", MAC), 0) == 0, "judged against now they are six hours old and are no alert"

    def test_a_group_keeps_the_newest_events_own_subnet(self):
        events = [_ev("nak", MAC, T0, subnet_id=2), _ev("nak", MAC, T0 + timedelta(seconds=5), subnet_id=None)]
        groups, _r, _wm = cp.collect(events, None)
        assert groups[("nak", MAC, "")]["subnet_id"] is None, "the newest event named none: the row is unattributed"
        events = [_ev("nak", MAC, T0, subnet_id=None), _ev("nak", MAC, T0 + timedelta(seconds=5), subnet_id=1)]
        assert cp.collect(events, None)[0][("nak", MAC, "")]["subnet_id"] == 1

    def test_a_converted_time_is_never_later_than_now(self):
        now = T0 + timedelta(minutes=10)
        (e,) = cp.shift_events([_ev("nak", MAC, T0 + timedelta(minutes=9))], -3600, now)
        assert e["uts"] == now and e["ts"] == T0 + timedelta(minutes=9), "an offset not caught up with: clamp, keep ts"


class TestTheKeaHostsClock:
    ALLOC = datetime(2026, 10, 4, 7, 0, 0)  # the host's local clock, UTC-5: 12:00 UTC

    def _alloc(self, ip, local=None, secs=3600):
        return {"ts": local or self.ALLOC, "ip": ip, "seconds": secs}

    def test_utc_minus_five_from_one_lease_that_lands_on_a_quarter_hour(self):
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 0, 0)}  # 12:00 UTC + 3600 s
        assert cp.clock_offset([self._alloc("10.0.0.5")], expiries) == -18000.0

    def test_two_leases_that_agree_are_enough_even_when_each_is_a_few_minutes_off(self):
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 3, 0), "10.0.0.6": datetime(2026, 10, 4, 13, 1, 0)}
        got = cp.clock_offset([self._alloc("10.0.0.5"), self._alloc("10.0.0.6")], expiries)
        assert got == -18000.0, "a few minutes of skew: to the nearest quarter hour it is still UTC-5"

    def test_a_single_lease_that_is_not_near_a_quarter_hour_is_not_trusted(self):
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 7, 0)}  # renewed later: 7 minutes from any quarter hour
        assert cp.clock_offset([self._alloc("10.0.0.5")], expiries) is None

    def test_two_leases_that_disagree_settle_nothing(self):
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 0, 0), "10.0.0.6": datetime(2026, 10, 4, 14, 0, 0)}
        assert cp.clock_offset([self._alloc("10.0.0.5"), self._alloc("10.0.0.6")], expiries) is None

    def test_only_the_newest_allocation_of_an_address_counts(self):
        later = self.ALLOC + timedelta(minutes=30)
        allocs = [self._alloc("10.0.0.5"), self._alloc("10.0.0.5", local=later)]
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 30, 0)}  # the renewal at 12:30 UTC
        assert cp.clock_offset(allocs, expiries) == -18000.0

    def test_no_lease_row_no_answer(self):
        assert cp.clock_offset([self._alloc("10.0.0.5")], {}) is None and cp.clock_offset([], {"10.0.0.5": T0}) is None

    def test_a_host_east_of_utc(self):
        expiries = {"10.0.0.5": datetime(2026, 10, 4, 13, 0, 0)}
        assert cp.clock_offset([self._alloc("10.0.0.5", local=datetime(2026, 10, 4, 14, 0, 0))], expiries) == 7200.0

    def test_the_sentence_for_the_page(self):
        assert cp.describe_offset(-18000.0, "measured") == "UTC-5 (from the lease records)"
        assert cp.describe_offset(19800.0, "measured") == "UTC+5:30 (from the lease records)"
        assert cp.describe_offset(0.0, "measured") == "UTC+0 (from the lease records)"
        assert "assumed UTC" in cp.describe_offset(None, "assumed") and "assumed UTC" in cp.describe_offset(
            0.0, "assumed"
        )


class TestAnAlertAboutAClientWithNoSubnetFailsClosedForAScopedChannel:
    def test_the_channel_rule(self):
        scoped = {"channel_type": "telegram", "subnet_scope": "[1, 2]"}
        open_ = {"channel_type": "slack", "subnet_scope": None}
        assert alerts.channel_allows_subnet(scoped, None) is True, "kea_down and friends: no subnet, goes everywhere"
        assert alerts.channel_allows_subnet(scoped, None, scoped=True) is False
        assert alerts.channel_allows_subnet(open_, None, scoped=True) is True, (
            "a channel with no scope hears everything"
        )
        assert alerts.channel_allows_subnet(scoped, 1, scoped=True) is True
        assert alerts.channel_allows_subnet(scoped, 3, scoped=True) is False
        assert alerts.channel_allows_subnet({"subnet_scope": "[]"}, None, scoped=True) is True, (
            "an empty scope is no scope"
        )

    def test_a_malformed_scope_still_fails_open(self):
        assert alerts.channel_allows_subnet({"subnet_scope": "{not json"}, None, scoped=True) is True

    def test_client_problems_is_a_scoped_alert_type_by_itself(self):
        assert "client_problems" in alerts.SCOPED_ALERT_TYPES and "kea_down" not in alerts.SCOPED_ALERT_TYPES

    def test_send_alert_reaches_the_open_channel_and_not_the_scoped_one(self, monkeypatch):
        sent = []
        channels = [
            {"channel_type": "telegram", "subnet_scope": "[1]"},
            {"channel_type": "slack", "subnet_scope": None},
        ]
        monkeypatch.setattr(alerts, "get_alert_template", lambda alert_type: "{{ server }}")  # no database in this file
        monkeypatch.setattr(alerts, "get_active_channels", lambda: channels)
        monkeypatch.setattr(alerts, "channel_handles_alert", lambda channel, alert_type: True)
        monkeypatch.setattr(alerts, "get_channel_config", lambda channel: {})
        monkeypatch.setattr(alerts, "_send_telegram_channel", lambda message, config: sent.append("telegram") or True)
        monkeypatch.setattr(alerts, "_send_slack_channel", lambda message, config: sent.append("slack") or True)
        monkeypatch.setattr(alerts, "__emit_event", lambda *a, **k: None)
        kw = {"mac": MAC, "ip": "", "kind": "NAK", "count": 3, "server": "kea-a", "investigate": "/client?q=x"}
        results = alerts.send_alert("client_problems", log_result=False, subnet_id=None, **kw)
        assert sent == ["slack"] and results == [("slack", True, "")]
        sent.clear()
        alerts.send_alert("client_problems", log_result=False, subnet_id=1, **kw)
        assert sorted(sent) == ["slack", "telegram"]
        sent.clear()
        alerts.send_alert("kea_down", log_result=False, subnet_id=None, server="kea-a")
        assert sorted(sent) == ["slack", "telegram"], "an unscoped alert type is unchanged"
