"""
tests/test_kea_log_trace.py
────────────────────────────
v5.48.0 (Q49) — jen.services.kea_log_trace: pure, no DB. The fixture lines
use the message ids and argument order from ISC's dhcp4_messages.mes /
dhcp4_srv.cc at Kea-3.0.0 (checked, not invented): the label is
`[hwtype=1 <mac>], cid=[<cid>], tid=0x<tid>` and the body follows a `:`.
"""

from jen.services import kea_log_trace as klt

MAC = "aa:bb:cc:dd:ee:01"
OTHER_MAC = "11:22:33:44:55:66"


def _label(mac, tid="1a2b3c"):
    return f"[hwtype=1 {mac}], cid=[01:{mac}], tid=0x{tid}"


def _line(ts, level, msg_id, body, logger="lease4-logger"):
    return f"2026-09-19 {ts} {level:<5} [kea-dhcp4.{logger}/1234.140] {msg_id} {body}"


EXCHANGE = [
    _line(
        "10:00:00.100",
        "INFO",
        "DHCP4_PACKET_RECEIVED",
        f"{_label(MAC)}: DHCPDISCOVER (type 1) received from 0.0.0.0 to 255.255.255.255 on interface eth0",
        "packet4-logger",
    ),
    _line("10:00:00.105", "INFO", "DHCP4_LEASE_OFFER", f"{_label(MAC)}: lease 10.0.1.55 will be offered"),
    _line(
        "10:00:00.106",
        "INFO",
        "DHCP4_PACKET_SEND",
        f"{_label(MAC)}: trying to send packet DHCPOFFER (type 2) from 10.0.1.1:67 to 255.255.255.255:68 on interface eth0",
        "packet4-logger",
    ),
    _line(
        "10:00:00.900",
        "INFO",
        "DHCP4_PACKET_RECEIVED",
        f"{_label(MAC, '1a2b3d')}: DHCPREQUEST (type 3) received from 0.0.0.0 to 255.255.255.255 on interface eth0",
        "packet4-logger",
    ),
    _line(
        "10:00:00.905",
        "INFO",
        "DHCP4_LEASE_ALLOC",
        f"{_label(MAC, '1a2b3d')}: lease 10.0.1.55 has been allocated for 3600 seconds",
    ),
]
NAK = [
    _line(
        "10:05:00.000",
        "DEBUG",
        "DHCP4_PACKET_NAK_0002",
        f"{_label(MAC, '99')}: invalid address 10.9.9.9 requested by INIT-REBOOT",
        "bad-packets4-logger",
    ),
]
DDNS = [
    _line(
        "10:00:01.000",
        "ERROR",
        "DHCP4_DDNS_REQUEST_SEND_FAILED",
        "failed sending a request to kea-dhcp-ddns, error: connection refused,  ncr: "
        "{ change-type : 0, forward-change : yes, fqdn : host1.lan., ip-address : 10.0.1.55 }",
        "ddns4-logger",
    ),
]
NOISE = [
    _line(
        "10:00:00.200",
        "INFO",
        "DHCP4_LEASE_ALLOC",
        f"{_label(OTHER_MAC)}: lease 10.0.1.99 has been allocated for 3600 seconds",
    ),
    _line(
        "10:00:01.000",
        "ERROR",
        "DHCP4_DDNS_REQUEST_SEND_FAILED",
        "failed sending a request to kea-dhcp-ddns, error: refused,  ncr: { ip-address : 10.0.1.99 }",
        "ddns4-logger",
    ),
    "not a kea line at all",
    "",
]


class TestParseLines:
    def test_full_exchange_is_parsed_in_order(self):
        events = klt.parse_lines(NOISE + EXCHANGE, MAC)
        assert [e["id"] for e in events] == [
            "DHCP4_PACKET_RECEIVED",
            "DHCP4_LEASE_OFFER",
            "DHCP4_PACKET_SEND",
            "DHCP4_PACKET_RECEIVED",
            "DHCP4_LEASE_ALLOC",
        ]
        assert events[1]["summary"] == "offered 10.0.1.55"
        assert events[1]["ip"] == "10.0.1.55"
        assert events[0]["summary"] == "DHCPDISCOVER received from 0.0.0.0"
        assert events[4]["summary"] == "allocated 10.0.1.55 for 3600 s"

    def test_other_clients_lines_are_excluded(self):
        events = klt.parse_lines(NOISE + EXCHANGE, MAC)
        assert all(OTHER_MAC not in e["raw"] for e in events)
        assert all(e["ip"] != "10.0.1.99" for e in events)

    def test_mac_matching_ignores_case_and_separators(self):
        assert len(klt.parse_lines(EXCHANGE, "AA-BB-CC-DD-EE-01")) == 5

    def test_invalid_mac_and_no_client_id_matches_nothing(self):
        assert klt.parse_lines(EXCHANGE, "not-a-mac") == []
        assert klt.parse_lines(EXCHANGE, "") == []

    def test_client_id_alone_can_match(self):
        events = klt.parse_lines(EXCHANGE, "", client_id="01:aa:bb:cc:dd:ee:01")
        assert len(events) == 5

    def test_nak_is_classified_and_explained(self):
        events = klt.parse_lines(NAK, MAC)
        assert events[0]["kind"] == "nak"
        assert events[0]["level"] == "DEBUG"
        assert events[0]["ip"] == "10.9.9.9"
        assert "INIT-REBOOT address 10.9.9.9" in events[0]["summary"]

    def test_ddns_failure_attached_only_when_it_names_this_clients_ip(self):
        events = klt.parse_lines(EXCHANGE + DDNS + NOISE, MAC)
        ddns = [e for e in events if e["id"] == "DHCP4_DDNS_REQUEST_SEND_FAILED"]
        assert len(ddns) == 1
        assert "10.0.1.55" not in ddns[0]["summary"]  # plain-English, not raw ncr
        assert ddns[0]["kind"] == "problem"

    def test_ddns_failure_for_another_clients_ip_is_not_attached(self):
        events = klt.parse_lines(EXCHANGE + NOISE, MAC)
        assert not [e for e in events if e["id"] == "DHCP4_DDNS_REQUEST_SEND_FAILED"]

    def test_unknown_id_is_kept_with_raw_text_not_dropped(self):
        line = _line("10:00:00.500", "INFO", "DHCP4_SOMETHING_NEW", f"{_label(MAC)}: brand new message body")
        events = klt.parse_lines([line], MAC)
        assert events[0]["kind"] == "unknown"
        assert "brand new message body" in events[0]["summary"]

    def test_decline_release_and_reuse(self):
        lines = [
            _line(
                "10:00:00.000",
                "INFO",
                "DHCP4_DECLINE_LEASE",
                f"Received DHCPDECLINE for addr 10.0.1.55 from client {_label(MAC)}. The lease will be unavailable for 86400 seconds.",
            ),
            _line("10:00:05.000", "INFO", "DHCP4_RELEASE", f"{_label(MAC)}: address 10.0.1.55 was released properly."),
            _line(
                "10:00:10.000",
                "INFO",
                "DHCP4_LEASE_REUSE",
                f"{_label(MAC)}: lease 10.0.1.55 has been reused for 600 seconds",
            ),
        ]
        events = klt.parse_lines(lines, MAC)
        assert [e["kind"] for e in events] == ["decline", "release", "ack"]
        assert events[0]["ip"] == "10.0.1.55"

    def test_every_listed_id_exists_in_the_table_with_a_real_level(self):
        for msg_id, (level, kind) in klt.MESSAGES.items():
            assert msg_id.startswith("DHCP4_")
            assert level in ("DEBUG", "INFO", "WARN", "ERROR")
            assert kind


class TestGroupExchanges:
    def test_one_exchange_ends_in_ack(self):
        groups = klt.group_exchanges(klt.parse_lines(EXCHANGE, MAC))
        assert len(groups) == 1
        assert groups[0]["outcome"] == "ack"
        assert groups[0]["ip"] == "10.0.1.55"
        assert len(groups[0]["events"]) == 5

    def test_gap_of_two_seconds_or_more_splits(self):
        events = klt.parse_lines(EXCHANGE + NAK, MAC)
        groups = klt.group_exchanges(events)
        assert [g["outcome"] for g in groups] == ["ack", "nak"]

    def test_nak_outranks_ack_within_one_group(self):
        events = klt.parse_lines(EXCHANGE[:2] + NAK, MAC)
        groups = klt.group_exchanges(events, gap=1000)
        assert len(groups) == 1
        assert groups[0]["outcome"] == "nak"

    def test_empty_is_empty(self):
        assert klt.group_exchanges([]) == []


class TestVisibilityNote:
    def test_info_only_says_what_it_cannot_see(self):
        note = klt.visibility_note(klt.parse_lines(EXCHANGE, MAC), 900)
        assert "900" in note
        assert "DEBUG" in note and "INFO" in note

    def test_debug_lines_seen_says_so(self):
        note = klt.visibility_note(klt.parse_lines(NAK, MAC), 10)
        assert "logs at DEBUG" in note
