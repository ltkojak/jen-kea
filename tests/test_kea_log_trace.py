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


# ── v5.68.0-beta.9 (Q144): attribution by what the log showed BEFORE the event ───────────────────────────────────────


def _alloc(ts, mac, ip, tid, msg_id="DHCP4_LEASE_ALLOC", secs=3600):
    return _line(ts, "INFO", msg_id, f"{_label(mac, tid)}: lease {ip} has been allocated for {secs} seconds")


def _ddns_fail(ts, ip, tid=None):
    label = f"[hwtype=1 {MAC}], tid=0x{tid}: " if tid else ""
    return _line(
        ts,
        "ERROR",
        "DHCP4_DDNS_REQUEST_SEND_FAILED",
        f"{label}failed sending a request to kea-dhcp-ddns, error: connection refused, ncr: {{ ip-address : {ip} }}",
        "ddns4-logger",
    )


class TestADdnsFailureIsBlamedOnTheNearestPrecedingAllocation:
    def test_a_allocates_a_fails_b_reuses_the_failure_stays_with_a(self):
        lines = [
            _alloc("10:00:00.100", MAC, "10.0.1.55", "1"),
            _ddns_fail("10:00:00.200", "10.0.1.55"),
            _alloc("10:30:00.100", OTHER_MAC, "10.0.1.55", "2"),
        ]
        (event,) = klt.problem_events(lines)
        assert event["kind"] == "ddns-failed" and event["mac"] == MAC and event["ip"] == "10.0.1.55"

    def test_the_newest_allocation_before_the_failure_wins_not_the_newest_in_the_tail(self):
        lines = [
            _alloc("10:00:00.100", MAC, "10.0.1.55", "1"),
            _alloc("10:10:00.100", OTHER_MAC, "10.0.1.55", "2"),
            _ddns_fail("10:10:00.200", "10.0.1.55"),
            _alloc("10:20:00.100", MAC, "10.0.1.55", "3"),
        ]
        (event,) = klt.problem_events(lines)
        assert event["mac"] == OTHER_MAC

    def test_a_failure_before_any_allocation_in_the_tail_is_dropped_not_given_to_a_later_holder(self):
        lines = [_ddns_fail("10:00:00.200", "10.0.1.55"), _alloc("10:30:00.100", OTHER_MAC, "10.0.1.55", "2")]
        assert klt.problem_events(lines) == []

    def test_a_failure_that_names_a_transaction_prefers_the_allocation_in_that_transaction(self):
        lines = [
            _alloc("10:00:00.100", MAC, "10.0.1.55", "1"),
            _alloc("10:00:00.150", OTHER_MAC, "10.0.1.55", "2"),
            _ddns_fail("10:00:00.200", "10.0.1.55", tid="1"),
        ]
        (event,) = klt.problem_events(lines)
        assert event["mac"] == MAC, "the failure's own transaction, though another client's allocation is nearer"

    def test_a_transaction_that_matches_nothing_falls_back_to_the_nearest_preceding(self):
        lines = [_alloc("10:00:00.100", MAC, "10.0.1.55", "1"), _ddns_fail("10:00:00.200", "10.0.1.55", tid="9")]
        assert klt.problem_events(lines)[0]["mac"] == MAC


class TestTheSubnetKeaSelectedForTheTransaction:
    def _selected(self, ts, mac, tid, subnet):
        return _line(
            ts,
            "DEBUG",
            "DHCP4_SUBNET_SELECTED",
            f"{_label(mac, tid)}: the subnet with ID {subnet} was selected for client assignments",
            "packets",
        )

    def _nak_send(self, ts, mac, tid):
        return _line(
            ts,
            "INFO",
            "DHCP4_PACKET_SEND",
            f"{_label(mac, tid)}: trying to send packet DHCPNAK (type 6) from 10.0.0.1:67 to 10.0.0.2:67 on interface eth0",
            "packets",
        )

    def test_a_nak_carries_the_subnet_selected_in_its_own_transaction(self):
        lines = [self._selected("10:00:00.100", MAC, "5", 2), self._nak_send("10:00:00.200", MAC, "5")]
        (event,) = klt.problem_events(lines)
        assert event["kind"] == "nak" and event["subnet_id"] == 2

    def test_no_subnet_line_means_no_subnet_never_a_guess(self):
        (event,) = klt.problem_events([self._nak_send("10:00:00.200", MAC, "5")])
        assert event["subnet_id"] is None

    def test_another_clients_or_another_transactions_selection_is_not_borrowed(self):
        lines = [
            self._selected("10:00:00.100", OTHER_MAC, "5", 2),
            self._selected("10:00:00.110", MAC, "6", 3),
            self._nak_send("10:00:00.200", MAC, "5"),
        ]
        assert klt.problem_events(lines)[0]["subnet_id"] is None

    def test_a_selection_from_long_before_is_a_different_exchange(self):
        lines = [self._selected("10:00:00.100", MAC, "5", 2), self._nak_send("10:05:00.200", MAC, "5")]
        assert klt.problem_events(lines)[0]["subnet_id"] is None, (
            "tids are the client's xid and repeat; a minute is the limit"
        )

    def test_the_two_lines_of_one_nak_keep_the_subnet(self):
        lines = [
            self._selected("10:00:00.100", MAC, "5", 2),
            _line(
                "10:00:00.150",
                "DEBUG",
                "DHCP4_PACKET_NAK_0004",
                f"{_label(MAC, '5')}: failed to grant a lease, client sent ciaddr 0.0.0.0, requested-ip-address 10.0.0.9",
                "bad-packets",
            ),
            self._nak_send("10:00:00.200", MAC, "5"),
        ]
        (event,) = klt.problem_events(lines)
        assert event["subnet_id"] == 2 and event["ip"] == "10.0.0.9"


class TestAllocationsAndTheNewestLine:
    def test_allocation_and_reuse_lines_come_back_in_order_with_their_seconds(self):
        lines = [
            _alloc("10:00:00.100", MAC, "10.0.1.55", "1"),
            _alloc("10:00:01.100", OTHER_MAC, "10.0.1.56", "2", msg_id="DHCP4_LEASE_REUSE", secs=600),
            _line("10:00:02.000", "INFO", "DHCP4_LEASE_OFFER", f"{_label(MAC)}: lease 10.0.1.57 will be offered"),
        ]
        got = klt.allocations(lines)
        assert [(a["ip"], a["seconds"]) for a in got] == [("10.0.1.55", 3600), ("10.0.1.56", 600)]
        assert got[0]["ts"] < got[1]["ts"]

    def test_the_newest_timestamp_of_any_dhcp4_line(self):
        lines = [
            _alloc("10:00:00.100", MAC, "10.0.1.55", "1"),
            "not a log line",
            _alloc("10:07:00.000", MAC, "10.0.1.56", "2"),
        ]
        assert klt.newest_ts(lines).strftime("%H:%M:%S") == "10:07:00" and klt.newest_ts(["nothing"]) is None


class TestLogPathForIsTheLoggersOwnFile:
    """v5.69.0-beta.6 (Q175): where kea-dhcp4 writes its log is ONE definition, and every reader of that log asks it - the Problems sweep read the configured path for 1447
    sweeps of a host whose logger wrote to stdout, while the investigation arm already asked the daemon's own logger config."""

    def test_the_loggers_first_file_output_wins(self):
        cfg = {
            "Dhcp4": {
                "loggers": [
                    {
                        "name": "kea-dhcp4",
                        "output-options": [{"output": "stdout"}, {"output": "/var/log/kea/dhcp4.log"}],
                    }
                ]
            }
        }
        assert klt.log_path_for(cfg) == "/var/log/kea/dhcp4.log"

    def test_stdout_alone_falls_back_to_the_configured_path(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "/var/log/kea/kea-dhcp4.log")
        cfg = {
            "Dhcp4": {
                "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout", "pattern": "%-5p %m\n"}]}]
            }
        }
        assert klt.log_path_for(cfg) == "/var/log/kea/kea-dhcp4.log"

    def test_a_file_outside_var_log_is_not_offered(self):
        from jen import extensions

        cfg = {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "/tmp/kea.log"}]}]}}
        assert klt.log_path_for(cfg) in ("", extensions.DHCP4_LOG)

    def test_no_config_is_the_configured_path(self):
        from jen import extensions

        assert klt.log_path_for(None) == extensions.DHCP4_LOG

    def test_a_file_the_host_would_refuse_is_skipped_for_the_next_one_that_it_would_read(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "")
        cfg = {
            "Dhcp4": {
                "loggers": [
                    {
                        "name": "kea-dhcp4",
                        "output-options": [{"output": "/tmp/kea.log"}, {"output": "/var/log/kea/kea-dhcp4.log"}],
                    }
                ]
            }
        }
        assert klt.log_path_for(cfg) == "/var/log/kea/kea-dhcp4.log"

    def test_another_loggers_file_is_not_the_dhcp4_log(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "")
        cfg = {
            "Dhcp4": {"loggers": [{"name": "kea-dhcp4.dhcpsrv", "output-options": [{"output": "/var/log/kea/x.log"}]}]}
        }
        assert klt.log_path_for(cfg) == ""

    def test_a_configured_path_the_host_would_refuse_is_nothing(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "/srv/kea/kea.log")
        assert klt.log_path_for(None) == ""


class TestNothingElseReadsTheConfiguredLogPath:
    """The whole-tree guard of the definition (Q175): a second reader of `DHCP4_LOG` is the next sweep that reads the wrong file."""

    ALLOWED = {"jen/config.py", "jen/extensions.py", "jen/services/kea_log_trace.py"}

    def test_every_read_of_dhcp4_log_is_in_the_three_files(self):
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        found = []
        for path in sorted((root / "jen").rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                hit = (
                    (isinstance(node, ast.Attribute) and node.attr == "DHCP4_LOG")
                    or (isinstance(node, ast.Name) and node.id == "DHCP4_LOG")
                    or (isinstance(node, ast.Constant) and node.value == "DHCP4_LOG")
                    or (isinstance(node, ast.alias) and node.name == "DHCP4_LOG")
                )
                if hit and rel not in self.ALLOWED:
                    found.append(f"{rel}:{getattr(node, 'lineno', '?')}")
        assert not found, f"the configured log path is read outside log_path_for: {found}"

    def test_the_trace_sentence_names_the_field_not_the_file(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = [
            p.relative_to(root).as_posix()
            for p in (root / "jen").rglob("*.py")
            if "dhcp4_log_path in jen.config" in p.read_text(encoding="utf-8")
        ]
        assert not offenders, offenders
