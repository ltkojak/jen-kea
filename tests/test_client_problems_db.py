"""
tests/test_client_problems_db.py
──────────────────────────────────
v5.68.0-beta.5 (Q140) — the Problems inbox sweep against the real test database: the upsert per (server, kind, client, address), a line
read by two sweeps counted once, the alert threshold and its once-a-day rule, resolution after 24 hours and on recurrence, 30-day
pruning, a server that cannot be read, and the two kinds read from the lease database (a declined lease; a reservation held by a
different client). The log is a stand-in for `kea_host.tail_log` (the helper's tail-log needs a Kea host) and the alert sender
records instead of sending; everything else - the tables, the watermark in `settings`, the SQL - is real.
"""

from datetime import datetime, timedelta

import pytest

from jen import extensions
from jen.services import alerts, kea_host
from jen.services import client_problems as cp

MAC = "aa:bb:cc:dd:ee:41"
MAC_HEX = "AABBCCDDEE41"
MAC2 = "aa:bb:cc:dd:ee:42"
MAC2_HEX = "AABBCCDDEE42"
NOW = datetime(2026, 10, 4, 12, 0, 0)

SERVER_A = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
SERVER_B = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.6"}


def _line(second, msg_id, body, mac=MAC, tid=None, level="INFO", minute=0, hour=11, day=4):
    tid = tid or f"0x{second:x}{minute:x}"
    return (
        f"2026-10-{day:02d} {hour:02d}:{minute:02d}:{second:02d}.100 {level:<5} [kea-dhcp4.test/1.1] {msg_id} "
        f"[hwtype=1 {mac}], cid=[01:{mac}], tid={tid}: {body}"
    )


def nak(second, mac=MAC, minute=0, hour=11, day=4):
    return _line(
        second,
        "DHCP4_PACKET_SEND",
        "trying to send packet DHCPNAK (type 6) from a:67 to b:67",
        mac,
        minute=minute,
        hour=hour,
        day=day,
    )


def prime(logs, server_id=1):
    """A server's FIRST read sets its watermark and never alerts (a backlog is not news). Do that read with one ordinary line, so the
    next sweep - the one under test - is a normal one."""
    logs[server_id] = [_line(1, "DHCP4_LEASE_OFFER", "lease 10.45.0.9 will be offered", hour=10)]
    cp.sweep(NOW - timedelta(minutes=10), servers=[SERVER_A if server_id == 1 else SERVER_B])


def decline(second, ip="10.45.0.9", mac=MAC, minute=0, hour=11):
    return _line(
        second,
        "DHCP4_DECLINE_LEASE",
        f"Received DHCPDECLINE for addr {ip} from client x.",
        mac,
        minute=minute,
        hour=hour,
    )


@pytest.fixture
def stack(db, monkeypatch):
    """Two SSH servers whose logs the test sets, a recorded alert sender, a subnet map, and a clean table."""
    logs = {1: [], 2: []}
    calls = {"tail": [], "alerts": []}

    def fake_tail(server, path, lines=200, timeout=None, helper_only=False):
        calls["tail"].append((server["id"], path, lines, helper_only))
        value = logs[server["id"]]
        if isinstance(value, dict):
            return value
        return {"ok": True, "code": "ok", "lines": list(value), "via": "helper"}

    monkeypatch.setattr(kea_host, "tail_log", fake_tail)
    monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(SERVER_A), dict(SERVER_B)])
    monkeypatch.setattr(
        extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.45.0.0/24"}, 2: {"name": "B", "cidr": "10.46.0.0/24"}}
    )
    monkeypatch.setattr(extensions, "CLIENT_PROBLEM_THRESHOLD", 3)
    monkeypatch.setattr(
        alerts,
        "send_alert",
        lambda alert_type, log_result=True, subnet_id=None, **kw: (
            calls["alerts"].append((alert_type, subnet_id, kw)) or [("telegram", True, "")]
        ),
    )
    _clean(db)
    yield logs, calls
    _clean(db)


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM client_problems")
        cur.execute(
            "DELETE FROM settings WHERE setting_key LIKE 'client_problems_wm:%' OR setting_key LIKE 'client_problems_clock:%' "
            "OR setting_key = 'client_problems_dropped'"
        )
        cur.execute(
            "DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s) OR address IN "
            "(INET_ATON('10.45.0.60'), INET_ATON('10.45.0.61'), INET_ATON('10.45.0.70'))",
            (MAC_HEX, MAC2_HEX),
        )
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN (%s, %s)", (MAC_HEX, MAC2_HEX))
    db.commit()


def rows(db, where="1=1", params=()):
    with db.cursor() as cur:
        cur.execute(f"SELECT * FROM client_problems WHERE {where} ORDER BY kind, mac, ip", params)  # nosec B608 - test helper
        return cur.fetchall()


class TestTheLogKinds:
    def test_a_sweep_upserts_one_row_per_kind_client_and_address(self, db, stack):
        logs, calls = stack
        logs[1] = [nak(1), nak(2), decline(3), decline(4, ip="10.45.0.10"), nak(5, mac=MAC2)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["servers"] == 1 and out["events"] == 5 and out["errors"] == []
        got = {(r["kind"], r["mac"], r["ip"]): r["count"] for r in rows(db, "server_id=1")}
        assert got == {
            ("nak", MAC, ""): 2,
            ("decline", MAC, "10.45.0.9"): 1,
            ("decline", MAC, "10.45.0.10"): 1,
            ("nak", MAC2, ""): 1,
        }
        assert calls["tail"] == [(1, extensions.DHCP4_LOG, 1000, True)], "the helper's bounded tail, helper only"

    def test_a_row_carries_the_subnet_its_address_is_in(self, db, stack):
        logs, _c = stack
        logs[1] = [decline(1, ip="10.46.0.7")]
        cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] == 2

    def test_a_row_with_no_address_is_not_placed_by_where_its_mac_is_now(self, db, stack):
        # v5.68.0-beta.9 (Q144): it used to take the client's CURRENT subnet - which showed a NAK from subnet B to a user of subnet A
        logs, _c = stack
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.60'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (MAC_HEX,),
            )
        db.commit()
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] is None

    def test_a_row_whose_client_is_nowhere_has_no_subnet_and_is_for_unrestricted_callers_only(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1, mac="aa:bb:cc:dd:ee:99")]
        cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] is None

    def test_the_same_lines_read_by_the_next_sweep_add_nothing(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1), nak(2)]
        cp.sweep(NOW, servers=[SERVER_A])
        out = cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        assert out["events"] == 0 and rows(db)[0]["count"] == 2

    def test_new_lines_after_the_watermark_are_added_and_the_log_rotating_loses_nothing(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1), nak(2)]
        cp.sweep(NOW, servers=[SERVER_A])
        logs[1] = [nak(1, minute=5)]  # a rotated log: the first two lines are gone, one newer line is there
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        assert rows(db)[0]["count"] == 3

    def test_the_watermark_is_kept_in_settings_per_server(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1)]
        logs[2] = [nak(1, minute=3)]
        cp.sweep(NOW)
        with db.cursor() as cur:
            cur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE 'client_problems_wm:%' ORDER BY 1")
            assert [r["setting_key"] for r in cur.fetchall()] == ["client_problems_wm:1", "client_problems_wm:2"]

    def test_two_servers_are_two_rows(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1)]
        logs[2] = [nak(1)]
        cp.sweep(NOW)
        assert sorted(r["server_id"] for r in rows(db)) == [1, 2]

    def test_a_server_that_cannot_be_read_records_nothing_and_the_next_one_still_runs(self, db, stack):
        logs, _c = stack
        logs[1] = {"ok": False, "code": "error", "detail": "ssh refused"}
        logs[2] = [nak(1)]
        out = cp.sweep(NOW)
        assert out["servers"] == 1 and len(out["errors"]) == 1 and "kea-a" in out["errors"][0]
        assert [r["server_id"] for r in rows(db)] == [2]

    def test_a_server_with_no_helper_is_skipped_not_guessed_at(self, db, stack):
        logs, _c = stack
        logs[1] = {"ok": False, "code": "no-helper", "detail": "the Kea host helper is not installed"}
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["servers"] == 0 and "no-helper" in out["errors"][0] and not rows(db)

    def test_a_server_without_ssh_is_not_a_log_source(self, db, stack, monkeypatch):
        logs, calls = stack
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": ""}])
        assert cp.sweep(NOW)["servers"] == 0 and calls["tail"] == []

    def test_the_stored_detail_is_a_sentence_not_raw_log_text(self, db, stack):
        logs, _c = stack
        logs[1] = [decline(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        detail = rows(db)[0]["detail"]
        assert "10.45.0.9" in detail and "hwtype" not in detail and "tid=" not in detail


class TestResolution:
    def test_a_kind_that_has_not_recurred_for_a_day_is_resolved_and_leaves_the_inbox(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        out = cp.sweep(NOW + timedelta(hours=25), servers=[SERVER_A])
        assert out["resolved"] == 1
        assert rows(db)[0]["resolved_at"] is not None and cp.fetch_open([], []) == []

    def test_inside_the_day_it_stays_open(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert cp.sweep(NOW + timedelta(hours=23), servers=[SERVER_A])["resolved"] == 0

    def test_a_recurrence_reopens_it_as_a_fresh_episode(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1), nak(2)]
        cp.sweep(NOW, servers=[SERVER_A])
        cp.sweep(NOW + timedelta(hours=25), servers=[SERVER_A])
        logs[1] = [nak(1, minute=30, hour=13, day=5)]
        cp.sweep(NOW + timedelta(hours=26), servers=[SERVER_A])
        row = rows(db)[0]
        assert row["resolved_at"] is None and row["count"] == 1, "a new episode: the old count does not carry over"
        assert row["first_seen"] == datetime(2026, 10, 5, 13, 30, 1)

    def test_rows_not_seen_for_thirty_days_are_pruned_and_younger_ones_kept(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1), nak(2, mac=MAC2)]
        cp.sweep(NOW, servers=[SERVER_A])
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET last_seen=%s WHERE mac=%s", (NOW - timedelta(days=31), MAC))
            cur.execute(
                "UPDATE client_problems SET last_seen=%s, resolved_at=%s WHERE mac=%s",
                (NOW - timedelta(days=10), NOW, MAC2),
            )
        db.commit()
        assert cp.prune(NOW) == 1
        assert [r["mac"] for r in rows(db)] == [MAC2]


class TestTheAlert:
    def test_three_in_an_hour_is_one_alert_carrying_the_subnet(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(1), decline(2), decline(3)]  # a decline names the address, and the address names the subnet
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["alerts"] == 1
        ((alert_type, subnet_id, kw),) = calls["alerts"]
        assert alert_type == "client_problems" and subnet_id == 1
        assert kw["mac"] == MAC and kw["kind"] == "Declined an address" and kw["count"] == 3
        assert kw["investigate"] == f"/client?q={MAC}" and kw["server"] == "kea-a"

    def test_a_client_with_no_attributable_subnet_alerts_with_none_which_a_scoped_channel_refuses(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2), nak(3)]
        assert cp.sweep(NOW, servers=[SERVER_A])["alerts"] == 1
        assert calls["alerts"][0][1] is None
        assert alerts.channel_allows_subnet({"subnet_scope": "[1]"}, None, scoped=True) is False

    def test_two_is_not_enough(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2)]
        assert cp.sweep(NOW, servers=[SERVER_A])["alerts"] == 0 and calls["alerts"] == []

    def test_a_chattering_client_is_one_alert_not_sixty(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(i) for i in range(1, 11)]
        cp.sweep(NOW, servers=[SERVER_A])
        logs[1] = [nak(i) for i in range(1, 11)] + [nak(i, minute=1) for i in range(1, 51)]
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        assert len(calls["alerts"]) == 1

    def test_it_alerts_again_after_a_day(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2), nak(3)]
        cp.sweep(NOW, servers=[SERVER_A])
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET alerted_at=%s", (NOW - timedelta(hours=25),))
        db.commit()
        # three more inside the hour that ends at the next sweep (the window is now, not the newest line)
        logs[1] = [nak(1), nak(2), nak(3), *[nak(i, minute=58) for i in (1, 2, 3)]]
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        assert len(calls["alerts"]) == 2

    def test_a_different_kind_for_the_same_client_is_its_own_alert(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2), nak(3), decline(4), decline(5), decline(6)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert sorted(c[2]["kind"] for c in calls["alerts"]) == ["Declined an address", "NAK"]

    def test_the_threshold_key_is_honoured(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        monkeypatch.setattr(extensions, "CLIENT_PROBLEM_THRESHOLD", 2)
        logs[1] = [nak(1), nak(2)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert len(calls["alerts"]) == 1

    def test_a_failing_sender_does_not_stop_the_sweep_and_is_not_marked_sent(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)

        def boom(*a, **k):
            raise RuntimeError("telegram is down")

        monkeypatch.setattr(alerts, "send_alert", boom)
        logs[1] = [nak(1), nak(2), nak(3)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["errors"] == [] and rows(db)[0]["alerted_at"] is None and rows(db)[0]["alert_attempted_at"] == NOW

    def test_the_state_kinds_never_alert(self, db, stack):
        _l, calls = stack
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.61'), NULL, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 1)"
            )
        db.commit()
        for i in range(5):
            cp.sweep(NOW + timedelta(minutes=5 * i), servers=[])
        assert calls["alerts"] == []


# ── v5.68.0-beta.9 (Q144): scope by the event, honest times, a delivered alert is one that landed ────────────────────────


def alloc(second, ip, mac=MAC, hour=11, minute=0, secs=3600):
    return _line(
        second, "DHCP4_LEASE_ALLOC", f"lease {ip} has been allocated for {secs} seconds", mac, hour=hour, minute=minute
    )


def ddns_failed(second, ip, hour=11, minute=0):
    return (
        f"2026-10-04 {hour:02d}:{minute:02d}:{second:02d}.100 ERROR [kea-dhcp4.ddns4-logger/1.1] DHCP4_DDNS_REQUEST_SEND_FAILED "
        f"failed sending a request to kea-dhcp-ddns, error: connection refused, ncr: {{ ip-address : {ip} }}"
    )


class TestAnEventIsScopedByItsOwnEvidence:
    def test_a_nak_for_a_client_now_in_another_subnet_is_not_shown_to_that_subnets_users(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2), nak(3)]  # NAKed in B's world: the lines name no address and no subnet
        with db.cursor() as cur:  # ...and the client has since moved to A, where it holds a lease
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.60'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (MAC_HEX,),
            )
        db.commit()
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] is None, "the row is NOT placed by where the client is now"
        assert cp.widget([1], False, NOW)["total"] == 0, "the A-scoped user sees nothing"
        assert cp.widget([], True, NOW)["total"] == 1, "an unrestricted caller sees it"
        assert cp.fetch_open(["p.subnet_id IN (%s)"], [1]) == []
        # and the alert is about a client Jen could not place: it carries no subnet, which the scoped-alert rule fails closed on
        assert out["alerts"] == 1 and calls["alerts"][0][1] is None

    def test_the_events_own_address_still_places_it(self, db, stack):
        logs, _c = stack
        logs[1] = [decline(1, ip="10.46.0.7")]
        cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] == 2

    def test_a_subnet_kea_selected_for_the_very_transaction_places_a_nak_with_no_address(self, db, stack):
        logs, _c = stack
        logs[1] = [
            _line(
                1,
                "DHCP4_SUBNET_SELECTED",
                "the subnet with ID 2 was selected for client assignments",
                tid="0x77",
                level="DEBUG",
            ),
            _line(1, "DHCP4_PACKET_SEND", "trying to send packet DHCPNAK (type 6) from a:67 to b:67", tid="0x77"),
        ]
        cp.sweep(NOW, servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] == 2

    def test_a_row_keeps_its_subnet_as_events_for_the_same_address_arrive(self, db, stack):
        logs, _c = stack
        logs[1] = [decline(1, ip="10.45.0.9")]
        cp.sweep(NOW - timedelta(minutes=5), servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] == 1
        db.commit()  # end the snapshot of the read above
        logs[1] = [decline(1, ip="10.45.0.9"), decline(2, ip="10.45.0.9", minute=1)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        assert rows(db)[0]["subnet_id"] == 1 and rows(db)[0]["count"] == 2


class TestADdnsFailureStaysWithTheClientThatHadTheAddress:
    def test_a_allocates_a_fails_b_reuses_the_address(self, db, stack):
        logs, _c = stack
        logs[1] = [
            alloc(1, "10.45.0.9", MAC),
            ddns_failed(2, "10.45.0.9"),
            alloc(5, "10.45.0.9", MAC2, minute=30),
        ]
        cp.sweep(NOW, servers=[SERVER_A])
        (row,) = rows(db, "kind='ddns-failed'")
        assert row["mac"] == MAC and row["ip"] == "10.45.0.9" and row["subnet_id"] == 1


class TestTheEventsOwnTimesAreStored:
    def test_a_row_carries_the_time_of_its_events_not_the_time_of_the_sweep(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1), nak(9)]
        cp.sweep(NOW, servers=[SERVER_A])
        row = rows(db)[0]
        assert row["first_seen"] == datetime(2026, 10, 4, 11, 0, 1) and row["last_seen"] == datetime(
            2026, 10, 4, 11, 0, 9
        )

    def test_a_log_in_a_timezone_west_of_utc_is_converted_with_the_offset_the_lease_records_show(self, db, stack):
        import calendar

        logs, _c = stack
        expire_utc = calendar.timegm((NOW + timedelta(hours=1)).timetuple())  # allocated 12:00 UTC for an hour
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.70'), UNHEX(%s), 3600, FROM_UNIXTIME(%s), 1, 0)",
                (MAC2_HEX, expire_utc),
            )
        db.commit()
        # the Kea host runs on UTC-5: its log says 07:00 for what was 12:00 UTC, and 06:59:50 for a NAK ten seconds before
        logs[1] = [alloc(0, "10.45.0.70", MAC2, hour=7), nak(50, minute=59, hour=6)]
        cp.sweep(NOW, servers=[SERVER_A])
        row = rows(db, "kind='nak'")[0]
        assert row["first_seen"] == datetime(2026, 10, 4, 11, 59, 50), "06:59:50 local, plus five hours"
        with db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key='client_problems_clock:1'")
            assert float(cur.fetchone()["setting_value"]) == -18000.0
        assert "UTC-5" in " ".join(n["text"] for n in cp.clock_notes() if n["name"] == "kea-a")

    def test_a_server_that_has_shown_no_lease_evidence_is_read_as_utc_and_the_page_says_so(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert "assumed UTC" in " ".join(n["text"] for n in cp.clock_notes() if n["name"] == "kea-a")

    def test_an_event_older_than_a_day_is_not_ingested(self, db, stack):
        logs, _c = stack
        logs[1] = [nak(1, hour=9)]
        out = cp.sweep(NOW + timedelta(hours=40), servers=[SERVER_A])
        assert out["events"] == 0 and not rows(db)


class TestAStaleBacklogIsNotNews:
    def test_three_naks_from_six_hours_ago_on_a_servers_first_sweep_are_recorded_with_their_own_time_and_never_alert(
        self, db, stack
    ):
        logs, calls = stack
        logs[1] = [nak(1, hour=6), nak(2, hour=6), nak(3, hour=6)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["events"] == 3 and out["alerts"] == 0 and out["alerts_attempted"] == 0 and calls["alerts"] == []
        row = rows(db)[0]
        assert row["count"] == 3 and row["first_seen"] == datetime(2026, 10, 4, 6, 0, 1)

    def test_the_second_sweep_with_one_new_nak_is_still_not_an_alert_the_window_is_now(self, db, stack):
        logs, calls = stack
        logs[1] = [nak(1, hour=6), nak(2, hour=6), nak(3, hour=6)]
        cp.sweep(NOW, servers=[SERVER_A])
        logs[1] = [nak(1, hour=6), nak(2, hour=6), nak(3, hour=6), nak(4, minute=55)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["events"] == 1 and out["alerts"] == 0 and calls["alerts"] == [], (
            "one NAK in the last hour is not three"
        )

    def test_a_first_read_that_found_nothing_but_ordinary_lines_still_sets_the_watermark(self, db, stack):
        logs, calls = stack
        prime(logs)
        with db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key='client_problems_wm:1'")
            assert cur.fetchone() is not None
        logs[1] = [nak(1), nak(2), nak(3)]
        assert cp.sweep(NOW, servers=[SERVER_A])["alerts_attempted"] == 1


class TestDeliveredIsNotAttempted:
    def _three(self, logs):
        # late in the hour, so that they are still inside the alert window half an hour later
        logs[1] = [decline(1, minute=40), decline(2, minute=40), decline(3, minute=40)]

    def test_a_failed_delivery_is_not_marked_sent_and_is_retried_every_half_hour_not_every_sweep(
        self, db, stack, monkeypatch
    ):
        logs, calls = stack
        prime(logs)
        monkeypatch.setattr(
            alerts,
            "send_alert",
            lambda alert_type, log_result=True, subnet_id=None, **kw: (
                calls["alerts"].append((alert_type, subnet_id, kw)) or [("telegram", False, "429")]
            ),
        )
        self._three(logs)
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert (out["alerts"], out["alerts_attempted"], out["alerts_failed"]) == (0, 1, 1)
        row = rows(db)[0]
        assert row["alerted_at"] is None and row["alert_attempted_at"] == NOW
        assert cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])["alerts_attempted"] == 0, (
            "bounded: not every sweep"
        )
        assert cp.sweep(NOW + timedelta(minutes=29), servers=[SERVER_A])["alerts_attempted"] == 0
        db.commit()  # the test's connection holds a snapshot from the read above; end it so the next read sees the sweep's writes
        # half an hour after the try it goes again - with no new trouble from the client - and this time it lands
        monkeypatch.setattr(
            alerts,
            "send_alert",
            lambda alert_type, log_result=True, subnet_id=None, **kw: (
                calls["alerts"].append((alert_type, subnet_id, kw)) or [("telegram", True, "")]
            ),
        )
        out = cp.sweep(NOW + timedelta(minutes=31), servers=[SERVER_A])
        assert (out["alerts"], out["alerts_attempted"], out["alerts_failed"]) == (1, 1, 0)
        db.commit()
        assert rows(db)[0]["alerted_at"] == NOW + timedelta(minutes=31)

    def test_a_delivered_alert_is_marked_and_then_silent_for_the_day(self, db, stack):
        logs, calls = stack
        prime(logs)
        self._three(logs)
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert (out["alerts"], out["alerts_failed"]) == (1, 0) and rows(db)[0]["alerted_at"] == NOW
        logs[1] = [*logs[1], decline(4, minute=2)]
        assert cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])["alerts_attempted"] == 0

    def test_no_eligible_channel_is_not_delivery(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        monkeypatch.setattr(alerts, "send_alert", lambda *a, **k: [])
        self._three(logs)
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert (out["alerts"], out["alerts_failed"]) == (0, 1) and rows(db)[0]["alerted_at"] is None

    def test_a_sender_that_raises_is_a_failed_attempt_and_the_sweep_goes_on(self, db, stack, monkeypatch):
        logs, _c = stack
        prime(logs)

        def boom(*a, **k):
            raise RuntimeError("telegram is down")

        monkeypatch.setattr(alerts, "send_alert", boom)
        self._three(logs)
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["errors"] == [] and out["alerts_failed"] == 1 and rows(db)[0]["alerted_at"] is None


class TestTheAlertIsDecidedPerSubnet:
    """v5.68.0-beta.13 (Q148): the count that crosses the threshold, and the row the delivery is recorded on, are per (kind, client, subnet),
    None its own key, so a channel scoped to a subnet is never told a number made of rows it cannot see on the page."""

    A, B = "10.45.0.9", "10.46.0.9"  # an address in subnet 1 (A) and one in subnet 2 (B)

    def _counts(self, calls):
        return sorted((subnet, kw["count"]) for _type, subnet, kw in calls["alerts"])

    def test_two_in_b_and_one_in_a_with_a_threshold_of_three_alerts_nobody(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(1, ip=self.B), decline(2, ip=self.B), decline(3, ip=self.A)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["alerts_attempted"] == 0 and calls["alerts"] == []

    def test_three_in_a_and_two_in_b_alerts_a_with_three_never_five(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(i, ip=self.A) for i in (1, 2, 3)] + [decline(i, ip=self.B) for i in (4, 5)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["alerts"] == 1 and self._counts(calls) == [(1, 3)]

    def test_each_subnet_that_crosses_alerts_on_its_own_count(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(i, ip=self.A) for i in (1, 2, 3)] + [decline(i, ip=self.B) for i in (4, 5, 6, 7)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert self._counts(calls) == [(1, 3), (2, 4)]

    def test_a_delivery_is_recorded_on_that_subnets_rows_only(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(i, ip=self.A) for i in (1, 2, 3)] + [decline(i, ip=self.B) for i in (4, 5)]
        cp.sweep(NOW, servers=[SERVER_A])
        by_subnet = {r["subnet_id"]: r for r in rows(db)}
        assert by_subnet[1]["alerted_at"] == NOW and by_subnet[1]["qualified_count"] is None, (
            "delivered: nothing left to retry"
        )
        assert by_subnet[2]["alerted_at"] is None and by_subnet[2]["alert_attempted_at"] is None
        assert by_subnet[2]["qualified_at"] is None, "two in B never qualified"

    def test_unattributed_events_are_their_own_key_and_never_topped_up_by_attributed_ones(self, db, stack):
        logs, calls = stack
        prime(logs)
        # three NAKs that name no address (no subnet) and two declines in A: only the unattributed key crosses
        logs[1] = [nak(1), nak(2), nak(3), decline(4, ip=self.A), decline(5, ip=self.A)]
        cp.sweep(NOW, servers=[SERVER_A])
        assert self._counts(calls) == [(None, 3)]
        assert alerts.channel_allows_subnet({"subnet_scope": "[1]"}, None, scoped=True) is False

    def test_two_unattributed_and_one_attributed_is_nobody(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [nak(1), nak(2), decline(3, ip=self.A)]
        assert cp.sweep(NOW, servers=[SERVER_A])["alerts_attempted"] == 0


class TestADeliveredAlertLeavesNoPendingQualification:
    """v5.68.0-beta.14 (Q149 item 8): `qualified_at` / `qualified_count` are what a RETRY reads. A delivery used to set `alerted_at` and leave
    them behind (only the 24-hour expiry cleared them), so a delivered alert looked like one still waiting to be retried."""

    def test_delivery_sets_alerted_and_attempted_and_clears_the_qualification_on_that_subnets_rows(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [decline(i, ip="10.45.0.9") for i in (1, 2, 3)] + [decline(i, ip="10.46.0.9") for i in (4, 5)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert out["alerts"] == 1
        by = {r["subnet_id"]: r for r in rows(db)}
        assert by[1]["alerted_at"] == NOW and by[1]["alert_attempted_at"] == NOW
        assert by[1]["qualified_at"] is None and by[1]["qualified_count"] is None
        assert by[2]["alerted_at"] is None and by[2]["qualified_at"] is None, "the other subnet's row is untouched"

    def test_a_failed_delivery_keeps_the_qualification_for_the_retry(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        monkeypatch.setattr(
            alerts, "send_alert", lambda alert_type, log_result=True, subnet_id=None, **kw: [("telegram", False, "429")]
        )
        logs[1] = [decline(i, ip="10.45.0.9") for i in (1, 2, 3)]
        cp.sweep(NOW, servers=[SERVER_A])
        row = rows(db)[0]
        assert row["alerted_at"] is None and row["qualified_at"] == NOW and row["qualified_count"] == 3


class TestAFailedAlertSurvivesTheLogRotating:
    """v5.68.0-beta.13 (Q148): the retry reads the PERSISTED qualification (`qualified_at` / `qualified_count`), not the 1000-line tail, until
    the alert is delivered, the row is resolved, or the qualification is 24 hours old."""

    def _sender(self, calls, monkeypatch, ok):
        monkeypatch.setattr(
            alerts,
            "send_alert",
            lambda alert_type, log_result=True, subnet_id=None, **kw: (
                calls["alerts"].append((alert_type, subnet_id, kw)) or [("telegram", ok, "" if ok else "429")]
            ),
        )

    def test_threshold_reached_delivery_fails_the_tail_rotates_and_the_retry_still_happens(
        self, db, stack, monkeypatch
    ):
        logs, calls = stack
        prime(logs)
        self._sender(calls, monkeypatch, False)
        logs[1] = [decline(1, minute=40), decline(2, minute=40), decline(3, minute=40)]
        cp.sweep(NOW, servers=[SERVER_A])
        row = rows(db)[0]
        assert row["alerted_at"] is None and row["qualified_at"] == NOW and row["qualified_count"] == 3
        # a busy server: the next sweep's 1000 lines hold none of the qualifying ones
        logs[1] = [_line(i, "DHCP4_LEASE_OFFER", "lease 10.45.0.77 will be offered", mac=MAC2) for i in range(1, 6)]
        out = cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        assert out["alerts_attempted"] == 0, "bounded: not every sweep"
        db.commit()
        self._sender(calls, monkeypatch, True)
        out = cp.sweep(NOW + timedelta(minutes=31), servers=[SERVER_A])
        assert (out["alerts"], out["alerts_attempted"]) == (1, 1), (
            "31 minutes on, with none of the lines in the tail, it goes again"
        )
        retry = calls["alerts"][-1][2]
        assert retry["count"] == 3 and retry["at"] == NOW.strftime("%Y-%m-%d %H:%M"), (
            "the persisted count and time, not the tail's"
        )
        db.commit()
        assert rows(db)[0]["alerted_at"] == NOW + timedelta(minutes=31)

    def test_a_resolved_row_is_not_retried(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        self._sender(calls, monkeypatch, False)
        logs[1] = [decline(1, minute=40), decline(2, minute=40), decline(3, minute=40)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET resolved_at=%s", (NOW + timedelta(minutes=1),))
        db.commit()
        logs[1] = []
        assert cp.sweep(NOW + timedelta(minutes=31), servers=[SERVER_A])["alerts_attempted"] == 0

    def test_after_24_hours_the_qualification_is_cleared_and_must_be_earned_again(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        self._sender(calls, monkeypatch, False)
        logs[1] = [decline(1, minute=40), decline(2, minute=40), decline(3, minute=40)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        logs[1] = []
        out = cp.sweep(NOW + timedelta(hours=24, minutes=1), servers=[SERVER_A])
        assert out["alerts_attempted"] == 0, "a day old and undelivered: dropped, not retried for ever"
        db.commit()
        assert rows(db)[0]["qualified_at"] is None and rows(db)[0]["qualified_count"] is None

    def test_a_recurrence_after_resolution_starts_a_fresh_qualification(self, db, stack, monkeypatch):
        logs, calls = stack
        prime(logs)
        self._sender(calls, monkeypatch, False)
        logs[1] = [decline(1, minute=40), decline(2, minute=40), decline(3, minute=40)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET resolved_at=%s", (NOW + timedelta(minutes=1),))
        db.commit()
        logs[1] = [decline(1, hour=13, minute=50), decline(2, hour=13, minute=50)]
        cp.sweep(NOW + timedelta(hours=2), servers=[SERVER_A])
        db.commit()
        row = rows(db)[0]
        assert row["resolved_at"] is None and row["qualified_at"] is None and row["alert_attempted_at"] is None


def nak_in(subnet, second, minute=0, mac=MAC):
    """A NAK that names no address, in the transaction Kea selected `subnet` for (a DEBUG line) - the only way such a row is placed."""
    tid = f"0x{subnet:x}{second:02x}{minute:02x}"
    return [
        _line(
            second,
            "DHCP4_SUBNET_SELECTED",
            f"the subnet with ID {subnet} was selected for client assignments",
            mac=mac,
            tid=tid,
            level="DEBUG",
            minute=minute,
        ),
        _line(
            second,
            "DHCP4_PACKET_SEND",
            "trying to send packet DHCPNAK (type 6) from a:67 to b:67",
            mac=mac,
            tid=tid,
            minute=minute,
        ),
    ]


class TestARowsIdentityIncludesItsSubnet:
    """v5.68.0-beta.14 (Q149): migration 33 makes `scope_key` (= COALESCE(subnet_id, -1)) part of the unique key. Before it, the same client,
    kind and EMPTY address in B, B and A were ONE row whose subnet was reassigned to the newest event's while its count, times and alert
    state stayed - so B's history and a qualification earned in B ended up on an A row."""

    def _by_subnet(self, db):
        db.commit()
        return {r["subnet_id"]: r for r in rows(db)}

    def _sender(self, calls, monkeypatch, ok):
        monkeypatch.setattr(
            alerts,
            "send_alert",
            lambda alert_type, log_result=True, subnet_id=None, **kw: (
                calls["alerts"].append((alert_type, subnet_id, kw)) or [("telegram", ok, "" if ok else "429")]
            ),
        )

    def test_b_b_a_with_no_address_is_a_b_row_and_an_a_row_and_neither_qualifies_at_three(self, db, stack):
        logs, calls = stack
        prime(logs)
        logs[1] = [*nak_in(2, 1), *nak_in(2, 2), *nak_in(1, 3)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        by = self._by_subnet(db)
        assert sorted(by) == [1, 2] and by[2]["count"] == 2 and by[1]["count"] == 1
        assert by[1]["mac"] == by[2]["mac"] == MAC and by[1]["ip"] == by[2]["ip"] == ""
        assert out["alerts_attempted"] == 0 and calls["alerts"] == [], "two in B and one in A is not three anywhere"
        assert cp.widget([1], False, NOW)["total"] == 1, "the A-scoped page sees the one row of its own subnet"
        assert [r["subnet_id"] for r in cp.fetch_open(["p.subnet_id IN (%s)"], [1])] == [1]

    def test_a_b_qualification_that_failed_delivery_is_not_carried_onto_an_a_row_nor_retried_there(
        self, db, stack, monkeypatch
    ):
        logs, calls = stack
        prime(logs)
        self._sender(calls, monkeypatch, False)
        logs[1] = [*nak_in(2, 1, minute=40), *nak_in(2, 2, minute=40), *nak_in(2, 3, minute=40)]
        cp.sweep(NOW, servers=[SERVER_A])
        b = self._by_subnet(db)[2]
        assert (
            b["qualified_at"] == NOW
            and b["qualified_count"] == 3
            and b["alert_attempted_at"] == NOW
            and b["alerted_at"] is None
        )
        # an A event arrives for the same client, kind and empty address
        logs[1] = [*logs[1], *nak_in(1, 4, minute=41)]
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        by = self._by_subnet(db)
        assert by[2]["qualified_at"] == NOW and by[2]["qualified_count"] == 3 and by[2]["count"] == 3, (
            "B keeps its own state"
        )
        assert by[1]["count"] == 1 and by[1]["qualified_at"] is None and by[1]["alert_attempted_at"] is None, (
            "A is a separate row"
        )
        calls["alerts"].clear()
        self._sender(calls, monkeypatch, True)
        out = cp.sweep(NOW + timedelta(minutes=31), servers=[SERVER_A])
        assert out["alerts"] == 1 and [(s, kw["count"]) for _t, s, kw in calls["alerts"]] == [(2, 3)], (
            "B's retry, for B's subnet"
        )
        by = self._by_subnet(db)
        assert by[2]["alerted_at"] is not None and by[1]["alerted_at"] is None and by[1]["alert_attempted_at"] is None

    def test_attributed_and_unattributed_events_are_separate_rows_in_both_directions(self, db, stack):
        logs, _c = stack
        prime(logs)
        logs[1] = [nak(1), *nak_in(1, 2)]  # one that names no subnet at all, and one Kea placed in A
        cp.sweep(NOW, servers=[SERVER_A])
        by = self._by_subnet(db)
        assert set(by) == {None, 1} and by[None]["count"] == 1 and by[1]["count"] == 1
        # and the other way round: the next sweep's first event is the unattributed one
        logs[1] = [*logs[1], nak(5, minute=2)]
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        by = self._by_subnet(db)
        assert by[None]["count"] == 2 and by[1]["count"] == 1, "the unattributed row grew; the A row did not move"

    def test_rows_resolve_independently(self, db, stack):
        logs, _c = stack
        prime(logs)
        logs[1] = [*nak_in(2, 1), *nak_in(1, 2)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET last_seen=%s WHERE subnet_id=2", (NOW - timedelta(hours=25),))
        db.commit()
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        by = self._by_subnet(db)
        assert by[2]["resolved_at"] is not None and by[1]["resolved_at"] is None, "B went quiet and resolved; A did not"

    def test_a_recurrence_in_one_subnet_reopens_only_that_subnets_row(self, db, stack):
        logs, _c = stack
        prime(logs)
        logs[1] = [*nak_in(2, 1), *nak_in(1, 2)]
        cp.sweep(NOW, servers=[SERVER_A])
        db.commit()
        with db.cursor() as cur:
            cur.execute("UPDATE client_problems SET resolved_at=%s", (NOW + timedelta(minutes=1),))
        db.commit()
        logs[1] = [*logs[1], *nak_in(2, 9, minute=30)]
        cp.sweep(NOW + timedelta(minutes=10), servers=[SERVER_A])
        by = self._by_subnet(db)
        assert by[2]["resolved_at"] is None and by[2]["count"] == 1, "B reopened as a fresh episode"
        assert by[1]["resolved_at"] is not None and by[1]["count"] == 1, "A stayed resolved"

    def test_counts_never_mix_across_sweeps_and_the_unique_key_is_per_subnet(self, db, stack):
        logs, _c = stack
        prime(logs)
        logs[1] = nak_in(2, 1)
        cp.sweep(NOW, servers=[SERVER_A])
        logs[1] = [*logs[1], *nak_in(2, 2, minute=1), *nak_in(1, 3, minute=1)]
        cp.sweep(NOW + timedelta(minutes=5), servers=[SERVER_A])
        by = self._by_subnet(db)
        assert by[2]["count"] == 2 and by[1]["count"] == 1
        assert len(rows(db)) == 2, "two rows, not one that moved"
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM client_problems WHERE scope_key = -1")
            assert cur.fetchone()["n"] == 0, "scope_key is the subnet's id here, never the unattributed -1"


class TestTheDatabaseKinds:
    def _declined(self, db, ip="10.45.0.61", subnet=1):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON(%s), NULL, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 1)",
                (ip, subnet),
            )
        db.commit()

    def test_a_declined_lease_that_has_not_expired_is_a_row_about_the_address(self, db, stack):
        self._declined(db)
        out = cp.sweep(NOW, servers=[])
        assert out["state_rows"] == 1
        row = rows(db)[0]
        assert (row["server_id"], row["kind"], row["mac"], row["ip"], row["subnet_id"], row["count"]) == (
            0, "declined-lease", "", "10.45.0.61", 1, 1,
        )  # fmt: skip

    def test_an_expired_declined_lease_is_not(self, db, stack):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.61'), NULL, 3600, DATE_SUB(NOW(), INTERVAL 1 HOUR), 1, 1)"
            )
        db.commit()
        assert cp.sweep(NOW, servers=[])["state_rows"] == 0 and not rows(db)

    def test_a_state_does_not_count_up_each_sweep(self, db, stack):
        self._declined(db)
        for i in range(3):
            cp.sweep(NOW + timedelta(minutes=5 * i), servers=[])
        assert rows(db)[0]["count"] == 1

    def test_a_state_that_is_gone_resolves_at_once_not_after_a_day(self, db, stack):
        self._declined(db)
        cp.sweep(NOW, servers=[])
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON('10.45.0.61')")
        db.commit()
        out = cp.sweep(NOW + timedelta(minutes=5), servers=[])
        assert rows(db)[0]["resolved_at"] is not None and cp.fetch_open([], []) == [] and out["state_rows"] == 0

    def test_a_reservation_whose_address_is_leased_to_a_different_client_is_a_row_about_the_reserved_client(
        self, db, stack
    ):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON('10.45.0.60'), 'reserved-one')",
                (MAC_HEX,),
            )
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.60'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (MAC2_HEX,),
            )
        db.commit()
        cp.sweep(NOW, servers=[])
        row = rows(db)[0]
        assert (row["kind"], row["mac"], row["ip"], row["subnet_id"], row["server_id"]) == (
            "reservation-held", MAC, "10.45.0.60", 1, 0,
        )  # fmt: skip
        assert MAC2 in row["detail"]

    def test_a_reservation_leased_to_its_own_client_is_not_a_problem(self, db, stack):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON('10.45.0.60'))",
                (MAC_HEX,),
            )
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (INET_ATON('10.45.0.60'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (MAC_HEX,),
            )
        db.commit()
        assert cp.sweep(NOW, servers=[])["state_rows"] == 0


class TestTheSweepRecordsWhetherItCanReadEachServer:
    """v5.68.0-beta.17 (Q152, item e) - a log that could not be read used to be a line in the sweep's summary. The sweep now keeps the
    time of each server's last successful read, its last error and the number of misses in a row, and the Health Center's "Problems
    inbox sweep" row fails after six (thirty minutes) and goes green on the next successful read."""

    @pytest.fixture(autouse=True)
    def _clock_and_cleanup(self, db, monkeypatch):
        monkeypatch.setattr(cp, "_now", lambda: NOW)
        self._wipe(db)
        yield
        self._wipe(db)

    @staticmethod
    def _wipe(db):
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM settings WHERE setting_key LIKE 'client_problems_read:%' OR setting_key LIKE 'client_problems_err:%' "
                "OR setting_key LIKE 'client_problems_miss:%' OR setting_key = 'client_problems_swept'"
            )
        db.commit()

    @staticmethod
    def _row():
        from jen.services import health

        return health._problems_sweep({})

    def test_a_good_read_records_the_time_and_clears_the_error(self, db, stack):
        logs, _ = stack
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        st = cp.read_status([SERVER_A])
        assert st["swept_at"] == NOW
        assert st["servers"] == [{"id": 1, "name": "kea-a", "last_read": NOW, "last_error": "", "misses": 0}]

    def test_six_misses_turn_the_row_red_and_the_next_good_read_turns_it_green(self, db, stack, monkeypatch):
        logs, _ = stack
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(SERVER_A)])
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])  # one good read, then the log goes unreadable
        logs[1] = {"ok": False, "code": "unreachable", "lines": []}
        for n in range(1, 6):
            cp.sweep(NOW, servers=[SERVER_A])
            row = self._row()
            assert row.status == "ok" and f"({n} missed)" in row.detail, (n, row.status, row.detail)
        cp.sweep(NOW, servers=[SERVER_A])  # the sixth miss in a row
        row = self._row()
        assert row.status == "fail" and row.id == "problems_sweep"
        assert "kea-a" in row.detail and "6 sweeps" in row.detail and "unreachable" in row.detail
        assert "last read 2026-10-04 12:00 UTC" in row.detail
        logs[1] = [nak(2)]
        cp.sweep(NOW, servers=[SERVER_A])
        row = self._row()
        assert row.status == "ok" and "missed" not in row.detail
        assert cp.read_status([SERVER_A])["servers"][0]["misses"] == 0

    def test_an_exception_while_reading_counts_as_a_miss_and_names_it(self, db, stack, monkeypatch):
        logs, _ = stack

        def boom(*a, **k):
            raise TimeoutError("ssh timed out")

        monkeypatch.setattr(kea_host, "tail_log", boom)
        cp.sweep(NOW, servers=[SERVER_A])
        s = cp.read_status([SERVER_A])["servers"][0]
        assert s["misses"] == 1 and s["last_error"] == "TimeoutError" and s["last_read"] is None

    def test_one_blind_server_is_named_and_the_healthy_one_is_not(self, db, stack, monkeypatch):
        logs, _ = stack
        logs[1] = {"ok": False, "code": "unreachable", "lines": []}
        logs[2] = [nak(1)]
        for _ in range(cp.MISS_LIMIT):
            cp.sweep(NOW, servers=[SERVER_A, SERVER_B])
        row = self._row()
        assert row.status == "fail" and "kea-a" in row.detail and "kea-b" not in row.detail

    def test_the_row_is_skipped_when_no_server_has_ssh(self, db, stack, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "plain", "api_url": "http://x"}])
        row = self._row()
        assert row.status == "skip" and "no Kea server has SSH" in row.detail

    def test_the_row_is_skipped_before_the_sweep_has_ever_run(self, db, stack):
        assert self._row().status == "skip"

    def test_a_sweep_that_has_stopped_running_is_a_failure_too(self, db, stack, monkeypatch):
        logs, _ = stack
        logs[1] = [nak(1)]
        cp.sweep(NOW, servers=[SERVER_A])
        monkeypatch.setattr(cp, "_now", lambda: NOW + timedelta(minutes=40))
        row = self._row()
        assert row.status == "fail" and "the sweep itself last ran at" in row.detail

    def test_the_row_is_registered_in_the_health_center_in_step(self):
        from jen.services import health

        assert health._CHECK_META["problems_sweep"] == ("Problems inbox sweep", "kea")
        assert health._problems_sweep in health._CHECKS


class TestANakStormCannotFloodTheInbox:
    """v5.68.0-beta.21 (Q156, item 6): a group is keyed by (kind, client, address, subnet), so a thousand-line tail of declines from spoofed MACs and
    requested addresses added up to a thousand rows per sweep, kept 30 days - `MAX_DB_ROWS` bounds only the two lease-database kinds. At most
    `MAX_NEW_KEYS_PER_SWEEP` NEW keys are recorded per server per sweep; the rest are counted, logged once and shown by the Health row."""

    @staticmethod
    def _storm(n, first=0):
        out = []
        for i in range(first, first + n):
            out.append(
                decline(
                    i % 60,
                    ip=f"10.45.{i // 250}.{i % 250 + 1}",
                    mac=f"aa:bb:cc:{i // 65536:02x}:{(i // 256) % 256:02x}:{i % 256:02x}",
                    minute=(i // 60) % 60,
                )
            )
        return out

    def test_a_thousand_distinct_spoofed_keys_record_the_cap_and_count_the_rest(self, db, stack, caplog):
        logs, _calls = stack
        prime(logs)
        logs[1] = self._storm(1000)
        out = cp.sweep(NOW, servers=[SERVER_A])
        assert len(rows(db, "kind='decline'")) == cp.MAX_NEW_KEYS_PER_SWEEP == 200
        assert out["dropped_keys"] == 800
        assert "800 new problem keys were not recorded" in caplog.text
        assert caplog.text.count("new problem keys were not recorded") == 1, "logged once per sweep"

    def test_the_newest_new_keys_are_the_ones_kept(self, db, stack):
        logs, _calls = stack
        prime(logs)
        logs[1] = self._storm(1000)
        cp.sweep(NOW, servers=[SERVER_A])
        kept = {r["mac"] for r in rows(db, "kind='decline'")}
        newest = {f"aa:bb:cc:{i // 65536:02x}:{(i // 256) % 256:02x}:{i % 256:02x}" for i in range(800, 1000)}
        assert kept == newest

    def test_a_key_that_already_exists_always_updates_even_when_the_cap_is_spent(self, db, stack):
        logs, _calls = stack
        prime(logs)
        logs[1] = self._storm(1)
        cp.sweep(NOW - timedelta(minutes=5), servers=[SERVER_A])
        before = rows(db, "kind='decline'")[0]["count"]
        logs[1] = [decline(59, ip="10.45.0.1", mac="aa:bb:cc:00:00:00", minute=30), *self._storm(400, first=1000)]
        out = cp.sweep(NOW, servers=[SERVER_A])
        existing = rows(db, "kind='decline' AND mac='aa:bb:cc:00:00:00'")
        assert existing and existing[0]["count"] > before, "the existing key was not updated"
        assert out["dropped_keys"] == 200 and len(rows(db, "kind='decline'")) == 1 + 200

    def test_a_normal_sweep_drops_nothing_and_clears_the_record(self, db, stack):
        logs, _calls = stack
        prime(logs)
        logs[1] = self._storm(300)
        assert cp.sweep(NOW - timedelta(minutes=5), servers=[SERVER_A])["dropped_keys"] == 100
        assert cp.read_status([SERVER_A])["dropped"] == 100
        logs[1] = [decline(5, ip="10.45.0.200", mac=MAC2, minute=40)]
        assert cp.sweep(NOW, servers=[SERVER_A])["dropped_keys"] == 0
        assert cp.read_status([SERVER_A])["dropped"] == 0

    def test_the_health_row_warns_and_names_the_count(self, db, stack, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(cp, "_now", lambda: NOW)

        logs, _calls = stack
        prime(logs)
        logs[1] = self._storm(500)
        cp.sweep(NOW, servers=[SERVER_A])
        check = health._problems_sweep({})
        assert (
            check.status == "warn"
            and "300 problem keys dropped last sweep" in check.detail
            and "NAK storm" in check.detail
        )
