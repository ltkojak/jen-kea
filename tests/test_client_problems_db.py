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
            "DELETE FROM settings WHERE setting_key LIKE 'client_problems_wm:%' OR setting_key LIKE 'client_problems_clock:%'"
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

    def test_the_newest_event_decides_where_a_row_is(self, db, stack):
        logs, _c = stack
        logs[1] = [decline(1, ip="10.45.0.9")]
        cp.sweep(NOW - timedelta(minutes=5), servers=[SERVER_A])
        assert rows(db)[0]["subnet_id"] == 1
        logs[1] = [decline(1, ip="10.45.0.9"), decline(2, ip="10.45.0.9", minute=1)]
        cp.sweep(NOW, servers=[SERVER_A])
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
