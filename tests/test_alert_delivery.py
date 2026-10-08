"""
tests/test_alert_delivery.py
────────────────────────────
v5.68.0-beta.19 (Q154) - an alert's state knows whether ANYONE WAS TOLD. beta.18 recorded a condition as handled after the send whatever the send
returned: every channel down, or no channel eligible yet, and the warning was suppressed until the condition recovered - and a later `_ok` went out
for a warning nobody had received. `notify_condition` is the one helper (utilization, pool_exhaustion, packet_health, cert_expiring, pool_forecast):
notified only when at least one ELIGIBLE channel returned ok, retried with backoff (1, 2, 4 ... 60 min) while the condition holds, `_ok` only after
a delivered warning. The clock is injected (`now=`), the sender is a stand-in.
"""

from datetime import datetime, timedelta

import pytest

from jen import extensions
from jen.services import alerts

T0 = datetime(2026, 10, 7, 12, 0, 0)
OK = [("telegram", True, "")]
DOWN = [("telegram", False, "HTTP 502")]


class Sender:
    """Answers each send_alert with the next scripted result (the last one repeats) and records what was sent."""

    def __init__(self, *script):
        self.script = list(script) or [OK]
        self.sent = []

    def __call__(self, alert_type, *a, **kw):
        self.sent.append(alert_type)
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]


@pytest.fixture
def send(monkeypatch):
    def install(*script):
        sender = Sender(*script)
        monkeypatch.setattr(alerts, "send_alert", sender)
        return sender

    return install


def _notify(active, now, **kw):
    return alerts.notify_condition(
        "utilization_high", 7, active, kwargs={"pct": 90}, ok_type="utilization_ok", now=now, **kw
    )


class TestEveryChannelFails:
    def test_the_warning_is_retried_never_suppressed(self, db, send):
        sender = send(DOWN)
        assert _notify(True, T0) == "pending"
        assert alerts.alert_delivery("utilization_high", 7) == {
            "active": True,
            "notified": False,
            "attempts": 1,
            "last_attempt": T0.isoformat(),
        }
        # backing off 1 minute: a pass 30 s later does not try
        assert _notify(True, T0 + timedelta(seconds=30)) == "waiting" and sender.sent == ["utilization_high"]
        assert _notify(True, T0 + timedelta(minutes=1)) == "pending" and len(sender.sent) == 2

    def test_the_backoff_doubles_to_an_hour(self, db, send):
        sender = send(DOWN)
        now = T0
        waits = []
        for _ in range(9):
            while _notify(True, now) == "waiting":
                now += timedelta(seconds=30)
            waits.append(now)
            now += timedelta(seconds=1)
        gaps = [int((b - a).total_seconds() // 60) for a, b in zip(waits, waits[1:], strict=False)]
        assert gaps == [1, 2, 4, 8, 16, 32, 60, 60], gaps
        assert len(sender.sent) == 9

    def test_when_a_channel_comes_back_it_is_delivered_once_and_then_quiet(self, db, send):
        sender = send(DOWN, DOWN, OK)
        _notify(True, T0)
        _notify(True, T0 + timedelta(minutes=1))
        assert _notify(True, T0 + timedelta(minutes=3)) == "sent"
        assert alerts.alert_delivery("utilization_high", 7)["notified"] is True
        for minutes in (4, 10, 90):
            assert _notify(True, T0 + timedelta(minutes=minutes)) == "quiet"
        assert sender.sent == ["utilization_high"] * 3

    def test_a_sender_that_raises_is_a_failed_attempt_not_a_crash(self, db, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("smtp exploded")

        monkeypatch.setattr(alerts, "send_alert", boom)
        assert _notify(True, T0) == "pending"
        assert alerts.alert_delivery("utilization_high", 7)["attempts"] == 1


class TestNoChannelIsEligibleYet:
    def test_pending_until_one_appears(self, db, send):
        """send_alert answers [] when no channel handles the type / the subnet: nobody was told."""
        sender = send([], [], OK)
        assert _notify(True, T0) == "pending"
        assert _notify(True, T0 + timedelta(minutes=1)) == "pending"
        assert alerts.alert_delivery("utilization_high", 7)["notified"] is False
        assert _notify(True, T0 + timedelta(minutes=3)) == "sent"
        assert len(sender.sent) == 3


class TestOneOfTwoSucceeds:
    def test_one_delivery_counts_and_nothing_is_repeated(self, db, send):
        sender = send([("telegram", False, "429"), ("ntfy", True, "")])
        assert _notify(True, T0) == "sent"
        assert alerts.alert_delivery("utilization_high", 7)["notified"] is True
        assert _notify(True, T0 + timedelta(minutes=5)) == "quiet"
        assert sender.sent == ["utilization_high"], (
            "the failed channel is not retried, and the delivered one is never re-sent"
        )


class TestTheRecoveryFollowsADeliveredWarning:
    def test_no_ok_for_a_warning_nobody_received(self, db, send):
        sender = send(DOWN)
        _notify(True, T0)
        assert _notify(False, T0 + timedelta(minutes=10)) == "cleared"
        assert sender.sent == ["utilization_high"], "no utilization_ok was sent"
        assert alerts.alert_state("utilization_high", 7) is False

    def test_an_ok_after_a_delivered_warning(self, db, send):
        sender = send(OK)
        _notify(True, T0)
        assert _notify(False, T0 + timedelta(minutes=10)) == "recovered"
        assert sender.sent == ["utilization_high", "utilization_ok"]
        assert _notify(False, T0 + timedelta(minutes=20)) == "quiet"

    def test_a_type_with_no_ok_just_clears(self, db, send):
        sender = send(OK)
        alerts.notify_condition("pool_forecast", 1, True, kwargs={}, now=T0)
        assert alerts.notify_condition("pool_forecast", 1, False, kwargs={}, now=T0) == "cleared"
        assert sender.sent == ["pool_forecast"]

    def test_it_re_arms_after_a_recovery(self, db, send):
        sender = send(OK)
        _notify(True, T0)
        _notify(False, T0 + timedelta(minutes=5))
        assert _notify(True, T0 + timedelta(minutes=10)) == "sent"
        assert sender.sent == ["utilization_high", "utilization_ok", "utilization_high"]


class TestThroughTheRealChecks:
    def test_utilization_is_retried_on_the_next_pass_and_exhaustion_follows(self, db, monkeypatch, send):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.81.0.0/16"}})
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        cfg = {"subnet4": [{"id": 1, "subnet": "10.81.0.0/16", "pools": [{"pool": "10.81.0.10 - 10.81.0.29"}]}]}
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM lease4 WHERE address BETWEEN INET_ATON('10.81.0.0') AND INET_ATON('10.81.255.255')"
            )
            for n in range(10, 28):
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                    "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                    (f"10.81.0.{n}", f"AABB0000{n:04X}"),
                )
        db.commit()
        try:
            sender = send(DOWN)
            with db.cursor() as cur:
                alerts.check_utilization_alerts(cur, cfg)
            assert sorted(sender.sent) == ["pool_exhaustion", "utilization_high"]
            assert not alerts.alert_delivery("pool_exhaustion", 1)["notified"]
            # the channel recovers; a later pass (after the backoff) delivers both
            monkeypatch.setattr(alerts, "_utcnow", lambda: T0 + timedelta(minutes=2))
            sender2 = send(OK)
            with db.cursor() as cur:
                alerts.check_utilization_alerts(cur, cfg)
            assert sorted(sender2.sent) == ["pool_exhaustion", "utilization_high"]
            assert alerts.alert_delivery("pool_exhaustion", 1)["notified"] is True
        finally:
            with db.cursor() as cur:
                cur.execute(
                    "DELETE FROM lease4 WHERE address BETWEEN INET_ATON('10.81.0.0') AND INET_ATON('10.81.255.255')"
                )
            db.commit()

    def test_packet_health_is_retried_too(self, db, monkeypatch, send):
        import json

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea", "api_url": "http://x"}])
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
            for ago, stats in (
                (30, {"pkt4-received": 100, "pkt4-receive-drop": 0}),
                (0, {"pkt4-received": 200, "pkt4-receive-drop": 50}),  # 25 % dropped: fail
            ):
                cur.execute(
                    "INSERT INTO server_stats (server_id, snapshot_time, stats) VALUES (1, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s)",
                    (ago, json.dumps(stats)),
                )
        db.commit()
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        send(DOWN)
        alerts._check_packet_health_alerts()
        assert alerts.alert_delivery("packet_health", 1)["notified"] is False
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0 + timedelta(minutes=2))
        sender = send(OK)
        alerts._check_packet_health_alerts()
        assert sender.sent == ["packet_health"] and alerts.alert_delivery("packet_health", 1)["notified"] is True


class TestCertExpiryAndTheForecastUseTheSameHelper:
    def test_a_cert_warning_nobody_received_is_retried(self, db, monkeypatch, send):
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: 5)
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        sender = send(DOWN)
        alerts.check_cert_expiry_alert()
        assert sender.sent == ["cert_expiring"]
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0 + timedelta(minutes=2))
        sender = send(OK)
        alerts.check_cert_expiry_alert()
        assert sender.sent == ["cert_expiring"] and alerts.alert_delivery("cert_expiring", 7)["notified"] is True
        alerts.check_cert_expiry_alert()
        assert sender.sent == ["cert_expiring"], "delivered: quiet"

    def test_a_tighter_bucket_speaks_once_and_a_looser_one_is_already_told(self, db, monkeypatch, send):
        sender = send(OK)
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: 25)
        alerts.check_cert_expiry_alert()
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: 6)
        alerts.check_cert_expiry_alert()
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: 200)  # renewed
        alerts.check_cert_expiry_alert()
        assert sender.sent == ["cert_expiring", "cert_expiring"]
        assert not any(alerts.alert_state("cert_expiring", b) for b in (30, 7, 1))

    def test_the_forecast_reminds_weekly_once_delivered_and_retries_until_then(self, db, monkeypatch, send):
        from datetime import date

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        history = {
            1: [
                {
                    "snapshot_time": datetime(2026, 9, 15) - timedelta(days=10 - i),
                    "active_leases": 100 + 8 * i,
                    "pool_used": 100 + 8 * i,
                    "pool_size": 254,
                }
                for i in range(10)
            ]
        }
        monkeypatch.setattr("jen.services.health.lease_history_window", lambda days=31: history)
        sender = send(DOWN, OK)
        today = date(2026, 9, 15)
        alerts.check_pool_forecast_alerts(today=today)
        assert alerts.alert_delivery("pool_forecast", 1)["notified"] is False, "nobody took it"
        alerts.check_pool_forecast_alerts(
            today=today + timedelta(days=1)
        )  # past the 1-minute backoff: tried again, delivered
        assert alerts.alert_delivery("pool_forecast", 1)["notified"] is True and len(sender.sent) == 2
        alerts.check_pool_forecast_alerts(today=today + timedelta(days=4))
        assert len(sender.sent) == 2
        alerts.check_pool_forecast_alerts(today=today + timedelta(days=8))  # a week after it was told
        assert len(sender.sent) == 3


class TestAnOlderJensStateIsHonoured:
    def test_the_beta_18_one_reads_as_active_and_not_notified(self, db):
        """v5.68.0-beta.20 (Q155, item 6): beta.18 wrote "1" after a send whose result nobody checked. Reading it as DELIVERED let an undelivered
        warning survive the upgrade as sent until the condition recovered; it now reads as active, not notified - one attempt on the next pass."""
        from jen.models.user import set_global_setting

        set_global_setting("alert_state:utilization_high:3", "1")
        set_global_setting("alert_state:utilization_high:4", "0")
        assert alerts.alert_delivery("utilization_high", 3) == {
            "active": True,
            "notified": False,
            "attempts": 0,
            "last_attempt": None,
        }
        assert alerts.alert_state("utilization_high", 4) is False

    def test_an_active_old_state_gets_one_attempt_on_the_next_pass_and_then_recovers_normally(self, db, send):
        from jen.models.user import set_global_setting

        sender = send(OK)
        set_global_setting("alert_state:utilization_high:3", "1")
        assert (
            alerts.notify_condition("utilization_high", 3, True, kwargs={}, ok_type="utilization_ok", now=T0) == "sent"
        )
        assert sender.sent == ["utilization_high"], "one attempt: a possible single duplicate beats a missed warning"
        assert (
            alerts.notify_condition("utilization_high", 3, True, kwargs={}, ok_type="utilization_ok", now=T0) == "quiet"
        )
        alerts.notify_condition("utilization_high", 3, False, kwargs={}, ok_type="utilization_ok", now=T0)
        assert sender.sent == ["utilization_high", "utilization_ok"]

    def test_an_old_active_state_whose_channel_is_still_down_keeps_trying_and_never_sends_a_recovery_nobody_asked_for(
        self, db, send
    ):
        from jen.models.user import set_global_setting

        sender = send(DOWN)
        set_global_setting("alert_state:utilization_high:5", "1")
        assert (
            alerts.notify_condition("utilization_high", 5, True, kwargs={}, ok_type="utilization_ok", now=T0)
            == "pending"
        )
        assert (
            alerts.notify_condition("utilization_high", 5, False, kwargs={}, ok_type="utilization_ok", now=T0)
            == "cleared"
        )
        assert sender.sent == ["utilization_high"]


class TestARecoveryIsStateToo:
    """v5.68.0-beta.20 (Q155, item 5): the `_ok` result used to be ignored and the state cleared - a recovery that failed was never retried, and the
    operator kept "high" forever. `r` (recovery pending) is set when the `_ok` was not delivered; every pass retries it with the same backoff."""

    def _warn_then_clear(self, send, ok_script):
        sender = send(OK, *ok_script)
        assert _notify(True, T0) == "sent"
        return sender

    def test_the_ok_fails_is_retried_and_succeeds_exactly_once_without_the_warning_again(self, db, send):
        sender = self._warn_then_clear(send, [DOWN, DOWN, OK])
        assert _notify(False, T0 + timedelta(minutes=10)) == "recovery-pending"
        state = alerts._load_state("utilization_high", 7)
        assert state["r"] is True and state["a"] is False and state["c"] == 1
        assert _notify(False, T0 + timedelta(minutes=10, seconds=30)) == "waiting", "backing off 1 minute"
        assert (
            _notify(False, T0 + timedelta(minutes=11)) == "recovery-pending"
        )  # second failure: the next wait is 2 minutes
        assert _notify(False, T0 + timedelta(minutes=12)) == "waiting"
        assert _notify(False, T0 + timedelta(minutes=13)) == "recovered"
        assert sender.sent == ["utilization_high", "utilization_ok", "utilization_ok", "utilization_ok"]
        assert alerts._load_state("utilization_high", 7)["r"] is False
        for minutes in (14, 30, 200):
            assert _notify(False, T0 + timedelta(minutes=minutes)) == "quiet"
        assert sender.sent.count("utilization_ok") == 3 and sender.sent.count("utilization_high") == 1, (
            "delivered once: no further ok, and the warning is never sent again while a recovery waits"
        )

    def test_no_eligible_channel_for_the_ok_keeps_the_recovery_pending_until_one_exists(self, db, send):
        """`utilization_ok` has to be ticked on a channel; with none, `send_alert` answers [] - nobody was told - so it stays owed."""
        sender = self._warn_then_clear(send, [[], [], OK])
        assert _notify(False, T0 + timedelta(minutes=5)) == "recovery-pending"
        assert _notify(False, T0 + timedelta(minutes=6)) == "recovery-pending"
        assert alerts.alert_delivery("utilization_high", 7)["active"] is False
        assert _notify(False, T0 + timedelta(minutes=8)) == "recovered"
        assert sender.sent == ["utilization_high", "utilization_ok", "utilization_ok", "utilization_ok"]

    def test_a_condition_that_comes_back_while_its_recovery_is_owed_does_not_re_warn(self, db, send):
        sender = self._warn_then_clear(send, [DOWN])
        assert _notify(False, T0 + timedelta(minutes=5)) == "recovery-pending"
        assert _notify(True, T0 + timedelta(minutes=6)) == "quiet", "the earlier warning was delivered and still stands"
        state = alerts._load_state("utilization_high", 7)
        assert state["a"] is True and state["n"] is True and state["r"] is False
        assert sender.sent == ["utilization_high", "utilization_ok"]
        # and a later real recovery is delivered normally
        sender2 = send(OK)
        assert _notify(False, T0 + timedelta(minutes=30)) == "recovered" and sender2.sent == ["utilization_ok"]

    def test_a_sender_that_raises_on_the_ok_is_a_failed_attempt_not_a_crash(self, db, monkeypatch):
        calls = []

        def flaky(alert_type, *a, **k):
            calls.append(alert_type)
            if alert_type == "utilization_ok":
                raise RuntimeError("smtp exploded")
            return OK

        monkeypatch.setattr(alerts, "send_alert", flaky)
        assert _notify(True, T0) == "sent"
        assert _notify(False, T0 + timedelta(minutes=5)) == "recovery-pending"
        assert alerts._load_state("utilization_high", 7)["r"] is True

    def test_a_type_without_an_ok_just_clears_even_if_a_recovery_was_somehow_owed(self, db, send):
        from jen.models.user import set_global_setting

        send(OK)
        set_global_setting("alert_state:pool_forecast:9", '{"a":false,"n":false,"t":null,"c":2,"d":null,"r":true}')
        assert alerts.notify_condition("pool_forecast", 9, False, kwargs={}, now=T0) == "cleared"
        assert alerts._load_state("pool_forecast", 9)["r"] is False


class TestAQuietPassWritesNothing:
    """v5.68.0-beta.20 (Q155, F-1): `notify_condition` saved the state on its quiet path - a settings UPSERT per (type, key) on every 30-second pass
    with nothing changed."""

    def test_only_a_change_is_written(self, db, send, monkeypatch):
        send(OK)
        writes = []
        real = alerts._save_state
        monkeypatch.setattr(alerts, "_save_state", lambda *a, **k: (writes.append(a[:2]), real(*a, **k))[1])
        assert _notify(True, T0) == "sent" and len(writes) == 1
        for minutes in range(1, 20):
            assert _notify(True, T0 + timedelta(minutes=minutes)) == "quiet"
        assert len(writes) == 1, f"{len(writes) - 1} writes on passes that changed nothing"
        assert _notify(False, T0 + timedelta(minutes=30)) == "recovered" and len(writes) == 2
        for minutes in range(31, 40):
            assert _notify(False, T0 + timedelta(minutes=minutes)) == "quiet"
        assert len(writes) == 2

    def test_a_waiting_pass_writes_nothing_either(self, db, send, monkeypatch):
        send(DOWN)
        _notify(True, T0)
        writes = []
        real = alerts._save_state
        monkeypatch.setattr(alerts, "_save_state", lambda *a, **k: (writes.append(a[:2]), real(*a, **k))[1])
        assert _notify(True, T0 + timedelta(seconds=10)) == "waiting" and writes == []
        assert _notify(True, T0 + timedelta(seconds=40)) == "waiting" and writes == []

    def test_a_missing_state_that_stays_quiet_writes_no_row(self, db, send, monkeypatch):
        writes = []
        monkeypatch.setattr(alerts, "_save_state", lambda *a, **k: writes.append(a[:2]))
        for minutes in range(5):
            assert _notify(False, T0 + timedelta(minutes=minutes)) == "quiet"
        assert writes == []


class _Stop(BaseException):
    """Ends the alert loop from inside its own sleep (a BaseException passes the loop's `except Exception`)."""


@pytest.fixture
def real_loop(monkeypatch):
    """Run the REAL `alerts.check_alerts` loop on an injected clock: `time.sleep` advances `alerts._utcnow` and ends the run after the given
    simulated minutes. Only what is not under test is stubbed - the Kea servers (none), the snapshot pass and the daily summary."""
    import time as _time

    clock = {"now": T0}
    monkeypatch.setattr(alerts, "_utcnow", lambda: clock["now"])
    monkeypatch.setattr(extensions, "KEA_SERVERS", [])
    monkeypatch.setattr(alerts, "run_snapshot_pass", lambda: None)
    monkeypatch.setattr(alerts, "send_daily_summary", lambda: None)
    monkeypatch.setitem(alerts.__dict__, "__kea_command", lambda *a, **k: {"result": 1})
    monkeypatch.setitem(alerts.__dict__, "__get_active_kea_server", lambda: None)
    monkeypatch.setitem(alerts.__dict__, "__check_config_drift", list)

    def drive(minutes):
        end = T0 + timedelta(minutes=minutes)

        def fake_sleep(seconds):
            clock["now"] += timedelta(seconds=seconds)
            if clock["now"] >= end:
                raise _Stop

        monkeypatch.setattr(_time, "sleep", fake_sleep)
        with pytest.raises(_Stop):
            alerts.check_alerts()

    alerts._CONDITION_CACHE.clear()
    yield drive
    alerts._CONDITION_CACHE.clear()


class TestTheConditionsRunInTheRealLoop:
    """v5.68.0-beta.20 (Q155, item 3): `notify_condition` schedules a failed delivery for retry in 1, 2, 4 ... minutes, but the certificate and forecast
    checks were called once per process-day - a one-day certificate warning whose channel was down was next attempted tomorrow, after the certificate
    expired. They now run every CONDITION_INTERVAL_MINUTES in the alert loop, with the expensive inputs cached hourly. These tests run the loop itself."""

    def test_the_default_cadence_is_every_fifteen_minutes(self, db, real_loop, monkeypatch):
        assert alerts.CONDITION_INTERVAL_MINUTES == 15 and alerts.CONDITION_CACHE_MINUTES == 60
        calls = []
        monkeypatch.setattr(alerts, "run_slow_conditions", lambda now=None: calls.append(now))
        real_loop(40)
        assert len(calls) == 3, f"expected the first pass, then one every 15 minutes: {calls}"
        gaps = [(b - a).total_seconds() / 60 for a, b in zip(calls, calls[1:], strict=False)]
        assert all(15 <= gap < 16 for gap in gaps), gaps

    def test_a_cert_warning_whose_first_send_fails_is_attempted_again_two_minutes_later(
        self, db, real_loop, monkeypatch, send
    ):
        monkeypatch.setattr(
            alerts, "CONDITION_INTERVAL_MINUTES", 1
        )  # the loop's cadence; the retry backoff (1, 2, 4 min) is notify_condition's
        days_calls = []
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: (days_calls.append(1), 1)[1])
        sender = send(DOWN, DOWN, OK)
        real_loop(5)
        assert sender.sent == ["cert_expiring"] * 3, sender.sent
        assert alerts.alert_delivery("cert_expiring", 1)["notified"] is True
        assert len(days_calls) == 1, "the certificate file is read once an hour, not on every pass"

    def test_a_forecast_whose_first_send_fails_is_attempted_again_and_delivered(self, db, real_loop, monkeypatch, send):
        monkeypatch.setattr(alerts, "CONDITION_INTERVAL_MINUTES", 1)
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: None)
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        history = {
            1: [
                {
                    "snapshot_time": T0 - timedelta(days=10 - i),
                    "active_leases": 100 + 8 * i,
                    "pool_used": 100 + 8 * i,
                    "pool_size": 254,
                }
                for i in range(10)
            ]
        }
        reads = []
        monkeypatch.setattr("jen.services.health.lease_history_window", lambda days=31: (reads.append(1), history)[1])
        sender = send(DOWN, OK)
        real_loop(4)
        assert sender.sent == ["pool_forecast", "pool_forecast"], sender.sent
        assert alerts.alert_delivery("pool_forecast", 1)["notified"] is True
        assert len(reads) == 1, "the history is read and the forecast fitted once an hour"

    def test_the_cache_expires_after_an_hour(self, db, real_loop, monkeypatch, send):
        monkeypatch.setattr(alerts, "CONDITION_INTERVAL_MINUTES", 10)
        days_calls = []
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: (days_calls.append(1), 100)[1])
        send(OK)
        real_loop(130)
        assert len(days_calls) == 3, "t=0.5 min, then after the hour, then after the next hour"

    def test_the_loop_does_not_gate_either_check_on_the_calendar_day_any_more(self):
        import inspect

        source = inspect.getsource(alerts.check_alerts)
        assert "last_cert_check_date" not in source and "run_slow_conditions" in source
