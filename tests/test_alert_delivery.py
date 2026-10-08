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

    def drive(minutes, hooks=None):
        """Run the loop for `minutes` of simulated time. `hooks` {n: fn(clock)} runs after the n-th sleep (1-based) - a place to jump the clock or
        change the world between two cycles."""
        end = T0 + timedelta(minutes=minutes)
        slept = {"n": 0}

        def fake_sleep(seconds):
            clock["now"] += timedelta(seconds=seconds)
            slept["n"] += 1
            if hooks and slept["n"] in hooks:
                hooks[slept["n"]](clock)
            if clock["now"] >= end:
                raise _Stop

        monkeypatch.setattr(_time, "sleep", fake_sleep)
        with pytest.raises(_Stop):
            alerts.check_alerts()

    drive.clock = clock
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


class TestTheDailySummaryIsDueAtOrAfterItsTime:
    """v5.68.0-beta.21 (Q156, item 7): `summary_due = now.hour == h and now.minute == m`, evaluated once per outer cycle - and a cycle is 6 x (probe + 5 s),
    90 s with one server down, plus the heavy block. The one-minute window was missed with no log line. It is now due AT OR AFTER its time, once a day,
    and `daily_summary_sent` (the date) survives a restart. These tests run the real loop on a clock that JUMPS over the minute."""

    DAY = "2026-10-07"  # T0 is 12:00:00 on this date

    @pytest.fixture
    def summary(self, db, monkeypatch):
        from jen.models.user import set_global_setting

        sent = []
        monkeypatch.setattr(alerts, "send_daily_summary", lambda: sent.append(alerts._utcnow()) or "delivered")

        def configure(at, persisted=""):
            set_global_setting("daily_summary_time", at)
            set_global_setting("daily_summary_sent", persisted)

        yield sent, configure
        set_global_setting("daily_summary_sent", "")
        set_global_setting("daily_summary_time", "07:00")

    @staticmethod
    def _stored():
        from jen.models.user import get_global_setting

        return get_global_setting("daily_summary_sent", "")

    def test_a_cycle_that_jumps_from_before_the_minute_to_after_it_still_sends_once(self, real_loop, summary):
        sent, configure = summary
        configure("12:04")  # no record, and 12:00 has not reached it: the first cycle past it sends
        # the clock goes from 12:01:00 to 12:11:00 between two cycles - no cycle ever starts inside minute 12:04
        real_loop(20, hooks={12: lambda clock: clock.__setitem__("now", clock["now"] + timedelta(minutes=10))})
        assert len(sent) == 1 and sent[0] >= T0 + timedelta(minutes=10), sent
        assert self._stored() == self.DAY

    def test_it_is_sent_once_a_day_not_every_cycle_after_its_time(self, real_loop, summary):
        sent, configure = summary
        configure("12:00", persisted="2026-10-06")
        real_loop(10)
        assert len(sent) == 1

    def test_a_restart_after_sending_does_not_send_again(self, real_loop, summary):
        sent, configure = summary
        configure("11:00", persisted=self.DAY)
        real_loop(20)
        assert sent == []

    def test_a_restart_before_its_time_sends_at_the_first_cycle_past_it(self, real_loop, summary):
        sent, configure = summary
        configure("12:10")
        real_loop(20)
        assert len(sent) == 1 and T0 + timedelta(minutes=10) <= sent[0] < T0 + timedelta(minutes=11)

    def test_a_start_after_the_time_with_no_record_does_not_announce_a_summary_at_a_random_hour(
        self, real_loop, summary
    ):
        """A fresh install, or the first start after the upgrade that added the record: 07:00 has passed, nothing says it was not sent - the loop
        does not send a 'daily' summary at 12:00 because it happened to start then."""
        sent, configure = summary
        configure("07:00")
        real_loop(20)
        assert sent == []

    def test_the_next_day_it_is_sent_again(self, real_loop, summary):
        sent, configure = summary
        configure("11:00", persisted=self.DAY)
        # the run ends 3 minutes after the clock has jumped a day, so the cycles after the jump actually run
        real_loop(24 * 60 + 3, hooks={4: lambda clock: clock.__setitem__("now", clock["now"] + timedelta(days=1))})
        assert len(sent) == 1 and sent[0].date().isoformat() == "2026-10-08"
        assert self._stored() == "2026-10-08"

    def test_a_failed_summary_is_retried_no_more_often_than_every_fifteen_minutes_and_is_not_recorded(
        self, real_loop, summary, monkeypatch
    ):
        sent, configure = summary
        tries = []
        monkeypatch.setattr(alerts, "send_daily_summary", lambda: tries.append(alerts._utcnow()) or "failed")
        configure("11:00", persisted="2026-10-06")
        real_loop(40)
        assert len(tries) == 3, f"expected the first try, then one every 15 minutes: {tries}"
        assert all((b - a) >= timedelta(minutes=15) for a, b in zip(tries, tries[1:], strict=False))
        assert self._stored() == "2026-10-06", "a summary that failed to build is not recorded as sent"

    def test_send_daily_summary_says_whether_it_worked(self, db, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr(alerts, "_pending_summary", None)
        monkeypatch.setattr(alerts, "send_alert", lambda *a, **k: [("telegram", True, "")])
        assert alerts.send_daily_summary() == "delivered"
        monkeypatch.setattr(alerts, "send_alert", lambda *a, **k: [])
        assert alerts.send_daily_summary() == "undelivered", (
            "no channel was eligible: nobody was told (beta.21 pinned True here)"
        )

        def broken():
            raise RuntimeError("kea database down")

        monkeypatch.setattr(alerts, "_pending_summary", None)
        monkeypatch.setitem(alerts.__dict__, "__kea_db_ctx", broken)
        assert alerts.send_daily_summary() == "failed"


class TestTheKnownMacsSeedIsRetried:
    """v5.68.0-beta.21 (Q156, item 12): the seed ran once before the loop. A Jen database that was down at start left `known_macs` empty for the life of
    the process and every known device that was offline at start fired `new_device` when it came back. The seed is retried at the top of each cycle until
    it succeeds, and `new_device` is not sent until it has."""

    D_MAC = "aa:bb:cc:00:1a:01"
    NEW_MAC = "aa:bb:cc:00:1a:02"

    @pytest.fixture
    def world(self, db, monkeypatch):
        sent = []
        monkeypatch.setattr(alerts, "send_alert", lambda t, *a, **kw: sent.append(t) or [("test", True, "")])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.85.0.0/24"}})

        def lease(mac, n):
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) VALUES "
                    "(INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                    (f"10.85.0.{n}", mac.replace(":", "")),
                )
            db.commit()

        def clean():
            with db.cursor() as cur:
                cur.execute(
                    "DELETE FROM lease4 WHERE address BETWEEN INET_ATON('10.85.0.0') AND INET_ATON('10.85.0.255')"
                )
            db.commit()

        clean()
        yield sent, lease
        clean()

    def test_the_seed_fails_twice_then_succeeds_and_a_known_device_coming_back_is_not_new(
        self, real_loop, world, monkeypatch
    ):
        sent, lease = world
        attempts = []

        def seed(known_macs):
            attempts.append(1)
            if len(attempts) < 3:
                return False
            known_macs.add(self.D_MAC)
            return True

        monkeypatch.setattr(alerts, "_seed_known_macs", seed)
        # D is in the devices table all along but only comes online during the third cycle (its first sleep is #13)
        real_loop(5, hooks={13: lambda clock: lease(self.D_MAC, 9)})
        assert len(attempts) == 3, "retried every cycle until it worked, then never again"
        assert "new_lease" in sent
        assert "new_device" not in sent, "a device that was in the table all along was announced as new"

    def test_while_the_seed_keeps_failing_no_device_is_announced_as_new(self, real_loop, world, monkeypatch):
        sent, lease = world
        attempts = []
        monkeypatch.setattr(alerts, "_seed_known_macs", lambda known: attempts.append(1) or False)
        real_loop(4, hooks={13: lambda clock: lease(self.NEW_MAC, 11)})
        assert len(attempts) >= 3, "the seed is retried at the top of every cycle"
        assert "new_lease" in sent and "new_device" not in sent

    def test_once_seeded_a_truly_new_device_is_still_announced(self, real_loop, world, monkeypatch):
        sent, lease = world
        monkeypatch.setattr(alerts, "_seed_known_macs", lambda known: (known.add(self.D_MAC), True)[1])
        real_loop(3, hooks={13: lambda clock: lease(self.NEW_MAC, 12)})
        assert "new_device" in sent

    def test_the_seed_itself_reports_failure_and_success(self, db, monkeypatch):
        known = set()
        assert alerts._seed_known_macs(known) is True
        monkeypatch.setitem(alerts.__dict__, "__jen_db_ctx", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        assert alerts._seed_known_macs(known) is False


class TestOrphanedAlertStateIsCleared:
    """v5.68.0-beta.21 (Q156, item 11): `if info is None: continue` - a subnet that left Jen's map kept its `alert_state:utilization_high:<sid>` /
    `pool_exhaustion` / `pool_forecast` rows active for ever (never an `_ok`, loaded on every settings reload); a removed server's packet-health state
    likewise."""

    @staticmethod
    def _stored(db, alert_type):
        with db.cursor() as cur:
            cur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE %s", (f"alert_state:{alert_type}:%",))
            return sorted(r["setting_key"].rsplit(":", 1)[1] for r in cur.fetchall())

    @staticmethod
    def _put(db, alert_type, keys):
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key LIKE %s", (f"alert_state:{alert_type}:%",))
            for key in keys:
                cur.execute(
                    "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)",
                    (f"alert_state:{alert_type}:{key}", '{"a":true,"n":true,"t":null,"c":0,"d":null,"r":false}'),
                )
        db.commit()
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()

    def test_the_rows_of_keys_that_are_not_live_are_deleted_and_the_live_ones_kept(self, db, send):
        sender = send(OK)
        self._put(db, "utilization_high", [5, 6, 7])
        assert alerts._clear_orphan_states("utilization_high", {5, 7}) == 1
        assert self._stored(db, "utilization_high") == ["5", "7"]
        assert sender.sent == [], "no recovery is sent: the thing the alert was about is gone"

    def test_the_last_subnet_s_state_is_cleared_too(self, db):
        """beta.21 cleared nothing for an empty live set ("an unreadable configuration"), but SUBNET_MAP is the last APPLIED config: empty means the
        last subnet was removed, and its state stayed active for ever (Q157, item 6)."""
        self._put(db, "pool_exhaustion", [1, 2])
        assert alerts._clear_orphan_states("pool_exhaustion", []) == 2
        assert self._stored(db, "pool_exhaustion") == []

    def test_removing_the_last_subnet_through_the_real_pass_clears_its_rows(self, db, monkeypatch, send):
        send(OK)
        self._put(db, "utilization_high", [61])
        self._put(db, "pool_exhaustion", [61])
        self._put(db, "pool_forecast", [61])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.services.health.lease_history_window", lambda days=31: {})
        with db.cursor() as cur:
            alerts.check_utilization_alerts(cur, {"subnet4": []})
        alerts.check_pool_forecast_alerts(today=T0.date())
        for kind in ("utilization_high", "pool_exhaustion", "pool_forecast"):
            assert self._stored(db, kind) == [], kind

    def test_removing_the_last_server_clears_its_packet_health_state(self, db, monkeypatch):
        self._put(db, "packet_health", [4])
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        alerts._check_packet_health_alerts()
        assert self._stored(db, "packet_health") == []

    def test_a_process_whose_config_was_never_applied_touches_nothing(self, db, monkeypatch):
        self._put(db, "utilization_high", [1, 2])
        monkeypatch.setattr(extensions, "cfg", None)
        assert alerts._clear_orphan_states("utilization_high", []) == 0
        assert self._stored(db, "utilization_high") == ["1", "2"]

    def test_another_alert_types_rows_are_untouched(self, db):
        self._put(db, "utilization_high", [9])
        self._put(db, "packet_health", [9])
        alerts._clear_orphan_states("utilization_high", {1})
        assert self._stored(db, "utilization_high") == [] and self._stored(db, "packet_health") == ["9"]

    def test_a_subnet_leaving_the_map_loses_its_state_on_the_next_utilization_pass(self, db, monkeypatch, send):
        send(OK)
        self._put(db, "utilization_high", [41, 42])
        self._put(db, "pool_exhaustion", [41, 42])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {41: {"name": "A", "cidr": "10.141.0.0/24"}})
        with db.cursor() as cur:
            alerts.check_utilization_alerts(cur, {"subnet4": []})
        assert self._stored(db, "utilization_high") == ["41"] and self._stored(db, "pool_exhaustion") == ["41"]

    def test_the_forecast_pass_clears_a_removed_subnet(self, db, monkeypatch, send):
        send(OK)
        self._put(db, "pool_forecast", [51, 52])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {51: {"name": "A", "cidr": "10.151.0.0/24"}})
        monkeypatch.setattr("jen.services.health.lease_history_window", lambda days=31: {})
        alerts.check_pool_forecast_alerts(today=T0.date())
        assert self._stored(db, "pool_forecast") == ["51"]

    def test_a_removed_server_loses_its_packet_health_state(self, db, monkeypatch):
        self._put(db, "packet_health", [1, 2])
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea", "api_url": "http://x"}])
        alerts._check_packet_health_alerts()
        assert self._stored(db, "packet_health") == ["1"]

    def test_the_cert_buckets_are_not_subnet_keys_and_are_never_touched(self, db, monkeypatch):
        self._put(db, "cert_expiring", [30, 7, 1])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.1.0.0/24"}})
        with db.cursor() as cur:
            alerts.check_utilization_alerts(cur, {"subnet4": []})
        assert self._stored(db, "cert_expiring") == ["1", "30", "7"]


_REAL_SEND_DAILY_SUMMARY = alerts.send_daily_summary


class TestTheSummaryIsRecordedOnlyWhenAChannelTookIt:
    """v5.68.0-beta.22 (Q157, item 2): `send_daily_summary` returned True after `send_alert(...)` whatever the channels answered, and the loop recorded
    the day as sent. Every other notification since beta.19 is judged by `_delivered`. "delivered" is recorded; "undelivered" is retried with the
    notification backoff (1, 2, 4 ... 60 min) and never recorded; the built text is kept so a retry does not rebuild."""

    @pytest.fixture
    def world(self, db, monkeypatch, real_loop):
        from jen.models.user import set_global_setting

        builds = []
        monkeypatch.setattr(alerts, "send_daily_summary", _REAL_SEND_DAILY_SUMMARY)
        monkeypatch.setattr(alerts, "_pending_summary", None)
        monkeypatch.setattr(alerts, "_build_daily_summary", lambda: (builds.append(1), "the built summary")[1])
        set_global_setting("daily_summary_time", "11:00")
        set_global_setting("daily_summary_sent", "2026-10-06")  # yesterday: due from the first cycle
        yield builds
        set_global_setting("daily_summary_sent", "")
        set_global_setting("daily_summary_time", "07:00")

    @staticmethod
    def _stored():
        from jen.models.user import get_global_setting

        return get_global_setting("daily_summary_sent", "")

    def test_one_channel_taking_it_is_recorded_and_sent_once(self, real_loop, world, send):
        sender = send([("telegram", False, "429"), ("ntfy", True, "")])
        real_loop(10)
        assert sender.sent == ["daily_summary"] and world == [1]
        assert self._stored() == "2026-10-07"

    def test_every_channel_failing_is_not_recorded_retried_at_1_2_4_minutes_and_built_once(
        self, real_loop, world, send
    ):
        sender = send(DOWN, DOWN, DOWN, OK)
        real_loop(12)
        # cycles end every 30 s: attempts at 0:30 (c1, wait 1 min), 1:30 (c2, wait 2 min), 3:30 (c3, wait 4 min), 7:30 (delivered)
        assert sender.sent == ["daily_summary"] * 4, sender.sent
        assert world == [1], "the summary was built once: a retry sends the kept text"
        assert self._stored() == "2026-10-07", "recorded only when it was finally delivered"

    def test_the_retries_follow_the_backoff_not_every_cycle(self, real_loop, world, send, monkeypatch):
        sender = send(DOWN)
        times = []
        inner = alerts.send_alert
        monkeypatch.setattr(alerts, "send_alert", lambda *a, **k: (times.append(alerts._utcnow()), inner(*a, **k))[1])
        real_loop(10)
        gaps = [int((b - a).total_seconds() // 60) for a, b in zip(times, times[1:], strict=False)]
        assert gaps[:3] == [1, 2, 4], gaps
        assert self._stored() == "2026-10-06", "never delivered, never recorded"
        assert len(sender.sent) == len(times)

    def test_no_eligible_channel_is_not_recorded(self, real_loop, world, send):
        sender = send([])  # send_alert answers [] when no channel handles daily_summary
        real_loop(4)
        assert len(sender.sent) >= 2 and self._stored() == "2026-10-06"

    def test_a_restart_with_a_pending_summary_builds_again_and_sends_once_delivered(
        self, real_loop, world, send, monkeypatch
    ):
        send(DOWN)
        real_loop(3)
        assert world == [1] and alerts._pending_summary is not None and self._stored() == "2026-10-06"
        # the process restarts: the pending text is memory of the old process
        monkeypatch.setattr(alerts, "_pending_summary", None)
        alerts._CONDITION_CACHE.clear()
        sender2 = send(OK)
        real_loop.clock["now"] = T0
        real_loop(3)
        assert world == [1, 1], "built again after the restart"
        assert sender2.sent == ["daily_summary"] and self._stored() == "2026-10-07"

    def test_a_new_day_drops_the_pending_text(self, db, monkeypatch, send):
        monkeypatch.setattr(alerts, "_pending_summary", (T0.date() - timedelta(days=1), "yesterday's text"))
        built = []
        monkeypatch.setattr(alerts, "_build_daily_summary", lambda: (built.append(1), "today's text")[1])
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        sender = send(OK)
        assert alerts.send_daily_summary() == "delivered" and built == [1] and sender.sent == ["daily_summary"]

    def test_the_pending_text_is_what_the_retry_sends(self, db, monkeypatch):
        sent_texts = []
        results = iter([DOWN, OK])
        monkeypatch.setattr(alerts, "_pending_summary", None)
        monkeypatch.setattr(alerts, "_utcnow", lambda: T0)
        monkeypatch.setattr(alerts, "_build_daily_summary", lambda: f"built at call {len(sent_texts)}")
        monkeypatch.setattr(alerts, "send_alert", lambda t, **kw: (sent_texts.append(kw["summary"]), next(results))[1])
        assert alerts.send_daily_summary() == "undelivered"
        assert alerts.send_daily_summary() == "delivered"
        assert sent_texts == ["built at call 0", "built at call 0"]

    def test_a_failing_settings_write_is_logged_and_the_day_is_not_recorded(
        self, real_loop, world, send, monkeypatch, caplog
    ):
        send(OK)
        monkeypatch.setitem(alerts.__dict__, "__set_global_setting", lambda key, value: False)
        real_loop(3)
        assert "daily_summary_sent could not be stored" in caplog.text
        assert self._stored() == "2026-10-06"

    def test_set_global_setting_says_whether_it_wrote(self, db, monkeypatch):
        from jen.models import db as dbmod
        from jen.models.user import set_global_setting

        assert set_global_setting("q157_probe", "1") is True

        def down():
            raise RuntimeError("database down")

        monkeypatch.setattr(dbmod, "jen_db", down)
        assert set_global_setting("q157_probe", "2") is False

    def test_a_save_state_that_cannot_be_stored_warns(self, db, monkeypatch, caplog):
        monkeypatch.setitem(alerts.__dict__, "__set_global_setting", lambda key, value: False)
        alerts._save_state("utilization_high", 3, {"a": True, "n": True, "t": None, "c": 0, "d": None, "r": False})
        assert "could not be stored" in caplog.text


class TestTheSummaryWaitsForSettingsItCanRead:
    """v5.68.0-beta.22 (Q157, item 13): `_summary_sent_date()` read through an EMPTY cache when the Jen database was down at start (`""` and
    `"07:00"`): a start at 12:00 decided "07:00 has passed, today is sent" and skipped a configured 20:00 summary that day."""

    def test_the_database_down_for_the_first_cycles_then_up_the_20_00_summary_is_sent(self, db, monkeypatch, real_loop):
        from jen.models import db as dbmod
        from jen.models import user as usermod
        from jen.models.user import set_global_setting

        set_global_setting("daily_summary_time", "20:00")
        set_global_setting("daily_summary_sent", "")
        sent = []
        monkeypatch.setattr(alerts, "send_daily_summary", lambda: sent.append(alerts._utcnow()) or "delivered")
        # the process just started: nothing was ever read
        monkeypatch.setattr(usermod, "_settings_cache", {})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 0)
        monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        state = {"up": False}
        real = dbmod.jen_db

        import contextlib

        @contextlib.contextmanager
        def flaky():
            if not state["up"]:
                raise RuntimeError("the Jen database is down")
            with real() as conn:
                yield conn

        monkeypatch.setattr(dbmod, "jen_db", flaky)

        def comes_up(clock):
            state["up"] = True
            usermod._settings_next_try_mono = 0

        def evening(clock):
            clock["now"] = T0.replace(hour=19, minute=59, second=30)

        try:
            real_loop(8 * 60 + 8, hooks={13: comes_up, 14: evening})
            assert alerts._summary_sent_date() is not alerts.UNKNOWN
            assert len(sent) == 1 and sent[0].hour == 20, f"sent at {sent}"
        finally:
            set_global_setting("daily_summary_time", "07:00")
            set_global_setting("daily_summary_sent", "")

    def test_while_the_settings_are_unreadable_nothing_is_sent_even_when_the_time_has_passed(
        self, db, monkeypatch, real_loop
    ):
        from jen.models import db as dbmod
        from jen.models import user as usermod

        sent = []
        monkeypatch.setattr(alerts, "send_daily_summary", lambda: sent.append(1) or "delivered")
        monkeypatch.setattr(usermod, "_settings_cache", {})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 0)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        monkeypatch.setattr(dbmod, "jen_db", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        real_loop(5)
        assert sent == []

    def test_the_sentinel_is_what_an_unread_settings_table_gives(self, monkeypatch):
        from jen.models import user as usermod

        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        monkeypatch.setattr(usermod, "_settings_cache_ts", time_now_plus())
        assert alerts._summary_sent_date() is alerts.UNKNOWN


def time_now_plus():
    import time

    return time.time() + 3600  # a cache that is "fresh" so no reload is attempted
