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
    def test_the_beta_18_values_read_as_active_and_notified(self, db):
        from jen.models.user import set_global_setting

        set_global_setting("alert_state:utilization_high:3", "1")
        set_global_setting("alert_state:utilization_high:4", "0")
        assert alerts.alert_delivery("utilization_high", 3) == {
            "active": True,
            "notified": True,
            "attempts": 0,
            "last_attempt": None,
        }
        assert alerts.alert_state("utilization_high", 4) is False

    def test_an_active_old_state_is_not_re_sent_on_upgrade_and_does_recover(self, db, send):
        from jen.models.user import set_global_setting

        sender = send(OK)
        set_global_setting("alert_state:utilization_high:3", "1")
        alerts.notify_condition("utilization_high", 3, True, kwargs={}, ok_type="utilization_ok", now=T0)
        assert sender.sent == []
        alerts.notify_condition("utilization_high", 3, False, kwargs={}, ok_type="utilization_ok", now=T0)
        assert sender.sent == ["utilization_ok"]
