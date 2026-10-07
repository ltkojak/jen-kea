"""
tests/test_alert_state.py
─────────────────────────
v5.68.0-beta.18 (Q153) - every threshold alert has a transition state that survives a restart, and pool exhaustion has one at all.

`utilization_high/_ok` and `packet_health/_ok` remembered which side a condition was on in a local set of `check_alerts()` - lost on every
restart, so each upgrade re-sent every alert whose condition was still true and never sent the `_ok` for one that cleared while Jen was
down - and `pool_exhaustion` had no memory whatever and re-sent every cycle. The state is `alert_state:<type>:<key>` in the settings table. A
"restart" in these tests is a fresh call with nothing carried over but the database (the state used to live in the caller's locals).
"""

import pytest

from jen import extensions
from jen.services import alerts

A_RANGE = [{"pool": "10.81.0.10 - 10.81.0.29"}]  # 20 addresses
TWO_POOLS = [
    {"pool": "10.81.0.10 - 10.81.0.59"},
    {"pool": "10.81.1.0 - 10.81.1.199"},
]  # 50 (offsets 10-59) + 200 (offsets 256-455)


def _cfg(pools, sid=1):
    return {"subnet4": [{"id": sid, "subnet": "10.81.0.0/16", "pools": pools}]}


def _ip(n):
    import ipaddress

    return int(ipaddress.IPv4Address("10.81.0.0")) + n


@pytest.fixture
def world(db, monkeypatch):
    """Subnet 1 'A' known to Jen, a recorded alert sender, a clean lease table for 10.81.0.0/16, threshold 80 %, exhaustion at 5 free."""
    from jen.models.user import set_global_setting

    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.81.0.0/16"}})
    sent = []
    monkeypatch.setattr(alerts, "send_alert", lambda t, *a, **kw: sent.append((t, kw)))
    set_global_setting("alert_threshold_pct", "80")
    set_global_setting("pool_exhaustion_free", "5")
    _wipe(db)
    yield sent
    _wipe(db)


def _wipe(db):
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM lease4 WHERE subnet_id=1 AND address BETWEEN INET_ATON('10.81.0.0') AND INET_ATON('10.81.255.255')"
        )
    db.commit()


def _lease(db, n, *, expired=False, subnet_id=1):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) VALUES "
            f"(%s, UNHEX(%s), 3600, {'DATE_SUB(NOW(), INTERVAL 1 HOUR)' if expired else 'DATE_ADD(NOW(), INTERVAL 1 HOUR)'}, %s, 0)",  # nosec B608 - test seed
            (_ip(n), f"AABB0000{n:04X}", subnet_id),
        )
    db.commit()


def _fill(db, first, count):
    for n in range(first, first + count):
        _lease(db, n)


def _drain(db, first, count):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE address BETWEEN %s AND %s", (_ip(first), _ip(first + count - 1)))
    db.commit()


def _pass(db, pools):
    """One pass of the alert loop's utilisation check - everything a restart would lose is passed in fresh each time."""
    with db.cursor() as cur:
        alerts.check_utilization_alerts(cur, _cfg(pools))


def _types(sent):
    return [t for t, _ in sent]


class TestPoolExhaustion:
    def test_repeated_passes_while_exhausted_send_one_alert(self, db, world):
        _fill(db, 10, 17)  # 20 - 17 = 3 free <= 5
        for _ in range(5):
            _pass(db, A_RANGE)
        assert _types(world).count("pool_exhaustion") == 1

    def test_it_recovers_with_hysteresis_and_re_arms(self, db, world):
        _fill(db, 10, 17)  # 3 free
        _pass(db, A_RANGE)
        assert _types(world).count("pool_exhaustion") == 1
        _drain(db, 10, 2)  # 5 free: at the line, inside the margin -> still alerted, nothing sent
        _pass(db, A_RANGE)
        _drain(db, 12, 1)  # 6 free: still below N + max(2, N // 5) = 7
        _pass(db, A_RANGE)
        assert "pool_exhaustion_ok" not in _types(world), "no flapping around the line"
        _drain(db, 13, 1)  # 7 free: recovered
        _pass(db, A_RANGE)
        assert _types(world).count("pool_exhaustion_ok") == 1
        _fill(db, 10, 4)  # 20 - 17 = 3 free again: re-armed, fires again once
        _pass(db, A_RANGE)
        assert _types(world).count("pool_exhaustion") == 2

    def test_the_recovery_carries_the_free_count(self, db, world):
        _fill(db, 10, 18)
        _pass(db, A_RANGE)
        _drain(db, 10, 10)
        _pass(db, A_RANGE)
        ok = next(kw for t, kw in world if t == "pool_exhaustion_ok")
        assert ok["free"] == 12 and ok["subnet"] == "A" and ok["subnet_id"] == 1

    def test_the_hysteresis_margin_scales_with_the_threshold(self, db, world):
        from jen.models.user import set_global_setting

        set_global_setting("pool_exhaustion_free", "20")  # fires at 20 free, recovers at 20 + max(2, 20 // 5) = 24 free
        _fill(db, 10, 50)
        _fill(db, 256, 180)  # 230 of 250 used: 20 free
        _pass(db, TWO_POOLS)
        assert _types(world).count("pool_exhaustion") == 1
        _drain(db, 256, 3)  # 23 free: inside the margin
        _pass(db, TWO_POOLS)
        assert "pool_exhaustion_ok" not in _types(world)
        _drain(db, 259, 1)  # 24 free
        _pass(db, TWO_POOLS)
        assert _types(world).count("pool_exhaustion_ok") == 1


class TestTwoPoolsOneSubnet:
    def test_a_subnet_is_judged_once_over_the_union_not_per_pool(self, db, world):
        """100 active leases over pools of 50 and 200 used to read as 200 % of the first pool and 50 % of the second, and flip the subnet's
        state twice in one pass. Over the union it is 100/250 = 40 %: nothing to say."""
        _fill(db, 256, 100)  # all inside the 200-address pool
        _pass(db, TWO_POOLS)
        assert world == []

    def test_high_utilisation_is_judged_on_the_union_and_reports_it(self, db, world):
        _fill(db, 10, 50)
        _fill(db, 256, 150)  # 200 of 250 = 80 %
        _pass(db, TWO_POOLS)
        assert _types(world) == ["utilization_high"]
        kw = world[0][1]
        assert (kw["used"], kw["total"], kw["pct"]) == (200, 250, 80)

    def test_a_pass_never_sends_one_subnets_alert_twice(self, db, world):
        _fill(db, 10, 50)
        _fill(db, 256, 150)
        for _ in range(4):
            _pass(db, TWO_POOLS)
        assert _types(world).count("utilization_high") == 1

    def test_a_reservation_outside_every_pool_is_not_pool_consumption(self, db, world):
        _fill(db, 10, 15)  # 15 of 20 in the pool = 75 %
        _fill(db, 40, 5)  # five active leases OUTSIDE the pool (reservations): they are not dynamic consumption
        _pass(db, A_RANGE)
        assert "utilization_high" not in _types(world), "75 %, not 100 %"

    def test_an_expired_lease_in_the_pool_is_not_consumption(self, db, world):
        _fill(db, 10, 13)
        for n in range(23, 29):
            _lease(db, n, expired=True)
        _pass(db, A_RANGE)
        assert world == []


class TestUtilisationAcrossARestart:
    def test_a_restart_in_the_middle_of_the_condition_sends_nothing(self, db, world):
        _fill(db, 10, 17)  # 85 % and 3 free: both alert
        _pass(db, A_RANGE)
        assert sorted(_types(world)) == ["pool_exhaustion", "utilization_high"]
        world.clear()
        # the process restarts: no memory but the database
        _pass(db, A_RANGE)
        assert world == [], "it used to re-send utilization_high on every restart"

    def test_a_condition_that_cleared_while_jen_was_down_sends_its_ok_once(self, db, world):
        _fill(db, 10, 17)
        _pass(db, A_RANGE)
        world.clear()
        _drain(db, 10, 17)  # cleared while Jen was not running
        _pass(db, A_RANGE)  # the first pass after the restart
        _pass(db, A_RANGE)
        assert sorted(_types(world)) == ["pool_exhaustion_ok", "utilization_ok"], "each recovery exactly once"

    def test_the_state_is_a_settings_row_named_for_the_type_and_the_key(self, db, world):
        _fill(db, 10, 17)
        _pass(db, A_RANGE)
        with db.cursor() as cur:
            cur.execute(
                "SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'alert_state:%' ORDER BY setting_key"
            )
            rows = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}
        assert rows == {"alert_state:pool_exhaustion:1": "1", "alert_state:utilization_high:1": "1"}

    def test_a_subnet_without_a_readable_pool_is_skipped(self, db, world):
        _fill(db, 10, 3)
        _pass(db, [])
        _pass(db, [{"pool": "junk"}])
        assert world == []


class TestPacketHealthAcrossARestart:
    def _stats(self, db, minutes_ago, stats):
        import json

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO server_stats (server_id, snapshot_time, stats) VALUES (1, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s)",
                (minutes_ago, json.dumps(stats)),
            )
        db.commit()

    def test_a_restart_neither_re_alerts_nor_loses_the_recovery(self, db, monkeypatch):
        sent = []
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea", "api_url": "http://x"}])
        monkeypatch.setattr(alerts, "send_alert", lambda t, *a, **kw: sent.append(t))
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._stats(db, 30, {"pkt4-received": 100, "pkt4-receive-drop": 0})
        self._stats(db, 0, {"pkt4-received": 200, "pkt4-receive-drop": 50})
        alerts._check_packet_health_alerts()
        alerts._check_packet_health_alerts()  # a restart between the two: the state is in the database
        assert sent == ["packet_health"]
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._stats(db, 30, {"pkt4-received": 100, "pkt4-receive-drop": 0})
        self._stats(db, 0, {"pkt4-received": 200, "pkt4-receive-drop": 0})
        alerts._check_packet_health_alerts()
        alerts._check_packet_health_alerts()
        assert sent == ["packet_health", "packet_health_ok"]


class TestThePieces:
    def test_the_new_alert_type_is_registered_everywhere_a_type_must_be(self):
        t = "pool_exhaustion_ok"
        assert t in alerts.ALERT_TYPE_ICONS and t in alerts.ALERT_TYPE_LABELS and t in alerts.DEFAULT_TEMPLATES
        assert alerts.DEFAULT_TEMPLATES[t].startswith(alerts.GLYPH_LEGEND[2][0]), "a recovery is the green glyph"

    def test_check_alerts_keeps_no_local_transition_sets(self):
        import inspect

        src = inspect.getsource(alerts.check_alerts)
        assert "alerted_high_subnets" not in src and "alerted_packet_health" not in src
        assert "check_utilization_alerts" in src
