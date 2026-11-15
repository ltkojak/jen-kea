"""v7.1.0-beta.6 (Q237, AP14): `ha_failover` is under the delivery contract.

It was the one alert of `check_alerts` that read nobody's answer: `send_alert`'s result was dropped and the state map was a local of the loop. A failover whose
channels all failed was never tried again, and one across a restart of Jen was never announced. Every test here runs the real `check_ha_state_alert` and the
real `notify_condition` over a settings store that is a dict, with the channels and the clock in the test's hands.
"""

import datetime
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRV = {"id": 1, "name": "kea-a"}


class World:
    def __init__(self):
        self.settings: dict = {}
        self.sent: list = []
        self.events: list = []
        self.delivers = True
        self.stores = True
        self.readable = True
        self.now = datetime.datetime(2026, 11, 15, 12, 0, 0)

    def later(self, minutes):
        self.now += datetime.timedelta(minutes=minutes)

    def restart(self):
        """A new process: what was only in memory is gone, what was stored is there."""
        from jen.services import alerts

        alerts._unsaved_states.clear()


@pytest.fixture()
def world(monkeypatch):
    from jen import extensions
    from jen.services import alerts

    w = World()

    def send(alert_type, **kwargs):
        w.sent.append((alert_type, kwargs["old_state"], kwargs["new_state"], kwargs["server_name"]))
        return [("telegram", w.delivers, "")]

    def store(key, value):
        if w.stores:
            w.settings[key] = value
        return w.stores

    def read(key, default=None, strict=False):
        if strict and not w.readable:
            raise RuntimeError("the Jen database is away")
        # the cached read of a Jen that started with its database down answers its default
        return w.settings.get(key, default) if w.readable else default

    monkeypatch.setattr("jen.services.alerts.__get_global_setting", read)
    monkeypatch.setattr("jen.services.alerts.__set_global_setting", store)
    monkeypatch.setattr("jen.services.alerts.__emit_event", lambda name, **kw: w.events.append((name, kw["detail"])))
    monkeypatch.setattr(alerts, "send_alert", send)
    monkeypatch.setattr(alerts, "_utcnow", lambda: w.now)
    monkeypatch.setattr(extensions, "KEA_SERVERS", [SRV, {"id": 2, "name": "kea-b"}], raising=False)
    alerts._unsaved_states.clear()
    yield w
    alerts._unsaved_states.clear()


def _see(state, srv=SRV):
    from jen.services.alerts import check_ha_state_alert

    return check_ha_state_alert(srv, state)


class TestAFailoverIsAnnouncedOnceAndOnlyWhenSomebodyTookIt:
    def test_the_first_state_ever_seen_announces_nothing_and_is_stored(self, world):
        assert _see("hot-standby") == "first"
        assert world.sent == [] and world.events == []
        assert "alert_state:event:ha_states" in world.settings

    def test_a_change_is_sent_once_and_a_quiet_pass_sends_and_writes_nothing(self, world):
        _see("hot-standby")
        assert _see("partner-down") == "sent"
        assert world.sent == [("ha_failover", "hot-standby", "partner-down", "kea-a")]
        before = dict(world.settings)
        for _ in range(5):
            world.later(1)
            assert _see("partner-down") == "quiet"
        assert len(world.sent) == 1 and world.settings == before
        assert world.events == [("ha.state_changed", "hot-standby -> partner-down")]

    def test_a_failover_nobody_took_is_tried_again_until_somebody_does(self, world):
        _see("hot-standby")
        world.delivers = False
        assert _see("partner-down") == "pending"
        assert _see("partner-down") == "waiting"  # the backoff: not on every five-second pass
        world.later(2)
        assert _see("partner-down") == "pending"
        world.delivers = True
        world.later(5)
        assert _see("partner-down") == "sent"
        assert [s[1:3] for s in world.sent] == [("hot-standby", "partner-down")] * 3
        world.later(60)
        assert _see("partner-down") == "quiet"
        assert len(world.events) == 1  # one observed change, however many attempts

    def test_it_was_recorded_as_announced_whatever_the_channels_said(self, world):
        """The defect itself: after a send nobody took, the next pass must still owe the alert."""
        _see("hot-standby")
        world.delivers = False
        _see("partner-down")
        world.delivers = True
        world.later(10)
        assert _see("partner-down") == "sent"

    def test_two_changes_nobody_was_told_about_are_one_alert_from_the_state_the_operator_knows(self, world):
        _see("hot-standby")
        world.delivers = False
        _see("partner-down")
        world.delivers = True
        world.later(10)
        assert _see("waiting") == "sent"
        assert world.sent[-1][1:3] == ("hot-standby", "waiting")
        assert [e[1] for e in world.events] == ["hot-standby -> partner-down", "partner-down -> waiting"]

    def test_a_state_that_went_back_before_anybody_was_told_ends_with_nothing_sent(self, world):
        _see("hot-standby")
        world.delivers = False
        _see("partner-down")
        world.delivers = True
        world.later(10)
        assert _see("hot-standby") == "cleared"
        world.later(10)
        assert _see("hot-standby") == "quiet"
        assert len(world.sent) == 1  # the one attempt nobody took
        assert len(world.events) == 2  # both changes are in the timeline


class TestARestartForgetsNothing:
    def test_a_failover_while_jen_was_down_is_announced_at_the_first_observation(self, world):
        _see("hot-standby")
        world.restart()
        assert _see("partner-down") == "sent"
        assert world.sent == [("ha_failover", "hot-standby", "partner-down", "kea-a")]

    def test_an_alert_still_owed_is_still_owed_after_a_restart(self, world):
        _see("hot-standby")
        world.delivers = False
        _see("partner-down")
        world.restart()
        world.delivers = True
        world.later(10)
        assert _see("partner-down") == "sent"
        assert len(world.events) == 1  # the change was observed once: the restart does not observe it again

    def test_a_delivered_failover_is_not_sent_again_after_a_restart(self, world):
        _see("hot-standby")
        _see("partner-down")
        world.restart()
        world.later(10)
        assert _see("partner-down") == "quiet"
        assert len(world.sent) == 1

    def test_a_record_that_could_not_be_stored_is_kept_for_the_next_pass(self, world):
        """The Jen database away: nothing is written, and the pass after a delivered alert must not send it again."""
        _see("hot-standby")
        world.stores = False
        assert _see("partner-down") == "sent"
        for _ in range(3):
            world.later(5)
            assert _see("partner-down") == "quiet"
        assert len(world.sent) == 1
        world.stores = True
        _see("partner-down")
        assert '"1":["partner-down","partner-down"]' in world.settings["alert_state:event:ha_states"]

    def test_a_server_that_was_removed_leaves_the_record(self, world):
        from jen import extensions

        _see("hot-standby")
        _see("hot-standby", {"id": 2, "name": "kea-b"})
        extensions.KEA_SERVERS[:] = [SRV]
        _see("partner-down")
        assert '"2"' not in world.settings["alert_state:event:ha_states"]

    def test_each_server_has_its_own_state(self, world):
        other = {"id": 2, "name": "kea-b"}
        _see("hot-standby")
        _see("hot-standby", other)
        assert _see("partner-down", other) == "sent"
        assert _see("hot-standby") == "quiet"
        assert world.sent == [("ha_failover", "hot-standby", "partner-down", "kea-b")]


class TestTheLoopSendsItNoOtherWay:
    def test_ha_failover_reaches_a_channel_only_through_notify_condition(self):
        """Over the whole tree: no `send_alert("ha_failover"` anywhere, one `notify_condition("ha_failover"` call site (the function, called twice in it)."""
        import ast

        direct, through = [], []
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)):
                    continue
                if node.args[0].value != "ha_failover":
                    continue
                name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                (direct if name == "send_alert" else through).append((path.name, name))
        assert direct == []
        assert sorted(set(through)) == [("alerts.py", "_clear_orphan_states"), ("alerts.py", "notify_condition")]

    def test_the_loop_keeps_no_ha_state_of_its_own(self):
        source = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        assert "last_ha_states = " not in source
        assert "check_ha_state_alert(srv, " in source


class TestARecordThatCannotBeReadIsNotAFirstState:
    """(Q238, AW2) `{}` meant "no server has been seen", and it was also what an unreadable record answered: the failover was recorded as the first state, told
    to nobody, and never announced later because it was on record as told."""

    def test_a_failover_seen_while_the_record_cannot_be_read_is_announced_when_it_can(self, world):
        _see("hot-standby")
        before = dict(world.settings)
        world.readable = False
        for _ in range(3):
            assert _see("partner-down") == "unreadable"
        assert world.sent == [] and world.events == [] and world.settings == before
        world.readable = True
        assert _see("partner-down") == "sent"
        assert world.sent == [("ha_failover", "hot-standby", "partner-down", "kea-a")]

    def test_a_jen_that_starts_with_its_database_down_decides_nothing_until_it_is_back(self, world):
        _see("hot-standby")
        world.restart()
        world.readable = False
        assert _see("partner-down") == "unreadable"
        world.readable = True
        assert _see("partner-down") == "sent"

    def test_the_record_is_asked_of_the_table_and_not_of_the_cache(self):
        import inspect

        from jen.services import alerts

        assert '__get_global_setting(_HA_KNOWN, "", strict=True)' in inspect.getsource(alerts._ha_known)

    @pytest.mark.parametrize("stored", ["not json", "[1, 2]", '"a string"'], ids=["not JSON", "a list", "a string"])
    def test_a_damaged_record_is_started_again_and_says_so(self, stored, world, caplog):
        """Decided: with no usable record there is no state to compare with, so the state seen now is recorded and a warning is logged."""
        world.settings["alert_state:event:ha_states"] = stored
        with caplog.at_level("WARNING"):
            assert _see("partner-down") == "first"
        assert "damaged" in caplog.text
        assert _see("hot-standby") == "sent"

    def test_one_damaged_row_starts_that_server_again_and_keeps_the_rest(self, world):
        other = {"id": 2, "name": "kea-b"}
        _see("hot-standby")
        _see("hot-standby", other)
        world.settings["alert_state:event:ha_states"] = '{"1":["hot-standby"],"2":["hot-standby","hot-standby"]}'
        assert _see("partner-down") == "first"
        assert _see("partner-down", other) == "sent"

    def test_an_empty_server_list_drops_nobody(self, world):
        from jen import extensions

        other = {"id": 2, "name": "kea-b"}
        _see("hot-standby")
        _see("hot-standby", other)
        extensions.KEA_SERVERS[:] = []
        _see("partner-down")
        extensions.KEA_SERVERS[:] = [SRV, other]
        assert _see("partner-down", other) == "sent"
