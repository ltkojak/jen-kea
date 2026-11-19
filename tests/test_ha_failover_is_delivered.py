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

    # (Q239, AX1) the fakes stand where the DATABASE is, in `jen.models.user`, and `alerts`' own two wrappers run for real. Q238 faked the wrappers
    # themselves with a `strict`-aware function the product did not have, so every test here passed over a call that raised TypeError on every box
    monkeypatch.setattr("jen.models.user.get_global_setting", read)
    monkeypatch.setattr("jen.models.user.set_global_setting", store)
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
        assert "ha_state_alert_in_the_loop(srv, " in source


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

    def test_the_record_is_asked_of_the_table_and_not_of_the_cache(self, world, monkeypatch):
        """Asked of the real call: what reaches `jen.models.user.get_global_setting` for the HA record carries `strict=True`."""
        asked = []
        monkeypatch.setattr(
            "jen.models.user.get_global_setting",
            lambda key, default=None, strict=False: asked.append((key, strict)) or default,
        )
        _see("hot-standby")
        assert ("alert_state:event:ha_states", True) in asked

    def test_a_mistake_in_the_code_is_raised_and_is_not_a_record_that_cannot_be_read(self, world, monkeypatch):
        """(Q239, AX1) The P1: the reader raised TypeError and the catch-all answered "unreadable" for ever."""

        def broken(key, default=None):
            return default

        monkeypatch.setattr("jen.models.user.get_global_setting", broken)
        with pytest.raises(TypeError):
            _see("hot-standby")

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


def _calls_that_do_not_fit(source: str, where: str) -> list:
    """Every call in `source` of a module-level function of the same module with a keyword that function does not take, or with more positional arguments than
    it has parameters. ONE implementation: the sweep over the tree and the proof that it sees the defect both call it (Q240, AY10)."""
    import ast

    tree = ast.parse(source)
    defs: dict = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            defs[node.name] = None if node.name in defs else node  # defined twice: not judged
    wrong = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        fn = defs.get(node.func.id)
        if fn is None:
            continue
        a = fn.args
        names = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
        for kw in node.keywords:
            if kw.arg is not None and kw.arg not in names and a.kwarg is None:
                wrong.append(f"{where}:{node.lineno} {fn.name}({kw.arg}=...)")
        positional = [x for x in node.args if not isinstance(x, ast.Starred)]
        if a.vararg is None and len(positional) > len(a.posonlyargs) + len(a.args):
            wrong.append(f"{where}:{node.lineno} {fn.name}: {len(positional)} positional")
    return wrong


class TestNoCallPassesWhatItsOwnFunctionDoesNotTake:
    """(Q239, AX1) The class, over the whole tree. A module calls one of its OWN module-level functions with a keyword that function does not take, or with
    more positional arguments than it has parameters: nothing but running that line finds it, and a test that fakes the function hides it."""

    def test_every_call_of_a_module_level_function_fits_its_signature(self):
        wrong = []
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            wrong += _calls_that_do_not_fit(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
        assert not wrong, wrong

    def test_the_sweep_sees_the_defect_it_was_written_for(self):
        """The call of 7.1.0-beta.7, and its two neighbors, through the sweep itself."""
        source = (
            "def __get(key, default=None):\n    return default\n\n"
            "def known():\n    return __get('k', '', strict=True)\n\n"
            "def many():\n    return __get('k', '', 3)\n\n"
            "def fine():\n    return __get('k', default='')\n"
        )
        assert _calls_that_do_not_fit(source, "m.py") == ["m.py:5 __get(strict=...)", "m.py:8 __get: 3 positional"]


class TestAFailedHaCheckEndsTheHaCheckAndNothingElse:
    """(Q240, AY1) Q239 raises a programming error out of `check_ha_state_alert`, and `check_alerts` has one `try` around its whole cycle: the raise skipped
    the servers still to be checked, the lease passes, the certificate conditions and the stale pass, on every cycle."""

    def test_whatever_the_check_raises_is_logged_by_name_and_answered(self, world, monkeypatch, caplog):
        from jen.services import alerts

        def broken(key, default=None):
            return default

        monkeypatch.setattr("jen.models.user.get_global_setting", broken)
        with caplog.at_level("ERROR"):
            assert alerts.ha_state_alert_in_the_loop(SRV, "hot-standby") == "failed"
        assert "HA state alert for kea-a: TypeError" in caplog.text

    @pytest.mark.parametrize("error", [AttributeError("x"), RuntimeError("x"), KeyError("x")])
    def test_any_exception_of_the_check(self, error, monkeypatch):
        from jen.services import alerts

        def raises(srv, state):
            raise error

        monkeypatch.setattr(alerts, "check_ha_state_alert", raises)
        assert alerts.ha_state_alert_in_the_loop(SRV, "hot-standby") == "failed"

    def test_a_check_that_works_answers_what_it_did(self, world):
        from jen.services import alerts

        assert alerts.ha_state_alert_in_the_loop(SRV, "hot-standby") == "first"
        assert alerts.ha_state_alert_in_the_loop(SRV, "partner-down") == "sent"

    def test_the_loop_calls_the_check_only_through_it(self):
        """Over the function itself: `check_alerts` never calls `check_ha_state_alert`, and the one caller of that is the wrapper, inside its own `try`."""
        import ast

        tree = ast.parse((ROOT / "jen/services/alerts.py").read_text(encoding="utf-8"))
        funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

        def calls(fn):
            return [n.func.id for n in ast.walk(funcs[fn]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]

        assert "check_ha_state_alert" not in calls("check_alerts")
        assert calls("check_alerts").count("ha_state_alert_in_the_loop") == 1
        wrapper = funcs["ha_state_alert_in_the_loop"]
        guarded = next(n for n in wrapper.body if isinstance(n, ast.Try))
        assert [h.type.id for h in guarded.handlers] == ["Exception"]
        assert "check_ha_state_alert" in [
            n.func.id for n in ast.walk(guarded) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        callers = [name for name in funcs if name != "check_ha_state_alert" and "check_ha_state_alert" in calls(name)]
        assert callers == ["ha_state_alert_in_the_loop"]


class TestKeaCommandAlwaysAnswersAnObject:
    """(Q242, AZ12) `kea_command` says it always returns a dict. JSON that is not an object was returned as it came, to every caller. A real local
    server answers; nothing of the client is faked."""

    @pytest.fixture
    def answers(self, monkeypatch):
        import http.server
        import threading

        from jen import extensions

        class Handler(http.server.BaseHTTPRequestHandler):
            body = b"null"

            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(type(self).body)))
                self.end_headers()
                self.wfile.write(type(self).body)

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        monkeypatch.setattr(extensions, "KEA_API_URL", f"http://127.0.0.1:{httpd.server_address[1]}")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [], raising=False)
        yield Handler
        httpd.shutdown()

    @pytest.mark.parametrize(
        "body", [b"null", b"7", b'"hot-standby"', b"[7]", b'[["hot-standby"]]', b"[null]", b"true"]
    )
    def test_json_that_is_not_an_object_is_no_reply(self, answers, body):
        from jen.services.kea import kea_command

        answers.body = body
        reply = kea_command("ha-heartbeat")
        assert reply == {"result": 1, "text": "Kea answered with something that is not a reply.", "transport": "error"}

    @pytest.mark.parametrize(
        "body",
        [b'{"result":0,"arguments":{"state":"hot-standby"}}', b'[{"result":0,"arguments":{"state":"hot-standby"}}]'],
    )
    def test_a_reply_is_returned_as_kea_sent_it(self, answers, body):
        from jen.services.kea import kea_command

        answers.body = body
        assert kea_command("ha-heartbeat") == {"result": 0, "arguments": {"state": "hot-standby"}}


class TestTheSmallRowsOfTheHaRecord:
    def test_a_row_that_is_not_a_pair_is_said(self, world, caplog):
        """(Q240, AY7)"""
        _see("hot-standby")
        world.settings["alert_state:event:ha_states"] = '{"1":["hot-standby"],"2":["a","b"]}'
        with caplog.at_level("WARNING"):
            assert _see("partner-down") == "first"
        assert "1 row(s) that cannot be read" in caplog.text

    @pytest.mark.parametrize(
        "answer,state",
        [
            ({"result": 0, "arguments": {"state": "partner-down"}}, "partner-down"),
            ({"result": 0, "arguments": {"state": ""}}, ""),
            ({"result": 0, "arguments": {}}, ""),
            ({"result": 0, "arguments": None}, ""),
            ({"result": 0}, ""),
            ({"result": 2, "text": "'ha-heartbeat' command not supported."}, ""),
            ({"result": 1, "arguments": {"state": "partner-down"}}, ""),
            ({"result": 1, "arguments": ["x"]}, ""),
        ],
        ids=[
            "a state",
            "an empty state",
            "no state",
            "null arguments",
            "no arguments",
            "HA not configured",
            "an error that names a state",
            "an error",
        ],
    )
    def test_what_kea_sends_is_read_as_before_and_says_nothing(self, answer, state, caplog):
        """(Q242, AZ12) Every answer a Kea gives reads as it did at 7.1.0-beta.10 and logs nothing: a result that is not 0 is HA not configured here."""
        from jen.services.alerts import heartbeat_state

        with caplog.at_level("WARNING"):
            assert heartbeat_state(SRV, answer) == state
        assert caplog.text == ""

    @pytest.mark.parametrize(
        "answer,said",
        [
            (None, "the answer is a NoneType"),
            (["x"], "the answer is a list"),
            ("partner-down", "the answer is a str"),
            (7, "the answer is a int"),
            ({"result": 0, "arguments": [{"state": "partner-down"}]}, "its arguments are a list"),
            ({"result": 0, "arguments": []}, "its arguments are a list"),
            ({"result": 0, "arguments": "partner-down"}, "its arguments are a str"),
            ({"result": 0, "arguments": {"state": 7}}, "its state is a int"),
            ({"result": 0, "arguments": {"state": True}}, "its state is a bool"),
            ({"result": 0, "arguments": {"state": ["partner-down"]}}, "its state is a list"),
            ({"result": 0, "arguments": {"state": {"a": "partner-down"}}}, "its state is a dict"),
        ],
    )
    def test_an_answer_of_another_shape_is_no_state_and_is_named_by_its_type_only(self, answer, said, caplog):
        """(Q242, AZ12, AZ14) None of these raises, none is a state, and the line that says so carries the name of the type and nothing of the answer."""
        from jen.services.alerts import heartbeat_state

        with caplog.at_level("WARNING"):
            assert heartbeat_state(SRV, answer) == ""
        assert f"ha-heartbeat from kea-a: {said}, not what Kea sends" in caplog.text
        assert "partner-down" not in caplog.text

    def test_the_loop_reads_the_answer_through_it_and_nowhere_else(self):
        """Source: `check_alerts` holds no `.get` on the heartbeat's answer; the one read is `heartbeat_state`, inside the `if ha_state:` shape below."""
        import ast

        source = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        loop = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "check_alerts")
        text = ast.get_source_segment(source, loop)
        assert text.count('heartbeat_state(srv, __kea_command("ha-heartbeat", server=srv))') == 1
        assert text.count("ha-heartbeat") == 1 and "ha.get(" not in text

    def test_a_heartbeat_with_no_state_is_not_handed_to_the_check(self):
        """(Q240, AY8) The source: in `check_alerts` the one call of the check sits under `if ha_state:`. The loop itself is run in
        `tests/test_alert_delivery.py::...::test_a_heartbeat_that_names_no_state_announces_nothing`."""
        import ast

        tree = ast.parse((ROOT / "jen/services/alerts.py").read_text(encoding="utf-8"))
        loop = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "check_alerts")
        guards = [
            n
            for n in ast.walk(loop)
            if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "ha_state" and not n.orelse
        ]
        assert len(guards) == 1
        assert [c.func.id for c in ast.walk(guards[0]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)] == [
            "ha_state_alert_in_the_loop"
        ]
