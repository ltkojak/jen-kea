"""
tests/test_direct_socket_lock.py
────────────────────────────────
v5.68.0-beta.29 (Q165, edge 3) - the two direct-socket routes (`setup_direct_socket`, `remove_direct_socket`) act on the Kea HOST first and write Jen's own settings last.
beta.28 asked the identity question of a copy at the start, and a `turn_on` that recorded an entry between that question and the final write left the Kea changed and
the write refused. Now:

  * both routes run under `identity_lock` from their first line to their last (`turn_on` waits behind them), and
  * a refusal AFTER the remote change puts the Kea host back as it was (the socket removed again / put back, the daemon restarted) - or, when that fails too, says
    exactly which half is done and what a person does.

No database and no Kea: the route bodies are driven in a bare Flask request context with the wire stubbed (`pytest --noconftest tests/test_direct_socket_lock.py`).
"""

import copy
import inspect
import threading
import time

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen.services import kea_config_edit as ed
from jen.services.kea_changeset import ChangeSetResult

pytest_plugins = ("tests._investigation_world",)

SOCKET = {"socket-type": "http", "socket-address": "10.0.0.5", "socket-port": 8004}
UNIX = {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}
SENTENCE = "Jen's settings could not be read (its database is unavailable): the change to where it reaches this Kea was refused."


def _inner(view):
    """The route's own body, without the login / role decorators (they need a session user), under the SAME identity-lock wrapper the route has."""
    return infra._holding_identity_lock(inspect.unwrap(view))


class TestBothRoutesHoldTheLock:
    def test_the_marker_is_on_both_routes(self):
        for view in (infra.setup_direct_socket, infra.remove_direct_socket):
            assert getattr(view, "__holds_identity_lock__", False), view.__name__

    def test_no_other_route_in_the_module_claims_it(self):
        held = {
            name
            for name, fn in vars(infra).items()
            if inspect.isfunction(fn) and getattr(fn, "__holds_identity_lock__", False) and not name.startswith("_")
        }
        assert held == {"setup_direct_socket", "remove_direct_socket"}


class TestTurnOnWaitsBehindIt:
    def test_a_turn_on_started_while_a_route_holds_the_lock_waits_and_then_sees_the_result(self, world):
        from jen.services import investigation_logging as inv

        release, entered, done = threading.Event(), threading.Event(), threading.Event()
        outcome = {}

        @infra._holding_identity_lock
        def slow_route():
            entered.set()
            release.wait(5)

        t1 = threading.Thread(target=slow_route)
        t1.start()
        assert entered.wait(5)

        def run_turn_on():
            outcome["out"] = inv.turn_on(world.servers[0], 5, actor="alice")
            done.set()

        t2 = threading.Thread(target=run_turn_on)
        t2.start()
        time.sleep(0.4)
        assert not done.is_set(), "turn_on went ahead while a direct-socket route held the identity lock"
        release.set()
        t1.join(5)
        t2.join(10)
        assert done.is_set() and outcome["out"]["ok"]


@pytest.fixture
def wire(monkeypatch):
    """Everything the two route bodies reach, stubbed: one Kea server, a change set that records what it was asked, a config write that can be made to refuse."""
    log = {"flashes": [], "applies": [], "audits": [], "held_during_apply": [], "state": "ok"}
    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8000"}
    monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
    monkeypatch.setattr(infra, "flash", lambda text, style="message": log["flashes"].append((style, str(text))))
    monkeypatch.setattr(infra, "_server_by_id", lambda sid: server)
    monkeypatch.setattr(infra, "_daemon_creds", lambda s, svc: ("u", "p"))
    monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("Kea 3.0.3", None))
    monkeypatch.setattr(infra, "_identify_daemon", lambda *a, **k: "Dhcp4")
    monkeypatch.setattr("jen.services.capabilities.is_ca", lambda: False)
    monkeypatch.setattr("jen.services.kea.kea_command", lambda *a, **k: {"result": 1})
    monkeypatch.setattr(jconfig.app_config, "preflight_identity_change", lambda change: None)
    monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: log["audits"].append(a))
    monkeypatch.setattr(infra.__dict__["__user"], "set_global_setting", lambda *a, **k: True)

    def apply_change(service, mutate_fn, summary, **kw):
        log["held_during_apply"].append(jconfig.identity_lock._is_owned())
        log["applies"].append((summary, mutate_fn))
        result = log["results"].pop(0)
        return result

    monkeypatch.setattr("jen.services.kea_changeset.apply_change", apply_change)
    log["results"] = []
    log["server"] = server
    return log


def _post(view, **data):
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST", data=data):
        return view(1, "dhcp4")


def _ok(text="applied"):
    return ChangeSetResult("ok", "ok", [("success", text)])


class TestALateRefusalOnSetupPutsTheHostBack:
    FORM = {"scheme": "http", "address": "10.0.0.5", "port": "8004", "user": "u", "password": "p"}

    def _refuse_the_write(self, monkeypatch):
        def refuse(*a, **k):
            raise jconfig.ConfigChangeRefused(SENTENCE)

        monkeypatch.setattr(infra, "_write_direct_socket_config", refuse)

    def test_the_change_runs_under_the_lock(self, wire, monkeypatch):
        wire["results"] = [_ok()]
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert wire["held_during_apply"] == [True]

    def test_the_socket_this_request_added_is_taken_out_again_and_the_daemon_restarted(self, wire, monkeypatch):
        self._refuse_the_write(monkeypatch)
        wire["results"] = [_ok("socket added"), _ok("socket removed")]
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert len(wire["applies"]) == 2 and wire["held_during_apply"] == [True, True]
        summary, mutate = wire["applies"][1]
        assert "removed the control socket" in summary
        with_socket = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}}
        after, code = mutate(with_socket)
        assert code == "ok" and after["Dhcp4"]["control-sockets"] == [UNIX]
        texts = " ".join(t for _s, t in wire["flashes"])
        assert SENTENCE in texts and "was undone" in texts and "PARTIAL" not in texts
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_COMPENSATED"]

    def test_when_the_host_cannot_be_put_back_the_partial_state_is_named(self, wire, monkeypatch):
        self._refuse_the_write(monkeypatch)
        wire["results"] = [_ok(), ChangeSetResult("rolled_back", "error", [("error", "the daemon did not restart")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "PARTIAL STATE on kea-a" in texts and "rolled_back" in texts and "Remove socket" in texts
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_PARTIAL"]

    def test_a_socket_that_was_already_there_is_not_removed(self, wire, monkeypatch):
        self._refuse_the_write(monkeypatch)
        wire["results"] = [ChangeSetResult("nothing", "nochange", [("success", "already has exactly this socket")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert len(wire["applies"]) == 1, "only the one change-set call: nothing to undo"
        texts = " ".join(t for _s, t in wire["flashes"])
        assert SENTENCE in texts and "already in" in texts and not wire["audits"]


class TestALateRefusalOnRemovalPutsTheSocketBack:
    def _refuse(self, monkeypatch):
        def refuse(self_, fn, *a, **k):
            raise jconfig.ConfigChangeRefused(SENTENCE)

        monkeypatch.setattr(type(jconfig.app_config), "mutate", refuse)

    def test_the_removed_entry_is_set_again_exactly_as_it_was(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        before = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}}

        def run_removal(service, mutate_fn, summary, **kw):
            wire["held_during_apply"].append(jconfig.identity_lock._is_owned())
            wire["applies"].append((summary, mutate_fn))
            if len(wire["applies"]) == 1:
                after, code = mutate_fn(copy.deepcopy(before))
                assert code == "ok" and after["Dhcp4"]["control-sockets"] == [UNIX]
            return _ok()

        monkeypatch.setattr("jen.services.kea_changeset.apply_change", run_removal)
        _post(_inner(infra.remove_direct_socket))
        assert len(wire["applies"]) == 2 and wire["held_during_apply"] == [True, True]
        summary, put_back = wire["applies"][1]
        assert "put the kea-dhcp4 control socket back" in summary
        restored, code = put_back({"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX)]}})
        assert code == "ok" and restored["Dhcp4"]["control-sockets"] == [UNIX, SOCKET]
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "was undone" in texts and SENTENCE in texts

    def test_when_it_cannot_be_put_back_the_by_hand_step_names_the_entry(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        calls = []

        def run(service, mutate_fn, summary, **kw):
            calls.append(summary)
            if len(calls) == 1:
                mutate_fn({"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}})
                return _ok()
            return ChangeSetResult("rollback_failed", "restart-failed", [("error", "the daemon did not restart")])

        monkeypatch.setattr("jen.services.kea_changeset.apply_change", run)
        _post(_inner(infra.remove_direct_socket))
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "PARTIAL STATE on kea-a" in texts and "10.0.0.5" in texts and "8004" in texts

    def test_with_no_socket_to_remove_nothing_is_undone(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        wire["results"] = [
            ChangeSetResult("nothing", "nochange", [("success", "no http/https control socket to remove")])
        ]
        _post(_inner(infra.remove_direct_socket))
        assert len(wire["applies"]) == 1
        assert ed.remove_control_socket({"Dhcp4": {"control-sockets": [UNIX]}}, "dhcp4")[1] == "nochange"
