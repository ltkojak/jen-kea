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
import json
import threading
import time

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen.services import kea_config_edit as ed
from jen.services.kea_authoring import build_control_socket
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


SECRET = "TOPSECRET-socket-password"
FORM_PASSWORD = "FORMPW-from-the-superadmin"
CLIENT_SOCKET = {  # a socket with a Basic client and TLS: everything a text must never print
    "socket-type": "https",
    "socket-address": "10.0.0.7",
    "socket-port": 8005,
    "authentication": {"type": "basic", "realm": "kea", "clients": [{"user": "su", "password": SECRET}]},
    "trust-anchor": "/etc/kea/tls/ca.crt",
    "cert-file": "/etc/kea/tls/server.crt",
    "key-file": "/etc/kea/tls/server.key",
    "cert-required": True,
}
JEN_CONFIG = """[kea]
api_url = http://10.0.0.5:8004
api_user = u
api_pass = p
connection_mode = direct
direct_prev_api_url = http://10.0.0.5:8000
[kea_db]
host = db1
[jen_db]
host = jh
"""


@pytest.fixture
def wire(monkeypatch, caplog):
    """Everything the two route bodies reach, stubbed: one Kea server, a change set that records what it was asked and APPLIES it to a simulated host config (so a compensation can be
    compared with the original, byte for byte), a config write that can be made to refuse."""
    import configparser
    import logging

    caplog.set_level(logging.DEBUG)
    log = {
        "flashes": [],
        "applies": [],
        "audits": [],
        "held_during_apply": [],
        "results": [],  # a forced ChangeSetResult per call (the mutate still runs on the simulated host)
        "codes": [],
        "host": {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX)]}},
    }
    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8000"}
    monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
    monkeypatch.setattr(infra, "flash", lambda text, style="message": log["flashes"].append((style, str(text))))
    monkeypatch.setattr(infra, "_server_by_id", lambda sid: server)
    monkeypatch.setattr(infra, "_daemon_creds", lambda s, svc, url="": ("u", "p"))
    monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("Kea 3.0.3", None))
    monkeypatch.setattr(
        infra, "_identify_daemon", lambda url, *a, **k: "Control-agent" if ":8000" in url else "Dhcp4"
    )  # the saved Control Agent address (:8000) answers as one; a daemon's own socket as the daemon
    monkeypatch.setattr(
        infra,
        "_api_sockets_of",
        lambda s, svc: [x for x in ed.control_sockets(log["host"], svc) if ed._is_api_socket(x)],
    )

    def fresh_parser():
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(JEN_CONFIG)
        return parser

    monkeypatch.setattr(jconfig.app_config, "_read_parser", fresh_parser)
    monkeypatch.setattr("jen.services.capabilities.is_ca", lambda: False)
    monkeypatch.setattr("jen.services.kea.kea_command", lambda *a, **k: {"result": 1})
    monkeypatch.setattr(jconfig.app_config, "preflight_identity_change", lambda change, typed=None: None)
    monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: log["audits"].append(a))
    monkeypatch.setattr(infra.__dict__["__user"], "set_global_setting", lambda *a, **k: True)

    def apply_change(service, mutate_fn, summary, **kw):
        log["held_during_apply"].append(jconfig.identity_lock._is_owned())
        log["applies"].append((summary, mutate_fn))
        forced = log["results"].pop(0) if log["results"] else None
        after, code = mutate_fn(copy.deepcopy(log["host"]))
        log["codes"].append(code)
        if forced is not None:
            if forced.status == "ok" and code == "ok":
                log["host"] = after
            return forced
        if code == "ok":
            log["host"] = after
            return _ok()
        if code in ("nochange", "notfound"):
            return ChangeSetResult("nothing", code, [("success", code)])
        return ChangeSetResult("aborted", code, [("error", kw.get("code_messages", {}).get(code, code))])

    monkeypatch.setattr("jen.services.kea_changeset.apply_change", apply_change)
    log["server"] = server
    log["caplog"] = caplog
    return log


def _post(view, service="dhcp4", **data):
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST", data=data):
        return view(1, service)


def _ok(text="applied"):
    return ChangeSetResult("ok", "ok", [("success", text)])


def _everything_printed(wire) -> str:
    """Every flash, every audit row and every log line of a run - the places a recovery sentence could leak a socket's entry."""
    return " ".join(
        [t for _s, t in wire["flashes"]]
        + [str(a) for a in wire["audits"]]
        + [r.getMessage() for r in wire["caplog"].records]
    )


def _refuse_the_write(monkeypatch):
    def refuse(*a, **k):
        raise jconfig.ConfigChangeRefused(SENTENCE)

    monkeypatch.setattr(infra, "_write_direct_socket_config", refuse)


class TestALateRefusalOnSetupPutsTheHostBack:
    FORM = {"scheme": "http", "address": "10.0.0.5", "port": "8004", "user": "u", "password": "p"}

    def test_the_change_runs_under_the_lock(self, wire, monkeypatch):
        wire["results"] = [_ok()]
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert wire["held_during_apply"] == [True]

    def test_the_socket_this_request_added_is_taken_out_again_and_the_daemon_restarted(self, wire, monkeypatch):
        _refuse_the_write(monkeypatch)
        before = copy.deepcopy(wire["host"])
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert len(wire["applies"]) == 2 and wire["held_during_apply"] == [True, True]
        assert "restored the control sockets as they were before" in wire["applies"][1][0]
        assert wire["host"] == before, "the daemon's control-sockets are exactly what they were"
        texts = " ".join(t for _s, t in wire["flashes"])
        assert SENTENCE in texts and "was undone" in texts and "PARTIAL" not in texts
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_COMPENSATED"]

    def test_when_the_host_cannot_be_put_back_the_partial_state_is_named(self, wire, monkeypatch):
        _refuse_the_write(monkeypatch)
        wire["results"] = [_ok(), ChangeSetResult("rolled_back", "error", [("error", "the daemon did not restart")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "PARTIAL STATE on kea-a" in texts and "rolled_back" in texts and "http 10.0.0.5:8004" in texts
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_PARTIAL"]

    def test_a_socket_that_was_already_there_is_not_removed(self, wire, monkeypatch):
        _refuse_the_write(monkeypatch)
        wire["host"] = {
            "Dhcp4": {
                "control-sockets": [copy.deepcopy(UNIX), build_control_socket("http", "10.0.0.5", 8004, "u", "p")]
            }
        }
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert len(wire["applies"]) == 1, "only the one change-set call: nothing to undo"
        texts = " ".join(t for _s, t in wire["flashes"])
        assert SENTENCE in texts and "already in" in texts and not wire["audits"]

    # ── AB1 (Q186): the compensation restores the SNAPSHOT, not an inverse ────────────────────────────────────────────────────────────────────
    def test_replacing_an_existing_socket_then_a_failed_write_puts_the_original_back_byte_equal(
        self, wire, monkeypatch
    ):
        """The old compensation deleted every http/https entry and never restored the one `set_control_socket` had REPLACED."""
        _refuse_the_write(monkeypatch)
        wire["host"] = {
            "Dhcp4": {"a": 1, "control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)], "z": 2}
        }
        original = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert json.dumps(wire["host"]) == original, "the ORIGINAL https socket (auth + TLS) is back, key for key"
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "was undone" in texts and "PARTIAL" not in texts
        assert SECRET not in _everything_printed(wire)

    def test_a_config_with_a_unix_socket_only_comes_back_as_unix_only(self, wire, monkeypatch):
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert wire["host"] == {"Dhcp4": {"control-sockets": [UNIX]}}

    def test_a_write_that_fails_with_an_oserror_is_compensated_the_same_way(self, wire, monkeypatch):
        def fail(*a, **k):
            raise OSError(30, "Read-only file system")

        monkeypatch.setattr(infra, "_write_direct_socket_config", fail)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        original = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert json.dumps(wire["host"]) == original

    def test_the_compensations_own_restart_failing_is_the_partial_state_with_no_secret_anywhere(
        self, wire, monkeypatch
    ):
        _refuse_the_write(monkeypatch)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        wire["results"] = [
            _ok(),
            ChangeSetResult("rollback_failed", "restart-failed", [("error", "the daemon did not restart")]),
        ]
        form = dict(self.FORM, password=FORM_PASSWORD)
        _post(_inner(infra.setup_direct_socket), **form)
        printed = _everything_printed(wire)
        assert "PARTIAL STATE on kea-a" in printed and "Config History" in printed and "last revision" in printed
        assert "http 10.0.0.5:8004" in printed
        assert SECRET not in printed and FORM_PASSWORD not in printed
        assert "clients" not in printed and "'password'" not in printed and "key-file" not in printed
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_PARTIAL"]

    def test_a_file_that_already_matches_is_not_reported_as_undone(self, wire, monkeypatch):
        """If the restore finds the list already equal, nothing was rewritten and the daemon was not restarted by it: the daemon may still run the change, so it is the partial state."""
        _refuse_the_write(monkeypatch)
        wire["results"] = [_ok(), ChangeSetResult("nothing", "nochange", [("success", "already as it was")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        printed = _everything_printed(wire)
        assert "PARTIAL STATE" in printed and "not restarted by this undo" in printed and "was undone" not in printed

    def test_no_snapshot_means_no_claim_of_an_undo(self, wire, monkeypatch):
        """A plan that never read the config (the callback never ran) has nothing to restore: the by-hand text, never 'undone'."""
        _refuse_the_write(monkeypatch)
        monkeypatch.setattr(
            "jen.services.kea_changeset.apply_change", lambda *a, **k: _ok()
        )  # a change set that applies without ever calling the planner's callback
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        printed = _everything_printed(wire)
        assert "PARTIAL STATE" in printed and "no-snapshot" in printed and "was undone" not in printed

    def test_a_daemon_with_two_api_sockets_is_refused_before_anything_is_sent(self, wire, monkeypatch):
        wire["host"] = {
            "Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET), copy.deepcopy(CLIENT_SOCKET)]}
        }
        before = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert wire["applies"] == [], "refused before apply_change - and before any TLS material"
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "2 API sockets" in texts and "remove the others by hand" in texts
        assert json.dumps(wire["host"]) == before

    def test_a_second_socket_that_appears_after_the_check_aborts_the_plan_not_the_file(self, wire, monkeypatch):
        """The pre-read said one, the plan sees two (a hand edit between): `set_control_socket` answers `multiple` and the change set aborts before any write."""
        monkeypatch.setattr(infra, "_api_sockets_of", lambda s, svc: [])
        wire["host"] = {
            "Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET), copy.deepcopy(CLIENT_SOCKET)]}
        }
        before = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "more than one API socket" in texts and "were not changed" in texts
        assert json.dumps(wire["host"]) == before


class TestALateRefusalOnRemovalPutsTheSocketBack:
    def _refuse(self, monkeypatch):
        def refuse(self_, fn, *a, **k):
            raise jconfig.ConfigChangeRefused(SENTENCE)

        monkeypatch.setattr(type(jconfig.app_config), "mutate", refuse)

    def test_the_removed_entry_is_back_exactly_as_it_was(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        wire["host"] = {"Dhcp4": {"a": 1, "control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        original = json.dumps(wire["host"])
        _post(_inner(infra.remove_direct_socket))
        assert len(wire["applies"]) == 2 and wire["held_during_apply"] == [True, True]
        assert "put the kea-dhcp4 control socket back" in wire["applies"][1][0]
        assert json.dumps(wire["host"]) == original, (
            "the https socket with its authentication and TLS is back, key for key"
        )
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "was undone" in texts and SENTENCE in texts
        assert SECRET not in _everything_printed(wire)

    def test_the_removal_takes_out_only_the_named_socket(self, wire, monkeypatch):
        monkeypatch.setattr(type(jconfig.app_config), "mutate", lambda self_, fn, *a, **k: None)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}}
        _post(_inner(infra.remove_direct_socket))
        assert wire["host"] == {"Dhcp4": {"control-sockets": [UNIX]}}

    def test_a_daemon_with_two_api_sockets_is_refused_before_anything_is_sent(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        wire["host"] = {
            "Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET), copy.deepcopy(CLIENT_SOCKET)]}
        }
        before = json.dumps(wire["host"])
        _post(_inner(infra.remove_direct_socket))
        assert wire["applies"] == []
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "2 API sockets" in texts and "Jen manages one" in texts
        assert json.dumps(wire["host"]) == before

    def test_when_it_cannot_be_put_back_the_by_hand_step_describes_the_socket_and_prints_no_secret(
        self, wire, monkeypatch
    ):
        self._refuse(monkeypatch)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        wire["results"] = [
            _ok(),
            ChangeSetResult("rollback_failed", "restart-failed", [("error", "the daemon did not restart")]),
        ]
        _post(_inner(infra.remove_direct_socket))
        printed = _everything_printed(wire)
        assert "PARTIAL STATE on kea-a" in printed and "https 10.0.0.7:8005" in printed
        assert "Config History" in printed and "last revision" in printed
        assert SECRET not in printed and "key-file" not in printed and "trust-anchor" not in printed
        assert [a[0] for a in wire["audits"]] == ["DIRECT_SOCKET_PARTIAL"]

    def test_with_no_socket_to_remove_nothing_is_undone(self, wire, monkeypatch):
        self._refuse(monkeypatch)
        wire["results"] = [
            ChangeSetResult("nothing", "nochange", [("success", "no http/https control socket to remove")])
        ]
        _post(_inner(infra.remove_direct_socket))
        assert len(wire["applies"]) == 1
        assert ed.remove_control_socket({"Dhcp4": {"control-sockets": [UNIX]}}, "dhcp4")[1] == "nochange"


class TestAFailedWriteOfJensSettingsIsHandledLikeARefusal:
    """Q182 (X4, step i): the config writer can FAIL after the change set applied (a read-only jen.config, a full disk) - an OSError, not a refusal. The daemon was changed and Jen's
    settings were not: the same compensation, a flash that says what happened, a redirect - never a 500 with the Kea host left half done."""

    def test_setup_puts_the_host_back_and_redirects(self, wire, monkeypatch):
        def fail(*a, **k):
            raise OSError(30, "Read-only file system")

        monkeypatch.setattr(infra, "_write_direct_socket_config", fail)
        before = copy.deepcopy(wire["host"])
        response = _post(_inner(infra.setup_direct_socket), **TestALateRefusalOnSetupPutsTheHostBack.FORM)
        assert response.status_code == 302
        assert len(wire["applies"]) == 2 and "restored the control sockets" in wire["applies"][1][0]
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "could not write its own settings" in texts and "Read-only file system" in texts
        assert "was undone" in texts and "PARTIAL" not in texts
        assert wire["host"] == before

    def test_setup_with_a_socket_that_was_already_there_removes_nothing(self, wire, monkeypatch):
        def fail(*a, **k):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(infra, "_write_direct_socket_config", fail)
        wire["results"] = [ChangeSetResult("nothing", "nochange", [("success", "already has exactly this socket")])]
        response = _post(_inner(infra.setup_direct_socket), **TestALateRefusalOnSetupPutsTheHostBack.FORM)
        assert response.status_code == 302 and len(wire["applies"]) == 1
        assert "could not write its own settings" in " ".join(t for _s, t in wire["flashes"])

    def test_removal_puts_the_socket_back_and_redirects(self, wire, monkeypatch):
        def fail(self_, fn, *a, **k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(type(jconfig.app_config), "mutate", fail)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}}
        original = json.dumps(wire["host"])
        response = _post(_inner(infra.remove_direct_socket))
        assert response.status_code == 302 and len(wire["applies"]) == 2
        assert "put the kea-dhcp4 control socket back" in wire["applies"][1][0]
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "No space left on device" in texts and "was undone" in texts
        assert json.dumps(wire["host"]) == original
