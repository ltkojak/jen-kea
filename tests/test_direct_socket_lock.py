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
import os
import pathlib
import threading
import time

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen.services import kea_config_edit as ed
from jen.services.kea_authoring import build_control_socket
from jen.services.kea_changeset import ChangeSetResult
from tests._fs_flake import retry_transient_replace  # noqa: F401 (autouse)

pytest_plugins = ("tests._investigation_world",)

SOCKET = {"socket-type": "http", "socket-address": "10.0.0.5", "socket-port": 8004}
UNIX = {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}
SENTENCE = "Jen's settings could not be read (its database is unavailable): the change to where it reaches this Kea was refused."


def _inner(view):
    """The route's own body, without the login / role decorators (they need a session user), under the SAME identity-lock wrapper the route has."""
    return infra._holding_identity_lock(inspect.unwrap(view))


class TestBothRoutesHoldTheLock:
    def test_the_marker_is_on_both_routes(self):
        for view in (infra.setup_direct_socket, infra.remove_direct_socket, infra.rotate_kea_ca):
            assert getattr(view, "__holds_identity_lock__", False), view.__name__

    def test_no_other_route_in_the_module_claims_it(self):
        held = {
            name
            for name, fn in vars(infra).items()
            if inspect.isfunction(fn) and getattr(fn, "__holds_identity_lock__", False) and not name.startswith("_")
        }
        assert held == {"setup_direct_socket", "remove_direct_socket", "rotate_kea_ca"}


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
        "incidents": [],  # Q187: what record_attention was asked to keep in front of the operator
        "details": [],  # ... and the by-hand sentence each came with (Q189)
        "resolved": [],  # ... and the (server, service) pairs a verified recovery cleared
        "resolved_categories": [],  # ... and which categories each of those clearings was allowed to clear (None: all)
        "host": {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX)]}},
    }
    server = {
        "id": 1,
        "name": "kea-a",
        "ssh_host": "10.0.0.5",
        "api_url": "http://10.0.0.5:8004",
    }  # (direct mode: Jen dials the daemon's own socket; the saved Control Agent is :8000)
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
        lambda s, svc, errors=None: [x for x in ed.control_sockets(log["host"], svc) if ed._is_api_socket(x)],
    )

    def fresh_parser():
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(JEN_CONFIG)
        return parser

    monkeypatch.setattr(jconfig.app_config, "_read_parser", fresh_parser)
    monkeypatch.setattr(
        "jen.services.kea_changeset.record_attention",
        lambda server_id, service, operation, category, when=None, **kw: (
            (
                log["incidents"].append((server_id, service, category, operation)),
                log["details"].append(kw.get("detail", "")),
            )
            and True
        ),
    )
    monkeypatch.setattr(
        "jen.services.kea_changeset.recovery_incidents",
        lambda strict=False: [
            {"kind": "attention", "category": c, "status": c, "service": s, "server_id": sid, "server_name": "kea-a"}
            for sid, s, c, _op in log["incidents"]
        ],
    )  # (Q189: `kea_tls.host_material` reads the durable record; here it is the list the run recorded)
    monkeypatch.setattr(
        "jen.services.kea_changeset.resolve_attention",
        lambda server_id, service, **kw: (
            log["resolved"].append((server_id, service)) or log["resolved_categories"].append(kw.get("categories")) or 0
        ),
    )
    monkeypatch.setattr("jen.services.capabilities.is_ca", lambda: False)
    monkeypatch.setattr(
        "jen.services.capabilities.is_direct", lambda: True
    )  # (Q188: the endpoint Jen dials is the daemon's own, so a Control Agent answering there is the wrong answer)
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
        monkeypatch.setattr(infra, "_api_sockets_of", lambda s, svc, errors=None: [])
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


# ── Q187 (AC1): the probe-failure branch compensates a replacement ─────────────────────────────────────────────────────────────────────────────────
PROBE_FORM = {"scheme": "http", "address": "10.0.0.7", "port": "8014", "user": "u", "password": "p"}


def _never_written(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a failed probe must not write Jen's settings")

    monkeypatch.setattr(infra, "_write_direct_socket_config", boom)


class TestAProbeThatFailsAfterAReplacementPutsTheWorkingSocketBack:
    """The executed P1 of beta.17: `setup_direct_socket` REPLACES the daemon's http socket in place; when the new one does not answer the old code returned with the working socket gone
    and Jen still dialling it. The whole list - and the certificate - go back, exactly as for a refused write."""

    def _silent(self, monkeypatch):
        monkeypatch.setattr(
            infra,
            "_probe_after_restart",
            lambda url, *a, **k: ("", "connection refused") if "10.0.0.7:8014" in url else ("Kea 3.0.3", None),
        )  # (only the NEW socket is silent: the endpoint Jen uses answers once the old socket is back)

    def test_the_socket_you_had_is_back_byte_equal_and_the_flash_says_both(self, wire, monkeypatch):
        self._silent(monkeypatch)
        _never_written(monkeypatch)
        wire["host"] = {"Dhcp4": {"a": 1, "control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        original = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert json.dumps(wire["host"]) == original
        texts = " ".join(t for _s, t in wire["flashes"])
        assert "The socket you had (https 10.0.0.7:8005) is back" in texts
        assert "the new one (http 10.0.0.7:8014) did not answer" in texts and "connection refused" in texts
        assert "PARTIAL" not in texts and [a[0] for a in wire["audits"]] == [
            "SETUP_DIRECT_SOCKET",
            "DIRECT_SOCKET_COMPENSATED",
        ]
        assert wire["incidents"] == [] and wire["resolved"] == []
        assert SECRET not in _everything_printed(wire)

    def test_a_socket_that_answers_as_the_control_agent_is_compensated_the_same_way(self, wire, monkeypatch):
        monkeypatch.setattr(
            infra, "_identify_daemon", lambda url, *a, **k: "Control-agent" if "10.0.0.7:8014" in url else "Dhcp4"
        )
        _never_written(monkeypatch)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        original = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert json.dumps(wire["host"]) == original
        assert "answered as the Control Agent, not kea-dhcp4" in " ".join(t for _s, t in wire["flashes"])

    def test_the_compensations_own_failure_is_a_recorded_incident_not_only_a_flash(self, wire, monkeypatch):
        self._silent(monkeypatch)
        _never_written(monkeypatch)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(CLIENT_SOCKET)]}}
        wire["results"] = [
            _ok(),
            ChangeSetResult("rollback_failed", "restart-failed", [("error", "the daemon did not restart")]),
        ]
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert [(i[0], i[1], i[2]) for i in wire["incidents"]] == [(1, "dhcp4", "restart-failed")]
        assert SECRET not in json.dumps(wire["incidents"])

    def test_a_first_socket_stays_and_is_recorded_as_probe_pending(self, wire, monkeypatch):
        self._silent(monkeypatch)
        _never_written(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert ed.control_sockets(wire["host"], "dhcp4")[-1]["socket-port"] == 8014, (
            "nothing was replaced: the new socket stays in the daemon's config"
        )
        assert len(wire["applies"]) == 1, "no compensation call"
        assert [(i[0], i[1], i[2]) for i in wire["incidents"]] == [(1, "dhcp4", "probe-pending")]
        assert "http 10.0.0.7:8014" in wire["incidents"][0][3] and SECRET not in json.dumps(wire["incidents"])
        assert "run this again" in " ".join(t for _s, t in wire["flashes"])

    def test_a_socket_that_was_already_there_is_not_compensated_and_is_pending(self, wire, monkeypatch):
        self._silent(monkeypatch)
        _never_written(monkeypatch)
        wire["host"] = {
            "Dhcp4": {
                "control-sockets": [copy.deepcopy(UNIX), build_control_socket("http", "10.0.0.7", 8014, "u", "p")]
            }
        }
        before = json.dumps(wire["host"])
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert json.dumps(wire["host"]) == before and len(wire["applies"]) == 1
        assert [i[2] for i in wire["incidents"]] == ["probe-pending"]

    def test_a_later_probe_that_answers_clears_the_incident_of_that_server_and_service(self, wire, monkeypatch):
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert wire["resolved"] == [(1, "dhcp4")] and wire["incidents"] == []


# ── Q187 (AC2/AC3): the unit of recovery is the usable endpoint ──────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def tls_world(wire, monkeypatch, tmp_path):
    import types

    from jen import extensions
    from jen.services import kea_host, kea_tls

    monkeypatch.setattr(kea_tls, "SSL_DIR", str(tmp_path))
    monkeypatch.setattr(extensions, "KEA_API_CA", "")
    monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", "")
    monkeypatch.setattr(
        "jen.services.capabilities.for_server", lambda sid, probe_kea=True: types.SimpleNamespace(tls=True)
    )
    world = {"installed": [], "now": None, "fail_install_at": None, "restarts": [], "tls": kea_tls}

    def install_tls(server, service, files):
        n = len(world["installed"]) + 1
        if world["fail_install_at"] == n:
            world["installed"].append(None)
            return {"ok": False, "detail": "the helper refused it"}
        world["installed"].append(copy.deepcopy(files))
        world["now"] = copy.deepcopy(files)
        return {"ok": True}

    monkeypatch.setattr(kea_host, "install_tls", install_tls)

    def presented(url, client):
        """What the fake daemon presents: the certificate the host holds right now (Q188, AD2) - the real comparison against Jen's live pair then decides."""
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        if not world["now"]:
            return None
        cert = x509.load_pem_x509_certificate(world["now"]["server.crt"].encode())
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    monkeypatch.setattr(infra, "_presented_fingerprint", presented)
    monkeypatch.setattr(
        kea_host,
        "service_action",
        lambda server, service, action, *a, **k: world["restarts"].append(action) or {"ok": True},
    )
    wire["tls"] = world
    yield wire
    _assert_the_tls_invariants(wire)


def _assert_the_tls_invariants(wire):
    """Q189 (AE0), for every setup / remove scenario that touches TLS: T1 - when a socket of the daemon references Jen's TLS files, Jen's record of what the host holds (`host_material`) is
    byte-equal to the pair the host holds, or it is None and a `tls-local-stale` / `remote-unknown` / `tls-not-restored` incident names the server; T4 - nothing printed carries key material or the password.
    (A host's files that NO socket references are the host's, said in the flash - not a record Jen owes.)"""
    from jen.services import kea_tls

    world = wire["tls"]
    held = world["now"]
    if held:
        sockets = ed.control_sockets(wire["host"], "dhcp4")
        if infra._uses_jen_tls(sockets, "dhcp4"):
            record = kea_tls.host_material(1, "dhcp4")
            if record is None:
                assert any(
                    i[0] == 1 and i[1] == "dhcp4" and i[2] in ("tls-local-stale", "remote-unknown", "tls-not-restored")
                    for i in wire["incidents"]
                ), "T1: Jen has no record of the pair the host holds and no incident says so"
            else:
                assert (record["server.crt"], record["server.key"]) == (
                    held["server.crt"],
                    held["server.key"],
                ), "T1: Jen's record of the host's pair is not the pair the host holds"
    printed = _everything_printed(wire)
    assert "PRIVATE KEY" not in printed and SECRET not in printed, "T4: a secret was printed"


class TestTheTlsMaterialIsPartOfTheSnapshot:
    """An https change installs a new certificate over the old at fixed paths BEFORE the socket change; a restored socket entry must meet the certificate it was issued with."""

    FORM_A = {"scheme": "https", "address": "10.0.0.5", "port": "8004", "user": "u", "password": "p"}
    FORM_B = {"scheme": "https", "address": "10.0.0.7", "port": "8005", "user": "u", "password": "p"}

    def _first_https(self, world, monkeypatch):
        """A successful https setup at 10.0.0.5: the host now holds pair A and an https socket on Jen's paths; Jen's own pair is A."""
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM_A)
        a_files = copy.deepcopy(world["tls"]["now"])
        assert a_files and world["host"]["Dhcp4"]["control-sockets"][-1]["socket-type"] == "https"
        return a_files

    @staticmethod
    def _sans(pem: str):
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(pem.encode())
        return [str(v.value) for v in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]

    def test_https_a_then_https_b_with_the_write_refused_puts_the_sockets_and_the_certificate_back(
        self, tls_world, monkeypatch
    ):
        world = tls_world["tls"]
        a_files = self._first_https(tls_world, monkeypatch)
        host_after_a = json.dumps(tls_world["host"])
        _refuse_the_write(monkeypatch)
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert json.dumps(tls_world["host"]) == host_after_a, "the sockets are back, key for key"
        assert world["now"] == a_files, (
            "the host's certificate AND key are the ones the restored socket was issued with"
        )
        assert "10.0.0.5" in self._sans(world["now"]["server.crt"]) and "10.0.0.7" not in self._sans(
            world["now"]["server.crt"]
        )
        kt = world["tls"]
        assert pathlib.Path(kt.server_copy_path(1, "dhcp4")).read_text(encoding="ascii") == a_files["server.crt"], (
            "Jen's own copy agrees with the host again"
        )
        assert pathlib.Path(kt.server_key_path(1, "dhcp4")).read_text(encoding="ascii") == a_files["server.key"]
        assert not os.path.exists(kt.server_copy_path(1, "dhcp4") + ".prev"), (
            "the previous pair is retired once it is back"
        )
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "was undone" in texts and "PARTIAL" not in texts
        assert tls_world["incidents"] == []
        printed = _everything_printed(tls_world)
        assert "PRIVATE KEY" not in printed and "BEGIN CERTIFICATE" not in printed

    def test_the_previous_pair_was_reinstalled_before_the_restart_the_compensation_makes(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        a_files = self._first_https(tls_world, monkeypatch)
        _refuse_the_write(monkeypatch)
        order = []
        real_apply = tls_world["applies"]
        monkeypatch.setattr(
            "jen.services.kea_host.install_tls",
            lambda server, service, files: order.append("install") or world.__setitem__("now", files) or {"ok": True},
        )
        import jen.services.kea_changeset as kc

        inner = kc.apply_change
        monkeypatch.setattr(kc, "apply_change", lambda *a, **k: order.append("apply:" + a[2][:8]) or inner(*a, **k))
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert order == ["install", "apply:added an", "install", "apply:restored"], order
        assert world["now"] == a_files and real_apply

    def test_https_to_http_followed_by_a_refused_write_touches_no_certificate(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        self._first_https(tls_world, monkeypatch)
        installs = len(world["installed"])
        host_after_a = json.dumps(tls_world["host"])
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **dict(PROBE_FORM, address="10.0.0.9", port="8014"))
        assert json.dumps(tls_world["host"]) == host_after_a and len(world["installed"]) == installs
        assert tls_world["incidents"] == []

    def test_the_config_check_failing_after_the_install_puts_the_certificate_back(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        a_files = self._first_https(tls_world, monkeypatch)
        tls_world["results"] = [ChangeSetResult("aborted", "testerror", [("error", "config validation failed")])]
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert world["now"] == a_files and world["restarts"] == [], (
            "nothing was restarted: the daemon never left the old config"
        )
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "were put back" in texts and "PARTIAL" not in texts and tls_world["incidents"] == []

    def test_a_restart_that_failed_and_was_rolled_back_gets_the_old_certificate_and_one_more_restart(
        self, tls_world, monkeypatch
    ):
        world = tls_world["tls"]
        a_files = self._first_https(tls_world, monkeypatch)
        tls_world["results"] = [ChangeSetResult("rolled_back", "restart-failed", [("error", "did NOT restart")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert world["now"] == a_files and world["restarts"] == ["restart"], (
            "the changeset restarted the daemon on the NEW files; it is restarted once more on the old ones"
        )
        assert tls_world["incidents"] == []

    def test_a_restart_that_cannot_be_repeated_is_a_recorded_incident(self, tls_world, monkeypatch):
        self._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(
            "jen.services.kea_host.service_action", lambda *a, **k: {"ok": False, "detail": "unit failed"}
        )
        tls_world["results"] = [ChangeSetResult("rolled_back", "restart-failed", [("error", "did NOT restart")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert [i[2] for i in tls_world["incidents"]] == ["restart-failed"]

    def test_the_tls_rollback_itself_failing_is_partial_with_the_tls_not_restored_category(
        self, tls_world, monkeypatch
    ):
        world = tls_world["tls"]
        self._first_https(tls_world, monkeypatch)
        _refuse_the_write(monkeypatch)
        world["fail_install_at"] = (
            len(world["installed"]) + 2
        )  # the install of B succeeds, the reinstall of A is refused
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        texts = _everything_printed(tls_world)
        assert "PARTIAL STATE on kea-a" in texts and "certificate" in texts and "was undone" not in texts
        assert "tls-not-restored" in [i[2] for i in tls_world["incidents"]]
        assert "PRIVATE KEY" not in texts

    def test_no_earlier_copy_means_the_sockets_come_back_and_the_certificate_is_a_recorded_incident(
        self, tls_world, monkeypatch
    ):
        """A certificate installed by hand (or one issued before Jen kept the key): there is no `.prev` pair to put back."""
        kt = tls_world["tls"]["tls"]
        tls_world["host"] = {
            "Dhcp4": {
                "control-sockets": [
                    copy.deepcopy(UNIX),
                    build_control_socket("https", "10.0.0.5", 8004, "u", "p", tls=kt.remote_tls_paths("dhcp4")),
                ]
            }
        }
        original = json.dumps(tls_world["host"])
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert json.dumps(tls_world["host"]) == original
        texts = _everything_printed(tls_world)
        assert "PARTIAL STATE" in texts and "no earlier copy" in texts and "was undone" not in texts
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]

    def test_a_first_https_socket_has_nothing_to_put_back_and_says_nothing_false(self, tls_world, monkeypatch):
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert tls_world["host"] == {"Dhcp4": {"control-sockets": [UNIX]}}
        assert tls_world["incidents"] == [] and "was undone" in " ".join(t for _s, t in tls_world["flashes"])

    def test_jens_own_pair_is_what_the_host_has_so_a_pair_that_was_never_installed_is_never_a_recovery_point(
        self, tls_world, monkeypatch
    ):
        """Second pass (Q187, finding 2, sequence B): a first https setup whose Jen client certificate fails validation issues a pair and stops before installing it. Jen's own copies must not
        change, or the next attempt would keep that unsent pair as the 'earlier' one and a later undo would put it on the host."""
        kt = tls_world["tls"]["tls"]
        monkeypatch.setattr("jen.services.kea.validate_client_tls_material", lambda *a, **k: "stand-in: unusable")
        _post(_inner(infra.setup_direct_socket), **self.FORM_A)
        assert kt.current_material(1, "dhcp4") is None and kt.previous_material(1, "dhcp4") is None
        assert tls_world["tls"]["installed"] == [] and not os.path.exists(kt.server_copy_path(1, "dhcp4"))

    def test_an_install_the_helper_refuses_leaves_jens_pair_alone_and_says_the_socket_was_not_changed(
        self, tls_world, monkeypatch
    ):
        world = tls_world["tls"]
        kt = world["tls"]
        a_files = self._first_https(tls_world, monkeypatch)
        world["fail_install_at"] = len(world["installed"]) + 1  # B's install is refused
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert kt.current_material(1, "dhcp4")["server.key"] == a_files["server.key"], (
            "Jen's pair is still what the host has"
        )
        assert world["now"] == a_files, "the pair Jen last installed was re-asserted (a lost reply may have applied B)"
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert (
            "nothing was changed in the daemon's sockets" in texts
            and "PARTIAL" not in texts
            and tls_world["incidents"] == []
        )

    def test_a_refused_install_whose_reassertion_is_also_refused_is_a_recorded_incident(self, tls_world, monkeypatch):
        """Second pass (finding 7): `install_tls` answering not-ok does not prove nothing was installed (a lost reply). With a socket on Jen's files and no way to re-assert, it is an incident."""
        world = tls_world["tls"]
        self._first_https(tls_world, monkeypatch)
        base = len(world["installed"])

        def refuse_from_now(server, service, files):
            world["installed"].append(None)
            return {"ok": False, "detail": "ssh: connection reset"}

        monkeypatch.setattr("jen.services.kea_host.install_tls", refuse_from_now)
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert len(world["installed"]) == base + 2, "the install, then the re-assertion"
        texts = _everything_printed(tls_world)
        assert "PARTIAL STATE on kea-a" in texts and "may have been replaced" in texts
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]

    def test_an_earlier_operation_that_stood_is_the_recovery_point_not_the_first_attempts_pair(
        self, tls_world, monkeypatch
    ):
        """Second pass (finding 2, sequence A): A is on the host; the socket is removed (TLS untouched); a setup B whose probe fails leaves B on the host (a first socket stays); a setup C that
        replaces B and fails must put back B - what the host had immediately before C - never A."""
        world = tls_world["tls"]
        self._first_https(tls_world, monkeypatch)
        tls_world["host"] = {
            "Dhcp4": {"control-sockets": [copy.deepcopy(UNIX)]}
        }  # the Remove button's result: no API socket, certificate A still on the host
        monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("", "no answer"))
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        b_files = copy.deepcopy(world["now"])
        assert [i[2] for i in tls_world["incidents"]] == ["probe-pending"]
        host_with_b = json.dumps(tls_world["host"])
        _post(_inner(infra.setup_direct_socket), **dict(self.FORM_B, address="10.0.0.9", port="8006"))
        assert json.dumps(tls_world["host"]) == host_with_b, "the sockets are back"
        assert world["now"] == b_files, "and so is the certificate the restored socket (B) was issued with - not A"
        assert "10.0.0.7" in self._sans(world["now"]["server.crt"])

    def test_a_pair_that_does_not_belong_together_is_never_put_on_a_host(self, tls_world, monkeypatch):
        kt = tls_world["tls"]["tls"]
        self._first_https(tls_world, monkeypatch)
        other = kt.issue_server_cert(
            {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}, "dhcp4", "10.0.0.8", commit=False
        )
        pathlib.Path(kt.server_key_path(1, "dhcp4") + ".prev").write_text(other["server.key"], encoding="ascii")
        pathlib.Path(kt.server_copy_path(1, "dhcp4") + ".prev").write_text(
            pathlib.Path(kt.server_copy_path(1, "dhcp4")).read_text(encoding="ascii"), encoding="ascii"
        )
        assert kt.previous_material(1, "dhcp4") is None, "the certificate's key is not the key beside it"
        assert kt.current_material(1, "dhcp4") is not None

    def test_a_success_retires_the_previous_pair(self, tls_world, monkeypatch):
        kt = tls_world["tls"]["tls"]
        self._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert kt.previous_material(1, "dhcp4") is None
        assert tls_world["resolved"][-1] == (1, "dhcp4")
        assert tls_world["resolved_categories"][-1] is None, (
            "this run replaced the certificate and it was proved: every category of the server and service may clear"
        )


class TestAnHttpsSocketIsOnJensFilesByAnyOfTheThree:
    """Second pass (Q187): `install-tls` overwrites ca.crt, server.crt AND server.key; a socket that references any of them loses what it was issued with."""

    def test_the_cert_the_key_or_the_trust_anchor_each_make_it_jens(self):
        root = "/etc/kea/tls/dhcp4"
        for field in ("cert-file", "key-file", "trust-anchor"):
            entry = {
                "socket-type": "https",
                "socket-address": "10.0.0.5",
                "socket-port": 8004,
                field: f"{root}/"
                + {"cert-file": "server.crt", "key-file": "server.key", "trust-anchor": "ca.crt"}[field],
            }
            assert infra._uses_jen_tls([entry], "dhcp4"), field
        assert not infra._uses_jen_tls(
            [{"socket-type": "https", "cert-file": "/etc/ssl/own.crt", "key-file": "/etc/ssl/own.key"}], "dhcp4"
        )
        assert not infra._uses_jen_tls([{"socket-type": "http", "cert-file": f"{root}/server.crt"}], "dhcp4")
        assert not infra._uses_jen_tls(None, "dhcp4")


# ── Q188 (AD2/AD3/AD4/AD7/AD9): the https setup is one transaction ────────────────────────────────────────────────────────────────────────────────
class TestTheHttpsSetupCommitsJensStateFirstAndStopsAtTheFirstUnprovedStep:
    """AD2: `.prev` (what the host has) and `.staged` (what it is about to be given) are written BEFORE `install_tls`; the promotion to live comes after, and when it fails the operation STOPS -
    the previous material goes back, the existing socket is probed, `.prev` is kept, and the socket change never starts."""

    A = TestTheTlsMaterialIsPartOfTheSnapshot
    FORM_B = TestTheTlsMaterialIsPartOfTheSnapshot.FORM_B

    @pytest.mark.parametrize("victim", [".crt", ".key"])
    def test_install_ok_and_the_local_promotion_fails_for_either_file(self, tls_world, monkeypatch, victim):
        world = tls_world["tls"]
        kt = world["tls"]
        a_files = self.A()._first_https(tls_world, monkeypatch)
        applies_before = len(tls_world["applies"])
        host_before = json.dumps(tls_world["host"])
        real = os.replace
        live = {kt.server_copy_path(1, "dhcp4"), kt.server_key_path(1, "dhcp4")}

        def failing(src, dst, *a, **k):
            if str(dst) in live and str(dst).endswith(victim):
                raise OSError(13, "Permission denied")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        monkeypatch.setattr(os, "replace", real)
        assert world["now"] == a_files, "the previous material is back on the host"
        assert len(tls_world["applies"]) == applies_before and json.dumps(tls_world["host"]) == host_before, (
            "the socket change never started"
        )
        assert kt.previous_material(1, "dhcp4") is not None, "`.prev` is kept after a failed commit"
        assert not pathlib.Path(kt.server_copy_path(1, "dhcp4") + ".staged").exists()
        assert kt.current_material(1, "dhcp4")["server.crt"] == a_files["server.crt"], "Jen's live pair is untouched"
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "Jen cannot keep its own copy of the new certificate" in texts and "applied kea-dhcp4" not in texts
        assert tls_world["incidents"] == []

    def test_the_promotion_failing_and_the_old_certificate_not_going_back_is_an_incident(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        self.A()._first_https(tls_world, monkeypatch)

        def refuse_promotion(sid, service):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("jen.services.kea_tls.promote_staged", refuse_promotion)
        world["fail_install_at"] = len(world["installed"]) + 2  # B's install ok, the re-assertion of A refused
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]
        assert "PARTIAL STATE" in _everything_printed(tls_world)

    def test_a_pair_that_cannot_be_staged_is_never_installed(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        monkeypatch.setattr(
            "jen.services.kea_tls.stage_issued", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "Permission denied"))
        )
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert world["installed"] == [] and tls_world["applies"] == []
        assert "Jen cannot keep its own copy" in " ".join(t for _s, t in tls_world["flashes"])

    def test_a_stale_prev_from_an_older_operation_is_never_the_rollback_source(self, tls_world, monkeypatch):
        """Two generations on disk: the live pair A and a `.prev` left by something older. The new operation sets `.prev` to what the host has NOW; the reinstall is handed A."""
        world = tls_world["tls"]
        kt = world["tls"]
        a_files = self.A()._first_https(tls_world, monkeypatch)
        older = kt.issue_server_cert(
            {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}, "dhcp4", "10.0.0.99", commit=False
        )
        pathlib.Path(kt.server_copy_path(1, "dhcp4") + ".prev").write_text(older["server.crt"], encoding="ascii")
        pathlib.Path(kt.server_key_path(1, "dhcp4") + ".prev").write_text(older["server.key"], encoding="ascii")
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert world["installed"][-1]["server.key"] == a_files["server.key"], (
            "the last reinstall was given A, not the stale generation"
        )
        assert world["now"] == a_files

    def test_a_completed_setup_presents_the_certificate_jen_holds(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        kt = world["tls"]
        self.A()._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        presented = infra._presented_fingerprint("https://10.0.0.7:8005", None)
        assert presented == kt.fingerprint(kt.server_copy_path(1, "dhcp4"))
        assert "answers directly" in " ".join(t for _s, t in tls_world["flashes"])

    def test_a_socket_that_presents_a_certificate_jen_does_not_hold_is_not_a_completed_setup(
        self, tls_world, monkeypatch
    ):
        world = tls_world["tls"]
        a_files = self.A()._first_https(tls_world, monkeypatch)
        host_after_a = json.dumps(tls_world["host"])
        monkeypatch.setattr(infra, "_presented_fingerprint", lambda url, client: "0" * 64)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "not the one Jen holds" in texts and "answers directly" not in texts
        assert json.dumps(tls_world["host"]) == host_after_a and world["now"] == a_files, (
            "compensated like a failed probe"
        )


class TestAPartialTlsRestoreIsPartial:
    """AD3: `_put_tls_back` has two halves. The host taking the old pair while Jen's copy cannot follow is `tls-local-stale`, never 'undone', and `.prev` is kept for a retry."""

    def test_the_local_half_failing_after_the_host_took_the_old_pair(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        kt = world["tls"]
        a_files = TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        _refuse_the_write(monkeypatch)
        monkeypatch.setattr(kt, "restore_previous", lambda sid, service: False)
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **TestTheTlsMaterialIsPartOfTheSnapshot.FORM_B)
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert world["now"] == a_files, "the host has the old pair"
        assert "was undone" not in texts and "PARTIAL STATE" in texts
        assert [i[2] for i in tls_world["incidents"]] == ["tls-local-stale"]
        assert kt.previous_material(1, "dhcp4") is not None, "`.prev` is kept for a retry"

    def test_the_put_back_answers_both_halves(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        kt = world["tls"]
        TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **TestTheTlsMaterialIsPartOfTheSnapshot.FORM_B)
        # a success retired .prev: nothing to put back
        assert infra._put_tls_back(SERVERS_ONE, "dhcp4") == {"remote": "none-saved", "local": "ok"}
        assert kt.previous_material(1, "dhcp4") is None


SERVERS_ONE = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8000"}


@pytest.mark.parametrize(
    "why",
    ["refuses", "silent", "control-agent", "auth", "timeout"],
)
class TestUndoneMeansTheEndpointAnswered:
    """AD4: after the compensation's restart `_undo_remote_change` probes the endpoint Jen dials, with the credentials and TLS context recorded BEFORE the first remote change, and requires it to
    identify as the right daemon. A restored file and a restart are not an answer."""

    FORM = {"scheme": "http", "address": "10.0.0.7", "port": "8014", "user": "u", "password": "p"}

    def _break_the_original(self, monkeypatch, why):
        def probe(url, user, pwd, service, verify=None, cert=None):
            if "10.0.0.5:8004" in url:  # the endpoint Jen dials
                return {
                    "refuses": ("", "connection refused"),
                    "silent": ("", "no route"),
                    "control-agent": ("Kea 3.0.3", None),
                    "auth": ("", "HTTP 401 Unauthorized"),
                    "timeout": ("", "timed out"),
                }[why]
            return "Kea 3.0.3", None

        monkeypatch.setattr(infra, "_probe_after_restart", probe)
        if why == "control-agent":
            monkeypatch.setattr(
                infra, "_identify_daemon", lambda url, *a, **k: "Control-agent" if "10.0.0.5:8004" in url else "Dhcp4"
            )

    def test_config_and_restart_ok_but_the_endpoint_does_not_answer(self, wire, monkeypatch, why):
        self._break_the_original(monkeypatch, why)
        _refuse_the_write(monkeypatch)
        before = json.dumps(wire["host"])
        wire["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        texts = " ".join(t for _s, t in wire["flashes"])
        assert json.dumps(wire["host"]) == before, "the file and the restart are back"
        assert "was undone" not in texts and "PARTIAL STATE" in texts and "the endpoint Jen uses" in texts
        assert [i[2] for i in wire["incidents"]] == ["restored-endpoint-unreachable"]
        assert SECRET not in _everything_printed(wire) and "10.0.0.5:8004" in texts

    def test_a_later_successful_setup_clears_it(self, wire, monkeypatch, why):
        self._break_the_original(monkeypatch, why)
        _refuse_the_write(monkeypatch)
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("Kea 3.0.3", None))
        monkeypatch.setattr(infra, "_identify_daemon", lambda *a, **k: "Dhcp4")
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **self.FORM)
        assert wire["resolved"][-1] == (1, "dhcp4"), (
            "a probe that got its answer clears the incident of THIS server and service"
        )


def test_an_endpoint_that_answers_makes_the_undo_complete(wire, monkeypatch):
    _refuse_the_write(monkeypatch)
    _post(_inner(infra.setup_direct_socket), **TestUndoneMeansTheEndpointAnswered.FORM)
    assert "was undone" in " ".join(t for _s, t in wire["flashes"]) and wire["incidents"] == []


def test_an_http_success_proves_nothing_about_a_certificate(wire, monkeypatch):
    """Second pass (Q188): a plain-http socket that answers clears the recovery categories about the sockets and the daemon - never `tls-not-restored` or `tls-local-stale`, which are about
    a certificate this run did not touch."""
    monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
    _post(_inner(infra.setup_direct_socket), **TestUndoneMeansTheEndpointAnswered.FORM)
    cleared = wire["resolved_categories"][-1]
    assert cleared is not None and "tls-not-restored" not in cleared and "tls-local-stale" not in cleared
    assert "probe-pending" in cleared and "remote-unknown" in cleared


class TestAnUnreadableConfigIsNotNoSocketUsesJensFiles:
    """AD7 / RELEASE_AUDIT (l): an unavailable observation never reads as safe."""

    FORM_B = TestTheTlsMaterialIsPartOfTheSnapshot.FORM_B

    def test_the_https_path_refuses_before_the_install_when_the_pre_read_is_none(self, tls_world, monkeypatch):
        monkeypatch.setattr(infra, "_api_sockets_of", lambda s, svc, errors=None: None)
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert tls_world["tls"]["installed"] == [] and tls_world["applies"] == []
        assert "could not read" in " ".join(t for _s, t in tls_world["flashes"])

    def test_the_http_path_is_unchanged(self, wire, monkeypatch):
        """(the observation matters where files at fixed paths are replaced)"""
        monkeypatch.setattr(infra, "_api_sockets_of", lambda s, svc, errors=None: None)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        _post(_inner(infra.setup_direct_socket), **PROBE_FORM)
        assert len(wire["applies"]) == 1

    def test_a_plan_that_could_not_read_after_a_pre_read_that_did_means_nothing_references_the_files(
        self, tls_world, monkeypatch
    ):
        """Q189 (AE6b), the first half of the case beta.19 pinned as 'remote-unknown': the PRE-read read the daemon's sockets and none referenced Jen's files; only the plan's read failed. The material
        the failed attempt installed is unreferenced - 'nothing to put back' is the answer, said, with no incident - and Jen drops its own copy of files no socket uses (AE6c)."""
        monkeypatch.setattr(
            "jen.services.kea_changeset.apply_change",
            lambda *a, **k: ChangeSetResult("aborted", "error", [("error", "could not read the config")]),
        )
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        texts = _everything_printed(tls_world)
        assert (
            "no socket references" in texts and "dropped its own copy" in texts and "could not read what" not in texts
        )
        assert tls_world["incidents"] == []
        kt = tls_world["tls"]["tls"]
        assert not pathlib.Path(kt.server_copy_path(1, "dhcp4")).exists(), "the copy of the unreferenced pair is gone"

    def test_a_plan_that_could_not_read_after_a_pre_read_that_found_jens_files_in_use_puts_the_old_pair_back(
        self, tls_world, monkeypatch
    ):
        """... and the second half: the pre-read saw an https socket on Jen's files; the previous pair cannot be put back. That is `tls-not-restored` - the pre-read DID read the sockets, so it is
        not `remote-unknown` ('could not read what the sockets referenced' would be false)."""
        TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(
            "jen.services.kea_changeset.apply_change",
            lambda *a, **k: ChangeSetResult("aborted", "error", [("error", "could not read the config")]),
        )
        tls_world["tls"]["fail_install_at"] = (
            len(tls_world["tls"]["installed"]) + 2
        )  # B installs; the reinstall of A is refused
        tls_world["incidents"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]
        assert "could not read what" not in _everything_printed(tls_world)


class TestTheChangeSetsTwoRollbackFailedStates:
    """AD9: `rollback_failed` is two states for the certificate. A REVERT that failed leaves the NEW socket entry in the file: the old pair is not reinstalled under it."""

    FORM_B = TestTheTlsMaterialIsPartOfTheSnapshot.FORM_B

    def _after_a(self, tls_world, monkeypatch):
        a_files = TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        tls_world["tls"]["installed"].clear()
        return a_files

    def test_a_failed_revert_does_not_put_the_old_pair_under_the_new_entry(self, tls_world, monkeypatch):
        self._after_a(tls_world, monkeypatch)
        tls_world["results"] = [
            ChangeSetResult("rollback_failed", "error", [("error", "revert failed")], still_new_ids=[1])
        ]
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert len(tls_world["tls"]["installed"]) == 1, (
            "only the NEW pair was installed; the old one was not put under the new entry"
        )
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]
        assert "NEW socket entry is still" in _everything_printed(tls_world)

    def test_a_restart_that_would_not_start_on_the_restored_config_gets_the_old_pair_and_one_more_restart(
        self, tls_world, monkeypatch
    ):
        a_files = self._after_a(tls_world, monkeypatch)
        tls_world["results"] = [ChangeSetResult("rollback_failed", "restart-failed", [("error", "did not restart")])]
        _post(_inner(infra.setup_direct_socket), **self.FORM_B)
        assert tls_world["tls"]["now"] == a_files and tls_world["tls"]["restarts"] == ["restart"]


class TestANochangeRerunDoesNotReplaceFilesTheDaemonWillNotReload:
    """AD9: the socket is already in the daemon's config -> no restart -> new files written under it would not be loaded until the next restart."""

    FORM_A = TestTheTlsMaterialIsPartOfTheSnapshot.FORM_A

    def test_no_new_material_is_installed_and_the_flash_never_says_restarted(self, tls_world, monkeypatch):
        world = tls_world["tls"]
        a_files = TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        installs = len(world["installed"])
        monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("", "no route"))
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_A)
        assert len(world["installed"]) == installs and world["now"] == a_files
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "was not restarted" in texts and "restarted with the new socket" not in texts


_REAL_API_SOCKETS_OF = (
    infra._api_sockets_of
)  # (the fixtures above replace it with a fake; the pre-read tests below need the real one)


@pytest.mark.parametrize(
    "exc",
    [TimeoutError("timed out"), EOFError(), OSError(104, "Connection reset by peer")],
    ids=["timeout", "eof", "reset"],
)
class TestThePreReadIsACallSiteToo:
    """Q189 (AE4): the routes read the daemon's config before they send anything. A channel exception there was a 500 with every flash dropped (executed: 3 classes x setup-http, setup-https, remove).
    Now it is a refusal that says so - and nothing was sent."""

    def _break_the_read(self, monkeypatch, exc):
        from jen.services import kea_host

        monkeypatch.setattr(infra, "_api_sockets_of", _REAL_API_SOCKETS_OF)

        def helper_call(server, op, payload=None, timeout=60):
            if op == "read-config":
                raise exc
            raise AssertionError(f"nothing else may be sent: {op}")

        monkeypatch.setattr(kea_host, "helper_call", helper_call)

    def _assert_a_refusal_that_sent_nothing(self, wire, exc):
        texts = " ".join(t for _s, t in wire["flashes"])
        assert (
            "Jen could not reach kea-a to read" in texts
            and "nothing was changed" in texts
            and type(exc).__name__ in texts
        )
        assert wire["applies"] == [], "nothing was sent to the Kea host"
        assert [a[0] for a in wire["audits"]] == []
        assert SECRET not in _everything_printed(wire)

    def test_setup_http(self, wire, monkeypatch, exc):
        self._break_the_read(monkeypatch, exc)
        _post(_inner(infra.setup_direct_socket), **TestALateRefusalOnSetupPutsTheHostBack.FORM)
        self._assert_a_refusal_that_sent_nothing(wire, exc)

    def test_setup_https(self, tls_world, monkeypatch, exc):
        self._break_the_read(monkeypatch, exc)
        _post(_inner(infra.setup_direct_socket), **TestTheTlsMaterialIsPartOfTheSnapshot.FORM_A)
        self._assert_a_refusal_that_sent_nothing(tls_world, exc)
        assert tls_world["tls"]["installed"] == [], "no certificate was installed either"

    def test_remove(self, wire, monkeypatch, exc):
        self._break_the_read(monkeypatch, exc)
        wire["host"] = {"Dhcp4": {"control-sockets": [copy.deepcopy(UNIX), copy.deepcopy(SOCKET)]}}
        _post(_inner(infra.remove_direct_socket))
        self._assert_a_refusal_that_sent_nothing(wire, exc)


class TestAFirstSocketThatPresentsAnotherCertificateIsOneAnswer:
    """Q189 (AE5): a socket that answers as the daemon but presents a certificate that is not the one Jen holds - the flash said 'remove the socket and set it up again', the incident said
    `probe-pending` 'run the setup again' (unsatisfiable, and Health 'warn' for a state that is not a probe still pending). One category, `tls-local-stale`, one by-hand sentence."""

    FORM_A = TestTheTlsMaterialIsPartOfTheSnapshot.FORM_A

    def test_the_first_socket_case(self, tls_world, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(infra, "_presented_fingerprint", lambda url, client: "0" * 64)
        tls_world["flashes"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_A)
        texts = " ".join(t for _s, t in tls_world["flashes"])
        assert "not the one Jen holds" in texts and "remove the direct socket and set it up again" in texts
        assert [i[2] for i in tls_world["incidents"]] == ["tls-local-stale"], "ONE category, not probe-pending"
        assert "remove the direct socket and set it up again" in tls_world["details"][0], "the two sentences agree"
        assert health._tls_local_stale_labels() == ["kea-a kea-dhcp4"], "Health's certificate row carries it"

    def test_a_nochange_rerun_is_the_same_answer(self, tls_world, monkeypatch):
        TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(infra, "_presented_fingerprint", lambda url, client: "0" * 64)
        tls_world["incidents"].clear()
        _post(_inner(infra.setup_direct_socket), **self.FORM_A)
        assert [i[2] for i in tls_world["incidents"]] == ["tls-local-stale"]

    def test_a_later_setup_that_passes_the_fingerprint_gate_clears_it(self, tls_world, monkeypatch):
        TestTheTlsMaterialIsPartOfTheSnapshot()._first_https(tls_world, monkeypatch)
        monkeypatch.setattr(infra, "_write_direct_socket_config", lambda *a, **k: "url written")
        before = len(tls_world["resolved_categories"])
        _post(
            _inner(infra.setup_direct_socket), **self.FORM_A
        )  # a rerun of the same socket: nothing replaced, and the socket presents Jen's own certificate
        assert tls_world["resolved_categories"][before:] == [None], (
            "the socket presented exactly the certificate Jen holds: every category of this server and service may clear, the certificate ones included"
        )


class TestANewEntryStillInTheConfigIsNotNoSocketReferencesTheFiles:
    """Q189 second pass, finding 4: a FIRST https setup whose revert failed (`rollback_failed`, the NEW entry is still in the daemon's config) references the files it installed. The
    'no socket references them' shortcut (AE6b/c) must not fire - and must not delete Jen's only record of the pair the config now points at."""

    def test_the_local_pair_is_kept_and_the_incident_is_recorded(self, tls_world, monkeypatch):
        kt = tls_world["tls"]["tls"]
        tls_world["results"] = [
            ChangeSetResult("rollback_failed", "error", [("error", "revert failed")], still_new_ids=[1])
        ]
        _post(_inner(infra.setup_direct_socket), **TestTheTlsMaterialIsPartOfTheSnapshot.FORM_A)
        texts = _everything_printed(tls_world)
        assert "still in kea-dhcp4's config" in texts and "no socket references" not in texts
        assert (
            pathlib.Path(kt.server_copy_path(1, "dhcp4")).exists()
            and pathlib.Path(kt.server_key_path(1, "dhcp4")).exists()
        )
        assert [i[2] for i in tls_world["incidents"]] == ["tls-not-restored"]
