"""
tests/test_kea_changeset_transports.py
──────────────────────────────────────
Q212 (BB2) - the change set over whichever transport each target has. An `api` target is a stateful fake Kea (tests/e2e/_fake_kea_server.py::StatefulKeaServer) reached by the REAL
`kea_command`; a `file` target is the helper fake the rest of the change-set tests use. Pure: runs under `--noconftest`.
"""

import ast
import copy
import pathlib
import threading
import time

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host
from tests import _kea_api_world as world
from tests._kea_host_fakes import FakeHelper
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture
def daemon():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.hang_seconds = 1.2
    f.start()
    yield f
    f.stop()


@pytest.fixture
def helper(monkeypatch):
    h = FakeHelper()
    h.configs[(2, "dhcp4")] = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
    h.shas[(2, "dhcp4")] = "sha-b"
    h.responses["test-config"] = {"ok": True}
    h.responses["apply-config"] = {"ok": True, "sha256": "new-b", "helper_version": 2}
    h.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
    monkeypatch.setattr(kea_host, "helper_call", h.helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", dict)
    return h


def api_server(daemon, **extra):
    return {"id": 1, "name": "kea-a", "api_url": daemon.url, "config_transport": "api", **extra}


FILE_SERVER = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2", "config_transport": "file"}


def lifetime(value):
    def mutate(cfg):
        out = copy.deepcopy(cfg)
        out["Dhcp4"]["valid-lifetime"] = value
        return out, "ok"

    return mutate


class TestTheTransportIsPure:
    @pytest.mark.parametrize(
        ("server", "service", "want"),
        [
            ({"ssh_host": "h"}, "dhcp4", "file"),  # absent: today's behavior, SSH present
            ({}, "dhcp4", "off"),  # absent, no SSH: an API-only server was never a write target
            ({"config_transport": ""}, "dhcp4", "off"),
            ({"config_transport": "api"}, "dhcp4", "api"),
            ({"config_transport": "api"}, "dhcp6", "api"),
            ({"config_transport": "api", "ssh_host": "h"}, "d2", "file"),  # D2 stays on the file path where SSH exists
            ({"config_transport": "api"}, "d2", "off"),
            ({"config_transport": "file"}, "dhcp4", "off"),  # file with no SSH host
            ({"config_transport": "file", "ssh_host": "h"}, "dhcp4", "file"),
            ({"config_transport": "off", "ssh_host": "h"}, "dhcp4", "off"),
            ({"config_transport": "API", "ssh_host": "h"}, "dhcp4", "off"),  # a mistake never grants a write path
            ({"config_transport": "yes", "ssh_host": "h"}, "dhcp4", "off"),
            ({"config_transport": "ssh", "ssh_host": "h"}, "dhcp4", "off"),
        ],
    )
    def test_the_table(self, server, service, want):
        assert cs._transport(server, service) == want

    def test_it_never_asks_capabilities_or_the_network(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("_transport must be pure")

        monkeypatch.setattr("jen.services.capabilities.for_server", boom)
        monkeypatch.setattr("jen.services.kea.kea_command", boom)
        assert cs._transport({"config_transport": "api"}, "dhcp4") == "api"

    def test_a_server_not_in_kea_servers_still_plans(self, daemon, helper, store):
        """The existing change-set tests' dicts are not in KEA_SERVERS: planning must not resolve through it."""
        result = cs.apply_change("dhcp4", lifetime(5), "x", servers=[FILE_SERVER])
        assert result.status == "ok"


class TestAnApiOnlyServerIsATarget:
    def test_a_server_with_no_ssh_is_changed_over_the_api_with_no_restart(self, daemon, helper, store):
        result = cs.apply_change("dhcp4", lifetime(7200), "lifetime", servers=[api_server(daemon)])
        assert result.status == "ok", result.lines
        assert daemon.running["valid-lifetime"] == 7200 and daemon.file == daemon.running  # live and persisted
        assert helper.calls == []  # nothing touched SSH
        assert any("over the API, no restart" in text for _k, text in result.lines)
        assert result.covered == ["kea-a"]

    def test_the_revision_is_a_kea_row(self, daemon, helper, store):
        cs.apply_change("dhcp4", lifetime(7200), "lifetime", servers=[api_server(daemon)])
        assert [(r["hash_kind"], r["source"]) for r in store.rows] == [("kea", "baseline"), ("kea", "jen")]


class TestAnApiServerThatDoesNotAnswerAbortsTheSet:
    def test_the_plan_read_fails_and_nothing_else_is_written(self, daemon, helper, store):
        daemon.stopped = True
        result = cs.apply_change("dhcp4", lifetime(1), "x", servers=[FILE_SERVER, api_server(daemon)])
        assert result.status == "aborted"
        assert any("kea-a" in text for k, text in result.lines if k == "error")
        assert "apply-config" not in helper.ops()


class TestOffIsNotATarget:
    def test_the_line_names_it_and_nothing_is_sent_to_it(self, daemon, helper, store):
        off = api_server(daemon, config_transport="off", name="kea-off")
        result = cs.apply_change("dhcp4", lifetime(9), "x", servers=[off, FILE_SERVER])
        assert result.status == "ok"
        assert any("kea-off: not a write target" in text for _k, text in result.lines)
        assert daemon.commands == []

    def test_only_off_servers_is_noservers(self, daemon, helper, store):
        off = api_server(daemon, config_transport="off")
        result = cs.apply_change("dhcp4", lifetime(9), "x", servers=[off])
        assert result.status == "noservers"

    def test_an_api_only_server_with_no_setting_is_silently_not_a_target(self, daemon, helper, store):
        """Today's behavior for a server that predates the key: no SSH host, no write, no new line in any change set."""
        legacy = {"id": 1, "name": "kea-old", "api_url": daemon.url}
        result = cs.apply_change("dhcp4", lifetime(9), "x", servers=[legacy, FILE_SERVER])
        assert result.status == "ok" and not any("kea-old" in text for _k, text in result.lines)
        assert daemon.commands == []


class TestMixedTargets:
    def test_file_is_written_first_then_api_goes_live_then_the_file_target_restarts(self, daemon, helper, store):
        order = []
        helper.responses["apply-config"] = lambda s, o, p: (
            order.append("file-write"),
            {"ok": True, "sha256": "new-b", "helper_version": 2},
        )[1]
        helper.responses["service"] = lambda s, o, p: (
            order.append("restart"),
            {"ok": True, "unit": "kea-dhcp4-server", "state": "active"},
        )[1]
        daemon.hooks["config-set"] = lambda f: order.append("api-set")
        daemon.hooks["config-write"] = lambda f: order.append("api-write")
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon), FILE_SERVER])
        assert result.status == "ok", result.lines
        assert order == ["file-write", "api-set", "api-write", "restart"]
        # the restart ranges over the file target only: one restart, never one for the api target
        assert helper.ops().count("service") == 1

    def test_the_file_targets_restart_failing_reverts_the_api_target_over_the_api(self, daemon, helper, store):
        before = copy.deepcopy(daemon.running)
        helper.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit failed"}
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon), FILE_SERVER])
        assert result.last_code == "restart-failed"
        assert daemon.running == before and daemon.file == before  # put back live AND in the file
        assert [r["source"] for r in store.rows if r["source"] == "rollback" and r["hash_kind"] == "kea"] == ["rollback"]

    def test_the_api_targets_write_failure_reverts_the_file_target(self, daemon, helper, store):
        daemon.write_fails = "Unable to open file /etc/kea/kea-dhcp4.conf for writing"
        before = copy.deepcopy(daemon.running)
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon), FILE_SERVER])
        assert result.status == "aborted"
        assert daemon.running == before
        files = [p for (_sid, op, p) in helper.calls if op == "apply-config"]
        assert (
            len(files) == 2 and files[1]["config"] == helper.configs[(2, "dhcp4")]
        )  # kea-b was written, then put back
        assert any("Unable to open file" in text for _k, text in result.lines)

    def test_the_by_hand_line_is_per_transport(self, daemon, helper, store):
        # both targets end up stuck: the api target's revert is refused, the file target's second restart fails
        helper.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit failed"}
        original = daemon._answer

        def refuse_after_the_first_set(command, arguments):
            if command == "config-set" and daemon.commands.count("config-set") >= 2:
                return {"result": 1, "text": "refused"}
            return original(command, arguments)

        daemon._answer = refuse_after_the_first_set
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon), FILE_SERVER])
        assert result.status == "rollback_failed"
        text = " ".join(t for _k, t in result.lines)
        assert "config-set the previous revision" in text  # the api target
        assert "restart Kea there by hand" in text  # the file target
        assert set(result.needs_hands) == {"kea-a", "kea-b"}

    def test_an_api_write_the_daemon_could_not_prove_is_needs_hands_and_not_undone(self, daemon, helper, store):
        stranger = copy.deepcopy(daemon.running)
        stranger["valid-lifetime"] = 3
        daemon.hooks["config-write"] = lambda f: f.set_running(stranger)
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon)])
        assert result.status == "rollback_failed" and result.needs_hands == ["kea-a"]
        assert daemon.running == stranger  # the daemon's own answer is the record; nothing was set over it
        assert daemon.commands.count("config-set") == 1


class TestAFilePathWriteToAnApiServerComparesFirst:
    SERVER = {"id": 3, "name": "kea-c", "ssh_host": "10.0.0.3", "config_transport": "api"}

    def _wire(self, daemon, helper, file_cfg):
        server = {**self.SERVER, "api_url": daemon.url}
        helper.configs[(3, "dhcp4")] = file_cfg
        helper.shas[(3, "dhcp4")] = "raw-c"
        return server

    def test_a_daemon_that_differs_from_its_file_refuses_and_names_both_digests(self, daemon, helper, store):
        server = self._wire(daemon, helper, {"Dhcp4": {"valid-lifetime": 1}})
        result = cs.apply_change("dhcp4", lifetime(5), "logging on", servers=[server], transport="file")
        assert result.status == "aborted"
        text = " ".join(t for _k, t in result.lines)
        assert (
            "runs a configuration its file does not carry" in text and daemon.digest()[:12] in text and "raw-c" in text
        )
        assert "apply-config" not in helper.ops()

    def test_equal_is_written_and_a_kea_row_follows_the_restart(self, daemon, helper, store):
        server = self._wire(daemon, helper, {"Dhcp4": copy.deepcopy(daemon.running)})
        result = cs.apply_change("dhcp4", lifetime(5), "logging on", servers=[server], transport="file")
        assert result.status == "ok", result.lines
        assert "apply-config" in helper.ops() and "service" in helper.ops()
        assert any(r["hash_kind"] == "kea" and r["source"] == "jen" for r in store.rows)

    def test_a_daemon_that_does_not_answer_does_not_block_the_write(self, daemon, helper, store):
        """The host's own restore must still be possible when the daemon is down."""
        server = self._wire(daemon, helper, {"Dhcp4": {"valid-lifetime": 1}})
        daemon.stopped = True
        assert kea_host.apply_config(server, "dhcp4", {"Dhcp4": {}})["ok"]


class TestAnApiServerWithSshIsCheckedForAnUnloadedEdit:
    def test_a_file_that_carries_an_edit_the_daemon_has_not_loaded_aborts(self, daemon, helper, store):
        server = api_server(daemon, ssh_host="10.0.0.1")
        helper.configs[(1, "dhcp4")] = {"Dhcp4": {"valid-lifetime": 1}}
        result = cs.apply_change("dhcp4", lifetime(5), "x", servers=[server])
        assert result.status == "aborted"
        assert any("carries an edit the daemon has not loaded" in t for _k, t in result.lines)
        assert "config-set" not in daemon.commands

    def test_an_unreadable_file_aborts_too(self, daemon, helper, store):
        server = api_server(daemon, ssh_host="10.0.0.1")  # the helper fake has no file for server 1: "missing"
        result = cs.apply_change("dhcp4", lifetime(5), "x", servers=[server])
        assert result.status == "aborted" and any("could not be read" in t for _k, t in result.lines)

    def test_a_file_that_agrees_lets_the_change_through(self, daemon, helper, store):
        server = api_server(daemon, ssh_host="10.0.0.1")
        helper.configs[(1, "dhcp4")] = {"Dhcp4": copy.deepcopy(daemon.running)}
        helper.shas[(1, "dhcp4")] = "raw-a"
        # step 8 of the sequence reads the file again after the write: the fake file now carries the new configuration
        original = daemon._answer

        def write_through(command, arguments):
            reply = original(command, arguments)
            if command == "config-write":
                helper.configs[(1, "dhcp4")] = {"Dhcp4": copy.deepcopy(daemon.running)}
            return reply

        daemon._answer = write_through
        result = cs.apply_change("dhcp4", lifetime(5), "x", servers=[server])
        assert result.status == "ok", result.lines


class TestTheCallersDoNotChange:
    def _calls(self):
        sites = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                    if name == "apply_change":
                        sites.append((path.relative_to(ROOT).as_posix(), node))
        return sites

    def test_thirteen_call_sites_exactly_five_pass_transport_file_and_none_passes_api(self):
        sites = self._calls()
        assert len(sites) == 13, [(p, n.lineno) for p, n in sites]
        file_path, other = [], []
        for path, node in sites:
            kw = {k.arg: k.value for k in node.keywords}
            if "transport" in kw:
                assert isinstance(kw["transport"], ast.Constant) and kw["transport"].value == "file"
                file_path.append(path)
            else:
                other.append(path)
        assert sorted(file_path) == sorted(
            ["jen/routes/settings/infrastructure.py"] * 3 + ["jen/services/investigation_logging.py"] * 2
        )

    def test_no_callee_of_run_change_starts_a_change_set(self):
        """The change lock is not reentrant: `finalize` writes `[subnets]` through `app_config`, and nothing under `_run_change_unlocked` may call `apply_change` or `_run_change`."""
        tree = ast.parse((ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8"))
        callers = {}
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
                name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
                if name in ("apply_change", "_run_change", "_run_change_unlocked"):
                    callers.setdefault(name, set()).add(fn.name)
        assert callers == {"_run_change": {"apply_change"}, "_run_change_unlocked": {"_run_change"}}, callers

    def test_the_finalize_callbacks_do_not_start_one(self):
        """Every `finalize=` callback in the tree: none calls apply_change (a deadlock behind the lock)."""
        offenders = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "finalize" and isinstance(kw.value, ast.Name):
                            names.add(kw.value.id)
            for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in names):
                for c in ast.walk(fn):
                    if isinstance(c, ast.Call) and getattr(c.func, "attr", getattr(c.func, "id", "")) == "apply_change":
                        offenders.append((path.name, fn.name))
        assert offenders == []


class TestOneChangeAtATime:
    def test_a_second_change_waits_and_says_so(self, daemon, helper, store):
        release = threading.Event()
        holding = threading.Event()

        def hold():
            with cs.change_lock():
                holding.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        holding.wait(2)
        threading.Timer(1.3, release.set).start()
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon)])
        t.join(3)
        assert result.status == "ok"
        assert result.lines[0][1].startswith("ℹ️ waited 1 s for another change")
        assert daemon.commands.count("config-set") == 1  # the daemon saw ONE sequence

    def test_the_give_up_sentence(self, daemon, helper, store, monkeypatch):
        monkeypatch.setattr(cs, "CHANGE_WAIT_SECONDS", 0.2)
        release = threading.Event()
        holding = threading.Event()

        def hold():
            with cs.change_lock(5):
                holding.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        holding.wait(2)
        started = time.monotonic()
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[api_server(daemon)])
        release.set()
        t.join(3)
        assert time.monotonic() - started < 3
        assert result.status == "aborted" and result.last_code == "busy"
        assert "another change is running on this box; try again in a moment" in result.lines[0][1]
        assert daemon.commands == []

    def test_the_lock_is_released_after_a_change_that_raises_nothing_and_after_one_that_aborts(
        self, daemon, helper, store
    ):
        daemon.stopped = True
        assert cs.apply_change("dhcp4", lifetime(1), "x", servers=[api_server(daemon)]).status == "aborted"
        daemon.stopped = False
        assert cs.apply_change("dhcp4", lifetime(2), "x", servers=[api_server(daemon)]).status == "ok"
