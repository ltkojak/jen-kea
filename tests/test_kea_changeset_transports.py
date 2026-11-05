"""
tests/test_kea_changeset_transports.py
──────────────────────────────────────
Q212 (BB2) - the change set over whichever transport each target has. An `api` target is a stateful fake Kea (tests/e2e/_fake_kea_server.py::StatefulKeaServer) reached by the REAL
`kea_command`; a `file` target is the helper fake the rest of the change-set tests use. Pure: runs under `--noconftest`.
"""

import ast
import copy
import json
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
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    return world.install_probes(monkeypatch)


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
            (
                {"config_transport": "api", "ssh_host": "h"},
                "dhcp6",
                "file",
            ),  # dhcp6 joins D2 on the file path in this beta
            ({"config_transport": "api"}, "dhcp6", "off"),
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
        assert any("kea-off: read-only" in text for _k, text in result.lines)
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
        assert [r["source"] for r in store.rows if r["source"] == "rollback" and r["hash_kind"] == "kea"] == [
            "rollback"
        ]

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


class TestSecondPassRowsOfTheChangeSet:
    def test_row8_a_blank_form_digest_falls_back_to_the_plan_digest(self, daemon, helper, store):
        """`expected_sha_for` answering None for an api target must not turn the compare into no compare: a stranger's change after the Plan makes the set refuse."""
        server = api_server(daemon)

        def stranger_after_the_plan(srv):
            changed = copy.deepcopy(daemon.running)
            changed["valid-lifetime"] = 55
            daemon.set_running(changed)  # between the Plan read and the Commit
            return None

        result = cs.apply_change(
            "dhcp4", lifetime(7200), "x", servers=[server], expected_sha_for=stranger_after_the_plan
        )
        assert (
            result.status == "aborted" and daemon.running["valid-lifetime"] == 55
        )  # the stranger's change was not overwritten

    def test_row2_an_unresolved_pending_change_stops_the_plan_before_any_file_target_is_written(
        self, daemon, helper, store
    ):
        cfg = copy.deepcopy(daemon.running)
        store.record(
            1,
            "dhcp4",
            {"Dhcp4": {**cfg, "valid-lifetime": 1}},
            "before",
            "left by a crash",
            hash_kind="kea",
            source="pending",
        )
        changed = copy.deepcopy(daemon.running)
        changed["valid-lifetime"] = 99
        daemon.set_running(changed)  # neither state
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[FILE_SERVER, api_server(daemon)])
        assert result.status == "aborted" and result.last_code == "needs-hands"
        assert "apply-config" not in helper.ops()  # the file target was never written

    def test_row1_a_rollback_and_investigations_own_revert_pass_the_choke_points_compare(
        self, daemon, helper, store, monkeypatch
    ):
        server = {"id": 3, "name": "kea-c", "ssh_host": "10.0.0.3", "config_transport": "api", "api_url": daemon.url}
        helper.configs[(3, "dhcp4")] = {"Dhcp4": {"valid-lifetime": 1}}  # a file the daemon does not run
        helper.shas[(3, "dhcp4")] = "raw-c"
        assert not kea_host.apply_config(server, "dhcp4", {"Dhcp4": {}}, source="jen")["ok"]  # a new write is refused
        assert kea_host.apply_config(server, "dhcp4", {"Dhcp4": {}}, source="rollback")["ok"]
        with kea_host.investigation_writer():
            assert kea_host.apply_config(server, "dhcp4", {"Dhcp4": {}}, source="jen")["ok"]


class TestQ216TheRestoreWindowIsAskedAtPlan:
    def test_a_mixed_set_inside_the_window_writes_nothing_anywhere(self, daemon, helper, store, monkeypatch):
        """BF6: the window is asked at PLAN, beside the probe gate - not inside `apply`, after the file targets were written and had to be reverted."""
        monkeypatch.setattr(
            "jen.services.investigation_logging.restore_window",
            lambda server, now=None: "the host is restoring logging at 2026-11-04T12:00:30+00:00; try again after it",
        )
        server = api_server(daemon)
        daemon.commands.clear()
        before = copy.deepcopy(helper.configs[(2, "dhcp4")])
        result = cs.apply_change("dhcp4", lifetime(7200), "x", servers=[FILE_SERVER, server])
        assert result.status == "aborted" and result.last_code == "investigation-on"
        assert "try again after it" in " ".join(t for _k, t in result.lines)
        assert helper.configs[(2, "dhcp4")] == before and "apply-config" not in helper.ops()
        assert not any(c in daemon.commands for c in ("config-set", "config-write", "config-hash-get"))

    def test_a_file_only_set_is_not_asked(self, daemon, helper, store, monkeypatch):
        monkeypatch.setattr(
            "jen.services.investigation_logging.restore_window",
            lambda server, now=None: pytest.fail("a file target is not asked"),
        )
        assert cs.apply_change("dhcp4", lifetime(7200), "x", servers=[FILE_SERVER]).status == "ok"


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

    def test_a_restart_records_the_daemons_digest(self, daemon, helper, store):
        """Q217 AB1 - `record_after_file_write` pinned from the change set's caller: the `kea` row carries the digest the daemon answers with after the restart."""
        server = self._wire(daemon, helper, {"Dhcp4": copy.deepcopy(daemon.running)})
        assert cs.apply_change("dhcp4", lifetime(5), "logging on", servers=[server], transport="file").status == "ok"
        row = [r for r in store.rows if r["hash_kind"] == "kea" and r["source"] == "jen"][-1]
        assert row["sha256"] == daemon.digest()

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


class TestAPreviewValidatesOnItsOwnTransport:
    """Q217 AB7 - `kea_host.test_via_transport`: the validation a preview runs is the one the write would take. An api server with no SSH validates over `config-test`; a file server through the
    helper; an off server is skipped (nothing will be written, so Apply is not held by it)."""

    def test_an_api_server_with_no_ssh_is_validated_by_the_daemon(self, daemon, helper, store):
        res = kea_host.test_via_transport(api_server(daemon), "dhcp4", {"Dhcp4": copy.deepcopy(daemon.running)})
        assert res["ok"] is True and "config-test" in daemon.commands and "test-config" not in helper.ops()

    def test_a_daemon_that_refuses_the_candidate_says_so(self, daemon, helper, store):
        daemon.test_fails = "bad pool"
        res = kea_host.test_via_transport(api_server(daemon), "dhcp4", {"Dhcp4": copy.deepcopy(daemon.running)})
        assert res["ok"] is False and res["code"] == "testerror"

    def test_a_file_server_is_validated_through_the_helper(self, daemon, helper, store):
        res = kea_host.test_via_transport(FILE_SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["ok"] is True and "test-config" in helper.ops() and "config-test" not in daemon.commands

    def test_the_helper_only_and_tls_arguments_reach_the_file_path(self, daemon, helper, store, monkeypatch):
        seen = {}
        monkeypatch.setattr(kea_host, "test_config", lambda server, service, cfg, **kw: seen.update(kw) or {"ok": True})
        kea_host.test_via_transport(FILE_SERVER, "dhcp4", {}, tls_paths={"a": "b"}, helper_only=True)
        assert seen == {"tls_paths": {"a": "b"}, "helper_only": True}

    def test_an_off_server_is_skipped_and_nothing_is_sent(self, daemon, helper, store):
        server = {"id": 9, "name": "kea-z", "api_url": daemon.url, "ssh_host": "10.0.0.9", "config_transport": "off"}
        res = kea_host.test_via_transport(server, "dhcp4", {"Dhcp4": {}})
        assert res == {"ok": True, "code": "skipped", "detail": "read-only"}
        assert "config-test" not in daemon.commands and "test-config" not in helper.ops()


class TestAnUnreadableRecordStore:
    """Q217 AB9 - a store that cannot be asked is its own outcome at PLAN: nothing is sent, and nobody's hands are needed (the store has to come back)."""

    def test_an_unreadable_store_aborts_without_hands(self, daemon, helper, store):
        server = api_server(daemon)
        store.unreadable = True
        result = cs.apply_change("dhcp4", lifetime(5), "x", servers=[server])
        assert result.status == "aborted" and result.last_code == "unreadable"
        assert result.needs_hands == [] and result.needs_hands_ids == []
        assert any("cannot be read" in t for _k, t in result.lines)
        assert not any(c in daemon.commands for c in ("config-set", "config-write"))


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


EDIT_KEY = "user-context"
EDIT = {"jen-note": "the operator's own edit, never loaded by the daemon"}


class TestTheSettlementAsksTheFileFirst:
    """Q218 BH1 c (AC1, the P1): the WORLD where both guards fire - a live pending row (a process died between `config-set` and the verify) AND a hand edit of the file on the Kea host. The Plan used to settle
    the row (a `config-write`) BEFORE it asked about the edit, so the question was asked of a file already replaced and the set went on over a destroyed edit. Now the sender asks."""

    @pytest.fixture
    def ssh_server(self, daemon, store, monkeypatch):
        server = api_server(daemon, ssh_host="10.0.0.1")
        monkeypatch.setattr(kea_host, "guard_kea_write", lambda *a, **k: "")
        self.seen = world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=1)
        kea_host.read_config_versioned(
            server, "dhcp4"
        )  # the baseline of the clean file: what the store already has when an edit appears
        self.seen["reads"].clear()
        return server

    def _live_pending(self, daemon, server, store, *, record_before=True):
        cfg, digest = api.read(
            server, "dhcp4", capture=record_before
        )  # a capturing read records the state before as a `kea` row
        cand = copy.deepcopy(cfg)
        cand["Dhcp4"]["subnet4"].append(
            {"id": 96, "subnet": "10.96.0.0/24", "pools": [{"pool": "10.96.0.1-10.96.0.9"}]}
        )
        store.record(1, "dhcp4", cand, digest, "a change the crash left", hash_kind="kea", source="pending")
        daemon.set_running(cand["Dhcp4"])  # the daemon took it; the file is still the state before
        return cfg, digest

    def test_a_live_pending_row_and_a_hand_edit_write_nothing_and_name_the_edit(self, daemon, ssh_server, store):
        self._live_pending(daemon, ssh_server, store)
        daemon.file[EDIT_KEY] = copy.deepcopy(EDIT)
        daemon.commands.clear()
        result = cs.apply_change("dhcp4", lifetime(7200), "a subnet edit", servers=[ssh_server])
        assert result.status != "ok", result.lines
        assert "config-write" not in daemon.commands and "config-set" not in daemon.commands
        assert EDIT_KEY in daemon.file, "the operator's edit is still on the host"
        text = " ".join(t for _k, t in result.lines)
        assert "Dhcp4.user-context" in text and "carries an edit the daemon has not loaded" in text
        assert store.pending(1, "dhcp4") is not None, "the row stays: the daemon runs the change, the file waits"
        external = [r for r in store.rows if r["source"] == "external"]
        assert external and EDIT_KEY in json.loads(external[-1]["config"])["Dhcp4"], "and the edit is in Config history"

    def test_the_control_with_no_pending_row_is_the_q216_refusal(self, daemon, ssh_server, store):
        daemon.file[EDIT_KEY] = copy.deepcopy(EDIT)
        daemon.commands.clear()
        result = cs.apply_change("dhcp4", lifetime(7200), "a subnet edit", servers=[ssh_server])
        assert result.status == "aborted"
        assert "config-write" not in daemon.commands and EDIT_KEY in daemon.file
        assert any("Dhcp4.user-context" in t for _k, t in result.lines)

    def test_the_second_control_a_pending_row_and_a_file_equal_to_the_state_before_settles_and_goes_on(
        self, daemon, ssh_server, store
    ):
        self._live_pending(daemon, ssh_server, store)
        result = cs.apply_change("dhcp4", lifetime(7200), "a subnet edit", servers=[ssh_server])
        assert result.status == "ok", result.lines
        assert daemon.running["valid-lifetime"] == 7200 and daemon.file == daemon.running
        assert store.pending(1, "dhcp4") is None

    def test_settle_it_now_asks_the_same_question(self, daemon, ssh_server, store):
        self._live_pending(daemon, ssh_server, store)
        daemon.file[EDIT_KEY] = copy.deepcopy(EDIT)
        daemon.commands.clear()
        lines, settled = api.settle_pending(ssh_server, "dhcp4")
        assert settled is False and "config-write" not in daemon.commands and EDIT_KEY in daemon.file
        assert "Dhcp4.user-context" in lines[0]

    def test_a_pending_row_with_no_revision_of_the_state_before_is_refused_by_the_plan(self, daemon, ssh_server, store):
        self._live_pending(daemon, ssh_server, store, record_before=False)
        daemon.commands.clear()
        result = cs.apply_change("dhcp4", lifetime(7200), "a subnet edit", servers=[ssh_server])
        assert result.status != "ok" and "config-write" not in daemon.commands
        assert "cannot be proved against the state before the change" in " ".join(t for _k, t in result.lines)


class TestTheFirstWriteTarget:
    """Q218 BH6 h (AC27): the import reads, validates and applies on the first server that takes changes - not `KEA_SERVERS[0]`, which may be Read-only while the second is on Live API."""

    def test_the_first_server_that_is_not_read_only(self, monkeypatch):
        servers = [
            {"id": 1, "name": "kea-a", "api_url": "http://a/", "config_transport": "off"},
            {"id": 2, "name": "kea-b", "api_url": "http://b/", "config_transport": "api"},
            {"id": 3, "name": "kea-c", "api_url": "http://c/", "ssh_host": "10.0.0.3"},
        ]
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        assert cs.first_write_target("dhcp4")["id"] == 2
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers[:1])
        assert cs.first_write_target("dhcp4") is None
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        assert cs.first_write_target("dhcp4") is None
        # dhcp6 has no API transport: a server with no SSH host takes nothing there
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        assert cs.first_write_target("dhcp6")["id"] == 3

    def test_no_import_route_reads_the_first_server_in_the_list(self):
        source = (ROOT / "jen" / "routes" / "subnets.py").read_text(encoding="utf-8")
        assert "extensions.KEA_SERVERS[0]" not in source.replace("`KEA_SERVERS[0]`", "")
        assert source.count("first_write_target(") == 3  # the import preview, its apply and the reservations step
