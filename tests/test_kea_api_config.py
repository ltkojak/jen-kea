"""
tests/test_kea_api_config.py
────────────────────────────
Q212 (BB1) - `jen/services/kea_api_config.py` against a fake Kea that HOLDS a configuration (tests/e2e/_fake_kea_server.py::StatefulKeaServer): `config-set` replaces what runs,
`config-write` writes a held file, a restart reloads the file, and the switches make it refuse, hang, stop or answer without its key. The module is driven through the REAL
`kea_command` over HTTP to a local server; the revision store is an in-memory stand-in (no database), the investigation question is the one `tests/test_kea_changeset.py` patches by string.

Pure: runs under `--noconftest`.
"""

import ast
import copy
import json
import logging
import pathlib

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_host as host
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 7


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture
def refusal(monkeypatch):
    """The investigation question (INV-005), patched the way tests/test_kea_changeset.py patches it - by the module's own name."""
    box = {"text": ""}
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: box["text"])
    return box


@pytest.fixture
def fake(monkeypatch, store, refusal):
    cfg = copy.deepcopy(TWO_SUBNET_DHCP4)
    cfg["lease-database"] = {"type": "mysql", "user": "kea", "password": "s3cr3t-pw"}
    f = StatefulKeaServer(cfg)
    f.start()
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)
    f.hang_seconds = 1.2
    yield f
    f.stop()


@pytest.fixture
def server(fake):
    return {"id": SID, "name": "kea-a", "api_url": fake.url, "api_user": "", "api_pass": ""}


def _candidate(cfg, lifetime=7200):
    out = copy.deepcopy(cfg)
    out["Dhcp4"]["valid-lifetime"] = lifetime
    return out


def _plan(server):
    cfg, digest = api.read(server, "dhcp4", capture=False)
    assert cfg is not None and digest
    return cfg, digest


def _apply(server, summary="a change", **kw):
    cfg, digest = _plan(server)
    return api.apply(server, "dhcp4", _candidate(cfg), digest, summary, before_cfg=cfg, **kw), cfg, digest


class TestRead:
    def test_the_digest_comes_from_the_reply_and_is_stripped_from_the_config(self, fake, server):
        cfg, digest = api.read(server, "dhcp4", capture=False)
        assert digest == fake.digest()
        assert "hash" not in cfg and "Dhcp4" in cfg
        assert fake.commands == ["config-get"]

    def test_the_service_key_is_required(self, fake, server):
        fake.no_service_key = True
        errors = []
        assert api.read(server, "dhcp4", errors=errors, capture=False) == (None, None)
        assert (
            errors and "not kea-dhcp4" in errors[0]
        )  # direct mode: kea_command's own wrong-daemon sentence; in CA mode the module says "without a Dhcp4 section"

    def test_the_modules_own_nokey_sentence_in_control_agent_mode(self, fake, server, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        fake.no_service_key = True
        errors = []
        assert api.read(server, "dhcp4", errors=errors, capture=False) == (None, None)
        assert "without a Dhcp4 section" in errors[0] and "nokey" in errors[0]

    def test_a_reply_without_a_digest_is_a_failed_read_never_a_hash_get(self, fake, server):
        fake.no_digest = True
        errors = []
        assert api.read(server, "dhcp4", errors=errors, capture=False) == (None, None)
        assert "digest" in errors[0]
        assert "config-hash-get" not in fake.commands

    def test_a_daemon_that_does_not_answer_is_a_failed_read_with_a_sentence(self, fake, server):
        fake.stopped = True
        errors = []
        assert api.read(server, "dhcp4", errors=errors, capture=False) == (None, None)
        assert errors

    def test_capture_records_a_baseline_then_an_external_change(self, fake, server, store):
        api.read(server, "dhcp4")
        assert [(r["source"], r["hash_kind"]) for r in store.rows] == [("baseline", "kea")]
        api.read(server, "dhcp4")
        assert len(store.rows) == 1  # the same digest: nothing to record
        other = copy.deepcopy(fake.running)
        other["valid-lifetime"] = 1
        fake.set_running(other)
        api.read(server, "dhcp4")
        assert [(r["source"], r["hash_kind"]) for r in store.rows] == [("baseline", "kea"), ("external", "kea")]

    def test_a_read_without_capture_records_nothing(self, fake, server, store):
        api.read(server, "dhcp4", capture=False)
        assert store.rows == []

    def test_a_file_read_skips_the_daemons_rows(self, store):
        """`kea_host._capture_baseline_or_external_change` compares with the latest NON-`kea` row: a daemon digest is never a file hash."""
        store.record(SID, "dhcp4", {"Dhcp4": {}}, "f" * 64, "file", hash_kind="raw", source="baseline")
        store.record(SID, "dhcp4", {"Dhcp4": {}}, "a" * 64, "api", hash_kind="kea", source="jen")
        host._capture_baseline_or_external_change(SID, "dhcp4", {"Dhcp4": {}}, "f" * 64)
        assert [r["source"] for r in store.rows] == ["baseline", "jen"]  # no spurious "baseline re-established"


class TestApplyInOrder:
    def test_the_exact_sequence_and_nothing_else(self, fake, server):
        result, _cfg, _digest = _apply(server)
        assert result["ok"] and result["code"] == "ok" and result["via"] == "api"
        assert fake.commands[1:] == [
            "config-hash-get",
            "config-set",
            "config-write",
            "config-get",
        ]  # [0] is the Plan read
        assert result["sha256"] == fake.digest()
        assert fake.file == fake.running and fake.running["valid-lifetime"] == 7200

    def test_once_per_service(self, monkeypatch, store, refusal):
        six = StatefulKeaServer({"subnet6": [], "hooks-libraries": []}, key="Dhcp6")
        six.start()
        try:
            monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
            monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)
            srv = {"id": SID, "name": "kea-a", "api_url": "http://127.0.0.1:1/", "api6_url": six.url}
            cfg, digest = api.read(srv, "dhcp6", capture=False)
            cand = copy.deepcopy(cfg)
            cand["Dhcp6"]["valid-lifetime"] = 9
            result = api.apply(srv, "dhcp6", cand, digest, "v6", before_cfg=cfg)
            assert result["ok"], result
            assert six.commands[1:] == ["config-hash-get", "config-set", "config-write", "config-get"]
        finally:
            six.stop()

    def test_the_revision_is_the_daemons_answer(self, fake, server, store):
        result, _cfg, _digest = _apply(server, summary="lifetime 7200")
        rows = [r for r in store.rows if r["source"] != "baseline"]
        assert len(rows) == 1  # one row per apply, never two
        row = rows[0]
        assert (row["hash_kind"], row["source"], row["sha256"]) == ("kea", "jen", result["sha256"])
        assert json.loads(row["config"]) == {"Dhcp4": fake.running}  # what config-get returned, hash stripped

    def test_a_revert_is_an_apply_with_source_rollback(self, fake, server, store):
        result, cfg, digest = _apply(server)
        back = api.revert(server, "dhcp4", cfg, result["sha256"], "rollback: a change", before_cfg=_candidate(cfg))
        assert back["ok"] and fake.running == cfg["Dhcp4"] and fake.file == cfg["Dhcp4"]
        assert [r["source"] for r in store.rows][-1] == "rollback"


class TestConflictSendsNothing:
    def test_a_stranger_changed_it_after_the_plan_read(self, fake, server, store):
        cfg, digest = _plan(server)
        stranger = copy.deepcopy(fake.running)
        stranger["valid-lifetime"] = 1
        fake.set_running(stranger)
        fake.commands.clear()
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert result["code"] == "conflict" and not result["ok"]
        assert fake.commands == ["config-hash-get"]
        assert store.pending(SID, "dhcp4") is None  # the pending record is deleted

    def test_a_daemon_that_does_not_answer_the_digest_question_sends_nothing(self, fake, server):
        cfg, digest = _plan(server)
        fake.stopped = True
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert result["code"] == "noanswer"


class TestTheApiOnlyGuard:
    @pytest.mark.parametrize(
        "mutate",
        [
            lambda c: c["Dhcp4"].__setitem__("control-sockets", [{"socket-type": "http", "socket-port": 9}]),
            lambda c: c["Dhcp4"].__setitem__("hooks-libraries", [{"library": "/usr/lib/kea/hooks/libdhcp_x.so"}]),
            lambda c: c["Dhcp4"].__setitem__(
                "control-sockets",
                [
                    {
                        "socket-type": "https",
                        "cert-file": "/etc/kea/tls/dhcp4/server.crt",
                        "key-file": "/etc/kea/tls/dhcp4/server.key",
                    }
                ],
            ),
        ],
        ids=["control-sockets", "hook library", "TLS paths"],
    )
    def test_each_is_refused_before_anything_is_sent(self, fake, server, mutate):
        cfg, digest = _plan(server)
        fake.commands.clear()
        cand = copy.deepcopy(cfg)
        mutate(cand)
        result = api.apply(server, "dhcp4", cand, digest, "x", before_cfg=cfg)
        assert result["code"] == "guard" and "file path" in result["detail"]
        assert fake.commands == []

    def test_a_pool_change_is_not_a_guard_case(self, fake, server):
        result, _c, _d = _apply(server)
        assert result["ok"]


class TestTheMarkerIsRefusedOverTheApi:
    def test_the_investigation_question_is_asked_first(self, fake, server, refusal):
        cfg, digest = _plan(server)
        fake.commands.clear()
        refusal["text"] = "the investigation marker would be erased"
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert result["code"] == "guard" and "investigation marker" in result["detail"]
        assert fake.commands == []

    def test_the_investigation_writer_passes(self, fake, server, refusal, monkeypatch):
        """`guard_kea_write` honors `investigation_writer()` exactly as `apply_config` does."""
        refusal["text"] = "would erase the marker"
        with host.investigation_writer():
            assert host.guard_kea_write(server, {}, "dhcp4") == ""
        assert host.guard_kea_write(server, {}, "dhcp4") == "would erase the marker"
        assert host.guard_kea_write(server, {}, "dhcp6") == ""  # only dhcp4 carries the marker


class TestSetFailedLeavesTheDaemon:
    def test_kea_refuses_and_the_old_configuration_serves(self, fake, server, store):
        fake.set_fails = "a pool of type V4 does not match the prefix of a subnet"
        before = copy.deepcopy(fake.running)
        result, _c, digest = _apply(server)
        assert result["code"] == "set-failed" and "does not match the prefix" in result["detail"]
        assert fake.running == before and fake.digest() == digest
        assert store.pending(SID, "dhcp4") is None

    def test_a_refusal_whose_text_looks_like_a_timeout_is_still_a_refusal(self, fake, server):
        """Read by the `transport` key, never by the sentence: Kea's own words can be anything."""
        fake.set_fails = "Kea API request timed out."
        result, _c, _d = _apply(server)
        assert result["code"] == "set-failed"

    def test_a_set_failed_that_stops_answering_needs_hands(self, fake, server, store):
        fake.set_fails = "fatal error"
        fake.set_fails_and_stops = True
        result, _c, _d = _apply(server)
        assert result["code"] == "noanswer" and result["needs_hands"]
        assert "restart reloads its file" in result["detail"]
        assert store.pending(SID, "dhcp4") is not None  # a half-known state keeps its record


class TestWriteFailedIsUndone:
    def test_the_set_is_put_back_and_the_file_is_untouched(self, fake, server, store):
        fake.write_fails = "Error during config-write: Unable to open file /etc/kea/kea-dhcp4.conf for writing"
        before = copy.deepcopy(fake.running)
        result, _c, _d = _apply(server)
        assert result["code"] == "write-failed" and "Unable to open file" in result["detail"]
        assert fake.running == before and fake.file == before
        assert fake.commands[-3:] == [
            "config-write",
            "config-set",
            "config-get",
        ]  # the undo: set the previous configuration, ask what runs
        assert store.pending(SID, "dhcp4") is None
        assert not result.get("needs_hands")

    def test_an_undo_that_cannot_be_proved_is_needs_hands(self, fake, server, store):
        fake.write_fails = "denied"
        fake.hooks["config-write"] = lambda f: setattr(f, "stopped", True) if False else None
        # the daemon refuses the write, then the undo's set is refused too
        orig = fake._answer

        def refuse_the_undo(command, arguments):
            if command == "config-set" and fake.commands.count("config-set") >= 2:
                return {"result": 1, "text": "refused"}
            return orig(command, arguments)

        fake._answer = refuse_the_undo
        result, _c, _d = _apply(server)
        assert result["code"] == "write-failed" and result["needs_hands"]
        assert store.pending(SID, "dhcp4") is not None


class TestAWriteTimeoutIsNeverOk:
    def test_three_resends_then_unverified(self, fake, server):
        fake.hang = {"config-write": "before"}
        result, _c, _d = _apply(server)
        assert fake.commands.count("config-write") == api.WRITE_ATTEMPTS
        assert result["code"] == "unverified" and not result["ok"] and result["needs_hands"]
        assert "file may not carry" in result["detail"]

    def test_with_ssh_the_files_own_answer_decides(self, fake, server, monkeypatch):
        fake.hang = {"config-write": "before"}
        server["ssh_host"] = "10.0.0.9"
        # the helper reads a file that carries what runs: proved
        monkeypatch.setattr(
            host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": copy.deepcopy(fake.running)}, "r" * 64)
        )
        result, _c, _d = _apply(server)
        assert result["ok"] and result["code"] == "ok"

    def test_with_ssh_a_file_that_differs_is_unverified(self, fake, server, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": {"stale": True}}, "r" * 64))
        result, _c, _d = _apply(server)
        assert result["code"] == "unverified" and "does not carry what the daemon runs" in result["detail"]

    def test_with_ssh_a_file_that_agrees_records_a_raw_row_beside_the_kea_row(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        monkeypatch.setattr(
            host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": copy.deepcopy(fake.running)}, "r" * 64)
        )
        result, _c, _d = _apply(server)
        assert result["ok"]
        kinds = sorted(r["hash_kind"] for r in store.rows if r["source"] == "jen")
        assert kinds == ["kea", "raw"]


class TestASetTimeoutIsAsked:
    def test_applied_then_no_answer_continues(self, fake, server):
        fake.hang = {"config-set": "after"}
        result, _c, _d = _apply(server)
        assert result["ok"], result
        assert fake.file == fake.running and fake.running["valid-lifetime"] == 7200

    def test_never_run_is_set_failed(self, fake, server):
        fake.hang = {"config-set": "before"}
        before = copy.deepcopy(fake.running)
        result, _c, _d = _apply(server)
        assert result["code"] == "set-failed" and fake.running == before

    def test_neither_the_change_nor_the_one_before_is_unverified(self, fake, server):
        fake.hang = {"config-set": "before"}
        stranger = copy.deepcopy(fake.running)
        stranger["valid-lifetime"] = 5

        fake.hooks["config-set"] = lambda f: f.set_running(stranger)
        result, _c, _d = _apply(server)
        assert result["code"] == "unverified" and result["needs_hands"]
        assert result["before_hash"] and result["after_hash"]

    def test_no_answer_to_the_question_either_is_noanswer(self, fake, server):
        fake.hang = {"config-set": "before"}
        fake.hooks["config-set"] = lambda f: setattr(f, "stopped", True)
        result, _c, _d = _apply(server)
        assert result["code"] == "noanswer" and result["needs_hands"]


class TestUnverifiedIsNotUndone:
    def test_a_different_digest_afterward_is_left_as_the_daemons_answer(self, fake, server):
        stranger = copy.deepcopy(fake.running)
        stranger["valid-lifetime"] = 3

        fake.hooks["config-write"] = lambda f: f.set_running(stranger)
        result, _c, _d = _apply(server)
        assert result["code"] == "unverified" and result["needs_hands"]
        assert fake.commands.count("config-set") == 1  # nothing was sent to put anything back


class TestThePendingRecord:
    def test_written_before_the_set_and_cleared_after_the_verify(self, fake, server, store):
        seen = {}

        def look(f):
            row = store.pending(SID, "dhcp4")
            seen["row"] = row

        fake.hooks["config-set"] = look
        cfg, digest = _plan(server)
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert result["ok"]
        assert seen["row"] is not None and seen["row"]["sha256"] == digest  # the candidate, with the BEFORE digest
        assert json.loads(seen["row"]["config"])["Dhcp4"]["valid-lifetime"] == 7200
        assert store.pending(SID, "dhcp4") is None

    def _pending(self, fake, server, store):
        cfg, digest = _plan(server)
        cand = _candidate(cfg)
        store.record(SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending")
        return cfg, digest, cand

    def test_a_change_that_is_live_is_finished_on_the_next_read(self, fake, server, store):
        _cfg, _digest, cand = self._pending(fake, server, store)
        fake.set_running(cand["Dhcp4"])  # Jen died after config-set, before config-write
        notes = []
        cfg, new = api.read(server, "dhcp4", capture=False, notes=notes)
        assert fake.file == fake.running  # config-write was sent
        assert new == fake.digest() and notes and "finished" in notes[0]
        assert store.pending(SID, "dhcp4") is None
        assert [r["source"] for r in store.rows] == ["jen"]

    def test_a_change_that_never_landed_is_deleted(self, fake, server, store):
        self._pending(fake, server, store)
        notes = []
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert store.rows == [] and notes and "never reached" in notes[0]

    def test_neither_state_stays_pending_and_blocks_an_apply_but_not_a_restore(self, fake, server, store):
        _cfg, digest, _cand = self._pending(fake, server, store)
        stranger = copy.deepcopy(fake.running)
        stranger["valid-lifetime"] = 11
        fake.set_running(stranger)
        notes = []
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert store.pending(SID, "dhcp4") is not None
        assert "neither" in notes[0] and digest in notes[0] and fake.digest() in notes[0]
        cfg, now = api.read(server, "dhcp4", capture=False)
        blocked = api.apply(server, "dhcp4", _candidate(cfg), now, "x", before_cfg=cfg)
        assert blocked["code"] == "unverified" and blocked["needs_hands"]
        restored = api.apply(server, "dhcp4", _candidate(cfg, 4), now, "restore", source="restore", before_cfg=cfg)
        assert restored["ok"], restored

    def test_no_answer_leaves_the_record(self, fake, server, store):
        self._pending(fake, server, store)
        fake.stopped = True
        assert api.read(server, "dhcp4", capture=False) == (None, None)
        assert store.pending(SID, "dhcp4") is not None


class TestNoReplyOrPayloadIsLogged:
    def test_no_password_and_no_key_of_the_configuration_reaches_a_log(self, fake, server, caplog):
        caplog.set_level(logging.DEBUG)
        _apply(server)  # the whole happy path
        fake.write_fails = "denied"
        _apply(server)  # a write failure and its undo
        fake.write_fails = None
        fake.set_fails = "refused"
        _apply(server)  # a refusal
        fake.set_fails = None
        fake.hang = {"config-write": "before"}
        _apply(server)  # a hang
        text = caplog.text
        assert "s3cr3t-pw" not in text and "subnet4" not in text and "valid-lifetime" not in text
        assert "config-set" in text  # command names are what it logs


class TestD2IsRefused:
    def test_the_module_answers_noservice(self, fake, server):
        result = api.apply(server, "d2", {"DhcpDdns": {}}, "h", "x")
        assert result["code"] == "noservice" and not result["ok"]
        assert api.read(server, "d2", errors=[], capture=False) == (None, None)
        assert api.hash(server, "d2") is None
        assert fake.commands == []


class TestTheModuleIsTheOneSender:
    def test_the_three_commands_appear_in_one_module_only(self):
        words = ("config-set", "config-write", "config-hash-get")
        found = {}
        for path in sorted((ROOT / "jen").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for w in words:
                if f'"{w}"' in text or f"'{w}'" in text:
                    found.setdefault(w, set()).add(path.relative_to(ROOT).as_posix())
        assert found == {w: {"jen/services/kea_api_config.py"} for w in words}, found

    def test_the_module_has_no_ssh_import_and_posts_only_through_kea_command(self):
        tree = ast.parse((ROOT / "jen/services/kea_api_config.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported |= {f"{node.module}.{a.name}" if node.module else a.name for a in node.names}
        allowed = {
            "__future__.annotations",
            "copy",
            "json",
            "logging",
            "jen.services.config_revisions",
            "jen.services.kea",
            "jen.services.kea_host",
            "jen.services.kea_authoring",
            "jen.services.kea_tls",
        }
        assert imported <= allowed, imported - allowed
        calls = {
            ast.unparse(n.func)
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and "post" in ast.unparse(n.func).lower()
        }
        assert calls == set(), calls  # no direct HTTP: every command goes through `kea_command`
