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


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    return world.install_probes(monkeypatch)


@pytest.fixture
def refusal(monkeypatch):
    """The investigation question (INV-005), patched the way tests/test_kea_changeset.py patches it - by the module's own name."""
    box = {"text": ""}
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: box["text"])
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
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

    def test_dhcp6_and_d2_are_not_served_in_this_beta(self, fake, server):
        """ISC's dhcp4 image has no kea-dhcp6, so row 10 could not be built against a real daemon (run 41703269176): dhcp6 joins D2 on the file path."""
        for service in ("dhcp6", "d2"):
            assert api.apply(server, service, {"Dhcp6": {}}, "h", "x")["code"] == "noservice"
            assert api.read(server, service, errors=[], capture=False) == (None, None)
            assert api.hash(server, service) is None
        assert fake.commands == []

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

    def test_a_change_that_is_live_is_classified_by_a_read_and_finished_by_the_settle(self, fake, server, store):
        _cfg, _digest, cand = self._pending(fake, server, store)
        fake.set_running(cand["Dhcp4"])  # Jen died after config-set, before config-write
        notes = []
        fake.commands.clear()
        cfg, new = api.read(server, "dhcp4", capture=False, notes=notes)
        assert fake.commands == ["config-get"], "a read sends config-get and nothing else (Q216 AA19)"
        assert fake.file != fake.running and store.pending(SID, "dhcp4") is not None
        assert new == fake.digest() and notes and "is live" in notes[0]
        lines = api.settle_pending(server, "dhcp4")  # the settlement: under the lock, from the card or the Plan
        assert fake.file == fake.running  # config-write was sent
        assert lines and "finished" in lines[0] and store.pending(SID, "dhcp4") is None
        assert [r["source"] for r in store.rows] == ["jen"]

    def test_a_change_that_never_landed_is_classified_by_a_read_and_deleted_by_the_settle(self, fake, server, store):
        self._pending(fake, server, store)
        notes = []
        fake.commands.clear()
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert fake.commands == ["config-get"] and notes and "never reached" in notes[0] and store.rows != []
        lines = api.settle_pending(server, "dhcp4")
        assert store.rows == [] and "never reached" in lines[0]

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
            "jen.services.investigation_logging",  # the host's restore window (lazy: that module imports the change set)
            "hashlib",  # the probe is bound to its endpoint by a hash
            "datetime.datetime",  # the stored probe's clock (lazy)
            "datetime.timezone",
            "jen.models.user",  # the stored probe is a settings row (lazy)
        }
        assert imported <= allowed, imported - allowed
        calls = {
            ast.unparse(n.func)
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and "post" in ast.unparse(n.func).lower()
        }
        assert calls == set(), calls  # no direct HTTP: every command goes through `kea_command`


from jen.services import investigation_logging as _inv  # noqa: E402

_REAL_RESTORE_WINDOW = _inv.restore_window  # captured before any fixture patches it out


class TestSecondPassRows:
    """The rows of pass/reports/v7.0.0-beta.1-fix-rows.md (fix rows 1-3, 7, 8 and P3a)."""

    def test_row3_a_young_pending_row_is_not_settled_by_a_reader(self, fake, server, store):
        cfg, digest = _plan(server)
        from datetime import datetime, timezone

        rid = store.record(SID, "dhcp4", _candidate(cfg), digest, "in flight", hash_kind="kea", source="pending")
        store.rows[-1]["created_at"] = datetime.now(
            timezone.utc
        )  # an apply is between its pending record and its config-set
        notes = []
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert notes and "in progress" in notes[0] and store.pending(SID, "dhcp4")["id"] == rid  # not discarded

    def test_row2_a_change_that_stands_supersedes_an_unresolved_pending_row(self, fake, server, store):
        cfg, digest = _plan(server)
        stranger = copy.deepcopy(fake.running)
        stranger["valid-lifetime"] = 11
        store.record(SID, "dhcp4", _candidate(cfg, 99), digest, "left by a crash", hash_kind="kea", source="pending")
        fake.set_running(stranger)  # neither state
        cfg2, d2 = api.read(server, "dhcp4", capture=False)
        restored = api.apply(server, "dhcp4", _candidate(cfg2, 4), d2, "restore", source="restore", before_cfg=cfg2)
        assert restored["ok"] and store.pending(SID, "dhcp4") is None
        cfg3, d3 = api.read(server, "dhcp4", capture=False)
        assert api.apply(server, "dhcp4", _candidate(cfg3, 5), d3, "normal", before_cfg=cfg3)["ok"]

    def test_row7_an_authored_file_is_a_subset_of_what_the_daemon_runs(self):
        authored = {"Dhcp4": {"valid-lifetime": 3600, "subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        running = {
            "Dhcp4": {
                "valid-lifetime": 3600,
                "echo-client-id": True,
                "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "t1-percent": 0.5}],
            }
        }
        assert api.file_in_daemon(authored, running, "dhcp4")
        edited = {
            "Dhcp4": {
                "valid-lifetime": 3600,
                "subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}, {"id": 2, "subnet": "10.1.0.0/24"}],
            }
        }
        assert not api.file_in_daemon(edited, running, "dhcp4")  # a hand-added subnet the daemon does not run
        assert api.same_modulo_defaults(running, authored, "dhcp4")

    def test_row3_p3a_a_write_that_may_have_landed_before_a_refusal_is_needs_hands(self, fake, server, store):
        fake.hang = {"config-write": "after"}  # the first write lands and goes quiet
        original = fake._answer
        seen = {"n": 0}

        def second_refused(command, arguments):
            if command == "config-write":
                seen["n"] += 1
                fake.hang.clear()  # only the FIRST attempt goes quiet (the handler already took its mode for this one)
                if seen["n"] >= 2:
                    return {"result": 1, "text": "denied"}
            return original(command, arguments)

        fake._answer = second_refused
        result, _c, _d = _apply(server)
        assert result["code"] == "write-failed" and result["needs_hands"] and "earlier attempt" in result["detail"]


class TestTheFirstDifferenceIsNamed:
    """Q217 BG3 b: ONE walk answers "is it carried?" and "where does it differ?"; `_carries` is its negation, so they cannot disagree."""

    FILE = {
        "Dhcp4": {
            "valid-lifetime": 3600,
            "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.10 - 10.0.0.20"}]}],
            "hosts-database": {"type": "mysql", "name": "kea", "password": "hunter2-secret"},
        }
    }

    def _live(self):
        return {
            "Dhcp4": {
                "valid-lifetime": 3600,
                "decline-probation-period": 86400,
                "subnet4": [
                    {"id": 1, "subnet": "10.0.0.0/24", "t1-percent": 0.5, "pools": [{"pool": "10.0.0.10-10.0.0.20"}]}
                ],
                "hosts-databases": [{"type": "mysql", "name": "kea", "password": "hunter2-secret", "port": 3306}],
            }
        }

    def test_a_file_that_is_carried_names_nothing(self):
        # a renamed key IS carried, and a pool with spaces IS the same pool
        assert api.difference_text(self.FILE, self._live(), "dhcp4") == "" and api.file_in_daemon(
            self.FILE, self._live(), "dhcp4"
        )

    def test_a_changed_leaf(self):
        live = self._live()
        live["Dhcp4"]["valid-lifetime"] = 7200
        text = api.difference_text(self.FILE, live, "dhcp4")
        assert text == "at Dhcp4.valid-lifetime: the file says 3600, the daemon 7200"
        assert not api.file_in_daemon(self.FILE, live, "dhcp4")

    def test_a_missing_key(self):
        live = self._live()
        del live["Dhcp4"]["valid-lifetime"]
        assert (
            api.difference_text(self.FILE, live, "dhcp4")
            == "at Dhcp4.valid-lifetime: the file says 3600, the daemon nothing"
        )

    def test_a_longer_list(self):
        file_cfg = copy.deepcopy(self.FILE)
        file_cfg["Dhcp4"]["subnet4"].append({"id": 2, "subnet": "10.1.0.0/24"})
        text = api.difference_text(file_cfg, self._live(), "dhcp4")
        assert text == "at Dhcp4.subnet4: the file says a list of 2, the daemon a list of 1"

    def test_the_path_is_built_as_the_walk_descends(self):
        live = self._live()
        live["Dhcp4"]["subnet4"][0]["pools"][0]["pool"] = "10.0.0.10-10.0.0.99"
        assert api.difference_text(self.FILE, live, "dhcp4").startswith("at Dhcp4.subnet4[0].pools[0].pool: ")

    def test_the_value_under_a_password_key_is_never_printed(self):
        live = self._live()
        live["Dhcp4"]["hosts-databases"][0]["password"] = "a-different-secret"
        text = api.difference_text(self.FILE, live, "dhcp4")
        assert text.startswith("at Dhcp4.hosts-database.password") and "hunter2" not in text and "different" not in text
        assert "not shown" in text

    def test_a_missing_object_is_not_printed_whole(self):
        live = self._live()
        del live["Dhcp4"]["hosts-databases"]
        text = api.difference_text(self.FILE, live, "dhcp4")
        assert (
            text == "at Dhcp4.hosts-database: the file says an object with 3 keys, the daemon nothing"
            and "hunter2" not in text
        )

    def test_a_leaf_is_cut_to_sixty_characters(self):
        file_cfg = {"Dhcp4": {"user-context": {"note": "x" * 200}}}
        live = {"Dhcp4": {"user-context": {"note": "y" * 200}}}
        text = api.difference_text(file_cfg, live, "dhcp4")
        assert "x" * 60 not in text and "…" in text

    def test_first_difference_is_the_negation_of_carries(self):
        for running, candidate in (
            ({"a": 1}, {"a": 1}),
            ({"a": 1}, {"a": 2}),
            ({"a": [1, 2]}, {"a": [1]}),
            ({}, {"b": 1}),
        ):
            assert (api.first_difference(running, candidate) == "") is api._carries(running, candidate)


class TestQ216TheRegister:
    """Q216 - BF3 (no compare, no set), BF8 b (a hook's parameters), g (an unreadable record), o (the digest on record) and l (one restore window per Kea)."""

    def test_bf3_no_digest_to_compare_against_sends_nothing_and_writes_no_pending_row(self, fake, server, store):
        cfg, _digest = _plan(server)
        fake.commands.clear()
        result = api.apply(server, "dhcp4", _candidate(cfg), "", "x", before_cfg=cfg)
        assert result["code"] == "conflict" and "no digest to compare against" in result["detail"]
        assert fake.commands == [] and store.rows == []

    def test_bf8b_a_hooks_parameters_are_part_of_the_guard(self):
        before = {
            "Dhcp4": {
                "hooks-libraries": [
                    {
                        "library": "/usr/lib/ha.so",
                        "parameters": {
                            "high-availability": [
                                {"this-server-name": "a", "peers": [{"url": "http://10.0.0.2:8000/"}]}
                            ]
                        },
                    }
                ]
            }
        }
        same = copy.deepcopy(before)
        assert api._api_only_guard("dhcp4", before, same) == ""
        changed = copy.deepcopy(before)
        changed["Dhcp4"]["hooks-libraries"][0]["parameters"]["high-availability"][0]["peers"][0]["url"] = (
            "http://10.0.0.9:8000/"
        )
        assert (
            api._api_only_guard("dhcp4", before, changed) == api.GUARD_SENTENCE and "parameters" in api.GUARD_SENTENCE
        )
        reordered = copy.deepcopy(before)
        reordered["Dhcp4"]["hooks-libraries"].append({"library": "/usr/lib/lease_cmds.so"})
        assert api._api_only_guard("dhcp4", before, reordered)

    def test_bf8b_a_revision_from_before_an_ha_peer_change_is_refused_over_the_api(self, fake, server, store):
        """The Config history restore row: the restore's candidate is an OLDER revision; its hooks entry carries the old peer address, so it goes through the file path."""
        cfg, digest = _plan(server)
        running = copy.deepcopy(cfg)
        running["Dhcp4"]["hooks-libraries"] = [
            {
                "library": "/usr/lib/ha.so",
                "parameters": {"high-availability": [{"peers": [{"url": "http://10.0.0.9:8000/"}]}]},
            }
        ]
        old = copy.deepcopy(running)
        old["Dhcp4"]["hooks-libraries"][0]["parameters"]["high-availability"][0]["peers"][0]["url"] = (
            "http://10.0.0.2:8000/"
        )
        fake.commands.clear()
        result = api.apply(server, "dhcp4", old, digest, "restore", source="restore", before_cfg=running)
        assert result["code"] == "guard" and "its parameters" in result["detail"] and fake.commands == []

    def test_bg_an_unreadable_record_is_a_refusal_and_nothing_is_sent(self, fake, server, store):
        cfg, digest = _plan(server)
        store.unreadable = True
        fake.commands.clear()
        blocked = api.pending_block(server, "dhcp4")
        assert "cannot be read" in blocked
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert result["code"] == "unverified" and "cannot be read" in result["detail"]
        assert not any(c in fake.commands for c in ("config-set", "config-write", "config-hash-get"))
        assert "cannot be read" in api.record_unreadable(server, "dhcp4")

    def test_bg_a_read_still_answers_and_says_the_record_could_not_be_read(self, fake, server, store):
        store.unreadable = True
        notes = []
        cfg, digest = api.read(server, "dhcp4", capture=False, notes=notes)
        assert cfg is not None and digest and notes and "cannot be read" in notes[0]

    def test_bg_the_real_store_raises_rather_than_answering_none(self, monkeypatch):
        from jen.services import config_revisions as rev

        class Boom:
            def __enter__(self):
                raise OSError("database down")

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(rev, "_jen_db", lambda: Boom())
        with pytest.raises(rev.RevisionStoreUnreadable):
            rev.pending(7, "dhcp4")

    def test_bo_a_hand_set_of_a_key_the_file_omits_is_a_difference_when_a_digest_is_on_record(
        self, fake, server, store, monkeypatch
    ):
        """The containment blind spot: the daemon writes 45 defaults out that the file omits, so a stranger's `config-set` of ONE of them is invisible to `file_in_daemon`. The digest of the last
        configuration Jen recorded is the check; the file-path write is refused naming both."""
        fake.expand = _expands
        cfg, digest = _plan(server)
        file_cfg = {"Dhcp4": copy.deepcopy(fake.running)}
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: (copy.deepcopy(file_cfg), "r" * 64))
        server = {**server, "ssh_host": "10.0.0.7", "config_transport": "api"}
        store.record(
            SID, "dhcp4", {"Dhcp4": copy.deepcopy(fake.running)}, fake.digest(), "jen", hash_kind="kea", source="jen"
        )
        assert api.api_daemon_differs(server, "dhcp4") == ""  # as recorded: the daemon is what Jen last wrote
        stranger = copy.deepcopy(fake.running)
        stranger["decline-probation-period"] = 123  # an expanded default the FILE omits
        fake.set_running(stranger)
        file_cfg = {"Dhcp4": {k: v for k, v in file_cfg["Dhcp4"].items() if k != "decline-probation-period"}}
        sentence = api.api_daemon_differs(server, "dhcp4")
        assert "not the one Jen last recorded" in sentence and fake.digest()[:12] in sentence

    def test_bo_without_a_kea_row_containment_is_the_fallback_and_its_limit_is_named_by_this_test(
        self, fake, server, store, monkeypatch
    ):
        fake.expand = _expands
        _plan(server)
        file_cfg = {"Dhcp4": {"valid-lifetime": fake.running["valid-lifetime"]}}  # the file omits the defaults
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: (copy.deepcopy(file_cfg), "r" * 64))
        server = {**server, "ssh_host": "10.0.0.7", "config_transport": "api"}
        stranger = copy.deepcopy(fake.running)
        stranger["decline-probation-period"] = 123
        fake.set_running(stranger)
        assert (
            api.api_daemon_differs(server, "dhcp4") == ""
        )  # no `kea` row on record: containment says the file is in the daemon, and it is - the limit of the fallback

    def test_bl_one_kea_is_one_window_whichever_server_id_names_it(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        until = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(timespec="seconds")
        record = {
            "servers": {"9": {"name": "kea-a", "until": until, "ssh_host": "10.0.0.7", "removed": True}},
            "damaged": False,
        }
        monkeypatch.setattr(_inv, "_record", lambda: record)
        same_kea = {"id": 2, "ssh_host": "10.0.0.7"}
        other_kea = {"id": 3, "ssh_host": "10.0.0.8"}
        assert "try again after it" in _REAL_RESTORE_WINDOW(same_kea)
        assert _REAL_RESTORE_WINDOW(other_kea) == ""

    def test_reads_from_every_route_send_one_command(self, fake, server, store, monkeypatch):
        """Q216 AA19, the whole-tree reading: the one function every GET reads a configuration through sends `config-get` and nothing else, with a settled-by-content pending row on record."""
        cfg, digest = _plan(server)
        cand = copy.deepcopy(cfg)
        cand["Dhcp4"]["valid-lifetime"] = 4242
        store.record(SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending")
        fake.set_running(cand["Dhcp4"])
        fake.commands.clear()
        host.read_via_transport(server, "dhcp4")
        assert fake.commands == ["config-get"], fake.commands
        assert store.pending(SID, "dhcp4") is not None

    def test_the_source_has_one_settler_and_a_read_never_calls_it(self):
        tree = ast.parse((ROOT / "jen" / "services" / "kea_api_config.py").read_text(encoding="utf-8"))
        read = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read")
        called = {
            (c.func.id if isinstance(c.func, ast.Name) else c.func.attr)
            for c in ast.walk(read)
            if isinstance(c, ast.Call) and isinstance(c.func, (ast.Name, ast.Attribute))
        }
        assert not called & {"_reconcile_pending", "settle_pending", "write_file", "_write_with_retries"}, called
        assert "_classify_pending" in called


class TestTheHostsDeadlineIsRespected:
    """BB9 d: an API write within two sweep intervals of an investigation deadline could land over the HOST's restore (Kea has no compare-and-set), so it is refused with the host's own words."""

    def _entry(self, monkeypatch, minutes_from_now, **entry):
        from datetime import datetime, timedelta, timezone

        until = (datetime.now(timezone.utc) + timedelta(minutes=minutes_from_now)).isoformat(timespec="seconds")
        record = {"servers": {str(SID): {"name": "kea-a", "until": until, **entry}}, "damaged": False}
        monkeypatch.setattr(_inv, "_record", lambda: record)
        monkeypatch.setattr(_inv, "restore_window", _REAL_RESTORE_WINDOW)
        return until

    def test_a_deadline_two_minutes_away_refuses_and_nothing_is_sent(self, fake, server, monkeypatch):
        cfg, digest = _plan(server)
        fake.commands.clear()
        until = self._entry(monkeypatch, 1.5)
        result = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert (
            result["code"] == "investigation-on"
            and "try again after it" in result["detail"]
            and until in result["detail"]
        )
        assert fake.commands == []

    def test_a_deadline_that_has_just_passed_refuses_too(self, fake, server, monkeypatch):
        cfg, digest = _plan(server)
        self._entry(monkeypatch, -1.5)
        assert api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)["code"] == "investigation-on"

    def test_a_deadline_ten_minutes_away_does_not(self, fake, server, monkeypatch):
        cfg, digest = _plan(server)
        self._entry(monkeypatch, 10)
        assert api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)["ok"]

    def test_an_entry_already_restored_in_the_file_and_the_daemon_has_nothing_to_protect(
        self, fake, server, monkeypatch
    ):
        cfg, digest = _plan(server)
        self._entry(monkeypatch, 1, file="restored", daemon="restored")
        assert api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)["ok"]

    def test_a_rollback_is_not_stopped_by_it(self, fake, server, monkeypatch):
        cfg, digest = _plan(server)
        self._entry(monkeypatch, 1)
        assert api.apply(server, "dhcp4", _candidate(cfg), digest, "x", source="rollback", before_cfg=cfg)["ok"]

    def test_only_dhcp4_carries_the_marker(self, fake, server, monkeypatch):
        self._entry(monkeypatch, 1)
        assert _REAL_RESTORE_WINDOW({"id": SID + 1}) == ""  # another server's id: no entry


def _expands(section):
    """What Kea does to what it is given (docs/ARCHITECTURE.md 3.17, row 08): defaults written into every subnet."""
    out = copy.deepcopy(section)
    for subnet in out.get("subnet4", []):
        subnet.setdefault("t1-percent", 0.5)
        subnet.setdefault("allocator", "iterative")
        subnet.setdefault("reservations", [])
    out.setdefault("echo-client-id", True)
    return out


class TestKeaWritesItsDefaultsOut:
    """Real Kea (compat run 41703269176) answers `config-get` with defaults written into a subnet Jen just added, so a candidate is a SUBSET of what the daemon runs, never equal to it: the compare
    that settles a set with no answer, and the one that settles a pending change, are 'the daemon carries everything the candidate said', with the BEFORE state asked first."""

    def _new_subnet(self, cfg):
        out = copy.deepcopy(cfg)
        out["Dhcp4"]["subnet4"].append({"id": 9, "subnet": "10.9.0.0/24", "pools": [{"pool": "10.9.0.10 - 10.9.0.20"}]})
        return out

    def test_a_set_that_applied_with_no_answer_is_recognized_though_the_daemon_expanded_it(self, fake, server):
        fake.expand = _expands
        fake.hang = {"config-set": "after"}
        cfg, digest = _plan(server)
        result = api.apply(server, "dhcp4", self._new_subnet(cfg), digest, "x", before_cfg=cfg)
        assert result["ok"], result
        assert any(s.get("id") == 9 for s in fake.file["subnet4"])

    def test_a_pending_change_that_is_live_is_finished_though_the_daemon_expanded_it(self, fake, server, store):
        fake.expand = _expands
        cfg, digest = _plan(server)
        candidate = self._new_subnet(cfg)
        store.record(SID, "dhcp4", candidate, digest, "interrupted", hash_kind="kea", source="pending")
        fake.set_running(_expands(candidate["Dhcp4"]))  # Jen died after config-set, before config-write
        notes = []
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert notes and "is live" in notes[0], notes
        lines = api.settle_pending(server, "dhcp4")
        assert lines and "finished" in lines[0], lines
        assert any(s.get("id") == 9 for s in fake.file["subnet4"]) and store.pending(SID, "dhcp4") is None

    def test_a_pure_deletion_that_never_landed_is_not_mistaken_for_one_that_did(self, fake, server, store):
        """The candidate lacks a subnet; the daemon still has it, so the daemon 'carries' the candidate. The BEFORE digest is asked first: nothing landed."""
        cfg, digest = _plan(server)
        candidate = copy.deepcopy(cfg)
        candidate["Dhcp4"]["subnet4"] = candidate["Dhcp4"]["subnet4"][:1]
        store.record(SID, "dhcp4", candidate, digest, "interrupted", hash_kind="kea", source="pending")
        notes = []
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert notes and "never reached" in notes[0], notes
        api.settle_pending(server, "dhcp4")
        assert store.pending(SID, "dhcp4") is None
        assert len(fake.running["subnet4"]) == 2  # nothing was set, nothing was written

    def test_carries_knows_the_keys_kea_renames_by_name(self):
        """Q216 BF4. A hand-written file's singular `hosts-database` / `control-socket` come back from `config-get` as one-element lists; the table is the module's, the compat row its source."""
        assert api._carries(
            {"hosts-databases": [{"type": "mysql", "name": "x", "port": 3306}]},
            {"hosts-database": {"type": "mysql", "name": "x"}},
        )
        assert api._carries(
            {"control-sockets": [{"socket-type": "unix", "socket-name": "/s"}]},
            {"control-socket": {"socket-type": "unix"}},
        )
        assert not api._carries(
            {"hosts-databases": [{"type": "mysql"}, {"type": "pgsql"}]}, {"hosts-database": {"type": "mysql"}}
        )  # a list of two is not the one the file named
        assert not api._carries({"hosts-databases": [{"type": "pgsql"}]}, {"hosts-database": {"type": "mysql"}})
        assert not api._carries({}, {"hosts-database": {"type": "mysql"}})
        assert api.RENAMED_KEYS == {"hosts-database": "hosts-databases", "control-socket": "control-sockets"}

    def test_a_default_valued_key_config_get_omits_is_carried_and_nothing_else_is(self):
        """Q216, found by compat row 11 on Kea 3.0.5, 3.2.1 and 3.3.3: `service-sockets-require-all: false` and `service-sockets-max-retries: 0` come back from `config-get` as nothing."""
        running = {"interfaces-config": {"interfaces": ["*"], "re-detect": True}}
        assert api._carries(
            running,
            {
                "interfaces-config": {
                    "interfaces": ["*"],
                    "service-sockets-require-all": False,
                    "service-sockets-max-retries": 0,
                }
            },
        )
        assert not api._carries(
            running, {"interfaces-config": {"service-sockets-require-all": True}}
        )  # not the default: a difference
        assert not api._carries(running, {"interfaces-config": {"service-sockets-max-retries": 3}})
        assert not api._carries(
            running, {"interfaces-config": {"service-sockets-max-retries": False}}
        )  # False is not 0 here
        assert not api._carries(
            {"x": {}}, {"x": {"service-sockets-require-all": False}}
        )  # only under interfaces-config

    def test_only_a_pool_is_compared_without_its_spaces(self):
        """Q216 BF5. Fixup 2 stripped the spaces of EVERY string on both sides; Kea re-renders a pool "a - b" as "a-b" and nothing else row 09 saw."""
        assert api._carries(
            {"pools": [{"pool": "10.0.0.10-10.0.0.20"}]}, {"pools": [{"pool": "10.0.0.10 - 10.0.0.20"}]}
        )
        assert not api._carries({"user-context": {"note": "a-b"}}, {"user-context": {"note": "a - b"}})
        assert not api._carries({"comment": "ab"}, {"comment": "a b"})
        assert set(api.SPACE_INSENSITIVE_KEYS) == {"pool"}

    def test_carries_is_a_subset_test(self):
        assert api._carries({"a": 1, "b": 2}, {"a": 1})
        assert not api._carries({"a": 1}, {"a": 1, "b": 2})
        assert not api._carries({"a": 2}, {"a": 1})
        assert api._carries([{"x": 1, "y": 2}], [{"x": 1}])
        assert not api._carries([{"x": 1}, {"x": 2}], [{"x": 1}])  # lists are positional and the same length
        assert api._carries(5, 5) and not api._carries(5, 6) and not api._carries([], {"a": 1})
