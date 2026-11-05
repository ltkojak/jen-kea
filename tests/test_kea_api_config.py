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

    def _file_then(self, monkeypatch, fake, later):
        """The host's file: what it holds before the daemon is asked to write it (the state before the change, which step (6) asks about), then `later()` - the helper's answer once the write was tried."""
        reads = {"n": 0}

        def read(*a, **k):
            reads["n"] += 1
            if reads["n"] == 1:
                return {"Dhcp4": copy.deepcopy(fake.file)}, "r" * 64
            return {"Dhcp4": later()}, "r" * 64

        monkeypatch.setattr(host, "read_config_versioned", read)

    def test_with_ssh_the_files_own_answer_decides(self, fake, server, monkeypatch):
        fake.hang = {"config-write": "before"}
        server["ssh_host"] = "10.0.0.9"
        # the helper reads a file that carries what runs: proved
        self._file_then(monkeypatch, fake, lambda: copy.deepcopy(fake.running))
        result, _c, _d = _apply(server)
        assert result["ok"] and result["code"] == "ok"

    def test_with_ssh_a_file_that_differs_is_unverified(self, fake, server, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        self._file_then(monkeypatch, fake, lambda: {"stale": True})
        result, _c, _d = _apply(server)
        assert result["code"] == "unverified" and "does not carry what the daemon runs" in result["detail"]

    def test_with_ssh_a_file_that_agrees_records_a_raw_row_beside_the_kea_row(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        world.host_reads_the_fakes_file(monkeypatch, fake)
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

    def _file_reads(self, monkeypatch, fake, later):
        """The first read of the file (step 6's question, before the write) is the file as it is; the next is `later(fake)` (step 8's verify, after the daemon proved the write)."""
        reads = {"n": 0}

        def read(*a, **k):
            reads["n"] += 1
            return ({"Dhcp4": copy.deepcopy(fake.file)}, "r" * 64) if reads["n"] == 1 else later(fake)

        monkeypatch.setattr(host, "read_config_versioned", read)

    def test_a_file_that_cannot_be_read_back_is_ok_with_a_note(self, fake, server, store, monkeypatch):
        """Q218 BH6 a (AC8; Q217 AB8's fix, pinned): the daemon's own digest proved the write, so a file that cannot be READ BACK afterward is not a difference - `ok` with a note, no hands, and no raw
        row; a file that reads but differs is `unverified` with hands; the canonical sentinel (a helper with no raw hash) is `ok` and records no `raw` row."""
        server["ssh_host"] = "10.0.0.9"
        self._file_reads(monkeypatch, fake, lambda f: (None, None))
        result, _c, _d = _apply(server)
        assert result["ok"] and result["code"] == "ok" and "could not be read back" in result["note"]
        assert not result.get("needs_hands") and not any(r["hash_kind"] == "raw" for r in store.rows)

        self._file_reads(monkeypatch, fake, lambda f: ({"Dhcp4": {"stale": True}}, "r" * 64))
        result, _c, _d = _apply(server)
        assert result["code"] == "unverified" and result["needs_hands"]
        assert "does not carry what the daemon runs" in result["detail"]

        store.rows.clear()
        sentinel = host._CANONICAL_SENTINEL_PREFIX + "0" * 64
        self._file_reads(monkeypatch, fake, lambda f: ({"Dhcp4": copy.deepcopy(f.running)}, sentinel))
        result, _c, _d = _apply(server)
        assert result["ok"] and not any(r["hash_kind"] == "raw" for r in store.rows)


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
        lines, _settled = api.settle_pending(
            server, "dhcp4"
        )  # the settlement: under the lock, from the card or the Plan
        assert fake.file == fake.running  # config-write was sent
        assert lines and "finished" in lines[0] and store.pending(SID, "dhcp4") is None
        assert [r["source"] for r in store.rows] == ["jen"]

    def test_a_change_that_never_landed_is_classified_by_a_read_and_deleted_by_the_settle(self, fake, server, store):
        self._pending(fake, server, store)
        notes = []
        fake.commands.clear()
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert fake.commands == ["config-get"] and notes and "never reached" in notes[0] and store.rows != []
        lines, _settled = api.settle_pending(server, "dhcp4")
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

    def test_every_write_file_caller_passes_before(self):
        """Q218 BH1 a (CFG-005): `write_file(server, service, *, before, ...)` has no default for `before`, and the whole tree is walked: every caller names it, so a new caller cannot forget the question."""
        callers = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name == "write_file":
                    callers.append((path.relative_to(ROOT).as_posix(), node.lineno, {k.arg for k in node.keywords}))
        assert callers, "the walk found no caller at all"
        assert all("before" in kws for _p, _l, kws in callers), callers
        assert sorted({p for p, _l, _k in callers}) == [
            "jen/services/kea_api_config.py",
            "jen/services/kea_transport_switch.py",
        ], callers
        assert len(callers) == 3, callers  # the settlement's live branch, `_to_api` (both its entries) and `_to_file`

    def test_config_write_has_one_sender_and_it_is_asked_first(self):
        """Q218 BH1 b: the only `_cmd(..., "config-write")` in the tree is `_send_write`; it is called by `write_file` and by `_write_with_retries` only, `_write_with_retries` by `apply` only, and each
        of those asks the file (`_ask_the_file`) on a line BEFORE the call."""
        tree = ast.parse((ROOT / "jen/services/kea_api_config.py").read_text(encoding="utf-8"))
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

        def calls(fn, target):
            return [
                n.lineno
                for n in ast.walk(fn)
                if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == target
            ]

        senders = [
            name
            for name, fn in funcs.items()
            if any(
                isinstance(n, ast.Call)
                and getattr(n.func, "id", "") == "_cmd"
                and any(isinstance(a, ast.Constant) and a.value == "config-write" for a in n.args)
                for n in ast.walk(fn)
            )
        ]
        assert senders == ["_send_write"], senders
        assert {n for n, fn in funcs.items() if calls(fn, "_send_write")} == {"write_file", "_write_with_retries"}
        assert {n for n, fn in funcs.items() if calls(fn, "_write_with_retries")} == {"apply"}
        for name, sent in (("write_file", "_send_write"), ("apply", "_write_with_retries")):
            asked, went = calls(funcs[name], "_ask_the_file"), calls(funcs[name], sent)
            assert asked and went and min(asked) < min(went), (name, asked, went)

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
            "re",  # the pool-path rule blanks list indexes
            "pathlib",  # the defaults vectors live beside the code (Q217 AB6)
            "jen.services.secret_keys.is_secret_key",  # the ONE definition of a secret key name: the compare prints a path, never a value under one (LEAK-001)
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

    def test_a_non_scalar_prints_its_shape_never_its_content(self):
        """Q218 BH5 b (AC15): a difference of KIND is named at the PARENT, where `_secret_path` cannot see a secret one level below: a container prints its shape and the scalar on the other side only its
        type, so nothing under a secret key (or where one would sit) is ever printed."""
        secret = {"password": "hunter2-secret", "user": "kea"}
        for live_value, file_value in (
            (secret, "plain"),
            ("plain", secret),
            ([secret], "plain"),
            ({"nested": {"password": "hunter2-secret"}}, 7),
            (secret, ["x"]),
        ):
            text = api.difference_text(
                {"Dhcp4": {"lease-database": file_value}}, {"Dhcp4": {"lease-database": live_value}}, "dhcp4"
            )
            assert text.startswith("at Dhcp4.lease-database:"), text
            assert "hunter2" not in text and "plain" not in text and "kea" not in text, text
        assert (
            api.difference_text({"Dhcp4": {"lease-database": secret}}, {"Dhcp4": {"lease-database": "plain"}}, "dhcp4")
            == "at Dhcp4.lease-database: the file says an object with 2 keys, the daemon a string"
        )
        # two scalars still print, and a path that names a secret never does
        assert "the file says 3600, the daemon 7200" in api.difference_text(
            {"Dhcp4": {"valid-lifetime": 3600}}, {"Dhcp4": {"valid-lifetime": 7200}}, "dhcp4"
        )

    def test_a_renamed_key_against_another_count_names_the_count(self):
        """Q218 BH5 c (AC16): one singular `hosts-database` in the file against two backends on the daemon was reported as "the daemon nothing" - the renamed-key branch only descended when the list had
        exactly one element. The verdict (a difference) was right; the sentence names the count now."""
        one = {"Dhcp4": {"hosts-database": {"type": "mysql", "name": "kea"}}}
        two = {"Dhcp4": {"hosts-databases": [{"type": "mysql", "name": "kea"}, {"type": "mysql", "name": "other"}]}}
        assert api.file_in_daemon(one, two, "dhcp4") is False
        assert (
            api.difference_text(one, two, "dhcp4")
            == "at Dhcp4.hosts-database: the file says one hosts-database, the daemon runs 2 hosts-databases"
        )
        none = {"Dhcp4": {"hosts-databases": []}}
        assert "the daemon runs 0 hosts-databases" in api.difference_text(one, none, "dhcp4")
        # the control: exactly one is still descended into, and carried
        same = {"Dhcp4": {"hosts-databases": [{"type": "mysql", "name": "kea", "port": 3306}]}}
        assert api.file_in_daemon(one, same, "dhcp4") is True


class TestADamagedPendingRecord:
    """Q217 AB10-AB12: ONE parser for a pending row's body, and a damaged row is a fourth state - never `AttributeError`, never "that change is live" from an empty section, never "there is no pending
    change" while one blocks. The 3 x 3 matrix Opus ran: bodies x (read, pending_block, settle_pending)."""

    BODIES = [
        "7",
        '"a config"',
        "[1, 2]",
        '{"Dhcp4": {}}',
        "{}",
        "null",
        "{not json",
        '{"Dhcp4": [1]}',  # (Q218 BH2 f, AC24) a truthy service section that is no object: damaged, never "unresolved" for ever
        '{"Dhcp4": "x"}',
        '{"Dhcp4": 7}',
        '{"Dhcp4": true}',
    ]

    def _damaged(self, fake, server, store, body, sha="before-digest"):
        row_id = store.record(
            SID, "dhcp4", {"Dhcp4": {"valid-lifetime": 1}}, sha, "x", hash_kind="kea", source="pending"
        )
        next(r for r in store.rows if r["id"] == row_id)["config"] = body
        return row_id

    @pytest.mark.parametrize("body", BODIES)
    def test_a_read_says_damaged_and_sends_one_command(self, fake, server, store, body):
        self._damaged(fake, server, store, body)
        notes = []
        fake.commands.clear()
        api.read(server, "dhcp4", capture=False, notes=notes)
        assert fake.commands == ["config-get"] and notes and "is damaged" in notes[0]

    @pytest.mark.parametrize("body", BODIES)
    def test_the_gate_refuses_with_the_same_sentence_and_sends_nothing(self, fake, server, store, body):
        self._damaged(fake, server, store, body)
        fake.commands.clear()
        blocked = api.pending_block(server, "dhcp4")
        cfg, digest = _plan(server)
        fake.commands.clear()
        applied = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert "is damaged" in blocked and applied["code"] == "unverified" and "is damaged" in applied["detail"]
        assert not any(c in fake.commands for c in ("config-set", "config-write"))

    @pytest.mark.parametrize("body", BODIES)
    def test_settle_marks_it_damaged_and_never_calls_it_live(self, fake, server, store, body):
        row_id = self._damaged(fake, server, store, body)
        fake.commands.clear()
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled and "damaged and the daemon runs" in lines[0]
        assert "config-write" not in fake.commands and "config-set" not in fake.commands
        assert next(r for r in store.rows if r["id"] == row_id)["source"] == "damaged"
        assert store.pending(SID, "dhcp4") is None  # it no longer blocks; Config history carries it

    def test_a_damaged_row_whose_before_digest_is_the_daemons_never_reached_it(self, fake, server, store):
        _cfg_now, digest = _plan(server)
        self._damaged(fake, server, store, "{not json", sha=digest)
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled and "never reached the daemon" in lines[0] and store.rows == []

    def test_a_store_that_cannot_change_the_row_is_not_settled(self, fake, server, store, monkeypatch):
        """Q217, second pass row 4: `settled` is what the store did, not what the code meant to do."""
        row_id = self._damaged(fake, server, store, "{not json")
        monkeypatch.setattr(api._rev, "mark_damaged", lambda rev_id: False)
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled is False and "could not be marked" in lines[0]
        assert next(r for r in store.rows if r["id"] == row_id)["source"] == "pending"
        _cfg_now, digest = _plan(server)
        row_id = self._damaged(fake, server, store, "{not json", sha=digest)
        monkeypatch.setattr(api._rev, "discard", lambda rev_id: False)
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled is False and "could not be removed" in lines[0]

    def test_the_one_parser_is_the_only_one(self):
        source = (ROOT / "jen" / "services" / "kea_api_config.py").read_text(encoding="utf-8")
        assert source.count('json.loads(row["config"])') == 1, "a second parser of a pending row's body"


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
        assert (
            result["code"] == "unreadable" and "cannot be read" in result["detail"] and not result.get("needs_hands")
        )  # (Q217 AB9) nobody's hands
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
        shipped, _name = api.load_vector("3.0.5")
        # the file omits Kea's written-out defaults, as a file Jen authored does (Q217: the reverse compare is real now, so "the defaults" are the shipped vector's)
        file_cfg = {"Dhcp4": {k: v for k, v in fake.running.items() if k not in shipped}}
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
        lines, _settled = api.settle_pending(server, "dhcp4")
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
        """Q216 BF5, as a PATH (Q217 AB15): Kea re-renders a pool "a - b" as "a-b" and nothing else row 09 saw; a `user-context.pool` and a top-level `pool` compare exactly."""
        pool_a = {"subnet4": [{"pools": [{"pool": "10.0.0.10-10.0.0.20"}]}]}
        pool_b = {"subnet4": [{"pools": [{"pool": "10.0.0.10 - 10.0.0.20"}]}]}
        assert api._carries(pool_a, pool_b)
        shared_a = {"shared-networks": [{"subnet4": pool_a["subnet4"]}]}
        shared_b = {"shared-networks": [{"subnet4": pool_b["subnet4"]}]}
        assert api._carries(shared_a, shared_b)  # a shared network's subnets are the same shape one level down
        assert not api._carries(
            {"user-context": {"pool": "a-b"}}, {"user-context": {"pool": "a - b"}}
        )  # (AB15) the key name alone is not the rule
        assert not api._carries({"pool": "ab"}, {"pool": "a b"})
        assert not api._carries(
            {"subnet4": [{"user-context": {"note": "a-b"}}]}, {"subnet4": [{"user-context": {"note": "a - b"}}]}
        )
        assert set(api.SPACE_INSENSITIVE_PATHS) == {
            "subnet4[].pools[].pool",
            "subnet6[].pools[].pool",
            "subnet6[].pd-pools[].prefix",
        }

    def test_a_bool_is_not_an_int(self):
        """Q217 AB3: Python says True == 1; Kea does not."""
        assert not api._carries({"a": True}, {"a": 1}) and not api._carries({"a": 1}, {"a": True})
        assert not api._carries({"a": False}, {"a": 0})
        assert api._carries({"a": True}, {"a": True}) and api._carries({"a": 1}, {"a": 1})

    def test_carries_is_a_subset_test(self):
        assert api._carries({"a": 1, "b": 2}, {"a": 1})
        assert not api._carries({"a": 1}, {"a": 1, "b": 2})
        assert not api._carries({"a": 2}, {"a": 1})
        assert api._carries([{"x": 1, "y": 2}], [{"x": 1}])
        assert not api._carries([{"x": 1}, {"x": 2}], [{"x": 1}])  # lists are positional and the same length
        assert api._carries(5, 5) and not api._carries(5, 6) and not api._carries([], {"a": 1})


class TestADeletionIsADifference:
    """Q217 AB6 - `file_in_daemon` asks both directions. Everything the file says is carried by the daemon (the old question) AND every key the daemon runs that is not one of Kea's own written-out
    defaults is in the file: a key DELETED from the file reads as a difference, not as agreement, so the next `config-write` cannot destroy it unasked. The defaults are the daemon's own answer,
    recorded per minor version (compat row 12); here a small set stands in."""

    DEFAULTS = frozenset({"valid-lifetime", "echo-client-id", "subnet4[].t1-percent", "subnet4[].reservations"})

    def _live(self):
        return {
            "Dhcp4": {
                "valid-lifetime": 3600,
                "echo-client-id": True,
                "hooks-libraries": [{"library": "/usr/lib/kea/libdhcp_lease_cmds.so"}],
                "hosts-databases": [{"type": "mysql", "password": "hunter2"}],
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "10.0.0.0/24",
                        "t1-percent": 0.5,
                        "reservations": [],
                        "option-data": [{"name": "routers", "data": "10.0.0.1"}],
                    }
                ],
            }
        }

    def _file(self):
        """What Jen authored: the daemon's configuration with Kea's written-out defaults left out."""
        live = copy.deepcopy(self._live())
        for k in ("valid-lifetime", "echo-client-id"):
            del live["Dhcp4"][k]
        for k in ("t1-percent", "reservations"):
            del live["Dhcp4"]["subnet4"][0][k]
        live["Dhcp4"]["hosts-database"] = {"type": "mysql", "password": "hunter2"}
        del live["Dhcp4"]["hosts-databases"]
        return live

    def test_a_file_that_omits_only_defaults_is_the_daemons(self):
        assert api.file_in_daemon(self._file(), self._live(), "dhcp4", defaults=self.DEFAULTS)
        assert api.difference_text(self._file(), self._live(), "dhcp4", defaults=self.DEFAULTS) == ""

    def test_a_deleted_hooks_library_is_a_difference(self):
        file_cfg = self._file()
        del file_cfg["Dhcp4"]["hooks-libraries"]
        assert api.file_in_daemon(file_cfg, self._live(), "dhcp4", defaults=self.DEFAULTS) is False
        text = api.difference_text(file_cfg, self._live(), "dhcp4", defaults=self.DEFAULTS)
        assert text == "at Dhcp4.hooks-libraries: the file says nothing, the daemon a list of 1", text

    def test_a_deleted_option_of_a_subnet_is_named_by_its_path(self):
        file_cfg = self._file()
        del file_cfg["Dhcp4"]["subnet4"][0]["option-data"]
        text = api.difference_text(file_cfg, self._live(), "dhcp4", defaults=self.DEFAULTS)
        assert text.startswith("at Dhcp4.subnet4[0].option-data:"), text

    def test_a_subnet_removed_a_changed_value_and_an_added_key_are_differences_too(self):
        removed = self._file()
        removed["Dhcp4"]["subnet4"] = []
        changed = self._file()
        changed["Dhcp4"]["subnet4"][0]["subnet"] = "10.9.0.0/24"
        added = self._file()
        added["Dhcp4"]["decline-probation-period"] = 5
        for file_cfg in (removed, changed, added):
            assert api.file_in_daemon(file_cfg, self._live(), "dhcp4", defaults=self.DEFAULTS) is False

    def test_a_default_key_the_file_omits_is_not_a_difference_without_a_vector_the_old_question_only(self):
        file_cfg = self._file()
        del file_cfg["Dhcp4"]["hooks-libraries"]
        assert (
            api.file_in_daemon(file_cfg, self._live(), "dhcp4") is True
        )  # no vector: only the first direction can be asked

    def test_a_deleted_secret_never_prints_its_value(self):
        file_cfg = self._file()
        del file_cfg["Dhcp4"]["hosts-database"]["password"]
        text = api.difference_text(file_cfg, self._live(), "dhcp4", defaults=self.DEFAULTS)
        assert "hunter2" not in text and "Dhcp4.hosts-database" in text and "not shown" in text, text

    def test_the_renamed_key_is_matched_by_its_alias_not_reported_as_extra(self):
        assert api.file_in_daemon(self._file(), self._live(), "dhcp4", defaults=self.DEFAULTS)

    def test_the_loader_takes_the_exact_minor_then_the_nearest_lower_and_never_a_higher(self, tmp_path):
        for minor in (0, 2):
            (tmp_path / f"kea_defaults_3.{minor}.json").write_text(json.dumps({"paths": [f"k{minor}"]}))
        assert api.load_vector("3.0.5", tmp_path) == (frozenset({"k0"}), "3.0")
        assert api.load_vector("3.1.4", tmp_path) == (frozenset({"k0"}), "3.0")
        assert api.load_vector("3.2.1", tmp_path) == (frozenset({"k2"}), "3.2")
        assert api.load_vector("3.3.3", tmp_path) == (frozenset({"k2"}), "3.2")
        assert api.load_vector("2.6.1", tmp_path) == (None, "")
        assert api.load_vector("4.0.0", tmp_path) == (None, "")
        assert api.load_vector("", tmp_path) == (None, "")

    def test_a_vector_that_cannot_be_read_asks_nothing(self, tmp_path):
        (tmp_path / "kea_defaults_3.0.json").write_text("{not json")
        assert api.load_vector("3.0.1", tmp_path) == (None, "")

    @pytest.mark.parametrize(
        "body",
        [
            '{"paths": "abc"}',  # a string iterates as characters: a tiny wrong set
            '{"paths": {"a": 1}}',  # an object iterates as its keys
            '{"paths": [1, 2]}',  # numbers are not key paths
            '{"paths": ["a"], "populated": ["a"]}',
            '{"paths": ["a"], "populated": {"a": "not a list"}}',
            "[1, 2]",
            "7",
            "null",
        ],
    )
    def test_a_vector_of_the_wrong_shape_asks_nothing(self, tmp_path, body):
        """Q218 BH5 d (AC23): a vector whose `paths` is a string or an object loaded as a tiny wrong set; its shape is checked, and one that is not `paths: [str]` and `populated: {str: [..]}` asks nothing."""
        (tmp_path / "kea_defaults_3.0.json").write_text(body)
        assert api.load_vector("3.0.1", tmp_path) == (None, "")
        (tmp_path / "kea_defaults_3.0.json").write_text('{"paths": ["a", "b.c"], "populated": {"b.c": ["x"]}}')
        paths, name = api.load_vector("3.0.1", tmp_path)
        assert paths == frozenset({"a", "b.c"}) and name == "3.0" and paths.populated == {"b.c": ["x"]}

    def test_compare_uses_the_daemons_vector_and_names_the_place(self, fake, server, monkeypatch):
        monkeypatch.setattr(api, "defaults_for", lambda s, svc="dhcp4": (self.DEFAULTS, {"version": "3.0.1"}))
        file_cfg = self._file()
        del file_cfg["Dhcp4"]["hooks-libraries"]
        agrees, where = api.compare(server, "dhcp4", file_cfg, self._live())
        assert agrees is False and where.startswith("at Dhcp4.hooks-libraries:")
        assert api.compare(server, "dhcp4", self._file(), self._live()) == (True, "")

    def test_the_shipped_vectors_are_keys_only(self):
        """The recorded files carry key paths and nothing else (no values), sorted, indexes blanked."""
        for path in sorted(api.KEA_DEFAULTS_DIR.glob("kea_defaults_*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            assert set(data) <= {"kea", "paths", "populated"} and data["paths"] == sorted(set(data["paths"])), path.name
            assert set(data.get("populated", {})) <= set(data["paths"]), path.name
            assert all(
                isinstance(v, list) and all(isinstance(i, str) for i in v) for v in data.get("populated", {}).values()
            ), path.name  # lists of names, never values of a setting
            assert all(isinstance(p, str) and "[0]" not in p for p in data["paths"]), path.name


class TestADefaultIsJudgedByItsValueToo:
    """Q217, second pass row 1: a path in the vector is a default only when the VALUE the daemon runs is one - an empty list, an object of defaults, or the list Kea defaults to - so a populated
    `option-data`, `reservations`, `relay` or `shared-networks` deleted from the file is a difference even though the vector holds the path."""

    def _defaults(self):
        paths = api.DefaultsSet(
            {
                "subnet4[].option-data",
                "subnet4[].reservations",
                "subnet4[].relay",
                "subnet4[].relay.ip-addresses",
                "shared-networks",
                "host-reservation-identifiers",
                "valid-lifetime",
            }
        )
        paths.populated = {"host-reservation-identifiers": ["hw-address", "duid"]}
        return paths

    def _live(self):
        return {
            "Dhcp4": {
                "valid-lifetime": 3600,
                "host-reservation-identifiers": ["hw-address", "duid"],
                "shared-networks": [{"name": "guest"}],
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "10.0.0.0/24",
                        "option-data": [{"name": "routers", "data": "10.0.0.1"}],
                        "reservations": [{"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.0.0.5"}],
                        "relay": {"ip-addresses": ["10.0.0.1"]},
                    }
                ],
            }
        }

    def test_a_populated_key_deleted_wholesale_is_a_difference_though_the_vector_holds_its_path(self):
        live = self._live()
        for key in ("option-data", "reservations", "relay"):
            file_cfg = copy.deepcopy(live)
            file_cfg["Dhcp4"]["subnet4"][0].pop(key)
            file_cfg["Dhcp4"].pop("valid-lifetime")
            file_cfg["Dhcp4"].pop("host-reservation-identifiers")
            assert api.file_in_daemon(file_cfg, live, "dhcp4", defaults=self._defaults()) is False, key
        gone = copy.deepcopy(live)
        gone["Dhcp4"].pop("shared-networks")
        assert api.file_in_daemon(gone, live, "dhcp4", defaults=self._defaults()) is False

    def test_the_same_keys_empty_are_defaults(self):
        live = self._live()
        live["Dhcp4"]["subnet4"][0].update({"option-data": [], "reservations": [], "relay": {}})
        live["Dhcp4"]["shared-networks"] = []
        bare = {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        assert api.file_in_daemon(bare, live, "dhcp4", defaults=self._defaults()) is True

    def test_a_list_kea_defaults_to_is_a_default_only_while_it_is_that_list(self):
        live = {"Dhcp4": {"host-reservation-identifiers": ["hw-address", "duid"], "subnet4": []}}
        assert api.file_in_daemon({"Dhcp4": {"subnet4": []}}, live, "dhcp4", defaults=self._defaults()) is True
        live["Dhcp4"]["host-reservation-identifiers"] = ["flex-id"]
        assert api.file_in_daemon({"Dhcp4": {"subnet4": []}}, live, "dhcp4", defaults=self._defaults()) is False

    def test_a_scalar_default_is_judged_by_its_path_alone_the_named_limit(self):
        live = {"Dhcp4": {"valid-lifetime": 123, "subnet4": []}}
        assert api.file_in_daemon({"Dhcp4": {"subnet4": []}}, live, "dhcp4", defaults=self._defaults()) is True

    def test_the_shipped_vector_catches_the_five_deletions(self):
        shipped, name = api.load_vector("3.0.5")
        assert shipped is not None and name == "3.0"
        subnet = {
            "id": 1,
            "subnet": "10.0.0.0/24",
            "option-data": [{"name": "routers", "data": "10.0.0.1"}],
            "reservations": [{"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.0.0.5"}],
            "relay": {"ip-addresses": ["10.0.0.1"]},
        }
        live = {
            "Dhcp4": {
                "option-data": [{"name": "domain-name-servers", "data": "10.0.0.53"}],
                "shared-networks": [{"name": "guest", "subnet4": []}],
                "subnet4": [subnet],
            }
        }
        paths = (
            ("option-data",),
            ("shared-networks",),
            ("subnet4", 0, "option-data"),
            ("subnet4", 0, "reservations"),
            ("subnet4", 0, "relay"),
        )
        for path in paths:
            file_cfg = copy.deepcopy(live)
            node = file_cfg["Dhcp4"]
            for step in path[:-1]:
                node = node[step]
            node.pop(path[-1])
            assert api.file_in_daemon(file_cfg, live, "dhcp4", defaults=shipped) is False, path


EDIT_KEY = "user-context"
EDIT = {"jen-note": "the operator's own edit, never loaded by the daemon"}


class TestWriteFileAsksTheFile:
    """Q218 BH1 a (CFG-005): `write_file` READS the file first (capturing: an edit is in Config history before it can be lost) and sends `config-write` only when the file carries what Jen knows."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        self.seen = world.host_reads_the_fakes_file(monkeypatch, fake, store)
        host.read_config_versioned(
            server, "dhcp4"
        )  # an earlier read of the clean file: the baseline the store already has when an edit appears
        self.seen["reads"].clear()
        return server

    def test_a_file_that_is_the_state_before_is_written_over(self, fake, ssh):
        cfg, _digest = _plan(ssh)
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4", before=cfg)
        assert out["ok"] and "config-write" in fake.commands
        assert self.seen["reads"] == [True], "the sender's read is the capturing one"

    def test_an_edit_the_daemon_never_loaded_is_refused_by_name_and_nothing_is_sent(self, fake, ssh, store):
        cfg, _digest = _plan(ssh)
        fake.file[EDIT_KEY] = copy.deepcopy(EDIT)
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4", before=cfg)
        assert not out["ok"] and out["code"] == "unloaded-edit"
        assert "Dhcp4.user-context" in out["detail"] and "carries an edit the daemon has not loaded" in out["detail"]
        assert "config-write" not in fake.commands and EDIT_KEY in fake.file
        external = [r for r in store.rows if r["source"] == "external"]
        assert external and EDIT_KEY in json.loads(external[-1]["config"])["Dhcp4"], "the edit is in Config history"

    def test_discard_writes_over_it_and_the_edit_was_in_config_history_before_the_write(self, fake, ssh, store):
        cfg, _digest = _plan(ssh)
        fake.file[EDIT_KEY] = copy.deepcopy(EDIT)
        at_the_write = {}

        def look(f):
            at_the_write["rows"] = [(r["source"], r["hash_kind"]) for r in store.rows]

        fake.hooks["config-write"] = look
        out = api.write_file(ssh, "dhcp4", before=cfg, discard=True)
        assert out["ok"] and EDIT_KEY not in fake.file
        assert ("external", "raw") in at_the_write["rows"], (
            "the discarded edit was recorded BEFORE config-write went out"
        )

    def test_a_file_that_is_what_the_daemon_runs_loses_nothing_to_its_own_rendering(self, fake, ssh):
        cfg, _digest = _plan(ssh)
        stale_before = copy.deepcopy(cfg)
        stale_before["Dhcp4"]["valid-lifetime"] = 1  # a `before` the file does not carry ...
        out = api.write_file(ssh, "dhcp4", before=stale_before, running=cfg)  # ... but the file IS what runs
        assert out["ok"]

    def test_no_ssh_host_means_no_file_to_ask(self, fake, server, monkeypatch):
        reads = []
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: reads.append(a) or (None, None))
        fake.commands.clear()
        out = api.write_file(server, "dhcp4", before=None)
        assert out["ok"] and reads == [] and "config-write" in fake.commands

    def test_before_none_with_an_ssh_host_is_refused_and_nothing_is_sent(self, fake, ssh):
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4", before=None)
        assert not out["ok"] and out["code"] == "unloaded-edit" and "cannot be proved" in out["detail"]
        assert "config-write" not in fake.commands and self.seen["reads"] == []

    def test_a_file_that_cannot_be_read_is_never_overwritten_not_even_with_discard(self, fake, server, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: (None, None))
        cfg, _digest = _plan(server)
        fake.commands.clear()
        out = api.write_file(server, "dhcp4", before=cfg, discard=True)
        assert not out["ok"] and out["code"] == "unloaded-edit" and "could not be read" in out["detail"]
        assert "config-write" not in fake.commands

    def test_a_refused_write_is_still_keas_own_words(self, fake, ssh):
        cfg, _digest = _plan(ssh)
        fake.write_fails = "Permission denied"
        out = api.write_file(ssh, "dhcp4", before=cfg)
        assert out["code"] == "write-failed" and "Permission denied" in out["detail"]


class TestTheLiveBranchWaitsOnTheFile:
    """Q218 BH1 b (AC1, AC2): a settlement of a LIVE pending row asks the file against the state before the change - the newest settled `kea` revision with the row's before digest - or what the daemon
    runs now; an edit, or a file nothing can prove, is never overwritten and the row stays."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        self.seen = world.host_reads_the_fakes_file(monkeypatch, fake, store)
        host.read_config_versioned(
            server, "dhcp4"
        )  # an earlier read of the clean file: the baseline the store already has when an edit appears
        self.seen["reads"].clear()
        return server

    def _live(self, fake, server, store, *, record_before=True):
        cfg, digest = _plan(server)
        if record_before:
            store.record(SID, "dhcp4", cfg, digest, "the state before", hash_kind="kea", source="baseline")
        cand = _candidate(cfg)
        row_id = store.record(SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending")
        fake.set_running(cand["Dhcp4"])  # the daemon took it; the FILE is still the state before
        return cfg, digest, row_id

    def test_the_file_is_the_state_before_so_the_settlement_writes_and_finishes(self, fake, ssh, store):
        self._live(fake, ssh, store)
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled and "finished" in lines[0] and fake.file == fake.running
        assert store.pending(SID, "dhcp4") is None

    def test_an_edit_the_daemon_never_loaded_waits_and_the_row_stays(self, fake, ssh, store):
        self._live(fake, ssh, store)
        fake.file[EDIT_KEY] = copy.deepcopy(EDIT)
        fake.commands.clear()
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "is live and its file write waits" in lines[0] and "Dhcp4.user-context" in lines[0]
        assert "config-write" not in fake.commands and EDIT_KEY in fake.file
        assert store.pending(SID, "dhcp4") is not None
        assert any(r["source"] == "external" for r in store.rows), "the edit is in Config history"

    def test_no_revision_proves_the_before_state_so_the_file_is_not_overwritten(self, fake, ssh, store):
        self._live(fake, ssh, store, record_before=False)
        fake.commands.clear()
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "cannot be proved against the state before the change" in lines[0]
        assert "restart Kea on" in lines[0] and "config-write" not in fake.commands
        assert store.pending(SID, "dhcp4") is not None

    def test_no_revision_but_a_file_that_is_what_the_daemon_runs_loses_nothing(self, fake, ssh, store):
        self._live(fake, ssh, store, record_before=False)
        fake.file = copy.deepcopy(fake.running)  # the host's file already carries the change
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled and "finished" in lines[0]

    def test_a_pending_or_damaged_row_is_not_a_proof_of_the_state_before(self, fake, ssh, store):
        cfg, digest, _row = self._live(fake, ssh, store, record_before=False)
        store.record(SID, "dhcp4", cfg, digest, "damaged", hash_kind="kea", source="damaged")
        assert api._before_state(ssh, "dhcp4", store.pending(SID, "dhcp4")) is None

    def test_a_server_with_no_ssh_host_settles_as_before(self, fake, server, store):
        self._live(fake, server, store, record_before=False)
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled and "finished" in lines[0] and fake.file == fake.running

    def test_a_finish_that_fails_in_the_live_branch_is_not_settled(self, fake, ssh, store, monkeypatch):
        row_id = self._live(fake, ssh, store)[2]
        monkeypatch.setattr(api._rev, "finish", lambda *a, **k: False)
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "could not be finished" in lines[0] and "try again" in lines[0]
        assert next(r for r in store.rows if r["id"] == row_id)["source"] == "pending"
        assert "finished now" not in api.pending_block(
            ssh, "dhcp4"
        )  # the next Plan is not refused with a success sentence

    def test_a_read_says_what_the_settlement_waits_on_and_sends_only_config_get(self, fake, ssh, store):
        self._live(fake, ssh, store)
        fake.file[EDIT_KEY] = copy.deepcopy(EDIT)
        fake.commands.clear()
        notes = []
        api.read(ssh, "dhcp4", capture=False, notes=notes)
        assert "config-write" not in fake.commands and "config-set" not in fake.commands
        assert notes and "is live and its file write waits" in notes[0] and "Dhcp4.user-context" in notes[0]
        assert self.seen["reads"] == [False], "a read is not a write path: no capture"
        assert api.pending_note(ssh, "dhcp4") == notes[0]


class TestTheRecordIsAPreconditionOfTheSendAndOfOk:
    """Q218 BH2 (AC3, AC5, CFG-006): a change nobody can find the record of is never sent, and a change whose record could not be finished is not 'ok' and keeps its row."""

    def test_a_record_that_cannot_be_written_sends_nothing(self, fake, server, store, monkeypatch):
        monkeypatch.setattr(api._rev, "record", lambda *a, **k: None)
        cfg, digest = _plan(server)
        fake.commands.clear()
        out = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert not out["ok"] and out["code"] == "unreadable" and "nothing was sent" in out["detail"]
        assert not out.get("needs_hands")
        assert not any(c in fake.commands for c in ("config-set", "config-write")) and store.rows == []

    def test_a_finish_that_fails_at_step_nine_leaves_the_row_and_the_next_plan_finishes_it(
        self, fake, server, store, monkeypatch
    ):
        server["ssh_host"] = "10.0.0.9"
        world.host_reads_the_fakes_file(monkeypatch, fake, store)
        real, calls = api._rev.finish, {"n": 0}

        def flaky(rev_id, **kw):
            calls["n"] += 1
            return False if calls["n"] == 1 else real(rev_id, **kw)

        monkeypatch.setattr(api._rev, "finish", flaky)
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", cfg, digest, "the state before", hash_kind="kea", source="baseline")
        out = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert out["code"] == "unverified" and out["needs_hands"] and "could not be finished" in out["detail"]
        assert store.pending(SID, "dhcp4") is not None, "the row is the one record of what the daemon runs"
        assert any(r["hash_kind"] == "raw" and r["source"] == "jen" for r in store.rows), (
            "the file's raw row is recorded"
        )
        # the next Plan (the gate) settles it by content: the daemon carries the change and the file IS what runs
        assert api.pending_block(server, "dhcp4") == ""
        assert store.pending(SID, "dhcp4") is None
        assert any(r["source"] == "jen" and r["hash_kind"] == "kea" for r in store.rows)

    def test_a_finish_that_fails_leaves_no_ok_over_a_pending_row(self, fake, server, store, monkeypatch):
        monkeypatch.setattr(api._rev, "finish", lambda *a, **k: False)
        out, _c, _d = _apply(server)
        assert not out["ok"] and out["code"] == "unverified"
        assert store.pending(SID, "dhcp4") is not None


class TestAPendingOrDamagedRowIsNeverTheLastKnownState:
    """Q218 BH2 e (hypothesis D of Q217's second pass)."""

    def test_a_damaged_row_does_not_make_the_daemon_differ_from_a_digest_it_left(self, fake, server, store):
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", cfg, digest, "the state before", hash_kind="kea", source="baseline")
        server["config_transport"] = "api"
        row_id = store.record(SID, "dhcp4", {"Dhcp4": {"x": 1}}, "older-digest", "x", hash_kind="kea", source="pending")
        assert api._rev.mark_damaged(row_id)
        # the daemon runs `digest`: the newest SETTLED kea row is the one with that digest; the damaged row's digest is nobody's state
        assert api.api_daemon_differs(server, "dhcp4") == ""
        assert store.latest_of_kind(SID, "dhcp4", "kea")["sha256"] == digest

    def test_latest_of_kind_skips_pending_and_damaged(self, store):
        store.record(SID, "dhcp4", {"Dhcp4": {}}, "settled", "x", hash_kind="kea", source="jen")
        store.record(SID, "dhcp4", {"Dhcp4": {}}, "p", "x", hash_kind="kea", source="pending")
        store.record(SID, "dhcp4", {"Dhcp4": {}}, "d", "x", hash_kind="kea", source="damaged")
        assert store.latest_of_kind(SID, "dhcp4", "kea")["sha256"] == "settled"
        assert store.by_digest(SID, "dhcp4", "p") is None and store.by_digest(SID, "dhcp4", "d") is None
        assert store.by_digest(SID, "dhcp4", "settled")["source"] == "jen"


class TestApplyAsksTheFileAtStepSix:
    """Q218 BH1 b: `apply`'s own `config-write` (step 6) asks the file as the sender does. The daemon has taken the change when it is asked, so a refusal is `unverified` - nothing is undone, the pending row
    STAYS, and the sentence names the edit."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        world.host_reads_the_fakes_file(monkeypatch, fake, store)
        host.read_config_versioned(server, "dhcp4")  # the baseline of the clean file
        return server

    def test_an_edit_that_appeared_after_the_plan_is_refused_at_step_six_and_the_row_stays(self, fake, ssh, store):
        cfg, digest = _plan(ssh)
        fake.file[EDIT_KEY] = copy.deepcopy(EDIT)  # the operator edits the file between the Plan and the write
        fake.commands.clear()
        out = api.apply(ssh, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert out["code"] == "unverified" and out["needs_hands"] and not out["ok"]
        assert "its file was not written" in out["detail"] and "Dhcp4.user-context" in out["detail"]
        assert "config-set" in fake.commands and "config-write" not in fake.commands
        assert fake.running["valid-lifetime"] == 7200, "nothing is undone: the daemon runs the change"
        assert EDIT_KEY in fake.file, "and the operator's edit is still on the host"
        assert store.pending(SID, "dhcp4") is not None, (
            "the pending row is the state `_reconcile_pending` settles by content"
        )
        assert any(r["source"] == "external" for r in store.rows)

    def test_a_rollback_is_proved_against_the_state_the_daemon_runs_not_its_sparse_candidate(self, fake, ssh, store):
        cfg, digest = _plan(ssh)
        first = api.apply(ssh, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert first["ok"]
        after, after_digest = _plan(ssh)
        sparse = _candidate(
            cfg
        )  # what `Target.after_cfg` holds: the candidate Jen built, not what the daemon reported back
        out = api.revert(ssh, "dhcp4", cfg, after_digest, "rollback: x", before_cfg=sparse)
        assert out["ok"], out
        assert fake.running["valid-lifetime"] == cfg["Dhcp4"]["valid-lifetime"] and fake.file == fake.running


class TestAScalarIsJudgedByItsValueToo:
    """Q218 D1 (the second pass, P1): a scalar the operator DELETES from the file while the daemon runs another value read as "Kea wrote a default" because the vector lists the path, so a `config-write`
    put the deleted line back. A scalar is a default only when it is the value the daemon wrote out for that path (`DefaultsSet.scalars`) or the value of the same-named key in an enclosing scope."""

    def _set(self, scalars=...):
        paths = api.DefaultsSet(
            {
                "t1-percent",
                "valid-lifetime",
                "subnet4[]",
                "subnet4[].valid-lifetime",
                "subnet4[].t1-percent",
                "echo-client-id",
            }
        )
        if scalars is not ...:
            paths.scalars = scalars
        return paths

    LIVE = {
        "Dhcp4": {
            "valid-lifetime": 3600,
            "t1-percent": 0.3,
            "echo-client-id": True,
            "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "valid-lifetime": 3600, "t1-percent": 0.2}],
        }
    }

    def _file(self, **drop):
        cfg = copy.deepcopy(self.LIVE)
        for key in drop.get("top", ()):
            del cfg["Dhcp4"][key]
        for key in drop.get("subnet", ()):
            del cfg["Dhcp4"]["subnet4"][0][key]
        return cfg

    def test_a_deleted_scalar_that_is_not_the_default_is_a_difference(self):
        defaults = self._set(
            {"t1-percent": 0.5, "valid-lifetime": 7200, "echo-client-id": True, "subnet4[].t1-percent": 0.5}
        )
        for file_cfg, where in (
            (self._file(top=["t1-percent"]), "Dhcp4.t1-percent"),
            (self._file(subnet=["t1-percent"]), "Dhcp4.subnet4[0].t1-percent"),
            (self._file(top=["valid-lifetime"]), "Dhcp4.valid-lifetime"),
        ):
            assert api.file_in_daemon(file_cfg, self.LIVE, "dhcp4", defaults=defaults) is False, where
            assert api.difference_text(file_cfg, self.LIVE, "dhcp4", defaults=defaults).startswith(f"at {where}:")

    def test_the_value_kea_writes_out_is_a_default(self):
        live = copy.deepcopy(self.LIVE)
        live["Dhcp4"]["t1-percent"] = 0.5
        live["Dhcp4"]["subnet4"][0]["t1-percent"] = 0.5
        defaults = self._set({"t1-percent": 0.5, "echo-client-id": True, "subnet4[].t1-percent": 0.5})
        file_cfg = copy.deepcopy(live)
        del (
            file_cfg["Dhcp4"]["t1-percent"],
            file_cfg["Dhcp4"]["subnet4"][0]["t1-percent"],
            file_cfg["Dhcp4"]["echo-client-id"],
        )
        assert api.file_in_daemon(file_cfg, live, "dhcp4", defaults=defaults) is True

    def test_a_value_inherited_from_the_scope_above_is_a_default_and_a_different_one_is_not(self):
        defaults = self._set(
            {"echo-client-id": True}
        )  # no recorded value for the subnet's valid-lifetime: it is contextual
        file_cfg = self._file(subnet=["valid-lifetime"])
        assert api.file_in_daemon(file_cfg, self.LIVE, "dhcp4", defaults=defaults) is True  # 3600 is the global 3600
        live = copy.deepcopy(self.LIVE)
        live["Dhcp4"]["subnet4"][0]["valid-lifetime"] = 7200
        file_cfg = copy.deepcopy(live)
        del file_cfg["Dhcp4"]["subnet4"][0]["valid-lifetime"]
        assert (
            api.file_in_daemon(file_cfg, live, "dhcp4", defaults=defaults) is False
        )  # the daemon runs 7200, the global is 3600

    def test_a_boolean_is_not_a_number(self):
        defaults = self._set({"echo-client-id": True, "t1-percent": 1})
        live = {"Dhcp4": {"echo-client-id": 1, "t1-percent": True}}
        assert api.file_in_daemon({"Dhcp4": {}}, live, "dhcp4", defaults=defaults) is False

    def test_a_vector_with_no_recorded_values_keeps_the_path_rule(self):
        defaults = self._set()  # `scalars` is None: recorded before values were
        assert defaults.scalars is None
        assert api.file_in_daemon(self._file(top=["t1-percent"]), self.LIVE, "dhcp4", defaults=defaults) is True

    def test_load_vector_reads_and_validates_scalars(self, tmp_path):
        (tmp_path / "kea_defaults_3.0.json").write_text(
            '{"paths": ["a"], "scalars": {"a": 0.5, "b": "x", "c": true, "d": null}}'
        )
        paths, _name = api.load_vector("3.0.1", tmp_path)
        assert paths.scalars == {"a": 0.5, "b": "x", "c": True, "d": None}
        for bad in (
            '{"paths": ["a"], "scalars": ["a"]}',
            '{"paths": ["a"], "scalars": {"a": [1]}}',
            '{"paths": ["a"], "scalars": {"a": {"b": 1}}}',
        ):
            (tmp_path / "kea_defaults_3.0.json").write_text(bad)
            assert api.load_vector("3.0.1", tmp_path) == (None, "")
        (tmp_path / "kea_defaults_3.0.json").write_text('{"paths": ["a"]}')
        assert api.load_vector("3.0.1", tmp_path)[0].scalars is None

    def test_the_shipped_vectors_may_carry_scalars_and_only_scalars_of_their_paths(self):
        for path in sorted(api.KEA_DEFAULTS_DIR.glob("kea_defaults_*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            assert set(data.get("scalars", {})) <= set(data["paths"]), path.name


class TestAnOwnWriteIsNotChangedOutsideJen:
    """Q218 D8 (the second pass): the settlement's `config-write` wrote the file and recorded a `kea` row and no `raw` row, so the next capturing read recorded Jen's own write as `external`."""

    def test_a_settlement_records_the_file_it_wrote(self, fake, server, store, monkeypatch):
        server["ssh_host"] = "10.0.0.9"
        world.host_reads_the_fakes_file(monkeypatch, fake, store)
        host.read_config_versioned(server, "dhcp4")  # the baseline of the clean file
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", cfg, digest, "the state before", hash_kind="kea", source="baseline")
        cand = _candidate(cfg)
        store.record(SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending")
        fake.set_running(cand["Dhcp4"])
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled, lines
        assert any(r["hash_kind"] == "raw" and r["source"] == "jen" for r in store.rows)
        host.read_config_versioned(server, "dhcp4")  # the next capturing read
        assert not [r for r in store.rows if r["source"] == "external"]
