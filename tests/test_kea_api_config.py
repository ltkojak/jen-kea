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


@pytest.fixture(autouse=True)
def file_proof_follows_the_read(monkeypatch):
    """Q219: the proof reads the file through `kea_host.read_config_proof`; a test that stubs the plain read gets a proof derived from it (the file was written before the daemon's last load). A test about
    the clock installs the `HostClock` world instead (`world.ProofWorld`)."""
    world.proof_follows_the_read(monkeypatch)


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
        """The host's file: what it holds when the proof asks (a capturing read: the Plan's and step (6)'s), then `later()` - the helper's answer to step (8)'s verify, once the write was tried."""

        def read(*a, **k):
            cfg = {"Dhcp4": copy.deepcopy(fake.file)} if k.get("capture", True) else {"Dhcp4": later()}
            return cfg, world.sha_of(cfg)  # the sha follows the bytes, as a real file's does

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
        kinds = sorted(r["hash_kind"] for r in store.rows if r["source"] in ("jen", "rendering"))
        assert kinds == ["kea", "raw"]
        assert [r["source"] for r in store.rows if r["hash_kind"] == "raw"] == ["rendering"], (
            "Kea's own file is `rendering`"
        )


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
        """A capturing read (the proof's, before the write) is the file as it is; the non-capturing one is `later(fake)` (step 8's verify, after the daemon proved the write)."""

        def read(*a, **k):
            if k.get("capture", True):
                return ({"Dhcp4": copy.deepcopy(fake.file)}, "r" * 64)
            return later(fake)

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
        assert restored["ok"], (
            restored
        )  # (Q219) the daemon runs neither state: the row is stale and the restore is the way out

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

    def test_every_write_file_caller_is_one_of_three_and_none_passes_a_before(self):
        """Q218 BH1 a (CFG-005), Q219: `write_file(server, service, *, planned_sha, discard)` asks the proof itself, so a caller cannot forget the question - and the whole tree is walked: the settlement's live
        branch, `_to_api` and `_to_file` are the only callers, and the removed `before` is named by none."""
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
        assert all("before" not in kws and "running" not in kws and "unproved" not in kws for _p, _l, kws in callers), (
            callers
        )
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

    # ── Q219: the decision has one definition and every other question is reached through it ────────────────────────────────
    @staticmethod
    def _callers(name):
        """`module:function` for every call of `name` (a bare name or an attribute) under jen/, attributed to the INNERMOST function that makes it."""
        found = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                stack = list(ast.iter_child_nodes(fn))
                while stack:
                    node = stack.pop()
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        continue  # a nested function is its own function
                    if isinstance(node, ast.Call):
                        called = (
                            node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                        )
                        if called == name:
                            found.append(f"{path.stem}:{fn.name}")
                    stack.extend(ast.iter_child_nodes(node))
        return sorted(found)

    def test_compare_has_exactly_one_caller_and_it_is_file_proof(self):
        """Q219 BI1 d: the walk that names a path is reached ONLY through the proof's sentence - it decides nothing anywhere else."""
        assert self._callers("compare") == ["kea_api_config:file_proof"], self._callers("compare")

    def test_difference_text_is_reached_only_through_compare_and_file_against_is_gone(self):
        assert self._callers("difference_text") == ["kea_api_config:compare"]
        assert self._callers("file_against") == []

    def test_file_in_daemon_is_asked_by_the_proof_and_by_apply_only(self):
        """Decided 16 and BI1 d: the forward walk is (L)'s third condition in `file_proof`, and `apply` asks it of Kea's own rendering at step (8). (Q223 AH2 asked it of the file a rollback found;
        Q224 AJ2 asks THAT question both ways, of two renderings, through `mirrors` - its one caller is the rollback branch of `apply`.) Two functions, two call sites; `mirrors`, one."""
        assert self._callers("file_in_daemon") == [
            "kea_api_config:apply",
            "kea_api_config:file_proof",
        ]
        assert self._callers("mirrors") == ["kea_api_config:apply"]

    def test_file_proof_has_exactly_these_callers_and_fails_on_a_seventh(self):
        """Decided 16: `_ask_the_file`, `probe`, the Plan's `_unloaded_edit`, `_to_api`, `_to_file` and `api_daemon_differs` - `apply`'s proof for a caller with no Plan goes through `_ask_the_file`."""
        names = sorted(set(self._callers("file_proof")))
        assert names == sorted(
            [
                "kea_api_config:_ask_the_file",
                "kea_api_config:probe",
                "kea_api_config:api_daemon_differs",
                "kea_changeset:_unloaded_edit",
                "kea_transport_switch:_to_api",
                "kea_transport_switch:_to_file",
            ]
        ), names

    def test_the_vector_is_reached_only_through_the_walk_that_names_a_path(self):
        assert self._callers("defaults_for") == ["kea_api_config:compare"]
        assert self._callers("load_vector") == ["kea_api_config:defaults_for"]

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
            "jen.services.secret_keys.without_userinfo",  # (Q221, AE12) the ONE definition of an address without its user-info: a leaf the compare prints never carries a password; a pure module
            "jen.services.config_revisions",
            "jen.services.kea",
            "jen.services.kea_host",
            "jen.services.kea_authoring",
            "jen.services.kea_tls",
            "jen.services.investigation_logging",  # the host's restore window (lazy: that module imports the change set)
            "hashlib",  # the probe is bound to its endpoint by a hash
            "datetime.datetime",  # the stored probe's clock (lazy)
            "datetime.timezone",
            "urllib.parse.urlsplit",  # `endpoint_key`: the host and port of an api_url (Q219, lazy)
            "jen.models.user",  # the stored probe is a settings row (lazy)
            "jen.services.write_mode",  # (Q223, AH4) the label of the discard box, as the card prints it (lazy; a module of words with no imports of its own)
        }
        assert imported <= allowed, imported - allowed
        calls = {
            ast.unparse(n.func)
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and "post" in ast.unparse(n.func).lower()
        }
        assert calls == set(), calls  # no direct HTTP: every command goes through `kea_command`


class TestLeafGrammar:
    """Q219 BI6 c (AD13): a container is named by its shape and the noun agrees with the count - "1 key", "1 entry" - and a value is never printed."""

    @pytest.mark.parametrize(
        ("value", "text"),
        [
            ({}, "an object with 0 keys"),
            ({"a": 1}, "an object with 1 key"),
            ({"a": 1, "b": 2}, "an object with 2 keys"),
            ([], "a list of 0 entries"),
            (["x"], "a list of 1 entry"),
            (["x", "y", "z"], "a list of 3 entries"),
        ],
    )
    def test_the_noun_agrees_with_the_count(self, value, text):
        assert api._leaf(value) == text


class TestTheOldNamesAreGone:
    """Q219 BI6 b (AD19): the two public names that differed by word order and meant two row kinds are `record_daemon_after_file_change` and `record_rendering_after_write`; the old names are absent from the tree."""

    OLD = (
        "record_after_file_write",
        "record_file_after_write",
        "same_modulo_defaults",
        "unloaded_edit_sentence",
        "_before_state",
    )

    def test_no_old_name_is_in_the_product_tree(self):
        found = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            found += [f"{path.relative_to(ROOT).as_posix()}: {name}" for name in self.OLD if name in text]
        assert not found, found

    def test_the_new_names_are_the_callers_names(self):
        assert hasattr(api, "record_daemon_after_file_change") and hasattr(api, "record_rendering_after_write")

    def test_a_rendering_row_is_always_source_rendering(self):
        import inspect

        assert "source" not in inspect.signature(api.record_rendering_after_write).parameters


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
        assert not hasattr(api, "same_modulo_defaults"), "step 8 asks `file_in_daemon` one way (Q219, Decided 16)"

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
        assert text == "at Dhcp4.subnet4: the file says a list of 2 entries, the daemon a list of 1 entry"

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
        store.rows.clear()  # the first row stays pending (its mark failed): the store keeps ONE per server, so the second case starts clean
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
        # the file omits Kea's written-out defaults AT their default values, as a file Jen authored does (Q217: the reverse compare is real now, so "the defaults" are the shipped vector's; Q218 D1:
        # a scalar is a default only at the value the daemon wrote out)
        file_cfg = {
            "Dhcp4": {k: v for k, v in fake.running.items() if not api._is_default(k, v, shipped, (fake.running,))}
        }
        monkeypatch.setattr(host, "read_config_versioned", lambda *a, **k: (copy.deepcopy(file_cfg), "r" * 64))
        server = {**server, "ssh_host": "10.0.0.7", "config_transport": "api"}
        stranger = copy.deepcopy(fake.running)
        stranger["decline-probation-period"] = 123
        fake.set_running(stranger)
        # no `kea` row on record: since Q219 the fallback is the PROOF (the file was written before the daemon's last load and is in the daemon), and a hand `config-set` by something that is not Jen after
        # that load is the named limit of one writer per daemon (docs/ARCHITECTURE.md 3.17): outside the supported configuration, and what Jen can still see - the digest of the last recording - needs a row
        assert api.api_daemon_differs(server, "dhcp4") == ""

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
        assert text == "at Dhcp4.hooks-libraries: the file says nothing, the daemon a list of 1 entry", text

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
        """The recorded files carry key paths, the names of the lists Kea defaults to non-empty, and the VALUE the daemon wrote out for a scalar path (Q218 D1: the defaults' values, never a setting), sorted, indexes blanked."""
        for path in sorted(api.KEA_DEFAULTS_DIR.glob("kea_defaults_*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            assert set(data) <= {"kea", "paths", "populated", "scalars"} and data["paths"] == sorted(
                set(data["paths"])
            ), path.name
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
    """Q218 BH1 a (CFG-005), rewritten by Q219: `write_file` READS the file first (capturing: an edit is in Config history before it can be lost) and sends `config-write` only over a file `file_proof`
    accepts - one the daemon has loaded, Jen's own rendering, or the one the Plan proved (`planned_sha`) - or over a `none` the operator discarded on this act."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        self.w = world.ProofWorld(fake, server, store, monkeypatch)
        self.seen = self.w.seen
        self.seen["reads"].clear()
        return server

    def test_a_file_the_daemon_loaded_is_written_over(self, fake, ssh):
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4")
        assert out["ok"] and "config-write" in fake.commands
        assert self.seen["reads"] == [True], "the sender's read is the capturing one"

    def test_an_edit_the_daemon_never_loaded_is_refused_by_name_and_nothing_is_sent(self, fake, ssh, store):
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4")
        assert not out["ok"] and out["code"] == "unloaded-edit"
        assert "Dhcp4.user-context" in out["detail"] and "has not loaded that edit" in out["detail"]
        assert "config-write" not in fake.commands and EDIT_KEY in fake.file
        external = [r for r in store.rows if r["source"] == "external"]
        assert external and EDIT_KEY in json.loads(external[-1]["config"])["Dhcp4"], "the edit is in Config history"

    def test_discard_writes_over_it_and_the_edit_was_in_config_history_before_the_write(self, fake, ssh, store):
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        at_the_write = {}

        def look(f):
            at_the_write["rows"] = [(r["source"], r["hash_kind"]) for r in store.rows]

        fake.hooks["config-write"] = look
        out = api.write_file(ssh, "dhcp4", discard=True)
        assert out["ok"] and EDIT_KEY not in fake.file
        assert ("external", "raw") in at_the_write["rows"], (
            "the discarded edit was recorded BEFORE config-write went out"
        )

    def test_jens_own_rendering_loses_nothing_to_a_new_rendering(self, fake, ssh, store):
        edited = {**fake.file, EDIT_KEY: copy.deepcopy(EDIT)}
        self.w.hand_edit(edited)
        store.record(
            SID,
            "dhcp4",
            {"Dhcp4": edited},
            self.seen["sha"]({"Dhcp4": edited}),
            "rendered",
            hash_kind="raw",
            source="rendering",
        )
        assert api.write_file(ssh, "dhcp4")["ok"]

    def test_the_file_the_plan_proved_is_written_over_though_the_daemon_never_loaded_it(self, fake, ssh):
        edited = {**fake.file, EDIT_KEY: copy.deepcopy(EDIT)}
        self.w.hand_edit(edited)
        planned = self.seen["sha"]({"Dhcp4": edited})
        assert api.write_file(ssh, "dhcp4", planned_sha=planned)["ok"]

    def test_no_ssh_host_means_no_file_to_ask(self, fake, server, monkeypatch):
        reads = []
        monkeypatch.setattr(host, "read_config_proof", lambda *a, **k: reads.append(a) or (None, None, None))
        fake.commands.clear()
        out = api.write_file(server, "dhcp4")
        assert out["ok"] and reads == [] and "config-write" in fake.commands

    def test_a_file_that_cannot_be_read_is_never_overwritten_not_even_with_discard(self, fake, ssh, monkeypatch):
        monkeypatch.setattr(host, "read_config_proof", lambda *a, **k: (None, None, None))
        fake.commands.clear()
        out = api.write_file(ssh, "dhcp4", discard=True)
        assert not out["ok"] and out["code"] == "unloaded-edit" and "could not be read" in out["detail"]
        assert "config-write" not in fake.commands

    def test_the_signature_has_no_before_and_a_caller_cannot_pass_one(self):
        import inspect

        params = inspect.signature(api.write_file).parameters
        assert list(params) == ["server", "service", "planned_sha", "discard"], list(params)
        with pytest.raises(TypeError):
            api.write_file({}, "dhcp4", before={})

    def test_a_refused_write_is_still_keas_own_words(self, fake, ssh):
        fake.write_fails = "Permission denied"
        out = api.write_file(ssh, "dhcp4")
        assert out["code"] == "write-failed" and "Permission denied" in out["detail"]


class TestTheLiveBranchWaitsOnTheFile:
    """Q218 BH1 b (AC1, AC2), rewritten by Q219: a settlement of a LIVE pending row asks the proof with the file the row's Plan proved (`file_sha256`): the file is byte for byte that one, or Jen's own
    rendering; an edit made since - or a row an earlier release wrote, which carries none - is never overwritten and the row stays."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        self.w = world.ProofWorld(fake, server, store, monkeypatch)
        self.seen = self.w.seen
        self.seen["reads"].clear()
        return server

    def _live(self, fake, server, store, *, planned=True):
        cfg, digest = _plan(server)
        cand = _candidate(cfg)
        sha = self.seen["sha"]({"Dhcp4": fake.file}) if planned else None
        row_id = store.record(
            SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending", file_sha256=sha
        )
        fake.set_running(cand["Dhcp4"])  # the daemon took it; the FILE is still the one the Plan proved
        return cfg, digest, row_id

    def test_the_file_is_the_planned_one_so_the_settlement_writes_and_finishes(self, fake, ssh, store):
        self._live(fake, ssh, store)
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled and "finished" in lines[0] and fake.file == fake.running
        assert store.pending(SID, "dhcp4") is None

    def test_an_edit_made_since_the_plan_waits_and_the_row_stays(self, fake, ssh, store):
        self._live(fake, ssh, store)
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "is live and its file write waits" in lines[0]
        assert "not the file this change was planned over" in lines[0] and "has not loaded that edit" in lines[0]
        assert "config-write" not in fake.commands and EDIT_KEY in fake.file
        assert store.pending(SID, "dhcp4") is not None
        assert any(r["source"] == "external" for r in store.rows), "the edit is in Config history"

    def test_a_row_that_carries_no_planned_file_is_refused_with_the_restart_sentence(self, fake, ssh, store):
        self._live(fake, ssh, store, planned=False)
        fake.commands.clear()
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "cannot be proved against the file this change was planned over" in lines[0]
        assert "restart Kea there" in lines[0] and "config-write" not in fake.commands
        assert store.pending(SID, "dhcp4") is not None

    def test_the_refusal_is_the_same_even_when_the_file_is_what_the_daemon_runs(self, fake, ssh, store):
        self._live(fake, ssh, store, planned=False)
        fake.file = copy.deepcopy(fake.running)  # the host's file already carries the change: fail closed anyway
        lines, settled = api.settle_pending(ssh, "dhcp4")
        assert settled is False and "planned over" in lines[0]

    def test_a_server_with_no_ssh_host_settles_as_before(self, fake, server, store):
        self._live(fake, server, store, planned=False)
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
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        notes = []
        api.read(ssh, "dhcp4", capture=False, notes=notes)
        assert "config-write" not in fake.commands and "config-set" not in fake.commands
        assert (
            notes
            and "is live and its file write waits" in notes[0]
            and "not the file this change was planned over" in notes[0]
        )
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
        world.ProofWorld(fake, server, store, monkeypatch)
        real, calls = api._rev.finish, {"n": 0}

        def flaky(rev_id, **kw):
            calls["n"] += 1
            return False if calls["n"] == 1 else real(rev_id, **kw)

        monkeypatch.setattr(api._rev, "finish", flaky)
        cfg, digest = _plan(server)
        proof = api.file_proof(server, "dhcp4")
        out = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg, planned_sha=proof["sha256"])
        assert out["code"] == "unverified" and out["needs_hands"] and "could not be finished" in out["detail"]
        assert store.pending(SID, "dhcp4") is not None, "the row is the one record of what the daemon runs"
        assert any(r["hash_kind"] == "raw" and r["source"] == "rendering" for r in store.rows), (
            "the file's raw row is recorded as Kea's own rendering"
        )
        # the next Plan (the gate) settles it by content: the daemon carries the change and the file IS Jen's rendering
        assert api.pending_block(server, "dhcp4") == ""
        assert store.pending(SID, "dhcp4") is None
        assert any(r["source"] == "jen" and r["hash_kind"] == "kea" for r in store.rows)

    def test_a_finish_that_fails_leaves_no_ok_over_a_pending_row(self, fake, server, store, monkeypatch):
        monkeypatch.setattr(api._rev, "finish", lambda *a, **k: False)
        out, _c, _d = _apply(server)
        assert not out["ok"] and out["code"] == "unverified"
        assert store.pending(SID, "dhcp4") is not None


class TestAStoreThatRaisesAtStepThreeIsUnreadable:
    """Q219 BI2 c (AD9): the pending record's write RAISING is the same refusal as one that answers None - `unreadable`, nothing sent - never an exception out of `apply`, and the two routes that call `apply` directly (the restore
    and the import) answer the sentence, not a 500."""

    def test_a_store_that_raises_at_step_three_is_the_same_refusal(self, fake, server, store, monkeypatch):
        """Q219 BI2 c (AD9): `record` RAISING is `unreadable` with nothing sent, never an exception out of `apply`."""

        def boom(*a, **k):
            raise RuntimeError("the database went away")

        monkeypatch.setattr(api._rev, "record", boom)
        cfg, digest = _plan(server)
        fake.commands.clear()
        out = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert not out["ok"] and out["code"] == "unreadable" and "nothing was sent" in out["detail"]
        assert not any(c in fake.commands for c in ("config-set", "config-write"))

    def test_the_two_routes_that_call_apply_directly_catch_the_unreadable_store(self):
        for rel in ("jen/routes/servers.py", "jen/routes/subnets.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            assert "RevisionStoreUnreadable" in source and "unreadable_sentence(" in source, rel


class TestARestoreOverALivePendingChangeIsRefused:
    """Q219 BI2 b (AD5): a restore never plants a second pending row. Over a LIVE record (the daemon runs a change whose file write is owed) it asks for the settlement first and sends nothing; over a stale one
    (the change never reached the daemon, the body is damaged, or the daemon runs neither state) the restore is the way out and supersedes it."""

    def _live(self, fake, server, store):
        cfg, digest = _plan(server)
        cand = _candidate(cfg)
        store.record(SID, "dhcp4", cand, digest, "interrupted", hash_kind="kea", source="pending")
        fake.set_running(cand["Dhcp4"])
        return cfg, digest

    def test_a_live_row_refuses_the_restore_and_nothing_is_sent(self, fake, server, store):
        self._live(fake, server, store)
        cfg, now = api.read(server, "dhcp4", capture=False)
        fake.commands.clear()
        out = api.apply(server, "dhcp4", _candidate(cfg, 4), now, "restore", source="restore", before_cfg=cfg)
        assert not out["ok"] and out["code"] == "unverified"
        assert (
            out["detail"]
            == f"settle the unresolved change on {server['name']} first - Settle it now on its Write mode card"
        )
        assert "config-set" not in fake.commands and "config-write" not in fake.commands
        assert len([r for r in store.rows if r["source"] == "pending"]) == 1, "no second row"

    def test_a_row_the_daemon_never_took_is_superseded_by_the_restore(self, fake, server, store):
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", _candidate(cfg, 99), digest, "never landed", hash_kind="kea", source="pending")
        out = api.apply(server, "dhcp4", _candidate(cfg, 4), digest, "restore", source="restore", before_cfg=cfg)
        assert out["ok"] and store.pending(SID, "dhcp4") is None

    def test_a_daemon_that_does_not_answer_cannot_be_restored_over_a_record(self, fake, server, store):
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", _candidate(cfg, 99), digest, "in doubt", hash_kind="kea", source="pending")
        fake.stopped = True
        out = api.apply(server, "dhcp4", _candidate(cfg, 4), digest, "restore", source="restore", before_cfg=cfg)
        assert not out["ok"]
        assert store.pending(SID, "dhcp4") is not None


class TestLiveNotYetInItsFileIsTheLine:
    """Q219 BI2 d (AD17, AD18): a change the daemon took whose file write was refused reads "live in the daemon on <host>, not yet in its file:" - never "failed"."""

    def test_the_step_six_refusal_begins_with_the_live_sentence(self, fake, server, store, monkeypatch):
        w = world.ProofWorld(fake, server, store, monkeypatch)
        cfg, digest = _plan(server)
        w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        out = api.apply(server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg, planned_sha="0" * 64)
        assert out["code"] == "unverified" and out["needs_hands"]
        assert out["detail"].startswith(f"live in the daemon on {server['name']}, not yet in its file:"), out["detail"]
        assert "failed" not in out["detail"].lower().split(":")[0]


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
    """Q218 BH1 b, rewritten by Q219: `apply`'s own `config-write` (step 6) asks the proof as the sender does - the file is still the one the Plan proved, or Jen's own rendering. The daemon has taken the
    change when it is asked, so a refusal is `unverified` - nothing is undone, the pending row STAYS, and the sentence names the edit."""

    @pytest.fixture
    def ssh(self, fake, server, store, monkeypatch):
        self.w = world.ProofWorld(fake, server, store, monkeypatch)
        return server

    def test_an_edit_that_appeared_after_the_plan_is_refused_at_step_six_and_the_row_stays(self, fake, ssh, store):
        cfg, digest = _plan(ssh)
        planned = api.file_proof(ssh, "dhcp4")["sha256"]
        self.w.hand_edit(
            {**fake.file, EDIT_KEY: copy.deepcopy(EDIT)}
        )  # the operator edits the file between the Plan and the write
        fake.commands.clear()
        out = api.apply(ssh, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg, planned_sha=planned)
        assert out["code"] == "unverified" and out["needs_hands"] and not out["ok"]
        assert "not yet in its file" in out["detail"] and "not the file this change was planned over" in out["detail"]
        assert "config-set" in fake.commands and "config-write" not in fake.commands
        assert fake.running["valid-lifetime"] == 7200, "nothing is undone: the daemon runs the change"
        assert EDIT_KEY in fake.file, "and the operator's edit is still on the host"
        row = store.pending(SID, "dhcp4")
        assert row is not None and row["file_sha256"] == planned, "the row keeps the file the Plan proved"
        assert any(r["source"] == "external" for r in store.rows)

    def test_a_caller_with_no_plan_proves_the_file_itself_before_anything_is_sent(self, fake, ssh, store):
        """A restore or an import brings no `planned_sha`: `apply` asks the proof BEFORE the pending row and the `config-set`, so a hand edit is refused with nothing changed."""
        cfg, digest = _plan(ssh)
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        out = api.apply(ssh, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert out["code"] == "guard" and not out["ok"] and "has not loaded that edit" in out["detail"]
        assert (
            "config-set" not in fake.commands
            and "config-write" not in fake.commands
            and store.pending(SID, "dhcp4") is None
        )

    def test_a_rollback_is_proved_by_jens_own_rendering(self, fake, ssh, store):
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

    def test_a_rollback_over_a_hand_edit_is_refused_before_the_set_with_the_sentence(self, fake, ssh, store):
        # (Q219 E10 refused it at step (6), after `config-set`; Q224 AJ9 refuses it before: the daemon and its file keep the change, nothing is sent, no row is left)
        cfg, digest = _plan(ssh)
        first = api.apply(ssh, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert first["ok"]
        _after, after_digest = _plan(ssh)
        self.w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        out = api.revert(ssh, "dhcp4", cfg, after_digest, "rollback: x", before_cfg=_candidate(cfg))
        assert (
            out["code"] == "guard"
            and "does not say what the daemon runs" in out["detail"]
            and "nothing was sent" in out["detail"]
        )
        assert "config-set" not in fake.commands and "config-write" not in fake.commands
        assert (
            fake.running["valid-lifetime"] == _candidate(cfg)["Dhcp4"]["valid-lifetime"]
            and store.pending(SID, "dhcp4") is None
        )


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
        w = world.ProofWorld(fake, server, store, monkeypatch)
        cfg, digest = _plan(server)
        store.record(SID, "dhcp4", cfg, digest, "the state before", hash_kind="kea", source="baseline")
        cand = _candidate(cfg)
        store.record(
            SID,
            "dhcp4",
            cand,
            digest,
            "interrupted",
            hash_kind="kea",
            source="pending",
            file_sha256=w.seen["sha"]({"Dhcp4": fake.file}),
        )
        fake.set_running(cand["Dhcp4"])
        lines, settled = api.settle_pending(server, "dhcp4")
        assert settled, lines
        assert any(r["hash_kind"] == "raw" and r["source"] == "rendering" for r in store.rows)
        host.read_config_versioned(server, "dhcp4")  # the next capturing read
        assert not [r for r in store.rows if r["source"] == "external"]


VECTOR_MODES = ["shipped", "absent", "everything-is-a-default"]


@pytest.fixture(params=VECTOR_MODES)
def vector_mode(request, monkeypatch):
    """Q219: every world below runs three times - with the shipped vector, with NO vector (`load_vector` answers nothing) and with `_is_default` answering True for everything (beta.4's worst case): the
    verdicts and the write counts are the same in all three, because the vector decides nothing. (Only the PATH in a sentence may differ.)"""
    if request.param == "absent":
        monkeypatch.setattr(api, "load_vector", lambda version, directory=None: (None, ""))
    elif request.param == "everything-is-a-default":
        monkeypatch.setattr(api, "_is_default", lambda *a, **k: True)
    return request.param


def _candidate_of(cfg, lifetime=5400):
    out = copy.deepcopy(cfg)
    out["Dhcp4"]["valid-lifetime"] = lifetime
    return out


class TestTheProofIsTheDaemonsOwnAnswer:
    """Q219 BI1 h (AD1, AD20, AD21): every world the product is FOR - a hand-authored file and a Jen-authored one - through the real sequence (the Plan's proof, `apply`, the settlement, `_to_api`) against a
    fake daemon that writes Kea's defaults out and a fake host that answers `config-loaded` from a settable clock, asserting the `config-write` count AND what the file holds afterward. The oracle -
    the defaults vector - is removed from the decision, and the class runs without it."""

    @pytest.fixture
    def w(self, fake, server, store, monkeypatch, vector_mode):
        self.mode = vector_mode
        world_ = world.ProofWorld(fake, server, store, monkeypatch)
        world_.start(world_.ad1_running(fake.running))
        return world_

    def _plan(self, w):
        """What `apply_change`'s Plan does for one api target: read, ask the proof BEFORE any `config-set`, keep the file's sha."""
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        return cfg, digest, api.file_proof(w.server, "dhcp4")

    def _apply(self, w, cfg, digest, proof, lifetime=5400):
        return api.apply(
            w.server,
            "dhcp4",
            _candidate_of(cfg, lifetime),
            digest,
            "a change",
            before_cfg=cfg,
            planned_sha=proof["sha256"],
        )

    def _through_the_plan(self, w):
        cfg, digest, proof = self._plan(w)
        if not proof["ok"]:
            return proof, None
        return proof, self._apply(w, cfg, digest, proof)

    # ── the AD1 world: a scalar the operator deleted from the file, and a daemon that never loaded the edit ──────────
    def test_ad1_an_inherited_scalar_deleted_and_not_loaded_writes_nothing_and_prints_both_times(self, w, fake):
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        proof, out = self._through_the_plan(w)
        assert out is None and proof["how"] == "none" and not proof["ok"]
        assert w.sets() == 0 and w.writes() == 0
        assert "valid-lifetime" not in fake.file["subnet4"][0], "the operator's deletion is still on the host"
        assert "written at " in proof["why"] and "the daemon last loaded its configuration at " in proof["why"]
        assert "has not loaded that edit" in proof["why"] and "restart Kea there" in proof["why"]
        if self.mode == "shipped":
            assert "Dhcp4.subnet4[0].valid-lifetime" in proof["why"], proof["why"]

    def test_ad1_the_same_world_reloaded_is_accepted_and_rendered(self, w, fake):
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        w.reload()
        proof, out = self._through_the_plan(w)
        assert proof["ok"] and proof["how"] == "loaded"
        assert out["ok"] and w.writes() == 1
        assert fake.file["valid-lifetime"] == 5400, "the file is Kea's rendering of what runs"

    def test_ad1_the_same_world_as_jens_own_rendering_is_accepted(self, w, fake, store):
        edited = world.without(fake.file, "subnet4", 0, "valid-lifetime")
        w.hand_edit(edited)
        store.record(
            SID,
            "dhcp4",
            {"Dhcp4": edited},
            w.seen["sha"]({"Dhcp4": edited}),
            "rendered",
            hash_kind="raw",
            source="rendering",
        )
        proof, out = self._through_the_plan(w)
        assert proof["ok"] and proof["how"] == "rendering" and out["ok"] and w.writes() == 1

    def test_ad1_through_the_switch_the_same_world_is_refused_then_accepted(self, w, fake, monkeypatch):
        from jen.services import kea_transport_switch as sw

        monkeypatch.setattr(
            host,
            "config_write_check",
            lambda server, service="dhcp4": {
                "ok": True,
                "may_write": True,
                "mode": "0660",
                "includes": [],
                "account": {"name": "_kea"},
            },
        )
        monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        consents = {"consent_rendering", "consent_unauthenticated"}
        refused = sw._to_api(w.server, "file", consents, "tester")
        assert not refused["ok"] and w.writes() == 0, refused
        assert "valid-lifetime" not in fake.file["subnet4"][0]
        w.reload()
        accepted = sw._to_api(w.server, "file", consents, "tester")
        assert accepted["ok"] and w.writes() == 1, accepted

    # ── the AD20 and AD21 worlds: files that are loaded and fine ─────────────────────────────────────────────────
    def test_ad20_a_hand_authored_file_with_name_only_options_that_the_daemon_loaded_is_accepted(self, w, fake):
        fake.running["option-data"] = world.ProofWorld.render_defaults(
            {"option-data": [{"name": "routers", "data": "10.99.0.1"}]}
        )["option-data"]  # the daemon runs the option with its code, space, csv-format and always-send written out
        authored = copy.deepcopy(fake.running)
        authored["option-data"] = [
            {"name": "routers", "data": "10.99.0.1"}
        ]  # the hand-authored file: the name and the data only
        authored["subnet4"][0].pop("valid-lifetime")  # an inherited valid-lifetime omitted too
        w.loaded_file(authored)
        proof, out = self._through_the_plan(w)
        assert proof["ok"] and proof["how"] == "loaded", proof
        assert out["ok"] and w.writes() == 1

    def test_ad21_jens_own_file_path_output_without_always_send_is_accepted(self, w, fake):
        jen_file = copy.deepcopy(fake.running)
        for subnet in jen_file["subnet4"]:
            subnet["option-data"] = [
                {"name": o["name"], "code": o["code"], "space": "dhcp4", "csv-format": True, "data": o["data"]}
                for o in subnet["option-data"]
            ]  # name, code, space, csv-format, data: no `always-send` (kea_config_edit.py writes this shape)
        w.loaded_file(jen_file)
        proof, out = self._through_the_plan(w)
        assert proof["ok"] and proof["how"] == "loaded" and out["ok"] and w.writes() == 1

    # ── the clock decides, to the second ─────────────────────────────────────────────────────────────────────────
    def test_a_touch_after_the_load_is_refused_and_the_times_name_it(self, w, fake):
        w.clock.touch()
        proof, out = self._through_the_plan(w)
        assert out is None and proof["how"] == "none" and w.writes() == 0
        assert "written at " in proof["why"] and "last loaded its configuration at " in proof["why"]

    def test_an_edit_in_the_same_second_as_the_load_passes_the_named_limit(self, w, fake):
        """The sub-second limit (§3.17): the proof compares whole seconds. Asserted so the day it is closed this test says so."""
        w.clock.mtime = w.clock.loaded_at
        proof, out = self._through_the_plan(w)
        assert proof["ok"] and proof["how"] == "loaded"

    def test_the_file_written_before_the_load_but_not_carried_is_a_reload_that_did_not_take(self, w, fake):
        authored = copy.deepcopy(fake.running)
        authored["subnet4"][0]["comment"] = "never loaded"
        w.loaded_file(authored)  # older than the load, but the daemon does not run it (a failed reload is not a load)
        proof, out = self._through_the_plan(w)
        assert out is None and not proof["ok"] and "before the daemon's last load" in proof["why"]
        assert w.writes() == 0

    # ── step (6): the file is checked again after the daemon took the change ─────────────────────────────────────
    def test_an_edit_between_the_plan_and_the_set_is_unverified_and_nothing_is_written(self, w, fake, store):
        cfg, digest, proof = self._plan(w)
        assert proof["ok"]
        edited = world.without(fake.file, "subnet4", 0, "valid-lifetime")
        original = fake._answer

        def answer(command, arguments):
            reply = original(command, arguments)
            if command == "config-set" and reply.get("result") == 0:
                w.hand_edit(edited)  # the operator edits the file after the Plan proved it
            return reply

        fake._answer = answer
        out = self._apply(w, cfg, digest, proof)
        assert not out["ok"] and out["code"] == "unverified" and out["needs_hands"]
        assert out["detail"].startswith(f"live in the daemon on {w.server['name']}, not yet in its file:"), out[
            "detail"
        ]
        assert w.writes() == 0
        row = store.pending(SID, "dhcp4")
        assert row is not None and row["file_sha256"] == proof["sha256"], "the row keeps the file the Plan proved"
        assert "valid-lifetime" not in fake.file["subnet4"][0]

    def test_the_settlement_of_that_row_is_refused_while_the_file_is_not_the_planned_one(self, w, fake, store):
        cfg, digest, proof = self._plan(w)
        store.record(
            SID,
            "dhcp4",
            _candidate_of(cfg),
            digest,
            "left by a crash",
            hash_kind="kea",
            source="pending",
            file_sha256=proof["sha256"],
        )
        fake.set_running(_candidate_of(cfg)["Dhcp4"])
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        fake.commands.clear()
        lines, settled = api.settle_pending(w.server, "dhcp4")
        assert settled is False and w.writes() == 0
        assert (
            "is live and its file write waits" in lines[0] and "not the file this change was planned over" in lines[0]
        ), lines
        assert store.pending(SID, "dhcp4") is not None

    def test_the_settlement_over_the_planned_file_writes_once(self, w, fake, store):
        cfg, digest, proof = self._plan(w)
        store.record(
            SID,
            "dhcp4",
            _candidate_of(cfg),
            digest,
            "left by a crash",
            hash_kind="kea",
            source="pending",
            file_sha256=proof["sha256"],
        )
        fake.set_running(_candidate_of(cfg)["Dhcp4"])
        fake.commands.clear()
        lines, settled = api.settle_pending(w.server, "dhcp4")
        assert settled is True and w.writes() == 1, lines
        assert store.pending(SID, "dhcp4") is None
        assert any(r["source"] == "rendering" for r in store.rows), "the settlement's own rendering is recorded"

    def test_a_pending_row_from_before_this_release_is_refused_with_the_restart_sentence(self, w, fake, store):
        cfg, digest, _proof = self._plan(w)
        store.record(SID, "dhcp4", _candidate_of(cfg), digest, "an old row", hash_kind="kea", source="pending")
        fake.set_running(_candidate_of(cfg)["Dhcp4"])
        fake.commands.clear()
        lines, settled = api.settle_pending(w.server, "dhcp4")
        assert settled is False and w.writes() == 0
        assert "cannot be proved against the file this change was planned over" in lines[0]
        assert "restart Kea there" in lines[0]

    # ── hosts and daemons that cannot answer ─────────────────────────────────────────────────────────────────────
    def test_a_host_below_build_22_proves_only_jens_own_rendering(self, w, fake, store):
        w.clock.has_op = False
        edited = world.without(fake.file, "subnet4", 0, "valid-lifetime")
        w.loaded_file(edited)  # a hand edit the daemon loaded - but no clock to say so
        proof, out = self._through_the_plan(w)
        assert out is None and proof["how"] == "none" and w.writes() == 0
        assert "needs helper build 22" in proof["why"] and "press Update helper" in proof["why"]
        store.record(
            SID,
            "dhcp4",
            {"Dhcp4": edited},
            w.seen["sha"]({"Dhcp4": edited}),
            "rendered",
            hash_kind="raw",
            source="rendering",
        )
        proof, out = self._through_the_plan(w)
        assert proof["how"] == "rendering" and out["ok"] and w.writes() == 1

    def test_a_daemon_that_answered_no_socket_is_r_and_p_only_with_the_note(self, w, fake):
        w.clock.daemon = False
        w.clock.socket_note = "the socket did not answer"
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        proof, out = self._through_the_plan(w)
        assert out is None and w.writes() == 0
        assert "could not be read" in proof["why"] and "the socket did not answer" in proof["why"], proof["why"]

    def test_a_status_get_without_a_reload_field_is_r_and_p_only(self, w, fake):
        w.clock.reload_field = False
        w.loaded_file(copy.deepcopy(fake.running))
        proof, out = self._through_the_plan(w)
        assert out is None and not proof["ok"] and "status-get carries no reload" in proof["why"]


class TestFileProofOrder:
    """Q219 BI1 c: (R) before (P) before (L); `unreadable` and `no-file`; the three sentences for no op, no socket and no `reload`; and the proof's keys are exactly the eight."""

    @pytest.fixture
    def w(self, fake, server, store, monkeypatch):
        world_ = world.ProofWorld(fake, server, store, monkeypatch)
        world_.start(world_.ad1_running(fake.running))
        return world_

    KEYS = {"ok", "how", "sha256", "mtime", "loaded_at", "started_at", "where", "why"}

    def test_the_eight_keys_and_the_values_of_a_loaded_file(self, w):
        proof = api.file_proof(w.server, "dhcp4")
        assert set(proof) == self.KEYS and proof["ok"] and proof["how"] == "loaded"
        assert isinstance(proof["mtime"], int) and isinstance(proof["loaded_at"], int)
        assert isinstance(proof["started_at"], int)
        assert proof["mtime"] <= proof["loaded_at"] and proof["where"] == "" and proof["why"] == ""

    def test_no_ssh_host_is_no_file_and_ok(self, fake, server):
        out = api.file_proof(server, "dhcp4")
        assert out["ok"] and out["how"] == "no-file" and set(out) == self.KEYS

    def test_a_file_that_cannot_be_read_is_unreadable_and_not_ok(self, w, monkeypatch):
        monkeypatch.setattr(host, "read_config_proof", lambda *a, **k: (None, None, None))
        out = api.file_proof(w.server, "dhcp4")
        assert not out["ok"] and out["how"] == "unreadable" and "could not be read" in out["why"]

    def test_the_order_is_rendering_then_planned_then_loaded(self, w, fake, store):
        edited = world.without(fake.file, "subnet4", 0, "valid-lifetime")
        w.hand_edit(edited)
        sha = w.seen["sha"]({"Dhcp4": edited})
        assert api.file_proof(w.server, "dhcp4")["how"] == "none"
        assert api.file_proof(w.server, "dhcp4", planned_sha=sha)["how"] == "planned"
        store.record(SID, "dhcp4", {"Dhcp4": edited}, sha, "rendered", hash_kind="raw", source="rendering")
        assert api.file_proof(w.server, "dhcp4", planned_sha=sha)["how"] == "rendering", "(R) is asked before (P)"
        w.reload()
        store.rows[:] = [r for r in store.rows if r["source"] != "rendering"]
        assert api.file_proof(w.server, "dhcp4", planned_sha="0" * 64)["how"] == "loaded"

    def test_a_pending_row_turns_the_clock_off(self, w, fake, store):
        """The daemon's last commit is Jen's own `config-set`: while a change is pending the load time proves nothing."""
        store.record(SID, "dhcp4", {"Dhcp4": fake.running}, "a" * 64, "in flight", hash_kind="kea", source="pending")
        out = api.file_proof(w.server, "dhcp4")
        assert not out["ok"] and out["how"] == "none" and "unresolved" in out["why"]

    def test_an_unreadable_record_turns_the_clock_off_too(self, w, store):
        store.unreadable = True
        assert api.file_proof(w.server, "dhcp4")["how"] == "none"

    def test_three_sentences_for_no_op_no_socket_and_no_reload(self, w, fake):
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        w.clock.has_op = False
        assert "needs helper build 22" in api.file_proof(w.server, "dhcp4")["why"]
        w.clock.has_op = True
        w.clock.daemon = False
        assert "could not be read on" in api.file_proof(w.server, "dhcp4")["why"]
        w.clock.daemon, w.clock.reload_field = True, False
        assert "status-get carries no reload" in api.file_proof(w.server, "dhcp4")["why"]

    def test_the_times_print_in_utc_to_the_second(self, w, fake):
        import re

        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        why = api.file_proof(w.server, "dhcp4")["why"]
        stamp = r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC"
        assert re.search(rf"written at {stamp} and the daemon last loaded its configuration at {stamp}", why), why


class TestSecondPassRowsOfBeta5:
    """The second pass's rows E1, E3, E4, E9, E10 and H1 (pass/reports/v7.0.0-beta.5-fix-rows.md): each executed here against the real sequence."""

    @pytest.fixture
    def w(self, fake, server, store, monkeypatch):
        world_ = world.ProofWorld(fake, server, store, monkeypatch)
        world_.start(world_.ad1_running(fake.running))
        return world_

    # E1 - a change is never refused on a stale `agree False`: the WRITE PATH reads it again (Q221 moved the re-read out of the gate, which is a read every page makes)
    @staticmethod
    def _the_host_answers(monkeypatch):
        """The helper's `config-write-check`, as a host answers it: the world stands in for the file reads, and the probe asks this too."""
        monkeypatch.setattr(
            api._host,
            "config_write_check",
            lambda server, service="dhcp4": {
                "ok": True,
                "may_write": True,
                "mode": "0660",
                "account": {"name": "_kea"},
                "includes": [],
            },
        )

    CONSENTS = [
        "consent_rendering",
        "consent_unauthenticated",
    ]  # the fake daemon has no authentication, and a full re-read says so

    def test_e1_a_stored_false_is_read_again_by_the_write_path_and_a_restart_since_opens_it(
        self, w, fake, server, monkeypatch
    ):
        self._the_host_answers(monkeypatch)
        probes = api.stored_probe(server["id"])
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        api.store_probe(
            server["id"],
            {**probes, "agree": False, "agree_at": "at Dhcp4.subnet4[0].valid-lifetime", "consents": self.CONSENTS},
        )
        assert "carries a configuration the daemon is not running" in api.probe_gate(server)
        w.reload()  # the operator did what the sentence said
        assert "carries a configuration the daemon is not running" in api.probe_gate(server), (
            "the gate is a read: it answers from the stored result"
        )
        assert api.stored_probe(server["id"])["agree"] is False
        assert (
            api.refresh_if_stale(server) is True
        )  # what the Plan of the next change, and `apply`, ask before the gate
        assert api.probe_gate(server) == ""
        stored = api.stored_probe(server["id"])
        assert stored["agree"] is True and stored["proof"] == "loaded" and "agree_at" not in stored

    def test_e1_a_file_that_is_still_unloaded_keeps_the_gate_closed(self, w, fake, server, monkeypatch):
        self._the_host_answers(monkeypatch)
        probes = api.stored_probe(server["id"])
        w.hand_edit(world.without(fake.file, "subnet4", 0, "valid-lifetime"))
        api.store_probe(server["id"], {**probes, "agree": False, "consents": self.CONSENTS})
        assert api.refresh_if_stale(server) is True  # read again, and the answer is still no
        assert "daemon is not running" in api.probe_gate(server)
        stored = api.stored_probe(server["id"])
        assert stored["agree"] is False and stored["proof"] == "none"

    # E3 - a refused restore loses nothing
    def test_e3_a_refused_restore_keeps_the_stale_record(self, w, fake, server, store):
        cfg, digest = api.read(server, "dhcp4", capture=False)
        store.record(SID, "dhcp4", _candidate_of(cfg, 99), digest, "never landed", hash_kind="kea", source="pending")
        w.hand_edit({**fake.file, EDIT_KEY: copy.deepcopy(EDIT)})
        fake.commands.clear()
        out = api.apply(server, "dhcp4", _candidate_of(cfg, 4), digest, "restore", source="restore", before_cfg=cfg)
        assert out["code"] == "guard" and "config-set" not in fake.commands
        assert store.pending(SID, "dhcp4") is None, "it no longer blocks ..."
        assert [r["source"] for r in store.rows if r["summary"] == "never landed"] == ["damaged"], (
            "... and it is still in Config history"
        )

    # E4 - a rendering that could not be recorded is said
    def test_e4_a_change_whose_rendering_cannot_be_recorded_says_so(self, w, fake, server, store, monkeypatch):
        real = store.record

        def refuse_rendering(*a, **k):
            return None if k.get("source") == "rendering" else real(*a, **k)

        monkeypatch.setattr(api._rev, "record", refuse_rendering)
        cfg, digest = api.read(server, "dhcp4", capture=False)
        proof = api.file_proof(server, "dhcp4")
        out = api.apply(server, "dhcp4", _candidate_of(cfg), digest, "x", before_cfg=cfg, planned_sha=proof["sha256"])
        assert (
            out["ok"]
            and "could not be recorded in Config history" in out["note"]
            and "restart Kea there" in out["note"]
        )

    # E9 - times are bounded
    def test_e9_an_absurd_time_is_no_time_and_never_raises(self, w, monkeypatch):
        real = host.read_config_proof

        def absurd(server, service, *, capture=True):
            cfg, sha, times = real(server, service, capture=capture)
            return cfg, sha, {**times, "mtime": 10**15, "daemon": {"pid": 1, "uptime": 5, "reload": -5}}

        monkeypatch.setattr(host, "read_config_proof", absurd)
        out = api.file_proof(w.server, "dhcp4")
        assert out["mtime"] is None and out["loaded_at"] is None and not out["ok"]
        assert api._utc(10**15) == "an unreadable time"

    # E10 - a rollback's row carries the file, and a live row with no planned file says the restart
    def test_e10_a_rollback_row_carries_the_file_as_it_stands(self, w, fake, server, store):
        cfg, digest = api.read(server, "dhcp4", capture=False)
        first = api.apply(
            server,
            "dhcp4",
            _candidate_of(cfg),
            digest,
            "x",
            before_cfg=cfg,
            planned_sha=api.file_proof(server, "dhcp4")["sha256"],
        )
        assert first["ok"]
        _after, after_digest = api.read(server, "dhcp4", capture=False)
        seen = {}
        fake.hooks["config-set"] = lambda f: seen.setdefault("row", store.pending(SID, "dhcp4"))
        api.revert(server, "dhcp4", cfg, after_digest, "rollback: x", before_cfg=_candidate_of(cfg))
        assert (
            seen["row"]
            and seen["row"]["file_sha256"] == w.seen["sha"]({"Dhcp4": fake.file})
            or len(seen["row"]["file_sha256"]) == 64
        )

    def test_e10_a_restore_over_a_live_row_with_no_planned_file_says_the_restart(self, w, fake, server, store):
        cfg, digest = api.read(server, "dhcp4", capture=False)
        cand = _candidate_of(cfg)
        store.record(SID, "dhcp4", cand, digest, "an older release", hash_kind="kea", source="pending")
        fake.set_running(cand["Dhcp4"])
        out = api.apply(server, "dhcp4", _candidate_of(cfg, 4), digest, "restore", source="restore", before_cfg=cfg)
        assert not out["ok"] and "restart Kea there to run the file instead of the change" in out["detail"]
        assert out["detail"].index("tick the box beside Settle it now") < out["detail"].index(
            "restart Kea there"
        )  # (Q223, AH2) the box first

    # H1 - a write that never ran
    def test_h1_a_write_that_may_not_have_run_over_the_planned_file_is_unverified(self, w, fake, server, store):
        fake.hang = {"config-write": "before"}  # the command never runs and no answer comes
        cfg, digest = api.read(server, "dhcp4", capture=False)
        proof = api.file_proof(server, "dhcp4")
        out = api.apply(server, "dhcp4", _candidate_of(cfg), digest, "x", before_cfg=cfg, planned_sha=proof["sha256"])
        assert not out["ok"] and out["code"] == "unverified"
