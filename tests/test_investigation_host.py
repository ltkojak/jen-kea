"""
tests/test_investigation_host.py
────────────────────────────────
v5.68.0-beta.29 (Q165) - Jen's side of "the Kea HOST owns the restore": turning logging on asks the host's helper (build 15) to arm a self-restore AFTER the file is written and
BEFORE the daemon is asked, and refuses - with the file put back - when it cannot; turning it off (and the sweep's restore) asks the host to restore NOW, with Jen's older
file-writing path as the fallback; the sweep reads the host's own report; an armed entry's by-hand text is one command on the host; and a candidate config whose marker is not
the one recorded is refused (compared, not validated).

The fake host is the one of tests/_investigation_world.py: it restores a logger with the helper's OWN `_restore_logger` and moves the daemon with a SIGHUP, with one restart as the
fallback. No database, no Kea:  pytest --noconftest tests/test_investigation_host.py
"""

import copy
from datetime import timedelta

import pytest

from jen.services import investigation_logging as inv
from jen.services import kea_config_edit as ed
from tests._investigation_world import NOW, _cfg

pytest_plugins = ("tests._investigation_world",)


def _logger(cfg):
    return next(x for x in cfg["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")


def _at_debug(cfg):
    entry = next((x for x in (cfg.get("Dhcp4") or {}).get("loggers", []) if x["name"] == "kea-dhcp4"), None)
    return bool(entry) and entry.get("severity") == "DEBUG" and entry.get("debuglevel") == 55


def _later(monkeypatch, minutes):
    monkeypatch.setattr(inv, "_now", lambda: NOW + timedelta(minutes=minutes))


class TestTurnOnNeedsTheHost:
    def test_a_helper_below_build_15_is_refused_before_anything_is_written(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        kea.build = 14
        out = inv.turn_on(world.servers[0], 5, actor="alice")
        assert not out["ok"] and out["until"] == ""
        assert "build 17 or later" in out["lines"][0] and "Update helper" in out["lines"][0]
        assert kea.file == original and kea.writes == 0 and "host:arm" not in kea.calls
        assert not inv.active() and "_audit" not in world.store

    def test_a_host_with_no_helper_is_refused_and_told_to_install_it(self, world):
        kea = world.daemons[1]
        kea.helper_code = "missing"
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "not installed" in out["lines"][0] and kea.writes == 0

    def test_a_helper_that_cannot_be_asked_is_refused_not_guessed_at(self, world):
        kea = world.daemons[1]
        kea.host_down = True
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "could not ask" in out["lines"][0] and kea.writes == 0 and not inv.active()

    def test_the_host_is_armed_after_the_file_write_and_before_the_daemon_is_asked(self, world):
        kea = world.daemons[1]
        out = inv.turn_on(world.servers[0], 15, actor="alice")
        assert out["ok"]
        calls = kea.calls
        write = next(i for i, c in enumerate(calls) if c.startswith("apply("))
        arm = calls.index("host:arm")
        reload_ = calls.index("config-reload")
        assert write < arm < reload_, calls

    def test_the_state_the_host_holds_is_the_deadline_and_the_markers_own_restore_object(self, world):
        kea = world.daemons[1]
        out = inv.turn_on(world.servers[0], 15)
        marker = ed.investigation_marker(kea.file)
        assert kea.helper_state["restore"] == marker["restore"] == {"severity": "INFO", "debuglevel": "absent"}
        assert ed._parse_until(kea.helper_state["until"]) == ed._parse_until(out["until"])
        assert kea.helper_state["jen"] == {"server_id": "1", "name": "kea-a"}

    def test_the_entry_records_that_the_host_holds_it(self, world):
        inv.turn_on(world.servers[0], 5)
        (row,) = inv.active()
        assert row["armed"] is True and row["host_timer"] == "systemd" and row["host_error"] == ""

    def test_a_shorter_session_is_refused_and_the_running_one_is_untouched(self, world):
        """A session is only ever extended: the host's record does not accept an earlier deadline (INV-008), so Jen says so before it writes anything."""
        kea = world.daemons[1]
        first = inv.turn_on(world.servers[0], 60)
        assert first["ok"]
        writes, state = kea.writes, copy.deepcopy(kea.helper_state)
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "only extended" in out["lines"][0] and "Turn it off first" in out["lines"][0]
        assert kea.writes == writes and kea.helper_state == state and len(inv.active()) == 1 and _at_debug(kea.loaded)

    def test_extending_a_session_arms_the_host_again_with_the_new_deadline(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        out = inv.turn_on(world.servers[0], 15)
        assert out["ok"] and ed._parse_until(kea.helper_state["until"]) == ed._parse_until(out["until"])
        assert kea.helper_state["restore"] == {"severity": "INFO", "debuglevel": "absent"}, (
            "the ORIGINAL level, not DEBUG"
        )


class TestARefusedArmPutsTheFileBack:
    def test_an_arm_the_host_refuses_reverts_the_file_and_nothing_is_on(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        kea.arm_fails = "the state directory could not be created"
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and out["until"] == ""
        assert any("could not arm its self-restore" in line for line in out["lines"]), out["lines"]
        assert kea.file == original and not inv.active() and "_audit" not in world.store
        assert "config-reload" not in kea.calls, "the daemon was never asked to read the DEBUG file"

    def test_a_timer_none_host_is_refused_and_its_state_is_settled(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        kea.timer = "none"
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and any("cannot restore the log level by itself" in line for line in out["lines"]), out[
            "lines"
        ]
        assert kea.file == original and not inv.active() and "config-reload" not in kea.calls
        assert "host:disarm" in kea.calls, "the state the host wrote is settled, not left armed with no timer behind it"

    def test_a_daemon_without_config_reload_that_was_restarted_onto_the_file_is_still_finished(self, world):
        """The change set restarted the daemon onto the DEBUG file before the arm: the file is put back and the entry is kept so the daemon step is finished."""
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        kea.arm_fails = "no space"
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and not _at_debug(kea.file)
        entry = inv._record()["servers"]["1"]
        assert entry["file"] == "restored" and not entry.get("armed")
        inv.sweep(now=NOW)
        assert not _at_debug(kea.loaded) and not inv.active()


class TestTurnOffAsksTheHost:
    def test_the_host_restores_and_jen_only_looks(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        inv.turn_on(world.servers[0], 15)
        before = len(kea.calls)
        out = inv.turn_off(world.servers[0], actor="alice")
        assert out["ok"] and kea.file == original and not inv.active() and not _at_debug(kea.loaded)
        after = kea.calls[before:]
        assert "host:disarm" in after and not any(c.startswith("apply(") for c in after), after
        assert kea.helper_state["restored_at"] and kea.helper_state["how"] == "reload"
        assert [a[0] for a in world.store["_audit"]] == ["INVESTIGATION_LOGGING_ON", "INVESTIGATION_LOGGING_OFF"]

    @pytest.mark.parametrize("fault", ["host_restore_fails", "host_down"])
    def test_a_host_that_cannot_restore_leaves_it_to_jens_own_path_and_says_so(self, world, fault):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        inv.turn_on(world.servers[0], 15)
        setattr(kea, fault, True)
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and kea.file == original and not inv.active()
        assert any("could not restore the log level itself" in line for line in out["lines"]), out["lines"]
        assert any(c.startswith("apply(") for c in kea.calls[1:])

    def test_a_daemon_that_ignores_sighup_gets_the_hosts_one_restart(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.hup_ignored = True
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and out["mode"] == "restart" and not _at_debug(kea.loaded) and not inv.active()
        assert kea.helper_state["how"] == "restart"

    def test_a_restore_the_host_already_did_is_not_done_twice(self, world, monkeypatch):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 5)
        _later(monkeypatch, 6)
        assert kea.host_tick()[0] is True
        before = len(kea.calls)
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and not inv.active()
        assert not any(c.startswith("apply(") for c in kea.calls[before:])

    def test_a_damaged_marker_does_not_stop_the_host(self, world):
        """Jen refuses to guess at a marker that lost its restore object; the host holds the original in its own state and does not need it."""
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        inv.turn_on(world.servers[0], 15)
        del _logger(kea.file)["user-context"]["jen-investigation"]["restore"]
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and not inv.active() and not _at_debug(kea.loaded)
        assert kea.file == original


class TestTheSweepAndTheHost:
    def test_the_host_restores_by_itself_and_the_sweep_only_finishes_the_entry(self, world, monkeypatch):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        inv.turn_on(world.servers[0], 5)
        _later(monkeypatch, 5)
        assert kea.host_tick() is not None and kea.file == original and not _at_debug(kea.loaded)
        before = len(kea.calls)
        summary = inv.sweep(now=NOW + timedelta(minutes=5))
        assert summary["restored"] == ["kea-a"] and not inv.active()
        assert not any(c.startswith("apply(") for c in kea.calls[before:])

    def test_with_jen_not_running_at_all_the_host_puts_it_back(self, world, monkeypatch):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        inv.turn_on(world.servers[0], 5)
        assert _at_debug(kea.loaded)
        _later(monkeypatch, 4)
        assert kea.host_tick() is None and _at_debug(kea.loaded), "not before the deadline"
        _later(monkeypatch, 5)
        assert kea.host_tick()[0] is True
        assert kea.file == original and not _at_debug(kea.loaded), "no sweep, no Jen: the host did it"

    def test_the_status_the_host_reports_is_kept_beside_the_entry(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.helper_state["last_error"] = "kea-dhcp4 -t refused the restored config"
        inv.sweep(now=NOW)
        (row,) = inv.active()
        assert "refused the restored config" in row["host_error"] and row["armed"]
        kea.helper_state["last_error"] = None
        inv.sweep(now=NOW)
        assert inv.active()[0]["host_error"] == ""

    def test_a_host_that_does_not_answer_is_said_not_assumed_fine(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.host_down = True
        inv.sweep(now=NOW)
        (row,) = inv.active()
        assert "could not be read" in row["host_error"]
        from jen.services import health

        check = health._debug_logging_left_on({})
        assert check.status == "warn" and "could not be read" in check.detail

    def test_an_entry_the_host_has_no_state_for_is_armed_again_while_there_is_time(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.helper_state = None  # a person removed the host's state file
        inv.sweep(now=NOW)
        assert kea.helper_state is not None and inv.active()[0]["armed"]
        assert ed._parse_until(kea.helper_state["until"]) == ed._parse_until(inv.active()[0]["until"])

    def test_an_entry_on_a_host_whose_helper_is_too_old_says_so_and_stays_unarmed(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.build = 14
        inv.sweep(now=NOW)
        (row,) = inv.active()
        assert row["armed"] is False and "build 17" in row["host_error"]

    def test_a_legacy_entry_is_armed_by_the_first_sweep_after_the_upgrade(self, world, monkeypatch):
        kea = world.daemons[1]
        real = inv._arm_host
        monkeypatch.setattr(inv, "_arm_host", lambda server, entry, until: (True, [], False, None))
        assert inv.turn_on(world.servers[0], 15)["ok"]  # an entry as beta.28 wrote it: no host state behind it
        monkeypatch.setattr(inv, "_arm_host", real)
        assert kea.helper_state is None and not inv.active()[0]["armed"]
        inv.sweep(now=NOW)
        assert kea.helper_state is not None and inv.active()[0]["armed"]


class TestTheByHandTextsAreOneCommandForAnArmedEntry:
    COMMAND = "sudo jen-kea-helper --self-restore --now"

    def test_every_by_hand_text_names_the_host_command(self, world):
        inv.turn_on(world.servers[0], 15)
        (row,) = inv.active()
        for text in (inv.by_hand(row), inv.by_hand_daemon(row), inv.by_hand_damaged(row), inv.by_hand_running(row)):
            assert self.COMMAND in text and "10.0.0.1" in text

    def test_an_entry_from_before_build_15_keeps_the_hand_edit(self, world, monkeypatch):
        monkeypatch.setattr(inv, "_arm_host", lambda server, entry, until: (True, [], False, None))
        inv.turn_on(world.servers[0], 15)
        (row,) = inv.active()
        assert self.COMMAND not in inv.by_hand(row) and "jen-investigation" in inv.by_hand(row)

    def test_a_stuck_armed_entry_is_told_the_command_on_the_health_row(self, world):
        from jen.services import health

        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.host_restore_fails = True
        kea.reload_ignored = kea.restart_ignored = True
        kea.restart_ok = False
        inv.turn_off(world.servers[0])
        row = inv.active()[0]
        if row["needs_hand"]:
            assert self.COMMAND in health._debug_logging_left_on({}).detail


class TestAMarkerThatIsNotTheRecordedOneIsRefused:
    def _on(self, world):
        assert inv.turn_on(world.servers[0], 15)["ok"]
        return world.daemons[1], world.servers[0]

    def test_a_candidate_with_the_same_marker_is_let_through(self, world):
        kea, server = self._on(world)
        candidate = copy.deepcopy(kea.file)
        candidate["Dhcp4"]["subnet4"] = [{"id": 5, "subnet": "10.5.0.0/24"}]
        assert inv.file_write_refusal(server, candidate) == ""

    def test_a_different_restore_object_is_refused(self, world):
        kea, server = self._on(world)
        candidate = copy.deepcopy(kea.file)
        _logger(candidate)["user-context"]["jen-investigation"]["restore"] = {"severity": "WARN", "debuglevel": 0}
        text = inv.file_write_refusal(server, candidate)
        assert "restore object" in text and "Turn it off from Servers first" in text
        assert [a[0] for a in world.store["_audit"]][-1] == "INVESTIGATION_LOGGING_FILE_WRITE_REFUSED"

    def test_a_different_deadline_is_refused(self, world):
        kea, server = self._on(world)
        candidate = copy.deepcopy(kea.file)
        _logger(candidate)["user-context"]["jen-investigation"]["until"] = (NOW + timedelta(hours=3)).isoformat(
            timespec="seconds"
        )
        assert "deadline" in inv.file_write_refusal(server, candidate)

    def test_a_revision_recorded_in_an_earlier_session_is_exactly_this_case(self, world):
        kea, server = self._on(world)
        old, _ = ed.set_investigation_logging(
            _cfg([{"name": "kea-dhcp4", "severity": "WARN", "debuglevel": 0}]), (NOW - timedelta(days=1)).isoformat()
        )
        assert inv.file_write_refusal(server, old)

    def test_the_same_kea_under_another_server_number_is_protected_too(self, world):
        """Found by the walk: a server removed by hand and another pointed at the same Kea writes to the file that carries the marker with no entry under ITS id."""
        kea, _server = self._on(world)
        other_id = {"id": 9, "name": "kea-x", "ssh_host": "10.0.0.1"}
        candidate, _ = ed.clear_investigation_logging(copy.deepcopy(kea.file))
        assert "would remove the marker" in inv.file_write_refusal(other_id, candidate)
        elsewhere = {"id": 9, "name": "kea-y", "ssh_host": "10.0.0.2"}
        assert inv.file_write_refusal(elsewhere, candidate) == ""


class TestTheWrappersAroundTheHelperOps:
    """`kea_host.investigation_arm / _disarm / _status`: the payload each op is sent and how each answer is normalised (there is no legacy engine for these)."""

    @pytest.fixture
    def wire(self, monkeypatch):
        from jen.services import kea_host

        sent = []
        replies = []

        def helper_call(server, op, payload=None, timeout=60):
            sent.append((op, payload))
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        monkeypatch.setattr(kea_host, "helper_call", helper_call)
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda server: None)
        monkeypatch.setattr(kea_host, "_conf_path", lambda server, service: "/etc/kea/kea-dhcp4.conf")
        return kea_host, sent, replies

    SERVER = {"id": 4, "name": "kea-d", "ssh_host": "10.0.0.4"}

    def test_arm_sends_the_service_the_path_the_deadline_the_restore_object_and_who(self, wire):
        host, sent, replies = wire
        replies.append({"ok": True, "timer": "systemd", "until": "2026-10-10T12:15:00+00:00"})
        out = host.investigation_arm(
            self.SERVER, "2026-10-10T12:15:00+00:00", {"created": True}, {"server_id": "4", "name": "kea-d"}
        )
        assert sent == [
            (
                "investigation-arm",
                {
                    "service": "dhcp4",
                    "path": "/etc/kea/kea-dhcp4.conf",
                    "until": "2026-10-10T12:15:00+00:00",
                    "restore": {"created": True},
                    "jen": {"server_id": "4", "name": "kea-d"},
                    "log_path": "",
                },
            )
        ]
        assert out["ok"] and out["code"] == "ok" and out["timer"] == "systemd"

    def test_an_arm_that_does_not_report_a_timer_reads_as_none(self, wire):
        host, _sent, replies = wire
        replies.append({"ok": True})
        assert host.investigation_arm(self.SERVER, "2026-10-10T12:15:00+00:00", {"created": True})["timer"] == "none"

    def test_a_helper_older_than_build_15_is_named(self, wire):
        host, _sent, replies = wire
        replies.append({"ok": False, "error": "unknown-op"})
        out = host.investigation_status(self.SERVER)
        assert not out["ok"] and out["code"] == "old" and "build 17" in out["detail"]

    def test_a_missing_helper_and_a_transport_error_are_told_apart(self, wire):
        host, _sent, replies = wire
        replies += [host.HelperMissing("sudo: command not found"), host.HelperUnreachable("ssh: no route")]
        assert host.investigation_disarm(self.SERVER)["code"] == "missing"
        assert host.investigation_disarm(self.SERVER) == {"ok": False, "code": "error", "detail": "ssh: no route"}

    def test_the_helpers_own_refusal_keeps_its_detail(self, wire):
        host, sent, replies = wire
        replies.append({"ok": False, "error": "restore-failed", "detail": "kea-dhcp4 -t refused"})
        out = host.investigation_disarm(self.SERVER)
        assert out == {"ok": False, "code": "error", "detail": "kea-dhcp4 -t refused"}
        assert sent == [("investigation-disarm", {"service": "dhcp4", "path": "/etc/kea/kea-dhcp4.conf"})]

    def test_an_arm_the_host_refuses_because_it_holds_another_session_keeps_the_record(self, wire):
        host, _sent, replies = wire
        record = {
            "until": "2026-10-10T12:30:00+00:00",
            "restore": {"created": True},
            "armed_at": "2026-10-10T12:00:00+00:00",
        }
        replies.append({"ok": False, "error": "armed", "existing": record})
        out = host.investigation_arm(
            self.SERVER,
            "2026-10-10T12:15:00+00:00",
            {"severity": "INFO", "debuglevel": 0},
            None,
            "/var/log/kea/kea-dhcp4.log",
        )
        assert out["ok"] is False and out["code"] == "armed" and out["existing"] == record

    def test_a_state_file_the_host_cannot_trust_is_its_own_code_never_no_session(self, wire):
        """build 17 (Q168, INV-009): the helper's `bad-state` keeps its sentence and the file's path; it is not `error` and it is certainly not an unarmed host."""
        host, _sent, replies = wire
        replies.append(
            {
                "ok": False,
                "error": "bad-state",
                "armed": None,
                "detail": "the state file cannot be trusted",
                "state_file": "/var/lib/jen-kea-helper/x.json",
            }
        )
        out = host.investigation_status(self.SERVER)
        assert out == {
            "ok": False,
            "code": "bad-state",
            "detail": "the state file cannot be trusted",
            "state_file": "/var/lib/jen-kea-helper/x.json",
        }
        replies.append({"ok": False, "error": "bad-state"})
        out = host.investigation_disarm(self.SERVER)
        assert out["code"] == "bad-state" and out["detail"] and out["state_file"] == ""

    def test_the_timer_wrapper_sends_ensure_and_reads_none_when_the_host_does_not_say(self, wire):
        host, sent, replies = wire
        replies.append({"ok": True})
        out = host.investigation_timer(self.SERVER)
        assert sent == [("investigation-timer", {"action": "ensure"})] and out["ok"] and out["timer"] == "none"

    def test_the_minimum_build_is_the_one_the_helper_ships(self):
        from jen.services import kea_host

        assert kea_host.INVESTIGATION_MIN_HELPER_BUILD == 17 == kea_host.JEN_HELPER_SHIPPED_BUILD


class TestTheElevenRowsOfTheCandidateMarker:
    """v5.68.0-beta.30 (Q167, INV-002/INV-005): what the Kea-file guard does with the marker in a candidate config, row by row. Beta.29 let a MALFORMED marker through as 'carried' over a
    file whose entry recorded a valid restore - the one write that damages the record of what to put back."""

    def _on(self, world):
        assert inv.turn_on(world.servers[0], 15)["ok"]
        return world.daemons[1], world.servers[0]

    def _candidate(self, kea, value="@same"):
        candidate = copy.deepcopy(kea.file)
        context = _logger(candidate)["user-context"]
        if value is None:
            del context["jen-investigation"]
        elif value != "@same":
            context["jen-investigation"] = value
        return candidate

    def _mark_the_entry_invalid(self, world, text=None):
        import json

        record = json.loads(world.store[inv.RECORD_KEY])
        record["servers"]["1"]["marker_invalid"] = True
        if text is not None:
            record["servers"]["1"]["damaged_marker"] = text
        world.store[inv.RECORD_KEY] = json.dumps(record)

    def test_row_1_no_marker_is_refused(self, world):
        kea, server = self._on(world)
        assert "would remove the marker" in inv.file_write_refusal(server, self._candidate(kea, None))

    def test_row_2_the_same_valid_marker_is_allowed(self, world):
        kea, server = self._on(world)
        assert inv.file_write_refusal(server, self._candidate(kea)) == ""

    def test_row_3_a_different_restore_is_refused(self, world):
        kea, server = self._on(world)
        marker = dict(ed.investigation_marker(kea.file), restore={"severity": "WARN", "debuglevel": 0})
        assert "restore object" in inv.file_write_refusal(server, self._candidate(kea, marker))

    def test_row_4_a_different_deadline_is_refused(self, world):
        kea, server = self._on(world)
        marker = dict(ed.investigation_marker(kea.file), until=(NOW + timedelta(hours=5)).isoformat(timespec="seconds"))
        assert "deadline" in inv.file_write_refusal(server, self._candidate(kea, marker))

    @pytest.mark.parametrize(
        "row,restore",
        [
            ("row_5_an_empty_restore_object", {}),
            ("row_6_a_restore_that_is_a_string", "WARN"),
            ("row_7_a_restore_that_is_a_list", [{"severity": "WARN"}]),
        ],
    )
    def test_rows_5_to_7_a_malformed_restore_is_refused(self, world, row, restore):
        kea, server = self._on(world)
        marker = dict(ed.investigation_marker(kea.file), restore=restore)
        refusal = inv.file_write_refusal(server, self._candidate(kea, marker))
        assert "is malformed" in refusal and "damage the record of what to put back" in refusal, row
        assert [a[0] for a in world.store["_audit"]][-1] == "INVESTIGATION_LOGGING_FILE_WRITE_REFUSED"

    def test_row_8_a_marker_that_is_not_an_object_is_refused(self, world):
        kea, server = self._on(world)
        assert "is malformed" in inv.file_write_refusal(
            server, self._candidate(kea, "a string where an object belongs")
        )

    def test_row_9_a_marker_with_no_restore_at_all_is_refused(self, world):
        kea, server = self._on(world)
        marker = {"until": ed.investigation_marker(kea.file)["until"]}
        assert "is malformed" in inv.file_write_refusal(server, self._candidate(kea, marker))

    def test_row_10_an_entry_that_recorded_its_damage_lets_only_that_exact_marker_through(self, world):
        import json

        kea, server = self._on(world)
        damaged = {"until": ed.investigation_marker(kea.file)["until"], "restore": {}}
        self._mark_the_entry_invalid(world, json.dumps(damaged, sort_keys=True))
        assert inv.file_write_refusal(server, self._candidate(kea, damaged)) == ""
        assert "differs from the damaged marker" in inv.file_write_refusal(
            server, self._candidate(kea, dict(damaged, restore="x"))
        )

    def test_row_11_an_entry_that_never_recorded_its_damage_lets_no_malformed_marker_through(self, world):
        kea, server = self._on(world)
        self._mark_the_entry_invalid(world)
        damaged = {"until": ed.investigation_marker(kea.file)["until"], "restore": {}}
        assert "did not record" in inv.file_write_refusal(server, self._candidate(kea, damaged))

    def test_a_valid_marker_over_a_damaged_entry_is_the_repair_and_is_allowed(self, world):
        kea, server = self._on(world)
        self._mark_the_entry_invalid(world, "{}")
        assert inv.file_write_refusal(server, self._candidate(kea)) == ""

    def test_the_damage_is_recorded_when_the_marker_is_found_damaged(self, world):
        import json

        kea, server = self._on(world)
        damaged = {"until": ed.investigation_marker(kea.file)["until"], "restore": {}}
        _logger(kea.file)["user-context"]["jen-investigation"] = damaged
        inv.sweep(now=NOW, full=True)
        entry = json.loads(world.store[inv.RECORD_KEY])["servers"]["1"]
        assert entry["marker_invalid"] is True and entry["damaged_marker"] == json.dumps(damaged, sort_keys=True)


class TestAnUnresolvedSessionOnTheHostIsNeverOverwritten:
    """v5.68.0-beta.30 (Q167, INV-008): the host's record is authoritative; Jen shows a session it does not recognise, refuses to turn logging on over it, and never arms over it."""

    OTHER = {"severity": "WARN", "debuglevel": 0}

    def _foreign_session(self, kea):
        kea.helper_state = {
            "until": (NOW + timedelta(minutes=30)).isoformat(timespec="seconds"),
            "restore": dict(self.OTHER),
            "restored_at": None,
            "how": None,
            "last_error": None,
            "restarts": 0,
            "attempts": 0,
            "needs_hand": False,
            "log_path": "/var/log/kea/kea-dhcp4.log",
            "armed_at": NOW.isoformat(timespec="seconds"),
            "jen": {"server_id": "9", "name": "another jen"},
        }

    def test_turn_on_refuses_before_writing_when_the_host_holds_a_session_it_is_not_this_ones(self, world):
        kea = world.daemons[1]
        self._foreign_session(kea)
        original = copy.deepcopy(kea.file)
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "does not recognise" in out["lines"][0] and "--self-restore --now" in out["lines"][0]
        assert kea.file == original and kea.writes == 0 and "host:arm" not in kea.calls and not inv.active()

    def test_an_arm_the_host_refuses_after_the_gate_reverts_the_file_and_says_why(self, world, monkeypatch):
        """The race the gate cannot close: the session appears between the status read and the arm."""
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        monkeypatch.setattr(
            inv._host, "investigation_status", lambda server: {"ok": True, "code": "ok", "armed": False}
        )
        self._foreign_session(kea)
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and any("does not recognise" in line for line in out["lines"]), out["lines"]
        assert kea.file == original and not inv.active()
        assert kea.helper_state["restore"] == self.OTHER, "the host's record was not touched"

    def test_the_sweep_records_a_session_that_replaced_this_entrys_and_health_fails(self, world):
        from jen.services import health

        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        self._foreign_session(kea)  # a second Jen, or an older backup of this one, armed over it
        inv.sweep(now=NOW)
        (row,) = inv.active()
        assert row["host_conflict"] and row["host_conflict"]["restore"] == self.OTHER and row["armed"] is False
        check = health._debug_logging_left_on({})
        assert check.status == "fail" and "does not recognise" in check.detail and "kea-a" in check.detail
        assert kea.helper_state["restore"] == self.OTHER, "Jen never re-armed over it"

    def test_an_extension_of_this_entrys_own_session_is_not_a_conflict(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        assert inv.turn_on(world.servers[0], 15)["ok"]
        assert inv.active()[0]["host_conflict"] is None and "extended" not in str(kea.helper_state.get("last_error"))

    def test_a_restored_session_on_the_host_is_not_a_conflict(self, world):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 5)
        assert inv.turn_off(world.servers[0])["ok"]
        assert kea.helper_state["restored_at"]
        assert inv.turn_on(world.servers[0], 5)["ok"], "the host's record is resolved: a new session is armed"

    def test_when_the_host_could_not_restore_and_jen_did_the_host_is_settled_too(self, world, monkeypatch):
        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 5)
        real, calls = kea.host_restore, []

        def fails_once():
            calls.append(1)
            return (False, None, "kea-dhcp4 -t refused the restored config") if len(calls) == 1 else real()

        monkeypatch.setattr(kea, "host_restore", fails_once)
        assert inv.turn_off(world.servers[0])["ok"], "Jen's own file-writing path finished it"
        assert kea.helper_state["restored_at"], "and the host was asked once more, so its record is resolved"
        assert inv.turn_on(world.servers[0], 5)["ok"], "a new session is not blocked by the old record"


class TestAStateFileTheHostCannotReadIsAConflictNotNoSession:
    """v5.68.0-beta.31 (Q168, INV-009): a host whose state file exists and cannot be read answers `bad-state` to status and disarm and `armed`/unreadable to an arm. Jen shows it as an
    unreadable conflict (Health fails, turning logging on is refused with the same sentence) and still restores at the deadline by its own path."""

    def test_turn_on_is_refused_before_anything_is_written(self, world):
        kea = world.daemons[1]
        kea.state_bad = True
        original = copy.deepcopy(kea.file)
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "cannot read" in out["lines"][0] and "Nothing was changed" in out["lines"][0]
        assert kea.file == original and kea.writes == 0 and "host:arm" not in kea.calls and not inv.active()

    def test_the_sweep_shows_it_as_an_unreadable_conflict_and_health_fails(self, world):
        from jen.services import health

        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 15)["ok"]
        kea.state_bad = True
        inv.sweep(now=NOW)
        (row,) = inv.active()
        assert (
            row["host_conflict"]["unreadable"] is True and row["armed"] is False and "cannot read" in row["host_error"]
        )
        check = health._debug_logging_left_on({})
        assert check.status == "fail" and "kea-a" in check.detail

    def test_a_disarm_that_answers_bad_state_takes_jens_own_path(self, world):
        """The host cannot restore (its record is unusable): Jen's own file-writing path finishes the restore and says why it did not use the host's."""
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.state_bad = True
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and not _at_debug(kea.file) and not _at_debug(kea.loaded), out["lines"]

    def test_a_sweep_past_the_deadline_restores_it_when_the_hosts_tick_cannot(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.state_bad = True
        assert kea.host_tick() is None or kea.host_tick()[0] is False
        inv.sweep(now=NOW + timedelta(minutes=6))
        assert not inv.active() and not _at_debug(kea.loaded)


class TestTheRestorationTimersLiveness:
    def test_a_stopped_timer_is_started_again_and_the_row_warns_then_clears(self, world):
        from jen.services import health

        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.timer_running = False
        inv.sweep(now=NOW)
        assert "host:timer" in kea.calls and kea.timer_running is True
        (row,) = inv.active()
        assert row["timer_down"] == 1
        check = health._debug_logging_left_on({})
        assert check.status == "warn" and "restoration timer is not running" in check.detail
        inv.sweep(now=NOW)
        assert inv.active()[0]["timer_down"] == 0
        assert health._debug_logging_left_on({}).status == "ok"

    def test_a_timer_that_stays_down_for_three_sweeps_fails_health(self, world):
        from jen.services import health

        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.timer = "none"  # the host cannot run a timer any more (systemd gone, the unit masked)
        kea.timer_running = False
        statuses = []
        for _ in range(3):
            inv.sweep(now=NOW)
            statuses.append(health._debug_logging_left_on({}).status)
        assert statuses == ["warn", "warn", "fail"]
        assert "restoration timer has not been running for 3 sweeps" in health._debug_logging_left_on({}).detail

    def test_a_host_that_says_a_person_has_to_act_fails_health_with_the_command(self, world):
        from jen.services import health

        kea = world.daemons[1]
        inv.turn_on(world.servers[0], 15)
        kea.helper_state.update(
            needs_hand=True, last_error="Kea refused the restored config: DHCP4_CONFIG_LOAD_FAIL", attempts=10
        )
        inv.sweep(now=NOW)
        check = health._debug_logging_left_on({})
        assert (
            check.status == "fail"
            and "--self-restore --now" in check.detail
            and "could not confirm its restore" in check.detail
        )


class TestInvestigationLoggingIsOptIn:
    """v5.68.0-beta.30 (Q167): early access, off by default. The switch gates ONLY turning on; a session that exists is always restored and shown."""

    def _switch(self, world, value):
        if value is None:
            world.store.pop(inv.ENABLED_KEY, None)
        else:
            world.store[inv.ENABLED_KEY] = value

    @pytest.mark.parametrize("value", [None, "false", "", "no", "0", "TRUE-ish"])
    def test_off_means_turn_on_is_refused_and_nothing_is_touched(self, world, value):
        self._switch(world, value)
        kea = world.daemons[1]
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "not switched on" in out["lines"][0] and "early access" in out["lines"][0]
        assert kea.writes == 0 and kea.calls == [] and not inv.active()

    @pytest.mark.parametrize("value", ["true", "True", " true "])
    def test_on_means_everything_as_before(self, world, value):
        self._switch(world, value)
        assert inv.enabled() is True
        assert inv.turn_on(world.servers[0], 5)["ok"]

    def test_an_unreadable_settings_table_reads_as_off(self, world):
        world.db["unavailable"] = True
        assert inv.enabled() is False

    def test_switching_it_off_never_strands_a_session_that_is_on(self, world, monkeypatch):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        assert inv.turn_on(world.servers[0], 5)["ok"]
        self._switch(world, "false")
        assert len(inv.active()) == 1, "still shown"
        from jen.services import health

        assert health._debug_logging_left_on({}).status == "ok"
        monkeypatch.setattr(inv, "_now", lambda: NOW + timedelta(minutes=6))
        assert kea.host_tick()[0] is True
        assert inv.sweep(now=NOW + timedelta(minutes=6))["restored"] == ["kea-a"], "still swept"
        assert kea.file == original and not inv.active()

    def test_switching_it_off_never_blocks_turn_off_forget_or_acknowledge(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        self._switch(world, "false")
        assert inv.turn_off(world.servers[0])["ok"], "turn off is never gated"
        assert (
            inv.forget(1) is False and inv.acknowledge_damaged("alice", all_subnets=True) is False
        )  # refused for their own reasons, not for the switch

    def test_only_turn_on_asks_the_switch_in_the_service(self):
        """Self-check (e): `enabled()` is read by `turn_on` and by nothing that restores, shows or forgets."""
        import ast
        import pathlib

        tree = ast.parse(pathlib.Path(inv.__file__).read_text(encoding="utf-8"))
        readers = {
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "enabled"
                for n in ast.walk(node)
            )
        }
        assert readers == {"turn_on"}, readers

    def test_the_three_surfaces_the_route_and_the_toggle_are_the_only_other_readers(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        hits = {}
        for path in [*(root / "jen").rglob("*.py"), *(root / "templates").glob("*.html")]:
            text = path.read_text(encoding="utf-8")
            if (
                "investigation_logging_enabled" in text
                or "inv.enabled(" in text
                or "__inv.enabled(" in text
                or "ENABLED_KEY" in text
            ):
                hits[path.relative_to(root).as_posix()] = True
        assert set(hits) == {
            "jen/__init__.py",
            "jen/routes/servers.py",
            "jen/routes/settings/infrastructure.py",
            "jen/services/investigation_logging.py",
            "templates/_investigation_logging.html",
            "templates/servers.html",
            "templates/settings_kea.html",
            "templates/trace.html",
        }, sorted(hits)

    def _render(self, enabled, entry):
        import pathlib

        import jinja2

        root = pathlib.Path(__file__).resolve().parent.parent
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(root / "templates")), undefined=jinja2.StrictUndefined, autoescape=True
        )
        env.globals.update(icon=lambda *a, **k: "", csrf_token=lambda: "t")
        template = env.from_string(
            "{% from '_investigation_logging.html' import investigation_controls with context %}{{ investigation_controls(server, entry, 'servers') }}"
        )
        return template.render(server={"id": 1, "name": "kea-a"}, entry=entry, investigation_logging_enabled=enabled)

    def test_the_buttons_exist_only_when_it_is_on_and_a_running_session_always_shows_its_off_button(self):
        entry = {"until": "2099-01-01T00:00:00+00:00", "remaining_s": 300, "armed": True}
        assert self._render(False, None).strip() == ""
        assert "investigation-logging/on" not in self._render(False, entry)
        assert "investigation-logging/off" in self._render(False, entry), (
            "a session that is on can always be turned off"
        )
        on = self._render(True, None)
        assert on.count("investigation-logging/on") == 3 and "investigation-logging/off" not in on
