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
        assert "build 15 or later" in out["lines"][0] and "Update helper" in out["lines"][0]
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
        assert row["armed"] is False and "build 15" in row["host_error"]

    def test_a_legacy_entry_is_armed_by_the_first_sweep_after_the_upgrade(self, world, monkeypatch):
        kea = world.daemons[1]
        real = inv._arm_host
        monkeypatch.setattr(inv, "_arm_host", lambda server, entry, until: (True, [], False))
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
        monkeypatch.setattr(inv, "_arm_host", lambda server, entry, until: (True, [], False))
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

    def test_a_marker_that_is_damaged_is_not_compared(self, world):
        kea, server = self._on(world)
        candidate = copy.deepcopy(kea.file)
        del _logger(candidate)["user-context"]["jen-investigation"]["restore"]
        assert inv.file_write_refusal(server, candidate) == ""

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
        assert not out["ok"] and out["code"] == "old" and "build 15" in out["detail"]

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

    def test_the_minimum_build_is_the_one_the_helper_ships(self):
        from jen.services import kea_host

        assert kea_host.INVESTIGATION_MIN_HELPER_BUILD == 15 == kea_host.JEN_HELPER_SHIPPED_BUILD
