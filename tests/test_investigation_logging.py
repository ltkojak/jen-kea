"""
tests/test_investigation_logging.py
───────────────────────────────────
v5.68.0-beta.3 (Q138) — investigation logging on demand: the pure loggers mutation (jen.services.kea_config_edit), the service that
applies it to ONE server (reload when the daemon has `config-reload`, restart otherwise), the every-minute sweep, and the Health row.
No database and no Kea: the change set and the daemon are replaced by an in-memory server, settings by a dict.
`pytest --noconftest tests/test_investigation_logging.py`.
"""

import copy
from datetime import timedelta

import pytest

from jen.services import investigation_logging as inv
from jen.services import kea_config_edit as ed
from tests._investigation_world import FUTURE, NOW, PAST, FakeKea, _cfg

# the `world` fixture (and the fake Kea it builds) lives in tests/_investigation_world.py, shared with the other files that drive the service
pytest_plugins = ("tests._investigation_world",)


def _entry(cfg):
    return next(x for x in cfg["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")


class TestSetAndClear:
    def test_a_config_with_no_loggers_gets_an_entry_and_loses_it_again(self):
        original = _cfg()
        on, code = ed.set_investigation_logging(original, FUTURE)
        assert code == "ok" and "loggers" not in original["Dhcp4"], "the caller's dict is never touched"
        entry = _entry(on)
        assert entry["severity"] == "DEBUG" and entry["debuglevel"] == 55
        assert entry["user-context"]["jen-investigation"] == {"until": FUTURE, "restore": {"created": True}}
        assert "output-options" not in entry, "a created entry inherits Kea's default output"
        off, code = ed.clear_investigation_logging(on)
        assert code == "ok" and off == {"Dhcp4": {"valid-lifetime": 3600, "subnet4": [], "loggers": []}}

    def test_an_existing_entry_keeps_its_output_options_and_gets_its_old_level_back_exactly(self):
        outputs = [{"output": "/var/log/kea/kea-dhcp4.log", "maxsize": 2048000, "maxver": 4, "flush": True}]
        original = _cfg(
            [
                {"name": "kea-dhcp4", "output-options": outputs, "severity": "WARN", "debuglevel": 0},
                {"name": "kea-dhcp4.hosts", "severity": "INFO"},
            ]
        )
        on, _ = ed.set_investigation_logging(original, FUTURE)
        entry = _entry(on)
        assert entry["output-options"] == outputs and (entry["severity"], entry["debuglevel"]) == ("DEBUG", 55)
        assert entry["user-context"]["jen-investigation"]["restore"] == {"severity": "WARN", "debuglevel": 0}
        assert on["Dhcp4"]["loggers"][1] == original["Dhcp4"]["loggers"][1], "another logger entry is not touched"
        off, code = ed.clear_investigation_logging(on)
        assert code == "ok" and off == original

    def test_absent_severity_and_debuglevel_are_removed_again_not_set_to_defaults(self):
        original = _cfg([{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}]}])
        on, _ = ed.set_investigation_logging(original, FUTURE)
        assert on["Dhcp4"]["loggers"][0]["user-context"]["jen-investigation"]["restore"] == {
            "severity": "absent",
            "debuglevel": "absent",
        }
        assert ed.clear_investigation_logging(on)[0] == original

    def test_setting_again_only_moves_the_deadline_and_never_makes_debug_the_thing_to_restore(self):
        original = _cfg([{"name": "kea-dhcp4", "severity": "INFO"}])
        once, _ = ed.set_investigation_logging(original, FUTURE)
        later = (NOW + timedelta(minutes=30)).isoformat()
        twice, code = ed.set_investigation_logging(once, later)
        assert code == "ok"
        marker = _entry(twice)["user-context"]["jen-investigation"]
        assert marker == {"until": later, "restore": {"severity": "INFO", "debuglevel": "absent"}}
        assert ed.clear_investigation_logging(twice)[0] == original
        assert ed.set_investigation_logging(once, FUTURE)[0] == once, "idempotent for the same deadline"

    def test_other_user_context_keys_survive_both_ways(self):
        original = _cfg([{"name": "kea-dhcp4", "severity": "INFO", "user-context": {"owner": "netops"}}])
        on, _ = ed.set_investigation_logging(original, FUTURE)
        assert _entry(on)["user-context"]["owner"] == "netops"
        assert ed.clear_investigation_logging(on)[0] == original

    def test_the_sweep_rule_restores_only_what_is_due(self):
        on, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4", "severity": "INFO"}]), FUTURE)
        assert ed.clear_investigation_logging(on, now=NOW) == (on, "nochange"), "ten minutes left: not due"
        expired, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4", "severity": "INFO"}]), PAST)
        restored, code = ed.clear_investigation_logging(expired, now=NOW)
        assert code == "ok" and _entry(restored) == {"name": "kea-dhcp4", "severity": "INFO"}

    def test_an_unreadable_deadline_counts_as_passed(self):
        on, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4"}]), "not a date")
        assert ed.clear_investigation_logging(on, now=NOW)[1] == "ok"

    def test_a_naive_deadline_is_read_as_utc(self):
        naive = (NOW + timedelta(minutes=5)).replace(tzinfo=None).isoformat()
        on, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4"}]), naive)
        assert ed.clear_investigation_logging(on, now=NOW)[1] == "nochange"

    def test_nothing_marked_is_nothing_to_do(self):
        cfg = _cfg([{"name": "kea-dhcp4", "severity": "INFO"}])
        assert ed.clear_investigation_logging(cfg) == (cfg, "nochange")
        assert ed.clear_investigation_logging(_cfg()) == (_cfg(), "nochange")
        assert ed.investigation_marker(cfg) is None

    @pytest.mark.parametrize(
        "cfg",
        [
            {},
            {"Dhcp4": None},
            {"Dhcp4": {"loggers": "nope"}},
            {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "user-context": 3}]}},
        ],
    )
    def test_shapes_Kea_does_not_document_are_unsupported_not_guessed(self, cfg):
        assert ed.set_investigation_logging(cfg, FUTURE)[1] == "unsupported"
        assert ed.clear_investigation_logging(cfg)[1] == "nochange"

    def test_the_marker_reader(self):
        on, _ = ed.set_investigation_logging(_cfg(), FUTURE)
        assert ed.investigation_marker(on) == {"until": FUTURE, "restore": {"created": True}}


# ── the service: one fake Kea host, an in-memory settings table, a fake daemon ────────────────────────


class TestTurnOn:
    def test_it_writes_without_a_restart_and_reloads_when_the_daemon_has_config_reload(self, world):
        out = inv.turn_on(world.servers[0], 15, actor="alice")
        assert (
            out["ok"]
            and out["mode"] == "reload"
            and out["until"] == (NOW + timedelta(minutes=15)).isoformat(timespec="seconds")
        )
        calls = world.daemons[1].calls
        assert "apply(restart=False):investigation logging on for 15 min" in calls and "config-reload" in calls
        assert not any(c.startswith("restart") for c in calls)
        assert _entry(world.daemons[1].file)["debuglevel"] == 55
        (entry,) = inv.active()
        assert (
            entry["name"] == "kea-a"
            and entry["by"] == "alice"
            and entry["remaining_s"] == 900
            and entry["mode"] == "reload"
        )
        assert [a[0] for a in world.store["_audit"]] == ["INVESTIGATION_LOGGING_ON"]

    def test_a_daemon_without_config_reload_is_restarted_and_the_result_says_so(self, world):
        world.daemons[1].commands = ["version-get"]
        out = inv.turn_on(world.servers[0], 5)
        assert (
            out["ok"]
            and out["mode"] == "restart"
            and "apply(restart=True):investigation logging on for 5 min" in world.daemons[1].calls
        )
        assert any("restarted" in line for line in out["lines"])

    def test_a_refused_reload_puts_the_file_back_and_never_restarts_kea(self, world):
        """beta.22 (Q157): beta.21 refused when list-commands was silent and then RESTARTED Kea when the next call to the same API - config-reload -
        failed. A reload that does not return 0 is a refusal, a connection failure or a timeout (the same shape) and turning logging on never restarts."""
        original = copy.deepcopy(world.daemons[1].file)
        world.daemons[1].reload_result = 1
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and out["until"] == "" and world.daemons[1].file == original and not inv.active()
        assert not any(c.startswith("restart") for c in world.daemons[1].calls), world.daemons[1].calls
        assert any("did not confirm the reload" in line and "nothing was restarted" in line for line in out["lines"]), (
            out["lines"]
        )
        assert "_audit" not in world.store

    def test_only_the_three_durations_exist(self, world):
        out = inv.turn_on(world.servers[0], 7)
        assert not out["ok"] and world.daemons[1].writes == 0

    def test_one_server_at_a_time(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        refused = inv.turn_on(world.servers[1], 5)
        assert not refused["ok"] and "already on for kea-a" in refused["lines"][0] and world.daemons[2].writes == 0
        assert inv.turn_on(world.servers[0], 15)["ok"], "the same server may be extended"
        assert len(inv.active()) == 1

    def test_a_config_it_cannot_change_is_an_error_not_an_entry(self, world):
        world.daemons[2].file = {"Dhcp4": {"loggers": "nope"}}
        out = inv.turn_on(world.servers[1], 5)
        assert not out["ok"] and "no Dhcp4 section" in out["lines"][0] and not inv.active()


class TestTurnOff:
    def test_it_puts_the_level_back_and_drops_the_entry(self, world):
        original = copy.deepcopy(world.daemons[1].file)
        inv.turn_on(world.servers[0], 15)
        out = inv.turn_off(world.servers[0], actor="alice")
        assert out["ok"] and world.daemons[1].file == original and not inv.active()
        assert [a[0] for a in world.store["_audit"]] == ["INVESTIGATION_LOGGING_ON", "INVESTIGATION_LOGGING_OFF"]

    def test_a_failed_restore_keeps_the_entry_so_it_is_retried(self, world):
        inv.turn_on(world.servers[0], 15)
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        out = inv.turn_off(world.servers[0])
        assert not out["ok"] and len(inv.active()) == 1


class TestSweep:
    def _on(self, world, minutes=5):
        assert inv.turn_on(world.servers[0], minutes)["ok"]

    def test_a_live_entry_is_left_alone(self, world, monkeypatch):
        self._on(world)
        writes = world.daemons[1].writes
        assert inv.sweep(now=NOW + timedelta(minutes=2)) == {"restored": [], "adopted": [], "errors": []}
        assert world.daemons[1].writes == writes and len(inv.active()) == 1

    def test_an_expired_entry_is_restored_and_dropped(self, world):
        original = copy.deepcopy(world.daemons[1].file)
        self._on(world)
        out = inv.sweep(now=NOW + timedelta(minutes=6))
        assert out["restored"] == ["kea-a"] and world.daemons[1].file == original and not inv.active()
        assert world.store["_audit"][-1][0] == "INVESTIGATION_LOGGING_OFF"

    def test_a_failed_restore_stays_indexed_with_its_error_and_turns_the_health_row_red(self, world):
        self._on(world)
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        late = NOW + timedelta(minutes=9)
        out = inv.sweep(now=late)
        assert out["restored"] == [] and out["errors"] and "kea-a" in out["errors"][0]
        (entry,) = inv.active(now=late)
        assert entry["error"] and entry["overdue"]
        # and the very next minute, with the daemon healthy again, it is put back
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 0, True
        assert inv.sweep(now=late + timedelta(minutes=1))["restored"] == ["kea-a"] and not inv.active()

    def test_the_cheap_path_never_reads_a_config(self, world, monkeypatch):
        reads = []
        monkeypatch.setattr(inv._host, "read_config_versioned", lambda *a: reads.append(a) or (None, ""))
        inv.sweep(now=NOW)
        assert reads == []

    def test_a_full_scan_restores_a_marker_nobody_indexed(self, world):
        stale, _ = ed.set_investigation_logging(world.daemons[2].file, PAST)
        world.daemons[2].file = stale
        out = inv.sweep(now=NOW, full=True)
        assert out["restored"] == ["kea-b"] and ed.investigation_marker(world.daemons[2].file) is None

    def test_a_full_scan_adopts_a_live_marker_so_the_banners_show_it(self, world):
        live, _ = ed.set_investigation_logging(world.daemons[2].file, FUTURE)
        world.daemons[2].file = live
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-b"] and [e["name"] for e in inv.active(NOW)] == ["kea-b"]
        assert ed.investigation_marker(world.daemons[2].file), "a live one is left on"

    def test_an_entry_for_a_server_that_was_removed_is_kept_and_marked(self, world):
        # v5.68.0-beta.9 (Q144): it used to be dropped as "nothing for Jen to restore" - the remote config kept DEBUG 55 forever
        self._on(world)
        world.servers.pop(0)
        inv.sweep(now=NOW)
        (entry,) = inv.active()
        assert entry["removed"]

    def test_an_unreadable_server_is_an_error_line_not_a_crash(self, world, monkeypatch):
        def boom(server, service):
            raise OSError("no route")

        monkeypatch.setattr(inv._host, "read_config_versioned", boom)
        out = inv.sweep(now=NOW, full=True)
        assert len(out["errors"]) == 2 and "OSError" in out["errors"][0]

    def test_the_job_scans_everything_on_its_first_run_and_then_every_tenth(self, world, monkeypatch):
        seen = []
        monkeypatch.setattr(inv, "sweep", lambda now=None, full=False: seen.append(full) or {})
        for _ in range(11):
            inv.run_sweep_job()
        assert seen == [True] + [False] * 9 + [True]


# ── v5.68.0-beta.9 (Q144): the state machine - a restore the daemon never took, an enable the daemon never took, a removed server ────


def _level(cfg):
    """(severity, debuglevel) of the kea-dhcp4 logger in `cfg`, or None when it has no such entry."""
    entry = next((x for x in (cfg.get("Dhcp4", {}).get("loggers") or []) if x.get("name") == "kea-dhcp4"), None)
    return (entry.get("severity"), entry.get("debuglevel")) if entry else None


def _daemon_at_debug(fake):
    return _level(fake.loaded) == ("DEBUG", 55)


class TestARestoreTheDaemonNeverTookIsNotForgotten:
    def _on(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        assert _daemon_at_debug(world.daemons[1])

    def test_two_failed_sweeps_keep_the_entry_and_the_third_finishes_the_job(self, world):
        self._on(world)
        kea = world.daemons[1]
        kea.reload_result, kea.restart_ok = 1, False
        for minute in (6, 7):
            out = inv.sweep(now=NOW + timedelta(minutes=minute))
            assert out["restored"] == [] and out["errors"], minute
            assert ed.investigation_marker(kea.file) is None, "the FILE was put back on the first try"
            assert _daemon_at_debug(kea), "and the daemon is still at DEBUG 55"
            (entry,) = inv.active(now=NOW + timedelta(minutes=minute))
            assert (entry["file"], entry["daemon"], entry["stuck"]) == ("restored", "debug", True)
        kea.reload_result, kea.restart_ok = 0, True
        calls_before = len(kea.calls)
        out = inv.sweep(now=NOW + timedelta(minutes=8))
        assert out["restored"] == ["kea-a"] and not inv.active()
        assert not _daemon_at_debug(kea), "the third sweep ran the reload that the 'nothing' change set used to skip"
        assert "config-reload" in kea.calls[calls_before:] and kea.writes == 2, (
            "no second write: the file was already clean"
        )

    def test_a_nothing_change_set_with_the_daemon_step_still_owed_runs_it(self, world):
        self._on(world)
        kea = world.daemons[1]
        clean, _ = ed.clear_investigation_logging(kea.file)
        kea.file = clean  # a person removed the marker from the file; the daemon never heard
        out = inv.turn_off(world.servers[0], actor="alice")
        assert out["ok"] and not _daemon_at_debug(kea) and not inv.active()

    def test_turn_off_with_nothing_marked_and_nothing_indexed_does_nothing(self, world):
        kea = world.daemons[1]
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and out["mode"] == "nothing" and "config-reload" not in kea.calls and not inv.active()

    def test_a_failed_restore_after_turn_off_is_retried_by_the_sweep_even_though_the_time_is_not_up(self, world):
        self._on(world)
        kea = world.daemons[1]
        kea.reload_result, kea.restart_ok = 1, False
        out = inv.turn_off(world.servers[0], actor="alice")
        assert not out["ok"] and len(inv.active()) == 1
        kea.reload_result, kea.restart_ok = 0, True
        swept = inv.sweep(now=NOW + timedelta(minutes=1))  # five-minute window: not expired
        assert swept["restored"] == ["kea-a"] and not inv.active() and not _daemon_at_debug(kea)

    def test_a_daemon_with_no_reload_is_restored_by_the_restart_inside_the_change_set(self, world):
        world.daemons[1].commands = ["version-get"]
        self._on(world)
        out = inv.sweep(now=NOW + timedelta(minutes=6))
        assert out["restored"] == ["kea-a"] and not _daemon_at_debug(world.daemons[1]) and not inv.active()


class TestTurnOnTakesResponsibilityBeforeTheDaemonIsAsked:
    def test_the_entry_is_saved_before_config_reload_is_sent(self, world):
        seen = []
        real = world.daemons[1].kea_command

        def spy(command, **kw):
            if command == "config-reload":
                seen.append([e["name"] for e in inv.active()])
            return real(command, **kw)

        world.daemons[1].kea_command = spy
        assert inv.turn_on(world.servers[0], 5)["ok"]
        assert seen == [["kea-a"]], "an entry already existed when the daemon was asked"

    def test_a_daemon_that_did_not_take_it_gets_the_file_put_straight_back(self, world):
        original = copy.deepcopy(world.daemons[1].file)
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and world.daemons[1].file == original and not inv.active()
        assert "did not confirm the reload" in out["lines"][-1] or any("did not confirm" in x for x in out["lines"])

    def test_when_even_the_revert_fails_the_entry_stays_and_the_sweep_finishes_it(self, world):
        kea = world.daemons[1]
        kea.reload_result, kea.restart_ok = 1, False
        kea.fail_writes_after = 1  # the on write works, the revert does not
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and ed.investigation_marker(kea.file), "the file still carries the marker"
        (entry,) = inv.active()
        assert entry["file"] == "debug" and entry["pending"] == "reload" and entry["error"]
        # a restart before expiry would activate DEBUG: the entry exists, so the banner and the Health row know
        kea.reload_result, kea.restart_ok, kea.fail_writes_after = 0, True, None
        assert inv.sweep(now=NOW + timedelta(minutes=6))["restored"] == ["kea-a"]
        assert not inv.active() and ed.investigation_marker(kea.file) is None and not _daemon_at_debug(kea)

    def test_a_restart_that_could_not_be_rolled_back_is_indexed_not_forgotten(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        kea.rollback_fails = True
        kea.restart_ok = False
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"]
        (entry,) = inv.active()
        assert entry["file"] == "debug" and entry["pending"] == "restart" and entry["error"]


class TestAServerRemovedFromJenKeepsItsEntry:
    def test_the_sweep_marks_the_entry_removed_and_audits_it_once(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers.pop(0)
        for _ in range(3):
            assert inv.sweep(now=NOW + timedelta(minutes=10)) == {"restored": [], "adopted": [], "errors": []}
        (entry,) = inv.active(NOW + timedelta(minutes=10))
        assert entry["removed"] and entry["name"] == "kea-a" and entry["ssh_host"] == "10.0.0.1"
        assert [a[0] for a in world.store["_audit"]].count("INVESTIGATION_LOGGING_ORPHANED") == 1

    def test_the_health_row_fails_naming_the_server_and_the_by_hand_restore(self, world):
        from jen.services import health

        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers.pop(0)
        inv.sweep(now=NOW)
        c = health._debug_logging_left_on({})
        assert c.status == "fail"
        assert "kea-a" in c.detail and "removed from Jen" in c.detail and "restore it by hand" in c.detail
        assert "10.0.0.1" in c.detail and "jen-investigation" in c.detail and "debuglevel" in c.detail

    def test_removal_is_refused_while_an_entry_exists_and_allowed_after_turn_off(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        refusal = inv.removal_refusal([1], actor="alice")
        assert "kea-a" in refusal and "turn it off from Servers first" in refusal
        assert world.store["_audit"][-1][0] == "INVESTIGATION_LOGGING_REMOVAL_REFUSED"
        assert inv.removal_refusal([2]) == "", "a server without an entry is not blocked"
        assert inv.turn_off(world.servers[0])["ok"]
        assert inv.removal_refusal([1]) == ""

    def test_a_half_finished_restore_also_blocks_removal(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        assert not inv.turn_off(world.servers[0])["ok"]
        assert inv.removal_refusal([1]) != ""

    def test_forget_drops_only_a_removed_entry(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        assert inv.forget(1, actor="alice") is False, "a live server is put back with turn_off, never forgotten"
        world.servers.pop(0)
        inv.sweep(now=NOW)
        assert inv.forget(1, actor="alice") is True and not inv.active()
        assert world.store["_audit"][-1][0] == "INVESTIGATION_LOGGING_FORGOTTEN"

    def test_a_server_that_comes_back_is_restored_normally(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        gone = world.servers.pop(0)
        inv.sweep(now=NOW + timedelta(minutes=10))
        world.servers.insert(0, gone)
        out = inv.sweep(now=NOW + timedelta(minutes=11))
        assert out["restored"] == ["kea-a"] and not inv.active()


class TestAdoptionIsAuditedAndTheRowNamesTheServer:
    def test_a_full_scan_that_adopts_a_live_marker_writes_an_audit_row(self, world):
        live, _ = ed.set_investigation_logging(world.daemons[2].file, FUTURE)
        world.daemons[2].file = live
        inv.sweep(now=NOW, full=True)
        assert world.store["_audit"][-1][0] == "INVESTIGATION_LOGGING_ADOPTED" and "kea-b" in world.store["_audit"][-1]

    def test_the_health_row_names_the_server_when_a_restore_is_still_owed(self, world):
        from jen.services import health

        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        inv.sweep(now=NOW + timedelta(minutes=6))
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "kea-a" in c.detail and "still at DEBUG 55" in c.detail


class TestADamagedMarkerIsNeverReadAsProofTheKeysNeverExisted:
    """v5.68.0-beta.13 (Q148): `clear_investigation_logging` used to read a marker whose `restore` object was missing or damaged as `{}`, so
    every key read as "absent" and the logger's severity and debuglevel were REMOVED together with the marker. It validates the marker
    first; an unreadable one changes NOTHING and answers "marker-invalid". Only a valid `{"created": true}`, or BOTH keys each "absent"
    or a real value, restores."""

    def _on(self, restore_edit):
        cfg = _cfg(
            [{"name": "kea-dhcp4", "severity": "INFO", "debuglevel": 3, "output-options": [{"output": "stdout"}]}]
        )
        on, _ = ed.set_investigation_logging(cfg, PAST)
        marker = _entry(on)["user-context"]["jen-investigation"]
        restore_edit(marker)
        return on

    @pytest.mark.parametrize(
        "damage",
        [
            lambda m: m.pop("restore"),
            lambda m: m.__setitem__("restore", "INFO"),
            lambda m: m.__setitem__("restore", {"debuglevel": 3}),
            lambda m: m.__setitem__("restore", {"severity": "INFO"}),
            lambda m: m.__setitem__("restore", {"created": "yes"}),
            lambda m: m.__setitem__("restore", {"created": False, "severity": "INFO", "debuglevel": 3}),
            lambda m: m.__setitem__("restore", {"severity": "", "debuglevel": 3}),
            lambda m: m.__setitem__("restore", {"severity": "INFO", "debuglevel": "3"}),
            lambda m: m.__setitem__("restore", {"severity": "INFO", "debuglevel": True}),
            lambda m: m.__setitem__("restore", None),
        ],
        ids=[
            "missing-restore",
            "restore-not-a-dict",
            "missing-severity",
            "missing-debuglevel",
            "created-not-a-bool",
            "created-false",
            "empty-severity",
            "debuglevel-a-string",
            "debuglevel-a-bool",
            "restore-null",
        ],
    )
    def test_a_marker_that_lost_its_restore_object_changes_nothing(self, damage):
        on = self._on(damage)
        before = copy.deepcopy(on)
        out, code = ed.clear_investigation_logging(on)
        assert code == "marker-invalid" and out == before, "the logger and the marker are left exactly as they are"
        assert (_entry(out)["severity"], _entry(out)["debuglevel"]) == ("DEBUG", 55)
        assert ed.clear_investigation_logging(on, now=NOW)[1] == "marker-invalid", (
            "the sweep's rule gets the same answer"
        )

    def test_the_absent_sentinels_are_valid_and_remove_the_keys(self):
        on = self._on(lambda m: m.__setitem__("restore", {"severity": "absent", "debuglevel": "absent"}))
        out, code = ed.clear_investigation_logging(on)
        assert code == "ok" and "severity" not in _entry(out) and "debuglevel" not in _entry(out)
        assert "user-context" not in _entry(out) and _entry(out)["output-options"] == [{"output": "stdout"}]

    def test_real_saved_values_are_valid_and_come_back(self):
        on = self._on(lambda m: m.__setitem__("restore", {"severity": "WARN", "debuglevel": 0}))
        out, code = ed.clear_investigation_logging(on)
        assert code == "ok" and (_entry(out)["severity"], _entry(out)["debuglevel"]) == ("WARN", 0)

    def test_a_valid_created_marker_removes_the_entry_it_created(self):
        on, _ = ed.set_investigation_logging(_cfg(), PAST)
        out, code = ed.clear_investigation_logging(on)
        assert code == "ok" and out["Dhcp4"]["loggers"] == []

    def test_a_damaged_marker_is_judged_before_it_is_due_not_at_its_deadline(self):
        """v5.68.0-beta.14 (Q149): beta.13 answered "nochange" for a damaged marker whose `until` was in the future, so Jen knew logging was
        on and did not know it had lost the way back until the deadline. Whether the way back can be trusted is its own question."""
        on, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4"}]), FUTURE)
        _entry(on)["user-context"]["jen-investigation"].pop("restore")
        before = copy.deepcopy(on)
        out, code = ed.clear_investigation_logging(on, now=NOW)
        assert code == "marker-invalid" and out == before, "damaged, whatever the deadline, and nothing is changed"

    def test_a_marker_that_is_not_an_object_is_damaged_too(self):
        on, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4"}]), FUTURE)
        _entry(on)["user-context"]["jen-investigation"] = "until the 7th"
        assert ed.validate_investigation_marker(on) != ""
        assert ed.clear_investigation_logging(on, now=NOW)[1] == "marker-invalid"
        out, code = ed.set_investigation_logging(on, FUTURE)
        assert code == "marker-invalid" and _entry(out)["user-context"]["jen-investigation"] == "until the 7th", (
            "a turn-on never writes the logger's current DEBUG values over an unreadable marker"
        )

    def test_the_validator_is_separate_from_is_it_due(self):
        assert ed.validate_investigation_marker(_cfg()) == "", "no logger, no marker: nothing to distrust"
        assert ed.validate_investigation_marker({}) == "", "no Dhcp4 block either"
        valid, _ = ed.set_investigation_logging(_cfg([{"name": "kea-dhcp4"}]), FUTURE)
        assert ed.validate_investigation_marker(valid) == ""
        _entry(valid)["user-context"]["jen-investigation"]["restore"] = {"severity": "INFO"}
        assert "debuglevel" in ed.validate_investigation_marker(valid)

    def test_turning_it_on_again_never_records_debug_as_what_to_restore(self):
        damaged = self._on(lambda m: m.pop("restore"))
        out, code = ed.set_investigation_logging(damaged, FUTURE)
        assert code == "marker-invalid" and "restore" not in _entry(out)["user-context"]["jen-investigation"]

    def test_the_pure_validator(self):
        assert ed.restore_problem({"created": True}) == ""
        assert ed.restore_problem({"severity": "INFO", "debuglevel": 3}) == ""
        assert ed.restore_problem({"severity": "absent", "debuglevel": "absent"}) == ""
        assert ed.restore_problem({"severity": "INFO", "debuglevel": "absent"}) == ""
        assert ed.restore_problem({"created": True, "severity": "INFO"}) != "", "created is the WHOLE restore object"
        assert ed.restore_problem(None) != "" and ed.restore_problem([]) != ""


class TestADamagedMarkerIsSaidOutLoud:
    """The sweep records the unreadable marker as the entry's error, the Health row goes red naming the server with the by-hand text, and
    turn_off says the same - and none of them changes the config."""

    def _damaged_world(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        marker = _entry(world.daemons[1].file)["user-context"]["jen-investigation"]
        marker.pop("restore")
        return copy.deepcopy(world.daemons[1].file)

    def test_turn_off_refuses_changes_nothing_and_says_how_to_restore_it_by_hand(self, world):
        before = self._damaged_world(world)
        writes = world.daemons[1].writes
        out = inv.turn_off(world.servers[0], actor="alice")
        assert out["ok"] is False and world.daemons[1].file == before and world.daemons[1].writes == writes
        text = out["lines"][-1]
        assert "the investigation-logging marker on kea-a is damaged" in text and "Config history" in text
        assert "10.0.0.1" in text and "jen-investigation" in text and "debuglevel" in text
        assert "`restore`" not in text and "restore object" not in text, "never points at the object that is damaged"
        (entry,) = inv.active()
        assert entry["marker_invalid"] and entry["error"], "the entry is kept so the Health row keeps saying so"
        assert world.daemons[1].calls.count("config-reload") == 1, (
            "only turn_on's: the daemon was not asked to reload a config nobody wrote"
        )

    def test_the_sweep_records_it_as_an_error_and_keeps_trying_to_read_it_every_minute_without_writing(self, world):
        before = self._damaged_world(world)
        for minute in (6, 7, 8):
            out = inv.sweep(now=NOW + timedelta(minutes=minute))
            assert out["restored"] == [] and "damaged" in out["errors"][0] and "kea-a" in out["errors"][0]
        assert world.daemons[1].file == before

    def test_the_health_row_goes_red_naming_the_server_and_the_by_hand_text(self, world):
        from jen.services import health

        self._damaged_world(world)
        inv.sweep(now=NOW + timedelta(minutes=6))
        c = health._debug_logging_left_on({})
        assert c.status == "fail"
        assert "the investigation-logging marker on kea-a is damaged" in c.detail and "Config history" in c.detail
        assert "10.0.0.1" in c.detail and "jen-investigation" in c.detail and "`restore`" not in c.detail
        assert "should have ended" not in c.detail and "still at DEBUG 55" not in c.detail, "said once, not three ways"

    @pytest.mark.parametrize(
        "damage",
        [
            lambda m: m.pop("restore"),
            lambda m: m.__setitem__("restore", {"severity": "INFO"}),
            lambda m: m.__setitem__("restore", {"created": False}),
        ],
        ids=["no-restore", "missing-debuglevel", "created-false"],
    )
    def test_the_guidance_for_each_damaged_shape_never_names_the_damaged_object(self, world, damage):
        """v5.68.0-beta.14 (Q149): beta.13's by-hand text told the operator to read what the marker's `restore` object says - the very
        object just declared unreadable. The guidance now goes to Config history, to the config as it was before the logging went on."""
        assert inv.turn_on(world.servers[0], 5)["ok"]
        damage(_entry(world.daemons[1].file)["user-context"]["jen-investigation"])
        for text in (
            inv.turn_off(world.servers[0])["lines"][-1],
            inv.by_hand_damaged({"ssh_host": "10.0.0.1", "kea_conf": "/etc/kea/kea-dhcp4.conf"}),
            inv.by_hand_damaged({"server_id": "1", "history_revision": 41}),
        ):
            assert "`restore`" not in text and "restore object" not in text, text
            assert "Config history" in text and "jen-investigation" in text and "Forget" in text, text

    def test_the_revision_before_the_logging_went_on_is_linked_when_the_server_is_still_in_jen(
        self, world, monkeypatch
    ):
        from jen.services import config_revisions as rev

        rows = [  # newest first, as list_revisions returns them
            {"id": 45, "summary": "something later"},
            {"id": 44, "summary": "investigation logging on for 15 min"},
            {"id": 43, "summary": "investigation logging on for 5 min"},
            {"id": 42, "summary": "the config as it was before"},
        ]
        monkeypatch.setattr(rev, "list_revisions", lambda server_id, service, limit=100: rows)
        assert inv.turn_on(world.servers[0], 5)["ok"]
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"].pop("restore")
        text = inv.turn_off(world.servers[0])["lines"][-1]
        assert "revision 42" in text and "/servers/1/config-history/42" in text
        assert inv.active()[0]["history_revision"] == 42, "the Servers page links it"

    def test_a_damaged_marker_with_no_history_says_to_use_a_backup(self):
        text = inv.by_hand_damaged({"server_id": "1", "history_revision": None})
        assert "none is on record" in text and "backup" in text

    def test_a_damaged_future_marker_is_unhealthy_on_the_next_full_scan_not_at_expiry(self, world):
        """v5.68.0-beta.14 (Q149): beta.13 indexed a live marker without validating it, so Health stayed green until the deadline."""
        from jen.services import health

        assert inv.turn_on(world.servers[0], 60)["ok"]
        before = None
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"].pop("restore")
        before = copy.deepcopy(world.daemons[1].file)
        writes = world.daemons[1].writes
        assert health._debug_logging_left_on({}).status == "ok", "nothing has looked yet"
        out = inv.sweep(now=NOW + timedelta(minutes=1), full=True)  # an hour from its deadline
        assert out["restored"] == [] and "damaged" in out["errors"][0]
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "damaged" in c.detail and "Config history" in c.detail
        assert world.daemons[1].file == before and world.daemons[1].writes == writes, (
            "the DEBUG is left exactly as it is"
        )
        (entry,) = inv.active()
        assert entry["marker_invalid"]
        again = inv.sweep(now=NOW + timedelta(minutes=2), full=True)
        assert again["errors"] == [], "said once"
        refused = inv.turn_on(world.servers[0], 5)
        assert refused["ok"] is False and world.daemons[1].file == before, "Turn On is refused over a damaged marker"

    def test_forget_is_refused_while_the_file_still_carries_the_marker_and_accepted_once_it_does_not(self, world):
        assert inv.turn_on(world.servers[0], 60)["ok"]
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"].pop("restore")
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert inv.forget(1) is False and inv.active(), "Jen reads the file: 'I fixed it' is checked, not believed"
        entry = _entry(world.daemons[1].file)
        entry["severity"], entry["debuglevel"] = "INFO", 0
        del entry["user-context"]
        assert inv.forget(1) is False, (
            "the file is clean but Kea is still SEEN at investigation DEBUG (fixup 4, F5): put it back, do not forget it"
        )
        world.daemons[1].loaded = copy.deepcopy(world.daemons[1].file)  # the person reloaded Kea
        assert inv.forget(1, actor="alice") is True and not inv.active()

    def test_a_marker_repaired_by_hand_stops_being_reported_damaged(self, world):
        assert inv.turn_on(world.servers[0], 60)["ok"]
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"].pop("restore")
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"]["restore"] = {
            "severity": "INFO",
            "debuglevel": "absent",
        }
        inv.sweep(now=NOW + timedelta(minutes=2), full=True)
        (entry,) = inv.active()
        assert not entry["marker_invalid"] and not entry["error"]

    def test_removing_the_server_stays_refused_while_it_is_unreadable(self, world):
        self._damaged_world(world)
        inv.turn_off(world.servers[0])
        assert inv.removal_refusal([1]) != ""

    def test_once_a_person_fixes_the_marker_the_next_sweep_restores_it(self, world):
        self._damaged_world(world)
        inv.sweep(now=NOW + timedelta(minutes=6))
        _entry(world.daemons[1].file)["user-context"]["jen-investigation"]["restore"] = {
            "severity": "INFO",
            "debuglevel": "absent",
        }
        out = inv.sweep(now=NOW + timedelta(minutes=7))
        assert out["restored"] == ["kea-a"] and not inv.active()
        assert _entry(world.daemons[1].file) == {"name": "kea-dhcp4", "severity": "INFO"}


class TestTheHealthRow:
    def _check(self):
        from jen.services import health

        return health._debug_logging_left_on({})

    def test_nothing_on_is_ok(self, world):
        c = self._check()
        assert c.status == "ok" and c.id == "debug_logging_left_on" and c.title == "DEBUG logging left on"

    def test_on_and_in_time_is_ok_and_names_the_deadline(self, world):
        inv.turn_on(world.servers[0], 5)
        c = self._check()
        assert c.status == "ok" and "kea-a: on until" in c.detail

    def test_overdue_fails_and_says_what_to_do(self, world, monkeypatch):
        inv.turn_on(world.servers[0], 5)
        monkeypatch.setattr(inv, "_now", lambda: NOW + timedelta(minutes=30))
        c = self._check()
        assert (
            c.status == "fail"
            and "should have ended" in c.detail
            and "turn logging off from Trace or Servers" in c.fix_hint
        )
        assert c.fix_url == "/tools/trace"

    def test_it_is_registered_in_the_kea_group_in_step_with_the_runner(self):
        from jen.services import health

        assert health._CHECK_META["debug_logging_left_on"] == ("DEBUG logging left on", "kea")
        names = [fn.__name__.lstrip("_") for fn in health._CHECKS]
        assert names == health.CHECK_IDS, "the runner zips _CHECKS with CHECK_IDS: the two lists must stay in step"


class TestTheScheduler:
    def test_the_sweep_is_a_one_minute_job(self):
        import inspect

        from jen.services import scheduler

        src = inspect.getsource(scheduler.start_scheduler)
        assert (
            'id="jen_investigation_sweep"' in src and "IntervalTrigger(minutes=1)" in src and "max_instances=1" in src
        )


class TestTheMacroSeesTheRequestContext:
    """The controls macro prints a CSRF token. `csrf_token` is a context processor, not a Jinja global, and an imported macro does
    not see the context unless it is imported `with context` - without it the Trace page was a 500 (found by the e2e journeys)."""

    def test_every_template_that_imports_the_macro_imports_it_with_context(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent / "templates"
        importers = [p for p in root.glob("*.html") if "import investigation_controls" in p.read_text(encoding="utf-8")]
        assert {p.name for p in importers} >= {"trace.html", "servers.html"}
        for p in importers:
            if p.name == "_investigation_logging.html":
                continue
            text = p.read_text(encoding="utf-8")
            assert re.search(r"import investigation_controls with context %\}", text), p.name


class TestAControlAgentThatDidNotAnswer:
    """v5.68.0-beta.21 (Q156, item 4): `_supports_reload` was `result == 0 and "config-reload" in arguments`, and `kea_command` returns result 1 on a
    connection failure or timeout - so a Control Agent that was DOWN read as "this daemon has no config-reload", `_change` passed `restart=True`, and
    turning logging ON wrote the file and restarted kea-dhcp4 over SSH. On Kea 3.0+ config-reload is always listed: "not listed" can only mean
    "could not ask". `_reload_support` says yes / no / unknown; turning ON refuses on unknown, and only the restore falls back to a restart."""

    def test_the_three_answers(self, world):
        daemon = world.daemons[1]
        assert inv._reload_support(world.servers[0]) == "yes"
        daemon.commands = ["version-get"]
        assert inv._reload_support(world.servers[0]) == "no"
        daemon.list_unreachable = True
        assert inv._reload_support(world.servers[0]) == "unknown"

    def test_turn_on_with_the_api_down_writes_nothing_restarts_nothing_and_says_what_to_check(self, world):
        daemon = world.daemons[1]
        daemon.list_unreachable = True
        before = copy.deepcopy(daemon.file)
        out = inv.turn_on(world.servers[0], 5, actor="alice")
        assert out["ok"] is False and out["until"] == ""
        assert "did not answer" in out["lines"][0] and "Settings → Kea → Probe" in out["lines"][0]
        assert daemon.writes == 0 and daemon.file == before
        assert not any(c.startswith(("apply", "restart")) for c in daemon.calls), daemon.calls
        assert not inv.active(), "no index entry: nothing was written, so nothing is owed"
        assert "_audit" not in world.store

    def test_turn_on_still_restarts_a_daemon_that_answered_and_lacks_config_reload(self, world):
        world.daemons[1].commands = ["version-get"]
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] and out["mode"] == "restart"
        assert any(c.startswith("apply(restart=True)") for c in world.daemons[1].calls)

    def test_turn_off_with_the_api_down_restores_with_a_restart_and_says_why(self, world):
        daemon = world.daemons[1]
        original = copy.deepcopy(daemon.file)
        assert inv.turn_on(world.servers[0], 5)["ok"]
        daemon.list_unreachable = True
        out = inv.turn_off(world.servers[0], actor="alice")
        assert out["ok"] and out["mode"] == "restart" and daemon.file == original
        assert any("did not answer" in line and "restarted to take the restore" in line for line in out["lines"]), out[
            "lines"
        ]
        assert not inv.active()

    def test_the_expiry_sweep_with_the_api_down_still_restores_with_the_restart_and_the_line_says_why(self, world):
        daemon = world.daemons[1]
        original = copy.deepcopy(daemon.file)
        assert inv.turn_on(world.servers[0], 5)["ok"]
        daemon.list_unreachable = True
        out = inv.sweep(now=NOW + timedelta(minutes=6))
        assert out["restored"] == ["kea-a"] and daemon.file == original and not inv.active()
        assert any(c.startswith("apply(restart=True)") for c in daemon.calls), (
            "DEBUG 55 must come off: the restart is the fallback here"
        )
        assert daemon.loaded == original, "the running daemon took the restore"

    def test_a_restore_that_finds_nothing_to_write_but_a_daemon_still_at_debug_restarts_when_the_api_is_down(
        self, world
    ):
        daemon = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        # the file was put back by hand; the daemon still runs DEBUG 55 and Kea's API is down
        daemon.file, _code = ed.clear_investigation_logging(daemon.loaded)
        daemon.list_unreachable = True
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and out["mode"] == "restart"
        assert any("did not answer" in line for line in out["lines"])


class TestTurningOnNeverRestartsKea:
    """v5.68.0-beta.22 (Q157, item 1): the matrix. `turn_on` calls Kea's API twice - `list-commands`, then `config-reload` - and beta.21 handled only a
    silence on the FIRST. Every way the second can fail is the same reply shape (`result` 1 with a text), so none of them may become a restart over SSH:
    the file is put back, nothing is indexed, and the line says so. Only a daemon that ANSWERED and does not list config-reload keeps the documented
    restart (the operator was told the daemon lacks it)."""

    @staticmethod
    def _restarted(kea):
        return [
            c
            for c in kea.calls
            if c.startswith("restart") or c == "apply(restart=True):investigation logging on for 5 min"
        ]

    @pytest.mark.parametrize(
        "text", ["reload refused", "connection refused", "timed out after 10 s", "HTTP 502 from the Control Agent", ""]
    )
    def test_a_reload_that_fails_in_any_way_reverts_and_never_restarts(self, world, text):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        kea.reload_result, kea.reload_text = 1, text
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and out["until"] == ""
        assert kea.file == original and ed.investigation_marker(kea.file) is None, "the file was put back"
        assert self._restarted(kea) == [], kea.calls
        assert not inv.active() and "_audit" not in world.store
        assert any("nothing was restarted" in line for line in out["lines"])
        assert not _daemon_at_debug(kea), "the daemon never moved"

    def test_a_reload_that_works_reloads_and_does_not_restart(self, world):
        kea = world.daemons[1]
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] and out["mode"] == "reload" and self._restarted(kea) == []

    def test_a_daemon_that_answered_and_lacks_config_reload_is_restarted_as_documented(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        out = inv.turn_on(world.servers[0], 5)
        assert (
            out["ok"]
            and out["mode"] == "restart"
            and "apply(restart=True):investigation logging on for 5 min" in kea.calls
        )

    def test_a_silent_list_commands_refuses_before_writing(self, world):
        kea = world.daemons[1]
        kea.list_unreachable = True
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and kea.writes == 0 and self._restarted(kea) == []

    def test_a_failed_reload_then_a_failed_revert_keeps_the_entry_with_the_error_and_the_sweep_finishes_it(self, world):
        kea = world.daemons[1]
        kea.reload_result, kea.reload_text, kea.fail_writes_after = 1, "connection refused", 1
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and ed.investigation_marker(kea.file), "the file still carries the marker"
        assert self._restarted(kea) == [], "even now, turning ON did not restart"
        (entry,) = inv.active()
        assert entry["file"] == "debug" and entry["pending"] == "reload" and entry["error"]
        kea.reload_result, kea.fail_writes_after = 0, None
        assert inv.sweep(now=NOW + timedelta(minutes=6))["restored"] == ["kea-a"]
        assert not inv.active() and ed.investigation_marker(kea.file) is None

    def test_the_restore_paths_still_restart_when_the_reload_fails_and_say_so(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_result, kea.reload_text = 1, "connection refused"
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and out["mode"] == "restart" and "restart:dhcp4" in kea.calls
        assert any("config-reload was refused (connection refused)" in line for line in out["lines"])

    def test_the_expiry_sweep_still_restarts_when_the_reload_fails(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_result, kea.reload_text = 1, "timed out"
        assert inv.sweep(now=NOW + timedelta(minutes=6))["restored"] == ["kea-a"]
        assert "restart:dhcp4" in kea.calls and not _daemon_at_debug(kea)

    def test_turn_on_is_the_only_caller_that_forbids_the_restart(self):
        import inspect

        source = inspect.getsource(inv)
        assert source.count("allow_restart=False") == 1 and source.count("allow_restart=True") == 1
        assert "def _daemon_step(" in source and "allow_restart: bool," in source


# ── v5.68.0-beta.23 (Q158): the daemon is OBSERVED, never inferred ─────────────────────────────────────────────────────────────────


def _servers_of(value):
    import json

    return json.loads(value or "{}").get("servers", {})


class TestTheRunningLoggerIsRead:
    """`daemon_logger` reads `config-get` (tests/kea_compat/test_log_levels.py records what Kea 3.0.3 / 3.2.0 / 3.3.1 answer); `observe` turns it into
    the entry's daemon state: debug / restored / other / unknown."""

    def test_the_four_states(self, world):
        kea, server = world.daemons[1], world.servers[0]
        entry = {"restore": {"severity": "INFO", "debuglevel": "absent"}}
        assert inv.observe(server, entry) == "restored" and entry["daemon"] == "restored" and entry["observed_at"]
        assert entry["seen"].startswith("INFO")
        on, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.loaded = on
        assert inv.observe(server, entry) == "debug" and "DEBUG" in entry["seen"]
        kea.loaded = _cfg([{"name": "kea-dhcp4", "severity": "WARN", "debuglevel": 0}])
        assert inv.observe(server, entry) == "other" and "WARN" in entry["seen"]
        kea.api_silent = True
        assert inv.observe(server, entry) == "unknown" and entry["seen"] == ""

    def test_what_is_read_when_kea_answers_with_something_that_is_not_a_dhcp4_config(self, world, monkeypatch):
        for reply in (
            {"result": 0, "arguments": {"Dhcp6": {}}},
            {"result": 0, "arguments": []},
            {"result": 0},
            {"result": 0, "arguments": {"Dhcp4": {"loggers": "nope"}}},
            {"result": 1, "text": "x"},
        ):
            monkeypatch.setattr(inv._kea, "kea_command", lambda command, server=None, _r=reply, **kw: _r)
            assert inv.daemon_logger(world.servers[0]) is None, reply

    def test_a_logger_that_is_absent_is_what_a_created_one_looks_like_once_restored(self, world):
        kea, server = world.daemons[2], world.servers[1]
        assert inv.daemon_logger(server) == {"present": False, "severity": None, "debuglevel": None, "marker": None}
        assert inv.observe(server, {"restore": {"created": True}}) == "restored"
        assert inv.observe(server, {}) == "restored", (
            "an entry written before beta.23 has no restore object: no marker and not DEBUG 55"
        )
        assert inv.observe(server, {"restore": {"severity": "INFO", "debuglevel": 0}}) == "other", (
            "the logger it described is gone"
        )
        on, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.loaded = on
        assert inv.observe(server, {"restore": {"created": True}}) == "debug"

    @pytest.mark.parametrize(
        "restore, shown, expected",
        [
            ({"severity": "WARN", "debuglevel": 0}, {"severity": "WARN", "debuglevel": 0}, "restored"),
            ({"severity": "WARN", "debuglevel": 0}, {"severity": "warn", "debuglevel": 0}, "restored"),
            ({"severity": "WARN", "debuglevel": 0}, {"severity": "INFO", "debuglevel": 0}, "other"),
            ({"severity": "WARN", "debuglevel": 0}, {"severity": "WARN", "debuglevel": 3}, "other"),
            ({"severity": "absent", "debuglevel": "absent"}, {"severity": "INFO", "debuglevel": 0}, "restored"),
            ({"severity": "absent", "debuglevel": "absent"}, {"severity": "DEBUG", "debuglevel": 55}, "other"),
            ({"severity": "INFO", "debuglevel": "absent"}, {"severity": "INFO"}, "restored"),
            ({"severity": "DEBUG", "debuglevel": 99}, {"severity": "DEBUG", "debuglevel": 99}, "restored"),
            ({"severity": "DEBUG", "debuglevel": 55}, {"severity": "DEBUG", "debuglevel": 55}, "restored"),
        ],
    )
    def test_restored_means_what_the_marker_said_it_was(self, world, restore, shown, expected):
        world.daemons[1].loaded = _cfg([{"name": "kea-dhcp4", **shown}])
        assert inv.observe(world.servers[0], {"restore": restore}) == expected

    def test_a_restart_gets_a_few_seconds_to_answer(self, world, monkeypatch):
        sleeps = []
        monkeypatch.setattr(inv, "_sleep", sleeps.append)
        kea = world.daemons[1]
        kea.silent_gets = 2
        entry = {}
        t = [0.0]
        monkeypatch.setattr(inv.time, "monotonic", lambda: t.__setitem__(0, t[0] + 0.1) or t[0])
        assert inv.observe(world.servers[0], entry, wait_s=inv.OBSERVE_AFTER_RESTART_S) == "restored"
        assert len(sleeps) == 2, "it looked again after each silence"
        kea.silent_gets = 99
        sleeps.clear()
        assert inv.observe(world.servers[0], entry, wait_s=0) == "unknown" and sleeps == [], "no waiting unless asked"


class TestALostReloadReplyIsNotAFailure:
    """The reviewer's P1: a `config-reload` Kea APPLIED whose HTTP reply was lost came back as a failure; the file was put back, the entry dropped,
    and the daemon stayed at DEBUG 55 with nothing left that knew. Turning on now reverts the file WITHOUT a restart and then LOOKS."""

    def test_turn_on_keeps_the_entry_says_what_it_saw_and_never_restarts(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        kea.reload_applied_but_lost = True
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and out["until"] == ""
        assert kea.file == original and ed.investigation_marker(kea.file) is None, "the file is back"
        assert _daemon_at_debug(kea), "and the daemon DID take the change"
        assert not any(c.startswith("restart") for c in kea.calls), kea.calls
        assert any("applied the change although its API did not confirm it" in line for line in out["lines"]), out[
            "lines"
        ]
        (entry,) = inv.active()
        assert (entry["file"], entry["daemon"], entry["pending"], entry["stuck"]) == (
            "restored",
            "debug",
            "reload",
            True,
        )
        assert entry["observed_at"] and "_audit" not in world.store, "nothing is audited as ON"

    def test_the_health_row_says_so_and_the_sweep_finishes_it_without_a_restart(self, world):
        from jen.services import health

        kea = world.daemons[1]
        kea.reload_applied_but_lost = True
        inv.turn_on(world.servers[0], 5)
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "kea-a" in c.detail and "still at DEBUG 55" in c.detail
        calls_before = len(kea.calls)
        out = inv.sweep(now=NOW)  # nothing is due by the clock; the entry is owed a daemon step
        assert out["restored"] == ["kea-a"] and not inv.active() and not _daemon_at_debug(kea)
        assert not any(c.startswith("restart") for c in kea.calls[calls_before:]), (
            "the reload was applied; Jen SAW the daemon restored"
        )
        assert kea.file == _cfg([{"name": "kea-dhcp4", "severity": "INFO"}])

    def test_a_reload_truly_refused_is_seen_restored_and_dropped_at_once(self, world):
        kea = world.daemons[1]
        kea.reload_result, kea.reload_text = 1, "reload refused"
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and not inv.active() and not _daemon_at_debug(kea)
        assert any("Logging was not activated" in line for line in out["lines"])

    def test_a_restore_whose_reply_is_lost_is_not_followed_by_a_restart(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_applied_but_lost = True
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and not inv.active() and not _daemon_at_debug(kea)
        assert "restart:dhcp4" not in kea.calls, "the daemon was SEEN restored, so the restart fallback did not run"
        assert any("seen at the right level" in line for line in out["lines"]), out["lines"]

    def test_a_restore_the_daemon_really_refused_still_restarts_when_it_is_not_seen_restored(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_result, kea.reload_text = 1, "refused"
        out = inv.turn_off(world.servers[0])
        assert out["ok"] and out["mode"] == "restart" and "restart:dhcp4" in kea.calls and not inv.active()


class TestAnEntryIsDroppedOnlyWhenTheDaemonWasSeenRestored:
    def test_a_restore_that_reports_ok_but_leaves_the_daemon_at_debug_keeps_the_entry(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        real = kea.kea_command

        def reload_says_ok_and_does_nothing(command, **kw):
            if command == "config-reload":
                kea.calls.append(command)
                return {"result": 0, "text": "reloaded"}
            return real(command, **kw)

        kea.kea_command = reload_says_ok_and_does_nothing
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is False and _daemon_at_debug(kea)
        (entry,) = inv.active()
        assert (entry["file"], entry["daemon"], entry["pending"], entry["stuck"]) == (
            "restored",
            "debug",
            "reload",
            True,
        )
        assert "still running at DEBUG 55" in out["lines"][-1]
        kea.kea_command = real
        assert inv.sweep(now=NOW)["restored"] == ["kea-a"] and not inv.active()

    def test_a_daemon_that_cannot_be_seen_keeps_the_entry_and_nothing_is_restarted_on_a_guess(self, world):
        from jen.services import health

        kea = world.daemons[1]
        kea.reload_result, kea.reload_text, kea.api_silent = 1, "connection refused", True
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False
        (entry,) = inv.active()
        assert (entry["file"], entry["daemon"], entry["pending"]) == ("restored", "unknown", "reload")
        assert not any(c.startswith("restart") for c in kea.calls), kea.calls
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "unconfirmed since" in c.detail and "kea-a" in c.detail
        calls_before = len(kea.calls)
        for minute in (1, 2, 3):  # the API stays silent: the sweep looks, and does not reload or restart on a guess
            assert inv.sweep(now=NOW + timedelta(minutes=minute))["restored"] == []
        assert not any(c.startswith(("restart", "config-reload")) for c in kea.calls[calls_before:]), kea.calls[
            calls_before:
        ]
        kea.api_silent, kea.reload_result = False, 0  # the API comes back: Jen sees the daemon at its original level
        assert inv.sweep(now=NOW + timedelta(minutes=4))["restored"] == ["kea-a"] and not inv.active()

    def test_a_reload_kea_confirms_but_the_level_cannot_be_read_back_is_on_and_unconfirmed(self, world):
        from jen.services import health

        kea = world.daemons[1]
        real = kea.kea_command
        kea.kea_command = lambda command, **kw: (
            {"result": 1, "text": "connection refused"} if command == "config-get" else real(command, **kw)
        )
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is True and any("could not read Kea's running log level back" in line for line in out["lines"])
        (entry,) = inv.active()
        assert (entry["file"], entry["daemon"], entry["pending"]) == ("debug", "unknown", None)
        assert health._debug_logging_left_on({}).status == "warn"
        kea.kea_command = real
        inv.sweep(now=NOW + timedelta(minutes=1))  # the API answers: the daemon is SEEN at DEBUG
        (entry,) = inv.active(now=NOW + timedelta(minutes=1))
        assert entry["daemon"] == "debug" and health._debug_logging_left_on({}).status == "ok"

    def test_a_daemon_seen_at_something_else_is_said_so_and_the_entry_stays(self, world):
        from jen.services import health

        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        real = kea.kea_command

        def reload_lands_on_warn(command, **kw):
            if command == "config-reload":
                kea.calls.append(command)
                kea.loaded = _cfg([{"name": "kea-dhcp4", "severity": "WARN", "debuglevel": 0}])
                return {"result": 0, "text": "reloaded"}
            return real(command, **kw)

        kea.kea_command = reload_lands_on_warn
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is False and any("WARN" in line and "neither" in line for line in out["lines"])
        (entry,) = inv.active()
        assert entry["daemon"] == "other" and entry["stuck"]
        assert "neither at investigation DEBUG nor at what it was before" in health._debug_logging_left_on({}).detail

    def test_a_restart_that_leaves_the_daemon_where_it_was_is_not_believed(self, world):
        """beta.23 dropped the entry here. Fixup 4 (F3): a restart that SUCCEEDED and a daemon at its original level is a contradiction - the entry
        stays, the file goes back, nothing is restarted again, and Health names api_url and ssh_host (TestContradictoryEvidence... pins the rest)."""
        kea = world.daemons[1]
        kea.commands = ["version-get"]  # no config-reload: the restart path
        kea.restart_ignored = True
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and ed.investigation_marker(kea.file) is None
        (entry,) = inv.active()
        assert entry["contradiction"] and entry["daemon"] == "other"
        assert any("is not running the file Jen wrote" in line for line in out["lines"])


class TestEveryStateWriteIsChecked:
    """`set_global_setting` answers False when the Jen database did not take a write (beta.22). The index is now written on that answer."""

    @staticmethod
    def _pending_write(value):
        return any(e.get("pending") == "reload" and e.get("daemon") == "unknown" for e in _servers_of(value).values())

    @staticmethod
    def _post_activation_write(value):
        return any(
            e.get("daemon") == "debug" and e.get("pending") is None and e.get("file") == "debug"
            for e in _servers_of(value).values()
        )

    def test_the_helpers_report_what_was_stored(self, world):
        world.db["fails"] = lambda value: True
        record = {"servers": {}}
        assert inv._put(record, 1, {"name": "x"}) is False
        assert inv._drop(record, 1) is False and "1" in record["servers"], (
            "a drop that was not stored leaves the entry in view"
        )
        world.db["fails"] = None
        assert (
            inv._put(record, 1, {"name": "x"}) is True and inv._drop(record, 1) is True and inv._drop(record, 1) is True
        )

    def test_the_db_failing_at_the_pending_write_reverts_the_file_and_never_asks_the_daemon(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        world.db["fails"] = self._pending_write
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and kea.file == original and not inv.active()
        assert "config-reload" not in kea.calls and "config-get" not in kea.calls, "the daemon was not asked"
        assert any("Jen could not record this" in line and "nothing was activated" in line for line in out["lines"])
        assert not _daemon_at_debug(kea) and "_audit" not in world.store

    def test_the_db_failing_at_the_pending_write_and_the_revert_failing_too_says_where_the_marker_is(self, world):
        kea = world.daemons[1]
        kea.fail_writes_after = 1
        world.db["fails"] = self._pending_write
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and "config-reload" not in kea.calls
        assert any("could not be put back" in line and "ten-minute scan" in line for line in out["lines"])
        assert ed.investigation_marker(kea.file), "the file still carries the marker; the full scan adopts it"
        world.db["fails"], kea.fail_writes_after = None, None
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"], "indexed by the full scan, which reads the file"
        assert inv.sweep(now=NOW + timedelta(minutes=6))["restored"] == ["kea-a"]

    def test_the_db_failing_after_the_activation_turns_logging_off_again(self, world):
        kea = world.daemons[1]
        original = copy.deepcopy(kea.file)
        world.db["fails"] = self._post_activation_write
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and out["until"] == ""
        assert any(
            "could not record that logging is on" in line and "turned off again" in line for line in out["lines"]
        ), out["lines"]
        assert kea.file == original and not _daemon_at_debug(kea) and not inv.active()
        assert "_audit" not in world.store

    def test_the_db_failing_at_the_final_drop_leaves_the_entry_and_the_next_sweep_drops_it(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.db["fails"] = lambda value: value == ""
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is True and not _daemon_at_debug(kea)
        assert any("could not clear its own record" in line for line in out["lines"])
        assert len(inv.active()) == 1, "the entry is still stored"
        world.db["fails"] = None
        calls_before = len(kea.calls)
        assert inv.sweep(now=NOW)["restored"] == ["kea-a"] and not inv.active()
        assert not any(c.startswith(("config-reload", "restart")) for c in kea.calls[calls_before:]), (
            "it was SEEN restored: nothing to do"
        )

    def test_a_failed_save_of_the_orphan_flag_is_not_a_crash(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers.pop(0)
        world.db["fails"] = lambda value: True
        inv.sweep(now=NOW)  # does not raise


class TestTheFullScanReadsTheDaemonToo:
    def test_a_running_logger_at_debug_with_a_clean_file_and_no_entry_is_adopted_and_restored(self, world):
        kea = world.daemons[1]
        on, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.loaded = (
            on  # the daemon runs DEBUG 55 ... and the file was put back (a lost reply, a hand edit, a restored backup)
        )
        assert ed.investigation_marker(kea.file) is None and not inv.active()
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"] and out["restored"] == ["kea-a"] and out["errors"] == []
        assert not _daemon_at_debug(kea) and not inv.active()
        assert "config-reload" in kea.calls and "restart:dhcp4" not in kea.calls
        assert [a[0] for a in world.store["_audit"]][:1] == ["INVESTIGATION_LOGGING_ADOPTED"]

    def test_without_config_reload_the_documented_restart_finishes_it(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        on, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.loaded = on
        out = inv.sweep(now=NOW, full=True)
        assert out["restored"] == ["kea-a"] and kea.writes == 0, "the file was already clean: nothing was written"
        assert "restart:dhcp4" in kea.calls and not _daemon_at_debug(kea) and not inv.active()

    def test_a_live_marker_in_the_file_is_adopted_with_the_daemon_observed(self, world):
        kea = world.daemons[1]
        live, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.file = kea.loaded = live
        assert inv.sweep(now=NOW, full=True)["adopted"] == ["kea-a"]
        (entry,) = inv.active(NOW)
        assert (entry["file"], entry["daemon"], entry["pending"]) == ("debug", "debug", None)

    def test_a_live_marker_in_the_file_that_the_daemon_never_loaded_is_adopted_unconfirmed_not_assumed(self, world):
        kea = world.daemons[1]
        live, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.file = live  # written, never reloaded
        inv.sweep(now=NOW, full=True)
        (entry,) = inv.active(NOW)
        assert entry["file"] == "debug" and entry["daemon"] == "restored" and entry["pending"] == "reload"

    def test_a_daemon_that_does_not_answer_is_not_adopted_or_restarted(self, world):
        kea = world.daemons[2]
        kea.api_silent = True
        assert inv.sweep(now=NOW, full=True) == {"restored": [], "adopted": [], "errors": []}
        assert not any(c.startswith(("config-reload", "restart")) for c in kea.calls)

    def test_a_logger_at_debug_without_the_marker_is_somebody_elses_and_is_left_alone(self, world):
        kea = world.daemons[1]
        kea.file = kea.loaded = _cfg([{"name": "kea-dhcp4", "severity": "DEBUG", "debuglevel": 99}])
        assert inv.sweep(now=NOW, full=True) == {"restored": [], "adopted": [], "errors": []}
        assert not inv.active() and not any(c.startswith(("config-reload", "restart")) for c in kea.calls)

    def test_the_cheap_path_reads_no_daemon_for_a_known_good_entry(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        calls_before = len(world.daemons[1].calls)
        inv.sweep(now=NOW + timedelta(minutes=1))
        assert "config-get" not in world.daemons[1].calls[calls_before:], (
            "an entry seen at DEBUG is not re-read every minute"
        )
        assert "config-get" not in world.daemons[2].calls


# ── v5.68.0-beta.23 fixup 4 (Fable's audit of the pushed tree) ────────────────────────────────────────────────────────────────────


def _count(kea, *names):
    return sum(1 for c in kea.calls if c in names)


def _reloads(kea):
    return _count(kea, "config-reload")


def _restarts(kea):
    return _count(kea, "restart:dhcp4")


class TestTheDaemonStepIsBounded:
    """F1: `_restore`'s "nothing" branch skipped the daemon step only for `unknown`; `other` and a `debug` that never lands fell through to a reload EVERY
    sweep and a RESTART every sweep whenever the reload was refused or lost (or the daemon had no config-reload). No counter; the prose said "Jen has left it".
    An `other` daemon is now left alone; a `debug` daemon gets RELOAD_TRIES reloads, then ONE restart per entry, then nothing."""

    def _other_after_turn_off(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        real = kea.kea_command

        def reload_lands_on_warn(command, **kw):
            if command == "config-reload":
                kea.calls.append(command)
                kea.loaded = _cfg([{"name": "kea-dhcp4", "severity": "WARN", "debuglevel": 0}])
                return {"result": 0, "text": "reloaded"}
            return real(command, **kw)

        kea.kea_command = reload_lands_on_warn
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is False and inv.active()[0]["daemon"] == "other"
        return kea, real

    def test_an_other_daemon_over_five_sweeps_gets_zero_reloads_and_zero_restarts_and_health_fails(self, world):
        from jen.services import health

        kea, _real = self._other_after_turn_off(world)
        reloads, restarts = _reloads(kea), _restarts(kea)
        for minute in range(1, 6):
            out = inv.sweep(now=NOW + timedelta(minutes=minute))
            assert out["restored"] == [] and out["errors"], minute
        assert (_reloads(kea) - reloads, _restarts(kea) - restarts) == (0, 0), kea.calls
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "left it alone" in c.detail and "WARN" in c.detail and "Forget" in c.detail
        (entry,) = inv.active(NOW)
        assert entry["needs_hand"] and entry["pending"] is None
        print(
            f"F1 other daemon over five sweeps: reloads {_reloads(kea) - reloads}, restarts {_restarts(kea) - restarts}"
        )

    def test_the_other_daemon_can_be_forgotten_after_an_observation(self, world):
        kea, _real = self._other_after_turn_off(world)
        assert inv.forget(1, actor="alice") is True and not inv.active()
        assert [a[0] for a in world.store["_audit"]].count("INVESTIGATION_LOGGING_FORGOTTEN") == 1

    def test_a_debug_daemon_whose_reloads_never_land_gets_three_reloads_one_restart_then_nothing(self, world):
        from jen.services import health

        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        reloads0, restarts0 = _reloads(kea), _restarts(kea)
        kea.reload_ignored = kea.restart_ignored = True  # Kea says ok and stays at DEBUG
        assert inv.turn_off(world.servers[0])["ok"] is False
        for minute in range(1, 9):
            inv.sweep(now=NOW + timedelta(minutes=minute))
        reloads, restarts = _reloads(kea) - reloads0, _restarts(kea) - restarts0
        assert (reloads, restarts) == (3, 1), kea.calls
        (entry,) = inv.active(NOW)
        assert entry["exhausted"] and entry["needs_hand"] and entry["daemon"] == "debug"
        c = health._debug_logging_left_on({})
        assert (
            c.status == "fail"
            and "Jen reloaded 3 times and restarted once" in c.detail
            and "restore it by hand" in c.detail
        )
        assert "10.0.0.1" in c.detail and "Forget" in c.detail
        # the button after that does nothing more either, and says the same
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is False and "restore it by hand" in out["lines"][-1]
        assert (_reloads(kea) - reloads0, _restarts(kea) - restarts0) == (3, 1)
        print(f"F1 debug daemon that never lands over nine attempts: reloads {reloads}, restarts {restarts}")

    def test_a_person_who_reloads_it_by_hand_ends_it_without_forget(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_ignored = kea.restart_ignored = True
        inv.turn_off(world.servers[0])
        for minute in range(1, 7):
            inv.sweep(now=NOW + timedelta(minutes=minute))
        assert inv.active()[0]["exhausted"]
        kea.loaded = copy.deepcopy(kea.file)  # the person ran config-reload themselves
        calls = len(kea.calls)
        assert inv.sweep(now=NOW + timedelta(minutes=7))["restored"] == ["kea-a"] and not inv.active()
        assert not any(c in ("config-reload", "restart:dhcp4") for c in kea.calls[calls:])

    def test_a_refused_reload_restarts_once_and_then_the_count_runs_out(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        reloads0, restarts0 = _reloads(kea), _restarts(kea)
        kea.reload_result, kea.reload_text, kea.restart_ignored = 1, "refused", True
        inv.turn_off(world.servers[0])
        for minute in range(1, 9):
            inv.sweep(now=NOW + timedelta(minutes=minute))
        assert _restarts(kea) - restarts0 == 1, "ONE restart per entry, never a second"
        assert _reloads(kea) - reloads0 == 3

    def test_a_daemon_with_no_config_reload_is_restarted_once_not_every_minute(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.restart_ignored = True
        restarts0 = _restarts(kea)
        for minute in range(6, 12):
            inv.sweep(now=NOW + timedelta(minutes=minute))
        assert _restarts(kea) - restarts0 <= 1, kea.calls


class TestATurnOnThatRestartedKeaAndSawOtherIsNotSuccess:
    """F2: the restart branch kept the entry and answered ok=True (with an audit row) for a daemon seen at NEITHER level, while the reload branch reverted
    for the same observation. A daemon at a third level did not take the file."""

    def test_the_file_goes_back_nothing_is_restarted_again_and_the_entry_is_kept_unconfirmed(self, world):
        from jen.services import health

        kea = world.daemons[1]
        kea.commands = ["version-get"]
        real = kea.apply_change

        def restart_lands_on_warn(service, mutate_fn, summary, **kw):
            result = real(service, mutate_fn, summary, **kw)
            kea.loaded = _cfg([{"name": "kea-dhcp4", "severity": "WARN", "debuglevel": 0}])
            return result

        kea.apply_change = restart_lands_on_warn
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and out["until"] == "" and "_audit" not in world.store
        assert ed.investigation_marker(kea.file) is None, "the file was put back"
        assert _restarts(kea) == 0 and sum(c.startswith("apply(restart=True)") for c in kea.calls) == 1, (
            "no second restart"
        )
        (entry,) = inv.active()
        assert entry["daemon"] == "other" and entry["file"] == "restored" and entry["pending"] is None
        assert health._debug_logging_left_on({}).status == "fail"


class TestContradictoryEvidenceIsNamedNotIndexedAsNothing:
    """F3: a daemon restarted (or reloaded) on a DEBUG file and then shown at its ORIGINAL level cannot be the daemon that read the file: the API Jen asks is
    answering for a different Kea than the one SSH edits. beta.23 reverted the file and indexed NOTHING, leaving the box SSH touched at DEBUG 55 with a clean
    file, and the full scan reading the other daemon."""

    def test_a_restart_that_left_the_apis_daemon_at_its_original_level_is_a_contradiction(self, world):
        from jen.services import health

        kea = world.daemons[1]
        kea.commands = ["version-get"]
        kea.restart_ignored = True  # the daemon the API answers for did not move
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and ed.investigation_marker(kea.file) is None and "_audit" not in world.store
        assert any(
            "is not running the file Jen wrote" in line and "api_url and ssh_host" in line for line in out["lines"]
        ), out["lines"]
        assert _restarts(kea) == 0 and sum(c.startswith("apply(restart=True)") for c in kea.calls) == 1
        (entry,) = inv.active()
        assert (
            entry["contradiction"] and entry["daemon"] == "other" and "not running the file Jen wrote" in entry["seen"]
        )
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "api_url" in c.detail and "ssh_host" in c.detail and "10.0.0.1" in c.detail
        assert "Forget" in c.detail

    def test_a_reload_whose_reply_said_ok_but_whose_api_daemon_is_a_second_kea_is_a_contradiction(self, world):
        kea = world.daemons[1]
        kea.second = _cfg([{"name": "kea-dhcp4", "severity": "INFO"}])  # config-get answers from ANOTHER daemon
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and not any(c.startswith("restart") for c in kea.calls)
        assert ed.investigation_marker(kea.file) is None
        (entry,) = inv.active()
        assert entry["contradiction"] and entry["daemon"] == "other"
        assert any("Kea said it reloaded" in line for line in out["lines"])

    def test_a_refused_reload_with_the_daemon_at_its_original_level_is_still_just_not_activated(self, world):
        kea = world.daemons[1]
        kea.reload_result, kea.reload_text = 1, "refused"
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and not inv.active() and not _daemon_at_debug(kea)

    def test_the_contradiction_survives_the_sweeps_and_only_forget_ends_it(self, world):
        """F10 (fixup 5): the entry is `file=restored`, so it is due every minute, and the restore's nothing branch observed the SAME wrong daemon,
        which shows the captured original level, read "restored" and dropped it - one sweep later. Nothing is reloaded or restarted for it and no
        observation ends it."""
        from jen.services import health

        kea = world.daemons[1]
        kea.commands = ["version-get"]
        kea.restart_ignored = True
        inv.turn_on(world.servers[0], 5)
        assert inv.active()[0]["contradiction"]
        reloads0, restarts0 = _reloads(kea), _restarts(kea)
        writes0 = kea.writes
        for minute in (1, 2, 3):
            out = inv.sweep(now=NOW + timedelta(minutes=minute))
            assert out["restored"] == [], minute
        (entry,) = inv.active(NOW + timedelta(minutes=3))
        assert entry["contradiction"] and entry["needs_hand"] and entry["pending"] is None
        assert (_reloads(kea) - reloads0, _restarts(kea) - restarts0) == (0, 0), kea.calls
        assert kea.writes == writes0, "the file is already clean: the sweeps wrote (and so restarted) nothing"
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "api_url" in c.detail and "ssh_host" in c.detail
        # the button does not end it either
        assert inv.turn_off(world.servers[0])["ok"] is False and inv.active()
        assert inv.forget(1, actor="alice") is True and not inv.active(), "Forget (after a look) is what ends it"
        print(
            f"F10 contradiction over three sweeps + Turn off: reloads {_reloads(kea) - reloads0}, restarts {_restarts(kea) - restarts0}"
        )

    def test_the_contradiction_can_be_forgotten_once_a_person_has_looked(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        kea.restart_ignored = True
        inv.turn_on(world.servers[0], 5)
        assert inv.active()[0]["contradiction"]
        assert inv.forget(1, actor="alice") is True and not inv.active()


class TestTheWritesAfterALostReplyAreChecked:
    """F4: the three puts after a lost reply ignored `_put`. When the one after the revert failed, the STORED entry stayed `file=debug` while the file was
    clean, and the cheap block then observed `debug` and set `pending=None`: Health said "on", the response promised a reload, and DEBUG ran on a clean file
    until the deadline."""

    @staticmethod
    def _after_revert(value):
        return any(
            e.get("file") == "restored" and e.get("daemon") == "debug" and e.get("pending") == "reload"
            for e in _servers_of(value).values()
        )

    def test_a_failed_write_after_the_revert_is_said_and_the_sweep_finishes_it_from_the_file(self, world):
        kea = world.daemons[1]
        kea.reload_applied_but_lost = True
        world.db["fails"] = self._after_revert
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False
        assert any("Jen could not record this" in line and "ten-minute scan" in line for line in out["lines"]), out[
            "lines"
        ]
        (stored,) = inv.active()
        assert stored["file"] == "debug" and stored["daemon"] == "unknown", "the stored entry is the OLD one"
        world.db["fails"] = None
        kea.reload_applied_but_lost = False
        inv.sweep(now=NOW + timedelta(minutes=1))  # the cheap block: observes DEBUG, reads the file: it is clean
        (entry,) = inv.active(NOW + timedelta(minutes=1))
        assert entry["file"] == "restored" and entry["pending"] == "reload", (
            "pending is NOT cleared for an entry whose file disagrees"
        )
        assert inv.sweep(now=NOW + timedelta(minutes=2))["restored"] == ["kea-a"] and not inv.active()
        assert not _daemon_at_debug(kea)

    def test_a_marker_still_in_the_file_does_clear_pending_when_the_daemon_is_seen_at_debug(self, world):
        kea = world.daemons[1]
        real = kea.kea_command
        kea.kea_command = lambda command, **kw: (
            {"result": 1, "text": "connection refused"} if command == "config-get" else real(command, **kw)
        )
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.kea_command = real
        inv.sweep(now=NOW + timedelta(minutes=1))
        (entry,) = inv.active(NOW + timedelta(minutes=1))
        assert entry["daemon"] == "debug" and entry["pending"] is None and entry["file"] == "debug"

    def test_the_orphan_and_adoption_writes_log_a_warning_when_they_fail(self, world, caplog):
        import logging

        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers.pop(0)
        world.db["fails"] = lambda value: True
        with caplog.at_level(logging.WARNING, logger=inv.logger.name):
            inv.sweep(now=NOW)
        assert "removed-server flag" in caplog.text
        caplog.clear()
        world.servers.insert(0, {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"})
        world.db["fails"] = None
        inv.forget(1)
        live, _ = ed.set_investigation_logging(world.daemons[2].file, FUTURE)
        world.daemons[2].file = world.daemons[2].loaded = live
        world.db["fails"] = lambda value: True
        with caplog.at_level(logging.WARNING, logger=inv.logger.name):
            inv.sweep(now=NOW, full=True)
        assert "adopted entry" in caplog.text

    def test_the_architecture_names_the_writes_that_are_checked(self):
        import pathlib

        text = (pathlib.Path(__file__).resolve().parent.parent / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "every write of the index is checked" not in text, "(d) said 'every write'; it names the ones that are"
        assert "`_did_not_take`" in text and "the writes that are checked" in text


class TestForgetObservesFirst:
    """F5: `forget` dropped a `marker_invalid` entry on the file alone and ignored `_drop`'s bool, writing the audit row regardless."""

    def test_it_refuses_while_the_daemon_is_seen_at_debug_with_the_marker(self, world):
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 60)["ok"]
        _entry(kea.file)["user-context"]["jen-investigation"].pop("restore")
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        clean = _entry(kea.file)
        clean["severity"], clean["debuglevel"] = "INFO", 0
        del clean["user-context"]
        assert inv.forget(1) is False, "the file was fixed but Kea still runs investigation DEBUG"
        assert "INVESTIGATION_LOGGING_FORGOTTEN" not in [a[0] for a in world.store["_audit"]]

    def test_the_audit_row_is_written_only_when_the_entry_is_really_gone(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers.pop(0)
        inv.sweep(now=NOW)
        world.db["fails"] = lambda value: value == ""
        assert inv.forget(1, actor="alice") is False and inv.active()
        assert "INVESTIGATION_LOGGING_FORGOTTEN" not in [a[0] for a in world.store["_audit"]]
        world.db["fails"] = None
        assert inv.forget(1, actor="alice") is True
        assert [a[0] for a in world.store["_audit"]].count("INVESTIGATION_LOGGING_FORGOTTEN") == 1

    def test_an_entry_unconfirmable_for_over_an_hour_may_be_forgotten_a_fresh_one_may_not(self, world):
        kea = world.daemons[1]
        kea.reload_result, kea.reload_text, kea.api_silent = 1, "connection refused", True
        inv.turn_on(world.servers[0], 5)
        assert inv.active()[0]["daemon"] == "unknown"
        assert inv.forget(1) is False, "five minutes: waiting may still learn something"
        later = NOW + timedelta(hours=2)
        import pytest as _pytest

        with _pytest.MonkeyPatch.context() as mp:
            mp.setattr(inv, "_now", lambda: later)
            assert inv.forget(1) is True and not inv.active(later)


class TestHealthWarnsForAFileAtDebugThatKeaIsNotRunning:
    def test_a_live_marker_the_daemon_never_loaded_is_a_warn_not_an_ok(self, world):
        from jen.services import health

        kea = world.daemons[1]
        live, _ = ed.set_investigation_logging(kea.file, FUTURE)
        kea.file = live  # written, never reloaded
        inv.sweep(now=NOW, full=True)
        (entry,) = inv.active(NOW)
        assert entry["not_loaded"] and entry["file"] == "debug" and entry["daemon"] == "restored"
        c = health._debug_logging_left_on({})
        assert c.status == "warn" and "not running it" in c.detail and "has not been reloaded" in c.detail

    def test_a_healthy_entry_is_still_ok(self, world):
        from jen.services import health

        assert inv.turn_on(world.servers[0], 5)["ok"]
        assert health._debug_logging_left_on({}).status == "ok"


class TestAMovedDaemonWithASilentApiIsFinishedWhenTheApiReturns:
    """F9: Kea APPLIED the reload, the reply was lost, AND the API then stopped answering. Nothing may be reloaded or restarted on a guess while it is
    silent; when it returns: seen at DEBUG -> one reload -> seen restored -> dropped."""

    def test_silent_then_back(self, world):
        kea = world.daemons[1]
        kea.reload_applied_but_lost = True
        real = kea.kea_command
        kea.kea_command = lambda command, **kw: (
            {"result": 1, "text": "connection refused"} if command == "config-get" else real(command, **kw)
        )
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and _daemon_at_debug(kea) and ed.investigation_marker(kea.file) is None
        (entry,) = inv.active()
        assert (entry["file"], entry["daemon"]) == ("restored", "unknown")
        reloads0, restarts0 = _reloads(kea), _restarts(kea)
        for minute in (1, 2, 3):
            assert inv.sweep(now=NOW + timedelta(minutes=minute))["restored"] == []
        assert (_reloads(kea) - reloads0, _restarts(kea) - restarts0) == (0, 0), "silent: nothing on a guess"
        kea.kea_command = real  # the API returns
        kea.reload_applied_but_lost = False
        assert inv.sweep(now=NOW + timedelta(minutes=4))["restored"] == ["kea-a"] and not inv.active()
        assert (_reloads(kea) - reloads0, _restarts(kea) - restarts0) == (1, 0)
        assert not _daemon_at_debug(kea)


# ── v5.68.0-beta.24 (Q159): "debug" means DEBUG 55 exactly, and a damaged record fails closed ─────────────────────────────────────────


_MISSING = object()


def _marked_logger(severity, debuglevel):
    """A running kea-dhcp4 logger that carries a valid jen-investigation marker, at the given severity and debuglevel."""
    entry = {
        "name": "kea-dhcp4",
        "severity": severity,
        "user-context": {
            "jen-investigation": {"until": FUTURE, "restore": {"severity": "INFO", "debuglevel": "absent"}}
        },
    }
    if debuglevel is not _MISSING:
        entry["debuglevel"] = debuglevel
    return _cfg([entry])


class TestDebugMeansDebugFiftyFiveExactly:
    """Item 1: `observe` classified "debug" for any DEBUG logger carrying the marker; the predicate for "at the investigation level" existed
    (`_at_investigation_level`: DEBUG AND debuglevel 55) and the classification did not use it. A DEBUG 0 / DEBUG 30 logger with the marker was reported
    as investigation logging active: turn_on said success, cleared pending, and Health said "on"."""

    @pytest.mark.parametrize(
        "severity, level, state, seen",
        [
            ("DEBUG", 0, "other", "DEBUG at debuglevel 0, not 55"),
            ("DEBUG", 30, "other", "DEBUG at debuglevel 30, not 55"),
            ("DEBUG", 55, "debug", "DEBUG / debuglevel 55"),
            ("INFO", 0, "other", "INFO / debuglevel 0"),
            ("DEBUG", _MISSING, "other", "DEBUG at debuglevel None, not 55"),
            ("DEBUG", "55", "other", "DEBUG at debuglevel 55, not 55"),
        ],
        ids=["debug-0", "debug-30", "debug-55", "info-0", "debuglevel-missing", "debuglevel-a-string"],
    )
    def test_the_six_cases_each_with_a_valid_marker(self, world, severity, level, state, seen):
        world.daemons[1].loaded = _marked_logger(severity, level)
        entry = {"restore": {"severity": "INFO", "debuglevel": "absent"}}
        assert inv.observe(world.servers[0], entry) == state
        assert entry["daemon"] == state and entry["seen"] == seen, entry

    def test_a_reload_that_lands_on_debug_thirty_is_not_success(self, world):
        from jen.services import health

        kea = world.daemons[1]
        real = kea.kea_command

        def lands_on_debug_30(command, **kw):
            result = real(command, **kw)
            if command == "config-reload":
                _entry(kea.loaded)["debuglevel"] = 30
            return result

        kea.kea_command = lands_on_debug_30
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and out["until"] == "" and "_audit" not in world.store
        assert ed.investigation_marker(kea.file) is None, "the file went back"
        (entry,) = inv.active()
        assert (
            entry["daemon"] == "other"
            and entry["seen"] == "DEBUG at debuglevel 30, not 55"
            and entry["pending"] is None
        )
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "left it alone" in c.detail and "DEBUG at debuglevel 30, not 55" in c.detail

    def test_the_full_scan_adopts_debug_fifty_five_and_not_debug_thirty(self, world):
        kea = world.daemons[1]
        kea.loaded = _marked_logger("DEBUG", 30)  # clean file, running DEBUG 30 with the marker
        assert inv.sweep(now=NOW, full=True) == {"restored": [], "adopted": [], "errors": []}
        assert not inv.active() and not any(c.startswith(("config-reload", "restart")) for c in kea.calls)
        kea.loaded = _marked_logger("DEBUG", 55)
        out = inv.sweep(now=NOW, full=True)
        assert (
            out["adopted"] == ["kea-a"]
            and out["restored"] == ["kea-a"]
            and not _daemon_at_debug(kea)
            and not inv.active()
        )

    def test_nothing_classifies_by_severity_alone(self):
        """The self-check, as a test: INVESTIGATION_SEVERITY appears only inside `_at_investigation_level`, `_is_original` and `_describe`."""
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(inv))
        users = {
            fn.name
            for fn in ast.walk(tree)
            if isinstance(fn, ast.FunctionDef)
            and any(isinstance(n, ast.Attribute) and n.attr == "INVESTIGATION_SEVERITY" for n in ast.walk(fn))
        }
        assert users == {"_at_investigation_level", "_is_original", "_describe"}, users


class TestADamagedRecordFailsClosed:
    """Item 3: `_record()` read a stored value that was not a JSON object with a `servers` object as an EMPTY index. The one-server rule then allowed a
    second session, the next write overwrote the damaged value, and only the ten-minute scan could rediscover a running DEBUG."""

    @staticmethod
    def _damage(world, raw):
        world.store[inv.RECORD_KEY] = raw

    def test_an_empty_value_and_an_empty_record_are_not_damaged(self, world):
        assert inv._record() == {"servers": {}, "damaged": False, "raw": "", "bad": []}
        self._damage(world, '{"servers": {}}')
        assert inv._record()["damaged"] is False and inv.turn_on(world.servers[0], 5)["ok"]

    def test_one_active_server_is_a_valid_record(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        record = inv._record()
        assert record["damaged"] is False and list(record["servers"]) == ["1"]

    @pytest.mark.parametrize(
        "raw",
        [
            '{"servers": ',
            "not json at all",
            "[]",
            '"a string"',
            "42",
            '{"nope": 1}',
            '{"servers": []}',
            '{"servers": "x"}',
        ],
    )
    def test_malformed_and_wrong_shaped_values_are_damaged_and_turn_on_is_refused(self, world, raw):
        from jen.services import health

        self._damage(world, raw)
        record = inv._record()
        assert record["damaged"] is True and record["servers"] == {} and record["raw"] == raw
        kea = world.daemons[1]
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and "cannot be read; see Health" in out["lines"][0]
        assert kea.writes == 0 and kea.calls == [] and world.store[inv.RECORD_KEY] == raw, (
            "nothing asked, nothing written, nothing overwritten"
        )
        assert inv.active() == []
        c = health._debug_logging_left_on({})
        assert (
            c.status == "fail"
            and "`investigation_logging` setting" in c.detail
            and "investigation_logging.damaged" in c.detail
        )

    def test_the_damaged_value_is_kept_once_before_anything_overwrites_it(self, world):
        self._damage(world, "{broken")
        inv.sweep(
            now=NOW
        )  # while damaged EVERY sweep is the recovery phase (Q160), full or not: every server was read, none holds a marker
        assert world.store[inv.DAMAGED_KEY] == "{broken", "the old value, kept"
        assert world.store[inv.RECORD_KEY] == "" and inv._record()["damaged"] is False
        self._damage(world, "[1, 2]")  # damaged again: the first copy is NOT replaced
        inv.sweep(now=NOW, full=True)
        assert world.store[inv.DAMAGED_KEY] == "{broken"

    def test_if_the_old_value_cannot_be_kept_nothing_is_overwritten(self, world, monkeypatch):
        self._damage(world, "{broken")

        def refuse_the_copy(key, value):  # the settings table refuses the DAMAGED_KEY write only
            if key == inv.DAMAGED_KEY:
                return False
            world.store[key] = value
            return True

        monkeypatch.setattr("jen.models.user.set_global_setting", refuse_the_copy)
        out = inv.sweep(now=NOW, full=True)
        assert world.store[inv.RECORD_KEY] == "{broken" and inv._record()["damaged"] is True
        assert out["errors"] and "could not be rebuilt" in out["errors"][-1]

    def test_a_server_the_scan_could_not_read_leaves_the_record_damaged(self, world, monkeypatch):
        self._damage(world, "{broken")
        real = inv._host.read_config_versioned

        def unreadable_b(server, service):
            if server["id"] == 2:
                raise OSError("no route")
            return real(server, service)

        monkeypatch.setattr(inv._host, "read_config_versioned", unreadable_b)
        out = inv.sweep(now=NOW, full=True)
        assert out["errors"] and inv._record()["damaged"] is True and world.store[inv.RECORD_KEY] == "{broken", (
            "that server may be the one at DEBUG"
        )

    def test_malformed_while_a_daemon_runs_debug_the_other_server_is_refused_the_scan_adopts_and_the_record_is_repaired(
        self, world
    ):
        from jen.services import health

        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 60)["ok"] and _daemon_at_debug(kea)
        self._damage(world, "{this was the record")  # the record is lost while kea-a keeps running DEBUG 55
        assert inv.active() == []
        refused = inv.turn_on(world.servers[1], 5)
        assert refused["ok"] is False and "cannot be read" in refused["lines"][0] and world.daemons[2].writes == 0
        assert health._debug_logging_left_on({}).status == "fail"
        out = inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert out["adopted"] == ["kea-a"] and out["errors"] == []
        assert inv._record()["damaged"] is False and [e["name"] for e in inv.active(NOW)] == ["kea-a"]
        assert world.store[inv.DAMAGED_KEY] == "{this was the record"
        assert health._debug_logging_left_on({}).status == "ok", "the next page load"
        assert inv.sweep(now=NOW + timedelta(minutes=2))["errors"] == [], "the next sweep"
        assert _daemon_at_debug(kea), "the adopted logging is still on, and still indexed"
        assert inv.turn_off(world.servers[0])["ok"] and not inv.active() and not _daemon_at_debug(kea)


# ── v5.68.0-beta.25 (Q160): the damaged-index recovery is a separate phase that writes nothing until every server was examined ────────


class TestTheRecoveryWritesNothingUntilEveryServerWasExamined:
    """Items 1 and 2: beta.24 rebuilt a damaged index inside the ordinary full scan, where every discovery was written at once and the first write cleared
    the damaged flag - one adopted server plus one unreadable server left the index healthy with one entry, and the unreadable server may be the one at
    DEBUG 55; and a clean file whose daemon could not be read counted as examined. Recovery is its own phase now: every SSH server's file AND running daemon
    are read into an in-memory candidate, a server that could not be examined is a problem, and unless there are none NOTHING is written. Every test below
    asserts the STORED value (and the setting that keeps the old one), not the return."""

    DAMAGED = "{this was the record"

    @pytest.fixture
    def three(self, world):
        """A third server, so one can be refused while two are examined."""
        world.daemons[3] = FakeKea(_cfg())
        world.servers.append({"id": 3, "name": "kea-c", "ssh_host": "10.0.0.3"})
        world.store[inv.RECORD_KEY] = self.DAMAGED
        return world

    @staticmethod
    def _unreadable(world, monkeypatch, sid):
        real = inv._host.read_config_versioned

        def read(server, service):
            if server["id"] == sid:
                raise OSError("no route")
            return real(server, service)

        monkeypatch.setattr(inv._host, "read_config_versioned", read)

    @staticmethod
    def _stored_servers(world):
        return _servers_of(world.store.get(inv.RECORD_KEY, ""))

    def test_a_marker_on_a_and_an_unreadable_config_on_b_writes_nothing_and_turn_on_stays_refused(
        self, three, monkeypatch
    ):
        from jen.services import health

        live, _ = ed.set_investigation_logging(three.daemons[1].file, FUTURE)
        three.daemons[1].file = three.daemons[1].loaded = live
        self._unreadable(three, monkeypatch, 2)
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == [] and any("kea-b: config unreadable" in e for e in out["errors"])
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv.DAMAGED_KEY not in three.store, (
            "nothing was written, not even for the server that WAS readable"
        )
        assert inv._record()["damaged"] is True
        refused = inv.turn_on(three.servers[2], 5)
        assert refused["ok"] is False and "cannot be read" in refused["lines"][0] and three.daemons[3].writes == 0
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "kea-b: config unreadable" in c.detail and "could not examine" in c.detail

    def test_a_live_marker_on_a_and_a_damaged_marker_on_b_are_both_written_once_with_b_flagged(self, three):
        live, _ = ed.set_investigation_logging(three.daemons[1].file, FUTURE)
        three.daemons[1].file = three.daemons[1].loaded = live
        bad, _ = ed.set_investigation_logging(three.daemons[2].file, FUTURE)
        _entry(bad)["user-context"]["jen-investigation"].pop("restore")
        three.daemons[2].file = three.daemons[2].loaded = bad
        out = inv.sweep(now=NOW, full=True)
        assert sorted(out["adopted"]) == ["kea-a", "kea-b"] and out["errors"] == []
        stored = self._stored_servers(three)
        assert (
            sorted(stored) == ["1", "2"]
            and stored["2"]["marker_invalid"] is True
            and "marker_invalid" not in stored["1"]
        )
        assert stored["1"]["daemon"] == "debug" and stored["1"]["restore"] == {
            "severity": "INFO",
            "debuglevel": "absent",
        }
        assert three.store[inv.DAMAGED_KEY] == self.DAMAGED and inv._record()["damaged"] is False

    def test_every_server_examined_is_one_write_with_the_old_value_kept(self, three, monkeypatch):
        live, _ = ed.set_investigation_logging(three.daemons[1].file, FUTURE)
        three.daemons[1].file = three.daemons[1].loaded = live
        import jen.models.user as usermod

        writes, original = [], usermod.set_global_setting

        def counting(key, value):
            writes.append(key)
            return original(key, value)

        monkeypatch.setattr(usermod, "set_global_setting", counting)
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"]
        assert writes == [inv.DAMAGED_KEY, inv.RECORD_KEY], writes  # the old value, then ONE write of the record
        assert three.store[inv.DAMAGED_KEY] == self.DAMAGED
        assert list(self._stored_servers(three)) == ["1"] and inv._record()["damaged"] is False
        assert [e["name"] for e in inv.active(NOW)] == ["kea-a"]

    def test_the_database_failing_at_the_final_write_leaves_the_damaged_value_stored(self, three):
        live, _ = ed.set_investigation_logging(three.daemons[1].file, FUTURE)
        three.daemons[1].file = three.daemons[1].loaded = live
        three.db["fails"] = lambda value: True
        out = inv.sweep(now=NOW, full=True)
        assert any("could not be rebuilt" in e for e in out["errors"])
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv._record()["damaged"] is True

    def test_a_clean_file_with_an_unreachable_daemon_is_not_examined(self, three):
        from jen.services import health

        three.daemons[2].api_silent = True
        out = inv.sweep(now=NOW, full=True)
        assert any("kea-b: running daemon not observed" in e for e in out["errors"])
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv._record()["damaged"] is True
        assert "kea-b: running daemon not observed" in health._debug_logging_left_on({}).detail

    def test_a_clean_file_with_the_daemon_at_debug_is_adopted_and_restored_on_the_next_sweep(self, three):
        kea = three.daemons[1]
        kea.loaded = _marked_logger("DEBUG", 55)  # the file is clean, the daemon runs DEBUG 55 under the marker
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"] and out["restored"] == []
        stored = self._stored_servers(three)["1"]
        assert (stored["file"], stored["daemon"], stored["pending"]) == ("restored", "debug", "reload")
        assert _daemon_at_debug(kea), "the recovery itself restored nothing"
        nxt = inv.sweep(now=NOW + timedelta(minutes=1))
        assert nxt["restored"] == ["kea-a"] and not _daemon_at_debug(kea) and self._stored_servers(three) == {}

    def test_a_marker_in_the_file_with_an_unreachable_daemon_stays_damaged(self, three):
        live, _ = ed.set_investigation_logging(three.daemons[1].file, FUTURE)
        three.daemons[1].file = live
        three.daemons[1].api_silent = True
        inv.sweep(now=NOW, full=True)
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv._record()["damaged"] is True

    def test_mixed_known_and_unknown_daemons_stay_damaged(self, three):
        three.daemons[1].loaded = _marked_logger("DEBUG", 55)
        three.daemons[3].api_silent = True
        inv.sweep(now=NOW, full=True)
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv.DAMAGED_KEY not in three.store
        three.daemons[3].api_silent = False  # the next minute: everything is readable
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert list(self._stored_servers(three)) == ["1"] and inv._record()["damaged"] is False

    def test_a_scan_interrupted_mid_way_writes_nothing(self, three, monkeypatch):
        real = inv.daemon_logger

        def blows_up_on_b(server):
            if server["id"] == 2:
                raise RuntimeError("the fake raised mid-scan")
            return real(server)

        monkeypatch.setattr(inv, "daemon_logger", blows_up_on_b)
        three.daemons[1].loaded = _marked_logger("DEBUG", 55)
        out = inv.sweep(now=NOW, full=True)
        assert any("kea-b: running daemon not observed (RuntimeError)" in e for e in out["errors"])
        assert three.store[inv.RECORD_KEY] == self.DAMAGED and inv.DAMAGED_KEY not in three.store

    def test_the_full_scan_runs_on_every_tick_while_damaged_and_on_every_tenth_otherwise(self, three, monkeypatch):
        reads = []
        real = inv._host.read_config_versioned
        monkeypatch.setattr(inv._host, "read_config_versioned", lambda s, svc: reads.append(s["id"]) or real(s, svc))
        three.daemons[3].api_silent = True  # recovery cannot finish: it stays damaged, tick after tick
        for _ in range(3):
            inv.run_sweep_job()
        assert len(reads) == 3 * 3, reads  # three servers read on EACH of the three ticks
        three.daemons[3].api_silent = False
        inv.run_sweep_job()  # the tick that rebuilds it
        assert inv._record()["damaged"] is False
        reads.clear()
        for _ in range(3):
            inv.run_sweep_job()
        assert reads == [], "healthy again: the cheap path, no full reads until every tenth run"

    def test_the_next_sweep_after_a_recovery_does_the_ordinary_work(self, three):
        """The trace for `_recovery_status`: a failed attempt is shown by Health; a successful one ends the damaged state and the status says rebuilt."""
        from jen.services import health

        three.daemons[2].api_silent = True
        inv.sweep(now=NOW, full=True)
        assert inv.recovery_status()["rebuilt"] is False and inv.recovery_status()["problems"]
        assert health._debug_logging_left_on({}).status == "fail"
        three.daemons[2].api_silent = False
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert inv.recovery_status() == {"at": inv._iso(NOW + timedelta(minutes=1)), "problems": [], "rebuilt": True}
        assert health._debug_logging_left_on({}).status == "ok"


class TestEveryStoredEntryIsValidated:
    """Item 4: `_record` validated the outer shape only: `{"servers": {"2": {}}}` or `{"servers": {"2": null}}` read as healthy, and `turn_on`'s
    `others = [e["name"] ...]` raised KeyError / TypeError, as did every reader of `entry.get(...)` on a non-dict."""

    @pytest.mark.parametrize(
        "raw",
        [
            '{"servers": {"2": {}}}',
            '{"servers": {"2": null}}',
            '{"servers": {"2": []}}',
            '{"servers": {"2": {"name": 42}}}',
        ],
        ids=["empty-entry", "null-entry", "list-entry", "name-not-a-string"],
    )
    def test_a_malformed_entry_is_damaged_nothing_raises_and_recovery_repairs_it(self, world, raw):
        from jen.services import health

        world.store[inv.RECORD_KEY] = raw
        record = inv._record()
        assert record["damaged"] is True and record["bad"] == ["2"] and record["servers"] == {}
        assert inv.active() == []
        assert inv.turn_on(world.servers[0], 5)["ok"] is False, "a second session is refused"
        assert inv.turn_on(world.servers[1], 5)["ok"] is False
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "entry for server 2 is malformed" in c.detail
        assert (
            inv.sweep(now=NOW)["errors"] == []
        )  # does not raise: the recovery examined both servers, found nothing, rebuilt
        assert world.store[inv.RECORD_KEY] == "" and world.store[inv.DAMAGED_KEY] == raw
        assert inv._record()["damaged"] is False and health._debug_logging_left_on({}).status == "ok"

    def test_a_valid_entry_of_every_shape_this_module_writes_is_accepted(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        stored = _servers_of(world.store[inv.RECORD_KEY])["1"]
        assert inv._valid_entry(stored) and inv._record()["damaged"] is False
        for field, value in (
            ("reload_tries", 2),
            ("restarted", True),
            ("contradiction", False),
            ("history_revision", None),
            ("history_revision", 41),
            ("restore", {"created": True}),
            ("error", "text"),
            ("seen", "INFO / debuglevel 0"),
        ):
            assert inv._valid_entry({**stored, field: value}), field
        for field, value in (
            ("reload_tries", True),
            ("reload_tries", "2"),
            ("restarted", 1),
            ("restore", "x"),
            ("ssh_host", 5),
            ("file", "elsewhere"),
            ("daemon", "asleep"),
            ("pending", "later"),
            ("history_revision", "41"),
        ):
            assert not inv._valid_entry({**stored, field: value}), (field, value)

    def test_the_malformed_entry_is_never_read_by_row_or_readers(self, world):
        world.store[inv.RECORD_KEY] = '{"servers": {"1": {"name": "kea-a", "until": "x"}, "2": null}}'
        # (Q161 flipped this: the removal decision used to read the empty map of a damaged record as "nothing blocks it")
        assert [b["server_id"] for b in inv.blocking_removal([1, 2])] == ["1", "2"]
        assert inv.removal_refusal([1]) != "" and inv.forget(2) is False


class TestTheRecoveryBlockHasNoWrites:
    """Self-check (a), as a test: the block that examines the servers calls no write helper at all, and the phase that follows it has exactly one `_save`
    and no `_put` / `_drop` - a damaged record is replaced by ONE write, never piecemeal."""

    @staticmethod
    def _calls(name):
        import ast
        import inspect

        fn = next(
            n for n in ast.walk(ast.parse(inspect.getsource(inv))) if isinstance(n, ast.FunctionDef) and n.name == name
        )
        return [c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]

    def test_examining_calls_no_write_helper(self):
        assert not {"_put", "_save", "_drop"} & set(self._calls("_recovery_candidates"))

    def test_the_phase_has_one_save_and_no_put(self):
        calls = self._calls("_recover")
        assert calls.count("_save") == 1 and "_put" not in calls and "_drop" not in calls

    def test_put_and_drop_refuse_a_damaged_record(self, world):
        world.store[inv.RECORD_KEY] = "{broken"
        record = inv._record()
        assert inv._put(record, 1, {"name": "x", "until": ""}) is False and inv._drop(record, 1) is True
        assert world.store[inv.RECORD_KEY] == "{broken"


class TestRemovalIsRefusedWhileTheRecordIsDamaged:
    """Item 1: `blocking_removal` read `_record()["servers"]`, got `{}` from a damaged record, and `removal_refusal` answered "" - so a server at DEBUG 55 whose
    entry was in the unreadable value could be removed from Settings, and with it the only way to put it back. Every assertion is on the stored record and the
    audit row, not only the return."""

    DAMAGED = "{this was the record"

    @staticmethod
    def _audits(world, action):
        return [a for a in world.store.get("_audit", []) if a[0] == action]

    def test_removing_the_primary_ssh_server_is_refused_and_audited(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        text = inv.removal_refusal([1], actor="alice")
        assert "cannot be read, so it cannot tell whether this server is at investigation DEBUG" in text
        assert (
            "Repair the record first (Health → DEBUG logging left on)" in text
            and "no way for Jen to put it back" in text
        )
        (row,) = self._audits(world, "INVESTIGATION_LOGGING_REMOVAL_REFUSED")
        assert (
            row[1] == "Server 1"
            and "removal refused while Jen's record of investigation logging is unreadable (by alice)" in row[2]
        )
        assert world.store[inv.RECORD_KEY] == self.DAMAGED, "nothing was written"

    def test_removing_an_extra_server_is_refused(self, world):
        world.store[inv.RECORD_KEY] = '{"servers": []}'
        assert inv.removal_refusal([2], actor="alice") != ""
        assert (
            len(self._audits(world, "INVESTIGATION_LOGGING_REMOVAL_REFUSED")) == 1
            and world.store[inv.RECORD_KEY] == '{"servers": []}'
        )

    def test_removing_one_of_several_is_refused_and_all_are_named(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert [b["server_id"] for b in inv.blocking_removal([2, 3, 4])] == ["2", "3", "4"]
        assert all(b["damaged_record"] for b in inv.blocking_removal([2, 3, 4]))
        assert inv.removal_refusal([2, 3, 4]) != ""
        (row,) = self._audits(world, "INVESTIGATION_LOGGING_REMOVAL_REFUSED")
        assert row[1] == "Server 2, Server 3, Server 4"

    def test_a_valid_empty_record_allows_removal(self, world):
        for raw in ("", '{"servers": {}}'):
            world.store[inv.RECORD_KEY] = raw
            assert inv.removal_refusal([1], actor="alice") == "" and inv.blocking_removal([1]) == []
        assert self._audits(world, "INVESTIGATION_LOGGING_REMOVAL_REFUSED") == []

    def test_a_valid_record_with_no_entry_for_the_target_allows_removal(self, world):
        assert inv.turn_on(world.servers[0], 5)["ok"]
        stored = world.store[inv.RECORD_KEY]
        assert inv.removal_refusal([2]) == "" and world.store[inv.RECORD_KEY] == stored
        assert inv.removal_refusal([1]) != "", "and the server WITH an entry is still refused"

    def test_a_rebuilt_record_allows_removal_again(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.removal_refusal([1]) != ""
        inv.sweep(now=NOW, full=True)  # every server examined, nothing found: rebuilt
        assert inv._record()["damaged"] is False and world.store[inv.RECORD_KEY] == ""
        assert inv.removal_refusal([1]) == ""

    def test_forget_and_turn_off_decline_a_damaged_record_too(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.forget(1) is False and inv.turn_off(world.servers[0])["ok"] is False
        assert world.store[inv.RECORD_KEY] == self.DAMAGED


class TestZeroServersIsNotARecovery:
    """Item 2: `_recover` over an empty set of SSH servers found no entries and no problems, and `_save` wrote an empty healthy record - nothing had been
    examined. It stays damaged until a PERSON says so."""

    DAMAGED = "{this was the record"

    @staticmethod
    def _audits(world, action):
        return [a for a in world.store.get("_audit", []) if a[0] == action]

    def test_no_ssh_server_at_all_stays_damaged_and_health_says_so(self, world):
        from jen.services import health

        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.servers.clear()
        out = inv.sweep(now=NOW, full=True)
        assert out["errors"] == ["no Kea server with SSH is configured, so nothing could be examined"]
        assert world.store[inv.RECORD_KEY] == self.DAMAGED and inv.DAMAGED_KEY not in world.store
        c = health._debug_logging_left_on({})
        assert c.status == "fail" and "no Kea server with SSH is configured" in c.detail

    def test_only_servers_without_ssh_stay_damaged_naming_each(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        for s in world.servers:
            s["ssh_host"] = ""
        out = inv.sweep(now=NOW, full=True)
        assert "no Kea server with SSH is configured, so nothing could be examined" in out["errors"]
        assert "kea-a: no SSH, so its file and daemon cannot be examined" in out["errors"]
        assert "kea-b: no SSH, so its file and daemon cannot be examined" in out["errors"]
        assert world.store[inv.RECORD_KEY] == self.DAMAGED

    def test_a_half_configured_server_holds_the_damaged_state(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.servers[1]["ssh_host"] = ""  # kea-b has no SSH; kea-a is examined fine
        out = inv.sweep(now=NOW, full=True)
        assert out["errors"] == ["kea-b: no SSH, so its file and daemon cannot be examined"]
        assert world.store[inv.RECORD_KEY] == self.DAMAGED and inv._record()["damaged"] is True
        world.servers[1]["ssh_host"] = "10.0.0.2"  # fixed: the next minute rebuilds it
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert world.store[inv.RECORD_KEY] == "" and inv._record()["damaged"] is False

    def test_every_server_verified_with_no_markers_clears_it(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.sweep(now=NOW, full=True)["errors"] == []
        assert world.store[inv.RECORD_KEY] == "" and world.store[inv.DAMAGED_KEY] == self.DAMAGED

    def test_a_verified_daemon_at_debug_is_adopted(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.daemons[1].loaded = _marked_logger("DEBUG", 55)
        assert inv.sweep(now=NOW, full=True)["adopted"] == ["kea-a"]
        assert list(_servers_of(world.store[inv.RECORD_KEY])) == ["1"]

    def test_the_acknowledgement_by_a_restricted_admin_is_refused(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.servers.clear()
        inv.sweep(now=NOW, full=True)
        assert inv.acknowledge_damaged("bob", all_subnets=False) is False and inv.acknowledge_damaged("bob") is False
        assert (
            world.store[inv.RECORD_KEY] == self.DAMAGED
            and self._audits(world, "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED") == []
        )

    def test_the_acknowledgement_by_an_all_subnets_admin_writes_an_empty_record_and_audits_it(self, world):
        from jen.services import health

        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.servers.clear()
        inv.sweep(now=NOW, full=True)
        assert health._debug_logging_left_on({}).status == "fail"
        assert inv.acknowledge_damaged("alice", all_subnets=True) is True
        assert world.store[inv.RECORD_KEY] == "" and world.store[inv.DAMAGED_KEY] == self.DAMAGED, (
            "empty record written, old value kept"
        )
        (row,) = self._audits(world, "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED")
        assert row[1] == "alice" and "no Kea server with SSH is configured, so nothing could be examined" in row[2]
        assert inv.recovery_status() == {"at": "", "problems": [], "rebuilt": None}
        assert inv._record()["damaged"] is False and health._debug_logging_left_on({}).status == "ok"
        print(f"ACK audit row: {row}")

    def test_the_acknowledgement_is_refused_when_nothing_is_damaged_or_no_problem_was_recorded(self, world):
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False, "nothing damaged"
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False, (
            "damaged, but the rebuild has not recorded anything it could not examine"
        )
        assert (
            world.store[inv.RECORD_KEY] == self.DAMAGED
            and self._audits(world, "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED") == []
        )

    def test_after_the_acknowledgement_logging_works_again(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        world.servers[1]["ssh_host"] = ""
        inv.sweep(now=NOW, full=True)
        assert inv.acknowledge_damaged("alice", all_subnets=True)
        assert inv.turn_on(world.servers[0], 5)["ok"] and [e["name"] for e in inv.active()] == ["kea-a"]

    def test_the_servers_page_banner_shows_the_button_only_with_recorded_problems(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.record_banner() == {"damaged": True, "problems": [], "at": ""}
        world.servers.clear()
        inv.sweep(now=NOW, full=True)
        banner = inv.record_banner()
        assert banner["damaged"] and banner["problems"] == [
            "no Kea server with SSH is configured, so nothing could be examined"
        ]


class TestTheEntryValidatorChecksWhatTheFieldsMean:
    """Item 3: `_valid_entry` checked types only: `until: "gibberish"` passed (and `_parse_until` reads it as due now), `restore: {}` passed although it is no
    way back, `file` and `daemon` could be absent (and defaulted), `reload_tries` was any int. The fields that decide what Jen does are validated for meaning."""

    @staticmethod
    def _entry(**over):
        base = {
            "name": "kea-a",
            "until": FUTURE,
            "file": "debug",
            "daemon": "debug",
            "pending": None,
            "ssh_host": "10.0.0.1",
        }
        base.update(over)
        return base

    @pytest.mark.parametrize(
        "bad",
        [
            {"until": "gibberish"},
            {"until": ""},
            {"until": 5},
            {"restore": {}},
            {"restore": {"severity": "INFO"}},
            {"restore": {"created": False}},
            {"observed_at": "2026-10-04T12:00:00+00:00", "file": None},
            {"reload_tries": -1},
            {"reload_tries": 99},
            {"reload_tries": 2, "daemon": None},
        ],
        ids=[
            "until-gibberish",
            "until-empty",
            "until-not-text",
            "restore-empty",
            "restore-missing-debuglevel",
            "restore-created-false",
            "file-not-a-state",
            "reload-tries-negative",
            "reload-tries-beyond-the-bound",
            "daemon-not-a-state",
        ],
    )
    def test_each_of_the_ten_cases_is_damaged_and_nothing_raises(self, world, bad):
        import json

        from jen.services import health

        entry = self._entry(**bad)
        world.store[inv.RECORD_KEY] = json.dumps({"servers": {"2": entry}})
        record = inv._record()
        assert record["damaged"] is True and record["bad"] == ["2"] and record["servers"] == {}
        assert inv.turn_on(world.servers[0], 5)["ok"] is False, "a second session is refused"
        assert health._debug_logging_left_on({}).status == "fail" and inv.active() == []
        inv.sweep(now=NOW)  # does not raise: it is the recovery, and it repairs it
        assert inv._record()["damaged"] is False and world.store[inv.RECORD_KEY] == ""

    def test_an_entry_written_by_entry_for_today_is_valid(self, world):
        entry = inv._entry_for(world.servers[0], FUTURE, "alice")
        assert inv._valid_entry(entry) and not inv._is_legacy_entry({**entry, "reload_tries": 1})

    def test_the_bound_is_inclusive(self):
        assert inv._valid_entry(self._entry(reload_tries=0)) and inv._valid_entry(
            self._entry(reload_tries=inv.RELOAD_TRIES + 1)
        )
        assert not inv._valid_entry(self._entry(reload_tries=inv.RELOAD_TRIES + 2))

    def test_the_legacy_shape_is_normalised_not_damaged(self, world, caplog):
        import json
        import logging

        legacy = {
            "name": "kea-a",
            "until": FUTURE,
            "ssh_host": "10.0.0.1",
            "by": "alice",
        }  # before beta.9: no file, no daemon, no observations
        assert inv._valid_entry(legacy) and inv._is_legacy_entry(legacy)
        world.store[inv.RECORD_KEY] = json.dumps({"servers": {"1": legacy}})
        inv._legacy_logged.discard("1")
        with caplog.at_level(logging.INFO, logger=inv.logger.name):
            record = inv._record()
            inv._record()
        assert record["damaged"] is False
        assert (
            record["servers"]["1"]["file"],
            record["servers"]["1"]["daemon"],
            record["servers"]["1"]["pending"],
        ) == ("debug", "debug", None)
        assert caplog.text.count("predates the file/daemon fields") == 1, "said once"
        (row,) = inv.active(NOW)
        assert row["file"] == "debug" and row["daemon"] == "debug" and row["stuck"] is False

    def test_a_file_less_entry_that_has_observation_keys_is_not_legacy(self):
        assert not inv._valid_entry({"name": "kea-a", "until": FUTURE, "seen": "INFO / debuglevel 0"})
        assert not inv._valid_entry({"name": "kea-a", "until": FUTURE, "restarted": True, "daemon": "debug"})


# ── v5.68.0-beta.27 (Q162): a server with outstanding state keeps its connection identity; the acknowledgement is one transaction ───────


class TestAnEndpointChangeKeepsTheServerIdentity:
    """Item 1: the removal guard (Q144) protects a server's PRESENCE. The same id with a new SSH host passed it - and every later observation, reload and
    restore then went to a DIFFERENT Kea while the one at DEBUG 55 was left there. `endpoint_change_refusal` protects the four fields that say WHICH Kea:
    ssh_host, ssh_user, kea_conf, api_url. Credentials and the display name are not identity."""

    @pytest.fixture
    def w(self, world):
        for s, host in zip(world.servers, ("10.0.0.1", "10.0.0.2"), strict=True):
            s.update(api_url=f"http://{host}:8000", ssh_user="jen", kea_conf="/etc/kea/kea-dhcp4.conf")
        return world

    @staticmethod
    def _audits(world, action="INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED"):
        return [a for a in world.store.get("_audit", []) if a[0] == action]

    def test_01_an_active_entry_and_the_ssh_host_pointed_elsewhere_is_refused_and_audited(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        text = inv.endpoint_change_refusal(1, {"ssh_host": "10.9.9.9"}, actor="alice")
        assert "Investigation logging is on for kea-a" in text and "turn it off from Servers first" in text
        assert "Changing its ssh_host now would point Jen at a different Kea while this one is still at DEBUG" in text
        (row,) = self._audits(w)
        assert (
            row[1] == "kea-a"
            and "change of ssh_host refused while investigation logging is on or owed a restore (by alice)" in row[2]
        )

    def test_02_another_server_kept_with_a_new_host_is_refused(self, w):
        assert inv.turn_on(w.servers[1], 5)["ok"]
        assert "kea-b" in inv.endpoint_change_refusal(
            2, {"api_url": "http://10.0.0.2:8000", "ssh_host": "10.7.7.7"}, actor="alice"
        )
        assert len(self._audits(w)) == 1

    def test_03_a_changed_api_url_is_refused(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        text = inv.endpoint_change_refusal(1, {"api_url": "http://elsewhere:8000"}, actor="alice")
        assert "Changing its api_url" in text

    def test_04_an_unreadable_record_refuses_any_endpoint_change_and_names_it(self, w):
        w.store[inv.RECORD_KEY] = "{broken"
        text = inv.endpoint_change_refusal(2, {"ssh_user": "someone-else"}, actor="alice")
        assert "cannot be read, so it cannot tell whether this server is at investigation DEBUG" in text
        assert "changing where Jen reaches this Kea could leave the old one at DEBUG with no way back" in text
        (row,) = self._audits(w)
        assert (
            "change of ssh_user refused while Jen's record of investigation logging is unreadable (by alice)" in row[2]
        )
        assert w.store[inv.RECORD_KEY] == "{broken"

    def test_05_a_valid_empty_record_allows_the_change(self, w):
        for raw in ("", '{"servers": {}}'):
            w.store[inv.RECORD_KEY] = raw
            assert (
                inv.endpoint_change_refusal(1, {"ssh_host": "10.9.9.9", "api_url": "http://x:1"}, actor="alice") == ""
            )
        assert self._audits(w) == []

    def test_06_the_display_name_and_credentials_are_not_identity(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        proposed = {"name": "Renamed", "api_user": "other", "api_pass": "p", "ssh_key": "/k"}
        assert inv.endpoint_change_refusal(1, proposed, actor="alice") == ""
        # and the identity fields UNCHANGED, however they are spelled, are no change either
        same = {
            "api_url": "http://10.0.0.1:8000",
            "ssh_host": "10.0.0.1",
            "ssh_user": "jen",
            "kea_conf": "/etc/kea/kea-dhcp4.conf",
        }
        assert inv.endpoint_change_refusal(1, same, actor="alice") == "" and self._audits(w) == []

    def test_07_a_blank_config_path_is_the_default_one_not_a_change(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        assert inv.endpoint_change_refusal(1, {"kea_conf": ""}, actor="alice") == ""
        assert "kea_conf" in inv.endpoint_change_refusal(1, {"kea_conf": "/opt/kea/dhcp4.conf"}, actor="alice")

    def test_08_a_server_with_no_entry_is_free_to_change_while_another_is_on(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        assert inv.endpoint_change_refusal(2, {"ssh_host": "10.7.7.7"}, actor="alice") == ""
        assert inv.removal_refusal([2]) == "", "and a server with no entry can be removed"

    def test_09_after_turn_off_the_change_is_allowed(self, w):
        assert inv.turn_on(w.servers[0], 5)["ok"]
        assert inv.endpoint_change_refusal(1, {"ssh_host": "10.9.9.9"}, actor="alice") != ""
        assert inv.turn_off(w.servers[0])["ok"]
        assert inv.endpoint_change_refusal(1, {"ssh_host": "10.9.9.9"}, actor="alice") == ""

    def test_10_a_restore_that_is_not_finished_still_holds_the_identity(self, w):
        kea = w.daemons[1]
        assert inv.turn_on(w.servers[0], 5)["ok"]
        kea.reload_ignored = kea.restart_ignored = True
        assert inv.turn_off(w.servers[0])["ok"] is False and inv.active()[0]["stuck"]
        assert "turn it off from Servers first" in inv.endpoint_change_refusal(
            1, {"ssh_host": "10.9.9.9"}, actor="alice"
        )

    def test_an_unknown_server_has_nothing_to_protect(self, w):
        assert inv.endpoint_change_refusal(99, {"ssh_host": "10.9.9.9"}, actor="alice") == ""


class TestTheAcknowledgementAndItsAuditRowAreOneTransaction:
    """Item 3: `_save(...)` then `_audit(...)`, and `user.audit` logs and returns on failure - the empty record was committed with no durable record of who
    asserted what. `set_global_setting_and_audit` carries both statements on one connection; `acknowledge_damaged` re-reads the record under its lock and uses it."""

    DAMAGED = "{this was the record"

    @staticmethod
    def _problems(world):
        world.store[inv.RECORD_KEY] = TestTheAcknowledgementAndItsAuditRowAreOneTransaction.DAMAGED
        world.servers.clear()
        inv.sweep(now=NOW, full=True)

    def test_state_and_audit_commit_together(self, world):
        self._problems(world)
        assert inv.acknowledge_damaged("alice", all_subnets=True) is True
        assert world.store[inv.RECORD_KEY] == "" and world.store[inv.DAMAGED_KEY] == self.DAMAGED
        rows = [a for a in world.store["_audit"] if a[0] == "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED"]
        assert len(rows) == 1 and rows[0][1] == "alice"

    def test_the_audit_failing_leaves_the_damaged_record_the_copy_present_and_false_returned(self, world):
        self._problems(world)
        world.db["audit_fails"] = True
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False
        assert world.store[inv.RECORD_KEY] == self.DAMAGED, "the record is still the damaged one"
        assert world.store[inv.DAMAGED_KEY] == self.DAMAGED, "the old value was kept first"
        assert not [a for a in world.store.get("_audit", []) if a[0] == "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED"]
        assert inv.recovery_status()["problems"], "and the decision is still open: the status is not cleared"
        world.db["audit_fails"] = False
        assert inv.acknowledge_damaged("alice", all_subnets=True) is True, "so a retry can complete it"

    def test_two_concurrent_calls_make_one_true_one_false_and_one_audit_row(self, world):
        import threading

        self._problems(world)
        results, barrier = [], threading.Barrier(2)

        def go():
            barrier.wait(5)
            results.append(inv.acknowledge_damaged("alice", all_subnets=True))

        threads = [threading.Thread(target=go) for _ in range(2)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(10)
        assert sorted(results) == [False, True]
        assert len([a for a in world.store["_audit"] if a[0] == "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED"]) == 1

    def test_the_acknowledgement_does_not_use_the_ordinary_audit_helper(self):
        import ast
        import inspect

        fn = next(
            n
            for n in ast.walk(ast.parse(inspect.getsource(inv)))
            if isinstance(n, ast.FunctionDef) and n.name == "acknowledge_damaged"
        )
        assert "_audit" not in [
            c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
        ]

    def test_the_three_existing_refusals_are_kept(self, world):
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False, "nothing damaged"
        world.store[inv.RECORD_KEY] = self.DAMAGED
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False, "no problem recorded"
        self._problems(world)
        assert inv.acknowledge_damaged("bob", all_subnets=False) is False, "a restricted admin"
        assert world.store[inv.RECORD_KEY] == self.DAMAGED


class TestTheRealTransactionIsAllOrNothing:
    """`set_global_setting_and_audit` itself, against a connection that has transaction semantics (rows reach the 'tables' only on commit; an exception in the
    context rolls back what the connection held)."""

    @pytest.fixture
    def fake_db(self, monkeypatch):
        import contextlib

        from jen.models import db as dbmod
        from jen.models import user as usermod

        world = {"settings": {}, "audit": [], "commit_raises": False, "audit_raises": False, "settings_raises": False}

        class Cursor:
            def __init__(self, conn):
                self.conn = conn

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                if "audit_log" in sql:
                    if world["audit_raises"]:
                        raise RuntimeError("audit insert failed")
                    self.conn.pending.append(("audit", params))
                else:
                    if world["settings_raises"]:
                        raise RuntimeError("settings upsert failed")
                    self.conn.pending.append(("settings", params))

        class Conn:
            def __init__(self):
                self.pending = []

            def cursor(self):
                return Cursor(self)

            def commit(self):
                if world["commit_raises"]:
                    raise RuntimeError("commit failed")
                for table, params in self.pending:
                    if table == "audit":
                        world["audit"].append(params)
                    else:
                        world["settings"][params[0]] = params[1]
                self.pending = []

        @contextlib.contextmanager
        def jen_db():
            conn = Conn()
            try:
                yield conn
            except Exception:
                conn.pending = []  # rollback
                raise

        monkeypatch.setattr(dbmod, "jen_db", jen_db)
        monkeypatch.setattr(usermod, "_audit_identity", lambda: (7, "alice", "10.1.1.1"))

        def invalidated():
            world["invalidated"] = 1

        monkeypatch.setattr(usermod, "_invalidate_settings_cache", invalidated)
        return world

    def test_both_rows_are_written_with_the_same_columns_audit_writes(self, fake_db):
        from jen.models import user as usermod

        assert usermod.set_global_setting_and_audit("k", "v", "SOME_ACTION", "ent", "details") is True
        assert fake_db["settings"] == {"k": "v"} and fake_db["audit"] == [
            (7, "alice", "SOME_ACTION", "ent", "details", "10.1.1.1")
        ]
        assert fake_db.get("invalidated") == 1

    def test_the_audit_insert_raising_rolls_the_setting_back_too(self, fake_db):
        from jen.models import user as usermod

        fake_db["audit_raises"] = True
        assert usermod.set_global_setting_and_audit("k", "v", "A", "e", "d") is False
        assert fake_db["settings"] == {} and fake_db["audit"] == []

    def test_the_commit_raising_leaves_neither_row(self, fake_db):
        from jen.models import user as usermod

        fake_db["commit_raises"] = True
        assert usermod.set_global_setting_and_audit("k", "v", "A", "e", "d") is False
        assert fake_db["settings"] == {} and fake_db["audit"] == []
        assert fake_db.get("invalidated") is None, (
            "the settings cache is not invalidated for a write that did not happen"
        )

    def test_the_settings_upsert_raising_writes_no_audit_row(self, fake_db):
        from jen.models import user as usermod

        fake_db["settings_raises"] = True
        assert usermod.set_global_setting_and_audit("k", "v", "A", "e", "d") is False
        assert fake_db["audit"] == []


class TestARebuiltEntryIsValidBeforeItIsWritten:
    """Item 2: `_recovery_candidates` copied an unparseable `until` from the marker into the entry; `_valid_entry` (Q161) requires it to parse, so `_recover` wrote
    a candidate the next `_record()` read as damaged, and the loop repeated forever. An unreadable deadline is treated as DUE NOW (`deadline_malformed`, the
    ordinary restore finishes it), and every candidate is validated before the one write. Each test asserts the STORED record."""

    DAMAGED = "{this was the record"

    @pytest.fixture
    def w(self, world):
        world.store[inv.RECORD_KEY] = self.DAMAGED
        return world

    @staticmethod
    def _marker_on(world, sid, until):
        cfg, _ = ed.set_investigation_logging(world.daemons[sid].file, FUTURE)
        _entry(cfg)["user-context"]["jen-investigation"]["until"] = until
        world.daemons[sid].file = world.daemons[sid].loaded = cfg

    def test_a_valid_marker_with_a_valid_deadline_is_written_as_it_is(self, w):
        self._marker_on(w, 1, FUTURE)
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"] and out["errors"] == []
        stored = _servers_of(w.store[inv.RECORD_KEY])["1"]
        assert stored["until"] == FUTURE and "deadline_malformed" not in stored and inv._record()["damaged"] is False

    def test_a_valid_restore_and_a_deadline_that_is_not_a_date_is_due_now_and_restored_by_the_next_sweep(self, w):
        from jen.services import health

        self._marker_on(w, 1, "not-a-date")
        out = inv.sweep(now=NOW, full=True)
        assert out["adopted"] == ["kea-a"] and out["errors"] == []
        stored = _servers_of(w.store[inv.RECORD_KEY])["1"]
        assert stored["until"] == inv._iso(NOW) and stored["deadline_malformed"] is True
        assert stored["restore"] == {"severity": "INFO", "debuglevel": "absent"}, "the restore object is kept"
        assert inv._record()["damaged"] is False, "the record the recovery wrote is one the next load accepts (no loop)"
        (row,) = inv.active(NOW)
        assert row["deadline_malformed"] is True
        assert (
            "its marker's deadline was unreadable, so it was treated as due" in health._debug_logging_left_on({}).detail
        )
        nxt = inv.sweep(now=NOW + timedelta(minutes=1))
        assert (
            nxt["restored"] == ["kea-a"]
            and w.store[inv.RECORD_KEY] == ""
            and ed.investigation_marker(w.daemons[1].file) is None
        )
        assert not _daemon_at_debug(w.daemons[1])

    def test_a_marker_with_no_deadline_is_due_now_too(self, w):
        cfg, _ = ed.set_investigation_logging(w.daemons[1].file, FUTURE)
        _entry(cfg)["user-context"]["jen-investigation"].pop("until")
        w.daemons[1].file = w.daemons[1].loaded = cfg
        inv.sweep(now=NOW, full=True)
        stored = _servers_of(w.store[inv.RECORD_KEY])["1"]
        assert stored["until"] == inv._iso(NOW) and inv._record()["damaged"] is False

    def test_an_expired_deadline_is_due_and_restored(self, w):
        self._marker_on(w, 1, PAST)
        inv.sweep(now=NOW, full=True)
        assert _servers_of(w.store[inv.RECORD_KEY])["1"]["until"] == PAST
        assert inv.sweep(now=NOW + timedelta(minutes=1))["restored"] == ["kea-a"] and w.store[inv.RECORD_KEY] == ""

    def test_a_running_marker_with_a_clean_file_and_a_gibberish_deadline_is_adopted_due_now(self, w):
        logger_ = _marked_logger("DEBUG", 55)
        _entry(logger_)["user-context"]["jen-investigation"]["until"] = "gibberish"
        w.daemons[1].loaded = logger_
        inv.sweep(now=NOW, full=True)
        stored = _servers_of(w.store[inv.RECORD_KEY])["1"]
        assert (
            stored["deadline_malformed"] is True and stored["until"] == inv._iso(NOW) and stored["file"] == "restored"
        )
        assert inv.sweep(now=NOW + timedelta(minutes=1))["restored"] == ["kea-a"] and not _daemon_at_debug(w.daemons[1])

    def test_a_marker_whose_restore_is_malformed_is_flagged_for_a_person_not_guessed_at(self, w):
        cfg, _ = ed.set_investigation_logging(w.daemons[1].file, FUTURE)
        _entry(cfg)["user-context"]["jen-investigation"]["restore"] = {}
        w.daemons[1].file = w.daemons[1].loaded = cfg
        out = inv.sweep(now=NOW, full=True)
        assert out["errors"] == [] and inv._record()["damaged"] is False
        stored = _servers_of(w.store[inv.RECORD_KEY])["1"]
        assert stored["marker_invalid"] is True and "restore" not in stored, (
            "the established damaged-marker state: by-hand guidance, nothing changed"
        )

    def test_a_candidate_that_fails_validation_is_a_problem_nothing_is_written_and_it_stays_damaged(
        self, w, monkeypatch
    ):
        self._marker_on(w, 1, FUTURE)
        real = inv._valid_entry
        monkeypatch.setattr(
            inv, "_valid_entry", lambda e: False if (isinstance(e, dict) and e.get("name") == "kea-a") else real(e)
        )
        out = inv.sweep(now=NOW, full=True)
        assert any("kea-a: its marker cannot be read into a valid entry" in e for e in out["errors"])
        assert w.store[inv.RECORD_KEY] == self.DAMAGED and inv.DAMAGED_KEY not in w.store
        monkeypatch.setattr(inv, "_valid_entry", real)
        assert inv.sweep(now=NOW + timedelta(minutes=1), full=True)["errors"] == [], (
            "and the next minute, readable again, it is rebuilt"
        )
        assert list(_servers_of(w.store[inv.RECORD_KEY])) == ["1"]

    def test_the_final_check_before_the_write_refuses_an_invalid_entry_even_if_the_candidate_step_let_it_through(
        self, w, monkeypatch
    ):
        self._marker_on(w, 1, FUTURE)
        monkeypatch.setattr(inv, "_candidate_ready", lambda entry, now: True)  # a bug in the candidate step...
        entry_names = []
        real_valid = inv._valid_entry

        def reject_kea_a_at_the_gate(e):
            if isinstance(e, dict) and e.get("name") == "kea-a":
                entry_names.append(e["name"])
                return False
            return real_valid(e)

        monkeypatch.setattr(inv, "_valid_entry", reject_kea_a_at_the_gate)
        out = inv.sweep(now=NOW, full=True)
        assert entry_names and any("a rebuilt entry failed validation" in e for e in out["errors"])
        assert w.store[inv.RECORD_KEY] == self.DAMAGED, "...is caught by the assertion in _recover: nothing is written"

    def test_two_servers_one_malformed_deadline_one_unreadable_writes_nothing_and_one_ok_writes_both(
        self, w, monkeypatch
    ):
        self._marker_on(w, 1, "gibberish")
        real = inv._host.read_config_versioned

        def b_unreadable(server, service):
            if server["id"] == 2:
                raise OSError("no route")
            return real(server, service)

        monkeypatch.setattr(inv._host, "read_config_versioned", b_unreadable)
        out = inv.sweep(now=NOW, full=True)
        assert any("kea-b: config unreadable" in e for e in out["errors"]) and w.store[inv.RECORD_KEY] == self.DAMAGED
        monkeypatch.setattr(inv._host, "read_config_versioned", real)
        self._marker_on(w, 2, FUTURE)
        out = inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        stored = _servers_of(w.store[inv.RECORD_KEY])
        assert (
            sorted(stored) == ["1", "2"]
            and stored["1"]["deadline_malformed"] is True
            and "deadline_malformed" not in stored["2"]
        )
        assert inv._record()["damaged"] is False


# ── v5.68.0-beta.26 (Q161): an unreadable record is never evidence of anything - enforced over EVERY reader ──────────────────────────


#: Readers of `_record()` that may read an empty server map without checking `damaged`, each with why it is safe. A function NOT on this list that reads the
#: record must test `damaged` before it uses `["servers"]`. `blocking_removal` is deliberately not here: it DECIDES, and an empty map is the wrong answer.
_READ_ONLY_RECORD_READERS = {
    "active": "it renders (banners, the Servers page, the Health row's list) and decides nothing; a damaged record has no rows to show, and the Health row, "
    "turn-on, turn-off, removal and the sweep each test `damaged` themselves",
}


class TestEveryReaderOfTheRecordHandlesDamaged:
    """Items 1 and 2 were one mistake: `damaged` (beta.24) was applied to the readers of the index the spec named and not to all of them - `blocking_removal`
    read `_record()["servers"]`, got `{}`, and let a server at DEBUG 55 be removed. The lease definition of beta.17 had the same shape and was closed by a
    whole-tree source test; this is that test for the record, so the next state cannot miss a reader without CI going red."""

    @staticmethod
    def _tree(relpath):
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        return ast.parse((root / relpath).read_text(encoding="utf-8"))

    @staticmethod
    def _is_record_call(node):
        import ast

        f = node.func if isinstance(node, ast.Call) else None
        return (isinstance(f, ast.Name) and f.id == "_record") or (isinstance(f, ast.Attribute) and f.attr == "_record")

    @staticmethod
    def _damaged_check_line(fn):
        """The first line in `fn` that tests `damaged` (`.get("damaged")` or `["damaged"]`), or None."""
        import ast

        lines = []
        for n in ast.walk(fn):
            is_get = isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
            if is_get and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "damaged":
                lines.append(n.lineno)
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and n.slice.value == "damaged":
                lines.append(n.lineno)
        return min(lines) if lines else None

    @staticmethod
    def _first_servers_use(fn):
        import ast

        lines = [
            n.lineno
            for n in ast.walk(fn)
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and n.slice.value == "servers"
        ]
        return min(lines) if lines else None

    def _readers(self, relpath):
        import ast

        out = []
        for fn in ast.walk(self._tree(relpath)):
            if (
                isinstance(fn, ast.FunctionDef)
                and fn.name != "_record"
                and any(self._is_record_call(n) for n in ast.walk(fn))
            ):
                out.append(fn)
        return sorted(out, key=lambda f: f.lineno)

    def test_every_reader_in_the_service_checks_damaged_before_it_uses_the_servers_or_is_on_the_read_only_list(self):
        readers = self._readers("jen/services/investigation_logging.py")
        names = [f.name for f in readers]
        print(f"READERS of _record() in investigation_logging.py ({len(names)}): {', '.join(names)}")
        assert len(names) >= 6, f"the walk found {names}: the test has lost its power"
        bad = []
        for fn in readers:
            if fn.name in _READ_ONLY_RECORD_READERS:
                continue
            checked, used = self._damaged_check_line(fn), self._first_servers_use(fn)
            if checked is None or (used is not None and checked > used):
                bad.append(fn.name)
        assert not bad, (
            f"these readers of the record use it without testing `damaged` first: {bad}; readers seen: {names}"
        )
        stale = set(_READ_ONLY_RECORD_READERS) - set(names)
        assert not stale, f"read-only allowlist entries that no longer read the record: {sorted(stale)}"

    def test_health_checks_damaged_where_it_reads_the_record(self):
        readers = self._readers("jen/services/health.py")
        print(f"READERS of _record() in health.py: {', '.join(f.name for f in readers)}")
        assert [f.name for f in readers] == ["_debug_logging_left_on"]
        assert self._damaged_check_line(readers[0]) is not None

    def test_no_route_or_other_module_reads_the_record_directly(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "jen"
        offenders = []
        for path in root.rglob("*.py"):
            rel = path.relative_to(root.parent).as_posix()
            if rel in ("jen/services/investigation_logging.py", "jen/services/health.py"):
                continue
            if "_record()" in path.read_text(encoding="utf-8") and "investigation_logging" in path.read_text(
                encoding="utf-8"
            ):
                offenders.append(rel)
        assert not offenders, f"read the investigation record without going through the service: {offenders}"

    def test_every_route_that_asks_for_a_removal_refusal_stops_on_a_non_empty_one(self):
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        callers = []
        for path in sorted((root / "jen" / "routes").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                for n in ast.walk(fn):
                    if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                        f = n.value.func
                        if isinstance(f, ast.Attribute) and f.attr in ("removal_refusal", "blocking_removal"):
                            var = n.targets[0].id
                            callers.append(f"{path.relative_to(root).as_posix()}::{fn.name}")
                            stops = [
                                i
                                for i in ast.walk(fn)
                                if isinstance(i, ast.If)
                                and isinstance(i.test, ast.Name)
                                and i.test.id == var
                                and any(
                                    isinstance(b, ast.Return)
                                    for b in ast.walk(ast.Module(body=i.body, type_ignores=[]))
                                )
                            ]
                            assert stops, (
                                f"{path.name}::{fn.name} asks {f.attr} and does not stop on a non-empty answer"
                            )
        print(f"ROUTES that ask for a removal refusal: {', '.join(callers)}")
        assert len(callers) >= 2, callers


# ── v5.68.0-beta.29 (Q165): the host's restore and Jen's are one transformation ─────────────────────────────────────────────────────────────────────


def _restore_vectors():
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parent / "vectors" / "investigation_restore.json"
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


class TestJensRestoreMatchesTheSharedVectors:
    """`tests/vectors/investigation_restore.json` holds the logger transformation of a restore. `jen-kea-helper`'s `_restore_logger` (tests/test_kea_helper_investigation.py) and
    `kea_config_edit.clear_investigation_logging` are both run against it, so the host and Jen can never put a logger back two different ways."""

    @pytest.mark.parametrize("case", [c for c in _restore_vectors() if c["both"]], ids=lambda c: c["name"][:60])
    def test_clear_investigation_logging_gives_the_vectors_after(self, case):
        out, code = ed.clear_investigation_logging(copy.deepcopy(case["before"]))
        assert out == case["after"]
        assert code in ("ok", "nochange")

    def test_the_vector_file_is_not_empty_and_has_both_kinds(self):
        cases = _restore_vectors()
        assert len(cases) >= 10 and any(c["both"] for c in cases) and any(not c["both"] for c in cases)
