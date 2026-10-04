"""
tests/test_investigation_logging.py
───────────────────────────────────
v5.68.0-beta.3 (Q138) — investigation logging on demand: the pure loggers mutation (jen.services.kea_config_edit), the service that
applies it to ONE server (reload when the daemon has `config-reload`, restart otherwise), the every-minute sweep, and the Health row.
No database and no Kea: the change set and the daemon are replaced by an in-memory server, settings by a dict.
`pytest --noconftest tests/test_investigation_logging.py`.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from jen.services import investigation_logging as inv
from jen.services import kea_config_edit as ed
from jen.services.kea_changeset import ChangeSetResult

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
FUTURE = (NOW + timedelta(minutes=10)).isoformat()
PAST = (NOW - timedelta(minutes=3)).isoformat()


def _cfg(loggers="absent"):
    section = {"valid-lifetime": 3600, "subnet4": []}
    if loggers != "absent":
        section["loggers"] = loggers
    return {"Dhcp4": section}


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


class FakeKea:
    """One server's config file and daemon. `commands` is what `list-commands` answers; `reload` what config-reload returns."""

    def __init__(self, cfg, commands=("config-reload", "version-get"), reload_result=0, restart_ok=True):
        self.file = copy.deepcopy(cfg)
        self.commands, self.reload_result, self.restart_ok = list(commands), reload_result, restart_ok
        self.calls = []
        self.writes = 0

    def kea_command(self, command, **kw):
        self.calls.append(command)
        if command == "list-commands":
            return {"result": 0, "arguments": self.commands}
        if command == "config-reload":
            return {"result": self.reload_result, "text": "reloaded" if not self.reload_result else "reload refused"}
        return {"result": 0}

    def service_action(self, server, service, action):
        self.calls.append(f"{action}:{service}")
        return {"ok": self.restart_ok, "detail": "" if self.restart_ok else "unit failed"}

    def apply_change(self, service, mutate_fn, summary, **kw):
        after, code = mutate_fn(self.file)
        skip = kw.get("skip_codes", ("notfound", "nochange"))
        assert kw["servers"] and len(kw["servers"]) == 1, "always exactly one target"
        self.calls.append(f"apply(restart={kw.get('restart', True)}):{summary}")
        if code in skip:
            return ChangeSetResult("nothing", code, [("success", f"ℹ️ {code}")])
        if code != "ok":
            return ChangeSetResult("aborted", code, [("error", f"❌ {kw['code_messages'].get(code, code)}")])
        self.file = after
        self.writes += 1
        return ChangeSetResult("ok", "ok", [("success", f"✅ {summary}")])

    def read_config_versioned(self, server, service):
        return copy.deepcopy(self.file), "sha"


@pytest.fixture
def world(monkeypatch):
    """Servers 1 and 2, each its own FakeKea; settings in a dict; the clock fixed."""
    from jen import extensions

    store = {}
    monkeypatch.setattr("jen.models.user.get_global_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr("jen.models.user.set_global_setting", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr("jen.models.user.audit", lambda *a, **k: store.setdefault("_audit", []).append(a))
    servers = [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}, {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}]
    monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
    daemons = {1: FakeKea(_cfg([{"name": "kea-dhcp4", "severity": "INFO"}])), 2: FakeKea(_cfg())}

    def pick(server):
        return daemons[server["id"]]

    monkeypatch.setattr(inv._kea, "kea_command", lambda command, server=None, **kw: pick(server).kea_command(command))
    monkeypatch.setattr(
        inv._host,
        "service_action",
        lambda server, service, action: pick(server).service_action(server, service, action),
    )
    monkeypatch.setattr(
        inv._host, "read_config_versioned", lambda server, service: pick(server).read_config_versioned(server, service)
    )

    def fake_apply(service, mutate_fn, summary, **kw):
        return pick(kw["servers"][0]).apply_change(service, mutate_fn, summary, **kw)

    monkeypatch.setattr(inv._changeset, "apply_change", fake_apply)
    monkeypatch.setattr(inv, "_now", lambda: NOW)
    inv._runs["n"] = 0
    return type("World", (), {"store": store, "servers": servers, "daemons": daemons})


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

    def test_a_refused_reload_falls_back_to_a_restart_and_says_why(self, world):
        world.daemons[1].reload_result = 1
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] and out["mode"] == "restart" and "restart:dhcp4" in world.daemons[1].calls
        assert any("config-reload was refused (reload refused)" in line for line in out["lines"])

    def test_a_refused_reload_and_a_failed_restart_is_a_failure_that_says_the_daemon_kept_its_settings(self, world):
        world.daemons[1].reload_result, world.daemons[1].restart_ok = 1, False
        out = inv.turn_on(world.servers[0], 5)
        assert not out["ok"] and "still running on its previous settings" in out["lines"][-1] and not inv.active()

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

    def test_an_entry_for_a_server_that_was_removed_is_dropped(self, world):
        self._on(world)
        world.servers.pop(0)
        inv.sweep(now=NOW)
        assert not inv.active()

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
