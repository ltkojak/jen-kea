"""
tests/test_kea_helper_investigation.py
──────────────────────────────────────
v5.68.0-beta.29 (Q165) - jen-kea-helper build 15: the Kea HOST owns the restore of investigation logging. Three ops (`investigation-arm`, `-disarm`, `-status`), the
`--self-restore [--now]` argv mode the timer runs, and the restore routine they share. Pure / tmp-dir tests with `systemctl`, the SIGHUP and the `-t` check faked: nothing
here needs systemd, a Kea or root. The logger transformation itself is tested against the vector file Jen's own routine is tested against
(tests/vectors/investigation_restore.json), so the two can never put a logger back differently.

    pytest --noconftest tests/test_kea_helper_investigation.py
"""

import copy
import importlib.util
import io
import json
import os
import pathlib
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"
_VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "investigation_restore.json"

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
SERVICE = "dhcp4"
RESTORE = {"severity": "WARN", "debuglevel": 0}
UNIT = "kea-dhcp4-server"


def _load():
    loader = SourceFileLoader("jen_kea_helper_inv", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def helper():
    return _load()


def _config(at_debug=True, marker=True):
    entry = {"name": "kea-dhcp4", "output-options": [{"output": "/var/log/kea/kea-dhcp4.log"}]}
    if at_debug:
        entry.update(severity="DEBUG", debuglevel=55)
    else:
        entry.update(severity="WARN", debuglevel=0)
    if marker:
        entry["user-context"] = {"jen-investigation": {"until": "2099-01-01T00:00:00+00:00", "restore": dict(RESTORE)}}
    return {"Dhcp4": {"valid-lifetime": 3600, "subnet4": [], "loggers": [entry]}}


class Proc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class Host:
    """One Kea host as the helper sees it: a config file, a state directory, a unit directory, a faked `systemctl` and a faked SIGHUP."""

    def __init__(self, helper, monkeypatch, tmp_path):
        self.helper, self.tmp_path = helper, tmp_path
        self.conf_dir = tmp_path / "etc-kea"
        self.conf_dir.mkdir()
        self.conf = self.conf_dir / "kea-dhcp4.conf"
        self.state_dir = tmp_path / "state"
        self.units = tmp_path / "units"
        self.now = NOW
        self.calls = []  # (name, args) of every _run_bin
        self.signals = []  # (pid, signal) of every os.kill
        self.timer = "ok"  # "ok" | "no-systemctl" | "enable-fails" | "inactive"
        self.unit_states = ["active"]  # what `is-active <kea unit>` answers, in turn (the last one repeats)
        self.restart_rc = 0
        self.main_pid = 4242
        self.kea_test = (True, {"ok": True})
        monkeypatch.setattr(helper, "_STATE_DIR", str(self.state_dir))
        monkeypatch.setattr(helper, "_SYSTEMD_DIR", str(self.units))
        monkeypatch.setattr(
            helper, "_allowed_conf_path", lambda p: isinstance(p, str) and p.endswith(".conf") and ".." not in p
        )
        monkeypatch.setattr(helper, "_now", lambda: self.now)
        monkeypatch.setattr(helper, "_sleep", lambda s: None)
        monkeypatch.setattr(helper, "_find_bin", self._find_bin)
        monkeypatch.setattr(helper, "_run_bin", self._run_bin)
        monkeypatch.setattr(helper, "_run_kea_test", lambda service, path, cfg, tls: self.kea_test)
        monkeypatch.setattr(os, "kill", lambda pid, sig: self.signals.append((pid, sig)))
        monkeypatch.setattr(os, "fchown", lambda *a: None, raising=False)
        monkeypatch.setattr(os, "chown", lambda *a: None, raising=False)

    def _find_bin(self, name):
        return None if (name == "systemctl" and self.timer == "no-systemctl") else f"/usr/bin/{name}"

    def _run_bin(self, name, args, **kw):
        self.calls.append((name, list(args)))
        if name != "systemctl":
            return Proc()
        if args[:1] == ["show"]:
            if "LoadState" in args:
                return Proc("loaded\n")
            if "MainPID" in args:
                return Proc(f"{self.main_pid}\n")
            return Proc("\n")
        if args[:1] == ["is-active"]:
            if args[1].endswith(".timer"):
                return Proc(
                    "inactive\n" if self.timer == "inactive" else "active\n", 0 if self.timer != "inactive" else 3
                )
            state = self.unit_states[0] if len(self.unit_states) == 1 else self.unit_states.pop(0)
            return Proc(state + "\n", 0 if state == "active" else 3)
        if args[:1] == ["enable"]:
            return Proc(
                "",
                1 if self.timer == "enable-fails" else 0,
                "Failed to enable unit" if self.timer == "enable-fails" else "",
            )
        if args[:1] == ["restart"]:
            if self.restart_rc == 0:
                self.unit_states = ["active"]
            return Proc("", self.restart_rc, "Job failed" if self.restart_rc else "")
        return Proc()

    def write_config(self, cfg):
        self.conf.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    def config(self):
        return json.loads(self.conf.read_text(encoding="utf-8"))

    def state(self):
        return json.loads((self.state_dir / "investigation-dhcp4.json").read_text(encoding="utf-8"))

    def arm(self, minutes=5, restore=None, **extra):
        payload = {
            "service": SERVICE,
            "path": str(self.conf),
            "until": (self.now + timedelta(minutes=minutes)).isoformat(),
            "restore": dict(restore or RESTORE),
            **extra,
        }
        return self.op("investigation-arm", payload)

    def op(self, name, payload):
        out = io.StringIO()
        code = self.helper.main(
            argv=["jen-kea-helper", name], stdin=io.StringIO(json.dumps(payload)), stdout=out, stderr=io.StringIO()
        )
        reply = json.loads(out.getvalue())
        assert code == 0
        return reply

    def tick(self, *flags):
        out = io.StringIO()
        code = self.helper.main(
            argv=["jen-kea-helper", "--self-restore", *flags], stdin=io.StringIO(""), stdout=out, stderr=io.StringIO()
        )
        assert code == 0
        return json.loads(out.getvalue())

    def restarts(self):
        return [c for c in self.calls if c[0] == "systemctl" and c[1][:1] == ["restart"]]


@pytest.fixture
def host(helper, monkeypatch, tmp_path):
    return Host(helper, monkeypatch, tmp_path)


class TestTheSharedVectors:
    """The logger transformation is the same one Jen's `clear_investigation_logging` performs: the vector file holds both kinds of case."""

    @pytest.mark.parametrize(
        "case", json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"], ids=lambda c: c["name"][:60]
    )
    def test_restore_logger_gives_the_vectors_after(self, helper, case):
        before = copy.deepcopy(case["before"])
        out, code = helper._restore_logger(before, case["restore"])
        assert out == case["after"]
        assert before == case["before"], "the caller's config is never mutated"
        assert code == ("nothing" if case["after"] == case["before"] else "ok")


class TestRestoreShape:
    @pytest.mark.parametrize(
        "restore",
        [
            {"created": True},
            {"severity": "INFO", "debuglevel": 0},
            {"severity": "absent", "debuglevel": "absent"},
            {"severity": "WARN", "debuglevel": "absent"},
        ],
    )
    def test_valid(self, helper, restore):
        assert helper._restore_shape_ok(restore) is True

    @pytest.mark.parametrize(
        "restore",
        [
            None,
            {},
            "created",
            {"created": False},
            {"created": "yes"},
            {"created": True, "severity": "INFO"},
            {"severity": "INFO"},
            {"debuglevel": 0},
            {"severity": "", "debuglevel": 0},
            {"severity": 3, "debuglevel": 0},
            {"severity": "INFO", "debuglevel": True},
            {"severity": "INFO", "debuglevel": "0"},
            {"severity": "INFO", "debuglevel": 0, "extra": 1},
        ],
    )
    def test_invalid(self, helper, restore):
        assert helper._restore_shape_ok(restore) is False


class TestArm:
    def test_it_writes_the_state_and_starts_the_timer(self, host):
        reply = host.arm(5, jen={"server_id": 1, "name": "kea-a"})
        assert reply["ok"] is True and reply["timer"] == "systemd"
        state = host.state()
        assert state["service"] == "dhcp4" and state["path"] == str(host.conf) and state["restore"] == RESTORE
        assert (
            state["restored_at"] is None
            and state["how"] is None
            and state["last_error"] is None
            and state["restarts"] == 0
        )
        assert state["jen"] == {"server_id": 1, "name": "kea-a"}
        assert datetime.fromisoformat(state["until"]) == NOW + timedelta(minutes=5)
        assert ("systemctl", ["enable", "--now", "jen-kea-investigation.timer"]) in host.calls

    def test_the_state_is_private_and_so_is_its_directory(self, host):
        host.arm()
        if os.name == "nt":
            pytest.skip("POSIX modes")
        assert (host.state_dir.stat().st_mode & 0o777) == 0o700
        assert ((host.state_dir / "investigation-dhcp4.json").stat().st_mode & 0o777) == 0o600
        assert [n for n in os.listdir(host.state_dir) if n.endswith(".jen_tmp")] == []

    def test_the_units_are_written_once_and_the_daemon_reloaded_only_when_they_changed(self, host):
        host.arm()
        assert (host.units / "jen-kea-investigation.service").read_text().count("--self-restore") == 1
        timer = (host.units / "jen-kea-investigation.timer").read_text()
        assert "OnBootSec=30s" in timer and "OnUnitActiveSec=60s" in timer and "Persistent=true" in timer
        assert host.calls.count(("systemctl", ["daemon-reload"])) == 1
        if os.name == "nt":
            pytest.skip(
                "os.open on Windows translates newlines, so the units never byte-compare equal there; the helper only runs on Linux"
            )
        host.arm()
        assert host.calls.count(("systemctl", ["daemon-reload"])) == 1, (
            "unchanged units are not rewritten and systemd is not told again"
        )

    @pytest.mark.parametrize("failure", ["no-systemctl", "enable-fails", "inactive"])
    def test_a_host_with_no_working_timer_says_none(self, host, failure):
        host.timer = failure
        reply = host.arm()
        assert reply["ok"] is True and reply["timer"] == "none" and reply["detail"]

    @pytest.mark.parametrize(
        ("change", "error"),
        [
            ({"service": "dhcp6"}, "not-allowed"),
            ({"service": "d2"}, "not-allowed"),
            ({"path": "/tmp/evil.txt"}, "not-allowed"),
            ({"path": "/etc/kea/../x.conf"}, "not-allowed"),
            ({"until": "not-a-date"}, "bad-until"),
            ({"until": 12345}, "bad-until"),
            ({"until": "2099-01-01T00:00:00+00:00"}, "bad-until"),
            ({"restore": {}}, "bad-restore"),
            ({"restore": {"severity": "INFO"}}, "bad-restore"),
            ({"restore": {"created": True, "severity": "INFO"}}, "bad-restore"),
            ({"jen": "x"}, "bad-jen"),
            ({"jen": {"other": 1}}, "bad-jen"),
        ],
    )
    def test_a_bad_request_is_refused_and_writes_nothing(self, host, change, error):
        payload = {
            "service": SERVICE,
            "path": str(host.conf),
            "until": (NOW + timedelta(minutes=5)).isoformat(),
            "restore": dict(RESTORE),
            **change,
        }
        reply = host.op("investigation-arm", payload)
        assert reply["ok"] is False and reply["error"] == error
        assert not (host.state_dir / "investigation-dhcp4.json").exists()
        assert host.calls == []

    def test_a_past_deadline_is_armed_and_due_at_the_next_tick(self, host):
        assert host.arm(-3)["ok"] is True

    def test_arming_again_is_a_new_session(self, host):
        host.arm(5, restore={"created": True})
        host.arm(15, restore=RESTORE)
        state = host.state()
        assert (
            state["restore"] == RESTORE
            and datetime.fromisoformat(state["until"]) == NOW + timedelta(minutes=15)
            and state["restored_at"] is None
        )


class TestDisarm:
    def test_it_restores_the_logger_and_asks_the_daemon_to_re_read_the_file(self, host):
        host.write_config(_config())
        host.arm()
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply == {
            "ok": True,
            "restored": True,
            "how": "reload",
            "detail": "",
            "helper_version": 7,
            "helper_build": 15,
        }
        assert host.config() == _config(at_debug=False, marker=False)
        assert host.signals and host.signals[0][0] == 4242
        assert host.restarts() == []
        state = host.state()
        assert state["restored_at"] and state["how"] == "reload" and state["last_error"] is None
        assert json.loads((host.conf_dir / "kea-dhcp4.conf.jen_backup").read_text()) == _config(), (
            "the previous file is kept"
        )

    def test_a_file_that_is_already_restored_still_gets_a_reload(self, host):
        """Jen (or a person) cleaned the file but the daemon may never have re-read it: the host makes sure."""
        host.write_config(_config(at_debug=False, marker=False))
        host.arm()
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["restored"] is True and reply["how"] == "reload" and host.signals
        assert host.config() == _config(at_debug=False, marker=False)

    def test_not_armed_is_not_an_error(self, host):
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert (
            reply["ok"] is True
            and reply["restored"] is False
            and reply["how"] == "nothing"
            and reply["detail"] == "not armed"
        )

    def test_a_second_disarm_does_nothing(self, host):
        host.write_config(_config())
        host.arm()
        host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        signals = len(host.signals)
        again = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert (
            again["ok"] is True
            and again["restored"] is False
            and again["detail"] == "already restored"
            and len(host.signals) == signals
        )

    def test_another_path_than_the_armed_one_is_refused(self, host):
        host.write_config(_config())
        host.arm()
        other = host.conf_dir / "other.conf"
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(other)})
        assert reply["ok"] is False and reply["error"] == "bad-state"
        assert host.config() == _config(), "nothing was touched"

    def test_a_bad_request_is_refused(self, host):
        assert host.op("investigation-disarm", {"service": "dhcp6", "path": str(host.conf)})["error"] == "not-allowed"
        assert host.op("investigation-disarm", {"service": SERVICE, "path": "/tmp/x.txt"})["error"] == "not-allowed"

    def test_a_config_that_fails_the_daemons_own_check_is_not_written(self, host):
        host.write_config(_config())
        host.arm()
        host.kea_test = (False, {"ok": False, "error": "testerror", "detail": "ERROR bad"})
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is False and reply["error"] == "restore-failed" and "testerror" in reply["detail"]
        assert host.config() == _config(), "the live file is untouched"
        assert host.signals == [] and host.restarts() == []
        state = host.state()
        assert state["restored_at"] is None and "testerror" in state["last_error"], "and the next tick tries again"

    def test_an_unreadable_config_is_a_recorded_failure_not_a_crash(self, host):
        host.conf.write_text("{ not json", encoding="utf-8")
        host.arm()
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is False and "could not be read" in reply["detail"]
        assert "could not be read" in host.state()["last_error"]

    def test_a_missing_config_is_a_recorded_failure(self, host):
        host.arm()
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is False and host.state()["restored_at"] is None


class TestTheReload:
    def test_a_unit_that_is_not_active_after_the_hup_is_restarted(self, host):
        host.write_config(_config())
        host.arm()
        host.unit_states = ["inactive"]  # the HUP left it down
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is True and reply["how"] == "restart" and len(host.restarts()) == 1
        assert host.state()["restarts"] == 1

    def test_a_unit_with_no_main_process_is_restarted_without_a_signal(self, host):
        host.write_config(_config())
        host.arm()
        host.main_pid = 0
        host.unit_states = ["inactive"]
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["how"] == "restart" and host.signals == []

    def test_a_restart_that_fails_is_recorded_and_never_repeated(self, host):
        host.write_config(_config())
        host.arm()
        host.unit_states = ["inactive"]
        host.restart_rc = 1
        first = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert first["ok"] is False and "restart" in first["detail"] and len(host.restarts()) == 1
        for _ in range(3):
            host.tick("--now")
        assert len(host.restarts()) == 1, "one restart per state file, whatever the ticks do"
        assert "not restarting again" in host.state()["last_error"]
        assert host.config() == _config(at_debug=False, marker=False), (
            "the FILE is restored; only the daemon could not be made to re-read it"
        )

    def test_a_host_with_no_kea_unit_reports_it(self, host, monkeypatch):
        host.write_config(_config())
        host.arm()
        monkeypatch.setattr(host.helper, "_resolve_unit", lambda service, action: None)
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is False and "no Kea unit" in reply["detail"]


class TestStatus:
    def test_not_armed(self, host):
        assert host.op("investigation-status", {"service": SERVICE})["armed"] is False

    def test_armed_then_restored(self, host):
        host.write_config(_config())
        host.arm(5, jen={"server_id": 2, "name": "kea-b"})
        status = host.op("investigation-status", {"service": SERVICE})
        assert (
            status["ok"]
            and status["armed"] is True
            and status["restored_at"] is None
            and status["jen"]["name"] == "kea-b"
        )
        host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["armed"] is False and status["restored_at"] and status["how"] == "reload"

    def test_a_failed_restore_shows_the_hosts_own_error(self, host):
        host.conf.write_text("{ not json", encoding="utf-8")
        host.arm()
        host.tick("--now")
        assert "could not be read" in host.op("investigation-status", {"service": SERVICE})["last_error"]

    def test_another_service_is_refused(self, host):
        assert host.op("investigation-status", {"service": "d2"})["error"] == "not-allowed"


class TestSelfRestore:
    """The timer's tick: no stdin, no Jen, nothing but the state file."""

    def test_an_expired_state_is_restored_and_one_that_is_not_due_is_left(self, host):
        host.write_config(_config())
        host.arm(5)
        out = host.tick()
        assert out["restored"] == [] and host.config() == _config(), "five minutes left: not due"
        host.now = NOW + timedelta(minutes=5, seconds=1)
        out = host.tick()
        assert out["ok"] is True and out["restored"] == [{"service": "dhcp4", "how": "reload"}]
        assert host.config() == _config(at_debug=False, marker=False)
        assert host.tick()["restored"] == [], "restored once"

    def test_now_restores_what_is_armed_without_waiting(self, host):
        host.write_config(_config())
        host.arm(60)
        assert host.tick("--now")["restored"] == [{"service": "dhcp4", "how": "reload"}]
        assert host.config() == _config(at_debug=False, marker=False)

    def test_a_failed_restore_is_retried_on_the_next_tick(self, host):
        host.write_config(_config())
        host.arm(-1)
        host.kea_test = (False, {"ok": False, "error": "testerror", "detail": "ERROR"})
        out = host.tick()
        assert out["ok"] is False and out["failed"][0]["error"]
        host.kea_test = (True, {"ok": True})
        assert host.tick()["restored"] == [{"service": "dhcp4", "how": "reload"}]
        assert host.state()["last_error"] is None

    def test_it_works_with_nothing_armed_and_with_no_state_directory(self, host):
        assert host.tick() == {
            "ok": True,
            "checked": 0,
            "restored": [],
            "failed": [],
            "helper_version": 7,
            "helper_build": 15,
        }

    def test_a_state_file_the_helper_did_not_write_is_reported_and_never_acted_on(self, host):
        host.write_config(_config())
        host.arm(-1)
        state = host.state()
        state["path"] = "/etc/passwd"  # tampered
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state))
        out = host.tick()
        assert out["ok"] is False and out["failed"][0]["error"] == "the state file is not usable"
        assert host.config() == _config() and host.signals == []

    def test_an_unreadable_state_file_is_reported(self, host):
        host.arm(-1)
        (host.state_dir / "investigation-dhcp4.json").write_text("not json")
        out = host.tick()
        assert out["ok"] is False and out["failed"]

    def test_the_argv_mode_reads_no_stdin(self, host):
        class Boom:
            def read(self, *_):
                raise AssertionError("stdin was read")

        out = io.StringIO()
        assert (
            host.helper.main(argv=["jen-kea-helper", "--self-restore"], stdin=Boom(), stdout=out, stderr=io.StringIO())
            == 0
        )
        assert json.loads(out.getvalue())["ok"] is True

    def test_two_services_worth_of_files_are_not_a_thing(self, host):
        host.arm(-1)
        (host.state_dir / "investigation-dhcp6.json").write_text("{}")
        assert host.tick()["checked"] == 2, "only dhcp4 state files are ever acted on (the other name does not match)"


class TestTheContract:
    def test_the_ops_are_registered_and_the_build_is_15(self, helper):
        for name in ("investigation-arm", "investigation-disarm", "investigation-status"):
            assert name in helper._OPS
        assert helper.HELPER_BUILD == 15 and helper.HELPER_VERSION == 7

    def test_there_is_still_no_sudoers_change(self):
        root = _SCRIPT.parent
        text = (root / "jen-sudoers").read_text(encoding="utf-8")
        assert "investigation" not in text and "self-restore" not in text, (
            "the one-line grant is unchanged: the timer runs the helper as root without sudo"
        )

    def test_the_timer_runs_the_installed_helper_as_a_oneshot(self, helper):
        assert "ExecStart=/usr/local/sbin/jen-kea-helper --self-restore" in helper._TIMER_SERVICE_TEXT
        assert "Type=oneshot" in helper._TIMER_SERVICE_TEXT
        assert "OnBootSec=30s" in helper._TIMER_TEXT and "OnUnitActiveSec=60s" in helper._TIMER_TEXT

    def test_the_helper_never_trusts_the_marker_to_know_how_to_restore(self):
        source = _SCRIPT.read_text(encoding="utf-8")
        a = source.index("def _restore_state(")
        b = source.index("def _restore_failed(")
        body = source[a:b]
        assert 'state["restore"]' in body and "investigation_marker" not in body and "_INV_KEY" not in body

    def test_the_timer_is_not_a_second_source_of_the_deadline(self, host):
        """`until` is the helper's own: the units carry no time and the tick reads only the state file."""
        host.arm(5)
        assert "2026" not in (host.units / "jen-kea-investigation.timer").read_text()
