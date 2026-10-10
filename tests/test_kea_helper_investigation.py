"""
tests/test_kea_helper_investigation.py
──────────────────────────────────────
v5.68.0-beta.29 (Q165) - jen-kea-helper build 15: the Kea HOST owns the restore of investigation logging. Three ops (`investigation-arm`, `-disarm`, `-status`), the
`--self-restore [--now]` argv mode the timer runs, and the restore routine they share. Pure / tmp-dir tests with `systemctl`, the SIGHUP and the `-t` check faked: nothing
here needs systemd, a Kea or root. The logger transformation itself is tested against the vector file Jen's own routine is tested against
(tests/vectors/investigation_restore.json), so the two can never put a logger back differently.

    pytest --noconftest tests/test_kea_helper_investigation.py
"""

import base64
import copy
import importlib.util
import io
import json
import os
import pathlib
import socket
import time
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
        # build 17 (Q168): the evidence is the daemon's own ANSWER. `loaded` is what the RUNNING daemon runs (the first config written is what it was started with); `socket_mode` says whether
        # its control socket "answers" config-get from `loaded`, is "silent" (refuses / times out) or is "absent" from the config. A SIGHUP does what `reload_mode` says -
        #   "success" (loaded := the file; Kea logs started + completion), "applied_hidden" (loaded := the file; the restored level hides the completion line: only the START is in the log),
        #   "started_not_applied" (Kea logs the START and never applies the file: THE beta.30 P1 sequence), "fail" (Kea logs a refusal; loaded unchanged), "silent" (nothing at all);
        # a restart does what `restart_mode` says - "ok" (a NEW pid, loaded := the file), "same_pid" (the restart was absorbed: same pid, loaded unchanged), "fail" (a start-failure id, no
        # process), "fresh_but_old" (a new pid still running the OLD config).
        self.log = tmp_path / "kea-dhcp4.log"
        self.log.write_text("old line DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS from long ago\n", encoding="utf-8")
        self.reload_mode = "success"
        self.restart_mode = "ok"
        self.socket_mode = "answers"  # or a LIST consumed one entry per `config-get` (the last one repeats): ["at-debug", "silent", "silent"]; "at-debug" = the daemon answers with the DEBUG-55 + marker logger, "hang" = it accepts and never answers (two socket waits of the fake clock)
        self.asks, self.log_on_ask = (
            0,
            None,
        )  # `log_on_ask=(n, [lines])`: the lines are appended when the n-th question is asked
        self.clock = 0.0  # the fake wall clock: `_sleep` advances it and `_monotonic` reads it, so every wait of the helper is measured in time, not in sleeps
        self.loaded = None
        self.pid_after_restart = None
        self.kea_test = (True, {"ok": True})
        monkeypatch.setattr(helper, "_STATE_DIR", str(self.state_dir))
        monkeypatch.setattr(helper, "_SYSTEMD_DIR", str(self.units))
        monkeypatch.setattr(
            helper, "_allowed_conf_path", lambda p: isinstance(p, str) and p.endswith(".conf") and ".." not in p
        )
        monkeypatch.setattr(helper, "_now", lambda: self.now)
        monkeypatch.setattr(helper, "_sleep", self._sleep)
        monkeypatch.setattr(helper, "_monotonic", lambda: self.clock)
        monkeypatch.setattr(helper, "_find_bin", self._find_bin)
        monkeypatch.setattr(helper, "_run_bin", self._run_bin)
        monkeypatch.setattr(helper, "_run_kea_test", lambda service, path, cfg, tls: self.kea_test)
        monkeypatch.setattr(os, "kill", self._kill)
        monkeypatch.setattr(
            helper,
            "_control_socket",
            lambda config: None if self._peek_mode() == "absent" else ("unix", str(tmp_path / "kea4-ctrl.sock")),
        )
        monkeypatch.setattr(helper, "_ask_daemon", self._ask)
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: isinstance(p, str) and p.endswith(".log"))
        monkeypatch.setattr(os, "fchown", lambda *a: None, raising=False)
        monkeypatch.setattr(os, "chown", lambda *a: None, raising=False)

    def _append(self, *lines):
        with open(self.log, "a", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in lines))

    def _file_config(self):
        try:
            return json.loads(self.conf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _sleep(self, seconds):
        self.clock += seconds

    def _cursor_of(self):
        """The mode source in force: a plain value, a list, or {"before": ..., "after": ...} (before / after the one restart was issued)."""
        if isinstance(self.socket_mode, dict):
            return self.socket_mode, ("after" if self.restarts() else "before")
        return None, None

    def _peek_mode(self):
        holder, key = self._cursor_of()
        value = holder[key] if holder else self.socket_mode
        return value[0] if isinstance(value, list) else value

    def _next_mode(self):
        holder, key = self._cursor_of()
        value = holder[key] if holder else self.socket_mode
        if isinstance(value, list):
            return value.pop(0) if len(value) > 1 else value[0]
        return value

    def _ask(self, spec, command):
        """What the daemon's own control socket answers (in-process: the transport has its own tests, with real sockets)."""
        self.asks += 1
        if self.log_on_ask is not None and self.asks == self.log_on_ask[0]:
            self._append(
                *self.log_on_ask[1]
            )  # a line that lands in Kea's log between two questions (another instance of Kea wrote it)
        mode = self._next_mode()
        if mode == "hang":
            self.clock += 2 * self.helper._SOCKET_WAIT_S  # the connect and the read each wait the full time
            return None
        if mode not in ("answers", "at-debug"):
            return None
        if command != "config-get":
            return {"result": 1, "text": "unsupported"}
        source = _config() if mode == "at-debug" else self.loaded
        section = copy.deepcopy((source or {}).get("Dhcp4", {}))
        return {"result": 0, "arguments": {"Dhcp4": section}}

    def daemon_runs(self, cfg):
        self.loaded = copy.deepcopy(cfg)

    def _kill(self, pid, sig):
        self.signals.append((pid, sig))
        started = "2026-10-10 12:00:00.001 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION initiate server reconfiguration using file: x"
        if self.reload_mode in ("success", "applied_hidden"):
            self.loaded = copy.deepcopy(self._file_config())
        if self.reload_mode == "success":
            self._append(
                started,
                "2026-10-10 12:00:00.090 INFO  [kea-dhcp4.dhcp4/1] DHCP4_CONFIG_COMPLETE DHCPv4 server has completed configuration",
                "2026-10-10 12:00:00.095 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS dynamic server reconfiguration succeeded with file: x",
            )
        elif self.reload_mode in ("applied_hidden", "started_not_applied"):
            self._append(started)
        elif (
            self.reload_mode == "logged_but_not_loaded"
        ):  # Kea logs the whole success and the daemon is still running the old config: the log and the daemon DISAGREE
            self._append(
                started,
                "2026-10-10 12:00:00.090 INFO  [kea-dhcp4.dhcp4/1] DHCP4_CONFIG_COMPLETE DHCPv4 server has completed configuration",
                "2026-10-10 12:00:00.095 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS dynamic server reconfiguration succeeded with file: x",
            )
        elif self.reload_mode == "fail":
            self._append(
                started,
                "2026-10-10 12:00:00.050 ERROR [kea-dhcp4.dhcp4/1] DHCP4_CONFIG_LOAD_FAIL configuration error using file: x, reason: unsupported parameter",
                "2026-10-10 12:00:00.051 ERROR [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_FAIL dynamic server reconfiguration failed with file: x",
            )

    # ── the log, rotated and flooded the way a real one is ─────────────────────────────────────────────────────────────
    def log_rotate(self, rename=True, then=""):
        """Rotate Kea's log: by rename (the old file becomes `<log>.1`, a new one starts) or by truncation in place; `then` is written into the new/emptied file."""
        if rename:
            os.replace(self.log, str(self.log) + ".1")
            self.log.write_text(then, encoding="utf-8")
        else:
            self.log.write_text(then, encoding="utf-8")

    def log_flood(self, nbytes, last_line=""):
        """Append `nbytes` of unrelated DEBUG lines and then `last_line`."""
        filler = "2026-10-10 12:00:01.000 DEBUG [kea-dhcp4.packets/1] DHCP4_PACKET_RECEIVED noise noise noise noise noise noise noise noise\n"
        with open(self.log, "a", encoding="utf-8") as f:
            written = 0
            while written < nbytes:
                f.write(filler)
                written += len(filler)
            if last_line:
                f.write(last_line + "\n")

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
        if args[:1] == ["is-enabled"]:
            return Proc("enabled\n" if self.timer not in ("inactive", "enable-fails") else "disabled\n", 0)
        if args[:1] == ["enable"]:
            return Proc(
                "",
                1 if self.timer == "enable-fails" else 0,
                "Failed to enable unit" if self.timer == "enable-fails" else "",
            )
        if args[:1] == ["restart"]:
            if self.restart_rc == 0:
                self.unit_states = ["active"]
                new_pid = self.pid_after_restart or self.main_pid + 1
                if self.restart_mode in ("ok", "fresh_but_old"):
                    self.main_pid = new_pid
                    if self.restart_mode == "ok":
                        self.loaded = copy.deepcopy(self._file_config())
                    self._append(
                        "2026-10-10 12:00:03.000 INFO  [kea-dhcp4.dhcp4/1] DHCP4_STARTED Kea DHCPv4 server version 3.0.3 started"
                    )
                elif self.restart_mode == "fail":
                    self.unit_states = ["inactive"]
                    self.main_pid = 0
                    self._append(
                        "2026-10-10 12:00:03.000 ERROR [kea-dhcp4.dhcp4/1] DHCP4_CONFIG_LOAD_FAIL configuration error using file: x"
                    )
            return Proc("", self.restart_rc, "Job failed" if self.restart_rc else "")
        return Proc()

    def write_config(self, cfg):
        self.conf.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        if self.loaded is None:
            self.loaded = copy.deepcopy(cfg)  # the first file written is what the daemon was started with

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
            "log_path": str(self.log),
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
        self.last_code = code
        reply = json.loads(out.getvalue())
        assert code == (0 if reply["ok"] else 1), "the exit status says whether a restore failed (build 16)"
        return reply

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
            ({"log_path": "/tmp/kea.txt"}, "bad-log-path"),
        ],
    )
    def test_a_bad_request_is_refused_and_writes_nothing(self, host, change, error):
        payload = {
            "service": SERVICE,
            "path": str(host.conf),
            "until": (NOW + timedelta(minutes=5)).isoformat(),
            "restore": dict(RESTORE),
            "log_path": str(host.log),
            **change,
        }
        reply = host.op("investigation-arm", payload)
        assert reply["ok"] is False and reply["error"] == error
        assert not (host.state_dir / "investigation-dhcp4.json").exists()
        assert host.calls == []

    def test_the_log_path_is_optional_when_the_daemon_has_a_control_socket(self, host):
        """Build 17 (Q168): a Kea that logs to syslog or stdout has no log file, but its control socket can answer the question directly."""
        reply = host.arm(5, log_path=None)
        assert reply["ok"] is True and host.state()["log_path"] is None

    def test_a_log_that_does_not_exist_is_fine_while_the_daemon_can_be_asked(self, host):
        assert host.arm(5, log_path=str(host.log) + ".missing.log")["ok"] is True

    def test_no_socket_and_no_log_is_refused_because_nothing_could_be_verified(self, host):
        host.socket_mode = "absent"
        host.log.unlink()
        reply = host.arm(5, log_path=None)
        assert reply["ok"] is False and reply["error"] == "no-evidence" and "no way to see" in reply["detail"]
        assert not (host.state_dir / "investigation-dhcp4.json").exists()

    def test_no_socket_but_a_readable_log_is_enough(self, host):
        host.socket_mode = "absent"
        assert host.arm(5)["ok"] is True

    def test_the_log_path_is_found_from_the_files_own_logger_when_the_caller_sent_none(self, host):
        host.write_config(
            {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": str(host.log)}]}]}}
        )
        host.socket_mode = "absent"
        assert host.arm(5, log_path=None)["ok"] is True and host.state()["log_path"] == str(host.log)

    def test_a_past_deadline_is_armed_and_due_at_the_next_tick(self, host):
        assert host.arm(-3)["ok"] is True

    def test_arming_after_the_last_session_was_restored_is_a_new_session(self, host):
        host.write_config(_config())
        host.arm(5, restore={"created": True})
        host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
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
            "helper_build": 17,
        }
        assert host.config() == _config(at_debug=False, marker=False)
        assert host.signals and host.signals[0][0] == 4242
        assert host.restarts() == []
        state = host.state()
        assert state["restored_at"] and state["how"] == "reload" and state["last_error"] is None
        assert json.loads((host.conf_dir / "kea-dhcp4.conf.jen_backup").read_text()) == _config(), (
            "the previous file is kept"
        )

    def test_a_file_that_is_already_restored_still_gets_a_reload_when_the_daemon_is_not_running_it(self, host):
        """Jen (or a person) cleaned the file but the daemon never re-read it: the host makes sure."""
        host.write_config(_config(at_debug=False, marker=False))
        host.daemon_runs(_config())  # the daemon is still at DEBUG 55
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
        host.reload_mode = "silent"  # the HUP left Kea saying nothing: not confirmed
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is True and reply["how"] == "restart" and len(host.restarts()) == 1
        assert host.state()["restarts"] == 1

    def test_a_unit_with_no_main_process_is_restarted_without_a_signal(self, host):
        host.write_config(_config())
        host.arm()
        host.main_pid = 0
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["how"] == "restart" and host.signals == []

    def test_a_restart_that_fails_is_recorded_and_never_repeated(self, host):
        host.write_config(_config())
        host.arm()
        host.reload_mode = "silent"
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
            "helper_build": 17,
        }

    def test_a_state_file_the_helper_did_not_write_is_reported_and_never_acted_on(self, host):
        host.write_config(_config())
        host.arm(-1)
        state = host.state()
        state["path"] = "/etc/passwd"  # tampered
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state))
        out = host.tick()
        assert out["ok"] is False and out["failed"][0]["error"].startswith("the state file is not usable")
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
    def test_the_ops_are_registered_and_the_build_is_17(self, helper):
        for name in ("investigation-arm", "investigation-disarm", "investigation-status", "investigation-timer"):
            assert name in helper._OPS
        assert helper.HELPER_BUILD == 17 and helper.HELPER_VERSION == 7

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


class TestARestoreIsDoneWhenTheDaemonSaysSo:
    """v5.68.0-beta.31 (Q168, INV-007): `restored_at` is written on exactly one of three pieces of evidence - the running daemon's own `config-get` shows the file's logger, Kea's own
    completion id (only when no socket answered), a NEW active process after the one restart - and the state says which. A reload-START line is never completion: that was the beta.30 P1
    (a restored WARN level hides the INFO completion line, and "started, nothing failed for three seconds" was recorded as a restore)."""

    def _disarm(self, host):
        return host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})

    def _armed_at_debug(self, host, **arm):
        host.write_config(_config())
        host.arm(**arm)

    # ── the daemon's own answer ─────────────────────────────────────────────────────────────────────────────────────────
    def test_the_p1_row_the_socket_says_restored_while_the_log_shows_only_the_started_line(self, host):
        self._armed_at_debug(host)
        host.reload_mode = (
            "applied_hidden"  # the restored level hides the completion line: the log has the START and nothing else
        )
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "reload" and host.restarts() == []
        assert host.state()["evidence"] == "config-get" and host.state()["restored_at"]

    def test_the_socket_alone_is_enough_when_there_is_no_log_file_at_all(self, host):
        self._armed_at_debug(host, log_path=None)
        host.log.unlink()
        host.reload_mode = "applied_hidden"
        reply = self._disarm(host)
        assert reply["ok"] and host.state()["evidence"] == "config-get", "no log was readable and none was needed"

    def test_a_daemon_that_already_runs_the_file_is_accepted_without_a_signal(self, host):
        host.write_config(
            _config(at_debug=False, marker=False)
        )  # the daemon was started with (or has been reloaded onto) the clean file
        host.arm()
        reply = self._disarm(host)
        assert reply["ok"] and host.signals == [] and host.restarts() == []
        assert host.state()["evidence"] == "config-get"

    def test_a_logger_somebody_changed_on_purpose_is_verified_against_the_file_not_the_restore_object(self, host):
        """The state says "created" (remove the logger); the file's logger is WARN with no marker (a person set it since): `_restore_logger` answers "nothing", and the daemon is judged by the FILE."""
        host.write_config(_config())
        host.arm(5, restore={"created": True})
        host.write_config(_config(at_debug=False, marker=False))
        host.reload_mode = "applied_hidden"
        reply = self._disarm(host)
        assert reply["ok"] and host.state()["evidence"] == "config-get", reply

    # ── the log, only when no socket answered ───────────────────────────────────────────────────────────────────────────
    def test_no_socket_and_a_completion_line_is_log_evidence(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "silent"
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "reload" and host.state()["evidence"] == "log" and host.restarts() == []

    def test_a_silent_socket_and_only_a_started_line_is_not_a_restore_the_one_restart_decides(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "silent"
        host.reload_mode = "started_not_applied"
        reply = self._disarm(host)
        assert len(host.restarts()) == 1, "the started line is not evidence: the one restart was taken"
        assert reply["ok"] and reply["how"] == "restart" and host.state()["evidence"] == "process"

    def test_the_started_line_is_quoted_in_the_error_when_nothing_ever_confirms(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "silent"
        host.reload_mode = "started_not_applied"
        host.restart_mode = "same_pid"
        reply = self._disarm(host)
        assert (
            reply["ok"] is False
            and "the reload started (" in reply["detail"]
            and "nothing shows it completed" in reply["detail"]
        )
        assert host.state()["restored_at"] is None

    def test_the_socket_still_at_debug_while_the_log_shows_completion_is_a_contradiction_not_a_restore(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "logged_but_not_loaded"
        host.restart_mode = "fresh_but_old"
        reply = self._disarm(host)
        assert reply["ok"] is False and host.state()["restored_at"] is None

    def test_a_refused_reload_is_reported_with_kea_s_line_and_nothing_is_restarted(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "fail"
        reply = self._disarm(host)
        assert (
            reply["ok"] is False
            and "Kea refused the restored config" in reply["detail"]
            and "DHCP4_CONFIG_LOAD_FAIL" in reply["detail"]
        )
        assert host.restarts() == [] and host.state()["restored_at"] is None and host.state()["attempts"] == 1

    # ── the one restart ─────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_restart_gives_a_new_active_process_and_that_is_process_evidence_when_no_socket_answers(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "absent"
        host.reload_mode = "silent"
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "restart" and host.state()["evidence"] == "process"

    def test_a_restart_that_was_absorbed_keeps_the_same_pid_and_is_not_a_restore(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "absent"
        host.reload_mode = "silent"
        host.restart_mode = "same_pid"
        reply = self._disarm(host)
        assert reply["ok"] is False and host.state()["restored_at"] is None and len(host.restarts()) == 1

    def test_a_restart_with_a_start_failure_id_is_not_a_restore(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"
        host.restart_mode = "fail"
        reply = self._disarm(host)
        assert reply["ok"] is False and "restarted, but Kea refused the restored config" in reply["detail"]
        assert host.state()["restarts"] == 1 and host.state()["restored_at"] is None

    def test_a_restart_the_socket_confirms_is_config_get_evidence(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "restart" and host.state()["evidence"] == "config-get"

    def test_a_new_process_the_socket_says_is_still_at_debug_is_not_a_restore(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"
        host.restart_mode = "fresh_but_old"
        reply = self._disarm(host)
        assert reply["ok"] is False and host.state()["restored_at"] is None

    def test_a_restart_that_fails_outright_is_recorded_and_never_repeated(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"
        host.restart_rc = 1
        assert self._disarm(host)["ok"] is False
        for _ in range(3):
            host.tick("--now")
        assert len(host.restarts()) == 1 and "not restarting again" in host.state()["last_error"]

    # ── bookkeeping ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_ten_unconfirmed_ticks_say_a_person_has_to_act_and_a_later_success_clears_it(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "silent"
        host.reload_mode = "started_not_applied"
        host.restart_mode = "same_pid"
        for n in range(10):
            out = host.tick("--now")
            assert out["ok"] is False and host.last_code == 1
            assert host.state()["attempts"] == n + 1
        assert host.state()["needs_hand"] is True
        host.socket_mode, host.reload_mode = "answers", "success"
        assert host.tick("--now")["ok"] is True
        assert host.state()["needs_hand"] is False and host.state()["evidence"] == "config-get"

    def test_restored_at_and_its_evidence_are_written_in_exactly_one_place(self):
        source = _SCRIPT.read_text(encoding="utf-8")
        assert source.count("restored_at=") == 1, "one writer of restored_at"
        a = source.index("restored_at=")
        before = source[a - 900 : a]
        assert 'how not in ("reload", "restart")' in before and "evidence not in _EVIDENCE" in before, (
            "after a verified how AND the evidence that verified it"
        )
        assert "evidence=evidence" in source[a : a + 200]

    def test_there_is_no_legacy_branch_and_no_settle_heuristic_left(self):
        source = _SCRIPT.read_text(encoding="utf-8")
        section = source[source.index("# ── Build 15") :]
        for gone in ("_load_state", "_STARTED_SETTLE_S", "_log_lines_after", '"log_path" not in state', "legacy ="):
            assert gone not in section, gone


class TestOneAnswerAboutTheStateFile:
    """v5.68.0-beta.31 (Q168, INV-009): an existing state file that cannot be trusted is never "no session". Arm, disarm, status and the tick give ONE answer."""

    BAD = {
        "malformed JSON": "{ nope",
        "a JSON list": "[1, 2]",
        "an object with missing fields": '{"service": "dhcp4"}',
        "a bad restore object": None,  # filled from a real state below
    }

    def _write(self, host, kind):
        host.write_config(_config())
        if kind == "absent":
            return
        host.arm()
        path = host.state_dir / "investigation-dhcp4.json"
        if kind == "pending":
            return
        if kind == "restored":
            state = host.state()
            state.update(restored_at="2026-10-10T12:05:00+00:00", how="reload", evidence="config-get")
            path.write_text(json.dumps(state))
            return
        if kind == "a bad restore object":
            state = host.state()
            state["restore"] = {"severity": 5}
            path.write_text(json.dumps(state))
            return
        path.write_text(self.BAD[kind])

    @pytest.mark.parametrize(
        "kind", ["malformed JSON", "a JSON list", "an object with missing fields", "a bad restore object"]
    )
    def test_a_file_that_exists_and_cannot_be_trusted_is_bad_state_everywhere(self, host, kind):
        self._write(host, kind)
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["ok"] is False and status["error"] == "bad-state" and status["armed"] is None
        assert (
            "cannot be trusted" in status["detail"]
            and "--self-restore --now" in status["detail"]
            and status["state_file"].endswith("investigation-dhcp4.json")
        )
        disarm = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert disarm["ok"] is False and disarm["error"] == "bad-state" and "cannot be trusted" in disarm["detail"]
        arm = host.arm(5)
        assert (
            arm["ok"] is False
            and arm["error"] == "armed"
            and arm["existing"]["unreadable"] is True
            and "cannot be trusted" in arm["detail"]
        )
        tick = host.tick("--now")
        assert (
            tick["ok"] is False
            and tick["failed"][0]["error"].startswith("the state file is not usable")
            and host.last_code == 1
        )
        assert host.signals == [] and host.config() == _config(), "nothing was restored, signalled or overwritten"

    def test_an_absent_file_is_no_session_everywhere(self, host):
        self._write(host, "absent")
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["ok"] is True and status["armed"] is False
        assert host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})["detail"] == "not armed"
        assert host.tick("--now")["checked"] == 0
        assert host.arm(5)["ok"] is True

    def test_a_pending_file_is_a_session_everywhere(self, host):
        self._write(host, "pending")
        assert host.op("investigation-status", {"service": SERVICE})["armed"] is True
        assert host.arm(5)["idempotent"] is True
        assert host.tick("--now")["restored"] == [{"service": "dhcp4", "how": "reload"}]

    def test_a_restored_file_is_a_finished_session_everywhere(self, host):
        self._write(host, "restored")
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["armed"] is False and status["restored_at"] and status["evidence"] == "config-get"
        assert (
            host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})["detail"]
            == "already restored"
        )
        assert host.tick("--now")["restored"] == []
        assert host.arm(5)["ok"] is True

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs a POSIX non-root user to make a file unreadable",
    )
    def test_an_unreadable_file_is_bad_state_too(self, host):
        self._write(host, "pending")
        path = host.state_dir / "investigation-dhcp4.json"
        path.chmod(0)
        try:
            assert host.op("investigation-status", {"service": SERVICE})["error"] == "bad-state"
            assert host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})["error"] == "bad-state"
            assert host.arm(5)["error"] == "armed"
            assert host.tick("--now")["failed"]
        finally:
            path.chmod(0o600)

    def test_a_dangling_symlink_is_a_file_that_exists_and_cannot_be_read(self, host):
        if os.name == "nt":
            pytest.skip("symlinks need privileges on Windows")
        host.state_dir.mkdir(parents=True, exist_ok=True)
        (host.state_dir / "investigation-dhcp4.json").symlink_to(host.tmp_path / "nowhere")
        assert host.op("investigation-status", {"service": SERVICE})["error"] == "bad-state"


class TestTheLogIsFollowedNotAssumed:
    """v5.68.0-beta.31 (Q168, INV-010): log evidence follows the file's identity across rotation and is read incrementally; an exhausted or unreadable log is unconfirmed, never success."""

    OK = "2026-10-10 12:00:00.095 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS dynamic server reconfiguration succeeded"

    def _cursor(self, host):
        return host.helper._LogCursor(str(host.log))

    def test_appended_lines_are_read(self, host):
        cursor = self._cursor(host)
        host._append("new line one", self.OK)
        assert cursor.new_lines()[-1] == self.OK
        assert cursor.new_lines() == [], "and only once"

    def test_a_truncation_in_place_is_read_from_the_start(self, host):
        host.log_flood(
            2000
        )  # (a file the truncation makes SMALLER than the offset: the same inode grown past it again cannot be told from an append - the socket is the arbiter then)
        cursor = self._cursor(host)
        host.log_rotate(rename=False, then=self.OK + "\n")
        assert cursor.new_lines() == [self.OK]

    def test_a_rename_with_a_smaller_new_file(self, host):
        cursor = self._cursor(host)
        host.log_rotate(rename=True, then=self.OK + "\n")
        assert self.OK in cursor.new_lines()

    def test_a_rename_with_a_new_file_LARGER_than_the_old_offset_is_read_from_its_start(self, host):
        """Beta.30 read a rotated file from the OLD offset whenever it had grown past it: the completion line at byte 10 of the new file was never seen."""
        cursor = self._cursor(host)
        size_before = os.path.getsize(host.log)
        host.log_rotate(rename=True, then=self.OK + "\n" + "x" * (size_before * 3) + "\n")
        assert self.OK in cursor.new_lines()

    def test_the_completion_line_written_to_the_old_file_just_before_the_rotation_is_found_in_dot_1(self, host):
        cursor = self._cursor(host)
        host._append(self.OK)
        host.log_rotate(rename=True, then="a fresh line\n")
        lines = cursor.new_lines()
        assert self.OK in lines and "a fresh line" in lines

    def test_two_mebibytes_of_noise_before_the_one_line_that_matters(self, host):
        cursor = self._cursor(host)
        host.log_flood(2 << 20, last_line=self.OK)
        lines = cursor.new_lines()
        assert lines[-1] == self.OK and cursor.scanned > host.helper._LOG_READ_MAX

    def test_sixty_five_mebibytes_exhaust_the_scan(self, host):
        cursor = self._cursor(host)
        host.log_flood(65 << 20, last_line=self.OK)
        cursor.new_lines()
        assert cursor.exhausted is True and cursor.new_lines() == []

    def test_an_exhausted_log_is_unconfirmed_never_success_and_the_restart_is_taken(self, host, monkeypatch):
        monkeypatch.setattr(host.helper, "_LOG_SCAN_MAX", 3 << 20)
        host.write_config(_config())
        host.arm()
        host.socket_mode = "silent"
        host.reload_mode = "silent"
        host.restart_mode = "same_pid"
        real_kill = host._kill

        def flood_then_complete(pid, sig):
            real_kill(pid, sig)
            host.log_flood(4 << 20, last_line=self.OK)  # the completion line is past the scan budget

        monkeypatch.setattr(os, "kill", flood_then_complete)
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] is False and host.state()["restored_at"] is None and len(host.restarts()) == 1

    def test_a_log_deleted_during_the_wait_reads_as_unreadable(self, host):
        cursor = self._cursor(host)
        host.log.unlink()
        assert cursor.new_lines() is None

    def test_a_log_replaced_by_a_new_file_without_the_line_is_unconfirmed(self, host):
        cursor = self._cursor(host)
        host.log_rotate(rename=True, then="nothing of interest\n")
        assert self.OK not in (cursor.new_lines() or [])

    def test_an_unreadable_log_before_the_signal_means_no_cursor_and_the_socket_decides(self, host):
        host.write_config(_config())
        host.arm()
        host.log.unlink()
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] and host.state()["evidence"] == "config-get"


class TestABuild15RecordIsVerifiedLikeAnyOther:
    """v5.68.0-beta.31 (Q168, INV-011): every host record is verified by the one contract, whatever build armed it."""

    def _as_armed_by_build_15(self, host, **arm):
        host.write_config(
            {
                "Dhcp4": {
                    **_config()["Dhcp4"],
                    "loggers": [{**_config()["Dhcp4"]["loggers"][0], "output-options": [{"output": str(host.log)}]}],
                }
            }
        )
        host.arm(**arm)
        state = host.state()
        state.pop("log_path", None)
        for key in ("attempts", "needs_hand", "evidence", "verified_by_build"):
            state.pop(key, None)
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state))
        return state

    def test_with_a_socket_it_is_verified_by_the_daemons_answer_and_the_log_path_is_recorded(self, host):
        before = self._as_armed_by_build_15(host)
        host.reload_mode = "applied_hidden"
        reply = host.tick("--now")
        assert reply["ok"] and host.state()["evidence"] == "config-get"
        after = host.state()
        assert after["log_path"] == str(host.log) and after["verified_by_build"] == host.helper.HELPER_BUILD
        assert (after["until"], after["restore"], after["armed_at"]) == (
            before["until"],
            before["restore"],
            before["armed_at"],
        )

    def test_with_only_a_log_it_is_verified_by_the_completion_line(self, host):
        self._as_armed_by_build_15(host)
        host.socket_mode = "absent"
        assert host.tick("--now")["ok"] and host.state()["evidence"] == "log"

    def test_with_neither_there_is_no_evidence_and_the_record_is_otherwise_untouched(self, host):
        before = self._as_armed_by_build_15(host)
        host.socket_mode = "absent"
        host.log.unlink()
        for n in range(3):
            out = host.tick("--now")
            assert out["ok"] is False and "no way to see whether Kea re-read its file" in out["failed"][0]["error"]
            assert host.state()["attempts"] == n + 1
        after = host.state()
        assert (after["until"], after["restore"], after["armed_at"]) == (
            before["until"],
            before["restore"],
            before["armed_at"],
        )
        assert after["restored_at"] is None and host.signals == []

    def test_a_weaker_rule_is_never_presented_as_verification(self, host):
        self._as_armed_by_build_15(host)
        host.socket_mode = "silent"
        host.reload_mode = "silent"
        host.restart_mode = "same_pid"
        assert host.tick("--now")["ok"] is False and host.state()["restored_at"] is None, (
            "an active unit is not a restore, whatever build armed it"
        )


class TestADaemonThatAnsweredOnceIsJudgedByItsAnswer:
    """The release audit's two P1s (Q168 fixup): the socket is the arbiter for the WHOLE verification. A daemon that answered once - with the investigation level still running - and then
    went silent is never rescued by a completion line in the log (another instance wrote it) or by a fresh process (a unit whose `-c` is not this file)."""

    def _disarm(self, host):
        return host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})

    def _armed_at_debug(self, host):
        host.write_config(_config())
        host.arm()

    def test_f1_a_restarted_daemon_that_answered_at_debug_and_then_went_silent_is_not_a_restore(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"  # the reload is not taken: the one restart decides
        host.restart_mode = "fresh_but_old"  # a new pid that still runs the old config
        host.socket_mode = {
            "before": "silent",
            "after": ["at-debug", "silent"],
        }  # after the restart: one answer at DEBUG 55 with the marker, then silence
        reply = self._disarm(host)
        assert reply["ok"] is False and host.state()["restored_at"] is None, reply
        assert len(host.restarts()) == 1

    def test_f1_the_same_restart_with_the_socket_silent_from_the_start_is_process_evidence(self, host):
        self._armed_at_debug(host)
        host.reload_mode = "silent"
        host.socket_mode = "silent"
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "restart" and host.state()["evidence"] == "process"

    def test_f2_a_completion_line_after_a_socket_that_answered_at_debug_is_not_evidence(self, host):
        """Poll 1 the daemon answers DEBUG/55 + marker; poll 2 its socket times out while the completion line lands (written by another instance of Kea)."""
        self._armed_at_debug(host)
        host.reload_mode = "started_not_applied"
        host.restart_mode = "same_pid"
        host.socket_mode = ["at-debug", "at-debug", "silent"]  # the pre-check, poll 1, then silence
        host.log_on_ask = (
            3,
            [
                "2026-10-10 12:00:00.095 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS dynamic server reconfiguration succeeded with file: x"
            ],
        )  # lands as poll 2 is asked
        reply = self._disarm(host)
        assert reply["ok"] is False and host.state()["restored_at"] is None, reply
        assert len(host.restarts()) == 1, "the log line was not taken for the answer: the one restart was spent"

    def test_f2_the_same_with_no_socket_at_all_is_log_evidence(self, host):
        self._armed_at_debug(host)
        host.socket_mode = "absent"
        reply = self._disarm(host)
        assert reply["ok"] and reply["how"] == "reload" and host.state()["evidence"] == "log" and host.restarts() == []


class TestTheMatcherAcceptsTheOperatorsOwnDebug:
    """F3: the restore object may itself be DEBUG/55 (the operator's own level when logging was turned on); after the restore the FILE says so and the daemon shows the same."""

    def test_a_file_that_is_itself_debug_55_without_a_marker_matches_a_daemon_showing_exactly_that(self, helper):
        file_entry = {"name": "kea-dhcp4", "severity": "DEBUG", "debuglevel": 55}
        seen = {"present": True, "severity": "DEBUG", "debuglevel": 55, "marker": None}
        assert helper._daemon_matches(seen, file_entry) is True

    def test_the_same_daemon_with_the_marker_still_carried_is_not_a_match(self, helper):
        file_entry = {"name": "kea-dhcp4", "severity": "DEBUG", "debuglevel": 55}
        seen = {"present": True, "severity": "DEBUG", "debuglevel": 55, "marker": {"until": "x"}}
        assert helper._daemon_matches(seen, file_entry) is False

    def test_a_file_without_a_level_does_not_match_a_daemon_at_the_investigation_level(self, helper):
        seen = {"present": True, "severity": "DEBUG", "debuglevel": 55, "marker": None}
        assert helper._daemon_matches(seen, {"name": "kea-dhcp4"}) is False

    def test_an_end_to_end_restore_to_the_operators_own_debug_55_is_recorded_by_the_daemons_answer(self, host):
        host.write_config(_config())
        own = {"severity": "DEBUG", "debuglevel": 55}
        host.arm(5, restore=own)
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] and host.state()["how"] == "reload" and host.state()["evidence"] == "config-get", reply
        assert host.restarts() == [], "no restart was spent on a restore that was already right"


class TestTheRestartBudgetIsSpentOnDiskFirst:
    """F4 and F5: the one restart is recorded BEFORE it is issued, and an extension of the session does not forget it."""

    def test_f4_the_state_on_disk_already_says_restarts_1_when_the_restart_itself_blows_up(self, host, monkeypatch):
        host.write_config(_config())
        host.arm()
        host.reload_mode = "silent"
        host.socket_mode = "silent"
        real = host._run_bin

        def dies_on_restart(name, args, **kw):
            if name == "systemctl" and args[:1] == ["restart"]:
                raise KeyboardInterrupt("the helper was killed between the restart and the end of the restore")
            return real(name, args, **kw)

        monkeypatch.setattr(host.helper, "_run_bin", dies_on_restart)
        with pytest.raises(KeyboardInterrupt):
            host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert host.state()["restarts"] == 1, "the budget was spent on disk before systemctl was asked"

    def test_f4_the_next_tick_does_not_restart_kea_again(self, host, monkeypatch):
        host.write_config(_config())
        host.arm()
        state = host.state()
        state["restarts"] = 1
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state), encoding="utf-8")
        host.reload_mode = "silent"
        host.socket_mode = "silent"
        host.now = NOW + timedelta(minutes=6)
        out = host.tick()
        assert out["ok"] is False and host.restarts() == []

    def test_f5_an_extension_keeps_the_spent_restart_the_failures_and_the_hand_flag(self, host):
        host.write_config(_config())
        host.arm(5)
        state = host.state()
        state.update(restarts=1, attempts=4, needs_hand=True, last_error="nothing shows it", verified_by_build=17)
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state), encoding="utf-8")
        reply = host.arm(15)
        assert reply["ok"] and reply.get("extended_from"), reply
        after = host.state()
        assert (after["restarts"], after["attempts"], after["needs_hand"], after["last_error"]) == (
            1,
            4,
            True,
            "nothing shows it",
        )
        assert after["extended_from"] == state["until"] and after["verified_by_build"] == 17


class TestEveryWaitIsBoundedByTheClock:
    """F6: the waits are measured in time, not in sleeps - a socket that accepts and never answers costs two socket waits a poll, and the verification still ends on its deadline."""

    def test_await_reload_ends_within_the_hup_wait_plus_two_socket_waits_against_a_hanging_socket(self, host):
        host.write_config(_config())
        host.socket_mode = "hang"
        before = host.clock
        verdict = host.helper._await_reload(
            ("unix", "x"), None, host.helper._logger_entry(_config(at_debug=False, marker=False))
        )
        assert verdict == ("none", None, None)
        assert host.clock - before <= host.helper._HUP_WAIT_S + 2 * host.helper._SOCKET_WAIT_S + 0.5

    def test_await_restart_ends_within_the_restart_wait_plus_two_socket_waits_against_a_hanging_socket(self, host):
        host.write_config(_config())
        host.socket_mode = "hang"
        host.main_pid = 9001  # a new, active process
        before = host.clock
        verdict = host.helper._await_restart(
            UNIT, 4242, ("unix", "x"), None, host.helper._logger_entry(_config(at_debug=False, marker=False))
        )
        assert verdict == ("ok", "process", None), (
            "a daemon that NEVER answered is judged by the process: a new active pid, settled"
        )
        assert host.clock - before <= host.helper._RESTART_WAIT_S + 2 * host.helper._SOCKET_WAIT_S + 0.5

    def test_the_socket_wait_is_two_seconds(self, helper):
        assert helper._SOCKET_WAIT_S == 2.0


class TestATamperedCounterIsBadState:
    """F8: a counter the arm never writes as anything but an integer is not a state this helper wrote - never a traceback."""

    @pytest.mark.parametrize("bad", ["x", None, True, 1.5, [1]])
    def test_all_four_ops_say_bad_state(self, host, bad):
        host.write_config(_config())
        host.arm()
        state = host.state()
        state["restarts"] = bad
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state), encoding="utf-8")
        payload = {"service": SERVICE, "path": str(host.conf)}
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["ok"] is False and status["error"] == "bad-state"
        disarm = host.op("investigation-disarm", payload)
        assert disarm["ok"] is False and disarm["error"] == "bad-state"
        arm = host.arm()
        assert arm["ok"] is False and arm["error"] == "armed" and arm["existing"]["unreadable"] is True
        tick = host.tick("--now")
        assert tick["ok"] is False and tick["failed"] and "not usable" in tick["failed"][0]["error"]


class TestTheStoredLogPathFallsBackToTheFilesOwnOutput:
    """F10: a stored `log_path` that no longer reads must not cost the log evidence the file's own logger can give."""

    def test_a_stored_path_that_is_gone_and_a_file_logger_that_exists_is_log_evidence(self, host, monkeypatch):
        cfg = _config()
        cfg["Dhcp4"]["loggers"][0]["output-options"] = [{"output": str(host.log)}]
        host.write_config(cfg)
        host.arm(log_path=str(host.log))
        state = host.state()
        state["log_path"] = str(host.tmp_path / "gone.log")
        (host.state_dir / "investigation-dhcp4.json").write_text(json.dumps(state), encoding="utf-8")
        host.socket_mode = "absent"
        reply = host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert reply["ok"] and reply["how"] == "reload" and host.state()["evidence"] == "log", reply


class TestEveryVerifiedRestoreNamesTheBuildThatVerifiedIt:
    """F7: `verified_by_build` is written with the one `restored_at`, whatever armed the record."""

    def test_a_record_that_already_had_a_log_path_still_gets_it(self, host):
        host.write_config(_config())
        host.arm()
        assert "verified_by_build" not in host.state() or host.state()["verified_by_build"] is None
        host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        assert host.state()["verified_by_build"] == host.helper.HELPER_BUILD


class TestALineIsNeverCutAcrossReads:
    """F11: an id split across two 1 MiB reads is found (and counted once)."""

    def test_the_completion_id_split_across_the_read_boundary_is_found_once(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_LOG_READ_MAX", 64)
        log = tmp_path / "k.log"
        log.write_text("start\n", encoding="utf-8")
        cursor = helper._LogCursor(str(log))
        line = "2026-10-10 12:00:00.095 INFO  [kea-dhcp4.dhcp4/1] DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS dynamic server reconfiguration succeeded\n"
        with open(log, "a", encoding="utf-8") as f:
            f.write("x" * 40 + "\n" + line)
        lines = cursor.new_lines()
        found = [ln for ln in lines if "DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS" in ln]
        assert len(found) == 1 and found[0].endswith("succeeded"), lines

    def test_a_partial_line_is_kept_until_it_is_finished(self, helper, tmp_path):
        log = tmp_path / "k.log"
        log.write_text("", encoding="utf-8")
        cursor = helper._LogCursor(str(log))
        with open(log, "a", encoding="utf-8") as f:
            f.write("DHCP4_DYNAMIC_RECON")
        assert cursor.new_lines() == []
        with open(log, "a", encoding="utf-8") as f:
            f.write("FIGURATION_SUCCESS ok\n")
        assert cursor.new_lines() == ["DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS ok"]

    def test_the_unfinished_tail_of_a_rotated_file_is_flushed_through_the_same_splitter(self, helper, tmp_path):
        log = tmp_path / "k.log"
        log.write_text("", encoding="utf-8")
        cursor = helper._LogCursor(str(log))
        with open(log, "a", encoding="utf-8") as f:
            f.write("whole line\ntail without newline")
        assert cursor.new_lines() == ["whole line"]
        os.replace(log, str(log) + ".1")
        log.write_text("fresh\n", encoding="utf-8")
        assert cursor.new_lines() == ["tail without newline", "fresh"]


class TestTwoRestoresAtOnce:
    def test_a_restore_that_finds_the_session_already_restored_under_the_lock_does_nothing(self, host):
        host.write_config(_config())
        host.arm()
        stale = host.state()  # what a caller loaded BEFORE it took the lock
        assert host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})["restored"] is True
        signals, restarts = len(host.signals), len(host.restarts())
        ok, how, detail = host.helper._restore_state("dhcp4", stale)
        assert (ok, how, detail) == (True, "reload", "already restored")
        assert len(host.signals) == signals and len(host.restarts()) == restarts, (
            "no second signal, and the one restart is not spent"
        )

    def test_a_state_file_that_became_unreadable_underneath_is_not_overwritten_by_the_restore(self, host):
        host.write_config(_config())
        host.arm()
        stale = host.state()
        (host.state_dir / "investigation-dhcp4.json").write_text("{ garbage")
        ok, how, detail = host.helper._restore_state("dhcp4", stale)
        assert ok is False and "changed underneath" in detail
        assert (host.state_dir / "investigation-dhcp4.json").read_text() == "{ garbage"


class TestTheControlSocketIsFoundInTheConfig:
    def _c(self, helper, sockets=None, singular=None):
        section = {}
        if sockets is not None:
            section["control-sockets"] = sockets
        if singular is not None:
            section["control-socket"] = singular
        return helper._control_socket({"Dhcp4": section})

    def test_a_unix_socket_is_preferred(self, helper):
        got = self._c(
            helper,
            [
                {
                    "socket-type": "http",
                    "socket-address": "127.0.0.1",
                    "socket-port": 8000,
                    "authentication": {"type": "basic", "clients": [{"user": "u", "password": "p"}]},
                },
                {"socket-type": "unix", "socket-name": "/run/kea/k4.sock"},
            ],
        )
        assert got == ("unix", "/run/kea/k4.sock")

    def test_a_plain_local_http_socket_with_inline_credentials(self, helper):
        entry = {
            "socket-type": "http",
            "socket-address": "0.0.0.0",
            "socket-port": 8004,
            "authentication": {"type": "basic", "clients": [{"user": "jen", "password": "pw"}]},
        }
        assert self._c(helper, [entry]) == ("http", ("127.0.0.1", 8004, "jen", "pw"))

    def test_a_plain_local_http_socket_with_credential_files_under_directory(self, helper, tmp_path):
        (tmp_path / "u").write_text("jen\n")
        (tmp_path / "p").write_text("secret\n")
        entry = {
            "socket-type": "http",
            "socket-address": "::",
            "socket-port": 8005,
            "authentication": {
                "type": "basic",
                "directory": str(tmp_path),
                "clients": [{"user-file": "u", "password-file": "p"}],
            },
        }
        assert self._c(helper, [entry]) == ("http", ("::1", 8005, "jen", "secret"))

    def test_the_directory_defaults_to_etc_kea(self, helper, monkeypatch):
        opened = []

        def fake_open(path, *a, **k):
            opened.append(path)
            raise OSError("no")

        entry = {
            "socket-type": "http",
            "socket-address": "127.0.0.1",
            "socket-port": 8004,
            "authentication": {"type": "basic", "clients": [{"user-file": "u", "password-file": "p"}]},
        }
        with monkeypatch.context() as m:
            m.setattr("builtins.open", fake_open)
            assert self._c(helper, [entry]) is None
        assert os.path.join("/etc/kea", "u") in opened

    def test_a_remote_address_is_no_socket_evidence(self, helper):
        entry = {
            "socket-type": "http",
            "socket-address": "10.1.2.3",
            "socket-port": 8004,
            "authentication": {"type": "basic", "clients": [{"user": "a", "password": "b"}]},
        }
        assert self._c(helper, [entry]) is None

    def test_https_is_no_socket_evidence(self, helper):
        entry = {
            "socket-type": "http",
            "socket-address": "127.0.0.1",
            "socket-port": 8004,
            "trust-anchor": "/etc/kea/ca.pem",
            "cert-file": "/c",
            "key-file": "/k",
            "authentication": {"type": "basic", "clients": [{"user": "a", "password": "b"}]},
        }
        assert self._c(helper, [entry]) is None

    def test_http_without_basic_auth_is_no_socket_evidence(self, helper):
        assert self._c(helper, [{"socket-type": "http", "socket-address": "127.0.0.1", "socket-port": 8004}]) is None

    def test_the_singular_pre_2_7_2_map_is_a_one_entry_list(self, helper):
        assert self._c(helper, singular={"socket-type": "unix", "socket-name": "/run/kea/old.sock"}) == (
            "unix",
            "/run/kea/old.sock",
        )

    def test_neither_is_none(self, helper):
        assert (
            self._c(helper) is None
            and helper._control_socket(None) is None
            and helper._control_socket({"Dhcp4": {"control-sockets": "x"}}) is None
        )
        assert self._c(helper, [{"socket-type": "unix", "socket-name": "relative.sock"}]) is None


class TestAskingTheDaemon:
    """`_ask_daemon` against real sockets: a reply the daemon keeps the connection open after, one it closes after, a list (the Control Agent's wrapping), garbage, nothing listening."""

    REPLY = {"result": 0, "arguments": {"Dhcp4": {"loggers": []}}}

    def _serve_http(self, reply_bytes, close_after=True, expect_auth=None):
        import threading

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        seen = {}

        def run():
            conn, _ = server.accept()
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += conn.recv(4096)
                head, _, rest = data.partition(b"\r\n\r\n")
                length = int(
                    [h.split(b":")[1] for h in head.split(b"\r\n") if h.lower().startswith(b"content-length")][0]
                )
                while len(rest) < length:
                    rest += conn.recv(4096)
                seen["head"], seen["body"] = head.decode(), rest
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + reply_bytes)
                if not close_after:
                    time.sleep(1.5)  # a daemon that keeps the connection open

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return server, seen, thread

    def test_http_with_basic_auth_a_reply_that_closes(self, helper):
        server, seen, thread = self._serve_http(json.dumps([self.REPLY]).encode())
        reply = helper._ask_daemon(("http", ("127.0.0.1", server.getsockname()[1], "jen", "pw")), "config-get")
        thread.join(3)
        server.close()
        assert reply == self.REPLY and json.loads(seen["body"]) == {"command": "config-get"}
        assert "Authorization: Basic " + base64.b64encode(b"jen:pw").decode() in seen["head"]

    def test_http_a_reply_the_daemon_keeps_the_connection_open_after(self, helper):
        server, _seen, thread = self._serve_http(json.dumps(self.REPLY).encode(), close_after=False)
        started = time.monotonic()
        reply = helper._ask_daemon(("http", ("127.0.0.1", server.getsockname()[1], "jen", "pw")), "config-get")
        assert reply == self.REPLY and time.monotonic() - started < 1.4, (
            "returned as soon as the reply parsed, not when the connection closed"
        )
        thread.join(3)
        server.close()

    def test_garbage_is_none(self, helper):
        server, _seen, thread = self._serve_http(b"<html>not json</html>")
        assert helper._ask_daemon(("http", ("127.0.0.1", server.getsockname()[1], "jen", "pw")), "config-get") is None
        thread.join(3)
        server.close()

    def test_nothing_listening_is_none(self, helper):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        assert helper._ask_daemon(("http", ("127.0.0.1", port, "a", "b")), "config-get") is None

    @pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no unix sockets here")
    def test_a_unix_socket_a_plain_json_reply_and_a_list_reply(self, helper, tmp_path):
        import threading

        for payload in (self.REPLY, [self.REPLY]):
            path = str(tmp_path / f"k{type(payload).__name__}.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            server.listen(1)

            def run(server=server, payload=payload):
                conn, _ = server.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(json.dumps(payload).encode())
                    time.sleep(0.5)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            assert helper._ask_daemon(("unix", path), "config-get") == self.REPLY
            thread.join(3)
            server.close()
        assert helper._ask_daemon(("unix", str(tmp_path / "nothing.sock")), "config-get") is None


class TestWhatTheDaemonMustShowToMatchTheFile:
    """`_daemon_matches`: the running logger against the logger of the FILE the helper wrote."""

    def _seen(self, severity="INFO", level=None, marker=None, present=True):
        return {"present": present, "severity": severity, "debuglevel": level, "marker": marker}

    @pytest.mark.parametrize(
        "seen,file_entry,expected",
        [
            (
                {"present": True, "severity": "WARN", "debuglevel": 0, "marker": None},
                {"severity": "WARN", "debuglevel": 0},
                True,
            ),
            (
                {"present": True, "severity": "warn", "debuglevel": 0, "marker": None},
                {"severity": "WARN", "debuglevel": 0},
                True,
            ),
            (
                {"present": True, "severity": "DEBUG", "debuglevel": 55, "marker": None},
                {"severity": "WARN", "debuglevel": 0},
                False,
            ),
            (
                {"present": True, "severity": "WARN", "debuglevel": 0, "marker": {"until": "x"}},
                {"severity": "WARN", "debuglevel": 0},
                False,
            ),
            (
                {"present": True, "severity": "INFO", "debuglevel": 0, "marker": None},
                {"severity": "WARN", "debuglevel": 0},
                False,
            ),
            ({"present": True, "severity": "INFO", "debuglevel": 0, "marker": None}, {"output-options": []}, True),
            ({"present": True, "severity": "DEBUG", "debuglevel": 55, "marker": None}, {"output-options": []}, False),
            ({"present": False, "severity": None, "debuglevel": None, "marker": None}, None, True),
            ({"present": True, "severity": "INFO", "debuglevel": 0, "marker": None}, None, False),
            ({"present": False, "severity": None, "debuglevel": None, "marker": None}, {"severity": "INFO"}, False),
            (None, {"severity": "INFO"}, False),
        ],
    )
    def test_the_table(self, helper, seen, file_entry, expected):
        assert helper._daemon_matches(seen, file_entry) is expected


class TestAnUnresolvedHostRecordIsNeverOverwritten:
    """v5.68.0-beta.30 (Q167, INV-008): `investigation-arm` used to replace the previous state 'restored or not'. The record on the host is authoritative."""

    def _record(self, host):
        return json.loads((host.state_dir / "investigation-dhcp4.json").read_text(encoding="utf-8"))

    def test_the_same_session_again_is_idempotent_and_writes_nothing(self, host):
        host.arm(5, jen={"server_id": 1, "name": "kea-a"})
        before = self._record(host)
        reply = host.arm(5, jen={"server_id": 1, "name": "kea-a"})
        assert reply["ok"] and reply.get("idempotent") is True
        assert self._record(host) == before

    def test_two_jens_with_the_same_session_do_not_change_whose_record_it_is(self, host):
        host.arm(5, jen={"server_id": 1, "name": "kea-a"})
        reply = host.arm(5, jen={"server_id": 9, "name": "second-jen"})
        assert reply["ok"] and reply.get("idempotent") is True
        assert self._record(host)["jen"] == {"server_id": 1, "name": "kea-a"}

    def test_the_same_restore_with_a_later_deadline_is_an_extension(self, host):
        host.arm(5)
        reply = host.arm(15)
        assert reply["ok"] and reply["extended_from"]
        state = self._record(host)
        assert (
            datetime.fromisoformat(state["until"]) == NOW + timedelta(minutes=15)
            and state["extended_from"] == reply["extended_from"]
        )

    def test_an_earlier_deadline_is_not_an_extension(self, host):
        host.arm(15)
        reply = host.arm(5)  # a Jen restored from an older backup
        assert reply["ok"] is False and reply["error"] == "armed" and reply["existing"]["restore"] == RESTORE
        assert datetime.fromisoformat(self._record(host)["until"]) == NOW + timedelta(minutes=15)

    def test_a_different_restore_object_is_refused_with_the_record(self, host):
        host.arm(5, restore=RESTORE)
        reply = host.arm(5, restore={"created": True})
        assert reply["ok"] is False and reply["error"] == "armed" and reply["existing"]["restore"] == RESTORE
        assert self._record(host)["restore"] == RESTORE, "the original level is still the one the host holds"

    def test_a_different_config_path_is_refused(self, host):
        host.arm(5)
        other = host.conf_dir / "other.conf"
        reply = host.arm(5, path=str(other))
        assert reply["ok"] is False and reply["error"] == "armed"

    def test_a_record_waiting_for_a_person_is_still_unresolved(self, host):
        host.write_config(_config())
        host.arm(-1)
        host.kea_test = (False, {"ok": False, "error": "testerror", "detail": "bad"})
        for _ in range(10):
            host.tick()
        assert self._record(host)["needs_hand"] is True
        assert host.arm(30, restore={"created": True})["error"] == "armed"

    def test_once_it_is_restored_the_next_arm_is_a_new_session(self, host):
        host.write_config(_config())
        host.arm(5)
        host.op("investigation-disarm", {"service": SERVICE, "path": str(host.conf)})
        reply = host.arm(5, restore={"created": True})
        assert reply["ok"] and not reply.get("idempotent")
        assert self._record(host)["restore"] == {"created": True} and self._record(host)["restored_at"] is None

    def test_a_state_file_that_cannot_be_read_blocks_an_arm_until_a_person_looks(self, host):
        host.arm(5)
        (host.state_dir / "investigation-dhcp4.json").write_text("not json")
        reply = host.arm(5)
        assert (
            reply["ok"] is False
            and reply["error"] == "armed"
            and reply["existing"]["unreadable"] is True
            and "cannot be trusted" in reply["detail"]
        )

    def test_the_arms_write_is_guarded_by_the_existing_state_check(self):
        source = _SCRIPT.read_text(encoding="utf-8")
        a = source.index("def op_investigation_arm(")
        body = source[a : source.index("def op_investigation_disarm(")]
        assert body.index('_read_state("dhcp4")') < body.index('_save_state("dhcp4", state)')


class TestTheTimersOwnLiveness:
    def test_an_armed_state_with_a_stopped_timer_says_so(self, host):
        host.arm()
        host.timer = "inactive"
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["armed"] is True and status["timer_active"] is False and status["timer_enabled"] is False
        assert status["last_error"] == "Restoration timer is not active"

    def test_a_running_timer_is_reported_active_and_enabled(self, host):
        host.arm()
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["timer_active"] is True and status["timer_enabled"] is True and status["last_error"] is None

    def test_nothing_armed_means_the_timer_is_not_asked_about(self, host):
        status = host.op("investigation-status", {"service": SERVICE})
        assert status["armed"] is False and not [c for c in host.calls if c[1][:1] == ["is-active"]]

    def test_the_timer_op_re_asserts_it(self, host):
        host.arm()
        before = len([c for c in host.calls if c[1][:1] == ["enable"]])
        reply = host.op("investigation-timer", {"action": "ensure"})
        assert reply["ok"] is True and reply["timer"] == "systemd"
        assert len([c for c in host.calls if c[1][:1] == ["enable"]]) == before + 1

    def test_the_timer_op_reports_a_host_that_cannot(self, host):
        host.timer = "no-systemctl"
        reply = host.op("investigation-timer", {"action": "ensure"})
        assert reply["ok"] is False and reply["timer"] == "none" and reply["detail"]

    def test_the_timer_op_takes_one_action_only(self, host):
        assert host.op("investigation-timer", {"action": "disable"})["error"] == "not-allowed"
        assert host.op("investigation-timer", {})["error"] == "not-allowed"
