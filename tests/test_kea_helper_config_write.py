"""
tests/test_kea_helper_config_write.py
─────────────────────────────────────
Q212 (BB4) - helper build 19: who may write the daemon's own file. `config-write-check` (facts), `allow-config-write` (the grant) and `deny-config-write` (its inverse), the backup that is
never group-writable, and the timer tick that keeps verifying after a restore. Tmp-dir tests, no SSH, no real Kea; the chown of a non-root test run is stubbed the way tests/test_kea_helper.py
stubs it. Skipped on Windows (no `fchmod`, no group bits).
"""

import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
from importlib.machinery import SourceFileLoader

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes and descriptors")

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"


@pytest.fixture(scope="module")
def helper():
    loader = SourceFileLoader("jen_kea_helper_cw", str(_SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _a_state_directory_of_its_own(monkeypatch, tmp_path_factory, helper):
    monkeypatch.setattr(helper, "_STATE_DIR", str(tmp_path_factory.mktemp("jen-kea-helper-state")))


@pytest.fixture
def chown_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)), raising=False)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: None, raising=False)
    return calls


def _run(helper, op, payload):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = helper.main(
        argv=["jen-kea-helper", op], stdin=io.StringIO(json.dumps(payload)), stdout=stdout, stderr=stderr
    )
    out = json.loads(stdout.getvalue().strip())
    out.pop("helper_version", None)
    out.pop("helper_build", None)
    return code, out


@pytest.fixture
def conf(tmp_path, helper, monkeypatch):
    monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
    path = tmp_path / "kea-dhcp4.conf"
    path.write_text('{"Dhcp4": {"valid-lifetime": 3600}}')
    path.chmod(0o640)
    return path


def _account(monkeypatch, helper, *, uid=None, gid=None, extra=()):
    me = os.getuid()
    acct = {
        "name": "_kea",
        "uid": me + 7 if uid is None else uid,
        "gid": os.getgid() + 7 if gid is None else gid,
        "extra_groups": list(extra),
    }
    monkeypatch.setattr(helper, "_unit_account", lambda service: acct)
    return acct


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestTheOpsExistAtBuild19:
    def test_the_build_and_the_ops(self, helper):
        assert helper.HELPER_BUILD == 21
        for op in ("config-write-check", "allow-config-write", "deny-config-write"):
            assert op in helper._OPS


class TestConfigWriteCheck:
    def test_facts_only_and_nothing_is_changed(self, helper, conf, monkeypatch):
        acct = _account(monkeypatch, helper)
        before = (os.stat(conf).st_mode, os.stat(conf).st_mtime_ns)
        _code, out = _run(helper, "config-write-check", {"service": "dhcp4", "path": str(conf)})
        assert out["ok"] and out["mode"] == "0640" and out["owner_uid"] == os.getuid()
        assert out["account"]["uid"] == acct["uid"] and out["daemon_is_root"] is False
        assert out["may_write"] is False  # neither the owner nor in the file's group, no group-write bit
        assert out["includes"] == []
        assert (os.stat(conf).st_mode, os.stat(conf).st_mtime_ns) == before

    def test_an_account_in_the_files_group_with_the_bit_may_write(self, helper, conf, monkeypatch):
        _account(monkeypatch, helper, gid=os.stat(conf).st_gid)
        conf.chmod(0o660)
        _code, out = _run(helper, "config-write-check", {"service": "dhcp4", "path": str(conf)})
        assert out["may_write"] is True and out["mode"] == "0660"

    def test_a_root_daemon_writes_anyway(self, helper, conf, monkeypatch):
        monkeypatch.setattr(helper, "_unit_account", lambda service: None)
        _code, out = _run(helper, "config-write-check", {"service": "dhcp4", "path": str(conf)})
        assert out["may_write"] is True and out["daemon_is_root"] is True and out["account"] is None

    def test_an_include_directive_is_named(self, helper, conf, monkeypatch):
        _account(monkeypatch, helper)
        conf.write_text('{ <?include "/etc/kea/extra.json"?> "Dhcp4": {} }')
        _code, out = _run(helper, "config-write-check", {"service": "dhcp4", "path": str(conf)})
        assert out["includes"] == ["/etc/kea/extra.json"]

    def test_a_unit_whose_account_is_unknown_is_refused_never_guessed(self, helper, conf, monkeypatch):
        monkeypatch.setattr(helper, "_unit_account", lambda service: {"refused": "its unit runs as User=nobody-such"})
        _code, out = _run(helper, "config-write-check", {"service": "dhcp4", "path": str(conf)})
        assert out["ok"] is False and out["error"] == "unit-account"


class TestTheWalls:
    @pytest.mark.parametrize("op", ["config-write-check", "allow-config-write", "deny-config-write"])
    def test_a_path_outside_the_config_directories_is_refused(self, helper, conf, monkeypatch, op):
        _account(monkeypatch, helper)
        _code, out = _run(helper, op, {"service": "dhcp4", "path": "/etc/passwd"})
        assert out == {"ok": False, "error": "not-allowed"}

    @pytest.mark.parametrize("op", ["config-write-check", "allow-config-write", "deny-config-write"])
    def test_a_trailing_newline_is_refused(self, helper, conf, monkeypatch, op):
        """Q217 AB14 - `$` matches before one trailing newline; the basename wall is a `fullmatch` (build 21)."""
        _account(monkeypatch, helper)
        _code, out = _run(helper, op, {"service": "dhcp4", "path": str(conf) + "\n"})
        assert out == {"ok": False, "error": "not-allowed"}

    @pytest.mark.parametrize("op", ["config-write-check", "allow-config-write", "deny-config-write"])
    def test_a_service_that_is_not_one_is_refused(self, helper, conf, monkeypatch, op):
        _account(monkeypatch, helper)
        _code, out = _run(helper, op, {"service": "sshd", "path": str(conf)})
        assert out == {"ok": False, "error": "not-allowed"}

    @pytest.mark.parametrize("op", ["config-write-check", "allow-config-write", "deny-config-write"])
    def test_a_symlink_is_never_followed(self, helper, tmp_path, conf, monkeypatch, op):
        _account(monkeypatch, helper)
        target = tmp_path / "elsewhere.txt"
        target.write_text("{}")
        target.chmod(0o600)
        link = tmp_path / "kea-dhcp6.conf"
        link.symlink_to(target)
        _code, out = _run(helper, op, {"service": "dhcp6", "path": str(link)})
        assert out["ok"] is False and out["error"] == "symlink"
        assert _mode(target) == 0o600  # the target of the link was not touched

    @pytest.mark.parametrize("op", ["allow-config-write", "deny-config-write"])
    def test_a_directory_at_the_path_is_not_a_config_file(self, helper, tmp_path, conf, monkeypatch, op):
        _account(monkeypatch, helper)
        (tmp_path / "kea-dhcp6.conf").mkdir()
        _code, out = _run(helper, op, {"service": "dhcp6", "path": str(tmp_path / "kea-dhcp6.conf")})
        assert out["ok"] is False

    def test_a_missing_file_is_missing(self, helper, tmp_path, conf, monkeypatch):
        _account(monkeypatch, helper)
        _code, out = _run(helper, "allow-config-write", {"service": "dhcp6", "path": str(tmp_path / "kea-dhcp6.conf")})
        assert out["ok"] is False and out["error"] == "missing"


class TestAllowAndDeny:
    def test_allow_is_the_daemons_group_and_0660_on_the_file_only(
        self, helper, tmp_path, conf, monkeypatch, chown_calls
    ):
        acct = _account(monkeypatch, helper)
        directory_before = (stat.S_IMODE(os.stat(tmp_path).st_mode), os.stat(tmp_path).st_gid)
        _code, out = _run(helper, "allow-config-write", {"service": "dhcp4", "path": str(conf)})
        assert out["ok"] and out["changed"] is True
        assert chown_calls == [(-1, acct["gid"])]  # the group only; the owner stays as it is
        assert _mode(conf) == 0o660 and not _mode(conf) & 0o007  # never an `o` bit
        assert (
            stat.S_IMODE(os.stat(tmp_path).st_mode),
            os.stat(tmp_path).st_gid,
        ) == directory_before  # the directory is never opened for change
        assert out["before"]["mode"] == "0640" and out["after"]["mode"] == "0660"

    def test_deny_is_0640_and_keeps_the_group(self, helper, conf, monkeypatch, chown_calls):
        _account(monkeypatch, helper)
        conf.chmod(0o660)
        _code, out = _run(helper, "deny-config-write", {"service": "dhcp4", "path": str(conf)})
        assert out["ok"] and _mode(conf) == 0o640
        assert chown_calls == []  # the group is kept, so the daemon can still read its file

    def test_a_root_daemon_needs_no_grant_and_nothing_is_changed(self, helper, conf, monkeypatch, chown_calls):
        monkeypatch.setattr(helper, "_unit_account", lambda service: None)
        _code, out = _run(helper, "allow-config-write", {"service": "dhcp4", "path": str(conf)})
        assert out["ok"] and out["changed"] is False and chown_calls == [] and _mode(conf) == 0o640

    def test_allow_then_apply_config_keeps_the_grant(self, helper, conf, monkeypatch, chown_calls):
        """The next file-path write (logging on/off, a socket setup, a restore) must not revoke the grant: a 0664 file would be tightened to 0640, a 0660 one keeps its bit."""
        _account(monkeypatch, helper)
        monkeypatch.setattr(helper, "_run_kea_test", lambda *a, **k: (True, {"ok": True}))
        _run(helper, "allow-config-write", {"service": "dhcp4", "path": str(conf)})
        assert _mode(conf) == 0o660
        _code, out = _run(
            helper, "apply-config", {"service": "dhcp4", "path": str(conf), "config": {"Dhcp4": {"valid-lifetime": 7}}}
        )
        assert out["ok"], out
        assert _mode(conf) == 0o660  # still group-writable

    def test_the_backup_of_a_group_writable_file_is_never_group_writable(self, helper, conf, monkeypatch, chown_calls):
        _account(monkeypatch, helper)
        monkeypatch.setattr(helper, "_run_kea_test", lambda *a, **k: (True, {"ok": True}))
        conf.chmod(0o660)
        _code, out = _run(
            helper, "apply-config", {"service": "dhcp4", "path": str(conf), "config": {"Dhcp4": {"valid-lifetime": 8}}}
        )
        assert out["ok"], out
        backup = pathlib.Path(str(conf) + ".jen_backup")
        assert backup.exists() and _mode(backup) == 0o640

    def test_the_lock_is_taken_for_the_grant(self, helper, conf, monkeypatch, chown_calls):
        _account(monkeypatch, helper)
        held = []
        real = helper._locked

        def spy(path, *a, **k):
            held.append(path)
            return real(path, *a, **k)

        monkeypatch.setattr(helper, "_locked", spy)
        _run(helper, "allow-config-write", {"service": "dhcp4", "path": str(conf)})
        assert held == [str(conf)]


class TestQ216TheOpsBindTheServiceToTheFilesOwnName:
    """Build 20 (Q216 AA24): `config-write-check dhcp6 /etc/kea/kea-dhcp4.conf` was answered with the dhcp6 unit's account for the dhcp4 file. Where the file names a service (Kea's own file names) the
    `service` must be that one; a custom file name names no service and is not refused."""

    @pytest.mark.parametrize("op", ["op_config_write_check", "op_allow_config_write", "op_deny_config_write"])
    def test_a_mismatch_is_not_allowed(self, helper, op):
        out, _path = getattr(helper, op)({"service": "dhcp6", "path": "/etc/kea/kea-dhcp4.conf"})
        assert out == {"ok": False, "error": "not-allowed"}

    def test_the_names_agree(self, helper):
        assert helper._conf_names_another_service("dhcp4", "/etc/kea/kea-dhcp4.conf") is False
        assert helper._conf_names_another_service("d2", "/etc/kea/kea-dhcp-ddns.conf") is False
        assert helper._conf_names_another_service("dhcp6", "/etc/kea/kea-dhcp4.conf") is True
        assert helper._conf_names_another_service("dhcp4", "/etc/kea/kea-dhcp-ddns.conf") is True

    def test_a_custom_file_name_names_no_service(self, helper):
        assert helper._conf_names_another_service("dhcp4", "/etc/kea/site.conf") is False


class TestTheTickKeepsVerifying:
    """`--self-restore` after a restore (build 19): until Jen forgets the session or its deadline + 15 minutes, every tick asks again whether the FILE or the RUNNING daemon carries the
    investigation marker, and puts the logger back again when it does - F6's close."""

    NOW = "2026-11-03T12:00:00+00:00"

    def _state(self, conf, until="2026-11-03T11:50:00+00:00"):
        return {
            "service": "dhcp4",
            "path": str(conf),
            "restore": {"severity": "INFO", "debuglevel": "absent"},
            "until": until,
            "restored_at": "2026-11-03T11:50:30+00:00",
            "how": "reload",
            "evidence": "config-get",
            "verified_by_build": 18,
            "restarts": 0,
            "attempts": 0,
        }

    def _marked_file(self, conf, until="2026-11-03T11:50:00+00:00"):
        conf.write_text(
            json.dumps(
                {
                    "Dhcp4": {
                        "loggers": [
                            {
                                "name": "kea-dhcp4",
                                "severity": "DEBUG",
                                "debuglevel": 55,
                                "user-context": {"jen-investigation": {"until": until}},
                            }
                        ]
                    }
                }
            )
        )

    def _wire(self, helper, monkeypatch, restore_result=(True, "reload", "")):
        from datetime import datetime

        monkeypatch.setattr(helper, "_now", lambda: datetime.fromisoformat(self.NOW))
        saved, restored = [], []
        monkeypatch.setattr(helper, "_save_state", lambda service, state: saved.append(dict(state)))
        monkeypatch.setattr(
            helper, "_restore_state", lambda service, state: restored.append(dict(state)) or restore_result
        )
        return saved, restored

    def test_a_marker_back_in_the_file_is_restored_again_and_noted(self, helper, conf, monkeypatch):
        self._marked_file(conf)
        saved, restored = self._wire(helper, monkeypatch)
        assert helper._reverify("dhcp4", self._state(conf)) == (True, "reload", "")
        assert saved[0]["restored_at"] is None and "how" not in saved[0] and "evidence" not in saved[0]
        assert (
            saved[0]["re_restores"] == 1 and restored
        )  # the record is reopened (and a usable one: `how`/`evidence` absent), then the restore runs

    def test_a_marker_in_the_running_daemon_alone_is_found_too(self, helper, conf, monkeypatch):
        conf.write_text(
            json.dumps({"Dhcp4": {"control-sockets": [{"socket-type": "unix", "socket-name": "/run/kea/s"}]}})
        )
        saved, _restored = self._wire(helper, monkeypatch)
        monkeypatch.setattr(helper, "_control_socket", lambda config: ("sock", ""))
        monkeypatch.setattr(
            helper,
            "_daemon_logger_now",
            lambda sock: {
                "present": True,
                "severity": "DEBUG",
                "debuglevel": 55,
                "marker": {"until": "2026-11-03T11:50:00+00:00"},
            },
        )
        assert helper._reverify("dhcp4", self._state(conf))[0] is True
        assert saved

    def test_a_new_sessions_marker_in_the_file_is_not_a_stray__found_by_system_test_19(self, helper, conf, monkeypatch):
        """Build 20. Build 19 re-restored on ANY marker. Jen writes a NEW session's marker before the arm replaces the finished session's record; a tick that landed in that window took the new
        marker out ("file restored, daemon other, armed") - the System boundaries run on v7.0.0-beta.1 failed test_19 on it. The new marker carries a new deadline: it is not this session's."""
        self._marked_file(conf, until="2026-11-03T12:04:00+00:00")  # the new session's deadline, not the state's 11:50
        saved, restored = self._wire(helper, monkeypatch)
        monkeypatch.setattr(helper, "_control_socket", lambda config: (None, "no socket"))
        assert helper._reverify("dhcp4", self._state(conf)) is None
        assert saved == [] and restored == []

    def test_a_new_sessions_marker_in_the_running_daemon_is_not_a_stray_either(self, helper, conf, monkeypatch):
        conf.write_text(
            json.dumps({"Dhcp4": {"control-sockets": [{"socket-type": "unix", "socket-name": "/run/kea/s"}]}})
        )
        saved, restored = self._wire(helper, monkeypatch)
        monkeypatch.setattr(helper, "_control_socket", lambda config: ("sock", ""))
        monkeypatch.setattr(
            helper,
            "_daemon_logger_now",
            lambda sock: {
                "present": True,
                "severity": "DEBUG",
                "debuglevel": 55,
                "marker": {"until": "2026-11-03T12:04:00+00:00"},
            },
        )
        assert helper._reverify("dhcp4", self._state(conf)) is None
        assert saved == [] and restored == []

    @pytest.mark.parametrize("marker", [True, "x", {}, {"until": "not a time"}, {"until": None}])
    def test_a_marker_without_a_readable_deadline_is_not_this_sessions(self, helper, marker):
        assert helper._marker_is_the_states(marker, {"until": "2026-11-03T11:50:00+00:00"}) is False

    def test_the_same_instant_in_another_spelling_is_this_sessions(self, helper):
        assert helper._marker_is_the_states({"until": "2026-11-03T11:50:00Z"}, {"until": "2026-11-03T11:50:00+00:00"})
        assert helper._marker_is_the_states(
            {"until": "2026-11-03T12:50:00+01:00"}, {"until": "2026-11-03T11:50:00+00:00"}
        )

    def test_nothing_carrying_the_marker_is_nothing_to_do(self, helper, conf, monkeypatch):
        saved, restored = self._wire(helper, monkeypatch)
        monkeypatch.setattr(helper, "_control_socket", lambda config: (None, "no socket"))
        assert helper._reverify("dhcp4", self._state(conf)) is None
        assert saved == [] and restored == []

    def test_the_window_closes_fifteen_minutes_after_the_deadline(self, helper, conf, monkeypatch):
        self._marked_file(conf)
        saved, restored = self._wire(helper, monkeypatch)
        # the deadline was 11:44: 16 minutes before NOW
        assert helper._reverify("dhcp4", self._state(conf, until="2026-11-03T11:44:00+00:00")) is None
        assert saved == [] and restored == []

    def test_a_failed_second_restore_leaves_the_record_unresolved(self, helper, conf, monkeypatch):
        self._marked_file(conf)
        _saved, _restored = self._wire(helper, monkeypatch, restore_result=(False, None, "the reload was not verified"))
        assert helper._reverify("dhcp4", self._state(conf)) == (False, None, "the reload was not verified")

    def test_the_tick_calls_it_for_a_done_record(self, helper, conf, monkeypatch):
        self._marked_file(conf)
        self._wire(helper, monkeypatch)
        state = self._state(conf)
        monkeypatch.setattr(helper, "_STATE_DIR", str(conf.parent / "state"))
        os.makedirs(helper._STATE_DIR)
        pathlib.Path(helper._state_path("dhcp4")).write_text(json.dumps(state))
        monkeypatch.setattr(helper, "_read_state", lambda service: ("ok", state))
        result = helper._self_restore()
        assert result["restored"] == [{"service": "dhcp4", "how": "reload", "again": True}]
