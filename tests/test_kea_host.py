"""
tests/test_kea_host.py
──────────────────────
v5.11.0 — jen/services/kea_host.py: the single Kea-host client. Helper
transport is exercised against tests._kea6_helpers.FakeSSHClient; the
legacy fallback against the same fake replying with the OLD tokens.
"""

import json
import pathlib

import pytest

from jen.services import kea_host
from tests._kea6_helpers import FakeSSHClient

_JEN = pathlib.Path(__file__).resolve().parent.parent / "jen"

SERVER = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "ssh_user": "kea", "kea_conf": "/etc/kea/kea-dhcp4.conf"}

# the real status functions, captured before any test monkeypatches them
_REAL_HELPER_STATUS = kea_host.helper_status
_REAL_RECORD = kea_host.record_helper_status


@pytest.fixture
def quiet_status(monkeypatch):
    """No settings-table writes for the transport tests."""
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", lambda: {})


def _connect_seq(monkeypatch, *queues):
    """Hand out a fresh FakeSSHClient per _connect_ssh call, each from
    the next reply queue (the last queue repeats for extra calls)."""
    made = []
    q = list(queues)

    def connect(_server):
        replies = q[len(made)] if len(made) < len(q) else q[-1]
        f = FakeSSHClient(list(replies))
        made.append(f)
        return f

    monkeypatch.setattr(kea_host.__kea6, "_connect_ssh", connect)
    return made


class TestHelperCall:
    def test_json_round_trip_and_command_shape(self, monkeypatch, quiet_status):
        made = _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}}), "")])
        out = kea_host.helper_call(SERVER, "read-config", {"service": "dhcp4", "path": "/etc/kea/kea-dhcp4.conf"})
        assert out == {"ok": True, "config": {"Dhcp4": {}}}
        assert made[0].calls == ["sudo -n /usr/local/sbin/jen-kea-helper read-config"]
        assert json.loads(made[0].stdin_writes[0]) == {"service": "dhcp4", "path": "/etc/kea/kea-dhcp4.conf"}

    def test_missing_on_password_prompt(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        with pytest.raises(kea_host.HelperMissing):
            kea_host.helper_call(SERVER, "version", {})

    def test_missing_on_command_not_found(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [("", "bash: jen-kea-helper: command not found")])
        with pytest.raises(kea_host.HelperMissing):
            kea_host.helper_call(SERVER, "version", {})

    def test_error_on_garbage(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [("not json", "kaboom")])
        with pytest.raises(kea_host.HelperError):
            kea_host.helper_call(SERVER, "version", {})


class TestHighLevelHelperPath:
    def test_read_config_ok(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {"subnet4": []}}}), "")])
        assert kea_host.read_config(SERVER, "dhcp4") == {"Dhcp4": {"subnet4": []}}

    def test_read_config_missing_returns_none(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "missing"}), "")])
        assert kea_host.read_config(SERVER, "dhcp4") is None

    def test_test_config_maps_testerror(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "testerror", "detail": "ERROR: x"}), "")])
        res = kea_host.test_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["ok"] is False and res["code"] == "testerror" and res["via"] == "helper"
        assert res["detail"] == "ERROR: x"

    def test_apply_config_ok_with_backup(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "backup": "/etc/kea/kea-dhcp4.conf.jen_backup"}), "")])
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["ok"] is True and res["code"] == "ok" and res["backup"].endswith(".jen_backup")

    def test_apply_config_maps_missingbinary(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "missingbinary", "binary": "kea-dhcp4"}), "")])
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["code"] == "missingbinary" and res["binary"] == "kea-dhcp4"

    def test_service_action_ok(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "unit": "kea-dhcp4-server", "state": "active"}), "")])
        res = kea_host.service_action(SERVER, "dhcp4", "restart")
        assert res == {"ok": True, "code": "ok", "unit": "kea-dhcp4-server", "state": "active", "via": "helper"}

    def test_service_action_no_unit(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "no-unit"}), "")])
        res = kea_host.service_action(SERVER, "dhcp6", "restart")
        assert res["ok"] is False and "no kea-dhcp6-server unit" in res["detail"]

    def test_tail_log_ok(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "lines": ["a", "b"]}), "")])
        res = kea_host.tail_log(SERVER, "/var/log/kea/kea-ddns.log", 2)
        assert res["ok"] is True and res["lines"] == ["a", "b"]


class TestLegacyFallback:
    """A HelperMissing on any high-level call runs the legacy command and
    reports via == 'legacy'."""

    def test_read_config_falls_back_to_read_remote_json(self, monkeypatch, app):
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],  # helper probe → missing
            [(json.dumps({"Dhcp4": {"subnet4": [{"id": 7}]}}), "")],  # legacy `cat`
        )
        flags = []
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: flags.append(srv["id"]))
        with app.test_request_context("/"):
            cfg = kea_host.read_config(SERVER, "dhcp4")
        assert cfg == {"Dhcp4": {"subnet4": [{"id": 7}]}}
        assert flags == [1]

    def test_apply_config_legacy_reports_ok(self, monkeypatch, app):
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],
            [("ok", "")],  # legacy render_author_config_script → 'ok'
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"subnet4": []}})
        assert res["ok"] is True and res["code"] == "ok" and res["via"] == "legacy"

    def test_service_action_legacy_done_token(self, monkeypatch, app):
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],
            [("done", "")],
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.service_action(SERVER, "dhcp4", "restart")
        assert res["ok"] is True and res["via"] == "legacy"


class TestFlagLegacyDedupes:
    def test_one_flash_per_server_per_request(self, monkeypatch, app):
        seen = []
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "flash", lambda msg, cat=None: seen.append(msg))
        with app.test_request_context("/"):
            kea_host._flag_legacy(SERVER)
            kea_host._flag_legacy(SERVER)
            kea_host._flag_legacy({"id": 2, "name": "kea-b", "ssh_host": "x"})
        assert len(seen) == 2
        assert "kea-a" in seen[0] and "kea-b" in seen[1]


class TestNoDirectRootPathsOutsideKeaHost:
    """v5.11.0 — every Kea-host root operation goes through kea_host. The
    legacy `sudo python3` pipe and `subprocess ["ssh", …]` should exist
    ONLY inside kea_host.py (the fallback engine) and kea_authoring.py's
    render_install_helper_script (which deploys the helper once)."""

    def _py_files(self):
        return [p for p in _JEN.rglob("*.py")]

    def test_sudo_python3_pipe_only_in_kea_host_and_installer(self):
        offenders = []
        for p in self._py_files():
            text = p.read_text(encoding="utf-8")
            if ("base64 -d | sudo python3" in text or "| sudo python3" in text) and p.name not in (
                "kea_host.py",
                "kea_authoring.py",
            ):
                offenders.append(str(p.relative_to(_JEN.parent)))
        assert not offenders, offenders

    def test_no_subprocess_ssh_in_routes(self):
        offenders = []
        for p in (_JEN / "routes").rglob("*.py"):
            text = p.read_text(encoding="utf-8")
            # ddns.py keeps a plain-SSH `dig`/`host` lookup (no sudo)
            if (
                'subprocess.run(["ssh"' in text or "subprocess.run(['ssh'" in text or '["ssh"]\n' in text
            ) and p.name != "ddns.py":
                offenders.append(str(p.relative_to(_JEN.parent)))
        assert not offenders, offenders


class TestHelperDeployment:
    def test_render_install_helper_script_embeds_source_and_sudoers_line(self):
        from jen.services.kea_authoring import render_install_helper_script

        script = render_install_helper_script("HELPER_VERSION = 1\n# body\n", "matthew", 1)
        assert "HELPER_VERSION = 1" in script
        assert "matthew ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper" in script
        assert "visudo" in script and 'print("ok:1")' in script
        import ast

        ast.parse(script)  # the remote script must be valid python

    def test_install_helper_parses_ok(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 1\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:1", ""))
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 1, "code": "installed", "detail": ""}

    def test_install_helper_needs_a_path_in(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: False)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path"

    def test_install_helper_already_installed_short_circuits(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 1})
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 1, "code": "already", "detail": ""}

    def test_install_helper_sudoerror(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("sudoerror:bad line 2", ""))
        res = kea_host.install_helper(SERVER)
        assert res["code"] == "sudoerror" and res["detail"] == "bad line 2"


class TestStatusTracking:
    def test_record_and_read_round_trip(self, monkeypatch):
        store = {}

        class _U:
            @staticmethod
            def get_global_setting(k, d=None):
                return store.get(k, d)

            @staticmethod
            def set_global_setting(k, v):
                store[k] = v

        monkeypatch.setattr(kea_host, "_user", lambda: _U)
        monkeypatch.setattr(kea_host, "helper_status", _REAL_HELPER_STATUS)
        monkeypatch.setattr(kea_host, "record_helper_status", _REAL_RECORD)

        kea_host.record_helper_status(1, 1)
        kea_host.record_helper_status(2, None)
        data = kea_host.helper_status()
        assert data["1"]["version"] == 1
        assert data["2"]["version"] is None
        assert "checked" in data["1"]
