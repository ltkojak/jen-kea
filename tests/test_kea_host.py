"""
tests/test_kea_host.py
──────────────────────
v5.11.0 — jen/services/kea_host.py: the single Kea-host client. Helper
transport is exercised against tests._kea6_helpers.FakeSSHClient; the
legacy fallback against the same fake replying with the OLD tokens.
"""

import hashlib
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
    """No settings-table or history writes for the transport tests."""
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", dict)
    monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
    monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)


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

    def test_read_config_falls_back_to_read_remote_json(self, monkeypatch, app, quiet_status):
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

    def test_service_action_legacy_uses_exit_status_not_stdout_text(self, monkeypatch, app):
        """v5.28.0 (Q24, B1) — the real bug this replaces:
        `service_action()`'s legacy command used to append an
        unconditional trailing marker after `cmd1 || cmd2`, which
        printed even when BOTH systemctl attempts failed — Jen could
        report "restarted successfully" on a host where Kea never
        actually restarted. Success is now the compound command's own
        real exit status."""
        _connect_seq(monkeypatch, [("", "sudo: a password is required")], [("", "", 0)])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.service_action(SERVER, "dhcp4", "restart")
        assert res["ok"] is True and res["via"] == "legacy"

    def test_service_action_legacy_nonzero_exit_is_not_ok(self, monkeypatch, app):
        _connect_seq(
            monkeypatch, [("", "sudo: a password is required")], [("", "Failed to restart kea-dhcp4-server.service", 1)]
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.service_action(SERVER, "dhcp4", "restart")
        assert res["ok"] is False
        assert "Failed to restart" in res["detail"]

    def test_service_action_legacy_old_done_token_no_longer_counts(self, monkeypatch, app):
        """The old success token, printed with a nonzero real exit
        status, must NOT be believed — this is the exact shape of the
        original bug."""
        _connect_seq(monkeypatch, [("", "sudo: a password is required")], [("done", "", 1)])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.service_action(SERVER, "dhcp4", "restart")
        assert res["ok"] is False

    def test_install_package_legacy_uses_exit_status_not_text_sniffing(self, monkeypatch, app):
        """v5.28.0 (Q24, B1) — "E:" in apt's own normal chatter no
        longer looks like a failure; only a nonzero exit status does."""
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],
            [("Reading package lists...\nE: this line looks scary but the command still succeeded", "", 0)],
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.install_package(SERVER, "dhcp4")
        assert res["ok"] is True

    def test_install_package_legacy_nonzero_exit_is_not_ok(self, monkeypatch, app):
        _connect_seq(monkeypatch, [("", "sudo: a password is required")], [("some output", "", 100)])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.install_package(SERVER, "dhcp4")
        assert res["ok"] is False

    def test_no_unconditional_trailing_marker_survives_in_the_module(self):
        """Source guard for the exact bug fixed above: the old
        `; echo done` trick (or any equivalent unconditional trailing
        marker after a `||`-joined systemctl pair) must never come
        back."""
        src = pathlib.Path("jen/services/kea_host.py").read_text(encoding="utf-8")
        assert "echo done" not in src


class TestD2NeedsHelper:
    """v5.23.0 (Q19) — D2 has no legacy engine at all: a v1/v2 helper
    (helper present, but predates d2 support) answers "not-allowed", and
    a genuinely missing helper must NOT fall through to
    render_author_config_script / the `fam = dhcp4 if ... else dhcp6`
    legacy systemctl string — both would silently treat d2 as dhcp6."""

    def test_test_config_old_helper_gives_a_clear_message(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "not-allowed"}), "")])
        res = kea_host.test_config(SERVER, "d2", {"DhcpDdns": {}})
        assert res["ok"] is False and res["via"] == "helper"
        assert "v3" in res["detail"] and "helper" in res["detail"].lower()

    def test_apply_config_old_helper_gives_a_clear_message(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "not-allowed"}), "")])
        res = kea_host.apply_config(SERVER, "d2", {"DhcpDdns": {}})
        assert res["ok"] is False and res["via"] == "helper"
        assert "v3" in res["detail"]

    def test_service_action_old_helper_gives_a_clear_message(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "not-allowed"}), "")])
        res = kea_host.service_action(SERVER, "d2", "restart")
        assert res["ok"] is False and res["via"] == "helper"
        assert "v3" in res["detail"]

    def test_test_config_no_helper_does_not_fall_through_to_legacy(self, monkeypatch, app):
        made = _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.test_config(SERVER, "d2", {"DhcpDdns": {}})
        assert res["ok"] is False and res["via"] == "legacy"
        assert "v3" in res["detail"]
        assert len(made) == 1  # never opened a second connection to run a legacy script

    def test_apply_config_no_helper_does_not_fall_through_to_legacy(self, monkeypatch, app):
        made = _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "d2", {"DhcpDdns": {}})
        assert res["ok"] is False and res["via"] == "legacy"
        assert len(made) == 1

    def test_service_action_no_helper_does_not_fall_through_to_legacy(self, monkeypatch, app):
        made = _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.service_action(SERVER, "d2", "restart")
        assert res["ok"] is False and res["via"] == "legacy"
        assert len(made) == 1

    def test_service_action_no_unit_names_the_dhcp_ddns_unit(self, monkeypatch, quiet_status):
        """A real v3 helper answering "no-unit" (D2 not installed) is a
        different case from "not-allowed" (helper too old) — the message
        should name the actual unit family, not "kea-d2-server"."""
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "no-unit"}), "")])
        res = kea_host.service_action(SERVER, "d2", "restart")
        assert "kea-dhcp-ddns-server" in res["detail"]


class TestD2Supported:
    def test_false_when_unknown(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", dict)
        assert kea_host.d2_supported(1) is False

    def test_false_when_below_min(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 2}})
        assert kea_host.d2_supported(1) is False

    def test_true_when_at_or_above_min(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 3}})
        assert kea_host.d2_supported(1) is True


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
        return list(_JEN.rglob("*.py"))

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
        # v5.19.1 — install_helper() re-checks after the copy rather than
        # trusting the script's own echoed version, so the fake check_helper
        # answers differently on the two calls it makes here: nothing
        # installed yet, then the real (WANT) version once the copy lands.
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        calls = iter([{"ok": False, "version": None}, {"ok": True, "version": kea_host.JEN_HELPER_WANT_VERSION}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": kea_host.JEN_HELPER_WANT_VERSION, "code": "installed", "detail": ""}

    def test_install_helper_upgrades_an_old_version(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        calls = iter([{"ok": True, "version": 1}, {"ok": True, "version": 2}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 2, "code": "upgraded", "detail": ""}

    def test_install_helper_copy_did_not_take_is_stale(self, monkeypatch, quiet_status):
        # The script printed ok:2, but the helper's own `version` op still
        # answers 1 on re-check — install_helper must not trust the echo.
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        calls = iter([{"ok": True, "version": 1}, {"ok": True, "version": 1}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False
        assert res["code"] == "stale"
        assert res["version"] == 1
        assert "v1" in res["detail"] and "v2" in res["detail"]

    def test_install_helper_needs_a_path_in(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: False)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path"
        assert res["detail"] == "no legacy python3 grant to install through"

    def test_install_helper_old_version_needs_a_path_in_shows_the_manual_command(self, monkeypatch, quiet_status):
        # A helper is already there (v1), just below WANT — the message
        # must give the manual copy command, not just "nothing installed".
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 1})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: False)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path" and res["version"] == 1
        assert "sudo install -o root -g root -m 0755" in res["detail"]
        assert "/usr/local/sbin/jen-kea-helper" in res["detail"]

    def test_install_helper_already_installed_short_circuits(self, monkeypatch, quiet_status):
        # v5.19.1 — "already" now means "at or above JEN_HELPER_WANT_VERSION",
        # not just JEN_HELPER_MIN_VERSION — a v1 host is the "no-path"/
        # "stale" territory above, never "already".
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(
            kea_host, "check_helper", lambda s: {"ok": True, "version": kea_host.JEN_HELPER_WANT_VERSION}
        )
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": kea_host.JEN_HELPER_WANT_VERSION, "code": "already", "detail": ""}

    def test_install_helper_sudoerror(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("sudoerror:bad line 2", "", 0))
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

    def test_legacy_grant_persists_when_not_specified(self, monkeypatch):
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

        kea_host.record_helper_status(1, 2, legacy_grant=True)
        kea_host.record_helper_status(1, 2)  # a later call with no opinion on it
        assert kea_host.helper_status()["1"]["legacy_grant"] is True

        kea_host.record_helper_status(1, 2, legacy_grant=False)
        assert kea_host.helper_status()["1"]["legacy_grant"] is False


class TestCheckHelperRecordsLegacyGrant:
    """v5.20.0 (15F) — check_helper probes legacy_grant_present() on
    every call (including install_helper's own check_helper() calls) so
    Health Center can warn without SSHing at render time."""

    def test_probes_and_records_on_success(self, monkeypatch, quiet_status):
        recorded = []
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: True)
        monkeypatch.setattr(
            kea_host,
            "record_helper_status",
            lambda sid, v, legacy_grant=None: recorded.append((sid, v, legacy_grant)),
        )
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "helper_version": 2}), "")])
        kea_host.check_helper(SERVER)
        assert recorded == [(1, 2, True)]

    def test_records_on_missing_too(self, monkeypatch, quiet_status):
        recorded = []
        monkeypatch.setattr(kea_host, "legacy_grant_present", lambda s: False)
        monkeypatch.setattr(
            kea_host,
            "record_helper_status",
            lambda sid, v, legacy_grant=None: recorded.append((sid, v, legacy_grant)),
        )
        _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        kea_host.check_helper(SERVER)
        assert recorded == [(1, None, False)]


class TestHelperVersionFromResponse:
    """v5.16.0 — _record_from_resp learns the real version from any op's
    envelope, not just a `version` op."""

    def test_records_helper_version_from_a_data_op(self, monkeypatch, quiet_status):
        recorded = []
        monkeypatch.setattr(kea_host, "record_helper_status", lambda sid, v: recorded.append((sid, v)))
        monkeypatch.setattr(kea_host, "helper_status", dict)
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}, "helper_version": 2}), "")])
        kea_host.read_config(SERVER, "dhcp4")
        assert (1, 2) in recorded

    def test_falls_back_to_min_when_envelope_lacks_it(self, monkeypatch, quiet_status):
        recorded = []
        monkeypatch.setattr(kea_host, "record_helper_status", lambda sid, v: recorded.append((sid, v)))
        monkeypatch.setattr(kea_host, "helper_status", dict)
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}}), "")])
        kea_host.read_config(SERVER, "dhcp4")
        assert (1, kea_host.JEN_HELPER_MIN_VERSION) in recorded


class TestReadConfigVersioned:
    def test_returns_cfg_and_sha_from_a_v2_helper(self, monkeypatch, quiet_status):
        _connect_seq(
            monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}, "sha256": "abc", "helper_version": 2}), "")]
        )
        cfg, sha = kea_host.read_config_versioned(SERVER, "dhcp4")
        assert cfg == {"Dhcp4": {}} and sha == "abc"

    def test_returns_a_canonical_sentinel_on_a_v1_helper(self, monkeypatch, quiet_status):
        """v5.28.0 (Q24, B2) — a v1 helper gives no raw sha; this used
        to return None, disabling the concurrency guard entirely until
        apply_config()'s own (dangerously late) fallback kicked in. It
        now returns a canonical sentinel so every caller always has
        something to guard a write with."""
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}}), "")])
        cfg, sha = kea_host.read_config_versioned(SERVER, "dhcp4")
        assert cfg == {"Dhcp4": {}}
        assert sha == kea_host._canonical_sentinel({"Dhcp4": {}})

    def test_returns_a_canonical_sentinel_on_the_legacy_path(self, monkeypatch, app, quiet_status):
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],
            [(json.dumps({"Dhcp4": {"n": 1}}), "")],
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            cfg, sha = kea_host.read_config_versioned(SERVER, "dhcp4")
        assert cfg == {"Dhcp4": {"n": 1}}
        assert sha == kea_host._canonical_sentinel({"Dhcp4": {"n": 1}})

    # ── v5.20.0: baseline + hash_kind ────────────────────────────────────
    def test_first_v2_read_records_a_raw_baseline(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {"n": 1}}, "sha256": "abc"}), "")])
        calls = []
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a: None)
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: calls.append((a, k)))
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert len(calls) == 1
        args, kwargs = calls[0]
        assert kwargs.get("source") == "baseline"
        assert kwargs.get("hash_kind") == "raw"
        assert args[3] == "abc"  # the sha, passed through unchanged

    def test_first_v1_read_records_a_canonical_baseline(self, monkeypatch, quiet_status):
        from jen.services import config_revisions as rev_mod

        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {"n": 1}}}), "")])  # no sha256 -> v1
        calls = []
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a: None)
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: calls.append((a, k)))
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert len(calls) == 1
        args, kwargs = calls[0]
        assert kwargs.get("source") == "baseline"
        assert kwargs.get("hash_kind") == "canonical"
        expected_sha = hashlib.sha256(rev_mod.canonical({"Dhcp4": {"n": 1}}).encode()).hexdigest()
        assert args[3] == expected_sha

    def test_v1_read_records_nothing_once_a_baseline_exists(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}}), "")])
        calls = []
        monkeypatch.setattr(
            "jen.services.config_revisions.latest", lambda *a: {"sha256": "x", "hash_kind": "canonical"}
        )
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: calls.append(1))
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert not calls

    def test_crossover_from_canonical_to_raw_is_a_baseline_not_external(self, monkeypatch, quiet_status):
        # A host just upgraded v1->v2: the latest recorded revision is
        # "canonical" (there was never a raw hash before). The first v2
        # read must not be treated as an external change just because
        # the two sha VALUES differ — they're different quantities.
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {"n": 2}}, "sha256": "raw-sha"}), "")])
        calls = []
        monkeypatch.setattr(
            "jen.services.config_revisions.latest", lambda *a: {"sha256": "canon-sha", "hash_kind": "canonical"}
        )
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: calls.append((a, k)))
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert len(calls) == 1
        assert calls[0][1].get("source") == "baseline"
        assert calls[0][1].get("hash_kind") == "raw"

    def test_external_change_is_recorded_when_sha_differs(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {"n": 2}}, "sha256": "new"}), "")])
        calls = []
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a: {"sha256": "old", "hash_kind": "raw"})
        monkeypatch.setattr(
            "jen.services.config_revisions.record",
            lambda *a, **k: calls.append((a, k)),
        )
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert calls and calls[0][1].get("source") == "external"
        assert calls[0][1].get("hash_kind") == "raw"

    def test_no_external_capture_when_sha_matches(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "config": {"Dhcp4": {}}, "sha256": "same"}), "")])
        calls = []
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a: {"sha256": "same", "hash_kind": "raw"})
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: calls.append(1))
        kea_host.read_config_versioned(SERVER, "dhcp4")
        assert not calls


class TestApplyGuarded:
    def test_expect_sha256_is_passed_to_the_helper(self, monkeypatch, quiet_status):
        made = _connect_seq(monkeypatch, [(json.dumps({"ok": True, "sha256": "written", "helper_version": 2}), "")])
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}}, expect_sha256="base-sha")
        assert json.loads(made[0].stdin_writes[0])["expect_sha256"] == "base-sha"

    def test_no_expect_sha256_key_when_not_given(self, monkeypatch, quiet_status):
        made = _connect_seq(monkeypatch, [(json.dumps({"ok": True, "helper_version": 2}), "")])
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert "expect_sha256" not in json.loads(made[0].stdin_writes[0])

    def test_helper_conflict_maps_to_code_conflict(self, monkeypatch, quiet_status):
        _connect_seq(
            monkeypatch,
            [(json.dumps({"ok": False, "error": "conflict", "sha256": "current", "helper_version": 2}), "")],
        )
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}}, expect_sha256="stale")
        assert res["code"] == "conflict" and res["sha256"] == "current" and res["via"] == "helper"

    def test_v1_helper_jen_side_compare_proceeds_when_unchanged(self, monkeypatch, app, quiet_status):
        """v5.28.0 (Q24, B2) — the check now runs BEFORE the write: the
        first queued response is `_jen_side_conflict()`'s own re-read
        (which finds the live config unchanged), and only then does a
        SECOND connection make the actual apply-config call — the
        opposite order from before this fix, when apply-config ran
        first and the (v1-only) jen-side check ran after."""
        _connect_seq(
            monkeypatch,
            [(json.dumps({"ok": True, "config": {"Dhcp4": {"a": 1}}}), "")],  # pre-write re-read: unchanged
            [(json.dumps({"ok": True, "helper_version": 1}), "")],  # apply-config itself
        )
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["ok"] is True

    def test_v1_helper_jen_side_compare_conflicts_when_changed(self, monkeypatch, app, quiet_status):
        _connect_seq(
            monkeypatch,
            [(json.dumps({"ok": True, "config": {"Dhcp4": {"a": 999}}}), "")],  # pre-write re-read: different
        )
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})  # what the caller originally read
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["ok"] is False and res["code"] == "conflict" and res["via"] == "jen"

    def test_v1_sentinel_conflict_is_detected_before_any_apply_call(self, monkeypatch, app, quiet_status):
        """The regression ChatGPT's review asked for: on a conflict, the
        write must never have been attempted at all — not one SSH
        connection beyond the pre-write re-read."""
        made = _connect_seq(
            monkeypatch,
            [(json.dumps({"ok": True, "config": {"Dhcp4": {"a": 999}}}), "")],
        )
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["code"] == "conflict"
        assert len(made) == 1, "apply-config must never be reached once a conflict is detected"

    def test_v1_sentinel_is_never_sent_to_the_helper(self, monkeypatch, app, quiet_status):
        """The other regression ChatGPT's review asked for: the
        apply-config payload must carry no expect_sha256 key at all
        once the pre-write check has already passed — a v2+ helper
        would otherwise reject the sentinel string as a raw-sha
        mismatch."""
        made = _connect_seq(
            monkeypatch,
            [(json.dumps({"ok": True, "config": {"Dhcp4": {"a": 1}}}), "")],  # pre-write re-read: unchanged
            [(json.dumps({"ok": True, "helper_version": 1}), "")],  # apply-config itself
        )
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert "expect_sha256" not in json.loads(made[1].stdin_writes[0])

    def test_legacy_sentinel_conflict_is_detected_before_any_write(self, monkeypatch, app, quiet_status):
        """Same regression, over the legacy (no helper at all) path:
        conflict detection must happen before render_author_config_script
        ever runs, so no `sudo python3` connection is opened."""
        made = _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],  # helper probe for the pre-write re-read -> missing
            [(json.dumps({"Dhcp4": {"a": 999}}), "")],  # legacy cat: live config differs
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["code"] == "conflict"
        assert len(made) == 2, "no third connection (the sudo python3 write) should ever open"

    def test_legacy_sentinel_proceeds_to_write_when_unchanged(self, monkeypatch, app, quiet_status):
        made = _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required")],  # pre-write re-read: helper probe -> missing
            [(json.dumps({"Dhcp4": {"a": 1}}), "")],  # legacy cat: unchanged
            [("", "sudo: a password is required")],  # apply-config: helper probe -> missing
            [("ok", "", 0)],  # the actual write
        )
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["ok"] is True
        assert len(made) == 4

    def test_success_records_a_revision(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "sha256": "s1", "helper_version": 2}), "")])
        recorded = []
        monkeypatch.setattr(
            "jen.services.config_revisions.record",
            lambda sid, svc, cfg, sha, summary, *, hash_kind, source="jen": recorded.append(
                (sid, svc, sha, summary, source, hash_kind)
            ),
        )
        kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}}, summary="edit subnet 5")
        assert recorded == [(1, "dhcp4", "s1", "edit subnet 5", "jen", "raw")]

    def test_success_with_no_helper_sha_records_a_canonical_hash(self, monkeypatch, quiet_status):
        # No sha256 in the response (v1/legacy) -> _record_revision_after_apply
        # computes sha256(canonical(cfg)) itself and records it as "canonical".
        _connect_seq(monkeypatch, [(json.dumps({"ok": True}), "")])
        recorded = []
        monkeypatch.setattr(
            "jen.services.config_revisions.record",
            lambda sid, svc, cfg, sha, summary, *, hash_kind, source="jen": recorded.append((sha, hash_kind)),
        )
        kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 1}}, summary="edit subnet 5")
        assert len(recorded) == 1
        sha, hash_kind = recorded[0]
        assert hash_kind == "canonical"
        from jen.services import config_revisions as rev_mod

        assert sha == hashlib.sha256(rev_mod.canonical({"Dhcp4": {"a": 1}}).encode()).hexdigest()
