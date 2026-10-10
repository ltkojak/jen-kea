"""
tests/test_kea_host.py
──────────────────────
v5.11.0 — jen/services/kea_host.py: the single Kea-host client. Helper
transport is exercised against tests._kea6_helpers.FakeSSHClient; the
legacy fallback against the same fake replying with the OLD tokens.
"""

import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
from importlib.machinery import SourceFileLoader

import pytest

from jen.services import kea_host
from tests._kea6_helpers import FakeSSHClient

_JEN = pathlib.Path(__file__).resolve().parent.parent / "jen"
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_HELPER_SCRIPT_PATH = _REPO_ROOT / "jen-kea-helper"
_UPDATE_ROOT_PATH = _REPO_ROOT / "jen-update-root.py"

SERVER = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "ssh_user": "kea", "kea_conf": "/etc/kea/kea-dhcp4.conf"}

# v5.65.13 (Q102) — canned legacy_grant_status() results for install_helper tests that only care
# whether the grant is usable, not the probe mechanics (those are TestLegacyGrantStatus below).
_OK_GRANT = {"ok": True, "rc": 0, "reason": "", "user_at_host": "kea@10.0.0.5", "summary": ""}
_FAILED_GRANT = {
    "ok": False,
    "rc": 1,
    "reason": "a password is required",
    "user_at_host": "kea@10.0.0.5",
    "summary": "",
}

# the real status functions, captured before any test monkeypatches them
_REAL_HELPER_STATUS = kea_host.helper_status
_REAL_RECORD = kea_host.record_helper_status


@pytest.fixture(autouse=True)
def _no_investigation_guard(monkeypatch):
    """`apply_config` asks `investigation_logging.file_write_refusal` before it sends anything (v5.68.0-beta.28, Q164), which reads Jen's settings. These tests are
    about the helper and legacy mechanics of the write, not that question - it has its own tests (tests/test_identity_guard.py, through the REAL `apply_config`) -
    so it answers "no refusal" here and the tests need no database."""
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")


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


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory):
    """v5.66.0-beta.2 (Q104, item g) — a throwaway ed25519 key pair, generated once per test
    module run, in the same "allowed signers" format as kea_host.RELEASE_SIGNERS. Mirrors
    tests/test_kea_helper.py's own fixture of the same name; skipped only if ssh-keygen itself
    is unavailable — never true on CI's ubuntu runner (openssh-client), true here only on a dev
    box that has somehow removed it."""
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen not available")
    d = tmp_path_factory.mktemp("q104-kea-host-signing-key")
    key_path = d / "key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True, capture_output=True)
    pub_line = (d / "key.pub").read_text().strip().split()
    return {"priv": str(key_path), "signers_line": f"release@jen {pub_line[0]} {pub_line[1]}"}


def _sign(key_path, namespace, data, tmp_path, name="candidate"):
    """Mirrors tests/test_kea_helper.py's own _sign(): `ssh-keygen -Y sign` signs a FILE
    (producing `<file>.sig` beside it), unlike `-Y verify` which reads the message on stdin."""
    cand = tmp_path / name
    cand.write_bytes(data)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(cand)],
        check=True,
        capture_output=True,
    )
    return (tmp_path / f"{name}.sig").read_bytes()


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


class TestNoUnverifiedByHandFallback:
    """v5.66.0-beta.2 (Q104, item b) — the by-hand fallback for installing jen-kea-helper is
    now ONE verified one-liner (_helper_download_command(): fetch the helper AND its
    signature, `ssh-keygen -Y verify` locally, only then `sudo install`). Nothing in the app
    or its docs may show an operator a DIFFERENT, unverified way to get the helper onto a Kea
    host — that gap (v5.65.13's plain `curl ... -o /tmp/jen-kea-helper && sudo install ...`,
    trusting whatever bytes came back with no check at all) is exactly what this Q closes."""

    _ROOTS = ("jen", "templates", "docs")
    _EXTS = (".py", ".html", ".md")

    def _text_files(self):
        repo_root = _JEN.parent
        for root_name in self._ROOTS:
            root = repo_root / root_name
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                if p.is_file() and p.suffix in self._EXTS and "__pycache__" not in p.parts:
                    yield p

    def test_raw_githubusercontent_never_appears_alongside_jen_kea_helper(self):
        # PLUGIN_REGISTRY_URL legitimately uses raw.githubusercontent.com elsewhere (an
        # unrelated, read-only JSON metadata fetch) — this only flags the combination that
        # used to be the OLD unverified helper-download URL.
        offenders = []
        for p in self._text_files():
            for line in p.read_text(encoding="utf-8").splitlines():
                if "raw.githubusercontent.com" in line and "jen-kea-helper" in line:
                    offenders.append(str(p.relative_to(_JEN.parent)))
        assert not offenders, offenders

    def test_a_sudo_install_of_the_helper_never_appears_without_a_verify_step_in_the_same_file(self):
        offenders = []
        for p in self._text_files():
            text = p.read_text(encoding="utf-8")
            mentions_install = "sudo install" in text and "/usr/local/sbin/jen-kea-helper" in text
            if mentions_install and "ssh-keygen -Y verify" not in text:
                offenders.append(str(p.relative_to(_JEN.parent)))
        assert not offenders, offenders

    def test_the_old_fixed_tmp_path_is_gone(self):
        """v5.65.13 (Q102) shipped `curl ... -o /tmp/jen-kea-helper && sudo install ...
        /tmp/jen-kea-helper ...` with no verification at all — a distinctive literal fragment
        of the unverified command that should never reappear as LIVE text anywhere (kea_host.py
        keeps one mention in its own docstring, quoting that old wording as history — excluded
        by name, the same way this class's other checks exclude the unrelated plugin registry)."""
        offenders = []
        for p in self._text_files():
            if p.name == "kea_host.py":
                continue
            if "/tmp/jen-kea-helper" in p.read_text(encoding="utf-8"):
                offenders.append(str(p.relative_to(_JEN.parent)))
        assert not offenders, offenders

    def test_the_download_command_itself_is_the_verified_one_liner(self):
        cmd = kea_host._helper_download_command()
        assert "ssh-keygen -Y verify" in cmd
        assert cmd.index("ssh-keygen -Y verify") < cmd.index("sudo install")
        assert "/tmp/" not in cmd
        assert "raw.githubusercontent.com" not in cmd


class TestHelperSelfTestBeforeInstall:
    """v5.66.0-beta.7 (Q109, item b) — the by-hand line used to go straight from `ssh-keygen -Y
    verify` to `sudo install`, skipping the self-check the automatic signed-update path already
    runs on a candidate before installing it (Q104's preflight). The one-liner now runs the
    just-downloaded candidate's own `version` op and checks it reports EXACTLY the
    version/build this release's own source declares, between the verify and the install."""

    def test_self_test_runs_between_verify_and_install(self, monkeypatch):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\nHELPER_BUILD = 9\n")
        cmd = kea_host._helper_download_command()
        assert cmd.index("ssh-keygen -Y verify") < cmd.index("python3 -c")
        assert cmd.index("python3 -c") < cmd.index("sudo install")

    def test_self_test_bakes_in_the_real_source_version_and_build(self, monkeypatch):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 12\nHELPER_BUILD = 34\n")
        cmd = kea_host._helper_self_test_command()
        assert '"helper_version")==12' in cmd
        assert '"helper_build")==34' in cmd

    def test_self_test_runs_the_downloaded_candidate_not_the_installed_one(self):
        cmd = kea_host._helper_self_test_command()
        assert "/usr/bin/python3 -I jen-kea-helper version" in cmd

    def test_local_offline_variant_is_the_exact_tail_of_the_online_one(self, monkeypatch):
        """docs/admin-guide.md and docs/runbooks.md both show a SHORTER local-only variant (no
        curl download — a tarball install already has both files side by side) for the offline
        case; it must be an exact suffix of the online one-liner, never a hand-maintained fork
        of it that could silently drift out of sync."""
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\nHELPER_BUILD = 9\n")
        online = kea_host._helper_download_command()
        local = kea_host._helper_verify_and_install_command()
        assert online.endswith(local)


class TestDocsCarryTheSameByHandLine:
    """v5.66.0-beta.7 (Q109, item b) — one source (_helper_download_command() and
    _helper_verify_and_install_command()), several places that show a copy of it. Rather than
    trust hand-maintained doc prose to stay in sync forever, render the real command (with
    JEN_VERSION normalised to the same `vX.Y.Z` placeholder the docs already use) and assert
    it appears byte-for-byte in each doc's fenced code block."""

    def _online_normalized(self):
        from jen import JEN_VERSION

        cmd = kea_host._helper_download_command()  # the real, currently-shipped source
        return cmd.replace(f"v{JEN_VERSION}", "vX.Y.Z")

    def _local_only(self):
        return kea_host._helper_verify_and_install_command()

    def test_admin_guide_online_block_matches(self):
        text = (_REPO_ROOT / "docs" / "admin-guide.md").read_text(encoding="utf-8")
        assert self._online_normalized() in text

    def test_admin_guide_offline_block_matches(self):
        text = (_REPO_ROOT / "docs" / "admin-guide.md").read_text(encoding="utf-8")
        assert self._local_only() in text

    def test_runbooks_online_block_matches(self):
        text = (_REPO_ROOT / "docs" / "runbooks.md").read_text(encoding="utf-8")
        assert self._online_normalized() in text

    def test_runbooks_offline_block_matches(self):
        text = (_REPO_ROOT / "docs" / "runbooks.md").read_text(encoding="utf-8")
        assert self._local_only() in text

    def test_manual_install_block_matches(self):
        text = (_REPO_ROOT / "docs" / "manual-install.md").read_text(encoding="utf-8")
        assert self._local_only() in text


class TestTheLegacyScriptTravelsOnStdinNotInAnArgument:
    """v5.68.0-beta.30 (Q167): `echo <base64> | base64 -d | sudo python3` put the whole script into ONE command-line argument, and Linux caps an argument at 131072 bytes
    (MAX_ARG_STRLEN). The helper passed ~96 KB at build 16 and 'Install helper' failed with `/bin/sh: Argument list too long` - found by the system stack."""

    class _Channel:
        def __init__(self):
            self.shut = False

        def shutdown_write(self):
            self.shut = True

        def recv_exit_status(self):
            return 0

    class _Stream:
        def __init__(self, text="ok:1", channel=None):
            self._text, self.channel = text, channel

        def read(self):
            return self._text.encode()

    class _Stdin:
        def __init__(self, channel):
            self.sent, self.channel = [], channel

        def write(self, data):
            self.sent.append(data)

    def _run(self, monkeypatch, script):
        import base64

        seen = {}
        channel = self._Channel()
        stdin = self._Stdin(channel)

        class Ssh:
            def exec_command(self, command, timeout=None):
                seen["command"] = command
                return (
                    stdin,
                    TestTheLegacyScriptTravelsOnStdinNotInAnArgument._Stream("ok:1", channel),
                    TestTheLegacyScriptTravelsOnStdinNotInAnArgument._Stream("", channel),
                )

            def close(self):
                seen["closed"] = True

        monkeypatch.setattr(kea_host.__dict__["__kea6"], "_connect_ssh", lambda server: Ssh())
        out = kea_host._legacy_python3({"id": 1}, script)
        seen["stdin"] = "".join(stdin.sent)
        seen["decoded"] = base64.b64decode(seen["stdin"]).decode()
        seen["out"] = out
        seen["shut"] = channel.shut
        return seen

    def test_the_command_carries_no_payload_and_the_script_arrives_whole_on_stdin(self, monkeypatch):
        script = "print('x')\n" + "# padding\n" * 40_000  # ~440 KB, base64 ~590 KB: far past one argument's cap
        seen = self._run(monkeypatch, script)
        assert seen["command"] == "base64 -d | sudo python3" and len(seen["command"]) < 100
        assert seen["decoded"] == script and seen["shut"] is True and seen["closed"] is True
        assert seen["out"] == ("ok:1", "", 0)

    def test_no_command_string_is_built_around_the_script_any_more(self):
        assert "echo {enc}" not in (_REPO_ROOT / "jen" / "services" / "kea_host.py").read_text(encoding="utf-8")


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
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": kea_host.JEN_HELPER_WANT_VERSION, "code": "installed", "detail": ""}

    def test_install_helper_upgrades_an_old_version(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        calls = iter([{"ok": True, "version": 1}, {"ok": True, "version": 2}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 2, "code": "upgraded", "detail": ""}

    def test_install_helper_copy_did_not_take_is_stale(self, monkeypatch, quiet_status):
        # The script printed ok:2, but the helper's own `version` op still
        # answers 1 on re-check — install_helper must not trust the echo.
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        calls = iter([{"ok": True, "version": 1}, {"ok": True, "version": 1}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False
        assert res["code"] == "stale"
        assert res["version"] == 1
        assert "v1" in res["detail"] and "v2" in res["detail"]

    def test_install_helper_needs_a_path_in(self, monkeypatch, quiet_status):
        # v5.65.13 (Q102) — install_helper now consults legacy_grant_status(), not the boolean
        # legacy_grant_present(), so it can say WHY (sudo's own reason), not just "no".
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _FAILED_GRANT)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path"
        assert "no legacy python3 grant to install through" in res["detail"]
        assert "kea@10.0.0.5" in res["detail"] and "a password is required" in res["detail"]

    def test_install_helper_old_version_needs_a_path_in_shows_the_manual_command(self, monkeypatch, quiet_status):
        # A helper is already there (v1), just below WANT — the message
        # must give the manual copy command, not just "nothing installed".
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 1})
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _FAILED_GRANT)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path" and res["version"] == 1
        assert "sudo install -o root -g root -m 0755" in res["detail"]
        assert "/usr/local/sbin/jen-kea-helper" in res["detail"]
        # v5.65.13 (Q102) — says what sudo actually said, names the server, and points at the
        # ordering diagnostic instead of just handing back the manual command silently.
        assert "kea-a" in res["detail"] and "a password is required" in res["detail"]
        assert "sudo -l" in res["detail"]

    def test_install_helper_already_installed_short_circuits(self, monkeypatch, quiet_status):
        # v5.19.1 — "already" means "at or above the version being
        # installed" — a v1 host is the "no-path"/"stale" territory above,
        # never "already". v5.29.2 — that target is the HELPER_VERSION of
        # the file being copied, not JEN_HELPER_WANT_VERSION.
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 2\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 2})
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 2, "code": "already", "detail": ""}

    def test_install_helper_upgrades_a_host_above_want_but_below_shipped(self, monkeypatch, quiet_status):
        """v5.29.2 — the maintainer's report: a v3 host pressed Update
        helper (offered since v5.29.1 because the shipped file is v4) and
        got "v3 is already installed" back, because the copy was gated on
        WANT (2). The target is the shipped file's version."""
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 4\n# body\n")
        calls = iter([{"ok": True, "version": 3}, {"ok": True, "version": 4}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        scripts = []
        monkeypatch.setattr(
            kea_host, "_legacy_python3", lambda s, script, timeout=60: (scripts.append(script), ("ok:4", "", 0))[1]
        )
        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 4, "code": "upgraded", "detail": ""}
        assert "HELPER_VERSION = 4" in scripts[0]

    def test_install_helper_target_falls_back_to_shipped_when_unparseable(self, monkeypatch, quiet_status):
        assert kea_host._source_version("HELPER_VERSION = 7\n") == 7
        assert kea_host._source_version("x") == kea_host.JEN_HELPER_SHIPPED_VERSION
        assert kea_host._source_version(kea_host._helper_source()) == kea_host.JEN_HELPER_SHIPPED_VERSION

    def test_install_helper_sudoerror(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "x")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": False, "version": None})
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("sudoerror:bad line 2", "", 0))
        res = kea_host.install_helper(SERVER)
        assert res["code"] == "sudoerror" and res["detail"] == "bad line 2"


class TestSourceBuild:
    """v5.66.0-beta.2 (Q104) — _source_build() beside _source_version(), same shape."""

    def test_parses_a_declared_build(self):
        assert kea_host._source_build("HELPER_BUILD = 42\n") == 42

    def test_falls_back_to_shipped_when_unparseable(self):
        assert kea_host._source_build("x") == kea_host.JEN_HELPER_SHIPPED_BUILD

    def test_the_real_file_matches_the_shipped_build(self):
        assert kea_host._source_build(kea_host._helper_source()) == kea_host.JEN_HELPER_SHIPPED_BUILD


class TestHelperVersionLabelBuild:
    """v5.66.0-beta.2 (Q104) — a v7+ host that reports a build reads "v7 (build 7)"; behind
    on build only (same protocol version) reads "v7 (build 3, build 7 available)"; a host
    with no build info at all (pre-v7) is unaffected — same output as before this Q."""

    def test_current_version_and_build(self):
        assert kea_host.helper_version_label(7, shipped=7, build=7, shipped_build=7) == "v7 (build 7)"

    def test_current_version_behind_on_build(self):
        assert (
            kea_host.helper_version_label(7, shipped=7, build=3, shipped_build=7) == "v7 (build 3, build 7 available)"
        )

    def test_no_build_info_is_unaffected(self):
        assert kea_host.helper_version_label(5, shipped=7) == "v5 (v7 available)"
        assert kea_host.helper_version_label(7, shipped=7) == "v7"


class TestInstallHelperAlreadyComparesBuilds:
    """v5.66.0-beta.2 (Q104) — same VERSION, lower BUILD is a real update to offer (a
    helper-only fix with no protocol change), not "already"; a host that reports no build at
    all (below v7) still falls back to comparing version alone."""

    def test_same_version_lower_build_is_not_already(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\nHELPER_BUILD = 9\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 7, "build": 3})
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        signed_called = []
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: signed_called.append(1) or b"sig")
        monkeypatch.setattr(
            kea_host,
            "helper_call",
            lambda s, op, payload=None, timeout=60: {"ok": True, "installed_version": 7, "installed_build": 9},
        )
        calls = iter([{"ok": True, "version": 7, "build": 3}, {"ok": True, "version": 7, "build": 9}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 7, "code": "upgraded", "detail": ""}
        assert signed_called == [1]  # the signed path WAS used — it wasn't "already"

    def test_same_version_and_build_is_already(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\nHELPER_BUILD = 9\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 7, "build": 9})
        signed_called = []
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: signed_called.append(1) or b"sig")

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 7, "code": "already", "detail": ""}
        assert signed_called == []  # never even reached the signed path

    def test_no_build_reported_falls_back_to_version_only(self, monkeypatch, quiet_status):
        """A host below v7 never reports a build at all — check_helper()["build"] is None,
        and the already-check must fall back to comparing version alone exactly as it did
        before this Q, not treat a missing build as "0" (which would never be "already")."""
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 6\nHELPER_BUILD = 1\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 6, "build": None})

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 6, "code": "already", "detail": ""}

    def test_higher_version_but_not_newer_build_is_still_already(self, monkeypatch, quiet_status):
        """v5.66.0-beta.7 (Q109) — the exact regression this Q closes: the old
        `(current, current_build) >= (target, target_build)` tuple compare read a HIGHER
        target version as automatically "not already" regardless of build, since version
        dominates lexicographic order — so a target declaring v8/build-7 against an
        installed v7/build-9 looked like a real update and would have been sent to the
        signed path, which op_update itself would then have refused as build-not-newer.
        The two checks are independent now: build alone can make it "already" even when
        the candidate's protocol version is higher."""
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 8\nHELPER_BUILD = 7\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 7, "build": 9})
        signed_called = []
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: signed_called.append(1) or b"sig")

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 7, "code": "already", "detail": ""}
        assert signed_called == []  # never even reached the signed path


class TestVerifyHelperSignature:
    """v5.66.0-beta.2 (Q104, item g) — the same check jen-kea-helper's own `update` op runs on
    the Kea host, run here first so Jen never sends a signature it hasn't already checked
    itself. Uses a THROWAWAY key (never the embedded, real RELEASE_SIGNERS — a checkout's
    helper source is not signed by the real key, and weakening the check to make a test pass
    would defeat the whole point)."""

    def test_a_genuine_signature_verifies(self, monkeypatch, signing_key, tmp_path):
        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        candidate = b"the exact helper bytes about to be sent"
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)
        assert kea_host.verify_helper_signature(candidate, sig) is True

    def test_a_signature_over_different_bytes_does_not_verify(self, monkeypatch, signing_key, tmp_path):
        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        sig = _sign(signing_key["priv"], "jen-kea-helper", b"the original bytes", tmp_path)
        assert kea_host.verify_helper_signature(b"tampered bytes", sig) is False

    def test_a_signature_under_the_wrong_namespace_does_not_verify(self, monkeypatch, signing_key, tmp_path):
        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        candidate = b"the exact helper bytes"
        sig = _sign(signing_key["priv"], "jen-release", candidate, tmp_path)  # checksum namespace, not helper's
        assert kea_host.verify_helper_signature(candidate, sig) is False

    def test_garbage_bytes_do_not_verify(self, monkeypatch, signing_key):
        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        assert kea_host.verify_helper_signature(b"anything", b"not a signature") is False

    def test_release_signers_matches_jen_update_root_and_the_helper_byte_for_byte(self):
        spec = importlib.util.spec_from_file_location("q104_update_root_twin_check", _UPDATE_ROOT_PATH)
        update_root = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update_root)
        assert kea_host.RELEASE_SIGNERS == update_root.RELEASE_SIGNERS

        loader = SourceFileLoader("q104_kea_helper_twin_check", str(_HELPER_SCRIPT_PATH))
        helper_spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(helper_spec)
        loader.exec_module(helper)
        assert kea_host.RELEASE_SIGNERS == helper.RELEASE_SIGNERS


class TestHelperSignature:
    """v5.66.0 (Q103) — helper_signature() prefers the sibling file jen-update-root.py writes,
    falls back to fetching this release's own GitHub asset. v5.66.0-beta.2 (Q104, item g) —
    now PRE-VERIFIED against the candidate bytes before either copy is trusted: a sibling file
    that doesn't verify (wrong bytes, or oversize/bounded-out) falls through to a fetch exactly
    like an absent one does."""

    def test_prefers_the_sibling_file_when_it_verifies(self, monkeypatch, signing_key, tmp_path):
        from jen import extensions

        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        candidate = b"the exact helper bytes"
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)
        (tmp_path / "jen-kea-helper.sig").write_bytes(sig)
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))
        assert kea_host.helper_signature(candidate) == sig

    def test_falls_back_to_a_fetch_when_the_sibling_file_is_absent(self, monkeypatch, signing_key, tmp_path):
        from jen import extensions

        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))  # no jen-kea-helper.sig here
        candidate = b"the exact helper bytes"
        fetched_sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path, name="fetched")

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return fetched_sig

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: FakeResp())
        assert kea_host.helper_signature(candidate) == fetched_sig

    def test_falls_back_to_a_fetch_when_the_sibling_file_does_not_verify(self, monkeypatch, signing_key, tmp_path):
        """A sibling file signed over the WRONG bytes (stale — left over from a previous
        release, say) must never be trusted just because it's present and well-formed."""
        from jen import extensions

        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        candidate = b"the exact helper bytes"
        stale_sig = _sign(signing_key["priv"], "jen-kea-helper", b"stale candidate bytes", tmp_path, name="stale")
        (tmp_path / "jen-kea-helper.sig").write_bytes(stale_sig)
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))
        fetched_sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path, name="fetched")

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return fetched_sig

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: FakeResp())
        assert kea_host.helper_signature(candidate) == fetched_sig

    def test_an_oversize_sibling_file_falls_through_to_a_fetch(self, monkeypatch, signing_key, tmp_path):
        """v5.66.0-beta.2 (Q104, item g) — the local read had no cap at all before this Q; now
        it's bounded the same way the fetch always was."""
        from jen import extensions

        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        (tmp_path / "jen-kea-helper.sig").write_bytes(b"x" * (kea_host._HELPER_SIG_MAX + 1))
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))
        candidate = b"the exact helper bytes"
        fetched_sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path, name="fetched")

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return fetched_sig

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: FakeResp())
        assert kea_host.helper_signature(candidate) == fetched_sig

    def test_a_fetch_failure_returns_none_not_raises(self, monkeypatch, tmp_path):
        from jen import extensions

        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))

        def _raise(req, timeout=10):
            raise OSError("network down")

        monkeypatch.setattr("urllib.request.urlopen", _raise)
        assert kea_host.helper_signature(b"candidate bytes") is None

    def test_an_oversize_fetch_returns_none(self, monkeypatch, tmp_path):
        from jen import extensions

        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"x" * n  # always fills exactly the requested (cap + 1) read

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: FakeResp())
        assert kea_host.helper_signature(b"candidate bytes") is None

    def test_a_fetched_signature_that_does_not_verify_returns_none(self, monkeypatch, signing_key, tmp_path):
        from jen import extensions

        monkeypatch.setattr(kea_host, "RELEASE_SIGNERS", signing_key["signers_line"])
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path))
        wrong_sig = _sign(signing_key["priv"], "jen-kea-helper", b"different bytes entirely", tmp_path)

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return wrong_sig

        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: FakeResp())
        assert kea_host.helper_signature(b"the exact helper bytes") is None


class TestInstallHelperSigned:
    """v5.66.0 (Q103) — a host already at SIGNED_UPDATE_HELPER_MIN_VERSION takes the signed
    `update` path and never touches the legacy engine at all."""

    def test_takes_the_signed_path_not_legacy(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: b"sig-bytes")
        monkeypatch.setattr(
            kea_host,
            "legacy_grant_status",
            lambda s: (_ for _ in ()).throw(AssertionError("must not probe the legacy grant on the signed path")),
        )
        legacy_called = []
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda *a, **k: legacy_called.append(1) or ("ok:", "", 0))
        monkeypatch.setattr(
            kea_host,
            "helper_call",
            lambda s, op, payload=None, timeout=60: {"ok": True, "installed_version": 7, "previous_version": 6},
        )
        calls = iter([{"ok": True, "version": 6}, {"ok": True, "version": 7}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 7, "code": "upgraded", "detail": ""}
        assert legacy_called == []

    def test_no_signature_available_is_reported_distinctly(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 6})
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: None)
        monkeypatch.setattr(kea_host, "_fetch_helper_signature", lambda candidate: None)

        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-signature"
        # v5.66.0-beta.7 (Q109, item b) — the by-hand line IS now offered here: this is one of
        # the four cases the spec names (first install, the v5-bootstrap hop, not-installed,
        # and this one) — a Jen box that can't produce a signature to send is exactly the
        # "do it offline, from the tarball's own two files" case.
        assert "reinstall Jen from the release tarball" in res["detail"]
        assert "sudo install -o root -g root" in res["detail"]

    @pytest.mark.parametrize(
        "helper_error,expected_code,offers_by_hand",
        [
            ("bad-signature", "bad-signature", False),
            ("no-ssh-keygen", "no-ssh-keygen", False),
            ("not-newer", "not-newer", False),
            ("symlink", "symlink", False),
            ("unparseable", "unparseable", False),
            ("preflight-failed", "preflight-failed", False),
            ("postflight-failed", "postflight-failed", False),
            ("not-installed", "not-installed", True),
            ("rollback-failed", "rollback-failed", False),
            ("not-allowed", "error", False),
        ],
    )
    def test_op_refusal_codes_are_worded_distinctly(
        self, monkeypatch, quiet_status, helper_error, expected_code, offers_by_hand
    ):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 6})
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: b"sig-bytes")
        # v5.66.0-beta.2 (Q104, item g) — a "bad-signature" reply retries with a fetched
        # signature before reporting; forcing that fetch to fail keeps THIS test about the
        # wording of each code, not the retry itself (which TestBadSignatureRetry covers).
        monkeypatch.setattr(kea_host, "_fetch_helper_signature", lambda candidate: None)
        monkeypatch.setattr(
            kea_host,
            "helper_call",
            lambda s, op, payload=None, timeout=60: {
                "ok": False,
                "error": helper_error,
                "path": "/usr/local/sbin/jen-kea-helper",
                "prev_path": "/usr/local/sbin/jen-kea-helper.prev",
            },
        )

        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False
        assert res["code"] == expected_code
        assert res["version"] == 6
        # v5.66.0-beta.7 (Q109, item b) — a by-hand install is offered ONLY for not-installed
        # here (first-install and no-signature are covered by their own tests above); every
        # other refusal says what was observed and points at investigation/reporting it,
        # never at installing around it.
        assert ("sudo install -o root -g root" in res["detail"]) is offers_by_hand

    def test_helper_call_transport_failure_is_an_error_not_a_raise(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 6})
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: b"sig-bytes")

        def _raise(*a, **k):
            raise kea_host.HelperMissing("gone")

        monkeypatch.setattr(kea_host, "helper_call", _raise)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "error"

    def test_stale_after_signed_update_is_reported(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: b"sig-bytes")
        monkeypatch.setattr(
            kea_host, "helper_call", lambda s, op, payload=None, timeout=60: {"ok": True, "installed_version": 7}
        )
        calls = iter([{"ok": True, "version": 6}, {"ok": True, "version": 6}])  # still 6 despite the "ok" reply
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))

        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "stale"

    def test_below_min_version_still_uses_the_legacy_one_last_hop(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 6\n")
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _OK_GRANT)
        monkeypatch.setattr(kea_host, "_legacy_python3", lambda s, script, timeout=60: ("ok:", "", 0))
        signed_called = []
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: signed_called.append(1) or b"x")
        calls = iter([{"ok": True, "version": 5}, {"ok": True, "version": 6}])
        monkeypatch.setattr(kea_host, "check_helper", lambda s: next(calls))

        res = kea_host.install_helper(SERVER)
        assert res == {"ok": True, "version": 6, "code": "upgraded", "detail": ""}
        assert signed_called == []  # the signed path was never touched below SIGNED_UPDATE_HELPER_MIN_VERSION

    def test_below_min_version_legacy_refusal_mentions_the_one_last_hop(self, monkeypatch, quiet_status):
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 6\n")
        monkeypatch.setattr(kea_host, "check_helper", lambda s: {"ok": True, "version": 5})
        monkeypatch.setattr(kea_host, "legacy_grant_status", lambda s: _FAILED_GRANT)

        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "no-path"
        assert "one last hop" in res["detail"] and "signed" in res["detail"]


class TestBadSignatureRetry:
    """v5.66.0-beta.2 (Q104, item g) — a `bad-signature` reply from the HOST right after a
    LOCALLY-sourced signature is unexpected enough (the local copy just passed Jen's own
    verification) to be worth one retry with a freshly fetched signature before reporting
    failure. Never retries a second time, and never retries when the signature Jen sent was
    already the fetched one — there's nowhere left to fall back to."""

    def _install(self, monkeypatch, quiet_status, local_sig, fetched_sig, call_results):
        import base64

        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\n")
        monkeypatch.setattr(kea_host, "_helper_source_bytes", lambda: b"HELPER_VERSION = 7\n")
        # the fake source text has no HELPER_BUILD line, so _source_build() falls back to
        # JEN_HELPER_SHIPPED_BUILD — the recheck below must report that same build or the
        # "did the copy actually take" build_ok comparison in _install_helper_signed reports
        # a real success as "stale" instead.
        shipped_build = kea_host.JEN_HELPER_SHIPPED_BUILD
        # the initial current-version check, then (only reached on an "ok" reply) the
        # post-update recheck — a fixed 6 for both would misreport a real success as "stale".
        checks = iter([{"ok": True, "version": 6}, {"ok": True, "version": 7, "build": shipped_build}])
        monkeypatch.setattr(
            kea_host, "check_helper", lambda s: next(checks, {"ok": True, "version": 7, "build": shipped_build})
        )
        monkeypatch.setattr(kea_host, "_local_helper_signature", lambda candidate: local_sig)
        monkeypatch.setattr(kea_host, "_fetch_helper_signature", lambda candidate: fetched_sig)

        sent_signatures = []
        results = iter(call_results)

        def fake_helper_call(s, op, payload=None, timeout=60):
            sent_signatures.append(base64.b64decode(payload["signature_b64"]))
            return next(results)

        monkeypatch.setattr(kea_host, "helper_call", fake_helper_call)
        res = kea_host.install_helper(SERVER)
        return res, sent_signatures

    def test_retries_once_with_the_fetched_signature_and_succeeds(self, monkeypatch, quiet_status):
        res, sent = self._install(
            monkeypatch,
            quiet_status,
            local_sig=b"local-sig",
            fetched_sig=b"fetched-sig",
            call_results=[
                {"ok": False, "error": "bad-signature"},
                {"ok": True, "installed_version": 7, "installed_build": kea_host.JEN_HELPER_SHIPPED_BUILD},
            ],
        )
        assert sent == [b"local-sig", b"fetched-sig"]  # local tried first, then the retry
        assert res["ok"] is True

    def test_a_retry_that_also_fails_reports_bad_signature_not_a_loop(self, monkeypatch, quiet_status):
        res, sent = self._install(
            monkeypatch,
            quiet_status,
            local_sig=b"local-sig",
            fetched_sig=b"fetched-sig",
            call_results=[
                {"ok": False, "error": "bad-signature"},
                {"ok": False, "error": "bad-signature"},
            ],
        )
        assert sent == [b"local-sig", b"fetched-sig"]  # exactly one retry, never a second
        assert res["ok"] is False and res["code"] == "bad-signature"

    def test_no_fetched_signature_available_means_no_retry_at_all(self, monkeypatch, quiet_status):
        res, sent = self._install(
            monkeypatch,
            quiet_status,
            local_sig=b"local-sig",
            fetched_sig=None,
            call_results=[{"ok": False, "error": "bad-signature"}],
        )
        assert sent == [b"local-sig"]  # nothing to retry with
        assert res["ok"] is False and res["code"] == "bad-signature"

    def test_bad_signature_after_an_already_fetched_signature_is_never_retried(self, monkeypatch, quiet_status):
        """local_sig=None means the FIRST attempt already used the fetched one — there is no
        second source left to fall back to, so this must not call helper_call a second time."""
        res, sent = self._install(
            monkeypatch,
            quiet_status,
            local_sig=None,
            fetched_sig=b"fetched-sig",
            call_results=[{"ok": False, "error": "bad-signature"}],
        )
        assert sent == [b"fetched-sig"]  # only one attempt, ever
        assert res["ok"] is False and res["code"] == "bad-signature"


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
            lambda sid, v, build=None, legacy_grant=None: recorded.append((sid, v, build, legacy_grant)),
        )
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "helper_version": 2}), "")])
        kea_host.check_helper(SERVER)
        assert recorded == [(1, 2, None, True)]

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

    def test_jen_side_conflict_fails_closed_when_the_reread_itself_fails(self, monkeypatch, app, quiet_status):
        """v5.28.1 (Q26, A2) — a failed reread used to return None
        ("can't verify — let the write proceed, -t will catch anything
        wrong"), silently disabling the guard exactly when it matters
        most (an unreachable host). `-t` only validates the
        CANDIDATE's syntax; it has no way to know whether the live
        file changed since Jen's original read."""
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda server, service: (None, None))
        sentinel = kea_host._canonical_sentinel({"Dhcp4": {"a": 1}})
        with app.test_request_context("/"):
            res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 2}}, expect_sha256=sentinel)
        assert res["ok"] is False
        assert res["code"] == "error"
        assert "no changes were written" in res["detail"]

    def test_v1_success_returns_a_canonical_sentinel_but_records_hash_kind_canonical(self, monkeypatch, quiet_status):
        """v5.28.1 (Q26, A3) — the RETURNED result now carries a
        sentinel sha (so kea_changeset's rollback has something real
        to guard a revert with — before this it was None, i.e. no
        guard at all), but the RECORDED revision must still get
        hash_kind "canonical" computed from the real None (record()
        branches on `if sha:`, and the helper genuinely returned none)
        — the sentinel is added to the result AFTER that call, never
        fed into it."""
        _connect_seq(monkeypatch, [(json.dumps({"ok": True, "helper_version": 1}), "")])
        recorded = []
        monkeypatch.setattr(
            "jen.services.config_revisions.record",
            lambda sid, svc, cfg, sha, summary, *, hash_kind, source="jen": recorded.append((sha, hash_kind)),
        )
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 1}})
        assert res["ok"] is True
        assert res["sha256"].startswith("canonical:")
        assert recorded[0][1] == "canonical"
        assert res["sha256"] == f"canonical:{recorded[0][0]}"

    def test_legacy_success_also_returns_a_canonical_sentinel(self, monkeypatch, quiet_status):
        made = _connect_seq(monkeypatch, [("", "sudo: a password is required")], [("ok", "", 0)])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        recorded = []
        monkeypatch.setattr(
            "jen.services.config_revisions.record",
            lambda sid, svc, cfg, sha, summary, *, hash_kind, source="jen": recorded.append((sha, hash_kind)),
        )
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {"a": 1}})
        assert res["ok"] is True
        assert res["sha256"].startswith("canonical:")
        assert recorded[0][1] == "canonical"
        assert res["sha256"] == f"canonical:{recorded[0][0]}"
        assert len(made) == 2

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


class TestInstallTls:
    """v5.29.0 (Q29, C2) — kea_host.install_tls: helper-only, never the
    legacy engine (key material must never ride a generated root
    script); a pre-v4 helper answers unknown-op → "helper-required"."""

    FILES = {
        "ca.crt": "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        "server.crt": "c",
        "server.key": "k",
    }

    def test_ok_sends_service_and_files_and_returns_paths(self, monkeypatch, quiet_status):
        paths = {
            "ca.crt": "/etc/kea/tls/dhcp4/ca.crt",
            "server.crt": "/etc/kea/tls/dhcp4/server.crt",
            "server.key": "/etc/kea/tls/dhcp4/server.key",
        }
        made = _connect_seq(
            monkeypatch, [(json.dumps({"ok": True, "paths": paths, "owner": "root:_kea", "helper_version": 4}), "")]
        )
        res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res == {"ok": True, "code": "ok", "paths": paths, "owner": "root:_kea", "via": "helper"}
        assert made[0].calls == ["sudo -n /usr/local/sbin/jen-kea-helper install-tls"]
        assert json.loads(made[0].stdin_writes[0]) == {"service": "dhcp4", "files": self.FILES}

    def test_old_helper_unknown_op_is_helper_required(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "unknown-op", "helper_version": 3}), "")])
        res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res["ok"] is False and res["code"] == "helper-required"
        assert "v4" in res["detail"]

    def test_missing_helper_is_helper_required_and_never_legacy(self, monkeypatch, app):
        made = _connect_seq(monkeypatch, [("", "sudo: a password is required")])
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda srv: None)
        with app.test_request_context("/"):
            res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res["ok"] is False and res["code"] == "helper-required" and res["via"] == "legacy"
        assert len(made) == 1  # no second connection for a legacy python3 run
        assert not any("python3" in c for c in made[0].calls)

    def test_symlink_and_bad_pem_refusals_are_named(self, monkeypatch, quiet_status):
        _connect_seq(
            monkeypatch, [(json.dumps({"ok": False, "error": "symlink", "path": "/etc/kea/tls/dhcp4/server.key"}), "")]
        )
        res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res["code"] == "error" and "symlink" in res["detail"] and "server.key" in res["detail"]
        _connect_seq(monkeypatch, [(json.dumps({"ok": False, "error": "bad-pem", "file": "ca.crt"}), "")])
        res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res["code"] == "error" and "ca.crt" in res["detail"]

    def test_garbage_is_an_error_not_an_exception(self, monkeypatch, quiet_status):
        _connect_seq(monkeypatch, [("not json", "kaboom")])
        res = kea_host.install_tls(SERVER, "dhcp4", self.FILES)
        assert res["ok"] is False and res["code"] == "error"


class TestTlsSupported:
    def test_false_when_unknown(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", dict)
        assert kea_host.tls_supported(1) is False

    def test_false_when_below_min(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 3}})
        assert kea_host.tls_supported(1) is False

    def test_true_when_at_or_above_min(self, monkeypatch):
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 4}})
        assert kea_host.tls_supported(1) is True

    def test_want_version_is_not_bumped_for_tls(self):
        """Same call as D2: only the https path needs v4, so the general
        "upgrade available" hint must not nag every host."""
        assert kea_host.JEN_HELPER_WANT_VERSION < kea_host.TLS_HELPER_MIN_VERSION == 4

    def test_shipped_version_is_the_helper_files_version(self):
        """v5.29.1 — the Update helper button is offered below SHIPPED,
        so SHIPPED must track the file (a bump to one without the other
        would hide the button for the new version again) and cover the
        https gate."""
        import re

        src = (_JEN.parent / "jen-kea-helper").read_text(encoding="utf-8")
        file_version = int(re.search(r"^HELPER_VERSION = (\d+)$", src, re.M).group(1))
        assert file_version == kea_host.JEN_HELPER_SHIPPED_VERSION
        assert kea_host.JEN_HELPER_SHIPPED_VERSION >= kea_host.TLS_HELPER_MIN_VERSION
        assert kea_host.JEN_HELPER_SHIPPED_VERSION >= kea_host.JEN_HELPER_WANT_VERSION


class TestTheUpdateHelperButtonKnowsTheBuild:
    """v5.68.0-beta.7 (Q142) - a helper release that changes the build and not the version (builds 8, 9, 10) was invisible to the Update helper
    button, which compared versions alone while the label beside it said "build 10 available"."""

    def test_the_shipped_build_is_the_helper_files_build(self):
        import re

        src = (_JEN.parent / "jen-kea-helper").read_text(encoding="utf-8")
        file_build = int(re.search(r"^HELPER_BUILD = (\d+)$", src, re.M).group(1))
        assert file_build == kea_host.JEN_HELPER_SHIPPED_BUILD, (
            "JEN_HELPER_SHIPPED_BUILD must track the file: the button and the 'build N available' label both read it"
        )

    def _render(self, helper_version, helper_build, role="superadmin"):
        """The SSH card's row for one host, rendered with the shipped numbers; True when the Update/Install helper form is there."""
        import pathlib

        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(pathlib.Path(__file__).resolve().parent.parent / "templates")), autoescape=True
        )
        source = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        start = source.index("{% for s in ssh_servers %}")
        end = source.index("{% endfor %}", source.index("Remove legacy grant", start)) + len("{% endfor %}")
        row = env.from_string(source[start:end])
        s = {
            "id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "helper_version": helper_version, "helper_build": helper_build,
            "helper_label": kea_host.helper_version_label(
                helper_version, kea_host.JEN_HELPER_SHIPPED_VERSION, build=helper_build
            ),
            "helper_want": kea_host.JEN_HELPER_WANT_VERSION, "helper_shipped": kea_host.JEN_HELPER_SHIPPED_VERSION,
            "helper_shipped_build": kea_host.JEN_HELPER_SHIPPED_BUILD, "helper_known": True, "legacy_grant": False,
            "signed_update": True,
        }  # fmt: skip
        html = row.render(ssh_servers=[s], current_user={"role": role}, csrf_token=lambda: "t")
        return "install-kea-helper/1" in html, html

    def test_a_build_only_update_gets_the_button_and_the_label_agrees(self):
        shown, html = self._render(kea_host.JEN_HELPER_SHIPPED_VERSION, kea_host.JEN_HELPER_SHIPPED_BUILD - 3)
        assert shown and "Update helper" in html
        assert f"build {kea_host.JEN_HELPER_SHIPPED_BUILD} available" in html

    def test_a_current_host_has_no_button(self):
        shown, _html = self._render(kea_host.JEN_HELPER_SHIPPED_VERSION, kea_host.JEN_HELPER_SHIPPED_BUILD)
        assert not shown

    def test_a_host_that_reports_no_build_is_below_any_build(self):
        shown, html = self._render(kea_host.JEN_HELPER_SHIPPED_VERSION, None)
        assert shown and "Update helper" in html

    def test_a_version_below_shipped_still_gets_it(self):
        assert self._render(kea_host.JEN_HELPER_SHIPPED_VERSION - 1, None)[0]

    def test_no_helper_still_offers_the_install(self):
        shown, html = self._render(None, None)
        assert shown and "Install helper" in html

    def test_only_a_superadmin_is_offered_it(self):
        assert not self._render(kea_host.JEN_HELPER_SHIPPED_VERSION, 1, role="admin")[0]

    def test_the_route_passes_the_build_and_the_shipped_build(self):
        import pathlib

        src = (
            pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "settings" / "infrastructure.py"
        ).read_text(encoding="utf-8")
        assert (
            '"helper_build": st.get("build")' in src
            and '"helper_shipped_build": kea_host.JEN_HELPER_SHIPPED_BUILD' in src
        )


class TestRemoveLegacyGrant:
    """v5.49.0 (Q51) - the legacy grant removes itself; Jen never re-adds it."""

    def test_rendered_script_names_only_the_fixed_paths_and_has_the_three_guards(self):
        import ast
        import re

        from jen.services.kea_authoring import render_remove_legacy_grant_script

        script = render_remove_legacy_grant_script("matthew")
        ast.parse(script)  # the remote script must be valid python
        assert "os.path.isfile(HELPER_SUDOERS)" in script
        assert 'WANT = USER + " ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper"' in script
        assert '"visudo", "-c", "-f", HELPER_SUDOERS' in script
        assert "matthew" in script
        paths = set(re.findall(r'"(/[^"]*)"', script))
        assert paths == {"/etc/sudoers.d/jen-kea-helper", "/etc/sudoers.d/jen-kea"}

    def _stub(self, monkeypatch, replies, version=4):
        calls = {"ssh": 0, "checks": 0}

        def chk(s):
            calls["checks"] += 1
            return {"ok": True, "version": version} if version else {"ok": False, "version": None}

        def legacy(s, script, timeout=30):
            calls["ssh"] += 1
            if isinstance(replies, Exception):
                raise replies
            return replies

        monkeypatch.setattr(kea_host, "check_helper", chk)
        monkeypatch.setattr(kea_host, "_legacy_python3", legacy)
        return calls

    def test_removed_rechecks_so_the_flag_flips(self, monkeypatch):
        calls = self._stub(monkeypatch, ("ok:removed", "", 0))
        res = kea_host.remove_legacy_grant(SERVER)
        assert res == {"ok": True, "code": "removed", "detail": ""}
        assert calls["checks"] == 2  # the gate, then the re-check

    def test_absent_is_ok(self, monkeypatch):
        self._stub(monkeypatch, ("ok:absent", "", 0))
        assert kea_host.remove_legacy_grant(SERVER)["code"] == "absent"

    def test_refused_carries_the_reason(self, monkeypatch):
        self._stub(monkeypatch, ("refused:visudo rejected /etc/sudoers.d/jen-kea-helper", "", 1))
        res = kea_host.remove_legacy_grant(SERVER)
        assert res["ok"] is False and res["code"] == "refused" and "visudo rejected" in res["detail"]

    def test_stale_ok_token_with_nonzero_rc_is_not_success(self, monkeypatch):
        self._stub(monkeypatch, ("ok:removed", "sudo died", 1))
        res = kea_host.remove_legacy_grant(SERVER)
        assert res["ok"] is False and res["code"] == "error"

    def test_ssh_failure_is_an_error_not_a_raise(self, monkeypatch):
        self._stub(monkeypatch, OSError("connection reset"))
        res = kea_host.remove_legacy_grant(SERVER)
        assert res["ok"] is False and res["code"] == "error" and "connection reset" in res["detail"]

    def test_no_helper_never_touches_ssh(self, monkeypatch):
        calls = self._stub(monkeypatch, ("ok:removed", "", 0), version=None)
        res = kea_host.remove_legacy_grant(SERVER)
        assert res["ok"] is False and res["code"] == "no-helper"
        assert calls["ssh"] == 0


class TestEffectiveSshUser:
    """v5.65.13 (Q102) - one derivation, used everywhere the SSH user is needed."""

    def test_explicit_user_wins(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_USER", "global-default")
        assert kea_host.effective_ssh_user({"ssh_user": "kea"}) == "kea"

    def test_empty_string_falls_through_to_the_global_default(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_USER", "global-default")
        # config.py always sets the key, defaulting it to "" when unset - the bug this fixed.
        assert kea_host.effective_ssh_user({"ssh_user": ""}) == "global-default"

    def test_missing_key_falls_through_too(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_USER", "global-default")
        assert kea_host.effective_ssh_user({}) == "global-default"


class TestSudoLSummary:
    """v5.65.13 (Q102) - pure text-munging over a full `sudo -n -l` listing."""

    def test_no_python3_rule_at_all(self):
        assert kea_host._sudo_l_summary("User kea may run the following commands:\n    (root) ALL") == ""

    def test_empty_listing(self):
        assert kea_host._sudo_l_summary("") == ""

    def test_python3_rule_with_no_later_blanket(self):
        listing = (
            "Matching Defaults entries for kea on kea-a:\n"
            "    requiretty\n"
            "User kea may run the following commands on kea-a:\n"
            "    (root) NOPASSWD: /usr/bin/python3\n"
        )
        summary = kea_host._sudo_l_summary(listing)
        assert "python3 rule(s) on this host" in summary
        assert "NOPASSWD: /usr/bin/python3" in summary
        assert "LATER rule" not in summary

    def test_python3_rule_with_a_later_blanket_that_may_override_it(self):
        listing = (
            "User kea may run the following commands on kea-a:\n    (root) NOPASSWD: /usr/bin/python3\n    (root) ALL\n"
        )
        summary = kea_host._sudo_l_summary(listing)
        assert "NOPASSWD: /usr/bin/python3" in summary
        assert "LATER rule may override it" in summary
        assert "(root) ALL" in summary

    def test_a_later_nopasswd_all_is_not_treated_as_the_overriding_blanket(self):
        # NOPASSWD ALL doesn't take the python3 grant's usability away - only a later
        # rule that would demand a password is the "may override it" case.
        listing = (
            "User kea may run the following commands on kea-a:\n"
            "    (root) NOPASSWD: /usr/bin/python3\n"
            "    (root) NOPASSWD: ALL\n"
        )
        summary = kea_host._sudo_l_summary(listing)
        assert "LATER rule" not in summary


class TestLegacyGrantStatus:
    """v5.65.13 (Q102) - sudo's own first stderr line, not just a boolean; plus a second
    `sudo -n -l` probe (never `-l <cmd>` - see the function's own docstring for why) on failure."""

    def test_ok_grant_is_a_single_probe(self, monkeypatch):
        made = _connect_seq(monkeypatch, [("1", "", 0)])
        res = kea_host.legacy_grant_status(SERVER)
        assert res == {"ok": True, "rc": 0, "reason": "", "user_at_host": "kea@10.0.0.5", "summary": ""}
        assert len(made) == 1  # no follow-up `sudo -n -l` when the grant already works
        assert made[0].calls == ["sudo -n /usr/bin/python3 -c 'print(1)'"]

    def test_password_required_surfaces_sudos_reason_and_a_summary(self, monkeypatch, caplog):
        listing = (
            "User kea may run the following commands on kea-a:\n    (root) NOPASSWD: /usr/bin/python3\n    (root) ALL\n"
        )
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required", 1)],
            [(listing, "", 0)],
        )
        with caplog.at_level("WARNING"):
            res = kea_host.legacy_grant_status(SERVER)
        assert res["ok"] is False
        assert res["rc"] == 1
        assert res["reason"] == "sudo: a password is required"
        assert res["user_at_host"] == "kea@10.0.0.5"
        assert "may override it" in res["summary"]
        assert "kea@10.0.0.5" in caplog.text

    def test_tty_refusal_is_surfaced_verbatim(self, monkeypatch):
        _connect_seq(
            monkeypatch,
            [("", "sudo: sorry, you must have a tty to run sudo", 1)],
            [("", "", 0)],
        )
        res = kea_host.legacy_grant_status(SERVER)
        assert res["ok"] is False
        assert res["reason"] == "sudo: sorry, you must have a tty to run sudo"

    def test_no_python3_rule_gives_an_empty_summary(self, monkeypatch):
        _connect_seq(
            monkeypatch,
            [("", "sudo: a password is required", 1)],
            [("User kea may run the following commands on kea-a:\n    (root) NOPASSWD: ALL\n", "", 0)],
        )
        res = kea_host.legacy_grant_status(SERVER)
        assert res["summary"] == ""

    def test_the_follow_up_listing_failing_does_not_hide_the_original_reason(self, monkeypatch):
        calls = {"n": 0}

        def connect(_server):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeSSHClient([("", "sudo: a password is required", 1)])
            raise OSError("connection reset")

        monkeypatch.setattr(getattr(kea_host, "__kea6"), "_connect_ssh", connect)
        res = kea_host.legacy_grant_status(SERVER)
        assert res["ok"] is False
        assert res["reason"] == "sudo: a password is required"
        assert res["summary"] == ""

    def test_transport_exception_is_surfaced_as_the_reason(self, monkeypatch):
        def raise_connect(_server):
            raise OSError("Unable to connect to port 22")

        monkeypatch.setattr(getattr(kea_host, "__kea6"), "_connect_ssh", raise_connect)
        res = kea_host.legacy_grant_status(SERVER)
        assert res["ok"] is False
        assert res["rc"] == -1
        assert "Unable to connect to port 22" in res["reason"]
        assert res["user_at_host"] == "kea@10.0.0.5"
        assert res["summary"] == ""

    def test_names_the_actual_effective_user_not_just_the_configured_one(self, monkeypatch):
        _connect_seq(monkeypatch, [("1", "", 0)])
        server = dict(SERVER, ssh_user="")
        monkeypatch.setattr("jen.extensions.KEA_SSH_USER", "global-default")
        res = kea_host.legacy_grant_status(server)
        assert res["user_at_host"] == "global-default@10.0.0.5"


class TestTailLogHelperOnly:
    """v5.49.0-beta.6 (Q56-6) - Trace never falls back to the legacy `sudo tail`."""

    def test_missing_helper_is_refused_without_the_legacy_path(self, monkeypatch):
        def missing(*a, **k):
            raise kea_host.HelperMissing("no helper")

        def never(*a, **k):
            raise AssertionError("the legacy engine must not run")

        monkeypatch.setattr(kea_host, "helper_call", missing)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda s: None)
        monkeypatch.setattr(kea_host, "_legacy_ssh", never)
        res = kea_host.tail_log({"id": 1}, "/var/log/kea/x.log", 1000, timeout=15, helper_only=True)
        assert res["ok"] is False and res["code"] == "no-helper"

    def test_the_default_still_falls_back_for_the_ddns_log_tab(self, monkeypatch):
        def missing(*a, **k):
            raise kea_host.HelperMissing("no helper")

        monkeypatch.setattr(kea_host, "helper_call", missing)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda s: None)
        monkeypatch.setattr(kea_host, "_legacy_ssh", lambda s, cmd, timeout=30: ("l1\nl2", "", 0))
        res = kea_host.tail_log({"id": 1}, "/var/log/kea/x.log", 200)
        assert res["ok"] is True and res["via"] == "legacy"


# ── v5.67.0-beta.8 (Q120, item a) — an SSH connect that fails is a handled failure ────────────
#
# Against a REAL local SSH server (paramiko's own, on an ephemeral port, refusing every key) and a
# closed port, through the real kea6._connect_ssh() — CLAUDE.md "Probe, redirect and TLS behavior is
# tested against real local servers". The only seam is paramiko's connect() being pointed at the
# ephemeral port, because Jen always dials 22.


class _RefuseEveryKey:
    """A paramiko ServerInterface that offers publickey and refuses every key — the state of a
    Kea host whose authorized_keys does not yet hold Jen's key (the normal first try)."""

    @staticmethod
    def build():
        import paramiko

        class Refuse(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "publickey"

            def check_auth_publickey(self, username, key):
                return paramiko.AUTH_FAILED

            def check_auth_password(self, username, password):
                return paramiko.AUTH_FAILED

        return Refuse()


@pytest.fixture(scope="module")
def _rsa_key():
    paramiko = pytest.importorskip("paramiko")
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def local_ssh(monkeypatch, tmp_path, _rsa_key):
    """Point the real _connect_ssh() at (a) a paramiko server that refuses every key, or (b) a
    closed port. Returns a small controller: `.refuse()` / `.closed()`."""
    import socket
    import threading

    import paramiko

    from jen import extensions

    key_path = tmp_path / "jen_rsa"
    _rsa_key.write_private_key_file(str(key_path))
    monkeypatch.setattr(extensions, "SSH_KEY_PATH", str(key_path))
    monkeypatch.setattr(extensions, "SSH_KNOWN_HOSTS", str(tmp_path / "known_hosts"))

    state = {"port": None, "stop": threading.Event(), "sock": None, "threads": []}
    real_connect = paramiko.SSHClient.connect

    def connect_to_local(self, hostname, *args, **kwargs):
        kwargs["port"] = state["port"]
        return real_connect(self, "127.0.0.1", *args, **kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect_to_local)

    class Controller:
        def refuse(self):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sock.listen(5)
            sock.settimeout(0.2)
            state["sock"], state["port"] = sock, sock.getsockname()[1]

            def one(client):
                transport = paramiko.Transport(client)
                transport.add_server_key(_rsa_key)
                try:
                    transport.start_server(server=_RefuseEveryKey.build())
                    transport.join(timeout=10)
                except Exception:
                    pass
                finally:
                    transport.close()

            def serve():
                while not state["stop"].is_set():
                    try:
                        client, _addr = sock.accept()
                    except OSError:
                        continue
                    t = threading.Thread(target=one, args=(client,), daemon=True)
                    t.start()
                    state["threads"].append(t)

            threading.Thread(target=serve, daemon=True).start()

        def closed(self):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            state["port"] = sock.getsockname()[1]
            sock.close()

    yield Controller()
    state["stop"].set()
    if state["sock"] is not None:
        state["sock"].close()


class TestAnSshConnectFailureIsAHandledFailure:
    def test_helper_call_names_who_and_where_and_why(self, local_ssh):
        local_ssh.refuse()
        with pytest.raises(kea_host.HelperUnreachable) as exc:
            kea_host.helper_call(SERVER, "version", {})
        msg = str(exc.value)
        assert "SSH to kea@10.0.0.5 failed" in msg
        # paramiko reports a refused key as whichever of its key-type attempts failed last, so the
        # exception's own name varies; the hint is what carries the meaning
        assert "SSHException" in msg or "AuthenticationException" in msg
        assert "authorized_keys" in msg
        assert isinstance(exc.value, kea_host.HelperError)

    def test_a_closed_port_is_the_same_kind_of_failure(self, local_ssh):
        local_ssh.closed()
        with pytest.raises(kea_host.HelperUnreachable) as exc:
            kea_host.helper_call(SERVER, "version", {})
        assert "SSH to kea@10.0.0.5 failed" in str(exc.value)
        assert "authorized_keys" not in str(exc.value)

    def test_read_config_versioned_returns_nothing_instead_of_raising(self, local_ssh, quiet_status):
        local_ssh.refuse()
        assert kea_host.read_config_versioned(SERVER, "dhcp4") == (None, None)
        assert kea_host.read_config(SERVER, "dhcp4") is None

    def test_read_config_explains_why_when_asked(self, local_ssh, quiet_status):
        local_ssh.refuse()
        why = []
        assert kea_host.read_config_versioned(SERVER, "dhcp4", errors=why) == (None, None)
        assert len(why) == 1 and why[0].startswith("SSH to kea@10.0.0.5 failed")

    def test_check_helper_says_unreachable_and_does_not_claim_the_helper_is_absent(self, local_ssh, monkeypatch):
        local_ssh.refuse()
        recorded = []
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: recorded.append(a))
        res = kea_host.check_helper(SERVER)
        assert res["ok"] is False and res["code"] == "unreachable"
        assert "SSH to kea@10.0.0.5 failed" in res["detail"]
        assert recorded == [], "a host Jen never reached must not be recorded as having no helper"

    def test_install_helper_reports_the_connection_not_the_sudo_grant(self, local_ssh, monkeypatch):
        local_ssh.refuse()
        monkeypatch.setattr(kea_host, "_helper_source", lambda: "HELPER_VERSION = 7\nHELPER_BUILD = 9\n")
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        res = kea_host.install_helper(SERVER)
        assert res["ok"] is False and res["code"] == "unreachable"
        assert "SSH to kea@10.0.0.5 failed" in res["detail"]
        assert "legacy" not in res["detail"]

    def test_no_ssh_host_is_refused_before_paramiko_is_asked_to_connect(self, monkeypatch):
        def never(server):
            raise AssertionError("an empty host resolves to this very machine — never dial it")

        monkeypatch.setattr(getattr(kea_host, "__kea6"), "_connect_ssh", never)
        for host in ("", "   ", None):
            with pytest.raises(kea_host.HelperUnreachable) as exc:
                kea_host.helper_call({"id": 1, "name": "kea-a", "ssh_host": host}, "version", {})
            assert "no SSH host configured" in str(exc.value)

    def test_every_caller_that_catches_helper_error_now_catches_this_too(self):
        assert issubclass(kea_host.HelperUnreachable, kea_host.HelperError)
        assert not issubclass(kea_host.HelperUnreachable, kea_host.HelperMissing)


class TestMissingBinaryTellsTheRealReason:
    """v5.68.0-beta.6 (Q141) - build 10 says WHY it will not run a Kea binary that is there; an older build says only "missingbinary",
    which on a Kea from ISC's packages (daemon binary owned by its service account) is a binary that IS installed."""

    def test_a_reason_from_the_helper_reaches_the_result(self, monkeypatch, quiet_status):
        resp = {
            "ok": False,
            "error": "missingbinary",
            "binary": "kea-dhcp4",
            "detail": "is owned by alice, not the daemon's user",
        }
        _connect_seq(monkeypatch, [(json.dumps(resp), "")])
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["code"] == "missingbinary" and res["reason"] == "is owned by alice, not the daemon's user"
        assert res["detail"] == res["reason"] and "old_helper_build" not in res

    def test_no_reason_from_a_build_7_helper_says_so(self, monkeypatch, quiet_status):
        resp = {"ok": False, "error": "missingbinary", "binary": "kea-dhcp4", "helper_version": 7, "helper_build": 7}
        _connect_seq(monkeypatch, [(json.dumps(resp), "")])
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert res["reason"] == "" and res["old_helper_build"] == 7 and res["detail"] == "kea-dhcp4"

    def test_a_build_10_helper_that_found_nothing_is_just_not_installed(self, monkeypatch, quiet_status):
        resp = {"ok": False, "error": "missingbinary", "binary": "kea-dhcp4", "helper_version": 7, "helper_build": 10}
        _connect_seq(monkeypatch, [(json.dumps(resp), "")])
        res = kea_host.apply_config(SERVER, "dhcp4", {"Dhcp4": {}})
        assert "old_helper_build" not in res and res["reason"] == ""

    def test_the_sentence_when_the_helper_refused_a_binary_it_found(self):
        text = kea_host.missing_binary_text(
            {"binary": "kea-dhcp4", "reason": "is owned by alice, not the daemon's user"}
        )
        assert text == (
            "kea-dhcp4 is present but the helper will not run it: is owned by alice, not the daemon's user \u2014 "
            "update the helper (build 10 or later) / fix the ownership"
        )

    def test_the_sentence_when_nothing_was_found(self):
        assert kea_host.missing_binary_text({"binary": "kea-dhcp4"}) == "kea-dhcp4 is not installed on this server"
        assert kea_host.missing_binary_text({"binary": "kea-dhcp4"}, advice=True).endswith(
            "\u2014 install it and try again"
        )

    def test_the_sentence_from_an_old_helper_names_the_caveat(self):
        text = kea_host.missing_binary_text({"binary": "kea-dhcp4", "old_helper_build": 7})
        assert "not installed on this server" in text and "ISC's packages" in text and "build 7" in text
        assert "update the helper from Settings" in text

    def test_the_page_line_carries_the_reason(self):
        from jen.services import kea_changeset

        res = {"code": "missingbinary", "binary": "kea-dhcp4", "reason": "is owned by alice, not the daemon's user"}
        line = kea_changeset._failure_line("kea-a", res, "Kea")
        assert line.startswith("\u274c kea-a: kea-dhcp4 is present but the helper will not run it: is owned by alice")
        assert "not installed" not in line and line.endswith("fix the ownership.")

    def test_the_page_line_is_the_old_one_when_the_helper_found_nothing(self):
        from jen.services import kea_changeset

        line = kea_changeset._failure_line("kea-a", {"code": "missingbinary", "binary": "kea-dhcp4"}, "Kea")
        assert line == "\u274c kea-a: kea-dhcp4 is not installed on this server \u2014 install it and try again."

    def test_the_shipped_build_is_the_files(self):
        import re

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper").read_text(encoding="utf-8")
        assert int(re.search(r"^HELPER_BUILD = (\d+)$", src, re.M).group(1)) == kea_host.JEN_HELPER_SHIPPED_BUILD == 17
