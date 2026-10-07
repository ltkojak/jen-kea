"""
tests/test_kea_helper.py
────────────────────────
v5.11.0 — jen-kea-helper, the fixed-function root helper that replaces
the `sudo python3` config-push path on Kea hosts. Loaded via importlib
against its repo-root file path, exactly like test_jen_update_root.py
(a hyphenated filename isn't a valid module name).

Pure / tmp-dir tests only — no SSH, no real Kea. The `kea-dhcpX -t`
tests stub the binary with a tiny script on a temp PATH and are skipped
on Windows.
"""

import base64
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from importlib.machinery import SourceFileLoader

import pytest

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"
_UPDATE_ROOT_PATH = pathlib.Path(__file__).resolve().parent.parent / "jen-update-root.py"


def _load():
    # No .py suffix (it installs as /usr/local/sbin/jen-kea-helper), so
    # spec_from_file_location can't infer a loader — name one explicitly.
    loader = SourceFileLoader("jen_kea_helper", str(_SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def helper():
    if not _SCRIPT_PATH.exists():
        pytest.skip("jen-kea-helper not found at expected repo-root path")
    return _load()


def _run(helper, op, payload, keep_version=False):
    """Invoke main() with a captured stdin/stdout/stderr. Returns
    (exit_code, parsed_stdout_json, stderr_text). v2 stamps `helper_version`
    (v7, Q104: `helper_build` too) on every response; both are popped from
    the parsed dict unless keep_version=True so the many `out == {...}`
    assertions below don't all have to spell them out.
    TestHelperVersionEnvelope checks they're always present. v5.66.0-beta.2
    (Q104) — no longer touches $PATH: every binary this helper runs is
    resolved through _BIN_DIRS, never $PATH — see _fake_kea_bin below for
    how a test supplies a stub binary now."""
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = helper.main(argv=["jen-kea-helper", op], stdin=stdin, stdout=stdout, stderr=stderr)
    out = stdout.getvalue().strip()
    parsed = json.loads(out) if out else None
    if isinstance(parsed, dict) and not keep_version:
        parsed.pop("helper_version", None)
        parsed.pop("helper_build", None)
    return code, parsed, stderr.getvalue()


def _leftover_temps(directory):
    """Names of helper temp files left in `directory` (build 13: `.<name>.<16 hex>.jen_tmp`) - none must survive an op."""
    return sorted(n for n in os.listdir(directory) if n.endswith(".jen_tmp"))


class TestShape:
    def test_exists_at_repo_root(self):
        assert _SCRIPT_PATH.exists()

    def test_is_valid_python(self):
        import ast

        ast.parse(_SCRIPT_PATH.read_text(encoding="utf-8"))

    def test_no_bare_self_update_op(self, helper):
        # v5.66.0 (Q103) — there IS an "update" op now (TestUpdateOp below), but
        # never a "self-update"/"self_update" name: the whole point is that it
        # only ever installs a release-key-SIGNED, strictly newer candidate —
        # never "whatever Jen sends".
        assert "self-update" not in helper._OPS
        assert "self_update" not in helper._OPS

    def test_shebang_is_isolated_mode(self):
        # v5.66.0-beta.2 (Q104) — the kernel resolves this via sudo's own PATH; isolated mode
        # means no PYTHON* env vars and no script-directory sys.path entry once it's running.
        first_line = _SCRIPT_PATH.read_text(encoding="utf-8").splitlines()[0]
        assert first_line == "#!/usr/bin/python3 -I"


class TestD2Support:
    """v5.23.0 (Q19) — "d2" (kea-dhcp-ddns) joins dhcp4/dhcp6 as a valid
    service everywhere one is accepted."""

    def test_d2_is_a_valid_service(self, helper):
        assert helper._valid_service("d2") is True

    def test_d2_binary_name(self, helper):
        assert helper._SERVICE_BINARY["d2"] == "kea-dhcp-ddns"

    def test_d2_unit_family_is_dhcp_ddns_not_d2(self, helper):
        assert helper._SERVICE_UNIT_FAM["d2"] == "dhcp-ddns"

    def test_read_config_accepts_d2_service(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp-ddns.conf"
        p.write_text('{"DhcpDdns": {}}')
        code, out, _ = _run(helper, "read-config", {"service": "d2", "path": str(p)})
        assert out["ok"] is True and out["config"] == {"DhcpDdns": {}}

    def test_install_package_uses_the_dhcp_ddns_server_package(self, helper, monkeypatch):
        calls = []

        class Proc:
            returncode, stdout, stderr = 0, "installed ok\n", ""

        def fake_run(argv, **kw):
            calls.append(argv)
            return Proc()

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "install-package", {"service": "d2"})
        assert out["ok"] is True
        assert calls[1] == ["apt-get", "install", "-y", "kea-dhcp-ddns-server"]


class TestProtocolMisuse:
    def test_unknown_op_exits_2_with_json(self, helper):
        code, out, _ = _run(helper, "frobnicate", {})
        assert code == 2
        assert out == {"ok": False, "error": "unknown-op"}

    def test_bad_json_exits_2(self, helper):
        stdin = io.StringIO("{not json")
        stdout, stderr = io.StringIO(), io.StringIO()
        code = helper.main(argv=["jen-kea-helper", "version"], stdin=stdin, stdout=stdout, stderr=stderr)
        assert code == 2
        assert json.loads(stdout.getvalue())["ok"] is False

    def test_oversize_stdin_exits_2(self, helper):
        stdin = io.StringIO("x" * (helper.MAX_STDIN + 10))
        stdout, stderr = io.StringIO(), io.StringIO()
        code = helper.main(argv=["jen-kea-helper", "version"], stdin=stdin, stdout=stdout, stderr=stderr)
        assert code == 2
        assert json.loads(stdout.getvalue()) == {
            "ok": False,
            "error": "stdin-too-large",
            "helper_version": helper.HELPER_VERSION,
            "helper_build": helper.HELPER_BUILD,
        }

    def test_stdout_is_exactly_one_json_document(self, helper):
        _, _, _ = _run(helper, "version", {})
        stdin = io.StringIO("{}")
        stdout = io.StringIO()
        helper.main(argv=["jen-kea-helper", "version"], stdin=stdin, stdout=stdout, stderr=io.StringIO())
        text = stdout.getvalue()
        assert text.count("\n") == 1
        json.loads(text)  # parses whole

    def test_empty_stdin_is_treated_as_empty_object(self, helper):
        stdin = io.StringIO("")
        stdout = io.StringIO()
        code = helper.main(argv=["jen-kea-helper", "version"], stdin=stdin, stdout=stdout, stderr=io.StringIO())
        assert code == 0
        assert json.loads(stdout.getvalue())["ok"] is True


class TestVersion:
    def test_version(self, helper):
        code, out, err = _run(helper, "version", {}, keep_version=True)
        assert code == 0
        assert out["ok"] is True
        assert out["helper_version"] == helper.HELPER_VERSION == 7
        assert out["helper_build"] == helper.HELPER_BUILD == 13
        assert out["python"].count(".") == 2
        assert err.startswith("jen-kea-helper: version ok")


class TestBuildBumpReminder:
    """v5.66.0-beta.2 (Q104) — tests/kea_helper_build.json pins {"build": N, "sha256": <hash
    of jen-kea-helper at that build>}. A change to the file that does NOT also bump
    HELPER_BUILD past the pinned value fails here — updating the pin (both the hash and the
    build number) is how a change acknowledges it bumped the build, the same discipline
    RELEASE_SIGNERS twins enforce for the signing key elsewhere in this suite."""

    def test_file_hash_matches_the_pin_or_the_build_was_bumped_past_it(self, helper):
        import hashlib

        pin_path = pathlib.Path(__file__).resolve().parent / "kea_helper_build.json"
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        actual_sha = hashlib.sha256(_SCRIPT_PATH.read_bytes()).hexdigest()
        if actual_sha == pin["sha256"]:
            assert pin["build"] == helper.HELPER_BUILD, (
                f"jen-kea-helper is byte-identical to the pinned build ({pin['build']}) but "
                f"HELPER_BUILD reads {helper.HELPER_BUILD} — the two must never disagree"
            )
            return
        assert pin["build"] < helper.HELPER_BUILD, (
            f"jen-kea-helper changed (sha256 {actual_sha} != pinned {pin['sha256']}) but "
            f"HELPER_BUILD ({helper.HELPER_BUILD}) was not bumped past the pinned build "
            f"({pin['build']}) — bump HELPER_BUILD and update tests/kea_helper_build.json"
        )


class TestHelperVersionEnvelope:
    """v2 (v5.16.0) — every response, including protocol-error responses,
    carries helper_version so Jen learns the real number from any op.
    Bumped to 3 in v5.23.0 (Q19, d2 support), to 4 in v5.29.0 (Q29,
    install-tls), to 5 in v5.49.0 (bounded tail-log), to 6 in v5.66.0
    (Q103, signed `update`), to 7 in v5.66.0-beta.2 (Q104, PATH
    hardening + preflight/rollback) — which also adds `helper_build` to
    every envelope alongside `helper_version`."""

    @pytest.mark.parametrize(
        "op,payload",
        [
            ("version", {}),
            ("read-config", {"service": "dhcp4", "path": "/tmp/evil.conf"}),
            ("nonsense-op", {}),
            ("tail-log", {"path": "/etc/passwd"}),
            ("install-tls", {"service": "dhcp4", "files": {}}),
            ("remove-config", {"service": "dhcp4", "path": "/tmp/evil.conf"}),
            ("update", {}),
        ],
    )
    def test_every_response_carries_helper_version_and_build(self, helper, op, payload):
        _code, out, _err = _run(helper, op, payload, keep_version=True)
        assert out["helper_version"] == helper.HELPER_VERSION == 7
        assert out["helper_build"] == helper.HELPER_BUILD


class TestPathWalls:
    @pytest.mark.parametrize(
        "p",
        [
            "/etc/kea/../passwd",
            "/etc/kea/x.conf/",
            "/tmp/x.conf",
            "/etc/kea/kea dhcp4.conf",
            "/var/log/../etc/shadow",
            "relative.conf",
            "/etc/kea/kea-dhcp4.txt",
        ],
    )
    def test_conf_path_rejected(self, helper, p):
        assert helper._allowed_conf_path(p) is False

    @pytest.mark.parametrize(
        "p",
        [
            "/etc/kea/kea-dhcp4.conf",
            "/etc/kea/kea-dhcp6.conf",
            "/usr/local/etc/kea/kea-dhcp6.conf",
            "/etc/kea/kea-dhcp-ddns.conf",
            "/usr/local/etc/kea/kea-dhcp-ddns.conf",
        ],
    )
    def test_conf_path_allowed(self, helper, p):
        assert helper._allowed_conf_path(p) is True

    @pytest.mark.parametrize("p", ["/var/log/../etc/shadow", "/var/log/kea/x.txt", "/etc/kea/x.log", "rel.log"])
    def test_log_path_rejected(self, helper, p):
        assert helper._allowed_log_path(p) is False

    @pytest.mark.parametrize("p", ["/var/log/kea/kea-ddns.log", "/var/log/syslog.log"])
    def test_log_path_allowed(self, helper, p):
        assert helper._allowed_log_path(p) is True

    def test_read_config_rejects_a_bad_path(self, helper):
        code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": "/tmp/evil.conf"})
        assert code == 0 and out == {"ok": False, "error": "not-allowed"}

    def test_read_config_rejects_a_bad_service(self, helper):
        code, out, _ = _run(helper, "read-config", {"service": "dhcp9", "path": "/etc/kea/kea-dhcp4.conf"})
        assert out == {"ok": False, "error": "not-allowed"}


class TestReadConfig:
    def test_missing_file(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = str(tmp_path / "kea-dhcp4.conf")
        code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": p})
        assert out == {"ok": False, "error": "missing"}

    def test_invalid_json(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        p.write_text("{ this is not json")
        code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": str(p)})
        assert out["ok"] is False and out["error"] == "invalid-json"

    def test_ok(self, helper, tmp_path, monkeypatch):
        import hashlib

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        raw = json.dumps({"Dhcp4": {"subnet4": [{"id": 1}]}})
        p.write_bytes(raw.encode())
        code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": str(p)})
        assert out == {
            "ok": True,
            "config": {"Dhcp4": {"subnet4": [{"id": 1}]}},
            "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }

    def test_sha256_is_of_the_raw_bytes_whitespace_included(self, helper, tmp_path, monkeypatch):
        import hashlib

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        pretty = '{\n    "Dhcp4": {}\n}\n'  # a hand-formatted file
        p.write_bytes(pretty.encode())
        _code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": str(p)})
        assert out["sha256"] == hashlib.sha256(pretty.encode()).hexdigest()


def _fake_kea_bin(helper, monkeypatch, tmp_path, name, exit_code=0, stdout="", stderr="", marker=None):
    """Write a /bin/sh stub that mimics `kea-dhcpX -t` (or any other bare-name binary this
    helper resolves through _BIN_DIRS) and put its directory FIRST in _BIN_DIRS — v5.66.0-beta.2
    (Q104): binaries are resolved through _BIN_DIRS now, never $PATH, so a test supplies one by
    monkeypatching _BIN_DIRS directly rather than $PATH. The root-ownership check is stubbed
    True for every path (the fake binaries these tests write are never really root-owned, since
    the test itself doesn't run as root). If `marker` is a path, the stub `touch`es it on every
    call — a test can assert it did or didn't run."""
    import shlex

    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    script = d / name
    lines = ["#!/bin/sh"]
    if marker:
        lines.append(f"echo x >> {shlex.quote(str(marker))}")
    if stdout:
        lines.append(f"printf %s {shlex.quote(stdout)}")
    if stderr:
        lines.append(f"printf %s {shlex.quote(stderr)} >&2")
    lines.append(f"exit {exit_code}")
    script.write_text("\n".join(lines) + "\n")
    script.chmod(0o755)
    monkeypatch.setattr(helper, "_BIN_DIRS", (str(d),) + helper._BIN_DIRS)
    monkeypatch.setattr(helper, "_bin_owner_ok", lambda path: True)
    # v5.66.0-beta.7 (Q109) — _find_bin now also checks the DIRECTORY (_bin_dir_ok), not just
    # the file; stubbed True for the same reason _bin_owner_ok is above (this tmp_path
    # directory is never really root-owned, since the test itself doesn't run as root).
    monkeypatch.setattr(helper, "_bin_dir_ok", lambda d: True)
    return str(d)


class TestBinDirOk:
    """v5.66.0-beta.7 (Q109, item c) — _find_bin() already checked that a candidate BINARY is
    root-owned and not group/other-writable (_bin_owner_ok); it never checked the DIRECTORY
    the binary sits in, so a root-owned file inside a group-writable directory (which anyone
    in that group can replace with their own file, then have root-owned metadata copied onto
    it, or simply rename a new file into place inside) passed anyway. _bin_dir_ok() closes
    that. These tests fake os.stat's return for a real tmp_path directory rather than really
    chowning it to uid 0, since the test process itself doesn't run as root."""

    class _FakeStat:
        def __init__(self, mode, uid):
            self.st_mode = mode
            self.st_uid = uid

    def _patch_stat_for(self, helper, monkeypatch, target_dir, mode, uid):
        real_stat = helper.os.stat
        target_real = os.path.realpath(str(target_dir))

        def fake_stat(path):
            if os.path.realpath(str(path)) == target_real:
                return self._FakeStat(mode, uid)
            return real_stat(path)

        monkeypatch.setattr(helper.os, "stat", fake_stat)

    def test_root_owned_non_writable_directory_passes(self, helper, monkeypatch, tmp_path):
        d = tmp_path / "sbin"
        d.mkdir()
        self._patch_stat_for(helper, monkeypatch, d, stat.S_IFDIR | 0o755, uid=0)
        assert helper._bin_dir_ok(str(d)) is True

    def test_group_writable_root_owned_directory_fails(self, helper, monkeypatch, tmp_path):
        d = tmp_path / "sbin"
        d.mkdir()
        self._patch_stat_for(helper, monkeypatch, d, stat.S_IFDIR | 0o775, uid=0)
        assert helper._bin_dir_ok(str(d)) is False

    def test_other_writable_root_owned_directory_fails(self, helper, monkeypatch, tmp_path):
        d = tmp_path / "sbin"
        d.mkdir()
        self._patch_stat_for(helper, monkeypatch, d, stat.S_IFDIR | 0o757, uid=0)
        assert helper._bin_dir_ok(str(d)) is False

    def test_non_root_owned_directory_fails_even_if_not_writable(self, helper, monkeypatch, tmp_path):
        d = tmp_path / "sbin"
        d.mkdir()
        self._patch_stat_for(helper, monkeypatch, d, stat.S_IFDIR | 0o755, uid=1000)
        assert helper._bin_dir_ok(str(d)) is False

    def test_missing_directory_fails_closed(self, helper):
        assert helper._bin_dir_ok("/does/not/exist/at/all/q109") is False

    def test_find_bin_skips_a_directory_that_fails_the_dir_check_even_when_the_file_itself_passes(
        self, helper, monkeypatch, tmp_path
    ):
        """The exact scenario this Q closes: a root-owned, non-writable binary — the kind
        _bin_owner_ok alone would happily accept — sitting inside a directory that is itself
        group-writable must never be used."""
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "systemctl").write_bytes(b"#!/bin/true\n")
        good_dir = tmp_path / "good"
        good_dir.mkdir()
        monkeypatch.setattr(helper, "_BIN_DIRS", (str(bad_dir), str(good_dir)))
        monkeypatch.setattr(helper, "_bin_owner_ok", lambda path: True)
        monkeypatch.setattr(helper, "_bin_dir_ok", lambda d: d != str(bad_dir))

        assert helper._find_bin("systemctl") is None  # bad_dir skipped; good_dir has no such file


win = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX exec stub for kea-dhcpX")


class TestNoPathTrust:
    """v5.66.0-beta.2 (Q104) — every binary this helper runs is resolved through the
    root-owned _BIN_DIRS allowlist, never $PATH. A fake binary placed FIRST on $PATH (each
    touching its own marker file if ever run) must never be reached, however plausible its
    name — _BIN_DIRS is left at its real, unmodified default throughout, so the isolation
    is proved without any help from a stubbed allowlist."""

    @win
    def test_a_fake_path_binary_is_never_reached(self, helper, tmp_path, monkeypatch):
        import shlex

        evil = tmp_path / "evil-bin"
        evil.mkdir()
        markers = {}
        for name in ("python3", "ssh-keygen", "systemctl", "apt-get", "kea-dhcp4"):
            marker = tmp_path / f"{name}.touched"
            markers[name] = marker
            script = evil / name
            script.write_text(f"#!/bin/sh\necho x >> {shlex.quote(str(marker))}\nexit 0\n")
            script.chmod(0o755)
        monkeypatch.setenv("PATH", str(evil) + os.pathsep + (os.environ.get("PATH") or ""))

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = str(tmp_path / "kea-dhcp4.conf")

        _run(helper, "version", {})
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {}})
        _run(helper, "service", {"service": "dhcp4", "action": "status"})
        _run(helper, "install-package", {"service": "dhcp4"})
        _run(
            helper,
            "update",
            {"helper_b64": base64.b64encode(b"x").decode(), "signature_b64": base64.b64encode(b"y").decode()},
        )

        for name, marker in markers.items():
            assert not marker.exists(), f"the fake {name!r} placed first on $PATH was reached"


@win
class TestTestConfig:
    def _paths(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        return str(tmp_path / "kea-dhcp4.conf")

    def test_missing_binary(self, helper, tmp_path, monkeypatch):
        # no _fake_kea_bin call: _BIN_DIRS stays at its real default, and kea-dhcp4 genuinely
        # isn't there on a dev/CI box, so _find_bin("kea-dhcp4") returns None on its own.
        p = self._paths(helper, tmp_path, monkeypatch)
        code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {}})
        assert out == {"ok": False, "error": "missingbinary", "binary": "kea-dhcp4"}

    def test_d2_missing_binary_names_kea_dhcp_ddns(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = str(tmp_path / "kea-dhcp-ddns.conf")
        code, out, _ = _run(helper, "test-config", {"service": "d2", "path": p, "config": {}})
        assert out == {"ok": False, "error": "missingbinary", "binary": "kea-dhcp-ddns"}

    def test_d2_pass_runs_the_kea_dhcp_ddns_binary(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = str(tmp_path / "kea-dhcp-ddns.conf")
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp-ddns", exit_code=0)
        code, out, _ = _run(helper, "test-config", {"service": "d2", "path": p, "config": {"DhcpDdns": {}}})
        assert out == {"ok": True}

    def test_pass_and_tmp_is_removed(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True}
        assert _leftover_temps(tmp_path) == []

    def test_testerror_detail_and_tmp_removed(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        _fake_kea_bin(
            helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=1, stderr="ERROR line one\nERROR line two\ninfo\n"
        )
        code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {}})
        assert out["error"] == "testerror"
        assert out["detail"] == "ERROR line one | ERROR line two"
        assert _leftover_temps(tmp_path) == []

    def test_tlsmissing_checked_before_the_binary_runs(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        code, out, _ = _run(
            helper,
            "test-config",
            {"service": "dhcp4", "path": p, "config": {}, "tls_paths": [["/nope/cert.pem", "file"]]},
        )
        assert out == {"ok": False, "error": "tlsmissing", "path": "/nope/cert.pem"}
        assert _leftover_temps(tmp_path) == []


@win
class TestRunAsTheDaemonsOwnAccount:
    """v5.68.0-beta.6 (Q141). ISC's own deb ships /usr/sbin/kea-dhcp4 as `_kea:_kea` 0750; build 7-9 required root:root of EVERY
    binary the helper runs and so answered `missingbinary` ("not installed") for a Kea that was installed - every config push through
    the helper failed on such a host. Build 10 runs `kea-dhcpX -t` as the account the daemon runs as and trusts the binary by who
    executes it: root:root for a binary run as root (unchanged), a regular file owned by exactly that SYSTEM account with no
    group/other write bit for the daemon's. The tests cannot become another user, so they fake what `lstat` and `pwd` report and
    capture the arguments of the `subprocess.run` call (the stub binary is never exec'd as another account)."""

    KEA_UID, KEA_GID = 105, 106

    def _setup(self, helper, tmp_path, monkeypatch, uid=105, mode=0o750, unit=None, root_owned=False, regular=True):
        import pwd
        import types

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        binary = os.path.join(d, "kea-dhcp4")
        # the fake binaries are never really root-owned: _fake_kea_bin stubbed _bin_owner_ok True; this class chooses
        monkeypatch.setattr(helper, "_bin_owner_ok", lambda path: root_owned)
        real_lstat = os.lstat

        def lstat(path, *a, **k):
            if str(path) == binary:
                kind = stat.S_IFREG if regular else stat.S_IFLNK
                return types.SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_gid=uid + 1)
            return real_lstat(path, *a, **k)

        monkeypatch.setattr(os, "lstat", lstat)
        accounts = {
            105: ("_kea", 106),
            300: ("othersys", 301),
            200: ("keauser", 201),
            1001: ("alice", 1001),
            0: ("root", 0),
        }

        def getpwuid(u):
            if u not in accounts:
                raise KeyError(u)
            name, gid = accounts[u]
            return types.SimpleNamespace(pw_name=name, pw_uid=u, pw_gid=gid)

        monkeypatch.setattr(pwd, "getpwuid", getpwuid)
        monkeypatch.setattr(helper, "_unit_account", lambda service: unit)
        # the helper runs as root in production and chowns the validation copy to the account that runs -t; the tests run as
        # whoever the CI runner is, so the call is recorded instead of made
        self.chowns = []
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: self.chowns.append((uid, gid)))
        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw))
            seen = {}
            if os.path.exists(cmd[-1]):
                seen["mode"] = stat.S_IMODE(os.stat(cmd[-1]).st_mode)
            calls[-1] = (cmd, {**kw, "_seen": seen})
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        return str(tmp_path / "kea-dhcp4.conf"), binary, calls

    def test_a_binary_owned_by_a_system_account_is_run_as_that_account(self, helper, tmp_path, monkeypatch):
        p, binary, calls = self._setup(helper, tmp_path, monkeypatch)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True}
        ((cmd, kw),) = calls
        assert cmd[:2] == [binary, "-t"]
        assert os.path.dirname(cmd[2]) == os.path.dirname(p) and re.fullmatch(
            r"\.kea-dhcp4\.conf\.[0-9a-f]{16}\.jen_tmp", os.path.basename(cmd[2])
        ), "a unique name in the config's own directory, never the fixed `<conf>.jen_tmp` two helpers would share"
        assert (kw["user"], kw["group"], kw["extra_groups"]) == (105, 106, []), (
            "the daemon's own account, no supplementary groups"
        )
        assert kw["env"]["HOME"] == "/" and kw["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"

    def test_apply_config_goes_through_the_same_run(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch)
        _code, out, _ = _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["ok"] is True and calls[0][1]["user"] == 105

    def test_a_root_root_binary_is_run_as_root_exactly_as_before(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=0, mode=0o755, root_owned=True)
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        ((_cmd, kw),) = calls
        assert "user" not in kw and "group" not in kw and "extra_groups" not in kw

    def test_a_binary_owned_by_an_ordinary_user_is_refused_with_the_reason(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=1001)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {
            "ok": False,
            "error": "missingbinary",
            "binary": "kea-dhcp4",
            "detail": "is owned by alice, not a system account and not the daemon's user",
        }
        assert calls == [], "the binary was never run"

    def test_a_group_writable_binary_is_refused_even_when_a_system_account_owns_it(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, mode=0o770)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["error"] == "missingbinary" and out["detail"] == "is writable by its group or by everyone"
        assert calls == []

    def test_a_world_writable_binary_is_refused(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, mode=0o757)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["detail"] == "is writable by its group or by everyone" and calls == []

    def test_a_symlink_is_refused(self, helper, tmp_path, monkeypatch):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, regular=False)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["detail"] == "is not a regular file" and calls == []

    def test_a_root_owned_binary_that_is_not_root_root_is_not_run_as_root_or_as_anyone(
        self, helper, tmp_path, monkeypatch
    ):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=0, mode=0o755)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["error"] == "missingbinary" and "root but not root:root" in out["detail"] and calls == []

    def test_the_units_user_is_the_account_it_runs_as(self, helper, tmp_path, monkeypatch):
        unit = {"name": "keauser", "uid": 200, "gid": 201, "extra_groups": []}
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=200, unit=unit)
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert (calls[0][1]["user"], calls[0][1]["group"]) == (200, 201)

    def test_a_binary_owned_by_a_different_system_account_than_the_units_user_is_refused(
        self, helper, tmp_path, monkeypatch
    ):
        unit = {"name": "keauser", "uid": 200, "gid": 201, "extra_groups": []}
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=300, unit=unit)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["detail"] == "is owned by othersys, not the daemon's user keauser" and calls == []

    def test_a_nonexistent_binary_has_no_detail(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        monkeypatch.setattr(helper, "_BIN_DIRS", (str(tmp_path / "empty"),))
        monkeypatch.setattr(helper, "_bin_dir_ok", lambda d: True)
        (tmp_path / "empty").mkdir()
        _code, out, _ = _run(
            helper, "test-config", {"service": "dhcp4", "path": str(tmp_path / "kea-dhcp4.conf"), "config": {}}
        )
        assert out == {"ok": False, "error": "missingbinary", "binary": "kea-dhcp4"}

    @pytest.mark.parametrize("umask", [0o077, 0o022, 0o000])
    def test_the_validation_copy_is_root_owned_0640_readable_not_writable_by_the_daemons_group(
        self, helper, tmp_path, monkeypatch, umask
    ):
        """v5.68.0-beta.13 (Q148) made the copy the daemon account's own 0600; Q150 (build 13) takes the ownership back: it is
        `root:<the daemon's effective gid>` 0640 - READABLE by the account that runs `-t` (through its group), not WRITABLE by it, so that
        account cannot change the config between its write and its validation. It is created 0600 and only becomes 0640 once complete."""
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch)
        old = os.umask(umask)
        try:
            _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        finally:
            os.umask(old)
        assert calls[0][1]["_seen"]["mode"] == 0o640, (
            "group-readable for the account that runs -t, writable by nobody but root"
        )
        assert self.chowns == [(0, self.KEA_GID)], "owned by ROOT, group = the daemon's effective gid (never its uid)"
        assert (calls[0][1]["user"], calls[0][1]["group"]) == (self.KEA_UID, self.KEA_GID)
        assert _leftover_temps(tmp_path) == []

    @pytest.mark.parametrize("umask", [0o077, 0o022])
    def test_the_validation_copy_is_root_0600_when_it_runs_as_root(self, helper, tmp_path, monkeypatch, umask):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=0, mode=0o755, root_owned=True)
        old = os.umask(umask)
        try:
            _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        finally:
            os.umask(old)
        assert calls[0][1]["_seen"]["mode"] == 0o600
        assert self.chowns == [], "run as root: the file stays root's own (nobody needs to chown it)"
        assert "user" not in calls[0][1]
        assert _leftover_temps(tmp_path) == []

    def test_a_planted_file_or_symlink_at_the_old_fixed_name_is_never_used_or_followed(
        self, helper, tmp_path, monkeypatch
    ):
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch)
        stale = pathlib.Path(p + ".jen_tmp")
        stale.write_text("old credentials")
        os.chmod(stale, 0o666)
        victim = tmp_path / "victim"
        victim.write_text("keep")
        os.symlink(victim, tmp_path / ".kea-dhcp4.conf.jen_tmp")
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert calls[0][1]["_seen"]["mode"] == 0o640, "a new O_EXCL file, not the planted one"
        assert stale.read_text() == "old credentials" and victim.read_text() == "keep"

    def test_the_daemon_owned_binary_needs_its_owner_execute_bit(self, helper, tmp_path, monkeypatch):
        """Build 13 (Q150): `os.access(X_OK)` is ROOT's answer - true when ANY class may execute - so a `_kea`-owned file with o+x and no
        u+x passed and then failed to exec as `_kea`. Refused before exec, with the reason."""
        p, _binary, calls = self._setup(helper, tmp_path, monkeypatch, mode=0o605)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {
            "ok": False,
            "error": "missingbinary",
            "binary": "kea-dhcp4",
            "detail": "is owned by a system account that has no execute permission on it",
        }
        assert calls == [], "never exec'd"

    def test_a_root_owned_binary_run_as_root_needs_its_owner_execute_bit_too(self, helper, tmp_path, monkeypatch):
        p, binary, calls = self._setup(helper, tmp_path, monkeypatch, uid=0, mode=0o755, root_owned=True)
        os.chmod(
            binary, 0o655
        )  # r-x for group and other, nothing for the owner: root could exec it, by a bit it is not using
        monkeypatch.setattr(helper.os, "access", lambda path, mode: True)
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["error"] == "missingbinary" and "no owner execute permission" in out["detail"] and calls == []

    def test_the_clean_environment_has_a_home(self, helper):
        assert helper._CLEAN_ENV == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/"}

    def test_only_a_system_account_counts(self, helper, monkeypatch, tmp_path):
        import types

        f = tmp_path / "bin"
        f.write_text("x")
        for uid, expect in ((105, True), (999, True), (1000, False), (0, False)):
            monkeypatch.setattr(
                os,
                "lstat",
                lambda path, uid=uid, *a, **k: types.SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o750, st_uid=uid, st_gid=uid
                ),
            )
            assert helper._daemon_bin_ok(str(f), uid) is expect, uid

    @pytest.mark.parametrize(
        "mode,expect", [(0o750, True), (0o700, True), (0o605, False), (0o055, False), (0o640, False)]
    )
    def test_the_owner_execute_bit_is_required(self, helper, monkeypatch, tmp_path, mode, expect):
        import types

        f = tmp_path / "bin"
        f.write_text("x")
        monkeypatch.setattr(
            os,
            "lstat",
            lambda path, *a, **k: types.SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=105, st_gid=106),
        )
        assert helper._daemon_bin_ok(str(f), 105) is expect, oct(mode)

    def test_unit_account_reads_the_units_user_and_ignores_root_and_unknown_accounts(self, helper, monkeypatch):
        import pwd
        import types

        monkeypatch.setattr(helper, "_resolve_unit", lambda service, action: "kea-dhcp4-server")
        kea = {"name": "_kea", "uid": 105, "gid": 106, "extra_groups": []}
        for answer, expect in (
            ("User=_kea\nGroup=\nSupplementaryGroups=\n", kea),
            ("User=root\nGroup=\nSupplementaryGroups=\n", None),
            ("User=\nGroup=\nSupplementaryGroups=\n", None),
            (
                "User=ghost\nGroup=\nSupplementaryGroups=\n",
                {"refused": "its unit runs as User=ghost, which is not an account on this host"},
            ),
        ):
            monkeypatch.setattr(
                helper, "_run_bin", lambda name, args, answer=answer, **kw: types.SimpleNamespace(stdout=answer)
            )

            def getpwnam(n):
                if n == "_kea":
                    return types.SimpleNamespace(pw_name="_kea", pw_uid=105, pw_gid=106)
                raise KeyError(n)

            monkeypatch.setattr(pwd, "getpwnam", getpwnam)
            assert helper._unit_account("dhcp4") == expect, answer
        monkeypatch.setattr(helper, "_resolve_unit", lambda service, action: None)
        assert helper._unit_account("dhcp4") is None


@win
class TestTheUnitsOwnIdentityIsWhatValidationRunsAs:
    """v5.68.0-beta.13 (Q148). A unit with `Group=` or `SupplementaryGroups=` (TLS material readable through a group) starts fine under
    systemd and used to fail Jen's `-t`, which ran as the account's primary group with no supplementary groups. `_unit_account` reads
    `User`, `Group` and `SupplementaryGroups` in ONE `systemctl show`, the gid is the unit's `Group=` when set, `extra_groups` are the
    supplementary gids, and a group the host lacks is refused with the reason - never guessed. systemctl is a stub (the system suite's
    compose nodes have no systemd - stand-in named here, per CLAUDE.md - so the harness stands in for a scenario that cannot run there)."""

    GROUPS = {"keacerts": 301, "ssl-cert": 302, "kea": 106}
    MEMBERS = []  # the account's own /etc/group memberships; a test sets it on the instance

    def _systemd(self, helper, monkeypatch, show_output):
        import grp
        import pwd
        import types

        asked = []
        monkeypatch.setattr(helper, "_resolve_unit", lambda service, action: "kea-dhcp4-server")

        def run_bin(name, args, **kw):
            asked.append((name, list(args)))
            return types.SimpleNamespace(stdout=show_output)

        monkeypatch.setattr(helper, "_run_bin", run_bin)
        kea = types.SimpleNamespace(pw_name="_kea", pw_uid=105, pw_gid=106)
        monkeypatch.setattr(pwd, "getpwnam", lambda n: kea if n == "_kea" else (_ for _ in ()).throw(KeyError(n)))
        monkeypatch.setattr(pwd, "getpwuid", lambda u: kea if u == 105 else (_ for _ in ()).throw(KeyError(u)))
        # the account's /etc/group memberships, as initgroups(3) reports them (the primary group first, like the real call)
        monkeypatch.setattr(os, "getgrouplist", lambda n, g: [g, *self.MEMBERS])

        def getgrnam(n):
            if n not in self.GROUPS:
                raise KeyError(n)
            return types.SimpleNamespace(gr_gid=self.GROUPS[n])

        monkeypatch.setattr(grp, "getgrnam", getgrnam)
        return asked

    def test_user_only_runs_as_the_account_with_its_primary_group_and_nothing_else(self, helper, monkeypatch):
        asked = self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") == {"name": "_kea", "uid": 105, "gid": 106, "extra_groups": []}
        assert asked == [
            ("systemctl", ["show", "-p", "User", "-p", "Group", "-p", "SupplementaryGroups", "kea-dhcp4-server"])
        ]

    def test_user_and_group_take_the_units_group_not_the_passwd_primary(self, helper, monkeypatch):
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=keacerts\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") == {"name": "_kea", "uid": 105, "gid": 301, "extra_groups": []}
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=4242\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4")["gid"] == 4242, "a numeric Group= is a gid"

    def test_user_and_supplementary_groups_are_all_passed_as_extra_groups(self, helper, monkeypatch):
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=keacerts ssl-cert 9001\n")
        assert helper._unit_account("dhcp4") == {
            "name": "_kea",
            "uid": 105,
            "gid": 106,
            "extra_groups": [301, 302, 9001],
        }

    def test_an_unknown_group_is_refused_with_the_reason_never_guessed(self, helper, monkeypatch):
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=keacerts nosuchgroup\n")
        out = helper._unit_account("dhcp4")
        assert out == {"refused": "its unit names the group 'nosuchgroup', which does not exist on this host"}
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=gone\nSupplementaryGroups=\n")
        assert "'gone'" in helper._unit_account("dhcp4")["refused"]

    def test_the_whole_identity_reaches_the_validator_and_an_unknown_group_never_runs_it(
        self, helper, tmp_path, monkeypatch
    ):
        import types

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        binary = os.path.join(d, "kea-dhcp4")
        monkeypatch.setattr(helper, "_bin_owner_ok", lambda path: False)
        monkeypatch.setattr(helper, "_daemon_bin_ok", lambda path, uid: True)
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
        real_lstat = os.lstat
        monkeypatch.setattr(
            os,
            "lstat",
            lambda path, *a, **k: (
                types.SimpleNamespace(st_mode=stat.S_IFREG | 0o750, st_uid=105, st_gid=106)
                if str(path) == binary
                else real_lstat(path, *a, **k)
            ),
        )
        ran = []
        monkeypatch.setattr(
            helper.subprocess,
            "run",
            lambda cmd, **kw: ran.append((cmd, kw)) or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        p = str(tmp_path / "kea-dhcp4.conf")
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=keacerts\nSupplementaryGroups=ssl-cert 9001\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True}
        ((cmd, kw),) = ran
        assert (kw["user"], kw["group"], kw["extra_groups"]) == (105, 301, [302, 9001])
        ran.clear()
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=nosuchgroup\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["error"] == "missingbinary" and "nosuchgroup" in out["detail"] and ran == []

    # ── build 12 (v5.68.0-beta.14, Q149): the unit's identity first, the binary second ──

    def test_a_numeric_user_is_an_account_too(self, helper, monkeypatch):
        self._systemd(helper, monkeypatch, "User=105\nGroup=\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") == {"name": "_kea", "uid": 105, "gid": 106, "extra_groups": []}
        self._systemd(helper, monkeypatch, "User=0\nGroup=\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") is None, "a numeric 0 is root: the unit names no unprivileged account"

    def test_an_unresolvable_user_is_a_refusal_with_the_reason_never_none(self, helper, monkeypatch):
        for who in ("ghost", "4242"):
            self._systemd(helper, monkeypatch, f"User={who}\nGroup=\nSupplementaryGroups=\n")
            assert helper._unit_account("dhcp4") == {
                "refused": f"its unit runs as User={who}, which is not an account on this host"
            }, who

    def test_the_accounts_own_group_memberships_reach_the_validator(self, helper, monkeypatch):
        self.MEMBERS = [302, 9001]  # an ordinary /etc/group line: `ssl-cert:x:302:_kea`
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") == {"name": "_kea", "uid": 105, "gid": 106, "extra_groups": [302, 9001]}

    def test_memberships_and_the_units_supplementary_groups_are_both_passed_without_duplicates(
        self, helper, monkeypatch
    ):
        self.MEMBERS = [302]
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=keacerts ssl-cert\n")
        assert helper._unit_account("dhcp4")["extra_groups"] == [302, 301], "302 once, memberships first"

    def test_a_group_of_the_unit_keeps_the_memberships_and_never_repeats_the_primary(self, helper, monkeypatch):
        self.MEMBERS = [106, 302]  # the passwd primary group is an ordinary membership once Group= replaces it
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=keacerts\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4") == {"name": "_kea", "uid": 105, "gid": 301, "extra_groups": [106, 302]}
        self.MEMBERS = [301]
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=keacerts\nSupplementaryGroups=\n")
        assert helper._unit_account("dhcp4")["extra_groups"] == [], "the gid the call sets as primary is not repeated"

    def _kea_on_disk(self, helper, monkeypatch, tmp_path, binary_uid, binary_mode):
        """A kea-dhcp4 stub the test pretends is owned by `binary_uid`; subprocess.run is recorded, never executed."""
        import types

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        binary = os.path.join(d, "kea-dhcp4")
        os.chmod(binary, binary_mode)
        root_owned = binary_uid == 0
        monkeypatch.setattr(helper, "_bin_owner_ok", lambda path: root_owned)
        monkeypatch.setattr(helper, "_daemon_bin_ok", lambda path, uid: uid == binary_uid)
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
        ran = []
        monkeypatch.setattr(
            helper.subprocess,
            "run",
            lambda cmd, **kw: ran.append((cmd, kw)) or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        )
        return str(tmp_path / "kea-dhcp4.conf"), ran

    def test_a_root_owned_binary_under_user_kea_is_run_as_kea_not_as_root(self, helper, tmp_path, monkeypatch):
        """The Q149 finding. Build 11 consulted the unit only after the root:root check had succeeded, so this shape - a root-owned,
        0755 kea-dhcp4 (a hand install, or a package that does not hand the binary to the service account) under a unit that says
        `User=_kea` - was validated as ROOT. The daemon runs as `_kea`; so does `-t`."""
        self.MEMBERS = [302]
        p, ran = self._kea_on_disk(helper, monkeypatch, tmp_path, binary_uid=0, binary_mode=0o755)
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=keacerts\nSupplementaryGroups=ssl-cert\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True}
        ((_cmd, kw),) = ran
        assert (kw["user"], kw["group"], kw["extra_groups"]) == (105, 301, [302]), "the unit's account, never root"

    def test_a_root_owned_binary_with_no_user_in_the_unit_is_still_run_as_root(self, helper, tmp_path, monkeypatch):
        p, ran = self._kea_on_disk(helper, monkeypatch, tmp_path, binary_uid=0, binary_mode=0o755)
        self._systemd(helper, monkeypatch, "User=\nGroup=\nSupplementaryGroups=\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True} and "user" not in ran[0][1], "no User=: the daemon is root's, so is -t"

    def test_a_root_owned_binary_the_units_account_cannot_execute_is_refused_not_run_as_root(
        self, helper, tmp_path, monkeypatch
    ):
        p, ran = self._kea_on_disk(helper, monkeypatch, tmp_path, binary_uid=0, binary_mode=0o700)
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["error"] == "missingbinary" and "does not let the daemon's user _kea execute it" in out["detail"]
        assert ran == []

    def test_an_unknown_user_refuses_whatever_owns_the_binary_and_never_runs_as_root(
        self, helper, tmp_path, monkeypatch
    ):
        for owner in (0, 105):
            p, ran = self._kea_on_disk(helper, monkeypatch, tmp_path, binary_uid=owner, binary_mode=0o755)
            self._systemd(helper, monkeypatch, "User=ghost\nGroup=\nSupplementaryGroups=\n")
            _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
            assert out == {
                "ok": False,
                "error": "missingbinary",
                "binary": "kea-dhcp4",
                "detail": "its unit runs as User=ghost, which is not an account on this host",
            }, owner
            assert ran == [], "not run as root, not run as anyone"

    def test_a_binary_owned_by_the_units_account_still_runs_as_it(self, helper, tmp_path, monkeypatch):
        p, ran = self._kea_on_disk(helper, monkeypatch, tmp_path, binary_uid=105, binary_mode=0o750)
        self._systemd(helper, monkeypatch, "User=_kea\nGroup=\nSupplementaryGroups=\n")
        _code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out == {"ok": True} and ran[0][1]["user"] == 105


@win
class TestApplyConfig:
    def _setup(self, helper, tmp_path, monkeypatch, existing=None):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        if existing is not None:
            p.write_text(json.dumps(existing))
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        return str(p)

    def test_writes_new_file_0644(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch)
        code, out, _ = _run(
            helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {"subnet4": []}}}
        )
        assert out["ok"] is True and out["backup"] is None
        assert json.loads(pathlib.Path(p).read_text()) == {"Dhcp4": {"subnet4": []}}
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644

    def test_backup_written_and_mode_preserved(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, existing={"old": True})
        os.chmod(p, 0o640)
        code, out, _ = _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"new": True}})
        assert out["ok"] is True and out["backup"] == p + ".jen_backup"
        assert json.loads(pathlib.Path(p + ".jen_backup").read_text()) == {"old": True}
        assert json.loads(pathlib.Path(p).read_text()) == {"new": True}
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o640

    def test_exists_and_no_overwrite_refuses(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, existing={"old": True})
        code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": p, "config": {"new": True}, "allow_overwrite": False},
        )
        assert out == {"ok": False, "error": "exists"}
        assert json.loads(pathlib.Path(p).read_text()) == {"old": True}

    def test_chown_calls_made_for_new_file(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch)
        chowns = []
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowns.append((uid, gid)))
        _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {}})
        assert chowns == [(0, 0)], (
            "root:root, applied to the DESCRIPTOR (build 13), not to a path another process could swap"
        )
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644

    # ── v2: optimistic concurrency ─────────────────────────────────────────

    def test_apply_returns_the_sha_of_the_bytes_written(self, helper, tmp_path, monkeypatch):
        import hashlib

        p = self._setup(helper, tmp_path, monkeypatch)
        _code, out, _ = _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        assert out["ok"] is True
        assert out["sha256"] == hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

    def test_matching_expect_sha256_applies(self, helper, tmp_path, monkeypatch):
        import hashlib

        p = self._setup(helper, tmp_path, monkeypatch, existing={"Dhcp4": {"a": 1}})
        cur = hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
        _code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": p, "config": {"Dhcp4": {"a": 2}}, "expect_sha256": cur},
        )
        assert out["ok"] is True
        assert json.loads(pathlib.Path(p).read_text()) == {"Dhcp4": {"a": 2}}
        assert out["sha256"] != cur

    def test_stale_expect_sha256_is_a_conflict_and_nothing_is_touched(self, helper, tmp_path, monkeypatch):
        import hashlib

        marker = tmp_path / "kea_ran"
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        p.write_text(json.dumps({"Dhcp4": {"a": 1}}))
        original = p.read_bytes()
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0, marker=marker)
        _code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": str(p), "config": {"Dhcp4": {"a": 9}}, "expect_sha256": "deadbeef" * 8},
        )
        assert out["ok"] is False and out["error"] == "conflict"
        assert out["sha256"] == hashlib.sha256(original).hexdigest()
        assert p.read_bytes() == original  # file untouched
        assert _leftover_temps(tmp_path) == []
        assert not marker.exists()  # kea-dhcpX -t was never invoked

    def test_expect_empty_string_on_missing_file_applies(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch)  # file does not exist
        _code, out, _ = _run(
            helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}, "expect_sha256": ""}
        )
        assert out["ok"] is True

    def test_expect_empty_string_but_file_exists_is_conflict(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, existing={"Dhcp4": {}})
        _code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": p, "config": {"Dhcp4": {"new": 1}}, "expect_sha256": ""},
        )
        assert out["ok"] is False and out["error"] == "conflict"

    def test_a_lock_file_is_created_for_every_apply_whether_or_not_expect_is_given(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch)
        _run(
            helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}}
        )  # no expect_sha256 at all
        assert pathlib.Path(p + ".jen_lock").exists()

    def test_a_lock_file_is_created_when_expect_is_given(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, existing={"Dhcp4": {}})
        _run(
            helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {"x": 1}}, "expect_sha256": ""}
        )
        # expect "" conflicts (file exists), but the lock is taken first
        assert pathlib.Path(p + ".jen_lock").exists()


class TestService:
    """v5.66.0-beta.2 (Q104) — op_service resolves "systemctl" through _find_bin now, not a
    bare name; every test here stubs _find_bin to return the name UNCHANGED (pretending
    resolution is a no-op) so the exact-argv assertions below — written against the
    pre-Q104 bare-name shape — still hold, while subprocess.run itself stays mocked."""

    def test_tries_both_unit_names_and_enable_gets_now(self, helper, monkeypatch):
        calls = []

        class Proc:
            def __init__(self, rc=0, out="", err=""):
                self.returncode, self.stdout, self.stderr = rc, out, err

        def fake_run(argv, **kw):
            calls.append(argv)
            if argv[:3] == ["systemctl", "show", "-p"]:
                unit = argv[-1]
                return Proc(out="loaded" if unit == "isc-kea-dhcp6-server" else "not-found")
            if argv[:2] == ["systemctl", "is-active"]:
                return Proc(out="active")
            return Proc(rc=0)

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "service", {"service": "dhcp6", "action": "enable"})
        assert out == {"ok": True, "unit": "isc-kea-dhcp6-server", "state": "active"}
        action_call = [c for c in calls if c[:2] == ["systemctl", "enable"]][0]
        assert action_call == ["systemctl", "enable", "--now", "isc-kea-dhcp6-server"]

    def test_no_unit(self, helper, monkeypatch):
        class Proc:
            returncode, stdout, stderr = 0, "not-found", ""

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Proc())
        code, out, _ = _run(helper, "service", {"service": "dhcp4", "action": "restart"})
        assert out == {"ok": False, "error": "no-unit"}

    def test_d2_tries_the_dhcp_ddns_unit_names(self, helper, monkeypatch):
        """v5.23.0 (Q19) — d2's unit family is "dhcp-ddns", not "d2"."""
        calls = []

        class Proc:
            def __init__(self, rc=0, out="", err=""):
                self.returncode, self.stdout, self.stderr = rc, out, err

        def fake_run(argv, **kw):
            calls.append(argv)
            if argv[:3] == ["systemctl", "show", "-p"]:
                unit = argv[-1]
                return Proc(out="loaded" if unit == "kea-dhcp-ddns-server" else "not-found")
            if argv[:2] == ["systemctl", "is-active"]:
                return Proc(out="active")
            return Proc(rc=0)

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "service", {"service": "d2", "action": "restart"})
        assert out == {"ok": True, "unit": "kea-dhcp-ddns-server", "state": "active"}
        show_calls = [c[-1] for c in calls if c[:3] == ["systemctl", "show", "-p"]]
        assert show_calls == ["kea-dhcp-ddns-server"]  # found on the first try

    def test_bad_action(self, helper):
        code, out, _ = _run(helper, "service", {"service": "dhcp4", "action": "obliterate"})
        assert out == {"ok": False, "error": "not-allowed"}


class TestTailLog:
    def test_clamps_and_reads(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: p == str(tmp_path / "k.log"))
        f = tmp_path / "k.log"
        f.write_text("\n".join(f"line {i}" for i in range(500)) + "\n")
        code, out, _ = _run(helper, "tail-log", {"path": str(f), "lines": 999999})
        assert out["ok"] is True and len(out["lines"]) == 500 and out["lines"][-1] == "line 499"
        code, out, _ = _run(helper, "tail-log", {"path": str(f), "lines": 3})
        assert out["lines"] == ["line 497", "line 498", "line 499"]

    def test_missing(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: True)
        code, out, _ = _run(helper, "tail-log", {"path": str(tmp_path / "nope.log")})
        assert out == {"ok": False, "error": "missing"}

    def test_rejects_bad_path(self, helper):
        code, out, _ = _run(helper, "tail-log", {"path": "/etc/passwd"})
        assert out == {"ok": False, "error": "not-allowed"}


class TestInstallPackage:
    """v5.66.0-beta.2 (Q104) — op_install_package resolves "apt-get" through _find_bin now;
    both tests stub it to return the name unchanged so the exact-argv assertions still hold."""

    def test_argv_and_output_tail(self, helper, monkeypatch):
        calls = []

        class Proc:
            returncode, stdout, stderr = 0, "installed ok\n", ""

        def fake_run(argv, **kw):
            calls.append(argv)
            return Proc()

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "install-package", {"service": "dhcp6"})
        assert out["ok"] is True
        assert calls[0] == ["apt-get", "update", "-qq"]
        assert calls[1] == ["apt-get", "install", "-y", "kea-dhcp6-server"]

    def test_failure_reported(self, helper, monkeypatch):
        class Proc:
            returncode, stdout, stderr = 100, "", "E: Unable to locate package\n"

        monkeypatch.setattr(helper, "_find_bin", lambda name: name)
        monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Proc())
        code, out, _ = _run(helper, "install-package", {"service": "dhcp4"})
        assert out["ok"] is False and "Unable to locate" in out["output"]


# ── v4 (v5.29.0, Q29): install-tls ──────────────────────────────────────────

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\nZm9v\n-----END CERTIFICATE-----\n"
_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n"


def _tls_files(**over):
    files = {"ca.crt": _CERT_PEM, "server.crt": _CERT_PEM, "server.key": _KEY_PEM}
    files.update(over)
    return files


class TestInstallTls:
    """The op's whole path wall is "these three basenames under
    /etc/kea/tls/<service>/": the payload never carries a path, and the
    content guard is markers + size only (the helper can't parse PEM)."""

    @pytest.fixture
    def tls_root(self, helper, tmp_path, monkeypatch):
        root = tmp_path / "tls"
        monkeypatch.setattr(helper, "_TLS_ROOT", str(root))
        monkeypatch.setattr(helper, "_daemon_group", lambda service: ("root", 0))
        return root

    def test_is_registered_and_is_not_an_update_op(self, helper):
        assert "install-tls" in helper._OPS
        assert "update" not in "install-tls"

    def test_writes_exactly_the_three_files_under_the_service_dir(self, helper, tls_root):
        code, out, _ = _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        assert code == 0 and out["ok"] is True, out
        d = tls_root / "dhcp4"
        assert sorted(os.listdir(d)) == ["ca.crt", "server.crt", "server.key"]
        assert (d / "server.key").read_text() == _KEY_PEM
        assert (d / "ca.crt").read_text() == _CERT_PEM
        assert out["paths"] == {name: str(d / name) for name in ("ca.crt", "server.crt", "server.key")}
        assert out["owner"] == "root:root"
        assert not any(n.endswith(".jen_tmp") for n in os.listdir(d))

    def test_each_service_gets_its_own_directory(self, helper, tls_root):
        for svc in ("dhcp4", "dhcp6", "d2"):
            _code, out, _ = _run(helper, "install-tls", {"service": svc, "files": _tls_files()})
            assert out["ok"] is True
        assert sorted(n for n in os.listdir(tls_root) if not n.endswith(".jen_lock")) == ["d2", "dhcp4", "dhcp6"]

    @win
    def test_modes_key_0640_certs_0644_dir_0755(self, helper, tls_root):
        _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        d = tls_root / "dhcp4"
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o755
        assert stat.S_IMODE(os.stat(d / "server.key").st_mode) == 0o640
        assert stat.S_IMODE(os.stat(d / "server.crt").st_mode) == 0o644
        assert stat.S_IMODE(os.stat(d / "ca.crt").st_mode) == 0o644

    def test_overwrite_replaces_atomically(self, helper, tls_root):
        _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        new_key = _KEY_PEM.replace("MIGHAgEAMBMGByqGSM49", "QUJDREVGR0hJSktMTU5P")
        _code, out, _ = _run(
            helper, "install-tls", {"service": "dhcp4", "files": _tls_files(**{"server.key": new_key})}
        )
        assert out["ok"] is True
        assert (tls_root / "dhcp4" / "server.key").read_text() == new_key

    @pytest.mark.parametrize("service", ["dhcp9", "", None, "ca"])
    def test_bad_service_is_not_allowed(self, helper, tls_root, service):
        _code, out, _ = _run(helper, "install-tls", {"service": service, "files": _tls_files()})
        assert out == {"ok": False, "error": "not-allowed"}
        assert not tls_root.exists()

    @pytest.mark.parametrize(
        "files",
        [
            {},
            {"ca.crt": _CERT_PEM},  # missing two
            {"ca.crt": _CERT_PEM, "server.crt": _CERT_PEM, "server.key": _KEY_PEM, "extra.crt": _CERT_PEM},
            {"../ca.crt": _CERT_PEM, "server.crt": _CERT_PEM, "server.key": _KEY_PEM},
            {"/etc/passwd": _CERT_PEM, "server.crt": _CERT_PEM, "server.key": _KEY_PEM},
            "not a dict",
        ],
    )
    def test_file_set_must_be_exactly_the_three_names(self, helper, tls_root, files):
        _code, out, _ = _run(helper, "install-tls", {"service": "dhcp4", "files": files})
        assert out == {"ok": False, "error": "not-allowed"}
        assert not tls_root.exists()

    def test_a_path_in_the_payload_is_ignored_entirely(self, helper, tls_root, tmp_path):
        """No `path`/`dir` key is read — the destination is fixed."""
        elsewhere = tmp_path / "elsewhere"
        _code, out, _ = _run(
            helper,
            "install-tls",
            {"service": "dhcp4", "files": _tls_files(), "path": str(elsewhere), "dir": str(elsewhere)},
        )
        assert out["ok"] is True
        assert not elsewhere.exists()
        assert (tls_root / "dhcp4" / "ca.crt").exists()

    @pytest.mark.parametrize(
        "name,body",
        [
            pytest.param("server.key", _CERT_PEM, id="cert-where-key-goes"),
            pytest.param("ca.crt", _KEY_PEM, id="key-where-cert-goes"),
            pytest.param("server.crt", "not pem at all", id="not-pem"),
            pytest.param("server.crt", "", id="empty"),
            pytest.param("server.crt", 12345, id="not-a-string"),
            pytest.param("server.key", _KEY_PEM + _CERT_PEM, id="key-plus-cert"),
            pytest.param(
                "ca.crt",
                "-----BEGIN CERTIFICATE-----\n" + ("A" * (64 * 1024)) + "\n-----END CERTIFICATE-----\n",
                id="oversize",
            ),
            pytest.param(
                "server.crt", "-----BEGIN CERTIFICATE-----\n#!/bin/sh\n-----END CERTIFICATE-----\n", id="script"
            ),
        ],
    )
    def test_bad_pem_is_refused_and_nothing_written(self, helper, tls_root, name, body):
        _code, out, _ = _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files(**{name: body})})
        assert out == {"ok": False, "error": "bad-pem", "file": name}
        assert not tls_root.exists()

    def test_a_chain_of_certificates_is_accepted_for_ca_crt(self, helper, tls_root):
        _code, out, _ = _run(
            helper, "install-tls", {"service": "dhcp4", "files": _tls_files(**{"ca.crt": _CERT_PEM * 2})}
        )
        assert out["ok"] is True

    @win
    def test_refuses_a_symlinked_target(self, helper, tls_root, tmp_path):
        d = tls_root / "dhcp4"
        d.mkdir(parents=True)
        victim = tmp_path / "victim"
        victim.write_text("keep me")
        os.symlink(victim, d / "server.key")
        _code, out, _ = _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        assert out["ok"] is False and out["error"] == "symlink"
        assert victim.read_text() == "keep me"

    @win
    def test_refuses_a_symlinked_service_dir(self, helper, tls_root, tmp_path):
        tls_root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, tls_root / "dhcp4", target_is_directory=True)
        _code, out, _ = _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        assert out["ok"] is False and out["error"] == "symlink"
        assert os.listdir(elsewhere) == []

    def test_daemon_group_falls_back_to_root_when_nothing_resolves(self, helper, monkeypatch):
        monkeypatch.setattr(helper, "_resolve_unit", lambda service, action: None)
        try:
            import pwd  # noqa: F401
        except ImportError:
            assert helper._daemon_group("dhcp4") == ("root", 0)
            return
        monkeypatch.setattr("pwd.getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
        assert helper._daemon_group("dhcp4") == ("root", 0)

    def test_daemon_group_prefers_the_units_user(self, helper, monkeypatch):
        pytest.importorskip("pwd")
        import pwd

        class Proc:
            returncode, stdout, stderr = 0, "keauser\n", ""

        monkeypatch.setattr(helper, "_resolve_unit", lambda service, action: "kea-dhcp4-server")
        monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Proc())

        class PW:
            pw_gid = 4242

        monkeypatch.setattr(
            pwd, "getpwnam", lambda name: PW() if name == "keauser" else (_ for _ in ()).throw(KeyError(name))
        )
        assert helper._daemon_group("dhcp4") == ("keauser", 4242)


def _load_jen_update_root():
    """The same importlib-against-file-path pattern test_jen_update_root.py uses — needed here
    only for the RELEASE_SIGNERS twin check below."""
    spec = importlib.util.spec_from_file_location("jen_update_root_twin_check", _UPDATE_ROOT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _candidate_bytes(version, build=None):
    """The real helper source with HELPER_VERSION and HELPER_BUILD (Q104) rewritten — a
    realistic candidate, not a fabricated stub, so a signature over it exercises the exact
    bytes ssh-keygen -Y verify sees, and so a preflight/postflight probe of it genuinely
    runs the real code. `build` defaults to `version` when not given."""
    if build is None:
        build = version
    src = _SCRIPT_PATH.read_text(encoding="utf-8")
    src = re.sub(r"^HELPER_VERSION = \d+$", f"HELPER_VERSION = {version}", src, count=1, flags=re.M)
    src = re.sub(r"^HELPER_BUILD = \d+$", f"HELPER_BUILD = {build}", src, count=1, flags=re.M)
    return src.encode()


def _allow_real_ssh_keygen(helper, monkeypatch):
    """op_update resolves ssh-keygen through _find_bin (a root-owned _BIN_DIRS allowlist),
    never $PATH — patched here to answer with the REAL system ssh-keygen (found via $PATH,
    the same way the signing_key fixture itself needs it) for that one name, so these tests
    can drive a genuine signature check without being root. A plain _BIN_DIRS-prepend isn't
    enough on Windows: shutil.which() resolves PATHEXT (ssh-keygen.EXE), but _find_bin joins
    the bare name, so the two would disagree on the exact path."""
    real = shutil.which("ssh-keygen")
    if real is None:
        pytest.skip("ssh-keygen not available")
    orig_find_bin = helper._find_bin
    monkeypatch.setattr(helper, "_find_bin", lambda name: real if name == "ssh-keygen" else orig_find_bin(name))


def _sign(key_path, namespace, data, tmp_path, name="candidate"):
    """`ssh-keygen -Y sign` signs a FILE (producing `<file>.sig` beside it), unlike `-Y verify`
    which reads the message on stdin — mirrors release.yml's own `ssh-keygen -Y sign -f ... -n
    ... SHA256SUMS` usage exactly, just against a throwaway key and a throwaway file."""
    cand = tmp_path / name
    cand.write_bytes(data)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(cand)],
        check=True,
        capture_output=True,
    )
    return (tmp_path / f"{name}.sig").read_bytes()


@pytest.fixture(scope="module")
def signing_key(tmp_path_factory):
    """A throwaway ed25519 key pair, generated once per test module run. Skipped only if
    ssh-keygen itself is unavailable — never true on CI's ubuntu runner (openssh-client), and
    true here only on a dev box that has somehow removed it."""
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen not available")
    d = tmp_path_factory.mktemp("s103-signing-key")
    key_path = d / "key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True, capture_output=True)
    os.chmod(key_path, 0o600)
    pub_line = (d / "key.pub").read_text().strip().split()
    return {"priv": str(key_path), "signers_line": f"release@jen {pub_line[0]} {pub_line[1]}"}


class TestUpdateOp:
    """v5.66.0 (Q103) — the ONE way the helper ever replaces itself: a candidate signed by the
    Jen project's release key under the `jen-kea-helper` namespace, declaring a strictly higher
    HELPER_VERSION. Every test here uses a THROWAWAY key via the optional `_EXTRA_SIGNERS` file
    (never the embedded, real RELEASE_SIGNERS — a checkout's helper is not signed by the real
    key, and weakening that check to make a test pass would defeat the whole point)."""

    def _use_throwaway_signer(self, helper, monkeypatch, signing_key, tmp_path):
        signers = tmp_path / "allowed_signers"
        signers.write_text(signing_key["signers_line"] + "\n")
        monkeypatch.setattr(helper, "_EXTRA_SIGNERS", str(signers))
        monkeypatch.setattr(helper, "_extra_signers_owner_ok", lambda path: True)
        _allow_real_ssh_keygen(helper, monkeypatch)
        # v5.66.0-beta.2 (Q104): preflight/postflight run _PREFLIGHT_PYTHON (hardcoded
        # /usr/bin/python3 in production — real on every deploy target). Point it at
        # whichever interpreter is running THIS test, so the real preflight/postflight
        # logic is exercised on any platform, not skipped outright.
        monkeypatch.setattr(helper, "_PREFLIGHT_PYTHON", sys.executable)
        if sys.platform == "win32":
            # _CLEAN_ENV is deliberately a Linux-shaped PATH with nothing else — correct in
            # production (this helper never runs anywhere but a real Kea host), but Windows
            # Python needs SYSTEMROOT on the environment to reach its own crypto APIs during
            # interpreter startup (hash randomization), so a plain _CLEAN_ENV subprocess call
            # fails immediately here. Add it back for THIS test's own preflight/postflight
            # subprocess only — production's _CLEAN_ENV is untouched.
            monkeypatch.setattr(
                helper, "_CLEAN_ENV", {**helper._CLEAN_ENV, "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
            )

    def _target(self, helper, monkeypatch, tmp_path, content=b"old helper content"):
        target = tmp_path / "installed-helper"
        target.write_bytes(content)
        monkeypatch.setattr(helper, "_SELF_PATH", str(target))
        return target

    def _update(self, helper, candidate, signature):
        payload = {
            "helper_b64": base64.b64encode(candidate).decode(),
            "signature_b64": base64.b64encode(signature).decode(),
        }
        return _run(helper, "update", payload)

    def test_is_registered(self, helper):
        assert "update" in helper._OPS

    def test_release_signers_matches_jen_update_root_byte_for_byte(self, helper):
        assert helper.RELEASE_SIGNERS == _load_jen_update_root().RELEASE_SIGNERS

    def test_good_signature_installs_atomically_and_cleans_up(self, helper, signing_key, tmp_path, monkeypatch):
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {
            "ok": True,
            "installed_version": 99,
            "installed_build": 99,
            "previous_version": helper.HELPER_VERSION,
            "previous_build": helper.HELPER_BUILD,
        }
        assert target.read_bytes() == candidate
        assert not (tmp_path / "installed-helper.prev").exists()  # cleaned up after a good postflight
        if sys.platform != "win32":
            assert stat.S_IMODE(target.stat().st_mode) == 0o755
        # the temp dir op_update made (tempfile.mkdtemp beside the target) is gone — only this
        # test's own fixture files remain (the signers file, and _sign()'s candidate + its .sig)
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            "allowed_signers",
            "candidate",
            "candidate.sig",
            "installed-helper",
        ]

    def test_flipped_byte_is_bad_signature_and_target_untouched(self, helper, signing_key, tmp_path, monkeypatch):
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        original = target.read_bytes()
        candidate = bytearray(_candidate_bytes(99))
        sig = _sign(signing_key["priv"], "jen-kea-helper", bytes(candidate), tmp_path)
        candidate[-10] ^= 0xFF  # flip a byte AFTER signing — the signature no longer matches

        code, out, _err = self._update(helper, bytes(candidate), sig)
        assert out == {"ok": False, "error": "bad-signature"}
        assert target.read_bytes() == original

    def test_wrong_namespace_is_bad_signature(self, helper, signing_key, tmp_path, monkeypatch):
        """Signed correctly, but under `jen-release` (the checksum-signature namespace) — never
        accepted as a helper-update signature, and vice versa (the whole point of a distinct
        namespace: one signature can't be replayed as the other)."""
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        original = target.read_bytes()
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-release", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "bad-signature"}
        assert target.read_bytes() == original

    @pytest.mark.parametrize(
        "version,build,case,detail",
        [
            (7, 7, "same version, same build", "build-not-newer"),
            (7, 3, "same version, LOWER build", "build-not-newer"),
            (
                6,
                99,
                "LOWER version, even with a much higher build — a protocol downgrade is never installed",
                "protocol-downgrade",
            ),
            (3, 1, "lower version and lower build", "protocol-downgrade"),
            (
                8,
                8,
                "HIGHER version, but build not newer — v5.66.0-beta.7 (Q109): the old code nested the "
                "build check inside 'same version', so a higher-VERSION candidate skipped it entirely",
                "build-not-newer",
            ),
            (8, 7, "HIGHER version, LOWER build — the exact regression Q109 closes", "build-not-newer"),
        ],
    )
    def test_equal_or_lower_is_not_newer(
        self, helper, signing_key, tmp_path, monkeypatch, version, build, case, detail
    ):
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        original = target.read_bytes()
        candidate = _candidate_bytes(version, build)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path, name=f"candidate-{version}-{build}")

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "not-newer", "detail": detail}, case
        assert target.read_bytes() == original

    def test_same_version_higher_build_is_newer(self, helper, signing_key, tmp_path, monkeypatch):
        """v5.66.0-beta.2 (Q104) — HELPER_BUILD orders two files that changed WITHOUT a
        protocol bump between them; a same-VERSION, higher-BUILD candidate is accepted."""
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        candidate = _candidate_bytes(helper.HELPER_VERSION, helper.HELPER_BUILD + 1)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out["ok"] is True
        assert out["installed_version"] == helper.HELPER_VERSION
        assert out["installed_build"] == helper.HELPER_BUILD + 1
        assert target.read_bytes() == candidate

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"helper_b64": "x"},
            {"signature_b64": "x"},
            {"helper_b64": 12345, "signature_b64": "x"},
            {"helper_b64": base64.b64encode(b"x").decode(), "signature_b64": "not valid base64!!"},
        ],
    )
    def test_missing_or_malformed_fields_are_not_allowed(self, helper, payload):
        code, out, _err = _run(helper, "update", payload)
        assert out == {"ok": False, "error": "not-allowed"}

    def test_oversize_helper_is_not_allowed(self, helper, signing_key, tmp_path):
        oversize = b"x" * (helper._UPDATE_MAX_HELPER + 1)
        sig = _sign(signing_key["priv"], "jen-kea-helper", oversize, tmp_path)
        code, out, _err = self._update(helper, oversize, sig)
        assert out == {"ok": False, "error": "not-allowed"}

    def test_oversize_signature_is_not_allowed(self, helper):
        candidate = _candidate_bytes(99)
        code, out, _err = self._update(helper, candidate, b"x" * (helper._UPDATE_MAX_SIGNERS + 1))
        assert out == {"ok": False, "error": "not-allowed"}

    @pytest.mark.skipif(sys.platform == "win32", reason="needs a real symlink")
    def test_self_path_symlink_is_refused(self, helper, signing_key, tmp_path, monkeypatch):
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        victim = tmp_path / "victim"
        victim.write_text("keep me")
        link = tmp_path / "installed-helper"
        os.symlink(victim, link)
        monkeypatch.setattr(helper, "_SELF_PATH", str(link))
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "symlink"}
        assert victim.read_text() == "keep me"

    def test_no_ssh_keygen_is_reported_distinctly(self, helper, signing_key, tmp_path, monkeypatch):
        # Deliberately NOT _use_throwaway_signer (which now also makes ssh-keygen
        # resolvable) — the signers file is set up by hand so _find_bin("ssh-keygen") is
        # the only thing under test. A CI box's real /usr/bin/ssh-keygen is genuinely
        # root-owned (installed by the package manager, regardless of what UID pytest
        # itself runs as), so leaving _find_bin at its real default would find it there —
        # force the "missing" case explicitly instead of relying on the box's state.
        signers = tmp_path / "allowed_signers"
        signers.write_text(signing_key["signers_line"] + "\n")
        monkeypatch.setattr(helper, "_EXTRA_SIGNERS", str(signers))
        monkeypatch.setattr(helper, "_extra_signers_owner_ok", lambda path: True)
        orig_find_bin = helper._find_bin
        monkeypatch.setattr(helper, "_find_bin", lambda name: None if name == "ssh-keygen" else orig_find_bin(name))
        self._target(helper, monkeypatch, tmp_path)
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "no-ssh-keygen"}

    def test_extra_signers_file_with_bad_ownership_is_ignored(self, helper, signing_key, tmp_path, monkeypatch):
        """The owner/mode check is monkeypatched directly (this test doesn't run as root, so it
        can't chown a real file to root:root) — with it forced False, the throwaway key is never
        trusted and only the embedded (real) RELEASE_SIGNERS applies, so a throwaway-signed
        candidate is refused exactly like an unsigned one."""
        signers = tmp_path / "allowed_signers"
        signers.write_text(signing_key["signers_line"] + "\n")
        monkeypatch.setattr(helper, "_EXTRA_SIGNERS", str(signers))
        monkeypatch.setattr(helper, "_extra_signers_owner_ok", lambda path: False)
        _allow_real_ssh_keygen(helper, monkeypatch)
        target = self._target(helper, monkeypatch, tmp_path)
        original = target.read_bytes()
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "bad-signature"}
        assert target.read_bytes() == original

    def test_no_installed_file_refuses_not_installed_and_writes_nothing(
        self, helper, signing_key, tmp_path, monkeypatch
    ):
        """v5.66.0-beta.4 (Q106) — update() replaces an installed helper, it never installs
        one: with no regular file at _SELF_PATH, it refuses before writing or preflighting
        anything at all."""
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = tmp_path / "installed-helper"  # never created
        monkeypatch.setattr(helper, "_SELF_PATH", str(target))
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "not-installed"}
        assert not target.exists()
        # nothing beyond this test's own fixture files (the signers file, and _sign()'s
        # candidate + its .sig) — no tmp_dir, no partial install
        assert sorted(p.name for p in tmp_path.iterdir()) == ["allowed_signers", "candidate", "candidate.sig"]

    def test_postflight_failure_restores_the_previous_bytes_and_leaves_no_prev(
        self, helper, signing_key, tmp_path, monkeypatch
    ):
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        original = target.read_bytes()
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        real_probe = helper._probe_helper_version

        def fake_probe(path):
            # the postflight probe is the one call against the INSTALLED path — fail only
            # that one; the preflight probe (against a temp file elsewhere) runs for real.
            if path == str(target):
                return False, None, None, "boom: candidate crashed after install"
            return real_probe(path)

        monkeypatch.setattr(helper, "_probe_helper_version", fake_probe)

        code, out, _err = self._update(helper, candidate, sig)
        assert out == {"ok": False, "error": "postflight-failed", "detail": "boom: candidate crashed after install"}
        assert target.read_bytes() == original
        assert not (tmp_path / "installed-helper.prev").exists()

    def test_a_failed_rollback_reports_rollback_failed_naming_both_paths(
        self, helper, signing_key, tmp_path, monkeypatch
    ):
        """v5.66.0-beta.4 (Q106) — the rollback after a postflight failure is now unconditional;
        this is what fires when the rollback itself can't be applied."""
        self._use_throwaway_signer(helper, monkeypatch, signing_key, tmp_path)
        target = self._target(helper, monkeypatch, tmp_path)
        candidate = _candidate_bytes(99)
        sig = _sign(signing_key["priv"], "jen-kea-helper", candidate, tmp_path)

        monkeypatch.setattr(
            helper,
            "_probe_helper_version",
            lambda path: (False, None, None, "boom") if path == str(target) else (True, 99, 99, ""),
        )
        real_replace = os.replace
        prev_path = str(target) + ".prev"

        def fake_replace(src, dst):
            if str(src) == prev_path:
                raise OSError("disk exploded")
            return real_replace(src, dst)

        monkeypatch.setattr(helper.os, "replace", fake_replace)

        code, out, _err = self._update(helper, candidate, sig)
        assert out["ok"] is False
        assert out["error"] == "rollback-failed"
        assert out["path"] == str(target)
        assert out["prev_path"] == prev_path
        assert "boom" in out["detail"] and "disk exploded" in out["detail"]


class TestBoundedTail:
    """v5.49.0-beta.6 (Q56-6) - tail-log holds only the requested lines in memory
    (collections.deque), however large the log file is."""

    def test_uses_a_bounded_deque_not_a_full_read(self):
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper").read_text(encoding="utf-8")
        body = src[src.index("def op_tail_log") : src.index("def op_install_package")]
        assert "collections.deque(f, maxlen=lines)" in body
        assert ".read()" not in body  # never the whole file

    def test_a_5mb_log_returns_exactly_the_last_100_lines(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: p == str(tmp_path / "big.log"))
        f = tmp_path / "big.log"
        with open(f, "w") as fh:
            for i in range(80000):
                fh.write(f"2026-09-20 10:00:00.000 INFO [kea-dhcp4] line {i:06d} " + "x" * 40 + "\n")
        assert f.stat().st_size >= 5_000_000
        code, out, _ = _run(helper, "tail-log", {"path": str(f), "lines": 100})
        assert out["ok"] is True and len(out["lines"]) == 100
        assert out["lines"][0].split("line ")[1].startswith("079900")
        assert out["lines"][-1].split("line ")[1].startswith("079999")

    def test_lines_have_no_trailing_newline_and_bad_bytes_are_replaced(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: True)
        f = tmp_path / "odd.log"
        f.write_bytes(b"first\r\nsecond \xff\xfe bytes\nthird")
        code, out, _ = _run(helper, "tail-log", {"path": str(f), "lines": 10})
        assert out["ok"] is True
        assert out["lines"][0] == "first" and out["lines"][2] == "third"
        assert "�" in out["lines"][1]  # invalid bytes replaced, not an error

    def test_a_short_file_and_the_clamp_still_work(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_allowed_log_path", lambda p: True)
        f = tmp_path / "s.log"
        f.write_text("a\nb\n")
        assert _run(helper, "tail-log", {"path": str(f), "lines": 999999})[1]["lines"] == ["a", "b"]
        assert _run(helper, "tail-log", {"path": str(f), "lines": 0})[1]["lines"] == ["b"]  # clamped to >= 1


# ── build 13 (v5.68.0-beta.15, Q150): private from the first byte, the lock everywhere, remove-config ─────────────────────────────────


class _DirWatcher(threading.Thread):
    """Stats every entry of `directory` in a tight loop and records the modes it ever sees, by name (a temp file is just "temp")."""

    def __init__(self, directory):
        super().__init__(daemon=True)
        self.directory, self.stop, self.seen, self.samples = directory, threading.Event(), {}, 0

    def run(self):
        while not self.stop.is_set():
            try:
                with os.scandir(self.directory) as it:
                    for entry in it:
                        try:
                            mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                        except FileNotFoundError:
                            continue
                        kind = "temp" if entry.name.startswith(".") and entry.name.endswith(".jen_tmp") else entry.name
                        self.seen.setdefault(kind, set()).add(mode)
                        self.samples += 1
            except FileNotFoundError:
                pass

    def watch(self, work, rounds):
        self.start()
        try:
            for i in range(rounds):
                work(i)
        finally:
            self.stop.set()
            self.join(5)


def _say(request, line):
    reporter = request.config.pluginmanager.getplugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line(line)


@pytest.fixture
def wide_window(monkeypatch):
    """A 1 ms pause in every fsync: the window between "written" and "final mode" is wide enough that a polling watcher cannot miss it."""
    real = os.fsync

    def slow(fd):
        time.sleep(0.001)
        real(fd)

    monkeypatch.setattr(os, "fsync", slow)


@win
class TestEveryFileTheHelperWritesIsPrivateAtEveryInstant:
    """Q150 (build 13). A watcher stats every entry of the directory in a tight loop while the real op runs 120 times under umask 022
    (so the old `open()` would have produced 0644 and be seen). A file that ends 0600 is only ever seen 0600; one that ends 0640 is seen
    0600 until it is complete."""

    ROUNDS = 120

    @pytest.fixture(autouse=True)
    def _umask(self, wide_window):
        old = os.umask(0o022)
        yield
        os.umask(old)

    def _report(self, request, label, watcher):
        observed = {k: sorted(oct(m) for m in v) for k, v in sorted(watcher.seen.items())}
        _say(
            request,
            f"[helper private-write watcher] {label}: {watcher.samples} stats over {self.ROUNDS} runs; modes seen {observed}",
        )
        assert watcher.samples > 0

    def test_replacing_a_0600_config_is_never_readable_by_another_uid_at_any_instant(
        self, helper, tmp_path, monkeypatch, request
    ):
        conf_dir = tmp_path / "etc"
        conf_dir.mkdir()
        conf = conf_dir / "kea-dhcp4.conf"
        conf.write_text(json.dumps({"Dhcp4": {"password": "s3cret"}}))
        os.chmod(conf, 0o600)
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(conf_dir),))
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        w = _DirWatcher(str(conf_dir))
        w.watch(
            lambda i: _run(
                helper,
                "apply-config",
                {"service": "dhcp4", "path": str(conf), "config": {"Dhcp4": {"password": f"s3cret-{i}"}}},
            ),
            self.ROUNDS,
        )
        self._report(request, "apply-config over a 0600 config", w)
        for kind, modes in w.seen.items():
            assert modes <= {0o600}, f"{kind} was seen with mode(s) {sorted(oct(m) for m in modes - {0o600})}"
        assert "temp" in w.seen, "the watcher never caught a temp file in flight: the test has no power"
        assert json.loads(conf.read_text())["Dhcp4"]["password"] == f"s3cret-{self.ROUNDS - 1}"

    def test_the_backup_of_a_0600_config_is_private_from_its_first_byte_too(
        self, helper, tmp_path, monkeypatch, request
    ):
        conf_dir = tmp_path / "etc"
        conf_dir.mkdir()
        conf = conf_dir / "kea-dhcp4.conf"
        conf.write_text(json.dumps({"Dhcp4": {"password": "s3cret"}}))
        os.chmod(conf, 0o600)
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(conf_dir),))
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        w = _DirWatcher(str(conf_dir))
        w.watch(
            lambda i: _run(
                helper, "apply-config", {"service": "dhcp4", "path": str(conf), "config": {"Dhcp4": {"n": i}}}
            ),
            self.ROUNDS,
        )
        self._report(request, "the .jen_backup copy", w)
        assert w.seen.get("kea-dhcp4.conf.jen_backup") == {0o600}, (
            "shutil.copy2 created it with the umask, then chmod'ed it"
        )

    def test_the_validation_copy_is_never_group_or_other_writable_and_world_unreadable(
        self, helper, tmp_path, monkeypatch, request
    ):
        conf_dir = tmp_path / "etc"
        conf_dir.mkdir()
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(conf_dir),))
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        w = _DirWatcher(str(conf_dir))
        w.watch(
            lambda i: _run(
                helper,
                "test-config",
                {"service": "dhcp4", "path": str(conf_dir / "kea-dhcp4.conf"), "config": {"Dhcp4": {"i": i}}},
            ),
            self.ROUNDS,
        )
        self._report(request, "the -t validation copy (run as root: stays 0600)", w)
        assert w.seen["temp"] == {0o600}

    def test_server_key_is_0600_while_written_and_0640_only_when_complete(self, helper, tmp_path, monkeypatch, request):
        root = tmp_path / "tls"
        monkeypatch.setattr(helper, "_TLS_ROOT", str(root))
        monkeypatch.setattr(helper, "_daemon_group", lambda service: ("root", 0))
        service_dir = root / "dhcp4"
        os.makedirs(service_dir)
        w = _DirWatcher(str(service_dir))
        w.watch(lambda i: _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()}), self.ROUNDS)
        self._report(request, "install-tls (server.key final 0640, certs 0644)", w)
        assert w.seen["server.key"] == {0o640}, "the final name is only ever the complete, 0640 file"
        assert w.seen["server.crt"] == {0o644} and w.seen["ca.crt"] == {0o644}
        assert w.seen["temp"] <= {0o600, 0o640, 0o644}
        # the PRIVATE KEY is the thing that must never be world-readable before it is complete: the key's own temp is 0600 until the
        # fchmod, which is the last thing before the replace. (Certificates are public: their temps reach 0644 the same way.)
        assert 0o600 in w.seen["temp"]


@win
class TestTheLockIsTakenForEveryOp:
    """Build 13: `<conf>.jen_lock` for EVERY test-config, apply-config, remove-config (and `<tls dir>.jen_lock` for install-tls)."""

    @pytest.fixture
    def taken(self, helper, monkeypatch):
        import contextlib

        paths = []
        real = helper._locked

        @contextlib.contextmanager
        def spy(path):
            paths.append(path)
            with real(path):
                yield

        monkeypatch.setattr(helper, "_locked", spy)
        return paths

    def test_test_config_and_apply_config_and_remove_config_lock_their_path(self, helper, tmp_path, monkeypatch, taken):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        p = str(tmp_path / "kea-dhcp4.conf")
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})
        _run(helper, "remove-config", {"service": "dhcp4", "path": p, "expect_sha256": "0" * 64})
        assert taken == [p, p, p]

    def test_install_tls_locks_the_service_directory(self, helper, tmp_path, monkeypatch, taken):
        root = tmp_path / "tls"
        monkeypatch.setattr(helper, "_TLS_ROOT", str(root))
        monkeypatch.setattr(helper, "_daemon_group", lambda service: ("root", 0))
        _run(helper, "install-tls", {"service": "dhcp4", "files": _tls_files()})
        assert taken == [str(root / "dhcp4")]

    def test_a_held_lock_blocks_the_other_ops_until_it_is_released(self, helper, tmp_path, monkeypatch):
        """A real `flock`: while an apply is inside its (slow) validation, a test-config of the same file does not even start `kea -t`."""
        import fcntl

        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        started, finished = tmp_path / "started", tmp_path / "finished"
        stub = pathlib.Path(d) / "kea-dhcp4"
        stub.write_text(f"#!/bin/sh\ntouch {started}\nsleep 0.6\ntouch {finished}\nexit 0\n")
        stub.chmod(0o755)
        p = str(tmp_path / "kea-dhcp4.conf")
        result = {}
        t = threading.Thread(
            target=lambda: result.update(
                apply=_run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}})[1]
            )
        )
        t.start()
        for _ in range(100):
            if started.exists():
                break
            time.sleep(0.02)
        assert started.exists() and not finished.exists(), "the apply is inside its validation"
        fd = os.open(p + ".jen_lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # the apply holds it
        finally:
            os.close(fd)
        t.join(10)
        assert result["apply"]["ok"] is True


@win
class TestConcurrentOpsOnOnePath:
    """Q150: a fixed `<conf>.jen_tmp` was shared by two helper processes on one config. Each op now has its own unique file."""

    def _stub_that_reports_what_it_was_given(self, helper, monkeypatch, tmp_path):
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=1)
        stub = pathlib.Path(d) / "kea-dhcp4"
        # prints the validated file's own content as its ERROR line (so the op's `detail` says WHAT it validated), after a pause
        # long enough for two runs to overlap
        stub.write_text('#!/bin/sh\nsleep 0.3\necho "ERROR saw=$(cat "$2" | tr -d \' \\n\')"\nexit 1\n')
        stub.chmod(0o755)

    def test_two_concurrent_test_configs_with_different_candidates_each_validate_their_own(
        self, helper, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        self._stub_that_reports_what_it_was_given(helper, monkeypatch, tmp_path)
        p = str(tmp_path / "kea-dhcp4.conf")
        results = {}

        def run(marker):
            results[marker] = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"m": marker}})[1]

        threads = [threading.Thread(target=run, args=(m,)) for m in ("MARKER-A", "MARKER-B")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        for mine, other in (("MARKER-A", "MARKER-B"), ("MARKER-B", "MARKER-A")):
            detail = results[mine]["detail"]
            assert mine in detail and other not in detail, f"{mine} validated {detail!r}"
        assert _leftover_temps(tmp_path) == []

    def test_a_test_config_started_during_an_apply_waits_for_it(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        d = _fake_kea_bin(helper, monkeypatch, tmp_path, "kea-dhcp4", exit_code=0)
        log = tmp_path / "order.log"
        stub = pathlib.Path(d) / "kea-dhcp4"
        stub.write_text(
            f'#!/bin/sh\necho "start $(tr -d \' \\n\' < "$2")" >> {log}\nsleep 0.3\necho "end" >> {log}\nexit 0\n'
        )
        stub.chmod(0o755)
        p = str(tmp_path / "kea-dhcp4.conf")
        a = threading.Thread(
            target=lambda: _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"m": "APPLY"}})
        )
        a.start()
        for _ in range(100):
            if log.exists():
                break
            time.sleep(0.02)
        _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {"m": "TEST"}})
        a.join(10)
        lines = log.read_text().splitlines()
        assert [ln.split()[0] for ln in lines] == ["start", "end", "start", "end"], (
            "the two validations never overlapped"
        )
        assert "APPLY" in lines[0] and "TEST" in lines[2]


@win
class TestRemoveConfig:
    """Build 13: the rollback of an Author Kea Config target that had no file. Removes a config only if it still is the file Jen wrote."""

    def _setup(self, helper, tmp_path, monkeypatch, content=None):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp6.conf"
        if content is not None:
            p.write_text(content)
        return p

    def _sha(self, p):
        import hashlib

        return hashlib.sha256(p.read_bytes()).hexdigest()

    def test_is_registered(self, helper):
        assert "remove-config" in helper._OPS

    def test_removes_the_file_when_the_sha_matches(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, "{}")
        code, out, _ = _run(
            helper, "remove-config", {"service": "dhcp6", "path": str(p), "expect_sha256": self._sha(p)}
        )
        assert out == {"ok": True, "removed": True} and not p.exists()

    def test_leaves_a_file_somebody_replaced_alone(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch, "{}")
        wrote = self._sha(p)
        p.write_text('{"someone": "else"}')
        _code, out, _ = _run(helper, "remove-config", {"service": "dhcp6", "path": str(p), "expect_sha256": wrote})
        assert out["ok"] is False and out["error"] == "conflict" and out["sha256"] == self._sha(p) and p.exists()

    def test_an_already_absent_file_is_the_state_wanted(self, helper, tmp_path, monkeypatch):
        p = self._setup(helper, tmp_path, monkeypatch)
        _code, out, _ = _run(helper, "remove-config", {"service": "dhcp6", "path": str(p), "expect_sha256": "a" * 64})
        assert out == {"ok": True, "removed": False}

    @pytest.mark.parametrize("sha", [None, "", "short", "G" * 64, "A" * 64, 123])
    def test_a_missing_or_malformed_sha_is_never_a_license_to_delete(self, helper, tmp_path, monkeypatch, sha):
        p = self._setup(helper, tmp_path, monkeypatch, "{}")
        payload = {"service": "dhcp6", "path": str(p)}
        if sha is not None:
            payload["expect_sha256"] = sha
        _code, out, _ = _run(helper, "remove-config", payload)
        assert out == {"ok": False, "error": "not-allowed"} and p.exists()

    def test_the_path_wall_is_the_same_as_apply_config(self, helper, tmp_path, monkeypatch):
        victim = tmp_path / "kea-dhcp6.conf"
        victim.write_text("{}")
        # not under an allowed directory
        _code, out, _ = _run(
            helper, "remove-config", {"service": "dhcp6", "path": str(victim), "expect_sha256": self._sha(victim)}
        )
        assert out == {"ok": False, "error": "not-allowed"} and victim.exists()
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        for bad in ("../x.conf", "/etc/passwd", str(tmp_path / "other.txt")):
            _code, out, _ = _run(helper, "remove-config", {"service": "dhcp6", "path": bad, "expect_sha256": "a" * 64})
            assert out == {"ok": False, "error": "not-allowed"}, bad
        _code, out, _ = _run(
            helper, "remove-config", {"service": "bogus", "path": str(victim), "expect_sha256": "a" * 64}
        )
        assert out == {"ok": False, "error": "not-allowed"}
