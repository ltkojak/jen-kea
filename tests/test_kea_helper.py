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

import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
from importlib.machinery import SourceFileLoader

import pytest

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"


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


def _run(helper, op, payload, path_env=None):
    """Invoke main() with a captured stdin/stdout/stderr. Returns
    (exit_code, parsed_stdout_json, stderr_text)."""
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()
    old_path = os.environ.get("PATH")
    if path_env is not None:
        os.environ["PATH"] = path_env
    try:
        code = helper.main(argv=["jen-kea-helper", op], stdin=stdin, stdout=stdout, stderr=stderr)
    finally:
        if path_env is not None:
            os.environ["PATH"] = old_path or ""
    out = stdout.getvalue().strip()
    parsed = json.loads(out) if out else None
    return code, parsed, stderr.getvalue()


class TestShape:
    def test_exists_at_repo_root(self):
        assert _SCRIPT_PATH.exists()

    def test_is_valid_python(self):
        import ast

        ast.parse(_SCRIPT_PATH.read_text(encoding="utf-8"))

    def test_no_self_update_op(self, helper):
        # The whole point of the helper is that Jen can't make the Kea
        # host run a file Jen wrote — an op that rewrites the helper puts
        # that straight back.
        assert "self-update" not in helper._OPS
        assert "self_update" not in helper._OPS
        assert not any("update" in op for op in helper._OPS)


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
        assert json.loads(stdout.getvalue()) == {"ok": False, "error": "stdin-too-large"}

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
        code, out, err = _run(helper, "version", {})
        assert code == 0
        assert out["ok"] is True
        assert out["helper_version"] == helper.HELPER_VERSION == 1
        assert out["python"].count(".") == 2
        assert err.startswith("jen-kea-helper: version ok")


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
        "p", ["/etc/kea/kea-dhcp4.conf", "/etc/kea/kea-dhcp6.conf", "/usr/local/etc/kea/kea-dhcp6.conf"]
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
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        p.write_text(json.dumps({"Dhcp4": {"subnet4": [{"id": 1}]}}))
        code, out, _ = _run(helper, "read-config", {"service": "dhcp4", "path": str(p)})
        assert out == {"ok": True, "config": {"Dhcp4": {"subnet4": [{"id": 1}]}}}


def _fake_kea_bin(tmp_path, name, exit_code=0, stdout="", stderr=""):
    """Write an executable stub that mimics `kea-dhcpX -t`."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    script = d / name
    body = "#!/usr/bin/env python3\nimport sys\n"
    body += f"sys.stdout.write({stdout!r})\nsys.stderr.write({stderr!r})\nsys.exit({exit_code})\n"
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(d)


win = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX exec stub for kea-dhcpX")


@win
class TestTestConfig:
    def _paths(self, helper, tmp_path, monkeypatch):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        return str(tmp_path / "kea-dhcp4.conf")

    def test_missing_binary(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        code, out, _ = _run(
            helper, "test-config", {"service": "dhcp4", "path": p, "config": {}}, path_env="/nonexistent"
        )
        assert out == {"ok": False, "error": "missingbinary", "binary": "kea-dhcp4"}

    def test_pass_and_tmp_is_removed(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        bindir = _fake_kea_bin(tmp_path, "kea-dhcp4", exit_code=0)
        code, out, _ = _run(
            helper, "test-config", {"service": "dhcp4", "path": p, "config": {"Dhcp4": {}}}, path_env=bindir
        )
        assert out == {"ok": True}
        assert not os.path.exists(p + ".jen_tmp")

    def test_testerror_detail_and_tmp_removed(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        bindir = _fake_kea_bin(tmp_path, "kea-dhcp4", exit_code=1, stderr="ERROR line one\nERROR line two\ninfo\n")
        code, out, _ = _run(helper, "test-config", {"service": "dhcp4", "path": p, "config": {}}, path_env=bindir)
        assert out["error"] == "testerror"
        assert out["detail"] == "ERROR line one | ERROR line two"
        assert not os.path.exists(p + ".jen_tmp")

    def test_tlsmissing_checked_before_the_binary_runs(self, helper, tmp_path, monkeypatch):
        p = self._paths(helper, tmp_path, monkeypatch)
        bindir = _fake_kea_bin(tmp_path, "kea-dhcp4", exit_code=0)
        code, out, _ = _run(
            helper,
            "test-config",
            {"service": "dhcp4", "path": p, "config": {}, "tls_paths": [["/nope/cert.pem", "file"]]},
            path_env=bindir,
        )
        assert out == {"ok": False, "error": "tlsmissing", "path": "/nope/cert.pem"}
        assert not os.path.exists(p + ".jen_tmp")


@win
class TestApplyConfig:
    def _setup(self, helper, tmp_path, monkeypatch, existing=None):
        monkeypatch.setattr(helper, "_ALLOWED_CONF_DIRS", (str(tmp_path),))
        p = tmp_path / "kea-dhcp4.conf"
        if existing is not None:
            p.write_text(json.dumps(existing))
        bindir = _fake_kea_bin(tmp_path, "kea-dhcp4", exit_code=0)
        return str(p), bindir

    def test_writes_new_file_0644(self, helper, tmp_path, monkeypatch):
        p, bindir = self._setup(helper, tmp_path, monkeypatch)
        code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": p, "config": {"Dhcp4": {"subnet4": []}}},
            path_env=bindir,
        )
        assert out["ok"] is True and out["backup"] is None
        assert json.loads(pathlib.Path(p).read_text()) == {"Dhcp4": {"subnet4": []}}
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o644

    def test_backup_written_and_mode_preserved(self, helper, tmp_path, monkeypatch):
        p, bindir = self._setup(helper, tmp_path, monkeypatch, existing={"old": True})
        os.chmod(p, 0o640)
        code, out, _ = _run(
            helper, "apply-config", {"service": "dhcp4", "path": p, "config": {"new": True}}, path_env=bindir
        )
        assert out["ok"] is True and out["backup"] == p + ".jen_backup"
        assert json.loads(pathlib.Path(p + ".jen_backup").read_text()) == {"old": True}
        assert json.loads(pathlib.Path(p).read_text()) == {"new": True}
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o640

    def test_exists_and_no_overwrite_refuses(self, helper, tmp_path, monkeypatch):
        p, bindir = self._setup(helper, tmp_path, monkeypatch, existing={"old": True})
        code, out, _ = _run(
            helper,
            "apply-config",
            {"service": "dhcp4", "path": p, "config": {"new": True}, "allow_overwrite": False},
            path_env=bindir,
        )
        assert out == {"ok": False, "error": "exists"}
        assert json.loads(pathlib.Path(p).read_text()) == {"old": True}

    def test_chown_calls_made_for_new_file(self, helper, tmp_path, monkeypatch):
        p, bindir = self._setup(helper, tmp_path, monkeypatch)
        chowns = []

        def spy(path, uid, gid):
            chowns.append((str(path), uid, gid))

        monkeypatch.setattr(os, "chown", spy)
        _run(helper, "apply-config", {"service": "dhcp4", "path": p, "config": {}}, path_env=bindir)
        assert (p + ".jen_apply_tmp", 0, 0) in chowns


class TestService:
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

        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "service", {"service": "dhcp6", "action": "enable"})
        assert out == {"ok": True, "unit": "isc-kea-dhcp6-server", "state": "active"}
        action_call = [c for c in calls if c[:2] == ["systemctl", "enable"]][0]
        assert action_call == ["systemctl", "enable", "--now", "isc-kea-dhcp6-server"]

    def test_no_unit(self, helper, monkeypatch):
        class Proc:
            returncode, stdout, stderr = 0, "not-found", ""

        monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Proc())
        code, out, _ = _run(helper, "service", {"service": "dhcp4", "action": "restart"})
        assert out == {"ok": False, "error": "no-unit"}

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
    def test_argv_and_output_tail(self, helper, monkeypatch):
        calls = []

        class Proc:
            returncode, stdout, stderr = 0, "installed ok\n", ""

        def fake_run(argv, **kw):
            calls.append(argv)
            return Proc()

        monkeypatch.setattr(helper.subprocess, "run", fake_run)
        code, out, _ = _run(helper, "install-package", {"service": "dhcp6"})
        assert out["ok"] is True
        assert calls[0] == ["apt-get", "update", "-qq"]
        assert calls[1] == ["apt-get", "install", "-y", "kea-dhcp6-server"]

    def test_failure_reported(self, helper, monkeypatch):
        class Proc:
            returncode, stdout, stderr = 100, "", "E: Unable to locate package\n"

        monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Proc())
        code, out, _ = _run(helper, "install-package", {"service": "dhcp4"})
        assert out["ok"] is False and "Unable to locate" in out["output"]
