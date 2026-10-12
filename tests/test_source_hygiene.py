"""
tests/test_source_hygiene.py
────────────────────────────
v5.69.0-beta.5 (Q174): the P3 sweep's pure checks - the drift the register found once is held by a test that reads the whole tree, and the small behaviours that had no test of their
own get one here. Nothing in this file needs a database (`pytest --noconftest tests/test_source_hygiene.py`), except the one test that builds the app.
"""

import ast
import pathlib
import threading

import pytest


def _py_files(root="jen"):
    return sorted(pathlib.Path(root).rglob("*.py"))


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"))


# ── one definition, every use ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_one_ip_to_int():
    found = []
    for p in _py_files():
        for node in ast.walk(_tree(p)):
            if isinstance(node, ast.FunctionDef) and node.name.lstrip("_") == "ip_to_int":
                found.append(p.as_posix())
    assert found == ["jen/services/netutil.py"]


class TestIpToInt:
    def test_the_one_body(self):
        from jen.services.netutil import ip_to_int

        assert ip_to_int("10.0.0.1") == 167772161
        assert ip_to_int(" 10.0.0.1 ") == 167772161
        for bad in ("", None, "10.0.0", "10.0.0.256", "::1", "host", "10.0.0.1/24"):
            assert ip_to_int(bad) is None, bad


def test_no_kea_reply_is_read_with_a_default_that_null_defeats():
    """Kea can answer `"arguments": null`; `.get("arguments", {})` then returns None and the next `.get` raises. Every read is `(x.get("arguments") or {})`."""
    found = []
    for p in _py_files():
        for node in ast.walk(_tree(p)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "arguments"
            ):
                found.append(f"{p.as_posix()}:{node.lineno}")
    assert found == []


# routes whose function renders an htmx partial AND flashes - each with the reason the flash is not in the partial's branch
_LIST_PAGE_REASON = (
    "the list page is the full page AND its own search-as-you-type swap: its load-error sentence is flashed for the page and is not shown in a swap (the table then reads empty). "
    "Carrying a notice through htmx (an HX-Trigger and a banner) is a feature, recorded in the register, not a one-liner"
)
_FLASH_WITH_A_PARTIAL_REVIEWED: dict = {
    "jen/routes/devices.py::devices": _LIST_PAGE_REASON,
    "jen/routes/devices.py::_devices_v6": _LIST_PAGE_REASON,
    "jen/routes/leases.py::leases": _LIST_PAGE_REASON,
    "jen/routes/leases.py::_leases_v6": _LIST_PAGE_REASON,
    "jen/routes/reservations.py::reservations": _LIST_PAGE_REASON,
    "jen/routes/reservations.py::_reservations_v6": _LIST_PAGE_REASON,
}


def test_an_htmx_partial_never_queues_a_flash():
    """A flash queued while answering a partial is shown on the NEXT full page, about something else. A route that renders a `_`-prefixed template carries its sentences IN the partial."""
    offenders = []
    for p in sorted(pathlib.Path("jen/routes").rglob("*.py")):
        for fn in ast.walk(_tree(p)):
            if not isinstance(fn, ast.FunctionDef):
                continue
            renders_partial = any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "render_template"
                and n.args
                and isinstance(n.args[0], ast.Constant)
                and str(n.args[0].value).startswith("_")
                for n in ast.walk(fn)
            )
            if not renders_partial:
                continue
            # flash() calls whose nearest enclosing function is THIS one (not a nested helper that decides for itself)
            nested = [n for n in ast.walk(fn) if isinstance(n, ast.FunctionDef) and n is not fn]
            inside_nested = {id(c) for f in nested for c in ast.walk(f)}
            for n in ast.walk(fn):
                if (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name)
                    and n.func.id == "flash"
                    and id(n) not in inside_nested
                ):
                    key = f"{p.as_posix()}::{fn.name}"
                    if key not in _FLASH_WITH_A_PARTIAL_REVIEWED:
                        offenders.append(f"{key}:{n.lineno}")
    assert offenders == [], offenders


def test_the_reviewed_flash_list_is_live():
    for key in _FLASH_WITH_A_PARTIAL_REVIEWED:
        path, name = key.split("::")
        assert any(isinstance(n, ast.FunctionDef) and n.name == name for n in ast.walk(_tree(pathlib.Path(path)))), key


def test_every_rule_and_method_has_one_endpoint(app):
    """The same path and method on two endpoints means the second is unreachable (`/api/saved-searches` was defined in dashboard.py and again in search.py)."""
    reviewed: dict = {}  # (rule, method): why two endpoints share it
    seen = {}
    for r in app.url_map.iter_rules():
        for m in r.methods - {"HEAD", "OPTIONS"}:
            key = (r.rule, m)
            if key in seen and key not in reviewed:
                pytest.fail(f"{key}: {seen[key]} and {r.endpoint}")
            seen.setdefault(key, r.endpoint)


# ── Kea host: what "the helper is missing" is ───────────────────────────────────────────────────────────────────────────────────────────────────


class TestOnlyTheFirstStderrLineSaysTheHelperIsMissing:
    @pytest.mark.parametrize(
        "err",
        [
            "sudo: a password is required",
            "bash: line 1: /usr/local/sbin/jen-kea-helper: No such file or directory",
            "sudo: jen-kea-helper: command not found",
        ],
    )
    def test_the_refusals_sudo_and_the_shell_write(self, err):
        from jen.services import kea_host

        assert kea_host._looks_missing(err) is True

    def test_a_later_line_is_not_a_missing_helper(self):
        from jen.services import kea_host

        err = "Traceback (most recent call last):\n  File x\nFileNotFoundError: [Errno 2] No such file or directory: '/etc/kea/x'"
        assert kea_host._looks_missing(err) is False
        assert kea_host._looks_missing("") is False

    def test_helper_call_treats_a_traceback_as_an_error_not_as_missing(self, monkeypatch):
        from jen.services import kea_host

        class Chan:
            def shutdown_write(self):
                pass

        class Out:
            def __init__(self, text):
                self._t = text

            def read(self):
                return self._t.encode()

        class SSH:
            def exec_command(self, cmd, timeout=0):
                err = "Traceback (most recent call last):\nFileNotFoundError: No such file or directory: 'x'"
                stdin = type("S", (), {"write": lambda s, d: None, "channel": Chan()})()
                return stdin, Out(""), Out(err)

            def close(self):
                pass

        monkeypatch.setattr(kea_host, "_open_ssh", lambda server: SSH())
        with pytest.raises(kea_host.HelperError) as e:
            kea_host.helper_call({"id": 1}, "version", {})
        assert not isinstance(e.value, kea_host.HelperMissing)


class TestTheGrantProbeIsOneSessionUnlessAskedToExplain:
    def test_check_helpers_yes_no_does_not_list_sudoers(self, monkeypatch):
        from jen.services import kea_host

        calls = []
        monkeypatch.setattr(
            kea_host,
            "_legacy_ssh",
            lambda s, cmd, timeout=30: calls.append(cmd) or ("", "sudo: a password is required", 1),
        )
        assert kea_host.legacy_grant_present({"id": 1, "ssh_host": "h"}) is False
        assert calls == ["sudo -n /usr/bin/python3 -c 'print(1)'"]

    def test_the_settings_page_still_gets_the_explanation(self, monkeypatch):
        from jen.services import kea_host

        calls = []
        monkeypatch.setattr(
            kea_host,
            "_legacy_ssh",
            lambda s, cmd, timeout=30: calls.append(cmd) or ("", "sudo: a password is required", 1),
        )
        status = kea_host.legacy_grant_status({"id": 1, "ssh_host": "h"})
        assert status["ok"] is False and len(calls) == 2 and calls[1] == "sudo -n -l"


class TestTwoServersRecordedAtOnceBothStay:
    def test_a_concurrent_record_does_not_lose_a_row(self, monkeypatch):
        import json
        import time

        from jen.services import kea_host

        store = {}

        class FakeUser:
            @staticmethod
            def get_global_setting(key, default=None):
                return store.get(key, default)

            @staticmethod
            def set_global_setting(key, value):
                time.sleep(0.05)  # the window between one thread's read and its write
                store[key] = value
                return True

        monkeypatch.setattr(kea_host, "_user", lambda: FakeUser)
        threads = [threading.Thread(target=kea_host.record_helper_status, args=(i, 7)) for i in (1, 2, 3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(json.loads(store[kea_host._HELPER_STATUS_KEY])) == ["1", "2", "3"]


# ── Kea client ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestProbeCommandAnswersOddRepliesWithASentence:
    def _probe(self, monkeypatch, body):
        from jen.services import kea

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return body

        monkeypatch.setattr(kea.http, "post", lambda *a, **k: Resp())
        return kea.probe_command("http://kea:8000", "u", "p", "version-get")

    def test_an_empty_list(self, monkeypatch):
        result, err = self._probe(monkeypatch, [])
        assert result is None and "empty list" in err

    def test_a_reply_that_is_not_an_object(self, monkeypatch):
        result, err = self._probe(monkeypatch, ["nope"])
        assert result is None and "not a reply" in err

    def test_null_arguments_do_not_raise_in_the_version_read(self, monkeypatch):
        from jen.services import kea

        monkeypatch.setattr(
            kea, "probe_command", lambda *a, **k: ({"result": 0, "arguments": None, "text": "2.6.0"}, "")
        )
        assert kea.test_connection("http://kea:8000", "u", "p") == ("2.6.0", "")


def test_the_v6_form_says_when_kea_did_not_answer(monkeypatch):
    from jen.services import kea6

    monkeypatch.setattr(kea6, "kea6_command", lambda *a, **k: {"result": 1, "text": "down"})
    data = kea6.get_subnet6_kea_data(100)
    assert data["pools"] == [] and "could not be read" in data["error"]
    monkeypatch.setattr(kea6, "kea6_command", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert "could not be read" in kea6.get_subnet6_kea_data(100)["error"]


def test_the_v6_pool_does_not_share_a_plaintext_v4_pool(monkeypatch):
    from jen import extensions
    from jen.models import db

    for name in ("HOST", "USER", "PASS", "NAME"):
        monkeypatch.setattr(extensions, f"KEA6_DB_{name}", "same")
        monkeypatch.setattr(extensions, f"KEA_DB_{name}", "same")
    monkeypatch.setattr(extensions, "KEA6_DB_PORT", 3306)
    monkeypatch.setattr(extensions, "KEA_DB_PORT", 3306)
    monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "")
    monkeypatch.setattr(extensions, "KEA6_DB_SSL_CA", "")
    assert db._kea6_targets_same_db() is True
    monkeypatch.setattr(extensions, "KEA6_DB_SSL_CA", "/etc/jen/ssl/ca.pem")
    assert db._kea6_targets_same_db() is False


# ── config, the fallback redirect, files ─────────────────────────────────────────────────────────────────────────────────────────────────────


class TestAHandMadeConfigWithoutKeaDoesNotTraceback:
    def test_derive_kea_servers_without_the_kea_section(self):
        import configparser

        from jen.config import AppConfig

        cfg = configparser.ConfigParser()
        cfg.read_string("[jen_db]\nhost=h\nuser=u\npassword=p\n")
        servers = AppConfig.derive_kea_servers(cfg, quiet=True)
        assert servers and servers[0]["api_url"] == ""


class TestTheFallbackRedirect:
    def test_it_keeps_the_query_and_refuses_a_host_it_would_not_serve(self):
        import run

        resp = run._http_redirect_response("jen.lan:5050", "leases", b"search=a%20b&page=2", 8443)
        assert resp.status_code == 301 and resp.headers["Location"] == "https://jen.lan:8443/leases?search=a%20b&page=2"
        assert run._http_redirect_response("jen.lan", "", b"", 8443).headers["Location"] == "https://jen.lan:8443/"
        body, status = run._http_redirect_response("evil.example/x?y", "", b"", 8443)
        assert status == 400


class TestOneAnswerForAFileThatIsAbsentOrUnreadable:
    def test_the_same_sentence_either_way(self, tmp_path):
        from jen.services import auth

        missing = str(tmp_path / "nope.pem")
        directory = str(tmp_path)
        real = tmp_path / "ca.pem"
        real.write_text("x")
        assert auth.usable_file(str(real)) is True
        assert auth.usable_file(missing) is False and auth.usable_file(directory) is False
        assert auth.usable_file(None) is False
        text = auth.unusable_file_message("CA bundle", "/p")
        assert "does not exist or Jen cannot read it" in text and "not found" not in text


class TestTheImportSpoolIsSwept:
    def test_only_old_spool_files_go(self, tmp_path, monkeypatch):
        import os
        import time

        from jen import extensions
        from jen.routes import database

        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(tmp_path))
        old = tmp_path / "jen_import_old.json.gz"
        fresh = tmp_path / "jen_import_fresh.json.gz"
        other = tmp_path / "keep_me.json.gz"
        for f in (old, fresh, other):
            f.write_bytes(b"x")
        past = time.time() - 7200
        os.utime(old, (past, past))
        os.utime(other, (past, past))
        assert database._sweep_import_spool() == 1
        assert not old.exists() and fresh.exists() and other.exists()


class TestAPluginPackageHasASizeCap:
    def test_a_declared_length_over_the_cap_is_refused_before_reading(self):
        from jen.services import plugins

        class Resp:
            headers = {"Content-Length": str(60 * 1024 * 1024)}
            content = b""

        with pytest.raises(plugins._ZipTooBig):
            plugins._read_capped(Resp(), plugins.MAX_PLUGIN_ZIP_BYTES)

    def test_a_body_over_the_cap_without_a_header_is_refused(self):
        from jen.services import plugins

        class Resp:
            headers = {}
            content = b"x" * 11

        with pytest.raises(plugins._ZipTooBig):
            plugins._read_capped(Resp(), 10)
        Resp.content = b"x" * 10
        assert plugins._read_capped(Resp(), 10) == b"x" * 10

    def test_the_root_updater_refuses_it_too(self):
        import http.server
        import importlib.util
        import threading as th

        spec = importlib.util.spec_from_file_location("jen_update_root_q174", pathlib.Path("jen-update-root.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                if self.path == "/declared":
                    self.send_header("Content-Length", "5000")
                self.end_headers()
                self.wfile.write(b"x" * 5000)

            def log_message(self, *a):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        t = th.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            assert len(mod.fetch_bytes_with_sha256(base + "/declared", max_bytes=10000)[0]) == 5000
            with pytest.raises(RuntimeError):
                mod.fetch_bytes_with_sha256(base + "/declared", max_bytes=1000)
            with pytest.raises(RuntimeError):
                mod.fetch_bytes_with_sha256(base + "/undeclared", max_bytes=1000)
        finally:
            server.shutdown()


class TestTheCandidateUrlIsAKeaUrlShape:
    @pytest.mark.parametrize("url", ["http://kea:8004", "https://10.0.0.5:8000/", "http://[::1]:8004"])
    def test_scheme_host_port_is_one(self, url):
        from jen.routes.settings.infrastructure import _is_kea_url_shape

        assert _is_kea_url_shape(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://u:p@kea:8004",
            "http://kea:8004/admin",
            "http://kea:8004/?x=1",
            "http://kea:8004/#f",
            "http://kea:8004;x",
        ],
    )
    def test_anything_else_is_not(self, url):
        from jen.routes.settings.infrastructure import _is_kea_url_shape

        assert _is_kea_url_shape(url) is False


# ── settings that are not numbers ────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestASettingThatIsNotANumberIsTheDefault:
    def test_stale_device_days(self, monkeypatch):
        from jen.models import user

        for stored, expect in (("14", 14), ("abc", 30), ("", 30), ("-3", 30), ("0", 30)):
            monkeypatch.setattr(user, "get_global_setting", lambda key, default=None, v=stored: v)
            assert user.get_stale_device_days() == expect, stored

    def test_the_alert_loops_integer_settings(self, monkeypatch):
        from jen.services import alerts

        monkeypatch.setattr(alerts, "__get_global_setting", lambda key, default=None: "oops", raising=False)
        monkeypatch.setitem(alerts.__dict__, "__get_global_setting", lambda key, default=None: "oops")
        assert alerts._int_setting("alert_threshold_pct", 80) == 80
        monkeypatch.setitem(alerts.__dict__, "__get_global_setting", lambda key, default=None: "75")
        assert alerts._int_setting("alert_threshold_pct", 80) == 75


class TestAnEmptyMacIsAKeyLikeAnyOther:
    def test_a_group_with_no_mac_that_already_has_a_row_is_not_new(self):
        from jen.services import client_problems as cp

        class Cur:
            def __init__(self):
                self.rows = []

            def execute(self, sql, params=None):
                self.rows = [{"kind": "nak", "mac": "", "ip": "10.0.0.5", "scope_key": -1}] if "mac IN" in sql else []

            def fetchall(self):
                return self.rows

        groups = {("nak", "", "10.0.0.5", None): {"last_ts": 5}, ("nak", "", "10.0.0.6", None): {"last_ts": 9}}
        kept, dropped = cp._cap_new_keys(Cur(), 1, groups, limit=0)
        assert ("nak", "", "10.0.0.5", None) in kept and dropped == 1  # the known one stays; only the new one is capped
