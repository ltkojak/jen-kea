"""
tests/test_ddns.py
────────────────────
ddns.py had no dedicated test file before this — flagged in the Jen
maturity roadmap (Tier 1). The route's lookup-validator rejection path
was already covered in tests/test_security_fixes.py
(TestRemoteCommandValidators::test_ddns_lookup_route_rejects_invalid_host);
this file covers what wasn't: the auth boundary, the SSH log-fetch
branch's error handling, and — the actual regression this file exists
to guard against — that both SSH call sites in this route use the
hardened auth.ssh_cli_opts() (StrictHostKeyChecking=accept-new) rather
than the old inline StrictHostKeyChecking=no flags fixed in v4.4.8.
"""

from unittest.mock import MagicMock, patch


class TestDdnsPageAuth:
    def test_requires_login(self, client):
        r = client.get("/ddns", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()


class TestDdnsLogFetch:
    """v5.11.0 — the DDNS log read goes through jen.services.kea_host.tail_log
    (helper op `tail-log` / legacy `sudo tail`). Stub it here."""

    def _stub_tail(self, monkeypatch, result):
        from jen.services import kea_host

        calls = []
        monkeypatch.setattr(kea_host, "tail_log", lambda srv, path, lines=200: (calls.append((path, lines)), result)[1])
        return calls

    def test_ssh_host_not_configured(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        calls = self._stub_tail(monkeypatch, {"ok": True, "code": "ok", "lines": []})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"ssh host not configured" in r.data.lower()
        assert calls == []

    def test_successful_log_fetch_shows_newest_first(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        calls = self._stub_tail(monkeypatch, {"ok": True, "code": "ok", "lines": ["oldest", "newest"]})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert calls and calls[0][0] == extensions.DDNS_LOG
        body = r.data.decode()
        assert body.index("newest") < body.index("oldest")  # reversed for display

    def test_missing_log_file(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        self._stub_tail(monkeypatch, {"ok": False, "code": "missing", "detail": "log file not found"})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"log file not found" in r.data.lower()

    def test_ssh_error_is_reported(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        self._stub_tail(monkeypatch, {"ok": False, "code": "error", "detail": "connection timed out"})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"ssh error" in r.data.lower()


class TestDdnsSshLookupProvider:
    """dns_provider='ssh' does a dig/host lookup over SSH — same hardened
    ssh_cli_opts() regression guard as the log-fetch path above."""

    def test_ssh_lookup_uses_hardened_ssh_opts(self, logged_in_client, monkeypatch):
        import configparser

        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")  # skip log fetch branch

        # extensions.cfg is a session-shared global (built once by
        # _patch_extensions()) — swap the whole reference via monkeypatch
        # rather than mutating it in place, so the original is restored
        # automatically at teardown instead of leaking a "ddns" section
        # into every test that runs after this one.
        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["ddns"] = {"dns_provider": "ssh"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        fake_active_server = {"ssh_host": "10.0.0.5", "ssh_user": "kea"}
        fake_lookup_result = MagicMock(returncode=0, stdout="10.99.0.50\n", stderr="")

        with (
            patch("jen.services.kea.get_active_kea_server", return_value=fake_active_server),
            patch("jen.routes.ddns.subprocess.run", return_value=fake_lookup_result) as mock_run,
        ):
            r = logged_in_client.get("/ddns", query_string={"host": "test-host.local"})
            assert r.status_code == 200
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "StrictHostKeyChecking=accept-new" in call_args
            assert "StrictHostKeyChecking=no" not in call_args
