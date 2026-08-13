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

from unittest.mock import patch, MagicMock

import pytest


class TestDdnsPageAuth:
    def test_requires_login(self, client):
        r = client.get("/ddns", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()


class TestDdnsLogFetch:
    def test_ssh_host_not_configured(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        with patch("jen.routes.ddns.subprocess.run") as mock_run:
            r = logged_in_client.get("/ddns")
            assert r.status_code == 200
            assert b"ssh host not configured" in r.data.lower()
            mock_run.assert_not_called()

    def test_successful_log_fetch_uses_hardened_ssh_opts(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SSH_USER", "kea")
        fake_result = MagicMock(returncode=0, stdout="line1\nline2\n", stderr="")
        with patch("jen.routes.ddns.subprocess.run", return_value=fake_result) as mock_run:
            r = logged_in_client.get("/ddns")
            assert r.status_code == 200
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "StrictHostKeyChecking=accept-new" in call_args
            assert "StrictHostKeyChecking=no" not in call_args

    def test_missing_log_file(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SSH_USER", "kea")
        fake_result = MagicMock(returncode=1, stdout="", stderr="No such file or directory")
        with patch("jen.routes.ddns.subprocess.run", return_value=fake_result):
            r = logged_in_client.get("/ddns")
            assert r.status_code == 200
            assert b"log file not found" in r.data.lower()

    def test_ssh_timeout(self, logged_in_client, monkeypatch):
        import subprocess
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SSH_USER", "kea")
        with patch("jen.routes.ddns.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=15)):
            r = logged_in_client.get("/ddns")
            assert r.status_code == 200
            assert b"timed out" in r.data.lower()


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

        with patch("jen.services.kea.get_active_kea_server", return_value=fake_active_server), \
             patch("jen.routes.ddns.subprocess.run", return_value=fake_lookup_result) as mock_run:
            r = logged_in_client.get("/ddns", query_string={"host": "test-host.local"})
            assert r.status_code == 200
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "StrictHostKeyChecking=accept-new" in call_args
            assert "StrictHostKeyChecking=no" not in call_args
