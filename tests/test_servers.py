"""
tests/test_servers.py
──────────────────────
servers.py had no dedicated test coverage before this — flagged in the
Jen maturity roadmap (Tier 1) as one of the files where real bugs were
found without any test having caught them (the StrictHostKeyChecking=no
gap, fixed in v4.4.8, lived in this exact file). Covers the auth
boundary on both routes and the restart route's error-handling paths
without ever actually invoking a real SSH connection.
"""

from unittest.mock import patch, MagicMock

import pytest

from tests.conftest import restricted_client as _restricted_client


class TestServersPageAuth:
    def test_requires_login(self, client):
        r = client.get("/servers", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()

    def test_loads_for_logged_in_user(self, logged_in_client, mock_kea):
        r = logged_in_client.get("/servers")
        assert r.status_code == 200


class TestRestartRouteAuth:
    def test_requires_login(self, client):
        r = client.post("/servers/restart/1", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()

    def test_forbidden_for_viewer(self, client, db):
        _restricted_client(client, db, allowed_subnets=None, role="viewer",
                            username="servers_viewer1")
        r = client.post("/servers/restart/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"admin access required" in r.data.lower()


class TestRestartRouteBehavior:
    """These never invoke a real subprocess — subprocess.run is mocked
    throughout, so this only tests Jen's own logic (server lookup,
    ssh_host presence check, flash messaging, audit logging), not SSH
    connectivity itself."""

    def test_nonexistent_server_id(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [
            {"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea", "api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test", "kea_conf": "", "role": "primary"}
        ])
        with patch("jen.routes.servers.subprocess.run") as mock_run:
            r = logged_in_client.post("/servers/restart/999", follow_redirects=True)
            assert r.status_code == 200
            assert b"not found" in r.data.lower()
            mock_run.assert_not_called()

    def test_server_without_ssh_configured(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [
            {"id": 1, "name": "No SSH Kea", "ssh_host": "", "ssh_user": "", "api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test", "kea_conf": "", "role": "primary"}
        ])
        with patch("jen.routes.servers.subprocess.run") as mock_run:
            r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
            assert r.status_code == 200
            assert b"ssh not configured" in r.data.lower()
            mock_run.assert_not_called()

    def test_successful_restart_uses_hardened_ssh_opts(self, logged_in_client, monkeypatch):
        # v4.4.8 regression guard: confirm the restart command actually
        # goes through auth.ssh_cli_opts() (StrictHostKeyChecking=accept-new)
        # rather than the old inline StrictHostKeyChecking=no flags.
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [
            {"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea", "api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test", "kea_conf": "", "role": "primary"}
        ])
        fake_result = MagicMock(returncode=0, stderr=b"")
        with patch("jen.routes.servers.subprocess.run", return_value=fake_result) as mock_run:
            r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
            assert r.status_code == 200
            assert b"restarted" in r.data.lower()
            assert mock_run.called
            call_args = mock_run.call_args[0][0]  # the command list
            assert "ssh" in call_args
            assert "StrictHostKeyChecking=accept-new" in call_args
            assert "StrictHostKeyChecking=no" not in call_args

    def test_failed_restart_shows_stderr(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [
            {"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea", "api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test", "kea_conf": "", "role": "primary"}
        ])
        fake_result = MagicMock(returncode=1, stderr=b"Permission denied")
        with patch("jen.routes.servers.subprocess.run", return_value=fake_result):
            r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
            assert r.status_code == 200
            assert b"failed" in r.data.lower()
