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


class TestHaStatusDerivation:
    """v4.4.17: this whole class exists because a first draft of the
    active/degraded derivation logic was wrong on the most common real
    case (healthy hot-standby) — caught only by actually running it
    against realistic scenarios before shipping, not by inspection.
    These tests go through the real /servers route end to end, not the
    derivation logic in isolation, so a future regression in how the
    route wires kea.get_all_server_status() into the template would
    also be caught here."""

    def _servers_config(self):
        return [
            {"id": 1, "name": "Primary", "ssh_host": "", "ssh_user": "",
             "api_url": "http://localhost:18000", "api_user": "test",
             "api_pass": "test", "kea_conf": "", "role": "primary"},
            {"id": 2, "name": "Standby", "ssh_host": "", "ssh_user": "",
             "api_url": "http://localhost:18001", "api_user": "test",
             "api_pass": "test", "kea_conf": "", "role": "standby"},
        ]

    def test_healthy_hot_standby_only_primary_is_active(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc
        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(extensions.cfg, "get", lambda section, key, fallback=None:
                            "hot-standby" if (section, key) == ("kea", "ha_mode") else fallback)
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [
            {"server": cfg[0], "up": True, "ha_state": "hot-standby", "ha_partner": "hot-standby", "version": "2.4.0"},
            {"server": cfg[1], "up": True, "ha_state": "hot-standby", "ha_partner": "hot-standby", "version": "2.4.0"},
        ])
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        # Only Primary should carry the ACTIVE marker, not both.
        assert r.data.count(b"ACTIVE") == 1
        assert b"no working backup" not in r.data.lower()

    def test_primary_down_standby_active_and_degraded_warning_shown(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc
        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(extensions.cfg, "get", lambda section, key, fallback=None:
                            "hot-standby" if (section, key) == ("kea", "ha_mode") else fallback)
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [
            {"server": cfg[0], "up": False, "ha_state": None, "ha_partner": None, "version": ""},
            {"server": cfg[1], "up": True, "ha_state": "partner-down", "ha_partner": "unavailable", "version": "2.4.0"},
        ])
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert b"no working backup" in r.data.lower()
        assert r.data.count(b"ACTIVE") == 1  # Standby, not Primary

    def test_load_balancing_both_active_no_warning(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc
        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(extensions.cfg, "get", lambda section, key, fallback=None:
                            "load-balancing" if (section, key) == ("kea", "ha_mode") else fallback)
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [
            {"server": cfg[0], "up": True, "ha_state": "load-balancing", "ha_partner": "load-balancing", "version": "2.4.0"},
            {"server": cfg[1], "up": True, "ha_state": "load-balancing", "ha_partner": "load-balancing", "version": "2.4.0"},
        ])
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert r.data.count(b"ACTIVE") == 2
        assert b"no working backup" not in r.data.lower()
