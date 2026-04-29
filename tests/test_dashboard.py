"""
tests/test_dashboard.py
───────────────────────
Tests for dashboard page and api/stats endpoint.
"""

import json
import pytest


class TestDashboard:
    """Dashboard page — GET /"""

    def test_dashboard_loads(self, logged_in_client, mock_kea):
        """Dashboard returns 200 for authenticated user."""
        r = logged_in_client.get("/")
        assert r.status_code == 200

    def test_dashboard_contains_subnet_cards(self, logged_in_client, mock_kea):
        """Dashboard renders subnet cards from SUBNET_MAP."""
        r = logged_in_client.get("/")
        assert b"Test Network" in r.data

    def test_dashboard_no_kea_graceful(self, logged_in_client, monkeypatch):
        """Dashboard loads even when Kea is unreachable."""
        from jen.services import kea as kea_svc
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [{
            "server": {"id": 1, "name": "Test Kea"}, "up": False,
            "ha_state": None, "version": "", "role": "primary"
        }])
        r = logged_in_client.get("/")
        assert r.status_code == 200

    def test_dashboard_hours_param(self, logged_in_client, mock_kea):
        """Dashboard accepts valid hours parameter."""
        for hours in ["0.5", "1", "4", "8", "12", "24"]:
            r = logged_in_client.get(f"/?hours={hours}")
            assert r.status_code == 200

    def test_dashboard_invalid_hours_defaults(self, logged_in_client, mock_kea):
        """Invalid hours parameter falls back to default."""
        r = logged_in_client.get("/?hours=999")
        assert r.status_code == 200


class TestApiStats:
    """API stats endpoint — GET /api/stats"""

    def test_api_stats_returns_json(self, logged_in_client, mock_kea):
        """api/stats returns valid JSON."""
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, dict)

    def test_api_stats_has_kea_up(self, logged_in_client, mock_kea):
        """api/stats includes kea_up field."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "kea_up" in data

    def test_api_stats_has_servers(self, logged_in_client, mock_kea):
        """api/stats includes servers array."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "servers" in data
        assert isinstance(data["servers"], list)

    def test_api_stats_has_subnets(self, logged_in_client, mock_kea):
        """api/stats includes subnets data."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "subnets" in data or "stats" in data

    def test_api_stats_kea_down_graceful(self, logged_in_client, monkeypatch):
        """api/stats returns valid JSON even when Kea is down."""
        from jen.services import kea as kea_svc
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command",
                           lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [])
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data.get("kea_up") is False
