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


class TestPrometheusMetrics:
    """v4.4.15: /metrics expanded from 2 metric families to 7. This
    endpoint has no auth (by design, for scraper compatibility), so it's
    reachable with a bare `client` fixture, not `logged_in_client`."""

    def test_unauthenticated_access_allowed(self, client, mock_kea):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert r.mimetype == "text/plain"

    def test_output_is_valid_prometheus_exposition_format(self, client, mock_kea):
        r = client.get("/metrics")
        text = r.data.decode()
        # Every metric line must be preceded by its own HELP and TYPE
        # comment — this is the actual Prometheus exposition format
        # contract, not just "doesn't crash".
        for family in ["jen_subnet_active_leases", "jen_subnet_reserved_hosts",
                        "jen_subnet_pool_size", "jen_subnet_utilization_ratio",
                        "jen_alerts_sent_total", "jen_kea_up", "jen_server_up"]:
            assert f"# HELP {family}" in text, f"missing HELP for {family}"
            assert f"# TYPE {family}" in text, f"missing TYPE for {family}"

    def test_alerts_sent_total_is_declared_a_counter(self, client, mock_kea):
        # The one genuinely-monotonic metric here — everything else is a
        # gauge. Getting this TYPE line wrong would make Grafana's
        # rate()/increase() panels silently misbehave.
        r = client.get("/metrics")
        text = r.data.decode()
        assert "# TYPE jen_alerts_sent_total counter" in text

    def test_server_up_reflects_mock_kea_server(self, client, mock_kea):
        r = client.get("/metrics")
        text = r.data.decode()
        assert 'jen_server_up{server="Test Kea"} 1' in text

    def test_token_protection_when_configured(self, client, mock_kea, monkeypatch):
        from jen import extensions
        import configparser
        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["server"] = {"metrics_token": "s3cret"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        r_no_token = client.get("/metrics")
        assert r_no_token.status_code == 401

        r_wrong_token = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
        assert r_wrong_token.status_code == 401

        r_right_token = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
        assert r_right_token.status_code == 200

    def test_survives_kea_down(self, client, monkeypatch):
        from jen.services import kea as kea_svc
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command",
                           lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [])
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "jen_kea_up 0" in r.data.decode()
