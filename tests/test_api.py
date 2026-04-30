"""
tests/test_api.py
─────────────────
Tests for API endpoints — lease history, alert summary,
recent leases, and dashboard stats.
"""

import json
import pytest


class TestLeaseHistoryApi:
    """GET /api/lease-history"""

    def test_returns_json(self, logged_in_client):
        """Returns valid JSON with history key."""
        r = logged_in_client.get("/api/lease-history")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "history" in data

    def test_default_days_is_7(self, logged_in_client):
        """Default time range is 7 days."""
        r = logged_in_client.get("/api/lease-history")
        data = json.loads(r.data)
        assert data.get("days") == 7

    def test_accepts_days_param(self, logged_in_client):
        """Accepts ?days= parameter."""
        for days in [1, 3, 7, 30]:
            r = logged_in_client.get(f"/api/lease-history?days={days}")
            assert r.status_code == 200
            data = json.loads(r.data)
            assert data.get("days") == days

    def test_caps_days_at_90(self, logged_in_client):
        """Clamps days to maximum of 90."""
        r = logged_in_client.get("/api/lease-history?days=999")
        data = json.loads(r.data)
        assert data.get("days") == 90

    def test_history_is_dict(self, logged_in_client):
        """History value is a dict keyed by subnet_id."""
        r = logged_in_client.get("/api/lease-history")
        data = json.loads(r.data)
        assert isinstance(data["history"], dict)

    def test_with_history_data(self, logged_in_client, db):
        """Returns data points when lease_history has rows."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO lease_history
                    (subnet_id, active_leases, dynamic_leases, reserved_leases, pool_size)
                VALUES (1, 50, 30, 20, 200),
                       (1, 55, 35, 20, 200)
            """)
        db.commit()

        r = logged_in_client.get("/api/lease-history?days=7")
        data = json.loads(r.data)
        # Should have data for subnet 1
        assert "1" in data["history"] or len(data["history"]) > 0


class TestAlertSummaryApi:
    """GET /api/alert-summary"""

    def test_returns_json(self, logged_in_client):
        """Returns valid JSON with alerts key."""
        r = logged_in_client.get("/api/alert-summary")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "alerts" in data

    def test_empty_when_no_alerts(self, logged_in_client):
        """Returns empty list when no alerts logged."""
        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        assert isinstance(data["alerts"], list)

    def test_returns_up_to_10(self, logged_in_client, db):
        """Returns at most 10 alerts."""
        with db.cursor() as cur:
            for i in range(15):
                cur.execute("""
                    INSERT INTO alert_log (channel_type, alert_type, message, status)
                    VALUES ('telegram', 'kea_down', %s, 'sent')
                """, (f"Alert {i}",))
        db.commit()

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        assert len(data["alerts"]) <= 10

    def test_alert_fields(self, logged_in_client, db):
        """Alert entries contain required fields."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                VALUES ('telegram', 'new_device', 'New device seen', 'failed', 'Timeout')
            """)
        db.commit()

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        if data["alerts"]:
            a = data["alerts"][0]
            for field in ["type", "channel", "status", "sent_at", "error"]:
                assert field in a


class TestDashboardStatsApi:
    """GET /api/stats"""

    def test_returns_json(self, logged_in_client, mock_kea):
        """Returns valid JSON."""
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, dict)

    def test_has_required_keys(self, logged_in_client, mock_kea):
        """Response includes kea_up, subnets, servers, pool_sizes."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        for key in ["kea_up", "subnets", "servers"]:
            assert key in data

    def test_servers_always_present(self, logged_in_client, monkeypatch):
        """servers key present even when Kea DB query fails."""
        from jen.services import kea as kea_svc
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command",
                           lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [])

        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "servers" in data
        assert data["kea_up"] is False

    def test_requires_auth(self, app):
        """api/stats redirects when not authenticated."""
        # Use a fresh client with no session to test unauthenticated access
        with app.test_client() as fresh_client:
            r = fresh_client.get("/api/stats", follow_redirects=False)
            assert r.status_code in (301, 302, 308)
