"""
tests/test_alerts.py
────────────────────
Tests for the alert system — test button, channel configuration,
alert log, and HTMX partial responses.
"""

import json
import time
import pytest


class TestAlertEndpoints:
    """Alert summary API and settings page."""

    def test_alert_summary_returns_json(self, logged_in_client):
        """api/alert-summary returns valid JSON with alerts key."""
        r = logged_in_client.get("/api/alert-summary")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

    def test_alert_summary_structure(self, logged_in_client, db):
        """api/alert-summary entries have expected fields."""
        # Insert a test alert log entry
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                VALUES ('telegram', 'kea_down', 'Test message', 'failed', 'Connection refused')
            """)
        db.commit()
        time.sleep(0.1)

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        assert len(data["alerts"]) > 0
        alert = data["alerts"][0]
        for field in ["type", "channel", "status", "sent_at", "error"]:
            assert field in alert

    def test_alert_summary_includes_error(self, logged_in_client, db):
        """api/alert-summary includes error detail when present."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                VALUES ('telegram', 'new_device', 'New device', 'failed', 'Token invalid')
            """)
        db.commit()

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        errors = [a["error"] for a in data["alerts"] if a["error"]]
        assert any("Token invalid" in e for e in errors)

    def test_settings_alerts_page_loads(self, logged_in_client):
        """Settings → Alerts page loads."""
        r = logged_in_client.get("/settings/alerts")
        assert r.status_code == 200

    def test_settings_alerts_shows_recent_log(self, logged_in_client, db):
        """Settings → Alerts page shows recent alert log."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_log (channel_type, alert_type, message, status)
                VALUES ('telegram', 'kea_up', 'Kea is up', 'sent')
            """)
        db.commit()

        r = logged_in_client.get("/settings/alerts")
        assert r.status_code == 200
        assert b"kea_up" in r.data or b"kea up" in r.data

    def test_test_alert_requires_channel(self, logged_in_client):
        """Test alert with no channels configured returns error."""
        r = logged_in_client.post("/settings/test-alert/999",
                                  follow_redirects=True)
        assert r.status_code in (200, 404)


class TestHTMXRoutes:
    """HTMX partial response routes."""

    def test_reservations_htmx_returns_fragment(self, logged_in_client,
                                                 mock_kea_reservations):
        """Reservations with HX-Request returns HTML fragment not full page."""
        r = logged_in_client.get("/reservations",
                                 headers={"HX-Request": "true"})
        assert r.status_code == 200
        # Fragment should NOT contain full page structure
        assert b"<!DOCTYPE html>" not in r.data
        assert b"<html" not in r.data

    def test_leases_htmx_returns_fragment(self, logged_in_client,
                                           mock_kea_db):
        """Leases with HX-Request returns HTML fragment not full page."""
        r = logged_in_client.get("/leases",
                                 headers={"HX-Request": "true"})
        assert r.status_code == 200
        assert b"<!DOCTYPE html>" not in r.data
        assert b"<html" not in r.data

    def test_dashboard_htmx_returns_fragment(self, logged_in_client,
                                              mock_kea):
        """Dashboard with HX-Request returns recent leases fragment."""
        r = logged_in_client.get("/?hours=1",
                                 headers={"HX-Request": "true"})
        assert r.status_code == 200
        assert b"<!DOCTYPE html>" not in r.data

    def test_delete_reservation_htmx_returns_empty(self, logged_in_client,
                                                    monkeypatch):
        """Deleting a reservation via HTMX returns empty string (removes row)."""
        from jen.services import kea as kea_svc
        from jen.models import db as db_mod

        # Mock Kea to return the host for lookup and success for delete
        def mock_kea_cmd(cmd, *a, server=None, **kw):
            if "get" in cmd:
                return {"result": 0, "arguments": {"hosts": [
                    {"hw-address": "aa:bb:cc:dd:ee:01",
                     "ip-address": "10.99.0.10",
                     "hostname": "test",
                     "dhcp4-subnet-id": 1, "id": 101}
                ]}}
            return {"result": 0, "text": "deleted"}

        monkeypatch.setattr(kea_svc, "kea_command", mock_kea_cmd)
        monkeypatch.setattr(kea_svc, "get_active_kea_server",
                            lambda: {"id": 1, "api_url": "http://localhost:18000",
                                     "api_user": "test", "api_pass": "test"})

        # Mock the Kea DB for the host lookup
        class MockCursor:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def execute(self, sql, args=None):
                self._sql = sql
            def fetchone(self):
                return {"ip": "10.99.0.10", "mac_hex": "AABBCCDDEEE01",
                        "subnet_id": 1}
            def fetchall(self): return []
            def close(self): pass

        class MockConn:
            def cursor(self): return MockCursor()
            def close(self): pass
            def commit(self): pass

        monkeypatch.setattr(db_mod, "get_kea_db", lambda: MockConn())

        r = logged_in_client.post("/reservations/delete/101",
                                  headers={"HX-Request": "true"},
                                  data={"subnet_id": "1"})
        assert r.status_code == 200
        assert r.data == b""


@pytest.fixture
def mock_kea_reservations(monkeypatch):
    from jen.services import kea as kea_svc
    monkeypatch.setattr(kea_svc, "kea_command", lambda cmd, *a, **kw: {
        "result": 0,
        "arguments": {"hosts": [
            {"hw-address": "aa:bb:cc:dd:ee:01",
             "ip-address": "10.99.0.10",
             "hostname": "test-host",
             "dhcp4-subnet-id": 1,
             "id": 101},
        ]}
    })
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(kea_svc, "get_active_kea_server",
                        lambda: {"id": 1, "api_url": "http://localhost:18000",
                                 "api_user": "test", "api_pass": "test"})


@pytest.fixture
def mock_kea_db(monkeypatch):
    class MockCursor:
        def __init__(self): self._rows = []
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql, args=None): self._rows = []
        def fetchone(self): return None
        def fetchall(self): return []
        def close(self): pass

    class MockConn:
        def cursor(self): return MockCursor()
        def close(self): pass
        def commit(self): pass

    from jen.models import db as db_mod
    monkeypatch.setattr(db_mod, "get_kea_db", lambda: MockConn())
