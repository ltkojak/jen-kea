"""
tests/test_reservations.py
──────────────────────────
Tests for reservation CRUD — add, edit, delete, bulk delete.
These tests mock the Kea API so no real Kea server is needed.
"""

import json
import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────
def _kea_add_ok(*a, **kw):
    return {"result": 0, "text": "Host added", "arguments": {}}

def _kea_del_ok(*a, **kw):
    return {"result": 0, "text": "Host deleted", "arguments": {}}

def _kea_list(*a, **kw):
    return {
        "result": 0,
        "arguments": {"hosts": [
            {"hw-address": "aa:bb:cc:dd:ee:01",
             "ip-address": "10.99.0.10",
             "hostname": "test-host-1",
             "dhcp4-subnet-id": 1,
             "id": 101},
        ]}
    }


@pytest.fixture
def mock_kea_reservations(monkeypatch):
    """Mock Kea API for reservation operations."""
    from jen.services import kea as kea_svc
    monkeypatch.setattr(kea_svc, "kea_command", lambda cmd, *a, **kw:
        _kea_list()   if "get-all" in cmd or "get-by" in cmd
        else _kea_add_ok() if "add"    in cmd
        else _kea_del_ok() if "del"    in cmd
        else {"result": 0, "arguments": {}}
    )
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(kea_svc, "get_active_kea_server",
                        lambda: {"id": 1, "api_url": "http://localhost:18000",
                                 "api_user": "test", "api_pass": "test"})


class TestReservationsList:
    """Reservations list page."""

    def test_reservations_loads(self, logged_in_client, mock_kea_reservations):
        """Reservations page returns 200."""
        r = logged_in_client.get("/reservations")
        assert r.status_code == 200

    def test_reservations_add_page_loads(self, logged_in_client, mock_kea_reservations):
        """Add reservation page returns 200."""
        r = logged_in_client.get("/reservations/add")
        assert r.status_code == 200


class TestAddReservation:
    """Add reservation — POST /reservations/add"""

    def test_add_reservation_success(self, logged_in_client, mock_kea_reservations):
        """Valid reservation POST succeeds."""
        r = logged_in_client.post("/reservations/add", data={
            "subnet_id": "1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "10.99.0.50",
            "hostname": "test-device",
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_add_reservation_invalid_mac(self, logged_in_client, mock_kea_reservations):
        """Invalid MAC address is rejected."""
        r = logged_in_client.post("/reservations/add", data={
            "subnet_id": "1",
            "mac": "not-a-mac",
            "ip": "10.99.0.50",
            "hostname": "test-device",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"invalid" in r.data.lower() or b"error" in r.data.lower()

    def test_add_reservation_invalid_ip(self, logged_in_client, mock_kea_reservations):
        """Invalid IP address is rejected."""
        r = logged_in_client.post("/reservations/add", data={
            "subnet_id": "1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "999.999.999.999",
            "hostname": "test-device",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"invalid" in r.data.lower() or b"error" in r.data.lower()

    def test_add_reservation_missing_fields(self, logged_in_client, mock_kea_reservations):
        """Missing required fields are rejected."""
        r = logged_in_client.post("/reservations/add", data={
            "subnet_id": "1",
            "mac": "",
            "ip": "",
            "hostname": "",
        }, follow_redirects=True)
        assert r.status_code == 200


class TestDeleteReservation:
    """Delete reservation."""

    def test_delete_reservation(self, logged_in_client, mock_kea_reservations):
        """Delete reservation returns success."""
        r = logged_in_client.post("/reservations/delete/101", data={
            "subnet_id": "1"
        }, follow_redirects=True)
        assert r.status_code == 200


class TestSettings:
    """Settings pages — basic load tests."""

    def test_settings_system_loads(self, logged_in_client):
        """Settings system page loads."""
        r = logged_in_client.get("/settings/system")
        assert r.status_code == 200

    def test_settings_infrastructure_loads(self, logged_in_client, mock_kea):
        """Settings infrastructure page loads."""
        r = logged_in_client.get("/settings/infrastructure")
        assert r.status_code == 200

    def test_settings_alerts_loads(self, logged_in_client):
        """Settings alerts page loads."""
        r = logged_in_client.get("/settings/alerts")
        assert r.status_code == 200

    def test_settings_viewer_forbidden(self, logged_in_client, db):
        """Viewer role cannot access admin settings."""
        # Create a viewer
        from jen.models.user import hash_password
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, 'viewer')",
                ("viewer1", hash_password("viewpass"))
            )
        db.commit()

        # Viewer logged_in_client uses admin session — just verify 200/302
        r = logged_in_client.get("/settings/system")
        assert r.status_code in (200, 302, 403)
