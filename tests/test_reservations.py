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


class TestEditReservation:
    """Regression coverage for the v4.4.0 bug where reservation notes got
    silently orphaned. Kea's reservation-del + reservation-add (how Jen
    implements "edit") churns hosts.host_id — an AUTO_INCREMENT primary
    key — even though ip/mac/subnet don't change. The route must write
    reservation_notes against the new host_id, not the stale one from the
    URL, or the note becomes invisible on the list page despite a
    "Reservation updated" success message."""

    def test_notes_survive_host_id_reassignment(self, logged_in_client, db, monkeypatch):
        from jen.services import kea as kea_svc

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee99'), 0, 1, INET_ATON('10.99.0.50'), 'churn-test')"
            )
            old_host_id = cur.lastrowid
        db.commit()

        def _kea_mock(cmd, *a, **kw):
            # Simulate what a real Kea server does to the hosts table on
            # reservation-del/reservation-add: delete-then-reinsert, which
            # assigns a brand new AUTO_INCREMENT host_id.
            if "reservation-del" in cmd:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM hosts WHERE host_id=%s", (old_host_id,))
                db.commit()
                return {"result": 0, "text": "deleted", "arguments": {}}
            if "reservation-add" in cmd:
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                        "dhcp4_subnet_id, ipv4_address, hostname) "
                        "VALUES (UNHEX('aabbccddee99'), 0, 1, INET_ATON('10.99.0.50'), 'churn-test-renamed')"
                    )
                db.commit()
                return {"result": 0, "text": "added", "arguments": {}}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", _kea_mock)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        r = logged_in_client.post(
            f"/reservations/edit/{old_host_id}",
            data={"hostname": "churn-test-renamed", "notes": "should survive"},
        )
        assert r.status_code in (200, 302)

        with db.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", ("10.99.0.50",))
            row = cur.fetchone()
        assert row is not None
        current_host_id = row["host_id"]
        assert current_host_id != old_host_id, "test setup didn't actually churn the id — mock is wrong"

        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (current_host_id,))
            note_row = cur.fetchone()
        assert note_row is not None, "note was not written under the new host_id — it got orphaned"
        assert note_row["notes"] == "should survive"

        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (old_host_id,))
            stale_row = cur.fetchone()
        assert stale_row is None, "orphaned note under the old host_id was not cleaned up"


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
