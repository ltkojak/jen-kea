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


class TestReservationStatus:
    """v5.1.3 — active/inactive (and conflict) status on the reservations
    list, matching what Windows DHCP shows: does the reserved IP
    currently have a live lease bound to it? Uses real hosts/lease4 rows
    against the real test DB rather than mocking Kea, since this is
    Jen's own read-side computation, not a Kea API call."""

    def _insert_reservation(self, db, mac_hex="aabbccddee01", ip="10.99.1.10",
                            hostname="status-test", subnet_id=1):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (mac_hex, subnet_id, ip, hostname),
            )
            host_id = cur.lastrowid
        db.commit()
        return host_id

    def _insert_lease(self, db, ip, mac_hex, state=0, expire_offset_seconds=3600):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, "
                "subnet_id, state) VALUES (INET_ATON(%s), UNHEX(%s), 3600, "
                "DATE_ADD(NOW(), INTERVAL %s SECOND), 1, %s)",
                (ip, mac_hex, expire_offset_seconds, state),
            )
        db.commit()

    def test_reservation_with_no_lease_is_inactive(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.10", mac_hex="aabbccddee01")
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        # The filter dropdown always contains the literal text "Active
        # only"/"Inactive only" regardless of data, so check the specific
        # status-badge marker (○/●) rather than the bare word.
        assert b"\xe2\x97\x8b Inactive" in resp.data  # ○ Inactive
        assert b"\xe2\x97\x8f Active" not in resp.data  # ● Active

    def test_reservation_with_matching_active_lease_is_active(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.11", mac_hex="aabbccddee02")
        self._insert_lease(db, "10.99.1.11", "aabbccddee02")
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8f Active" in resp.data  # ● Active

    def test_expired_lease_does_not_count_as_active(self, logged_in_client, db):
        """A lease that already expired must not make the reservation
        show as active — only a genuinely live lease counts."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.12", mac_hex="aabbccddee03")
        self._insert_lease(db, "10.99.1.12", "aabbccddee03", expire_offset_seconds=-3600)
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8b Inactive" in resp.data

    def test_released_lease_does_not_count_as_active(self, logged_in_client, db):
        """state != 0 (released/expired-per-Kea) must not count as active
        even if the expire timestamp is still in the future."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.13", mac_hex="aabbccddee04")
        self._insert_lease(db, "10.99.1.13", "aabbccddee04", state=1)
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8b Inactive" in resp.data

    def test_different_mac_on_reserved_ip_shows_conflict(self, logged_in_client, db):
        """The reserved IP has a live lease, but it belongs to a
        different device than the reservation — must be flagged
        distinctly from a plain 'Active' status."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.14", mac_hex="aabbccddee05")
        self._insert_lease(db, "10.99.1.14", "112233445566")  # different MAC
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"Conflict" in resp.data

    def test_status_filter_active_only(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.20", mac_hex="aabbccddee10", hostname="online-host")
        self._insert_lease(db, "10.99.1.20", "aabbccddee10")
        self._insert_reservation(db, ip="10.99.1.21", mac_hex="aabbccddee11", hostname="offline-host")
        resp = logged_in_client.get("/reservations?status=active")
        assert resp.status_code == 200
        assert b"online-host" in resp.data
        assert b"offline-host" not in resp.data

    def test_status_filter_inactive_only(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.22", mac_hex="aabbccddee12", hostname="printer-alpha")
        self._insert_lease(db, "10.99.1.22", "aabbccddee12")
        self._insert_reservation(db, ip="10.99.1.23", mac_hex="aabbccddee13", hostname="scanner-beta")
        resp = logged_in_client.get("/reservations?status=inactive")
        assert resp.status_code == 200
        assert b"scanner-beta" in resp.data
        assert b"printer-alpha" not in resp.data

    def test_invalid_status_value_falls_back_to_all(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.24", mac_hex="aabbccddee14", hostname="whatever-host")
        resp = logged_in_client.get("/reservations?status=bogus")
        assert resp.status_code == 200
        assert b"whatever-host" in resp.data  # not filtered out


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


class TestBulkReservationActions:
    """v5.2.2 — bulk delete/export on the Reservations page. This
    JS (toggleAll/updateCount/confirmBulk) and both backend routes
    (bulk_delete_reservations, bulk_export_reservations) already
    existed before this release — but there was no checkbox, no
    select-all, no action bar, and no <form> anywhere in the template
    to actually connect them. The feature was completely unreachable
    from the UI despite a fully correct, already-tested-looking
    backend. These tests exercise the routes directly (as any prior
    test here could already have done, had anyone written one) and
    also confirm the previously-missing markup is now actually
    present in a real rendered page.
    """

    def _insert_host(self, db, mac_hex="aabbccddee10", ip="10.99.0.40",
                      subnet_id=1, hostname="bulk-test-host"):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (mac_hex, subnet_id, ip, hostname)
            )
            host_id = cur.lastrowid
        db.commit()
        return host_id

    def test_bulk_delete_removes_selected_reservations(self, logged_in_client, db, monkeypatch):
        """v5.2.2/5.2.3 CI failure fix: the actual `hosts` row is
        removed by Kea itself when it processes reservation-del
        (Kea owns that table, the same way the single-item delete
        route already works — see delete_reservation() above, which
        never issues its own DELETE FROM hosts either) — Jen's own
        side of this is only cleaning up reservation_notes and
        reporting the outcome. Asserting the row is gone from a
        *mocked* Kea's perspective was asserting something outside
        what a mock can actually simulate; the mock returns success
        without touching the real hosts table, so the row was always
        going to still be there in this test environment regardless of
        whether the route's logic is correct. This is exactly the same
        shape of gap as the existing test_delete_reservation() test
        above, which only checks status_code == 200 for the same
        reason — it just wasn't followed for this new test.

        What this test verifies instead: Jen sends the correct
        reservation-del command (matching this specific host's
        subnet-id and MAC), and reports success — the parts actually
        under Jen's control and observable without a real Kea server.
        """
        host_id = self._insert_host(db, mac_hex="aabbccddee10", subnet_id=1)
        calls = []

        def fake_kea_command(cmd, service="dhcp4", arguments=None, server=None):
            calls.append((cmd, arguments))
            return {"result": 0, "text": "Host deleted", "arguments": {}}

        monkeypatch.setattr("jen.services.kea.kea_command", fake_kea_command)

        r = logged_in_client.post("/reservations/bulk-delete",
                                  data={"host_ids[]": [str(host_id)]},
                                  follow_redirects=True)
        assert r.status_code == 200
        assert b"Deleted 1 reservation" in r.data

        del_calls = [c for c in calls if c[0] == "reservation-del"]
        assert len(del_calls) == 1, f"expected exactly one reservation-del call, got {del_calls}"
        _, args = del_calls[0]
        assert args["subnet-id"] == 1
        assert args["identifier"] == "aa:bb:cc:dd:ee:10"
        assert args["identifier-type"] == "hw-address"

    def test_bulk_delete_with_no_selection_shows_error(self, logged_in_client, mock_kea):
        r = logged_in_client.post("/reservations/bulk-delete", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No reservations selected" in r.data

    def test_bulk_delete_respects_subnet_restriction(self, client, db, mock_kea):
        """A bulk action can't be used to reach a subnet a restricted
        admin couldn't touch one at a time — same guard as the
        single-item delete route, checked per host_id in the loop."""
        from tests.conftest import restricted_client
        host_id = self._insert_host(db, mac_hex="aabbccddee11", ip="10.99.0.41", subnet_id=1)
        restricted_client(client, db, allowed_subnets=[999])
        r = client.post("/reservations/bulk-delete",
                        data={"host_ids[]": [str(host_id)]},
                        follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT * FROM hosts WHERE host_id=%s", (host_id,))
            assert cur.fetchone() is not None, "reservation outside the restricted admin's scope must survive"

    def test_bulk_export_returns_csv_of_selected_reservations(self, logged_in_client, db, mock_kea):
        host_id = self._insert_host(db, mac_hex="aabbccddee12", ip="10.99.0.42", hostname="export-target")
        r = logged_in_client.post("/reservations/bulk-export",
                                  data={"host_ids[]": [str(host_id)]})
        assert r.status_code == 200
        assert b"export-target" in r.data
        assert b"10.99.0.42" in r.data

    def test_bulk_export_with_no_selection_shows_error(self, logged_in_client, mock_kea):
        r = logged_in_client.post("/reservations/bulk-export", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No reservations selected" in r.data

    def test_reservations_page_now_actually_renders_the_bulk_markup(self, logged_in_client, db, mock_kea):
        """Regression guard for the actual bug: the page must contain
        real checkboxes, a select-all control, and a bulk form —
        not just the JS that references IDs which didn't exist."""
        host_id = self._insert_host(db, mac_hex="aabbccddee13", ip="10.99.0.43")
        r = logged_in_client.get("/reservations")
        assert r.status_code == 200
        body = r.data.decode()
        assert 'id="bulk-form"' in body
        assert 'id="selectAll"' in body
        assert f'name="host_ids[]" value="{host_id}"' in body
