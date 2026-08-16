"""
tests/test_devices_page.py
────────────────────────────
v5.1.4 — Devices page action-column redesign. The old markup omitted
the "reserve" icon entirely for a device that already has a
reservation, which shifted every other icon in the row and was the
actual bug report this change fixes. Now every row gets a single "⋯"
action-menu trigger regardless of which actions apply, and the
reservation state renders as a real, always-present menu item —
either a working "Create reservation" link or a disabled "Reservation
exists" label — never an omitted icon.
"""

import pytest


def _insert_device(db, mac_hex="aabbccddee01", last_ip="10.10.10.50", subnet_id=None):
    mac_colon = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen)
            VALUES (%s, %s, 'test-device', %s, NOW(), NOW())
        """, (mac_colon, last_ip, subnet_id))
        return cur.lastrowid


def _insert_reservation(db, mac_hex="aabbccddee01", ip="10.10.10.50", subnet_id=1):
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                dhcp4_subnet_id, ipv4_address, hostname)
            VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), 'reserved-host')
        """, (mac_hex, subnet_id, ip))


class TestDevicesActionMenu:

    def test_action_menu_present_regardless_of_reservation_state(self, logged_in_client, db):
        """The core fix: both a reserved and an unreserved device get
        the exact same action-menu wrapper — no icon is silently
        omitted, no row shifts relative to another."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee01", last_ip="10.10.10.50")
        _insert_device(db, mac_hex="aabbccddee02", last_ip="10.10.10.51")
        _insert_reservation(db, mac_hex="aabbccddee01", ip="10.10.10.50")
        db.commit()

        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        body = resp.data.decode()
        assert body.count('class="action-menu"') == 2

    def test_reserved_device_shows_disabled_reservation_exists_item(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee03", last_ip="10.10.10.52")
        _insert_reservation(db, mac_hex="aabbccddee03", ip="10.10.10.52")
        db.commit()

        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"Reservation exists" in resp.data
        assert b'action-menu-item disabled">' in resp.data

    def test_unreserved_device_shows_working_create_reservation_link(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee04", last_ip="10.10.10.53")
        db.commit()

        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"Create reservation" in resp.data
        assert b"/reservations/add?mac=" in resp.data

    def test_admin_sees_edit_and_delete_items(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee05", last_ip="10.10.10.54")
        db.commit()

        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"edit-btn" in resp.data
        assert b"Remove from inventory" in resp.data

    def test_viewer_does_not_see_edit_or_delete_items(self, client, db):
        from tests.conftest import restricted_client
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee06", last_ip="10.10.10.55", subnet_id=1)
        db.commit()

        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        resp = c.get("/devices")
        assert resp.status_code == 200
        body = resp.data.decode()
        # The click-handler JS always contains the literal string
        # "edit-btn" in its selector regardless of whether any button
        # exists — check for the actual rendered element instead of the
        # bare substring.
        assert 'action-menu-item edit-btn' not in body
        assert b"Remove from inventory" not in resp.data
        # But the reservation item should still be visible to a viewer —
        # it's informational/a link, not a mutating action gated to admins.
        assert b"Create reservation" in resp.data or b"Reservation exists" in resp.data

    def test_no_external_icon_font_or_cdn_reference(self, logged_in_client, db):
        """The whole point of inline SVG icons: zero network dependency,
        unlike the CDN-hosted Chart.js bug just fixed elsewhere."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee07", last_ip="10.10.10.56")
        db.commit()
        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"cdnjs" not in resp.data
        assert b"font-face" not in resp.data
        assert b"<svg" in resp.data

    def test_edit_button_retains_all_data_attributes(self, logged_in_client, db):
        """The edit-btn's click handler (devices.html JS) relies on
        e.target.closest('.edit-btn') plus its data-* attributes —
        confirm the redesign didn't drop any of them."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices")
        db.commit()
        _insert_device(db, mac_hex="aabbccddee08", last_ip="10.10.10.57")
        db.commit()
        resp = logged_in_client.get("/devices")
        body = resp.data.decode()
        assert 'data-mac=' in body
        assert 'data-name=' in body
        assert 'data-owner=' in body
        assert 'data-notes=' in body
        assert 'data-type=' in body
        assert 'data-icon=' in body
