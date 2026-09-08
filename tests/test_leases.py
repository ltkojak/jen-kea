"""
tests/test_leases.py
────────────────────
Tests for lease list, search, and IP map pages.
Kea DB queries are mocked — no real Kea database needed.
"""

import pytest


@pytest.fixture
def mock_kea_db(monkeypatch):
    """Mock get_kea_db to return empty results for lease queries."""

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


class TestLeases:
    """Lease list page."""

    def test_leases_page_loads(self, logged_in_client, mock_kea_db):
        """Leases page returns 200."""
        r = logged_in_client.get("/leases")
        assert r.status_code == 200

    def test_leases_search(self, logged_in_client, mock_kea_db):
        """Leases search parameter is accepted."""
        r = logged_in_client.get("/leases?q=192.168")
        assert r.status_code == 200

    def test_leases_subnet_filter(self, logged_in_client, mock_kea_db):
        """Leases subnet filter parameter is accepted."""
        r = logged_in_client.get("/leases?subnet=1")
        assert r.status_code == 200

    def test_ip_map_loads(self, logged_in_client, mock_kea_db):
        """IP map page returns 200."""
        r = logged_in_client.get("/ipmap")
        assert r.status_code == 200


class TestIpMapPoolBlocks:
    """Unit tests for leases._build_pool_blocks — pure logic, no DB/Kea needed.

    Regression coverage for the v4.3.6 bug where a subnet with more than one
    Kea pool stanza (e.g. a /23 split into two /24-sized pools) only ever
    showed the first pool on the map.
    """

    def test_multiple_pool_stanzas_all_included(self):
        from jen.routes.leases import _build_pool_blocks
        pools = [("10.10.10.50", "10.10.10.250"), ("10.10.11.50", "10.10.11.250")]
        blocks, truncated = _build_pool_blocks(pools)
        assert len(blocks) == 2
        assert blocks[0]["ips"][0] == "10.10.10.50"
        assert blocks[0]["ips"][-1] == "10.10.10.250"
        assert blocks[1]["ips"][0] == "10.10.11.50"
        assert blocks[1]["ips"][-1] == "10.10.11.250"
        assert not truncated

    def test_pool_crossing_octet_boundary(self):
        from jen.routes.leases import _build_pool_blocks
        blocks, truncated = _build_pool_blocks([("10.10.10.250", "10.10.11.5")])
        assert len(blocks) == 1
        assert blocks[0]["ips"][0] == "10.10.10.250"
        assert blocks[0]["ips"][-1] == "10.10.11.5"
        assert len(blocks[0]["ips"]) == 12
        assert not truncated

    def test_oversized_pool_is_truncated_not_hung(self):
        from jen.routes.leases import MAX_IPMAP_ADDRESSES, _build_pool_blocks
        blocks, truncated = _build_pool_blocks([("10.0.0.0", "10.0.255.255")])
        assert truncated is True
        assert sum(len(b["ips"]) for b in blocks) == MAX_IPMAP_ADDRESSES

    def test_no_pools_returns_empty(self):
        from jen.routes.leases import _build_pool_blocks
        blocks, truncated = _build_pool_blocks([])
        assert blocks == []
        assert truncated is False

    def test_invalid_ip_in_pool_skipped_not_crashed(self):
        from jen.routes.leases import _build_pool_blocks
        blocks, truncated = _build_pool_blocks([("not-an-ip", "10.0.0.5"), ("10.0.0.1", "10.0.0.3")])
        assert len(blocks) == 1
        assert blocks[0]["start"] == "10.0.0.1"


class TestSearch:
    """Global search."""

    def test_search_page_loads(self, logged_in_client, mock_kea_db):
        """Search page returns 200."""
        r = logged_in_client.get("/search?q=test")
        assert r.status_code == 200

    def test_search_empty_query(self, logged_in_client, mock_kea_db):
        """Empty search query is handled gracefully."""
        r = logged_in_client.get("/search?q=")
        assert r.status_code == 200


class TestLeaseRowActionMenu:
    """v5.1.4 — Lease row actions (reserve/release) converted to the
    unified action-menu component. A leased device that already has a
    static reservation shows a different item set (View reservation
    only) than one that doesn't (Create reservation + Release lease) —
    the same conditional-item-count case the whole redesign started
    from — so this is verified directly against real lease4/hosts
    rows, not just smoke-tested."""

    def test_lease_without_reservation_shows_create_and_release(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("""
                INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire,
                    subnet_id, state, hostname)
                VALUES (INET_ATON('10.10.10.90'), UNHEX('aabbccddee90'), 3600,
                    DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'no-res-host')
            """)
        db.commit()
        resp = logged_in_client.get("/leases")
        assert resp.status_code == 200
        body = resp.data.decode()
        assert 'class="action-menu"' in body
        assert "Create reservation" in body
        assert "Release lease" in body
        assert "View reservation" not in body

    def test_lease_with_reservation_shows_view_only(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
            cur.execute("""
                INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire,
                    subnet_id, state, hostname)
                VALUES (INET_ATON('10.10.10.91'), UNHEX('aabbccddee91'), 3600,
                    DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'res-host')
            """)
            cur.execute("""
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp4_subnet_id, ipv4_address, hostname)
                VALUES (UNHEX('aabbccddee91'), 0, 1, INET_ATON('10.10.10.91'), 'res-host')
            """)
        db.commit()
        resp = logged_in_client.get("/leases")
        assert resp.status_code == 200
        body = resp.data.decode()
        assert 'class="action-menu"' in body
        assert "View reservation" in body
        assert "Create reservation" not in body
        assert "Release lease" not in body

    def test_no_leftover_old_icon_row_classes(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("""
                INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire,
                    subnet_id, state, hostname)
                VALUES (INET_ATON('10.10.10.92'), UNHEX('aabbccddee92'), 3600,
                    DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'leftover-check')
            """)
        db.commit()
        resp = logged_in_client.get("/leases")
        assert b'"btn-act-edit' not in resp.data
        assert b'"btn-act-pin' not in resp.data
        assert b'"btn-act-del' not in resp.data


class TestBulkReleaseLeases:
    """v5.2.2 — bulk release of multiple active, non-reserved leases at
    once, following the same shape as reservations.py's
    bulk_delete_reservations()."""

    def _insert_lease(self, db, mac_hex, ip, subnet_id=1):
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire,
                    subnet_id, state, hostname)
                VALUES (INET_ATON(%s), UNHEX(%s), 3600,
                    DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 0, 'bulk-release-test')
            """, (ip, mac_hex, subnet_id))
        db.commit()

    def test_bulk_release_marks_selected_leases_expired(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
        db.commit()
        self._insert_lease(db, "aabbccddee20", "10.10.10.95")
        r = logged_in_client.post("/leases/bulk-release",
                                  data={"ips[]": ["10.10.10.95"]},
                                  follow_redirects=True)
        assert r.status_code == 200
        assert b"Released 1 lease" in r.data
        with db.cursor() as cur:
            cur.execute("SELECT state FROM lease4 WHERE inet_ntoa(address)='10.10.10.95'")
            assert cur.fetchone()["state"] == 1

    def test_bulk_release_skips_reserved_lease_even_if_submitted_directly(self, logged_in_client, db):
        """The template only offers a checkbox for non-reserved leases,
        but the route re-checks server-side too — a request here isn't
        required to have come from that exact form."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee21'), 0, 1, INET_ATON('10.10.10.96'), 'reserved-host')"
            )
        db.commit()
        self._insert_lease(db, "aabbccddee21", "10.10.10.96")
        r = logged_in_client.post("/leases/bulk-release",
                                  data={"ips[]": ["10.10.10.96"]},
                                  follow_redirects=True)
        assert r.status_code == 200
        assert b"Released 0 lease" in r.data
        with db.cursor() as cur:
            cur.execute("SELECT state FROM lease4 WHERE inet_ntoa(address)='10.10.10.96'")
            assert cur.fetchone()["state"] == 0, "reserved lease must not be released via bulk action"

    def test_bulk_release_with_no_selection_shows_error(self, logged_in_client):
        r = logged_in_client.post("/leases/bulk-release", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No leases selected" in r.data

    def test_bulk_release_respects_subnet_restriction(self, client, db):
        from tests.conftest import restricted_client
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
        db.commit()
        self._insert_lease(db, "aabbccddee22", "10.10.10.97", subnet_id=1)
        restricted_client(client, db, allowed_subnets=[999])
        r = client.post("/leases/bulk-release",
                        data={"ips[]": ["10.10.10.97"]},
                        follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT state FROM lease4 WHERE inet_ntoa(address)='10.10.10.97'")
            assert cur.fetchone()["state"] == 0, "lease outside the restricted admin's scope must survive"

    def test_leases_page_renders_bulk_markup_for_active_nonreserved_leases(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
        db.commit()
        self._insert_lease(db, "aabbccddee23", "10.10.10.98")
        r = logged_in_client.get("/leases")
        assert r.status_code == 200
        body = r.data.decode()
        assert 'id="bulk-form"' in body
        assert 'action="/leases/bulk-release"' in body
        assert 'name="ips[]" value="10.10.10.98"' in body
