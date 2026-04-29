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
    import pymysql
    import pymysql.cursors

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
