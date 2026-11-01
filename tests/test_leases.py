"""
tests/test_leases.py
────────────────────
Tests for lease list, search, and IP map pages.
Kea DB queries are mocked — no real Kea database needed.
"""

import re

import pytest


@pytest.fixture
def mock_kea_db(monkeypatch):
    """Mock get_kea_db to return empty results for lease queries."""

    class MockCursor:
        def __init__(self):
            self._rows = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def execute(self, sql, args=None):
            self._rows = []

        def fetchone(self):
            return None

        def fetchall(self):
            return []

        def close(self):
            pass

    class MockConn:
        def cursor(self):
            return MockCursor()

        def close(self):
            pass

        def commit(self):
            pass

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

    def test_empty_state_teaches_instead_of_a_blank_table(self, logged_in_client, mock_kea_db):
        """v5.39.0 (Q39) — mock_kea_db returns zero leases; the empty
        row should explain why (Kea hands out leases on demand) and
        point at Health rather than leaving a bare table."""
        r = logged_in_client.get("/leases")
        body = r.data.decode()
        assert "No active leases yet" in body
        assert 'href="/health-center"' in body


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


class TestIpMapRendersACidrPool:
    """v5.69.0-beta.3 (Q172, item 10): `_get_pools` kept only a pool written `a - b`; Kea also accepts `10.0.0.0/25`, which then had no cells on the map and the page said it could not
    determine the pool. `jen.services.pools.parse_pool` is the one reader of what a pool is."""

    @staticmethod
    def _config(monkeypatch, pools):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "CIDR-NET", "cidr": "10.0.0.0/24"}})
        monkeypatch.setattr(
            kea_svc,
            "kea_command",
            lambda *a, **kw: {
                "result": 0,
                "arguments": {
                    "Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "pools": [{"pool": p} for p in pools]}]}
                },
            },
        )
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

    def test_a_cidr_pool_renders_one_cell_per_address(self, logged_in_client, db, monkeypatch):
        self._config(monkeypatch, ["10.0.0.0/25"])
        body = logged_in_client.get("/ipmap?subnet=1").get_data(as_text=True)
        assert body.count('class="ip-cell ip-') == 128
        assert "10.0.0.0 — 10.0.0.127" in body

    def test_a_range_pool_and_a_cidr_pool_render_together(self, logged_in_client, db, monkeypatch):
        self._config(monkeypatch, ["10.0.0.10 - 10.0.0.19", "10.0.0.192/28"])
        body = logged_in_client.get("/ipmap?subnet=1").get_data(as_text=True)
        assert body.count('class="ip-cell ip-') == 10 + 16

    def test_an_unreadable_pool_is_left_out_not_fatal(self, logged_in_client, db, monkeypatch):
        self._config(monkeypatch, ["not a pool", "10.0.0.20-10.0.0.22"])
        body = logged_in_client.get("/ipmap?subnet=1").get_data(as_text=True)
        assert body.count('class="ip-cell ip-') == 3


class TestIpMapForAUserWhoMaySeeNoSubnet:
    """v5.68.0-beta.22 (Q157, item 8): `default_subnet` fell back to the first CONFIGURED subnet when the user's own map was empty, and the page then
    queried and printed that subnet's leases, reservations and CIDR - reachable for a restricted account whose access list names only subnets that
    have since left `[subnets]` (or is empty). Pre-existing since v4.4.9, found by the grep for the old spelling."""

    @pytest.fixture
    def two_subnets(self, db, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {
                1: {"name": "FIRST-CONFIGURED-NET", "cidr": "10.201.0.0/24"},
                2: {"name": "SECOND-NET", "cidr": "10.202.0.0/24"},
            },
        )
        monkeypatch.setattr("jen.routes.leases._get_pools", lambda sid: [("10.201.0.10", "10.201.0.20")])
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON('10.201.0.12')")
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='00AA02010001'")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
                "(INET_ATON('10.201.0.12'), UNHEX('00AA02010002'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'first-net-lease-host')"
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) VALUES "
                "(UNHEX('00AA02010001'), 0, 1, INET_ATON('10.201.0.15'), 'first-net-reservation-host')"
            )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON('10.201.0.12')")
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='00AA02010001'")
        db.commit()

    SECRETS = (
        "FIRST-CONFIGURED-NET",
        "10.201.0",
        "first-net-lease-host",
        "first-net-reservation-host",
        "SECOND-NET",
        "10.202.0",
        "00:aa:02",
    )

    @pytest.mark.parametrize("allowed", [[], [999]])
    def test_a_user_with_no_visible_subnet_gets_a_page_with_nothing_of_any_subnet(
        self, client, db, two_subnets, allowed
    ):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(
            client, db, allowed_subnets=allowed, role="viewer", username=f"_ipmap_none_{len(allowed)}"
        )
        for url in ("/ipmap", "/ipmap?subnet=1", "/ipmap?subnet=2", "/ipmap?subnet=garbage"):
            r = c.get(url)
            assert r.status_code == 200
            body = r.get_data(as_text=True)
            assert "no subnet you can see" in body and 'id="ipmap-no-subnets"' in body
            for secret in self.SECRETS:
                assert secret.lower() not in body.lower(), f"{url}: {secret!r} reached a user who may see no subnet"

    def test_nothing_is_queried_for_such_a_user(self, client, db, two_subnets, monkeypatch):
        from jen.models import db as dbmod
        from tests.conftest import restricted_client

        asked = []
        real = dbmod.kea_db

        def watching():
            asked.append(1)
            return real()

        monkeypatch.setattr(dbmod, "kea_db", watching)
        c, _uid = restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_ipmap_none_q")
        assert c.get("/ipmap").status_code == 200
        assert asked == [], "the Kea database was opened for a user who may see no subnet"

    def test_a_user_with_a_visible_subnet_still_gets_the_map_and_cannot_pick_another(self, client, db, two_subnets):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[2], role="viewer", username="_ipmap_two")
        body = c.get("/ipmap?subnet=1").get_data(as_text=True)
        assert "SECOND-NET" in body and "FIRST-CONFIGURED-NET" not in body and "first-net-lease-host" not in body
        assert "no subnet you can see" not in body

    def test_an_unrestricted_user_sees_the_first_subnet_by_default(self, logged_in_client, two_subnets):
        body = logged_in_client.get("/ipmap").get_data(as_text=True)
        assert "FIRST-CONFIGURED-NET" in body and "first-net-lease-host" in body


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
            cur.execute(
                """
                INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire,
                    subnet_id, state, hostname)
                VALUES (INET_ATON(%s), UNHEX(%s), 3600,
                    DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 0, 'bulk-release-test')
            """,
                (ip, mac_hex, subnet_id),
            )
        db.commit()

    def test_bulk_release_marks_selected_leases_expired(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
        db.commit()
        self._insert_lease(db, "aabbccddee20", "10.10.10.95")
        r = logged_in_client.post("/leases/bulk-release", data={"ips[]": ["10.10.10.95"]}, follow_redirects=True)
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
        r = logged_in_client.post("/leases/bulk-release", data={"ips[]": ["10.10.10.96"]}, follow_redirects=True)
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
        r = client.post("/leases/bulk-release", data={"ips[]": ["10.10.10.97"]}, follow_redirects=True)
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


# ── Q205 (v5.70.0-beta.1): AU4 / AU5 / AU8 / AU10 on the lease list ────────────────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def q205_rows(db):
    """Subnet 1: a lease that has a reservation, a plain lease, and a plain lease with NO hostname."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC000001')")
        for ip, mac, host in (
            ("10.99.0.21", "AABBCC000001", "reserved-host"),
            ("10.99.0.22", "AABBCC000002", "plain-host"),
            ("10.99.0.23", "AABBCC000003", None),
        ):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 13 DAY), 1, 0, %s)",
                (ip, mac, host),
            )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) VALUES (UNHEX('AABBCC000001'), 0, 1, INET_ATON('10.99.0.21'), 'reserved-host')"
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC000001')")
    db.commit()


class TestTheLeaseListQ205:
    def _page(self, client, path="/leases"):
        return client.get(path).data.decode()

    def test_au4_a_reserved_lease_shows_a_disabled_box_not_an_empty_cell(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client)
        assert 'disabled title="Reserved - the address is not released from here"' in page
        assert page.count('name="ips[]"') == 2, "only the releasable rows carry a submitted box"
        assert 'name="ips[]" value="10.99.0.21"' not in page and 'name="ips[]" value="10.99.0.22"' in page

    def test_au4_the_count_and_select_all_count_enabled_boxes_only(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client)
        assert ".row-checkbox:not(:disabled):checked" in page and ".row-checkbox:not(:disabled)')" in page
        assert (
            "document.querySelectorAll('.row-checkbox:checked').length" not in page
            and "document.querySelectorAll('.row-checkbox').length" not in page
        )

    def test_au5_delete_stale_leaves_the_filter_bar_for_the_foot_of_the_table(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client)
        assert "Delete Stale" not in page
        assert page.count('action="/leases/delete-stale"') == 1
        assert page.index('action="/leases/delete-stale"') > page.index("</table>"), (
            "after the table, not in the filter bar above it"
        )
        assert 'data-confirm="Delete all expired/stale leases from the database?"' in page
        i = page.index('action="/leases/delete-stale"')
        assert "btn-danger" not in page[i : i + 400] and "btn-secondary" in page[i : i + 400], (
            "a quiet secondary control"
        )

    def test_au5_the_partial_carries_the_control_too(self, logged_in_client, q205_rows):
        partial = logged_in_client.get("/leases", headers={"HX-Request": "true"}).data.decode()
        assert 'action="/leases/delete-stale"' in partial and "Delete stale leases" in partial

    def test_au5_a_viewer_has_no_delete_stale(self, client, db, q205_rows):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="stale_viewer")
        assert "delete-stale" not in client.get("/leases").data.decode()

    def test_au8_the_badge_is_a_filter_link_that_keeps_the_pages_other_arguments(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client, "/leases?search=plain&sort=ip&dir=asc&page=3")
        m = re.search(r'<a class="badge badge-tone-\w+" href="([^"]+)"', page)
        assert m, "the lease row's badge is a link"
        href = m.group(1).replace("&amp;", "&")
        assert (
            href.startswith("/leases?")
            and "subnet=1" in href
            and "search=plain" in href
            and "sort=ip" in href
            and "dir=asc" in href
        )
        assert "page=" not in href, "a new filter starts at page one"

    def test_au8_a_scoped_viewer_links_only_to_their_own_subnet(self, client, db, q205_rows):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="badge_link_viewer")
        hrefs = set(re.findall(r'<a class="badge badge-tone-\w+" href="([^"]+)"', client.get("/leases").data.decode()))
        assert hrefs and all(h.endswith("subnet=1") for h in hrefs), hrefs

    def test_au10_an_empty_hostname_says_so(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client)
        assert page.count('<span class="muted">no hostname</span>') == 1
        assert "plain-host" in page and "reserved-host" in page

    def test_au10_the_count_agrees(self, logged_in_client, q205_rows):
        # Q206 (AV4): the count moved from the page header into the swapped results, where it says what the list holds ("3 active leases", not "3 leases found")
        assert "3 active leases" in self._page(logged_in_client)
        one = self._page(logged_in_client, "/leases?search=plain-host")
        assert "1 active lease" in one and "1 active leases" not in one

    def test_au3_the_expiry_is_a_time_element_with_the_relative_form_as_its_title(self, logged_in_client, q205_rows):
        page = self._page(logged_in_client)
        assert re.search(
            r'<span class="desk-only" title="in 1[23] d"><time datetime="[0-9T:-]+Z" data-jen-time="fmt"', page
        )
        assert page.count('data-jen-time="rel"') >= 3, "the phone column keeps its relative form"
        assert re.search(r">20\d\d-\d\d-\d\d \d\d:\d\d UTC</time>", page), "the server-rendered text is still UTC"


@pytest.fixture
def q206_rows(db):
    """Subnet 1: two leases that expire in 30 minutes, one in 3 hours that carries a reservation, and one that expired an hour ago."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC000013')")
        for ip, mac, host, expire in (
            ("10.99.0.31", "AABBCC000011", "soon-a", "DATE_ADD(NOW(), INTERVAL 30 MINUTE)"),
            ("10.99.0.32", "AABBCC000012", "soon-b", "DATE_ADD(NOW(), INTERVAL 30 MINUTE)"),
            ("10.99.0.33", "AABBCC000013", "later-c", "DATE_ADD(NOW(), INTERVAL 3 HOUR)"),
            ("10.99.0.34", "AABBCC000014", "gone-d", "DATE_SUB(NOW(), INTERVAL 1 HOUR)"),
        ):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                f"VALUES (INET_ATON(%s), UNHEX(%s), 3600, {expire}, 1, 0, %s)",
                (ip, mac, host),
            )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) VALUES (UNHEX('AABBCC000013'), 0, 1, INET_ATON('10.99.0.33'), 'later-c')"
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC000013')")
    db.commit()


def _summary(body):
    """The text of the results-summary line, whitespace folded (None when the response has none)."""
    m = re.search(r'<p class="results-summary"[^>]*>(.*?)</p>', body, re.S)
    return " ".join(re.sub(r"<[^>]+>", "", m.group(1)).split()) if m else None


class TestResultsSummary:
    """Q206 (AV4): the summary line lives INSIDE the swapped results, so a filter change updates it, and on the live list it says what expires soon and what is reserved."""

    HX = {"HX-Request": "true"}

    def test_a_filter_change_returns_the_partial_with_the_new_total(self, logged_in_client, q206_rows):
        full = logged_in_client.get("/leases").data.decode()
        assert _summary(full).startswith("3 active leases")
        # the swap for a changed search carries ITS OWN total - the old shape (the count in the page shell, outside the swap) is pinned as the regression
        partial = logged_in_client.get("/leases?search=soon", headers=self.HX).data.decode()
        assert "<html" not in partial and _summary(partial).startswith("2 active leases")
        one = logged_in_client.get("/leases?search=later", headers=self.HX).data.decode()
        assert _summary(one).startswith("1 active lease ")

    def test_the_summary_is_inside_the_results_not_the_page_header(self, logged_in_client, q206_rows):
        full = logged_in_client.get("/leases").data.decode()
        assert full.index('<div id="leases-results">') < full.index('id="leases-summary"')
        header = full[
            full.index('<div class="page-header">') : full.index("</div>", full.index('<div class="page-header">'))
        ]
        assert "found" not in header and not re.search(r"\d+ (active )?leases?", header)

    def test_two_leases_expiring_within_the_hour_are_counted(self, logged_in_client, q206_rows):
        text = _summary(logged_in_client.get("/leases", headers=self.HX).data.decode())
        assert "2 expire within the hour" in text

    def test_one_lease_expiring_within_the_hour_is_singular(self, logged_in_client, q206_rows):
        text = _summary(logged_in_client.get("/leases?search=soon-a", headers=self.HX).data.decode())
        assert "1 expires within the hour" in text

    def test_none_expiring_within_the_hour_means_no_clause(self, logged_in_client, q206_rows):
        text = _summary(logged_in_client.get("/leases?search=later", headers=self.HX).data.decode())
        assert "within the hour" not in text and text.startswith("1 active lease")

    def test_the_hour_is_counted_over_the_same_filter(self, logged_in_client, q206_rows):
        # the same where: a search that excludes both soon-leases also excludes them from the count
        text = _summary(logged_in_client.get("/leases?search=soon-b", headers=self.HX).data.decode())
        assert "1 expires within the hour" in text

    def test_a_reserved_lease_is_counted(self, logged_in_client, q206_rows):
        assert "1 reserved" in _summary(logged_in_client.get("/leases", headers=self.HX).data.decode())

    def test_no_reserved_lease_means_no_clause(self, logged_in_client, q206_rows):
        assert "reserved" not in _summary(logged_in_client.get("/leases?search=soon", headers=self.HX).data.decode())

    def test_a_paged_list_says_the_reserved_count_is_for_the_page(self, logged_in_client, q206_rows):
        # the reserved set is read for the rows shown, so a paged list says so rather than imply the whole filtered set (the route honours any whole number of rows, the select offers four)
        text = _summary(logged_in_client.get("/leases?per_page=2", headers=self.HX).data.decode())
        assert text.startswith("3 active leases") and "1 reserved on this page" in text
        one_page = _summary(logged_in_client.get("/leases?per_page=50", headers=self.HX).data.decode())
        assert "1 reserved" in one_page and "on this page" not in one_page

    def test_the_subnet_is_named_by_the_filter_that_names_it(self, logged_in_client, q206_rows):
        text = _summary(logged_in_client.get("/leases?subnet=1", headers=self.HX).data.decode())
        assert text.startswith("3 active leases in Test Network")

    def test_the_history_does_not_call_every_lease_expired(self, logged_in_client, q206_rows):
        # the history lists every lease row Kea still holds, live ones included (tests/test_active_lease.py::test_01b), so "N expired leases" would be false
        text = _summary(logged_in_client.get("/leases?expired=1", headers=self.HX).data.decode())
        assert text.startswith("4 leases") and "the history" in text
        assert "within the hour" not in text and "reserved" not in text and "active" not in text

    def test_a_subnet_that_does_not_exist_names_nothing(self, logged_in_client, q206_rows):
        text = _summary(logged_in_client.get("/leases?subnet=999", headers=self.HX).data.decode())
        assert " in " not in text.split("·")[0]

    def test_the_restricted_summary_counts_only_what_the_caller_may_see(self, client, db, q206_rows):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="summary_viewer")
        text = _summary(client.get("/leases", headers=self.HX).data.decode())
        assert text == "3 active leases · 2 expire within the hour · 1 reserved"

    def test_a_reservation_in_a_subnet_the_caller_cannot_see_is_not_counted(self, client, db, q206_rows):
        # SP-1: the lease is in subnet 1, its only reservation is in subnet 2 (the moved-client shape): a viewer scoped to 1 must not read "1 reserved"
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCC000013'")
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCC000013'), 0, 2, INET_ATON('10.98.9.33'), 'moved')"
            )
        db.commit()
        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="moved_summary_viewer")
        text = _summary(client.get("/leases", headers=self.HX).data.decode())
        assert "reserved" not in text, text

    def test_the_unrestricted_caller_still_counts_every_reservation(self, logged_in_client, db, q206_rows):
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCC000013'")
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCC000013'), 0, 2, INET_ATON('10.98.9.33'), 'moved')"
            )
        db.commit()
        assert "1 reserved" in _summary(logged_in_client.get("/leases", headers=self.HX).data.decode())


class TestFilteredEmptyState:
    """Q206 (AV6): a search that matched nothing says so, names the search, and offers one way out; an empty list with no filter is the sentence it always was."""

    def test_no_filter_and_no_rows_keep_the_old_sentence(self, logged_in_client, mock_kea_db):
        body = logged_in_client.get("/leases").data.decode()
        assert "No active leases yet" in body and 'href="/health-center"' in body
        assert "Clear filters" not in body

    def test_a_search_that_matched_nothing_names_the_search_and_offers_clear_filters(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases?search=nothing-matches-this&per_page=100").data.decode()
        assert "No active leases match “nothing-matches-this”" in body
        assert body.count("Clear filters") == 1
        assert 'href="/leases?per_page=100&amp;sort=expires&amp;dir=desc"' in body
        # rule 7: the absences are asserted only on the filtered shape
        assert "No active leases yet" not in body and "Kea hands out leases" not in body

    def test_the_swap_names_it_too(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases?search=nothing-matches-this", headers={"HX-Request": "true"}).data.decode()
        assert "No active leases match “nothing-matches-this”" in body and "Clear filters" in body

    def test_a_subnet_filter_alone_is_named(self, logged_in_client, db, q206_rows):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        db.commit()
        body = logged_in_client.get("/leases?subnet=1").data.decode()
        assert "No active leases in Test Network" in body and "Clear filters" in body

    def test_a_time_window_the_route_applied_is_a_filter_even_when_it_has_no_name(
        self, logged_in_client, db, q206_rows
    ):
        # SP-3: ?minutes=-5 is applied (INTERVAL -5 MINUTE), ?minutes=1e3 and 5.5 are ignored (int() raises) - the empty row reads what the ROUTE decided
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        db.commit()
        applied = logged_in_client.get("/leases?minutes=-5").data.decode()
        assert "No active leases in the selected time window" in applied and "Clear filters" in applied
        for ignored in ("1e3", "5.5", "abc"):
            body = logged_in_client.get(f"/leases?minutes={ignored}").data.decode()
            assert "No active leases yet" in body and "Clear filters" not in body, ignored

    def test_a_search_is_sanitised_before_it_is_named(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases?search=<zzq>").data.decode()
        assert "match “zzq”" in body and "<zzq>" not in body.split('id="leases-results"', 1)[1]


class TestTheIpIsNoLongerALinkToItself:
    """Q206 (AV7): the IP cell used to link to a search for its own address on the page it is printed on; it is a copy control now, and the row's way on is Investigate and the action menu."""

    def test_no_self_link_and_the_ip_is_a_copy_control(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases").data.decode()
        assert 'href="/leases?search=' not in body
        assert re.search(
            r'<button type="button" class="copy mono" data-copy="10\.99\.0\.31" title="Copy 10\.99\.0\.31">10\.99\.0\.31</button>',
            body,
        )

    def test_the_mac_is_a_copy_control_in_the_cell_and_in_the_action_menu(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases").data.decode()
        assert body.count('data-copy="AA:BB:CC:00:00:11"') == 2  # the MAC cell and the action menu's line

    def test_the_row_still_carries_investigate(self, logged_in_client, q206_rows):
        body = logged_in_client.get("/leases").data.decode()
        assert body.count('href="/client?q=') >= 3, "every row names a client, and every such row carries Investigate"
