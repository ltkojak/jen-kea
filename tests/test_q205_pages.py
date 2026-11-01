"""
tests/test_q205_pages.py
────────────────────────
Q205 (v5.70.0-beta.1): the badge as a filter link (AU8), the empty hostname (AU10) and the `<time>` element (AU3) on the pages that were not covered where they live - Devices, Reservations, the
dashboard's recent leases and Search. Each page is asked as the four principals of the authz matrix where a hidden subnet could show.
"""

import re

import pytest

from jen import extensions

LINK = re.compile(r'<a class="badge badge-tone-(\w+)" href="([^"]+)"')


@pytest.fixture
def seeded(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCC00AA01', 'AABBCC00AA02')")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC00AA03')")
        cur.execute("DELETE FROM devices WHERE mac IN ('aa:bb:cc:00:aa:04', 'aa:bb:cc:00:aa:05')")
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
            "(INET_ATON('10.99.0.31'), UNHEX('AABBCC00AA01'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'q205-search-host'), "
            "(INET_ATON('10.77.0.32'), UNHEX('AABBCC00AA02'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 2, 0, 'q205-hidden-host')"
        )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) VALUES (UNHEX('AABBCC00AA03'), 0, 1, INET_ATON('10.99.0.33'), NULL)"
        )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) VALUES "
            "('aa:bb:cc:00:aa:04', '10.99.0.34', NULL, 1, NOW(), NOW()), ('aa:bb:cc:00:aa:05', '10.77.0.35', 'q205-hidden-device', 2, NOW(), NOW())"
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCC00AA01', 'AABBCC00AA02')")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCC00AA03')")
        cur.execute("DELETE FROM devices WHERE mac IN ('aa:bb:cc:00:aa:04', 'aa:bb:cc:00:aa:05')")
    db.commit()


@pytest.fixture(autouse=True)
def two_subnets(monkeypatch):
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Test Network", "cidr": "10.99.0.0/24"}, 2: {"name": "ZZ-HIDDEN-NET", "cidr": "10.77.0.0/24"}},
    )


def _hrefs(body):
    return [(tone, href.replace("&amp;", "&")) for tone, href in LINK.findall(body)]


class TestTheBadgeIsAFilter:
    def test_devices_link_to_the_same_page_with_the_subnet(self, logged_in_client, seeded):
        links = _hrefs(logged_in_client.get("/devices?sort=mac&dir=asc").data.decode())
        assert links
        mine = [h for _t, h in links if "subnet=1" in h]
        assert mine and all(h.startswith("/devices?") and "sort=mac" in h and "dir=asc" in h for h in mine)

    def test_reservations_link_to_the_same_page_with_the_subnet(self, logged_in_client, seeded):
        links = _hrefs(logged_in_client.get("/reservations?status=all").data.decode())
        mine = [h for _t, h in links if "subnet=1" in h]
        assert mine and all(h.startswith("/reservations?") and "status=all" in h for h in mine)

    def test_search_links_to_the_lease_list_filtered(self, logged_in_client, seeded):
        links = _hrefs(logged_in_client.get("/search?q=q205-search-host").data.decode())
        assert ("blue", "/leases?subnet=1") in links

    def test_the_dashboards_recent_leases_link_to_the_lease_list_filtered(self, logged_in_client, seeded):
        for body in (
            logged_in_client.get("/api/recent-leases").data.decode(),
            logged_in_client.get("/", headers={"HX-Request": "true"}).data.decode(),
            logged_in_client.get("/").data.decode(),
        ):
            assert ("blue", "/leases?subnet=1") in _hrefs(body)

    @pytest.mark.parametrize("path", ["/leases", "/devices", "/reservations", "/search?q=q205", "/"])
    def test_a_scoped_viewer_gets_no_link_badge_tone_or_name_for_a_hidden_subnet(self, client, db, seeded, path):
        from tests.conftest import restricted_client

        restricted_client(
            client, db, allowed_subnets=[1], role="viewer", username=f"q205_scoped_{abs(hash(path)) % 9999}"
        )
        body = client.get(path).data.decode()
        assert "ZZ-HIDDEN-NET" not in body and "subnet=2" not in body and "q205-hidden" not in body, path
        assert all(h.endswith("subnet=1") or "subnet=1&" in h or "subnet=1" in h for _t, h in _hrefs(body))


class TestAnEmptyHostnameSaysSo:
    def test_a_reservation_with_no_hostname(self, logged_in_client, seeded):
        body = logged_in_client.get("/reservations").data.decode()
        assert '<span class="muted">no hostname</span>' in body

    def test_a_device_with_no_hostname(self, logged_in_client, seeded):
        body = logged_in_client.get("/devices").data.decode()
        assert '<span class="muted">no hostname</span>' in body

    def test_the_sort_by_hostname_treats_null_and_empty_alike(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes"
        for name, col in (
            ("leases.py", "l.hostname"),
            ("devices.py", "d.last_hostname"),
            ("reservations.py", "h.hostname"),
        ):
            assert f"COALESCE({col}, '')" in (root / name).read_text(encoding="utf-8"), name

    def test_a_name_with_only_the_trailing_dot_is_no_name(self, app):
        from flask import render_template_string

        with app.test_request_context("/"):
            out = render_template_string(
                "{% from '_hostname.html' import hostname_or_none %}{{ hostname_or_none(h) }}", h="."
            )
        assert "no hostname" in out
        with app.test_request_context("/"):
            out = render_template_string(
                "{% from '_hostname.html' import hostname_or_none %}{{ hostname_or_none(h) }}", h="tardis."
            )
        assert out == "tardis"


class TestTimesAreTimeElements:
    def test_the_leases_devices_and_reservations_print_time_elements_with_utc_text(self, logged_in_client, seeded):
        for path in ("/leases", "/devices"):
            body = logged_in_client.get(path).data.decode()
            assert re.search(
                r'<time datetime="20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ" data-jen-time="(fmt|date|time)"', body
            ), path

    def test_the_nav_offers_the_per_browser_pick_beside_the_theme(self, logged_in_client):
        body = logged_in_client.get("/").data.decode()
        assert body.count('data-time-mode="local"') >= 2 and body.count('data-time-mode="utc"') >= 2, (
            "the desktop dropdown and the phone sheet"
        )
        assert "jen-time-pick" in body and "window.jenTime" in body

    def test_the_rewriter_is_in_a_nonced_script_and_runs_after_swaps(self, logged_in_client):
        body = logged_in_client.get("/").data.decode()
        start = body.index("window.jenTime = (function()")
        head = body[:start]
        assert re.search(r'<script nonce="[^"]+">', head[head.rindex("<script") :]), (
            "the rewriter lives in a nonce'd script"
        )
        assert "htmx:afterSwap" in body[start : start + 6000]


class TestTheAuthorDraftIsDroppedOnSuccessOnly:
    """Second pass SP-1: the Author page's draft (sessionStorage) is dropped by the page AFTER a written config - the server says so, once - and by nothing else."""

    def test_the_marker_is_carried_once_and_only_for_a_known_service(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["author_draft_done"] = "dhcp4"
        first = logged_in_client.get("/").data.decode()
        second = logged_in_client.get("/").data.decode()
        assert 'var done = "dhcp4";' in first
        assert "var done = null;" in second
        with logged_in_client.session_transaction() as sess:
            sess["author_draft_done"] = "x'; alert(1); '"
        assert "var done = null;" in logged_in_client.get("/").data.decode()

    def test_the_route_sets_it_in_the_ok_branch_only_and_nothing_else_marks_an_apply(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        text = (root / "jen" / "routes" / "settings" / "authoring.py").read_text(encoding="utf-8")
        assert text.count('session["author_draft_done"]') == 1
        ok = text.index('if result.status == "ok":')
        assert ok < text.index('session["author_draft_done"]') < text.index("else:", ok)
        for name in ("templates/base.html", "templates/author_kea_config.html"):
            assert "jen-author-applying" not in (root / name).read_text(encoding="utf-8"), name


class TestABadgeWithNoNameIsNotAnEmptyLink:
    def test_a_subnet_jen_does_not_list_prints_its_number_and_is_not_a_link(self, app):
        from flask import render_template_string

        with app.test_request_context("/leases"):
            out = render_template_string(
                "{% from '_subnet_badge.html' import subnet_badge %}{{ subnet_badge(3, '', link=True) }}"
            )
        assert "<a " not in out and "#3" in out
