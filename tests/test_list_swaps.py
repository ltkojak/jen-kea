"""
tests/test_list_swaps.py
────────────────────────
v5.70.0-beta.4 (Q208, AX1): the column headers and the page numbers of Leases, Devices and Reservations swap their results in place. Each link KEEPS its `href` (the no-script fallback, a new
tab, and the thing the older tests pin), and gains `hx-get` with the same URL, the id the page's filter form already targets, and `hx-push-url`. The sorted header says so with `aria-sort`.
"""

import re
from html.parser import HTMLParser

import pytest

from tests import test_authz_matrix as _matrix
from tests.test_authz_matrix import _caller, assert_no_marker

# the matrix's own fixtures (the two subnets A and B, and the client in B), used here by name
_subnets = _matrix._subnets
seeded = _matrix.seeded

HX = {"HX-Request": "true"}
PAGES = [
    # path, the id the filter form targets, a column the page sorts by
    ("/leases", "#leases-results", "hostname"),
    ("/devices", "#devices-results", "device_name"),
    ("/reservations", "#reservations-results", "hostname"),
]


class _Page(HTMLParser):
    """Collects `.th-link` anchors, `.pagination a` anchors and every `th[aria-sort]`."""

    def __init__(self):
        super().__init__()
        self.th_links, self.page_links, self.aria_sorts = [], [], []
        self._in_pagination = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "div" and "pagination" in (a.get("class") or "").split():
            self._in_pagination = 1
        elif tag == "div" and self._in_pagination:
            self._in_pagination += 1
        if tag == "th" and "aria-sort" in a:
            self.aria_sorts.append(a["aria-sort"])
        if tag == "a" and "th-link" in (a.get("class") or "").split():
            self.th_links.append(a)
        elif tag == "a" and self._in_pagination:
            self.page_links.append(a)

    def handle_endtag(self, tag):
        if tag == "div" and self._in_pagination:
            self._in_pagination -= 1


def parse(html):
    p = _Page()
    p.feed(html)
    return p


@pytest.fixture
def three_rows(db):
    """Three rows on each list, in subnet 1, so per_page=1 gives three pages."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        cur.execute("DELETE FROM devices WHERE mac LIKE 'ac:00:00:00:00:%%'")
        for n in (1, 2, 3):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, %s)",
                (f"10.99.0.{60 + n}", f"AC000000000{n}", f"swap-{n}"),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), %s)",
                (f"AC000000000{n}", f"10.99.0.{70 + n}", f"swap-res-{n}"),
            )
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) "
                "VALUES (%s, %s, %s, 1, %s, NOW(), NOW())",
                (f"ac:00:00:00:00:0{n}", f"10.99.0.{60 + n}", f"swap-{n}", f"swap-device-{n}"),
            )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
        cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        cur.execute("DELETE FROM devices WHERE mac LIKE 'ac:00:00:00:00:%%'")
    db.commit()


class TestSortAndPageLinksSwap:
    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_the_filter_forms_target_is_what_the_links_name(self, logged_in_client, three_rows, path, target, col):
        shell = logged_in_client.get(path).data.decode()
        assert f'hx-target="{target}"' in shell, (
            "the page's own filter form no longer targets this id: read it, do not guess"
        )
        assert f'<div id="{target[1:]}">' in shell

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_every_header_and_page_link_swaps_and_keeps_its_href(self, logged_in_client, three_rows, path, target, col):
        html = logged_in_client.get(f"{path}?per_page=1&sort={col}&dir=asc", headers=HX).data.decode()
        links = parse(html)
        assert links.th_links, "the partial has no sortable header"
        assert links.page_links, "per_page=1 over three rows must paginate"
        for a in links.th_links + links.page_links:
            assert a.get("href", "").startswith("?"), a
            assert a.get("hx-get") == a["href"], a
            assert a.get("hx-target") == target, a
            assert a.get("hx-push-url") == "true", a

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_a_page_link_scrolls_to_the_top_and_a_sort_link_does_not(
        self, logged_in_client, three_rows, path, target, col
    ):
        links = parse(logged_in_client.get(f"{path}?per_page=1&sort={col}&dir=asc", headers=HX).data.decode())
        assert all("show:top" in a.get("hx-swap", "") for a in links.page_links)
        assert not any("hx-swap" in a for a in links.th_links)

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    @pytest.mark.parametrize("direction", ["asc", "desc"])
    def test_exactly_one_header_is_aria_sorted_and_it_follows_dir(
        self, logged_in_client, three_rows, path, target, col, direction
    ):
        links = parse(logged_in_client.get(f"{path}?per_page=1&sort={col}&dir={direction}", headers=HX).data.decode())
        assert links.aria_sorts == ["ascending" if direction == "asc" else "descending"]

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_the_full_page_carries_the_same_links(self, logged_in_client, three_rows, path, target, col):
        full = parse(logged_in_client.get(f"{path}?per_page=1&sort={col}&dir=asc").data.decode())
        assert full.th_links and all(a.get("hx-get") == a["href"] for a in full.th_links)

    def test_the_arrow_glyphs_stay(self, logged_in_client, three_rows):
        html = logged_in_client.get("/leases?sort=hostname&dir=asc", headers=HX).data.decode()
        assert "Hostname ↑" in html


class TestAHistoryRestoreGetsTheFullPage:
    """SP-5: htmx's history restore (Back, cache miss) sends HX-Request AND HX-History-Restore-Request and swaps the answer in as the whole page - a bare partial would replace the body."""

    RESTORE = {"HX-Request": "true", "HX-History-Restore-Request": "true"}

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_it_is_a_document(self, logged_in_client, three_rows, path, target, col):
        html = logged_in_client.get(f"{path}?sort={col}&dir=desc&per_page=1&page=2", headers=self.RESTORE).data.decode()
        assert "<html" in html and "<nav" in html and f'id="{target[1:]}"' in html

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_an_ordinary_swap_is_still_the_partial(self, logged_in_client, three_rows, path, target, col):
        assert "<html" not in logged_in_client.get(f"{path}?per_page=1&page=2", headers=HX).data.decode()

    @pytest.mark.parametrize("path", ["/leases?view=v6", "/devices?view=v6", "/reservations?view=v6"])
    def test_the_v6_views_too(self, logged_in_client, ipv6_flag_on, path):
        assert "<html" in logged_in_client.get(path, headers=self.RESTORE).data.decode()


class TestTheFallbackIsUnchanged:
    """The href assertions of tests/test_leases.py, tests/test_devices_page.py and tests/test_reservations.py are untouched: the links still carry the exact `?sort=...` and `?page=...` text."""

    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_the_href_is_the_old_text(self, logged_in_client, three_rows, path, target, col):
        links = parse(
            logged_in_client.get(f"{path}?per_page=1&sort={col}&dir=asc&search=swap", headers=HX).data.decode()
        )
        sorts = [a["href"] for a in links.th_links]
        assert all(re.match(r"\?sort=\w+&dir=(asc|desc)&", h) for h in sorts), sorts
        pages = [a["href"] for a in links.page_links]
        assert all(re.match(r"\?page=\d+&", h) for h in pages), pages
        assert all("search=swap" in h and "per_page=1" in h for h in sorts + pages), "a swap keeps every other argument"


class TestAScopedAccountSeesTheSameRowsThroughASortLink:
    """The links call the same routes, so the test is the four-principal shape of tests/test_authz_matrix.py: a caller scoped to A names no part of B through a sort or page link."""

    @pytest.mark.parametrize("role", ["viewer_A", "admin_A"])
    @pytest.mark.parametrize(("path", "target", "col"), PAGES)
    def test_a_sort_by_subnet_through_the_swap_lists_no_hidden_subnet(
        self, client, db, seeded, role, path, target, col
    ):
        _caller(client, db, role)
        for query in (
            "sort=subnet&dir=asc",
            "sort=subnet&dir=desc",
            "sort=subnet&dir=asc&per_page=1&page=2",
            f"sort={col}&dir=desc&per_page=1",
        ):
            html = client.get(f"{path}?{query}", headers=HX).data.decode()
            assert_no_marker(html)
            for a in parse(html).th_links + parse(html).page_links:
                assert_no_marker(a.get("href", "") + a.get("hx-get", ""))

    @pytest.mark.parametrize("path", [p for p, _t, _c in PAGES])
    def test_the_unrestricted_caller_does_see_b_so_the_absence_above_is_a_fact(self, client, db, seeded, path):
        _caller(client, db, "admin_all")
        html = client.get(f"{path}?sort=subnet&dir=asc", headers=HX).data.decode()
        assert "ZZ-SECRET-B" in html or "10.77.0." in html
