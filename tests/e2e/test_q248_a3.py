"""
tests/e2e/test_q248_a3.py
─────────────────────────
Q248, stage a3 - the lists, wide monitors and the way back, measured in a real browser with the CSP on, against the live server.

* V12  a lease, a reservation and a device with an 85-character hostname, at 1440, 1024 and 2560 px: the page does not scroll sideways, the table's right edge is
       inside its card, every row menu is inside the window, and the long cell's title is the whole value. The audit log's long details the same, and they open.
* V13  the four lists at 1024, 1100 and 1280 px: no sideways scroll, no date and no badge on two lines; Devices keeps Last seen, Leases keeps Expires.
* V48  the list search boxes' placeholders fit their fields at 1440 px and on a phone; Phosphor's wider font does not wrap the Leases filter row at 1440 px.
* V51  at 390 px each lease, reservation and device card shows its MAC; a device card its subnet and its status.
* V54  at 2560 and 1920 px the first strip tab starts where the page title does, the pin button ends where the content does, a table page is wider than 1,400 px and
       at most 1,800 px, Settings - Kea is at most 1,400 px, and both bars still run edge to edge.
* addition 4  a plugin's detail page, Trace and Saved searches show their parent's strip with its tab lit; the two core pages' back link goes back.
* addition 5  the marks, the two summary filters (kept by a search and a sort, counted by the phone's Filters button, cleared by Clear), the relative expiry.
"""

import re
from datetime import datetime, timedelta

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

PHONE = {"width": 390, "height": 844}
LONG = "conference-room-display-with-a-very-long-descriptive-hostname-b2.lab.example.internal"
LONG_NAME = "Wall display, north side, by the door, behind the plant, above the radiator"
LONG_DETAILS = (
    "Changed the pool of subnet 1 from 10.99.0.100 - 10.99.0.199 to 10.99.0.100 - 10.99.0.220 and its lease time. " * 4
)
LEASE_MACS = ("AABBCC2483E1", "AABBCC2483E4", "AABBCC2483E5")  # the long one, the one about to expire, the reserved one
HOST_MACS = ("AABBCC2483E2", "AABBCC2483E5")
DEVICE_MAC = "aa:bb:cc:24:83:e3"
MAC_TEXT = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
LISTS = ["/leases", "/reservations", "/devices", "/settings/logs"]


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


def _wipe(cur):
    for mac in LEASE_MACS:
        cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (mac,))
    for mac in HOST_MACS:
        cur.execute("DELETE FROM hosts WHERE dhcp_identifier=UNHEX(%s)", (mac,))
    cur.execute("DELETE FROM devices WHERE mac=%s", (DEVICE_MAC,))
    cur.execute("DELETE FROM audit_log WHERE action='Q248_A3_LONG'")


@pytest.fixture
def rows():
    """In subnet 1: a lease, a reservation and a device whose hostname is 85 characters; a lease that expires in twenty minutes; a lease that is reserved; an audit
    event with long details. Removed again: every journey of the suite shares one database."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            _wipe(cur)
            for ip, mac, host, expire in (
                ("10.99.0.181", LEASE_MACS[0], LONG, "DATE_ADD(NOW(), INTERVAL 2 HOUR)"),
                ("10.99.0.183", LEASE_MACS[1], "q248a3-soon", "DATE_ADD(NOW(), INTERVAL 20 MINUTE)"),
                ("10.99.0.184", LEASE_MACS[2], "q248a3-resv", "DATE_ADD(NOW(), INTERVAL 6 HOUR)"),
            ):
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                    f"VALUES (INET_ATON(%s), UNHEX(%s), 86400, {expire}, 1, %s, 0)",  # nosec B608 - test seed
                    (ip, mac, host),
                )
            for ip, mac, host in (("10.99.0.182", HOST_MACS[0], LONG), ("10.99.0.184", HOST_MACS[1], "q248a3-resv")):
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                    "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), %s)",
                    (mac, ip, host),
                )
            cur.execute(
                "INSERT INTO devices (mac, device_name, owner, last_ip, last_hostname, last_subnet_id, manufacturer, device_type, first_seen, last_seen) "
                "VALUES (%s, %s, 'Facilities and audio visual', '10.99.0.181', %s, 1, 'Shenzhen Extremely Long Manufacturer Name Technology Co., Ltd.', 'tv', NOW(), NOW())",
                (DEVICE_MAC, LONG_NAME, LONG),
            )
            cur.execute(
                "INSERT INTO audit_log (user_id, username, action, entity, details, ip_address) VALUES (1, 'admin', 'Q248_A3_LONG', 'subnets', %s, '10.0.0.9')",
                (LONG_DETAILS,),
            )
        yield
    finally:
        with conn.cursor() as cur:
            _wipe(cur)
        conn.close()


def _at(page, base_url, width, height=1000):
    """Sign in as the superadmin at this width, with every script error collected."""
    page.set_viewport_size({"width": width, "height": height})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    return errors


@pytest.fixture
def phone(browser, base_url):
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()
    assert not errors, errors


# what a list page measures: the page, its table against its card, its row menus, its rows
LIST_JS = """() => {
    const t = document.querySelector('.container table.rowlist');
    const card = t.closest('.card');
    const tr = t.getBoundingClientRect(), cr = card.getBoundingClientRect();
    const menus = Array.from(t.querySelectorAll('.action-menu-btn')).map(b => b.getBoundingClientRect());
    const lines = e => e.getClientRects().length;
    return {
        sideways: document.documentElement.scrollWidth - window.innerWidth,
        table_right: tr.right, card_right: cr.right, table_left: tr.left, card_left: cr.left,
        menus: menus.length,
        menus_outside: menus.filter(r => r.right > window.innerWidth + 0.5 || r.right > cr.right + 0.5 || r.left < cr.left - 0.5).length,
        broken_times: Array.from(t.querySelectorAll('tbody time')).filter(e => lines(e) > 1).length,
        tall_badges: Array.from(t.querySelectorAll('tbody .badge')).filter(e => e.getBoundingClientRect().height > 28).length,
        tallest_row: Math.max(0, ...Array.from(t.querySelectorAll('tbody tr')).map(r => r.getBoundingClientRect().height)),
        headers: Array.from(t.querySelectorAll('thead th')).filter(th => getComputedStyle(th).display !== 'none').map(th => th.innerText.replace(/[↑↓]/g, '').trim().toUpperCase()),
    };
}"""


def _open(page, base_url, path):
    page.goto(f"{base_url}{path}")
    page.wait_for_load_state("networkidle")
    return page.evaluate(LIST_JS)


# ───────────────────────────── V12: one long value ─────────────────────────────


class TestALongValueNeverPushesAListOffThePage:
    @pytest.mark.parametrize("width", [1440, 1024, 2560])
    @pytest.mark.parametrize("path", ["/leases", "/reservations", "/devices"])
    def test_the_table_stays_in_its_card_and_the_row_menus_in_the_window(self, page, base_url, rows, path, width):
        errors = _at(page, base_url, width)
        m = _open(page, base_url, path)
        assert m["sideways"] <= 0, m
        assert m["table_right"] <= m["card_right"] + 1 and m["table_left"] >= m["card_left"] - 1, m
        assert m["menus"] > 0 and m["menus_outside"] == 0, m
        # the long cell: one line, and its title is the whole value
        cell = page.locator(f'.container table.rowlist .clip[title="{LONG}"]').first
        expect(cell).to_be_visible()
        assert cell.inner_text() == LONG, "the whole value is in the page; the cell only shows what fits"
        assert cell.bounding_box()["height"] < 30
        if width == 1024:
            assert cell.evaluate("e => e.scrollHeight > e.clientHeight + 1"), (
                "at 1024 px the value does not fit its column: it is cut"
            )
        assert not errors, errors

    def test_a_cut_value_ends_in_an_ellipsis_and_keeps_what_follows_it_beside_it(self, page, base_url, rows):
        _at(page, base_url, 1024)
        page.goto(f"{base_url}/leases?search=conference-room")
        cell = page.locator(f'.clip[title="{LONG}"]')
        assert cell.evaluate("e => getComputedStyle(e).webkitLineClamp") == "1"
        # the row is as tall as every other row (one line), and its menu is where the others' are
        m = page.evaluate(LIST_JS)
        assert m["tallest_row"] < 60 and m["menus_outside"] == 0, m

    @pytest.mark.parametrize("width", [1440, 1024, 2560])
    def test_the_audit_logs_long_details(self, page, base_url, rows, width):
        errors = _at(page, base_url, width)
        m = _open(page, base_url, "/settings/logs")
        assert m["sideways"] <= 0 and m["table_right"] <= m["card_right"] + 1, m
        cell = page.locator(".clip[data-clip-toggle]", has_text="Changed the pool of subnet 1").first
        assert cell.get_attribute("title") == LONG_DETAILS
        closed = cell.bounding_box()["height"]
        assert closed < 30, "one line"
        # an event has no page of its own: a click opens the details where they are, and a click closes them
        cell.click()
        assert cell.bounding_box()["height"] > closed + 10
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        cell.click()
        assert abs(cell.bounding_box()["height"] - closed) < 1
        assert not errors, errors


# ───────────────────────────── V13: the lists at 1024, 1100 and 1280 px ─────────────────────────────


class TestTheListsAtNarrowWidths:
    @pytest.mark.parametrize("width", [1024, 1100, 1280])
    @pytest.mark.parametrize("path", LISTS)
    def test_no_sideways_scroll_and_nothing_on_two_lines(self, page, base_url, rows, path, width):
        errors = _at(page, base_url, width)
        m = _open(page, base_url, path)
        assert m["sideways"] <= 0, m
        assert m["table_right"] <= m["card_right"] + 1, m
        assert m["menus_outside"] == 0, m
        assert m["broken_times"] == 0 and m["tall_badges"] == 0, m
        assert m["tallest_row"] < 60, "a row is one line of text at every width"
        assert not errors, errors

    @pytest.mark.parametrize("width", [1024, 1100, 1280, 1440])
    def test_devices_keeps_last_seen_and_drops_first_seen_first(self, page, base_url, rows, width):
        _at(page, base_url, width)
        heads = _open(page, base_url, "/devices")["headers"]
        assert "LAST SEEN" in heads and "STATUS" in heads and "MAC ADDRESS" in heads and "" in heads[-1:], heads
        assert ("FIRST SEEN" in heads) == (width >= 1440), heads
        assert ("OWNER" in heads) == (width >= 1440), heads
        assert ("TYPE" in heads) == (width >= 1280), heads

    @pytest.mark.parametrize("width", [1024, 1100, 1280])
    def test_leases_keeps_expires_and_drops_obtained(self, page, base_url, rows, width):
        _at(page, base_url, width)
        heads = _open(page, base_url, "/leases")["headers"]
        assert "EXPIRES" in heads and "MAC ADDRESS" in heads, heads
        assert ("OBTAINED" in heads) == (width >= 1280), heads

    def test_a_dropped_column_takes_its_cells_with_it(self, page, base_url, rows):
        """Each visible header is over a visible cell of the same column (a header hidden without its cells shifts every column after it)."""
        _at(page, base_url, 1024)
        for path in ("/devices", "/leases"):
            page.goto(f"{base_url}{path}")
            shown = page.evaluate(
                """() => {
                    const t = document.querySelector('.container table.rowlist');
                    const vis = e => getComputedStyle(e).display !== 'none';
                    const head = Array.from(t.querySelectorAll('thead th')).map(vis);
                    return Array.from(t.querySelectorAll('tbody tr')).filter(r => r.children.length === head.length)
                        .map(r => Array.from(r.children).map(vis).join()).filter(s => s !== head.join()).length;
                }"""
            )
            assert shown == 0, path


# ───────────────────────────── V48: the list search boxes ─────────────────────────────

# the placeholder as text in the field: a field scrolls what does not fit, so scrollWidth past clientWidth is a cut placeholder
PLACEHOLDER_FITS = """() => {
    const e = document.querySelector('.filter-bar input[name=search]');
    const typed = e.value;
    e.value = e.placeholder;
    const fits = e.scrollWidth <= e.clientWidth + 1;
    e.value = typed;
    return {placeholder: e.placeholder, fits: fits, width: e.clientWidth, name: e.getAttribute('aria-label'), title: e.title};
}"""


class TestTheListSearchBoxes:
    @pytest.mark.parametrize(
        "path,words",
        [("/leases", "Search leases"), ("/reservations", "Search"), ("/devices", "Search devices")],
    )
    def test_the_placeholder_fits_at_1440(self, page, base_url, path, words):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}{path}")
        m = page.evaluate(PLACEHOLDER_FITS)
        assert m["placeholder"] == words and m["fits"], m
        assert m["name"] == m["title"] and m["name"].startswith("Search by "), m

    @pytest.mark.parametrize(
        "path",
        [
            "/leases",
            "/leases?subnet=1&reserved=1",
            "/reservations",
            "/reservations?subnet=1",
            "/devices",
            "/devices?subnet=1",
        ],
    )
    def test_the_placeholder_fits_on_a_phone(self, phone, base_url, rows, path):
        """Beside the Filters button (with and without its count) and the Select button, which a list with rows has: the field's narrowest."""
        phone.goto(f"{base_url}{path}")
        expect(phone.locator(".filter-bar .select-toggle")).to_be_visible()
        if "subnet=1" in path:
            expect(phone.locator(".fs-count-label")).to_have_text(re.compile(r"Filters \(\d\)"))
        m = phone.evaluate(PLACEHOLDER_FITS)
        assert m["fits"], m
        assert phone.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    def test_phosphors_wider_font_does_not_wrap_the_leases_filter_row_at_1440(self, browser, base_url, rows):
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        ctx.add_init_script("try { localStorage.setItem('jen-theme-pick', 'phosphor'); } catch (e) {}")
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        page.goto(f"{base_url}/leases")
        assert page.evaluate("document.documentElement.getAttribute('data-theme')") == "phosphor"
        tops = page.evaluate(
            """() => Array.from(document.querySelectorAll('.filter-bar select, .filter-bar input:not([type=hidden]), .filter-bar .btn'))
                .filter(e => e.getClientRects().length).map(e => Math.round(e.getBoundingClientRect().top))"""
        )
        assert len(tops) >= 9 and max(tops) - min(tops) < 20, tops
        assert page.evaluate(PLACEHOLDER_FITS)["fits"]
        # and with both of the summary's filters on (they are fields of this form) the row is the same row
        page.goto(f"{base_url}/leases?reserved=1&expiring=1")
        again = page.evaluate(
            """() => Array.from(document.querySelectorAll('.filter-bar select, .filter-bar input:not([type=hidden]), .filter-bar .btn'))
                .filter(e => e.getClientRects().length).map(e => Math.round(e.getBoundingClientRect().top))"""
        )
        assert again == tops
        ctx.close()


# ───────────────────────────── V51: a phone card shows its MAC ─────────────────────────────

CARDS_JS = """() => Array.from(document.querySelectorAll('.container table.rowlist tbody tr')).filter(r => r.querySelector('td[data-m]:not([data-m=full])')).map(r => {
    const mac = r.querySelector('td[data-m=third] button.copy[data-copy]');
    const second = r.querySelector('td[data-m=secondary]');
    const box = e => e ? e.getBoundingClientRect() : null;
    const row = box(r), m = box(mac), s = box(second);
    return {
        mac: mac ? mac.innerText.trim() : null,
        shown: !!m && m.width > 0 && m.height > 0 && m.left >= row.left && m.right <= row.right + 0.5,
        below: !!m && !!s && m.top >= s.bottom - 2,
        font: mac ? getComputedStyle(mac).fontFamily : '',
        size: mac ? parseFloat(getComputedStyle(mac).fontSize) : 0,
        thirds: Array.from(r.querySelectorAll('td[data-m=third]')).filter(td => getComputedStyle(td).display !== 'none').map(td => td.innerText.trim()),
    };
})"""


class TestAPhoneCardShowsItsMac:
    @pytest.mark.parametrize("path", ["/leases", "/reservations", "/devices"])
    def test_each_card_shows_its_mac_as_a_third_line_in_the_code_font(self, phone, base_url, rows, path):
        phone.goto(f"{base_url}{path}")
        phone.wait_for_load_state("networkidle")
        cards = phone.evaluate(CARDS_JS)
        assert cards, "the list is empty"
        for card in cards:
            assert card["mac"] and MAC_TEXT.match(card["mac"]), card
            assert card["shown"] and card["below"], card
            assert "mono" in card["font"].lower() and card["size"] <= 12, card
        assert phone.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    def test_a_device_card_keeps_its_subnet_and_its_status(self, phone, base_url, rows):
        phone.goto(f"{base_url}/devices?search=radiator")
        phone.wait_for_load_state("networkidle")
        cards = phone.evaluate(CARDS_JS)
        assert len(cards) == 1
        assert cards[0]["thirds"][0].lower() == DEVICE_MAC
        assert cards[0]["thirds"][1] == "Office" and "Dynamic" in cards[0]["thirds"][2], cards[0]

    def test_the_mac_is_still_the_copy_control_and_the_row_still_opens_its_menu(self, phone, base_url, rows):
        phone.goto(f"{base_url}/leases?search=q248a3-resv")
        row = phone.locator("#leases-table-body tr").first
        mac = row.locator('td[data-m="third"] button.copy')
        assert mac.get_attribute("data-copy").replace(":", "").upper() == LEASE_MACS[2]
        mac.tap()
        expect(row.locator(".action-menu-toggle")).not_to_be_checked()  # the tap was the button's own
        row.locator('td[data-m="primary"]').tap(position={"x": 4, "y": 4})
        expect(row.locator(".action-menu-toggle")).to_be_checked()


# ───────────────────────────── addition 5: the marks, the filters, the expiry ─────────────────────────────


def _shown_hosts(page):
    return page.locator("#leases-table-body .clip").all_inner_texts()


class TestLeaseRowsShowWhatTheSummaryCounts:
    def test_the_marks_are_on_the_rows(self, page, base_url, rows):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases?search=q248a3")
        soon = page.locator("#leases-table-body tr", has_text="q248a3-soon")
        resv = page.locator("#leases-table-body tr", has_text="q248a3-resv")
        expect(soon.locator(".row-mark", has_text="Expires soon")).to_be_visible()
        expect(resv.locator(".row-mark", has_text="Reserved")).to_be_visible()
        assert soon.locator(".row-mark").count() == 1 and resv.locator(".row-mark").count() == 1
        expect(page.locator("#leases-summary")).to_contain_text(
            "2 active leases · 1 expires within the hour · 1 reserved"
        )

    def test_a_compact_row_stays_compact_with_a_mark_and_a_clip_in_it(self, browser, base_url, rows):
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        ctx.add_init_script("try { localStorage.setItem('jen-density-pick', 'compact'); } catch (e) {}")
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        for path in ("/leases", "/devices", "/reservations"):
            m = _open(page, base_url, path)
            assert 0 < m["tallest_row"] <= 40, (path, m)
        ctx.close()

    def test_the_reserved_count_filters_the_list_and_a_search_and_a_sort_keep_it(self, page, base_url, rows):
        errors = _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases?search=q248a3")
        assert sorted(_shown_hosts(page)) == ["q248a3-resv", "q248a3-soon"]
        page.locator("#leases-summary a.summary-filter", has_text="reserved").click()
        page.wait_for_url(re.compile(r"reserved=1"))
        assert "search=q248a3" in page.url
        assert _shown_hosts(page) == ["q248a3-resv"]
        chip = page.locator("#leases-summary a.filter-chip")
        expect(chip).to_have_text(re.compile(r"Reserved only"))
        assert chip.bounding_box()["height"] >= 24
        # the form's own refresh (a changed search, 400 ms later) keeps the filter: it is a field of the form
        page.fill('.filter-bar input[name="search"]', "q248a3-")
        page.wait_for_url(re.compile(r"search=q248a3-(&|$)"))
        assert "reserved=1" in page.url and _shown_hosts(page) == ["q248a3-resv"]
        # so does a sort
        page.locator("#leases-results thead a.th-link", has_text="IP Address").click()
        page.wait_for_url(re.compile(r"sort=ip"))
        assert "reserved=1" in page.url and _shown_hosts(page) == ["q248a3-resv"]
        # the chip takes the filter away and keeps the search
        page.locator("#leases-summary a.filter-chip").click()
        page.wait_for_url(lambda url: "reserved=1" not in url)
        assert "search=q248a3-" in page.url and sorted(_shown_hosts(page)) == ["q248a3-resv", "q248a3-soon"]
        assert not errors, errors

    def test_the_expiring_count_filters_the_list_and_clear_clears_it(self, page, base_url, rows):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases?search=q248a3")
        page.locator("#leases-summary a.summary-filter", has_text="within the hour").click()
        page.wait_for_url(re.compile(r"expiring=1"))
        assert _shown_hosts(page) == ["q248a3-soon"]
        expect(page.locator("#leases-summary a.filter-chip")).to_have_text(re.compile(r"Expiring soon only"))
        page.locator(".filter-bar a.btn", has_text="Clear").click()
        page.wait_for_url(re.compile(r"/leases$"))
        assert page.locator("#leases-summary a.filter-chip").count() == 0

    def test_the_phones_filters_button_counts_them_and_its_sheet_holds_them(self, phone, base_url, rows):
        phone.goto(f"{base_url}/leases")
        expect(phone.locator(".fs-count-label")).to_have_text("Filters")
        phone.goto(f"{base_url}/leases?reserved=1&search=q248a3")
        expect(phone.locator(".fs-count-label")).to_have_text("Filters (1)")
        assert _shown_hosts(phone) == ["q248a3-resv"]
        phone.locator(".fs-filter-toggle").tap()
        reserved = phone.locator('.filter-bar input[name="reserved"]')
        expiring = phone.locator('.filter-bar input[name="expiring"]')
        expect(reserved).to_be_visible()
        expect(reserved).to_be_checked()
        expect(expiring).not_to_be_checked()
        expiring.check()
        expect(phone.locator(".fs-count-label")).to_have_text("Filters (2)")
        phone.wait_for_url(re.compile(r"expiring=1"))
        assert "reserved=1" in phone.url
        expect(phone.locator("#leases-summary")).to_contain_text("0 active leases")
        # Clear, in the same sheet, clears both
        phone.locator(".filter-bar a.btn", has_text="Clear").tap()
        phone.wait_for_url(re.compile(r"/leases$"))
        expect(phone.locator(".fs-count-label")).to_have_text("Filters")

    def test_a_desktop_does_not_show_the_two_boxes_in_its_filter_row(self, page, base_url, rows):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases?reserved=1")
        box = page.locator('.filter-bar input[name="reserved"]')
        expect(box).to_be_hidden()
        expect(box).to_be_checked()

    @pytest.mark.parametrize("mode", ["utc", "local"])
    def test_the_expiry_is_relative_and_its_title_is_the_exact_time_in_the_readers_mode(
        self, browser, base_url, rows, mode
    ):
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, timezone_id="Asia/Tokyo")
        ctx.add_init_script(f"try {{ localStorage.setItem('jen-time-pick', '{mode}'); }} catch (e) {{}}")
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        page.goto(f"{base_url}/leases?search=q248a3-resv")
        cell = page.locator('#leases-table-body time[data-jen-time="rel"]').first
        expect(cell).to_be_visible()
        assert re.fullmatch(r"in (5|6) h", cell.inner_text())
        moment = datetime.strptime(cell.get_attribute("datetime"), "%Y-%m-%dT%H:%M:%SZ")
        title = cell.get_attribute("title")
        if mode == "utc":
            assert title == moment.strftime("%Y-%m-%d %H:%M") + " UTC"
        else:
            assert title.startswith((moment + timedelta(hours=9)).strftime("%Y-%m-%d %H:%M")) and not title.endswith(
                "UTC"
            ), title
        # with no script the title is the wrapper's: the UTC time
        assert cell.locator("xpath=..").get_attribute("title") == moment.strftime("%Y-%m-%d %H:%M") + " UTC"
        ctx.close()


# ───────────────────────────── V54: wide monitors ─────────────────────────────

BARS_JS = """() => {
    const box = s => { const e = document.querySelector(s); return e ? e.getBoundingClientRect() : null; };
    const c = document.querySelector('.container'), cs = getComputedStyle(c), cr = c.getBoundingClientRect();
    const tab = box('.section-tabs .section-tab'), h1 = box('.page-header h1'), pin = box('.section-pin-btn'), brand = box('.nav-brand'), search = box('.nav-search');
    const links = document.querySelector('.nav-links');
    return {
        content_width: cr.width, content_left: cr.left + parseFloat(cs.paddingLeft), content_right: cr.right - parseFloat(cs.paddingRight),
        tab_left: tab ? tab.left : null, title_left: h1 ? h1.left : null, pin_right: pin ? pin.right : null,
        brand_left: brand ? brand.left : null, search_right: search ? search.right : null,
        nav_width: box('nav.nav').width, strip_width: box('.section-tabs-wrap') ? box('.section-tabs-wrap').width : null,
        links_cut: links.scrollWidth > links.clientWidth + 1, fit: document.querySelector('nav.nav').getAttribute('data-fit'),
        window: document.documentElement.clientWidth, sideways: document.documentElement.scrollWidth - window.innerWidth,
    };
}"""


@pytest.fixture
def clean_nav():
    def wipe():
        conn = _db()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_nav")
        finally:
            conn.close()

    wipe()
    yield
    wipe()


class TestWideMonitors:
    @pytest.mark.parametrize("width", [2560, 1920])
    @pytest.mark.parametrize("path", ["/reservations", "/devices", "/settings/logs"])
    def test_a_table_pages_content_is_wider_and_its_bars_are_where_every_pages_are(
        self, page, base_url, clean_nav, path, width
    ):
        # Q249: the bars do not follow the wider content. They are measured against a form page at the same width: the logo, the first tab and the search box
        # are at the same x on both, so nothing in the two bars moves when a person goes from one page to the next.
        errors = _at(page, base_url, width)
        page.goto(f"{base_url}/settings/kea")
        form = page.evaluate(BARS_JS)
        page.goto(f"{base_url}{path}")
        m = page.evaluate(BARS_JS)
        assert 1400 < m["content_width"] <= 1800, m
        assert m["title_left"] < m["tab_left"], m  # the content is wider than the bars
        for key in ("brand_left", "search_right", "tab_left"):
            assert abs(m[key] - form[key]) <= 1, (key, m, form)
        # and both bars' backgrounds still run edge to edge
        assert m["nav_width"] == m["window"] and m["strip_width"] == m["window"] and m["sideways"] <= 0, m
        assert not m["links_cut"] and m["fit"] == "0", m
        assert not errors, errors

    @pytest.mark.parametrize("width", [2560, 1920])
    def test_leases_has_no_pin_and_lines_up_too(self, page, base_url, clean_nav, width):
        _at(page, base_url, width)
        page.goto(f"{base_url}/leases")
        m = page.evaluate(BARS_JS)
        assert 1400 < m["content_width"] <= 1800 and m["pin_right"] is None, m
        assert m["title_left"] < m["tab_left"], m  # Q249: the bars keep their one column; only the content is wider

    @pytest.mark.parametrize("width", [2560, 1920])
    @pytest.mark.parametrize("path", ["/settings/kea", "/reports"])
    def test_a_form_page_stays_1400_and_its_bars_line_up_with_it(self, page, base_url, clean_nav, path, width):
        _at(page, base_url, width)
        page.goto(f"{base_url}{path}")
        m = page.evaluate(BARS_JS)
        assert m["content_width"] <= 1400, m
        assert abs(m["tab_left"] - m["title_left"]) <= 2 and abs(m["pin_right"] - m["content_right"]) <= 2, m
        assert abs(m["brand_left"] - m["content_left"]) <= 2 and abs(m["search_right"] - m["content_right"]) <= 2, m
        assert m["nav_width"] == m["window"] and m["strip_width"] == m["window"], m

    @pytest.mark.parametrize("width", [1440, 1024])
    def test_the_bars_keep_the_contents_side_padding_at_laptop_and_tablet_widths(
        self, page, base_url, clean_nav, width
    ):
        _at(page, base_url, width)
        page.goto(f"{base_url}/settings/kea")
        form = page.evaluate(BARS_JS)
        page.goto(f"{base_url}/reservations")
        m = page.evaluate(BARS_JS)
        # Q249: the bars are a form page's bars at every width; a table page's content may start up to the 20 px of the centered column's margin to their left
        # (at 1440 px the bars' column is 1,400 px and the table uses the whole window), and at 1024 px the two are one column
        assert abs(m["brand_left"] - form["brand_left"]) <= 1 and abs(m["tab_left"] - form["tab_left"]) <= 1, (m, form)
        slack = 22 if width > 1400 else 2
        assert -2 <= m["tab_left"] - m["title_left"] <= slack and -2 <= m["content_right"] - m["pin_right"] <= slack, m
        assert -2 <= m["brand_left"] - m["content_left"] <= slack, m

    def test_abouts_release_notes_are_about_80_characters_a_line(self, page, base_url):
        _at(page, base_url, 2560)
        page.goto(f"{base_url}/about")
        widths = page.evaluate(
            """() => Array.from(document.querySelectorAll('.changelog-body')).filter(e => e.getClientRects().length).map(e => {
                const probe = document.createElement('span'); probe.textContent = '0'.repeat(80); probe.style.visibility = 'hidden'; probe.style.whiteSpace = 'nowrap';
                e.appendChild(probe); const ch80 = probe.getBoundingClientRect().width; probe.remove();
                return [e.getBoundingClientRect().width, ch80];
            })"""
        )
        assert widths, "About shows no release notes"
        for width, ch80 in widths:
            assert width <= ch80 + 1 and width < 800, (width, ch80)
        assert page.evaluate("document.querySelector('.container').getBoundingClientRect().width") <= 1400


# ───────────────────────────── addition 4: the way back ─────────────────────────────


def _lit(page):
    return {
        "tabs": [t.strip() for t in page.locator(".section-tabs .section-tab.active").all_inner_texts()],
        "top": [t.strip() for t in page.locator(".nav-links a.nav-link.active:not(.nav-fav)").all_inner_texts()],
    }


class TestDetailPagesKeepTheirParentsStrip:
    @pytest.mark.parametrize(
        "path,tab",
        [("/network/ipam/subnet/kea/1", "IPAM"), ("/network/discovery/results/1", "Discovery")],
    )
    def test_a_plugins_detail_page(self, page, base_url, clean_nav, path, tab):
        errors = _at(page, base_url, 1440)
        page.goto(f"{base_url}{path}")
        assert page.url.endswith(path), f"the detail page did not open: {page.url}"
        assert _lit(page) == {"tabs": [tab], "top": ["Network"]}
        expect(page.locator(".section-tabs .section-tab.active")).to_be_visible()
        assert not errors, errors

    def test_trace_is_under_investigate_and_its_link_goes_back(self, page, base_url, clean_nav):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/tools/trace")
        assert _lit(page) == {"tabs": ["Investigate"], "top": ["Network"]}
        back = page.locator("#main .container a.back-link")
        assert back.count() == 1
        expect(back).to_have_text("← Investigate a client")
        # the first thing in the content, above the title
        assert back.bounding_box()["y"] < page.locator(".page-header h1").bounding_box()["y"]
        back.click()
        page.wait_for_url(re.compile(r"/client$"))
        assert _lit(page)["tabs"] == ["Investigate"]

    def test_saved_searches_is_under_leases_and_its_link_goes_back(self, page, base_url, clean_nav):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/saved-searches")
        assert _lit(page) == {"tabs": ["Leases"], "top": ["Management"]}
        back = page.locator("#main .container a.back-link")
        expect(back).to_have_text("← Leases")
        back.click()
        page.wait_for_url(re.compile(r"/leases$"))

    def test_on_a_phone_the_bottom_bar_marks_leases_for_saved_searches(self, phone, base_url, clean_nav):
        phone.goto(f"{base_url}/saved-searches")
        expect(phone.locator("nav.tabbar a.active")).to_have_text("Leases")
        expect(phone.locator("a.back-link")).to_be_visible()
