"""
tests/e2e/test_mobile.py
────────────────────────
v5.51.0 (Q58) — the phone screenshot job.

Two jobs in one file:

1. Every GET page in PAGES is opened at 390 x 844 (device scale 2, a phone), checked
   for horizontal overflow and small tap targets, and saved as a full-page
   screenshot to artifacts/mobile/<page>.png. A desktop pass at 1440 x 900 saves
   artifacts/desktop/<page>.png. The `e2e` job uploads both directories on EVERY
   run (not only on failure) — the maintainer reviews them on the phone.
2. The foundation patterns in base.html (tab bar, More sheet, rowlist, filter
   sheet, action overflow, Select mode, chip rows) are driven against a small
   synthetic DOM, so they are tested before any page has been converted to use them.

These contexts open with bypass_csp=True: the suite tests LAYOUT here, and the
nonce-only CSP forbids the page.evaluate() the synthetic DOM needs. The journeys
in the other files keep the CSP on.
"""

import pathlib
import re

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
MOBILE_DIR = ROOT / "artifacts" / "mobile"
DESKTOP_DIR = ROOT / "artifacts" / "desktop"

PHONE = {"width": 390, "height": 844}
DESKTOP = {"width": 1440, "height": 900}
MIN_TAP = 44

# name -> path. Every nav destination, the Q41-Q49 tools, Getting started, each
# Settings page, a subnet edit form and the HA maintenance chooser.
PAGES = [
    ("dashboard", "/"),
    ("leases", "/leases"),
    ("reservations", "/reservations"),
    ("devices", "/devices"),
    ("reports", "/reports"),
    ("subnets", "/subnets"),
    ("servers", "/servers"),
    ("ddns", "/ddns"),
    ("health", "/health-center"),
    ("explain", "/tools/explain"),
    ("doctor", "/tools/doctor"),
    ("timeline", "/timeline"),
    ("trace", "/tools/trace"),
    ("reconcile", "/ddns/reconcile"),
    ("getting-started", "/getting-started"),
    ("about", "/about"),
    ("profile", "/profile"),
    ("saved-searches", "/saved-searches"),
    ("settings-home", "/settings"),
    ("settings-kea", "/settings/kea"),
    ("settings-databases", "/settings/databases"),
    ("settings-security", "/settings/security"),
    ("settings-alerts", "/settings/alerts"),
    ("settings-appearance", "/settings/appearance"),
    ("settings-system", "/settings/system"),
    ("settings-logs", "/settings/logs"),
    ("settings-users", "/settings/users"),
    ("settings-api-keys", "/settings/api-keys"),
    ("subnet-edit", "/subnets/edit/1"),
    ("ha-maintenance", "/servers/ha/maintenance"),
]

# Pages that still overflow a phone today, with the release that converts them.
# The list only shrinks: test_known_overflows_still_overflow fails when an entry
# stops overflowing so it gets removed. Empty means every page fits.
KNOWN_OVERFLOW = {}

# A phone browser widens the layout viewport to fit overflowing content, so window.innerWidth
# grows with it and "scrollWidth - innerWidth" reads 0 on a page that is 60px too wide (the
# About and Profile pages did exactly that). Measure against the device width instead.
OVERFLOW_JS = "(w) => Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - w"
WIDEST_JS = """(w) => [...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > w + 1
    && !e.closest('.table-wrap, .section-tabs, .chip-row, .card-toc, pre')).slice(0, 4)
    .map((e) => e.tagName.toLowerCase() + '.' + String(e.className).split(' ').slice(0, 2).join('.'))"""
SMALL_TAPS_JS = """(min) => {
    const out = [];
    const sel = '.tabbar a, .tabbar button, .btn';
    document.querySelectorAll(sel).forEach((el) => {
        // rows convert to the rowlist kebab in Q59/Q60; inline table buttons are not checked yet
        if (!el.closest('.tabbar') && el.closest('td, th')) return;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;      // display:none / inside a closed sheet
        const cs = getComputedStyle(el);
        if (cs.visibility === 'hidden') return;
        if (r.height < min - 0.5) out.push((el.textContent || el.className).trim().slice(0, 40) + ' = ' + Math.round(r.height));
    });
    return out;
}"""


@pytest.fixture(scope="module")
def phone_context(browser):
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True, bypass_csp=True)
    yield ctx
    ctx.close()


@pytest.fixture(scope="module")
def desktop_context(browser):
    ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
    yield ctx
    ctx.close()


@pytest.fixture(scope="module")
def phone(phone_context, base_url):
    page = phone_context.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    page.close()


@pytest.fixture(scope="module")
def desktop(desktop_context, base_url):
    page = desktop_context.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    page.close()


def _visit(page, base_url, path):
    resp = page.goto(f"{base_url}{path}", wait_until="load")
    page.wait_for_timeout(250)  # let deferred scripts and the first htmx swap settle
    return resp.status if resp else 0


class TestPhonePages:
    def test_every_page_fits_the_phone_and_is_screenshotted(self, phone, base_url):
        MOBILE_DIR.mkdir(parents=True, exist_ok=True)
        broken, overflow, small = [], {}, {}
        for name, path in PAGES:
            status = _visit(phone, base_url, path)
            if status >= 500:
                broken.append(f"{name} ({path}) -> HTTP {status}")
            over = phone.evaluate(OVERFLOW_JS, PHONE["width"])
            if over > 1 and name not in KNOWN_OVERFLOW:
                overflow[name] = f"{over} ({', '.join(phone.evaluate(WIDEST_JS, PHONE['width']))})"
            taps = phone.evaluate(SMALL_TAPS_JS, MIN_TAP)
            if taps:
                small[name] = taps
            phone.screenshot(path=str(MOBILE_DIR / f"{name}.png"), full_page=True)
        problems = []
        if broken:
            problems.append("server errors:\n  " + "\n  ".join(broken))
        if overflow:
            problems.append(
                "horizontal overflow (px past the viewport):\n  "
                + "\n  ".join(f"{k}: {v}" for k, v in overflow.items())
            )
        if small:
            problems.append(
                f"tap targets under {MIN_TAP}px:\n  "
                + "\n  ".join(f"{k}: {', '.join(v[:6])}" for k, v in small.items())
            )
        assert not problems, "\n".join(problems)

    def test_known_overflows_still_overflow(self, phone, base_url):
        for name, path in PAGES:
            if name in KNOWN_OVERFLOW:
                _visit(phone, base_url, path)
                assert phone.evaluate(OVERFLOW_JS, PHONE["width"]) > 1, (
                    f"{name} fits now: remove it from KNOWN_OVERFLOW"
                )

    def test_the_more_sheet_open_is_screenshotted(self, phone, base_url):
        _visit(phone, base_url, "/leases")
        phone.click('.tabbar button[data-sheet-open="more-sheet"]')
        expect(phone.locator("#more-sheet")).to_be_visible()
        phone.screenshot(path=str(MOBILE_DIR / "more-sheet.png"))
        phone.keyboard.press("Escape")
        expect(phone.locator("#more-sheet")).to_be_hidden()


class TestDesktopPass:
    def test_every_page_is_screenshotted_and_the_phone_chrome_is_absent(self, desktop, base_url):
        DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
        broken = []
        for name, path in PAGES:
            status = _visit(desktop, base_url, path)
            if status >= 500:
                broken.append(f"{name} -> HTTP {status}")
            desktop.screenshot(path=str(DESKTOP_DIR / f"{name}.png"), full_page=True)
        assert not broken, broken
        expect(desktop.locator(".tabbar")).to_be_hidden()
        expect(desktop.locator("#more-sheet")).to_be_hidden()
        expect(desktop.locator(".nav-links")).to_be_visible()


DEMO = """
<div id="q58-demo">
  <div class="filter-bar" id="demo-filters">
    <form method="GET" style="display:contents;">
      <select name="subnet" aria-label="Subnet"><option value="all">All Subnets</option><option value="1">Office</option></select>
      <select name="minutes" aria-label="Seen within"><option value="">All time</option><option value="5" selected>Last 5 min</option></select>
      <input type="text" name="search" placeholder="Search IP, hostname, MAC...">
      <button type="submit" class="btn btn-secondary">Filter</button>
    </form>
  </div>
  <div class="action-bar" id="demo-actions">
    <a class="btn btn-primary" href="#">Add</a>
    <a class="btn btn-secondary" href="#">Export</a>
    <a class="btn btn-secondary" href="#">Import</a>
  </div>
  <div class="chip-row" id="demo-chips">
    <a class="badge" href="#a">Alpha alpha alpha</a><a class="badge" href="#b">Beta beta beta</a>
    <a class="badge" href="#c">Gamma gamma gamma</a><a class="badge" href="#d">Delta delta delta</a>
    <a class="badge" href="#e">Epsilon epsilon</a><a class="badge" href="#f">Zeta zeta zeta zeta</a>
  </div>
  <div class="card" style="padding:0;"><table class="rowlist" id="demo-rows"><tbody>
    <tr><td><input type="checkbox" class="row-checkbox"></td>
        <td data-m="primary"><a href="/leases">host-one</a></td><td data-m="badge"><span class="badge">Apple</span></td>
        <td data-m="secondary">10.99.0.5</td><td data-m="secondary">Office</td><td data-m="secondary">—</td>
        <td data-m="secondary">3h</td><td data-m="hide">HIDDEN-CELL</td><td data-m="trailing"><span>&#8942;</span></td></tr>
    <tr><td><input type="checkbox" class="row-checkbox"></td>
        <td data-m="primary"><a href="/leases">host-two</a></td><td data-m="secondary"></td>
        <td data-m="secondary">10.99.0.6</td><td data-m="trailing"><span>&#8942;</span></td></tr>
  </tbody></table></div>
</div>
"""


@pytest.fixture
def demo(phone, base_url):
    _visit(phone, base_url, "/about")
    phone.evaluate(
        "(html) => { document.querySelector('.container').innerHTML = html; window.jenUi.enhance(document); }",
        DEMO,
    )
    return phone


class TestFoundationPatterns:
    def test_tabbar_five_controls_and_active_state(self, phone, base_url):
        _visit(phone, base_url, "/")
        bar = phone.locator(".tabbar")
        expect(bar).to_be_visible()
        expect(bar.locator("a, button")).to_have_count(5)
        expect(bar.locator("a.active")).to_have_text(re.compile("Dashboard"))
        box = bar.bounding_box()
        assert abs((box["y"] + box["height"]) - PHONE["height"]) < 2  # pinned to the bottom edge

    def test_top_bar_is_logo_dot_avatar_only(self, phone, base_url):
        _visit(phone, base_url, "/")
        expect(phone.locator(".nav .theme-toggle")).to_be_hidden()
        expect(phone.locator("#kb-hint-btn")).to_be_hidden()
        expect(phone.locator(".nav-links")).to_be_hidden()
        expect(phone.locator("#kea-indicator")).to_be_visible()
        expect(phone.locator(".nav-avatar")).to_be_visible()

    def test_more_sheet_lists_the_destinations_and_navigates(self, phone, base_url):
        _visit(phone, base_url, "/")
        phone.click('.tabbar button[data-sheet-open="more-sheet"]')
        sheet = phone.locator("#more-sheet")
        expect(sheet).to_be_visible()
        for label in ("Management", "Network", "Settings"):
            expect(sheet.locator(".sheet-group-label", has_text=label).first).to_be_visible()
        for label in ("Reservations", "Devices", "Subnets", "Health", "Timeline"):
            expect(sheet.get_by_role("link", name=re.compile(label)).first).to_be_visible()
        sheet.get_by_role("link", name=re.compile("Devices")).first.click()
        expect(phone).to_have_url(re.compile(r"/devices"))

    def test_content_is_never_hidden_behind_the_tabbar(self, phone, base_url):
        _visit(phone, base_url, "/about")
        pad = phone.evaluate("() => parseFloat(getComputedStyle(document.body).paddingBottom)")
        assert pad >= 56

    def test_rowlist_is_two_lines_and_drops_empty_cells(self, demo):
        row = demo.locator("#demo-rows tbody tr").first
        expect(demo.locator("#demo-rows thead")).to_have_count(0)
        expect(row.locator("td", has_text="HIDDEN-CELL")).to_be_hidden()
        assert row.bounding_box()["height"] <= 76
        primary = row.locator('td[data-m="primary"]').bounding_box()
        secondaries = row.locator('td[data-m="secondary"]:visible')
        # "—" is dropped: 10.99.0.5, Office, 3h remain, all on one line below the name
        assert secondaries.count() == 3
        ys = [secondaries.nth(i).bounding_box()["y"] for i in range(3)]
        assert max(ys) - min(ys) < 2 and min(ys) > primary["y"] + primary["height"] - 2
        # the second row's empty secondary cell is gone too
        expect(demo.locator("#demo-rows tbody tr").nth(1).locator('td[data-m="secondary"]:visible')).to_have_count(1)

    def test_tapping_a_row_opens_its_primary_link(self, demo):
        demo.locator("#demo-rows tbody tr").first.locator('td[data-m="secondary"]:visible').first.click()
        expect(demo).to_have_url(re.compile(r"/leases"))

    def test_filter_bar_collapses_to_search_plus_filters_and_opens_a_sheet(self, demo):
        bar = demo.locator("#demo-filters")
        toggle = bar.locator(".fs-filter-toggle")
        expect(toggle).to_be_visible()
        expect(toggle).to_contain_text("Filters (1)")  # the "Last 5 min" select is a non-default value
        expect(bar.locator('input[name="search"]')).to_be_visible()
        expect(bar.locator('select[name="subnet"]')).to_be_hidden()
        toggle.click()
        expect(bar).to_have_class(re.compile(r"\bopen\b"))
        expect(bar.locator('select[name="subnet"]')).to_be_visible()
        expect(bar.locator(".fs-label", has_text="Seen within")).to_be_visible()  # the select's aria-label, shown
        expect(bar.locator(".fs-head")).to_be_visible()
        bar.locator(".fs-head .btn").click()
        expect(bar.locator('select[name="subnet"]')).to_be_hidden()

    def test_action_bar_keeps_the_primary_and_folds_the_rest(self, demo):
        bar = demo.locator("#demo-actions")
        expect(bar.locator(".btn-primary")).to_be_visible()
        expect(bar.get_by_text("Export")).to_be_hidden()
        bar.locator(".fs-actions-toggle").click()
        expect(bar.get_by_text("Export")).to_be_visible()
        expect(bar.get_by_text("Import")).to_be_visible()
        demo.keyboard.press("Escape")
        expect(bar.get_by_text("Export")).to_be_hidden()

    def test_select_mode_reveals_the_checkboxes(self, demo):
        boxes = demo.locator("#demo-rows .row-checkbox")
        expect(boxes.first).to_be_hidden()
        toggle = demo.locator(".select-toggle")
        expect(toggle).to_be_visible()
        toggle.click()
        expect(demo.locator("body")).to_have_class(re.compile(r"select-mode"))
        expect(boxes.first).to_be_visible()
        assert boxes.first.bounding_box()["height"] >= 20
        toggle.click()
        expect(boxes.first).to_be_hidden()

    def test_chip_row_is_one_scrolling_line(self, demo):
        chips = demo.locator("#demo-chips")
        expect(chips).to_have_css("flex-wrap", "nowrap")
        expect(chips).to_have_css("overflow-x", "auto")
        assert demo.evaluate(
            "() => { const e = document.getElementById('demo-chips'); return e.scrollWidth > e.clientWidth; }"
        )


class TestDesktopIsUntouched:
    def test_the_phone_patterns_do_nothing_at_1440(self, desktop, base_url):
        _visit(desktop, base_url, "/about")
        desktop.evaluate(
            "(html) => { document.querySelector('.container').innerHTML = html; window.jenUi.enhance(document); }",
            DEMO,
        )
        expect(desktop.locator(".fs-filter-toggle")).to_be_hidden()
        expect(desktop.locator('#demo-filters select[name="subnet"]')).to_be_visible()
        expect(desktop.locator(".select-toggle")).to_be_hidden()
        expect(desktop.locator("#demo-actions .btn", has_text="Export")).to_be_visible()
        expect(desktop.locator("#demo-rows .row-checkbox").first).to_be_visible()
        expect(desktop.locator("#demo-chips")).to_have_css("flex-wrap", "wrap")


class TestListPagesOnThePhone:
    """v5.52.0 (Q59): the real Leases / Reservations / Devices pages use the vocabulary."""

    def test_leases_filters_collapse_into_a_labelled_sheet(self, phone, base_url):
        _visit(phone, base_url, "/leases")
        bar = phone.locator(".filter-bar").first
        expect(bar.locator(".fs-filter-toggle")).to_be_visible()
        expect(bar.locator('input[name="search"]')).to_be_visible()
        expect(bar.locator('select[name="subnet"]')).to_be_hidden()
        bar.locator(".fs-filter-toggle").click()
        for label in ("Subnet", "Time", "Rows per page", "Sort", "Order"):
            expect(bar.locator(".fs-label", has_text=label).first).to_be_visible()
        phone.screenshot(path=str(MOBILE_DIR / "leases-filter-sheet.png"))
        bar.locator(".fs-head .btn").click()
        expect(bar.locator('select[name="subnet"]')).to_be_hidden()

    def test_reservations_keep_add_and_fold_the_csv_actions(self, phone, base_url):
        _visit(phone, base_url, "/reservations")
        bar = phone.locator(".action-bar").first
        expect(bar.locator(".btn-primary")).to_contain_text("Add Reservation")
        expect(bar.get_by_text("Export CSV")).to_be_hidden()
        bar.locator(".fs-actions-toggle").click()
        expect(bar.get_by_text("Export CSV")).to_be_visible()
        expect(bar.get_by_text("Dry-run Import")).to_be_visible()
        phone.keyboard.press("Escape")

    def test_devices_type_chips_are_one_row_and_stale_days_is_in_the_sheet(self, phone, base_url):
        _visit(phone, base_url, "/devices")
        expect(phone.locator("#type-filter-bar")).to_have_css("flex-wrap", "nowrap")
        bar = phone.locator(".filter-bar").first
        bar.locator(".fs-filter-toggle").click()
        expect(bar.locator(".fs-label", has_text="Stale after (days)")).to_be_visible()
        expect(bar.locator('input[name="stale_days"]')).to_be_visible()

    def test_the_desktop_keeps_its_columns_and_hides_the_phone_controls(self, desktop, base_url):
        for path in ("/leases", "/reservations", "/devices"):
            _visit(desktop, base_url, path)
            expect(desktop.locator("table.rowlist thead").first).to_be_visible()
            expect(desktop.locator(".fs-filter-toggle")).to_be_hidden()
            expect(desktop.locator('select[name="sort"]')).to_be_hidden()


class TestGeneratedStylesheetLoads:
    def test_the_extracted_stylesheet_is_served_and_applied(self, phone, base_url):
        resp = phone.request.get(f"{base_url}/static/css/ui-classes.css")
        assert resp.status == 200 and ".u-" in resp.text()
        _visit(phone, base_url, "/ddns")
        expect(phone.locator("link[href*='ui-classes.css']")).to_have_count(1, timeout=5000)
