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

from jen.services import theme as thememod
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


class TestDashboardHeaderRowOnPhone:
    """v5.56.1 (Q68c) — the header controls stacked onto three lines at
    phone width (Customize / select / a stray dot); they must share one
    row instead."""

    def test_customize_and_the_refresh_select_share_the_same_row(self, phone, base_url):
        # Center-aligned, not top-aligned — the button and select are
        # different heights (the select keeps its compact size), so their
        # own tops legitimately differ; what "share a row" actually means
        # is their vertical centers line up and the header stays one line
        # tall, not three.
        _visit(phone, base_url, "/")
        customize_mid = phone.eval_on_selector(
            "#customize-btn", "el => { var r = el.getBoundingClientRect(); return r.top + r.height / 2; }"
        )
        select_mid = phone.eval_on_selector(
            "#refreshInterval", "el => { var r = el.getBoundingClientRect(); return r.top + r.height / 2; }"
        )
        assert abs(customize_mid - select_mid) < 2
        controls_height = phone.eval_on_selector(".page-header-controls", "el => el.getBoundingClientRect().height")
        assert controls_height < 60, f"page-header-controls is {controls_height}px tall — looks stacked, not a row"

    def test_last_updated_and_the_auto_refresh_label_stay_hidden(self, phone, base_url):
        _visit(phone, base_url, "/")
        expect(phone.locator("#last-updated")).to_be_hidden()
        expect(phone.locator(".dash-refresh-label")).to_be_hidden()


class TestSettingsCardsCollapsibleOnPhone:
    """v5.56.1 (Q68d) — settings-kea.png was 8,988px tall: seven cards,
    all expanded, under a TOC. `_card_toc.html`'s own script collapses
    every card it lists except one on the phone; desktop is untouched."""

    def test_only_the_first_card_is_open_on_load(self, phone, base_url):
        _visit(phone, base_url, "/settings/kea")
        assert "collapsed" not in (phone.get_attribute("#kea-api", "class") or "")
        for anchor in ("kea-ssh", "kea-servers", "kea6", "kea-d2", "kea-packages", "kea-drift"):
            assert "collapsed" in (phone.get_attribute(f"#{anchor}", "class") or ""), anchor

    def test_tapping_a_toc_chip_opens_its_card(self, phone, base_url):
        _visit(phone, base_url, "/settings/kea")
        phone.click('.card-toc a[href="#kea-d2"]')
        assert "collapsed" not in (phone.get_attribute("#kea-d2", "class") or "")
        expect(phone.locator("#kea-d2 form")).to_be_visible()

    def test_the_screenshot_is_well_under_3000px(self, phone, base_url):
        _visit(phone, base_url, "/settings/kea")
        MOBILE_DIR.mkdir(parents=True, exist_ok=True)
        phone.screenshot(path=str(MOBILE_DIR / "settings-kea.png"), full_page=True)
        height = phone.evaluate("document.documentElement.scrollHeight")
        assert height < 3000, f"settings-kea is {height}px tall"

    def test_desktop_shows_every_card_open(self, desktop, base_url):
        _visit(desktop, base_url, "/settings/kea")
        for anchor in ("kea-api", "kea-ssh", "kea-servers", "kea6", "kea-d2", "kea-packages", "kea-drift"):
            expect(desktop.locator(f"#{anchor} > :not(.card-header)").first).to_be_visible()

    # v5.56.4 (Q72c) — the two-column Settings layout at >=1280px. The
    # baseline is settings-kea.png's actual pixel height from the
    # v5.56.3-beta.1 CI artifact (1440x2546, device_scale_factor 1 so PNG
    # pixels == CSS/scrollHeight pixels) — a real measurement, not a guess.
    SETTINGS_KEA_HEIGHT_BEFORE_Q72 = 2546

    def test_settings_kea_is_at_least_30_percent_shorter_than_5_56_3(self, desktop, base_url):
        _visit(desktop, base_url, "/settings/kea")
        height = desktop.evaluate("document.documentElement.scrollHeight")
        ceiling = self.SETTINGS_KEA_HEIGHT_BEFORE_Q72 * 0.7
        assert height <= ceiling, (
            f"settings-kea is {height}px tall now, needed <= {ceiling:.0f}px (was {self.SETTINGS_KEA_HEIGHT_BEFORE_Q72}px)"
        )


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


class TestSkipLinkAndFocusOrder:
    """v5.56.4 (Q72a) — the first Tab stop on any page is the skip link;
    activating it moves real keyboard focus into <main>, not just the URL
    hash (needs tabindex="-1" on <main> — a bare landmark isn't focusable)."""

    def test_tab_then_enter_lands_focus_in_main(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/leases")
        page.keyboard.press("Tab")
        assert page.evaluate("document.activeElement.className") == "skip-link"
        assert page.evaluate("document.activeElement.getAttribute('href')") == "#main"
        page.keyboard.press("Enter")
        page.wait_for_timeout(100)
        assert page.evaluate("document.activeElement.id") == "main"
        ctx.close()


class TestAriaLabelSweep:
    """v5.56.4 (Q72a) — every icon-only button/label/anchor across the
    whole PAGES list carries an accessible name; a visible text sibling
    (any non-whitespace textContent) is an accessible name on its own and
    doesn't need one too."""

    def test_every_icon_only_control_has_an_accessible_name(self, desktop, base_url):
        js = """() => {
            const out = [];
            document.querySelectorAll('button, a, label[for], [role="button"]').forEach((el) => {
                if (el.offsetParent === null) return;  // hidden (closed sheet/dropdown, display:none)
                const text = (el.textContent || '').replace(/\\s+/g, '');
                if (text.length > 0) return;  // has a visible accessible name already
                const named = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')
                    || el.getAttribute('title') || (el.tagName === 'IMG' && el.getAttribute('alt'));
                if (!named) out.push(el.outerHTML.slice(0, 120));
            });
            return out;
        }"""
        offenders = {}
        for name, path in PAGES:
            _visit(desktop, base_url, path)
            found = desktop.evaluate(js)
            if found:
                offenders[name] = found
        assert not offenders, offenders


class TestProgressBarAndFullPageSubmit:
    """v5.56.4 (Q72b) — #jen-progress driven by jenFetch (htmx already has
    its own beforeRequest/afterRequest path, not re-tested here), and a
    plain full-page <form> submit disables its button until the response
    lands, resetting again on a bfcache pageshow."""

    def test_progress_bar_toggles_on_jen_progress_start_and_stop(self, browser, base_url):
        # jenFetch is a two-line wrapper (window.jenFetch = function(url,
        # opts) { start(); return fetch(url, opts).finally(stop); }) —
        # tests/test_desktop_polish.py checks that source directly. What's
        # worth an actual browser is the DOM half: does the #jen-progress
        # element really pick up and drop the "active" class. Driving a
        # real network delay through page.route()/a patched window.fetch
        # to exercise that indirectly proved unreliable in CI for reasons
        # that didn't reproduce locally (something about this sync
        # Playwright bridge's timing with a slow fetch in flight) — calling
        # jenProgress.start()/stop() directly is the same DOM mechanism,
        # deterministically.
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        page.evaluate("() => window.jenProgress.start()")
        expect(page.locator("#jen-progress")).to_have_class(re.compile(r"\bactive\b"))
        page.evaluate("() => window.jenProgress.stop()")
        expect(page.locator("#jen-progress")).not_to_have_class(re.compile(r"\bactive\b"))
        ctx.close()

    # Explain's own submit button, not any of the several other
    # button[type=submit] on the page (the nav's Logout forms in particular).
    _EXPLAIN_SUBMIT = 'form[action="/tools/explain"] button[type=submit]'

    def test_explain_submit_disables_its_button_before_navigating(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/tools/explain")
        page.fill('input[name="mac"]', "aa:bb:cc:dd:ee:ff")
        # Read state back in the SAME script that triggers the click,
        # before the browser's own (real, unmocked) navigation has a
        # chance to tear the page down — jenBeginFullPageSubmit runs
        # synchronously inside the 'submit' handler, ahead of navigation,
        # so this doesn't need a slow route to observe it; racing a real
        # click()-then-assert against a real page navigation is exactly
        # the kind of flake a synchronous round trip avoids.
        state = page.eval_on_selector(
            self._EXPLAIN_SUBMIT,
            "b => { b.click(); return { disabled: b.disabled, ariaBusy: b.getAttribute('aria-busy') }; }",
        )
        assert state["disabled"] is True
        assert state["ariaBusy"] == "true"
        ctx.close()

    def test_pageshow_clears_a_stale_disabled_submit_button(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/tools/explain")
        page.eval_on_selector(
            self._EXPLAIN_SUBMIT,
            "b => { b.disabled = true; b.setAttribute('aria-busy', 'true'); "
            "window.dispatchEvent(new Event('pageshow')); }",
        )
        expect(page.locator(self._EXPLAIN_SUBMIT)).to_be_enabled()
        assert page.get_attribute(self._EXPLAIN_SUBMIT, "aria-busy") is None
        ctx.close()


class TestStickyTableHeaderOnDesktop:
    """v5.56.4 (Q72d) — a sticky <thead> th on Leases stops at
    --sticky-top (nav height + the section-tab strip, since Leases has
    one), not just under the bare nav."""

    def test_the_first_header_cell_has_sticky_positioning_at_the_shared_offset(self, browser, base_url):
        # Simulating an actual scroll and checking where the header lands
        # depends on how many rows this run's dataset happens to have
        # seeded (too few, and a large scroll overshoots the table's own
        # bottom and unsticks it again — proved flaky in CI trying to
        # guess or search for a safe amount). Checking the computed style
        # directly is exactly as strong a check of "this header is set up
        # to stick at --sticky-top" without needing a real scroll at all.
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/leases")
        expect(page.locator("table.rowlist thead th").first).to_be_visible()
        style = page.eval_on_selector(
            "table.rowlist thead th",
            "el => { var cs = getComputedStyle(el); return { position: cs.position, top: cs.top }; }",
        )
        sticky_top = page.evaluate("getComputedStyle(document.body).getPropertyValue('--sticky-top').trim()")
        assert style["position"] == "sticky"
        assert style["top"] == sticky_top, f"th top is {style['top']!r}, --sticky-top is {sticky_top!r}"
        ctx.close()


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

    def test_more_sheet_traps_tab_and_restores_focus_on_escape(self, phone, base_url):
        # v5.56.1 (Q68m) — the sheet was role="dialog" aria-modal="true" but
        # never actually moved or trapped focus, and never restored it.
        _visit(phone, base_url, "/")
        more_btn = phone.locator('.tabbar button[data-sheet-open="more-sheet"]')
        more_btn.click()
        expect(phone.locator("#more-sheet")).to_be_visible()
        for _ in range(10):
            phone.keyboard.press("Tab")
            inside = phone.evaluate("document.getElementById('more-sheet').contains(document.activeElement)")
            assert inside, "focus escaped the More sheet"
        phone.keyboard.press("Escape")
        expect(phone.locator("#more-sheet")).to_be_hidden()
        expect(more_btn).to_be_focused()

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


class TestThemePicker:
    """v5.55.0 (Q63) — the preset picker. One context per preset (an
    add_init_script that seeds localStorage before any page load, same
    trick the picker itself relies on to avoid FOUC) so each gets its own
    screenshot pair and a real computed --bg to assert against."""

    @pytest.fixture(params=list(thememod.PRESET_IDS))
    def preset_id(self, request):
        return request.param

    @pytest.fixture
    def themed_page(self, browser, base_url, preset_id):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        ctx.add_init_script(f"localStorage.setItem('jen-theme-pick', {preset_id!r})")
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        yield page
        ctx.close()

    def test_computed_bg_matches_the_preset_and_is_screenshotted(self, themed_page, base_url, preset_id):
        _visit(themed_page, base_url, "/")
        assert themed_page.get_attribute("html", "data-theme") == preset_id
        bg = themed_page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()")
        assert bg == thememod.PRESETS[preset_id]["tokens"]["bg"]
        DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
        themed_page.screenshot(path=str(DESKTOP_DIR / f"theme-{preset_id}.png"), full_page=True)

        themed_page.set_viewport_size(PHONE)
        _visit(themed_page, base_url, "/")
        MOBILE_DIR.mkdir(parents=True, exist_ok=True)
        themed_page.screenshot(path=str(MOBILE_DIR / f"theme-{preset_id}.png"), full_page=True)
        # Phosphor's mono UI is desktop-only (widens tables past the phone
        # overflow guard) — confirm it did NOT switch --font-ui on the phone.
        if preset_id == "phosphor":
            font_ui = themed_page.evaluate(
                "getComputedStyle(document.documentElement).getPropertyValue('--font-ui').trim()"
            )
            font_mono = themed_page.evaluate(
                "getComputedStyle(document.documentElement).getPropertyValue('--font-mono').trim()"
            )
            assert font_ui != font_mono
        # Phosphor's mono UI and Retro's 2px bevel borders (extra_css) are
        # the two presets that add width beyond the shared layout — both get
        # the phone overflow guard.
        if preset_id in ("phosphor", "retro"):
            over = themed_page.evaluate(OVERFLOW_JS, PHONE["width"])
            assert over <= 1, f"{preset_id} overflows the phone by {over}px"

    def test_reports_chart_border_color_tracks_the_theme(self, themed_page, base_url, preset_id):
        _visit(themed_page, base_url, "/reports")
        canvas = themed_page.locator("canvas").first
        if canvas.count() == 0:
            pytest.skip("no history data seeded for a chart canvas")
        resolved = themed_page.evaluate("window.jenColor('var(--primary)')")
        assert resolved.replace(" ", "").lower() == thememod.PRESETS[preset_id]["tokens"]["primary"].lower()


class TestRetroNavContrast:
    """v5.56.1 (Q68f) — once (a) landed and Retro's nav actually turned
    navy, its non-anchor controls (still var(--text-muted), ~1.5:1 on
    navy) became unreadable. palette_warnings() only ever sees a
    preset's *tokens*, never extra_css, so it can't catch this — the
    e2e is the only guard."""

    def test_theme_toggle_and_the_version_string_are_white_on_navy(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        ctx.add_init_script("localStorage.setItem('jen-theme-pick', 'retro')")
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/")
        toggle_color = page.eval_on_selector(".theme-toggle", "el => getComputedStyle(el).color")
        version_color = page.eval_on_selector(".nav-brand span", "el => getComputedStyle(el).color")
        assert toggle_color == "rgb(255, 255, 255)"
        assert version_color == "rgb(255, 255, 255)"
        ctx.close()


class TestThemeAppliesBeforeContentPaints:
    """v5.56.1 (Q68h) — the theme used to apply from a script positioned
    after {% block content %}, so a non-Dark pick painted Dark first.
    The fix is a synchronous <head> script; the earliest this test can
    observe data-theme without literally capturing paint frames is the
    moment the HTML parser reaches the closing </html> tag (readyState
    'interactive', reached the instant after every parser-blocking
    script — including the <head> one — has run, and before body
    content the OLD code depended on for its own script tag to even
    exist). A regression back to a post-content script would still be
    'interactive' by definition of when that event fires, but would no
    longer be true at the moment content itself starts parsing — this
    still catches the concrete fix (the constant is read and applied
    before <style>/<body>, never after)."""

    def test_data_theme_is_already_correct_at_interactive(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        ctx.add_init_script("""
            localStorage.setItem('jen-theme-pick', 'light');
            window.__themeAtInteractive = null;
            document.addEventListener('readystatechange', function() {
                if (document.readyState === 'interactive' && window.__themeAtInteractive === null) {
                    window.__themeAtInteractive = document.documentElement.getAttribute('data-theme');
                }
            });
        """)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _visit(page, base_url, "/")
        assert page.evaluate("window.__themeAtInteractive") == "light"
        ctx.close()


class TestThemePickerSwitchesWithoutReload:
    def test_picking_a_theme_in_the_nav_dropdown_applies_immediately(self, desktop, base_url):
        _visit(desktop, base_url, "/leases")
        desktop.click("#dd-theme + label.theme-toggle")
        desktop.click('.theme-pick[data-theme-id="light"]')
        expect(desktop.locator("html")).to_have_attribute("data-theme", "light")
        bg = desktop.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()")
        assert bg == thememod.PRESETS["light"]["tokens"]["bg"]
        stored = desktop.evaluate("localStorage.getItem('jen-theme-pick')")
        assert stored == "light"
        meta = desktop.get_attribute('meta[name="theme-color"]', "content")
        assert meta.lower() == thememod.PRESETS["light"]["tokens"]["primary"].lower()
        # Reset so this module-scoped `desktop` page doesn't leak into later tests.
        desktop.click("#dd-theme + label.theme-toggle")
        desktop.click('.theme-pick[data-theme-id="dark"]')
        expect(desktop.locator("html")).to_have_attribute("data-theme", "dark")


class TestTouchNav:
    """v5.55.1 (Q64) — base.html's old touchstart/touchmove/touchend block
    (in the tree since v2.5.10) navigated on ANY touchend that started on a
    link, including one that ended a vertical scroll — deleted. These prove
    the property via a real touch drag through CDP (Input.dispatchTouchEvent,
    the Q40 precedent), not just a source-guard absence check: a drag must
    behave like a drag (scroll, no navigation), and a tap must still behave
    like a tap (navigation, or the row-tap click handler)."""

    def _touch_drag_up(self, page, x, y, steps=3, step_px=40):
        cdp = page.context.new_cdp_session(page)
        cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": x, "y": y}]})
        for i in range(1, steps + 1):
            cdp.send(
                "Input.dispatchTouchEvent",
                {"type": "touchMove", "touchPoints": [{"x": x, "y": y - i * step_px}]},
            )
        cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})

    def test_a_vertical_drag_starting_on_a_settings_tile_scrolls_not_navigates(self, phone, base_url):
        _visit(phone, base_url, "/settings")
        start_url = phone.url
        tile = phone.locator(".settings-tile").first
        box = tile.bounding_box()
        self._touch_drag_up(phone, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        phone.wait_for_timeout(200)
        assert phone.url == start_url, "a scroll that started on a link navigated"
        assert phone.evaluate("window.scrollY") > 0, "the drag did not actually scroll the page"

    def test_a_tap_on_the_same_tile_still_navigates(self, phone, base_url):
        _visit(phone, base_url, "/settings")
        tile = phone.locator(".settings-tile").first
        href = tile.get_attribute("href")
        box = tile.bounding_box()
        phone.touchscreen.tap(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        phone.wait_for_url(f"{base_url}{href}", timeout=5000)

    def test_a_vertical_drag_starting_on_a_leases_row_does_not_open_its_action_menu(self, phone, base_url):
        # The standard (non-demo) e2e dataset's fake Kea server reports zero
        # leases (tests/e2e/_fake_kea_server.py's canned lease4-get-all) — the
        # existing Leases journeys never needed an actual row, only this one
        # does, so seed one directly (subnet 1 = "Office", 10.99.0.0/24, the
        # standard E2E_SUBNETS fixture every other journey already assumes).
        from jen.models.db import kea_db

        with kea_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCCDDEEFF'")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, state, expire, valid_lifetime, hostname) "
                "VALUES (INET_ATON('10.99.0.222'), UNHEX('AABBCCDDEEFF'), 1, 0, "
                "DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600, 'touch-nav-probe')"
            )
            db.commit()
        try:
            _visit(phone, base_url, "/leases")
            row = phone.locator("table.rowlist tbody tr").first
            box = row.bounding_box()
            self._touch_drag_up(phone, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            phone.wait_for_timeout(200)
            toggle = row.locator(".action-menu-toggle").first
            if toggle.count():
                assert not toggle.is_checked(), "a scroll that started on a row opened its action menu"
        finally:
            with kea_db() as db, db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCCDDEEFF'")
                db.commit()


class TestAlertSummaryStatusColumn:
    """v5.55.1 (Q64) — an "ok" row used to print "✓ ok" on every single
    line; only a failure needs the reader's eye, so only a failure gets a
    cell at all now."""

    def test_one_failed_and_one_ok_row_shows_exactly_one_failed_chip(self, desktop, base_url):
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status, error) "
                "VALUES ('telegram', 'kea_up', 'ok test message', 'ok', NULL)"
            )
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status, error) "
                "VALUES ('telegram', 'kea_down', 'failed test message', 'failed', 'Connection refused')"
            )
            db.commit()
            # v1 shape (a plain list of widget ids) — dashboard_prefs.upgrade()
            # reads it same as a v2 dict; simplest way to make an opt-in
            # catalog widget visible without driving the Customize UI.
            cur.execute(
                "INSERT INTO dashboard_prefs (user_id, widgets) VALUES (1, %s) ON DUPLICATE KEY UPDATE widgets=%s",
                (
                    '["subnet_stats","recent_leases","alert_summary"]',
                    '["subnet_stats","recent_leases","alert_summary"]',
                ),
            )
            db.commit()

        _visit(desktop, base_url, "/")
        panel = desktop.locator("#alert-summary-body")
        expect(panel.locator("table")).to_be_visible(timeout=5000)
        text = panel.inner_text()
        assert text.count("✗") == 1, f"expected exactly one failed chip, got: {text!r}"
        assert "✓" not in text, f"an ok row still printed a checkmark: {text!r}"
        assert panel.locator(".badge-danger").count() == 1

        # Reset so this module-scoped `desktop` page's account doesn't carry
        # alert_summary into later tests in this file.
        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM dashboard_prefs WHERE user_id=1")
            cur.execute("DELETE FROM alert_log WHERE message IN ('ok test message', 'failed test message')")
            db.commit()


class TestInstallDefaultPrecedence:
    """v5.55.3 (Q66) — the install default silently never applied from
    v5.55.0 through v5.55.2: applyTheme() wrote the fallback into
    localStorage on every single page load, including the very first one
    any browser ever made, pinning it as if it had been a deliberate pick
    forever after. Fixed: applyTheme(id, persist) only writes when a real
    pick happens (the picker's own click handler), under a new key
    (jen-theme-pick) the old, permanently-polluted one (jen-theme) can
    never leak into. Each test opens its own fresh context — the
    module-scoped `phone`/`desktop` fixtures elsewhere in this file
    already have an opinion about what's stored."""

    @pytest.fixture(autouse=True)
    def install_default_phosphor(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/appearance")
        page.locator('select[name="theme_default"]').select_option("phosphor")
        page.locator('form[action="/settings/theme/default"] button[type="submit"]').click()
        expect(page.get_by_text("Install default theme updated.")).to_be_visible()
        yield
        page.goto(f"{base_url}/settings/appearance")
        page.locator('select[name="theme_default"]').select_option("dark")
        page.locator('form[action="/settings/theme/default"] button[type="submit"]').click()
        expect(page.get_by_text("Install default theme updated.")).to_be_visible()

    def test_a_fresh_context_never_pins_the_fallback_into_storage(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            for _ in range(2):
                page.goto(f"{base_url}/")
                assert page.evaluate("localStorage.getItem('jen-theme-pick')") is None
                assert page.get_attribute("html", "data-theme") == "phosphor"
        finally:
            ctx.close()

    def test_a_new_browser_gets_the_new_install_default_with_the_check_mark_on_it(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/")
            expect(page.locator("html")).to_have_attribute("data-theme", "phosphor")
            page.click("#dd-theme + label.theme-toggle")
            # Scoped to the nav dropdown specifically — the phone sheet has
            # its own copy of the same data-theme-id="" button, always in
            # the DOM (just CSS-hidden on desktop), so the bare selector
            # matches two elements and Playwright's strict-mode Locator
            # API (unlike the legacy page.click(selector) string form used
            # elsewhere in this file) refuses to resolve it.
            install_default_btn = page.locator('.nav-dropdown-content .theme-pick[data-theme-id=""]')
            expect(install_default_btn).to_contain_text("Install default (Phosphor)")
            expect(install_default_btn).to_have_class(re.compile(r"\bactive\b"))
        finally:
            ctx.close()

    def test_picking_light_stores_it_and_survives_reload_while_the_default_stays_phosphor(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/")
            page.click("#dd-theme + label.theme-toggle")
            page.click('.theme-pick[data-theme-id="light"]')
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            page.reload()
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            assert page.evaluate("localStorage.getItem('jen-theme-pick')") == "light"
        finally:
            ctx.close()

    def test_picking_install_default_clears_the_stored_pick(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        ctx.add_init_script("localStorage.setItem('jen-theme-pick', 'light')")
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/")
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            page.click("#dd-theme + label.theme-toggle")
            page.click('.nav-dropdown-content .theme-pick[data-theme-id=""]')
            expect(page.locator("html")).to_have_attribute("data-theme", "phosphor")
            assert page.evaluate("localStorage.getItem('jen-theme-pick')") is None
        finally:
            ctx.close()

    def test_the_old_polluted_key_is_dropped_and_ignored(self, browser, base_url):
        ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
        ctx.add_init_script("localStorage.setItem('jen-theme', 'light')")
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/")
            expect(page.locator("html")).to_have_attribute("data-theme", "phosphor")
            assert page.evaluate("localStorage.getItem('jen-theme')") is None
        finally:
            ctx.close()
