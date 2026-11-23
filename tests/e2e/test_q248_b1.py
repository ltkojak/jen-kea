"""
tests/e2e/test_q248_b1.py
─────────────────────────
Q248, the rows of the look over v7.2.0-beta.5 that only a browser can measure (the rest are tests/test_q248_b1.py):

* V34 on a phone, a row of facts that wraps never starts a line with its separator dot, and the dot is still drawn between two facts on one line.
* V35 the Devices page's Filters button carries a count only when a filter is set.
* V39 no checkbox label on a settings page is drawn in upper case.
* V40 the daily summary time is drawn like the fields beside it.
* V43 search results on a phone: one closing line for the groups with no match, and a row's action is in view without scrolling sideways.
"""

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

PHONE = {"width": 390, "height": 844}
DESKTOP = {"width": 1440, "height": 900}

# a row list as the pages make it: one row whose facts cannot fit a phone line (its last fact wraps), one that fits
ROWS = """
<div class="card" id="q248-card"><div class="table-wrap"><table class="rowlist" id="q248-rows">
  <thead><tr><th>IP</th><th>Name</th><th>Subnet</th><th>Status</th><th>Note</th></tr></thead>
  <tbody>
    <tr><td data-m="secondary" class="mono">10.99.0.209</td><td data-m="primary">kids-tablet</td>
        <td data-m="secondary"><span class="badge badge-tone-blue">Production</span></td><td data-m="secondary">Inactive</td>
        <td data-m="secondary">Reception display by the front door</td></tr>
    <tr><td data-m="secondary" class="mono">10.99.0.5</td><td data-m="primary">printer</td>
        <td data-m="secondary">Office</td><td data-m="secondary"></td><td data-m="secondary"></td></tr>
  </tbody></table></div></div>
"""

# every visible fact of every row: does it start a line, has it a separator, and is that separator drawn where a person sees it
FACTS_JS = """() => {
    const out = [];
    document.querySelectorAll('#q248-rows tbody tr').forEach((tr, r) => {
        const cs = getComputedStyle(tr);
        const box = tr.getBoundingClientRect();
        const clipLeft = box.left + parseFloat(cs.borderLeftWidth);
        const contentLeft = clipLeft + parseFloat(cs.paddingLeft);
        const clips = cs.overflowX === 'hidden' || cs.overflowX === 'clip';
        let prevRight = null;
        tr.querySelectorAll('td').forEach((td) => {
            const m = td.getAttribute('data-m');
            if (getComputedStyle(td).display === 'none' || !(m === 'secondary' || m === null)) return;
            const b = td.getBoundingClientRect();
            const before = getComputedStyle(td, '::before');
            const hasDot = !!before.content && before.content !== 'none' && before.content !== 'normal';
            const lineStart = b.left <= contentLeft + 1;
            let dotVisible = false, dotInGap = null;
            if (hasDot) {
                if (before.position === 'absolute') {
                    const dotRight = b.right - parseFloat(before.right);
                    const dotLeft = dotRight - parseFloat(before.width);
                    dotVisible = !(clips && dotRight <= clipLeft + 0.5);
                    dotInGap = prevRight !== null && dotLeft >= prevRight - 0.5 && dotRight <= b.left + 0.5;
                } else {
                    dotVisible = true;      // in the flow: it is the first thing on the fact's own line
                }
            }
            out.push({row: r, text: td.textContent.trim().slice(0, 24), lineStart, hasDot, dotVisible, dotInGap, top: Math.round(b.top)});
            prevRight = b.right;
        });
    });
    return out;
}"""


@pytest.fixture(scope="module")
def phone(browser, base_url):
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True, bypass_csp=True)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


@pytest.fixture(scope="module")
def desktop(browser, base_url):
    ctx = browser.new_context(viewport=DESKTOP, bypass_csp=True)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


def _visit(page, base_url, path):
    page.goto(f"{base_url}{path}", wait_until="load")
    page.wait_for_timeout(250)  # deferred scripts and the first htmx swap


def _with_rows(page, base_url, path):
    _visit(page, base_url, path)
    page.evaluate(
        "(html) => { document.querySelector('.container').insertAdjacentHTML('beforeend', html); window.jenUi.enhance(document); }",
        ROWS,
    )
    page.locator("#q248-rows").scroll_into_view_if_needed()
    return page.evaluate(FACTS_JS)


class TestAWrappedRowDoesNotStartWithItsSeparator:
    @pytest.mark.parametrize("path", ["/", "/reservations", "/settings/logs", "/leases", "/devices"])
    def test_a_fact_that_starts_a_line_shows_no_dot(self, phone, base_url, path):
        facts = _with_rows(phone, base_url, path)
        first = [f for f in facts if f["row"] == 0]
        wrapped = [f for f in first if f["lineStart"] and f["hasDot"]]
        assert wrapped, f"the fixture row did not wrap at 390 px: {first}"
        assert not [f for f in wrapped if f["dotVisible"]], f"a line starts with the separator: {wrapped}"

    def test_the_dot_is_still_drawn_between_two_facts_on_one_line(self, phone, base_url):
        facts = _with_rows(phone, base_url, "/reservations")
        mid = [f for f in facts if f["hasDot"] and not f["lineStart"]]
        assert len(mid) >= 3, facts
        assert all(f["dotVisible"] and f["dotInGap"] for f in mid), mid
        # and the first fact of a row has none
        assert not facts[0]["hasDot"]

    def test_the_row_keeps_its_inset(self, phone, base_url):
        _with_rows(phone, base_url, "/reservations")
        inset = phone.evaluate(
            """() => { const tr = document.querySelector('#q248-rows tbody tr'); const td = tr.querySelector('td[data-m="primary"]');
                return Math.round(td.getBoundingClientRect().left - tr.getBoundingClientRect().left); }"""
        )
        assert inset == 12, inset

    def test_a_desktop_row_is_a_table_row(self, desktop, base_url):
        _visit(desktop, base_url, "/reservations")
        desktop.evaluate(
            "(html) => { document.querySelector('.container').insertAdjacentHTML('beforeend', html); window.jenUi.enhance(document); }",
            ROWS,
        )
        got = desktop.evaluate(
            """() => { const tr = document.querySelector('#q248-rows tbody tr'); const cs = getComputedStyle(tr);
                return [cs.display, cs.overflowX, cs.borderLeftWidth, getComputedStyle(tr.querySelector('td[data-m="secondary"]'), '::before').content]; }"""
        )
        assert got[0] == "table-row" and got[1] == "visible" and got[2] == "0px" and got[3] in ("none", "normal"), got


class TestTheFiltersCount:
    def test_devices_counts_no_filter_when_none_is_set(self, phone, base_url):
        _visit(phone, base_url, "/devices")
        label = phone.locator(".filter-bar .fs-count-label").first
        expect(label).to_have_text("Filters")
        # the setting is in view, under the search, and is not part of the sheet
        expect(phone.locator('.devices-stale input[name="stale_days"]')).to_be_visible()

    def test_a_filter_that_is_set_is_counted(self, phone, base_url):
        _visit(phone, base_url, "/devices?stale=1")
        expect(phone.locator(".filter-bar .fs-count-label").first).to_have_text("Filters (1)")

    def test_the_desktop_keeps_the_setting_on_the_filter_line(self, desktop, base_url):
        _visit(desktop, base_url, "/devices")
        tops = desktop.evaluate(
            """() => [document.querySelector('.devices-filter-row .filter-bar select[name="subnet"]'), document.querySelector('.devices-stale input[name="stale_days"]')]
                .map((el) => Math.round(el.getBoundingClientRect().top + el.getBoundingClientRect().height / 2))"""
        )
        assert abs(tops[0] - tops[1]) <= 6, tops


class TestSettingsControls:
    @pytest.mark.parametrize("path", ["/settings/kea", "/settings/security", "/settings/alerts", "/settings/system"])
    def test_no_checkbox_label_is_upper_case(self, desktop, base_url, path):
        _visit(desktop, base_url, path)
        shouting = desktop.evaluate(
            """() => [...document.querySelectorAll('label')].filter((l) => l.querySelector('input[type=checkbox]')
                && getComputedStyle(l).textTransform === 'uppercase').map((l) => l.textContent.trim().replace(/\\s+/g, ' ').slice(0, 60))"""
        )
        assert shouting == [], shouting

    def test_the_summary_time_is_drawn_like_its_neighbors(self, desktop, base_url):
        _visit(desktop, base_url, "/settings/alerts")
        got = desktop.evaluate(
            """() => { const pick = (el) => { const cs = getComputedStyle(el); return [cs.height, cs.borderTopWidth, cs.borderTopColor, cs.backgroundColor, cs.fontSize, cs.paddingLeft]; };
                return [pick(document.getElementById('f-summary_time')), pick(document.getElementById('f-pool_exhaustion_free')), document.getElementById('f-summary_time').type]; }"""
        )
        assert got[2] == "text" and got[0] == got[1], got

    def test_the_browser_refuses_a_time_that_is_not_hh_mm(self, desktop, base_url):
        _visit(desktop, base_url, "/settings/alerts")
        field = desktop.locator("#f-summary_time")
        field.fill("7am")
        assert desktop.evaluate("document.getElementById('f-summary_time').checkValidity()") is False
        field.fill("18:30")
        assert desktop.evaluate("document.getElementById('f-summary_time').checkValidity()") is True
        _visit(desktop, base_url, "/settings/alerts")  # leave the form as it was (nothing was submitted)


class TestSearchResultsOnAPhone:
    HOST = "q248-b1-search-host"

    @pytest.fixture
    def lease(self):
        from jen.models.db import kea_db

        with kea_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000C1')")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, state, expire, valid_lifetime, hostname) "
                "VALUES (INET_ATON('10.99.0.231'), UNHEX('AC24800000C1'), 1, 0, DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600, %s)",
                (self.HOST,),
            )
            db.commit()
        yield
        with kea_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000C1')")
            db.commit()

    def test_the_action_is_in_view_and_nothing_scrolls_sideways(self, phone, base_url, lease):
        _visit(phone, base_url, f"/search?q={self.HOST}")
        row = phone.locator("table.rowlist tbody tr", has_text=self.HOST).first
        expect(row).to_be_visible()
        view = row.locator('td[data-m="trailing"] a', has_text="View")
        expect(view).to_be_visible()
        box = view.bounding_box()
        assert box["x"] >= 0 and box["x"] + box["width"] <= PHONE["width"], box
        investigate = row.locator('td[data-m="trailing"] .phone-only a')
        expect(investigate).to_be_visible()
        ibox = investigate.bounding_box()
        assert ibox["x"] + ibox["width"] <= PHONE["width"], ibox
        expect(row.locator('td[data-m="trailing"] .desk-only a')).to_be_hidden()
        wrap = phone.evaluate(
            "() => { const w = document.querySelector('.table-wrap'); return [w.scrollWidth, w.clientWidth]; }"
        )
        assert wrap[0] <= wrap[1] + 1, wrap
        expect(phone.locator("table.rowlist thead").first).to_be_hidden()

    def test_groups_with_no_match_take_one_line_not_a_card_each(self, phone, base_url, lease):
        _visit(phone, base_url, f"/search?q={self.HOST}")
        empty_cards = phone.evaluate(
            "() => [...document.querySelectorAll('.card')].filter((c) => /^No .* results\\.$/.test((c.querySelector('p') || {textContent: ''}).textContent.trim())).length"
        )
        assert empty_cards == 0
        line = phone.locator("#search-no-match")
        if line.count():  # the plugins that answer a search are whatever this install has switched on
            expect(line).to_have_count(1)
            expect(line).to_contain_text("No matches in: ")

    def test_the_desktop_shows_the_word_and_the_columns(self, desktop, base_url, lease):
        _visit(desktop, base_url, f"/search?q={self.HOST}")
        row = desktop.locator("table.rowlist tbody tr", has_text=self.HOST).first
        expect(row.locator('td[data-m="trailing"] .desk-only a')).to_contain_text("Investigate")
        expect(row.locator('td[data-m="trailing"] .phone-only')).to_be_hidden()
        expect(desktop.locator("table.rowlist thead").first).to_be_visible()
