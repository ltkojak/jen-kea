"""
tests/e2e/test_q248_c2.py
─────────────────────────
Q248, stage c2, in a real browser: what tests/test_q248_c2.py cannot hold from a rendered page.

* V44  Subnets: a row opens in place with a click anywhere on its head and with Enter and Space on its button, the chevron turns, Expand All opens every
       row, the open rows (and Expand All) survive a reload, an id that no longer exists is ignored, the badge's color picker does not open the row,
       the name is the row's largest text, and a 390 px phone is not scrolled sideways.
* V38  the in-page tabs take a person to a page of the group and are still there on it (API Docs, the migration wizard); a phone's tabs are 40 px tall;
       the jump line is one line of links that lead to their cards.
* V42  the Plugin Manager is not wider than a 375 px screen and prints every description whole.
* V53  Reports: each chart's y-axis ends under twice the largest value it draws; a pool far above the lines is a figure in the card's text and a pool
       inside the range is a dashed line; Scale to Pool runs the axis up to the pool and survives a reload; a legend entry is drawn as its line; at
       390 px the range control has a row to itself and no two x-axis labels touch.
"""

import json

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e import conftest as e2e
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
SMALL_PHONE = {"width": 375, "height": 812}

# A phone browser widens the layout viewport to fit overflowing content, so the page is measured against the device's width (tests/e2e/test_mobile.py).
OVERFLOW_JS = "(w) => Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - w"


def _ids():
    return sorted(e2e._current_subnets())


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


@pytest.fixture
def desktop(browser, base_url):
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


@pytest.fixture
def phone(browser, base_url):
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


# ── V44: Subnets ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def _subnets(page, base_url, stored=None):
    """Open Subnets with `jen-subnets-open` set to `stored` (None: nothing stored), as a browser that kept it would."""
    page.goto(f"{base_url}/subnets")
    if stored is None:
        page.evaluate("() => localStorage.removeItem('jen-subnets-open')")
    else:
        page.evaluate("(v) => localStorage.setItem('jen-subnets-open', v)", stored)
    page.goto(f"{base_url}/subnets")
    expect(page.locator(".subnet-row").first).to_be_visible()


def _open_ids(page):
    return page.evaluate(
        "() => [...document.querySelectorAll('.subnet-row')].filter(r => !r.querySelector('.subnet-detail').hidden).map(r => Number(r.dataset.subnetId))"
    )


class TestSubnetsIsAList:
    def test_one_row_per_subnet_all_closed_on_a_first_visit(self, desktop, base_url):
        _subnets(desktop, base_url)
        assert desktop.locator(".subnet-row").count() == len(_ids())
        assert _open_ids(desktop) == []
        expect(desktop.locator("#subnets-expand-all")).to_have_text("Expand All")

    def test_a_row_opens_with_a_click_on_its_head_and_closes_with_the_next(self, desktop, base_url):
        _subnets(desktop, base_url)
        sid = _ids()[0]
        row = desktop.locator(f"#subnet-{sid}")
        toggle, detail = row.locator(".subnet-toggle"), row.locator(f"#subnet-detail-{sid}")
        closed_chevron = toggle.locator(".ico").evaluate("(e) => getComputedStyle(e).transform")
        row.locator(".subnet-cidr").click()  # the head, not the button
        expect(detail).to_be_visible()
        expect(toggle).to_have_attribute("aria-expanded", "true")
        desktop.wait_for_timeout(250)  # the chevron's turn is a 150 ms transition
        assert toggle.locator(".ico").evaluate("(e) => getComputedStyle(e).transform") != closed_chevron, (
            "the chevron turns"
        )
        expect(detail).to_contain_text("Lease Duration")
        expect(detail).to_contain_text("Notes")
        toggle.click()
        expect(detail).to_be_hidden()
        expect(toggle).to_have_attribute("aria-expanded", "false")

    def test_enter_and_space_work_on_the_rows_button(self, desktop, base_url):
        _subnets(desktop, base_url)
        sid = _ids()[0]
        toggle, detail = desktop.locator(f"#subnet-{sid} .subnet-toggle"), desktop.locator(f"#subnet-detail-{sid}")
        toggle.focus()
        desktop.keyboard.press("Enter")
        expect(detail).to_be_visible()
        desktop.keyboard.press("Space")
        expect(detail).to_be_hidden()
        desktop.keyboard.press("Space")
        expect(detail).to_be_visible()

    def test_more_than_one_row_may_be_open(self, desktop, base_url):
        _subnets(desktop, base_url)
        for sid in _ids()[:2]:
            desktop.locator(f"#subnet-{sid} .subnet-toggle").click()
        assert _open_ids(desktop) == _ids()[:2]

    def test_expand_all_opens_every_row_and_is_remembered(self, desktop, base_url):
        _subnets(desktop, base_url)
        button = desktop.locator("#subnets-expand-all")
        button.click()
        assert _open_ids(desktop) == _ids()
        expect(button).to_have_text("Collapse All")
        assert desktop.evaluate("() => localStorage.getItem('jen-subnets-open')") == "all"
        desktop.reload()
        assert _open_ids(desktop) == _ids(), "Expand All survives a reload"
        expect(desktop.locator("#subnets-expand-all")).to_have_text("Collapse All")
        desktop.locator("#subnets-expand-all").click()
        assert _open_ids(desktop) == []
        assert desktop.evaluate("() => localStorage.getItem('jen-subnets-open')") == "[]"
        desktop.reload()
        assert _open_ids(desktop) == []

    def test_the_open_rows_survive_a_reload(self, desktop, base_url):
        _subnets(desktop, base_url)
        sid = _ids()[-1]
        desktop.locator(f"#subnet-{sid} .subnet-toggle").click()
        assert json.loads(desktop.evaluate("() => localStorage.getItem('jen-subnets-open')")) == [sid]
        desktop.reload()
        assert _open_ids(desktop) == [sid]
        expect(desktop.locator(f"#subnet-{sid} .subnet-toggle")).to_have_attribute("aria-expanded", "true")

    def test_an_id_that_no_longer_exists_is_ignored_and_a_broken_value_opens_nothing(self, desktop, base_url):
        errors = []
        desktop.on("pageerror", lambda e: errors.append(str(e)))
        sid = _ids()[0]
        _subnets(desktop, base_url, stored=json.dumps([987654, sid]))
        assert _open_ids(desktop) == [sid]
        _subnets(desktop, base_url, stored="{not json")
        assert _open_ids(desktop) == []
        _subnets(desktop, base_url, stored='"a string"')
        assert _open_ids(desktop) == []
        assert errors == []

    def test_the_badges_color_picker_does_not_open_the_row(self, desktop, base_url):
        _subnets(desktop, base_url)
        sid = _ids()[0]
        desktop.locator(f'.tone-btn[data-subnet-id="{sid}"]').click()
        expect(desktop.locator(f"#subnet-{sid} .tone-menu")).to_be_visible()
        assert _open_ids(desktop) == []
        desktop.keyboard.press("Escape")

    def test_the_name_is_the_largest_text_of_a_row(self, desktop, base_url):
        _subnets(desktop, base_url, stored="all")
        sizes = desktop.evaluate(
            """() => [...document.querySelectorAll('.subnet-row')].map(row => {
                const px = el => parseFloat(getComputedStyle(el).fontSize);
                const texts = [...row.querySelectorAll('*')].filter(el => el.offsetParent !== null
                    && [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()));
                return {name: px(row.querySelector('.subnet-name')), usage: px(row.querySelector('.subnet-usage-figures')),
                        largest: Math.max(...texts.filter(el => !el.classList.contains('subnet-name')).map(px))};
            })"""
        )
        assert sizes
        for s in sizes:
            assert s["name"] > s["usage"], s
            assert s["name"] > s["largest"], f"the name ({s['name']} px) is not the largest text of its open row: {s}"

    def test_a_phone_gets_a_short_card_that_opens_the_same_way(self, phone, base_url):
        _subnets(phone, base_url)
        assert phone.evaluate(OVERFLOW_JS, PHONE["width"]) <= 1, "the page is wider than the screen"
        sid = _ids()[0]
        row = phone.locator(f"#subnet-{sid}")
        expect(row.locator(".subnet-name")).to_be_visible()
        expect(row.locator(".subnet-cidr")).to_be_visible()
        expect(row.locator(".subnet-usage")).to_be_visible()
        assert row.locator(".subnet-cell-desk").count() == 3
        for i in range(3):
            expect(row.locator(".subnet-cell-desk").nth(i)).to_be_hidden()
        head = row.locator(".subnet-row-head").bounding_box()
        assert head["height"] < 170, f"a closed row is {head['height']} px tall on a phone"
        name = row.locator(".subnet-name").evaluate("(e) => parseFloat(getComputedStyle(e).fontSize)")
        usage = row.locator(".subnet-usage-figures").evaluate("(e) => parseFloat(getComputedStyle(e).fontSize)")
        assert name > usage
        assert row.locator(".subnet-toggle").bounding_box()["height"] >= 40
        row.locator(".subnet-toggle").click()
        expect(phone.locator(f"#subnet-detail-{sid}")).to_be_visible()
        assert phone.evaluate(OVERFLOW_JS, PHONE["width"]) <= 1, "the page is wider than the screen with a row open"
        phone.reload()
        assert _open_ids(phone) == [sid]
        phone.evaluate("() => localStorage.removeItem('jen-subnets-open')")

    def test_the_whole_list_is_a_fraction_of_the_page_the_cards_made(self, desktop, base_url):
        """Four subnets took 2,486 px of cards; a closed list of them is a few rows."""
        _subnets(desktop, base_url)
        box = desktop.evaluate(
            "() => { const r = [...document.querySelectorAll('.subnet-row')]; "
            "return r[r.length - 1].getBoundingClientRect().bottom - r[0].getBoundingClientRect().top; }"
        )
        assert box < 90 * len(_ids()), f"{len(_ids())} closed rows take {box} px"


# ── V38: the in-page tabs and the jump line ──────────────────────────────────────────────────────────────────────────────────────────


class TestTheInPageTabs:
    def test_a_tab_leads_to_its_page_and_the_tabs_are_still_there(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/security")
        tabs = desktop.locator("nav.page-tabs")
        expect(tabs.locator('.page-tab[aria-current="page"]')).to_have_text("Policies")
        tabs.get_by_role("link", name="API Docs").click()
        desktop.wait_for_url("**/settings/api-docs")
        tabs = desktop.locator("nav.page-tabs")
        expect(tabs.locator('.page-tab[aria-current="page"]')).to_have_text("API Docs")
        tabs.get_by_role("link", name="Policies").click()
        desktop.wait_for_url("**/settings/security")

    def test_the_migration_wizard_has_a_way_back(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/databases/migrate")
        tabs = desktop.locator("nav.page-tabs")
        expect(tabs.locator('.page-tab[aria-current="page"]')).to_have_text("Migrate")
        tabs.get_by_role("link", name="Connections").click()
        desktop.wait_for_url("**/settings/databases?tab=connections")
        expect(desktop.locator('nav.page-tabs .page-tab[aria-current="page"]')).to_have_text("Connections")

    def test_the_current_tab_is_told_from_the_rest_by_more_than_its_color(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/security")
        look = desktop.evaluate(
            """() => { const s = el => { const c = getComputedStyle(el); return {weight: c.fontWeight, shadow: c.boxShadow, bottom: c.borderBottomColor}; };
                return {on: s(document.querySelector('.page-tab[aria-current="page"]')), off: s(document.querySelector('.page-tab:not(.active)'))}; }"""
        )
        assert int(look["on"]["weight"]) > int(look["off"]["weight"])
        assert look["on"]["shadow"] != "none" and look["off"]["shadow"] == "none", (
            "the current tab carries the accent line"
        )

    @pytest.mark.parametrize("path", ["/settings/security", "/settings/databases", "/ddns"])
    def test_a_phones_tabs_are_40_px_tall_and_stay_on_the_screen(self, phone, base_url, path):
        phone.goto(f"{base_url}{path}")
        boxes = phone.evaluate(
            "() => [...document.querySelectorAll('.page-tab')].map(e => e.getBoundingClientRect().height)"
        )
        assert boxes and min(boxes) >= 40, boxes
        assert phone.evaluate(OVERFLOW_JS, PHONE["width"]) <= 1, "the tab row makes the page wider than the screen"
        rows = phone.evaluate(
            "() => new Set([...document.querySelectorAll('.page-tab')].map(e => Math.round(e.getBoundingClientRect().top))).size"
        )
        assert rows == 1, "a phone's tabs are one row that scrolls"

    def test_the_jump_line_is_one_line_of_links_that_lead_to_their_cards(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/kea")
        jump = desktop.locator("nav.page-jump")
        expect(jump).to_be_visible()
        expect(jump.locator(".page-jump-label")).to_have_text("On this page:")
        look = jump.locator("a").first.evaluate(
            "(e) => { const c = getComputedStyle(e); return [c.borderTopWidth, c.backgroundColor, c.borderRadius]; }"
        )
        assert look == ["0px", "rgba(0, 0, 0, 0)", "0px"], "a text link, not a pill"
        tops = jump.evaluate(
            "(n) => new Set([...n.querySelectorAll('a')].map(a => Math.round(a.getBoundingClientRect().top))).size"
        )
        assert tops == 1, "one line at 1440 px"
        jump.get_by_role("link", name="SSH to the Kea server").click()
        assert desktop.evaluate("() => location.hash") == "#kea-ssh"
        desktop.wait_for_timeout(300)
        top = desktop.locator("#kea-ssh").evaluate("(e) => e.getBoundingClientRect().top")
        assert 0 <= top < DESKTOP["height"], f"the card is at {top} px after its link"

    def test_the_jump_line_is_under_the_tabs(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/security")
        tabs = desktop.locator("nav.page-tabs").bounding_box()
        jump = desktop.locator("nav.page-jump").bounding_box()
        assert jump["y"] >= tabs["y"] + tabs["height"] - 1


# ── V42: the Plugin Manager ──────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestThePluginManager:
    def test_it_is_not_wider_than_a_375_px_screen(self, browser, base_url):
        ctx = browser.new_context(viewport=SMALL_PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/settings/plugins")
            expect(page.locator(".plugin-table")).to_be_visible()
            over = page.evaluate(OVERFLOW_JS, SMALL_PHONE["width"])
            assert over <= 1, f"the Plugin Manager is {over} px wider than a 375 px screen"
        finally:
            ctx.close()

    def test_every_description_is_whole_and_wrapped(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/plugins")
        rows = desktop.evaluate(
            """() => [...document.querySelectorAll('.plugin-table .plugin-desc')].map(e => ({text: e.textContent.trim(),
                cut: e.scrollWidth > e.clientWidth + 1, lines: Math.round(e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight))}))"""
        )
        assert len(rows) >= 7, "every bundled plugin is installed in this suite"
        assert not [r for r in rows if r["cut"] or r["text"].endswith("…")], rows
        assert max(len(r["text"]) for r in rows) > 200 and max(r["lines"] for r in rows) > 1, "a long description wraps"

    def test_settings_system_names_each_plugin_once_and_links_to_the_manager(self, desktop, base_url):
        desktop.goto(f"{base_url}/settings/system")
        card = desktop.locator("#sys-plugins")
        assert card.locator("tbody tr").count() >= 7
        assert card.locator("tbody td div").count() == 0, "a row is a name, a version and a status"
        card.get_by_role("link", name="Manage plugins").click()
        desktop.wait_for_url("**/settings/plugins")


# ── V53: Reports ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# Every chart of the page: its y-axis, the values it draws (the pool's own line apart), its legend against its lines, and its x-axis labels as drawn.
CHARTS_JS = """
() => Object.values(Chart.instances).map(c => {
  const x = c.scales.x, y = c.scales.y, ctx = c.ctx;
  const drawn = c.data.datasets.filter(d => d.label !== 'Pool Size');
  const values = drawn.flatMap(d => d.data).filter(v => typeof v === 'number');
  const pool = c.data.datasets.find(d => d.label === 'Pool Size');
  ctx.save();
  ctx.font = '10px ' + Chart.defaults.font.family;
  const ticks = x.ticks.map((t, i) => { const label = Array.isArray(t.label) ? t.label.join(' ') : String(t.label);
      return {label, x: x.getPixelForTick(i), w: ctx.measureText(label).width}; });
  ctx.restore();
  return {
    id: c.canvas.id, width: c.width, yMax: y.max, largest: Math.max(0, ...values),
    pool: pool ? {dash: pool.borderDash, max: Math.max(...pool.data.filter(v => typeof v === 'number'))} : null,
    legend: c.legend.legendItems.map(i => ({text: i.text, stroke: i.strokeStyle, dash: i.lineDash || [], point: i.pointStyle})),
    lines: c.data.datasets.map(d => ({text: d.label, stroke: d.borderColor, dash: d.borderDash || []})),
    usePointStyle: c.options.plugins.legend.labels.usePointStyle,
    ticks,
  };
})
"""


@pytest.fixture
def history(live_server):
    """Four days of half-hourly snapshots of the first two subnets: the first has a pool of 121 with about twenty addresses in use (its line is far
    under its pool), the second a pool of 20 with twelve to seventeen in use (its pool is inside the axis its lines need)."""
    a, b = _ids()[:2]
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id IN (%s, %s)", (a, b))
            for n in range(192):
                for subnet_id, used, pool in ((a, 16 + (n * 7) % 7, 121), (b, 12 + (n * 5) % 6, 20)):
                    cur.execute(
                        "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, dynamic_leases, reserved_leases, pool_used, pool_size) "
                        "VALUES (%s, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s, %s, 3, %s, %s)",
                        (subnet_id, n * 30, used + 2, used, used, pool),
                    )
        yield a, b
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id IN (%s, %s)", (a, b))
        conn.close()


def _reports(page, base_url, scale=None):
    page.goto(f"{base_url}/reports")
    if scale is None:
        page.evaluate("() => localStorage.removeItem('jen-reports-scale')")
    else:
        page.evaluate("(v) => localStorage.setItem('jen-reports-scale', v)", scale)
    page.goto(f"{base_url}/reports")
    page.wait_for_function("() => window.Chart && Object.keys(Chart.instances).length >= 2")
    return {c["id"]: c for c in page.evaluate(CHARTS_JS)}


class TestReports:
    def test_each_axis_ends_under_twice_the_largest_value_drawn(self, desktop, base_url, history):
        charts = _reports(desktop, base_url)
        assert len(charts) >= 2
        for c in charts.values():
            assert c["largest"] > 0, c["id"]
            assert c["largest"] < c["yMax"] < 2 * c["largest"], (
                f"{c['id']}: the axis runs to {c['yMax']} for lines that reach {c['largest']}"
            )

    def test_a_pool_far_above_the_lines_is_a_figure_and_a_pool_inside_the_range_is_a_dashed_line(
        self, desktop, base_url, history
    ):
        a, b = history
        charts = _reports(desktop, base_url)
        assert charts[f"chart-{a}"]["pool"] is None
        expect(desktop.locator(f"#chart-pool-{a}")).to_be_visible()
        expect(desktop.locator(f"#chart-pool-{a}")).to_contain_text("Pool: 121 addresses")
        inside = charts[f"chart-{b}"]["pool"]
        assert inside and inside["dash"] == [4, 4] and inside["max"] == 20 <= charts[f"chart-{b}"]["yMax"]
        expect(desktop.locator(f"#chart-pool-{b}")).to_be_hidden()

    def test_scale_to_pool_runs_the_axis_to_the_pool_and_survives_a_reload(self, desktop, base_url, history):
        a, _b = history
        _reports(desktop, base_url)
        box = desktop.locator("#scale-pool")
        expect(box).not_to_be_checked()
        desktop.get_by_label("Scale to Pool").check()
        assert desktop.evaluate("() => localStorage.getItem('jen-reports-scale')") == "1"
        chart = {c["id"]: c for c in desktop.evaluate(CHARTS_JS)}[f"chart-{a}"]
        assert chart["pool"] and chart["yMax"] >= 121, "the axis runs up to the pool and the pool's line is drawn"
        expect(desktop.locator(f"#chart-pool-{a}")).to_be_hidden()
        desktop.reload()
        desktop.wait_for_function("() => window.Chart && Object.keys(Chart.instances).length >= 2")
        expect(desktop.locator("#scale-pool")).to_be_checked()
        chart = {c["id"]: c for c in desktop.evaluate(CHARTS_JS)}[f"chart-{a}"]
        assert chart["pool"] and chart["yMax"] >= 121
        desktop.get_by_label("Scale to Pool").uncheck()
        chart = {c["id"]: c for c in desktop.evaluate(CHARTS_JS)}[f"chart-{a}"]
        assert chart["pool"] is None and chart["yMax"] < 2 * chart["largest"]
        assert desktop.evaluate("() => localStorage.getItem('jen-reports-scale')") == "0"
        desktop.evaluate("() => localStorage.removeItem('jen-reports-scale')")

    def test_a_legend_entry_is_drawn_as_its_line(self, desktop, base_url, history):
        for c in _reports(desktop, base_url, scale="1").values():
            assert c["usePointStyle"] is True
            assert [(i["text"], i["stroke"], i["dash"]) for i in c["legend"]] == [
                (d["text"], d["stroke"], d["dash"]) for d in c["lines"]
            ]
            assert {i["point"] for i in c["legend"]} == {"line"}
            dashed = [i["text"] for i in c["legend"] if i["dash"]]
            assert "Pool Size" in dashed, "with Scale to Pool on, the pool's dashed line has a dashed legend entry"
        desktop.evaluate("() => localStorage.removeItem('jen-reports-scale')")

    def test_the_colors_are_the_themes(self, desktop, base_url, history):
        charts = _reports(desktop, base_url)
        primary = desktop.evaluate("() => jenColor('var(--primary)')")
        for c in charts.values():
            assert c["lines"][0]["text"] == "Pool used" and c["lines"][0]["stroke"] == primary

    def test_on_a_phone_the_range_has_its_own_row_and_no_two_labels_touch(self, phone, base_url, history):
        charts = _reports(phone, base_url)
        assert phone.evaluate(OVERFLOW_JS, PHONE["width"]) <= 1
        boxes = phone.evaluate(
            """() => { const b = sel => { const r = document.querySelector(sel).getBoundingClientRect(); return {top: r.top, bottom: r.bottom}; };
                return {title: b('.reports-head h1'), range: b('#days-select'), scale: b('.reports-scale')}; }"""
        )
        assert boxes["range"]["top"] >= boxes["title"]["bottom"], "the range control is on a row under the title"
        assert boxes["scale"]["top"] >= boxes["range"]["bottom"] - 1, (
            "the Scale to Pool choice is on the next row, not beside the range"
        )
        for c in charts.values():
            ticks = c["ticks"]
            assert 2 <= len(ticks) <= 5, f"{c['id']} draws {len(ticks)} x-axis labels on a phone"
            assert all(len(t["label"]) <= 6 for t in ticks), [t["label"] for t in ticks]
            for left, right in zip(ticks, ticks[1:], strict=False):
                gap = (right["x"] - right["w"] / 2) - (left["x"] + left["w"] / 2)
                assert gap >= 4, f"{c['id']}: '{left['label']}' and '{right['label']}' are {gap:.1f} px apart"
