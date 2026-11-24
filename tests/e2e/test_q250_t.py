"""
tests/e2e/test_q250_t.py
────────────────────────
Q250, lane t - the top row and the section strip span the window on every page, measured in Chromium at 2560, 1920, 1440, 1024 and 390 px, with no and with five
favorites, in two themes: the logo is the bar's side padding from the left edge, the last account control the same from the right edge, the first section tab is
under the logo, those x values are the same on every page at one width, the content column is as it was (1,400 px; 1,800 px on Leases) and centered, nothing
scrolls sideways, nothing in the row is drawn under another at 1024 px and every favorite is shown at 2560 px.
"""

import json

import pymysql
import pymysql.cursors
import pytest

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

WIDTHS = [2560, 1920, 1440, 1024, 390]
PAGES = [("/leases", 1800), ("/users", 1400), ("/", 1400), ("/settings/kea", 1400)]
THEMES = ["dark", "light"]
FAVORITES = ["/reservations", "/devices", "/reports", "plugin:presence.index", "plugin:wol.index"]

MEASURE = """() => {
    const vis = e => { if (!e) return false; const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
    const nav = document.querySelector('nav.nav'), inner = nav.querySelector('.nav-inner'), ics = getComputedStyle(inner);
    const brand = nav.querySelector('.nav-brand').getBoundingClientRect();
    const last = ['.nav-search', '.nav-kb', '.nav-right'].map(s => nav.querySelector(s)).find(vis);
    const tab = [...document.querySelectorAll('.section-tabs .section-tab')].find(vis);
    const c = document.querySelector('.container'), cr = c.getBoundingClientRect();
    const bottom = nav.getBoundingClientRect().bottom;
    const drawn = e => vis(e) && e.getBoundingClientRect().top < bottom && !e.closest('.nav-dropdown-content');
    const items = [...nav.querySelectorAll('a, label, button, input:not([type=checkbox]):not([type=hidden])')].filter(drawn).map(e => {
        const r = e.getBoundingClientRect(), at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return {name: (e.getAttribute('aria-label') || e.getAttribute('title') || e.textContent.trim() || e.className).slice(0, 40),
                favorite: e.classList.contains('nav-fav'), own: !!at && (at === e || e.contains(at))};
    });
    return {window: document.documentElement.clientWidth,
            pad_left: parseFloat(ics.paddingLeft), pad_right: parseFloat(ics.paddingRight),
            brand_left: brand.left, last_right: last ? last.getBoundingClientRect().right : null,
            tab_left: tab ? tab.getBoundingClientRect().left + tab.closest('.section-tabs').scrollLeft : null,
            container_width: cr.width, container_left: cr.left, container_right: cr.right,
            nav_width: nav.getBoundingClientRect().width, fit: nav.getAttribute('data-fit'),
            sideways: document.documentElement.scrollWidth - document.documentElement.clientWidth,
            covered: items.filter(i => !i.own).map(i => i.name), favoritesDrawn: items.filter(i => i.favorite).length};
}"""


def _sql(statement, args=()):
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(statement, args)
            return cur.fetchall()
    finally:
        conn.close()


@pytest.fixture
def favorites(live_server):
    uid = _sql("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))[0]["id"]
    _sql("DELETE FROM user_nav")

    def put(items):
        _sql("DELETE FROM user_nav")
        if items:
            _sql("INSERT INTO user_nav (user_id, top_row, tabbar) VALUES (%s, %s, '[]')", (uid, json.dumps(items)))

    yield put
    _sql("DELETE FROM user_nav")


def _desk(browser, base_url, theme, width):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    ctx.add_init_script(f"try {{ localStorage.setItem('jen-theme-pick', {json.dumps(theme)}); }} catch (e) {{}}")
    page = ctx.new_page()
    page.script_errors = []
    page.on("pageerror", lambda e: page.script_errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    return ctx, page


def _measure(page, base_url, path):
    page.goto(f"{base_url}{path}")
    page.evaluate("() => document.fonts.ready.then(() => true)")
    return page.evaluate(MEASURE)


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("nfav", [0, 5])
@pytest.mark.parametrize("width", WIDTHS)
class TestTheTopRowSpansTheWindow:
    def test_the_bar_the_strip_and_the_content_are_where_they_should_be(
        self, browser, base_url, favorites, width, nfav, theme
    ):
        favorites(FAVORITES[:nfav])
        ctx, page = _desk(browser, base_url, theme, width)
        try:
            seen = {}
            for path, content_max in PAGES:
                m = _measure(page, base_url, path)
                seen[path] = m
                assert m["nav_width"] == m["window"], (path, m)
                # (a) the logo is the bar's own side padding from the window's left edge, (b) the last account control the same from the right edge
                assert abs(m["brand_left"] - m["pad_left"]) <= 1, (path, m)
                assert abs((m["window"] - m["last_right"]) - m["pad_right"]) <= 1, (path, m)
                # (c) the first section tab is under the logo (a strip scrolled to its lit tab on a phone is measured as if at its start)
                if m["tab_left"] is not None:
                    assert abs(m["tab_left"] - m["brand_left"]) <= 1, (path, m)
                else:
                    assert path == "/", (path, m)
                # (e) the content column is as it was, and centered
                assert m["container_width"] <= content_max, (path, m)
                assert abs(m["container_left"] - (m["window"] - m["container_right"])) <= 1, (path, m)
                # (f) nothing scrolls sideways
                assert m["sideways"] <= 0, (path, m)
            if width >= 1440:
                assert seen["/leases"]["pad_left"] == 20
            # (d) the same x on every page at one width
            for key in ("brand_left", "last_right"):
                values = {round(m[key], 1) for m in seen.values()}
                assert max(values) - min(values) <= 1, (key, {p: m[key] for p, m in seen.items()})
            tabs = {round(m["tab_left"], 1) for m in seen.values() if m["tab_left"] is not None}
            assert max(tabs) - min(tabs) <= 1, tabs
            assert page.script_errors == [], page.script_errors
        finally:
            ctx.close()

    def test_a_wide_window_shows_every_favorite_and_nothing_is_drawn_under_another(
        self, browser, base_url, favorites, width, nfav, theme
    ):
        favorites(FAVORITES[:nfav])
        ctx, page = _desk(browser, base_url, theme, width)
        try:
            for path, _ in PAGES[:2]:
                m = _measure(page, base_url, path)
                # (g) no item of the top row is drawn under another
                assert m["covered"] == [], (path, width, m["covered"])
                if width == 2560:
                    # (h) every favorite is shown, at the widest level
                    assert m["favoritesDrawn"] == nfav and m["fit"] == "0", (path, m)
        finally:
            ctx.close()
