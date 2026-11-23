"""
tests/e2e/test_q249_c.py
────────────────────────
Q249, lane C - the page rows of the executing pass on v7.2.0-beta.6, in a real browser with the CSP on, against the live server.

* BI1   Edit Subnet with a Kea config that sets no renew-timer and no rebind-timer (IPv6: no preferred-lifetime either): no script error, "Review changes"
        opens the confirm panel, and Apply posts the form. The Kea is the suite's stand-in Control Agent serving that config (its per-test override).
        The stand-in fleet has no server a change can be written to, so the real preview keeps Apply disabled: the panel is opened against the REAL preview
        first, and for the post alone the preview's answer is stood in by the browser (`page.route`), named where it is used.
* BI2   the top row at 1024 and 1100 px with zero, three and five favorites, with and without the Getting started pill: every item drawn in the row is
        the element at its own center, and the page does not scroll sideways.
* BI11  Devices' IPv6 view has no script error, Escape there throws nothing, and the IPv4 view's dialog still opens and closes.
* BI18  Reports: a pool just above the fitted axis is a dashed line inside it; a pool far above it is a figure in the card.
* C2    a field error moved under its field carries the error icon.
"""

import copy
import json

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e import conftest as e2e
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

V6_ID = 10
DEVICE_MAC = "aa:bb:cc:24:9c:01"


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


def _sql(statement, args=()):
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(statement, args)
            return cur.fetchall()
    finally:
        conn.close()


def _ids():
    return sorted(e2e._current_subnets())


@pytest.fixture
def desk(browser, base_url):
    """A 1440 px page signed in as the superadmin, with every script error collected in `page.script_errors`."""
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.script_errors = []
    page.on("pageerror", lambda e: page.script_errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


# ───────────────────────────── BI1: Edit Subnet with no timers in Kea's config ─────────────────────────────


@pytest.fixture
def kea_without_timers(fake_kea):
    """The stand-in Control Agent serves its own config with no `renew-timer` / `rebind-timer` anywhere (a valid Kea config: Kea derives T1 and T2), and a
    Dhcp6 section with one subnet that sets no timer and no lifetime. Put back after."""
    saved = fake_kea.responses["config-get"]
    answer = copy.deepcopy(saved)
    dhcp4 = answer["arguments"]["Dhcp4"]
    for key in ("renew-timer", "rebind-timer"):
        dhcp4.pop(key, None)
        for subnet in dhcp4.get("subnet4", []):
            subnet.pop(key, None)
    answer["arguments"]["Dhcp6"] = {
        "subnet6": [
            {"id": V6_ID, "subnet": "2001:db8:10::/64", "pools": [{"pool": "2001:db8:10::100-2001:db8:10::200"}]}
        ]
    }
    fake_kea.responses["config-get"] = answer
    yield
    fake_kea.responses["config-get"] = saved


@pytest.fixture
def ipv6_on(live_server):
    """IPv6 on in the live app, the way an operator turns it on: the `ipv6_enabled` setting and `[subnets6]` through the config's own writer. Put back after."""
    from jen import extensions
    from jen.config import app_config
    from jen.models.user import set_global_setting

    before = copy.deepcopy(extensions.SUBNET6_MAP)
    set_global_setting("ipv6_enabled", "true")
    app_config.write_subnets6({V6_ID: {"name": "V6Lab", "cidr": "2001:db8:10::/64"}})
    yield
    app_config.write_subnets6(before)
    set_global_setting("ipv6_enabled", "false")


def _review_and_apply(page, base_url, path, field, value):
    page.goto(f"{base_url}{path}")
    expect(page.locator("#f-renew")).to_have_value("")
    expect(page.locator("#f-rebind")).to_have_value("")
    assert page.script_errors == [], page.script_errors
    expect(page.locator("#confirm-panel")).to_be_hidden()

    # the real preview: the panel opens and says what is changing (no server of the stand-in fleet takes a change, so Apply stays disabled)
    page.fill(field, value)
    page.click("#show-confirm-btn")
    expect(page.locator("#confirm-panel")).to_be_visible()
    expect(page.locator("#change-summary")).to_contain_text(value)
    expect(page.locator("#validation-summary")).to_contain_text("no server takes this change")
    expect(page.locator("#apply-btn")).to_be_disabled()
    page.click("#confirm-cancel-btn")
    expect(page.locator("#confirm-panel")).to_be_hidden()

    # the post: the preview's answer is stood in here (a pass with nothing to validate against), so that Apply can be pressed; the save itself is the real route
    page.route(
        f"**{path}/preview",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"ok": True, "no_changes": False, "diff": [], "servers": [], "all_passed": True}),
        ),
    )
    page.click("#show-confirm-btn")
    expect(page.locator("#apply-btn")).to_be_enabled()
    with page.expect_request(lambda r: r.method == "POST" and r.url == f"{base_url}{path}") as posted:
        page.click("#apply-btn")
    page.wait_for_load_state("load")
    assert value in (posted.value.post_data or "")
    response = posted.value.response()
    assert response is not None and response.status < 500, response.status
    page.unroute(f"**{path}/preview")
    assert page.script_errors == [], page.script_errors


class TestEditSubnetWithNoTimers:
    def test_the_ipv4_page_reviews_and_posts(self, desk, base_url, kea_without_timers):
        _review_and_apply(desk, base_url, f"/subnets/edit/{_ids()[0]}", "#f-lifetime", "7200")

    def test_the_ipv6_page_reviews_and_posts(self, desk, base_url, kea_without_timers, ipv6_on):
        desk.goto(f"{base_url}/subnets/edit6/{V6_ID}")
        expect(desk.locator("#f-preferred")).to_have_value("")
        expect(desk.locator("#f-valid")).to_have_value("")
        _review_and_apply(desk, base_url, f"/subnets/edit6/{V6_ID}", "#f-valid", "7200")

    def test_a_config_with_its_timers_still_fills_the_fields(self, desk, base_url):
        desk.goto(f"{base_url}/subnets/edit/{_ids()[0]}")
        expect(desk.locator("#f-renew")).to_have_value("900")
        expect(desk.locator("#f-rebind")).to_have_value("1800")
        desk.fill("#f-renew", "901")
        desk.click("#show-confirm-btn")
        expect(desk.locator("#confirm-panel")).to_be_visible()
        expect(desk.locator("#change-summary")).to_contain_text("900")
        assert desk.script_errors == [], desk.script_errors


# ───────────────────────────── BI2: the top row with five favorites ─────────────────────────────

FAVORITES = ["/reservations", "/devices", "/reports", "plugin:presence.index", "plugin:wol.index"]

# every link, label, button and field drawn in the top row, with whether the element at its center is itself (or inside it)
ROW_ITEMS = """() => {
    const nav = document.querySelector('nav.nav');
    const bottom = nav.getBoundingClientRect().bottom;
    const drawn = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
        return r.width > 0 && r.height > 0 && r.top < bottom && s.display !== 'none' && s.visibility !== 'hidden' && !e.closest('.nav-dropdown-content'); };
    const items = [...nav.querySelectorAll('a, label, button, input:not([type=checkbox]):not([type=hidden])')].filter(drawn).map(e => {
        const r = e.getBoundingClientRect();
        const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return {name: (e.getAttribute('aria-label') || e.getAttribute('title') || e.textContent.trim() || e.id || e.className).slice(0, 40),
                favorite: e.classList.contains('nav-fav'), own: !!at && (at === e || e.contains(at))};
    });
    return {items: items, fit: nav.getAttribute('data-fit'), pill: !!nav.querySelector('.gs-pill'),
            favoritesDrawn: items.filter(i => i.favorite).length,
            sideways: document.documentElement.scrollWidth - window.innerWidth};
}"""


@pytest.fixture
def nav_state(live_server):
    """Sets the superadmin's favorites and whether the Getting started pill is shown; both are put back as they were found."""
    from jen.models.user import get_global_setting, set_global_setting
    from jen.services import onboarding

    dismissed = get_global_setting(onboarding._DISMISSED_KEY, "false")
    uid = _sql("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))[0]["id"]
    _sql("DELETE FROM user_nav")

    def set_state(favorites, pill):
        _sql("DELETE FROM user_nav")
        if favorites:
            _sql("INSERT INTO user_nav (user_id, top_row, tabbar) VALUES (%s, %s, '[]')", (uid, json.dumps(favorites)))
        set_global_setting(onboarding._DISMISSED_KEY, "false" if pill else "true")

    yield set_state
    _sql("DELETE FROM user_nav")
    set_global_setting(onboarding._DISMISSED_KEY, dismissed)


class TestEveryTopRowItemCanBeClicked:
    @pytest.mark.parametrize("pill", [True, False])
    @pytest.mark.parametrize("favorites", [0, 3, 5])
    @pytest.mark.parametrize("width", [1024, 1100])
    def test_each_item_drawn_is_the_element_at_its_own_center(self, desk, base_url, nav_state, width, favorites, pill):
        nav_state(FAVORITES[:favorites], pill)
        desk.set_viewport_size({"width": width, "height": 900})
        for path in ("/leases", "/about"):
            desk.goto(f"{base_url}{path}")
            desk.evaluate("() => document.fonts.ready.then(() => true)")
            row = desk.evaluate(ROW_ITEMS)
            assert row["pill"] is pill, row
            assert len(row["items"]) >= 8, row
            covered = [i["name"] for i in row["items"] if not i["own"]]
            assert covered == [], (width, favorites, pill, path, row["fit"], covered)
            assert row["sideways"] <= 0, (width, favorites, pill, path, row["sideways"])
            assert desk.locator(".nav-links .nav-fav").count() == favorites
            assert row["favoritesDrawn"] <= favorites
            if row["fit"] != "4":
                assert row["favoritesDrawn"] == favorites, row
        assert desk.script_errors == [], desk.script_errors

    def test_five_favorites_at_1024_leave_from_the_right_and_come_back_in_a_wider_window(
        self, desk, base_url, nav_state
    ):
        nav_state(FAVORITES, True)
        desk.set_viewport_size({"width": 1024, "height": 900})
        desk.goto(f"{base_url}/leases")
        desk.evaluate("() => document.fonts.ready.then(() => true)")
        favorites = desk.locator(".nav-links .nav-fav")
        expect(favorites).to_have_count(5)
        shown = [favorites.nth(i).is_visible() for i in range(5)]
        assert desk.locator("nav.nav").get_attribute("data-fit") == "4"
        # the ones that left are the last ones, and at least one is still in the row
        assert shown[0] and not shown[-1] and shown == sorted(shown, reverse=True), shown
        expect(desk.locator(".gs-pill")).to_be_visible()
        expect(desk.locator(".gs-pill .gs-pill-label")).to_be_hidden()
        assert "Getting started" in desk.locator(".gs-pill").get_attribute("aria-label")
        # a favorite that left the row is still where it came from: the page opens from its own address, and the row has no hole where it was
        for i in range(5):
            if shown[i]:
                favorites.nth(i).click(trial=True)
        desk.set_viewport_size({"width": 1680, "height": 900})
        desk.wait_for_function("w => window.innerWidth === w", arg=1680)
        desk.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
        for i in range(5):
            expect(favorites.nth(i)).to_be_visible()
        assert desk.locator("nav.nav").get_attribute("data-fit") != "4"
        assert desk.script_errors == [], desk.script_errors


# ───────────────────────────── BI11: Devices' IPv6 view ─────────────────────────────


@pytest.fixture
def device(live_server):
    _sql("DELETE FROM devices WHERE mac=%s", (DEVICE_MAC,))
    _sql(
        "INSERT INTO devices (mac, device_name, last_ip, last_subnet_id) VALUES (%s, 'q249-c-device', '10.99.0.67', %s)",
        (DEVICE_MAC, _ids()[0]),
    )
    yield
    _sql("DELETE FROM devices WHERE mac=%s", (DEVICE_MAC,))


class TestDevicesIPv6View:
    def test_the_ipv6_view_has_no_script_error_and_escape_throws_nothing(self, desk, base_url, ipv6_on):
        desk.goto(f"{base_url}/devices?view=v6")
        expect(desk.locator("#devices-results")).to_be_visible()
        assert desk.locator("#editModal").count() == 0
        assert desk.script_errors == [], desk.script_errors
        desk.keyboard.press("Escape")
        desk.locator('input[name="search"]').first.fill("2001:db8")
        desk.keyboard.press("Escape")
        assert desk.script_errors == [], desk.script_errors
        # the statements after the line that threw ran: the page's own functions below it exist
        assert desk.evaluate("() => typeof updateCount === 'function' && typeof confirmBulkDelete === 'function'")

    def test_the_ipv4_view_still_opens_and_closes_its_dialog(self, desk, base_url, device):
        desk.goto(f"{base_url}/devices?search=q249-c-device")
        row = desk.locator("tr", has_text="q249-c-device").first
        row.locator(".action-menu-btn").click()
        row.locator(".edit-btn").click()
        modal = desk.locator("#editModal")
        expect(modal).to_be_visible()
        desk.mouse.click(5, 5)  # the backdrop
        expect(modal).to_be_hidden()
        if not row.locator(".edit-btn").is_visible():
            row.locator(".action-menu-btn").click()
        row.locator(".edit-btn").click()
        expect(modal).to_be_visible()
        desk.keyboard.press("Escape")
        expect(modal).to_be_hidden()
        assert desk.script_errors == [], desk.script_errors


# ───────────────────────────── BI18: Reports, a pool just above the axis ─────────────────────────────

CHARTS = """() => Object.values(Chart.instances).filter(c => /^chart-\\d+$/.test(c.canvas.id)).map(c => {
    const pool = c.data.datasets.find(d => d.label === 'Pool Size');
    return {id: c.canvas.id, yMax: c.scales.y.max,
            pool: pool ? {dash: pool.borderDash, max: Math.max(...pool.data.filter(v => typeof v === 'number'))} : null};
})"""


@pytest.fixture
def history(live_server):
    """Two days of hourly snapshots: the first subnet has 88 to 90 addresses in use of a pool of 101 (its lines fit an axis of 100, its pool is just above
    it), the second the same lines and a pool of 130 (more than a quarter above the axis)."""
    a, b = _ids()[:2]
    _sql("DELETE FROM lease_history WHERE subnet_id IN (%s, %s)", (a, b))
    conn = _db()
    try:
        with conn.cursor() as cur:
            for n in range(48):
                for subnet_id, pool in ((a, 101), (b, 130)):
                    used = 88 + n % 3
                    cur.execute(
                        "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, dynamic_leases, reserved_leases, pool_used, pool_size) "
                        "VALUES (%s, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s, %s, 3, %s, %s)",
                        (subnet_id, n * 60, used, used, used, pool),
                    )
    finally:
        conn.close()
    yield a, b
    _sql("DELETE FROM lease_history WHERE subnet_id IN (%s, %s)", (a, b))


class TestReportsPoolLine:
    def test_a_pool_just_above_the_axis_is_drawn_and_one_far_above_is_a_figure(self, desk, base_url, history):
        a, b = history
        desk.goto(f"{base_url}/reports")
        desk.evaluate("() => localStorage.removeItem('jen-reports-scale')")
        desk.goto(f"{base_url}/reports")
        desk.wait_for_function("() => window.Chart && Object.keys(Chart.instances).length >= 2")
        charts = {c["id"]: c for c in desk.evaluate(CHARTS)}
        near = charts[f"chart-{a}"]
        assert near["pool"] and near["pool"]["dash"] == [4, 4] and near["pool"]["max"] == 101, near
        assert 101 <= near["yMax"] <= 125, near
        expect(desk.locator(f"#chart-pool-{a}")).to_be_hidden()
        far = charts[f"chart-{b}"]
        assert far["pool"] is None and far["yMax"] == 100, far
        expect(desk.locator(f"#chart-pool-{b}")).to_be_visible()
        expect(desk.locator(f"#chart-pool-{b}")).to_contain_text("Pool: 130 addresses")
        assert desk.script_errors == [], desk.script_errors


# ───────────────────────────── C2: a field error's icon ─────────────────────────────


class TestAFieldErrorHasItsIcon:
    def test_the_error_under_the_field_carries_the_error_icon(self, desk, base_url):
        desk.goto(f"{base_url}/settings/api-keys")
        desk.fill(
            "#f-name", " "
        )  # passes the browser's own "required"; the route refuses a name of spaces and makes no key
        desk.locator(".apikey-submit").click()
        desk.wait_for_load_state("load")
        error = desk.locator("#f-name-error")
        expect(error).to_have_text("Key name is required.")
        expect(error.locator("svg.ico use")).to_have_attribute("href", "#i-circle-x")
        expect(desk.locator("#f-name")).to_have_attribute("aria-invalid", "true")
        assert desk.locator(".alert[data-field]").count() == 0
        assert desk.script_errors == [], desk.script_errors
