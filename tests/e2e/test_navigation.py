"""
tests/e2e/test_navigation.py
────────────────────────────
v7.2.0-beta.1 (Q243) - a person's own navigation and the sign-in page that was open too long, in a real browser
with the CSP on (the default `page`), against the live server.

* The pin button at the end of a section's tabs puts the page being shown into the top row and takes it out.
* The Customize navigation page fills the phone's bottom bar; a phone shows the bar the person chose, and the
  favorites lead the More menu.
* A sign-in form whose session cookie is gone (a tab the browser kept) is answered with the sign-in page and one
  sentence - never the 403 page - and signing in from THAT page works.

Screenshots go beside the screenshot job's own (artifacts/desktop, artifacts/mobile): the maintainer reviews them.
"""

import pathlib

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from jen.routes.auth import SIGN_IN_AGAIN
from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DESKTOP_DIR = ROOT / "artifacts" / "desktop"
MOBILE_DIR = ROOT / "artifacts" / "mobile"
WIDE = {"width": 1680, "height": 900}
PHONE = {"width": 390, "height": 844}


def _forget_navigation():
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_nav")
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def nobody_has_a_navigation_of_their_own():
    """Every journey in this suite shares one database: a favorite left behind would be in the next file's screenshots."""
    _forget_navigation()
    yield
    _forget_navigation()


def _add(page, base_url, place, label):
    page.goto(f"{base_url}/navigation")
    card = page.locator(f"#navc-{place}")
    option = card.locator("select[name=dest] option", has_text=label).first
    card.locator("select[name=dest]").select_option(value=option.get_attribute("value"))
    card.locator("form.navc-add button[type=submit]").click()
    page.wait_for_url(f"{base_url}/navigation")
    return card


class TestTopRowFavorites:
    def test_pin_from_the_strip_then_unpin(self, page, base_url):
        page.set_viewport_size(WIDE)
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        page.goto(f"{base_url}/health-center")
        expect(page.locator(".nav-links .nav-fav")).to_have_count(0)
        button = page.locator(".section-pin-btn")
        expect(button).to_have_text("Add to top row")
        button.click()
        page.wait_for_url(f"{base_url}/health-center")
        favorite = page.locator(".nav-links .nav-fav")
        expect(favorite).to_have_count(1)
        expect(favorite).to_have_text("Health")
        expect(favorite).to_have_class("nav-link nav-fav active")
        expect(page.locator(".section-pin-btn")).to_have_text("Remove from top row")
        # the five fixed items are all still there, before the favorite
        expect(page.locator(".nav-links a.nav-link:not(.nav-fav)")).to_have_count(5)
        DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(DESKTOP_DIR / "navigation-pinned.png"))
        # from another page the favorite is one click away
        page.goto(f"{base_url}/leases")
        page.locator(".nav-links .nav-fav").click()
        page.wait_for_url(f"{base_url}/health-center")
        page.locator(".section-pin-btn").click()
        page.wait_for_url(f"{base_url}/health-center")
        expect(page.locator(".nav-links .nav-fav")).to_have_count(0)

    def test_the_customize_page_adds_orders_and_removes(self, page, base_url):
        page.set_viewport_size(WIDE)
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        _add(page, base_url, "top", "Reports")
        card = _add(page, base_url, "top", "Timeline")
        expect(card.locator(".card-title")).to_contain_text("(2 of 5)")
        expect(page.locator(".nav-links .nav-fav")).to_have_text(["Reports", "Timeline"])
        card.get_by_role("button", name="Move up Timeline").click()
        page.wait_for_url(f"{base_url}/navigation")
        expect(page.locator(".nav-links .nav-fav")).to_have_text(["Timeline", "Reports"])
        page.screenshot(path=str(DESKTOP_DIR / "navigation-customize.png"), full_page=True)
        page.locator("#navc-top").get_by_role("button", name="Remove Timeline").click()
        page.wait_for_url(f"{base_url}/navigation")
        expect(page.locator(".nav-links .nav-fav")).to_have_text(["Reports"])
        page.locator("#navc-top").get_by_role("button", name="Reset to default").click()
        page.wait_for_url(f"{base_url}/navigation")
        expect(page.locator(".nav-links .nav-fav")).to_have_count(0)

    def test_a_narrower_window_keeps_the_icons_and_fits(self, page, base_url):
        """Five favorites at 1280: the words go, the icons stay, and the top bar does not push the page sideways."""
        page.set_viewport_size({"width": 1280, "height": 800})
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        for label in ("Reports", "Timeline", "Health", "Problems", "Devices"):
            _add(page, base_url, "top", label)
        expect(page.locator(".nav-links .nav-fav")).to_have_count(5)
        expect(page.locator(".nav-links .nav-fav .nav-fav-label").first).to_be_hidden()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        search = page.locator(".nav-search input").bounding_box()
        assert search["x"] + search["width"] <= 1280
        page.screenshot(path=str(DESKTOP_DIR / "navigation-five-at-1280.png"))


class TestThePhoneBar:
    def test_the_bar_the_person_chose(self, browser, base_url):
        ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
        page = ctx.new_page()
        try:
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            expect(page.locator(".tabbar a span")).to_have_text(["Dashboard", "Leases", "Reservations", "Settings"])
            for label in ("Dashboard", "Problems", "Alerts"):
                _add(page, base_url, "tabbar", label)
            _add(page, base_url, "top", "Reports")
            expect(page.locator(".tabbar a span")).to_have_text(["Dashboard", "Problems", "Alerts & Integrations"])
            expect(page.locator(".tabbar button span")).to_have_text("More")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            MOBILE_DIR.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(MOBILE_DIR / "navigation-customize.png"), full_page=True)
            page.locator(".tabbar a", has_text="Problems").click()
            page.wait_for_url(f"{base_url}/problems")
            expect(page.locator(".tabbar a.active span")).to_have_text("Problems")
            page.click('.tabbar button[data-sheet-open="more-sheet"]')
            expect(page.locator("#more-sheet")).to_be_visible()
            expect(page.locator("#more-sheet .sheet-group-label").first).to_have_text("Favorites")
            expect(page.locator("#more-sheet a", has_text="Customize navigation")).to_be_visible()
            page.screenshot(path=str(MOBILE_DIR / "navigation-more-sheet.png"))
        finally:
            ctx.close()


class TestASignInPageThatWasOpenTooLong:
    def test_the_form_comes_back_and_signing_in_from_it_works(self, page, context, base_url):
        page.goto(f"{base_url}/login")
        context.clear_cookies()  # the session this page's token belongs to is gone; the page itself is still on screen
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        expect(page.locator(".alert")).to_have_text(SIGN_IN_AGAIN)
        expect(page.locator("text=Back to Dashboard")).to_have_count(0)
        expect(page.locator('input[name="username"]')).to_have_value(ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        page.wait_for_url(f"{base_url}/")
        assert page.locator("h1", has_text="Dashboard").count() > 0
