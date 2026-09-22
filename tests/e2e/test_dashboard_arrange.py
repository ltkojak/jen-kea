"""
tests/e2e/test_dashboard_arrange.py
────────────────────────────────────
v5.54.0 (Q61) — dashboard Arrange mode: drag-and-drop on a desktop context,
the up/down arrows in a phone context (Safari's HTML5 drag is unreliable
there, which is why the arrows exist at all), the width picker, and
subnet-card pin/hide. Two subnets (E2E_SUBNETS: Office, Guest) give two
cards to reorder.
"""

import re

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import login

pytestmark = pytest.mark.e2e

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "e2e-Sup3rSecret!1"


@pytest.fixture
def dash_page(page, base_url):
    return login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")


def _panel_ids(page):
    return page.eval_on_selector_all(
        ".dash-widgets > div[id^='dash-']",
        "els => els.map(e => e.id).filter(id => window.getComputedStyle(document.getElementById(id)).display !== 'none')",
    )


def _card_ids(page):
    return page.eval_on_selector_all(
        "#dash-subnet_stats .stat-card[data-subnet-id]", "els => els.map(e => e.getAttribute('data-subnet-id'))"
    )


class TestArrangeOnDesktop:
    def test_arrows_reorder_a_panel_width_picker_and_save_persist(self, dash_page, base_url):
        page = dash_page
        page.click("#customize-btn")
        expect(page.locator("#dash-customize")).to_be_visible()
        page.check("#w-server_status")
        page.check("#w-alert_summary")
        page.click("#save-dash-prefs-btn")
        page.wait_for_timeout(200)

        before = _panel_ids(page)
        page.click("#arrange-btn")
        expect(page.locator("body")).to_have_class(re.compile(r"\barrange\b"))
        last = before[-1]
        # move the last visible panel to the top with repeated "move up" clicks
        for _ in range(len(before) - 1):
            page.locator("#" + last + " [data-arr-move='up']").click()
        assert _panel_ids(page)[0] == last

        page.locator("#" + last + " select[data-arr-width]").select_option("half")
        expect(page.locator("#" + last)).to_have_class(re.compile(r"\bdw-half\b"))

        page.click("#arrange-save-btn")
        expect(page.locator("body")).not_to_have_class(re.compile(r"\barrange\b"))
        page.reload()
        page.wait_for_timeout(300)
        assert _panel_ids(page)[0] == last
        expect(page.locator("#" + last)).to_have_class(re.compile(r"\bdw-half\b"))

    def test_native_drag_reorders_a_panel(self, dash_page, base_url):
        page = dash_page
        page.click("#customize-btn")
        page.click("#arrange-btn")
        ids = _panel_ids(page)
        assert len(ids) >= 2
        first, second = ids[0], ids[1]
        page.locator("#" + second + " .grip").drag_to(page.locator("#" + first + " .grip"))
        page.wait_for_timeout(100)
        assert _panel_ids(page)[0] == second
        page.click("#arrange-cancel-btn")  # don't persist this one — the arrows test above already covers save

    def test_cancel_reverts_without_saving(self, dash_page, base_url):
        page = dash_page
        before = _panel_ids(page)
        page.click("#customize-btn")
        page.click("#arrange-btn")
        page.locator("#" + before[-1] + " [data-arr-move='up']").click()
        assert _panel_ids(page) != before
        page.click("#arrange-cancel-btn")
        assert _panel_ids(page) == before


class TestArrangeOnPhone:
    @pytest.fixture
    def phone_dash(self, browser, base_url):
        ctx = browser.new_context(
            viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True, has_touch=True
        )
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        yield page
        ctx.close()

    def test_arrows_pin_and_hide_a_subnet_card_and_it_persists(self, phone_dash, base_url):
        page = phone_dash
        page.click("#customize-btn")
        page.click("#arrange-btn")
        expect(page.locator(".dash-width-picker").first).to_be_hidden()  # width picker is desktop-only

        cards = _card_ids(page)
        assert len(cards) >= 2
        second = cards[1]
        page.locator("#dash-subnet_stats .stat-card[data-subnet-id='" + second + "'] [data-arr-pin]").click()
        page.locator("#dash-subnet_stats .stat-card[data-subnet-id='" + cards[0] + "'] [data-arr-hide]").click()
        page.click("#arrange-save-btn")
        page.wait_for_timeout(200)

        page.reload()
        page.wait_for_timeout(300)
        visible = page.eval_on_selector_all(
            "#dash-subnet_stats .stat-card[data-subnet-id]",
            "els => els.filter(e => getComputedStyle(e).display !== 'none').map(e => e.getAttribute('data-subnet-id'))",
        )
        assert visible[0] == second
        assert cards[0] not in visible

    def test_compact_toggle_is_saved(self, phone_dash, base_url):
        page = phone_dash
        page.click("#customize-btn")
        page.check("#dash-compact-toggle")
        page.click("#save-dash-prefs-btn")
        page.wait_for_timeout(200)
        page.reload()
        page.wait_for_timeout(200)
        expect(page.locator("body")).to_have_class(re.compile(r"\bdash-compact\b"))
