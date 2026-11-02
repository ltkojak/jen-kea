"""
tests/e2e/test_print.py
───────────────────────
v5.70.0-beta.4 (Q208, AX8): a page prints without its chrome. `emulate_media(media="print")` is the browser's own print rendering.
"""

import pytest
from playwright.sync_api import expect

from tests.e2e.test_core_journeys import _seed_active_lease

pytestmark = pytest.mark.e2e


class TestThePrintSheet:
    def test_leases_prints_without_the_nav_and_with_the_hidden_columns(self, logged_in_page, base_url):
        _seed_active_lease()
        page = logged_in_page
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{base_url}/leases")
        hidden_on_a_phone = page.locator("td.hide-mobile").first
        expect(hidden_on_a_phone).to_be_hidden()
        page.emulate_media(media="print")
        expect(page.locator(".nav")).to_be_hidden()
        expect(page.locator(".filter-bar")).to_be_hidden()
        expect(page.locator(".tabbar")).to_be_hidden()
        expect(page.locator(".hide-mobile").first).to_be_visible()

    def test_the_print_only_line_shows_in_print_and_not_on_screen(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        line = page.locator("p.print-only")
        expect(line).to_be_hidden()
        page.emulate_media(media="print")
        expect(line).to_be_visible()
        expect(line).to_contain_text("Printed from Jen")
        expect(line).to_contain_text("localhost")
        expect(line.locator("time[data-jen-time]")).to_have_count(1)

    def test_no_url_is_sprayed_after_a_link(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.emulate_media(media="print")
        content = page.evaluate("getComputedStyle(document.querySelector('main a[href]'), '::after').content")
        assert content in ("none", "normal", '""')
