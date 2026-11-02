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


class TestAPortraitPrintoutIsNotAPhone:
    """Q210 (AZ2, Y2): `_card_toc.html`'s phone block was `@media (max-width: 768px)` with no `screen`, and its script collapses every card but one at any width, so a portrait A4 or Letter printout
    (703-725 CSS px of content width) of a Settings page lost most of its text: 2,332 characters against 5,786 at 1280 px, 17 card bodies hidden."""

    def _text_and_hidden(self, page):
        return page.evaluate(
            """() => ({
                text: document.body.innerText.length,
                hidden: [...document.querySelectorAll('.card[data-collapsible]')].filter(card =>
                    [...card.children].some(el => !el.classList.contains('card-header') && getComputedStyle(el).display === 'none')).length,
                collapsible: document.querySelectorAll('.card[data-collapsible]').length,
            })"""
        )

    def test_a_settings_page_prints_whole_at_portrait_width(self, logged_in_page, base_url):
        page = logged_in_page
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{base_url}/settings/kea")
        page.emulate_media(media="print")
        wide = self._text_and_hidden(page)
        page.set_viewport_size({"width": 703, "height": 900})
        page.wait_for_timeout(300)
        narrow = self._text_and_hidden(page)
        assert narrow["collapsible"] >= 3, "the page's own script marked its cards: the check is not vacuous"
        assert narrow["hidden"] == 0, "no collapsible card body is hidden in print"
        assert abs(narrow["text"] - wide["text"]) <= wide["text"] * 0.10, (narrow["text"], wide["text"])

    def test_the_same_page_on_a_phone_screen_still_collapses_its_cards(self, logged_in_page, base_url):
        """The fix is the `screen` qualifier, not the removal of the phone layout: on a 390 px SCREEN the cards but one are still collapsed."""
        page = logged_in_page
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{base_url}/settings/kea")
        assert self._text_and_hidden(page)["hidden"] >= 2
