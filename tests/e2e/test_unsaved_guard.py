"""
tests/e2e/test_unsaved_guard.py
───────────────────────────────
v5.70.0-beta.4 (Q208, AX3): a half-edited long form warns before it is left - and never blocks a save, a logout or the sign-in redirect.
"""

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _collect(page):
    seen = []

    def handle(dialog):
        seen.append(dialog.type)
        dialog.dismiss()

    page.on("dialog", handle)
    return seen


class TestTheUnsavedGuard:
    def test_typing_into_settings_kea_then_following_a_nav_link_asks(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        seen = _collect(page)
        field = page.locator("#f-server_name")
        field.scroll_into_view_if_needed()
        field.fill("A name I have not saved")
        page.locator('.nav-links a[href="/leases"]').first.click()
        page.wait_for_timeout(500)
        assert seen == ["beforeunload"], seen
        assert page.url.endswith("/settings/kea") or "/settings/kea" in page.url

    def test_leaving_untouched_does_not_ask(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        seen = _collect(page)
        page.locator('.nav-links a[href="/leases"]').first.click()
        page.wait_for_url("**/leases**")
        assert seen == []

    def test_saving_does_not_ask(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        seen = _collect(page)
        field = page.locator("#f-server_name")
        field.fill("Kea Server 1")
        field.locator("xpath=ancestor::form").locator("button[type=submit]").first.click()
        page.wait_for_load_state("load")
        assert "beforeunload" not in seen, seen

    def test_typing_and_then_changing_it_back_does_not_ask(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        seen = _collect(page)
        field = page.locator("#f-server_name")
        original = field.input_value()
        field.fill(original + "x")
        field.fill(original)
        page.locator('.nav-links a[href="/leases"]').first.click()
        page.wait_for_url("**/leases**")
        assert seen == []

    def test_a_dirty_form_does_not_block_a_list_filter_page(self, logged_in_page, base_url):
        """The three list filters are swapped by htmx and never carry the guard; typing in one and leaving is silent."""
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        seen = _collect(page)
        page.fill('input[name="search"]', "typed")
        page.locator('.section-tabs a[href="/devices"]').first.click()
        page.wait_for_url("**/devices**")
        assert seen == []

    def test_logout_from_a_page_with_no_edit_is_not_asked(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        seen = _collect(page)
        page.goto(f"{base_url}/logout")
        expect(page.locator("main form[action='/logout'] button[type=submit]")).to_be_visible()
        assert seen == []
