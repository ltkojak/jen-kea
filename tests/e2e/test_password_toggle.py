"""
tests/e2e/test_password_toggle.py
─────────────────────────────────
v5.70.0-beta.4 (Q208, AX7): every password field has a show/hide toggle, made by one script.
"""

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _toggle_works(page, field_selector):
    field = page.locator(field_selector)
    toggle = field.locator("xpath=following-sibling::button[contains(@class,'pw-toggle')]")
    expect(toggle).to_have_count(1)
    expect(toggle).to_have_attribute("aria-label", "Show password")
    expect(toggle).to_have_attribute("aria-pressed", "false")
    field.fill("not-a-real-password")
    toggle.click()
    expect(field).to_have_attribute("type", "text")
    assert field.input_value() == "not-a-real-password"
    expect(toggle).to_have_attribute("aria-pressed", "true")
    expect(toggle).to_have_attribute("aria-label", "Hide password")
    toggle.click()
    expect(field).to_have_attribute("type", "password")
    expect(toggle).to_have_attribute("aria-label", "Show password")


class TestThePasswordToggle:
    def test_the_sign_in_page_has_it(self, page, base_url):
        page.goto(f"{base_url}/login")
        _toggle_works(page, 'input[name="password"]')

    def test_the_toggle_is_reachable_by_keyboard(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.locator('input[name="password"]').focus()
        page.keyboard.press("Tab")
        expect(page.locator(".pw-toggle")).to_be_focused()
        page.keyboard.press("Enter")
        expect(page.locator('input[name="password"]')).to_have_attribute("type", "text")

    def test_signing_in_still_works_with_the_wrapper(self, page, base_url):
        from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")

    def test_an_authenticated_page_with_password_fields_has_them_all(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/profile")
        fields = page.locator("input[data-pw-enhanced]")
        assert fields.count() >= 3
        expect(page.locator(".pw-toggle")).to_have_count(fields.count())
        _toggle_works(page, "#f-new_password")

    def test_a_password_field_in_a_flex_row_keeps_its_row(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/kea")
        for box in page.locator(".pw-wrap").all():
            if box.is_visible():
                width = box.bounding_box()["width"]
                assert width > 100, "a wrapped field must not collapse"
