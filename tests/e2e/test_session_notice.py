"""
tests/e2e/test_session_notice.py
────────────────────────────────
v5.70.0-beta.4 (Q208, AX2): the idle sign-out is announced two minutes ahead and comes back to the page, in a real browser.

The browser's clock is moved with Playwright's `page.clock`; the SERVER's clock has to move with it (a touch is the server's `now`), so the fixture below shifts the two `datetime` names the
timeout middleware and `POST /session/touch` use. Both move by the same number of seconds, which is what a real two minutes before the deadline looks like from either side.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e


@pytest.fixture
def server_clock(monkeypatch):
    import jen
    import jen.routes.auth as auth
    import jen.services.session_timeout as session_timeout

    class Shifted(datetime):
        offset = timedelta(0)

        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + cls.offset

    monkeypatch.setattr(jen, "datetime", Shifted)
    monkeypatch.setattr(auth, "datetime", Shifted)
    monkeypatch.setattr(session_timeout, "datetime", Shifted)
    yield Shifted


def _signed_in_on_leases(page, base_url):
    page.clock.install(time=datetime.now(timezone.utc))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    page.goto(f"{base_url}/leases?subnet=1")
    deadline = int(page.locator("body").get_attribute("data-session-expires"))
    return deadline


def _jump_to(page, server_clock, deadline, remaining):
    """Both clocks to `remaining` seconds before `deadline`."""
    now = page.evaluate("Math.floor(Date.now() / 1000)")
    jump = deadline - remaining - now
    assert jump > 0
    server_clock.offset = timedelta(seconds=jump)
    page.clock.fast_forward(jump * 1000)


class TestTheSessionDialog:
    def test_it_opens_two_minutes_ahead_and_stay_signed_in_closes_it_and_moves_the_deadline(
        self, page, base_url, server_clock
    ):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 119)
        overlay = page.locator("#jen-session-overlay")
        expect(overlay).to_be_visible()
        expect(overlay).to_have_attribute("role", "alertdialog")
        expect(page.locator("#jen-session-stay")).to_be_focused()
        expect(page.locator("#jen-session-text")).to_contain_text("You will be signed out in 1:")
        page.get_by_role("button", name="Stay signed in").click()
        expect(overlay).to_be_hidden()
        assert page.evaluate("window.jenSessionWatch.expires()") > deadline + 3000, (
            "the touch moved the deadline an hour on"
        )

    def test_the_countdown_runs(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 119)
        text = page.locator("#jen-session-left")
        expect(text).to_have_text(re.compile(r"1:[45]\d"))
        before = text.inner_text()
        page.clock.run_for(5000)
        expect(text).not_to_have_text(before)
        assert text.inner_text() < before, "the countdown runs down"

    def test_escape_is_stay_signed_in_and_tab_stays_inside_the_dialog(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        page.keyboard.press("Tab")
        expect(page.locator("#jen-session-out")).to_be_focused()
        page.keyboard.press("Tab")
        expect(page.locator("#jen-session-stay")).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator("#jen-session-overlay")).to_be_hidden()

    def test_past_the_deadline_with_no_answer_the_page_goes_to_sign_in_and_remembers_where_it_was(
        self, page, base_url, server_clock
    ):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, -3)
        page.wait_for_url(re.compile(r".*/login\?next=(%2F|/)leases(%3F|\?)subnet(%3D|=)1"), timeout=15000)

    def test_signing_in_again_comes_back_to_the_page(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, -3)
        page.wait_for_url(re.compile(r".*/login\?next="), timeout=15000)
        server_clock.offset = timedelta(0)
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        page.wait_for_url(re.compile(r".*/leases\?subnet=1"), timeout=15000)

    def test_another_tabs_touch_closes_the_dialog_here(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        overlay = page.locator("#jen-session-overlay")
        expect(overlay).to_be_visible()
        # what the other tab's response would do: a later deadline arrives through the storage event
        later = page.evaluate("window.jenSessionWatch.expires()") + 3600
        page.evaluate(f"window.jenSessionWatch.ingest({later}, true)")
        expect(overlay).to_be_hidden()

    def test_sign_out_now_signs_out(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        page.get_by_role("button", name="Sign out now").click()
        page.wait_for_url(re.compile(r".*/login"), timeout=15000)
