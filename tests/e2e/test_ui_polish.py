"""
tests/e2e/test_ui_polish.py
───────────────────────────
v5.70.0-beta.2 (Q206): the seven polish items, in a real browser.

AV1  a saved filter is named through Jen's own dialog (Enter confirms), answered by a toast and a new option, with no navigation
AV2  a success flash fades by itself, an error flash stays until its close is clicked
AV3  a MAC is copied with a click - over the clipboard API, and again with `navigator.clipboard` removed (the plain-http fallback)
AV4  the summary line is part of the swap
AV5  the rows-per-page choice is remembered per browser
AV6  a search that matched nothing names itself, and Clear filters brings the rows back
AV7  the IP cell is a copy control, not a link to itself
"""

import re

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_USERNAME

pytestmark = pytest.mark.e2e

MAC_HEX = "AABBCCDDEE77"
MAC = "AA:BB:CC:DD:EE:77"
IP = "10.99.0.77"
HOST = "e2e-polish-host"


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


@pytest.fixture
def polish_lease():
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (MAC_HEX,))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 30 MINUTE), 1, %s, 0)",
                (IP, MAC_HEX, HOST),
            )
        yield
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (MAC_HEX,))
        conn.close()


@pytest.fixture
def no_saved_polish_filters():
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))
            uid = cur.fetchone()["id"]
            cur.execute("DELETE FROM saved_searches WHERE user_id=%s AND name LIKE 'e2e polish %%'", (uid,))
        yield
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM saved_searches WHERE name LIKE 'e2e polish %%'")
        conn.close()


class TestAV1TheSavedFilterDialog:
    @pytest.mark.parametrize("path", ["/leases", "/reservations"])
    def test_a_name_typed_through_the_dialog_gives_a_toast_and_an_option_with_no_navigation(
        self, logged_in_page, base_url, no_saved_polish_filters, path
    ):
        page = logged_in_page
        page.goto(f"{base_url}{path}?search=printer")
        page.evaluate("window.__noReload = 'still here'")
        url_before = page.url

        page.locator("#save-filter-btn").click()
        dialog = page.locator("#jen-prompt-overlay")
        expect(dialog).to_be_visible()
        expect(page.locator("#jen-prompt-input")).to_be_focused()
        page.keyboard.type("e2e polish printers")
        page.keyboard.press("Enter")

        expect(dialog).to_be_hidden()
        expect(page.locator("#jen-toasts")).to_contain_text("Filter saved: e2e polish printers")
        option = page.locator("#saved-filter-select option", has_text="e2e polish printers")
        expect(option).to_have_count(1)
        expect(page.locator("#saved-filter-select")).to_have_value("search=printer")
        assert page.url == url_before, "saving a filter must not navigate"
        assert page.evaluate("window.__noReload") == "still here", "saving a filter must not reload the page"

    def test_escape_and_an_empty_name_both_cancel(self, logged_in_page, base_url, no_saved_polish_filters):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.locator("#save-filter-btn").click()
        expect(page.locator("#jen-prompt-overlay")).to_be_visible()
        page.keyboard.press("Escape")
        expect(page.locator("#jen-prompt-overlay")).to_be_hidden()
        expect(page.locator("#save-filter-btn")).to_be_focused()  # focus returns to the opener

        page.locator("#save-filter-btn").click()
        page.keyboard.press("Enter")  # an empty value
        expect(page.locator("#jen-prompt-overlay")).to_be_hidden()
        expect(page.locator("#jen-toasts .toast")).to_have_count(0)
        expect(page.locator("#saved-filter-select option", has_text="e2e polish")).to_have_count(0)

    def test_a_native_browser_dialog_never_opens(self, logged_in_page, base_url, no_saved_polish_filters):
        page = logged_in_page
        seen = []
        page.on("dialog", lambda d: (seen.append(d.type), d.dismiss()))
        page.goto(f"{base_url}/leases")
        page.locator("#save-filter-btn").click()
        page.keyboard.type("e2e polish no native dialog")
        page.keyboard.press("Enter")
        expect(page.locator("#jen-toasts")).to_contain_text("Filter saved")
        assert seen == [], seen


def _flash(page, base_url, stale_days):
    """Make the server flash from /devices/settings (a valid number: success; one out of range: error), without consuming the flash: the fetch does not follow the redirect."""
    page.goto(f"{base_url}/devices")
    original = page.locator('input[name="stale_days"]').input_value()  # read BEFORE the post changes it
    token = page.locator('input[name="csrf_token"]').first.get_attribute("value")
    page.evaluate(
        """async ([token, days]) => {
            const body = new URLSearchParams({csrf_token: token, stale_days: days});
            await fetch('/devices/settings', {method: 'POST', body, redirect: 'manual', credentials: 'same-origin'});
        }""",
        [token, str(stale_days)],
    )
    page.goto(f"{base_url}/devices")
    return original


class TestAV2TheFlash:
    def test_a_success_flash_fades_by_itself_and_an_error_stays_until_it_is_closed(self, logged_in_page, base_url):
        page = logged_in_page
        original = _flash(page, base_url, 45)
        try:
            success = page.locator(".alert-flash.alert-success")
            expect(success).to_have_count(1)
            expect(success.locator(".alert-close")).to_have_attribute("aria-label", "Dismiss")
            expect(success).to_have_count(0, timeout=8000)  # gone within 8 s (it fades after 6)

            _flash(page, base_url, 9999)
            error = page.locator(".alert-flash.alert-error")
            expect(error).to_have_count(1)
            page.wait_for_timeout(8000)
            expect(error).to_have_count(1)  # still there at 8 s
            error.locator(".alert-close").click()
            expect(error).to_have_count(0)
        finally:
            _flash(page, base_url, original)

    def test_a_success_flash_can_be_closed_before_it_fades(self, logged_in_page, base_url):
        page = logged_in_page
        original = _flash(page, base_url, 46)
        try:
            success = page.locator(".alert-flash.alert-success")
            expect(success).to_have_count(1)
            success.locator(".alert-close").click()
            expect(success).to_have_count(0)
        finally:
            _flash(page, base_url, original)

    def test_a_toast_that_is_an_error_stays_and_a_success_leaves(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.evaluate("() => { jenToast('went well', 'success'); jenToast('went badly', 'error'); }")
        expect(page.locator("#jen-toasts .toast")).to_have_count(1)
        expect(page.locator("#jen-toasts-alert .toast")).to_have_count(1)
        expect(page.locator("#jen-toasts .toast")).to_have_count(0, timeout=8000)  # 5 s
        expect(page.locator("#jen-toasts-alert .toast")).to_have_count(1)
        page.locator("#jen-toasts-alert .alert-close").click()
        expect(page.locator("#jen-toasts-alert .toast")).to_have_count(0)


class TestAV3Copy:
    def test_a_click_copies_the_mac_and_the_toast_says_so(self, browser, base_url, polish_lease):
        from tests.e2e.conftest import ADMIN_PASSWORD, login

        ctx = browser.new_context()
        try:
            ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=base_url)
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/leases?search={HOST}")
            control = page.locator(f'button[data-copy="{MAC}"]').first
            control.click()
            expect(page.locator("#jen-toasts")).to_contain_text(f"Copied {MAC}")
            expect(control).to_have_class(re.compile(r"\bcopied\b"))
            assert page.evaluate("navigator.clipboard.readText()") == MAC

            page.locator(f'button[data-copy="{IP}"]').first.click()
            page.wait_for_function("(v) => navigator.clipboard.readText().then(t => t === v)", arg=IP)
        finally:
            ctx.close()

    def test_without_the_clipboard_api_the_fallback_still_copies(self, browser, base_url, polish_lease):
        """Jen is served over plain http on many home LANs, where `navigator.clipboard` does not exist."""
        from tests.e2e.conftest import ADMIN_PASSWORD, login

        ctx = browser.new_context()
        try:
            page = ctx.new_page()
            page.add_init_script("Object.defineProperty(Navigator.prototype, 'clipboard', {get: () => undefined});")
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/leases?search={HOST}")
            assert page.evaluate("typeof navigator.clipboard") == "undefined"
            control = page.locator(f'button[data-copy="{MAC}"]').first
            control.click()
            expect(page.locator("#jen-toasts")).to_contain_text(f"Copied {MAC}")
            expect(control).to_have_class(re.compile(r"\bcopied\b"))
            # read it back through the page's own paste where the browser allows it; the class and the toast above are the assertion where it does not
            page.locator('input[name="search"]').fill("")
            page.locator('input[name="search"]').focus()
            page.keyboard.press("Control+V")
            pasted = page.locator('input[name="search"]').input_value()
            if pasted:
                assert pasted == MAC
        finally:
            ctx.close()

    def test_the_copied_class_goes_after_a_moment(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases?search={HOST}")
        control = page.locator(f'button[data-copy="{MAC}"]').first
        control.click()
        expect(control).to_have_class(re.compile(r"\bcopied\b"))
        expect(control).not_to_have_class(re.compile(r"\bcopied\b"), timeout=3000)  # 1.2 s


class TestAV4AV7TheSummaryAndTheIpCell:
    def test_the_summary_is_part_of_the_swap(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        summary = page.locator("#leases-summary")
        expect(summary).to_contain_text("active lease")
        before = summary.inner_text()
        page.fill('input[name="search"]', HOST)
        expect(summary).to_contain_text("1 active lease")
        expect(summary).to_contain_text("1 expires within the hour")
        assert summary.inner_text() != before or "1 active lease" in before

    def test_the_ip_is_a_copy_control_and_not_a_link_to_itself(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases?search={HOST}")
        row = page.locator("tr", has_text=HOST)
        expect(row.locator(f'button[data-copy="{IP}"]')).to_have_count(1)
        expect(row.locator(f'a[href^="/leases?search={IP}"]')).to_have_count(0)
        expect(row.locator('a[href^="/client?q="]').first).to_be_attached()  # Investigate is still on the row


class TestAV5RowsPerPageIsRemembered:
    def test_pick_100_leave_return_see_100(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.select_option('select[name="per_page"]', "100")
        page.wait_for_url("**per_page=100**")
        page.goto(f"{base_url}/devices")
        page.goto(f"{base_url}/leases")
        expect(page.locator('select[name="per_page"]')).to_have_value("100")
        # another page keeps its own choice
        page.goto(f"{base_url}/reservations")
        expect(page.locator('select[name="per_page"]')).to_have_value("all")
        # put it back so no other journey inherits it
        page.goto(f"{base_url}/leases?per_page=all")
        page.goto(f"{base_url}/leases")
        expect(page.locator('select[name="per_page"]')).to_have_value("all")


class TestAV6TheFilteredEmptyState:
    def test_a_search_for_nothing_names_itself_and_clear_filters_brings_the_rows_back(
        self, logged_in_page, base_url, polish_lease
    ):
        page = logged_in_page
        page.goto(f"{base_url}/leases?search=zzz-nothing-matches")
        body = page.locator("#leases-results")
        expect(body).to_contain_text("No active leases match “zzz-nothing-matches”")
        expect(body).not_to_contain_text("No active leases yet")
        page.get_by_role("link", name="Clear filters").click()
        expect(page.locator("tr", has_text=HOST)).to_have_count(1)
        assert "search=" not in page.url


class TestAX10TheBadgeIsThePickerHint:
    """Q208 (AX10): the first visit to Subnets says the badge is the color picker; dismissing it is remembered by this browser."""

    @staticmethod
    def _forget(page, base_url):
        page.goto(f"{base_url}/subnets")
        page.evaluate("localStorage.removeItem('jen-tone-hint')")

    def test_first_visit_shows_it_dismiss_hides_it_and_a_reload_keeps_it_hidden(self, logged_in_page, base_url):
        page = logged_in_page
        self._forget(page, base_url)
        page.goto(f"{base_url}/subnets")
        hint = page.locator("#tone-hint")
        expect(hint).to_be_visible()
        expect(hint).to_contain_text("Click a subnet's name on its card to choose its badge color")
        hint.get_by_role("button", name="Dismiss").click()
        expect(hint).to_be_hidden()
        page.reload()
        expect(page.locator("#tone-hint")).to_be_hidden()
        assert page.evaluate("localStorage.getItem('jen-tone-hint')") == "seen"

    def test_another_browser_sees_it_again(self, logged_in_page, base_url):
        page = logged_in_page
        self._forget(page, base_url)
        page.goto(f"{base_url}/subnets")
        expect(page.locator("#tone-hint")).to_be_visible()


class TestAX1SortAndPageLinksSwapInPlace:
    def test_a_header_click_keeps_the_page_and_pushes_the_url(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.evaluate("window.__stay = 'same document'")
        page.locator("th a.th-link", has_text="Hostname").click()
        page.wait_for_url("**sort=hostname**")
        assert page.evaluate("window.__stay") == "same document", "a sort link must not reload the page"
        expect(page.locator("th[aria-sort]")).to_have_count(1)
        page.go_back()
        page.wait_for_load_state("load")

    def test_a_modified_click_is_the_browsers_own(self, logged_in_page, base_url, polish_lease):
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        with page.context.expect_page() as popup:
            page.locator("th a.th-link", has_text="Hostname").click(modifiers=["Control"])
        popup.value.wait_for_url("**sort=hostname**")
        popup.value.close()
