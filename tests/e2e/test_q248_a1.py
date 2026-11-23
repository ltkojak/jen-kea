"""
tests/e2e/test_q248_a1.py
─────────────────────────
Q248, stage a1 - keyboard access, dialogs and the Display menu, in a real browser with the CSP on, against the live server.

* V1   the Display menu, the Account menu and a lease row's action menu are opened, walked and closed with the keyboard alone.
* V2   the global search box and a menu's button show the focus ring.
* V3   Add User and Edit User: a dialog's role, focus on open, the Tab trap, Escape, focus given back, the page behind inert; a short password never leaves
       the browser; a form the server refused opens again with what was typed and the message beside its field.
* V41  ticking a subnet unticks All Subnets, in both user dialogs.
* V8   the targets that are not .btn measure 24 px or more (a phone's page pills 40), and a lease row is no taller for it.
* V9   the pages that had a control with no name have none.
* T1, T2, additions 12 and 13 - the Display menu: the default listed once, Match My System under both color schemes, Compact rows that survive a reload, the
  times options' words; the phone's sheet carries the same sections.
"""

import re

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

LAPTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
LEASE_MAC = "AABBCC248E01"
LEASE_HOST = "q248-menu-host"
LEASE_IP = "10.99.0.60"
DEVICE_MAC = "aa:bb:cc:24:8e:02"
RESERVED_MAC = "AABBCC248E03"
EDIT_USER = "q248_e2e_edit"


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


def _wipe(cur):
    cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (LEASE_MAC,))
    cur.execute("DELETE FROM hosts WHERE dhcp_identifier=UNHEX(%s)", (RESERVED_MAC,))
    cur.execute("DELETE FROM devices WHERE mac=%s", (DEVICE_MAC,))
    cur.execute("DELETE FROM users WHERE username=%s", (EDIT_USER,))


@pytest.fixture
def rows():
    """One lease, one device, one reservation and one account for this file, removed again: every journey of the suite shares one database."""
    from jen.models.user import hash_password

    conn = _db()
    try:
        with conn.cursor() as cur:
            _wipe(cur)
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, %s, 0)",
                (LEASE_IP, LEASE_MAC, LEASE_HOST),
            )
            cur.execute(
                "INSERT INTO devices (mac, device_name, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES (%s, 'Q248 Device', '10.99.0.61', 'q248-device-host', 1, NOW(), NOW())",
                (DEVICE_MAC,),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON('10.99.0.62'), 'q248-reserved-host')",
                (RESERVED_MAC,),
            )
            host_id = cur.lastrowid
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, 'admin', '[1]', 0)",
                (EDIT_USER, hash_password("q248-Not-used-1")),
            )
        yield {"host_id": host_id}
    finally:
        with conn.cursor() as cur:
            _wipe(cur)
        conn.close()


@pytest.fixture
def desk(page, base_url):
    """The default page (the CSP on), at the common laptop width, signed in as the superadmin, with every script error collected."""
    page.set_viewport_size(LAPTOP)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    assert not errors, errors


def _tab_to(page, selector, limit=40):
    """Press Tab until `selector` has the focus. Answers what had the focus just before it."""
    before = ""
    for _ in range(limit):
        page.keyboard.press("Tab")
        if page.evaluate("s => !!document.activeElement && document.activeElement.matches(s)", selector):
            return before
        before = page.evaluate(
            "(() => { const a = document.activeElement; return a ? a.tagName + '#' + a.id + '.' + a.className : ''; })()"
        )
    raise AssertionError(f"Tab never reached {selector}; the last stop was {before!r}")


def _focus_is_inside(page, selector):
    return page.evaluate("s => !!document.activeElement && !!document.activeElement.closest(s)", selector)


def _box(locator):
    box = locator.bounding_box()
    assert box is not None, "the element is not on screen"
    return box


# ───────────────────────────── V1, V2 ─────────────────────────────


class TestTheMenusFromTheKeyboard:
    def test_tab_goes_from_getting_started_to_display_to_account(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        before = _tab_to(page, "#dd-theme")
        if page.locator(".gs-pill").count():
            assert "gs-pill" in before, before
        page.keyboard.press("Tab")
        expect(page.locator("#dd-avatar")).to_be_focused()

    def test_the_display_menu_opens_moves_picks_and_closes(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        toggle, menu = page.locator("#dd-theme"), page.locator("#dd-theme-menu")
        _tab_to(page, "#dd-theme")
        # the label shows the ring while the hidden checkbox has the keyboard's focus
        ring = page.evaluate(
            "(() => { const s = getComputedStyle(document.querySelector('label[for=dd-theme]')); return [s.outlineStyle, s.outlineWidth]; })()"
        )
        assert ring == ["solid", "2px"], ring
        expect(toggle).to_have_attribute("aria-expanded", "false")
        page.keyboard.press("Space")
        expect(menu).to_be_visible()
        expect(toggle).to_have_attribute("aria-expanded", "true")
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
        expect(toggle).to_be_focused()
        expect(toggle).to_have_attribute("aria-expanded", "false")

        page.keyboard.press("Enter")
        expect(menu).to_be_visible()
        items = menu.locator("button")
        page.keyboard.press("ArrowDown")
        expect(items.nth(0)).to_be_focused()
        expect(items.nth(0)).to_have_attribute("data-theme-id", "")
        page.keyboard.press("End")
        expect(items.last).to_be_focused()
        expect(items.last).to_have_attribute("data-density", "compact")
        page.keyboard.press("ArrowDown")  # wraps
        expect(items.nth(0)).to_be_focused()
        page.keyboard.press("ArrowUp")  # wraps the other way
        expect(items.last).to_be_focused()
        page.keyboard.press("Home")
        page.keyboard.press("ArrowDown")
        page.keyboard.press("ArrowDown")
        expect(items.nth(2)).to_be_focused()
        expect(items.nth(2)).to_have_attribute("data-theme-id", "light")
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.keyboard.press("Enter")
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        expect(menu).to_be_hidden()
        expect(toggle).to_be_focused()
        expect(toggle).to_have_attribute("aria-expanded", "false")
        expect(items.nth(2)).to_have_attribute("aria-checked", "true")

    def test_arrow_down_on_the_button_opens_the_menu_on_its_first_item(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        _tab_to(page, "#dd-theme")
        page.keyboard.press("ArrowDown")
        expect(page.locator("#dd-theme-menu")).to_be_visible()
        expect(page.locator("#dd-theme-menu button").first).to_be_focused()
        # focus that leaves the menu closes it
        page.keyboard.press("Shift+Tab")
        page.keyboard.press("Shift+Tab")
        expect(page.locator("#dd-theme-menu")).to_be_hidden()

    def test_the_account_menu_reaches_sign_out_and_signs_out(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        toggle, menu = page.locator("#dd-avatar"), page.locator("#dd-avatar-menu")
        sign_out = menu.locator('form[action="/logout"] button')
        _tab_to(page, "#dd-avatar")
        page.keyboard.press("ArrowDown")
        expect(menu).to_be_visible()
        expect(menu.locator("a").first).to_be_focused()
        page.keyboard.press("End")
        expect(sign_out).to_be_focused()
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
        expect(toggle).to_be_focused()
        # opening Display closes Account, and the reverse: one menu at a time
        page.keyboard.press("Space")
        expect(menu).to_be_visible()
        page.locator('label[for="dd-theme"]').click()
        expect(page.locator("#dd-theme-menu")).to_be_visible()
        expect(menu).to_be_hidden()
        page.keyboard.press("Escape")
        # and Sign Out is used with the keyboard alone
        toggle.focus()
        page.keyboard.press("ArrowUp")  # opens the menu on its LAST item
        expect(sign_out).to_be_focused()
        page.keyboard.press("Enter")
        page.wait_for_url("**/login**")

    def test_a_lease_rows_menu_opens_reaches_its_first_action_and_closes(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text=LEASE_HOST).first
        toggle, dropdown = row.locator(".action-menu-toggle"), row.locator(".action-menu-dropdown")
        expect(toggle).to_have_attribute("aria-label", f"Actions for {LEASE_HOST}")
        row.locator("a.badge").focus()
        page.keyboard.press("Tab")
        expect(toggle).to_be_focused()
        page.keyboard.press("Space")
        expect(dropdown).to_be_visible()
        expect(toggle).to_have_attribute("aria-expanded", "true")
        page.keyboard.press("ArrowDown")
        expect(dropdown.locator(".copy")).to_be_focused()  # the first action: copy the MAC
        page.keyboard.press("ArrowDown")
        expect(dropdown.locator("a", has_text="Investigate")).to_be_focused()
        page.keyboard.press("Escape")
        expect(dropdown).to_be_hidden()
        expect(toggle).to_be_focused()
        expect(toggle).to_have_attribute("aria-expanded", "false")
        # Enter opens it too, and Enter on an item uses it
        page.keyboard.press("Enter")
        expect(dropdown).to_be_visible()
        page.keyboard.press("ArrowDown")
        page.keyboard.press("ArrowDown")
        page.keyboard.press("Enter")
        page.wait_for_url("**/client?q=**")

    def test_a_canceled_release_gives_the_focus_back_to_the_rows_menu(self, desk, base_url, rows):
        """The confirmation names its action, and a menu item that is gone when the dialog closes hands the focus to its menu's button."""
        page = desk
        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text=LEASE_HOST).first
        toggle = row.locator(".action-menu-toggle")
        release = row.locator(".action-menu-dropdown button", has_text="Release lease")
        toggle.focus()
        page.keyboard.press("Enter")
        for _ in range(12):  # the arrows reach it wherever the plugins' own actions put it
            page.keyboard.press("ArrowDown")
            if release.evaluate("e => e === document.activeElement"):
                break
        expect(release).to_be_focused()
        page.keyboard.press("Enter")
        expect(page.locator("#jen-confirm-overlay")).to_be_visible()
        expect(page.locator("#jen-confirm-ok")).to_have_text("Release")
        expect(page.locator("#jen-confirm-message")).to_have_text(f"Release lease for {LEASE_IP}?")
        page.keyboard.press("Escape")
        expect(page.locator("#jen-confirm-overlay")).to_be_hidden()
        expect(toggle).to_be_focused()
        # and confirmed, it releases THAT lease (the row's form is its own: it used to be swallowed by the bulk form around the table)
        page.keyboard.press("Enter")
        release.focus()
        page.keyboard.press("Enter")
        expect(page.locator("#jen-confirm-ok")).to_have_text("Release")
        with page.expect_navigation():
            page.locator("#jen-confirm-ok").click()
        expect(page.locator(".alert-success")).to_contain_text(f"Lease for {LEASE_IP} released.")
        expect(page.locator("tr", has_text=LEASE_HOST)).to_have_count(0)

    def test_a_plugins_row_action_posts_to_its_own_address(self, desk, base_url, rows):
        """A plugin's POST action in a row's menu (Presence's "Track presence") is a form of its own too: it used to be swallowed by the bulk form around the table and
        posted the bulk release. The request is answered here, in the browser, so nothing reaches the plugin."""
        page = desk
        seen = []

        def answer(route):
            seen.append((route.request.method, route.request.url))
            route.fulfill(status=200, content_type="text/html", body="<p>answered by the test</p>")

        page.route("**/management/presence/track-row**", answer)
        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text=LEASE_HOST).first
        action = row.locator(".action-menu-dropdown button", has_text="Track presence")
        if action.count() == 0:
            pytest.skip("the Presence plugin offers no row action in this run")
        row.locator(".action-menu-toggle").focus()
        page.keyboard.press("Space")
        with page.expect_navigation():
            action.click()
        assert len(seen) == 1 and seen[0][0] == "POST", seen
        assert "/management/presence/track-row?mac=" in seen[0][1] and LEASE_HOST in seen[0][1], seen

    def test_a_device_rows_remove_asks_first_and_removes_that_device(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/devices")
        row = page.locator("tr", has_text="Q248 Device").first
        toggle = row.locator(".action-menu-toggle")
        expect(toggle).to_have_attribute("aria-label", "Actions for Q248 Device")
        toggle.focus()
        page.keyboard.press("Space")
        row.locator(".action-menu-dropdown button", has_text="Remove from inventory").click()
        expect(page.locator("#jen-confirm-overlay")).to_be_visible()
        expect(page.locator("#jen-confirm-ok")).to_have_text("Remove")
        expect(page.locator("#jen-confirm-message")).to_have_text(
            f"Remove {DEVICE_MAC} from inventory? This cannot be undone."
        )
        with page.expect_navigation():
            page.locator("#jen-confirm-ok").click()
        expect(page.locator(".alert-success")).to_contain_text("Device removed from inventory.")
        expect(page.locator("tr", has_text="Q248 Device")).to_have_count(0)

    def test_the_search_box_shows_the_ring(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        page.locator("h1").first.click()
        page.keyboard.press("/")
        box = page.locator(".nav-search input")
        expect(box).to_be_focused()
        expect(box).to_have_attribute("aria-label", "Search")
        ring = box.evaluate("e => { const s = getComputedStyle(e); return [s.outlineStyle, s.outlineWidth]; }")
        assert ring == ["solid", "2px"], ring


# ───────────────────────────── V3, V41 ─────────────────────────────


class TestTheUserDialogs:
    def test_add_user_is_a_dialog_to_the_keyboard(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/settings/users")
        opener, dialog = page.locator("#add-user-btn"), page.locator("#add-modal")
        expect(dialog).to_be_hidden()
        opener.focus()
        page.keyboard.press("Enter")
        expect(dialog).to_be_visible()
        expect(dialog).to_have_attribute("role", "dialog")
        expect(dialog).to_have_attribute("aria-modal", "true")
        assert page.locator(f"#{dialog.get_attribute('aria-labelledby')}").inner_text().strip().endswith("Add User")
        expect(page.locator("#f-username")).to_be_focused()
        assert page.evaluate("document.querySelector('nav.nav').inert") is True
        assert page.evaluate("document.querySelector('.page-header').inert") is True
        for _ in range(14):
            page.keyboard.press("Tab")
            assert _focus_is_inside(page, "#add-modal")
        for _ in range(5):
            page.keyboard.press("Shift+Tab")
            assert _focus_is_inside(page, "#add-modal")
        page.keyboard.press("Escape")
        expect(dialog).to_be_hidden()
        expect(opener).to_be_focused()
        assert page.evaluate("document.querySelector('nav.nav').inert") is False

    def test_a_short_password_never_leaves_the_browser(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/settings/users")
        page.locator("#add-user-btn").click()
        page.evaluate("window.__q248_same_page = true")
        page.locator("#f-username").fill("q248_short_pw")
        page.locator("#f-password").click()
        page.keyboard.type(
            "short"
        )  # typed, as a person does: the browser checks the length only of a value a person edited
        page.keyboard.press("Enter")
        expect(page.locator("#add-modal")).to_be_visible()
        assert page.locator("#f-password").evaluate("e => e.validity.tooShort") is True
        assert page.evaluate("window.__q248_same_page") is True, "the form was not sent"
        expect(page.locator("#f-username")).to_have_value("q248_short_pw")

    def test_ticking_a_subnet_unticks_all_subnets(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/settings/users")
        page.locator("#add-user-btn").click()
        every = page.locator('#f-subnet_ids input[value="all"]')
        one = page.locator('#f-subnet_ids input[value="1"]')
        expect(every).to_be_checked()
        one.check()
        expect(every).not_to_be_checked()
        every.check()
        expect(one).not_to_be_checked()
        # a superadmin is never restricted: the list is not asked for
        page.locator("#add-role").select_option("superadmin")
        expect(page.locator("#add-subnet-group")).to_be_hidden()

    def test_a_refused_add_user_opens_again_with_what_was_typed(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/settings/users")
        page.locator("#add-user-btn").click()
        page.locator("#f-username").fill("bad name!")
        page.locator("#f-password").click()
        page.keyboard.type("longenough1")
        page.locator("#add-role").select_option("admin")
        page.locator('#f-subnet_ids input[value="1"]').check()
        page.locator("#f-timeout").fill("45")
        with page.expect_navigation():
            page.locator('#add-modal button[type="submit"]').click()
        assert page.url == f"{base_url}/settings/users"
        expect(page.locator("#add-modal")).to_be_visible()
        expect(page.locator("#f-username")).to_have_value("bad name!")
        expect(page.locator("#add-role")).to_have_value("admin")
        expect(page.locator('#f-subnet_ids input[value="1"]')).to_be_checked()
        expect(page.locator('#f-subnet_ids input[value="all"]')).not_to_be_checked()
        expect(page.locator("#f-timeout")).to_have_value("45")
        expect(page.locator("#f-password")).to_have_value("")
        expect(page.locator("#f-username-error")).to_contain_text("Username may only contain")
        expect(page.locator("#f-username")).to_have_attribute("aria-invalid", "true")
        expect(page.locator("#f-username")).to_be_focused()
        expect(page.locator('.alert[data-field="username"]')).to_have_count(0)
        # closing it gives the focus to the button that opens it
        page.keyboard.press("Escape")
        expect(page.locator("#add-user-btn")).to_be_focused()

    def test_edit_user_ticks_the_stored_subnets_and_gives_the_focus_back(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/settings/users")
        own = (
            page.locator("tr")
            .filter(has=page.locator("strong", has_text=re.compile(rf"^{ADMIN_USERNAME}$")))
            .locator(".edit-user-btn")
        )
        own.click()
        dialog = page.locator("#edit-modal")
        expect(dialog).to_be_visible()
        expect(dialog).to_have_attribute("role", "dialog")
        assert _focus_is_inside(page, "#edit-modal")
        # the superadmin stores no subnets and is asked for none
        expect(page.locator("#edit-subnet-group")).to_be_hidden()
        page.keyboard.press("Escape")
        expect(dialog).to_be_hidden()
        expect(own).to_be_focused()

        scoped = page.locator("tr", has_text=EDIT_USER).locator(".edit-user-btn")
        scoped.click()
        expect(page.locator("#edit-username-label")).to_have_text(EDIT_USER)
        expect(page.locator('#f-edit-subnet_ids input[value="1"]')).to_be_checked()
        expect(page.locator('#f-edit-subnet_ids input[value="all"]')).not_to_be_checked()
        page.locator('#f-edit-subnet_ids input[value="all"]').check()
        expect(page.locator('#f-edit-subnet_ids input[value="1"]')).not_to_be_checked()
        for _ in range(20):
            page.keyboard.press("Tab")
            assert _focus_is_inside(page, "#edit-modal")
        dialog.locator("[data-dialog-close]").last.click()
        expect(dialog).to_be_hidden()

    def test_a_refused_edit_user_opens_again_for_that_account(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/settings/users")
        page.locator("tr", has_text=EDIT_USER).locator(".edit-user-btn").click()
        page.locator("#edit-role").select_option("viewer")
        page.locator("#f-edit-timeout").fill("30")
        page.locator("#f-edit-new_password").click()
        page.keyboard.type("longenough1")
        page.locator("#f-edit-confirm_password").click()
        page.keyboard.type("longenough2")
        with page.expect_navigation():
            page.locator('#edit-form button[type="submit"]').click()
        expect(page.locator("#edit-modal")).to_be_visible()
        expect(page.locator("#edit-username-label")).to_have_text(EDIT_USER)
        expect(page.locator("#edit-role")).to_have_value("viewer")
        expect(page.locator("#f-edit-timeout")).to_have_value("30")
        expect(page.locator('#f-edit-subnet_ids input[value="1"]')).to_be_checked()
        expect(page.locator("#f-edit-new_password")).to_have_value("")
        expect(page.locator("#f-edit-confirm_password")).to_have_value("")
        expect(page.locator("#f-edit-confirm_password-error")).to_contain_text("New passwords do not match.")
        # the account is as it was
        conn = _db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role, session_timeout FROM users WHERE username=%s", (EDIT_USER,))
                assert cur.fetchone() == {"role": "admin", "session_timeout": None}
        finally:
            conn.close()

    def test_a_confirmation_opens_on_top_of_the_dialog_and_escape_closes_only_it(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/settings/users")
        page.locator("tr", has_text=EDIT_USER).locator(".edit-user-btn").click()
        page.locator("#delete-form button").click()
        expect(page.locator("#jen-confirm-overlay")).to_be_visible()
        expect(page.locator("#jen-confirm-ok")).to_have_text("Delete")
        expect(page.locator("#jen-confirm-cancel")).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator("#jen-confirm-overlay")).to_be_hidden()
        expect(page.locator("#edit-modal")).to_be_visible()
        page.keyboard.press("Escape")
        expect(page.locator("#edit-modal")).to_be_hidden()


# ───────────────────────────── the Display menu ─────────────────────────────


class TestTheDisplayMenu:
    def test_the_default_theme_is_listed_once_and_the_sections_carry_the_new_words(self, desk, base_url):
        page = desk
        page.goto(f"{base_url}/about")
        page.locator('label[for="dd-theme"]').click()
        menu = page.locator("#dd-theme-menu")
        themes = menu.locator(".theme-pick")
        expect(themes.first).to_contain_text("Dark (default)")
        expect(themes.first).to_have_attribute("aria-checked", "true")
        assert sum("Dark" in t for t in themes.all_inner_texts()) == 1
        expect(themes.nth(1)).to_contain_text("Match My System")
        expect(menu).not_to_contain_text("Install default")
        text = menu.text_content()  # the words as written: a section heading is drawn in capitals
        for words in (
            "Display",
            "Theme",
            "Display Times",
            "Local Browser Time",
            "UTC Time",
            "Table Rows",
            "Comfortable",
            "Compact",
        ):
            assert words in text, words
        # an item is a plain row in the text color, as in the Account menu: not an underlined link in the accent color
        look = "e => { const s = getComputedStyle(e); return [s.color, s.textDecorationLine]; }"
        account_look = page.locator("#dd-avatar-menu a").first.evaluate(look)
        assert themes.nth(2).evaluate(look) == account_look and account_look[1] == "none"
        # each theme row shows three sample dots, colored by a rule
        dots = themes.nth(2).locator(".theme-sample i")
        expect(dots).to_have_count(3)
        assert (
            dots.first.evaluate("e => getComputedStyle(e).backgroundColor") == "rgb(240, 242, 245)"
        )  # Light's page background
        # the times pick is stored and marked
        menu.locator('.time-pick[data-time-mode="utc"]').click()
        assert page.evaluate("localStorage.getItem('jen-time-pick')") == "utc"
        expect(menu.locator('.time-pick[data-time-mode="utc"]')).to_have_attribute("aria-checked", "true")

    def test_match_my_system_shows_light_then_dark_and_follows_a_change(self, browser, base_url):
        ctx = browser.new_context(viewport=LAPTOP, color_scheme="light")
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            expect(page.locator("html")).to_have_attribute(
                "data-theme", "dark"
            )  # the install's default, whatever the system asks for
            page.locator('label[for="dd-theme"]').click()
            page.locator('#dd-theme-menu .theme-pick[data-theme-id="system"]').click()
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            assert page.evaluate("localStorage.getItem('jen-theme-pick')") == "system"
            expect(page.locator('#dd-theme-menu .theme-pick[data-theme-id="system"]')).to_have_attribute(
                "aria-checked", "true"
            )
            page.emulate_media(color_scheme="dark")  # the operating system changes while the page is open
            expect(page.locator("html")).to_have_attribute("data-theme", "dark")
            assert page.evaluate("localStorage.getItem('jen-theme-pick')") == "system"
            page.reload()
            expect(page.locator("html")).to_have_attribute("data-theme", "dark")
            page.emulate_media(color_scheme="light")
            page.reload()
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            # the first row returns to the install's default and clears the pick
            page.locator('label[for="dd-theme"]').click()
            page.locator('#dd-theme-menu .theme-pick[data-theme-id=""]').click()
            expect(page.locator("html")).to_have_attribute("data-theme", "dark")
            assert page.evaluate("localStorage.getItem('jen-theme-pick')") is None
        finally:
            ctx.close()

    def test_compact_makes_a_lease_row_shorter_and_survives_a_reload(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text=LEASE_HOST).first
        tall = _box(row)["height"]
        assert 50 <= tall <= 56, tall
        page.locator('label[for="dd-theme"]').click()
        page.locator('#dd-theme-menu .density-pick[data-density="compact"]').click()
        expect(page.locator("html")).to_have_attribute("data-density", "compact")
        assert page.evaluate("localStorage.getItem('jen-density-pick')") == "compact"
        short = _box(row)["height"]
        assert 30 <= short <= 40 and short < tall, (tall, short)
        page.reload()
        expect(page.locator("html")).to_have_attribute("data-density", "compact")
        assert _box(page.locator("tr", has_text=LEASE_HOST).first)["height"] == short
        page.locator('label[for="dd-theme"]').click()
        expect(page.locator('#dd-theme-menu .density-pick[data-density="compact"]')).to_have_attribute(
            "aria-checked", "true"
        )
        page.locator('#dd-theme-menu .density-pick[data-density="comfortable"]').click()
        assert page.locator("html").get_attribute("data-density") is None
        assert page.evaluate("localStorage.getItem('jen-density-pick')") is None
        assert _box(page.locator("tr", has_text=LEASE_HOST).first)["height"] == tall

    def test_the_phones_sheet_carries_the_same_three_sections(self, browser, base_url):
        ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.locator('.tabbar [data-sheet-open="more-sheet"]').click()
            page.locator("#more-sheet .sheet-theme", has_text="Display").click()
            sheet = page.locator("#theme-sheet")
            expect(sheet).to_be_visible()
            text = sheet.text_content()  # the words as written: a section heading is drawn in capitals
            for words in (
                "Display",
                "Theme",
                "Dark (default)",
                "Match My System",
                "Display Times",
                "Local Browser Time",
                "UTC Time",
                "Table Rows",
                "Comfortable",
                "Compact",
            ):
                assert words in text, words
            assert "Install default" not in text and text.count("Dark") == 1
            sheet.locator('.theme-pick[data-theme-id="light"]').click()
            expect(page.locator("html")).to_have_attribute("data-theme", "light")
            expect(sheet).to_be_hidden()
        finally:
            ctx.close()


class TestAConfirmedButtonKeepsItsOwnAction:
    def test_the_custom_palettes_remove_removes_it(self, desk, base_url):
        """The Remove button of the custom palette form carries its own action (formaction) and a confirmation; the confirmed submit used to post the form's own
        action, which SAVED the palette. Its button says Remove."""
        page = desk
        page.goto(f"{base_url}/settings/appearance")
        try:
            with page.expect_navigation():
                page.locator('#theme-custom-form button[type="submit"]', has_text="Save Custom Palette").click()
            expect(page.locator(".alert-success", has_text="Custom theme palette saved.")).to_be_visible()
            remove = page.locator('#theme-custom-form button[formaction="/settings/theme/custom/remove"]')
            remove.click()
            expect(page.locator("#jen-confirm-ok")).to_have_text("Remove")
            expect(page.locator("#jen-confirm-message")).to_contain_text("This cannot be undone.")
            with page.expect_navigation():
                page.locator("#jen-confirm-ok").click()
            expect(page.locator(".alert-success", has_text="Custom theme palette removed.")).to_be_visible()
            expect(page.locator('#theme-custom-form button[formaction="/settings/theme/custom/remove"]')).to_have_count(
                0
            )
        finally:
            # a safety net for a failed run: the palette is gone from the table and from the server's 30-second settings cache
            from jen.models.user import _invalidate_settings_cache

            conn = _db()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM settings WHERE setting_key='theme_custom'")
            conn.close()
            _invalidate_settings_cache()


# ───────────────────────────── V8: targets ─────────────────────────────


class TestTargetsAreTwentyFourPixels:
    def _flash_an_error(self, page, base_url):
        """The API-key form refused for no name: the next page carries an error flash with its close button."""
        page.goto(f"{base_url}/settings/api-keys")
        token = page.evaluate("JSON.parse(document.body.getAttribute('hx-headers'))['X-CSRFToken']")
        r = page.context.request.post(
            f"{base_url}/settings/api-keys/create",
            form={"name": " ", "subnet_ids": "all"},
            headers={"X-CSRFToken": token, "Referer": f"{base_url}/subnets/add"},
            max_redirects=0,
        )
        assert r.status == 302

    def test_on_a_desktop(self, desk, base_url, rows):
        page = desk
        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text=LEASE_HOST).first
        sizes = {
            "copy": _box(row.locator(".copy").first),
            "badge": _box(row.locator("a.badge")),
            "sort header": _box(page.locator("th a.th-link").first),
        }
        assert 50 <= _box(row)["height"] <= 56, "the row is no taller for its bigger targets"
        assert _box(page.locator("thead tr").first)["height"] <= 40, "nor is the header row"
        page.evaluate(
            "(() => { const p = document.createElement('p'); p.className = 'small'; p.id = 'q248-fix'; "
            "p.innerHTML = 'DDNS updates are off. <a class=\"fix-link\" href=\"#\">Fix &rarr;</a>'; document.querySelector('.container').appendChild(p); })()"
        )
        sizes["Fix link"] = _box(page.locator("#q248-fix a"))
        page.locator("#kb-hint-btn").click()
        sizes["keyboard help close"] = _box(page.locator("#kb-modal-close-btn"))
        page.keyboard.press("Escape")
        self._flash_an_error(page, base_url)
        page.goto(f"{base_url}/leases")
        banner = page.locator(".alert-flash").first
        sizes["banner close"] = _box(banner.locator(".alert-close"))
        assert _box(banner)["height"] <= 46, "the banner is no taller for its close button"
        for name, box in sizes.items():
            assert box["height"] >= 24 and box["width"] >= 24, (name, box)

    def test_on_a_phone(self, browser, base_url, rows):
        ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
        try:
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/leases")
            row = page.locator("tr", has_text=LEASE_HOST).first
            for name, target in (("copy", row.locator(".copy").first), ("badge", row.locator("a.badge"))):
                box = _box(target)
                assert box["height"] >= 24 and box["width"] >= 24, (name, box)
            self._flash_an_error(page, base_url)
            page.goto(f"{base_url}/settings/users")
            close = _box(page.locator(".alert-flash .alert-close").first)
            assert close["height"] >= 24 and close["width"] >= 24, close
            pills = page.locator(".subtabs .subtab")
            assert pills.count() >= 2
            for i in range(pills.count()):
                assert _box(pills.nth(i))["height"] >= 40, pills.nth(i).inner_text()
            assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")
        finally:
            ctx.close()

    def test_customize_navigations_buttons(self, desk, base_url):
        page = desk
        conn = _db()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_nav")
            page.goto(f"{base_url}/navigation")
            card = page.locator("#navc-tabbar")
            expect(card.locator(".card-title")).to_contain_text("Phone bar (the default pages)")
            for _ in range(2):
                with page.expect_navigation():
                    card.locator("form.navc-add button[type=submit]").click()
            expect(card.locator(".card-title")).to_contain_text("Phone bar (2 of 4)")
            buttons = card.locator(".navc-list li button")
            expect(buttons).to_have_count(6)
            assert [buttons.nth(i).is_disabled() for i in range(6)] == [True, False, False, False, True, False]
            for i in range(6):
                box = _box(buttons.nth(i))
                assert box["height"] >= 24 and box["width"] >= 24, box
        finally:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_nav")
            conn.close()


# ───────────────────────────── V9: a control says what it is ─────────────────────────────

UNLABELED = """
(() => {
  const shown = el => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const s = getComputedStyle(el);
    return !(s.visibility === 'hidden' || s.display === 'none');
  };
  const inSheet = el => !!el.closest('.sheet, .sheet-backdrop, dialog:not([open]), [hidden]');
  const out = [];
  for (const el of document.querySelectorAll('input, select, textarea')) {
    if (inSheet(el) || !shown(el)) continue;
    if (['hidden', 'submit', 'button', 'image', 'reset'].includes(el.type)) continue;
    const named = (el.labels && el.labels.length) || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title');
    if (named || el.placeholder) continue;
    out.push((el.id ? '#' + el.id : el.tagName.toLowerCase()) + '[name=' + (el.name || '') + '] in ' + (el.parentElement ? el.parentElement.className : ''));
  }
  return out;
})()
"""


class TestNoControlWithoutAName:
    """The look-over's measure (pass/ui-review-720b5: a visible input, select or textarea with no label, aria-label, aria-labelledby or title, and no placeholder),
    over the pages of the core that had one. The Network Discovery page's schedule select is the plugin's own and is not walked here."""

    PAGES = [
        "/",
        "/leases",
        "/reservations",
        "/devices",
        "/reports",
        "/settings/users",
        "/settings/appearance",
        "/settings/kea",
        "/settings/databases",
        "/settings/databases/migrate",
        "/settings/system",
        "/settings/security",
        "/subnets/classes/new",
        "/setup/found",
        "/navigation",
    ]

    def test_the_pages_that_had_one_have_none(self, desk, base_url, rows):
        page = desk
        found = {}
        for path in [*self.PAGES, f"/reservations/edit/{rows['host_id']}"]:
            page.goto(f"{base_url}{path}")
            page.wait_for_load_state("load")
            if path == "/subnets/classes/new" and page.locator("#add-rule-btn").count():
                page.locator("#add-rule-btn").click()
            if path == "/settings/users":
                page.locator("#add-user-btn").click()
            bad = page.evaluate(UNLABELED)
            if bad:
                found[path] = bad
        assert not found, found
        # the rows this walk was for were on the page
        page.goto(f"{base_url}/devices")
        expect(page.locator('input.row-checkbox[aria-label="Select Q248 Device"]')).to_have_count(1)
        page.goto(f"{base_url}/reservations")
        expect(page.locator('input.row-checkbox[aria-label="Select q248-reserved-host"]')).to_have_count(1)
        expect(page.locator("#selectAll")).to_have_attribute("aria-label", "Select all rows")
