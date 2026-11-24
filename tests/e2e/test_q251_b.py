"""
tests/e2e/test_q251_b.py
────────────────────────
Q251 - the Edit User dialog for a single sign-on account, in a real browser with the CSP on: the identity provider sets such an account's subnets at every
sign-in, so the dialog offers no subnet box for it and says why in their place; a local account's dialog is what it was.
"""

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

SSO_USER = "q251_e2e_sso"
LOCAL_USER = "q251_e2e_local"
SENTENCE = (
    "Set by the identity provider at every sign-in (Subnet Mapping under Settings → Access & Security → Single Sign-On), "
    "so it is not edited here."
)


def _wipe(cur):
    cur.execute("DELETE FROM users WHERE username IN (%s, %s)", (SSO_USER, LOCAL_USER))


@pytest.fixture
def accounts():
    from jen.models.user import hash_password

    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cur:
            _wipe(cur)
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access, must_change_password, auth_provider, external_id) "
                "VALUES (%s, %s, 'admin', '[1]', 0, 'oidc', 'q251-sub')",
                (SSO_USER, hash_password("q251-Not-used-1")),
            )
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, 'admin', '[1]', 0)",
                (LOCAL_USER, hash_password("q251-Not-used-1")),
            )
        yield conn
    finally:
        with conn.cursor() as cur:
            _wipe(cur)
        conn.close()


@pytest.fixture
def desk(page, base_url):
    page.set_viewport_size({"width": 1440, "height": 900})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    assert not errors, errors


def _open(page, base_url, username):
    page.goto(f"{base_url}/settings/users")
    page.locator("tr", has_text=username).locator(".edit-user-btn").click()
    expect(page.locator("#edit-username-label")).to_have_text(username)


class TestEditUserForASingleSignOnAccount:
    def test_no_subnet_box_is_offered_and_the_sentence_stands_in_their_place(self, desk, base_url, accounts):
        page = desk
        _open(page, base_url, SSO_USER)
        expect(page.locator("#edit-subnet-group")).to_be_visible()
        expect(page.locator("#f-edit-subnet_ids")).to_be_hidden()
        expect(page.locator("#f-edit-subnet_ids-hint")).to_be_hidden()
        hint = page.locator("#edit-subnet-oidc-hint")
        expect(hint).to_be_visible()
        expect(hint).to_have_text(SENTENCE)
        boxes = page.locator('#f-edit-subnet_ids input[name="subnet_ids"]')
        assert boxes.count() >= 2
        for i in range(boxes.count()):
            expect(boxes.nth(i)).to_be_disabled()

    def test_saving_the_timeout_keeps_the_stored_subnets(self, desk, base_url, accounts):
        page = desk
        _open(page, base_url, SSO_USER)
        page.locator("#f-edit-timeout").fill("45")
        with page.expect_navigation():
            page.locator("#edit-form button[type=submit]").click()
        with accounts.cursor() as cur:
            cur.execute("SELECT role, subnet_access, session_timeout FROM users WHERE username=%s", (SSO_USER,))
            row = cur.fetchone()
        assert (row["role"], row["subnet_access"].replace(" ", ""), row["session_timeout"]) == ("admin", "[1]", 45)

    def test_a_local_accounts_dialog_is_what_it_was_even_after_a_single_sign_on_one(self, desk, base_url, accounts):
        page = desk
        _open(page, base_url, SSO_USER)
        page.keyboard.press("Escape")
        page.locator("tr", has_text=LOCAL_USER).locator(".edit-user-btn").click()
        expect(page.locator("#edit-username-label")).to_have_text(LOCAL_USER)
        expect(page.locator("#f-edit-subnet_ids")).to_be_visible()
        expect(page.locator("#edit-subnet-oidc-hint")).to_be_hidden()
        expect(page.locator('#f-edit-subnet_ids input[value="1"]')).to_be_enabled()
        expect(page.locator('#f-edit-subnet_ids input[value="1"]')).to_be_checked()
