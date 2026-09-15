"""
tests/e2e/test_mfa_journeys.py
─────────────────────────────────
v5.39.0 (Q40) step 2/2 — TOTP enrollment, passkey registration and
login through Chromium's virtual authenticator (CDP WebAuthn), and the
MFA challenge page's tab switching + remember-for select. This is the
class of bug 5.31.2/5.31.3 shipped with every server-rendered test
green (CHANGELOG [5.31.3]) — dead client-side JS that nothing but a
real browser would ever catch.

Each test creates its own throwaway user rather than reusing the
shared admin — once an account has an enrolled factor, every future
login for it needs the MFA challenge page, which would silently break
every other journey's plain-password `login()` if it happened to the
shared admin account.
"""

import pymysql
import pymysql.cursors
import pyotp
import pytest

from tests.conftest import TEST_DB
from tests.e2e.conftest import login

pytestmark = pytest.mark.e2e


def _create_user(username, password):
    from jen.models.user import hash_password

    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (username,))
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'superadmin', 0)",
                (username, hash_password(password)),
            )
        conn.commit()
    finally:
        conn.close()


def _add_virtual_authenticator(page):
    """A Chromium CDP virtual WebAuthn authenticator — real page JS runs
    unmodified; the browser answers navigator.credentials.create/get
    itself instead of prompting a human."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
            }
        },
    )
    return cdp


def _totp_secret(page):
    return page.locator("div.mono").first.text_content().strip()


class TestTotpEnrollment:
    def test_enroll_totp_shows_backup_codes(self, page, base_url):
        _create_user("e2e_totp_user", "e2e-Totp-Pw!1")
        login(page, base_url, "e2e_totp_user", "e2e-Totp-Pw!1", f"{base_url}/")

        page.goto(f"{base_url}/mfa/enroll")
        code = pyotp.TOTP(_totp_secret(page)).now()
        page.fill('input[name="code"]', code)
        page.get_by_role("button", name="Enroll Authenticator").click()
        page.wait_for_load_state("networkidle")
        assert "backup code" in page.content().lower()


class TestPasskeyRegistrationAndLogin:
    def test_register_a_passkey_then_log_in_with_it(self, page, base_url):
        _create_user("e2e_passkey_user", "e2e-Passkey-Pw!1")
        _add_virtual_authenticator(page)

        login(page, base_url, "e2e_passkey_user", "e2e-Passkey-Pw!1", f"{base_url}/")
        page.goto(f"{base_url}/mfa/enroll")
        page.fill("#passkey-name", "e2e-passkey")
        page.click("#passkey-add-btn")
        page.wait_for_url("**/mfa/passkey/enrolled", timeout=15000)

        # A fresh session — the account now carries an enrolled factor,
        # so the next login must stop at the MFA challenge page instead
        # of reaching the dashboard directly.
        page.context.clear_cookies()
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', "e2e_passkey_user")
        page.fill('input[name="password"]', "e2e-Passkey-Pw!1")
        page.click(".btn-login")
        page.wait_for_url("**/mfa/verify")
        page.click("#passkey-login-btn")
        page.wait_for_url(f"{base_url}/", timeout=15000)
        assert page.locator("h1", has_text="Dashboard").count() > 0


class TestMfaChallengeTabsAndRememberFor:
    def test_switching_to_the_totp_tab_and_remember_for_select(self, page, base_url):
        username, password = "e2e_multi_factor_user", "e2e-Multi-Pw!1"
        _create_user(username, password)
        _add_virtual_authenticator(page)

        login(page, base_url, username, password, f"{base_url}/")

        page.goto(f"{base_url}/mfa/enroll")
        secret = _totp_secret(page)
        page.fill('input[name="code"]', pyotp.TOTP(secret).now())
        page.get_by_role("button", name="Enroll Authenticator").click()
        page.wait_for_load_state("networkidle")

        page.goto(f"{base_url}/mfa/enroll")
        page.fill("#passkey-name", "e2e-second-factor")
        page.click("#passkey-add-btn")
        # /mfa/passkey/enrolled only shows the backup-codes page when
        # this was the user's *first* factor (TestPasskeyRegistrationAndLogin
        # covers that case) — as a second factor here, it 302s straight
        # back to /mfa/enroll instead, so there's no distinct URL to wait
        # for; wait for the enrollment POST's own round trip to settle.
        page.wait_for_load_state("networkidle", timeout=15000)

        page.context.clear_cookies()
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click(".btn-login")
        page.wait_for_url("**/mfa/verify")

        # Both factors enrolled — both tabs render, passkey is the
        # default active one.
        assert page.locator('button.tab[data-tab="passkey"]').count() == 1
        assert page.locator('button.tab[data-tab="totp"]').count() == 1

        page.click('button.tab[data-tab="totp"]')
        page.wait_for_selector("#tab-totp", state="visible", timeout=5000)

        page.check("#rememberCb")
        page.wait_for_selector("#rememberDays", state="visible", timeout=5000)
        page.select_option("#rememberDays select", "7")

        page.fill('#tab-totp input[name="code"]', pyotp.TOTP(secret).now())
        page.wait_for_url(f"{base_url}/", timeout=10000)
