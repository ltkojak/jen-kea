"""
tests/e2e/test_core_journeys.py
─────────────────────────────────
v5.39.0 (Q40) step 1/2 — the journeys that prove the live-server +
fake-Kea fixture actually works end to end: login (success and
failure), the forced-password-change gate, the dashboard, and
Leases -> "Why this address?" -> Explain. The remaining journeys (MFA,
passkeys, subnet edit, imports, HA maintenance, API keys, support
bundle, Health Center) land in step 2/2.
"""

import pymysql
import pymysql.cursors
import pytest

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, FRESH_PASSWORD, FRESH_USERNAME

pytestmark = pytest.mark.e2e


def _kea_db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)


def _seed_active_lease(mac_hex="AABBCCDDEE01", ip="10.99.0.50", subnet_id=1, hostname="e2e-test-host"):
    conn = _kea_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (mac_hex,))
            cur.execute(
                """INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state)
                   VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, %s, 0)""",
                (ip, mac_hex, subnet_id, hostname),
            )
        conn.commit()
    finally:
        conn.close()


class TestLogin:
    def test_login_reaches_the_dashboard(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        page.wait_for_url(f"{base_url}/")
        assert page.locator("h1", has_text="Dashboard").count() > 0

    def test_wrong_password_stays_on_login_with_a_flash(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', "definitely-not-the-password")
        page.click(".btn-login")
        page.wait_for_load_state("networkidle")
        assert "/login" in page.url
        assert page.get_by_text("Invalid username or password").count() > 0


class TestForcedPasswordChange:
    def test_a_fresh_account_is_routed_to_the_change_password_form_and_back_out(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', FRESH_USERNAME)
        page.fill('input[name="password"]', FRESH_PASSWORD)
        page.click(".btn-login")
        page.wait_for_url(f"{base_url}/force-password-change")
        assert page.locator("h1", has_text="Password Change Required").count() > 0

        new_password = "e2e-Brand-New-Pw!2"
        page.fill('input[name="new_password"]', new_password)
        page.fill('input[name="confirm_password"]', new_password)
        page.click(".btn-submit")

        # The gate clears — a fresh page load no longer bounces to the
        # change-password form, proving must_change_password actually
        # flipped, not just that this one POST redirected.
        page.wait_for_url(f"{base_url}/")
        page.goto(f"{base_url}/leases")
        assert "/force-password-change" not in page.url


class TestDashboard:
    def test_dashboard_loads_with_a_subnet_chart(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/")
        page.wait_for_selector('h1:has-text("Dashboard")')
        page.wait_for_selector('canvas[id^="chart-"]', state="attached", timeout=10000)
        assert page.locator('canvas[id^="chart-"]').count() > 0


class TestLeasesToExplain:
    def test_why_this_address_opens_explain_with_the_mac_filled(self, logged_in_page, base_url):
        _seed_active_lease()
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.wait_for_selector("text=e2e-test-host")

        # Open the row's action menu (a checkbox-driven CSS dropdown, no
        # JS) and follow "Why this address?" into Explain.
        row = page.locator("tr", has_text="e2e-test-host").first
        row.locator(".action-menu-btn").click()
        row.locator(".action-menu-item", has_text="Why this address?").click()

        page.wait_for_url("**/tools/explain**")
        mac_value = page.locator('input[name="mac"]').input_value()
        assert mac_value.replace(":", "").lower() == "aabbccddee01"
