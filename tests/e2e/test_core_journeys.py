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
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, FRESH_PASSWORD, FRESH_USERNAME, login

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
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        assert page.locator("h1", has_text="Dashboard").count() > 0

    def test_wrong_password_stays_on_login_with_a_flash(self, page, base_url):
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', "definitely-not-the-password")
        page.click(".btn-login")
        page.wait_for_load_state("networkidle")
        assert "/login" in page.url
        assert page.get_by_text("Invalid username or password").count() > 0


class TestLoginDiagnostics:
    """Temporary — v5.39.0 (Q40) debugging. Every login after the very
    first one in a run comes back "Invalid username or password." with
    no server exception logged, for the *correct* admin password too,
    not just the fresh account. This probes the same in-process Flask
    app directly (no browser, no HTTP) right where the pattern starts,
    to see which of {row missing, hash mismatch, silently locked out}
    it actually is before guessing at another fix blind. Remove once
    the real cause has a real fix."""

    def test_probe_admin_row_and_verify_password_in_process(self, page, base_url):
        # Reproduce the exact failure first: log in as admin a second
        # time in this run (test_login_reaches_the_dashboard already
        # did it once, successfully, earlier in this same session).
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        page.wait_for_load_state("networkidle")
        stuck_at_login = "/login" in page.url
        alerts = page.locator(".alert").all_text_contents()

        from jen.models.db import jen_db
        from jen.models.user import hash_password, needs_rehash, verify_password
        from jen.services.auth import get_rate_limit_settings, is_locked_out

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT id, username, password FROM users WHERE username=%s", (ADMIN_USERNAME,))
            rows = cur.fetchall()
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=%s", (ADMIN_USERNAME,))
            admin_count = cur.fetchone()["cnt"]
            cur.execute("SELECT ip_address, username, attempted_at FROM login_attempts ORDER BY attempted_at")
            attempts = cur.fetchall()

        verified = [verify_password(r["password"], ADMIN_PASSWORD) for r in rows]
        stored_prefix = rows[0]["password"][:25] if rows else None
        needs_rehash_result = needs_rehash(rows[0]["password"]) if rows else None
        fresh_hash = hash_password(ADMIN_PASSWORD)
        fresh_prefix = fresh_hash[:25]
        fresh_self_check = verify_password(fresh_hash, ADMIN_PASSWORD)
        locked, remaining = is_locked_out("127.0.0.1", ADMIN_USERNAME)

        raise AssertionError(
            f"stuck_at_login={stuck_at_login} alerts={alerts!r} | "
            f"admin_row_count={admin_count} verify_password_results={verified} | "
            f"stored_hash_prefix={stored_prefix!r} needs_rehash={needs_rehash_result!r} | "
            f"fresh_hash_prefix={fresh_prefix!r} fresh_self_check={fresh_self_check!r} | "
            f"rate_limit_settings={get_rate_limit_settings()!r} "
            f"is_locked_out={locked!r}/{remaining!r} | "
            f"login_attempts={attempts!r}"
        )


class TestForcedPasswordChange:
    def test_a_fresh_account_is_routed_to_the_change_password_form_and_back_out(self, page, base_url):
        login(page, base_url, FRESH_USERNAME, FRESH_PASSWORD, f"{base_url}/force-password-change")
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
