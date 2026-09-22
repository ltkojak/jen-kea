"""
tests/e2e/test_round3_journeys.py
───────────────────────────────────
v5.49.0-beta.3 (Q52) — browser journeys for the round-3 pages that
shipped after Q40: Configuration Doctor, Timeline, Client trace, DNS
Reconcile, and Getting started (including the dismiss button that was a
grey default <button> until this release).

Same rules as the rest of tests/e2e/: no page.evaluate /
page.wait_for_function (the CSP has no 'unsafe-eval'), assertions through
`expect(locator)`. Everything the pages read from Kea's own database is
seeded here with pymysql and removed in a `finally`.
"""

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import login
from tests.test_kea_log_trace import EXCHANGE, MAC

pytestmark = pytest.mark.e2e

MAC_HEX = MAC.replace(":", "").upper()
LEASE_IP = "10.99.0.150"
RESTRICTED_USER = "e2e_restricted_admin"
RESTRICTED_PASSWORD = "e2e-R3stricted!1"


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


@pytest.fixture
def lease():
    """One active lease for MAC in subnet 1 (10.99.0.0/24) with a hostname."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(INET_ATON(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'e2e-host')",
                (LEASE_IP, MAC_HEX),
            )
        yield LEASE_IP
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
        conn.close()


@pytest.fixture
def restricted_admin():
    """An admin limited to subnet 2 — MAC's lease lives in subnet 1."""
    import json

    from jen.models.user import hash_password

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (RESTRICTED_USER,))
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password, subnet_access) "
                "VALUES (%s, %s, 'admin', 0, %s)",
                (RESTRICTED_USER, hash_password(RESTRICTED_PASSWORD), json.dumps([2])),
            )
        yield RESTRICTED_USER
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (RESTRICTED_USER,))
        conn.close()


def test_doctor_renders_for_the_fake_kea_config(logged_in_page, base_url):
    page = logged_in_page
    page.goto(f"{base_url}/tools/doctor")
    expect(page.get_by_role("heading", name="Configuration Doctor")).to_be_visible()
    expect(page.get_by_role("link", name="Re-run")).to_be_visible()


def test_timeline_shows_the_active_lease_for_a_mac(logged_in_page, base_url, lease):
    page = logged_in_page
    page.goto(f"{base_url}/timeline?mac={MAC}")
    expect(page.get_by_text("Active lease").first).to_be_visible()
    expect(page.locator("body")).to_contain_text(lease)


def test_trace_renders_an_exchange_and_refuses_a_restricted_user(
    logged_in_page, base_url, lease, restricted_admin, monkeypatch, browser
):
    from jen.services import kea_host

    monkeypatch.setattr(
        kea_host,
        "tail_log",
        lambda server, path, lines=200, **kw: {"ok": True, "code": "ok", "lines": EXCHANGE, "via": "helper"},
    )
    page = logged_in_page
    page.goto(f"{base_url}/tools/trace?mac={MAC}")
    expect(page.locator("body")).to_contain_text("offered 10.0.1.55")

    # a subnet-2 admin must not see a subnet-1 client's log lines
    context = browser.new_context()
    try:
        other = context.new_page()
        login(other, base_url, restricted_admin, RESTRICTED_PASSWORD, f"{base_url}/")
        resp = other.goto(f"{base_url}/tools/trace?mac={MAC}")
        assert resp is not None and resp.status == 403
        expect(other.locator("body")).not_to_contain_text("offered 10.0.1.55")
    finally:
        context.close()


def test_reconcile_with_limit_one_renders_one_verdict_row(logged_in_page, base_url, lease, monkeypatch):
    from jen.routes import ddns

    monkeypatch.setattr(ddns, "_run_verify", lambda hostname, ip: {"forward_ips": [ip], "reverse_name": hostname})
    page = logged_in_page
    page.goto(f"{base_url}/ddns/reconcile?limit=1")
    rows = page.locator("table.rowlist tbody tr")
    expect(rows).to_have_count(1)
    expect(rows.first).to_contain_text("ok")


def test_getting_started_dismiss_button_is_a_real_link_style_and_clears_the_pill(logged_in_page, base_url):
    page = logged_in_page
    page.goto(f"{base_url}/getting-started")
    expect(page.get_by_role("heading", name="Getting Started")).to_be_visible()
    dismiss = page.get_by_role("button", name="Dismiss the nav reminder")
    expect(dismiss).to_be_visible()
    # v5.49.0-beta.3: it used to render as the browser's grey default button
    expect(dismiss).to_have_css("background-color", "rgba(0, 0, 0, 0)")
    dismiss.click()
    page.wait_for_url(f"{base_url}/getting-started")
    expect(page.locator("a", has_text="Getting started (")).to_have_count(0)


def test_saving_the_install_default_theme_actually_works_with_csrf_on(logged_in_page, base_url):
    # v5.55.2 (Q65) — this suite runs with CSRF enforcement ON (unlike the
    # unit suite, WTF_CSRF_ENABLED=False there), so it's the only layer
    # that could have caught the real bug: the theme-default form had no
    # csrf_token field, and every save 403'd with "Your session security
    # token is missing or expired." This proves the fix end to end, not
    # just that the field is present in the markup.
    page = logged_in_page
    try:
        page.goto(f"{base_url}/settings/appearance")
        select = page.locator('select[name="theme_default"]')
        expect(select).to_be_visible()
        select.select_option("phosphor")
        page.locator('form[action="/settings/theme/default"] button[type="submit"]').click()
        expect(page.get_by_text("Install default theme updated.")).to_be_visible()
        expect(page.locator('select[name="theme_default"]')).to_have_value("phosphor")
    finally:
        page.goto(f"{base_url}/settings/appearance")
        page.locator('select[name="theme_default"]').select_option("dark")
        page.locator('form[action="/settings/theme/default"] button[type="submit"]').click()
        expect(page.get_by_text("Install default theme updated.")).to_be_visible()
