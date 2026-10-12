"""
tests/e2e/test_saved_filters.py
────────────────────────────────
v5.69.0-beta.4 (Q173, item 1): the Saved-filters dropdown on Leases and Reservations lists a saved filter.

Both pages called `jenFetch` from a script inside the content block, which renders before the script that defined it, so the call threw "jenFetch is not defined" and the
dropdown stayed empty. Every other page was fine, which is why nothing noticed: this loads each page in a real browser and reads the dropdown.
"""

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_USERNAME

pytestmark = pytest.mark.e2e


@pytest.fixture
def saved_filters():
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))
            uid = cur.fetchone()["id"]
            cur.execute("DELETE FROM saved_searches WHERE user_id=%s AND name LIKE 'e2e saved %%'", (uid,))
            for page in ("leases", "reservations"):
                cur.execute(
                    "INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s, %s, %s, %s)",
                    (uid, f"e2e saved {page}", page, "search=printer"),
                )
        yield
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM saved_searches WHERE name LIKE 'e2e saved %%'")
        conn.close()


@pytest.mark.parametrize("page_name,path", [("leases", "/leases"), ("reservations", "/reservations")])
def test_the_saved_filters_dropdown_lists_a_saved_filter(logged_in_page, base_url, saved_filters, page_name, path):
    errors = []
    logged_in_page.on("pageerror", lambda e: errors.append(str(e)))
    logged_in_page.goto(f"{base_url}{path}")
    expect(logged_in_page.locator("#saved-filter-select option", has_text=f"e2e saved {page_name}")).to_have_count(1)
    assert not [e for e in errors if "jenFetch" in e], errors
