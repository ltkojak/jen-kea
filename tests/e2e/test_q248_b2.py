"""
tests/e2e/test_q248_b2.py
─────────────────────────
Q248, the additions on single pages that only a browser can show (the rest are tests/test_q248_b2.py):

* Addition 6   the line under Add Reservation's address field follows the Subnet select; a free cell of the IP map opens the form filled in, and a
               viewer's free cells are not links.
* Addition 3   the Health page's skipped checks are behind one closed line that opens, and stays open when the results are swapped.
* Addition 2   the dashboard's "Needs attention" card is drawn from the server's answer and only when the answer has a line.
"""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

DESKTOP = {"width": 1440, "height": 900}
VIEWER = "q248b2_viewer"
VIEWER_PASSWORD = "e2e-Q248b2!View"


@pytest.fixture(scope="module")
def admin(browser, base_url):
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()


@pytest.fixture(scope="module")
def viewer(browser, base_url):
    """A viewer made for this module and removed after it."""
    from jen.models.db import jen_db
    from jen.models.user import hash_password

    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username=%s", (VIEWER,))
        cur.execute(
            "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'viewer', 0)",
            (VIEWER, hash_password(VIEWER_PASSWORD)),
        )
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    login(page, base_url, VIEWER, VIEWER_PASSWORD, f"{base_url}/")
    yield page
    ctx.close()
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username=%s", (VIEWER,))


def _first_subnet(page):
    """(id, cidr) of the first subnet the Add Reservation select offers, read from the page (the dataset decides which subnets there are)."""
    return page.evaluate(
        """() => {
            const o = document.querySelectorAll('#f-subnet_id option:not([disabled])')[0];
            return [o.value, o.textContent.split('—')[1].trim()];
        }"""
    )


class TestTheRangeLineFollowsTheSubnet:
    def test_nothing_is_shown_until_a_subnet_is_chosen_and_then_it_follows_the_select(self, admin, base_url):
        admin.goto(f"{base_url}/reservations/add")
        line = admin.locator("#f-ip-range")
        expect(line).to_be_hidden()
        options = admin.evaluate(
            """() => Array.from(document.querySelectorAll('#f-subnet_id option:not([disabled])'))
                .map(o => [o.value, o.textContent.split('—')[1].trim()])"""
        )
        assert len(options) >= 2, options
        seen = []
        for value, cidr in options[:2]:
            admin.select_option("#f-subnet_id", value)
            expect(line).to_be_visible()
            text = line.inner_text()
            assert text.startswith(f"Subnet {cidr}"), text
            # the fake Kea of this suite gives every subnet one pool inside its own range
            assert " - pool " in text and text.split(" - pool ")[1].startswith(cidr.rsplit(".", 1)[0] + "."), text
            seen.append(text)
        assert seen[0] != seen[1]

    def test_an_address_typed_first_picks_the_subnet_and_the_line_with_it(self, admin, base_url):
        admin.goto(f"{base_url}/reservations/add")
        value, cidr = _first_subnet(admin)
        admin.fill("#f-ip", cidr.rsplit(".", 1)[0] + ".20")
        expect(admin.locator("#f-subnet_id")).to_have_value(value)
        expect(admin.locator("#f-ip-range")).to_contain_text(f"Subnet {cidr}")

    def test_the_line_is_the_address_fields_description(self, admin, base_url):
        admin.goto(f"{base_url}/reservations/add")
        assert admin.get_attribute("#f-ip", "aria-describedby") == "f-ip-range"


class TestAFreeMapCellOpensTheForm:
    def test_an_admin_selects_a_free_address_and_the_form_opens_filled_in(self, admin, base_url):
        admin.goto(f"{base_url}/ipmap")
        subnet = admin.eval_on_selector(".filter-bar select[name=subnet]", "s => s.value")
        cell = admin.locator("a.ip-cell.ip-free").first
        expect(cell).to_be_visible()
        label = cell.get_attribute("aria-label")
        address = label.split(":")[0]
        assert label == f"{address}: free. Add a reservation for this address"
        cell.click()
        admin.wait_for_url("**/reservations/add?**")
        expect(admin.locator("#f-ip")).to_have_value(address)
        expect(admin.locator("#f-subnet_id")).to_have_value(subnet)
        expect(admin.locator("#f-ip-range")).to_be_visible()
        expect(admin.locator("#f-subnet_id-hint")).to_be_hidden()

    def test_a_free_cell_can_be_reached_and_opened_from_the_keyboard(self, admin, base_url):
        admin.goto(f"{base_url}/ipmap")
        cell = admin.locator("a.ip-cell.ip-free").first
        cell.focus()
        assert admin.evaluate("document.activeElement.classList.contains('ip-free')")
        admin.keyboard.press("Enter")
        admin.wait_for_url("**/reservations/add?**")

    def test_a_viewers_free_cells_are_not_links(self, viewer, base_url):
        viewer.goto(f"{base_url}/ipmap")
        expect(viewer.locator(".ip-cell.ip-free").first).to_be_visible()
        assert viewer.locator("a.ip-cell").count() == 0
        assert viewer.locator("#ipmap-how").count() == 0


class TestTheHealthFold:
    def test_what_fails_or_warns_is_drawn_before_what_passes(self, admin, base_url):
        admin.goto(f"{base_url}/health-center")
        statuses = admin.eval_on_selector_all(
            "#health-results .hc-row", "rows => rows.filter(r => !r.closest('details')).map(r => r.dataset.status)"
        )
        rank = {"fail": 0, "warn": 1, "ok": 2}
        assert statuses and "skip" not in statuses
        assert [rank[s] for s in statuses] == sorted(rank[s] for s in statuses), statuses

    def test_the_skipped_checks_open_from_one_line_and_stay_open_across_a_refresh(self, admin, base_url):
        admin.goto(f"{base_url}/health-center")
        fold = admin.locator("#hc-skipped")
        expect(fold).to_have_count(1)
        skipped = fold.locator(".hc-row")
        n = skipped.count()
        assert n >= 1
        summary = fold.locator("summary")
        noun = "check was" if n == 1 else "checks were"
        expect(summary).to_have_text(f"{n} {noun} skipped (not applicable to this install)")
        assert admin.evaluate("document.getElementById('hc-skipped').open") is False
        expect(skipped.first).to_be_hidden()
        summary.click()
        expect(skipped.first).to_be_visible()
        # the results are swapped (Refresh here; the page does the same every minute): the fold a person opened is open in what was swapped in
        admin.evaluate("document.getElementById('hc-skipped').dataset.before = '1'")
        with admin.expect_response(lambda r: "/health-center/data" in r.url):
            admin.get_by_role("button", name="Refresh").click()
        admin.wait_for_function(
            "() => { const f = document.getElementById('hc-skipped'); return f && !f.dataset.before; }"
        )
        admin.wait_for_function("() => document.getElementById('hc-skipped').open === true")
        expect(admin.locator("#hc-skipped .hc-row").first).to_be_visible()

    def test_the_fold_is_opened_from_the_keyboard(self, admin, base_url):
        admin.goto(f"{base_url}/health-center")
        admin.locator("#hc-skipped summary").focus()
        admin.keyboard.press("Enter")
        admin.wait_for_function("() => document.getElementById('hc-skipped').open === true")


LINES = [
    {"kind": "server", "level": "fail", "text": "Kea server kea-b is not reachable", "url": "/servers"},
    {
        "kind": "health",
        "level": "fail",
        "text": "Jen database: could not <b>connect</b>",
        "url": "/health-center#check-db_jen",
    },
    {
        "kind": "pool",
        "level": "warn",
        "text": "Office (10.99.0.0/24): 85% of the pool is in use",
        "url": "/leases?subnet=1",
    },
]


def _answer_attention(page, lines, asked):
    """Answer the dashboard's request for the card with `lines`; every other widget of the same request answers as "nothing to show"."""

    def handle(route):
        names = route.request.url.split("widgets=")[1].split("&")[0].split(",")
        asked.append(names)
        if "attention" not in names:
            route.continue_()
            return
        body = dict.fromkeys(names)
        body["attention"] = lines
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    page.route("**/api/dashboard/catalog-data?**", handle)


class TestNeedsAttentionOnTheDashboard:
    def test_the_card_is_drawn_first_with_one_link_a_line(self, admin, base_url):
        asked = []
        _answer_attention(admin, LINES, asked)
        try:
            admin.goto(f"{base_url}/")
            card = admin.locator("#attention-card")
            expect(card).to_be_visible()
            links = card.locator(".attention-line a")
            expect(links).to_have_count(3)
            assert [links.nth(i).get_attribute("href") for i in range(3)] == [line["url"] for line in LINES]
            # a line is text: markup in a check's detail is shown, never run
            expect(links.nth(1)).to_have_text("Jen database: could not <b>connect</b>")
            assert card.locator(".attention-line b").count() == 0
            # the first card of the page, above the subnet cards
            top = card.bounding_box()["y"]
            assert top < admin.locator("#dash-widgets").bounding_box()["y"]
            assert "attention-fail" in card.get_attribute("class")
            # one request carried the card
            assert sum(1 for names in asked if "attention" in names) == 1
        finally:
            admin.unroute("**/api/dashboard/catalog-data?**")

    def test_with_nothing_to_say_the_card_is_not_drawn(self, admin, base_url):
        asked = []
        _answer_attention(admin, [], asked)
        try:
            with admin.expect_response(lambda r: "catalog-data" in r.url and "attention" in r.url):
                admin.goto(f"{base_url}/")
            admin.wait_for_timeout(300)  # the answer has arrived; give the page the turn in which it would draw
            assert asked, "the page asked for the card"
            expect(admin.locator("#attention-card")).to_be_hidden()
        finally:
            admin.unroute("**/api/dashboard/catalog-data?**")

    def test_the_card_shows_what_the_server_really_answers(self, admin, base_url):
        answer = admin.request.get(f"{base_url}/api/dashboard/catalog-data?widgets=attention")
        assert answer.ok
        lines = answer.json()["attention"]
        with admin.expect_response(lambda r: "catalog-data" in r.url and "attention" in r.url):
            admin.goto(f"{base_url}/")
        card = admin.locator("#attention-card")
        if lines:
            expect(card).to_be_visible()
            expect(card.locator(".attention-line")).to_have_count(len(lines))
        else:
            expect(card).to_be_hidden()
