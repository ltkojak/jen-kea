"""
tests/e2e/test_q252_c.py
────────────────────────
Q252 (Jen 7.2.1) - three things only a browser shows:

  * the question the Edit User dialog asks before it links an account to single sign-on says, for an account restricted to some subnets, what its first
    sign-in does to that restriction - and says nothing more than before for an account with every subnet;
  * every hint Health prints under a row's detail is a sentence, at a phone's width and a desk's (a hint written as a link's label read "Settings → Kea");
  * on the Kea logging card a radio and its label's text are one row at every width: at 390 px the two long labels wrapped under their radio.
"""

import pymysql
import pymysql.cursors
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.test_q249_a import (
    logging_primary,  # noqa: F401  (the Kea logging card's world: a stateful fake Kea and its host)
)

pytestmark = pytest.mark.e2e

RESTRICTED = "q252_e2e_some"
EVERY = "q252_e2e_all"
QUESTION = "Link this account to SSO? Local username/password login will be disabled for it immediately."
SAYS = (
    "This account is restricted to some subnets now. After it signs in through the identity provider it gets the subnets its groups map to under "
    "Settings → Access & Security → Single Sign-On → Subnet Mapping, and every subnet when no mapping is set."
)


def _wipe(cur):
    cur.execute("DELETE FROM users WHERE username IN (%s, %s)", (RESTRICTED, EVERY))


@pytest.fixture
def accounts():
    from jen.models.user import hash_password

    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with conn.cursor() as cur:
            _wipe(cur)
            for name, scope in ((RESTRICTED, "[1]"), (EVERY, None)):
                cur.execute(
                    "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, 'admin', %s, 0)",
                    (name, hash_password("q252-Not-used-1"), scope),
                )
        yield conn
    finally:
        with conn.cursor() as cur:
            _wipe(cur)
        conn.close()


def _asked(page, username):
    """Open Edit User for `username`, press Link to SSO, read the question, and cancel it."""
    page.locator("tr", has_text=username).locator(".edit-user-btn").click()
    expect(page.locator("#edit-username-label")).to_have_text(username)
    page.locator("#link-sso-form button[type=submit]").click()
    message = page.locator("#jen-confirm-message")
    expect(message).to_be_visible()
    text = message.inner_text()
    page.locator("#jen-confirm-cancel").click()
    expect(page.locator("#jen-confirm-overlay")).to_be_hidden()
    page.keyboard.press("Escape")
    expect(page.locator("#edit-modal")).to_be_hidden()
    return text


class TestTheLinksQuestion:
    def test_a_restricted_account_is_asked_with_the_sentence_and_one_with_every_subnet_without(
        self, logged_in_page, base_url, accounts
    ):
        page = logged_in_page
        page.set_viewport_size({"width": 1440, "height": 900})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"{base_url}/settings/users")
        assert _asked(page, RESTRICTED) == QUESTION + " " + SAYS
        assert _asked(page, EVERY) == QUESTION, "the sentence does not stay on the form from the account before"
        assert _asked(page, RESTRICTED) == QUESTION + " " + SAYS
        with accounts.cursor() as cur:
            cur.execute("SELECT username, auth_provider FROM users WHERE username IN (%s, %s)", (RESTRICTED, EVERY))
            assert {r["auth_provider"] for r in cur.fetchall()} == {"local"}, "a canceled question links nothing"
        assert not errors, errors


class TestHealthsHintsAreSentences:
    @pytest.mark.parametrize("width", [390, 1440])
    def test_no_hint_is_shorter_than_four_words(self, logged_in_page, base_url, width):
        page = logged_in_page
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{base_url}/health-center")
        page.wait_for_selector(".hc-row")
        hints = page.evaluate(
            "() => [...document.querySelectorAll('.hc-hint')].map(h => ({row: h.closest('.hc-row').getAttribute('data-check'), text: h.innerText.trim()}))"
        )
        assert hints, "Health shows at least one hint line in this world (the readiness rows warn)"
        short = [h for h in hints if len(h["text"].split()) < 4 or not h["text"].endswith(".")]
        assert short == [], short


# For each radio of the card: its own box, the box of the FIRST line of its label's text and the left edge of every line of that text.
RADIOS = """() => [...document.querySelectorAll('#kea-logging-1 .wm-mode-label')].map(label => {
    const radio = label.querySelector('input[type=radio]').getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(label.querySelector('strong'));
    const lines = [...range.getClientRects()];
    const card = document.getElementById('kea-logging-1').getBoundingClientRect();
    return {value: label.querySelector('input').value, radio_top: radio.top, radio_left: radio.left, radio_right: radio.right, radio_width: radio.width,
            first_top: lines[0].top, first_left: lines[0].left, lines: new Set(lines.map(r => Math.round(r.top))).size,
            leftmost: Math.min(...lines.map(r => r.left)), rightmost: Math.max(...lines.map(r => r.right)), card_right: card.right};
})"""


class TestARadioAndItsLabelAreOneRow:
    def _card(self, page, base_url, width):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{base_url}/settings/kea")
        if "collapsed" in (page.get_attribute("#kea-logging", "class") or ""):
            page.click(
                "#kea-logging > .card-header"
            )  # on a phone every card of the page but the first is folded: its header opens it
        page.locator("#kea-logging-1").scroll_into_view_if_needed()
        rows = page.evaluate(RADIOS)
        assert [r["value"] for r in rows] == ["journal", "file", "both"]
        return rows

    @pytest.mark.parametrize("width", [390, 1440])
    def test_the_radio_stands_beside_the_first_line_of_its_text(self, logged_in_page, base_url, logging_primary, width):  # noqa: F811
        rows = self._card(logged_in_page, base_url, width)
        for r in rows:
            assert abs(r["radio_top"] - r["first_top"]) <= 6, r
            assert r["radio_right"] <= r["first_left"] + 0.5, r
            assert r["leftmost"] >= r["radio_right"] - 0.5, ("a wrapped line runs under the radio", r)
            assert r["rightmost"] <= r["card_right"] + 0.5, ("the text leaves the card", r)
            assert r["radio_width"] >= 12, ("the radio was squeezed", r)
        if width == 390:
            assert max(r["lines"] for r in rows) >= 2, (
                "at a phone's width a long label wraps: the row this test is about"
            )
