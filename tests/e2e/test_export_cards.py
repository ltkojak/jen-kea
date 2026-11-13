"""
tests/e2e/test_export_cards.py
──────────────────────────────
v7.1.0-beta.2 (Q234, AR1, AR2, AR4) - Settings → Databases → Export in a real browser.

The two cards are one control since 7.1.0-beta.1, and nothing executed it: the script was pinned as two substrings of the template and the route as a string. Here the boxes
are ticked the way a person ticks them and the buttons are pressed.

  * an All box follows its boxes on both cards, and on the migration page (AR2);
  * nothing ticked is refused on BOTH cards with its own sentence (AR1): on the Jen card it used to export every table.
"""

import pytest

pytestmark = pytest.mark.e2e

EVERY_BOX_TICKED = "(id) => !document.getElementById(id).querySelector('input[type=checkbox]:not(:checked)')"
ANY_BOX_TICKED = "(id) => !!document.getElementById(id).querySelector('input[type=checkbox]:checked')"


def _all_box(page, group):
    return page.locator(f'input.toggle-all-cb[data-toggle-group="{group}"]')


def _follows(page, group):
    all_box = _all_box(page, group)
    first = page.locator(f"#{group} input[type=checkbox]").first
    all_box.check()
    assert page.evaluate(EVERY_BOX_TICKED, group) is True
    first.uncheck()
    assert all_box.is_checked() is False
    first.check()
    assert all_box.is_checked() is True
    all_box.uncheck()
    assert page.evaluate(ANY_BOX_TICKED, group) is False


class TestTheExportCards:
    @pytest.mark.parametrize("group", ["jen-tables", "kea-tables"])
    def test_an_all_box_follows_its_boxes(self, logged_in_page, base_url, group):
        page = logged_in_page
        page.goto(f"{base_url}/database?tab=export")
        _follows(page, group)

    def test_the_kea_card_opens_with_the_reservation_tables_ticked_and_leases_not(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/database?tab=export")
        ticked = page.evaluate(
            "() => Array.from(document.querySelectorAll('#kea-tables input[name=tables]:checked')).map(b => b.value)"
        )
        assert ticked == ["hosts", "dhcp4_options", "dhcp6_options", "ipv6_reservations"]
        assert _all_box(page, "kea-tables").is_checked() is False

    @pytest.mark.parametrize(
        "card,group,words",
        [
            ("jen", "jen-tables", "Tick at least one Jen table to export."),
            ("kea", "kea-tables", "Tick at least one Kea table to export."),
        ],
    )
    def test_nothing_ticked_is_refused_with_the_cards_own_sentence(self, logged_in_page, base_url, card, group, words):
        page = logged_in_page
        page.goto(f"{base_url}/database?tab=export")
        all_box = _all_box(page, group)
        all_box.check()
        all_box.uncheck()
        assert page.evaluate(ANY_BOX_TICKED, group) is False
        with page.expect_navigation(timeout=30000):
            page.locator(f'form[action="/database/export/{card}"] button[type=submit]').click()
        assert words in page.content()


class TestTheMigrationPage:
    def test_its_all_box_follows_its_boxes_too(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/database/migrate")
        page.locator("#card-jen").click()  # the table boxes are shown once the Jen database is chosen
        page.wait_for_selector("#jen-options", state="visible")
        _follows(page, "jen-mig-tables")
