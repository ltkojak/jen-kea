"""
tests/e2e/test_subnet_and_class_journeys.py
──────────────────────────────────────────────
v5.39.0 (Q40) step 2/2 — subnet edit -> preview -> apply, and the
client-class builder's live expression preview. Both preview flows
skip SSH validation entirely when no configured server has an
ssh_host (the harness's default) rather than erroring, so these
journeys exercise the real preview round trip without needing to fake
an SSH helper.
"""

import re

import pytest

pytestmark = pytest.mark.e2e


class TestSubnetEditPreviewApply:
    def test_edit_preview_and_apply_with_no_ssh_configured(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/subnets/edit/1")
        # Genuinely different from the fake Kea server's existing value
        # for this subnet (10.99.0.1, tests/e2e/_fake_kea_server.py) —
        # the page's own JS does a client-side diff against the
        # page-load value before ever calling the preview endpoint, and
        # skips the round trip entirely when nothing actually changed.
        page.fill("#f-routers", "10.99.0.254")
        page.click("#show-confirm-btn")
        page.wait_for_selector("#confirm-panel", state="visible", timeout=10000)
        # Not wait_for_function() — Jen's CSP has no 'unsafe-eval', so
        # Playwright can't evaluate a JS-string predicate in the page.
        # Playwright's own :has-text()/attribute selectors don't need
        # page-context eval at all.
        # (Q218 BH6 g, AC26) a fleet with no write target - this server has no SSH host and is not on Live API - has nothing to validate against and nothing to apply to: the preview says why
        # and Apply stays disabled (it used to read "all of none passed" and offered a change that no server would take)
        page.wait_for_selector("#validation-summary:has-text('no server takes this change')", timeout=10000)
        assert page.locator("#apply-btn").is_disabled()


class TestClassBuilderLivePreview:
    def test_adding_a_rule_updates_the_expression_preview(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/subnets/classes/new")
        page.fill('input[name="name"]', "e2e-test-class")

        # The page's own JS already adds one empty rule row on load
        # (dhcp_class_edit.html: "if (initialRules.length) {...} else
        # { addRow(); }" for a brand-new class) — clicking #add-rule-btn
        # here would add a *second*, still-empty row, and
        # build_expression() rejects any rule with an empty value, which
        # renders the error branch instead of the expression preview.
        row = page.locator(".jen-rule-row").first
        # Fill the value first, then change the select last — htmx's
        # trigger here is "change, keyup delay:500ms changed", and a
        # select's change event fires immediately (no debounce), so
        # whichever happens last is the one whose POST actually reflects
        # both fields.
        row.locator('input[name="rule_value"]').fill("PXEClient")
        row.locator('select[name="rule_field"]').select_option("vendor_class")

        page.wait_for_selector("#class-preview:has-text('PXEClient')", timeout=10000)


class TestPickABadgeTone:
    """Q205 (AU1 d/e): pick green on the card; the Leases page's badge for the same subnet carries `badge-tone-green` (the tone is chosen per subnet, by id)."""

    def test_pick_green_on_the_card_and_see_it_on_the_leases_page(self, logged_in_page, base_url):
        from playwright.sync_api import expect

        from tests.e2e.test_core_journeys import _seed_active_lease

        _seed_active_lease(mac_hex="AABBCCDDEE61", ip="10.99.0.61", hostname="e2e-badge-host")
        page = logged_in_page
        page.goto(f"{base_url}/subnets")
        btn = page.locator('.tone-btn[data-subnet-id="1"]')
        btn.click()
        menu = page.locator('.tone-picker:has(.tone-btn[data-subnet-id="1"]) .tone-menu')
        expect(menu).to_be_visible()
        assert menu.locator(".tone-choice").count() == 7, "seven swatches, each carrying the subnet's own name"
        menu.locator('.tone-choice[data-tone="green"]').click()
        expect(btn).to_have_class(re.compile(r"badge-tone-green"))
        expect(menu).to_be_hidden()

        page.goto(f"{base_url}/leases")
        row = page.locator("tr", has_text="e2e-badge-host").first
        expect(row.locator(".badge-tone-green")).to_have_count(1)

    def test_escape_closes_the_row_of_swatches(self, logged_in_page, base_url):
        from playwright.sync_api import expect

        page = logged_in_page
        page.goto(f"{base_url}/subnets")
        page.locator('.tone-btn[data-subnet-id="1"]').click()
        menu = page.locator('.tone-picker:has(.tone-btn[data-subnet-id="1"]) .tone-menu')
        expect(menu).to_be_visible()
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
