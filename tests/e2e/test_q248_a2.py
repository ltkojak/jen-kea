"""
tests/e2e/test_q248_a2.py
─────────────────────────
Q248, stage a2 - layout that breaks, measured in a real browser with the CSP on, against the live server.

* V10, V37  the top row at 1024, 1100, 1280 and 1440 px, with no favorite and with three: no two of its elements intersect, nothing is cut off, About is
            reachable, and at 1440 px three favorites keep their names.
* V11       nothing of a tab shows in the 24 px to the right of the pin button, wherever the strip is scrolled to; a scrolled strip is marked at its left edge.
* V14, addition 9, V16 - the setup wizard: the install command scrolls inside its box and the page does not; Back, Next and Finish; step 6 on a phone.
* V15       the API key form: Key Name and Subnet Access start level, the button is under the fields at the left; a phone stacks it.
* V16       MFA enrollment, the API documentation and the migration wizard at 390 px.
* V17       Packet Health's server name is one line.
* V47       the 404 page signed in and signed out.
* V48       no placeholder is wider than its field at 390 px on the pages the look-over measured.
* V55       the More sheet's Close button and where its focus lands, a collapsed card, stacked buttons, the forced password change card.
* V4 (left over) - the sign-in pages' buttons: the text is 4.5:1 or better against the lightest stop of the fill.
* addition 10 - a Copy button copies and says so on the button; addition 14 - search on the phone's top bar, "Find a setting" on the Settings hub.
"""

import re

import pymysql
import pymysql.cursors
import pyotp
import pytest
from playwright.sync_api import expect

from tests.conftest import TEST_DB
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

PHONE = {"width": 390, "height": 844}
LEASE_MAC = "AABBCC248A31"
LEASE_IP = "10.99.0.131"
FORCED_USER = "q248_a2_forced"
MFA_USER = "q248_a2_mfa"
USER_PASSWORD = "q248-A2-Pw!long1"


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


def _sql(statement, args=()):
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(statement, args)
            return cur.fetchall()
    finally:
        conn.close()


def _at(page, base_url, width, height=900):
    """Sign in as the superadmin at this width, with every script error collected."""
    page.set_viewport_size({"width": width, "height": height})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    return errors


def _no_sideways_scroll(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


@pytest.fixture
def clean_nav():
    _sql("DELETE FROM user_nav")
    yield
    _sql("DELETE FROM user_nav")


@pytest.fixture
def wizard_state():
    """The wizard's stored state, put back as it was found (the live server runs in this process and reads the same settings)."""
    from jen.models.user import get_global_setting, set_global_setting
    from jen.services import setup_wizard

    keys = (setup_wizard._STATE_KEY, setup_wizard._COMPLETED_KEY)
    before = {k: get_global_setting(k, "") for k in keys}
    yield
    for k, v in before.items():
        set_global_setting(k, v)


@pytest.fixture
def lease():
    _sql("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (LEASE_MAC,))
    _sql(
        "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
        "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 'q248-a2-phone-row', 0)",
        (LEASE_IP, LEASE_MAC),
    )
    yield
    _sql("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (LEASE_MAC,))


def _user(username, must_change):
    from jen.models.user import hash_password

    _sql("DELETE FROM users WHERE username=%s", (username,))
    _sql(
        "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'superadmin', %s)",
        (username, hash_password(USER_PASSWORD), must_change),
    )


# ───────────────────────────── V10, V37: the top row ─────────────────────────────

TOP_ROW = """() => {
    const nav = document.querySelector('nav.nav');
    const links = nav.querySelector('.nav-links');
    const shown = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden'; };
    const items = [];
    const add = (e, name) => { if (e && shown(e)) { const r = e.getBoundingClientRect(); items.push({name: name, l: r.left, r: r.right, t: r.top, b: r.bottom, inLinks: links.contains(e)}); } };
    add(nav.querySelector('.nav-brand'), 'brand');
    links.querySelectorAll(':scope > *').forEach(e => add(e, 'link ' + (e.textContent.trim() || e.getAttribute('title') || e.className)));
    nav.querySelectorAll('.nav-right > *').forEach(e => add(e, 'right ' + (e.id || e.className)));
    add(nav.querySelector('.nav-kb'), 'keyboard button');
    add(nav.querySelector('.nav-search'), 'search');
    const crossings = [];
    for (let i = 0; i < items.length; i++) for (let j = i + 1; j < items.length; j++) {
        const a = items[i], b = items[j];
        if (Math.min(a.r, b.r) - Math.max(a.l, b.l) > 0.5 && Math.min(a.b, b.b) - Math.max(a.t, b.t) > 0.5) crossings.push(a.name + ' / ' + b.name);
    }
    const box = links.getBoundingClientRect();
    const cut = items.filter(i => (i.inLinks && (i.r > box.right + 0.5 || i.l < box.left - 0.5)) || i.r > window.innerWidth + 0.5).map(i => i.name);
    const about = nav.querySelector('.nav-links a[href="/about"]');
    const labels = Array.from(nav.querySelectorAll('.nav-fav-label'));
    return {
        crossings: crossings, cut: cut, spill: links.scrollWidth - links.clientWidth,
        fit: nav.getAttribute('data-fit'), aboutInRow: !!about && shown(about),
        names: labels.filter(shown).map(e => e.textContent.trim()),
        favorites: nav.querySelectorAll('.nav-links .nav-fav').length,
        count: items.length,
    };
}"""


class TestTheTopRowFits:
    def _pin_three(self, page, base_url):
        page.set_viewport_size({"width": 1680, "height": 900})
        for path in ("/reports", "/health-center", "/devices"):
            page.goto(f"{base_url}{path}")
            button = page.locator(".section-pin-btn")
            expect(button).to_have_text("Add to top row")
            button.click()
            page.wait_for_url(f"{base_url}{path}")
        expect(page.locator(".nav-links .nav-fav")).to_have_count(3)

    @pytest.mark.parametrize("favorites", [0, 3])
    @pytest.mark.parametrize("width", [1024, 1100, 1280, 1440])
    def test_nothing_overlaps_nothing_is_cut_and_about_is_reachable(self, page, base_url, clean_nav, width, favorites):
        errors = _at(page, base_url, 1680)
        if favorites:
            self._pin_three(page, base_url)
        page.set_viewport_size({"width": width, "height": 900})
        for path in ("/leases", "/about"):
            page.goto(f"{base_url}{path}")
            page.evaluate("() => document.fonts.ready.then(() => true)")
            row = page.evaluate(TOP_ROW)
            assert row["count"] >= 8 and row["favorites"] == favorites, row
            assert row["crossings"] == [], (width, favorites, path, row)
            assert row["cut"] == [] and row["spill"] <= 1, (width, favorites, path, row)
            assert _no_sideways_scroll(page)
            # About: in the row, or the row gave it up and it is in the Account menu (where it always is)
            assert row["aboutInRow"] or int(row["fit"]) >= 2, row
            page.locator("label[for=dd-avatar]").click()
            item = page.locator('#dd-avatar-menu a[href="/about"]')
            expect(item).to_be_visible()
            item.click()
            page.wait_for_url(f"{base_url}/about")
        if favorites and width == 1440:
            assert row["names"] == ["Reports", "Health", "Devices"] and row["fit"] == "0", row
        assert not errors, errors

    def test_the_levels_come_in_order_as_the_window_narrows(self, page, base_url, clean_nav):
        """Resizing the window refits the row (the ResizeObserver): names first, then About, then the pill's words - and widening gives them back."""
        errors = _at(page, base_url, 1680)
        self._pin_three(page, base_url)
        page.goto(f"{base_url}/leases")
        seen = []
        for width in (1680, 1440, 1280, 1100, 1024, 1680):
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_function("w => window.innerWidth === w", arg=width)
            page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
            row = page.evaluate(TOP_ROW)
            assert row["crossings"] == [] and row["cut"] == [], (width, row)
            seen.append(int(row["fit"]))
        assert seen[0] == 0 and seen[-1] == 0, seen
        assert seen[:5] == sorted(seen[:5]) and seen[4] >= 2, seen
        assert not errors, errors

    def test_a_favorite_without_its_word_still_says_its_name(self, page, base_url, clean_nav):
        _at(page, base_url, 1680)
        self._pin_three(page, base_url)
        page.set_viewport_size({"width": 1024, "height": 900})
        page.goto(f"{base_url}/leases")
        favorite = page.locator(".nav-links .nav-fav").first
        expect(favorite.locator(".nav-fav-label")).to_be_hidden()
        expect(favorite).to_have_attribute("aria-label", "Reports")
        expect(favorite).to_have_attribute("title", "Reports")

    def test_the_pill_and_the_keyboard_button_are_24_px_tall(self, page, base_url):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases")
        for selector in (".gs-pill", "#kb-hint-btn"):
            if page.locator(selector).count():
                box = page.locator(selector).bounding_box()
                assert box["height"] >= 24 and box["width"] >= 24, (selector, box)
        assert page.locator("#kb-hint-btn").count() == 1

    def test_a_pin_says_what_it_did(self, page, base_url, clean_nav):
        _at(page, base_url, 1680)
        page.goto(f"{base_url}/reports")
        page.locator(".section-pin-btn").click()
        expect(page.locator(".alert-success")).to_contain_text("Added Reports to the top row.")
        page.locator(".section-pin-btn").click()
        expect(page.locator(".alert-success")).to_contain_text("Removed Reports from the top row.")


# ───────────────────────────── V11: the pin block and the strip ─────────────────────────────

RIGHT_OF_THE_PIN = """() => {
    const strip = document.querySelector('.section-tabs');
    const button = document.querySelector('.section-pin-btn');
    const block = document.querySelector('.section-pin');
    const max = strip.scrollWidth - strip.clientWidth;
    const bad = [];
    let gap = 0;
    for (let left = 0; left <= max + 6; left += 6) {
        strip.scrollLeft = Math.min(left, max);
        const r = button.getBoundingClientRect();
        const y = r.top + r.height / 2;
        for (let dx = 1; dx <= 24; dx++) {
            const x = r.right + dx;
            if (x >= window.innerWidth) break;
            const el = document.elementFromPoint(x, y);
            if (el && el.closest('.section-tab')) bad.push([strip.scrollLeft, dx, el.textContent.trim()]);
        }
        gap = Math.max(gap, strip.getBoundingClientRect().right - block.getBoundingClientRect().right);
    }
    strip.scrollLeft = 0;
    return {max: max, bad: bad.slice(0, 6), gap: gap};
}"""


class TestThePinBlockAndTheStrip:
    @pytest.mark.parametrize("path", ["/health-center", "/ddns", "/servers"])
    @pytest.mark.parametrize("width", [1440, 1024])
    def test_no_letter_of_a_tab_shows_to_the_right_of_the_pin_button(self, page, base_url, width, path):
        errors = _at(page, base_url, width)
        page.goto(f"{base_url}{path}")
        found = page.evaluate(RIGHT_OF_THE_PIN)
        if width == 1024:
            assert found["max"] > 0, (
                "the Network strip fits a 1024 px window now, so this test no longer looks at a strip that scrolls"
            )
        assert found["bad"] == [], (width, path, found)
        assert found["gap"] < 1, f"the pin block stops {found['gap']} px short of the strip's right edge"
        assert not errors, errors

    def test_a_scrolled_strip_is_marked_at_its_left_edge(self, page, base_url):
        _at(page, base_url, 1024)
        page.goto(f"{base_url}/subnets")
        wrap = page.locator(".section-tabs-wrap")
        fade = "() => getComputedStyle(document.querySelector('.section-tabs-wrap'), '::before').opacity"
        page.evaluate("document.querySelector('.section-tabs').scrollLeft = 0")
        page.wait_for_function("() => !document.querySelector('.section-tabs-wrap').classList.contains('is-scrolled')")
        page.wait_for_function(
            "() => getComputedStyle(document.querySelector('.section-tabs-wrap'), '::before').opacity === '0'"
        )
        page.evaluate("document.querySelector('.section-tabs').scrollLeft = 80")
        expect(wrap).to_have_class(re.compile(r"\bis-scrolled\b"))
        page.wait_for_function(
            "() => getComputedStyle(document.querySelector('.section-tabs-wrap'), '::before').opacity === '1'"
        )
        assert page.evaluate(fade) == "1"
        assert (
            page.evaluate("() => getComputedStyle(document.querySelector('.section-tabs-wrap'), '::before').left")
            == "0px"
        )


# ───────────────────────────── V14, V16, addition 9: the setup wizard ─────────────────────────────


class TestTheSetupWizard:
    @pytest.mark.parametrize("width", [1440, 1024, 390])
    def test_the_install_command_scrolls_inside_its_box_and_the_page_does_not(
        self, page, base_url, wizard_state, width
    ):
        errors = _at(page, base_url, width)
        page.goto(f"{base_url}/setup/helper")
        assert _no_sideways_scroll(page), "the page scrolls sideways"
        box = page.evaluate(
            """() => {
                const pre = document.getElementById('helper-command');
                const card = pre.closest('.card').getBoundingClientRect();
                const r = pre.getBoundingClientRect();
                const s = getComputedStyle(pre);
                return {inside: r.right <= card.right + 0.5 && r.left >= card.left - 0.5, scrolls: pre.scrollWidth > pre.clientWidth + 100,
                        oneLine: s.whiteSpace === 'pre', overflowX: s.overflowX, lines: pre.textContent.trim().split('\\n').length};
            }"""
        )
        assert box == {"inside": True, "scrolls": True, "oneLine": True, "overflowX": "auto", "lines": 1}, box
        button = page.locator('[data-copy-target="helper-command"]')
        expect(button).to_be_visible()
        assert button.bounding_box()["height"] >= 24
        assert not errors, errors

    def test_the_cards_headings_and_bullets(self, page, base_url, wizard_state):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/setup/helper")
        gaps = page.evaluate(
            """() => Array.from(document.querySelectorAll('.setup-card h3, .setup-card h4')).filter(h => h.previousElementSibling)
                .map(h => Math.round(h.getBoundingClientRect().top - h.previousElementSibling.getBoundingClientRect().bottom))"""
        )
        assert len(gaps) >= 2 and min(gaps) >= 16, gaps
        page.goto(f"{base_url}/setup/found")
        lists = page.evaluate(
            """() => Array.from(document.querySelectorAll('.setup-card ul')).map(ul => {
                const card = ul.closest('.card'); const pad = parseFloat(getComputedStyle(card).paddingLeft);
                return {inside: ul.getBoundingClientRect().left >= card.getBoundingClientRect().left + pad - 0.5, indent: parseFloat(getComputedStyle(ul).paddingLeft)};
            })"""
        )
        assert lists and all(item["inside"] and item["indent"] >= 18 for item in lists), lists

    def test_back_next_and_finish(self, page, base_url, wizard_state):
        errors = _at(page, base_url, 1440)
        page.goto(f"{base_url}/setup/connect")
        foot = page.locator(".setup-nav")
        expect(foot.get_by_role("link", name="Back")).to_have_count(0)
        foot.get_by_role("link", name="Next").click()
        page.wait_for_url(f"{base_url}/setup/found")
        page.locator(".setup-nav").get_by_role("link", name="Back").click()
        page.wait_for_url(f"{base_url}/setup/connect")
        for step in ("helper", "baseline", "recovery"):
            page.goto(f"{base_url}/setup/{step}")
            expect(page.locator(".setup-nav").get_by_role("link", name="Back")).to_be_visible()
            expect(page.locator(".setup-nav").get_by_role("link", name="Next")).to_be_visible()
            expect(page.locator(".u-setup-progress [aria-current=step]")).to_contain_text(step.capitalize())
        page.goto(f"{base_url}/setup/investigate")
        foot = page.locator(".setup-nav")
        expect(foot.get_by_role("link", name="Next")).to_have_count(0)
        expect(foot.get_by_role("link", name="Back")).to_be_visible()
        foot.get_by_role("button", name="Finish", exact=True).click()
        page.wait_for_url(f"{base_url}/")
        expect(page.locator("h1").first).to_contain_text("Dashboard")
        # the step the Finish button belongs to is ticked now, because the wizard's own state says done
        page.goto(f"{base_url}/setup/investigate")
        expect(page.locator(".u-setup-progress [data-step-state=done] svg")).not_to_have_count(0)
        assert not errors, errors

    def test_step_six_on_a_phone_keeps_investigate_in_reach(self, page, base_url, wizard_state, lease):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/setup/investigate")
        assert _no_sideways_scroll(page)
        row = page.locator("table.rowlist tbody tr", has_text=LEASE_IP)
        button = row.get_by_role("button", name="Investigate")
        box = button.bounding_box()
        assert box is not None and box["x"] >= 0 and box["x"] + box["width"] <= PHONE["width"], box
        card = page.locator(".setup-card").bounding_box()
        assert box["x"] + box["width"] <= card["x"] + card["width"] + 0.5, (box, card)
        assert row.evaluate("e => getComputedStyle(e).display") == "flex", "the phone's row pattern, not a table row"
        button.click()
        page.wait_for_url(re.compile(r"/client\?q="))
        assert not errors, errors


# ───────────────────────────── V15: the API key form ─────────────────────────────

API_KEY_FORM = """() => {
    const top = s => Math.round(document.querySelector(s).getBoundingClientRect().top);
    const box = s => document.querySelector(s).getBoundingClientRect();
    const name = box('#f-name'), list = box('#f-subnet_ids'), button = box('.apikey-submit'), write = box('input[name=can_write]');
    return {
        nameLabel: top('label[for=f-name]'), listLabel: top('#f-subnet_ids-label'),
        nameLeft: Math.round(name.left), buttonLeft: Math.round(button.left), buttonTop: button.top,
        listBottom: list.bottom, listLeft: list.left, nameRight: name.right, writeBottom: write.bottom, listTop: list.top,
    };
}"""


class TestTheApiKeyForm:
    @pytest.mark.parametrize("width", [1440, 1024])
    def test_the_fields_start_level_and_the_button_is_under_them_at_the_left(self, page, base_url, width):
        errors = _at(page, base_url, width)
        page.goto(f"{base_url}/settings/api-keys")
        m = page.evaluate(API_KEY_FORM)
        assert abs(m["nameLabel"] - m["listLabel"]) <= 1, m
        assert m["listLeft"] > m["nameRight"], "Subnet Access is the second column"
        assert abs(m["buttonLeft"] - m["nameLeft"]) <= 1 and m["buttonTop"] >= m["listBottom"], m
        assert _no_sideways_scroll(page)
        assert not errors, errors

    def test_a_phone_stacks_it(self, page, base_url):
        _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/settings/api-keys")
        m = page.evaluate(API_KEY_FORM)
        assert m["listTop"] > m["writeBottom"] and m["buttonTop"] >= m["listBottom"], m
        assert _no_sideways_scroll(page)


# ───────────────────────────── V16: phones ─────────────────────────────


class TestPhones:
    def test_mfa_enrollment_puts_the_code_above_the_form(self, page, base_url):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/mfa/enroll")
        m = page.evaluate(
            """() => {
                const qr = document.querySelector('.mfa-enroll-qr img').getBoundingClientRect();
                const code = document.getElementById('f-code').getBoundingClientRect();
                const name = document.getElementById('f-device_name').getBoundingClientRect();
                const secret = document.getElementById('totp-secret').getBoundingClientRect();
                return {qrBottom: qr.bottom, secretTop: secret.top, codeWidth: code.width, nameWidth: name.width};
            }"""
        )
        assert m["secretTop"] >= m["qrBottom"], m
        assert m["codeWidth"] >= 280 and m["nameWidth"] >= 280, m
        assert _no_sideways_scroll(page)
        assert not errors, errors

    def test_mfa_enrollment_is_side_by_side_on_a_desktop(self, page, base_url):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/mfa/enroll")
        assert page.evaluate(
            "() => document.getElementById('f-code').getBoundingClientRect().left > document.querySelector('.mfa-enroll-qr img').getBoundingClientRect().right"
        )

    def test_no_code_block_of_the_api_documentation_leaves_its_card(self, page, base_url):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/settings/api-docs")
        out = page.evaluate(
            """() => Array.from(document.querySelectorAll('pre.code-block')).filter(pre => {
                const card = pre.closest('.card').getBoundingClientRect();
                return pre.getBoundingClientRect().right > card.right + 0.5;
            }).map(pre => pre.id || pre.textContent.slice(0, 30))"""
        )
        assert out == [], out
        assert page.locator("pre.code-block").count() >= 10
        assert _no_sideways_scroll(page)
        assert not errors, errors

    def test_the_migration_wizard_keeps_each_table_name_on_one_line(self, page, base_url):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/settings/databases/migrate")
        if not page.locator("#jen-options").is_visible():
            page.locator("#radio-jen").check()
        expect(page.locator("#jen-options")).to_be_visible()
        names = page.evaluate(
            """() => Array.from(document.querySelectorAll('#jen-mig-tables label code')).map(c => ({
                name: c.textContent, lines: c.getClientRects().length,
                inside: c.getBoundingClientRect().right <= c.closest('.card').getBoundingClientRect().right + 0.5 }))"""
        )
        assert len(names) >= 15, names
        assert [n for n in names if n["lines"] != 1 or not n["inside"]] == [], names
        assert _no_sideways_scroll(page)
        assert not errors, errors


# ───────────────────────────── V17: Packet Health ─────────────────────────────


class TestPacketHealth:
    @pytest.mark.parametrize("width", [1440, 1024])
    def test_the_servers_name_is_one_line(self, page, base_url, width):
        """The widget's own row, written here the way dashboard.html's loadPacketHealth writes it (this dataset has no two snapshots to make one): the name
        was broken as "Kea Server" / "1" beside a long sentence of notes."""
        _at(page, base_url, width)
        page.goto(f"{base_url}/")
        page.wait_for_load_state(
            "networkidle"
        )  # the widgets have written what they have, so nothing rewrites the row below
        lines = page.evaluate(
            """() => {
                const widget = document.getElementById('dash-packet_health');
                widget.classList.remove('hidden');
                widget.querySelector('.dash-cat-body').innerHTML = '<table class="rowlist"><tbody><tr><td data-m="primary">Kea Server 1</td>' +
                    '<td data-m="secondary">drops + parse failures: 11.2% of received (10/89); NAKs: 1.1% of replies (1 NAK / 88 ACK); ' +
                    'allocation failures: 0.0% of requests; declines: 0.0% of requests; and a note long enough to need the whole card twice over</td></tr></tbody></table>';
                const cell = widget.querySelector('td[data-m=primary]');
                const range = document.createRange();
                range.selectNodeContents(cell);
                return new Set(Array.from(range.getClientRects()).map(r => Math.round(r.top))).size;
            }"""
        )
        assert lines == 1


# ───────────────────────────── V47: the 404 page ─────────────────────────────


class TestThe404Page:
    def test_signed_in_it_is_the_normal_page(self, page, base_url):
        errors = _at(page, base_url, 1440)
        response = page.goto(f"{base_url}/no-such-page-q248/here")
        assert response.status == 404
        expect(page.locator(".nav-links")).to_be_visible()
        expect(page.locator(".not-found h1")).to_have_text("Page not found")
        expect(page.locator(".not-found code")).to_have_text("/no-such-page-q248/here")
        assert page.evaluate("document.documentElement.dataset.theme") == page.evaluate(
            "jenThemeResolve(localStorage.getItem('jen-theme-pick'))"
        )
        page.locator(".not-found a.btn").click()
        page.wait_for_url(f"{base_url}/")
        assert not errors, errors

    @pytest.mark.parametrize("width", [1440, 390])
    def test_signed_out_it_is_the_sign_in_cards_shape(self, page, base_url, width):
        page.set_viewport_size({"width": width, "height": 844})
        page.goto(f"{base_url}/login")
        card = page.locator(".login-card").bounding_box()
        response = page.goto(f"{base_url}/no-such-page-q248/here")
        assert response.status == 404
        box = page.locator(".box").bounding_box()
        assert abs(box["width"] - card["width"]) <= 1 and abs(box["x"] - card["x"]) <= 1, (box, card)
        expect(page.locator(".box h1")).to_have_text("Page not found")
        expect(page.locator(".box .logo-img")).to_be_visible()
        expect(page.locator(".nav")).to_have_count(0)
        assert _no_sideways_scroll(page)
        page.get_by_role("link", name="Sign in").click()
        page.wait_for_url(re.compile(r"/login"))


# ───────────────────────────── V48: placeholders ─────────────────────────────

TIGHT_PLACEHOLDERS = """() => {
    const canvas = document.createElement('canvas').getContext('2d');
    // a textarea wraps its placeholder, so it is never cut; a placeholder that is a path under this install's own config directory is as long as the test tree's
    // path (/etc/jen/ssl/... on a real install), so it is not a sentence to shorten
    return Array.from(document.querySelectorAll('input[placeholder]')).filter(e => {
        const r = e.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && e.placeholder && e.placeholder.charAt(0) !== '/' &&
            !e.closest('.filter-bar') && !e.closest('.sheet') && !e.closest('.nav-search');
    }).map(e => {
        const s = getComputedStyle(e);
        canvas.font = s.fontStyle + ' ' + s.fontWeight + ' ' + s.fontSize + ' ' + s.fontFamily;
        const spacing = parseFloat(s.letterSpacing) || 0;
        const need = canvas.measureText(e.placeholder).width + spacing * e.placeholder.length;
        const room = e.clientWidth - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight);
        return {field: e.id || e.name, text: e.placeholder, need: Math.round(need), room: Math.round(room)};
    }).filter(m => m.need > m.room + 1);
}"""


class TestPlaceholdersFitAPhone:
    @pytest.mark.parametrize(
        "path",
        [
            "/reservations/add",
            "/settings/appearance",
            "/client",
            "/tools/explain",
            "/mfa/enroll",
            "/setup/connect",
            "/settings/api-keys",
        ],
    )
    def test_no_placeholder_is_wider_than_its_field(self, page, base_url, wizard_state, path):
        _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}{path}")
        assert page.evaluate(TIGHT_PLACEHOLDERS) == []


# ───────────────────────────── V55: the smaller ones ─────────────────────────────


class TestTheSmallerOnes:
    def test_the_more_sheet_opens_on_its_close_button_and_the_button_closes_it(self, page, base_url):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/leases")
        more = page.locator('.tabbar [data-sheet-open="more-sheet"]')
        more.click()
        sheet = page.locator("#more-sheet")
        expect(sheet).to_be_visible()
        close = sheet.locator(".sheet-close")
        expect(close).to_be_focused()
        expect(sheet.locator(".sheet-search input")).not_to_be_focused()
        expect(sheet.locator(".sheet-search input")).to_be_visible()
        assert close.bounding_box()["height"] >= 44
        close.click()
        expect(sheet).to_be_hidden()
        expect(more).to_be_focused()
        assert not errors, errors

    @pytest.mark.parametrize("path", ["/settings/kea", "/settings/appearance", "/settings/alerts", "/settings/system"])
    def test_a_collapsed_card_on_a_phone_shows_its_header_and_nothing_else(self, page, base_url, path):
        _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}{path}")
        cards = page.evaluate(
            """() => Array.from(document.querySelectorAll('.card[data-collapsible].collapsed')).map(card => {
                const header = card.querySelector(':scope > .card-header');
                const showing = Array.from(card.children).filter(c => c !== header && c.getClientRects().length > 0).length;
                const s = getComputedStyle(card);
                const frame = parseFloat(s.paddingTop) + parseFloat(s.paddingBottom) + parseFloat(s.borderTopWidth) + parseFloat(s.borderBottomWidth);
                return {id: card.id, showing: showing, extra: Math.round(card.getBoundingClientRect().height - header.getBoundingClientRect().height - frame)};
            })"""
        )
        assert len(cards) >= 2, cards
        assert [c for c in cards if c["showing"] or c["extra"] > 1] == [], cards

    def _gap(self, page, first, second):
        a, b = first.bounding_box(), second.bounding_box()
        assert a is not None and b is not None
        if b["y"] >= a["y"] + a["height"] - 0.5:
            return b["y"] - (a["y"] + a["height"])
        return b["x"] - (a["x"] + a["width"])

    def test_stacked_buttons_keep_a_gap(self, page, base_url):
        _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/settings/system")
        page.evaluate(
            "() => document.querySelectorAll('.card.collapsed').forEach(c => c.classList.remove('collapsed'))"
        )
        gap = self._gap(
            page,
            page.get_by_role("button", name="Download support bundle"),
            page.get_by_role("link", name="Report an issue"),
        )
        assert gap >= 7.5, gap
        page.goto(f"{base_url}/settings/kea")
        page.evaluate(
            "() => document.querySelectorAll('.card.collapsed').forEach(c => c.classList.remove('collapsed'))"
        )
        gap = self._gap(page, page.get_by_role("button", name="Save Kea API"), page.locator("#probe-kea-btn"))
        assert gap >= 7.5, gap
        gap = self._gap(page, page.locator("#probe-kea-btn"), page.locator("#probe-candidate-url"))
        assert gap >= 7.5, gap
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(f"{base_url}/settings/security")
        card = page.locator(".card", has=page.get_by_role("button", name="Clear All Lockouts"))
        gap = self._gap(
            page,
            card.get_by_role("button", name="Save Rate Limiting", exact=True),
            card.get_by_role("button", name="Clear All Lockouts"),
        )
        assert gap >= 7.5, gap

    def test_the_forced_password_change_card_is_the_sign_in_card(self, page, base_url):
        _user(FORCED_USER, 1)
        try:
            page.set_viewport_size({"width": 1440, "height": 900})
            page.goto(f"{base_url}/login")
            card = page.locator(".login-card").bounding_box()
            logo = page.locator(".logo-img").bounding_box()
            login(page, base_url, FORCED_USER, USER_PASSWORD, f"{base_url}/force-password-change")
            forced = page.locator(".card").bounding_box()
            forced_logo = page.locator(".logo-img").bounding_box()
            assert abs(forced["width"] - card["width"]) <= 1 and abs(forced["x"] - card["x"]) <= 1, (forced, card)
            assert abs(forced_logo["height"] - logo["height"]) <= 1, (forced_logo, logo)
            expect(page.locator("h1")).to_contain_text("Password Change Required")
            same = "e => { const s = getComputedStyle(e); return [s.backgroundColor, s.borderRadius, s.paddingLeft, s.paddingTop]; }"
            forced_style = page.locator(".card").evaluate(same)
            page.context.clear_cookies()
            page.goto(f"{base_url}/login")
            assert page.locator(".login-card").evaluate(same) == forced_style
        finally:
            _sql("DELETE FROM users WHERE username=%s", (FORCED_USER,))


# ───────────────────────────── the sign-in pages' buttons ─────────────────────────────

BUTTON_CONTRAST = """e => {
    const s = getComputedStyle(e);
    const rgb = t => (t.match(/rgba?\\(([^)]+)\\)/g) || []).map(c => c.match(/[\\d.]+/g).slice(0, 3).map(Number));
    const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
    const stops = s.backgroundImage !== 'none' ? rgb(s.backgroundImage) : rgb(s.backgroundColor);
    const text = lum(rgb(s.color)[0]);
    const ratios = stops.map(c => { const a = Math.max(text, lum(c)), b = Math.min(text, lum(c)); return (a + 0.05) / (b + 0.05); });
    return {worst: Math.min.apply(null, ratios), stops: stops.length, fill: s.backgroundImage !== 'none' ? s.backgroundImage : s.backgroundColor};
}"""


class TestTheSignInButtonsHoldTheirText:
    def test_on_the_three_pages_and_with_one_fill(self, page, base_url):
        page.set_viewport_size({"width": 1440, "height": 900})
        fills = {}
        page.goto(f"{base_url}/login")
        fills["sign in"] = page.locator("button.btn-login").evaluate(BUTTON_CONTRAST)

        _user(FORCED_USER, 1)
        _user(MFA_USER, 0)
        try:
            login(page, base_url, FORCED_USER, USER_PASSWORD, f"{base_url}/force-password-change")
            fills["forced password change"] = page.locator(".btn-submit").evaluate(BUTTON_CONTRAST)
            page.context.clear_cookies()

            # an account with an authenticator, signed out and in again: the challenge page
            login(page, base_url, MFA_USER, USER_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/mfa/enroll")
            secret = page.locator("#totp-secret").text_content().strip()
            page.fill('input[name="code"]', pyotp.TOTP(secret).now())
            page.get_by_role("button", name="Enroll Authenticator").click()
            page.wait_for_load_state("networkidle")
            page.context.clear_cookies()
            page.goto(f"{base_url}/login")
            page.fill('input[name="username"]', MFA_USER)
            page.fill('input[name="password"]', USER_PASSWORD)
            page.click(".btn-login")
            page.wait_for_url("**/mfa/verify")
            button = page.locator("button.btn:not(.btn-secondary):visible").first
            fills["MFA challenge"] = button.evaluate(BUTTON_CONTRAST)
        finally:
            _sql("DELETE FROM mfa_methods WHERE user_id IN (SELECT id FROM users WHERE username=%s)", (MFA_USER,))
            _sql("DELETE FROM mfa_backup_codes WHERE user_id IN (SELECT id FROM users WHERE username=%s)", (MFA_USER,))
            _sql("DELETE FROM users WHERE username IN (%s, %s)", (FORCED_USER, MFA_USER))
        for name, found in fills.items():
            assert found["stops"] >= 1 and found["worst"] >= 4.5, (name, found)
        assert len({found["fill"] for found in fills.values()}) == 1, fills


# ───────────────────────────── addition 10: copy buttons ─────────────────────────────


class TestCopyButtons:
    def test_the_secret_is_copied_and_the_button_says_so_for_two_seconds(self, browser, base_url):
        ctx = browser.new_context()
        try:
            ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=base_url)
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/mfa/enroll")
            secret = page.locator("#totp-secret").text_content().strip()
            assert re.fullmatch(r"[A-Z2-7]{16,}", secret)
            button = page.locator('[data-copy-target="totp-secret"]')
            label = button.locator(".copy-btn-label")
            expect(label).to_have_text("Copy")
            assert button.bounding_box()["height"] >= 24
            button.click()
            expect(label).to_have_text("Copied")
            assert page.evaluate("navigator.clipboard.readText()") == secret
            page.wait_for_timeout(2300)
            expect(label).to_have_text("Copy")
        finally:
            ctx.close()

    def test_a_refused_copy_says_what_to_do(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/api-docs")
        page.evaluate("window.jenCopyText = function() { return Promise.resolve(false); }")
        button = page.locator('[data-copy-target="req-1"]')
        button.click()
        expect(button.locator(".copy-btn-label")).to_have_text("Copy failed - select the text")
        expect(button).not_to_have_class(re.compile(r"\bcopied\b"))

    def test_an_api_example_is_copied_as_it_reads(self, browser, base_url):
        ctx = browser.new_context()
        try:
            ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=base_url)
            page = ctx.new_page()
            login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
            page.goto(f"{base_url}/settings/api-docs")
            shown = page.locator("#req-2").text_content().strip()
            page.locator('[data-copy-target="req-2"]').click()
            page.wait_for_function("(v) => navigator.clipboard.readText().then(t => t === v)", arg=shown)
            assert shown.startswith("curl -s ") and "/api/v1/" in shown
            page.goto(f"{base_url}/setup/helper")
            command = page.locator("#helper-command").text_content().strip()
            page.locator('[data-copy-target="helper-command"]').click()
            page.wait_for_function("(v) => navigator.clipboard.readText().then(t => t === v)", arg=command)
        finally:
            ctx.close()


# ───────────────────────────── addition 14: search on a phone, Find a setting ─────────────────────────────


class TestSearchFromThePhonesTopBar:
    def test_the_button_opens_the_field_and_escape_puts_it_away(self, page, base_url):
        errors = _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/leases")
        button = page.locator("#nav-search-btn")
        field = page.locator(".nav-search input")
        expect(button).to_be_visible()
        expect(field).to_be_hidden()
        box = button.bounding_box()
        assert box["width"] >= 44 and box["height"] >= 44, box
        button.click()
        expect(field).to_be_visible()
        expect(field).to_be_focused()
        expect(button).to_have_attribute("aria-expanded", "true")
        assert field.bounding_box()["width"] >= 340
        assert field.evaluate("e => parseFloat(getComputedStyle(e).fontSize)") >= 16, "no zoom on focus"
        assert _no_sideways_scroll(page)
        page.keyboard.press("Escape")
        expect(field).to_be_hidden()
        expect(button).to_be_focused()
        expect(button).to_have_attribute("aria-expanded", "false")
        button.click()
        field.fill("q248-nothing")
        page.keyboard.press("Enter")
        page.wait_for_url(re.compile(r"/search\?q=q248-nothing"))
        assert not errors, errors

    def test_a_desktop_has_no_such_button(self, page, base_url):
        _at(page, base_url, 1440)
        page.goto(f"{base_url}/leases")
        expect(page.locator("#nav-search-btn")).to_be_hidden()
        expect(page.locator(".nav-search input")).to_be_visible()


class TestFindASetting:
    def test_typing_filters_the_groups_without_a_request(self, page, base_url):
        errors = _at(page, base_url, 1440)
        page.goto(f"{base_url}/settings")
        page.wait_for_load_state("networkidle")
        tiles = page.locator(".settings-tile")
        expect(tiles).to_have_count(7)
        requests = []
        page.on("request", lambda r: requests.append(r.url))
        box = page.locator("#settings-find")
        box.fill("smtp")
        expect(page.locator(".settings-tile:visible")).to_have_count(1)
        expect(page.locator(".settings-tile:visible .settings-tile-label")).to_have_text("Alerts & Integrations")
        box.fill("certificate")
        visible = page.locator(".settings-tile:visible .settings-tile-label").all_text_contents()
        assert "Access & Security" in visible and "Appearance" not in visible, visible
        box.fill("session timeout")
        expect(page.locator(".settings-tile:visible .settings-tile-label")).to_have_text("Access & Security")
        box.fill("databases")  # a group's own name
        expect(page.locator(".settings-tile:visible .settings-tile-label")).to_have_text("Databases")
        box.fill("zzzz-q248")
        expect(page.locator(".settings-tile:visible")).to_have_count(0)
        expect(page.locator("#settings-find-none")).to_be_visible()
        expect(page.locator("#settings-find-none")).to_have_text("No setting matches.")
        box.press("Escape")
        expect(box).to_have_value("")
        expect(page.locator(".settings-tile:visible")).to_have_count(7)
        expect(page.locator("#settings-find-none")).to_be_hidden()
        # the top row's status dot asks /api/stats every thirty seconds on every page; nothing else may have been asked for
        assert [u for u in requests if not u.endswith("/api/stats")] == [], requests
        assert not errors, errors

    def test_it_is_on_a_phone_too(self, page, base_url):
        _at(page, base_url, PHONE["width"], PHONE["height"])
        page.goto(f"{base_url}/settings")
        box = page.locator("#settings-find")
        expect(box).to_be_visible()
        box.fill("backup")
        expect(page.locator(".settings-tile:visible .settings-tile-label")).to_have_text("Databases")
        assert _no_sideways_scroll(page)
