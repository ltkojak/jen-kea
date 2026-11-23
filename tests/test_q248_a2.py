"""
tests/test_q248_a2.py
─────────────────────
Q248, stage a2 - layout that breaks, and the small additions that sit on the same pages: what a rendered page, a route and the source can hold. What only a
browser can show (boxes that do not intersect, a strip scrolled under a button, a width on a phone, a contrast, a copy) is tests/e2e/test_q248_a2.py.

* V10, V37  the top row: no fixed rule takes the favorites' names, About is always in the Account menu, a favorite keeps its name for a screen reader, and
            pinning a page says what it did.
* V11       a strip with a pin block gives its right padding to the block; a scrolled strip is marked at its left edge.
* V14, V16, addition 9 - the setup wizard: the install command in a box with a Copy button, Back and Next at the foot of every step, Finish on the last,
            a tick only on a step the wizard's own state calls done, and step 6's leases as the phone's row pattern.
* V15       the API key form is a grid: Key Name and Access, then Subnet Access, then the button.
* V17       Packet Health's server name is one line.
* V47       the 404 page: inside the normal page for a signed-in person, the sign-in card's shape and the install's default theme signed out; a refusal names
            the page.
* V48       placeholders are examples that fit; what they explained is the field's hint.
* V49       the keyboard a phone shows for an IPv4 address, a MAC and a host name - over the WHOLE template tree.
* V55       stacked buttons keep a gap, a collapsed card hides everything, the forced password change card is the sign-in card, the More sheet has a Close
            button ahead of its search field, the IP map prints the whole name, the reconcile chips are words.
* addition 10 - Copy buttons from ONE listener; addition 14 - search on the phone's top bar and "Find a setting" on the Settings hub.
"""

import pathlib
import re

import pytest

from jen.services import dns_reconcile, setup_wizard

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"


def _src(name):
    return (TEMPLATES / name).read_text(encoding="utf-8").replace("\r\n", "\n")


BASE = _src("base.html")
INPUT_TAG = re.compile(r"<input\b[^>]*>", re.S)


def _attr(tag, name):
    m = re.search(r"\b" + re.escape(name) + r'="([^"]*)"', tag)
    return m.group(1) if m else None


def _tag(html, needle):
    """The whole opening tag that holds `needle`."""
    i = html.index(needle)
    return html[html.rindex("<", 0, i) : html.index(">", i) + 1]


def _body(client, path, **kw):
    r = client.get(path, **kw)
    assert r.status_code == 200, (path, r.status_code)
    return r.get_data(as_text=True)


@pytest.fixture
def clean_nav(db):
    def wipe():
        with db.cursor() as cur:
            cur.execute("DELETE FROM user_nav")
        db.commit()

    wipe()
    yield
    wipe()


@pytest.fixture
def wizard_state():
    """The wizard's stored state, put back as it was found."""
    from jen.models.user import get_global_setting, set_global_setting

    keys = (setup_wizard._STATE_KEY, setup_wizard._COMPLETED_KEY)
    before = {k: get_global_setting(k, "") for k in keys}
    for k in keys:
        set_global_setting(k, "")
    yield
    for k, v in before.items():
        set_global_setting(k, v)


# ───────────────────────────── V10, V37: the top row ─────────────────────────────


class TestTheTopRow:
    def test_no_width_rule_takes_the_names_of_the_favorites(self):
        """A fixed rule hid every favorite's name below 1500 px, though a 1440 px window with three favorites has room. The names go only when the row is measured short."""
        assert "max-width: 1500px" not in BASE
        assert ".nav.nav-fit-1 .nav-fav-label" in BASE
        assert ".nav.nav-fit-2 .nav-top-about" in BASE
        assert ".nav.nav-fit-3 .gs-pill-label" in BASE

    def test_the_link_group_clips_and_the_right_hand_group_never_shrinks(self):
        """With no script the row clips what does not fit; it never draws one group over the other."""
        links = re.search(r"\n\s*\.nav-links \{([^}]*)\}", BASE).group(1)
        assert "min-width: 0" in links and "overflow: hidden" in links
        assert re.search(r"\.nav-right \{[^}]*flex-shrink: 0", BASE)
        assert re.search(r"\.nav-kb, \.nav-search \{ flex-shrink: 0; \}", BASE)

    def test_the_fit_is_measured_once_bound_and_run_again_on_a_resize_and_when_fonts_load(self):
        script = BASE[BASE.index("function jenNavFit()") :]
        script = script[: script.index("window.jenNavFit = jenNavFit")]
        assert "scrollWidth > fitLinks.clientWidth" in script and "scrollWidth > fitNav.clientWidth" in script
        assert "new ResizeObserver(" in script and "document.fonts.ready.then(jenNavFit)" in script
        assert BASE.count("function jenNavFit()") == 1

    def test_about_is_in_the_account_menu_and_marked_in_the_row(self, logged_in_client):
        body = _body(logged_in_client, "/about")
        menu = body[body.index('id="dd-avatar-menu"') :]
        menu = menu[: menu.index("</form>")]
        assert '<a href="/about" role="menuitem">' in menu
        row = body[body.index('<div class="nav-links"') : body.index('<div class="nav-right">')]
        assert 'href="/about" class="nav-link nav-top-about active"' in row

    def test_the_pill_and_the_keyboard_button_are_24_px_targets(self):
        assert re.search(r"\.nav a\.gs-pill, #kb-hint-btn \{ min-height: 24px; \}", BASE)
        assert '<span class="gs-pill-label">Getting started (' in BASE
        assert 'class="nav-link gs-pill" title="The first-hour checklist" aria-label="Getting started (' in BASE

    def test_a_favorite_that_shows_its_icon_only_still_has_its_name(self, logged_in_client, clean_nav):
        logged_in_client.post("/navigation/pin", data={"dest": "/reports", "pinned": "0", "next": "/leases"})
        tag = _tag(_body(logged_in_client, "/leases"), 'class="nav-link nav-fav ')
        assert _attr(tag, "title") == "Reports" and _attr(tag, "aria-label") == "Reports"


class TestAPinSaysWhatItDid:
    def test_adding_names_the_page(self, logged_in_client, clean_nav):
        r = logged_in_client.post(
            "/navigation/pin", data={"dest": "/reports", "pinned": "0", "next": "/reports"}, follow_redirects=True
        )
        body = r.get_data(as_text=True)
        at = body.index("Added Reports to the top row.")
        assert "alert alert-success" in body[body.rindex('<div class="alert', 0, at) : at], "a success message"

    def test_removing_names_the_page(self, logged_in_client, clean_nav):
        logged_in_client.post("/navigation/pin", data={"dest": "/reports", "pinned": "0", "next": "/reports"})
        logged_in_client.get("/reports")  # the first message is read and gone
        r = logged_in_client.post(
            "/navigation/pin", data={"dest": "/reports", "pinned": "1", "next": "/reports"}, follow_redirects=True
        )
        body = r.get_data(as_text=True)
        assert "Removed Reports from the top row." in body and "Added Reports" not in body

    def test_an_address_this_person_is_not_offered_is_never_named(self, logged_in_client, clean_nav):
        """The name comes from the list the person is offered, never from the form."""
        r = logged_in_client.post(
            "/navigation/pin",
            data={"dest": "/q248-<b>made-up</b>", "pinned": "0", "next": "/reports"},
            follow_redirects=True,
        )
        body = r.get_data(as_text=True)
        assert "to the top row." not in body and "made-up</b>" not in body


# ───────────────────────────── V11: the pin block and the strip ─────────────────────────────


class TestTheStripAndItsPinBlock:
    def test_a_strip_with_a_pin_block_says_so(self, logged_in_client, clean_nav):
        assert '<div class="section-tabs section-tabs--pin">' in _body(logged_in_client, "/reports")
        # a page a fixed top item links to has no pin, and its strip keeps its own padding
        assert '<div class="section-tabs">' in _body(logged_in_client, "/leases")

    def test_the_block_carries_the_strips_right_padding(self):
        at = BASE.index(".section-tabs--pin { padding-right: 0; }")
        assert ".section-tabs--pin .section-pin { padding-right: 20px; }" in BASE[at : at + 160]
        # a phone shows no pin block and gets its strip's padding back from its own rule, which must come later in the file to win
        assert BASE.index(".section-tabs { padding: 0 12px; }") > at

    def test_a_scrolled_strip_is_marked_at_its_left_edge(self):
        assert re.search(r"\.section-tabs-wrap::before \{[^}]*left: 0;[^}]*opacity: 0;", BASE)
        assert ".section-tabs-wrap.is-scrolled::before { opacity: 1; }" in BASE
        assert "classList.toggle('is-scrolled', stripEl.scrollLeft > 1)" in BASE


# ───────────────────────────── V14, V16, addition 9: the setup wizard ─────────────────────────────

STEP_PATHS = [
    "/setup/connect",
    "/setup/found",
    "/setup/helper",
    "/setup/baseline",
    "/setup/recovery",
    "/setup/investigate",
]


@pytest.fixture
def found_unreachable(monkeypatch):
    monkeypatch.setattr(setup_wizard, "discover", lambda: {"reachable": False})


class TestTheSetupWizard:
    def _foot(self, body):
        foot = body[body.index('<div class="setup-nav">') :]
        return foot[: foot.index("</div>")]

    @pytest.mark.parametrize("at", range(6))
    def test_back_and_next_are_at_the_foot_of_every_step(self, logged_in_client, wizard_state, found_unreachable, at):
        foot = self._foot(_body(logged_in_client, STEP_PATHS[at]))
        back = f'<a class="btn btn-secondary" href="{STEP_PATHS[at - 1]}">' if at else None
        nxt = f'<a class="btn btn-secondary" href="{STEP_PATHS[at + 1]}">' if at < 5 else None
        if back:
            assert back in foot and "Back</a>" in foot
        else:
            assert "Back" not in foot
        if nxt:
            assert nxt in foot and "Finish" not in foot
        else:
            assert "Next" not in foot

    def test_the_last_step_has_finish_and_it_lands_on_the_dashboard(self, logged_in_client, wizard_state):
        foot = self._foot(_body(logged_in_client, "/setup/investigate"))
        assert '<form method="POST" action="/setup/investigate/visit">' in foot
        assert '<input type="hidden" name="finish" value="1">' in foot and 'name="csrf_token"' in foot
        assert '<button type="submit" class="btn btn-primary">Finish</button>' in foot
        r = logged_in_client.post("/setup/investigate/visit", data={"finish": "1"})
        assert r.status_code == 302 and r.headers["Location"] == "/"
        assert setup_wizard.get_state().get("investigate") == "done"

    def test_finish_beside_a_chosen_client_still_opens_the_client(self, logged_in_client, wizard_state):
        r = logged_in_client.post("/setup/investigate/visit", data={"finish": "1", "mac": "aa:bb:cc:dd:ee:ff"})
        assert r.headers["Location"] == "/client?q=aa:bb:cc:dd:ee:ff"

    def test_next_records_nothing(self, logged_in_client, wizard_state):
        """Next is a link. A step is ticked by its own action, and "Skip for now" is still how a step is passed over on purpose."""
        logged_in_client.get("/setup/helper")
        logged_in_client.get("/setup/baseline")
        assert setup_wizard.get_state() == {}

    def test_a_tick_means_what_the_wizards_state_says(self, logged_in_client, wizard_state):
        setup_wizard.set_step("connect", "done")
        setup_wizard.set_step("found", "skipped")
        body = _body(logged_in_client, "/setup/helper")
        pills = re.findall(r"<span style=[^>]*>.*?</span>", body[body.index('class="u-setup-progress"') :], re.S)[:6]
        assert len(pills) == 6
        connect, found, helper, baseline = pills[:4]
        assert 'data-step-state="done"' in connect and 'title="Done"' in connect and "i-circle-check" in connect
        assert 'data-step-state="skipped"' in found and 'title="Skipped"' in found and "i-circle-check" not in found
        assert 'aria-current="step"' in helper and "data-step-state" not in helper and "i-circle-check" not in helper
        assert "aria-current" not in baseline and "data-step-state" not in baseline and "i-circle-check" not in baseline

    def test_the_install_command_is_one_line_in_a_box_with_a_copy_button(self, logged_in_client, wizard_state):
        body = _body(logged_in_client, "/setup/helper")
        box = _tag(body, 'id="helper-command"')
        assert box.startswith("<pre ") and 'class="copy-box"' in box
        assert 'data-copy-target="helper-command"' in body
        assert "u-3f3a6c" not in body and "u-86abda" not in _src("setup_helper.html")
        rule = re.search(r"\n\s*\.copy-box \{([^}]*)\}", BASE).group(1)
        assert "overflow-x: auto" in rule and "white-space: pre" in rule and "max-width: 100%" in rule

    def test_the_cards_have_room_above_a_heading_and_keep_their_bullets_inside(
        self, logged_in_client, wizard_state, found_unreachable
    ):
        for path in STEP_PATHS:
            assert "setup-card" in _tag(_body(logged_in_client, path), 'class="card u-'), path
        assert ".setup-card h3, .setup-card h4 { margin: 16px 0 6px; }" in BASE
        assert re.search(r"\.setup-card ul \{[^}]*padding-left: 22px", BASE)

    def test_step_six_is_the_row_pattern_a_phone_can_read(self, logged_in_client, wizard_state, db):
        mac = "AABBCC248A21"
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (mac,))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                "VALUES (INET_ATON('10.99.0.121'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 'q248-a2-step6', 0)",
                (mac,),
            )
        db.commit()
        try:
            body = _body(logged_in_client, "/setup/investigate")
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (mac,))
            db.commit()
        assert '<table class="table rowlist">' in body
        row = body[body.index("10.99.0.121") - 80 :]
        row = row[: row.index("</tr>")]
        assert '<td class="mono" data-m="primary">10.99.0.121</td>' in row
        assert row.count('data-m="secondary"') == 3 and 'data-m="hide"' in row
        action = row[row.index('<td data-m="trailing">') :]
        assert 'action="/setup/investigate/visit"' in action and ">Investigate</button>" in action


# ───────────────────────────── V15: the API key form ─────────────────────────────


class TestTheApiKeyForm:
    def test_it_is_a_grid_with_the_button_under_the_fields(self, logged_in_client):
        body = _body(logged_in_client, "/settings/api-keys")
        form = body[body.index('<form method="POST" action="/settings/api-keys/create" class="apikey-form">') :]
        form = form[: form.index("</form>")]
        col = form[form.index('<div class="apikey-col">') : form.index('id="f-subnet_ids-label"')]
        assert 'name="name"' in col and 'name="can_write"' in col
        assert form.index('id="f-subnet_ids"') < form.index('class="btn btn-primary apikey-submit"')
        assert "u-82d601" not in form and "min-width:160px" not in form

    def test_the_grid_is_aligned_to_the_top_and_stacks_on_a_phone(self):
        src = _src("api_keys.html")
        rule = re.search(r"\.apikey-form \{([^}]*)\}", src).group(1)
        assert "display: grid" in rule and "align-items: start" in rule
        assert ".apikey-submit { grid-column: 1 / -1; justify-self: start; }" in src
        assert "@media screen and (max-width: 768px) { .apikey-form { grid-template-columns: minmax(0, 1fr); } }" in src


# ───────────────────────────── V16: phones ─────────────────────────────


class TestPhones:
    def test_mfa_enrollment_stacks_below_600_px(self, logged_in_client):
        body = _body(logged_in_client, "/mfa/enroll")
        assert '<div class="mfa-enroll-grid">' in body
        assert (
            "@media screen and (max-width: 600px) { .mfa-enroll-grid { grid-template-columns: minmax(0, 1fr); } }"
            in body
        )
        assert "grid-template-columns:auto 1fr" not in body

    def test_an_api_example_may_be_narrower_than_its_longest_line(self, logged_in_client):
        body = _body(logged_in_client, "/settings/api-docs")
        assert '<div class="u-911b26 api-example">' in body
        assert ".api-example > div { min-width: 0; }" in body

    def test_the_migration_wizard_never_breaks_a_table_name(self):
        src = _src("database_migrate.html")
        assert '<div id="jen-mig-tables" class="mig-tables">' in src
        assert "grid-template-columns: repeat(auto-fill, minmax(230px, 1fr))" in src
        assert re.search(r"\.mig-tables label \{[^}]*white-space: nowrap", src)


# ───────────────────────────── V17: Packet Health ─────────────────────────────


class TestPacketHealth:
    def test_the_servers_name_is_one_line_beside_its_notes(self):
        src = _src("dashboard.html")
        rule = re.search(r'#dash-packet_health td\[data-m="primary"\] \{([^}]*)\}', src)
        assert rule and "white-space: nowrap" in rule.group(1)
        assert "@media screen and (min-width: 769px) { #dash-packet_health" in src


# ───────────────────────────── V47: the 404 page and a refusal ─────────────────────────────


class TestThe404Page:
    def test_signed_in_it_is_the_normal_page_with_the_address_and_the_way_back(self, logged_in_client):
        r = logged_in_client.get("/no-such-page-q248/<b>x</b>")
        body = r.get_data(as_text=True)
        assert r.status_code == 404
        assert '<div class="nav-links"' in body and 'id="dd-avatar-menu"' in body
        card = body[body.index('<div class="card not-found">') :]
        card = card[: card.index("</div>")]
        assert "<h1>Page not found</h1>" in card
        assert "<code>/no-such-page-q248/&lt;b&gt;x&lt;/b&gt;</code>" in card and "<b>x</b>" not in body
        assert '<a href="/" class="btn btn-primary">' in card

    def test_the_query_is_not_printed_and_a_long_address_is_cut(self, logged_in_client):
        body = logged_in_client.get("/no-such-page-q248?token=q248secret").get_data(as_text=True)
        assert "q248secret" not in body
        body = logged_in_client.get("/" + "a" * 900).get_data(as_text=True)
        assert "a" * 199 in body and "a" * 201 not in body

    def test_signed_out_it_is_the_sign_in_cards_shape_in_the_installs_default_theme(self, client):
        from jen.models.user import get_global_setting, set_global_setting

        before = get_global_setting("theme_default", "dark")
        set_global_setting("theme_default", "light")
        try:
            r = client.get("/no-such-page-q248/<b>x</b>")
        finally:
            set_global_setting("theme_default", before)
        body = r.get_data(as_text=True)
        assert r.status_code == 404
        assert '<html lang="en" data-theme="light">' in body
        assert ':root[data-theme="light"]' in body, "the theme's own token block is on the page"
        assert "jen-theme-pick" not in body, "a signed-out page reads no personal pick"
        assert "nav-links" not in body and "dd-avatar-menu" not in body
        assert "<h1>Page not found</h1>" in body
        assert "<code>/no-such-page-q248/&lt;b&gt;x&lt;/b&gt;</code>" in body and "<b>x</b>" not in body
        assert '<a href="/login" class="btn">Sign in</a>' in body
        src = _src("error.html")
        assert ".wrap { width:100%; max-width:400px; padding:20px; }" in src and "padding:44px 40px 36px" in src
        assert 'src="/static/icons/jen-logo-wide.png"' in src

    @pytest.mark.parametrize("headers", [{"HX-Request": "true"}, {"Sec-Fetch-Mode": "cors"}])
    def test_a_request_nobody_reads_gets_the_small_page(self, logged_in_client, headers):
        r = logged_in_client.get("/no-such-page-q248", headers=headers)
        body = r.get_data(as_text=True)
        assert r.status_code == 404 and "nav-links" not in body and "Page not found" in body

    def test_the_small_page_keeps_a_signed_in_persons_theme_pick(self, logged_in_client):
        body = logged_in_client.get("/no-such-page-q248", headers={"Sec-Fetch-Mode": "cors"}).get_data(as_text=True)
        assert (
            "localStorage.getItem('jen-theme-pick')" in body
            and '<a href="/" class="btn">Go to the dashboard</a>' in body
        )

    def test_another_error_keeps_its_code_and_message(self, app):
        from werkzeug.exceptions import MethodNotAllowed

        with app.test_request_context("/q248"):
            resp = app.make_response(app.handle_http_exception(MethodNotAllowed(["GET"])))
        body = resp.get_data(as_text=True)
        assert resp.status_code == 405 and "Error 405" in body and "Page not found" not in body


class TestARefusalNamesThePage:
    def test_the_admin_sentence(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="q248_a2_viewer")
        body = client.get("/settings/security", follow_redirects=True).get_data(as_text=True)
        assert "Admin access required for /settings/security." in body

    def test_the_superadmin_sentence(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="admin", username="q248_a2_admin")
        body = client.get("/setup/helper", follow_redirects=True).get_data(as_text=True)
        assert "Superadmin access required for /setup/helper." in body

    def test_the_api_key_pages_say_it_the_same_way(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="q248_a2_viewer2")
        body = client.get("/settings/api-keys", follow_redirects=True).get_data(as_text=True)
        assert "Admin access required for /settings/api-keys." in body

    def test_the_bare_sentence_is_gone_from_the_decorators_and_the_api_key_routes(self):
        for rel in ("jen/services/access.py", "jen/routes/api.py"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            assert 'flash("Admin access required.' not in text and 'flash("Superadmin access required.' not in text, rel


# ───────────────────────────── V48: placeholders ─────────────────────────────

# (template, the placeholder that was cut on a phone)
OLD_PLACEHOLDERS = [
    ("client.html", "aa:bb:cc:dd:ee:ff, 10.0.0.50, 2001:db8::50, a DUID or a hostname"),
    ("add_reservation.html", "Leave blank for subnet default, e.g. 1.1.1.1, 8.8.8.8"),
    ("edit_reservation.html", "Leave blank for subnet default"),
    ("settings_appearance.html", "#141414 or leave blank for default"),
    ("settings_kea.html", "optional — probe a specific direct socket URL, e.g. https://kea:8004"),
    ("settings_kea.html", "optional - another daemon of the same host, e.g. https://kea:8004"),
    ("setup_connect.html", "(saved — leave blank to keep it)"),
    ("setup_found.html", "(only if kea-dhcp6 is on a different host from the Kea API)"),
    ("explain.html", "MSFT 5.0, android-dhcp-14, PXEClient…"),
    ("api_docs.html", "Paste your full API key here to pre-fill examples"),
]
# the pages this stage went through: no placeholder written in the template is longer than this (about what a 390 px phone's field shows at 16 px)
STAGE_PAGES = [
    "client.html",
    "add_reservation.html",
    "edit_reservation.html",
    "settings_appearance.html",
    "setup_connect.html",
    "setup_found.html",
    "setup_helper.html",
    "explain.html",
    "api_docs.html",
    "api_keys.html",
    "mfa_enroll.html",
    "settings_home.html",
]
PLACEHOLDER_ROOM = 38


class TestPlaceholders:
    @pytest.mark.parametrize("name,old", OLD_PLACEHOLDERS)
    def test_the_sentence_is_no_longer_a_placeholder(self, name, old):
        assert old not in _src(
            name
        )  # anywhere: one of them was written inside a Jinja expression, not as the attribute's literal value

    @pytest.mark.parametrize("name", STAGE_PAGES)
    def test_a_placeholder_is_an_example_that_fits(self, name):
        long = [p for p in re.findall(r'placeholder="([^"{]*)"', _src(name)) if len(p) > PLACEHOLDER_ROOM]
        assert not long, (name, long)

    def test_what_the_dns_override_placeholder_explained_is_its_hint(self, logged_in_client):
        body = _body(logged_in_client, "/reservations/add")
        tag = _tag(body, 'name="dns_override"')
        assert (
            _attr(tag, "placeholder") == "1.1.1.1, 8.8.8.8" and _attr(tag, "aria-describedby") == "f-dns_override-hint"
        )
        assert (
            '<div class="form-hint" id="f-dns_override-hint">Leave blank to use the subnet\'s DNS servers.</div>'
            in body
        )

    def test_the_nav_color_is_an_example_and_its_hint_says_blank_is_the_default(self, logged_in_client):
        body = _body(logged_in_client, "/settings/appearance")
        assert _attr(_tag(body, 'name="nav_color_hex"'), "placeholder") == "#141414"
        assert "Leave blank for default." in body

    def test_the_probes_address_says_optional_under_the_field(self, logged_in_client):
        body = _body(logged_in_client, "/settings/kea")
        tag = _tag(body, 'id="probe-candidate-url"')
        assert (
            _attr(tag, "placeholder") == "https://kea:8004" and _attr(tag, "aria-describedby") == "probe-candidate-hint"
        )
        assert (
            'id="probe-candidate-hint">The address is optional: type one to probe a specific direct socket.</div>'
            in body
        )

    def test_the_vendor_class_examples_are_its_hint(self):
        src = _src("explain.html")
        assert 'placeholder="MSFT 5.0" aria-describedby="f-vendor_class-hint"' in src
        assert (
            'id="f-vendor_class-hint">What the client sends, for example MSFT 5.0, android-dhcp-14 or PXEClient.</div>'
            in src
        )

    def test_a_saved_password_says_so_under_the_field(self, logged_in_client, monkeypatch, wizard_state):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_PASS", "stored-api")
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "")
        body = _body(logged_in_client, "/setup/connect")
        assert _attr(_tag(body, 'name="api_pass"'), "placeholder") == "(saved)"
        assert 'id="f-api_pass-hint">A password is saved. Leave blank to keep it.</div>' in body
        assert _attr(_tag(body, 'name="kea_db_pass"'), "placeholder") == ""
        assert 'id="f-kea_db_pass-hint">Leave blank for none.</div>' in body


# ───────────────────────────── V49: the keyboard a phone shows ─────────────────────────────

MAC_NAMES = {"mac", "duid", "client_id", "user_class_bytes"}
# the same field name for another thing: single sign-on's client id is a word the identity provider chose, not a DHCP client identifier
NOT_A_MAC = {("settings_security.html", "client_id")}
HOST_NAMES = {
    "hostname",
    "host",
    "ssh_host",
    "extra_ssh_host[]",
    "smtp_host",
    "server_hostname",
    "db_host",
    "kea_db_host",
}
IPV4_FIELDS = [("add_reservation.html", "ip"), ("dhcp_class_edit.html", "next_server"), ("explain.html", "giaddr")]


def _text_inputs():
    """(template, tag) for every text input of every template, hidden ones and other types left out."""
    for p in sorted(TEMPLATES.glob("*.html")):
        for m in INPUT_TAG.finditer(p.read_text(encoding="utf-8")):
            tag = " ".join(m.group(0).split())
            if (_attr(tag, "type") or "text") in ("text", "search"):
                yield p.name, tag


class TestTheKeyboardAPhoneShows:
    def test_every_mac_field_of_the_tree(self):
        seen, missing = 0, []
        for name, tag in _text_inputs():
            if _attr(tag, "name") in MAC_NAMES and (name, _attr(tag, "name")) not in NOT_A_MAC:
                seen += 1
                if not all(a in tag for a in ('autocapitalize="off"', 'autocomplete="off"', 'spellcheck="false"')):
                    missing.append((name, tag[:90]))
        assert seen >= 7 and not missing, missing

    def test_every_host_name_field_of_the_tree(self):
        seen, missing = 0, []
        for name, tag in _text_inputs():
            if _attr(tag, "name") in HOST_NAMES:
                seen += 1
                if not all(a in tag for a in ('autocapitalize="off"', 'spellcheck="false"')):
                    missing.append((name, tag[:90]))
        assert seen >= 17 and not missing, missing

    @pytest.mark.parametrize("name,field", IPV4_FIELDS)
    def test_a_field_that_takes_one_ipv4_address(self, name, field):
        """No keypad is asked for: on an iPhone whose region writes decimals with a comma, the decimal keypad has a comma and no dot, and an
        address could not be typed at all. The field keeps the full keyboard and loses only capitals and spelling marks."""
        tags = [t for n, t in _text_inputs() if n == name and _attr(t, "name") == field]
        assert len(tags) == 1 and "inputmode" not in tags[0], tags
        assert 'autocapitalize="off"' in tags[0] and 'spellcheck="false"' in tags[0], tags

    def test_a_field_that_takes_a_list_a_range_or_ipv6_has_no_decimal_keypad(self):
        """A decimal keypad has no comma, hyphen, slash or colon: a field that may hold more than one IPv4 address must not get one."""
        for name, tag in _text_inputs():
            if _attr(tag, "name") in ("routers", "dns_servers", "pool", "cidr", "dns_override", "address", "prefix"):
                assert "inputmode" not in tag, (name, tag[:90])

    def test_the_rendered_form_carries_them(self, logged_in_client):
        body = _body(logged_in_client, "/reservations/add")
        ip = _tag(body, 'name="ip"')
        assert "inputmode" not in ip and 'autocapitalize="off"' in ip and 'spellcheck="false"' in ip
        mac = _tag(body, 'name="mac"')
        assert 'autocapitalize="off"' in mac and 'autocomplete="off"' in mac and 'spellcheck="false"' in mac


# ───────────────────────────── V55: the smaller ones ─────────────────────────────


class TestTheSmallerOnes:
    def test_stacked_buttons_keep_a_gap(self, logged_in_client):
        assert ".btn-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }" in BASE
        kea = _body(logged_in_client, "/settings/kea")
        row = kea[kea.index('<div class="btn-row">') :]
        row = row[: row.index("</div>")]
        assert "Save Kea API" in row and 'id="probe-kea-btn"' in row and 'id="probe-candidate-url"' in row
        system = _body(logged_in_client, "/settings/system")
        row = system[system.index('<div class="btn-row">') :]
        assert (
            "Download support bundle" in row[: row.index("</div>")] and "Report an issue" in row[: row.index("</div>")]
        )
        security = _body(logged_in_client, "/settings/security")
        assert '<form method="POST" action="/settings/clear-lockouts" class="mt-2"' in security
        assert "display:inline;margin-top:8px" not in security

    def test_a_collapsed_card_hides_everything_and_is_as_tall_as_its_header(self):
        toc = _src("_card_toc.html")
        assert ".card[data-collapsible].collapsed > :not(.card-header) { display: none !important; }" in toc
        assert ".card[data-collapsible].collapsed > .card-header { margin-bottom: 0; }" in toc

    def test_the_forced_password_change_card_is_the_sign_in_card(self):
        forced, login = _src("force_password_change.html"), _src("login.html")
        assert 'src="/static/icons/jen-logo-wide.png" alt="Jen" class="logo-img"' in forced
        assert (
            '<div class="logo-sub">The Kea DHCP Management Console</div>' in forced
            and '<div class="brand">' not in forced
        )
        for shared in ("max-width: 400px", "padding: 44px 40px 36px", "border-radius: 12px", "rgba(14, 22, 30, 0.92)"):
            assert shared in forced and shared in login, shared

    def test_the_four_sign_in_buttons_share_one_fill_that_holds_white(self):
        fill = "linear-gradient(135deg, #005f92, #0077b6)"
        for name in ("login.html", "force_password_change.html", "mfa_challenge.html"):
            assert fill in _src(name), name
        css = (ROOT / "static" / "css" / "session-watch.css").read_text(encoding="utf-8")
        assert ".jen-dialog .btn-primary { background: " + fill in css
        for text in (_src("login.html"), _src("force_password_change.html"), _src("mfa_challenge.html"), css):
            assert not re.search(
                r"background:\s*(linear-gradient\(135deg,\s*#0077b6,\s*#00b4d8\)|#00b4d8);[^}]*color:\s*#fff", text
            )

        def contrast_with_white(hex_color):
            def channel(v):
                v /= 255
                return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

            r, g, b = (int(hex_color[i : i + 2], 16) for i in (1, 3, 5))
            return 1.05 / (0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b) + 0.05)

        assert contrast_with_white("#005f92") >= 4.5 and contrast_with_white("#0077b6") >= 4.5

    def test_the_more_sheet_has_a_close_button_ahead_of_its_search_field(self, logged_in_client):
        body = _body(logged_in_client, "/about")
        sheet = body[body.index('<div class="sheet" id="more-sheet"') :]
        sheet = sheet[: sheet.index('id="theme-sheet"')]
        close = sheet.index('<button type="button" class="sheet-close" data-sheet-close aria-label="Close">')
        assert close < sheet.index('<form class="sheet-search"'), (
            "the sheet's first control is Close, so opening it does not raise the keyboard"
        )

    def test_the_ip_map_prints_the_whole_name_and_the_cell_cuts_it(self):
        src = _src("ipmap.html")
        assert "[:8]" not in src
        assert "<span class=\"ip-name\">{{ used[ip].hostname | hostname or '' }}</span>" in src
        assert "title=\"{{ ip }}&#10;{{ used[ip].hostname or 'No hostname' }}" in src
        rule = re.search(r"\.ip-cell \.ip-name \{([^}]*)\}", BASE).group(1)
        assert "text-overflow: ellipsis" in rule and "max-width: 100%" in rule

    def test_every_verdict_has_words(self):
        assert set(dns_reconcile.VERDICT_LABELS) == set(dns_reconcile.VERDICTS)
        for verdict, label in dns_reconcile.VERDICT_LABELS.items():
            assert label[0].isupper() and "-" not in label, (verdict, label)
        assert len(set(dns_reconcile.VERDICT_LABELS.values())) == len(dns_reconcile.VERDICTS)

    def test_the_reconcile_chips_say_them(self, logged_in_client, monkeypatch, mock_kea):
        monkeypatch.setattr(dns_reconcile, "reconcile", lambda *a, **k: [])
        body = _body(logged_in_client, "/ddns/reconcile")
        chips = body[body.index("Results — ") :]
        chips = chips[: chips.index("Export CSV")]
        for verdict, label in dns_reconcile.VERDICT_LABELS.items():
            assert f'verdict={verdict}" title="{verdict}"' in chips, verdict
            assert re.search(re.escape(label) + r" \(\d+\)", chips), label
            if verdict != "ok":
                assert not re.search(r">\s*" + re.escape(verdict) + r" \(", chips), verdict


# ───────────────────────────── addition 10: copy buttons ─────────────────────────────


class TestCopyButtons:
    def test_one_listener_serves_the_cells_and_the_buttons(self):
        assert BASE.count("closest('[data-copy-target], [data-copy-text]')") == 1
        i = BASE.index("closest('[data-copy-target], [data-copy-text]')")
        assert BASE.index("closest('[data-copy]')") > i > BASE[:i].rindex("document.addEventListener('click'")
        between = BASE[i : BASE.index("closest('[data-copy]')")]
        assert "document.addEventListener(" not in between, "the same listener, not a second one"
        assert "say(ok ? 'Copied' : 'Copy failed - select the text', ok)" in between and "}, 2000);" in between
        assert "window.jenCopyText(" in between

    def test_nothing_else_listens_for_a_copy_button(self):
        offenders = [
            p.name
            for p in sorted(TEMPLATES.glob("*.html"))
            if p.name != "base.html" and "[data-copy-target" in p.read_text(encoding="utf-8")
        ]
        assert not offenders, offenders

    def test_the_totp_secret(self, logged_in_client):
        body = _body(logged_in_client, "/mfa/enroll")
        assert 'id="totp-secret"' in body
        button = _tag(body, 'data-copy-target="totp-secret"')
        assert button.startswith("<button ") and 'type="button"' in button and "copy-btn" in button
        assert _attr(button, "aria-label") == "Copy the secret"

    def test_the_api_examples(self, logged_in_client):
        body = _body(logged_in_client, "/settings/api-docs")
        requests = re.findall(r'<pre class="code-block" id="(req-\d+)">', body)
        assert len(requests) >= 5
        for target in [*requests, "ha-presence", "ha-utilization", "ha-health"]:
            assert f'data-copy-target="{target}"' in body and f'id="{target}"' in body, target

    def test_the_helper_command_on_settings_kea(self):
        src = _src("settings_kea.html")
        assert '{{ copy_button("helper-by-hand-command", what="the helper install command") }}' in src
        assert '<pre class="mono u-c046bf" id="helper-by-hand-command">{{ helper_by_hand_command }}</pre>' in src

    def test_a_copy_button_is_a_24_px_target(self):
        assert re.search(r"\.copy-btn \{[^}]*min-height: 24px", BASE)


# ───────────────────────────── addition 14: search on a phone, Find a setting ─────────────────────────────


class TestSearchOnAPhoneAndFindASetting:
    def test_the_phones_top_bar_has_a_search_button_for_the_same_field(self, logged_in_client):
        body = _body(logged_in_client, "/about")
        button = _tag(body, 'id="nav-search-btn"')
        assert _attr(button, "aria-label") == "Search" and _attr(button, "aria-controls") == "nav-search"
        assert _attr(button, "aria-expanded") == "false" and 'type="button"' in button
        assert '<div class="nav-search" id="nav-search"' in body
        assert re.search(r"\n\s*\.nav-search-btn \{ display: none; \}", BASE), "not shown above a phone's width"
        assert ".nav.search-open .nav-search { display: block !important;" in BASE

    def test_the_hub_has_a_find_box_and_every_group_has_keywords(self, logged_in_client):
        body = _body(logged_in_client, "/settings")
        box = _tag(body, 'id="settings-find"')
        assert _attr(box, "type") == "text" and _attr(box, "aria-controls") == "settings-grid"
        assert '<label for="settings-find"' in body
        tiles = re.findall(r'<a href="([^"]+)" class="settings-tile" data-keywords="([^"]*)">', body)
        assert len(tiles) == 7
        for url, keywords in tiles:
            assert len(keywords.split(",")) >= 5, url
        by_url = dict(tiles)
        assert "SMTP" in by_url["/settings/alerts"] and "certificate" in by_url["/settings/security"]
        assert "session timeout" in by_url["/settings/security"] and "API key" in by_url["/settings/security"]
        assert "theme" in by_url["/settings/appearance"] and "backup" in by_url["/settings/databases"]
        assert (
            '<p class="settings-find-none" id="settings-find-none" role="status" hidden>No setting matches.</p>' in body
        )

    def test_the_filter_makes_no_request(self):
        script = _src("settings_home.html")
        script = script[script.index("{% block scripts %}") :]
        for word in ("fetch(", "jenFetch", "XMLHttpRequest", "htmx", "location"):
            assert word not in script, word
        assert "e.key === 'Escape'" in script and ".settings-tile[hidden] { display: none; }" in _src(
            "settings_home.html"
        )
