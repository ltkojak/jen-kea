"""
tests/test_field_errors.py
──────────────────────────
v5.70.0-beta.4 (Q208, AX4): a validation error that names ONE field is printed under that field, and every hint is tied to its input.

`flash_field(field, message)` (jen/services/forms.py) keeps `[field, message, form_path]` in the session (Q210: the third element is the page the form was on); base.html prints each as an alert
carrying `data-field` and `data-form`; one script moves it under `#f-<field>` on that page.
The first classes are pure (`py -m pytest --noconftest tests/test_field_errors.py -k "FlashField or Hint or Conversion or Script"`); the route classes need the app.
"""

import json
import pathlib
import random
import re
import string

import pytest
from flask import Flask, get_flashed_messages, session

from jen.services import forms

TEMPLATES = pathlib.Path("templates")
ROUTES = pathlib.Path("jen/routes")


@pytest.fixture
def ctx():
    app = Flask(__name__)
    app.secret_key = "t"
    with app.test_request_context("/"):
        yield app


class TestFlashField:
    def test_a_valid_name_is_stored_with_its_message(self, ctx):
        forms.flash_field("api_url", "API URL is required.")
        assert session["field_errors"] == [["api_url", "API URL is required.", ""]], (
            "no Referer: the page is unknown, so the error may land on any page (the beta.4 reading)"
        )
        assert get_flashed_messages() == []

    @pytest.mark.parametrize("name", ["f[0]", "a-b", "x_1", "kea6_api_url", "zone-forward", "a" * 64])
    def test_every_id_shape_the_templates_use_is_accepted(self, ctx, name):
        forms.flash_field(name, "m")
        assert session["field_errors"] == [[name, "m", ""]]

    @pytest.mark.parametrize("name", ["<script>", "../x", "a" * 65, "", "A", "has space", 'q"', "a;b", "x\n", None, 5])
    def test_a_name_that_could_reach_an_id_attribute_unchecked_falls_back_to_a_flash(self, ctx, name):
        forms.flash_field(name, "A message.")
        assert "field_errors" not in session
        assert get_flashed_messages(with_categories=True) == [("error", "A message.")]

    def test_the_list_is_capped_and_the_overflow_is_flashed_not_lost(self, ctx):
        for n in range(25):
            forms.flash_field(f"f{n}", f"m{n}")
        assert len(session["field_errors"]) == forms.MAX_FIELD_ERRORS == 20
        assert [m for _c, m in get_flashed_messages(with_categories=True)] == [f"m{n}" for n in range(20, 25)]

    def test_a_long_message_is_cut(self, ctx):
        forms.flash_field("x", "y" * 1000)
        assert len(session["field_errors"][0][1]) == forms.MAX_MESSAGE

    def test_take_pops_once_and_gives_the_same_list_within_a_request(self, ctx):
        forms.flash_field("a", "one")
        first = forms.take_field_errors()
        assert first == [("a", "one", "")] and "field_errors" not in session
        assert forms.take_field_errors() == first

    def test_take_ignores_a_tampered_entry(self, ctx):
        session["field_errors"] = [
            ["ok", "fine"],
            ["<b>", "x"],
            ["a"],
            "junk",
            [1, 2],
            ["p", "q", "/subnets/add"],
            ["r", "s", 5],
            ["t", "u", "/a", "extra"],
        ]
        assert forms.take_field_errors() == [("ok", "fine", ""), ("p", "q", "/subnets/add")]

    def test_a_list_beta_4_wrote_is_still_read(self, ctx):
        """Q210 (AZ5 a): two-element items are the old shape; they read as `form_path == ""`."""
        session["field_errors"] = [["name", "old shape"]]
        assert forms.take_field_errors() == [("name", "old shape", "")]


class TestTheMarkupEscapes:
    """A message reaches the page through `{{ message }}` (autoescaped), never `|safe`."""

    def test_the_alert_prints_the_message_through_the_escaping_filter(self):
        base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        m = re.search(
            r'<div class="alert alert-error alert-flash" role="alert" data-field="\{\{ field \}\}" data-form="\{\{ form_path \}\}">(.*?)</div>',
            base,
            re.S,
        )
        assert m, "the data-field alert"
        assert "{{ message }}" in m.group(1) and "|safe" not in m.group(1)
        assert 'data-field="{{ field }}"' in base and 'data-form="{{ form_path }}"' in base

    def test_the_rendered_alert_escapes_a_message_and_a_name(self):
        from jinja2 import Environment, FileSystemLoader

        env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
        html = env.from_string(
            '{% for field, message, form_path in errors %}<div data-field="{{ field }}" data-form="{{ form_path }}"><span class="alert-text">{{ message }}</span></div>{% endfor %}'
        ).render(errors=[('x"><script>alert(1)</script>', "<b>bold</b> & <script>x</script>", '/"><script>y</script>')])
        assert "<script>" not in html and "<b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html

    def test_the_script_writes_the_message_with_textcontent_and_looks_the_input_up_by_id(self):
        base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        block = base[base.index("AX4 - an error that names one field is moved under it") :]
        block = block[: block.index("function clearField")]
        assert "err.textContent = text" in block and "innerHTML" not in block
        assert "document.getElementById('f-' + " in block


class TestTheThemeRouteNamesTheField:
    def test_a_bad_hex_post_gives_a_data_field_alert_with_the_message_and_no_name_prefix(self, logged_in_client):
        form = {"radius": "6", "mono_ui": "on"}
        from jen.services import theme

        for token in theme.TOKENS:
            form[token] = "#112233"
        form["primary"] = "zzz"
        r = logged_in_client.post("/settings/theme/custom", data=form, follow_redirects=True)
        html = r.data.decode()
        assert 'data-field="primary"' in html
        assert "&#39;zzz&#39; is not a valid hex color" in html or "'zzz' is not a valid hex color" in html
        assert "primary: " not in re.sub(r"<[^>]+>", " ", html), "the message no longer starts with the field's name"
        assert 'id="f-primary"' in html, "the input the error belongs under exists on the page"

    def test_a_bad_radius_names_the_radius_input(self, logged_in_client):
        from jen.services import theme

        form = dict.fromkeys(theme.TOKENS, "#112233")
        form["radius"] = "99"
        html = logged_in_client.post("/settings/theme/custom", data=form, follow_redirects=True).data.decode()
        assert 'data-field="radius"' in html and 'id="f-radius"' in html

    def test_the_error_is_shown_once_and_then_gone(self, logged_in_client):
        from jen.services import theme

        form = dict.fromkeys(theme.TOKENS, "#112233")
        form["radius"] = "99"
        logged_in_client.post("/settings/theme/custom", data=form)
        assert 'data-field="radius"' in logged_in_client.get("/settings/appearance").data.decode()
        assert 'data-field="radius"' not in logged_in_client.get("/settings/appearance").data.decode()

    def test_the_services_string_api_is_unchanged(self):
        from jen.services import theme

        _result, errors = theme.validate_palette({"radius": "99"})
        assert any(e.startswith("radius: ") for e in errors)
        assert any(e.startswith("bg: ") for e in errors)


class TestAFieldNameThatIsNotAFieldNameIsAFlash:
    def test_a_hostile_name_through_the_real_page_is_a_flash_and_prints_no_attribute(self, app, logged_in_client):
        with app.test_request_context("/"):
            pass
        with logged_in_client.session_transaction() as sess:
            sess["field_errors"] = [["<script>alert(1)</script>", "x"], ["../x", "y"], ["a" * 65, "z"]]
        html = logged_in_client.get("/leases").data.decode()
        assert "data-field" not in html.split("<main")[1].split("</main>")[0], (
            "a tampered list prints nothing as an attribute"
        )
        assert "<script>alert(1)</script>" not in html

    def test_a_message_with_markup_through_flash_field_is_escaped_on_the_page(self, app, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["field_errors"] = [["hostname", "<img src=x onerror=alert(1)> & more"]]
        html = logged_in_client.get("/leases").data.decode()
        assert "<img src=x" not in html
        assert "&lt;img src=x onerror=alert(1)&gt; &amp; more" in html
        assert 'data-field="hostname"' in html


class TestAnErrorLandsOnItsOwnForm:
    """Q210 (AZ5 a, Y9): an error is raised for ONE form, so it carries the path of the page that form was on (the Referer's, when it is this site's) and the script moves it under an input only on that
    page - fifteen `f-<name>` ids are shared between pages (`f-name` on add_subnet and api_keys), so a stored message could be put under an unrelated input. A full page that has no such input
    prints a pending error as a plain flash, so one never outlives one full page."""

    @staticmethod
    def _ctx(referer=None):
        app = Flask(__name__)
        app.secret_key = "t"
        return app.test_request_context(
            "/", headers={"Referer": referer} if referer else {}, base_url="http://localhost"
        )

    @pytest.mark.parametrize(
        ("referer", "expected"),
        [
            ("http://localhost/subnets/add", "/subnets/add"),
            ("http://localhost/subnets/add?x=1#top", "/subnets/add"),
            ("http://localhost/settings/api-keys", "/settings/api-keys"),
            ("https://evil.example/subnets/add", ""),
            ("http://localhost.evil.example/x", ""),
            ("http://localhost//evil", ""),
            ("not a url", ""),
            (None, ""),
            ("http://localhost/" + "a" * 300, ""),
        ],
    )
    def test_the_form_path_is_the_referers_path_only_when_the_referer_is_this_site(self, referer, expected):
        with self._ctx(referer):
            forms.flash_field("name", "m")
            assert session["field_errors"] == [["name", "m", expected]]

    def test_the_alert_carries_the_form_path_on_every_page_and_the_text_is_never_lost(self, logged_in_client):
        """Server side: the same alert is printed on both pages with `data-form`, and its text is on the page either way (the script's choice - under an input or left as the flash it already is -
        is the browser's and is tests/e2e/test_ui_polish.py)."""
        for page in ("/settings/api-keys", "/settings/appearance"):
            with logged_in_client.session_transaction() as sess:
                sess["field_errors"] = [["name", "A name is required.", "/subnets/add"]]
            html = logged_in_client.get(page).data.decode()
            assert 'data-field="name" data-form="/subnets/add"' in html and "A name is required." in html, page

    def test_the_two_element_shape_prints_an_empty_form_path_and_lands_on_any_page(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["field_errors"] = [["name", "an old-shape message"]]
        assert 'data-field="name" data-form=""' in logged_in_client.get("/settings/api-keys").data.decode()

    def test_the_script_moves_an_error_only_on_the_page_it_was_raised_for(self):
        base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        block = base[base.index("AX4 - an error that names one field is moved under it") :]
        assert "var formPath = alertEl.getAttribute('data-form');" in block
        assert "if (formPath && formPath !== window.location.pathname) return;" in block
        assert block.index("formPath !== window.location.pathname") < block.index("document.getElementById('f-' + ")

    def test_the_sign_in_page_prints_a_pending_error_as_a_flash_and_the_list_is_empty_afterward(self, app):
        c = app.test_client()
        with c.session_transaction() as sess:
            sess["field_errors"] = [["name", "A name is required.", "/subnets/add"]]
        html = c.get("/login").data.decode()
        assert "A name is required." in html and "data-field" not in html
        with c.session_transaction() as sess:
            assert "field_errors" not in sess

    def test_every_standalone_page_that_prints_flashes_also_prints_the_pending_field_errors(self):
        """The login page, the forced password change and the second factor are not built on base.html; a field error raised for a form must not wait in the session for the next page that is."""
        for name in ("login.html", "force_password_change.html", "mfa_challenge.html"):
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            assert "get_flashed_messages" in text and "take_field_errors" in text, name
            assert text.index("take_field_errors") < text.index("get_flashed_messages"), (
                f"{name}: field errors come first, as on base.html"
            )

    def test_the_forced_change_screen_prints_a_pending_error_as_a_flash(self, client, db):
        from tests.test_password_change_enforcement import _client_with_must_change_password

        c, _ = _client_with_must_change_password(client, db, username="q210fielderr1")
        with c.session_transaction() as sess:
            sess["field_errors"] = [["name", "A name is required.", "/subnets/add"]]
        html = c.get("/force-password-change").data.decode()
        assert "A name is required." in html and "data-field" not in html
        with c.session_transaction() as sess:
            assert "field_errors" not in sess


class TestTheByteBudget:
    """Q210 (AZ5 b, Y8): `MAX_FIELD_ERRORS` x `MAX_MESSAGE` is 6,000 characters and the signed session cookie is 4,093 bytes in all; with incompressible messages 16 errors passed it, where a browser may silently
    drop the whole cookie and sign the person out. The list is held to `MAX_FIELD_BYTES` whatever its count; what does not fit is flashed instead (never lost)."""

    @staticmethod
    def _messages(n, seed=210):
        rng = random.Random(seed)
        return [
            "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(forms.MAX_MESSAGE))
            for _ in range(n)
        ]

    def test_the_first_message_that_would_pass_the_budget_falls_back_to_a_flash(self, ctx):
        messages = self._messages(forms.MAX_FIELD_ERRORS)
        item = len(json.dumps(["f00", messages[0], ""]))
        fits = forms.MAX_FIELD_BYTES // (
            item + 2
        )  # n items serialize to n * (item + 2) bytes: the brackets and the n - 1 separators
        assert 1 <= fits < forms.MAX_FIELD_ERRORS, "the budget, not the count, is what bites here"
        for n, message in enumerate(messages):
            forms.flash_field(f"f{n:02d}", message)
        stored = session["field_errors"]
        assert len(stored) == fits
        assert len(json.dumps(stored)) <= forms.MAX_FIELD_BYTES
        assert [m for _c, m in get_flashed_messages(with_categories=True)] == messages[fits:], (
            "what did not fit is flashed, in order, and none of it is lost"
        )

    def test_a_short_message_is_not_held_to_the_incompressible_worst_case(self, ctx):
        for n in range(forms.MAX_FIELD_ERRORS):
            forms.flash_field(f"f{n:02d}", f"m{n}")
        assert len(session["field_errors"]) == forms.MAX_FIELD_ERRORS, (
            "twenty short errors are well inside the budget: the count cap, as before"
        )

    def test_the_redirects_cookie_stays_under_the_browsers_limit(self, logged_in_client):
        """The real route, the real client: the palette form quotes each submitted value, so it is Jen's longest list. Twelve incompressible values."""
        from jen.services import theme

        rng = random.Random(7)
        form = {
            token: "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(400))
            for token in theme.TOKENS
        }
        form["radius"] = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(400))
        r = logged_in_client.post("/settings/theme/custom", data=form)
        assert r.status_code == 302
        cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie" and v.startswith("session=")]
        assert cookies, "the refusal wrote the session"
        assert all(len(c.split(";", 1)[0]) < 4093 for c in cookies), [len(c.split(";", 1)[0]) for c in cookies]


class TestEveryHintIsTied:
    HINT = re.compile(r'<(?:div|small|span|p)\b[^>]*class="[^"]*\bform-hint\b[^"]*"[^>]*>')
    CONTROL = re.compile(r"<(?:input|select|textarea)\b[^>]*>")

    @staticmethod
    def _masked(text):
        return re.sub(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", lambda m: " " * len(m.group(0)), text, flags=re.S)

    def _group_spans(self, masked):
        """(start, end) of every `<div class="form-group...">` with its own closing tag."""
        spans = []
        for m in re.finditer(r'<div\b[^>]*class="[^"]*\bform-group\b', masked):
            depth = 0
            for t in re.finditer(r"<div\b|</div>", masked[m.start() :]):
                depth += 1 if t.group(0).startswith("<div") else -1
                if depth == 0:
                    spans.append((m.start(), m.start() + t.end()))
                    break
        return spans

    @pytest.mark.parametrize("path", sorted(TEMPLATES.glob("*.html")), ids=lambda p: p.name)
    def test_a_hint_inside_a_group_with_an_f_input_is_that_inputs_description(self, path):
        text = path.read_text(encoding="utf-8")
        masked = self._masked(text)
        spans = self._group_spans(masked)
        for h in self.HINT.finditer(text):
            inner = [s for s in spans if s[0] < h.start() < s[1]]
            if not inner:
                continue
            start, end = min(inner, key=lambda s: s[1] - s[0])
            in_group = [c for c in self.CONTROL.finditer(text, start, end) if re.search(r'\bid="f-[^"{]+"', c.group(0))]
            if len(in_group) != 1:
                continue  # a group with several inputs (a card wrapped in a form-group) has no ONE input its hints describe
            controls = [c for c in in_group if c.start() < h.start()]
            if not controls:
                continue
            ctl = controls[-1].group(0)
            ctl_id = re.search(r'\bid="(f-[^"{]+)"', ctl).group(1)
            hint_id = re.search(r'\bid="([^"]+)"', h.group(0))
            assert hint_id, (path.name, "a hint with no id", ctl_id, h.group(0)[:100])
            assert hint_id.group(1) in (re.search(r'aria-describedby="([^"]*)"', ctl) or [None, ""])[1].split(), (
                path.name,
                ctl_id,
                hint_id.group(1),
            )

    @pytest.mark.parametrize("path", sorted(TEMPLATES.glob("*.html")), ids=lambda p: p.name)
    def test_a_hint_that_carries_an_id_is_named_by_a_control(self, path):
        """Q210 (AZ5 c, Y15): the rule beta.4 shipped was keyed on `input` and the `id=\"f-<name>\"` convention, so two script-filled hints beside a `<select>` (`kea-mode-hint`, `edit-role-oidc-hint`)
        were tied to nothing - the sentence was on screen and never announced. A `.form-hint` with an id must be named by some `aria-describedby` in its template, on an input, a select, a textarea
        or the group it describes; a note that describes no control carries no id."""
        text = path.read_text(encoding="utf-8")
        named = {tok for value in re.findall(r'aria-describedby="([^"]*)"', text) for tok in value.split()}
        orphans = []
        for h in self.HINT.finditer(text):
            hint_id = re.search(r'\bid="([^"{]+)"', h.group(0))
            if hint_id and hint_id.group(1) not in named:
                orphans.append(hint_id.group(1))
        assert not orphans, (path.name, orphans)

    def test_the_two_selects_whose_hints_were_tied_to_nothing_name_them_now(self):
        kea = (TEMPLATES / "settings_kea.html").read_text(encoding="utf-8")
        users = (TEMPLATES / "users.html").read_text(encoding="utf-8")
        assert '<select name="connection_mode" id="kea-connection-mode" aria-describedby="kea-mode-hint">' in kea
        assert 'id="edit-role" class="u-046678" aria-describedby="edit-role-oidc-hint"' in users

    @pytest.mark.parametrize("path", sorted(TEMPLATES.glob("*.html")), ids=lambda p: p.name)
    def test_every_static_aria_describedby_id_exists_in_the_same_template(self, path):
        text = path.read_text(encoding="utf-8")
        ids = set(re.findall(r'\bid="([^"{]+)"', text))
        for value in re.findall(r'aria-describedby="([^"{]*)"', text):
            for token in value.split():
                assert token in ids, (path.name, token)

    def test_the_hidden_hint_filled_by_script_keeps_its_id_and_is_referenced(self):
        text = (TEMPLATES / "add_reservation.html").read_text(encoding="utf-8")
        assert 'id="f-subnet_id-hint" hidden' in text
        assert 'aria-describedby="f-subnet_id-hint"' in text


class TestTheConversionCount:
    """The listed routes carry no `flash(` whose message starts with a field's display name followed by a colon, and the count converted and left is reported by `conversion_counts`."""

    FILES = [
        "settings/theme.py",
        "settings/alerts.py",
        "settings/infrastructure.py",
        "settings/security.py",
        "ddns.py",
        "database.py",
        "users.py",
        "api.py",
        "subnets.py",
        "reservations.py",
    ]

    @staticmethod
    def conversion_counts():
        converted = left = 0
        for name in TestTheConversionCount.FILES:
            text = (ROUTES / name).read_text(encoding="utf-8")
            converted += len(re.findall(r"\bflash_field\(", text))
            left += len(re.findall(r"""\bflash\([^)]*?["']error["']\s*\)""", text, re.S))
        return converted, left

    def test_no_listed_route_flashes_a_converted_fields_name_colon_message(self):
        names = set()
        for name in self.FILES:
            names |= set(
                re.findall(r"""flash_field\(\s*f?["']([a-z0-9_-]+)["']""", (ROUTES / name).read_text(encoding="utf-8"))
            )
        assert len(names) > 30
        for name in self.FILES:
            text = (ROUTES / name).read_text(encoding="utf-8")
            for field in names:
                display = field.replace("_", " ")
                assert not re.search(r"""flash\(\s*f?["']""" + re.escape(display) + ": ", text, re.I), (name, field)

    def test_the_conversion_is_substantial_and_the_remainder_is_the_form_or_host_level_refusals(self):
        converted, left = self.conversion_counts()
        assert converted >= 50, converted
        assert left > 0

    def test_the_identity_guards_refusals_stay_flashes(self):
        text = (ROUTES / "settings" / "infrastructure.py").read_text(encoding="utf-8")
        assert "ConfigChangeRefused" in text
        for needle in ('flash_field("api_url", str(', "flash_field('api_url', str("):
            assert needle not in text

    def test_every_converted_name_is_a_valid_field_name(self):
        for name in self.FILES:
            text = (ROUTES / name).read_text(encoding="utf-8")
            for m in re.finditer(r"""flash_field\(\s*f?["']([^"']+)["']""", text):
                literal = m.group(1)
                if "{" in literal:
                    literal = re.sub(r"\{[^}]*\}", "x", literal)
                assert forms.FIELD_NAME.match(literal), (name, literal)


class TestEveryConvertedFieldHasItsInput:
    """A converted name lands under an input only when the page it redirects to has `id="f-<name>"`. The fallback is a flash, so a missing input loses nothing - but the ones the Q converted all have one."""

    # name -> the template it is printed on
    PAGES = {
        "api_url": "settings_kea.html",
        "api_ca": "settings_kea.html",
        "api_client_cert": "settings_kea.html",
        "api_client_key": "settings_kea.html",
        "kea6_api_url": "settings_kea.html",
        "d2_api_url": "settings_kea.html",
        "host": "settings_kea.html",
        "ssh_user": "settings_kea.html",
        "kea_conf": "settings_kea.html",
        "dhcp4_log_path": "settings_kea.html",
        "log_path": "settings_kea.html",
        "server_name": "settings_kea.html",
        "ha_mode": "settings_kea.html",
        "timeout_minutes": "settings_security.html",
        "max_attempts": "settings_security.html",
        "lockout_minutes": "settings_security.html",
        "issuer": "settings_security.html",
        "client_id": "settings_security.html",
        "default_role": "settings_security.html",
        "role_map": "settings_security.html",
        "subnet_map_default": "settings_security.html",
        "summary_time": "settings_alerts.html",
        "pool_exhaustion_free": "settings_alerts.html",
        "alert_threshold_pct": "settings_alerts.html",
        "zone-forward": "ddns.html",
        "zone-reverse": "ddns.html",
        "passphrase": "database.html",
        "passphrase_confirm": "database.html",
        "username": "users.html",
        "password": "users.html",
        "current_password": "user_profile.html",
        "new_password": "user_profile.html",
        "confirm_password": "user_profile.html",
        "name": "api_keys.html",
        "subnet_ids": "api_keys.html",
        "id": "add_subnet.html",
        "cidr": "add_subnet.html",
        "pool": "add_subnet.html",
        "routers": "add_subnet.html",
        "dns": "add_subnet.html",
        "subnet_id": "add_reservation.html",
        "ip": "add_reservation.html",
        "mac": "add_reservation.html",
        "hostname": "add_reservation.html",
        "dns_override": "add_reservation.html",
        "radius": "settings_appearance.html",
        "primary": "settings_appearance.html",
    }

    @pytest.mark.parametrize(("name", "template"), sorted(PAGES.items()))
    def test_the_input_exists(self, name, template):
        text = (TEMPLATES / template).read_text(encoding="utf-8")
        has = (
            f'id="f-{name}"' in text
            or re.search(r'id="f-\{\{ [a-z_]+ \}\}"', text)
            and template == "settings_appearance.html"
        )
        assert has, (name, template)
