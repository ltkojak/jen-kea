"""
tests/test_q249_c.py
────────────────────
v7.2.0-beta.7 (Q249), lane C - the page rows of the executing pass on v7.2.0-beta.6 that a source or a rendered page can hold (the browser's half is
tests/e2e/test_q249_c.py).

* BI1   a value written into a script is filtered WHOLE: no template gives `|tojson` a quoted fallback the filter does not reach (the Edit Subnet page
        wrote `&#34;&#34;` into its script when Kea's config set no renew-timer, and the script did not parse).
* BI2   the top row has a fourth fit level: favorites leave the row from the right (the measure is the browser's; the source is pinned here).
* BI5   About's "what is new" drops a parenthesized group that holds a tracking code WHOLE, words and all.
* BI11  Devices binds its edit dialog only where the dialog is drawn (the IPv6 view has none).
* BI18  Reports: a pool at most 1.25 times the fitted axis is inside the axis (the source; the chart is measured in the browser).
* C2    the field-error message carries the icon a flashed error carries.
* C5    the HA reset's confirmation button says Reset.
* C8    "sign in", not "login", on the MFA challenge and the SSO card.
* C10   "Reserved" is said of leases: the IP map's legend and the client page's IPv6 table say reservation.
* C4    the user guide says which column a narrow list keeps.
"""

import pathlib
import re

import pytest

from jen import extensions
from jen.services import changelog

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"


def _src(name):
    return (TEMPLATES / name).read_text(encoding="utf-8")


# ── BI1 ──────────────────────────────────────────────────────────────────────

EXPRESSION = re.compile(r"\{\{(.*?)\}\}", re.S)
# `value | tojson if value else '""'`: a filter binds tighter than the conditional, so the quoted fallback is printed as it is, autoescaped (`&#34;&#34;`)
UNFILTERED_FALLBACK = re.compile(r"""\belse\s+(?:'[^']*'|"[^"]*")\s*$""")


def _unfiltered_fallbacks(text):
    return [e.strip() for e in EXPRESSION.findall(text) if "tojson" in e and UNFILTERED_FALLBACK.search(e)]


class TestAScriptValueIsFilteredWhole:
    def test_the_measure_finds_the_shape_that_broke_the_page_and_not_the_fix(self):
        assert _unfiltered_fallbacks("""x: {{ kea.renew_timer | tojson if kea.renew_timer else '""' }},""")
        assert _unfiltered_fallbacks("""x: {{ kea.renew_timer | tojson if kea.renew_timer else "''" }},""")
        assert not _unfiltered_fallbacks(
            """x: {{ (kea.renew_timer if kea.renew_timer is not none else "") | tojson }},"""
        )
        assert not _unfiltered_fallbacks("""x: {{ (url_for('a') if family == 'v6' else url_for('b')) | tojson }}""")

    def test_no_template_in_the_tree_has_one(self):
        found = {}
        paths = sorted(TEMPLATES.rglob("*.html")) + sorted((ROOT / "plugins").glob("*/templates/**/*.html"))
        assert len(paths) > 100
        for path in paths:
            hits = _unfiltered_fallbacks(path.read_text(encoding="utf-8"))
            if hits:
                found[path.relative_to(ROOT).as_posix()] = hits
        assert not found, found

    def test_the_seven_values_of_the_edit_page_are_filtered_whole_and_a_zero_stays_a_zero(self):
        from jinja2 import Environment

        src = _src("edit_subnet.html")
        lines = re.findall(
            r"^\s+\w+:\s+(\{\{ \(kea\.(\w+) if kea\.\w+ is not none else \"\"\) \| tojson \}\}),$", src, re.M
        )
        assert sorted(name for _expr, name in lines) == [
            "preferred_lifetime",
            "rebind_timer",
            "rebind_timer",
            "renew_timer",
            "renew_timer",
            "valid_lifetime",
            "valid_lifetime",
        ]
        env = Environment(autoescape=True)
        for expr, name in lines:
            for value, written in (("", '""'), (None, '""'), (0, "0"), (900, "900")):
                assert env.from_string(expr).render(kea={name: value}) == written, (name, value)

    def test_the_page_script_holds_no_escaped_quote_when_kea_sets_no_timer(self, logged_in_client, mock_kea):
        # the suite's Kea answers a config with no subnet in it: every value of the page is the empty one, as with a config that sets no timer
        html = logged_in_client.get("/subnets/edit/1").get_data(as_text=True)
        script = html.split("var _orig = {", 1)[1].split("};", 1)[0]
        assert "&#34;" not in script and "&#39;" not in script, script
        for key in ("valid_lifetime", "renew_timer", "rebind_timer"):
            assert re.search(rf'{key}:\s+"",', script), (key, script)

    @pytest.mark.usefixtures("ipv6_flag_on")
    def test_the_ipv6_page_script_holds_none_either(self, logged_in_client, mock_kea, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.get("/subnets/edit6/1")
        assert resp.status_code == 200
        script = resp.get_data(as_text=True).split("var _orig = {", 1)[1].split("};", 1)[0]
        assert "&#34;" not in script and "&#39;" not in script, script
        for key in ("preferred_lifetime", "valid_lifetime", "renew_timer", "rebind_timer"):
            assert re.search(rf'{key}:\s+"",', script), (key, script)


# ── BI2 ──────────────────────────────────────────────────────────────────────


class TestTheTopRowHasAFourthLevel:
    def test_favorites_leave_from_the_right_until_nothing_spills(self):
        base = _src("base.html")
        fit = base.split("function jenNavFit() {", 1)[1].split("if (fitLinks) {", 1)[0]
        assert "while (level < 3 && spills()) { level += 1; set(level); }" in fit
        assert "while (kept > 0 && spills()) {" in fit and "favs[kept].classList.add('nav-fav-off');" in fit
        # every run starts from the whole row: a wider window brings them back
        assert fit.index("classList.remove('nav-fav-off')") < fit.index("set(0);")
        assert ".nav .nav-links .nav-fav-off { display: none; }" in base


# ── BI5 ──────────────────────────────────────────────────────────────────────


def _codes(text):
    return [t for t in changelog._TRACKING_TOKEN_RE.findall(text) if changelog._is_tracking_code(t)]


class TestAGroupWithACodeGoesWhole:
    @pytest.mark.parametrize(
        "before, after",
        [
            ("The top row (V10, V11, V14; additions 9, 10, 14) fits.", "The top row fits."),
            ("Colors (V12, V13, V48, V51, V54; additions 4, 5).", "Colors."),
            ("About (additions 2, 3, 6, 7, 15, 16; V33) is shorter.", "About is shorter."),
            ("the rule (BG3; BG5 written down) holds", "the rule holds"),
            ("Presence 1.2.7 (BF1 of the pass, a defect of 1.2.6).", "Presence 1.2.7."),
            ("*IPAM Lite (IPAM-3 of the audit):* a lookup", "*IPAM Lite:* a lookup"),
        ],
    )
    def test_the_words_beside_the_code_go_with_it(self, before, after):
        assert changelog.strip_tracking_codes(before) == after

    @pytest.mark.parametrize(
        "kept",
        [
            "(additions 4, 5)",
            "(redirects to HTTPS)",
            "(RFC 5280)",
            "(SHA256, as before)",
            "(D2 and its keys)",
            "(P-256)",
            "(K8s)",
            "(7.2.0-beta.6)",
            "(v5.65.10)",
            "(Ubuntu 22.04 and 24.04)",
            "(HTTP 302)",
            "(TLS1.3)",
        ],
    )
    def test_a_group_with_no_code_is_kept(self, kept):
        text = f"The page {kept} is shown."
        assert changelog.strip_tracking_codes(text) == text

    def test_the_real_file_keeps_no_code_in_parentheses_and_leaves_no_hole(self):
        plain = changelog.parse_changelog(limit=6)
        read = changelog.whats_new(limit=6)
        assert len(read) == 6 and [e["version"] for e in read] == [e["version"] for e in plain]
        dropped = 0
        for shown, whole in zip(read, plain, strict=True):
            for group in re.findall(r"\(([^()]*)\)", shown["html"]):
                assert not _codes(group), (shown["version"], group)
            dropped += sum(1 for group in re.findall(r"\(([^()]*)\)", whole["html"]) if _codes(group))
            # nothing is left where a group was: no empty pair and no space before a period that the file itself does not have
            assert shown["html"].count("()") <= whole["html"].count("()"), shown["version"]
            assert shown["html"].count(" .") <= whole["html"].count(" ."), shown["version"]
        assert dropped > 20, dropped

    def test_the_entry_the_pass_read_prints_no_code_at_all(self):
        """7.2.0-beta.6 said About no longer prints the codes, and seventeen stayed behind "More" in three groups that also held the word "additions"."""
        entries = {e["version"]: e for e in changelog.parse_changelog(for_reading=True)}
        whole = {e["version"]: e for e in changelog.parse_changelog()}
        version = "7.2.0-beta.6"
        if version not in entries:  # folded into its stable entry at promotion: the rule is held by the tests above
            pytest.skip("the 7.2.0-beta.6 heading is no longer in the file")
        assert len(_codes(whole[version]["html"])) > 17
        assert _codes(entries[version]["html"]) == []
        assert "additions 4, 5" not in entries[version]["html"]


# ── BI11 ─────────────────────────────────────────────────────────────────────


class TestDevicesBindsWhatIsDrawn:
    def test_no_listener_is_put_on_an_element_the_ipv6_view_does_not_draw(self):
        src = _src("devices.html")
        scripts = src.split("{% block scripts %}", 1)[1]
        # the dialog and everything in it sit inside `{% if view_mode != 'v6' %}`
        dialog = src.split("{% if view_mode != 'v6' %}", 1)[1].split("{% block scripts %}", 1)[0]
        for element_id in re.findall(r"document\.getElementById\('([\w-]+)'\)\.addEventListener", scripts):
            assert f'id="{element_id}"' not in dialog, element_id
        assert "if (editModalEl) editModalEl.addEventListener('click'" in scripts
        close = scripts.split("function closeEditModal() {", 1)[1].split("}", 1)[0]
        assert "document.getElementById('editModal').style" not in close


# ── BI18 ─────────────────────────────────────────────────────────────────────


class TestReportsPoolJustAboveTheAxis:
    def test_the_axis_takes_a_pool_within_a_quarter_of_its_top(self):
        src = _src("reports.html")
        assert "if (!toPool && pool > axis.max && pool <= axis.max * 1.25) axis = niceAxis(pool);" in src
        assert "const poolInRange = pool > 0 && (toPool || pool <= axis.max);" in src


# ── C2 ───────────────────────────────────────────────────────────────────────


class TestAFieldErrorCarriesTheErrorIcon:
    def test_the_alert_a_field_error_is_printed_as_has_the_icon_of_a_flashed_error(self):
        base = _src("base.html")
        alert = re.search(
            r'<div class="alert alert-error alert-flash" role="alert" data-field=.*?</div>', base, re.S
        ).group(0)
        assert '{{ icon("circle-x") }}<span class="alert-text">{{ message }}</span>' in alert
        assert "'error': 'circle-x'" in base  # the flashed error's own
        # and the script that moves it under its field takes the icon with it, and still writes the message as text
        moved = base.split("document.querySelectorAll('.alert[data-field]')", 1)[1].split("function clearField", 1)[0]
        assert "var errIcon = alertEl.querySelector('svg');" in moved
        assert "if (errIcon) err.appendChild(errIcon.cloneNode(true));" in moved
        assert "err.appendChild(document.createTextNode(text));" in moved and "innerHTML" not in moved

    def test_a_refused_form_prints_it(self, logged_in_client):
        resp = logged_in_client.post("/users/add", data={"username": "", "password": ""}, follow_redirects=True)
        html = resp.get_data(as_text=True)
        alerts = re.findall(
            r'<div class="alert alert-error alert-flash" role="alert" data-field="[^"]+"[^>]*>(.*?)</div>', html, re.S
        )
        assert alerts, "the refusal names no field"
        for alert in alerts:
            assert alert.lstrip().startswith("<svg") and "#i-circle-x" in alert.split("<span", 1)[0], alert


# ── C5, C8, C10, C4 ──────────────────────────────────────────────────────────


class TestWords:
    def test_the_ha_reset_confirmation_button_says_reset(self):
        src = _src("servers.html")
        form = src.split("action='reset') }}\"", 1)[1].split(">", 1)[0]
        assert 'data-confirm="{{ ha_actions[\'reset\'].confirm }}" data-confirm-label="Reset"' in " ".join(form.split())

    def test_sign_in_is_the_verb(self):
        assert "Back to sign in</a>" in _src("mfa_challenge.html") and "Back to login" not in _src("mfa_challenge.html")
        security = _src("settings_security.html")
        assert (
            "Automatically create an account on first SSO sign-in</label>" in security and "SSO login" not in security
        )

    def test_the_sso_card_says_it_on_the_page(self, logged_in_client):
        html = logged_in_client.get("/settings/security").get_data(as_text=True)
        assert "Automatically create an account on first SSO sign-in" in html and "first SSO login" not in html

    def test_the_ip_map_legend_says_has_a_reservation(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/ipmap").get_data(as_text=True)
        assert ">Has a reservation</span>" in html
        assert ">Reserved</span>" not in html

    def test_the_client_page_heads_its_ipv6_column_reservation(self):
        src = _src("client.html")
        assert "<th>IPv6 identifier</th><th>Subnet</th><th>Hostname</th><th>Reservation</th>" in src
        assert "<th>Reserved</th>" not in src

    def test_the_user_guide_says_which_column_a_narrow_list_keeps(self):
        guide = (ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
        assert "keeps the column it is sorted by when you first open it, and the row's menu" in guide
        assert "always keeps the column it is sorted by" not in guide

    def test_the_user_guide_says_what_the_top_row_gives_up_last(self):
        guide = (ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
        assert "and last the favorites at the right end leave the row, one at a time" in guide
