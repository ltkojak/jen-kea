"""
tests/test_password_toggle.py
─────────────────────────────
v5.70.0-beta.4 (Q208, AX7): every password field has a show/hide toggle, made by ONE script - no template carries the markup. The script lives in `templates/_password_toggle.html`, which base.html
includes AND the two sign-in pages that are not built on base.html (login.html, force_password_change.html) include too: a named deviation from "ONE script in base.html", because those pages
would otherwise have no toggle at all. Pure source tests; the browser journey is tests/e2e/test_password_toggle.py.
"""

import pathlib
import re

import pytest

T = pathlib.Path("templates")
PARTIAL = (T / "_password_toggle.html").read_text(encoding="utf-8")
STANDALONE = ["login.html", "force_password_change.html", "mfa_challenge.html"]


class TestNoTemplateCarriesTheMarkup:
    def test_the_toggle_markup_exists_only_in_the_one_script_file(self):
        base = (T / "base.html").read_text(encoding="utf-8")
        assert 'class="pw-toggle"' not in base and 'class="pw-wrap"' not in base
        for p in T.glob("*.html"):
            if p.name in ("_password_toggle.html", "base.html"):
                continue  # (base.html NAMES the class in the print sheet's selector list; it does not make one)
            text = p.read_text(encoding="utf-8")
            assert "pw-toggle" not in text and "pw-wrap" not in text, p.name

    def test_the_static_js_directory_has_no_second_copy(self):
        assert not [
            p
            for p in pathlib.Path("static/js").glob("*.js")
            if p.name != "htmx.min.js" and "pw-toggle" in p.read_text(encoding="utf-8")
        ]

    def test_base_includes_the_enhancer_once(self):
        assert (T / "base.html").read_text(encoding="utf-8").count('{% include "_password_toggle.html" %}') == 1


class TestTheEnhancer:
    def test_it_is_nonced_and_runs_on_load_and_after_every_swap(self):
        assert '<script nonce="{{ csp_nonce }}">' in PARTIAL
        assert "document.addEventListener('DOMContentLoaded'" in PARTIAL
        assert "document.addEventListener('htmx:afterSettle'" in PARTIAL

    def test_the_button_is_reachable_by_keyboard_and_says_what_it_does(self):
        assert "tabindex" not in PARTIAL.lower()
        assert "btn.type = 'button'" in PARTIAL
        assert "'Show password'" in PARTIAL and "'Hide password'" in PARTIAL
        assert "aria-pressed" in PARTIAL

    def test_a_click_flips_type_label_pressed_and_icon(self):
        assert "input.type = show ? 'text' : 'password'" in PARTIAL
        assert "btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password')" in PARTIAL
        assert "btn.setAttribute('aria-pressed', show ? 'true' : 'false')" in PARTIAL
        assert "btn.innerHTML = show ? EYE_OFF : EYE" in PARTIAL

    def test_an_input_is_enhanced_once(self):
        assert "hasAttribute('data-pw-enhanced')" in PARTIAL

    def test_autocomplete_is_untouched(self):
        assert "autocomplete" not in PARTIAL

    def test_the_layout_is_a_flex_row_with_the_input_growing(self):
        assert re.search(r"\.pw-wrap \{[^}]*display: flex[^}]*align-items: center", PARTIAL)
        assert re.search(r"\.pw-wrap > input \{[^}]*flex: 1 1 auto[^}]*min-width: 0", PARTIAL)

    def test_the_icons_are_inline_because_the_standalone_pages_have_no_sprite(self):
        assert "<use" not in PARTIAL and PARTIAL.count("<svg") == 2

    def test_the_toggle_is_a_button_so_the_guards_form_data_never_includes_it(self):
        assert "createElement('button')" in PARTIAL

    @pytest.mark.parametrize("name", STANDALONE)
    def test_each_page_with_a_password_field_not_built_on_base_includes_it(self, name):
        text = (T / name).read_text(encoding="utf-8")
        assert "extends" not in text
        if 'type="password"' in text:
            assert '{% include "_password_toggle.html" %}' in text

    def test_every_template_with_a_password_input_reaches_the_enhancer(self):
        for p in T.glob("*.html"):
            text = p.read_text(encoding="utf-8")
            if 'type="password"' in text and p.name != "_password_toggle.html":
                assert "{% extends" in text or '{% include "_password_toggle.html" %}' in text, p.name

    def test_the_password_fields_of_the_item_are_all_still_there(self):
        count = sum(p.read_text(encoding="utf-8").count('type="password"') for p in T.glob("*.html"))
        assert count >= 40
