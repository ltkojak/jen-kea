"""
tests/test_template_csrf.py
──────────────────────────────
v5.55.2 (Q65) — Settings → Appearance → Theme → "Install Default" 403'd
on every save: `templates/settings_appearance.html`'s theme-default form
had no `csrf_token` hidden input. `tests/test_plugin_template_csrf.py`
already has exactly this scanner for `plugins/*/templates/`, found live
the same way for the bundled plugins — the whole suite runs with
`WTF_CSRF_ENABLED=False` (conftest.py), so no route test can observe a
missing field, and nothing was scanning Jen's OWN templates the same way.

This is that same scanner turned on `templates/**/*.html`: 148 POST forms,
one without a token before this release. Imports `_POST_FORM_RE` from the
plugin test rather than redefining it — one regex, two coverage areas.

A form that legitimately posts to a CSRF-exempt endpoint (an API-key-
authenticated route, for instance) would need an entry in ALLOWED with the
reason; there are none today, so the list starts empty.
"""

import glob
from pathlib import Path

import pytest

from tests.test_plugin_template_csrf import _POST_FORM_RE

# (file, reason) — a template allowed a POST form with no csrf_token, and
# why. Empty on purpose; see the module docstring.
ALLOWED: dict[str, str] = {}


def _all_template_files():
    return sorted(glob.glob("templates/**/*.html", recursive=True))


class TestJenFormsHaveCsrfToken:
    def test_at_least_one_template_exists(self):
        # If this ever returns zero, the glob pattern broke silently and
        # every other test here would be a vacuous pass.
        files = _all_template_files()
        assert len(files) > 0, "no template files found — check the glob pattern"

    @pytest.mark.parametrize("template_path", _all_template_files())
    def test_every_post_form_includes_csrf_token(self, template_path):
        rel = Path(template_path).as_posix()
        if rel in ALLOWED:
            pytest.skip(ALLOWED[rel])
        content = Path(template_path).read_text(encoding="utf-8")
        post_forms = _POST_FORM_RE.findall(content)
        for i, form_html in enumerate(post_forms):
            assert "csrf_token" in form_html, (
                f"{template_path}: POST form #{i + 1} has no csrf_token field "
                f"— every submission through it will get a 403 "
                f"'session security token is missing or expired'. "
                f"Form starts: {form_html[:120]!r}"
            )

    def test_allowlist_entries_still_need_it(self):
        # Catches an ALLOWED entry going stale (the form it excused was
        # since given a token anyway, so the entry should be removed).
        for rel, reason in ALLOWED.items():
            path = Path(rel)
            assert path.exists(), rel
            content = path.read_text(encoding="utf-8")
            post_forms = _POST_FORM_RE.findall(content)
            assert any("csrf_token" not in f for f in post_forms), (
                f"{rel} is allow-listed ({reason!r}) for a form missing csrf_token "
                f"that is no longer missing one — remove the entry"
            )

    def test_detector_itself_catches_a_known_bad_form(self):
        # Regression guard for the regex/logic — the exact shape the real
        # bug shipped as (a <select> + Save button, no hidden field at all).
        broken_html = """
        <form method="POST" action="/settings/theme/default" class="u-a76d59">
            <select name="theme_default" class="u-97445a">
                <option value="dark">Dark</option>
            </select>
            <button type="submit" class="btn btn-primary btn-sm">Save</button>
        </form>
        """
        forms = _POST_FORM_RE.findall(broken_html)
        assert len(forms) == 1
        assert "csrf_token" not in forms[0]

    def test_detector_accepts_a_known_good_form(self):
        fixed_html = """
        <form method="POST" action="/settings/theme/default" class="u-a76d59">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <select name="theme_default" class="u-97445a">
                <option value="dark">Dark</option>
            </select>
            <button type="submit" class="btn btn-primary btn-sm">Save</button>
        </form>
        """
        forms = _POST_FORM_RE.findall(fixed_html)
        assert len(forms) == 1
        assert "csrf_token" in forms[0]
