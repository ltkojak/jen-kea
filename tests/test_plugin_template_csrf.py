"""
tests/test_plugin_template_csrf.py
─────────────────────────────────────
Found live: every POST form across both bundled plugins (5 total — 2 in
IPAM, 3 in network-discovery) was missing its csrf_token hidden input,
causing a guaranteed 403 "session security token is missing or expired"
on every submission. csrf_token() is registered as an app-wide Jinja
global via a context processor (jen/__init__.py) and IS available
inside plugin templates — it just was never called in any of these
forms.

This wasn't caught by any existing test because the whole suite runs
with WTF_CSRF_ENABLED=False by default (mirroring Flask-WTF's own
config key, set in conftest.py), which is the right default for
testing application logic without CSRF noise — but it meant this
specific class of bug (a form silently missing its token field) had no
test surface at all.

Rather than one narrow test for the specific route that was reported,
this scans every <form method="POST"...> block in every current and
future plugin template file and asserts each one contains csrf_token
somewhere before its closing </form> — a structural check that
protects the whole plugin ecosystem, not just the one route that
happened to get reported.
"""

import glob
import re

import pytest

# Matches a <form ...method="POST"...> opening tag through its closing
# </form>, non-greedy so it doesn't span into a sibling form. Case-
# insensitive since HTML attribute casing isn't guaranteed consistent.
_POST_FORM_RE = re.compile(
    r'<form\b[^>]*\bmethod\s*=\s*["\']POST["\'][^>]*>.*?</form>',
    re.IGNORECASE | re.DOTALL,
)


def _all_plugin_template_files():
    return sorted(glob.glob("plugins/*/templates/**/*.html", recursive=True))


class TestPluginFormsHaveCsrfToken:
    def test_at_least_one_plugin_template_exists(self):
        # If this ever returns zero, the glob pattern broke silently
        # and every other test in this file would be a vacuous pass —
        # guard against that specifically.
        files = _all_plugin_template_files()
        assert len(files) > 0, "no plugin template files found — check the glob pattern"

    @pytest.mark.parametrize("template_path", _all_plugin_template_files())
    def test_every_post_form_includes_csrf_token(self, template_path):
        content = open(template_path).read()
        post_forms = _POST_FORM_RE.findall(content)
        for i, form_html in enumerate(post_forms):
            assert "csrf_token" in form_html, (
                f"{template_path}: POST form #{i + 1} has no csrf_token field "
                f"— every submission through it will get a 403 "
                f"'session security token is missing or expired'. "
                f"Form starts: {form_html[:120]!r}"
            )

    def test_detector_itself_catches_a_known_bad_form(self):
        # Regression guard for the regex/logic itself — confirms this
        # test would actually have caught the real bug that prompted
        # it, using the exact form HTML that shipped broken.
        broken_html = '''
        <form id="edit-form" method="POST" action="/network/ipam/entry/1">
            <input type="hidden" name="ip" id="edit-ip-input">
            <button type="submit">Save</button>
        </form>
        '''
        forms = _POST_FORM_RE.findall(broken_html)
        assert len(forms) == 1
        assert "csrf_token" not in forms[0]

    def test_detector_accepts_a_known_good_form(self):
        fixed_html = '''
        <form id="edit-form" method="POST" action="/network/ipam/entry/1">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="ip" id="edit-ip-input">
            <button type="submit">Save</button>
        </form>
        '''
        forms = _POST_FORM_RE.findall(fixed_html)
        assert len(forms) == 1
        assert "csrf_token" in forms[0]
