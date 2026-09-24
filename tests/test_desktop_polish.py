"""
tests/test_desktop_polish.py
─────────────────────────────
v5.56.4 (Q72) — desktop polish: keyboard/screen-reader basics, request
feedback (the #jen-progress bar and window.jenFetch), two-column Settings
at wide viewports, and sticky table headers.

The pure classes here (source-text checks, a stub-Jinja render of base.html
following tests/test_mobile_nav.py's `_render()` pattern) run with
`py -m pytest --noconftest tests/test_desktop_polish.py`. The e2e coverage
(focus order, the progress bar during a real request, the settings-kea
screenshot height) lives in tests/e2e/test_mobile.py, which already has the
`desktop` fixture and the PAGES list this Q's design reuses.
"""

import pathlib
import re

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader

from jen.routes.settings import nav as navmod
from jen.services import theme as thememod
from jen.services.icons import icon, nav_icon

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

# Every template that extends base.html gets window.jenFetch/#jen-progress
# for free; templates/mfa_challenge.html is a deliberate, standalone
# `<!DOCTYPE html>` page (not `{% extends "base.html" %}`, see its own
# `<head>`) reached mid-login before any Jen chrome exists, so it keeps a
# bare fetch(). Grep for a bare fetch( everywhere else and it should be gone.
BARE_FETCH_ALLOWED = {"mfa_challenge.html", "htmx.min.js"}


class TestJenFetchSweep:
    def test_no_template_calls_bare_fetch_except_the_documented_exception(self):
        offenders = []
        for path in TEMPLATES.glob("*.html"):
            if path.name in BARE_FETCH_ALLOWED:
                continue
            # window.jenFetch's own body legitimately calls the real fetch(),
            # and base.html's comments describe it in prose — neither is a
            # call site that needs switching, so only look at non-comment,
            # non-wrapper-definition lines.
            code_lines = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if not line.strip().startswith("//") and "return fetch(url, opts)" not in line
            ]
            if any(re.search(r"(?<![a-zA-Z])fetch\(", line) for line in code_lines):
                offenders.append(path.name)
        assert not offenders, offenders

    def test_jenfetch_and_progress_are_defined_in_base_html(self):
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert "window.jenFetch = function(url, opts)" in css
        assert "window.jenProgress = { start: start, stop: stop, reset: reset }" in css
        assert "htmx:beforeRequest" in css and "htmx:afterRequest" in css and "htmx:responseError" in css


class TestAccessibilityCss:
    def _css(self):
        return (TEMPLATES / "base.html").read_text(encoding="utf-8")

    def test_focus_visible_outline_exists_and_is_never_bare_outline_none(self):
        css = self._css()
        assert re.search(r":focus-visible[^{]*\{[^}]*outline:\s*2px solid var\(--primary\)", css, re.S)
        # Every rule that unconditionally sets outline:none is a plain
        # (non-:focus-visible) selector — the keyboard-focus case is always
        # covered by the rule above, which the cascade lets win (equal or
        # lower specificity, declared later in the file).
        for m in re.finditer(r"([^{}]+)\{[^{}]*outline:\s*none[^{}]*\}", css):
            assert ":focus-visible" not in m.group(1)

    def test_reduced_motion_rule_exists(self):
        assert "@media (prefers-reduced-motion: reduce)" in self._css()

    def test_skip_link_css_and_markup(self):
        css = self._css()
        assert ".skip-link" in css and ".skip-link:focus" in css
        html = _render()
        assert re.search(r'<body[^>]*>\s*<a href="#main" class="skip-link">Skip to content</a>', html)
        # tabindex="-1" is required, not decorative: without it the target
        # of a fragment link is never programmatically focusable, and
        # activating the skip link would scroll the page without actually
        # moving keyboard focus into it.
        assert '<main id="main" tabindex="-1">' in html
        assert re.search(r'<main id="main" tabindex="-1">.*<div class="container">', html, re.S)

    def test_aria_labels_on_the_audited_nav_controls(self):
        html = _render()
        assert 'aria-label="Theme"' in html  # already there since Q63
        assert 'aria-label="Account"' in html  # avatar
        assert 'aria-label="Keyboard shortcuts"' in html
        assert 'id="kb-modal-close-btn" aria-label="Close"' in html
        # Every action-menu kebab (row actions) already carries one.
        assert html.count('class="action-menu-btn" aria-label="Actions"') == 0  # none rendered w/o rows in the stub

    def test_flash_messages_carry_role_and_aria_live(self):
        html = _render(flashes=[("success", "Saved."), ("error", "Nope.")])
        assert '<div class="alert alert-success" role="status" aria-live="polite">Saved.</div>' in html
        assert '<div class="alert alert-error" role="alert">Nope.</div>' in html


class TestProgressBarMarkup:
    def test_jen_progress_is_the_first_thing_after_the_skip_link(self):
        html = _render()
        body = html.split("<body", 1)[1]
        skip_idx = body.index('class="skip-link"')
        bar_idx = body.index('id="jen-progress"')
        assert skip_idx < bar_idx

    def test_progress_bar_css_and_reduced_motion_variant(self):
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert "#jen-progress {" in css and "#jen-progress.active {" in css
        assert "@keyframes jen-progress-sweep" in css
        assert re.search(r"prefers-reduced-motion: reduce\)\s*\{\s*#jen-progress\.active::after", css, re.S)

    def test_full_page_submit_spinner_css_is_aria_busy_driven(self):
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert '[aria-busy="true"]' in css
        assert "@keyframes jen-spin" in css

    def test_wire_dispatch_begins_full_page_submit_before_every_submit_call(self):
        # The two data-confirm branches and data-submit call form.submit()
        # directly (the DOM method, which never fires the 'submit' event) —
        # each must call jenBeginFullPageSubmit itself, or a confirm-gated
        # full-page form would never show the spinner or disable its button.
        js = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        calls_before_submit = re.findall(r"jenBeginFullPageSubmit\([^)]*\);\s*(?:el|f)\.submit\(\);", js)
        assert len(calls_before_submit) == 3  # both data-confirm branches + data-submit
        assert len(re.findall(r"jenBeginFullPageSubmit\(", js)) >= 3
        assert "document.addEventListener('submit', function(e) {" in js
        assert "window.addEventListener('pageshow', jenResetFullPageSubmits);" in js


class TestTwoColumnSettings:
    def test_settings_cols_css_exists_at_1280(self):
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        m = re.search(r"@media \(min-width: 1280px\)\s*\{(.*?)\n        \}", css, re.S)
        assert m, "no @media (min-width: 1280px) block found"
        block = m.group(1)
        assert "columns: 2" in block
        assert ".settings-cols .card { break-inside: avoid; }" in block
        assert ".settings-cols .card--wide { column-span: all; }" in block

    # Each opening tag paired with the literal text immediately after the
    # last card in that file (before {% endif %}/{% endblock %}/the next
    # <script> — whichever ends the run of cards there) that closes it.
    # Hardcoded per file rather than counting <div>/</div> pairs generically:
    # settings_kea.html's direct_socket_setup macro has an {% if %}/{% else %}
    # with a different div count per branch, which is fine at render time
    # (only one branch ever executes) but makes a whole-file raw-text div
    # count meaningless.
    WRAP_CLOSES = {
        "settings_kea.html": '<div id="config-drift-results" class="u-b20d1a"></div>\n</div>\n{% endif %}\n</div>\n',
        "settings_security.html": (
            '<div class="form-hint u-8a77e5">Ports are set on '
            '<a href="/settings/system#sys-ports">System → Ports &amp; threads</a>.</div>\n</div>\n</div>\n{% endblock %}'
        ),
        "settings_system.html": '<button type="submit" class="btn btn-primary">{{ icon("save") }} Save</button>\n    </form>\n</div>\n</div>\n\n<script',
        "settings_alerts.html": (
            '<button type="submit" class="btn btn-primary u-8a77e5">Save Metrics Settings</button>\n'
            "    </form>\n</div>\n</div>\n{% endblock %}"
        ),
        "settings_appearance.html": "    </details>\n</div>\n</div>\n{% endblock %}",
    }

    def test_every_chip_toc_settings_page_wraps_its_cards(self):
        for name, closer in self.WRAP_CLOSES.items():
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            assert text.count('<div class="settings-cols">') == 1, name
            assert closer in text, name

    def test_wide_cards_are_marked(self):
        alerts = (TEMPLATES / "settings_alerts.html").read_text(encoding="utf-8")
        assert '<div class="card card--wide" id="al-templates">' in alerts
        appearance = (TEMPLATES / "settings_appearance.html").read_text(encoding="utf-8")
        assert '<div class="card card--wide" id="app-theme">' in appearance


class TestStickyTableHeaders:
    def test_sticky_header_css_uses_the_shared_offset_variable(self):
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        assert "--sticky-top: 56px;" in css
        assert "body.has-strip { --sticky-top: 96px; }" in css
        m = re.search(r"\.table-wrap thead th \{([^}]*)\}", css)
        assert m, "no sticky thead th rule found"
        rule = m.group(1)
        assert "position: sticky" in rule and "top: var(--sticky-top)" in rule

    def test_section_tabs_has_a_deterministic_height(self):
        # min-height (not just padding) makes --sticky-top's 96px an exact
        # match instead of "however tall the tab labels happen to render".
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        m = re.search(r"\.section-tabs \{([^}]*)\}", css)
        assert "min-height: 40px" in m.group(1)

    def test_has_strip_class_follows_nav_strip(self):
        with_strip = _render(endpoint="leases.leases")
        without_strip = _render(endpoint="profile.profile", authenticated=True, strip=False)
        assert 'class="has-tabbar has-strip"' in with_strip
        # "has-strip" also legitimately appears in the CSS rule
        # (body.has-strip { --sticky-top: 96px; }) regardless of which body
        # class actually renders — check the <body ...> tag specifically.
        body_tag = re.search(r"<body[^>]*>", without_strip).group(0)
        assert "has-strip" not in body_tag
        assert 'class="has-tabbar"' in body_tag

    def test_table_wrap_is_not_a_scroll_container_at_desktop_widths(self):
        """v5.58.1 (Q87) — .table-wrap { overflow-x: auto } (needed on a
        phone) made the wrapper the nearest ancestor with a scrolling
        mechanism, so a sticky th stuck to THAT box instead of the
        viewport, on every desktop table, not just inside a CSS
        multi-column container (Q74 step 0's diagnosis was a red
        herring, since corrected). At desktop widths overflow-x is unset
        so nothing inside .table-wrap can stick to it; sideways scroll
        becomes the opt-in .table-wrap--scroll, whose header is static
        since sticky cannot work inside a real scroll container."""
        css = (TEMPLATES / "base.html").read_text(encoding="utf-8")
        m = re.search(r"@media \(min-width: 769px\)\s*\{(.*?)\n\s*\}\n", css, re.DOTALL)
        assert m, "no @media (min-width: 769px) block found"
        block = m.group(1)
        assert ".table-wrap { overflow-x: visible; }" in block
        assert ".table-wrap--scroll { overflow-x: auto; }" in block
        assert ".table-wrap--scroll thead th { position: static; }" in block
        assert ".settings-cols" not in block, "the Q74 multi-column exclusion should be removed, not just unused"


PILL = None


def _render(role="admin", endpoint="leases.leases", authenticated=True, flashes=None, strip=None):
    env = Environment(loader=ChoiceLoader([DictLoader({}), FileSystemLoader(str(TEMPLATES))]))
    env.globals.update(
        icon=icon,
        nav_icon=nav_icon,
        csrf_token=lambda: "tok",
        url_for=lambda ep, **kw: "/" + ep,
        get_flashed_messages=lambda **kw: flashes or [],
    )

    class U:
        is_authenticated = authenticated
        username = "alice"
        all_subnets = True

    class R:
        args = {}

    R.endpoint = endpoint
    U.role = role

    nav_ctx = navmod.nav_context(endpoint, role if authenticated else None, [])
    if strip is False:
        nav_ctx = {**nav_ctx, "strip": []}

    theme_css = [
        (tid, thememod.render_css(tid, p["tokens"], p["radius"], p["mono_ui"], p["color_scheme"]))
        for tid, p in thememod.PRESETS.items()
    ]
    theme_presets = [(tid, p["name"]) for tid, p in thememod.PRESETS.items()]
    return env.get_template("base.html").render(
        current_user=U,
        request=R,
        csp_nonce="n0nce",
        jen_version="5.56.4",
        nav=nav_ctx,
        getting_started_pill=PILL,
        plugin_nav_items=[],
        theme_css=theme_css,
        theme_presets=theme_presets,
        theme_default="dark",
        theme_custom=None,
        theme_meta_color=thememod.PRESETS["dark"]["tokens"]["primary"],
    )
