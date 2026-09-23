"""
tests/test_theme.py
──────────────────────
v5.55.0 (Q63) — jen/services/theme.py is pure (no Flask/DB), so most of
this runs straight against it: render_css()'s output, validate_palette()'s
injection boundary, and the WCAG contrast maths. The other half is the
"hex wall" — a repo-wide sweep asserting no template that extends
base.html (nor ui-classes.css, nor a template-inline <script>) still
carries a literal `#rrggbb`/`#rgb` color: every one of those was either
converted to a `var(--token)` / `color-mix(in srgb, var(--token) N%,
transparent)` in this release or explicitly allow-listed below with a
reason.

`dark` and `light` are pinned byte-identical to their pre-Q63 literal
values — the default install LOOK does not change; only *where* the
values live does.
"""

import pathlib
import re

import pytest

from jen.services import theme

TEMPLATES = pathlib.Path("templates")

# Files that legitimately still carry a literal hex color, and why. Every
# other template that extends base.html (or is `_`-prefixed and rendered
# into one) must be hex-clean — that's the point of the wall.
ALLOWED_HEX_FILES = {
    # Standalone pages (no {% extends "base.html" %}) — they don't load
    # base.html's generated token blocks in the first place, so nothing
    # here could reference a theme token even if it wanted to.
    "error.html": "standalone page, no base.html token blocks",
    "force_password_change.html": "standalone page, no base.html token blocks",
    "login.html": "standalone page, no base.html token blocks",
    "mfa_challenge.html": "standalone page, no base.html token blocks",
    # A categorical per-device-type palette (router/camera/phone/…),
    # jen/routes/*.py's DEVICE_TYPE_DISPLAY — genuinely many distinct
    # colors keyed by device type, not a themeable tint. '#555555' here
    # is the shared "unknown type" fallback both files use.
    "_device_badge.html": "categorical device-type palette (DEVICE_TYPE_DISPLAY), not a theme token",
    "_device_rows.html": "same DEVICE_TYPE_DISPLAY fallback as _device_badge.html",
    # Settings → Appearance: the pre-Q63 branding nav-color form's default/
    # placeholder value (an admin-chosen arbitrary hex, not a theme token),
    # and the Q63 Theme card's own hex-format examples (<code>#1a1a2a</code>
    # in the help text, a placeholder="#000000" on a color field) — all
    # data/text an admin reads or types, never a CSS declaration Jinja
    # renders unescaped. The actual custom-palette values themselves never
    # appear as source-file hex; they come from validate_palette()'d form
    # data via Jinja variables, not literals in this file.
    "settings_appearance.html": "branding nav-color default + Theme card's own hex-format examples/placeholders, never a CSS declaration",
    # theme.py itself is the one place hex is the actual point.
}

HEX_RE = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b")
EXTENDS_RE = re.compile(r"""{%\s*extends\s+["']base\.html["']""")


def _extends_base(text: str) -> bool:
    return bool(EXTENDS_RE.search(text))


def _is_partial_of_base_pages(path: pathlib.Path) -> bool:
    # `_`-prefixed partials don't extend base.html themselves (they're
    # {% include %}'d or htmx-swapped into a page that does) — in scope
    # for the wall unless allow-listed above.
    return path.name.startswith("_")


class TestHexWall:
    def test_no_hex_literal_in_a_themed_template(self):
        offenders = []
        for path in sorted(TEMPLATES.glob("*.html")):
            if path.name in ALLOWED_HEX_FILES:
                continue
            text = path.read_text(encoding="utf-8")
            if not (_extends_base(text) or _is_partial_of_base_pages(path)):
                continue
            hits = HEX_RE.findall(text)
            if hits:
                offenders.append((path.name, hits))
        assert offenders == [], f"hex literals found in themed templates: {offenders}"

    def test_ui_classes_css_is_hex_clean(self):
        css = pathlib.Path("static/css/ui-classes.css").read_text(encoding="utf-8")
        assert HEX_RE.findall(css) == []

    def test_allowlist_files_actually_still_have_hex(self):
        # Catches an allow-list entry going stale (the hex it was excusing
        # got converted anyway, so the exception should be removed).
        for name in ALLOWED_HEX_FILES:
            path = TEMPLATES / name
            assert path.exists(), name
            assert HEX_RE.search(path.read_text(encoding="utf-8")), (
                f"{name} is allow-listed for a hex literal that is no longer there — remove the entry"
            )

    def test_static_js_files_are_hex_clean(self):
        # The two vendored files (htmx, chart.umd) are third-party as-is;
        # anything else under static/js/ is Jen's own and must be clean.
        js_dir = pathlib.Path("static/js")
        for path in sorted(js_dir.glob("*.js")):
            if path.name in ("htmx.min.js", "chart.umd.min.js"):
                continue
            assert HEX_RE.findall(path.read_text(encoding="utf-8")) == [], path.name


class TestPresetsPinned:
    """The default look must not change. Pin dark and light to their
    pre-Q63 literal values (theme.py) and their concatenated CSS output
    to the exact rule base.html used to hand-write."""

    def test_dark_tokens_are_byte_identical_to_pre_q63(self):
        assert theme.PRESETS["dark"]["tokens"] == {
            "bg": "#0d0d0d",
            "surface": "#141414",
            "surface2": "#1c1c1c",
            "surface3": "#252525",
            "border": "#2a2a2a",
            "text": "#e0e0e0",
            "text_muted": "#666",
            "primary": "#00b4d8",
            "success": "#2ecc71",
            "warning": "#f39c12",
            "danger": "#e74c3c",
        }
        assert theme.PRESETS["dark"]["radius"] == 6
        assert theme.PRESETS["dark"]["mono_ui"] is False
        assert theme.PRESETS["dark"]["color_scheme"] == "dark"

    def test_light_tokens_are_byte_identical_to_pre_q63(self):
        assert theme.PRESETS["light"]["tokens"] == {
            "bg": "#f0f2f5",
            "surface": "#ffffff",
            "surface2": "#f8f9fa",
            "surface3": "#eceff3",
            "border": "#dee2e6",
            "text": "#212529",
            "text_muted": "#6c757d",
            "primary": "#0077b6",
            "success": "#198754",
            "warning": "#fd7e14",
            "danger": "#dc3545",
        }
        assert theme.PRESETS["light"]["radius"] == 6

    def test_dark_render_css_matches_the_old_hand_written_block(self):
        css = theme.render_css("dark", **{k: v for k, v in theme.PRESETS["dark"].items() if k != "name"})
        assert css == (
            ':root[data-theme="dark"]{color-scheme:dark;'
            "--bg:#0d0d0d;--surface:#141414;--surface2:#1c1c1c;--surface3:#252525;"
            "--border:#2a2a2a;--text:#e0e0e0;--text-muted:#666;--primary:#00b4d8;"
            "--success:#2ecc71;--warning:#f39c12;--danger:#e74c3c;--radius:6px;}"
        )

    def test_phosphor_gets_a_desktop_only_mono_ui_rule(self):
        css = theme.render_css("phosphor", **{k: v for k, v in theme.PRESETS["phosphor"].items() if k != "name"})
        assert '@media (min-width:769px){:root[data-theme="phosphor"]{--font-ui:var(--font-mono);}}' in css

    def test_non_mono_presets_have_no_font_ui_override(self):
        for tid in ("dark", "light", "contrast", "slate", "ember", "retro"):
            css = theme.render_css(tid, **{k: v for k, v in theme.PRESETS[tid].items() if k != "name"})
            assert "--font-ui" not in css

    def test_preset_ids_order_is_dark_light_contrast_phosphor_slate_ember_retro(self):
        assert theme.PRESET_IDS == ("dark", "light", "contrast", "phosphor", "slate", "ember", "retro")

    def test_retro_is_an_explicit_light_scheme_despite_its_teal_background(self):
        # guess_color_scheme() would call this bg "dark" — retro pins it.
        assert theme.PRESETS["retro"]["color_scheme"] == "light"
        css = theme.render_css("retro", **{k: v for k, v in theme.PRESETS["retro"].items() if k != "name"})
        assert "color-scheme:light" in css

    def test_retro_css_carries_its_bevel_and_title_bar_rules(self):
        css = theme.render_css("retro", **{k: v for k, v in theme.PRESETS["retro"].items() if k != "name"})
        assert 'data-theme="retro"] .card' in css
        assert 'data-theme="retro"] .btn:active' in css
        assert 'data-theme="retro"] .nav{' in css
        assert "background:#000080" in css

    def test_extra_css_is_absent_from_every_other_presets_output(self):
        for tid in ("dark", "light", "contrast", "phosphor", "slate", "ember"):
            assert theme.PRESETS[tid].get("extra_css", "") == ""
            css = theme.render_css(tid, **{k: v for k, v in theme.PRESETS[tid].items() if k != "name"})
            assert "border-color:#ffffff #808080" not in css
            assert "#000080" not in css

    def test_retros_nav_control_contrast_is_a_documented_extra_css_only_fix(self):
        # v5.56.1 (Q68f) — palette_warnings() only ever inspects a
        # preset's tokens, never extra_css, so it has no way to see (or
        # flag) that the navy nav from extra_css needed its own white-
        # on-navy override for the theme toggle / version string / kb
        # button — that's why the real guard is the e2e test
        # (TestRetroNavContrast), not a unit assertion on this function.
        assert theme.palette_warnings(theme.PRESETS["retro"]["tokens"]) == []
        css = theme.PRESETS["retro"]["extra_css"]
        assert ".theme-toggle{" in css or ".theme-toggle," in css
        assert "#kb-hint-btn" in css


class TestEveryPresetPassesItsOwnContrastFloor:
    @pytest.mark.parametrize("preset_id", list(theme.PRESETS))
    def test_no_palette_warnings(self, preset_id):
        warnings = theme.palette_warnings(theme.PRESETS[preset_id]["tokens"])
        assert warnings == [], f"{preset_id}: {warnings}"


class TestContrastRatio:
    def test_black_on_white_is_21_to_1(self):
        assert theme.contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=0.01)

    def test_identical_colors_are_1_to_1(self):
        assert theme.contrast_ratio("#123456", "#123456") == pytest.approx(1.0, abs=0.001)

    def test_is_symmetric(self):
        a, b = theme.contrast_ratio("#0d0d0d", "#e0e0e0"), theme.contrast_ratio("#e0e0e0", "#0d0d0d")
        assert a == pytest.approx(b, abs=1e-9)

    def test_accepts_3_digit_shorthand(self):
        assert theme.contrast_ratio("#000", "#fff") == pytest.approx(21.0, abs=0.01)

    def test_high_contrast_preset_clears_wcag_aaa_on_text(self):
        tokens = theme.PRESETS["contrast"]["tokens"]
        assert theme.contrast_ratio(tokens["text"], tokens["bg"]) >= 7.0


class TestGuessColorScheme:
    def test_dark_background_guesses_dark(self):
        assert theme.guess_color_scheme(theme.PRESETS["dark"]["tokens"]) == "dark"

    def test_light_background_guesses_light(self):
        assert theme.guess_color_scheme(theme.PRESETS["light"]["tokens"]) == "light"


class TestValidatePalette:
    def _valid_form(self, **overrides):
        form = {name: theme.PRESETS["dark"]["tokens"][name] for name in theme.TOKENS}
        form["radius"] = "6"
        form["mono_ui"] = "on"
        form.update(overrides)
        return form

    def test_a_full_valid_form_round_trips(self):
        result, errors = theme.validate_palette(self._valid_form())
        assert errors == []
        # validate_palette always normalizes to 6-digit hex, even when the
        # submitted value (dark's own "#666") was 3-digit shorthand.
        expected = dict(theme.PRESETS["dark"]["tokens"])
        expected["text_muted"] = "#666666"
        assert result["tokens"] == expected
        assert result["radius"] == 6
        assert result["mono_ui"] is True

    def test_3_digit_shorthand_is_accepted_and_normalized(self):
        result, errors = theme.validate_palette(self._valid_form(text_muted="#666"))
        assert errors == []
        assert result["tokens"]["text_muted"] == "#666666"

    @pytest.mark.parametrize(
        "bad_value",
        [
            "url(javascript:alert(1))",
            "red; background:url(x)",
            "#12345678",  # 8-digit / alpha hex not accepted
            "expression(alert(1))",
            "red",  # named colors rejected — whitelist is hex-only
            "",
            "#12",
            "#1234567",
            "rgb(0,0,0)",
        ],
    )
    def test_rejects_anything_not_exactly_3_or_6_digit_hex(self, bad_value):
        result, errors = theme.validate_palette(self._valid_form(primary=bad_value))
        assert errors != []
        assert "primary" not in result["tokens"]

    def test_semicolon_and_brace_injection_attempts_are_rejected(self):
        for payload in ("#fff;}body{background:red", "#fff}", "#fff;color:red"):
            result, errors = theme.validate_palette(self._valid_form(bg=payload))
            assert errors != []
            assert "bg" not in result["tokens"]

    def test_radius_out_of_range_is_rejected(self):
        _, errors = theme.validate_palette(self._valid_form(radius="17"))
        assert any("radius" in e for e in errors)
        _, errors = theme.validate_palette(self._valid_form(radius="-1"))
        assert any("radius" in e for e in errors)

    def test_radius_non_numeric_is_rejected(self):
        _, errors = theme.validate_palette(self._valid_form(radius="6px"))
        assert any("radius" in e for e in errors)

    @pytest.mark.parametrize(
        "raw,expected", [("1", True), ("true", True), ("on", True), ("", False), ("0", False), ("off", False)]
    )
    def test_mono_ui_coercion(self, raw, expected):
        result, errors = theme.validate_palette(self._valid_form(mono_ui=raw))
        assert errors == []
        assert result["mono_ui"] is expected

    def test_every_field_missing_reports_every_field(self):
        _, errors = theme.validate_palette({})
        # 11 tokens + radius; mono_ui has a safe falsy default so it never errors
        assert len(errors) == len(theme.TOKENS) + 1

    def test_extra_css_in_the_form_is_ignored_not_stored(self):
        # extra_css is a fixed, built-in-preset-only string (Retro's bevels) —
        # the custom-palette form has no such field, and even a submitted one
        # must never reach the saved palette.
        result, errors = theme.validate_palette(self._valid_form(extra_css=":root{background:red}"))
        assert errors == []
        assert "extra_css" not in result


class TestAllPresetsCss:
    def test_concatenates_every_built_in_preset(self):
        css = theme.all_presets_css()
        for tid in theme.PRESET_IDS:
            assert f':root[data-theme="{tid}"]' in css


class TestPickerNeverPersistsTheFallback:
    """v5.55.3 (Q66) — applyTheme()'s `persist` argument is the whole fix.
    v5.55.0 through v5.55.2 called applyTheme() unconditionally on every
    page load, so the very first load on any browser silently pinned the
    install default into localStorage as if it had been a deliberate
    pick — after that, the install default could never win again for that
    browser. Every applyTheme(...) call site outside the picker's own
    click handler must pass persist=false; only the click handler may
    ever pass true."""

    def _base_html(self):
        return pathlib.Path("templates/base.html").read_text(encoding="utf-8")

    def test_only_the_click_handler_may_persist(self):
        src = self._base_html()
        start = src.index(".theme-pick').forEach(function(btn) {")
        # The inner addEventListener('click', ...) callback's own closing
        # "});" — both applyTheme(...) calls inside the handler are well
        # before it; the IIFE's own call (outside the handler entirely,
        # in an earlier <script> block) is well before `start` itself.
        end = src.index("});", start)
        # Every real CALL to applyTheme(...) — not the `function applyTheme(id, persist) {` definition.
        calls = [m.start() for m in re.finditer(r"(?<!function )applyTheme\(", src)]
        assert len(calls) == 3, f"expected 3 applyTheme(...) calls (IIFE + 2 in the click handler), found {len(calls)}"
        outside = [i for i in calls if not (start <= i <= end)]
        assert len(outside) == 1, (
            f"expected exactly one applyTheme(...) call outside the click handler, found {len(outside)}"
        )
        assert src[outside[0] :].startswith("applyTheme(initial, false)")

    def test_the_click_handler_is_the_only_persist_true_call(self):
        src = self._base_html()
        assert src.count("applyTheme(id, true)") == 1
        assert "applyTheme(THEME_DEFAULT, false)" in src

    def test_the_pick_is_stored_under_the_new_key_never_the_old_one(self):
        src = self._base_html()
        assert "localStorage.setItem('jen-theme-pick'" in src
        assert "localStorage.setItem('jen-theme'," not in src
        assert "localStorage.setItem('jen-theme', " not in src
        # The old key is actively cleaned up, not just abandoned.
        assert "localStorage.removeItem('jen-theme')" in src

    def test_the_check_mark_is_derived_from_stored_state_not_the_applied_id(self):
        # v5.55.0-5.55.2's applyTheme() marked whichever button's
        # data-theme-id matched the id just applied — including the
        # install-default fallback, mislabelling it as a personal pick.
        src = self._base_html()
        assert "localStorage.getItem('jen-theme-pick')" in src
        assert "bid === pick" in src and "bid === ''" in src


class TestInstallDefaultPickerEntry:
    def test_both_picker_surfaces_have_an_empty_data_theme_id_entry(self):
        src = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        assert src.count('data-theme-id=""') == 2  # nav dropdown + phone sheet
        assert src.count("Install default (") == 2


class TestThemeAppliesBeforePaint:
    """v5.56.1 (Q68h) — the theme pick used to apply after {% block
    content %} rendered, so any non-Dark pick painted Dark first. A tiny
    synchronous <head> script now sets data-theme before anything paints;
    the applyTheme()/picker/check-mark script stays where it was."""

    def _base_html(self):
        return pathlib.Path("templates/base.html").read_text(encoding="utf-8")

    def test_the_head_script_runs_before_the_style_block_and_before_head_closes(self):
        src = self._base_html()
        head_script = src.index("document.documentElement.dataset.theme = initial;")
        first_style = src.index("<style>")
        head_close = src.index("</head>")
        content_block = src.index("{% block content %}")
        assert head_script < first_style < head_close < content_block

    def test_the_head_script_declares_the_constants_only_once(self):
        src = self._base_html()
        assert src.count("var THEME_DEFAULT = ") == 1
        assert src.count("var THEME_IDS = ") == 1
        # both declarations must be the head script's, i.e. before <style>
        first_style = src.index("<style>")
        assert src.index("var THEME_DEFAULT = ") < first_style
        assert src.index("var THEME_IDS = ") < first_style
