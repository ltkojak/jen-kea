"""
tests/test_q248_c1.py
─────────────────────
Q248, the theme colors and the button sizes (V4 to V7, V18 and V8's button half).

The look-over of 7.2.0-beta.5 measured white text on the accent at 1.6:1 in High contrast and 2.5:1 in Dark, Dark's muted text at 3.2:1, Light's warning
banner at 2.3:1 and a manufacturer badge at 1.1:1 on Retro. This file holds EVERY preset to 4.5:1 for each pair of plain colors the page draws text in:
the text and the muted text on the three backgrounds, the text on each solid button, each banner's and each badge's text on its own chip. It is pure
(`py -m pytest --noconftest tests/test_q248_c1.py`): jen/services/theme.py computes the colors and imports nothing. The same pairs are measured in a
real browser, composited, by tests/e2e/test_q248_c1.py.
"""

import colorsys
import pathlib
import re

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader

from jen.services import theme
from jen.services.icons import icon, nav_icon

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
BASE = (TEMPLATES / "base.html").read_text(encoding="utf-8")
PRESETS = sorted(theme.PRESETS)
AA = 4.5
#: the sixteen device-type colors, read from where the pages take them (jen/services/fingerprint.py, which this pure file does not import)
_FP = (ROOT / "jen" / "services" / "fingerprint.py").read_text(encoding="utf-8")
DEVICE_COLORS = re.findall(
    r'"(#[0-9a-f]{6})"\)',
    _FP[_FP.index("DEVICE_TYPE_DISPLAY = {") : _FP.index("}", _FP.index("DEVICE_TYPE_DISPLAY = {"))],
)

#: token -> the name of its ink, for every token a banner or a badge prints text in
INKS = {
    "primary": "--primary-ink",
    "success": "--success-ink",
    "warning": "--warning-ink",
    "danger": "--danger-ink",
    "text_muted": "--muted-ink",
}
#: a banner or a badge class -> the token its chip is made of (templates/base.html)
BANNERS = {
    "alert-info": "primary",
    "alert-warning": "warning",
    "alert-error": "danger",
    "alert-danger": "danger",
    "alert-success": "success",
}
BADGES = {
    "badge-dynamic": "primary",
    "badge-reserved": "success",
    "badge-danger": "danger",
    "badge-warning": "warning",
    "badge-stale": "warning",
    "badge-admin": "danger",
    "badge-viewer": "text_muted",
    "badge-muted": "text_muted",
    "badge-tone-blue": "primary",
    "badge-tone-green": "success",
    "badge-tone-red": "danger",
    "badge-tone-orange": "warning",
}
#: the three status tokens: each one's ink is also printed as plain text, with no chip under it
STATUS = ("success", "warning", "danger")
BUTTONS = {
    "btn-primary": ("primary", "--on-accent"),
    "btn-success": ("success", "--on-success"),
    "btn-warning": ("warning", "--on-warning"),
    "btn-danger": ("danger", "--on-danger"),
}


def _tokens(preset):
    return theme.PRESETS[preset]["tokens"]


def _rule(selector, text=BASE):
    m = re.search(r"(?m)^\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", text)
    assert m, f"{selector} has no rule in base.html"
    return " ".join(m.group(1).split())


def _hue(hex_color):
    h = (theme._normalize_hex(hex_color) or hex_color).lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return colorsys.rgb_to_hls(r, g, b)[0] * 360


def _hue_gap(a, b):
    d = abs(_hue(a) - _hue(b)) % 360
    return min(d, 360 - d)


class TestTheTextOfEveryPresetReads:
    """V5: the text and the muted text, on the page, on a card and on the second surface (a table header, a hovered row)."""

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("ground", ["bg", "surface", "surface2"])
    def test_text_on_each_background(self, preset, ground):
        k = _tokens(preset)
        assert theme.contrast_ratio(k["text"], k[ground]) >= AA, (preset, ground)

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("ground", ["bg", "surface", "surface2"])
    def test_muted_text_on_each_background(self, preset, ground):
        k = _tokens(preset)
        ratio = theme.contrast_ratio(k["text_muted"], k[ground])
        assert ratio >= AA, f"{preset}: muted {k['text_muted']} on {ground} {k[ground]} is {ratio:.2f}:1"

    def test_the_three_values_that_moved(self):
        """Dark #666 (3.2:1 on its surface), Light #6c757d (4.2:1 on its page) and Retro #3c3c3c (3.5:1 on its teal page) moved; the four that passed did not."""
        assert _tokens("dark")["text_muted"] == "#8c8c8c"
        assert _tokens("light")["text_muted"] == "#646d75"
        assert _tokens("retro")["text_muted"] == "#282828"
        assert [_tokens(p)["text_muted"] for p in ("contrast", "phosphor", "slate", "ember")] == [
            "#c0c0c0",
            "#7fbf7f",
            "#7f90ab",
            "#a08a7e",
        ]

    def test_a_table_header_and_a_help_line_are_the_muted_token(self):
        assert "color: var(--text-muted);" in _rule("th") and "background: var(--surface2);" in _rule("th")
        assert "color: var(--text-muted);" in _rule(".form-hint")


class TestTheTextOnASolidButton:
    """V4: black or white, whichever reads better on that color - never a fixed white."""

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("button", sorted(BUTTONS))
    def test_every_solid_button_reads(self, preset, button):
        token, var = BUTTONS[button]
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        assert d[var] in (theme.BLACK, theme.WHITE)
        ratio = theme.contrast_ratio(d[var], k[token])
        assert ratio >= AA, f"{preset}: {d[var]} on {button} {k[token]} is {ratio:.2f}:1"
        # white where white reads (so a preset's buttons share one text color), else the better of the two
        white = theme.contrast_ratio(theme.WHITE, k[token])
        if white >= AA:
            assert d[var] == theme.WHITE, f"{preset}: white reads on {button} at {white:.2f}:1 and was not chosen"
        else:
            assert d[var] == theme.BLACK and ratio >= white, "black where white does not read"

    @pytest.mark.parametrize("button", sorted(BUTTONS))
    def test_the_rule_draws_the_on_color(self, button):
        token, var = BUTTONS[button]
        assert _rule(f".{button}") == f"background: var(--{token}); color: var({var});"

    def test_white_on_the_accent_was_the_defect(self):
        """What the look-over measured, from the same function: the numbers this row exists for."""
        white = {p: theme.contrast_ratio("#ffffff", _tokens(p)["primary"]) for p in PRESETS}
        assert (
            white["contrast"] < 1.7
            and white["phosphor"] < 1.9
            and white["dark"] < 2.5
            and white["slate"] < 2.5
            and white["ember"] < 2.4
        )
        assert (
            theme.derived_vars(_tokens("light"))["--on-accent"]
            == theme.WHITE
            == theme.derived_vars(_tokens("retro"))["--on-accent"]
        )

    def test_everything_else_drawn_on_the_accent_takes_the_on_color(self):
        assert "color: var(--on-accent);" in _rule(".pagination .current")
        assert "color: var(--on-accent);" in _rule(".skip-link")
        assert _rule(".badge-accent") == "background: var(--primary); color: var(--on-accent);"
        assert "color:var(--on-accent);" in _rule(".nav-avatar"), "the avatar's initials"

    def test_no_template_or_stylesheet_puts_a_fixed_black_or_white_on_a_theme_color(self):
        """The whole tree: a `var(--primary|success|warning|danger)` background with `white`, `black`, `#fff` or `#000` text in the same declaration block."""
        fixed = r"(?<![-\w])color\s*:\s*(?:white|black|#fff(?:fff)?|#000(?:000)?)\b"
        solid = r"background(?:-color)?\s*:\s*(?:linear-gradient\([^;]*)?var\(--(?:primary|success|warning|danger)\)"
        offenders = []
        files = sorted(TEMPLATES.glob("*.html")) + sorted((ROOT / "static" / "css").glob("*.css"))
        for path in files:
            text = path.read_text(encoding="utf-8")
            # a declaration block is a CSS rule body, or one branch of a style attribute (a Jinja tag ends a branch)
            for block in re.split(r"[{}\"]|%\}", text):
                if re.search(solid, block) and re.search(fixed, block):
                    offenders.append((path.name, " ".join(block.split())[:120]))
        assert offenders == [], offenders
        assert not re.search(
            fixed, theme.render_css("dark", **{k: v for k, v in theme.PRESETS["dark"].items() if k != "name"})
        )


class TestABannersAndABadgesTextReadsOnItsOwnChip:
    """V6: the chip is the token mixed 18% into the preset's surface; the text is the token's ink."""

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("token", sorted(INKS))
    def test_every_ink_reads_on_its_chip(self, preset, token):
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        chip = theme.mix(k[token], k["surface"], theme.TINT)
        ratio = theme.contrast_ratio(d[INKS[token]], chip)
        assert ratio >= AA, f"{preset}: {token} ink {d[INKS[token]]} on its chip {chip} is {ratio:.2f}:1"

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("token", sorted(INKS))
    def test_an_ink_also_reads_as_plain_text_on_a_card_and_on_the_second_surface(self, preset, token):
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        for ground in ("surface", "surface2"):
            assert theme.contrast_ratio(d[INKS[token]], k[ground]) >= AA, (preset, token, ground)

    @pytest.mark.parametrize("preset", PRESETS)
    def test_a_token_that_already_read_is_its_own_ink(self, preset):
        """A theme still looks like itself: nothing is moved that did not need moving. A status token is also plain text (`.ok`, `.warn`, `.bad`), so
        "already read" for one of those three is on its chip AND on the page, a card and the second surface (stage c2)."""
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        for token, var in INKS.items():
            full = theme._normalize_hex(k[token])
            grounds = [theme.mix(full, k["surface"], theme.TINT)]
            if token in STATUS:
                grounds += [k["bg"], k["surface"], k["surface2"]]
            if all(theme.contrast_ratio(full, g) >= theme.INK_FLOOR for g in grounds):
                assert d[var] == full, (preset, token)
            else:
                assert d[var] != full, (preset, token)

    def test_what_the_look_over_measured(self):
        light, retro = _tokens("light"), _tokens("retro")
        assert theme.contrast_ratio(light["warning"], theme.mix(light["warning"], light["surface"], 18)) < 2.4
        assert theme.derived_vars(light)["--warning-ink"] != light["warning"]
        assert theme.contrast_ratio(retro["danger"], theme.mix(retro["danger"], retro["surface"], 18)) < 4.0

    @pytest.mark.parametrize("cls", sorted(BANNERS))
    def test_each_banner_rule_is_a_chip_on_the_surface_with_its_ink(self, cls):
        token = BANNERS[cls]
        rule = re.search(r"(?m)^\s*(?:\.[\w-]+, )*\." + re.escape(cls) + r"(?:, \.[\w-]+)*\s*\{([^}]*)\}", BASE)
        assert rule, cls
        body = " ".join(rule.group(1).split())
        assert f"background: color-mix(in srgb, var(--{token}) 18%, var(--tint-base));" in body, body
        assert f"color: var({INKS[token]});" in body, body

    @pytest.mark.parametrize("cls", sorted(BADGES))
    def test_each_badge_rule_is_a_chip_on_the_surface_with_its_ink(self, cls):
        token = BADGES[cls]
        css_token = "text-muted" if token == "text_muted" else token
        assert (
            _rule(f".{cls}")
            == f"background: color-mix(in srgb, var(--{css_token}) 18%, var(--tint-base)); color: var({INKS[token]});"
        )

    def test_no_badge_or_banner_class_is_left_on_a_transparent_chip(self):
        for m in re.finditer(r"(?m)^\s*(\.(?:badge|alert|toast)[\w.-]*(?:, \.[\w-]+)*)\s*\{([^}]*)\}", BASE):
            assert "18%, transparent" not in m.group(2), m.group(1)

    def test_the_generated_tint_classes_are_gone_from_the_badges(self):
        css = (ROOT / "static" / "css" / "ui-classes.css").read_text(encoding="utf-8")
        assert "18%, transparent" not in css
        for path in sorted(TEMPLATES.glob("*.html")):
            assert not re.search(r"\bu-(?:08a316|9741b3|5fdac8)\b", path.read_text(encoding="utf-8")), path.name


class TestAStatusWordIsItsTokensInk:
    """Stage c2, the leftover of V6: a status word printed as plain text ("Connected", "No key generated", a field's error) was the token itself -
    2.6:1 for a warning on Light's white card. It is the token's ink, and the ink reads on the page, on a card and on the second surface."""

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("token", STATUS)
    @pytest.mark.parametrize("ground", ["bg", "surface", "surface2"])
    def test_a_status_ink_reads_on_the_page_a_card_and_the_second_surface(self, preset, token, ground):
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        ratio = theme.contrast_ratio(d[INKS[token]], k[ground])
        assert ratio >= AA, f"{preset}: {token} ink {d[INKS[token]]} on {ground} {k[ground]} is {ratio:.2f}:1"

    def test_what_the_token_itself_measured(self):
        light, retro = _tokens("light"), _tokens("retro")
        assert theme.contrast_ratio(light["warning"], light["surface"]) < 2.7, "Light's .warn on a card"
        # Retro's page is a mid teal: the inks that read on its gray cards did not read there, and Retro is the one preset the grounds move
        for token in STATUS:
            chip_only = theme.ink(retro[token], retro["surface"])
            assert theme.contrast_ratio(chip_only, retro["bg"]) < 4.0, token
            assert theme.derived_vars(retro)[INKS[token]] != chip_only, token
        for preset in PRESETS:
            if preset == "retro":
                continue
            k = _tokens(preset)
            for token in STATUS:
                assert theme.derived_vars(k)[INKS[token]] == theme.ink(k[token], k["surface"]), (preset, token)

    def test_the_utility_classes_and_a_fields_error_draw_the_ink(self):
        line = re.search(r"(?m)^\s*\.ok \{[^\n]*$", BASE).group(0)
        assert ".ok { color: var(--success-ink); }" in line
        assert ".warn { color: var(--warning-ink); }" in line
        assert ".bad { color: var(--danger-ink); }" in line
        assert "color: var(--danger-ink);" in _rule(".field-error")
        assert "color: var(--danger-ink);" in _rule(".field-note")
        assert "color: var(--danger-ink);" in _rule(".btn-danger-outline")

    #: a text color that is a bare status token, in a style rule, a style attribute or a script
    BARE = re.compile(r"(?<![-\w])color\s*[:=]\s*(?:\{[%{][^}]*[%}]\}\s*)?['\"]?\s*var\(--(?:success|warning|danger)\)")
    #: pages this stage did not own (each is another builder's in Q248) and the standalone error page, whose 72 px numeral is large text
    REVIEWED = {"users.html", "logs.html", "error.html", "base.html"}

    def test_no_generated_class_colors_text_with_a_bare_status_token(self):
        css = (ROOT / "static" / "css" / "ui-classes.css").read_text(encoding="utf-8")
        assert not re.search(r"[{;]color:var\(--(?:success|warning|danger)\)", css)
        assert "{color:var(--warning-ink);font-size:12px}" in css and "{color:var(--danger-ink)}" in css
        # the map's keys are what the templates carried (a class name is the hash of its key and never changes); the tool writes the ink
        mapping = (ROOT / "tools" / "inline_style_map.json").read_text(encoding="utf-8")
        assert '"color:var(--danger)": "u-497726"' in mapping

    def test_no_template_colors_text_with_a_bare_status_token(self):
        found = []
        for path in sorted(TEMPLATES.glob("*.html")):
            if path.name in self.REVIEWED:
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if self.BARE.search(line):
                    found.append((path.name, n, line.strip()[:100]))
        assert found == [], (
            "status-colored text takes the token's ink (var(--success-ink), var(--warning-ink), var(--danger-ink)): "
            + repr(found)
        )


class TestTheCategoricalHues:
    """A manufacturer badge's device-type color and the two fixed subnet tones: the text keeps one percentage of the hue per theme."""

    def test_the_hue_list_is_the_device_type_palette(self):
        assert len(DEVICE_COLORS) == 16 and sorted(DEVICE_COLORS) == sorted(theme.DEVICE_HUES)

    def test_the_fixed_tones_are_the_ones_base_html_draws(self):
        assert f"color-mix(in srgb, {theme.TONE_YELLOW} 18%, var(--tint-base))" in _rule(".badge-tone-yellow")
        assert f"color-mix(in srgb, {theme.TONE_PURPLE} 18%, var(--tint-base))" in _rule(".badge-tone-purple")

    @pytest.mark.parametrize("preset", PRESETS)
    @pytest.mark.parametrize("hue", DEVICE_COLORS)
    def test_a_manufacturer_badge_reads_in_every_device_color(self, preset, hue):
        k, d = _tokens(preset), theme.derived_vars(_tokens(preset))
        keep = int(d["--hue-keep"].rstrip("%"))
        label = theme.mix(hue, d["--hue-pole"], keep)
        chip = theme.mix(hue, k["surface"], theme.HUE_TINT)
        ratio = theme.contrast_ratio(label, chip)
        assert ratio >= AA, f"{preset}: {hue} kept {keep}% is {label} on {chip}: {ratio:.2f}:1"

    @pytest.mark.parametrize("preset", PRESETS)
    def test_the_color_itself_did_not_read(self, preset):
        """The control inside the file: with all of the hue kept (what the page drew), at least one device color is under 4.5:1 in every preset."""
        k = _tokens(preset)
        worst = min(theme.contrast_ratio(h, theme.mix(h, k["surface"], theme.HUE_TINT)) for h in DEVICE_COLORS)
        assert worst < AA, (preset, worst)
        assert int(theme.derived_vars(k)["--hue-keep"].rstrip("%")) >= 40, (
            "a badge keeps enough of its color to be told from another"
        )

    def test_the_badge_takes_its_color_as_a_variable_and_the_class_does_the_rest(self):
        rule = _rule(".mfr-badge")
        assert "background: color-mix(in srgb, var(--tc) 13%, var(--tint-base));" in rule
        assert "color: color-mix(in srgb, var(--tc) var(--hue-keep), var(--hue-pole));" in rule
        assert "invert(var(--vendor-invert))" in _rule(".mfr-badge img")
        for name in ("_device_badge.html", "_device_rows.html"):
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            assert 'class="mfr-badge' in text and 'style="--tc:{{' in text, name
            assert "22;color:" not in text and "invert(1)" not in text, name

    def test_a_logo_is_black_on_a_light_surface_and_white_on_a_dark_one(self):
        assert (
            theme.derived_vars(_tokens("light"))["--vendor-invert"]
            == "0"
            == theme.derived_vars(_tokens("retro"))["--vendor-invert"]
        )
        for preset in ("dark", "contrast", "phosphor", "slate", "ember"):
            assert theme.derived_vars(_tokens(preset))["--vendor-invert"] == "1", preset


class TestAWarningIsNotTheAccent:
    """V7: in Phosphor the warning WAS the accent (#ffb000 both); in Ember it was a shade of it (16 degrees of hue apart)."""

    def test_the_two_values_that_moved(self):
        assert _tokens("phosphor")["warning"] == "#ee7dff" and _tokens("phosphor")["primary"] == "#ffb000"
        assert _tokens("ember")["warning"] == "#f2ee5e" and _tokens("ember")["primary"] == "#ff8a3d"

    @pytest.mark.parametrize("preset", PRESETS)
    def test_the_warning_is_a_different_hue_from_the_accent_the_danger_and_the_success(self, preset):
        k = _tokens(preset)
        for other in ("primary", "danger", "success"):
            assert _hue_gap(k["warning"], k[other]) >= 30, (preset, other, _hue_gap(k["warning"], k[other]))

    def test_the_hue_gaps_reported(self):
        assert _hue_gap("#ffb000", "#ffb000") == 0 and round(_hue_gap("#ee7dff", "#ffb000")) == 109
        assert round(_hue_gap("#ffc247", "#ff8a3d")) == 16 and round(_hue_gap("#f2ee5e", "#ff8a3d")) == 35


def _render(flashes):
    """templates/base.html alone, with the flashes given (the way tests/test_desktop_polish.py renders it: no app, no database)."""
    from jen.routes.settings import nav as navmod

    env = Environment(loader=ChoiceLoader([DictLoader({}), FileSystemLoader(str(TEMPLATES))]))
    env.globals.update(
        icon=icon,
        author_draft_done=lambda: None,
        nav_icon=nav_icon,
        csrf_token=lambda: "tok",
        url_for=lambda ep, **kw: "/" + ep,
        get_flashed_messages=lambda **kw: flashes,
    )

    class U:
        is_authenticated = True
        username = "alice"
        all_subnets = True
        role = "admin"

    class R:
        args = {}
        endpoint = "leases.leases"

    return env.get_template("base.html").render(
        current_user=U,
        request=R,
        csp_nonce="n0nce",
        jen_version="7.2.0",
        nav=navmod.nav_context("leases.leases", "admin", []),
        getting_started_pill=None,
        plugin_nav_items=[],
        theme_css=[
            (tid, theme.render_css(tid, p["tokens"], p["radius"], p["mono_ui"], p["color_scheme"]))
            for tid, p in theme.PRESETS.items()
        ],
        theme_presets=[(tid, p["name"]) for tid, p in theme.PRESETS.items()],
        theme_default="dark",
        theme_custom=None,
        theme_meta_color=theme.PRESETS["dark"]["tokens"]["primary"],
    )


class TestAFlashCarriesItsCategorysIcon:
    """V7: a flashed message had no icon at all, so a warning and an information line differed only in color - and in Phosphor not even in that."""

    ICONS = {
        "warning": "triangle-alert",
        "info": "info",
        "success": "circle-check",
        "error": "circle-x",
        "danger": "circle-x",
        "message": "info",
    }

    @pytest.mark.parametrize("category", sorted(ICONS))
    def test_the_icon_comes_before_the_text(self, category):
        html = _render([(category, "Something happened.")])
        m = re.search(
            rf'<div class="alert alert-{category} alert-flash"[^>]*>(.*?)<span class="alert-text">Something happened\.</span>',
            html,
            re.S,
        )
        assert m, category
        assert m.group(1) == f'<svg class="ico" aria-hidden="true"><use href="#i-{self.ICONS[category]}"></use></svg>'

    def test_a_warning_and_an_information_line_have_different_icons(self):
        assert self.ICONS["warning"] != self.ICONS["info"]
        html = _render([("warning", "W."), ("info", "I.")])
        assert html.count('<use href="#i-triangle-alert"></use></svg><span class="alert-text">W.</span>') == 1
        assert html.count('<use href="#i-info"></use></svg><span class="alert-text">I.</span>') == 1

    def test_every_icon_named_is_in_the_sprite(self):
        sprite = (TEMPLATES / "_icon_sprite.html").read_text(encoding="utf-8")
        for name in set(self.ICONS.values()):
            assert f'<symbol id="i-{name}"' in sprite, name

    def test_a_toast_carries_the_same_icon_as_a_flash_of_its_kind(self):
        """Stage c2: `jenToast` is the flash made small and had no icon. Its four kinds name the four icons the flashes carry, the icon is built as
        an element (never as HTML text) and is the toast's first child, before its text."""
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        m = re.search(
            r"\{ success: '([\w-]+)', error: '([\w-]+)', info: '([\w-]+)', warning: '([\w-]+)' \}\[kind\]", body
        )
        assert m, "the toast names no icon for its kind"
        assert dict(zip(("success", "error", "info", "warning"), m.groups(), strict=True)) == {
            k: self.ICONS[k] for k in ("success", "error", "info", "warning")
        }
        assert (
            "use.setAttribute('href', '#i-' + " in body
            and "createElementNS(SVG, 'svg')" in body
            and "innerHTML" not in body
        )
        assert "ico.setAttribute('class', 'ico')" in body and "ico.setAttribute('aria-hidden', 'true')" in body
        assert (
            body.index("el.appendChild(ico)") < body.index("el.appendChild(text)") < body.index("el.appendChild(close)")
        )
        assert ".alert-flash > .ico, .toast > .ico { margin-top: 2px; }" in BASE


class TestACustomPalette:
    """An operator's palette gets its `--on-accent` computed like a preset's and is otherwise drawn as it was."""

    MID = {
        "bg": "#101418",
        "surface": "#182028",
        "surface2": "#202a34",
        "surface3": "#28343f",
        "border": "#33414f",
        "text": "#e6edf3",
        "text_muted": "#8b98a5",
        "primary": "#777777",
        "success": "#2ecc71",
        "warning": "#f39c12",
        "danger": "#e74c3c",
    }

    @pytest.mark.parametrize(
        "accent",
        [
            "#777777",
            "#808080",
            "#767676",
            "#6a8caf",
            "#c0504d",
            "#00b4d8",
            "#0077b6",
            "#ffb000",
            "#000080",
            "#ffffff",
            "#000000",
        ],
    )
    def test_a_mid_tone_accent_gets_an_on_color_that_reads(self, accent):
        d = theme.derived_vars({**self.MID, "primary": accent}, preset=False)
        assert d["--on-accent"] in (theme.BLACK, theme.WHITE)
        assert theme.contrast_ratio(d["--on-accent"], accent) >= AA, (accent, d["--on-accent"])

    def test_one_of_black_and_white_always_reads(self):
        """Every gray, which is every luminance a color can have: the better of the two is never under 4.5:1 (the worst is 4.58:1, at #757575 and #767676)."""
        worst = min(
            theme.contrast_ratio(theme.on_color(f"#{v:02x}{v:02x}{v:02x}"), f"#{v:02x}{v:02x}{v:02x}")
            for v in range(256)
        )
        assert AA <= worst < 4.7

    def test_the_rest_of_a_custom_palette_is_what_the_page_drew_before(self):
        d = theme.derived_vars(self.MID, preset=False)
        assert d == {
            "--on-accent": "#000000",
            "--on-success": "#ffffff",
            "--on-warning": "#000000",
            "--on-danger": "#ffffff",
            "--primary-ink": "var(--primary)",
            "--success-ink": "var(--success)",
            "--warning-ink": "var(--warning)",
            "--danger-ink": "var(--danger)",
            "--muted-ink": "var(--text-muted)",
            "--tint-base": "transparent",
            "--hue-keep": "100%",
            "--hue-pole": "#ffffff",
            "--tone-keep": "50%",
            "--tone-pole": "var(--text)",
            "--vendor-invert": "1",
        }

    def test_render_css_treats_any_id_that_is_not_a_preset_as_custom(self):
        css = theme.render_css("custom", self.MID, 6, False, "dark")
        assert (
            "--on-accent:#000000;" in css
            and "--tint-base:transparent;" in css
            and "--primary-ink:var(--primary);" in css
        )
        for name in theme.TOKENS:
            assert f"{theme.CSS_VARS[name]}:{self.MID[name]};" in css, "no token of the palette is rewritten"
        preset = theme.render_css("dark", **{k: v for k, v in theme.PRESETS["dark"].items() if k != "name"})
        assert "--tint-base:var(--surface);" in preset

    def test_every_theme_defines_every_derived_name(self):
        names = list(theme.derived_vars(self.MID, preset=False))
        for preset in PRESETS:
            assert list(theme.derived_vars(_tokens(preset))) == names, preset
        used = set(
            re.findall(
                r"var\((--(?:on-[a-z]+|[a-z]+-ink|tint-base|hue-keep|hue-pole|tone-keep|tone-pole|vendor-invert))\)",
                BASE,
            )
        )
        assert (
            used <= set(names) and {"--on-accent", "--warning-ink", "--tint-base", "--hue-keep", "--tone-keep"} <= used
        )

    def test_the_live_preview_computes_the_same_on_color(self):
        text = (TEMPLATES / "settings_appearance.html").read_text(encoding="utf-8")
        assert "const THEME_CUSTOM_DERIVED = {{ theme_custom_derived | tojson }};" in text
        assert (
            "themeContrastRatio('#000000', accent) >= themeContrastRatio('#ffffff', accent) ? '#000000' : '#ffffff'"
            in text
        )


class TestButtonsAreOneHeight:
    """V18 and V8: the source half. The heights themselves are measured in a browser (tests/e2e/test_q248_c1.py)."""

    def test_every_button_has_a_border_and_a_height(self):
        btn = _rule(".btn")
        assert "border: 1px solid transparent;" in btn and "border: none" not in btn
        assert "line-height: 16px;" in btn and "min-height: 32px;" in btn
        small = _rule(".btn-sm")
        assert "line-height: 14px;" in small and "min-height: 24px;" in small

    def test_no_button_variant_removes_the_border(self):
        for m in re.finditer(r"(?m)^\s*(\.btn[\w-]*)\s*\{([^}]*)\}", BASE):
            assert not re.search(r"border\s*:\s*(none|0)\b", m.group(2)), m.group(1)
