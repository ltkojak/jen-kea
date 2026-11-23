"""
jen/services/theme.py
───────────────────────
v5.55.0 (Q63) — the one source of truth for every color token Jen's UI
renders: the seven built-in presets and the validated custom palette a
superadmin can define for the whole install. Pure — no Flask, no DB, no
Jinja — so the generated CSS, the contrast math and the validator are all
testable directly (tests/test_theme.py).

`dark` and `light` carried their pre-Q63 values byte for byte until Q248
moved the one token in each that could not be read (`text_muted`: 3.2:1 on
Dark's surface, 4.2:1 on Light's page). `contrast` (High Contrast) keeps every text/background
pair at 7:1 or better (WCAG AAA); `phosphor` is the "for fun" terminal
preset the maintainer asked for (amber-on-green, monospace UI on desktop,
zero radius) — no animation, no typing effect, no scanline: just a palette.
v5.56.0 (Q67) adds `slate` (blue), `ember` (warm) and `retro` (a light,
Windows-3.1-era look) — `retro` is the one preset that carries `extra_css`,
a fixed CSS string scoped to its own `data-theme` selector that a custom
palette can never define; see `render_css()`.

`render_css()` is the ONLY place a validated palette's values reach the
page, through Jinja's `|safe` — `validate_palette()` is the injection
boundary a hostile form value can never get past (a whitelist regex on
every color, an int-clamped radius, nothing else accepted).
"""

from __future__ import annotations

import re

# Token order is significant: it's also the order render_css() emits
# declarations in and the order a custom-palette form lists fields in.
TOKENS = (
    "bg",
    "surface",
    "surface2",
    "surface3",
    "border",
    "text",
    "text_muted",
    "primary",
    "success",
    "warning",
    "danger",
)
# token name -> CSS custom property name (the one place the two spellings meet).
CSS_VARS = {
    "bg": "--bg",
    "surface": "--surface",
    "surface2": "--surface2",
    "surface3": "--surface3",
    "border": "--border",
    "text": "--text",
    "text_muted": "--text-muted",
    "primary": "--primary",
    "success": "--success",
    "warning": "--warning",
    "danger": "--danger",
}

# Retro's only concession to its era: classic beveled borders and a
# title-bar nav, scoped under its own data-theme so nothing else can see
# it. Colors and borders, not animation — same "no gimmicks" rule Q63
# set for Phosphor. Never exposed to the custom-palette form.
_RETRO_EXTRA_CSS = (
    ':root[data-theme="retro"] .card,'
    ':root[data-theme="retro"] .stat-card,'
    ':root[data-theme="retro"] .btn,'
    ':root[data-theme="retro"] .tabbar,'
    ':root[data-theme="retro"] .sheet{'
    "border-style:solid;border-width:2px;"
    "border-color:#ffffff #808080 #808080 #ffffff;"
    "}"
    ':root[data-theme="retro"] .btn:active{'
    "border-color:#808080 #ffffff #ffffff #808080;"
    "}"
    ':root[data-theme="retro"] .nav{'
    "background:#000080;color:#ffffff;"
    "}"
    # v5.56.1 (Q68f) — .nav a alone left every top-level nav control
    # (var(--text-muted), too dark for navy) unreadable: the theme
    # toggle, the version string, the keyboard-shortcut button. Icons
    # pick it up too via stroke:currentColor. The search box becomes a
    # plain light field instead, since white text needs a dark field to
    # sit on and the nav itself is now the dark field for everything else.
    ':root[data-theme="retro"] .nav a,'
    ':root[data-theme="retro"] .nav .theme-toggle,'
    ':root[data-theme="retro"] .nav-brand span,'
    ':root[data-theme="retro"] #kb-hint-btn{'
    "color:#ffffff;"
    "}"
    ':root[data-theme="retro"] .nav-search input{'
    "background:#ffffff;color:#000000;"
    "}"
    ':root[data-theme="retro"] .nav-search input::placeholder{'
    "color:#666666;"
    "}"
    # The two nav dropdowns (Theme, avatar) already sit on their own
    # var(--surface) panel, not the navy bar — the broad ".nav a" rule
    # above would otherwise paint their menu text white-on-gray too.
    # Same specificity as that rule; wins on source order (later).
    ':root[data-theme="retro"] .nav-dropdown-content a,'
    ':root[data-theme="retro"] .nav-dropdown-content button.linkish{'
    "color:var(--text);"
    "}"
    # Q247 (U12) - four things the navy bar and the teal page still hid. The Kea status dot is the theme's --success / --danger
    # (#004d00 and #8b0000: 1.6:1 on #000080) - a bright green or red in the bar only (#33ff66 11.9:1, #ff6060 5.4:1). The avatar is a
    # gradient of --primary, which IS the bar's navy - the classic gray face with black text (#c0c0c0 on #000080 8.8:1, the letter
    # 11.5:1). The keyboard button carries its color and border inline (--text-muted, --border: 1.5:1), which no rule without
    # !important reaches - white like the theme button beside it (16:1), and that button's border with it. And muted text in a page
    # header sits on the teal background, not on a card: #3c3c3c is 3.5:1 there, #1a1a1a 5.5:1.
    ':root[data-theme="retro"] .nav .kea-status.kea-up{'
    "background:#33ff66;box-shadow:0 0 6px #33ff66;"
    "}"
    ':root[data-theme="retro"] .nav .kea-status.kea-down{'
    "background:#ff6060;box-shadow:0 0 6px #ff6060;"
    "}"
    ':root[data-theme="retro"] .nav .nav-avatar{'
    "background:#c0c0c0;color:#000000;"
    "}"
    ':root[data-theme="retro"] #kb-hint-btn{'
    "color:#ffffff !important;border-color:#ffffff !important;"
    "}"
    ':root[data-theme="retro"] .nav .theme-toggle{'
    "border-color:#ffffff;"
    "}"
    ':root[data-theme="retro"] .page-header{'
    "--text-muted:#1a1a1a;"
    "}"
)

PRESETS = {
    "dark": {
        "name": "Dark",
        "tokens": {
            "bg": "#0d0d0d",
            "surface": "#141414",
            "surface2": "#1c1c1c",
            "surface3": "#252525",
            "border": "#2a2a2a",
            "text": "#e0e0e0",
            "text_muted": "#8c8c8c",
            "primary": "#00b4d8",
            "success": "#2ecc71",
            "warning": "#f39c12",
            "danger": "#e74c3c",
        },
        "radius": 6,
        "mono_ui": False,
        "color_scheme": "dark",
    },
    "light": {
        "name": "Light",
        "tokens": {
            "bg": "#f0f2f5",
            "surface": "#ffffff",
            "surface2": "#f8f9fa",
            "surface3": "#eceff3",
            "border": "#dee2e6",
            "text": "#212529",
            "text_muted": "#646d75",
            "primary": "#0077b6",
            "success": "#198754",
            "warning": "#fd7e14",
            "danger": "#dc3545",
        },
        "radius": 6,
        "mono_ui": False,
        "color_scheme": "light",
    },
    "contrast": {
        "name": "High contrast",
        "tokens": {
            "bg": "#000000",
            "surface": "#000000",
            "surface2": "#0a0a0a",
            "surface3": "#161616",
            "border": "#8a8a8a",
            "text": "#ffffff",
            "text_muted": "#c0c0c0",
            "primary": "#7fd9ff",
            "success": "#6fe39a",
            "warning": "#ffd24d",
            "danger": "#ff8080",
        },
        "radius": 6,
        "mono_ui": False,
        "color_scheme": "dark",
    },
    "phosphor": {
        "name": "Phosphor",
        "tokens": {
            "bg": "#0a0e0a",
            "surface": "#0f150f",
            "surface2": "#131b13",
            "surface3": "#182118",
            "border": "#1f3a1f",
            "text": "#b8f5b8",
            "text_muted": "#7fbf7f",
            "primary": "#ffb000",
            "success": "#33ff66",
            "warning": "#ee7dff",
            "danger": "#ff5f56",
        },
        "radius": 0,
        "mono_ui": True,
        "color_scheme": "dark",
    },
    "slate": {
        "name": "Slate",
        "tokens": {
            "bg": "#0f1520",
            "surface": "#161e2c",
            "surface2": "#1d2738",
            "surface3": "#243147",
            "border": "#2e3d55",
            "text": "#dbe4f3",
            "text_muted": "#7f90ab",
            "primary": "#5aa9ff",
            "success": "#3ddc97",
            "warning": "#ffb454",
            "danger": "#ff6b6b",
        },
        "radius": 6,
        "mono_ui": False,
        "color_scheme": "dark",
    },
    "ember": {
        "name": "Ember",
        "tokens": {
            "bg": "#140d0b",
            "surface": "#1c1310",
            "surface2": "#251a15",
            "surface3": "#2f221c",
            "border": "#3f2d25",
            "text": "#f1e4dc",
            "text_muted": "#a08a7e",
            "primary": "#ff8a3d",
            "success": "#7fd67a",
            "warning": "#f2ee5e",
            "danger": "#ff4d5e",
        },
        "radius": 6,
        "mono_ui": False,
        "color_scheme": "dark",
    },
    "retro": {
        "name": "Retro",
        "tokens": {
            "bg": "#20a0a0",
            "surface": "#c0c0c0",
            "surface2": "#d4d0c8",
            "surface3": "#e6e6e6",
            "border": "#404040",
            "text": "#000000",
            "text_muted": "#282828",
            "primary": "#000080",
            "success": "#004d00",
            "warning": "#5c2e00",
            "danger": "#8b0000",
        },
        "radius": 0,
        "mono_ui": False,
        # guess_color_scheme() would call the teal bg dark; form controls
        # (and the rest of the "light desktop" reading) need it explicit.
        "color_scheme": "light",
        "extra_css": _RETRO_EXTRA_CSS,
    },
}

PRESET_IDS = tuple(PRESETS)  # insertion order — the picker and the Settings select both use this order

_HEX_RE = re.compile(r"^#([0-9a-f]{3}|[0-9a-f]{6})$")


def _normalize_hex(value: str) -> str | None:
    """`#abc` -> `#aabbcc`, `#AABBCC` -> `#aabbcc`. None for anything that
    isn't exactly a 3- or 6-digit hex color — no `rgb()`, no named colors,
    no 7+ digit values, nothing CSS-syntax-bearing (`url(`, `;`, `}`,
    `expression(`, …) can ever pass this."""
    v = value.strip().lower()
    if not _HEX_RE.match(v):
        return None
    if len(v) == 4:
        v = "#" + "".join(c * 2 for c in v[1:])
    return v


def render_css(
    theme_id: str, tokens: dict, radius: int, mono_ui: bool, color_scheme: str = "dark", extra_css: str = ""
) -> str:
    """`:root[data-theme="<id>"]{...}` for one preset or the custom palette.
    When `mono_ui`, also emits the desktop-only rule that points `--font-ui`
    at `--font-mono` for that theme — phones never get the monospace UI (it
    widens tables past the phone overflow guard). `extra_css` is appended
    verbatim after that — a built-in preset's own fixed string (e.g. Retro's
    bevels); the custom palette never has one, so it never passes this.
    After the eleven tokens come the colors DERIVED from them (`derived_vars`):
    a built-in preset gets all of them computed, the custom palette gets its
    `--on-accent` computed and everything else as it always rendered."""
    decls = "".join(f"{CSS_VARS[name]}:{tokens[name]};" for name in TOKENS)
    decls += "".join(f"{name}:{value};" for name, value in derived_vars(tokens, preset=theme_id in PRESETS).items())
    css = f':root[data-theme="{theme_id}"]{{color-scheme:{color_scheme};{decls}--radius:{radius}px;}}'
    if mono_ui:
        css += f'@media screen and (min-width:769px){{:root[data-theme="{theme_id}"]{{--font-ui:var(--font-mono);}}}}'
    css += extra_css
    return css


def all_presets_css() -> str:
    """Every built-in preset's CSS, concatenated — what base.html's context
    processor hands the page in place of the old two hand-written blocks."""
    return "".join(
        render_css(theme_id, p["tokens"], p["radius"], p["mono_ui"], p["color_scheme"], p.get("extra_css", ""))
        for theme_id, p in PRESETS.items()
    )


def validate_palette(form: dict) -> tuple[dict, list[str]]:
    """`form` is anything `dict`-like with `.get()` (a real `request.form` or
    a plain dict in a test). Returns `({"tokens", "radius", "mono_ui"}, errors)` —
    every accepted token is a normalized 6-digit hex, `errors` is empty only
    when every field validated. This is the one place a submitted palette is
    allowed to become CSS; nothing downstream re-validates it. Each error is a
    sentence that starts with the field's name (the form of it a log line wants);
    `validate_palette_fields` is the same check with the field kept apart from the
    message, which is what the form prints under the input (Q208, AX4)."""
    result, fields = validate_palette_fields(form)
    return result, [f"{name.replace('_', ' ')}: {message}" for name, message in fields]


def validate_palette_fields(form: dict) -> tuple[dict, list[tuple[str, str]]]:
    """`validate_palette` with each error as `(field, message)`: `field` is the form field's name (the input's id is `f-<field>`), `message` does not repeat it."""
    errors: list[tuple[str, str]] = []
    tokens: dict[str, str] = {}
    for name in TOKENS:
        raw = str(form.get(name, "") or "")
        norm = _normalize_hex(raw)
        if norm is None:
            errors.append((name, f"'{raw}' is not a valid hex color (e.g. #1a1a2a)"))
        else:
            tokens[name] = norm
    radius_raw = str(form.get("radius", "") or "").strip()
    radius = 6
    try:
        radius = int(radius_raw)
        if not (0 <= radius <= 16):
            raise ValueError
    except ValueError:
        errors.append(("radius", "Must be a whole number from 0 to 16"))
    mono_ui = str(form.get("mono_ui", "")).strip().lower() in ("1", "true", "on", "yes")
    return {"tokens": tokens, "radius": radius, "mono_ui": mono_ui}, errors


def _srgb_to_linear(channel: int) -> float:
    c = channel / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _relative_luminance(hex_color: str) -> float:
    # Accepts 3-digit shorthand too (a preset's own literal, e.g. dark's "#666")
    # — normalize first rather than requiring every caller to expand it first.
    h = (_normalize_hex(hex_color) or hex_color).lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    r, g, b = _srgb_to_linear(r), _srgb_to_linear(g), _srgb_to_linear(b)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(hex_a: str, hex_b: str) -> float:
    """WCAG 2.x contrast ratio, 1.0 (identical) to 21.0 (black on white)."""
    la, lb = _relative_luminance(hex_a), _relative_luminance(hex_b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def guess_color_scheme(tokens: dict) -> str:
    """The custom palette has no explicit light/dark field (the form is just
    eleven colors + radius + a checkbox) — `<meta name="color-scheme">`
    mainly steers browser-native chrome (scrollbars, form controls), so a
    background-luminance guess is a fine default rather than one more field."""
    return "light" if _relative_luminance(tokens["bg"]) > 0.5 else "dark"


# ── Q248 (V4 to V7): the colors a theme DERIVES from its eleven tokens ──────────────────────────────────────────────────────────────────────────
# Three kinds, all computed here so one pure test (tests/test_q248_c1.py) can hold every preset to 4.5:1:
#   on-colors  the text on a solid button of that color: white where white reads at 4.5:1, else black or white, whichever reads better (`on_fill`). White on the accent was 1.6:1 in
#              High contrast and 2.5:1 in Dark.
#   inks       the token as TEXT on its own 18% chip (a banner, a status or subnet badge): the token itself when that already reads at 4.5:1,
#              else the token moved toward black or white in 5% steps until it does (`ink`). Light's warning banner was 2.3:1. The three STATUS
#              inks are also plain text with no chip (`.ok`, `.warn`, `.bad`), so they read on the page, a card and the second surface as well.
#   keep       how much of a categorical hue (a manufacturer badge's device-type color, the yellow and purple subnet tones) a badge's text keeps
#              before the rest is black or white: ONE percentage per theme, the highest at which every hue in BADGE_HUES reads at 4.5:1.
# A chip is the color mixed 18% (TINT) into the theme's SURFACE - not into whatever is behind it - so its own background is one known color.
BLACK = "#000000"
WHITE = "#ffffff"
TINT = 18  # percent of the color in a banner's or a badge's background (base.html's color-mix)
HUE_TINT = 13  # percent of a device-type color in a manufacturer badge's background (the "22" alpha it always had)
INK_FLOOR = 4.6  # what a derived text color is computed to; the tests hold 4.5, the difference is the browser's rounding of a color-mix
TONE_YELLOW = "#e6b400"  # the two subnet badge tones that are fixed hues, not theme tokens (templates/base.html .badge-tone-yellow / -purple)
TONE_PURPLE = "#a371f7"
# every categorical hue a badge prints its text in: jen/services/fingerprint.py's DEVICE_TYPE_DISPLAY colors (tests/test_q248_c1.py holds the two
# lists equal; this module stays pure and imports nothing) and the two fixed tones
DEVICE_HUES = (
    "#a8a8a8",
    "#a4c639",
    "#00a4ef",
    "#e95420",
    "#ff9900",
    "#00b4d8",
    "#9b59b6",
    "#7f8c8d",
    "#16a085",
    "#27ae60",
    "#2980b9",
    "#e74c3c",
    "#c7053d",
    "#4285f4",
    "#3498db",
    "#555555",
)


def mix(hex_a: str, hex_b: str, percent_a: float) -> str:
    """`color-mix(in srgb, a percent_a%, b)` of two opaque colors, as `#rrggbb`."""
    a = (_normalize_hex(hex_a) or hex_a).lstrip("#")
    b = (_normalize_hex(hex_b) or hex_b).lstrip("#")
    p = percent_a / 100.0
    return "#" + "".join(f"{round(int(a[i : i + 2], 16) * p + int(b[i : i + 2], 16) * (1 - p)):02x}" for i in (0, 2, 4))


def on_color(hex_color: str) -> str:
    """Black or white, whichever has the higher contrast ratio on `hex_color` (one of the two is always at least 4.5:1)."""
    return BLACK if contrast_ratio(BLACK, hex_color) >= contrast_ratio(WHITE, hex_color) else WHITE


def on_fill(hex_color: str) -> str:
    """The text on a solid button of `hex_color`: white when white reads on it at 4.5:1, else black or white by `on_color`.

    A preset whose buttons can all carry white keeps one text color across them: in Light, white is 4.87:1 on the accent and 4.53:1 on
    success and on danger, where black is 4.63:1 and 4.64:1, and `on_color` alone gave the primary button white text and the two beside
    it black."""
    return WHITE if contrast_ratio(WHITE, hex_color) >= 4.5 else on_color(hex_color)


def ink(hex_color: str, surface: str, tint: int = TINT, grounds: tuple = ()) -> str:
    """`hex_color` as text on its own chip (`tint`% of it mixed into `surface`): the color itself when that reads at INK_FLOOR, else moved toward
    black or white (whichever the chip needs) in 5% steps until it does.

    `grounds` are the plain backgrounds the ink is ALSO printed on with no chip under it (Q248: a status line - "Connected", "No key generated",
    a field's error - is the ink on the page, on a card or on the second surface): the ink reads at INK_FLOOR on each of them too. Retro is the
    one preset this moves: its page is a mid teal, where the three status inks that read on its gray cards were 3.6:1 to 3.7:1."""
    chip = mix(hex_color, surface, tint)
    pole = on_color(chip)
    for keep in range(100, -1, -5):
        candidate = mix(hex_color, pole, keep)
        if all(contrast_ratio(candidate, back) >= INK_FLOOR for back in (chip, *grounds)):
            return candidate
    return pole


def hue_keep(surface: str, hues: tuple = DEVICE_HUES, tint: int = HUE_TINT) -> int:
    """The highest percentage (a multiple of 5) of a categorical hue that a badge's text may keep on this surface with every one of `hues` (each on
    a chip of `tint`% of itself) still reading at INK_FLOOR; the rest of the text color is `on_color(surface)`."""
    pole = on_color(surface)
    for keep in range(100, -1, -5):
        if all(contrast_ratio(mix(h, pole, keep), mix(h, surface, tint)) >= INK_FLOOR for h in hues):
            return keep
    return 0


def derived_vars(tokens: dict, preset: bool = True) -> dict:
    """CSS custom property -> value for everything a theme derives from its tokens, in the order render_css() emits them.

    `preset=False` is the custom palette: its `--on-accent` is computed like a preset's, and every other name carries what the page drew before
    these names existed (white on success and danger, black on warning, a token as its own text color, a transparent chip), so an operator's
    palette looks as it did except for the text on its primary button."""
    if not preset:
        return {
            "--on-accent": on_fill(tokens["primary"]),
            "--on-success": WHITE,
            "--on-warning": BLACK,
            "--on-danger": WHITE,
            "--primary-ink": "var(--primary)",
            "--success-ink": "var(--success)",
            "--warning-ink": "var(--warning)",
            "--danger-ink": "var(--danger)",
            "--muted-ink": "var(--text-muted)",
            "--tint-base": "transparent",
            "--hue-keep": "100%",
            "--hue-pole": WHITE,
            "--tone-keep": "50%",
            "--tone-pole": "var(--text)",
            "--vendor-invert": "1",
        }
    surface = tokens["surface"]
    pole = on_color(surface)
    # a status ink is also plain text (`.ok`, `.warn`, `.bad`, a field's error): on the page, on a card and on the second surface
    plain = (tokens["bg"], surface, tokens["surface2"])
    return {
        "--on-accent": on_fill(tokens["primary"]),
        "--on-success": on_fill(tokens["success"]),
        "--on-warning": on_fill(tokens["warning"]),
        "--on-danger": on_fill(tokens["danger"]),
        "--primary-ink": ink(tokens["primary"], surface),
        "--success-ink": ink(tokens["success"], surface, grounds=plain),
        "--warning-ink": ink(tokens["warning"], surface, grounds=plain),
        "--danger-ink": ink(tokens["danger"], surface, grounds=plain),
        "--muted-ink": ink(tokens["text_muted"], surface),
        "--tint-base": "var(--surface)",
        "--hue-keep": f"{hue_keep(surface)}%",
        "--hue-pole": pole,
        "--tone-keep": f"{hue_keep(surface, (TONE_YELLOW, TONE_PURPLE), TINT)}%",
        "--tone-pole": pole,
        # a manufacturer's logo is drawn as a one-color silhouette: white on a dark surface, black on a light one
        "--vendor-invert": "1" if pole == WHITE else "0",
    }


def palette_warnings(tokens: dict) -> list[str]:
    """Human-readable contrast warnings for a set of tokens — shown both
    server-side after a save and (the same wording, computed in JS) live as
    the custom-palette form is edited. Never blocks a save; the install
    owner may have a reason."""
    warnings = []
    text_bg = contrast_ratio(tokens["text"], tokens["bg"])
    if text_bg < 4.5:
        warnings.append(f"Text on background is only {text_bg:.1f}:1 — WCAG AA wants at least 4.5:1.")
    muted_bg = contrast_ratio(tokens["text_muted"], tokens["bg"])
    if muted_bg < 3:
        warnings.append(
            f"Muted text on background is only {muted_bg:.1f}:1 — likely hard to read (aim for 3:1 or more)."
        )
    primary_bg = contrast_ratio(tokens["primary"], tokens["bg"])
    if primary_bg < 3:
        warnings.append(
            f"The primary accent on background is only {primary_bg:.1f}:1 — links and buttons may be hard to see (aim for 3:1 or more)."
        )
    return warnings
