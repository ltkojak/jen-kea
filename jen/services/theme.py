"""
jen/services/theme.py
───────────────────────
v5.55.0 (Q63) — the one source of truth for every colour token Jen's UI
renders: the seven built-in presets and the validated custom palette a
superadmin can define for the whole install. Pure — no Flask, no DB, no
Jinja — so the generated CSS, the contrast maths and the validator are all
testable directly (tests/test_theme.py).

`dark` and `light` are today's values, byte-identical — the default look
does not change. `contrast` (High Contrast) keeps every text/background
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
every colour, an int-clamped radius, nothing else accepted).
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
# it. Colours and borders, not animation — same "no gimmicks" rule Q63
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
    # above would otherwise paint their menu text white-on-grey too.
    # Same specificity as that rule; wins on source order (later).
    ':root[data-theme="retro"] .nav-dropdown-content a,'
    ':root[data-theme="retro"] .nav-dropdown-content button.linkish{'
    "color:var(--text);"
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
            "text_muted": "#666",
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
            "text_muted": "#6c757d",
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
            "warning": "#ffb000",
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
            "warning": "#ffc247",
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
            "text_muted": "#3c3c3c",
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
    isn't exactly a 3- or 6-digit hex colour — no `rgb()`, no named colours,
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
    bevels); the custom palette never has one, so it never passes this."""
    decls = "".join(f"{CSS_VARS[name]}:{tokens[name]};" for name in TOKENS)
    css = f':root[data-theme="{theme_id}"]{{color-scheme:{color_scheme};{decls}--radius:{radius}px;}}'
    if mono_ui:
        css += f'@media (min-width:769px){{:root[data-theme="{theme_id}"]{{--font-ui:var(--font-mono);}}}}'
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
    allowed to become CSS; nothing downstream re-validates it."""
    errors: list[str] = []
    tokens: dict[str, str] = {}
    for name in TOKENS:
        raw = str(form.get(name, "") or "")
        norm = _normalize_hex(raw)
        if norm is None:
            errors.append(f"{name.replace('_', ' ')}: '{raw}' is not a valid hex colour (e.g. #1a1a2a)")
        else:
            tokens[name] = norm
    radius_raw = str(form.get("radius", "") or "").strip()
    radius = 6
    try:
        radius = int(radius_raw)
        if not (0 <= radius <= 16):
            raise ValueError
    except ValueError:
        errors.append("radius: must be a whole number from 0 to 16")
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
    eleven colours + radius + a checkbox) — `<meta name="color-scheme">`
    mainly steers browser-native chrome (scrollbars, form controls), so a
    background-luminance guess is a fine default rather than one more field."""
    return "light" if _relative_luminance(tokens["bg"]) > 0.5 else "dark"


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
