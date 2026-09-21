"""
tests/test_ui_classes.py
────────────────────────
v5.53.0 (Q60) — the generated stylesheet that replaced the static inline styles.

tools/extract_inline_styles.py moved `style="…"` attributes into `u-xxxxxx` classes and
regenerates static/css/ui-classes.css from tools/inline_style_map.json. These tests keep the
three in step and keep the pieces of the design that are easy to break: nothing that a script
toggles was converted, the standalone pages do not depend on a stylesheet they do not load,
and a fixed multi-column grid collapses on a phone.

Pure (no DB): `py -m pytest --noconftest tests/test_ui_classes.py`.
"""

import importlib.util
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _tool():
    spec = importlib.util.spec_from_file_location("extract_inline_styles", ROOT / "tools" / "extract_inline_styles.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = _tool()
CSS = (ROOT / "static" / "css" / "ui-classes.css").read_text(encoding="utf-8").replace("\r\n", "\n")
MAP = json.loads((ROOT / "tools" / "inline_style_map.json").read_text(encoding="utf-8"))
TEMPLATES = sorted((ROOT / "templates").glob("*.html"))
CLASS_USE = re.compile(r"\bu-[0-9a-f]{6}\b")
# Templates the next step converts (Q60 step 2: the Settings pages); empty once it lands.
PENDING = {
    "api_docs.html",
    "api_keys.html",
    "user_profile.html",
    "users.html",
    "settings_kea.html",
    "settings_alerts.html",
    "settings_system.html",
    "settings_security.html",
    "settings_appearance.html",
    "database.html",
    "database_migrate.html",
    "database_import_confirm.html",
    "plugins.html",
    "logs.html",
    "saved_searches.html",
    "mfa_enroll.html",
    "mfa_trusted_devices.html",
    "mfa_backup_codes.html",
    "reauth.html",
    "logout_confirm.html",
}


def _all_template_text():
    return {p.name: p.read_text(encoding="utf-8") for p in TEMPLATES}


class TestGeneratedStylesheet:
    def test_css_is_exactly_what_the_map_renders(self):
        assert tool.render_css(MAP) == CSS, "run: py tools/extract_inline_styles.py --check"

    def test_class_names_are_the_hash_of_their_declarations(self):
        for decl, cls in MAP.items():
            assert cls == tool.class_for(decl), (decl, cls)

    def test_every_class_a_template_uses_exists_in_the_css(self):
        defined = set(CLASS_USE.findall(CSS))
        missing = {}
        for name, text in _all_template_text().items():
            for c in set(CLASS_USE.findall(text)) - defined:
                missing.setdefault(name, []).append(c)
        assert not missing, missing

    def test_no_class_in_the_css_is_unused(self):
        used = set()
        for text in _all_template_text().values():
            used |= set(CLASS_USE.findall(text))
        unused = set(CLASS_USE.findall(CSS)) - used
        assert not unused, f"unused generated classes (delete them from the map): {sorted(unused)[:10]}"

    def test_rules_double_their_selector_for_precedence(self):
        for cls in MAP.values():
            assert f".{cls}.{cls}{{" in CSS

    def test_base_links_the_stylesheet_after_its_own_style_block(self):
        base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        assert '<link rel="stylesheet" href="/static/css/ui-classes.css?v={{ jen_version }}">' in base
        assert base.index("</style>") < base.index("ui-classes.css")


class TestWhatWasLeftAlone:
    def test_nothing_a_script_toggles_was_converted(self):
        for decl in MAP:
            assert not tool.SKIP_PROPS.search(decl), decl

    def test_standalone_pages_do_not_use_the_stylesheet(self):
        for name in ("login.html", "mfa_challenge.html", "force_password_change.html", "error.html"):
            assert not CLASS_USE.search((ROOT / "templates" / name).read_text(encoding="utf-8")), name

    def test_no_style_with_jinja_was_touched(self):
        for decl in MAP:
            assert "{" not in decl

    def test_the_extractor_finds_nothing_left_to_convert(self):
        uses = tool.count_uses()
        for name, text in _all_template_text().items():
            if name in PENDING or not (name.startswith("_") or tool.EXTENDS_RE.search(text)):
                continue
            _, n = tool.convert(text.replace("\r\n", "\n"), dict(MAP), uses)
            assert n == 0, (
                f"{name}: {n} more static styles could be extracted: py tools/extract_inline_styles.py templates/{name}"
            )


class TestPhoneCollapse:
    def test_fixed_multi_column_grids_collapse(self):
        assert tool.stacks_on_phone("display:grid;grid-template-columns:1fr 1fr;gap:16px")
        assert tool.stacks_on_phone("display:grid;grid-template-columns:repeat(3,1fr)")
        assert not tool.stacks_on_phone("display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))")
        assert not tool.stacks_on_phone("display:flex;gap:8px")

    def test_the_css_carries_a_phone_block_for_them(self):
        assert "@media (max-width:768px){" in CSS
        grids = [c for d, c in MAP.items() if tool.stacks_on_phone(d)]
        assert grids and all(f".{c}.{c}{{grid-template-columns:1fr}}" in CSS for c in grids)


class TestConvertMechanics:
    def test_adds_to_an_existing_class_or_creates_one(self):
        uses = {"color:red": 2}
        out, n = tool.convert('<p class="a" style="color:red">x</p><p style="color:red">y</p>', {}, uses)
        assert n == 2
        assert 'class="a u-' in out and out.count("style=") == 0 and out.count('class="u-') == 1

    def test_leaves_jinja_display_none_fixed_and_one_offs_alone(self):
        src = (
            '<p style="color:{{ c }}">a</p><p style="display:none">b</p>'
            '<p style="position:fixed;top:0">c</p><p style="color:blue">d</p>'
        )
        out, n = tool.convert(src, {}, {"color:blue": 1})
        assert n == 0 and out == src

    def test_a_class_attribute_with_inner_quotes_is_left_alone(self):
        src = '<p class="{{ \'a\' if x else "b" }}" style="color:red">x</p>'
        out, n = tool.convert(src, {}, {"color:red": 3})
        assert n == 0 and out == src
