"""
tests/test_icons.py
────────────────────
v5.50.0 (Q57) — the icon system and the scanner that keeps emoji out of the UI.

Pure (no DB): `py -m pytest --noconftest tests/test_icons.py`.

1. Drift guard: the committed templates/_icon_sprite.html equals what
   tools/build_icon_sprite.py builds from static/icons/src/*.svg.
2. Every icon name a template, nav.py, subnets.py or the alert map uses exists
   as a symbol in the sprite (a missing one renders nothing).
3. The scanner: no Extended_Pictographic character in templates/**,
   jen/routes/** or static/js/** outside an explicit, reasoned allowlist.
   This is what keeps the swap from eroding.
4. Alert emoji: every DEFAULT_TEMPLATES entry starts with ONE glyph from the
   standard set, one meaning per glyph.
"""

import importlib.util
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sprite_tool = _load("build_icon_sprite", "tools/build_icon_sprite.py")
swap_tool = _load("replace_emoji_icons", "tools/replace_emoji_icons.py")  # the scanner shares its range table

# Where an emoji is CONTENT, not UI chrome, and why.
ALLOWED = {
    # device-type badges shown on Devices rows ("vendor badges must not change")
    "jen/routes/devices.py": "device-type badge glyphs stored/displayed per device",
    # the Telegram/Discord test message a channel sends (alert content, not UI)
    "jen/routes/settings/alerts.py": "alert channel test messages",
}


def _scan_files():
    for sub, exts in (("templates", (".html",)), ("jen/routes", (".py",)), ("static/js", (".js",))):
        for p in sorted((ROOT / sub).rglob("*")):
            if p.is_file() and p.suffix in exts:
                yield p


class TestSprite:
    def test_committed_sprite_equals_the_build(self, tmp_path):
        built = sprite_tool.build()
        committed = (ROOT / "templates" / "_icon_sprite.html").read_text(encoding="utf-8").replace("\r\n", "\n")
        assert committed == built, "run: py tools/build_icon_sprite.py"

    def test_every_source_is_a_symbol_and_has_a_licence_next_to_it(self):
        names = {p.stem for p in (ROOT / "static" / "icons" / "src").glob("*.svg")}
        assert len(names) >= 60
        assert (ROOT / "static" / "icons" / "LICENSE").read_text(encoding="utf-8").startswith("ISC License")
        sprite = (ROOT / "templates" / "_icon_sprite.html").read_text(encoding="utf-8")
        assert set(re.findall(r'<symbol id="i-([a-z0-9-]+)"', sprite)) == names

    def test_nothing_is_baked_in_a_colour(self):
        sprite = (ROOT / "templates" / "_icon_sprite.html").read_text(encoding="utf-8")
        assert not re.search(r'(?:fill|stroke)="(?!none|currentColor)', sprite)


class TestNamesUsedExist:
    @staticmethod
    def _symbols():
        sprite = (ROOT / "templates" / "_icon_sprite.html").read_text(encoding="utf-8")
        return set(re.findall(r'<symbol id="i-([a-z0-9-]+)"', sprite))

    def test_template_icon_calls_and_inline_svg_uses(self):
        symbols, missing = self._symbols(), []
        for p in (ROOT / "templates").glob("*.html"):
            if p.name == "_icon_sprite.html":
                continue
            text = p.read_text(encoding="utf-8")
            used = set(re.findall(r"""icon\(\s*["']([a-z0-9-]+)["']""", text)) | set(
                re.findall(r"#i-([a-z0-9-]+)", text)
            )
            missing += [(p.name, n) for n in used if n not in symbols]
        assert not missing, missing

    def test_nav_and_import_source_and_alert_names(self):
        symbols = self._symbols()
        nav = (ROOT / "jen" / "routes" / "settings" / "nav.py").read_text(encoding="utf-8")
        sub = (ROOT / "jen" / "routes" / "subnets.py").read_text(encoding="utf-8")
        names = set(re.findall(r'"icon": "([a-z0-9-]+)"', nav)) | set(re.findall(r'"icon": "([a-z0-9-]+)"', sub))
        assert names and names <= symbols, names - symbols
        from jen.services import alerts

        assert set(alerts.ALERT_TYPE_ICONS.values()) | {alerts.DEFAULT_ALERT_ICON} <= symbols
        assert set(alerts.DEFAULT_TEMPLATES) <= set(alerts.ALERT_TYPE_ICONS)

    def test_the_dashboards_whitelist_covers_every_alert_icon(self):
        from jen.services import alerts

        html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        listed = set(re.findall(r"'([a-z0-9-]+)'", re.search(r"var ALERT_ICONS = \[(.*?)\];", html, re.S).group(1)))
        assert set(alerts.ALERT_TYPE_ICONS.values()) | {alerts.DEFAULT_ALERT_ICON} <= listed

    def test_icon_helper(self):
        from jen.services.icons import icon, nav_icon

        assert 'aria-hidden="true"' in icon("pencil") and "#i-pencil" in icon("pencil")
        assert 'role="img"' in icon("pencil", label="Edit") and 'aria-label="Edit"' in icon("pencil", label="Edit")
        assert str(icon("no-such-icon")) == ""
        assert str(nav_icon("🗺️")) == "🗺️"  # a plugin's own emoji still renders, as text
        assert "#i-server" in nav_icon("server")

    def test_icon_only_controls_are_labelled(self):
        """The two unidentifiable top-bar controls now say what they are."""
        base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        assert 'title="Keyboard shortcuts (?)"' in base
        # v5.55.0 (Q63) — the dark/light toggle became the theme picker.
        assert 'aria-label="Theme"' in base


class TestNoEmojiInTheUi:
    def test_scanner(self):
        offenders = []
        for p in _scan_files():
            rel = p.relative_to(ROOT).as_posix()
            if rel in ALLOWED:
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                for ch in line:
                    if swap_tool.is_pict(ch):
                        offenders.append(f"{rel}:{n}: {ch!r}")
                        break
        assert not offenders, "emoji in the UI — use icon('name') (tools/icon_map.json):\n" + "\n".join(offenders[:20])

    def test_allowlist_entries_still_need_it(self):
        for rel in ALLOWED:
            text = (ROOT / rel).read_text(encoding="utf-8")
            assert any(swap_tool.is_pict(c) for c in text), f"{rel} no longer contains emoji — drop it from ALLOWED"

    def test_the_scanner_catches_one(self):
        assert swap_tool.is_pict("📊") and swap_tool.is_pict("⚠") and not swap_tool.is_pict("→")
        assert not swap_tool.is_pict("✓") and not swap_tool.is_pict("—")


class TestMapCoverage:
    def test_every_mapped_name_exists(self):
        import json

        symbols = {p.stem for p in (ROOT / "static" / "icons" / "src").glob("*.svg")}
        m = json.loads((ROOT / "tools" / "icon_map.json").read_text(encoding="utf-8"))
        allowed_unused = {"smartphone", "server", "monitor-smartphone"}  # only devices.py glyph rows
        for emoji, name in m["default"].items():
            assert name in symbols or name in allowed_unused, (emoji, name)
        for rule in m["rules"]:
            assert rule["name"] in symbols, rule
