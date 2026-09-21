"""
tests/test_ui_ratchet.py
────────────────────────
v5.51.0 (Q58) — the UI debt only goes down.

Two counters that a later change may lower and never raise:

1. The number of inline `style="` attributes across templates/**. Q58 measured
   the starting value; Q59 and Q60 move the phone layouts into classes and
   lower it (Q60 targets < 600). When a change lowers the count, lower
   MAX_INLINE_STYLES to the new number in the same commit and say so in the
   CHANGELOG entry. Raising it is the failure this test exists to cause.
2. The size of the emoji scanner's allowlist (tests/test_icons.py ALLOWED):
   content that is genuinely not interface chrome. It should shrink, not grow.

Pure (no DB): `py -m pytest --noconftest tests/test_ui_ratchet.py`.
"""

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Q58 measured 1,739 across templates/**; Q59 (Leases, Reservations, Devices) lowered it to 1,645; Q60 (extracted classes, Management + Network + Settings) to 507.
MAX_INLINE_STYLES = 507
MAX_EMOJI_ALLOWLIST = 2


def _inline_style_count():
    total = 0
    for p in (ROOT / "templates").rglob("*"):
        if p.is_file():
            total += p.read_text(encoding="utf-8").count('style="')
    return total


class TestInlineStyleRatchet:
    def test_inline_styles_never_grow(self):
        n = _inline_style_count()
        assert n <= MAX_INLINE_STYLES, (
            f"{n} inline style= attributes in templates/ (ceiling {MAX_INLINE_STYLES}). "
            "Use a class or a utility from base.html (docs/ui.md) instead of a new inline style."
        )

    def test_a_lower_count_lowers_the_ceiling(self):
        """The ratchet only works if the ceiling follows the count down."""
        n = _inline_style_count()
        assert n >= MAX_INLINE_STYLES - 25, (
            f"templates/ now has {n} inline styles, well under the ceiling {MAX_INLINE_STYLES}: "
            f"set MAX_INLINE_STYLES = {n} in tests/test_ui_ratchet.py and note it in the CHANGELOG."
        )


class TestEmojiAllowlistRatchet:
    def test_allowlist_never_grows(self):
        spec = importlib.util.spec_from_file_location("test_icons_for_ratchet", ROOT / "tests" / "test_icons.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert len(mod.ALLOWED) <= MAX_EMOJI_ALLOWLIST, sorted(mod.ALLOWED)
