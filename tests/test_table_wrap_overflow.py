"""
tests/test_table_wrap_overflow.py
──────────────────────────────────
v5.1.18 attempted to fix .action-menu-dropdown getting clipped inside
.table-wrap (visible mainly on short, heavily-filtered result sets —
one or two rows, opening the "⋯" menu near the bottom, and getting a
forced tiny scrollbar instead of the menu floating naturally above the
page) by adding overflow-y: visible to .table-wrap.

That fix was wrong and did nothing. The CSS overflow computed-value
fixup rule (one non-visible axis forces the other to behave as
non-visible too) operates on the COMPUTED value, not on whether it was
authored explicitly or left as the default — overflow-x: auto;
overflow-y: visible; computes identically to overflow-x: auto; alone.
There is no way to fix this by tweaking overflow properties on the
same element; v5.1.18 shipped a no-op, and the bug was still fully
present in v5.1.19 exactly as reported.

v5.1.20's actual fix: .action-menu-dropdown is repositioned via JS to
position:fixed (viewport-relative, genuinely escapes ancestor overflow
clipping) computed from the trigger button's own coordinates, only
while open. See positionActionMenuDropdown() in base.html.

This project has no browser-automation test infrastructure (no
Selenium/Playwright/etc.) — nothing here can execute real JS against a
real DOM and assert on actual rendered pixel positions. These tests
are therefore structural: they confirm the fix mechanism is actually
present in the shipped code (the right function exists, calls the
right APIs, is wired to the right events) rather than a full behavioral
guarantee. That's a real limitation, not a substitute for someone
manually confirming the dropdown no longer clips on a short, filtered
table after deploying this.
"""

import pathlib
import re


class TestActionMenuDropdownPositioning:

    def _base_html(self):
        return pathlib.Path("templates/base.html").read_text(errors="ignore")

    def test_table_wrap_still_allows_horizontal_scroll(self):
        """The original, actually-intended behavior — wide tables
        scrolling horizontally on narrow screens — must still work."""
        content = self._base_html()
        match = re.search(r"\.table-wrap\s*\{([^}]*)\}", content)
        assert match, ".table-wrap rule not found in base.html"
        assert re.search(r"overflow-x\s*:\s*auto", match.group(1))

    def test_v5_1_18_ineffective_overflow_y_fix_is_not_reintroduced(self):
        """v5.1.18's overflow-y: visible on .table-wrap did nothing (see
        module docstring) and was reverted in v5.1.20. This isn't
        asserting a *fix* — it's a tripwire against re-adding a change
        that looks plausible, reads like a fix, and does nothing,
        potentially crowding out someone actually attempting the real
        fix (or worse, being trusted as sufficient again)."""
        content = self._base_html()
        match = re.search(r"\.table-wrap\s*\{([^}]*)\}", content)
        assert match, ".table-wrap rule not found in base.html"
        assert not re.search(r"overflow-y\s*:\s*visible", match.group(1)), (
            "overflow-y: visible on .table-wrap computes identically to "
            "leaving overflow-y unset once overflow-x is non-visible (the "
            "CSS overflow fixup rule doesn't distinguish explicit from "
            "defaulted visible) — this property does nothing here and its "
            "presence risks being mistaken for a real fix again."
        )

    def test_position_fixed_repositioning_function_exists(self):
        """The actual fix mechanism must be present: a function that
        switches the dropdown to position:fixed based on the trigger
        button's real coordinates."""
        content = self._base_html()
        assert "function positionActionMenuDropdown" in content
        assert "getBoundingClientRect" in content
        assert re.search(r"dropdown\.style\.position\s*=\s*['\"]fixed['\"]", content)

    def test_repositioning_accounts_for_viewport_bounds_not_container_bounds(self):
        """Must measure against the viewport (document.documentElement
        client dimensions), not against .table-wrap's own box — using
        the container's bounds would just relocate the same clipping
        bug rather than escape it."""
        content = self._base_html()
        assert "document.documentElement.clientWidth" in content
        assert "document.documentElement.clientHeight" in content

    def test_flip_upward_fallback_exists_for_low_viewport_room(self):
        """A button near the bottom of the viewport (exactly the
        short-filtered-table case reported) needs the menu to open
        upward instead of being positioned off-screen below."""
        content = self._base_html()
        # The core flip condition: not enough room below AND enough room above.
        assert re.search(r"rect\.top\s*-\s*dh\s*-\s*4", content)

    def test_open_close_and_scroll_all_manage_inline_position_state(self):
        """Every place a menu closes must clear the inline position
        override, and scrolling must close open menus (a stale fixed
        position would otherwise drift from its trigger as the page
        scrolls underneath it) — otherwise leftover inline styles or a
        drifting menu are new bugs traded for the old one."""
        content = self._base_html()
        assert "function closeActionMenu" in content
        assert "function closeAllActionMenus" in content
        assert re.search(r"addEventListener\(['\"]scroll['\"],\s*function\s*\(\)\s*\{\s*closeAllActionMenus\(\)", content)
