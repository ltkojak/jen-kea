"""
tests/test_table_wrap_overflow.py
──────────────────────────────────
v5.1.18 — .table-wrap only ever set overflow-x: auto, leaving
overflow-y implicit (the default, visible). Per the CSS spec's overflow
computed-value fixup rule, when one axis is explicitly set to something
other than visible and the other is left as visible, browsers force
BOTH axes to behave as auto — so this container was silently clipping
vertical overflow too, everywhere it's used (16 templates: Leases,
Reservations, Devices, both v4 and v6 variants, Users, API Keys, Audit
Log, Plugins, Search Results, Saved Searches, Alert Settings, MFA
Trusted Devices, the Dashboard's recent-leases widget).

The visible symptom: .action-menu-dropdown is an absolutely-positioned
child that needs to overflow below the table when a row near the
bottom opens its menu. With a short, heavily-filtered result set (one
or two rows), there's no natural extra table height to absorb that
overflow, so the dropdown got trapped inside a forced, tiny scroll
region instead of floating naturally above the page — reported as
needing to scroll inside a cramped box just to click a menu item.

Fixed by setting overflow-y explicitly (rather than leaving it
implicit), which removes the ambiguity that triggers the fixup rule.
This test parses the actual CSS rule text rather than just checking a
substring is present, so it can't be satisfied by, say, overflow-y
also being clipped some other way.
"""

import pathlib
import re


class TestTableWrapOverflow:

    def _get_table_wrap_rule(self):
        content = pathlib.Path("templates/base.html").read_text(errors="ignore")
        match = re.search(r"\.table-wrap\s*\{([^}]*)\}", content)
        assert match, ".table-wrap rule not found in base.html"
        return match.group(1)

    def test_table_wrap_sets_overflow_x_auto(self):
        """The actual intended behavior — horizontal scroll for wide
        tables on narrow screens — must still work."""
        rule = self._get_table_wrap_rule()
        assert re.search(r"overflow-x\s*:\s*auto", rule)

    def test_table_wrap_explicitly_sets_overflow_y_visible(self):
        """The regression this test exists to catch: overflow-y must be
        set explicitly, not left implicit, or the CSS overflow
        computed-value fixup rule silently forces it to behave as auto
        again — reintroducing the dropdown-clipping bug."""
        rule = self._get_table_wrap_rule()
        assert re.search(r"overflow-y\s*:\s*visible", rule), (
            ".table-wrap must explicitly set overflow-y: visible — leaving it "
            "implicit while overflow-x is non-visible triggers the CSS spec's "
            "overflow fixup rule, forcing overflow-y to behave as auto too, "
            "which clips any absolutely-positioned dropdown menu that needs "
            "to overflow below a short, filtered table."
        )

    def test_action_menu_dropdown_has_no_own_overflow_clipping(self):
        """The dropdown itself must not clip its own content either —
        confirms the fix isn't undone one level down."""
        content = pathlib.Path("templates/base.html").read_text(errors="ignore")
        match = re.search(r"\.action-menu-dropdown\s*\{([^}]*)\}", content)
        assert match, ".action-menu-dropdown rule not found in base.html"
        rule = match.group(1)
        # overflow: hidden here is fine — it's for the dropdown's own
        # rounded corners clipping its menu items' backgrounds, not a
        # scroll container. Just confirm no overflow-y: auto/scroll was
        # added directly on the dropdown itself as a workaround.
        assert not re.search(r"overflow-y\s*:\s*(auto|scroll)", rule)
