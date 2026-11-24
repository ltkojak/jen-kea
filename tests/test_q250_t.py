"""
tests/test_q250_t.py
────────────────────
Q250, lane t - the top row and the section strip span the window again; only the content column is 1,400 px (1,800 px on a list page). Source facts: the
measurements in a browser are tests/e2e/test_q250_t.py.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")


def _rule(selector):
    return re.search(r"\n\s*" + re.escape(selector) + r" \{([^}]*)\}", BASE).group(1)


class TestTheTopRowSpansTheWindow:
    def test_the_inner_row_has_no_max_width_and_no_auto_margin(self):
        rule = _rule(".nav-inner")
        assert "max-width" not in rule and "margin" not in rule, rule
        assert (
            "padding: 0 20px" in rule and "env(safe-area-inset-left)" in rule and "env(safe-area-inset-right)" in rule
        )

    def test_nothing_in_the_page_names_the_old_column_variable(self):
        assert "--page-w" not in BASE

    def test_the_strip_has_no_max_width_and_no_auto_margin(self):
        rule = re.search(r"\.section-tabs-wrap > \.section-tabs \{([^}]*)\}", BASE).group(1)
        assert "max-width" not in rule and "margin" not in rule, rule
        assert "min-height: 39px" in rule and "border-bottom: 0" in rule

    def test_the_strips_fades_sit_at_its_own_edges(self):
        assert re.search(r"\.section-tabs-wrap::after \{ content: \"\"; position: absolute; right: 0;", BASE)
        assert re.search(r"\.section-tabs-wrap::before \{ content: \"\"; position: absolute; left: 0;", BASE)
        assert not re.search(r"\.section-tabs-wrap::(before|after) \{ (left|right): max\(", BASE)

    def test_the_content_column_is_as_it_was(self):
        assert ".container { max-width: 1400px; margin: 0 auto; padding: 20px; }" in BASE
        assert ".content--wide { max-width: 1800px; }" in BASE
