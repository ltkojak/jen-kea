"""
tests/test_print.py
───────────────────
v5.70.0-beta.4 (Q208, AX8): a page prints without its chrome. Source tests (`py -m pytest --noconftest tests/test_print.py`); the print rendering in a browser is tests/e2e/test_print.py.
"""

import pathlib
import re
from datetime import datetime, timezone

from jen.services import timefmt

BASE = pathlib.Path("templates/base.html").read_text(encoding="utf-8")


def _print_block():
    start = BASE.index("@media print {")
    depth, i = 0, start
    while True:
        c = BASE[i]
        depth += c == "{"
        depth -= c == "}"
        i += 1
        if depth == 0 and i > start + 15:
            return BASE[start:i]


class TestThePrintSheet:
    def test_it_hides_the_chrome_the_item_names(self):
        hide = _print_block().split("}")[0]
        for selector in (
            ".nav",
            ".section-tabs-wrap",
            ".filter-bar",
            ".pagination",
            ".btn",
            "#jen-toasts",
            ".alert-close",
            "#kb-modal",
            "#jen-confirm-overlay",
            "#jen-prompt-overlay",
            "#jen-session-overlay",
            ".pw-toggle",
            ".tone-menu",
        ):
            assert selector in hide, selector
        assert "display: none !important" in hide

    def test_it_also_hides_the_phone_chrome_and_the_skip_link(self):
        hide = _print_block().split("}")[0]
        for selector in (".tabbar", ".sheet", ".skip-link", "#jen-progress"):
            assert selector in hide, selector

    def test_the_hidden_columns_print(self):
        assert re.search(r"\.hide-mobile, \.hide-tablet \{ display: table-cell !important; \}", _print_block())

    def test_the_table_uses_the_page_and_a_print_size(self):
        assert re.search(r"table\.rowlist \{ width: 100%; font-size: 10pt; \}", _print_block())

    def test_details_open_up_and_links_print_no_urls(self):
        block = _print_block()
        assert "details > *:not(summary) { display: block; }" in block
        assert "a[href]::after { content: none !important; }" in block

    def test_the_page_margin(self):
        assert "@page { margin: 12mm; }" in BASE


class TestPrintIsNotAPhone:
    """SP-1: a portrait A4 or Letter page is 703-725 CSS px wide, and a `(max-width: 768px)` block matches it - the phone layout (and its `.hide-mobile { display: none !important }`, which comes
    later than the print rule and ties it) applied to a printout. The phone and tablet blocks are SCREEN layouts."""

    def test_every_width_block_of_base_names_the_screen(self):
        offenders = [m.group(0) for m in re.finditer(r"@media\s*\(max-width[^{]*\{", BASE)]
        assert not offenders, offenders

    def test_the_phone_blocks_are_still_there(self):
        assert "@media screen and (max-width: 768px) {" in BASE and "@media screen and (max-width: 480px) {" in BASE


class TestThePrintOnlyLine:
    def test_it_is_hidden_on_screen_and_shown_in_print(self):
        assert re.search(r"\n\s*\.print-only \{ display: none; \}", BASE)
        assert re.search(r"@media print \{.*?\.print-only \{ display: block;", BASE, re.S)

    def test_it_says_where_and_when(self):
        m = re.search(r'<p class="print-only">(.*?)</p>', BASE)
        assert m and "Printed from Jen" in m.group(1) and "request.host" in m.group(1) and "print_stamp" in m.group(1)

    def test_it_is_for_a_signed_in_page_only(self):
        assert '{% if current_user.is_authenticated %}<p class="print-only">' in BASE

    def test_its_time_goes_through_the_time_rewriter(self):
        stamp = str(timefmt.fmt_filter(datetime.now(timezone.utc)))
        assert stamp.startswith("<time datetime=") and 'data-jen-time="fmt"' in stamp

    def test_the_host_is_escaped(self):
        assert "{{ request.host }}" in BASE and "request.host|safe" not in BASE
