"""
tests/test_print.py
───────────────────
v5.70.0-beta.4 (Q208, AX8): a page prints without its chrome. Source tests (`py -m pytest --noconftest tests/test_print.py`); the print rendering in a browser is tests/e2e/test_print.py.

v5.70.0-beta.5 (Q210, AZ2): the print sheet is ONE file (static/css/print.css, linked with media="print" by every template that carries its own <html> element), and its rule - the phone and
tablet layouts are SCREEN layouts - is checked over the WHOLE of templates/ and static/, not over base.html alone (Y2, Y21, Y24a).
"""

import pathlib
import re
from datetime import datetime, timezone

from jen.services import timefmt

BASE = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
CSS = pathlib.Path("static/css/print.css").read_text(encoding="utf-8")


def _print_block():
    start = CSS.index("@media print {")
    depth, i = 0, start
    while True:
        c = CSS[i]
        depth += c == "{"
        depth -= c == "}"
        i += 1
        if depth == 0 and i > start + 15:
            return CSS[start:i]


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

    def test_it_hides_the_sign_in_canvas_and_the_card_contents_row(self):
        """Q215 (Z8, Z9): the sign-in page's animated `.bg-canvas` printed as a blank block and the cards' `.card-toc` chip row printed a row of links that go nowhere on paper."""
        hide = _print_block().split("}")[0]
        for selector in (".bg-canvas", ".card-toc"):
            assert selector in hide, selector

    def test_the_hidden_columns_print(self):
        assert re.search(r"\.hide-mobile, \.hide-tablet \{ display: table-cell !important; \}", _print_block())

    def test_the_table_uses_the_page_and_a_print_size(self):
        assert re.search(r"table\.rowlist \{ width: 100%; font-size: 10pt; \}", _print_block())

    def test_details_open_up_and_links_print_no_urls(self):
        block = _print_block()
        assert "details > *:not(summary) { display: block; }" in block
        assert "a[href]::after { content: none !important; }" in block

    def test_a_collapsed_card_prints_whole_whatever_the_medium_of_the_block_that_collapses_it(self):
        assert ".card[data-collapsible].collapsed > :not(.card-header) { display: block !important; }" in _print_block()

    def test_the_page_margin(self):
        assert "@page { margin: 12mm; }" in CSS

    def test_the_sheet_leaves_base_and_is_linked_for_print_only_after_the_inline_style(self):
        """The rules moved: base.html carries the link, never the block (a `body` rule here must come AFTER the page's own, so the link follows the inline <style>)."""
        assert "@media print" not in BASE and "@page" not in BASE
        link = '<link rel="stylesheet" href="/static/css/print.css?v={{ jen_version }}" media="print">'
        assert link in BASE
        assert BASE.index("</style>\n    <!-- v5.53.0") < BASE.index(link) < BASE.index("</head>")


class TestPrintIsNotAPhone:
    """SP-1 / Y2 / Y24a: a portrait A4 or Letter page is 703-725 CSS px wide, and a bare `(max-width: 768px)` block matches it - the phone layout (and `_card_toc.html`'s collapsing of every card but one,
    and a `.hide-mobile { display: none !important }` that ties the print rule) applied to a printout. The phone and tablet blocks are SCREEN layouts. The beta.4 test scanned base.html; Y2 lived in
    `_card_toc.html`. This one reads the WHOLE of templates/ and static/ (and plugins/), `.html`, `.css` and `.js`, and every `@media` with a width in it names `screen`."""

    WIDTH = re.compile(r"(?:max|min)-width")
    #: `matchMedia('(max-width: ...)')` calls in scripts are not stylesheets: they run in a browser on a screen (a tap handler, a chart's sizing) and print never evaluates them. Each entry is
    #: (file, the media query) with the reason; the test compares both ways, so an unreviewed call fails and so does a stale entry.
    REVIEWED_MATCHMEDIA = {
        (
            "templates/base.html",
            "(max-width: 768px)",
        ): "the row-tap handler that opens a row's primary link: a tap is a touch gesture and exists only on a screen (the narrower pointer query beside it, for the UTC reading of a time, is not a width)",
        (
            "templates/reports.html",
            "(max-width: 768px)",
        ): "sizes a chart when the page is drawn on a phone-width screen; a chart is drawn on screen and printed as the image it is",
    }
    CALL = re.compile(r"""matchMedia\(\s*['"](\((?:max|min)-width[^)]*\))""")

    def _files(self):
        for root in ("templates", "static", "plugins"):
            for p in sorted(pathlib.Path(root).rglob("*")):
                if p.is_file() and p.suffix in (".html", ".css", ".js"):
                    yield p

    def test_every_width_block_of_the_whole_tree_names_the_screen(self):
        offenders, scanned = [], 0
        for p in self._files():
            text = p.read_text(encoding="utf-8", errors="replace")
            scanned += 1
            for m in re.finditer(r"@media([^{]*)\{", text):
                if self.WIDTH.search(m.group(1)) and not re.search(r"\bscreen\b", m.group(1)):
                    offenders.append(f"{p.as_posix()}: {m.group(0).strip()}")
        assert scanned > 100, "the walk found too few files to be the whole tree"
        assert not offenders, offenders

    def test_the_python_that_emits_css_names_the_screen_too(self):
        """Second pass 9: jen/services/theme.py writes an `@media (min-width:769px)` block into the page; the tree walk read only .html, .css and .js."""
        offenders = []
        # Q215 (Z12): the tree, not a directory - `jen/`, `plugins/`, `tools/` and the top-level scripts (the tests are the rule's own subject and are left out)
        sources = [p for top in ("jen", "plugins", "tools") for p in sorted(pathlib.Path(top).rglob("*.py"))]
        sources += sorted(pathlib.Path(".").glob("*.py"))
        assert len(sources) > 50, "the walk found too few Python files to be the tree"
        for p in sources:
            for m in re.finditer(r"@media([^{]*)\{", p.read_text(encoding="utf-8")):
                if self.WIDTH.search(m.group(1)) and not re.search(r"\bscreen\b", m.group(1)):
                    offenders.append(f"{p.as_posix()}: {m.group(0).strip()}")
        assert not offenders, offenders

    def test_a_closed_details_prints_open(self):
        """Second pass 8: Chrome keeps the content of a closed <details> out of layout whatever `display` says, so print.css's own rule cannot show it: the page opens them for print and closes them after."""
        assert "window.addEventListener('beforeprint'" in BASE and "details:not([open])" in BASE
        assert "window.addEventListener('afterprint'" in BASE

    def test_the_phone_blocks_are_still_there(self):
        assert "@media screen and (max-width: 768px) {" in BASE and "@media screen and (max-width: 480px) {" in BASE
        assert "@media screen and (max-width: 768px) {" in pathlib.Path("templates/_card_toc.html").read_text(
            encoding="utf-8"
        )

    def test_the_matchmedia_calls_are_exactly_the_reviewed_list(self):
        found = {
            (p.as_posix(), m.group(1))
            for p in self._files()
            for m in self.CALL.finditer(p.read_text(encoding="utf-8", errors="replace"))
        }
        assert found == set(self.REVIEWED_MATCHMEDIA), (
            f"a width-based matchMedia in a script is not on the reviewed list (say why it only runs on a screen), or an entry is stale: {sorted(found ^ set(self.REVIEWED_MATCHMEDIA))}"
        )
        assert all(len(reason) > 20 for reason in self.REVIEWED_MATCHMEDIA.values())


class TestEveryStandalonePageLinksThePrintSheet:
    """Y21: the sign-in page, the forced password change, the second factor and the error page are not built on base.html; under print media the sign-in page kept its dark background and its show/hide button."""

    LINK = re.compile(r'<link rel="stylesheet" href="/static/css/print\.css[^"]*" media="print">')

    def test_every_template_with_its_own_html_element_links_it(self):
        standalone = [
            p
            for p in sorted(pathlib.Path("templates").rglob("*.html"))
            if re.search(r"<!doctype", p.read_text(encoding="utf-8"), re.I)
        ]
        assert len(standalone) >= 5, [p.name for p in standalone]
        missing = [p.name for p in standalone if not self.LINK.search(p.read_text(encoding="utf-8"))]
        assert not missing, missing

    def test_the_link_follows_the_pages_own_style_block(self):
        for name in ("login.html", "force_password_change.html", "mfa_challenge.html", "error.html"):
            text = pathlib.Path("templates", name).read_text(encoding="utf-8")
            assert text.rindex("</style>") < self.LINK.search(text).start() < text.index("</head>"), name


class TestThePrintOnlyLine:
    def test_it_is_hidden_on_screen_and_shown_in_print(self):
        assert re.search(r"\n\s*\.print-only \{ display: none; \}", BASE)
        assert re.search(r"@media print \{.*?\.print-only \{ display: block;", CSS, re.S)

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
