"""
tests/test_search_mark.py
─────────────────────────
v5.70.0-beta.4 (Q208, AX6): a search result marks what matched. `mark_match` escapes FIRST and marks the escaped text, so a hostname that is itself markup (a client names itself) is printed as that
text; `copy_cell(value, label, display)` shows the marked text while `data-copy` stays the raw value. The first classes are pure.
"""

import pathlib
import re

import pytest
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from jen.services.text import mark_match


class TestMarkMatch:
    def test_the_example_of_the_entry(self):
        assert mark_match("<b>printer</b>", "print") == Markup("&lt;b&gt;<mark>print</mark>er&lt;/b&gt;")

    def test_an_empty_or_missing_q_marks_nothing_and_still_escapes(self):
        assert mark_match("<i>x</i>", "") == Markup("&lt;i&gt;x&lt;/i&gt;")
        assert mark_match("<i>x</i>", None) == Markup("&lt;i&gt;x&lt;/i&gt;")
        assert "<mark>" not in mark_match("abc", "")

    def test_it_is_case_insensitive_and_keeps_the_texts_own_case(self):
        assert mark_match("Printer-PRINT", "print") == Markup("<mark>Print</mark>er-<mark>PRINT</mark>")

    def test_nothing_or_none_in_is_empty_out(self):
        assert mark_match(None, "x") == Markup("")
        assert mark_match("", "x") == Markup("")

    @pytest.mark.parametrize(
        "hostile",
        ["<mark>", "</td>", "</mark><script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "&amp;", "a&b"],
    )
    def test_a_hostname_that_is_itself_markup_is_printed_as_text_with_or_without_a_match(self, hostile):
        for q in ("", "a", "mark", "td", "amp", "&", "<", "x"):
            out = str(mark_match(hostile, q))
            stripped = out.replace("<mark>", "").replace("</mark>", "")
            assert "<" not in stripped and ">" not in stripped, (hostile, q, out)
            assert out.count("<mark>") == out.count("</mark>")

    def test_a_q_that_is_a_tag_matches_the_text_not_the_markup(self):
        assert mark_match("<mark>", "<mark>") == Markup("<mark>&lt;mark&gt;</mark>")
        assert mark_match("</td>", "td") == Markup("&lt;/<mark>td</mark>&gt;")

    def test_a_q_inside_an_entity_does_not_split_it(self):
        out = str(mark_match("a&b", "amp"))
        assert out == "a&amp;b", "q='amp' is in the ESCAPED text only: the entity must stay whole"
        assert str(mark_match("a&b", "&")) == "a<mark>&amp;</mark>b"

    def test_regex_metacharacters_in_q_are_literal(self):
        assert mark_match("a.b", ".") == Markup("a<mark>.</mark>b")
        assert mark_match("a(b", "(") == Markup("a<mark>(</mark>b")
        assert "<mark>" not in mark_match("aXb", ".*")

    def test_the_filter_is_registered_as_mark(self):
        assert '_text.mark_match, "mark"' in pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")


class TestTheMacro:
    ENV = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    ENV.filters["mark"] = mark_match

    def _render(self, call):
        return self.ENV.from_string("{% from '_copy.html' import copy_cell %}" + call).render()

    def test_data_copy_is_the_raw_value_whatever_is_displayed(self):
        out = self._render("{{ copy_cell('aa:bb:cc', display='aa:bb:cc'|mark('bb')) }}")
        assert 'data-copy="aa:bb:cc"' in out
        assert ">aa:<mark>bb</mark>:cc</button>" in out

    def test_data_copy_never_contains_a_mark(self):
        out = self._render("{{ copy_cell('<mark>', display='<mark>'|mark('mark')) }}")
        assert re.search(r'data-copy="([^"]*)"', out).group(1) == "&lt;mark&gt;"
        assert "<mark>" not in re.search(r'data-copy="([^"]*)"', out).group(1)

    def test_without_display_it_is_what_it_was(self):
        out = self._render("{{ copy_cell('10.0.0.1') }}")
        assert (
            out
            == '<button type="button" class="copy mono" data-copy="10.0.0.1" title="Copy 10.0.0.1">10.0.0.1</button>'
        )

    def test_a_plain_string_display_is_escaped(self):
        assert "&lt;b&gt;" in self._render("{{ copy_cell('x', display='<b>') }}")

    def test_an_empty_value_prints_nothing_even_with_a_display(self):
        assert self._render("{{ copy_cell('', display='x') }}").strip() == ""


class TestTheSearchPage:
    def test_search_results_marks_every_cell_the_item_names(self):
        text = pathlib.Path("templates/search_results.html").read_text(encoding="utf-8")
        assert text.count("|mark(q)") >= 7
        assert "hostname_or_none(l.hostname, q)" in text and "hostname_or_none(r.hostname, q)" in text

    def test_the_css_mark_rule_reads_the_tokens_that_exist(self):
        base = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        m = re.search(r"\n\s*mark \{([^}]*)\}", base)
        assert m and "color: inherit" in m.group(1) and "var(--warning)" in m.group(1)

    def test_a_route_marks_the_hostname_and_keeps_data_copy_raw(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON('10.99.0.91'), UNHEX('AC00000000A1'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'printer-room')"
            )
        db.commit()
        try:
            html = logged_in_client.get("/search?q=print&list=1").data.decode()
            assert "<mark>print</mark>er-room" in html
            assert 'data-copy="10.99.0.91"' in html
            assert not re.search(r'data-copy="[^"]*<mark>', html)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            db.commit()

    def test_a_client_that_names_itself_markup_is_printed_as_text(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON('10.99.0.92'), UNHEX('AC00000000A2'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, '</td><mark>x')"
            )
        db.commit()
        try:
            html = logged_in_client.get("/search?q=mark&list=1").data.decode()
            assert "&lt;/td&gt;&lt;<mark>mark</mark>&gt;x" in html
            assert "</td><mark>x" not in html
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            db.commit()
