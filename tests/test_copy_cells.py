"""
tests/test_copy_cells.py
────────────────────────
v5.70.0-beta.2 (Q206, AV3): a MAC or an IP printed as text on a list is a copy control (`templates/_copy.html::copy_cell`), served by ONE delegated listener in base.html.

Pure source and render tests - no database (`py -m pytest --noconftest tests/test_copy_cells.py`). Copying in a real browser, over a secure context and over the plain-http fallback, is
tests/e2e/test_ui_polish.py.
"""

import pathlib
import re
from html.parser import HTMLParser

import pytest
from jinja2 import Environment, FileSystemLoader

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
BASE = (TEMPLATES / "base.html").read_text(encoding="utf-8")

# the row partials tests/test_investigate_links.py::test_the_row_partials_import_the_macro walks, and the search page
ROW_PARTIALS = [
    "_lease_rows.html",
    "_reservation_row.html",
    "_device_rows.html",
    "_recent_leases.html",
    "_recent_leases_rows.html",
    "search_results.html",
]

# `{{ x.mac }}`, `{{ x.ip|f }}`, `{{ x.last_ip or '—' }}` - the whole expression IS the value (a macro call that takes it as an argument is not a print)
PRINTS_THE_VALUE = re.compile(r"\{\{\s*\w+\.(?:mac|ip|last_ip)\s*(?:(?:\||or\s)[^}]*)?\}\}")
# a reviewed exception is a (template, line fragment) -> the reason. Empty: every printed MAC and IP in the row partials is a copy control.
REVIEWED: dict = {}


def text_nodes_that_print_a_value(source):
    """The `{{ x.mac }}`-shaped prints left in `source` once the copy_cell calls, the Jinja statements and comments, and every HTML tag (attributes included) are gone."""
    source = re.sub(r"\{#.*?#\}", "", source, flags=re.S)
    source = re.sub(r"\{%.*?%\}", "", source, flags=re.S)
    source = re.sub(r"<!--.*?-->", "", source, flags=re.S)
    source = re.sub(r"\{\{\s*copy_cell\(.*?\)\s*(?:or [^}]*)?\}\}", "", source, flags=re.S)
    source = re.sub(r"<[^>]*>", "", source)
    return PRINTS_THE_VALUE.findall(source)


class TestEveryMacAndIpIsACopyControl:
    @pytest.mark.parametrize("name", ROW_PARTIALS)
    def test_nothing_is_printed_bare(self, name):
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        left = [x for x in text_nodes_that_print_a_value(source) if (name, x) not in REVIEWED]
        assert not left, f"{name} prints {left} as plain text - wrap it in copy_cell() (templates/_copy.html)"

    @pytest.mark.parametrize("name", ROW_PARTIALS)
    def test_the_partial_imports_the_macro(self, name):
        assert "import copy_cell" in (TEMPLATES / name).read_text(encoding="utf-8")

    def test_the_sweep_sees_what_it_is_for(self):
        assert text_nodes_that_print_a_value('<td class="mono">{{ l.mac }}</td>')
        assert text_nodes_that_print_a_value("<td>{{ d.last_ip or '—' }}</td>")
        assert text_nodes_that_print_a_value("<td>{{ r.ip|upper }}</td>")

    def test_the_sweep_ignores_what_is_not_a_text_node(self):
        for ok in (
            '<td class="mono">{{ copy_cell(l.mac) }}</td>',
            "<td>{{ copy_cell(d.last_ip) or '—' }}</td>",
            '<a href="/timeline?mac={{ l.mac }}">x</a>',
            '<button data-mac="{{ d.mac }}" title="{{ d.ip }}">x</button>',
            "{{ investigate_link(l.mac) }}",
            "{{ device_badge(device_info, l.mac, a, b) }}",
            "{# {{ l.mac }} #}",
        ):
            assert not text_nodes_that_print_a_value(ok), ok

    def test_the_reviewed_list_is_empty(self):
        assert REVIEWED == {}


class TestOneListener:
    def test_base_defines_exactly_one_data_copy_listener(self):
        assert BASE.count("closest('[data-copy]')") == 1

    def test_nothing_else_listens_for_data_copy(self):
        offenders = [
            p.as_posix()
            for p in sorted(TEMPLATES.glob("*.html")) + sorted((ROOT / "plugins").rglob("*.html"))
            if p.name not in ("base.html", "_copy.html") and "[data-copy]" in p.read_text(encoding="utf-8")
        ]
        assert not offenders, offenders

    def test_the_listener_is_inside_the_nonced_script_and_delegated_to_document(self):
        i = BASE.index("closest('[data-copy]')")
        before = BASE[:i]
        assert before.rindex("<script nonce=") > before.rindex("</script>")
        assert BASE[:i].rindex("document.addEventListener('click'") > BASE[:i].rindex("window.jenCopyText = ")

    def test_a_secure_context_uses_the_clipboard_api_and_a_plain_http_page_the_fallback(self):
        body = BASE[BASE.index("window.jenCopyText = function") : BASE.index("closest('[data-copy]')")]
        assert "window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText" in body
        assert "Promise.resolve(legacyCopy(text))" in body
        # a rejected clipboard write falls through to the same fallback
        assert "function() { return legacyCopy(text); }" in body
        legacy = BASE[BASE.index("function legacyCopy(") : BASE.index("window.jenCopyText = function")]
        assert "document.execCommand('copy')" in legacy and "sink.select()" in legacy and "sink.remove()" in legacy

    def test_a_copy_says_so_with_a_toast_and_a_class_for_1_2_seconds(self):
        body = BASE[BASE.index("closest('[data-copy]')") :]
        body = body[: body.index("});\n", body.index("setTimeout"))]
        assert "window.jenToast('Copied ' + value, 'success')" in body
        assert "classList.add('copied')" in body and "}, 1200)" in body
        assert "Could not copy " in body  # a copy that failed says so too

    def test_the_shared_copier_is_what_the_two_older_copy_buttons_use(self):
        for name in ("mfa_backup_codes.html", "api_keys.html"):
            assert "jenCopyText(" in (TEMPLATES / name).read_text(encoding="utf-8")


def _env():
    return Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)


class TestTheMacro:
    def render(self, expr, **ctx):
        return _env().from_string("{% from '_copy.html' import copy_cell %}" + expr).render(**ctx)

    def test_it_renders_a_button_that_is_styled_as_text(self):
        out = self.render("{{ copy_cell(v) }}", v="aa:bb:cc:dd:ee:ff")
        assert out == (
            '<button type="button" class="copy mono" data-copy="aa:bb:cc:dd:ee:ff" title="Copy aa:bb:cc:dd:ee:ff">aa:bb:cc:dd:ee:ff</button>'
        )

    def test_the_title_can_name_what_is_copied(self):
        out = self.render("{{ copy_cell(v, 'the MAC') }}", v="10.0.0.5")
        assert 'title="Copy the MAC"' in out and ">10.0.0.5</button>" in out

    def test_the_value_is_escaped_in_the_attribute_and_in_the_text(self):
        out = self.render("{{ copy_cell(v) }}", v='"><script>x</script>')
        assert "<script>" not in out and "&#34;&gt;&lt;script&gt;" in out

    @pytest.mark.parametrize("empty", [None, ""])
    def test_an_empty_value_prints_nothing_so_the_caller_can_write_a_dash(self, empty):
        assert self.render("{{ copy_cell(v) }}", v=empty) == ""
        assert self.render("{{ copy_cell(v) or '—' }}", v=empty) == "—"


class Buttons(HTMLParser):
    """The text nodes of a page, split into those inside a [data-copy] button and those outside."""

    def __init__(self):
        super().__init__()
        self.inside, self.outside, self._depth = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag == "button" and "data-copy" in dict(attrs):
            self._depth += 1

    def handle_endtag(self, tag):
        if tag == "button" and self._depth:
            self._depth -= 1

    def handle_data(self, data):
        if data.strip():
            (self.inside if self._depth else self.outside).append(data.strip())


class TestRenderedRows:
    def _render(self, name, **ctx):
        from tests.test_list_pages_phone import _env as phone_env

        base = {
            "current_user": type("U", (), {"role": "admin", "all_subnets": True, "is_authenticated": True})(),
            "show_expired": False,
            "ipv6_enabled": False,
            "subnet6_map": {},
        }
        base.update(ctx)
        return phone_env().get_template(name).render(**base)

    def test_a_lease_row_prints_its_ip_and_both_mac_lines_as_copy_controls(self):
        from tests.test_list_pages_phone import _lease

        html = self._render("_lease_rows.html", leases=[_lease()])
        parsed = Buttons()
        parsed.feed(html)
        assert parsed.inside.count("10.0.0.5") == 1
        assert parsed.inside.count("aa:bb:cc:dd:ee:ff") == 2  # the MAC cell and the action menu's line
        assert not [t for t in parsed.outside if "10.0.0.5" in t or "aa:bb:cc:dd:ee:ff" in t], parsed.outside

    def test_a_reservation_row_prints_its_ip_and_both_mac_lines_as_copy_controls(self):
        from tests.test_list_pages_phone import _res

        html = self._render("_reservation_row.html", h=_res())
        parsed = Buttons()
        parsed.feed(html)
        assert parsed.inside.count("10.0.0.9") == 1
        assert parsed.inside.count("aa:bb:cc:00:00:01") == 2
        assert not [t for t in parsed.outside if "10.0.0.9" in t or "aa:bb:cc:00:00:01" in t], parsed.outside

    def test_the_copy_control_sits_inside_the_cell_so_the_phone_shape_is_unchanged(self):
        from tests.test_list_pages_phone import _cells, _lease

        cells = _cells(self._render("_lease_rows.html", leases=[_lease()]))[0]
        assert [m for m, _ in cells] == [
            None,
            "secondary",
            "primary",
            "hide",
            "secondary",
            "hide",
            "secondary",
            "trailing",
        ]
        assert cells[1][1] == "10.0.0.5"
