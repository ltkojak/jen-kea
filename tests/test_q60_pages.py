"""
tests/test_q60_pages.py
───────────────────────
v5.53.0 (Q60) — the rest of the pages on the phone: rowlist cells on the remaining
tables, the alert-template accordion, the Reports chart on a phone, labelled selects.

Pure except TestPages (needs the CI database):
`py -m pytest --noconftest tests/test_q60_pages.py -k "not TestPages"`.
"""

import pathlib
import re
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODES = {"primary", "secondary", "badge", "trailing", "hide", "full"}


def _src(name):
    return (ROOT / "templates" / name).read_text(encoding="utf-8")


ROWLIST_TABLES = [
    "_leases6_results.html",
    "_reservations6_results.html",
    "_devices6_results.html",
    "ddns_reconcile.html",
    "users.html",
    "api_keys.html",
    "saved_searches.html",
    "mfa_trusted_devices.html",
    "plugins.html",
    "settings_system.html",
    "logs.html",
    "database.html",
    "config_history.html",
    "settings_kea.html",
    "dhcp_classes.html",
]


class TestRowlistTables:
    def test_every_converted_table_tags_every_body_cell(self):
        for f in ROWLIST_TABLES:
            src = _src(f)
            assert "rowlist" in src, f
            for table in re.findall(r"<table\b[^>]*rowlist[^>]*>.*?</table>", src, re.S):
                body = table[table.index("<tbody") :]
                for td in re.findall(r"<td\b[^>]*>", body):
                    m = re.search(r'data-m="(\w+)"', td)
                    assert m and m.group(1) in MODES, (f, td)

    def test_no_table_outside_base_still_uses_the_old_card_pattern(self):
        left = [
            p.name
            for p in (ROOT / "templates").glob("*.html")
            if p.name != "base.html" and "mobile-cards" in p.read_text(encoding="utf-8")
        ]
        assert not left, left

    def test_each_table_has_a_primary_cell_in_its_row(self):
        for f in ROWLIST_TABLES:
            for table in re.findall(r"<table\b[^>]*rowlist[^>]*>.*?</table>", _src(f), re.S):
                assert 'data-m="primary"' in table or 'data-m="badge"' in table, f

    def test_the_audit_log_keeps_its_details_on_a_phone(self):
        src = _src("logs.html")
        assert re.search(r'data-m="secondary"[^>]*>\{\{ log\.details \}\}', src)


class Forms(HTMLParser):
    """Track form nesting: a <form> opened while another is open is invalid HTML."""

    def __init__(self):
        super().__init__()
        self.depth, self.nested = 0, 0

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            if self.depth:
                self.nested += 1
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == "form" and self.depth:
            self.depth -= 1


class TestAlertAccordion:
    def test_each_template_is_a_details_with_the_type_and_first_line_in_the_summary(self):
        src = _src("settings_alerts.html")
        assert '<details class="al-tpl"' in src and 'class="al-tpl-first"' in src
        assert "striptags" in src and "al-tpl-label" in src

    def test_save_and_reset_are_sibling_forms_not_nested(self):
        src = _src("settings_alerts.html")
        block = src[src.index('<details class="al-tpl"') : src.index("</details>")]
        p = Forms()
        p.feed(block)
        assert p.nested == 0
        assert block.count("<form") == 2
        assert (
            'action="/settings/alerts/save-template"' in block and 'action="/settings/alerts/reset-template"' in block
        )

    def test_expand_and_collapse_all_exist_and_are_wired_without_an_inline_handler(self):
        src = _src("settings_alerts.html")
        assert 'data-al-fold="open"' in src and 'data-al-fold="close"' in src
        assert "d.open = open" in src
        assert not re.search(r"<button[^>]*\sonclick=", src)

    def test_the_textarea_is_labelled_for_screen_readers(self):
        assert 'aria-label="{{ label }} message template"' in _src("settings_alerts.html")

    def test_accordion_styles_live_in_base(self):
        base = _src("base.html")
        for cls in (".al-tpl {", ".al-tpl > summary", ".al-tpl-first", ".al-tpl-text"):
            assert cls in base, cls


class TestReportsOnAPhone:
    def test_chart_gets_a_taller_aspect_ratio_and_a_bottom_legend_on_a_phone(self):
        src = _src("reports.html")
        assert "window.matchMedia('(max-width: 768px)').matches" in src
        assert "aspectRatio: 1.5" in src  # 350px wide -> about 233px tall, above the 200px floor
        assert "position: PHONE ? 'bottom' : 'top'" in src


class TestLabels:
    def test_ipmap_select_is_labelled(self):
        assert 'aria-label="Subnet"' in _src("ipmap.html")

    def test_settings_toc_chips_use_the_scrolling_row(self):
        base = _src("base.html")
        assert ".chip-row, .card-toc { flex-wrap: nowrap;" in base


class TestPages:
    def test_alerts_page_renders_one_accordion_row_per_alert_type(self, logged_in_client):
        from jen.services.alerts import ALERT_TYPE_LABELS

        html = logged_in_client.get("/settings/alerts").data.decode()
        assert html.count('<details class="al-tpl"') == len(ALERT_TYPE_LABELS)
        assert 'action="/settings/alerts/reset-template"' in html
        p = Forms()
        p.feed(html[html.index('id="al-templates"') : html.index("Add/Edit Channel Modal")])
        assert p.nested == 0

    def test_the_stylesheet_is_linked_and_served(self, logged_in_client):
        html = logged_in_client.get("/settings/alerts").data.decode()
        assert "/static/css/ui-classes.css?v=" in html
        r = logged_in_client.get("/static/css/ui-classes.css")
        assert r.status_code == 200 and b".u-" in r.data

    def test_converted_settings_pages_still_render(self, logged_in_client):
        for path in (
            "/settings/users",
            "/settings/api-keys",
            "/settings/logs?tab=alerts",
            "/settings/logs?tab=audit",
            "/settings/databases?tab=backups",
            "/saved-searches",
        ):
            r = logged_in_client.get(path)
            assert r.status_code == 200, path
