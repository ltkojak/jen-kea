"""
tests/test_q248_c2.py
─────────────────────
Q248, stage c2: four redesigns, as far as a rendered page and a template's source can hold them. The browser's half (a row opens with the keyboard, the
open rows survive a reload, a chart's axis, a phone's widths) is tests/e2e/test_q248_c2.py. The two leftovers of stage c1 (a status word is its token's
ink; a toast carries its category's icon) are in c1's own files.

* V44  Subnets is a LIST: one row per subnet the account sees, the name the row's largest text, the detail that was the whole card closed under it.
* V38  the page pills are real tabs in ONE in-page tab style, drawn on every page of their group and only for the roles each page lets in; the jump pills
       are one line, "On this page:", a link per card in card order, each the card's own title.
* V42  the plugins are listed once in each place: name, version and status on Settings - System, the whole description in the Plugin Manager, whose
       "Available" offers only what is not installed and whose missing host package is a sentence with its command in a box.
* V53  Reports: the y-axis fits the lines, the pool is a dashed line inside the range or a figure in the card's text, Scale to Pool is today's view.
"""

import pathlib
import re
from html.parser import HTMLParser
from unittest.mock import patch

import pytest

from jen import extensions
from jen.routes.settings import nav as navmod
from jen.services import plugins as plugins_svc
from tests.conftest import restricted_client

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
BASE = (TEMPLATES / "base.html").read_text(encoding="utf-8")

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class _Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children, self.text = [], []  # `text` is the element's OWN text, not its descendants'

    @property
    def classes(self):
        return (self.attrs.get("class") or "").split()

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def find(self, cls):
        return [n for n in self.walk() if cls in n.classes]

    def all_text(self):
        return " ".join(" ".join(t for n in self.walk() for t in n.text).split())

    def own_text(self):
        return " ".join(" ".join(self.text).split())


class _Tree(HTMLParser):
    """A page as a tree of elements: enough to ask "which cards are the children of this column block, in order" without a regular expression."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("root", [], None)
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self.cur)
        self.cur.children.append(node)
        if tag not in VOID:
            self.cur = node

    def handle_startendtag(self, tag, attrs):
        self.cur.children.append(_Node(tag, attrs, self.cur))

    def handle_endtag(self, tag):
        n = self.cur
        while n is not None and n.tag != tag:
            n = n.parent
        if n is not None and n.parent is not None:
            self.cur = n.parent

    def handle_data(self, data):
        if data.strip():
            self.cur.text.append(data)


def _tree(html):
    t = _Tree()
    t.feed(html)
    return t.root


def _forms_without_a_token(root):
    out = []
    for form in (n for n in root.walk() if n.tag == "form"):
        if (form.attrs.get("method") or "").upper() != "POST":
            continue
        if not any(n.tag == "input" and n.attrs.get("name") == "csrf_token" for n in form.walk()):
            out.append(form.attrs.get("action"))
    return out


# ── V44: Subnets ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

NET_A = {"name": "C2 Office", "cidr": "10.99.0.0/24"}
NET_B = {"name": "ZZ-C2-HIDDEN", "cidr": "10.77.0.0/24"}
CFG = {
    "valid-lifetime": 3600,
    "renew-timer": 1800,
    "rebind-timer": 3150,
    "option-data": [{"name": "domain-name-servers", "data": "9.9.9.9"}],
    "shared-networks": [],
    "subnet4": [
        {
            "id": 1,
            "subnet": "10.99.0.0/24",
            "valid-lifetime": 86400,
            "pools": [{"pool": "10.99.0.10 - 10.99.0.50"}],
            "option-data": [{"name": "routers", "data": "10.99.0.1"}],
        },
        {
            "id": 2,
            "subnet": "10.77.0.0/24",
            "pools": [{"pool": "10.77.0.10 - 10.77.0.20"}],
            "option-data": [{"name": "routers", "data": "10.77.0.1"}],
        },
    ],
}


@pytest.fixture
def two_nets(monkeypatch):
    from jen.services import kea as kea_svc

    def fake(command, *a, **kw):
        if command == "config-get":
            return {"result": 0, "arguments": {"Dhcp4": CFG}}
        return {"result": 0, "text": "mocked", "arguments": {"subnet4": [], "Dhcp4": {}, "hosts": []}}

    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(NET_A), 2: dict(NET_B)})
    monkeypatch.setattr(kea_svc, "kea_command", fake)
    monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1, "name": "Test Kea"})
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)


@pytest.fixture
def ssh_ready(monkeypatch):
    """The page offers Edit and Move only where a config change can be written: the SSH key exists and a host is set."""
    import os

    real = os.path.exists
    monkeypatch.setattr("os.path.exists", lambda p: True if p == extensions.SSH_KEY_PATH else real(p))
    monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")


def _rows(html):
    return _tree(html).find("subnet-row")


class TestSubnetsIsAList:
    def test_a_superadmin_gets_one_row_per_subnet(self, logged_in_client, two_nets):
        rows = _rows(logged_in_client.get("/subnets").get_data(as_text=True))
        assert [r.attrs["data-subnet-id"] for r in rows] == ["1", "2"]
        assert [r.find("subnet-name")[0].all_text() for r in rows] == [NET_A["name"], NET_B["name"]]
        assert [r.find("subnet-cidr")[0].all_text() for r in rows] == [NET_A["cidr"], NET_B["cidr"]]

    def test_a_row_is_a_real_button_that_names_the_detail_it_opens_and_starts_closed(self, logged_in_client, two_nets):
        rows = _rows(logged_in_client.get("/subnets").get_data(as_text=True))
        assert len(rows) == 2
        for row in rows:
            sid = row.attrs["data-subnet-id"]
            (toggle,) = row.find("subnet-toggle")
            assert toggle.tag == "button" and toggle.attrs["type"] == "button"
            assert toggle.attrs["aria-expanded"] == "false" and toggle.attrs["aria-controls"] == f"subnet-detail-{sid}"
            (detail,) = row.find("subnet-detail")
            assert detail.attrs["id"] == f"subnet-detail-{sid}" and "hidden" in detail.attrs
            assert toggle.find("subnet-name"), "the name is the button's text"

    def test_the_row_shows_the_badge_the_bar_with_its_figures_the_lease_time_the_gateway_and_the_options(
        self, logged_in_client, two_nets
    ):
        row = _rows(logged_in_client.get("/subnets").get_data(as_text=True))[0]
        (head,) = row.find("subnet-row-head")
        assert [b.all_text() for b in head.find("badge") if any(c.startswith("badge-tone-") for c in b.classes)][0] == (
            NET_A["name"]
        ), "the subnet's own badge"
        (usage,) = head.find("subnet-usage")
        bars = [n for n in usage.walk() if n.tag == "progress"]
        assert len(bars) == 1 and bars[0].attrs["class"].startswith("pool-use usage-bar usage-")
        assert re.fullmatch(r"\d+ of 41 \(\d+%\)", usage.find("subnet-usage-figures")[0].all_text())
        cells = {c.find("stat-label")[0].all_text(): c.all_text() for c in head.find("subnet-cell")}
        assert cells["Lease time"] == "Lease time 1 d"
        assert cells["Gateway"] == "Gateway 10.99.0.1"
        assert cells["Options"] == "Options 2", "routers on the subnet and the global name servers"

    def test_the_detail_keeps_what_the_card_showed(self, logged_in_client, two_nets):
        row = _rows(logged_in_client.get("/subnets").get_data(as_text=True))[0]
        text = row.find("subnet-detail")[0].all_text()
        for expected in (
            "Lease Duration",
            "Renew Timer (T1)",
            "Rebind Timer (T2)",
            "Leases Active: ",
            "Address Pools",
            "10.99.0.10 - 10.99.0.50",
            "Router / Gateway",
            "9.9.9.9",
            "Options: 1 here · 1 inherited",
            "Notes",
        ):
            assert expected in text, expected

    def test_an_account_limited_to_one_subnet_gets_that_row_and_never_reads_the_others_name(self, client, db, two_nets):
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="c2_scoped")
        html = client.get("/subnets").get_data(as_text=True)
        assert [r.attrs["data-subnet-id"] for r in _rows(html)] == ["1"]
        assert NET_B["name"] not in html and "10.77.0." not in html

    def test_an_administrator_edits_and_moves_from_inside_the_open_row(
        self, logged_in_client, two_nets, ssh_ready, monkeypatch
    ):
        cfg = {**CFG, "shared-networks": [{"name": "c2-shared", "subnet4": []}]}
        from jen.services import kea as kea_svc

        monkeypatch.setattr(
            kea_svc,
            "kea_command",
            lambda command, *a, **kw: (
                {"result": 0, "arguments": {"Dhcp4": cfg}} if command == "config-get" else {"result": 0}
            ),
        )
        root = _tree(logged_in_client.get("/subnets").get_data(as_text=True))
        row = root.find("subnet-row")[0]
        (detail,) = row.find("subnet-detail")
        (head,) = row.find("subnet-row-head")
        assert [a for a in detail.walk() if a.tag == "a" and a.attrs.get("href") == "/subnets/edit/1"]
        assert [f for f in detail.walk() if f.tag == "form" and f.attrs.get("action") == "/subnets/move/1"]
        assert not [n for n in head.walk() if n.tag in ("a", "form", "select")], (
            "the row's head carries the toggle and the badge, no action"
        )
        assert _forms_without_a_token(root) == []

    def test_a_viewer_has_no_write_control(self, client, db, two_nets, ssh_ready):
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="c2_viewer")
        root = _tree(client.get("/subnets").get_data(as_text=True))
        rows = root.find("subnet-row")
        assert len(rows) == 2, "a viewer sees the rows"
        main = next(n for n in root.walk() if n.tag == "main" or n.attrs.get("id") == "main-content")
        for cls in (
            "tone-btn",
            "tone-menu",
            "note-display-btn",
            "save-note-btn",
            "subnet-options",
            "subnet-detail-actions",
        ):
            assert not main.find(cls), cls
        assert not [n for n in main.walk() if n.tag in ("form", "textarea", "select")], "a viewer's page posts nothing"
        hrefs = [a.attrs.get("href", "") for a in main.walk() if a.tag == "a"]
        assert not [
            h for h in hrefs if h.startswith(("/subnets/edit", "/subnets/add", "/subnets/options", "/subnets/classes"))
        ], hrefs
        # and the row still opens: the toggle is the one button a viewer's row has
        for row in rows:
            assert [b.classes for b in row.walk() if b.tag == "button"] == [["subnet-toggle"]]

    def test_expand_all_is_at_the_top_of_a_list_and_absent_with_no_subnet(
        self, logged_in_client, two_nets, monkeypatch
    ):
        html = logged_in_client.get("/subnets").get_data(as_text=True)
        assert html.index('id="subnets-expand-all"') < html.index('class="subnet-row"')
        assert re.search(
            r'<button type="button" class="btn btn-sm btn-secondary" id="subnets-expand-all">Expand All</button>', html
        )
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        assert 'id="subnets-expand-all"' not in logged_in_client.get("/subnets").get_data(as_text=True)

    def test_the_open_rows_are_remembered_in_this_browser(self):
        src = (TEMPLATES / "subnets.html").read_text(encoding="utf-8")
        assert "var KEY = 'jen-subnets-open';" in src
        assert "try { localStorage.setItem(KEY, value); } catch (e)" in src
        assert "try { stored = localStorage.getItem(KEY); } catch (e)" in src
        assert "all ? 'all' : JSON.stringify(" in src and "if (stored === 'all')" in src
        assert "try { list = JSON.parse(stored); } catch (e) { list = []; }" in src, (
            "a stored value that is not a list opens nothing"
        )

    def test_the_name_is_the_largest_text_of_a_row(self):
        src = (TEMPLATES / "subnets.html").read_text(encoding="utf-8")
        sizes = {
            m.group(1): int(m.group(2)) for m in re.finditer(r"(?m)^\.(subnet-[\w-]+) \{[^}]*font-size: (\d+)px", src)
        }
        assert sizes["subnet-name"] == 16 and sizes["subnet-stat"] < sizes["subnet-name"]
        row = src[src.index('<div class="subnet-row"') : src.index("{% else %}\n{% from '_empty.html'")]
        assert "u-9aa3cd" not in row, "the 20 px figure class is not used inside a row"


# ── V38: the in-page tabs and the jump line ──────────────────────────────────────────────────────────────────────────────────────────


def _tabs(html):
    """[(label, href, is current)] of the page's in-page tab row, or [] when it draws none."""
    navs = _tree(html).find("page-tabs")
    assert len(navs) <= 1
    if not navs:
        return []
    assert navs[0].tag == "nav" and navs[0].attrs.get("aria-label")
    out = []
    for a in navs[0].children:
        assert a.tag == "a" and "page-tab" in a.classes
        current = a.attrs.get("aria-current") == "page"
        assert current == ("active" in a.classes), (
            "the current tab is marked for the eye and for a screen reader together"
        )
        out.append((a.all_text(), a.attrs["href"], current))
    return out


def _no_registry(monkeypatch):
    monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], ""))


class TestThePagePillsAreTabs:
    def test_the_macro_draws_tabs_marks_the_current_one_and_draws_no_row_of_one(self):
        from jinja2 import Environment, FileSystemLoader

        env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)
        call = "{% from '_settings_subtabs.html' import subtabs %}{{ subtabs(items, 'b') }}"
        items = [{"id": "a", "label": "Alpha", "url": "/a"}, {"id": "b", "label": "Beta", "url": "/b?x=1&y=2"}]
        assert _tabs(env.from_string(call).render(items=items)) == [
            ("Alpha", "/a", False),
            ("Beta", "/b?x=1&y=2", True),
        ]
        assert env.from_string(call).render(items=items[:1]).strip() == ""
        assert env.from_string(call).render(items=[]).strip() == ""

    @pytest.mark.parametrize(
        ("path", "labels", "current"),
        [
            ("/settings/security", ["Policies", "Users", "API Keys", "API Docs"], "Policies"),
            ("/settings/users", ["Policies", "Users", "API Keys", "API Docs"], "Users"),
            ("/settings/api-keys", ["Policies", "Users", "API Keys", "API Docs"], "API Keys"),
            ("/settings/api-docs", ["Policies", "Users", "API Keys", "API Docs"], "API Docs"),
            (
                "/settings/databases",
                ["Connections", "Export", "Import", "Backups", "Schedule", "Migrate", "Recovery"],
                "Connections",
            ),
            (
                "/settings/databases/migrate",
                ["Connections", "Export", "Import", "Backups", "Schedule", "Migrate", "Recovery"],
                "Migrate",
            ),
            (
                "/database/kea-identifiers",
                ["Connections", "Export", "Import", "Backups", "Schedule", "Migrate", "Recovery"],
                "Import",
            ),
            ("/settings/logs", ["Audit Log", "Alert Log"], "Audit Log"),
            ("/settings/system", ["Updates & System", "Plugin Manager"], "Updates & System"),
            ("/settings/plugins", ["Updates & System", "Plugin Manager"], "Plugin Manager"),
        ],
    )
    def test_every_page_of_a_group_draws_its_groups_tabs(
        self, logged_in_client, mock_kea, monkeypatch, path, labels, current
    ):
        _no_registry(monkeypatch)
        r = logged_in_client.get(path)
        assert r.status_code == 200, path
        tabs = _tabs(r.get_data(as_text=True))
        assert [t[0] for t in tabs] == labels
        assert [t[0] for t in tabs if t[2]] == [current]

    def test_a_viewer_on_api_docs_is_shown_no_tab_that_would_bounce(self, client, db):
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="c2_docs_viewer")
        r = client.get("/settings/api-docs")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert _tabs(html) == [], "API Docs is the one page of its group a viewer may open: a row of one tab is no row"
        assert not _tree(html).find("page-tab")

    def test_an_administrator_on_api_docs_gets_the_three_pages_an_administrator_may_open(self, client, db):
        restricted_client(client, db, allowed_subnets=None, role="admin", username="c2_docs_admin")
        tabs = _tabs(client.get("/settings/api-docs").get_data(as_text=True))
        assert tabs == [
            ("Policies", "/settings/security", False),
            ("API Keys", "/settings/api-keys", False),
            ("API Docs", "/settings/api-docs", True),
        ]

    @pytest.mark.parametrize("role", ["viewer", "admin", "superadmin"])
    def test_every_tab_listed_for_a_role_opens_for_that_role(self, client, db, mock_kea, monkeypatch, role):
        """The rule the list is filtered by is the rule each page's route enforces: nobody is shown a tab that sends them away."""
        _no_registry(monkeypatch)
        restricted_client(client, db, allowed_subnets=None, role=role, username=f"c2_tabs_{role}")
        listed = navmod.nav_context("settings.settings_security", role)["subtabs"]
        seen = 0
        for group, tabs in listed.items():
            for tab in tabs:
                r = client.get(tab["url"])
                assert r.status_code == 200, f"{role}: the {tab['label']} tab of {group} answered {r.status_code}"
                seen += 1
        assert seen == {"viewer": 1, "admin": 7, "superadmin": 15}[role]

    def test_ddns_and_investigate_draw_the_same_tabs(self, logged_in_client, mock_kea):
        tabs = _tabs(logged_in_client.get("/ddns").get_data(as_text=True))
        assert [t[0] for t in tabs][:1] == ["Status"] and [t[0] for t in tabs if t[2]] == ["Status"]
        client_src = (TEMPLATES / "client.html").read_text(encoding="utf-8")
        assert "{{ subtabs(view_tabs.items, tab, 'Views of this client') }}" in client_src
        assert "badge-reserved{% else %}badge-dynamic" not in client_src, "the views were status badges"
        assert "{% from '_settings_subtabs.html' import subtabs %}" in (TEMPLATES / "_ddns_tabs.html").read_text(
            encoding="utf-8"
        )

    def test_the_tab_style_is_one_block_of_base_html_and_a_phones_tabs_are_40_px(self):
        block = BASE[BASE.index("Q248 (V38): the in-page tabs.") :]
        block = block[: block.index("/* Tables */")]
        assert ".page-tabs {" in block and ".page-tab {" in block and ".page-tab.active {" in block
        phone = block[block.index("@media screen and (max-width: 768px) {") :]
        assert re.search(r"\.page-tab \{[^}]*min-height: 40px;", phone)
        assert BASE.count(".page-tab {") == 2, "the rule and its phone rule, nowhere else"


SETTINGS_PAGES = ["/settings/kea", "/settings/security", "/settings/alerts", "/settings/appearance", "/settings/system"]


def _cards(root):
    """[(id, title)] of the page's cards: the children of its column block, in the order they come."""
    (cols,) = root.find("settings-cols")
    out = []
    for card in cols.children:
        if "card" not in card.classes:
            continue
        title = card.find("card-title")[0]
        out.append((card.attrs.get("id"), title.own_text()))
    return out


def _jump(root):
    (nav,) = root.find("page-jump")
    assert nav.tag == "nav" and nav.attrs["aria-label"] == "On this page"
    assert nav.children[0].own_text() == "On this page:"
    return [(a.attrs["href"].lstrip("#"), a.all_text()) for a in nav.children[1:]]


class TestTheJumpLine:
    @pytest.mark.parametrize("path", SETTINGS_PAGES)
    @pytest.mark.parametrize("role", ["superadmin", "admin"])
    def test_one_link_per_card_in_card_order_by_the_cards_own_title(self, client, db, mock_kea, path, role):
        restricted_client(client, db, allowed_subnets=None, role=role, username=f"c2_jump_{role}")
        r = client.get(path)
        assert r.status_code == 200
        root = _tree(r.get_data(as_text=True))
        cards = _cards(root)
        assert len(cards) >= 3 and all(cid for cid, _ in cards), cards
        assert _jump(root) == cards
        ids = [n.attrs["id"] for n in root.walk() if "id" in n.attrs]
        for cid, _ in cards:
            assert ids.count(cid) == 1, f"#{cid} is the id of {ids.count(cid)} elements"

    def test_every_settings_page_with_a_jump_line_is_in_this_test(self):
        users = sorted(
            p.name
            for p in TEMPLATES.glob("*.html")
            if not p.name.startswith("_") and "{% include '_card_toc.html' %}" in p.read_text(encoding="utf-8")
        )
        assert users == sorted(f"settings_{p.rsplit('/', 1)[1]}.html" for p in SETTINGS_PAGES)

    def test_it_is_a_plain_line_that_a_phone_and_paper_do_not_show(self):
        src = (TEMPLATES / "_card_toc.html").read_text(encoding="utf-8")
        assert '<span class="page-jump-label">On this page:</span>' in src
        assert 'class="card-toc"' not in src, "the row of pills is gone"
        assert re.search(r"@media screen and \(max-width: 768px\) \{\s*\.page-jump \{ display: none; \}", src)
        assert "@media print { .page-jump { display: none; } }" in src
        assert "document.querySelectorAll('.page-jump a[href^=\"#\"]')" in src, "a link still opens the card it names"


# ── V42: the plugins, once in each place ─────────────────────────────────────────────────────────────────────────────────────────────

TAIL = "and this last clause is past the eightieth character and past the one hundred and twentieth too."
DESCRIPTION = (
    "A plugin made for this test, with a description as long as a real one: it says what the plugin does, where, "
    + TAIL
)


def _plugin(**over):
    p = {
        "id": "c2demo",
        "name": "C2 Demo Plugin",
        "version": "1.2.3",
        "description": DESCRIPTION,
        "path": "/x",
        "bundled": False,
        "root_owned": False,
        "enabled": True,
        "version_ok": True,
        "api_ok": True,
    }
    p.update(over)
    return p


def _entry(**over):
    e = {
        "id": "c2demo",
        "name": "C2 Demo Plugin",
        "version": "1.2.3",
        "description": DESCRIPTION,
        "author": "Tester",
        "tags": ["network"],
        "requires_jen": "0.0.0",
    }
    e.update(over)
    return e


def _manager(logged_in_client, installed, registry, systemd=False, missing=()):
    with (
        patch("jen.services.plugins.discover_plugins", return_value=installed),
        patch("jen.services.plugins.fetch_registry", return_value=(registry, "")),
        patch("jen.services.plugins.is_systemd_host", return_value=systemd),
        patch("jen.services.plugins.missing_os_packages", return_value=list(missing)),
        patch("jen.services.plugins.consume_plugin_results", return_value=[]),
    ):
        r = logged_in_client.get("/settings/plugins")
    assert r.status_code == 200
    return r.get_data(as_text=True)


class TestThePluginsAreListedOnce:
    def test_settings_system_shows_name_version_and_status_and_a_link_to_the_manager(self, logged_in_client):
        with patch("jen.services.plugins.discover_plugins", return_value=[_plugin()]):
            html = logged_in_client.get("/settings/system").get_data(as_text=True)
        root = _tree(html)
        card = next(n for n in root.walk() if n.attrs.get("id") == "sys-plugins")
        (row,) = [n for n in card.walk() if n.tag == "tr" and n.parent.tag == "tbody"]
        assert [" ".join(td.all_text().split()) for td in row.children] == ["C2 Demo Plugin", "v1.2.3", "● Enabled"]
        assert DESCRIPTION[:40] not in html and TAIL not in html
        links = [a for a in card.walk() if a.tag == "a" and a.attrs.get("href") == "/settings/plugins"]
        assert [a.all_text() for a in links] == ["Manage plugins"]

    def test_the_manager_prints_the_whole_description(self, logged_in_client):
        html = _manager(logged_in_client, [_plugin()], [_entry()])
        (desc,) = _tree(html).find("plugin-desc")
        assert desc.all_text() == DESCRIPTION

    def test_neither_page_cuts_a_description(self):
        for name in ("settings_system.html", "plugins.html"):
            assert "[:80]" not in (TEMPLATES / name).read_text(encoding="utf-8"), name

    def test_available_offers_only_what_is_not_installed(self, logged_in_client):
        other = _entry(id="c2other", name="C2 Other Plugin", description="Not installed on this box.")
        html = _manager(logged_in_client, [_plugin()], [_entry(), other])
        cards = _tree(html).find("plugin-card")
        assert [c.find("plugin-card-head")[0].children[0].all_text() for c in cards] == ["C2 Other Plugin"]
        assert 'action="/settings/plugins/install/c2other"' in html
        assert 'action="/settings/plugins/install/c2demo"' not in html
        assert html.count(DESCRIPTION) == 1, "an installed plugin is described once, in the Installed table"
        assert "Every available plugin is installed." not in html

    def test_with_everything_installed_it_is_one_line(self, logged_in_client):
        html = _manager(logged_in_client, [_plugin()], [_entry()])
        assert "Every available plugin is installed." in html and not _tree(html).find("plugin-card")
        assert "No plugins in the registry." not in html

    def test_an_empty_registry_still_says_so(self, logged_in_client):
        html = _manager(logged_in_client, [_plugin()], [])
        assert "No plugins in the registry." in html and "Every available plugin is installed." not in html

    def test_an_update_is_still_offered_in_the_installed_table(self, logged_in_client):
        html = _manager(logged_in_client, [_plugin()], [_entry(version="1.3.0")])
        assert 'action="/settings/plugins/update/c2demo"' in html
        assert "Every available plugin is installed." in html

    def test_a_missing_host_package_is_a_sentence_under_the_status_with_its_command_in_a_box(self, logged_in_client):
        root = _tree(_manager(logged_in_client, [_plugin()], [], systemd=False, missing=["nmap"]))
        (row,) = [n for n in root.find("plugin-table")[0].walk() if n.tag == "tr" and n.parent.tag == "tbody"]
        status = next(td for td in row.children if td.attrs.get("data-m") == "badge")
        actions = next(td for td in row.children if td.attrs.get("data-m") == "trailing")
        assert status.find("plugin-needs")[0].all_text() == "Needs nmap on the Jen host:"
        (box,) = status.find("plugin-cmd")
        code = next(n for n in box.walk() if n.tag == "code")
        button = next(n for n in box.walk() if n.tag == "button")
        assert code.all_text() == "sudo apt install nmap" and code.attrs["id"] == "plugin-cmd-c2demo"
        assert button.attrs["type"] == "button" and button.attrs["data-copy-target"] == code.attrs["id"]
        assert button.all_text() == "Copy"
        assert "apt" not in actions.all_text() and not [n for n in actions.walk() if n.tag == "code"], (
            "the Actions column holds actions"
        )

    def test_on_a_systemd_host_the_install_button_stays_in_actions_and_there_is_no_command_to_copy(
        self, logged_in_client
    ):
        root = _tree(_manager(logged_in_client, [_plugin()], [], systemd=True, missing=["nmap"]))
        (row,) = [n for n in root.find("plugin-table")[0].walk() if n.tag == "tr" and n.parent.tag == "tbody"]
        status = next(td for td in row.children if td.attrs.get("data-m") == "badge")
        actions = next(td for td in row.children if td.attrs.get("data-m") == "trailing")
        assert status.find("plugin-needs")[0].all_text() == "Needs nmap on the Jen host."
        assert not status.find("plugin-cmd")
        assert [
            f for f in actions.walk() if f.tag == "form" and f.attrs.get("action") == "/settings/plugins/deps/c2demo"
        ]

    def test_every_form_keeps_its_token_and_the_poller_still_finds_what_it_reads(self, logged_in_client):
        other = _entry(id="c2other", name="C2 Other Plugin")
        html = _manager(logged_in_client, [_plugin()], [_entry(version="1.3.0"), other], systemd=True, missing=["nmap"])
        root = _tree(html)
        assert _forms_without_a_token(root) == []
        actions = sorted(
            f.attrs["action"]
            for f in root.walk()
            if f.tag == "form" and "/settings/plugins/" in f.attrs.get("action", "")
        )
        assert actions == [
            "/settings/plugins/deps/c2demo",
            "/settings/plugins/disable/c2demo",
            "/settings/plugins/install/c2demo",  # Reinstall: a copy that is not root-owned, on a systemd host
            "/settings/plugins/install/c2other",
            "/settings/plugins/uninstall/c2demo",
            "/settings/plugins/update/c2demo",
        ]
        assert [n.attrs.get("data-plugin-id") for n in root.find("plugin-install-result")] == ["c2demo"]
        assert [n.tag for n in root.walk() if n.attrs.get("id") == "plugin-request-status"] == ["div"]
        src = (TEMPLATES / "plugins.html").read_text(encoding="utf-8")
        assert "document.querySelector('.plugin-install-result[data-plugin-id=\"' + pluginId + '\"]')" in src
        assert "document.getElementById('plugin-request-status')" in src

    def test_the_registrys_cards_are_never_wider_than_the_screen(self):
        src = (TEMPLATES / "plugins.html").read_text(encoding="utf-8")
        assert (
            ".plugin-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(360px, 100%), 1fr));"
            in src
        )
        assert "minmax(360px,1fr)" not in src


# ── V53: Reports ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def history(db):
    """Forty snapshots of the suite's one subnet over the last two days: a pool of 121 with about twenty addresses used."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
        for n in range(40):
            cur.execute(
                "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, dynamic_leases, reserved_leases, pool_used, pool_size) "
                "VALUES (1, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s, %s, 4, %s, 121)",
                (n * 60, 20 + n % 3, 16 + n % 3, 18 + n % 3),
            )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
    db.commit()


class TestReports:
    def test_the_card_carries_the_pool_figure_for_the_script_to_show(self, logged_in_client, history):
        html = logged_in_client.get("/reports?days=7").get_data(as_text=True)
        assert re.search(r'<span id="chart-pool-1" hidden>Pool: 121 addresses · </span>40 data points</span>', html)

    def test_scale_to_pool_is_a_labeled_checkbox_beside_the_range_and_only_where_there_is_a_chart(
        self, logged_in_client, db
    ):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        html = logged_in_client.get("/reports").get_data(as_text=True)
        assert "No history data yet" in html and 'id="scale-pool"' not in html
        assert '<label for="days-select">Time range:</label>' in html

    def test_the_checkbox_is_drawn_with_history(self, logged_in_client, history):
        root = _tree(logged_in_client.get("/reports?days=7").get_data(as_text=True))
        (label,) = root.find("reports-scale")
        box = next(n for n in label.walk() if n.tag == "input")
        assert label.tag == "label" and box.attrs["type"] == "checkbox" and box.attrs["id"] == "scale-pool"
        assert label.all_text() == "Scale to Pool"
        (controls,) = root.find("reports-controls")
        assert [n.attrs.get("id") for n in controls.walk() if n.tag in ("select", "input")] == [
            "days-select",
            "scale-pool",
        ]

    def test_the_axis_fits_the_lines_unless_scale_to_pool_is_on(self):
        src = (TEMPLATES / "reports.html").read_text(encoding="utf-8")
        assert "const axis = niceAxis(largestOf([total, reserved, active, projection]));" in src, (
            "the pool is not one of the values"
        )
        assert "...(toPool ? {} : { max: axis.max })," in src and "...(toPool ? {} : { stepSize: axis.step })" in src
        assert "const poolInRange = largestOf([poolSize]) > 0 && (toPool || largestOf([poolSize]) <= axis.max);" in src
        assert "if (poolNote) poolNote.hidden = poolInRange;" in src
        pool = src[src.index("if (poolInRange) {") :]
        pool = pool[: pool.index("if (proj.length) {")]
        assert "label: 'Pool Size'" in pool and "borderDash: [4, 4]" in pool and "borderColor: textColor" in pool

    def test_the_choice_is_this_browsers(self):
        src = (TEMPLATES / "reports.html").read_text(encoding="utf-8")
        assert "const SCALE_KEY = 'jen-reports-scale';" in src
        assert "try { return localStorage.getItem(SCALE_KEY) === '1'; } catch (e) { return false; }" in src
        assert "try { localStorage.setItem(SCALE_KEY, scaleBox.checked ? '1' : '0'); } catch (e)" in src

    def test_a_legend_entry_is_drawn_as_its_line_and_a_phone_gets_fewer_shorter_labels(self):
        src = (TEMPLATES / "reports.html").read_text(encoding="utf-8")
        legend = src[src.index("function legendOptions(textColor) {") : src.index("// The x-axis labels.")]
        assert "usePointStyle: true," in legend and "pointStyle: 'line'," in legend and "boxWidth: 12" not in src
        assert (
            "strokeStyle: d.borderColor, fillStyle: d.borderColor, lineWidth: d.borderWidth, lineDash: d.borderDash || []"
            in legend
        )
        assert src.count("legend: legendOptions(textColor),") == 2, "the IPv4 charts and the IPv6 charts"
        assert src.count("ticks: xTicks(textColor)") == 2
        assert "maxTicksLimit: PHONE ? 5 : 12," in src and "return PHONE ? shortLabel(stamp) : stamp;" in src

    def test_no_color_is_written_into_the_script(self):
        src = (TEMPLATES / "reports.html").read_text(encoding="utf-8")
        script = src[src.index("{% block scripts %}") :]
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", script)
        for token in ("--border", "--text-muted", "--text", "--surface2", "--primary", "--success", "--warning"):
            assert f"jenColor('var({token})')" in script, token
