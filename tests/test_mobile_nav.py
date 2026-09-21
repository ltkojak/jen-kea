"""
tests/test_mobile_nav.py
────────────────────────
v5.51.0 (Q58) — the phone's bottom tab bar and More sheet.

The pure classes (nav data, a stub-Jinja render of base.html, token/utility
presence) run with `py -m pytest --noconftest tests/test_mobile_nav.py`; the
last class renders real pages through the app and needs the CI database.
"""

import pathlib
import re

import pytest
from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader

from jen.routes.settings import nav as navmod
from jen.services.icons import icon, nav_icon

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_ITEMS = [
    {"section": "network", "label": "IPAM", "icon": "network", "endpoint": "ipam.index"},
    {"section": "tools", "label": "Extras", "icon": "", "endpoint": "extras.index"},
]


class TestTabbarData:
    def test_admin_gets_the_five_specified_items(self):
        ctx = navmod.nav_context("dashboard.dashboard", "admin", PLUGIN_ITEMS)
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "Leases", "Reservations", "Settings"]
        assert ctx["tabbar"][0]["active"] and not any(t["active"] for t in ctx["tabbar"][1:])
        assert ctx["tabbar_more_active"] is False  # More is the fifth control, added by the template

    def test_viewer_has_no_settings_so_the_slot_is_devices(self):
        ctx = navmod.nav_context("leases.leases", "viewer")
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "Leases", "Reservations", "Devices"]
        assert [t["id"] for t in ctx["tabbar"] if t["active"]] == ["leases"]

    @pytest.mark.parametrize(
        "endpoint,role,active",
        [
            ("reservations.reservations", "admin", "reservations"),
            ("settings.settings_kea", "admin", "settings"),
            ("settings.settings", "superadmin", "settings"),
            ("devices.devices", "viewer", "devices"),
        ],
    )
    def test_active_follows_the_endpoint(self, endpoint, role, active):
        ctx = navmod.nav_context(endpoint, role)
        assert [t["id"] for t in ctx["tabbar"] if t["active"]] == [active]

    def test_more_lights_when_the_page_is_none_of_the_four(self):
        assert navmod.nav_context("servers.servers", "admin")["tabbar_more_active"] is True
        assert navmod.nav_context("reports.reports", "viewer")["tabbar_more_active"] is True

    def test_every_tab_url_is_a_real_top_level_destination(self):
        for role in ("viewer", "admin", "superadmin"):
            for t in navmod.nav_context("dashboard.dashboard", role)["tabbar"]:
                assert t["url"].startswith("/") and t["icon"]


class TestSheetContents:
    def _labels(self, ctx):
        return {g["id"]: [i["label"] for i in g["items"]] for g in ctx["sheet"]}

    def test_admin_sheet_lists_every_destination_grouped_like_the_desktop_nav(self):
        got = self._labels(navmod.nav_context("dashboard.dashboard", "admin", PLUGIN_ITEMS))
        assert got["management"] == ["Leases", "Reservations", "Devices", "Reports"]
        assert {"Subnets", "Servers", "DDNS", "Health", "Explain", "Doctor", "Timeline", "IPAM"} <= set(got["network"])
        assert "Kea" in got["settings"] and "Logs" in got["settings"]
        assert got["plugins"] == ["Extras"]
        assert got["about"] == ["About"]

    def test_viewer_sheet_has_no_settings_group(self):
        assert "settings" not in self._labels(navmod.nav_context("dashboard.dashboard", "viewer"))

    def test_restricted_account_does_not_see_the_all_subnets_pages(self):
        full = self._labels(navmod.nav_context("dashboard.dashboard", "admin", all_subnets=True))
        restricted = self._labels(navmod.nav_context("dashboard.dashboard", "admin", all_subnets=False))
        assert "Doctor" in full["network"] and "Doctor" not in restricted["network"]

    def test_superadmin_only_settings_groups_stay_hidden_from_admins(self):
        admin = self._labels(navmod.nav_context("dashboard.dashboard", "admin"))["settings"]
        sup = self._labels(navmod.nav_context("dashboard.dashboard", "superadmin"))["settings"]
        assert set(admin) <= set(sup)

    def test_active_item_is_marked(self):
        ctx = navmod.nav_context("servers.servers", "admin")
        net = next(g for g in ctx["sheet"] if g["id"] == "network")
        assert [i["label"] for i in net["items"] if i["active"]] == ["Servers"]


def _render(role="admin", endpoint="servers.servers", pill=None):
    env = Environment(loader=ChoiceLoader([DictLoader({}), FileSystemLoader(str(ROOT / "templates"))]))
    env.globals.update(
        icon=icon,
        nav_icon=nav_icon,
        csrf_token=lambda: "tok",
        url_for=lambda ep, **kw: "/plugin/" + ep,
        get_flashed_messages=lambda **kw: [],
    )

    class U:
        is_authenticated = True
        username = "alice"
        role = "admin"

    class R:
        args = {}
        endpoint = "servers.servers"

    U.role = role
    return env.get_template("base.html").render(
        current_user=U,
        request=R,
        csp_nonce="n0nce",
        jen_version="5.51.0",
        nav=navmod.nav_context(endpoint, role, PLUGIN_ITEMS),
        getting_started_pill=pill,
        plugin_nav_items=PLUGIN_ITEMS,
    )


class TestBaseRender:
    def test_tabbar_and_sheet_are_present_with_the_five_controls(self):
        html = _render()
        bar = re.search(r'<nav class="tabbar".*?</nav>', html, re.S).group(0)
        assert bar.count("<a ") == 4 and bar.count("<button") == 1
        for label in ("Dashboard", "Leases", "Reservations", "Settings", "More"):
            assert f"<span>{label}</span>" in bar
        assert 'data-sheet-open="more-sheet"' in bar and 'id="more-sheet"' in html
        assert 'id="sheet-backdrop"' in html
        assert 'class="has-tabbar"' in html

    def test_active_tab_has_aria_current(self):
        html = _render(endpoint="leases.leases")
        assert re.search(r'<a href="/leases" class="active" aria-current="page">', html)
        assert html.count('aria-current="page"') == 1

    def test_sheet_carries_search_theme_logout_and_the_pill(self):
        html = _render(pill={"done": 2, "total": 7})
        sheet = re.search(r'<div class="sheet" id="more-sheet".*?\n</div>\n', html, re.S).group(0)
        assert 'action="/search"' in sheet and "sheet-theme" in sheet
        assert 'action="/logout"' in sheet and 'name="csrf_token"' in sheet
        assert "Getting started (2/7)" in sheet
        assert "/plugin/extras.index" in sheet  # a plugin destination resolves through url_for

    def test_the_hamburger_and_drawer_are_gone(self):
        html = _render()
        assert "nav-hamburger" not in html and "nav-mobile-drawer" not in html
        assert "nav-mobile-dashboard" not in html

    def test_viewer_render_has_no_settings_anywhere_in_the_bar(self):
        html = _render(role="viewer")
        bar = re.search(r'<nav class="tabbar".*?</nav>', html, re.S).group(0)
        assert "<span>Settings</span>" not in bar and "<span>Devices</span>" in bar

    def test_no_inline_handlers_were_added(self):
        html = re.sub(r"<script.*?</script>", "", _render(), flags=re.S)  # comments in scripts may name them
        assert not re.search(r"<[^>]*\son(click|change|submit|load)=", html)

    def test_every_script_tag_carries_the_nonce(self):
        html = _render()
        for m in re.finditer(r"<script\b[^>]*>", html):
            assert "nonce=" in m.group(0) or "src=" in m.group(0), m.group(0)


class TestTokensAndUtilities:
    def _css(self):
        return (ROOT / "templates" / "base.html").read_text(encoding="utf-8")

    def test_scale_tokens_exist(self):
        css = self._css()
        for tok in (
            "--sp-1: 4px",
            "--sp-6: 32px",
            "--fs-xs: 11px",
            "--fs-2xl: 26px",
            "--radius-sm",
            "--surface3",
            "--tap: 44px",
        ):
            assert tok in css, tok

    def test_surface3_is_defined_for_both_themes(self):
        css = self._css()
        assert css.count("--surface3:") == 2

    def test_utilities_named_by_the_spec_exist(self):
        css = self._css()
        for cls in (".muted", ".small", ".flex", ".wrap", ".gap-2", ".mt-2", ".mb-2", ".grow", ".right", ".stack"):
            assert re.search(re.escape(cls) + r"\s*\{", css), cls

    def test_ios_safe_areas_and_dvh(self):
        css = self._css()
        assert "env(safe-area-inset-bottom)" in css and "85dvh" in css

    def test_the_sheet_never_shows_on_desktop(self):
        assert "@media (min-width: 769px)" in self._css()


class TestRealPages:
    def test_dashboard_page_has_the_tabbar_for_an_admin(self, logged_in_client):
        r = logged_in_client.get("/leases")
        assert r.status_code == 200
        assert b'<nav class="tabbar"' in r.data and b'id="more-sheet"' in r.data
        assert b"nav-hamburger" not in r.data

    def test_login_page_has_no_tabbar(self, client):
        r = client.get("/login")
        assert b'class="tabbar"' not in r.data
