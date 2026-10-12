"""
tests/test_templates_roles.py
─────────────────────────────
v5.69.0-beta.4 (Q173, item 2): a viewer never sees an action the route refuses. Each page below is rendered as a viewer (and, where the route has one, as a
scoped admin) and the control is asserted absent; the same page as a superadmin proves the marker is real, not a string that never appeared.
"""

import pathlib
import re

import pytest

from jen import extensions
from tests.conftest import restricted_client

A = {"name": "Office", "cidr": "10.99.0.0/24"}
B = {"name": "Guest", "cidr": "10.99.1.0/24"}


@pytest.fixture
def two_subnets(monkeypatch):
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A), 2: dict(B)})


# (path, a marker only an admin should be offered). The Configure link carries its class, because the same href is also a string in the page's own script.
CONTROLS = [
    ("/devices", 'action="/devices/settings"'),  # the stale-days form
    ("/subnets", "Options:"),  # the subnet card's options link
    ("/servers", 'href="/settings/kea#kea-servers"'),  # servers.html, single-server view
    ("/", 'id="w-getting_started"'),  # the widget catalog entry
    ("/", 'href="/settings/alerts" class="btn btn-sm btn-secondary"'),  # the Alert Summary's Configure link
]


class TestAViewerSeesNoAdminControl:
    @pytest.mark.parametrize("n,path,marker", [(i, p, m) for i, (p, m) in enumerate(CONTROLS)])
    def test_the_control_is_absent_for_a_viewer(self, client, db, mock_kea, two_subnets, n, path, marker):
        v, _ = restricted_client(client, db, None, role="viewer", username=f"q173_viewer_{n}")
        body = v.get(path, follow_redirects=True).get_data(as_text=True)
        assert marker not in body

    @pytest.mark.parametrize("path,marker", CONTROLS)
    def test_the_control_is_present_for_a_superadmin(self, logged_in_client, mock_kea, two_subnets, path, marker):
        body = logged_in_client.get(path, follow_redirects=True).get_data(as_text=True)
        assert marker in body

    def test_the_configure_ha_link_sits_inside_the_role_condition(self):
        """/servers shows it only for a multi-server install with no HA mode; rendering that needs two live Kea servers, so the template's own condition is pinned."""
        text = pathlib.Path("templates/servers.html").read_text(encoding="utf-8")
        assert re.search(
            r"\{% if current_user\.role in \('admin', 'superadmin'\) %\}<a href=\"/settings/kea#kea-servers\"[^>]*>Configure HA",
            text,
        )


class TestTheDdnsSubTabsMatchTheCaller:
    def test_a_scoped_admin_is_not_offered_verify_on_the_reconcile_page(
        self, client, db, mock_kea, two_subnets, monkeypatch
    ):
        from jen.routes import ddns as ddns_routes

        monkeypatch.setattr(ddns_routes, "_reconcile_rows", lambda: ([], []))
        c, _ = restricted_client(client, db, [1], role="admin", username="q173_ddns_scoped")
        body = c.get("/ddns/reconcile", follow_redirects=True).get_data(as_text=True)
        assert "/ddns?tab=verify" not in body

    def test_an_admin_with_every_subnet_is_offered_it(self, client, db, mock_kea, two_subnets, monkeypatch):
        from jen.routes import ddns as ddns_routes

        monkeypatch.setattr(ddns_routes, "_reconcile_rows", lambda: ([], []))
        c, _ = restricted_client(client, db, None, role="admin", username="q173_ddns_all")
        body = c.get("/ddns/reconcile", follow_redirects=True).get_data(as_text=True)
        assert "/ddns?tab=verify" in body


class TestTheDashboardCatalogFollowsTheRole:
    def test_a_viewer_is_not_offered_the_getting_started_widget(self):
        from jen.services import dashboard_prefs as dp

        assert "getting_started" not in dp.catalog_for(False)
        assert "getting_started" in dp.catalog_for(True)

    def test_a_viewers_stored_layout_loses_it_and_an_admins_keeps_it(self):
        from jen.services import dashboard_prefs as dp

        raw = {"v": 2, "panels": [{"id": "totals", "w": "full"}, {"id": "getting_started", "w": "third"}]}
        assert [p["id"] for p in dp.validate(raw, [], admin=False)["panels"]] == ["totals"]
        assert [p["id"] for p in dp.validate(raw, [], admin=True)["panels"]] == ["totals", "getting_started"]
        # no argument is the safe answer: a caller that forgets to say who is asking gets the viewer's catalog
        assert [p["id"] for p in dp.validate(raw, [])["panels"]] == ["totals"]

    def test_the_catalog_data_route_gives_a_viewer_nothing_for_it(self, client, db, mock_kea):
        v, _ = restricted_client(client, db, None, role="viewer", username="q173_catalog_viewer")
        r = v.get("/api/dashboard/catalog-data?widgets=getting_started")
        assert r.status_code == 200 and "getting_started" not in r.get_json()


class TestSubnetsOffersOnlyWhatTheCallerMayDo:
    def test_a_scoped_admin_is_not_offered_add_subnet(self, client, db, mock_kea, two_subnets):
        c, _ = restricted_client(client, db, [1], role="admin", username="q173_scoped_subnets")
        body = c.get("/subnets", follow_redirects=True).get_data(as_text=True)
        assert 'href="/subnets/add"' not in body

    def test_an_admin_with_every_subnet_is_offered_it(self, client, db, mock_kea, two_subnets):
        c, _ = restricted_client(client, db, None, role="admin", username="q173_all_subnets")
        body = c.get("/subnets", follow_redirects=True).get_data(as_text=True)
        assert 'href="/subnets/add"' in body

    def test_a_viewer_is_not_told_to_set_up_ssh(self, client, db, mock_kea, two_subnets):
        # the test install has no SSH configured, so an admin would be shown the banner here
        v, _ = restricted_client(client, db, None, role="viewer", username="q173_viewer_ssh")
        body = v.get("/subnets", follow_redirects=True).get_data(as_text=True)
        assert "Subnet editing requires SSH" not in body

    def test_the_template_gates_the_banner_and_both_add_buttons(self):
        text = pathlib.Path("templates/subnets.html").read_text(encoding="utf-8")
        assert "{% if not ssh_ready and current_user.role in ('superadmin','admin') %}" in text
        assert text.count("current_user.all_subnets") >= 2


class TestTheReconcileChipsAreReadable:
    def test_the_selected_chip_sets_a_text_colour_with_its_background(self):
        text = pathlib.Path("templates/ddns_reconcile.html").read_text(encoding="utf-8")
        assert text.count("background:var(--primary);color:white;") == 2
        assert "badge-production" not in text

    def test_the_reverify_link_is_for_a_caller_who_can_use_it(self):
        text = pathlib.Path("templates/ddns_reconcile.html").read_text(encoding="utf-8")
        i = text.index("/ddns?tab=verify&hostname=")
        assert "{% if current_user.all_subnets %}" in text[:i] and text.rfind(
            "{% if current_user.all_subnets %}", 0, i
        ) > text.rfind("{% endif %}", 0, i)
