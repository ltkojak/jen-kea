"""
tests/test_dashboard_arrangement.py
────────────────────────────────────
v5.54.0 (Q61) — the dashboard prefs v2 routes and the arrangement markup.

Needs the CI database (uses `logged_in_client`/`restricted_client`).
"""

import json

from tests.conftest import restricted_client


class TestSavePrefsRoute:
    def test_v2_body_round_trips_through_save_and_get(self, logged_in_client, db, mock_kea):
        body = {
            "v": 2,
            "panels": [{"id": "totals", "w": "half"}, {"id": "server_status", "w": "half"}],
            "subnets": {"order": [], "pinned": [], "hidden": []},
            "compact": True,
        }
        r = logged_in_client.post("/api/dashboard/save-prefs", json=body)
        assert r.status_code == 200 and r.get_json()["ok"] is True
        got = logged_in_client.get("/api/dashboard/get-prefs").get_json()
        assert got["panels"] == body["panels"]
        assert got["compact"] is True
        assert got["widgets"] == ["totals", "server_status"]  # v1 shape kept for any cached client script

    def test_a_v1_style_body_still_saves(self, logged_in_client, db, mock_kea):
        r = logged_in_client.post("/api/dashboard/save-prefs", json={"widgets": ["recent_leases", "totals"]})
        assert r.status_code == 200
        got = logged_in_client.get("/api/dashboard/get-prefs").get_json()
        assert [p["id"] for p in got["panels"]] == ["recent_leases", "totals"]

    def test_an_unknown_widget_id_in_the_body_is_dropped_not_stored(self, logged_in_client, db, mock_kea):
        logged_in_client.post("/api/dashboard/save-prefs", json={"v": 2, "panels": [{"id": "not-real", "w": "full"}]})
        got = logged_in_client.get("/api/dashboard/get-prefs").get_json()
        assert "not-real" not in [p["id"] for p in got["panels"]]

    def test_empty_body_falls_back_to_default_panels(self, logged_in_client, db, mock_kea):
        logged_in_client.post("/api/dashboard/save-prefs", json={})
        got = logged_in_client.get("/api/dashboard/get-prefs").get_json()
        assert got["panels"]  # never empty

    def test_no_login_is_refused(self, client):
        r = client.post("/api/dashboard/save-prefs", json={"v": 2, "panels": []})
        assert r.status_code in (302, 401)


class TestSubnetScopedPrefs:
    def test_restricted_account_cannot_pin_or_hide_a_subnet_it_cannot_see(self, client, db, mock_kea):
        rc, _uid = restricted_client(client, db, allowed_subnets=[1])
        body = {"v": 2, "panels": [], "subnets": {"order": [1, 999], "pinned": [999], "hidden": [999]}}
        rc.post("/api/dashboard/save-prefs", json=body)
        got = rc.get("/api/dashboard/get-prefs").get_json()
        assert got["subnets"]["order"] == [1]
        assert got["subnets"]["pinned"] == []
        assert got["subnets"]["hidden"] == []

    def test_a_previously_saved_id_the_account_has_since_lost_is_dropped_on_read(
        self, client, db, mock_kea, monkeypatch
    ):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {1: {"name": "Test Network", "cidr": "10.99.0.0/24"}, 2: {"name": "Second Net", "cidr": "10.99.1.0/24"}},
        )
        rc, _uid = restricted_client(client, db, allowed_subnets=[1, 2])
        rc.post(
            "/api/dashboard/save-prefs",
            json={"v": 2, "panels": [], "subnets": {"order": [1, 2], "pinned": [2], "hidden": []}},
        )
        saved_before_narrowing = rc.get("/api/dashboard/get-prefs").get_json()
        assert saved_before_narrowing["subnets"]["pinned"] == [2]  # sanity: it really was accessible and stored
        with db.cursor() as cur:
            cur.execute("UPDATE users SET subnet_access=%s WHERE username='restricted1'", (json.dumps([1]),))
        db.commit()
        got = rc.get("/api/dashboard/get-prefs").get_json()
        assert got["subnets"]["order"] == [1]
        assert 2 not in got["subnets"]["pinned"]


class TestDashboardPageMarkup:
    def test_subnet_cards_carry_a_stable_id_for_client_side_reordering(self, logged_in_client, db, mock_kea):
        html = logged_in_client.get("/").data.decode()
        assert "data-subnet-id=" in html

    def test_arrange_controls_and_compact_toggle_are_present(self, logged_in_client, db, mock_kea):
        html = logged_in_client.get("/").data.decode()
        assert 'id="arrange-btn"' in html
        assert 'id="arrange-save-btn"' in html and 'id="arrange-cancel-btn"' in html
        assert 'id="dash-compact-toggle"' in html

    def test_widget_catalog_is_serialised_for_the_page_script(self, logged_in_client, db, mock_kea):
        from jen.services import dashboard_prefs as dp

        html = logged_in_client.get("/").data.decode()
        assert "var WIDGET_CATALOG" in html
        for wid in dp.WIDGET_CATALOG:
            assert wid in html

    def test_no_inline_on_handlers_were_added(self, logged_in_client, db, mock_kea):
        import re

        html = logged_in_client.get("/").data.decode()
        assert not re.search(r"<[^>]*\son(click|change)=", html)
