"""
tests/test_dashboard_arrangement.py
────────────────────────────────────
v5.54.0 (Q61) — the dashboard prefs v2 routes and the arrangement markup.

Needs the CI database (uses `logged_in_client`/`restricted_client`).
"""

import json

import pytest

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
            # token_version+1 is what actually invalidates the session's cached
            # subnet_access (jen/__init__.py::load_user) — the same UPDATE
            # jen/routes/users.py's own subnet-access edit route runs.
            cur.execute(
                "UPDATE users SET subnet_access=%s, token_version=token_version+1 WHERE username='restricted1'",
                (json.dumps([1]),),
            )
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


class TestCatalogDataRoute:
    def test_only_the_requested_widgets_are_computed(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import dashboard_catalog as dc

        calls = []
        monkeypatch.setattr(
            dc, "getting_started_widget", lambda *a, **k: calls.append("getting_started") or {"done": 1, "total": 2}
        )
        monkeypatch.setattr(dc, "forecast_widget", lambda *a, **k: calls.append("forecast") or [])
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=getting_started")
        assert r.status_code == 200
        assert calls == ["getting_started"]
        assert r.get_json() == {"getting_started": {"done": 1, "total": 2}}

    def test_an_unknown_widget_name_is_ignored(self, logged_in_client, db, mock_kea):
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=not-a-real-widget")
        assert r.status_code == 200 and r.get_json() == {}

    def test_no_login_is_refused(self, client):
        r = client.get("/api/dashboard/catalog-data?widgets=forecast")
        assert r.status_code in (302, 401)

    def test_a_builder_exception_is_a_clean_500_not_a_traceback(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import dashboard_catalog as dc

        def boom(*a, **k):
            raise RuntimeError("boom")

        monkeypatch.setattr(dc, "forecast_widget", boom)
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=forecast")
        assert r.status_code == 500
        assert b"boom" not in r.data

    def test_run_checks_runs_once_for_both_readiness_and_ddns_widgets(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        # v5.56.1 (Q68k) — readiness_widget()/ddns_errors_widget() used to
        # each call health.run_checks() themselves; enabling both widgets
        # doubled that work (Kea/DB/DNS/remote round trips) on one request.
        from jen.services import health

        calls = []

        def counted():
            calls.append(1)
            return []

        monkeypatch.setattr(health, "run_checks", counted)
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=readiness,ddns_errors")
        assert r.status_code == 200
        assert calls == [1]
        assert r.get_json() == {"readiness": None, "ddns_errors": None}

    def test_run_checks_never_runs_when_neither_widget_is_requested(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import health

        def boom():
            raise AssertionError("run_checks should not have been called")

        monkeypatch.setattr(health, "run_checks", boom)
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=forecast")
        assert r.status_code == 200

    def test_a_run_checks_failure_degrades_both_widgets_to_null_not_a_500(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        from jen.services import health

        def boom():
            raise RuntimeError("kea down")

        monkeypatch.setattr(health, "run_checks", boom)
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=readiness,ddns_errors")
        assert r.status_code == 200
        assert r.get_json() == {"readiness": None, "ddns_errors": None}

    # v5.57.0 (Q73, Q72's missed item e) — a d2_errors skip used to
    # collapse to a bare None; the panel then printed one generic
    # sentence no matter which of three reasons applied. Route-level so
    # this exercises the same run_checks() sharing as the test above,
    # not just ddns_errors_widget() in isolation.
    @pytest.mark.parametrize(
        "detail",
        [
            "DDNS updates disabled",
            "direct mode needs a D2 control-socket URL ([d2] api_url — 5.22.0)",
            "D2 statistics unavailable",
        ],
    )
    def test_each_ddns_skip_reason_reaches_the_route_with_its_fix_url(
        self, logged_in_client, db, mock_kea, monkeypatch, detail
    ):
        from jen.services import health
        from jen.services.health import Check

        monkeypatch.setattr(
            health, "run_checks", lambda: [Check("d2_errors", "D2 errors", "ddns", "skip", detail, fix_url="/ddns")]
        )
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=ddns_errors")
        assert r.status_code == 200
        assert r.get_json() == {"ddns_errors": {"status": "skip", "detail": detail, "fix_url": "/ddns"}}


class TestDataHrefGuardsInteractiveChildren:
    """v5.54.0 (Q61) — Arrange mode was the first thing to put interactive
    buttons inside a [data-href] container (a subnet stat-card); clicking one
    used to also fire the card's own "navigate to /leases?subnet=N" listener."""

    def test_base_html_skips_navigation_from_an_interactive_descendant(self):
        base = (__import__("pathlib").Path(__file__).resolve().parent.parent / "templates" / "base.html").read_text(
            encoding="utf-8"
        )
        anchor = "document.querySelectorAll('[data-href]').forEach(function(el) {"
        assert anchor in base
        block = base[base.index(anchor) : base.index("});", base.index(anchor)) + 3]
        assert "e.target.closest(" in block
