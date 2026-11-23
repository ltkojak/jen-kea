"""
tests/test_q248_b2.py
─────────────────────
Q248, the additions on single pages (the look over v7.2.0-beta.5, section D, and V33). What a rendered page, a JSON answer or a pure function
can hold is here; what only a browser can show (the Add Reservation line following its select, a free map cell opening the form, the Health
fold, the card drawn from the answer) is tests/e2e/test_q248_b2.py.

* Addition 2   "Needs attention" on the dashboard: its lines are the signed-in account's own - a superadmin, a viewer and a subnet-restricted admin.
* Addition 3   Health: failures and warnings first, each group's passing checks, the skipped checks behind one closed line; the JSON keeps its order.
* Addition 6   Add Reservation carries each of the account's subnets with its pools; a free cell of the IP map is a link for an admin, never for a viewer.
* Addition 16  Edit Reservation has a Delete form of its own, to the route the list uses.
* Addition 7   the audit log is filtered by action, by user and by whole days in UTC; the filters stay set across paging and one link clears them.
* Addition 15 and V33  About shows the newest release's lead paragraph, the rest behind one closed "More", and no tracking code a reader cannot resolve.
"""

import pathlib
import re

import pytest

from jen import extensions
from jen.services import changelog, health
from jen.services import dashboard_catalog as dcatalog
from jen.services import kea as kea_svc
from tests.conftest import restricted_client

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

SEEN = {"name": "Alpha-Seen", "cidr": "10.98.1.0/24"}
HIDDEN = {"name": "ZZ-HIDDEN-LAB", "cidr": "10.77.0.0/24"}
HIDDEN_MARKS = ("ZZ-HIDDEN-LAB", "10.77.0", "subnet=2", "subnet_id=2")


def _src(name):
    return (TEMPLATES / name).read_text(encoding="utf-8").replace("\r\n", "\n")


@pytest.fixture
def two_subnets(monkeypatch):
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(SEEN), 2: dict(HIDDEN)})


def _seed_history(db, rows):
    """`rows`: (subnet id, addresses in use, pool size) - one latest snapshot each."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease_history")
        for sid, used, size in rows:
            cur.execute(
                "INSERT INTO lease_history (subnet_id, active_leases, pool_used, pool_size, snapshot_time) "
                "VALUES (%s, %s, %s, %s, DATE_SUB(NOW(), INTERVAL 5 MINUTE))",
                (sid, used, used, size),
            )
    db.commit()


@pytest.fixture
def history(db):
    """Lease snapshots for one test: `history(rows)` replaces what is there, and nothing is left behind."""
    yield lambda rows: _seed_history(db, rows)
    _seed_history(db, [])


@pytest.fixture
def pools_over(history):
    """Subnet 1 over the alert threshold (85 %), subnet 2 with one address left."""
    history([(1, 85, 100), (2, 99, 100)])


def _checks_as_health_scopes_them(seen):
    """A stand-in for `health.run_checks` that scopes as the real one does: one check fails for every account, and a fleet-wide check - whose detail names a
    subnet - fails for an account that sees every subnet and is skipped for one that does not (the rule of `_kea_config_drift`, `_config_doctor` and their kin)."""

    def run(ctx=None):
        ctx = dict(ctx or {})
        seen.append(ctx)
        fleet = health.Check("kea_config_drift", "Subnet map matches Kea", "kea", "fail", "ZZ-HIDDEN-LAB is not in Kea")
        if not ctx.get("unrestricted", True):
            fleet.status, fleet.detail = "skip", "fleet-wide summary is for unrestricted accounts"
        return [
            health.Check("kea_reachable", "Kea servers reachable", "kea", "ok", "1/1 reachable"),
            fleet,
            health.Check("db_kea", "Kea database", "jen", "fail", "could not connect"),
            health.Check("cert_expiry", "TLS certificate expiry", "jen", "warn", "expires in 20 days"),
        ]

    return run


def _attention(client):
    r = client.get("/api/dashboard/catalog-data?widgets=attention")
    assert r.status_code == 200
    return r.get_json()["attention"], r.get_data(as_text=True)


# ── Addition 2: Needs attention ──────────────────────────────────────────────


class TestNeedsAttentionIsTheAccountsOwn:
    def test_a_superadmin_is_shown_the_failing_checks_and_both_pools(
        self, logged_in_client, db, mock_kea, monkeypatch, two_subnets, pools_over
    ):
        seen = []
        monkeypatch.setattr(health, "run_checks", _checks_as_health_scopes_them(seen))
        lines, _ = _attention(logged_in_client)
        assert [(line["kind"], line["url"]) for line in lines] == [
            ("health", "/health-center#check-kea_config_drift"),
            ("health", "/health-center#check-db_kea"),
            ("pool", "/leases?subnet=2"),
            ("pool", "/leases?subnet=1"),
        ]
        texts = [line["text"] for line in lines]
        assert texts[0] == "Subnet map matches Kea: ZZ-HIDDEN-LAB is not in Kea"
        assert texts[2] == "ZZ-HIDDEN-LAB (10.77.0.0/24): 1 address left in the pool"
        assert texts[3] == "Alpha-Seen (10.98.1.0/24): 85% of the pool is in use (the alert threshold is 80%)"
        assert [line["level"] for line in lines] == ["fail", "fail", "fail", "warn"]
        # a warning is not a failure: the certificate that expires in 20 days is on the Health page, not here
        assert not any("certificate" in t for t in texts)
        assert seen[0]["unrestricted"] is True and seen[0]["admin"] is True

    def test_a_restricted_admin_is_never_shown_the_hidden_subnet(
        self, client, db, mock_kea, monkeypatch, two_subnets, pools_over
    ):
        seen = []
        monkeypatch.setattr(health, "run_checks", _checks_as_health_scopes_them(seen))
        restricted_client(client, db, [1], role="admin", username="q248b2_scoped")
        lines, body = _attention(client)
        assert [(line["kind"], line["url"]) for line in lines] == [
            ("health", "/health-center#check-db_kea"),
            ("pool", "/leases?subnet=1"),
        ]
        for mark in HIDDEN_MARKS:
            assert mark not in body, mark
        # the checks were run with the account's own scope, as the Health page runs them
        assert seen[0]["unrestricted"] is False
        assert seen[0]["subnet_filter"](1) is True and seen[0]["subnet_filter"](2) is False
        page = client.get("/").get_data(as_text=True)
        for mark in HIDDEN_MARKS:
            assert mark not in page, mark

    def test_a_restricted_admin_whose_only_pool_is_fine_has_no_pool_line(
        self, client, db, mock_kea, monkeypatch, two_subnets, history
    ):
        history([(1, 10, 100), (2, 99, 100)])
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: [])
        restricted_client(client, db, [1], role="admin", username="q248b2_scoped_ok")
        lines, body = _attention(client)
        assert lines == []
        for mark in HIDDEN_MARKS:
            assert mark not in body, mark

    def test_a_viewer_is_shown_lines_that_all_lead_to_pages_a_viewer_may_open(
        self, client, db, mock_kea, monkeypatch, two_subnets, pools_over
    ):
        seen = []
        monkeypatch.setattr(health, "run_checks", _checks_as_health_scopes_them(seen))
        restricted_client(client, db, None, role="viewer", username="q248b2_viewer")
        lines, _ = _attention(client)
        assert len(lines) == 4 and seen[0]["admin"] is False and seen[0]["unrestricted"] is True
        for line in lines:
            path = line["url"].split("#")[0]
            assert path.split("?")[0] in ("/health-center", "/leases", "/servers"), line
            assert client.get(path).status_code == 200, path

    def test_a_restricted_viewer_is_scoped_as_a_restricted_admin_is(
        self, client, db, mock_kea, monkeypatch, two_subnets, pools_over
    ):
        monkeypatch.setattr(health, "run_checks", _checks_as_health_scopes_them([]))
        restricted_client(client, db, [1], role="viewer", username="q248b2_viewer_scoped")
        lines, body = _attention(client)
        assert [line["url"] for line in lines] == ["/health-center#check-db_kea", "/leases?subnet=1"]
        for mark in HIDDEN_MARKS:
            assert mark not in body, mark


class TestNeedsAttentionSaysEachThingOnce:
    def test_a_server_that_is_down_is_a_line_to_the_servers_page_and_not_a_health_line_too(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        statuses = [
            {"server": {"id": 1, "name": "kea-a"}, "up": True, "ha_state": None, "version": "3.0.0"},
            {"server": {"id": 2, "name": "kea-b"}, "up": False, "ha_state": None, "version": ""},
        ]
        calls = []
        monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: calls.append(1) or statuses)
        seen = []

        def run(ctx=None):
            seen.append(dict(ctx))
            return [health.Check("kea_reachable", "Kea servers reachable", "kea", "fail", "kea-b not reachable")]

        monkeypatch.setattr(health, "run_checks", run)
        _seed_history(db, [])
        lines, _ = _attention(logged_in_client)
        assert lines == [
            {"kind": "server", "level": "fail", "text": "Kea server kea-b is not reachable", "url": "/servers"}
        ]
        # the read of the servers was made once and handed to the checks
        assert calls == [1] and seen[0]["server_status"] is statuses

    def test_with_no_server_reading_the_health_row_is_what_says_it(self, db):
        failing = health.Check("kea_reachable", "Kea servers reachable", "kea", "fail", "no server status available")
        lines = dcatalog.attention_widget([failing], None, {})
        assert [line["url"] for line in lines] == ["/health-center#check-kea_reachable"]

    def test_a_pool_line_stands_in_for_the_pool_row_of_health(self, db, two_subnets, pools_over):
        failing = health.Check("pool_utilization", "Pool utilization", "capacity", "fail", "near exhaustion: x 99%")
        lines = dcatalog.attention_widget([failing], [], {2: dict(HIDDEN)})
        assert [line["kind"] for line in lines] == ["pool"]

    def test_nothing_wrong_is_an_empty_list(self, logged_in_client, db, mock_kea, monkeypatch):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        monkeypatch.setattr(
            health, "run_checks", lambda ctx=None: [health.Check("db_jen", "Jen database", "jen", "ok", "1 ms")]
        )
        lines, _ = _attention(logged_in_client)
        assert lines == []

    def test_a_health_run_that_raises_still_answers(self, logged_in_client, db, mock_kea, monkeypatch, pools_over):
        def boom(ctx=None):
            raise RuntimeError("kea down")

        monkeypatch.setattr(health, "run_checks", boom)
        lines, _ = _attention(logged_in_client)
        assert [line["kind"] for line in lines] == ["pool"]


class TestNeedsAttentionAddsNoSecondRun:
    def test_one_request_for_the_card_and_the_two_widgets_runs_the_checks_once(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: calls.append(1) or [])
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=attention,readiness,ddns_errors")
        assert r.status_code == 200 and calls == [1]
        assert set(r.get_json()) == {"attention", "readiness", "ddns_errors"}

    def test_a_request_that_does_not_name_the_card_reads_no_server_status_for_it(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        def boom():
            raise AssertionError("the server status is read for the card only")

        monkeypatch.setattr(kea_svc, "get_all_server_status", boom)
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: [])
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=readiness")
        assert r.status_code == 200 and "attention" not in r.get_json()

    def test_the_page_asks_for_the_three_health_readers_in_one_request(self):
        src = _src("dashboard.html")
        assert "var HEALTH_BACKED = { attention: true, readiness: true, ddns_errors: true };" in src
        assert "jenFetch('/api/dashboard/catalog-data?widgets=' + ids.join(','))" in src
        assert ".then(loadAttention);" in src


class TestNeedsAttentionOnThePage:
    def test_the_card_is_the_first_thing_and_is_not_drawn_until_it_has_a_line(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/").get_data(as_text=True)
        card = re.search(r'<div id="attention-card" class="([^"]*)"', html)
        assert card and "hidden" in card.group(1).split()
        assert "Needs attention" in html
        assert html.index('id="attention-card"') < html.index('id="dash-customize"') < html.index('id="dash-widgets"')
        assert re.search(r'<ul class="attention-list" id="attention-list">\s*</ul>', html)

    def test_it_is_not_a_widget_a_person_switches_off(self):
        from jen.services import dashboard_prefs

        assert "attention" not in dashboard_prefs.WIDGET_CATALOG

    def test_the_pool_rule_is_the_health_rows_rule(self, db, two_subnets, history):
        history([(1, 79, 100), (2, 80, 100)])
        assert [(p["subnet_id"], p["level"]) for p in health.pools_needing_attention([1, 2])] == [(2, "warn")]
        history([(1, 95, 100), (2, 80, 100)])
        got = health.pools_needing_attention([1, 2])
        assert [(p["subnet_id"], p["level"], p["free"]) for p in got] == [(1, "crit", 5), (2, "warn", 20)]
        assert health.pools_needing_attention([2]) == [got[1]]
        assert health.pools_needing_attention([]) == []
        ctx = {"subnet_filter": lambda _sid: True}
        assert health._pool_utilization(ctx).status == "fail"
        history([(1, 79, 100)])
        assert health._pool_utilization(ctx).status == "ok" and health.pools_needing_attention([1]) == []


# ── Addition 3: Health ───────────────────────────────────────────────────────

C = health.Check
MIXED = [
    C("kea_reachable", "Kea servers reachable", "kea", "ok", "1/1 reachable"),
    C("kea_ha_state", "HA state healthy", "kea", "skip", "single server"),
    C("kea_hooks", "Kea hooks loaded", "kea", "warn", "lease_cmds missing"),
    C("pool_utilization", "Pool utilization", "capacity", "ok", "1 subnet below 80%"),
    C("d2_reachable", "kea-dhcp-ddns reachable", "ddns", "skip", "DDNS updates disabled"),
    C("db_jen", "Jen database", "jen", "fail", "could not connect"),
    C("schema_current", "Database schema current", "jen", "ok", "40"),
    C("kea32_d2_socket", "kea-dhcp-ddns on its own socket", "readiness", "skip", "DDNS updates disabled"),
]


class TestHealthPutsWhatNeedsYouFirst:
    def _page(self, client, monkeypatch, checks, path="/health-center"):
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: list(checks))
        return client.get(path).get_data(as_text=True)

    def test_failures_then_warnings_then_passes_then_the_skipped(self, logged_in_client, mock_kea, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, MIXED)
        order = re.findall(r'data-check="(\w+)" data-status="(\w+)"', html)
        assert order == [
            ("db_jen", "fail"),
            ("kea_hooks", "warn"),
            ("kea_reachable", "ok"),
            ("pool_utilization", "ok"),
            ("schema_current", "ok"),
            ("kea_ha_state", "skip"),
            ("d2_reachable", "skip"),
            ("kea32_d2_socket", "skip"),
        ]
        sections = re.findall(r'data-hc-section="(\w+)"', html)
        assert sections == ["attention", "kea", "capacity", "jen", "skipped"]
        assert "Failures and warnings" in html

    def test_the_skipped_checks_are_behind_one_closed_line(self, logged_in_client, mock_kea, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, MIXED).split('id="health-results"')[1]
        fold = re.search(r"<details([^>]*)>\s*<summary>([^<]*)</summary>(.*?)</details>", html, re.S)
        assert fold and 'class="hc-skipped"' in fold.group(1) and " open" not in fold.group(1)
        assert fold.group(2) == "3 checks were skipped (not applicable to this install)"
        assert re.findall(r'data-status="(\w+)"', fold.group(3)) == ["skip", "skip", "skip"]
        # nothing skipped is drawn outside the fold
        assert 'data-status="skip"' not in html.replace(fold.group(0), "")

    def test_one_skipped_check_is_singular_and_none_draws_no_fold(self, logged_in_client, mock_kea, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, MIXED[:2])
        assert "1 check was skipped (not applicable to this install)" in html
        html = self._page(logged_in_client, monkeypatch, MIXED[:1])
        assert "<details" not in html.split('id="health-results"')[1].split("</main>")[0]
        assert "Failures and warnings" not in html

    def test_the_partial_htmx_swaps_is_ordered_the_same_and_has_no_script(
        self, logged_in_client, mock_kea, monkeypatch
    ):
        html = self._page(logged_in_client, monkeypatch, MIXED, "/health-center/data?partial=1")
        assert [cid for cid, _ in re.findall(r'data-check="(\w+)" data-status="(\w+)"', html)][:2] == [
            "db_jen",
            "kea_hooks",
        ]
        assert "<script" not in html and "<details" in html

    def test_every_row_has_the_id_the_dashboard_links_to(self, logged_in_client, mock_kea, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, MIXED)
        for c in MIXED:
            assert f'id="check-{c.id}" data-check="{c.id}"' in html, c.id

    def test_the_json_keeps_every_check_in_the_order_it_was_run(self, logged_in_client, mock_kea, monkeypatch):
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: list(MIXED))
        data = logged_in_client.get("/health-center/data").get_json()
        assert [c["id"] for c in data["checks"]] == [c.id for c in MIXED]
        assert data["summary"] == {"ok": 3, "warn": 1, "fail": 1, "skip": 3}

    def test_the_page_keeps_the_fold_open_across_a_swap(self):
        src = _src("health_center.html")
        assert "results.addEventListener('toggle'," in src and "results.addEventListener('htmx:afterSwap'," in src
        assert "<script" not in _src("_health_checks.html")


# ── Addition 6: help choosing an address ─────────────────────────────────────


def _kea_with_pools(monkeypatch, pools_by_id, result=0):
    answer = {
        "result": result,
        "text": "mocked",
        "arguments": {
            "Dhcp4": {
                "subnet4": [
                    {"id": sid, "subnet": extensions.SUBNET_MAP[sid]["cidr"], "pools": [{"pool": p} for p in pools]}
                    for sid, pools in pools_by_id.items()
                ]
            }
        },
    }
    monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: answer)
    monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})


def _pools_in_page(html):
    import json

    return json.loads(re.search(r"var SUBNET_POOLS = (\{.*?\});", html).group(1))


class TestAddReservationShowsTheSubnetsPools:
    POOLS = {1: ["10.98.1.100 - 10.98.1.200", "10.98.1.64/28"], 2: ["10.77.0.50-10.77.0.60"]}

    def test_the_form_carries_each_subnet_with_its_pools(self, logged_in_client, db, monkeypatch, two_subnets):
        _kea_with_pools(monkeypatch, self.POOLS)
        html = logged_in_client.get("/reservations/add").get_data(as_text=True)
        assert _pools_in_page(html) == {
            "1": ["10.98.1.64 - 10.98.1.79", "10.98.1.100 - 10.98.1.200"],
            "2": ["10.77.0.50 - 10.77.0.60"],
        }
        assert '<div class="form-hint" id="f-ip-range" hidden></div>' in html
        assert 'id="f-ip"' in html and 'aria-describedby="f-ip-range"' in html

    def test_a_restricted_admin_gets_only_their_own(self, client, db, monkeypatch, two_subnets):
        _kea_with_pools(monkeypatch, self.POOLS)
        restricted_client(client, db, [1], role="admin", username="q248b2_addres")
        html = client.get("/reservations/add").get_data(as_text=True)
        assert set(_pools_in_page(html)) == {"1"}
        for mark in ("ZZ-HIDDEN-LAB", "10.77.0"):
            assert mark not in html, mark

    def test_pools_that_cannot_be_read_leave_the_range_alone(self, logged_in_client, db, monkeypatch, two_subnets):
        _kea_with_pools(monkeypatch, self.POOLS, result=1)
        html = logged_in_client.get("/reservations/add").get_data(as_text=True)
        assert _pools_in_page(html) == {}
        assert re.search(r'"1":\s*"10\.98\.1\.0/24"', html)  # the range the line is written from

        def boom(*a, **kw):
            raise RuntimeError("kea down")

        monkeypatch.setattr(kea_svc, "kea_command", boom)
        r = logged_in_client.get("/reservations/add")
        assert r.status_code == 200 and _pools_in_page(r.get_data(as_text=True)) == {}

    def test_a_refused_form_is_drawn_again_with_its_pools(self, logged_in_client, db, monkeypatch, two_subnets):
        _kea_with_pools(monkeypatch, self.POOLS)
        r = logged_in_client.post(
            "/reservations/add", data={"subnet_id": "1", "mac": "not-a-mac", "ip": "10.98.1.20", "hostname": ""}
        )
        assert r.status_code == 400
        assert _pools_in_page(r.get_data(as_text=True))["1"] == ["10.98.1.64 - 10.98.1.79", "10.98.1.100 - 10.98.1.200"]

    def test_the_line_is_written_as_decided(self):
        src = _src("add_reservation.html")
        assert (
            "rangeLine.textContent = 'Subnet ' + cidr + (pools.length ? ' - ' + "
            "(pools.length > 1 ? 'pools ' : 'pool ') + drawn.join(', ') : '');"
        ) in src
        assert "Use next free" not in src


class TestAFreeMapCellOpensTheForm:
    def _map(self, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "Test Network", "cidr": "10.99.0.0/24"}})
        _kea_with_pools(monkeypatch, {1: ["10.99.0.20-10.99.0.23"]})

    def test_for_an_admin_a_free_cell_is_a_link_with_the_subnet_and_the_address(
        self, logged_in_client, db, monkeypatch
    ):
        self._map(monkeypatch)
        html = logged_in_client.get("/ipmap?subnet=1").get_data(as_text=True)
        links = re.findall(r'<a class="ip-cell ip-free" href="([^"]+)"', html)
        assert links == [f"/reservations/add?subnet_id=1&amp;ip=10.99.0.{n}" for n in (20, 21, 22, 23)]
        assert html.count('class="ip-cell ip-') == 4
        assert "Select a free address to reserve it." in html

    def test_a_used_cell_is_never_a_link(self, logged_in_client, db, monkeypatch):
        self._map(monkeypatch)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbcc248b21'), 0, 1, INET_ATON('10.99.0.21'), 'q248-taken')"
            )
        db.commit()
        try:
            html = logged_in_client.get("/ipmap?subnet=1").get_data(as_text=True)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE hostname='q248-taken'")
            db.commit()
        assert "ip=10.99.0.21" not in html and html.count('<a class="ip-cell ip-free"') == 3
        assert 'class="ip-cell ip-reserved"' in html

    def test_a_viewers_free_cells_are_not_links(self, client, db, monkeypatch):
        self._map(monkeypatch)
        restricted_client(client, db, None, role="viewer", username="q248b2_mapviewer")
        html = client.get("/ipmap?subnet=1").get_data(as_text=True)
        assert html.count('<div class="ip-cell ip-free"') == 4
        assert "/reservations/add" not in html and "Select a free address" not in html

    def test_the_link_opens_the_form_filled_in(self, logged_in_client, db, monkeypatch):
        self._map(monkeypatch)
        html = logged_in_client.get("/reservations/add?subnet_id=1&ip=10.99.0.22").get_data(as_text=True)
        assert re.search(r'<option value="1" selected>', html)
        assert re.search(r'name="ip" id="f-ip"[^>]*value="10.99.0.22"', html)


# ── Addition 16: Delete on Edit Reservation ──────────────────────────────────


@pytest.fixture
def a_reservation(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM hosts WHERE hostname='q248-edit'")
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
            "VALUES (UNHEX('aabbcc248b16'), 0, 1, INET_ATON('10.99.0.77'), 'q248-edit')"
        )
        host_id = cur.lastrowid
    db.commit()
    yield host_id
    with db.cursor() as cur:
        cur.execute("DELETE FROM hosts WHERE hostname='q248-edit'")
        cur.execute("DELETE FROM events WHERE ip='10.99.0.77'")  # the delete route records an event for the address
    db.commit()


class TestEditReservationCanDelete:
    def test_the_page_has_a_delete_form_of_its_own_to_the_lists_route(self, logged_in_client, mock_kea, a_reservation):
        html = logged_in_client.get(f"/reservations/edit/{a_reservation}").get_data(as_text=True)
        form = re.search(r'<form method="POST" action="/reservations/delete/(\d+)"([^>]*)>(.*?)</form>', html, re.S)
        assert form and int(form.group(1)) == a_reservation
        attrs, inner = form.group(2), form.group(3)
        assert 'data-confirm="Delete the reservation for 10.99.0.77? This cannot be undone."' in attrs
        assert 'data-confirm-label="Delete"' in attrs
        assert 'name="csrf_token"' in inner
        button = re.search(r"<button([^>]*)>(.*?)</button>", inner, re.S)
        assert 'type="submit"' in button.group(1) and 'data-confirm-label="Delete"' in button.group(1)
        assert "btn-danger" in button.group(1) and button.group(2).strip().endswith("Delete Reservation")
        # never inside the edit form: the edit form is closed before the delete form opens
        edit_open = html.index('id="edit-reservation-form"')
        assert html.index("</form>", edit_open) < html.index('action="/reservations/delete/')

    def test_the_delete_lands_on_the_list_with_the_routes_own_message(
        self, logged_in_client, db, monkeypatch, a_reservation
    ):
        sent = []
        monkeypatch.setattr(
            kea_svc, "kea_command", lambda cmd, *a, **kw: sent.append((cmd, kw.get("arguments"))) or {"result": 0}
        )
        r = logged_in_client.post(f"/reservations/delete/{a_reservation}")
        assert r.status_code == 302 and r.headers["Location"].endswith("/reservations")
        assert sent[0][0] == "reservation-del" and sent[0][1]["subnet-id"] == 1
        with logged_in_client.session_transaction() as sess:
            assert ("success", "Reservation 10.99.0.77 deleted.") in sess.get("_flashes", [])

    def test_a_restricted_admin_is_refused_the_page_and_the_delete(
        self, client, db, mock_kea, two_subnets, a_reservation
    ):
        restricted_client(client, db, [2], role="admin", username="q248b2_noedit")
        r = client.get(f"/reservations/edit/{a_reservation}")
        assert r.status_code == 302
        r = client.post(f"/reservations/delete/{a_reservation}")
        assert r.status_code == 302
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM hosts WHERE host_id=%s", (a_reservation,))
            assert cur.fetchone()["n"] == 1


# ── Addition 7: audit log filters ────────────────────────────────────────────


@pytest.fixture
def audit_rows(db):
    rows = [
        ("admin", "ADD_RESERVATION", "10.99.0.5", "first", "2026-11-01 10:00:00"),
        ("bob", "DELETE_USER", "carol", "second", "2026-11-02 23:59:59"),
        ("admin", "LOGIN", "admin", "third", "2026-11-03 00:00:00"),
        ("bob", "LOGIN", "bob", "fourth", "2026-11-03 12:00:00"),
    ]
    with db.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        for username, action, entity, details, at in rows:
            cur.execute(
                "INSERT INTO audit_log (user_id, username, action, entity, details, created_at) VALUES (1, %s, %s, %s, %s, %s)",
                (username, action, entity, details, at),
            )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
    db.commit()


def _details(html):
    """The Details column of the rows drawn, in order."""
    return re.findall(
        r'<td data-m="secondary" class="u-865c33"><span class="clip" data-clip-toggle title="[^"]*">([^<]*)</span></td>',
        html,
    )


class TestAuditLogFilters:
    def _get(self, client, query):
        r = client.get("/settings/logs?tab=audit" + query)
        assert r.status_code == 200
        return r.get_data(as_text=True)

    def test_by_action(self, logged_in_client, audit_rows):
        assert _details(self._get(logged_in_client, "&action=LOGIN")) == ["fourth", "third"]

    def test_by_user(self, logged_in_client, audit_rows):
        assert _details(self._get(logged_in_client, "&user=bob")) == ["fourth", "second"]

    def test_a_day_is_a_whole_day_in_utc(self, logged_in_client, audit_rows):
        assert _details(self._get(logged_in_client, "&from=2026-11-02&to=2026-11-02")) == ["second"]
        assert _details(self._get(logged_in_client, "&to=2026-11-02")) == ["second", "first"]
        assert _details(self._get(logged_in_client, "&from=2026-11-03")) == ["fourth", "third"]

    def test_the_filters_and_the_search_combine(self, logged_in_client, audit_rows):
        assert _details(self._get(logged_in_client, "&action=LOGIN&user=bob&from=2026-11-03")) == ["fourth"]
        assert _details(self._get(logged_in_client, "&user=admin&search=third")) == ["third"]

    def test_the_selects_offer_what_the_log_holds_and_show_what_is_set(self, logged_in_client, audit_rows):
        html = self._get(logged_in_client, "&action=LOGIN&user=bob&from=2026-11-01&to=2026-11-03")
        action = re.search(r'<select name="action"[^>]*>(.*?)</select>', html, re.S).group(1)
        assert re.findall(r'<option value="([^"]*)"( selected)?>', action) == [
            ("", ""),
            ("ADD_RESERVATION", ""),
            ("DELETE_USER", ""),
            ("LOGIN", " selected"),
        ]
        user = re.search(r'<select name="user"[^>]*>(.*?)</select>', html, re.S).group(1)
        assert re.findall(r'<option value="([^"]*)"( selected)?>', user) == [
            ("", ""),
            ("admin", ""),
            ("bob", " selected"),
        ]
        assert re.search(r'<input type="date" name="from" value="2026-11-01"', html)
        assert re.search(r'<input type="date" name="to" value="2026-11-03"', html)
        assert (
            '<a href="/settings/logs?tab=audit" class="btn btn-sm btn-secondary" id="audit-clear">Clear filters</a>'
            in html
        )

    def test_nothing_set_shows_no_clear(self, logged_in_client, audit_rows):
        html = self._get(logged_in_client, "")
        assert "Clear filters" not in html and len(_details(html)) == 4

    def test_a_value_the_log_does_not_hold_matches_nothing_and_raises_nothing(self, logged_in_client, audit_rows):
        for query in ("&action=NO_SUCH_ACTION", "&user=nobody", "&action=%27%20OR%201%3D1%20--%20", "&user=%25"):
            html = self._get(logged_in_client, query)
            assert _details(html) == [], query
            assert "No audit events match." in html and "No audit events yet." not in html
            assert re.search(r'<a class="btn btn-sm" href="/settings/logs\?tab=audit">Clear filters</a>', html)
        # and it is shown as set, as one more choice of its select
        html = self._get(logged_in_client, "&action=NO_SUCH_ACTION")
        assert '<option value="NO_SUCH_ACTION" selected>NO_SUCH_ACTION</option>' in html

    def test_a_day_that_cannot_be_read_is_no_filter(self, logged_in_client, audit_rows):
        for query in ("&from=yesterday", "&to=2026-13-45", "&from=2026-11-02T10:00", "&from=&to="):
            html = self._get(logged_in_client, query)
            assert len(_details(html)) == 4, query
            assert "Clear filters" not in html, query

    def test_the_paging_links_keep_every_filter(self, logged_in_client, db, audit_rows):
        with db.cursor() as cur:
            for i in range(60):
                cur.execute(
                    "INSERT INTO audit_log (user_id, username, action, entity, details, created_at) "
                    "VALUES (1, 'bob', 'RELEASE_LEASE', 'x', %s, '2026-11-02 08:00:00')",
                    (f"bulk {i}",),
                )
        db.commit()
        html = self._get(logged_in_client, "&action=RELEASE_LEASE&user=bob&from=2026-11-02&to=2026-11-02&search=bulk")
        assert len(_details(html)) == 50
        want = "?tab=audit&amp;search=bulk&amp;action=RELEASE_LEASE&amp;user=bob&amp;from=2026-11-02&amp;to=2026-11-02&amp;page=2"
        assert f'<a href="{want}">2</a>' in html and f'<a href="{want}">Next ›</a>' in html
        page2 = self._get(
            logged_in_client, "&action=RELEASE_LEASE&user=bob&from=2026-11-02&to=2026-11-02&search=bulk&page=2"
        )
        assert len(_details(page2)) == 10

    def test_the_page_still_needs_every_subnet(self, client, db, audit_rows):
        restricted_client(client, db, [1], role="admin", username="q248b2_logs")
        r = client.get("/settings/logs?tab=audit&action=LOGIN")
        assert r.status_code == 302 and "/settings/logs" not in r.headers["Location"]

    def test_there_is_no_export(self):
        src = _src("logs.html")
        assert "csv" not in src.lower() and "export" not in src.lower()


# ── Addition 15 and V33: About ───────────────────────────────────────────────

FILE = """# Changelog

## [9.1.0] - 2030-02-02

**The lead sentence of the newest release (U1, U2).** No migration.

**1. Navigation (BG1, BG6, BG7).** The pin button (redirects to HTTPS) on Ubuntu (Ubuntu 22.04).

- A bullet that cites a row (WOL-1 to WOL-4, WOL-16) and a standard (RFC 5280).
- The whole-number test (DEF-003), never a bare cast.

**Registered, not changed.** From the pass: BG5 and BG8, which nobody here can look up.

### Registered, not in this release

AP14 and the rows after it.

### What this release proves

It was run (v5.65.10) before it was filed (7.2.0-beta.4).

## [9.0.0] - 2030-01-01

**The older release.** Its own text (BF2).
"""


class TestTrackingCodesAreLeftOut:
    @pytest.mark.parametrize(
        "kept",
        [
            "(redirects to HTTPS)",
            "(7.2.0-beta.4)",
            "(v5.65.10)",
            "(RFC 5280)",
            "(Ubuntu 22.04)",
            "(D2)",
            "(SHA256)",
            "(P-256)",
            "(IPv6)",
            "(K8s)",
            "(RFC5280)",
            "(1.2.9)",
            "(not in use: no certificate is installed)",
            "(BG3; BG5 written down)",
            "(4 P1, 31 P2, 67 P3 by its readers' tiers)",
        ],
    )
    def test_what_is_not_a_group_of_codes_survives(self, kept):
        text = f"The port {kept} is shown."
        assert changelog.strip_tracking_codes(text) == text

    @pytest.mark.parametrize(
        "before, after",
        [
            ("Navigation (U1, U2, U3).", "Navigation."),
            ("IPAM Lite 1.8.4 (BG1, BG6, BG7).", "IPAM Lite 1.8.4."),
            ("Pages (U5 to U15).", "Pages."),
            ("Wake (WOL-1 to WOL-4, WOL-16, WOL-22).", "Wake."),
            ("the one whole-number test (DEF-003), never", "the one whole-number test, never"),
            ("*Host Watchdog (BG12):* a host", "*Host Watchdog:* a host"),
            ("its two rows (BE1, BE2) are", "its two rows are"),
            ("masks (AZ6, BA4, and BB10) the bundle", "masks the bundle"),
            ("a row (BD1 and BD2; BH3) here", "a row here"),
        ],
    )
    def test_a_group_of_codes_goes_with_the_space_before_it(self, before, after):
        assert changelog.strip_tracking_codes(before) == after

    def test_the_real_file_is_read_without_them(self):
        plain = changelog.parse_changelog(limit=5)
        read = changelog.whats_new(limit=5)
        assert [e["version"] for e in read] == [e["version"] for e in plain] and len(read) == 5
        only_codes = re.compile(
            r"\((?:[A-Z]{1,6}-?\d{1,4})(?:(?:\s*[,;/]\s*(?:and\s+)?|\s+(?:and|to)\s+)[A-Z]{1,6}-?\d{1,4})*\)"
        )
        for e in read:
            assert not only_codes.search(e["html"]), (e["version"], only_codes.search(e["html"]).group(0))
            assert not re.search(r"<(?:p|h4)>(?:<strong>|<em>)*Registered\b", e["html"]), e["version"]
            assert e["lead"].startswith("<p>") and e["lead"].endswith("</p>") and e["lead"].count("<p>") == 1
            assert e["lead"] + e["rest"] == e["html"]

    def test_the_lead_the_rest_and_the_registered_parts(self, tmp_path):
        path = tmp_path / "CHANGELOG.md"
        path.write_text(FILE, encoding="utf-8")
        newest, older = changelog.whats_new(path=path)
        assert newest["version"] == "9.1.0" and older["version"] == "9.0.0"
        assert newest["lead"] == "<p><strong>The lead sentence of the newest release.</strong> No migration.</p>"
        rest = newest["rest"]
        assert "<strong>1. Navigation.</strong> The pin button (redirects to HTTPS) on Ubuntu (Ubuntu 22.04)." in rest
        assert "<li>A bullet that cites a row and a standard (RFC 5280).</li>" in rest
        assert "<li>The whole-number test, never a bare cast.</li>" in rest
        assert "Registered" not in rest and "BG5" not in rest and "AP14" not in rest
        assert (
            "<h4>What this release proves</h4><p>It was run (v5.65.10) before it was filed (7.2.0-beta.4).</p>" in rest
        )
        assert older["lead"] == "<p><strong>The older release.</strong> Its own text.</p>" and older["rest"] == ""
        # the file as it is, for a caller that asks for it
        plain = changelog.parse_changelog(path=path)[0]
        assert set(plain) == {"version", "date", "html"}
        assert "(BG1, BG6, BG7)" in plain["html"] and "Registered, not changed." in plain["html"]
        assert "<h4>Registered, not in this release</h4>" in plain["html"]


class TestAboutShowsTheNewestLead:
    def test_only_the_newest_lead_is_in_view_and_the_rest_is_behind_one_closed_more(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/about").get_data(as_text=True)
        card = html.split('id="whats-new"')[1].split("Full Changelog")[0]
        entries = changelog.whats_new(limit=5)
        before, more = card.split('<details class="wn-more">', 1)
        assert more.lstrip().startswith("<summary>More</summary>")
        assert before.count("changelog-body") == 1 and entries[0]["lead"] in before
        assert f"v{entries[0]['version']}" in before
        for e in entries[1:]:
            assert f'data-version="{e["version"]}"' not in before and f'data-version="{e["version"]}"' in more
        assert entries[0]["rest"] in more
        assert "<details open" not in card and card.count("<details") == len(entries)

    def test_the_page_prints_no_tracking_code_group_and_no_registered_paragraph(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/about").get_data(as_text=True)
        card = html.split('id="whats-new"')[1].split("Full Changelog")[0]
        for gone in (
            "(U1, U2, U3)",
            "(BG1, BG6, BG7)",
            "(U5 to U15)",
            "Registered, not changed",
            "Registered, not in this beta",
        ):
            assert gone not in card, gone
        assert not re.search(r"\((?:[A-Z]{1,6}-?\d{1,4})(?:, [A-Z]{1,6}-?\d{1,4})*\)", card)

    def test_a_file_with_one_short_entry_draws_no_more(self, logged_in_client, mock_kea, monkeypatch, tmp_path):
        path = tmp_path / "CHANGELOG.md"
        path.write_text("## [1.0.0] - 2030-01-01\n\nOnly this.\n", encoding="utf-8")
        monkeypatch.setattr(changelog, "whats_new", lambda limit=5: changelog.parse_changelog(path, limit, True))
        html = logged_in_client.get("/about").get_data(as_text=True)
        card = html.split('id="whats-new"')[1].split("Full Changelog")[0]
        assert "<p>Only this.</p>" in card and "<details" not in card
