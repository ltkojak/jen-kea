"""
tests/test_problems_page.py
────────────────────────────
v5.68.0-beta.5 (Q140) — the Problems inbox page, its lazy answer and the dashboard widget, against the real test database: one entry per
client newest first, the server and kind filters, the empty and failed states, the Investigate link, and — the part that matters — who
sees which row: a caller restricted to some subnets sees only rows in them and never a row with no subnet; one who may see every
subnet sees both. The answer endpoint judges a client exactly as /client does, so a client outside the caller's subnets is the same
empty answer as one that does not exist and the Overview's answer is never computed for it.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from jen import extensions
from jen.services import client_problems as cp
from jen.services import dashboard_catalog as dc

MAC_A = "aa:bb:cc:dd:ee:51"
MAC_B = "aa:bb:cc:dd:ee:52"
MAC_X = "aa:bb:cc:dd:ee:53"  # no subnet at all
MAC_OLD = "aa:bb:cc:dd:ee:54"
IP_A = "10.45.0.51"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)  # naive UTC, as the table stores it


@pytest.fixture
def inbox(db, monkeypatch):
    """Problem rows in subnet 1 (A), subnet 2 (B), no subnet, and an old one - and a lease for the A client."""
    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
    monkeypatch.setattr(
        extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.45.0.0/24"}, 2: {"name": "B", "cidr": "10.46.0.0/24"}}
    )
    now = _now()
    with db.cursor() as cur:
        cur.execute("DELETE FROM client_problems")
        cur.execute("DELETE FROM lease4 WHERE address=INET_ATON(%s)", (IP_A,))
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC_A, MAC_B))
        cur.execute(
            "INSERT INTO client_problems (server_id, kind, mac, ip, subnet_id, first_seen, last_seen, `count`, detail) VALUES "
            "(1, 'nak', %s, '', 1, %s, %s, 4, 'Kea sent a DHCPNAK'), "
            "(1, 'decline', %s, '10.45.0.77', 1, %s, %s, 1, '10.45.0.77 was declined'), "
            "(1, 'nak', %s, '', 2, %s, %s, 2, 'Kea sent a DHCPNAK'), "
            "(1, 'drop', %s, '', NULL, %s, %s, 1, 'packet dropped'), "
            "(0, 'declined-lease', '', '10.46.0.9', 2, %s, %s, 1, '10.46.0.9 was declined by a client'), "
            "(1, 'nak', %s, '', 1, %s, %s, 9, 'old')",
            (
                MAC_A, now - timedelta(minutes=30), now - timedelta(minutes=2),
                MAC_A, now - timedelta(minutes=50), now - timedelta(minutes=20),
                MAC_B, now - timedelta(minutes=40), now - timedelta(minutes=10),
                MAC_X, now - timedelta(minutes=5), now - timedelta(minutes=5),
                now - timedelta(minutes=15), now - timedelta(minutes=15),
                MAC_OLD, now - timedelta(days=2), now - timedelta(days=2),
            ),
        )  # fmt: skip
        cur.execute("UPDATE client_problems SET resolved_at=%s WHERE mac=%s", (now, MAC_OLD))
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
            "VALUES (INET_ATON(%s), UNHEX(REPLACE(%s, ':', '')), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
            (IP_A, MAC_A),
        )
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC_A, IP_A))
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM client_problems")
        cur.execute("DELETE FROM lease4 WHERE address=INET_ATON(%s)", (IP_A,))
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC_A, MAC_B))
    db.commit()


class TestThePage:
    def test_one_entry_per_client_newest_first_with_every_kind_it_had(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems").data.decode()
        assert body.index(MAC_A) < body.index(MAC_X) < body.index(MAC_B), (
            "newest last_seen first: A (2 min), X (5), B (10)"
        )
        assert body.count(MAC_A) >= 1 and "NAK" in body and "Declined an address" in body
        assert "NAK × 4" in body, "the count shows once it is more than one"

    def test_a_resolved_row_is_not_in_the_inbox(self, logged_in_client, inbox):
        assert MAC_OLD not in logged_in_client.get("/problems").data.decode()

    def test_a_row_with_only_an_address_is_that_address(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems").data.decode()
        assert "10.46.0.9" in body and "Declined lease" in body and "lease database" in body

    def test_every_row_is_one_click_from_its_investigation(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems").data.decode()
        assert f"/client?q={quote(MAC_A, safe='')}" in body and "/client?q=10.46.0.9" in body

    def test_the_server_filter_keeps_that_servers_rows(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems?server=1").data.decode()
        assert MAC_A in body and "10.46.0.9" not in body
        assert "10.46.0.9" in logged_in_client.get("/problems?server=0").data.decode()

    def test_the_kind_filter(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems?kind=decline").data.decode()
        assert "10.45.0.77" in body and MAC_B not in body and MAC_X not in body

    def test_an_unknown_kind_is_ignored_not_an_error(self, logged_in_client, inbox):
        r = logged_in_client.get("/problems?kind=%27%3B--")
        assert r.status_code == 200 and MAC_A in r.data.decode()

    def test_a_server_that_is_not_a_number_is_ignored(self, logged_in_client, inbox):
        assert logged_in_client.get("/problems?server=abc").status_code == 200

    def test_nothing_to_show_says_so_and_what_fills_the_list(self, logged_in_client, db, inbox):
        with db.cursor() as cur:
            cur.execute("DELETE FROM client_problems")
        db.commit()
        body = logged_in_client.get("/problems").data.decode()
        assert "No client has had DHCP trouble" in body and "rebuilt every five minutes" in body

    def test_without_ssh_it_says_which_kinds_can_still_appear(self, logged_in_client, db, inbox, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": ""}])
        with db.cursor() as cur:
            cur.execute("DELETE FROM client_problems")
        db.commit()
        assert "needs SSH access" in logged_in_client.get("/problems").data.decode()

    def test_the_legend_names_the_log_level_and_links_to_investigation_logging(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems").data.decode()
        assert "only while a server logs at DEBUG" in body and "investigation logging" in body

    def test_an_unreadable_table_is_a_message_not_a_500(self, logged_in_client, inbox, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("table is gone")

        monkeypatch.setattr(cp, "fetch_open", boom)
        r = logged_in_client.get("/problems")
        assert (
            r.status_code == 200
            and "could not read the Problems list" in r.data.decode()
            and "table is gone" not in r.data.decode()
        )

    def test_it_is_in_the_nav_under_network(self):
        from pathlib import Path

        nav = (Path(__file__).resolve().parent.parent / "jen" / "routes" / "settings" / "nav.py").read_text(
            encoding="utf-8"
        )
        assert '"url": "/problems"' in nav and '"match": ("problems.",)' in nav

    def test_a_visitor_who_is_not_logged_in_is_sent_to_login(self, client, inbox):
        r = client.get("/problems")
        assert r.status_code in (301, 302) and "login" in r.headers["Location"].lower()


class TestWhoSeesWhichRow:
    def test_a_scoped_viewer_sees_only_their_subnets_rows_and_never_the_unattributed_one(self, client, db, inbox):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_problems_a")
        body = client.get("/problems").data.decode()
        assert MAC_A in body
        assert MAC_B not in body and "10.46.0.9" not in body, "a row in a subnet they cannot see"
        assert MAC_X not in body, "a row with no subnet is for callers who may see every subnet"

    def test_the_filters_do_not_widen_it(self, client, db, inbox):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_problems_a2")
        body = client.get("/problems?server=0&kind=declined-lease").data.decode()
        assert "10.46.0.9" not in body

    def test_a_caller_with_no_subnets_sees_nothing(self, client, db, inbox):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_problems_none")
        body = client.get("/problems").data.decode()
        assert MAC_A not in body and MAC_B not in body and MAC_X not in body

    def test_a_caller_who_may_see_every_subnet_sees_every_row_including_the_unattributed(self, logged_in_client, inbox):
        body = logged_in_client.get("/problems").data.decode()
        assert all(x in body for x in (MAC_A, MAC_B, MAC_X, "10.46.0.9"))


class TestTheLazyAnswer:
    def _stub(self, monkeypatch, line="would offer 10.45.0.60"):
        calls = []

        def fake(view):
            calls.append(view.mac)
            return line

        monkeypatch.setattr("jen.routes.client._overview_line", fake)
        return calls

    def test_it_is_the_overview_line_for_a_client_the_caller_may_see(self, logged_in_client, inbox, monkeypatch):
        calls = self._stub(monkeypatch)
        body = logged_in_client.get(f"/problems/answer?q={MAC_A}").data.decode()
        assert "would offer 10.45.0.60" in body and calls == [MAC_A]
        assert f"/client?q={quote(MAC_A, safe='')}&amp;tab=explain" in body  # the ampersand is escaped in an attribute

    def test_nothing_is_computed_until_a_row_is_expanded(self, logged_in_client, inbox, monkeypatch):
        calls = self._stub(monkeypatch)
        logged_in_client.get("/problems")
        assert calls == []

    def test_a_client_outside_the_callers_subnets_is_the_same_empty_answer_and_nothing_is_computed(
        self, client, db, inbox, monkeypatch
    ):
        from tests.conftest import restricted_client

        calls = self._stub(monkeypatch)
        restricted_client(client, db, allowed_subnets=[2], role="viewer", username="_problems_b_only")
        body = client.get(f"/problems/answer?q={MAC_A}").data.decode()
        assert "no answer" in body.lower() and "would offer" not in body and calls == []

    def test_an_unknown_identifier_and_an_empty_one_are_the_same_empty_answer(
        self, logged_in_client, inbox, monkeypatch
    ):
        calls = self._stub(monkeypatch)
        assert "no answer" in logged_in_client.get("/problems/answer?q=aa:bb:cc:dd:ee:99").data.decode().lower()
        assert "no answer" in logged_in_client.get("/problems/answer").data.decode().lower()
        assert calls == []

    def test_a_failing_overview_line_is_the_empty_answer(self, logged_in_client, inbox, monkeypatch):
        self._stub(monkeypatch, line="")
        assert "no answer" in logged_in_client.get(f"/problems/answer?q={MAC_A}").data.decode().lower()


class TestTheDashboardWidget:
    def test_it_counts_clients_by_kind_in_the_last_hour_and_lists_the_five_most_recent(self, inbox):
        out = dc.problems_widget([1, 2], True)
        assert (
            out["hours"] == 1
            and out["total"] == 4
            and out["counts"] == {"NAK": 2, "Declined an address": 1, "Packet dropped": 1, "Declined lease": 1}
        )
        assert [t["who"] for t in out["top"]] == [MAC_A, MAC_X, MAC_B, "10.46.0.9"]
        assert out["top"][0]["count"] == 5 and out["top"][0]["kinds"] == ["Declined an address", "NAK"]

    def test_a_row_older_than_an_hour_is_not_counted(self, inbox):
        assert MAC_OLD not in [t["who"] for t in dc.problems_widget([1, 2], True)["top"]]

    def test_a_restricted_caller_gets_only_their_subnets_and_never_the_unattributed_row(self, inbox):
        out = dc.problems_widget([1], False)
        assert [t["who"] for t in out["top"]] == [MAC_A] and out["total"] == 1

    def test_a_caller_with_no_subnets_gets_an_empty_widget(self, inbox):
        assert dc.problems_widget([], False) == {"hours": 1, "total": 0, "counts": {}, "top": []}

    def test_nothing_in_the_inbox_is_an_empty_widget_not_a_failure(self, db, inbox):
        with db.cursor() as cur:
            cur.execute("DELETE FROM client_problems")
        db.commit()
        assert dc.problems_widget([1], True)["total"] == 0

    def test_it_is_served_by_the_catalog_route_with_the_callers_scope(self, logged_in_client, inbox):
        r = logged_in_client.get("/api/dashboard/catalog-data?widgets=problems")
        assert r.status_code == 200 and r.get_json()["problems"]["total"] == 4

    def test_a_scoped_user_is_served_only_their_rows(self, client, db, inbox):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_problems_widget")
        out = client.get("/api/dashboard/catalog-data?widgets=problems").get_json()["problems"]
        assert out["total"] == 1 and [t["who"] for t in out["top"]] == [MAC_A]

    def test_it_is_a_picker_widget_and_the_page_has_its_slot_and_loader(self, logged_in_client):
        from jen.services import dashboard_prefs as dp

        assert dp.WIDGET_CATALOG["problems"]["label"] == "Clients with problems"
        html = logged_in_client.get("/").data.decode()
        assert 'id="w-problems"' in html and 'id="dash-problems"' in html and "problems: loadProblems" in html
