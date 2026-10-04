"""
tests/test_investigate_links.py
────────────────────────────────
v5.68.0-beta.1 (Q134 a, d) — the Investigation page (`/client`) is the front door, so every row that names a client
carries the same "Investigate" action, from ONE macro (templates/_investigate.html) the next page cannot forget:

* a scan of every core template that prints a MAC (it must import the macro, or be a page that is itself part of the
  investigation, with the reason written down);
* the macro and the pure text rule behind the Alerts log and the dashboard's alert strip;
* route tests against real subnets — a subnet-restricted admin never gets an Investigate link for a client outside
  their subnets (the pages' own queries already filter the rows; these prove the new links add no way round that);
* the search box: one whole MAC or IPv4 address goes straight to /client, anything else still searches;
* the alert strip on /client is judged on the CLIENT (docs/ARCHITECTURE.md §2).

The first three groups are pure and run without a database (`pytest --noconftest -k "not Route"`).
"""

import pathlib
import re
from urllib.parse import quote, unquote

import pytest

from jen import extensions
from jen.services.client_subject import identifier_in_text

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_TEMPLATES = _ROOT / "templates"

_PRINTS_A_MAC = re.compile(r"\{\{[^}]*\b[A-Za-z_]+\.mac\b")

# Core templates that print a MAC and are NOT a row naming a client to investigate — each with its reason.
_NOT_A_ROW = {
    "client.html": "the Investigation page itself",
    "setup_investigate.html": "the first-hour wizard's own step: its button records the step, then opens /client",
    "explain.html": "the Explain tool's own page for ONE client — a tab of the Investigation page, one click from it",
    "_explain_result.html": "the Explain result for ONE client, embedded in the Investigation page's Explain tab",
    "add_reservation.html": "a form: the MAC is an input being typed, not a row",
    "edit_reservation.html": "a form editing ONE reservation: the MAC is the field being edited",
}


class TestEveryRowThatNamesAClientCarriesTheLink:
    def test_every_template_that_prints_a_mac_imports_the_macro_or_says_why_not(self):
        missing = []
        for path in sorted(_TEMPLATES.glob("*.html")):
            text = path.read_text(encoding="utf-8")
            if not _PRINTS_A_MAC.search(text) or path.name in _NOT_A_ROW:
                continue
            if "import investigate_link" not in text:
                missing.append(path.name)
        assert not missing, (
            f"{missing} print a MAC but do not import templates/_investigate.html's investigate_link — add the link "
            "(one macro, so the next page cannot forget it), or add the template to _NOT_A_ROW with its reason"
        )

    def test_the_list_of_exceptions_has_no_stale_entries(self):
        for name in _NOT_A_ROW:
            path = _TEMPLATES / name
            assert path.is_file(), f"{name} is on the not-a-row list but no longer exists"
            assert _PRINTS_A_MAC.search(path.read_text(encoding="utf-8")), (
                f"{name} no longer prints a MAC — drop it from _NOT_A_ROW"
            )

    def test_no_template_hand_writes_the_link_the_macro_is_for(self):
        """A hand-written `<a href="/client?q=`` is the copy that drifts (a changed class, a forgotten label)."""
        allowed = {
            "_investigate.html",
            "client.html",
            "dashboard.html",
        }  # the macro; the page's own tab strip; the JS twin
        offenders = [
            p.name
            for p in sorted(_TEMPLATES.glob("*.html"))
            if p.name not in allowed and 'href="/client?q=' in p.read_text(encoding="utf-8")
        ]
        assert not offenders, f"{offenders} write the Investigate link by hand — use investigate_link()"

    def test_the_three_javascript_widgets_carry_it_too(self):
        text = (_TEMPLATES / "dashboard.html").read_text(encoding="utf-8")
        assert "function investigateLink(who)" in text
        for call in ("investigateLink(a.client)", "investigateLink(r.mac || r.ip)", "investigateLink(d.mac)"):
            assert call in text, f"the dashboard no longer calls {call}"
        # the link's value is URL-encoded and its title escaped, whatever the server sent
        assert "encodeURIComponent(who)" in text and "escapeHtml(who)" in text

    @pytest.mark.parametrize(
        "name",
        [
            "_lease_rows.html",
            "_reservation_row.html",
            "_device_rows.html",
            "_recent_leases.html",
            "_recent_leases_rows.html",
        ],
    )
    def test_the_row_partials_import_the_macro(self, name):
        assert "import investigate_link" in (_TEMPLATES / name).read_text(encoding="utf-8")


@pytest.fixture
def macro_env():
    from jinja2 import Environment, FileSystemLoader

    from jen.services.icons import icon

    env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True)
    env.globals["icon"] = icon
    return env


class TestTheMacro:
    def _render(self, env, call):
        return env.from_string("{% from '_investigate.html' import investigate_link %}" + call).render().strip()

    def test_the_three_kinds(self, macro_env):
        menu = self._render(macro_env, "{{ investigate_link('aa:bb:cc:dd:ee:ff') }}")
        assert menu.startswith('<a href="/client?q=aa%3Abb%3Acc%3Add%3Aee%3Aff" class="action-menu-item">')
        assert "Investigate</a>" in menu
        button = self._render(macro_env, "{{ investigate_link('10.0.0.5', 'button') }}")
        assert 'class="btn btn-sm btn-secondary"' in button and "Investigate</a>" in button
        icon_only = self._render(macro_env, "{{ investigate_link('10.0.0.5', 'icon') }}")
        assert 'title="Investigate 10.0.0.5"' in icon_only and 'aria-label="Investigate"' in icon_only

    def test_nothing_is_rendered_without_an_identifier(self, macro_env):
        for who in ("''", "none", "undefined"):
            assert self._render(macro_env, "{{ investigate_link(" + who + ") }}") == ""

    def test_the_identifier_is_encoded_and_escaped(self, macro_env):
        out = self._render(macro_env, "{{ investigate_link('x\"><script>alert(1)</script>', 'icon') }}")
        assert "<script>" not in out
        assert "%3Cscript%3E" in out

    def test_an_ipv6_address_and_a_duid_survive_the_url(self, macro_env):
        assert "q=2001%3Adb8%3A%3A10" in self._render(macro_env, "{{ investigate_link('2001:db8::10') }}")
        assert "q=duid%3A00030001" in self._render(macro_env, "{{ investigate_link('duid:00030001') }}")


class TestIdentifierInText:
    """The Alerts log and the alert strip read the client out of the message an alert rendered."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("IP: 10.0.0.5\nMAC: AA:BB:CC:DD:EE:FF\nHostname: x", "aa:bb:cc:dd:ee:ff"),
            ("new device aa-bb-cc-dd-ee-ff at 10.0.0.5", "aa:bb:cc:dd:ee:ff"),
            ("lease for 10.0.0.5 (printer) on Subnet1", "10.0.0.5"),
            ("Kea at 10.0.0.5. is down", "10.0.0.5"),
            ("10.0.0.50 and 10.0.0.5", "10.0.0.50"),
            ("subnet 10.0.0.0/24 is 91% full", ""),
            ("version 1.2.3.4.5 released", ""),
            ("999.1.1.1 is not an address", ""),
            ("mac aa:bb:cc:dd:ee is short", ""),
            ("aa:bb:cc:dd:ee:ff:00 is longer than a MAC", ""),
            ("mixed aa:bb-cc:dd-ee:ff separators", ""),
            ("", ""),
            (None, ""),
        ],
    )
    def test_the_first_client_the_text_names(self, text, expected):
        assert identifier_in_text(text) == expected

    def test_a_mac_wins_over_an_address(self):
        assert identifier_in_text("10.0.0.5 aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"


class TestTheSearchBoxRule:
    def test_only_a_whole_mac_or_ipv4_address_goes_to_the_client_page(self):
        from jen.routes import search

        assert frozenset({"mac", "ipv4"}) == search._GOES_TO_CLIENT_PAGE


# ── Route tests (need the unit suite's database) ────────────────────────────────

A_MAC, A_HEX, A_IP = "de:ad:be:ef:11:aa", "DEADBEEF11AA", "10.98.1.10"
B_MAC, B_HEX, B_IP = "de:ad:be:ef:11:bb", "DEADBEEF11BB", "10.77.0.77"


def _href(who):
    """The href the macro writes (Jinja's urlencode: everything but `/` is percent-encoded)."""
    return f'href="/client?q={quote(who, safe="/")}"'


@pytest.fixture
def two_clients(db, monkeypatch):
    """One client in subnet 1 (A) and one in subnet 2 (B), each with a lease and a device row."""
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Alpha-A", "cidr": "10.98.1.0/24"}, 2: {"name": "Bravo-B", "cidr": "10.77.0.0/24"}},
    )
    _remove(db)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
            "(INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'alpha-host'), "
            "(INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 2, 0, 'bravo-host')",
            (A_IP, A_HEX, B_IP, B_HEX),
        )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) "
            "VALUES (%s, %s, 'alpha-host', 1, 'Alpha device', NOW(), NOW()), "
            "(%s, %s, 'bravo-host', 2, 'Bravo device', NOW(), NOW())",
            (A_MAC, A_IP, B_MAC, B_IP),
        )
    db.commit()
    yield
    _remove(db)


def _remove(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s)", (A_HEX, B_HEX))
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (A_MAC, B_MAC))
    db.commit()


def _restricted_admin(client, db, name):
    from tests.conftest import restricted_client

    restricted_client(client, db, allowed_subnets=[1], role="admin", username=name)
    return client


class TestRouteRecentLeasesWidget:
    def test_an_unrestricted_caller_gets_a_link_for_every_row(self, logged_in_client, two_clients):
        body = logged_in_client.get("/api/recent-leases?hours=1").data.decode()
        # the widget prints Kea's own HEX() of the address, upper case; the Investigation page accepts either
        assert _href(A_MAC.upper()) in body and _href(B_MAC.upper()) in body

    def test_a_restricted_admin_gets_a_link_only_for_a_client_in_their_subnets(self, client, db, two_clients):
        c = _restricted_admin(client, db, "_inv_recent")
        body = c.get("/api/recent-leases?hours=1").data.decode()
        assert _href(A_MAC.upper()) in body
        assert B_MAC.upper() not in body.upper() and B_IP not in body


class TestRouteTimelineHeader:
    def test_the_timeline_page_links_to_the_investigation_of_its_subject(self, logged_in_client, two_clients):
        body = logged_in_client.get(f"/timeline?mac={A_MAC}").data.decode()
        assert _href(A_MAC) in body

    def test_a_restricted_admin_gets_no_link_for_a_client_they_may_not_see(self, client, db, two_clients):
        c = _restricted_admin(client, db, "_inv_timeline")
        body = c.get(f"/timeline?mac={B_MAC}").data.decode()
        assert _href(B_MAC) not in body and "Bravo" not in body


class TestRouteAlertLinks:
    @pytest.fixture
    def alert(self, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status) VALUES ('telegram', 'new_lease', %s, 'ok')",
                (f"IP: {A_IP}\nMAC: {A_MAC}\nHostname: alpha-host",),
            )
        db.commit()

    def test_the_strip_names_the_client_to_an_unrestricted_caller_only(self, logged_in_client, client, db, alert):
        rows = logged_in_client.get("/api/alert-summary").get_json()["alerts"]
        assert rows[0]["client"] == A_MAC
        c = _restricted_admin(client, db, "_inv_strip")
        scoped = c.get("/api/alert-summary").get_json()["alerts"]
        assert scoped[0]["client"] == "" and scoped[0]["message"] == ""

    def test_the_alerts_log_links_the_client_for_an_unrestricted_caller_only(self, logged_in_client, client, db, alert):
        assert _href(A_MAC) in logged_in_client.get("/settings/logs?tab=alerts").data.decode()
        c = _restricted_admin(client, db, "_inv_log")
        r = c.get("/settings/logs?tab=alerts")
        assert r.status_code in (200, 302, 403)
        assert _href(A_MAC) not in r.data.decode()


class TestRouteSearchGoesStraightToTheClient:
    @pytest.mark.parametrize("typed", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "10.0.0.5"])
    def test_one_whole_identifier_redirects(self, logged_in_client, typed):
        r = logged_in_client.get("/search", query_string={"q": typed})
        assert r.status_code == 302
        location = unquote(r.headers["Location"])
        assert "/client" in location and f"q={typed}" in location

    @pytest.mark.parametrize("typed", ["printer-1", "aa:bb:cc", "10.0.0", "10.0", "findme"])
    def test_anything_else_still_searches(self, logged_in_client, typed):
        assert logged_in_client.get("/search", query_string={"q": typed}).status_code == 200

    def test_list_1_is_the_way_back_to_the_results_page(self, logged_in_client):
        r = logged_in_client.get("/search", query_string={"q": "aa:bb:cc:dd:ee:ff", "list": "1"})
        assert r.status_code == 200 and b"Search Results" in r.data

    def test_the_client_page_links_back_to_the_list(self, logged_in_client, two_clients):
        body = logged_in_client.get(f"/client?q={A_MAC}").data.decode()
        assert "list=1" in body and "Search results for this" in body

    def test_a_restricted_caller_is_redirected_too_and_the_client_page_does_the_judging(self, client, db, two_clients):
        c = _restricted_admin(client, db, "_inv_search")
        assert c.get("/search", query_string={"q": B_MAC}).status_code == 302
        page = c.get("/client", query_string={"q": B_MAC}).data.decode()
        assert "No client matched" in page and B_IP not in page


class TestRouteTheClientPageAlertStrip:
    """docs/ARCHITECTURE.md §2 (Q134 d): alert_log rows carry no subnet, so the strip is judged on the CLIENT —
    unrestricted callers always, a restricted one when the view names a subnet they may see — and shows type,
    status and time, never the message."""

    SENTINEL = "SENTINEL-ALERT-MESSAGE-TEXT"

    @pytest.fixture
    def alerts(self, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status) VALUES "
                "('telegram', 'stale_reservation', %s, 'ok'), ('telegram', 'new_device', %s, 'ok')",
                (f"{self.SENTINEL} {A_MAC} {A_IP} moved from Bravo-B", f"{self.SENTINEL} {B_MAC} {B_IP} Bravo-B"),
            )
        db.commit()

    def test_an_unrestricted_caller_sees_the_alert_for_either_client(self, logged_in_client, two_clients, alerts):
        for mac, kind in ((A_MAC, "stale_reservation"), (B_MAC, "new_device")):
            body = logged_in_client.get(f"/client?q={mac}").data.decode()
            assert "Last alert" in body and kind in body
            assert self.SENTINEL not in body

    def test_a_restricted_admin_sees_the_alert_about_their_own_client(self, client, db, two_clients, alerts):
        c = _restricted_admin(client, db, "_inv_alert_own")
        body = c.get(f"/client?q={A_MAC}").data.decode()
        assert "Last alert" in body and "stale_reservation" in body
        assert self.SENTINEL not in body and "Bravo-B" not in body

    def test_a_restricted_admin_sees_nothing_of_the_alert_about_a_client_in_another_subnet(
        self, client, db, two_clients, alerts
    ):
        c = _restricted_admin(client, db, "_inv_alert_other")
        body = c.get(f"/client?q={B_MAC}").data.decode()
        assert "Last alert" not in body and "new_device" not in body
        assert "No client matched" in body

    def test_a_restricted_viewer_is_judged_the_same_way(self, client, db, two_clients, alerts):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_inv_alert_viewer")
        assert "Last alert" in client.get(f"/client?q={A_MAC}").data.decode()
