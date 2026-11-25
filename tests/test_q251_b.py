"""
tests/test_q251_b.py
────────────────────
Q251, what an account is shown about reservations, and three links: the rows of the executing pass on v7.2.0-beta.8.

* Investigate's hostname search keeps a `hosts` row with no IPv4 subnet (an IPv6 reservation) for an account that sees every subnet only: a restricted
  account is not told "More than one client uses that hostname" about it.
* "View reservation" for a client whose only reservation is Kea's global one opens its Investigate page, which shows it; the Reservations list does not.
* The Doctor's duplicate check compares IPv4 reservations: a row with no IPv4 subnet is not one.
* The Devices row menu offers "Create reservation" to an admin only.
* A single sign-on account's Subnet Access is the identity provider's: not offered in the dialog, kept by the server, refused by the subnets-only route.
* The Reserved mark and the Reserved filter ask one set of subnets: the account's stored list.
* The stale-reservation alert reads IPv4 reservations.
* Bulk release refuses what its checkbox disables: a client with any reservation the account counts.
* The Doctor hands an admin no link to the Kea logging card, which Settings - Kea draws for a superadmin only.
"""

import html as htmllib
import json
import pathlib
import re
from datetime import datetime

import pytest

from jen.services import alerts
from jen.services import config_doctor as doctor

ROOT = pathlib.Path(__file__).resolve().parent.parent

MAC_A = "AABBCC251B01"
MAC_B = "AABBCC251B02"
SHARED = "q251b-shared-name"
LEASE = "q251b-lease"
RES_NAME = "q251b-reserved-name"
SENTENCE = (
    "Set by the identity provider at every sign-in (Subnet Mapping under Settings → Access & Security → Single Sign-On), "
    "so it is not edited here."
)
HEADING = "More than one client uses that hostname"


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")


def _colon(hexed):
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).lower()


def _as(client, db, role, subnets, username):
    """Sign the test client in as a new account. `subnets` None is every subnet (the column is NULL), a list is the account's own."""
    from tests.conftest import restricted_client

    _c, uid = restricted_client(client, db, subnets, role=role, username=username)
    if subnets is None:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET subnet_access=NULL WHERE id=%s", (uid,))
        db.commit()
    return uid


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE hostname LIKE 'q251b-%%'")
        cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q251b-%%'")
        cur.execute("DELETE FROM devices WHERE last_hostname LIKE 'q251b-%%'")
        cur.execute("DELETE FROM users WHERE username LIKE 'q251b%%'")
    db.commit()


@pytest.fixture(autouse=True)
def _own_rows(request):
    """Every test that touches the database starts and ends without this file's rows. A test that asks for no database (the pure ones, which run with
    `--noconftest`) is left alone."""
    if not {"db", "client", "logged_in_client"} & set(request.fixturenames):
        yield
        return
    db = request.getfixturevalue("db")
    _clean(db)
    yield
    _clean(db)


def _lease(db, mac, ip, hostname, subnet=1):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) VALUES "
            "(INET_ATON(%s), UNHEX(%s), 3600, NOW() + INTERVAL 2 HOUR, %s, %s, 0)",
            (ip, mac, subnet, hostname),
        )
    db.commit()


def _host(db, mac, subnet, hostname, ip="10.99.0.171"):
    """One `hosts` row by hardware address. `subnet` None is an IPv6 reservation (no IPv4 subnet id), 0 is Kea's global IPv4 one."""
    with db.cursor() as cur:
        if subnet is None:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, dhcp6_subnet_id, hostname) "
                "VALUES (UNHEX(%s), 0, NULL, 10, %s)",
                (mac, hostname),
            )
        else:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (mac, subnet, ip, hostname),
            )
    db.commit()


def _lease_row(page):
    for tr in re.findall(r"<tr\b.*?</tr>", page, re.S):
        if LEASE in tr:
            return tr
    return None


# ── row 1 (BK1): the hostname search and a row with no IPv4 subnet ───────────


@pytest.fixture
def shared_name(db):
    """Client A holds a lease in subnet 1 under a name; `second(subnet)` gives ANOTHER client, B, a `hosts` row of the same name: None is an IPv6
    reservation, 2 a subnet a one-subnet account may not see, 0 Kea's global IPv4 reservation."""
    _lease(db, MAC_A, "10.99.0.161", SHARED)

    def second(subnet):
        _host(db, MAC_B, subnet, SHARED, ip="10.99.1.162" if subnet == 2 else "10.99.0.162")

    return second


def _search(client):
    r = client.get(f"/client?q={SHARED}")
    assert r.status_code == 200
    return r.get_data(as_text=True)


class TestTheHostnameSearchKeepsAnIpv6RowForNobodyRestricted:
    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_an_ipv6_reservation_of_the_same_name_is_not_a_second_client_to_a_one_subnet_account(
        self, client, db, shared_name, role
    ):
        shared_name(None)
        _as(client, db, role, [1], f"q251b_v6_{role}")
        page = _search(client)
        assert HEADING not in page
        assert _colon(MAC_B) not in page.lower()
        assert _colon(MAC_A) in page.lower(), "the page is client A's own"

    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_a_reservation_in_a_hidden_subnet_is_not_one_either(self, client, db, shared_name, role):
        """As on v7.2.0-beta.8."""
        shared_name(2)
        _as(client, db, role, [1], f"q251b_hid_{role}")
        page = _search(client)
        assert HEADING not in page and _colon(MAC_B) not in page.lower() and _colon(MAC_A) in page.lower()

    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_a_global_reservation_of_the_same_name_is_everyones(self, client, db, shared_name, role):
        """As on v7.2.0-beta.8: subnet 0 belongs to no subnet an account can be scoped out of."""
        shared_name(0)
        _as(client, db, role, [1], f"q251b_glb_{role}")
        page = _search(client)
        assert HEADING in page and _colon(MAC_A) in page.lower() and _colon(MAC_B) in page.lower()

    @pytest.mark.parametrize("subnet", [None, 2, 0])
    @pytest.mark.parametrize("who", ["superadmin", "admin"])
    def test_an_account_with_every_subnet_is_answered_as_before(
        self, client, logged_in_client, db, shared_name, who, subnet
    ):
        """As on v7.2.0-beta.8: nothing is judged for an account that sees every subnet."""
        shared_name(subnet)
        if who == "admin":
            _as(client, db, "admin", None, "q251b_every")
        page = _search(logged_in_client if who == "superadmin" else client)
        assert HEADING in page and _colon(MAC_A) in page.lower() and _colon(MAC_B) in page.lower()

    @pytest.mark.parametrize("subnet", [None, 2])
    def test_an_admin_with_no_subnets_is_shown_nothing_of_the_second_client(self, client, db, shared_name, subnet):
        """As on v7.2.0-beta.8."""
        shared_name(subnet)
        _as(client, db, "admin", [], "q251b_none")
        page = _search(client)
        assert HEADING not in page and _colon(MAC_B) not in page.lower() and _colon(MAC_A) not in page.lower()

    def test_the_lookup_itself(self, db, shared_name):
        from jen.services import client_subject as subject

        shared_name(None)
        assert subject.macs_for_hostname(SHARED, {1}) == {_colon(MAC_A)}
        assert subject.macs_for_hostname(SHARED, set()) == set()
        assert subject.macs_for_hostname(SHARED, None) == {_colon(MAC_A), _colon(MAC_B)}


# ── row 2 (BK6): "View reservation" for a global reservation ─────────────────


def _view_item(tr):
    m = re.search(r'<a href="([^"]*)"[^>]*>(?:(?!</a>).)*View reservation([^<]*)</a>', tr, re.S)
    assert m, tr
    return htmllib.unescape(m.group(1)), m.group(2).strip()


class TestViewReservationOpensAPageThatShowsIt:
    @pytest.mark.parametrize("who", ["superadmin", "admin_every", "admin_one"])
    def test_a_global_reservation_opens_the_clients_investigate_page(self, client, logged_in_client, db, who):
        _lease(db, MAC_A, "10.99.0.163", LEASE)
        _host(db, MAC_A, 0, RES_NAME, ip="10.99.0.163")
        c = logged_in_client if who == "superadmin" else client
        if who != "superadmin":
            _as(client, db, "admin", None if who == "admin_every" else [1], f"q251b_{who}")
        tr = _lease_row(c.get("/leases").get_data(as_text=True))
        href, tail = _view_item(tr)
        assert tail == "(global)"
        assert href == "/client?q=" + _colon(MAC_A).upper().replace(":", "%3A"), (
            "the address the Investigate macro writes for this row"
        )
        assert "/reservations?search=" not in tr
        r = c.get(href)
        assert r.status_code == 200 and RES_NAME in r.get_data(as_text=True), (
            "the page the item opens shows the reservation"
        )

    @pytest.mark.parametrize("who", ["superadmin", "admin_one"])
    def test_a_reservation_in_a_subnet_opens_the_list_with_its_row(self, client, logged_in_client, db, who):
        _lease(db, MAC_A, "10.99.0.163", LEASE)
        _host(db, MAC_A, 1, RES_NAME, ip="10.99.0.163")
        c = logged_in_client if who == "superadmin" else client
        if who != "superadmin":
            _as(client, db, "admin", [1], f"q251b_{who}")
        tr = _lease_row(c.get("/leases").get_data(as_text=True))
        href, tail = _view_item(tr)
        assert tail == "" and href == f"/reservations?search={_colon(MAC_A).upper()}"
        listed = c.get(href).get_data(as_text=True)
        assert (
            listed.count(RES_NAME) >= 1 and len(re.findall(r"<tr\b[^>]*>(?:(?!</tr>).)*" + RES_NAME, listed, re.S)) == 1
        )

    def test_a_client_reserved_in_a_subnet_and_globally_opens_the_list(self, logged_in_client, db):
        _lease(db, MAC_A, "10.99.0.163", LEASE)
        _host(db, MAC_A, 0, RES_NAME, ip="10.99.0.164")
        _host(db, MAC_A, 1, RES_NAME, ip="10.99.0.163")
        href, tail = _view_item(_lease_row(logged_in_client.get("/leases").get_data(as_text=True)))
        assert tail == "" and href.startswith("/reservations?search=")

    def test_the_address_is_the_macros(self):
        macro = _src("templates/_investigate.html")
        link = re.search(r'<a href="([^"]*)" class="action-menu-item"', macro).group(1)
        assert link == "/client?q={{ who|urlencode }}"
        assert "{% macro investigate_href(who) -%}\n" + link + "\n{%- endmacro %}" in macro
        assert '<a href="{{ investigate_href(l.mac) }}"' in _src("templates/_lease_rows.html")


# ── row 3 (BK7): the Doctor's duplicate check ────────────────────────────────


def _dup(hosts):
    return [f["id"] for f in doctor._check_duplicate_reservations({}, hosts)]


class TestTheDuplicateCheckComparesIpv4Reservations:
    DUID = "00010001AABBCCDD"

    def test_two_rows_with_no_ipv4_subnet_are_no_finding(self):
        rows = [{"subnet_id": None, "identifier_type": 1, "identifier": self.DUID, "ip": None} for _ in range(2)]
        assert _dup(rows) == []

    def test_two_rows_with_no_ipv4_subnet_and_one_address_are_no_finding(self):
        rows = [{"subnet_id": None, "identifier_type": 1, "identifier": self.DUID, "ip": "0.0.0.0"} for _ in range(2)]
        assert _dup(rows) == []

    def test_two_rows_in_one_subnet_are_the_finding_as_before(self):
        rows = [{"subnet_id": 5, "identifier_type": 0, "identifier": "AABBCC251B01", "ip": None} for _ in range(2)]
        found = doctor._check_duplicate_reservations({}, rows)
        assert [f["id"] for f in found] == ["duplicate_reservation_identifier"]
        assert found[0]["detail"] == "2 reservations in subnet 5 share identifier aabbcc251b01"

    def test_two_global_rows_are_compared_among_themselves(self):
        rows = [{"subnet_id": 0, "identifier_type": 0, "identifier": "AABBCC251B01", "ip": None} for _ in range(2)]
        assert _dup(rows) == ["duplicate_reservation_identifier"]

    def test_one_row_with_no_ipv4_subnet_and_one_in_a_subnet_are_no_finding(self):
        rows = [
            {"subnet_id": None, "identifier_type": 0, "identifier": "AABBCC251B01", "ip": None},
            {"subnet_id": 5, "identifier_type": 0, "identifier": "AABBCC251B01", "ip": None},
        ]
        assert _dup(rows) == []


# ── row 4 (BK10): the Devices row menu ───────────────────────────────────────


@pytest.fixture
def device(db):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) VALUES (%s, '10.99.0.165', %s, 1, NOW(), NOW())",
            (_colon(MAC_A), LEASE),
        )
    db.commit()


class TestTheDevicesMenuOffersCreateToAnAdminOnly:
    @pytest.mark.parametrize("subnets", [None, [1]])
    def test_a_viewer_is_offered_no_create_reservation(self, client, db, device, subnets):
        _as(client, db, "viewer", subnets, "q251b_viewer")
        page = client.get("/devices").get_data(as_text=True)
        assert LEASE in page, "the device is shown"
        assert "/reservations/add" not in page and "Create reservation" not in page

    @pytest.mark.parametrize("subnets", [None, [1]])
    def test_an_admin_is(self, client, db, device, subnets):
        _as(client, db, "admin", subnets, "q251b_admin")
        page = client.get("/devices").get_data(as_text=True)
        assert LEASE in page and "/reservations/add?mac=" in page

    def test_a_superadmin_is(self, logged_in_client, device):
        assert "/reservations/add?mac=" in logged_in_client.get("/devices").get_data(as_text=True)

    def test_reservation_exists_stays_for_a_viewer(self, client, db, device):
        _host(db, MAC_A, 1, RES_NAME, ip="10.99.0.165")
        _as(client, db, "viewer", [1], "q251b_viewer")
        page = client.get("/devices").get_data(as_text=True)
        assert "Reservation exists" in page and "/reservations/add" not in page


# ── row 5 (BK11): a single sign-on account's Subnet Access ───────────────────


def _make_user(db, username, role, subnet_access, provider="local"):
    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access, must_change_password, auth_provider) VALUES (%s, %s, %s, %s, 0, %s)",
            (username, hash_password("Q251b-x-Pass!1"), role, subnet_access, provider),
        )
        uid = cur.lastrowid
    db.commit()
    return uid


def _stored(db, uid):
    db.commit()  # a fresh read of what the route committed
    with db.cursor() as cur:
        cur.execute("SELECT role, subnet_access, session_timeout FROM users WHERE id=%s", (uid,))
        row = cur.fetchone()
    scope = row["subnet_access"]
    return row["role"], (json.loads(scope) if scope is not None else None), row["session_timeout"]


class TestASingleSignOnAccountsSubnetsAreTheIdentityProviders:
    def test_posted_subnets_do_not_replace_the_stored_ones_and_the_timeout_is_saved(self, logged_in_client, db):
        uid = _make_user(db, "q251b_oidc", "admin", "[1]", provider="oidc")
        r = logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "subnet_ids": "2"})
        assert r.status_code == 302
        assert _stored(db, uid) == ("admin", [1], 30)

    @pytest.mark.parametrize("posted", [{"subnet_ids": "all"}, {"subnet_ids": "1"}, {}, {"subnet_ids": "not-a-number"}])
    def test_whatever_is_posted(self, logged_in_client, db, posted):
        uid = _make_user(db, "q251b_oidc", "viewer", "[1]", provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "40", **posted})
        assert _stored(db, uid) == ("viewer", [1], 40)

    def test_a_stored_null_stays_null(self, logged_in_client, db):
        uid = _make_user(db, "q251b_oidc_all", "admin", None, provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "subnet_ids": "1"})
        assert _stored(db, uid) == ("admin", None, 30)

    def test_a_stored_empty_list_stays_empty(self, logged_in_client, db):
        uid = _make_user(db, "q251b_oidc_none", "admin", "[]", provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "subnet_ids": "1"})
        assert _stored(db, uid) == ("admin", [], 30)

    def test_a_local_account_stores_what_was_posted(self, logged_in_client, db):
        uid = _make_user(db, "q251b_local", "admin", "[1]")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "role": "admin", "subnet_ids": "all"})
        assert _stored(db, uid) == ("admin", None, 30)

    def test_the_subnets_only_route_refuses_with_the_sentence_and_changes_nothing(self, logged_in_client, db):
        uid = _make_user(db, "q251b_oidc", "admin", "[1]", provider="oidc")
        r = logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": "all"}, follow_redirects=True)
        assert htmllib.escape(SENTENCE, quote=False) in r.get_data(as_text=True)
        assert _stored(db, uid) == ("admin", [1], None)

    def test_the_subnets_only_route_still_serves_a_local_account(self, logged_in_client, db):
        uid = _make_user(db, "q251b_local", "admin", "[1]")
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": "all"})
        assert _stored(db, uid) == ("admin", None, None)

    def test_the_page_holds_the_sentence_and_tells_the_dialog_which_account_is_single_sign_on(
        self, logged_in_client, db
    ):
        _make_user(db, "q251b_oidc", "admin", "[1]", provider="oidc")
        _make_user(db, "q251b_local", "admin", "[1]")
        page = logged_in_client.get("/settings/users").get_data(as_text=True)
        hint = re.search(r'<div class="form-hint warn" id="edit-subnet-oidc-hint" hidden>(.*?)</div>', page, re.S)
        assert hint and htmllib.unescape(hint.group(1)) == SENTENCE
        flags = {}
        for raw in re.findall(r"data-user='([^']*)'", page):
            u = json.loads(htmllib.unescape(raw))
            flags[u["username"]] = u["is_oidc"]
        assert flags["q251b_oidc"] is True and flags["q251b_local"] is False

    def test_the_dialog_offers_no_box_for_one(self):
        """The browser's half is tests/e2e/test_q251_b.py; this is the wiring it runs."""
        page = _src("templates/users.html")
        body = page.split("function showSsoSubnets(isOidc) {", 1)[1].split("\n}\n", 1)[0]
        assert "document.getElementById('f-edit-subnet_ids').hidden = isOidc;" in body
        assert "document.getElementById('edit-subnet-oidc-hint').hidden = !isOidc;" in body
        assert "box.disabled = isOidc;" in body
        assert "showSsoSubnets(!!u.is_oidc);" in page.split("function openEditModal(u, opener) {", 1)[1]

    def test_the_words_are_the_settings_pages_own(self):
        from jen.routes import users

        assert users.SSO_SUBNETS_SENTENCE == SENTENCE
        security = _src("templates/settings_security.html")
        assert '<label for="oidc-subnet-map">Subnet Mapping ' in security
        assert "Access &amp; Security</h1>" in security and "Single Sign-On (OIDC)</span>" in security


# ── row 6 (BK12): the mark and the filter ask one set of subnets ─────────────


def _reserved_count(page):
    summary = re.search(r'id="leases-summary">(.*?)</p>', page, re.S).group(1)
    m = re.search(r">\s*(\d+) reserved", summary)
    return int(m.group(1)) if m else 0


class TestTheReservedMarkAndFilterAskTheStoredList:
    def test_a_reservation_in_a_stored_subnet_jens_map_does_not_name(self, client, db):
        from jen import extensions

        assert 7 not in extensions.SUBNET_MAP and 1 in extensions.SUBNET_MAP
        _lease(db, MAC_A, "10.99.0.166", LEASE)
        _host(db, MAC_A, 7, RES_NAME, ip="10.99.7.166")
        _as(client, db, "admin", [1, 7], "q251b_two")
        page = client.get("/leases").get_data(as_text=True)
        assert "badge-reserved" in _lease_row(page), "the row's mark"
        assert _reserved_count(page) == 1
        assert _lease_row(client.get("/leases?reserved=1").get_data(as_text=True)) is not None, (
            "the filter lists the row its count counted"
        )

    def test_a_reservation_in_a_subnet_the_account_does_not_store_is_still_none(self, client, db):
        _lease(db, MAC_A, "10.99.0.166", LEASE)
        _host(db, MAC_A, 2, RES_NAME, ip="10.99.1.166")
        _as(client, db, "admin", [1, 7], "q251b_two")
        page = client.get("/leases").get_data(as_text=True)
        assert "badge-reserved" not in _lease_row(page) and _reserved_count(page) == 0
        assert _lease_row(client.get("/leases?reserved=1").get_data(as_text=True)) is None

    def test_an_account_with_every_subnet_is_unchanged(self, logged_in_client, db):
        _lease(db, MAC_A, "10.99.0.166", LEASE)
        _host(db, MAC_A, 7, RES_NAME, ip="10.99.7.166")
        assert _lease_row(logged_in_client.get("/leases?reserved=1").get_data(as_text=True)) is not None

    def test_the_parameter_is_the_stored_list(self):
        from jen.models.user import User
        from jen.routes import leases

        assert leases._stored_subnet_ids(User(5, "u", "admin", subnet_access=[1, 7])) == "1,7"
        assert leases._stored_subnet_ids(User(5, "u", "admin", subnet_access=[])) == ""
        assert leases._stored_subnet_ids(User(5, "u", "admin", subnet_access=[1, "x"])) == "", (
            "a list the model reads as no subnets"
        )
        text = _src("jen/routes/leases.py")
        assert "params.append(_stored_subnet_ids(current_user))" in text
        assert "accessible_subnet_ids(extensions.SUBNET_MAP)" not in text


# ── row 7 (BK13): the stale-reservation alert ────────────────────────────────


class TestTheStaleReservationAlertReadsIpv4Reservations:
    MAC = "aa:bb:cc:25:1b:71"

    @pytest.fixture(autouse=True)
    def _rows(self, db, monkeypatch):
        self._wipe(db)
        self.sent = []
        monkeypatch.setattr(alerts, "_utcnow", lambda: datetime(2026, 11, 24, 12, 0, 0))
        monkeypatch.setattr(
            alerts, "send_alert", lambda alert_type, *a, **kw: self.sent.append(alert_type) or [("telegram", True, "")]
        )
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES (%s, '10.0.0.71', 'q251b-old-box', 1, DATE_SUB(NOW(), INTERVAL 90 DAY), DATE_SUB(NOW(), INTERVAL 60 DAY))",
                (self.MAC,),
            )
        db.commit()
        yield
        self._wipe(db)

    def _wipe(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE mac=%s", (self.MAC,))
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCC251B71'")
            cur.execute("DELETE FROM settings WHERE setting_key LIKE 'alert_state:stale_reservation:%'")
        db.commit()
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()

    def _run(self, db):
        with db.cursor() as cur:
            alerts.check_stale_reservation_alerts(cur)
        return [s for s in self.sent if s == "stale_reservation"]

    def test_a_device_whose_only_host_row_is_an_ipv6_reservation_raises_nothing(self, db):
        _host(db, "AABBCC251B71", None, "q251b-old-box")
        assert self._run(db) == []

    def test_an_ipv4_reservation_raises_as_before(self, db):
        _host(db, "AABBCC251B71", 1, "q251b-old-box", ip="10.0.0.71")
        assert self._run(db) == ["stale_reservation"]

    def test_a_global_ipv4_reservation_raises_too(self, db):
        _host(db, "AABBCC251B71", 0, "q251b-old-box", ip="10.0.0.71")
        assert self._run(db) == ["stale_reservation"]

    def test_the_query(self):
        body = _src("jen/services/alerts.py").split("def check_stale_reservation_alerts(", 1)[1].split("\ndef ", 1)[0]
        assert (
            '"SELECT inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_subnet_id FROM hosts WHERE dhcp_identifier=UNHEX(%s) AND dhcp_identifier_type=0 "\n'
            '            "AND dhcp4_subnet_id IS NOT NULL",'
        ) in body


# ── row 8 (BK18 D12): bulk release asks the checkbox's rule ──────────────────


def _state(db, ip):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT state FROM lease4 WHERE address=INET_ATON(%s)", (ip,))
        return cur.fetchone()["state"]


class TestBulkReleaseRefusesWhatItsCheckboxDisables:
    IP = "10.99.0.167"

    @pytest.mark.parametrize("who", ["superadmin", "admin_one"])
    def test_a_hand_made_post_for_a_globally_reserved_client_releases_nothing(self, client, logged_in_client, db, who):
        _lease(db, MAC_A, self.IP, LEASE)
        _host(db, MAC_A, 0, RES_NAME, ip="10.99.0.168")
        c = logged_in_client if who == "superadmin" else client
        if who != "superadmin":
            _as(client, db, "admin", [1], "q251b_one")
        tr = _lease_row(c.get("/leases").get_data(as_text=True))
        assert re.search(r'<input[^>]*class="[^"]*row-checkbox[^"]*"[^>]*disabled', tr), (
            "the page disables this row's box"
        )
        r = c.post("/leases/bulk-release", data={"ips[]": [self.IP]}, follow_redirects=True)
        assert "Released 0 leases. 1 failed or skipped." in r.get_data(as_text=True)
        assert _state(db, self.IP) == 0

    def test_a_reservation_in_the_leases_own_subnet_is_refused_as_before(self, logged_in_client, db):
        _lease(db, MAC_A, self.IP, LEASE)
        _host(db, MAC_A, 1, RES_NAME, ip=self.IP)
        logged_in_client.post("/leases/bulk-release", data={"ips[]": [self.IP]})
        assert _state(db, self.IP) == 0

    @pytest.mark.parametrize("who", ["superadmin", "admin_one"])
    def test_a_client_with_no_reservation_is_released_as_before(self, client, logged_in_client, db, who):
        _lease(db, MAC_A, self.IP, LEASE)
        c = logged_in_client if who == "superadmin" else client
        if who != "superadmin":
            _as(client, db, "admin", [1], "q251b_one")
        r = c.post("/leases/bulk-release", data={"ips[]": [self.IP]}, follow_redirects=True)
        assert "Released 1 lease." in r.get_data(as_text=True)
        assert _state(db, self.IP) == 1

    def test_a_reservation_the_account_does_not_count_does_not_block_it(self, client, db):
        """The checkbox's rule on both sides: a one-subnet admin's box for a client reserved only in a hidden subnet is enabled, and its post releases."""
        _lease(db, MAC_A, self.IP, LEASE)
        _host(db, MAC_A, 2, RES_NAME, ip="10.99.1.168")
        _as(client, db, "admin", [1], "q251b_one")
        tr = _lease_row(client.get("/leases").get_data(as_text=True))
        assert not re.search(r'<input[^>]*class="[^"]*row-checkbox[^"]*"[^>]*disabled', tr)
        client.post("/leases/bulk-release", data={"ips[]": [self.IP]})
        assert _state(db, self.IP) == 1

    def test_an_ipv6_reservation_does_not_block_it(self, logged_in_client, db):
        _lease(db, MAC_A, self.IP, LEASE)
        _host(db, MAC_A, None, RES_NAME)
        logged_in_client.post("/leases/bulk-release", data={"ips[]": [self.IP]})
        assert _state(db, self.IP) == 1

    def test_a_lease_in_a_subnet_the_admin_may_not_see_is_still_refused(self, client, db):
        _lease(db, MAC_A, "10.99.1.169", LEASE, subnet=2)
        _as(client, db, "admin", [1], "q251b_one")
        client.post("/leases/bulk-release", data={"ips[]": ["10.99.1.169"]})
        assert _state(db, "10.99.1.169") == 0


# ── row 9: the Doctor's link to the Kea logging card ─────────────────────────

STDOUT = {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}], "severity": "INFO"}]}
NO_TIME = {
    "loggers": [
        {
            "name": "kea-dhcp4",
            "output-options": [{"output": "/var/log/kea/kea-dhcp4.log", "pattern": "%-5p %m\n"}],
            "severity": "INFO",
        }
    ]
}


@pytest.fixture
def kea_config(mock_kea, monkeypatch):
    from jen.services import kea as kea_svc

    def answer(dhcp4):
        monkeypatch.setattr(
            kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "mocked", "arguments": {"Dhcp4": dhcp4}}
        )

    return answer


def _finding(page, title):
    """The Doctor's card for one finding: from its title to the next finding's (or the page's end)."""
    assert title in page
    return page.split(title, 1)[1].split("text-transform:uppercase", 1)[0]


class TestTheDoctorHandsAnAdminNoLinkToACardItIsNotShown:
    TITLE = "Kea&#39;s log is not written to a file Jen can read"
    SAYS = "A superadmin can choose a file under Settings → Kea → Kea logging"

    def test_an_admins_finding_keeps_its_sentence_and_has_no_link(self, client, db, kea_config):
        kea_config(STDOUT)
        _as(client, db, "admin", None, "q251b_admin")
        r = client.get("/tools/doctor")
        assert r.status_code == 200
        page = r.get_data(as_text=True)
        card = _finding(page, self.TITLE)
        assert self.SAYS in card
        assert "#kea-logging" not in page and "Fix →" not in card

    def test_a_superadmins_finding_links_to_the_card(self, logged_in_client, kea_config):
        kea_config(STDOUT)
        card = _finding(logged_in_client.get("/tools/doctor").get_data(as_text=True), self.TITLE)
        assert self.SAYS in card
        assert '<a class="btn btn-sm" href="/settings/kea#kea-logging">Fix →</a>' in card

    def test_the_pattern_finding_follows_the_same_rule(self, client, logged_in_client, db, kea_config):
        kea_config(NO_TIME)
        title = "Kea&#39;s log lines carry no date and time"
        assert '<a class="btn btn-sm" href="/settings/kea#kea-logging">Fix →</a>' in _finding(
            logged_in_client.get("/tools/doctor").get_data(as_text=True), title
        )
        _as(client, db, "admin", None, "q251b_admin")
        assert "Fix →" not in _finding(client.get("/tools/doctor").get_data(as_text=True), title)

    def test_an_admin_keeps_the_link_of_a_finding_about_a_page_it_may_open(self, client, db, kea_config):
        kea_config({"subnet4": [{"id": 5, "subnet": "10.0.5.0/24"}]})
        _as(client, db, "admin", None, "q251b_admin")
        page = client.get("/tools/doctor").get_data(as_text=True)
        assert "Fix →" in page, "a finding that is not about the Kea logging card keeps its link"

    def test_the_doctor_itself_knows_no_role(self):
        assert "current_user" not in _src("jen/services/config_doctor.py")
        found = {f["id"]: f["fix_url"] for f in doctor.diagnose(STDOUT, hosts=[])}
        assert found["logger-no-file"] == "/settings/kea#kea-logging"
        from jen.routes import doctor as route

        assert route._KEA_LOGGING_CARD_FINDINGS == ("logger-no-file", "logger-pattern-no-timestamp")
