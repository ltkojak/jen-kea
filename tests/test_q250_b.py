"""
tests/test_q250_b.py
────────────────────
Q250, what a restricted account and an admin are shown: the rows of the executing pass on v7.2.0-beta.7 about subnet scope and the reservation definition.

* Investigate (and Explain, and Timeline) read only IPv4 reservations: a `hosts` row with no IPv4 subnet is an IPv6 reservation, never Kea's global IPv4 one.
* ONE rule for "this client has a reservation" on a list or a card: an account that does not see every subnet counts the IPv4 reservations in its own
  subnets and Kea's global ones (subnet 0), and no reservation in a subnet it may not see. The Leases list, the Devices list and the dashboard's Top devices.
* A Health row links only to a page the ACCOUNT may open: Trace, Doctor and Client classes turn away an admin who does not see every subnet.
* The "log file missing" row names the card each of its two answers is on, says who can choose a file, and links to the card for a superadmin only.
* A single-sign-on account's role is its stored one before its subnets are worked out from the form.
"""

import json
import pathlib
import re

import pytest

from jen import extensions
from jen.services import access, health
from jen.services import client_subject as subject

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")


def _as(client, db, role, subnets, username):
    """Sign the test client in as a new account. `subnets` None is every subnet (the column is NULL), a list is the account's own."""
    from tests.conftest import restricted_client

    _c, uid = restricted_client(client, db, subnets, role=role, username=username)
    if subnets is None:
        with db.cursor() as cur:
            cur.execute("UPDATE users SET subnet_access=NULL WHERE id=%s", (uid,))
        db.commit()
    return uid


def _colon(hexed):
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).lower()


MAC = "AABBCC250B01"
V6_NAME = "q250b-v6-host-name"
V4_NAME = "q250b-v4-host-name"
LEASE = "q250b-lease"

#: who is asked, as (role, the account's subnets; None is every subnet)
EVERY = [("superadmin", None), ("admin", None)]
ONE = [("admin", [1]), ("viewer", [1])]


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE hostname LIKE 'q250b-%%'")
        cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q250b-%%'")
        cur.execute("DELETE FROM devices WHERE last_hostname LIKE 'q250b-%%'")
    db.commit()


@pytest.fixture
def world(db):
    """One client with a lease in subnet 1 (the one subnet the suite's map has) and a device row there. `reserve(subnet)` gives it its only `hosts` row:
    None is an IPv6 reservation by hardware address (no IPv4 subnet), 0 is Kea's global IPv4 reservation, 1 is the account's subnet, 2 is a subnet a
    one-subnet account may not see."""
    _clean(db)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) VALUES "
            f"(INET_ATON('10.99.0.91'), UNHEX('{MAC}'), 3600, NOW() + INTERVAL 2 HOUR, 1, '{LEASE}', 0)"
        )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) VALUES (%s, '10.99.0.91', %s, 1, NOW(), NOW())",
            (_colon(MAC), LEASE),
        )
    db.commit()

    def reserve(subnet):
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q250b-%%'")
            if subnet is None:
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, dhcp6_subnet_id, hostname) "
                    f"VALUES (UNHEX('{MAC}'), 0, NULL, 10, '{V6_NAME}')"
                )
            else:
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                    f"VALUES (UNHEX('{MAC}'), 0, %s, INET_ATON('10.99.0.91'), '{V4_NAME}')",
                    (subnet,),
                )
        db.commit()

    yield reserve
    _clean(db)


# ── row 1: Investigate reads only IPv4 reservations ──────────────────────────


class TestInvestigateReadsOnlyIpv4Reservations:
    @pytest.mark.parametrize("role,subnets", ONE)
    def test_an_ipv6_reservations_name_is_not_shown_to_a_one_subnet_account(self, client, db, world, role, subnets):
        world(None)
        _as(client, db, role, subnets, f"q250b_inv6_{role}")
        r = client.get(f"/client?q={_colon(MAC)}")
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and LEASE in html, "the client itself is in the account's subnet and is shown"
        assert V6_NAME not in html

    @pytest.mark.parametrize("role,subnets", ONE)
    def test_a_global_ipv4_reservation_is_still_shown_to_a_one_subnet_account(self, client, db, world, role, subnets):
        world(0)
        _as(client, db, role, subnets, f"q250b_inv0_{role}")
        html = client.get(f"/client?q={_colon(MAC)}").get_data(as_text=True)
        assert V4_NAME in html

    @pytest.mark.parametrize("role,subnets", ONE)
    def test_a_reservation_in_a_hidden_subnet_is_not_shown(self, client, db, world, role, subnets):
        """As on v7.2.0-beta.7: `authorize` drops it."""
        world(2)
        _as(client, db, role, subnets, f"q250b_inv2_{role}")
        html = client.get(f"/client?q={_colon(MAC)}").get_data(as_text=True)
        assert LEASE in html and V4_NAME not in html

    def test_a_superadmins_page_for_an_ipv4_reservation_is_unchanged(self, logged_in_client, world):
        for subnet in (1, 2, 0):
            world(subnet)
            html = logged_in_client.get(f"/client?q={_colon(MAC)}").get_data(as_text=True)
            assert V4_NAME in html and LEASE in html, subnet

    def test_the_loader_returns_no_row_without_an_ipv4_subnet(self, world):
        world(None)
        assert subject.load_reservations4(MAC) == []
        world(0)
        rows = subject.load_reservations4(MAC)
        assert [(r["subnet_id"], r["hostname"]) for r in rows] == [(0, V4_NAME)] and subject._is_global(rows[0])
        world(2)
        assert [r["subnet_id"] for r in subject.load_reservations4(MAC)] == [2]

    def test_explain_and_timeline_get_the_same_rows(self, app, world):
        """The two callers outside the module: Explain's `_load_reservations` (it matched the IPv6 row as a global reservation with no address) and
        Timeline's `build_timeline`, which reads the first row as the client's IPv4 reservation."""
        from jen.routes import explain

        world(None)
        assert explain._load_reservations(MAC, "") == []
        assert "__subject.load_reservations4(" in _src("jen/services/timeline.py")
        assert "__subject.load_reservations4(" in _src("jen/routes/explain.py")

    def test_the_query_is_the_decided_one(self):
        text = _src("jen/services/client_subject.py")
        body = text.split("def load_reservations4(", 1)[1].split("\ndef ", 1)[0]
        assert (
            '"FROM hosts WHERE dhcp4_subnet_id IS NOT NULL AND ((HEX(dhcp_identifier)=%s AND dhcp_identifier_type=0) "'
            in body
        )
        assert '"OR (HEX(dhcp_identifier)=%s AND dhcp_identifier_type=3))"' in body
        assert '"subnet_id": r["subnet_id"] or 0' in body, "nothing else in the function changed"


# ── row 2: one rule for "this client has a reservation" ──────────────────────


def _lease_row(html):
    for tr in re.findall(r"<tr\b.*?</tr>", html, re.S):
        if LEASE in tr:
            return tr
    return None


def _top_device(client):
    data = client.get("/api/top-devices").get_json()
    mine = [d for d in data["devices"] if d["mac"] == _colon(MAC)]
    assert len(mine) == 1, data
    return mine[0]


def _reserved_count(html):
    summary = re.search(r'id="leases-summary">(.*?)</p>', html, re.S).group(1)
    m = re.search(r">\s*(\d+) reserved", summary)
    return int(m.group(1)) if m else 0


def _box(tr):
    return re.search(r'<input[^>]*class="[^"]*row-checkbox[^"]*"[^>]*>', tr).group(0)


def _says(client, role, reserved):
    """Every place a list or a card says whether this client has a reservation, held to one answer."""
    assert _top_device(client)["has_reservation"] is reserved, "the dashboard's Top devices pin"
    html = client.get("/leases").get_data(as_text=True)
    assert "Could not load leases" not in html
    tr = _lease_row(html)
    assert tr is not None
    assert ("badge-reserved" in tr) is reserved, "the Leases row's mark"
    assert _reserved_count(html) == (1 if reserved else 0), "the summary's N reserved"
    listed = _lease_row(client.get("/leases?reserved=1").get_data(as_text=True))
    assert (listed is not None) is reserved, "the Reserved filter"
    if role != "viewer":  # the checkbox and the action menu are an admin's
        assert ("disabled" in _box(tr)) is reserved and ('title="Reserved' in tr) is reserved
        assert ("View reservation" in tr) is reserved
        assert ("Create reservation" in tr) is not reserved and ("Release lease" in tr) is not reserved
    devices = client.get("/devices").get_data(as_text=True)
    assert "Could not load devices" not in devices and LEASE in devices
    assert ("Has static reservation" in devices) is reserved, "the Devices row's mark"


class TestOneRuleForHasAReservation:
    @pytest.mark.parametrize("role,subnets", ONE)
    def test_a_reservation_in_a_hidden_subnet_is_no_reservation_to_a_one_subnet_account(
        self, client, db, world, role, subnets
    ):
        world(2)
        _as(client, db, role, subnets, f"q250b_hid_{role}")
        _says(client, role, False)

    @pytest.mark.parametrize("role,subnets", ONE)
    def test_a_global_reservation_is_one_to_a_one_subnet_account(self, client, db, world, role, subnets):
        world(0)
        _as(client, db, role, subnets, f"q250b_glb_{role}")
        _says(client, role, True)

    @pytest.mark.parametrize("role,subnets", ONE)
    def test_a_reservation_in_the_accounts_subnet_is_one(self, client, db, world, role, subnets):
        """As on v7.2.0-beta.7."""
        world(1)
        _as(client, db, role, subnets, f"q250b_own_{role}")
        _says(client, role, True)

    @pytest.mark.parametrize("role,subnets", EVERY)
    @pytest.mark.parametrize("subnet", [1, 2, 0])
    def test_an_account_with_every_subnet_counts_every_ipv4_reservation(self, client, db, world, role, subnets, subnet):
        """As on v7.2.0-beta.7: nothing changes for an account that sees every subnet."""
        world(subnet)
        _as(client, db, role, subnets, f"q250b_all_{role}")
        _says(client, role, True)

    @pytest.mark.parametrize("role,subnets", EVERY + ONE)
    def test_an_ipv6_reservation_is_none_to_anyone(self, client, db, world, role, subnets):
        """As on v7.2.0-beta.7 (Q249's definition)."""
        world(None)
        _as(client, db, role, subnets, f"q250b_v6_{role}")
        _says(client, role, False)

    def test_the_rule_itself(self):
        from jen.models.user import User

        one = User(5, "u", "admin", subnet_access=[1])
        every = User(6, "v", "admin", subnet_access=None)
        got = [access.sees_reservation_in(one, s) for s in (None, 0, 1, 2, "1", "0", True, False)]
        assert got == [False, True, True, False, True, False, False, False]
        assert [access.sees_reservation_in(every, s) for s in (None, 0, 1, 2)] == [False, True, True, True]
        assert access.sees_reservation_in(User(7, "s", "superadmin", subnet_access=[1]), 2) is True

    def test_the_filters_condition_is_the_rule(self):
        from jen.routes import leases

        assert leases.RESERVED_VISIBLE == (
            "EXISTS (SELECT 1 FROM hosts h WHERE h.dhcp_identifier = l.hwaddr AND (h.dhcp4_subnet_id = 0 OR FIND_IN_SET(h.dhcp4_subnet_id, %s)))"
        )
        assert leases.RESERVED_VISIBLE.count("%s") == 1


# The definition, over the whole tree. Every query of the `hosts` table under jen/ and plugins/ is counted per file and held to this reviewed list: a new read of
# `hosts` anywhere changes a count and fails here until it is read and placed. "judges" is the number of those queries whose answer becomes "this client has a
# reservation" on a list or a card for the signed-in account; each such file must ask the one rule (`access.sees_reservation_in`, or its SQL in
# `leases.RESERVED_VISIBLE`). The reason says what the file's remaining reads are and why the rule is not theirs.
_HOSTS_READS = {
    # file: (queries of hosts, of which judge "has a reservation" for an account's list or card, what the rest are)
    "jen/routes/api.py": (
        4,
        0,
        "the API's reservation rows themselves (count, list, lookup by address or id), scoped by the key's own subnets",
    ),
    "jen/routes/dashboard.py": (
        4,
        1,
        "Top devices judges (1). The other three are per-subnet numbers of the caller's own subnets: reservations in the subnet, and leases with no "
        "reservation in the lease's OWN subnet (dynamic), which is one account-independent number of a subnet the account sees",
    ),
    "jen/routes/ddns.py": (1, 0, "DDNS status lists reservation names, each row filtered by the caller's subnets"),
    "jen/routes/devices.py": (1, 1, "the Devices list's mark"),
    "jen/routes/leases.py": (
        5,
        3,
        "the row's mark, the Reserved filter for every subnet and for the caller's (3). The bulk-release guard asks about the lease's OWN subnet, "
        "which the route then checks the caller may access; the IP map reads one subnet the caller was checked for",
    ),
    "jen/routes/reservations.py": (
        15,
        0,
        "the Reservations pages: the reservation rows themselves, each under the page's own subnet check",
    ),
    "jen/routes/search.py": (1, 0, "search lists reservation rows under add_subnet_restriction"),
    "jen/routes/subnets.py": (2, 0, "the number of reservations in one subnet the caller was checked for"),
    "jen/services/alerts.py": (
        5,
        0,
        "the background alert loop: no signed-in account; per-subnet numbers and the lease's own subnet",
    ),
    "jen/services/client_problems.py": (
        1,
        0,
        "an address reserved for one client and held by another: the problem's own evidence, scoped where it is shown",
    ),
    "jen/services/client_subject.py": (
        3,
        0,
        "Investigate reads the reservation ROWS (IPv4 only since Q250) and `authorize` judges each on its own subnet, a global one kept for everyone - "
        "the rule `sees_reservation_in` was written from; the other two find a client's subnet or its MAC by hostname",
    ),
    "jen/services/health.py": (1, 0, "a fleet-wide check, skipped for an account that does not see every subnet"),
    "jen/services/kea6.py": (2, 0, "IPv6 reservations (dhcp6_subnet_id)"),
    "jen/services/kea_identifiers.py": (3, 0, "the superadmin's identifier repair page"),
    "plugins/dns-sync/plugin.py": (1, 0, "a bundled plugin (not edited here): names to publish"),
    "plugins/ipam/plugin.py": (1, 0, "a bundled plugin (not edited here): one subnet's address map"),
    "plugins/network-discovery/plugin.py": (
        1,
        0,
        "a bundled plugin (not edited here): REPORTED - it reads a row with no IPv4 subnet as a reservation in every subnet it scans (reader D9)",
    ),
    "plugins/watchdog/plugin.py": (
        1,
        0,
        "a bundled plugin (not edited here): hosts to offer, a global one to unrestricted callers only",
    ),
    "plugins/wol/plugin.py": (
        1,
        0,
        "a bundled plugin (not edited here): hosts to offer, a global one to unrestricted callers only",
    ),
}
_ASKS_THE_RULE = re.compile(r"sees_reservation_in\(")


def _hosts_reads():
    found = {}
    for base in ("jen", "plugins", "templates"):
        for path in sorted((ROOT / base).rglob("*")):
            if path.suffix not in (".py", ".html") or not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            if "/tests/" in rel:
                continue
            n = len(re.findall(r"\b(?:FROM|JOIN) hosts\b", path.read_text(encoding="utf-8")))
            if n:
                found[rel] = n
    return found


class TestEveryReadOfHostsIsPlaced:
    def test_the_whole_tree_matches_the_reviewed_list(self):
        found = _hosts_reads()
        assert found == {rel: n for rel, (n, _j, _why) in _HOSTS_READS.items()}, (
            "a query of the hosts table was added or removed: read it, and if its answer says a client has a reservation on a list or a card, "
            "hold it to access.sees_reservation_in before placing it on _HOSTS_READS"
        )
        assert sum(found.values()) == 53 and sum(j for _n, j, _w in _HOSTS_READS.values()) == 5

    def test_each_file_that_judges_asks_the_one_rule(self):
        for rel, (_n, judges, why) in _HOSTS_READS.items():
            assert why.strip()
            if judges and rel.startswith("jen/"):
                assert _ASKS_THE_RULE.search(_src(rel)), rel
        asking = sorted(
            p.relative_to(ROOT).as_posix()
            for p in (ROOT / "jen").rglob("*.py")
            if _ASKS_THE_RULE.search(p.read_text(encoding="utf-8")) and p.name != "access.py"
        )
        assert asking == ["jen/routes/dashboard.py", "jen/routes/devices.py", "jen/routes/leases.py"]

    def test_no_page_judges_with_the_bare_subnet_question(self):
        """The three pages asked `all_subnets or can_access_subnet(row's subnet)` each in its own words, and one of them not at all."""
        for rel in ("jen/routes/dashboard.py", "jen/routes/devices.py", "jen/routes/leases.py"):
            text = _src(rel)
            assert "all_subnets or current_user.can_access_subnet(" not in text, rel
        assert "reserved_macs" not in _src("jen/routes/leases.py")


# ── row 3: a Health row links only where the account may go ──────────────────

TURNED_AWAY = ["/tools/trace", "/tools/doctor", "/subnets/classes"]


def _health_links():
    """Every address a check of jen/services/health.py can put in `fix_url` or `link`: Q249's enumeration of the ones written in the source, and the one held in a constant."""
    from tests.test_q249_b import _static_links

    return sorted(set(_static_links()) | {health._SWEEP_MISSING_URL})


def _finished(url, ctx):
    c = health.Check("x", "X", "kea", "fail", "d", "Fix it", url, link=url, link_label="Open")
    health._links_for_caller([c], ctx)
    return c


#: GET pages that take no argument and are never opened by the walk below: not pages of the application a link names
_NOT_WALKED = ("/static", "/api/", "/logout", "/login", "/auth", "/metrics", "/healthz")
#: a page that answers an account without every subnet differently and is NOT on NEEDS_EVERY_SUBNET, with why
_DEPENDS_ON_THE_QUERY = {
    # with no `level` it shows the GLOBAL options, which need every subnet; `?level=subnet&key=<id>` is open to an admin of that subnet. No Health row links here.
    "subnets.dhcp_options_page",
}


class TestAccountMayOpen:
    def test_role_may_opens_answers_are_unchanged(self, app):
        with app.app_context():
            for path, role, want in [
                ("/settings/users", "superadmin", True),
                ("/settings/users", "admin", False),
                ("/settings/kea", "admin", True),
                ("/settings/kea?tab=x#kea-logging", "viewer", False),
                ("/health-center", "viewer", True),
                ("/leases", "nobody", True),
                ("/health-center", "nobody", False),
                ("/tools/trace", "admin", True),
                ("/no/such/page", "superadmin", False),
                ("", "superadmin", False),
                (None, "superadmin", False),
                ("https://evil.example/settings/kea", "superadmin", False),
            ]:
                assert access.role_may_open(path, role) is want, (path, role)

    def test_an_account_without_every_subnet_is_refused_the_pages_that_need_them(self, app):
        with app.app_context():
            for path in TURNED_AWAY + [
                "/settings/logs",
                "/subnets/classes/new",
                "/subnets/add",
                "/servers/1/config-history",
            ]:
                assert access.account_may_open(path, "admin", True), path
                assert not access.account_may_open(path, "admin", False), path
                assert not access.account_may_open(path, "viewer", True), path
            for path in ("/settings/kea", "/servers", "/subnets", "/leases", "/health-center#check-kea_hooks"):
                assert access.account_may_open(path, "admin", False), path
            assert not access.account_may_open("/settings/users", "admin", True), "the role is still asked first"
            assert not access.account_may_open("/no/such/page", "superadmin", True)

    def test_every_name_on_the_list_is_a_get_page_an_admin_may_open(self, app):
        gets = {r.endpoint for r in app.url_map.iter_rules() if "GET" in r.methods}
        assert gets >= access.NEEDS_EVERY_SUBNET, sorted(access.NEEDS_EVERY_SUBNET - gets)
        assert isinstance(access.NEEDS_EVERY_SUBNET, frozenset) and len(access.NEEDS_EVERY_SUBNET) == 11
        for endpoint in access.NEEDS_EVERY_SUBNET:
            assert app.view_functions[endpoint]._jen_min_role in ("admin", "superadmin"), endpoint

    def test_the_list_is_what_the_routes_do(self, app, client, db, mock_kea):
        """The guard DRIVES the routes: every GET page that takes no argument is opened by an admin with every subnet and by a one-subnet admin. A page that
        answers the first with 200 and turns the second away is on the list (or on the reviewed exception above), and a page on the list never answers the second with 200."""
        pages = sorted(
            {
                (r.endpoint, r.rule)
                for r in app.url_map.iter_rules()
                if "GET" in r.methods and not r.arguments and not r.rule.startswith(_NOT_WALKED)
            }
        )
        assert len(pages) >= 60
        every = app.test_client()
        _as(every, db, "admin", None, "q250b_walk_every")
        _as(client, db, "admin", [1], "q250b_walk_one")
        turned_away = set()
        for endpoint, path in pages:
            full, part = every.get(path).status_code, client.get(path).status_code
            if full == 200 and part != 200:
                turned_away.add(endpoint)
            if endpoint in access.NEEDS_EVERY_SUBNET:
                assert part in (302, 403), (path, part)
        assert turned_away - _DEPENDS_ON_THE_QUERY == {e for e in turned_away if e in access.NEEDS_EVERY_SUBNET}, (
            sorted(turned_away - access.NEEDS_EVERY_SUBNET)
        )
        assert {"trace.trace_page", "doctor.doctor_page", "subnets.dhcp_classes_page", "users.audit_log"} <= turned_away

    @pytest.mark.parametrize("endpoint", ["servers.config_history", "servers.config_history_detail"])
    def test_the_pages_that_take_a_server_turn_a_one_subnet_admin_away(self, app, client, db, endpoint):
        _as(client, db, "admin", [1], "q250b_hist_one")
        with app.test_request_context():
            from flask import url_for

            path = (
                url_for(endpoint, server_id=1, rev_id=1)
                if endpoint.endswith("detail")
                else url_for(endpoint, server_id=1)
            )
        assert client.get(path).status_code == 302
        with client.session_transaction() as sess:
            assert [m for _c, m in sess.get("_flashes", [])] == ["Config history needs access to all subnets."]


class TestAHealthRowLinksWhereTheAccountMayGo:
    def test_the_walk_still_names_the_three_pages(self):
        links = {u.split("#")[0] for u in _health_links()}
        assert set(TURNED_AWAY) <= links and len(_health_links()) >= 12

    def test_every_link_a_one_subnet_admin_keeps_opens_for_that_admin(self, client, db, mock_kea):
        """Drives the routes: each link Health can produce is finished for the signed-in one-subnet admin (no scope named: the account's own is read), and every
        one that is left is opened. None answers a redirect or a refusal."""
        _as(client, db, "admin", [1], "q250b_links_one")
        kept = []
        with client:
            client.get("/about")
            for url in _health_links():
                c = _finished(url, {"admin": True})
                assert c.fix_url == c.link and (c.fix_hint, c.link_label) == (
                    ("Fix it", "Open") if c.link else ("", "")
                )
                if c.link:
                    kept.append(url)
        assert len(kept) >= 5 and "/settings/kea" in kept and "/servers" in kept
        for url in kept:
            r = client.get(url.split("#")[0])
            assert r.status_code == 200, (url, r.status_code, r.headers.get("Location"))
        assert not {u.split("#")[0] for u in kept} & set(TURNED_AWAY)

    def test_a_one_subnet_viewers_links_open_too(self, client, db, mock_kea):
        _as(client, db, "viewer", [1], "q250b_links_viewer")
        kept = []
        with client:
            client.get("/about")
            kept = [u for u in _health_links() if _finished(u, {"admin": False}).link]
        assert kept
        for url in kept:
            assert client.get(url.split("#")[0]).status_code == 200, url

    @pytest.mark.parametrize("role,subnets", EVERY)
    def test_an_account_with_every_subnet_keeps_what_its_role_may_open(self, app, client, db, role, subnets):
        _as(client, db, role, subnets, f"q250b_links_{role}")
        with client:
            client.get("/about")
            for url in _health_links():
                c = _finished(url, {"admin": True})
                want = access.role_may_open(url, role)
                assert bool(c.fix_url) is want and bool(c.link) is want, (role, url)
                if url.split("#")[0] in TURNED_AWAY:
                    assert c.fix_url == url, (role, url)

    def test_the_scope_is_the_callers(self, app, client, db):
        with app.app_context():
            assert health._caller_sees_every_subnet({}) is True, "no signed-in session: a key or a background run"
            assert health._caller_sees_every_subnet({"all_subnets": False}) is False
            assert _finished("/tools/trace", {"role": "admin", "all_subnets": False}).fix_url == ""
            assert _finished("/tools/trace", {"role": "admin", "all_subnets": True}).fix_url == "/tools/trace"
            assert _finished("/tools/trace", {"role": "admin"}).fix_url == "/tools/trace"
        _as(client, db, "admin", [1], "q250b_scope_one")
        with client:
            client.get("/about")
            assert health._caller_sees_every_subnet({}) is False
            assert health._caller_sees_every_subnet({"all_subnets": True}) is True, "a scope the caller names wins"

    def test_a_one_subnet_admins_real_run_names_none_of_the_three(self, client, db, mock_kea):
        _as(client, db, "admin", [1], "q250b_run_one")
        checks = client.get("/health-center/data").get_json()["checks"]
        named = {
            (c["id"], u) for c in checks for u in (c["fix_url"], c["link"]) if u and u.split("#")[0] in TURNED_AWAY
        }
        assert named == set()
        assert next(c for c in checks if c["id"] == "kea_hooks")["fix_url"] == "/settings/kea", (
            "a page it may open stays"
        )
        html = client.get("/health-center/data?partial=1").get_data(as_text=True)
        assert not any(f'href="{u}' in html for u in TURNED_AWAY)

    @pytest.mark.parametrize("role,subnets", EVERY)
    def test_the_real_run_of_an_account_with_every_subnet_still_names_trace(self, client, db, mock_kea, role, subnets):
        _as(client, db, role, subnets, f"q250b_run_{role}")
        checks = client.get("/health-center/data").get_json()["checks"]
        assert next(c for c in checks if c["id"] == "debug_logging_left_on")["fix_url"] == "/tools/trace"

    def test_the_rows_are_finished_by_the_accounts_rule_in_one_place(self):
        text = _src("jen/services/health.py")
        assert text.count("account_may_open(") == 2 and "role_may_open(" not in text.replace("account_may_open", "")
        body = text.split("def _links_for_caller(", 1)[1].split("\ndef ", 1)[0]
        assert "every = _caller_sees_every_subnet(ctx)" in body


# ── row 4: the "log file missing" row ────────────────────────────────────────

SWEEP_SID = 7250
SENTENCE = (
    "; a superadmin can choose a file under Settings → Kea → Kea logging, or set the Kea log path under Settings → Kea → SSH if Kea already writes one "
    "(6 sweeps without a read, last read never)"
)
HINT = (
    "A superadmin can choose a file under Settings → Kea → Kea logging, or set the Kea log path under Settings → Kea → SSH if Kea already writes one; "
    "the sweep retries every five minutes."
)


@pytest.fixture
def blind_server(db, monkeypatch):
    """One SSH-configured server whose log file the sweep has not found six times in a row, recorded by the sweep's own writers in the settings table."""
    from jen.models.user import _invalidate_settings_cache
    from jen.services import client_problems as cp

    def clean():
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key LIKE %s", (f"client_problems_%:{SWEEP_SID}",))
            cur.execute("DELETE FROM settings WHERE setting_key=%s", (cp._SWEPT_KEY,))
        db.commit()
        _invalidate_settings_cache()

    clean()
    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": SWEEP_SID, "name": "kea-a", "ssh_host": "10.0.0.1"}])
    now = cp._now()
    for _ in range(cp.MISS_LIMIT):
        cp._note_server(SWEEP_SID, False, "missing", now, "/var/log/kea/kea-dhcp4.log")
    cp._note_swept(now)
    yield
    clean()


def _sweep_row(client):
    return next(c for c in client.get("/health-center/data").get_json()["checks"] if c["id"] == "problems_sweep")


class TestTheLogFileMissingRow:
    def test_an_admins_row_has_the_sentence_and_no_link_to_a_card_it_is_not_shown(
        self, client, db, mock_kea, blind_server
    ):
        _as(client, db, "admin", None, "q250b_sweep_admin")
        row = _sweep_row(client)
        assert row["status"] == "fail" and SENTENCE in row["detail"]
        assert row["detail"].startswith("kea-a: /var/log/kea/kea-dhcp4.log is not on kea-a")
        assert row["fix_url"] == "" and row["fix_hint"] == HINT
        partial = client.get("/health-center/data?partial=1").get_data(as_text=True)
        assert "#kea-logging" not in partial and "a superadmin can choose a file" in partial
        page = client.get("/settings/kea").get_data(as_text=True)
        assert 'id="kea-logging"' not in page, "the card is a superadmin's"
        assert 'id="kea-ssh"' in page and "Kea log path" in page.split('id="kea-ssh"', 1)[1], (
            "the field the sentence names is on the SSH card"
        )

    def test_a_superadmins_row_links_to_the_card(self, logged_in_client, mock_kea, blind_server):
        row = _sweep_row(logged_in_client)
        assert row["status"] == "fail" and SENTENCE in row["detail"]
        assert (row["fix_url"], row["fix_hint"]) == ("/settings/kea#kea-logging", HINT)
        assert 'href="/settings/kea#kea-logging"' in logged_in_client.get("/health-center/data?partial=1").get_data(
            as_text=True
        )

    @pytest.mark.parametrize("subnets", [None, [1]])
    def test_a_viewers_row_has_the_sentence_and_no_link(self, client, db, mock_kea, blind_server, subnets):
        _as(client, db, "viewer", subnets, "q250b_sweep_viewer")
        row = _sweep_row(client)
        assert row["status"] == "fail" and SENTENCE in row["detail"] and row["fix_url"] == ""

    def test_a_one_subnet_admins_row_has_no_link(self, client, db, mock_kea, blind_server):
        _as(client, db, "admin", [1], "q250b_sweep_one")
        row = _sweep_row(client)
        assert row["status"] == "fail" and SENTENCE in row["detail"] and row["fix_url"] == ""

    def test_a_caller_that_is_no_session_keeps_the_link(self, app, blind_server):
        """An API key or a background run: every link stays (`_caller_role`)."""
        with app.app_context():
            assert health._problems_sweep({}).fix_url == "/settings/kea#kea-logging"

    def test_the_words_name_the_two_cards(self):
        assert health._SWEEP_MISSING_HINT == HINT and health._SWEEP_MISSING_URL == "/settings/kea#kea-logging"
        text = _src("jen/services/health.py")
        assert "set the log path there" not in text
        assert 'c.fix_url = _SWEEP_MISSING_URL if _caller_role(ctx) == "superadmin" else ""' in text


# ── row 5: a single-sign-on account's role comes before its subnets ──────────


def _make_user(db, username, role, subnet_access, provider="local"):
    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access, must_change_password, auth_provider) VALUES (%s, %s, %s, %s, 0, %s)",
            (username, hash_password("Q250b-x-Pass!1"), role, subnet_access, provider),
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


class TestASingleSignOnAccountsRoleComesFirst:
    def test_a_crafted_role_does_not_widen_a_single_sign_on_account(self, logged_in_client, db):
        uid = _make_user(db, "q250b_oidc", "admin", "[1]", provider="oidc")
        r = logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "role": "superadmin", "subnet_ids": "1"})
        assert r.status_code == 302
        assert _stored(db, uid) == ("admin", [1], 30)

    def test_a_crafted_role_with_nothing_ticked_is_refused_for_a_single_sign_on_admin(self, logged_in_client, db):
        """The role the subnets are judged for is the stored one: an admin with no box ticked is refused, where the posted Superadmin stored every subnet."""
        uid = _make_user(db, "q250b_oidc_none", "admin", "[1]", provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "role": "superadmin"})
        assert _stored(db, uid) == ("admin", [1], None)

    def test_a_local_admin_is_still_promoted(self, logged_in_client, db):
        uid = _make_user(db, "q250b_local", "admin", "[1]")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "role": "superadmin", "subnet_ids": "1"})
        assert _stored(db, uid) == ("superadmin", None, 30)

    def test_a_single_sign_on_account_stored_with_no_subnets_still_saves(self, logged_in_client, db):
        """Q249's exception: nothing ticked, a stored empty scope."""
        uid = _make_user(db, "q250b_oidc_empty", "admin", "[]", provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "45"})
        assert _stored(db, uid) == ("admin", [], 45)

    def test_a_single_sign_on_superadmin_keeps_every_subnet(self, logged_in_client, db):
        uid = _make_user(db, "q250b_oidc_super", "superadmin", None, provider="oidc")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "role": "viewer", "subnet_ids": "1"})
        assert _stored(db, uid) == ("superadmin", None, 30)

    def test_the_order_in_the_source(self):
        body = _src("jen/routes/users.py").split("def edit_user(", 1)[1]
        stored_role = body.index('if role is None:\n                    role = row["role"]')
        sso = body.index('if row["auth_provider"] == "oidc":')
        scope = body.index("_subnet_access_from_form(subnet_ids_raw, role)")
        assert stored_role < sso < scope
