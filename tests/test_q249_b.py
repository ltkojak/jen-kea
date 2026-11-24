"""
tests/test_q249_b.py
────────────────────
Q249, access, accounts and the Health links: what the executing pass on v7.2.0-beta.6 found in who may see or change what.

* A refusal names the fixed part of the route that refused, never the address that was typed.
* The "Needs attention" card leaves Health's pool row out only when its own pool lines say all of it.
* `can_access_subnet` never raises; "this lease has a reservation" reads only a reservation with an IPv4 subnet.
* A form with no role keeps the account's role: a superadmin can save their own Edit User dialog.
* A Superadmin row stores no subnet list. An unreadable stored scope is shown as no subnets. A stored empty scope can be kept.
* "N reserved" counts lease rows.
* A subnet-restricted admin is shown no Logs tab or tile.
* A Health row links only to a page the caller's role may open.
* An audit filter day with no next day is no filter.
* Small words and one color on the Users page; the HA action's refusal is the decorators' sentence.
"""

import json
import pathlib
import re
from decimal import Decimal

import pytest

from jen.models.user import User, read_subnet_scope
from jen.routes.settings import nav as navmod
from jen.services import access, dashboard_catalog, health

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")


def _as(client, db, role, subnets, username):
    """Sign the test client in as a new account. `subnets` None is every subnet (the column is NULL), a list is the account's own."""
    from tests.conftest import restricted_client

    restricted_client(client, db, subnets, role=role, username=username)
    with db.cursor() as cur:
        if subnets is None:
            cur.execute("UPDATE users SET subnet_access=NULL WHERE username=%s", (username,))
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        uid = cur.fetchone()["id"]
    db.commit()
    return uid


def _row(db, user_id):
    db.commit()  # a fresh read of what the route committed
    with db.cursor() as cur:
        cur.execute("SELECT username, role, subnet_access, session_timeout FROM users WHERE id=%s", (user_id,))
        return cur.fetchone()


def _make_user(db, username, role="admin", subnet_access=None):
    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (username, hash_password("testpass123"), role, subnet_access),
        )
        uid = cur.lastrowid
    db.commit()
    return uid


def _flashes(client):
    with client.session_transaction() as sess:
        return [m for _c, m in sess.get("_flashes", [])]


# ── a refusal names the route, not the address ───────────────────────────────


class TestARefusalNamesTheRouteNotTheAddress:
    CRAFTED = "/database/backup/download/Your session expired. Sign in again at evil.example."

    def test_a_crafted_address_puts_none_of_its_words_in_the_banner(self, client, db):
        _as(client, db, "viewer", None, "q249_refused_viewer")
        r = client.get(self.CRAFTED)
        assert r.status_code == 302
        said = _flashes(client)
        assert said == ["Superadmin access required for /database/backup/download."], said
        body = client.get("/", follow_redirects=True).get_data(as_text=True)
        assert "evil.example" not in body and "Your session expired" not in body

    def test_an_admin_is_told_the_same_and_nothing_of_the_address(self, client, db):
        _as(client, db, "admin", None, "q249_refused_admin")
        client.get(self.CRAFTED)
        assert _flashes(client) == ["Superadmin access required for /database/backup/download."]

    def test_a_route_with_no_variable_part_still_names_itself(self, client, db):
        _as(client, db, "viewer", None, "q249_refused_viewer2")
        client.get("/settings/users")
        client.get("/settings/security")
        assert _flashes(client) == [
            "Superadmin access required for /settings/users.",
            "Admin access required for /settings/security.",
        ]

    def test_with_no_matched_route_the_sentence_names_no_page(self, app):
        with app.test_request_context("/no/such/page/Sign in at evil.example"):
            assert access.refusal_sentence("Admin") == "Admin access required."

    def test_a_route_that_is_a_variable_from_its_first_character_names_no_page(self, app):
        from werkzeug.routing import Rule

        with app.test_request_context("/whatever"):
            from flask import request

            request.url_rule = Rule("/<path:anything>")
            assert access.refusal_sentence("Superadmin") == "Superadmin access required."

    def test_the_sentence_never_reads_the_request_path(self):
        body = _src("jen/services/access.py").split("def refusal_sentence", 1)[1].split("\ndef ", 1)[0]
        code = body.split('"""', 2)[2]
        assert (
            "request.path" not in code
            and "full_path" not in code
            and "request.url_rule" in code.replace('getattr(request, "url_rule"', "request.url_rule")
        )

    def test_the_ha_action_answers_with_the_same_sentence(self, client, db):
        _as(client, db, "admin", None, "q249_ha_admin")
        r = client.post("/servers/ha/1/sync")
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and "Superadmin access required for /servers/ha." in body
        assert "for this HA action" not in body

    def test_a_viewer_is_refused_an_admin_ha_action_in_that_sentence(self, client, db):
        _as(client, db, "viewer", None, "q249_ha_viewer")
        r = client.post("/servers/ha/1/heartbeat")
        assert r.status_code == 403 and "Admin access required for /servers/ha." in r.get_data(as_text=True)


# ── the "Needs attention" card and Health's pool row ─────────────────────────


@pytest.fixture
def history(db):
    def put(*rows):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            for subnet_id, used, size in rows:
                cur.execute(
                    "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, pool_size, pool_used) "
                    "VALUES (%s, UTC_TIMESTAMP(), %s, %s, %s)",
                    (subnet_id, used, size, used),
                )
        db.commit()

    yield put
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease_history")
    db.commit()


def _attention(client):
    r = client.get("/api/dashboard/catalog-data?widgets=attention")
    assert r.status_code == 200
    return r.get_json()["attention"]


def _pool_lines(lines):
    return [x for x in lines if x["kind"] == "pool" or "check-pool_utilization" in x["url"]]


class TestTheCardSaysWhatHealthSaysAboutPools:
    def test_a_failing_subnet_outside_the_map_is_not_turned_into_one_amber_line(
        self, logged_in_client, mock_kea, history
    ):
        history((7, 100, 100), (1, 85, 100))  # subnet 7: Kea serves it, Jen's map does not name it
        lines = _pool_lines(_attention(logged_in_client))
        health_row = [x for x in lines if x["kind"] == "health"]
        assert len(health_row) == 1 and health_row[0]["level"] == "fail", lines
        assert "Subnet 7" in health_row[0]["text"] and health_row[0]["url"] == "/health-center#check-pool_utilization"
        own = [x for x in lines if x["kind"] == "pool"]
        assert len(own) == 1 and own[0]["level"] == "warn" and own[0]["url"] == "/leases?subnet=1"
        assert any(x["level"] == "fail" for x in lines), "the card's edge takes the worst level of its lines"

    def test_a_warning_outside_the_map_is_drawn_as_a_warning(self, logged_in_client, mock_kea, history):
        history((7, 85, 100), (1, 10, 100))
        lines = _pool_lines(_attention(logged_in_client))
        assert [(x["kind"], x["level"]) for x in lines] == [("health", "warn")], lines
        assert "Subnet 7" in lines[0]["text"]

    def test_the_row_is_left_out_when_the_pool_lines_say_all_of_it(self, logged_in_client, mock_kea, history):
        history((1, 85, 100))
        lines = _pool_lines(_attention(logged_in_client))
        assert [(x["kind"], x["level"]) for x in lines] == [("pool", "warn")], lines

    def test_nothing_is_said_of_a_pool_that_is_fine(self, logged_in_client, mock_kea, history):
        history((1, 10, 100), (7, 10, 100))
        assert _pool_lines(_attention(logged_in_client)) == []

    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_a_one_subnet_account_is_told_nothing_of_a_subnet_it_may_not_see(self, client, db, mock_kea, history, role):
        history((7, 100, 100), (1, 85, 100))
        _as(client, db, role, [1], f"q249_card_{role}")
        lines = _attention(client)
        assert [(x["kind"], x["level"]) for x in _pool_lines(lines)] == [("pool", "warn")], lines
        assert "Subnet 7" not in json.dumps(lines) and "100%" not in json.dumps(lines)
        checks = client.get("/health-center/data").get_json()["checks"]
        row = next(c for c in checks if c["id"] == "pool_utilization")
        assert row["status"] == "warn" and "Subnet 7" not in row["detail"]

    def test_an_unrestricted_admin_reads_what_the_superadmin_reads(self, client, db, mock_kea, history):
        history((7, 100, 100), (1, 85, 100))
        _as(client, db, "admin", None, "q249_card_admin_all")
        kinds = sorted((x["kind"], x["level"]) for x in _pool_lines(_attention(client)))
        assert kinds == [("health", "fail"), ("pool", "warn")]

    def test_the_rows_flagged_subnets_are_not_in_the_json(self):
        c = health.Check("pool_utilization", "Pool utilization", "capacity")
        c.flagged_subnets.append(7)
        assert "flagged_subnets" not in c.as_dict()
        assert health.Check("x", "X", "kea").flagged_subnets == [], "each row has a list of its own"

    def test_a_read_that_failed_is_still_a_failing_line(self):
        row = health.Check("pool_utilization", "Pool utilization", "capacity", "fail", "could not read lease history")
        lines = dashboard_catalog.attention_widget([row], [], {})
        assert [(x["kind"], x["level"]) for x in lines] == [("health", "fail")]


# ── can_access_subnet never raises; a reservation is one with an IPv4 subnet ─


class TestCanAccessSubnetNeverRaises:
    @pytest.mark.parametrize("odd", [None, "", "abc", "1.5", 1.5, [], {}, True, False, b"1", "１", "-1", " "])
    def test_a_value_that_is_not_a_whole_number_is_in_nobodys_list(self, odd):
        assert User(5, "u", "admin", subnet_access=[1]).can_access_subnet(odd) is False

    @pytest.mark.parametrize(
        "odd", [float("nan"), float("inf"), Decimal("NaN"), Decimal("sNaN"), Decimal("Infinity"), Decimal("1.5")]
    )
    def test_a_number_that_is_not_finite_or_not_whole_is_no_subnet(self, odd):
        assert User(5, "u", "admin", subnet_access=[1]).can_access_subnet(odd) is False

    @pytest.mark.parametrize("one", [1, "1", " 1 ", 1.0, Decimal(1)])
    def test_a_whole_number_is_read_as_before(self, one):
        u = User(5, "u", "viewer", subnet_access=[1])
        assert u.can_access_subnet(one) is True and u.can_access_subnet(2) is False

    def test_an_unrestricted_account_is_still_asked_nothing(self):
        assert User(5, "u", "admin").can_access_subnet(None) is True
        assert User(5, "u", "superadmin", subnet_access=[1]).can_access_subnet(None) is True


MAC_V6_ONLY = "AABBCC249077"
MAC_RESERVED = "AABBCC249078"


@pytest.fixture
def leases_and_hosts(db):
    """Two leases in subnet 1. One client has only a row with no IPv4 subnet (what Kea stores for an IPv6 reservation by hardware address); one has an IPv4 reservation."""

    def clean():
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hostname LIKE 'q249b-%%'")
            cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q249b-%%'")
        db.commit()

    clean()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) VALUES "
            f"(INET_ATON('10.99.0.77'), UNHEX('{MAC_V6_ONLY}'), 3600, NOW() + INTERVAL 2 HOUR, 1, 'q249b-v6only', 0), "
            f"(INET_ATON('10.99.0.78'), UNHEX('{MAC_RESERVED}'), 3600, NOW() + INTERVAL 2 HOUR, 1, 'q249b-reserved', 0)"
        )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, dhcp6_subnet_id, hostname) "
            f"VALUES (UNHEX('{MAC_V6_ONLY}'), 0, NULL, 10, 'q249b-host6')"
        )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
            f"VALUES (UNHEX('{MAC_RESERVED}'), 0, 1, INET_ATON('10.99.0.78'), 'q249b-host4')"
        )
    db.commit()
    yield
    clean()


def _lease_rows(html):
    """hostname -> the row's markup, for the two leases of the fixture."""
    out = {}
    for tr in re.findall(r"<tr\b.*?</tr>", html, re.S):
        for name in ("q249b-v6only", "q249b-reserved"):
            if name in tr:
                out[name] = tr
    return out


WHO = [
    ("superadmin", None),
    ("admin", None),
    ("admin", [1]),
    ("viewer", [1]),
]


class TestAReservationIsOneWithAnIpv4Subnet:
    @pytest.mark.parametrize("role,subnets", WHO)
    def test_the_leases_page_loads_and_marks_only_the_ipv4_reservation(
        self, client, db, leases_and_hosts, role, subnets
    ):
        _as(client, db, role, subnets, f"q249_leases_{role}_{'all' if subnets is None else 'one'}")
        html = client.get("/leases").get_data(as_text=True)
        assert "Could not load leases" not in html
        rows = _lease_rows(html)
        assert set(rows) == {"q249b-v6only", "q249b-reserved"}
        assert "badge-reserved" in rows["q249b-reserved"] and "badge-reserved" not in rows["q249b-v6only"]
        summary = re.search(r'id="leases-summary">(.*?)</p>', html, re.S).group(1)
        assert re.search(r">\s*1 reserved", summary), summary

    @pytest.mark.parametrize("role,subnets", WHO)
    def test_the_reserved_filter_lists_only_the_ipv4_reservation(self, client, db, leases_and_hosts, role, subnets):
        _as(client, db, role, subnets, f"q249_filter_{role}_{'all' if subnets is None else 'one'}")
        rows = _lease_rows(client.get("/leases?reserved=1").get_data(as_text=True))
        assert set(rows) == {"q249b-reserved"}

    @pytest.mark.parametrize("subnets", [None, [1]])
    def test_an_admin_may_release_the_lease_that_has_no_ipv4_reservation(self, client, db, leases_and_hosts, subnets):
        _as(client, db, "admin", subnets, "q249_release_admin")
        rows = _lease_rows(client.get("/leases").get_data(as_text=True))

        def box(tr):
            return re.search(r'<input[^>]*class="[^"]*row-checkbox[^"]*"[^>]*>', tr)

        assert box(rows["q249b-v6only"]) and "disabled" not in box(rows["q249b-v6only"]).group(0)
        reserved_box = box(rows["q249b-reserved"])
        assert reserved_box is None or "disabled" in reserved_box.group(0)

    def test_a_reservation_in_a_hidden_subnet_changes_no_mark(self, client, db, leases_and_hosts):
        with db.cursor() as cur:
            cur.execute("UPDATE hosts SET dhcp4_subnet_id=2 WHERE hostname='q249b-host4'")
        db.commit()
        _as(client, db, "viewer", [1], "q249_hidden_viewer")
        html = client.get("/leases").get_data(as_text=True)
        assert "Could not load leases" not in html
        rows = _lease_rows(html)
        assert set(rows) == {"q249b-v6only", "q249b-reserved"} and not any(
            "badge-reserved" in tr for tr in rows.values()
        )

    @pytest.mark.parametrize("role,subnets", [("superadmin", None), ("admin", [1])])
    def test_the_devices_page_reads_the_same_rule(self, client, db, leases_and_hosts, role, subnets):
        mac = ":".join(MAC_V6_ONLY[i : i + 2] for i in range(0, 12, 2)).lower()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES (%s, '10.99.0.77', 'q249b-v6only', 1, NOW(), NOW())",
                (mac,),
            )
        db.commit()
        _as(client, db, role, subnets, f"q249_devices_{role}")
        r = client.get("/devices")
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and "q249b-v6only" in html and "Could not load devices" not in html

    @pytest.mark.parametrize("role", ["superadmin", "admin"])
    def test_a_global_reservation_marks_the_lease_for_an_account_with_every_subnet(
        self, client, db, leases_and_hosts, role
    ):
        """Subnet 0 is Kea's global IPv4 reservation. A regression guard: this is what the page did before Q249."""
        with db.cursor() as cur:
            cur.execute("UPDATE hosts SET dhcp4_subnet_id=0 WHERE hostname='q249b-host4'")
        db.commit()
        _as(client, db, role, None, f"q249_global_{role}")
        html = client.get("/leases").get_data(as_text=True)
        rows = _lease_rows(html)
        assert "badge-reserved" in rows["q249b-reserved"] and "badge-reserved" not in rows["q249b-v6only"]
        assert set(_lease_rows(client.get("/leases?reserved=1").get_data(as_text=True))) == {"q249b-reserved"}
        mac = ":".join(MAC_RESERVED[i : i + 2] for i in range(0, 12, 2)).lower()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES (%s, '10.99.0.78', 'q249b-reserved', 1, NOW(), NOW())",
                (mac,),
            )
        db.commit()
        devices = client.get("/devices").get_data(as_text=True)
        assert "Could not load devices" not in devices and "q249b-reserved" in devices

    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_a_global_reservation_marks_the_lease_for_a_restricted_account_too(
        self, client, db, leases_and_hosts, role
    ):
        """Q250 decided the other way from Q249: subnet 0 is Kea's global reservation, in no subnet an account can be scoped out of, so the row carries the mark,
        the filter lists it and the summary counts it for a subnet-restricted account as well (`access.sees_reservation_in`; tests/test_q250_b.py)."""
        with db.cursor() as cur:
            cur.execute("UPDATE hosts SET dhcp4_subnet_id=0 WHERE hostname='q249b-host4'")
        db.commit()
        _as(client, db, role, [1], f"q249_global_one_{role}")
        html = client.get("/leases").get_data(as_text=True)
        assert "Could not load leases" not in html
        rows = _lease_rows(html)
        assert set(rows) == {"q249b-v6only", "q249b-reserved"}
        assert "badge-reserved" in rows["q249b-reserved"] and "badge-reserved" not in rows["q249b-v6only"]
        assert set(_lease_rows(client.get("/leases?reserved=1").get_data(as_text=True))) == {"q249b-reserved"}

    def test_the_condition_is_the_decided_one(self):
        from jen.routes import leases

        assert leases.V4_RESERVATION.format(h="h.") == "h.dhcp4_subnet_id IS NOT NULL", (
            "0 is Kea's global IPv4 reservation"
        )
        assert leases.V4_RESERVATION.format(h="h.") in leases.RESERVED_ANY


# The definition, over the whole tree: every query of `hosts` that finds a reservation by the client's identifier. Each either requires an IPv4 subnet (the rule, or a
# stricter one: the lease's own subnet, a named subnet, the caller's subnets) or is on this reviewed list with the reason it reads every row.
_BY_IDENTIFIER = re.compile(r"(?:HEX\()?(?:h\.)?dhcp_identifier\)?\s*(?:=|IN\b)")
_NEEDS_V4_SUBNET = re.compile(
    r"V4_RESERVATION"
    r"|dhcp4_subnet_id IS NOT NULL"
    r"|dhcp4_subnet_id > 0"
    r"|dhcp4_subnet_id\s*=\s*(?:l\.subnet_id|%s)"
    r"|FIND_IN_SET\((?:h\.)?dhcp4_subnet_id"
)
_READS_EVERY_ROW = {
    # (Q251) jen/services/alerts.py left this list: the stale-reservation alert requires an IPv4 subnet now. It was excused with "it is about the reservation,
    # not about a lease", and it told of an IPv6 reservation as an IPv4 one with no address and no subnet. The list is empty.
    # (Q250) jen/services/client_subject.py left this list: `load_reservations4` requires an IPv4 subnet now. It was excused with "a global one is kept for
    # everyone", and the row with no IPv4 subnet it read became that global one.
}


def _hosts_queries_by_identifier():
    found = []
    for base in ("jen", "plugins"):
        for path in sorted((ROOT / base).rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if "/tests/" in rel:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                if not re.search(r"\b(?:FROM|JOIN) hosts\b", line):
                    continue
                window = "\n".join(lines[max(0, i - 3) : i + 5])
                if _BY_IDENTIFIER.search(window):
                    found.append((rel, i + 1, bool(_NEEDS_V4_SUBNET.search(window))))
    return found


class TestEveryReservationLookupByIdentifier:
    def test_each_requires_an_ipv4_subnet_or_is_reviewed(self):
        found = _hosts_queries_by_identifier()
        assert len(found) >= 13, "the scan still finds the queries it was written over"
        loose = {}
        for rel, _line, ruled in found:
            if not ruled:
                loose[rel] = loose.get(rel, 0) + 1
        assert loose == _READS_EVERY_ROW, (
            "a query finds a reservation by the client's identifier without requiring an IPv4 subnet: "
            f"{[f for f in found if not f[2]]}"
        )

    def test_the_three_pages_that_mark_a_client_reserved_carry_the_rule(self):
        ruled = {rel for rel, _line, ok in _hosts_queries_by_identifier() if ok}
        assert {"jen/routes/leases.py", "jen/routes/devices.py", "jen/routes/dashboard.py"} <= ruled


# ── "N reserved" counts lease rows ───────────────────────────────────────────


class TestReservedCountsLeaseRows:
    def test_one_reserved_client_with_two_leases_is_two(self, logged_in_client, db, leases_and_hosts):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) VALUES "
                f"(INET_ATON('10.99.0.79'), UNHEX('{MAC_RESERVED}'), 3600, NOW() + INTERVAL 2 HOUR, 1, 'q249b-second', 0)"
            )
        db.commit()
        html = logged_in_client.get("/leases").get_data(as_text=True)
        summary = re.search(r'id="leases-summary">(.*?)</p>', html, re.S).group(1)
        assert re.search(r">\s*2 reserved", summary), summary
        listed = logged_in_client.get("/leases?reserved=1").get_data(as_text=True)
        assert re.search(r'id="leases-summary">\s*2 active leases', listed), "the link lists what the number counted"


# ── the Users page and its routes ────────────────────────────────────────────


class TestAFormWithNoRoleKeepsTheRole:
    def test_a_superadmin_saves_their_own_dialog(self, logged_in_client, db):
        r = logged_in_client.post("/users/edit/1", data={"timeout": "45", "subnet_ids": "all"})
        assert r.status_code == 302 and _flashes(logged_in_client) == ["User 'admin' updated."]
        row = _row(db, 1)
        assert row["role"] == "superadmin" and row["session_timeout"] == 45 and row["subnet_access"] is None

    def test_naming_a_lower_role_for_oneself_is_still_refused(self, logged_in_client, db):
        logged_in_client.post("/users/edit/1", data={"role": "admin", "timeout": "45", "subnet_ids": "all"})
        assert _flashes(logged_in_client) == ["You cannot demote your own Superadmin account."]
        row = _row(db, 1)
        assert row["role"] == "superadmin" and row["session_timeout"] is None

    @pytest.mark.parametrize("role", ["admin", "viewer", "superadmin"])
    def test_any_row_keeps_its_role(self, logged_in_client, db, role):
        uid = _make_user(db, f"q249_keeps_{role}", role=role, subnet_access="[1]")
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30", "subnet_ids": "1"})
        row = _row(db, uid)
        assert row["role"] == role and row["session_timeout"] == 30
        assert row["subnet_access"] is None if role == "superadmin" else json.loads(row["subnet_access"]) == [1]

    def test_a_role_that_is_named_is_still_stored_and_still_checked(self, logged_in_client, db):
        uid = _make_user(db, "q249_named_role", role="viewer", subnet_access="[1]")
        logged_in_client.post(f"/users/edit/{uid}", data={"role": "admin", "subnet_ids": "1"})
        assert _row(db, uid)["role"] == "admin"
        logged_in_client.post(f"/users/edit/{uid}", data={"role": "owner", "subnet_ids": "1"})
        assert "Invalid role." in _flashes(logged_in_client) and _row(db, uid)["role"] == "admin"

    @pytest.mark.parametrize("role,subnets", [("admin", None), ("admin", [1]), ("viewer", None)])
    def test_only_a_superadmin_reaches_the_route(self, client, db, role, subnets):
        target = _make_user(db, "q249_untouched", role="viewer", subnet_access="[1]")
        _as(client, db, role, subnets, f"q249_not_super_{role}_{'all' if subnets is None else 'one'}")
        r = client.post(f"/users/edit/{target}", data={"timeout": "30", "subnet_ids": "all"})
        assert r.status_code == 302 and _flashes(client) == ["Superadmin access required for /users/edit."]
        row = _row(db, target)
        assert row["session_timeout"] is None and json.loads(row["subnet_access"]) == [1]


class TestASuperadminRowStoresNoList:
    def test_set_subnets_ignores_the_list(self, logged_in_client, db):
        uid = _make_user(db, "q249_super_row", role="superadmin")
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": "1"})
        assert _row(db, uid)["subnet_access"] is None

    def test_another_role_still_stores_it_and_is_still_refused_whole(self, logged_in_client, db):
        uid = _make_user(db, "q249_admin_row", role="admin")
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": "1"})
        assert json.loads(_row(db, uid)["subnet_access"]) == [1]
        logged_in_client.post(f"/users/set-subnets/{uid}", data={})
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": ["all", "1"]})
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": "abc"})
        assert json.loads(_row(db, uid)["subnet_access"]) == [1]

    def test_a_missing_account_is_said(self, logged_in_client):
        logged_in_client.post("/users/set-subnets/999999", data={"subnet_ids": "1"})
        assert _flashes(logged_in_client) == ["User not found."]


def _users_page_row(html, username):
    tr = next(t for t in re.findall(r"<tr\b.*?</tr>", html, re.S) if f"<strong>{username}</strong>" in t)
    cell = re.search(r'<td data-m="secondary" class="u-865c33">(.*?)</td>', tr, re.S).group(1)
    data = json.loads(re.search(r"data-user='([^']*)'", tr).group(1).replace("&#34;", '"'))
    return " ".join(cell.split()), data


class TestOneReaderOfAStoredScope:
    @pytest.mark.parametrize("stored", ["null", '"abc"', "5", "{}", '[1, "abc"]', "[true]", "[]"])
    def test_the_reader_says_no_subnets(self, stored):
        assert read_subnet_scope(stored) == []
        assert User(5, "u", "admin", subnet_access=stored).subnet_access_list == []

    def test_the_reader_says_every_subnet_only_for_no_value(self):
        assert (
            read_subnet_scope(None) is None and read_subnet_scope("[1, 2]") == [1, 2] and read_subnet_scope([3]) == [3]
        )
        assert read_subnet_scope("not json") == []

    @pytest.mark.parametrize("stored", ["null", '"abc"', "5", "{}"])
    def test_the_users_page_shows_the_dash_and_ticks_nothing(self, logged_in_client, db, stored):
        _make_user(db, "q249_oddscope", role="admin", subnet_access=stored)
        r = logged_in_client.get("/settings/users")
        assert r.status_code == 200
        cell, data = _users_page_row(r.get_data(as_text=True), "q249_oddscope")
        assert cell == "—" and data["subnet_ids"] == []

    def test_no_stored_list_is_still_all_subnets_and_a_list_is_its_names(self, logged_in_client, db):
        _make_user(db, "q249_allscope", role="admin", subnet_access=None)
        _make_user(db, "q249_onescope", role="viewer", subnet_access="[1]")
        _make_user(db, "q249_superscope", role="superadmin", subnet_access='"abc"')
        html = logged_in_client.get("/settings/users").get_data(as_text=True)
        assert _users_page_row(html, "q249_allscope") == ("All subnets", _users_page_row(html, "q249_allscope")[1])
        assert _users_page_row(html, "q249_allscope")[1]["subnet_ids"] is None
        assert _users_page_row(html, "q249_onescope")[0] == "Test Network"
        assert _users_page_row(html, "q249_onescope")[1]["subnet_ids"] == [1]
        assert _users_page_row(html, "q249_superscope")[0] == "All subnets", "a Superadmin is never restricted"

    def test_the_page_has_no_reader_of_its_own(self):
        body = _src("jen/routes/users.py").split("def users():", 1)[1].split("\ndef ", 1)[0]
        assert "read_subnet_scope(" in body and "json" not in body.lower().replace("tojson", "")

    @pytest.mark.parametrize("role,subnets", [("admin", None), ("admin", [1]), ("viewer", None)])
    def test_the_page_is_a_superadmins(self, client, db, role, subnets):
        _as(client, db, role, subnets, f"q249_users_{role}_{'all' if subnets is None else 'one'}")
        assert client.get("/settings/users").status_code == 302
        assert _flashes(client) == ["Superadmin access required for /settings/users."]


class TestAStoredEmptyScopeCanBeKept:
    @pytest.mark.parametrize("stored", ["[]", "null", '"abc"'])
    def test_nothing_ticked_is_accepted_for_an_account_with_no_subnets(self, logged_in_client, db, stored):
        uid = _make_user(db, "q249_empty", role="viewer", subnet_access=stored)
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30"})
        assert _flashes(logged_in_client) == ["User 'q249_empty' updated."]
        row = _row(db, uid)
        assert row["session_timeout"] == 30 and json.loads(row["subnet_access"]) == [] and row["role"] == "viewer"

    @pytest.mark.parametrize("stored", [None, "[1]"])
    def test_nothing_ticked_is_refused_for_every_other_account(self, logged_in_client, db, stored):
        uid = _make_user(db, "q249_scoped", role="viewer", subnet_access=stored)
        logged_in_client.post(f"/users/edit/{uid}", data={"timeout": "30"})
        row = _row(db, uid)
        assert row["session_timeout"] is None
        assert row["subnet_access"] is None if stored is None else json.loads(row["subnet_access"]) == [1]

    def test_an_account_with_no_subnets_can_be_given_some(self, logged_in_client, db):
        uid = _make_user(db, "q249_empty2", role="viewer", subnet_access="[]")
        logged_in_client.post(f"/users/edit/{uid}", data={"subnet_ids": "1"})
        assert json.loads(_row(db, uid)["subnet_access"]) == [1]

    def test_the_two_forms_that_do_not_read_the_row_are_unchanged(self, logged_in_client, db):
        uid = _make_user(db, "q249_empty3", role="viewer", subnet_access="[]")
        logged_in_client.post(f"/users/set-subnets/{uid}", data={})
        assert "Tick All Subnets or at least one subnet. Nothing was changed." in _flashes(logged_in_client)
        logged_in_client.post(
            "/users/add", data={"username": "q249_added", "password": "longenough1", "role": "viewer"}
        )
        with db.cursor() as cur:
            db.commit()
            cur.execute("SELECT COUNT(*) AS n FROM users WHERE username='q249_added'")
            assert cur.fetchone()["n"] == 0


class TestTheUsersPageWords:
    def test_the_role_is_not_printed_in_the_bare_warning_color(self, logged_in_client):
        src = _src("templates/users.html")
        assert not re.search(r"color:\s*var\(--warning\)", src)
        html = logged_in_client.get("/settings/users").get_data(as_text=True)
        assert re.search(
            r'<span style="color:var\(--warning-ink\);[^"]*">\s*<svg.*?</svg>\s*Superadmin</span>', html, re.S
        )

    def test_single_sign_on_is_signed_in_to(self):
        src = _src("templates/users.html")
        assert "on every SSO sign-in." in src and "SSO login" not in src


# ── the Logs group for a subnet-restricted admin ─────────────────────────────


class TestLogsNeedEverySubnet:
    def test_a_restricted_admin_is_listed_no_logs_tab_group_or_destination(self):
        ctx = navmod.nav_context("settings.settings", "admin", all_subnets=False)
        assert ctx["subtabs"]["logs"] == []
        assert "logs" not in [g["id"] for g in ctx["settings_groups"]]
        assert "/settings/logs" not in [g["url"] for g in ctx["strip"]]
        assert "/settings/logs" not in [d["id"] for d in ctx["destinations"]]
        assert "/settings/logs" not in [i.get("url") for g in ctx["sheet"] for i in g["items"]]
        assert [g["id"] for g in ctx["settings_groups"]] == [
            "kea",
            "databases",
            "security",
            "alerts",
            "appearance",
            "system",
        ]

    @pytest.mark.parametrize("role", ["admin", "superadmin"])
    def test_an_account_with_every_subnet_keeps_all_of_it(self, role):
        ctx = navmod.nav_context("users.audit_log", role, all_subnets=True)
        assert [t["id"] for t in ctx["subtabs"]["logs"]] == ["audit", "alerts"]
        assert "logs" in [g["id"] for g in ctx["settings_groups"]]
        assert any(g["url"] == "/settings/logs" and g["active"] for g in ctx["strip"])
        assert "/settings/logs" in [d["id"] for d in ctx["destinations"]]

    def test_a_stored_favorite_to_logs_does_not_resolve_for_a_restricted_admin(self):
        prefs = {"top": ["/settings/logs", "/reports"], "tabbar": []}
        ctx = navmod.nav_context("leases.leases", "admin", all_subnets=False, prefs=prefs)
        assert [f["id"] for f in ctx["favorites"]] == ["/reports"]

    def test_every_tab_of_the_group_is_the_one_route_that_refuses(self):
        assert all(
            t["url"].startswith("/settings/logs") and t.get("requires_all_subnets") for t in navmod.SUBTABS["logs"]
        )
        body = _src("jen/routes/users.py").split("def audit_log():", 1)[1]
        assert body.index("if not current_user.all_subnets:") < body.index('request.args.get("tab"')

    def test_the_settings_page_draws_no_logs_tile_for_a_restricted_admin(self, client, db, mock_kea):
        _as(client, db, "admin", [1], "q249_nolog_admin")
        html = client.get("/settings").get_data(as_text=True)
        assert 'href="/settings/system"' in html and 'href="/settings/logs"' not in html
        r = client.get("/settings/logs")
        assert r.status_code == 302 and _flashes(client) == ["Logs need access to all subnets."]

    def test_the_two_links_inside_settings_pages_follow_the_same_list(self, client, db, mock_kea):
        _as(client, db, "admin", [1], "q249_nolink_admin")
        alerts = client.get("/settings/alerts").get_data(as_text=True)
        system = client.get("/settings/system").get_data(as_text=True)
        assert "plus the Prometheus hook.</p>" in alerts and "Delivery history" not in alerts
        assert "/settings/logs" not in alerts and "/settings/logs" not in system
        assert re.search(r"Current log: <strong>[^<]*</strong> entr(?:y|ies)\.</div>", system)

    def test_an_unrestricted_admin_keeps_the_two_links(self, client, db, mock_kea):
        _as(client, db, "admin", None, "q249_link_admin")
        alerts = client.get("/settings/alerts").get_data(as_text=True)
        system = client.get("/settings/system").get_data(as_text=True)
        assert 'Delivery history is under <a href="/settings/logs?tab=alerts">Logs → Alert log</a>.</p>' in alerts
        assert re.search(r'entr(?:y|ies) — <a href="/settings/logs">view</a>\.</div>', system)

    def test_the_templates_read_the_list_nav_made_and_carry_no_rule(self):
        for name, tab in (("settings_alerts.html", "alerts"), ("settings_system.html", "audit")):
            src = _src(f"templates/{name}")
            assert f"nav.subtabs['logs']|selectattr('id', 'equalto', '{tab}')|list" in src
            assert "all_subnets" not in src.split("/settings/logs", 1)[0][-400:]

    def test_an_unrestricted_admin_keeps_the_tile_and_the_page(self, client, db, mock_kea):
        _as(client, db, "admin", None, "q249_log_admin")
        assert 'href="/settings/logs"' in client.get("/settings").get_data(as_text=True)
        assert client.get("/settings/logs").status_code == 200


# ── a Health row links only where the caller's role may go ───────────────────


def _static_links():
    """Every address a check of jen/services/health.py can put in `fix_url` or `link`: the ones written in the source."""
    text = _src("jen/services/health.py")
    found = set(re.findall(r'fix_url="(/[^"]*)"', text))
    found |= set(re.findall(r'\.fix_url(?:, c\.fix_hint)? = "(/[^"]*)"', text))
    found |= set(re.findall(r'\.link(?:, c\.link_label)? = "(/[^"]*)"', text))
    return sorted(found)


ADMIN_ONLY = ["/settings/kea", "/tools/doctor", "/settings/system", "/settings/security", "/tools/trace"]


class TestRoleMayOpen:
    def test_the_decorators_mark_the_view(self, app):
        views = app.view_functions
        assert views["users.users"]._jen_min_role == "superadmin"
        assert views["users.audit_log"]._jen_min_role == "admin"
        assert views["health.health_center"]._jen_min_role == "viewer"

    def test_a_view_wrapped_twice_keeps_the_stricter_mark(self):
        def page():
            return "x"

        assert access.viewer_or_above(access.superadmin_required(page))._jen_min_role == "superadmin"
        assert access.superadmin_required(access.viewer_or_above(page))._jen_min_role == "superadmin"
        assert access.admin_required(access.superadmin_required(page))._jen_min_role == "superadmin"

    def test_the_answer_is_the_mark_of_the_matched_view(self, app):
        with app.app_context():
            assert access.role_may_open("/settings/users", "superadmin")
            assert not access.role_may_open("/settings/users", "admin")
            assert not access.role_may_open("/settings/users", "viewer")
            assert access.role_may_open("/settings/kea", "admin") and not access.role_may_open(
                "/settings/kea", "viewer"
            )
            assert access.role_may_open("/health-center", "viewer")
            assert access.role_may_open("/leases", "viewer"), "a view the decorators did not mark is open to every role"

    def test_the_query_and_the_fragment_are_cut_off(self, app):
        with app.app_context():
            assert access.role_may_open("/settings/kea?tab=x#kea-logging", "admin")
            assert not access.role_may_open("/settings/kea?tab=x#kea-logging", "viewer")
            assert access.role_may_open("/health-center#check-kea_hooks", "viewer")

    def test_a_path_that_matches_nothing_is_refused(self, app):
        with app.app_context():
            for path in ("/no/such/page", "", None, "settings/kea", "https://evil.example/settings/kea"):
                assert not access.role_may_open(path, "superadmin"), path

    def test_an_unknown_role_opens_only_an_unmarked_view(self, app):
        with app.app_context():
            assert not access.role_may_open("/health-center", "nobody") and access.role_may_open("/leases", "nobody")


class TestAHealthRowLinksWhereTheCallerMayGo:
    def test_the_source_still_names_the_links_this_test_walks(self):
        links = _static_links()
        assert len(links) >= 12 and set(ADMIN_ONLY) <= {u.split("#")[0] for u in links}, links

    def test_a_superadmins_links_are_unchanged(self, app):
        with app.app_context():
            for url in _static_links():
                c = health.Check("x", "X", "kea", "fail", "d", "Fix it", url, link=url, link_label="Open")
                health._links_for_caller([c], {"role": "superadmin"})
                assert (c.fix_url, c.fix_hint, c.link, c.link_label) == (url, "Fix it", url, "Open"), url

    def test_a_viewer_is_left_no_link_to_a_page_that_refuses_a_viewer(self, app):
        with app.app_context():
            kept = []
            for url in _static_links():
                c = health.Check("x", "X", "kea", "fail", "d", "Fix it", url, link=url, link_label="Open")
                health._links_for_caller([c], {"admin": False})
                assert c.fix_url == c.link and (c.fix_hint, c.link_label) == (
                    ("Fix it", "Open") if c.link else ("", "")
                )
                if c.fix_url:
                    kept.append(url)
                    assert access.role_may_open(url, "viewer")
            for url in _static_links():
                if url.split("#")[0] in ADMIN_ONLY:
                    assert url not in kept, url
            assert "/servers" in kept and "/subnets" in kept

    def test_every_link_a_viewer_keeps_opens_for_a_viewer(self, client, db, mock_kea, app):
        with app.app_context():
            kept = [u for u in _static_links() if access.role_may_open(u, "viewer")]
        _as(client, db, "viewer", None, "q249_walk_viewer")
        for url in kept:
            r = client.get(url)
            assert r.status_code == 200, (url, r.status_code, _flashes(client))
            assert "access required" not in r.get_data(as_text=True), url

    def test_an_admin_keeps_an_admin_page_and_loses_a_superadmin_one(self, app):
        with app.app_context():
            c = health.Check(
                "x", "X", "kea", "fail", "d", "", "/settings/kea", link="/settings/users", link_label="Open"
            )
            health._links_for_caller([c], {"role": "admin"})
            assert c.fix_url == "/settings/kea" and (c.link, c.link_label) == ("", "")

    def test_the_role_is_the_callers(self, client, db, app):
        assert health._caller_role({"role": "admin", "admin": False}) == "admin"
        assert health._caller_role({"admin": False}) == "viewer"
        assert health._caller_role({"admin": True}) == "superadmin", "no signed-in session: a key or a background run"
        _as(client, db, "admin", None, "q249_role_admin")
        with client:
            client.get("/about")
            assert health._caller_role({"admin": True}) == "admin"

    def test_a_viewers_real_run_draws_no_link_to_an_admin_page(self, client, db, mock_kea):
        _as(client, db, "viewer", None, "q249_health_viewer")
        checks = client.get("/health-center/data").get_json()["checks"]
        hooks = next(c for c in checks if c["id"] == "kea_hooks")
        assert hooks["status"] == "fail" and hooks["fix_url"] == "", "the row that sent a viewer to Settings -> Kea"
        for c in checks:
            for url in (c["fix_url"], c["link"]):
                assert not url or url.split("#")[0].split("?")[0] not in ADMIN_ONLY, (c["id"], url)
        html = client.get("/health-center/data?partial=1").get_data(as_text=True)
        assert 'href="/settings/kea' not in html and 'href="/tools/doctor' not in html
        assert 'id="check-kea_hooks"' in html, "the row itself is still shown"

    def test_a_superadmins_real_run_keeps_the_link(self, logged_in_client, mock_kea):
        checks = logged_in_client.get("/health-center/data").get_json()["checks"]
        assert next(c for c in checks if c["id"] == "kea_hooks")["fix_url"] == "/settings/kea"
        assert 'href="/settings/kea"' in logged_in_client.get("/health-center/data?partial=1").get_data(as_text=True)

    def test_doctors_row_for_a_viewer_draws_neither_link(self, app):
        row = health.Check("config_doctor", "Configuration Doctor", "kea", "warn", "3 findings", "", "/tools/doctor")
        with app.test_request_context("/health-center"):
            from datetime import datetime, timezone

            from flask import render_template

            health._links_for_caller([row], {"admin": False})
            html = render_template(
                "_health_checks.html",
                grouped=[("kea", "Kea", [row])],
                group_banners={},
                summary={"ok": 0, "warn": 1, "fail": 0, "skip": 0},
                checked_at=datetime.now(timezone.utc),
            )
        assert "/tools/doctor" not in html and "hc-fix" not in html and "3 findings" in html

    def test_the_rows_are_finished_in_one_place_and_the_template_has_no_rule(self):
        text = _src("jen/services/health.py")
        run = text.split("def run_checks(", 1)[1].split("\ndef ", 1)[0]
        assert run.count("return ") == 1 and "return _links_for_caller(out, ctx)" in run
        # (Q250) the question is `account_may_open`: the role, then the account's subnets
        assert text.count("account_may_open(") == 2, "the fix link and the detail link, in _links_for_caller only"
        partial = _src("templates/_health_checks.html")
        assert "role" not in partial and "admin" not in partial


# ── an audit filter day with no next day ─────────────────────────────────────


class TestTheLastDayIsNoFilter:
    def test_whole_day(self):
        from datetime import date

        from jen.routes.users import _whole_day

        assert _whole_day("9999-12-31") is None
        assert _whole_day("9999-12-30") == date(9999, 12, 30) and _whole_day("2026-11-23") == date(2026, 11, 23)

    def test_the_page_loads_and_ignores_it(self, logged_in_client):
        r = logged_in_client.get("/settings/logs?from=9999-12-31&to=9999-12-31")
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and "Could not load audit log" not in html
        assert 'value="9999-12-31"' not in html, "a day that is no filter is not shown as one"
