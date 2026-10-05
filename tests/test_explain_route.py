"""
tests/test_explain_route.py
───────────────────────────
v5.35.0 (Q34) — /tools/explain: the form, the decision page with the
Kea config stubbed, subnet access, and the row links that lead here.
"""

import pathlib

import pytest

from jen.models.db import kea_db

REPO = pathlib.Path(__file__).resolve().parent.parent

CFG = {
    "valid-lifetime": 3600,
    "option-data": [{"name": "domain-name-servers", "data": "1.1.1.1"}],
    "client-classes": [{"name": "printers", "test": "substring(pkt4.mac,0,3) == 0xaabbcc"}],
    "subnet4": [
        {
            "id": 1,
            "subnet": "192.168.1.0/24",
            "option-data": [{"name": "routers", "data": "192.168.1.1"}],
            "pools": [
                {"pool": "192.168.1.10 - 192.168.1.99", "client-classes": ["printers"]},
                {"pool": "192.168.1.100 - 192.168.1.200"},
            ],
        }
    ],
}


@pytest.fixture
def stub_config(monkeypatch):
    monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: CFG)


class TestPage:
    def test_form_renders_without_a_client(self, logged_in_client):
        r = logged_in_client.get("/tools/explain")
        assert r.status_code == 200
        page = r.get_data(as_text=True)
        assert 'name="mac"' in page and 'name="subnet"' in page
        assert "Answer" not in page

    def test_bad_mac_is_refused(self, logged_in_client, stub_config):
        page = logged_in_client.get("/tools/explain?mac=nope").get_data(as_text=True)
        assert "isn&#39;t a MAC address" in page or "isn't a MAC address" in page

    def test_decision_renders_with_all_six_steps(self, logged_in_client, stub_config, mock_kea):
        page = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1").get_data(as_text=True)
        for title in (
            "Subnet selection",
            "Reservation",
            "Client classes",
            "Subnet guards",
            "Pools and address",
            "Options",
        ):
            assert title in page, title
        assert "from pool 192.168.1.10 - 192.168.1.99" in page  # printers matched → guarded pool
        assert "printers" in page and "matched" in page
        assert "routers" in page and "192.168.1.1" in page

    def test_non_printer_gets_the_open_pool(self, logged_in_client, stub_config, mock_kea):
        page = logged_in_client.get("/tools/explain?mac=00:11:22:33:44:55&subnet=1").get_data(as_text=True)
        assert "from pool 192.168.1.100 - 192.168.1.200" in page

    def test_current_lease_wins(self, logged_in_client, stub_config, mock_kea):
        with kea_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='001122334455'")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, state, expire, valid_lifetime) "
                "VALUES (INET_ATON('192.168.1.150'), UNHEX('001122334455'), 1, 0, DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600)"
            )
            db.commit()
        try:
            page = logged_in_client.get("/tools/explain?mac=00:11:22:33:44:55").get_data(as_text=True)
            assert "192.168.1.150" in page and "renewed" in page
            assert "from the current lease" in page  # subnet auto-chosen
        finally:
            with kea_db() as db, db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='001122334455'")
                db.commit()

    def test_host_db_reservation_is_found(self, logged_in_client, stub_config, mock_kea):
        with kea_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE77'")
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE77'), 0, 1, INET_ATON('192.168.1.250'), 'res-host')"
            )
            db.commit()
        try:
            page = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:77&subnet=1").get_data(as_text=True)
            assert "192.168.1.250" in page and "reservation" in page and "res-host" in page
        finally:
            with kea_db() as db, db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE77'")
                db.commit()

    def test_restricted_user_cannot_explain_a_foreign_subnet(self, client, db, stub_config, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_explain_viewer")
        page = c.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1").get_data(as_text=True)
        assert "You do not have access to that subnet" in page
        assert "Pools and address" not in page

    def test_config_get_failure_is_a_flash_not_a_500(self, logged_in_client, monkeypatch):
        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: None)
        r = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1")
        assert r.status_code == 200
        assert "Could not read the Kea configuration" in r.get_data(as_text=True)


class TestLinks:
    def test_nav_and_row_links_point_here(self):
        assert '"url": "/tools/explain"' in (REPO / "jen" / "routes" / "settings" / "nav.py").read_text(
            encoding="utf-8"
        )
        for name in ("_lease_rows.html", "_reservation_row.html"):
            assert "/tools/explain?mac=" in (REPO / "templates" / name).read_text(encoding="utf-8"), name


# ── v5.68.0-beta.2 (Q135): inputs by source, and the why-not verdicts, through the route ─────────────────────────────

MAC2 = "00:11:22:33:44:55"
NO_LOG = {
    "classes": None,
    "query": None,
    "cid": None,
    "state": "no-helper",
    "message": "Reading Kea's log needs the Kea host helper.",
}
KEA_LOG = {
    "classes": {
        "classes": ["ALL", "VENDOR_CLASS_Acme-1", "printers"],
        "at": "2026-10-04 15:10:39",
        "id": "x",
        "message": "",
    },
    "query": {
        "at": "2026-10-04 15:10:41",
        "hostname": "packet-host",
        "vendor_class": "Acme-1",
        "client_id": "01:00:11:22:33:44:55",
        "user_class": "",
        "circuit_id": "eth0/1/7",
        "remote_id": "",
    },
    "cid": {"client_id": "01:00:11:22:33:44:55", "at": "2026-10-04 15:10:41"},
    "state": "ok",
    "message": "",
}
RELAY_CONTEXT = '{ "ISC": { "relay-agent-info": { "remote-id": "0A0B0C0D0E0F", "sub-options": "0x010441424344" } } }'


def _cleanup(db):
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM lease4 WHERE HEX(hwaddr) IN ('001122334455', '00AAAAAAAA01', '00AAAAAAAA02', '00AAAAAAAA03')"
        )
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('001122334455', '00AAAAAAAA02')")
    db.commit()


@pytest.fixture
def lease_with_extras(db):
    _cleanup(db)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, client_id, subnet_id, state, expire, valid_lifetime, hostname, user_context) "
            "VALUES (INET_ATON('192.168.1.150'), UNHEX('001122334455'), UNHEX('01001122334455'), 1, 0, "
            "DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600, 'lease-host', %s)",
            (RELAY_CONTEXT,),
        )
    db.commit()
    yield
    _cleanup(db)


@pytest.fixture
def no_log(monkeypatch):
    seen = []

    def read_log(mac, *, allowed, fetch=True):
        seen.append(allowed)
        return NO_LOG

    monkeypatch.setattr("jen.services.explain_context.read_log", read_log)
    return seen


@pytest.fixture
def needs_vendor_class(monkeypatch):
    """A config with a class whose test reads option 60: with no vendor class supplied it is undecided, so something is MISSING."""
    cfg = dict(CFG, **{"client-classes": [{"name": "windows", "test": "substring(option[60].hex,0,4) == 'MSFT'"}]})
    monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: cfg)


class TestInputsBySource:
    def test_the_lease_row_fills_the_client_id_hostname_and_relay_ids_and_says_so(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, no_log
    ):
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert "Inputs used" in page
        assert "lease-host" in page and "01:00:11:22:33:44:55" in page and "ABCD" in page and "0a0b0c0d0e0f" in page
        assert "the current lease" in page and "the lease&#39;s extended info" in page
        assert "the MAC you asked about" in page

    def test_what_was_typed_is_labelled_typed_and_wins(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, no_log
    ):
        page = logged_in_client.get(
            f"/tools/explain?mac={MAC2}&hostname=typed-host&vendor_class=HP+JetDirect"
        ).get_data(as_text=True)
        assert "typed-host" in page and "HP JetDirect" in page and "typed" in page
        assert "lease-host" not in page, "the typed hostname replaced the lease's"

    def test_auto_off_is_only_the_mac_and_what_was_typed(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, no_log
    ):
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}&auto=0").get_data(as_text=True)
        assert "lease-host" not in page and "01:00:11:22:33:44:55" not in page and "Inputs used" in page

    def test_kea_log_inputs_appear_for_an_admin_who_may_read_it(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, monkeypatch
    ):
        monkeypatch.setattr(
            "jen.services.explain_context.read_log", lambda mac, *, allowed, fetch=True: KEA_LOG if allowed else NO_LOG
        )
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert "packet-host" in page and "Acme-1" in page and "eth0/1/7" in page
        assert "Kea&#39;s log (packet dump)" in page
        assert "assigned by Kea at 2026-10-04 15:10:39" in page, (
            "the printers class has a test Jen cannot settle; Kea's list decides it"
        )

    def test_a_restricted_caller_never_asks_for_the_log(
        self, client, db, stub_config, mock_kea, lease_with_extras, no_log
    ):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_explain_scoped_admin")
        page = c.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert no_log == [False], "a subnet-scoped admin may not read the Kea log, so it is not read for them"
        assert "lease-host" in page, "their own subnet's lease still fills the form"

    def test_a_lease_in_a_subnet_the_caller_cannot_see_contributes_nothing(
        self, client, db, stub_config, mock_kea, lease_with_extras, no_log
    ):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_explain_blind_viewer")
        page = c.get(f"/tools/explain?mac={MAC2}&subnet=999").get_data(as_text=True)
        for secret in ("lease-host", "01:00:11:22:33:44:55", "0a0b0c0d0e0f", "ABCD"):
            assert secret not in page, f"{secret!r} leaked from a lease in a subnet the viewer cannot see"

    def test_the_embedded_result_carries_the_form_that_goes_back_to_the_investigation_page(
        self, logged_in_client, mock_kea, lease_with_extras, no_log, needs_vendor_class
    ):
        r = logged_in_client.get(f"/tools/explain?mac={MAC2}&subnet=1&embed_q={MAC2}", headers={"HX-Request": "true"})
        page = r.get_data(as_text=True)
        assert 'action="/client"' in page and 'name="q" value="00:11:22:33:44:55"' in page
        assert 'name="tab" value="explain"' in page
        for field in ("client_id", "vendor_class", "user_class", "hostname", "circuit_id", "remote_id", "giaddr"):
            assert f'name="{field}"' in page, field
        assert "Explain again" in page
        assert "needed to decide a class" in page, (
            "an input a class test needs and nothing supplied is marked as needed"
        )

    def test_without_an_identifier_to_go_back_to_there_is_no_inline_form(
        self, logged_in_client, stub_config, mock_kea, no_log
    ):
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}&subnet=1", headers={"HX-Request": "true"}).get_data(
            as_text=True
        )
        assert "Explain again" not in page and "Inputs used" in page

    def test_a_scoped_admin_is_told_who_may_read_kea_s_log(self, client, db, mock_kea, needs_vendor_class):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_explain_hint_admin")
        page = c.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1").get_data(as_text=True)
        assert "needs an admin with access to every subnet" in page

    def test_an_admin_with_no_helper_is_told_to_type_what_is_missing(
        self, logged_in_client, mock_kea, no_log, needs_vendor_class
    ):
        page = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1").get_data(as_text=True)
        assert "needs the Kea host helper" in page and "Type what is missing below" in page


SMALL_CFG = {
    "subnet4": [
        {
            "id": 1,
            "subnet": "192.168.1.0/24",
            "pools": [{"pool": "192.168.1.10 - 192.168.1.11"}, {"pool": "192.168.1.100 - 192.168.1.110"}],
        }
    ]
}


def _lease(db, mac_hex, ip, subnet_id=1):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, state, expire, valid_lifetime) VALUES "
            "(INET_ATON(%s), UNHEX(%s), %s, 0, DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600)",
            (ip, mac_hex, subnet_id),
        )
    db.commit()


class TestLeaseAwareVerdicts:
    @pytest.fixture
    def small(self, monkeypatch, db, no_log):
        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: SMALL_CFG)
        _cleanup(db)
        yield
        _cleanup(db)

    def test_a_full_pool_is_a_verdict_and_the_next_pool_is_the_answer(self, logged_in_client, db, small, mock_kea):
        _lease(db, "00AAAAAAAA01", "192.168.1.10")
        _lease(db, "00AAAAAAAA03", "192.168.1.11")
        page = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1").get_data(as_text=True)
        assert "eligible but FULL (2 of 2 addresses leased)" in page
        assert "from pool 192.168.1.100 - 192.168.1.110 (11 free)" in page
        assert "(FULL)" in page

    def test_a_reserved_address_held_by_another_client_names_the_holder_and_links_to_it(
        self, logged_in_client, db, small, mock_kea
    ):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('00AAAAAAAA02'), 0, 1, INET_ATON('192.168.1.50'), 'wanted')"
            )
        db.commit()
        _lease(db, "00AAAAAAAA01", "192.168.1.50")
        page = logged_in_client.get("/tools/explain?mac=00:aa:aa:aa:aa:02&subnet=1&embed_q=00:aa:aa:aa:aa:02").get_data(
            as_text=True
        )
        assert "is held by 00:aa:aa:aa:aa:01" in page and "only once that lease expires or is released" in page
        assert "/client?q=00%3Aaa%3Aaa%3Aaa%3Aaa%3A01" in page, "the holder links to its own investigation"
        assert "tab=changes" in page and "element=reservation" in page, (
            "an admin may follow the why-not to the config changes"
        )

    def test_a_scoped_admin_does_not_get_the_changes_link(self, client, db, small, mock_kea):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('00AAAAAAAA02'), 0, 1, INET_ATON('192.168.1.50'), 'wanted')"
            )
        db.commit()
        _lease(db, "00AAAAAAAA01", "192.168.1.50")
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_explain_holder_admin")
        page = c.get(
            "/tools/explain?mac=00:aa:aa:aa:aa:02&subnet=1&embed_q=00:aa:aa:aa:aa:02", headers={"HX-Request": "true"}
        ).get_data(as_text=True)
        assert "is held by 00:aa:aa:aa:aa:01" in page, "the holder is in a subnet they may see"
        assert "tab=changes" not in page

    def test_the_holder_of_an_address_in_a_subnet_the_caller_cannot_see_is_not_revealed(
        self, client, db, small, mock_kea
    ):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('00AAAAAAAA02'), 0, 1, INET_ATON('192.168.1.50'), 'wanted')"
            )
        db.commit()
        _lease(
            db, "00AAAAAAAA01", "192.168.1.50", subnet_id=2
        )  # the lease on that address sits in a subnet they cannot see
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_explain_scoped_viewer")
        page = c.get("/tools/explain?mac=00:aa:aa:aa:aa:02&subnet=1").get_data(as_text=True)
        assert "00:aa:aa:aa:aa:01" not in page and "is held by" not in page

    def test_an_identifier_type_that_is_not_enabled_is_never_matched(
        self, logged_in_client, db, monkeypatch, mock_kea, no_log
    ):
        cfg = dict(SMALL_CFG, **{"host-reservation-identifiers": ["circuit-id"]})
        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: cfg)
        _cleanup(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('00AAAAAAAA02'), 0, 1, INET_ATON('192.168.1.50'), 'wanted')"
            )
        db.commit()
        try:
            page = logged_in_client.get("/tools/explain?mac=00:aa:aa:aa:aa:02&subnet=1").get_data(as_text=True)
            assert "never matched" in page and "hw-address is not in host-reservation-identifiers (circuit-id)" in page
        finally:
            _cleanup(db)

    def test_a_relay_that_does_not_match_the_subnet_is_a_stage_verdict(self, logged_in_client, small, mock_kea):
        page = logged_in_client.get("/tools/explain?mac=aa:bb:cc:dd:ee:01&subnet=1&giaddr=10.9.9.9").get_data(
            as_text=True
        )
        assert "NOT selected" in page and "Everything below assumes it was" in page


class TestTheUsableLeaseIsTheOnlyLeaseTheRouteKnows:
    """v5.68.0-beta.10 (Q145): the route filtered the lease for the INPUTS and then let the unfiltered one choose the subnet (refused:
    "You do not have access"), reach the engine and word the page - so a client with a current lease in a subnet the caller cannot see
    and a reservation in one they can got nothing, and the hidden lease still reached `run()`."""

    HIDDEN_IP = "10.99.0.5"

    @pytest.fixture
    def split(self, monkeypatch, db, no_log):
        from jen import extensions

        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: SMALL_CFG)
        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {1: {"name": "NET-A", "cidr": "192.168.1.0/24"}, 2: {"name": "HIDDEN-NET-B", "cidr": "10.99.0.0/24"}},
        )
        _cleanup(db)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON(%s)", (self.HIDDEN_IP,))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, client_id, subnet_id, state, expire, valid_lifetime, hostname) VALUES "
                "(INET_ATON(%s), UNHEX('00AAAAAAAA02'), UNHEX('0100AAAAAAAA02'), 2, 0, DATE_ADD(NOW(), INTERVAL 1 HOUR), 3600, "
                "'hidden-lease-host')",
                (self.HIDDEN_IP,),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('00AAAAAAAA02'), 0, 1, INET_ATON('192.168.1.50'), 'reserved-in-a')"
            )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON(%s)", (self.HIDDEN_IP,))
        db.commit()
        _cleanup(db)

    def test_a_scoped_caller_is_explained_in_the_subnet_of_the_reservation_and_never_sees_the_hidden_lease(
        self, client, db, split, mock_kea
    ):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_explain_split_admin")
        page = c.get("/tools/explain?mac=00:aa:aa:aa:aa:02").get_data(as_text=True)
        assert "from a reservation" in page, "the subnet came from what the caller may see, not from the hidden lease"
        assert "You do not have access to that subnet" not in page
        assert "192.168.1.50" in page, "the engine ran in subnet A from the reservation"
        for secret in (self.HIDDEN_IP, "hidden-lease-host", "HIDDEN-NET-B", "the current lease"):
            assert secret not in page, f"{secret!r}: the hidden lease reached the page"


class TestTheTabNamesTheExchange:
    """v5.68.0-beta.10 (Q145): what was read from Kea's log is one exchange on one server, and the tab says which."""

    def _view(self, **tx):
        return {
            **KEA_LOG,
            "server": {"id": 2, "name": "kea-b"},
            "transaction": {"tid": "0x9", "first": "2026-10-04 15:10:39.100", "at": "2026-10-04 15:10:39.670", "complete": True,
                            "before_config_change": False, **tx},
        }  # fmt: skip

    def test_it_says_which_exchange_and_which_server(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, monkeypatch
    ):
        monkeypatch.setattr(
            "jen.services.explain_context.read_log",
            lambda mac, *, allowed, fetch=True: self._view() if allowed else NO_LOG,
        )
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert "the one at 2026-10-04 15:10:39.670, transaction 0x9, on kea-b" in page
        assert "logged before the config last changed" not in page

    def test_an_exchange_from_before_a_config_change_says_so(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, monkeypatch
    ):
        monkeypatch.setattr(
            "jen.services.explain_context.read_log",
            lambda mac, *, allowed, fetch=True: self._view(before_config_change=True) if allowed else NO_LOG,
        )
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert "logged before the config last changed, so Kea may decide differently now" in page

    def test_a_log_that_never_names_the_client_says_so(
        self, logged_in_client, stub_config, mock_kea, lease_with_extras, monkeypatch
    ):
        empty = {
            "classes": None,
            "query": None,
            "cid": None,
            "state": "ok",
            "message": "",
            "transaction": None,
            "server": {"id": 1, "name": "kea-a"},
        }
        monkeypatch.setattr(
            "jen.services.explain_context.read_log", lambda mac, *, allowed, fetch=True: empty if allowed else NO_LOG
        )
        page = logged_in_client.get(f"/tools/explain?mac={MAC2}").get_data(as_text=True)
        assert (
            "Kea&#39;s log on kea-a does not show this client" in page
            or "Kea's log on kea-a does not show this client" in page
        )


class TestOption77AsBytesOnThePage:
    """v5.68.0-beta.10 (Q145): the same two class tests - one written for a length-prefixed client, one for a plain-text client - are
    undecided when only the text is known, and decided from the bytes when they are given (the values real Kea matched, kea-compat)."""

    LP = "08:6a:65:6e:2d:75:73:65:72"

    @pytest.fixture
    def two_forms(self, monkeypatch):
        cfg = dict(
            SMALL_CFG,
            **{
                "client-classes": [
                    {"name": "lp-class", "test": "option[77].hex == 0x086a656e2d75736572"},
                    {"name": "plain-class", "test": "option[77].hex == 'jen-user'"},
                ]
            },
        )
        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: cfg)

    def _rows(self, page):
        import re

        out = {}
        for name in ("lp-class", "plain-class"):
            m = re.search(rf'<td class="mono">{name}</td>\s*<td[^>]*>\s*(\w+)\s*</td>', page)
            out[name] = m.group(1) if m else None
        return out

    def test_text_only_leaves_both_undecided_and_names_the_bytes_as_what_would_settle_it(
        self, logged_in_client, two_forms, mock_kea, no_log
    ):
        page = logged_in_client.get("/tools/explain?mac=00:11:22:33:44:55&subnet=1&user_class=jen-user").get_data(
            as_text=True
        )
        assert self._rows(page) == {"lp-class": "undecided", "plain-class": "undecided"}
        assert "supply user class as sent (option 77 bytes, hex)" in page

    def test_length_prefixed_bytes_match_only_the_length_prefixed_test(
        self, logged_in_client, two_forms, mock_kea, no_log
    ):
        page = logged_in_client.get(
            f"/tools/explain?mac=00:11:22:33:44:55&subnet=1&user_class=jen-user&user_class_bytes={self.LP}"
        ).get_data(as_text=True)
        assert self._rows(page) == {"lp-class": "matched", "plain-class": "no"}

    def test_raw_bytes_match_only_the_plain_test(self, logged_in_client, two_forms, mock_kea, no_log):
        page = logged_in_client.get(
            "/tools/explain?mac=00:11:22:33:44:55&subnet=1&user_class_bytes=6a:65:6e:2d:75:73:65:72"
        ).get_data(as_text=True)
        assert self._rows(page) == {"lp-class": "no", "plain-class": "matched"}
