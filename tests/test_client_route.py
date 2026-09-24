"""
tests/test_client_route.py
────────────────────────────
v5.63.0 (Q82) — GET /client: identifier resolution end to end (found,
not-found, ambiguous-hostname candidates, subnet-denied), each tab
renders without error, and Trace's gate is enforced the same way the
standalone /tools/trace page enforces it.
"""

import pytest

MAC = "aa:bb:cc:dd:ef:10"
MAC_HEX = "AABBCCDDEF10"
IP = "10.45.0.5"

CFG = {
    "valid-lifetime": 3600,
    "option-data": [{"name": "domain-name-servers", "data": "1.1.1.1"}],
    "subnet4": [{"id": 1, "subnet": "10.45.0.0/24", "pools": [{"pool": "10.45.0.2 - 10.45.0.200"}]}],
}


@pytest.fixture
def stub_config(monkeypatch):
    monkeypatch.setattr("jen.routes.client.dhcp4_config", lambda force=False: CFG)


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
    db.commit()


@pytest.fixture
def seeded(db):
    _clean(db)
    with db.cursor() as cur:
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC, IP))
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
            "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
            (IP, MAC_HEX),
        )
    db.commit()
    yield
    _clean(db)


class TestNoIdentifier:
    def test_blank_form_renders(self, logged_in_client):
        r = logged_in_client.get("/client")
        assert r.status_code == 200
        assert b"Investigate a client" in r.data


class TestResolution:
    def test_found_mac_shows_tabs(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        body = r.data.decode()
        assert MAC in body
        for tab in ("Overview", "Explain", "Trace", "Timeline", "Dns", "Config"):
            assert tab in body

    def test_found_by_ip_resolves_the_holder(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={IP}")
        assert r.status_code == 200
        assert MAC in r.data.decode()

    def test_not_found_shows_a_message(self, logged_in_client, db):
        _clean(db)
        r = logged_in_client.get("/client?q=aa:bb:cc:dd:ef:99")
        assert r.status_code == 200
        assert b"No client matched" in r.data

    def test_ambiguous_hostname_shows_candidates(self, logged_in_client, db):
        _clean(db)
        other = "aa:bb:cc:dd:ef:11"
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'dupe-host', 1)", (MAC,))
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'dupe-host', 1)", (other,)
            )
        db.commit()
        try:
            r = logged_in_client.get("/client?q=dupe-host")
            assert r.status_code == 200
            body = r.data.decode()
            assert "More than one client" in body
            assert MAC in body and other in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC, other))
            db.commit()


class TestSubnetRestriction:
    def test_restricted_viewer_outside_the_subnet_is_denied(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_client_viewer")
        r = client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        body = r.data.decode()
        assert "do not have access" in body
        assert IP not in body

    def test_restricted_viewer_inside_the_subnet_sees_it(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_client_viewer2")
        r = client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        assert IP in r.data.decode()


class TestTabs:
    def test_overview_tab_lists_leases_and_reservations(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=overview")
        assert IP in r.data.decode()

    def test_explain_tab_embeds_via_htmx(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=explain")
        assert b"hx-get=" in r.data
        assert b"/tools/explain?mac=" in r.data

    def test_timeline_tab_embeds_via_htmx(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=timeline")
        assert b"hx-get=" in r.data
        assert b"/timeline?mac=" in r.data

    def test_trace_tab_embeds_via_htmx_for_an_unrestricted_admin(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=trace")
        assert b"/tools/trace?mac=" in r.data

    def test_trace_tab_refuses_a_restricted_admin(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_client_trace_admin")
        r = client.get(f"/client?q={MAC}&tab=trace")
        assert r.status_code == 200
        assert b"Trace needs admin access to every subnet" in r.data

    def test_dns_tab_with_no_hostname_says_so(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=dns")
        assert b"no named reservation or lease" in r.data

    def test_config_tab_shows_the_evaluation(self, logged_in_client, seeded, stub_config):
        r = logged_in_client.get(f"/client?q={MAC}&tab=config")
        assert r.status_code == 200
        assert b"Effective configuration" in r.data

    def test_an_invalid_tab_falls_back_to_overview(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=nonsense")
        assert r.status_code == 200
        assert IP in r.data.decode()


class TestNavAndRowLinks:
    def test_nav_points_here(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parent.parent
        assert '"url": "/client"' in (repo / "jen" / "routes" / "settings" / "nav.py").read_text(encoding="utf-8")

    def test_row_menus_offer_investigate(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parent.parent
        for name in ("_lease_rows.html", "_reservation_row.html", "_device_rows.html"):
            assert "/client?q=" in (repo / "templates" / name).read_text(encoding="utf-8"), name
