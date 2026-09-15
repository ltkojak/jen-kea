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
