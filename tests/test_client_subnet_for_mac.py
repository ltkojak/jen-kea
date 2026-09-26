"""
tests/test_client_subnet_for_mac.py
─────────────────────────────────────
v5.65.6 (Q95) — plugin_api.client_subnet_for_mac: the ONE precedence for attributing a MAC
to a subnet. Wake, Presence and Switch Port each carried a private lookup with a slightly
different order (lease then reservation; device then lease then reservation); a plugin that
disagrees with Jen about where a client is authorises on the wrong subnet.

Precedence: current lease (state 0, not past its expiry) → reservation (a global one has no
subnet and says nothing) → the device's last known subnet → None.
"""

import pytest

from jen import plugin_api

MAC = "de:ad:be:ef:09:01"
HEX = "DEADBEEF0901"


@pytest.fixture
def clean(db):
    def wipe():
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (HEX,))
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (HEX,))
            cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        db.commit()

    wipe()
    yield db
    wipe()


def _lease(db, subnet, expire="DATE_ADD(NOW(), INTERVAL 1 HOUR)", state=0, ip="10.60.0.5"):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
            f"VALUES (INET_ATON(%s), UNHEX(%s), 3600, {expire}, %s, %s)",
            (ip, HEX, subnet, state),
        )
    db.commit()


def _reservation(db, subnet):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address) "
            "VALUES (UNHEX(%s), 0, %s, INET_ATON('10.60.0.99'))",
            (HEX, subnet),
        )
    db.commit()


def _device(db, subnet):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_subnet_id, device_name, first_seen, last_seen) "
            "VALUES (%s, '10.60.0.5', %s, 'dev', NOW(), NOW())",
            (MAC, subnet),
        )
    db.commit()


class TestPrecedence:
    def test_it_is_exported_and_listed(self):
        assert "client_subnet_for_mac" in plugin_api.__all__
        assert callable(plugin_api.client_subnet_for_mac)

    def test_nothing_known_is_none(self, clean):
        assert plugin_api.client_subnet_for_mac(MAC) is None
        assert plugin_api.client_subnet_for_mac("") is None
        assert plugin_api.client_subnet_for_mac(None) is None

    def test_a_current_lease_beats_a_reservation_and_a_device(self, clean):
        _lease(clean, 3)
        _reservation(clean, 2)
        _device(clean, 1)
        assert plugin_api.client_subnet_for_mac(MAC) == 3

    def test_a_reservation_beats_a_device(self, clean):
        _reservation(clean, 2)
        _device(clean, 1)
        assert plugin_api.client_subnet_for_mac(MAC) == 2

    def test_a_device_alone_is_enough(self, clean):
        _device(clean, 1)
        assert plugin_api.client_subnet_for_mac(MAC) == 1

    def test_an_expired_or_reclaimed_lease_is_not_current(self, clean):
        _lease(clean, 3, expire="DATE_SUB(NOW(), INTERVAL 1 HOUR)")
        _lease(clean, 4, state=2, ip="10.60.0.6")
        _device(clean, 1)
        assert plugin_api.client_subnet_for_mac(MAC) == 1

    def test_a_global_reservation_says_nothing_about_where_the_client_is(self, clean):
        _reservation(clean, 0)
        _device(clean, 1)
        assert plugin_api.client_subnet_for_mac(MAC) == 1
        with clean.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        clean.commit()
        assert plugin_api.client_subnet_for_mac(MAC) is None

    def test_case_and_whitespace_do_not_matter(self, clean):
        _lease(clean, 3)
        assert plugin_api.client_subnet_for_mac("  " + MAC.upper() + " ") == 3

    def test_an_unreadable_kea_table_is_a_missing_source_not_an_error(self, clean, monkeypatch):
        _device(clean, 1)

        def boom(*a, **k):
            raise RuntimeError("kea db down")

        # client_subject reaches the pool through the `jen.models.db` module, so this is the same name
        monkeypatch.setattr("jen.models.db.kea_db", boom)
        assert plugin_api.client_subnet_for_mac(MAC) == 1  # the device source still answers
