"""
tests/test_stored_objects_switchport.py
────────────────────────────────────────
v5.68.0-beta.12 (Q147) — Switch Port Locator 1.1.2 through the page, the search and the JSON API, in BOTH directions of the moved-client
fixture (tests/stored_object_fixtures.py). Every stored position is judged by its OWN switch's subnet through the one `positions_in_scope`;
where the client is now decides nothing. Direction 1: the newest position of the client now in A is on a switch in B, an older one on a switch
in A - the A caller is given the A switch only. Only-B: nothing at all, the same answer as a MAC no switch has reported.
"""

# ruff: noqa: F811 - the fixtures are imported by name (the same way tests/test_authz_matrix_plugins.py imports its own)

import json

import pytest

from tests.stored_object_fixtures import (  # noqa: F401 - fixtures are used by name
    D_MAC,
    S1,
    S2,
    SW_A,
    login,
    page,
    stored_objects,
)
from tests.test_authz_matrix import (  # noqa: F401
    A_MAC,
    _caller,
    _subnets,
    assert_no_marker,
    seeded,
)
from tests.test_authz_matrix_plugins import pclient, plugin_app, plugin_data  # noqa: F401

pytestmark = pytest.mark.usefixtures("seeded")

SP = "/network/switchport"
API = "/api/v1/plugins/switchport/locate"


def _api(pclient, db, role, mac):
    headers = login(pclient, db, role)
    r = pclient.get(f"{API}/{mac}", headers=headers)
    return r.status_code, (r.get_json() or {})


def _search(pclient, db, role, mac):
    return page(pclient, db, role, f"/search?q={mac}&list=1")


class TestDirection1NewestPositionOnABSwitchClientNowInA:
    def test_the_page_gives_a_caller_scoped_to_a_the_a_switch_only(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_A", f"{SP}/?mac={A_MAC}")
        assert S1 + "-sw-a" in body and "Gi1/0/7" in body
        assert S1 + "-sw-b" not in body and "Gi2/0/9" not in body
        assert "was last seen on" in body, "the newest position was hidden, so the page says last seen, not is on"
        assert_no_marker(body)

    def test_the_search_gives_the_a_switch_only(self, pclient, db, stored_objects):
        body = _search(pclient, db, "admin_A", A_MAC)
        assert S1 + "-sw-a" in body and S1 + "-sw-b" not in body and "Gi2/0/9" not in body

    def test_the_api_gives_a_scoped_key_the_a_switch_only(self, pclient, db, stored_objects):
        status, body = _api(pclient, db, "key_read", A_MAC)
        assert status == 200 and body["located"] is True and body["switch"] == S1 + "-sw-a" and body["vlan"] == 20
        assert S1 + "-sw-b" not in json.dumps(body)

    def test_an_unrestricted_caller_is_given_the_newest_position_and_the_b_scoped_owner_its_own(
        self, pclient, db, stored_objects
    ):
        everything = page(pclient, db, "admin_all", f"{SP}/?mac={A_MAC}")
        assert S1 + "-sw-b" in everything and "is on" in everything
        owner = page(pclient, db, "admin_B", f"{SP}/?mac={A_MAC}")
        assert S1 + "-sw-b" in owner and S1 + "-sw-a" not in owner

    def test_when_the_only_positions_are_on_b_switches_nothing_is_located_on_any_surface(
        self, pclient, db, stored_objects
    ):
        with db.cursor() as cur:
            cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s", (SW_A,))
        db.commit()
        body = page(pclient, db, "admin_A", f"{SP}/?mac={A_MAC}")
        assert "No switch has reported" in body and S1 + "-sw-b" not in body and "Gi2/0/9" not in body
        assert_no_marker(body)
        assert S1 + "-sw-b" not in _search(pclient, db, "admin_A", A_MAC)
        status, api = _api(pclient, db, "key_read", A_MAC)
        assert status == 200 and api == {"mac": A_MAC, "located": False}, "the answer a MAC no switch has reported gets"


class TestDirection2PositionOnAnASwitchClientNowInB:
    def test_it_is_the_a_callers_to_see_on_every_surface_whatever_subnet_the_client_is_in(
        self, pclient, db, stored_objects
    ):
        body = page(pclient, db, "admin_A", f"{SP}/?mac={D_MAC}")
        assert S2 + "-sw" in body and "is on" in body
        assert_no_marker(body)
        assert S2 + "-sw" in _search(pclient, db, "admin_A", D_MAC)
        status, api = _api(pclient, db, "key_read", D_MAC)
        assert status == 200 and api["switch"] == S2 + "-sw"

    def test_a_caller_scoped_to_b_is_not_given_it_although_the_client_is_in_b(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_B", f"{SP}/?mac={D_MAC}")
        assert S2 + "-sw" not in body and "No switch has reported" in body
        assert S2 + "-sw" not in _search(pclient, db, "admin_B", D_MAC)
