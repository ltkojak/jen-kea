"""
tests/test_stored_objects_wol.py
─────────────────────────────────
v5.68.0-beta.12 (Q147) — Wake & Actions 1.1.2 through the real pages and API, in BOTH directions of the moved-client fixture
(tests/stored_object_fixtures.py): a favourite is a stored object judged on its OWN stored subnet by the list, add, delete and the wake from
the list; a WAKE is an act on a live host judged on where the host is now, and never borrows the SecureOn password of a favourite the caller
may not see. The packet is recorded instead of sent, with the SecureOn it would have carried.
"""

# ruff: noqa: F811 - the fixtures are imported by name (the same way tests/test_authz_matrix_plugins.py imports its own)

import json
import sys

import pytest

from tests.stored_object_fixtures import (  # noqa: F401 - fixtures are used by name
    D_MAC,
    S1,
    S2,
    SECUREON_BYTES,
    login,
    one,
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

WOL = "/management/wol"


@pytest.fixture
def packets(plugin_app):
    """(mac, directed-broadcast CIDR, SecureOn bytes or None) for every wake the plugin would have sent."""
    mod = sys.modules["jen_plugin_wol"]
    sent = []
    real = mod._send_wake
    mod._send_wake = lambda mac, cidr, secureon: sent.append((mac, cidr, secureon))
    mod._last_sent.clear()
    yield sent
    mod._send_wake = real
    mod._last_sent.clear()


def _favourite(db, mac):
    return one(db, "SELECT id, label, subnet_id FROM wol_hosts WHERE mac=%s", (mac,))


class TestDirection1StoredInBClientNowInA:
    def test_the_list_hides_it_from_a_caller_scoped_to_a_and_shows_it_to_the_owner_and_to_an_unrestricted_one(
        self, pclient, db, stored_objects
    ):
        body = page(pclient, db, "admin_A", WOL + "/")
        assert S1 + "-wol" not in body
        assert_no_marker(body)
        assert S1 + "-wol" in page(pclient, db, "admin_B", WOL + "/"), "its owner (scoped to B) sees it"
        everything = page(pclient, db, "admin_all", WOL + "/")
        assert S1 + "-wol" in everything and "now in" in everything and "Alpha-A" in everything

    def test_the_owner_is_not_told_where_the_client_is_now_when_it_is_a_subnet_they_cannot_see(
        self, pclient, db, stored_objects
    ):
        assert "now in" not in page(pclient, db, "admin_B", WOL + "/")

    def test_add_over_an_existing_favourite_cannot_rewrite_it(self, pclient, db, stored_objects):
        login(pclient, db, "admin_A")
        pclient.post(WOL + "/favourites/add", data={"mac": A_MAC, "label": "hijacked", "secureon": ""})
        assert _favourite(db, A_MAC)["label"] == S1 + "-wol"

    def test_delete_cannot_remove_it(self, pclient, db, stored_objects):
        fav = _favourite(db, A_MAC)
        login(pclient, db, "admin_A")
        pclient.post(f"{WOL}/favourites/{fav['id']}/delete")
        assert _favourite(db, A_MAC) is not None

    def test_waking_it_from_the_list_is_not_found_and_sends_nothing(self, pclient, db, stored_objects, packets):
        fav = _favourite(db, A_MAC)
        login(pclient, db, "admin_A")
        pclient.post(f"{WOL}/favourites/{fav['id']}/wake")
        assert packets == []

    def test_a_wake_of_the_host_itself_goes_ahead_without_the_hidden_favourites_password(
        self, pclient, db, stored_objects, packets
    ):
        login(pclient, db, "admin_A")
        pclient.post(f"{WOL}/wake?mac={A_MAC}")
        assert [(m, s) for m, _c, s in packets] == [(A_MAC, None)], "the host is in A: the wake goes, with no SecureOn"

    def test_the_wake_api_does_the_same_for_a_scoped_key(self, pclient, db, stored_objects, packets):
        headers = login(pclient, db, "key_write")
        r = pclient.post(
            "/api/v1/plugins/wol/wake", data=json.dumps({"mac": A_MAC}), headers=headers, follow_redirects=False
        )
        assert r.status_code == 200 and [(m, s) for m, _c, s in packets] == [(A_MAC, None)]

    def test_the_control_an_unrestricted_caller_may_see_the_favourite_so_its_password_is_used(
        self, pclient, db, stored_objects, packets
    ):
        login(pclient, db, "admin_all")
        pclient.post(f"{WOL}/wake?mac={A_MAC}")
        assert [(m, s) for m, _c, s in packets] == [(A_MAC, SECUREON_BYTES)]


class TestDirection2StoredInAClientNowInB:
    def test_the_list_shows_it_to_the_caller_scoped_to_a_without_naming_b(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_A", WOL + "/")
        assert S2 + "-wol" in body and D_MAC in body, "stored in A: it is theirs, whatever subnet the host is in now"
        assert "now in" not in body
        assert_no_marker(body)
        assert S2 + "-wol" not in page(pclient, db, "admin_B", WOL + "/")

    def test_it_can_be_relabelled_and_deleted_by_its_owner(self, pclient, db, stored_objects):
        login(pclient, db, "admin_A")
        pclient.post(WOL + "/favourites/add", data={"mac": D_MAC, "label": "renamed", "secureon": ""})
        fav = _favourite(db, D_MAC)
        assert fav["label"] == "renamed" and fav["subnet_id"] == 1, "relabelled, and still filed under A"
        pclient.post(f"{WOL}/favourites/{fav['id']}/delete")
        assert _favourite(db, D_MAC) is None

    def test_it_cannot_be_woken_because_the_host_is_now_on_a_network_the_caller_cannot_see(
        self, pclient, db, stored_objects, packets
    ):
        fav = _favourite(db, D_MAC)
        login(pclient, db, "admin_A")
        pclient.post(f"{WOL}/favourites/{fav['id']}/wake")
        pclient.post(f"{WOL}/wake?mac={D_MAC}")
        assert packets == []

    def test_nor_by_a_scoped_key(self, pclient, db, stored_objects, packets):
        headers = login(pclient, db, "key_write")
        r = pclient.post(
            "/api/v1/plugins/wol/wake", data=json.dumps({"mac": D_MAC}), headers=headers, follow_redirects=False
        )
        assert r.status_code in (403, 404) and packets == []
