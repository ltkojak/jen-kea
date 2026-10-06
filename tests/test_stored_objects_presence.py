"""
tests/test_stored_objects_presence.py
──────────────────────────────────────
v5.68.0-beta.12 (Q147) — Presence 1.2.0 through the real pages, in BOTH directions of the moved-client fixture
(tests/stored_object_fixtures.py). `pr_tracked.subnet_id` is the OWNER subnet: written when a device is tracked, changed only by an explicit
move by a caller who may see both subnets (an audit row), never by a lease event; the list, untrack and the card judge on it, and where the
device is now is derived at read time and shown only to a caller who may see that subnet.
"""

# ruff: noqa: F811 - the fixtures are imported by name (the same way tests/test_authz_matrix_plugins.py imports its own)

import pytest

from tests.stored_object_fixtures import (  # noqa: F401 - fixtures are used by name
    D_MAC,
    S1,
    S2,
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

PR = "/management/presence"


def _owner(db, mac):
    row = one(db, "SELECT subnet_id FROM pr_tracked WHERE mac=%s", (mac,))
    return row["subnet_id"] if row else None


class TestDirection1TrackedInBClientNowInA:
    def test_it_is_hidden_from_a_caller_scoped_to_a_and_visible_to_its_owner(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_A", PR + "/")
        assert S1 + "-pr" not in body
        assert_no_marker(body)
        owner = page(pclient, db, "admin_B", PR + "/")
        assert S1 + "-pr" in owner and "now in" not in owner, "the owner sees it and is not told the client is in A"
        everything = page(pclient, db, "admin_all", PR + "/")
        assert S1 + "-pr" in everything and "now in" in everything and "Alpha-A" in everything

    def test_a_caller_scoped_to_a_cannot_untrack_it(self, pclient, db, stored_objects):
        _caller(pclient, db, "admin_A")
        pclient.post(f"{PR}/untrack/{A_MAC}")
        assert _owner(db, A_MAC) == 2

    def test_a_lease_event_never_re_files_it_under_the_clients_current_subnet(self, plugin_app, db, stored_objects):
        import sys

        mod = sys.modules["jen_plugin_presence"]
        with plugin_app.app_context():
            for kind in ("lease.new", "lease.ip_changed", "lease.expired"):
                mod._on_lease_event({"mac": A_MAC, "kind": kind})
        assert _owner(db, A_MAC) == 2, "the client is in A; the tracking is owned by B and stays there"

    def test_only_an_explicit_move_by_a_caller_who_sees_both_subnets_changes_the_owner(
        self, pclient, db, stored_objects
    ):
        _caller(pclient, db, "admin_A")
        pclient.post(f"{PR}/move/{A_MAC}", data={"subnet_id": "1"})
        assert _owner(db, A_MAC) == 2, "an A-scoped caller cannot move what B owns, even into A"
        assert one(db, "SELECT id FROM audit_log WHERE action='PRESENCE_MOVE'") is None
        _caller(pclient, db, "admin_all")
        pclient.post(f"{PR}/move/{A_MAC}", data={"subnet_id": "1"})
        assert _owner(db, A_MAC) == 1
        audit = one(db, "SELECT details FROM audit_log WHERE action='PRESENCE_MOVE' AND entity=%s", (A_MAC,))
        assert audit and "2 -> 1" in audit["details"]
        assert S1 + "-pr" in page(pclient, db, "admin_A", PR + "/"), "now owned by A, so A's caller sees it"
        assert S1 + "-pr" not in page(pclient, db, "admin_B", PR + "/")

    def test_a_scoped_caller_cannot_move_a_device_into_a_subnet_they_cannot_see(self, pclient, db, stored_objects):
        _caller(pclient, db, "admin_all")
        pclient.post(f"{PR}/move/{A_MAC}", data={"subnet_id": "1"})  # now A's
        _caller(pclient, db, "admin_A")
        pclient.post(f"{PR}/move/{A_MAC}", data={"subnet_id": "2"})
        assert _owner(db, A_MAC) == 1


class TestDirection2TrackedInAClientNowInB:
    def test_the_owner_scoped_to_a_sees_it_without_being_told_about_b(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_A", PR + "/")
        assert S2 + "-pr" in body and "now in" not in body
        assert_no_marker(body)
        assert S2 + "-pr" not in page(pclient, db, "admin_B", PR + "/"), (
            "a caller scoped to B has no claim on A's tracking"
        )

    def test_the_owner_can_untrack_it(self, pclient, db, stored_objects):
        _caller(pclient, db, "admin_A")
        pclient.post(f"{PR}/untrack/{D_MAC}")
        assert _owner(db, D_MAC) is None

    def test_a_caller_scoped_to_b_cannot_untrack_it_even_though_the_client_is_in_b(self, pclient, db, stored_objects):
        from tests.stored_object_fixtures import as_admin_b

        as_admin_b(pclient, db)
        pclient.post(f"{PR}/untrack/{D_MAC}")
        assert _owner(db, D_MAC) == 1

    def test_the_owner_cannot_move_it_into_b(self, pclient, db, stored_objects):
        _caller(pclient, db, "admin_A")
        pclient.post(f"{PR}/move/{D_MAC}", data={"subnet_id": "2"})
        assert _owner(db, D_MAC) == 1
