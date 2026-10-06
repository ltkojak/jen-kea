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
    SW_B,
    SW_D,
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


class TestAScopedCallerCannotTellThatAHiddenNewerPositionExists:
    """v5.68.0-beta.14 (Q149): 1.1.2 said "was last seen on" / "Last seen on" instead of "is on" / "On" only when the newest position was
    on a switch the caller may not see - a tell. A scoped caller's page, card and API are built from the visible positions alone, so they
    are IDENTICAL with the hidden newer position and without it."""

    @staticmethod
    def _located_block(body):
        import re

        match = re.search(r'<div class="alert alert-info mt-2">.*?</div>', body, re.S)
        return re.sub(r"\s+", " ", match.group(0)) if match else ""

    @staticmethod
    def _card(body):
        import re

        match = re.search(r'data-plugin-card="switchport".*?</table>', body, re.S)
        return re.sub(r"\s+", " ", match.group(0)) if match else ""

    def _everything(self, pclient, db, headers):
        page_body = page(pclient, db, "admin_A", f"{SP}/?mac={A_MAC}")
        overview = page(pclient, db, "admin_A", f"/client?q={A_MAC}")
        r = pclient.get(
            f"{API}/{A_MAC}", headers=headers
        )  # `login` inserts an API key row: once per test, never per call
        return self._located_block(page_body), self._card(overview), (r.status_code, r.get_json() or {})

    def test_the_page_the_card_and_the_api_are_the_same_with_and_without_the_hidden_newer_position(
        self, pclient, db, stored_objects
    ):
        headers = login(pclient, db, "key_read")
        with_b = self._everything(pclient, db, headers)
        with db.cursor() as cur:
            cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s", (SW_B,))
        db.commit()
        without_b = self._everything(pclient, db, headers)
        assert with_b[0] and with_b[0] == without_b[0], "the page's located block"
        assert S1 + "-sw-a" in with_b[1] and with_b[1] == without_b[1], "the Investigation card"
        assert with_b[2] == without_b[2] and with_b[2][1]["switch"] == S1 + "-sw-a", "the API answer"
        assert "was last seen on" in with_b[0] and " is on " not in with_b[0]
        assert "Last seen on" in with_b[1] and "On " + S1 not in with_b[1]

    def test_an_unrestricted_caller_keeps_is_on_when_the_newest_position_is_theirs(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_all", f"{SP}/?mac={A_MAC}")
        assert "is on" in body and S1 + "-sw-b" in body


class TestDirection2PositionOnAnASwitchClientNowInB:
    def test_it_is_the_a_callers_to_see_on_every_surface_whatever_subnet_the_client_is_in(
        self, pclient, db, stored_objects
    ):
        body = page(pclient, db, "admin_A", f"{SP}/?mac={D_MAC}")
        assert S2 + "-sw" in body and "was last seen on" in body, "a scoped caller never gets an 'is on' claim (v1.1.3)"
        assert_no_marker(body)
        assert S2 + "-sw" in _search(pclient, db, "admin_A", D_MAC)
        status, api = _api(pclient, db, "key_read", D_MAC)
        assert status == 200 and api["switch"] == S2 + "-sw"

    def test_a_caller_scoped_to_b_is_not_given_it_although_the_client_is_in_b(self, pclient, db, stored_objects):
        body = page(pclient, db, "admin_B", f"{SP}/?mac={D_MAC}")
        assert S2 + "-sw" not in body and "No switch has reported" in body
        assert S2 + "-sw" not in _search(pclient, db, "admin_B", D_MAC)


class TestAMoveIsAnnouncedWhereItsSwitchesAre:
    """v5.68.0-beta.15 (Q150, Switch Port Locator 1.1.4). The move alert and its Timeline event name two switches and two ports; they were sent with
    the subnet of the CLIENT's lease, so the names of switches in B reached a channel and a Timeline scoped to A. Now: both switches in one
    attributable subnet -> that subnet; different subnets, or either unattributable -> subnet None, the alert `scoped=True` (a channel with a subnet
    scope never receives it) and the event unrestricted-only. Run through Jen's REAL alert filter and the real events table."""

    SENT = None

    def _world(self, monkeypatch, db):
        import json
        import sys

        from jen.services import alerts

        module = sys.modules["jen_plugin_switchport"]
        sent = []
        channels = [
            {"id": "A", "channel_type": "ntfy", "alert_types": ["switchport_moved"], "subnet_scope": json.dumps([1])},
            {"id": "B", "channel_type": "ntfy", "alert_types": ["switchport_moved"], "subnet_scope": json.dumps([2])},
            {"id": "all", "channel_type": "ntfy", "alert_types": ["switchport_moved"], "subnet_scope": None},
        ]
        monkeypatch.setattr(alerts, "get_active_channels", lambda: channels)
        monkeypatch.setattr(alerts, "get_channel_config", lambda ch: {"who": ch["id"]})
        monkeypatch.setattr(alerts, "_send_ntfy_channel", lambda message, config: sent.append(config["who"]) or True)
        with db.cursor() as cur:
            cur.execute("DELETE FROM events WHERE kind='plugin.switchport.moved' AND mac=%s", (A_MAC,))
        db.commit()
        return module, sent

    def _event_subnet(self, db):
        with db.cursor() as cur:
            cur.execute(
                "SELECT subnet_id FROM events WHERE kind='plugin.switchport.moved' AND mac=%s ORDER BY id DESC LIMIT 1",
                (A_MAC,),
            )
            row = cur.fetchone()
        return row["subnet_id"] if row else "no event"

    def test_a_client_in_a_moving_between_a_b_switch_and_an_a_switch_tells_only_unrestricted_channels(
        self, plugin_app, db, stored_objects, monkeypatch
    ):
        module, sent = self._world(monkeypatch, db)
        with plugin_app.app_context():
            module._emit_move(A_MAC, (SW_B, 1), (SW_A, 1))  # the client's lease is in A; the switches are in B and in A
        assert sent == ["all"], "neither the A-scoped nor the B-scoped channel is told about switches in two subnets"
        assert self._event_subnet(db) is None, "and the Timeline entry is for unrestricted viewers"

    def test_both_switches_in_a_is_a_moves_in_a(self, plugin_app, db, stored_objects, monkeypatch):
        module, sent = self._world(monkeypatch, db)
        with plugin_app.app_context():
            module._emit_move(A_MAC, (SW_A, 1), (SW_D, 1))  # SW_A and SW_D are both in A
        assert sorted(sent) == ["A", "all"], "the A channel and the unrestricted one; never the B channel"
        assert self._event_subnet(db) == 1

    def test_the_clients_own_subnet_decides_nothing(self, plugin_app, db, stored_objects, monkeypatch):
        """A client currently in B moving between two A switches is an A move, whatever the lease says."""
        module, sent = self._world(monkeypatch, db)
        monkeypatch.setattr(module, "_current_subnet_for_mac", lambda mac: 2)
        with plugin_app.app_context():
            module._emit_move(A_MAC, (SW_A, 1), (SW_D, 1))
        assert sorted(sent) == ["A", "all"] and self._event_subnet(db) == 1
