"""
tests/test_investigation_logging_routes.py
───────────────────────────────────────────
v5.68.0-beta.3 (Q138) — the buttons, the banners and the access rule for investigation logging. The service itself (reload, restart,
sweep) is tested without a database in tests/test_investigation_logging.py; here it is stubbed and what is under test is who may press
the button, where the person lands, and what each page shows while it is on.
"""

import pytest

from jen import extensions

SERVER = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
ON = {
    "server_id": "1",
    "name": "kea-a",
    "until": "2026-10-04T12:15:00+00:00",
    "remaining_s": 900,
    "overdue": False,
    "by": "admin",
    "mode": "reload",
    "error": "",
}


@pytest.fixture
def stubs(monkeypatch):
    """One SSH server, the service's turn_on/turn_off recorded, nothing active."""
    from jen.services import investigation_logging as inv

    monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(SERVER)])
    calls = []
    monkeypatch.setattr(
        inv,
        "turn_on",
        lambda server, minutes, actor="": (
            calls.append(("on", server["id"], minutes, actor))
            or {
                "ok": True,
                "mode": "reload",
                "lines": ["✅ investigation logging on for 15 min"],
                "until": "2026-10-04T12:15:00+00:00",
            }
        ),
    )
    monkeypatch.setattr(
        inv,
        "turn_off",
        lambda server, actor="", reason="": (
            calls.append(("off", server["id"], actor)) or {"ok": True, "mode": "reload", "lines": ["✅ off"]}
        ),
    )
    monkeypatch.setattr(inv, "active", lambda now=None: [])
    return calls


class TestWhoMayPressIt:
    def test_an_unrestricted_admin_turns_it_on_for_one_server_and_lands_on_servers(self, logged_in_client, stubs):
        r = logged_in_client.post("/servers/1/investigation-logging/on", data={"minutes": "15", "back": "servers"})
        assert r.status_code == 302 and r.headers["Location"].endswith("/servers")
        assert stubs == [("on", 1, 15, "admin")]

    def test_it_goes_back_to_the_trace_page_it_came_from(self, logged_in_client, stubs):
        r = logged_in_client.post(
            "/servers/1/investigation-logging/on", data={"minutes": "5", "back": "trace", "mac": "AA:BB:CC:DD:EE:01"}
        )
        location = r.headers["Location"]
        assert "/tools/trace" in location and "mac=aa:bb:cc:dd:ee:01" in location and "server=1" in location

    def test_back_is_an_allowlist_never_a_url(self, logged_in_client, stubs):
        r = logged_in_client.post(
            "/servers/1/investigation-logging/on", data={"minutes": "5", "back": "https://evil.example/x"}
        )
        assert r.headers["Location"].endswith("/servers")

    def test_off(self, logged_in_client, stubs):
        logged_in_client.post("/servers/1/investigation-logging/off", data={"back": "servers"})
        assert stubs == [("off", 1, "admin")]

    def test_a_viewer_cannot(self, client, db, stubs):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="_inv_viewer")
        r = client.post("/servers/1/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"admin access required" in r.data.lower() and stubs == []

    def test_anonymous_is_sent_to_login(self, client, stubs):
        r = client.post("/servers/1/investigation-logging/on", data={"minutes": "5"})
        assert r.status_code in (301, 302, 308) and "login" in r.headers["Location"].lower() and stubs == []

    def test_an_admin_scoped_to_some_subnets_cannot_the_log_names_every_client(self, client, db, stubs):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_inv_scoped_admin")
        r = client.post("/servers/1/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"needs access to all subnets" in r.data and stubs == []

    def test_an_unknown_action_is_a_404(self, logged_in_client, stubs):
        assert logged_in_client.post("/servers/1/investigation-logging/maybe").status_code == 404

    def test_a_server_without_ssh_is_refused(self, logged_in_client, stubs, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": ""}])
        r = logged_in_client.post("/servers/1/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"needs a Kea server with SSH" in r.data and stubs == []

    def test_a_server_that_does_not_exist_is_refused(self, logged_in_client, stubs):
        r = logged_in_client.post("/servers/9/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"needs a Kea server with SSH" in r.data and stubs == []

    def test_a_failure_is_a_generic_message_not_the_exception(self, logged_in_client, stubs, monkeypatch):
        from jen.services import investigation_logging as inv

        def boom(*a, **k):
            raise RuntimeError("paramiko exploded at 10.0.0.5:22")

        monkeypatch.setattr(inv, "turn_on", boom)
        r = logged_in_client.post("/servers/1/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"Could not change the log level" in r.data and b"paramiko" not in r.data

    def test_a_service_refusal_is_shown_as_an_error(self, logged_in_client, stubs, monkeypatch):
        from jen.services import investigation_logging as inv

        monkeypatch.setattr(
            inv,
            "turn_on",
            lambda server, minutes, actor="": {"ok": False, "mode": "", "lines": ["already on for kea-b"], "until": ""},
        )
        r = logged_in_client.post("/servers/1/investigation-logging/on", data={"minutes": "5"}, follow_redirects=True)
        assert b"already on for kea-b" in r.data


class TestWhatThePagesShow:
    def _servers_page(self, client, monkeypatch):
        from jen.services import kea

        entry = {"server": dict(SERVER), "up": True, "ha_state": None, "version": "3.0.3", "role": "primary"}
        monkeypatch.setattr(kea, "get_all_server_status", lambda: [entry])
        return client.get("/servers").data.decode()

    def test_the_servers_page_offers_the_three_durations_to_an_unrestricted_admin(
        self, logged_in_client, stubs, mock_kea, monkeypatch
    ):
        page = self._servers_page(logged_in_client, monkeypatch)
        assert "/servers/1/investigation-logging/on" in page
        for minutes in (5, 15, 60):
            assert f'name="minutes" value="{minutes}"' in page
        assert "can fill the disk on a busy server" in page, "the 60-minute confirm names the disk"

    def test_while_it_is_on_the_card_offers_only_turning_it_off(self, logged_in_client, stubs, mock_kea, monkeypatch):
        from jen.services import investigation_logging as inv

        monkeypatch.setattr(inv, "active", lambda now=None: [ON])
        page = self._servers_page(logged_in_client, monkeypatch)
        assert "/servers/1/investigation-logging/off" in page and 'name="minutes"' not in page
        assert "ON for kea-a until 2026-10-04T12:15:00+00:00" in page

    def test_a_scoped_admin_is_not_offered_the_buttons(self, client, db, stubs, mock_kea, monkeypatch):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_inv_scoped_page")
        assert "investigation-logging" not in self._servers_page(client, monkeypatch)

    def test_the_banner_shows_on_servers_trace_dashboard_and_the_investigation_page(
        self, logged_in_client, stubs, mock_kea, monkeypatch
    ):
        from jen.services import investigation_logging as inv

        monkeypatch.setattr(inv, "active", lambda now=None: [ON])
        for path in ("/servers", "/tools/trace", "/", "/client"):
            page = logged_in_client.get(path).data.decode()
            assert "Investigation logging is on for kea-a" in page and "(15 min left)" in page, path
            assert "/servers/1/investigation-logging/off" in page, path

    def test_no_banner_on_a_page_that_has_nothing_to_do_with_it(self, logged_in_client, stubs, monkeypatch):
        from jen.services import investigation_logging as inv

        monkeypatch.setattr(inv, "active", lambda now=None: [ON])
        assert "Investigation logging is on" not in logged_in_client.get("/leases").data.decode()

    def test_an_overdue_one_says_so(self, logged_in_client, stubs, mock_kea, monkeypatch):
        from jen.services import investigation_logging as inv

        monkeypatch.setattr(inv, "active", lambda now=None: [{**ON, "overdue": True, "remaining_s": 0}])
        assert "has not been put back yet" in logged_in_client.get("/servers").data.decode()

    def test_a_viewer_never_sees_the_banner(self, client, db, stubs, monkeypatch):
        from jen.services import investigation_logging as inv
        from tests.conftest import restricted_client

        monkeypatch.setattr(inv, "active", lambda now=None: [ON])
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="_inv_viewer_banner")
        assert "Investigation logging is on" not in client.get("/").data.decode()

    def test_the_trace_page_carries_the_control_card_and_the_honest_description(self, logged_in_client, stubs):
        page = logged_in_client.get("/tools/trace").data.decode()
        assert (
            "Investigation logging" in page
            and "debuglevel 55" in page
            and "/servers/1/investigation-logging/on" in page
        )
        assert 'name="back" value="trace"' in page


class TestTheLiveWatch:
    """v5.68.0-beta.3 (Q138): 'Watch this client' polls every 3 s for ten minutes (it was 5 s for 60 s)."""

    def _page(self, client, monkeypatch, t, active=()):
        from jen.services import investigation_logging as inv
        from tests.test_kea_log_trace import EXCHANGE, MAC
        from tests.test_trace_route import _ok, _stub_tail

        monkeypatch.setattr(inv, "active", lambda now=None: list(active))
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        return client.get(
            "/tools/trace", query_string={"mac": MAC, "server": 1, "watch": 1, "t": t}, headers={"HX-Request": "true"}
        ).data.decode()

    def test_it_polls_every_three_seconds_and_says_for_how_long(self, logged_in_client, stubs, monkeypatch):
        page = self._page(logged_in_client, monkeypatch, 0)
        assert 'hx-trigger="every 3s"' in page and "&t=3" in page
        assert "refreshing every 3 s, stops after 10 minutes or when you leave the page" in page

    def test_the_server_stops_it_at_ten_minutes_whatever_the_page_does(self, logged_in_client, stubs, monkeypatch):
        assert 'hx-trigger="every 3s"' in self._page(logged_in_client, monkeypatch, 597)
        assert "hx-trigger" not in self._page(logged_in_client, monkeypatch, 600)

    def test_the_button_says_ten_minutes(self, logged_in_client, stubs):
        assert "Watch this client for 10 minutes" in logged_in_client.get("/tools/trace").data.decode()

    def test_with_logging_off_the_note_says_what_turning_it_on_would_add(self, logged_in_client, stubs, monkeypatch):
        page = self._page(logged_in_client, monkeypatch, 0)
        assert "Investigation logging on kea-a" in page and "adds the classes Kea assigned" in page

    def test_with_logging_on_it_does_not_say_it_again(self, logged_in_client, stubs, monkeypatch):
        page = self._page(logged_in_client, monkeypatch, 0, active=[ON])
        assert "adds the classes Kea assigned" not in page


class TestAServerRemovedFromJenWhileItWasOn:
    """v5.68.0-beta.9 (Q144): the Servers page says so, with the by-hand restore, and an admin who did it can tell Jen to stop reporting it."""

    ORPHAN = {
        **ON,
        "server_id": "7",
        "name": "gone-kea",
        "removed": True,
        "ssh_host": "10.9.9.9",
        "kea_conf": "/etc/kea/kea-dhcp4.conf",
        "file": "debug",
        "daemon": "debug",
        "pending": None,
        "stuck": False,
    }

    def _page(self, client, monkeypatch):
        from jen.services import investigation_logging as inv
        from jen.services import kea

        entry = {"server": dict(SERVER), "up": True, "ha_state": None, "version": "3.0.3", "role": "primary"}
        monkeypatch.setattr(kea, "get_all_server_status", lambda: [entry])
        monkeypatch.setattr(inv, "active", lambda now=None: [self.ORPHAN])
        return client.get("/servers").data.decode()

    def test_the_page_names_the_server_and_the_by_hand_restore(self, logged_in_client, stubs, mock_kea, monkeypatch):
        page = self._page(logged_in_client, monkeypatch)
        assert "may still be on on gone-kea, which was removed from Jen" in page
        assert "10.9.9.9" in page and "/etc/kea/kea-dhcp4.conf" in page and "jen-investigation" in page
        assert "/servers/investigation-logging/forget/7" in page

    def test_a_scoped_admin_is_not_shown_the_host_details(self, client, db, stubs, mock_kea, monkeypatch):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_inv_orphan_scoped")
        assert "10.9.9.9" not in self._page(client, monkeypatch)

    def test_forget_calls_the_service_and_lands_on_servers(self, logged_in_client, stubs, monkeypatch):
        from jen.services import investigation_logging as inv

        seen = []
        monkeypatch.setattr(inv, "forget", lambda server_id, actor="": seen.append((server_id, actor)) or True)
        r = logged_in_client.post("/servers/investigation-logging/forget/7")
        assert r.status_code == 302 and r.headers["Location"].endswith("/servers") and seen == [(7, "admin")]

    def test_a_viewer_and_a_scoped_admin_cannot_forget(self, client, db, stubs, monkeypatch):
        from jen.services import investigation_logging as inv
        from tests.conftest import restricted_client

        seen = []
        monkeypatch.setattr(inv, "forget", lambda server_id, actor="": seen.append(server_id) or True)
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="_inv_forget_viewer")
        client.post("/servers/investigation-logging/forget/7")
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_inv_forget_scoped")
        client.post("/servers/investigation-logging/forget/7")
        assert seen == []


class TestADamagedMarkerOnAServerJenCanStillReach:
    """v5.68.0-beta.14 (Q149): the marker that says how to put the log level back is itself damaged. The Servers page says so, links the
    Config history revision to start from, and offers Forget - which the service only accepts once the file no longer carries the marker."""

    DAMAGED = {
        **ON,
        "server_id": "7",
        "name": "live-kea",
        "removed": False,
        "marker_invalid": True,
        "history_revision": 41,
        "ssh_host": "10.9.9.8",
        "kea_conf": "/etc/kea/kea-dhcp4.conf",
        "file": "debug",
        "daemon": "debug",
        "pending": None,
        "stuck": False,
    }

    def _page(self, client, monkeypatch):
        from jen.services import investigation_logging as inv
        from jen.services import kea

        entry = {"server": dict(SERVER), "up": True, "ha_state": None, "version": "3.0.3", "role": "primary"}
        monkeypatch.setattr(kea, "get_all_server_status", lambda: [entry])
        monkeypatch.setattr(inv, "active", lambda now=None: [self.DAMAGED])
        return client.get("/servers").data.decode()

    def test_the_page_names_the_server_links_the_revision_and_offers_forget(
        self, logged_in_client, stubs, mock_kea, monkeypatch
    ):
        page = self._page(logged_in_client, monkeypatch)
        assert "The investigation-logging marker on live-kea is damaged" in page
        assert "/servers/7/config-history/41" in page and "Config history" in page
        assert "/servers/investigation-logging/forget/7" in page
        assert "`restore`" not in page, "the guidance never points at the damaged object"

    def test_a_scoped_admin_is_not_shown_the_host_details(self, client, db, stubs, mock_kea, monkeypatch):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_inv_damaged_scoped")
        assert "10.9.9.8" not in self._page(client, monkeypatch)
