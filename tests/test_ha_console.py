"""
tests/test_ha_console.py
──────────────────────────
v5.21.0 (Q16) — the HA operations console: jen/services/kea_ha.py
(status-get normalization, HA config summary, per-subnet lease-count
comparison) and the POST /servers/ha/<id>/<action> route that sends the
allowlisted HA commands. `HA_ACTIONS` is the only door to a Kea HA
command — these tests confirm nothing outside it reaches `kea_command()`,
and that role gates (a mere admin can only heartbeat) are actually
enforced, not just documented.
"""

from jen.services import kea_ha
from tests.conftest import restricted_client as _restricted_client

# ── Fixtures shared by the service-layer and route tests ────────────────────

SERVERS = [
    {
        "id": 1,
        "name": "Primary",
        "role": "primary",
        "ssh_host": "",
        "ssh_user": "",
        "api_url": "http://localhost:18000",
        "api_user": "test",
        "api_pass": "test",
        "kea_conf": "",
    },
    {
        "id": 2,
        "name": "Standby",
        "role": "standby",
        "ssh_host": "",
        "ssh_user": "",
        "api_url": "http://localhost:18001",
        "api_user": "test",
        "api_pass": "test",
        "kea_conf": "",
    },
]

HA_DHCP4_CFG = {
    "hooks-libraries": [
        {
            "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
            "parameters": {
                "high-availability": [
                    {
                        "this-server-name": "server1",
                        "mode": "hot-standby",
                        "heartbeat-delay": 10000,
                        "max-response-delay": 60000,
                        "max-ack-delay": 5000,
                        "max-unacked-clients": 5,
                        "peers": [
                            {"name": "server1", "role": "primary"},
                            {"name": "server2", "role": "standby", "auto-failover": True},
                        ],
                    }
                ]
            },
        }
    ]
}


def _status_get_response(state="hot-standby", unacked_left=5):
    return {
        "result": 0,
        "arguments": {
            "high-availability": [
                {
                    "ha-servers": {
                        "local": {"role": "primary", "scopes": ["server1"], "state": state},
                        "remote": {
                            "role": "standby",
                            "age": 2,
                            "in-touch": True,
                            "last-scopes": ["server2"],
                            "last-state": state,
                            "connecting-clients": 0,
                            "unacked-clients": 0,
                            "unacked-clients-left": unacked_left,
                            "analyzed-packets": 42,
                        },
                    }
                }
            ]
        },
    }


# ── Pure / mocked-Kea service tests ──────────────────────────────────────────


class TestHaStatus:
    def test_normalizes_a_captured_status_get(self, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: _status_get_response())
        status = kea_ha.ha_status(SERVERS[0])
        assert status["local"] == {"role": "primary", "scopes": ["server1"], "state": "hot-standby"}
        assert status["remote"]["state"] == "hot-standby"
        assert status["remote"]["in_touch"] is True
        assert status["remote"]["unacked_clients_left"] == 5
        assert status["remote"]["analyzed_packets"] == 42

    def test_none_when_high_availability_absent(self, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "arguments": {}})
        assert kea_ha.ha_status(SERVERS[0]) is None

    def test_none_when_command_fails(self, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "unreachable"})
        assert kea_ha.ha_status(SERVERS[0]) is None


class TestHaConfig:
    def test_reads_the_ha_hook_parameters(self):
        cfg = kea_ha.ha_config(HA_DHCP4_CFG)
        assert cfg["this_server_name"] == "server1"
        assert cfg["mode"] == "hot-standby"
        assert cfg["heartbeat_delay"] == 10000
        assert len(cfg["peers"]) == 2
        assert cfg["peers"][1]["auto-failover"] is True

    def test_none_without_the_ha_hook(self):
        assert kea_ha.ha_config({"hooks-libraries": [{"library": "/x/libdhcp_lease_cmds.so"}]}) is None

    def test_none_with_no_hooks_at_all(self):
        assert kea_ha.ha_config({"hooks-libraries": []}) is None

    def test_none_with_no_config(self):
        assert kea_ha.ha_config(None) is None
        assert kea_ha.ha_config({}) is None


class TestPartnerName:
    def test_finds_the_other_peer_in_a_pair(self):
        cfg = kea_ha.ha_config(HA_DHCP4_CFG)
        assert kea_ha.partner_name(cfg) == "server2"

    def test_none_without_this_server_name(self):
        assert kea_ha.partner_name({"this_server_name": None, "peers": [{"name": "server2"}]}) is None

    def test_none_when_not_a_two_node_pair(self):
        cfg = {
            "this_server_name": "server1",
            "peers": [{"name": "server1"}, {"name": "server2"}, {"name": "server3"}],
        }
        assert kea_ha.partner_name(cfg) is None


class TestCompareAssigned:
    def test_matching_and_mismatching_subnets(self, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN"}, 2: {"name": "Guest"}})

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            counts = {"Primary": (10, 3), "Standby": (10, 4)}[server["name"]]
            return {
                "result": 0,
                "arguments": {
                    "subnet[1].assigned-addresses": [[counts[0], "t"]],
                    "subnet[2].assigned-addresses": [[counts[1], "t"]],
                },
            }

        monkeypatch.setattr(kea_svc, "kea_command", fake)
        rows = kea_ha.compare_assigned(SERVERS)
        by_id = {r["subnet_id"]: r for r in rows}
        assert by_id[1]["name"] == "LAN"
        assert by_id[1]["counts"] == {"Primary": 10, "Standby": 10}
        assert by_id[1]["mismatch"] is False
        assert by_id[2]["mismatch"] is True

    def test_empty_when_every_server_fails(self, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "down"})
        assert kea_ha.compare_assigned(SERVERS) == []


# ── Route: POST /servers/ha/<id>/<action> ────────────────────────────────────


def _wire(monkeypatch, kea_command):
    from jen import extensions
    from jen.services import kea as kea_svc

    monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(s) for s in SERVERS])
    monkeypatch.setattr(kea_svc, "kea_command", kea_command)


class TestHaActionRouteAuth:
    def test_requires_login(self, client):
        r = client.post("/servers/ha/1/heartbeat", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()

    def test_unknown_action_is_404(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, lambda *a, **kw: {"result": 0, "text": "ok"})
        r = logged_in_client.post("/servers/ha/1/not-a-real-action")
        assert r.status_code == 404

    def test_viewer_is_forbidden(self, client, db, monkeypatch):
        _wire(monkeypatch, lambda *a, **kw: {"result": 0, "text": "ok"})
        _restricted_client(client, db, allowed_subnets=None, role="viewer", username="ha_viewer1")
        r = client.post("/servers/ha/1/heartbeat")
        assert r.status_code == 403

    def test_admin_can_heartbeat_but_not_sync(self, client, db, monkeypatch):
        calls = []

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append(command)
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)
        _restricted_client(client, db, allowed_subnets=None, role="admin", username="ha_admin1")

        r = client.post("/servers/ha/1/heartbeat", follow_redirects=True)
        assert r.status_code == 200
        assert "ha-heartbeat" in calls

        r = client.post("/servers/ha/1/sync")
        assert r.status_code == 403

    def test_superadmin_can_do_every_action(self, logged_in_client, monkeypatch):
        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            if command == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": HA_DHCP4_CFG}}
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)
        for action in ("heartbeat", "sync", "continue", "maintenance-start", "maintenance-cancel", "reset"):
            r = logged_in_client.post(f"/servers/ha/1/{action}", follow_redirects=True)
            assert r.status_code == 200, f"{action} should be reachable by a superadmin"


class TestHaActionRouteBehavior:
    def test_each_action_sends_exactly_its_pinned_command(self, logged_in_client, monkeypatch):
        calls = []

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append((command, service, arguments, server.get("name")))
            if command == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": HA_DHCP4_CFG}}
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)

        logged_in_client.post("/servers/ha/1/heartbeat")
        assert ("ha-heartbeat", "dhcp4", {}, "Primary") in calls

        calls.clear()
        logged_in_client.post("/servers/ha/1/continue")
        assert ("ha-continue", "dhcp4", {}, "Primary") in calls

        calls.clear()
        logged_in_client.post("/servers/ha/1/maintenance-start")
        assert ("ha-maintenance-start", "dhcp4", {}, "Primary") in calls

        calls.clear()
        logged_in_client.post("/servers/ha/1/maintenance-cancel")
        assert ("ha-maintenance-cancel", "dhcp4", {}, "Primary") in calls

        calls.clear()
        logged_in_client.post("/servers/ha/1/reset")
        assert ("ha-reset", "dhcp4", {}, "Primary") in calls

    def test_sync_derives_the_partner_name_server_side(self, logged_in_client, monkeypatch):
        calls = []

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append((command, arguments))
            if command == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": HA_DHCP4_CFG}}
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)
        r = logged_in_client.post("/servers/ha/1/sync", follow_redirects=True)
        assert r.status_code == 200
        assert ("ha-sync", {"server-name": "server2", "max-period": 60}) in calls

    def test_sync_refuses_when_partner_cannot_be_determined(self, logged_in_client, monkeypatch):
        calls = []

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append(command)
            if command == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": {}}}  # no HA hook configured
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)
        r = logged_in_client.post("/servers/ha/1/sync", follow_redirects=True)
        assert r.status_code == 200
        assert "ha-sync" not in calls
        assert b"could not determine" in r.data.lower()

    def test_scopes_sends_the_checked_form_values(self, logged_in_client, monkeypatch):
        calls = []

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append((command, arguments))
            return {"result": 0, "text": "ok"}

        _wire(monkeypatch, fake)
        r = logged_in_client.post("/servers/ha/1/scopes", data={"scopes": ["server2"]}, follow_redirects=True)
        assert r.status_code == 200
        assert ("ha-scopes", {"scopes": ["server2"]}) in calls

    def test_scopes_refuses_with_nothing_checked(self, logged_in_client, monkeypatch):
        calls = []
        # follow_redirects=True lands back on GET /servers, which makes its
        # own version-get/ha-heartbeat/status-get/etc. calls through this
        # same stub — so the refusal is "ha-scopes never sent", not "calls
        # stayed empty".
        _wire(monkeypatch, lambda command, **kw: (calls.append(command), {"result": 0, "text": "ok"})[1])
        r = logged_in_client.post("/servers/ha/1/scopes", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert "ha-scopes" not in calls
        assert b"select at least one scope" in r.data.lower()

    def test_kea_error_shows_a_danger_flash_not_a_traceback(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, lambda *a, **kw: {"result": 1, "text": "HA service not configured for dhcp4"})
        r = logged_in_client.post("/servers/ha/1/heartbeat", follow_redirects=True)
        assert r.status_code == 200
        assert b"HA service not configured for dhcp4" in r.data

    def test_nonexistent_server_id(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, lambda *a, **kw: {"result": 0, "text": "ok"})
        r = logged_in_client.post("/servers/ha/999/heartbeat", follow_redirects=True)
        assert r.status_code == 200
        assert b"not found" in r.data.lower()

    def test_audit_row_written_per_action(self, logged_in_client, monkeypatch, db):
        _wire(monkeypatch, lambda *a, **kw: {"result": 0, "text": "heartbeat ok"})
        logged_in_client.post("/servers/ha/1/heartbeat", follow_redirects=True)
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='ha_heartbeat' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None
        assert row["details"] == "heartbeat ok"


# ── Page rendering ────────────────────────────────────────────────────────────


class TestServersPageHaPanel:
    def _wire_page(self, monkeypatch, ha_states):
        """ha_states: {server_name: status-get-arguments-or-None}."""
        from jen import extensions
        from jen.services import kea as kea_svc

        cfg = [dict(s) for s in SERVERS]
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(
            extensions.cfg,
            "get",
            lambda section, key, fallback=None: "hot-standby" if (section, key) == ("kea", "ha_mode") else fallback,
        )
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {"server": cfg[0], "up": True, "ha_state": "hot-standby", "ha_partner": "hot-standby", "version": ""},
                {"server": cfg[1], "up": True, "ha_state": "hot-standby", "ha_partner": "hot-standby", "version": ""},
            ],
        )

        def fake(command, service="dhcp4", arguments=None, server=None, timeout=10):
            if command == "status-get":
                state = ha_states.get(server["name"])
                return state if state is not None else {"result": 0, "arguments": {}}
            if command == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": {}}}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", fake)

    def test_ha_panel_shown_only_for_the_ha_enabled_server(self, logged_in_client, monkeypatch):
        self._wire_page(monkeypatch, {"Primary": _status_get_response(), "Standby": None})
        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert b"HA Status" in r.data
        assert r.data.count(b"HA Status") == 1

    def test_no_ha_panel_when_neither_server_has_the_hook(self, logged_in_client, monkeypatch):
        self._wire_page(monkeypatch, {"Primary": None, "Standby": None})
        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert b"HA Status" not in r.data

    def test_unacked_badge_shown_below_threshold(self, logged_in_client, monkeypatch):
        self._wire_page(monkeypatch, {"Primary": _status_get_response(unacked_left=1), "Standby": None})
        r = logged_in_client.get("/servers")
        assert b"partner-down imminent" in r.data

    def test_unacked_badge_absent_above_threshold(self, logged_in_client, monkeypatch):
        self._wire_page(monkeypatch, {"Primary": _status_get_response(unacked_left=5), "Standby": None})
        r = logged_in_client.get("/servers")
        assert b"partner-down imminent" not in r.data
