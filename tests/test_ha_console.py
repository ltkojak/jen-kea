"""
tests/test_ha_console.py
──────────────────────────
v5.21.0 (Q16) — the HA operations console. This step covers
jen/services/kea_ha.py: status-get normalization, the HA config
summary read from a Dhcp4 config map, partner-name derivation, and the
per-subnet lease-count comparison. Step 2 adds the route/page tests
for POST /servers/ha/<id>/<action> and the /servers HA panel.
"""

from jen.services import kea_ha

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
