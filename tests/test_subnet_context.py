"""
tests/test_subnet_context.py
────────────────────────────
v5.30.0 (Q30, A4) — jen/services/subnet_context.py: everything Jen
already knows about one subnet, in one call, for the plugins. Pure
tests: the config is passed in, the host-IP probes are patched.
"""

import pytest

from jen import extensions
from jen.services import subnet_context as sc

CFG = {
    "option-data": [{"name": "domain-name-servers", "code": 6, "data": "10.0.0.53, 1.1.1.1"}],
    "subnet4": [
        {
            "id": 1,
            "subnet": "10.0.0.0/24",
            "pools": [{"pool": "10.0.0.100 - 10.0.0.199"}, {"pool": "10.0.0.224/27"}],
            "option-data": [{"name": "routers", "code": 3, "data": "10.0.0.1"}],
        },
        {"id": 2, "subnet": "10.0.1.0/24", "pools": [{"pool": "10.0.1.50-10.0.1.60"}]},
    ],
    "shared-networks": [
        {
            "name": "office",
            "option-data": [{"name": "routers", "code": 3, "data": "10.0.2.254"}],
            "subnet4": [{"id": 3, "subnet": "10.0.2.0/24", "pools": []}],
        }
    ],
}


@pytest.fixture(autouse=True)
def _wire(monkeypatch):
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {
            1: {"name": "LAN", "cidr": "10.0.0.0/24"},
            2: {"name": "IoT", "cidr": "10.0.1.0/24"},
            3: {"name": "Office", "cidr": "10.0.2.0/24"},
        },
    )
    monkeypatch.setattr(
        extensions,
        "KEA_SERVERS",
        [
            {
                "id": 1,
                "ssh_host": "10.0.0.5",
                "api_url": "http://10.0.0.5:8000",
                "api6_url": "",
                "api_d2_url": "https://kea.lan:53001",
            }
        ],
    )
    monkeypatch.setattr(sc, "jen_host_ips", lambda: {"10.0.0.9", "192.168.50.2"})


class TestSubnetContext:
    def test_gateway_dns_pools_and_infrastructure(self):
        ctx = sc.subnet_context(1, dhcp4_cfg=CFG, with_notes=False)
        assert ctx["cidr"] == "10.0.0.0/24" and ctx["name"] == "LAN"
        assert ctx["gateways"] == ["10.0.0.1"]
        assert ctx["dns"] == ["10.0.0.53", "1.1.1.1"]  # global option inherited
        assert [(t) for _f, _l, t in ctx["pools"]] == ["10.0.0.100 - 10.0.0.199", "10.0.0.224/27"]
        assert ctx["kea_host_ips"] == {"10.0.0.5"}  # the DNS-named d2 URL is not an IP; api_url host is
        assert ctx["jen_host_ips"] == {"10.0.0.9"}  # only the address inside this subnet
        assert ctx["infrastructure"] == {
            "10.0.0.0": "network",
            "10.0.0.255": "broadcast",
            "10.0.0.1": "gateway",
            "10.0.0.53": "dns",
            "10.0.0.5": "kea-server",
            "10.0.0.9": "jen-host",
        }
        assert ctx["notes"] == ""

    def test_classify_and_in_pool(self):
        ctx = sc.subnet_context(1, dhcp4_cfg=CFG, with_notes=False)
        assert sc.classify_address(ctx, "10.0.0.1") == "gateway"
        assert sc.classify_address(ctx, "10.0.0.42") is None
        assert sc.in_pool(ctx, "10.0.0.150") and sc.in_pool(ctx, "10.0.0.230")
        assert not sc.in_pool(ctx, "10.0.0.42") and not sc.in_pool(ctx, "garbage")

    def test_shared_network_gateway_is_inherited(self):
        ctx = sc.subnet_context(3, dhcp4_cfg=CFG, with_notes=False)
        assert ctx["gateways"] == ["10.0.2.254"] and ctx["pools"] == []
        assert ctx["infrastructure"]["10.0.2.254"] == "gateway"

    def test_pool_without_spaces_and_no_gateway(self):
        ctx = sc.subnet_context(2, dhcp4_cfg=CFG, with_notes=False)
        assert ctx["gateways"] == [] and ctx["pools"][0][2] == "10.0.1.50 - 10.0.1.60"
        assert "10.0.1.1" not in ctx["infrastructure"]

    def test_unknown_subnet_is_none_and_no_config_is_tolerated(self, monkeypatch):
        assert sc.subnet_context(99, dhcp4_cfg=CFG) is None
        monkeypatch.setattr(sc, "dhcp4_config", lambda force=False: None)
        ctx = sc.subnet_context(1, with_notes=False)
        assert ctx["gateways"] == [] and ctx["pools"] == []
        assert ctx["infrastructure"]["10.0.0.5"] == "kea-server"  # still labelled without Kea

    @pytest.mark.parametrize(
        "pool,expected",
        [
            ("10.0.0.10 - 10.0.0.20", (167772170, 167772180, "10.0.0.10 - 10.0.0.20")),
            ("10.0.0.10-10.0.0.20", (167772170, 167772180, "10.0.0.10 - 10.0.0.20")),
            ("10.0.0.64/26", (167772224, 167772287, "10.0.0.64/26")),
            ("10.0.0.20 - 10.0.0.10", None),  # reversed
            ("10.9.0.0/24", None),  # not inside the subnet
            ("nonsense", None),
            ("", None),
        ],
    )
    def test_parse_pool(self, pool, expected):
        import ipaddress

        assert sc.parse_pool(pool, ipaddress.IPv4Network("10.0.0.0/24")) == expected

    def test_config_cache_is_used_within_ttl(self, monkeypatch):
        from jen.services import kea as kea_svc

        calls = []

        def fake_cmd(command, *a, **k):
            calls.append(command)
            return {"result": 0, "arguments": {"Dhcp4": CFG}}

        monkeypatch.setattr(kea_svc, "kea_command", fake_cmd)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})
        sc.invalidate_config_cache()
        assert sc.dhcp4_config() is CFG or sc.dhcp4_config() == CFG
        sc.dhcp4_config()
        sc.dhcp4_config()
        assert calls == ["config-get"]
        sc.invalidate_config_cache()
        sc.dhcp4_config()
        assert calls == ["config-get", "config-get"]
        sc.invalidate_config_cache()
