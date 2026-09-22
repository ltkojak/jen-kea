"""
tests/test_e2e_fake_kea.py
────────────────────────────
v5.54.0-era (Q62) — tests/e2e/_fake_kea_server.py's config-get body used to
be a hand-written literal. It's now built from the same subnet dict
conftest.py feeds `app_config.write_subnets()`, so this test pins that the
refactor produced byte-for-byte the same config the default (non-demo) e2e
run always served — the 22 existing journeys must never notice the change.

Pure, no DB, no Playwright: `py -m pytest --noconftest tests/test_e2e_fake_kea.py`.
"""

from tests.e2e._fake_kea_server import DEFAULT_RESPONSES, TWO_SUBNET_DHCP4, FakeKeaServer, build_dhcp4_config

ORIGINAL_LITERAL = {
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    "subnet4": [
        {
            "id": 1,
            "subnet": "10.99.0.0/24",
            "pools": [{"pool": "10.99.0.100 - 10.99.0.200"}],
            "option-data": [{"name": "routers", "data": "10.99.0.1"}],
        },
        {
            "id": 2,
            "subnet": "10.99.1.0/24",
            "pools": [{"pool": "10.99.1.100 - 10.99.1.200"}],
            "option-data": [{"name": "routers", "data": "10.99.1.1"}],
        },
    ],
    "hooks-libraries": [],
}


class TestDefaultDatasetUnchanged:
    def test_the_builder_reproduces_the_original_literal_exactly(self):
        assert TWO_SUBNET_DHCP4 == ORIGINAL_LITERAL

    def test_default_responses_config_get_still_serves_it(self):
        assert DEFAULT_RESPONSES["config-get"]["arguments"]["Dhcp4"] == ORIGINAL_LITERAL

    def test_a_server_with_no_override_serves_the_original_too(self):
        server = FakeKeaServer()
        server.start()
        try:
            assert server.responses["config-get"]["arguments"]["Dhcp4"] == ORIGINAL_LITERAL
        finally:
            server.stop()


class TestBuildDhcp4Config:
    def test_dns_is_optional_per_subnet(self):
        cfg = build_dhcp4_config(
            {1: {"name": "A", "cidr": "10.0.1.0/24"}, 2: {"name": "B", "cidr": "10.0.2.0/24"}},
            routers={1: "10.0.1.1", 2: "10.0.2.1"},
            dns={1: "10.0.1.53,9.9.9.9"},
        )
        opts = {s["id"]: s["option-data"] for s in cfg["subnet4"]}
        assert {"name": "domain-name-servers", "data": "10.0.1.53,9.9.9.9"} in opts[1]
        assert all(o["name"] != "domain-name-servers" for o in opts[2])

    def test_pool_range_and_valid_lifetime_are_per_subnet(self):
        cfg = build_dhcp4_config(
            {10: {"name": "X", "cidr": "10.20.10.0/24"}},
            routers={10: "10.20.10.1"},
            pool_range={10: (100, 220)},
            valid_lifetime={10: 604800},
        )
        s = cfg["subnet4"][0]
        assert s["pools"] == [{"pool": "10.20.10.100 - 10.20.10.220"}]
        assert s["valid-lifetime"] == 604800
        assert cfg["valid-lifetime"] == 3600  # the top-level default is untouched

    def test_a_subnet_outside_valid_lifetime_keeps_only_the_top_level_default(self):
        cfg = build_dhcp4_config({1: {"name": "A", "cidr": "10.0.1.0/24"}}, routers={1: "10.0.1.1"})
        assert "valid-lifetime" not in cfg["subnet4"][0]

    def test_a_dhcp4_config_override_is_served_by_config_get(self):
        cfg = build_dhcp4_config({5: {"name": "Z", "cidr": "10.5.0.0/24"}}, routers={5: "10.5.0.1"})
        server = FakeKeaServer(dhcp4_config=cfg)
        server.start()
        try:
            assert server.responses["config-get"]["arguments"]["Dhcp4"] == cfg
            # every other default response (version-get, status-get, ...) is untouched
            assert server.responses["version-get"] == DEFAULT_RESPONSES["version-get"]
        finally:
            server.stop()
