"""
tests/test_preview_transport_routes.py
──────────────────────────────────────
Q217 (AB7) - the previews of a change validate on the server's OWN write mode. An api server with NO SSH host previews a subnet edit and a client class (it used to read "config test passed" only
for a server with SSH, and the other two previews could not run at all); a Read-only server with SSH is told, in words, that nothing was validated against it. The daemon is a real stateful fake
(`tests/e2e/_fake_kea_server.py`); the route is the real one. DB-backed (login), so it runs in CI.
"""

import copy

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_host
from tests import _kea_api_world as world
from tests._kea_host_fakes import FakeHelper
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer


@pytest.fixture
def daemon():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.start()
    yield f
    f.stop()


@pytest.fixture(autouse=True)
def _world(monkeypatch):
    world.install_store(monkeypatch)
    world.install_probes(monkeypatch)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 2.0)
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "Office", "cidr": "10.99.0.0/24"}})
    monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data", lambda sid: {"pool_str": "", "pools": []})


def _server(daemon, **extra):
    return {"id": 1, "name": "kea-a", "api_url": daemon.url, "config_transport": "api", **extra}


class TestASubnetEditPreviewOnAnApiServerWithNoSsh:
    def test_the_daemon_validates_it(self, logged_in_client, monkeypatch, daemon):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [_server(daemon)])
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.99.0.10-10.99.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["all_passed"] is True and data["servers"][0]["message"] == "Config test passed", data
        assert "config-test" in daemon.commands

    def test_a_refusal_by_the_daemon_is_the_message(self, logged_in_client, monkeypatch, daemon):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [_server(daemon)])
        daemon.test_fails = "bad pool range"
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.99.0.10-10.99.0.200"})
        data = r.get_json()
        assert data["all_passed"] is False and "bad pool range" in data["servers"][0]["message"], data


class TestAClassPreviewOnAnApiServerWithNoSsh:
    FORM = {"is_new": "1", "orig_name": "", "name": "voice", "mode": "advanced", "test": "1 == 1"}

    def test_the_daemon_validates_it(self, logged_in_client, monkeypatch, daemon):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [_server(daemon)])
        r = logged_in_client.post("/subnets/classes/preview", data=self.FORM)
        assert r.status_code == 200 and b"Kea accepted this config" in r.data
        assert "config-test" in daemon.commands

    def test_a_read_only_server_with_ssh_is_not_validated_and_says_so(self, logged_in_client, monkeypatch, daemon):
        server = _server(daemon, ssh_host="10.0.0.5", config_transport="off")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": copy.deepcopy(daemon.running)}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        r = logged_in_client.post("/subnets/classes/preview", data=self.FORM)
        assert r.status_code == 200 and b"Read-only" in r.data
        assert "test-config" not in fake.ops() and "config-test" not in daemon.commands

    def test_a_write_target_is_validated_before_a_read_only_host_that_merely_has_ssh(
        self, logged_in_client, monkeypatch, daemon
    ):
        """Q217, second pass row 9: the Read-only host is listed FIRST and the Live API server is still the one the preview asks."""
        read_only = {
            "id": 2,
            "name": "kea-ro",
            "api_url": "http://127.0.0.1:9",
            "ssh_host": "10.0.0.5",
            "config_transport": "off",
        }
        monkeypatch.setattr(extensions, "KEA_SERVERS", [read_only, _server(daemon)])
        monkeypatch.setattr(
            kea_host,
            "read_via_transport",
            lambda server, service, **kw: (copy.deepcopy({"Dhcp4": daemon.running}), "d"),
        )
        r = logged_in_client.post("/subnets/classes/preview", data=self.FORM)
        assert r.status_code == 200 and b"Kea accepted this config" in r.data and "config-test" in daemon.commands
