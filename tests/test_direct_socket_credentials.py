"""
tests/test_direct_socket_credentials.py
───────────────────────────────────────
v5.69.0-beta.13 (Q182, X4) - the direct-socket routes and CRED-004. Pure (`py -m pytest --noconftest tests/test_direct_socket_credentials.py`): a real temporary jen.config, the real
writer, the route's own edit function.

  * the pair that was pushed into the daemon's config and ANSWERED the probe is written as the endpoint's own when the resolver would withhold it at the new address (a socket set up by
    IP on a server Jen reaches by name) - never dropped (subagent S2);
  * `_daemon_creds` is `credentials.resolve`'s answer, at the address the endpoint is about to be given - there is no second decider (S3);
  * the routes type the ONE endpoint they repoint, not the server's three (so a second endpoint's password is not carried along unseen);
  * removing a socket leaves the user and password with no address, and the next address is a move that must be typed (S4b).
"""

import configparser

import pytest

from jen import extensions
from jen.config import AppConfig, ConfigChangeRefused, app_config
from jen.routes.settings import infrastructure as infra
from jen.services import credentials as cred
from jen.services import kea

HOSTNAME = """
[kea]
connection_mode = direct
api_url = http://kea-a.lan:8004
api_user = u
api_pass = S
[kea_db]
host = db1
user = k
password = KDB
[jen_db]
host = jh
user = j
password = JP
[server]
"""

PRIMARY = {"id": 1, "name": "kea-a", "api_url": "http://kea-a.lan:8004", "api_user": "u", "api_pass": "S"}


@pytest.fixture(autouse=True)
def _a_real_file(tmp_path, monkeypatch):
    path = tmp_path / "jen.config"
    path.write_text(HOSTNAME, encoding="utf-8")
    monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
    monkeypatch.setattr(app_config, "reload", lambda: None)
    monkeypatch.setattr("jen.config._identity_guards", [])
    return path


def _parse(text):
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


class TestTheProbedPairIsTheEndpointsOwn:
    def test_a_socket_set_up_by_ip_on_a_primary_named_by_hostname_keeps_the_pair_it_was_probed_with(self, _a_real_file):
        fn, changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "u", "S")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert on_disk.get("kea6", "api_url") == "http://10.0.0.5:8006"
        assert (on_disk.get("kea6", "api_user"), on_disk.get("kea6", "api_pass")) == ("u", "S")
        assert on_disk.get("kea6", "api_pass_shared") == "1"
        assert any("kea6" in c and "kept" in c for c in changed)
        servers = AppConfig.derive_kea_servers(on_disk, quiet=True)
        assert kea._endpoint_for(servers[0], "dhcp6") == ("http://10.0.0.5:8006", "u", "S"), (
            "what the transport sends is the pair the daemon answered the probe with"
        )

    def test_the_same_host_spelled_the_same_way_writes_no_override(self, _a_real_file):
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://kea-a.lan:8006", "u", "S")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert not on_disk.has_option("kea6", "api_pass") and cred.resolve(on_disk)["kea6"].password == "S"

    def test_a_pair_that_differs_from_the_servers_is_written_as_before(self, _a_real_file):
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "six", "6pw")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert (on_disk.get("kea6", "api_user"), on_disk.get("kea6", "api_pass")) == ("six", "6pw")
        assert not on_disk.has_option("kea6", "api_pass_shared")

    def test_an_additional_servers_d2_socket_by_ip_keeps_its_pair(self, _a_real_file):
        _a_real_file.write_text(
            HOSTNAME + "[kea_server_2]\nname = b\napi_url = http://kea-b.lan:8004\napi_user = su\napi_pass = SP\n",
            encoding="utf-8",
        )
        server = {"id": 2, "name": "b", "api_url": "http://kea-b.lan:8004", "api_user": "su", "api_pass": "SP"}
        fn, _changed = infra._direct_socket_edit(server, "d2", "http://10.0.0.6:53001", "su", "SP")
        app_config.mutate(fn, reload=False, typed={"server_2_d2"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert (on_disk.get("kea_server_2", "api_d2_user"), on_disk.get("kea_server_2", "api_d2_pass")) == ("su", "SP")
        assert cred.resolve(on_disk)["server_2_d2"].password == "SP"

    def test_the_writer_still_wants_that_one_endpoint_typed(self, _a_real_file):
        """Narrowing `typed` to the endpoint the route repoints does not weaken the rule: the probed pair is the same secret on a second host, and it is refused unless that endpoint is typed."""
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "u", "S")
        before = _a_real_file.read_bytes()
        with pytest.raises(ConfigChangeRefused):
            app_config.mutate(fn, reload=False, typed=set())
        assert _a_real_file.read_bytes() == before
        assert (
            infra._endpoint_name(PRIMARY, "dhcp6") == "kea6" and infra._endpoint_name({"id": 3}, "d2") == "server_3_d2"
        )


class TestDaemonCredsIsTheResolversAnswer:
    """S3: the form's defaults are what `credentials.resolve` gives the endpoint at the address it is about to have - the old fallback to the server's v4 pair was a second decider."""

    def test_a_different_spelling_of_the_host_is_withheld_and_the_default_is_nothing(self):
        assert infra._daemon_creds(PRIMARY, "dhcp6", "http://10.0.0.5:8006") == ("", "")

    def test_the_same_host_inherits_the_servers_pair(self):
        assert infra._daemon_creds(PRIMARY, "dhcp6", "http://kea-a.lan:8006") == ("u", "S")

    def test_it_is_resolve_for_an_endpoint_already_configured(self, _a_real_file):
        _a_real_file.write_text(HOSTNAME + "[kea6]\napi_url = http://10.0.0.5:8006\n", encoding="utf-8")
        resolved = cred.resolve(_parse(_a_real_file.read_text(encoding="utf-8")))["kea6"]
        assert resolved.withheld == "kea"
        assert infra._daemon_creds(PRIMARY, "dhcp6") == (resolved.user, resolved.password) == ("", "")

    def test_the_servers_own_endpoint_returns_its_own_pair(self):
        assert infra._daemon_creds(PRIMARY, "dhcp4", "http://10.0.0.5:8004") == ("u", "S")

    def test_an_unknown_server_has_none(self):
        assert infra._daemon_creds({"id": 9}, "dhcp4") == ("", "")


class TestARemovedSocketLeavesTheCredentialsAndTheNextAddressIsAMove:
    def test_s4b(self, _a_real_file, monkeypatch):
        _a_real_file.write_text(
            HOSTNAME + "[kea6]\napi_url = http://10.0.0.5:8006\napi_user = u\napi_pass = S\napi_pass_shared = 1\n",
            encoding="utf-8",
        )

        def remove(cfg):  # the route's own `_apply` for dhcp6 in direct mode: the address key goes, nothing else
            cfg.remove_option("kea6", "api_url")

        app_config.mutate(remove, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert on_disk.has_option("kea6", "api_user") and on_disk.has_option("kea6", "api_pass")
        assert not on_disk.has_option("kea6", "api_url")

        def give_it_an_address(cfg):
            cfg.set("kea6", "api_url", "http://elsewhere:8006")

        before = _a_real_file.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.mutate(give_it_an_address, reload=False)
        assert _a_real_file.read_bytes() == before
        app_config.mutate(give_it_an_address, reload=False, typed={"kea6"})
