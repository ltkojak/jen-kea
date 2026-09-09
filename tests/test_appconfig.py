"""
tests/test_appconfig.py
───────────────────────
AppConfig single-source-of-truth guarantees (v4.0.0).

Every write path must leave the on-disk file, extensions.cfg, and all
derived globals consistent — the stale-config bug class fixed in v3.8.1
must be structurally impossible.
"""

import configparser

import pytest

from jen import extensions
from jen.config import app_config, load_config, write_config_value, write_subnets_config


@pytest.fixture
def isolated_config(tmp_path):
    """Point AppConfig at a throwaway config file, restore afterwards."""
    original_path = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u1", "api_pass": "p1"}
    cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
    cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
    cfg["server"] = {"http_port": "5050", "https_port": "8443"}
    cfg["subnets"] = {"1": "LAN, 192.168.1.0/24"}
    path = tmp_path / "jen.config"
    with open(path, "w") as f:
        cfg.write(f)
    extensions.CONFIG_FILE = str(path)
    app_config.reload()
    yield path
    extensions.CONFIG_FILE = original_path
    # Restore in-memory state for subsequent tests (conftest values)
    from tests.conftest import _patch_extensions

    _patch_extensions()


class TestAppConfig:
    def test_reload_derives_all_globals(self, isolated_config):
        assert extensions.KEA_API_URL == "http://1.2.3.4:8000"
        assert extensions.HTTP_PORT == 5050
        assert extensions.SUBNET_MAP == {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}
        assert len(extensions.KEA_SERVERS) == 1

    def test_write_value_keeps_disk_and_memory_consistent(self, isolated_config):
        app_config.write_value("kea", "api_url", "http://5.6.7.8:8000")
        assert extensions.KEA_API_URL == "http://5.6.7.8:8000"
        assert extensions.KEA_SERVERS[0]["api_url"] == "http://5.6.7.8:8000"
        on_disk = configparser.ConfigParser()
        on_disk.read(str(isolated_config))
        assert on_disk.get("kea", "api_url") == "http://5.6.7.8:8000"

    def test_legacy_write_config_value_wrapper_reloads(self, isolated_config):
        write_config_value("server", "http_port", "6000")
        assert extensions.HTTP_PORT == 6000

    def test_write_subnets_reloads_subnet_map(self, isolated_config):
        write_subnets_config({2: {"name": "IoT", "cidr": "10.0.50.0/24"}})
        assert extensions.SUBNET_MAP == {2: {"name": "IoT", "cidr": "10.0.50.0/24"}}

    def test_mutate_rederives_kea_servers(self, isolated_config):
        def add_server(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://9.9.9.9:8000")
            p.set("kea_server_2", "name", "Standby")

        app_config.mutate(add_server)
        assert len(extensions.KEA_SERVERS) == 2
        assert extensions.KEA_SERVERS[1]["name"] == "Standby"
        # credentials fall back to primary values from the parser, not globals
        assert extensions.KEA_SERVERS[1]["api_user"] == "u1"

    def test_extensions_cfg_tracks_disk_after_mutation(self, isolated_config):
        def add_then_check(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://9.9.9.9:8000")

        app_config.mutate(add_then_check)
        app_config.mutate(lambda p: p.remove_section("kea_server_2"))
        assert len(extensions.KEA_SERVERS) == 1
        assert not extensions.cfg.has_section("kea_server_2")

    def test_write_values_batch(self, isolated_config):
        app_config.write_values([("kea_db", "host", "newhost"), ("jen_db", "host", "newhost")])
        assert extensions.KEA_DB_HOST == "newhost"
        assert extensions.JEN_DB_HOST == "newhost"

    def test_legacy_load_config_wrapper(self, isolated_config):
        app_config.write_value("kea_db", "host", "newhost")
        c = load_config()
        assert c.get("kea_db", "host") == "newhost"

    def test_load_raises_on_missing_file(self, isolated_config):
        extensions.CONFIG_FILE = "/nonexistent/jen.config"
        with pytest.raises(FileNotFoundError):
            app_config.load()

    def test_load_raises_on_missing_required(self, isolated_config, tmp_path):
        bad = tmp_path / "bad.config"
        bad.write_text("[kea]\napi_url = http://x\n")
        extensions.CONFIG_FILE = str(bad)
        with pytest.raises(ValueError):
            app_config.load()


class TestKea3ConnectionMode:
    """v5.10.0 — [kea] connection_mode + api_ca / api_tls_verify, and
    the api6_url the server dicts carry for direct mode. connection_mode
    is optional: absent → 'ca' → every prior release's behaviour."""

    def test_defaults_when_key_absent(self, isolated_config):
        assert extensions.KEA_CONNECTION_MODE == "ca"
        assert extensions.KEA_API_CA == ""
        assert extensions.KEA_API_TLS_VERIFY is True
        assert extensions.KEA_API_CLIENT_CERT == ""
        assert extensions.KEA_API_CLIENT_KEY == ""
        assert extensions.KEA_SERVERS[0]["api6_url"] == ""

    def test_direct_mode_and_tls_options_round_trip(self, isolated_config):
        app_config.write_values(
            [
                ("kea", "connection_mode", "direct"),
                ("kea", "api_ca", "/etc/jen/ssl/kea-ca.pem"),
                ("kea", "api_tls_verify", "false"),
                ("kea", "api_client_cert", "/etc/jen/ssl/client.pem"),
                ("kea", "api_client_key", "/etc/jen/ssl/client.key"),
            ]
        )
        assert extensions.KEA_CONNECTION_MODE == "direct"
        assert extensions.KEA_API_CA == "/etc/jen/ssl/kea-ca.pem"
        assert extensions.KEA_API_TLS_VERIFY is False
        assert extensions.KEA_API_CLIENT_CERT == "/etc/jen/ssl/client.pem"
        assert extensions.KEA_API_CLIENT_KEY == "/etc/jen/ssl/client.key"

    def test_derive_kea_servers_carries_api6_url_from_kea6_section(self, isolated_config):
        app_config.mutate(lambda p: (p.add_section("kea6"), p.set("kea6", "api_url", "http://kea6:8006")))
        assert extensions.KEA_SERVERS[0]["api6_url"] == "http://kea6:8006"

    def test_extra_server_api6_url_is_its_own_key(self, isolated_config):
        def add(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://s2:8000")
            p.set("kea_server_2", "api6_url", "http://s2:8006")

        app_config.mutate(add)
        assert extensions.KEA_SERVERS[1]["api6_url"] == "http://s2:8006"
