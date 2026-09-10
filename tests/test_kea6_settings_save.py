"""
tests/test_kea6_settings_save.py
────────────────────────────────
v5.10.2 — save_infra_kea6() lifecycle. ChatGPT's 5.10.0/5.10.1 review:
"clearing a previously-set [kea6] value" was advertised (docstring +
"(inherited)" placeholders) but never implemented — a blank field wrote
nothing, so a stale override survived, and after a direct→ca switch that
could aim a CA-shaped `{"service": ["dhcp6"]}` payload at the v6 daemon.

Blank text field ⇒ the key is removed. Blank password ⇒ kept. Tick
Inherit ⇒ password removed. Empty section ⇒ removed.
"""

import configparser

import pytest

from jen import extensions
from jen.config import app_config


@pytest.fixture
def isolated_config(tmp_path):
    """Point AppConfig at a throwaway jen.config so route POSTs write
    there, not the real file. Same pattern as tests/test_appconfig.py."""
    original_path = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u4", "api_pass": "p4"}
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
    from tests.conftest import _patch_extensions

    _patch_extensions()


def _on_disk(path):
    p = configparser.ConfigParser()
    p.read(str(path))
    return p


def _post(client, **fields):
    return client.post("/settings/infrastructure/save-kea6", data=fields, follow_redirects=True)


class TestKea6ClearingAndInheritance:
    def test_blank_api_url_removes_the_key_and_inherits_v4(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, api_url="http://kea6:8006")
        assert _on_disk(isolated_config).get("kea6", "api_url") == "http://kea6:8006"

        r = _post(logged_in_client, api_url="")
        assert b"cleared" in r.data
        disk = _on_disk(isolated_config)
        assert not (disk.has_section("kea6") and disk.has_option("kea6", "api_url"))
        # ca mode: KEA6_API_URL falls back to the v4 URL at load time
        assert extensions.KEA6_API_URL == "http://1.2.3.4:8000"

    def test_all_blank_on_a_config_with_no_kea6_is_a_noop(self, logged_in_client, db, mock_kea, isolated_config):
        from jen.models.user import get_global_setting

        r = _post(logged_in_client)
        assert b"No Kea6 changes" in r.data
        assert get_global_setting("restart_pending", "false") != "true"
        assert not _on_disk(isolated_config).has_section("kea6")

    def test_blank_password_is_kept_but_inherit_checkbox_removes_it(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _post(logged_in_client, api_url="http://kea6:8006", api_pass="secret6")
        assert _on_disk(isolated_config).get("kea6", "api_pass") == "secret6"

        # blank password, other field still set → password survives
        _post(logged_in_client, api_url="http://kea6:8006", api_user="u6")
        assert _on_disk(isolated_config).get("kea6", "api_pass") == "secret6"

        # tick Inherit → password key removed
        _post(logged_in_client, api_url="http://kea6:8006", inherit_api_pass="1")
        disk = _on_disk(isolated_config)
        assert not disk.has_option("kea6", "api_pass")

    def test_section_is_removed_when_every_override_is_cleared(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, api_url="http://kea6:8006", api_user="u6", api_pass="s6")
        assert _on_disk(isolated_config).has_section("kea6")
        _post(logged_in_client, api_url="", api_user="", inherit_api_pass="1")
        assert not _on_disk(isolated_config).has_section("kea6")

    def test_direct_mode_api_url_without_port_is_rejected(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "connection_mode", "direct")
        r = _post(logged_in_client, api_url="http://kea6")
        assert b"explicit port" in r.data
        assert not _on_disk(isolated_config).has_option("kea6", "api_url")


class TestSaveKeaPortValidation:
    def test_direct_mode_rejects_a_portless_api_url(self, logged_in_client, db, mock_kea, isolated_config):
        r = logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={"api_url": "http://kea", "api_user": "u", "connection_mode": "direct", "api_tls_verify": "1"},
            follow_redirects=True,
        )
        assert b"explicit port" in r.data
        assert _on_disk(isolated_config).get("kea", "api_url") == "http://1.2.3.4:8000"  # unchanged

    def test_ca_mode_accepts_a_portless_api_url(self, logged_in_client, db, mock_kea, isolated_config):
        logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={"api_url": "http://kea-ca", "api_user": "u", "connection_mode": "ca", "api_tls_verify": "1"},
            follow_redirects=True,
        )
        assert _on_disk(isolated_config).get("kea", "api_url") == "http://kea-ca"

    def test_direct_mode_accepts_an_explicit_port(self, logged_in_client, db, mock_kea, isolated_config):
        logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={"api_url": "http://kea:8004", "api_user": "u", "connection_mode": "direct", "api_tls_verify": "1"},
            follow_redirects=True,
        )
        assert _on_disk(isolated_config).get("kea", "api_url") == "http://kea:8004"


class TestSaveKeaClientCert:
    def test_one_of_two_is_rejected(self, logged_in_client, db, mock_kea, isolated_config):
        r = logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={
                "api_url": "https://kea:8004",
                "api_user": "u",
                "connection_mode": "direct",
                "api_tls_verify": "1",
                "api_client_cert": "/etc/jen/ssl/only-cert.pem",
            },
            follow_redirects=True,
        )
        assert b"both the client certificate and key" in r.data
        assert not _on_disk(isolated_config).has_option("kea", "api_client_cert")

    def test_nonexistent_path_is_rejected(self, logged_in_client, db, mock_kea, isolated_config):
        r = logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={
                "api_url": "https://kea:8004",
                "api_user": "u",
                "connection_mode": "direct",
                "api_tls_verify": "1",
                "api_client_cert": "/no/such/cert.pem",
                "api_client_key": "/no/such/key.pem",
            },
            follow_redirects=True,
        )
        assert b"not found on the Jen host" in r.data

    def test_a_real_matching_pair_is_saved(self, logged_in_client, db, mock_kea, isolated_config, tmp_path):
        """v5.10.3 — a real pair now, not two text files: the route
        validates the material before writing it."""
        from tests.test_ssl_material import _pair

        _pair(tmp_path, name="c")
        cert, key = tmp_path / "c.crt", tmp_path / "c.key"
        logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={
                "api_url": "https://kea:8004",
                "api_user": "u",
                "connection_mode": "direct",
                "api_tls_verify": "1",
                "api_client_cert": str(cert),
                "api_client_key": str(key),
            },
            follow_redirects=True,
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea", "api_client_cert") == str(cert)
        assert disk.get("kea", "api_client_key") == str(key)

    def test_a_mismatched_pair_is_refused(self, logged_in_client, db, mock_kea, isolated_config, tmp_path):
        """The 5.10.2 gap: both paths existed, so isfile() passed and every
        later Kea request died with an opaque SSLError instead."""
        from tests.test_ssl_material import _pair

        _pair(tmp_path, name="a")
        _pair(tmp_path, cn="other", name="b")
        r = logged_in_client.post(
            "/settings/infrastructure/save-kea",
            data={
                "api_url": "https://kea:8004",
                "api_user": "u",
                "connection_mode": "direct",
                "api_tls_verify": "1",
                "api_client_cert": str(tmp_path / "a.crt"),
                "api_client_key": str(tmp_path / "b.key"),
            },
            follow_redirects=True,
        )
        assert b"does not match" in r.data
        assert not _on_disk(isolated_config).has_option("kea", "api_client_cert")


class TestDirectPortWarnings:
    def test_warning_lists_a_portless_url_in_direct_mode(self, logged_in_client, db, mock_kea, isolated_config):
        # a portless URL that was valid in ca mode, now in direct mode
        app_config.write_values([("kea", "api_url", "http://kea-noport"), ("kea", "connection_mode", "direct")])
        body = logged_in_client.get("/settings/kea").data
        assert b"explicit port on every API URL" in body
        assert b"http://kea-noport" in body

    def test_no_warning_in_ca_mode(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "api_url", "http://kea-noport")  # ca mode (default)
        body = logged_in_client.get("/settings/kea").data
        assert b"explicit port on every API URL" not in body
