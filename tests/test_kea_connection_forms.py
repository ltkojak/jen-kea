"""
tests/test_kea_connection_forms.py
──────────────────────────────────
v5.69.0-beta.9 (Q178, CRED-002) - a saved password is never sent to an endpoint it was not typed for. Every connection form that keeps a blank password (the Kea API, Kea6,
D2, an additional server, Kea's database, Jen's database) refuses a blank password for a NEW endpoint, with one sentence and no write; the same endpoint keeps its password; a
typed password is written; "Inherit", where the form has one, is the way out.
"""

import configparser

import pytest

from jen import extensions
from jen.config import app_config
from tests.test_extra_servers import _rows, _seed

SENTENCE = "enter the password for the new endpoint"


@pytest.fixture
def isolated_config(tmp_path):
    original_path = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "https://kea-a:8000", "api_user": "u4", "api_pass": "S"}
    cfg["kea_db"] = {"host": "db-a", "user": "du", "password": "KDB", "database": "kea"}
    cfg["jen_db"] = {"host": "db-a", "user": "ju", "password": "JDB", "database": "jen"}
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


def _disk(path):
    p = configparser.ConfigParser()
    p.read(str(path))
    return p


def _post(client, url, **data):
    return client.post(url, data=data, follow_redirects=True)


class TestTheKeaApiForm:
    URL = "/settings/infrastructure/save-kea"

    def _fields(self, **over):
        return {"api_url": "https://kea-a:8000", "api_user": "u4", "api_pass": "", "connection_mode": "ca", **over}

    def test_a_new_endpoint_with_a_blank_password_is_refused_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, self.URL, **self._fields(api_url="https://kea-b:8000"))
        assert SENTENCE.encode() in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea", "api_url") == "https://kea-a:8000" and disk.get("kea", "api_pass") == "S"

    def test_a_new_endpoint_with_a_typed_password_is_written(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, self.URL, **self._fields(api_url="https://kea-b:8000", api_pass="N"))
        disk = _disk(isolated_config)
        assert disk.get("kea", "api_url") == "https://kea-b:8000" and disk.get("kea", "api_pass") == "N"

    def test_the_same_endpoint_with_a_blank_password_is_written_and_the_password_is_kept(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, self.URL, **self._fields(api_url="https://KEA-A:8000/", api_user="newuser"))
        assert SENTENCE.encode() not in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea", "api_user") == "newuser" and disk.get("kea", "api_pass") == "S"

    def test_a_different_port_is_a_different_place(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, **self._fields(api_url="https://kea-a:9000"))
        assert SENTENCE.encode() in r.data and _disk(isolated_config).get("kea", "api_url") == "https://kea-a:8000"


class TestTheKea6Form:
    URL = "/settings/infrastructure/save-kea6"

    @pytest.fixture(autouse=True)
    def _stored(self, isolated_config):
        app_config.write_values(
            [
                ("kea6", "api_url", "https://k6-a:8006"),
                ("kea6", "api_pass", "S6"),
                ("kea6_db", "host", "db6-a"),
                ("kea6_db", "password", "D6"),
            ]
        )

    def test_a_new_api_endpoint_with_a_blank_password_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, api_url="https://k6-b:8006")
        assert SENTENCE.encode() in r.data
        assert _disk(isolated_config).get("kea6", "api_url") == "https://k6-a:8006"

    def test_a_new_database_host_with_a_blank_password_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, self.URL, api_url="https://k6-a:8006", db_host="db6-b")
        assert SENTENCE.encode() in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea6_db", "host") == "db6-a" and disk.get("kea6_db", "password") == "D6"

    def test_inherit_is_the_way_out_and_removes_the_password(self, logged_in_client, db, mock_kea, isolated_config):
        # (Q178 second pass: Inherit is honoured for another PORT of the Kea API's host - the daemons' own sockets - and not for a different host)
        r = _post(logged_in_client, self.URL, api_url="https://kea-a:9006", db_host="db6-a", inherit_api_pass="1")
        assert SENTENCE.encode() not in r.data and b"different host from the Kea API" not in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea6", "api_url") == "https://kea-a:9006" and not disk.has_option("kea6", "api_pass")

    def test_inherit_does_not_send_the_kea_password_to_a_different_host(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, self.URL, api_url="https://k6-b:8006", inherit_api_pass="1")
        assert b"different host from the Kea API" in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea6", "api_url") == "https://k6-a:8006" and disk.get("kea6", "api_pass") == "S6"

    def test_a_typed_password_writes_the_new_endpoint(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, self.URL, api_url="https://k6-b:8006", db_host="db6-a", api_pass="N6")
        disk = _disk(isolated_config)
        assert disk.get("kea6", "api_url") == "https://k6-b:8006" and disk.get("kea6", "api_pass") == "N6"

    def test_clearing_the_address_without_inherit_would_send_the_password_to_the_v4_endpoint_and_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, self.URL, api_url="")
        assert SENTENCE.encode() in r.data

    def test_an_unchanged_save_is_not_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, api_url="https://k6-a:8006", db_host="db6-a")
        assert SENTENCE.encode() not in r.data


class TestTheD2Form:
    URL = "/settings/infrastructure/save-d2"

    @pytest.fixture(autouse=True)
    def _stored(self, isolated_config):
        app_config.write_values([("d2", "api_url", "https://d2-a:8000"), ("d2", "api_pass", "SD")])

    def test_a_new_endpoint_with_a_blank_password_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, api_url="https://d2-b:8000")
        assert SENTENCE.encode() in r.data
        disk = _disk(isolated_config)
        assert disk.get("d2", "api_url") == "https://d2-a:8000" and disk.get("d2", "api_pass") == "SD"

    def test_inherit_with_a_new_endpoint_is_written(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, api_url="https://kea-a:9000", inherit_api_pass="1")
        assert SENTENCE.encode() not in r.data and b"different host from the Kea API" not in r.data
        disk = _disk(isolated_config)
        assert disk.get("d2", "api_url") == "https://kea-a:9000" and not disk.has_option("d2", "api_pass")

    def test_inherit_onto_a_different_host_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, self.URL, api_url="https://d2-b:8000", inherit_api_pass="1")
        assert b"different host from the Kea API" in r.data
        assert _disk(isolated_config).get("d2", "api_url") == "https://d2-a:8000"

    def test_the_same_endpoint_keeps_the_password(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, self.URL, api_url="https://d2-a:8000", api_user="x")
        assert _disk(isolated_config).get("d2", "api_pass") == "SD"


class TestAnAdditionalServer:
    URL = "/settings/infrastructure/save-extra-servers"

    def test_a_row_with_a_new_address_and_a_blank_password_is_refused_and_no_row_changes(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        before = dict(_disk(isolated_config).items("kea_server_2"))
        r = logged_in_client.post(
            self.URL,
            data=_rows(
                {
                    "extra_id[]": "2",
                    "extra_name[]": "Standby",
                    "extra_api_url[]": "https://s2-b:8000",
                    "extra_ssh_host[]": "10.0.0.2",
                }
            ),
            follow_redirects=True,
        )
        assert SENTENCE.encode() in r.data
        assert dict(_disk(isolated_config).items("kea_server_2")) == before

    def test_the_ipv6_address_is_checked_too(self, logged_in_client, db, mock_kea, isolated_config):
        _seed(
            (
                2,
                {
                    "api_url": "https://s2-a:8000",
                    "api_pass": "P2",
                    "api6_url": "https://s2-a:8006",
                    "api6_pass": "P6",
                    "name": "Standby",
                    "ssh_host": "10.0.0.2",
                },
            )
        )
        r = logged_in_client.post(
            self.URL,
            data=_rows(
                {
                    "extra_id[]": "2",
                    "extra_name[]": "Standby",
                    "extra_api_url[]": "https://s2-a:8000",
                    "extra_api6_url[]": "https://s2-b:8006",
                    "extra_ssh_host[]": "10.0.0.2",
                }
            ),
            follow_redirects=True,
        )
        assert (
            SENTENCE.encode() in r.data
            and _disk(isolated_config).get("kea_server_2", "api6_url") == "https://s2-a:8006"
        )

    def test_a_typed_password_writes_the_new_address(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        logged_in_client.post(
            self.URL,
            data=_rows(
                {
                    "extra_id[]": "2",
                    "extra_name[]": "Standby",
                    "extra_api_url[]": "https://s2-b:8000",
                    "extra_api_pass[]": "N2",
                    "extra_ssh_host[]": "10.0.0.2",
                }
            ),
        )
        disk = _disk(isolated_config)
        assert (
            disk.get("kea_server_2", "api_url") == "https://s2-b:8000" and disk.get("kea_server_2", "api_pass") == "N2"
        )

    def test_the_same_address_keeps_the_password_and_a_new_row_still_inherits_the_primarys(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        logged_in_client.post(
            self.URL,
            data=_rows(
                {
                    "extra_id[]": "2",
                    "extra_name[]": "Standby",
                    "extra_api_url[]": "https://s2-a:8000/",
                    "extra_ssh_host[]": "10.0.0.2",
                },
                {"extra_id[]": "", "extra_name[]": "Third", "extra_api_url[]": "https://s3:8000"},
            ),
        )
        disk = _disk(isolated_config)
        assert disk.get("kea_server_2", "api_pass") == "P2"
        assert disk.get("kea_server_3", "api_pass") == "S", (
            "a genuinely new row has no saved password of its own and inherits the primary's, as documented"
        )


@pytest.mark.parametrize(
    "url,section,stored",
    [
        ("/settings/infrastructure/save-kea-db", "kea_db", "KDB"),
        ("/settings/infrastructure/save-jen-db", "jen_db", "JDB"),
    ],
)
class TestTheDatabaseForms:
    def _fields(self, **over):
        return {"host": "db-a", "user": "du", "password": "", "database": "kea", **over}

    def test_a_new_host_with_a_blank_password_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config, url, section, stored
    ):
        r = _post(logged_in_client, url, **self._fields(host="db-b"))
        assert SENTENCE.encode() in r.data
        disk = _disk(isolated_config)
        assert disk.get(section, "host") == "db-a" and disk.get(section, "password") == stored

    def test_a_new_host_with_the_password_is_written(
        self, logged_in_client, db, mock_kea, isolated_config, url, section, stored
    ):
        _post(logged_in_client, url, **self._fields(host="db-b", password="NEWPW"))
        disk = _disk(isolated_config)
        assert disk.get(section, "host") == "db-b" and disk.get(section, "password") == "NEWPW"

    def test_the_same_host_with_a_blank_password_keeps_it(
        self, logged_in_client, db, mock_kea, isolated_config, url, section, stored
    ):
        _post(logged_in_client, url, **self._fields(host="DB-A", user="other-user"))
        disk = _disk(isolated_config)
        assert disk.get(section, "user") == "other-user" and disk.get(section, "password") == stored


class TestTheOneHelper:
    def test_every_connection_route_calls_it_and_the_ddns_route_uses_same_endpoint(self):
        import pathlib

        src = pathlib.Path("jen/routes/settings/infrastructure.py").read_text(encoding="utf-8")
        assert src.count("_secret_for_new_endpoint(") >= 7, (
            "the definition plus the Kea, Kea DB, Jen DB, Kea6 (one loop), D2 and extra-server calls"
        )
        assert "same_endpoint(" in src
        for route in (
            "save_infra_kea",
            "save_infra_kea_db",
            "save_infra_kea6",
            "save_infra_d2",
            "save_extra_servers",
            "save_infra_jen_db",
        ):
            body = src.split(f"def {route}(", 1)[1].split("\n@bp.route", 1)[0]
            assert "_secret_for_new_endpoint(" in body or "_EndpointNeedsItsPassword" in body, route


class TestAPasswordTheFormInheritsStaysWithTheKeaHost:
    """Q178's adversarial pass: Kea6 and D2 use the Kea API's password when they have none of their own, and an admin may point D2 anywhere - the inherited secret must not go to a
    different host. Another port of the same host is the design (the daemons' own sockets)."""

    def test_an_admin_pointing_d2_at_another_host_with_no_password_is_refused(
        self, client, db, mock_kea, isolated_config
    ):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, None, role="admin", username="q178_d2_admin")
        r = c.post(
            "/settings/infrastructure/save-d2", data={"api_url": "https://attacker.example:8000"}, follow_redirects=True
        )
        assert b"different host from the Kea API" in r.data
        assert not _disk(isolated_config).has_section("d2")

    def test_the_same_host_on_its_own_port_inherits_as_designed(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, "/settings/infrastructure/save-d2", api_url="https://kea-a:53001")
        assert b"different host" not in r.data
        assert _disk(isolated_config).get("d2", "api_url") == "https://kea-a:53001"

    def test_a_typed_password_makes_a_different_host_fine(self, logged_in_client, db, mock_kea, isolated_config):
        _post(logged_in_client, "/settings/infrastructure/save-d2", api_url="https://d2-host:53001", api_pass="D2PW")
        disk = _disk(isolated_config)
        assert disk.get("d2", "api_url") == "https://d2-host:53001" and disk.get("d2", "api_pass") == "D2PW"

    def test_kea6_with_no_password_of_its_own_on_a_different_host_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, "/settings/infrastructure/save-kea6", api_url="https://k6-new:8006")
        assert b"different host from the Kea API" in r.data
        assert not _disk(isolated_config).has_section("kea6")

    def test_the_kea6_database_host_follows_the_same_rule(self, logged_in_client, db, mock_kea, isolated_config):
        r = _post(logged_in_client, "/settings/infrastructure/save-kea6", db_host="db6-new")
        assert b"different host from the Kea API" in r.data
        r = _post(logged_in_client, "/settings/infrastructure/save-kea6", db_host="db-a")
        assert b"different host" not in r.data

    def test_clearing_the_d2_address_falls_back_to_the_kea_host_and_is_fine(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(logged_in_client, "/settings/infrastructure/save-d2", api_url="")
        assert b"different host" not in r.data
