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
            ],
            typed={
                "kea6",
                "kea6_db",
            },  # (Q183, Y2: a password VALUE changes only when typed - this fixture is the superadmin who typed them)
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
        app_config.write_values([("d2", "api_url", "https://d2-a:8000"), ("d2", "api_pass", "SD")], typed={"d2"})

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
        assert not disk.has_option("kea_server_3", "api_pass"), (
            "Q179 adjustment: a new row is given the primary's password only by its own 'share' box (CRED-003); without it nothing is copied into the section"
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

    def test_pointing_d2_at_another_host_with_no_password_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        # (Q179 adjustment: this posted as an admin in Q178; the D2 form is a superadmin's now - the admin's refusal is TestEveryIdentityRouteIsASuperadminsForm)
        r = logged_in_client.post(
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


IDENTITY_ROUTES = [
    ("/settings/infrastructure/save-kea", {"api_url": "https://elsewhere:8000", "api_user": "u4", "api_pass": "x"}),
    ("/settings/infrastructure/save-ssh", {"host": "10.9.9.9", "user": "jen"}),
    ("/settings/infrastructure/save-d2", {"api_url": "https://kea-a:53001", "api_pass": "x"}),
    (
        "/settings/infrastructure/save-extra-servers",
        {
            "extra_id[]": [""],
            "extra_name[]": ["N"],
            "extra_role[]": ["standby"],
            "extra_api_url[]": ["https://s9:8000"],
            "extra_api_user[]": [""],
            "extra_api_pass[]": ["x"],
            "extra_api6_url[]": [""],
            "extra_api6_user[]": [""],
            "extra_api6_pass[]": [""],
            "extra_ssh_host[]": ["10.0.0.9"],
            "extra_ssh_user[]": ["jen"],
            "extra_kea_conf[]": ["/etc/kea/kea-dhcp4.conf"],
        },
    ),
    ("/settings/infrastructure/direct-socket/1/dhcp4", {"address": "10.0.0.1", "port": "8004", "tls": "http"}),
    ("/settings/infrastructure/direct-socket/1/dhcp4/remove", {}),
]


class TestEveryIdentityRouteIsASuperadminsForm:
    """RBAC-004 (v5.69.0-beta.10, Q179): the six routes that write where Jen reaches a Kea server refuse an admin, write nothing, and the Settings -> Kea page shows an admin the
    same cards as facts (a superadmin sees the forms)."""

    @pytest.mark.parametrize(("url", "data"), IDENTITY_ROUTES)
    def test_an_admin_is_refused_and_nothing_is_written(self, client, db, mock_kea, isolated_config, url, data):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, None, role="admin", username="q179_admin")
        before = isolated_config.read_bytes()
        r = c.post(url, data=data, follow_redirects=True)
        assert b"SuperAdmin access required" in r.data
        assert isolated_config.read_bytes() == before

    @pytest.mark.parametrize(("url", "data"), IDENTITY_ROUTES)
    def test_a_superadmin_with_an_old_confirmation_is_sent_to_confirm_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config, url, data
    ):
        from datetime import datetime, timedelta, timezone

        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        before = isolated_config.read_bytes()
        r = logged_in_client.post(url, data=data)
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert isolated_config.read_bytes() == before

    def test_an_admin_sees_the_four_cards_as_facts_and_no_form_that_writes_them(
        self, client, db, mock_kea, isolated_config
    ):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, None, role="admin", username="q179_admin_page")
        body = c.get("/settings/kea").get_data(as_text=True)
        for url, _data in IDENTITY_ROUTES:
            assert f'action="{url}"' not in body, url
        assert 'action="/settings/infrastructure/direct-socket' not in body
        assert body.count("Only a superadmin changes where Jen reaches Kea.") >= 4
        assert "https://kea-a:8000" in body  # the facts are there
        assert 'id="kea-d2"' in body  # the D2 card is a read-only one, not absent
        assert (
            'action="/settings/infrastructure/save-ha"' in body
        )  # the HA mode and the primary's name are not where Jen connects

    def test_a_superadmin_sees_the_forms(self, logged_in_client, db, mock_kea, isolated_config):
        body = logged_in_client.get("/settings/kea").get_data(as_text=True)
        for url in (
            "/settings/infrastructure/save-kea",
            "/settings/infrastructure/save-ssh",
            "/settings/infrastructure/save-d2",
            "/settings/infrastructure/save-extra-servers",
        ):
            assert f'action="{url}"' in body, url
        assert "Only a superadmin changes where Jen reaches Kea." not in body

    def test_the_admin_page_still_has_every_control_its_script_binds(self, client, db, mock_kea, isolated_config):
        """The script binds the probe button by id; an admin has no additional-servers form, so those three bindings are guarded (a missing element would stop the whole block)."""
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, None, role="admin", username="q179_admin_js")
        body = c.get("/settings/kea").get_data(as_text=True)
        assert 'id="probe-kea-btn"' in body and 'id="add-server-row-btn"' not in body
        assert "if (addServerRowBtn)" in body

    def test_an_admin_probes_a_daemon_of_the_same_host_and_not_a_different_one(
        self, client, db, mock_kea, isolated_config, monkeypatch
    ):
        from jen.routes.settings import infrastructure as infra
        from tests.conftest import restricted_client

        seen = []
        monkeypatch.setattr(
            infra,
            "_probe_once",
            lambda url, user, pwd, omit_service, service="dhcp4", **k: (seen.append(url) or "3.0.0", None),
        )
        c, _ = restricted_client(client, db, None, role="admin", username="q179_probe_admin")
        r = c.post("/settings/infrastructure/probe-kea", data={"candidate_url": "https://attacker.example:8004"})
        assert r.status_code == 403 and seen == []
        c.post("/settings/infrastructure/probe-kea", data={"candidate_url": "https://kea-a:8004"})
        assert seen == ["https://kea-a:8004"]

    def test_a_superadmin_may_probe_an_address_they_typed(
        self, logged_in_client, db, mock_kea, isolated_config, monkeypatch
    ):
        from jen.routes.settings import infrastructure as infra

        seen = []
        monkeypatch.setattr(
            infra,
            "_probe_once",
            lambda url, user, pwd, omit_service, service="dhcp4", **k: (seen.append(url) or "3.0.0", None),
        )
        logged_in_client.post("/settings/infrastructure/probe-kea", data={"candidate_url": "https://new-host:8004"})
        assert seen == ["https://new-host:8004"]


class TestAnAdminsProbeNeverDowngradesTheScheme:
    """Q203 AS1 (CRED-002, RBAC-004): a probe is a credential send, so an admin's candidate is the same host over NO WEAKER scheme (`auth.no_weaker_scheme`) - with the endpoint
    configured https, `http://kea-a:<any port>` would have carried the saved Kea API credential in clear text. A superadmin's deliberate http test stays allowed."""

    CONFIGURED_HTTPS = "https://kea-a:8000"
    CONFIGURED_HTTP = "http://kea-a:8000"

    def _probe(self, monkeypatch, client, configured, candidate):
        from jen.routes.settings import infrastructure as infra

        seen = []
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "Test Kea", "api_url": configured, "api_user": "u", "api_pass": "p"}],
        )
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(
            infra,
            "_probe_once",
            lambda url, user, pwd, omit_service, service="dhcp4", **k: (seen.append(url) or "3.0.0", None),
        )
        r = client.post("/settings/infrastructure/probe-kea", data={"candidate_url": candidate})
        return r, seen

    def _admin(self, client, db):
        from tests.conftest import restricted_client

        return restricted_client(client, db, None, role="admin", username="q203_as1_admin")[0]

    def test_1_https_configured_an_admins_http_candidate_on_the_same_host_is_refused_and_nothing_is_dialled(
        self, client, db, monkeypatch
    ):
        admin = self._admin(client, db)
        for port in ("8004", "8000", "9999", "80"):
            r, seen = self._probe(monkeypatch, admin, self.CONFIGURED_HTTPS, f"http://kea-a:{port}")
            assert r.status_code == 403, port
            assert seen == [], port
            error = r.get_json()["error"]
            assert "different host" in error and "over http where Jen reaches this host over https" in error

    def test_2_https_configured_an_admins_https_candidate_on_another_port_is_probed(self, client, db, monkeypatch):
        r, seen = self._probe(monkeypatch, self._admin(client, db), self.CONFIGURED_HTTPS, "https://kea-a:8004")
        assert r.status_code == 200 and seen == ["https://kea-a:8004"]

    def test_3_http_configured_an_admins_https_candidate_is_probed(self, client, db, monkeypatch):
        r, seen = self._probe(monkeypatch, self._admin(client, db), self.CONFIGURED_HTTP, "https://kea-a:8004")
        assert r.status_code == 200 and seen == ["https://kea-a:8004"]

    def test_4_http_configured_an_admins_http_candidate_is_probed(self, client, db, monkeypatch):
        r, seen = self._probe(monkeypatch, self._admin(client, db), self.CONFIGURED_HTTP, "http://kea-a:8004")
        assert r.status_code == 200 and seen == ["http://kea-a:8004"]

    def test_5_a_superadmin_may_test_http_against_an_https_endpoint_deliberately(
        self, logged_in_client, db, monkeypatch
    ):
        r, seen = self._probe(monkeypatch, logged_in_client, self.CONFIGURED_HTTPS, "http://kea-a:8004")
        assert r.status_code == 200 and seen == ["http://kea-a:8004"]

    def test_6_an_upper_cased_scheme_reads_as_the_scheme_it_is(self, client, db, monkeypatch):
        admin = self._admin(client, db)
        r, seen = self._probe(monkeypatch, admin, self.CONFIGURED_HTTPS, "HTTPS://kea-a:8004")
        assert r.status_code == 200 and seen == ["HTTPS://kea-a:8004"]
        r, seen = self._probe(monkeypatch, admin, self.CONFIGURED_HTTPS, "HTTP://kea-a:8004")
        assert r.status_code == 403 and seen == []

    def test_7_a_different_host_over_https_is_refused_as_before(self, client, db, monkeypatch):
        r, seen = self._probe(
            monkeypatch, self._admin(client, db), self.CONFIGURED_HTTPS, "https://attacker.example:8004"
        )
        assert r.status_code == 403 and seen == []

    def test_the_docstring_says_what_is_true(self):
        from jen.routes.settings import infrastructure as infra

        doc = infra.probe_kea.__doc__
        assert "never downgrades" in doc and "no_weaker_scheme" in doc
        assert "The scheme is never downgraded." not in doc


class TestOneAnswerForASecret:
    """Q179, T2: the Inherit box and the password box of Kea6 and D2 are one question."""

    @pytest.fixture(autouse=True)
    def _stored(self, isolated_config):
        app_config.write_values(
            [
                ("kea6", "api_url", "https://kea-a:8006"),
                ("kea6", "api_pass", "S6"),
                ("d2", "api_url", "https://kea-a:53001"),
                ("d2", "api_pass", "SD"),
            ],
            typed={"kea6", "d2"},
        )

    SENTENCE6 = b"Choose one for the Kea6 API password: inherit the Kea API"
    SENTENCED2 = b"Choose one for the D2 API password: inherit the Kea API"

    def test_kea6_inherit_and_a_typed_password_is_refused_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = isolated_config.read_bytes()
        r = _post(
            logged_in_client,
            "/settings/infrastructure/save-kea6",
            api_url="https://kea-a:8006",
            api_pass="N",
            inherit_api_pass="1",
        )
        assert self.SENTENCE6 in r.data and isolated_config.read_bytes() == before

    def test_d2_inherit_and_a_typed_password_is_refused_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = isolated_config.read_bytes()
        r = _post(
            logged_in_client,
            "/settings/infrastructure/save-d2",
            api_url="https://kea-a:53001",
            api_pass="N",
            inherit_api_pass="1",
        )
        assert self.SENTENCED2 in r.data and isolated_config.read_bytes() == before

    def test_the_database_pair_of_kea6_is_the_same_question(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_values([("kea6_db", "host", "db-a"), ("kea6_db", "password", "D6")], typed={"kea6_db"})
        before = isolated_config.read_bytes()
        r = _post(
            logged_in_client,
            "/settings/infrastructure/save-kea6",
            api_url="https://kea-a:8006",
            db_host="db-a",
            db_pass="N",
            inherit_db_pass="1",
        )
        assert b"Choose one for the Kea6 database password" in r.data and isolated_config.read_bytes() == before

    def test_inherit_with_a_blank_box_on_the_same_host_is_written_and_inherits(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _post(logged_in_client, "/settings/infrastructure/save-d2", api_url="https://kea-a:53001", inherit_api_pass="1")
        assert not _disk(isolated_config).has_option("d2", "api_pass")

    def test_inherit_with_a_blank_box_on_a_different_host_is_beta_nines_refusal(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = _post(
            logged_in_client, "/settings/infrastructure/save-d2", api_url="https://d2-other:53001", inherit_api_pass="1"
        )
        assert b"different host from the Kea API" in r.data and _disk(isolated_config).get("d2", "api_pass") == "SD"

    def test_no_inherit_and_a_typed_password_on_a_different_host_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _post(logged_in_client, "/settings/infrastructure/save-d2", api_url="https://d2-other:53001", api_pass="TYPED")
        disk = _disk(isolated_config)
        assert disk.get("d2", "api_url") == "https://d2-other:53001" and disk.get("d2", "api_pass") == "TYPED"

    def test_the_helper_is_given_the_effective_secret(self):
        import inspect

        from jen.routes.settings import infrastructure as infra

        for fn in (infra.save_infra_kea6, infra.save_infra_d2):
            src = inspect.getsource(fn)
            assert "_one_answer_for_a_secret(" in src and "effective" in src, fn.__name__


class TestAnAdditionalServerUsesTheCredentialItIsGiven:
    """Q179, T3: the password an additional server keeps is the one its connection RESOLVES (its own, else the primary's), and sharing the primary's with a NEW row is its own box."""

    URL = "/settings/infrastructure/save-extra-servers"

    def _post(self, client, *rows):
        data = _rows(*rows)
        data["extra_share_pass[]"] = [r.get("share", "0") for r in rows]
        return client.post(self.URL, data=data, follow_redirects=True)

    def test_a_section_with_no_password_of_its_own_moved_to_a_new_address_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        # (Q180 adjustment: the section is on the primary's host - kea-a - so it INHERITS the primary's "S"; on another host it would have none and nothing to leak)
        _seed((2, {"api_url": "https://kea-a:8001", "name": "Standby", "ssh_host": "10.0.0.2"}))
        before = dict(_disk(isolated_config).items("kea_server_2"))
        r = self._post(
            logged_in_client,
            {
                "extra_id[]": "2",
                "extra_name[]": "Standby",
                "extra_api_url[]": "https://s2-b:8000",
                "extra_ssh_host[]": "10.0.0.2",
            },
        )
        assert SENTENCE.encode() in r.data
        assert dict(_disk(isolated_config).items("kea_server_2")) == before

    def test_the_same_address_is_written_and_nothing_is_copied_into_the_section(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        r = self._post(
            logged_in_client,
            {
                "extra_id[]": "2",
                "extra_name[]": "Standby2",
                "extra_api_url[]": "https://s2-a:8000/",
                "extra_ssh_host[]": "10.0.0.2",
            },
        )
        assert SENTENCE.encode() not in r.data
        disk = _disk(isolated_config)
        assert disk.get("kea_server_2", "name") == "Standby2" and not disk.has_option("kea_server_2", "api_pass")

    def test_the_ipv6_address_is_judged_against_the_password_it_would_use(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed(
            (
                2,
                {
                    "api_url": "https://s2-a:8000",
                    "api_pass": "P2",
                    "api6_url": "https://s2-a:8006",
                    "name": "Standby",
                    "ssh_host": "10.0.0.2",
                },
            )
        )
        r = self._post(
            logged_in_client,
            {
                "extra_id[]": "2",
                "extra_name[]": "Standby",
                "extra_api_url[]": "https://s2-a:8000",
                "extra_api6_url[]": "https://s2-v6:8006",
                "extra_ssh_host[]": "10.0.0.2",
            },
        )
        assert (
            SENTENCE.encode() in r.data
            and _disk(isolated_config).get("kea_server_2", "api6_url") == "https://s2-a:8006"
        )

    def test_a_new_row_with_the_share_box_gets_the_primarys_password_in_its_section(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._post(
            logged_in_client,
            {"extra_id[]": "", "extra_name[]": "Peer", "extra_api_url[]": "https://peer:8000", "share": "1"},
        )
        assert _disk(isolated_config).get("kea_server_2", "api_pass") == "S"

    def test_a_new_row_without_the_box_and_without_a_password_has_no_password_key(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._post(logged_in_client, {"extra_id[]": "", "extra_name[]": "Peer", "extra_api_url[]": "https://peer:8000"})
        assert not _disk(isolated_config).has_option("kea_server_2", "api_pass")

    def test_a_new_row_with_a_typed_password_and_the_box_is_two_answers_and_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = isolated_config.read_bytes()
        r = self._post(
            logged_in_client,
            {
                "extra_id[]": "",
                "extra_name[]": "Peer",
                "extra_api_url[]": "https://peer:8000",
                "extra_api_pass[]": "OWN",
                "share": "1",
            },
        )
        # (Q180 adjustment: Q179 let a typed password win over the box; U3 says ticked AND typed is two answers - "Choose one" - and nothing is written)
        assert b"Choose one for the API password" in r.data and isolated_config.read_bytes() == before

    def test_an_old_page_that_sends_no_share_list_shares_nothing(self, logged_in_client, db, mock_kea, isolated_config):
        logged_in_client.post(
            self.URL, data=_rows({"extra_id[]": "", "extra_name[]": "Peer", "extra_api_url[]": "https://peer:8000"})
        )
        assert not _disk(isolated_config).has_option("kea_server_2", "api_pass")

    def test_the_page_offers_the_box_on_a_new_row(self, logged_in_client, db, mock_kea, isolated_config):
        body = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert "Share the primary's API password (an HA peer of the same Kea)" in body
        assert 'name="extra_share_pass[]"' in body


class TestAnAdditionalServersIpv6AddressIsJudgedAgainstThePasswordItUses:
    """Q179's second pass: a row with no IPv6 password of its own uses its API password; a typed API password was typed for the row."""

    URL = "/settings/infrastructure/save-extra-servers"

    def _row(self, **over):
        return {
            "extra_id[]": "2",
            "extra_name[]": "Standby",
            "extra_api_url[]": "https://s2-a:8000",
            "extra_ssh_host[]": "10.0.0.2",
            **over,
        }

    def test_a_new_api_address_with_the_new_password_typed_is_written_on_a_v4_only_install(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        r = logged_in_client.post(
            self.URL,
            data=_rows(self._row(**{"extra_api_url[]": "https://s2-b:8000", "extra_api_pass[]": "N2"})),
            follow_redirects=True,
        )
        assert b"IPv6 API address" not in r.data
        disk = _disk(isolated_config)
        assert (
            disk.get("kea_server_2", "api_url") == "https://s2-b:8000" and disk.get("kea_server_2", "api_pass") == "N2"
        )

    def test_a_dhcp6_socket_on_another_port_of_the_same_host_needs_no_password(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        r = logged_in_client.post(
            self.URL, data=_rows(self._row(**{"extra_api6_url[]": "https://s2-a:8006"})), follow_redirects=True
        )
        assert SENTENCE.encode() not in r.data
        assert _disk(isolated_config).get("kea_server_2", "api6_url") == "https://s2-a:8006"

    def test_a_dhcp6_address_on_a_different_host_with_the_api_password_kept_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "Standby", "ssh_host": "10.0.0.2"}))
        r = logged_in_client.post(
            self.URL, data=_rows(self._row(**{"extra_api6_url[]": "https://elsewhere:8006"})), follow_redirects=True
        )
        assert SENTENCE.encode() in r.data and not _disk(isolated_config).has_option("kea_server_2", "api6_url")
