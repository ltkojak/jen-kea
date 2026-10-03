"""
tests/test_ca_fields.py
───────────────────────
v5.67.0-beta.15 (Q129, item d) — two missing CA fields. The migration wizard never passed a target `ssl_ca`
(`_direct_conn(..., ssl_ca="")`, so the connection was plain: a target that requires TLS failed, and one that merely
allows it got the credentials in clear), and the setup wizard's Connect step could not SET `[kea_db] ssl_ca` (it
honoured one already in jen.config). Each now has an optional "CA bundle" field carried through the test and the
save, validated like the Kea API CA (a file that exists on the Jen host).
"""

import contextlib

import pytest

from jen import extensions
from jen.services import dbexport, setup_wizard


@pytest.fixture
def ca_file(tmp_path):
    p = tmp_path / "db-ca.pem"
    p.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")
    return str(p)


class TestTheConnectionUsesTheCa:
    def test_a_ca_means_a_verifying_tls_connection(self, monkeypatch, ca_file):
        seen = {}
        monkeypatch.setattr(dbexport.pymysql, "connect", lambda **kw: seen.update(kw) or object())
        dbexport._direct_conn("h", 3306, "u", "p", "d", ca_file)
        assert seen["ssl"] == {"ca": ca_file}

    def test_no_ca_means_no_ssl_argument_at_all_as_before(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(dbexport.pymysql, "connect", lambda **kw: seen.update(kw) or object())
        dbexport._direct_conn("h", 3306, "u", "p", "d")
        assert "ssl" not in seen

    def test_test_connection_passes_it_on(self, monkeypatch, ca_file):
        seen = []
        monkeypatch.setattr(dbexport, "_direct_conn", lambda *a: seen.append(a) or (_ for _ in ()).throw(OSError("x")))
        assert dbexport.test_connection("h", "3306", "u", "p", "d", ca_file)[0] is False
        assert seen[0][-1] == ca_file

    @pytest.mark.parametrize("which", ["jen", "kea"])
    def test_both_migrations_connect_to_the_target_with_it(self, monkeypatch, db, ca_file, which):
        """The real migrate_jen / migrate_kea against the real source, the TARGET connection faked at the one
        boundary: every `_direct_conn` call for the target carries the CA."""
        seen = []
        real = dbexport._direct_conn

        def fake(host, port, user, password, database, ssl_ca=""):
            if host == "target.invalid":
                seen.append(ssl_ca)
                raise OSError("no such target")
            return real(host, port, user, password, database, ssl_ca)

        monkeypatch.setattr(dbexport, "_direct_conn", fake)
        with contextlib.suppress(Exception):  # the faked target refuses; only the arguments matter here
            if which == "jen":
                dbexport.migrate_jen("target.invalid", 3306, "u", "p", "d", ["settings"], target_ssl_ca=ca_file)
            else:
                dbexport.migrate_kea("target.invalid", 3306, "u", "p", "d", target_ssl_ca=ca_file)
        assert seen and set(seen) == {ca_file}

    def test_the_signatures_default_to_a_plain_connection(self):
        import inspect

        for fn in (dbexport.migrate_jen, dbexport.migrate_kea):
            assert inspect.signature(fn).parameters["target_ssl_ca"].default == ""


class TestMigrationRoutes:
    def test_the_test_button_refuses_a_ca_that_is_not_a_file_and_connects_to_nothing(
        self, logged_in_client, monkeypatch
    ):
        monkeypatch.setattr(
            dbexport, "test_connection", lambda *a: (_ for _ in ()).throw(AssertionError("connected anyway"))
        )
        r = logged_in_client.post(
            "/database/migrate/test",
            data={"host": "h", "user": "u", "database": "d", "ssl_ca": "/no/such/ca.pem"},
        )
        assert r.get_json() == {"ok": False, "error": "CA bundle path not found on the Jen host: /no/such/ca.pem"}

    def test_the_test_button_passes_a_real_ca_through(self, logged_in_client, monkeypatch, ca_file):
        seen = []
        monkeypatch.setattr(dbexport, "test_connection", lambda *a: seen.append(a) or (True, {"version": "x"}))
        r = logged_in_client.post(
            "/database/migrate/test", data={"host": "h", "user": "u", "database": "d", "ssl_ca": ca_file}
        )
        assert r.get_json()["ok"] is True and seen[0][-1] == ca_file
        seen.clear()
        logged_in_client.post("/database/migrate/test", data={"host": "h", "user": "u", "database": "d"})
        assert seen[0][-1] == "", "no CA given: a plain connection"

    def test_the_run_refuses_a_missing_ca_before_starting_anything(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            dbexport, "migrate_jen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("migrated anyway"))
        )
        r = logged_in_client.post(
            "/database/migrate/run",
            data={
                "which": "jen",
                "host": "h",
                "user": "u",
                "database": "d",
                "tables": ["settings"],
                "ssl_ca": "/no/ca",
            },
        )
        assert b"event: error" in r.data and b"CA bundle path not found" in r.data

    @pytest.mark.parametrize("which", ["jen", "kea"])
    def test_the_run_hands_the_ca_to_the_migration(self, logged_in_client, monkeypatch, ca_file, which):
        seen = []
        monkeypatch.setattr(dbexport, "migrate_jen", lambda *a, **k: seen.append(("jen", k)) or ["ok"])
        monkeypatch.setattr(dbexport, "migrate_kea", lambda *a, **k: seen.append(("kea", k)) or ["ok"])
        r = logged_in_client.post(
            "/database/migrate/run",
            data={"which": which, "host": "h", "user": "u", "database": "d", "tables": ["settings"], "ssl_ca": ca_file},
        )
        assert b"event: done" in r.data
        assert seen == [(which, {"target_ssl_ca": ca_file})]

    def test_the_page_has_the_field_and_sends_it_both_times(self, logged_in_client):
        page = logged_in_client.get("/settings/databases/migrate").data.decode()
        assert 'id="t-ca"' in page and "CA bundle (optional)" in page
        assert page.count("fd.append('ssl_ca', document.getElementById('t-ca').value.trim());") == 2


class TestSetupSavesAndTestsIt:
    FORM = {
        "api_url": "http://kea.test:8000",
        "api_user": "u",
        "api_pass": "",
        "kea_db_host": "dbhost",
        "kea_db_user": "kea",
        "kea_db_pass": "",
        "kea_db_name": "kea",
    }
    CONNECTED = {
        "ok": True,
        "mode": "direct",
        "url": "http://kea.test:8000",
        "version": "3.2.0",
        "version_text": "3.2.0",
        "identified": "Dhcp4",
        "attempts": [],
    }

    def _capture(self, monkeypatch):
        seen = {"db": [], "save": []}
        monkeypatch.setattr(setup_wizard, "test_kea_connection", lambda *a, **k: self.CONNECTED)
        monkeypatch.setattr(setup_wizard, "test_kea_db", lambda h, u, p, d, **kw: seen["db"].append(kw) or (True, {}))
        monkeypatch.setattr(setup_wizard, "save_connection", lambda **kw: seen["save"].append(kw))
        monkeypatch.setattr(setup_wizard, "set_step", lambda *a: None)
        return seen

    def test_the_ca_is_tested_and_saved(self, logged_in_client, monkeypatch, ca_file):
        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=dict(self.FORM, kea_db_ssl_ca=ca_file))
        assert seen["db"][0]["ssl_ca"] == ca_file
        assert seen["save"][0]["kea_db_ssl_ca"] == ca_file

    def test_a_path_that_is_not_a_file_is_refused_before_anything_is_tested(self, logged_in_client, monkeypatch):
        seen = self._capture(monkeypatch)
        r = logged_in_client.post("/setup/connect", data=dict(self.FORM, kea_db_ssl_ca="/no/such/ca.pem"))
        assert r.status_code == 200 and b"Database CA bundle path not found" in r.data
        assert seen["db"] == [] and seen["save"] == []
        assert b"/no/such/ca.pem" in r.data, "the typed value comes back in the form"

    def test_an_empty_field_clears_a_saved_ca(self, logged_in_client, monkeypatch):
        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=self.FORM)
        assert seen["db"][0]["ssl_ca"] == "" and seen["save"][0]["kea_db_ssl_ca"] == ""

    def test_the_form_shows_the_saved_ca(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "/etc/jen/ssl/kea-db-ca.pem")
        page = logged_in_client.get("/setup/connect").data.decode()
        assert 'name="kea_db_ssl_ca"' in page and 'value="/etc/jen/ssl/kea-db-ca.pem"' in page


class TestSaveConnectionWritesIt:
    def _save(self, monkeypatch, **over):
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(list(items)))
        monkeypatch.setattr("jen.models.db.reset_kea_pools", lambda: None)
        kw = {
            "api_url": "http://kea:8000",
            "api_user": "u",
            "api_pass": "",
            "mode": "ca",
            "kea_db_host": "h",
            "kea_db_user": "u",
            "kea_db_pass": "",
            "kea_db_name": "kea",
        }
        kw.update(over)
        setup_wizard.save_connection(**kw)
        return calls[0]

    def test_it_is_written_when_given_and_cleared_by_an_empty_one(self, monkeypatch):
        assert ("kea_db", "ssl_ca", "/p/ca.pem") in self._save(monkeypatch, kea_db_ssl_ca="/p/ca.pem")
        assert ("kea_db", "ssl_ca", "") in self._save(monkeypatch, kea_db_ssl_ca="")

    def test_it_is_left_alone_when_the_caller_says_nothing(self, monkeypatch):
        assert not [i for i in self._save(monkeypatch) if i[1] == "ssl_ca"]
