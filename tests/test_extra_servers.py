"""
tests/test_extra_servers.py
───────────────────────────
v5.10.2 — Settings → Additional Servers. ChatGPT's 5.10.0/5.10.1 review:
_rewrite_extra_servers() removed every [kea_server_N] and rebuilt from a
fixed set of form fields, so `api6_url` (and any hand-added key like
`ssh_key`) was silently dropped whenever the operator edited an unrelated
field. And `api6_user` / `api6_pass` never reached the transport because
derive_kea_servers() didn't populate them.

Now: the form carries all eleven per-server fields, keys it doesn't
manage are copied back, and per-server v6 credentials make the full trip
config → model → _endpoint_for().
"""

import configparser

import pytest

from jen import extensions
from jen.config import app_config


@pytest.fixture
def isolated_config(tmp_path):
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


# All twelve per-server lists, one row's worth by default. extra_id[] is
# the row's original kea_server_N ("" = a row added in the UI).
def _form(**over):
    base = {
        "extra_id[]": "",
        "extra_name[]": "Standby",
        "extra_role[]": "standby",
        "extra_api_url[]": "http://s2:8000",
        "extra_api_user[]": "s2u",
        "extra_api_pass[]": "",
        "extra_api6_url[]": "",
        "extra_api6_user[]": "",
        "extra_api6_pass[]": "",
        "extra_ssh_host[]": "",
        "extra_ssh_user[]": "",
        "extra_kea_conf[]": "/etc/kea/kea-dhcp4.conf",
    }
    base.update(over)
    return base


def _rows(*rows):
    """Build the twelve repeated-field lists from per-row dicts. Werkzeug's
    test client sends a list value as repeated fields, which is what
    request.form.getlist() reads back."""
    keys = [
        "extra_id[]",
        "extra_name[]",
        "extra_role[]",
        "extra_api_url[]",
        "extra_api_user[]",
        "extra_api_pass[]",
        "extra_api6_url[]",
        "extra_api6_user[]",
        "extra_api6_pass[]",
        "extra_ssh_host[]",
        "extra_ssh_user[]",
        "extra_kea_conf[]",
    ]
    defaults = dict.fromkeys(keys, "")
    defaults["extra_role[]"] = "standby"
    defaults["extra_kea_conf[]"] = "/etc/kea/kea-dhcp4.conf"
    return {k: [{**defaults, **r}[k] for r in rows] for k in keys}


def _seed(*servers):
    """Seed [kea_server_N] sections from {n: {key: value}} pairs."""

    def _apply(p):
        for n, opts in servers:
            sec = f"kea_server_{n}"
            p.add_section(sec)
            for k, v in opts.items():
                p.set(sec, k, v)

    app_config.mutate(_apply)


class TestExtraServerV6EndToEnd:
    def test_page_shows_api6_url_and_user_but_never_the_password(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.mutate(
            lambda p: (
                p.add_section("kea_server_2"),
                p.set("kea_server_2", "api_url", "http://s2:8000"),
                p.set("kea_server_2", "api6_url", "http://s2:8006"),
                p.set("kea_server_2", "api6_user", "s2u6"),
                p.set("kea_server_2", "api6_pass", "s2secret"),
            )
        )
        body = logged_in_client.get("/settings/kea").data
        assert b'name="extra_api6_url[]" value="http://s2:8006"' in body
        assert b'name="extra_api6_user[]" value="s2u6"' in body
        assert b"s2secret" not in body

    def test_save_round_trip_carries_v6_creds_to_endpoint_for(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "connection_mode", "direct")
        logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_form(
                **{
                    "extra_api_url[]": "http://s2:8004",
                    "extra_api6_url[]": "http://s2:8006",
                    "extra_api6_user[]": "s2u6",
                    "extra_api6_pass[]": "s2secret",
                }
            ),
            follow_redirects=True,
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api6_url") == "http://s2:8006"
        assert disk.get("kea_server_2", "api6_user") == "s2u6"
        assert disk.get("kea_server_2", "api6_pass") == "s2secret"

        srv = extensions.KEA_SERVERS[1]
        assert srv["api6_user"] == "s2u6"
        from jen.services.kea import _endpoint_for

        url, user, pwd = _endpoint_for(srv, "dhcp6")
        assert (url, user, pwd) == ("http://s2:8006", "s2u6", "s2secret")

    def test_blank_api6_pass_keeps_the_previous_value(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.mutate(
            lambda p: (
                p.add_section("kea_server_2"),
                p.set("kea_server_2", "api_url", "http://s2:8000"),
                p.set("kea_server_2", "api6_url", "http://s2:8006"),
                p.set("kea_server_2", "api6_pass", "keepme"),
            )
        )
        logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_form(**{"extra_id[]": "2", "extra_api6_url[]": "http://s2:8006", "extra_api6_pass[]": ""}),
            follow_redirects=True,
        )
        assert _on_disk(isolated_config).get("kea_server_2", "api6_pass") == "keepme"

    def test_unknown_keys_survive_the_rebuild(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.mutate(
            lambda p: (
                p.add_section("kea_server_2"),
                p.set("kea_server_2", "api_url", "http://s2:8000"),
                p.set("kea_server_2", "ssh_key", "/etc/jen/ssh/special"),
                p.set("kea_server_2", "custom_note", "hi"),
            )
        )
        logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_form(**{"extra_id[]": "2", "extra_name[]": "Renamed"}),
            follow_redirects=True,
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "name") == "Renamed"  # form field applied
        assert disk.get("kea_server_2", "ssh_key") == "/etc/jen/ssh/special"  # preserved
        assert disk.get("kea_server_2", "custom_note") == "hi"  # preserved

    def test_mismatched_list_lengths_write_nothing(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.mutate(lambda p: (p.add_section("kea_server_2"), p.set("kea_server_2", "api_url", "http://s2:8000")))
        form = _form(**{"extra_name[]": "X"})
        del form["extra_api6_user[]"]  # one list short → zip(strict=True) raises
        r = logged_in_client.post("/settings/infrastructure/save-extra-servers", data=form, follow_redirects=True)
        assert b"form data was inconsistent" in r.data
        # section untouched
        assert _on_disk(isolated_config).get("kea_server_2", "api_url") == "http://s2:8000"

    def test_direct_mode_api6_url_without_port_is_rejected(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "connection_mode", "direct")
        r = logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_form(**{"extra_api_url[]": "http://s2:8004", "extra_api6_url[]": "http://s2"}),
            follow_redirects=True,
        )
        assert b"IPv6 API URL" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")


class TestExtraServerIdentity:
    """v5.10.3 — preservation follows the row's ORIGINAL section id
    (extra_id[]), not its position. 5.10.2 rebuilt each row into the
    section at its new position and read the blank-password fallback and
    the unknown-key snapshot from THAT section — so reordering two rows
    silently swapped their api_pass / api6_pass / ssh_key."""

    def _save(self, client, form):
        return client.post("/settings/infrastructure/save-extra-servers", data=form, follow_redirects=True)

    def test_reorder_keeps_each_password_with_its_own_server(self, logged_in_client, db, mock_kea, isolated_config):
        _seed(
            (2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}),
            (3, {"api_url": "http://s3:8000", "api_pass": "P3", "ssh_key": "/K3"}),
        )
        # Swap the two rows in the UI, both password fields left blank.
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "3", "extra_name[]": "Three", "extra_api_url[]": "http://s3:8000"},
                {"extra_id[]": "2", "extra_name[]": "Two", "extra_api_url[]": "http://s2:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_url") == "http://s3:8000"
        assert disk.get("kea_server_2", "api_pass") == "P3"  # NOT P2
        assert disk.get("kea_server_2", "ssh_key") == "/K3"
        assert disk.get("kea_server_3", "api_url") == "http://s2:8000"
        assert disk.get("kea_server_3", "api_pass") == "P2"
        assert disk.get("kea_server_3", "ssh_key") == "/K2"

    def test_deleting_the_middle_row_renumbers_without_a_gap(self, logged_in_client, db, mock_kea, isolated_config):
        _seed(
            (2, {"api_url": "http://s2:8000", "api_pass": "P2"}),
            (3, {"api_url": "http://s3:8000", "api_pass": "P3"}),
            (4, {"api_url": "http://s4:8000", "api_pass": "P4", "ssh_key": "/K4"}),
        )
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "2", "extra_api_url[]": "http://s2:8000"},
                {"extra_id[]": "4", "extra_api_url[]": "http://s4:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert not disk.has_section("kea_server_4")
        assert disk.get("kea_server_2", "api_url") == "http://s2:8000"
        assert disk.get("kea_server_3", "api_url") == "http://s4:8000"
        assert disk.get("kea_server_3", "api_pass") == "P4"  # its own, not P3's
        assert disk.get("kea_server_3", "ssh_key") == "/K4"
        assert len(extensions.KEA_SERVERS) == 3  # primary + 2, none hidden by a gap

    def test_blank_api_url_row_leaves_no_numbering_gap(self, logged_in_client, db, mock_kea, isolated_config):
        self._save(
            logged_in_client,
            _rows(
                {"extra_api_url[]": ""},  # blank row — skipped
                {"extra_name[]": "A", "extra_api_url[]": "http://a:8000"},
                {"extra_name[]": "B", "extra_api_url[]": "http://b:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_url") == "http://a:8000"
        assert disk.get("kea_server_3", "api_url") == "http://b:8000"
        # derive_kea_servers() stops at the first gap — both must be visible
        assert len(extensions.KEA_SERVERS) == 3

    def test_a_new_row_carries_nothing_over(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}))
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "2", "extra_api_url[]": "http://s2:8000"},
                {"extra_id[]": "", "extra_name[]": "Fresh", "extra_api_url[]": "http://s9:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_3", "api_pass") == "p4"  # the primary's, per isolated_config
        assert not disk.has_option("kea_server_3", "ssh_key")

    @pytest.mark.parametrize("bogus", ["99", "abc", "-1"])
    def test_an_unknown_id_is_treated_as_a_new_row(self, logged_in_client, db, mock_kea, isolated_config, bogus):
        _seed((2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}))
        self._save(logged_in_client, _rows({"extra_id[]": bogus, "extra_api_url[]": "http://new:8000"}))
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_pass") == "p4"  # not P2
        assert not disk.has_option("kea_server_2", "ssh_key")

    def test_a_duplicated_id_only_claims_the_first_row(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}))
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "2", "extra_api_url[]": "http://first:8000"},
                {"extra_id[]": "2", "extra_api_url[]": "http://second:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_pass") == "P2"
        assert disk.get("kea_server_3", "api_pass") == "p4"  # second claim refused
        assert not disk.has_option("kea_server_3", "ssh_key")

    def test_missing_id_list_is_the_inconsistent_form_path(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000"}))
        form = _form(**{"extra_name[]": "X"})
        del form["extra_id[]"]
        r = self._save(logged_in_client, form)
        assert b"form data was inconsistent" in r.data
        assert _on_disk(isolated_config).get("kea_server_2", "api_url") == "http://s2:8000"
