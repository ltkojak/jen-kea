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
    silently swapped their api_pass / api6_pass / ssh_key.

    v5.20.0 (Q15) — the section NUMBER is now a stable identity too, not
    just what travels with it: a row with a known, unclaimed id keeps
    its own `[kea_server_N]` number regardless of its position in the
    form, and a save no longer renumbers the remaining sections
    contiguously. `kea_config_revisions.server_id` and
    `kea_helper_status` are keyed by this number, so the old
    contiguous-renumbering behavior silently reassigned a deleted
    server's history/status to whichever server next landed on its old
    number."""

    def _save(self, client, form):
        return client.post("/settings/infrastructure/save-extra-servers", data=form, follow_redirects=True)

    def test_reorder_keeps_each_password_with_its_own_server(self, logged_in_client, db, mock_kea, isolated_config):
        _seed(
            (2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}),
            (3, {"api_url": "http://s3:8000", "api_pass": "P3", "ssh_key": "/K3"}),
        )
        # Submit the two rows in the OPPOSITE order — this must not move
        # anything between sections: each row's extra_id[] IS its
        # section now, full stop, regardless of where it sits in the form.
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "3", "extra_name[]": "Three", "extra_api_url[]": "http://s3:8000"},
                {"extra_id[]": "2", "extra_name[]": "Two", "extra_api_url[]": "http://s2:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "name") == "Two"
        assert disk.get("kea_server_2", "api_url") == "http://s2:8000"
        assert disk.get("kea_server_2", "api_pass") == "P2"
        assert disk.get("kea_server_2", "ssh_key") == "/K2"
        assert disk.get("kea_server_3", "name") == "Three"
        assert disk.get("kea_server_3", "api_url") == "http://s3:8000"
        assert disk.get("kea_server_3", "api_pass") == "P3"
        assert disk.get("kea_server_3", "ssh_key") == "/K3"

    def test_deleting_the_middle_row_leaves_a_gap_and_keeps_ids(self, logged_in_client, db, mock_kea, isolated_config):
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
        assert not disk.has_section("kea_server_3")  # a gap — normal now, not a bug
        assert disk.get("kea_server_2", "api_url") == "http://s2:8000"
        assert disk.get("kea_server_2", "api_pass") == "P2"
        assert disk.get("kea_server_4", "api_url") == "http://s4:8000"
        assert disk.get("kea_server_4", "api_pass") == "P4"  # its own — never renumbered away
        assert disk.get("kea_server_4", "ssh_key") == "/K4"
        assert len(extensions.KEA_SERVERS) == 3  # primary + 2, gap-tolerant read (Q14)

    def test_blank_api_url_row_is_dropped_and_the_rest_keep_their_ids(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._save(
            logged_in_client,
            _rows(
                {"extra_api_url[]": ""},  # blank row — dropped
                {"extra_name[]": "A", "extra_api_url[]": "http://a:8000"},
                {"extra_name[]": "B", "extra_api_url[]": "http://b:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        # None of these rows had a prior identity (nothing was seeded),
        # so the two real ones get sequential new ids starting at 2 —
        # the same numbers the old contiguous-renumbering behavior
        # produced, but because there's nothing to preserve yet, not
        # because a gap was closed.
        assert disk.get("kea_server_2", "api_url") == "http://a:8000"
        assert disk.get("kea_server_3", "api_url") == "http://b:8000"
        assert len(extensions.KEA_SERVERS) == 3

    def test_a_new_row_carries_nothing_over(self, logged_in_client, db, mock_kea, isolated_config):
        _seed(
            (2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}),
            (4, {"api_url": "http://s4:8000", "api_pass": "P4"}),
        )
        self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "2", "extra_api_url[]": "http://s2:8000"},
                {"extra_id[]": "4", "extra_api_url[]": "http://s4:8000"},
                {"extra_id[]": "", "extra_name[]": "Fresh", "extra_api_url[]": "http://s9:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        # The new row lands one past the highest id that exists (4), not
        # one past the number of rows (which would be 5 either way here,
        # but only coincidentally — the id space and the row count are
        # different things now that ids don't renumber contiguously).
        assert disk.get("kea_server_5", "api_url") == "http://s9:8000"
        assert disk.get("kea_server_5", "api_pass") == "p4"  # the primary's, per isolated_config
        assert not disk.has_option("kea_server_5", "ssh_key")
        assert disk.get("kea_server_2", "api_pass") == "P2"  # untouched
        assert disk.get("kea_server_4", "api_pass") == "P4"  # untouched

    @pytest.mark.parametrize("bogus", ["99", "abc", "-1"])
    def test_an_unknown_id_is_treated_as_a_new_row(self, logged_in_client, db, mock_kea, isolated_config, bogus):
        _seed((2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}))
        self._save(logged_in_client, _rows({"extra_id[]": bogus, "extra_api_url[]": "http://new:8000"}))
        disk = _on_disk(isolated_config)
        # Section 2 wasn't resubmitted at all (this save has only the
        # one, unknown-id row), so it's gone; the bogus-id row is new
        # and lands one past the highest id that existed THIS save (2),
        # not at 2 itself.
        assert not disk.has_section("kea_server_2")
        assert disk.get("kea_server_3", "api_pass") == "p4"  # the primary's fallback
        assert not disk.has_option("kea_server_3", "ssh_key")

    def test_history_stays_attached_after_deleting_another_server(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        from jen.services import config_revisions as rev

        _seed(
            (3, {"api_url": "http://s3:8000", "api_pass": "P3"}),
            (4, {"api_url": "http://s4:8000", "api_pass": "P4"}),
        )
        rev.record(3, "dhcp4", {"Dhcp4": {"subnet4": [{"id": 3}]}}, "sha3", "seed 3", source="jen", hash_kind="raw")
        rev.record(4, "dhcp4", {"Dhcp4": {"subnet4": [{"id": 4}]}}, "sha4", "seed 4", source="jen", hash_kind="raw")
        try:
            # Delete server 3 by simply not resubmitting its row.
            self._save(logged_in_client, _rows({"extra_id[]": "4", "extra_api_url[]": "http://s4:8000"}))
            disk = _on_disk(isolated_config)
            assert not disk.has_section("kea_server_3")
            assert disk.get("kea_server_4", "api_url") == "http://s4:8000"

            # Server 4's history stays attached to id 4 — untouched by
            # server 3's deletion, and NOT reassigned to whatever a
            # contiguous renumber would have put at that position.
            latest4 = rev.latest(4, "dhcp4")
            assert latest4 is not None and latest4["summary"] == "seed 4"
            # Server 3's history is orphaned (its config section is
            # gone) but still lives under id 3 — it is not silently
            # inherited by another server.
            latest3 = rev.latest(3, "dhcp4")
            assert latest3 is not None and latest3["summary"] == "seed 3"
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM kea_config_revisions WHERE server_id IN (3, 4)")
            db.commit()

    def test_a_duplicated_id_is_refused_outright_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        """v5.68.0-beta.27 (Q162): this used to give the first row the id and the second a fresh one. A submitted id that appears twice is a tampered form
        (Jen's own page never sends one), and the identity of a server is its id: refused before any comparison, with the configuration untouched."""
        _seed((2, {"api_url": "http://s2:8000", "api_pass": "P2", "ssh_key": "/K2"}))
        r = self._save(
            logged_in_client,
            _rows(
                {"extra_id[]": "2", "extra_api_url[]": "http://first:8000"},
                {"extra_id[]": "2", "extra_api_url[]": "http://second:8000"},
            ),
        )
        assert b"duplicate or unknown server id" in r.data
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_url") == "http://s2:8000" and disk.get("kea_server_2", "api_pass") == "P2"
        assert not disk.has_section("kea_server_3"), "no second claim was turned into a new server"

    def test_missing_id_list_is_the_inconsistent_form_path(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000"}))
        form = _form(**{"extra_name[]": "X"})
        del form["extra_id[]"]
        r = self._save(logged_in_client, form)
        assert b"form data was inconsistent" in r.data
        assert _on_disk(isolated_config).get("kea_server_2", "api_url") == "http://s2:8000"


class TestRemovingAServerWithInvestigationLoggingOn:
    """v5.68.0-beta.9 (Q144): a server that still has an investigation-logging entry (the log level on, or a restore not finished) cannot
    be removed - or have its API URL or SSH host blanked - from this form until turn_off has succeeded: Jen would lose the only way it has
    to put the level back."""

    @staticmethod
    def _entry_for(server_id, name="Standby"):
        import json

        from jen.models import user as _user

        _user.set_global_setting(
            "investigation_logging",
            json.dumps(
                {
                    "servers": {
                        str(server_id): {
                            "name": name,
                            "until": "2099-01-01T00:00:00+00:00",
                            "file": "debug",
                            "daemon": "debug",
                            "pending": None,
                            "ssh_host": "10.0.0.2",
                        }
                    }
                }
            ),
        )

    @staticmethod
    def _clear():
        from jen.models import user as _user

        _user.set_global_setting("investigation_logging", "")

    def test_removing_the_row_is_refused_and_the_section_stays(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(2)
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True
            )
            assert b"Investigation logging is on for Standby" in r.data and b"turn it off from Servers first" in r.data
            assert _on_disk(isolated_config).has_section("kea_server_2"), "nothing was written"
        finally:
            self._clear()

    def test_blanking_its_ssh_host_is_refused_too(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(2)
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-extra-servers",
                data=_rows({"extra_id[]": "2", "extra_api_url[]": "http://s2:8000", "extra_ssh_host[]": ""}),
                follow_redirects=True,
            )
            assert b"turn it off from Servers first" in r.data
            assert _on_disk(isolated_config).get("kea_server_2", "ssh_host") == "10.0.0.2"
        finally:
            self._clear()

    def test_editing_it_while_keeping_it_is_allowed(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(2)
        try:
            logged_in_client.post(
                "/settings/infrastructure/save-extra-servers",
                data=_rows(
                    {
                        "extra_id[]": "2",
                        "extra_name[]": "Renamed",
                        "extra_api_url[]": "http://s2:8000",
                        "extra_ssh_host[]": "10.0.0.2",
                    }
                ),
                follow_redirects=True,
            )
            assert _on_disk(isolated_config).get("kea_server_2", "name") == "Renamed"
        finally:
            self._clear()

    def test_after_turn_off_the_removal_goes_through(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(2)
        self._clear()  # what a successful turn_off leaves
        logged_in_client.post("/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True)
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_another_servers_entry_does_not_block_removing_this_one(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(5, name="Elsewhere")
        try:
            logged_in_client.post("/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True)
            assert not _on_disk(isolated_config).has_section("kea_server_2")
        finally:
            self._clear()

    def test_the_refusal_writes_an_audit_row(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._entry_for(2)
        try:
            logged_in_client.post("/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True)
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action='INVESTIGATION_LOGGING_REMOVAL_REFUSED'")
                assert cur.fetchone()["n"] == 1
        finally:
            self._clear()

    def test_the_primary_ssh_host_cannot_be_blanked_while_it_is_on(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._entry_for(1, name="Primary")
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "", "user": "", "kea_conf": ""},
                follow_redirects=True,
            )
            assert b"turn it off from Servers first" in r.data
        finally:
            self._clear()


class TestRemovingAServerWhileTheInvestigationRecordIsUnreadable:
    """v5.68.0-beta.26 (Q161, item 1): an unreadable record is not evidence that a server is NOT at investigation DEBUG. Both settings routes already stop on a
    non-empty refusal; `blocking_removal` now returns one for a damaged record."""

    @staticmethod
    def _damage(raw="{broken"):
        from jen.models import user as _user

        _user.set_global_setting("investigation_logging", raw)

    @staticmethod
    def _clear():
        from jen.models import user as _user

        _user.set_global_setting("investigation_logging", "")

    def test_removing_an_extra_server_is_refused_with_the_sentence_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._damage()
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True
            )
            assert b"cannot be read, so it cannot tell whether this server is at investigation DEBUG" in r.data
            assert _on_disk(isolated_config).has_section("kea_server_2"), "nothing was written"
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action='INVESTIGATION_LOGGING_REMOVAL_REFUSED'")
                assert cur.fetchone()["n"] == 1
        finally:
            self._clear()

    def test_blanking_the_primary_ssh_host_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        self._damage('{"servers": []}')
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "", "user": "", "kea_conf": ""},
                follow_redirects=True,
            )
            assert b"cannot be read, so it cannot tell whether this server is at investigation DEBUG" in r.data
        finally:
            self._clear()

    def test_a_valid_empty_record_allows_the_removal(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}))
        self._clear()
        logged_in_client.post("/settings/infrastructure/save-extra-servers", data=_rows(), follow_redirects=True)
        assert not _on_disk(isolated_config).has_section("kea_server_2")


class TestChangingWhereAServerIsReachedWhileInvestigationLoggingIsOn:
    """v5.68.0-beta.27 (Q162, item 1): the removal guard protects a server's presence; the same id with a new SSH host, SSH user, config path or API URL
    passed it. Every assertion is on what is on disk, the flash, and the audit row."""

    SERVER = {"api_url": "http://s2:8000", "name": "Standby", "ssh_host": "10.0.0.2"}
    SAME_ROW = {
        "extra_id[]": "2",
        "extra_name[]": "Standby",
        "extra_api_url[]": "http://s2:8000",
        "extra_ssh_host[]": "10.0.0.2",
    }

    @staticmethod
    def _entry(server_id, name="Standby"):
        TestRemovingAServerWithInvestigationLoggingOn._entry_for(server_id, name)

    @staticmethod
    def _clear():
        TestRemovingAServerWithInvestigationLoggingOn._clear()

    @staticmethod
    def _refused_rows(db):
        with db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE action='INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED'"
            )
            return cur.fetchone()["n"]

    def _post_extra(self, client, **row):
        return client.post(
            "/settings/infrastructure/save-extra-servers", data=_rows({**self.SAME_ROW, **row}), follow_redirects=True
        )

    def test_the_primary_ssh_host_pointed_elsewhere_is_refused_not_written_and_audited(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        app_config.write_values([("kea_ssh", "host", "10.0.0.5"), ("kea_ssh", "user", "jen")])
        self._entry(1, "Primary")
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "10.9.9.9", "user": "jen", "kea_conf": ""},
                follow_redirects=True,
            )
            assert b"Changing its ssh_host now would point Jen at a different Kea" in r.data
            assert _on_disk(isolated_config).get("kea_ssh", "host") == "10.0.0.5", "nothing was written"
            assert self._refused_rows(db) == 1
        finally:
            self._clear()

    def test_the_primary_ssh_save_that_changes_nothing_identity_goes_through(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        app_config.write_values([("kea_ssh", "host", "10.0.0.5"), ("kea_ssh", "user", "jen")])
        self._entry(1, "Primary")
        try:
            logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "10.0.0.5", "user": "jen", "kea_conf": ""},
                follow_redirects=True,
            )
            assert self._refused_rows(db) == 0
        finally:
            self._clear()

    def test_an_extra_server_kept_with_a_new_host_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, dict(self.SERVER)))
        self._entry(2)
        try:
            r = self._post_extra(logged_in_client, **{"extra_ssh_host[]": "10.7.7.7"})
            assert b"Changing its ssh_host now would point Jen at a different Kea" in r.data
            assert _on_disk(isolated_config).get("kea_server_2", "ssh_host") == "10.0.0.2"
            assert self._refused_rows(db) == 1
        finally:
            self._clear()

    def test_a_changed_api_url_is_refused_for_the_primary_and_an_unchanged_one_is_not(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._entry(1, "Primary")
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-kea",
                data={"api_url": "http://other:8000", "api_user": "u4", "connection_mode": "ca"},
                follow_redirects=True,
            )
            assert b"Changing its api_url now would point Jen at a different Kea" in r.data
            assert _on_disk(isolated_config).get("kea", "api_url") == "http://1.2.3.4:8000"
            logged_in_client.post(
                "/settings/infrastructure/save-kea",
                data={"api_url": "http://1.2.3.4:8000", "api_user": "renamed-user", "connection_mode": "ca"},
                follow_redirects=True,
            )
            assert _on_disk(isolated_config).get("kea", "api_user") == "renamed-user", "credentials are not identity"
        finally:
            self._clear()

    def test_an_unreadable_record_refuses_any_endpoint_change(self, logged_in_client, db, mock_kea, isolated_config):
        from jen.models import user as _user

        _seed((2, dict(self.SERVER)))
        _user.set_global_setting("investigation_logging", "{broken")
        try:
            r = self._post_extra(logged_in_client, **{"extra_api_url[]": "http://elsewhere:8000"})
            assert b"cannot be read, so it cannot tell whether this server is at investigation DEBUG" in r.data
            assert _on_disk(isolated_config).get("kea_server_2", "api_url") == "http://s2:8000"
            assert self._refused_rows(db) == 1
        finally:
            self._clear()

    def test_a_valid_empty_record_saves_the_change(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, dict(self.SERVER)))
        self._clear()
        self._post_extra(logged_in_client, **{"extra_ssh_host[]": "10.7.7.7"})
        assert _on_disk(isolated_config).get("kea_server_2", "ssh_host") == "10.7.7.7"

    def test_the_display_name_and_the_credentials_alone_are_saved_with_an_active_entry(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, dict(self.SERVER)))
        self._entry(2)
        try:
            self._post_extra(logged_in_client, **{"extra_name[]": "Renamed", "extra_api_user[]": "new-user"})
            disk = _on_disk(isolated_config)
            assert disk.get("kea_server_2", "name") == "Renamed" and disk.get("kea_server_2", "api_user") == "new-user"
            assert self._refused_rows(db) == 0
        finally:
            self._clear()

    def test_a_duplicated_submitted_id_is_refused_outright(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, dict(self.SERVER)))
        r = logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_rows(self.SAME_ROW, {**self.SAME_ROW, "extra_api_url[]": "http://second:8000"}),
            follow_redirects=True,
        )
        assert b"duplicate or unknown server id" in r.data
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "api_url") == "http://s2:8000" and not disk.has_section("kea_server_3"), (
            "nothing was written"
        )

    def test_an_unknown_id_carrying_an_ssh_host_is_refused_outright_but_a_new_row_is_not(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        _seed((2, dict(self.SERVER)))
        r = logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_rows(
                self.SAME_ROW,
                {
                    **self.SAME_ROW,
                    "extra_id[]": "7",
                    "extra_api_url[]": "http://s7:8000",
                    "extra_ssh_host[]": "10.0.0.7",
                },
            ),
            follow_redirects=True,
        )
        assert b"duplicate or unknown server id" in r.data and not _on_disk(isolated_config).has_section("kea_server_3")
        logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_rows(
                self.SAME_ROW,
                {
                    "extra_id[]": "",
                    "extra_name[]": "Fresh",
                    "extra_api_url[]": "http://s9:8000",
                    "extra_ssh_host[]": "10.0.0.9",
                },
            ),
            follow_redirects=True,
        )
        assert _on_disk(isolated_config).get("kea_server_3", "ssh_host") == "10.0.0.9", "a blank id is a new row"

    def test_after_turn_off_the_change_is_saved(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, dict(self.SERVER)))
        self._entry(2)
        self._clear()  # what a successful turn_off leaves
        self._post_extra(logged_in_client, **{"extra_ssh_host[]": "10.7.7.7"})
        assert _on_disk(isolated_config).get("kea_server_2", "ssh_host") == "10.7.7.7"


class TestServerNamesAndConfigFilenames:
    """v5.69.0-beta.3 (Q172, items 6 and 7): two servers never share a name (the change set's restart and revert bookkeeping is keyed by id, but every line a person reads
    names a server by it), a name is one line of at most 100 characters, and the configured Kea config file is a `*.conf` file (it IS the dhcp4 file Jen reads and writes)."""

    def _save(self, client, form):
        return client.post("/settings/infrastructure/save-extra-servers", data=form, follow_redirects=True)

    def test_two_rows_with_one_name_are_refused_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = self._save(
            logged_in_client,
            _rows(
                {"extra_name[]": "Standby", "extra_api_url[]": "http://a:8000"},
                {"extra_name[]": "standby", "extra_api_url[]": "http://b:8000"},
            ),
        )
        assert b"every server needs its own name" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_a_name_equal_to_the_primarys_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "name", "Main")
        r = self._save(logged_in_client, _rows({"extra_name[]": "main", "extra_api_url[]": "http://a:8000"}))
        assert b"every server needs its own name" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_a_name_over_one_hundred_characters_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = self._save(logged_in_client, _rows({"extra_name[]": "n" * 101, "extra_api_url[]": "http://a:8000"}))
        assert b"one line of at most 100 characters" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_a_name_with_a_newline_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        r = self._save(
            logged_in_client, _rows({"extra_name[]": "Standby\nrole = primary", "extra_api_url[]": "http://a:8000"})
        )
        assert b"one line of at most 100 characters" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_distinct_names_and_blank_names_are_saved(self, logged_in_client, db, mock_kea, isolated_config):
        self._save(
            logged_in_client,
            _rows(
                {"extra_name[]": "", "extra_api_url[]": "http://a:8000"},
                {"extra_name[]": "", "extra_api_url[]": "http://b:8000"},
                {"extra_name[]": "n" * 100, "extra_api_url[]": "http://c:8000"},
            ),
        )
        disk = _on_disk(isolated_config)
        assert disk.get("kea_server_2", "name") == "Kea Server 2" and disk.get("kea_server_3", "name") == "Kea Server 3"
        assert disk.get("kea_server_4", "name") == "n" * 100

    def test_an_extra_servers_config_file_must_be_a_dot_conf_file(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = self._save(
            logged_in_client, _rows({"extra_api_url[]": "http://a:8000", "extra_kea_conf[]": "/etc/kea/kea-dhcp4.json"})
        )
        assert b"must end in .conf" in r.data
        assert not _on_disk(isolated_config).has_section("kea_server_2")

    def test_the_primarys_ssh_save_refuses_a_config_file_that_is_not_dot_conf(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = logged_in_client.post(
            "/settings/infrastructure/save-ssh",
            data={"host": "10.0.0.5", "user": "jen", "kea_conf": "/etc/kea/kea-dhcp4.json"},
            follow_redirects=True,
        )
        assert b"must end in .conf" in r.data
        assert not _on_disk(isolated_config).has_section("kea_ssh")

    def test_the_primarys_ssh_save_accepts_a_renamed_dot_conf_file(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        logged_in_client.post(
            "/settings/infrastructure/save-ssh",
            data={"host": "10.0.0.5", "user": "jen", "kea_conf": "/etc/kea/kea-dhcp4-prod.conf"},
            follow_redirects=True,
        )
        assert _on_disk(isolated_config).get("kea_ssh", "kea_conf") == "/etc/kea/kea-dhcp4-prod.conf"


class TestThePrimarysNameFollowsTheSameRules:
    """The second pass (Q172, finding 7): the HA form renames the primary; it was refused nothing, so it could take an extra server's name (locking the extra-servers form out)
    or be a multi-line value."""

    def _save(self, client, name):
        return client.post(
            "/settings/infrastructure/save-ha", data={"ha_mode": "", "server_name": name}, follow_redirects=True
        )

    def test_a_name_an_extra_server_already_has_is_refused(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"name": "Kea-B", "api_url": "http://s2:8000"}))
        r = self._save(logged_in_client, "kea-b")
        assert b"every server needs its own name" in r.data
        assert not _on_disk(isolated_config).has_option("kea", "name")

    @pytest.mark.parametrize("bad", ["two\nlines", "x" * 101])
    def test_a_name_that_is_not_one_short_line_is_refused(self, logged_in_client, db, mock_kea, isolated_config, bad):
        r = self._save(logged_in_client, bad)
        assert b"one line of at most 100 characters" in r.data
        assert not _on_disk(isolated_config).has_option("kea", "name")

    def test_a_fresh_name_is_saved(self, logged_in_client, db, mock_kea, isolated_config):
        _seed((2, {"name": "Kea-B", "api_url": "http://s2:8000"}))
        self._save(logged_in_client, "kea-a")
        assert _on_disk(isolated_config).get("kea", "name") == "kea-a"


class TestTheKeaLogPathField:
    """v5.69.0-beta.6 (Q175): `[kea] dhcp4_log_path` is a field on Settings → Kea → SSH, validated by the rule the Kea host's helper applies to a log it reads (`valid_log_path`),
    and blank is the default again - the key is removed, never saved empty."""

    URL = "/settings/infrastructure/save-ssh"

    def _post(self, client, **data):
        return client.post(
            self.URL, data={"host": "10.0.0.5", "user": "jen", "kea_conf": "", **data}, follow_redirects=True
        )

    def test_the_field_renders_with_the_configured_value_and_the_default_as_the_placeholder(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        app_config.write_value("kea", "dhcp4_log_path", "/var/log/kea/dhcp4.log")
        r = logged_in_client.get("/settings/kea")
        body = r.data.decode()
        assert 'name="dhcp4_log_path"' in body and 'value="/var/log/kea/dhcp4.log"' in body
        assert 'placeholder="/var/log/kea/kea-dhcp4.log"' in body
        assert 'for="f-dhcp4_log_path"' in body

    def test_a_path_outside_var_log_is_refused_and_the_key_is_unchanged(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        app_config.write_value("kea", "dhcp4_log_path", "/var/log/kea/mine.log")
        r = self._post(logged_in_client, dhcp4_log_path="/etc/shadow")
        assert b"Invalid Kea log path" in r.data
        assert _on_disk(isolated_config).get("kea", "dhcp4_log_path") == "/var/log/kea/mine.log"
        assert extensions.DHCP4_LOG == "/var/log/kea/mine.log"

    @pytest.mark.parametrize(
        "bad", ["/var/log/../etc/x.log", "/var/log/kea/x.txt", "var/log/x.log", "/var/log/a b.log", "/var/log/x;y.log"]
    )
    def test_other_shapes_the_host_would_refuse_are_refused_here(
        self, logged_in_client, db, mock_kea, isolated_config, bad
    ):
        r = self._post(logged_in_client, dhcp4_log_path=bad)
        assert b"Invalid Kea log path" in r.data
        assert not _on_disk(isolated_config).has_option("kea", "dhcp4_log_path")

    def test_a_good_path_is_written_and_is_live(self, logged_in_client, db, mock_kea, isolated_config):
        self._post(logged_in_client, dhcp4_log_path="/var/log/kea/dhcp4.log")
        assert _on_disk(isolated_config).get("kea", "dhcp4_log_path") == "/var/log/kea/dhcp4.log"
        assert extensions.DHCP4_LOG == "/var/log/kea/dhcp4.log"

    def test_blank_removes_the_key_and_is_the_default_again(self, logged_in_client, db, mock_kea, isolated_config):
        app_config.write_value("kea", "dhcp4_log_path", "/var/log/kea/dhcp4.log")
        self._post(logged_in_client, dhcp4_log_path="")
        assert not _on_disk(isolated_config).has_option("kea", "dhcp4_log_path")
        assert extensions.DHCP4_LOG == "/var/log/kea/kea-dhcp4.log"

    def test_an_empty_value_already_in_the_file_reads_as_the_default(self, isolated_config):
        app_config.write_value("kea", "dhcp4_log_path", "")
        assert extensions.DHCP4_LOG == "/var/log/kea/kea-dhcp4.log"

    def test_a_refused_log_path_writes_nothing_of_the_ssh_form_either(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        self._post(logged_in_client, host="10.9.9.9", dhcp4_log_path="/etc/passwd")
        assert not _on_disk(isolated_config).has_option("kea_ssh", "host")

    def test_saving_the_path_forgets_where_each_servers_log_was_found(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        from jen.services import log_tail

        log_tail._paths[99] = (1e12, "/var/log/kea/stale.log")
        self._post(logged_in_client, dhcp4_log_path="/var/log/kea/dhcp4.log")
        assert 99 not in log_tail._paths
