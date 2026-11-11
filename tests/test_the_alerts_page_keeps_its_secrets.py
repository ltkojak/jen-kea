"""v7.0.0-beta.12 (Q226) - the DB-backed rows of the pass on 7.0.0-beta.11.

AL2  the Alerts page carries no channel secret: (Q227, AM1, AM7) the `<script>` data carries only the keys `SHOWN_KEYS` names, so a write-only key is absent, not blank.
AL3  a blank secret on an edit is kept only while the channel names the same place; a blank for a changed SMTP host is refused with the field named.
AL24 a subnet-restricted admin sees only channels inside their scope and may not edit, test or delete one outside it ("Channel not found.").
AL13 the unrestricted branch of the channel's scope refuses a value that is not a whole number, whole.
AL23 the SMTP port is validated where it is typed.
AL5  the Security page prints the rate limit the server applies, not the stored text.

Needs the database (the `client`, `db` and `logged_in_client` fixtures of tests/conftest.py)."""

import json

import pytest

from tests.conftest import restricted_client

SAVE = "/settings/alerts/save-channel"


def _row(db, name):
    db.commit()  # a fresh read view: the connection is REPEATABLE READ with autocommit off, and the routes commit on another connection (Q215's F2)
    with db.cursor() as cur:
        cur.execute("SELECT * FROM alert_channels WHERE channel_name=%s", (name,))
        return cur.fetchone()


def _drop(db, name):
    with db.cursor() as cur:
        cur.execute("DELETE FROM alert_channels WHERE channel_name=%s", (name,))
    db.commit()


def _config(db, name):
    from jen.services import alerts

    row = _row(db, name)
    return alerts.get_channel_config(row) if row else None


def _email(name, **over):
    data = {
        "channel_type": "email",
        "channel_name": name,
        "enabled": "on",
        "smtp_host": "mail.example.test",
        "smtp_port": "587",
        "smtp_user": "jen",
        "smtp_pass": "s3cret-pass",
        "from_addr": "jen@example.test",
        "to_addr": "ops@example.test",
        "use_tls": "on",
        "alert_types[]": ["kea_down"],
    }
    data.update(over)
    return data


def _set_global(db, key, value):
    from jen.models.user import set_global_setting

    assert set_global_setting(key, value)


class TestThePageCarriesNoSecret:
    """AL2."""

    def test_the_script_data_has_no_secret_key_and_the_rest_present(self, logged_in_client, db):
        name = "_secret_page"
        _drop(db, name)
        try:
            r = logged_in_client.post(SAVE, data=_email(name), follow_redirects=True)
            assert r.status_code == 200
            assert _config(db, name)["smtp_pass"] == "s3cret-pass", "stored, encrypted at rest"
            html = logged_in_client.get("/settings/alerts").data.decode()
            assert "s3cret-pass" not in html
            # (Q227, AM1) the key is absent. `"smtp_pass":` is the script data's spelling; the form's own `name="smtp_pass"` input stays
            assert '"smtp_pass":' not in html and '"smtp_host": "mail.example.test"' in html
        finally:
            _drop(db, name)

    def test_a_generic_webhooks_url_is_not_in_the_page_and_a_blank_one_keeps_it(self, logged_in_client, db):
        """(Q227, AM1, AM23) a webhook URL carries its token in the path or the query. It is write-only: absent from the page, and an edit that leaves it blank keeps it."""
        name = "_secret_hook"
        _drop(db, name)
        data = {
            "channel_type": "webhook",
            "channel_name": name,
            "enabled": "on",
            "webhook_url": "https://hooks.example.test/in/QrStUvTok?key=WxYzTok",
            "header_name": "X-Token",
            "header_value": "HdrTok123",
            "alert_types[]": ["kea_down"],
        }
        try:
            logged_in_client.post(SAVE, data=data, follow_redirects=True)
            row = _row(db, name)
            assert row is not None
            html = logged_in_client.get("/settings/alerts").data.decode()
            assert "QrStUvTok" not in html and "WxYzTok" not in html and "HdrTok123" not in html
            assert '"webhook_url":' not in html and '"header_name": "X-Token"' in html
            r = logged_in_client.post(
                SAVE,
                data={**data, "channel_id": str(row["id"]), "webhook_url": "", "header_value": ""},
                follow_redirects=True,
            )
            assert r.status_code == 200 and b"enter the secret again" not in r.data
            cfg = _config(db, name)
            assert cfg["webhook_url"] == data["webhook_url"] and cfg["header_value"] == "HdrTok123"
        finally:
            _drop(db, name)

    def test_a_webhook_url_with_a_password_in_it_is_refused(self, logged_in_client, db):  # AM23, CRED-005
        name = "_secret_userinfo"
        _drop(db, name)
        try:
            logged_in_client.post(
                SAVE,
                data={
                    "channel_type": "webhook",
                    "channel_name": name,
                    "enabled": "on",
                    "webhook_url": "https://jen:PwInUrl@hooks.example.test/x",
                    "alert_types[]": ["kea_down"],
                },
                follow_redirects=True,
            )
            assert _row(db, name) is None, "nothing was written"
        finally:
            _drop(db, name)

    def test_q228_a_header_value_is_not_carried_to_another_path(
        self, logged_in_client, db
    ):  # the beta.13 review's #2, CRED-002
        name = "_secret_path"
        _drop(db, name)
        data = {
            "channel_type": "webhook",
            "channel_name": name,
            "enabled": "on",
            "webhook_url": "https://hooks.example.test/team-a",
            "header_name": "Authorization",
            "header_value": "TeamASecret77",
            "alert_types[]": ["kea_down"],
        }
        try:
            logged_in_client.post(SAVE, data=data, follow_redirects=True)
            row = _row(db, name)
            assert row is not None
            r = logged_in_client.post(
                SAVE,
                data={
                    **data,
                    "channel_id": str(row["id"]),
                    "webhook_url": "https://hooks.example.test/team-b",
                    "header_value": "",
                },
                follow_redirects=True,
            )
            assert b"enter the secret again" in r.data
            cfg = _config(db, name)
            assert cfg["webhook_url"] == data["webhook_url"] and cfg["header_value"] == "TeamASecret77"
        finally:
            _drop(db, name)

    def test_q228_a_stored_ntfy_address_with_a_password_is_withheld_and_kept(
        self, logged_in_client, db
    ):  # AN1, CRED-005
        from jen.services import alerts

        name = "_secret_ntfy_legacy"
        _drop(db, name)
        legacy = {
            "url": "https://qzuser:LegacyPw9@ntfy.example.test",
            "topic": "jen",
            "token": "tk_LegacyTok5",
            "priority": "default",
        }
        try:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types, subnet_scope) VALUES (%s, %s, %s, %s, %s, %s)",
                    ("ntfy", name, 1, alerts.encode_channel_config(legacy), json.dumps(["kea_down"]), None),
                )
            db.commit()
            html = logged_in_client.get("/settings/alerts").data.decode()
            assert "LegacyPw9" not in html and "tk_LegacyTok5" not in html and "qzuser" not in html
            assert "url_withheld" in html and "so it is not shown. It is still used as saved." in html
            row = _row(db, name)
            r = logged_in_client.post(
                SAVE,
                data={
                    "channel_type": "ntfy",
                    "channel_name": name,
                    "enabled": "on",
                    "channel_id": str(row["id"]),
                    "ntfy_url": "",
                    "ntfy_topic": "jen-renamed",
                    "ntfy_token": "",
                    "ntfy_priority": "default",
                    "alert_types[]": ["kea_down"],
                },
                follow_redirects=True,
            )
            assert r.status_code == 200 and b"enter the secret again" not in r.data
            cfg = _config(db, name)
            assert cfg["url"] == legacy["url"] and cfg["token"] == "tk_LegacyTok5" and cfg["topic"] == "jen-renamed"
        finally:
            _drop(db, name)


class TestAScopedChannelIsNotSentTheDailySummary:
    """(Q227, AM2) the daily summary names every subnet. A channel limited to some subnets cannot take it, and an alert type that is not on the list refuses the form."""

    @staticmethod
    def _hook(name, **over):
        data = {
            "channel_type": "webhook",
            "channel_name": name,
            "enabled": "on",
            "webhook_url": "https://hooks.example.test/x",
            "alert_types[]": ["kea_down", "daily_summary"],
        }
        data.update(over)
        return data

    def test_a_scoped_channel_with_the_daily_summary_is_refused(self, logged_in_client, db):
        name = "_scoped_summary"
        _drop(db, name)
        try:
            r = logged_in_client.post(SAVE, data=self._hook(name, subnet_ids=["1"]), follow_redirects=True)
            assert r.status_code == 200 and b"only a channel for All Subnets can receive it" in r.data
            assert _row(db, name) is None, "nothing was written"
        finally:
            _drop(db, name)

    def test_a_channel_for_all_subnets_takes_it(self, logged_in_client, db):
        name = "_all_summary"
        _drop(db, name)
        try:
            logged_in_client.post(SAVE, data=self._hook(name, subnet_ids=["all"]), follow_redirects=True)
            row = _row(db, name)
            assert row is not None and row["subnet_scope"] is None
            assert json.loads(row["alert_types"]) == ["kea_down", "daily_summary"]
        finally:
            _drop(db, name)

    def test_a_restricted_admin_cannot_tick_it(self, client, db):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_ch_summary")
        name = "_restricted_summary"
        _drop(db, name)
        try:
            r = c.post(SAVE, data=self._hook(name, subnet_ids=["1"]), follow_redirects=True)
            assert r.status_code == 200 and b"only a channel for All Subnets can receive it" in r.data
            assert _row(db, name) is None
        finally:
            _drop(db, name)

    def test_an_alert_type_that_is_not_on_the_list_is_refused(self, logged_in_client, db):
        name = "_bad_type"
        _drop(db, name)
        try:
            r = logged_in_client.post(
                SAVE, data=self._hook(name, **{"alert_types[]": ["kea_down", "not_a_type"]}), follow_redirects=True
            )
            assert r.status_code == 200 and b"Choose the alert types from the list." in r.data
            assert _row(db, name) is None
        finally:
            _drop(db, name)

    def test_a_telegram_token_and_a_slack_url_are_blank_too(self, logged_in_client, db):
        for name, data in (
            (
                "_secret_tg",
                {
                    "channel_type": "telegram",
                    "channel_name": "_secret_tg",
                    "enabled": "on",
                    "token": "111:AbCdEfTok",
                    "chat_id": "42",
                    "alert_types[]": ["kea_down"],
                },
            ),
            (
                "_secret_slack",
                {
                    "channel_type": "slack",
                    "channel_name": "_secret_slack",
                    "enabled": "on",
                    "slack_webhook": "https://hooks.slack.com/services/T/B/XyZsecret",
                    "alert_types[]": ["kea_down"],
                },
            ),
        ):
            _drop(db, name)
            try:
                logged_in_client.post(SAVE, data=data, follow_redirects=True)
                html = logged_in_client.get("/settings/alerts").data.decode()
                assert "AbCdEfTok" not in html and "XyZsecret" not in html, name
                assert '"chat_id": "42"' in html or name != "_secret_tg"
            finally:
                _drop(db, name)


class TestABlankSecretIsKeptOnlyForTheSamePlace:
    """AL3, AL23."""

    def _make(self, client, db, name):
        _drop(db, name)
        client.post(SAVE, data=_email(name), follow_redirects=True)
        row = _row(db, name)
        assert row is not None
        return row["id"]

    def test_a_blank_password_for_the_same_server_is_kept(self, logged_in_client, db):
        name = "_kept_same"
        cid = self._make(logged_in_client, db, name)
        try:
            r = logged_in_client.post(
                SAVE,
                data=_email(name, channel_id=str(cid), smtp_pass="", to_addr="new@example.test"),
                follow_redirects=True,
            )
            assert r.status_code == 200 and b"enter the secret again" not in r.data
            cfg = _config(db, name)
            assert cfg["smtp_pass"] == "s3cret-pass" and cfg["to_addr"] == "new@example.test"
        finally:
            _drop(db, name)

    @pytest.mark.parametrize("change", [{"smtp_host": "other.example.test"}, {"smtp_port": "25"}, {"use_tls": ""}])
    def test_a_blank_password_for_a_changed_place_is_refused_and_nothing_is_written(self, logged_in_client, db, change):
        name = "_kept_changed"
        cid = self._make(logged_in_client, db, name)
        try:
            data = _email(name, channel_id=str(cid), smtp_pass="", **change)
            if "use_tls" in change:
                data.pop("use_tls")
            r = logged_in_client.post(SAVE, data=data, follow_redirects=True)
            assert (
                r.status_code == 200
                and b"The channel&#39;s destination changed - enter the secret again." in r.data
                or b"destination changed" in r.data
            ), r.data[:3000]
            cfg = _config(db, name)
            assert cfg["smtp_host"] == "mail.example.test" and cfg["smtp_port"] == "587" and cfg["use_tls"] == "true", (
                "the row is as it was"
            )
            assert cfg["smtp_pass"] == "s3cret-pass"
        finally:
            _drop(db, name)

    def test_a_typed_password_goes_with_the_new_server(self, logged_in_client, db):
        name = "_kept_typed"
        cid = self._make(logged_in_client, db, name)
        try:
            logged_in_client.post(
                SAVE,
                data=_email(name, channel_id=str(cid), smtp_host="other.example.test", smtp_pass="new-pass"),
                follow_redirects=True,
            )
            cfg = _config(db, name)
            assert cfg["smtp_host"] == "other.example.test" and cfg["smtp_pass"] == "new-pass"
        finally:
            _drop(db, name)

    def test_use_tls_round_trips(self, logged_in_client, db):
        name = "_tls_off"
        _drop(db, name)
        try:
            data = _email(name)
            data.pop("use_tls")
            logged_in_client.post(SAVE, data=data, follow_redirects=True)
            assert _config(db, name)["use_tls"] == "false"
            html = logged_in_client.get("/settings/alerts").data.decode()
            assert '"use_tls": "false"' in html, "the page carries the flag for the edit form to restore"
        finally:
            _drop(db, name)

    @pytest.mark.parametrize(
        "port", ["", "abc", "0", "65536", "²"]
    )  # a field is stripped before it is judged, as every form in Jen does: "25 " is 25
    def test_a_bad_port_is_refused(self, logged_in_client, db, port):
        name = "_bad_port"
        _drop(db, name)
        r = logged_in_client.post(SAVE, data=_email(name, smtp_port=port), follow_redirects=True)
        assert r.status_code == 200 and b"SMTP port must be a whole number from 1 to 65535" in r.data, port
        assert _row(db, name) is None


class TestARestrictedAdminSeesOnlyTheirChannels:
    """AL24 (and AL2's reach): the list, and the three acting routes."""

    def _wide(self, client, db, name):
        _drop(db, name)
        client.post(SAVE, data=_email(name, smtp_pass="wide-secret"), follow_redirects=True)
        row = _row(db, name)
        assert row is not None and row["subnet_scope"] is None
        return row["id"]

    def test_a_channel_for_every_subnet_is_not_listed_and_its_secret_never_served(self, client, logged_in_client, db):
        name = "_wide_channel"
        cid = self._wide(logged_in_client, db, name)
        try:
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_alerts_scoped")
            html = c.get("/settings/alerts").data.decode()
            assert (
                name not in html and "wide-secret" not in html and str(cid) not in html.split("JEN_CHANNELS")[-1][:200]
            )
        finally:
            _drop(db, name)

    def test_edit_delete_and_test_of_a_channel_outside_the_scope_are_one_message(self, client, logged_in_client, db):
        name = "_wide_channel_acts"
        cid = self._wide(logged_in_client, db, name)
        try:
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_alerts_scoped_acts")
            r = c.post(
                SAVE,
                data=_email(name, channel_id=str(cid), channel_name="renamed", smtp_pass="", subnet_ids=["1"]),
                follow_redirects=True,
            )
            assert b"Channel not found." in r.data and _row(db, name) is not None and _row(db, "renamed") is None
            r = c.post(f"/settings/alerts/delete-channel/{cid}", follow_redirects=True)
            assert b"Channel not found." in r.data and _row(db, name) is not None
            r = c.post(f"/settings/alerts/test-channel/{cid}", follow_redirects=True)
            assert (
                b"Channel not found." in r.data and b"Test message sent" not in r.data and b"Test failed" not in r.data
            )
        finally:
            _drop(db, name)

    def test_a_channel_inside_the_scope_is_listed_and_editable(self, client, db):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_alerts_scoped_own")
        name = "_own_channel"
        _drop(db, name)
        try:
            r = c.post(SAVE, data=_email(name, subnet_ids=["1"]), follow_redirects=True)
            assert r.status_code == 200 and json.loads(_row(db, name)["subnet_scope"]) == [1]
            assert name in c.get("/settings/alerts").data.decode()
            cid = _row(db, name)["id"]
            r = c.post(
                SAVE,
                data=_email(name, channel_id=str(cid), smtp_pass="", to_addr="x@example.test", subnet_ids=["1"]),
                follow_redirects=True,
            )
            assert (
                b"Channel not found." not in r.data and _config(db, name)["to_addr"] == "x@example.test"
            )  # the flash has the period; the page's own script carries "Channel not found'" without it
        finally:
            _drop(db, name)

    def test_the_unrestricted_branch_refuses_a_bad_id_whole(self, logged_in_client, db):  # AL13
        name = "_bad_scope"
        _drop(db, name)
        r = logged_in_client.post(SAVE, data=_email(name, subnet_ids=["1", "x"]), follow_redirects=True)
        assert b"Subnet ids must be numbers." in r.data and _row(db, name) is None
        try:
            logged_in_client.post(SAVE, data=_email(name, subnet_ids=["1", "1"]), follow_redirects=True)
            assert json.loads(_row(db, name)["subnet_scope"]) == [1]
        finally:
            _drop(db, name)


class TestTheSecurityPagePrintsWhatTheServerApplies:
    """AL5."""

    def test_a_stored_00_prints_as_0_and_a_stored_5000_as_1000(self, logged_in_client, db):
        _set_global(db, "rl_max_attempts", "5000")
        _set_global(db, "rl_lockout_minutes", "00")
        _set_global(db, "rl_mode", "everyone")
        try:
            html = logged_in_client.get("/settings/security").data.decode()
            assert 'name="max_attempts" value="1000"' in html and 'name="lockout_minutes" value="0"' in html
            assert "5000" not in html.split('name="max_attempts"')[1][:40]
        finally:
            _set_global(db, "rl_max_attempts", "10")
            _set_global(db, "rl_lockout_minutes", "15")
            _set_global(db, "rl_mode", "both")

    def test_the_system_page_prints_the_retention_the_prune_applies(self, logged_in_client, db):
        _set_global(db, "audit_retention_days", "99999")
        try:
            html = logged_in_client.get("/settings/system").data.decode()
            assert 'value="3650"' in html and 'value="99999"' not in html
        finally:
            _set_global(db, "audit_retention_days", "90")
