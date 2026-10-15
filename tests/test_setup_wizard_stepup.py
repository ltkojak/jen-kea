"""
tests/test_setup_wizard_stepup.py
─────────────────────────────────
v5.69.0-beta.10 (Q179, RBAC-004) - the setup wizard's POST steps that write where Jen reaches Kea (the connection, the SSH target) ask for a password confirmed within ten minutes
BEFORE they probe or write, and send the person to the confirmation page; without that the config writer's guard refused with a sentence the next submit would meet again. The GET
steps need no confirmation.
"""

from datetime import datetime, timedelta, timezone

import pytest

CONNECT = {
    "api_url": "http://kea.example:8000",
    "api_user": "u",
    "api_pass": "p",
    "kea_db_host": "db.example",
    "kea_db_user": "k",
    "kea_db_pass": "p",
    "kea_db_name": "kea",
}


def _stale(client, minutes=30):
    with client.session_transaction() as sess:
        sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


class TestTheWizardAsksForTheConfirmationItNeeds:
    def test_the_connection_step_sends_a_stale_session_to_confirm_and_does_nothing_first(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        from jen.services import setup_wizard

        probed = []
        monkeypatch.setattr(setup_wizard, "save_connection", lambda **k: probed.append(k) or (True, ""))
        _stale(logged_in_client)
        r = logged_in_client.post("/setup/connect", data=CONNECT)
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert probed == []

    def test_the_ssh_target_step_does_the_same(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import setup_wizard

        saved = []
        monkeypatch.setattr(setup_wizard, "save_ssh_target", lambda host, user: saved.append(host) or (True, ""))
        _stale(logged_in_client)
        r = logged_in_client.post(
            "/setup/helper", data={"action": "save_target", "ssh_host": "10.0.0.9", "ssh_user": "jen"}
        )
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert saved == []

    def test_a_fresh_session_goes_on_to_save_the_target(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import setup_wizard

        saved = []
        monkeypatch.setattr(setup_wizard, "save_ssh_target", lambda host, user: saved.append(host) or (True, ""))
        r = logged_in_client.post(
            "/setup/helper", data={"action": "save_target", "ssh_host": "10.0.0.9", "ssh_user": "jen"}
        )
        assert r.status_code == 302 and "/auth/reauth" not in r.headers["Location"]
        assert saved == ["10.0.0.9"]

    @pytest.mark.parametrize("path", ["/setup/connect", "/setup/helper"])
    def test_the_steps_that_only_show_a_page_need_no_confirmation(self, logged_in_client, db, mock_kea, path):
        _stale(logged_in_client)
        r = logged_in_client.get(path)
        assert r.status_code == 200
