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


class TestTheIpv6StepSendsOnlyTheCredentialResolveWouldGive:
    """Q180, U4: the Found step's IPv6 check probes the address it is given - with the primary's password only on the primary's host, else a typed one, else NOTHING is sent."""

    @pytest.fixture
    def probe(self, monkeypatch):
        from jen import extensions
        from jen.services import capabilities, setup_wizard

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea-a:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "jen")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "PRIMARY")
        monkeypatch.setattr(capabilities, "is_direct", lambda: True)
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        calls = []

        def fake(url, user, password, *, omit_service):
            calls.append((url, user, password, omit_service))
            return {
                "ok": False,
                "error": "stub",
                "version": "",
                "subnet6_count": 0,
                "orphaned_subnets6": {},
                "proposed_subnets6": {},
            }

        monkeypatch.setattr(setup_wizard, "probe_v6", fake)
        return calls

    def _post(self, client, **data):
        return client.post("/setup/found", data={"action": "check_v6", **data})

    def test_a_stale_session_is_sent_to_confirm_and_no_request_is_made(self, logged_in_client, db, mock_kea, probe):
        _stale(logged_in_client)
        r = self._post(logged_in_client, v6_url="http://kea-a:8006")
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert probe == []

    def test_a_candidate_on_the_primarys_host_is_probed_with_the_primarys_password(
        self, logged_in_client, db, mock_kea, probe
    ):
        self._post(logged_in_client, v6_url="http://kea-a:8006")
        assert probe == [("http://kea-a:8006", "jen", "PRIMARY", True)]

    def test_a_candidate_elsewhere_without_a_password_is_refused_before_any_request(
        self, logged_in_client, db, mock_kea, probe
    ):
        r = self._post(logged_in_client, v6_url="http://elsewhere:8006")
        assert probe == []
        assert b"different host from the Kea API" in r.data and b'name="v6_pass"' in r.data

    def test_a_candidate_elsewhere_with_its_own_password_is_probed_with_that_password_only(
        self, logged_in_client, db, mock_kea, probe
    ):
        self._post(logged_in_client, v6_url="http://elsewhere:8006", v6_pass="OWN")
        # (Q181: the USER follows the password's rule - the primary's only on the same host; this socket is on another one, so none unless one is typed)
        assert probe == [
            ("http://elsewhere:8006", "jen", "OWN", True)
        ]  # (the user rides alongside a password typed for this socket - `resolve`'s rule)


class TestTheIpv6StepCanSayNoAuthentication:
    """Q181, V4: "This DHCPv6 control socket has no authentication" - an explicit blank, probed with no auth and saved as `[kea6] api_pass =`; never the primary's password."""

    @pytest.fixture
    def probe(self, monkeypatch):
        from jen import extensions
        from jen.services import capabilities, setup_wizard

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea-a:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "jen")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "PRIMARY")
        monkeypatch.setattr(capabilities, "is_direct", lambda: True)
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        calls, enabled = [], []

        def fake(url, user, password, *, omit_service):
            calls.append((url, user, password))
            return {
                "ok": True,
                "error": "",
                "version": "3.0.0",
                "subnet6_count": 0,
                "orphaned_subnets6": {},
                "proposed_subnets6": {},
            }

        monkeypatch.setattr(setup_wizard, "probe_v6", fake)
        monkeypatch.setattr(setup_wizard, "enable_v6", lambda *a, **k: enabled.append(k) or None)
        return calls, enabled

    def test_a_socket_elsewhere_with_the_box_is_probed_with_no_auth_and_saved_blank(
        self, logged_in_client, db, mock_kea, probe
    ):
        calls, enabled = probe
        logged_in_client.post(
            "/setup/found", data={"action": "check_v6", "v6_url": "http://elsewhere:8006", "v6_no_auth": "1"}
        )
        logged_in_client.post(
            "/setup/found", data={"action": "enable_v6", "v6_url": "http://elsewhere:8006", "v6_no_auth": "1"}
        )
        assert calls == [("http://elsewhere:8006", "", ""), ("http://elsewhere:8006", "", "")]
        assert enabled and enabled[0]["no_auth"] is True and enabled[0]["api_pass"] == ""

    def test_without_the_box_and_without_a_password_nothing_is_sent(self, logged_in_client, db, mock_kea, probe):
        calls, _enabled = probe
        r = logged_in_client.post("/setup/found", data={"action": "check_v6", "v6_url": "http://elsewhere:8006"})
        assert calls == [] and b"different host from the Kea API" in r.data

    def test_the_box_and_a_typed_password_are_two_answers(self, logged_in_client, db, mock_kea, probe):
        calls, _enabled = probe
        r = logged_in_client.post(
            "/setup/found",
            data={"action": "check_v6", "v6_url": "http://elsewhere:8006", "v6_no_auth": "1", "v6_pass": "x"},
        )
        assert calls == [] and b"Choose one for the DHCPv6 API password" in r.data

    def test_a_typed_user_for_a_socket_elsewhere_is_what_is_probed_and_saved(
        self, logged_in_client, db, mock_kea, probe
    ):
        calls, enabled = probe
        logged_in_client.post(
            "/setup/found",
            data={"action": "enable_v6", "v6_url": "http://elsewhere:8006", "v6_pass": "OWN", "v6_user": "v6user"},
        )
        assert calls == [("http://elsewhere:8006", "v6user", "OWN")] and enabled[0]["api_user"] == "v6user"
