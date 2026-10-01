"""
tests/test_setup_wizard.py
────────────────────────────
v5.67.0 (Q115) — the /setup wizard. jen/services/setup_wizard.py's own
state-machine helpers (current_step, needs_entry_redirect,
test_kea_connection) are pure enough to unit-test with monkeypatched
settings/HTTP — no DB or Flask needed; the route tests below (access
control, the one-time redirect) need the real app and show as errors
without a DB, same as every other route test in this suite.
"""

from unittest.mock import MagicMock, patch

import pytest

from jen.services import setup_wizard

# ── current_step() / all_resolved() — pure given get_state() ────────────────


class TestCurrentStep:
    def test_nothing_resolved_starts_at_the_first_step(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", dict)
        assert setup_wizard.current_step() == setup_wizard.STEPS[0]

    def test_first_step_done_moves_to_the_second(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: {setup_wizard.STEPS[0]: "done"})
        assert setup_wizard.current_step() == setup_wizard.STEPS[1]

    def test_a_skipped_step_counts_as_resolved(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: {setup_wizard.STEPS[0]: "skipped"})
        assert setup_wizard.current_step() == setup_wizard.STEPS[1]

    def test_everything_resolved_stays_on_the_last_step(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: dict.fromkeys(setup_wizard.STEPS, "done"))
        assert setup_wizard.current_step() == setup_wizard.STEPS[-1]
        assert setup_wizard.all_resolved() is True

    def test_not_all_resolved_when_one_is_missing(self, monkeypatch):
        state = dict.fromkeys(setup_wizard.STEPS, "done")
        del state[setup_wizard.STEPS[0]]
        monkeypatch.setattr(setup_wizard, "get_state", lambda: state)
        assert setup_wizard.all_resolved() is False


class TestGetState:
    def test_unknown_keys_and_values_are_dropped(self, monkeypatch):
        monkeypatch.setattr(
            "jen.models.user.get_global_setting",
            lambda key, default="": '{"connect": "done", "not-a-step": "done", "found": "whatever"}',
        )
        assert setup_wizard.get_state() == {"connect": "done"}

    def test_absent_or_malformed_json_is_empty(self, monkeypatch):
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        assert setup_wizard.get_state() == {}
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "{not json")
        assert setup_wizard.get_state() == {}

    def test_set_step_rejects_an_unknown_step_or_status(self):
        with pytest.raises(ValueError):
            setup_wizard.set_step("not-a-real-step", "done")
        with pytest.raises(ValueError):
            setup_wizard.set_step(setup_wizard.STEPS[0], "maybe")


# ── entry / one-time redirect ────────────────────────────────────────────────


class TestEntryRedirect:
    def test_kea_connected_needs_both_url_and_subnets(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        assert setup_wizard.kea_connected() is False

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        assert setup_wizard.kea_connected() is False

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        assert setup_wizard.kea_connected() is True

    def test_needs_redirect_only_once_and_only_when_disconnected(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "kea_connected", lambda: False)
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        assert setup_wizard.needs_entry_redirect() is True

        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "true")
        assert setup_wizard.needs_entry_redirect() is False

        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        monkeypatch.setattr(setup_wizard, "kea_connected", lambda: True)
        assert setup_wizard.needs_entry_redirect() is False

    def test_mark_shown_writes_the_flag(self):
        with patch("jen.models.user.set_global_setting") as set_mock:
            setup_wizard.mark_entry_redirect_shown()
            set_mock.assert_called_once_with(setup_wizard._REDIRECT_SHOWN_KEY, "true")


# ── test_kea_connection() — mocked HTTP, no real socket ─────────────────────


def _kea_response(version_text="2.7.5"):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"result": 0, "arguments": {"extended": version_text}, "text": ""}
    return resp


class TestTestKeaConnection:
    def test_control_agent_style_url_answers_directly(self, monkeypatch):
        monkeypatch.setattr("requests.post", lambda *a, **k: _kea_response("2.7.5"))
        result = setup_wizard.test_kea_connection("http://kea:8000", "u", "p")
        assert result["ok"] is True
        assert result["mode"] == "ca"
        assert result["version"] == "2.7.5"
        assert len(result["attempts"]) == 1

    def test_falls_back_to_the_direct_socket_port(self, monkeypatch):
        calls = []

        def fake_post(url, **kw):
            calls.append(url)
            if url == "http://kea:8000":
                raise ConnectionError("refused")
            return _kea_response("3.1.0")

        monkeypatch.setattr("requests.post", fake_post)
        result = setup_wizard.test_kea_connection("http://kea:8000", "u", "p")
        assert result["ok"] is True
        assert result["mode"] == "direct"
        assert result["url"] == "http://kea:8004"
        assert calls == ["http://kea:8000", "http://kea:8004"]

    def test_dhcp6_falls_back_to_8006(self, monkeypatch):
        def fake_post(url, **kw):
            if url.endswith(":8000"):
                raise ConnectionError("refused")
            return _kea_response("2.7.5")

        monkeypatch.setattr("requests.post", fake_post)
        result = setup_wizard.test_kea_connection("http://kea:8000", "u", "p", service="dhcp6")
        assert result["ok"] is True
        assert result["url"] == "http://kea:8006"

    def test_nothing_answers_is_a_clean_failure(self, monkeypatch):
        monkeypatch.setattr("requests.post", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("refused")))
        result = setup_wizard.test_kea_connection("http://kea:8000", "u", "p")
        assert result["ok"] is False
        assert result["mode"] is None
        assert len(result["attempts"]) == 2  # ca attempt, then the direct fallback

    def test_a_kea_error_result_is_not_a_transport_failure(self, monkeypatch):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"result": 1, "text": "unauthorized"}
        monkeypatch.setattr("requests.post", lambda *a, **k: resp)
        result = setup_wizard.test_kea_connection("http://kea:8000", "u", "p")
        assert result["ok"] is False
        assert result["attempts"][0]["error"] == "unauthorized"


# ── discover() — service layer mocked, no real Kea ──────────────────────────


class TestDiscover:
    def test_shape_when_everything_answers(self, monkeypatch):
        caps = MagicMock(
            reachable=True,
            kea_version_text="2.7.5",
            host_cmds=True,
            lease_cmds=True,
            ha_commands=False,
            ddns=False,
        )
        monkeypatch.setattr("jen.services.capabilities.for_primary", lambda **kw: caps)
        monkeypatch.setattr(
            "jen.services.kea.kea_command",
            lambda *a, **kw: {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}},
        )
        monkeypatch.setattr("jen.services.kea_ha.ha_config", lambda cfg: None)
        monkeypatch.setattr(
            "jen.services.config_drift.fetch_live_subnet_map",
            lambda family="v4": {1: "10.0.0.0/24", 2: "10.0.1.0/24"},
        )
        monkeypatch.setattr(setup_wizard, "_ipv6_enabled", lambda: False)

        found = setup_wizard.discover()
        assert found["reachable"] is True
        assert found["kea_version"] == "2.7.5"
        assert found["hooks"] == {"host_cmds": True, "lease_cmds": True, "ha_commands": False, "ddns": False}
        assert found["ha"] is None
        assert found["ipv6_enabled"] is False
        assert found["proposed_subnets"] == {
            1: {"name": "Subnet1", "cidr": "10.0.0.0/24"},
            2: {"name": "Subnet2", "cidr": "10.0.1.0/24"},
        }

    def test_a_failed_config_get_does_not_raise(self, monkeypatch):
        caps = MagicMock(
            reachable=False, kea_version_text="", host_cmds=False, lease_cmds=False, ha_commands=False, ddns=False
        )
        monkeypatch.setattr("jen.services.capabilities.for_primary", lambda **kw: caps)
        monkeypatch.setattr(
            "jen.services.kea.kea_command", lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("down"))
        )
        monkeypatch.setattr("jen.services.config_drift.fetch_live_subnet_map", lambda family="v4": {})
        monkeypatch.setattr(setup_wizard, "_ipv6_enabled", lambda: False)

        found = setup_wizard.discover()
        assert found["reachable"] is False
        assert found["ha"] is None
        assert found["proposed_subnets"] == {}


# ── step 3: the Kea host helper — pure/mocked parts ─────────────────────────


class TestSshTarget:
    def test_ready_needs_both_host_and_user(self):
        assert setup_wizard.ssh_target_ready({"ssh_host": "", "ssh_user": ""}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "kea.lan", "ssh_user": ""}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "", "ssh_user": "jen"}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "kea.lan", "ssh_user": "jen"}) is True

    def test_save_rejects_an_invalid_host_or_user(self):
        ok, err = setup_wizard.save_ssh_target("-oProxyCommand=x", "jen")
        assert ok is False and err

        ok, err = setup_wizard.save_ssh_target("kea.lan", "not a valid user!")
        assert ok is False and err

    def test_save_writes_kea_ssh_section_on_success(self, monkeypatch):
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(items))
        ok, err = setup_wizard.save_ssh_target("kea.lan", "jen")
        assert ok is True and err == ""
        assert calls == [[("kea_ssh", "host", "kea.lan"), ("kea_ssh", "user", "jen")]]


class TestTestSsh:
    def test_ok_when_connect_succeeds(self, monkeypatch):
        ssh = MagicMock()
        monkeypatch.setattr("jen.services.kea6._connect_ssh", lambda server: ssh)
        result = setup_wizard.test_ssh({"ssh_host": "kea.lan"})
        assert result == {"ok": True, "detail": ""}
        ssh.close.assert_called_once()

    def test_failure_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea6._connect_ssh", lambda server: (_ for _ in ()).throw(OSError("refused")))
        result = setup_wizard.test_ssh({"ssh_host": "kea.lan"})
        assert result["ok"] is False
        assert "refused" in result["detail"]


class TestHelperWrappers:
    def test_helper_status_passes_through_check_helper(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.check_helper", lambda server: {"ok": True, "version": 6})
        assert setup_wizard.helper_status({"id": 1}) == {"ok": True, "version": 6}

    def test_install_helper_step_passes_through_install_helper(self, monkeypatch):
        sentinel = {"ok": False, "version": None, "code": "sudoerror", "detail": "no dice"}
        monkeypatch.setattr("jen.services.kea_host.install_helper", lambda server: sentinel)
        assert setup_wizard.install_helper_step({"id": 1}) is sentinel

    def test_helper_download_command_passes_through(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host._helper_download_command", lambda: "curl ... | sudo bash")
        assert setup_wizard.helper_download_command() == "curl ... | sudo bash"


# ── step 4: baseline — mocked ────────────────────────────────────────────────


class TestCaptureBaseline:
    def test_unreadable_config_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.read_config", lambda server, service: None)
        result = setup_wizard.capture_baseline({"id": 1}, "dhcp4")
        assert result == {"ok": False, "revision": None}

    def test_a_readable_config_returns_the_latest_revision(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.read_config", lambda server, service: {"Dhcp4": {}})
        monkeypatch.setattr(
            "jen.services.config_revisions.latest", lambda server_id, service: {"id": 1, "source": "baseline"}
        )
        result = setup_wizard.capture_baseline({"id": 1}, "dhcp4")
        assert result == {"ok": True, "revision": {"id": 1, "source": "baseline"}}


# ── the wizard's own clock ───────────────────────────────────────────────────


class TestWizardClock:
    def test_mark_started_only_writes_once(self, monkeypatch):
        store = {}
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": store.get(key, default))
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: store.__setitem__(key, value))
        setup_wizard.mark_started()
        first = store[setup_wizard._STARTED_KEY]
        setup_wizard.mark_started()
        assert store[setup_wizard._STARTED_KEY] == first

    def test_elapsed_seconds_is_none_before_started(self, monkeypatch):
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        assert setup_wizard.elapsed_seconds() is None

    def test_get_state_never_starts_the_clock(self, monkeypatch):
        """get_state() is called by onboarding.checklist() on every page
        load — it must never have the side effect mark_started() has."""
        calls = []
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: calls.append((key, value)))
        setup_wizard.get_state()
        assert calls == []


# ── routes — access control ─────────────────────────────────────────────────


class TestSetupAccessControl:
    def test_superadmin_sees_the_connect_step(self, logged_in_client):
        r = logged_in_client.get("/setup/connect")
        assert r.status_code == 200
        assert b"Kea API URL" in r.data

    def test_admin_is_turned_away(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin")
        r = c.get("/setup/connect")
        assert r.status_code != 200
        assert b"Kea API URL" not in r.data

    def test_viewer_is_turned_away(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get("/setup/connect")
        assert r.status_code != 200
        assert b"Kea API URL" not in r.data

    def test_setup_home_redirects_to_the_current_step(self, logged_in_client):
        r = logged_in_client.get("/setup/")
        assert r.status_code == 302
        assert "/setup/connect" in r.headers["Location"]

    @pytest.mark.parametrize(
        "path,marker",
        [
            ("/setup/helper", b"Kea host helper"),
            ("/setup/baseline", b"Capture a baseline"),
            ("/setup/recovery", b"recovery point"),
            ("/setup/investigate", b"Investigate a client"),
        ],
    )
    def test_superadmin_sees_each_remaining_step(self, logged_in_client, path, marker):
        r = logged_in_client.get(path)
        assert r.status_code == 200
        assert marker.lower() in r.data.lower()

    @pytest.mark.parametrize("path", ["/setup/helper", "/setup/baseline", "/setup/recovery", "/setup/investigate"])
    def test_admin_is_turned_away_from_every_remaining_step(self, client, db, path):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin")
        r = c.get(path)
        assert r.status_code != 200

    @pytest.mark.parametrize("path", ["/setup/helper", "/setup/baseline", "/setup/recovery", "/setup/investigate"])
    def test_viewer_is_turned_away_from_every_remaining_step(self, client, db, path):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get(path)
        assert r.status_code != 200


# ── the one-time entry redirect ─────────────────────────────────────────────


class TestEntryRedirectThroughForcedPasswordChange:
    def _force_must_change(self, db):
        with db.cursor() as cur:
            cur.execute("UPDATE users SET must_change_password=1 WHERE username='admin'")
        db.commit()

    def _superadmin_session(self, client):
        with client.session_transaction() as sess:
            sess["_user_cache"] = {"id": 1, "username": "admin", "role": "superadmin", "session_timeout": None}
            sess["_user_id"] = "1"
            sess["_fresh"] = True

    def test_superadmin_lands_on_setup_when_kea_is_unset(self, client, db, monkeypatch):
        from jen import extensions
        from jen.services import setup_wizard as sw

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        monkeypatch.setattr(sw, "mark_entry_redirect_shown", lambda: None)
        self._force_must_change(db)
        self._superadmin_session(client)
        r = client.post(
            "/force-password-change",
            data={"new_password": "a-real-password-1", "confirm_password": "a-real-password-1"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "/setup" in r.headers["Location"]

    def test_the_redirect_fires_only_once(self, client, db, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "true")
        self._force_must_change(db)
        self._superadmin_session(client)
        r = client.post(
            "/force-password-change",
            data={"new_password": "a-real-password-2", "confirm_password": "a-real-password-2"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "/setup" not in r.headers["Location"]
