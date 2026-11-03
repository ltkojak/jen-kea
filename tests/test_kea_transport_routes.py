"""
tests/test_kea_transport_routes.py
──────────────────────────────────
Q212 (BB10) - the five routes of the per-server card (the probe, the switch, the helper's grant and its inverse, "I have fixed it") against the five principals: an anonymous caller, a viewer, an admin
scoped to a subnet, an admin with no scope and a superadmin. Only the superadmin reaches the work; the four that change something also ask for a recent confirmation of the password. The work is
stubbed (nothing here talks to a daemon or a host) - the walk asks WHO gets there, `tests/test_transport_switch.py` and `tests/test_kea_api_probe.py` ask what happens when they do.
"""

from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from tests.conftest import restricted_client

SERVER = {"id": 3, "name": "kea-c", "api_url": "http://127.0.0.1:9/", "ssh_host": "10.0.0.3", "config_transport": "off"}

ROUTES = [
    ("/settings/infrastructure/probe-kea-config/3", False),
    ("/settings/infrastructure/kea-transport/3", True),
    ("/settings/infrastructure/allow-config-write/3", True),
    ("/settings/infrastructure/deny-config-write/3", True),
    ("/settings/infrastructure/config-write-fixed/3", True),
]


@pytest.fixture
def worked(monkeypatch):
    """Every piece of work the five routes can reach, replaced by a recorder: a request that gets through the gates is visible, one that does not leaves it empty."""
    calls = []
    monkeypatch.setattr(extensions, "KEA_SERVERS", [SERVER])
    monkeypatch.setattr(
        "jen.services.kea_api_config.probe", lambda *a, **k: calls.append("probe") or {"config_api": True}
    )
    monkeypatch.setattr(
        "jen.services.kea_transport_switch.switch",
        lambda *a, **k: (
            calls.append("switch") or {"ok": True, "level": "success", "line": "switched", "from": "off", "to": "api"}
        ),
    )
    for name in ("allow_config_write", "deny_config_write"):
        monkeypatch.setattr(
            f"jen.services.kea_host.{name}",
            lambda *a, _n=name, **k: calls.append(_n) or {"ok": True, "changed": False, "detail": "x"},
        )
    monkeypatch.setattr("jen.services.kea_api_config.stored_probe", lambda sid: {"refused": "denied"})
    monkeypatch.setattr("jen.services.kea_api_config.clear_refusal", lambda sid: calls.append("fixed") or True)
    monkeypatch.setattr("jen.services.capabilities.invalidate", lambda *a, **k: None)
    return calls


def _post(client, url):
    return client.post(url, data={"transport": "api", "consent": "1"}, follow_redirects=False)


class TestOnlyASuperadminGetsThere:
    @pytest.mark.parametrize(("url", "_step_up"), ROUTES)
    def test_an_anonymous_caller_is_sent_to_sign_in(self, client, worked, url, _step_up):
        r = _post(client, url)
        assert r.status_code in (301, 302, 401) and worked == []
        if r.status_code in (301, 302):
            assert "login" in r.headers["Location"]

    @pytest.mark.parametrize(("url", "_step_up"), ROUTES)
    @pytest.mark.parametrize("role", ["viewer", "admin"])
    def test_a_viewer_and_an_admin_are_refused(self, client, db, worked, url, _step_up, role):
        restricted_client(client, db, None, role=role, username=f"{role}-q212")
        r = _post(client, url)
        assert r.status_code in (302, 403) and worked == []

    @pytest.mark.parametrize(("url", "_step_up"), ROUTES)
    def test_an_admin_scoped_to_a_subnet_is_refused(self, client, db, worked, url, _step_up):
        restricted_client(client, db, [1], role="admin", username="scoped-q212")
        r = _post(client, url)
        assert r.status_code in (302, 403) and worked == []

    @pytest.mark.parametrize(("url", "_step_up"), ROUTES)
    def test_a_superadmin_gets_to_the_work(self, logged_in_client, worked, url, _step_up):
        r = _post(logged_in_client, url)
        assert r.status_code in (200, 302) and worked, (url, r.status_code)


class TestTheFourThatChangeSomethingAskForARecentConfirmation:
    @pytest.mark.parametrize(("url", "needs"), ROUTES)
    def test_a_stale_confirmation_stops_it_before_any_work(self, logged_in_client, worked, url, needs):
        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        r = _post(logged_in_client, url)
        if needs:
            assert r.status_code == 302 and "reauth" in r.headers["Location"] and worked == []
        else:
            assert worked == ["probe"]  # the probe only reads: it asks for no confirmation

    def test_an_unknown_server_is_a_message_not_an_error(self, logged_in_client, worked):
        r = _post(logged_in_client, "/settings/infrastructure/kea-transport/99")
        assert r.status_code == 302 and worked == []
