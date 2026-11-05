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
    ("/settings/infrastructure/settle-pending-change/3", True),
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
    monkeypatch.setattr("jen.services.kea_api_config.stored_probe", lambda sid: {"refused": "denied", "at": "T"})
    monkeypatch.setattr("jen.services.kea_api_config.clear_refusal", lambda sid: calls.append("fixed") or True)
    monkeypatch.setattr(
        "jen.services.kea_api_config.settle_pending",
        lambda *a, **k: calls.append("settle") or (["a change was finished now"], True),
    )
    monkeypatch.setattr("jen.services.capabilities.invalidate", lambda *a, **k: None)
    return calls


def _post(client, url):
    return client.post(url, data={"transport": "api", "probe_at": "T"}, follow_redirects=False)


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
            assert (
                worked == ["probe"]
            )  # the readiness check only READS: it asks for no confirmation (the consent is the switch, TestAConsentIsAnActNotAClick)

    def test_an_unknown_server_is_a_message_not_an_error(self, logged_in_client, worked):
        r = _post(logged_in_client, "/settings/infrastructure/kea-transport/99")
        assert r.status_code == 302 and worked == []


class TestAConsentIsAnActNotAClick:
    """Q217 BG2 / CFG-003 (Q216 AA1 moved here). The consent is the SWITCH POST: given for the facts the operator READ (the form carries the stored probe's `at` as `probe_at`), by a superadmin who
    confirmed the password recently, for the consents named by the boxes ticked. The readiness check reads and records nothing."""

    def test_the_readiness_check_records_no_consent(self, logged_in_client, worked, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            "jen.services.kea_api_config.probe",
            lambda server, service="dhcp4", **k: seen.update(k) or {"config_api": True},
        )
        logged_in_client.post(
            "/settings/infrastructure/probe-kea-config/3", data={"consent": "1", "consent_rendering": "1"}
        )
        assert seen == {}  # no consent, no consents: the route does not even read them

    def test_a_stale_confirmation_stops_the_switch_before_any_work(self, logged_in_client, worked):
        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        r = _post(logged_in_client, "/settings/infrastructure/kea-transport/3")
        assert r.status_code == 302 and "reauth" in r.headers["Location"] and worked == []

    def test_a_switch_for_facts_that_are_not_the_stored_ones_is_refused(self, logged_in_client, worked):
        r = logged_in_client.post(
            "/settings/infrastructure/kea-transport/3",
            data={"transport": "api", "probe_at": "OLD", "consent_rendering": "1"},
            follow_redirects=True,
        )
        assert worked == [] and b"readiness check was refreshed" in r.data

    def test_a_switch_with_no_facts_at_all_is_refused(self, logged_in_client, worked):
        r = logged_in_client.post(
            "/settings/infrastructure/kea-transport/3", data={"transport": "api", "consent_rendering": "1"}
        )
        assert worked == [] and r.status_code == 302

    def test_the_consents_recorded_are_the_boxes_ticked(self, logged_in_client, worked, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            "jen.services.kea_transport_switch.switch",
            lambda server, target, consents=(), actor="": (
                seen.update(target=target, consents=set(consents))
                or {
                    "ok": True,
                    "level": "success",
                    "line": "switched",
                    "from": "file",
                    "to": "api",
                    "consents": sorted(consents),
                }
            ),
        )
        logged_in_client.post(
            "/settings/infrastructure/kea-transport/3",
            data={"transport": "api", "probe_at": "T", "consent_rendering": "1", "bogus": "1"},
        )
        assert seen == {"target": "api", "consents": {"consent_rendering"}}

    def test_a_switch_to_the_file_or_to_read_only_needs_no_facts(self, logged_in_client, worked):
        logged_in_client.post("/settings/infrastructure/kea-transport/3", data={"transport": "off"})
        assert worked == ["switch"]

    @pytest.mark.parametrize("target", ["file", "off", "api"])
    def test_probe_at_is_checked_for_every_act_that_carries_a_consent(self, logged_in_client, worked, target):
        """Q218 BH3 c (AC18): a consent is given for the facts whose time the form carries, whatever the target - `discard_file_edit` on a switch to File over SSH was bound to no facts' time."""
        r = logged_in_client.post(
            "/settings/infrastructure/kea-transport/3",
            data={"transport": target, "probe_at": "OLD", "discard_file_edit": "1"},
            follow_redirects=True,
        )
        assert worked == [] and b"readiness check was refreshed" in r.data
        logged_in_client.post(
            "/settings/infrastructure/kea-transport/3",
            data={"transport": target, "probe_at": "T", "discard_file_edit": "1"},
        )
        assert worked == ["switch"], "the same act with the facts' own time goes through"

    def test_the_audit_row_prints_the_recorded_consents(self, logged_in_client, worked, monkeypatch):
        """Q218 BH3 e (AC13): the row names what was RECORDED (and what was ignored), never the set the form submitted."""
        rows = []
        monkeypatch.setattr("jen.models.user.audit", lambda action, entity, details="": rows.append((action, details)))
        monkeypatch.setattr(
            "jen.services.kea_transport_switch.switch",
            lambda server, target, consents=(), actor="": {
                "ok": True,
                "level": "success",
                "line": "switched",
                "from": "off",
                "to": "api",
                "consents": ["consent_rendering"],
                "ignored": ["discard_file_edit"],
            },
        )
        logged_in_client.post(
            "/settings/infrastructure/kea-transport/3",
            data={"transport": "api", "probe_at": "T", "consent_rendering": "1", "discard_file_edit": "1"},
        )
        details = [d for a, d in rows if a == "KEA_TRANSPORT_SWITCHED"]
        assert details and "consents: consent_rendering" in details[0] and "ignored: discard_file_edit" in details[0]
        assert "consents: consent_rendering, discard_file_edit" not in details[0]


class TestIHaveFixedItIsForAServerNothingCanProve:
    def test_a_server_whose_host_can_prove_it_is_sent_to_the_check(self, logged_in_client, worked, monkeypatch):
        monkeypatch.setattr(
            "jen.services.kea_api_config.stored_probe", lambda sid: {"refused": "denied", "write": {"may_write": False}}
        )
        r = logged_in_client.post("/settings/infrastructure/config-write-fixed/3", follow_redirects=False)
        assert r.status_code == 302 and "fixed" not in worked


class TestTheSettleRouteWorksUnderTheLockAndIsAudited:
    def test_it_settles_and_says_what_was_done(self, logged_in_client, worked):
        r = logged_in_client.post("/settings/infrastructure/settle-pending-change/3", follow_redirects=True)
        assert r.status_code == 200 and worked == ["settle"] and b"finished now" in r.data

    def test_a_young_change_flashes_warning(self, logged_in_client, worked, monkeypatch):
        monkeypatch.setattr(
            "jen.services.kea_api_config.settle_pending",
            lambda *a, **k: (["a change of T is in progress; it is not settled until it has had 120 s"], False),
        )
        r = logged_in_client.post("/settings/infrastructure/settle-pending-change/3", follow_redirects=True)
        assert r.status_code == 200 and b"in progress" in r.data and b"alert-warning" in r.data
