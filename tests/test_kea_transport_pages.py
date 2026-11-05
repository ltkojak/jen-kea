"""
tests/test_kea_transport_pages.py
─────────────────────────────────
Q212 (BB5, BB7) - what an operator sees and does with the per-server transport: the Servers page's badge ("one word for one state"), the Settings → Kea card, a config-history restore over the daemon's own
API (the live digest of THIS request, no restart, a pre-socket revision refused with the file-path sentence, `off` flashed) and the history page's labels for the new revision sources.
DB-backed (the page and the audit); the daemon is a stub.
"""

import json

import pytest

from jen import extensions
from jen.services import config_revisions as rev
from jen.services import kea as kea_svc
from jen.services import kea_api_config as api
from jen.services import kea_host

SERVER_API = {
    "id": 1,
    "name": "Test Kea",
    "api_url": "http://localhost:18000",
    "config_transport": "api",
    "role": "primary",
}
SERVER_FILE = {
    "id": 2,
    "name": "File Kea",
    "api_url": "http://localhost:18001",
    "ssh_host": "10.0.0.2",
    "role": "standby",
}
SERVER_LEGACY = {"id": 3, "name": "Legacy Kea", "api_url": "http://localhost:18002", "role": "standby"}


@pytest.fixture
def three(monkeypatch):
    monkeypatch.setattr(extensions, "KEA_SERVERS", [SERVER_API, SERVER_FILE, SERVER_LEGACY])
    monkeypatch.setattr(
        kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "mocked", "arguments": {"Dhcp4": {}}}
    )
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(
        kea_svc,
        "get_all_server_status",
        lambda: [
            {"server": s, "up": True, "ha_state": None, "version": "3.0.5", "role": s["role"]}
            for s in extensions.KEA_SERVERS
        ],
    )
    monkeypatch.setattr(
        api, "stored_probe", lambda sid: {"auth": "none", "at": "2026-11-03T12:00:00+00:00"} if sid == 1 else None
    )
    return [SERVER_API, SERVER_FILE, SERVER_LEGACY]


def _only(monkeypatch, server):
    """One server on the page: a multi-server page also asks for HA status and the compare table, which this test is not about."""
    monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
    monkeypatch.setattr(
        kea_svc,
        "get_all_server_status",
        lambda: [{"server": server, "up": True, "ha_state": None, "version": "3.0.5", "role": server["role"]}],
    )


class TestTheServersPageBadge:
    @pytest.mark.parametrize(("server", "word"), [(SERVER_API, "api"), (SERVER_FILE, "file"), (SERVER_LEGACY, "off")])
    def test_one_word_per_server(self, logged_in_client, three, monkeypatch, server, word):
        _only(monkeypatch, server)
        html = logged_in_client.get("/servers").data.decode()
        assert f'data-transport="{word}"' in html

    def test_an_api_server_with_no_authentication_says_so(self, logged_in_client, three, monkeypatch):
        _only(monkeypatch, SERVER_API)
        html = logged_in_client.get("/servers").data.decode()
        assert "Live API, unauthenticated" in html

    def test_a_remembered_refusal_is_named_on_the_server(self, logged_in_client, three, monkeypatch):
        _only(monkeypatch, SERVER_API)
        monkeypatch.setattr(
            api, "refusal_sentence", lambda server: "the daemon on Test Kea may not write its file (denied)"
        )
        html = logged_in_client.get("/servers").data.decode()
        assert "data-transport-refused" in html and "may not write its file" in html


class TestTheSettingsCard:
    def test_the_card_lists_every_server_with_its_word_and_a_superadmin_gets_the_controls(
        self, logged_in_client, three
    ):
        html = logged_in_client.get("/settings/kea").data.decode()
        assert 'id="kea-config-transport"' in html
        for name in ("Test Kea", "File Kea", "Legacy Kea"):
            assert name in html
        assert "/settings/infrastructure/kea-transport/1" in html and "data-wm-check" in html


class TestTheCardOffersOnlyWhatTheFactsAllow:
    """Q216 AA1 (the consent boxes exist only with the facts on the page), AA9 ("I have fixed it" is for a server nothing can prove), AA13 (the badge says blocked where the gate does)."""

    def _stored(self, monkeypatch, value):
        monkeypatch.setattr(api, "stored_probe", lambda sid: value if sid == 1 else None)

    def test_no_stored_probe_no_consent_control_and_a_blocked_badge(self, logged_in_client, three, monkeypatch):
        self._stored(monkeypatch, None)
        html = logged_in_client.get("/settings/kea").data.decode()
        card = html.split('id="config-card-1"')[1].split('id="config-card-2"')[0]
        assert "data-wm-consent=" not in card and ", blocked" in card and "Current: Live API" in card

    def test_a_stored_probe_brings_the_consent_control_with_its_timestamp_and_the_named_consents(
        self, logged_in_client, three, monkeypatch
    ):
        self._stored(monkeypatch, {"at": "2026-11-04T10:00:00+00:00", "config_api": True, "auth": "none"})
        html = logged_in_client.get("/settings/kea").data.decode()
        card = html.split('id="config-card-1"')[1].split('id="config-card-2"')[0]
        assert 'name="probe_at" value="2026-11-04T10:00:00+00:00"' in card
        assert 'name="consent_rendering"' in card and 'name="consent_unauthenticated"' in card
        assert 'name="confirm_no_include"' in card  # server 1 has no SSH host

    def test_i_have_fixed_it_is_not_offered_where_the_host_can_prove_it(self, logged_in_client, three, monkeypatch):
        monkeypatch.setattr(
            api,
            "stored_probe",
            lambda sid: {"refused": "denied", "write": {"may_write": False}} if sid == 2 else None,
        )
        monkeypatch.setattr(api, "refusal_sentence", lambda server: "denied" if server["id"] == 2 else "")
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"2": {"build": 20}})
        html = logged_in_client.get("/settings/kea").data.decode()
        assert "/settings/infrastructure/config-write-fixed/2" not in html

    def test_i_have_fixed_it_is_offered_for_an_ssh_server_whose_helper_is_too_old(
        self, logged_in_client, three, monkeypatch
    ):
        monkeypatch.setattr(api, "stored_probe", lambda sid: {"refused": "denied"} if sid == 2 else None)
        monkeypatch.setattr(api, "refusal_sentence", lambda server: "denied" if server["id"] == 2 else "")
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"2": {"build": 18}})
        html = logged_in_client.get("/settings/kea").data.decode()
        assert "/settings/infrastructure/config-write-fixed/2" in html


class TestTheGateSentencesAreAnAdminsToRead:
    """Second pass, row 1: the gate's sentences name host paths, the daemon's account and a file mode; a viewer sees a neutral phrase."""

    def _stored(self, monkeypatch):
        monkeypatch.setattr(
            api,
            "stored_probe",
            lambda sid: (
                {
                    "at": "2026-11-04T10:00:00+00:00",
                    "config_api": True,
                    "consented_at": "2026-11-04T10:00:00+00:00",
                    "include": ["/etc/kea/secret-site-extra.json"],
                    "agree": True,
                    "write": {"may_write": True},
                }
                if sid == 1
                else None
            ),
        )
        monkeypatch.setattr(api, "_age_days", lambda iso: 0.1)

    def test_an_admin_reads_the_sentence(self, logged_in_client, three, monkeypatch):
        self._stored(monkeypatch)
        _only(monkeypatch, SERVER_API)
        html = logged_in_client.get("/servers").data.decode()
        assert "secret-site-extra.json" in html

    def test_a_viewer_reads_a_neutral_phrase(self, client, db, three, monkeypatch):
        from tests.conftest import restricted_client

        self._stored(monkeypatch)
        restricted_client(client, db, None, role="viewer", username="viewer-q216")
        _only(monkeypatch, SERVER_API)
        html = client.get("/servers").data.decode()
        assert "secret-site-extra.json" not in html and "Live API is not ready yet" in html


class TestAViewerIsNotToldAnEndpointHasNoAuthentication:
    """Q217 BG4 a (Opus's AB5): `transport_unauthenticated` is gated like the two lines around it - the badge a viewer reads is the mode word alone."""

    def _stored(self, monkeypatch):
        monkeypatch.setattr(
            api,
            "stored_probe",
            lambda sid: (
                {
                    "at": "2026-11-04T10:00:00+00:00",
                    "config_api": True,
                    "consented_at": "2026-11-04T10:00:00+00:00",
                    "auth": "none",
                }
                if sid == 1
                else None
            ),
        )

    def test_the_admin_and_the_superadmin_read_it(self, logged_in_client, three, monkeypatch):
        self._stored(monkeypatch)
        _only(monkeypatch, SERVER_API)
        assert "unauthenticated" in logged_in_client.get("/servers").data.decode()

    def test_a_viewer_never_reads_unauthenticated(self, client, db, three, monkeypatch):
        from tests.conftest import restricted_client

        self._stored(monkeypatch)
        _only(monkeypatch, SERVER_API)
        restricted_client(client, db, None, role="viewer", username="viewer-q217")
        html = client.get("/servers").data.decode()
        assert "unauthenticated" not in html and "Live API" in html


class TestARestoreOverTheApi:
    CFG = {"Dhcp4": {"valid-lifetime": 1234, "subnet4": []}}

    @pytest.fixture
    def revision(self, db, three, monkeypatch):
        rid = rev.record(1, "dhcp4", self.CFG, "h" * 64, "an earlier configuration", hash_kind="kea", source="jen")
        assert rid
        return rid

    def _wire(self, monkeypatch, apply_result=None, live=("live-digest-1", {"Dhcp4": {"valid-lifetime": 3600}})):
        calls = {}
        monkeypatch.setattr(api, "read", lambda server, service, **kw: (live[1], live[0]))
        monkeypatch.setattr(api, "test", lambda server, service, cfg: {"ok": True, "code": "ok", "via": "api"})

        def apply(server, service, cfg, expect_hash, summary, source="jen", **kw):
            calls.update(expect=expect_hash, summary=summary, source=source, cfg=cfg)
            return apply_result or {"ok": True, "code": "ok", "via": "api", "sha256": "new-digest-1234567890"}

        monkeypatch.setattr(api, "apply", apply)
        return calls

    def test_the_live_digest_of_this_request_guards_it_and_nothing_restarts(
        self, logged_in_client, revision, monkeypatch
    ):
        calls = self._wire(monkeypatch)
        restarted = []
        monkeypatch.setattr("jen.services.kea_host.service_action", lambda *a, **k: restarted.append(a) or {"ok": True})
        r = logged_in_client.post(f"/servers/1/config-history/{revision}/restore", follow_redirects=True)
        assert r.status_code == 200 and b"over the API" in r.data and b"no restart" in r.data
        assert calls["expect"] == "live-digest-1" and calls["source"] == "restore" and calls["cfg"] == self.CFG
        assert restarted == []

    def test_a_pre_socket_revision_is_refused_with_the_file_path_sentence(
        self, logged_in_client, revision, monkeypatch
    ):
        self._wire(monkeypatch, apply_result={"ok": False, "code": "guard", "via": "api", "detail": api.GUARD_SENTENCE})
        r = logged_in_client.post(f"/servers/1/config-history/{revision}/restore", follow_redirects=True)
        assert b"goes through the file path" in r.data

    def test_an_unproved_restore_is_a_durable_attention_note(self, logged_in_client, revision, monkeypatch):
        from jen.services import kea_changeset as cs

        self._wire(
            monkeypatch,
            apply_result={
                "ok": False,
                "code": "unverified",
                "via": "api",
                "detail": "the daemon did not confirm",
                "needs_hands": True,
            },
        )
        logged_in_client.post(f"/servers/1/config-history/{revision}/restore", follow_redirects=True)
        incidents = cs.recovery_incidents()
        assert any(i.get("category") == "config-api-unverified" for i in incidents), incidents

    def test_a_read_only_server_is_not_restored_over_anything(self, logged_in_client, db, three, monkeypatch):
        server = dict(SERVER_API, config_transport="off")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        rid = rev.record(1, "dhcp4", self.CFG, "h" * 64, "x", hash_kind="kea", source="jen")
        r = logged_in_client.post(f"/servers/1/config-history/{rid}/restore", follow_redirects=True)
        assert b"Read-only" in r.data


class TestTheHistoryLabelsTheNewSources:
    @pytest.mark.parametrize("source", ["rollback", "switch", "pending", "damaged"])
    def test_each_source_has_its_own_badge(self, logged_in_client, three, source):
        rev.record(1, "dhcp4", {"Dhcp4": {}}, "d" * 64, f"a {source} row", hash_kind="kea", source=source)
        html = logged_in_client.get("/servers/1/config-history?service=dhcp4").data.decode()
        assert f">{source}</span>" in html

    def test_the_detail_page_says_what_a_pending_change_is(self, logged_in_client, three):
        rid = rev.record(1, "dhcp4", {"Dhcp4": {}}, "d" * 64, "pending one", hash_kind="kea", source="pending")
        html = logged_in_client.get(f"/servers/1/config-history/{rid}").data.decode()
        assert "daemon's own answer has not settled it" in html and "Recorded from the daemon's own answer" in html
        assert json.loads(rev.get(rid)["config"]) == {"Dhcp4": {}}
