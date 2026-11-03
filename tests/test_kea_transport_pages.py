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


class TestTheServersPageBadge:
    def test_one_word_per_server(self, logged_in_client, three):
        html = logged_in_client.get("/servers").data.decode()
        assert 'data-transport="api"' in html and 'data-transport="file"' in html and 'data-transport="off"' in html

    def test_an_api_server_with_no_authentication_says_so(self, logged_in_client, three):
        html = logged_in_client.get("/servers").data.decode()
        assert "API, unauthenticated" in html

    def test_a_remembered_refusal_is_named_on_the_server(self, logged_in_client, three, monkeypatch):
        monkeypatch.setattr(
            api,
            "refusal_sentence",
            lambda server: "the daemon on Test Kea may not write its file (denied)" if server["id"] == 1 else "",
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
        assert "/settings/infrastructure/kea-transport/1" in html and "data-config-probe" in html

    def test_an_admin_sees_the_facts_and_no_controls(self, client, db, three):
        from tests.conftest import restricted_client

        restricted_client(client, db, None, role="admin", username="card-admin-q212")
        html = client.get("/settings/kea").data.decode()
        assert 'id="kea-config-transport"' in html
        assert "/settings/infrastructure/kea-transport/" not in html and "data-config-probe" not in html


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

    def test_an_off_server_is_not_a_write_target(self, logged_in_client, db, three, monkeypatch):
        server = dict(SERVER_API, config_transport="off")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        rid = rev.record(1, "dhcp4", self.CFG, "h" * 64, "x", hash_kind="kea", source="jen")
        r = logged_in_client.post(f"/servers/1/config-history/{rid}/restore", follow_redirects=True)
        assert b"not a write target" in r.data


class TestTheHistoryLabelsTheNewSources:
    @pytest.mark.parametrize("source", ["rollback", "switch", "pending"])
    def test_each_source_has_its_own_badge(self, logged_in_client, three, source):
        rev.record(1, "dhcp4", {"Dhcp4": {}}, "d" * 64, f"a {source} row", hash_kind="kea", source=source)
        html = logged_in_client.get("/servers/1/config-history?service=dhcp4").data.decode()
        assert f">{source}</span>" in html

    def test_the_detail_page_says_what_a_pending_change_is(self, logged_in_client, three):
        rid = rev.record(1, "dhcp4", {"Dhcp4": {}}, "d" * 64, "pending one", hash_kind="kea", source="pending")
        html = logged_in_client.get(f"/servers/1/config-history/{rid}").data.decode()
        assert "daemon's own answer has not settled it" in html and "Recorded from the daemon's own answer" in html
        assert json.loads(rev.get(rid)["config"]) == {"Dhcp4": {}}
