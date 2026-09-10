"""
tests/test_config_revisions.py
──────────────────────────────
v5.16.0 — jen/services/config_revisions.py: the Kea config history store
behind migration 20, plus the /servers/<id>/config-history routes that
render and restore it.
"""

import json

import pytest

from jen.models.db import jen_db
from jen.services import config_revisions as rev
from tests.conftest import restricted_client as _restricted_client

_SID = 90210  # a server id no other test seeds


@pytest.fixture(autouse=True)
def _clean():
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (_SID,))
    yield
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (_SID,))


def _cfg(n):
    return {"Dhcp4": {"subnet4": [{"id": n}]}}


class TestCanonical:
    def test_stable_regardless_of_key_order(self):
        a = rev.canonical({"b": 1, "a": 2})
        b = rev.canonical({"a": 2, "b": 1})
        assert a == b
        assert a == '{\n  "a": 2,\n  "b": 1\n}'


class TestRecordAndRead:
    def test_record_returns_id_and_latest_reads_it_back(self):
        rid = rev.record(_SID, "dhcp4", _cfg(1), "sha-1", "add subnet 1")
        assert isinstance(rid, int)
        last = rev.latest(_SID, "dhcp4")
        assert last["id"] == rid
        assert last["sha256"] == "sha-1"
        assert last["summary"] == "add subnet 1"
        assert last["source"] == "jen"
        assert json.loads(last["config"]) == _cfg(1)

    def test_config_is_stored_canonicalised(self):
        rev.record(_SID, "dhcp4", {"z": 1, "a": 2}, "s", "x")
        assert rev.latest(_SID, "dhcp4")["config"] == '{\n  "a": 2,\n  "z": 1\n}'

    def test_service_is_scoped(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s4", "v4")
        rev.record(_SID, "dhcp6", _cfg(2), "s6", "v6")
        assert rev.latest(_SID, "dhcp4")["sha256"] == "s4"
        assert rev.latest(_SID, "dhcp6")["sha256"] == "s6"

    def test_latest_is_none_when_empty(self):
        assert rev.latest(_SID, "dhcp4") is None

    def test_source_external(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s", "changed outside Jen", source="external")
        assert rev.latest(_SID, "dhcp4")["source"] == "external"


class TestListAndGet:
    def test_list_is_newest_first_and_omits_the_body(self):
        for i in range(3):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}")
        rows = rev.list_revisions(_SID, "dhcp4")
        assert [r["summary"] for r in rows] == ["rev 2", "rev 1", "rev 0"]
        assert "config" not in rows[0]

    def test_get_returns_the_full_row(self):
        rid = rev.record(_SID, "dhcp4", _cfg(7), "s7", "rev 7")
        got = rev.get(rid)
        assert got["id"] == rid and json.loads(got["config"]) == _cfg(7)

    def test_previous(self):
        r0 = rev.record(_SID, "dhcp4", _cfg(0), "s0", "rev 0")
        r1 = rev.record(_SID, "dhcp4", _cfg(1), "s1", "rev 1")
        assert rev.previous(r1, _SID, "dhcp4")["id"] == r0
        assert rev.previous(r0, _SID, "dhcp4") is None


class TestPrune:
    def test_prune_keeps_the_newest_n(self):
        ids = [rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}") for i in range(10)]
        removed = rev.prune(_SID, "dhcp4", keep=3)
        assert removed == 7
        kept = {r["id"] for r in rev.list_revisions(_SID, "dhcp4")}
        assert kept == set(ids[-3:])

    def test_prune_is_a_noop_below_the_threshold(self):
        for i in range(2):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}")
        assert rev.prune(_SID, "dhcp4", keep=5) == 0

    def test_record_prunes_automatically(self, monkeypatch):
        monkeypatch.setattr(rev, "_keep", lambda: 4)
        for i in range(9):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}")
        assert len(rev.list_revisions(_SID, "dhcp4")) == 4

    def test_prune_scopes_to_one_service(self):
        for i in range(6):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", "v4")
        rev.record(_SID, "dhcp6", _cfg(0), "s6", "v6")
        rev.prune(_SID, "dhcp4", keep=2)
        assert len(rev.list_revisions(_SID, "dhcp6")) == 1


class TestDiff:
    def test_unified_diff_lines_have_no_trailing_newline(self):
        out = rev.diff("a\nb\nc", "a\nB\nc")
        assert all(not ln.endswith("\n") for ln in out)
        assert any(ln.startswith("-b") for ln in out)
        assert any(ln.startswith("+B") for ln in out)

    def test_identical_inputs_produce_no_diff(self):
        assert rev.diff("x\ny", "x\ny") == []

    def test_labels_appear_in_the_header(self):
        out = rev.diff("a", "b", a_label="rev 3", b_label="rev 4")
        assert any("rev 3" in ln for ln in out[:2])
        assert any("rev 4" in ln for ln in out[:2])


# ── Routes ────────────────────────────────────────────────────────────────

_HSID = 77  # server id used by the route tests


@pytest.fixture
def hist(monkeypatch):
    """A KEA_SERVERS with one SSH-capable server (id 77) and a clean
    kea_config_revisions slice for it."""
    from jen import extensions

    server = {"id": _HSID, "name": "kea-hist", "ssh_host": "10.0.0.5", "ssh_user": "kea"}
    monkeypatch.setattr(extensions, "KEA_SERVERS", [server])

    def _wipe():
        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (_HSID,))

    _wipe()
    yield server
    _wipe()


class TestHistoryListRoute:
    def test_200_for_a_superadmin_and_shows_revisions(self, logged_in_client, hist):
        rev.record(_HSID, "dhcp4", _cfg(1), "sha-aaaa1111", "add subnet 1")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history")
        assert r.status_code == 200
        assert b"add subnet 1" in r.data
        assert b"sha-aaaa1111"[:12] in r.data  # short sha shown

    def test_unknown_server_redirects(self, logged_in_client, hist):
        r = logged_in_client.get("/servers/999/config-history", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_restricted_admin_is_refused(self, client, db, hist, mock_kea):
        c, _ = _restricted_client(client, db, allowed_subnets=[1], role="admin", username="hist_restr")
        r = c.get(f"/servers/{_HSID}/config-history", follow_redirects=True)
        assert r.status_code == 200
        assert b"access to all subnets" in r.data

    def test_viewer_is_refused_by_admin_gate(self, client, db, hist):
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="viewer", username="hist_viewer")
        r = c.get(f"/servers/{_HSID}/config-history", follow_redirects=True)
        assert b"admin access required" in r.data.lower()

    def test_requires_login(self, client, hist):
        r = client.get(f"/servers/{_HSID}/config-history", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()


class TestHistoryDiffRoute:
    def test_diff_against_previous_revision(self, logged_in_client, hist):
        rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1")
        r2 = rev.record(_HSID, "dhcp4", _cfg(2), "s2", "rev 2")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{r2}")
        assert r.status_code == 200
        assert b'"id": 1' in r.data or b"&#34;id&#34;: 1" in r.data  # the removed line
        assert b"rev 2" in r.data

    def test_a_script_tag_in_the_server_name_is_escaped(self, logged_in_client, hist, monkeypatch):
        from jen import extensions

        evil = dict(hist, name="<script>alert('x')</script>")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [evil])
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{rid}")
        assert r.status_code == 200
        assert b"<script>alert(" not in r.data
        assert b"&lt;script&gt;" in r.data

    def test_unknown_revision_redirects_to_the_list(self, logged_in_client, hist):
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/424242", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "config-history" in r.headers.get("Location", "")

    def test_download_serves_json(self, logged_in_client, hist):
        rid = rev.record(_HSID, "dhcp4", _cfg(5), "s5", "rev 5")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{rid}/download")
        assert r.status_code == 200
        assert r.mimetype == "application/json"
        assert json.loads(r.data) == _cfg(5)


class TestHistoryRestoreRoute:
    def _stub_host(self, monkeypatch, *, test_ok=True, apply_res=None):
        calls = {"test": [], "apply": [], "restart": []}
        monkeypatch.setattr(
            "jen.services.kea_host.test_config",
            lambda srv, svc, cfg, *a, **k: (calls["test"].append(svc), {"ok": test_ok, "detail": "bad"})[1],
        )
        monkeypatch.setattr(
            "jen.services.kea_host.apply_config",
            lambda srv, svc, cfg, **k: (
                calls["apply"].append(k),
                apply_res or {"ok": True, "code": "ok", "via": "helper"},
            )[1],
        )
        monkeypatch.setattr(
            "jen.services.kea_host.service_action",
            lambda srv, svc, act: (calls["restart"].append((svc, act)), {"ok": True})[1],
        )
        return calls

    def test_superadmin_restore_applies_with_latest_sha_and_restarts(self, logged_in_client, hist, monkeypatch):
        old = rev.record(_HSID, "dhcp4", _cfg(1), "sha-old", "rev 1")
        rev.record(_HSID, "dhcp4", _cfg(2), "sha-latest", "rev 2")
        calls = self._stub_host(monkeypatch)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{old}/restore", follow_redirects=True)
        assert r.status_code == 200
        assert calls["apply"][0]["expect_sha256"] == "sha-latest"
        assert calls["apply"][0]["source"] == "restore"
        assert calls["apply"][0]["summary"] == f"restore of #{old}"
        assert calls["restart"] == [("dhcp4", "restart")]
        assert b"Restored revision" in r.data

    def test_restore_is_forbidden_for_a_plain_admin(self, client, db, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1")
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="hist_admin_ro")
        r = c.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"superadmin" in r.data.lower()

    def test_restore_conflict_flashes_and_does_not_restart(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1")
        calls = self._stub_host(monkeypatch, apply_res={"ok": False, "code": "conflict", "via": "helper"})
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert r.status_code == 200
        assert b"changed since this page loaded" in r.data
        assert calls["restart"] == []

    def test_restore_aborts_when_the_config_fails_validation(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1")
        calls = self._stub_host(monkeypatch, test_ok=False)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"Restore aborted" in r.data
        assert calls["apply"] == []
