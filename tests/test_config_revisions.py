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
        rid = rev.record(_SID, "dhcp4", _cfg(1), "sha-1", "add subnet 1", hash_kind="raw")
        assert isinstance(rid, int)
        last = rev.latest(_SID, "dhcp4")
        assert last["id"] == rid
        assert last["sha256"] == "sha-1"
        assert last["summary"] == "add subnet 1"
        assert last["source"] == "jen"
        assert last["hash_kind"] == "raw"
        assert json.loads(last["config"]) == _cfg(1)

    def test_config_is_stored_canonicalised(self):
        rev.record(_SID, "dhcp4", {"z": 1, "a": 2}, "s", "x", hash_kind="raw")
        # latest() decrypts transparently — the DECRYPTED body is still
        # the stable canonical JSON, even though the column itself now
        # holds a "v1:"-prefixed Fernet token (see TestEncryptionAtRest).
        assert rev.latest(_SID, "dhcp4")["config"] == '{\n  "a": 2,\n  "z": 1\n}'

    def test_service_is_scoped(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s4", "v4", hash_kind="raw")
        rev.record(_SID, "dhcp6", _cfg(2), "s6", "v6", hash_kind="raw")
        assert rev.latest(_SID, "dhcp4")["sha256"] == "s4"
        assert rev.latest(_SID, "dhcp6")["sha256"] == "s6"

    def test_latest_is_none_when_empty(self):
        assert rev.latest(_SID, "dhcp4") is None

    def test_source_external(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s", "changed outside Jen", source="external", hash_kind="raw")
        assert rev.latest(_SID, "dhcp4")["source"] == "external"

    def test_source_baseline(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s", "initial baseline", source="baseline", hash_kind="raw")
        assert rev.latest(_SID, "dhcp4")["source"] == "baseline"

    def test_hash_kind_round_trips_for_every_kind(self):
        for kind in ("raw", "canonical", "legacy"):
            rev.record(_SID, "dhcp4", _cfg(1), "s", kind, hash_kind=kind)
            assert rev.latest(_SID, "dhcp4")["hash_kind"] == kind


class TestEncryptionAtRest:
    """v5.20.0 — config bodies are encrypted with the same Fernet key as
    MFA secrets and alert-channel config (crypto.py), never plaintext."""

    def test_stored_column_is_a_fernet_token_not_plaintext(self):
        from jen.services.crypto import PREFIX

        rev.record(_SID, "dhcp4", _cfg(1), "s", "x", hash_kind="raw")
        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT config FROM kea_config_revisions WHERE server_id=%s AND service='dhcp4' "
                "ORDER BY id DESC LIMIT 1",
                (_SID,),
            )
            raw_column = cur.fetchone()["config"]
        assert raw_column.startswith(PREFIX)
        assert "subnet4" not in raw_column  # ciphertext hides the plaintext structure

    def test_get_and_previous_also_decrypt(self):
        r0 = rev.record(_SID, "dhcp4", _cfg(0), "s0", "rev 0", hash_kind="raw")
        r1 = rev.record(_SID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        assert json.loads(rev.get(r1)["config"]) == _cfg(1)
        assert json.loads(rev.previous(r1, _SID, "dhcp4")["config"]) == _cfg(0)
        assert r0 != r1


class TestListAndGet:
    def test_list_is_newest_first_and_omits_the_body(self):
        for i in range(3):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}", hash_kind="raw")
        rows = rev.list_revisions(_SID, "dhcp4")
        assert [r["summary"] for r in rows] == ["rev 2", "rev 1", "rev 0"]
        assert "config" not in rows[0]

    def test_get_returns_the_full_row(self):
        rid = rev.record(_SID, "dhcp4", _cfg(7), "s7", "rev 7", hash_kind="raw")
        got = rev.get(rid)
        assert got["id"] == rid and json.loads(got["config"]) == _cfg(7)

    def test_previous(self):
        r0 = rev.record(_SID, "dhcp4", _cfg(0), "s0", "rev 0", hash_kind="raw")
        r1 = rev.record(_SID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        assert rev.previous(r1, _SID, "dhcp4")["id"] == r0
        assert rev.previous(r0, _SID, "dhcp4") is None


class TestPrune:
    def test_prune_keeps_the_newest_n(self):
        ids = [rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}", hash_kind="raw") for i in range(10)]
        removed = rev.prune(_SID, "dhcp4", keep=3)
        assert removed == 7
        kept = {r["id"] for r in rev.list_revisions(_SID, "dhcp4")}
        assert kept == set(ids[-3:])

    def test_prune_is_a_noop_below_the_threshold(self):
        for i in range(2):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}", hash_kind="raw")
        assert rev.prune(_SID, "dhcp4", keep=5) == 0

    def test_record_prunes_automatically(self, monkeypatch):
        monkeypatch.setattr(rev, "_keep", lambda: 4)
        for i in range(9):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}", hash_kind="raw")
        assert len(rev.list_revisions(_SID, "dhcp4")) == 4

    def test_prune_scopes_to_one_service(self):
        for i in range(6):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", "v4", hash_kind="raw")
        rev.record(_SID, "dhcp6", _cfg(0), "s6", "v6", hash_kind="raw")
        rev.prune(_SID, "dhcp4", keep=2)
        assert len(rev.list_revisions(_SID, "dhcp6")) == 1


class TestPruneKeepsTheRecordOfAChange:
    """Q218 BH2 d, e (CFG-006, AC28): a `pending` or `damaged` row is the one record of a change the daemon may be running. The retention prune never removes it and does not count it among the rows
    kept, and no reader takes it for the last settled state."""

    @pytest.mark.parametrize("in_flight", ["pending", "damaged"])
    def test_keep_one_over_an_in_flight_row_with_fifty_settled_rows_above_it(self, in_flight):
        old = rev.record(_SID, "dhcp4", _cfg(0), "before", "the record", hash_kind="kea", source=in_flight)
        for i in range(50):
            rev.record(_SID, "dhcp4", _cfg(i + 1), f"s{i}", f"rev {i}", hash_kind="kea", source="jen")
        removed = rev.prune(_SID, "dhcp4", keep=1)
        kept = {r["id"]: r["source"] for r in rev.list_revisions(_SID, "dhcp4")}
        assert old in kept and kept[old] == in_flight, "the record of the change is still there"
        assert removed == 49 and sum(1 for s in kept.values() if s == "jen") == 1

    def test_a_row_in_flight_is_not_what_pushes_a_settled_revision_out(self):
        for i in range(3):
            rev.record(_SID, "dhcp4", _cfg(i), f"s{i}", f"rev {i}", hash_kind="kea", source="jen")
        rev.record(_SID, "dhcp4", _cfg(9), "p", "in flight", hash_kind="kea", source="pending")
        rev.record(_SID, "dhcp4", _cfg(10), "d", "damaged", hash_kind="kea", source="damaged")
        assert (
            rev.prune(_SID, "dhcp4", keep=3) == 0
        )  # the three settled rows are all there are of them: keep=3 keeps them all
        assert len(rev.list_revisions(_SID, "dhcp4")) == 5

    def test_latest_of_kind_skips_pending_and_damaged(self):
        rev.record(_SID, "dhcp4", _cfg(1), "settled", "x", hash_kind="kea", source="jen")
        rev.record(_SID, "dhcp4", _cfg(2), "p", "x", hash_kind="kea", source="pending")
        rev.record(_SID, "dhcp4", _cfg(3), "d", "x", hash_kind="kea", source="damaged")
        assert rev.latest_of_kind(_SID, "dhcp4", "kea")["sha256"] == "settled"

    def test_latest_skips_pending_and_damaged(self):
        """Q218 D3 (the second pass): `latest()` was unfiltered, so the recovery bundle, the support bundle, Explain and the capture read an in-flight candidate as the server's configuration."""
        rev.record(_SID, "dhcp4", _cfg(1), "settled", "x", hash_kind="kea", source="jen")
        rev.record(_SID, "dhcp4", _cfg(2), "p", "x", hash_kind="kea", source="pending")
        rev.record(_SID, "dhcp4", _cfg(3), "d", "x", hash_kind="kea", source="damaged")
        assert rev.latest(_SID, "dhcp4")["sha256"] == "settled"
        assert rev.latest(_SID, "dhcp4", exclude_kind="raw")["sha256"] == "settled"
        assert {r["source"] for r in rev.list_revisions(_SID, "dhcp4")} == {"jen", "pending", "damaged"}

    def test_the_row_that_proves_a_pending_changes_before_state_is_kept(self):
        """Q218 D6: fifty-five raw rows beside an open pending row pushed the settled `kea` row holding its BEFORE state out, and the settlement then could not prove the file."""
        before = rev.record(
            _SID, "dhcp4", _cfg(0), "before-digest", "the state before", hash_kind="kea", source="baseline"
        )
        pending = rev.record(_SID, "dhcp4", _cfg(1), "before-digest", "the change", hash_kind="kea", source="pending")
        for i in range(55):
            rev.record(_SID, "dhcp4", _cfg(i + 2), f"raw{i}", "an external edit", hash_kind="raw", source="external")
        kept = {r["id"] for r in rev.list_revisions(_SID, "dhcp4")}
        assert before in kept and pending in kept
        assert rev.by_digest(_SID, "dhcp4", "before-digest")["id"] == before

    def test_by_digest_finds_the_settled_revision_and_never_a_row_in_flight(self):
        settled = rev.record(_SID, "dhcp4", _cfg(1), "same", "x", hash_kind="kea", source="baseline")
        rev.record(_SID, "dhcp4", _cfg(2), "same", "x", hash_kind="kea", source="pending")
        rev.record(
            _SID, "dhcp4", _cfg(3), "same", "x", hash_kind="raw", source="jen"
        )  # another kind of digest is not comparable
        found = rev.by_digest(_SID, "dhcp4", "same")
        assert found["id"] == settled and json.loads(found["config"]) == _cfg(1)
        assert rev.by_digest(_SID, "dhcp4", "unknown") is None and rev.by_digest(_SID, "dhcp4", "") is None
        assert rev.by_digest(_SID, "dhcp6", "same") is None


class TestOnePendingRowPerServer:
    """Q219 (BI2 b, AD5): at most one `pending` row per (server, service) is the STORE's rule - `record(source="pending")` answers None when one exists, so a restore over a live pending change can no
    longer plant a second record that every reader takes for the newest."""

    def test_a_second_pending_row_is_not_written(self):
        first = rev.record(_SID, "dhcp4", _cfg(1), "a" * 64, "the change", hash_kind="kea", source="pending")
        second = rev.record(_SID, "dhcp4", _cfg(2), "b" * 64, "another", hash_kind="kea", source="pending")
        assert first is not None and second is None
        assert rev.pending(_SID, "dhcp4")["id"] == first
        assert len([r for r in rev.list_revisions(_SID, "dhcp4") if r["source"] == "pending"]) == 1

    def test_a_pending_row_of_another_server_or_service_is_not_in_the_way(self):
        assert rev.record(_SID, "dhcp4", _cfg(1), "a" * 64, "x", hash_kind="kea", source="pending") is not None
        assert rev.record(_SID, "dhcp6", _cfg(1), "a" * 64, "x", hash_kind="kea", source="pending") is not None
        assert rev.record(_SID + 1, "dhcp4", _cfg(1), "a" * 64, "x", hash_kind="kea", source="pending") is not None
        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (_SID + 1,))

    def test_a_settled_row_never_blocks_a_pending_one_and_a_finished_one_frees_the_slot(self):
        rev.record(_SID, "dhcp4", _cfg(1), "s" * 64, "settled", hash_kind="kea", source="jen")
        first = rev.record(_SID, "dhcp4", _cfg(2), "a" * 64, "the change", hash_kind="kea", source="pending")
        assert first is not None
        assert rev.finish(first, source="jen", sha256="c" * 64)
        assert rev.record(_SID, "dhcp4", _cfg(3), "c" * 64, "the next", hash_kind="kea", source="pending") is not None

    def test_a_non_pending_row_is_never_refused_for_a_pending_one_on_record(self):
        rev.record(_SID, "dhcp4", _cfg(1), "a" * 64, "the change", hash_kind="kea", source="pending")
        assert rev.record(_SID, "dhcp4", _cfg(2), "f" * 64, "an external edit", hash_kind="raw", source="external")

    def test_the_proved_file_rides_on_the_pending_row_only_as_given(self):
        rid = rev.record(
            _SID, "dhcp4", _cfg(1), "a" * 64, "the change", hash_kind="kea", source="pending", file_sha256="d" * 64
        )
        assert rev.pending(_SID, "dhcp4")["file_sha256"] == "d" * 64
        rev.finish(rid, source="jen", sha256="e" * 64)
        other = rev.record(_SID, "dhcp4", _cfg(2), "f" * 64, "no file", hash_kind="kea", source="pending")
        assert rev.pending(_SID, "dhcp4")["id"] == other and rev.pending(_SID, "dhcp4")["file_sha256"] is None


class TestLatestRendering:
    """Q219 (Decided 8 and 14): `latest_rendering` is the newest `raw` row whose source is `rendering` - the file Kea wrote after a change over the API - and nothing else. A file Jen wrote over SSH
    whose restart failed is a `jen`/`rollback`/`restore` raw row and is NEVER Jen's rendering."""

    def test_only_a_rendering_row_counts(self):
        for source in ("jen", "rollback", "restore", "baseline", "external", "switch", "pending", "damaged"):
            rev.record(_SID, "dhcp4", _cfg(1), f"{source:0<64}"[:64], source, hash_kind="raw", source=source)
        assert rev.latest_rendering(_SID, "dhcp4") is None

    def test_a_rendering_row_of_the_wrong_hash_kind_does_not_count(self):
        rev.record(_SID, "dhcp4", _cfg(1), "k" * 64, "the daemon's digest", hash_kind="kea", source="rendering")
        assert rev.latest_rendering(_SID, "dhcp4") is None

    def test_the_newest_rendering_wins_and_is_per_server_and_service(self):
        rev.record(_SID, "dhcp4", _cfg(1), "1" * 64, "first", hash_kind="raw", source="rendering")
        newest = rev.record(_SID, "dhcp4", _cfg(2), "2" * 64, "second", hash_kind="raw", source="rendering")
        rev.record(_SID, "dhcp4", _cfg(3), "3" * 64, "a later hand edit", hash_kind="raw", source="external")
        rev.record(_SID, "dhcp6", _cfg(4), "4" * 64, "another service", hash_kind="raw", source="rendering")
        got = rev.latest_rendering(_SID, "dhcp4")
        assert got["id"] == newest and got["sha256"] == "2" * 64
        assert rev.latest_rendering(_SID + 99, "dhcp4") is None

    def test_a_rendering_is_a_settled_row_the_prune_and_latest_treat_as_jens(self):
        for n in range(4):
            rev.record(_SID, "dhcp4", _cfg(n), f"{n}" * 64, f"r{n}", hash_kind="raw", source="rendering")
        assert rev.latest(_SID, "dhcp4")["source"] == "rendering"
        rev.prune(_SID, "dhcp4", keep=2)
        assert [r["summary"] for r in rev.list_revisions(_SID, "dhcp4")] == ["r3", "r2"]


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
        rev.record(_HSID, "dhcp4", _cfg(1), "sha-aaaa1111", "add subnet 1", hash_kind="raw")
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

    def test_baseline_source_shows_its_badge(self, logged_in_client, hist):
        rev.record(_HSID, "dhcp4", _cfg(1), "sha1", "initial baseline", source="baseline", hash_kind="raw")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history")
        assert r.status_code == 200
        assert b"baseline" in r.data


class TestHistoryDiffRoute:
    def test_diff_against_previous_revision(self, logged_in_client, hist):
        rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        r2 = rev.record(_HSID, "dhcp4", _cfg(2), "s2", "rev 2", hash_kind="raw")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{r2}")
        assert r.status_code == 200
        assert b'"id": 1' in r.data or b"&#34;id&#34;: 1" in r.data  # the removed line
        assert b"rev 2" in r.data

    def test_a_script_tag_in_the_server_name_is_escaped(self, logged_in_client, hist, monkeypatch):
        from jen import extensions

        evil = dict(hist, name="<script>alert('x')</script>")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [evil])
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{rid}")
        assert r.status_code == 200
        assert b"<script>alert(" not in r.data
        assert b"&lt;script&gt;" in r.data

    def test_baseline_source_shows_an_info_alert(self, logged_in_client, hist):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "sha1", "initial baseline", source="baseline", hash_kind="raw")
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/{rid}")
        assert r.status_code == 200
        assert b"first config Jen saw on this host" in r.data

    def test_unknown_revision_redirects_to_the_list(self, logged_in_client, hist):
        r = logged_in_client.get(f"/servers/{_HSID}/config-history/424242", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "config-history" in r.headers.get("Location", "")

    def test_download_serves_json(self, logged_in_client, hist):
        rid = rev.record(_HSID, "dhcp4", _cfg(5), "s5", "rev 5", hash_kind="raw")
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
        old = rev.record(_HSID, "dhcp4", _cfg(1), "sha-old", "rev 1", hash_kind="raw")
        rev.record(_HSID, "dhcp4", _cfg(2), "sha-latest", "rev 2", hash_kind="raw")
        calls = self._stub_host(monkeypatch)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{old}/restore", follow_redirects=True)
        assert r.status_code == 200
        assert calls["apply"][0]["expect_sha256"] == "sha-latest"
        assert calls["apply"][0]["source"] == "restore"
        assert calls["apply"][0]["summary"] == f"restore of #{old}"
        assert calls["restart"] == [("dhcp4", "restart")]
        assert b"Restored revision" in r.data

    def test_restore_is_forbidden_for_a_plain_admin(self, client, db, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="hist_admin_ro")
        r = c.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"superadmin" in r.data.lower()

    def test_restore_conflict_flashes_and_does_not_restart(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub_host(monkeypatch, apply_res={"ok": False, "code": "conflict", "via": "helper"})
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert r.status_code == 200
        assert b"changed since this page loaded" in r.data
        assert calls["restart"] == []

    def test_restore_aborts_when_the_config_fails_validation(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub_host(monkeypatch, test_ok=False)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"Restore aborted" in r.data
        assert calls["apply"] == []

    def test_restore_with_a_non_raw_latest_reads_the_live_sha_instead(self, logged_in_client, hist, monkeypatch):
        # v5.20.0 — a "canonical"/"legacy" latest sha is NOT comparable to
        # what a helper v2 apply-config will re-hash (it hashes a
        # different thing entirely), so restore must not pass it as
        # expect_sha256. It reads the live sha right before the write
        # instead, the same short-window pattern add/delete already use.
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "canon-sha", "rev 1", hash_kind="canonical")
        calls = self._stub_host(monkeypatch)
        monkeypatch.setattr(
            "jen.services.kea_host.read_config_versioned",
            lambda srv, svc: (_cfg(1), "live-sha-on-host"),
        )
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert r.status_code == 200
        assert calls["apply"][0]["expect_sha256"] == "live-sha-on-host"


class TestARestoreTakesTheChangeLockOnBothBranches:
    """Q219 BI2 e (AD-Q2): the file branch of the restore took no change lock while the api branch did, so a restore could run beside a change, a switch or an import. Both answer the busy sentence."""

    @pytest.mark.parametrize("transport", ["file", "api"])
    def test_a_restore_under_a_held_lock_is_the_busy_sentence_and_nothing_is_sent(
        self, logged_in_client, hist, monkeypatch, transport
    ):
        import threading

        from jen import extensions
        from jen.services import kea_changeset as cs

        server = {
            "id": _HSID,
            "name": "kea-hist",
            "ssh_host": "10.0.0.5",
            "ssh_user": "kea",
            "api_url": "http://127.0.0.1:9/",
        }
        if transport == "api":
            server["config_transport"] = "api"
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        sent = []
        for name in ("test_config", "apply_config", "service_action"):
            monkeypatch.setattr(
                f"jen.services.kea_host.{name}", lambda *a, _n=name, **k: sent.append(_n) or {"ok": True}
            )
        monkeypatch.setattr(
            "jen.services.kea_api_config.apply", lambda *a, **k: sent.append("api-apply") or {"ok": True}
        )
        monkeypatch.setattr(cs, "CHANGE_WAIT_SECONDS", 0.2)
        release, holding = threading.Event(), threading.Event()

        def hold():
            with cs.change_lock(5):
                holding.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        holding.wait(2)
        try:
            r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        finally:
            release.set()
            t.join(3)
        assert cs.BUSY_SENTENCE[1:].encode() in r.data, r.data[:400]
        assert "apply_config" not in sent and "api-apply" not in sent and "service_action" not in sent


class TestTheRestoreRouteIsHeldToItsSiblingsGate:
    """Q203 AS2 (the pass's N4/N5/N6): the restore wrote a stored revision into the daemon's file behind a superadmin and NO step-up while its sibling, the unmasked download of the same revision, asks for
    one; a failed restart was a flash and nothing else; and it passed no `tls_paths`, so the material-before-reference preflight never ran on a restore."""

    @pytest.fixture(autouse=True)
    def _clean_incidents(self):
        from jen.services import kea_changeset

        kea_changeset.acknowledge_recovery(_HSID)
        yield
        kea_changeset.acknowledge_recovery(_HSID)

    @staticmethod
    def _stub(monkeypatch, restart_ok=True):
        calls = {"test": [], "apply": [], "restart": []}
        monkeypatch.setattr(
            "jen.services.kea_host.test_config",
            lambda srv, svc, cfg, *a, **k: (calls["test"].append(k), {"ok": True})[1],
        )
        monkeypatch.setattr(
            "jen.services.kea_host.apply_config",
            lambda srv, svc, cfg, **k: (calls["apply"].append(k), {"ok": True, "code": "ok", "via": "helper"})[1],
        )
        monkeypatch.setattr(
            "jen.services.kea_host.service_action",
            lambda srv, svc, act: (
                calls["restart"].append((svc, act)),
                {"ok": restart_ok, "detail": "" if restart_ok else "unit kea-dhcp4-server failed to start"},
            )[1],
        )
        return calls

    @staticmethod
    def _stale(client):
        from datetime import datetime, timedelta, timezone

        with client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()

    def test_an_admin_is_refused_and_nothing_reaches_the_host(self, client, db, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="q203_restore_admin")
        r = c.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"superadmin" in r.data.lower()
        assert calls == {"test": [], "apply": [], "restart": []}

    def test_a_superadmin_without_a_recent_confirmation_is_sent_to_confirm_and_nothing_reaches_the_host(
        self, logged_in_client, hist, monkeypatch
    ):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub(monkeypatch)
        self._stale(logged_in_client)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore")
        assert r.status_code == 302 and "reauth" in r.headers["Location"]
        assert calls == {"test": [], "apply": [], "restart": []}

    def test_a_superadmin_with_a_recent_confirmation_restores(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub(monkeypatch)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"Restored revision" in r.data and calls["restart"] == [("dhcp4", "restart")]

    def test_a_failed_restart_is_a_durable_incident_the_banner_and_health_carry_and_a_working_restart_ends_it(
        self, logged_in_client, hist, monkeypatch
    ):
        from jen.services import health, kea_changeset

        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        calls = self._stub(monkeypatch, restart_ok=False)
        r = logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert b"restart Kea manually" in r.data
        # persisted: the unresolved note is in the settings table, not only in the flash
        mine = [
            i
            for i in kea_changeset.recovery_incidents(strict=True)
            if i.get("category") == "config-restart-failed" and str(i.get("server_id")) == str(_HSID)
        ]
        assert len(mine) == 1 and mine[0]["service"] == "dhcp4" and mine[0]["summary"] == f"restore of revision #{rid}"
        assert "did not restart on it" in mine[0]["detail"]
        # delivered: the Servers banner reads the same note
        banner = kea_changeset.attention()
        assert any(i.get("category") == "config-restart-failed" for i in banner["incidents"])
        # derived: Health's "direct-socket changes are proved" row carries it as a stopped daemon (fail, not warn)
        row = health._direct_socket_recovery({})
        assert row.status == "fail" and "config-restart-failed" in row.detail, (row.status, row.detail)
        # a second failed restore refreshes the same incident, it does not stack
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert len([i for i in kea_changeset.recovery_incidents() if i.get("category") == "config-restart-failed"]) == 1
        # resolved by the next restart of that daemon that works (here: the same restore, the unit starting this time)
        calls_ok = self._stub(monkeypatch, restart_ok=True)
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert not [i for i in kea_changeset.recovery_incidents() if i.get("category") == "config-restart-failed"]
        assert calls_ok["restart"] == [("dhcp4", "restart")] and calls["restart"]

    def test_the_servers_restart_button_that_works_also_ends_it(self, logged_in_client, hist, monkeypatch):
        from jen.services import kea_changeset

        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        self._stub(monkeypatch, restart_ok=False)
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert [i for i in kea_changeset.recovery_incidents() if i.get("category") == "config-restart-failed"]
        self._stub(monkeypatch, restart_ok=True)
        logged_in_client.post(f"/servers/restart/{_HSID}", follow_redirects=True)
        assert not [i for i in kea_changeset.recovery_incidents() if i.get("category") == "config-restart-failed"]

    def test_a_superadmin_can_acknowledge_it_like_any_other_unproved_recovery(
        self, logged_in_client, hist, monkeypatch
    ):
        from jen.services import kea_changeset

        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "rev 1", hash_kind="raw")
        self._stub(monkeypatch, restart_ok=False)
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert kea_changeset.acknowledge_recovery(_HSID, "dhcp4", "config-restart-failed") == 1

    def test_the_restore_passes_the_tls_paths_its_config_references_to_the_test_and_the_apply(
        self, logged_in_client, hist, monkeypatch
    ):
        from jen.services import kea_tls

        remote = kea_tls.remote_tls_paths("dhcp4")
        cfg = {
            "Dhcp4": {
                "control-socket": {
                    "socket-type": "https",
                    "trust-anchor": remote["trust_anchor"],
                    "cert-file": remote["cert_file"],
                    "key-file": remote["key_file"],
                }
            }
        }
        rid = rev.record(_HSID, "dhcp4", cfg, "s1", "rev with https", hash_kind="raw")
        calls = self._stub(monkeypatch)
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        wanted = [(remote["trust_anchor"], "file"), (remote["cert_file"], "file"), (remote["key_file"], "file")]
        assert calls["test"][0]["tls_paths"] == wanted and calls["apply"][0]["tls_paths"] == wanted

    def test_a_config_that_references_none_passes_none(self, logged_in_client, hist, monkeypatch):
        rid = rev.record(_HSID, "dhcp4", _cfg(1), "s1", "plain", hash_kind="raw")
        calls = self._stub(monkeypatch)
        logged_in_client.post(f"/servers/{_HSID}/config-history/{rid}/restore", follow_redirects=True)
        assert calls["test"][0]["tls_paths"] == [] and calls["apply"][0]["tls_paths"] == []


class TestPruneKeepsTheNewestRendering:
    """Q221 - the newest `rendering` row is what `kea_api_config.file_proof`'s (R) reads: the file Kea wrote after a change over the API. With `config_revision_keep` at 1 (the settings form allows
    1 to 1000) a later capture pushed it out, and every second change over the API was then refused until Kea was restarted. The prune never takes it; an OLDER rendering goes like any row."""

    def test_the_newest_rendering_survives_a_keep_of_one(self):
        _clean()
        rendering = rev.record(
            _SID, "dhcp4", _cfg(1), "file-sha-1", "kea wrote its file", hash_kind="raw", source="rendering"
        )
        for n in range(2, 6):
            rev.record(_SID, "dhcp4", _cfg(n), f"digest-{n}", f"read {n}", hash_kind="kea", source="external")
        rev.prune(_SID, "dhcp4", keep=1)
        assert (rev.latest_rendering(_SID, "dhcp4") or {}).get("id") == rendering
        kept = [r["id"] for r in rev.list_revisions(_SID, "dhcp4")]
        assert rendering in kept and len(kept) == 2, kept  # the newest settled row, and the newest rendering
        _clean()

    def test_an_older_rendering_goes_like_any_row(self):
        _clean()
        older = rev.record(
            _SID, "dhcp4", _cfg(1), "file-sha-1", "kea wrote its file", hash_kind="raw", source="rendering"
        )
        rev.record(_SID, "dhcp4", _cfg(2), "digest-2", "a change", hash_kind="kea", source="jen")
        newer = rev.record(
            _SID, "dhcp4", _cfg(3), "file-sha-3", "kea wrote its file", hash_kind="raw", source="rendering"
        )
        rev.record(_SID, "dhcp4", _cfg(4), "digest-4", "read", hash_kind="kea", source="external")
        rev.prune(_SID, "dhcp4", keep=1)
        kept = [r["id"] for r in rev.list_revisions(_SID, "dhcp4")]
        assert newer in kept and older not in kept and len(kept) == 2, kept
        _clean()

    def test_no_rendering_at_all_prunes_as_before(self):
        _clean()
        for n in range(1, 5):
            rev.record(_SID, "dhcp4", _cfg(n), f"digest-{n}", f"read {n}", hash_kind="kea", source="external")
        assert rev.prune(_SID, "dhcp4", keep=2) == 2
        assert len(rev.list_revisions(_SID, "dhcp4")) == 2
        _clean()
