"""
tests/test_config_revisions.py
──────────────────────────────
v5.16.0 — jen/services/config_revisions.py: the Kea config history store
behind migration 20. The route-level tests (history page 200/403, diff
escaping, restore) live in test_servers*.py alongside the blueprint.
"""

import json

import pytest

from jen.models.db import jen_db
from jen.services import config_revisions as rev

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
