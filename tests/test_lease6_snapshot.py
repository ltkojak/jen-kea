"""
tests/test_lease6_snapshot.py
─────────────────────────────
v5.68.0-beta.17 (Q152, item d) - `lease6_history` was created by migration 11 in v5.0 and nothing wrote it: every install had an empty
table, the backup described "historical IPv6 lease counts" that did not exist, and an IPv6 subnet had no history on Reports. The
snapshot job now writes one row per IPv6 subnet (active leases by type, reservations by type) when IPv6 is on - and nothing, not even a
read of the v6 tables, when it is off - with the same retention as the IPv4 history, and Reports charts the counts with no projection.
"""

import pytest

from jen import extensions
from jen.models.db import jen_db
from jen.models.user import _invalidate_settings_cache, set_global_setting
from jen.services import alerts, kea6

V6 = {501: {"name": "V6LAN", "cidr": "2001:db8:501::/64", "paired_subnet4_id": 1}}
V6_UNPAIRED = {502: {"name": "V6UNPAIRED", "cidr": "2001:db8:502::/64", "paired_subnet4_id": None}}


def _lease(kind):
    return {"lease_type_name": kind}


def _host(*kinds):
    return {"reservations": [{"type_name": k} for k in kinds]}


@pytest.fixture
def v6_world(monkeypatch):
    """IPv6 on, two v6 subnets configured, scripted v6 readers, and a clean lease6_history."""
    set_global_setting("ipv6_enabled", "true")
    _invalidate_settings_cache()
    monkeypatch.setattr(extensions, "SUBNET6_MAP", {**V6, **V6_UNPAIRED})
    leases = {
        501: [_lease("IA_NA")] * 3 + [_lease("IA_PD")] * 2 + [_lease("IA_TA")],
        502: [_lease("IA_NA")],
    }
    hosts = {501: [_host("IA_NA"), _host("IA_NA", "IA_PD")], 502: []}
    calls = []
    monkeypatch.setattr(
        kea6, "list_lease6", lambda subnet_id=None, **k: calls.append(("leases", subnet_id)) or leases[subnet_id]
    )
    monkeypatch.setattr(
        kea6, "get_ipv6_reservations", lambda subnet_id=None: calls.append(("resv", subnet_id)) or hosts[subnet_id]
    )
    _wipe()
    yield calls
    _wipe()
    set_global_setting("ipv6_enabled", "false")
    _invalidate_settings_cache()


def _wipe():
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM lease6_history")
        db.commit()


def _rows():
    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT subnet_id, active_na, active_ta, active_pd, reserved_na, reserved_pd FROM lease6_history ORDER BY subnet_id, id"
        )
        return cur.fetchall()


class TestTheSnapshotWritesLease6History:
    def test_one_row_per_v6_subnet_with_the_counts_by_type(self, v6_world):
        alerts.take_lease6_snapshot()
        assert _rows() == [
            {"subnet_id": 501, "active_na": 3, "active_ta": 1, "active_pd": 2, "reserved_na": 2, "reserved_pd": 1},
            {"subnet_id": 502, "active_na": 1, "active_ta": 0, "active_pd": 0, "reserved_na": 0, "reserved_pd": 0},
        ]

    def test_the_ipv4_snapshot_pass_writes_both_tables_when_ipv6_is_on(self, v6_world, mock_kea):
        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            db.commit()
        alerts.take_lease_snapshot()
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM lease_history")
            v4 = cur.fetchone()["n"]
        assert v4 >= 1, "the IPv4 snapshot still ran"
        assert {r["subnet_id"] for r in _rows()} == {501, 502}, "and the same pass recorded the IPv6 subnets"

    def test_rows_older_than_the_retention_are_removed_with_the_same_setting(self, v6_world):
        set_global_setting("history_retention_days", "30")
        try:
            with jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "INSERT INTO lease6_history (subnet_id, snapshot_time, active_na) VALUES (501, DATE_SUB(NOW(), INTERVAL 31 DAY), 9)"
                )
                cur.execute(
                    "INSERT INTO lease6_history (subnet_id, snapshot_time, active_na) VALUES (501, DATE_SUB(NOW(), INTERVAL 10 DAY), 8)"
                )
                db.commit()
            alerts.take_lease6_snapshot()
            kept = [r["active_na"] for r in _rows() if r["subnet_id"] == 501]
            assert 9 not in kept and 8 in kept
        finally:
            set_global_setting("history_retention_days", "90")


class TestNothingRunsWithIpv6Off:
    """The v4-only guarantee (tests/test_kea6_config.py::TestZeroBehaviorChange): with IPv6 off the snapshot job never reads a v6 table
    and never writes lease6_history."""

    def test_no_v6_reader_is_called_and_no_row_is_written(self, monkeypatch, mock_kea):
        set_global_setting("ipv6_enabled", "false")
        _invalidate_settings_cache()
        monkeypatch.setattr(extensions, "SUBNET6_MAP", V6)

        def boom(*a, **k):
            raise AssertionError("a v6 reader ran with IPv6 off")

        monkeypatch.setattr(kea6, "list_lease6", boom)
        monkeypatch.setattr(kea6, "get_ipv6_reservations", boom)
        _wipe()
        alerts.take_lease_snapshot()
        assert _rows() == []


class TestReportsChartsTheCounts:
    def _seed(self, subnet_id=501):
        with jen_db() as db, db.cursor() as cur:
            for i in range(3):
                cur.execute(
                    "INSERT INTO lease6_history (subnet_id, active_na, active_ta, active_pd, reserved_na, reserved_pd) "
                    "VALUES (%s, %s, 0, %s, 1, 0)",
                    (subnet_id, 10 + i, 2),
                )
            db.commit()

    def test_a_v6_subnet_gets_a_chart_and_the_reason_there_is_no_projection(self, v6_world, logged_in_client):
        self._seed()
        page = logged_in_client.get("/reports").get_data(as_text=True)
        assert 'id="chart6-501"' in page and "V6LAN" in page
        assert "has no finite pool to project against" in page
        fn6 = page[page.index("function buildCharts6") : page.index("buildCharts6();")]
        assert "Pool Size" not in fn6 and "projection" not in fn6.lower().replace("no projection", ""), (
            "an IPv6 chart has no pool-size series and no projection dataset"
        )
        assert "const HISTORY6" in page

    def test_the_page_carries_no_v6_chart_when_ipv6_is_off(self, logged_in_client, monkeypatch):
        set_global_setting("ipv6_enabled", "false")
        _invalidate_settings_cache()
        monkeypatch.setattr(extensions, "SUBNET6_MAP", V6)
        _wipe()
        self._seed()
        page = logged_in_client.get("/reports").get_data(as_text=True)
        assert "chart6-" not in page and "finite pool" not in page
        _wipe()

    def test_a_restricted_account_sees_only_the_v6_subnets_paired_to_a_v4_subnet_it_may_see(self, v6_world, client, db):
        from tests.conftest import restricted_client

        self._seed(501)
        self._seed(502)
        c, _uid = restricted_client(client, db, [1])
        page = c.get("/reports").get_data(as_text=True)
        assert 'id="chart6-501"' in page, "paired to v4 subnet 1, which this account may see"
        assert "chart6-502" not in page, "an unpaired v6 subnet is for unrestricted accounts only"
