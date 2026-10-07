"""
tests/test_lease6_snapshot.py
─────────────────────────────
v5.68.0-beta.17 (Q152, item d; Q153 moved the counting to two aggregate queries and the retention out of the IPv6 path) - `lease6_history` was created by migration 11 in v5.0 and nothing wrote it: every install had an empty
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


@pytest.fixture
def v6_world(monkeypatch):
    """IPv6 on, two v6 subnets configured, scripted AGGREGATE v6 readers (v5.68.0-beta.18: two queries for the whole map), clean history."""
    set_global_setting("ipv6_enabled", "true")
    _invalidate_settings_cache()
    monkeypatch.setattr(extensions, "SUBNET6_MAP", {**V6, **V6_UNPAIRED})
    calls = []
    monkeypatch.setattr(
        kea6,
        "count_lease6_by_subnet",
        lambda subnet_ids=None: (
            calls.append("leases")
            or {501: {"IA_NA": 3, "IA_TA": 1, "IA_PD": 2}, 502: {"IA_NA": 1, "IA_TA": 0, "IA_PD": 0}}
        ),
    )
    monkeypatch.setattr(
        kea6,
        "count_reservations6_by_subnet",
        lambda subnet_ids=None: calls.append("resv") or {501: {"IA_NA": 2, "IA_PD": 1}, 502: {"IA_NA": 0, "IA_PD": 0}},
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

    def test_two_aggregate_queries_for_the_whole_map_not_two_per_subnet(self, v6_world):
        """Q153 (7): it was `list_lease6` + `get_ipv6_reservations` per subnet (2 x N, every lease materialised with a MAC lookup)."""
        alerts.take_lease6_snapshot()
        assert v6_world == ["leases", "resv"]

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

    def test_rows_older_than_the_retention_are_removed_by_the_retention_pass(self, v6_world, mock_kea):
        set_global_setting("history_retention_days", "30")
        try:
            _seed_old_and_recent()
            alerts.purge_history()
            kept = [r["active_na"] for r in _rows() if r["subnet_id"] == 501]
            assert 9 not in kept and 8 in kept
        finally:
            set_global_setting("history_retention_days", "90")


def _seed_old_and_recent():
    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease6_history (subnet_id, snapshot_time, active_na) VALUES (501, DATE_SUB(NOW(), INTERVAL 31 DAY), 9)"
        )
        cur.execute(
            "INSERT INTO lease6_history (subnet_id, snapshot_time, active_na) VALUES (501, DATE_SUB(NOW(), INTERVAL 10 DAY), 8)"
        )
        db.commit()


class TestRetentionDoesNotDependOnTheFeatureFlag:
    """v5.68.0-beta.18 (Q153, item 6): the purge used to live inside `take_lease6_snapshot`, which runs only while IPv6 is ON - turn IPv6
    off and months of rows outlived `history_retention_days` forever. It is now part of the unconditional pass."""

    def test_an_old_row_is_removed_with_ipv6_off_and_no_v6_query_runs(self, monkeypatch, mock_kea):
        set_global_setting("ipv6_enabled", "false")
        _invalidate_settings_cache()
        monkeypatch.setattr(extensions, "SUBNET6_MAP", V6)

        def boom(*a, **k):
            raise AssertionError("a v6 query ran with IPv6 off")

        for name in ("list_lease6", "get_ipv6_reservations", "count_lease6_by_subnet", "count_reservations6_by_subnet"):
            monkeypatch.setattr(kea6, name, boom)
        set_global_setting("history_retention_days", "30")
        _wipe()
        try:
            _seed_old_and_recent()
            alerts.purge_history()
            assert [r["active_na"] for r in _rows()] == [8], (
                "the 31-day-old row is gone, the 10-day-old one stays, nothing new is written"
            )
        finally:
            set_global_setting("history_retention_days", "90")
            _wipe()


class TestTheAggregateCountsMatchTheReaders:
    """The two aggregate queries count what `list_lease6` / `get_ipv6_reservations` list, against the real tables."""

    @pytest.fixture
    def seeded(self, db, monkeypatch):
        from tests.test_kea6_binary_addresses import packed

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {771: {"name": "S", "cidr": "2001:db8:71::/64", "paired_subnet4_id": None}}
        )
        _clean(db)
        with db.cursor() as cur:
            for address, lease_type, expire, state in (
                ("2001:db8:71::1", 0, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71::2", 0, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71::3", 0, "DATE_SUB(NOW(), INTERVAL 1 HOUR)", 0),  # state 0 past its expiry
                ("2001:db8:71::4", 1, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71:100::", 2, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71::5", 0, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 1),  # declined
            ):
                cur.execute(
                    "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "  # nosec B608 - test seed
                    f"prefix_len, hostname, hwaddr, state) VALUES (INET6_ATON(%s), %s, 3600, {expire}, 771, 1800, %s, 1, 64, 'h', NULL, %s)",
                    (address, bytes.fromhex("00030001001a2b3c4d5e"), lease_type, state),
                )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname) VALUES (%s, 1, 771, 'res')",
                (bytes.fromhex("00030001001a2b3c4d5e"),),
            )
            host_id = cur.lastrowid
            for address, rtype in (("2001:db8:71::50", 0), ("2001:db8:71::51", 0), ("2001:db8:71:200::", 2)):
                cur.execute(
                    "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id, excluded_prefix, excluded_prefix_len) "
                    "VALUES (%s, 64, %s, 1, %s, NULL, 0)",
                    (packed(address), rtype, host_id),
                )
        db.commit()
        yield
        _clean(db)

    def test_active_leases_by_type(self, seeded):
        counted = kea6.count_lease6_by_subnet()
        listed = {}
        for lease in kea6.list_lease6(subnet_id=771):
            listed[lease["lease_type_name"]] = listed.get(lease["lease_type_name"], 0) + 1
        assert counted == {771: {"IA_NA": 2, "IA_TA": 1, "IA_PD": 1}}
        assert {k: v for k, v in counted[771].items() if v} == listed

    def test_reservations_by_type(self, seeded):
        counted = kea6.count_reservations6_by_subnet()
        listed = {}
        for host in kea6.get_ipv6_reservations(subnet_id=771):
            for r in host["reservations"]:
                listed[r["type_name"]] = listed.get(r["type_name"], 0) + 1
        assert counted == {771: {"IA_NA": 2, "IA_PD": 1}}
        assert {k: v for k, v in counted[771].items() if v} == listed

    def test_a_subnet_outside_the_map_is_never_returned(self, seeded):
        assert set(kea6.count_lease6_by_subnet([999])) == {999}
        assert kea6.count_lease6_by_subnet([999]) == {999: {"IA_NA": 0, "IA_TA": 0, "IA_PD": 0}}
        assert 771 not in kea6.count_reservations6_by_subnet([999])


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease6 WHERE subnet_id=771")
        cur.execute(
            "DELETE FROM ipv6_reservations WHERE host_id IN (SELECT host_id FROM hosts WHERE dhcp6_subnet_id=771)"
        )
        cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id=771")
    db.commit()


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
        assert 'id="chart6-' not in page and "has no finite pool to project against" not in page
        _wipe()

    def test_a_restricted_account_sees_only_the_v6_subnets_paired_to_a_v4_subnet_it_may_see(self, v6_world, client, db):
        from tests.conftest import restricted_client

        self._seed(501)
        self._seed(502)
        c, _uid = restricted_client(client, db, [1])
        page = c.get("/reports").get_data(as_text=True)
        assert 'id="chart6-501"' in page, "paired to v4 subnet 1, which this account may see"
        assert "chart6-502" not in page, "an unpaired v6 subnet is for unrestricted accounts only"
