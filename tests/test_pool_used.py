"""
tests/test_pool_used.py
──────────────────────
v5.68.0-beta.19 (Q154) - the Q153 contract "pool consumption is the active leases INSIDE the pool union" holds in every layer, not just the live
page: what is PERSISTED (`lease_history.pool_used`), what is DERIVED from it (Health, the forecast, the pool-forecast alert, Prometheus, Reports,
the dashboard history). One fixture: a 100-address pool with 80 leases in it and 30 active leases outside it (reservations). The subnet has 110
active clients, uses 80 % of its pool and has 20 free - and every surface says so; before this release the persisted and derived ones said 110 %.
"""

import re

import pytest

from jen import extensions
from jen.models.db import jen_db
from jen.services import alerts, capacity, health
from jen.services import kea as kea_svc

POOLS = [{"pool": "10.92.0.1 - 10.92.0.100"}]
CONFIG = {"subnet4": [{"id": 1, "subnet": "10.92.0.0/16", "pools": POOLS}]}
IN, OUT, SIZE = 80, 30, 100


def _ip(text):
    import ipaddress

    return int(ipaddress.IPv4Address(text))


@pytest.fixture
def world(db, monkeypatch, mock_kea):
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.92.0.0/16"}})
    fake = lambda command, *a, **kw: (  # noqa: E731
        {"result": 0, "text": "ok", "arguments": {"Dhcp4": CONFIG}}
        if command == "config-get"
        else {"result": 0, "text": "ok", "arguments": {}}
    )
    monkeypatch.setattr(kea_svc, "kea_command", fake)
    monkeypatch.setattr("jen.routes.api.kea_command", fake)
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4")
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
        for n in range(IN):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (%s, UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (_ip("10.92.0.1") + n, f"AABB9200{n:04X}"),
            )
        for n in range(OUT):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (%s, UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (_ip("10.92.0.150") + n, f"AABB9201{n:04X}"),
            )
        # eight earlier days, rising to today's 80 in the pool while the whole-subnet count runs 30 higher
        for ago in range(8, 0, -1):
            used = IN - 2 * (ago - 1)
            cur.execute(
                "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, dynamic_leases, reserved_leases, pool_size, pool_used) "
                "VALUES (1, DATE_SUB(NOW(), INTERVAL %s DAY), %s, %s, %s, %s, %s)",
                (ago, used + OUT, used, OUT, SIZE, used),
            )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4")
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
    db.commit()


@pytest.fixture
def metrics_opened(monkeypatch):
    import configparser

    cfg = configparser.ConfigParser()
    cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
    if "server" not in cfg:
        cfg["server"] = {}
    cfg["server"]["metrics_open"] = "true"
    monkeypatch.setattr(extensions, "cfg", cfg)


def _newest(db):
    with db.cursor() as cur:
        cur.execute(
            "SELECT active_leases, pool_used, pool_size, reserved_leases FROM lease_history WHERE subnet_id=1 ORDER BY snapshot_time DESC, id DESC LIMIT 1"
        )
        return cur.fetchone()


class TestEightyInThirtyOutOnEverySurface:
    def test_1_the_snapshot_persists_both_numbers(self, world, db):
        alerts.take_lease_snapshot()
        row = _newest(db)
        assert (row["active_leases"], row["pool_used"], row["pool_size"]) == (IN + OUT, IN, SIZE)

    def test_2_the_dashboard_live_stats(self, world, logged_in_client):
        data = logged_in_client.get("/api/stats").get_json()
        assert data["pool_sizes"]["1"] == SIZE and data["subnets"]["1"]["pool_used"] == IN
        assert data["subnets"]["1"]["active"] == IN + OUT

    def test_3_the_dashboard_history_percentage_is_pool_use(self, world, logged_in_client, db):
        alerts.take_lease_snapshot()
        points = logged_in_client.get("/api/lease-history?days=30").get_json()["history"]["1"]
        assert points[-1]["pct"] == 80.0 and points[-1]["u"] == 80.0 and points[-1]["a"] == 110.0

    def test_4_the_rest_api(self, world, client, db):
        import hashlib

        raw = "q154-pool-used-key-0123456789"
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            owner = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) VALUES (%s, %s, %s, %s, NULL, 1)",
                ("q154", hashlib.sha256(raw.encode()).hexdigest(), raw[:8], owner),
            )
        db.commit()
        data = client.get("/api/v1/subnets", headers={"Authorization": f"Bearer {raw}"}).get_json()
        row = next(s for s in data["subnets"] if s["id"] == 1)
        assert (row["active_leases"], row["pool_used"], row["pool_size"], row["utilization_pct"]) == (
            IN + OUT,
            IN,
            SIZE,
            80.0,
        )
        assert row["peak_30d"] == IN, "the high-water mark is pool use, not the whole subnet's 110"

    def test_5_reports(self, world, logged_in_client):
        alerts.take_lease_snapshot()
        page = logged_in_client.get("/reports?days=30").get_data(as_text=True)
        assert "80% of the pool used (80 of 100)" in page and "110%" not in page
        assert re.search(r"Free: <strong[^>]*>20</strong>", page)
        assert "Peak pool use (30d): <strong" in page

    def test_6_health_pool_utilization(self, world):
        alerts.take_lease_snapshot()
        check = health._pool_utilization({"subnet_filter": lambda sid: True})
        assert "80%" in check.detail and "110%" not in check.detail, check.detail

    def test_7_prometheus_ratio(self, world, client, metrics_opened):
        alerts.take_lease_snapshot()
        text = client.get("/metrics").get_data(as_text=True)
        ratio = next(
            x for x in text.splitlines() if x.startswith("jen_subnet_utilization_ratio{") and "10.92.0.0/16" in x
        )
        assert ratio.endswith(" 0.8000")

    def test_8_the_high_water_mark_and_the_forecast(self, world):
        alerts.take_lease_snapshot()
        rows = health.lease_history_window()[1]
        assert capacity.high_water(rows)["peak"] == IN
        f = capacity.forecast(rows)
        assert f["pool_size"] == SIZE and f["latest_peak"] == IN and f["pct_now"] == 80.0 and f["trend"] == "rising"

    def test_9_the_pool_forecast_alert(self, world, monkeypatch):
        sent = []
        monkeypatch.setattr(alerts, "send_alert", lambda t, *a, **kw: sent.append((t, kw)) or [("test", True, "")])
        alerts.take_lease_snapshot()
        alerts.check_pool_forecast_alerts()
        kw = next(kw for t, kw in sent if t == "pool_forecast")
        assert kw["peak"] == IN and kw["total"] == SIZE, "the alert's numbers are pool use, never the subnet's 110"


class TestRowsFromBeforeTheColumnAreNotReadings:
    @pytest.fixture
    def legacy(self, world, db):
        with db.cursor() as cur:
            cur.execute("UPDATE lease_history SET pool_used=NULL WHERE subnet_id=1")
        db.commit()

    def test_health_waits_for_a_snapshot_that_records_pool_use(self, legacy):
        check = health._pool_utilization({"subnet_filter": lambda sid: True})
        assert check.status == "skip" and "first snapshot that records pool use" in check.detail

    def test_the_forecast_says_insufficient_history_and_there_is_no_high_water(self, legacy):
        rows = health.lease_history_window()[1]
        assert capacity.forecast(rows)["trend"] == "insufficient" and capacity.high_water(rows) is None

    def test_prometheus_exports_the_pool_size_but_no_ratio(self, legacy, client, metrics_opened):
        text = client.get("/metrics").get_data(as_text=True)
        assert any(x.startswith("jen_subnet_pool_size{") and "10.92.0.0/16" in x for x in text.splitlines())
        assert not any(x.startswith("jen_subnet_utilization_ratio{") and "10.92.0.0/16" in x for x in text.splitlines())

    def test_reports_says_when_pool_use_starts(self, legacy, logged_in_client):
        page = logged_in_client.get("/reports?days=30").get_data(as_text=True)
        assert "Pool use is recorded from the first snapshot taken after the upgrade" in page

    def test_one_new_snapshot_makes_health_report_it(self, legacy):
        alerts.take_lease_snapshot()
        assert "80%" in health._pool_utilization({"subnet_filter": lambda sid: True}).detail

    def test_the_old_rows_are_never_backfilled(self, legacy, db):
        alerts.take_lease_snapshot()
        with jen_db() as jdb, jdb.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM lease_history WHERE subnet_id=1 AND pool_used IS NULL")
            assert cur.fetchone()["n"] == 8


class TestAnUnmeasuredPoolUseIsNeverReplacedByAnotherNumber:
    """v5.68.0-beta.20 (Q155, item 7): beta.19 left two fallbacks to the number it had removed. `capacity.used` read `active_leases` for a row with no
    `pool_used` KEY, and the dashboard showed `s.dynamic` under the pool-use label when `api_stats`' consumption pass failed (the key was simply
    left out). Pool use is now null until measured, the page says "unavailable", and no path puts anything else in its place."""

    def test_api_stats_says_null_when_the_consumption_pass_fails(self, world, logged_in_client, monkeypatch):
        from jen.services import pools

        def broken(cur, sid, defs):
            raise RuntimeError("kea database went away")

        monkeypatch.setattr(pools, "consumption", broken)
        data = logged_in_client.get("/api/stats").get_json()
        assert "pool_used" in data["subnets"]["1"] and data["subnets"]["1"]["pool_used"] is None
        assert data["pool_sizes"]["1"] == SIZE, "the pool size is still known; only the use is not"
        assert data["subnets"]["1"]["dynamic"] == IN + OUT, (
            "dynamic stays what it is (every lease here is dynamic) - a different number on a different question"
        )

    def test_api_stats_says_null_when_kea_s_config_cannot_be_read(self, world, logged_in_client, monkeypatch):
        failing = lambda command, *a, **kw: {"result": 1, "text": "unreachable", "arguments": {}}  # noqa: E731
        monkeypatch.setattr(kea_svc, "kea_command", failing)
        data = logged_in_client.get("/api/stats").get_json()
        assert data["subnets"]["1"]["pool_used"] is None

    def test_api_stats_reports_the_measured_value_when_it_works(self, world, logged_in_client):
        assert logged_in_client.get("/api/stats").get_json()["subnets"]["1"]["pool_used"] == IN

    def test_the_prometheus_ratio_is_omitted_for_a_subnet_with_no_measured_use(self, world, client, db, metrics_opened):
        with db.cursor() as cur:
            cur.execute("UPDATE lease_history SET pool_used=NULL WHERE subnet_id=1")
        db.commit()
        text = client.get("/metrics").get_data(as_text=True)
        assert 'jen_subnet_pool_size{subnet="A"' in text
        assert 'jen_subnet_utilization_ratio{subnet="A"' not in text, "no ratio is computed from anything else"


class TestNoPathReadsActiveLeasesAsPoolUse:
    def test_the_dashboard_script_has_no_dynamic_fallback_under_the_pool_use_label(self):
        import pathlib

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "dashboard.html").read_text(
            encoding="utf-8"
        )
        assert "s.pool_used !== undefined) ? s.pool_used : s.dynamic" not in html
        assert "pool use unavailable" in html and "usedUnknown" in html
        assert "totalDynamic / totalPool" not in html, "the totals widget's percentage is pool use too"

    def test_capacity_used_is_none_for_a_row_without_the_key(self):
        assert capacity.used({"active_leases": 99}) is None

    def test_no_source_line_feeds_active_leases_into_a_capacity_calculation(self):
        """The whole tree: `capacity.py` never names `active_leases` outside prose, and the history readers select pool_used beside it."""
        import ast
        import pathlib

        source = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "services" / "capacity.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        code_uses = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "active_leases"
        ]
        assert code_uses == [], "capacity.py reads the subnet's whole active count as a code value"
