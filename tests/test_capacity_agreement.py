"""
tests/test_capacity_agreement.py
────────────────────────────────
v5.68.0-beta.18 (Q153) - every capacity number comes from one place. One seeded subnet with TWO pool ranges (50 + 60 addresses) and one
CIDR pool (64): the snapshot, `lease_history`, the forecast, Health, the dashboard's live stats, the REST API, Prometheus and the alert
loop must all say 174 - and agree on what is consumed. (Pool size was computed four ways: the last pool won, a CIDR pool was skipped, a
sum that still skipped CIDR, and a whole-subnet count compared with each pool in turn.)
"""

import pytest

from jen import extensions
from jen.models.db import jen_db
from jen.services import alerts, capacity
from jen.services import kea as kea_svc

POOLS = [
    {"pool": "10.91.0.10 - 10.91.0.59"},  # 50
    {"pool": "10.91.0.100-10.91.0.159"},  # 60
    {"pool": "10.91.1.0/26"},  # 64
]
SIZE = 174
IN_POOL_ACTIVE = 12
CONFIG = {"subnet4": [{"id": 1, "subnet": "10.91.0.0/16", "pools": POOLS}]}


def _ip(text):
    import ipaddress

    return int(ipaddress.IPv4Address(text))


@pytest.fixture
def subnet(db, monkeypatch, mock_kea):
    """Subnet 1 with the three pools; 8 active leases in the ranges, 4 in the CIDR pool, an EXPIRED one in a range, and one active
    lease OUTSIDE every pool (a reservation's address)... which the history keeps as an active lease but no pool consumes."""
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.91.0.0/16"}})
    monkeypatch.setattr(
        kea_svc,
        "kea_command",
        lambda command, *a, **kw: (
            {"result": 0, "text": "ok", "arguments": {"Dhcp4": CONFIG}}
            if command == "config-get"
            else {"result": 0, "text": "ok", "arguments": {}}
        ),
    )
    # jen.routes.api imported kea_command BY NAME, so the module attribute patch above does not reach it
    monkeypatch.setattr("jen.routes.api.kea_command", kea_svc.kea_command)
    _wipe(db)
    with db.cursor() as cur:
        rows = [(_ip("10.91.0.10") + i, "A") for i in range(5)] + [(_ip("10.91.0.100") + i, "A") for i in range(3)]
        rows += [(_ip("10.91.1.0") + i, "A") for i in range(4)]
        for n, (address, _x) in enumerate(rows):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (%s, UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (address, f"AABB9100{n:04X}"),
            )
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
            "VALUES (%s, UNHEX('AABB91009999'), 3600, DATE_SUB(NOW(), INTERVAL 1 HOUR), 1, 0)",
            (_ip("10.91.0.30"),),
        )
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
    db.commit()
    yield
    _wipe(db)
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
    db.commit()


def _wipe(db):
    """Subnet 1's totals count EVERY lease of the subnet, so a lease another test left behind would be counted too: start from none."""
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM lease4 WHERE subnet_id=1 OR address BETWEEN INET_ATON('10.91.0.0') AND INET_ATON('10.91.255.255')"
        )
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


class TestOneNumberEverywhere:
    def test_the_snapshot_stores_the_total_of_every_pool(self, subnet):
        alerts.take_lease_snapshot()
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT pool_size, active_leases FROM lease_history WHERE subnet_id=1 ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row["pool_size"] == SIZE, "50 + 60 + 64: not the last pool's size, and the CIDR pool is counted"
        assert row["active_leases"] == IN_POOL_ACTIVE, "the expired row is not an active lease"

    def test_the_forecast_health_and_prometheus_read_the_same_size_back(self, subnet, client, metrics_opened):
        from jen.services import health

        alerts.take_lease_snapshot()
        window = health.lease_history_window()
        assert capacity.current_pool_size(window[1]) == SIZE
        assert capacity.forecast(window[1])["pool_size"] == SIZE
        text = client.get("/metrics").get_data(as_text=True)
        line = next(x for x in text.splitlines() if x.startswith("jen_subnet_pool_size{") and "10.91.0.0/16" in x)
        assert line.endswith(f" {SIZE}")

    def test_the_dashboards_live_stats(self, subnet, logged_in_client):
        data = logged_in_client.get("/api/stats").get_json()
        assert data["pool_sizes"]["1"] == SIZE
        assert data["subnets"]["1"]["pool_used"] == IN_POOL_ACTIVE

    def test_the_rest_api(self, subnet, client, db):
        import hashlib

        raw = "q153-capacity-key-0123456789ab"
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            owner = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) VALUES (%s, %s, %s, %s, NULL, 1)",
                ("q153cap", hashlib.sha256(raw.encode()).hexdigest(), raw[:8], owner),
            )
        db.commit()
        data = client.get("/api/v1/subnets", headers={"Authorization": f"Bearer {raw}"}).get_json()
        row = next(s for s in data["subnets"] if s["id"] == 1)
        assert row["pool_size"] == SIZE and row["pool_used"] == IN_POOL_ACTIVE
        assert row["pools"] == ["10.91.0.10 - 10.91.0.59", "10.91.0.100-10.91.0.159", "10.91.1.0/26"], (
            "the CIDR pool is listed too"
        )
        assert row["utilization_pct"] == round(IN_POOL_ACTIVE / SIZE * 100, 1)

    def test_the_alert_loop_judges_the_same_capacity_and_consumption(self, subnet, db, monkeypatch):
        sent = []
        monkeypatch.setattr(alerts, "send_alert", lambda t, *a, **kw: sent.append((t, kw)) or [("test", True, "")])
        from jen.models.user import set_global_setting

        set_global_setting("alert_threshold_pct", "5")  # 12 / 174 = 7 %: over this line
        with db.cursor() as cur:
            alerts.check_utilization_alerts(cur, CONFIG)
        high = next(kw for t, kw in sent if t == "utilization_high")
        assert (high["used"], high["total"], high["pct"]) == (IN_POOL_ACTIVE, SIZE, 7)

    def test_an_active_lease_outside_every_pool_is_active_but_consumes_nothing(self, subnet, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state) "
                "VALUES (%s, UNHEX('AABB91008888'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0)",
                (_ip("10.91.0.200"),),
            )
        db.commit()
        from jen.services import pools

        with db.cursor() as cur:
            assert pools.consumption(cur, 1, POOLS) == IN_POOL_ACTIVE, "the reservation's address is outside every pool"
            cur.execute("SELECT COUNT(*) AS n FROM lease4 WHERE state = 0 AND expire > NOW() AND subnet_id=1")
            assert cur.fetchone()["n"] == IN_POOL_ACTIVE + 1, "...but it is an active lease"
