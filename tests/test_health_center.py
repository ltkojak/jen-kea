"""
tests/test_health_center.py
───────────────────────────
v5.12.0 — the Health Center. Step 1 covers the check engine
(jen/services/health.py), kea.server_clock_offset, and the _endpoint_for
d2 branch. The page/route/nav/alert tests live further down (step 2/3).
"""

import http.server
import threading
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from jen import extensions
from jen.services import health
from jen.services import kea as kea_svc

# ── shared ctx builders ────────────────────────────────────────────────────


def _status(name="kea-a", up=True, ha_state=None, sid=1, role="primary"):
    return {"server": {"id": sid, "name": name, "role": role}, "up": up, "ha_state": ha_state, "version": "2.6.1"}


def _ctx(**over):
    base = {
        "server_status": [_status()],
        "active_server": {"id": 1, "name": "kea-a"},
        "dhcp4_config": {"subnet4": [], "hooks-libraries": []},
        "subnet_filter": lambda _sid: True,
    }
    base.update(over)
    return base


# ── kea_reachable ──────────────────────────────────────────────────────────


class TestKeaReachable:
    def test_all_up(self):
        c = health._kea_reachable(_ctx(server_status=[_status("kea-a"), _status("kea-b", sid=2)]))
        assert c.status == "ok" and "2/2" in c.detail

    def test_one_down(self):
        c = health._kea_reachable(_ctx(server_status=[_status("kea-a"), _status("kea-b", up=False, sid=2)]))
        assert c.status == "fail" and "kea-b" in c.detail

    def test_all_down(self):
        c = health._kea_reachable(_ctx(server_status=[_status(up=False)]))
        assert c.status == "fail"

    def test_no_status_at_all(self):
        c = health._kea_reachable(_ctx(server_status=[]))
        assert c.status == "fail"


# ── kea_version_supported ──────────────────────────────────────────────────


class TestKeaVersion:
    def test_ca_mode_kea_30_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        st = _status()
        st["version"] = "3.0.0"
        c = health._kea_version_supported(_ctx(server_status=[st]))
        assert c.status == "warn" and "deprecated" in c.detail

    def test_ca_mode_kea_32_fails(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        st = _status()
        st["version"] = "3.2.1"
        c = health._kea_version_supported(_ctx(server_status=[st]))
        assert c.status == "fail" and "removed" in c.detail

    def test_ca_mode_kea_26_ok(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        c = health._kea_version_supported(_ctx())
        assert c.status == "ok"

    def test_direct_mode_old_kea_fails(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        st = _status()
        st["version"] = "2.6.1"
        c = health._kea_version_supported(_ctx(server_status=[st]))
        assert c.status == "fail" and "2.7.2" in c.detail

    def test_no_version_skips(self):
        st = _status()
        st["version"] = ""
        c = health._kea_version_supported(_ctx(server_status=[st]))
        assert c.status == "skip"


# ── kea_ha_state ───────────────────────────────────────────────────────────


class TestKeaHaState:
    def test_non_ha_skips(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1}])
        c = health._kea_ha_state(_ctx())
        assert c.status == "skip"

    def test_healthy_pair_ok(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1}, {"id": 2}])
        monkeypatch.setattr(extensions, "cfg", _FakeCfg({"kea": {"ha_mode": "hot-standby"}}))
        ss = [_status("kea-a", ha_state="hot-standby"), _status("kea-b", sid=2, ha_state="hot-standby")]
        c = health._kea_ha_state(_ctx(server_status=ss))
        assert c.status == "ok"

    def test_partner_down_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1}, {"id": 2}])
        monkeypatch.setattr(extensions, "cfg", _FakeCfg({"kea": {"ha_mode": "hot-standby"}}))
        ss = [_status("kea-a", ha_state="partner-down"), _status("kea-b", sid=2, ha_state=None, up=False)]
        c = health._kea_ha_state(_ctx(server_status=ss))
        assert c.status == "warn" and "partner-down" in c.detail

    def test_terminated_fails(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1}, {"id": 2}])
        monkeypatch.setattr(extensions, "cfg", _FakeCfg({"kea": {"ha_mode": "hot-standby"}}))
        ss = [_status("kea-a", ha_state="terminated"), _status("kea-b", sid=2, ha_state="hot-standby")]
        c = health._kea_ha_state(_ctx(server_status=ss))
        assert c.status == "fail" and "kea-a" in c.detail


# ── kea_hooks ──────────────────────────────────────────────────────────────


class TestKeaHooks:
    def _cfg(self, libs):
        return {"hooks-libraries": [{"library": f"/usr/lib/kea/hooks/{n}"} for n in libs]}

    def test_all_present_ok(self):
        c = health._kea_hooks(_ctx(dhcp4_config=self._cfg(["libdhcp_host_cmds.so", "libdhcp_lease_cmds.so"])))
        assert c.status == "ok"

    def test_missing_host_cmds_fails_naming_it(self):
        c = health._kea_hooks(_ctx(dhcp4_config=self._cfg(["libdhcp_lease_cmds.so"])))
        assert c.status == "fail" and "libdhcp_host_cmds.so" in c.detail

    def test_no_config_skips(self):
        c = health._kea_hooks(_ctx(dhcp4_config=None))
        assert c.status == "skip"

    def test_ha_hook_required_when_ha(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1}, {"id": 2}])
        monkeypatch.setattr(extensions, "cfg", _FakeCfg({"kea": {"ha_mode": "hot-standby"}}))
        c = health._kea_hooks(_ctx(dhcp4_config=self._cfg(["libdhcp_host_cmds.so", "libdhcp_lease_cmds.so"])))
        assert c.status == "fail" and "libdhcp_ha.so" in c.detail


# ── kea_time_sync ──────────────────────────────────────────────────────────


class TestKeaTimeSync:
    def test_no_header_skips(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.server_clock_offset", lambda *a, **kw: None)
        c = health._kea_time_sync(_ctx())
        assert c.status == "skip"

    def test_small_offset_ok(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.server_clock_offset", lambda *a, **kw: 4.0)
        c = health._kea_time_sync(_ctx())
        assert c.status == "ok"

    def test_medium_offset_warns(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.server_clock_offset", lambda *a, **kw: -75.0)
        c = health._kea_time_sync(_ctx())
        assert c.status == "warn" and "behind" in c.detail

    def test_large_offset_fails(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.server_clock_offset", lambda *a, **kw: 900.0)
        c = health._kea_time_sync(_ctx())
        assert c.status == "fail"


# ── kea_config_drift ───────────────────────────────────────────────────────


class TestKeaConfigDrift:
    def test_no_drift_ok(self, monkeypatch):
        monkeypatch.setattr("jen.services.config_drift.check_config_drift", list)
        c = health._kea_config_drift(_ctx())
        assert c.status == "ok"

    def test_drift_warns(self, monkeypatch):
        monkeypatch.setattr(
            "jen.services.config_drift.check_config_drift",
            lambda: [{"message": "subnet 3 disagrees", "subnet_id": 3}],
        )
        c = health._kea_config_drift(_ctx())
        assert c.status == "warn" and "subnet 3 disagrees" in c.detail


# ── kea_subnets_declared ───────────────────────────────────────────────────


class TestKeaSubnetsDeclared:
    def test_all_named_ok(self, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN"}, 2: {"name": "IoT"}})
        cfg = {"subnet4": [{"id": 1}, {"id": 2}]}
        c = health._kea_subnets_declared(_ctx(dhcp4_config=cfg))
        assert c.status == "ok"

    def test_undeclared_kea_subnet_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN"}})
        cfg = {"subnet4": [{"id": 1}, {"id": 9}]}
        c = health._kea_subnets_declared(_ctx(dhcp4_config=cfg))
        assert c.status == "warn" and "9" in c.detail

    def test_orphaned_jen_subnet_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN"}, 7: {"name": "Old"}})
        cfg = {"subnet4": [{"id": 1}]}
        c = health._kea_subnets_declared(_ctx(dhcp4_config=cfg))
        assert c.status == "warn" and "7" in c.detail


# ── capacity ───────────────────────────────────────────────────────────────


class TestPoolUtilisation:
    def _seed(self, db, rows):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            for sid, active, size, mins_ago in rows:
                cur.execute(
                    "INSERT INTO lease_history (subnet_id, active_leases, pool_size, snapshot_time) "
                    "VALUES (%s, %s, %s, DATE_SUB(NOW(), INTERVAL %s MINUTE))",
                    (sid, active, size, mins_ago),
                )
        db.commit()

    def test_no_rows_skips(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        c = health._pool_utilisation(_ctx())
        assert c.status == "skip"

    def test_below_threshold_ok(self, db):
        self._seed(db, [(1, 10, 100, 5)])
        c = health._pool_utilisation(_ctx())
        assert c.status == "ok"

    def test_over_threshold_warns(self, db):
        self._seed(db, [(1, 85, 100, 5)])
        c = health._pool_utilisation(_ctx())
        assert c.status == "warn"

    def test_near_exhaustion_fails(self, db):
        self._seed(db, [(1, 98, 100, 5)])
        c = health._pool_utilisation(_ctx())
        assert c.status == "fail"

    def test_restricted_viewer_only_sees_own(self, db):
        self._seed(db, [(1, 98, 100, 5), (2, 10, 100, 5)])
        c = health._pool_utilisation(_ctx(subnet_filter=lambda sid: sid == 2))
        assert c.status == "ok"  # subnet 1 (the hot one) filtered out


class TestLeaseSnapshotFresh:
    def test_no_rows_skips(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        c = health._lease_snapshot_fresh(_ctx())
        assert c.status == "skip"

    def test_recent_ok(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            cur.execute("INSERT INTO lease_history (subnet_id, snapshot_time) VALUES (1, NOW())")
        db.commit()
        c = health._lease_snapshot_fresh(_ctx())
        assert c.status == "ok"

    def test_stale_warns(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            cur.execute(
                "INSERT INTO lease_history (subnet_id, snapshot_time) VALUES (1, DATE_SUB(NOW(), INTERVAL 180 MINUTE))"
            )
        db.commit()
        c = health._lease_snapshot_fresh(_ctx())
        assert c.status == "warn"


# ── ddns ───────────────────────────────────────────────────────────────────


class TestD2:
    def _cfg(self, enabled):
        return {"dhcp-ddns": {"enable-updates": enabled}}

    def test_skip_when_disabled(self):
        c = health._d2_reachable(_ctx(dhcp4_config=self._cfg(False)))
        assert c.status == "skip" and "disabled" in c.detail

    def test_skip_in_direct_mode(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        c = health._d2_reachable(_ctx(dhcp4_config=self._cfg(True)))
        assert c.status == "skip" and "direct" in c.detail

    def test_ok_when_d2_answers(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr("jen.services.kea.kea_command", lambda *a, **kw: {"result": 0, "text": "2.6.1"})
        c = health._d2_reachable(_ctx(dhcp4_config=self._cfg(True)))
        assert c.status == "ok"

    def test_warn_when_d2_silent(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr("jen.services.kea.kea_command", lambda *a, **kw: {"result": 1, "text": "no d2"})
        c = health._d2_reachable(_ctx(dhcp4_config=self._cfg(True)))
        assert c.status == "warn"

    def test_errors_counter_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(
            "jen.services.kea.kea_command",
            lambda *a, **kw: {"result": 0, "arguments": {"ncr-error": [[3, "t"]], "update-error": [[1, "t"]]}},
        )
        c = health._d2_errors(_ctx(dhcp4_config=self._cfg(True)))
        assert c.status == "warn" and "ncr-error=3" in c.detail

    def test_errors_zero_ok(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(
            "jen.services.kea.kea_command",
            lambda *a, **kw: {"result": 0, "arguments": {"ncr-error": [[0, "t"]]}},
        )
        c = health._d2_errors(_ctx(dhcp4_config=self._cfg(True)))
        assert c.status == "ok"


# ── jen ────────────────────────────────────────────────────────────────────


class TestCertExpiry:
    @pytest.mark.parametrize(
        "days,expected",
        [(40, "ok"), (20, "warn"), (5, "fail"), (-1, "fail"), (None, "skip")],
    )
    def test_thresholds(self, monkeypatch, days, expected):
        monkeypatch.setattr(health, "cert_days_left", lambda: days)
        c = health._cert_expiry(_ctx())
        assert c.status == expected


class TestSchemaCurrent:
    def test_current_ok(self, db):
        c = health._schema_current(_ctx())
        assert c.status == "ok"

    def test_behind_fails(self, db, monkeypatch):
        monkeypatch.setattr("jen.models.migrations.latest_version", lambda: 9999)
        c = health._schema_current(_ctx())
        assert c.status == "fail" and "9999" in c.detail


class TestDbChecks:
    def test_jen_ok(self, db):
        assert health._db_jen(_ctx()).status == "ok"

    def test_kea_ok(self, db):
        assert health._db_kea(_ctx()).status == "ok"


class TestHelperInstalled:
    def test_no_ssh_skips(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a"}])
        c = health._helper_installed(_ctx())
        assert c.status == "skip"

    def test_recorded_ok(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        monkeypatch.setattr("jen.services.kea_host.helper_status", lambda: {"1": {"version": 1}})
        c = health._helper_installed(_ctx())
        assert c.status == "ok"

    def test_missing_warns(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        monkeypatch.setattr("jen.services.kea_host.helper_status", dict)
        c = health._helper_installed(_ctx())
        assert c.status == "warn" and "kea-a" in c.detail


class TestBackgroundWorkers:
    def test_none_skips(self, monkeypatch):
        monkeypatch.setattr("jen.services.background.STARTED_AT", None)
        c = health._background_workers(_ctx())
        assert c.status == "skip"

    def test_set_ok(self, monkeypatch):
        monkeypatch.setattr("jen.services.background.STARTED_AT", datetime.now(timezone.utc) - timedelta(hours=2))
        c = health._background_workers(_ctx())
        assert c.status == "ok"


class TestUpdateAvailable:
    def test_always_skips_no_network(self):
        c = health._update_available(_ctx())
        assert c.status == "skip"


# ── run_checks resilience ──────────────────────────────────────────────────


class TestRunChecks:
    def test_a_raising_check_becomes_fail_and_the_rest_run(self, monkeypatch, mock_kea, db):
        boom = list(health._CHECKS)

        def _explode(_ctx):
            raise RuntimeError("kaboom")

        boom[0] = _explode
        monkeypatch.setattr(health, "_CHECKS", boom)
        checks = health.run_checks(_ctx())
        by_id = {c.id: c for c in checks}
        assert by_id["kea_reachable"].status == "fail"
        assert "kaboom" in by_id["kea_reachable"].detail
        assert len(checks) == len(health.CHECK_IDS)

    def test_every_id_present_and_grouped(self, mock_kea, db):
        checks = health.run_checks(_ctx())
        assert [c.id for c in checks] == health.CHECK_IDS
        assert all(c.group in health.GROUP_ORDER for c in checks)

    def test_summarise(self):
        checks = [health.Check("a", "A", "jen", "ok"), health.Check("b", "B", "jen", "warn")]
        assert health.summarise(checks) == {"ok": 1, "warn": 1, "fail": 0, "skip": 0}


# ── kea.server_clock_offset against a real local server ─────────────────────


class _DateHandler(http.server.BaseHTTPRequestHandler):
    date_offset_s = 0  # class attr set per test
    send_date = True

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = b'{"result":0,"arguments":{"extended":"3.0.0"}}'
        # send_response_only, not send_response: the latter auto-adds its
        # own current-time Date header, which would mask the one we set.
        self.send_response_only(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if type(self).send_date:
            when = datetime.now(timezone.utc) + timedelta(seconds=type(self).date_offset_s)
            self.send_header("Date", format_datetime(when, usegmt=True))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def date_server(monkeypatch):
    servers = []

    def _start(offset_s=0, with_date=True):
        handler = type("H", (_DateHandler,), {"date_offset_s": offset_s, "send_date": with_date})
        httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        servers.append(httpd)
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        monkeypatch.setattr(extensions, "KEA_API_URL", url)
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        return url

    yield _start
    for s in servers:
        s.shutdown()


class TestServerClockOffset:
    def test_offset_from_date_header(self, date_server):
        date_server(offset_s=-120)
        off = kea_svc.server_clock_offset()
        assert off is not None and -125 < off < -115

    def test_in_sync(self, date_server):
        date_server(offset_s=0)
        off = kea_svc.server_clock_offset()
        assert off is not None and abs(off) < 5

    def test_no_date_header_returns_none(self, date_server):
        date_server(with_date=False)
        assert kea_svc.server_clock_offset() is None

    def test_unreachable_returns_none(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://127.0.0.1:1")
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        assert kea_svc.server_clock_offset() is None


# ── _endpoint_for d2 branch ────────────────────────────────────────────────


class TestEndpointForD2:
    def test_ca_mode_uses_v4_endpoint(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u4")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p4")
        assert kea_svc._endpoint_for(None, "d2") == ("http://kea:8000", "u4", "p4")

    def test_ca_mode_per_server(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        srv = {"api_url": "http://kea-b:8000", "api_user": "ub", "api_pass": "pb"}
        assert kea_svc._endpoint_for(srv, "d2") == ("http://kea-b:8000", "ub", "pb")

    def test_direct_mode_returns_error_dict(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        r = kea_svc._endpoint_for(None, "d2")
        assert isinstance(r, dict) and r["result"] == 1 and "[d2] api_url" in r["text"]

    def test_kea_command_d2_posts_service_d2_in_ca(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")

        calls = []

        class _Fake:
            import requests as _r

            exceptions = _r.exceptions

            def post(self, url, json=None, **kw):
                calls.append(json)

                class _R:
                    status_code = 200

                    def raise_for_status(self):
                        pass

                    def json(self):
                        return {"result": 0}

                return _R()

        monkeypatch.setattr(kea_svc, "http", _Fake())
        kea_svc.kea_command("version-get", service="d2")
        assert calls[0] == {"command": "version-get", "service": ["d2"]}


# ── small fake configparser for ha_mode ────────────────────────────────────


class _FakeCfg:
    def __init__(self, data):
        self.data = data

    def get(self, section, key, fallback=""):
        return self.data.get(section, {}).get(key, fallback)

    def has_section(self, section):
        return section in self.data


# ── the page, the JSON twin, the partial (step 2) ──────────────────────────


def _check_status(payload: dict, check_id: str) -> str:
    return next(c["status"] for c in payload["checks"] if c["id"] == check_id)


class TestHealthCenterPage:
    def test_page_renders_for_superadmin(self, logged_in_client, mock_kea, db):
        r = logged_in_client.get("/health-center")
        assert r.status_code == 200
        body = r.data.decode()
        for cid in health.CHECK_IDS:
            assert f'data-check="{cid}"' in body, cid

    def test_page_renders_for_plain_admin_and_viewer(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        for role in ("admin", "viewer"):
            c, _uid = restricted_client(client, db, allowed_subnets=None, role=role, username=f"hc_{role}")
            assert c.get("/health-center").status_code == 200

    def test_json_twin_shape(self, logged_in_client, mock_kea, db):
        data = logged_in_client.get("/health-center/data").get_json()
        assert set(data) == {"checked_at", "summary", "checks"}
        assert set(data["summary"]) == {"ok", "warn", "fail", "skip"}
        assert [c["id"] for c in data["checks"]] == health.CHECK_IDS
        assert all({"id", "title", "group", "status", "detail"} <= set(c) for c in data["checks"])

    def test_partial_is_not_a_full_page(self, logged_in_client, mock_kea, db):
        r = logged_in_client.get("/health-center/data?partial=1")
        assert r.status_code == 200
        body = r.data.decode()
        assert "<html" not in body.lower()
        assert 'data-check="db_jen"' in body

    def test_login_required(self, client, db):
        r = client.get("/health-center", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_restricted_viewer_capacity_is_scoped(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            cur.execute(
                "INSERT INTO lease_history (subnet_id, active_leases, pool_size, snapshot_time) "
                "VALUES (1, 98, 100, NOW()), (2, 5, 100, NOW())"
            )
        db.commit()

        full, _u1 = restricted_client(client, db, allowed_subnets=None, role="admin", username="hc_full")
        assert _check_status(full.get("/health-center/data").get_json(), "pool_utilisation") == "fail"

        scoped, _u2 = restricted_client(client, db, allowed_subnets=[2], role="viewer", username="hc_scoped")
        assert _check_status(scoped.get("/health-center/data").get_json(), "pool_utilisation") == "ok"


class TestHealthNav:
    def test_health_in_network_strip(self):
        from jen.routes.settings import nav as navmod

        assert "Health" in [t["label"] for t in navmod.SECTION_STRIPS["network"]]

    def test_health_activates_network_and_its_strip_item(self):
        from jen.routes.settings import nav as navmod

        ctx = navmod.nav_context("health.health_center", "viewer")
        assert [i for i in ctx["top"] if i["active"]][0]["id"] == "network"
        assert [t["label"] for t in ctx["strip"] if t["active"]] == ["Health"]
