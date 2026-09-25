"""
tests/test_servers.py
──────────────────────
servers.py had no dedicated test coverage before this — flagged in the
Jen maturity roadmap (Tier 1) as one of the files where real bugs were
found without any test having caught them (the StrictHostKeyChecking=no
gap, fixed in v4.4.8, lived in this exact file). Covers the auth
boundary on both routes and the restart route's error-handling paths
without ever actually invoking a real SSH connection.
"""

import json

from tests.conftest import restricted_client as _restricted_client


class TestServersPageAuth:
    def test_requires_login(self, client):
        r = client.get("/servers", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()

    def test_loads_for_logged_in_user(self, logged_in_client, mock_kea):
        r = logged_in_client.get("/servers")
        assert r.status_code == 200


class TestRestartRouteAuth:
    def test_requires_login(self, client):
        r = client.post("/servers/restart/1", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()

    def test_forbidden_for_viewer(self, client, db):
        _restricted_client(client, db, allowed_subnets=None, role="viewer", username="servers_viewer1")
        r = client.post("/servers/restart/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"admin access required" in r.data.lower()


class TestRestartRouteBehavior:
    """v5.11.0 — the restart goes through jen.services.kea_host.service_action
    (helper op `service` / legacy dual-name systemctl). It's stubbed here;
    the dual-name-unit handling itself is covered in test_kea_helper.py and
    test_kea_host.py."""

    _SERVER = {
        "id": 1,
        "name": "Test Kea",
        "ssh_host": "10.0.0.5",
        "ssh_user": "kea",
        "api_url": "http://localhost:18000",
        "api_user": "test",
        "api_pass": "test",
        "kea_conf": "",
        "role": "primary",
    }

    def _stub(self, monkeypatch, result=None):
        from jen.services import kea_host

        calls = []
        monkeypatch.setattr(
            kea_host,
            "service_action",
            lambda srv, svc, act: (calls.append((srv.get("name"), svc, act)), result or {"ok": True, "code": "ok"})[1],
        )
        return calls

    def test_nonexistent_server_id(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(self._SERVER)])
        calls = self._stub(monkeypatch)
        r = logged_in_client.post("/servers/restart/999", follow_redirects=True)
        assert r.status_code == 200
        assert b"not found" in r.data.lower()
        assert calls == []

    def test_server_without_ssh_configured(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(self._SERVER, ssh_host="", ssh_user="")])
        calls = self._stub(monkeypatch)
        r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"ssh not configured" in r.data.lower()
        assert calls == []

    def test_successful_restart_delegates_to_kea_host(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(self._SERVER)])
        calls = self._stub(monkeypatch, {"ok": True, "code": "ok", "unit": "kea-dhcp4-server"})
        r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"restarted" in r.data.lower()
        assert calls == [("Test Kea", "dhcp4", "restart")]

    def test_failed_restart_shows_the_detail_not_a_traceback(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(self._SERVER)])
        self._stub(monkeypatch, {"ok": False, "code": "error", "detail": "Permission denied"})
        r = logged_in_client.post("/servers/restart/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"failed" in r.data.lower()
        assert b"Permission denied" in r.data


class TestHaStatusDerivation:
    """v4.4.17: this whole class exists because a first draft of the
    active/degraded derivation logic was wrong on the most common real
    case (healthy hot-standby) — caught only by actually running it
    against realistic scenarios before shipping, not by inspection.
    These tests go through the real /servers route end to end, not the
    derivation logic in isolation, so a future regression in how the
    route wires kea.get_all_server_status() into the template would
    also be caught here."""

    def _servers_config(self):
        return [
            {
                "id": 1,
                "name": "Primary",
                "ssh_host": "",
                "ssh_user": "",
                "api_url": "http://localhost:18000",
                "api_user": "test",
                "api_pass": "test",
                "kea_conf": "",
                "role": "primary",
            },
            {
                "id": 2,
                "name": "Standby",
                "ssh_host": "",
                "ssh_user": "",
                "api_url": "http://localhost:18001",
                "api_user": "test",
                "api_pass": "test",
                "kea_conf": "",
                "role": "standby",
            },
        ]

    def test_healthy_hot_standby_only_primary_is_active(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(
            extensions.cfg,
            "get",
            lambda section, key, fallback=None: "hot-standby" if (section, key) == ("kea", "ha_mode") else fallback,
        )
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {
                    "server": cfg[0],
                    "up": True,
                    "ha_state": "hot-standby",
                    "ha_partner": "hot-standby",
                    "version": "2.4.0",
                },
                {
                    "server": cfg[1],
                    "up": True,
                    "ha_state": "hot-standby",
                    "ha_partner": "hot-standby",
                    "version": "2.4.0",
                },
            ],
        )
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        # Only Primary should carry the ACTIVE marker, not both.
        assert r.data.count(b"ACTIVE") == 1
        assert b"no working backup" not in r.data.lower()

    def test_primary_down_standby_active_and_degraded_warning_shown(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(
            extensions.cfg,
            "get",
            lambda section, key, fallback=None: "hot-standby" if (section, key) == ("kea", "ha_mode") else fallback,
        )
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {"server": cfg[0], "up": False, "ha_state": None, "ha_partner": None, "version": ""},
                {
                    "server": cfg[1],
                    "up": True,
                    "ha_state": "partner-down",
                    "ha_partner": "unavailable",
                    "version": "2.4.0",
                },
            ],
        )
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert b"no working backup" in r.data.lower()
        assert r.data.count(b"ACTIVE") == 1  # Standby, not Primary

    def test_load_balancing_both_active_no_warning(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        cfg = self._servers_config()
        monkeypatch.setattr(extensions, "KEA_SERVERS", cfg)
        monkeypatch.setattr(
            extensions.cfg,
            "get",
            lambda section, key, fallback=None: "load-balancing" if (section, key) == ("kea", "ha_mode") else fallback,
        )
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {
                    "server": cfg[0],
                    "up": True,
                    "ha_state": "load-balancing",
                    "ha_partner": "load-balancing",
                    "version": "2.4.0",
                },
                {
                    "server": cfg[1],
                    "up": True,
                    "ha_state": "load-balancing",
                    "ha_partner": "load-balancing",
                    "version": "2.4.0",
                },
            ],
        )
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "", "arguments": {}})

        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert r.data.count(b"ACTIVE") == 2
        assert b"no working backup" not in r.data.lower()


class TestPacketHealthOnServersPage:
    """Q42 step 2 — the Servers page's "Packet health" block, backed by
    server_stats (migration 26 / alerts.take_server_stats_snapshot)."""

    def _insert(self, db, minutes_ago, stats):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO server_stats (server_id, snapshot_time, stats) "
                "VALUES (1, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s)",
                (minutes_ago, json.dumps(stats)),
            )
        db.commit()

    def test_collecting_message_with_no_snapshots(self, logged_in_client, mock_kea, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        r = logged_in_client.get("/servers")
        assert r.status_code == 200
        assert b"collecting" in r.data.lower()

    def test_shows_rates_with_two_snapshots(self, logged_in_client, mock_kea, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._insert(db, 30, {"pkt4-received": 100, "pkt4-ack-sent": 90})
        self._insert(db, 0, {"pkt4-received": 200, "pkt4-ack-sent": 180})
        r = logged_in_client.get("/servers")
        body = r.data.decode()
        assert "Packet health" in body
        assert "Received" in body

    def test_fail_status_and_all_counters_table_shown(self, logged_in_client, mock_kea, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._insert(db, 30, {"pkt4-received": 100, "pkt4-receive-drop": 0, "pkt4-unknown-received": 1})
        self._insert(db, 0, {"pkt4-received": 200, "pkt4-receive-drop": 50, "pkt4-unknown-received": 4})
        r = logged_in_client.get("/servers")
        body = r.data.decode()
        assert "Fail" in body
        # pkt4-unknown-received isn't one of the named rate rows — it must
        # still surface, in the "all counters" table, so a counter no one
        # has named yet doesn't get silently dropped.
        assert "pkt4-unknown-received" in body


class TestPacketHealthForServer:
    """Unit coverage for jen.routes.servers._packet_health_for_server —
    the route-level query/shape function the block above renders."""

    def _insert(self, db, minutes_ago, stats):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO server_stats (server_id, snapshot_time, stats) "
                "VALUES (1, DATE_SUB(NOW(), INTERVAL %s MINUTE), %s)",
                (minutes_ago, json.dumps(stats)),
            )
        db.commit()

    def test_none_with_fewer_than_two_snapshots(self, db):
        from jen.routes.servers import _packet_health_for_server

        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        assert _packet_health_for_server(1) is None
        self._insert(db, 0, {"pkt4-received": 10})
        assert _packet_health_for_server(1) is None

    def test_named_and_other_counters_split(self, db):
        from jen.routes.servers import _packet_health_for_server

        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._insert(db, 30, {"pkt4-received": 100, "pkt4-ack-sent": 90, "pkt4-unknown-received": 0})
        self._insert(db, 0, {"pkt4-received": 200, "pkt4-ack-sent": 180, "pkt4-unknown-received": 3})

        ph = _packet_health_for_server(1)
        assert ph is not None
        assert ph["status"] == "ok"
        named_labels = {n["label"] for n in ph["named"]}
        assert {"Received", "Acked", "Offered", "Naked", "Dropped", "Parse failed", "Allocation failed"} <= named_labels
        assert ("pkt4-unknown-received", 3) in ph["other_counters"]
        assert len(ph["sparkline"]) == 1

    def test_kea_3_2_drop_reasons_are_named_only_when_reported(self, db):
        """v5.49.0-beta.3 (Q52) - the names are the ones read from the
        kea-compat run's 3.2.0 artifact; a server that doesn't report them
        (3.0) gets no row of zeros."""
        from jen.routes.servers import _packet_health_for_server

        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._insert(db, 30, {"pkt4-received": 100, "pkt4-duplicate": 0})
        self._insert(db, 0, {"pkt4-received": 200, "pkt4-duplicate": 3})
        ph = _packet_health_for_server(1)
        assert {"label": "Duplicate packet", "key": "pkt4-duplicate", "total": 3} in ph["named"]
        assert ("pkt4-duplicate", 3) not in ph["other_counters"]

        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        self._insert(db, 30, {"pkt4-received": 100})
        self._insert(db, 0, {"pkt4-received": 200})
        ph = _packet_health_for_server(1)
        assert "Duplicate packet" not in {n["label"] for n in ph["named"]}


class TestChangesetAttentionBanner:
    """v5.65.1 (Q90) - a rolled-back / failed-rollback change set stays on the Servers page
    until an admin dismisses it."""

    def _set(self, db, value):
        from jen.models.user import set_global_setting

        set_global_setting("changeset_attention", value)

    def test_no_banner_by_default(self, logged_in_client, mock_kea, db):
        self._set(db, "")
        assert b"could not be rolled back cleanly" not in logged_in_client.get("/servers").data

    def test_rollback_failed_banner_names_the_servers(self, logged_in_client, mock_kea, db):
        self._set(
            db,
            json.dumps(
                {
                    "status": "rollback_failed",
                    "summary": "add a pool",
                    "at": "2026-09-25T10:00:00+00:00",
                    "needs_hands": ["kea-b"],
                    "failed_restart": ["kea-b"],
                    "lines": ["boom from kea-b"],
                }
            ),
        )
        body = logged_in_client.get("/servers").data.decode()
        assert "could not be rolled back cleanly" in body
        assert "kea-b" in body and "add a pool" in body and "boom from kea-b" in body

    def test_rolled_back_banner_says_nothing_was_changed(self, logged_in_client, mock_kea, db):
        self._set(
            db,
            json.dumps({"status": "rolled_back", "summary": "s", "at": "t", "failed_restart": ["kea-a"], "lines": []}),
        )
        body = logged_in_client.get("/servers").data.decode()
        assert "was rolled back" in body and "Nothing was changed" in body

    def test_dismiss_clears_it(self, logged_in_client, mock_kea, db):
        self._set(
            db, json.dumps({"status": "rolled_back", "summary": "s", "at": "t", "failed_restart": [], "lines": []})
        )
        r = logged_in_client.post("/servers/changeset-attention/dismiss", follow_redirects=True)
        assert r.status_code == 200 and b"was rolled back" not in r.data

    def test_dismiss_needs_login(self, client):
        r = client.post("/servers/changeset-attention/dismiss", follow_redirects=False)
        assert r.status_code in (301, 302, 308) and "login" in r.headers.get("Location", "").lower()
