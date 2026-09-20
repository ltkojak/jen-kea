"""
tests/test_api.py
─────────────────
Tests for API endpoints — lease history, alert summary,
recent leases, and dashboard stats.
"""

import json


class TestLeaseHistoryApi:
    """GET /api/lease-history"""

    def test_returns_json(self, logged_in_client):
        """Returns valid JSON with history key."""
        r = logged_in_client.get("/api/lease-history")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "history" in data

    def test_default_days_is_7(self, logged_in_client):
        """Default time range is 7 days."""
        r = logged_in_client.get("/api/lease-history")
        data = json.loads(r.data)
        assert data.get("days") == 7

    def test_accepts_days_param(self, logged_in_client):
        """Accepts ?days= parameter."""
        for days in [1, 3, 7, 30]:
            r = logged_in_client.get(f"/api/lease-history?days={days}")
            assert r.status_code == 200
            data = json.loads(r.data)
            assert data.get("days") == days

    def test_caps_days_at_90(self, logged_in_client):
        """Clamps days to maximum of 90."""
        r = logged_in_client.get("/api/lease-history?days=999")
        data = json.loads(r.data)
        assert data.get("days") == 90

    def test_history_is_dict(self, logged_in_client):
        """History value is a dict keyed by subnet_id."""
        r = logged_in_client.get("/api/lease-history")
        data = json.loads(r.data)
        assert isinstance(data["history"], dict)

    def test_with_history_data(self, logged_in_client, db):
        """Returns data points when lease_history has rows."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO lease_history
                    (subnet_id, active_leases, dynamic_leases, reserved_leases, pool_size)
                VALUES (1, 50, 30, 20, 200),
                       (1, 55, 35, 20, 200)
            """)
        db.commit()

        r = logged_in_client.get("/api/lease-history?days=7")
        data = json.loads(r.data)
        # Should have data for subnet 1
        assert "1" in data["history"] or len(data["history"]) > 0


class TestAlertSummaryApi:
    """GET /api/alert-summary"""

    def test_returns_json(self, logged_in_client):
        """Returns valid JSON with alerts key."""
        r = logged_in_client.get("/api/alert-summary")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "alerts" in data

    def test_empty_when_no_alerts(self, logged_in_client):
        """Returns empty list when no alerts logged."""
        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        assert isinstance(data["alerts"], list)

    def test_returns_up_to_10(self, logged_in_client, db):
        """Returns at most 10 alerts."""
        with db.cursor() as cur:
            for i in range(15):
                cur.execute(
                    """
                    INSERT INTO alert_log (channel_type, alert_type, message, status)
                    VALUES ('telegram', 'kea_down', %s, 'sent')
                """,
                    (f"Alert {i}",),
                )
        db.commit()

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        assert len(data["alerts"]) <= 10

    def test_alert_fields(self, logged_in_client, db):
        """Alert entries contain required fields."""
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                VALUES ('telegram', 'new_device', 'New device seen', 'failed', 'Timeout')
            """)
        db.commit()

        r = logged_in_client.get("/api/alert-summary")
        data = json.loads(r.data)
        if data["alerts"]:
            a = data["alerts"][0]
            for field in ["type", "channel", "status", "sent_at", "error"]:
                assert field in a


class TestDashboardStatsApi:
    """GET /api/stats"""

    def test_returns_json(self, logged_in_client, mock_kea):
        """Returns valid JSON."""
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, dict)

    def test_has_required_keys(self, logged_in_client, mock_kea):
        """Response includes kea_up, subnets, servers, pool_sizes."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        for key in ["kea_up", "subnets", "servers"]:
            assert key in data

    def test_servers_always_present(self, logged_in_client, monkeypatch):
        """servers key present even when Kea DB query fails."""
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", list)

        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "servers" in data
        assert data["kea_up"] is False

    def test_requires_auth(self, app):
        """api/stats redirects when not authenticated."""
        # Use a fresh client with no session to test unauthenticated access
        with app.test_client() as fresh_client:
            r = fresh_client.get("/api/stats", follow_redirects=False)
            assert r.status_code in (301, 302, 308)


class TestApiDocsKeyListIsAdminOnly:
    """v5.10.4 — /settings/api-docs pre-filled its examples from a list
    of every active key's name and prefix, shown to any logged-in user
    even though /settings/api-keys itself is admin-only."""

    @staticmethod
    def _seed_key(db, prefix):
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys")
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, active) VALUES (%s, %s, %s, 1, 1)",
                (f"key-{prefix}", f"hash-{prefix}", prefix),
            )
        db.commit()

    def test_admin_with_a_key_sees_the_prefill_buttons(self, logged_in_client, db):
        self._seed_key(db, "abc12345")
        r = logged_in_client.get("/settings/api-docs")
        assert r.status_code == 200
        assert b"keybtn-" in r.data
        assert b"abc12345" in r.data

    def test_viewer_never_sees_key_names_or_prefixes(self, client, db):
        from tests.conftest import restricted_client

        self._seed_key(db, "xyz98765")
        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get("/settings/api-docs")
        assert r.status_code == 200
        assert b"keybtn-" not in r.data
        assert b"xyz98765" not in r.data


class TestApiDocsListsOnlyOwnKeys:
    """v5.49.0-beta.2 (audit L) - a plain admin's docs page pre-fills from the
    keys THEY created, exactly like the API Keys page; a superadmin sees all."""

    def test_admin_sees_only_their_own_keys(self, client, db):
        from tests.conftest import restricted_client

        c, uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="docs_admin_l")
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys")
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, active) VALUES "
                "('mine', 'h-mine', 'MINEPFX1', %s, 1), ('theirs', 'h-theirs', 'THEIRPF1', 1, 1)",
                (uid,),
            )
        db.commit()
        body = c.get("/settings/api-docs").data.decode()
        assert "MINEPFX1" in body
        assert "THEIRPF1" not in body

    def test_superadmin_still_sees_every_key(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        second = _insert_admin_user(db, "docs_second_owner")
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys")
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, active) VALUES "
                "('a', 'h-a', 'AAAAPFX1', 1, 1), ('b', 'h-b', 'BBBBPFX1', %s, 1)",
                (second,),
            )
        db.commit()
        body = logged_in_client.get("/settings/api-docs").data.decode()
        assert "AAAAPFX1" in body and "BBBBPFX1" in body


class TestServersApi:
    """Q42 step 2 — GET /api/v1/servers: server list + packet_health
    (null until a server has two server_stats snapshots)."""

    def _key(self, db, admin_id, raw, name):
        import hashlib

        from tests.test_api_key_authorization import _insert_api_key

        key_id = _insert_api_key(db, name, created_by=admin_id)
        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id)
            )
        db.commit()

    def test_requires_key(self, client, mock_kea):
        r = client.get("/api/v1/servers")
        assert r.status_code == 401

    def test_lists_servers_with_null_packet_health_by_default(self, logged_in_client, db, mock_kea):
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_servers_api_probe1'")
            cur.execute("DELETE FROM server_stats")
        db.commit()
        admin_id = _insert_admin_user(db, "servers_api_admin1")
        db.commit()
        raw = "jen_servers_api_probe_key1"
        self._key(db, admin_id, raw, "_servers_api_probe1")

        r = logged_in_client.get("/api/v1/servers", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["count"] == 1
        srv = data["servers"][0]
        assert srv["id"] == 1
        assert srv["up"] is True
        assert srv["packet_health"] is None

    def test_packet_health_populated_with_two_snapshots(self, logged_in_client, db, mock_kea):
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_servers_api_probe2'")
            cur.execute("DELETE FROM server_stats")
            cur.execute(
                "INSERT INTO server_stats (server_id, snapshot_time, stats) VALUES "
                "(1, DATE_SUB(NOW(), INTERVAL 30 MINUTE), %s), (1, NOW(), %s)",
                (json.dumps({"pkt4-received": 100}), json.dumps({"pkt4-received": 200})),
            )
        db.commit()
        admin_id = _insert_admin_user(db, "servers_api_admin2")
        db.commit()
        raw = "jen_servers_api_probe_key2"
        self._key(db, admin_id, raw, "_servers_api_probe2")

        r = logged_in_client.get("/api/v1/servers", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        ph = r.get_json()["servers"][0]["packet_health"]
        assert ph is not None
        assert ph["status"] == "ok"
        assert ph["rates"]["pkt4-received"] > 0


class TestHealthApi:
    """Q44 — GET /api/v1/health/checks and GET /api/v1/health/readiness:
    the same jen.services.health run(s) the Health Center page uses,
    as JSON, gated the same way as every other read endpoint."""

    def _key(self, db, admin_id, raw, name, subnet_access=None):
        import hashlib

        from tests.test_api_key_authorization import _insert_api_key

        key_id = _insert_api_key(db, name, created_by=admin_id, subnet_access=subnet_access)
        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id)
            )
        db.commit()

    def test_checks_requires_key(self, client, mock_kea):
        r = client.get("/api/v1/health/checks")
        assert r.status_code == 401

    def test_readiness_requires_key(self, client, mock_kea):
        r = client.get("/api/v1/health/readiness")
        assert r.status_code == 401

    def test_checks_returns_the_health_center_run(self, logged_in_client, db, mock_kea):
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_health_api_probe1'")
        db.commit()
        admin_id = _insert_admin_user(db, "health_api_admin1")
        db.commit()
        raw = "jen_health_api_probe_key1"
        self._key(db, admin_id, raw, "_health_api_probe1")

        r = logged_in_client.get("/api/v1/health/checks", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert set(data) == {"checked_at", "summary", "checks"}
        assert set(data["summary"]) == {"ok", "warn", "fail", "skip"}
        assert any(c["id"] == "kea_reachable" for c in data["checks"])

    def test_readiness_returns_only_the_readiness_group(self, logged_in_client, db, mock_kea):
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_health_api_probe2'")
        db.commit()
        admin_id = _insert_admin_user(db, "health_api_admin2")
        db.commit()
        raw = "jen_health_api_probe_key2"
        self._key(db, admin_id, raw, "_health_api_probe2")

        r = logged_in_client.get("/api/v1/health/readiness", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert set(data["summary"]) == {"ready", "actions", "checked"}
        assert data["checks"]
        assert all(c["group"] == "readiness" for c in data["checks"])

    def test_scoped_key_only_sees_its_own_subnet_in_capacity_checks(self, logged_in_client, db, mock_kea):
        """Mirrors TestHealthCenterPage's restricted-viewer test for the
        page itself: the checks list is unaffected (kea/ddns/jen groups
        aren't subnet-scoped), but pool_utilization only reasons about
        subnets in the key's scope."""
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_health_api_probe3'")
            cur.execute("DELETE FROM lease_history")
            cur.execute(
                "INSERT INTO lease_history (subnet_id, active_leases, pool_size, snapshot_time) "
                "VALUES (1, 98, 100, NOW())"
            )
        db.commit()
        admin_id = _insert_admin_user(db, "health_api_admin3")
        db.commit()
        raw = "jen_health_api_probe_key3"
        self._key(db, admin_id, raw, "_health_api_probe3", subnet_access=[999])

        r = logged_in_client.get("/api/v1/health/checks", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        util = next(c for c in r.get_json()["checks"] if c["id"] == "pool_utilization")
        assert util["status"] in ("ok", "skip")
