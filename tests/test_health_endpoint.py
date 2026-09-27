"""
tests/test_health_endpoint.py
──────────────────────────────
v5.65.6 (Q95) — /api/v1/health answers from Jen alone.

The self-updater confirms the running version by polling this endpoint with a 5-second
timeout, and the restore's health poll does the same. It used to call Kea live, twice, each up
to the Kea API timeout, so with Kea unreachable (a condition Jen is meant to survive) it took
~20 s, read as "Jen is not up", and rolled a HEALTHY update or restore back. Now it never calls
Kea; /api/v1/health/kea keeps the live probe, behind an API key.

v5.65.12 (Q101 a) — the public body was trimmed to `jen_version` alone. Kea's up/version/
checked-at state and the subnet count (added 5.65.6, narrowed from a per-server list in 5.65.10)
were reconnaissance for no benefit: every real consumer of this route reads `jen_version` only.
Both moved to the key-gated /api/v1/health/kea, already cached there.
"""

import hashlib
import secrets
import time
from unittest.mock import patch

import pytest

from jen.services import kea as kea_service


@pytest.fixture(autouse=True)
def _clean_cache():
    kea_service._HEALTH_CACHE.clear()
    yield
    kea_service._HEALTH_CACHE.clear()


def _slow(*_a, **_k):
    time.sleep(5)
    return {"result": 0, "arguments": {"extended": "3.0.0"}}


class TestHealthNeverWaitsOnKea:
    def test_returns_in_under_a_second_when_every_kea_call_would_take_five(self, client):
        with (
            patch("jen.routes.api.probe_kea_health", side_effect=_slow),
            patch("jen.routes.api.kea_command", side_effect=_slow),
            patch("jen.services.kea.kea_command", side_effect=_slow),
            patch("jen.services.kea.probe_kea_health", side_effect=_slow),
        ):
            started = time.monotonic()
            r = client.get("/api/v1/health")
            elapsed = time.monotonic() - started
        assert r.status_code == 200
        assert elapsed < 1.0, f"/api/v1/health took {elapsed:.1f}s - it must not call Kea"

    def test_the_route_never_imports_a_live_probe_into_its_path(self):
        import inspect

        from jen.routes import api

        src = inspect.getsource(api.api_v1_health)
        assert "kea_is_up" not in src and "kea_command" not in src and "probe_kea_health" not in src

    def test_the_public_body_is_jen_version_and_nothing_else(self, client):
        """v5.65.12 (Q101 a): Kea's up/version/checked-at state and the subnet count moved to the
        key-gated /api/v1/health/kea - reconnaissance for no benefit to a caller with no key, and
        every real consumer (the updater, the restore poll, the system suite) reads jen_version
        only. This is unconditional: a probe having run makes no difference to this route."""
        data = client.get("/api/v1/health").get_json()
        assert set(data) == {"jen_version"}
        assert data["jen_version"]
        with patch(
            "jen.services.kea.kea_command",
            return_value={"result": 0, "arguments": {"extended": "3.0.1\nlong text"}},
        ):
            assert kea_service.kea_is_up() is True
        data = client.get("/api/v1/health").get_json()
        assert set(data) == {"jen_version"}, "a Kea probe having run must not add fields to the public body"


class TestLiveProbeIsSeparateAndKeyed:
    def _key(self, db):
        raw = "jen_" + secrets.token_hex(20)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) "
                "VALUES (%s, %s, %s, 1, NULL, 1)",
                ("health-kea-test", hashlib.sha256(raw.encode()).hexdigest(), raw[:8]),
            )
        db.commit()
        return raw

    def test_it_needs_an_api_key(self, client):
        assert client.get("/api/v1/health/kea").status_code == 401

    def test_it_probes_kea_live_once(self, client, db):
        raw = self._key(db)
        entry = {"up": True, "version": "3.2.0", "at": time.time()}
        with patch("jen.routes.api.probe_kea_health", return_value=entry) as probe:
            r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["kea_up"] is True and body["kea_version"] == "3.2.0" and body["kea_checked_at"]
        assert "server" in body and isinstance(body["servers"], list)
        assert probe.call_count == 1

    def test_the_probe_is_exactly_one_kea_call(self, client, db):
        """v5.65.10 (Q99 b): it was kea_is_up (a version-get) and then a second version-get."""
        raw = self._key(db)
        calls = []

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append((cmd, server))
            return {"result": 0, "arguments": {"extended": "3.0.9"}}

        with patch("jen.services.kea.kea_command", side_effect=fake_command):
            r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.get_json()["kea_version"] == "3.0.9"
        assert len(calls) == 1 and calls[0][0] == "version-get", calls

    def test_it_probes_the_active_server_not_the_primary_and_runs_no_election(self, client, db):
        raw = self._key(db)
        second = {"id": 2, "name": "kea-b", "api_url": "http://kea-b:8000/"}
        calls = []

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append((cmd, server))
            return {"result": 0, "arguments": {"extended": "3.0.9"}}

        with (
            patch("jen.routes.api.cached_active_server", return_value=second),
            patch("jen.services.kea.kea_command", side_effect=fake_command),
            patch("jen.routes.api.get_active_kea_server") as election,
        ):
            r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.get_json()["server"] == "kea-b"
        assert calls == [("version-get", second)]
        election.assert_not_called()  # the HA election probes every server; this route must not

    def test_a_dead_server_costs_one_timeout_not_two(self, client, db):
        raw = self._key(db)
        calls = []

        def dead(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append(cmd)
            return {"result": 1, "text": "Cannot connect"}

        with patch("jen.services.kea.kea_command", side_effect=dead):
            body = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"}).get_json()
        assert body["kea_up"] is False and body["kea_version"] == "" and len(calls) == 1

    def test_the_per_server_list_lives_here_and_needs_the_key(self, client, db):
        raw = self._key(db)
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            body = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"}).get_json()
        assert body["servers"] and all({"name", "up", "version", "checked_at"} <= set(s) for s in body["servers"])
        assert client.get("/api/v1/health/kea").status_code == 401

    def test_the_subnet_count_lives_here_now(self, client, db):
        """v5.65.12 (Q101 a): moved off the public /api/v1/health body."""
        raw = self._key(db)
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            body = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"}).get_json()
        from jen import extensions

        assert body["subnets"] == len(extensions.SUBNET_MAP)

    def test_no_kea_server_configured_is_an_answer_not_an_error(self, client, db, monkeypatch):
        from jen import extensions

        raw = self._key(db)
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        monkeypatch.setitem(extensions._active_server_cache, "server", None)
        r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["kea_up"] is False and data["servers"] == [] and isinstance(data["subnets"], int)


class TestOneProbeEverywhere:
    """v5.65.10 (Q99 b): kea_is_up, the status page and the API share ONE probe."""

    def test_kea_is_up_is_the_probes_up(self):
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            assert kea_service.kea_is_up() is True
            entry = kea_service.probe_kea_health()
        assert entry["up"] is True and entry["version"] == "3.0.1" and entry["at"]

    def test_get_all_server_status_asks_each_server_for_its_version_once(self, monkeypatch):
        from jen import extensions

        servers = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        seen = []

        def fake(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            seen.append((cmd, server["name"]))
            if cmd == "ha-heartbeat":
                return {"result": 0, "arguments": {"state": "hot-standby", "partner-state": "hot-standby"}}
            return {"result": 0, "arguments": {"extended": "3.0.1\nx"}}

        with patch("jen.services.kea.kea_command", side_effect=fake):
            rows = kea_service.get_all_server_status()
        assert [r["version"] for r in rows] == ["3.0.1", "3.0.1"]
        assert sorted(seen) == [
            ("ha-heartbeat", "a"),
            ("ha-heartbeat", "b"),
            ("version-get", "a"),
            ("version-get", "b"),
        ]

    def test_a_down_server_has_an_empty_version_and_no_heartbeat(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "a"}])
        with patch("jen.services.kea.kea_command", return_value={"result": 1, "text": "down"}):
            rows = kea_service.get_all_server_status()
        assert rows[0]["up"] is False and rows[0]["version"] == ""

    def test_no_configured_server_is_none_not_an_indexerror(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        assert kea_service.get_active_kea_server() is None


class TestCacheIsPerServer:
    def test_the_cached_list_never_probes(self):
        with patch("jen.services.kea.kea_command", side_effect=_slow):
            started = time.monotonic()
            rows = kea_service.all_cached_kea_health()
        assert time.monotonic() - started < 1.0
        assert isinstance(rows, list) and all({"name", "up", "checked_at"} <= set(s) for s in rows)

    def test_a_probe_of_one_server_does_not_answer_for_another(self):
        one, two = {"id": 1, "name": "a"}, {"id": 2, "name": "b"}
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            kea_service.kea_is_up(server=one)
        assert kea_service.cached_kea_health(one)["up"] is True
        assert kea_service.cached_kea_health(two)["up"] is None
