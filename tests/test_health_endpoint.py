"""
tests/test_health_endpoint.py
──────────────────────────────
v5.65.6 (Q95) — /api/v1/health answers from Jen alone.

The self-updater confirms the running version by polling this endpoint with a 5-second
timeout, and the restore's health poll does the same. It used to call Kea live, twice, each up
to the Kea API timeout, so with Kea unreachable (a condition Jen is meant to survive) it took
~20 s, read as "Jen is not up", and rolled a HEALTHY update or restore back. Now it reads the
last probe the background poller made and never calls Kea; /api/v1/health/kea keeps the live
probe, behind an API key.
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
            patch("jen.routes.api.kea_is_up", side_effect=_slow),
            patch("jen.routes.api.kea_command", side_effect=_slow),
            patch("jen.services.kea.kea_command", side_effect=_slow),
            patch("jen.services.kea.kea_is_up", side_effect=_slow),
        ):
            started = time.monotonic()
            r = client.get("/api/v1/health")
            elapsed = time.monotonic() - started
        assert r.status_code == 200
        assert elapsed < 1.0, f"/api/v1/health took {elapsed:.1f}s - it must not call Kea"

    def test_kea_is_unknown_until_something_has_probed(self, client):
        data = client.get("/api/v1/health").get_json()
        assert data["kea_up"] is None and data["kea_version"] is None and data["kea_checked_at"] is None
        assert data["jen_version"] and isinstance(data["subnets"], int)

    def test_it_reports_what_the_last_probe_learned(self, client):
        with patch(
            "jen.services.kea.kea_command",
            return_value={"result": 0, "arguments": {"extended": "3.0.1\nlong text"}},
        ):
            assert kea_service.kea_is_up() is True
        data = client.get("/api/v1/health").get_json()
        assert data["kea_up"] is True and data["kea_version"] == "3.0.1" and data["kea_checked_at"]
        with patch("jen.services.kea.kea_command", return_value={"result": 1, "text": "Cannot connect"}):
            assert kea_service.kea_is_up() is False
        data = client.get("/api/v1/health").get_json()
        assert data["kea_up"] is False and data["kea_version"] is None

    def test_a_stale_probe_is_unknown_not_a_guess(self, client):
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            kea_service.kea_is_up()
        for entry in kea_service._HEALTH_CACHE.values():
            entry["at"] -= 10_000
        data = client.get("/api/v1/health").get_json()
        assert data["kea_up"] is None

    def test_the_route_never_imports_a_live_probe_into_its_path(self):
        import inspect

        from jen.routes import api

        src = inspect.getsource(api.api_v1_health)
        assert "kea_is_up" not in src and "kea_command" not in src


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

    def test_it_probes_kea_live(self, client, db):
        raw = self._key(db)
        with (
            patch("jen.routes.api.kea_is_up", return_value=True),
            patch("jen.routes.api.kea_command", return_value={"result": 0, "arguments": {"extended": "3.2.0\nx"}}),
        ):
            r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["kea_up"] is True and body["kea_version"] == "3.2.0" and "server" in body

    def test_it_probes_the_active_server_not_the_primary(self, client, db):
        raw = self._key(db)
        second = {"id": 2, "name": "kea-b", "api_url": "http://kea-b:8000/"}
        calls = []

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            calls.append(server)
            return {"result": 0, "arguments": {"extended": "3.0.9"}}

        with (
            patch("jen.routes.api.get_active_kea_server", return_value=second),
            patch("jen.routes.api.kea_command", side_effect=fake_command),
            patch("jen.routes.api.kea_is_up", return_value=True) as up,
        ):
            r = client.get("/api/v1/health/kea", headers={"Authorization": f"Bearer {raw}"})
        assert r.get_json()["server"] == "kea-b"
        assert up.call_args.kwargs["server"] == second and calls == [second]


class TestCacheIsPerServer:
    def test_the_health_body_lists_every_server_and_never_probes(self, client):
        with patch("jen.services.kea.kea_command", side_effect=_slow):
            started = time.monotonic()
            data = client.get("/api/v1/health").get_json()
        assert time.monotonic() - started < 1.0
        assert isinstance(data["kea_servers"], list) and all(
            {"name", "up", "checked_at"} <= set(s) for s in data["kea_servers"]
        )

    def test_a_probe_of_one_server_does_not_answer_for_another(self):
        one, two = {"id": 1, "name": "a"}, {"id": 2, "name": "b"}
        with patch("jen.services.kea.kea_command", return_value={"result": 0, "arguments": {"extended": "3.0.1"}}):
            kea_service.kea_is_up(server=one)
        assert kea_service.cached_kea_health(one)["up"] is True
        assert kea_service.cached_kea_health(two)["up"] is None
