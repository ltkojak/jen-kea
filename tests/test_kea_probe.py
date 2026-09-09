"""
tests/test_kea_probe.py
───────────────────────
v5.10.0 — the /settings/infrastructure/probe-kea route and the
parse_kea_version helper it leans on. The probe is read-only: a
version-get against the configured endpoint, then a direct fallback on
port 8004, then a version-keyed recommendation about the Control Agent
(deprecated Kea 3.0, removed Kea 3.2, direct sockets from 2.7.2).
"""

import pytest

from jen import extensions
from jen.services import kea as kea_svc


class TestParseKeaVersion:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("3.2.0", (3, 2, 0)),
            ("3.0.0\ntarball: kea-3.0.0.tar.gz", (3, 0, 0)),
            ("2.6.1", (2, 6, 1)),
            ("Kea 2.7.2 (extended)", (2, 7, 2)),
            ("", None),
            ("mocked", None),
            (None, None),
        ],
    )
    def test_parse(self, text, expected):
        assert kea_svc.parse_kea_version(text) == expected

    def test_tuples_order_as_expected(self):
        assert kea_svc.parse_kea_version("3.0.0") < kea_svc.parse_kea_version("3.2.0")
        assert kea_svc.parse_kea_version("2.7.2") < (2, 7, 3)


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _FakeHTTP:
    """Answers version-get per-URL: `replies` maps a URL substring to the
    JSON body to return; anything unmatched raises ConnectionError."""

    import requests as _r

    exceptions = _r.exceptions

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def post(self, url, json=None, auth=None, timeout=None, verify=None):
        self.calls.append({"url": url, "json": json})
        for frag, body in self.replies.items():
            if frag in url:
                if isinstance(body, Exception):
                    raise body
                return _Resp(body)
        raise self.exceptions.ConnectionError(f"no fake for {url}")


@pytest.fixture
def probe_http(monkeypatch):
    def _install(replies):
        fake = _FakeHTTP(replies)
        monkeypatch.setattr(kea_svc, "http", fake)
        return fake

    return _install


def _ok(version):
    return [{"result": 0, "arguments": {"extended": version}}]


class TestProbeRoute:
    def test_configured_ca_endpoint_answers_kea_30_recommends_switch(
        self, logged_in_client, db, probe_http, monkeypatch
    ):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        probe_http({"localhost:18000": _ok("3.0.0")})
        r = logged_in_client.post("/settings/infrastructure/probe-kea")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["version"] == "3.0.0"
        assert data["answered_mode"] == "ca"
        assert data["recommendation"]["level"] == "warn"
        assert "deprecated" in data["recommendation"]["text"].lower()

    def test_kea_32_on_ca_is_a_hard_error(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        probe_http({"localhost:18000": _ok("3.2.0")})
        data = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()
        assert data["recommendation"]["level"] == "bad"
        assert "removed" in data["recommendation"]["text"].lower()

    def test_falls_back_to_direct_socket_on_8004(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        # CA URL refuses; the :8004 direct socket answers.
        probe_http({"localhost:8004": _ok("3.2.0")})
        data = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()
        assert data["ok"] is True
        assert data["answered_mode"] == "direct"
        assert data["answered_url"].endswith(":8004")
        assert data["recommendation"]["level"] == "ok"
        assert len(data["attempts"]) == 1  # the failed CA attempt is recorded

    def test_direct_fallback_omits_service_field(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        fake = probe_http({"localhost:8004": _ok("3.2.0")})
        logged_in_client.post("/settings/infrastructure/probe-kea")
        direct_call = next(c for c in fake.calls if "8004" in c["url"])
        assert "service" not in direct_call["json"]
        ca_call = next(c for c in fake.calls if "18000" in c["url"])
        assert ca_call["json"].get("service") == ["dhcp4"]

    def test_nothing_answers_returns_ok_false(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        probe_http({})  # every URL raises
        data = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()
        assert data["ok"] is False
        assert data["recommendation"]["level"] == "bad"
        assert len(data["attempts"]) == 2

    def test_configured_direct_mode_does_not_double_probe(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        fake = probe_http({"localhost:18000": _ok("3.2.0")})
        data = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()
        assert data["answered_mode"] == "direct"
        assert len(fake.calls) == 1
        assert "service" not in fake.calls[0]["json"]

    def test_requires_admin(self, client, db):
        r = client.post("/settings/infrastructure/probe-kea")
        assert r.status_code in (302, 401, 403)
