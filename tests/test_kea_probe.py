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

    def post(self, url, json=None, auth=None, timeout=None, verify=None, cert=None):
        self.calls.append({"url": url, "json": json, "cert": cert, "auth": auth})
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

    def test_forwards_client_cert_when_configured(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", "/c.pem")
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", "/c.key")
        fake = probe_http({"localhost:18000": _ok("3.0.0")})
        logged_in_client.post("/settings/infrastructure/probe-kea")
        assert fake.calls[0]["cert"] == ("/c.pem", "/c.key")

    def test_default_fallback_keeps_the_scheme(self, logged_in_client, db, probe_http, monkeypatch):
        """v5.10.2 — https CA that refuses → the :8004 fallback stays https,
        never downgrades to http (would leak credentials)."""
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        monkeypatch.setattr(extensions, "KEA_API_URL", "https://localhost:18000")
        # v5.10.3 — the probe resolves its endpoint through _endpoint_for(),
        # which reads the SERVER dict; keep it in sync the way
        # derive_kea_servers() would.
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [dict(extensions.KEA_SERVERS[0], api_url="https://localhost:18000")],
        )
        fake = probe_http({})  # nothing answers
        logged_in_client.post("/settings/infrastructure/probe-kea")
        assert any(c["url"] == "https://localhost:8004" for c in fake.calls)
        assert not any(c["url"].startswith("http://") for c in fake.calls)


class TestProbeCandidateUrl:
    def test_candidate_that_answers_recommends_switching(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        fake = probe_http({"kea-direct:8004": _ok("3.2.0")})
        data = logged_in_client.post(
            "/settings/infrastructure/probe-kea", data={"candidate_url": "https://kea-direct:8004"}
        ).get_json()
        assert data["ok"] is True
        assert data["candidate"] is True
        assert data["answered_url"] == "https://kea-direct:8004"
        assert data["recommendation"]["level"] == "ok"
        assert "set this as the API URL" in data["recommendation"]["text"]
        # one call only — no configured endpoint, no :8004 auto-fallback
        assert len(fake.calls) == 1
        assert "service" not in fake.calls[0]["json"]

    def test_candidate_that_refuses_is_ok_false_with_one_attempt(self, logged_in_client, db, probe_http, monkeypatch):
        fake = probe_http({})  # nothing answers
        data = logged_in_client.post(
            "/settings/infrastructure/probe-kea", data={"candidate_url": "https://kea-direct:8004"}
        ).get_json()
        assert data["ok"] is False
        assert data["candidate"] is True
        assert len(data["attempts"]) == 1
        assert len(fake.calls) == 1  # no :8004 auto-probe

    def test_candidate_without_port_is_400(self, logged_in_client, db, probe_http, monkeypatch):
        probe_http({})
        r = logged_in_client.post("/settings/infrastructure/probe-kea", data={"candidate_url": "https://kea-direct"})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_candidate_with_bad_scheme_is_400(self, logged_in_client, db, probe_http, monkeypatch):
        probe_http({})
        r = logged_in_client.post("/settings/infrastructure/probe-kea", data={"candidate_url": "ftp://kea:8004"})
        assert r.status_code == 400


class TestProbeServerAndService:
    """v5.10.3 — Probe used the primary's URL and credentials whatever you
    asked it about, so a standby could not be tested at all. server_id and
    service now pick the endpoint via kea._endpoint_for(), i.e. exactly
    what Jen will dial for that daemon on that server."""

    PRIMARY = {
        "id": 1,
        "name": "Test Kea",
        "api_url": "http://localhost:18000",
        "api_user": "u1",
        "api_pass": "p1",
        "api6_url": "",
        "api6_user": "",
        "api6_pass": "",
    }
    STANDBY = {
        "id": 2,
        "name": "s2",
        "api_url": "http://kea02:9000",
        "api_user": "u2",
        "api_pass": "p2",
        "api6_url": "",
        "api6_user": "",
        "api6_pass": "",
    }

    @pytest.fixture(autouse=True)
    def _two_servers(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(self.PRIMARY), dict(self.STANDBY)])
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")

    def test_server_id_picks_that_servers_url_and_credentials(self, logged_in_client, db, probe_http):
        fake = probe_http({"kea02:9000": _ok("3.2.0")})
        data = logged_in_client.post("/settings/infrastructure/probe-kea", data={"server_id": "2"}).get_json()
        assert data["ok"] is True
        assert data["server"] == "s2"
        assert fake.calls[0]["url"] == "http://kea02:9000"
        assert fake.calls[0]["auth"] == ("u2", "p2")

    def test_dhcp6_sends_the_dhcp6_service_and_falls_back_to_8006(self, logged_in_client, db, probe_http):
        fake = probe_http({})  # nothing answers, so both attempts are recorded
        data = logged_in_client.post(
            "/settings/infrastructure/probe-kea", data={"server_id": "2", "service": "dhcp6"}
        ).get_json()
        assert data["service"] == "dhcp6"
        assert fake.calls[0]["json"]["service"] == ["dhcp6"]
        assert any(c["url"] == "http://kea02:8006" for c in fake.calls)
        assert not any(c["url"].endswith(":8004") for c in fake.calls)

    def test_direct_dhcp6_without_a_v6_url_is_400(self, logged_in_client, db, probe_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        probe_http({})
        r = logged_in_client.post("/settings/infrastructure/probe-kea", data={"server_id": "2", "service": "dhcp6"})
        assert r.status_code == 400
        assert "kea-dhcp6 control-socket" in r.get_json()["error"]
        assert r.get_json()["server"] == "s2"

    def test_candidate_url_uses_the_selected_servers_credentials(self, logged_in_client, db, probe_http):
        fake = probe_http({"kea02:8004": _ok("3.2.0")})
        data = logged_in_client.post(
            "/settings/infrastructure/probe-kea",
            data={"server_id": "2", "candidate_url": "http://kea02:8004"},
        ).get_json()
        assert data["ok"] is True
        assert fake.calls[0]["auth"] == ("u2", "p2")

    @pytest.mark.parametrize("bogus", ["9", "x", ""])
    def test_an_unknown_server_id_falls_back_to_the_primary(self, logged_in_client, db, probe_http, bogus):
        fake = probe_http({"localhost:18000": _ok("3.2.0")})
        data = logged_in_client.post("/settings/infrastructure/probe-kea", data={"server_id": bogus}).get_json()
        assert data["server"] == "Test Kea"
        assert fake.calls[0]["auth"] == ("u1", "p1")
