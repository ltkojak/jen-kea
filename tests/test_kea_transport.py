"""
tests/test_kea_transport.py
───────────────────────────
v5.10.0 — jen/services/kea.py became a transport layer. [kea]
connection_mode picks between:

  ca (default)  — one endpoint (a kea-ctrl-agent) routes by the JSON
                  "service" field. Byte-identical to every prior release.
  direct        — talk straight to each daemon's HTTP control socket
                  (Kea 3.2 removed the Control Agent). dhcp4 → KEA_API_URL,
                  dhcp6 → KEA6_API_URL (no fallback), "service" omitted.

The GOLDEN class is the one that matters most: with connection_mode
absent, the outgoing request (URL + JSON body + auth) is unchanged.
"""

import pytest

from jen import extensions
from jen.services import kea as kea_svc


class _Resp:
    def __init__(self, body):
        self._body = body
        self.status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _FakeRequests:
    """Drop-in for `jen.services.kea.http` (the `requests` module) that
    records every .post() and returns a canned reply. `.exceptions` is
    the real module so kea_command's except-branches still resolve."""

    import requests as _r

    exceptions = _r.exceptions

    def __init__(self):
        self.calls = []
        self.reply = [{"result": 0, "arguments": {"extended": "3.2.0"}}]

    def post(self, url, json=None, auth=None, timeout=None, verify=None):
        self.calls.append({"url": url, "json": json, "auth": auth, "timeout": timeout, "verify": verify})
        return _Resp(self.reply)


@pytest.fixture
def fake_http(monkeypatch):
    fake = _FakeRequests()
    monkeypatch.setattr(kea_svc, "http", fake)
    return fake


@pytest.fixture(autouse=True)
def _kea_globals(monkeypatch):
    monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea4:8000")
    monkeypatch.setattr(extensions, "KEA_API_USER", "u4")
    monkeypatch.setattr(extensions, "KEA_API_PASS", "p4")
    # ca-mode default: KEA6_* equals KEA_* (AppConfig.apply does this fallback)
    monkeypatch.setattr(extensions, "KEA6_API_URL", "http://kea4:8000")
    monkeypatch.setattr(extensions, "KEA6_API_USER", "u4")
    monkeypatch.setattr(extensions, "KEA6_API_PASS", "p4")
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
    monkeypatch.setattr(extensions, "KEA_API_CA", "")
    monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", True)


class TestGoldenCaMode:
    """connection_mode absent/'ca' — nothing about the request changes."""

    def test_dhcp4_request_is_unchanged(self, fake_http):
        kea_svc.kea_command("config-get")
        c = fake_http.calls[0]
        assert c["url"] == "http://kea4:8000"
        assert c["json"] == {"command": "config-get", "service": ["dhcp4"]}
        assert c["auth"] == ("u4", "p4")
        assert c["timeout"] == 10
        assert c["verify"] is True  # == requests' own default

    def test_dhcp4_with_arguments(self, fake_http):
        kea_svc.kea_command("subnet4-get", arguments={"id": 1})
        assert fake_http.calls[0]["json"] == {
            "command": "subnet4-get",
            "service": ["dhcp4"],
            "arguments": {"id": 1},
        }

    def test_dhcp6_via_kea6_command_still_routes_through_the_one_endpoint(self, fake_http):
        from jen.services.kea6 import kea6_command

        kea6_command("config-get")
        c = fake_http.calls[0]
        assert c["url"] == "http://kea4:8000"
        assert c["json"] == {"command": "config-get", "service": ["dhcp6"]}

    def test_explicit_kea6_url_is_used_in_ca_mode(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA6_API_URL", "http://kea6-ca:9000")
        from jen.services.kea6 import kea6_command

        kea6_command("version-get")
        assert fake_http.calls[0]["url"] == "http://kea6-ca:9000"

    def test_server_dict_overrides_the_endpoint(self, fake_http):
        srv = {"api_url": "http://kea-standby:8000", "api_user": "us", "api_pass": "ps"}
        kea_svc.kea_command("ha-heartbeat", server=srv)
        c = fake_http.calls[0]
        assert c["url"] == "http://kea-standby:8000"
        assert c["auth"] == ("us", "ps")
        assert c["json"] == {"command": "ha-heartbeat", "service": ["dhcp4"]}


class TestDirectMode:
    @pytest.fixture(autouse=True)
    def _direct(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "KEA6_API_URL", "")  # no v4 fallback in direct mode

    def test_dhcp4_omits_the_service_field(self, fake_http):
        kea_svc.kea_command("config-get")
        c = fake_http.calls[0]
        assert c["url"] == "http://kea4:8000"
        assert c["json"] == {"command": "config-get"}
        assert "service" not in c["json"]

    def test_dhcp4_with_arguments_omits_service(self, fake_http):
        kea_svc.kea_command("subnet4-get", arguments={"id": 1})
        assert fake_http.calls[0]["json"] == {"command": "subnet4-get", "arguments": {"id": 1}}

    def test_dhcp6_hits_the_kea6_socket_url(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA6_API_URL", "http://kea6:8006")
        from jen.services.kea6 import kea6_command

        kea6_command("config-get")
        c = fake_http.calls[0]
        assert c["url"] == "http://kea6:8006"
        assert c["json"] == {"command": "config-get"}

    def test_dhcp6_with_no_kea6_url_returns_an_error_dict_without_posting(self, fake_http):
        from jen.services.kea6 import kea6_command

        result = kea6_command("config-get")
        assert result["result"] == 1
        assert "kea-dhcp6 control-socket" in result["text"]
        assert fake_http.calls == []

    def test_kea6_is_up_is_false_when_no_kea6_url(self, fake_http):
        from jen.services.kea6 import kea6_is_up

        assert kea6_is_up() is False
        assert fake_http.calls == []

    def test_per_server_api6_url_wins_over_the_global(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA6_API_URL", "http://global6:8006")
        srv = {
            "api_url": "http://kea4a:8000",
            "api_user": "u",
            "api_pass": "p",
            "api6_url": "http://kea6a:8006",
        }
        kea_svc.kea_command("config-get", service="dhcp6", server=srv)
        assert fake_http.calls[0]["url"] == "http://kea6a:8006"

    def test_per_server_dhcp6_does_not_fall_back_to_that_servers_v4_url(self, fake_http):
        srv = {"api_url": "http://kea4a:8000", "api_user": "u", "api_pass": "p"}  # no api6_url
        result = kea_svc.kea_command("config-get", service="dhcp6", server=srv)
        assert result["result"] == 1
        assert fake_http.calls == []


class TestResponseNormalisation:
    def test_list_wrapped_response_is_unwrapped(self, fake_http):
        fake_http.reply = [{"result": 0, "text": "ok"}]
        assert kea_svc.kea_command("version-get") == {"result": 0, "text": "ok"}

    def test_bare_object_response_passes_through(self, fake_http):
        fake_http.reply = {"result": 0, "text": "ok"}
        assert kea_svc.kea_command("version-get") == {"result": 0, "text": "ok"}


class TestTlsVerify:
    def test_ca_bundle_path_is_passed_as_verify(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_API_CA", "/etc/jen/ssl/kea-ca.pem")
        kea_svc.kea_command("version-get")
        assert fake_http.calls[0]["verify"] == "/etc/jen/ssl/kea-ca.pem"

    def test_verify_false_when_toggle_off_and_no_ca(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", False)
        kea_svc.kea_command("version-get")
        assert fake_http.calls[0]["verify"] is False

    def test_ca_path_wins_over_the_toggle(self, fake_http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_API_CA", "/ca.pem")
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", False)
        kea_svc.kea_command("version-get")
        assert fake_http.calls[0]["verify"] == "/ca.pem"
