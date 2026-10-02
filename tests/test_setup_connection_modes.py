"""
tests/test_setup_connection_modes.py
─────────────────────────────────────
v5.67.0-beta.8 (Q120, items b, e, k, l) — what the setup wizard's Connect step decides about the URL the
operator typed, against REAL local HTTP servers that answer the way Kea does (CLAUDE.md: probe behaviour is
tested against real local servers, not a mocked `requests.post`).

The behaviour these servers imitate was verified first against real kea-dhcp4 3.0.3, 3.2.0 and 3.3.1
(tests/kea_compat `test_a_daemon_identifies_itself_with_or_without_a_service_field`, results in the
kea-compat artifact):

  * a daemon answers `version-get` and `config-get` with `service: ["dhcp4"]` EXACTLY as without one, so
    "it answered a command carrying a service field" proves nothing about whether a Control Agent is
    there — the old Connect step recorded every daemon as "ca";
  * a direct-style `config-get` answers `{"Dhcp4": {...}, "hash": "..."}` from a daemon, and a Control
    Agent answers it about itself (`"Control-agent"`); the trailing `hash` is not the answer.
"""

import base64
import http.server
import json
import socket
import threading

import pytest

from jen.services import kea as kea_service
from jen.services import setup_wizard

USER, PASSWORD = "u", "p"


class _FakeKea(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    role = "daemon"  # daemon | ca | ca-dhcp4-down | mute-config | dhcp6-daemon
    received: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        auth = self.headers.get("Authorization", "")
        want = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if auth != want:
            return self._send(401, {"result": 1, "text": "unauthorized"})
        command, service = payload.get("command"), payload.get("service")
        type(self).received.append((command, service))
        role = type(self).role

        if role in ("ca", "ca-dhcp4-down") and service:
            if role == "ca-dhcp4-down":
                return self._send(
                    200,
                    [
                        {
                            "result": 1,
                            "text": "unable to forward command to the dhcp4 service: No such file or directory. "
                            "The server is likely to be offline",
                        }
                    ],
                )
            return self._send(200, [{"result": 0, "arguments": {"extended": "3.0.3"}, "text": ""}])

        if command == "version-get":
            version = "3.0.3" if role in ("ca", "ca-dhcp4-down") else "3.2.0"
            return self._send(200, [{"result": 0, "arguments": {"extended": version}, "text": version}])
        if command == "config-get":
            if role == "mute-config":
                return self._send(200, [{"result": 2, "text": "command not permitted"}])
            if role in ("ca", "ca-dhcp4-down"):
                return self._send(200, [{"result": 0, "arguments": {"Control-agent": {}, "hash": "abc"}}])
            key = "Dhcp6" if role == "dhcp6-daemon" else "Dhcp4"
            return self._send(200, [{"result": 0, "arguments": {key: {}, "hash": "abc"}}])
        return self._send(200, [{"result": 2, "text": "unknown command"}])

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def _serve(role, host="127.0.0.1"):
    handler = type("Handler", (_FakeKea,), {"role": role, "received": []})
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    class Server(http.server.ThreadingHTTPServer):
        address_family = family

    srv = Server((host, 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    return srv, handler, port


@pytest.fixture
def kea_server():
    made = []

    def make(role, host="127.0.0.1"):
        srv, handler, port = _serve(role, host)
        made.append(srv)
        shown = f"[{host}]" if ":" in host else host
        return {"url": f"http://{shown}:{port}", "received": handler.received, "port": port}

    yield make
    for srv in made:
        srv.shutdown()
        srv.server_close()


class TestTheModeIsWhatAnsweredNotWhatWasAsked:
    def test_a_daemons_own_control_socket_is_direct_mode(self, kea_server):
        """The bug: a daemon answers a service-style probe, so the old step saved it as "ca"."""
        server = kea_server("daemon")
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD)
        assert result["ok"] is True
        assert result["mode"] == "direct"
        assert result["identified"] == "Dhcp4"
        assert result["url"] == server["url"]
        assert result["version"] == "3.2.0"
        # the typed URL was asked first, in direct style (no service field), and only that URL
        assert server["received"][0] == ("version-get", None)
        assert [a["url"] for a in result["attempts"]] == [server["url"]]

    def test_a_control_agent_is_ca_mode_after_its_dhcp4_service_answers(self, kea_server):
        server = kea_server("ca")
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD)
        assert result["ok"] is True
        assert result["mode"] == "ca"
        assert result["identified"] == "Control-agent"
        assert ("version-get", ["dhcp4"]) in server["received"], "Jen sends a Control Agent a service field"

    def test_a_control_agent_whose_dhcp4_is_down_is_not_connected(self, kea_server):
        server = kea_server("ca-dhcp4-down")
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD)
        assert result["ok"] is False
        assert "unable to forward" in result["attempts"][-1]["error"]

    def test_an_answer_that_cannot_be_identified_keeps_the_given_default(self, kea_server):
        server = kea_server("mute-config")
        as_direct = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD, default_mode="direct")
        as_ca = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD, default_mode="ca")
        assert as_direct["ok"] and as_direct["mode"] == "direct" and as_direct["identified"] is None
        assert as_ca["ok"] and as_ca["mode"] == "ca"

    def test_a_dhcp6_socket_is_not_accepted_as_the_dhcp4_one(self, kea_server):
        server = kea_server("dhcp6-daemon")
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD, service="dhcp4")
        assert result["ok"] is False
        assert "kea-dhcp6's control socket, not kea-dhcp4's" in result["attempts"][0]["error"]
        again = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD, service="dhcp6")
        assert again["ok"] is True and again["mode"] == "direct"


class TestTheTypedUrlIsTriedFirstAndGuessedOnlyWithoutAPort:
    def test_a_custom_port_is_tried_as_typed_and_nothing_else(self, kea_server):
        """Item k — `https://kea:9004`-style: the port the operator typed is used, never replaced by :8004."""
        server = kea_server("daemon")
        assert server["port"] not in (8000, 8004, 8006)
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD)
        assert result["ok"] is True and result["url"] == server["url"]
        assert len(result["attempts"]) == 1

    def test_a_wrong_password_is_reported_for_the_typed_url_not_for_a_guessed_port(self, kea_server):
        """Item e — the old step flashed attempts[-1], always the :8004 guess."""
        server = kea_server("daemon")
        result = setup_wizard.test_kea_connection(server["url"], USER, "wrong")
        assert result["ok"] is False
        assert len(result["attempts"]) == 1, "a typed port means no guess"
        first = result["attempts"][0]
        assert first["typed"] is True and first["url"] == server["url"]
        assert "401" in first["error"] or "unauthorized" in first["error"].lower()

    def test_an_unreachable_typed_port_is_the_error_shown_first(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        result = setup_wizard.test_kea_connection(f"http://127.0.0.1:{port}", USER, PASSWORD)
        assert result["ok"] is False
        assert result["attempts"][0]["typed"] is True
        assert result["attempts"][0]["error"]

    def test_the_guess_is_tried_second_when_no_port_was_typed(self, monkeypatch):
        probed = []

        def fake_test_connection(url, user, password, **kw):
            probed.append((url, kw.get("omit_service")))
            return ("", "refused") if url == "http://kea.lan" else ("3.2.0", "")

        monkeypatch.setattr(kea_service, "test_connection", fake_test_connection)
        monkeypatch.setattr(kea_service, "identify_daemon", lambda *a, **kw: "Dhcp4")
        result = setup_wizard.test_kea_connection("http://kea.lan", USER, PASSWORD)
        assert result["ok"] and result["url"] == "http://kea.lan:8004" and result["mode"] == "direct"
        assert probed == [("http://kea.lan", True), ("http://kea.lan:8004", True)]
        assert [a["typed"] for a in result["attempts"]] == [True, False]

    def test_the_dhcp6_guess_is_8006(self, monkeypatch):
        probed = []
        monkeypatch.setattr(kea_service, "test_connection", lambda url, *a, **kw: probed.append(url) or ("", "refused"))
        setup_wizard.test_kea_connection("http://kea.lan", USER, PASSWORD, service="dhcp6")
        assert probed == ["http://kea.lan", "http://kea.lan:8006"]


class TestDirectGuess:
    @pytest.mark.parametrize(
        "typed,service,expected",
        [
            ("http://kea.lan", "dhcp4", "http://kea.lan:8004"),
            ("https://kea.lan", "dhcp6", "https://kea.lan:8006"),
            ("http://kea.lan/", "dhcp4", "http://kea.lan:8004"),
            ("http://[2001:db8::1]", "dhcp4", "http://[2001:db8::1]:8004"),  # item l: re-bracketed
            ("https://[2001:db8::1]/", "dhcp6", "https://[2001:db8::1]:8006"),
            ("http://kea.lan:8000", "dhcp4", None),  # a typed port is never replaced
            ("https://kea.lan:9004", "dhcp4", None),
            ("http://[2001:db8::1]:8000", "dhcp4", None),
            ("http://kea.lan:notaport", "dhcp4", None),
            ("http://", "dhcp4", None),
        ],
    )
    def test_cases(self, typed, service, expected):
        assert setup_wizard._direct_guess(typed, service) == expected

    def test_the_old_construction_produced_an_unparseable_url(self):
        """What `f"{scheme}://{host}:{port}"` did with urlparse(url).hostname, for the record."""
        from urllib.parse import urlparse

        host = urlparse("http://[2001:db8::1]:8000").hostname
        assert f"http://{host}:8004" == "http://2001:db8::1:8004"
        assert setup_wizard._direct_guess("http://[2001:db8::1]", "dhcp4") != "http://2001:db8::1:8004"


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6 on this host")
class TestAnIpv6LiteralEndToEnd:
    def test_a_bracketed_literal_is_probed_and_kept_as_typed(self, kea_server):
        try:
            server = kea_server("daemon", host="::1")
        except OSError:
            pytest.skip("no IPv6 loopback")
        assert server["url"].startswith("http://[::1]:")
        result = setup_wizard.test_kea_connection(server["url"], USER, PASSWORD)
        assert result["ok"] is True, result["attempts"]
        assert result["url"] == server["url"]
        assert result["mode"] == "direct"


class TestIdentifyDaemon:
    def test_a_daemon_and_a_control_agent(self, kea_server):
        assert kea_service.identify_daemon(kea_server("daemon")["url"], USER, PASSWORD) == "Dhcp4"
        assert kea_service.identify_daemon(kea_server("ca")["url"], USER, PASSWORD) == "Control-agent"
        assert kea_service.identify_daemon(kea_server("dhcp6-daemon")["url"], USER, PASSWORD) == "Dhcp6"

    def test_failure_is_none_not_an_exception(self, kea_server):
        assert kea_service.identify_daemon(kea_server("mute-config")["url"], USER, PASSWORD) is None
        assert kea_service.identify_daemon(kea_server("daemon")["url"], USER, "wrong") is None

    def test_the_trailing_hash_is_never_the_answer(self, monkeypatch):
        reply = {"result": 0, "arguments": {"hash": "abc", "Dhcp4": {}}}
        monkeypatch.setattr(kea_service, "probe_command", lambda *a, **kw: (reply, ""))
        assert kea_service.identify_daemon("http://x", "u", "p") == "Dhcp4"
        only_hash = {"result": 0, "arguments": {"hash": "abc"}}
        monkeypatch.setattr(kea_service, "probe_command", lambda *a, **kw: (only_hash, ""))
        assert kea_service.identify_daemon("http://x", "u", "p") is None

    def test_settings_probe_uses_the_same_identification(self, kea_server):
        from jen.routes.settings import infrastructure

        assert infrastructure._identify_daemon(kea_server("ca")["url"], USER, PASSWORD, "dhcp4") == "Control-agent"
        assert infrastructure._identify_daemon(kea_server("daemon")["url"], USER, PASSWORD, "dhcp4") == "Dhcp4"
