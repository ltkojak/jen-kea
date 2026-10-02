"""
tests/test_kea_tls_probe.py
────────────────────────────
v5.67.0-beta.5 (Q117, item f) — ChatGPT's review: /setup's Connect step
called `requests.post(url, ..., auth=(user, password), timeout=8)` with
no `verify`, no `cert`, while the real client (jen/services/kea.py)
honors `[kea] api_ca`/`api_tls_verify`/`api_client_cert`/`api_client_key`.
A site with a private CA or Kea's default mTLS control socket failed at
the very first step of the flagship first-hour flow. The fix is one
shared primitive, `kea.test_connection()`, used by both the setup step
and Settings' own probe-kea route.

CLAUDE.md: "Probe, redirect and TLS behavior is tested against real
local servers, not a mocked urlopen" — a real v5.8.3 SSL health-check
bug shipped behind a test that mocked urlopen *raising* instead of a
real server *redirecting*. So every test here stands up a real
ThreadingHTTPServer wrapped in real TLS (a private CA this process
generates itself, never in any system trust store) and calls
kea.test_connection()/setup_wizard.test_kea_connection() against it for
real — no mocked `requests.post`.
"""

import datetime
import http.server
import ipaddress
import json
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from jen.services import kea as kea_service
from jen.services import setup_wizard


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca(cn="Jen Test CA"):
    """A private CA this process makes up — never installed in any
    system trust store, so a probe with no explicit `verify` override
    must fail against anything it signs."""
    key = _new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(ca_cert, ca_key, cn, *, client=False):
    """A cert signed by `_ca()`'s CA — server (with a 127.0.0.1 SAN, so
    hostname verification against that IP passes) or client (no SAN
    needed; client certs are identified by the server's own CA trust,
    not by hostname)."""
    key = _new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if not client:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ).decode()
    return cert_pem, key_pem


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


class _VersionGetHandler(http.server.BaseHTTPRequestHandler):
    """Answers every POST with a Kea-shaped version-get reply, list-
    wrapped the way a real Control Agent replies."""

    protocol_version = "HTTP/1.1"
    version_text = "3.2.0"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps([{"result": 0, "arguments": {"extended": self.version_text}, "text": ""}]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Dhcp6Handler(http.server.BaseHTTPRequestHandler):
    """Answers version-get AND config-get — probe_v6()'s own two-call
    shape (version first, then a subnet6 listing) against ONE real
    server, Kea-shaped: list-wrapped, same as the Control Agent."""

    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        command = payload.get("command")
        if command == "config-get":
            reply = {
                "result": 0,
                "arguments": {"Dhcp6": {"subnet6": [{"id": 1, "subnet": "2001:db8::/64"}]}},
            }
        else:
            reply = {"result": 0, "arguments": {"extended": "3.2.0"}, "text": ""}
        body = json.dumps([reply]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve_tls(handler_cls, server_cert, server_key, *, ca_for_client_verify=None):
    """A real HTTPS server on 127.0.0.1:<random port>. When
    `ca_for_client_verify` is given, the server REQUIRES a client
    certificate signed by that CA (mTLS) — matching Kea's own
    cert-required default for its https control socket. Returns
    (base_url, shutdown)."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(server_cert, server_key)
    if ca_for_client_verify:
        ctx.load_verify_locations(cafile=ca_for_client_verify)
        ctx.verify_mode = ssl.CERT_REQUIRED
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    return f"https://127.0.0.1:{port}", srv.shutdown


@pytest.fixture(scope="module")
def private_ca_server(tmp_path_factory):
    """A real HTTPS server whose certificate is signed by a CA this
    process made up — not in any system trust store."""
    tmp_path = tmp_path_factory.mktemp("private_ca_server")
    ca_cert, ca_key = _ca()
    ca_path = _write(tmp_path, "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM).decode())
    server_cert_pem, server_key_pem = _leaf(ca_cert, ca_key, "127.0.0.1")
    server_cert_path = _write(tmp_path, "server.crt", server_cert_pem)
    server_key_path = _write(tmp_path, "server.key", server_key_pem)
    url, shutdown = _serve_tls(_VersionGetHandler, server_cert_path, server_key_path)
    yield {"url": url, "ca_path": ca_path}
    shutdown()


@pytest.fixture(scope="module")
def mtls_server(tmp_path_factory):
    """A real HTTPS server that ALSO requires a client certificate
    signed by the same private CA — Kea's own cert-required default for
    its per-daemon https control socket."""
    tmp_path = tmp_path_factory.mktemp("mtls_server")
    ca_cert, ca_key = _ca()
    ca_path = _write(tmp_path, "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM).decode())
    server_cert_pem, server_key_pem = _leaf(ca_cert, ca_key, "127.0.0.1")
    server_cert_path = _write(tmp_path, "server.crt", server_cert_pem)
    server_key_path = _write(tmp_path, "server.key", server_key_pem)
    client_cert_pem, client_key_pem = _leaf(ca_cert, ca_key, "jen-client", client=True)
    client_cert_path = _write(tmp_path, "client.crt", client_cert_pem)
    client_key_path = _write(tmp_path, "client.key", client_key_pem)
    url, shutdown = _serve_tls(_VersionGetHandler, server_cert_path, server_key_path, ca_for_client_verify=ca_path)
    yield {"url": url, "ca_path": ca_path, "client_cert": client_cert_path, "client_key": client_key_path}
    shutdown()


@pytest.fixture(scope="module")
def dhcp6_server(tmp_path_factory):
    """A real HTTPS server (private CA, no client cert needed) that
    answers both version-get and config-get — what probe_v6() actually
    calls, end to end, against a real socket."""
    tmp_path = tmp_path_factory.mktemp("dhcp6_server")
    ca_cert, ca_key = _ca()
    ca_path = _write(tmp_path, "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM).decode())
    server_cert_pem, server_key_pem = _leaf(ca_cert, ca_key, "127.0.0.1")
    server_cert_path = _write(tmp_path, "server.crt", server_cert_pem)
    server_key_path = _write(tmp_path, "server.key", server_key_pem)
    url, shutdown = _serve_tls(_Dhcp6Handler, server_cert_path, server_key_path)
    yield {"url": url, "ca_path": ca_path}
    shutdown()


class TestKeaTestConnectionAgainstAPrivateCaServer:
    """kea.test_connection() — the one shared TLS-aware primitive."""

    def test_succeeds_with_the_right_ca_bundle(self, private_ca_server):
        version_text, err = kea_service.test_connection(
            private_ca_server["url"], "u", "p", verify=private_ca_server["ca_path"]
        )
        assert version_text == "3.2.0", err
        assert err == ""

    def test_fails_with_no_ca_override_system_trust_does_not_know_this_ca(self, private_ca_server):
        # verify=True — the default, system-trust behavior a caller gets
        # by NOT overriding anything. This private CA is in no system
        # trust store, so the handshake must fail with requests/urllib3's
        # own canned certificate-verification wording.
        version_text, err = kea_service.test_connection(private_ca_server["url"], "u", "p", verify=True)
        assert version_text == ""
        assert err
        assert "certificate" in err.lower() or "ssl" in err.lower()


class TestKeaTestConnectionAgainstAnMtlsServer:
    def test_succeeds_with_a_valid_client_cert(self, mtls_server):
        version_text, err = kea_service.test_connection(
            mtls_server["url"],
            "u",
            "p",
            verify=mtls_server["ca_path"],
            cert=(mtls_server["client_cert"], mtls_server["client_key"]),
        )
        assert version_text == "3.2.0", err

    def test_fails_without_any_client_cert(self, mtls_server):
        version_text, err = kea_service.test_connection(mtls_server["url"], "u", "p", verify=mtls_server["ca_path"])
        assert version_text == ""
        assert err


class TestSetupWizardHonorsTheSameTlsMaterial:
    """The actual regression: setup_wizard.test_kea_connection() (what
    /setup's Connect step calls) used to never look at TLS settings at
    all. Same real servers, driven through the wizard's own function."""

    def test_connect_step_succeeds_against_a_private_ca_server(self, private_ca_server):
        result = setup_wizard.test_kea_connection(
            private_ca_server["url"], "u", "p", verify=private_ca_server["ca_path"]
        )
        assert result["ok"] is True
        assert result["version"] == "3.2.0"
        assert result["mode"] == "ca"

    def test_connect_step_fails_without_the_ca_override(self, private_ca_server):
        result = setup_wizard.test_kea_connection(private_ca_server["url"], "u", "p", verify=True)
        assert result["ok"] is False

    def test_connect_step_succeeds_against_an_mtls_server(self, mtls_server):
        result = setup_wizard.test_kea_connection(
            mtls_server["url"],
            "u",
            "p",
            verify=mtls_server["ca_path"],
            cert=(mtls_server["client_cert"], mtls_server["client_key"]),
        )
        assert result["ok"] is True
        assert result["version"] == "3.2.0"


class TestNoClientCertificateIsSaidOutLoud:
    """v5.67.0-beta.8 (Q120, item f) — `cert=None` means "nothing given, use the SAVED client certificate".
    The Connect step probed with None when its form had cleared the certificate fields, so the probe passed
    WITH the saved certificate, then saved the empty fields — and every later call failed. The explicit
    sentinel means none at all. Same real mTLS server as above."""

    def _saved_cert(self, monkeypatch, mtls_server):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", mtls_server["client_cert"])
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", mtls_server["client_key"])

    def test_none_still_falls_back_to_the_saved_certificate(self, mtls_server, monkeypatch):
        self._saved_cert(monkeypatch, mtls_server)
        version_text, err = kea_service.test_connection(mtls_server["url"], "u", "p", verify=mtls_server["ca_path"])
        assert version_text == "3.2.0", err

    def test_the_sentinel_means_no_certificate_even_when_one_is_saved(self, mtls_server, monkeypatch):
        self._saved_cert(monkeypatch, mtls_server)
        version_text, err = kea_service.test_connection(
            mtls_server["url"], "u", "p", verify=mtls_server["ca_path"], cert=kea_service.NO_CLIENT_CERT
        )
        assert version_text == ""
        assert err

    def test_the_connect_step_fails_when_the_form_cleared_the_certificate(self, mtls_server, monkeypatch):
        """The end-to-end shape of the bug: saved cert present, form cleared it -> must NOT pass."""
        self._saved_cert(monkeypatch, mtls_server)
        result = setup_wizard.test_kea_connection(
            mtls_server["url"], "u", "p", verify=mtls_server["ca_path"], cert=kea_service.NO_CLIENT_CERT
        )
        assert result["ok"] is False

    def test_the_sentinel_is_falsy_and_readable(self):
        assert not kea_service.NO_CLIENT_CERT
        assert repr(kea_service.NO_CLIENT_CERT) == "NO_CLIENT_CERT"


class TestProbeV6AgainstARealServer:
    """probe_v6() (item g — "Check for DHCPv6") has no verify/cert
    parameters of its own: by the time the Found step runs, Connect has
    already saved the real [kea] TLS material, so probe_v6 relies on
    kea.probe_command's own default resolution (_tls_verify()/
    _tls_client_cert()) the same way the globally-configured client
    does. Monkeypatching extensions.KEA_API_CA to this server's CA is
    standing in for that already-saved Connect step."""

    def test_finds_the_real_subnet6_list(self, dhcp6_server, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_CA", dhcp6_server["ca_path"])
        result = setup_wizard.probe_v6(dhcp6_server["url"], "u", "p", omit_service=False)
        assert result["ok"] is True
        assert result["version"] == "3.2.0"
        assert result["subnet6_count"] == 1
        assert result["proposed_subnets6"] == {
            1: {"name": "Subnet1", "cidr": "2001:db8::/64", "paired_subnet4_id": None}
        }

    def test_fails_without_the_ca_override(self, dhcp6_server, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_CA", "")
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", True)
        result = setup_wizard.probe_v6(dhcp6_server["url"], "u", "p", omit_service=False)
        assert result["ok"] is False
