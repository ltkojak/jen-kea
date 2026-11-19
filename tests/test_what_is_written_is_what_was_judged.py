"""
tests/test_what_is_written_is_what_was_judged.py
────────────────────────────────────────────────
Q241 (AZ1, AZ3 of the executing pass on v7.1.0-beta.9).

Jen judged the text an operator pasted and wrote that same text to disk, and OpenSSL read the file by its own rules. Wherever the two readings differed, a
certificate was judged and not served: a CA bundle whose BEGIN line had a space, a tab or a word before it was counted by Jen (`text.find`) and skipped by
OpenSSL (a BEGIN line starts its line), so the upload was accepted, installed and followed by a restart into an HTTPS that a client holding only the root
refused. And a private key pasted into the certificate field was skipped by the loader and written, with the rest of the field, into three files of mode 0644.

`cert_files` is the one answer to both: the certificates Jen read are written out again, and that text is what is judged, loaded and written. These tests run
the real route, read the files it wrote, serve them with a real `ssl` server context and complete a real handshake with a client that trusts only the root.
"""

import datetime
import io
import os
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from jen import extensions
from jen.routes.settings import security
from jen.routes.settings.security import validate_cert_material

BEGIN = "-----BEGIN CERTIFICATE-----"


def _issue(cn, key, issuer_cert=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@pytest.fixture(scope="module")
def chain():
    """root -> intermediate -> leaf, as PEM text, and the leaf's key."""
    root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _issue("Q241 Root", root_key, ca=True)
    mid = _issue("Q241 Intermediate", mid_key, root, root_key, ca=True)
    leaf = _issue("jen.q241.example", leaf_key, mid, mid_key)
    return {"root": _pem(root), "mid": _pem(mid), "leaf": _pem(leaf), "key": _key_pem(leaf_key)}


def _point_ssl_at(monkeypatch, tmp_path):
    ssl_dir = tmp_path / "ssl"
    ssl_dir.mkdir()
    for attr in ("SSL_CERT", "SSL_KEY", "SSL_CA", "SSL_COMBINED"):
        monkeypatch.setattr(extensions, attr, str(ssl_dir / (attr.lower().replace("ssl_", "") + ".pem")))
    monkeypatch.setattr("jen.services.runtime.restart_service", lambda *a, **k: "systemd")
    return ssl_dir


def _post(client, cert, key, ca=None):
    data = {
        "certificate": (io.BytesIO(cert.encode()), "certificate.crt"),
        "private_key": (io.BytesIO(key.encode()), "private.key"),
    }
    if ca is not None:
        data["ca_bundle"] = (io.BytesIO(ca.encode()), "ca_bundle.crt")
    return client.post("/settings/upload-cert", data=data, content_type="multipart/form-data", follow_redirects=True)


def _a_client_that_holds_only_the_root(ssl_dir, root_pem):
    """None when a client whose only trusted certificate is the root completes a handshake with a server that serves the files the route wrote; else the
    verifier's own words."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(ssl_dir / "combined.pem"), str(ssl_dir / "key.pem"))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.load_verify_locations(cadata=root_pem)
    return security._handshake(server, client)


# what an operator's paste does to the BEGIN line of the intermediate; OpenSSL reads a BEGIN line only at the start of its line
BEGIN_LINES = [
    ("as issued", BEGIN),
    ("one space before it", " " + BEGIN),
    ("one tab before it", "\t" + BEGIN),
    ("a word before it", "intermediate: " + BEGIN),
    ("a carriage return before it", "\r" + BEGIN),
]


class TestTheRouteWritesWhatItJudged:
    @pytest.mark.parametrize("how,begin_line", BEGIN_LINES, ids=[h for h, _ in BEGIN_LINES])
    def test_an_intermediate_jen_accepted_is_served(
        self, logged_in_client, tmp_path, monkeypatch, chain, how, begin_line
    ):
        """AZ1. The real route, the files it wrote, a real handshake: an upload Jen accepts is one a client holding only the root accepts."""
        ssl_dir = _point_ssl_at(monkeypatch, tmp_path)
        ca = chain["mid"].replace(BEGIN, begin_line, 1)
        r = _post(logged_in_client, chain["leaf"], chain["key"], ca)
        assert b"validated and installed" in r.data, r.data[-600:]
        assert _a_client_that_holds_only_the_root(ssl_dir, chain["root"]) is None
        assert (ssl_dir / "ca.pem").read_text() == chain["mid"]
        assert (ssl_dir / "combined.pem").read_text() == chain["leaf"] + chain["mid"]

    @pytest.mark.parametrize("how,begin_line", BEGIN_LINES[1:], ids=[h for h, _ in BEGIN_LINES[1:]])
    def test_a_fullchain_in_the_certificate_field_is_served_whole(
        self, logged_in_client, tmp_path, monkeypatch, chain, how, begin_line
    ):
        ssl_dir = _point_ssl_at(monkeypatch, tmp_path)
        fullchain = chain["leaf"] + chain["mid"].replace(BEGIN, begin_line, 1)
        r = _post(logged_in_client, fullchain, chain["key"])
        assert b"validated and installed" in r.data, r.data[-600:]
        assert _a_client_that_holds_only_the_root(ssl_dir, chain["root"]) is None
        assert (ssl_dir / "cert.pem").read_text() == chain["leaf"] + chain["mid"]

    @pytest.mark.parametrize("field", ["certificate", "ca_bundle"])
    def test_a_private_key_in_a_certificate_field_reaches_no_file_but_the_key_file(
        self, logged_in_client, tmp_path, monkeypatch, chain, field
    ):
        """AZ3. A combined PEM (chain and key in one file) is an ordinary thing to upload. The key is written to the key file, mode 0640, and nowhere else."""
        ssl_dir = _point_ssl_at(monkeypatch, tmp_path)
        cert = chain["leaf"] + (chain["key"] if field == "certificate" else "")
        ca = chain["mid"] + (chain["key"] if field == "ca_bundle" else "")
        r = _post(logged_in_client, cert, chain["key"], ca)
        assert b"validated and installed" in r.data, r.data[-600:]
        for name in ("cert.pem", "ca.pem", "combined.pem"):
            assert "PRIVATE KEY" not in (ssl_dir / name).read_text(), name
        assert (ssl_dir / "key.pem").read_text() == chain["key"]
        assert oct(os.stat(ssl_dir / "key.pem").st_mode & 0o777) == "0o640"
        assert _a_client_that_holds_only_the_root(ssl_dir, chain["root"]) is None

    def test_a_block_that_cannot_be_parsed_is_refused_and_nothing_is_written(
        self, logged_in_client, tmp_path, monkeypatch, chain
    ):
        ssl_dir = _point_ssl_at(monkeypatch, tmp_path)
        broken = BEGIN + "\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
        r = _post(logged_in_client, chain["leaf"], chain["key"], broken)
        assert b"Certificate rejected" in r.data and b"could not be read" in r.data
        assert list(ssl_dir.iterdir()) == []


class TestCertFiles:
    def test_only_the_certificates_are_kept_in_the_order_pasted_each_once(self, chain):
        pasted = (
            "Bag Attributes\n    friendlyName: jen\n"
            + chain["leaf"]
            + "# the intermediate\n"
            + chain["mid"]
            + chain["leaf"]
            + chain["key"]
        )
        cert, ca, combined = security.cert_files(pasted, None)
        assert cert == chain["leaf"] + chain["mid"] and ca == "" and combined == cert

    def test_the_combined_chain_is_the_certificate_then_the_ca_bundle(self, chain):
        cert, ca, combined = security.cert_files(chain["leaf"], chain["mid"] + chain["root"])
        assert (cert, ca) == (chain["leaf"], chain["mid"] + chain["root"]) and combined == cert + ca

    def test_what_it_returns_is_its_own_fixed_point(self, chain):
        first = security.cert_files(chain["leaf"] + " " + chain["mid"], chain["root"])
        assert security.cert_files(first[0], first[1]) == first

    def test_a_field_with_no_whole_certificate_is_empty(self, chain):
        assert security.cert_files(BEGIN + "\nAAAA\n", "nothing here") == ("", "", "")

    def test_a_field_that_holds_only_a_key_is_refused_by_name(self, chain):
        assert validate_cert_material(chain["leaf"], chain["key"], chain["key"]) == (
            "the CA bundle is not a PEM certificate bundle"
        )


class TestTheRouteAndTheJudgeAskTheSameFunction:
    def test_the_upload_route_writes_nothing_of_the_request_but_the_key_and_cert_files_answer(self):
        """Source: the judge and the route each replace the upload by what `cert_files` answers, in one statement, and nothing else builds the combined chain."""
        import inspect

        source = inspect.getsource(security)
        assert source.count("cert_data, ca_data, combined = cert_files(cert_data, ca_data)") == 2, (
            "the judge and the route"
        )
        assert source.count("cert_files(") == 4, (
            "those two, the definition, and `certificates_only` for an earlier copy (Q242)"
        )
        assert source.count("combined = ") == 2 and "combined.append" not in source
