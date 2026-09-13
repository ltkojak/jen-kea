"""
tests/test_kea_tls.py
─────────────────────
v5.29.0 (Q29, C1) — jen/services/kea_tls.py, the Jen-managed private CA
for Kea's https control sockets. Everything runs against a tmp_path
SSL_DIR; assertions use cryptography itself (signature verification,
extensions, validity), never string-matching PEM.
"""

import os
import stat
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID

from jen.services import kea_tls

posix = pytest.mark.skipif(sys.platform == "win32", reason="file modes")


@pytest.fixture
def ssl_dir(tmp_path, monkeypatch):
    d = tmp_path / "ssl"
    monkeypatch.setattr(kea_tls, "SSL_DIR", str(d))
    monkeypatch.setattr(kea_tls, "_hostname", lambda: "jenhost")
    return d


SERVER = {"id": 2, "name": "standby", "ssh_host": "kea02.lan"}


class TestEnsureCa:
    def test_creates_both_halves_and_is_idempotent(self, ssl_dir):
        first = kea_tls.ensure_ca()
        assert first["created"] is True
        assert os.path.isfile(first["cert"]) and os.path.isfile(first["key"])
        assert first["subject"].startswith("Jen Kea CA jenhost ")
        again = kea_tls.ensure_ca()
        assert again["created"] is False
        assert kea_tls.load_cert(first["cert"]).serial_number == kea_tls.load_cert(again["cert"]).serial_number

    def test_ca_shape(self, ssl_dir):
        kea_tls.ensure_ca()
        ca = kea_tls.load_cert(kea_tls.ca_paths()[0])
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and bc.value.ca is True and bc.value.path_length == 0
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign and ku.crl_sign
        assert ca.issuer == ca.subject
        ca.verify_directly_issued_by(ca)  # self-signed, signature checks
        span = ca.not_valid_after_utc - ca.not_valid_before_utc
        assert timedelta(days=3650) <= span <= timedelta(days=3651)
        assert isinstance(ca.public_key().curve, type(kea_tls.ec.SECP256R1()))

    @posix
    def test_key_is_0600_and_cert_0644(self, ssl_dir):
        r = kea_tls.ensure_ca()
        assert stat.S_IMODE(os.stat(r["key"]).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(r["cert"]).st_mode) == 0o644

    def test_a_cert_without_a_key_is_regenerated_as_a_pair(self, ssl_dir):
        r = kea_tls.ensure_ca()
        os.remove(r["key"])
        old_serial = kea_tls.load_cert(r["cert"]).serial_number
        r2 = kea_tls.ensure_ca()
        assert r2["created"] is True
        assert kea_tls.load_cert(r2["cert"]).serial_number != old_serial
        assert os.path.isfile(r2["key"])
        assert os.path.isfile(r["cert"] + ".prev")  # the orphaned cert is kept aside

    def test_force_rotates(self, ssl_dir):
        a = kea_tls.load_cert(kea_tls.ensure_ca()["cert"]).serial_number
        b = kea_tls.load_cert(kea_tls.ensure_ca(force=True)["cert"]).serial_number
        assert a != b


class TestServerCert:
    def test_sans_carry_the_bind_ip_and_the_ssh_host(self, ssl_dir):
        kea_tls.ensure_ca()
        files = kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        assert set(files) == {"ca.crt", "server.crt", "server.key"}
        cert = x509.load_pem_x509_certificate(files["server.crt"].encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert [str(v) for v in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.6"]
        assert san.get_values_for_type(x509.DNSName) == ["kea02.lan"]
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False

    def test_signed_by_the_ca_and_five_years(self, ssl_dir):
        kea_tls.ensure_ca()
        files = kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        ca = x509.load_pem_x509_certificate(files["ca.crt"].encode())
        cert = x509.load_pem_x509_certificate(files["server.crt"].encode())
        cert.verify_directly_issued_by(ca)
        assert ca.serial_number == kea_tls.load_cert(kea_tls.ca_paths()[0]).serial_number
        span = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert timedelta(days=1826) <= span <= timedelta(days=1827)
        assert cert.not_valid_before_utc < datetime.now(timezone.utc)  # clock-skew margin

    def test_key_matches_the_cert(self, ssl_dir):
        kea_tls.ensure_ca()
        files = kea_tls.issue_server_cert(SERVER, "dhcp6", "10.0.0.6")
        cert = x509.load_pem_x509_certificate(files["server.crt"].encode())
        key = kea_tls.serialization.load_pem_private_key(files["server.key"].encode(), password=None)
        assert key.public_key().public_numbers() == cert.public_key().public_numbers()

    def test_duplicate_and_ip_ssh_host_dedupe(self, ssl_dir):
        kea_tls.ensure_ca()
        files = kea_tls.issue_server_cert({"id": 1, "name": "p", "ssh_host": "10.0.0.5"}, "dhcp4", "10.0.0.5")
        san = x509.load_pem_x509_certificate(files["server.crt"].encode()).extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        assert len(list(san.value)) == 1

    def test_a_copy_is_kept_per_server_and_service_for_health(self, ssl_dir):
        kea_tls.ensure_ca()
        kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        kea_tls.issue_server_cert(SERVER, "d2", "10.0.0.6")
        copies = kea_tls.issued_server_copies()
        assert [(c["server_id"], c["service"]) for c in copies] == [("2", "d2"), ("2", "dhcp4")]
        assert all(1800 <= c["days_left"] <= 1826 for c in copies)
        assert copies[0]["path"] == kea_tls.server_copy_path(2, "d2")

    def test_files_payload_is_what_the_helper_takes(self, ssl_dir):
        """Exactly the three basenames, str PEM bodies, each under the
        helper's 64 KiB cap and matching its marker guard."""
        import re

        kea_tls.ensure_ca()
        files = kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        assert files["server.key"].startswith("-----BEGIN PRIVATE KEY-----\n")
        assert files["server.crt"].startswith("-----BEGIN CERTIFICATE-----\n")
        for body in files.values():
            assert isinstance(body, str) and len(body) < 64 * 1024
            assert re.fullmatch(r"(?:-----BEGIN [A-Z ]+-----\n[A-Za-z0-9+/=\n]+-----END [A-Z ]+-----\n)+", body)

    def test_remote_paths_are_the_fixed_layout(self):
        assert kea_tls.remote_tls_paths("dhcp6") == {
            "trust_anchor": "/etc/kea/tls/dhcp6/ca.crt",
            "cert_file": "/etc/kea/tls/dhcp6/server.crt",
            "key_file": "/etc/kea/tls/dhcp6/server.key",
            "cert_required": True,
        }


class TestClientCert:
    def test_issued_once_with_client_auth(self, ssl_dir):
        kea_tls.ensure_ca()
        r = kea_tls.issue_client_cert()
        assert r["issued"] is True
        cert = kea_tls.load_cert(r["cert"])
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        assert kea_tls.issued_by(r["cert"], kea_tls.ca_paths()[0])
        assert kea_tls.client_cert_ok()
        assert kea_tls.issue_client_cert()["issued"] is False

    @posix
    def test_client_key_is_0600(self, ssl_dir):
        kea_tls.ensure_ca()
        r = kea_tls.issue_client_cert()
        assert stat.S_IMODE(os.stat(r["key"]).st_mode) == 0o600

    def test_reissued_when_the_ca_changed_underneath(self, ssl_dir):
        kea_tls.ensure_ca()
        first = kea_tls.load_cert(kea_tls.issue_client_cert()["cert"]).serial_number
        kea_tls.ensure_ca(force=True)
        assert kea_tls.client_cert_ok() is False
        second = kea_tls.load_cert(kea_tls.issue_client_cert()["cert"]).serial_number
        assert first != second
        assert kea_tls.client_cert_ok()


class TestRotate:
    def test_old_leaves_no_longer_verify_against_the_new_ca(self, ssl_dir):
        kea_tls.ensure_ca()
        old_client = kea_tls.issue_client_cert()["cert"]
        old_server = kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        old_client_cert = kea_tls.load_cert(old_client)
        r = kea_tls.rotate_ca()
        assert r["ca"]["created"] and r["client"]["issued"]
        new_ca = kea_tls.load_cert(kea_tls.ca_paths()[0])
        # InvalidSignature when the (same-named) new CA's key doesn't verify
        # the old leaf; ValueError if the subject names differ (a rotation
        # on a later day). Either way: not trusted.
        with pytest.raises((InvalidSignature, ValueError)):
            old_client_cert.verify_directly_issued_by(new_ca)
        with pytest.raises((InvalidSignature, ValueError)):
            x509.load_pem_x509_certificate(old_server["server.crt"].encode()).verify_directly_issued_by(new_ca)
        # the new client cert does verify, and the old CA is kept aside
        assert kea_tls.issued_by(kea_tls.client_paths()[0], kea_tls.ca_paths()[0])
        assert os.path.isfile(kea_tls.ca_paths()[0] + ".prev")
        # and a freshly issued server cert chains to the new CA
        fresh = kea_tls.issue_server_cert(SERVER, "dhcp4", "10.0.0.6")
        x509.load_pem_x509_certificate(fresh["server.crt"].encode()).verify_directly_issued_by(new_ca)


class TestExpiryHelpers:
    def test_absent_or_garbage_is_none(self, ssl_dir):
        assert kea_tls.cert_expiry(str(ssl_dir / "nope.crt")) is None
        ssl_dir.mkdir()
        (ssl_dir / "junk.crt").write_text("not pem")
        assert kea_tls.cert_expiry(str(ssl_dir / "junk.crt")) is None
        assert kea_tls.days_left(str(ssl_dir / "junk.crt")) is None
        assert kea_tls.issued_by(str(ssl_dir / "junk.crt"), str(ssl_dir / "junk.crt")) is False

    def test_days_left_on_a_real_cert(self, ssl_dir):
        r = kea_tls.ensure_ca()
        assert 3640 <= kea_tls.days_left(r["cert"]) <= 3650
        assert kea_tls.ca_present()
