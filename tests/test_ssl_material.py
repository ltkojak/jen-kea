"""
tests/test_ssl_material.py
──────────────────────────
v5.9.1 — a certificate upload used to be checked textually ("contains
BEGIN CERTIFICATE"), so a real certificate paired with the wrong private
key was written straight to /etc/jen/ssl, Jen restarted, gunicorn refused
the pair, and systemd's Restart=always spun the console into an outage.

Two guards now:
  - validate_cert_material() loads the pair (and CA bundle) with the same
    ssl API gunicorn uses, on temp files, BEFORE anything on disk changes;
  - run.py's _cert_pair_loadable() refuses to launch HTTPS with a pair that
    can't load, comes up HTTP-only with a CRITICAL, and sets
    JEN_SSL_DISABLED=1 so jen.config.ssl_configured() — the one choke point
    for "is SSL on" — agrees with what's actually being served.

Certificates are generated with `cryptography` (a runtime dependency).
"""

import io
import os
from unittest.mock import MagicMock

import pytest

from jen import extensions
from jen.routes.settings.security import validate_cert_material


def _pair(tmp_path, cn="jen.example.com", name="a"):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ).decode()
    (tmp_path / f"{name}.crt").write_text(cert_pem)
    (tmp_path / f"{name}.key").write_text(key_pem)
    return cert_pem, key_pem


class TestValidateCertMaterial:
    def test_matching_pair_is_accepted(self, tmp_path):
        cert, key = _pair(tmp_path)
        assert validate_cert_material(cert, key, None) is None

    def test_matching_pair_with_ca_bundle_is_accepted(self, tmp_path):
        cert, key = _pair(tmp_path)
        ca, _ = _pair(tmp_path, cn="Some CA", name="ca")
        assert validate_cert_material(cert, key, ca) is None

    def test_mismatched_key_is_rejected_with_a_clear_reason(self, tmp_path):
        cert, _ = _pair(tmp_path, name="a")
        _, other_key = _pair(tmp_path, name="b")
        reason = validate_cert_material(cert, other_key, None)
        assert reason is not None and "does not match" in reason

    def test_truncated_pem_is_rejected(self, tmp_path):
        cert, key = _pair(tmp_path)
        assert validate_cert_material(cert[: len(cert) // 2] + "\n-----END CERTIFICATE-----\n", key, None) is not None
        assert validate_cert_material(cert, key[: len(key) // 2], None) is not None

    def test_non_pem_inputs_are_rejected_before_loading(self):
        assert validate_cert_material("nope", "nope", None) is not None
        assert validate_cert_material("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n", "nope", None)

    def test_bad_ca_bundle_is_rejected(self, tmp_path):
        cert, key = _pair(tmp_path)
        assert validate_cert_material(cert, key, "this is not a bundle") is not None


class TestUploadCertRoute:
    def _post(self, client, cert, key):
        return client.post(
            "/settings/upload-cert",
            data={
                "certificate": (io.BytesIO(cert.encode()), "certificate.crt"),
                "private_key": (io.BytesIO(key.encode()), "private.key"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def _point_ssl_at(self, monkeypatch, tmp_path):
        ssl_dir = tmp_path / "ssl"
        ssl_dir.mkdir()
        for attr in ("SSL_CERT", "SSL_KEY", "SSL_CA", "SSL_COMBINED"):
            monkeypatch.setattr(extensions, attr, str(ssl_dir / attr.lower().replace("ssl_", "") + ".pem"))
        # never actually schedule a restart from a test
        monkeypatch.setattr("jen.routes.settings.security.threading.Thread", lambda *a, **k: MagicMock())
        return ssl_dir

    def test_mismatched_pair_is_refused_and_nothing_is_written(self, logged_in_client, tmp_path, monkeypatch):
        ssl_dir = self._point_ssl_at(monkeypatch, tmp_path)
        cert, _ = _pair(tmp_path, name="a")
        _, other_key = _pair(tmp_path, name="b")
        r = self._post(logged_in_client, cert, other_key)
        assert r.status_code == 200
        assert b"Certificate rejected" in r.data and b"does not match" in r.data
        assert list(ssl_dir.iterdir()) == []

    def test_valid_pair_is_installed_atomically_and_previous_kept(self, logged_in_client, tmp_path, monkeypatch):
        ssl_dir = self._point_ssl_at(monkeypatch, tmp_path)
        cert1, key1 = _pair(tmp_path, name="one")
        r = self._post(logged_in_client, cert1, key1)
        assert b"validated and installed" in r.data
        assert (ssl_dir / "cert.pem").read_text() == cert1
        assert (ssl_dir / "key.pem").read_text() == key1
        assert not (ssl_dir / "cert.pem.prev").exists()
        cert2, key2 = _pair(tmp_path, name="two")
        self._post(logged_in_client, cert2, key2)
        assert (ssl_dir / "cert.pem").read_text() == cert2
        assert (ssl_dir / "cert.pem.prev").read_text() == cert1
        assert (ssl_dir / "key.pem.prev").read_text() == key1
        assert not any(p.name.endswith(".new") for p in ssl_dir.iterdir())
        assert oct(os.stat(ssl_dir / "key.pem").st_mode & 0o777) == "0o640"


class TestRunPyStartupGuard:
    def test_loadable_pair_true_bad_pair_false(self, tmp_path):
        import run

        cert, key = _pair(tmp_path, name="ok")
        assert run._cert_pair_loadable(str(tmp_path / "ok.crt"), str(tmp_path / "ok.key")) is True
        _pair(tmp_path, name="other")
        assert run._cert_pair_loadable(str(tmp_path / "ok.crt"), str(tmp_path / "other.key")) is False
        assert run._cert_pair_loadable(str(tmp_path / "missing.crt"), str(tmp_path / "ok.key")) is False

    def test_ssl_configured_honours_the_disabled_flag(self, tmp_path, monkeypatch):
        from jen.config import ssl_configured

        cert, key = _pair(tmp_path, name="c")
        monkeypatch.setattr(extensions, "SSL_CERT", str(tmp_path / "c.crt"))
        monkeypatch.setattr(extensions, "SSL_KEY", str(tmp_path / "c.key"))
        monkeypatch.delenv("JEN_SSL_DISABLED", raising=False)
        assert ssl_configured() is True
        monkeypatch.setenv("JEN_SSL_DISABLED", "1")
        assert ssl_configured() is False

    def test_main_falls_back_to_http_when_pair_unloadable(self, tmp_path, monkeypatch):
        """The whole point: a bad pair must not become a crash loop."""
        import run

        monkeypatch.setattr(run, "ssl_configured", lambda: True)
        monkeypatch.setattr(run, "_ssl_cert_paths", lambda: ("/nope.crt", "/nope.key"))
        monkeypatch.setattr(run, "_gunicorn_importable", lambda: True)
        monkeypatch.setattr(run, "_build_config_from_env", lambda: None)
        monkeypatch.setattr(run.app_config, "reload", lambda: None)
        monkeypatch.setattr(run, "configure_logging", lambda *a, **k: None)
        monkeypatch.delenv("JEN_SSL_DISABLED", raising=False)
        launched = {}

        def fake_execvp(prog, argv):
            launched["argv"] = argv
            raise SystemExit(0)

        monkeypatch.setattr(run.os, "execvp", fake_execvp)
        with pytest.raises(SystemExit):
            run.main()
        assert "--certfile" not in launched["argv"]  # HTTP bind, not HTTPS
        assert os.environ.get("JEN_SSL_DISABLED") == "1"
        monkeypatch.delenv("JEN_SSL_DISABLED", raising=False)


class TestHttpsRedirectHardening:
    def test_query_string_preserved_and_host_validated(self, logged_in_client, monkeypatch):
        import jen

        monkeypatch.setattr(jen, "_ssl_configured_cache", True)
        monkeypatch.setattr(extensions, "HTTPS_PORT", 8443)
        r = logged_in_client.get("/settings/databases?tab=backups", headers={"Host": "jen.local:5050"})
        assert r.status_code == 301
        assert r.headers["Location"] == "https://jen.local:8443/settings/databases?tab=backups"
        r = logged_in_client.get("/leases", headers={"Host": "10.0.0.5"})
        assert r.headers["Location"] == "https://10.0.0.5:8443/leases"
        r = logged_in_client.get("/leases", headers={"Host": "evil.example/x"})
        assert r.status_code == 400

    def test_safe_host_rules(self):
        from jen.httpredirect import safe_host

        assert safe_host("jen.local:5050") == "jen.local"
        assert safe_host("10.0.0.5") == "10.0.0.5"
        assert safe_host("[::1]:5050") == "[::1]"
        assert safe_host("jen.local.") == "jen.local."
        assert safe_host("") is None
        assert safe_host("evil.example/x") is None
        assert safe_host("a b") is None
        assert safe_host("[::1") is None
        assert safe_host("x" * 300) is None
