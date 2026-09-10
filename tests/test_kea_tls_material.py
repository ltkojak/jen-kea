"""
tests/test_kea_tls_material.py
──────────────────────────────
v5.10.3 — kea.validate_client_tls_material(). Until now [kea]
api_client_cert / api_client_key were only os.path.isfile() checked, and
isfile() is a stat(): a cert paired with the wrong key, a non-PEM file, or
a root:root 600 key that www-data can't read all passed, and then every
Kea request failed with an opaque SSLError. Same lesson 5.9.1 learned for
Jen's own server certificate — load the material with the API that will
actually use it, as the process that will actually use it.

Certificates come from tests/test_ssl_material.py::_pair (cryptography is
a runtime dependency); nothing here shells out to openssl.
"""

import os

import pytest

from jen.services.kea import validate_client_tls_material
from tests.test_ssl_material import _pair


class TestValidateClientTlsMaterial:
    def test_nothing_configured_is_fine(self):
        assert validate_client_tls_material("", "", "") is None

    def test_matching_pair_is_accepted(self, tmp_path):
        _pair(tmp_path, name="c")
        assert validate_client_tls_material(str(tmp_path / "c.crt"), str(tmp_path / "c.key"), "") is None

    def test_only_one_of_the_pair_is_rejected(self, tmp_path):
        _pair(tmp_path, name="c")
        err = validate_client_tls_material(str(tmp_path / "c.crt"), "", "")
        assert err and "both" in err

    def test_mismatched_pair_is_rejected(self, tmp_path):
        _pair(tmp_path, name="a")
        _pair(tmp_path, cn="other", name="b")
        err = validate_client_tls_material(str(tmp_path / "a.crt"), str(tmp_path / "b.key"), "")
        assert err and "does not match" in err

    def test_garbage_key_is_rejected(self, tmp_path):
        _pair(tmp_path, name="c")
        junk = tmp_path / "junk.key"
        junk.write_text("this is not a private key\n")
        err = validate_client_tls_material(str(tmp_path / "c.crt"), str(junk), "")
        assert err and "could not be loaded" in err

    @pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions only")
    def test_unreadable_key_is_rejected(self, tmp_path):
        if os.geteuid() == 0:
            pytest.skip("root can read anything")
        _pair(tmp_path, name="c")
        key = tmp_path / "c.key"
        key.chmod(0o000)
        try:
            err = validate_client_tls_material(str(tmp_path / "c.crt"), str(key), "")
        finally:
            key.chmod(0o600)
        assert err and "readable" in err

    def test_valid_ca_bundle_is_accepted(self, tmp_path):
        _pair(tmp_path, name="c")
        _pair(tmp_path, cn="Some CA", name="ca")
        err = validate_client_tls_material(str(tmp_path / "c.crt"), str(tmp_path / "c.key"), str(tmp_path / "ca.crt"))
        assert err is None

    def test_garbage_ca_bundle_is_rejected(self, tmp_path):
        _pair(tmp_path, name="c")
        bad_ca = tmp_path / "bad-ca.pem"
        bad_ca.write_text("nope\n")
        err = validate_client_tls_material(str(tmp_path / "c.crt"), str(tmp_path / "c.key"), str(bad_ca))
        assert err and "CA bundle" in err

    def test_ca_only_is_validated_too(self, tmp_path):
        bad_ca = tmp_path / "bad-ca.pem"
        bad_ca.write_text("nope\n")
        assert validate_client_tls_material("", "", str(bad_ca)) is not None
